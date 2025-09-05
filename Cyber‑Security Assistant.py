#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Cyber‑Security Assistant
========================
A FastAPI service that uses Ollama’s GPT‑OSS 20 B model to generate
AV/EDR‑style recommendations for removing malware/ransomware.
The service

  • enforces a manual confirmation for destructive actions,
  • writes every recommendation & outcome to a secure audit log,
  • can run in batch mode (CSV input → single report),
  • exposes a REST endpoint (`/recommend`) for on‑the‑fly queries.

Author:  <your‑name>
Date:    2025‑09‑05
"""

import os
import csv
import json
import logging
import traceback
from pathlib import Path
from typing import List, Dict, Any, Optional

import ollama  # pip install ollama
from fastapi import FastAPI, HTTPException, Body, Query
from pydantic import BaseModel, Field, validator
from fastapi.responses import JSONResponse
from starlette.status import HTTP_422_UNPROCESSABLE_ENTITY

# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------
LOG_DIR = Path("/var/log/cyberassistant")
LOG_DIR.mkdir(parents=True, exist_ok=True)
AUDIT_LOG_PATH = LOG_DIR / "audit.log"

# Ensure the log file is only readable/writable by the owner (chmod 600)
if not AUDIT_LOG_PATH.exists():
    AUDIT_LOG_PATH.touch(mode=0o600, exist_ok=True)
else:
    os.chmod(AUDIT_LOG_PATH, 0o600)

# ----------------------------------------------------------------------
# Logging Setup
# ----------------------------------------------------------------------
logger = logging.getLogger("cyberassistant")
logger.setLevel(logging.INFO)
handler = logging.FileHandler(AUDIT_LOG_PATH, mode="a", encoding="utf-8")
formatter = logging.Formatter(
    "%(asctime)s | %(levelname)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
)
handler.setFormatter(formatter)
logger.addHandler(handler)

# ----------------------------------------------------------------------
# Ollama Client
# ----------------------------------------------------------------------
# Default Ollama port is 11434. If you run it elsewhere, change the host.
try:
    ollama_client = ollama.Client(host="http://localhost:11434")
    # Quick health‑check
    ollama_client.ping()
except Exception as exc:
    logger.critical(f"Failed to connect to Ollama: {exc}")
    raise SystemExit("Ollama server not reachable. Install/start Ollama first.") from exc

MODEL = "gpt-oss:20b"

# ----------------------------------------------------------------------
# Helper Functions
# ----------------------------------------------------------------------
def _generate_prompt(threat_info: Dict[str, Any]) -> str:
    """Create the system+user prompt that will be sent to the model."""
    system = "You are a cybersecurity assistant specialized in AV/EDR."
    user = (
        f"Threat Data:\n"
        f"{json.dumps(threat_info, indent=2)}\n\n"
        f"Provide a concise recommendation that includes "
        f"what to do, why it matters, and if it is destructive "
        f"(mention 'delete', 'remove', 'kill', etc.). "
        f"Return the recommendation in a single paragraph."
    )
    return {"system": system, "user": user}


def _is_destructive(recommendation: str) -> bool:
    """Naive check – look for destructive keywords."""
    destructive_terms = {"delete", "remove", "kill", "uninstall", "erase"}
    words = set(recommendation.lower().split())
    return bool(words & destructive_terms)


def _log_recommendation(
    threat_id: str,
    recommendation: str,
    destructive: bool,
    approved: Optional[bool] = None,
    notes: Optional[str] = None,
) -> None:
    """Write a structured log line to the audit file."""
    entry = {
        "threat_id": threat_id,
        "recommendation": recommendation,
        "destructive": destructive,
        "approved": approved,
        "notes": notes,
    }
    logger.info(json.dumps(entry))


def _ask_confirmation(action: str, threat_id: str) -> bool:
    """
    In a real UI you would pop up a dialog.  In this service we simply
    log the request and refuse automatically; the caller should
    set `confirm=True` in the request body.
    """
    logger.warning(
        f"Destructive action requested for threat {threat_id}: {action}. Awaiting manual confirmation."
    )
    # Default to deny unless caller explicitly approves
    return False


# ----------------------------------------------------------------------
# FastAPI Application
# ----------------------------------------------------------------------
app = FastAPI(
    title="Cyber‑Security Assistant API",
    description="Generate AV/EDR recommendations with safety checks, audit logging, and batch reporting.",
    version="1.0.0",
)

# ----------------------------------------------------------------------
# Data Models
# ----------------------------------------------------------------------
class Threat(BaseModel):
    """Single threat record (fields are flexible)."""

    threat_id: str = Field(..., example="malware-001")
    file_path: Optional[str] = None
    sha256: Optional[str] = None
    description: Optional[str] = None
    additional_info: Optional[Dict[str, Any]] = None


class RecommendationResponse(BaseModel):
    threat_id: str
    recommendation: str
    destructive: bool
    approved: bool
    notes: Optional[str] = None


class BatchRequest(BaseModel):
    threats: List[Threat]


class BatchResponse(BaseModel):
    report: List[RecommendationResponse]


class RecommendRequest(BaseModel):
    threat: Threat
    confirm: bool = Field(
        False,
        description="Set to true only if you want to perform destructive actions.",
    )


class RecommendResponse(BaseModel):
    threat_id: str
    recommendation: str
    destructive: bool
    approved: bool
    notes: Optional[str] = None


# ----------------------------------------------------------------------
# REST End‑points
# ----------------------------------------------------------------------
@app.post("/recommend", response_model=RecommendResponse)
async def recommend(request: RecommendRequest):
    """Generate recommendation for a single threat."""
    try:
        # Build the prompt
        prompt = _generate_prompt(request.threat.model_dump())
        # Send to Ollama
        response = ollama_client.chat.completions.create(
            model=MODEL, messages=[
                {"role": "system", "content": prompt["system"]},
                {"role": "user", "content": prompt["user"]},
            ]
        )
        recommendation = response.choices[0].message.content.strip()
    except Exception as exc:
        logger.error(f"Model error for {request.threat.threat_id}: {exc}")
        raise HTTPException(
            status_code=500, detail=f"Model generation failed: {exc}"
        )

    destructive = _is_destructive(recommendation)
    approved = True  # safe by default

    # Safety hook
    if destructive and not request.confirm:
        approved = _ask_confirmation(recommendation, request.threat.threat_id)
        if not approved:
            notes = "Destructive action denied – user / caller must confirm."
            _log_recommendation(
                request.threat.threat_id,
                recommendation,
                destructive,
                approved,
                notes,
            )
            raise HTTPException(
                status_code=400,
                detail="Destructive recommendation requires explicit confirmation.",
            )

    _log_recommendation(
        request.threat.threat_id,
        recommendation,
        destructive,
        approved,
        None,
    )

    return RecommendResponse(
        threat_id=request.threat.threat_id,
        recommendation=recommendation,
        destructive=destructive,
        approved=approved,
        notes=None,
    )


@app.post("/batch", response_model=BatchResponse)
async def batch(request: BatchRequest):
    """Process a list of threats and return a single report."""

    report_entries: List[RecommendationResponse] = []
    for threat in request.threats:
        try:
            # Reuse the single‑request logic but always deny destructive actions
            # in batch mode (to avoid accidental mass deletions).
            single_request = RecommendRequest(threat=threat, confirm=False)
            response = await recommend(single_request)  # reuse endpoint logic
            report_entries.append(
                RecommendationResponse(**response.dict())
            )
        except HTTPException as exc:
            # Log the failure but keep going
            logger.warning(f"Batch threat {threat.threat_id} failed: {exc.detail}")
            report_entries.append(
                RecommendationResponse(
                    threat_id=threat.threat_id,
                    recommendation="",
                    destructive=False,
                    approved=False,
                    notes=f"Failed: {exc.detail}",
                )
            )
        except Exception as exc:
            # Unexpected
            logger.error(f"Unexpected error on threat {threat.threat_id}: {exc}")
            report_entries.append(
                RecommendationResponse(
                    threat_id=threat.threat_id,
                    recommendation="",
                    destructive=False,
                    approved=False,
                    notes=f"Unexpected error: {exc}",
                )
            )

    return BatchResponse(report=report_entries)


# ----------------------------------------------------------------------
# CSV Helper – can be used by an external CLI or another service
# ----------------------------------------------------------------------
def read_threats_from_csv(csv_path: str) -> List[Threat]:
    """Parse a CSV where the first column is `threat_id`."""
    threats: List[Threat] = []
    with open(csv_path, newline="", encoding="utf-8") as fp:
        reader = csv.DictReader(fp)
        for row in reader:
            threats.append(Threat(**row))
    return threats


# ----------------------------------------------------------------------
# If run locally as `python main.py --batch data.csv`, generate a report
# ----------------------------------------------------------------------
if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Batch process a CSV of threats.")
    parser.add_argument(
        "--batch",
        dest="csv_file",
        help="Path to CSV file containing threat data (threat_id, ...).",
    )
    args = parser.parse_args()

    if not args.csv_file:
        print("Error: --batch <csv_file> required when running as a script.", file=sys.stderr)
        sys.exit(1)

    threats = read_threats_from_csv(args.csv_file)
    batch_req = BatchRequest(threats=threats)
    # Reuse the FastAPI endpoint logic without the server
    from fastapi.testclient import TestClient

    client = TestClient(app)
    resp = client.post("/batch", json=batch_req.dict())
    if resp.status_code != 200:
        print(f"Batch failed: {resp.text}")
        sys.exit(1)

    # Pretty‑print the report
    report = resp.json()
    print(json.dumps(report, indent=2))
