## Description
Summary: This GitHub project focuses on developing AI-powered anti-ransomware bots.

The goal of these bots is to automatically generate code that can detect, neutralize, and remove ransomware threats from computer systems. By leveraging OpenAI's GPT OSS 20B and real-time threat analysis, the bots can quickly identify unusual behavior patterns associated with ransomware. They then respond by isolating the affected files, stopping the malicious process, and restoring any compromised data from backups. This proactive approach helps protect users and organizations from the damaging effects of ransomware attacks, making data recovery faster and reducing potential losses.

## Ideas
- Using Ollama with gpt-os-20b
  
## How to install ollama
- Install Ollama → Get it here
### For 20B
- ollama pull gpt-oss:20b
 
### For 120B
- ollama pull gpt-oss:120b

## Malware Killer.py
#### How the script works

1. **Prompt the LLM** – The user supplies a base directory to scan, and the script sends a carefully‑worded prompt to Ollama.  
2. **LLM returns a single‑shot Python snippet** – Only pure Python code is returned (no extraneous text).  
3. **Dry run vs. kill** – By default the script prints the LLM output and **does not** execute it. If the user explicitly confirms (`y/N`), the generated code is run, but it will still only terminate processes if it’s certain that *the user* approved it.  
4. **Execution safety** – The script captures stdout/stderr, uses a 45‑second timeout, and prints the result.
> **⚠️ IMPORTANT**  
> * This script is for educational / defensive use only.  
> * Do **not** run it on systems that contain critical data unless you are absolutely sure that the model’s suggestions are safe.  
> * Always double‑check the LLM’s outputs before executing any destructive actions.  
> * Consider integrating established AV/EDR solutions instead of a hand‑rolled LLM‑based agent for production environments.

## Cybersecurity Assistant bot.py
## How it all fits together

| Feature | Implementation |
|---------|----------------|
| **Ollama integration** | `ollama_client.chat.completions.create(...)` using `/gpt-oss:20b`. |
| **Safety checks** | `_is_destructive()` flags risky verbs; callers must set `confirm=True` in the payload; otherwise a 400 error is returned. |
| **Audit logging** | Every recommendation is written to a `audit.log` file with restricted permissions (`chmod 600`). |
| **Batch mode** | `read_threats_from_csv()` + `/batch` endpoint produce a single JSON report. |
| **REST endpoint** | FastAPI endpoints `/recommend` and `/batch` expose the service. |
| **Secure environment** | Log file is owned by the service user; the API uses HTTPS in production (recommended). |

## Running the service

1. **Install dependencies**  
   ```bash
   pip install fastapi[all] pydantic ollama
   ```

2. **Start Ollama** (if it’s not running):  
   ```bash
   ollama serve
   ```

3. **Run the API** (use an ASGI server such as Uvicorn):  
   ```bash
   uvicorn main:app --host 0.0.0.0 --port 8000
   ```

4. **Call the service**  

   - *Single threat*  
     ```bash
     curl -XPOST http://localhost:8000/recommend \
          -H "Content-Type: application/json" \
          -d '{
                "threat": {
                  "threat_id": "malware-123",
                  "file_path": "C:\\Users\\admin\\Downloads\\evil.exe",
                  "sha256": "abcd1234...etc"
                },
                "confirm": true
              }'
     ```

   - *Batch (CSV)*  
     ```bash
     python main.py --batch threats.csv
     ```




