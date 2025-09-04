from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:11434/v1",  # Local Ollama API
    api_key="ollama"                       # Dummy key
)
 
response = client.chat.completions.create(
    model="gpt-oss:20b",
    messages=[
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "Generate service program in python code to find lua files in golang that perform encrypt, or destroy and quarantine the files.  "}
    ]
)
 
print(response.choices[0].message.content)
