
import json

from backend.log_reader import read_log
from backend.chunker import build_messages, LogChunk
from backend.model_client import LocalTokenizer
from backend.analyzer import (
    FINDINGS_SCHEMA,
    parse_findings
)


entries = [
    entry
    for entry in read_log(
        "data/Cultive8_Workspace_Agrigen_Server.log"
    )
    if entry.line_number in (29, 30, 32)
]

client = LocalTokenizer()

model = client.session.get(
    "http://127.0.0.1:8080/v1/models"
).json()["data"][0]["id"]

messages = build_messages(entries)

token_count = client.count_messages(messages)

print("Input tokens:", token_count)

assert token_count + 650 + 96 <= 2048

response = client.session.post(
    "http://127.0.0.1:8080/v1/chat/completions",
    json={
        "model": model,
        "messages": messages,
        "temperature": 0,
        "max_tokens": 650,
        "stream": False,
        "response_format": {
            "type": "json_schema",
            "schema": FINDINGS_SCHEMA
        }
    },
    timeout=180
)

response.raise_for_status()

result = response.json()["choices"][0]

print("Finish reason:", result["finish_reason"])
print("AI response:")
print(result["message"].get("content"))

if result["finish_reason"] == "stop":

    chunk = LogChunk(
        index=1,
        entries=tuple(entries),
        prompt_tokens=token_count
    )

    findings = parse_findings(
        result["message"]["content"],
        chunk
    )

    print("\nValidated AI findings:")
    print(json.dumps(findings, indent=2))
