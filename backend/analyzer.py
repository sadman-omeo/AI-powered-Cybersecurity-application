
import json
import re
import time
from pathlib import Path

import requests

from backend.log_reader import read_log
from backend.model_client import LocalTokenizer
from backend.chunker import (
    create_chunks,
    build_messages,
    RESERVED_OUTPUT
)
from backend.correlator import correlate, prior_context


SEVERITY_ORDER = {
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4
}


FINDINGS_SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "maxItems": 2,
            "items": {
                "type": "object",
                "properties": {
                    "attack_type": {
                        "type": "string"
                    },
                    "severity": {
                        "type": "string",
                        "enum": [
                            "Low",
                            "Medium",
                            "High",
                            "Critical"
                        ]
                    },
                    "identifier": {
                        "type": "string"
                    },
                    "evidence_lines": {
                        "type": "array",
                        "items": {
                            "type": "integer"
                        }
                    },
                    "reason": {
                        "type": "string"
                    },
                    "suggested_action": {
                        "type": "string"
                    }
                },
                "required": [
                    "attack_type",
                    "severity",
                    "identifier",
                    "evidence_lines",
                    "reason",
                    "suggested_action"
                ],
                "additionalProperties": False
            }
        }
    },
    "required": ["findings"],
    "additionalProperties": False
}



def parse_findings(content, chunk):
    """Validate model JSON and original evidence lines."""

    raw = str(content or "").strip()

    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        left = raw.find("{")
        right = raw.rfind("}")

        if left < 0 or right <= left:
            raise ValueError("Model returned no JSON object")

        obj = json.loads(raw[left:right + 1])

    if not isinstance(obj, dict) or not isinstance(
        obj.get("findings"), list
    ):
        raise ValueError("Missing findings array in model JSON")

    known = {
        entry.line_number: entry.text
        for entry in chunk.entries
    }

    valid = []

    for item in obj["findings"]:

        if not isinstance(item, dict):
            continue

        identifier = str(item.get("identifier", "")).strip()

        if not identifier:
            continue

        evidence = []

        for value in item.get("evidence_lines", []):

            match = re.fullmatch(
                r"L?(\d+)",
                str(value).strip(),
                flags=re.I
            )

            if match:
                num = int(match.group(1))

                if num in known:
                    evidence.append(num)

        evidence = sorted(set(evidence))

        # Reject invented line references or identifiers
        if not evidence or not any(
            identifier in known[line]
            for line in evidence
        ):
            continue

        kind = str(item.get("attack_type", "")).strip()
        reason = str(item.get("reason", "")).strip()
        action = str(item.get("suggested_action", "")).strip()

        if not (kind and reason and action):
            continue

        severity = str(
            item.get("severity", "Medium")
        ).title()

        if severity not in SEVERITY_ORDER:
            severity = "Medium"

        valid.append({
            "attack_type": kind,
            "severity": severity,
            "identifier": identifier,
            "evidence_lines": evidence,
            "reason": reason,
            "suggested_action": action,
            "sources": ["local_ai"]
        })

    return valid


def category(name):
    """Normalize similar attack names for deduplication."""

    value = name.lower()

    if any(word in value for word in (
        "brute", "login", "password", "credential"
    )):
        return "authentication"

    if "sql" in value:
        return "sql_injection"

    if any(word in value for word in (
        "scan", "reconnaissance", "path traversal"
    )):
        return "scanning"

    if any(word in value for word in (
        "rate", "traffic", "flood", "dos"
    )):
        return "request_rate"

    return value


def consolidate(findings):
    """Merge repeated findings across chunks."""

    combined = {}

    for item in findings:

        key = (
            category(item["attack_type"]),
            item["identifier"]
        )

        if key not in combined:
            combined[key] = dict(item)
            continue

        existing = combined[key]

        existing["evidence_lines"] = sorted(set(
            existing["evidence_lines"]
            + item["evidence_lines"]
        ))

        existing["sources"] = sorted(set(
            existing["sources"]
            + item["sources"]
        ))

        if (
            SEVERITY_ORDER[item["severity"]]
            > SEVERITY_ORDER[existing["severity"]]
        ):
            existing["severity"] = item["severity"]

        # Prefer findings established across the complete log
        if "cross_chunk_rules" in item["sources"]:
            existing["attack_type"] = item["attack_type"]
            existing["reason"] = item["reason"]
            existing["suggested_action"] = item["suggested_action"]

    return sorted(
        combined.values(),
        key=lambda f: (
            -SEVERITY_ORDER[f["severity"]],
            f["identifier"]
        )
    )


def run_analysis(
    log_path,
    output_dir="data/results",
    on_progress=None
):

    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    entries = list(read_log(log_path))

    if not entries:
        raise ValueError("The log file has no readable entries")

    base_url = "http://127.0.0.1:8080"
    tokenizer = LocalTokenizer(base_url)

    response = tokenizer.session.get(
        f"{base_url}/v1/models",
        timeout=15
    )

    response.raise_for_status()

    model_id = response.json()["data"][0]["id"]

    processed = 0
    chunk_count = 0
    errors = []
    ai_findings = []

    start_time = time.perf_counter()

    journal_path = output / "chunk_results.jsonl"

    with journal_path.open(
        "w", encoding="utf-8"
    ) as journal:

        while processed < len(entries):

            # Rebuild context from all previously processed entries
            context = prior_context(entries[:processed])

            # Create one chunk with the current context budget
            chunk = next(
                create_chunks(
                    entries[processed:],
                    tokenizer,
                    saved_context=context
                )
            )

            messages = build_messages(
                chunk.entries,
                saved_context=context
            )

            chunk_count += 1

            chunk_findings = []
            error = None

            started = time.perf_counter()

            # Retry once after a failed request or invalid JSON
            for attempt in range(2):

                try:
                    reply = tokenizer.session.post(
                        f"{base_url}/v1/chat/completions",
                        json={
                            "model": model_id,
                            "messages": messages,
                            "temperature": 0.1,
                            "max_tokens": RESERVED_OUTPUT,
                            "stream": False,
                            "response_format": {
                                "type": "json_schema",
                                "schema": FINDINGS_SCHEMA
                            }
                        },
                        timeout=180
                    )

                    reply.raise_for_status()

                    choice = reply.json()["choices"][0]
                    message = choice["message"]

                    content = (message.get("content") or "").strip()

                    if choice.get("finish_reason") == "length":
                        raise ValueError(
                            "Model response exceeded output token limit"
                        )

                    if not content:
                        raise ValueError(
                            "Empty model response. "
                            f"Finish reason: {choice.get('finish_reason')}. "
                            f"Reasoning characters: "
                            f"{len(message.get('reasoning_content') or '')}"
                        )

                    chunk_findings = parse_findings(
                        content, chunk
                    )

                    error = None
                    break

                except (
                    requests.RequestException,
                    ValueError,
                    KeyError,
                    IndexError,
                    TypeError
                ) as exc:

                    error = (
                        f"Chunk {chunk_count}, "
                        f"attempt {attempt + 1}: {exc}"
                    )

            if error:
                errors.append(error)

            ai_findings.extend(chunk_findings)

            processed += len(chunk.entries)

            # Save findings immediately after every chunk
            record = {
                "chunk": chunk_count,
                "start_line": chunk.entries[0].line_number,
                "end_line": chunk.entries[-1].line_number,
                "prompt_tokens": chunk.prompt_tokens,
                "duration_seconds": round(
                    time.perf_counter() - started, 2
                ),
                "findings": chunk_findings,
                "error": error
            }

            journal.write(
                json.dumps(record, ensure_ascii=False) + "\n"
            )

            journal.flush()

            print(
                f"Chunk {chunk_count}: "
                f"{processed}/{len(entries)} entries, "
                f"{len(chunk_findings)} AI findings"
                + (f" | ERROR: {error}" if error else ""),
                flush=True
            )

            if on_progress:
                on_progress({
                    "processed": processed,
                    "total": len(entries),
                    "chunks": chunk_count,
                    "errors": len(errors)
                })

    # Combine AI results with cross-chunk Python detection
    findings = consolidate(
        ai_findings + correlate(entries)
    )

    report = {
        "status": "complete" if not errors else "partial",
        "log_file": Path(log_path).name,
        "total_entries": len(entries),
        "chunks_processed": chunk_count,
        "local_model": model_id,
        "duration_seconds": round(
            time.perf_counter() - start_time, 2
        ),
        "findings_count": len(findings),
        "findings": findings,
        "errors": errors
    }

    (output / "report.json").write_text(
        json.dumps(
            report,
            indent=2,
            ensure_ascii=False
        ),
        encoding="utf-8"
    )

    return report
