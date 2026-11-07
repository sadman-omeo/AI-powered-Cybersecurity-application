import json

from pathlib import Path
from dataclasses import dataclass


@dataclass(frozen=True)
class LogEntry:
    line_number: int
    text: str


def read_log(file_path):

    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(
            f"Log file not found: {path}"
        )

    if path.suffix.lower() not in {".log", ".txt"}:
        raise ValueError(
            "Only .log and .txt files are supported."
        )

    with path.open(
        "r",
        encoding="utf-8-sig"
    ) as file:

        for line_number, raw_line in enumerate(file, start=1):

            text = raw_line.rstrip("\r\n")

            if not text.strip():
                continue

            try:
                parsed = json.loads(text)

                text = json.dumps(
                    parsed,
                    separators=(",", ":"),
                    ensure_ascii=False
                )

            except json.JSONDecodeError:
                pass

            yield LogEntry(
                line_number=line_number,
                text=text
            )

