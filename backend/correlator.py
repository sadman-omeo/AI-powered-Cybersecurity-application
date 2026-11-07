
import json
import re
from collections import defaultdict
from urllib.parse import unquote


def unique_records(entries):
    """Parse entries and ignore duplicate event/request IDs."""
    seen = set()

    for entry in entries:
        try:
            obj = json.loads(entry.text)
        except (json.JSONDecodeError, TypeError):
            continue

        if not isinstance(obj, dict):
            continue

        key = obj.get("event_id") or obj.get("request_id")

        if key:
            marker = (obj.get("app"), str(key))
            if marker in seen:
                continue
            seen.add(marker)

        yield entry.line_number, obj


def make_finding(kind, severity, ip, lines, reason, action):
    return {
        "attack_type": kind,
        "severity": severity,
        "identifier": ip,
        "evidence_lines": sorted(set(lines)),
        "reason": reason,
        "suggested_action": action,
        "sources": ["cross_chunk_rules"]
    }


def prior_context(entries):
    """Create compact memory from previously processed logs."""
    failures = defaultdict(list)

    for line, row in unique_records(entries):
        path = str(row.get("path", "")).lower()

        if row.get("auth_result") == "invalid_password" or (
            "/login" in path and row.get("status") == 401
        ):
            key = (
                row.get("app", "?"),
                row.get("client_ip", "?"),
                row.get("username", "?")
            )
            failures[key].append(line)

    pieces = []

    for (app, ip, user), lines in sorted(
        failures.items(),
        key=lambda pair: -len(pair[1])
    )[:5]:

        pieces.append(
            f"{app}/{ip}/{user}: {len(lines)} failed logins, "
            f"first L{lines[0]}, last L{lines[-1]}"
        )

    return "; ".join(pieces)[:450] or "No notable previous authentication pattern."


def correlate(entries):
    """Detect cross-chunk security patterns using the entire log."""

    auth = defaultdict(
        lambda: {
            "failed": [],
            "success": [],
            "later_access": []
        }
    )

    sql = defaultdict(list)
    scanning = defaultdict(list)

    rates = defaultdict(
        lambda: {
            "lines": [],
            "max_rate": 0,
            "blocked": 0
        }
    )

    for line, row in unique_records(entries):

        ip = str(row.get("client_ip", "")).strip()
        app = str(row.get("app", "?"))

        if not ip:
            continue

        path = str(row.get("path", ""))
        decoded = unquote(unquote(path)).lower()

        status = row.get("status")
        result = str(row.get("auth_result", "")).lower()
        username = str(row.get("username", "?"))

        auth_key = (app, ip, username)

        # Authentication patterns
        if "/login" in decoded:

            if result in ("invalid_password", "failure", "failed") or status == 401:
                auth[auth_key]["failed"].append(line)

            if result == "success" and status == 200:
                auth[auth_key]["success"].append(line)

        elif status == 200 and (
            "/admin/" in decoded or "/export" in decoded
        ):
            auth[auth_key]["later_access"].append(line)

        # SQL injection patterns
        if any(
            re.search(pattern, decoded)
            for pattern in (
                r"\bunion\s+select\b",
                r"\bor\s+\d+\s*=\s*\d+",
                r";\s*select\b",
                r"\bsleep\s*\("
            )
        ):
            sql[(app, ip)].append(line)

        # Sensitive file/path scanning
        if any(
            part in decoded
            for part in (
                "/.env",
                "/.git/",
                "/wp-admin",
                "/phpmyadmin",
                "etc/passwd",
                "../"
            )
        ):
            scanning[ip].append(
                (line, decoded.split("?")[0])
            )

        # Abnormally high request rates
        count = row.get("requests_in_window")
        window = row.get("window_seconds")

        if isinstance(count, (int, float)) and isinstance(window, (int, float)):
            if 0 < window <= 60 and count >= 80:
                item = rates[(app, ip)]
                item["lines"].append(line)
                item["max_rate"] = max(
                    item["max_rate"], count
                )
                item["blocked"] += (status == 429)

    findings = []

    # Connect failures with later successful logins
    for (_, ip, username), group in auth.items():

        failed = group["failed"]

        success = [
            line for line in group["success"]
            if failed and line > failed[0]
        ]

        if len(failed) < 3:
            continue

        followup = [
            line for line in group["later_access"]
            if success and line > success[0]
        ]

        compromised = bool(success)

        findings.append(
            make_finding(
                "Possible brute-force followed by access"
                if compromised else "Repeated failed logins",
                "High" if compromised else "Medium",
                ip,
                failed + success + followup,
                f"{len(failed)} failed logins for {username}"
                + (
                    " followed by successful authentication and later activity."
                    if compromised
                    else "; no successful login established."
                ),
                "Investigate login history, validate account ownership, "
                "enforce MFA and rate limits."
            )
        )

    # SQL injection attempts
    for (_, ip), lines in sql.items():

        findings.append(
            make_finding(
                "SQL injection attempt",
                "Medium",
                ip,
                lines,
                "SQL-style payloads appeared in request paths; "
                "success is not established.",
                "Inspect rejected requests, use parameterized queries "
                "and review WAF protections."
            )
        )

    # Reconnaissance and scanning
    for ip, occurrences in scanning.items():

        paths = {path for _, path in occurrences}

        if len(paths) >= 3:

            findings.append(
                make_finding(
                    "Sensitive-path scanning",
                    "Medium",
                    ip,
                    [line for line, _ in occurrences],
                    f"Requests targeted {len(paths)} different sensitive paths.",
                    "Review access controls, investigate exposed files "
                    "and block abusive scanning where appropriate."
                )
            )

    # Request-rate anomalies
    for (_, ip), data in rates.items():

        findings.append(
            make_finding(
                "Unusual request rate",
                "Medium",
                ip,
                data["lines"],
                f"Up to {data['max_rate']} requests in one short window; "
                f"{data['blocked']} logged rate-limit responses.",
                "Review client activity, verify authorized automation "
                "and apply rate limiting."
            )
        )

    return findings
