
import json
import sys

from backend.analyzer import run_analysis


DEFAULT_LOG = "data/Cultive8_Workspace_Agrigen_Server.log"


def main():

    log_path = (
        sys.argv[1]
        if len(sys.argv) > 1
        else DEFAULT_LOG
    )

    print("=" * 50)
    print("CULTIVE8 LOCAL AI SECURITY ANALYZER")
    print("=" * 50)

    print("Starting analysis...")
    print("Log file:", log_path)

    report = run_analysis(log_path)

    print("\n" + "=" * 50)
    print("ANALYSIS COMPLETE")
    print("=" * 50)

    print("Status:", report["status"])
    print("Entries:", report["total_entries"])
    print("Chunks:", report["chunks_processed"])
    print("Findings:", report["findings_count"])
    print("Errors:", len(report["errors"]))

    for finding in report["findings"]:

        print("\n" + "-" * 40)
        print("Attack:", finding["attack_type"])
        print("Severity:", finding["severity"])
        print("Identifier:", finding["identifier"])
        print("Lines:", finding["evidence_lines"])
        print("Reason:", finding["reason"])
        print("Action:", finding["suggested_action"])

    print("\nFull report: data/results/report.json")


if __name__ == "__main__":
    main()
