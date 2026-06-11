"""ThreatTriage CLI.

Usage:
    python -m threattriage 8.8.8.8
    python -m threattriage evil.com 1.2.3.4 <sha256> --html report.html
    python -m threattriage 45.155.205.99 --json
"""
import argparse
import sys
from .triage import triage
from . import report


def main(argv=None):
    ap = argparse.ArgumentParser(prog="threattriage",
                                 description="Enrich and triage IOCs (IP, hash, domain, URL).")
    ap.add_argument("indicators", nargs="+", help="one or more IPs, hashes, domains, or URLs")
    ap.add_argument("--json", action="store_true", help="output JSON")
    ap.add_argument("--html", metavar="FILE", help="write an HTML report to FILE")
    ap.add_argument("--no-color", action="store_true", help="disable terminal colors")
    args = ap.parse_args(argv)

    reports = [triage(i) for i in args.indicators]

    if args.json:
        print(report.render_json(reports if len(reports) > 1 else reports[0]))
    else:
        for rep in reports:
            print(report.render_terminal(rep, color=not args.no_color))

    if args.html:
        html = "\n<hr>\n".join(report.render_html(r) for r in reports)
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(html)
        print("  HTML report written to %s" % args.html)

    # exit non-zero if anything is malicious (handy for automation/CI)
    return 2 if any(r["verdict"] == "MALICIOUS" for r in reports) else 0


if __name__ == "__main__":
    sys.exit(main())
