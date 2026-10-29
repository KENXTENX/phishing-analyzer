"""Measure accuracy on labeled emails: eval/phishing/*.eml and eval/legit/*.eml.

python evaluate.py               rules + AI (uses the API, about a penny per 10 emails)
python evaluate.py --rules-only  rules only (free)
"""
import csv
import sys
import time
from pathlib import Path

from email_parser import parse_email
from rules import check_email

RULES_ONLY = "--rules-only" in sys.argv


def load_set(folder, label):
    return [(path, label) for path in sorted(Path(folder).glob("*.eml"))]


def rate(part, whole):
    return f"{part}/{whole} ({part / whole:.0%})" if whole else "n/a"


def summarize(rows, key):
    phish = [r for r in rows if r["label"] == "phishing"]
    legit = [r for r in rows if r["label"] == "legit"]
    return {
        "Phishing caught (called Phishing)": rate(sum(r[key] == "Phishing" for r in phish), len(phish)),
        "Phishing flagged (Phishing or Suspicious)": rate(sum(r[key] != "Likely safe" for r in phish), len(phish)),
        "False alarms (legit called Phishing)": rate(sum(r[key] == "Phishing" for r in legit), len(legit)),
        "Legit flagged (Phishing or Suspicious)": rate(sum(r[key] != "Likely safe" for r in legit), len(legit)),
    }


def main():
    emails = load_set("eval/phishing", "phishing") + load_set("eval/legit", "legit")
    if not emails:
        print("No emails found. Put .eml files in eval/phishing/ and eval/legit/.")
        return

    client = None
    if not RULES_ONLY:
        import anthropic
        from llm import analyze_with_llm
        client = anthropic.Anthropic()

    rows = []
    for i, (path, label) in enumerate(emails, 1):
        info = parse_email(path.read_bytes())
        rules_result = check_email(info)
        row = {"file": path.name, "label": label,
               "rule_score": rules_result["score"], "rules": rules_result["verdict"],
               "ai": "", "ai_confidence": ""}
        if client:
            try:
                ai = analyze_with_llm(info, rules_result, client)
                row["ai"], row["ai_confidence"] = ai["verdict"], ai["confidence"]
            except Exception as error:
                row["ai"] = "ERROR"
                print(f"  AI error on {path.name}: {error}")
                time.sleep(2)
        rows.append(row)
        print(f"[{i}/{len(emails)}] {label:8} rules={row['rules']:11} ai={row['ai'] or '-':11} {path.name[:50]}")

    with open("results.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    n_phish = sum(r["label"] == "phishing" for r in rows)
    n_legit = len(rows) - n_phish
    columns = {"Rules only": summarize(rows, "rules")}
    if client:
        columns["Rules + AI"] = summarize([r for r in rows if r["ai"] != "ERROR"], "ai")

    lines = [f"Tested on {n_phish} phishing and {n_legit} legitimate emails.", "",
             "| Metric | " + " | ".join(columns) + " |",
             "|---|" + "---|" * len(columns)]
    for metric in next(iter(columns.values())):
        lines.append(f"| {metric} | " + " | ".join(c[metric] for c in columns.values()) + " |")
    table = "\n".join(lines)

    Path("results.md").write_text(table + "\n")
    print("\n" + table)
    print("\nPer-email results: results.csv   Summary table: results.md")

    misses = [r for r in rows if (r["label"] == "phishing" and (r["ai"] or r["rules"]) == "Likely safe")
              or (r["label"] == "legit" and (r["ai"] or r["rules"]) == "Phishing")]
    if misses:
        print("\nMistakes worth reading:")
        for r in misses:
            print(f"  {r['label']:8} -> {r['ai'] or r['rules']:11} {r['file']}")


if __name__ == "__main__":
    main()