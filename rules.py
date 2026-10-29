"""Turn the facts from email_parser into red flags and a risk score."""
import ipaddress
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

import tldextract

from email_parser import parse_email

# Offline mode: use tldextract's built-in list instead of downloading one
extract = tldextract.TLDExtract(suffix_list_urls=())

# Brands phishers love to fake, and the real domains they send from
BRANDS = {
    "paypal": ["paypal.com"],
    "apple": ["apple.com", "icloud.com"],
    "microsoft": ["microsoft.com", "office.com", "live.com", "outlook.com",
                  "windows.net", "sharepoint.com", "microsoftonline.com"],
    "amazon": ["amazon.com", "amazonaws.com"],
    "netflix": ["netflix.com"],
    "google": ["google.com", "gmail.com", "googleapis.com", "googleusercontent.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "usps": ["usps.com"],
    "fedex": ["fedex.com"],
    "coinbase": ["coinbase.com"],
    "irs": ["irs.gov"],
}

SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "cutt.ly",
              "rebrand.ly", "shorturl.at", "rb.gy", "tiny.cc"}

# Free hosting that phishers use for fake pages (real brands rarely link here in email)
FREE_HOSTING = ("storage.googleapis.com", "firebasestorage.googleapis.com", "web.app",
                "firebaseapp.com", "blob.core.windows.net", "s3.amazonaws.com",
                "pages.dev", "r2.dev", "workers.dev", "netlify.app", "glitch.me",
                "ipfs.io", "sites.google.com", "forms.gle", "wixsite.com", "weebly.com")

RISKY_ATTACHMENTS = (".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".iso",
                     ".img", ".htm", ".html", ".docm", ".xlsm", ".zip", ".rar")

URGENT_PHRASES = ["urgent", "suspended", "verify your account", "immediately",
                  "within 24 hours", "unusual activity", "confirm your identity",
                  "account will be closed", "final notice", "act now", "locked"]

# Prize and giveaway bait
LURE_PHRASES = ["you've won", "you have won", "winner", "congratulations",
                "claim your", "free gift", "gift card", "reward", "prize",
                "you have been selected", "you've been selected"]

# Text aimed at AI tools that read the email (prompt injection)
INJECTION_RE = re.compile(
    r"ignore (all |any )?(previous|prior|above) instructions"
    r"|ai (assistant|model|system)"
    r"|mark (this|it) (email )?as (safe|legitimate)"
    r"|system prompt",
    re.IGNORECASE,
)

POINTS = {"high": 30, "medium": 15, "low": 5}

# Swap digits/symbols back to letters: paypa1 -> paypal, micr0soft -> microsoft
LOOKALIKE_SWAPS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "@": "a"})


def base_domain(domain_or_url):
    """'https://click.e.equifax.com/x' -> 'equifax.com'"""
    host = urlparse(domain_or_url).hostname if "://" in domain_or_url else domain_or_url
    parts = extract(host or "")
    return f"{parts.domain}.{parts.suffix}".lower() if parts.suffix else (host or "").lower()


def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def brand_lookalike(domain):
    """Return the brand a domain is pretending to be, or None."""
    real = base_domain(domain)
    squashed = real.replace("-", "").translate(LOOKALIKE_SWAPS)
    for brand, official in BRANDS.items():
        if brand in squashed and real not in official:
            return brand
    return None


def is_free_hosting(host):
    return any(host == h or host.endswith("." + h) for h in FREE_HOSTING)


def check_email(info):
    flags = []

    def flag(severity, title, detail):
        item = {"severity": severity, "flag": title, "detail": detail}
        if item not in flags:  # skip exact repeats (same flag, same link)
            flags.append(item)

    # 1. Sender authentication
    if info["spf"] in ("fail", "softfail"):
        flag("high", "SPF failed", "The sending server isn't authorized to send for this domain.")
    if info["dmarc"] == "fail":
        flag("high", "DMARC failed", "The From address doesn't line up with who actually sent it.")
    if info["dkim"] in ("fail", "permerror", "temperror"):
        flag("medium", "DKIM failed", "The email's digital signature didn't check out.")
    if info["dkim"] == "missing" and info["dmarc"] == "missing":
        flag("low", "No DKIM or DMARC", "The sender didn't sign the email, so it's easier to fake.")

    # 2. Reply-To goes somewhere else
    from_base = base_domain(info["from_domain"])
    if info["reply_to_domain"] and base_domain(info["reply_to_domain"]) != from_base:
        flag("high", "Reply-To mismatch",
             f"Sent from {from_base}, but replies go to {base_domain(info['reply_to_domain'])}.")

    # 3. Display name claims a brand the domain doesn't belong to
    name = re.sub(r"[^a-z]", "", info["from_name"].lower())
    for brand, official in BRANDS.items():
        if brand in name and from_base not in official:
            flag("high", "Brand impersonation",
                 f"Display name says '{info['from_name']}' but the address is @{info['from_domain']}.")
            break

    # 4. Sender domain is a lookalike
    fake = brand_lookalike(info["from_domain"])
    if fake:
        flag("high", "Lookalike sender domain", f"{info['from_domain']} imitates {fake}.")

    # 5. Links
    for link in info["links"]:
        url = link["url"]
        host = (urlparse(url).hostname or "").lower()
        link_base = base_domain(url)

        if is_ip(host):
            flag("high", "Link to a raw IP address", url[:100])
        if is_free_hosting(host):
            flag("medium", "Link to free cloud hosting",
                 f"{host} is free file hosting that phishers often use for fake pages.")
        if host in SHORTENERS or link_base in SHORTENERS:
            flag("medium", "Shortened link hides the destination", url[:100])
        fake = brand_lookalike(host)
        if fake:
            flag("high", "Lookalike link domain", f"{host} imitates {fake}.")

        # Link text shows one website but the link goes to another
        text = link["text"].strip().lower()
        shown = re.sub(r"^https?://", "", text).split("/")[0]
        if " " not in text and "." in shown:
            shown_base = base_domain(shown)
            if shown_base and shown_base != link_base:
                flag("medium", "Link text doesn't match destination",
                     f"Shows '{link['text'][:60]}' but goes to {link_base}.")

    # 6. Dangerous attachments
    for name in info["attachments"]:
        if name.lower().endswith(RISKY_ATTACHMENTS):
            flag("high", "Risky attachment", name)

    # 7. Pressure language
    text = f"{info['subject']} {info['body']}".lower()
    hits = [p for p in URGENT_PHRASES if p in text]
    if hits:
        flag("low" if len(hits) < 3 else "medium", "Urgency or threat language", ", ".join(hits))

    # 8. Prize and giveaway bait
    lures = [p for p in LURE_PHRASES if p in text]
    if lures:
        flag("medium" if len(lures) >= 2 else "low", "Prize or giveaway bait", ", ".join(lures))

    # 9. Greets you by your email username instead of your name
    username = re.sub(r"\d+$", "", info.get("to_address", "").split("@")[0].split("+")[0]).lower()
    opening = f"{info['subject']} {info['body'][:200]}".lower()
    if len(username) >= 5 and re.search(rf"\b{re.escape(username)}\b", opening):
        flag("medium", "Greets you by your email username",
             f"Addresses you as '{username}' (your email username), a sign of a bulk mailing.")

    # 10. Hidden instructions for AI tools
    match = INJECTION_RE.search(info["body"])
    if match:
        flag("high", "Prompt injection attempt",
             f"The email contains text aimed at AI tools: '{match.group(0)}'.")

    # Score: add up points, but count each type of flag only once
    seen, score = set(), 0
    for f in flags:
        if f["flag"] not in seen:
            score += POINTS[f["severity"]]
            seen.add(f["flag"])
    score = min(score, 100)

    if score >= 50:
        verdict = "Phishing"
    elif score >= 20:
        verdict = "Suspicious"
    else:
        verdict = "Likely safe"

    return {"score": score, "verdict": verdict, "flags": flags}


if __name__ == "__main__":
    files = [Path(p) for p in sys.argv[1:]] or sorted(Path("samples").glob("*.eml"))
    for path in files:
        result = check_email(parse_email(path.read_bytes()))
        print(f"\n=== {path.name} ===")
        print(f"Score: {result['score']}/100  ->  {result['verdict']}")
        for f in result["flags"][:8]:
            print(f"  [{f['severity'].upper()}] {f['flag']}: {f['detail']}")
        if len(result["flags"]) > 8:
            print(f"  ...and {len(result['flags']) - 8} more flags")