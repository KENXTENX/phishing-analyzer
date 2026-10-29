"""Read a .eml file and pull out the facts a phishing check needs."""
import email
import html as html_lib
import re
import sys
from email import policy
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import Path

URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)
# Invisible characters marketers use to pad preview text
INVISIBLE_RE = re.compile("[\u00ad\u034f\u200b-\u200f\u2060\ufeff]")


class LinkCollector(HTMLParser):
    """Collects visible text and every <a href> (with the text the reader sees)."""

    def __init__(self):
        super().__init__()
        self.links = []
        self.text_parts = []
        self._href = None
        self._link_text = []
        self._skip = False

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip = True
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._link_text = []

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self._skip = False
        if tag == "a" and self._href and self._href.lower().startswith("http"):
            self.links.append({"url": self._href, "text": " ".join(self._link_text).strip()})
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.text_parts.append(data)
        if self._href is not None:
            self._link_text.append(data.strip())


def domain_of(address):
    """'Name <me@Example.com>' -> 'example.com'"""
    return address.split("@")[-1].strip().lower() if "@" in address else ""


def auth_result(auth_header, check):
    """Find spf=pass / dkim=fail / dmarc=none in the Authentication-Results header."""
    match = re.search(rf"\b{check}=(\w+)", auth_header, re.IGNORECASE)
    return match.group(1).lower() if match else "missing"


def read_part(part):
    try:
        return part.get_content()
    except Exception:
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace")


def parse_email(raw_bytes):
    msg = email.message_from_bytes(raw_bytes, policy=policy.default)

    from_name, from_addr = parseaddr(str(msg.get("From", "")))
    reply_to = parseaddr(str(msg.get("Reply-To", "")))[1]
    to_address = parseaddr(str(msg.get("To", "")))[1]
    return_path = parseaddr(str(msg.get("Return-Path", "")))[1]
    auth = " ".join(str(h) for h in (msg.get_all("Authentication-Results") or []))

    plain, html, attachments = [], [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        if part.get_content_disposition() == "attachment":
            attachments.append(part.get_filename() or "unnamed")
        elif part.get_content_type() == "text/plain":
            plain.append(read_part(part))
        elif part.get_content_type() == "text/html":
            html.append(read_part(part))

    collector = LinkCollector()
    for chunk in html:
        collector.feed(chunk)

    links = list(collector.links)
    seen = {link["url"] for link in links}
    for text in plain + collector.text_parts:
        for url in URL_RE.findall(text):
            if url not in seen:
                links.append({"url": url, "text": ""})
                seen.add(url)

    body = "\n".join(plain) if plain else " ".join(collector.text_parts)
    body = INVISIBLE_RE.sub("", body)
    body = re.sub(r"\s+", " ", body).strip()

    return {
        "from_name": from_name,
        "from_address": from_addr,
        "from_domain": domain_of(from_addr),
        "reply_to": reply_to,
        "reply_to_domain": domain_of(reply_to),
        "to_address": to_address,
        "return_path_domain": domain_of(return_path),
        "subject": html_lib.unescape(str(msg.get("Subject", ""))),
        "spf": auth_result(auth, "spf"),
        "dkim": auth_result(auth, "dkim"),
        "dmarc": auth_result(auth, "dmarc"),
        "links": links,
        "attachments": attachments,
        "body": body[:5000],
    }


if __name__ == "__main__":
    files = [Path(p) for p in sys.argv[1:]] or sorted(Path("samples").glob("*.eml"))
    for path in files:
        info = parse_email(path.read_bytes())
        print(f"\n=== {path.name} ===")
        print(f"From:      {info['from_name']} <{info['from_address']}>")
        print(f"Reply-To:  {info['reply_to'] or '(none)'}")
        print(f"Subject:   {info['subject']}")
        print(f"SPF / DKIM / DMARC: {info['spf']} / {info['dkim']} / {info['dmarc']}")
        print(f"Links ({len(info['links'])}):")
        for link in info["links"][:5]:
            shown = f'  "{link["text"][:40]}"' if link["text"] else ""
            print(f"  - {link['url'][:80]}{shown}")
        if len(info["links"]) > 5:
            print(f"  ...and {len(info['links']) - 5} more")
        print(f"Attachments: {', '.join(info['attachments']) or '(none)'}")
        print(f"Body preview: {info['body'][:150]}")