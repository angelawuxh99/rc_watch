import os, json, hashlib, csv, io
from datetime import datetime, timezone
import requests, yaml
from bs4 import BeautifulSoup
import smtplib
from email.mime.text import MIMEText

USCIS_RC_CSV = "https://www.uscis.gov/sites/default/files/document/web-content/eb5rgncntrs.csv"
STATE_FILE = "state.json"
SOURCES_FILE = "rc_sources.yml"

RECIPIENTS = [
    "angelawuxh@outlook.com",
    "jensonacdc98@outlook.com"
]

def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()[:16]

def load_state():
    if os.path.exists(STATE_FILE):
        return json.load(open(STATE_FILE))
    return {"seen": {}}

def save_state(state):
    json.dump(state, open(STATE_FILE, "w"), indent=2)

def fetch_rc_list():
    r = requests.get(USCIS_RC_CSV, timeout=60)
    r.raise_for_status()
    reader = csv.DictReader(io.StringIO(r.text))
    rc_list = []
    for row in reader:
        rc_list.append({
            "rc_name": row["Regional Center"].strip(),
            "rc_id": row["Regional Center ID"].strip()
        })
    return rc_list

def load_sources():
    if not os.path.exists(SOURCES_FILE):
        return {}
    return yaml.safe_load(open(SOURCES_FILE)) or {}

def scan_page(url):
    headers = {"User-Agent": "Mozilla/5.0"}
    r = requests.get(url, headers=headers, timeout=60)
    r.raise_for_status()
    soup = BeautifulSoup(r.text, "html.parser")

    links = []
    for a in soup.select("a[href]"):
        href = a["href"]
        title = a.get_text(strip=True)
        if not title:
            continue
        full = requests.compat.urljoin(url, href)
        links.append((title, full))
    return links

def send_email(body):
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = "EB-5 RC Daily Digest"
    msg["From"] = os.environ["SMTP_USER"]
    msg["To"] = ", ".join(RECIPIENTS)

    with smtplib.SMTP(os.environ["SMTP_HOST"], int(os.environ.get("SMTP_PORT", 587))) as s:
        s.starttls()
        s.login(os.environ["SMTP_USER"], os.environ["SMTP_PASS"])
        s.sendmail(msg["From"], RECIPIENTS, msg.as_string())

def main():
    rc_list = fetch_rc_list()
    sources = load_sources()
    state = load_state()
    findings = []

    for rc in rc_list:
        rc_id = rc["rc_id"]
        rc_name = rc["rc_name"]

        if rc_id not in sources:
            continue

        for url in sources[rc_id].get("urls", []):
            try:
                links = scan_page(url)
            except:
                continue

            for title, link in links:
                if any(k in title.lower() for k in ["project", "offering", "eb-5", "tea"]):
                    key = sha(link)
                    if key in state["seen"]:
                        continue
                    state["seen"][key] = datetime.now(timezone.utc).isoformat()
                    findings.append(f"{rc_name}\n{title}\n{link}\n")

    if not findings:
        body = "No new/updated RC projects found in the last 3 months today."
    else:
        body = "EB-5 RC Daily Digest\n\n" + "\n".join(findings)

    send_email(body)
    save_state(state)

if __name__ == "__main__":
    main()
