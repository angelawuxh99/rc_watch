import os, re, json, csv, io, time, hashlib
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

import requests
from bs4 import BeautifulSoup
from dateutil.parser import parse as dtparse
import smtplib
from email.mime.text import MIMEText

USCIS_RC_CSV = "https://www.uscis.gov/sites/default/files/document/web-content/eb5rgncntrs.csv"

DATA_DIR = "data"
REGISTRY_PATH = os.path.join(DATA_DIR, "rc_registry.json")
SEEN_PATH = os.path.join(DATA_DIR, "seen.json")
CURSOR_PATH = os.path.join(DATA_DIR, "cursor.json")

RECIPIENTS = ["angelawuxh@outlook.com", "jensonacdc98@outlook.com"]

BATCH_SIZE = int(os.getenv("BATCH_SIZE", "80"))
MAX_SITE_PAGES = int(os.getenv("MAX_SITE_PAGES", "40"))
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "20"))

LOOKBACK_DAYS = 92  # ~3 months

UA = "Mozilla/5.0 (compatible; eb5-rc-scanner/2.0; +https://github.com/)"

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:16]

def ensure_data_dir():
    os.makedirs(DATA_DIR, exist_ok=True)

def load_json(path: str, default):
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return default

def save_json(path: str, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)

def http_get(url: str) -> Optional[requests.Response]:
    try:
        r = requests.get(url, headers={"User-Agent": UA}, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        if r.status_code >= 400:
            return None
        return r
    except Exception:
        return None

def fetch_uscis_rc_list() -> List[Dict[str, str]]:
    r = requests.get(USCIS_RC_CSV, headers={"User-Agent": UA}, timeout=REQUEST_TIMEOUT)
    r.raise_for_status()
    reader = csv.DictReader(io.StringIO(r.text))
    out = []
    for row in reader:
        out.append({
            "state": (row.get("State") or "").strip(),
            "rc_name": (row.get("Regional Center") or "").strip(),
            "rc_id": (row.get("Regional Center ID") or "").strip(),
        })
    return [x for x in out if x["rc_id"] and x["rc_name"]]

def normalize_name(s: str) -> str:
    s = s.lower()
    s = re.sub(r"[^a-z0-9\s&-]", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    for suf in ["regional center", "regional centres", "llc", "l.l.c", "inc", "corp", "corporation", "ltd", "limited", "company", "co", "group", "partners", "partner"]:
        s = re.sub(rf"\b{re.escape(suf)}\b", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s

def token_set(s: str) -> set:
    return set(normalize_name(s).split())

def jaccard(a: set, b: set) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)

def best_rc_match(issuer: str, rc_aliases: Dict[str, List[str]], threshold: float = 0.55) -> Optional[Tuple[str, float]]:
    iss_t = token_set(issuer)
    best = ("", 0.0)
    for rc_id, aliases in rc_aliases.items():
        for al in aliases:
            sc = jaccard(iss_t, token_set(al))
            if sc > best[1]:
                best = (rc_id, sc)
    return best if best[1] >= threshold else None

def guess_domains(name: str) -> List[str]:
    base = normalize_name(name)
    if not base:
        return []
    base = base.replace("&", "and")
    parts = base.split()
    cands = set()
    join1 = "".join(parts)
    join2 = "-".join(parts)
    join3 = "".join(parts[:3]) if len(parts) >= 3 else join1
    for j in [join1, join2, join3]:
        for tld in [".com", ".org", ".net"]:
            cands.add(j + tld)
    return [c for c in cands if len(c) >= 8][:25]

def try_discover_site(rc_name: str) -> Optional[str]:
    signals = re.compile(r"\b(eb-5|regional\s+center|immigrant\s+investor|I-526|I-829|I-956F)\b", re.I)
    for dom in guess_domains(rc_name):
        for scheme in ["https://", "http://"]:
            url = scheme + dom
            r = http_get(url)
            if not r or not r.text:
                continue
            text = r.text[:50000]
            if signals.search(text):
                return r.url
    return None

def extract_links(base_url: str, html: str) -> List[str]:
    soup = BeautifulSoup(html, "html.parser")
    links = []
    for a in soup.select("a[href]"):
        href = (a.get("href") or "").strip()
        if not href or href.startswith("#") or href.startswith("mailto:") or href.startswith("javascript:"):
            continue
        links.append(requests.compat.urljoin(base_url, href))
    seen = set()
    out = []
    for u in links:
        if u in seen:
            continue
        seen.add(u)
        out.append(u)
    return out

def rank_candidate_pages(urls: List[str]) -> List[str]:
    pri, sec = [], []
    for u in urls:
        lu = u.lower()
        if any(k in lu for k in ["project", "offering", "offerings", "investment", "eb5", "eb-5", "news", "press", "updates", "blog"]):
            pri.append(u)
        else:
            sec.append(u)
    return pri + sec

def parse_page_date(text: str) -> Optional[datetime]:
    m = re.search(r"\b(20\d{2}-\d{2}-\d{2})\b", text)
    if m:
        try:
            return dtparse(m.group(1)).astimezone(timezone.utc)
        except Exception:
            pass
    m2 = re.search(r"\b(Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+\d{1,2},\s+20\d{2}\b", text, re.I)
    if m2:
        try:
            return dtparse(m2.group(0)).astimezone(timezone.utc)
        except Exception:
            pass
    return None

def scan_site_for_updates(rc_id: str, rc_name: str, site: str, seen: Dict[str, dict]) -> List[dict]:
    findings = []
    r = http_get(site)
    if not r or not r.text:
        return findings
    links = extract_links(r.url, r.text)
    candidates = rank_candidate_pages([r.url] + links)
    cutoff = now_utc() - timedelta(days=LOOKBACK_DAYS)
    kw = re.compile(r"\b(project|offering|subscription|I-956F|rural|TEA|exemplar|Form\s+D|loan|equity)\b", re.I)

    fetched = 0
    for u in candidates:
        if fetched >= MAX_SITE_PAGES:
            break
        rr = http_get(u)
        fetched += 1
        if not rr or not rr.text:
            continue
        if sha(rr.url) in seen:
            continue
        text = BeautifulSoup(rr.text, "html.parser").get_text(" ", strip=True)
        if not kw.search(text):
            continue
        dt = parse_page_date(text)
        if dt and dt < cutoff:
            continue
        seen[sha(rr.url)] = {"ts": now_utc().isoformat(), "rc_id": rc_id}
        findings.append({
            "type": "WEB",
            "rc_id": rc_id,
            "rc_name": rc_name,
            "link": rr.url,
            "date": dt.isoformat() if dt else None,
            "note": "Website keyword match; date parsed" if dt else "Website keyword match; no date parsed",
        })
        time.sleep(0.2)
    return findings

def fetch_form_d_candidates() -> List[dict]:
    url = "https://efts.sec.gov/LATEST/search-index"
    cutoff = (now_utc() - timedelta(days=LOOKBACK_DAYS)).date().isoformat()
    payload = {
        "keysTyped": "D",
        "narrow": True,
        "page": 0,
        "from": 0,
        "size": 50,
        "filter": {"ciks": [], "forms": ["D"], "startdt": cutoff, "enddt": now_utc().date().isoformat()},
        "sort": "filedAt",
        "category": "custom"
    }
    try:
        r = requests.post(url, json=payload, headers={"User-Agent": UA, "Accept-Encoding": "gzip, deflate"}, timeout=REQUEST_TIMEOUT)
        if r.status_code >= 400:
            return []
        data = r.json()
        hits = data.get("hits", {}).get("hits", [])
        out = []
        for h in hits:
            src = h.get("_source", {}) or {}
            out.append({
                "issuer": src.get("entityName") or "",
                "filedAt": src.get("filedAt"),
                "link": src.get("linkToFilingDetails") or "",
                "cik": src.get("cik"),
            })
        return out
    except Exception:
        return []

def send_email(subject: str, body: str):
    host = os.environ["SMTP_HOST"]
    port = int(os.environ.get("SMTP_PORT", "587"))
    user = os.environ["SMTP_USER"]
    pwd  = os.environ["SMTP_PASS"]

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = user
    msg["To"] = ", ".join(RECIPIENTS)

    with smtplib.SMTP(host, port, timeout=30) as s:
        s.starttls()
        s.login(user, pwd)
        s.sendmail(user, RECIPIENTS, msg.as_string())

def format_digest(findings: List[dict], stats: dict) -> str:
    if not findings:
        return "No new/updated RC projects found in the last 3 months today.\n\nRun stats:\n" + json.dumps(stats, indent=2)

    lines = []
    lines.append(f"EB-5 RC Daily Digest — {now_utc().strftime('%Y-%m-%d')} (lookback {LOOKBACK_DAYS}d)")
    lines.append("")
    lines.append("Run stats:")
    lines.append(json.dumps(stats, indent=2))
    lines.append("")
    for f in findings:
        lines.append(f"[{f['type']}] RC: {f['rc_name']} (ID: {f['rc_id']})")
        lines.append(f"Link: {f['link']}")
        if f.get("date"):
            lines.append(f"Date: {f['date']}")
        if f.get("issuer"):
            lines.append(f"Issuer: {f['issuer']}")
        if f.get("note"):
            lines.append(f"Note: {f['note']}")
        lines.append("-" * 72)
    return "\n".join(lines)

def main():
    ensure_data_dir()
    registry = load_json(REGISTRY_PATH, {})
    seen = load_json(SEEN_PATH, {})
    cursor = load_json(CURSOR_PATH, {"offset": 0})

    rc_list = fetch_uscis_rc_list()
    rc_list_sorted = sorted(rc_list, key=lambda x: x["rc_id"])
    total_rc = len(rc_list_sorted)

    # alias table
    rc_aliases: Dict[str, List[str]] = {}
    for rc in rc_list_sorted:
        rid = rc["rc_id"]
        aliases = set([rc["rc_name"]])
        if rid in registry and isinstance(registry[rid], dict):
            for a in registry[rid].get("aliases", []) or []:
                aliases.add(a)
        rc_aliases[rid] = sorted(aliases)

    findings: List[dict] = []

    # Form D path
    formd_hits = fetch_form_d_candidates()
    matched_formd = 0
    for hit in formd_hits:
        issuer = hit.get("issuer") or ""
        if not issuer:
            continue
        m = best_rc_match(issuer, rc_aliases)
        if not m:
            continue
        rid, score = m
        link = hit.get("link") or ""
        if link and sha(link) in seen:
            continue
        if link:
            seen[sha(link)] = {"ts": now_utc().isoformat(), "rc_id": rid}
        matched_formd += 1
        findings.append({
            "type": "FORMD",
            "rc_id": rid,
            "rc_name": next((x["rc_name"] for x in rc_list_sorted if x["rc_id"] == rid), rid),
            "issuer": issuer,
            "link": link or "(no link)",
            "date": hit.get("filedAt"),
            "note": f"Fuzzy issuer→RC match (score={score:.2f}). Verify issuer/RC relationship.",
        })

    # Website path (rotating batch)
    offset = int(cursor.get("offset", 0)) % max(total_rc, 1)
    batch = rc_list_sorted[offset: offset + BATCH_SIZE]
    if len(batch) < BATCH_SIZE and total_rc > 0:
        batch += rc_list_sorted[0: max(0, BATCH_SIZE - len(batch))]

    discovered = 0
    scanned_sites = 0
    for rc in batch:
        rid = rc["rc_id"]
        rname = rc["rc_name"]
        site = (registry.get(rid, {}) or {}).get("site")
        if not site:
            site = try_discover_site(rname)
            if site:
                discovered += 1
                entry = registry.get(rid, {}) or {}
                entry["site"] = site
                entry["aliases"] = sorted(set((entry.get("aliases") or []) + [rname]))
                entry["updated_at"] = now_utc().isoformat()
                registry[rid] = entry
        if not site:
            continue
        scanned_sites += 1
        findings.extend(scan_site_for_updates(rid, rname, site, seen))

    cursor["offset"] = (offset + BATCH_SIZE) % max(total_rc, 1)

    stats = {
        "total_rc_baseline": total_rc,
        "site_registry_size": sum(1 for v in registry.values() if isinstance(v, dict) and v.get("site")),
        "batch_offset": offset,
        "batch_size": BATCH_SIZE,
        "sites_discovered_this_run": discovered,
        "sites_scanned_this_run": scanned_sites,
        "formd_hits_fetched": len(formd_hits),
        "formd_hits_matched": matched_formd,
        "total_findings_sent": len(findings),
    }

    save_json(REGISTRY_PATH, registry)
    save_json(SEEN_PATH, seen)
    save_json(CURSOR_PATH, cursor)

    send_email("EB-5 RC Daily Digest", format_digest(findings, stats))

if __name__ == "__main__":
    main()
