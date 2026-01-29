# EB-5 USCIS Regional Center Full Scanner (600+ RC baseline)

Daily email digest to:
- angelawuxh@outlook.com
- jensonacdc98@outlook.com

## What it does
- Fetches USCIS designated RC CSV as the baseline.
- Maintains a learned RC registry (websites/aliases) in `data/` via GitHub Actions cache.
- Two signal paths:
  1) SEC Form D (best-effort) -> fuzzy match issuer names to RC names/aliases
  2) Website scans (best-effort) -> heuristic website discovery + light crawl of likely pages
- Deduplicates and emails only net-new findings.

## Secrets (required)
SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS

## Tuning (optional env in workflow)
BATCH_SIZE, MAX_SITE_PAGES, REQUEST_TIMEOUT
