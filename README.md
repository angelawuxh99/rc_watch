# EB-5 USCIS Regional Center Daily Scanner

## What it does

- Fetches official USCIS EB-5 Regional Center list
- Uses it as baseline
- Scans configured RC websites
- Detects new project/offering keywords
- Sends daily email digest
- Deduplicates results

## Setup

1. Add GitHub Secrets:

SMTP_HOST
SMTP_PORT
SMTP_USER
SMTP_PASS

2. Edit rc_sources.yml and add RC websites.

3. Push to GitHub.

4. Go to Actions → Run workflow to test.
