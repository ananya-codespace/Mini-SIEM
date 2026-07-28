# Mini SIEM

A Security Information and Event Management (SIEM) tool built in Python — logs security events, detects suspicious patterns, raises alerts, and tamper-checks its own log history.

## Features
- Tamper-evident event logging using a hash chain
- Simulated login attempts and port scans to generate test data
- Correlation rules for brute-force logins and port scans, both with suppression support
- Risk scoring based on count, sensitive ports touched, and repeat offenders
- Periodic integrity check to catch tampered or deleted logs

## Tech Stack
- Language: `Python`
- Libraries: `sqlite3`, `hashlib`, `uuid`, `datetime`, `socket`, `time`

## How to Run
```bash
python main.py
```

## Usage
`main.py` runs a fixed pipeline: 
1. initializes tables
2. generates login events and runs brute-force detection (with one IP suppressed)
3. generates port scan events and runs port scan detection (with one IP suppressed)
4. deletes a row to simulate tampering, then runs the integrity check
5. prints the `alerts` table.

**Detection runs right after each batch of events rather than all at once at the end, since both rules only look at a recent time window — running everything together would push earlier events outside that window. `main.py` is hardcoded for now, with no user input.**

**A note on `siem.db` persistence:** since SQLite saves data to `siem.db` on disk, suppression entries from earlier runs stick around even after you change the IP being suppressed in the code. So if you test with one IP, then edit `main.py` to suppress a different IP, both IPs can end up suppressed — the old entry never went away, the new one just got added alongside it. Deleting `siem.db` (or wiping the `suppressions` table) between test runs keeps things clean and gives you results that actually reflect your latest code change.

## Project Structure
- **`database.py`** — creates the `events`, `alerts`, and `suppressions` tables
- **`models.py`** — all data access: inserting events/alerts/suppressions, checking suppression status, and scoring helpers (`count_previous_alerts`, `count_sensitive_ports`)
- **`hashing.py`** — computes an event's hash from its data + the previous hash
- **`integrity.py`** — walks the hash chain and flags tampering
- **`rules.py`** — brute-force and port scan detection, plus risk scoring
- **`event_generators.py`** — simulates login attempts and port scans
- **`main.py`** — orchestrates the full pipeline

**Each file owns one concern: schema, data access, hashing, tamper checks, detection logic, test data, and orchestration.**

## How It Works

**Hash-chained logging:** Each event's hash is derived from its own data plus the previous event's hash, so tampering with any past event breaks the chain from that point on. `sha256` is used here instead of `pbkdf2_hmac` because this hash isn't protecting a secret from brute-forcing — it's a fast fingerprint computed on every log event, and slowing that down with 100,000 iterations would hurt performance for no security benefit. `main.py` proves this works by deleting a row mid-run and confirming the integrity check catches it. If a log has been tampered (deleted/updated), an alert is raised immediately and the rest of the logs are not checked as the log's integrity has been compromised

**Event generators:** Login failures are logged with reason `"invalid_password"`; other realistic reasons aren't simulated yet. Port scans attempt real socket connections and log each as `"open"` or `"closed"`, without distinguishing "closed" from "nothing listening" — left as-is intentionally. Each connection uses a short **0.01s timeout** so an unresponsive port doesn't stall the scan and push later events outside the detection window. `user`/`target` are `None` where not applicable, keeping one shared schema across event types instead of separate tables per type.

**Correlation rules:** Both rules use a rolling time window (`datetime.timedelta`) and `GROUP BY source_ip` to count matching events per IP — brute-force counts total `LOGIN_FAILED` events over **60 seconds** *(10+ triggers an alert)*, port scan counts *distinct* ports via `COUNT(DISTINCT target)` over a wider **300-second window** *(15+ triggers an alert)*, since scanning ~100 ports realistically takes longer than 60 seconds even with the short timeout. Both also collect contributing event IDs with `GROUP_CONCAT(event_id)` into `related_event_ids` — stored but not used yet; in a real SIEM this is what lets you trace an alert back to its raw events.

**Risk scoring:** `calculate_score()` combines a **base score** per rule type, an **"extra"** for how far past threshold the count is, a **+5 repeat-offender bonus** per prior alert on that IP, and (port scans only) a **+10 bonus per sensitive port touched** *(22/SSH, 3389/RDP, 3306/MySQL)*. The total maps to **Low/Medium/Critical.**

**Suppression:** Both brute-force and port scan detection check `is_suppressed()` before raising an alert — if the IP + rule matches an unexpired suppression entry, the event is logged but no alert fires.

**Alert status:** Every alert is inserted with `status = "OPEN"`. A full workflow (moving alerts to `RESOLVED`, `FALSE_POSITIVE`, etc.) is out of scope for now.

**Small implementation notes:** `get_prev_hash()` uses `ORDER BY rowid DESC LIMIT 1` to grab the latest event's hash without tracking it separately in memory. `detect_tamper()` unpacks each fetched row directly into named variables instead of indexing into `row[0]`, `row[1]`, etc.

## Output
- Each pipeline stage prints its progress and any alerts/suppressions as they happen
- The integrity check prints whether the chain is intact — since `main.py` deletes a row on purpose, expect a detected-tampering message here, not "chain intact"
- The full `alerts` table is printed at the end
- All the output is printed on the termianl

## What I Learned
- Designing a hash chain for tamper-evident logs, and why the hash function should match the threat model (fast fingerprint vs. slow password hash)
- UUIDs over auto-increment IDs for unguessable identifiers
- Time-windowed SQL queries (`datetime.timedelta`, `GROUP BY`, `COUNT(DISTINCT ...)`, `GROUP_CONCAT`)
- Building a suppression system to cut alert noise, and why persistent storage (like a `.db` file) needs a clean-slate reset between test runs to reflect code changes accurately
- Weighted risk scoring combining multiple factors into one score
- Using `socket.settimeout()` to avoid a scan hanging on unresponsive ports
- A log can be tampered in two ways :
  - By deleting the log - the `prev_hash` value of the log after the deleted log will change
  - By updating the content of the event - the `event_data` value will change  

  In both the cases, `prev_hash` will differ from `curr_hash` due to which the chain breaks
- Structuring a multi-file project with one clear responsibility per file