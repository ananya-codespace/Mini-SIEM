# Mini SIEM

A Security Information and Event Management (SIEM) tool built in Python — logs security events, detects suspicious patterns, raises alerts, and tamper-checks its own log history.

## Features
- Tamper-evident event logging using a hash chain
- Simulated login attempts and port scans to generate test data
- Correlation rules to detect brute-force login attempts and port scans
- Risk scoring for alerts based on severity factors
- Alert suppression for known/expected IPs
- Periodic integrity check to detect if any log has been tampered with or deleted

## Tech Stack
- Language: Python
- Libraries: `sqlite3`, `hashlib`, `uuid`, `datetime`, `socket`, `time`

## How to Run
```bash
python main.py
```

## Usage
This is still a work-in-progress backend with no CLI yet — `main.py` currently acts as a manual test script that inserts sample events and prints the contents of the `events` table.

## How It Works

### Database Schema
Three tables in `siem.db`:
- **events** — every log entry, including the hash chain fields (`prev_hash`, `curr_hash`)
- **alerts** — raised whenever a correlation rule is triggered
- **suppressions** — known IPs/rules to ignore, with an optional expiry

Event and alert IDs use UUIDs instead of auto-increment integers, since UUIDs are effectively unguessable — this matters more in a security tool than in a typical CRUD app.

### Hash-Chained Logging
Every event's hash is computed from its own data plus the previous event's hash (`hashing.py`), so altering or deleting any past event breaks the chain from that point onward. `integrity.py` walks the entire chain in order and recomputes each hash to confirm nothing was changed — if a mismatch is found, tampering is flagged and an alert is raised.

This uses plain `sha256`, not `pbkdf2_hmac` (which was used for password hashing in PyVault). The two solve different problems: `pbkdf2_hmac` is deliberately slow (100,000 iterations) so that stolen password hashes are hard to brute-force. Here, the hash isn't protecting a secret — it's a fingerprint used to detect tampering, and it needs to be fast since a hash is computed for every single log event, potentially thousands per second. Using 100,000 iterations for this would make inserting logs painfully slow for no real security benefit — nobody's trying to "crack" a log's hash the way they'd crack a password.

### Event Generators
`event_generators.py` simulates realistic activity to test detection against:
- **Login attempts** — a configurable number of failures followed by an optional success
- **Port scans** — attempts real socket connections to a range of ports plus a few common ones, logging whether each was open or closed

For both `PORT_SCAN_ATTEMPT` and login events, `user` and `target` are set to `None` where they don't apply — a login event has no relevant port (`target`), and a port scan has no relevant `user`, so leaving the unused field `None` keeps the table schema uniform across all event types instead of needing separate tables per event type.

### Correlation Rules
`rules.py` checks for patterns within a rolling time window (last 60 seconds), using `datetime.timedelta` to calculate the cutoff timestamp and comparing it against stored event timestamps:
- **Brute-force detection** — counts `LOGIN_FAILED` events per IP using `GROUP BY source_ip`; if any IP crosses 10 failures in the window, an alert is raised
- **Port scan detection** — counts *distinct* ports touched per IP using `COUNT(DISTINCT target)`, so scanning the same port repeatedly doesn't inflate the count; 15+ distinct ports in the window triggers an alert

### Risk Scoring
Each alert gets a score based on a base value per rule type (brute-force weighted higher than port scans) plus how far past the threshold the count is. The score maps to a severity: Low, Medium, or Critical.

### Suppression
Before an alert is created, `is_suppressed()` checks whether the IP + rule combination matches a known suppression entry that hasn't expired (`expires_at IS NULL OR expires_at > now`). If suppressed, the event is logged but no alert is raised — with a print statement noting the suppression instead.

### Fetching the Previous Hash
`get_prev_hash()` fetches the most recently inserted event's hash using `ORDER BY rowid DESC LIMIT 1` — `rowid` is a hidden column SQLite maintains automatically for every table, always increasing with each insert. Ordering by it descending and limiting to 1 row gives the latest event without needing a separate "last hash" variable to track in memory.

### Tuple Unpacking in Integrity Checks
`detect_tamper()` fetches each row as a tuple and unpacks it directly into named variables (`event_id, timestamp, source_ip, ...`), in the same order the columns were selected in the query — this avoids repeatedly indexing into `row[0]`, `row[1]`, etc., making the tamper-check logic easier to read.

## Output
- Alerts and suppression matches are printed to the terminal as they're detected
- `main.py` currently prints every row in the `events` table as a manual sanity check

## What I Learned
- Designing a hash chain for tamper-evident logging, and why the choice of hash function depends on the threat model (fast fingerprinting vs. slow password hashing)
- Using UUIDs instead of auto-increment IDs for unguessable identifiers
- Writing correlation rules with time-windowed SQL queries (`datetime.timedelta`, `GROUP BY`, `COUNT(DISTINCT ...)`)
- Designing a suppression system to reduce alert noise for known/expected activity
- Building a basic weighted risk-scoring system to convert raw counts into severity levels
- Structuring a multi-file Python project (`database.py`, `models.py`, `hashing.py`, `rules.py`, `integrity.py`, `event_generators.py`) with clear separation of responsibilities
