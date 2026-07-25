# Mini SIEM

A Security Information and Event Management (SIEM) tool built in Python — logs security events, detects suspicious patterns, raises alerts, and tamper-checks its own log history.

## Features
- Tamper-evident event logging using a hash chain
- Simulated login attempts and port scans to generate test data
- Correlation rules to detect brute-force login attempts and port scans
- Risk scoring for alerts based on severity factors (count, sensitive ports, repeat offenders)
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
`main.py` runs the full pipeline end to end:
1. Initializes all three tables (`events`, `alerts`, `suppressions`)
2. Generates test events — simulated brute-force login attempts and a port scan
3. Runs the correlation rules to detect brute-force and port scan activity
4. Runs the integrity check to confirm the hash chain hasn't been tampered with
5. Prints the contents of the `alerts` table

Note that `main.py` is currently hardcoded — it runs a fixed set of test scenarios and doesn't take any user input yet.

## Project Structure

- **`database.py`** — DB connection and table creation
  - `init_events()` — creates the `events` table
  - `init_alerts()` — creates the `alerts` table
  - `init_suppressions()` — creates the `suppressions` table

- **`models.py`** — all data access (insert/fetch functions)
  - `get_prev_hash()` — fetches the most recent event's hash for chaining
  - `insert_event()` — computes an event's hash and inserts it into `events`
  - `insert_alert()` — inserts a new row into `alerts`
  - `insert_suppression()` — inserts a new row into `suppressions`
  - `is_suppressed()` — checks if an IP + rule combination is currently suppressed
  - `count_previous_alerts()` — counts prior alerts for an IP, used for the repeat-offender score bonus
  - `count_sensitive_ports()` — counts sensitive ports touched by an IP within a time window, used for the sensitive-port score bonus

- **`hashing.py`** — hash chain logic
  - `compute_hash()` — computes an event's hash from its data plus the previous event's hash

- **`integrity.py`** — tamper detection
  - `detect_tamper()` — walks the entire hash chain, recomputes each hash, and flags/alerts if any mismatch is found

- **`rules.py`** — correlation engine and risk scoring
  - `detect_brute_force()` — flags IPs with 10+ failed logins in the last 60 seconds
  - `detect_port_scan()` — flags IPs touching 15+ distinct ports in the last 60 seconds
  - `calculate_score()` — combines base score, count above threshold, repeat-offender bonus, and sensitive-port bonus into a final score and severity

- **`event_generators.py`** — test data generation
  - `simulate_login_attempts()` — generates a configurable number of failed logins, optionally followed by a success
  - `simulate_port_scan()` — attempts real socket connections across a range of ports to generate port scan events

- **`main.py`** — entry point; runs the full pipeline (table init → generate test events → run detection rules → check integrity → print alerts). Currently hardcoded with fixed test scenarios, no user input yet.

Each file owns one concern: schema (`database.py`), data access (`models.py`), hashing (`hashing.py`), tamper checks (`integrity.py`), detection logic (`rules.py`), test data (`event_generators.py`), and orchestration (`main.py`).

## How It Works

### Database Schema
Three tables in `siem.db`:
- **events** — every log entry, including the hash chain fields (`prev_hash`, `curr_hash`)
- **alerts** — raised whenever a correlation rule is triggered
- **suppressions** — known IPs/rules to ignore, with an optional expiry

Event and alert IDs use UUIDs instead of auto-increment integers, since UUIDs are effectively unguessable — this matters more in a security tool than in a typical CRUD app.

### Hash-Chained Logging
Every event's hash is computed from its own data plus the previous event's hash (`hashing.py`), so altering or deleting any past event breaks the chain from that point onward. `integrity.py` walks the entire chain in order and recomputes each hash to confirm nothing was changed — if a mismatch is found, tampering is flagged, an alert is raised, and the check stops (returning `False`) since the chain's integrity from that point on can no longer be trusted. If the whole chain checks out, it returns `True`.

This uses plain `sha256`, not `pbkdf2_hmac` (which was used for password hashing in PyVault). The two solve different problems: `pbkdf2_hmac` is deliberately slow (100,000 iterations) so that stolen password hashes are hard to brute-force. Here, the hash isn't protecting a secret — it's a fingerprint used to detect tampering, and it needs to be fast since a hash is computed for every single log event, potentially thousands per second. Using 100,000 iterations for this would make inserting logs painfully slow for no real security benefit — nobody's trying to "crack" a log's hash the way they'd crack a password.

### Event Generators
`event_generators.py` simulates activity to test detection against:
- **Login attempts** — a configurable number of failures followed by an optional success. Failures are currently always logged with the reason `"invalid_password"` — other realistic failure reasons (e.g. account locked, unknown user) aren't simulated yet
- **Port scans** — attempts real socket connections to a range of ports plus a few common ones, logging whether each was open or closed. A closed result is logged simply as `"port_closed"` without distinguishing between an actively refused connection and a port that's silently not listening — this distinction was intentionally left out for now

For both `PORT_SCAN_ATTEMPT` and login events, `user` and `target` are set to `None` where they don't apply — a login event has no relevant port (`target`), and a port scan has no relevant `user`, so leaving the unused field `None` keeps the table schema uniform across all event types instead of needing separate tables per event type.

### Correlation Rules
`rules.py` checks for patterns within a rolling time window (last 60 seconds), using `datetime.timedelta` to calculate the cutoff timestamp and comparing it against stored event timestamps:
- **Brute-force detection** — counts `LOGIN_FAILED` events per IP using `GROUP BY source_ip`; if any IP crosses 10 failures in the window, an alert is raised
- **Port scan detection** — counts *distinct* ports touched per IP using `COUNT(DISTINCT target)`, so scanning the same port repeatedly doesn't inflate the count; 15+ distinct ports in the window triggers an alert

Both queries also use `GROUP_CONCAT(event_id)` to collect the IDs of every event that contributed to the count, into a single comma-separated string per IP. This is stored in the alert's `related_event_ids` field but isn't actively used anywhere yet — in a real SIEM, this is what lets you click into an alert and see exactly which raw events triggered it.

### Risk Scoring
Each alert's score is built from several factors in `calculate_score()`:
- A **base score** per rule type (brute-force is weighted higher than port scans, since it's considered more severe on its own)
- An **extra** component for how far past the threshold the count is (e.g. 12 failures vs. 50 failures score differently)
- A **repeat offender bonus** — `count_previous_alerts()` adds 5 points for every prior alert already logged against that IP
- A **sensitive port bonus** — for port scans only, `count_sensitive_ports()` adds 10 points for each sensitive port touched (22/SSH, 3389/RDP, 3306/MySQL) within the same time window; this doesn't apply to brute-force alerts

The final score maps to a severity: Low, Medium, or Critical.

### Suppression
Before an alert is created, `is_suppressed()` checks whether the IP + rule combination matches a known suppression entry that hasn't expired (`expires_at IS NULL OR expires_at > now`). If suppressed, the event is logged but no alert is raised — with a print statement noting the suppression instead.

### Fetching the Previous Hash
`get_prev_hash()` fetches the most recently inserted event's hash using `ORDER BY rowid DESC LIMIT 1` — `rowid` is a hidden column SQLite maintains automatically for every table, always increasing with each insert. Ordering by it descending and limiting to 1 row gives the latest event without needing a separate "last hash" variable to track in memory.

### Tuple Unpacking in Integrity Checks
`detect_tamper()` fetches each row as a tuple and unpacks it directly into named variables (`event_id, timestamp, source_ip, ...`), in the same order the columns were selected in the query — this avoids repeatedly indexing into `row[0]`, `row[1]`, etc., making the tamper-check logic easier to read.

## Output
- Progress through each stage (table init, event generation, rule detection, integrity check) is printed to the terminal as `main.py` runs
- Triggered alerts are printed with their severity, rule name, IP, and score as they're detected; suppressed IPs are printed separately
- The integrity check prints whether the chain is intact or where tampering was found
- At the end, every row in the `alerts` table is printed as a summary

## What I Learned
- Designing a hash chain for tamper-evident logging, and why the choice of hash function depends on the threat model (fast fingerprinting vs. slow password hashing)
- Using UUIDs instead of auto-increment IDs for unguessable identifiers
- Writing correlation rules with time-windowed SQL queries (`datetime.timedelta`, `GROUP BY`, `COUNT(DISTINCT ...)`)
- Using `GROUP_CONCAT()` to collect related row IDs into a single string per group, and using `ORDER BY rowid DESC LIMIT 1` to fetch just the most recent row
- Designing a suppression system to reduce alert noise for known/expected activity
- Building a weighted risk-scoring system that combines multiple factors (base severity, count above threshold, repeat offenders, sensitive targets) into a single score
- Structuring a multi-file Python project with a clear separation of responsibilities — each file owns one concern (schema, data access, hashing, detection logic, tamper checks, test data)