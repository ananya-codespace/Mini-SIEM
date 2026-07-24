# functions to insert/fetch data - store things
import sqlite3
import uuid
import datetime 
import hashing

# to get the hash of the recently inserted event
def get_prev_hash():
    con = sqlite3.connect("siem.db")
    cur = con.cursor()
    cur.execute("SELECT curr_hash FROM events ORDER BY rowid DESC LIMIT 1")
    # rowid - rowid is a hidden column SQLite automatically maintains for every table and it always increases with each insert 
    # DESC - the highest rowid - the recently added log - comes first
    # LIMIT 1 - cuts the result down to just the top one
    row = cur.fetchone()
    # fetchone - returns a tuple like ('curr_hash',) if row exists
    con.close()
    if row is None:
        return "0"  # placeholder for the very first event
    else:
        return row[0]  # this will fetch the current hash value from the tuple
    
# extracting useful info from logs and inserting events into the database 
def insert_event(source_ip, event_type, user, target, detail):
    event_id = str(uuid.uuid4())  # built-in function to get a unique uuid object (128 bits)
    timestamp = str(datetime.datetime.now())  # current date and time when event occured
    # id and timestamp stored as string in db
    prev_hash = get_prev_hash()  
    event_data = {
        "event_id": event_id,
        "timestamp": timestamp,
        "source_ip": source_ip,
        "event_type": event_type,
        "user": user,
        "target": target,
        "detail": detail
    }
    curr_hash = hashing.compute_hash(event_data, prev_hash)

    # insering all the data into the database
    con = sqlite3.connect("siem.db")
    cur = con.cursor()
    # execute expects exactly two arguments: the SQL string, and then the values as a single tuple 
    cur.execute("""INSERT INTO events (event_id, timestamp, source_ip, event_type, user, target, detail, prev_hash, curr_hash) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""", (event_id, timestamp, source_ip, event_type, user, target, detail, prev_hash, curr_hash))
    con.commit()
    con.close()

# inserting alerts into the db
def insert_alert(source_ip, rule_name, score, severity, related_event_ids):
    alert_id = str(uuid.uuid4())
    triggered_at = str(datetime.datetime.now())
    status = "OPEN"

    con = sqlite3.connect("siem.db")
    cur = con.cursor()
    cur.execute("""INSERT INTO alerts (alert_id, triggered_at, source_ip, rule_name, related_event_ids, status, score, severity)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""", (alert_id, triggered_at, source_ip, rule_name, related_event_ids, status, score, severity))
    con.commit()
    con.close()
    
# inserting suppressions into the db
def insert_suppression(source_ip, rule_name, reason, expires_at):
    suppression_id = str(uuid.uuid4())
    con = sqlite3.connect("siem.db")
    cur = con.cursor()
    cur.execute("""INSERT INTO suppressions (suppression_id, source_ip, rule_name, reason, expires_at)
                VALUES (?, ?, ?, ?, ?)""", (suppression_id, source_ip, rule_name, reason, expires_at))
    con.commit()
    con.close()

# to check if an alert is to be suppressed
def is_suppressed(source_ip, rule_name):
    con = sqlite3.connect("siem.db")
    cur = con.cursor()
    current_time = str(datetime.datetime.now())
    # the alert gets suppressed in case its a known ip and also if expires_at is NULL or a future timestamp
    cur.execute("""SELECT source_ip FROM suppressions
                WHERE source_ip = ? AND rule_name = ? AND (expires_at IS NULL OR expires_at > ?)""", (source_ip, rule_name, current_time))
    ip = cur.fetchone()
    con.close()

    # checking if a row matching the ip and rule exists 
    if ip is None:
        return False
    return True

# repeat offender bonus to calculate score
def count_previous_alerts(source_ip):
    con = sqlite3.connect("siem.db")
    cur = con.cursor()
    cur.execute("SELECT COUNT(*) FROM alerts WHERE source_ip = ?", (source_ip, ))
    row = cur.fetchone()
    con.close()
    # for each alert a bonus value of 5 is added
    return row[0] * 5  # as fetchone() returns a tuple

# to check if sensitive ports touched
# sensitive ports: 22 - SSH, 3389 - RDP, 3306 - MySQL
def count_sensitive_ports(source_ip, cutoff):
    con = sqlite3.connect("siem.db")
    cur = con.cursor()
    cur.execute("""SELECT COUNT (DISTINCT target) FROM events
                WHERE source_ip = ? AND event_type = 'PORT_SCAN_ATTEMPT'
                AND target IN (?, ?, ?) AND timestamp > ?""", (source_ip, "22", "3389", "3306", cutoff))
    row = cur.fetchone()
    con.close()
    # for touching each sensitive port, a bonus of 10 is added
    return row[0] * 10 

# in readme, about limit and desc
