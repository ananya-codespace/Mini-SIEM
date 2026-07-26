# periodic check that walks the hash chain and confirms nothing broke - Tamper Detection
import sqlite3
import hashing
import models

# checking if any log has been deleted
def detect_tamper():
    con = sqlite3.connect("siem.db")
    cur = con.cursor()
    cur.execute("SELECT event_id, timestamp, source_ip, event_type, user, target, detail, prev_hash, curr_hash FROM events ORDER BY rowid")
    rows = cur.fetchall()
    con.close()

    expected_prev_hash = "0"
    for row in rows:
        # unpacking direction is backwards
        event_id, timestamp, source_ip, event_type, user, target, detail, prev_hash, stored_curr_hash = row
        # row already holds the fetched tuple
        event_data = {
            "event_id": event_id,
            "timestamp": timestamp,
            "source_ip": source_ip,
            "event_type": event_type,
            "user": user,
            "target": target,
            "detail": detail
        }

        recomputed_hash = hashing.compute_hash(event_data, expected_prev_hash)
        # if a log has been deleted, an alert is raised and we stop checking if more logs were deleted as log's integrity has been compromised 
        if recomputed_hash != stored_curr_hash:
            print(f"[Critical] LOG_TAMPERING_DETECTED - chain broken starting at event {event_id} (source_ip: {source_ip})")
            # if log deleted, added into the alerts table
            models.insert_alert(source_ip, "LOG_TAMPERING_DETECTED", 100, "Critical", None)
            return False  # chain broken
        expected_prev_hash = recomputed_hash
    return True  # walked entire chain, nothing broken


# in readme - about unpacking