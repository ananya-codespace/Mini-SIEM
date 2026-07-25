  # DB connection + table creation 
import sqlite3

# initializing the events table
def init_events():
    con = sqlite3.connect("siem.db")
    cur = con.cursor()
    # events table holds normalized log entries
    events_table = """
    CREATE TABLE IF NOT EXISTS events (
        event_id TEXT PRIMARY KEY,
        timestamp TEXT,
        source_ip TEXT,
        event_type TEXT,
        user TEXT,
        target TEXT,
        detail TEXT,
        prev_hash TEXT,
        curr_hash TEXT 
    );
    """
    # SIEMs use UUIDs (universally unique identifiers) instead of simple auto-increment numbers; UUIDs are effectively unguessable
    cur.execute(events_table)
    con.commit()
    con.close()

# initializing the alerts table
def init_alerts():
    con = sqlite3.connect("siem.db")
    cur = con.cursor()
    # alerts table holds alerts raised, if threshold crossed
    alerts_table = """
    CREATE TABLE IF NOT EXISTS alerts (
        alert_id TEXT PRIMARY KEY,
        triggered_at TEXT,
        source_ip TEXT,
        rule_name TEXT,
        related_event_ids TEXT,
        status TEXT,
        score INTEGER,
        severity TEXT
    );
    """
    cur.execute(alerts_table)
    con.commit()
    con.close()

# initializing the suppressions table
def init_suppressions():
    con = sqlite3.connect("siem.db")
    cur = con.cursor()
    # suppressions table holds the known alerts that are suppressed
    suppressions_table = """
    CREATE TABLE IF NOT EXISTS suppressions (
        suppression_id TEXT PRIMARY KEY,
        source_ip TEXT,
        rule_name TEXT,
        reason TEXT,
        expires_at TEXT
    );
    """    
    # expires_at - the alerts are suppressed for a while
    cur.execute(suppressions_table)
    con.commit()
    con.close()