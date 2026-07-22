# read events, decide if something suspicious is happening - Correlation Engine
import sqlite3
import datetime
import models

# brute-force detection rule - login attempts
def detect_brute_force():
    con = sqlite3.connect("siem.db")
    cur = con.cursor()
    # timedelta(seconds=60) = a 60-second duration; subtracting it from now()
    cutoff = str(datetime.datetime.now() - datetime.timedelta(seconds=60))
    # gives the exact timestamp of "60 seconds ago" - our cutoff for "recent" events

    # counting the number of LOGIN_FAILED events by each ip in the last 60 secs
    cur.execute("""SELECT source_ip, COUNT (*) FROM events 
                WHERE event_type = 'LOGIN_FAILED' AND timestamp > ?
                GROUP BY source_ip""", (cutoff,))  # '*' - adds all the rows
    # each row is a tuple like (source_ip, count)
    rows = cur.fetchall()
    con.close()

    # if ip count exceeds threshold value (10) within last 60 secs, raise an alert
    for (ip, count) in rows:
        if count >= 10:
            if not models.is_suppressed(ip, "BRUTE_FORCE_DETECTED"):
                score, severity = calculate_score("BRUTE_FORCE_DETECTED", count, 10)
                models.insert_alert(ip, "BRUTE_FORCE_DETECTED", score, severity)
                print("Alert - more than 10 attempts in 60 secs")
            else:
                print(f"Suppressed ip -{ip} matched a known suppression rule")

# port scan detection rule 
def detect_port_scan():
    con = sqlite3.connect("siem.db")
    cur = con.cursor()
    cutoff = str(datetime.datetime.now() - datetime.timedelta(seconds=60))

    # COUNT(DISTINCT target) counts unique ports touched per IP, not total attempts
    cur.execute("""SELECT source_ip, COUNT (DISTINCT target) FROM events
                WHERE event_type='PORT_SCAN_ATTEMPT' AND timestamp > ?
                GROUP BY source_ip""", (cutoff, ))
    rows = cur.fetchall()
    con.close()

    # alert raised if 15 or more distinct ports touched within last 60 secs
    for (ip, count) in rows:
        if count >= 15: 
            if not models.is_suppressed(ip, "PORT_SCAN_DETECTED"):
                score, severity = calculate_score("PORT_SCAN_DETECTED", count, 15)
                models.insert_alert(ip, "PORT_SCAN_DETECTED", score, severity)
                print("Alert - too many distinct ports")
            else:
                print(f"Suppressed ip -{ip} matched a known suppression rule")

# calculating scores for alerts to determine the severity
def calculate_score(rule_name, count, threshold):
    # port scanning is slightly less severe on its own than an actual login attack
    if rule_name == "BRUTE_FORCE_DETECTED":
         base_score = 30
    elif rule_name == "PORT_SCAN_DETECTED":
        base_score = 20
    # different scores for 12 failures and 50 failures
    extra = count - threshold
    score = base_score + extra
    if score <= 30:
        severity = "Low"
    elif score > 30 and score <= 60:
        severity = "Medium"
    else:
        severity = "Critical"
    return score, severity




# in readme, write about deltatime, group by and all that 
