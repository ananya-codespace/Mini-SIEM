# entry point to test things as we build
import sqlite3
import database
import rules
import integrity
import event_generators
import models

print("\n -------------------- MINI SIEM -------------------- ")

# initializing all 3 tables
print("\n -------------------- ")
print("Initializing Tables .....")
database.init_events()
database.init_alerts()
database.init_suppressions()
print(" -------------------- ")

# generating logs (test activities) and detecting suspicious activities

# login attempts + immediate brute-force check
print("\n -------------------- ")
print("Generating Login Test Events .....")
event_generators.simulate_login_attempts("192.168.1.45", "admin", 15, True)
event_generators.simulate_login_attempts("192.168.1.45", "admin", 5, False)
event_generators.simulate_login_attempts("192.168.1.50", "admin", 15, True)
print(" -------------------- ")

# adding a suppression for one of the scanned IPs
models.insert_suppression("192.168.1.50", "BRUTE_FORCE_DETECTED", "known test account, expected failures", None)

print("\n -------------------- ")
print("Running Brute-Force Detection .....")
rules.detect_brute_force()
print(" -------------------- ")

# port scans + immediate port-scan check
print("\n -------------------- ")
print("Generating Port Scan Test Events .....")
event_generators.simulate_port_scan("192.168.5.24")
event_generators.simulate_port_scan("192.168.7.36")
print(" -------------------- ")

# adding a suppression
models.insert_suppression("192.168.5.24", "PORT_SCAN_DETECTED", "known test scanner", None)

print("\n -------------------- ")
print("Running Port Scan Detection .....")
rules.detect_port_scan()
print(" -------------------- ")
# brute force and port scan run separately because by the time all of they run together, 60 seconds would have passed and only 1 activity would be recorded

# tamper checking - no log deleted
# print("\n -------------------- ")
# print("Checking Log Integrity .....")
# chain_ok = integrity.detect_tamper()
# if chain_ok:
#    print("No tampering detected - chain intact")
# print("\n -------------------- ")

# tamper checking - log deleted
print("\n -------------------- ")
print("Checking Log Integrity .....")
con = sqlite3.connect("siem.db")
cur = con.cursor()
# delete or update will lead to tampering
cur.execute("DELETE FROM events WHERE rowid = 5")  
# updating (eg: event detail/ source ip) will cause event_data value to change due to which the chain breaks
con.commit()
con.close()
chain_ok = integrity.detect_tamper()
if chain_ok:
   print("No tampering detected - chain intact")
print(" -------------------- ")

# printing the alerts from the alerts table
print("\n -------------------- ")
print("Alerts Table .....")
con = sqlite3.connect("siem.db")
cur = con.cursor()
cur.execute("SELECT source_ip, rule_name, status, score, severity FROM alerts")
rows = cur.fetchall()
for row in rows:
   print(row)
con.close()
print(" -------------------- ")

print("\n -------------------- SCAN COMPLETE ------------------- \n")



# in readme - mention that the main file is hardcoded and we r not taking any input
# also mention that the status is always OPEN -> RESOLVED / FALSE_POSITIVE / SUPPRESSED which can be any of these
# and changing or understanding the status only done later which is for now beyond the scope of this project - write this nicely







"""
1. events table created ✅ 
2. Write hashing.py → logic to compute curr_hash for a new event 
   (needed before we can insert anything, since every row needs its hash) ✅
3. Write models.py → function to insert a new event into the table
   (this is where hashing.py actually gets used — hash computed, then row inserted) ✅
4. Write a small test in main.py → manually insert a couple of fake events, 
   confirm they land in siem.db correctly ✅
5. Write event generators → 
     - a login attempt simulator (fake LOGIN_FAILED / LOGIN_SUCCESS events)
     - a port scan simulator (using socket, from our earlier discussion)
   (this is what actually produces realistic data to test detection on) ✅  
6. Write the correlation/rule engine →
     - brute-force detection rule (X failed logins in Y seconds)
     - port scan detection rule (X distinct ports in Y seconds) ✅
7. Create alerts table + insert logic → 
   when a rule fires, write a row into alerts ✅
8. Create suppressions table + logic → 
   check suppressions before creating an alert (or after, lowering score — 
   your open design decision from earlier) ✅
9. Add risk scoring → 
   compute a score when an alert is created, using the weighted factors 
   we discussed (base score + port count + sensitive ports + repeat offender) ✅
10. Add tamper detection → 
    periodic check that walks the hash chain and confirms nothing broke ✅

11. Check readme and also clarify the basis on which the files are divided


Fixes
1. related_event_ids in insert_alert() — still None ✅
2. Login simulator realism (varied reasons / username-guessing scenario) ✅
3. Additional scoring factors (sensitive ports, repeat offenders) ✅
4. Port scan "closed vs nothing listening" — agreed to leave as-is permanently ✅
"""