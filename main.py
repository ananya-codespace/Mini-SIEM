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



