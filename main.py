# entry point to test things as we build
import sqlite3
import database
import models

# for testing 
database.init_events()
models.insert_event("192.168.1.45", "LOGIN_FAILED", "admin", None, "invalid_password")
models.insert_event("192.168.1.41", "PORT_SCAN_ATTEMPT", None, "22", "port_scan_failed")
models.insert_event("192.168.1.45", "LOGIN_SUCCESS", "admin", None, "correct_password")

con = sqlite3.connect("siem.db")
cur = con.cursor()
cur.execute("SELECT * FROM events")
rows = cur.fetchall()
for row in rows:
   print(row)
con.close()
















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


Fixes
1. related_event_ids in insert_alert() — still None
2. Login simulator realism (varied reasons / username-guessing scenario)
3. Additional scoring factors (sensitive ports, repeat offenders)
4. Port scan "closed vs nothing listening" — agreed to leave as-is permanently
"""