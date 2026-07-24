#  a login attempt simulator and a port scan simulator
import time
import models
import socket

# login attempt simulator
def simulate_login_attempts(source_ip, user, num_failures, then_success=True):
    for i in range(num_failures):
        models.insert_event(source_ip, "LOGIN_FAILED", user, None, "invalid_password")
        time.sleep(3)
    if then_success:
        models.insert_event(source_ip, "LOGIN_SUCCESS", user, None, "correct_password")
# refine it later

# port scan simulator
def simulate_port_scan(source_ip):
    # client side code - client initiates connection
    common_ports = [443, 3306, 3389, 8080, 5432, 8443]
    ports_to_scan = list(range(1,100)) + common_ports
    for port in ports_to_scan:
        # creating socket object
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        res = sock.connect_ex(("127.0.0.1", port))  # connect_ex takes tuple as argument
        # res == 0 means open, nonzero means closed
        if res == 0:
            reason = "port_open"
        else:
            reason = "port_closed"  # or nothing listening 
        models.insert_event(source_ip, "PORT_SCAN_ATTEMPT", None, str(port), reason)
        sock.close()


"""
add in readme
why using none for target and user

tell that u r using only invalid password and port closed reason not being specified - 
like if its not listening or not responding
"""