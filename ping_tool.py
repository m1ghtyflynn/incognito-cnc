# Ping sweeping tool for you h4x0rs
import subprocess

for ping in range(1,10):
    # Add your rnage to scan here
    address = "127.0.0." + str(ping)
    res = subprocess.call(['/usr/xbin/ping', '-c', '3', address])
    if res == 0:
        print "ping to", address, "OK"
    elif res == 2:
        print "no response from", address
    else:
        print "ping to", address, "failed!"
