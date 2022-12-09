
import subprocess
try:
    arr = ["sudo", "/bin/ip", "link", "set", "wlan0", "down"  ]
    p = subprocess.Popen(arr)
    p.wait()
    print("down is done")
except Exception as e:
    print(e)