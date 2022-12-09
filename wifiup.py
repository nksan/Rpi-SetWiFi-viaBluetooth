
import subprocess
try:
    arr = ["sudo", "/bin/ip", "link", "set", "wlan0", "up"  ]
    p = subprocess.Popen(arr)
    p.wait()
    print("done")
except Exception as e:
    print(e)