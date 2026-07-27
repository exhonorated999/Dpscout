"""Quick standalone test for the AFC daemon thumbnail command.

Usage:
    py scripts/_test_thumb.py /DCIM/106APPLE/IMG_6810.HEIC
"""
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).parent
daemon = ROOT / "ios_afc_daemon.py"
path = sys.argv[1] if len(sys.argv) > 1 else "/DCIM/106APPLE/IMG_6810.HEIC"

proc = subprocess.Popen(
    ["py", "-u", str(daemon)],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    bufsize=1,
)

def send(obj):
    line = json.dumps(obj) + "\n"
    proc.stdin.write(line)
    proc.stdin.flush()
    print(">>> ", line.strip())

def recv():
    line = proc.stdout.readline()
    if not line:
        return None
    print("<<< ", line.strip()[:300])
    return json.loads(line)

# 1. ready
recv()
# 2. open
send({"cmd": "open"})
opened = recv()
print("OPEN:", opened)
# 3. thumbnail
send({"cmd": "thumbnail", "path": path, "max_dim": 256, "quality": 70})
t0 = time.time()
while True:
    ev = recv()
    if ev is None:
        break
    if ev.get("event") in ("thumbnail_result", "error"):
        break
    if time.time() - t0 > 60:
        print("TIMEOUT")
        break

# drain stderr
proc.stdin.close()
proc.wait(timeout=5)
err = proc.stderr.read()
if err:
    print("--- STDERR ---")
    print(err)
