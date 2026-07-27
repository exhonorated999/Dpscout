"""Smoke test the AFC daemon against the connected iPhone."""
import json
import subprocess
import sys
import threading
import time

DAEMON = r"C:\Users\JUSTI\Workspace\Datapilot_scout\scripts\ios_afc_daemon.py"

proc = subprocess.Popen(
    ["py", "-u", DAEMON],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    bufsize=1,
)


def reader_stderr():
    for line in proc.stderr:
        sys.stderr.write(f"[err] {line}")


threading.Thread(target=reader_stderr, daemon=True).start()


def send(cmd):
    s = json.dumps(cmd)
    print(f"-> {s[:120]}")
    proc.stdin.write(s + "\n")
    proc.stdin.flush()


def recv_until(predicate, timeout=120):
    start = time.time()
    while time.time() - start < timeout:
        line = proc.stdout.readline()
        if not line:
            print("[!] stdout EOF")
            return None
        line = line.strip()
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            print(f"<! {line[:200]}")
            continue
        ev = obj.get("event")
        if ev in ("file_hash", "progress"):
            # Compact print for spammy events
            if ev == "file_hash":
                p = obj.get("path", "")
                p = "..." + p[-50:] if len(p) > 50 else p
                print(f"<- hash {p}  {obj.get('size')}B  sha256={obj.get('sha256','')[:16]}...")
            else:
                print(f"<- progress files={obj.get('files_done')} bytes={obj.get('bytes_done')} elapsed={obj.get('elapsed_s')}s")
        else:
            print(f"<- {line[:300]}")
        if predicate(obj):
            return obj
    print("[!] timeout")
    return None


# 1. ready
recv_until(lambda o: o.get("event") == "ready", timeout=10)

# 2. ping
send({"cmd": "ping"})
recv_until(lambda o: o.get("event") == "pong", timeout=5)

# 3. open device (no UDID = first available)
send({"cmd": "open"})
recv_until(lambda o: o.get("event") == "opened", timeout=15)

# 4. list /DCIM
send({"cmd": "list", "path": "/DCIM"})
recv_until(lambda o: o.get("event") == "list_result", timeout=15)

# 5. list /DCIM/100APPLE (first subfolder)
send({"cmd": "list", "path": "/DCIM/100APPLE"})
r = recv_until(lambda o: o.get("event") == "list_result", timeout=15)
if r:
    print(f"   /DCIM/100APPLE has {len(r.get('entries', []))} entries")

# 6. walk_hash a SMALL scope — just first folder, just sha256, min 1 MB
print("\n--- hashing /DCIM/100APPLE (sha256 only, ≥1 MB files) ---")
t0 = time.time()
send({
    "cmd": "walk_hash",
    "roots": ["/DCIM/100APPLE"],
    "algos": ["sha256"],
    "min_bytes": 1_000_000,
})
recv_until(lambda o: o.get("event") in ("complete", "stopped", "error"), timeout=600)
elapsed = time.time() - t0
print(f"\n--- elapsed {elapsed:.1f}s ---")

# 7. quit
send({"cmd": "quit"})
recv_until(lambda o: o.get("event") == "bye", timeout=5)

proc.wait(timeout=5)
print(f"\nExit code: {proc.returncode}")
