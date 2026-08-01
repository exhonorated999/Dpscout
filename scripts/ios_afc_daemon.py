#!/usr/bin/env python3
"""
Datapilot Scout — iOS AFC Triage Daemon

Long-running sidecar that holds an AFC connection open to one iOS device
and serves JSON-RPC commands over stdin/stdout for live (non-copying)
hash scanning and metadata enumeration.

Wire protocol
-------------
Commands  — one JSON object per line on stdin.
Events    — one JSON object per line on stdout.

Supported commands:
    {"cmd": "ping"}
    {"cmd": "list_devices"}
    {"cmd": "open", "udid": "<UDID>"}
    {"cmd": "list", "path": "/DCIM"}
    {"cmd": "stat", "path": "/DCIM/100APPLE/IMG_0001.HEIC"}
    {"cmd": "walk_hash",
     "roots": ["/DCIM", "/Downloads", "/Recordings"],
     "algos": ["sha256", "sha1", "md5"],
     "min_bytes": 0,
     "extensions": null}                  # or list of lowercase ".heic" etc.
    {"cmd": "pull", "path": "/PhotoData/Photos.sqlite", "dest": "C:/abs/path"}
    {"cmd": "quit"}

Event shapes:
    {"event": "ready"}
    {"event": "pong"}
    {"event": "devices",     "data": [...]}
    {"event": "opened",      "udid": "..."}
    {"event": "list_result", "path": "...", "entries": [...]}
    {"event": "stat_result", "path": "...", "data": {...}}
    {"event": "file_hash",   "path": "...", "size": N, "sha256": "...", ...}
    {"event": "walk_warn",   "path": "...", "error": "..."}
    {"event": "progress",    "files_done": N, "bytes_done": N, "elapsed_s": F}
    {"event": "complete",    "files_done": N, "bytes_done": N, "elapsed_s": F}
    {"event": "pulled",      "path": "...", "dest": "...", "size": N}
    {"event": "error",       "msg": "...", "cmd": {...}}
    {"event": "bye"}

Exit codes:
    0  graceful shutdown
    2  fatal init error (e.g. pymobiledevice3 missing)
"""

import sys
import os
import json
import time
import struct
import asyncio
import base64
import hashlib
import traceback
from typing import Any, Dict, List, Optional

# On Windows, console subprocesses (e.g. ffmpeg) pop a visible black window
# unless CREATE_NO_WINDOW is passed. This daemon already runs windowless, so
# keep any children it spawns windowless too. 0 on non-Windows = no-op.
_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0

try:
    from pymobiledevice3.lockdown import create_using_usbmux
    from pymobiledevice3.services.afc import AfcService, AfcOpcode
    from pymobiledevice3.usbmux import list_devices
except ImportError as e:
    sys.stdout.write(json.dumps({
        "event": "fatal",
        "msg": "pymobiledevice3 not installed",
        "details": str(e),
    }) + "\n")
    sys.stdout.flush()
    sys.exit(2)

# Exception types that indicate the underlying lockdown / AFC connection
# has gone away. When we see any of these we mark the daemon's
# connection as dead and rebuild lockdown + AfcService on the next call.
# The list is generous on purpose — the cost of a needless reconnect is
# ~200 ms while the cost of a missed reconnect is a hung scan.
_RECONNECT_EXCEPTIONS: tuple = tuple()
try:
    from pymobiledevice3 import exceptions as _pmd_exc  # type: ignore
    _candidates = [
        "ConnectionFailedError",
        "ConnectionFailedToUsbmuxdError",
        "ConnectionTerminatedError",
        "MuxException",
        "MuxVersionError",
        "NoDeviceConnectedError",
        "IRecvNoDeviceConnectedError",
        "StreamClosedError",
        "TunneldConnectionError",
        "AfcException",
    ]
    _RECONNECT_EXCEPTIONS = tuple(
        getattr(_pmd_exc, n) for n in _candidates if hasattr(_pmd_exc, n)
    )
except Exception:  # noqa: BLE001
    pass
# Always reconnect on the universal "the pipe broke" Python errors too.
_RECONNECT_EXCEPTIONS = _RECONNECT_EXCEPTIONS + (
    ConnectionError,
    BrokenPipeError,
    OSError,
    EOFError,
)
# Also treat `construct` parser errors as reconnectable. pymobiledevice3
# uses construct to parse the AFC wire protocol — every response starts
# with the magic header b'CFA6LPAA'. If a previous call's response bytes
# were left in the socket buffer (e.g. a cancelled fread coroutine), the
# next call reads them and fails the magic check. Symptom in logs:
#   "Error in path (parsing) -> magic"
#   "parsing expected b'CFA6LPAA' but parsed b'<garbage>'"
# Once the socket is desynced like that it stays broken until we
# rebuild — tear it down and reconnect.
try:
    import construct as _construct  # type: ignore
    _RECONNECT_EXCEPTIONS = _RECONNECT_EXCEPTIONS + (_construct.ConstructError,)
except Exception:  # noqa: BLE001
    pass

# Optional: Pillow for in-memory thumbnail generation. We degrade
# gracefully if it is missing — the `thumbnail` command will simply
# return an error event the UI can ignore.
try:
    import io
    from PIL import Image  # type: ignore
    _PIL_OK = True
except Exception:
    _PIL_OK = False

# Optional: HEIC support (iPhone default format). Without this we can
# still serve JPEG/PNG/WebP/GIF, but HEIC will fail to decode.
try:
    import pillow_heif  # type: ignore
    pillow_heif.register_heif_opener()
    _HEIC_OK = True
except Exception:
    _HEIC_OK = False


# Read 256 KB per AFC chunk. Larger reduces RPC overhead; smaller keeps
# the asyncio loop responsive to stop signals. 256 KB is a good middle.
CHUNK = 256 * 1024

# Progress events: emit every N files OR every T seconds, whichever first.
PROGRESS_EVERY_FILES = 25
PROGRESS_EVERY_SECONDS = 1.0


def emit(obj: Dict[str, Any]) -> None:
    """Write a single line of JSON to stdout and flush.

    All Rust-side parsing is line-oriented, so the JSON value itself
    must not contain raw newlines (json.dumps escapes them, so this is
    safe by default).
    """
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


# Daemon-side debug log file. Tauri's sidecar wrapper forwards our
# stderr via `eprintln!` but that output is interleaved with cargo /
# vite chatter and is hard to grep. Writing the [DBG ...] lines to a
# stable on-disk path lets the dev (or the agent) tail one file.
try:
    _DBG_LOG_PATH = os.path.join(
        os.environ.get("TEMP") or os.environ.get("TMP") or os.path.expanduser("~"),
        "scout_afc_daemon.log",
    )
    # Truncate on each daemon start so we only see this session.
    _DBG_LOG_FH = open(_DBG_LOG_PATH, "w", encoding="utf-8", buffering=1)
    _DBG_LOG_FH.write(
        f"--- ios_afc_daemon.py started pid={os.getpid()} "
        f"time={time.strftime('%Y-%m-%d %H:%M:%S')} ---\n"
    )
except Exception:
    _DBG_LOG_FH = None
    _DBG_LOG_PATH = None


def dbg(msg: str) -> None:
    """Write a debug line to both stderr (for live tailing) and the
    on-disk log file (for after-the-fact inspection). Never raises."""
    try:
        sys.stderr.write(msg + "\n")
        sys.stderr.flush()
    except Exception:
        pass
    if _DBG_LOG_FH is not None:
        try:
            _DBG_LOG_FH.write(msg + "\n")
        except Exception:
            pass


class Daemon:
    def __init__(self) -> None:
        self.lockdown = None
        self.afc: Optional[AfcService] = None
        self.udid: Optional[str] = None
        self._stop_walk = False
        # Serializes every single AFC round-trip (listdir / stat /
        # fopen / fread / fclose). pymobiledevice3 holds one socket per
        # AfcService, so concurrent ops would garble the wire — but
        # locking at the per-call granularity lets walk_hash and
        # thumbnail interleave at every chunk boundary instead of one
        # blocking the other for the entire scan.
        self._afc_lock: asyncio.Lock = asyncio.Lock()
        # ─── Priority gating ────────────────────────────────────────
        # Thumbnail / pull / read_range / stat are user-driven and need
        # to feel responsive. walk_hash is bulk background work. When
        # a high-priority RPC is queued or running we want walk_hash to
        # stop grabbing the AFC lock between chunks so the user op can
        # complete promptly instead of round-robin'ing every chunk.
        #
        # Increment on enter of a high-priority RPC; decrement on exit.
        # walk_hash awaits `_priority_idle` between files (and between
        # chunks of a single large file). The event is set whenever
        # the counter drops to 0.
        self._priority_count: int = 0
        self._priority_idle: asyncio.Event = asyncio.Event()
        self._priority_idle.set()
        # Background task handle for an in-flight walk_hash. The main
        # dispatcher loop kicks walk_hash off as a task so it does NOT
        # block ping / list / stat / thumbnail commands.
        self._walk_task: Optional[asyncio.Task] = None
        # When True, the next AFC call will tear down lockdown + AFC
        # and rebuild before running. Set whenever any AFC RPC raises
        # one of `_RECONNECT_EXCEPTIONS` so the next caller transparently
        # gets a healthy connection. Survives trust-dialog re-pairs,
        # USB selective-suspend, brief cable bumps, etc.
        self._connection_dead: bool = False
        self._reconnect_attempts: int = 0

    async def _reconnect_inside_lock(self, reason: str) -> None:
        """Tear down and rebuild lockdown + AFC. MUST be called while
        holding ``self._afc_lock``. Emits ``afc_reconnect`` / ``afc_reconnected``
        events so the Rust side / UI can show status.
        """
        if not self.udid:
            raise RuntimeError(
                "AFC connection lost and no UDID stored — cannot reconnect"
            )
        self._reconnect_attempts += 1
        emit({
            "event": "afc_reconnect",
            "udid": self.udid,
            "attempt": self._reconnect_attempts,
            "reason": str(reason)[:200],
        })

        # Best-effort teardown of the dead handles. Any of these may
        # raise because the socket is already gone — ignore.
        old_afc = self.afc
        self.afc = None
        if old_afc is not None:
            try:
                res = old_afc.close()
                if asyncio.iscoroutine(res):
                    await res
            except Exception:
                pass
        old_lockdown = self.lockdown
        self.lockdown = None
        if old_lockdown is not None:
            try:
                close_fn = getattr(old_lockdown, "close", None)
                if callable(close_fn):
                    res = close_fn()
                    if asyncio.iscoroutine(res):
                        await res
            except Exception:
                pass

        # Brief pause for usbmuxd to notice the device is still present
        # after a re-pair / trust-dialog accept.
        await asyncio.sleep(0.4)

        self.lockdown = await create_using_usbmux(serial=self.udid)
        self.afc = AfcService(self.lockdown)
        try:
            res = self.afc.connect()
            if asyncio.iscoroutine(res):
                await res
        except AttributeError:
            pass

        self._connection_dead = False
        emit({
            "event": "afc_reconnected",
            "udid": self.udid,
            "attempt": self._reconnect_attempts,
        })

    def _enter_priority(self) -> None:
        """Mark that a high-priority (user-driven) AFC RPC is queued or
        running. While count > 0, ``walk_hash`` yields between files
        and between chunks so it doesn't keep stealing the AFC lock."""
        self._priority_count += 1
        if self._priority_count == 1:
            self._priority_idle.clear()
            dbg(f"[DBG prio] high-priority entered (count=1)")

    def _exit_priority(self) -> None:
        if self._priority_count > 0:
            self._priority_count -= 1
        if self._priority_count == 0:
            self._priority_idle.set()
            dbg(f"[DBG prio] high-priority drained (count=0)")

    async def _afc(self, method: str, *args, **kwargs) -> Any:
        """Serialized AFC call with transparent reconnect.

        - If the connection was marked dead by a prior failure, rebuild
          it FIRST, then issue the requested op.
        - If THIS call raises a known disconnect exception, mark the
          connection dead and re-raise (the caller decides whether to
          retry; for stream ops like fread on an open fd a retry is
          pointless because the fd is stale, but the NEXT fopen will
          trigger a reconnect transparently).
        """
        async with self._afc_lock:
            if self._connection_dead:
                try:
                    await self._reconnect_inside_lock(
                        reason="prior op marked connection dead"
                    )
                except Exception as recon_e:
                    # Keep flag set so next attempt also tries to rebuild.
                    raise RuntimeError(
                        f"reconnect failed: {recon_e}"
                    ) from recon_e
            try:
                afc = self.require_afc()
                res = getattr(afc, method)(*args, **kwargs)
                if asyncio.iscoroutine(res):
                    res = await res
                return res
            except _RECONNECT_EXCEPTIONS as e:
                self._connection_dead = True
                raise

    async def _afc_call(self, value: Any) -> Any:
        """Legacy serialized AFC call wrapper.

        Kept only so any older code paths that still pass a pre-built
        coroutine continue to work. New code should use ``_afc(method,
        *args)`` so we can reconnect-and-retry transparently. This
        wrapper still honours the dead-connection flag (best-effort)
        but cannot retry the coroutine if it dies, because the
        coroutine is already bound to the (possibly dead) AfcService
        instance.
        """
        async with self._afc_lock:
            if self._connection_dead:
                try:
                    await self._reconnect_inside_lock(
                        reason="legacy _afc_call saw dead flag"
                    )
                except Exception as recon_e:
                    raise RuntimeError(
                        f"reconnect failed: {recon_e}"
                    ) from recon_e
            try:
                if asyncio.iscoroutine(value):
                    return await value
                return value
            except _RECONNECT_EXCEPTIONS:
                self._connection_dead = True
                raise

    async def _drain_feeder(self, feed_task: asyncio.Task) -> None:
        """Wait for an AFC→ffmpeg feeder coroutine to exit cleanly.

        Never cancels: cancelling mid-fread corrupts the AFC socket
        (see comment in `_video_thumbnail_impl`). We give it up to 10 s
        to finish its current chunk and notice the closed ffmpeg pipe;
        if it doesn't, mark the connection dead so the next op
        reconnects rather than reading garbage off the wire.
        """
        if feed_task.done():
            try:
                feed_task.result()
            except Exception:
                pass
            return
        try:
            await asyncio.wait_for(asyncio.shield(feed_task), timeout=10.0)
        except asyncio.TimeoutError:
            # Feeder is wedged in an AFC read; do NOT cancel — instead
            # mark the connection dead and detach. The next caller will
            # reconnect transparently.
            self._connection_dead = True
        except Exception:
            # Feeder raised — that's fine, it's done.
            pass

    # ----- connection management -----

    async def open(self, udid: Optional[str]) -> None:
        # Idempotent: if we already have a live AFC handle for this UDID,
        # do NOT tear down and re-pair. Every UI thumbnail / range
        # request currently does an "open" first, and re-pairing on each
        # one can trigger the iOS Trust dialog mid-session and leaves
        # pending operations hanging behind the rebuild.
        target_udid = udid
        if self.afc is not None and self.udid is not None and not self._connection_dead:
            if target_udid is None or target_udid == self.udid:
                emit({"event": "opened", "udid": self.udid, "reused": True})
                return

        if self.afc is not None:
            try:
                close_res = self.afc.close()
                if asyncio.iscoroutine(close_res):
                    await close_res
            except Exception:
                pass
            self.afc = None

        self.lockdown = await create_using_usbmux(serial=udid)
        # AfcService methods all return coroutines in current pymobiledevice3
        # even when iscoroutinefunction reports False on the class. Always
        # await results via _maybe_await below.
        self.afc = AfcService(self.lockdown)
        try:
            res = self.afc.connect()
            if asyncio.iscoroutine(res):
                await res
        except AttributeError:
            pass
        self.udid = udid or getattr(self.lockdown, "udid", None) or getattr(
            self.lockdown, "serial", None
        )
        self._connection_dead = False
        self._reconnect_attempts = 0
        emit({"event": "opened", "udid": self.udid})

    def require_afc(self) -> AfcService:
        if self.afc is None:
            raise RuntimeError(
                "No device open. Send {\"cmd\":\"open\", \"udid\":...} first."
            )
        return self.afc

    # ----- discovery -----

    @staticmethod
    async def list_devices() -> List[Dict[str, Any]]:
        devices = await _ar(list_devices())
        out: List[Dict[str, Any]] = []
        for d in devices:
            udid = (
                getattr(d, "serial", None)
                or getattr(d, "udid", None)
                or (d.get("SerialNumber") if isinstance(d, dict) else None)
                or (d.get("UniqueDeviceID") if isinstance(d, dict) else None)
            )
            if udid:
                out.append({"udid": udid})
        return out

    # ----- per-path ops -----

    async def list_dir(self, path: str) -> List[Dict[str, Any]]:
        self.require_afc()
        try:
            names = await self._afc("listdir", path)
        except Exception as e:
            raise RuntimeError(f"listdir failed for {path!r}: {e}")
        entries: List[Dict[str, Any]] = []
        for name in names:
            if name in (".", ".."):
                continue
            full = _join_posix(path, name)
            try:
                st = await self._afc("stat", full)
            except Exception:
                continue
            entries.append({
                "name": name,
                "path": full,
                "size": int(st.get("st_size", 0) or 0),
                "type": _type_from_stat(st),
                "mtime": _iso_from_stat(st),
            })
        return entries

    async def stat(self, path: str) -> Dict[str, Any]:
        self.require_afc()
        st = await self._afc("stat", path)
        return {
            "path": path,
            "size": int(st.get("st_size", 0) or 0),
            "type": _type_from_stat(st),
            "mtime": _iso_from_stat(st),
            "raw": {str(k): str(v) for k, v in st.items()},
        }

    # ----- streaming walk + hash (the triage workhorse) -----

    # Files in these sets stream fast (KBs each) and contain virtually
    # all the matches we care about in forensic triage. They get
    # priority over videos so the Hash Matches panel populates quickly.
    _IMAGE_EXTS = frozenset({
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp",
        ".heic", ".heif", ".tiff", ".tif", ".dng", ".raw",
        ".cr2", ".nef", ".arw", ".svg", ".ico",
    })
    _VIDEO_EXTS = frozenset({
        ".mp4", ".mov", ".m4v", ".avi", ".mkv", ".wmv",
        ".webm", ".3gp", ".3g2", ".flv", ".mpg", ".mpeg",
        ".mts", ".m2ts", ".hevc", ".ts",
    })

    async def walk_hash(
        self,
        roots: List[str],
        algos: List[str],
        min_bytes: int,
        extensions: Optional[List[str]],
    ) -> Dict[str, Any]:
        """Walk + hash with priority passes.

        Pass 1: images (small, fast — hash matches surface in seconds).
        Pass 2: videos (large, slow — runs only after images are done).
        Pass 3: everything else.

        The user-supplied ``extensions`` filter, if any, is intersected
        with each pass so it still constrains the search. Final
        ``complete`` event fires only after all passes finish.
        """
        self._stop_walk = False
        start = time.monotonic()

        # Normalize user-supplied extension filter (lowercase, with
        # leading dot). If non-empty, every pass gets intersected with it.
        user_ext: Optional[set] = None
        if extensions:
            user_ext = {e.lower() if e.startswith(".") else f".{e.lower()}"
                        for e in extensions}

        # Priority phases. None = "anything not already covered".
        phases = [
            ("images", set(self._IMAGE_EXTS)),
            ("videos", set(self._VIDEO_EXTS)),
            ("other", None),
        ]
        covered = set(self._IMAGE_EXTS) | set(self._VIDEO_EXTS)

        totals = {"files_done": 0, "bytes_done": 0}

        for phase_name, phase_set in phases:
            if self._stop_walk:
                break

            # Compute the actual extension allow-list for this phase.
            if phase_set is None:
                # "Other" phase — everything except images/videos.
                if user_ext is not None:
                    pass_ext: Optional[set] = user_ext - covered
                    if not pass_ext:
                        continue
                else:
                    # Sentinel: None means "everything except covered".
                    pass_ext = None  # handled inside _walk_pass via complement
            else:
                if user_ext is not None:
                    pass_ext = phase_set & user_ext
                    if not pass_ext:
                        continue
                else:
                    pass_ext = phase_set

            emit({"event": "phase_started", "phase": phase_name})
            files, bytes_n = await self._walk_pass(
                roots=roots,
                algos=algos,
                min_bytes=min_bytes,
                ext_allow=pass_ext,
                ext_exclude=(covered if phase_set is None else None),
                start_clock=start,
                totals=totals,
            )
            totals["files_done"] += files
            totals["bytes_done"] += bytes_n
            emit({
                "event": "phase_complete",
                "phase": phase_name,
                "files_done": files,
                "bytes_done": bytes_n,
            })
            if self._stop_walk:
                break

        elapsed = round(time.monotonic() - start, 3)
        if self._stop_walk:
            emit({
                "event": "stopped",
                "files_done": totals["files_done"],
                "bytes_done": totals["bytes_done"],
                "elapsed_s": elapsed,
            })
            return {**totals, "stopped": True, "elapsed_s": elapsed}

        emit({
            "event": "complete",
            "files_done": totals["files_done"],
            "bytes_done": totals["bytes_done"],
            "elapsed_s": elapsed,
        })
        return {**totals, "elapsed_s": elapsed}

    async def _walk_pass(
        self,
        roots: List[str],
        algos: List[str],
        min_bytes: int,
        ext_allow: Optional[set],
        ext_exclude: Optional[set],
        start_clock: float,
        totals: Dict[str, int],
    ) -> tuple:
        """Single-phase walk. Returns (files_done, bytes_done) for THIS pass.

        ``ext_allow``: if set, only files whose extension is in this set
        are hashed.
        ``ext_exclude``: if set, files whose extension is in this set
        are skipped (used by the catch-all "other" phase to skip what
        the image/video phases already covered).
        """
        self.require_afc()

        files_done = 0
        bytes_done = 0
        last_progress = start_clock

        # Iterative DFS. Avoid blowing the stack on huge trees.
        stack: List[str] = []
        for r in roots:
            stack.append(r.rstrip("/") or "/")

        while stack:
            if self._stop_walk:
                # Outer walk_hash will emit the final "stopped" event;
                # just bail out here with what we have.
                return (files_done, bytes_done)

            # Priority gate: if any user-driven RPC (thumbnail, pull,
            # read_range, stat) is queued or in-flight, pause the walk
            # so those operations can use the AFC connection without
            # round-robin'ing every chunk.
            if not self._priority_idle.is_set():
                dbg("[DBG walk] yielding to priority work (dir loop)")
                await self._priority_idle.wait()
                dbg("[DBG walk] resuming after priority drained (dir loop)")

            path = stack.pop()
            try:
                names = await self._afc("listdir", path)
            except Exception as e:
                emit({"event": "walk_warn", "path": path, "error": str(e)})
                continue

            for name in names:
                if name in (".", ".."):
                    continue
                full = _join_posix(path, name)
                try:
                    st = await self._afc("stat", full)
                except Exception as e:
                    emit({"event": "walk_warn", "path": full, "error": str(e)})
                    continue

                kind = _type_from_stat(st)
                if kind == "dir":
                    stack.append(full)
                    continue
                if kind != "file":
                    continue

                size = int(st.get("st_size", 0) or 0)
                if size < min_bytes:
                    continue

                # Extension gating: allow-list and/or exclude-list.
                dot = full.rfind(".")
                ext_l = full[dot:].lower() if dot >= 0 else ""
                if ext_allow is not None:
                    if ext_l not in ext_allow:
                        continue
                if ext_exclude is not None and ext_l in ext_exclude:
                    continue

                # Stream-hash this file. NEVER persist content to disk.
                try:
                    hashers = {a: hashlib.new(a) for a in algos}
                except ValueError as e:
                    emit({"event": "error", "msg": f"bad algo: {e}"})
                    return (files_done, bytes_done)

                file_bytes = 0
                try:
                    fd = await self._afc("fopen", full, mode="r")
                except Exception as e:
                    emit({"event": "walk_warn", "path": full,
                          "error": f"fopen: {e}"})
                    continue

                try:
                    while True:
                        if self._stop_walk:
                            break
                        # Yield to user-driven priority RPCs between
                        # chunks. This is critical for big videos where
                        # a single fread CHUNK takes hundreds of ms
                        # and would otherwise starve thumbnail RPCs
                        # competing for the same AFC connection.
                        if not self._priority_idle.is_set():
                            dbg(f"[DBG walk] yielding mid-file to priority ({full})")
                            await self._priority_idle.wait()
                            dbg(f"[DBG walk] resumed mid-file ({full})")
                        chunk = await self._afc("fread", fd, CHUNK)
                        if not chunk:
                            break
                        for h in hashers.values():
                            h.update(chunk)
                        file_bytes += len(chunk)
                except Exception as e:
                    emit({"event": "walk_warn", "path": full,
                          "error": f"fread: {e}"})
                    try:
                        await self._afc("fclose", fd)
                    except Exception:
                        pass
                    continue
                finally:
                    try:
                        await self._afc("fclose", fd)
                    except Exception:
                        pass

                if self._stop_walk:
                    continue

                files_done += 1
                bytes_done += file_bytes

                hit = {
                    "event": "file_hash",
                    "path": full,
                    "size": file_bytes,
                    "mtime": _iso_from_stat(st),
                }
                for a, h in hashers.items():
                    hit[a] = h.hexdigest()
                emit(hit)

                now = time.monotonic()
                if (files_done % PROGRESS_EVERY_FILES == 0 or
                        (now - last_progress) >= PROGRESS_EVERY_SECONDS):
                    emit({
                        "event": "progress",
                        "files_done": totals["files_done"] + files_done,
                        "bytes_done": totals["bytes_done"] + bytes_done,
                        "elapsed_s": round(now - start_clock, 3),
                    })
                    last_progress = now

        return (files_done, bytes_done)

    def request_stop_walk(self) -> None:
        self._stop_walk = True

    # ----- on-demand single-file pull (Photos.sqlite, thumbnails, etc.) -----

    async def pull(self, path: str, dest: str) -> Dict[str, Any]:
        self.require_afc()
        os.makedirs(os.path.dirname(os.path.abspath(dest)), exist_ok=True)
        size = 0
        fd = await self._afc("fopen", path, mode="r")
        try:
            with open(dest, "wb") as out:
                while True:
                    chunk = await self._afc("fread", fd, CHUNK)
                    if not chunk:
                        break
                    out.write(chunk)
                    size += len(chunk)
        finally:
            try:
                await self._afc("fclose", fd)
            except Exception:
                pass
        return {"path": path, "dest": dest, "size": size}

    # ----- AFC random-access (for HTTP Range playback) -----

    async def _afc_seek(self, fd: int, offset: int, whence: int = 0) -> None:
        """Issue an AFC FILE_SEEK packet for an open handle.

        pymobiledevice3's AfcService doesn't expose a public seek
        wrapper, but the protocol op is defined (FILE_SEEK = 0x11) and
        the packet payload is just three little-endian quad-words:
        handle, whence (0=SET, 1=CUR, 2=END), offset.
        """
        payload = struct.pack("<QQq", int(fd), int(whence), int(offset))
        await self._afc("_do_operation", AfcOpcode.FILE_SEEK, payload)

    async def read_range(self, path: str, offset: int,
                          length: int) -> Dict[str, Any]:
        """Read [offset, offset+length) bytes from `path`. Reconnects
        transparently and retries once on connection failure (so
        playback survives a trust-dialog re-pair mid-stream).
        """
        if length < 0:
            raise RuntimeError(f"negative length: {length}")
        if length == 0:
            return {
                "path": path,
                "offset": offset,
                "length": 0,
                "data_b64": "",
                "eof": False,
            }
        last_err: Optional[Exception] = None
        for attempt in (0, 1):
            try:
                return await self._read_range_impl(path, offset, length)
            except _RECONNECT_EXCEPTIONS as e:
                last_err = e
                # _afc has already marked the connection dead; next
                # call inside _read_range_impl will reconnect first.
                continue
            except Exception as e:
                # Non-connection failure — don't retry.
                raise
        raise RuntimeError(
            f"read_range failed after reconnect: {last_err}"
        )

    async def _read_range_impl(self, path: str, offset: int,
                                length: int) -> Dict[str, Any]:
        fd = await self._afc("fopen", path, mode="r")
        try:
            if offset > 0:
                await self._afc_seek(fd, offset, whence=0)
            # Loop because fread might return short reads near EOF.
            buf = bytearray()
            remaining = length
            while remaining > 0:
                chunk = await self._afc("fread", fd, min(remaining, CHUNK))
                if not chunk:
                    break
                buf.extend(chunk)
                remaining -= len(chunk)
            eof = len(buf) < length
        finally:
            try:
                await self._afc("fclose", fd)
            except Exception:
                pass
        return {
            "path": path,
            "offset": offset,
            "length": len(buf),
            "data_b64": base64.b64encode(bytes(buf)).decode("ascii"),
            "eof": eof,
        }

    # ----- video thumbnail (AFC → tempfile → ffmpeg) -----

    async def video_thumbnail(self, path: str, max_dim: int = 320,
                               quality: int = 5,
                               max_bytes: int = 8 * 1024 * 1024 * 1024,
                               seek_seconds: float = 0.5) -> Dict[str, Any]:
        """Stream `path` bytes via AFC into a temp file on local disk,
        then run ffmpeg with a seekable file input to extract one
        frame at ~`seek_seconds`.

        Why temp-file instead of a pipe: iPhone Camera.app writes the
        `moov` atom at the END of the file for most `.MOV` recordings.
        Without seek, ffmpeg sees raw `mdat` bytes and emits
        `Invalid data found when processing input`. A seekable file
        lets ffmpeg jump to the trailing `moov` and decode normally.

        `max_bytes` defaults to 8 GB — effectively unlimited for any
        real iPhone recording. iOS desktop runs on workstations with
        plenty of disk, so we'd rather pay the IO than skip thumbnails.
        Reconnects + retries once on AFC disconnect.
        """
        last_err: Optional[Exception] = None
        for attempt in (0, 1):
            try:
                return await self._video_thumbnail_impl(
                    path, max_dim, quality, max_bytes, seek_seconds,
                )
            except _RECONNECT_EXCEPTIONS as e:
                last_err = e
                continue
        raise RuntimeError(
            f"video_thumbnail failed after reconnect: {last_err}"
        )

    async def _video_thumbnail_impl(self, path: str, max_dim: int,
                                     quality: int, max_bytes: int,
                                     seek_seconds: float) -> Dict[str, Any]:
        import tempfile
        dbg(f"[DBG vthumb] enter path={path!r} max_dim={max_dim} "
            f"max_bytes={max_bytes}")
        ffmpeg_path = os.environ.get("SCOUT_FFMPEG") or "ffmpeg"

        # --- Phase 1: AFC fopen + stream bytes into a temp file ---
        # Use NamedTemporaryFile with delete=False so we control unlink
        # after ffmpeg is done. .mp4 suffix nudges ffmpeg's autodetect.
        tmp = tempfile.NamedTemporaryFile(
            prefix="scout_vthumb_", suffix=".mp4", delete=False,
        )
        tmp_path = tmp.name
        tmp.close()
        dbg(f"[DBG vthumb] tempfile={tmp_path!r}")

        fd = await self._afc("fopen", path, mode="r")
        dbg(f"[DBG vthumb] fopen ok path={path!r} fd={fd!r}")

        feed_total = 0
        first_chunk_sz = -1
        truncated = False
        try:
            with open(tmp_path, "wb") as fh:
                while feed_total < max_bytes:
                    try:
                        chunk = await self._afc("fread", fd, CHUNK)
                    except _RECONNECT_EXCEPTIONS as e:
                        # Propagate to outer retry; tempfile cleaned in
                        # the finally below.
                        dbg(f"[DBG vthumb] fread disconnect "
                            f"{type(e).__name__}: {e}")
                        raise
                    if first_chunk_sz < 0:
                        first_chunk_sz = 0 if chunk is None else len(chunk)
                        dbg(f"[DBG vthumb] first fread fd={fd!r} "
                            f"len={first_chunk_sz}")
                    if not chunk:
                        break
                    fh.write(chunk)
                    feed_total += len(chunk)
                else:
                    # Loop exited because feed_total >= max_bytes (else
                    # clause runs only on natural while-loop end, but we
                    # use it here for "hit the cap" path because the
                    # while-condition itself exits at the cap).
                    truncated = True
        finally:
            try:
                await self._afc("fclose", fd)
            except Exception:
                pass

        dbg(f"[DBG vthumb] stream done feed_total={feed_total} "
            f"truncated={truncated}")

        if feed_total == 0:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
            raise RuntimeError(
                "video thumbnail: AFC returned 0 bytes "
                "(connection may be wedged)"
            )

        # --- Phase 2: ffmpeg with seekable file input ---
        # No probesize/analyzeduration overrides needed — a seekable
        # file lets ffmpeg jump to the moov atom regardless of where
        # it lives. `-ss` BEFORE `-i` is fast seek (works on files,
        # not on pipes); `-ss` AFTER `-i` is decoded seek (precise but
        # slow). For thumbnails, fast seek is fine.
        scale_filter = (
            f"scale='if(gt(iw,ih),{max_dim},-2)':"
            f"'if(gt(iw,ih),-2,{max_dim})'"
        )
        cmd = [
            ffmpeg_path,
            "-hide_banner", "-loglevel", "error",
            "-ss", str(seek_seconds),
            "-i", tmp_path,
            "-frames:v", "1",
            "-vf", scale_filter,
            "-q:v", str(quality),
            "-f", "image2",
            "pipe:1",
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                creationflags=_NO_WINDOW,
            )
        except FileNotFoundError:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
            raise RuntimeError(
                f"ffmpeg not found at {ffmpeg_path!r}. "
                "Set SCOUT_FFMPEG env var or install ffmpeg."
            )

        try:
            stdout_data, stderr_data = await asyncio.wait_for(
                proc.communicate(), timeout=60.0
            )
        except asyncio.TimeoutError:
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
            raise RuntimeError("ffmpeg timed out generating video thumbnail")
        finally:
            # Always remove the temp file once ffmpeg has its bytes.
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

        if proc.returncode != 0 or not stdout_data:
            stderr_txt = (
                (stderr_data or b"").decode("utf-8", errors="replace").strip()
            )
            details = stderr_txt or "no output"
            dbg(f"[DBG vthumb] ffmpeg fail rc={proc.returncode} "
                f"truncated={truncated} feed_total={feed_total} "
                f"err={details[:200]!r}")
            hint = ""
            if truncated:
                hint = (
                    f" (file truncated at {max_bytes // (1024*1024)} MB; "
                    "moov may be past the cap)"
                )
            raise RuntimeError(
                f"ffmpeg failed (rc={proc.returncode}): {details[:400]}{hint}"
            )

        dbg(f"[DBG vthumb] ffmpeg ok out_bytes={len(stdout_data)} "
            f"src_bytes={feed_total}")

        b64 = base64.b64encode(stdout_data).decode("ascii")
        return {
            "path": path,
            "data_url": f"data:image/jpeg;base64,{b64}",
            "src_bytes": feed_total,
            "out_bytes": len(stdout_data),
            "truncated": truncated,
        }

    async def thumbnail(self, path: str, max_dim: int = 256,
                        quality: int = 70,
                        max_bytes: int = 30 * 1024 * 1024) -> Dict[str, Any]:
        """Stream `path` bytes via AFC into memory, decode with PIL,
        resize to fit `max_dim` on the long edge, encode as JPEG, and
        return a base64 data URL. Reconnects + retries once on AFC
        disconnect.
        """
        if not _PIL_OK:
            raise RuntimeError("Pillow not installed in daemon environment")
        last_err: Optional[Exception] = None
        for attempt in (0, 1):
            try:
                return await self._thumbnail_impl(path, max_dim, quality, max_bytes)
            except _RECONNECT_EXCEPTIONS as e:
                last_err = e
                continue
        raise RuntimeError(
            f"thumbnail failed after reconnect: {last_err}"
        )

    async def _thumbnail_impl(self, path: str, max_dim: int, quality: int,
                              max_bytes: int) -> Dict[str, Any]:
        dbg(f"[DBG ithumb] enter path={path!r} max_dim={max_dim}")
        buf = bytearray()
        fd = await self._afc("fopen", path, mode="r")
        dbg(f"[DBG ithumb] fopen ok fd={fd!r}")
        first_chunk_sz = -1
        try:
            while True:
                chunk = await self._afc("fread", fd, CHUNK)
                if first_chunk_sz < 0:
                    first_chunk_sz = 0 if chunk is None else len(chunk)
                    dbg(f"[DBG ithumb] first fread fd={fd!r} "
                          f"len={first_chunk_sz}")
                if not chunk:
                    break
                buf.extend(chunk)
                if len(buf) > max_bytes:
                    raise RuntimeError(
                        f"file too large for thumbnail ({len(buf)} > {max_bytes})"
                    )
        finally:
            try:
                await self._afc("fclose", fd)
            except Exception:
                pass
        dbg(f"[DBG ithumb] read done path={path!r} total={len(buf)} "
            f"first_chunk_sz={first_chunk_sz}")

        # Sniff the first 16 bytes so we can prove whether AFC handed us
        # a real PNG / JPEG / HEIC etc. Some iOS devices write Apple
        # PhotoFormat blobs to .PNG files that vanilla Pillow can't
        # decode without HEIF/AVIF plugins.
        sniff = bytes(buf[:16])
        dbg(f"[DBG ithumb] magic={sniff.hex()} preview={sniff!r}")

        try:
            dbg(f"[DBG ithumb] PIL open start path={path!r}")
            img = Image.open(io.BytesIO(bytes(buf)))
            fmt_before = img.format
            img.load()  # Force-decode now while bytes are alive.
            dbg(f"[DBG ithumb] PIL load OK path={path!r} "
                f"fmt={fmt_before} mode={img.mode} size={img.size}")
        except Exception as e:
            # Dump the offending bytes to disk so we can post-mortem the
            # exact wire format the device handed us.
            try:
                dump_dir = os.environ.get("TEMP") or os.path.expanduser("~")
                safe_name = path.replace("/", "_").lstrip("_")
                dump_path = os.path.join(dump_dir, f"scout_afc_fail_{safe_name}.bin")
                with open(dump_path, "wb") as fh:
                    fh.write(bytes(buf))
                dbg(f"[DBG ithumb] PIL FAIL path={path!r} err={e!r} "
                    f"dumped={dump_path}")
            except Exception as dump_e:
                dbg(f"[DBG ithumb] PIL FAIL path={path!r} err={e!r} "
                    f"(dump also failed: {dump_e!r})")
            raise RuntimeError(f"PIL decode failed: {e}")

        # EXIF orientation respected so portraits aren't sideways.
        try:
            from PIL import ImageOps  # local import; tiny
            img = ImageOps.exif_transpose(img)
        except Exception:
            pass

        if img.mode not in ("RGB", "L"):
            dbg(f"[DBG ithumb] convert {img.mode}->RGB path={path!r}")
            img = img.convert("RGB")
        img.thumbnail((max_dim, max_dim), Image.LANCZOS)
        dbg(f"[DBG ithumb] resized to {img.size} path={path!r}")

        out = io.BytesIO()
        img.save(out, format="JPEG", quality=quality, optimize=True)
        b64 = base64.b64encode(out.getvalue()).decode("ascii")
        dbg(f"[DBG ithumb] return path={path!r} jpeg_bytes={len(out.getvalue())} b64_bytes={len(b64)}")
        return {
            "path": path,
            "data_url": f"data:image/jpeg;base64,{b64}",
            "width": img.width,
            "height": img.height,
            "src_bytes": len(buf),
            "out_bytes": len(b64),
        }


# ----- helpers ----------------------------------------------------------

async def _ar(value: Any) -> Any:
    """Await `value` if it is a coroutine, otherwise return it as-is.

    pymobiledevice3's AfcService wraps methods so that ``listdir``,
    ``stat``, ``fopen``, ``fread``, ``fclose`` (and friends) return
    coroutines at call-time even though ``inspect.iscoroutinefunction``
    reports them as sync at class-level. Always feed AFC results
    through this helper.
    """
    if asyncio.iscoroutine(value):
        return await value
    return value


def _join_posix(parent: str, name: str) -> str:
    if parent in ("", "/"):
        return "/" + name
    return parent.rstrip("/") + "/" + name


def _type_from_stat(st: Dict[str, Any]) -> str:
    ifmt = str(st.get("st_ifmt", "")).upper()
    if ifmt in ("S_IFDIR", "DIR"):
        return "dir"
    if ifmt in ("S_IFREG", "FILE"):
        return "file"
    if ifmt in ("S_IFLNK", "LINK"):
        return "link"
    return "other"


def _iso_from_stat(st: Dict[str, Any]) -> Optional[str]:
    """Best-effort mtime extraction. AFC returns nanosecond strings."""
    for key in ("st_mtime", "st_birthtime"):
        v = st.get(key)
        if v is None:
            continue
        try:
            ns = int(v)
            # AFC reports ns since epoch on modern iOS.
            secs = ns / 1_000_000_000 if ns > 10**12 else float(ns)
            return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(secs))
        except (TypeError, ValueError):
            continue
    return None


# ----- main loop -------------------------------------------------------

async def _stdin_lines():
    """Yield stdin lines without blocking the event loop."""
    loop = asyncio.get_event_loop()
    while True:
        line = await loop.run_in_executor(None, sys.stdin.readline)
        if not line:
            return
        yield line


async def main() -> int:
    daemon = Daemon()
    emit({"event": "ready"})

    # Strong references to in-flight thumbnail tasks so the GC doesn't
    # reap them mid-execution. Tasks are removed via done_callback once
    # they finish (success OR exception).
    _inflight_tasks: "set[asyncio.Task]" = set()

    async for raw in _stdin_lines():
        line = raw.strip()
        if not line:
            continue
        try:
            cmd = json.loads(line)
        except json.JSONDecodeError as e:
            emit({"event": "error", "msg": f"bad json: {e}", "raw": line[:200]})
            continue

        op = cmd.get("cmd")
        try:
            if op == "ping":
                emit({"event": "pong"})

            elif op == "list_devices":
                data = await Daemon.list_devices()
                emit({"event": "devices", "data": data})

            elif op == "open":
                await daemon.open(cmd.get("udid"))

            elif op == "list":
                entries = await daemon.list_dir(cmd["path"])
                emit({"event": "list_result", "path": cmd["path"],
                      "entries": entries})

            elif op == "stat":
                emit({"event": "stat_result",
                      "path": cmd["path"],
                      "data": await daemon.stat(cmd["path"])})

            elif op == "walk_hash":
                if daemon._walk_task is not None and not daemon._walk_task.done():
                    emit({"event": "error",
                          "msg": "walk_hash already in progress; send stop_walk first"})
                else:
                    roots = list(cmd.get("roots", ["/DCIM"]))
                    algos = list(cmd.get("algos", ["sha256"]))
                    min_bytes = int(cmd.get("min_bytes", 0))
                    extensions = cmd.get("extensions")

                    async def _run_walk(
                        _roots=roots, _algos=algos,
                        _min_bytes=min_bytes, _extensions=extensions,
                    ) -> None:
                        try:
                            await daemon.walk_hash(
                                roots=_roots, algos=_algos,
                                min_bytes=_min_bytes, extensions=_extensions,
                            )
                        except Exception as ex:
                            emit({"event": "error",
                                  "msg": f"walk_hash failed: {ex}",
                                  "trace": traceback.format_exc(limit=5)})

                    daemon._walk_task = asyncio.create_task(_run_walk())
                    emit({"event": "walk_started", "roots": roots})

            elif op == "stop_walk":
                daemon.request_stop_walk()
                emit({"event": "stop_requested"})

            elif op == "pull":
                daemon._enter_priority()
                try:
                    r = await daemon.pull(cmd["path"], cmd["dest"])
                    emit({"event": "pulled", **r})
                finally:
                    daemon._exit_priority()

            elif op == "thumbnail":
                # Run as a background task so the main dispatcher can
                # keep accepting commands. Without this, an image-thumb
                # request that arrives after a video-thumb has to wait
                # for the video's full AFC copy + ffmpeg run (could be
                # 30+ s for a big MOV) before the dispatcher even reads
                # the next stdin line.
                #
                # Enter priority synchronously here so walk_hash starts
                # yielding before the task is even scheduled. The task
                # itself only EXITS priority on completion.
                daemon._enter_priority()
                async def _run_thumb(_cmd=cmd):
                    try:
                        r = await daemon.thumbnail(
                            _cmd["path"],
                            max_dim=int(_cmd.get("max_dim", 256)),
                            quality=int(_cmd.get("quality", 70)),
                        )
                        dbg(f"[DBG dispatch] emit thumbnail_result path={r.get('path')!r} b64_len={r.get('out_bytes')}")
                        emit({"event": "thumbnail_result", **r})
                    except Exception as ex:  # noqa: BLE001
                        dbg(f"[DBG dispatch] thumbnail EXC path={_cmd.get('path')!r} err={ex!r}")
                        emit({
                            "event": "error",
                            "msg": str(ex),
                            "cmd": _cmd,
                            "trace": traceback.format_exc(limit=5),
                        })
                    finally:
                        daemon._exit_priority()
                _t = asyncio.create_task(_run_thumb())
                _inflight_tasks.add(_t)
                _t.add_done_callback(_inflight_tasks.discard)

            elif op == "video_thumbnail":
                daemon._enter_priority()
                async def _run_vthumb(_cmd=cmd):
                    try:
                        r = await daemon.video_thumbnail(
                            _cmd["path"],
                            max_dim=int(_cmd.get("max_dim", 320)),
                            quality=int(_cmd.get("quality", 5)),
                            seek_seconds=float(
                                _cmd.get("seek_seconds", 0.5)
                            ),
                        )
                        emit({"event": "video_thumbnail_result", **r})
                    except Exception as ex:  # noqa: BLE001
                        emit({
                            "event": "error",
                            "msg": str(ex),
                            "cmd": _cmd,
                            "trace": traceback.format_exc(limit=5),
                        })
                    finally:
                        daemon._exit_priority()
                _t = asyncio.create_task(_run_vthumb())
                _inflight_tasks.add(_t)
                _t.add_done_callback(_inflight_tasks.discard)

            elif op == "read_range":
                daemon._enter_priority()
                try:
                    r = await daemon.read_range(
                        cmd["path"],
                        offset=int(cmd.get("offset", 0)),
                        length=int(cmd.get("length", 0)),
                    )
                    # Echo request_id so the Rust side can pair concurrent
                    # ranges. Optional.
                    rid = cmd.get("request_id")
                    payload = {"event": "read_range_result", **r}
                    if rid is not None:
                        payload["request_id"] = rid
                    emit(payload)
                finally:
                    daemon._exit_priority()

            elif op == "quit":
                emit({"event": "bye"})
                return 0

            else:
                emit({"event": "error", "msg": f"unknown cmd: {op!r}",
                      "cmd": cmd})

        except Exception as e:
            emit({"event": "error", "msg": str(e), "cmd": cmd,
                  "trace": traceback.format_exc(limit=5)})

    return 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        emit({"event": "bye"})
        sys.exit(0)
