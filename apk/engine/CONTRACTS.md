# DeadNet engine — swarm build rules

All multi-card redesign code lives under `apk/engine/` (Python) and `apk/src/` (C++).
**`apk/engine/contracts.py` is the single source of truth.** Import from it; never
redefine its dataclasses, enums, DB names, SQL schema, or the shared-memory layout.

## Hard rules for every unit
1. **Create only your own new file(s).** Do NOT edit `main.py`, `main.kv`,
   `buildozer.spec`, `deadnet_apk.py`, or another unit's file — integration is done
   separately and in serial. If you need something from another unit, import it by the
   name given in the work-unit brief (it will exist at integration time) and code to
   `contracts.py`.
2. **Import the data model**: `from engine.contracts import ...` (the app runs with
   `apk/` on sys.path, so the package is `engine`). In standalone tests you may need to
   add the repo's `apk/` dir to `sys.path`.
3. **Every unit ships a `if __name__ == "__main__":` self-test** that runs on the x86_64
   build box (no device, no root) and prints PASS/FAIL. Mock `su`/`iw`/`ip` output from
   captured strings rather than calling them.
4. **No new pip/runtime deps.** Python stdlib only (sqlite3, struct, mmap, ctypes,
   subprocess, threading are all fine and bundled). C++ uses only the NDK sysroot.
5. **Root exec pattern**: shell out via `subprocess` with `["su","-c", cmd]`, matching
   `apk/utils/net_utils.py`. Keep all privileged calls in one place per unit.
6. **Logging**: `from kivy.logger import Logger` guarded by try/except so units import
   cleanly off-device (Kivy may be absent in a bare test env).

## Shared-memory (emit.cpp <-> EmissionController)
Layout + seqlock protocol is fully specified in `contracts.py` (FOCUS_* / STATS_*).
The C++ side must hardcode the byte offsets exactly as documented there. One focus +
one stats file per Transmitter card at `<appdir>/focus_<iface>.shm` / `stats_<iface>.shm`,
each pre-sized to `FOCUS_FILE_SIZE` / `STATS_FILE_SIZE`.

## Thematic naming
scents = detected signals/electronics; attention = focus weight; escaped envelopes =
leaked/surviving packets. Keep it consistent with `contracts.py`.
