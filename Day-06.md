# CTF Writeup — “Overheard at Breakfast”

### TryHackMe · Hacker Holidays · OSINT · Easy · 60 Points

**Flag:** `THM{XXXXXXXX}`

---

## TL;DR

A chat screenshot leaks an email address along with a clue about a **free profile tool starting with “G”**. The room’s **Hashing** theme provides the final hint.

The answer is **Gravatar**.

Gravatar profiles can be queried using the **MD5 hash of a normalized email address**. By hashing the leaked email, retrieving the corresponding Gravatar profile, and inspecting its `aboutMe` field, we find a Base64-encoded message containing the flag.

### Attack Chain

```text
Chat screenshot
      │
      ▼
Leaked email + "free profile tool starting with G"
      │
      ▼
Hashing clue + profile service
      │
      ▼
Gravatar
      │
      ▼
MD5(normalized email)
      │
      ▼
Gravatar JSON profile
      │
      ▼
aboutMe field
      │
      ▼
Base64 decode
      │
      ▼
FLAG
```

---

# 1. Read the Conversation Carefully

The biggest clue in this challenge is hidden in plain sight.

Mia tells us to **actually read what was said instead of skimming the conversation**.

The target mentions two important things:

> “I used to use this free tool that let me upload my profile and link other media accounts…”

and:

> “Started with a `G` if I remember correctly.”

She also provides her preferred method of communication:

```text
<target-email>@gmail.com
```

This gives us three useful clues:

* A **free profile service**
* It starts with **G**
* We have the target's **email address**

Combined with the room's **Hashing** theme, this strongly points toward **Gravatar**.

---

# 2. What Is Gravatar?

**Gravatar** stands for **Globally Recognized Avatar**.

It allows websites to associate an avatar and profile information with an email address. Instead of exposing the email directly in the lookup URL, the service uses a hash derived from the email.

The important concept for this challenge is:

```text
Email address
     │
     ▼
Normalize email
     │
     ▼
MD5 hash
     │
     ▼
Gravatar profile
```

Because the process is deterministic, the same normalized email always produces the same MD5 value.

This makes an email address a potentially useful **OSINT correlation point**.

---

# 3. Generate the Gravatar Hash

First, normalize the email and calculate its MD5 hash.

```bash
echo -n "someone@example.com" | tr '[:upper:]' '[:lower:]' | md5sum
```

### Why these commands?

* `echo -n` prevents an extra newline from being included.
* `tr '[:upper:]' '[:lower:]'` converts uppercase characters to lowercase.
* `md5sum` calculates the MD5 digest.

The output will look similar to:

```text
<32-character-md5-hash>
```

That hash becomes the identifier used to query the Gravatar profile.

---

# 4. Query the Gravatar Profile

Gravatar provides a JSON representation of a profile using the hash.

```bash
curl -s "https://gravatar.com/<md5hash>.json" | python3 -m json.tool
```

The JSON response contains profile information such as:

* Display name
* Location
* Profile username
* Bio / `aboutMe`
* Linked accounts or other profile information

The interesting part is the `aboutMe` field.

A shortened version looks like:

```json
{
    "aboutMe": "... email hashes follow you places you didn't expect ... Here is your prize: <base64-string>"
}
```

This is the key discovery.

---

# 5. Decode the Base64 Payload

The `aboutMe` field contains a Base64-encoded string.

Extract the encoded value and decode it:

```bash
echo '<base64-string>' | base64 -d
```

The decoded output reveals the flag:

```text
THM{XXXXXXXX}
```

---

# 6. Why the Attack Works

The important lesson is not simply “search Gravatar.”

The real lesson is **identity correlation through stable identifiers**.

An email address can act as a common identifier across multiple services. If a public service derives a predictable identifier from that email, anyone who already knows the email may be able to investigate whether a corresponding public profile exists.

In this challenge:

```text
Known email
    ↓
MD5 hash
    ↓
Gravatar lookup
    ↓
Public profile
    ↓
Hidden Base64 payload
    ↓
Flag
```

No exploitation or authentication bypass was required.

The challenge was primarily about recognizing the relationship between the clues.

---

# 7. OSINT Takeaways

### 1. Read leaked conversations literally

The challenge practically tells us the answer:

* Free profile service
* Starts with `G`
* Email address
* Hashing theme

The trick is noticing how those clues fit together.

### 2. Emails can be powerful OSINT identifiers

An email may connect multiple online identities and services.

When conducting **authorized OSINT**, an email can be a useful starting point for identifying publicly exposed profiles.

### 3. Check structured profile data

Don't only look at the visible webpage.

Machine-readable endpoints may expose useful fields such as:

```text
aboutMe
username
location
accounts
profile URLs
```

### 4. Look for encoded data

CTF challenges frequently hide information using common encodings.

If something looks suspiciously random, test common formats such as:

```text
Base64
Hex
URL encoding
```

Always verify what the data actually represents before assuming it is encrypted.

---

# 8. Defensive / Privacy Lessons

This challenge also demonstrates why **email reuse can create unwanted identity correlation**.

### Avoid unnecessary email reuse

Using the same email everywhere makes it easier to connect accounts belonging to the same person.

For privacy-sensitive use cases, separate identities should use appropriately separated accounts and identifiers.

### Remove old profiles completely

Deleting posts or profile content is not necessarily the same as deleting the underlying account.

Old profile records can remain discoverable depending on the service.

### Review public profile information

Regularly check what information is publicly associated with your email addresses, usernames, and other identifiers.

---

# 9. Detection Opportunities

For organizations, this technique can also be relevant during defensive security assessments.

Security teams can monitor whether:

* Employee email addresses appear in public profiles.
* Corporate identifiers are exposed through third-party services.
* Old employee accounts remain publicly associated with company addresses.
* Public profile information reveals unnecessary organizational details.

This is useful for **authorized exposure monitoring and attack-surface management**.

---

# 10. Command Cheat Sheet

### Generate the MD5 hash

```bash
echo -n "email@example.com" | tr '[:upper:]' '[:lower:]' | md5sum
```

### Query the Gravatar profile

```bash
curl -s "https://gravatar.com/<md5hash>.json" | python3 -m json.tool
```

### Open the human-readable profile

```text
https://gravatar.com/<md5hash>
```

### Decode Base64

```bash
echo '<base64-string>' | base64 -d
```

---

# 11. Final Takeaways

There are two lessons worth remembering from this challenge:

### **1. An email can become an identity pivot**

A single known email address can sometimes lead to publicly accessible profiles and additional identity information when services use deterministic identifiers.

### **2. Read every clue**

The challenge did not require complicated exploitation.

The service, hashing concept, and target email were all provided through the conversation. The main skill was recognizing the clues and connecting them.

---

## Conclusion

“Overheard at Breakfast” is a good example of a simple but effective OSINT challenge.

The complete path was:

```text
Conversation
   ↓
Email address
   ↓
"Free profile tool starting with G"
   ↓
Gravatar
   ↓
MD5(email)
   ↓
Public profile
   ↓
aboutMe
   ↓
Base64
   ↓
THM{XXXXXXXX}
```

The challenge demonstrates how seemingly harmless information can become a useful identity pivot when combined with public services and deterministic identifiers.

**Target, conversation, and profile information in this writeup are fictional challenge material. The analysis involved only the provided challenge data and a public profile lookup — no unauthorized access or intrusion was performed.**
