# CTF Writeup — "Management Wants a Word"

### TryHackMe · Hacker Holidays Day 14 · Forensics · Hard · 120 pts

**Category:** Forensics
**Techniques:** Windows Triage → Registry Secrets → DPAPI → Chrome Credential Recovery → VeraCrypt
**Flag:** `THM{xxx}`

---

## 1. Overview

**Management Wants a Word** is a Windows forensics challenge involving a KAPE triage collection from Vera's laptop.

The collected evidence contains:

* Windows registry hives
* Vera's Chrome profile
* Windows DPAPI master keys
* A suspicious extensionless file named `backup`

The `backup` file turns out to be a **VeraCrypt encrypted container**.

The password for that container is stored in Chrome. However, Chrome protects its saved credentials using Windows **DPAPI**, so the Windows user's password must be recovered first.

The complete chain is:

```text
KAPE Triage
    │
    ├── SAM + SYSTEM + SECURITY
    │          │
    │          ▼
    │     Recover Windows password
    │          │
    │          ▼
    │       minivera
    │
    ├── DPAPI Master Key + SID + password
    │          │
    │          ▼
    │     Decrypt DPAPI key
    │
    ├── Chrome Local State + Login Data
    │          │
    │          ▼
    │     Recover saved password
    │          │
    │          ▼
    │   [REDACTED]
    │
    └── Documents\backup
               │
               ▼
         VeraCrypt container
               │
               ▼
        Decrypted FAT filesystem
               │
               ▼
       Invoice PDF → embedded image
               │
               ▼
            THM{xxx}
```

---

# 2. Challenge Clues

Several clues in the challenge point toward the eventual solution.

### Browser clue

The statement:

> "a browser will remember things for you that you never told anyone else"

suggests checking browser-saved credentials.

### Password clue

The hint:

> "not every hidden file needs a password cracker, some of them just need a really good memory"

suggests that the password is already stored somewhere rather than needing brute force.

### Version clue

The version:

```text
1.26.29
```

points toward **VeraCrypt**, helping identify the suspicious `backup` file.

---

# 3. Understanding the Technologies

## Windows Registry

Important Windows registry hives include:

```text
SAM
SYSTEM
SECURITY
SOFTWARE
```

The SAM and SYSTEM hives can be combined to recover Windows account password hashes.

The SECURITY hive can also contain LSA secrets, including information related to automatic logon.

---

## Windows DPAPI

**DPAPI — Data Protection API** is used by Windows applications to protect sensitive information.

Chrome can use DPAPI to protect the encryption key used for stored credentials.

Conceptually:

```text
Chrome password
      │
      ▼
Chrome encryption key
      │
      ▼
Windows DPAPI
      │
      ▼
User's Windows credentials
```

Therefore, recovering the Windows user's password can allow the DPAPI-protected Chrome key to be recovered.

---

## VeraCrypt

A VeraCrypt container can look like an ordinary file.

For example:

```text
Documents\
└── backup
```

Even though the file has no obvious extension, its contents can actually represent an encrypted filesystem.

Once the correct password and volume parameters are known, the container can be decrypted and its filesystem analyzed.

---

# 4. Step 1 — Examine the Triage Data

After extracting the challenge archive, the KAPE directory contains a Windows filesystem tree.

The useful locations include:

```text
C\Windows\System32\config\
```

containing:

```text
SAM
SYSTEM
SECURITY
SOFTWARE
```

The Chrome profile is located under:

```text
C\Users\vera\AppData\Local\Google\Chrome For Testing\User Data\
```

Relevant Chrome files include:

```text
Local State
Default\Login Data
```

The DPAPI files are located under:

```text
C\Users\vera\AppData\Roaming\Microsoft\Protect\
```

Finally, the suspicious file is:

```text
C\Users\vera\Documents\backup
```

It is approximately **100 MB**, has no extension, and contains high-entropy data.

That makes an encrypted container a strong possibility.

---

# 5. Step 2 — Recover Vera's Windows Password

The first objective is recovering Vera's Windows password.

Use Impacket's `secretsdump` against the offline registry hives:

```bash id="4j6k2p"
secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL
```

Among the output is an LSA secret:

```text id="7b4q1s"
[*] DefaultPassword
(Unknown User):minivera
```

This gives us:

```text id="8v5m3x"
Windows password = minivera
```

The password can also be verified against Vera's NT hash.

Windows NT hashes are calculated using the password encoded as UTF-16LE and hashed with MD4.

For this password:

```text id="9k2r7d"
MD4("minivera".encode("utf-16-le"))
=
1241186a4aac4f34f4bf7ace71b396a8
```

The resulting hash matches Vera's account hash from the SAM dump.

Therefore:

```text id="0m8c4v"
Vera's Windows password: minivera
```

No password cracking was necessary.

---

# 6. Step 3 — Recover the DPAPI Master Key

The DPAPI master key files are stored inside Vera's user profile.

The directory name gives us the user's SID:

```text id="x8n2q5"
S-1-5-21-2529683458-431225740-1723070931-1000
```

Using the recovered Windows password, the DPAPI master key can be decrypted.

Example:

```bash id="q5t9s2"
dpapi.py masterkey \
  -file <masterkey-guid> \
  -sid S-1-5-21-2529683458-431225740-1723070931-1000 \
  -password minivera
```

A successful result indicates:

```text id="3w6k8p"
Decrypted key with User Key (SHA1)
```

The decrypted master key is now available for decrypting DPAPI-protected data belonging to Vera's Windows account.

---

# 7. Step 4 — Recover the Chrome Password

Chrome stores its encryption information in:

```text id="7z3m1q"
Local State
```

The relevant field is:

```text id="0p6v9c"
os_crypt.encrypted_key
```

The encrypted key contains a DPAPI marker:

```text id="5n2d7x"
DPAPI
```

After removing the prefix and decrypting the remaining data with Vera's DPAPI master key, we obtain Chrome's AES encryption key.

The Chrome database is:

```text id="8r4k6m"
Default\Login Data
```

This is a SQLite database containing saved login information.

The encrypted password uses Chrome's `v10` format:

```text id="2h7s5w"
v10
+
12-byte IV
+
ciphertext
+
16-byte authentication tag
```

The recovered credentials are:

```text id="6c9p3a"
URL:      http://bytelotus.thm:8080/
Username: VeraSecretVault
Password: [REDACTED]
```

The username is another useful clue:

```text id="1x5m8n"
VeraSecretVault
```

This strongly suggests that the recovered password is intended to unlock the suspicious `backup` file.

---

# 8. Step 5 — Identify the VeraCrypt Container

The file:

```text id="4v8q2m"
C\Users\vera\Documents\backup
```

is approximately 100 MB and contains random-looking high-entropy data.

There is no normal document header or filesystem signature.

Combined with the challenge clue pointing toward VeraCrypt, the file can be treated as a VeraCrypt container.

The recovered Chrome password is used as the container password.

---

# 9. Step 6 — Decrypt the VeraCrypt Header

VeraCrypt uses a volume header containing information required to decrypt the filesystem.

For this challenge, the relevant process is:

```text id="9p4x6c"
Container
   │
   ▼
64-byte salt
   │
   ▼
PBKDF2-HMAC-SHA512
500,000 iterations
   │
   ▼
Header key
   │
   ▼
AES-XTS
   │
   ▼
Decrypted volume header
```

The decrypted header begins with:

```text id="3q7m2v"
VERA
```

This is a strong confirmation that the password and parameters are correct.

The volume's master keys are located within the decrypted header.

---

# 10. Important VeraCrypt Detail

The actual filesystem data begins at:

```text id="6w9k1r"
131072
```

bytes into the container.

The data is processed in 512-byte sectors.

A critical detail is the starting data-unit number.

Because:

```text id="5d8p3x"
131072 / 512 = 256
```

the first data unit must use:

```text id="7f2n6q"
256
```

rather than:

```text id="0c4m8z"
0
```

Using the wrong starting counter results in garbage even when the encryption keys are correct.

With the correct value of `256`, the first sector reveals:

```text id="2v6q9s"
MSDOS5.0
```

This identifies the filesystem as FAT.

---

# 11. Step 7 — Parse the FAT Filesystem

Once the encrypted volume has been decrypted, the FAT filesystem can be parsed.

The important files are:

```text id="8k3m7p"
/secret_financial_documents/important_invoice_byte_lotus.pdf
/secret_financial_documents/transactions_q3.csv
/$RECYCLE.BIN/DESKTOP.INI
/System Volume Information/WPSettings.dat
```

The invoice PDF is approximately:

```text id="4r9x2c"
26747 bytes
```

---

# 12. FAT Cluster Chain Trap

There is a small forensic trap here.

Reading only the first cluster of the PDF produces an incomplete file of around:

```text id="6m2q8v"
1024 bytes
```

The PDF is actually stored across multiple FAT clusters.

Therefore, the complete cluster chain must be followed to reconstruct the full:

```text id="1p7s4d"
26747-byte PDF
```

This is an important reminder that filesystem parsing is not simply about reading the first sector containing a file.

---

# 13. Step 8 — Extract the Invoice Image

The completed PDF contains no useful selectable text.

Instead, it contains an embedded image:

```text id="5x8c3n"
/XObject /Image
```

with:

```text id="2q6m9v"
FlateDecode
636 × 724
```

Extracting and opening the image reveals a fake **Byte Lotus Resorts** invoice.

The flag is displayed as an invoice line item.

The recovered value is:

```text id="9s4k7x"
THM{xxx}
```

---

# 14. Root Cause

The main operational-security failure was not a weakness in VeraCrypt itself.

The problem was the way the password was stored.

The security chain effectively became:

```text
VeraCrypt password
      │
      ▼
Chrome saved password
      │
      ▼
Chrome encryption key
      │
      ▼
Windows DPAPI
      │
      ▼
Weak Windows password
      │
      ▼
DefaultPassword LSA secret
```

Once the offline registry hives were available, the Windows password could be recovered.

That unlocked DPAPI, which unlocked Chrome, which revealed the VeraCrypt password.

---

# 15. Defensive Takeaways

### Don't store vault passwords in browsers

A password protecting a sensitive encrypted container should not be stored alongside ordinary browser credentials.

### Use a strong Windows password

DPAPI ultimately depends on protection tied to the Windows user account.

A weak password makes offline recovery significantly easier.

### Avoid Windows auto-login

The `DefaultPassword` LSA secret can expose the password needed to access the user's protected data.

### Use full-disk encryption

If the entire laptop had been protected by full-disk encryption, obtaining usable registry and browser artifacts from a powered-off system would be considerably harder.

### Treat forensic collections as highly sensitive

A KAPE collection containing:

```text
SAM
SYSTEM
SECURITY
DPAPI
Chrome profile
```

can contain enough material to reconstruct highly sensitive credentials.

---

# 16. Detection Opportunities

During forensic analysis, investigate:

* Large extensionless files with high entropy.
* Browser profiles containing saved credentials.
* Presence of Windows `DefaultPassword` secrets.
* DPAPI master key artifacts.
* Encrypted containers stored in user Documents folders.
* Browser credentials associated with sensitive services.
* Unusual files that appear to contain encrypted filesystems.

A particularly suspicious chain would be:

```text
Registry hives
      +
DPAPI artifacts
      +
Chrome Login Data
      +
Large encrypted container
```

Together, these artifacts can indicate a recoverable credential chain.

---

# 17. Command Cheat-Sheet

### Recover Windows account information

```bash id="8d4m2x"
secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL
```

Look for:

```text id="3q7v9m"
DefaultPassword
```

---

### Decrypt DPAPI master key

```bash id="1f6k8p"
dpapi.py masterkey \
  -file <masterkey-guid> \
  -sid <SID> \
  -password minivera
```

---

### Chrome credential recovery

Process:

```text id="7m2c5x"
Local State
     ↓
DPAPI encrypted Chrome key
     ↓
DPAPI master key
     ↓
Chrome AES key
     ↓
Login Data
     ↓
v10 AES-GCM blob
     ↓
saved password
```

---

### VeraCrypt analysis

Important parameters discovered in the challenge:

```text id="4p8n2v"
Salt:             first 64 bytes
KDF:              PBKDF2-HMAC-SHA512
Iterations:       500000
Cipher:           AES-XTS
Header:           bytes 64–512
Master keys:      header offset 256
Data offset:      131072
Sector size:      512 bytes
Data-unit start:  256
Filesystem:       FAT
```

---

# 18. Lessons Learned

### Lesson 1 — Look for where secrets were already stored

A strong encryption algorithm does not help if the password is saved somewhere recoverable.

The important discovery was not cracking VeraCrypt.

It was finding the password Chrome had already remembered.

### Lesson 2 — Follow the authentication chain

The challenge demonstrates a classic dependency chain:

```text
Windows password
      ↓
DPAPI
      ↓
Chrome
      ↓
VeraCrypt password
      ↓
Encrypted container
      ↓
Invoice
      ↓
Flag
```

Breaking one weak link can expose everything downstream.

### Lesson 3 — File formats matter

Two small technical details were critical:

```text
VeraCrypt data-unit counter = 256
```

and:

```text
FAT file = complete cluster chain
```

Using the wrong counter or reading only one cluster produces corrupted output even when the correct password and encryption keys have been obtained.

---

# Final Result

The complete investigation was:

```text
KAPE triage
    ↓
Registry hives
    ↓
DefaultPassword
    ↓
Windows password
    ↓
DPAPI master key
    ↓
Chrome encryption key
    ↓
Saved vault password
    ↓
VeraCrypt container
    ↓
FAT filesystem
    ↓
Invoice PDF
    ↓
Embedded invoice image
    ↓
THM{xxx}
```

**Final Flag:**

```text
THM{xxx}
```

> **Key takeaway:** When strong encryption appears impossible to break, investigate the surrounding ecosystem. The weakness may not be the cryptography—it may be the fact that a user, browser, or operating system has already stored the secret somewhere accessible.

*Target, users, credentials, and challenge artifacts are fictional TryHackMe material. Analysis was performed offline against the provided forensic collection.*
