# After Hours — WMI Fileless Persistence

**Platform:** TryHackMe
**Event:** Hacker Holidays — Day 12
**Category:** Forensics / DFIR
**Focus:** WMI Event Subscription · PowerShell Obfuscation · Fileless Execution · .NET Analysis

**Flag:** `THM{XXXX}`

---

## 1. Investigation Summary

The challenge provides several files with no obvious extension:

```text
OBJECTS.DATA
INDEX.BTR
MAPPING1.MAP
MAPPING2.MAP
MAPPING3.MAP
```

Rather than being unrelated binary files, these are components of a Windows **CIM/WMI repository**.

The investigation reveals a persistent WMI event subscription. A scheduled WMI event launches an encoded PowerShell command, which retrieves another payload from a custom WMI class.

The PowerShell loader then:

```text
WMI Event Subscription
        ↓
Encoded PowerShell
        ↓
Read payload from WMI
        ↓
Base64 decode
        ↓
Raw DEFLATE decompression
        ↓
.NET assembly in memory
        ↓
Environment check
        ↓
Create local "patch" account
        ↓
Decode password
        ↓
Flag
```

The important DFIR aspect is that the executable payload never needs to exist as a normal file on disk.

---

# 2. Understanding the Evidence

After extracting the supplied archive:

```bash
mkdir day12
cd day12
unzip -o ../attachments-1784136288483.zip
ls -la
```

The files look like:

```text
INDEX.BTR
MAPPING1.MAP
MAPPING2.MAP
MAPPING3.MAP
OBJECTS.DATA
```

This combination is a strong indicator of a Windows WMI/CIM repository.

The most important file is:

```text
OBJECTS.DATA
```

It contains the actual object and instance information.

The other files primarily provide indexing and repository-management information.

For this investigation, the objective is not to boot the repository or execute anything from it.

Instead, the repository is treated as a static forensic artifact.

---

# 3. Searching for WMI Eventing Objects

The WMI event persistence mechanism uses three important object types:

```text
__EventFilter
CommandLineEventConsumer
__FilterToConsumerBinding
```

A quick search can determine whether these structures exist:

```python
import re

data = open("OBJECTS.DATA", "rb").read()
text = data.decode("latin1")

keywords = [
    "CommandLineEventConsumer",
    "ActiveScriptEventConsumer",
    "__EventFilter",
    "FilterToConsumerBinding",
    "CommandLineTemplate"
]

for keyword in keywords:
    print(keyword, len(re.findall(re.escape(keyword), text, re.I)))
```

The presence of these names confirms that the repository contains WMI eventing information.

However, the raw counts are not enough.

Windows installations contain built-in WMI class definitions, so many matches are legitimate system data.

The useful information is contained in the actual instance values.

---

# 4. Finding the Event Filter

Searching the repository for WQL statements reveals an interesting filter:

```text
__EventFilter
Name: EngineTelemetryFilter
Namespace: root\cimv2
```

Its query is equivalent to:

```text
SELECT * FROM __InstanceModificationEvent
WITHIN 60
WHERE TargetInstance ISA 'Win32_LocalTime'
AND TargetInstance.Minute = 30
```

This tells us what triggers the persistence.

### Breaking down the query

`__InstanceModificationEvent` is an intrinsic WMI event generated when WMI instances change.

The filter watches:

```text
Win32_LocalTime
```

which changes as the system clock advances.

The important condition is:

```text
TargetInstance.Minute = 30
```

Therefore, the malicious action is designed to trigger around:

```text
HH:30
```

every hour.

The name:

```text
EngineTelemetryFilter
```

also appears deliberately harmless, resembling a legitimate monitoring component.

---

# 5. Identifying the Event Consumer

The next component is the event consumer.

The repository contains a `CommandLineEventConsumer` instance with a command resembling:

```text
cmd /C powershell.exe -Sta -Nop -Window Hidden -enc <BASE64>
```

Several options immediately stand out:

```text
-Sta
-Nop
-Window Hidden
-enc
```

The most important is:

```text
-enc
```

which means `-EncodedCommand`.

PowerShell expects the encoded command to represent UTF-16LE text.

The third component is the binding:

```text
__FilterToConsumerBinding
```

This connects the filter to the consumer.

The relationship is therefore:

```text
EngineTelemetryFilter
        │
        ▼
FilterToConsumerBinding
        │
        ▼
CommandLineEventConsumer
        │
        ▼
PowerShell loader
```

Without the binding, the two objects would not form the complete persistence chain.

---

# 6. Decoding the PowerShell Command

The encoded command can be extracted from the repository and decoded.

For example:

```python
import base64

encoded = b"<BASE64_COMMAND>"

decoded = base64.b64decode(encoded)
print(decoded.decode("utf-16le"))
```

The resulting PowerShell script is the real clue.

It does not contain a large executable payload.

Instead, it accesses another WMI class:

```powershell
ROOT\cimv2:Win32_HardwareTelemetry
```

and retrieves:

```text
ConfigData
```

Conceptually:

```powershell
$file =
    ([WmiClass]'ROOT\cimv2:Win32_HardwareTelemetry').
    Properties['ConfigData'].Value
```

This means the repository contains another hidden layer.

The event consumer is only the loader.

The actual executable is stored inside WMI.

---

# 7. Understanding the Fileless Loader

The PowerShell script performs three major transformations.

### Stage 1 — Base64 decoding

The `ConfigData` value is decoded from Base64.

### Stage 2 — DEFLATE decompression

The resulting bytes are passed through:

```text
DeflateStream
```

in decompression mode.

### Stage 3 — In-memory assembly loading

The decompressed bytes are passed to:

```powershell
[Reflection.Assembly]::Load(...)
```

and the assembly entry point is invoked.

So the payload path is:

```text
WMI ConfigData
      ↓
Base64
      ↓
Compressed bytes
      ↓
Raw DEFLATE
      ↓
.NET PE
      ↓
Reflection.Assembly::Load()
```

No traditional executable needs to be written to disk.

---

# 8. Recovering ConfigData

The next forensic task is to locate the large Base64 value associated with:

```text
Win32_HardwareTelemetry
```

The blob can then be extracted from `OBJECTS.DATA`.

Once the Base64 value is obtained, decode it:

```python
import base64

encoded = b"<CONFIGDATA>"
compressed = base64.b64decode(encoded)
```

At this point, the result is not yet a normal executable.

It is compressed data.

---

# 9. The Raw DEFLATE Detail

This is an important part of the analysis.

The PowerShell loader uses `.NET DeflateStream`.

The data is **raw DEFLATE**, rather than a complete gzip or zlib stream.

Therefore, Python's default decompression mode is not appropriate.

Use:

```python
import zlib

payload = zlib.decompress(compressed, -15)
```

The `-15` parameter tells zlib to expect a headerless/raw DEFLATE stream.

The resulting data begins with:

```text
MZ
```

which indicates a Windows PE file.

Save it for static analysis:

```python
open("payload.exe", "wb").write(payload)
```

Then:

```bash
file payload.exe
```

The result identifies it as a small managed .NET executable.

---

# 10. Examining the .NET Payload

The recovered binary is very small, so its metadata provides useful information even without executing it.

Interesting identifiers include:

```text
updates.exe
Program
AfterHours
Main
Environment
get_MachineName
ProcessStartInfo
Process
Start
Console
WriteLine
```

The embedded string data also contains:

```text
bytelotusdc
cmd.exe
Execution halted: Environment mismatch.
```

and a command resembling:

```text
/c net user patch <BASE64> /add
```

These strings allow the program's behavior to be reconstructed statically.

---

# 11. Environment Check

The payload does not immediately execute its main action.

It first checks the machine name.

Conceptually:

```csharp
if (Environment.MachineName.Equals(
        "bytelotusdc",
        StringComparison.OrdinalIgnoreCase))
{
    // continue
}
else
{
    Console.WriteLine(
        "Execution halted: Environment mismatch."
    );
}
```

This is an execution guard.

The malware is intended to operate only on a particular host:

```text
bytelotusdc
```

On another machine, it exits without performing the main action.

From a forensic perspective, this is useful because the sample can be safely understood without needing to execute it.

---

# 12. What the Payload Attempts to Do

When the hostname matches, the program launches:

```text
cmd.exe
```

with arguments equivalent to:

```text
net user patch <BASE64_PASSWORD> /add
```

This creates a local Windows account named:

```text
patch
```

The name is intentionally ordinary-looking and could easily be mistaken for a legitimate maintenance account.

The password is encoded using Base64.

---

# 13. Recovering the Flag

The password value can be decoded without executing the payload:

```bash
python -c "import base64; print(base64.b64decode('<BASE64>').decode())"
```

The decoded value is:

```text
THM{XXXX}
```

Therefore:

**Flag:** `THM{XXXX}`

The important point is that the flag is recovered through static analysis rather than by actually running the embedded executable.

---

# 14. Complete Evidence Chain

The investigation can be summarized as:

```text
OBJECTS.DATA
      │
      ▼
__EventFilter
"EngineTelemetryFilter"
      │
      │ WQL
      ▼
Win32_LocalTime.Minute = 30
      │
      ▼
__FilterToConsumerBinding
      │
      ▼
CommandLineEventConsumer
      │
      ▼
powershell.exe -enc ...
      │
      ▼
Decode UTF-16LE
      │
      ▼
Win32_HardwareTelemetry.ConfigData
      │
      ▼
Base64 decode
      │
      ▼
Raw DEFLATE
      │
      ▼
.NET PE
      │
      ▼
AfterHours.Program
      │
      ▼
Machine name check
      │
      ▼
net user patch ...
      │
      ▼
Decode password
      │
      ▼
THM{XXXX}
```

---

# 15. Why This Technique Is Effective

WMI provides attackers with several useful capabilities.

A malicious actor can create:

```text
__EventFilter
```

to define when something should happen.

A:

```text
CommandLineEventConsumer
```

can define what command should run.

And:

```text
__FilterToConsumerBinding
```

connects the two.

Together they provide a persistent event-triggered execution mechanism.

The payload can also be hidden inside WMI data itself.

This creates two layers of concealment:

```text
Persistence
    → WMI event subscription

Payload
    → WMI class property
```

The executable therefore does not have to appear as an obvious file in locations such as:

```text
Startup
Run keys
Scheduled Tasks
```

---

# 16. Forensic Indicators

Several artifacts from this investigation would be valuable to defenders.

### Suspicious WMI subscriptions

Look for:

```text
__EventFilter
CommandLineEventConsumer
ActiveScriptEventConsumer
__FilterToConsumerBinding
```

Especially when they reference:

```text
powershell.exe
cmd.exe
-enc
```

---

### Encoded PowerShell

A command containing:

```text
powershell.exe -enc
```

should receive additional scrutiny, particularly when launched through WMI.

---

### Suspicious WMI classes

A custom class with a large Base64 property is unusual.

For example:

```text
Win32_HardwareTelemetry
    └── ConfigData
```

A large encoded blob inside such a property can indicate hidden payload storage.

---

### Unexpected account creation

The payload ultimately attempts:

```text
net user patch ... /add
```

Windows Security Event ID `4720` can identify user-account creation.

---

# 17. Defensive Recommendations

## Monitor WMI persistence

Regularly enumerate persistent event filters and consumers.

For example:

```powershell
Get-WmiObject -Namespace root\subscription -Class __EventFilter
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer
Get-WmiObject -Namespace root\subscription -Class ActiveScriptEventConsumer
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
```

Unexpected entries should be investigated.

---

## Monitor PowerShell launched through WMI

A chain such as:

```text
WmiPrvSE.exe
      ↓
powershell.exe -enc
```

is particularly suspicious.

---

## Enable PowerShell logging

Script Block Logging can provide visibility into decoded PowerShell activity.

This is especially useful when attackers use `-EncodedCommand`.

---

## Restrict arbitrary .NET loading

Application control mechanisms such as WDAC or AppLocker, combined with appropriate PowerShell restrictions, can make arbitrary in-memory assembly loading significantly harder.

---

## Monitor new local accounts

Creation of unexpected accounts should generate an alert, especially when initiated by unusual parent processes.

---

# 18. Useful DFIR Workflow

A safe investigation workflow is:

```text
1. Identify the artifact
        ↓
2. Determine its format
        ↓
3. Locate persistence mechanisms
        ↓
4. Recover encoded commands
        ↓
5. Reproduce transformations offline
        ↓
6. Extract the embedded payload
        ↓
7. Analyze the payload statically
        ↓
8. Recover indicators/credentials/flags
```

The important principle is to avoid executing unknown code merely to understand what it does.

---

# 19. Command Reference

### Extract the evidence

```bash
unzip attachments.zip
ls
```

### Search for WMI structures

```python
import re

data = open("OBJECTS.DATA", "rb").read()

for item in [
    "__EventFilter",
    "CommandLineEventConsumer",
    "__FilterToConsumerBinding"
]:
    print(item, data.count(item.encode()))
```

### Decode PowerShell

```python
import base64

decoded = base64.b64decode(encoded)
print(decoded.decode("utf-16le"))
```

### Decompress the hidden payload

```python
import base64
import zlib

compressed = base64.b64decode(blob)
payload = zlib.decompress(compressed, -15)

open("payload.exe", "wb").write(payload)
```

### Identify the recovered PE

```bash
file payload.exe
```

### Decode the final Base64 value

```bash
python -c "import base64; print(base64.b64decode('<BASE64>').decode())"
```

---

# 20. Key Lessons

### WMI can hide persistence

WMI is a legitimate Windows management technology, but its event subscription system can also be abused for persistence.

---

### Fileless does not mean payload-free

If a loader appears to contain no obvious executable, look for where it retrieves its data.

In this case:

```text
PowerShell
   ↓
WMI class
   ↓
ConfigData
   ↓
compressed assembly
```

The payload was stored inside the repository itself.

---

### Always reproduce the exact encoding chain

The payload required several transformations:

```text
Base64
   ↓
raw DEFLATE
   ↓
.NET PE
```

Using normal zlib or gzip decompression would fail.

The same principle applies to forensic investigations generally: reproduce the exact transformation performed by the loader rather than guessing the format.

---

# Final Takeaway

This challenge demonstrates a useful DFIR mindset:

**Don't execute the malware to understand it when the evidence already contains the answer.**

The WMI repository exposed the persistence mechanism, the encoded PowerShell exposed the payload location, the WMI property contained the compressed executable, and the .NET metadata revealed the final action.

The complete investigation was therefore performed offline:

```text
Raw WMI Repository
       ↓
Persistence Discovery
       ↓
PowerShell Decoding
       ↓
Payload Carving
       ↓
Raw DEFLATE Inflation
       ↓
.NET Static Analysis
       ↓
Base64 Decoding
       ↓
THM{XXXX}
```

**Flag:** `THM{XXXX}`

*The artifact was analyzed offline in the intended TryHackMe challenge environment. No recovered payload was executed during the analysis.*
