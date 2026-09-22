# 🧠 MemLabs Lab 5 – Memory Forensics

A complete memory forensics investigation of **MemLabs Lab 5**, involving process analysis, file extraction, command-history recovery, Base64 decoding, and reverse engineering of a reconstructed executable.

## 📌 Overview

This project analyzes the memory dump:

```text
MemoryDump_Lab5.raw
```

The investigation was performed in multiple stages using **Volatility 3, Volatility 2.6, WinRAR, Base64 decoding, and IDA Pro**.

The objective was to identify hidden artifacts inside the memory image and recover all three flags from the challenge.

---

## 🎯 Objectives

The main objectives of this investigation were:

* Analyze the Windows memory dump.
* Identify running and suspicious processes.
* Examine process hierarchy and command-line arguments.
* Locate files present in memory.
* Extract hidden files from the memory image.
* Recover command history.
* Decode Base64-encoded data.
* Extract and analyze a reconstructed PE executable.
* Perform static reverse engineering.
* Recover all three challenge flags.

---

## 🛠️ Tools Used

| Tool               | Purpose                                                |
| ------------------ | ------------------------------------------------------ |
| **Volatility 3**   | Initial memory analysis and process/file investigation |
| **Volatility 2.6** | Legacy plugins and additional artifact recovery        |
| **WinRAR**         | Extract the recovered RAR archive                      |
| **Base64 Decoder** | Decode encoded flag data                               |
| **IDA Pro**        | Static reverse engineering of the recovered executable |

---

# 🔎 Investigation Workflow

## Stage 1 – Volatility 3

Volatility 3 was used for the initial memory triage.

### 1. List Running Processes

```powershell
vol.exe -f MemLabs-Lab5\MemoryDump_Lab5.raw windows.pslist
```

Used to identify processes running when the memory image was captured.

### 2. View Process Tree

```powershell
vol.exe -f MemLabs-Lab5\MemoryDump_Lab5.raw windows.pstree
```

Used to examine parent-child process relationships and identify unusual processes.

### 3. Check Command-Line Arguments

```powershell
vol.exe -f MemLabs-Lab5\MemoryDump_Lab5.raw windows.cmdline
```

Used to recover command-line arguments that could contain clues, paths, or encoded information.

### 4. Search for Notepad

```powershell
vol.exe -f MemLabs-Lab5\MemoryDump_Lab5.raw windows.filescan | findstr /i "NOTEPAD.EXE"
```

This helped locate the `NOTEPAD.EXE` file object in memory.

### 5. Dump a File from Memory

```powershell
mkdir output

vol.exe -f MemLabs-Lab5\MemoryDump_Lab5.raw -o output windows.dumpfiles --virtaddr 0x3fca5250
```

The file object identified during `filescan` was extracted for further analysis.

### 6. Search for the Important File

```powershell
vol.exe -f MemLabs-Lab5\MemoryDump_Lab5.raw -o output windows.dumpfiles --filter "SW1wb3J0YW50"
```

`SW1wb3J0YW50` is the Base64 representation of:

```text
Important
```

This resulted in the recovery of an `Important.rar` archive.

### 7. Analyze Process Memory

```powershell
vol.exe -f MemLabs-Lab5\MemoryDump_Lab5.raw windows.vadinfo --pid 2724
```

```powershell
vol.exe -f MemLabs-Lab5\MemoryDump_Lab5.raw windows.dlllist --pid 2724
```

These commands were used to inspect memory regions and loaded DLLs of PID `2724`.

### 8. Check Network Activity

```powershell
vol.exe -f MemLabs-Lab5\MemoryDump_Lab5.raw windows.netscan
```

Used to investigate network-related artifacts in the memory image.

### 9. Search Raw Memory

```powershell
findstr /i "Zmxh" MemLabs-Lab5\MemoryDump_Lab5.raw
```

`Zmxh` is the Base64 prefix for `fla`, so it was searched for as a possible indicator of an encoded flag.

---

# 🔬 Stage 2 – Volatility 2.6

Volatility 3 did not provide all the legacy plugins required to complete the investigation. Therefore, Volatility 2.6 was used.

## 10. Identify the Memory Profile

```powershell
volatility_2.6_win64_standalone.exe -f MemoryDump_Lab5.raw imageinfo
```

The identified profile was:

```text
Win7SP1x64
```

## 11. Recheck Processes

```powershell
volatility_2.6_win64_standalone.exe -f MemoryDump_Lab5.raw --profile=Win7SP1x64 pslist
```

## 12. Recover Internet Explorer History

```powershell
volatility_2.6_win64_standalone.exe -f MemoryDump_Lab5.raw --profile=Win7SP1x64 iehistory
```

## 13. Search AppPatch Files

```powershell
volatility_2.6_win64_standalone.exe -f MemoryDump_Lab5.raw --profile=Win7SP1x64 filescan | findstr /i "AppPatch"
```

## 14. Read Extracted File

```powershell
type output\file.None.0xfffffa800209bc40.dat
```

## 15. Dump Process Memory

```powershell
volatility_2.6_win64_standalone.exe -f MemoryDump_Lab5.raw --profile=Win7SP1x64 memdump -p 1396 -D output
```

---

# 🚩 Stage 1 Flag

A Base64-encoded string was recovered:

```text
ZmxhZ3shIV93M0xMX2QwbjNfU3Q0ZzMtMV8wZl9MNEJfNV9EMG4zXyEhfQ
```

After decoding:

```text
flag{!!_w3LL_d0n3_St4g3-1_0f_L4B_5_D0n3_!!}
```

---

# 📦 Stage 2 – Recovering the RAR Archive

The recovered archive was extracted using WinRAR:

```powershell
"C:\Program Files\WinRAR\WinRAR.exe" x output\Important.rar
```

The next step was recovering the password from Windows console history.

### Recover Console History

```powershell
volatility_2.6_win64_standalone.exe -f MemoryDump_Lab5.raw --profile=Win7SP1x64 consoles
```

The command history was cross-checked using:

```powershell
volatility_2.6_win64_standalone.exe -f MemoryDump_Lab5.raw --profile=Win7SP1x64 cmdscan
```

The recovered password was used to open the RAR archive, which contained:

```text
Stage2.png
```

The image contained the Stage 2 flag.

### 🚩 Stage 2 Flag

```text
flag{W1th_th1s_$taGe_2_1s_cOmPL3T3_!!}
```

---

# 💻 Stage 3 – Reverse Engineering

The final stage involved recovering the in-memory image section of `NOTEPAD.EXE`.

## 16. Dump the Notepad Image Section

```powershell
volatility_2.6_win64_standalone.exe -f MemoryDump_Lab5.raw --profile=Win7SP1x64 dumpfiles -Q 0x3fca5250 -D notepad-dump
```

The extracted `.img` file represented the in-memory `ImageSectionObject` of `NOTEPAD.EXE`.

## 17. Reconstruct the Executable

```powershell
copy notepad-dump\file.None.0xfffffa80021a1600.img NOTEPAD_STAGE3.exe
```

The reconstructed executable was then analyzed using **IDA Pro**.

## 18. Static Analysis

Inside `WinMainCRTStartup`, a sequence of byte values and `push` instructions was identified.

This represented a **stack-string obfuscation technique**, where characters of the final flag were stored as immediate byte values instead of appearing directly as a normal string.

Reading the characters in t
