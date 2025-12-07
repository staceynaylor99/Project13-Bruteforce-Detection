# Project 13 – Windows Brute-Force Login Detection

This lab simulates a brute-force style login attack on a Windows virtual machine and detects it using Windows Security Event Logs (4625/4624) and a custom PowerShell script. It shows how a SOC analyst can move from raw logs to a simple detection and alert.

---

## Overview

**Goal:** Detect repeated failed logon attempts that look like a brute-force or password-guessing attack.

**Key ideas:**

- Windows writes failed logons as **Event ID 4625**
- Successful logons use **Event ID 4624**
- A cluster of 4625s in a short time window is a classic brute-force pattern
- PowerShell can query these events and raise an alert

---

## Attack Simulation

To generate realistic logs, I:

1. Locked the Windows VM.
2. Entered the **wrong password** many times in a row.
3. Finally logged in with the **correct password**.

This produced:

- Multiple `4625` failed logon events
- A final `4624` successful logon

This is the same pattern an attacker or script would generate while guessing passwords.

---

## Evidence Collected (Screenshots)

All screenshots are in the [`screenshots`](./screenshots) folder.

- **`Project13-4625-Cluster.png`**  
  Cluster of Event ID 4625 entries in the Security log, showing repeated failed logons.

- **`Project13-4625-Details.png`**  
  Detailed properties for a single 4625 event, including:
  - Failure reason (bad username or password)
  - Account name
  - Logon type
  - Source address (localhost inside the VM)
  - Timestamp

- **`Project13-Bruteforce-Alert.png`**  
  PowerShell window showing the detection script counting failed logons and printing an alert.

For a narrative-style walkthrough, see [`DetectionNotes.md`](./DetectionNotes.md).

---

## Detection Logic (PowerShell)

The main detection script is [`BruteForceDetect.ps1`](./BruteForceDetect.ps1).

It looks for failed logons (`4625`) in the last **5 minutes** and raises an alert if there are many:

```powershell
# Brute-force login detection script
# Checks for repeated Event ID 4625 failures in last 5 minutes

$Events = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id      = 4625
} | Where-Object {
    $_.TimeCreated -gt (Get-Date).AddMinutes(-5)
}

if ($Events.Count -ge 6) {
    Write-Host "ALERT: Possible brute-force attack detected! ($($Events.Count) failures in the last 5 minutes)"
} else {
    Write-Host "Failed logons in last 5 minutes: $($Events.Count)"
    Write-Host "No brute-force behavior detected."
}
