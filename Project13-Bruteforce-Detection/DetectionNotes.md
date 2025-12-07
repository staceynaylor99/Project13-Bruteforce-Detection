Project 13 – Windows Brute-Force Login Detection
1. Overview

This project simulates a brute-force login attack on a Windows system and uses Windows Security Logs plus PowerShell to detect repeated failed logon attempts. This reflects a common SOC workflow for identifying suspicious authentication behavior.

2. Attack Simulation

I intentionally entered incorrect passwords multiple times on the Windows login screen. This produced:

Many 4625 (failed logon) events

A final 4624 (successful logon) event

These patterns mimic brute-force or password-spray activity.

3. Evidence Collected
Project13-4625-Cluster.png

Shows a tight cluster of failed 4625 events triggered during the simulation.

Project13-4625-Details.png

Shows the detailed properties for a 4625 event, including:

Failure reason

Logon type

Account name

Source network address (IPv4 or IPv6 localhost inside VM)

Timestamp

Project13-Bruteforce-Alert.png

Shows the PowerShell detection script raising an alert after identifying repeated failed logons.

4. Detection Logic (PowerShell)

This script searches Security logs for Event ID 4625 and raises an alert when repeated failures happen:

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


For testing, I also used a wider 1-hour window to ensure detection triggers during screenshots.

5. Why This Matters

Brute-force activity is one of the most common early-stage attacks during intrusion attempts. Being able to:

Read Windows authentication logs

Identify abnormal login patterns

Build detection logic

Convert raw logs into an alert

is a core SOC skill used every day in enterprise environments.

This project shows practical detection engineering and log analysis experience.