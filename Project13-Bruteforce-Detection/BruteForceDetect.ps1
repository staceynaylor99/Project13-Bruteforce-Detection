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
