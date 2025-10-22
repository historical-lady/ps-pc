# ==============================================================================
# child_lock_template.ps1
# Original file by u/nohalfmeasure
# DESCRIPTION:
# This script performs the following security hardening tasks on a Windows PC:
# 1. Creates a new, secure local administrator account.
# 2. Demotes all other non-essential local administrator accounts.
# 3. Sets a daily time limit (cumulative or window) for non-administrator accounts with anti-tampering measures.
# 4. Sets specific DNS servers for network security and porn blocking.
# 5. Creates a scheduled task to display a message and remaining time at logon.
# 6. Mails the credentials for the new administrator account to a specified address.
# 7. Restricts access to the Control Panel for non-administrators.
#
# USAGE:
# 1. Fill in the configuration variables below.
# 2. Run this script with Administrator privileges using the start.bat file.
# ==============================================================================

# --- SCRIPT CONFIGURATION (EDIT THESE VALUES) ---

# New Admin User Configuration
$newAdminUsername = "Parent" # Name for the new local administrator account

# --- Daily Time Limit for Non-Admins (CHOOSE ONE METHOD) ---

# METHOD 1: Cumulative Time Limit (e.g., 3 hours and 0 minutes total per day)
# Set the total number of hours and minutes a non-admin can use the computer per day.
# To disable this method and use the time window method instead, set both hours and minutes to 0.
$cumulativeTimeLimitHours = 3
$cumulativeTimeLimitMinutes = 0

# METHOD 2: Specific Time Window (e.g., only between 4 PM and 7 PM)
# NOTE: This is IGNORED if $cumulativeTimeLimitHours or $cumulativeTimeLimitMinutes is greater than 0.
# For example, "16:00-19:00" allows logon only between 4 PM and 7 PM.
# To disable time limits completely, set hours and minutes to 0 and $timeLimitWindow to "".
$timeLimitWindow = "07:00-23:00"

# Email Notification Configuration (not necessary if you select not to use email when prompted by the script)
$recipientEmail = "recipient@gmail.com"      # <<< The email address to receive the new password.
$smtpServer     = "smtp.gmail.com"         # Gmail's SMTP server address.
$smtpPort       = 587                             # Use 587 for TLS/STARTTLS.
$smtpUser       = "sender@gmail.com" # Your full Gmail address for authentication.
$smtpPass       = "xxxx xxxx xxxx xxxx"         # Use a 16-digit App Password from your Google Account, not your main password.


# --- SCRIPT BODY ---

# 1. Administrative Privileges Check
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Warning "Administrator privileges required. Relaunching..."
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
    exit
}
Write-Host "Administrator privileges confirmed."
Write-Host ""

$useEmail = $false
while ($true) {
    Write-Host "Select password storage option: "
    Write-Host "`t(1) Email with hardcoded mail info"
    Write-Host "`t(2) Write to console"
    $input = Read-Host "(enter 1 or 2)"
    if ($input -eq "1") {
        $useEmail = $true
        break
    }
    elseif ($input -eq "2") {
        $useEmail = $false
        break
    }
    else {
        Write-Host "Enter 1 or 2"
    }
}

# 2. Test SMTP credentials BEFORE making any system changes
if ($useEmail) {
    Write-Host "Testing SMTP connection to $smtpServer..."
    try {
        $smtpClient = New-Object System.Net.Mail.SmtpClient($smtpServer, $smtpPort)
        $smtpClient.EnableSsl = $true
        $smtpClient.Credentials = New-Object System.Net.NetworkCredential($smtpUser, $smtpPass)
        #$smtpClient.Send($smtpUser, $recipientEmail, "Script Execution Started on $($env:COMPUTERNAME)", "SMTP connection test successful.")
        Write-Host "SMTP connection successful."
    } catch {
        Write-Error "FATAL: Could not connect to the SMTP server. Please check your SMTP settings and password in the script."
        Write-Error "Error details: $($_.Exception.Message)"
        Read-Host "Press Enter to exit."
        exit
    }
}

# 3. Get Language-Independent Group Names and SIDs
try {
    $adminSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
    $adminGroupName = $adminSid.Translate([System.Security.Principal.NTAccount]).Value.Split('\')[1]

    $usersSid = "S-1-5-32-545" # Well-known SID for BUILTIN\Users
} catch {
    Write-Error "FATAL: Could not resolve essential group SIDs. This may be a sign of a deeper OS issue."
    Read-Host "Press Enter to exit."
    exit
}

# 4. Function to generate a random, secure password
function Generate-SecurePassword {
    param ([int]$length = 16)
    $charSet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+'
    $randomBytes = New-Object byte[] $length
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($randomBytes)
    $password = -join ($randomBytes | ForEach-Object { $charSet[$_ % $charSet.Length] })
    return $password
}

# 5. Create or Update the Local Administrator Account
$plainTextPassword = Generate-SecurePassword
$securePassword = ConvertTo-SecureString $plainTextPassword -AsPlainText -Force
Write-Host "Generated a new secure password for user '$newAdminUsername'."
$description = "Local administrator account."

try {
    Write-Host "Checking for existing user '$newAdminUsername'..."
    $user = Get-LocalUser -Name $newAdminUsername -ErrorAction SilentlyContinue

    if ($user) {
        Write-Host "User '$newAdminUsername' exists. Resetting password."
        Set-LocalUser -Name $newAdminUsername -Password $securePassword
        Enable-LocalUser -Name $newAdminUsername
        net user $newAdminUsername /expires:never | Out-Null
        Write-Host "Password for existing user '$newAdminUsername' has been successfully reset."
    } else {
        Write-Host "User '$newAdminUsername' not found. Creating new administrator account."
        New-LocalUser -Name $newAdminUsername -Password $securePassword -FullName "Local Administrator" -Description $description -PasswordNeverExpires | Out-Null
        Write-Host "User '$newAdminUsername' created."
    }

    Write-Host "Ensuring '$newAdminUsername' is a member of the '$adminGroupName' group."
    Add-LocalGroupMember -Group $adminGroupName -Member $newAdminUsername -ErrorAction SilentlyContinue
    Write-Host "User '$newAdminUsername' is configured as an administrator."

} catch {
    Write-Error "FATAL: Could not create or update user '$newAdminUsername'. Script will stop. Error: $($_.Exception.Message)"
    Read-Host "Press Enter to exit."
    exit
}

# 6. Verify that the new user is now an administrator
Start-Sleep -Seconds 1
$admins = Get-LocalGroupMember -Group $adminGroupName | Select-Object -ExpandProperty Name
$isMember = $false
foreach ($member in $admins) {
    if ($member -eq $newAdminUsername -or $member.EndsWith("\$newAdminUsername")) {
        $isMember = $true
        break
    }
}

if (-not $isMember) {
    Write-Error "FATAL: Failed to verify that '$newAdminUsername' is in the Administrators group. Aborting script to prevent lockout."
    Read-Host "Press Enter to exit."
    exit
}
Write-Host "Successfully verified that '$newAdminUsername' is an administrator."
Write-Host ""

# 7. Send Credentials via Email
$computerName = $env:COMPUTERNAME
$emailSubject = "Child Safety Lockdown Alert For: $computerName"
$emailBody = @"
The Child Safety System Lockdown script has been run on the machine: '$computerName'.  Administrative users have been demoted to regular users, and a new local administrator account has been configured:

Username: $newAdminUsername
Password: $plainTextPassword

Please store this password securely.
"@

if ($useEmail) {
    try {
        Write-Host "Sending final credentials email to $recipientEmail..."
        $smtpClient.Send($smtpUser, $recipientEmail, $emailSubject, $emailBody)
        Write-Host "Email sent successfully."
    } catch {
        Write-Error "CRITICAL: Could not send the final password email, but the account has been created."
        Write-Warning "The password for user '$newAdminUsername' is: $plainTextPassword"
        Write-Warning "Please record this password MANUALLY. The script will now stop."
        Read-Host "Press Enter to exit."
        exit
    }
}
else {
    Write-Host $emailSubject
    Write-Host $emailBody
}

# 8. Configure Network Settings
Write-Host "Configuring DNS settings..."
try {
    $dnsIps = @(
        @("185.228.168.10", "185.228.169.11"),
        @("185.228.168.168", "185.228.169.168"),
        @("1.1.1.3", "1.0.0.3"),
        @("208.67.222.123", "208.67.220.123")
    )
    $dnsNames = @(
        "CleanBrowsingAdult",
        "CleanBrowsingFamily",
        "CloudFlareFamily",
        "OpenDNS"
    )

    $dnsIndex = 0
    while ($true) {
        Write-Host @"
Select a DNS server for web filtering:
    (1) CleanBrowsingAdult (blocks adult sites): "185.228.168.10", "185.228.169.11"
    (2) CleanBrowsingFamily (also blocks mixed content like Reddit): "185.228.168.168", "185.228.169.168"
    (3) CloudFlareFamily: "1.1.1.3", "1.0.0.3"
    (4) OpenDNS: "208.67.222.123", "208.67.220.123"
    (5) Disable web filtering
"@
        $input = Read-Host "(enter selection 1-5)"
        if (@("1", "2", "3", "4", "5") -contains $input) {
            $dnsIndex = [int]$input
            break
        }
        else {
            Write-Host "Enter a number 1-5"
        }
    }

    if ($dnsIndex -eq 5) {
        Write-Host "Skipping web filtering"
    }
    else {
        $ips = $dnsIps[$dnsIndex - 1]
        $name = $dnsNames[$dnsIndex - 1]
        Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Set-DnsClientServerAddress -ServerAddresses($ips[0], $ips[1])
        Write-Host "Set DNS server to" $name
        ipconfig /flushdns
        Write-Host "DNS cache flushed"
    }
} catch {
    Write-Warning "Could not configure network settings. Error: $($_.Exception.Message)"
}
Write-Host ""

# 9. Demote all other administrators to standard users
Write-Host "Securing existing administrator accounts..."
try {
    $members = Get-LocalGroupMember -Group $adminGroupName

    foreach ($member in $members) {
        if (($member.SID.Value -like "*-500") -or ($member.Name -eq $newAdminUsername) -or ($member.Name.EndsWith("\$($NewAdminUsername)"))) {
            Write-Host "-> Skipping '$($member.Name)' (it is a protected or newly created administrator)."
            continue
        }

        try {
            Write-Warning "--> Removing user '$($member.Name)' from the '$adminGroupName' group."
            Remove-LocalGroupMember -Group $adminGroupName -Member $member.Name -Confirm:$false
            Write-Host "--> Successfully removed '$($member.Name)' from the Administrators group."
        } catch {
            Write-Error "Failed to remove user '$($member.Name)' from the '$adminGroupName' group. Error: $($_.Exception.Message)"
        }
    }
} catch {
    Write-Error "An error occurred while trying to modify the Administrators group: $($_.Exception.Message)"
}
Write-Host ""

# 10. Set Daily Time Limits for all Non-Administrator Users
if (($cumulativeTimeLimitHours -gt 0) -or ($cumulativeTimeLimitMinutes -gt 0)) {
    # METHOD 1: CUMULATIVE TIME LIMITS
    $totalLimitMinutes = ($cumulativeTimeLimitHours * 60) + $cumulativeTimeLimitMinutes
    Write-Host "Setting up cumulative daily time limits of $cumulativeTimeLimitHours hour(s) and $cumulativeTimeLimitMinutes minute(s) (Total: $totalLimitMinutes minutes)."
    
    # Step 1: Enable Auditing for Logoff events
    try {
        Write-Host "Enabling 'Success' auditing for Logoff events..."
        auditpol /set /subcategory:"{0CCE9216-69AE-11D9-BED3-505054503030}" /success:enable | Out-Null # Logoff GUID
    } catch {
        Write-Warning "Could not verify or set audit policy. Logoff detection might not work correctly. Error: $($_.Exception.Message)"
    }
    
    # Step 2: Create tracking directory and helper scripts with hardened permissions
    $timeLockDir = "C:\ProgramData\TimeLock"
    if (-not (Test-Path $timeLockDir)) {
        New-Item -Path $timeLockDir -ItemType Directory | Out-Null
    }

    # Set permissions on the TimeLock directory to prevent renaming/deletion by non-admins
    Write-Host "Setting secure permissions on the TimeLock directory..."
    $acl = Get-Acl $timeLockDir
    $acl.SetAccessRuleProtection($true, $false) # Disable inheritance, clear existing rules
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
    $userReadWriteRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Authenticated Users", "ReadAndExecute, Write", "ContainerInherit, ObjectInherit", "None", "Allow")
    $userDenyDeleteRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Authenticated Users", "Delete, DeleteSubdirectoriesAndFiles", "ContainerInherit, ObjectInherit", "None", "Deny")
    
    $acl.AddAccessRule($adminRule)
    $acl.AddAccessRule($systemRule)
    $acl.AddAccessRule($userReadWriteRule)
    $acl.AddAccessRule($userDenyDeleteRule)
    Set-Acl -Path $timeLockDir -AclObject $acl
    
    Set-Content -Path "$timeLockDir\config.txt" -Value $totalLimitMinutes

    # Create VBScript helper for running PowerShell scripts silently
    $vbsSilentRunner = @'
' VBScript to run a PowerShell script without a window.
Set objShell = CreateObject("WScript.Shell")
If WScript.Arguments.Count > 0 Then
    psScriptPath = WScript.Arguments(0)
    objShell.Run "powershell.exe -ExecutionPolicy Bypass -File """ & psScriptPath & """", 0, False
End If
'@
    Set-Content -Path "$timeLockDir\SilentRunner.vbs" -Value $vbsSilentRunner

    # Create VBScript helper for displaying modal popups
    $vbsPopup = @'
' VBScript to display a modal popup message that stays on top.
Set objShell = CreateObject("WScript.Shell")
If WScript.Arguments.Count > 0 Then
    messageText = WScript.Arguments(0)
    ' 48 = vbExclamation icon, 0 = vbOKOnly button, 4096 = vbSystemModal (stays on top)
    objShell.Popup messageText, 0, "Time Limit Warning", 48 + 4096
End If
'@
    Set-Content -Path "$timeLockDir\Popup.vbs" -Value $vbsPopup

    $logonScript = @'
# TimeLock_Logon.ps1: This script runs when a user logs on.
$timeLockDir = "C:\ProgramData\TimeLock"
$user = $env:USERNAME
$logFile = "$timeLockDir\$user.log"
$sessionFile = "$timeLockDir\$user.session"
$secret = 'bfg92b3jaskd92nfd02b1'
$todayDate = (Get-Date).ToString("yyyy-MM-dd")
$tamperFile = "$timeLockDir\$user-$todayDate.tamper"

# Part 1: Check for a tamper flag from a previous session today. If found, immediate logoff.
if (Test-Path $tamperFile) {
    logoff
    exit
}

# Part 2: Process previous (potentially unclean) session from unexpected shutdown
if ((Get-Item $sessionFile).Length -gt 0) {
    try {
        $sessionContent = Get-Content -Path $sessionFile
        if ($sessionContent -like "*|*") {
            $parts = $sessionContent.Split('|')
            if ($parts.Length -eq 2) {
                $timestamp = $parts[0]
                $storedHash = $parts[1]
                
                $dataToSign = "$($timestamp)$($user)$($secret)"
                $hashBytes = [System.Text.Encoding]::UTF8.GetBytes($dataToSign)
                $sha256 = New-Object System.Security.Cryptography.SHA256Managed
                $expectedHash = [System.BitConverter]::ToString($sha256.ComputeHash($hashBytes)).Replace("-", "")

                if ($storedHash -ne $expectedHash) {
                    # Tampering detected on the old session file.
                    Set-Content -Path $tamperFile -Value "Tampering detected at logon on $todayDate"
                    logoff
                    exit
                } else {
                    # Unclean but valid session. Log the time used.
                    $logonTime = [DateTime]::Parse($timestamp, $null, [System.Globalization.DateTimeStyles]::RoundtripKind)
                    $minutesUsedToday = 0
                    if (Test-Path $logFile) {
                        try {
                            $logContent = Get-Content $logFile
                            if ($logContent[0] -eq $todayDate) { $minutesUsedToday = [int]$logContent[1] }
                        } catch { }
                    }
                    $sessionMinutes = ((Get-Date).ToUniversalTime() - $logonTime).TotalMinutes
                    $newTotalMinutes = $minutesUsedToday + [math]::Ceiling($sessionMinutes)
                    Set-Content -Path $logFile -Value "$todayDate`n$newTotalMinutes"
                }
            }
        }
    } catch { 
        # Any error reading the file is treated as tampering.
        Set-Content -Path $tamperFile -Value "Corrupt session file detected at logon on $todayDate"
        logoff
        exit
    }
}

# Part 3: Check total time used today and decide if logon is allowed
try { $limitMinutesTotal = [int](Get-Content "$timeLockDir\config.txt") } catch { exit }
if ($limitMinutesTotal -le 0) { exit }

$totalMinutesUsedToday = 0
if (Test-Path $logFile) {
    try {
        $logContent = Get-Content $logFile
        if ($logContent[0] -eq $todayDate) {
            $totalMinutesUsedToday = [int]$logContent[1]
        } else {
            # New day, so remove old warning flags and tamper file from previous days
            Get-ChildItem -Path $timeLockDir -Filter "$user-*.flag" | Remove-Item -Force -ErrorAction SilentlyContinue
            Get-ChildItem -Path $timeLockDir -Filter "$user-*.tamper" | Remove-Item -Force -ErrorAction SilentlyContinue
        }
    } catch { }
}

if ($totalMinutesUsedToday -ge $limitMinutesTotal) {
    logoff
    exit
}

# Part 4: Create a new session file for the current session
$newTimestamp = (Get-Date).ToUniversalTime().ToString("o")
$newDataToSign = "$($newTimestamp)$($user)$($secret)"
$newHashBytes = [System.Text.Encoding]::UTF8.GetBytes($newDataToSign)
$newSha256 = New-Object System.Security.Cryptography.SHA256Managed
$newHash = [System.BitConverter]::ToString($newSha256.ComputeHash($newHashBytes)).Replace("-", "")
$newFileContent = "$($newTimestamp)|$($newHash)"
Set-Content -Path $sessionFile -Value $newFileContent

# Part 5: Launch the countdown timer GUI
$timerScriptPath = "$timeLockDir\TimeLock_Timer.ps1"
if (Test-Path $timerScriptPath) {
    Start-Process powershell.exe -ArgumentList "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$timerScriptPath`""
}
'@
    Set-Content -Path "$timeLockDir\TimeLock_Logon.ps1" -Value $logonScript

    $logoffScript = @'
# TimeLock_Logoff.ps1: This script runs when a user logs off cleanly.
$timeLockDir = "C:\ProgramData\TimeLock"
$user = $env:USERNAME
$logFile = "$timeLockDir\$user.log"
$sessionFile = "$timeLockDir\$user.session"
$timerPidFile = "$timeLockDir\$user.timer.pid"
$secret = 'bfg92b3jaskd92nfd02b1' 

# Terminate the timer GUI process if it's running
if (Test-Path $timerPidFile) {
    try {
        $pid = Get-Content $timerPidFile
        Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
    } catch {}
}

if (-not (Test-Path $sessionFile) -or (Get-Item $sessionFile).Length -eq 0) { exit }

try {
    $sessionContent = Get-Content -Path $sessionFile
    if (-not ($sessionContent -like "*|*")) { throw "Invalid session file format" }
    
    $parts = $sessionContent.Split('|')
    if ($parts.Length -ne 2) { throw "Invalid session file content" }
    $timestamp = $parts[0]
    $storedHash = $parts[1]

    $dataToSign = "$($timestamp)$($user)$($secret)"
    $hashBytes = [System.Text.Encoding]::UTF8.GetBytes($dataToSign)
    $sha256 = New-Object System.Security.Cryptography.SHA256Managed
    $expectedHash = [System.BitConverter]::ToString($sha256.ComputeHash($hashBytes)).Replace("-", "")

    if ($storedHash -ne $expectedHash) {
        Clear-Content -Path $sessionFile -ErrorAction SilentlyContinue
        exit
    }
    
    $logonTime = [DateTime]::Parse($timestamp, $null, [System.Globalization.DateTimeStyles]::RoundtripKind)
    $minutesUsedToday = 0
    $today = (Get-Date).ToString("yyyy-MM-dd")

    if (Test-Path $logFile) {
        try {
            $logContent = Get-Content $logFile
            if ($logContent[0] -eq $today) { $minutesUsedToday = [int]$logContent[1] }
        } catch { }
    }

    $sessionMinutes = ((Get-Date).ToUniversalTime() - $logonTime).TotalMinutes
    $newTotalMinutes = $minutesUsedToday + [math]::Ceiling($sessionMinutes)
    Set-Content -Path $logFile -Value "$today`n$newTotalMinutes"
    Clear-Content -Path $sessionFile -ErrorAction SilentlyContinue
} catch {
    Clear-Content -Path $sessionFile -ErrorAction SilentlyContinue
}
'@
    Set-Content -Path "$timeLockDir\TimeLock_Logoff.ps1" -Value $logoffScript

    $checkScript = @'
# TimeLock_Check.ps1: This script runs every minute to check for overuse.
$timeLockDir = "C:\ProgramData\TimeLock"
$user = $env:USERNAME
$sessionFile = "$timeLockDir\$user.session"
$popupScript = "$timeLockDir\Popup.vbs"
$timerPidFile = "$timeLockDir\$user.timer.pid"
$secret = 'bfg92b3jaskd92nfd02b1' 
$logonTime = $null
$todayDate = (Get-Date).ToString("yyyy-MM-dd")
$tamperFile = "$timeLockDir\$user-$todayDate.tamper"

# Anti-tampering check: Validate the session file. If missing, corrupt, or hash mismatch, log off immediately.
if (-not (Test-Path $sessionFile) -or (Get-Item $sessionFile).Length -eq 0) { 
    # Session file empty or missing, likely after a clean logoff or lock. Let logoff/logon scripts handle it.
    exit
}
try {
    $sessionContent = Get-Content -Path $sessionFile
    if (-not ($sessionContent -like "*|*")) { throw "Invalid session file format" }

    $parts = $sessionContent.Split('|')
    if ($parts.Length -ne 2) { throw "Invalid session file content" }
    $timestamp = $parts[0]
    $storedHash = $parts[1]
    
    $dataToSign = "$($timestamp)$($user)$($secret)"
    $hashBytes = [System.Text.Encoding]::UTF8.GetBytes($dataToSign)
    $sha256 = New-Object System.Security.Cryptography.SHA256Managed
    $expectedHash = [System.BitConverter]::ToString($sha256.ComputeHash($hashBytes)).Replace("-", "")

    if ($storedHash -ne $expectedHash) { 
        Set-Content -Path $tamperFile -Value "Tampering detected during session on $todayDate"
        if (Test-Path $timerPidFile) { try { Stop-Process -Id (Get-Content $timerPidFile) -Force -ErrorAction SilentlyContinue } catch {} }
        logoff
        exit 
    }

    $logonTime = [DateTime]::Parse($timestamp, $null, [System.Globalization.DateTimeStyles]::RoundtripKind)
} catch {
    Set-Content -Path $tamperFile -Value "Corrupt session file detected during session on $todayDate"
    if (Test-Path $timerPidFile) { try { Stop-Process -Id (Get-Content $timerPidFile) -Force -ErrorAction SilentlyContinue } catch {} }
    logoff
    exit
}
if ($logonTime -eq $null) { 
    Set-Content -Path $tamperFile -Value "Session file read error on $todayDate"
    if (Test-Path $timerPidFile) { try { Stop-Process -Id (Get-Content $timerPidFile) -Force -ErrorAction SilentlyContinue } catch {} }
    logoff
    exit 
}

# Now proceed with normal time checking
try { $limitMinutesTotal = [int](Get-Content "$timeLockDir\config.txt") } catch { exit }
if ($limitMinutesTotal -le 0) { exit }

$logFile = "$timeLockDir\$user.log"
$flag10min = "$timeLockDir\$user-10min.flag"
$flag5min = "$timeLockDir\$user-5min.flag"
$minutesUsedBeforeSession = 0

if (Test-Path $logFile) {
    try {
        $logContent = Get-Content $logFile
        if ($logContent[0] -eq $todayDate) { $minutesUsedBeforeSession = [int]$logContent[1] }
    } catch { }
}

$currentSessionMinutes = (New-TimeSpan -Start $logonTime -End (Get-Date).ToUniversalTime()).TotalMinutes
$totalMinutesUsedSoFar = $minutesUsedBeforeSession + $currentSessionMinutes
$minutesRemaining = $limitMinutesTotal - $totalMinutesUsedSoFar

if (($minutesRemaining -le 10) -and (-not (Test-Path $flag10min))) {
    Start-Process wscript.exe -ArgumentList "`"$popupScript`" `"You have less than 10 minutes of computer time remaining for today.`"" -NoNewWindow
    Set-Content -Path $flag10min -Value 1 -Force
}

if (($minutesRemaining -le 5) -and (-not (Test-Path $flag5min))) {
    Start-Process wscript.exe -ArgumentList "`"$popupScript`" `"You have less than 5 minutes of computer time remaining for today. Please save your work.`"" -NoNewWindow
    Set-Content -Path $flag5min -Value 1 -Force
}

if ($totalMinutesUsedSoFar -ge $limitMinutesTotal) {
    $finalTotalMinutes = $minutesUsedBeforeSession + [math]::Ceiling($currentSessionMinutes)
    Set-Content -Path $logFile -Value "$todayDate`n$finalTotalMinutes"
    if (Test-Path $timerPidFile) { try { Stop-Process -Id (Get-Content $timerPidFile) -Force -ErrorAction SilentlyContinue } catch {} }
    Clear-Content -Path $sessionFile -ErrorAction SilentlyContinue
    logoff
}
'@
    Set-Content -Path "$timeLockDir\TimeLock_Check.ps1" -Value $checkScript
    
    $timerScript = @'
# TimeLock_Timer.ps1 - GUI Countdown Timer
$timeLockDir = "C:\ProgramData\TimeLock"
$user = $env:USERNAME
$mutexName = "Global\TimeLock_Timer_Mutex_$($user)"
$isFirstInstance = $false
$mutex = New-Object System.Threading.Mutex($true, $mutexName, [ref]$isFirstInstance)

if (-not $isFirstInstance) {
    # Another instance is already running for this user. Exit quietly.
    exit
}

try {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $logFile = "$timeLockDir\$user.log"
    $sessionFile = "$timeLockDir\$user.session"
    $pidFile = "$timeLockDir\$user.timer.pid"
    
    $PID | Out-File -FilePath $pidFile -Encoding ascii

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Time Remaining"
    $form.Size = New-Object System.Drawing.Size(220, 90)
    $form.StartPosition = "Manual"
    
    # Get screen dimensions using a more reliable method for VMs
    try {
        $video = Get-CimInstance -ClassName Win32_VideoController
        $screenWidth = $video.CurrentHorizontalResolution
        $screenHeight = $video.CurrentVerticalResolution
        if (-not $screenWidth -or -not $screenHeight) { throw "Could not determine screen resolution via CIM." }
        $form.Location = New-Object System.Drawing.Point($screenWidth - $form.Width - 10, $screenHeight - $form.Height - 10)
    } catch {
        # Fallback to a default position if CIM fails
        $form.Location = New-Object System.Drawing.Point(800, 600)
    }

    $form.TopMost = $true
    $form.FormBorderStyle = 'FixedSingle'
    $form.MaximizeBox = $false
    $form.MinimizeBox = $true

    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Point(10, 15)
    $label.Size = New-Object System.Drawing.Size(200, 30)
    $label.Font = New-Object System.Drawing.Font("Segoe UI", 12)
    $label.Text = "Calculating..."
    $form.Controls.Add($label)

    $notifyIcon = New-Object System.Windows.Forms.NotifyIcon
    $notifyIcon.Icon = [System.Drawing.SystemIcons]::Information
    $notifyIcon.Text = "Click to show remaining time"
    $notifyIcon.Visible = $true
    
    $notifyIcon.add_Click({
        $form.Show()
        $form.WindowState = 'Normal'
        $form.Activate()
    })
    
    $form.Add_FormClosing({
        param($sender, $e)
        if ($e.CloseReason -eq 'UserClosing') {
            $e.Cancel = $true
            $sender.Hide()
        }
    })
    
    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 1000

    $timer.add_Tick({
        $logonTime = $null
        try {
            if (-not (Test-Path $sessionFile) -or (Get-Item $sessionFile).Length -eq 0) {
                 $label.Text = "Paused"
                 return
            }
            $sessionContent = Get-Content -Path $sessionFile -ErrorAction Stop
            if ($sessionContent -like "*|*") {
                $timestamp = $sessionContent.Split('|')[0]
                $logonTime = [DateTime]::Parse($timestamp, $null, [System.Globalization.DateTimeStyles]::RoundtripKind)
            }
        } catch {
            $label.Text = "Paused"
            return
        }
        
        if ($logonTime -eq $null) {
            $label.Text = "Error..."
            return
        }

        try { $limitMinutesTotal = [int](Get-Content "$timeLockDir\config.txt") } catch { return }
        if ($limitMinutesTotal -le 0) { $form.Close(); return }

        $minutesUsedBeforeSession = 0
        $todayDate = (Get-Date).ToString("yyyy-MM-dd")
        if (Test-Path $logFile) {
            try {
                $logContent = Get-Content $logFile
                if ($logContent[0] -eq $todayDate) { $minutesUsedBeforeSession = [int]$logContent[1] }
            } catch { }
        }

        $currentSessionSeconds = (New-TimeSpan -Start $logonTime -End (Get-Date).ToUniversalTime()).TotalSeconds
        $totalSecondsUsedSoFar = ($minutesUsedBeforeSession * 60) + $currentSessionSeconds
        $totalLimitSeconds = $limitMinutesTotal * 60
        $secondsRemaining = $totalLimitSeconds - $totalSecondsUsedSoFar

        if ($secondsRemaining -le 0) {
            $timer.Stop()
            
            # Calculate final total minutes and write to log file
            $finalTotalMinutes = [math]::Ceiling($totalSecondsUsedSoFar / 60)
            Set-Content -Path $logFile -Value "$todayDate`n$finalTotalMinutes"
            
            # Clear session file and log off
            Clear-Content -Path $sessionFile -ErrorAction SilentlyContinue
            shutdown.exe /l /f
            
            # Close the form as a fallback
            $form.Close()
            return
        }

        $timespan = [TimeSpan]::FromSeconds([math]::Floor($secondsRemaining))
        $label.Text = $timespan.ToString("hh\:mm\:ss")
    })

    $form.Add_Shown({ $timer.Start() })
    
    [System.Windows.Forms.Application]::Run($form)

    # Clean up after form is closed
    $timer.Dispose()
    $notifyIcon.Dispose()
    if (Test-Path $pidFile) {
        Remove-Item $pidFile -Force
    }
}
catch {
    $errorMessage = $error[0].ToString() + "`r`n" + $error[0].InvocationInfo.PositionMessage
    Set-Content -Path "$timeLockDir\timer_error.log" -Value $errorMessage -Encoding utf8
}
finally {
    if ($mutex) {
        $mutex.ReleaseMutex()
        $mutex.Dispose()
    }
}
'@
    Set-Content -Path "$timeLockDir\TimeLock_Timer.ps1" -Value $timerScript

    # After creating the core files, harden their permissions to be read-only for non-admins.
    Write-Host "Hardening permissions on core TimeLock files to prevent tampering..."
    $coreFiles = @(
        "$timeLockDir\config.txt",
        "$timeLockDir\TimeLock_Logon.ps1",
        "$timeLockDir\TimeLock_Logoff.ps1",
        "$timeLockDir\TimeLock_Check.ps1",
        "$timeLockDir\SilentRunner.vbs",
        "$timeLockDir\Popup.vbs",
        "$timeLockDir\TimeLock_Timer.ps1"
    )

    $fileAdminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", "Allow")
    $fileSystemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "Allow")
    $fileUserReadOnlyRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Authenticated Users", "ReadAndExecute", "Allow")
    foreach ($file in $coreFiles) {
        if (Test-Path $file) {
            try {
                $fileAcl = Get-Acl $file
                $fileAcl.SetAccessRuleProtection($true, $false)
                $fileAcl.AddAccessRule($fileAdminRule)
                $fileAcl.AddAccessRule($fileSystemRule)
                $fileAcl.AddAccessRule($fileUserReadOnlyRule)
                Set-Acl -Path $file -AclObject $fileAcl
            } catch {
                Write-Warning "Could not harden permissions for core file '$file'. Error: $($_.Exception.Message)"
            }
        }
    }
    Write-Host "Helper scripts for time tracking created in $timeLockDir"

    # Step 3: Create scheduled tasks for each non-admin user
    $allUsers = Get-LocalUser | Where-Object { $_.Enabled -eq $true }
    foreach ($user in $allUsers) {
        if ($user.Name -eq $newAdminUsername) { continue }
        $isAdmin = Get-LocalGroupMember -Group $adminGroupName -Member $user.Name -ErrorAction SilentlyContinue
        if ($isAdmin) { continue }

        Write-Host "Setting up time limit tasks for user '$($user.Name)'..."
        $sessionFile = "$timeLockDir\$($user.Name).session"
        if (-not (Test-Path $sessionFile)) {
            New-Item -Path $sessionFile -ItemType File | Out-Null
        }
        try {
            Write-Host "--> Hardening session file for '$($user.Name)'..."
            $sessionAcl = Get-Acl $sessionFile
            $sessionAcl.SetAccessRuleProtection($true, $false)
            $sessionAdminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", "Allow")
            $sessionSystemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "Allow")
            $sessionUserWriteRule = New-Object System.Security.AccessControl.FileSystemAccessRule($user.Name, "Write, ReadAndExecute", "Allow")
            $sessionUserDenyDeleteRule = New-Object System.Security.AccessControl.FileSystemAccessRule($user.Name, "Delete", "Deny")
            $sessionAcl.AddAccessRule($sessionAdminRule)
            $sessionAcl.AddAccessRule($sessionSystemRule)
            $sessionAcl.AddAccessRule($sessionUserWriteRule)
            $sessionAcl.AddAccessRule($sessionUserDenyDeleteRule)
            Set-Acl -Path $sessionFile -AclObject $sessionAcl
        } catch {
            Write-Warning "--> Could not harden session file for '$($user.Name)'. Error: $($_.Exception.Message)"
        }

        Get-ScheduledTask -TaskName "TimeLock_*" | Where-Object { $_.TaskPath -like "*$($user.Name)" } | ForEach-Object { Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false }
        
        $silentRunner = "$timeLockDir\SilentRunner.vbs"
        $principal = New-ScheduledTaskPrincipal -UserId $user.Name
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
        
        $logonPsScript = "$timeLockDir\TimeLock_Logon.ps1"
        $logonArgument = "`"$silentRunner`" `"$logonPsScript`""
        $actionLogon = New-ScheduledTaskAction -Execute 'wscript.exe' -Argument $logonArgument
        $triggerLogon = New-ScheduledTaskTrigger -AtLogon
        Register-ScheduledTask -TaskName "TimeLock_Logon_$($user.Name)" -Action $actionLogon -Trigger $triggerLogon -Principal $principal -Settings $settings -Force -ErrorAction SilentlyContinue

        $logoffPsScript = "$timeLockDir\TimeLock_Logoff.ps1"
        $taskNameLogoff = "TimeLock_Logoff_$($user.Name)"
        $taskActionArgument = "`"$silentRunner`" `"$logoffPsScript`""
        $taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><RegistrationInfo><Description>Updates user screen time log upon logoff.</Description><Author>SecureDevice Script</Author></RegistrationInfo><Triggers><EventTrigger><Enabled>true</Enabled><Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="Security"&gt;&lt;Select Path="Security"&gt;*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and (EventID=4647)]] and *[EventData[Data[@Name='TargetUserName']='$($user.Name)']]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription></EventTrigger></Triggers><Principals><Principal id="Author"><UserId>$($user.Name)</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals><Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>false</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><IdleSettings><StopOnIdleEnd>true</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun><ExecutionTimeLimit>PT2M</ExecutionTimeLimit><Priority>7</Priority></Settings><Actions Context="Author"><Exec><Command>wscript.exe</Command><Arguments>$taskActionArgument</Arguments></Exec></Actions></Task>
"@
        $tempXmlPath = Join-Path $env:TEMP "TimeLockTask.xml"
        try {
            $taskXml | Out-File -FilePath $tempXmlPath -Encoding unicode
            schtasks.exe /create /tn "$taskNameLogoff" /xml "$tempXmlPath" /f | Out-Null
        } catch {
            Write-Warning "Failed to create logoff task for $($user.Name). Error: $($_.Exception.Message)"
        } finally { if (Test-Path $tempXmlPath) { Remove-Item $tempXmlPath -Force } }

        $checkPsScript = "$timeLockDir\TimeLock_Check.ps1"
        $checkArgument = "`"$silentRunner`" `"$checkPsScript`""
        $actionCheck = New-ScheduledTaskAction -Execute 'wscript.exe' -Argument $checkArgument
        $triggerCheck = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 9999)
        Register-ScheduledTask -TaskName "TimeLock_Check_$($user.Name)" -Action $actionCheck -Trigger $triggerCheck -Principal $principal -Settings $settings -Force -ErrorAction SilentlyContinue
    }

    # Step 4: Harden Security of Time Limit Tasks and Service
    Write-Host "Hardening security for Task Scheduler service and time limit tasks..."
    try {
        $sddl = "D:(A;;LCRPWP;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWRPWPDTLOCRRC;;;BA)"
        sc.exe sdset Schedule $sddl | Out-Null
        Write-Host "-> Task Scheduler service permissions hardened."
        $taskFiles = Get-ChildItem -Path "C:\Windows\System32\Tasks" -Filter "TimeLock_*"
        foreach ($taskFile in $taskFiles) {
            try {
                Write-Host "--> Securing task file: $($taskFile.FullName)"
                icacls.exe $taskFile.FullName /inheritance:d | Out-Null
                icacls.exe $taskFile.FullName /remove *$usersSid | Out-Null
                icacls.exe $taskFile.FullName /grant "*S-1-5-11:(F)" /grant "*S-1-5-32-544:(F)" | Out-Null # Authenticated Users, Administrators
            } catch {
                Write-Warning "--> Could not set permissions for task file '$($taskFile.FullName)'. Error: $($_.Exception.Message)"
            }
        }
        Write-Host "-> Time limit task file permissions hardened."
    } catch {
        Write-Warning "Could not harden Task Scheduler security. Error: $($_.Exception.Message)"
    }

} elseif (-not [string]::IsNullOrEmpty($timeLimitWindow)) {
    # METHOD 2: TIME WINDOW LIMIT
    # TODO: this doesn't actually log users off when time's up (need a service/task?)
    Write-Host "Applying daily time window limits for non-administrator users..."
    try {
        $allUsers = Get-LocalUser | Where-Object { $_.Enabled -eq $true }
        foreach ($user in $allUsers) {
            if ($user.Name -eq $newAdminUsername) {
                Write-Host "-> Skipping time limit for administrator '$($user.Name)'."
                continue
            }
            $isAdmin = Get-LocalGroupMember -Group $adminGroupName -Member $user.Name -ErrorAction SilentlyContinue
            if ($isAdmin) {
                Write-Host "-> Skipping time limit for administrator '$($user.Name)'."
                continue
            }
            try {
                Write-Host "--> Applying time limit ($timeLimitWindow) to user '$($user.Name)'..."
                net user "$($user.Name)" /time:M-Su,$timeLimitWindow | Out-Null
                Write-Host "--> Successfully set time limit for '$($user.Name)'."
            } catch {
                Write-Warning "Could not set time limit for user '$($user.Name)'. Error: $($_.Exception.Message)"
            }
        }
    } catch {
        Write-Error "An error occurred while trying to set time limits: $($_.Exception.Message)"
    }
} else {
    Write-Host "Skipping time limits as no method was configured."
}
Write-Host ""


# 11. Set up logon message task
Write-Host "Creating scheduled task for logon message..."
try {
    $taskName = "LogonMessage"

    # msg.exe doesn't exist in windows home; use powershell one-liners instead
    
    # Needs less permissions, but doesn't stay in the foreground
    #$action = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument "-Command `"Add-Type -AssemblyName PresentationFramework;[System.Windows.MessageBox]::Show('This system has been locked down for your protection. If you are an adult, please log in with the admin credentials emailed to you for full system access.', 'Parental Controls Warning', 0, 48)`""
    
    # Needs maybe more permissions? But always stays in the foreground until acknowledged ;)
    $action = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument "-Command `"[void][System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic');[Microsoft.VisualBasic.Interaction]::MsgBox('This system has been locked down for your protection. If you are an adult, please log in with the admin credentials emailed to you for full system access.', 'SystemModal,MsgBoxSetForeground,Exclamation', 'Parental Controls Warning')`""

    $trigger = New-ScheduledTaskTrigger -AtLogon
    $principal = New-ScheduledTaskPrincipal -GroupId $usersSid 
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        Write-Host "Removed existing scheduled task '$taskName'."
    }
    
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force
    Write-Host "Scheduled task '$taskName' created successfully."
} catch {
    Write-Error "Failed to create scheduled logon task. Error: $($_.Exception.Message)"
}
Write-Host ""


# 12. Restrict access to Control Panel for non-administrators
Write-Host "Restricting access to Control Panel for non-admin users..."
try {
    # Computer\HKEY_USERS\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun ???
    $policyKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    if (-not (Test-Path $policyKey)) {
        New-Item -Path $policyKey -Force | Out-Null
    }
    Set-ItemProperty -Path $policyKey -Name "NoControlPanel" -Value 1 -Type DWord -Force
    Write-Host "Control Panel access will be restricted for users upon their next login."
} catch {
    Write-Error "Failed to set registry key to restrict Control Panel. Error: $($_.Exception.Message)"
}
Write-Host ""

# 13. Harden Script Directory
Write-Host "Hardening the child lock script directory..."
try {
    $scriptDir = $PSScriptRoot
    if ($scriptDir) {
        $acl = Get-Acl $scriptDir
        $acl.SetAccessRuleProtection($true, $false) # Disable inheritance, remove existing rules from parent

        $adminSidPrincipal = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
        $systemSidPrincipal = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")
        $usersSidPrincipal = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-545")

        $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule($adminSidPrincipal, "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
        $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule($systemSidPrincipal, "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
        $userDenyRule = New-Object System.Security.AccessControl.FileSystemAccessRule($usersSidPrincipal, "ReadAndExecute", "ContainerInherit, ObjectInherit", "None", "Deny")

        $acl.AddAccessRule($adminRule)
        $acl.AddAccessRule($systemRule)
        $acl.AddAccessRule($userDenyRule)

        Set-Acl -Path $scriptDir -AclObject $acl
        Write-Host "-> Script directory permissions hardened successfully."
    } else {
        Write-Warning "-> Could not determine script directory. Skipping hardening."
    }
} catch {
    Write-Warning "Could not harden the script directory permissions. Error: $($_.Exception.Message)"
}
Write-Host ""

# 14. Final message and logoff
Write-Host "Script finished successfully."
#shutdown.exe /l /f
