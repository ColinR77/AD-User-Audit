<#
.SYNOPSIS
    Audits Active Directory user accounts based on last sign-in date and password age.

.DESCRIPTION
    This script audits AD user accounts, reporting on:
    - Last sign-in date (LastLogonDate)
    - Password age
    - Password expiration status
    - Account status (enabled/disabled)
    - Account lockout status
    
.PARAMETER DaysInactive
    Number of days of inactivity to flag accounts (default: 90)

.PARAMETER PasswordAgeDays
    Number of days to flag old passwords (default: 90)

.PARAMETER SearchBase
    Optional OU to limit the search (e.g., "OU=Users,DC=domain,DC=com")

.PARAMETER ExportPath
    Optional path to export results to CSV

.PARAMETER IncludeDisabled
    Include disabled accounts in the audit

.EXAMPLE
    .\Audit-ADUserAccounts.ps1
    
.EXAMPLE
    .\Audit-ADUserAccounts.ps1 -DaysInactive 60 -PasswordAgeDays 180 -ExportPath "C:\Audit\ADUsers.csv"
    
.EXAMPLE
    .\Audit-ADUserAccounts.ps1 -SearchBase "OU=Users,DC=contoso,DC=com" -IncludeDisabled
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [int]$DaysInactive = 90,
    
    [Parameter(Mandatory=$false)]
    [int]$PasswordAgeDays = 90,
    
    [Parameter(Mandatory=$false)]
    [string]$SearchBase,
    
    [Parameter(Mandatory=$false)]
    [string]$ExportPath,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeDisabled
)

# Check for Active Directory module
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "Active Directory PowerShell module is not installed. Please install RSAT tools."
    exit 1
}

Import-Module ActiveDirectory

Write-Host "=== Active Directory User Account Audit ===" -ForegroundColor Cyan
Write-Host "Domain: $env:USERDNSDOMAIN" -ForegroundColor Green
Write-Host "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Green
Write-Host "Inactive Threshold: $DaysInactive days" -ForegroundColor Green
Write-Host "Password Age Threshold: $PasswordAgeDays days" -ForegroundColor Green
if ($SearchBase) {
    Write-Host "Search Base: $SearchBase" -ForegroundColor Green
}
Write-Host ""

$results = @()
$currentDate = Get-Date
$inactiveDate = $currentDate.AddDays(-$DaysInactive)

# Build filter
$filter = "ObjectClass -eq 'user'"
if (-not $IncludeDisabled) {
    $filter += " -and Enabled -eq `$true"
}

# Get AD users
$properties = @(
    'SamAccountName',
    'DisplayName',
    'EmailAddress',
    'Enabled',
    'LastLogonDate',
    'PasswordLastSet',
    'PasswordNeverExpires',
    'PasswordExpired',
    'AccountExpirationDate',
    'LockedOut',
    'Created',
    'Modified',
    'Description',
    'Department',
    'Title',
    'Manager'
)

try {
    $getADUserParams = @{
        Filter = $filter
        Properties = $properties
    }
    
    if ($SearchBase) {
        $getADUserParams.SearchBase = $SearchBase
    }
    
    $adUsers = Get-ADUser @getADUserParams
    
    Write-Host "Found $($adUsers.Count) user accounts to audit..." -ForegroundColor Yellow
    Write-Host ""
    
    foreach ($user in $adUsers) {
        Write-Host "Processing: $($user.SamAccountName)..." -ForegroundColor Yellow
        
        # Calculate password age
        $passwordAge = $null
        $passwordAgeStatus = "N/A"
        if ($user.PasswordLastSet) {
            $passwordAge = ($currentDate - $user.PasswordLastSet).Days
            if ($user.PasswordNeverExpires) {
                $passwordAgeStatus = "Password Never Expires"
            } elseif ($user.PasswordExpired) {
                $passwordAgeStatus = "EXPIRED"
            } elseif ($passwordAge -gt $PasswordAgeDays) {
                $passwordAgeStatus = "WARNING - Old Password"
            } else {
                $passwordAgeStatus = "OK"
            }
        } else {
            $passwordAgeStatus = "Never Set"
        }
        
        # Calculate last logon age
        $lastLogonAge = $null
        $activityStatus = "N/A"
        if ($user.LastLogonDate) {
            $lastLogonAge = ($currentDate - $user.LastLogonDate).Days
            if ($lastLogonAge -gt $DaysInactive) {
                $activityStatus = "WARNING - Inactive"
            } else {
                $activityStatus = "Active"
            }
        } else {
            $activityStatus = "Never Logged On"
        }
        
        # Calculate days until account expires
        $daysUntilExpiration = $null
        $expirationStatus = "Never"
        if ($user.AccountExpirationDate) {
            $daysUntilExpiration = ($user.AccountExpirationDate - $currentDate).Days
            if ($daysUntilExpiration -le 0) {
                $expirationStatus = "EXPIRED"
            } elseif ($daysUntilExpiration -le 30) {
                $expirationStatus = "WARNING - Expires Soon"
            } else {
                $expirationStatus = "OK"
            }
        }
        
        # Get manager name
        $managerName = "N/A"
        if ($user.Manager) {
            try {
                $managerObj = Get-ADUser -Identity $user.Manager -Properties DisplayName -ErrorAction SilentlyContinue
                $managerName = $managerObj.DisplayName
            } catch {
                $managerName = $user.Manager
            }
        }
        
        # Create result object
        $result = [PSCustomObject]@{
            Username = $user.SamAccountName
            DisplayName = $user.DisplayName
            Email = $user.EmailAddress
            Enabled = $user.Enabled
            LockedOut = $user.LockedOut
            LastLogonDate = if ($user.LastLogonDate) { $user.LastLogonDate.ToString('yyyy-MM-dd HH:mm:ss') } else { "Never" }
            DaysSinceLastLogon = $lastLogonAge
            ActivityStatus = $activityStatus
            PasswordLastSet = if ($user.PasswordLastSet) { $user.PasswordLastSet.ToString('yyyy-MM-dd HH:mm:ss') } else { "Never" }
            PasswordAgeDays = $passwordAge
            PasswordAgeStatus = $passwordAgeStatus
            PasswordNeverExpires = $user.PasswordNeverExpires
            PasswordExpired = $user.PasswordExpired
            AccountExpirationDate = if ($user.AccountExpirationDate) { $user.AccountExpirationDate.ToString('yyyy-MM-dd') } else { "Never" }
            DaysUntilExpiration = $daysUntilExpiration
            ExpirationStatus = $expirationStatus
            Department = $user.Department
            Title = $user.Title
            Manager = $managerName
            Created = $user.Created.ToString('yyyy-MM-dd')
            Modified = $user.Modified.ToString('yyyy-MM-dd')
            Description = $user.Description
        }
        
        $results += $result
    }
    
    # Display results
    Write-Host "`n=== Audit Results ===" -ForegroundColor Cyan
    $results | Format-Table Username, DisplayName, Enabled, ActivityStatus, DaysSinceLastLogon, PasswordAgeStatus, PasswordAgeDays -AutoSize
    
    # Summary statistics
    Write-Host "`n=== Summary ===" -ForegroundColor Cyan
    Write-Host "Total Accounts: $($results.Count)" -ForegroundColor Green
    Write-Host "Enabled Accounts: $($results | Where-Object {$_.Enabled -eq $true} | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor Green
    Write-Host "Disabled Accounts: $($results | Where-Object {$_.Enabled -eq $false} | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor Green
    Write-Host "Locked Out Accounts: $($results | Where-Object {$_.LockedOut -eq $true} | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor Red
    Write-Host "Inactive Accounts (>$DaysInactive days): $($results | Where-Object {$_.ActivityStatus -eq 'WARNING - Inactive'} | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor Yellow
    Write-Host "Old Passwords (>$PasswordAgeDays days): $($results | Where-Object {$_.PasswordAgeStatus -eq 'WARNING - Old Password'} | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor Yellow
    Write-Host "Expired Passwords: $($results | Where-Object {$_.PasswordExpired -eq $true} | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor Red
    Write-Host "Never Logged On: $($results | Where-Object {$_.ActivityStatus -eq 'Never Logged On'} | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor Yellow
    Write-Host "Accounts Expiring Soon (within 30 days): $($results | Where-Object {$_.ExpirationStatus -eq 'WARNING - Expires Soon'} | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor Yellow
    
    # Display critical findings
    Write-Host "`n=== Critical Findings ===" -ForegroundColor Red
    
    $lockedAccounts = $results | Where-Object {$_.LockedOut -eq $true}
    if ($lockedAccounts.Count -gt 0) {
        Write-Host "`nLocked Out Accounts:" -ForegroundColor Red
        $lockedAccounts | Format-Table Username, DisplayName, LastLogonDate -AutoSize
    }
    
    $expiredPasswords = $results | Where-Object {$_.PasswordExpired -eq $true}
    if ($expiredPasswords.Count -gt 0) {
        Write-Host "`nExpired Passwords:" -ForegroundColor Red
        $expiredPasswords | Format-Table Username, DisplayName, PasswordLastSet -AutoSize
    }
    
    # Export if path provided
    if ($ExportPath) {
        try {
            $results | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
            Write-Host "`nResults exported to: $ExportPath" -ForegroundColor Green
        } catch {
            Write-Error "Failed to export results: $_"
        }
    }
    
    Write-Host "`nAudit Complete!" -ForegroundColor Cyan
    
} catch {
    Write-Error "Failed to query Active Directory: $_"
    exit 1
}