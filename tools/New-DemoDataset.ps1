<#
.SYNOPSIS
    Generates the synthetic demo domain used by AD-Audit-Toolkit demo mode.
.DESCRIPTION
    Every object this produces is fake. Dates are stored as day offsets so the
    demo is stable no matter when it runs. The generator seeds a realistic mix
    of clean accounts and deliberate findings so a reviewer sees the tool work.
    Run this to regenerate ADAuditToolkit\Data\demo-domain.json.
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path $PSScriptRoot '..\ADAuditToolkit\Data\demo-domain.json'),
    [int]$Seed = 20260715
)

$rand = New-Object System.Random($Seed)

$firstNames = @('James', 'Mary', 'Robert', 'Linda', 'Michael', 'Patricia', 'David', 'Jennifer', 'Chris', 'Karen',
    'Daniel', 'Nancy', 'Paul', 'Lisa', 'Mark', 'Betty', 'Steven', 'Sandra', 'Kevin', 'Ashley',
    'Brian', 'Emily', 'George', 'Donna', 'Edward', 'Carol', 'Ronald', 'Amanda', 'Kenneth', 'Melissa')
$lastNames = @('Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller', 'Davis', 'Rodriguez', 'Martinez',
    'Hernandez', 'Lopez', 'Gonzalez', 'Wilson', 'Anderson', 'Thomas', 'Taylor', 'Moore', 'Jackson', 'Martin',
    'Lee', 'Perez', 'Thompson', 'White', 'Harris', 'Sanchez', 'Clark', 'Ramirez', 'Lewis', 'Robinson')

$users = New-Object System.Collections.ArrayList
$usedSam = @{}

function New-Sam {
    param($first, $last)
    $base = ($first.Substring(0, 1) + $last).ToLower()
    $sam = $base
    $i = 1
    while ($usedSam.ContainsKey($sam)) { $sam = "$base$i"; $i++ }
    $usedSam[$sam] = $true
    $sam
}

# 200 ordinary users. Most are clean and active.
for ($i = 0; $i -lt 200; $i++) {
    $fn = $firstNames[$rand.Next($firstNames.Count)]
    $ln = $lastNames[$rand.Next($lastNames.Count)]
    $sam = New-Sam $fn $ln
    $lastLogon = $rand.Next(0, 45)
    $pwdSet = $rand.Next(0, 120)
    $neverExpires = $false
    $notReqd = $false
    $enabled = $true

    $roll = $rand.NextDouble()
    if ($roll -lt 0.12) { $lastLogon = $rand.Next(95, 400) }      # stale
    elseif ($roll -lt 0.16) { $enabled = $false; $lastLogon = $rand.Next(120, 600) }
    if ($rand.NextDouble() -lt 0.08) { $neverExpires = $true }     # password never expires
    if ($rand.NextDouble() -lt 0.10) { $pwdSet = $rand.Next(370, 900) } # aged password
    if ($rand.NextDouble() -lt 0.02) { $notReqd = $true }          # passwd not required

    [void]$users.Add([pscustomobject]@{
            SamAccountName         = $sam
            DisplayName            = "$fn $ln"
            Enabled                = $enabled
            LastLogonDaysAgo       = $lastLogon
            PasswordLastSetDaysAgo  = $pwdSet
            PasswordNeverExpires   = $neverExpires
            PasswordNotRequired    = $notReqd
            ServicePrincipalNames  = @()
            TrustedForDelegation   = $false
            WhenCreatedDaysAgo     = $rand.Next(400, 2000)
            Description            = ''
        })
}

# Service accounts. These carry SPNs and non-expiring passwords, which is the realistic bad pattern.
$svcRoles = @('sql', 'iis', 'backup', 'sched', 'app', 'mail', 'sync', 'report', 'monitor', 'web')
foreach ($role in $svcRoles) {
    $sam = "svc-$role"
    $usedSam[$sam] = $true
    $spns = @("$role/host01.corp.local", "$role/host01.corp.local:1433")
    [void]$users.Add([pscustomobject]@{
            SamAccountName         = $sam
            DisplayName            = "Service $role"
            Enabled                = $true
            LastLogonDaysAgo       = $rand.Next(0, 30)
            PasswordLastSetDaysAgo  = $rand.Next(300, 1100)
            PasswordNeverExpires   = $true
            PasswordNotRequired    = $false
            ServicePrincipalNames  = $spns
            TrustedForDelegation   = ($role -eq 'app')
            WhenCreatedDaysAgo     = $rand.Next(500, 1800)
            Description            = "Service account for $role"
        })
}

# Admin accounts. Some are fine. A few are deliberate findings.
$admins = @(
    @{ sam = 'admin.jsmith'; logon = 3; enabled = $true; never = $true; spn = $false },
    @{ sam = 'admin.mjones'; logon = 12; enabled = $true; never = $false; spn = $false },
    @{ sam = 'admin.legacy'; logon = 210; enabled = $true; never = $true; spn = $false },   # inactive privileged
    @{ sam = 'admin.former'; logon = 300; enabled = $false; never = $true; spn = $false },  # disabled but privileged
    @{ sam = 'admin.dbadmin'; logon = 6; enabled = $true; never = $true; spn = $true },     # privileged + kerberoastable
    @{ sam = 'admin.builtin'; logon = 40; enabled = $true; never = $true; spn = $false }
)
foreach ($a in $admins) {
    $spns = if ($a.spn) { @('MSSQLSvc/db01.corp.local:1433') } else { @() }
    [void]$users.Add([pscustomobject]@{
            SamAccountName         = $a.sam
            DisplayName            = $a.sam
            Enabled                = $a.enabled
            LastLogonDaysAgo       = $a.logon
            PasswordLastSetDaysAgo  = $rand.Next(30, 300)
            PasswordNeverExpires   = $a.never
            PasswordNotRequired    = $false
            ServicePrincipalNames  = $spns
            TrustedForDelegation   = $false
            WhenCreatedDaysAgo     = $rand.Next(800, 2500)
            Description            = 'Administrative account'
        })
}

# Computers. Servers, workstations, DCs, one dormant, one with unconstrained delegation.
$computers = New-Object System.Collections.ArrayList
[void]$computers.Add([pscustomobject]@{ Name = 'DC01'; Enabled = $true; LastLogonDaysAgo = 0; OperatingSystem = 'Windows Server 2022'; TrustedForDelegation = $true; IsDomainController = $true })
[void]$computers.Add([pscustomobject]@{ Name = 'DC02'; Enabled = $true; LastLogonDaysAgo = 1; OperatingSystem = 'Windows Server 2022'; TrustedForDelegation = $true; IsDomainController = $true })
[void]$computers.Add([pscustomobject]@{ Name = 'FILE01'; Enabled = $true; LastLogonDaysAgo = 2; OperatingSystem = 'Windows Server 2019'; TrustedForDelegation = $true; IsDomainController = $false }) # unconstrained deleg finding
[void]$computers.Add([pscustomobject]@{ Name = 'APP-LEGACY'; Enabled = $true; LastLogonDaysAgo = 190; OperatingSystem = 'Windows Server 2012 R2'; TrustedForDelegation = $false; IsDomainController = $false }) # dormant
for ($i = 1; $i -le 30; $i++) {
    $n = 'WS{0:D3}' -f $i
    $logon = $rand.Next(0, 20)
    if ($rand.NextDouble() -lt 0.1) { $logon = $rand.Next(130, 400) }
    [void]$computers.Add([pscustomobject]@{ Name = $n; Enabled = $true; LastLogonDaysAgo = $logon; OperatingSystem = 'Windows 11 Enterprise'; TrustedForDelegation = $false; IsDomainController = $false })
}

# Privileged groups. Domain Admins is deliberately oversized. Nested group demonstrates recursion.
$groups = @(
    [pscustomobject]@{ Name = 'Domain Admins'; Members = @('admin.jsmith', 'admin.mjones', 'admin.legacy', 'admin.former', 'admin.dbadmin', 'admin.builtin', 'Tier0-Ops') },
    [pscustomobject]@{ Name = 'Enterprise Admins'; Members = @('admin.jsmith') },
    [pscustomobject]@{ Name = 'Schema Admins'; Members = @('admin.jsmith') },
    [pscustomobject]@{ Name = 'Administrators'; Members = @('Domain Admins', 'admin.builtin') },
    [pscustomobject]@{ Name = 'Account Operators'; Members = @('svc-sched') },
    [pscustomobject]@{ Name = 'Backup Operators'; Members = @('svc-backup') },
    [pscustomobject]@{ Name = 'Server Operators'; Members = @() },
    [pscustomobject]@{ Name = 'Print Operators'; Members = @() },
    [pscustomobject]@{ Name = 'Tier0-Ops'; Members = @('admin.mjones', 'admin.dbadmin') }
)

$dataset = [pscustomobject]@{
    Domain    = [pscustomobject]@{
        Name           = 'corp.local'
        PasswordPolicy = [pscustomobject]@{
            MinPasswordLength           = 8       # below baseline, deliberate finding
            MaxPasswordAgeDays          = 0       # never expires, deliberate finding
            LockoutThreshold            = 0       # disabled, deliberate finding
            ComplexityEnabled           = $true
            ReversibleEncryptionEnabled = $false
        }
    }
    Users     = @($users)
    Computers = @($computers)
    Groups    = @($groups)
}

$dir = Split-Path $OutputPath -Parent
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
$dataset | ConvertTo-Json -Depth 6 | Out-File -FilePath $OutputPath -Encoding UTF8

Write-Host "Wrote $($users.Count) users, $($computers.Count) computers, $($groups.Count) groups to $OutputPath"
