BeforeAll {
    $moduleRoot = Split-Path $PSScriptRoot -Parent
    Import-Module (Join-Path $moduleRoot 'ADAuditToolkit\ADAuditToolkit.psd1') -Force

    # Build a small deterministic dataset in memory so tests do not depend on the
    # shipped demo file. Every check gets at least one object it should catch and
    # at least one it should ignore.
    $now = Get-Date
    $script:TestData = [pscustomobject]@{
        Domain    = [pscustomobject]@{
            Name           = 'test.local'
            PasswordPolicy = [pscustomobject]@{
                MinPasswordLength           = 8
                MaxPasswordAgeDays          = 0
                LockoutThreshold            = 0
                ComplexityEnabled           = $true
                ReversibleEncryptionEnabled = $true
            }
        }
        Users     = @(
            [pscustomobject]@{ SamAccountName = 'active.user'; DisplayName = 'Active'; Enabled = $true; LastLogonDate = $now.AddDays(-2); PasswordLastSet = $now.AddDays(-10); PasswordNeverExpires = $false; PasswordNotRequired = $false; ServicePrincipalNames = @(); TrustedForDelegation = $false; WhenCreated = $now.AddDays(-500); Description = '' }
            [pscustomobject]@{ SamAccountName = 'stale.user'; DisplayName = 'Stale'; Enabled = $true; LastLogonDate = $now.AddDays(-200); PasswordLastSet = $now.AddDays(-50); PasswordNeverExpires = $false; PasswordNotRequired = $false; ServicePrincipalNames = @(); TrustedForDelegation = $false; WhenCreated = $now.AddDays(-800); Description = '' }
            [pscustomobject]@{ SamAccountName = 'never.expires'; DisplayName = 'NeverExp'; Enabled = $true; LastLogonDate = $now.AddDays(-1); PasswordLastSet = $now.AddDays(-5); PasswordNeverExpires = $true; PasswordNotRequired = $false; ServicePrincipalNames = @(); TrustedForDelegation = $false; WhenCreated = $now.AddDays(-500); Description = '' }
            [pscustomobject]@{ SamAccountName = 'no.pwd'; DisplayName = 'NoPwd'; Enabled = $true; LastLogonDate = $now.AddDays(-1); PasswordLastSet = $now.AddDays(-5); PasswordNeverExpires = $false; PasswordNotRequired = $true; ServicePrincipalNames = @(); TrustedForDelegation = $false; WhenCreated = $now.AddDays(-500); Description = '' }
            [pscustomobject]@{ SamAccountName = 'old.pwd'; DisplayName = 'OldPwd'; Enabled = $true; LastLogonDate = $now.AddDays(-1); PasswordLastSet = $now.AddDays(-400); PasswordNeverExpires = $false; PasswordNotRequired = $false; ServicePrincipalNames = @(); TrustedForDelegation = $false; WhenCreated = $now.AddDays(-900); Description = '' }
            [pscustomobject]@{ SamAccountName = 'svc.kerb'; DisplayName = 'Svc'; Enabled = $true; LastLogonDate = $now.AddDays(-1); PasswordLastSet = $now.AddDays(-5); PasswordNeverExpires = $true; PasswordNotRequired = $false; ServicePrincipalNames = @('http/host'); TrustedForDelegation = $false; WhenCreated = $now.AddDays(-500); Description = '' }
            [pscustomobject]@{ SamAccountName = 'deleg.user'; DisplayName = 'Deleg'; Enabled = $true; LastLogonDate = $now.AddDays(-1); PasswordLastSet = $now.AddDays(-5); PasswordNeverExpires = $false; PasswordNotRequired = $false; ServicePrincipalNames = @(); TrustedForDelegation = $true; WhenCreated = $now.AddDays(-500); Description = '' }
            [pscustomobject]@{ SamAccountName = 'priv.inactive'; DisplayName = 'PrivInactive'; Enabled = $true; LastLogonDate = $now.AddDays(-120); PasswordLastSet = $now.AddDays(-5); PasswordNeverExpires = $false; PasswordNotRequired = $false; ServicePrincipalNames = @(); TrustedForDelegation = $false; WhenCreated = $now.AddDays(-500); Description = '' }
            [pscustomobject]@{ SamAccountName = 'priv.disabled'; DisplayName = 'PrivDisabled'; Enabled = $false; LastLogonDate = $now.AddDays(-10); PasswordLastSet = $now.AddDays(-5); PasswordNeverExpires = $false; PasswordNotRequired = $false; ServicePrincipalNames = @(); TrustedForDelegation = $false; WhenCreated = $now.AddDays(-500); Description = '' }
        )
        Computers = @(
            [pscustomobject]@{ Name = 'DC01'; Enabled = $true; LastLogonDate = $now.AddDays(-1); OperatingSystem = 'Windows Server 2022'; TrustedForDelegation = $true; IsDomainController = $true }
            [pscustomobject]@{ Name = 'SRV-DELEG'; Enabled = $true; LastLogonDate = $now.AddDays(-1); OperatingSystem = 'Windows Server 2019'; TrustedForDelegation = $true; IsDomainController = $false }
            [pscustomobject]@{ Name = 'WS-DORMANT'; Enabled = $true; LastLogonDate = $now.AddDays(-200); OperatingSystem = 'Windows 11'; TrustedForDelegation = $false; IsDomainController = $false }
            [pscustomobject]@{ Name = 'WS-OK'; Enabled = $true; LastLogonDate = $now.AddDays(-3); OperatingSystem = 'Windows 11'; TrustedForDelegation = $false; IsDomainController = $false }
        )
        Groups    = @(
            [pscustomobject]@{ Name = 'Domain Admins'; Members = @('priv.inactive', 'priv.disabled', 'active.user', 'svc.kerb', 'never.expires', 'old.pwd', 'no.pwd') }
            [pscustomobject]@{ Name = 'Enterprise Admins'; Members = @('active.user') }
        )
        Source    = 'Unit test dataset'
    }

    # Reach into the module scope to call the private check runner.
    $script:Results = & (Get-Module ADAuditToolkit) { param($d) Invoke-AuditChecks -Data $d } $script:TestData
    function Get-Check { param($id) $script:Results | Where-Object { $_.CheckId -eq $id } }
    function Get-Objects { param($id) (Get-Check $id).Findings | ForEach-Object { $_.ObjectName } }
}

Describe 'Invoke-AuditChecks' {
    It 'returns all ten checks' {
        @($script:Results).Count | Should -Be 10
    }

    It 'flags the stale user and not the active one' {
        Get-Objects 'STALE-USERS' | Should -Contain 'stale.user'
        Get-Objects 'STALE-USERS' | Should -Not -Contain 'active.user'
    }

    It 'flags password-never-expires accounts' {
        Get-Objects 'PWD-NEVER-EXPIRES' | Should -Contain 'never.expires'
    }

    It 'scores a privileged never-expires account as High' {
        $f = (Get-Check 'PWD-NEVER-EXPIRES').Findings | Where-Object { $_.ObjectName -eq 'never.expires' }
        $f.Severity | Should -Be 'High'
    }

    It 'flags password-not-required accounts as High' {
        $f = (Get-Check 'PWD-NOT-REQUIRED').Findings | Where-Object { $_.ObjectName -eq 'no.pwd' }
        $f.Severity | Should -Be 'High'
    }

    It 'flags aged passwords' {
        Get-Objects 'OLD-PASSWORDS' | Should -Contain 'old.pwd'
        Get-Objects 'OLD-PASSWORDS' | Should -Not -Contain 'active.user'
    }

    It 'flags oversized privileged groups' {
        Get-Objects 'PRIV-SPRAWL' | Should -Contain 'Domain Admins'
    }

    It 'flags inactive and disabled privileged members' {
        Get-Objects 'PRIV-INACTIVE' | Should -Contain 'priv.inactive'
        Get-Objects 'PRIV-INACTIVE' | Should -Contain 'priv.disabled'
    }

    It 'flags kerberoastable accounts' {
        Get-Objects 'KERBEROASTABLE' | Should -Contain 'svc.kerb'
    }

    It 'flags unconstrained delegation but excludes domain controllers' {
        Get-Objects 'UNCONSTRAINED-DELEG' | Should -Contain 'SRV-DELEG'
        Get-Objects 'UNCONSTRAINED-DELEG' | Should -Contain 'deleg.user'
        Get-Objects 'UNCONSTRAINED-DELEG' | Should -Not -Contain 'DC01'
    }

    It 'flags dormant computers but excludes active ones' {
        Get-Objects 'DORMANT-COMPUTERS' | Should -Contain 'WS-DORMANT'
        Get-Objects 'DORMANT-COMPUTERS' | Should -Not -Contain 'WS-OK'
    }

    It 'flags weak password policy including reversible encryption as High' {
        $findings = (Get-Check 'WEAK-PWD-POLICY').Findings
        $findings.Count | Should -BeGreaterThan 0
        ($findings | Where-Object { $_.Detail -match 'reversible' }).Severity | Should -Be 'High'
    }
}

Describe 'Nested group resolution' {
    It 'resolves nested privileged group membership' {
        $data = [pscustomobject]@{
            Groups = @(
                [pscustomobject]@{ Name = 'Domain Admins'; Members = @('outer.user', 'Nested') }
                [pscustomobject]@{ Name = 'Nested'; Members = @('inner.user') }
            )
        }
        $members = & (Get-Module ADAuditToolkit) { param($d) Get-ResolvedGroupMembers -Data $d -GroupName 'Domain Admins' } $data
        $members | Should -Contain 'outer.user'
        $members | Should -Contain 'inner.user'
    }
}

Describe 'HTML encoding' {
    It 'escapes angle brackets and ampersands' {
        $out = & (Get-Module ADAuditToolkit) { param($t) ConvertTo-HtmlEncoded $t } '<script>&"'
        $out | Should -Be '&lt;script&gt;&amp;&quot;'
    }
}

Describe 'Invoke-ADAudit demo mode' {
    It 'produces a report and findings from the shipped dataset' {
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) 'adaudit-test.html'
        $result = Invoke-ADAudit -Demo -OutputPath $tmp -PassThru
        Test-Path $tmp | Should -BeTrue
        $result.TotalFindings | Should -BeGreaterThan 0
        $result.Summary.Score | Should -BeGreaterOrEqual 0
        $result.Summary.Score | Should -BeLessOrEqual 100
        Remove-Item $tmp -ErrorAction SilentlyContinue
    }
}
