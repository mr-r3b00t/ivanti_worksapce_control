#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Enumerates the Ivanti Workspace Control (IWC) allow list configuration on the local machine.

.DESCRIPTION
    This script reads the local IWC agent cache, registry settings, and XML configuration
    objects to enumerate:
      - Authorized Files (file hash rules)
      - Authorized Certificates (certificate-based rules)
      - Authorized Owners (NTFS owner rules)
      - Blocked Paths
      - Security mode settings (Allow/Deny)
      - Agent cache status and metadata

.NOTES
    Must be run as Administrator to access Program Files cache and HKLM registry keys.
    Author:  Generated for IWC enumeration
    Version: 1.0
#>

[CmdletBinding()]
param(
    [switch]$ExportCsv,
    [string]$OutputPath = "$env:USERPROFILE\Desktop\IWC_AllowList_Report"
)

# ── Helpers ──────────────────────────────────────────────────────────────────

function Write-Section ([string]$Title) {
    $bar = '=' * 70
    Write-Host "`n$bar" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "$bar" -ForegroundColor Cyan
}

function Write-SubSection ([string]$Title) {
    Write-Host "`n  ── $Title ──" -ForegroundColor Yellow
}

# ── 1. Locate the Agent Cache ────────────────────────────────────────────────

Write-Section 'IWC Agent Cache Location'

$defaultCachePaths = @(
    (Join-Path $env:ProgramFiles 'Ivanti\Workspace Control\Data\DBCache'),
    (Join-Path ${env:ProgramFiles(x86)} 'Ivanti\Workspace Control\Data\DBCache')
)

$regPaths = @(
    'HKLM:\SOFTWARE\WOW6432Node\RES\Workspace Manager',
    'HKLM:\SOFTWARE\RES\Workspace Manager'
)

$cachePath = $null

# First, try the registry for a custom cache path
foreach ($rp in $regPaths) {
    try {
        $val = (Get-ItemProperty -Path $rp -Name LocalCachePath -ErrorAction Stop).LocalCachePath
        if ($val -and (Test-Path $val)) {
            $cachePath = $val
            Write-Host "  Cache path (from registry): $cachePath" -ForegroundColor Green
            break
        }
    } catch { }
}

# Fall back to default locations: Program Files and Program Files (x86)
if (-not $cachePath) {
    foreach ($dp in $defaultCachePaths) {
        if ($dp -and (Test-Path $dp)) {
            $cachePath = $dp
            Write-Host "  Cache path (default):       $cachePath" -ForegroundColor Green
            break
        }
    }
}

if (-not $cachePath) {
    Write-Host "  [!] Could not locate the IWC agent cache. Is Workspace Control installed?" -ForegroundColor Red
    Write-Host "      Checked:" -ForegroundColor Red
    foreach ($dp in $defaultCachePaths) { Write-Host "        - $dp" -ForegroundColor Red }
    exit 1
}

# Cache size
try {
    $cacheSize = '{0:N2} MB' -f ((Get-ChildItem $cachePath -Recurse -ErrorAction Stop |
        Measure-Object -Property Length -Sum).Sum / 1MB)
    Write-Host "  Cache size:                 $cacheSize"
} catch {
    Write-Host "  Cache size:                 Unable to calculate" -ForegroundColor DarkYellow
}

# Transaction backlog
$txPath = Join-Path $cachePath 'Transactions'
if (Test-Path $txPath) {
    $txCount = (Get-ChildItem $txPath -File -ErrorAction SilentlyContinue | Measure-Object).Count
    Write-Host "  Pending transactions:       $txCount"
}

# ── 2. Registry-based Security Settings ──────────────────────────────────────

Write-Section 'Registry Security Settings'

$settingsKeys = @(
    'HKLM:\SOFTWARE\Policies\RES\Workspace Manager\Settings',
    'HKLM:\SOFTWARE\WOW6432Node\Policies\RES\Workspace Manager\Settings',
    'HKLM:\SOFTWARE\RES\Workspace Manager',
    'HKLM:\SOFTWARE\WOW6432Node\RES\Workspace Manager'
)

# Keywords that relate to security / allow-list features
$securityKeywords = @(
    'Security', 'Whitelist', 'Allowlist', 'Blacklist', 'DenyList',
    'AuthorizedOwner', 'AuthorizedCert', 'CertSec', 'AppGuard',
    'ManagedApp', 'MemoryShield', 'FileHash', 'Blocked', 'Learning'
)

$registryFindings = [System.Collections.ArrayList]::new()

foreach ($key in $settingsKeys) {
    if (-not (Test-Path $key)) { continue }

    Write-SubSection "Key: $key"
    try {
        $props = Get-ItemProperty -Path $key -ErrorAction Stop
        $props.PSObject.Properties | Where-Object {
            $_.Name -notmatch '^PS' # skip PowerShell metadata properties
        } | ForEach-Object {
            $name  = $_.Name
            $value = $_.Value

            # Highlight security-related values
            $isSecurityRelated = $false
            foreach ($kw in $securityKeywords) {
                if ($name -match $kw) { $isSecurityRelated = $true; break }
            }

            $colour = if ($isSecurityRelated) { 'Green' } else { 'Gray' }
            Write-Host ("    {0,-45} = {1}" -f $name, $value) -ForegroundColor $colour

            [void]$registryFindings.Add([PSCustomObject]@{
                RegistryKey = $key
                Name        = $name
                Value       = $value
                SecurityRelated = $isSecurityRelated
            })
        }
    } catch {
        Write-Host "    [!] Unable to read: $_" -ForegroundColor Red
    }

    # Enumerate sub-keys (security settings are sometimes nested)
    Get-ChildItem -Path $key -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Host "    Sub-key: $($_.PSChildName)" -ForegroundColor DarkCyan
        try {
            $subProps = Get-ItemProperty -Path $_.PSPath -ErrorAction Stop
            $subProps.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                Write-Host ("      {0,-43} = {1}" -f $_.Name, $_.Value) -ForegroundColor Gray
                [void]$registryFindings.Add([PSCustomObject]@{
                    RegistryKey = $_.PSPath
                    Name        = $_.Name
                    Value       = $_.Value
                    SecurityRelated = $false
                })
            }
        } catch { }
    }
}

# Also check HKCU for per-user overrides
$hkcuKey = 'HKCU:\Software\Policies\RES\Workspace Manager\Settings'
if (Test-Path $hkcuKey) {
    Write-SubSection "Per-User Overrides: $hkcuKey"
    Get-ItemProperty -Path $hkcuKey -ErrorAction SilentlyContinue |
        ForEach-Object { $_.PSObject.Properties } |
        Where-Object { $_.Name -notmatch '^PS' } |
        ForEach-Object {
            Write-Host ("    {0,-45} = {1}" -f $_.Name, $_.Value) -ForegroundColor Magenta
        }
} else {
    Write-Host "`n  No per-user overrides found at $hkcuKey" -ForegroundColor DarkGray
}

# ── 3. Parse XML Objects in the Cache ────────────────────────────────────────

Write-Section 'Cached Configuration Objects (XML)'

$objectsPath = Join-Path $cachePath 'Objects'
$xmlFiles    = @()

if (Test-Path $objectsPath) {
    $xmlFiles = Get-ChildItem -Path $objectsPath -Filter '*.xml' -Recurse -ErrorAction SilentlyContinue
    Write-Host "  Total XML config objects found: $($xmlFiles.Count)"
} else {
    Write-Host "  [!] Objects folder not found at $objectsPath" -ForegroundColor Red
}

# Scan XML files for security / allow-list related content
$authorizedFiles   = [System.Collections.ArrayList]::new()
$authorizedCerts   = [System.Collections.ArrayList]::new()
$authorizedOwners  = [System.Collections.ArrayList]::new()
$blockedPaths      = [System.Collections.ArrayList]::new()
$securityConfigs   = [System.Collections.ArrayList]::new()

# ── NEW: Collect all allowed executable paths & folders ──
$allowedExePaths   = [System.Collections.ArrayList]::new()
$allowedExeFolders = [System.Collections.ArrayList]::new()

# Regex to catch file paths ending in .exe, .com, .msi, .bat, .cmd, .ps1
$exePathRegex = '(?i)([a-z]:\\[^<>"|\r\n*?]+\.(?:exe|com|msi|bat|cmd|ps1|vbs|wsf))'
# Regex to catch folder-only paths (e.g. path-based allow rules)
$folderPathRegex = '(?i)([a-z]:\\(?:[^<>"|\r\n*?]+\\))'
# Regex for UNC paths
$uncPathRegex = '(?i)(\\\\[^<>"|\r\n*?]+\.(?:exe|com|msi|bat|cmd|ps1|vbs|wsf))'
$uncFolderRegex = '(?i)(\\\\[^<>"|\r\n*?]+\\)'
# Regex for paths with environment variables
$envPathRegex = '(?i)(%[a-z_()]+%\\[^<>"|\r\n*?]+)'

foreach ($xmlFile in $xmlFiles) {
    try {
        [xml]$xml = Get-Content -Path $xmlFile.FullName -ErrorAction Stop

        # Convert to string for keyword scanning
        $content = $xml.OuterXml

        # ──────────────────────────────────────────────────────────────
        # Extract ALL executable paths from every XML (apps, security)
        # ──────────────────────────────────────────────────────────────

        # 1) Search ALL attributes and text nodes for .exe paths
        $allNodes = $xml.SelectNodes('//*')
        foreach ($node in $allNodes) {
            # Check attributes
            foreach ($attr in $node.Attributes) {
                $val = $attr.Value
                # Full exe paths
                foreach ($match in [regex]::Matches($val, $exePathRegex)) {
                    [void]$allowedExePaths.Add([PSCustomObject]@{
                        Path        = $match.Value
                        Folder      = [System.IO.Path]::GetDirectoryName($match.Value)
                        FileName    = [System.IO.Path]::GetFileName($match.Value)
                        Source      = 'XMLAttribute'
                        Attribute   = $attr.Name
                        NodeName    = $node.LocalName
                        ConfigFile  = $xmlFile.Name
                    })
                }
                # UNC exe paths
                foreach ($match in [regex]::Matches($val, $uncPathRegex)) {
                    [void]$allowedExePaths.Add([PSCustomObject]@{
                        Path        = $match.Value
                        Folder      = [System.IO.Path]::GetDirectoryName($match.Value)
                        FileName    = [System.IO.Path]::GetFileName($match.Value)
                        Source      = 'XMLAttribute (UNC)'
                        Attribute   = $attr.Name
                        NodeName    = $node.LocalName
                        ConfigFile  = $xmlFile.Name
                    })
                }
                # Env var paths
                foreach ($match in [regex]::Matches($val, $envPathRegex)) {
                    $mval = $match.Value
                    $fname = if ($mval -match '\\([^\\]+)$') { $Matches[1] } else { '' }
                    $fdir  = if ($fname) { $mval.Replace("\$fname", '') } else { $mval }
                    [void]$allowedExePaths.Add([PSCustomObject]@{
                        Path        = $mval
                        Folder      = $fdir
                        FileName    = $fname
                        Source      = 'XMLAttribute (EnvVar)'
                        Attribute   = $attr.Name
                        NodeName    = $node.LocalName
                        ConfigFile  = $xmlFile.Name
                    })
                }
            }

            # Check inner text (non-child text content)
            if ($node.HasChildNodes -eq $false -and $node.InnerText) {
                $txt = $node.InnerText
                foreach ($match in [regex]::Matches($txt, $exePathRegex)) {
                    [void]$allowedExePaths.Add([PSCustomObject]@{
                        Path        = $match.Value
                        Folder      = [System.IO.Path]::GetDirectoryName($match.Value)
                        FileName    = [System.IO.Path]::GetFileName($match.Value)
                        Source      = 'XMLText'
                        Attribute   = ''
                        NodeName    = $node.LocalName
                        ConfigFile  = $xmlFile.Name
                    })
                }
                foreach ($match in [regex]::Matches($txt, $uncPathRegex)) {
                    [void]$allowedExePaths.Add([PSCustomObject]@{
                        Path        = $match.Value
                        Folder      = [System.IO.Path]::GetDirectoryName($match.Value)
                        FileName    = [System.IO.Path]::GetFileName($match.Value)
                        Source      = 'XMLText (UNC)'
                        Attribute   = ''
                        NodeName    = $node.LocalName
                        ConfigFile  = $xmlFile.Name
                    })
                }
                foreach ($match in [regex]::Matches($txt, $envPathRegex)) {
                    $mval = $match.Value
                    $fname = if ($mval -match '\\([^\\]+)$') { $Matches[1] } else { '' }
                    $fdir  = if ($fname) { $mval.Replace("\$fname", '') } else { $mval }
                    [void]$allowedExePaths.Add([PSCustomObject]@{
                        Path        = $mval
                        Folder      = $fdir
                        FileName    = $fname
                        Source      = 'XMLText (EnvVar)'
                        Attribute   = ''
                        NodeName    = $node.LocalName
                        ConfigFile  = $xmlFile.Name
                    })
                }
            }
        }

        # 2) Also do a raw string scan for anything the node walk missed
        foreach ($match in [regex]::Matches($content, $exePathRegex)) {
            # Deduplicate later — just collect
            [void]$allowedExeFolders.Add($match.Value)
        }
        foreach ($match in [regex]::Matches($content, $uncPathRegex)) {
            [void]$allowedExeFolders.Add($match.Value)
        }
        foreach ($match in [regex]::Matches($content, $envPathRegex)) {
            [void]$allowedExeFolders.Add($match.Value)
        }

        # ──────────────────────────────────────────────────────────────
        # Original security rule detection
        # ──────────────────────────────────────────────────────────────

        # ── Authorized Files / Hashes
        if ($content -match 'authorizedfile|filehash|allowedfile|hashvalue') {
            $secNodes = $xml.SelectNodes('//*[contains(local-name(),"AuthorizedFile") or contains(local-name(),"FileHash") or contains(local-name(),"AllowedFile")]')
            if ($secNodes -and $secNodes.Count -gt 0) {
                foreach ($node in $secNodes) {
                    [void]$authorizedFiles.Add([PSCustomObject]@{
                        SourceFile  = $xmlFile.Name
                        NodeName    = $node.LocalName
                        InnerXml    = $node.OuterXml.Substring(0, [Math]::Min(500, $node.OuterXml.Length))
                    })
                }
            } else {
                [void]$authorizedFiles.Add([PSCustomObject]@{
                    SourceFile = $xmlFile.Name
                    NodeName   = '(keyword match)'
                    InnerXml   = ''
                })
            }
        }

        # ── Authorized Certificates
        if ($content -match 'authorizedcert|certsec|certificate.*security') {
            $secNodes = $xml.SelectNodes('//*[contains(local-name(),"Certificate") or contains(local-name(),"CertSec")]')
            if ($secNodes -and $secNodes.Count -gt 0) {
                foreach ($node in $secNodes) {
                    [void]$authorizedCerts.Add([PSCustomObject]@{
                        SourceFile = $xmlFile.Name
                        NodeName   = $node.LocalName
                        Publisher  = $node.GetAttribute('Publisher')
                        Product    = $node.GetAttribute('ProductName')
                        InnerXml   = $node.OuterXml.Substring(0, [Math]::Min(500, $node.OuterXml.Length))
                    })
                }
            } else {
                [void]$authorizedCerts.Add([PSCustomObject]@{
                    SourceFile = $xmlFile.Name
                    NodeName   = '(keyword match)'
                    Publisher  = ''
                    Product    = ''
                    InnerXml   = ''
                })
            }
        }

        # ── Authorized Owners
        if ($content -match 'authorizedowner|ntfsowner|trustedowner') {
            [void]$authorizedOwners.Add([PSCustomObject]@{
                SourceFile = $xmlFile.Name
                Detail     = 'Authorized Owners configuration detected'
            })
        }

        # ── Blocked Paths
        if ($content -match 'blockedpath|blockpath|denypath') {
            [void]$blockedPaths.Add([PSCustomObject]@{
                SourceFile = $xmlFile.Name
                Detail     = 'Blocked Paths configuration detected'
            })
        }

        # ── General security settings
        if ($content -match 'securitymode|whitelistmode|allowmode|learningmode|appguard') {
            [void]$securityConfigs.Add([PSCustomObject]@{
                SourceFile = $xmlFile.Name
                Detail     = 'Security mode / AppGuard configuration detected'
            })
        }

    } catch {
        # Skip unparseable files silently
    }
}

# ══════════════════════════════════════════════════════════════════════════════
# ── Display: Allowed Executable Paths & Folders ──────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

Write-Section 'Allowed Executable Paths (Where an EXE Can Run From)'

# Deduplicate the structured results
$uniqueExePaths = $allowedExePaths |
    Sort-Object -Property Path -Unique

# Build a deduplicated folder list
$allFolders = @()
$allFolders += $allowedExePaths | ForEach-Object { $_.Folder } | Where-Object { $_ }
$allFolders += $allowedExeFolders | ForEach-Object {
    try { [System.IO.Path]::GetDirectoryName($_) } catch { $_ }
} | Where-Object { $_ }
$uniqueFolders = $allFolders | Sort-Object -Unique

Write-SubSection "Individual Allowed Executables ($($uniqueExePaths.Count) found)"
if ($uniqueExePaths.Count -gt 0) {
    $uniqueExePaths | ForEach-Object {
        $icon = switch -Regex ($_.Source) {
            'EnvVar' { '[ENV]' }
            'UNC'    { '[UNC]' }
            default  { '[LOC]' }
        }
        Write-Host ("    $icon {0}" -f $_.Path) -ForegroundColor Green
        Write-Host ("         Node: {0}  |  Attr: {1}  |  Config: {2}" -f $_.NodeName, $_.Attribute, $_.ConfigFile) -ForegroundColor DarkGray
    }
} else {
    Write-Host "    None found in local cache" -ForegroundColor DarkGray
}

Write-SubSection "Unique Allowed Folders ($($uniqueFolders.Count) found)"
if ($uniqueFolders.Count -gt 0) {
    Write-Host ""
    $uniqueFolders | ForEach-Object {
        Write-Host "    $_" -ForegroundColor Green
    }
    Write-Host ""
    Write-Host "    These are the directories from which executables are configured to run." -ForegroundColor DarkGray
} else {
    Write-Host "    None found in local cache" -ForegroundColor DarkGray
}

# ══════════════════════════════════════════════════════════════════════════════
# ── Display: Original Security Rule Results ──────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

Write-Section 'Security Rules Detail'

Write-SubSection "Authorized Files / Hashes"
if ($authorizedFiles.Count -gt 0) {
    $authorizedFiles | ForEach-Object {
        Write-Host "    File: $($_.SourceFile)  |  Node: $($_.NodeName)" -ForegroundColor Green
    }
} else {
    Write-Host "    None found in local cache" -ForegroundColor DarkGray
}

Write-SubSection "Authorized Certificates"
if ($authorizedCerts.Count -gt 0) {
    $authorizedCerts | ForEach-Object {
        $extra = if ($_.Publisher) { " | Publisher: $($_.Publisher), Product: $($_.Product)" } else { '' }
        Write-Host "    File: $($_.SourceFile)  |  Node: $($_.NodeName)$extra" -ForegroundColor Green
    }
} else {
    Write-Host "    None found in local cache" -ForegroundColor DarkGray
}

Write-SubSection "Authorized Owners"
if ($authorizedOwners.Count -gt 0) {
    $authorizedOwners | ForEach-Object { Write-Host "    $($_.SourceFile): $($_.Detail)" -ForegroundColor Green }
} else {
    Write-Host "    None found in local cache" -ForegroundColor DarkGray
}

Write-SubSection "Blocked Paths"
if ($blockedPaths.Count -gt 0) {
    $blockedPaths | ForEach-Object { Write-Host "    $($_.SourceFile): $($_.Detail)" -ForegroundColor Green }
} else {
    Write-Host "    None found in local cache" -ForegroundColor DarkGray
}

Write-SubSection "Security Mode / AppGuard Config"
if ($securityConfigs.Count -gt 0) {
    $securityConfigs | ForEach-Object { Write-Host "    $($_.SourceFile): $($_.Detail)" -ForegroundColor Green }
} else {
    Write-Host "    None found in local cache" -ForegroundColor DarkGray
}

# ── 4. Installed IWC Components ──────────────────────────────────────────────

Write-Section 'Installed Workspace Control Components'

$iwcInstallPaths = @(
    (Join-Path $env:ProgramFiles 'Ivanti\Workspace Control'),
    (Join-Path ${env:ProgramFiles(x86)} 'Ivanti\Workspace Control')
)

$foundInstall = $false
foreach ($iwcInstallPath in $iwcInstallPaths) {
    if (Test-Path $iwcInstallPath) {
        $foundInstall = $true
        $exes = Get-ChildItem -Path $iwcInstallPath -Filter '*.exe' -ErrorAction SilentlyContinue
        Write-Host "  Install path: $iwcInstallPath"
        Write-Host "  Executables found: $($exes.Count)"
        $exes | ForEach-Object {
            $ver = $_.VersionInfo.ProductVersion
            Write-Host ("    {0,-30} v{1}" -f $_.Name, $ver)
        }
    }
}

if (-not $foundInstall) {
    Write-Host "  [!] IWC install directory not found at:" -ForegroundColor Red
    foreach ($p in $iwcInstallPaths) { Write-Host "        - $p" -ForegroundColor Red }
}

# ── 5. Export (optional) ─────────────────────────────────────────────────────

if ($ExportCsv) {
    Write-Section 'Exporting to CSV'

    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    if ($registryFindings.Count -gt 0) {
        $regFile = Join-Path $OutputPath 'RegistrySettings.csv'
        $registryFindings | Export-Csv -Path $regFile -NoTypeInformation
        Write-Host "  Registry settings     -> $regFile" -ForegroundColor Green
    }

    if ($uniqueExePaths.Count -gt 0) {
        $epFile = Join-Path $OutputPath 'AllowedExePaths.csv'
        $uniqueExePaths | Export-Csv -Path $epFile -NoTypeInformation
        Write-Host "  Allowed exe paths     -> $epFile" -ForegroundColor Green
    }

    if ($uniqueFolders.Count -gt 0) {
        $efFile = Join-Path $OutputPath 'AllowedExeFolders.csv'
        $uniqueFolders | ForEach-Object { [PSCustomObject]@{ FolderPath = $_ } } |
            Export-Csv -Path $efFile -NoTypeInformation
        Write-Host "  Allowed exe folders   -> $efFile" -ForegroundColor Green
    }

    if ($authorizedFiles.Count -gt 0) {
        $afFile = Join-Path $OutputPath 'AuthorizedFiles.csv'
        $authorizedFiles | Export-Csv -Path $afFile -NoTypeInformation
        Write-Host "  Authorized files      -> $afFile" -ForegroundColor Green
    }

    if ($authorizedCerts.Count -gt 0) {
        $acFile = Join-Path $OutputPath 'AuthorizedCerts.csv'
        $authorizedCerts | Export-Csv -Path $acFile -NoTypeInformation
        Write-Host "  Authorized certs      -> $acFile" -ForegroundColor Green
    }

    Write-Host "`n  Export complete." -ForegroundColor Cyan
}

# ── Summary ──────────────────────────────────────────────────────────────────

Write-Section 'Summary'
Write-Host "  Cache location:          $cachePath"
Write-Host "  Registry values found:   $($registryFindings.Count)"
Write-Host "  XML config objects:      $($xmlFiles.Count)"
Write-Host ""
Write-Host "  Allowed exe paths:       $($uniqueExePaths.Count)" -ForegroundColor White
Write-Host "  Allowed exe folders:     $($uniqueFolders.Count)" -ForegroundColor White
Write-Host ""
Write-Host "  Authorized file rules:   $($authorizedFiles.Count)"
Write-Host "  Authorized cert rules:   $($authorizedCerts.Count)"
Write-Host "  Authorized owner rules:  $($authorizedOwners.Count)"
Write-Host "  Blocked path rules:      $($blockedPaths.Count)"
Write-Host "  Security config entries: $($securityConfigs.Count)"
Write-Host ""
Write-Host "  Tip: Run with -ExportCsv to save results to CSV files." -ForegroundColor DarkGray
Write-Host "       e.g. .\Get-IWCAllowListConfig.ps1 -ExportCsv" -ForegroundColor DarkGray
Write-Host ""
