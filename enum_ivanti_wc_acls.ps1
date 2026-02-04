#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Enumerates the Ivanti Workspace Control (IWC) allow list configuration and audits
    NTFS permissions to find paths a standard user could hijack.

.DESCRIPTION
    This script reads the local IWC agent cache, registry settings, and XML configuration
    objects to enumerate:
      - Authorized Files (file hash rules)
      - Authorized Certificates (certificate-based rules)
      - Authorized Owners (NTFS owner rules)
      - Blocked Paths
      - Security mode settings (Allow/Deny)
      - Agent cache status and metadata
      - All executable paths and folders from which EXEs are allowed to run

    It then performs an NTFS ACL audit on every discovered path, checking whether
    standard user groups (Users, Everyone, Authenticated Users, INTERACTIVE) have
    Write, Modify, CreateFiles, or FullControl permissions. Any writable path is
    flagged as a potential privilege escalation / exe hijack vulnerability.

.NOTES
    Must be run as Administrator to access Program Files cache and HKLM registry keys.
    Author:  Generated for IWC enumeration
    Version: 2.0
#>

[CmdletBinding()]
param(
    [switch]$ExportCsv,
    [string]$OutputPath = "$env:USERPROFILE\Desktop\IWC_AllowList_Report"
)

# -- Helpers ------------------------------------------------------------------

function Write-Section ([string]$Title) {
    $bar = '=' * 70
    Write-Host "`n$bar" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "$bar" -ForegroundColor Cyan
}

function Write-SubSection ([string]$Title) {
    Write-Host "`n  -- $Title --" -ForegroundColor Yellow
}

# -- ACL Check Helpers --------------------------------------------------------

# SIDs / identity references that represent a standard (non-admin) user
$script:UserWriteSIDs = @(
    'S-1-1-0'          # Everyone
    'S-1-5-4'          # INTERACTIVE
    'S-1-5-11'         # Authenticated Users
    'S-1-5-32-545'     # BUILTIN\Users
)
$script:UserWriteNames = @(
    'Everyone',
    'INTERACTIVE',
    'Authenticated Users',
    'BUILTIN\Users',
    'Users'
)

# File permissions that allow overwriting an exe
$script:DangerousFileRights = @(
    [System.Security.AccessControl.FileSystemRights]::Write
    [System.Security.AccessControl.FileSystemRights]::Modify
    [System.Security.AccessControl.FileSystemRights]::FullControl
    [System.Security.AccessControl.FileSystemRights]::WriteData
    [System.Security.AccessControl.FileSystemRights]::AppendData
)

# Folder permissions that allow creating/writing a new file
$script:DangerousFolderRights = @(
    [System.Security.AccessControl.FileSystemRights]::Write
    [System.Security.AccessControl.FileSystemRights]::Modify
    [System.Security.AccessControl.FileSystemRights]::FullControl
    [System.Security.AccessControl.FileSystemRights]::CreateFiles
    [System.Security.AccessControl.FileSystemRights]::WriteData
    [System.Security.AccessControl.FileSystemRights]::AppendData
)

function Resolve-EnvPath ([string]$PathString) {
    <# Expand %ENV_VAR% references and return the resolved path #>
    try {
        return [System.Environment]::ExpandEnvironmentVariables($PathString)
    } catch {
        return $PathString
    }
}

function Test-IdentityIsStandardUser ([System.Security.AccessControl.FileSystemAccessRule]$Ace) {
    <# Returns $true if the ACE identity matches a standard user group #>
    $identity = $Ace.IdentityReference.Value

    # Check by well-known name
    foreach ($name in $script:UserWriteNames) {
        if ($identity -like "*$name*") { return $true }
    }

    # Check by SID
    try {
        $sid = $Ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
        if ($sid -in $script:UserWriteSIDs) { return $true }
    } catch { }

    return $false
}

function Test-UserCanWriteFile ([string]$FilePath) {
    <#
    .SYNOPSIS
        Checks if a standard user can overwrite the file at $FilePath.
    .OUTPUTS
        PSCustomObject with: Writable, Exists, Permissions (list of risky ACEs), Path
    #>
    $result = [PSCustomObject]@{
        Path           = $FilePath
        Type           = 'File'
        Exists         = $false
        Writable       = $false
        Risk           = 'N/A'
        DangerousAces  = [System.Collections.ArrayList]::new()
        Owner          = ''
        Notes          = ''
    }

    $resolved = Resolve-EnvPath $FilePath
    $result.Path = $resolved

    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        # File doesn't exist -- check if the PARENT FOLDER is writable
        # (user could create the file)
        $parentDir = Split-Path $resolved -Parent
        if ($parentDir -and (Test-Path -LiteralPath $parentDir -PathType Container)) {
            $folderResult = Test-UserCanWriteFolder $parentDir
            $result.Exists  = $false
            $result.Writable = $folderResult.Writable
            $result.Risk     = if ($folderResult.Writable) { 'HIGH - File missing, parent folder writable -- user can create it' } else { 'OK - File missing, parent folder protected' }
            $result.DangerousAces = $folderResult.DangerousAces
            $result.Owner    = $folderResult.Owner
            $result.Notes    = "File does not exist. Checked parent: $parentDir"
        } else {
            $result.Notes = "File and parent folder do not exist: $resolved"
            $result.Risk  = 'UNKNOWN - Path not found'
        }
        return $result
    }

    $result.Exists = $true

    try {
        $acl = Get-Acl -LiteralPath $resolved -ErrorAction Stop
        $result.Owner = $acl.Owner

        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            if (-not (Test-IdentityIsStandardUser $ace)) { continue }

            # Check if any dangerous rights are granted
            foreach ($right in $script:DangerousFileRights) {
                if ($ace.FileSystemRights -band $right) {
                    [void]$result.DangerousAces.Add([PSCustomObject]@{
                        Identity = $ace.IdentityReference.Value
                        Rights   = $ace.FileSystemRights.ToString()
                        Inherited = $ace.IsInherited
                    })
                    $result.Writable = $true
                    break
                }
            }
        }

        $result.Risk = if ($result.Writable) {
            'HIGH - Standard user can overwrite this executable'
        } else {
            'OK - Protected'
        }
    } catch {
        $result.Notes = "ACL read error: $_"
        $result.Risk  = 'ERROR - Could not read ACL'
    }

    return $result
}

function Test-UserCanWriteFolder ([string]$FolderPath) {
    <#
    .SYNOPSIS
        Checks if a standard user can create/write files in $FolderPath.
    .OUTPUTS
        PSCustomObject with: Writable, Exists, Permissions (list of risky ACEs), Path
    #>
    $result = [PSCustomObject]@{
        Path           = $FolderPath
        Type           = 'Folder'
        Exists         = $false
        Writable       = $false
        Risk           = 'N/A'
        DangerousAces  = [System.Collections.ArrayList]::new()
        Owner          = ''
        Notes          = ''
    }

    $resolved = Resolve-EnvPath $FolderPath
    $result.Path = $resolved

    if (-not (Test-Path -LiteralPath $resolved -PathType Container)) {
        # Folder doesn't exist -- walk up to find nearest existing parent
        $checkDir = $resolved
        while ($checkDir -and -not (Test-Path -LiteralPath $checkDir -PathType Container)) {
            $checkDir = Split-Path $checkDir -Parent
        }
        if ($checkDir -and (Test-Path -LiteralPath $checkDir -PathType Container)) {
            $result.Notes = "Folder missing. Nearest existing parent: $checkDir"
            $resolved = $checkDir
        } else {
            $result.Notes = "Folder and all parents missing: $resolved"
            $result.Risk  = 'UNKNOWN - Path not found'
            return $result
        }
    }

    $result.Exists = $true

    try {
        $acl = Get-Acl -LiteralPath $resolved -ErrorAction Stop
        $result.Owner = $acl.Owner

        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            if (-not (Test-IdentityIsStandardUser $ace)) { continue }

            foreach ($right in $script:DangerousFolderRights) {
                if ($ace.FileSystemRights -band $right) {
                    [void]$result.DangerousAces.Add([PSCustomObject]@{
                        Identity  = $ace.IdentityReference.Value
                        Rights    = $ace.FileSystemRights.ToString()
                        Inherited = $ace.IsInherited
                    })
                    $result.Writable = $true
                    break
                }
            }
        }

        $result.Risk = if ($result.Writable) {
            'HIGH - Standard user can write files to this folder'
        } else {
            'OK - Protected'
        }
    } catch {
        $result.Notes = "ACL read error: $_"
        $result.Risk  = 'ERROR - Could not read ACL'
    }

    return $result
}

# -- 1. Locate the Agent Cache ------------------------------------------------

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

# -- 2. Registry-based Security Settings --------------------------------------

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

# -- 3. Parse XML Objects in the Cache ----------------------------------------

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

# -- NEW: Collect all allowed executable paths & folders --
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

        # --------------------------------------------------------------
        # Extract ALL executable paths from every XML (apps, security)
        # --------------------------------------------------------------

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
            # Deduplicate later -- just collect
            [void]$allowedExeFolders.Add($match.Value)
        }
        foreach ($match in [regex]::Matches($content, $uncPathRegex)) {
            [void]$allowedExeFolders.Add($match.Value)
        }
        foreach ($match in [regex]::Matches($content, $envPathRegex)) {
            [void]$allowedExeFolders.Add($match.Value)
        }

        # --------------------------------------------------------------
        # Original security rule detection
        # --------------------------------------------------------------

        # -- Authorized Files / Hashes
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

        # -- Authorized Certificates
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

        # -- Authorized Owners
        if ($content -match 'authorizedowner|ntfsowner|trustedowner') {
            [void]$authorizedOwners.Add([PSCustomObject]@{
                SourceFile = $xmlFile.Name
                Detail     = 'Authorized Owners configuration detected'
            })
        }

        # -- Blocked Paths
        if ($content -match 'blockedpath|blockpath|denypath') {
            [void]$blockedPaths.Add([PSCustomObject]@{
                SourceFile = $xmlFile.Name
                Detail     = 'Blocked Paths configuration detected'
            })
        }

        # -- General security settings
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

# ==============================================================================
# -- ACL Audit: Check Write Permissions on Allowed Paths ----------------------
# ==============================================================================

Write-Section 'Permission Audit -- Can a Standard User Overwrite Allowed EXEs?'

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

# -- Audit individual exe files -----------------------------------------------

Write-SubSection "Checking Individual Executables ($($uniqueExePaths.Count) paths)"

$fileAuditResults  = [System.Collections.ArrayList]::new()
$vulnerableFiles   = [System.Collections.ArrayList]::new()

$counter = 0
foreach ($exeEntry in $uniqueExePaths) {
    $counter++
    Write-Progress -Activity 'Auditing executable permissions' -Status $exeEntry.Path -PercentComplete (($counter / [Math]::Max($uniqueExePaths.Count,1)) * 100)

    $auditResult = Test-UserCanWriteFile $exeEntry.Path

    # Attach source metadata
    $auditResult | Add-Member -NotePropertyName 'ConfigFile'  -NotePropertyValue $exeEntry.ConfigFile -Force
    $auditResult | Add-Member -NotePropertyName 'NodeName'    -NotePropertyValue $exeEntry.NodeName   -Force
    $auditResult | Add-Member -NotePropertyName 'OrigPath'    -NotePropertyValue $exeEntry.Path       -Force

    [void]$fileAuditResults.Add($auditResult)

    if ($auditResult.Writable) {
        [void]$vulnerableFiles.Add($auditResult)
    }

    # Display
    $icon = if ($auditResult.Writable) { '[!!]' } else { '[OK]' }
    $colour = if ($auditResult.Writable) { 'Red' } else { 'Green' }

    Write-Host ("    $icon {0}" -f $auditResult.Path) -ForegroundColor $colour
    if ($auditResult.Writable) {
        Write-Host "         RISK: $($auditResult.Risk)" -ForegroundColor Red
        foreach ($ace in $auditResult.DangerousAces) {
            $inhText = if ($ace.Inherited) { '(inherited)' } else { '(explicit)' }
            Write-Host "           -> $($ace.Identity): $($ace.Rights) $inhText" -ForegroundColor Yellow
        }
    }
    if ($auditResult.Notes) {
        Write-Host "         Note: $($auditResult.Notes)" -ForegroundColor DarkGray
    }
}
Write-Progress -Activity 'Auditing executable permissions' -Completed

# -- Audit folders ------------------------------------------------------------

Write-SubSection "Checking Allowed Folders ($($uniqueFolders.Count) folders)"

$folderAuditResults  = [System.Collections.ArrayList]::new()
$vulnerableFolders   = [System.Collections.ArrayList]::new()

$counter = 0
foreach ($folder in $uniqueFolders) {
    $counter++
    Write-Progress -Activity 'Auditing folder permissions' -Status $folder -PercentComplete (($counter / [Math]::Max($uniqueFolders.Count,1)) * 100)

    $auditResult = Test-UserCanWriteFolder $folder

    [void]$folderAuditResults.Add($auditResult)

    if ($auditResult.Writable) {
        [void]$vulnerableFolders.Add($auditResult)
    }

    # Display
    $icon = if ($auditResult.Writable) { '[!!]' } else { '[OK]' }
    $colour = if ($auditResult.Writable) { 'Red' } else { 'Green' }

    Write-Host ("    $icon {0}" -f $auditResult.Path) -ForegroundColor $colour
    Write-Host ("         Owner: {0}" -f $(if ($auditResult.Owner) { $auditResult.Owner } else { 'N/A' })) -ForegroundColor DarkGray
    if ($auditResult.Writable) {
        Write-Host "         RISK: $($auditResult.Risk)" -ForegroundColor Red
        foreach ($ace in $auditResult.DangerousAces) {
            $inhText = if ($ace.Inherited) { '(inherited)' } else { '(explicit)' }
            Write-Host "           -> $($ace.Identity): $($ace.Rights) $inhText" -ForegroundColor Yellow
        }
    }
    if ($auditResult.Notes) {
        Write-Host "         Note: $($auditResult.Notes)" -ForegroundColor DarkGray
    }
}
Write-Progress -Activity 'Auditing folder permissions' -Completed

# ==============================================================================
# -- VULNERABILITY REPORT -----------------------------------------------------
# ==============================================================================

Write-Section '[!]  VULNERABILITY REPORT -- User-Writable Allowed Paths'

if ($vulnerableFiles.Count -eq 0 -and $vulnerableFolders.Count -eq 0) {
    Write-Host ""
    Write-Host "  [OK] No user-writable paths found. All allowed paths appear protected." -ForegroundColor Green
    Write-Host ""
} else {
    $totalVulns = $vulnerableFiles.Count + $vulnerableFolders.Count
    Write-Host ""
    Write-Host "  +==================================================================+" -ForegroundColor Red
    Write-Host "  |  $totalVulns VULNERABLE PATH(S) FOUND                                     |" -ForegroundColor Red
    Write-Host "  |  A standard user could potentially hijack allowed executables.  |" -ForegroundColor Red
    Write-Host "  +==================================================================+" -ForegroundColor Red
    Write-Host ""

    if ($vulnerableFiles.Count -gt 0) {
        Write-SubSection "Writable Executables ($($vulnerableFiles.Count))"
        Write-Host ""
        foreach ($vf in $vulnerableFiles) {
            Write-Host "    [!!] $($vf.Path)" -ForegroundColor Red
            Write-Host "         Risk:   $($vf.Risk)" -ForegroundColor Yellow
            Write-Host "         Owner:  $($vf.Owner)" -ForegroundColor DarkGray
            Write-Host "         Config: $($vf.ConfigFile)" -ForegroundColor DarkGray
            Write-Host "         Dangerous permissions:" -ForegroundColor Yellow
            foreach ($ace in $vf.DangerousAces) {
                $inhText = if ($ace.Inherited) { 'inherited' } else { 'EXPLICIT' }
                Write-Host "           * $($ace.Identity)  ->  $($ace.Rights)  ($inhText)" -ForegroundColor Yellow
            }
            if ($vf.Notes) { Write-Host "         Note: $($vf.Notes)" -ForegroundColor DarkGray }
            Write-Host ""
        }
    }

    if ($vulnerableFolders.Count -gt 0) {
        Write-SubSection "Writable Folders ($($vulnerableFolders.Count))"
        Write-Host ""
        foreach ($vd in $vulnerableFolders) {
            Write-Host "    [!!] $($vd.Path)" -ForegroundColor Red
            Write-Host "         Risk:   $($vd.Risk)" -ForegroundColor Yellow
            Write-Host "         Owner:  $($vd.Owner)" -ForegroundColor DarkGray
            Write-Host "         Dangerous permissions:" -ForegroundColor Yellow
            foreach ($ace in $vd.DangerousAces) {
                $inhText = if ($ace.Inherited) { 'inherited' } else { 'EXPLICIT' }
                Write-Host "           * $($ace.Identity)  ->  $($ace.Rights)  ($inhText)" -ForegroundColor Yellow
            }
            if ($vd.Notes) { Write-Host "         Note: $($vd.Notes)" -ForegroundColor DarkGray }
            Write-Host ""
        }
    }

    Write-Host "  -- Remediation Guidance --" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "    For writable EXE files:" -ForegroundColor White
    Write-Host "      * Remove Write/Modify for Users, Everyone, Authenticated Users" -ForegroundColor Gray
    Write-Host "      * Ensure file owner is SYSTEM, TrustedInstaller, or Administrators" -ForegroundColor Gray
    Write-Host "      * Consider using file hash rules instead of path-based rules" -ForegroundColor Gray
    Write-Host ""
    Write-Host "    For writable folders:" -ForegroundColor White
    Write-Host "      * Remove CreateFiles/Write for standard user groups" -ForegroundColor Gray
    Write-Host "      * Use specific exe paths instead of broad folder allow rules" -ForegroundColor Gray
    Write-Host "      * Enable Authorized Owners to require NTFS owner = admin" -ForegroundColor Gray
    Write-Host "      * Enable certificate-based whitelisting for additional protection" -ForegroundColor Gray
    Write-Host ""
}

# ==============================================================================
# -- Display: Original Security Rule Results ----------------------------------
# ==============================================================================

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

# -- 4. Installed IWC Components ----------------------------------------------

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

# -- 5. Export (optional) -----------------------------------------------------

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

    # Audit results (flattened for CSV)
    if ($fileAuditResults.Count -gt 0) {
        $faFile = Join-Path $OutputPath 'AuditResults_Files.csv'
        $fileAuditResults | Select-Object Path, Type, Exists, Writable, Risk, Owner, Notes,
            @{N='DangerousIdentities'; E={ ($_.DangerousAces | ForEach-Object { $_.Identity }) -join '; ' }},
            @{N='DangerousRights';     E={ ($_.DangerousAces | ForEach-Object { $_.Rights })   -join '; ' }},
            @{N='ConfigFile'; E={ $_.ConfigFile }} |
            Export-Csv -Path $faFile -NoTypeInformation
        Write-Host "  File audit results    -> $faFile" -ForegroundColor Green
    }

    if ($folderAuditResults.Count -gt 0) {
        $daFile = Join-Path $OutputPath 'AuditResults_Folders.csv'
        $folderAuditResults | Select-Object Path, Type, Exists, Writable, Risk, Owner, Notes,
            @{N='DangerousIdentities'; E={ ($_.DangerousAces | ForEach-Object { $_.Identity }) -join '; ' }},
            @{N='DangerousRights';     E={ ($_.DangerousAces | ForEach-Object { $_.Rights })   -join '; ' }} |
            Export-Csv -Path $daFile -NoTypeInformation
        Write-Host "  Folder audit results  -> $daFile" -ForegroundColor Green
    }

    if ($vulnerableFiles.Count -gt 0 -or $vulnerableFolders.Count -gt 0) {
        $vulnFile = Join-Path $OutputPath 'VULNERABILITIES.csv'
        $allVulns = @()
        $allVulns += $vulnerableFiles  | Select-Object Path, Type, Risk, Owner,
            @{N='DangerousIdentities'; E={ ($_.DangerousAces | ForEach-Object { $_.Identity }) -join '; ' }},
            @{N='DangerousRights';     E={ ($_.DangerousAces | ForEach-Object { $_.Rights })   -join '; ' }},
            Notes
        $allVulns += $vulnerableFolders | Select-Object Path, Type, Risk, Owner,
            @{N='DangerousIdentities'; E={ ($_.DangerousAces | ForEach-Object { $_.Identity }) -join '; ' }},
            @{N='DangerousRights';     E={ ($_.DangerousAces | ForEach-Object { $_.Rights })   -join '; ' }},
            Notes
        $allVulns | Export-Csv -Path $vulnFile -NoTypeInformation
        Write-Host "  ** VULNERABILITIES ** -> $vulnFile" -ForegroundColor Red
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

# -- Summary ------------------------------------------------------------------

Write-Section 'Summary'
Write-Host "  Cache location:          $cachePath"
Write-Host "  Registry values found:   $($registryFindings.Count)"
Write-Host "  XML config objects:      $($xmlFiles.Count)"
Write-Host ""
Write-Host "  Allowed exe paths:       $($uniqueExePaths.Count)" -ForegroundColor White
Write-Host "  Allowed exe folders:     $($uniqueFolders.Count)" -ForegroundColor White
Write-Host ""

$vulnColour = if (($vulnerableFiles.Count + $vulnerableFolders.Count) -gt 0) { 'Red' } else { 'Green' }
Write-Host "  +- Permission Audit Results -----------------------------" -ForegroundColor $vulnColour
Write-Host "  |  Files checked:           $($fileAuditResults.Count)" -ForegroundColor White
Write-Host "  |  Folders checked:         $($folderAuditResults.Count)" -ForegroundColor White
Write-Host "  |  Writable EXE files:      $($vulnerableFiles.Count)" -ForegroundColor $vulnColour
Write-Host "  |  Writable folders:        $($vulnerableFolders.Count)" -ForegroundColor $vulnColour
Write-Host "  |  TOTAL VULNERABILITIES:   $($vulnerableFiles.Count + $vulnerableFolders.Count)" -ForegroundColor $vulnColour
Write-Host "  +--------------------------------------------------------" -ForegroundColor $vulnColour
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
