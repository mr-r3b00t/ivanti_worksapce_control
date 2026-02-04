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

    It also discovers all network shares (UNC paths) referenced in the config,
    tests server reachability (TCP/445, ICMP, DNS), share accessibility, and
    sub-path availability. Accessible and inaccessible shares are tracked
    separately for reporting.

.NOTES
    Must be run as Administrator to access Program Files cache and HKLM registry keys.
    Author:  Generated for IWC enumeration
    Version: 3.0
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

# Bitmask of ONLY write-specific rights (individual bits, not composites).
# Using individual bits avoids false positives: composite rights like Modify
# and FullControl include ReadAndExecute bits, so checking
# "ReadAndExecute -band Modify" incorrectly returns non-zero.
# By only checking write-specific bits we ensure we only flag genuine
# write/create/delete permissions.
$script:FileWriteBitMask = [int](
    [System.Security.AccessControl.FileSystemRights]::WriteData -bor              # 0x2 (CreateFiles)
    [System.Security.AccessControl.FileSystemRights]::AppendData -bor             # 0x4 (CreateDirectories)
    [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor # 0x10
    [System.Security.AccessControl.FileSystemRights]::WriteAttributes -bor         # 0x100
    [System.Security.AccessControl.FileSystemRights]::Delete -bor                  # 0x10000
    [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor       # 0x40000
    [System.Security.AccessControl.FileSystemRights]::TakeOwnership                # 0x80000
)

# Folder write mask -- same bits, focused on file creation
$script:FolderWriteBitMask = $script:FileWriteBitMask

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

            # Check if any write-specific bits are set
            if (([int]$ace.FileSystemRights -band $script:FileWriteBitMask) -ne 0) {
                # Identify which specific write rights are present
                $matchedRights = [System.Security.AccessControl.FileSystemRights](
                    [int]$ace.FileSystemRights -band $script:FileWriteBitMask
                )
                [void]$result.DangerousAces.Add([PSCustomObject]@{
                    Identity      = $ace.IdentityReference.Value
                    Rights        = $ace.FileSystemRights.ToString()
                    WriteRights   = $matchedRights.ToString()
                    Inherited     = $ace.IsInherited
                })
                $result.Writable = $true
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

            # Check if any write-specific bits are set
            if (([int]$ace.FileSystemRights -band $script:FolderWriteBitMask) -ne 0) {
                $matchedRights = [System.Security.AccessControl.FileSystemRights](
                    [int]$ace.FileSystemRights -band $script:FolderWriteBitMask
                )
                [void]$result.DangerousAces.Add([PSCustomObject]@{
                    Identity    = $ace.IdentityReference.Value
                    Rights      = $ace.FileSystemRights.ToString()
                    WriteRights = $matchedRights.ToString()
                    Inherited   = $ace.IsInherited
                })
                $result.Writable = $true
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

# -- NEW: Collect ALL network/UNC paths (shares, mapped drives, DFS) --
$allNetworkPaths   = [System.Collections.ArrayList]::new()

# Regex to catch file paths ending in .exe, .com, .msi, .bat, .cmd, .ps1
$exePathRegex = '(?i)([a-z]:\\[^<>"|\r\n*?]+\.(?:exe|com|msi|bat|cmd|ps1|vbs|wsf))'
# Regex to catch folder-only paths (e.g. path-based allow rules)
$folderPathRegex = '(?i)([a-z]:\\(?:[^<>"|\r\n*?]+\\))'
# Regex for UNC paths
$uncPathRegex = '(?i)(\\\\[^<>"|\r\n*?]+\.(?:exe|com|msi|bat|cmd|ps1|vbs|wsf))'
$uncFolderRegex = '(?i)(\\\\[^<>"|\r\n*?]+\\)'
# Regex for paths with environment variables
$envPathRegex = '(?i)(%[a-z_()]+%\\[^<>"|\r\n*?]+)'
# Broad regex to capture ANY UNC path (for network share inventory)
$anyUncRegex = '(?i)(\\\\[a-z0-9_\-\.]+\\[^<>"|\r\n*?\s]+)'

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

        # 3) Collect ALL UNC/network paths for the network share inventory
        foreach ($match in [regex]::Matches($content, $anyUncRegex)) {
            [void]$allNetworkPaths.Add([PSCustomObject]@{
                FullPath   = $match.Value.TrimEnd('\', '/')
                ConfigFile = $xmlFile.Name
            })
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
            Write-Host "              Write rights: $($ace.WriteRights)" -ForegroundColor Yellow
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
            Write-Host "              Write rights: $($ace.WriteRights)" -ForegroundColor Yellow
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
                Write-Host "             Write rights: $($ace.WriteRights)" -ForegroundColor Yellow
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
                Write-Host "             Write rights: $($ace.WriteRights)" -ForegroundColor Yellow
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
# -- Network Share Discovery & Accessibility Audit ----------------------------
# ==============================================================================

Write-Section 'Network Share Discovery & Accessibility'

# Also collect UNC paths from the exe/folder lists already found
foreach ($ep in $allowedExePaths) {
    $p = $ep.Path
    if ($p -match '^\\\\') {
        [void]$allNetworkPaths.Add([PSCustomObject]@{
            FullPath   = $p.TrimEnd('\', '/')
            ConfigFile = $ep.ConfigFile
        })
    }
}
foreach ($fp in $allowedExeFolders) {
    if ($fp -match '^\\\\') {
        [void]$allNetworkPaths.Add([PSCustomObject]@{
            FullPath   = $fp.TrimEnd('\', '/')
            ConfigFile = '(folder scan)'
        })
    }
}
foreach ($uf in $uniqueFolders) {
    if ($uf -match '^\\\\') {
        [void]$allNetworkPaths.Add([PSCustomObject]@{
            FullPath   = $uf.TrimEnd('\', '/')
            ConfigFile = '(folder scan)'
        })
    }
}

# Extract unique share roots (\\server\share) from all collected UNC paths
function Get-ShareRoot ([string]$UncPath) {
    <# Extracts \\server\share from a longer UNC path #>
    if ($UncPath -match '^(\\\\[^\\]+\\[^\\]+)') {
        return $Matches[1]
    }
    return $null
}

function Get-ServerName ([string]$UncPath) {
    <# Extracts the server name from a UNC path #>
    if ($UncPath -match '^\\\\([^\\]+)') {
        return $Matches[1]
    }
    return $null
}

# Build unique lists
$uniqueFullUncPaths = $allNetworkPaths | ForEach-Object { $_.FullPath } | Sort-Object -Unique
$uniqueShareRoots   = $uniqueFullUncPaths | ForEach-Object { Get-ShareRoot $_ } |
    Where-Object { $_ } | Sort-Object -Unique
$uniqueServers      = $uniqueFullUncPaths | ForEach-Object { Get-ServerName $_ } |
    Where-Object { $_ } | Sort-Object -Unique

# Build a lookup: share root -> list of full paths that reference it
$sharePathMap = @{}
foreach ($fp in $uniqueFullUncPaths) {
    $root = Get-ShareRoot $fp
    if ($root) {
        if (-not $sharePathMap.ContainsKey($root)) {
            $sharePathMap[$root] = [System.Collections.ArrayList]::new()
        }
        if ($fp -ne $root) {
            [void]$sharePathMap[$root].Add($fp)
        }
    }
}

# Build a lookup: share root -> config files that reference it
$shareConfigMap = @{}
foreach ($np in $allNetworkPaths) {
    $root = Get-ShareRoot $np.FullPath
    if ($root) {
        if (-not $shareConfigMap.ContainsKey($root)) {
            $shareConfigMap[$root] = [System.Collections.ArrayList]::new()
        }
        if ($np.ConfigFile -and $np.ConfigFile -notin $shareConfigMap[$root]) {
            [void]$shareConfigMap[$root].Add($np.ConfigFile)
        }
    }
}

Write-Host "  Unique UNC paths found:    $($uniqueFullUncPaths.Count)"
Write-Host "  Unique share roots:        $($uniqueShareRoots.Count)"
Write-Host "  Unique servers referenced: $($uniqueServers.Count)"

# -- Test server reachability & share accessibility ---

Write-SubSection "Server Reachability"

$serverResults = [System.Collections.ArrayList]::new()
$counter = 0
foreach ($server in $uniqueServers) {
    $counter++
    Write-Progress -Activity 'Testing server reachability' -Status $server -PercentComplete (($counter / [Math]::Max($uniqueServers.Count,1)) * 100)

    $reachable = $false
    $method    = ''

    # Try TCP 445 (SMB) first with a short timeout
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $connect = $tcp.BeginConnect($server, 445, $null, $null)
        $waited = $connect.AsyncWaitHandle.WaitOne(2000, $false)
        if ($waited -and $tcp.Connected) {
            $reachable = $true
            $method = 'TCP/445 (SMB)'
        }
        $tcp.Close()
    } catch { }

    # Fallback: ping
    if (-not $reachable) {
        try {
            $ping = Test-Connection -ComputerName $server -Count 1 -Quiet -ErrorAction SilentlyContinue
            if ($ping) {
                $reachable = $true
                $method = 'ICMP Ping'
            }
        } catch { }
    }

    # Fallback: DNS resolution only
    if (-not $reachable) {
        try {
            $dns = [System.Net.Dns]::GetHostEntry($server)
            if ($dns.AddressList.Count -gt 0) {
                $method = 'DNS resolves but not reachable on 445/ICMP'
            } else {
                $method = 'DNS resolution failed'
            }
        } catch {
            $method = 'DNS resolution failed'
        }
    }

    $colour = if ($reachable) { 'Green' } else { 'Red' }
    $icon   = if ($reachable) { '[OK]' } else { '[!!]' }
    Write-Host "    $icon $server -- $method" -ForegroundColor $colour

    [void]$serverResults.Add([PSCustomObject]@{
        Server    = $server
        Reachable = $reachable
        Method    = $method
    })
}
Write-Progress -Activity 'Testing server reachability' -Completed

# -- Test each share root for accessibility ---

Write-SubSection "Share Accessibility ($($uniqueShareRoots.Count) shares)"

$accessibleShares   = [System.Collections.ArrayList]::new()
$inaccessibleShares = [System.Collections.ArrayList]::new()

$counter = 0
foreach ($shareRoot in $uniqueShareRoots) {
    $counter++
    Write-Progress -Activity 'Testing share accessibility' -Status $shareRoot -PercentComplete (($counter / [Math]::Max($uniqueShareRoots.Count,1)) * 100)

    $server     = Get-ServerName $shareRoot
    $accessible = $false
    $canList    = $false
    $userWrite  = $false
    $owner      = ''
    $errMsg     = ''
    $subPaths   = if ($sharePathMap.ContainsKey($shareRoot)) { $sharePathMap[$shareRoot] } else { @() }
    $configs    = if ($shareConfigMap.ContainsKey($shareRoot)) { ($shareConfigMap[$shareRoot] -join ', ') } else { '' }

    # Check if the share root is accessible
    try {
        if (Test-Path -LiteralPath $shareRoot -ErrorAction Stop) {
            $accessible = $true

            # Can we list contents?
            try {
                $listing = Get-ChildItem -LiteralPath $shareRoot -ErrorAction Stop | Select-Object -First 1
                $canList = $true
            } catch {
                $canList = $false
            }

            # Check write permissions for standard users
            try {
                $acl = Get-Acl -LiteralPath $shareRoot -ErrorAction Stop
                $owner = $acl.Owner
                foreach ($ace in $acl.Access) {
                    if ($ace.AccessControlType -ne 'Allow') { continue }
                    # Check if identity is a standard user group
                    $isUser = $false
                    foreach ($name in $script:UserWriteNames) {
                        if ($ace.IdentityReference.Value -like "*$name*") { $isUser = $true; break }
                    }
                    if (-not $isUser) {
                        try {
                            $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                            if ($sid -in $script:UserWriteSIDs) { $isUser = $true }
                        } catch { }
                    }
                    if ($isUser) {
                        if (([int]$ace.FileSystemRights -band $script:FolderWriteBitMask) -ne 0) {
                            $userWrite = $true
                        }
                    }
                    if ($userWrite) { break }
                }
            } catch {
                $errMsg = "ACL check failed: $_"
            }
        } else {
            $errMsg = 'Path not accessible (Test-Path returned false)'
        }
    } catch {
        $errMsg = "Access error: $_"
    }

    # Build result object
    $shareResult = [PSCustomObject]@{
        ShareRoot       = $shareRoot
        Server          = $server
        Accessible      = $accessible
        CanListContents = $canList
        UserWritable    = $userWrite
        Owner           = $owner
        SubPathsFound   = $subPaths.Count
        ConfigFiles     = $configs
        Error           = $errMsg
    }

    if ($accessible) {
        [void]$accessibleShares.Add($shareResult)
    } else {
        [void]$inaccessibleShares.Add($shareResult)
    }

    # Display
    if ($accessible) {
        $writeWarn = if ($userWrite) { ' ** USER-WRITABLE **' } else { '' }
        $colour    = if ($userWrite) { 'Yellow' } else { 'Green' }
        Write-Host "    [OK] $shareRoot" -ForegroundColor $colour
        Write-Host "         Accessible: Yes  |  Can list: $canList  |  Owner: $owner$writeWarn" -ForegroundColor DarkGray
    } else {
        Write-Host "    [!!] $shareRoot" -ForegroundColor Red
        Write-Host "         Accessible: No   |  Error: $errMsg" -ForegroundColor DarkGray
    }

    if ($subPaths.Count -gt 0) {
        Write-Host "         Sub-paths referencing this share:" -ForegroundColor DarkGray
        foreach ($sp in $subPaths) {
            Write-Host "           - $sp" -ForegroundColor DarkGray
        }
    }
    if ($configs) {
        Write-Host "         Referenced in: $configs" -ForegroundColor DarkGray
    }
}
Write-Progress -Activity 'Testing share accessibility' -Completed

# -- Summary tables ---

Write-SubSection "Accessible Shares ($($accessibleShares.Count))"
if ($accessibleShares.Count -gt 0) {
    foreach ($s in $accessibleShares) {
        $writeFlag = if ($s.UserWritable) { ' [USER-WRITABLE]' } else { '' }
        $colour    = if ($s.UserWritable) { 'Yellow' } else { 'Green' }
        Write-Host "    $($s.ShareRoot)$writeFlag" -ForegroundColor $colour
    }
} else {
    Write-Host "    None" -ForegroundColor DarkGray
}

Write-SubSection "Inaccessible Shares ($($inaccessibleShares.Count))"
if ($inaccessibleShares.Count -gt 0) {
    foreach ($s in $inaccessibleShares) {
        Write-Host "    $($s.ShareRoot)" -ForegroundColor Red
        Write-Host "      Error: $($s.Error)" -ForegroundColor DarkGray
    }
} else {
    Write-Host "    None -- all shares were accessible" -ForegroundColor Green
}

# -- Also test full sub-paths on accessible shares ---

Write-SubSection "Full Path Accessibility (sub-paths on accessible shares)"

$subPathResults = [System.Collections.ArrayList]::new()
$allSubPaths = $sharePathMap.Values | ForEach-Object { $_ } | Sort-Object -Unique

$counter = 0
foreach ($sp in $allSubPaths) {
    $counter++
    Write-Progress -Activity 'Testing sub-path accessibility' -Status $sp -PercentComplete (($counter / [Math]::Max($allSubPaths.Count,1)) * 100)

    $spAccessible = $false
    $spIsFile     = $false
    $spIsFolder   = $false
    $spError      = ''

    try {
        if (Test-Path -LiteralPath $sp -PathType Leaf -ErrorAction Stop) {
            $spAccessible = $true
            $spIsFile     = $true
        } elseif (Test-Path -LiteralPath $sp -PathType Container -ErrorAction Stop) {
            $spAccessible = $true
            $spIsFolder   = $true
        } else {
            $spError = 'Path does not exist'
        }
    } catch {
        $spError = "$_"
    }

    $spType = if ($spIsFile) { 'File' } elseif ($spIsFolder) { 'Folder' } else { 'N/A' }

    [void]$subPathResults.Add([PSCustomObject]@{
        Path       = $sp
        Accessible = $spAccessible
        Type       = $spType
        Error      = $spError
    })

    $colour = if ($spAccessible) { 'Green' } else { 'Red' }
    $icon   = if ($spAccessible) { '[OK]' } else { '[!!]' }
    Write-Host "    $icon $sp ($spType)" -ForegroundColor $colour
    if ($spError) { Write-Host "         Error: $spError" -ForegroundColor DarkGray }
}
Write-Progress -Activity 'Testing sub-path accessibility' -Completed

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
            @{N='DangerousIdentities'; E={ ($_.DangerousAces | ForEach-Object { $_.Identity })    -join '; ' }},
            @{N='FullRights';          E={ ($_.DangerousAces | ForEach-Object { $_.Rights })      -join '; ' }},
            @{N='WriteRightsOnly';     E={ ($_.DangerousAces | ForEach-Object { $_.WriteRights }) -join '; ' }},
            @{N='ConfigFile'; E={ $_.ConfigFile }} |
            Export-Csv -Path $faFile -NoTypeInformation
        Write-Host "  File audit results    -> $faFile" -ForegroundColor Green
    }

    if ($folderAuditResults.Count -gt 0) {
        $daFile = Join-Path $OutputPath 'AuditResults_Folders.csv'
        $folderAuditResults | Select-Object Path, Type, Exists, Writable, Risk, Owner, Notes,
            @{N='DangerousIdentities'; E={ ($_.DangerousAces | ForEach-Object { $_.Identity })    -join '; ' }},
            @{N='FullRights';          E={ ($_.DangerousAces | ForEach-Object { $_.Rights })      -join '; ' }},
            @{N='WriteRightsOnly';     E={ ($_.DangerousAces | ForEach-Object { $_.WriteRights }) -join '; ' }} |
            Export-Csv -Path $daFile -NoTypeInformation
        Write-Host "  Folder audit results  -> $daFile" -ForegroundColor Green
    }

    if ($vulnerableFiles.Count -gt 0 -or $vulnerableFolders.Count -gt 0) {
        $vulnFile = Join-Path $OutputPath 'VULNERABILITIES.csv'
        $allVulns = @()
        $allVulns += $vulnerableFiles  | Select-Object Path, Type, Risk, Owner,
            @{N='DangerousIdentities'; E={ ($_.DangerousAces | ForEach-Object { $_.Identity })    -join '; ' }},
            @{N='FullRights';          E={ ($_.DangerousAces | ForEach-Object { $_.Rights })      -join '; ' }},
            @{N='WriteRightsOnly';     E={ ($_.DangerousAces | ForEach-Object { $_.WriteRights }) -join '; ' }},
            Notes
        $allVulns += $vulnerableFolders | Select-Object Path, Type, Risk, Owner,
            @{N='DangerousIdentities'; E={ ($_.DangerousAces | ForEach-Object { $_.Identity })    -join '; ' }},
            @{N='FullRights';          E={ ($_.DangerousAces | ForEach-Object { $_.Rights })      -join '; ' }},
            @{N='WriteRightsOnly';     E={ ($_.DangerousAces | ForEach-Object { $_.WriteRights }) -join '; ' }},
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

    # Network share reports
    if ($accessibleShares.Count -gt 0) {
        $asFile = Join-Path $OutputPath 'NetworkShares_Accessible.csv'
        $accessibleShares | Export-Csv -Path $asFile -NoTypeInformation
        Write-Host "  Accessible shares     -> $asFile" -ForegroundColor Green
    }

    if ($inaccessibleShares.Count -gt 0) {
        $isFile = Join-Path $OutputPath 'NetworkShares_Inaccessible.csv'
        $inaccessibleShares | Export-Csv -Path $isFile -NoTypeInformation
        Write-Host "  Inaccessible shares   -> $isFile" -ForegroundColor Red
    }

    if ($serverResults.Count -gt 0) {
        $srFile = Join-Path $OutputPath 'NetworkServers.csv'
        $serverResults | Export-Csv -Path $srFile -NoTypeInformation
        Write-Host "  Server reachability   -> $srFile" -ForegroundColor Green
    }

    if ($subPathResults.Count -gt 0) {
        $spFile = Join-Path $OutputPath 'NetworkSubPaths.csv'
        $subPathResults | Export-Csv -Path $spFile -NoTypeInformation
        Write-Host "  Network sub-paths     -> $spFile" -ForegroundColor Green
    }

    # Combined full inventory
    $allShareInventory = @()
    $allShareInventory += $accessibleShares   | Select-Object ShareRoot, Server, Accessible, CanListContents, UserWritable, Owner, SubPathsFound, ConfigFiles, Error
    $allShareInventory += $inaccessibleShares | Select-Object ShareRoot, Server, Accessible, CanListContents, UserWritable, Owner, SubPathsFound, ConfigFiles, Error
    if ($allShareInventory.Count -gt 0) {
        $invFile = Join-Path $OutputPath 'NetworkShares_FullInventory.csv'
        $allShareInventory | Export-Csv -Path $invFile -NoTypeInformation
        Write-Host "  Full share inventory  -> $invFile" -ForegroundColor Cyan
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

$netColour = if ($inaccessibleShares.Count -gt 0) { 'Yellow' } else { 'Green' }
$writeColour = if (($accessibleShares | Where-Object { $_.UserWritable }).Count -gt 0) { 'Red' } else { 'Green' }
Write-Host "  +- Network Share Audit ----------------------------------" -ForegroundColor $netColour
Write-Host "  |  Servers referenced:      $($uniqueServers.Count)" -ForegroundColor White
Write-Host "  |  Servers reachable:       $(($serverResults | Where-Object { $_.Reachable }).Count)" -ForegroundColor White
Write-Host "  |  Servers unreachable:     $(($serverResults | Where-Object { -not $_.Reachable }).Count)" -ForegroundColor $netColour
Write-Host "  |  Share roots found:       $($uniqueShareRoots.Count)" -ForegroundColor White
Write-Host "  |  Shares accessible:       $($accessibleShares.Count)" -ForegroundColor Green
Write-Host "  |  Shares inaccessible:     $($inaccessibleShares.Count)" -ForegroundColor $netColour
Write-Host "  |  Shares user-writable:    $(($accessibleShares | Where-Object { $_.UserWritable }).Count)" -ForegroundColor $writeColour
Write-Host "  +--------------------------------------------------------" -ForegroundColor $netColour
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
