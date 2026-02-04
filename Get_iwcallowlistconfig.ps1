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
    Version: 4.0
#>

[CmdletBinding()]
param(
    [switch]$ExportCsv,
    [switch]$ExportHtml,
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

# -- 6. HTML Report (optional) ------------------------------------------------

if ($ExportHtml) {
    Write-Section 'Generating HTML Report'

    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    $reportDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $hostName   = $env:COMPUTERNAME
    $userName   = "$env:USERDOMAIN\$env:USERNAME"

    $totalVulns         = $vulnerableFiles.Count + $vulnerableFolders.Count
    $reachableServers   = ($serverResults | Where-Object { $_.Reachable }).Count
    $unreachableServers = ($serverResults | Where-Object { -not $_.Reachable }).Count
    $writableShareCount = ($accessibleShares | Where-Object { $_.UserWritable }).Count

    # -- Helper: build an HTML table from an array of objects
    function ConvertTo-HtmlTable {
        param(
            [Parameter(Mandatory)][array]$Data,
            [string[]]$Columns,
            [string]$HighlightColumn = '',
            [string]$HighlightValue  = '',
            [string]$HighlightClass  = 'risk-high'
        )
        if ($Data.Count -eq 0) { return '<p class="empty">None found.</p>' }
        if (-not $Columns) { $Columns = $Data[0].PSObject.Properties.Name }
        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.Append('<div class="table-wrap"><table><thead><tr>')
        foreach ($col in $Columns) {
            [void]$sb.Append("<th>$col</th>")
        }
        [void]$sb.Append('</tr></thead><tbody>')
        foreach ($row in $Data) {
            $rowClass = ''
            if ($HighlightColumn -and $row.$HighlightColumn -eq $HighlightValue) {
                $rowClass = " class=`"$HighlightClass`""
            }
            [void]$sb.Append("<tr$rowClass>")
            foreach ($col in $Columns) {
                $val = $row.$col
                if ($null -eq $val) { $val = '' }
                $val = [System.Web.HttpUtility]::HtmlEncode("$val")
                [void]$sb.Append("<td>$val</td>")
            }
            [void]$sb.Append('</tr>')
        }
        [void]$sb.Append('</tbody></table></div>')
        return $sb.ToString()
    }

    # -- Build flat data for HTML tables
    $fileAuditFlat = $fileAuditResults | Select-Object Path, Exists, Writable, Risk, Owner,
        @{N='Identity';    E={ ($_.DangerousAces | ForEach-Object { $_.Identity })    -join '; ' }},
        @{N='FullRights';  E={ ($_.DangerousAces | ForEach-Object { $_.Rights })      -join '; ' }},
        @{N='WriteRights'; E={ ($_.DangerousAces | ForEach-Object { $_.WriteRights }) -join '; ' }},
        Notes

    $folderAuditFlat = $folderAuditResults | Select-Object Path, Exists, Writable, Risk, Owner,
        @{N='Identity';    E={ ($_.DangerousAces | ForEach-Object { $_.Identity })    -join '; ' }},
        @{N='FullRights';  E={ ($_.DangerousAces | ForEach-Object { $_.Rights })      -join '; ' }},
        @{N='WriteRights'; E={ ($_.DangerousAces | ForEach-Object { $_.WriteRights }) -join '; ' }},
        Notes

    $vulnFlat = @()
    $vulnFlat += $vulnerableFiles | Select-Object Path,
        @{N='Type'; E={ 'File' }}, Risk, Owner,
        @{N='Identity';    E={ ($_.DangerousAces | ForEach-Object { $_.Identity })    -join '; ' }},
        @{N='WriteRights'; E={ ($_.DangerousAces | ForEach-Object { $_.WriteRights }) -join '; ' }},
        Notes
    $vulnFlat += $vulnerableFolders | Select-Object Path,
        @{N='Type'; E={ 'Folder' }}, Risk, Owner,
        @{N='Identity';    E={ ($_.DangerousAces | ForEach-Object { $_.Identity })    -join '; ' }},
        @{N='WriteRights'; E={ ($_.DangerousAces | ForEach-Object { $_.WriteRights }) -join '; ' }},
        Notes

    $regFlat = $registryFindings | Select-Object RegistryKey, Name, Value, SecurityRelated

    $shareAllFlat = @()
    $shareAllFlat += $accessibleShares   | Select-Object ShareRoot, Server, Accessible, CanListContents, UserWritable, Owner, SubPathsFound, ConfigFiles, Error
    $shareAllFlat += $inaccessibleShares | Select-Object ShareRoot, Server, Accessible, CanListContents, UserWritable, Owner, SubPathsFound, ConfigFiles, Error

    # Ensure System.Web is loaded for HtmlEncode
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

    # -- Compose HTML
    $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IWC Allow List Audit Report - $hostName</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Serif:wght@600;700&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root {
    --white: #ffffff;
    --bg: #f4f5f7;
    --surface: #ffffff;
    --surface-alt: #f9fafb;
    --border: #e2e5ea;
    --border-light: #eef0f3;
    --text: #1a1f36;
    --text-secondary: #525f7f;
    --text-muted: #8792a2;
    --brand: #0a2540;
    --accent: #0066ff;
    --accent-light: #e8f0fe;
    --accent-hover: #0052cc;
    --green: #00a67e;
    --green-bg: #edfcf7;
    --green-border: #b5ead6;
    --red: #dc2626;
    --red-bg: #fef2f2;
    --red-border: #fca5a5;
    --amber: #d97706;
    --amber-bg: #fffbeb;
    --amber-border: #fcd34d;
    --shadow-sm: 0 1px 2px rgba(0,0,0,0.04), 0 1px 3px rgba(0,0,0,0.06);
    --shadow-md: 0 2px 4px rgba(0,0,0,0.04), 0 4px 12px rgba(0,0,0,0.06);
    --shadow-lg: 0 4px 8px rgba(0,0,0,0.04), 0 8px 24px rgba(0,0,0,0.08);
    --radius: 8px;
    --radius-lg: 12px;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'IBM Plex Sans', -apple-system, BlinkMacSystemFont, sans-serif;
    font-size: 15px;
    background: var(--bg);
    color: var(--text);
    line-height: 1.65;
    -webkit-font-smoothing: antialiased;
  }

  /* -- Header / Masthead -------------------------------------------------- */
  .report-header {
    background: var(--brand);
    color: var(--white);
    padding: 40px 48px 36px;
    position: relative;
    overflow: hidden;
  }
  .report-header::before {
    content: '';
    position: absolute;
    top: -60%; right: -10%;
    width: 500px; height: 500px;
    background: radial-gradient(circle, rgba(0,102,255,0.15) 0%, transparent 70%);
    pointer-events: none;
  }
  .report-header::after {
    content: '';
    position: absolute;
    bottom: 0; left: 0; right: 0;
    height: 1px;
    background: linear-gradient(90deg, transparent, rgba(255,255,255,0.12), transparent);
  }
  .header-eyebrow {
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 2px;
    text-transform: uppercase;
    color: rgba(255,255,255,0.5);
    margin-bottom: 10px;
  }
  .header-title {
    font-family: 'IBM Plex Serif', Georgia, serif;
    font-size: 30px;
    font-weight: 700;
    letter-spacing: -0.5px;
    margin-bottom: 6px;
    position: relative;
  }
  .header-sub {
    font-size: 13px;
    color: rgba(255,255,255,0.55);
    font-weight: 400;
  }
  .header-sub span {
    color: rgba(255,255,255,0.35);
    margin: 0 8px;
  }
  .header-badge {
    display: inline-block;
    margin-top: 16px;
    padding: 5px 14px;
    border-radius: 100px;
    font-size: 12px;
    font-weight: 600;
  }
  .header-badge.critical {
    background: rgba(220,38,38,0.2);
    color: #fca5a5;
    border: 1px solid rgba(220,38,38,0.3);
  }
  .header-badge.clean {
    background: rgba(0,166,126,0.2);
    color: #6ee7b7;
    border: 1px solid rgba(0,166,126,0.3);
  }

  /* -- Layout ------------------------------------------------------------- */
  .container { max-width: 1280px; margin: 0 auto; padding: 32px 48px 64px; }

  /* -- Navigation --------------------------------------------------------- */
  .nav-bar {
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    padding: 0 48px;
    position: sticky;
    top: 0;
    z-index: 100;
    box-shadow: var(--shadow-sm);
  }
  .nav-inner {
    max-width: 1280px;
    margin: 0 auto;
    display: flex;
    gap: 0;
    overflow-x: auto;
  }
  .nav-bar a {
    display: inline-block;
    padding: 14px 18px;
    font-size: 13px;
    font-weight: 500;
    color: var(--text-secondary);
    text-decoration: none;
    border-bottom: 2px solid transparent;
    white-space: nowrap;
    transition: color 0.15s, border-color 0.15s;
  }
  .nav-bar a:hover {
    color: var(--accent);
    border-bottom-color: var(--accent);
  }

  /* -- Section headers ---------------------------------------------------- */
  h2 {
    font-family: 'IBM Plex Serif', Georgia, serif;
    font-size: 22px;
    font-weight: 700;
    color: var(--brand);
    letter-spacing: -0.3px;
    margin: 48px 0 8px 0;
    padding-bottom: 12px;
    border-bottom: 2px solid var(--brand);
  }
  h2 .count {
    font-family: 'IBM Plex Sans', sans-serif;
    font-size: 14px;
    font-weight: 500;
    color: var(--text-muted);
    margin-left: 8px;
  }
  h3 {
    font-size: 16px;
    font-weight: 600;
    color: var(--text);
    margin: 24px 0 10px 0;
    padding-left: 12px;
    border-left: 3px solid var(--accent);
  }

  /* -- Summary cards ------------------------------------------------------- */
  .summary-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
    margin: 24px 0 8px 0;
  }
  @media (max-width: 1000px) {
    .summary-grid { grid-template-columns: repeat(2, 1fr); }
  }
  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 20px 22px;
    box-shadow: var(--shadow-sm);
    transition: box-shadow 0.2s;
    position: relative;
    overflow: hidden;
  }
  .card:hover { box-shadow: var(--shadow-md); }
  .card-title {
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 1.2px;
    text-transform: uppercase;
    color: var(--text-muted);
    margin-bottom: 10px;
  }
  .card-value {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 32px;
    font-weight: 500;
    line-height: 1;
    color: var(--brand);
  }
  .card-value.ok     { color: var(--green); }
  .card-value.warn   { color: var(--amber); }
  .card-value.danger { color: var(--red); }
  .card-detail {
    font-size: 13px;
    color: var(--text-muted);
    margin-top: 8px;
    line-height: 1.4;
  }
  .card-stripe {
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
  }
  .card-stripe.blue   { background: var(--accent); }
  .card-stripe.green  { background: var(--green); }
  .card-stripe.red    { background: var(--red); }
  .card-stripe.amber  { background: var(--amber); }

  /* -- Tables ------------------------------------------------------------- */
  .table-wrap {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    overflow: hidden;
    box-shadow: var(--shadow-sm);
    margin: 12px 0 20px 0;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 14px;
  }
  thead th {
    background: var(--surface-alt);
    padding: 12px 14px;
    text-align: left;
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    color: var(--text-muted);
    border-bottom: 2px solid var(--border);
    position: sticky;
    top: 47px;
    z-index: 10;
  }
  td {
    padding: 10px 14px;
    border-bottom: 1px solid var(--border-light);
    color: var(--text-secondary);
    font-family: 'IBM Plex Sans', -apple-system, BlinkMacSystemFont, sans-serif;
    font-size: 13px;
    word-break: break-word;
    max-width: 420px;
  }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: var(--accent-light); }
  tr.risk-high td { background: var(--red-bg); }
  tr.risk-high:hover td { background: #fee2e2; }

  /* -- Status pills in tables --------------------------------------------- */
  td.status-ok { color: var(--green); font-weight: 600; }
  td.status-fail { color: var(--red); font-weight: 600; }

  /* -- Alert boxes -------------------------------------------------------- */
  .alert {
    border-radius: var(--radius-lg);
    padding: 20px 24px;
    margin: 16px 0;
    display: flex;
    gap: 14px;
    align-items: flex-start;
  }
  .alert-icon {
    flex-shrink: 0;
    width: 24px; height: 24px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 13px;
    font-weight: 700;
    margin-top: 1px;
  }
  .alert.danger {
    background: var(--red-bg);
    border: 1px solid var(--red-border);
  }
  .alert.danger .alert-icon {
    background: var(--red);
    color: var(--white);
  }
  .alert.success {
    background: var(--green-bg);
    border: 1px solid var(--green-border);
  }
  .alert.success .alert-icon {
    background: var(--green);
    color: var(--white);
  }
  .alert-title {
    font-size: 15px;
    font-weight: 700;
    margin-bottom: 4px;
    color: var(--text);
  }
  .alert-body {
    font-size: 14px;
    color: var(--text-secondary);
    line-height: 1.55;
  }

  /* -- Remediation box ---------------------------------------------------- */
  .remediation {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 24px 28px;
    margin: 16px 0;
    box-shadow: var(--shadow-sm);
  }
  .remediation h3 {
    border-left: 3px solid var(--green);
    margin-top: 0;
    margin-bottom: 14px;
  }
  .remediation ol {
    padding-left: 20px;
    counter-reset: remediation;
  }
  .remediation li {
    padding: 6px 0;
    font-size: 14px;
    color: var(--text-secondary);
    line-height: 1.5;
  }

  /* -- Empty state -------------------------------------------------------- */
  .empty { color: var(--text-muted); font-style: italic; padding: 16px 0; font-size: 14px; }

  /* -- Footer ------------------------------------------------------------- */
  .report-footer {
    margin-top: 56px;
    padding: 24px 0;
    border-top: 1px solid var(--border);
    display: flex;
    justify-content: space-between;
    align-items: center;
    color: var(--text-muted);
    font-size: 12px;
  }
  .report-footer .logo-text {
    font-weight: 700;
    color: var(--brand);
    font-size: 13px;
  }

  /* -- Print -------------------------------------------------------------- */
  @media print {
    body { background: #fff; font-size: 11px; }
    .nav-bar { display: none; }
    .report-header { padding: 24px; background: #fff; color: #000; }
    .report-header::before, .report-header::after { display: none; }
    .header-eyebrow, .header-sub { color: #666; }
    .header-title { color: #000; }
    .container { padding: 16px; }
    .card { break-inside: avoid; box-shadow: none; border: 1px solid #ccc; }
    .table-wrap { box-shadow: none; }
    thead th { position: static; }
    h2 { break-after: avoid; }
    .alert, .remediation { break-inside: avoid; }
  }
</style>
</head>
<body>

<!-- ====== HEADER ====== -->
<div class="report-header">
  <div class="header-eyebrow">Security Audit Report</div>
  <div class="header-title">Ivanti Workspace Control</div>
  <div class="header-sub">
    Allow List Configuration &amp; Permission Analysis
  </div>
  <div class="header-sub" style="margin-top:8px;">
    $hostName<span>|</span>$userName<span>|</span>$reportDate
  </div>
  <div class="header-badge $(if ($totalVulns -gt 0) { 'critical' } else { 'clean' })">
    $(if ($totalVulns -gt 0) { "!! $totalVulns Vulnerability$(if ($totalVulns -ne 1){'ies'}else{'y'}) Detected" } else { 'All Clear -- No Vulnerabilities Found' })
  </div>
</div>

<!-- ====== NAV ====== -->
<nav class="nav-bar">
  <div class="nav-inner">
    <a href="#summary">Summary</a>
    <a href="#vulns">Vulnerabilities</a>
    <a href="#file-audit">File Audit</a>
    <a href="#folder-audit">Folder Audit</a>
    <a href="#network">Network Shares</a>
    <a href="#registry">Registry</a>
    <a href="#security-rules">Security Rules</a>
    <a href="#components">Components</a>
  </div>
</nav>

<div class="container">

<!-- ====== SUMMARY ====== -->
<h2 id="summary">Executive Summary</h2>
<div class="summary-grid">
  <div class="card">
    <div class="card-stripe $(if ($totalVulns -gt 0) { 'red' } else { 'green' })"></div>
    <div class="card-title">Vulnerabilities</div>
    <div class="card-value $(if ($totalVulns -gt 0) { 'danger' } else { 'ok' })">$totalVulns</div>
    <div class="card-detail">$($vulnerableFiles.Count) files / $($vulnerableFolders.Count) folders writable</div>
  </div>
  <div class="card">
    <div class="card-stripe blue"></div>
    <div class="card-title">Allowed Executables</div>
    <div class="card-value">$($uniqueExePaths.Count)</div>
    <div class="card-detail">Across $($uniqueFolders.Count) unique folders</div>
  </div>
  <div class="card">
    <div class="card-stripe $(if ($inaccessibleShares.Count -gt 0) { 'amber' } else { 'green' })"></div>
    <div class="card-title">Network Shares</div>
    <div class="card-value $(if ($inaccessibleShares.Count -gt 0) { 'warn' } else { 'ok' })">$($uniqueShareRoots.Count)</div>
    <div class="card-detail">$($accessibleShares.Count) accessible / $($inaccessibleShares.Count) inaccessible</div>
  </div>
  <div class="card">
    <div class="card-stripe $(if ($unreachableServers -gt 0) { 'amber' } else { 'green' })"></div>
    <div class="card-title">Servers</div>
    <div class="card-value $(if ($unreachableServers -gt 0) { 'warn' } else { 'ok' })">$($uniqueServers.Count)</div>
    <div class="card-detail">$reachableServers reachable / $unreachableServers unreachable</div>
  </div>
</div>
<div class="summary-grid">
  <div class="card">
    <div class="card-stripe blue"></div>
    <div class="card-title">Config Objects</div>
    <div class="card-value">$($xmlFiles.Count)</div>
    <div class="card-detail">$($registryFindings.Count) registry values</div>
  </div>
  <div class="card">
    <div class="card-stripe blue"></div>
    <div class="card-title">Security Rules</div>
    <div class="card-value">$(($authorizedFiles.Count + $authorizedCerts.Count + $authorizedOwners.Count))</div>
    <div class="card-detail">$($authorizedFiles.Count) file / $($authorizedCerts.Count) cert / $($authorizedOwners.Count) owner</div>
  </div>
  <div class="card">
    <div class="card-stripe blue"></div>
    <div class="card-title">Blocked Paths</div>
    <div class="card-value">$($blockedPaths.Count)</div>
    <div class="card-detail">$($securityConfigs.Count) security config entries</div>
  </div>
  <div class="card">
    <div class="card-stripe $(if ($writableShareCount -gt 0) { 'red' } else { 'green' })"></div>
    <div class="card-title">Writable Shares</div>
    <div class="card-value $(if ($writableShareCount -gt 0) { 'danger' } else { 'ok' })">$writableShareCount</div>
    <div class="card-detail">Standard user write access to shares</div>
  </div>
</div>

<!-- ====== VULNERABILITIES ====== -->
<h2 id="vulns">Vulnerability Report</h2>
"@

    if ($totalVulns -eq 0) {
        $htmlContent += @"

<div class="alert success">
  <div class="alert-icon">&#10003;</div>
  <div>
    <div class="alert-title">No Vulnerabilities Detected</div>
    <div class="alert-body">All allowed executable paths and folders are protected from standard user write access. No privilege escalation vectors were identified in the current configuration.</div>
  </div>
</div>
"@
    } else {
        $htmlContent += @"

<div class="alert danger">
  <div class="alert-icon">!</div>
  <div>
    <div class="alert-title">$totalVulns Vulnerable Path$(if ($totalVulns -ne 1){'s'}) Detected</div>
    <div class="alert-body">A standard user could potentially overwrite or create executables in the following allow-listed paths. These represent privilege escalation vectors that should be remediated immediately.</div>
  </div>
</div>
"@
        $htmlContent += (ConvertTo-HtmlTable -Data $vulnFlat -Columns @('Path','Type','Risk','Owner','Identity','WriteRights','Notes') -HighlightColumn 'Type' -HighlightValue '' -HighlightClass '')

        $htmlContent += @"

<div class="remediation">
  <h3>Remediation Guidance</h3>
  <ol>
    <li>Remove Write/Modify permissions for Users, Everyone, and Authenticated Users on all flagged paths</li>
    <li>Ensure file owners are SYSTEM, TrustedInstaller, or Administrators</li>
    <li>Migrate from path-based allow rules to file hash or certificate-based rules where possible</li>
    <li>Enable the Authorized Owners feature to require NTFS owner = administrator</li>
    <li>Remove CreateFiles/Write permissions for standard user groups on flagged folders</li>
  </ol>
</div>
"@
    }

    # -- File Audit
    $htmlContent += @"

<h2 id="file-audit">File Permission Audit<span class="count">$($fileAuditResults.Count) paths checked</span></h2>
"@
    $htmlContent += (ConvertTo-HtmlTable -Data $fileAuditFlat -Columns @('Path','Exists','Writable','Risk','Owner','Identity','FullRights','WriteRights','Notes') -HighlightColumn 'Writable' -HighlightValue 'True' -HighlightClass 'risk-high')

    # -- Folder Audit
    $htmlContent += @"

<h2 id="folder-audit">Folder Permission Audit<span class="count">$($folderAuditResults.Count) folders checked</span></h2>
"@
    $htmlContent += (ConvertTo-HtmlTable -Data $folderAuditFlat -Columns @('Path','Exists','Writable','Risk','Owner','Identity','FullRights','WriteRights','Notes') -HighlightColumn 'Writable' -HighlightValue 'True' -HighlightClass 'risk-high')

    # -- Network Shares
    $htmlContent += @"

<h2 id="network">Network Share Audit</h2>
<h3>Server Reachability</h3>
"@
    $htmlContent += (ConvertTo-HtmlTable -Data $serverResults -Columns @('Server','Reachable','Method') -HighlightColumn 'Reachable' -HighlightValue 'False' -HighlightClass 'risk-high')

    $htmlContent += "<h3>Accessible Shares ($($accessibleShares.Count))</h3>"
    if ($accessibleShares.Count -gt 0) {
        $htmlContent += (ConvertTo-HtmlTable -Data $accessibleShares -Columns @('ShareRoot','Server','Accessible','CanListContents','UserWritable','Owner','SubPathsFound','ConfigFiles') -HighlightColumn 'UserWritable' -HighlightValue 'True' -HighlightClass 'risk-high')
    } else {
        $htmlContent += '<p class="empty">No accessible shares found.</p>'
    }

    $htmlContent += "<h3>Inaccessible Shares ($($inaccessibleShares.Count))</h3>"
    if ($inaccessibleShares.Count -gt 0) {
        $htmlContent += (ConvertTo-HtmlTable -Data $inaccessibleShares -Columns @('ShareRoot','Server','Error','ConfigFiles') -HighlightColumn '' -HighlightValue '' -HighlightClass 'risk-high')
    } else {
        $htmlContent += '<p class="empty">All shares were accessible.</p>'
    }

    if ($subPathResults.Count -gt 0) {
        $htmlContent += "<h3>Sub-Path Accessibility ($($subPathResults.Count))</h3>"
        $htmlContent += (ConvertTo-HtmlTable -Data $subPathResults -Columns @('Path','Accessible','Type','Error') -HighlightColumn 'Accessible' -HighlightValue 'False' -HighlightClass 'risk-high')
    }

    # -- Registry
    $htmlContent += @"

<h2 id="registry">Registry Settings<span class="count">$($registryFindings.Count) values</span></h2>
"@
    if ($regFlat.Count -gt 0) {
        $htmlContent += (ConvertTo-HtmlTable -Data $regFlat -Columns @('RegistryKey','Name','Value','SecurityRelated') -HighlightColumn 'SecurityRelated' -HighlightValue 'True' -HighlightClass '')
    } else {
        $htmlContent += '<p class="empty">No registry settings found.</p>'
    }

    # -- Security Rules
    $htmlContent += @"

<h2 id="security-rules">Security Rules</h2>
<h3>Authorized Files / Hashes ($($authorizedFiles.Count))</h3>
"@
    if ($authorizedFiles.Count -gt 0) {
        $htmlContent += (ConvertTo-HtmlTable -Data ($authorizedFiles | Select-Object SourceFile, NodeName))
    } else {
        $htmlContent += '<p class="empty">None found in local cache.</p>'
    }

    $htmlContent += "<h3>Authorized Certificates ($($authorizedCerts.Count))</h3>"
    if ($authorizedCerts.Count -gt 0) {
        $htmlContent += (ConvertTo-HtmlTable -Data ($authorizedCerts | Select-Object SourceFile, NodeName, Publisher, Product))
    } else {
        $htmlContent += '<p class="empty">None found in local cache.</p>'
    }

    $htmlContent += "<h3>Authorized Owners ($($authorizedOwners.Count))</h3>"
    if ($authorizedOwners.Count -gt 0) {
        $htmlContent += (ConvertTo-HtmlTable -Data $authorizedOwners)
    } else {
        $htmlContent += '<p class="empty">None found in local cache.</p>'
    }

    $htmlContent += "<h3>Blocked Paths ($($blockedPaths.Count))</h3>"
    if ($blockedPaths.Count -gt 0) {
        $htmlContent += (ConvertTo-HtmlTable -Data $blockedPaths)
    } else {
        $htmlContent += '<p class="empty">None found in local cache.</p>'
    }

    # -- Components
    $htmlContent += @"

<h2 id="components">Installed Components</h2>
"@
    $componentData = @()
    foreach ($iwcPath in $iwcInstallPaths) {
        if (Test-Path $iwcPath) {
            Get-ChildItem -Path $iwcPath -Filter '*.exe' -ErrorAction SilentlyContinue | ForEach-Object {
                $componentData += [PSCustomObject]@{
                    Path    = $_.FullName
                    Name    = $_.Name
                    Version = $_.VersionInfo.ProductVersion
                }
            }
        }
    }
    if ($componentData.Count -gt 0) {
        $htmlContent += (ConvertTo-HtmlTable -Data $componentData -Columns @('Name','Version','Path'))
    } else {
        $htmlContent += '<p class="empty">No IWC executables found.</p>'
    }

    # -- Footer
    $htmlContent += @"

<div class="report-footer">
  <div>
    <div class="logo-text">IWC Allow List Audit</div>
    <div>Report v4.0 -- Get-IWCAllowListConfig.ps1</div>
  </div>
  <div style="text-align:right;">
    <div>$hostName</div>
    <div>$reportDate</div>
  </div>
</div>

</div><!-- /.container -->
</body>
</html>
"@

    # Write file
    $htmlFile = Join-Path $OutputPath 'IWC_AllowList_AuditReport.html'
    $htmlContent | Out-File -FilePath $htmlFile -Encoding ascii -Force
    Write-Host "  HTML report -> $htmlFile" -ForegroundColor Green
    Write-Host ""

    # Auto-open in default browser
    try {
        Start-Process $htmlFile -ErrorAction SilentlyContinue
        Write-Host "  Report opened in default browser." -ForegroundColor DarkGray
    } catch {
        Write-Host "  Could not auto-open report. Open manually: $htmlFile" -ForegroundColor DarkGray
    }
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
Write-Host "  Tip: Run with -ExportCsv and/or -ExportHtml to save results." -ForegroundColor DarkGray
Write-Host "       e.g. .\Get-IWCAllowListConfig.ps1 -ExportHtml" -ForegroundColor DarkGray
Write-Host "            .\Get-IWCAllowListConfig.ps1 -ExportCsv -ExportHtml" -ForegroundColor DarkGray
Write-Host ""
