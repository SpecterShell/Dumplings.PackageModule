# SPDX-License-Identifier: Apache-2.0
# Provider-neutral static installer detection and parser orchestration.

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

function Get-InstallerExeFamilyDefault {
  param ([Parameter(Mandatory)][string]$Family)
  if ($Script:InstallerFamilyProjectionProvider) {
    return & $Script:InstallerFamilyProjectionProvider $Family
  }

  # Standalone generic analysis records only behavior discovered by a parser. The empty mutable
  # shape lets family parsers add observed scope or switch evidence without assuming provider policy.
  [pscustomobject][ordered]@{
    InstallModes        = @()
    InstallerSwitches   = [ordered]@{}
    ExpectedReturnCodes = @()
    Notes               = @()
  }
}

function Invoke-InstallerDetector {
  <#
  .SYNOPSIS
    Run one installer detector and normalize success/failure output
  .PARAMETER Name
    The detector name
  .PARAMETER ScriptBlock
    The detector logic to run
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The detector name')]
    [string]$Name,

    [Parameter(Mandatory, HelpMessage = 'The detector logic to run')]
    [scriptblock]$ScriptBlock
  )

  try {
    [pscustomobject]@{
      Name        = $Name
      Success     = $true
      Result      = & $ScriptBlock
      Diagnostics = [object[]]@()
    }
  } catch {
    [pscustomobject]@{
      Name        = $Name
      Success     = $false
      Result      = $null
      Diagnostics = [object[]]@(
        New-InstallerDiagnostic -Id "InstallerDetection.$(($Name -replace '[^A-Za-z0-9]+', '.').Trim('.')).ParserRejected" -Source $Name -Message $_.Exception.Message -Kind Fallback -Areas Detection
      )
    }
  }
}

function Get-InstallerFileVersionEvidence {
  <#
  .SYNOPSIS
    Get version resource evidence from an installer file
  .PARAMETER File
    The installer file
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The installer file')]
    [System.IO.FileInfo]$File
  )

  $VersionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($File.FullName)
  [pscustomobject]@{
    FileDescription = $VersionInfo.FileDescription
    FileVersion     = $VersionInfo.FileVersion
    ProductName     = $VersionInfo.ProductName
    ProductVersion  = $VersionInfo.ProductVersion
    CompanyName     = $VersionInfo.CompanyName
    OriginalName    = $VersionInfo.OriginalFilename
  }
}

function Test-InstallerBytePrefix {
  <#
  .SYNOPSIS
    Test whether a byte array starts with a specific byte prefix
  .PARAMETER Bytes
    The byte array to test
  .PARAMETER Prefix
    The byte prefix to match
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The byte array to test')]
    [byte[]]$Bytes,

    [Parameter(Mandatory, HelpMessage = 'The byte prefix to match')]
    [byte[]]$Prefix
  )

  if ($Bytes.Length -lt $Prefix.Length) { return $false }
  for ($Index = 0; $Index -lt $Prefix.Length; $Index++) {
    if ($Bytes[$Index] -ne $Prefix[$Index]) { return $false }
  }

  return $true
}

function Read-InstallerHeader {
  <#
  .SYNOPSIS
    Read the first bytes from a file for magic-byte detection
  .PARAMETER File
    The file to read
  .PARAMETER Count
    The maximum number of bytes to read
  #>
  [OutputType([byte[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The file to read')]
    [System.IO.FileInfo]$File,

    [Parameter(HelpMessage = 'The maximum number of bytes to read')]
    [int]$Count = 4096
  )

  $ReadCount = [Math]::Min($Count, [int]$File.Length)
  if ($ReadCount -le 0) { return , ([byte[]]::new(0)) }

  $Stream = [System.IO.File]::Open($File.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
  try {
    return , (Read-PEFileBytes -Stream $Stream -Offset 0 -Count $ReadCount)
  } finally {
    $Stream.Dispose()
  }
}

function Read-InstallerCfbRootStorageClassId {
  <#
  .SYNOPSIS
    Read the root storage CLSID from a Compound File Binary file
  .PARAMETER File
    The CFB file to inspect
  #>
  [OutputType([guid])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The CFB file to inspect')]
    [System.IO.FileInfo]$File
  )

  $Header = Read-InstallerHeader -File $File -Count 512
  $CfbMagic = [byte[]](0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1)
  if (-not (Test-InstallerBytePrefix -Bytes $Header -Prefix $CfbMagic)) { return $null }

  $SectorShift = [System.BitConverter]::ToUInt16($Header, 0x1E)
  $SectorSize = 1 -shl $SectorShift
  $FirstDirectorySector = [System.BitConverter]::ToUInt32($Header, 0x30)
  if ($FirstDirectorySector -eq [uint32]::MaxValue) { return $null }

  # The first directory entry is the root storage; its CLSID distinguishes MSI/MSP/MST.
  $RootDirectoryOffset = ([int64]$FirstDirectorySector + 1) * $SectorSize
  $Stream = [System.IO.File]::Open($File.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
  try {
    $RootDirectoryEntry = Read-PEFileBytes -Stream $Stream -Offset $RootDirectoryOffset -Count 128
    if ($RootDirectoryEntry.Length -lt 96) { return $null }

    $ClassIdBytes = [byte[]]::new(16)
    [Array]::Copy($RootDirectoryEntry, 0x50, $ClassIdBytes, 0, 16)
    [guid]::new($ClassIdBytes)
  } finally {
    $Stream.Dispose()
  }
}

function Get-InstallerCfbTypeEvidence {
  <#
  .SYNOPSIS
    Classify a Windows Installer CFB file by its root storage CLSID
  .PARAMETER File
    The CFB file to classify
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The CFB file to classify')]
    [System.IO.FileInfo]$File
  )

  $ClassId = Read-InstallerCfbRootStorageClassId -File $File
  $ClassIdText = if ($ClassId) { $ClassId.ToString('B').ToUpperInvariant() } else { $null }
  $Format = switch ($ClassIdText) {
    '{000C1084-0000-0000-C000-000000000046}' { 'Windows Installer Package' }
    '{000C1086-0000-0000-C000-000000000046}' { 'Windows Installer Patch' }
    '{000C1082-0000-0000-C000-000000000046}' { 'Windows Installer Transform' }
    default { 'Compound File Binary' }
  }
  $Type = switch ($ClassIdText) {
    '{000C1084-0000-0000-C000-000000000046}' { 'MSI' }
    '{000C1086-0000-0000-C000-000000000046}' { 'MSP' }
    '{000C1082-0000-0000-C000-000000000046}' { 'MST' }
    default { 'WindowsInstallerDatabase' }
  }

  [pscustomobject]@{
    Type    = $Type
    Format  = $Format
    ClassId = $ClassIdText
    Note    = 'Windows Installer CFB root storage CLSID, not filename extension, identifies MSI/MSP/MST.'
  }
}

function Get-InstallerZipTypeEvidence {
  <#
  .SYNOPSIS
    Inspect ZIP entries to distinguish archives from MSIX/AppX packages
  .PARAMETER Path
    The ZIP-like file path
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The ZIP-like file path')]
    [string]$Path
  )

  $Archive = Get-InstallerArchive -Path $Path
  try {
    $Entries = @(Get-InstallerArchiveEntry -Archive $Archive)
    $EntryNames = @($Entries.FullName)
    $SampleEntries = @($EntryNames | Select-Object -First 250)
    $HasAppxManifest = $EntryNames -contains 'AppxManifest.xml'
    $HasBundleManifest = $EntryNames -contains 'AppxMetadata/AppxBundleManifest.xml'
    $HasAppxSignature = $EntryNames -contains 'AppxSignature.p7x'

    [pscustomobject]@{
      EntryCount        = $Entries.Count
      SampleEntries     = $SampleEntries
      HasAppxManifest   = $HasAppxManifest
      HasBundleManifest = $HasBundleManifest
      HasAppxSignature  = $HasAppxSignature
      IsAppxMsixFamily  = $HasAppxManifest -or $HasBundleManifest -or $HasAppxSignature
    }
  } finally {
    $Archive.Dispose()
  }
}

function Get-InstallerPeTypeEvidence {
  <#
  .SYNOPSIS
    Inspect PE layout evidence for EXE-family routing
  .PARAMETER Path
    The PE file path
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The PE file path')]
    [string]$Path
  )

  $Layout = Get-PELayout -Path $Path
  if (-not $Layout) { return $null }

  $SectionNames = @($Layout.Sections | Select-Object -ExpandProperty Name)
  [pscustomobject]@{
    PeOffset          = $Layout.PeOffset
    Machine           = ('0x{0:X4}' -f $Layout.Machine)
    MachineName       = $Layout.MachineName
    OptionalHeader    = $Layout.OptionalHeaderFormat
    SectionNames      = $SectionNames
    HasResourceTable  = $Layout.ResourceOffset -ge 0
    HasWixBurnSection = $SectionNames -contains '.wixburn'
  }
}

function Get-InstallerPortableEvidence {
  <#
  .SYNOPSIS
    Build portable executable architecture and runtime evidence
  .PARAMETER Path
    The PE file path
  .PARAMETER RelatedFile
    Related PE and sidecar files
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The PE file path')]
    [string]$Path,

    [Parameter(HelpMessage = 'Related PE and sidecar files')]
    [string[]]$RelatedFile = @()
  )

  $RelatedPEFiles = @($RelatedFile | Where-Object {
      try {
        $RelatedLayout = Get-PELayout -Path $_
        $null -ne $RelatedLayout
      } catch {
        $false
      }
    })
  $ArchitectureInfo = Get-PEArchitectureInfo -Path $Path -RelatedFile $RelatedPEFiles
  $DependencyInfo = Get-PEDependencyInfo -Path $Path -RelatedFile $RelatedFile

  # Tauri applications retain at least one inexpensive framework literal in
  # normal generated builds. Gate the complete asset-map scan on those markers
  # so ordinary portable PEs do not pay the decompression-validation cost.
  $TauriExecutableInfo = $null
  $TauriMarkerPatterns = @('tauri://localhost', '__TAURI_INTERNALS__', '__TAURI_BUNDLE_TYPE_VAR_')
  foreach ($MarkerPattern in $TauriMarkerPatterns) {
    if (@(Find-BinaryPattern -Path $Path -Pattern ([Text.Encoding]::ASCII.GetBytes($MarkerPattern)) -Maximum 1).Count -gt 0) {
      try { $TauriExecutableInfo = Get-TauriExecutableInfo -Path $Path -ErrorAction Stop } catch { }
      break
    }
  }
  $Diagnostics = [Collections.Generic.List[object]]::new()
  foreach ($Diagnostic in @($ArchitectureInfo.Diagnostics) + @($DependencyInfo.Diagnostics) + @($TauriExecutableInfo.Diagnostics)) {
    if ($null -ne $Diagnostic) { $Diagnostics.Add($Diagnostic) }
  }
  [pscustomobject]@{
    ArchitectureInfo                = $ArchitectureInfo
    DependencyInfo                  = $DependencyInfo
    TauriExecutableInfo             = $TauriExecutableInfo
    RecommendedWinGetArchitecture   = $ArchitectureInfo.RecommendedWinGetArchitecture
    RecommendedWinGetArchitectures  = $ArchitectureInfo.RecommendedWinGetArchitectures
    RecommendedPackageDependencies  = $DependencyInfo.RecommendedPackageDependencies
    RecommendedPackageDependencyIds = $DependencyInfo.RecommendedPackageDependencyIds
    Diagnostics                     = @(Merge-InstallerDiagnostics -Diagnostic $Diagnostics.ToArray())
  }
}

function Get-InstallerPackageSignatureEvidence {
  <#
  .SYNOPSIS
    Validate an MSIX/AppX-family package signature against local trust roots
  .PARAMETER Path
    The MSIX/AppX-family package path
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The MSIX/AppX-family package path')]
    [string]$Path
  )

  try {
    $SignatureSha256 = Get-MSIXSignatureHash -Path $Path -ErrorAction SilentlyContinue
  } catch {
    $SignatureSha256 = $null
  }
  $AuthenticodeSignature = Get-AuthenticodeSignature -LiteralPath $Path
  $SignerCertificate = $AuthenticodeSignature.SignerCertificate
  $IsSigned = [bool]$SignatureSha256 -or ($null -ne $SignerCertificate)
  $IsTrusted = $AuthenticodeSignature.Status -eq [System.Management.Automation.SignatureStatus]::Valid

  [pscustomobject]@{
    IsSigned           = $IsSigned
    IsTrusted          = $IsTrusted
    Status             = $AuthenticodeSignature.Status.ToString()
    StatusMessage      = $AuthenticodeSignature.StatusMessage
    SignatureSha256    = $SignatureSha256
    SignerSubject      = if ($SignerCertificate) { $SignerCertificate.Subject } else { $null }
    SignerThumbprint   = if ($SignerCertificate) { $SignerCertificate.Thumbprint } else { $null }
    TimeStamperSubject = if ($AuthenticodeSignature.TimeStamperCertificate) { $AuthenticodeSignature.TimeStamperCertificate.Subject } else { $null }
    RequiredAction     = if (-not $IsSigned) { 'Reject: MSIX/AppX-family packages must contain a signature.' } elseif (-not $IsTrusted) { 'Reject: MSIX/AppX-family package signature is not valid and trusted by this system.' } else { $null }
  }
}

function Get-InstallerFileTypeEvidence {
  <#
  .SYNOPSIS
    Detect installer container type from magic bytes and static content evidence
  .PARAMETER File
    The file to classify
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The file to classify')]
    [System.IO.FileInfo]$File
  )

  $Header = Read-InstallerHeader -File $File
  $HeaderHex = ($Header | Select-Object -First 16 | ForEach-Object { $_.ToString('X2') }) -join ' '
  $Extension = $File.Extension.ToLowerInvariant()

  $CfbMagic = [byte[]](0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1)
  if (Test-InstallerBytePrefix -Bytes $Header -Prefix $CfbMagic) {
    $CfbEvidence = Get-InstallerCfbTypeEvidence -File $File
    return [pscustomobject]@{
      Type       = $CfbEvidence.Type
      Confidence = 'high'
      Magic      = 'D0 CF 11 E0 A1 B1 1A E1'
      Extension  = $Extension
      Evidence   = $CfbEvidence
    }
  }

  $ZipMagics = @(
    [byte[]](0x50, 0x4B, 0x03, 0x04),
    [byte[]](0x50, 0x4B, 0x05, 0x06),
    [byte[]](0x50, 0x4B, 0x07, 0x08)
  )
  foreach ($ZipMagic in $ZipMagics) {
    if (Test-InstallerBytePrefix -Bytes $Header -Prefix $ZipMagic) {
      $ZipEvidence = Get-InstallerZipTypeEvidence -Path $File.FullName -ErrorAction SilentlyContinue
      $Type = if ($ZipEvidence -and $ZipEvidence.IsAppxMsixFamily) { 'MSIXAppX' } else { 'ZipArchive' }
      return [pscustomobject]@{
        Type       = $Type
        Confidence = 'high'
        Magic      = ($ZipMagic | ForEach-Object { $_.ToString('X2') }) -join ' '
        Extension  = $Extension
        Evidence   = $ZipEvidence
      }
    }
  }

  if (Test-InstallerBytePrefix -Bytes $Header -Prefix ([byte[]](0x4D, 0x5A))) {
    $PeEvidence = try { Get-InstallerPeTypeEvidence -Path $File.FullName } catch { $null }
    return [pscustomobject]@{
      Type       = 'PE'
      Confidence = if ($PeEvidence) { 'high' } else { 'medium' }
      Magic      = '4D 5A'
      Extension  = $Extension
      Evidence   = $PeEvidence
    }
  }

  $HeaderText = [System.Text.Encoding]::UTF8.GetString($Header).TrimStart([char]0xFEFF, [char]0xFFFE, [char]0x200B, [char]0)
  if ($HeaderText -match '^\s*<' -and $HeaderText -match '<\s*AppInstaller\b') {
    return [pscustomobject]@{
      Type       = 'AppInstaller'
      Confidence = 'high'
      Magic      = 'XML AppInstaller'
      Extension  = $Extension
      Evidence   = [pscustomobject]@{ Note = '.appinstaller is not accepted by winget-pkgs; resolve the referenced AppX/MSIX package.' }
    }
  }

  # Download servers sometimes return a branded error or landing page with
  # HTTP 200. Treat an explicit HTML document as content, not an unknown
  # installer, so declared-family validation can report a definite mismatch.
  if ($HeaderText -match '(?is)^\s*(?:<\?xml\b[^>]*>\s*)?(?:<!doctype\s+html\b|<html(?:\s|>)|<head(?:\s|>)|<body(?:\s|>))') {
    return [pscustomobject]@{
      Type       = 'HTMLDocument'
      Confidence = 'high'
      Magic      = 'HTML document'
      Extension  = $Extension
      Evidence   = [pscustomobject]@{ Note = 'The downloaded response is an HTML document rather than an installer.' }
    }
  }

  [pscustomobject]@{
    Type       = 'Unknown'
    Confidence = 'low'
    Magic      = $HeaderHex
    Extension  = $Extension
    Evidence   = $null
  }
}

function Read-InstallerStringWindows {
  <#
  .SYNOPSIS
    Read bounded ASCII and UTF-16LE string windows from a file
  .PARAMETER File
    The file to scan
  .PARAMETER Budget
    The total byte budget across all scan windows
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The file to scan')]
    [System.IO.FileInfo]$File,

    [Parameter(Mandatory, HelpMessage = 'The total byte budget across all scan windows')]
    [int64]$Budget
  )

  $WindowCount = [Math]::Min(5, [Math]::Max(1, [int][Math]::Ceiling($File.Length / [Math]::Max(1, ($Budget / 5)))))
  $WindowSize = [Math]::Max(2048, [int64]($Budget / $WindowCount))
  $WindowSize = [Math]::Min($WindowSize, $File.Length)
  $Buffer = [byte[]]::new([int]$WindowSize)
  $Chunks = [System.Collections.Generic.List[string]]::new()
  $Offsets = [System.Collections.Generic.SortedSet[int64]]::new()
  if ($WindowCount -eq 1 -or $File.Length -le $WindowSize) {
    $null = $Offsets.Add(0)
  } else {
    for ($Index = 0; $Index -lt $WindowCount; $Index++) {
      $Offset = [int64][Math]::Round((($File.Length - $WindowSize) * $Index) / ($WindowCount - 1))
      $null = $Offsets.Add($Offset)
    }
  }

  $Stream = [System.IO.File]::Open($File.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
  try {
    foreach ($Offset in $Offsets) {
      $Stream.Seek($Offset, [System.IO.SeekOrigin]::Begin) | Out-Null
      [Array]::Clear($Buffer, 0, $Buffer.Length)
      $Read = $Stream.Read($Buffer, 0, $Buffer.Length)
      if ($Read -gt 0) {
        $Chunks.Add([System.Text.Encoding]::ASCII.GetString($Buffer, 0, $Read))
        $Chunks.Add([System.Text.Encoding]::Unicode.GetString($Buffer, 0, $Read - ($Read % 2)))
      }
    }
  } finally {
    $Stream.Dispose()
  }

  return ($Chunks -join "`n")
}

function Test-InstallerTextPattern {
  <#
  .SYNOPSIS
    Return all patterns present in a text block
  .PARAMETER Text
    The text block to scan
  .PARAMETER Patterns
    The case-insensitive patterns to locate
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The text block to scan')]
    [string]$Text,

    [Parameter(Mandatory, HelpMessage = 'The case-insensitive patterns to locate')]
    [string[]]$Patterns
  )

  $MatchedPatterns = foreach ($Pattern in $Patterns) {
    if ($Text.IndexOf($Pattern, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
      $Pattern
    }
  }

  @($MatchedPatterns)
}

function Get-InstallerGenericExeFamilyCandidate {
  <#
  .SYNOPSIS
    Detect generic EXE family candidates from bounded string windows
  .PARAMETER File
    The installer file
  .PARAMETER Budget
    The scan byte budget
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The installer file')]
    [System.IO.FileInfo]$File,

    [Parameter(Mandatory, HelpMessage = 'The scan byte budget')]
    [int64]$Budget,

    [Parameter(HelpMessage = 'A previously collected bounded string scan')]
    [AllowEmptyString()][string]$Text
  )

  if (-not $PSBoundParameters.ContainsKey('Text')) { $Text = Read-InstallerStringWindows -File $File -Budget $Budget }
  $Families = @(
    @{ Name = 'Advanced Installer'; Patterns = @('Advanced Installer', 'aicustact', 'AI_SETUPEXEPATH') },
    @{ Name = 'InstallShield'; Patterns = @('InstallShield', 'ISSetup.dll', 'InstallScript', 'setup.inx', 'ISScript') },
    @{ Name = 'Velopack'; Patterns = @('Velopack', 'vpk_', 'RELEASES.json') },
    @{ Name = 'Squirrel'; Patterns = @('Squirrel', 'SquirrelSetup', 'Update.exe', '.nupkg', 'RELEASES') },
    @{ Name = 'Zero Install'; Patterns = @('ZeroInstall.BootstrapConfig.ini', 'Downloads and runs Zero Install', 'Downloads and integrates') },
    @{ Name = 'Setup Factory'; Patterns = @('Setup Factory', 'Indigo Rose', 'IRSetup') },
    @{ Name = 'InstallAnywhere'; Patterns = @('InstallAnywhere', 'Zero G', 'lax.nl.current.vm', 'com.zerog', 'IAClasses.zip', 'Execute.zip', 'InstallScript.iap_xml') },
    @{ Name = 'InstallAware'; Patterns = @('InstallAware', 'MimarSinan') },
    @{ Name = 'Actual Installer'; Patterns = @('Actual Installer', 'actualinstaller', 'aisetup.ini', 'Englishai.lng') },
    @{ Name = 'DeployMaster'; Patterns = @('DeployMaster', 'DeployMaster Installation', 'deploymaster.com') },
    @{ Name = '7z SFX'; Patterns = @('7zS.sfx', '7zSD.sfx', '7-Zip SFX', ';!@Install@!UTF-8!', ';!@InstallEnd@!') },
    @{ Name = 'WinRAR GUI SFX'; Patterns = @('WinRAR SFX', 'WinRAR self-extracting archive', 'RarSFX', 'SFX module by Alexander Roshal') },
    @{ Name = 'InstallMate'; Patterns = @('InstallMate', 'Tarma Installer', 'Tarma Software') },
    @{ Name = 'QSetup'; Patterns = @('QSetup', 'Pantaray') },
    @{ Name = 'install4j'; Patterns = @('install4j', 'ej-technologies', '.install4j') },
    @{ Name = 'dotNetInstaller'; Patterns = @('dotNetInstaller', 'dotNetInstaller Bootstrapper') },
    @{ Name = 'IExpress'; Patterns = @('IExpress', 'WExtract', 'WEXTRACT', 'RunProgram=', 'InstallPrompt=', 'Extracting files') },
    @{ Name = 'Wise'; Patterns = @('WiseForWindowsInstaller', 'Wise for Windows Installer', 'WISE_SETUP_EXE_PATH', 'Wise Installation Wizard') },
    @{ Name = 'Chromium Setup'; Patterns = @('chrome.packed.7z', 'updater.packed.7z', 'Gact2.0Omaha', '--system-level', '--install-archive') },
    @{ Name = 'InstallBuilder'; Patterns = @('InstallBuilder', 'BitRock InstallBuilder', 'BitRock', 'unattendedmodeui', '--mode unattended') },
    @{ Name = 'Paquet Builder'; Patterns = @('Paquet Builder', 'G.D.G. Software', 'installpackbuilder.com', 'PaquetBuilder') },
    @{ Name = 'CreateInstall'; Patterns = @('CreateInstall', 'Novostrim', '.ciq') },
    @{ Name = 'InstallForge'; Patterns = @('InstallForge', 'InstallForge Setup', 'installforge.net') },
    @{ Name = 'Qt Installer Framework'; Patterns = @('Qt Installer Framework', 'org.qtproject.ifw', 'installerbase', 'MaintenanceTool') }
  )

  foreach ($Family in $Families) {
    $MatchedMarkers = Test-InstallerTextPattern -Text $Text -Patterns $Family.Patterns
    if ($MatchedMarkers.Count -gt 0) {
      $Confidence = if ($MatchedMarkers.Count -gt 1) { 'medium' } else { 'low' }
      [pscustomobject]@{
        Family                  = $Family.Name
        Confidence              = $Confidence
        MatchedMarkers          = $MatchedMarkers
        SuggestedManifestFields = Get-InstallerExeFamilyDefault -Family $Family.Name
      }
    }
  }
}

function Get-InstallerStructuralExeFamilyCandidate {
  <#
  .SYNOPSIS
    Detect installer families from bounded structural signatures before invoking parsers
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][IO.FileInfo]$File)

  $Seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $Layout = Get-PELayout -Path $File.FullName -ErrorAction SilentlyContinue
  if ($Layout -and @($Layout.Sections.Name) -contains '.wixburn' -and $Seen.Add('Burn')) {
    [pscustomobject]@{ Family = 'Burn'; Confidence = 'high'; MatchedMarkers = @('.wixburn PE section'); SuggestedManifestFields = [pscustomobject]@{ InstallerType = 'burn' } }
  }

  # InstallShield 3 distributed a reusable setup32 engine without an embedded
  # package overlay. Exact version-resource identity is structural runtime
  # evidence and is intentionally narrower than an InstallShield text marker.
  $VersionInfo = [Diagnostics.FileVersionInfo]::GetVersionInfo($File.FullName)
  if ($VersionInfo.ProductName -ieq 'InstallShield' -and
    $VersionInfo.FileDescription -ieq 'InstallShield Engine EXE' -and
    $VersionInfo.CompanyName -match '(?i)^InstallShield Corporation' -and
    $VersionInfo.ProductVersion -match '^3(?:\.|$)' -and
    $Seen.Add('InstallShield')) {
    [pscustomobject]@{ Family = 'InstallShield'; Confidence = 'high'; MatchedMarkers = @('InstallShield 3 setup32 PE version identity'); SuggestedManifestFields = Get-InstallerExeFamilyDefault -Family 'InstallShield' }
  }

  $Resources = @(Get-PEResourceInfo -Path $File.FullName -MaximumResources 16384 -ErrorAction SilentlyContinue)
  if ($Resources | Where-Object { $_.TypeId -eq 10 -and $_.Id -eq 11111 } | Select-Object -First 1) {
    if ($Seen.Add('Inno Setup')) {
      [pscustomobject]@{ Family = 'Inno Setup'; Confidence = 'high'; MatchedMarkers = @('RCDATA/11111 loader offset table'); SuggestedManifestFields = [pscustomobject]@{ InstallerType = 'inno' } }
    }
  }

  # Zero Install launchers are managed PEs with a named embedded bootstrap
  # configuration. Requiring the CLR ManifestResource row avoids classifying
  # unrelated .NET applications that merely mention Zero Install in strings.
  $ManagedConfig = Get-PEManagedResourceInfo -Path $File.FullName -Name 'ZeroInstall.BootstrapConfig.ini' -MaximumResources 16384 -MaximumResourceBytes 1048576 -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($ManagedConfig -and $Seen.Add('Zero Install')) {
    [pscustomobject]@{ Family = 'Zero Install'; Confidence = 'high'; MatchedMarkers = @('CLR ManifestResource ZeroInstall.BootstrapConfig.ini'); SuggestedManifestFields = Get-InstallerExeFamilyDefault -Family 'Zero Install' }
  }

  # Kachina is a native Tauri executable with a validated JSON-bearing TLV
  # stream. Route it before managed MicaSetup and generic Tauri evidence.
  if ((Test-KachinaInstaller -Path $File.FullName) -and $Seen.Add('Kachina')) {
    [pscustomobject]@{ Family = 'Kachina'; Confidence = 'high'; MatchedMarkers = @('PE overlay Kachina TLV stream + compiled configuration'); SuggestedManifestFields = Get-InstallerExeFamilyDefault -Family 'Kachina' }
  }

  # MicaSetup detection requires both its managed host model and the WPF payload
  # stream. This rejects ordinary WPF applications and native Kachina installers.
  if ((Test-MicaSetupInstaller -Path $File.FullName) -and $Seen.Add('MicaSetup')) {
    [pscustomobject]@{ Family = 'MicaSetup'; Confidence = 'high'; MatchedMarkers = @('CLR MicaSetup configuration host + WPF resources/setups/publish.7z'); SuggestedManifestFields = Get-InstallerExeFamilyDefault -Family 'MicaSetup' }
  }

  $NsisSignature = [byte[]](0xEF, 0xBE, 0xAD, 0xDE) + [Text.Encoding]::ASCII.GetBytes('NullsoftInst')
  $SignatureScanLength = [Math]::Min($File.Length, 67108864L)
  if ((Find-BinaryPattern -Path $File.FullName -Pattern $NsisSignature -Length $SignatureScanLength -Maximum 1).Count -gt 0 -and $Seen.Add('NSIS/Nullsoft')) {
    [pscustomobject]@{ Family = 'NSIS/Nullsoft'; Confidence = 'high'; MatchedMarkers = @('DEADBEEF + NullsoftInst'); SuggestedManifestFields = [pscustomobject]@{ InstallerType = 'nullsoft' } }
  }

  $QtCookie = [byte[]](0xF8, 0x68, 0xD6, 0x99, 0x1C, 0x0A, 0x63, 0xC2)
  $TailLength = [Math]::Min($File.Length, 1048576L)
  if ((Find-BinaryPattern -Path $File.FullName -Pattern $QtCookie -StartOffset ($File.Length - $TailLength) -Length $TailLength -Maximum 1 -Reverse).Count -gt 0 -and $Seen.Add('Qt Installer Framework')) {
    [pscustomobject]@{ Family = 'Qt Installer Framework'; Confidence = 'high'; MatchedMarkers = @('Qt IFW magic cookie'); SuggestedManifestFields = Get-InstallerExeFamilyDefault -Family 'Qt Installer Framework' }
  }

  $AdvancedInstallerMagic = [Text.Encoding]::ASCII.GetBytes('ADVINSTSFX')
  if ((Find-BinaryPattern -Path $File.FullName -Pattern $AdvancedInstallerMagic -Maximum 1 -Reverse).Count -gt 0) {
    # ADVINSTSFX can occur in unrelated payload bytes. Classification requires the GPL parser to
    # validate the complete footer, catalog records, payload ranges, and selected format profile.
    $FormatInfo = Get-AdvancedInstallerFormatInfo -Path $File.FullName -ErrorAction SilentlyContinue
    if ($FormatInfo.IsAdvancedInstaller -and $FormatInfo.IsSupported -and $Seen.Add('Advanced Installer')) {
      [pscustomobject]@{
        Family                  = 'Advanced Installer'
        Confidence              = 'high'
        MatchedMarkers          = @("$($FormatInfo.FormatProfileId): $($FormatInfo.FooterRoute) + $($FormatInfo.CatalogRoute)")
        FormatInfo              = $FormatInfo
        SuggestedManifestFields = Get-InstallerExeFamilyDefault -Family 'Advanced Installer'
      }
    }
  }

  $InstallBuilderProjectMarker = [Text.Encoding]::ASCII.GetBytes('project.xml')
  if ((Find-BinaryPattern -Path $File.FullName -Pattern $InstallBuilderProjectMarker -Maximum 1).Count -gt 0 -and $Seen.Add('InstallBuilder')) {
    [pscustomobject]@{ Family = 'InstallBuilder'; Confidence = 'medium'; MatchedMarkers = @('embedded project.xml record'); SuggestedManifestFields = Get-InstallerExeFamilyDefault -Family 'InstallBuilder' }
  }
}

function ConvertTo-InstallerFamilyEvidence {
  <#
  .SYNOPSIS
    Add provenance and validation state to an installer-family candidate.
  .PARAMETER Candidate
    Candidate produced by a structural detector or bounded text scan.
  .PARAMETER EvidenceKind
    Whether the candidate came from a structured binary check or a text heuristic.
  .PARAMETER IsOuterContainer
    Indicates that the structural marker identifies the outer installer container
    without requiring the metadata parser to complete successfully.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Candidate,
    [Parameter(Mandatory)][ValidateSet('Structural', 'Heuristic')][string]$EvidenceKind,
    [switch]$IsOuterContainer
  )

  [pscustomobject][ordered]@{
    Family                  = [string]$Candidate.Family
    Confidence              = [string]$Candidate.Confidence
    EvidenceKind            = $EvidenceKind
    ValidationStatus        = $IsOuterContainer ? 'ConfirmedStructure' : 'RoutingHint'
    IsOuterContainer        = $IsOuterContainer.IsPresent
    MatchedMarkers          = @($Candidate.MatchedMarkers)
    SuggestedManifestFields = $Candidate.SuggestedManifestFields
  }
}

function Get-InstallerParserNameForFamily {
  <#
  .SYNOPSIS
    Map analyzer family aliases to the parser result that validates them.
  .PARAMETER Family
    Candidate family name emitted by a structural or heuristic detector.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][string]$Family)

  switch ($Family) {
    'Inno Setup' { 'Inno' }
    'NSIS/Nullsoft' { 'NSIS' }
    { $_ -cin @('Squirrel', 'Velopack') } { 'Squirrel/Velopack' }
    default { $Family }
  }
}

function Resolve-InstallerFamilyEvidence {
  <#
  .SYNOPSIS
    Separate confirmed installer families from rejected and unvalidated routes.
  .PARAMETER Candidates
    Annotated structural and heuristic candidates used to route parsers.
  .PARAMETER ParserResults
    Parser invocation results produced for those candidates.
  .OUTPUTS
    One object containing DetectedFamilies, RoutingHints, and RejectedCandidates.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Candidates,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$ParserResults
  )

  $Detected = [Collections.Generic.List[object]]::new()
  $Rejected = [Collections.Generic.List[object]]::new()
  $ConfirmedParserNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

  foreach ($Candidate in $Candidates) {
    $ParserName = Get-InstallerParserNameForFamily -Family $Candidate.Family
    $MatchingRuns = @($ParserResults | Where-Object { $_.Name -ceq $ParserName })
    $SuccessfulRun = $MatchingRuns | Where-Object { $_.Success -and $_.Result } | Select-Object -First 1

    if ($SuccessfulRun) {
      # A parser success validates the family even when the initial route came
      # from a weak marker such as .ciq, RELEASES, or Update.exe.
      $null = $ConfirmedParserNames.Add($ParserName)
      $ResultFamilyProperty = $SuccessfulRun.Result.PSObject.Properties['Family']
      $ResultFamily = if ($null -ne $ResultFamilyProperty -and -not [string]::IsNullOrWhiteSpace([string]$ResultFamilyProperty.Value)) {
        [string]$ResultFamilyProperty.Value
      } else {
        [string]$Candidate.Family
      }
      $ResultConfidenceProperty = $SuccessfulRun.Result.PSObject.Properties['Confidence']
      $Detected.Add([pscustomobject][ordered]@{
          Family                  = $ResultFamily
          Confidence              = $null -eq $ResultConfidenceProperty ? 'high' : [string]$ResultConfidenceProperty.Value
          EvidenceKind            = 'Parser'
          ValidationStatus        = 'ConfirmedParser'
          IsOuterContainer        = $true
          ParserName              = $ParserName
          MatchedMarkers          = @($Candidate.MatchedMarkers)
          SuggestedManifestFields = $SuccessfulRun.Result.SuggestedManifestFields
        })
      continue
    }

    # Some signatures, such as a .wixburn section or the Advanced Installer
    # footer, identify the outer container independently from metadata decoding.
    if ($Candidate.IsOuterContainer) {
      $Detected.Add($Candidate)
    }

    $FailedRun = $MatchingRuns | Where-Object { $_.Success -eq $false -and @($_.Diagnostics).Count } | Select-Object -First 1
    if ($FailedRun) {
      $FailureDiagnostics = if ($Candidate.IsOuterContainer) {
        foreach ($Diagnostic in @($FailedRun.Diagnostics)) {
          $OriginalId = [string]$Diagnostic.Id
          New-InstallerDiagnostic `
            -Id "InstallerDetection.$(($Candidate.Family -replace '[^A-Za-z0-9]+', '.').Trim('.')).ConfirmedParserFailure" `
            -Source $ParserName `
            -Message ([string]$Diagnostic.Message) `
            -Kind Incomplete `
            -Areas Detection, Metadata `
            -AffectedFields InstallerType `
            -Evidence ([ordered]@{
              Family               = [string]$Candidate.Family
              Confidence           = [string]$Candidate.Confidence
              EvidenceKind         = [string]$Candidate.EvidenceKind
              MatchedMarkers       = [string[]]@($Candidate.MatchedMarkers)
              OriginalDiagnosticId = $OriginalId
            })
        }
      } else {
        [object[]]@($FailedRun.Diagnostics)
      }
      $Rejected.Add([pscustomobject][ordered]@{
          Family                  = [string]$Candidate.Family
          Confidence              = [string]$Candidate.Confidence
          EvidenceKind            = [string]$Candidate.EvidenceKind
          ValidationStatus        = 'RejectedByParser'
          IsOuterContainer        = [bool]$Candidate.IsOuterContainer
          ParserName              = $ParserName
          MatchedMarkers          = @($Candidate.MatchedMarkers)
          SuggestedManifestFields = $Candidate.SuggestedManifestFields
          Diagnostics             = [object[]]@($FailureDiagnostics)
        })
    }
  }

  # A parser can occasionally be invoked without an equivalent candidate alias.
  # Preserve its successful structured result as confirmed family evidence.
  foreach ($ParserResult in @($ParserResults | Where-Object { $_.Success -and $_.Result })) {
    $ResultFamilyProperty = $ParserResult.Result.PSObject.Properties['Family']
    if ($null -eq $ResultFamilyProperty -or [string]::IsNullOrWhiteSpace([string]$ResultFamilyProperty.Value)) { continue }
    $Family = [string]$ResultFamilyProperty.Value
    if ($Detected | Where-Object { $_.Family -ceq $Family } | Select-Object -First 1) { continue }
    $null = $ConfirmedParserNames.Add([string]$ParserResult.Name)
    $ResultConfidenceProperty = $ParserResult.Result.PSObject.Properties['Confidence']
    $Detected.Add([pscustomobject][ordered]@{
        Family                  = $Family
        Confidence              = $null -eq $ResultConfidenceProperty ? 'high' : [string]$ResultConfidenceProperty.Value
        EvidenceKind            = 'Parser'
        ValidationStatus        = 'ConfirmedParser'
        IsOuterContainer        = $true
        ParserName              = [string]$ParserResult.Name
        MatchedMarkers          = @()
        SuggestedManifestFields = $ParserResult.Result.SuggestedManifestFields
      })
  }

  $DetectedFamilies = @($Detected | Group-Object Family | ForEach-Object {
      $_.Group | Sort-Object { if ($_.ValidationStatus -ceq 'ConfirmedParser') { 0 } else { 1 } } | Select-Object -First 1
    })
  $RoutingHints = @($Candidates | Where-Object {
      -not $_.IsOuterContainer -and -not $ConfirmedParserNames.Contains((Get-InstallerParserNameForFamily -Family $_.Family))
    } | Group-Object Family | ForEach-Object {
      $_.Group | Sort-Object { if ($_.Confidence -ceq 'high') { 0 } elseif ($_.Confidence -ceq 'medium') { 1 } else { 2 } } | Select-Object -First 1
    })

  [pscustomobject]@{
    DetectedFamilies   = $DetectedFamilies
    RoutingHints       = $RoutingHints
    RejectedCandidates = @($Rejected)
  }
}

function Get-InstallerWrapperDiagnostic {
  <#
  .SYNOPSIS
    Detect NSIS/Inno wrapper evidence from bounded string windows
  .PARAMETER File
    The installer file
  .PARAMETER Budget
    The scan byte budget
  .PARAMETER ParserRuns
    The parser result records for the installer
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The installer file')]
    [System.IO.FileInfo]$File,

    [Parameter(Mandatory, HelpMessage = 'The scan byte budget')]
    [int64]$Budget,

    [Parameter(Mandatory, HelpMessage = 'The parser result records for the installer')]
    [AllowEmptyCollection()][object[]]$ParserRuns,

    [Parameter(HelpMessage = 'A previously collected bounded string scan')]
    [AllowEmptyString()][string]$Text
  )

  $OuterInstallers = @($ParserRuns | Where-Object {
      $_.Success -and ($_.Name -eq 'NSIS' -or $_.Name -eq 'Inno')
    })
  if ($OuterInstallers.Count -eq 0) { return }

  if (-not $PSBoundParameters.ContainsKey('Text')) { $Text = Read-InstallerStringWindows -File $File -Budget $Budget }
  $MsiPayloadMarkers = Test-InstallerTextPattern -Text $Text -Patterns @(
    '.msi',
    '.msp',
    '.msu',
    'msiexec',
    'Windows Installer',
    'WindowsInstaller',
    'ProductCode',
    'UpgradeCode',
    'MsiPackage'
  )
  $NestedExeMarkers = Test-InstallerTextPattern -Text $Text -Patterns @(
    'setup.exe',
    'installer.exe',
    'install.exe',
    'bootstrapper.exe'
  )
  $LaunchMarkers = Test-InstallerTextPattern -Text $Text -Patterns @(
    'ExecWait',
    'ShellExec',
    'nsExec::Exec',
    '$PLUGINSDIR',
    '{tmp}',
    '[Run]',
    'Filename:',
    'runascurrentuser'
  )

  foreach ($OuterInstaller in $OuterInstallers) {
    $Metadata = $OuterInstaller.Result.Metadata
    $ParserExtractedFiles = @()
    $ParserExecutedPayloads = @()
    $ParserWarnings = @()
    $ParserWritesAppsAndFeaturesEntry = $null

    if ($Metadata) {
      if ($Metadata.PSObject.Properties.Name -contains 'ExtractedFiles') { $ParserExtractedFiles = @($Metadata.ExtractedFiles) }
      if ($Metadata.PSObject.Properties.Name -contains 'ExecutedPayloads') { $ParserExecutedPayloads = @($Metadata.ExecutedPayloads) }
      if ($Metadata.PSObject.Properties.Name -contains 'Diagnostics') { $ParserWarnings = @($Metadata.Diagnostics) }
      if ($Metadata.PSObject.Properties.Name -contains 'WritesAppsAndFeaturesEntry') { $ParserWritesAppsAndFeaturesEntry = [bool]$Metadata.WritesAppsAndFeaturesEntry }
    }

    $ParserPayloadStrings = @(
      @($ParserExtractedFiles)
      @($ParserExecutedPayloads | ForEach-Object { "$($_.Command) $($_.Parameters)" })
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    $ParserMsiPayloadMarkers = @($ParserPayloadStrings | Where-Object { $_ -match '(?i)\.(msi|msp|msu)(\s|$)|msiexec|WindowsInstaller' })
    $ParserNestedExeMarkers = @($ParserPayloadStrings | Where-Object { $_ -match '(?i)(^|[\\/])(setup|install|installer|bootstrapper)\.exe(\s|$)|\b(setup|install|installer|bootstrapper)\.exe(\s|$)' })
    $ParserLaunchMarkers = @($ParserExecutedPayloads | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Command) })
    $HasParserWrapperEvidence = ($ParserMsiPayloadMarkers.Count + $ParserNestedExeMarkers.Count + $ParserLaunchMarkers.Count + $ParserWarnings.Count) -gt 0

    if (($MsiPayloadMarkers.Count + $NestedExeMarkers.Count + $ParserMsiPayloadMarkers.Count + $ParserNestedExeMarkers.Count) -eq 0 -and -not ($ParserWritesAppsAndFeaturesEntry -eq $false -and $HasParserWrapperEvidence)) { continue }

    $Confidence = if ($ParserWarnings.Count -gt 0 -or $ParserWritesAppsAndFeaturesEntry -eq $false -or $ParserLaunchMarkers.Count -gt 0 -or $LaunchMarkers.Count -gt 0 -or ($MsiPayloadMarkers.Count + $ParserMsiPayloadMarkers.Count) -gt 1) { 'medium' } else { 'low' }
    $Evidence = [pscustomobject][ordered]@{
      AppliesTo                 = $OuterInstaller.Name
      Confidence                = $Confidence
      MsiOrWindowsInstallerTags = [string[]]$MsiPayloadMarkers
      NestedExeTags             = [string[]]$NestedExeMarkers
      LaunchTags                = [string[]]$LaunchMarkers
      ParserEvidence            = [pscustomobject][ordered]@{
        WritesAppsAndFeaturesEntry = $ParserWritesAppsAndFeaturesEntry
        ExtractedPayloads          = @($ParserExtractedFiles)
        ExecutedPayloads           = @($ParserExecutedPayloads)
        MsiOrWindowsInstallerTags  = @($ParserMsiPayloadMarkers)
        NestedExeTags              = @($ParserNestedExeMarkers)
        Diagnostics                = [object[]]@($ParserWarnings)
      }
      RequiredAction            = 'Inspect the nested payload or install in a VM and compare visible ARP entries excluding SystemComponent=1. Use the nested MSI/WiX/custom installer metadata when that payload writes Apps & Features.'
    }
    New-InstallerDiagnostic -Id "InstallerWrapper.$($OuterInstaller.Name -replace '[^A-Za-z0-9]+', '.').NestedPayload" -Source 'InstallerAnalyzer' -Message 'This NSIS/Inno installer may be a wrapper around a nested installer. Do not assume the outer installer writes the visible ARP entry.' -Kind Risk -Areas Metadata, Installability -AffectedFields ProductCode, AppsAndFeaturesEntries -Evidence $Evidence
  }
}

function Invoke-InstallerMsiAnalysis {
  <#
  .SYNOPSIS
    Analyze a direct MSI installer
  .PARAMETER InstallerPath
    The installer path
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The installer path')]
    [string]$InstallerPath
  )

  $AnalyzerInstallerPath = $InstallerPath
  $MsiInfo = Get-MsiInstallerInfo -Path $AnalyzerInstallerPath
  $AllUsers = $MsiInfo.AllUsers
  # WinGet distinguishes MSI databases authored by WiX from other MSI packages.
  # Preserve that distinction only when the structured table classifier proves it;
  # an unknown builder remains the schema-valid generic MSI type.
  $ManifestInstallerType = $MsiInfo.InstallerBuilder -ceq 'WiX' ? 'wix' : 'msi'
  $ScopeRecommendation = if ($AllUsers -eq '1') {
    [pscustomobject]@{ Scope = 'machine'; Reason = 'MSI Property table contains ALLUSERS=1' }
  } elseif ([string]::IsNullOrWhiteSpace($AllUsers)) {
    [pscustomobject]@{ Scope = $null; Reason = 'MSI Property table does not contain ALLUSERS; omit Scope because ARP is still written under HKLM' }
  } else {
    [pscustomobject]@{ Scope = $null; Reason = "MSI Property table contains ALLUSERS=$AllUsers; verify package-specific scope before declaring Scope" }
  }

  [pscustomobject]@{
    Family                       = 'MSI'
    Confidence                   = 'high'
    InstallerType                = $ManifestInstallerType
    InstallerBuilder             = $MsiInfo.InstallerBuilder
    InstallerBuilderSource       = $MsiInfo.InstallerBuilderSource
    ProductVersion               = $MsiInfo.DisplayVersion
    ProductName                  = $MsiInfo.DisplayName
    Publisher                    = $MsiInfo.Publisher
    ProductCode                  = $MsiInfo.ProductCode
    UpgradeCode                  = $MsiInfo.UpgradeCode
    PackageArchitecture          = $MsiInfo.PackageArchitecture
    SupportedArchitectures       = $MsiInfo.SupportedArchitectures
    DefaultInstallLocation       = $MsiInfo.DefaultInstallLocation
    InstallLocationSwitch        = $MsiInfo.InstallLocationSwitch
    AppsAndFeaturesInstallerType = $MsiInfo.AppsAndFeaturesInstallerType
    AppsAndFeaturesProductCode   = $MsiInfo.AppsAndFeaturesProductCode
    WritesAppsAndFeaturesEntry   = $MsiInfo.WritesAppsAndFeaturesEntry
    Protocols                    = $MsiInfo.Protocols
    FileExtensions               = $MsiInfo.FileExtensions
    RegistryAssociationInfo      = $MsiInfo.RegistryAssociationInfo
    AllUsers                     = $AllUsers
    Scope                        = $ScopeRecommendation.Scope
    ScopeRecommendation          = $ScopeRecommendation
    Diagnostics                  = [object[]]@($MsiInfo.Diagnostics)

    SuggestedManifestFields      = [pscustomobject]@{ InstallerType = $ManifestInstallerType; Scope = $ScopeRecommendation.Scope }
  }
}

function Invoke-InstallerMsixAnalysis {
  <#
  .SYNOPSIS
    Analyze an MSIX/AppX-family installer
  .PARAMETER InstallerPath
    The installer path
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The installer path')]
    [string]$InstallerPath
  )

  $AnalyzerInstallerPath = $InstallerPath
  $PackageTypeInfo = Get-MSIXPackageTypeInfo -Path $InstallerPath
  $Manifests = @(Get-MSIXManifestXmlList -Path $InstallerPath -ErrorAction SilentlyContinue)
  $Identity = @($Manifests | ForEach-Object { $_.Package.Identity } | Where-Object { $_ } | Select-Object -First 1)[0]
  $SignatureEvidence = Get-InstallerPackageSignatureEvidence -Path $InstallerPath
  $PackageDependencies = foreach ($Manifest in $Manifests) {
    foreach ($Element in $Manifest.GetElementsByTagName('PackageDependency')) {
      [pscustomobject]@{
        PackageIdentifier = [string]$Element.Name
        MinimumVersion    = [string]$Element.MinVersion
        Publisher         = [string]$Element.Publisher
      }
    }
  }
  $DependencyInfo = ConvertTo-MSIXManifestDependencyInfo -PackageDependencies @($PackageDependencies)
  $AssociationInfo = ConvertTo-MSIXManifestAssociationInfo -Manifest $Manifests
  $TargetDeviceFamilies = foreach ($Manifest in $Manifests) {
    foreach ($Element in $Manifest.GetElementsByTagName('TargetDeviceFamily')) {
      [pscustomobject]@{ Name = [string]$Element.Name; MinVersion = [string]$Element.MinVersion }
    }
  }
  $SupportedTargetDeviceFamilies = @($TargetDeviceFamilies | Where-Object { $_.Name -cin @('Windows.Desktop', 'Windows.Universal') })
  $MinimumOSVersion = ($SupportedTargetDeviceFamilies | Where-Object { -not [string]::IsNullOrWhiteSpace($_.MinVersion) } | Sort-Object -Property { [System.Version]$_.MinVersion } | Select-Object -First 1).MinVersion
  $Capabilities = foreach ($Manifest in $Manifests) {
    foreach ($Element in $Manifest.GetElementsByTagName('*')) {
      if ($Element.LocalName -in @('Capability', 'DeviceCapability') -and $Element.Prefix -cne 'rescap' -and $Element.Name) { [string]$Element.Name }
    }
  }
  $RestrictedCapabilities = foreach ($Manifest in $Manifests) {
    foreach ($Element in $Manifest.GetElementsByTagName('*')) {
      if ($Element.LocalName -ceq 'Capability' -and $Element.Prefix -ceq 'rescap' -and $Element.Name) { [string]$Element.Name }
    }
  }

  [pscustomobject]@{
    Family                     = 'MSIX/AppX'
    Confidence                 = 'high'
    InstallerType              = $PackageTypeInfo.InstallerType
    PackageKind                = $PackageTypeInfo.PackageKind
    InstallerTypeEvidence      = $PackageTypeInfo.Evidence
    InstallerTypeAmbiguous     = $PackageTypeInfo.IsAmbiguous
    ProductVersion             = if ($Identity) { $Identity.Version } else { Read-ProductVersionFromMSIX -Path $AnalyzerInstallerPath -ErrorAction SilentlyContinue }
    PackageFamilyName          = if ($Identity) { "$($Identity.Name)_$(Get-MSIXPublisherHash -PublisherName $Identity.Publisher)" } else { Read-FamilyNameFromMSIX -Path $AnalyzerInstallerPath -ErrorAction SilentlyContinue }
    Architecture               = if ($Identity) { [string]$Identity.ProcessorArchitecture } else { $null }
    Platform                   = @($SupportedTargetDeviceFamilies | Select-Object -ExpandProperty Name -Unique)
    MinimumOSVersion           = $MinimumOSVersion
    Capabilities               = @($Capabilities | Sort-Object -Unique)
    RestrictedCapabilities     = @($RestrictedCapabilities | Sort-Object -Unique)
    Dependencies               = $DependencyInfo.Dependencies
    UnknownPackageDependencies = $DependencyInfo.UnknownPackageDependencies
    Diagnostics                = @(ConvertTo-InstallerDiagnostic -InputObject @(@($PackageTypeInfo.Diagnostics + $DependencyInfo.Diagnostics + $AssociationInfo.Diagnostics)) -Source 'InstallerAnalyzer' -Kind Incomplete -Areas Metadata)
    Protocols                  = $AssociationInfo.Protocols
    FileExtensions             = $AssociationInfo.FileExtensions
    RegistryAssociationInfo    = $AssociationInfo
    SignatureSha256            = $SignatureEvidence.SignatureSha256
    SignatureEvidence          = $SignatureEvidence
    Rejected                   = -not $SignatureEvidence.IsTrusted
    RejectionReason            = $SignatureEvidence.RequiredAction
    SuggestedManifestFields    = [pscustomobject]@{ InstallerType = $PackageTypeInfo.InstallerType; Dependencies = $DependencyInfo.Dependencies }
  }
}

function Get-InstallerArchiveEntryDirectoryName {
  <#
  .SYNOPSIS
    Get a normalized ZIP entry directory name
  .PARAMETER EntryName
    The ZIP entry full name
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The ZIP entry full name')]
    [string]$EntryName
  )

  $Normalized = $EntryName -replace '\\', '/'
  $LastSlash = $Normalized.LastIndexOf('/')
  if ($LastSlash -lt 0) { return '' }
  $Normalized.Substring(0, $LastSlash)
}

function Get-InstallerArchiveEntryFileName {
  <#
  .SYNOPSIS
    Get a normalized ZIP entry file name
  .PARAMETER EntryName
    The ZIP entry full name
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The ZIP entry full name')]
    [string]$EntryName
  )

  $Normalized = $EntryName -replace '\\', '/'
  $LastSlash = $Normalized.LastIndexOf('/')
  if ($LastSlash -lt 0) { return $Normalized }
  $Normalized.Substring($LastSlash + 1)
}

function Copy-InstallerArchiveEntryToFile {
  <#
  .SYNOPSIS
    Copy a ZIP entry to a local file without executing it
  .PARAMETER Entry
    The ZIP entry to copy
  .PARAMETER DestinationPath
    The destination file path
  #>
  param (
    [Parameter(Mandatory, HelpMessage = 'The ZIP entry to copy')]
    [psobject]$Entry,

    [Parameter(Mandatory, HelpMessage = 'The destination file path')]
    [string]$DestinationPath
  )

  $null = Export-InstallerArchiveEntry -Entry $Entry -DestinationPath $DestinationPath -MaximumBytes 104857600
}

function Get-InstallerPortableArchiveCandidate {
  <#
  .SYNOPSIS
    Select bounded portable PE candidates from ZIP entries
  .PARAMETER Entries
    ZIP entries
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'ZIP entries')]
    [psobject[]]$Entries
  )

  $RuntimeConfigKeys = @{}
  $ExeCandidateKeys = @{}
  foreach ($Entry in $Entries) {
    $FileName = Get-InstallerArchiveEntryFileName -EntryName $Entry.FullName
    $DirectoryName = Get-InstallerArchiveEntryDirectoryName -EntryName $Entry.FullName
    $BaseName = [System.IO.Path]::GetFileNameWithoutExtension($FileName)
    if ($FileName -match '(?i)\.exe$' -and $FileName -notmatch '(?i)(setup|install|uninstall|update|maintenancetool)') {
      $ExeCandidateKeys["$($DirectoryName.ToLowerInvariant())/$($BaseName.ToLowerInvariant())"] = $true
    }
    if ($FileName -notmatch '(?i)\.runtimeconfig\.json$') { continue }
    $BaseName = $FileName -replace '(?i)\.runtimeconfig\.json$', ''
    $RuntimeConfigKeys["$($DirectoryName.ToLowerInvariant())/$($BaseName.ToLowerInvariant())"] = $true
  }

  $CandidateRecords = foreach ($Entry in $Entries) {
    if ($Entry.Length -le 0 -or $Entry.Length -gt 104857600) { continue }
    $FileName = Get-InstallerArchiveEntryFileName -EntryName $Entry.FullName
    $DirectoryName = Get-InstallerArchiveEntryDirectoryName -EntryName $Entry.FullName
    $BaseName = [System.IO.Path]::GetFileNameWithoutExtension($FileName)
    $CandidateKey = "$($DirectoryName.ToLowerInvariant())/$($BaseName.ToLowerInvariant())"
    $HasRuntimeConfig = $RuntimeConfigKeys.ContainsKey($CandidateKey)
    $IsRuntimeHelper = $FileName -match '(?i)^(createdump|singlefilehost|apphost|dotnet)\.exe$'

    if ($FileName -match '(?i)\.exe$' -and $FileName -notmatch '(?i)(setup|install|uninstall|update|maintenancetool)') {
      [pscustomobject]@{
        Entry            = $Entry
        HasRuntimeConfig = $HasRuntimeConfig
        IsExe            = $true
        IsRuntimeHelper  = $IsRuntimeHelper
      }
      continue
    }

    if ($FileName -match '(?i)\.dll$') {
      if ($RuntimeConfigKeys.ContainsKey($CandidateKey) -and -not $ExeCandidateKeys.ContainsKey($CandidateKey)) {
        [pscustomobject]@{
          Entry            = $Entry
          HasRuntimeConfig = $true
          IsExe            = $false
          IsRuntimeHelper  = $false
        }
      }
    }
  }

  if (@($CandidateRecords | Where-Object { -not $_.IsRuntimeHelper }).Count -gt 0) {
    $CandidateRecords = @($CandidateRecords | Where-Object { -not $_.IsRuntimeHelper })
  }

  $SeenCandidates = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
  foreach ($Record in @($CandidateRecords | Sort-Object -Property @{ Expression = { if ($_.HasRuntimeConfig) { 0 } else { 1 } } }, @{ Expression = { if ($_.IsRuntimeHelper) { 1 } else { 0 } } }, @{ Expression = { if ($_.IsExe) { 0 } else { 1 } } }, @{ Expression = { $_.Entry.FullName } })) {
    if ($SeenCandidates.Add($Record.Entry.FullName)) {
      $Record.Entry
    }
  }
}

function Get-InstallerPortableArchiveRelatedEntry {
  <#
  .SYNOPSIS
    Select same-directory sidecars and DLLs for a ZIP portable PE candidate
  .PARAMETER Entries
    ZIP entries
  .PARAMETER Candidate
    The portable candidate entry
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'ZIP entries')]
    [psobject[]]$Entries,

    [Parameter(Mandatory, HelpMessage = 'The portable candidate entry')]
    [psobject]$Candidate
  )

  $CandidateDirectoryName = Get-InstallerArchiveEntryDirectoryName -EntryName $Candidate.FullName
  $CandidateFileName = Get-InstallerArchiveEntryFileName -EntryName $Candidate.FullName
  $CandidateBaseName = [System.IO.Path]::GetFileNameWithoutExtension($CandidateFileName)
  $ExactSidecarNames = @(
    "$CandidateBaseName.runtimeconfig.json",
    "$CandidateBaseName.deps.json",
    "$CandidateBaseName.dll",
    "$CandidateBaseName.exe"
  ) | ForEach-Object -Process { $_.ToLowerInvariant() }
  $BundledRuntimeNames = @('hostfxr.dll', 'hostpolicy.dll', 'coreclr.dll', 'System.Private.CoreLib.dll') | ForEach-Object -Process { $_.ToLowerInvariant() }

  $RelatedEntryRecords = foreach ($Entry in $Entries) {
    if ($Entry.FullName -eq $Candidate.FullName) { continue }
    if ($Entry.Length -le 0 -or $Entry.Length -gt 104857600) { continue }
    if ((Get-InstallerArchiveEntryDirectoryName -EntryName $Entry.FullName) -ne $CandidateDirectoryName) { continue }

    $FileName = Get-InstallerArchiveEntryFileName -EntryName $Entry.FullName
    $LowerFileName = $FileName.ToLowerInvariant()
    $Priority = if ($LowerFileName -in $ExactSidecarNames) {
      0
    } elseif ($LowerFileName -in $BundledRuntimeNames) {
      1
    } elseif ($LowerFileName -match '\.dll$') {
      2
    } else {
      $null
    }
    if ($null -ne $Priority) {
      [pscustomobject]@{
        Entry    = $Entry
        Priority = $Priority
      }
    }
  }

  $SeenRelatedEntries = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
  $RelatedEntries = [System.Collections.Generic.List[psobject]]::new()
  foreach ($Record in @($RelatedEntryRecords | Sort-Object -Property Priority, @{ Expression = { $_.Entry.FullName } })) {
    if ($SeenRelatedEntries.Add($Record.Entry.FullName)) {
      $RelatedEntries.Add($Record.Entry)
    }
    if ($RelatedEntries.Count -ge 50) { break }
  }

  @($RelatedEntries)
}

function Invoke-InstallerZipAnalysis {
  <#
  .SYNOPSIS
    Analyze a ZIP/archive installer
  .PARAMETER InstallerPath
    The installer path
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The installer path')]
    [string]$InstallerPath
  )

  $Archive = Get-InstallerArchive -Path $InstallerPath
  try {
    $Entries = @(Get-InstallerArchiveEntry -Archive $Archive)
    $NestedInstallers = @($Entries | Where-Object { $_.FullName -match '\.(exe|msi|msix|appx|appxbundle|msixbundle)$' })
    $PortableCandidates = @(Get-InstallerPortableArchiveCandidate -Entries $Entries)
    $PortableCandidateEvidence = [System.Collections.Generic.List[psobject]]::new()
    $TempFolder = $null

    try {
      foreach ($Candidate in @($PortableCandidates | Select-Object -First 10)) {
        if ($Candidate.Length -le 0 -or $Candidate.Length -gt 104857600) { continue }

        $ArchiveEntry = $Candidate
        if (-not $ArchiveEntry) { continue }
        if (-not $TempFolder) { $TempFolder = New-TempFolder }

        $CandidateFolder = Join-Path -Path $TempFolder -ChildPath "Candidate$($PortableCandidateEvidence.Count)"
        $null = New-Item -Path $CandidateFolder -ItemType Directory -Force
        $CandidateFileName = ([System.IO.Path]::GetFileName($Candidate.FullName) -replace '[^\w.\-]', '_')
        if ([string]::IsNullOrWhiteSpace($CandidateFileName)) { $CandidateFileName = "PortableCandidate$($PortableCandidateEvidence.Count).exe" }
        $CandidatePath = Join-Path -Path $CandidateFolder -ChildPath $CandidateFileName
        Copy-InstallerArchiveEntryToFile -Entry $ArchiveEntry -DestinationPath $CandidatePath

        $RelatedPaths = [System.Collections.Generic.List[string]]::new()
        foreach ($RelatedEntry in @(Get-InstallerPortableArchiveRelatedEntry -Entries $Entries -Candidate $Candidate)) {
          $RelatedArchiveEntry = $RelatedEntry
          if (-not $RelatedArchiveEntry) { continue }
          $RelatedFileName = (Get-InstallerArchiveEntryFileName -EntryName $RelatedEntry.FullName) -replace '[^\w.\-]', '_'
          if ([string]::IsNullOrWhiteSpace($RelatedFileName)) { continue }
          $RelatedPath = Join-Path -Path $CandidateFolder -ChildPath $RelatedFileName
          Copy-InstallerArchiveEntryToFile -Entry $RelatedArchiveEntry -DestinationPath $RelatedPath
          $RelatedPaths.Add($RelatedPath)
        }

        $PortableCandidateEvidence.Add([pscustomobject]@{
            RelativeFilePath = $Candidate.FullName
            RelatedFilePaths = @($RelatedPaths)
            Length           = $Candidate.Length
            Evidence         = Get-InstallerPortableEvidence -Path $CandidatePath -RelatedFile @($RelatedPaths)
          })
      }
    } finally {
      if ($TempFolder -and (Test-Path -LiteralPath $TempFolder)) {
        Remove-Item -LiteralPath $TempFolder -Recurse -Force
      }
    }

    [pscustomobject]@{
      Family                    = 'ZIP/archive'
      Confidence                = 'high'
      InstallerType             = 'zip'
      EntryCount                = $Entries.Count
      NestedInstallerFiles      = $NestedInstallers
      PortableCandidates        = $PortableCandidates
      PortableCandidateEvidence = @($PortableCandidateEvidence)
      SuggestedManifestFields   = [pscustomobject]@{ InstallerType = 'zip'; NestedInstallerType = 'exe/msi/msix/portable based on selected nested file' }
    }
  } finally {
    $Archive.Dispose()
  }
}

function Invoke-InstallerExeParser {
  <#
  .SYNOPSIS
    Run static EXE installer parsers in the current PackageModule session
  .PARAMETER InstallerPath
    The installer path
  .PARAMETER ExtractEmbeddedMsi
    Also extract embedded MSI metadata for Advanced Installer when available
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The installer path')]
    [string]$InstallerPath,

    [Parameter(HelpMessage = 'Also extract embedded MSI metadata for Advanced Installer when available')]
    [bool]$ExtractEmbeddedMsi,

    [Parameter(HelpMessage = 'Bounded generic-family candidates collected by the analyzer')]
    [object[]]$FamilyCandidates = @()
  )

  $AnalyzerInstallerPath = $InstallerPath
  $ShouldExtractEmbeddedMsi = $ExtractEmbeddedMsi
  $RouteByCandidates = $PSBoundParameters.ContainsKey('FamilyCandidates')
  $CandidateFamilies = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $CandidateByFamily = @{}
  foreach ($Candidate in $FamilyCandidates) {
    if ($Candidate.Family) {
      $null = $CandidateFamilies.Add([string]$Candidate.Family)
      $CandidateByFamily[[string]$Candidate.Family] = $Candidate
    }
  }

  function Test-InstallerCandidateFamily {
    param (
      [Parameter(Mandatory)][string]$Family,
      [ValidateSet('low', 'medium', 'high')][string]$MinimumConfidence = 'low'
    )
    if (-not $RouteByCandidates) { return $true }
    if (-not $CandidateFamilies.Contains($Family)) { return $false }
    $Rank = @{ low = 0; medium = 1; high = 2 }
    return $Rank[[string]$CandidateByFamily[$Family].Confidence] -ge $Rank[$MinimumConfidence]
  }

  function ConvertTo-GenericExeParserEvidence {
    <#
    .SYNOPSIS
      Normalize static metadata returned by a PackageModule EXE parser
    #>
    param (
      [Parameter(Mandatory)][string]$Family,
      [Parameter(Mandatory)][psobject]$Info,
      [ValidateSet('low', 'medium', 'high')][string]$Confidence = 'high'
    )

    $SuggestedManifestFields = Get-InstallerExeFamilyDefault -Family $Family
    if ($Info.Scope) { $SuggestedManifestFields | Add-Member -NotePropertyName Scope -NotePropertyValue $Info.Scope -Force }
    if ($Info.SupportedScopes) { $SuggestedManifestFields | Add-Member -NotePropertyName SupportedScopes -NotePropertyValue @($Info.SupportedScopes) -Force }
    if ($Info.ProductCode) { $SuggestedManifestFields | Add-Member -NotePropertyName ProductCode -NotePropertyValue $Info.ProductCode -Force }
    [pscustomobject]@{
      Family                      = $Family
      Confidence                  = $Confidence
      InstallerType               = "exe # $Family"
      Metadata                    = $Info
      ProductVersion              = $Info.DisplayVersion
      ProductName                 = $Info.DisplayName
      Publisher                   = $Info.Publisher
      ProductCode                 = $Info.ProductCode
      Scope                       = $Info.Scope
      SupportedScopes             = @($Info.SupportedScopes)
      DefaultScopeIsAuthoritative = [bool]($Info.PSObject.Properties['DefaultScopeIsAuthoritative'] -and $Info.DefaultScopeIsAuthoritative)
      AppsAndFeaturesEntries      = if ($Info.PSObject.Properties['AppsAndFeaturesEntries']) { @($Info.AppsAndFeaturesEntries) } else { @() }
      Protocols                   = @($Info.Protocols)
      FileExtensions              = @($Info.FileExtensions)
      RegistryAssociationInfo     = $Info.RegistryAssociationInfo
      NestedInstallerFiles        = @($Info.ExtractedFiles)
      ExecutedPayloads            = if ($Info.PSObject.Properties['ExecutedPayloads']) { @($Info.ExecutedPayloads) } else { @() }
      CanExpand                   = $Info.CanExpand

      Diagnostics                 = [object[]]@($Info.Diagnostics)
      SuggestedManifestFields     = $SuggestedManifestFields
    }
  }

  # Structured generic-family parsers are authoritative. Stop before broad SFX
  # heuristics when one succeeds because many installer engines embed archives.
  $StructuredParserResults = @(
    if (Test-InstallerCandidateFamily -Family 'Kachina') {
      Invoke-InstallerDetector -Name 'Kachina' -ScriptBlock {
        $Info = Get-KachinaInfo -Path $AnalyzerInstallerPath
        $Evidence = ConvertTo-GenericExeParserEvidence -Family 'Kachina' -Info $Info
        $Evidence.NestedInstallerFiles = @($Info.PayloadFiles.Path)
        $Evidence | Add-Member -NotePropertyName PayloadArchitectures -NotePropertyValue @($Info.PayloadArchitectures) -Force
        $Evidence | Add-Member -NotePropertyName DependencyInfo -NotePropertyValue $Info.DependencyInfo -Force
        $Evidence | Add-Member -NotePropertyName RuntimePackages -NotePropertyValue @($Info.RuntimePackages) -Force
        $Evidence | Add-Member -NotePropertyName EmbeddedRuntimePackages -NotePropertyValue @($Info.EmbeddedRuntimePackages) -Force
        $Evidence | Add-Member -NotePropertyName PatchFiles -NotePropertyValue @($Info.PatchFiles) -Force
        $Evidence.SuggestedManifestFields.InstallModes = @($Info.InstallModes)
        $Evidence.SuggestedManifestFields.InstallerSwitches = $Info.InstallerSwitches
        $Evidence.SuggestedManifestFields | Add-Member -NotePropertyName ElevationRequirement -NotePropertyValue $Info.ElevationRequirement -Force
        $Evidence
      }
    }

    if (Test-InstallerCandidateFamily -Family 'MicaSetup') {
      Invoke-InstallerDetector -Name 'MicaSetup' -ScriptBlock {
        $Info = Get-MicaSetupInfo -Path $AnalyzerInstallerPath
        $Evidence = ConvertTo-GenericExeParserEvidence -Family 'MicaSetup' -Info $Info
        $Evidence.NestedInstallerFiles = @($Info.PayloadFiles.Path)
        $Evidence | Add-Member -NotePropertyName PayloadArchitectures -NotePropertyValue @($Info.PayloadArchitectures) -Force
        $Evidence | Add-Member -NotePropertyName DependencyInfo -NotePropertyValue $Info.DependencyInfo -Force
        $Evidence.SuggestedManifestFields.InstallModes = @($Info.InstallModes)
        $Evidence.SuggestedManifestFields.InstallerSwitches = $Info.InstallerSwitches
        $Evidence
      }
    }

    if (Test-InstallerCandidateFamily -Family 'Zero Install') {
      Invoke-InstallerDetector -Name 'Zero Install' -ScriptBlock {
        $Info = Get-ZeroInstallInfo -Path $AnalyzerInstallerPath
        $Evidence = ConvertTo-GenericExeParserEvidence -Family 'Zero Install' -Info $Info

        # Bootstrap configuration controls whether this is an app-bound GUI or
        # CLI launcher, whether a store path is accepted, and whether --machine
        # can create a second scope. Replace broad family defaults accordingly.
        $Evidence.SuggestedManifestFields.InstallModes = @($Info.InstallModes)
        $Evidence.SuggestedManifestFields.InstallerSwitches = $Info.InstallerSwitches
        if ($Info.ScopeSwitches) { $Evidence.SuggestedManifestFields | Add-Member -NotePropertyName ScopeSwitches -NotePropertyValue $Info.ScopeSwitches -Force }
        if (-not $Info.Scope) { $Evidence.SuggestedManifestFields.PSObject.Properties.Remove('Scope') }
        $Evidence
      }
    }

    if (Test-InstallerCandidateFamily -Family 'Chromium Setup') {
      Invoke-InstallerDetector -Name 'Chromium Setup' -ScriptBlock {
        $Info = Get-ChromiumSetupInfo -Path $AnalyzerInstallerPath
        $SuggestedManifestFields = Get-InstallerExeFamilyDefault -Family 'Chromium Setup'
        if ($Info.Variant -eq 'ChromiumMiniInstaller') {
          $SuggestedManifestFields.InstallModes = @('silent')
          $SuggestedManifestFields.InstallerSwitches = [ordered]@{ Custom = '--do-not-launch-chrome'; Log = '--verbose-logging --log-file="<LOGPATH>"' }
          $SuggestedManifestFields | Add-Member -NotePropertyName ScopeSwitches -NotePropertyValue ([pscustomobject]@{ User = $null; Machine = '--system-level' }) -Force
        } elseif ($Info.Variant -eq 'ChromiumUpdater' -and -not $Info.IsOnlineBootstrapper) {
          $SuggestedManifestFields.InstallModes = @('interactive', 'silent')
          $SuggestedManifestFields.InstallerSwitches = [ordered]@{ Silent = '--install --silent'; SilentWithProgress = '--install --silent'; Interactive = '--install'; Log = '--enable-logging'; Upgrade = '--update' }
          $SuggestedManifestFields | Add-Member -NotePropertyName ScopeSwitches -NotePropertyValue ([pscustomobject]@{ User = '--enterprise'; Machine = '--system --enterprise' }) -Force
        } elseif ($Info.Variant -eq 'Omaha' -and -not $Info.IsOnlineBootstrapper -and -not $Info.UpdaterTag.IsTagged) {
          $SuggestedManifestFields.InstallModes = @('silent')
          $SuggestedManifestFields.InstallerSwitches = [ordered]@{ Silent = '/silent'; SilentWithProgress = '/silent' }
          $SuggestedManifestFields | Add-Member -NotePropertyName ScopeSwitches -NotePropertyValue ([pscustomobject]@{ User = $Info.UserScopeSwitch; Machine = $Info.MachineScopeSwitch }) -Force
          $SuggestedManifestFields.Notes += 'This untagged Omaha package installs its embedded updater runtime. Keep the complete /install runtime tag in each scope-specific Custom switch.'
        } elseif ($Info.Variant -eq 'Omaha' -and $Info.OfflineManifest) {
          $SuggestedManifestFields.Notes += 'This tagged Omaha package contains an offline target manifest and payload. Use its package action as static wrapper evidence, but preserve vendor-specific accepted switches.'
        } else {
          $SuggestedManifestFields.Notes += 'This tagged updater setup is an application bootstrapper. Expand its payload and validate package-specific switches and final ARP behavior.'
        }
        if ($Info.Scope) { $SuggestedManifestFields | Add-Member -NotePropertyName Scope -NotePropertyValue $Info.Scope -Force }
        if ($Info.SupportedScopes) { $SuggestedManifestFields | Add-Member -NotePropertyName SupportedScopes -NotePropertyValue @($Info.SupportedScopes) -Force }
        [pscustomobject]@{
          Family                  = 'Chromium Setup'
          Confidence              = 'high'
          InstallerType           = 'exe # Chromium Setup'
          Metadata                = $Info
          Variant                 = $Info.Variant
          ProductVersion          = $Info.DisplayVersion
          ProductName             = $Info.DisplayName
          Publisher               = $Info.Publisher
          ProductCode             = $Info.ProductCode
          ApplicationId           = $Info.ApplicationId
          Scope                   = $Info.Scope
          SupportedScopes         = $Info.SupportedScopes
          SupportsDualScope       = $Info.SupportsDualScope
          IsOnlineBootstrapper    = $Info.IsOnlineBootstrapper
          OfflineManifest         = $Info.OfflineManifest
          ArchiveResourceName     = $Info.ArchiveResourceName
          SetupResourceName       = $Info.SetupResourceName
          ExecutedPayloads        = $Info.ExecutedPayloads
          NestedInstallerFiles    = $Info.NestedFiles
          Diagnostics             = @(ConvertTo-InstallerDiagnostic -InputObject @($Info.Diagnostics) -Source 'InstallerAnalyzer' -Kind Incomplete -Areas Metadata)
          SuggestedManifestFields = $SuggestedManifestFields
        }
      }
    }

    if (Test-InstallerCandidateFamily -Family 'Wise') {
      Invoke-InstallerDetector -Name 'Wise' -ScriptBlock {
        $Info = Get-WiseInfo -Path $AnalyzerInstallerPath
        $SuggestedManifestFields = Get-InstallerExeFamilyDefault -Family 'Wise'
        if ($Info.Scope) { $SuggestedManifestFields | Add-Member -NotePropertyName Scope -NotePropertyValue $Info.Scope -Force }
        if ($Info.ProductCode) { $SuggestedManifestFields | Add-Member -NotePropertyName ProductCode -NotePropertyValue $Info.ProductCode -Force }
        if ($Info.InstallLocationSwitch) { $SuggestedManifestFields.InstallerSwitches['InstallLocation'] = $Info.InstallLocationSwitch }
        [pscustomobject]@{
          Family                  = 'Wise'
          Confidence              = 'high'
          InstallerType           = 'exe # Wise MSI'
          Metadata                = $Info
          ProductVersion          = $Info.DisplayVersion
          ProductName             = $Info.DisplayName
          Publisher               = $Info.Publisher
          ProductCode             = $Info.ProductCode
          UpgradeCode             = $Info.UpgradeCode
          Scope                   = $Info.Scope
          SupportedScopes         = $Info.SupportedScopes
          MsiInfo                 = $Info.AppsAndFeaturesEntries
          Protocols               = $Info.Protocols
          FileExtensions          = $Info.FileExtensions
          RegistryAssociationInfo = $Info.RegistryAssociationInfo
          NestedInstallerFiles    = $Info.ExtractedFiles
          CanExpand               = $Info.CanExpand
          Diagnostics             = @(ConvertTo-InstallerDiagnostic -InputObject @($Info.Diagnostics) -Source 'InstallerAnalyzer' -Kind Incomplete -Areas Metadata)
          SuggestedManifestFields = $SuggestedManifestFields
        }
      }
    }

    if (Test-InstallerCandidateFamily -Family 'Setup Factory') {
      Invoke-InstallerDetector -Name 'Setup Factory' -ScriptBlock {
        $Info = Get-SetupFactoryInfo -Path $AnalyzerInstallerPath
        [pscustomobject]@{
          Family                  = 'Setup Factory'
          Confidence              = 'high'
          InstallerType           = 'exe # Setup Factory'
          Metadata                = $Info
          ProductVersion          = $Info.DisplayVersion
          ProductName             = $Info.DisplayName
          Publisher               = $Info.Publisher
          ProductCode             = $Info.ProductCode
          Scope                   = $Info.Scope
          Protocols               = $Info.Protocols
          FileExtensions          = $Info.FileExtensions
          RegistryAssociationInfo = $Info.RegistryAssociationInfo
          SuggestedManifestFields = Get-InstallerExeFamilyDefault -Family 'Setup Factory'
        }
      }
    }

    if (Test-InstallerCandidateFamily -Family 'InstallAnywhere') {
      Invoke-InstallerDetector -Name 'InstallAnywhere' -ScriptBlock {
        $Info = Get-InstallAnywhereInfo -Path $AnalyzerInstallerPath
        [pscustomobject]@{
          Family                  = 'InstallAnywhere'
          Confidence              = 'high'
          InstallerType           = 'exe # InstallAnywhere'
          Metadata                = $Info
          ProductVersion          = $Info.DisplayVersion
          ProductName             = $Info.DisplayName
          Publisher               = $Info.Publisher
          ProductCode             = $Info.ProductCode
          UpgradeCode             = $Info.UpgradeCode
          Scope                   = $Info.Scope
          Protocols               = $Info.Protocols
          FileExtensions          = $Info.FileExtensions
          RegistryAssociationInfo = $Info.RegistryAssociationInfo
          SuggestedManifestFields = Get-InstallerExeFamilyDefault -Family 'InstallAnywhere'
        }
      }
    }

    if (Test-InstallerCandidateFamily -Family 'Actual Installer') {
      Invoke-InstallerDetector -Name 'Actual Installer' -ScriptBlock {
        $Info = Get-ActualInstallerInfo -Path $AnalyzerInstallerPath
        [pscustomobject]@{
          Family                  = 'Actual Installer'
          Confidence              = 'high'
          InstallerType           = 'exe # Actual Installer'
          Metadata                = $Info
          ProductVersion          = $Info.DisplayVersion
          ProductName             = $Info.DisplayName
          Publisher               = $Info.Publisher
          ProductCode             = $Info.ProductCode
          Scope                   = $Info.Scope
          SupportedScopes         = $Info.SupportedScopes
          Protocols               = $Info.Protocols
          FileExtensions          = $Info.FileExtensions
          RegistryAssociationInfo = $Info.RegistryAssociationInfo
          SuggestedManifestFields = Get-InstallerExeFamilyDefault -Family 'Actual Installer'
        }
      }
    }

    if (Test-InstallerCandidateFamily -Family 'InstallBuilder') {
      Invoke-InstallerDetector -Name 'InstallBuilder' -ScriptBlock {
        $Info = Get-InstallBuilderInfo -Path $AnalyzerInstallerPath
        [pscustomobject]@{
          Family                  = 'InstallBuilder'
          Confidence              = 'high'
          InstallerType           = 'exe # InstallBuilder'
          Metadata                = $Info
          ProductVersion          = $Info.DisplayVersion
          ProductName             = $Info.DisplayName
          Publisher               = $Info.Publisher
          ProductCode             = $Info.ProductCode
          Scope                   = $Info.Scope
          Protocols               = $Info.Protocols
          FileExtensions          = $Info.FileExtensions
          RegistryAssociationInfo = $Info.RegistryAssociationInfo
          SupportedScopes         = $Info.SupportedScopes
          NestedInstallerFiles    = $Info.PayloadFiles
          PayloadCompression      = if ($Info.CookfsInfo) { $Info.CookfsInfo.CompressionTypes } else { @() }
          SuggestedManifestFields = Get-InstallerExeFamilyDefault -Family 'InstallBuilder'
        }
      }
    }

    if (Test-InstallerCandidateFamily -Family 'InstallForge') {
      Invoke-InstallerDetector -Name 'InstallForge' -ScriptBlock {
        ConvertTo-GenericExeParserEvidence -Family 'InstallForge' -Info (Get-InstallForgeInfo -Path $AnalyzerInstallerPath)
      }
    }

    if (Test-InstallerCandidateFamily -Family 'InstallAware') {
      Invoke-InstallerDetector -Name 'InstallAware' -ScriptBlock {
        ConvertTo-GenericExeParserEvidence -Family 'InstallAware' -Info (Get-InstallAwareInfo -Path $AnalyzerInstallerPath)
      }
    }

    if (Test-InstallerCandidateFamily -Family 'Paquet Builder') {
      Invoke-InstallerDetector -Name 'Paquet Builder' -ScriptBlock {
        ConvertTo-GenericExeParserEvidence -Family 'Paquet Builder' -Info (Get-PaquetBuilderInfo -Path $AnalyzerInstallerPath)
      }
    }

    if (Test-InstallerCandidateFamily -Family 'QSetup') {
      Invoke-InstallerDetector -Name 'QSetup' -ScriptBlock {
        ConvertTo-GenericExeParserEvidence -Family 'QSetup' -Info (Get-QSetupInfo -Path $AnalyzerInstallerPath)
      }
    }

    if (Test-InstallerCandidateFamily -Family 'DeployMaster') {
      Invoke-InstallerDetector -Name 'DeployMaster' -ScriptBlock {
        $Info = Get-DeployMasterInfo -Path $AnalyzerInstallerPath
        $Confidence = if ($Info.RuntimeProductName -match '(?i)DeployMaster' -or $Info.FileDescription -match '(?i)DeployMaster') { 'high' } else { 'medium' }
        ConvertTo-GenericExeParserEvidence -Family 'DeployMaster' -Info $Info -Confidence $Confidence
      }
    }

    if (Test-InstallerCandidateFamily -Family 'CreateInstall') {
      Invoke-InstallerDetector -Name 'CreateInstall' -ScriptBlock {
        ConvertTo-GenericExeParserEvidence -Family 'CreateInstall' -Info (Get-CreateInstallInfo -Path $AnalyzerInstallerPath)
      }
    }

    if (Test-InstallerCandidateFamily -Family 'InstallMate') {
      Invoke-InstallerDetector -Name 'InstallMate' -ScriptBlock {
        ConvertTo-GenericExeParserEvidence -Family 'InstallMate' -Info (Get-InstallMateInfo -Path $AnalyzerInstallerPath)
      }
    }

    if (Test-InstallerCandidateFamily -Family 'InstallShield' -MinimumConfidence medium) {
      Invoke-InstallerDetector -Name 'InstallShield' -ScriptBlock {
        $TemporaryPath = New-TempFolder
        try {
          $Info = Get-InstallShieldInfo -Path $AnalyzerInstallerPath -DestinationPath $TemporaryPath
          # Parse a Setup.ini-selected MSI before deleting the extraction tree.
          # The detached MSI result remains usable by manifest updates, while
          # the outer metadata retains InstallShield variant/selection evidence.
          $MsiInfo = $Info.HasMsi -and $Info.Variant -ne 'Advanced UI' ? (Get-InstallShieldMsiInfo -Installer $Info) : $null
          $Evidence = ConvertTo-GenericExeParserEvidence -Family 'InstallShield' -Info ($null -eq $MsiInfo ? $Info : $MsiInfo)
          $Evidence.Metadata = $Info
          $Evidence | Add-Member -NotePropertyName Variant -NotePropertyValue $Info.Variant -Force
          $Evidence | Add-Member -NotePropertyName MsiInfo -NotePropertyValue $MsiInfo -Force
          $Evidence | Add-Member -NotePropertyName InstallScriptInfo -NotePropertyValue $Info.InstallScriptInfo -Force

          # Basic MSI forwarding switches are not valid for InstallScript-only
          # media. Recommend /s only when static analysis proves the package is
          # self-contained, such as a valid embedded setup.iss.
          if ($Info.Variant -eq 'InstallScript') {
            $Evidence.SuggestedManifestFields = [pscustomobject][ordered]@{
              InstallerType = 'exe # InstallShield InstallScript'
              Notes         = @("Static silent-support result: $($Info.InstallScriptInfo.SilentSupport).")
            }
            if ($Info.InstallScriptInfo.SilentSupport -eq 'Supported') {
              $Evidence.SuggestedManifestFields | Add-Member -NotePropertyName InstallModes -NotePropertyValue @('interactive', 'silent')
              $Evidence.SuggestedManifestFields | Add-Member -NotePropertyName InstallerSwitches -NotePropertyValue ([ordered]@{ Silent = '/s' })
            }
          } elseif ($Info.Variant -eq 'Advanced UI') {
            $Evidence | Add-Member -NotePropertyName InstallerType -NotePropertyValue 'exe # InstallShield Advanced UI' -Force
            $Evidence.SuggestedManifestFields = Get-InstallerExeFamilyDefault -Family 'InstallShield Advanced UI'
          }
          $Evidence
        } finally {
          Remove-Item -LiteralPath $TemporaryPath -Recurse -Force -ErrorAction SilentlyContinue
        }
      }
    }
  )
  $StructuredParserResults
  if ($StructuredParserResults.Success -contains $true) { return }

  if (Test-InstallerCandidateFamily -Family '7z SFX' -MinimumConfidence medium) {
    $WrapperResult = Invoke-InstallerDetector -Name '7z SFX' -ScriptBlock {
      $Info = Get-SevenZipSfxInfo -Path $AnalyzerInstallerPath
      [pscustomobject]@{
        Family                  = '7z SFX'
        Confidence              = 'high'
        InstallerType           = 'exe # 7z SFX'
        Metadata                = $Info
        ExecutedPayload         = $Info.ExecutedPayload
        ExecutedPayloads        = $Info.ExecutedPayloads
        PayloadArguments        = $Info.PayloadArguments
        NestedInstallerFiles    = $Info.NestedFiles
        SuggestedManifestFields = Get-InstallerExeFamilyDefault -Family '7z SFX'
      }
    }
    $WrapperResult
    if ($WrapperResult.Success) { return }
  }

  if (Test-InstallerCandidateFamily -Family 'WinRAR GUI SFX' -MinimumConfidence medium) {
    $WrapperResult = Invoke-InstallerDetector -Name 'WinRAR GUI SFX' -ScriptBlock {
      $Info = Get-WinRarSfxInfo -Path $AnalyzerInstallerPath
      [pscustomobject]@{
        Family                  = 'WinRAR GUI SFX'
        Confidence              = 'high'
        InstallerType           = 'exe # WinRAR GUI SFX'
        Metadata                = $Info
        ExecutedPayloads        = $Info.ExecutedPayloads
        NestedInstallerFiles    = $Info.NestedFiles
        SuggestedManifestFields = Get-InstallerExeFamilyDefault -Family 'WinRAR GUI SFX'
      }
    }
    $WrapperResult
    if ($WrapperResult.Success) { return }
  }

  if (Test-InstallerCandidateFamily -Family 'IExpress' -MinimumConfidence medium) {
    $WrapperResult = Invoke-InstallerDetector -Name 'IExpress' -ScriptBlock {
      $Info = Get-IExpressInfo -Path $AnalyzerInstallerPath
      [pscustomobject]@{
        Family                  = 'IExpress'
        Confidence              = 'high'
        InstallerType           = 'exe # IExpress'
        Metadata                = $Info
        ExecutedPayloads        = $Info.ExecutedPayloads
        NestedInstallerFiles    = $Info.NestedFiles
        SuggestedManifestFields = Get-InstallerExeFamilyDefault -Family 'IExpress'
      }
    }
    $WrapperResult
    if ($WrapperResult.Success) { return }
  }

  if (Test-InstallerCandidateFamily -Family 'dotNetInstaller' -MinimumConfidence medium) {
    $WrapperResult = Invoke-InstallerDetector -Name 'dotNetInstaller' -ScriptBlock {
      $Info = Get-DotNetInstallerInfo -Path $AnalyzerInstallerPath
      [pscustomobject]@{
        Family                  = 'dotNetInstaller'
        Confidence              = 'high'
        InstallerType           = 'exe # dotNetInstaller'
        Metadata                = $Info
        ProductVersion          = $Info.ConfigurationProductVersion
        ExecutedPayloads        = $Info.ExecutedPayloads
        NestedInstallerFiles    = $Info.NestedFiles
        SuggestedManifestFields = Get-InstallerExeFamilyDefault -Family 'dotNetInstaller'
      }
    }
    $WrapperResult
    if ($WrapperResult.Success) { return }
  }

  if (Test-InstallerCandidateFamily -Family 'Burn') {
    $KnownResult = Invoke-InstallerDetector -Name 'Burn' -ScriptBlock {
      $Info = Get-BurnEngineInfo -Path $AnalyzerInstallerPath
      $StubPath = Get-BurnStub -Path $AnalyzerInstallerPath
      try {
        $BootstrapperApplicationData = Get-BurnBootstrapperApplicationData -StubPath $StubPath -ErrorAction SilentlyContinue
        $Manifest = Get-BurnManifest -StubPath $StubPath
      } finally {
        Remove-Item -LiteralPath $StubPath -Force -ErrorAction SilentlyContinue
      }
      $BundleProperties = $BootstrapperApplicationData.BootstrapperApplicationData.WixBundleProperties
      $Registration = $Manifest.BurnManifest.Registration
      $ProductCode = if ($BundleProperties) {
        if ($BundleProperties.HasAttribute('Code')) { $BundleProperties.Code } else { $BundleProperties.Id }
      } elseif ($Registration.HasAttribute('Code')) { $Registration.Code } else { $Registration.Id }
      $UpgradeCode = if ($BundleProperties) { $BundleProperties.UpgradeCode } elseif ($Manifest.BurnManifest.RelatedBundle.HasAttribute('Code')) { $Manifest.BurnManifest.RelatedBundle.Code } else { $Manifest.BurnManifest.RelatedBundle.Id }
      $ProductName = if ($BundleProperties) { $BundleProperties.DisplayName } else { $Registration.Arp.DisplayName }
      [pscustomobject]@{
        Family                  = 'Burn'
        Confidence              = 'high'
        InstallerType           = 'burn'
        Metadata                = $Info
        ProductCode             = $ProductCode
        UpgradeCode             = $UpgradeCode
        ProductName             = $ProductName
        SuggestedManifestFields = [pscustomobject]@{ InstallerType = 'burn' }
      }
    }
    $KnownResult
    if ($KnownResult.Success) { return }
  }

  if (Test-InstallerCandidateFamily -Family 'Inno Setup') {
    $KnownResult = Invoke-InstallerDetector -Name 'Inno' -ScriptBlock {
      $Info = Get-InnoInfo -Path $AnalyzerInstallerPath
      [pscustomobject]@{
        Family                  = 'Inno Setup'
        Confidence              = 'high'
        InstallerType           = 'inno'
        Metadata                = $Info
        ProductVersion          = $Info.DisplayVersion
        ProductName             = $Info.DisplayName
        Publisher               = $Info.Publisher
        ProductCode             = $Info.ProductCode
        SuggestedManifestFields = [pscustomobject]@{ InstallerType = 'inno' }
      }
    }
    $KnownResult
    if ($KnownResult.Success) { return }
  }

  if (Test-InstallerCandidateFamily -Family 'NSIS/Nullsoft') {
    $KnownResult = Invoke-InstallerDetector -Name 'NSIS' -ScriptBlock {
      $Info = Get-NSISInfo -Path $AnalyzerInstallerPath
      [pscustomobject]@{
        Family                             = 'NSIS/Nullsoft'
        Confidence                         = 'high'
        InstallerType                      = 'nullsoft'
        Metadata                           = $Info
        ProductVersion                     = $Info.DisplayVersion
        ProductName                        = $Info.DisplayName
        Publisher                          = $Info.Publisher
        ProductCode                        = $Info.ProductCode
        Scope                              = $Info.Scope
        AppsAndFeaturesEntries             = @($Info.AppsAndFeaturesEntries)
        AppsAndFeaturesEvidence            = @($Info.AppsAndFeaturesEntryEvidence)
        HasLocalizedAppsAndFeaturesEntries = [bool]$Info.HasLocalizedAppsAndFeaturesEntries

        Diagnostics                        = [object[]]@($Info.Diagnostics)
        Protocols                          = $Info.Protocols
        FileExtensions                     = $Info.FileExtensions
        RegistryAssociationInfo            = $Info.RegistryAssociationInfo
        SuggestedManifestFields            = [pscustomobject]@{ InstallerType = 'nullsoft'; Scope = $Info.Scope; Notes = @('Create duplicate user/machine entries only when switch or registry-write evidence proves both modes.', 'Check decompiled strings/control flow for TestParameter, IfSilent, GetOptions, and custom silent-mode rejection.') }
      }
    }
    $KnownResult
    if ($KnownResult.Success) { return }
  }

  if (Test-InstallerCandidateFamily -Family 'Advanced Installer') {
    $KnownResult = Invoke-InstallerDetector -Name 'Advanced Installer' -ScriptBlock {
      $Info = Get-AdvancedInstallerInfo -Path $AnalyzerInstallerPath
      $MsiInfo = if ($ShouldExtractEmbeddedMsi) { Get-AdvancedInstallerMsiInfo -Installer $Info -ErrorAction SilentlyContinue } else { $null }
      [pscustomobject]@{
        Family                  = 'Advanced Installer'
        Confidence              = 'high'
        InstallerType           = 'exe # Advanced Installer'
        Metadata                = $Info
        MsiInfo                 = $MsiInfo
        Protocols               = if ($MsiInfo) { $MsiInfo.Protocols } else { @() }
        FileExtensions          = if ($MsiInfo) { $MsiInfo.FileExtensions } else { @() }
        RegistryAssociationInfo = if ($MsiInfo) { $MsiInfo.RegistryAssociationInfo } else { $null }
        SuggestedManifestFields = Get-InstallerExeFamilyDefault -Family 'Advanced Installer'
      }
    }
    $KnownResult
    if ($KnownResult.Success) { return }
  }

  if (Test-InstallerCandidateFamily -Family 'Qt Installer Framework') {
    $KnownResult = Invoke-InstallerDetector -Name 'Qt Installer Framework' -ScriptBlock {
      $FormatInfo = Get-QtInstallerFrameworkFormatInfo -Path $AnalyzerInstallerPath
      if (-not $FormatInfo.IsQtInstallerFramework -or -not $FormatInfo.IsSupported) {
        throw 'The file does not contain a structurally supported Qt Installer Framework format.'
      }
      if ($FormatInfo.MediaRole -ne 'Installer') {
        throw "The Qt Installer Framework media role is '$($FormatInfo.MediaRole)', not Installer."
      }
      $Info = Get-QtInstallerFrameworkInfo -Path $AnalyzerInstallerPath
      $SuggestedManifestFields = Get-InstallerExeFamilyDefault -Family 'Qt Installer Framework'
      if (-not $Info.SupportsSilentInstallation) {
        $SuggestedManifestFields.InstallModes = @('interactive')
        $SuggestedManifestFields.InstallerSwitches = [ordered]@{}
        $SuggestedManifestFields.Notes += 'This installer is GUI-only or has its command-line interface disabled; do not submit it as silent-capable.'
      } elseif (-not $Info.RequiresExplicitInstallLocation) {
        $SuggestedManifestFields.InstallerSwitches = [ordered]@{
          Silent             = 'install --accept-licenses --default-answer --confirm-command'
          SilentWithProgress = 'install --accept-licenses --default-answer --confirm-command'
          InstallLocation    = '--root "<INSTALLPATH>"'
        }
      }
      $SuggestedManifestFields | Add-Member -NotePropertyName UpgradeBehavior -NotePropertyValue $Info.RecommendedUpgradeBehavior -Force
      $SuggestedManifestFields | Add-Member -NotePropertyName Scope -NotePropertyValue $Info.Scope -Force
      $SuggestedManifestFields | Add-Member -NotePropertyName SupportedScopes -NotePropertyValue $Info.SupportedScopes -Force
      if ($Info.SupportsDualScope) {
        $SuggestedManifestFields | Add-Member -NotePropertyName ScopeSwitches -NotePropertyValue ([pscustomobject]@{
            User    = $Info.UserScopeSwitch
            Machine = $Info.MachineScopeSwitch
          }) -Force
      }
      [pscustomobject]@{
        Family                               = 'Qt Installer Framework'
        Confidence                           = 'high'
        InstallerType                        = 'exe # Qt Installer Framework'
        Metadata                             = $Info
        FormatInfo                           = $FormatInfo
        ProductVersion                       = $Info.DisplayVersion
        ProductName                          = $Info.DisplayName
        Publisher                            = $Info.Publisher
        ProductCode                          = $Info.ProductCode
        Scope                                = $Info.Scope
        SupportedScopes                      = $Info.SupportedScopes
        SupportsDualScope                    = $Info.SupportsDualScope
        Protocols                            = $Info.Protocols
        FileExtensions                       = $Info.FileExtensions
        RegistryAssociationInfo              = $Info.RegistryAssociationInfo
        InterfaceVariant                     = $Info.InterfaceVariant
        SupportsSilentInstallation           = $Info.SupportsSilentInstallation
        RequiresExplicitInstallLocation      = $Info.RequiresExplicitInstallLocation
        SupportsExistingInstallationOverride = $Info.SupportsExistingInstallationOverride
        RecommendedUpgradeBehavior           = $Info.RecommendedUpgradeBehavior
        SuggestedManifestFields              = $SuggestedManifestFields
      }
    }
    $KnownResult
    if ($KnownResult.Success) { return }
  }

  if (Test-InstallerCandidateFamily -Family 'install4j') {
    $KnownResult = Invoke-InstallerDetector -Name 'install4j' -ScriptBlock {
      $Info = Get-Install4jInfo -Path $AnalyzerInstallerPath
      $SuggestedManifestFields = Get-InstallerExeFamilyDefault -Family 'install4j'
      if ($Info.Scope) { $SuggestedManifestFields | Add-Member -NotePropertyName Scope -NotePropertyValue $Info.Scope -Force }
      if ($Info.SupportedScopes) { $SuggestedManifestFields | Add-Member -NotePropertyName SupportedScopes -NotePropertyValue $Info.SupportedScopes -Force }
      if ($Info.ProductCode) { $SuggestedManifestFields | Add-Member -NotePropertyName ProductCode -NotePropertyValue $Info.ProductCode -Force }
      [pscustomobject]@{
        Family                  = 'install4j'
        Confidence              = if ($Info.Config) { 'high' } else { 'medium' }
        InstallerType           = 'exe # install4j'
        Metadata                = $Info
        ProductVersion          = $Info.DisplayVersion
        ProductName             = $Info.DisplayName
        Publisher               = $Info.Publisher
        ProductCode             = $Info.ProductCode
        Scope                   = $Info.Scope
        SupportedScopes         = $Info.SupportedScopes
        SupportsDualScope       = $Info.SupportsDualScope
        SuggestedManifestFields = $SuggestedManifestFields
      }
    }
    $KnownResult
    if ($KnownResult.Success) { return }
  }

  if ((Test-InstallerCandidateFamily -Family 'Squirrel') -or (Test-InstallerCandidateFamily -Family 'Velopack')) {
    $KnownResult = Invoke-InstallerDetector -Name 'Squirrel/Velopack' -ScriptBlock {
      $Info = Get-SquirrelInfo -Path $AnalyzerInstallerPath
      [pscustomobject]@{
        Family                  = $Info.Family
        Confidence              = $Info.Confidence
        InstallerType           = 'exe # Squirrel'
        Metadata                = $Info
        ProductVersion          = $Info.DisplayVersion
        ProductName             = $Info.DisplayName
        Publisher               = $Info.Publisher
        ProductCode             = $Info.ProductCode
        Scope                   = $Info.Scope
        SuggestedManifestFields = $Info.SuggestedManifestFields
      }
    }
    $KnownResult
    if ($KnownResult.Success) { return }
  }
}

function Invoke-InstallerAnalysisCore {
  <#
  .SYNOPSIS
    Statically identify and summarize a Windows installer
  .DESCRIPTION
    This function is read-only. It runs PackageModule parser functions that are already
    loaded by Dumplings, scans bounded string windows for generic EXE families, and
    returns structured evidence for manifest decisions. It does not execute installers
    and does not format or serialize output for callers. DetectedFamilies contains only
    structurally confirmed or successfully parsed families. RoutingHints and
    RejectedCandidates retain unvalidated routing evidence without promoting it to a
    detected installer family.
  .PARAMETER Path
    The installer path to inspect
  .PARAMETER ScanBytes
    Total byte budget used for bounded multi-window string heuristics
  .PARAMETER ExtractEmbeddedMsi
    For Advanced Installer, also try static extraction of embedded MSI metadata
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, HelpMessage = 'The installer path to inspect')]
    [string]$Path,

    [Parameter(HelpMessage = 'Total byte budget used for bounded multi-window string heuristics')]
    [ValidateRange(4096, 268435456)]
    [int64]$ScanBytes = 16777216,

    [Parameter(HelpMessage = 'For Advanced Installer, also try static extraction of embedded MSI metadata')]
    [switch]$ExtractEmbeddedMsi
  )

  process {
    $Installer = Get-Item -LiteralPath $Path -Force
    $Extension = $Installer.Extension.ToLowerInvariant()
    $FileType = Get-InstallerFileTypeEvidence -File $Installer
    $Analysis = [ordered]@{
      Path                   = $Installer.FullName
      FileName               = $Installer.Name
      Length                 = $Installer.Length
      Sha256                 = (Get-FileHash -LiteralPath $Installer.FullName -Algorithm SHA256).Hash
      Extension              = $Extension
      DetectedFileType       = $FileType
      AuthenticodeSigner     = (Get-AuthenticodeSignature -LiteralPath $Installer.FullName -ErrorAction SilentlyContinue).SignerCertificate.Subject
      VersionInfo            = Get-InstallerFileVersionEvidence -File $Installer -ErrorAction SilentlyContinue
      ParserResults          = @()
      DetectedFamilies       = @()
      RoutingHints           = @()
      RejectedCandidates     = @()
      # Compatibility projection retained for callers written before evidence
      # separation. It contains confirmed families only.
      FamilyCandidates       = @()
      PortableEvidence       = $null
      Diagnostics            = @()
      HasWarningDiagnostics  = $false
      HasErrorDiagnostics    = $false
      HasBlockingDiagnostics = $false
      SuggestedNextSteps     = @()
    }

    switch ($FileType.Type) {
      'MSI' {
        $Analysis.ParserResults += Invoke-InstallerDetector -Name 'Windows Installer' -ScriptBlock {
          Invoke-InstallerMsiAnalysis -InstallerPath $Installer.FullName
        }
      }
      'MSP' {
        $Analysis.ParserResults += [pscustomobject]@{
          Name    = 'Windows Installer Patch'
          Success = $true
          Result  = [pscustomobject]@{
            Family                  = 'MSP'
            Confidence              = 'high'
            InstallerType           = 'msp'
            SuggestedManifestFields = [pscustomobject]@{ InstallerType = 'msp'; Note = 'Windows Installer patch package; verify winget-pkgs support and target-product behavior before authoring.' }
          }
        }
        $Analysis.SuggestedNextSteps += 'This file is a Windows Installer patch package by CFB root storage CLSID. Verify patch-package behavior before authoring.'
      }
      'MST' {
        $Analysis.Diagnostics += New-InstallerDiagnostic -Id 'InstallerArtifact.MstNotStandalone' -Source 'InstallerAnalyzer' -Message 'Windows Installer transform files are not standalone installer entries.' -Kind Invalid -Areas Detection, Installability
        $Analysis.SuggestedNextSteps += 'Use the base MSI/MSP package instead of the MST transform.'
      }
      'WindowsInstallerDatabase' {
        $Analysis.ParserResults += Invoke-InstallerDetector -Name 'Windows Installer' -ScriptBlock {
          Invoke-InstallerMsiAnalysis -InstallerPath $Installer.FullName
        }
        $Analysis.SuggestedNextSteps += 'This file uses CFB structured storage but has an unknown Windows Installer CLSID; verify whether it is MSI, MSP, MSM, MST, or another CFB document before authoring.'
      }
      'MSIXAppX' {
        $MsixResult = Invoke-InstallerDetector -Name 'MSIX/AppX' -ScriptBlock {
          Invoke-InstallerMsixAnalysis -InstallerPath $Installer.FullName
        }
        $Analysis.ParserResults += $MsixResult
        if ($MsixResult.Success -and $MsixResult.Result.Rejected) {
          $Analysis.Diagnostics += New-InstallerDiagnostic -Id 'MSIX.RejectedInstaller' -Source 'MSIX/AppX' -Message $MsixResult.Result.RejectionReason -Kind Invalid -Areas Detection, Installability -Evidence $MsixResult.Result
          $Analysis.SuggestedNextSteps += $MsixResult.Result.RejectionReason
        }
      }
      'ZipArchive' {
        # ParserResults is a collection of detector envelopes. Keep archive
        # analysis behind the same success/error boundary as every other
        # family so consumers never need to special-case raw ZIP results.
        $Analysis.ParserResults += Invoke-InstallerDetector -Name 'ZIP/archive' -ScriptBlock {
          Invoke-InstallerZipAnalysis -InstallerPath $Installer.FullName
        }
      }
      'PE' {
        $ScanText = Read-InstallerStringWindows -File $Installer -Budget $ScanBytes
        $StructuralCandidates = @(Get-InstallerStructuralExeFamilyCandidate -File $Installer | ForEach-Object {
            # These structures identify the outer container by format. The raw
            # NSIS signature and InstallBuilder project marker remain routes until
            # their parsers validate surrounding offsets and records.
            $OuterContainer = $_.Family -cin @('Burn', 'Inno Setup', 'Kachina', 'MicaSetup', 'Zero Install', 'Qt Installer Framework', 'Advanced Installer')
            ConvertTo-InstallerFamilyEvidence -Candidate $_ -EvidenceKind Structural -IsOuterContainer:$OuterContainer
          })
        $HeuristicCandidates = @(Get-InstallerGenericExeFamilyCandidate -File $Installer -Budget $ScanBytes -Text $ScanText | ForEach-Object {
            ConvertTo-InstallerFamilyEvidence -Candidate $_ -EvidenceKind Heuristic
          })
        $AllCandidates = @(
          $StructuralCandidates
          $HeuristicCandidates
        )
        $FamilyCandidates = @($AllCandidates | Group-Object Family | ForEach-Object { $_.Group | Sort-Object { if ($_.Confidence -eq 'high') { 0 } elseif ($_.Confidence -eq 'medium') { 1 } else { 2 } } | Select-Object -First 1 })
        $ParserRuns = @(Invoke-InstallerExeParser -InstallerPath $Installer.FullName -ExtractEmbeddedMsi:$ExtractEmbeddedMsi.IsPresent -FamilyCandidates $FamilyCandidates)
        $Analysis.ParserResults += $ParserRuns
        $ResolvedFamilies = Resolve-InstallerFamilyEvidence -Candidates $FamilyCandidates -ParserResults $ParserRuns
        $Analysis.DetectedFamilies += @($ResolvedFamilies.DetectedFamilies)
        $Analysis.RoutingHints += @($ResolvedFamilies.RoutingHints)
        $Analysis.RejectedCandidates += @($ResolvedFamilies.RejectedCandidates)
        $Analysis.FamilyCandidates += @($ResolvedFamilies.DetectedFamilies)
        $Analysis.Diagnostics += @(Get-InstallerWrapperDiagnostic -File $Installer -Budget $ScanBytes -ParserRuns $ParserRuns -Text $ScanText)
        if (-not ($ParserRuns.Success -contains $true)) {
          $Analysis.PortableEvidence = try { Get-InstallerPortableEvidence -Path $Installer.FullName } catch { $null }
        }
        if ($Analysis.PortableEvidence -and $Analysis.PortableEvidence.RecommendedPackageDependencyIds.Count -gt 0) {
          $Analysis.SuggestedNextSteps += "Portable evidence: static dependency evidence maps to package dependencies: $($Analysis.PortableEvidence.RecommendedPackageDependencyIds -join ', ')."
        }
        if (@($Analysis.Diagnostics | Where-Object Id -Like 'InstallerWrapper.*').Count -gt 0) {
          $Analysis.SuggestedNextSteps += 'Wrapper warning: the NSIS/Inno outer installer appears to contain nested installer payloads. Inspect the nested payload or use VM ARP-delta validation before setting AppsAndFeaturesEntries.'
        }
        $Analysis.SuggestedNextSteps += 'Use high-confidence parser results first. Use heuristic candidates only to choose which family-specific static or VM validation to run next.'
        $Analysis.SuggestedNextSteps += 'For generic EXE families, confirm silent switches and visible ARP entries in a VM unless publisher docs or existing manifest evidence is exact.'
      }
      'AppInstaller' {
        $Analysis.SuggestedNextSteps += '.appinstaller is not accepted by winget-pkgs manifests. Parse its XML and analyze the referenced MSIX/AppX package instead.'
      }
      'HTMLDocument' {
        $Analysis.Diagnostics += New-InstallerDiagnostic -Id 'InstallerArtifact.HtmlResponse' -Source 'InstallerAnalyzer' -Message 'The downloaded response is an HTML document, not an installer.' -Kind Invalid -Areas Detection, Installability
        $Analysis.SuggestedNextSteps += 'Retry the official installer URL or inspect its redirect, authentication, and rate-limit behavior.'
      }
      default {
        $Analysis.SuggestedNextSteps += 'Unknown file signature; inspect as archive or PE manually before choosing a installer type.'
      }
    }

    # Non-PE parsers already operate on decisive container evidence. Project
    # their successful family result into the same confirmed-family contract.
    if ($FileType.Type -cne 'PE') {
      foreach ($ParserResult in @($Analysis.ParserResults | Where-Object { $_.Success -and $_.Result })) {
        $FamilyProperty = $ParserResult.Result.PSObject.Properties['Family']
        if ($null -eq $FamilyProperty -or [string]::IsNullOrWhiteSpace([string]$FamilyProperty.Value)) { continue }
        $Analysis.DetectedFamilies += [pscustomobject][ordered]@{
          Family                  = [string]$FamilyProperty.Value
          Confidence              = 'high'
          EvidenceKind            = 'Parser'
          ValidationStatus        = 'ConfirmedParser'
          IsOuterContainer        = $true
          ParserName              = [string]$ParserResult.Name
          MatchedMarkers          = @()
          SuggestedManifestFields = $ParserResult.Result.SuggestedManifestFields
        }
      }
      $Analysis.DetectedFamilies = @($Analysis.DetectedFamilies | Group-Object Family | ForEach-Object { $_.Group | Select-Object -First 1 })
      $Analysis.FamilyCandidates = @($Analysis.DetectedFamilies)
    }

    # Parser results remain context-neutral. The analyzer is the first concrete
    # workflow boundary, so it resolves all nested and detector diagnostics for
    # a complete static-analysis report only after every family has run.
    $RawDiagnostics = [Collections.Generic.List[object]]::new()
    foreach ($Diagnostic in @($Analysis.Diagnostics)) { if ($Diagnostic) { $RawDiagnostics.Add($Diagnostic) } }
    foreach ($ParserResult in @($Analysis.ParserResults)) {
      if (($FileType.Type -cne 'PE' -or $ParserResult.Success) -and $ParserResult.PSObject.Properties['Diagnostics']) {
        foreach ($Diagnostic in @($ParserResult.Diagnostics)) { if ($Diagnostic) { $RawDiagnostics.Add($Diagnostic) } }
      }
      if ($ParserResult.Success -and $ParserResult.Result) {
        if ($ParserResult.Result.PSObject.Properties['Diagnostics']) {
          foreach ($Diagnostic in @($ParserResult.Result.Diagnostics)) { if ($Diagnostic) { $RawDiagnostics.Add($Diagnostic) } }
        }
        if ($ParserResult.Result.PSObject.Properties['Metadata']) {
          if ($ParserResult.Result.Metadata -and $ParserResult.Result.Metadata.PSObject.Properties['Diagnostics']) {
            foreach ($Diagnostic in @($ParserResult.Result.Metadata.Diagnostics)) { if ($Diagnostic) { $RawDiagnostics.Add($Diagnostic) } }
          }
        }
      }
    }
    foreach ($RejectedCandidate in @($Analysis.RejectedCandidates)) {
      foreach ($Diagnostic in @($RejectedCandidate.Diagnostics)) { if ($Diagnostic) { $RawDiagnostics.Add($Diagnostic) } }
    }
    if ($Analysis.PortableEvidence -and $Analysis.PortableEvidence.PSObject.Properties['Diagnostics']) {
      foreach ($Diagnostic in @($Analysis.PortableEvidence.Diagnostics)) { if ($Diagnostic) { $RawDiagnostics.Add($Diagnostic) } }
    }
    $Analysis.Diagnostics = @(Resolve-InstallerDiagnostics -Diagnostic $RawDiagnostics.ToArray() -Scenario FullAnalysis)
    $Analysis.HasWarningDiagnostics = @($Analysis.Diagnostics | Where-Object Level -EQ Warning).Count -gt 0
    $Analysis.HasErrorDiagnostics = @($Analysis.Diagnostics | Where-Object Level -EQ Error).Count -gt 0
    $Analysis.HasBlockingDiagnostics = @($Analysis.Diagnostics | Where-Object IsBlocking).Count -gt 0

    [pscustomobject]$Analysis
  }
}

function Get-InstallerAnalysis {
  <#
  .SYNOPSIS
    Statically identify and summarize a Windows installer.
  .PARAMETER Path
    The installer path to inspect.
  .PARAMETER ScanBytes
    Total byte budget used for bounded multi-window string heuristics.
  .PARAMETER ExtractEmbeddedMsi
    Also extract embedded MSI metadata from supported wrappers.
  .PARAMETER FamilyProjectionProvider
    Optional provider-specific family projection used by adapters such as WinGetAnalysis.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)][string]$Path,
    [ValidateRange(4096, 268435456)][int64]$ScanBytes = 16777216,
    [switch]$ExtractEmbeddedMsi,
    [scriptblock]$FamilyProjectionProvider
  )
  process {
    $PreviousProvider = $Script:InstallerFamilyProjectionProvider
    try {
      $Script:InstallerFamilyProjectionProvider = $FamilyProjectionProvider
      Invoke-InstallerAnalysisCore -Path $Path -ScanBytes $ScanBytes -ExtractEmbeddedMsi:$ExtractEmbeddedMsi
    } finally {
      $Script:InstallerFamilyProjectionProvider = $PreviousProvider
    }
  }
}

Export-ModuleMember -Function Get-InstallerAnalysis
