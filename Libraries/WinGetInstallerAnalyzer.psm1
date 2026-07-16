# SPDX-License-Identifier: MIT
# Detection references: https://github.com/horsicq/Detect-It-Easy and https://github.com/Bioruebe/UniExtract2

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

function Invoke-WinGetInstallerDetector {
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
      Name    = $Name
      Success = $true
      Result  = & $ScriptBlock
    }
  } catch {
    [pscustomobject]@{
      Name    = $Name
      Success = $false
      Error   = $_.Exception.Message
    }
  }
}

function Get-WinGetInstallerFileVersionEvidence {
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

function Test-WinGetInstallerBytePrefix {
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

function Read-WinGetInstallerHeader {
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
  if ($ReadCount -le 0) { return ,([byte[]]::new(0)) }

  $Stream = [System.IO.File]::Open($File.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
  try {
    return ,(Read-PEFileBytes -Stream $Stream -Offset 0 -Count $ReadCount)
  } finally {
    $Stream.Dispose()
  }
}

function Read-WinGetInstallerCfbRootStorageClassId {
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

  $Header = Read-WinGetInstallerHeader -File $File -Count 512
  $CfbMagic = [byte[]](0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1)
  if (-not (Test-WinGetInstallerBytePrefix -Bytes $Header -Prefix $CfbMagic)) { return $null }

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

function Get-WinGetInstallerCfbTypeEvidence {
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

  $ClassId = Read-WinGetInstallerCfbRootStorageClassId -File $File
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
    Type     = $Type
    Format   = $Format
    ClassId  = $ClassIdText
    Note     = 'Windows Installer CFB root storage CLSID, not filename extension, identifies MSI/MSP/MST.'
  }
}

function Get-WinGetInstallerZipTypeEvidence {
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
      EntryCount         = $Entries.Count
      SampleEntries      = $SampleEntries
      HasAppxManifest    = $HasAppxManifest
      HasBundleManifest  = $HasBundleManifest
      HasAppxSignature   = $HasAppxSignature
      IsAppxMsixFamily   = $HasAppxManifest -or $HasBundleManifest -or $HasAppxSignature
    }
  } finally {
    $Archive.Dispose()
  }
}

function Get-WinGetInstallerPeTypeEvidence {
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

function Get-WinGetInstallerPortableEvidence {
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
  [pscustomobject]@{
    ArchitectureInfo                = $ArchitectureInfo
    DependencyInfo                  = $DependencyInfo
    RecommendedWinGetArchitecture   = $ArchitectureInfo.RecommendedWinGetArchitecture
    RecommendedWinGetArchitectures  = $ArchitectureInfo.RecommendedWinGetArchitectures
    RecommendedPackageDependencies  = $DependencyInfo.RecommendedPackageDependencies
    RecommendedPackageDependencyIds = $DependencyInfo.RecommendedPackageDependencyIds
    Warnings                        = @($ArchitectureInfo.Warnings + $DependencyInfo.Warnings)
  }
}

function Get-WinGetInstallerPackageSignatureEvidence {
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

function Get-WinGetInstallerFileTypeEvidence {
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

  $Header = Read-WinGetInstallerHeader -File $File
  $HeaderHex = ($Header | Select-Object -First 16 | ForEach-Object { $_.ToString('X2') }) -join ' '
  $Extension = $File.Extension.ToLowerInvariant()

  $CfbMagic = [byte[]](0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1)
  if (Test-WinGetInstallerBytePrefix -Bytes $Header -Prefix $CfbMagic) {
    $CfbEvidence = Get-WinGetInstallerCfbTypeEvidence -File $File
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
    if (Test-WinGetInstallerBytePrefix -Bytes $Header -Prefix $ZipMagic) {
      $ZipEvidence = Get-WinGetInstallerZipTypeEvidence -Path $File.FullName -ErrorAction SilentlyContinue
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

  if (Test-WinGetInstallerBytePrefix -Bytes $Header -Prefix ([byte[]](0x4D, 0x5A))) {
    $PeEvidence = try { Get-WinGetInstallerPeTypeEvidence -Path $File.FullName } catch { $null }
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

  [pscustomobject]@{
    Type       = 'Unknown'
    Confidence = 'low'
    Magic      = $HeaderHex
    Extension  = $Extension
    Evidence   = $null
  }
}

function Read-WinGetInstallerStringWindows {
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

function Test-WinGetInstallerTextPattern {
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

function Get-WinGetInstallerExeFamilyDefault {
  <#
  .SYNOPSIS
    Get suggested manifest defaults for a generic EXE family
  .PARAMETER Family
    The generic EXE family name
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The generic EXE family name')]
    [string]$Family
  )

  switch ($Family) {
    'Advanced Installer' {
      [pscustomobject]@{
        InstallerType       = 'exe # Advanced Installer'
        Scope               = 'machine'
        InstallModes        = @('interactive', 'silent', 'silentWithProgress')
        InstallerSwitches   = [ordered]@{ Silent = '/exenoui /quiet /norestart'; SilentWithProgress = '/exenoui /passive /norestart'; InstallLocation = 'APPDIR="<INSTALLPATH>"'; Log = '/log "<LOGPATH>"' }
        ExpectedReturnCodes = @(
          [ordered]@{ InstallerReturnCode = -1; ReturnResponse = 'cancelledByUser' },
          [ordered]@{ InstallerReturnCode = 1; ReturnResponse = 'invalidParameter' },
          [ordered]@{ InstallerReturnCode = 87; ReturnResponse = 'invalidParameter' },
          [ordered]@{ InstallerReturnCode = 1601; ReturnResponse = 'contactSupport' },
          [ordered]@{ InstallerReturnCode = 1602; ReturnResponse = 'cancelledByUser' },
          [ordered]@{ InstallerReturnCode = 1618; ReturnResponse = 'installInProgress' },
          [ordered]@{ InstallerReturnCode = 1623; ReturnResponse = 'systemNotSupported' },
          [ordered]@{ InstallerReturnCode = 1625; ReturnResponse = 'blockedByPolicy' },
          [ordered]@{ InstallerReturnCode = 1628; ReturnResponse = 'invalidParameter' },
          [ordered]@{ InstallerReturnCode = 1633; ReturnResponse = 'systemNotSupported' },
          [ordered]@{ InstallerReturnCode = 1638; ReturnResponse = 'alreadyInstalled' },
          [ordered]@{ InstallerReturnCode = 1639; ReturnResponse = 'invalidParameter' },
          [ordered]@{ InstallerReturnCode = 1640; ReturnResponse = 'blockedByPolicy' },
          [ordered]@{ InstallerReturnCode = 1641; ReturnResponse = 'rebootInitiated' },
          [ordered]@{ InstallerReturnCode = 1643; ReturnResponse = 'blockedByPolicy' },
          [ordered]@{ InstallerReturnCode = 1644; ReturnResponse = 'blockedByPolicy' },
          [ordered]@{ InstallerReturnCode = 1649; ReturnResponse = 'blockedByPolicy' },
          [ordered]@{ InstallerReturnCode = 1650; ReturnResponse = 'invalidParameter' },
          [ordered]@{ InstallerReturnCode = 1654; ReturnResponse = 'systemNotSupported' },
          [ordered]@{ InstallerReturnCode = 3010; ReturnResponse = 'rebootRequiredToFinish' }
        )
        Notes               = @('The documented Advanced Installer bootstrapper return codes are included; verify customized launchers and payload-specific codes in a VM.', 'Decide AppsAndFeaturesEntries.InstallerType from the visible ARP entry, not just the embedded MSI.', 'Some packages use EXE ARP and hide MSI ARP with SystemComponent.')
      }
    }
    'InstallShield' {
      [pscustomobject]@{
        InstallerType       = 'exe # InstallShield'
        Scope               = 'machine'
        InstallModes        = @('interactive', 'silent', 'silentWithProgress')
        InstallerSwitches   = [ordered]@{ Silent = '/S /V/quiet /V/norestart'; SilentWithProgress = '/S /V/passive /V/norestart'; InstallLocation = '/V"INSTALLDIR=""<INSTALLPATH>"""'; Log = '/V"/log ""<LOGPATH>"""' }
        ExpectedReturnCodes = @()
        Notes               = @('Use these switches only for Basic MSI or InstallScript MSI variants.', 'If VM validation proves setup.exe propagates nested MSI exit codes, add the MSI mappings explicitly because the outer type is generic exe.', 'Block InstallScript-only installers that require setup.iss response files.')
      }
    }
    'InstallShield Advanced UI' {
      [pscustomobject]@{
        InstallerType       = 'exe # InstallShield Advanced UI'
        Scope               = 'machine'
        InstallModes        = @('interactive', 'silent', 'silentWithProgress')
        InstallerSwitches   = [ordered]@{ Silent = '/silent'; SilentWithProgress = '/passive'; InstallLocation = '/INSTALLDIR="<INSTALLPATH>"' }
        ExpectedReturnCodes = @(
          [ordered]@{ InstallerReturnCode = 0x8004070b; ReturnResponse = 'invalidParameter' },
          [ordered]@{ InstallerReturnCode = 0x80040711; ReturnResponse = 'installInProgress' },
          [ordered]@{ InstallerReturnCode = 1601; ReturnResponse = 'contactSupport' },
          [ordered]@{ InstallerReturnCode = 1602; ReturnResponse = 'cancelledByUser' },
          [ordered]@{ InstallerReturnCode = 1618; ReturnResponse = 'installInProgress' },
          [ordered]@{ InstallerReturnCode = 1623; ReturnResponse = 'systemNotSupported' },
          [ordered]@{ InstallerReturnCode = 1625; ReturnResponse = 'blockedByPolicy' },
          [ordered]@{ InstallerReturnCode = 1628; ReturnResponse = 'invalidParameter' },
          [ordered]@{ InstallerReturnCode = 1633; ReturnResponse = 'systemNotSupported' },
          [ordered]@{ InstallerReturnCode = 1638; ReturnResponse = 'alreadyInstalled' },
          [ordered]@{ InstallerReturnCode = 1639; ReturnResponse = 'invalidParameter' },
          [ordered]@{ InstallerReturnCode = 1640; ReturnResponse = 'blockedByPolicy' },
          [ordered]@{ InstallerReturnCode = 1641; ReturnResponse = 'rebootInitiated' },
          [ordered]@{ InstallerReturnCode = 1643; ReturnResponse = 'blockedByPolicy' },
          [ordered]@{ InstallerReturnCode = 1644; ReturnResponse = 'blockedByPolicy' },
          [ordered]@{ InstallerReturnCode = 1649; ReturnResponse = 'blockedByPolicy' },
          [ordered]@{ InstallerReturnCode = 1650; ReturnResponse = 'invalidParameter' },
          [ordered]@{ InstallerReturnCode = 1654; ReturnResponse = 'systemNotSupported' },
          [ordered]@{ InstallerReturnCode = 3010; ReturnResponse = 'rebootRequiredToFinish' }
        )
        Notes               = @('Use only after the package is independently identified as InstallShield Advanced UI.', 'Do not apply these switches to Basic MSI, InstallScript MSI, or InstallScript-only installers.')
      }
    }
    'Squirrel' {
      [pscustomobject]@{
        InstallerType       = 'exe # Squirrel'
        Scope               = 'user'
        InstallModes        = @('interactive', 'silent')
        InstallerSwitches   = [ordered]@{ Silent = '--silent'; SilentWithProgress = '--silent' }
        ExpectedReturnCodes = @()
        UpgradeBehavior     = 'install'
        Notes               = @('ProductCode is usually the embedded .nuspec id.', 'VM-check HKCU ARP, install path, and upgrade behavior.', 'Velopack descendants may need different uninstall behavior.')
      }
    }
    'Velopack' {
      [pscustomobject]@{
        InstallerType       = 'exe # Velopack'
        Scope               = 'user'
        InstallModes        = @('interactive', 'silent')
        InstallerSwitches   = [ordered]@{ Silent = '--silent'; SilentWithProgress = '--silent'; InstallLocation = '--installto "<INSTALLPATH>"'; Log = '--log "<LOGPATH>"' }
        ExpectedReturnCodes = @()
        UpgradeBehavior     = 'install'
        Notes               = @('ProductCode is usually the embedded .nuspec id.', 'VM-check HKCU ARP, install path, and upgrade behavior.')
      }
    }
    'Setup Factory' {
      [pscustomobject]@{
        InstallerType       = 'exe # Setup Factory'
        InstallModes        = @('interactive', 'silent')
        InstallerSwitches   = [ordered]@{ Silent = '/S'; SilentWithProgress = '/S' }
        ExpectedReturnCodes = @()
        Notes               = @('Use Get-SetupFactoryInfo for structured session variables, built-in uninstall settings, literal registry actions, ProductCode, publisher, and scope.', 'Verify case-sensitive switches and any required no-restart option in a VM.')
      }
    }
    'InstallAnywhere' {
      [pscustomobject]@{
        InstallerType       = 'exe # InstallAnywhere'
        InstallModes        = @('interactive', 'silent')
        InstallerSwitches   = [ordered]@{ Silent = '-i silent'; SilentWithProgress = '-i silent'; InstallLocation = '-DUSER_INSTALL_DIR="<INSTALLPATH>"' }
        ExpectedReturnCodes = @()
        Notes               = @('Stop if the package requires an installer.properties response file that cannot be expressed statically.')
      }
    }
    'InstallAware' {
      [pscustomobject]@{
        InstallerType       = 'exe # InstallAware'
        Scope               = 'machine'
        InstallModes        = @('interactive', 'silent', 'silentWithProgress')
        InstallerSwitches   = [ordered]@{ Silent = '/s'; SilentWithProgress = '/s'; InstallLocation = 'TARGETDIR="<INSTALLPATH>"'; Log = '/l="<LOGPATH>"' }
        ExpectedReturnCodes = @()
        Notes               = @('Confirm exact switches; some InstallAware packages are MSI-backed and may forward MSI properties.')
      }
    }
    'Actual Installer' {
      [pscustomobject]@{
        InstallerType       = 'exe # Actual Installer'
        InstallModes        = @('interactive', 'silent', 'silentWithProgress')
        InstallerSwitches   = [ordered]@{ Silent = '/S /L'; SilentWithProgress = '/S /L'; Interactive = '/L'; InstallLocation = '/D "<INSTALLPATH>"' }
        ExpectedReturnCodes = @()
        ScopeSwitches       = [pscustomobject]@{ User = '/CU'; Machine = '/RUNAS /ALL' }
        Notes               = @('Actual Installer can use /CU for current-user scope and /RUNAS /ALL for machine scope.', 'Verify package-specific ARP data and whether the setup permits both scopes.')
      }
    }
    'DeployMaster' {
      [pscustomobject]@{
        InstallerType       = 'exe # DeployMaster'
        InstallModes        = @('interactive', 'silent')
        InstallerSwitches   = [ordered]@{ Silent = '/silent'; SilentWithProgress = '/silent'; InstallLocation = '/appfolder "<INSTALLPATH>"' }
        ExpectedReturnCodes = @()
        Notes               = @('Verify accepted switch spelling and visible ARP entry in a VM.')
      }
    }
    '7z SFX' {
      [pscustomobject]@{
        InstallerType       = 'exe # 7z SFX'
        InstallModes        = @('interactive', 'silent', 'silentWithProgress')
        InstallerSwitches   = [ordered]@{ Silent = '-y'; SilentWithProgress = '-y' }
        ExpectedReturnCodes = @()
        Notes               = @('7z SFX is a wrapper; inspect the SFX config/comment and analyze the configured nested payload before choosing final switches or ARP metadata.', 'Use MSI/WiX AppsAndFeaturesEntries only when the nested installer writes a Windows Installer ARP entry.')
      }
    }
    'WinRAR GUI SFX' {
      [pscustomobject]@{
        InstallerType       = 'exe # WinRAR GUI SFX'
        InstallModes        = @('interactive', 'silent', 'silentWithProgress')
        InstallerSwitches   = [ordered]@{ Silent = '/S'; SilentWithProgress = '/S' }
        ExpectedReturnCodes = @()
        Notes               = @('WinRAR GUI SFX is a wrapper; inspect the SFX comment/config and analyze the configured nested payload before choosing final switches or ARP metadata.', 'Use MSI/WiX AppsAndFeaturesEntries only when the nested installer writes a Windows Installer ARP entry.')
      }
    }
    'InstallMate' {
      [pscustomobject]@{
        InstallerType       = 'exe # InstallMate'
        InstallModes        = @('interactive', 'silent', 'silentWithProgress')
        InstallerSwitches   = [ordered]@{ Silent = '/q2 /b0'; SilentWithProgress = '/q1 /b0'; InstallLocation = '"INSTALLDIR=<INSTALLPATH>"'; Log = '/log:"<LOGPATH>"' }
        ExpectedReturnCodes = @(
          [ordered]@{ InstallerReturnCode = 5; ReturnResponse = 'cancelledByUser' },
          [ordered]@{ InstallerReturnCode = 9; ReturnResponse = 'invalidParameter' },
          [ordered]@{ InstallerReturnCode = 11; ReturnResponse = 'systemNotSupported' },
          [ordered]@{ InstallerReturnCode = 12; ReturnResponse = 'rebootRequiredToFinish' },
          [ordered]@{ InstallerReturnCode = 13; ReturnResponse = 'packageInUse' },
          [ordered]@{ InstallerReturnCode = 14; ReturnResponse = 'alreadyInstalled' },
          [ordered]@{ InstallerReturnCode = 16; ReturnResponse = 'diskFull' },
          [ordered]@{ InstallerReturnCode = 20; ReturnResponse = 'installInProgress' }
        )
        Notes               = @('Verify accepted switch spelling; InstallMate packages may customize command line handling.')
      }
    }
    'QSetup' {
      [pscustomobject]@{
        InstallerType       = 'exe # QSetup'
        InstallModes        = @('interactive', 'silent', 'silentWithProgress')
        InstallerSwitches   = [ordered]@{ Silent = '/hide'; SilentWithProgress = '/silent'; InstallLocation = '/InstallDir="<INSTALLPATH>"' }
        ExpectedReturnCodes = @()
        Notes               = @('Verify switches and ARP data in a VM.')
      }
    }
    'install4j' {
      [pscustomobject]@{
        InstallerType       = 'exe # install4j'
        InstallModes        = @('interactive', 'silent', 'silentWithProgress')
        InstallerSwitches   = [ordered]@{ Silent = '-q -Dinstall4j.suppressUnattendedReboot=true'; SilentWithProgress = '-q -splash "" -Dinstall4j.suppressUnattendedReboot=true'; InstallLocation = '-dir "<INSTALLPATH>"'; Log = '-Dinstall4j.log="<LOGPATH>"' }
        ExpectedReturnCodes = @()
        Notes               = @('Use Get-Install4jInfo for static ProductCode, DisplayVersion, publisher, ARP-action, and scope evidence.', 'Use package docs or VM output to confirm unattended mode and directory switch.', 'Scope may depend on UAC availability; do not set Scope without parser evidence or VM validation.')
      }
    }
    'dotNetInstaller' {
      [pscustomobject]@{
        InstallerType       = 'exe # dotNetInstaller'
        InstallModes        = @('interactive', 'silent', 'silentWithProgress')
        InstallerSwitches   = [ordered]@{ Silent = '/q /nosplash /ComponentArgs "*":"/quiet /norestart"'; SilentWithProgress = '/qb /ComponentArgs "*":"/passive /norestart"'; Log = '/Log /LogFile "<LOGPATH>"' }
        ExpectedReturnCodes = @()
        Notes               = @('Confirm bundled prerequisite handling and final ARP entry in a VM.')
      }
    }
    'IExpress' {
      [pscustomobject]@{
        InstallerType       = 'exe # IExpress'
        InstallModes        = @('interactive', 'silent')
        InstallerSwitches   = [ordered]@{ Silent = '/Q'; SilentWithProgress = '/Q'; Log = '/L:"<LOGPATH>"' }
        ExpectedReturnCodes = @()
        Notes               = @('IExpress is a self-extracting wrapper; inspect the package command and nested payload before trusting switches or ARP metadata.', 'The visible Apps & Features entry normally comes from the nested installer or launched command.')
      }
    }
    'Wise' {
      [pscustomobject]@{
        InstallerType       = 'exe # Wise MSI'
        Scope               = 'machine'
        InstallModes        = @('interactive', 'silent', 'silentWithProgress')
        InstallerSwitches   = [ordered]@{ Silent = '/quiet /norestart'; SilentWithProgress = '/passive /norestart'; InstallLocation = 'INSTALLDIR="<INSTALLPATH>"'; Log = '/log "<LOGPATH>"' }
        ExpectedReturnCodes = @()
        Notes               = @('These defaults apply to the Wise-for-Windows-Installer MSI wrapper parsed by Get-WiseInfo, not every Wise generation.', 'If VM validation proves the Wise wrapper propagates nested MSI exit codes, add the MSI mappings explicitly because the outer type is generic exe.', 'Use the nested MSI for ProductCode, UpgradeCode, install-location property, associations, scope evidence, and AppsAndFeaturesEntries.InstallerType.')
      }
    }
    'Chromium Setup' {
      [pscustomobject]@{
        InstallerType       = 'exe # Chromium Setup'
        InstallModes        = @()
        InstallerSwitches   = [ordered]@{}
        ExpectedReturnCodes = @()
        Notes               = @('First distinguish ChromiumMiniInstaller, ChromiumUpdater, and Omaha with Get-ChromiumSetupInfo.', 'Do not copy switches across Chromium vendor forks; 360, Brave, Chrome, Vivaldi, Maxthon, and other packages customize setup behavior.', 'An updater appguid is update-protocol identity and must not be used as ProductCode.')
      }
    }
    'InstallBuilder' {
      [pscustomobject]@{
        InstallerType       = 'exe # InstallBuilder'
        InstallModes        = @('interactive', 'silent', 'silentWithProgress')
        InstallerSwitches   = [ordered]@{ Silent = '--mode unattended'; SilentWithProgress = '--mode unattended --unattendedmodeui minimal'; InstallLocation = '--prefix "<INSTALLPATH>"'; Log = '--debugtrace "<LOGPATH>"' }
        ExpectedReturnCodes = @()
        Notes               = @('InstallBuilder --help commonly opens a transient GUI help window; prefer static strings, vendor docs, or VM validation.', 'Verify whether the package supports user or machine scope before setting Scope.')
      }
    }
    'Paquet Builder' {
      [pscustomobject]@{
        InstallerType       = 'exe # Paquet Builder'
        InstallModes        = @('interactive', 'silent')
        InstallerSwitches   = [ordered]@{ Silent = '/s'; SilentWithProgress = '/s' }
        ExpectedReturnCodes = @()
        Notes               = @('Paquet Builder 2026.1 and later recognize /s and /silent natively when the project keeps that option enabled.', 'Older or customized packages may require project-defined command-line parsing; verify the exact package.')
      }
    }
    'CreateInstall' {
      [pscustomobject]@{
        InstallerType       = 'exe # CreateInstall'
        Scope               = 'machine'
        InstallModes        = @('interactive', 'silent')
        InstallerSwitches   = [ordered]@{ Silent = '-silent'; SilentWithProgress = '-silent' }
        ExpectedReturnCodes = @()
        UpgradeBehavior     = 'install'
        Notes               = @('Accepted Novostrim.CreateInstall manifests use -silent, but custom CreateInstall projects may differ.', 'Verify package-specific ProductCode and visible ARP data in a VM.')
      }
    }
    'InstallForge' {
      [pscustomobject]@{
        InstallerType       = 'exe # InstallForge'
        InstallModes        = @('interactive')
        InstallerSwitches   = [ordered]@{}
        ExpectedReturnCodes = @()
        Notes               = @('InstallForge does not support WinGet-compatible silent installation. Do not submit unless a separate verified silent-capable build or wrapper exists.')
      }
    }
    'Qt Installer Framework' {
      [pscustomobject]@{
        InstallerType       = 'exe # Qt Installer Framework'
        InstallModes        = @('interactive', 'silentWithProgress')
        InstallerSwitches   = [ordered]@{ Silent = 'install --root "<INSTALLPATH>" --accept-licenses --default-answer --confirm-command'; SilentWithProgress = 'install --root "<INSTALLPATH>" --accept-licenses --default-answer --confirm-command' }
        ExpectedReturnCodes = @()
        UpgradeBehavior     = 'uninstallPrevious'
        Notes               = @('Use these switches only when Get-QtInstallerFrameworkInfo reports InterfaceVariant=CLI and SupportsSilentInstallation=true.', 'Keep --root in Silent and SilentWithProgress only when RequiresExplicitInstallLocation=true; otherwise expose it as InstallLocation.', 'Qt IFW writes HKLM ARP only when the AllUsers variable is true; otherwise it writes HKCU ARP.', 'Use AllUsers=true or AllUsers=false as a custom switch only when parser evidence confirms the CLI path.')
      }
    }
    default {
      [pscustomobject]@{
        InstallerType       = 'exe'
        InstallModes        = @()
        InstallerSwitches   = [ordered]@{}
        ExpectedReturnCodes = @()
        Notes               = @('Unknown EXE family; do not submit without documented or VM-verified silent switches.')
      }
    }
  }
}

function Get-WinGetInstallerGenericExeFamilyCandidate {
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

  if (-not $PSBoundParameters.ContainsKey('Text')) { $Text = Read-WinGetInstallerStringWindows -File $File -Budget $Budget }
  $Families = @(
    @{ Name = 'Advanced Installer'; Patterns = @('Advanced Installer', 'aicustact', 'AI_SETUPEXEPATH') },
    @{ Name = 'InstallShield'; Patterns = @('InstallShield', 'ISSetup.dll', 'InstallScript', 'setup.inx', 'ISScript') },
    @{ Name = 'Velopack'; Patterns = @('Velopack', 'vpk_', 'RELEASES.json') },
    @{ Name = 'Squirrel'; Patterns = @('Squirrel', 'SquirrelSetup', 'Update.exe', '.nupkg', 'RELEASES') },
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
    $MatchedMarkers = Test-WinGetInstallerTextPattern -Text $Text -Patterns $Family.Patterns
    if ($MatchedMarkers.Count -gt 0) {
      $Confidence = if ($MatchedMarkers.Count -gt 1) { 'medium' } else { 'low' }
      [pscustomobject]@{
        Family                  = $Family.Name
        Confidence              = $Confidence
        MatchedMarkers          = $MatchedMarkers
        SuggestedManifestFields = Get-WinGetInstallerExeFamilyDefault -Family $Family.Name
      }
    }
  }
}

function Get-WinGetInstallerStructuralExeFamilyCandidate {
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

  $Resources = @(Get-PEResourceInfo -Path $File.FullName -MaximumResources 16384 -ErrorAction SilentlyContinue)
  if ($Resources | Where-Object { $_.TypeId -eq 10 -and $_.Id -eq 11111 } | Select-Object -First 1) {
    if ($Seen.Add('Inno Setup')) {
      [pscustomobject]@{ Family = 'Inno Setup'; Confidence = 'high'; MatchedMarkers = @('RCDATA/11111 loader offset table'); SuggestedManifestFields = [pscustomobject]@{ InstallerType = 'inno' } }
    }
  }

  $NsisSignature = [byte[]](0xEF, 0xBE, 0xAD, 0xDE) + [Text.Encoding]::ASCII.GetBytes('NullsoftInst')
  $SignatureScanLength = [Math]::Min($File.Length, 67108864L)
  if ((Find-BinaryPattern -Path $File.FullName -Pattern $NsisSignature -Length $SignatureScanLength -Maximum 1).Count -gt 0 -and $Seen.Add('NSIS/Nullsoft')) {
    [pscustomobject]@{ Family = 'NSIS/Nullsoft'; Confidence = 'high'; MatchedMarkers = @('DEADBEEF + NullsoftInst'); SuggestedManifestFields = [pscustomobject]@{ InstallerType = 'nullsoft' } }
  }

  $QtCookie = [byte[]](0xF8, 0x68, 0xD6, 0x99, 0x1C, 0x0A, 0x63, 0xC2)
  $TailLength = [Math]::Min($File.Length, 1048576L)
  if ((Find-BinaryPattern -Path $File.FullName -Pattern $QtCookie -StartOffset ($File.Length - $TailLength) -Length $TailLength -Maximum 1 -Reverse).Count -gt 0 -and $Seen.Add('Qt Installer Framework')) {
    [pscustomobject]@{ Family = 'Qt Installer Framework'; Confidence = 'high'; MatchedMarkers = @('Qt IFW magic cookie'); SuggestedManifestFields = Get-WinGetInstallerExeFamilyDefault -Family 'Qt Installer Framework' }
  }

  $AdvancedInstallerMagic = [Text.Encoding]::ASCII.GetBytes('ADVINSTSFX')
  if ((Find-BinaryPattern -Path $File.FullName -Pattern $AdvancedInstallerMagic -Maximum 1 -Reverse).Count -gt 0 -and $Seen.Add('Advanced Installer')) {
    [pscustomobject]@{ Family = 'Advanced Installer'; Confidence = 'high'; MatchedMarkers = @('ADVINSTSFX footer'); SuggestedManifestFields = Get-WinGetInstallerExeFamilyDefault -Family 'Advanced Installer' }
  }

  $InstallBuilderProjectMarker = [Text.Encoding]::ASCII.GetBytes('project.xml')
  if ((Find-BinaryPattern -Path $File.FullName -Pattern $InstallBuilderProjectMarker -Maximum 1).Count -gt 0 -and $Seen.Add('InstallBuilder')) {
    [pscustomobject]@{ Family = 'InstallBuilder'; Confidence = 'medium'; MatchedMarkers = @('embedded project.xml record'); SuggestedManifestFields = Get-WinGetInstallerExeFamilyDefault -Family 'InstallBuilder' }
  }
}

function Get-WinGetInstallerWrapperWarning {
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

  if (-not $PSBoundParameters.ContainsKey('Text')) { $Text = Read-WinGetInstallerStringWindows -File $File -Budget $Budget }
  $MsiPayloadMarkers = Test-WinGetInstallerTextPattern -Text $Text -Patterns @(
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
  $NestedExeMarkers = Test-WinGetInstallerTextPattern -Text $Text -Patterns @(
    'setup.exe',
    'installer.exe',
    'install.exe',
    'bootstrapper.exe'
  )
  $LaunchMarkers = Test-WinGetInstallerTextPattern -Text $Text -Patterns @(
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
      if ($Metadata.PSObject.Properties.Name -contains 'Warnings') { $ParserWarnings = @($Metadata.Warnings) }
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
    [pscustomobject]@{
      AppliesTo                 = $OuterInstaller.Name
      Confidence                = $Confidence
      MsiOrWindowsInstallerTags = $MsiPayloadMarkers
      NestedExeTags             = $NestedExeMarkers
      LaunchTags                = $LaunchMarkers
      ParserEvidence            = [pscustomobject]@{
        WritesAppsAndFeaturesEntry = $ParserWritesAppsAndFeaturesEntry
        ExtractedPayloads          = @($ParserExtractedFiles)
        ExecutedPayloads           = @($ParserExecutedPayloads)
        MsiOrWindowsInstallerTags  = @($ParserMsiPayloadMarkers)
        NestedExeTags              = @($ParserNestedExeMarkers)
        Warnings                   = @($ParserWarnings)
      }
      Warning                   = 'This NSIS/Inno installer may be a wrapper around a nested installer. Do not assume the outer installer writes the visible ARP entry.'
      RequiredAction            = 'Inspect the nested payload or install in a VM and compare visible ARP entries excluding SystemComponent=1. Use the nested MSI/WiX/custom installer metadata when that payload writes Apps & Features.'
    }
  }
}

function Invoke-WinGetInstallerMsiAnalysis {
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
  $AllUsers = Read-MsiProperty -Path $AnalyzerInstallerPath -Query "SELECT Value FROM Property WHERE Property='ALLUSERS'" -ErrorAction SilentlyContinue
  $MsiInfo = Get-MsiInstallerInfo -Path $AnalyzerInstallerPath
  $ScopeRecommendation = if ($AllUsers -eq '1') {
    [pscustomobject]@{ Scope = 'machine'; Reason = 'MSI Property table contains ALLUSERS=1' }
  } elseif ([string]::IsNullOrWhiteSpace($AllUsers)) {
    [pscustomobject]@{ Scope = $null; Reason = 'MSI Property table does not contain ALLUSERS; omit Scope because ARP is still written under HKLM' }
  } else {
    [pscustomobject]@{ Scope = $null; Reason = "MSI Property table contains ALLUSERS=$AllUsers; verify package-specific scope before declaring Scope" }
  }

  [pscustomobject]@{
    Family                  = 'MSI'
    Confidence              = 'high'
    InstallerType           = 'msi'
    ProductVersion          = $MsiInfo.ProductVersion
    ProductName             = $MsiInfo.ProductName
    ProductCode             = $MsiInfo.ProductCode
    UpgradeCode             = $MsiInfo.UpgradeCode
    Protocols               = $MsiInfo.Protocols
    FileExtensions          = $MsiInfo.FileExtensions
    RegistryAssociationInfo = $MsiInfo.RegistryAssociationInfo
    AllUsers                = $AllUsers
    ScopeRecommendation     = $ScopeRecommendation
    SuggestedManifestFields = [pscustomobject]@{ InstallerType = 'msi'; Scope = $ScopeRecommendation.Scope }
  }
}

function Invoke-WinGetInstallerMsixAnalysis {
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
  $SignatureEvidence = Get-WinGetInstallerPackageSignatureEvidence -Path $InstallerPath
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

  [pscustomobject]@{
    Family                  = 'MSIX/AppX'
    Confidence              = 'high'
    InstallerType           = $PackageTypeInfo.InstallerType
    PackageKind             = $PackageTypeInfo.PackageKind
    InstallerTypeEvidence   = $PackageTypeInfo.Evidence
    InstallerTypeAmbiguous  = $PackageTypeInfo.IsAmbiguous
    ProductVersion          = if ($Identity) { $Identity.Version } else { Read-ProductVersionFromMSIX -Path $AnalyzerInstallerPath -ErrorAction SilentlyContinue }
    PackageFamilyName       = if ($Identity) { "$($Identity.Name)_$(Get-MSIXPublisherHash -PublisherName $Identity.Publisher)" } else { Read-FamilyNameFromMSIX -Path $AnalyzerInstallerPath -ErrorAction SilentlyContinue }
    Dependencies            = $DependencyInfo.Dependencies
    UnknownPackageDependencies = $DependencyInfo.UnknownPackageDependencies
    Warnings                = @($PackageTypeInfo.Warnings + $DependencyInfo.Warnings + $AssociationInfo.Warnings)
    Protocols               = $AssociationInfo.Protocols
    FileExtensions          = $AssociationInfo.FileExtensions
    RegistryAssociationInfo = $AssociationInfo
    SignatureSha256         = $SignatureEvidence.SignatureSha256
    SignatureEvidence       = $SignatureEvidence
    Rejected                = -not $SignatureEvidence.IsTrusted
    RejectionReason         = $SignatureEvidence.RequiredAction
    SuggestedManifestFields = [pscustomobject]@{ InstallerType = $PackageTypeInfo.InstallerType; Dependencies = $DependencyInfo.Dependencies }
  }
}

function Get-WinGetInstallerArchiveEntryDirectoryName {
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

function Get-WinGetInstallerArchiveEntryFileName {
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

function Copy-WinGetInstallerArchiveEntryToFile {
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

function Get-WinGetInstallerPortableArchiveCandidate {
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
    $FileName = Get-WinGetInstallerArchiveEntryFileName -EntryName $Entry.FullName
    $DirectoryName = Get-WinGetInstallerArchiveEntryDirectoryName -EntryName $Entry.FullName
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
    $FileName = Get-WinGetInstallerArchiveEntryFileName -EntryName $Entry.FullName
    $DirectoryName = Get-WinGetInstallerArchiveEntryDirectoryName -EntryName $Entry.FullName
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

function Get-WinGetInstallerPortableArchiveRelatedEntry {
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

  $CandidateDirectoryName = Get-WinGetInstallerArchiveEntryDirectoryName -EntryName $Candidate.FullName
  $CandidateFileName = Get-WinGetInstallerArchiveEntryFileName -EntryName $Candidate.FullName
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
    if ((Get-WinGetInstallerArchiveEntryDirectoryName -EntryName $Entry.FullName) -ne $CandidateDirectoryName) { continue }

    $FileName = Get-WinGetInstallerArchiveEntryFileName -EntryName $Entry.FullName
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

function Invoke-WinGetInstallerZipAnalysis {
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
    $PortableCandidates = @(Get-WinGetInstallerPortableArchiveCandidate -Entries $Entries)
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
        Copy-WinGetInstallerArchiveEntryToFile -Entry $ArchiveEntry -DestinationPath $CandidatePath

        $RelatedPaths = [System.Collections.Generic.List[string]]::new()
        foreach ($RelatedEntry in @(Get-WinGetInstallerPortableArchiveRelatedEntry -Entries $Entries -Candidate $Candidate)) {
          $RelatedArchiveEntry = $RelatedEntry
          if (-not $RelatedArchiveEntry) { continue }
          $RelatedFileName = (Get-WinGetInstallerArchiveEntryFileName -EntryName $RelatedEntry.FullName) -replace '[^\w.\-]', '_'
          if ([string]::IsNullOrWhiteSpace($RelatedFileName)) { continue }
          $RelatedPath = Join-Path -Path $CandidateFolder -ChildPath $RelatedFileName
          Copy-WinGetInstallerArchiveEntryToFile -Entry $RelatedArchiveEntry -DestinationPath $RelatedPath
          $RelatedPaths.Add($RelatedPath)
        }

        $PortableCandidateEvidence.Add([pscustomobject]@{
            RelativeFilePath     = $Candidate.FullName
            RelatedFilePaths     = @($RelatedPaths)
            Length               = $Candidate.Length
            Evidence             = Get-WinGetInstallerPortableEvidence -Path $CandidatePath -RelatedFile @($RelatedPaths)
          })
      }
    } finally {
      if ($TempFolder -and (Test-Path -LiteralPath $TempFolder)) {
        Remove-Item -LiteralPath $TempFolder -Recurse -Force
      }
    }

    [pscustomobject]@{
      Family                  = 'ZIP/archive'
      Confidence              = 'high'
      InstallerType           = 'zip'
      EntryCount              = $Entries.Count
      NestedInstallerFiles    = $NestedInstallers
      PortableCandidates      = $PortableCandidates
      PortableCandidateEvidence = @($PortableCandidateEvidence)
      SuggestedManifestFields = [pscustomobject]@{ InstallerType = 'zip'; NestedInstallerType = 'exe/msi/msix/portable based on selected nested file' }
    }
  } finally {
    $Archive.Dispose()
  }
}

function Invoke-WinGetInstallerExeParser {
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

  function Test-WinGetInstallerCandidateFamily {
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

    $SuggestedManifestFields = Get-WinGetInstallerExeFamilyDefault -Family $Family
    if ($Info.Scope) { $SuggestedManifestFields | Add-Member -NotePropertyName Scope -NotePropertyValue $Info.Scope -Force }
    if ($Info.SupportedScopes) { $SuggestedManifestFields | Add-Member -NotePropertyName SupportedScopes -NotePropertyValue @($Info.SupportedScopes) -Force }
    if ($Info.ProductCode) { $SuggestedManifestFields | Add-Member -NotePropertyName ProductCode -NotePropertyValue $Info.ProductCode -Force }
    $ProductName = if ($Info.DisplayName) { $Info.DisplayName } elseif ($Info.PackageName) { $Info.PackageName } else { $Info.ProductName }
    [pscustomobject]@{
      Family                  = $Family
      Confidence              = $Confidence
      InstallerType           = "exe # $Family"
      Metadata                = $Info
      ProductVersion          = $Info.DisplayVersion
      ProductName             = $ProductName
      Publisher               = $Info.Publisher
      ProductCode             = $Info.ProductCode
      Scope                   = $Info.Scope
      SupportedScopes         = @($Info.SupportedScopes)
      Protocols               = @($Info.Protocols)
      FileExtensions          = @($Info.FileExtensions)
      RegistryAssociationInfo = $Info.RegistryAssociationInfo
      NestedInstallerFiles    = @($Info.ExtractedFiles)
      CanExpand               = $Info.CanExpand
      Warnings                = @($Info.Warnings)
      SuggestedManifestFields = $SuggestedManifestFields
    }
  }

  # Structured generic-family parsers are authoritative. Stop before broad SFX
  # heuristics when one succeeds because many installer engines embed archives.
  $StructuredParserResults = @(
    if (Test-WinGetInstallerCandidateFamily -Family 'Chromium Setup') { Invoke-WinGetInstallerDetector -Name 'Chromium Setup' -ScriptBlock {
    $Info = Get-ChromiumSetupInfo -Path $AnalyzerInstallerPath
    $SuggestedManifestFields = Get-WinGetInstallerExeFamilyDefault -Family 'Chromium Setup'
    if ($Info.Variant -eq 'ChromiumMiniInstaller') {
      $SuggestedManifestFields.InstallModes = @('silent')
      $SuggestedManifestFields.InstallerSwitches = [ordered]@{ Custom = '--do-not-launch-chrome'; Log = '--verbose-logging --log-file="<LOGPATH>"' }
      $SuggestedManifestFields | Add-Member -NotePropertyName ScopeSwitches -NotePropertyValue ([pscustomobject]@{ User = $null; Machine = '--system-level' }) -Force
    } elseif ($Info.Variant -eq 'ChromiumUpdater' -and -not $Info.IsOnlineBootstrapper) {
      $SuggestedManifestFields.InstallModes = @('interactive', 'silent')
      $SuggestedManifestFields.InstallerSwitches = [ordered]@{ Silent = '--install --silent'; SilentWithProgress = '--install --silent'; Interactive = '--install'; Log = '--enable-logging'; Upgrade = '--update' }
      $SuggestedManifestFields | Add-Member -NotePropertyName ScopeSwitches -NotePropertyValue ([pscustomobject]@{ User = '--enterprise'; Machine = '--system --enterprise' }) -Force
    } elseif ($Info.Variant -eq 'Omaha' -and -not $Info.IsOnlineBootstrapper) {
      $SuggestedManifestFields.InstallModes = @('silent')
      $SuggestedManifestFields.InstallerSwitches = [ordered]@{ Silent = '/silent'; SilentWithProgress = '/silent' }
      $SuggestedManifestFields | Add-Member -NotePropertyName ScopeSwitches -NotePropertyValue ([pscustomobject]@{ User = $Info.UserScopeSwitch; Machine = $Info.MachineScopeSwitch }) -Force
      $SuggestedManifestFields.Notes += 'This untagged Omaha package installs its embedded updater runtime. Keep the complete /install runtime tag in each scope-specific Custom switch.'
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
      ExecutedPayloads        = $Info.ExecutedPayloads
      NestedInstallerFiles    = $Info.NestedFiles
      Warnings                = $Info.Warnings
      SuggestedManifestFields = $SuggestedManifestFields
    }
  } }

    if (Test-WinGetInstallerCandidateFamily -Family 'Wise') { Invoke-WinGetInstallerDetector -Name 'Wise' -ScriptBlock {
    $Info = Get-WiseInfo -Path $AnalyzerInstallerPath
    $SuggestedManifestFields = Get-WinGetInstallerExeFamilyDefault -Family 'Wise'
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
      Warnings                = $Info.Warnings
      SuggestedManifestFields = $SuggestedManifestFields
    }
  } }

    if (Test-WinGetInstallerCandidateFamily -Family 'Setup Factory') { Invoke-WinGetInstallerDetector -Name 'Setup Factory' -ScriptBlock {
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
      SuggestedManifestFields = Get-WinGetInstallerExeFamilyDefault -Family 'Setup Factory'
    }
  } }

    if (Test-WinGetInstallerCandidateFamily -Family 'InstallAnywhere') { Invoke-WinGetInstallerDetector -Name 'InstallAnywhere' -ScriptBlock {
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
      SuggestedManifestFields = Get-WinGetInstallerExeFamilyDefault -Family 'InstallAnywhere'
    }
  } }

    if (Test-WinGetInstallerCandidateFamily -Family 'Actual Installer') { Invoke-WinGetInstallerDetector -Name 'Actual Installer' -ScriptBlock {
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
      SuggestedManifestFields = Get-WinGetInstallerExeFamilyDefault -Family 'Actual Installer'
    }
  } }

    if (Test-WinGetInstallerCandidateFamily -Family 'InstallBuilder') { Invoke-WinGetInstallerDetector -Name 'InstallBuilder' -ScriptBlock {
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
      SuggestedManifestFields = Get-WinGetInstallerExeFamilyDefault -Family 'InstallBuilder'
    }
  } }

    if (Test-WinGetInstallerCandidateFamily -Family 'InstallForge') { Invoke-WinGetInstallerDetector -Name 'InstallForge' -ScriptBlock {
    ConvertTo-GenericExeParserEvidence -Family 'InstallForge' -Info (Get-InstallForgeInfo -Path $AnalyzerInstallerPath)
  } }

    if (Test-WinGetInstallerCandidateFamily -Family 'InstallAware') { Invoke-WinGetInstallerDetector -Name 'InstallAware' -ScriptBlock {
    ConvertTo-GenericExeParserEvidence -Family 'InstallAware' -Info (Get-InstallAwareInfo -Path $AnalyzerInstallerPath)
  } }

    if (Test-WinGetInstallerCandidateFamily -Family 'Paquet Builder') { Invoke-WinGetInstallerDetector -Name 'Paquet Builder' -ScriptBlock {
    ConvertTo-GenericExeParserEvidence -Family 'Paquet Builder' -Info (Get-PaquetBuilderInfo -Path $AnalyzerInstallerPath)
  } }

    if (Test-WinGetInstallerCandidateFamily -Family 'QSetup') { Invoke-WinGetInstallerDetector -Name 'QSetup' -ScriptBlock {
    ConvertTo-GenericExeParserEvidence -Family 'QSetup' -Info (Get-QSetupInfo -Path $AnalyzerInstallerPath)
  } }

    if (Test-WinGetInstallerCandidateFamily -Family 'DeployMaster') { Invoke-WinGetInstallerDetector -Name 'DeployMaster' -ScriptBlock {
    $Info = Get-DeployMasterInfo -Path $AnalyzerInstallerPath
    $Confidence = if ($Info.RuntimeProductName -match '(?i)DeployMaster' -or $Info.FileDescription -match '(?i)DeployMaster') { 'high' } else { 'medium' }
    ConvertTo-GenericExeParserEvidence -Family 'DeployMaster' -Info $Info -Confidence $Confidence
  } }

    if (Test-WinGetInstallerCandidateFamily -Family 'CreateInstall') { Invoke-WinGetInstallerDetector -Name 'CreateInstall' -ScriptBlock {
    ConvertTo-GenericExeParserEvidence -Family 'CreateInstall' -Info (Get-CreateInstallInfo -Path $AnalyzerInstallerPath)
  } }

    if (Test-WinGetInstallerCandidateFamily -Family 'InstallMate') { Invoke-WinGetInstallerDetector -Name 'InstallMate' -ScriptBlock {
    ConvertTo-GenericExeParserEvidence -Family 'InstallMate' -Info (Get-InstallMateInfo -Path $AnalyzerInstallerPath)
  } }
  )
  $StructuredParserResults
  if ($StructuredParserResults.Success -contains $true) { return }

  if (Test-WinGetInstallerCandidateFamily -Family '7z SFX' -MinimumConfidence medium) {
    $WrapperResult = Invoke-WinGetInstallerDetector -Name '7z SFX' -ScriptBlock {
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
      SuggestedManifestFields = Get-WinGetInstallerExeFamilyDefault -Family '7z SFX'
    }
  }
    $WrapperResult
    if ($WrapperResult.Success) { return }
  }

  if (Test-WinGetInstallerCandidateFamily -Family 'WinRAR GUI SFX' -MinimumConfidence medium) {
    $WrapperResult = Invoke-WinGetInstallerDetector -Name 'WinRAR GUI SFX' -ScriptBlock {
    $Info = Get-WinRarSfxInfo -Path $AnalyzerInstallerPath
    [pscustomobject]@{
      Family                  = 'WinRAR GUI SFX'
      Confidence              = 'high'
      InstallerType           = 'exe # WinRAR GUI SFX'
      Metadata                = $Info
      ExecutedPayloads        = $Info.ExecutedPayloads
      NestedInstallerFiles    = $Info.NestedFiles
      SuggestedManifestFields = Get-WinGetInstallerExeFamilyDefault -Family 'WinRAR GUI SFX'
    }
  }
    $WrapperResult
    if ($WrapperResult.Success) { return }
  }

  if (Test-WinGetInstallerCandidateFamily -Family 'IExpress' -MinimumConfidence medium) {
    $WrapperResult = Invoke-WinGetInstallerDetector -Name 'IExpress' -ScriptBlock {
    $Info = Get-IExpressInfo -Path $AnalyzerInstallerPath
    [pscustomobject]@{
      Family                  = 'IExpress'
      Confidence              = 'high'
      InstallerType           = 'exe # IExpress'
      Metadata                = $Info
      ExecutedPayloads        = $Info.ExecutedPayloads
      NestedInstallerFiles    = $Info.NestedFiles
      SuggestedManifestFields = Get-WinGetInstallerExeFamilyDefault -Family 'IExpress'
    }
  }
    $WrapperResult
    if ($WrapperResult.Success) { return }
  }

  if (Test-WinGetInstallerCandidateFamily -Family 'dotNetInstaller' -MinimumConfidence medium) {
    $WrapperResult = Invoke-WinGetInstallerDetector -Name 'dotNetInstaller' -ScriptBlock {
    $Info = Get-DotNetInstallerInfo -Path $AnalyzerInstallerPath
    [pscustomobject]@{
      Family                  = 'dotNetInstaller'
      Confidence              = 'high'
      InstallerType           = 'exe # dotNetInstaller'
      Metadata                = $Info
      ProductVersion          = $Info.ProductVersion
      ExecutedPayloads        = $Info.ExecutedPayloads
      NestedInstallerFiles    = $Info.NestedFiles
      SuggestedManifestFields = Get-WinGetInstallerExeFamilyDefault -Family 'dotNetInstaller'
    }
  }
    $WrapperResult
    if ($WrapperResult.Success) { return }
  }

  if (Test-WinGetInstallerCandidateFamily -Family 'Burn') {
    $KnownResult = Invoke-WinGetInstallerDetector -Name 'Burn' -ScriptBlock {
    $Info = Get-BurnInfo -Path $AnalyzerInstallerPath
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

  if (Test-WinGetInstallerCandidateFamily -Family 'Inno Setup') {
    $KnownResult = Invoke-WinGetInstallerDetector -Name 'Inno' -ScriptBlock {
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

  if (Test-WinGetInstallerCandidateFamily -Family 'NSIS/Nullsoft') {
    $KnownResult = Invoke-WinGetInstallerDetector -Name 'NSIS' -ScriptBlock {
    $Info = Get-NSISInfo -Path $AnalyzerInstallerPath
    [pscustomobject]@{
      Family                  = 'NSIS/Nullsoft'
      Confidence              = 'high'
      InstallerType           = 'nullsoft'
      Metadata                = $Info
      ProductVersion          = $Info.DisplayVersion
      ProductName             = $Info.DisplayName
      Publisher               = $Info.Publisher
      ProductCode             = $Info.ProductCode
      Scope                   = $Info.Scope
      Protocols               = $Info.Protocols
      FileExtensions          = $Info.FileExtensions
      RegistryAssociationInfo = $Info.RegistryAssociationInfo
      SuggestedManifestFields = [pscustomobject]@{ InstallerType = 'nullsoft'; Scope = $Info.Scope; Notes = @('Create duplicate user/machine entries only when switch or registry-write evidence proves both modes.', 'Check decompiled strings/control flow for TestParameter, IfSilent, GetOptions, and custom silent-mode rejection.') }
    }
    }
    $KnownResult
    if ($KnownResult.Success) { return }
  }

  if (Test-WinGetInstallerCandidateFamily -Family 'Advanced Installer') {
    $KnownResult = Invoke-WinGetInstallerDetector -Name 'Advanced Installer' -ScriptBlock {
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
      SuggestedManifestFields = Get-WinGetInstallerExeFamilyDefault -Family 'Advanced Installer'
    }
    }
    $KnownResult
    if ($KnownResult.Success) { return }
  }

  if (Test-WinGetInstallerCandidateFamily -Family 'Qt Installer Framework') {
    $KnownResult = Invoke-WinGetInstallerDetector -Name 'Qt Installer Framework' -ScriptBlock {
    $Info = Get-QtInstallerFrameworkInfo -Path $AnalyzerInstallerPath
    $SuggestedManifestFields = Get-WinGetInstallerExeFamilyDefault -Family 'Qt Installer Framework'
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
      Family                  = 'Qt Installer Framework'
      Confidence              = 'high'
      InstallerType           = 'exe # Qt Installer Framework'
      Metadata                = $Info
      ProductVersion          = $Info.DisplayVersion
      ProductName             = $Info.PackageName
      Publisher               = $Info.Publisher
      ProductCode             = $Info.ProductCode
      Scope                   = $Info.Scope
      SupportedScopes         = $Info.SupportedScopes
      SupportsDualScope       = $Info.SupportsDualScope
      Protocols               = $Info.Protocols
      FileExtensions          = $Info.FileExtensions
      RegistryAssociationInfo = $Info.RegistryAssociationInfo
      InterfaceVariant        = $Info.InterfaceVariant
      SupportsSilentInstallation = $Info.SupportsSilentInstallation
      RequiresExplicitInstallLocation = $Info.RequiresExplicitInstallLocation
      SupportsExistingInstallationOverride = $Info.SupportsExistingInstallationOverride
      RecommendedUpgradeBehavior = $Info.RecommendedUpgradeBehavior
      SuggestedManifestFields = $SuggestedManifestFields
    }
    }
    $KnownResult
    if ($KnownResult.Success) { return }
  }

  if (Test-WinGetInstallerCandidateFamily -Family 'install4j') {
    $KnownResult = Invoke-WinGetInstallerDetector -Name 'install4j' -ScriptBlock {
    $Info = Get-Install4jInfo -Path $AnalyzerInstallerPath
    $SuggestedManifestFields = Get-WinGetInstallerExeFamilyDefault -Family 'install4j'
    if ($Info.Scope) { $SuggestedManifestFields | Add-Member -NotePropertyName Scope -NotePropertyValue $Info.Scope -Force }
    if ($Info.SupportedScopes) { $SuggestedManifestFields | Add-Member -NotePropertyName SupportedScopes -NotePropertyValue $Info.SupportedScopes -Force }
    if ($Info.ProductCode) { $SuggestedManifestFields | Add-Member -NotePropertyName ProductCode -NotePropertyValue $Info.ProductCode -Force }
    [pscustomobject]@{
      Family                  = 'install4j'
      Confidence              = if ($Info.Config) { 'high' } else { 'medium' }
      InstallerType           = 'exe # install4j'
      Metadata                = $Info
      ProductVersion          = $Info.DisplayVersion
      ProductName             = $Info.ProductName
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

  if ((Test-WinGetInstallerCandidateFamily -Family 'Squirrel') -or (Test-WinGetInstallerCandidateFamily -Family 'Velopack')) {
    $KnownResult = Invoke-WinGetInstallerDetector -Name 'Squirrel/Velopack' -ScriptBlock {
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

function Get-WinGetInstallerAnalysis {
  <#
  .SYNOPSIS
    Statically identify and summarize a Windows installer for WinGet manifest authoring
  .DESCRIPTION
    This function is read-only. It runs PackageModule parser functions that are already
    loaded by Dumplings, scans bounded string windows for generic EXE families, and
    returns structured evidence for manifest decisions. It does not execute installers
    and does not format or serialize output for callers.
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
    $FileType = Get-WinGetInstallerFileTypeEvidence -File $Installer
    $Analysis = [ordered]@{
      Path               = $Installer.FullName
      FileName           = $Installer.Name
      Length             = $Installer.Length
      Sha256             = (Get-FileHash -LiteralPath $Installer.FullName -Algorithm SHA256).Hash
      Extension          = $Extension
      DetectedFileType   = $FileType
      AuthenticodeSigner = (Get-AuthenticodeSignature -LiteralPath $Installer.FullName -ErrorAction SilentlyContinue).SignerCertificate.Subject
      VersionInfo        = Get-WinGetInstallerFileVersionEvidence -File $Installer -ErrorAction SilentlyContinue
      ParserResults      = @()
      FamilyCandidates   = @()
      PortableEvidence   = $null
      WrapperWarnings    = @()
      BlockingIssues     = @()
      SuggestedNextSteps = @()
    }

    switch ($FileType.Type) {
      'MSI' {
        $Analysis.ParserResults += Invoke-WinGetInstallerDetector -Name 'Windows Installer' -ScriptBlock {
          Invoke-WinGetInstallerMsiAnalysis -InstallerPath $Installer.FullName
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
        $Analysis.BlockingIssues += 'Windows Installer transform files are not standalone WinGet installers.'
        $Analysis.SuggestedNextSteps += 'Use the base MSI/MSP package instead of the MST transform.'
      }
      'WindowsInstallerDatabase' {
        $Analysis.ParserResults += Invoke-WinGetInstallerDetector -Name 'Windows Installer' -ScriptBlock {
          Invoke-WinGetInstallerMsiAnalysis -InstallerPath $Installer.FullName
        }
        $Analysis.SuggestedNextSteps += 'This file uses CFB structured storage but has an unknown Windows Installer CLSID; verify whether it is MSI, MSP, MSM, MST, or another CFB document before authoring.'
      }
      'MSIXAppX' {
        $MsixResult = Invoke-WinGetInstallerDetector -Name 'MSIX/AppX' -ScriptBlock {
          Invoke-WinGetInstallerMsixAnalysis -InstallerPath $Installer.FullName
        }
        $Analysis.ParserResults += $MsixResult
        if ($MsixResult.Success -and $MsixResult.Result.Rejected) {
          $Analysis.BlockingIssues += $MsixResult.Result.RejectionReason
          $Analysis.SuggestedNextSteps += $MsixResult.Result.RejectionReason
        }
        if ($MsixResult.Success -and $MsixResult.Result.Warnings) {
          $Analysis.SuggestedNextSteps += @($MsixResult.Result.Warnings)
        }
      }
      'ZipArchive' {
        $Analysis.ParserResults += Invoke-WinGetInstallerZipAnalysis -InstallerPath $Installer.FullName
      }
      'PE' {
        $ScanText = Read-WinGetInstallerStringWindows -File $Installer -Budget $ScanBytes
        $AllCandidates = @(
          Get-WinGetInstallerStructuralExeFamilyCandidate -File $Installer
          Get-WinGetInstallerGenericExeFamilyCandidate -File $Installer -Budget $ScanBytes -Text $ScanText
        )
        $FamilyCandidates = @($AllCandidates | Group-Object Family | ForEach-Object { $_.Group | Sort-Object { if ($_.Confidence -eq 'high') { 0 } elseif ($_.Confidence -eq 'medium') { 1 } else { 2 } } | Select-Object -First 1 })
        $ParserRuns = @(Invoke-WinGetInstallerExeParser -InstallerPath $Installer.FullName -ExtractEmbeddedMsi:$ExtractEmbeddedMsi.IsPresent -FamilyCandidates $FamilyCandidates)
        $Analysis.ParserResults += $ParserRuns
        $Analysis.FamilyCandidates += $FamilyCandidates
        $Analysis.WrapperWarnings += @(Get-WinGetInstallerWrapperWarning -File $Installer -Budget $ScanBytes -ParserRuns $ParserRuns -Text $ScanText)
        if (-not ($ParserRuns.Success -contains $true)) {
          $Analysis.PortableEvidence = try { Get-WinGetInstallerPortableEvidence -Path $Installer.FullName } catch { $null }
        }
        if ($Analysis.PortableEvidence -and $Analysis.PortableEvidence.RecommendedPackageDependencyIds.Count -gt 0) {
          $Analysis.SuggestedNextSteps += "Portable evidence: static dependency evidence maps to package dependencies: $($Analysis.PortableEvidence.RecommendedPackageDependencyIds -join ', ')."
        }
        if ($Analysis.PortableEvidence -and $Analysis.PortableEvidence.Warnings.Count -gt 0) {
          $Analysis.SuggestedNextSteps += @($Analysis.PortableEvidence.Warnings)
        }
        if ($Analysis.WrapperWarnings.Count -gt 0) {
          $Analysis.SuggestedNextSteps += 'Wrapper warning: the NSIS/Inno outer installer appears to contain nested installer payloads. Inspect the nested payload or use VM ARP-delta validation before setting AppsAndFeaturesEntries.'
        }
        $Analysis.SuggestedNextSteps += 'Use high-confidence parser results first. Use heuristic candidates only to choose which family-specific static or VM validation to run next.'
        $Analysis.SuggestedNextSteps += 'For generic EXE families, confirm silent switches and visible ARP entries in a VM unless publisher docs or existing manifest evidence is exact.'
      }
      'AppInstaller' {
        $Analysis.SuggestedNextSteps += '.appinstaller is not accepted by winget-pkgs manifests. Parse its XML and analyze the referenced MSIX/AppX package instead.'
      }
      default {
        $Analysis.SuggestedNextSteps += 'Unknown file signature; inspect as archive or PE manually before choosing a WinGet installer type.'
      }
    }

    [pscustomobject]$Analysis
  }
}

Export-ModuleMember -Function Get-WinGetInstallerAnalysis
