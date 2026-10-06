# SPDX-License-Identifier: Apache-2.0
# Format sources: https://github.com/Squirrel/Squirrel.Windows and https://github.com/velopack/velopack
# Squirrel/Velopack binary structures consumed here:
#
#   Squirrel PE/.rsrc/DATA/#131 -> ZIP -> nupkg -> nuspec
#   Clowd.Squirrel PE/.rsrc/DATA/#205 -> nupkg -> nuspec
#   Clowd.Squirrel/Velopack PE -> [PayloadOffset:i64 LE][PayloadLength:i64 LE]
#     -> 32-byte 94 F0 B1 7B ... 94 ED 7D signature -> bounded nupkg
#
# PE resource RVAs and Velopack locator offsets become absolute file ranges.
# A candidate is accepted only when ZIP/nupkg/nuspec structure validates; bare
# ZIP markers or --silent strings are insufficient.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:SquirrelBundleSignature = [byte[]](
  0x94, 0xF0, 0xB1, 0x7B, 0x68, 0x93, 0xE0, 0x29,
  0x37, 0xEB, 0x34, 0xEF, 0x53, 0xAA, 0xE7, 0xD4,
  0x2B, 0x54, 0xF5, 0x70, 0x7E, 0xF5, 0xD6, 0xF5,
  0x78, 0x54, 0x98, 0x3E, 0x5E, 0x94, 0xED, 0x7D
)

$Script:SquirrelResourceType = 'DATA'
$Script:SquirrelResourceId = 131
$Script:SquirrelFrameworkResourceType = 'FLAGS'
$Script:SquirrelFrameworkResourceId = 132
$Script:SquirrelFrameworkVersions = @('net45', 'net451', 'net452', 'net46', 'net461', 'net462', 'net47', 'net471', 'net472', 'net48')
$Script:ClowdSquirrelResourceIds = [ordered]@{
  AppId               = 200
  AppFriendlyName     = 201
  RequiredFrameworks  = 203
  BundledPackageName  = 204
  BundledPackageBytes = 205
}
$Script:VelopackSetupMarker = [Text.Encoding]::UTF8.GetBytes('VELOPACK_FIRSTRUN')
$Script:VelopackInstallLocationMarker = [Text.Encoding]::UTF8.GetBytes('installtoDIR')
$Script:VelopackLogMarker = [Text.Encoding]::UTF8.GetBytes('logFILE')

function Read-SquirrelWindowsResourceMetadata {
  <#
  .SYNOPSIS
    Read the .NET Framework prerequisite selected by a Squirrel.Windows setup
  .PARAMETER Stream
    A caller-owned readable, seekable installer stream
  .PARAMETER Resource
    PE resource entries parsed from Stream
  .PARAMETER LanguageId
    Resource language shared by the package and framework entries
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Resource,
    [Parameter(Mandatory)][ValidateRange(0, 65535)][int]$LanguageId
  )

  $Entry = $Resource | Where-Object {
    $_.TypeName -eq $Script:SquirrelFrameworkResourceType -and
    $_.Id -eq $Script:SquirrelFrameworkResourceId -and
    ($_.PSObject.Properties['LanguageId'] ? [int]$_.LanguageId : 0) -eq $LanguageId
  } | Select-Object -First 1

  if (-not $Entry) {
    return [pscustomobject][ordered]@{
      RequiredFrameworks     = @()
      FrameworkResourceValue = $null
      FrameworkFallbackUsed  = $false
    }
  }
  if ($Entry.Size -le 0 -or $Entry.Size -gt 64 -or $Entry.Size % 2 -ne 0) { throw 'The Squirrel.Windows framework resource has an invalid UTF-16 byte length.' }

  $Bytes = Read-BinaryBytes -Stream $Stream -Offset $Entry.Offset -Count ([int]$Entry.Size)
  $RawValue = [Text.Encoding]::Unicode.GetString($Bytes).TrimEnd([char[]]@([char]0))
  # FxHelper defaults unknown flags to .NET Framework 4.5. Preserve the raw
  # resource while reporting the prerequisite the launcher will actually test.
  $ResolvedValue = $RawValue -cin $Script:SquirrelFrameworkVersions ? $RawValue : 'net45'
  [pscustomobject][ordered]@{
    RequiredFrameworks     = @($ResolvedValue)
    FrameworkResourceValue = $RawValue
    FrameworkFallbackUsed  = $ResolvedValue -cne $RawValue
  }
}

function Read-ClowdSquirrelResourceMetadata {
  <#
  .SYNOPSIS
    Read bounded metadata from the transitional Clowd.Squirrel resource bundle
  .PARAMETER Stream
    A caller-owned readable, seekable installer stream
  .PARAMETER Resource
    PE resource entries parsed from Stream
  .PARAMETER LanguageId
    Resource language shared by the package and metadata entries
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Resource,
    [Parameter(Mandatory)][ValidateRange(0, 65535)][int]$LanguageId
  )

  $Values = [ordered]@{}
  foreach ($Name in @('AppId', 'AppFriendlyName', 'RequiredFrameworks', 'BundledPackageName')) {
    $Id = $Script:ClowdSquirrelResourceIds[$Name]
    $Entry = $Resource | Where-Object {
      $_.TypeName -eq $Script:SquirrelResourceType -and
      $_.Id -eq $Id -and
      ($_.PSObject.Properties['LanguageId'] ? [int]$_.LanguageId : 0) -eq $LanguageId
    } | Select-Object -First 1
    if (-not $Entry) {
      $Values[$Name] = $null
      continue
    }
    if ($Entry.Size -le 0 -or $Entry.Size -gt 65536 -or $Entry.Size % 2 -ne 0) { throw "Clowd.Squirrel resource $Id has an invalid UTF-16 byte length." }

    try {
      $Bytes = Read-BinaryBytes -Stream $Stream -Offset $Entry.Offset -Count ([int]$Entry.Size)
      $Values[$Name] = [Text.Encoding]::Unicode.GetString($Bytes).TrimEnd([char[]]@([char]0))
    } catch {
      throw "Could not read Clowd.Squirrel resource $Id for language $LanguageId. $($_.Exception.Message)"
    }
  }

  [pscustomobject][ordered]@{
    AppId              = $Values.AppId
    AppFriendlyName    = $Values.AppFriendlyName
    RequiredFrameworks = @($Values.RequiredFrameworks -split ',' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object Trim)
    BundledPackageName = $Values.BundledPackageName
  }
}

function Get-SquirrelPeResourceZipCandidate {
  <#
  .SYNOPSIS
    Find the embedded Squirrel update ZIP stored in the setup PE resources
  .PARAMETER Path
    The path to the installer
  .PARAMETER Stream
    A caller-owned readable, seekable installer stream
  .PARAMETER Layout
    An optional PE layout already parsed from Stream
  #>
  [OutputType([pscustomobject[]])]
  [CmdletBinding(DefaultParameterSetName = 'Path')]
  param (
    [Parameter(Mandatory, ParameterSetName = 'Path', HelpMessage = 'The path to the installer')][string]$Path,
    [Parameter(Mandatory, ParameterSetName = 'Stream', HelpMessage = 'A caller-owned installer stream')][IO.Stream]$Stream,
    [Parameter(ParameterSetName = 'Stream', HelpMessage = 'A parsed PE layout for Stream')][psobject]$Layout
  )

  $OwnsStream = $PSCmdlet.ParameterSetName -eq 'Path'
  if ($OwnsStream) {
    $File = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  }

  try {
    $Arguments = @{ Stream = $Stream }
    if ($Layout) { $Arguments.Layout = $Layout }
    $Resources = @(Get-PEResourceInfo @Arguments)

    # Metadata and package resources are language-specific. Associate each #205
    # payload only with sibling values from the same resource language.
    foreach ($Entry in $Resources) {
      if ($Entry.TypeName -ne $Script:SquirrelResourceType -or $Entry.Size -le 0) { continue }
      $LanguageId = $Entry.PSObject.Properties['LanguageId'] ? [int]$Entry.LanguageId : 0
      if ($Entry.Id -eq $Script:SquirrelResourceId) {
        [pscustomobject]@{
          Offset               = [long]$Entry.Offset
          Length               = [long]$Entry.Size
          Family               = 'Squirrel'
          DetectionRoute       = 'SquirrelPeResource'
          LauncherGeneration   = 'Squirrel.Windows'
          LauncherCapabilities = [pscustomobject]@{ Silent = $true; InstallLocation = $false; Log = $false }
          ResourceId           = $Script:SquirrelResourceId
          ResourceLanguageId   = $LanguageId
          ResourceMetadata     = Read-SquirrelWindowsResourceMetadata -Stream $Stream -Resource $Resources -LanguageId $LanguageId
        }
      } elseif ($Entry.Id -eq $Script:ClowdSquirrelResourceIds.BundledPackageBytes) {
        [pscustomobject]@{
          Offset               = [long]$Entry.Offset
          Length               = [long]$Entry.Size
          Family               = 'Velopack'
          DetectionRoute       = 'ClowdSquirrelPeResource'
          LauncherGeneration   = 'Clowd.Squirrel.Resource'
          LauncherCapabilities = [pscustomobject]@{ Silent = $true; InstallLocation = $false; Log = $false }
          ResourceId           = $Script:ClowdSquirrelResourceIds.BundledPackageBytes
          ResourceLanguageId   = $LanguageId
          ResourceMetadata     = Read-ClowdSquirrelResourceMetadata -Stream $Stream -Resource $Resources -LanguageId $LanguageId
        }
      }
    }
  } finally {
    if ($OwnsStream) { $Stream.Dispose() }
  }
}

function Find-SquirrelBytePattern {
  <#
  .SYNOPSIS
    Find byte pattern offsets inside a file
  .PARAMETER Path
    The path to scan
  .PARAMETER Pattern
    The byte pattern to locate
  .PARAMETER Maximum
    The maximum number of offsets to return
  .PARAMETER MaximumBytes
    The maximum number of bytes to scan from the start of the input
  #>
  [OutputType([long[]])]
  [CmdletBinding(DefaultParameterSetName = 'Path')]
  param (
    [Parameter(Mandatory, ParameterSetName = 'Path', HelpMessage = 'The path to scan')][string]$Path,
    [Parameter(Mandatory, ParameterSetName = 'Stream', HelpMessage = 'The caller-owned stream to scan')][IO.Stream]$Stream,

    [Parameter(Mandatory, HelpMessage = 'The byte pattern to locate')]
    [byte[]]$Pattern,

    [Parameter(HelpMessage = 'The maximum number of offsets to return')]
    [int]$Maximum = 128,

    [Parameter(HelpMessage = 'The maximum number of bytes to scan')]
    [long]$MaximumBytes = 0
  )

  $Length = if ($MaximumBytes -gt 0) { $MaximumBytes } else { 0 }
  if ($PSCmdlet.ParameterSetName -eq 'Path') {
    Find-BinaryPattern -Path $Path -Pattern $Pattern -Length $Length -Maximum $Maximum
  } else {
    Find-BinaryPattern -Stream $Stream -Pattern $Pattern -Length $Length -Maximum $Maximum
  }
}

function Test-SquirrelLauncherMarker {
  <#
  .SYNOPSIS
    Test one source-defined marker within a bounded launcher range
  .PARAMETER Stream
    A caller-owned readable, seekable installer stream
  .PARAMETER Pattern
    The source-defined marker bytes to find
  .PARAMETER Length
    The maximum launcher range to scan
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][byte[]]$Pattern,
    [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$Length
  )

  if ($Length -le 0) { return $false }
  return @(Find-BinaryPattern -Stream $Stream -Pattern $Pattern -Length ([Math]::Min($Length, $Stream.Length)) -Maximum 1).Count -gt 0
}

function Get-SquirrelBundleHeader {
  <#
  .SYNOPSIS
    Read the Velopack setup bundle header if present
  .PARAMETER Path
    The path to the installer
  .PARAMETER Stream
    A caller-owned readable, seekable installer stream
  .PARAMETER MaximumSignatures
    The maximum number of signed bundle markers to inspect
  .PARAMETER MaximumLauncherBytes
    The maximum launcher prefix to scan for signed bundle markers
  #>
  [OutputType([pscustomobject[]])]
  [CmdletBinding(DefaultParameterSetName = 'Path')]
  param (
    [Parameter(Mandatory, ParameterSetName = 'Path', HelpMessage = 'The path to the installer')][string]$Path,
    [Parameter(Mandatory, ParameterSetName = 'Stream', HelpMessage = 'A caller-owned installer stream')][IO.Stream]$Stream,
    [Parameter(HelpMessage = 'The maximum number of signed bundle markers to inspect')][ValidateRange(1, 1024)][int]$MaximumSignatures = 8,
    [Parameter(HelpMessage = 'The maximum launcher prefix to scan for signed bundle markers')][ValidateRange(1048576, 1073741824)][long]$MaximumLauncherBytes = 16777216
  )

  $OwnsStream = $PSCmdlet.ParameterSetName -eq 'Path'
  if ($OwnsStream) {
    $File = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  }
  if (-not $Stream.CanRead -or -not $Stream.CanSeek) {
    if ($OwnsStream) { $Stream.Dispose() }
    throw 'Velopack bundle parsing requires a readable, seekable stream.'
  }

  $SeenRanges = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  try {
    # The source-defined placeholder is in the launcher, before the appended
    # package. Keep all valid locators so an earlier decoy cannot hide a later one.
    foreach ($SignatureOffset in Find-SquirrelBytePattern -Stream $Stream -Pattern $Script:SquirrelBundleSignature -Maximum $MaximumSignatures -MaximumBytes ([Math]::Min($MaximumLauncherBytes, $Stream.Length))) {
      if ($SignatureOffset -lt 16) { continue }
      $HeaderBytes = Read-BinaryBytes -Stream $Stream -Offset ($SignatureOffset - 16) -Count 16

      $Offset = [System.BitConverter]::ToInt64($HeaderBytes, 0)
      $Length = [System.BitConverter]::ToInt64($HeaderBytes, 8)
      $LocatorEnd = $SignatureOffset + $Script:SquirrelBundleSignature.Length
      if ($Offset -lt $LocatorEnd -or $Length -le 0 -or $Offset -gt $Stream.Length -or $Length -gt $Stream.Length - $Offset) { continue }
      if (-not $SeenRanges.Add("$Offset`:$Length")) { continue }

      $IsVelopackSetup = Test-SquirrelLauncherMarker -Stream $Stream -Pattern $Script:VelopackSetupMarker -Length $Offset
      $Capabilities = [pscustomobject]@{
        Silent          = $true
        InstallLocation = $IsVelopackSetup -and (Test-SquirrelLauncherMarker -Stream $Stream -Pattern $Script:VelopackInstallLocationMarker -Length $Offset)
        Log             = $IsVelopackSetup -and (Test-SquirrelLauncherMarker -Stream $Stream -Pattern $Script:VelopackLogMarker -Length $Offset)
      }
      [pscustomobject]@{
        Offset               = $Offset
        Length               = $Length
        SignatureOffset      = [long]$SignatureOffset
        LauncherGeneration   = $IsVelopackSetup ? 'Velopack' : 'Clowd.Squirrel.Bundle'
        LauncherCapabilities = $Capabilities
      }
    }
  } finally {
    if ($OwnsStream) { $Stream.Dispose() }
  }
}

function Get-SquirrelZipLocalHeaderOffset {
  <#
  .SYNOPSIS
    Find candidate ZIP local file headers inside an installer
  .PARAMETER Path
    The path to the installer
  .PARAMETER Stream
    A caller-owned readable, seekable installer stream
  .PARAMETER Maximum
    The maximum number of candidate offsets to return
  #>
  [OutputType([long[]])]
  [CmdletBinding(DefaultParameterSetName = 'Path')]
  param (
    [Parameter(Mandatory, ParameterSetName = 'Path', HelpMessage = 'The path to the installer')][string]$Path,
    [Parameter(Mandatory, ParameterSetName = 'Stream', HelpMessage = 'The caller-owned stream to scan')][IO.Stream]$Stream,

    [Parameter(HelpMessage = 'The maximum number of candidate offsets to return')]
    [int]$Maximum = 128
  )

  $Signature = [byte[]](0x50, 0x4B, 0x03, 0x04)
  if ($PSCmdlet.ParameterSetName -eq 'Path') {
    Find-BinaryPattern -Path $Path -Pattern $Signature -Maximum $Maximum
  } else {
    Find-BinaryPattern -Stream $Stream -Pattern $Signature -Maximum $Maximum
  }
}

function Read-SquirrelNuspecFromZipArchive {
  <#
  .SYNOPSIS
    Read nuspec metadata from an opened ZIP archive
  .PARAMETER Archive
    The ZIP archive to inspect
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The ZIP archive to inspect')]
    $Archive
  )

  $NuspecEntries = [Collections.Generic.List[object]]::new()
  $EntryCount = 0
  foreach ($Candidate in Get-InstallerArchiveEntry -Archive $Archive) {
    if (++$EntryCount -gt 65536) { throw 'The package archive exceeds the 65536-entry limit.' }
    $Name = ([string]$Candidate.FullName).Replace('\', '/').TrimStart('/')
    while ($Name.StartsWith('./', [StringComparison]::Ordinal)) { $Name = $Name.Substring(2) }
    if ($Name.EndsWith('.nuspec', [StringComparison]::OrdinalIgnoreCase) -and $Name.IndexOf('/') -lt 0) {
      $NuspecEntries.Add($Candidate)
    }
  }
  if ($NuspecEntries.Count -eq 0) { return $null }
  if ($NuspecEntries.Count -gt 1) { throw 'The package archive contains multiple top-level nuspec files.' }
  $Entry = $NuspecEntries[0]

  $XmlText = Read-InstallerArchiveEntryText -Entry $Entry -MaximumBytes 2097152
  $Xml = Read-BoundedXmlDocument -Content $XmlText -MaximumCharacters 2097152

  $Metadata = $Xml.SelectSingleNode('/*[local-name()="package"]/*[local-name()="metadata"]')
  if (-not $Metadata) { return $null }
  $ReadValue = {
    param([string]$Name)
    $Node = $Metadata.SelectSingleNode("*[local-name()='$Name']")
    if ($Node) { return [string]$Node.InnerText }
    return $null
  }
  $ShortcutAumid = & $ReadValue 'shortcutAumid'
  if ([string]::IsNullOrWhiteSpace($ShortcutAumid)) { $ShortcutAumid = & $ReadValue 'shortcutAmuid' }

  [pscustomobject][ordered]@{
    Id                  = & $ReadValue 'id'
    Title               = & $ReadValue 'title'
    Version             = & $ReadValue 'version'
    Authors             = & $ReadValue 'authors'
    Owners              = & $ReadValue 'owners'
    Description         = & $ReadValue 'description'
    Summary             = & $ReadValue 'summary'
    ProjectUrl          = & $ReadValue 'projectUrl'
    IconUrl             = & $ReadValue 'iconUrl'
    MachineArchitecture = & $ReadValue 'machineArchitecture'
    RuntimeDependencies = & $ReadValue 'runtimeDependencies'
    MainExecutable      = & $ReadValue 'mainExe'
    OperatingSystem     = & $ReadValue 'os'
    Rid                 = & $ReadValue 'rid'
    MinimumOSVersion    = & $ReadValue 'osMinVersion'
    Channel             = & $ReadValue 'channel'
    ShortcutLocations   = & $ReadValue 'shortcutLocations'
    ShortcutAumid       = $ShortcutAumid
    ReleaseNotes        = & $ReadValue 'releaseNotes'
    ReleaseNotesHtml    = & $ReadValue 'releaseNotesHtml'
    SplashProgressColor = & $ReadValue 'splashProgressColor'
    NuspecPath          = $Entry.FullName
  }
}

function Read-SquirrelNuspecFromNupkgEntry {
  <#
  .SYNOPSIS
    Read nuspec metadata from a nested nupkg entry without executing the installer
  .PARAMETER Entry
    The nested nupkg entry
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The nested nupkg entry')]
    $Entry
  )

  $EntryStream = Open-InstallerArchiveEntry -Entry $Entry
  $Seekable = $null
  $NestedArchive = $null
  try {
    $Seekable = New-InstallerSeekableStream -SourceStream $EntryStream -MaximumBytes 1073741824 -MemoryThresholdBytes 16777216
    $NestedArchive = Get-InstallerArchive -Stream $Seekable.Stream
    Read-SquirrelNuspecFromZipArchive -Archive $NestedArchive
  } finally {
    if ($NestedArchive) { $NestedArchive.Dispose() }
    if ($Seekable) { $Seekable.Dispose() }
    $EntryStream.Dispose()
  }
}

function ConvertFrom-SquirrelArchitecture {
  <#
  .SYNOPSIS
    Normalize one Squirrel or Velopack architecture value for WinGet
  #>
  [OutputType([string])]
  param ([AllowEmptyString()][string]$Value)

  switch ($Value.Trim().ToLowerInvariant()) {
    'x86' { 'x86' }
    'x64' { 'x64' }
    'amd64' { 'x64' }
    'arm' { 'arm' }
    'arm64' { 'arm64' }
    'aarch64' { 'arm64' }
    default { $null }
  }
}

function Get-SquirrelRidArchitecture {
  <#
  .SYNOPSIS
    Read an optional Windows architecture suffix from a Velopack RID
  #>
  [OutputType([string])]
  param ([AllowEmptyString()][string]$Rid)

  $Match = [regex]::Match($Rid.Trim(), '^(?:win|windows)(?:\d+(?:\.\d+)*)?-(?<architecture>x86|x64|amd64|arm|arm64|aarch64)$', [Text.RegularExpressions.RegexOptions]::IgnoreCase)
  if (-not $Match.Success) { return $null }
  return ConvertFrom-SquirrelArchitecture -Value $Match.Groups['architecture'].Value
}

function ConvertFrom-SquirrelMetadataList {
  <#
  .SYNOPSIS
    Split one source-defined comma or semicolon delimited metadata value
  #>
  [OutputType([string[]])]
  param ([AllowEmptyString()][string]$Value)

  return [string[]]@($Value -split '[,;]' | ForEach-Object Trim | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

function Test-SquirrelMainExecutablePath {
  <#
  .SYNOPSIS
    Validate a Velopack mainExe as a relative Windows executable path
  #>
  [OutputType([bool])]
  param ([AllowEmptyString()][string]$Path)

  if ([string]::IsNullOrWhiteSpace($Path) -or $Path.IndexOf([char]0) -ge 0 -or [IO.Path]::IsPathRooted($Path) -or $Path.Contains(':')) { return $false }
  $Segments = @($Path -split '[\\/]')
  $InvalidSegments = @($Segments | Where-Object {
      [string]::IsNullOrWhiteSpace($_) -or $_ -in @('.', '..') -or $_.IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0 -or
      $_.EndsWith('.') -or $_.EndsWith(' ') -or $_ -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)'
    })
  if ($Segments.Count -eq 0 -or $InvalidSegments.Count -gt 0) { return $false }
  return $Segments[-1].EndsWith('.exe', [StringComparison]::OrdinalIgnoreCase)
}

function Get-SquirrelPayloadArchitecture {
  <#
  .SYNOPSIS
    Resolve concrete architecture evidence from one parsed PE layout
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Layout,
    [AllowNull()][psobject]$ClrHeader
  )

  $Architecture = switch ([uint16]$Layout.Machine) {
    0x014C {
      if ($ClrHeader -and $ClrHeader.ILOnly -and -not $ClrHeader.Requires32Bit -and -not $ClrHeader.NativeEntryPoint) { $null } else { 'x86' }
    }
    0x01C4 { 'arm' }
    0x8664 { 'x64' }
    0xAA64 { 'arm64' }
    default { $null }
  }
  [pscustomobject]@{
    Architecture = $Architecture
    IsAnyCpu     = [bool]($ClrHeader -and $ClrHeader.ILOnly -and -not $ClrHeader.Requires32Bit -and -not $ClrHeader.NativeEntryPoint -and $Layout.Machine -eq 0x014C)
  }
}

function Get-SquirrelMainExecutableEvidence {
  <#
  .SYNOPSIS
    Statically inspect the source-declared Velopack main executable
  .PARAMETER Archive
    Open nupkg archive containing lib/app
  .PARAMETER MainExecutable
    Validated mainExe path relative to lib/app
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]$Archive,
    [Parameter(Mandatory)][string]$MainExecutable
  )

  $ExpectedPath = 'lib/app/' + $MainExecutable.Replace('\', '/')
  $MatchingEntries = [Collections.Generic.List[object]]::new()
  $EntryCount = 0
  foreach ($Entry in Get-InstallerArchiveEntry -Archive $Archive) {
    if (++$EntryCount -gt 65536) { throw 'The package archive exceeds the 65536-entry limit.' }
    $EntryPath = ([string]$Entry.FullName).Replace('\', '/')
    if ([string]::Equals($EntryPath, $ExpectedPath, [StringComparison]::OrdinalIgnoreCase)) { $MatchingEntries.Add($Entry) }
  }
  if ($MatchingEntries.Count -eq 0) { throw "The Velopack package does not contain its declared main executable: $ExpectedPath" }
  if ($MatchingEntries.Count -gt 1) { throw "The Velopack package contains multiple entries for its declared main executable: $ExpectedPath" }

  $Entry = $MatchingEntries[0]
  if ($Entry.IsEncrypted -or -not [string]::IsNullOrWhiteSpace($Entry.LinkTarget)) { throw 'The Velopack main executable cannot be encrypted or stored as an archive link.' }
  if ($Entry.Length -le 0 -or $Entry.Length -gt 536870912) { throw 'The Velopack main executable is empty or exceeds the 512 MiB inspection limit.' }
  $EntryStream = Open-InstallerArchiveEntry -Entry $Entry
  $Seekable = $null
  try {
    $Seekable = New-InstallerSeekableStream -SourceStream $EntryStream -MaximumBytes 536870912 -MemoryThresholdBytes 16777216
    $Layout = Get-PELayout -Stream $Seekable.Stream
    if (-not $Layout) { throw "The Velopack main executable is not a valid PE image: $ExpectedPath" }
    $InspectionWarnings = [Collections.Generic.List[string]]::new()
    $ClrHeader = try { Get-PEClrHeader -Stream $Seekable.Stream } catch { $InspectionWarnings.Add($_.Exception.Message); $null }
    $ArchitectureInfo = Get-SquirrelPayloadArchitecture -Layout $Layout -ClrHeader $ClrHeader
    $TargetFramework = if ($ClrHeader) { try { Get-PEManagedTargetFramework -Stream $Seekable.Stream } catch { $InspectionWarnings.Add($_.Exception.Message); $null } } else { $null }
    $Imports = @(
      try { Get-PEImportedDll -Stream $Seekable.Stream } catch { $InspectionWarnings.Add($_.Exception.Message) }
      try { Get-PEDelayImportedDll -Stream $Seekable.Stream } catch { $InspectionWarnings.Add($_.Exception.Message) }
    )

    return [pscustomobject][ordered]@{
      RelativePath       = $ExpectedPath
      Length             = [long]$Entry.Length
      Machine            = ('0x{0:X4}' -f [uint16]$Layout.Machine)
      MachineName        = $Layout.MachineName
      Architecture       = $ArchitectureInfo.Architecture
      IsManaged          = $null -ne $ClrHeader
      IsAnyCpu           = $ArchitectureInfo.IsAnyCpu
      TargetFramework    = $TargetFramework
      ImportedDlls       = @($Imports | Select-Object Directory, DllName)
      DependencyDllNames = [string[]]@($Imports.DllName | Where-Object { $_ } | Sort-Object -Unique)
      InspectionWarnings = [string[]]@($InspectionWarnings)
    }
  } finally {
    if ($Seekable) { $Seekable.Dispose() }
    $EntryStream.Dispose()
  }
}

function Assert-SquirrelNuspecMetadata {
  <#
  .SYNOPSIS
    Validate source-required package metadata for the detected launcher generation
  .PARAMETER Nuspec
    Parsed package metadata to validate
  .PARAMETER LauncherGeneration
    The source generation whose metadata requirements apply
  #>
  param (
    [Parameter(Mandatory)][psobject]$Nuspec,
    [string]$LauncherGeneration
  )

  if ([string]::IsNullOrWhiteSpace($Nuspec.Id)) { throw 'The package does not declare the required id metadata.' }
  if ([string]::IsNullOrWhiteSpace($Nuspec.Version)) { throw 'The package does not declare the required version metadata.' }
  if ($LauncherGeneration -ne 'Velopack') { return }

  # Rust semver accepts three numeric components, optional SemVer 2 prerelease
  # and build identifiers, and rejects the default 0.0.0 sentinel.
  $VersionMatch = [regex]::Match([string]$Nuspec.Version, '^(?<major>0|[1-9]\d*)\.(?<minor>0|[1-9]\d*)\.(?<patch>0|[1-9]\d*)(?:-(?:0|[1-9]\d*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$')
  $NumericComponentsFit = $VersionMatch.Success
  if ($NumericComponentsFit) {
    foreach ($Name in @('major', 'minor', 'patch')) {
      $Component = [uint64]0
      if (-not [uint64]::TryParse($VersionMatch.Groups[$Name].Value, [Globalization.NumberStyles]::None, [Globalization.CultureInfo]::InvariantCulture, [ref]$Component)) {
        $NumericComponentsFit = $false
        break
      }
    }
  }
  if (-not $NumericComponentsFit -or ($VersionMatch.Groups['major'].Value -eq '0' -and $VersionMatch.Groups['minor'].Value -eq '0' -and $VersionMatch.Groups['patch'].Value -eq '0')) {
    throw "The Velopack package declares an invalid version: $($Nuspec.Version)"
  }
  if ([string]::IsNullOrWhiteSpace($Nuspec.MainExecutable)) { throw 'The Velopack package does not declare the required mainExe metadata.' }
  if (-not (Test-SquirrelMainExecutablePath -Path ([string]$Nuspec.MainExecutable))) { throw "The Velopack package declares an unsafe or invalid mainExe path: $($Nuspec.MainExecutable)" }
}

function ConvertTo-SquirrelInfo {
  <#
  .SYNOPSIS
    Build the static Squirrel metadata object returned by the parser
  .PARAMETER Path
    The path to the installer
  .PARAMETER Family
    The detected Squirrel-family name
  .PARAMETER DetectionRoute
    The structural container route that exposed the package metadata
  .PARAMETER Confidence
    The confidence level of the static detection
  .PARAMETER ZipOffset
    The ZIP payload offset inside the installer
  .PARAMETER Nuspec
    The nuspec metadata object
  .PARAMETER NupkgPath
    The optional nested nupkg path
  .PARAMETER DetectionEvidence
    Structural evidence supporting the selected family and route
  .PARAMETER DiagnosticMessage
    Diagnostic messages explaining incomplete or conflicting family evidence
  .PARAMETER Diagnostic
    Structured diagnostics associated with the selected route
  .PARAMETER AdditionalUnresolvedFields
    Fields left unresolved by route-level ambiguity
  .PARAMETER LauncherGeneration
    The source generation that defines launcher behavior
  .PARAMETER LauncherCapabilities
    Source-backed setup command-line capabilities
  .PARAMETER ResourceMetadata
    Optional metadata from a legacy Clowd.Squirrel resource bundle
  .PARAMETER PayloadEvidence
    Static PE evidence from the source-declared Velopack main executable
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the installer')][string]$Path,
    [Parameter(Mandatory, HelpMessage = 'The detected Squirrel-family name')][ValidateSet('Squirrel', 'Velopack', 'Squirrel/Velopack')][string]$Family,
    [Parameter(Mandatory, HelpMessage = 'The structural container route that exposed the package metadata')][ValidateSet('SquirrelPeResource', 'ClowdSquirrelPeResource', 'VelopackBundle', 'EmbeddedZipFallback', 'ConflictingAuthoritativeRoutes')][string]$DetectionRoute,
    [Parameter(Mandatory, HelpMessage = 'The confidence level of the static detection')][string]$Confidence,
    [Parameter(Mandatory, HelpMessage = 'The ZIP payload offset inside the installer')][long]$ZipOffset,
    [Parameter(Mandatory, HelpMessage = 'The nuspec metadata object')][pscustomobject]$Nuspec,
    [Parameter(HelpMessage = 'The optional nested nupkg path')][string]$NupkgPath,
    [Parameter(HelpMessage = 'Structural evidence supporting the selected family and route')][object[]]$DetectionEvidence = @(),
    [Parameter(HelpMessage = 'Diagnostic messages explaining incomplete or conflicting family evidence')][string[]]$DiagnosticMessage = @(),
    [Parameter(HelpMessage = 'Structured diagnostics associated with the selected route')][object[]]$Diagnostic = @(),
    [Parameter(HelpMessage = 'Fields left unresolved by route-level ambiguity')][string[]]$AdditionalUnresolvedFields = @(),
    [Parameter(HelpMessage = 'The source generation that defines launcher behavior')][string]$LauncherGeneration,
    [Parameter(HelpMessage = 'Source-backed setup command-line capabilities')][psobject]$LauncherCapabilities,
    [Parameter(HelpMessage = 'Optional metadata from a legacy Clowd.Squirrel resource bundle')][psobject]$ResourceMetadata,
    [Parameter(HelpMessage = 'Static PE evidence from the source-declared Velopack main executable')][psobject]$PayloadEvidence
  )

  $HasConfirmedLauncher = $Family -in @('Squirrel', 'Velopack')
  $NuspecDescription = $Nuspec.PSObject.Properties['Description'] ? [string]$Nuspec.Description : $null
  $NuspecSummary = $Nuspec.PSObject.Properties['Summary'] ? [string]$Nuspec.Summary : $null
  $NuspecOwners = $Nuspec.PSObject.Properties['Owners'] ? [string]$Nuspec.Owners : $null
  $NuspecProjectUrl = $Nuspec.PSObject.Properties['ProjectUrl'] ? [string]$Nuspec.ProjectUrl : $null
  $NuspecIconUrl = $Nuspec.PSObject.Properties['IconUrl'] ? [string]$Nuspec.IconUrl : $null

  # Squirrel.Windows and the Clowd generations use NuGet's package projection,
  # while Rust Velopack parses the nuspec into its own manifest. Keep these
  # fallback rules separate because they determine the actual ARP DisplayName.
  $DisplayName = if ($LauncherGeneration -eq 'Squirrel.Windows') {
    @([string]$Nuspec.Title, $NuspecDescription, $NuspecSummary | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1)[0]
  } else {
    [string]::IsNullOrWhiteSpace([string]$Nuspec.Title) ? [string]$Nuspec.Id : [string]$Nuspec.Title
  }
  $Publisher = if (-not [string]::IsNullOrWhiteSpace([string]$Nuspec.Authors)) {
    [string]$Nuspec.Authors
  } elseif ($LauncherGeneration -like 'Clowd.Squirrel.*' -and -not [string]::IsNullOrWhiteSpace($NuspecOwners)) {
    $NuspecOwners
  } elseif ($LauncherGeneration -like 'Clowd.Squirrel.*') {
    $DisplayName
  } else {
    $null
  }

  # Rust Velopack writes only the three numeric SemVer components
  # to DisplayVersion. Preserve the complete nuspec version separately for
  # update/version evidence.
  $PackageVersion = [string]$Nuspec.Version
  $DisplayVersion = if ($LauncherGeneration -eq 'Velopack') {
    $VersionMatch = [regex]::Match($PackageVersion, '^(?<core>(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))')
    $VersionMatch.Success ? $VersionMatch.Groups['core'].Value : $PackageVersion
  } else {
    $PackageVersion
  }
  $DefaultInstallLocation = if ($HasConfirmedLauncher -and $Nuspec.Id -cmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$') {
    '%LocalAppData%\' + $Nuspec.Id
  } else {
    $null
  }

  $Diagnostics = [Collections.Generic.List[object]]::new()
  foreach ($Item in $Diagnostic) { if ($null -ne $Item) { $Diagnostics.Add($Item) } }
  foreach ($Item in ConvertTo-InstallerDiagnostic -InputObject @($DiagnosticMessage) -Source 'Squirrel/Velopack' -Kind Incomplete -Areas Metadata) { $Diagnostics.Add($Item) }
  $Unresolved = [Collections.Generic.List[string]]::new()
  if ($Family -eq 'Squirrel/Velopack') {
    foreach ($Field in @('ProductCode', 'Scope', 'DefaultInstallLocation', 'AppsAndFeaturesEntries', 'InstallModes', 'InstallerSwitches', 'UpgradeBehavior', 'LauncherGeneration')) { $Unresolved.Add($Field) }
  }
  foreach ($Field in $AdditionalUnresolvedFields) { if (-not [string]::IsNullOrWhiteSpace($Field)) { $Unresolved.Add($Field) } }

  $RawArchitecture = ([string]$Nuspec.MachineArchitecture).Trim()
  $DeclaredArchitecture = ConvertFrom-SquirrelArchitecture -Value $RawArchitecture
  $RawRid = ([string]$Nuspec.Rid).Trim()
  $RidArchitecture = Get-SquirrelRidArchitecture -Rid $RawRid
  $PayloadArchitecture = if ($PayloadEvidence) { [string]$PayloadEvidence.Architecture } else { $null }
  $HasUnsupportedArchitecture = $RawArchitecture -and -not $DeclaredArchitecture
  if ($HasUnsupportedArchitecture) {
    $Unresolved.Add('Architecture')
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'Squirrel.Metadata.UnsupportedMachineArchitecture' -Source 'Squirrel/Velopack' -Message "The package declares an unsupported machineArchitecture value: $RawArchitecture" -Kind Unsupported -Areas Metadata -AffectedFields Architecture -Evidence ([ordered]@{ MachineArchitecture = $RawArchitecture })))
  }
  $ArchitectureCandidates = [string[]]@($DeclaredArchitecture, $RidArchitecture, $PayloadArchitecture | Where-Object { $_ } | Sort-Object -Unique)
  $Architecture = if (-not $HasUnsupportedArchitecture -and $ArchitectureCandidates.Count -eq 1) { $ArchitectureCandidates[0] } else { $null }
  if ($ArchitectureCandidates.Count -gt 1) {
    $Unresolved.Add('Architecture')
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'Squirrel.Metadata.ArchitectureConflict' -Source 'Squirrel/Velopack' -Message "The package architecture evidence conflicts: $($ArchitectureCandidates -join ', ')." -Kind Ambiguous -Areas Metadata -AffectedFields Architecture -Evidence ([ordered]@{ MachineArchitecture = $RawArchitecture; Rid = $RawRid; PayloadArchitecture = $PayloadArchitecture })))
  } elseif ($LauncherGeneration -eq 'Velopack' -and -not $Architecture) {
    $Unresolved.Add('Architecture')
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'Squirrel.Payload.ArchitectureUnresolved' -Source 'Squirrel/Velopack' -Message 'The Velopack package does not expose one concrete installed payload architecture.' -Kind Incomplete -Areas Metadata -AffectedFields Architecture -Evidence $PayloadEvidence))
  }
  if ($PayloadEvidence -and @($PayloadEvidence.InspectionWarnings).Count -gt 0) {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'Squirrel.Payload.InspectionIncomplete' -Source 'Squirrel/Velopack' -Message 'The main executable PE validated, but some optional dependency metadata could not be read.' -Kind Incomplete -Areas Metadata -AffectedFields Dependencies -Evidence ([ordered]@{ RelativePath = $PayloadEvidence.RelativePath; Warnings = @($PayloadEvidence.InspectionWarnings) })))
  }

  $RawMinimumOSVersion = ([string]$Nuspec.MinimumOSVersion).Trim()
  $ParsedMinimumOSVersion = [version]$null
  $MinimumOSVersion = if ($RawMinimumOSVersion -and [version]::TryParse($RawMinimumOSVersion, [ref]$ParsedMinimumOSVersion)) { $RawMinimumOSVersion } else { $null }
  if ($RawMinimumOSVersion -and -not $MinimumOSVersion) {
    $Unresolved.Add('MinimumOSVersion')
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'Squirrel.Metadata.InvalidMinimumOSVersion' -Source 'Squirrel/Velopack' -Message "The package declares an invalid osMinVersion value: $RawMinimumOSVersion" -Kind Invalid -Areas Metadata -AffectedFields MinimumOSVersion -Evidence ([ordered]@{ MinimumOSVersion = $RawMinimumOSVersion })))
  }

  $RawOperatingSystem = ([string]$Nuspec.OperatingSystem).Trim()
  $PackageOperatingSystem = $RawOperatingSystem -iin @('win', 'windows') ? 'windows' : $null
  if ($RawOperatingSystem -and -not $PackageOperatingSystem) {
    $Unresolved.Add('PackageOperatingSystem')
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'Squirrel.Metadata.NonWindowsOperatingSystem' -Source 'Squirrel/Velopack' -Message "The Windows setup package declares a non-Windows or unsupported os value: $RawOperatingSystem" -Kind Invalid -Areas Metadata -AffectedFields PackageOperatingSystem -Evidence ([ordered]@{ OperatingSystem = $RawOperatingSystem })))
  }

  $InstallModes = if ($HasConfirmedLauncher) { @('interactive', 'silent') } else { @() }
  if ($HasConfirmedLauncher -and -not $LauncherCapabilities) {
    $LauncherCapabilities = [pscustomobject]@{ Silent = $true; InstallLocation = $false; Log = $false }
  }
  $InstallerSwitches = [ordered]@{}
  if ($HasConfirmedLauncher -and $LauncherCapabilities.Silent) {
    $InstallerSwitches.Silent = '--silent'
    $InstallerSwitches.SilentWithProgress = '--silent'
  }
  if ($HasConfirmedLauncher -and $LauncherCapabilities.InstallLocation) { $InstallerSwitches.InstallLocation = '--installto "<INSTALLPATH>"' }
  if ($HasConfirmedLauncher -and $LauncherCapabilities.Log) { $InstallerSwitches.Log = '--log "<LOGPATH>"' }
  $UnresolvedFields = [string[]]@($Unresolved | Select-Object -Unique)
  $RuntimeDependenciesRaw = ([string]$Nuspec.RuntimeDependencies).Trim()
  $ShortcutLocationsRaw = ([string]$Nuspec.ShortcutLocations).Trim()
  $UpdatePath = $HasConfirmedLauncher ? "$DefaultInstallLocation\Update.exe" : $null
  $UninstallString = $HasConfirmedLauncher ? "`"$UpdatePath`" --uninstall" : $null
  $QuietUninstallString = if (-not $HasConfirmedLauncher) {
    $null
  } elseif ($LauncherGeneration -eq 'Velopack') {
    "$UninstallString --silent"
  } else {
    "$UninstallString -s"
  }
  $DisplayIcon = if ($HasConfirmedLauncher -and $LauncherGeneration -eq 'Velopack' -and -not [string]::IsNullOrWhiteSpace([string]$Nuspec.MainExecutable)) {
    "$DefaultInstallLocation\current\$([string]$Nuspec.MainExecutable -replace '/', '\')"
  } else {
    $null
  }
  $ArpUrlUpdateInfo = if ($HasConfirmedLauncher -and $LauncherGeneration -ne 'Velopack') { $NuspecProjectUrl } else { $null }
  $AppsAndFeaturesEntries = if ($HasConfirmedLauncher) {
    $Entry = [ordered]@{ ProductCode = [string]$Nuspec.Id }
    if (-not [string]::IsNullOrWhiteSpace($DisplayName)) { $Entry.DisplayName = $DisplayName }
    if (-not [string]::IsNullOrWhiteSpace($DisplayVersion)) { $Entry.DisplayVersion = $DisplayVersion }
    if (-not [string]::IsNullOrWhiteSpace($Publisher)) { $Entry.Publisher = $Publisher }
    @([pscustomobject]$Entry)
  } else {
    @()
  }
  $ArpEntries = if ($HasConfirmedLauncher) {
    @([pscustomobject][ordered]@{
        Root                 = 'HKCU'
        Key                  = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($Nuspec.Id)"
        RegistryView         = 'Default'
        ProductCode          = [string]$Nuspec.Id
        DisplayName          = $DisplayName
        DisplayVersion       = $DisplayVersion
        Publisher            = $Publisher
        InstallLocation      = $DefaultInstallLocation
        DisplayIcon          = $DisplayIcon
        UninstallString      = $UninstallString
        QuietUninstallString = $QuietUninstallString
        URLUpdateInfo        = $ArpUrlUpdateInfo
        NoModify             = 1
        NoRepair             = 1
        Language             = 0x0409
      })
  } else {
    @()
  }

  [pscustomobject][ordered]@{
    Path                         = [IO.Path]::GetFullPath($Path)
    InstallerType                = 'exe'
    ProductCode                  = $HasConfirmedLauncher ? $Nuspec.Id : $null
    UpgradeCode                  = $null
    DisplayName                  = $DisplayName
    DisplayVersion               = $DisplayVersion
    Publisher                    = $Publisher
    Scope                        = $HasConfirmedLauncher ? 'user' : $null
    DefaultInstallLocation       = $DefaultInstallLocation
    WritesAppsAndFeaturesEntry   = $HasConfirmedLauncher ? $true : $null
    AppsAndFeaturesProductCode   = $HasConfirmedLauncher ? $Nuspec.Id : $null
    AppsAndFeaturesInstallerType = $HasConfirmedLauncher ? 'exe' : $null
    AppsAndFeaturesEntries       = $AppsAndFeaturesEntries
    Diagnostics                  = @(Merge-InstallerDiagnostics -Diagnostic @($Diagnostics))
    UnresolvedFields             = $UnresolvedFields
    Family                       = $Family
    PackageId                    = $Nuspec.Id
    PackageVersion               = $PackageVersion
    Confidence                   = $Confidence
    DetectionRoute               = $DetectionRoute
    DetectionEvidence            = @($DetectionEvidence)
    InstallModes                 = $InstallModes
    InstallerSwitches            = $InstallerSwitches
    UpgradeBehavior              = $HasConfirmedLauncher ? 'install' : $null
    Architecture                 = $Architecture
    PayloadArchitectures         = [string[]]@(if ($Architecture -and $PayloadArchitecture -eq $Architecture) { $PayloadArchitecture })
    PayloadArchitectureInfo      = $PayloadEvidence
    PayloadDependencyInfo        = if ($PayloadEvidence) { [pscustomobject]@{ ImportedDlls = @($PayloadEvidence.ImportedDlls); DllNames = @($PayloadEvidence.DependencyDllNames); TargetFramework = $PayloadEvidence.TargetFramework; InspectionWarnings = @($PayloadEvidence.InspectionWarnings) } } else { $null }
    PackageMachineArchitecture   = $RawArchitecture
    PackageOperatingSystem       = $PackageOperatingSystem
    PackageOperatingSystemRaw    = $RawOperatingSystem
    MinimumOSVersion             = $MinimumOSVersion
    PackageRid                   = $RawRid
    MainExecutable               = $Nuspec.MainExecutable
    RegistryHive                 = $HasConfirmedLauncher ? 'HKCU' : $null
    RegistryView                 = $HasConfirmedLauncher ? 'Default' : $null
    RegistryPath                 = $HasConfirmedLauncher ? "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($Nuspec.Id)" : $null
    ArpEntries                   = $ArpEntries
    UninstallString              = $UninstallString
    QuietUninstallString         = $QuietUninstallString
    DisplayIcon                  = $DisplayIcon
    URLUpdateInfo                = $NuspecProjectUrl
    ProjectUrl                   = $NuspecProjectUrl
    IconUrl                      = $NuspecIconUrl
    ArpDynamicFields             = [string[]]@(if ($HasConfirmedLauncher) { 'InstallDate'; 'EstimatedSize'; if (-not $DisplayIcon) { 'DisplayIcon' } })
    RuntimeDependencies          = [string[]]@(ConvertFrom-SquirrelMetadataList -Value $RuntimeDependenciesRaw)
    RuntimeDependenciesRaw       = $RuntimeDependenciesRaw
    Channel                      = $Nuspec.Channel
    ShortcutLocations            = [string[]]@(ConvertFrom-SquirrelMetadataList -Value $ShortcutLocationsRaw)
    ShortcutLocationsRaw         = $ShortcutLocationsRaw
    ShortcutAumid                = $Nuspec.ShortcutAumid
    ReleaseNotes                 = $Nuspec.ReleaseNotes
    ReleaseNotesHtml             = $Nuspec.ReleaseNotesHtml
    SplashProgressColor          = $Nuspec.SplashProgressColor
    LauncherGeneration           = $LauncherGeneration
    LauncherCapabilities         = $LauncherCapabilities
    RequiredFrameworks           = [string[]]@(if ($ResourceMetadata) { $ResourceMetadata.RequiredFrameworks | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } })
    ResourceMetadata             = $ResourceMetadata
    ZipOffset                    = $ZipOffset
    NupkgPath                    = $NupkgPath
    Nuspec                       = $Nuspec
  }
}

function ConvertFrom-SquirrelReleases {
  <#
  .SYNOPSIS
    Convert Squirrel releases into organized hashtable
  .PARAMETER Content
    The string containing Squirrel releases information
  .LINK
    https://github.com/Squirrel/Squirrel.Windows/blob/HEAD/src/Squirrel/Utility.cs
  #>
  param (
    [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory, HelpMessage = 'The string containing Squirrel releases information')]
    [string]$Content
  )

  begin {
    $EntryRegex = [regex]::new('^([0-9a-fA-F]{40})\s+(\S+)\s+(\d+)[\r]*$', [System.Text.RegularExpressions.RegexOptions]::Compiled)
    $CommentRegex = [regex]::new('\s*#.*$', [System.Text.RegularExpressions.RegexOptions]::Compiled)
    $StagingRegex = [regex]::new('#\s+(\d{1,3})%$', [System.Text.RegularExpressions.RegexOptions]::Compiled)
    $SuffixRegex = [regex]::new('(-full|-delta)?\.nupkg$', [System.Text.RegularExpressions.RegexOptions]::Compiled)
    $VersionRegex = [regex]::new('\d+(\.\d+){0,3}(-[A-Za-z][0-9A-Za-z-]*)?', [System.Text.RegularExpressions.RegexOptions]::Compiled)

    $Result = @()
  }

  process {
    $Result += $Content | Split-LineEndings | Where-Object -FilterScript { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object -Process {
      $Entry = $_

      # Preserve staged rollout metadata before removing the trailing comment;
      # it changes eligibility but is not part of the filename/hash record.
      $StagingPercentage = $Entry -match $StagingRegex ? $Matches[1] / 100 : $null

      $Entry = $Entry -replace $CommentRegex
      if ([string]::IsNullOrWhiteSpace($Entry)) {
        return
      }

      $Match = $EntryRegex.Match($Entry)
      if (-not $Match.Success -or $Match.Groups.Count -ne 4) {
        throw "Invalid release entry: ${Entry}"
      }

      $Filename = $Match.Groups[2].Value

      $BaseUrl = $null
      $Query = $null

      $Uri = [uri]$null
      # RELEASES permits either a leaf filename or an absolute HTTP(S) URL.
      # Split URLs without dropping query parameters required by the feed.
      if ([uri]::TryCreate($Filename, [System.UriKind]::Absolute, [ref]$Uri) -and $Uri.Scheme -in @([uri]::UriSchemeHttp, [uri]::UriSchemeHttps)) {
        $Path = $Uri.LocalPath
        $Authority = $Uri.GetLeftPart([System.UriPartial]::Authority)

        if ([string]::IsNullOrEmpty($Path) -or [string]::IsNullOrEmpty($Authority)) {
          throw "Invalid URL: ${Filename}"
        }

        $IndexOfLastPathSeparator = $Path.LastIndexOf('/') + 1
        $BaseUrl = $Authority + $Path.Substring(0, $IndexOfLastPathSeparator)
        $Filename = $Path.Substring($IndexOfLastPathSeparator)

        if (-not [string]::IsNullOrEmpty($Uri.Query)) {
          $Query = $Uri.Query
        }
      }

      if ($Filename.IndexOfAny([System.IO.Path]::GetInvalidFileNameChars()) -gt -1) {
        throw "Filename can either be an absolute HTTP[s] URL, *or* a file name: ${Filename}"
      }

      return [pscustomobject]@{
        Version           = $VersionRegex.Match($SuffixRegex.Replace($Filename, '')).Value
        Sha1              = $Match.Groups[1].Value
        Filename          = $Filename
        Filesize          = [Int64]::Parse($Match.Groups[3].Value)
        IsDelta           = $Filename.EndsWith('-delta.nupkg', [System.StringComparison]::InvariantCultureIgnoreCase)
        BaseUrl           = $BaseUrl
        Query             = $Query
        StagingPercentage = $StagingPercentage
      }
    }
  }

  end {
    return $Result
  }
}

function Get-SquirrelInfoFromZipCandidate {
  <#
  .SYNOPSIS
    Read Squirrel or Velopack metadata from one embedded ZIP candidate
  .PARAMETER Path
    The path to the installer
  .PARAMETER Stream
    The caller-owned installer stream
  .PARAMETER Offset
    The ZIP payload offset inside the installer
  .PARAMETER Length
    The bounded ZIP payload length, or zero for the remainder of Stream
  .PARAMETER Family
    The family established by the outer container route
  .PARAMETER DetectionRoute
    The outer container route that exposed this ZIP candidate
  .PARAMETER Confidence
    The confidence assigned to the outer container route
  .PARAMETER DetectionEvidence
    Structural evidence supporting the outer container route
  .PARAMETER DiagnosticMessage
    Diagnostics associated with incomplete or conflicting route evidence
  .PARAMETER Diagnostic
    Structured diagnostics associated with the route
  .PARAMETER LauncherGeneration
    The source generation that defines launcher behavior
  .PARAMETER LauncherCapabilities
    Source-backed setup command-line capabilities
  .PARAMETER ResourceMetadata
    Optional metadata from a legacy Clowd.Squirrel resource bundle
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the installer')][string]$Path,
    [Parameter(Mandatory, HelpMessage = 'The caller-owned installer stream')][IO.Stream]$Stream,
    [Parameter(Mandatory, HelpMessage = 'The ZIP payload offset inside the installer')][long]$Offset,
    [Parameter(HelpMessage = 'The ZIP payload length inside the installer')][long]$Length,
    [Parameter(Mandatory, HelpMessage = 'The family established by the outer container route')][ValidateSet('Squirrel', 'Velopack', 'Squirrel/Velopack')][string]$Family,
    [Parameter(Mandatory, HelpMessage = 'The outer container route that exposed this ZIP candidate')][ValidateSet('SquirrelPeResource', 'ClowdSquirrelPeResource', 'VelopackBundle', 'EmbeddedZipFallback', 'ConflictingAuthoritativeRoutes')][string]$DetectionRoute,
    [Parameter(Mandatory, HelpMessage = 'The confidence assigned to the outer container route')][ValidateSet('high', 'medium', 'low')][string]$Confidence,
    [Parameter(HelpMessage = 'Structural evidence supporting the outer container route')][object[]]$DetectionEvidence = @(),
    [Parameter(HelpMessage = 'Diagnostics associated with incomplete or conflicting route evidence')][string[]]$DiagnosticMessage = @(),
    [Parameter(HelpMessage = 'Structured diagnostics associated with the route')][object[]]$Diagnostic = @(),
    [string]$LauncherGeneration,
    [psobject]$LauncherCapabilities,
    [psobject]$ResourceMetadata
  )

  if ($Offset -lt 0 -or $Offset -gt $Stream.Length) { throw 'The Squirrel package offset is outside the installer.' }
  $RangeLength = if ($Length -gt 0) { $Length } else { $Stream.Length - $Offset }
  if ($RangeLength -le 0 -or $RangeLength -gt $Stream.Length - $Offset) { throw 'The Squirrel package range is outside the installer.' }

  $Range = New-BoundedReadStream -Stream $Stream -Offset $Offset -Length $RangeLength -LeaveOpen
  $Archive = $null
  try {
    $Archive = Get-InstallerArchive -Stream $Range
    # Classic setup archives wrap one full nupkg. Velopack and transitional
    # Clowd bundles are nupkg-shaped and expose nuspec at the root.
    $NupkgEntries = [Collections.Generic.List[object]]::new()
    $EntryCount = 0
    foreach ($Entry in Get-InstallerArchiveEntry -Archive $Archive) {
      if (++$EntryCount -gt 65536) { throw 'The package archive exceeds the 65536-entry limit.' }
      $EntryName = ([string]$Entry.FullName).Replace('\', '/').TrimStart('/')
      while ($EntryName.StartsWith('./', [StringComparison]::Ordinal)) { $EntryName = $EntryName.Substring(2) }
      if ($EntryName.IndexOf('/') -lt 0 -and $EntryName.EndsWith('.nupkg', [StringComparison]::OrdinalIgnoreCase) -and -not $EntryName.EndsWith('-delta.nupkg', [StringComparison]::OrdinalIgnoreCase)) {
        $NupkgEntries.Add($Entry)
      }
    }
    if ($NupkgEntries.Count -gt 1) { throw 'The setup archive contains multiple full nupkg candidates.' }
    $NupkgEntry = $NupkgEntries.Count -eq 1 ? $NupkgEntries[0] : $null
    if ($NupkgEntry) {
      $Nuspec = Read-SquirrelNuspecFromNupkgEntry -Entry $NupkgEntry
      if ($Nuspec) {
        Assert-SquirrelNuspecMetadata -Nuspec $Nuspec -LauncherGeneration $LauncherGeneration
        return ConvertTo-SquirrelInfo -Path $Path -Family $Family -DetectionRoute $DetectionRoute -Confidence $Confidence -ZipOffset $Offset -NupkgPath $NupkgEntry.FullName -Nuspec $Nuspec -DetectionEvidence $DetectionEvidence -DiagnosticMessage $DiagnosticMessage -Diagnostic $Diagnostic -LauncherGeneration $LauncherGeneration -LauncherCapabilities $LauncherCapabilities -ResourceMetadata $ResourceMetadata
      }
    }

    $DirectNuspec = Read-SquirrelNuspecFromZipArchive -Archive $Archive
    if ($DirectNuspec) {
      Assert-SquirrelNuspecMetadata -Nuspec $DirectNuspec -LauncherGeneration $LauncherGeneration
      if ($ResourceMetadata.AppId -and -not [string]::Equals([string]$ResourceMetadata.AppId, [string]$DirectNuspec.Id, [StringComparison]::OrdinalIgnoreCase)) {
        throw "The Clowd.Squirrel AppId '$($ResourceMetadata.AppId)' conflicts with nuspec id '$($DirectNuspec.Id)'."
      }
      $PayloadEvidence = if ($LauncherGeneration -eq 'Velopack') { Get-SquirrelMainExecutableEvidence -Archive $Archive -MainExecutable $DirectNuspec.MainExecutable } else { $null }
      return ConvertTo-SquirrelInfo -Path $Path -Family $Family -DetectionRoute $DetectionRoute -Confidence $Confidence -ZipOffset $Offset -NupkgPath $ResourceMetadata.BundledPackageName -Nuspec $DirectNuspec -DetectionEvidence $DetectionEvidence -DiagnosticMessage $DiagnosticMessage -Diagnostic $Diagnostic -LauncherGeneration $LauncherGeneration -LauncherCapabilities $LauncherCapabilities -ResourceMetadata $ResourceMetadata -PayloadEvidence $PayloadEvidence
    }
  } finally {
    if ($Archive) { $Archive.Dispose() }
    $Range.Dispose()
  }
}

function Get-SquirrelInfo {
  <#
  .SYNOPSIS
    Get static metadata from a Squirrel or Velopack installer
  .PARAMETER Path
    The path to the installer
  .PARAMETER MaximumOffsets
    The maximum number of embedded ZIP offsets to try
  .PARAMETER MaximumBundleSignatures
    The maximum number of signed bundle markers to inspect
  .PARAMETER MaximumLauncherBytes
    The maximum launcher prefix to scan for signed bundle markers
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path,

    [Parameter(HelpMessage = 'The maximum number of embedded ZIP offsets to try')]
    [ValidateRange(1, 1024)][int]$MaximumOffsets = 64,

    [Parameter(HelpMessage = 'The maximum number of signed bundle markers to inspect')]
    [ValidateRange(1, 1024)][int]$MaximumBundleSignatures = 8,

    [Parameter(HelpMessage = 'The maximum launcher prefix to scan for signed bundle markers')]
    [ValidateRange(1048576, 1073741824)][long]$MaximumLauncherBytes = 16777216
  )

  process {
    $File = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $InputStream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
      $PeLayout = try { Get-PELayout -Stream $InputStream } catch { $null }
      # Some custom .NET single-file launchers bundle Squirrel client libraries
      # without carrying setup package metadata. That is an update client, not a
      # Squirrel setup, even though the library names are structurally present.
      $UnpackagedSquirrelRuntime = $false
      $DotNetBundle = Get-PEDotNetBundleInfo -Stream $InputStream
      if ($DotNetBundle) {
        $BundleEntryNames = @($DotNetBundle.Entries.RelativePath)
        $HasSquirrelLibrary = @($BundleEntryNames | Where-Object { [IO.Path]::GetFileName($_) -iin @('Squirrel.dll', 'NuGet.Squirrel.dll') }).Count -gt 0
        $HasPackageMetadata = @($BundleEntryNames | Where-Object { $_ -match '(?i)(?:^|/)(?:RELEASES|[^/]+\.(?:nupkg|nuspec))$' }).Count -gt 0
        $UnpackagedSquirrelRuntime = $HasSquirrelLibrary -and -not $HasPackageMetadata
      }

      # Authoritative routes identify the outer launcher independently from the
      # nupkg's internal shape. Preserve both routes until payload validation so
      # conflicting structural evidence cannot be hidden by candidate order.
      $AuthoritativeCandidates = [System.Collections.Generic.List[psobject]]::new()
      $ResourceCandidates = try {
        if ($PeLayout) { @(Get-SquirrelPeResourceZipCandidate -Stream $InputStream -Layout $PeLayout) } else { @() }
      } catch {
        throw "Squirrel PE-resource inspection failed: $($_.Exception.Message)"
      }
      foreach ($ResourceCandidate in $ResourceCandidates) {
        if ($AuthoritativeCandidates.Count -ge 64) { throw 'The installer exceeds the 64-candidate authoritative Squirrel-family limit.' }
        $ResourceFamily = $ResourceCandidate.PSObject.Properties['Family'] ? [string]$ResourceCandidate.Family : 'Squirrel'
        $ResourceRoute = $ResourceCandidate.PSObject.Properties['DetectionRoute'] ? [string]$ResourceCandidate.DetectionRoute : 'SquirrelPeResource'
        $ResourceId = $ResourceCandidate.PSObject.Properties['ResourceId'] ? [int]$ResourceCandidate.ResourceId : $Script:SquirrelResourceId
        $ResourceGeneration = $ResourceCandidate.PSObject.Properties['LauncherGeneration'] ? [string]$ResourceCandidate.LauncherGeneration : 'Squirrel.Windows'
        $ResourceCapabilities = $ResourceCandidate.PSObject.Properties['LauncherCapabilities'] ? $ResourceCandidate.LauncherCapabilities : [pscustomobject]@{ Silent = $true; InstallLocation = $false; Log = $false }
        $ResourceLanguageId = $ResourceCandidate.PSObject.Properties['ResourceLanguageId'] ? [int]$ResourceCandidate.ResourceLanguageId : 0
        $AuthoritativeCandidates.Add([pscustomobject]@{
            Offset               = [long]$ResourceCandidate.Offset
            Length               = [long]$ResourceCandidate.Length
            Family               = $ResourceFamily
            DetectionRoute       = $ResourceRoute
            Confidence           = 'high'
            LauncherGeneration   = $ResourceGeneration
            LauncherCapabilities = $ResourceCapabilities
            ResourceMetadata     = $ResourceCandidate.ResourceMetadata
            DetectionEvidence    = @([pscustomobject]@{ Kind = 'PEResource'; Type = $Script:SquirrelResourceType; Id = $ResourceId; LanguageId = $ResourceLanguageId; Offset = [long]$ResourceCandidate.Offset; Length = [long]$ResourceCandidate.Length })
          })
      }

      $BundleHeaders = @(Get-SquirrelBundleHeader -Stream $InputStream -MaximumSignatures $MaximumBundleSignatures -MaximumLauncherBytes $MaximumLauncherBytes) | Where-Object { $null -ne $_ }
      foreach ($BundleHeader in $BundleHeaders) {
        if ($AuthoritativeCandidates.Count -ge 64) { throw 'The installer exceeds the 64-candidate authoritative Squirrel-family limit.' }
        $Generation = $BundleHeader.PSObject.Properties['LauncherGeneration'] ? [string]$BundleHeader.LauncherGeneration : 'Clowd.Squirrel.Bundle'
        $Capabilities = $BundleHeader.PSObject.Properties['LauncherCapabilities'] ? $BundleHeader.LauncherCapabilities : [pscustomobject]@{ Silent = $true; InstallLocation = $false; Log = $false }
        $AuthoritativeCandidates.Add([pscustomobject]@{
            Offset               = [long]$BundleHeader.Offset
            Length               = [long]$BundleHeader.Length
            Family               = 'Velopack'
            DetectionRoute       = 'VelopackBundle'
            Confidence           = 'high'
            LauncherGeneration   = $Generation
            LauncherCapabilities = $Capabilities
            ResourceMetadata     = $null
            DetectionEvidence    = @([pscustomobject]@{ Kind = 'BundleLocator'; Signature = '94F0B17B6893E02937EB34EF53AAE7D42B54F5707EF5D6F57854983E5E94ED7D'; SignatureOffset = [long]$BundleHeader.SignatureOffset; Offset = [long]$BundleHeader.Offset; Length = [long]$BundleHeader.Length; LauncherGeneration = $Generation })
          })
      }

      $AuthoritativeResults = [System.Collections.Generic.List[object]]::new()
      $AuthoritativeFailures = [System.Collections.Generic.List[string]]::new()
      foreach ($Candidate in $AuthoritativeCandidates) {
        try {
          $Info = Get-SquirrelInfoFromZipCandidate -Path $File.FullName -Stream $InputStream -Offset $Candidate.Offset -Length $Candidate.Length -Family $Candidate.Family -DetectionRoute $Candidate.DetectionRoute -Confidence $Candidate.Confidence -DetectionEvidence $Candidate.DetectionEvidence -LauncherGeneration $Candidate.LauncherGeneration -LauncherCapabilities $Candidate.LauncherCapabilities -ResourceMetadata $Candidate.ResourceMetadata
          if ($Info) { $AuthoritativeResults.Add($Info) }
        } catch {
          $AuthoritativeFailures.Add("$($Candidate.DetectionRoute) at offset $($Candidate.Offset): $($_.Exception.Message)")
        }
      }

      if ($AuthoritativeResults.Count -gt 0) {
        $Families = @($AuthoritativeResults.Family | Sort-Object -Unique)
        $Identity = @($AuthoritativeResults | ForEach-Object { "$($_.ProductCode)`0$($_.DisplayVersion)" } | Select-Object -Unique)
        if ($Identity.Count -gt 1) { throw 'The installer contains conflicting authoritative Squirrel-family package identities.' }
        $MetadataSignatures = @($AuthoritativeResults | ForEach-Object {
            [ordered]@{
              Id = $_.Nuspec.Id; Title = $_.Nuspec.Title; Version = $_.Nuspec.Version; Authors = $_.Nuspec.Authors
              Owners = $_.Nuspec.Owners; Description = $_.Nuspec.Description; Summary = $_.Nuspec.Summary; ProjectUrl = $_.Nuspec.ProjectUrl; IconUrl = $_.Nuspec.IconUrl
              MachineArchitecture = $_.Nuspec.MachineArchitecture; RuntimeDependencies = $_.Nuspec.RuntimeDependencies
              MainExecutable = $_.Nuspec.MainExecutable; OperatingSystem = $_.Nuspec.OperatingSystem; Rid = $_.Nuspec.Rid
              MinimumOSVersion = $_.Nuspec.MinimumOSVersion; Channel = $_.Nuspec.Channel; ShortcutLocations = $_.Nuspec.ShortcutLocations
              ShortcutAumid = $_.Nuspec.ShortcutAumid; ReleaseNotes = $_.Nuspec.ReleaseNotes; ReleaseNotesHtml = $_.Nuspec.ReleaseNotesHtml
              SplashProgressColor = $_.Nuspec.SplashProgressColor
            } | ConvertTo-Json -Compress
          } | Sort-Object -Unique -CaseSensitive)
        if ($MetadataSignatures.Count -gt 1) { throw 'The installer contains conflicting authoritative Squirrel-family package metadata.' }
        $LauncherContracts = @($AuthoritativeResults | ForEach-Object {
            "$($_.DetectionRoute)`0$($_.LauncherGeneration)`0$([bool]$_.LauncherCapabilities.Silent)`0$([bool]$_.LauncherCapabilities.InstallLocation)`0$([bool]$_.LauncherCapabilities.Log)"
          } | Select-Object -Unique)
        if ($Families.Count -eq 1 -and $LauncherContracts.Count -eq 1) {
          return $AuthoritativeResults[0]
        }

        # Preserve family and identity when every route agrees on them, but use
        # only launcher behavior proven by every validated generation.
        $BaseInfo = $AuthoritativeResults[0]
        $Evidence = @($AuthoritativeResults | ForEach-Object { $_.DetectionEvidence })
        $PayloadEvidence = @($AuthoritativeResults.PayloadArchitectureInfo | Where-Object { $null -ne $_ } | Select-Object -First 1)[0]
        $ResolvedFamily = $Families.Count -eq 1 ? $Families[0] : 'Squirrel/Velopack'
        $CommonCapabilities = if ($ResolvedFamily -ne 'Squirrel/Velopack') {
          [pscustomobject]@{
            Silent          = @($AuthoritativeResults | Where-Object { -not $_.LauncherCapabilities.Silent }).Count -eq 0
            InstallLocation = @($AuthoritativeResults | Where-Object { -not $_.LauncherCapabilities.InstallLocation }).Count -eq 0
            Log             = @($AuthoritativeResults | Where-Object { -not $_.LauncherCapabilities.Log }).Count -eq 0
          }
        } else {
          $null
        }
        $ConflictDiagnostic = New-InstallerDiagnostic -Id 'Squirrel.Detection.AuthoritativeRouteConflict' -Source 'Squirrel/Velopack' -Message 'The installer validates multiple authoritative Squirrel-family routes with different launcher contracts; only common behavior is retained.' -Kind Ambiguous -Areas Detection -AffectedFields LauncherGeneration, InstallerSwitches -Evidence ([ordered]@{ Families = $Families; Routes = @($AuthoritativeResults | Select-Object DetectionRoute, LauncherGeneration, LauncherCapabilities) })
        return ConvertTo-SquirrelInfo -Path $File.FullName -Family $ResolvedFamily -DetectionRoute 'ConflictingAuthoritativeRoutes' -Confidence 'low' -ZipOffset $BaseInfo.ZipOffset -NupkgPath $BaseInfo.NupkgPath -Nuspec $BaseInfo.Nuspec -DetectionEvidence $Evidence -Diagnostic @($ConflictDiagnostic) -AdditionalUnresolvedFields LauncherGeneration, InstallerSwitches -LauncherCapabilities $CommonCapabilities -ResourceMetadata $BaseInfo.ResourceMetadata -PayloadEvidence $PayloadEvidence
      }

      if ($AuthoritativeCandidates.Count -gt 0) {
        $FailureDetail = $AuthoritativeFailures.Count -gt 0 ? ($AuthoritativeFailures -join '; ') : 'no authoritative candidate contained valid package metadata'
        throw "The installer exposes an authoritative Squirrel-family structure, but payload validation failed: $FailureDetail"
      }

      if ($UnpackagedSquirrelRuntime) {
        throw 'The .NET single-file application contains Squirrel libraries but no embedded nupkg, nuspec, or RELEASES package metadata; treat it as a custom runtime bootstrapper and validate its installed ARP identity in a VM'
      }

      # ZIP signatures alone prove package metadata, not the setup launcher.
      # Skip authoritative ranges already attempted so a malformed exact route
      # cannot silently downgrade into a permissive generic interpretation.
      foreach ($Offset in Get-SquirrelZipLocalHeaderOffset -Stream $InputStream -Maximum $MaximumOffsets) {
        $InsideAuthoritativeRange = $false
        foreach ($Candidate in $AuthoritativeCandidates) {
          if ($Offset -ge $Candidate.Offset -and $Offset - $Candidate.Offset -lt $Candidate.Length) {
            $InsideAuthoritativeRange = $true
            break
          }
        }
        if ($InsideAuthoritativeRange) { continue }
        try {
          $Evidence = @([pscustomobject]@{ Kind = 'EmbeddedZip'; Offset = [long]$Offset })
          $GenericDiagnostic = New-InstallerDiagnostic -Id 'Squirrel.Detection.GenericPackageOnly' -Source 'Squirrel/Velopack' -Message 'Embedded Squirrel-compatible package metadata was found without an authoritative Squirrel or Velopack launcher structure; family-specific behavior remains unresolved.' -Kind Incomplete -Areas Detection -AffectedFields ProductCode, Scope, DefaultInstallLocation, AppsAndFeaturesEntries, InstallModes, InstallerSwitches, UpgradeBehavior, LauncherGeneration -Evidence $Evidence
          $Info = Get-SquirrelInfoFromZipCandidate -Path $File.FullName -Stream $InputStream -Offset $Offset -Length 0 -Family 'Squirrel/Velopack' -DetectionRoute 'EmbeddedZipFallback' -Confidence 'low' -DetectionEvidence $Evidence -Diagnostic @($GenericDiagnostic)
          if ($Info) { return $Info }
        } catch {
          continue
        }
      }
    } finally {
      $InputStream.Dispose()
    }

    throw 'The installer does not expose embedded Squirrel or Velopack nuspec metadata'
  }
}

function Read-ProductCodeFromSquirrel {
  <#
  .SYNOPSIS
    Read the product code from a Squirrel or Velopack installer
  .PARAMETER Path
    The path to the installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path
  )

  process {
    $Info = Get-SquirrelInfo -Path $Path
    if ([string]::IsNullOrWhiteSpace($Info.ProductCode)) { throw 'The Squirrel installer does not expose a ProductCode value' }
    return $Info.ProductCode
  }
}

function Test-SquirrelInstaller {
  <#
  .SYNOPSIS
    Test whether an installer exposes static Squirrel or Velopack metadata
  .PARAMETER Path
    The path to the installer
  #>
  [OutputType([bool])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path
  )

  process {
    try {
      $null = Get-SquirrelInfo -Path $Path
      return $true
    } catch {
      return $false
    }
  }
}

function Read-ProductVersionFromSquirrel {
  <#
  .SYNOPSIS
    Read the product version from a Squirrel or Velopack installer
  .PARAMETER Path
    The path to the installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path
  )

  process {
    $Info = Get-SquirrelInfo -Path $Path
    if ([string]::IsNullOrWhiteSpace($Info.DisplayVersion)) { throw 'The Squirrel installer does not expose a DisplayVersion value' }
    return $Info.DisplayVersion
  }
}

function Read-ProductNameFromSquirrel {
  <#
  .SYNOPSIS
    Read the product name from a Squirrel or Velopack installer
  .PARAMETER Path
    The path to the installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path
  )

  process {
    $Info = Get-SquirrelInfo -Path $Path
    if ([string]::IsNullOrWhiteSpace($Info.DisplayName)) { throw 'The Squirrel installer does not expose a DisplayName value' }
    return $Info.DisplayName
  }
}

function Read-PublisherFromSquirrel {
  <#
  .SYNOPSIS
    Read the publisher from a Squirrel or Velopack installer
  .PARAMETER Path
    The path to the installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path
  )

  process {
    $Info = Get-SquirrelInfo -Path $Path
    if ([string]::IsNullOrWhiteSpace($Info.Publisher)) { throw 'The Squirrel installer does not expose a Publisher value' }
    return $Info.Publisher
  }
}

Export-ModuleMember -Function Get-SquirrelInfo, Test-SquirrelInstaller, ConvertFrom-SquirrelReleases, Read-ProductCodeFromSquirrel, Read-ProductVersionFromSquirrel, Read-ProductNameFromSquirrel, Read-PublisherFromSquirrel
