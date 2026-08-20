# SPDX-License-Identifier: Apache-2.0
# Structure references: https://github.com/dotnet/dotnet

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }
# Import-analysis reference: https://github.com/lucasg/Dependencies

$Script:DotNetRuntimeFrameworkPackageMap = @{
  'Microsoft.NETCore.App'        = 'Microsoft.DotNet.Runtime'
  'Microsoft.WindowsDesktop.App' = 'Microsoft.DotNet.DesktopRuntime'
  'Microsoft.AspNetCore.App'     = 'Microsoft.DotNet.AspNetCore'
}
$Script:DotNetSupportedDependencyMajors = 5..10
$Script:DotNetBundledRuntimeFileNames = @('hostfxr.dll', 'hostpolicy.dll', 'coreclr.dll', 'System.Private.CoreLib.dll')
$Script:DotNetAppHostPlaceholder = 'c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2'
$Script:DotNetAppHostMaximumBindingLength = 1024
$Script:DotNetHostMaximumBindingLength = 1024
$Script:DotNetBundleHeaderSignature = [byte[]](
  0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38,
  0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32,
  0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18,
  0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae
)

function Resolve-PortableVCRedistRuntime {
  <#
  .SYNOPSIS
    Map an imported DLL to a Visual C++ runtime generation
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][string]$DllName)
  $Name = [IO.Path]::GetFileName($DllName).ToLowerInvariant()
  switch -Regex ($Name) {
    '^(msvcr80|msvcp80|atl80|mfc80.*|mfcm80.*)\.dll$' { '2005'; break }
    '^(msvcr90|msvcp90|atl90|mfc90.*|mfcm90.*)\.dll$' { '2008'; break }
    '^(msvcr100|msvcp100|mfc100.*|mfcm100.*|vcomp100)\.dll$' { '2010'; break }
    '^(msvcr110|msvcp110|mfc110.*|mfcm110.*|vcomp110)\.dll$' { '2012'; break }
    '^(msvcr120|msvcp120|mfc120.*|mfcm120.*|vcomp120)\.dll$' { '2013'; break }
    '^(vcruntime140.*|msvcp140.*|concrt140|mfc140.*|mfcm140.*|vcomp140|vccorlib140.*)\.dll$' { '2015+'; break }
    default { $null }
  }
}

function Test-PortableUcrtImport {
  <#
  .SYNOPSIS
    Test whether an imported DLL belongs to the Universal C Runtime
  #>
  [OutputType([bool])]
  param ([Parameter(Mandatory)][string]$DllName)
  $Name = [IO.Path]::GetFileName($DllName).ToLowerInvariant()
  return $Name -eq 'ucrtbase.dll' -or $Name -like 'api-ms-win-crt-*.dll'
}

function Get-PortableVCRedistPackageIdentifier {
  <#
  .SYNOPSIS
    Build a concrete WinGet VCRedist package identifier
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][ValidateSet('2005', '2008', '2010', '2012', '2013', '2015+')][string]$RuntimeVersion,
    [Parameter(Mandatory)][ValidateSet('x86', 'x64', 'arm64')][string]$Architecture
  )
  if ($Architecture -eq 'arm64' -and $RuntimeVersion -ne '2015+') { return $null }
  return "Microsoft.VCRedist.$RuntimeVersion.$Architecture"
}

function Get-PEDotNetAppHostBindingCandidateFromStream {
  <#
  .SYNOPSIS
    Find bounded apphost DLL binding candidates without buffering the PE image
  #>
  [OutputType([string[]])]
  param ([Parameter(Mandatory)][System.IO.Stream]$Stream)
  $Candidates = [Collections.Generic.List[string]]::new()
  $Needle = [Text.Encoding]::ASCII.GetBytes('.dll')
  foreach ($DllOffset in @(Find-BinaryPattern -Stream $Stream -Pattern $Needle -Maximum 4096)) {
    $WindowStart = [Math]::Max(0L, $DllOffset - $Script:DotNetHostMaximumBindingLength)
    $WindowLength = [int][Math]::Min(($Script:DotNetHostMaximumBindingLength * 2) + $Needle.Length, $Stream.Length - $WindowStart)
    $Window = Read-BinaryBytes -Stream $Stream -Offset $WindowStart -Count $WindowLength
    $LocalDllOffset = [int]($DllOffset - $WindowStart)
    $Start = $LocalDllOffset
    while ($Start -gt 0 -and $Window[$Start - 1] -ne 0 -and ($LocalDllOffset - $Start) -lt $Script:DotNetHostMaximumBindingLength) { $Start-- }
    $End = $LocalDllOffset + $Needle.Length
    while ($End -lt $Window.Length -and $Window[$End] -ne 0 -and ($End - $Start) -lt $Script:DotNetHostMaximumBindingLength) { $End++ }
    if ($End -le $Start -or $End - $Start -gt $Script:DotNetHostMaximumBindingLength) { continue }
    $Candidate = [Text.Encoding]::UTF8.GetString($Window, $Start, $End - $Start)
    if ($Candidate -notmatch '(?i)\.dll$' -or $Candidate -match '[\x00-\x1F]|[<>:"|?*]' -or $Candidate -match '^[A-Za-z]:[\\/]' -or $Candidate.StartsWith('\')) { continue }
    $Candidates.Add($Candidate)
  }
  return @($Candidates | Sort-Object -Unique)
}

function Read-PERuntimeConfig {
  <#
  .SYNOPSIS
    Read a .NET runtimeconfig JSON file
  .PARAMETER Path
    The runtimeconfig.json path
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The runtimeconfig.json path')]
    [string]$Path
  )

  $File = Get-Item -LiteralPath $Path -Force
  $Content = Get-Content -LiteralPath $File.FullName -Raw -Encoding UTF8
  if ([string]::IsNullOrWhiteSpace($Content)) { return $null }
  $Json = $Content | ConvertFrom-Json
  [pscustomobject]@{
    Path = $File.FullName
    Json = $Json
  }
}

function Find-PEBytePattern {
  <#
  .SYNOPSIS
    Find all offsets of a byte pattern inside a byte array
  .PARAMETER Bytes
    The byte array to search
  .PARAMETER Pattern
    The byte pattern to find
  #>
  [OutputType([int[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The byte array to search')]
    [byte[]]$Bytes,

    [Parameter(Mandatory, HelpMessage = 'The byte pattern to find')]
    [byte[]]$Pattern
  )

  @(Find-BinaryPattern -Bytes $Bytes -Pattern $Pattern) | ForEach-Object { [int]$_ }
}

function Read-PE7BitEncodedLength {
  <#
  .SYNOPSIS
    Read the 7-bit string length format used by .NET bundle manifests
  .PARAMETER Bytes
    The bundle byte array
  .PARAMETER Offset
    The offset to read from
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The bundle byte array')]
    [byte[]]$Bytes,

    [Parameter(Mandatory, HelpMessage = 'The offset to read from')]
    [int]$Offset
  )

  if ($Offset -lt 0 -or $Offset -ge $Bytes.Count) { return $null }

  $FirstByte = [int]$Bytes[$Offset]
  if (($FirstByte -band 0x80) -eq 0) {
    return [pscustomobject]@{ Length = $FirstByte; BytesRead = 1 }
  }

  if ($Offset + 1 -ge $Bytes.Count) { return $null }
  $SecondByte = [int]$Bytes[$Offset + 1]
  if (($SecondByte -band 0x80) -ne 0) { return $null }

  [pscustomobject]@{
    Length    = (($SecondByte -shl 7) -bor ($FirstByte -band 0x7F))
    BytesRead = 2
  }
}

function Read-PEBundleString {
  <#
  .SYNOPSIS
    Read a length-prefixed UTF-8 bundle manifest string
  .PARAMETER Bytes
    The bundle byte array
  .PARAMETER Offset
    The offset to read from
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The bundle byte array')]
    [byte[]]$Bytes,

    [Parameter(Mandatory, HelpMessage = 'The offset to read from')]
    [int]$Offset
  )

  $LengthInfo = Read-PE7BitEncodedLength -Bytes $Bytes -Offset $Offset
  if (-not $LengthInfo -or $LengthInfo.Length -le 0) { return $null }

  $StringOffset = $Offset + $LengthInfo.BytesRead
  if ($StringOffset + $LengthInfo.Length -gt $Bytes.Count) { return $null }

  [pscustomobject]@{
    Value     = [System.Text.Encoding]::UTF8.GetString($Bytes, $StringOffset, $LengthInfo.Length)
    BytesRead = $LengthInfo.BytesRead + $LengthInfo.Length
  }
}

function Read-PEDotNetBundleBinaryString {
  <#
  .SYNOPSIS
    Read one BinaryWriter-compatible UTF-8 string from a .NET bundle manifest.
  .PARAMETER Reader
    Binary reader positioned at the seven-bit encoded byte length.
  .PARAMETER MaximumBytes
    Maximum accepted UTF-8 byte length.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][System.IO.BinaryReader]$Reader,
    [ValidateRange(1, 1048576)][int]$MaximumBytes = 32768
  )

  $Length = 0
  $Shift = 0
  $Terminated = $false
  for ($Index = 0; $Index -lt 5; $Index++) {
    $Value = $Reader.ReadByte()
    $Length = $Length -bor (($Value -band 0x7F) -shl $Shift)
    if (($Value -band 0x80) -eq 0) { $Terminated = $true; break }
    $Shift += 7
  }
  if (-not $Terminated -or $Length -lt 0 -or $Length -gt $MaximumBytes) { throw 'The .NET bundle contains an invalid string length.' }
  $Bytes = $Reader.ReadBytes($Length)
  if ($Bytes.Count -ne $Length) { throw 'The .NET bundle string is truncated.' }
  return [Text.Encoding]::UTF8.GetString($Bytes)
}

function Read-PEDotNetBundleEntryInfo {
  <#
  .SYNOPSIS
    Parse validated file entries from a .NET single-file bundle manifest.
  .PARAMETER Stream
    Caller-owned seekable stream containing the bundle.
  .PARAMETER HeaderOffset
    Absolute offset of the bundle header.
  .PARAMETER MaximumEntries
    Maximum accepted embedded-file count.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][System.IO.Stream]$Stream,
    [Parameter(Mandatory)][long]$HeaderOffset,
    [ValidateRange(1, 100000)][int]$MaximumEntries = 100000
  )

  $OriginalPosition = $Stream.Position
  $Reader = $null
  try {
    $Stream.Position = $HeaderOffset
    $Reader = [IO.BinaryReader]::new($Stream, [Text.Encoding]::UTF8, $true)
    $MajorVersion = $Reader.ReadUInt32()
    $MinorVersion = $Reader.ReadUInt32()
    $EmbeddedFileCount = $Reader.ReadInt32()
    if (-not (($MajorVersion -eq 2 -or $MajorVersion -eq 6) -and $MinorVersion -eq 0)) { throw "Unsupported .NET bundle manifest version $MajorVersion.$MinorVersion." }
    if ($EmbeddedFileCount -le 0 -or $EmbeddedFileCount -gt $MaximumEntries) { throw "The .NET bundle embedded-file count '$EmbeddedFileCount' is outside the parser limit." }
    $null = Read-PEDotNetBundleBinaryString -Reader $Reader
    for ($Index = 0; $Index -lt 4; $Index++) { $null = $Reader.ReadInt64() }
    $null = $Reader.ReadUInt64()

    $Entries = [System.Collections.Generic.List[object]]::new($EmbeddedFileCount)
    for ($Index = 0; $Index -lt $EmbeddedFileCount; $Index++) {
      $Offset = $Reader.ReadInt64()
      $Size = $Reader.ReadInt64()
      $CompressedSize = $MajorVersion -ge 6 ? $Reader.ReadInt64() : 0
      $Type = $Reader.ReadByte()
      $RelativePath = Read-PEDotNetBundleBinaryString -Reader $Reader
      $StoredSize = $CompressedSize -gt 0 ? $CompressedSize : $Size
      if ($Offset -lt 0 -or $Size -lt 0 -or $CompressedSize -lt 0 -or $StoredSize -gt $Stream.Length -or $Offset -gt $Stream.Length - $StoredSize) {
        throw "The .NET bundle entry '$RelativePath' points outside the file."
      }
      $Entries.Add([pscustomobject]@{
          RelativePath   = $RelativePath.Replace('\', '/')
          Offset         = $Offset
          Size           = $Size
          CompressedSize = $CompressedSize
          Type           = $Type
        })
    }
    return $Entries.ToArray()
  } finally {
    if ($Reader) { $Reader.Dispose() }
    $Stream.Position = $OriginalPosition
  }
}

function Get-PEDotNetBundleInfo {
  <#
  .SYNOPSIS
    Read .NET single-file bundle header evidence from an apphost
  .PARAMETER Path
    The PE file path
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, ParameterSetName = 'Path', HelpMessage = 'The PE file path')][string]$Path,
    [Parameter(Mandatory, ParameterSetName = 'Stream', HelpMessage = 'The caller-owned PE stream')][System.IO.Stream]$Stream
  )

  $OwnsStream = $PSCmdlet.ParameterSetName -eq 'Path'
  if ($OwnsStream) {
    $File = Get-Item -LiteralPath $Path -Force
    $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  }
  if ($Stream.Length -gt 536870912) { if ($OwnsStream) { $Stream.Dispose() }; return $null }

  $BundleHeaders = [System.Collections.Generic.List[psobject]]::new()
  try {
    # The signature is only a locator. Authenticate the preceding header pointer,
    # supported bundle version, bounded file count, and embedded JSON ranges.
    foreach ($SignatureOffset in @(Find-BinaryPattern -Stream $Stream -Pattern $Script:DotNetBundleHeaderSignature -Maximum 16)) {
      if ($SignatureOffset -lt 8) { continue }
      $HeaderOffset = [BitConverter]::ToInt64((Read-BinaryBytes -Stream $Stream -Offset ($SignatureOffset - 8) -Count 8), 0)
      if ($HeaderOffset -le 0 -or $HeaderOffset + 60 -gt $Stream.Length) { continue }

      try {
        $HeaderBytes = Read-BinaryBytes -Stream $Stream -Offset $HeaderOffset -Count ([int][Math]::Min(4096, $Stream.Length - $HeaderOffset))
        $MajorVersion = [System.BitConverter]::ToUInt32($HeaderBytes, 0)
        $MinorVersion = [System.BitConverter]::ToUInt32($HeaderBytes, 4)
        $EmbeddedFileCount = [System.BitConverter]::ToInt32($HeaderBytes, 8)
        if (-not (($MajorVersion -eq 6 -and $MinorVersion -eq 0) -or ($MajorVersion -eq 2 -and $MinorVersion -eq 0))) { continue }
        if ($EmbeddedFileCount -le 0 -or $EmbeddedFileCount -gt 100000) { continue }

        $ReadOffset = 12
        $BundleId = Read-PEBundleString -Bytes $HeaderBytes -Offset $ReadOffset
        if (-not $BundleId) { continue }
        $ReadOffset += $BundleId.BytesRead

        $DepsJsonOffset = [System.BitConverter]::ToInt64($HeaderBytes, $ReadOffset)
        $DepsJsonSize = [System.BitConverter]::ToInt64($HeaderBytes, $ReadOffset + 8)
        $RuntimeConfigJsonOffset = [System.BitConverter]::ToInt64($HeaderBytes, $ReadOffset + 16)
        $RuntimeConfigJsonSize = [System.BitConverter]::ToInt64($HeaderBytes, $ReadOffset + 24)
        $Flags = [System.BitConverter]::ToUInt64($HeaderBytes, $ReadOffset + 32)

        $RuntimeConfigJson = $null
        if ($RuntimeConfigJsonOffset -gt 0 -and $RuntimeConfigJsonSize -gt 0 -and $RuntimeConfigJsonSize -lt 10485760 -and $RuntimeConfigJsonOffset + $RuntimeConfigJsonSize -le $Stream.Length) {
          $RuntimeConfigJson = [Text.Encoding]::UTF8.GetString((Read-BinaryBytes -Stream $Stream -Offset $RuntimeConfigJsonOffset -Count ([int]$RuntimeConfigJsonSize)))
        }

        $Entries = Read-PEDotNetBundleEntryInfo -Stream $Stream -HeaderOffset $HeaderOffset
        $BundleHeaders.Add([pscustomobject]@{
            HeaderOffset            = $HeaderOffset
            SignatureOffset         = $SignatureOffset
            MajorVersion            = $MajorVersion
            MinorVersion            = $MinorVersion
            EmbeddedFileCount       = $EmbeddedFileCount
            BundleId                = $BundleId.Value
            DepsJsonOffset          = $DepsJsonOffset
            DepsJsonSize            = $DepsJsonSize
            RuntimeConfigJsonOffset = $RuntimeConfigJsonOffset
            RuntimeConfigJsonSize   = $RuntimeConfigJsonSize
            RuntimeConfigJson       = $RuntimeConfigJson
            Flags                   = $Flags
            IsNetCoreApp3CompatMode = ($Flags -band 1) -ne 0
            Entries                 = $Entries
          })
      } catch {
        continue
      }
    }
  } finally {
    if ($OwnsStream) { $Stream.Dispose() }
  }

  if ($BundleHeaders.Count -eq 0) { return $null }
  # Prefer the latest valid header in case stale publish artifacts or signatures
  # remain earlier in the native host image.
  @($BundleHeaders | Sort-Object -Property HeaderOffset -Descending | Select-Object -First 1)[0]
}

function Get-PERuntimeConfigPath {
  <#
  .SYNOPSIS
    Find a runtimeconfig sidecar for a PE file
  .PARAMETER Path
    The PE file path
  .PARAMETER RelatedFile
    Related sidecar files
  .PARAMETER AppPath
    The managed app path resolved from apphost binding
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The PE file path')]
    [string]$Path,

    [Parameter(HelpMessage = 'Related sidecar files')]
    [string[]]$RelatedFile = @(),

    [Parameter(HelpMessage = 'The managed app path resolved from apphost binding')]
    [AllowNull()]
    [string]$AppPath
  )

  # A bound managed assembly determines the preferred sidecar basename. The
  # outer host basename remains a fallback for conventional apphost layouts.
  $CandidateBases = [System.Collections.Generic.List[psobject]]::new()
  if (-not [string]::IsNullOrWhiteSpace($AppPath)) {
    try {
      $AppFile = Get-Item -LiteralPath $AppPath -Force -ErrorAction SilentlyContinue
      if ($AppFile) {
        $CandidateBases.Add([pscustomobject]@{
            DirectoryName = $AppFile.DirectoryName
            BaseName      = [System.IO.Path]::GetFileNameWithoutExtension($AppFile.Name)
          })
      }
    } catch {
    }
  }

  $File = Get-Item -LiteralPath $Path -Force
  $CandidateBases.Add([pscustomobject]@{
      DirectoryName = $File.DirectoryName
      BaseName      = [System.IO.Path]::GetFileNameWithoutExtension($File.Name)
    })

  foreach ($CandidateBase in $CandidateBases) {
    $RuntimeConfigName = "$($CandidateBase.BaseName).runtimeconfig.json"
    $AdjacentPath = Join-Path -Path $CandidateBase.DirectoryName -ChildPath $RuntimeConfigName
    if (Test-Path -LiteralPath $AdjacentPath -PathType Leaf) {
      return (Get-Item -LiteralPath $AdjacentPath -Force).FullName
    }
  }

  foreach ($Related in @($RelatedFile | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
    try {
      $RelatedFileInfo = Get-Item -LiteralPath $Related -Force
      foreach ($CandidateBase in $CandidateBases) {
        $RuntimeConfigName = "$($CandidateBase.BaseName).runtimeconfig.json"
        if ($RelatedFileInfo.Name -ieq $RuntimeConfigName) { return $RelatedFileInfo.FullName }
      }
    } catch {
      continue
    }
  }

  return $null
}

function Resolve-PEDotNetAppHostBoundAssemblyPath {
  <#
  .SYNOPSIS
    Resolve an apphost-bound managed DLL path using host-relative rules
  .PARAMETER HostFile
    The apphost file
  .PARAMETER BoundAssemblyRelativePath
    The apphost-bound managed DLL relative path
  .PARAMETER RelatedFile
    Related PE and sidecar files
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The apphost file')]
    [System.IO.FileInfo]$HostFile,

    [Parameter(Mandatory, HelpMessage = 'The apphost-bound managed DLL relative path')]
    [string]$BoundAssemblyRelativePath,

    [Parameter(HelpMessage = 'Related PE and sidecar files')]
    [string[]]$RelatedFile = @()
  )

  # Apphost bindings are application-relative paths. Reject rooted values before
  # resolving adjacent or caller-supplied related files.
  if ([string]::IsNullOrWhiteSpace($BoundAssemblyRelativePath)) { return $null }
  if ([System.IO.Path]::IsPathRooted($BoundAssemblyRelativePath)) { return $null }

  $NormalizedRelativePath = $BoundAssemblyRelativePath -replace '/', [System.IO.Path]::DirectorySeparatorChar
  $CandidatePath = Join-Path -Path $HostFile.DirectoryName -ChildPath $NormalizedRelativePath
  if (Test-Path -LiteralPath $CandidatePath -PathType Leaf) {
    return (Get-Item -LiteralPath $CandidatePath -Force).FullName
  }

  $ComparableRelativePath = ($BoundAssemblyRelativePath -replace '\\', '/').TrimStart('/').ToLowerInvariant()
  foreach ($Related in @($RelatedFile | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
    try {
      $RelatedFileInfo = Get-Item -LiteralPath $Related -Force
      if ($RelatedFileInfo.Name -ieq ([System.IO.Path]::GetFileName($BoundAssemblyRelativePath))) {
        return $RelatedFileInfo.FullName
      }
      $RelatedComparable = ($RelatedFileInfo.FullName -replace '\\', '/').ToLowerInvariant()
      if ($RelatedComparable.EndsWith("/$ComparableRelativePath")) {
        return $RelatedFileInfo.FullName
      }
    } catch {
      continue
    }
  }

  return $null
}

function Get-PEDotNetAppHostBindingCandidate {
  <#
  .SYNOPSIS
    Find candidate apphost-bound DLL strings in a patched apphost image
  .PARAMETER Bytes
    The apphost byte array
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The apphost byte array')]
    [byte[]]$Bytes
  )

  $Candidates = [System.Collections.Generic.List[string]]::new()
  $DllNeedle = [System.Text.Encoding]::ASCII.GetBytes('.dll')
  # Recover only bounded NUL-terminated UTF-8 strings around .dll suffixes. Path
  # syntax checks remove imports and arbitrary binary strings from candidates.
  foreach ($DllOffset in @(Find-PEBytePattern -Bytes $Bytes -Pattern $DllNeedle)) {
    $Start = $DllOffset
    while ($Start -gt 0 -and $Bytes[$Start - 1] -ne 0 -and ($DllOffset - $Start) -lt $Script:DotNetAppHostMaximumBindingLength) {
      $Start--
    }

    $End = $DllOffset + $DllNeedle.Count
    while ($End -lt $Bytes.Count -and $Bytes[$End] -ne 0 -and ($End - $Start) -lt $Script:DotNetAppHostMaximumBindingLength) {
      $End++
    }

    if ($End -le $Start -or $End - $Start -gt $Script:DotNetAppHostMaximumBindingLength) { continue }
    $Candidate = [System.Text.Encoding]::UTF8.GetString($Bytes, $Start, $End - $Start)
    if ($Candidate -notmatch '(?i)\.dll$') { continue }
    if ($Candidate -match '[\x00-\x1F]' -or $Candidate -match '^[A-Za-z]:[\\/]' -or $Candidate.StartsWith('\\')) { continue }
    if ($Candidate -match '[<>:"|?*]') { continue }
    $Candidates.Add($Candidate)
  }

  @($Candidates | Sort-Object -Unique)
}

function Get-PEDotNetAppHostInfo {
  <#
  .SYNOPSIS
    Read .NET apphost binding evidence without executing the host
  .PARAMETER Path
    The PE file path
  .PARAMETER RelatedFile
    Related PE and sidecar files
  .PARAMETER ArchitectureInfo
    Architecture information for the PE file
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The PE file path')]
    [string]$Path,

    [Parameter(HelpMessage = 'Related PE and sidecar files')]
    [string[]]$RelatedFile = @(),

    [Parameter(Mandatory, HelpMessage = 'Architecture information for the PE file')]
    [psobject]$ArchitectureInfo
  )

  $File = Get-Item -LiteralPath $Path -Force
  # Apphost is a native executable. Managed DLLs and oversized binaries use
  # their direct CLR/runtimeconfig evidence instead of a full host scan.
  if ($ArchitectureInfo.FileKind -ne 'Executable' -or $ArchitectureInfo.IsManaged -or $File.Length -gt 536870912) {
    return [pscustomobject]@{
      IsAppHost                   = $false
      IsBound                     = $false
      IsUnboundTemplate           = $false
      BoundAssemblyRelativePath   = $null
      BoundAssemblyPath           = $null
      BoundAssemblyIsManaged      = $false
      CandidateBoundAssemblyPaths = @()
      PlaceholderOffset           = $null
      BundleInfo                  = $null
    }
  }

  $HostStream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    # Inspect the host once for template placeholder, single-file bundle, and
    # patched managed-DLL binding evidence.
    $PlaceholderBytes = [System.Text.Encoding]::UTF8.GetBytes($Script:DotNetAppHostPlaceholder)
    $PlaceholderOffset = @(Find-BinaryPattern -Stream $HostStream -Pattern $PlaceholderBytes -Maximum 1 | Select-Object -First 1)[0]
    $BundleInfo = Get-PEDotNetBundleInfo -Stream $HostStream
    $Candidates = @(Get-PEDotNetAppHostBindingCandidateFromStream -Stream $HostStream)
  } finally { $HostStream.Dispose() }
  $ResolvedCandidates = foreach ($Candidate in $Candidates) {
    $ResolvedPath = Resolve-PEDotNetAppHostBoundAssemblyPath -HostFile $File -BoundAssemblyRelativePath $Candidate -RelatedFile $RelatedFile
    if (-not $ResolvedPath) { continue }
    $ResolvedPEFile = Get-PEFileIfValid -Path $ResolvedPath
    if (-not $ResolvedPEFile) { continue }
    [pscustomobject]@{
      RelativePath = $Candidate
      Path         = $ResolvedPEFile.FullName
      IsManaged    = $null -ne (Get-PEClrHeader -Path $ResolvedPEFile.FullName)
    }
  }
  $ManagedCandidate = @($ResolvedCandidates | Where-Object { $_.IsManaged } | Select-Object -First 1)[0]

  [pscustomobject]@{
    IsAppHost                   = $null -ne $ManagedCandidate -or $null -ne $BundleInfo -or $null -ne $PlaceholderOffset
    IsBound                     = $null -ne $ManagedCandidate
    IsUnboundTemplate           = $null -ne $PlaceholderOffset
    BoundAssemblyRelativePath   = if ($ManagedCandidate) { $ManagedCandidate.RelativePath } else { $null }
    BoundAssemblyPath           = if ($ManagedCandidate) { $ManagedCandidate.Path } else { $null }
    BoundAssemblyIsManaged      = if ($ManagedCandidate) { $ManagedCandidate.IsManaged } else { $false }
    CandidateBoundAssemblyPaths = @($Candidates)
    PlaceholderOffset           = $PlaceholderOffset
    BundleInfo                  = $BundleInfo
  }
}

function Get-PEDotNetBundledRuntimeFile {
  <#
  .SYNOPSIS
    Find .NET runtime marker files that indicate a bundled runtime
  .PARAMETER Path
    The PE file path
  .PARAMETER RelatedFile
    Related sidecar files
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The PE file path')]
    [string]$Path,

    [Parameter(HelpMessage = 'Related sidecar files')]
    [string[]]$RelatedFile = @()
  )

  $File = Get-Item -LiteralPath $Path -Force
  $MarkerPaths = [System.Collections.Generic.List[string]]::new()
  foreach ($MarkerName in $Script:DotNetBundledRuntimeFileNames) {
    $CandidatePath = Join-Path -Path $File.DirectoryName -ChildPath $MarkerName
    if (Test-Path -LiteralPath $CandidatePath -PathType Leaf) {
      $MarkerPaths.Add((Get-Item -LiteralPath $CandidatePath -Force).FullName)
    }
  }

  foreach ($Related in @($RelatedFile | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
    try {
      $RelatedFileInfo = Get-Item -LiteralPath $Related -Force
      if ($RelatedFileInfo.Name -iin $Script:DotNetBundledRuntimeFileNames) {
        $MarkerPaths.Add($RelatedFileInfo.FullName)
      }
    } catch {
      continue
    }
  }

  @($MarkerPaths | Sort-Object -Unique)
}

function Get-PERelatedSameNameManagedDll {
  <#
  .SYNOPSIS
    Find a same-name managed DLL sidecar for a PE apphost
  .PARAMETER Path
    The PE file path
  .PARAMETER RelatedFile
    Related sidecar files
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The PE file path')]
    [string]$Path,

    [Parameter(HelpMessage = 'Related sidecar files')]
    [string[]]$RelatedFile = @()
  )

  $File = Get-Item -LiteralPath $Path -Force
  $DllName = "$([System.IO.Path]::GetFileNameWithoutExtension($File.Name)).dll"
  $AdjacentPath = Join-Path -Path $File.DirectoryName -ChildPath $DllName
  if (Test-Path -LiteralPath $AdjacentPath -PathType Leaf) {
    $Dll = Get-PEFileIfValid -Path $AdjacentPath
    if ($Dll -and (Get-PEClrHeader -Path $Dll.FullName)) { return $Dll.FullName }
  }

  foreach ($Related in @($RelatedFile | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
    try {
      $RelatedFileInfo = Get-Item -LiteralPath $Related -Force
      if ($RelatedFileInfo.Name -ieq $DllName) {
        $Dll = Get-PEFileIfValid -Path $RelatedFileInfo.FullName
        if ($Dll -and (Get-PEClrHeader -Path $Dll.FullName)) { return $Dll.FullName }
      }
    } catch {
      continue
    }
  }

  return $null
}

function Test-PENativeAppHostStringEvidence {
  <#
  .SYNOPSIS
    Check bounded strings for .NET apphost-related markers
  .PARAMETER Path
    The PE file path
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The PE file path')]
    [string]$Path
  )

  $File = Get-Item -LiteralPath $Path -Force
  if ($File.Length -gt 268435456) { return $false }

  $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    foreach ($Marker in @('hostfxr', '.runtimeconfig.json')) {
      if (@(Find-BinaryPattern -Stream $Stream -Pattern ([Text.Encoding]::ASCII.GetBytes($Marker)) -Maximum 1).Count) { return $true }
      if (@(Find-BinaryPattern -Stream $Stream -Pattern ([Text.Encoding]::Unicode.GetBytes($Marker)) -Maximum 1).Count) { return $true }
    }
    return $false
  } finally { $Stream.Dispose() }
}

function ConvertFrom-PERuntimeConfigFramework {
  <#
  .SYNOPSIS
    Convert runtimeconfig framework entries to dependency evidence
  .PARAMETER Framework
    A runtimeconfig framework object
  .PARAMETER Included
    Indicates whether the framework was listed in includedFrameworks
  .PARAMETER Warnings
    A list that receives warnings
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'A runtimeconfig framework object')]
    [psobject]$Framework,

    [Parameter(HelpMessage = 'Indicates whether the framework was listed in includedFrameworks')]
    [switch]$Included,

    [Parameter(Mandatory, HelpMessage = 'A list that receives warnings')]
    [AllowEmptyCollection()]
    [System.Collections.Generic.List[string]]$Warnings
  )

  $Name = [string]$Framework.name
  $Version = [string]$Framework.version
  $Major = $null
  if ($Version -match '^(?<Major>\d+)') {
    $Major = [int]$Matches.Major
  }

  # Map only framework names and major versions represented by public WinGet
  # runtime packages; retain unsupported entries as explicit review warnings.
  $PackagePrefix = $Script:DotNetRuntimeFrameworkPackageMap[$Name]
  $PackageIdentifier = if ($PackagePrefix -and $Major -in $Script:DotNetSupportedDependencyMajors) { "$PackagePrefix.$Major" } else { $null }
  if (-not $PackagePrefix) {
    $Warnings.Add("Unknown .NET runtimeconfig framework '$Name' was found; dependency mapping requires manual review.")
  } elseif ($Major -notin $Script:DotNetSupportedDependencyMajors) {
    $Warnings.Add("Runtimeconfig framework '$Name' version '$Version' is outside the supported Microsoft.DotNet dependency majors 5-10.")
  }

  [pscustomobject]@{
    Name              = $Name
    Version           = $Version
    MajorVersion      = $Major
    IsIncluded        = $Included.IsPresent
    PackageIdentifier = $PackageIdentifier
    MinimumVersion    = if ($Version) { $Version } else { $null }
  }
}

function Get-PEDotNetRuntimeInfo {
  <#
  .SYNOPSIS
    Read static .NET runtime dependency evidence for a PE file
  .PARAMETER Path
    The PE file path
  .PARAMETER RelatedFile
    Related PE and sidecar files
  .PARAMETER ArchitectureInfo
    Architecture information for the PE file
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The PE file path')]
    [string]$Path,

    [Parameter(HelpMessage = 'Related PE and sidecar files')]
    [string[]]$RelatedFile = @(),

    [Parameter(Mandatory, HelpMessage = 'Architecture information for the PE file')]
    [psobject]$ArchitectureInfo
  )

  $Warnings = [System.Collections.Generic.List[string]]::new()
  $File = Get-Item -LiteralPath $Path -Force
  # Runtimeconfig is authoritative whether adjacent to a bound app DLL, beside
  # the host, or embedded in a validated single-file bundle.
  $AppHostInfo = Get-PEDotNetAppHostInfo -Path $File.FullName -RelatedFile $RelatedFile -ArchitectureInfo $ArchitectureInfo
  $RuntimeConfigPath = Get-PERuntimeConfigPath -Path $File.FullName -RelatedFile $RelatedFile -AppPath $AppHostInfo.BoundAssemblyPath
  $RuntimeConfig = if ($RuntimeConfigPath) {
    try {
      Read-PERuntimeConfig -Path $RuntimeConfigPath
    } catch {
      $Warnings.Add("Failed to parse .NET runtimeconfig '$RuntimeConfigPath': $($_.Exception.Message)")
      $null
    }
  } else {
    $null
  }
  if (-not $RuntimeConfig -and $AppHostInfo.BundleInfo -and -not [string]::IsNullOrWhiteSpace($AppHostInfo.BundleInfo.RuntimeConfigJson)) {
    try {
      $RuntimeConfig = [pscustomobject]@{
        Path = "bundle:$($File.FullName)"
        Json = $AppHostInfo.BundleInfo.RuntimeConfigJson | ConvertFrom-Json
      }
    } catch {
      $Warnings.Add("Failed to parse embedded .NET bundle runtimeconfig in '$($File.FullName)': $($_.Exception.Message)")
    }
  }
  $BundledRuntimeFiles = @(Get-PEDotNetBundledRuntimeFile -Path $File.FullName -RelatedFile $RelatedFile)
  $SameNameManagedDll = Get-PERelatedSameNameManagedDll -Path $File.FullName -RelatedFile $RelatedFile
  $HasAppHostStringEvidence = if (-not $ArchitectureInfo.IsManaged -and $ArchitectureInfo.FileKind -eq 'Executable') { Test-PENativeAppHostStringEvidence -Path $File.FullName } else { $false }
  $IsDotNetAppHost = (-not $ArchitectureInfo.IsManaged -and $ArchitectureInfo.FileKind -eq 'Executable' -and ($AppHostInfo.IsBound -or $AppHostInfo.BundleInfo -or ($RuntimeConfig -and ($SameNameManagedDll -or $HasAppHostStringEvidence))))

  $Frameworks = [System.Collections.Generic.List[psobject]]::new()
  $IncludedFrameworks = [System.Collections.Generic.List[psobject]]::new()
  if ($RuntimeConfig -and $RuntimeConfig.Json.runtimeOptions) {
    foreach ($Framework in @($RuntimeConfig.Json.runtimeOptions.framework)) {
      if ($Framework) { $Frameworks.Add((ConvertFrom-PERuntimeConfigFramework -Framework $Framework -Warnings $Warnings)) }
    }
    foreach ($Framework in @($RuntimeConfig.Json.runtimeOptions.frameworks)) {
      if ($Framework) { $Frameworks.Add((ConvertFrom-PERuntimeConfigFramework -Framework $Framework -Warnings $Warnings)) }
    }
    foreach ($Framework in @($RuntimeConfig.Json.runtimeOptions.includedFrameworks)) {
      if ($Framework) { $IncludedFrameworks.Add((ConvertFrom-PERuntimeConfigFramework -Framework $Framework -Included -Warnings $Warnings)) }
    }
  }

  # includedFrameworks and core host/runtime files prove self-contained output;
  # recommending a shared runtime in that case would be redundant.
  $IsRuntimeBundled = $BundledRuntimeFiles.Count -gt 0 -or $IncludedFrameworks.Count -gt 0
  $DependencyCandidates = if ($IsRuntimeBundled) { @() } else { @($Frameworks | Where-Object { $_.PackageIdentifier }) }
  # Desktop and ASP.NET runtime packages include the base runtime of the same
  # major, so suppress the weaker Microsoft.NETCore.App recommendation.
  $SpecificMajorVersions = @($DependencyCandidates | Where-Object { $_.Name -in @('Microsoft.WindowsDesktop.App', 'Microsoft.AspNetCore.App') } | Select-Object -ExpandProperty MajorVersion -Unique)
  $DependencyCandidates = @($DependencyCandidates | Where-Object {
      -not ($_.Name -eq 'Microsoft.NETCore.App' -and $_.MajorVersion -in $SpecificMajorVersions)
    })

  $DependencyGroups = @($DependencyCandidates | Group-Object -Property PackageIdentifier)
  $RecommendedDependencies = foreach ($Group in $DependencyGroups) {
    $VersionRecords = @($Group.Group | Where-Object { $_.MinimumVersion } | ForEach-Object -Process {
        $RawVersion = [string]$_.MinimumVersion
        $ComparableVersion = $null
        try {
          $ComparableVersion = [version](($RawVersion -split '-', 2)[0])
        } catch {
          $ComparableVersion = $null
        }
        [pscustomobject]@{
          Raw        = $RawVersion
          Comparable = $ComparableVersion
        }
      })
    $ComparableVersions = @($VersionRecords | Where-Object { $_.Comparable })
    $MinimumVersion = if ($ComparableVersions.Count -gt 0) {
      @($ComparableVersions | Sort-Object -Property Comparable -Descending | Select-Object -First 1)[0].Raw
    } elseif ($VersionRecords.Count -gt 0) {
      @($VersionRecords | Sort-Object -Property Raw -Descending | Select-Object -First 1)[0].Raw
    } else {
      $null
    }
    if ($MinimumVersion) {
      [pscustomobject]@{ PackageIdentifier = $Group.Name; MinimumVersion = $MinimumVersion }
    } else {
      [pscustomobject]@{ PackageIdentifier = $Group.Name }
    }
  }

  if (-not $RuntimeConfig -and $ArchitectureInfo.IsManaged -and $ArchitectureInfo.FileKind -eq 'Dll' -and $ArchitectureInfo.TargetFramework -and $ArchitectureInfo.TargetFramework.FrameworkName -eq '.NETCoreApp' -and $ArchitectureInfo.TargetFramework.VersionObject.Major -ge 5) {
    $Warnings.Add("Managed .NET $($ArchitectureInfo.TargetFramework.Version) DLL has no runtimeconfig sidecar; inspect the application host/runtimeconfig before adding .NET runtime dependencies.")
  }

  [pscustomobject]@{
    Path                            = $File.FullName
    RuntimeConfigPath               = if ($RuntimeConfig) { $RuntimeConfig.Path } else { $null }
    HasRuntimeConfig                = $null -ne $RuntimeConfig
    IsDotNetAppHost                 = [bool]$IsDotNetAppHost
    AppHostInfo                     = $AppHostInfo
    BoundAssemblyPath               = $AppHostInfo.BoundAssemblyPath
    BoundAssemblyRelativePath       = $AppHostInfo.BoundAssemblyRelativePath
    SameNameManagedDll              = $SameNameManagedDll
    HasAppHostStringEvidence        = [bool]$HasAppHostStringEvidence
    IsRuntimeBundled                = [bool]$IsRuntimeBundled
    BundledRuntimeFiles             = $BundledRuntimeFiles
    Frameworks                      = @($Frameworks)
    IncludedFrameworks              = @($IncludedFrameworks)
    RecommendedPackageDependencies  = @($RecommendedDependencies | Sort-Object -Property PackageIdentifier)
    RecommendedPackageDependencyIds = @($RecommendedDependencies | Select-Object -ExpandProperty PackageIdentifier | Sort-Object -Unique)
    Diagnostics                     = @(ConvertTo-InstallerDiagnostic -InputObject @($Warnings) -Source 'PEDependency' -Kind Incomplete -Areas Metadata -AffectedFields Dependencies)
  }
}

function Get-PEDependencyInfo {
  <#
  .SYNOPSIS
    Statically detect PE runtime dependency evidence
  .DESCRIPTION
    The function reads direct and delay-import DLL names without executing the binary,
    maps known Visual C++ runtime imports to WinGet package dependency identifiers,
    reports Universal C Runtime imports separately, and reads .NET runtimeconfig sidecars.
  .PARAMETER Path
    The PE file path
  .PARAMETER RelatedFile
    Related PE files and sidecar files to inspect with the PE file
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The PE file path')]
    [string]$Path,

    [Parameter(HelpMessage = 'Related PE files and sidecar files to inspect with the PE file')]
    [string[]]$RelatedFile = @()
  )

  process {
    $PrimaryFile = Get-Item -LiteralPath $Path -Force
    $InputFiles = @($Path) + @($RelatedFile)
    $Files = @($InputFiles | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object -Process { (Get-Item -LiteralPath $_ -Force).FullName } | Sort-Object -Unique)
    # Sidecar JSON stays in CheckedFiles but only validated PE files participate
    # in import and architecture analysis.
    $PEFiles = @($Files | ForEach-Object -Process {
        $PEFile = Get-PEFileIfValid -Path $_
        if ($PEFile) { $PEFile.FullName }
      } | Sort-Object -Unique)
    $Warnings = [System.Collections.Generic.List[string]]::new()
    $AllImports = [System.Collections.Generic.List[psobject]]::new()
    $VCRedistImports = [System.Collections.Generic.List[psobject]]::new()
    $UcrtImports = [System.Collections.Generic.List[psobject]]::new()
    $RelatedPEFiles = @($RelatedFile | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object -Process {
        $RelatedPEFile = Get-PEFileIfValid -Path $_
        if ($RelatedPEFile) { $RelatedPEFile.FullName }
      } | Sort-Object -Unique)
    $PrimaryArchitectureInfo = Get-PEArchitectureInfo -Path $PrimaryFile.FullName -RelatedFile $RelatedPEFiles
    $DotNetInfo = Get-PEDotNetRuntimeInfo -Path $PrimaryFile.FullName -RelatedFile $RelatedFile -ArchitectureInfo $PrimaryArchitectureInfo

    foreach ($FilePath in $PEFiles) {
      $ArchitectureInfo = Get-PEArchitectureInfo -Path $FilePath
      $FileArchitectures = @($ArchitectureInfo.RecommendedWinGetArchitectures)
      if ($FileArchitectures.Count -eq 0) {
        $Warnings.Add("Could not determine concrete architecture for $FilePath; VCRedist package mapping may be incomplete.")
      }

      # Direct and delay imports are equivalent dependency evidence, but retain
      # their source directory so authors can inspect why a mapping was made.
      $Imports = @(
        Get-PEImportedDll -Path $FilePath
        Get-PEDelayImportedDll -Path $FilePath
      )

      foreach ($Import in $Imports) {
        $ImportRecord = [pscustomobject]@{
          Path      = $FilePath
          Directory = $Import.Directory
          DllName   = $Import.DllName
        }
        $AllImports.Add($ImportRecord)

        # Runtime DLL names map to a VC generation; concrete PE architecture then
        # selects the corresponding WinGet redistributable package identifier.
        $RuntimeVersion = Resolve-PortableVCRedistRuntime -DllName $Import.DllName
        if ($RuntimeVersion) {
          foreach ($Architecture in $FileArchitectures) {
            $PackageIdentifier = Get-PortableVCRedistPackageIdentifier -RuntimeVersion $RuntimeVersion -Architecture $Architecture
            if ($PackageIdentifier) {
              $VCRedistImports.Add([pscustomobject]@{
                  Path              = $FilePath
                  Directory         = $Import.Directory
                  DllName           = $Import.DllName
                  RuntimeVersion    = $RuntimeVersion
                  Architecture      = $Architecture
                  PackageIdentifier = $PackageIdentifier
                })
            } else {
              $Warnings.Add("Import '$($Import.DllName)' maps to VC++ $RuntimeVersion, but no Microsoft.VCRedist.$RuntimeVersion.$Architecture package is available.")
            }
          }
          continue
        }

        if (Test-PortableUcrtImport -DllName $Import.DllName) {
          $UcrtImports.Add([pscustomobject]@{
              Path      = $FilePath
              Directory = $Import.Directory
              DllName   = $Import.DllName
            })
        }
      }
    }

    $VCRedistPackageIds = @($VCRedistImports | Select-Object -ExpandProperty PackageIdentifier -Unique | Sort-Object)
    $DotNetPackageIds = @($DotNetInfo.RecommendedPackageDependencyIds)
    $PackageIds = @($VCRedistPackageIds + $DotNetPackageIds | Sort-Object -Unique)
    $RecommendedDependencies = [System.Collections.Generic.List[psobject]]::new()
    foreach ($PackageId in $VCRedistPackageIds) {
      $RecommendedDependencies.Add([pscustomobject]@{ PackageIdentifier = $PackageId })
    }
    foreach ($Dependency in @($DotNetInfo.RecommendedPackageDependencies)) {
      $RecommendedDependencies.Add($Dependency)
    }

    [pscustomobject]@{
      Path                            = $PrimaryFile.FullName
      CheckedFiles                    = $Files
      CheckedPEFiles                  = $PEFiles
      ImportedDlls                    = @($AllImports)
      DependsOnVCRedist               = $VCRedistImports.Count -gt 0
      DependsOnUcrt                   = $UcrtImports.Count -gt 0
      DependsOnVisualCRuntime         = $VCRedistImports.Count -gt 0 -or $UcrtImports.Count -gt 0
      DependsOnDotNetRuntime          = $DotNetInfo.RecommendedPackageDependencyIds.Count -gt 0
      VCRedistImports                 = @($VCRedistImports)
      UcrtImports                     = @($UcrtImports)
      DotNetInfo                      = $DotNetInfo
      RecommendedPackageDependencyIds = $PackageIds
      RecommendedPackageDependencies  = @($RecommendedDependencies | Sort-Object -Property PackageIdentifier)
      Diagnostics                     = @(
        Merge-InstallerDiagnostics -Diagnostic @(
          @(ConvertTo-InstallerDiagnostic -InputObject @($Warnings) -Source 'PEDependency' -Kind Incomplete -Areas Metadata -AffectedFields Dependencies)
          $DotNetInfo.Diagnostics
          $PrimaryArchitectureInfo.Diagnostics
        )
      )
    }
  }
}

function Test-PEVCRedistDependency {
  <#
  .SYNOPSIS
    Test whether a PE file imports Visual C++ runtime DLLs
  .PARAMETER Path
    The PE file path
  .PARAMETER RelatedFile
    Related PE files to inspect with the PE file
  #>
  [OutputType([bool])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The PE file path')]
    [string]$Path,

    [Parameter(HelpMessage = 'Related PE files to inspect with the PE file')]
    [string[]]$RelatedFile = @()
  )

  process {
    (Get-PEDependencyInfo -Path $Path -RelatedFile $RelatedFile).DependsOnVCRedist
  }
}

Export-ModuleMember -Function Resolve-PortableVCRedistRuntime, Test-PortableUcrtImport, Get-PortableVCRedistPackageIdentifier, Get-PEDotNetAppHostBindingCandidateFromStream, Get-PEDotNetBundleInfo, Get-PEDependencyInfo, Test-PEVCRedistDependency
