# SPDX-License-Identifier: Apache-2.0
# Format sources:
# - https://github.com/wixtoolset/wix/blob/main/src/wix/WixToolset.Core.Burn/Bundles/BurnCommon.cs
# - https://github.com/wixtoolset/wix/blob/main/src/wix/WixToolset.Core.Burn/Bundles/BurnReader.cs
# - https://github.com/wixtoolset/wix/blob/main/src/wix/WixToolset.Core.Burn/CommandLine/ExtractSubcommand.cs
# Burn binary structure consumed here (section-relative, little-endian integers):
#
#   PE bundle
#   +-- .wixburn
#   |   Offset  Size  Field
#   |   0x00       4  Magic: 00 43 F1 00 (uint32 0x00F14300)
#   |   0x04       4  Format version (2)
#   |   0x08      16  Bundle GUID
#   |   0x18       4  StubSize -> absolute UX CAB offset
#   |   0x1C      12  original checksum/signature metadata
#   |   0x28       4  container format (1 = CAB)
#   |   0x2C       4  container count, including UX
#   |   0x30     4*N  UX size followed by attached-container sizes
#   +-- [StubSize, StubSize + UXSize) UX CAB
#   |   +-- entry "0" -> UX\manifest.xml
#   |   `-- u* entries -> UX\<Payload.FilePath>
#   +-- optional padding and original engine signature -> EngineSize
#   +-- [EngineSize, ...] attached CAB slots in header order
#   |   `-- a* entries -> <Container.Id>\<Payload.FilePath>
#   `-- optional current Authenticode signature after attached containers
#
# Every CAB is exposed through an exact declared range. BurnManifest XML maps
# opaque CAB source IDs to logical output paths and identifies detached/external
# payloads whose bytes are not present in the bundle.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# Force stop on error
$ErrorActionPreference = 'Stop'

function Get-Assembly {
  <#
  .SYNOPSIS
    Get the Microsoft.Deployment.Compression.Cab.dll assembly
  #>
  [OutputType([string])]
  param ()

  if (Test-Path -Path ($Path = Join-Path $PSScriptRoot '..' '..' 'Assets' 'Assemblies' 'Microsoft.Deployment.Compression.Cab.dll')) {
    return (Get-Item -Path $Path -Force)
  } else {
    throw 'The Microsoft.Deployment.Compression.Cab.dll assembly could not be found'
  }
}

function Import-Assembly {
  <#
  .SYNOPSIS
    Load the Microsoft.Deployment.Compression.Cab.dll assembly
  #>

  Import-CabinetDependency
}

Import-Assembly

# .wixburn field offsets are relative to the section's raw file range.
$BURN_SECTION_OFFSET_MAGIC = 0
$BURN_SECTION_OFFSET_VERSION = 4
$BURN_SECTION_OFFSET_BUNDLEGUID = 8
$BURN_SECTION_OFFSET_STUBSIZE = 24
$BURN_SECTION_OFFSET_ORIGINALCHECKSUM = 28
$BURN_SECTION_OFFSET_ORIGINALSIGNATUREOFFSET = 32
$BURN_SECTION_OFFSET_ORIGINALSIGNATURESIZE = 36
$BURN_SECTION_OFFSET_FORMAT = 40
$BURN_SECTION_OFFSET_COUNT = 44
$BURN_SECTION_OFFSET_UXSIZE = 48
$BURN_SECTION_MIN_SIZE = 52
$BURN_SECTION_MAGIC = 0x00f14300
$BURN_SECTION_VERSION = 0x00000002
$BURN_MAXIMUM_CONTAINER_COUNT = 65536
$BURN_MAXIMUM_CABINET_ENTRIES = 65536

function Get-BurnEngineInfo {
  <#
  .SYNOPSIS
    Get the engine header layout from a WiX bundle file
  .DESCRIPTION
    Read the .wixburn section header: bundle code, format version, stub size,
    signature boundary, container layout, and engine size.
  .PARAMETER Path
    The path to the WiX bundle file
  .PARAMETER Stream
    The binary stream of the WiX bundle file
  .LINK
    https://github.com/wixtoolset/wix/blob/main/src/wix/WixToolset.Core.Burn/Bundles/BurnCommon.cs
  #>
  [CmdletBinding()]
  param(
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the WiX bundle file')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Stream', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The binary stream of the WiX bundle file')]
    [System.IO.Stream]$Stream
  )

  process {
    $OwnsStream = $PSCmdlet.ParameterSetName -eq 'Path'
    if ($OwnsStream) {
      $Path = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
      $Stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    }
    if (-not $Stream.CanRead -or -not $Stream.CanSeek) { throw 'Burn parsing requires a readable, seekable stream.' }
    $OriginalPosition = $Stream.Position

    try {
      # Shared PE parsing validates DOS/NT headers, section ranges, and the
      # current Authenticode certificate directory without duplicating PE code.
      $PELayout = Get-PELayout -Stream $Stream
      if (-not $PELayout) { throw 'The file is not a valid PE image.' }
      $WixBurnSections = @($PELayout.Sections | Where-Object Name -CEQ '.wixburn')
      if ($WixBurnSections.Count -ne 1) { throw 'Missing or ambiguous .wixburn section. Not a valid WiX Burn installer.' }
      $WixBurnSection = $WixBurnSections[0]
      [long]$WixBurnDataOffset = $WixBurnSection.RawOffset
      [long]$WixBurnRawDataSize = $WixBurnSection.RawSize
      if ($WixBurnRawDataSize -lt $Script:BURN_SECTION_MIN_SIZE) { throw '.wixburn section too small. Invalid installer.' }
      if ($WixBurnDataOffset -lt 0 -or $WixBurnRawDataSize -gt $Stream.Length - $WixBurnDataOffset) { throw '.wixburn section range is outside the installer.' }

      # Read only the fixed prefix first. The declared count then determines the
      # exact number of uint32 size records needed from the section.
      $WixBurnPrefix = Read-BinaryBytes -Stream $Stream -Offset $WixBurnDataOffset -Count $Script:BURN_SECTION_MIN_SIZE
      $Magic = [BitConverter]::ToUInt32($WixBurnPrefix, $Script:BURN_SECTION_OFFSET_MAGIC)
      if ($Magic -ne $Script:BURN_SECTION_MAGIC) { throw 'Invalid WiX Burn magic number.' }
      $Version = [BitConverter]::ToUInt32($WixBurnPrefix, $Script:BURN_SECTION_OFFSET_VERSION)
      if ($Version -ne $Script:BURN_SECTION_VERSION) { throw "Unsupported WiX Burn section version: $Version" }
      $Format = [BitConverter]::ToUInt32($WixBurnPrefix, $Script:BURN_SECTION_OFFSET_FORMAT)
      if ($Format -ne 1) { throw "Unknown Burn container format: $Format" }
      [uint32]$ContainerCount = [BitConverter]::ToUInt32($WixBurnPrefix, $Script:BURN_SECTION_OFFSET_COUNT)
      [long]$MaximumSectionContainers = [Math]::Floor(($WixBurnRawDataSize - $Script:BURN_SECTION_OFFSET_UXSIZE) / 4)
      if ($ContainerCount -gt $MaximumSectionContainers -or $ContainerCount -gt $Script:BURN_MAXIMUM_CONTAINER_COUNT) { throw 'The Burn container count exceeds the section or parser limit.' }
      [int]$BurnHeaderSize = $Script:BURN_SECTION_OFFSET_UXSIZE + ([int]$ContainerCount * 4)
      $WixBurnBytes = Read-BinaryBytes -Stream $Stream -Offset $WixBurnDataOffset -Count $BurnHeaderSize

      $BundleGuidBytes = [byte[]]::new(16)
      [Array]::Copy($WixBurnBytes, $Script:BURN_SECTION_OFFSET_BUNDLEGUID, $BundleGuidBytes, 0, $BundleGuidBytes.Length)
      $BundleCode = [Guid]::new($BundleGuidBytes)
      [long]$StubSize = [BitConverter]::ToUInt32($WixBurnBytes, $Script:BURN_SECTION_OFFSET_STUBSIZE)
      $OriginalChecksum = [BitConverter]::ToUInt32($WixBurnBytes, $Script:BURN_SECTION_OFFSET_ORIGINALCHECKSUM)
      [long]$OriginalSignatureOffset = [BitConverter]::ToUInt32($WixBurnBytes, $Script:BURN_SECTION_OFFSET_ORIGINALSIGNATUREOFFSET)
      [long]$OriginalSignatureSize = [BitConverter]::ToUInt32($WixBurnBytes, $Script:BURN_SECTION_OFFSET_ORIGINALSIGNATURESIZE)
      if ($StubSize -le 0 -or $StubSize -gt $Stream.Length) { throw 'The Burn stub size is outside the installer.' }

      $CertificateDirectory = $PELayout.DataDirectories['Certificate']
      [long]$CurrentSignatureOffset = if ($CertificateDirectory -and $CertificateDirectory.Size -gt 0 -and $CertificateDirectory.Offset -ge 0) { $CertificateDirectory.Offset } else { 0 }
      [long]$CurrentSignatureSize = if ($CurrentSignatureOffset -gt 0) { $CertificateDirectory.Size } else { 0 }
      if ($CurrentSignatureOffset -gt 0 -and $CurrentSignatureSize -gt $Stream.Length - $CurrentSignatureOffset) { throw 'The current Authenticode signature range is outside the installer.' }

      $ContainerSizes = [Collections.Generic.List[long]]::new([int]$ContainerCount)
      for ($Index = 0; $Index -lt $ContainerCount; $Index++) {
        [long]$Size = [BitConverter]::ToUInt32($WixBurnBytes, $Script:BURN_SECTION_OFFSET_UXSIZE + ($Index * 4))
        if ($Size -le 0) { throw "Burn container $Index has an invalid size." }
        $ContainerSizes.Add($Size)
      }
      [long]$UXSize = $ContainerCount -gt 0 ? $ContainerSizes[0] : 0
      if ($UXSize -gt $Stream.Length - $StubSize) { throw 'The Burn UX container range is outside the installer.' }
      [long]$UXEnd = $StubSize + $UXSize
      if ($CurrentSignatureOffset -gt 0 -and $CurrentSignatureOffset -lt $UXEnd) { throw 'The current Authenticode signature overlaps the Burn UX container.' }

      # Match WiX BurnCommon: attached containers begin after the preserved
      # original engine signature, or after the current signature for a
      # UX-only bundle, otherwise immediately after the UX cabinet.
      [long]$EngineSize = if ($OriginalSignatureOffset -gt 0) {
        if ($OriginalSignatureOffset -lt $UXEnd) { throw 'The original Burn signature overlaps the UX container.' }
        if ($OriginalSignatureSize -gt $Stream.Length - $OriginalSignatureOffset) { throw 'The original Burn signature range is outside the installer.' }
        $OriginalSignatureOffset + $OriginalSignatureSize
      } elseif ($CurrentSignatureOffset -gt 0 -and $ContainerCount -lt 2) {
        $CurrentSignatureOffset + $CurrentSignatureSize
      } else {
        $UXEnd
      }
      if ($EngineSize -lt $UXEnd -or $EngineSize -gt $Stream.Length) { throw 'The Burn engine boundary is inconsistent with the UX container.' }

      $Containers = [Collections.Generic.List[object]]::new([int]$ContainerCount)
      [long]$AttachedOffset = $EngineSize
      for ($Index = 0; $Index -lt $ContainerCount; $Index++) {
        [long]$Offset = $Index -eq 0 ? $StubSize : $AttachedOffset
        [long]$Size = $ContainerSizes[$Index]
        if ($Size -gt $Stream.Length - $Offset) { throw "Burn container $Index extends beyond the installer." }
        $Containers.Add([pscustomobject][ordered]@{
            Index  = $Index
            Kind   = $Index -eq 0 ? 'UX' : 'Attached'
            Offset = $Offset
            Size   = $Size
          })
        if ($Index -gt 0) { $AttachedOffset += $Size }
      }
      if ($CurrentSignatureOffset -gt 0 -and $ContainerCount -gt 1 -and $AttachedOffset -gt $CurrentSignatureOffset) { throw 'The attached Burn containers overlap the current Authenticode signature.' }

      [pscustomobject][ordered]@{
        Path                    = $Path
        MachineType             = $PELayout.Machine
        BundleCode              = $BundleCode
        Version                 = $Version
        StubSize                = $StubSize
        UXAddress               = $StubSize
        UXSize                  = $UXSize
        OriginalChecksum        = $OriginalChecksum
        OriginalSignatureOffset = $OriginalSignatureOffset
        OriginalSignatureSize   = $OriginalSignatureSize
        CurrentSignatureOffset  = $CurrentSignatureOffset
        CurrentSignatureSize    = $CurrentSignatureSize
        ContainerCount          = $ContainerCount
        AttachedContainers      = $Containers.ToArray()
        EngineSize              = $EngineSize
        WixburnRawDataSize      = $WixBurnRawDataSize
        WixburnDataOffset       = $WixBurnDataOffset
      }
    } finally {
      if ($OwnsStream) {
        $Stream.Dispose()
      } else {
        $null = $Stream.Seek($OriginalPosition, [IO.SeekOrigin]::Begin)
      }
    }
  }
}

function Get-BurnStub {
  <#
  .SYNOPSIS
    Extract the Burn stub (embedded CAB) from a WiX bundle file and return its path
  .PARAMETER Path
    The path to the WiX bundle file
  .PARAMETER Stream
    The binary stream of the WiX bundle file
  #>
  [OutputType([string])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the WiX bundle file')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Stream', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The binary stream of the WiX bundle file')]
    [System.IO.Stream]$Stream
  )

  process {
    $OwnsStream = $PSCmdlet.ParameterSetName -eq 'Path'
    if ($OwnsStream) {
      $Path = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
      $Stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    }
    if (-not $Stream.CanRead -or -not $Stream.CanSeek) { throw 'Burn extraction requires a readable, seekable stream.' }
    $OriginalPosition = $Stream.Position
    $CabPath = [IO.Path]::GetTempFileName()
    $Succeeded = $false

    try {
      $BurnInfo = Get-BurnEngineInfo -Stream $Stream
      if ($BurnInfo.ContainerCount -eq 0) { throw 'The Burn bundle has no UX container.' }
      $UXContainer = $BurnInfo.AttachedContainers[0]
      $CabStream = [IO.File]::Open($CabPath, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
      try {
        # Stream.CopyTo's second argument is a buffer size, not a byte limit.
        # Copy the exact source-declared CAB range through the bounded helper.
        Copy-BinaryStreamRange -Source $Stream -Destination $CabStream -Offset $UXContainer.Offset -Length $UXContainer.Size
      } finally {
        $CabStream.Dispose()
      }
      $Succeeded = $true
      return $CabPath
    } finally {
      if (-not $Succeeded) { Remove-Item -LiteralPath $CabPath -Force -ErrorAction SilentlyContinue }
      if ($OwnsStream) {
        $Stream.Dispose()
      } else {
        $null = $Stream.Seek($OriginalPosition, [IO.SeekOrigin]::Begin)
      }
    }
  }
}

function Get-BurnManifest {
  <#
  .SYNOPSIS
    Get the Burn manifest from a WiX bundle file
  .PARAMETER Path
    The path to the WiX bundle file
  .PARAMETER StubPath
    The path to the extracted Burn stub CAB file
  #>
  [OutputType([xml])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the WiX bundle file')]
    [string]$Path,

    [Parameter(ParameterSetName = 'StubPath', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the extracted Burn stub CAB file')]
    [string]$StubPath
  )

  process {
    $OwnsStub = $PSCmdlet.ParameterSetName -eq 'Path'
    $StubPath = switch ($PSCmdlet.ParameterSetName) {
      'Path' { Get-BurnStub -Path $Path }
      'StubPath' { Resolve-InstallerFileSystemPath -Path $StubPath -PathType Leaf }
      default { throw 'Invalid parameter set.' }
    }
    $ManifestReader = $null
    try {
      # Open entry 0 only after the temporary UX cabinet exists. The finally
      # block removes a path-owned cabinet even when CAB or XML parsing fails.
      $Stub = [Microsoft.Deployment.Compression.Cab.CabInfo]::new($StubPath)
      $ManifestReader = $Stub.OpenText('0')
      [xml]$ManifestReader.ReadToEnd()
    } finally {
      if ($ManifestReader) { $ManifestReader.Dispose() }
      if ($OwnsStub) { Remove-Item -LiteralPath $StubPath -Force -ErrorAction SilentlyContinue }
    }
  }
}

function Export-BurnContainerRange {
  <#
  .SYNOPSIS
    Materialize one exact Burn container range as a temporary cabinet
  .PARAMETER Stream
    Caller-owned, readable, seekable bundle stream. Its position is restored by
    the shared range-copy helper.
  .PARAMETER Container
    Validated Get-BurnEngineInfo container evidence containing Offset and Size.
  .PARAMETER DestinationPath
    Resolved temporary cabinet path to create or replace.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)]$Container,
    [Parameter(Mandatory)][string]$DestinationPath
  )

  $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
  $Output = [IO.File]::Open($DestinationPath, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
  try {
    Copy-BinaryStreamRange -Source $Stream -Destination $Output -Offset $Container.Offset -Length $Container.Size
  } finally {
    $Output.Dispose()
  }
  return $DestinationPath
}

function ConvertTo-BurnExtractionPath {
  <#
  .SYNOPSIS
    Validate and normalize one untrusted Burn manifest or cabinet-relative path
  .PARAMETER Path
    Relative path from Burn XML or a cabinet catalog. Drive, UNC, parent, invalid,
    and Windows reserved-name components are rejected before output reservation.
  .PARAMETER Description
    Human-readable record identity included in malformed-input errors.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Description
  )

  if ([string]::IsNullOrWhiteSpace($Path) -or $Path.IndexOf([char]0) -ge 0) { throw "$Description has an empty or invalid path." }
  $Normalized = $Path.Replace('/', '\')
  if ([IO.Path]::IsPathRooted($Normalized) -or $Normalized -match '^[A-Za-z]:') { throw "$Description has a rooted path: $Path" }
  $InvalidCharacters = [IO.Path]::GetInvalidFileNameChars()
  $Components = $Normalized.Split('\')
  foreach ($Component in $Components) {
    if ([string]::IsNullOrEmpty($Component) -or $Component -in '.', '..') { throw "$Description contains a path traversal or empty segment: $Path" }
    if ($Component.IndexOfAny($InvalidCharacters) -ge 0 -or $Component.EndsWith('.') -or $Component.EndsWith(' ')) {
      throw "$Description contains an invalid Windows path component: $Path"
    }
    if ($Component -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)') {
      throw "$Description contains a reserved Windows path component: $Path"
    }
  }
  return $Components -join '\'
}

function Add-BurnPayloadMapping {
  <#
  .SYNOPSIS
    Add one source-backed Burn payload mapping to a container lookup
  .PARAMETER Map
    Case-insensitive dictionary keyed by normalized CAB source path.
  .PARAMETER SourcePath
    Burn manifest SourcePath naming the physical CAB entry.
  .PARAMETER FilePath
    Burn manifest FilePath projected beneath UX or the authored container ID.
  .PARAMETER FileSize
    Optional Burn manifest uncompressed payload size. Empty values remain unknown.
  #>
  param (
    [Parameter(Mandatory)][Collections.IDictionary]$Map,
    [Parameter(Mandatory)][string]$SourcePath,
    [Parameter(Mandatory)][string]$FilePath,
    [string]$FileSize
  )

  $SourceKey = $SourcePath.Replace('/', '\').TrimStart('\')
  if ([string]::IsNullOrWhiteSpace($SourceKey)) { throw 'A Burn payload has no cabinet SourcePath.' }
  if ([string]::IsNullOrWhiteSpace($FilePath)) { throw "Burn payload '$SourcePath' has no FilePath." }
  $SourceKey = ConvertTo-BurnExtractionPath -Path $SourceKey -Description "Burn payload '$SourcePath' SourcePath"
  $FilePath = ConvertTo-BurnExtractionPath -Path $FilePath -Description "Burn payload '$SourcePath' FilePath"
  [long]$ExpectedSize = -1
  if (-not [string]::IsNullOrWhiteSpace($FileSize) -and (-not [long]::TryParse($FileSize, [ref]$ExpectedSize) -or $ExpectedSize -lt 0)) {
    throw "Burn payload '$SourcePath' has an invalid FileSize."
  }
  if (-not $Map.ContainsKey($SourceKey)) { $Map[$SourceKey] = [Collections.Generic.List[object]]::new() }
  $Map[$SourceKey].Add([pscustomobject][ordered]@{
      FilePath     = $FilePath
      ExpectedSize = $ExpectedSize
    })
}

function Get-BurnExtractionManifestInfo {
  <#
  .SYNOPSIS
    Resolve Burn manifest container slots and logical payload mappings
  .PARAMETER Manifest
    Parsed BurnManifest XML from UX cabinet entry 0.
  .PARAMETER EngineInfo
    Validated physical container ranges from Get-BurnEngineInfo.
  .OUTPUTS
    Container IDs by physical index, UX and attached source maps, and unavailable
    external or detached payload paths.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][xml]$Manifest,
    [Parameter(Mandatory)]$EngineInfo
  )

  $Root = $Manifest.DocumentElement
  if (-not $Root -or $Root.LocalName -ne 'BurnManifest') { throw 'UX cabinet entry 0 is not a BurnManifest document.' }
  [int]$AttachedSlotCount = [Math]::Max(0, [int]$EngineInfo.ContainerCount - 1)
  $ContainerByIndex = [Collections.Generic.Dictionary[int, string]]::new()
  $IndexByContainer = [Collections.Generic.Dictionary[string, int]]::new([StringComparer]::OrdinalIgnoreCase)
  $DetachedContainerIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $UnindexedAttachedIds = [Collections.Generic.List[string]]::new()

  # AttachedIndex is the source-backed relation between a physical .wixburn
  # size slot and an authored Burn container ID. Detached containers have no
  # physical range in the bundle and are retained only as unavailable evidence.
  foreach ($ContainerNode in @($Root.ChildNodes | Where-Object LocalName -EQ 'Container')) {
    $ContainerId = $ContainerNode.GetAttribute('Id')
    if ([string]::IsNullOrWhiteSpace($ContainerId)) { throw 'A Burn Container element has no Id.' }
    $ContainerId = ConvertTo-BurnExtractionPath -Path $ContainerId -Description "Burn container ID '$ContainerId'"
    if ($ContainerId.Contains('\')) { throw "Burn container ID '$ContainerId' is not a single output directory name." }
    $AttachedValue = $ContainerNode.GetAttribute('Attached')
    $AttachedIndexText = $ContainerNode.GetAttribute('AttachedIndex')
    $IsAttached = $AttachedValue -in 'yes', 'true', '1'
    $IsDetached = -not [string]::IsNullOrWhiteSpace($AttachedValue) -and -not $IsAttached

    if (-not [string]::IsNullOrWhiteSpace($AttachedIndexText)) {
      [int]$AttachedIndex = 0
      if (-not [int]::TryParse($AttachedIndexText, [ref]$AttachedIndex) -or $AttachedIndex -lt 1 -or $AttachedIndex -gt $AttachedSlotCount) {
        throw "Burn container '$ContainerId' has an invalid AttachedIndex."
      }
      if ($IsDetached) { throw "Burn container '$ContainerId' is both detached and assigned an AttachedIndex." }
      if ($ContainerByIndex.ContainsKey($AttachedIndex)) { throw "More than one Burn container uses AttachedIndex $AttachedIndex." }
      if ($IndexByContainer.ContainsKey($ContainerId)) { throw "Burn container ID '$ContainerId' is duplicated." }
      $ContainerByIndex.Add($AttachedIndex, $ContainerId)
      $IndexByContainer.Add($ContainerId, $AttachedIndex)

      $FileSizeText = $ContainerNode.GetAttribute('FileSize')
      if (-not [string]::IsNullOrWhiteSpace($FileSizeText)) {
        [long]$DeclaredSize = 0
        if (-not [long]::TryParse($FileSizeText, [ref]$DeclaredSize) -or $DeclaredSize -ne $EngineInfo.AttachedContainers[$AttachedIndex].Size) {
          throw "Burn container '$ContainerId' does not match the size declared by .wixburn."
        }
      }
    } elseif ($IsAttached) {
      $UnindexedAttachedIds.Add($ContainerId)
    } else {
      $null = $DetachedContainerIds.Add($ContainerId)
    }
  }

  if ($AttachedSlotCount -eq 1) {
    if ($ContainerByIndex.ContainsKey(1)) {
      if ($UnindexedAttachedIds.Count -gt 0) { throw 'The single attached Burn slot has additional unindexed container candidates.' }
    } else {
      if ($UnindexedAttachedIds.Count -gt 1) { throw 'The single attached Burn slot has more than one possible container ID.' }
      $ContainerId = $UnindexedAttachedIds.Count -eq 1 ? $UnindexedAttachedIds[0] : 'WixAttachedContainer'
      $ContainerByIndex.Add(1, $ContainerId)
      $IndexByContainer.Add($ContainerId, 1)
    }
  } elseif ($AttachedSlotCount -gt 1) {
    if ($UnindexedAttachedIds.Count -gt 0 -or $ContainerByIndex.Count -ne $AttachedSlotCount) {
      throw 'The Burn manifest does not unambiguously map every attached container slot.'
    }
  } elseif ($UnindexedAttachedIds.Count -gt 0 -or $ContainerByIndex.Count -gt 0) {
    throw 'The Burn manifest describes attached containers that are absent from the bundle.'
  }

  $UXMappings = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
  $UXNodes = @($Root.ChildNodes | Where-Object LocalName -EQ 'UX')
  if ($UXNodes.Count -ne 1) { throw 'The Burn manifest does not contain exactly one UX element.' }
  foreach ($PayloadNode in @($UXNodes[0].ChildNodes | Where-Object LocalName -EQ 'Payload')) {
    Add-BurnPayloadMapping -Map $UXMappings -SourcePath $PayloadNode.GetAttribute('SourcePath') `
      -FilePath $PayloadNode.GetAttribute('FilePath') -FileSize $PayloadNode.GetAttribute('FileSize')
  }

  $AttachedMappings = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
  $UnavailablePaths = [Collections.Generic.List[string]]::new()
  [int]$ExternalPayloadCount = 0
  [int]$DetachedPayloadCount = 0
  foreach ($PayloadNode in @($Root.ChildNodes | Where-Object LocalName -EQ 'Payload')) {
    $Packaging = $PayloadNode.GetAttribute('Packaging')
    $FilePath = $PayloadNode.GetAttribute('FilePath')
    $ContainerId = $PayloadNode.GetAttribute('Container')
    if ($Packaging -ine 'embedded') {
      $ExternalPayloadCount++
      if (-not [string]::IsNullOrWhiteSpace($FilePath)) { $UnavailablePaths.Add($FilePath) }
      continue
    }

    if ([string]::IsNullOrWhiteSpace($ContainerId)) {
      if ($AttachedSlotCount -ne 1) { throw "Embedded Burn payload '$FilePath' has no unambiguous container." }
      $ContainerId = $ContainerByIndex[1]
    }
    if ($DetachedContainerIds.Contains($ContainerId)) {
      $DetachedPayloadCount++
      if (-not [string]::IsNullOrWhiteSpace($FilePath)) { $UnavailablePaths.Add([IO.Path]::Combine($ContainerId, $FilePath)) }
      continue
    }
    if (-not $IndexByContainer.ContainsKey($ContainerId)) { throw "Embedded Burn payload '$FilePath' references unknown container '$ContainerId'." }
    if (-not $AttachedMappings.ContainsKey($ContainerId)) {
      $AttachedMappings[$ContainerId] = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
    }
    Add-BurnPayloadMapping -Map $AttachedMappings[$ContainerId] -SourcePath $PayloadNode.GetAttribute('SourcePath') `
      -FilePath $FilePath -FileSize $PayloadNode.GetAttribute('FileSize')
  }

  return [pscustomobject][ordered]@{
    ContainerByIndex       = $ContainerByIndex
    UXMappings             = $UXMappings
    AttachedMappings       = $AttachedMappings
    DetachedContainerIds   = $DetachedContainerIds
    UnavailablePaths       = $UnavailablePaths.ToArray()
    ExternalPayloadCount   = $ExternalPayloadCount
    DetachedPayloadCount   = $DetachedPayloadCount
    DetachedContainerCount = $DetachedContainerIds.Count
  }
}

function Get-BurnCabinetCatalog {
  <#
  .SYNOPSIS
    Project one physical Burn cabinet catalog into logical WiX extraction paths
  .PARAMETER Path
    Exact temporary cabinet path for one validated Burn container.
  .PARAMETER RootPath
    Logical `UX` or authored container-ID directory beneath the destination.
  .PARAMETER Mapping
    Case-insensitive SourcePath-to-FilePath mapping from BurnManifest XML.
  .PARAMETER ContainerIndex
    Physical .wixburn container slot index used for deterministic ordering.
  .PARAMETER UX
    Treat source entry 0 as UX manifest.xml.
  .PARAMETER MaximumEntries
    Maximum physical records accepted from this cabinet.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$RootPath,
    [Parameter(Mandatory)][Collections.IDictionary]$Mapping,
    [Parameter(Mandatory)][int]$ContainerIndex,
    [switch]$UX,
    [ValidateRange(1, [int]::MaxValue)][int]$MaximumEntries = 65536
  )

  $Entries = @(Get-CabinetEntry -Path $Path -MaximumEntries $MaximumEntries)
  $SeenSources = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $MatchedMappings = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $Catalog = [Collections.Generic.List[object]]::new()
  foreach ($Entry in $Entries) {
    $SourceKey = ConvertTo-BurnExtractionPath -Path $Entry.FullName.Replace('/', '\').TrimStart('\') -Description "Burn cabinet entry '$($Entry.FullName)'"
    if (-not $SeenSources.Add($SourceKey)) { throw "The Burn cabinet contains duplicate source entry '$SourceKey'." }
    if ($UX -and $SourceKey -eq '0') {
      $Catalog.Add([pscustomobject][ordered]@{
          CabinetPath    = $Path
          ContainerIndex = $ContainerIndex
          SourceName     = $Entry.SourceName
          SourcePath     = $SourceKey
          LogicalPath    = [IO.Path]::Combine($RootPath, 'manifest.xml')
          Length         = $Entry.Length
        })
      continue
    }

    if ($Mapping.ContainsKey($SourceKey)) {
      $null = $MatchedMappings.Add($SourceKey)
      foreach ($Target in $Mapping[$SourceKey]) {
        if ($Target.ExpectedSize -ge 0 -and $Target.ExpectedSize -ne $Entry.Length) {
          throw "Burn payload '$SourceKey' does not match its manifest FileSize."
        }
        $Catalog.Add([pscustomobject][ordered]@{
            CabinetPath    = $Path
            ContainerIndex = $ContainerIndex
            SourceName     = $Entry.SourceName
            SourcePath     = $SourceKey
            LogicalPath    = [IO.Path]::Combine($RootPath, $Target.FilePath)
            Length         = $Entry.Length
          })
      }
    } else {
      # WiX extracts every CAB record before applying manifest renames. Retain
      # records absent from the XML under their physical cabinet path.
      $Catalog.Add([pscustomobject][ordered]@{
          CabinetPath    = $Path
          ContainerIndex = $ContainerIndex
          SourceName     = $Entry.SourceName
          SourcePath     = $SourceKey
          LogicalPath    = [IO.Path]::Combine($RootPath, $Entry.FullName)
          Length         = $Entry.Length
        })
    }
  }
  foreach ($SourceKey in $Mapping.Keys) {
    if (-not $MatchedMappings.Contains([string]$SourceKey)) { throw "Burn manifest payload '$SourceKey' is absent from its attached cabinet." }
  }
  return $Catalog.ToArray()
}

function Expand-BurnInstaller {
  <#
  .SYNOPSIS
    Extract embedded WiX Burn payloads using a WiX 7-style directory projection
  .DESCRIPTION
    Writes UX payloads beneath UX and attached payloads beneath their authored
    container IDs. External payloads and detached containers are reported but
    never downloaded. The installer is parsed and copied only as data.
  .PARAMETER Path
    Path to the Burn bundle executable. The path is resolved with PowerShell
    provider semantics before .NET opens it.
  .PARAMETER DestinationPath
    Output directory. A temporary directory is created when omitted.
  .PARAMETER Name
    Optional wildcard matching projected paths, source CAB paths, or leaf names.
    All embedded files are selected when omitted.
  .PARAMETER CollisionAction
    Behavior when a projected path already exists or another payload projects to
    the same path. Prompt asks only after a collision is detected.
  .PARAMETER MaximumExpandedBytes
    Maximum aggregate bytes written across all selected logical outputs.
  #>
  [CmdletBinding()]
  [OutputType([IO.FileInfo[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [string]$Name = '*',
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Prompt',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 17179869184
  )

  process {
    $Path = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
    if ([string]::IsNullOrWhiteSpace($DestinationPath)) { $DestinationPath = New-TempFolder }
    $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
    $TemporaryPath = New-TempFolder
    $BundleStream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
      $EngineInfo = Get-BurnEngineInfo -Stream $BundleStream
      if ($EngineInfo.ContainerCount -eq 0) { throw 'The Burn bundle has no embedded UX container.' }

      # The UX container must be decoded first because entry 0 owns the logical
      # mappings and physical AttachedIndex assignments for every later CAB.
      $CabinetPaths = [Collections.Generic.Dictionary[int, string]]::new()
      $UXCabinetPath = Join-Path $TemporaryPath 'container-00000000.cab'
      $null = Export-BurnContainerRange -Stream $BundleStream -Container $EngineInfo.AttachedContainers[0] -DestinationPath $UXCabinetPath
      $CabinetPaths.Add(0, $UXCabinetPath)
      $Manifest = Get-BurnManifest -StubPath $UXCabinetPath
      $ManifestInfo = Get-BurnExtractionManifestInfo -Manifest $Manifest -EngineInfo $EngineInfo

      $Catalog = [Collections.Generic.List[object]]::new()
      foreach ($Entry in (Get-BurnCabinetCatalog -Path $UXCabinetPath -RootPath 'UX' -Mapping $ManifestInfo.UXMappings `
            -ContainerIndex 0 -UX -MaximumEntries $Script:BURN_MAXIMUM_CABINET_ENTRIES)) {
        $Catalog.Add($Entry)
      }
      if ($Catalog.Count -gt $Script:BURN_MAXIMUM_CABINET_ENTRIES) { throw 'The Burn cabinet catalogs exceed the configured entry limit.' }
      for ($Index = 1; $Index -lt $EngineInfo.ContainerCount; $Index++) {
        $ContainerId = $ManifestInfo.ContainerByIndex[$Index]
        $CabinetPath = Join-Path $TemporaryPath ('container-{0:D8}.cab' -f $Index)
        $null = Export-BurnContainerRange -Stream $BundleStream -Container $EngineInfo.AttachedContainers[$Index] -DestinationPath $CabinetPath
        $CabinetPaths.Add($Index, $CabinetPath)
        $Mapping = $ManifestInfo.AttachedMappings.ContainsKey($ContainerId) ? $ManifestInfo.AttachedMappings[$ContainerId] : [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($Entry in (Get-BurnCabinetCatalog -Path $CabinetPath -RootPath $ContainerId -Mapping $Mapping `
              -ContainerIndex $Index -MaximumEntries $Script:BURN_MAXIMUM_CABINET_ENTRIES)) {
          $Catalog.Add($Entry)
        }
        if ($Catalog.Count -gt $Script:BURN_MAXIMUM_CABINET_ENTRIES) { throw 'The Burn cabinet catalogs exceed the configured entry limit.' }
      }

      # Match both the WiX-projected path and the opaque CAB source path. Leaf
      # matching remains available through Test-ExtractionPattern.
      $MatchingCatalog = [Collections.Generic.List[object]]::new()
      foreach ($Entry in $Catalog) {
        if ((Test-ExtractionPattern -Path $Entry.LogicalPath -Pattern $Name) -or
          (Test-ExtractionPattern -Path $Entry.SourcePath -Pattern $Name)) {
          $MatchingCatalog.Add($Entry)
        }
      }
      if ($MatchingCatalog.Count -eq 0) {
        $UnavailableMatch = @($ManifestInfo.UnavailablePaths | Where-Object { Test-ExtractionPattern -Path $_ -Pattern $Name })
        if ($UnavailableMatch.Count -gt 0) { throw "Burn selector '$Name' matches only external or detached payloads whose bytes are not embedded." }
        throw "No embedded Burn payload matches selector '$Name'."
      }

      # Resolve and reserve every destination before any CAB is decompressed so
      # duplicate manifest FilePath values use the same collision semantics as
      # pre-existing files.
      $ReservedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
      $Selected = [Collections.Generic.List[object]]::new()
      [long]$TotalExpandedBytes = 0
      foreach ($Entry in $MatchingCatalog) {
        $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $Entry.LogicalPath `
          -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
        if (-not $Target.ShouldWrite) { continue }
        if ($Entry.Length -gt $MaximumExpandedBytes - $TotalExpandedBytes) { throw 'The selected Burn payloads exceed the configured output limit.' }
        $TotalExpandedBytes += $Entry.Length
        $Selected.Add([pscustomobject][ordered]@{
            CabinetPath     = $Entry.CabinetPath
            ContainerIndex  = $Entry.ContainerIndex
            SourceName      = $Entry.SourceName
            DestinationPath = $Target.Path
            Length          = $Entry.Length
          })
      }

      # Decode each physical cabinet once. The shared helper deduplicates source
      # entries that intentionally project to several logical aliases.
      foreach ($ContainerIndex in @($Selected.ContainerIndex | Sort-Object -Unique)) {
        $ContainerSelection = @($Selected | Where-Object ContainerIndex -EQ $ContainerIndex)
        if ($ContainerSelection.Count -eq 0) { continue }
        $null = Export-CabinetSelection -Path $CabinetPaths[$ContainerIndex] -Selection $ContainerSelection `
          -MaximumEntries $Script:BURN_MAXIMUM_CABINET_ENTRIES -MaximumExpandedBytes $MaximumExpandedBytes
      }

      if ($ManifestInfo.ExternalPayloadCount -gt 0 -or $ManifestInfo.DetachedContainerCount -gt 0) {
        Write-Warning ('Burn extraction omitted {0} external payload(s) and {1} detached container(s) because their bytes are not embedded.' -f `
            $ManifestInfo.ExternalPayloadCount, $ManifestInfo.DetachedContainerCount)
      }
      $Results = [Collections.Generic.List[IO.FileInfo]]::new($Selected.Count)
      foreach ($Item in $Selected) { $Results.Add((Get-Item -LiteralPath $Item.DestinationPath -Force)) }
      return $Results.ToArray()
    } finally {
      $BundleStream.Dispose()
      Remove-Item -LiteralPath $TemporaryPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }
}

function Get-BurnUXPayload {
  <#
  .SYNOPSIS
    Get the Burn BootstrapperApplicationData from a WiX bundle file
  .PARAMETER Path
    The path to the WiX bundle file
  .PARAMETER StubPath
    The path to the extracted Burn stub CAB file
  .PARAMETER Name
    The name of the UX payload to extract (e.g. BootstrapperApplicationData.xml)
  #>
  [OutputType([Microsoft.Deployment.Compression.Cab.CabFileInfo])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the WiX bundle file')]
    [string]$Path,

    [Parameter(ParameterSetName = 'StubPath', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the extracted Burn stub CAB file')]
    [string]$StubPath,

    [Parameter(Position = 1, HelpMessage = 'The name of the UX payload to extract (e.g. BootstrapperApplicationData.xml)')]
    [string]$Name
  )

  process {
    $StubPath = switch ($PSCmdlet.ParameterSetName) {
      'Path' { Get-BurnStub -Path $Path }
      'StubPath' { (Test-Path -Path $StubPath) ? $StubPath : (throw "The specified Burn stub path '$StubPath' is invalid.") }
      default { throw 'Invalid parameter set.' }
    }
    # BurnManifest maps logical UX FilePath values to cabinet SourcePath entries; use that mapping
    # instead of searching cabinet names heuristically.
    $Manifest = Get-BurnManifest -StubPath $StubPath
    $Stub = [Microsoft.Deployment.Compression.Cab.CabInfo]::new($StubPath)

    $NamespaceManager = [System.Xml.XmlNamespaceManager]::new($Manifest.NameTable)
    $NamespaceManager.AddNamespace('burn', $Manifest.DocumentElement.NamespaceURI)
    if ($Name) {
      $UXPayloads = $Manifest.SelectSingleNode("/burn:BurnManifest/burn:UX/burn:Payload[@FilePath='${Name}']", $NamespaceManager)
      if (-not $UXPayloads) { throw "The UX Payload with the name '${Name}' could not be found." }
    } else {
      $UXPayloads = $Manifest.SelectNodes('/burn:BurnManifest/burn:UX/burn:Payload', $NamespaceManager)
      if (-not $UXPayloads) { throw 'No UX Payloads found in the manifest.' }
    }
    foreach ($UXPayload in $UXPayloads) {
      $UXFileInfo = $Stub.GetFiles($UXPayload.SourcePath)[0]
      Add-Member -InputObject $UXFileInfo -MemberType 'NoteProperty' -Name 'RealName' -Value $UXPayload.FilePath
      Write-Output -InputObject $UXFileInfo
    }
  }
}

function Get-BurnBootstrapperApplicationData {
  <#
  .SYNOPSIS
    Get the Burn BootstrapperApplicationData from a WiX bundle file
  .PARAMETER Path
    The path to the WiX bundle file
  .PARAMETER StubPath
    The path to the extracted Burn stub CAB file
  #>
  [OutputType([xml])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the WiX bundle file')]
    [string]$Path,

    [Parameter(ParameterSetName = 'StubPath', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the extracted Burn stub CAB file')]
    [string]$StubPath
  )

  process {
    $Reader = (Get-BurnUXPayload @PSBoundParameters -Name 'BootstrapperApplicationData.xml').OpenText()
    try {
      [xml]$Reader.ReadToEnd()
    } finally {
      $Reader.Close()
    }
  }
}

function Convert-BurnMachineTypeToArchitecture {
  <#
  .SYNOPSIS
    Convert a PE machine type to a WinGet architecture name
  .PARAMETER MachineType
    The PE machine type value
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The PE machine type value')]
    [int]$MachineType
  )

  switch ($MachineType) {
    0x014C { 'x86' }
    0x8664 { 'x64' }
    0xAA64 { 'arm64' }
    0x01C4 { 'arm' }
    default { "unknown:0x$($MachineType.ToString('X4'))" }
  }
}

function Test-BurnArchitectureCondition {
  <#
  .SYNOPSIS
    Evaluate simple Burn architecture conditions for a Windows architecture
  .PARAMETER Condition
    The Burn condition text
  .PARAMETER Architecture
    The WinGet architecture to test
  #>
  [OutputType([bool])]
  param (
    [AllowNull()]
    [string]$Condition,

    [Parameter(Mandatory, HelpMessage = 'The WinGet architecture to test')]
    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture
  )

  if ([string]::IsNullOrWhiteSpace($Condition)) { return $true }

  $NativeMachine = switch ($Architecture) {
    'x86' { 332 }
    'x64' { 34404 }
    'arm64' { 43620 }
  }
  $Values = @{
    VersionNT64   = $Architecture -in @('x64', 'arm64')
    NativeMachine = $NativeMachine
  }

  # Translate only Burn's common architecture-condition subset into PowerShell operators. Unknown
  # variables are made permissive to avoid incorrectly excluding a supported architecture.
  $Expression = $Condition
  $Expression = [regex]::Replace($Expression, '(?i)\b(NOT|AND|OR)\b', { param($Match) $Match.Value.ToLowerInvariant() })
  foreach ($Name in $Values.Keys) {
    $Expression = [regex]::Replace($Expression, "(?i)\b$([regex]::Escape($Name))\b", [string]$Values[$Name])
  }

  # Keep only the common boolean/numeric subset used by Burn architecture
  # guards. Unknown variables are treated as true to avoid false negatives.
  $Expression = [regex]::Replace($Expression, '(?i)\b[A-Z_][A-Z0-9_]*\b', 'True')
  $Expression = $Expression -replace '<>', '-ne'
  $Expression = $Expression -replace '>=', '-ge'
  $Expression = $Expression -replace '<=', '-le'
  $Expression = $Expression -replace '(?<![<>=!])=(?!=)', '-eq'
  $Expression = $Expression -replace '(?i)\bnot\b', '-not'
  $Expression = $Expression -replace '(?i)\band\b', '-and'
  $Expression = $Expression -replace '(?i)\bor\b', '-or'

  try {
    return [bool]([scriptblock]::Create($Expression).Invoke())
  } catch {
    return $true
  }
}

function Get-BurnPackageArchitectureInfo {
  <#
  .SYNOPSIS
    Read supported and unsupported Windows architectures from Burn package conditions
  .PARAMETER Path
    The path to the WiX bundle file
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the WiX bundle file')]
    [string]$Path
  )

  process {
    $BurnInfo = Get-BurnEngineInfo -Path $Path
    $BootstrapperApplicationData = $null
    try {
      $BootstrapperApplicationData = Get-BurnBootstrapperApplicationData -Path $Path
    } catch {
      $BootstrapperApplicationData = $null
    }

    $PackageNodes = @()
    if ($BootstrapperApplicationData) {
      $PackageNodes = @($BootstrapperApplicationData.GetElementsByTagName('WixPackageProperties'))
    }

    # Exclude the synthetic Bundle row and evaluate only executable package types that can constrain
    # the host architecture.
    $RelevantPackageNodes = @($PackageNodes | Where-Object {
        $_.Package -ne 'Bundle' -and (
          -not $_.PackageType -or
          $_.PackageType -in @('Exe', 'Msi', 'Msp', 'Msu')
        )
      })

    $Supported = [System.Collections.Generic.List[string]]::new()
    foreach ($Architecture in @('x86', 'x64', 'arm64')) {
      if (-not $RelevantPackageNodes) {
        # If the package manifest is unavailable, fall back to the bundle PE
        # machine. This is weaker than package conditions but still useful for
        # native x64/arm64 bootstrapper stubs.
        $BundleArchitecture = Convert-BurnMachineTypeToArchitecture -MachineType $BurnInfo.MachineType
        if ($BundleArchitecture -eq 'x86' -or $Architecture -eq $BundleArchitecture -or ($BundleArchitecture -eq 'x64' -and $Architecture -eq 'arm64')) {
          $Supported.Add($Architecture)
        }
        continue
      }

      foreach ($Package in $RelevantPackageNodes) {
        if (Test-BurnArchitectureCondition -Condition $Package.InstallCondition -Architecture $Architecture) {
          if (-not $Supported.Contains($Architecture)) { $Supported.Add($Architecture) }
          break
        }
      }
    }

    if ($Supported.Count -eq 3) {
      # Conditions that omit architecture can appear universal. Corroborate with explicit payload
      # folder/name markers only when they consistently indicate one native family.
      $Manifest = Get-BurnManifest -Path $Path
      $ManifestText = $Manifest.OuterXml
      $HasX64Marker = $ManifestText -match '(?i)(ProgramFiles64Folder|System64Folder|\bx64\b|_x64\b|x64Setup|SetupX64|amd64)'
      $HasX86Marker = $ManifestText -match '(?i)(ProgramFilesFolder(?!64)|FilePath="[^"]*(\bx86\b|_x86\b|x86Setup|SetupX86)[^"]*")'
      $HasArm64Marker = $ManifestText -match '(?i)(\barm64\b|_arm64\b|arm64Setup|SetupArm64)'

      if ($HasX64Marker -and -not $HasX86Marker -and -not $HasArm64Marker) {
        $Supported = [System.Collections.Generic.List[string]]::new()
        $Supported.Add('x64')
        $Supported.Add('arm64')
      } elseif ($HasArm64Marker -and -not $HasX64Marker -and -not $HasX86Marker) {
        $Supported = [System.Collections.Generic.List[string]]::new()
        $Supported.Add('arm64')
      }
    }

    $SupportedArchitectures = @('x86', 'x64', 'arm64') | Where-Object { $Supported.Contains($_) }
    [PSCustomObject]@{
      BundleArchitecture       = Convert-BurnMachineTypeToArchitecture -MachineType $BurnInfo.MachineType
      SupportedArchitectures   = $SupportedArchitectures
      UnsupportedArchitectures = @('x86', 'x64', 'arm64') | Where-Object { $_ -notin $SupportedArchitectures }
      Packages                 = $RelevantPackageNodes
    }
  }
}

function Convert-BurnPerMachineToScope {
  <#
  .SYNOPSIS
    Convert Burn PerMachine metadata to a WinGet scope
  .PARAMETER PerMachine
    The Burn PerMachine value
  #>
  [OutputType([string])]
  param (
    [AllowNull()]
    [string]$PerMachine
  )

  switch -Regex ($PerMachine) {
    '^(?i)(yes|1|true)$' { return 'machine' }
    '^(?i)(no|0|false)$' { return 'user' }
    default { return $null }
  }
}

function Get-BurnScopeInfo {
  <#
  .SYNOPSIS
    Read static install scope metadata from a WiX Burn bundle
  .PARAMETER Path
    The path to the WiX bundle file
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the WiX bundle file')]
    [string]$Path
  )

  process {
    $BootstrapperApplicationData = $null
    try {
      $BootstrapperApplicationData = Get-BurnBootstrapperApplicationData -Path $Path
    } catch {
      $BootstrapperApplicationData = $null
    }
    $Manifest = Get-BurnManifest -Path $Path

    # BootstrapperApplicationData provides the authored BA view; fall back to the engine manifest's
    # Registration element when BA data is unavailable.
    $BundlePerMachine = $null
    if ($BootstrapperApplicationData) {
      $BundleProperties = @($BootstrapperApplicationData.GetElementsByTagName('WixBundleProperties') | Select-Object -First 1)
      if ($BundleProperties) { $BundlePerMachine = $BundleProperties[0].GetAttribute('PerMachine') }
    }
    if ([string]::IsNullOrWhiteSpace($BundlePerMachine)) {
      $Registration = @($Manifest.GetElementsByTagName('Registration') | Select-Object -First 1)
      if ($Registration) { $BundlePerMachine = $Registration[0].GetAttribute('PerMachine') }
    }

    $DefaultScope = Convert-BurnPerMachineToScope -PerMachine $BundlePerMachine
    # Non-permanent chain packages provide supporting scope evidence but do not replace the bundle's
    # registration scope.
    $PackageScopes = @(
      $Manifest.GetElementsByTagName('*') |
        Where-Object { $_.Name -match 'Package$' -and $_.GetAttribute('Permanent') -ne 'yes' -and $_.HasAttribute('PerMachine') } |
        ForEach-Object { Convert-BurnPerMachineToScope -PerMachine $_.GetAttribute('PerMachine') } |
        Where-Object { $_ } |
        Select-Object -Unique
    )

    $OverridableVariables = @()
    if ($BootstrapperApplicationData) {
      $OverridableVariables = @($BootstrapperApplicationData.GetElementsByTagName('WixStdbaOverridableVariable') | ForEach-Object { $_.GetAttribute('Name') } | Where-Object { $_ })
    }
    $VariableNames = @($Manifest.GetElementsByTagName('Variable') | ForEach-Object { $_.GetAttribute('Id') } | Where-Object { $_ })
    $PackageIds = @($Manifest.GetElementsByTagName('*') | Where-Object { $_.Name -match 'Package$' } | ForEach-Object { $_.GetAttribute('Id') } | Where-Object { $_ })

    # Python-style Burn bundles expose both all-users and just-for-me package
    # groups, and make InstallAllUsers overridable from the command line.
    $HasAllUsersPackage = [bool]($PackageIds | Where-Object { $_ -match '(?i)(^|_)AllUsers($|_)' })
    $HasJustForMePackage = [bool]($PackageIds | Where-Object { $_ -match '(?i)(^|_)JustForMe($|_)' })
    $HasInstallAllUsersVariable = $VariableNames -contains 'InstallAllUsers'
    $HasInstallAllUsersOverride = $OverridableVariables -contains 'InstallAllUsers'
    $SupportsDualScope = $HasAllUsersPackage -and $HasJustForMePackage -and $HasInstallAllUsersVariable -and $HasInstallAllUsersOverride

    $SupportedScopes = if ($SupportsDualScope) {
      @('user', 'machine')
    } elseif ($DefaultScope) {
      @($DefaultScope)
    } else {
      @()
    }

    [PSCustomObject]@{
      DefaultScope              = $DefaultScope
      SupportedScopes           = $SupportedScopes
      SupportsDualScope         = $SupportsDualScope
      BundlePerMachine          = $BundlePerMachine
      PackageScopes             = $PackageScopes
      ScopeVariables            = @($VariableNames | Where-Object { $_ -match '(?i)(InstallAllUsers|InstallPerMachine|PerMachine|AllUsers)' })
      OverridableScopeVariables = @($OverridableVariables | Where-Object { $_ -match '(?i)(InstallAllUsers|InstallPerMachine|PerMachine|AllUsers)' })
    }
  }
}

function Read-ScopeFromBurn {
  <#
  .SYNOPSIS
    Read the default install scope from a WiX Burn bundle
  .PARAMETER Path
    The path to the WiX bundle file
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the WiX bundle file')]
    [string]$Path
  )

  process {
    (Get-BurnScopeInfo -Path $Path).DefaultScope
  }
}

function Read-SupportedScopesFromBurn {
  <#
  .SYNOPSIS
    Read install scopes supported by a WiX Burn bundle
  .PARAMETER Path
    The path to the WiX bundle file
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the WiX bundle file')]
    [string]$Path
  )

  process {
    (Get-BurnScopeInfo -Path $Path).SupportedScopes
  }
}

function Test-BurnDualScope {
  <#
  .SYNOPSIS
    Test whether a WiX Burn bundle statically exposes both user and machine scope
  .PARAMETER Path
    The path to the WiX bundle file
  #>
  [OutputType([bool])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the WiX bundle file')]
    [string]$Path
  )

  process {
    (Get-BurnScopeInfo -Path $Path).SupportsDualScope
  }
}

function Read-UnsupportedArchitecturesFromBurn {
  <#
  .SYNOPSIS
    Read Windows architectures that the Burn installer does not support
  .PARAMETER Path
    The path to the WiX bundle file
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the WiX bundle file')]
    [string]$Path
  )

  process {
    (Get-BurnPackageArchitectureInfo -Path $Path).UnsupportedArchitectures
  }
}

function Test-BurnUnsupportedArchitecture {
  <#
  .SYNOPSIS
    Test whether the Burn installer does not support a Windows architecture
  .PARAMETER Path
    The path to the WiX bundle file
  .PARAMETER Architecture
    The Windows architecture to test
  #>
  [OutputType([bool])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the WiX bundle file')]
    [string]$Path,

    [Parameter(Mandatory, HelpMessage = 'The Windows architecture to test')]
    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture
  )

  process {
    (Get-BurnPackageArchitectureInfo -Path $Path).UnsupportedArchitectures -contains $Architecture
  }
}

function Read-ProductCodeFromBurn {
  <#
  .SYNOPSIS
    Read the ProductCode property of the WiX bundle file
  .PARAMETER Path
    The path to the WiX bundle file
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the WiX bundle file')]
    [string]$Path
  )

  process {
    try {
      $BootstrapperApplicationData = Get-BurnBootstrapperApplicationData -Path $Path
      if ($BootstrapperApplicationData.BootstrapperApplicationData.WixBundleProperties.HasAttribute('Code')) {
        # WiX v6+
        Write-Output -InputObject $BootstrapperApplicationData.BootstrapperApplicationData.WixBundleProperties.Code
      } else {
        Write-Output -InputObject $BootstrapperApplicationData.BootstrapperApplicationData.WixBundleProperties.Id
      }
    } catch {
      $Manifest = Get-BurnManifest -Path $Path
      if ($Manifest.BurnManifest.Registration.HasAttribute('Code')) {
        # WiX v6+
        Write-Output -InputObject $Manifest.BurnManifest.Registration.Code
      } else {
        Write-Output -InputObject $Manifest.BurnManifest.Registration.Id
      }
    }
  }
}

function Read-UpgradeCodeFromBurn {
  <#
  .SYNOPSIS
    Read the UpgradeCode property of the WiX bundle file
  .PARAMETER Path
    The path to the WiX bundle file
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the WiX bundle file')]
    [string]$Path
  )

  process {
    try {
      $BootstrapperApplicationData = Get-BurnBootstrapperApplicationData -Path $Path
      Write-Output -InputObject $BootstrapperApplicationData.BootstrapperApplicationData.WixBundleProperties.UpgradeCode
    } catch {
      $Manifest = Get-BurnManifest -Path $Path
      if ($Manifest.BurnManifest.RelatedBundle.HasAttribute('Code')) {
        # WiX v6+
        Write-Output -InputObject $Manifest.BurnManifest.RelatedBundle.Code
      } else {
        Write-Output -InputObject $Manifest.BurnManifest.RelatedBundle.Id
      }
    }
  }
}

function Read-ProductNameFromBurn {
  <#
  .SYNOPSIS
    Read the ProductName property of the WiX bundle file
  .PARAMETER Path
    The path to the WiX bundle file
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the WiX bundle file')]
    [string]$Path
  )

  process {
    try {
      $BootstrapperApplicationData = Get-BurnBootstrapperApplicationData -Path $Path
      Write-Output -InputObject $BootstrapperApplicationData.BootstrapperApplicationData.WixBundleProperties.DisplayName
    } catch {
      $Manifest = Get-BurnManifest -Path $Path
      Write-Output -InputObject $Manifest.BurnManifest.Registration.Arp.DisplayName
    }
  }
}

function Get-BurnInfo {
  <#
  .SYNOPSIS
    Get static metadata from a WiX Burn bootstrapper bundle
  .DESCRIPTION
    Read the Burn manifest registration, ARP, and related-bundle elements and
    the bundle scope evidence in one pass, matching the metadata contract of
    the other installer-family parsers.
  .PARAMETER Path
    The path to the WiX bundle file
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the WiX bundle file')]
    [string]$Path
  )

  process {
    $null = Get-BurnEngineInfo -Path $Path
    $Manifest = Get-BurnManifest -Path $Path
    $Registration = @($Manifest.GetElementsByTagName('Registration') | Select-Object -First 1)
    if ($Registration.Count -eq 0) { throw 'The Burn manifest does not contain a Registration element' }
    $Registration = $Registration[0]
    $Arp = @($Registration.ChildNodes | Where-Object LocalName -EQ 'Arp' | Select-Object -First 1)
    $RelatedBundle = @($Manifest.GetElementsByTagName('RelatedBundle') | Select-Object -First 1)
    $ProductCode = $Registration.GetAttribute('Code')
    if ([string]::IsNullOrWhiteSpace($ProductCode)) { $ProductCode = $Registration.GetAttribute('Id') }
    $UpgradeCode = if ($RelatedBundle.Count -gt 0) {
      $Value = $RelatedBundle[0].GetAttribute('Code')
      [string]::IsNullOrWhiteSpace($Value) ? $RelatedBundle[0].GetAttribute('Id') : $Value
    } else { $null }
    $ScopeInfo = Get-BurnScopeInfo -Path $Path
    $Info = [pscustomobject][ordered]@{
      Path                         = (Get-Item -Path $Path -Force).FullName
      InstallerType                = 'Burn'
      ProductCode                  = $ProductCode
      UpgradeCode                  = $UpgradeCode
      DisplayName                  = $Arp.Count -gt 0 ? $Arp[0].GetAttribute('DisplayName') : $null
      DisplayVersion               = $Arp.Count -gt 0 ? $Arp[0].GetAttribute('DisplayVersion') : $null
      Publisher                    = $Arp.Count -gt 0 ? $Arp[0].GetAttribute('Publisher') : $null
      Scope                        = $ScopeInfo.DefaultScope
      DefaultInstallLocation       = $null
      WritesAppsAndFeaturesEntry   = $true
      AppsAndFeaturesProductCode   = $ProductCode
      AppsAndFeaturesInstallerType = 'burn'
      Warnings                     = [string[]]@()
      UnresolvedFields             = [string[]]@()
    }
    if ([string]::IsNullOrWhiteSpace($Info.DisplayName)) { $Info.DisplayName = Read-ProductNameFromBurn -Path $Path }
    if ([string]::IsNullOrWhiteSpace($Info.DisplayVersion)) { $Info.DisplayVersion = Read-ProductVersionFromExe -Path $Path }
    return $Info
  }
}

Export-ModuleMember -Function Get-BurnEngineInfo, Get-BurnStub, Get-BurnManifest, Expand-BurnInstaller, Get-BurnUXPayload, Get-BurnBootstrapperApplicationData, Get-BurnPackageArchitectureInfo, Get-BurnScopeInfo, Get-BurnInfo, Read-ScopeFromBurn, Read-SupportedScopesFromBurn, Test-BurnDualScope, Read-UnsupportedArchitecturesFromBurn, Test-BurnUnsupportedArchitecture, Read-ProductCodeFromBurn, Read-UpgradeCodeFromBurn, Read-ProductNameFromBurn
