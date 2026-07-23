# SPDX-License-Identifier: Apache-2.0
# Format sources: https://chromium.googlesource.com/chromium/src/+/main/chrome/installer/mini_installer,
# https://chromium.googlesource.com/chromium/src/+/main/chrome/install_static/install_util.cc,
# https://chromium.googlesource.com/chromium/src/+/main/chrome/updater/tag.h,
# https://github.com/google/omaha/blob/main/omaha/installers/build_metainstaller.py,
# https://github.com/brave/brave-core/tree/master/chromium_src/chrome/install_static, and
# https://learn.microsoft.com/microsoft-edge/webview2/concepts/distribution.
# Static Chromium installer parser. It distinguishes the bare Chromium mini
# installer, Chromium/Google Updater, and legacy Google Update/Omaha wrappers.
# No installer payload or update command is executed.
#
# Binary structures consumed here:
#
#   mini-installer: PE resources B7 setup*.7z > BL setup.ex_ > BN setup.exe,
#                   plus the product archive
#   Updater:        B7 updater.packed.7z -> updater.7z/bin/updater.exe
#   Omaha:          B resource 102 -> LZMA -> BCJ2 -> TAR/offline manifest
#   certificate:    "Gact2.0Omaha" + uint16 BE length + UTF-8 query, or
#                   bounded UTF-16LE start/end markers (Updater/Edge)
#
# Resource RVAs are mapped through PE sections. Tags are read only inside the
# certificate-table file range. Decoders receive declared input/output bounds.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:ChromiumUpdaterTagMarker = [Text.Encoding]::ASCII.GetBytes('Gact2.0Omaha')
$Script:ChromiumUpdaterWideTagPrefix = [Text.Encoding]::Unicode.GetBytes('Gact2.0Omaha')
$Script:ChromiumUpdaterWideTagSuffix = [Text.Encoding]::Unicode.GetBytes('ahamO0.2tcaG')
$Script:MicrosoftEdgeTagPrefix = [Text.Encoding]::Unicode.GetBytes('MSEDGE_')
$Script:MicrosoftEdgeTagSuffix = [Text.Encoding]::Unicode.GetBytes('_EGDESM')
$Script:ChromiumMaximumCertificateBytes = 16777216
$Script:ChromiumMaximumResourceBytes = 2147483648
$Script:ChromiumMaximumOfflineManifestBytes = 4194304
$Script:ChromiumInstallConstantsSize64 = 232
$Script:ChromiumInstallConstantsSize32 = 168

function ConvertFrom-ChromiumQueryTag {
  <#
  .SYNOPSIS
    Convert one updater query string into normalized tag evidence
  .PARAMETER RawTag
    Raw text to parse as format metadata without executing embedded commands.
  .PARAMETER Offset
    Byte offset in the coordinate system named by this function: absolute file, PE/resource, overlay, or record relative.
  .PARAMETER Length
    Declared size or parser bound in bytes or characters, as named by the field; ranges are validated before reading.
  .PARAMETER TagFormat
    Detected format variant controlling version-specific parsing rules.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][AllowEmptyString()][string]$RawTag,
    [Parameter(Mandatory)][long]$Offset,
    [Parameter(Mandatory)][int]$Length,
    [Parameter(Mandatory)][string]$TagFormat
  )

  $Parameters = [ordered]@{}
  foreach ($Part in ($RawTag -split '&')) {
    if ([string]::IsNullOrWhiteSpace($Part)) { continue }
    $Pair = $Part -split '=', 2
    $Key = [Uri]::UnescapeDataString($Pair[0].Replace('+', ' '))
    $Value = if ($Pair.Count -gt 1) { [Uri]::UnescapeDataString($Pair[1].Replace('+', ' ')) } else { '' }
    $Parameters[$Key] = $Value
  }

  [pscustomobject]@{
    MarkerFound     = $true
    IsTagged        = -not [string]::IsNullOrWhiteSpace($RawTag)
    TagFormat       = $TagFormat
    Offset          = $Offset
    Length          = $Length
    RawTag          = $RawTag
    Parameters      = [pscustomobject]$Parameters
    ApplicationId   = $Parameters['appguid'] ?? $Parameters['appid']
    ApplicationName = $Parameters['appname']
    NeedsAdmin      = $Parameters['needsadmin']
    Brand           = $Parameters['brand']
  }
}

function ConvertFrom-ChromiumUpdaterTagData {
  <#
  .SYNOPSIS
    Parse the Chromium Updater/Omaha tag framing from certificate bytes
  .PARAMETER Bytes
    Authenticode certificate-table bytes containing an optional updater tag
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes)

  # Probe the source-defined certificate-tag encodings in precedence order. Each candidate must be
  # completely bounded by the certificate table before query parameters are decoded.
  foreach ($Offset in (Find-BinaryPattern -Bytes $Bytes -Pattern $Script:ChromiumUpdaterTagMarker -Maximum 32)) {
    $LengthOffset = $Offset + $Script:ChromiumUpdaterTagMarker.Length
    if ($LengthOffset + 2 -gt $Bytes.Length) { continue }
    $Length = ([int]$Bytes[$LengthOffset] -shl 8) -bor [int]$Bytes[$LengthOffset + 1]
    $TagOffset = $LengthOffset + 2
    if ($TagOffset + $Length -gt $Bytes.Length) { continue }
    $RawTag = if ($Length -gt 0) { [Text.Encoding]::UTF8.GetString($Bytes, $TagOffset, $Length) } else { '' }
    return ConvertFrom-ChromiumQueryTag -RawTag $RawTag -Offset $Offset -Length $Length -TagFormat 'OmahaCertificateTag'
  }

  foreach ($Offset in (Find-BinaryPattern -Bytes $Bytes -Pattern $Script:ChromiumUpdaterWideTagPrefix -Maximum 32)) {
    $TagOffset = $Offset + $Script:ChromiumUpdaterWideTagPrefix.Length
    $SuffixOffset = $null
    foreach ($Candidate in (Find-BinaryPattern -Bytes $Bytes -Pattern $Script:ChromiumUpdaterWideTagSuffix -StartOffset $TagOffset -Maximum 1)) {
      $SuffixOffset = $Candidate
      break
    }
    if ($null -eq $SuffixOffset) { continue }
    $Length = [int]($SuffixOffset - $TagOffset)
    if ($Length -lt 0 -or $Length % 2 -ne 0) { continue }
    $RawTag = if ($Length -gt 0) { [Text.Encoding]::Unicode.GetString($Bytes, $TagOffset, $Length) } else { '' }
    return ConvertFrom-ChromiumQueryTag -RawTag $RawTag -Offset $Offset -Length $Length -TagFormat 'ChromiumWideCertificateTag'
  }

  foreach ($Offset in (Find-BinaryPattern -Bytes $Bytes -Pattern $Script:MicrosoftEdgeTagPrefix -Maximum 32)) {
    $TagOffset = $Offset + $Script:MicrosoftEdgeTagPrefix.Length
    $SuffixOffset = $null
    foreach ($Candidate in (Find-BinaryPattern -Bytes $Bytes -Pattern $Script:MicrosoftEdgeTagSuffix -StartOffset $TagOffset -Maximum 1)) {
      $SuffixOffset = $Candidate
      break
    }
    if ($null -eq $SuffixOffset) { continue }
    $Length = [int]($SuffixOffset - $TagOffset)
    if ($Length -le 0 -or $Length % 2 -ne 0) { continue }
    $RawTag = [Text.Encoding]::Unicode.GetString($Bytes, $TagOffset, $Length)
    return ConvertFrom-ChromiumQueryTag -RawTag $RawTag -Offset $Offset -Length $Length -TagFormat 'MicrosoftEdgeCertificateTag'
  }

  [pscustomobject]@{
    MarkerFound     = $false
    IsTagged        = $false
    TagFormat       = $null
    Offset          = $null
    Length          = 0
    RawTag          = $null
    Parameters      = [pscustomobject][ordered]@{}
    ApplicationId   = $null
    ApplicationName = $null
    NeedsAdmin      = $null
    Brand           = $null
  }
}

function Read-ChromiumInstallerTagFromStream {
  <#
  .SYNOPSIS
    Read a certificate tag from an already parsed PE stream
  .PARAMETER Stream
    Caller-owned binary stream. Sequential readers may advance its byte position; helpers do not dispose it.
  .PARAMETER Layout
    Previously validated layout evidence containing the coordinate ranges needed by this operation.
  .PARAMETER FileLength
    Declared size or parser bound in bytes or characters, as named by the field; ranges are validated before reading.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][psobject]$Layout,
    [Parameter(Mandatory)][long]$FileLength
  )

  $Certificate = $Layout.DataDirectories.Certificate
  # IMAGE_DIRECTORY_ENTRY_SECURITY stores a file offset rather than an RVA.
  if (-not $Certificate -or $Certificate.Rva -eq 0 -or $Certificate.Size -eq 0) {
    return ConvertFrom-ChromiumUpdaterTagData -Bytes ([byte[]]::new(0))
  }
  if ($Certificate.Size -gt $Script:ChromiumMaximumCertificateBytes -or $Certificate.Rva + $Certificate.Size -gt $FileLength) {
    throw 'The PE certificate table exceeds the Chromium tag parser limits.'
  }
  $Bytes = Read-BinaryBytes -Stream $Stream -Offset ([long]$Certificate.Rva) -Count ([int]$Certificate.Size)
  return ConvertFrom-ChromiumUpdaterTagData -Bytes $Bytes
}

function Read-ChromiumInstallerTag {
  <#
  .SYNOPSIS
    Read an updater metainstaller tag from the PE certificate table
  .PARAMETER Path
    The path to a Chromium Updater or Omaha installer
  .NOTES
    Searching only IMAGE_DIRECTORY_ENTRY_SECURITY avoids false positives from
    updater source strings compiled into the PE image.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)

  process {
    $File = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
      $Layout = Get-PELayout -Stream $Stream
      if (-not $Layout) { throw 'The file is not a valid PE image.' }
      return Read-ChromiumInstallerTagFromStream -Stream $Stream -Layout $Layout -FileLength $File.Length
    } finally { $Stream.Dispose() }
  }
}

function Get-ChromiumSetupResourceEvidence {
  <#
  .SYNOPSIS
    Normalize Chromium named-resource evidence for classification
  .PARAMETER Stream
    Caller-owned binary stream. Sequential readers may advance its byte position; helpers do not dispose it.
  .PARAMETER Layout
    Previously validated layout evidence containing the coordinate ranges needed by this operation.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][psobject]$Layout
  )

  # Keep only Chromium's named binary resource types; ordinary RCDATA is too broad and causes
  # unrelated installers to be classified from nested payload names.
  foreach ($Resource in (Get-PEResourceInfo -Stream $Stream -Layout $Layout)) {
    $Type = if ($Resource.TypeName) { [string]$Resource.TypeName } else { [string]$Resource.TypeId }
    $Name = if ($Resource.Name) { [string]$Resource.Name } else { [string]$Resource.Id }
    $Type = $Type.ToUpperInvariant()
    if ($Type -ne 'B' -and $Type -ne 'B7' -and $Type -ne 'BL' -and $Type -ne 'BN' -and $Type -ne 'BD') { continue }
    [pscustomobject]@{
      Type     = $Type
      Name     = $Name
      Id       = $Resource.Id
      Offset   = [long]$Resource.Offset
      Size     = [long]$Resource.Size
      Resource = $Resource
    }
  }
}

function Get-ChromiumSetupLayoutEvidence {
  <#
  .SYNOPSIS
    Select the source-defined Chromium payload resources in one pass
  .PARAMETER Resources
    Validated PE resource evidence with file-relative offsets and bounded lengths.
  .PARAMETER Tag
    Detected format variant controlling version-specific parsing rules.
  .PARAMETER VersionInfo
    Detected format variant controlling version-specific parsing rules.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][object[]]$Resources,
    [Parameter(Mandatory)][psobject]$Tag,
    [Parameter(Mandatory)][Diagnostics.FileVersionInfo]$VersionInfo
  )

  $MiniArchive = $null
  $MiniArchivePriority = 0
  $MiniSetup = $null
  $MiniSetupPriority = 0
  $UpdaterArchive = $null
  $OmahaResource = $null

  # Apply Chromium's resource-name precedence rather than selecting the largest archive. Packed
  # patch resources outrank compressed CAB and raw setup forms.
  foreach ($Resource in $Resources) {
    if (-not $UpdaterArchive -and $Resource.Type -eq 'B7' -and $Resource.Name -match '(?i)^updater(?:\.packed)?\.7z$') {
      $UpdaterArchive = $Resource
      continue
    }
    if (-not $OmahaResource -and $Resource.Type -eq 'B' -and ($Resource.Id -eq 102 -or $Resource.Name -eq '102')) {
      $OmahaResource = $Resource
      continue
    }

    $SetupPriority = 0
    if ($Resource.Type -eq 'B7' -and $Resource.Name -match '(?i)^setup(?:_patch)?(?:\.packed)?\.7z$') { $SetupPriority = 3 }
    elseif ($Resource.Type -eq 'BL' -and $Resource.Name -match '(?i)^setup\.ex_$') { $SetupPriority = 2 }
    elseif ($Resource.Type -eq 'BN' -and $Resource.Name -match '(?i)^setup\.exe$') { $SetupPriority = 1 }
    if ($SetupPriority -gt $MiniSetupPriority) {
      $MiniSetup = $Resource
      $MiniSetupPriority = $SetupPriority
      continue
    }

    if (($Resource.Type -eq 'B7' -or $Resource.Type -eq 'BN') -and
      $Resource.Name -match '(?i)^(?!setup(?:[._]|$)|updater(?:[._]|$)).+(?:\.packed)?\.7z$') {
      $ArchivePriority = if ($Resource.Type -eq 'B7') { 2 } else { 1 }
      if ($ArchivePriority -gt $MiniArchivePriority) {
        $MiniArchive = $Resource
        $MiniArchivePriority = $ArchivePriority
      }
    }
  }

  # Classification requires a complete source-backed resource combination. Omaha additionally
  # needs tag or updater identity evidence because resource 102 alone is not unique enough.
  $Variant = if ($UpdaterArchive) {
    'ChromiumUpdater'
  } elseif ($MiniArchive -and $MiniSetup) {
    'ChromiumMiniInstaller'
  } elseif ($OmahaResource -and ($Tag.MarkerFound -or $VersionInfo.OriginalFilename -match '(?i)(update|updater).*setup')) {
    'Omaha'
  } else {
    throw 'The PE does not contain a supported Chromium Setup resource layout.'
  }

  $SelectedResources = switch ($Variant) {
    'ChromiumMiniInstaller' { @($MiniArchive, $MiniSetup) }
    'ChromiumUpdater' { @($UpdaterArchive) }
    'Omaha' { @($OmahaResource) }
  }
  [pscustomobject]@{
    Variant           = $Variant
    MiniArchive       = $MiniArchive
    MiniSetup         = $MiniSetup
    UpdaterArchive    = $UpdaterArchive
    OmahaResource     = $OmahaResource
    SelectedResources = $SelectedResources
  }
}

function Open-ChromiumSetupContext {
  <#
  .SYNOPSIS
    Open one installer stream and cache its PE, resource, tag, and layout evidence
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)

  $File = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    # Parse PE layout, named resources, certificate tag, and variant once while sharing one stream.
    $Layout = Get-PELayout -Stream $Stream
    if (-not $Layout) { throw 'The file is not a valid PE image.' }
    $Resources = [Collections.Generic.List[object]]::new()
    foreach ($Resource in (Get-ChromiumSetupResourceEvidence -Stream $Stream -Layout $Layout)) {
      $Resource.Resource.Path = $File.FullName
      $Resources.Add($Resource)
    }
    $Tag = Read-ChromiumInstallerTagFromStream -Stream $Stream -Layout $Layout -FileLength $File.Length
    $VersionInfo = [Diagnostics.FileVersionInfo]::GetVersionInfo($File.FullName)
    $Evidence = Get-ChromiumSetupLayoutEvidence -Resources $Resources.ToArray() -Tag $Tag -VersionInfo $VersionInfo
    [pscustomobject]@{
      File        = $File
      Stream      = $Stream
      Layout      = $Layout
      Resources   = $Resources.ToArray()
      Tag         = $Tag
      VersionInfo = $VersionInfo
      Evidence    = $Evidence
    }
  } catch {
    $Stream.Dispose()
    throw
  }
}

function Close-ChromiumSetupContext {
  <#
  .SYNOPSIS
    Close a context returned by Open-ChromiumSetupContext
  .PARAMETER Context
    Parsed context or metadata object produced by the corresponding format reader.
  #>
  param ([Parameter(Mandatory)][psobject]$Context)
  $Context.Stream.Dispose()
}

function Export-ChromiumMiniInstallerSetupFromContext {
  <#
  .SYNOPSIS
    Export the source-selected setup.exe payload from an open mini-installer
  .PARAMETER Context
    Open Chromium setup context whose stream remains owned by the caller.
  .PARAMETER DestinationPath
    Existing or new directory that receives exactly one nested setup.exe.
  .PARAMETER MaximumExpandedBytes
    Hard limit for the decompressed setup payload.
  #>
  [OutputType([IO.FileInfo])]
  param (
    [Parameter(Mandatory)][psobject]$Context,
    [Parameter(Mandatory)][string]$DestinationPath,
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 134217728
  )

  if ($Context.Evidence.Variant -cne 'ChromiumMiniInstaller' -or -not $Context.Evidence.MiniSetup) {
    throw 'The Chromium setup context does not contain a selected mini-installer setup resource.'
  }
  $null = New-Item -Path $DestinationPath -ItemType Directory -Force
  $Evidence = $Context.Evidence.MiniSetup
  $OutputPath = Resolve-SafeExtractionPath -DestinationPath $DestinationPath -RelativePath 'setup.exe'

  # Chromium's stub selects one setup representation by resource precedence. Decode only that
  # representation so metadata inspection follows the same payload that the stub would execute.
  if ($Evidence.Type -eq 'BN') {
    return Export-PEResourceData -Resource $Evidence.Resource -DestinationPath $OutputPath -MaximumBytes $MaximumExpandedBytes
  }
  if ($Evidence.Type -eq 'BL') {
    $CabinetPath = New-TempFile
    try {
      $null = Export-PEResourceData -Resource $Evidence.Resource -DestinationPath $CabinetPath -MaximumBytes $Script:ChromiumMaximumResourceBytes
      $Files = @(Export-CabinetEntry -Path $CabinetPath -DestinationPath $DestinationPath -Name 'setup.exe' -MaximumExpandedBytes $MaximumExpandedBytes)
      if ($Files.Count -ne 1) { throw 'The selected Chromium BL resource does not contain exactly one setup.exe.' }
      return Get-Item -LiteralPath $Files[0] -Force
    } finally {
      Remove-Item -LiteralPath $CabinetPath -Force -ErrorAction SilentlyContinue
    }
  }
  if ($Evidence.Type -eq 'B7') {
    $ResourceStream = New-BoundedReadStream -Stream $Context.Stream -Offset $Evidence.Offset -Length $Evidence.Size -LeaveOpen
    $Archive = $null
    try {
      $Archive = Get-InstallerArchive -Stream $ResourceStream
      $Entries = @(Get-InstallerArchiveEntry -Archive $Archive | Where-Object { $_.FullName -ieq 'setup.exe' -or [IO.Path]::GetFileName($_.FullName) -ieq 'setup.exe' })
      if ($Entries.Count -ne 1) { throw 'The selected Chromium B7 resource does not contain exactly one setup.exe.' }
      return Export-InstallerArchiveEntry -Entry $Entries[0] -DestinationPath $OutputPath -MaximumBytes $MaximumExpandedBytes
    } finally {
      if ($Archive) { $Archive.Dispose() }
      $ResourceStream.Dispose()
    }
  }
  throw "The selected Chromium setup resource type '$($Evidence.Type)' is not supported."
}

function Read-ChromiumUtf16StringContainingOffset {
  <#
  .SYNOPSIS
    Read one bounded null-terminated UTF-16LE string around a known pattern offset
  .PARAMETER Stream
    Caller-owned seekable setup.exe stream. Its original position is restored.
  .PARAMETER Offset
    Absolute file offset of a UTF-16LE pattern inside the requested string.
  .PARAMETER MaximumCharacters
    Maximum characters inspected on either side of the pattern.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$Offset,
    [ValidateRange(1, 4096)][int]$MaximumCharacters = 512
  )

  $MaximumBytes = $MaximumCharacters * 2
  $WindowStart = [Math]::Max(0L, $Offset - $MaximumBytes)
  $WindowEnd = [Math]::Min($Stream.Length, $Offset + $MaximumBytes)
  $Bytes = Read-BinaryBytes -Stream $Stream -Offset $WindowStart -Count ([int]($WindowEnd - $WindowStart))
  $PatternIndex = [int]($Offset - $WindowStart)

  # Walk on the pattern's UTF-16 alignment only. A missing terminator at either bounded edge means
  # the candidate is incomplete and must not become registry evidence.
  $Start = $PatternIndex
  while ($Start -ge 2 -and -not ($Bytes[$Start - 2] -eq 0 -and $Bytes[$Start - 1] -eq 0)) { $Start -= 2 }
  if ($Start -lt 2 -and $WindowStart -ne 0) { return $null }
  $End = $PatternIndex
  while ($End + 1 -lt $Bytes.Length -and -not ($Bytes[$End] -eq 0 -and $Bytes[$End + 1] -eq 0)) { $End += 2 }
  if ($End + 1 -ge $Bytes.Length) { return $null }
  if ($End -le $Start -or ($End - $Start) % 2 -ne 0) { return $null }

  [pscustomobject]@{
    Offset = $WindowStart + $Start
    Text   = [Text.Encoding]::Unicode.GetString($Bytes, $Start, $End - $Start)
  }
}

function Read-ChromiumImageString {
  <#
  .SYNOPSIS
    Read a bounded string addressed by a preferred-image virtual pointer
  .PARAMETER Stream
    Caller-owned seekable PE stream. Random reads restore its original position.
  .PARAMETER Layout
    Parsed PE layout containing the preferred image base and section mappings.
  .PARAMETER Pointer
    Preferred virtual address stored in a linked Chromium constant record.
  .PARAMETER Encoding
    ASCII for narrow Chromium switches and schemes, or Unicode for wchar_t fields.
  .PARAMETER MaximumCharacters
    Maximum number of characters accepted before a null terminator is required.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][psobject]$Layout,
    [Parameter(Mandatory)][uint64]$Pointer,
    [Parameter(Mandatory)][ValidateSet('ASCII', 'Unicode')][string]$Encoding,
    [ValidateRange(1, 4096)][int]$MaximumCharacters = 256
  )

  # Linked pointers use the PE preferred image base. Reject null, underflow, and addresses outside
  # the 32-bit RVA space before mapping the pointer through the section table.
  if ($Pointer -eq 0 -or $Pointer -lt [uint64]$Layout.ImageBase) { return $null }
  $RvaValue = $Pointer - [uint64]$Layout.ImageBase
  if ($RvaValue -gt [uint32]::MaxValue) { return $null }
  $Offset = Convert-PEVirtualAddressToFileOffset -Rva ([uint32]$RvaValue) -Sections $Layout.Sections
  if ($Offset -lt 0 -or $Offset -ge $Stream.Length) { return $null }

  $BytesPerCharacter = $Encoding -eq 'Unicode' ? 2 : 1
  $MaximumBytes = $MaximumCharacters * $BytesPerCharacter
  $Bytes = Read-BinaryBytes -Stream $Stream -Offset $Offset -Count ([int][Math]::Min($MaximumBytes, $Stream.Length - $Offset))
  if ($Encoding -eq 'Unicode') {
    $End = 0
    while ($End + 1 -lt $Bytes.Length -and -not ($Bytes[$End] -eq 0 -and $Bytes[$End + 1] -eq 0)) { $End += 2 }
    if ($End + 1 -ge $Bytes.Length) { return $null }
    $Text = [Text.Encoding]::Unicode.GetString($Bytes, 0, $End)
  } else {
    $End = [Array]::IndexOf($Bytes, [byte]0)
    if ($End -lt 0) { return $null }
    $Text = [Text.Encoding]::ASCII.GetString($Bytes, 0, $End)
  }

  [pscustomobject]@{ Offset = $Offset; Text = $Text }
}

function Read-ChromiumInstallConstantsRecord {
  <#
  .SYNOPSIS
    Parse the source-defined identity prefix of one Chromium InstallConstants record
  .PARAMETER Stream
    Caller-owned seekable setup.exe stream.
  .PARAMETER Layout
    Parsed PE layout used to resolve linked string pointers.
  .PARAMETER Offset
    Absolute file offset of the candidate InstallConstants record.
  .PARAMETER PointerSize
    Native pointer width in bytes, derived from PE32 or PE32+.
  .PARAMETER StructureSize
    Expected source-defined size of the complete record in bytes.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][psobject]$Layout,
    [Parameter(Mandatory)][long]$Offset,
    [Parameter(Mandatory)][ValidateSet(4, 8)][int]$PointerSize,
    [Parameter(Mandatory)][int]$StructureSize
  )

  if ($Offset -lt 0 -or $Offset + $StructureSize -gt $Stream.Length) { return $null }
  $DeclaredSize = [uint64](Read-BinaryInteger -Stream $Stream -Offset $Offset -Size $PointerSize)
  if ($DeclaredSize -ne $StructureSize) { return $null }
  $Index = [uint32](Read-BinaryInteger -Stream $Stream -Offset ($Offset + $PointerSize) -Size 4)
  if ($Index -gt 31) { return $null }

  # The first identity fields have remained ordered across the supported 32-bit and 64-bit
  # InstallConstants layouts. Later GUID/icon fields are deliberately not interpreted here.
  $PointerBase = $PointerSize -eq 8 ? 16 : 8
  $Pointers = [uint64[]]::new(9)
  for ($Field = 0; $Field -lt $Pointers.Length; $Field++) {
    $Pointers[$Field] = [uint64](Read-BinaryInteger -Stream $Stream -Offset ($Offset + $PointerBase + ($Field * $PointerSize)) -Size $PointerSize)
  }
  $InstallSwitch = Read-ChromiumImageString -Stream $Stream -Layout $Layout -Pointer $Pointers[0] -Encoding ASCII -MaximumCharacters 64
  $InstallSuffix = Read-ChromiumImageString -Stream $Stream -Layout $Layout -Pointer $Pointers[1] -Encoding Unicode -MaximumCharacters 64
  $LogoSuffix = Read-ChromiumImageString -Stream $Stream -Layout $Layout -Pointer $Pointers[2] -Encoding Unicode -MaximumCharacters 64
  $ApplicationId = Read-ChromiumImageString -Stream $Stream -Layout $Layout -Pointer $Pointers[3] -Encoding Unicode -MaximumCharacters 64
  $BaseApplicationName = Read-ChromiumImageString -Stream $Stream -Layout $Layout -Pointer $Pointers[4] -Encoding Unicode -MaximumCharacters 128
  $BaseApplicationId = Read-ChromiumImageString -Stream $Stream -Layout $Layout -Pointer $Pointers[5] -Encoding Unicode -MaximumCharacters 128
  $BrowserProgIdPrefix = Read-ChromiumImageString -Stream $Stream -Layout $Layout -Pointer $Pointers[6] -Encoding Unicode -MaximumCharacters 64
  $BrowserProgIdDescription = Read-ChromiumImageString -Stream $Stream -Layout $Layout -Pointer $Pointers[7] -Encoding Unicode -MaximumCharacters 128
  $DirectLaunchUrlScheme = Read-ChromiumImageString -Stream $Stream -Layout $Layout -Pointer $Pointers[8] -Encoding ASCII -MaximumCharacters 64

  # Require every pointer in the identity prefix to resolve and then validate the source field's
  # lexical contract. This prevents arbitrary size-like data from being mistaken for a mode table.
  if ($null -in @($InstallSwitch, $InstallSuffix, $LogoSuffix, $ApplicationId, $BaseApplicationName, $BaseApplicationId, $BrowserProgIdPrefix, $BrowserProgIdDescription, $DirectLaunchUrlScheme)) { return $null }
  if ($InstallSwitch.Text -notmatch '^[A-Za-z0-9-]{0,64}$' -or
    $InstallSuffix.Text -match '[\x00-\x1F\\/]' -or
    $ApplicationId.Text -notmatch '^(?:|\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\})$' -or
    [string]::IsNullOrWhiteSpace($BaseApplicationName.Text) -or $BaseApplicationName.Text -match '[\x00-\x1F\\/]' -or
    $BaseApplicationId.Text -notmatch '^[A-Za-z0-9.]+$' -or $BrowserProgIdPrefix.Text -notmatch '^[A-Za-z0-9.]+$' -or
    $DirectLaunchUrlScheme.Text -notmatch '^(?:|[A-Za-z][A-Za-z0-9+.-]{0,63})$') { return $null }

  $SupportsSystemLevelOffset = $PointerSize -eq 8 ? 204 : 144
  $SupportsSystemLevel = [bool](Read-BinaryInteger -Stream $Stream -Offset ($Offset + $SupportsSystemLevelOffset) -Size 1)
  [pscustomobject]@{
    Offset                = $Offset
    StructureSize         = $StructureSize
    Index                 = [int]$Index
    InstallSwitch         = $InstallSwitch.Text
    InstallSuffix         = $InstallSuffix.Text
    LogoSuffix            = $LogoSuffix.Text
    ApplicationId         = $ApplicationId.Text
    BaseApplicationName   = $BaseApplicationName.Text
    BaseApplicationId     = $BaseApplicationId.Text
    BrowserProgIdPrefix   = $BrowserProgIdPrefix.Text
    DirectLaunchUrlScheme = $DirectLaunchUrlScheme.Text
    SupportsSystemLevel   = $SupportsSystemLevel
  }
}

function Get-ChromiumInstallModeInfo {
  <#
  .SYNOPSIS
    Locate and validate Chromium's contiguous kInstallModes array
  .PARAMETER Stream
    Caller-owned seekable setup.exe stream.
  .PARAMETER Layout
    Parsed PE layout. Only PE32 and PE32+ source layouts are supported.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][psobject]$Layout
  )

  $PointerSize = $Layout.OptionalHeaderMagic -eq 0x20B ? 8 : 4
  $StructureSize = $PointerSize -eq 8 ? $Script:ChromiumInstallConstantsSize64 : $Script:ChromiumInstallConstantsSize32
  $SizePattern = $PointerSize -eq 8 ? [BitConverter]::GetBytes([uint64]$StructureSize) : [BitConverter]::GetBytes([uint32]$StructureSize)
  $Tables = [Collections.Generic.List[object]]::new()

  # A real array begins with the primary record (index zero), then stores secondary modes in
  # contiguous records whose self-reported size and indexes agree.
  foreach ($Offset in (Find-BinaryPattern -Stream $Stream -Pattern $SizePattern -Maximum 512 -Alignment $PointerSize)) {
    $Primary = Read-ChromiumInstallConstantsRecord -Stream $Stream -Layout $Layout -Offset $Offset -PointerSize $PointerSize -StructureSize $StructureSize
    if (-not $Primary -or $Primary.Index -ne 0) { continue }
    $Records = [Collections.Generic.List[object]]::new()
    for ($ExpectedIndex = 0; $ExpectedIndex -lt 32; $ExpectedIndex++) {
      $RecordOffset = $Offset + ([long]$ExpectedIndex * $StructureSize)
      $Record = Read-ChromiumInstallConstantsRecord -Stream $Stream -Layout $Layout -Offset $RecordOffset -PointerSize $PointerSize -StructureSize $StructureSize
      if (-not $Record -or $Record.Index -ne $ExpectedIndex) { break }
      $Records.Add($Record)
    }
    if ($Records.Count -gt 0) {
      $Signature = [string]::Join([char]0x1F, @($Records | ForEach-Object { "$($_.InstallSwitch)|$($_.InstallSuffix)|$($_.ApplicationId)|$($_.BaseApplicationName)" }))
      $Tables.Add([pscustomobject]@{ Offset = $Offset; Records = $Records.ToArray(); Signature = $Signature })
    }
  }

  $Warnings = [Collections.Generic.List[string]]::new()
  $Selected = $null
  if ($Tables.Count -gt 0) {
    $Ranked = @($Tables | Sort-Object -Property @{ Expression = { $_.Records.Count }; Descending = $true }, @{ Expression = 'Offset'; Descending = $false })
    $Best = @($Ranked | Where-Object { $_.Records.Count -eq $Ranked[0].Records.Count })
    $DistinctSignatures = @($Best.Signature | Sort-Object -Unique)
    if ($DistinctSignatures.Count -gt 1) {
      $Warnings.Add("Chromium setup contains multiple equally complete InstallConstants arrays at $([string]::Join(', ', @($Best | ForEach-Object { '0x' + $_.Offset.ToString('X') }))).")
    } else {
      $Selected = $Best[0]
    }
  }

  [pscustomobject]@{
    Offset        = if ($Selected) { $Selected.Offset } else { $null }
    StructureSize = $StructureSize
    PointerSize   = $PointerSize
    InstallModes  = if ($Selected) { $Selected.Records } else { @() }
    Warnings      = $Warnings.ToArray()
  }
}

function Find-ChromiumProductPathName {
  <#
  .SYNOPSIS
    Verify a canonical kProductPathName candidate derived from an install mode
  .PARAMETER Stream
    Caller-owned seekable setup.exe stream.
  .PARAMETER DirectLaunchUrlScheme
    Source-defined direct-launch scheme from the primary InstallConstants record.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][AllowEmptyString()][string]$DirectLaunchUrlScheme
  )

  if ([string]::IsNullOrWhiteSpace($DirectLaunchUrlScheme)) { return $null }
  # Vendor product path constants commonly preserve the direct-launch scheme's words while using
  # display casing (for example, brave-browser -> Brave-Browser). Treat this only as a candidate;
  # require an independently stored, null-terminated wchar_t string in the PE before accepting it.
  $Candidate = [Globalization.CultureInfo]::InvariantCulture.TextInfo.ToTitleCase($DirectLaunchUrlScheme.ToLowerInvariant())
  $Pattern = [Text.Encoding]::Unicode.GetBytes("$Candidate$([char]0)")
  $CandidateOffsets = [Collections.Generic.List[long]]::new()
  foreach ($Offset in (Find-BinaryPattern -Stream $Stream -Pattern $Pattern -Maximum 16 -Alignment 1)) {
    if ($Offset -ge 2) {
      $Prefix = Read-BinaryBytes -Stream $Stream -Offset ($Offset - 2) -Count 2
      if ($Prefix[0] -ne 0 -or $Prefix[1] -ne 0) { continue }
    }
    $CandidateOffsets.Add($Offset)
  }
  if ($CandidateOffsets.Count -eq 1) { return $Candidate }
  return $null
}

function Read-ChromiumAsciiStringContainingOffset {
  <#
  .SYNOPSIS
    Read one bounded null-terminated ASCII string containing a known offset
  .PARAMETER Stream
    Caller-owned seekable stream. Its original position is restored.
  .PARAMETER Offset
    Absolute file offset of an ASCII pattern inside the requested string.
  .PARAMETER MaximumCharacters
    Maximum characters inspected on either side of the pattern.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$Offset,
    [ValidateRange(1, 512)][int]$MaximumCharacters = 80
  )

  $WindowStart = [Math]::Max(0L, $Offset - $MaximumCharacters)
  $WindowEnd = [Math]::Min($Stream.Length, $Offset + $MaximumCharacters)
  $Bytes = Read-BinaryBytes -Stream $Stream -Offset $WindowStart -Count ([int]($WindowEnd - $WindowStart))
  $PatternIndex = [int]($Offset - $WindowStart)
  $Start = $PatternIndex
  while ($Start -ge 1 -and $Bytes[$Start - 1] -ne 0) { $Start-- }
  if ($Start -lt 1 -and $WindowStart -ne 0) { return $null }
  $End = $PatternIndex
  while ($End -lt $Bytes.Length -and $Bytes[$End] -ne 0) { $End++ }
  if ($End -ge $Bytes.Length -or $End -le $Start) { return $null }

  [pscustomobject]@{
    Offset = $WindowStart + $Start
    Text   = [Text.Encoding]::ASCII.GetString($Bytes, $Start, $End - $Start)
  }
}

function Get-ChromiumLegacyProductIdentityInfo {
  <#
  .SYNOPSIS
    Resolve product identity used by legacy Chromium-family setup forks
  .DESCRIPTION
    Some vendor forks do not retain Chromium's current InstallConstants layout. They instead
    embed an ASCII product-specific install-directory switch, a matching Software\<product>
    registry root, and the standalone product path appended to Chromium's composed uninstall
    registry root. This function requires all three literals and returns no identity when more
    than one product agrees.
  .PARAMETER Stream
    Caller-owned seekable setup.exe stream. Random reads restore its original position.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][IO.Stream]$Stream)

  $Candidates = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
  $InstallDirectorySuffix = [Text.Encoding]::ASCII.GetBytes('-install-dir')
  foreach ($Offset in (Find-BinaryPattern -Stream $Stream -Pattern $InstallDirectorySuffix -Maximum 128 -Alignment 1)) {
    $InstallDirectorySwitch = Read-ChromiumAsciiStringContainingOffset -Stream $Stream -Offset $Offset -MaximumCharacters 80
    if (-not $InstallDirectorySwitch) { continue }
    $Match = [regex]::Match($InstallDirectorySwitch.Text, '^(?<Token>[A-Za-z][A-Za-z0-9-]{1,63})-install-dir$', 'CultureInvariant')
    if (-not $Match.Success) { continue }

    $Token = $Match.Groups['Token'].Value.ToLowerInvariant()
    # Chromium uninstall paths preserve the product path's display casing. Reconstruct only the
    # deterministic title-cased token, then require that exact null-terminated UTF-16 literal in
    # the binary. Multiple occurrences are acceptable; they all prove the same candidate value.
    $ProductPathName = [Globalization.CultureInfo]::InvariantCulture.TextInfo.ToTitleCase($Token)
    $ProductPattern = [Text.Encoding]::Unicode.GetBytes("$ProductPathName$([char]0)")
    $HasProductPathName = $false
    foreach ($ProductOffset in (Find-BinaryPattern -Stream $Stream -Pattern $ProductPattern -Maximum 32 -Alignment 1)) {
      if ($ProductOffset -eq 0) { $HasProductPathName = $true; break }
      if ($ProductOffset -lt 2) { continue }
      $Prefix = Read-BinaryBytes -Stream $Stream -Offset ($ProductOffset - 2) -Count 2
      if ($Prefix[0] -eq 0 -and $Prefix[1] -eq 0) { $HasProductPathName = $true; break }
    }
    if (-not $HasProductPathName -or $Candidates.ContainsKey($ProductPathName)) { continue }

    # The same product path must independently own a registry namespace. This excludes generic
    # switches such as user-data-dir even when their token happens to appear as display text.
    $ProductRegistryPattern = [Text.Encoding]::Unicode.GetBytes("Software\$ProductPathName$([char]0)")
    $ProductRegistryMatches = @(Find-BinaryPattern -Stream $Stream -Pattern $ProductRegistryPattern -Maximum 8 -Alignment 1)
    if ($ProductRegistryMatches.Count -eq 0) { continue }
    $Candidates[$ProductPathName] = [pscustomobject]@{
      ProductCode            = $ProductPathName
      InstallDirectorySwitch = $InstallDirectorySwitch.Text
      ProductRegistryPath    = "Software\$ProductPathName"
    }
  }

  $ResolvedCandidate = if ($Candidates.Count -eq 1) { @($Candidates.Values)[0] } else { $null }
  [pscustomobject]@{
    ProductCode            = if ($ResolvedCandidate) { $ResolvedCandidate.ProductCode } else { $null }
    InstallDirectorySwitch = if ($ResolvedCandidate) { $ResolvedCandidate.InstallDirectorySwitch } else { $null }
    ProductRegistryPath    = if ($ResolvedCandidate) { $ResolvedCandidate.ProductRegistryPath } else { $null }
    Candidates             = @($Candidates.Values)
    IsAmbiguous            = $Candidates.Count -gt 1
  }
}

function Get-ChromiumNestedSetupRegistryInfo {
  <#
  .SYNOPSIS
    Read explicit Chromium ARP identity evidence from a nested setup.exe
  .DESCRIPTION
    Chromium's install_static::GetUninstallRegistryPath constructs the visible
    ARP key from kCompanyPathName, kProductPathName, and the selected install
    suffix. Vendor forks either leave the resulting literal uninstall path in
    setup.exe or expose the same company/product pair in their updater Clients
    registry path. Literal uninstall paths take precedence; repeated literals
    outrank incidental auxiliary-product keys.
  .PARAMETER Path
    Path to the statically extracted nested setup.exe. The file is never run.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)

  $File = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    $DirectCandidates = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
    $UpdateCandidates = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
    $UpdateCompanyCandidates = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
    $UninstallPaths = [Collections.Generic.List[string]]::new()
    $UpdateClientPaths = [Collections.Generic.List[string]]::new()
    $ComposesUninstallRegistryPath = $false
    $InstallModeInfo = $null
    $LegacyProductIdentity = $null

    # Modern Chromium setup binaries carry a linked kInstallModes table. Non-PE synthetic fixtures
    # and older vendor forks simply continue through the explicit registry-path parser.
    try {
      $Layout = Get-PELayout -Stream $Stream
      if ($Layout) { $InstallModeInfo = Get-ChromiumInstallModeInfo -Stream $Stream -Layout $Layout }
    } catch { }

    # Match only registry structures used by Chromium setup. This deliberately avoids arbitrary
    # branding/version strings, which are not authoritative ARP identity evidence.
    $UninstallSuffix = '\Microsoft\Windows\CurrentVersion\Uninstall\'
    foreach ($Offset in (Find-BinaryPattern -Stream $Stream -Pattern ([Text.Encoding]::Unicode.GetBytes($UninstallSuffix)) -Maximum 512 -Alignment 1)) {
      $String = Read-ChromiumUtf16StringContainingOffset -Stream $Stream -Offset $Offset
      if (-not $String) { continue }
      if ($String.Text -match '^Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\$') {
        $ComposesUninstallRegistryPath = $true
        continue
      }
      $Match = [regex]::Match($String.Text, 'Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\(?<Key>.+)$', 'IgnoreCase,CultureInvariant')
      if (-not $Match.Success) { continue }
      $Key = $Match.Groups['Key'].Value.Trim()
      # ProductCode is the immediate uninstall subkey. Reject templates, partial GUIDs, nested
      # paths, and control characters rather than trying to complete or normalize them.
      if ($Key.Length -gt 200 -or $Key -match '[\\/%\x00-\x1F]' -or
        (($Key.Contains('{') -or $Key.Contains('}')) -and $Key -notmatch '^\{[0-9A-Fa-f-]{36}\}(?:.+)?$')) { continue }
      $UninstallPaths.Add($String.Text)
      if (-not $DirectCandidates.ContainsKey($Key)) {
        $DirectCandidates[$Key] = [pscustomobject]@{ ProductCode = $Key; Count = 0; Source = 'DirectUninstallRegistryPath' }
      }
      $DirectCandidates[$Key].Count++
    }

    # Some modern vendor builds compose the uninstall path at runtime. Their updater integration
    # still embeds Software\<company>\<product>\Update\Clients, exposing the same two constants
    # consumed by GetUninstallRegistryPath without relying on PE display branding.
    $UpdateClientsSuffix = '\Update\Clients'
    foreach ($Offset in (Find-BinaryPattern -Stream $Stream -Pattern ([Text.Encoding]::Unicode.GetBytes($UpdateClientsSuffix)) -Maximum 512 -Alignment 1)) {
      $String = Read-ChromiumUtf16StringContainingOffset -Stream $Stream -Offset $Offset
      if (-not $String) { continue }
      $Match = [regex]::Match($String.Text, 'Software\\(?<Root>.+?)\\Update\\Clients\\?$', 'IgnoreCase,CultureInvariant')
      if (-not $Match.Success) { continue }
      $Segments = @($Match.Groups['Root'].Value.Split([char]'\') | ForEach-Object Trim | Where-Object { $_ })
      if ($Segments.Count -eq 0 -or @($Segments | Where-Object { $_ -match '[/%\x00-\x1F]' }).Count -gt 0) { continue }
      $UpdateClientPaths.Add($Match.Value)
      if ($Segments.Count -ge 2) {
        $ProductCode = [string]::Join(' ', $Segments)
        if (-not $UpdateCandidates.ContainsKey($ProductCode)) {
          $UpdateCandidates[$ProductCode] = [pscustomobject]@{ ProductCode = $ProductCode; Count = 0; Source = 'ChromiumUpdateClientPath' }
        }
        $UpdateCandidates[$ProductCode].Count++
      } else {
        $Company = $Segments[0]
        if (-not $UpdateCompanyCandidates.ContainsKey($Company)) {
          $UpdateCompanyCandidates[$Company] = [pscustomobject]@{ Company = $Company; Count = 0 }
        }
        $UpdateCompanyCandidates[$Company].Count++
      }
    }

    $Warnings = [Collections.Generic.List[string]]::new()
    $Selected = $null
    # A repeated direct path is stronger than a one-off auxiliary uninstall key. Equal-frequency
    # candidates are intentionally left unresolved because static evidence cannot choose safely.
    $Candidates = if ($DirectCandidates.Count -gt 0) {
      @($DirectCandidates.Values)
    } elseif ($ComposesUninstallRegistryPath) {
      @($UpdateCandidates.Values)
    } else {
      @()
    }
    if ($Candidates.Count -gt 0) {
      $Ranked = @($Candidates | Sort-Object -Property @{ Expression = 'Count'; Descending = $true }, @{ Expression = 'ProductCode'; Descending = $false })
      if ($Ranked.Count -gt 1 -and $Ranked[0].Count -eq $Ranked[1].Count) {
        $Warnings.Add("Chromium setup contains ambiguous $($Ranked[0].Source) ProductCode candidates: $([string]::Join(', ', @($Ranked | ForEach-Object ProductCode))).")
      } else {
        $Selected = $Ranked[0]
      }
    }
    if (-not $Selected -and $Candidates.Count -eq 0 -and $ComposesUninstallRegistryPath -and
      $UpdateCompanyCandidates.Count -gt 0 -and $InstallModeInfo -and $InstallModeInfo.InstallModes.Count -gt 0) {
      $Companies = @($UpdateCompanyCandidates.Values | Sort-Object -Property @{ Expression = 'Count'; Descending = $true }, @{ Expression = 'Company'; Descending = $false })
      if ($Companies.Count -gt 1 -and $Companies[0].Count -eq $Companies[1].Count) {
        $Warnings.Add("Chromium setup contains ambiguous updater company-path constants: $([string]::Join(', ', @($Companies | ForEach-Object Company))).")
      } else {
        $Company = $Companies[0].Company
        $PrimaryMode = @($InstallModeInfo.InstallModes | Where-Object Index -EQ 0)[0]
        if ($PrimaryMode.BaseApplicationName.StartsWith("$Company ", [StringComparison]::OrdinalIgnoreCase)) {
          $Selected = [pscustomobject]@{ ProductCode = $PrimaryMode.BaseApplicationName; Count = 1; Source = 'ChromiumCompanyAndInstallConstants' }
        } else {
          $ProductPathName = Find-ChromiumProductPathName -Stream $Stream -DirectLaunchUrlScheme $PrimaryMode.DirectLaunchUrlScheme
          if ($ProductPathName) {
            $Selected = [pscustomobject]@{ ProductCode = "$Company $ProductPathName"; Count = 1; Source = 'ChromiumCompanyAndProductConstants' }
          }
        }
      }
    }
    if (-not $Selected -and $Candidates.Count -eq 0 -and $ComposesUninstallRegistryPath) {
      # Legacy Chromium forks can replace InstallConstants with product-specific switch constants.
      # Resolve the appended uninstall key only when the install-dir switch, product registry root,
      # and product path all agree; no PE publisher or product-name branding participates.
      $LegacyProductIdentity = Get-ChromiumLegacyProductIdentityInfo -Stream $Stream
      if ($LegacyProductIdentity.IsAmbiguous) {
        $Warnings.Add("Chromium setup contains ambiguous legacy product identity candidates: $([string]::Join(', ', @($LegacyProductIdentity.Candidates | ForEach-Object ProductCode))).")
      } elseif ($LegacyProductIdentity.ProductCode) {
        $Selected = [pscustomobject]@{ ProductCode = $LegacyProductIdentity.ProductCode; Count = 1; Source = 'LegacyChromiumProductSwitchAndRegistryPath' }
      }
    }
    if ($InstallModeInfo) { foreach ($Warning in $InstallModeInfo.Warnings) { $Warnings.Add($Warning) } }

    $ResolvedInstallModes = [Collections.Generic.List[object]]::new()
    if ($InstallModeInfo) {
      foreach ($Mode in $InstallModeInfo.InstallModes) {
        $ResolvedInstallModes.Add([pscustomobject]@{
            Index                 = $Mode.Index
            InstallSwitch         = $Mode.InstallSwitch
            InstallSuffix         = $Mode.InstallSuffix
            ApplicationId         = $Mode.ApplicationId
            BaseApplicationName   = $Mode.BaseApplicationName
            DirectLaunchUrlScheme = $Mode.DirectLaunchUrlScheme
            SupportsSystemLevel   = $Mode.SupportsSystemLevel
            ProductCode           = if ($Selected) { "$($Selected.ProductCode)$($Mode.InstallSuffix)" } else { $null }
          })
      }
    }

    [pscustomobject]@{
      ProductCode                   = if ($Selected) { $Selected.ProductCode } else { $null }
      ProductCodeSource             = if ($Selected) { $Selected.Source } else { $null }
      ComposesUninstallRegistryPath = $ComposesUninstallRegistryPath
      UninstallRegistryPaths        = $UninstallPaths.ToArray()
      UpdateClientRegistryPaths     = $UpdateClientPaths.ToArray()
      ProductCodeCandidates         = @($DirectCandidates.Values) + @($UpdateCandidates.Values)
      InstallModes                  = $ResolvedInstallModes.ToArray()
      InstallConstantsOffset        = if ($InstallModeInfo) { $InstallModeInfo.Offset } else { $null }
      InstallConstantsSize          = if ($InstallModeInfo) { $InstallModeInfo.StructureSize } else { $null }
      LegacyProductIdentity         = $LegacyProductIdentity
      Warnings                      = $Warnings.ToArray()
    }
  } finally {
    $Stream.Dispose()
  }
}

function Get-ChromiumMiniInstallerNestedSetupInfo {
  <#
  .SYNOPSIS
    Extract and inspect the nested setup selected by a Chromium mini-installer
  .PARAMETER Context
    Open Chromium setup context whose outer stream remains owned by the caller.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][psobject]$Context)

  $TemporaryFolder = New-TempFolder
  try {
    $SetupFile = Export-ChromiumMiniInstallerSetupFromContext -Context $Context -DestinationPath $TemporaryFolder
    $VersionInfo = [Diagnostics.FileVersionInfo]::GetVersionInfo($SetupFile.FullName)
    $RegistryInfo = Get-ChromiumNestedSetupRegistryInfo -Path $SetupFile.FullName
    [pscustomobject]@{
      ProductName                   = $VersionInfo.ProductName
      ProductVersion                = $VersionInfo.ProductVersion
      Publisher                     = $VersionInfo.CompanyName
      ProductCode                   = $RegistryInfo.ProductCode
      ProductCodeSource             = $RegistryInfo.ProductCodeSource
      ComposesUninstallRegistryPath = $RegistryInfo.ComposesUninstallRegistryPath
      UninstallRegistryPaths        = $RegistryInfo.UninstallRegistryPaths
      UpdateClientRegistryPaths     = $RegistryInfo.UpdateClientRegistryPaths
      ProductCodeCandidates         = $RegistryInfo.ProductCodeCandidates
      InstallModes                  = $RegistryInfo.InstallModes
      InstallConstantsOffset        = $RegistryInfo.InstallConstantsOffset
      InstallConstantsSize          = $RegistryInfo.InstallConstantsSize
      LegacyProductIdentity         = $RegistryInfo.LegacyProductIdentity
      Warnings                      = $RegistryInfo.Warnings
    }
  } finally {
    Remove-Item -LiteralPath $TemporaryFolder -Recurse -Force -ErrorAction SilentlyContinue
  }
}

function ConvertFrom-ChromiumOmahaOfflineManifest {
  <#
  .SYNOPSIS
    Read target package and execution evidence from OfflineManifest.gup
  .PARAMETER Path
    The path to an extracted Omaha offline manifest
  .PARAMETER ApplicationId
    The tagged application identity used to select the matching app element
  .PARAMETER Text
    Raw text to parse as format metadata without executing embedded commands.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, ParameterSetName = 'Path')][string]$Path,
    [Parameter(Mandatory, ParameterSetName = 'Text')][string]$Text,
    [string]$ApplicationId
  )

  # OfflineManifest.gup is untrusted embedded XML. Disable DTDs and external entity resolution.
  $Settings = [Xml.XmlReaderSettings]::new()
  $Settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
  $Settings.XmlResolver = $null
  $Settings.IgnoreComments = $true
  $TextReader = if ($PSCmdlet.ParameterSetName -eq 'Text') { [IO.StringReader]::new($Text) } else { $null }
  $Reader = if ($TextReader) { [Xml.XmlReader]::Create($TextReader, $Settings) } else { [Xml.XmlReader]::Create($Path, $Settings) }
  try {
    $Document = [Xml.XmlDocument]::new()
    $Document.XmlResolver = $null
    $Document.Load($Reader)
  } finally { $Reader.Dispose(); if ($TextReader) { $TextReader.Dispose() } }

  $Application = $null
  # A multi-app response is selected by the signed tag appid; an untagged payload uses its first
  # application only because no stronger outer identity exists.
  foreach ($Candidate in $Document.SelectNodes('/response/app')) {
    if ([string]::IsNullOrWhiteSpace($ApplicationId) -or $Candidate.GetAttribute('appid').Equals($ApplicationId, [StringComparison]::OrdinalIgnoreCase)) {
      $Application = $Candidate
      break
    }
  }
  if (-not $Application) { throw "OfflineManifest.gup does not contain tagged application '$ApplicationId'." }
  if ($Application.HasAttribute('status') -and $Application.GetAttribute('status') -cne 'ok') {
    throw 'OfflineManifest.gup does not contain a successful application response.'
  }

  $UpdateCheck = $Application.SelectSingleNode('updatecheck')
  $Manifest = if ($UpdateCheck) { $UpdateCheck.SelectSingleNode('manifest') } else { $null }
  if (-not $UpdateCheck -or $UpdateCheck.GetAttribute('status') -cne 'ok' -or -not $Manifest) {
    throw 'OfflineManifest.gup does not contain a successful update manifest.'
  }

  $Packages = [Collections.Generic.List[object]]::new()
  # Preserve package hashes and required flags as execution evidence without downloading anything.
  foreach ($Package in $Manifest.SelectNodes('packages/package')) {
    $Size = 0L
    $HasSize = [long]::TryParse($Package.GetAttribute('size'), [Globalization.NumberStyles]::Integer, [Globalization.CultureInfo]::InvariantCulture, [ref]$Size)
    $Packages.Add([pscustomobject]@{
        Name       = $Package.GetAttribute('name')
        HashSha256 = $Package.GetAttribute('hash_sha256')
        Size       = $HasSize ? $Size : $null
        Required   = $Package.GetAttribute('required') -ieq 'true'
      })
  }

  $Actions = [Collections.Generic.List[object]]::new()
  $InstallAction = $null
  # The install action, not TAR entry order alone, is authoritative when an offline manifest exists.
  foreach ($Action in $Manifest.SelectNodes('actions/action')) {
    $ActionInfo = [pscustomobject]@{
      Event      = $Action.GetAttribute('event')
      Run        = $Action.GetAttribute('run')
      Arguments  = $Action.GetAttribute('arguments').Trim()
      NeedsAdmin = $Action.GetAttribute('needsadmin')
    }
    $Actions.Add($ActionInfo)
    if (-not $InstallAction -and $ActionInfo.Event -ieq 'install') { $InstallAction = $ActionInfo }
  }

  [pscustomobject]@{
    ApplicationId = $Application.GetAttribute('appid')
    Version       = $Manifest.GetAttribute('version')
    Packages      = $Packages.ToArray()
    Actions       = $Actions.ToArray()
    InstallAction = $InstallAction
  }
}

function Get-ChromiumOmahaPayloadInfo {
  <#
  .SYNOPSIS
    Parse an Omaha offline manifest and inspect the executable it configures
  .PARAMETER Resource
    Validated PE resource evidence with file-relative offsets and bounded lengths.
  .PARAMETER ApplicationId
    Installer identity value used to select or report the matching static metadata record.
  .PARAMETER SkipNestedSetup
    Parse only OfflineManifest.gup without exporting and inspecting its configured target.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Resource,
    [string]$ApplicationId,
    [switch]$SkipNestedSetup
  )

  $Context = Open-ChromiumOmahaArchive -Resource $Resource -MaximumExpandedBytes $Script:ChromiumMaximumResourceBytes
  $NestedFolder = $null
  try {
    $Entries = [Collections.Generic.List[object]]::new()
    $ManifestEntry = $null
    foreach ($Entry in (Get-InstallerArchiveEntry -Archive $Context.Archive)) {
      $Entries.Add($Entry)
      if ($Entry.FullName -ine 'OfflineManifest.gup' -and [IO.Path]::GetFileName($Entry.FullName) -ine 'OfflineManifest.gup') { continue }
      if ($ManifestEntry) { throw 'The Omaha payload contains more than one OfflineManifest.gup entry.' }
      $ManifestEntry = $Entry
    }
    if (-not $ManifestEntry) {
      return [pscustomobject]@{ OfflineManifest = $null; NestedSetupInfo = $null; NestedSetupError = $null; TargetEntryName = $null }
    }

    $Text = Read-InstallerArchiveEntryText -Entry $ManifestEntry -MaximumBytes $Script:ChromiumMaximumOfflineManifestBytes
    $OfflineManifest = ConvertFrom-ChromiumOmahaOfflineManifest -Text $Text -ApplicationId $ApplicationId
    if ($SkipNestedSetup) {
      return [pscustomobject]@{ OfflineManifest = $OfflineManifest; NestedSetupInfo = $null; NestedSetupError = $null; TargetEntryName = $null }
    }

    # OfflineManifest.gup's install action is authoritative. Omaha appends the app GUID to package
    # entry names in its TAR, so accept either the literal configured name or that exact name plus
    # one suffix. Package size must agree when the manifest supplies it.
    $TargetNames = [Collections.Generic.List[string]]::new()
    if ($OfflineManifest.InstallAction -and -not [string]::IsNullOrWhiteSpace($OfflineManifest.InstallAction.Run)) {
      $TargetNames.Add([IO.Path]::GetFileName($OfflineManifest.InstallAction.Run))
    }
    foreach ($Package in $OfflineManifest.Packages) {
      if (-not [string]::IsNullOrWhiteSpace($Package.Name) -and -not $TargetNames.Contains([IO.Path]::GetFileName($Package.Name))) {
        $TargetNames.Add([IO.Path]::GetFileName($Package.Name))
      }
    }

    $TargetMatches = [Collections.Generic.List[object]]::new()
    for ($NameIndex = 0; $NameIndex -lt $TargetNames.Count; $NameIndex++) {
      $TargetName = $TargetNames[$NameIndex]
      $ExpectedPackage = @($OfflineManifest.Packages | Where-Object { [IO.Path]::GetFileName($_.Name).Equals($TargetName, [StringComparison]::OrdinalIgnoreCase) })[0]
      foreach ($Entry in $Entries) {
        $EntryName = [IO.Path]::GetFileName($Entry.FullName)
        $MatchKind = if ($EntryName.Equals($TargetName, [StringComparison]::OrdinalIgnoreCase)) {
          0
        } elseif ($EntryName.StartsWith("$TargetName.", [StringComparison]::OrdinalIgnoreCase)) {
          1
        } else { continue }
        if ($ExpectedPackage -and $null -ne $ExpectedPackage.Size -and [long]$Entry.Length -ne [long]$ExpectedPackage.Size) { continue }
        $TargetMatches.Add([pscustomobject]@{ Entry = $Entry; TargetName = $TargetName; Package = $ExpectedPackage; Rank = ($NameIndex * 2) + $MatchKind })
      }
    }

    # Microsoft offline bundles may rename a package entry while retaining the selected app's exact
    # size and SHA-256 in OfflineManifest.gup. Use a unique declared-size match only as a candidate;
    # the exported bytes are hash-verified below before the nested parser sees them.
    if ($TargetMatches.Count -eq 0) {
      for ($PackageIndex = 0; $PackageIndex -lt $OfflineManifest.Packages.Count; $PackageIndex++) {
        $Package = $OfflineManifest.Packages[$PackageIndex]
        if ($null -eq $Package.Size -or $Package.HashSha256 -notmatch '^[0-9A-Fa-f]{64}$') { continue }
        foreach ($Entry in $Entries) {
          if ([long]$Entry.Length -ne [long]$Package.Size) { continue }
          $TargetMatches.Add([pscustomobject]@{
              Entry      = $Entry
              TargetName = [IO.Path]::GetFileName($Package.Name)
              Package    = $Package
              Rank       = 100 + $PackageIndex
            })
        }
      }
    }

    $NestedSetupInfo = $null
    $NestedSetupError = $null
    $TargetEntryName = $null
    if ($TargetMatches.Count -gt 0) {
      $RankedMatches = @($TargetMatches | Sort-Object Rank, { $_.Entry.FullName })
      if ($RankedMatches.Count -gt 1 -and $RankedMatches[0].Rank -eq $RankedMatches[1].Rank) {
        $NestedSetupError = "OfflineManifest.gup target '$($RankedMatches[0].TargetName)' matches multiple Omaha entries."
      } else {
        $Target = $RankedMatches[0]
        $TargetEntryName = $Target.Entry.FullName
        $NestedFolder = New-TempFolder
        $TargetPath = Resolve-SafeExtractionPath -DestinationPath $NestedFolder -RelativePath $Target.TargetName
        try {
          $TargetFile = Export-InstallerArchiveEntry -Entry $Target.Entry -DestinationPath $TargetPath -MaximumBytes $Script:ChromiumMaximumResourceBytes
          if ($Target.Package -and $Target.Package.HashSha256 -match '^[0-9A-Fa-f]{64}$') {
            $ActualHash = (Get-FileHash -LiteralPath $TargetFile.FullName -Algorithm SHA256).Hash
            if (-not $ActualHash.Equals($Target.Package.HashSha256, [StringComparison]::OrdinalIgnoreCase)) {
              throw "The Omaha target '$($Target.Entry.FullName)' does not match OfflineManifest.gup SHA-256 evidence."
            }
          }
          # The configured target is normally a bare mini-installer. Disable a second Omaha payload
          # walk so malformed recursive wrappers cannot cause unbounded nesting.
          $NestedSetupInfo = Get-ChromiumSetupInfo -Path $TargetFile.FullName -SkipOfflineManifest
        } catch {
          $NestedSetupError = $_.Exception.Message
        }
      }
    } elseif ($TargetNames.Count -gt 0) {
      $NestedSetupError = "The Omaha payload does not contain the executable '$($TargetNames[0])' selected by OfflineManifest.gup."
    }

    [pscustomobject]@{
      OfflineManifest  = $OfflineManifest
      NestedSetupInfo  = $NestedSetupInfo
      NestedSetupError = $NestedSetupError
      TargetEntryName  = $TargetEntryName
    }
  } finally {
    if ($NestedFolder) { Remove-Item -LiteralPath $NestedFolder -Recurse -Force -ErrorAction SilentlyContinue }
    Close-ChromiumOmahaArchive -Context $Context
  }
}

function Get-ChromiumOmahaOfflineManifestInfo {
  <#
  .SYNOPSIS
    Extract and parse a tagged Omaha wrapper's embedded offline manifest
  .PARAMETER Resource
    Validated PE resource evidence with file-relative offsets and bounded lengths.
  .PARAMETER ApplicationId
    Installer identity value used to select or report the matching static metadata record.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Resource,
    [string]$ApplicationId
  )

  (Get-ChromiumOmahaPayloadInfo -Resource $Resource -ApplicationId $ApplicationId -SkipNestedSetup).OfflineManifest
}

function Get-ChromiumSetupInfoFromContext {
  <#
  .SYNOPSIS
    Classify and read static metadata from Chromium-family setup wrappers
  .PARAMETER Context
    An open Chromium setup parser context
  .PARAMETER SkipOfflineManifest
    Skip expensive Omaha payload decoding when only the outer resource layout is needed
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Context,
    [Parameter(DontShow)][switch]$SkipOfflineManifest
  )

  $Resources = $Context.Resources
  $VersionInfo = $Context.VersionInfo
  $Tag = $Context.Tag
  $LayoutEvidence = $Context.Evidence
  $Variant = $LayoutEvidence.Variant
  $MiniArchive = $LayoutEvidence.MiniArchive
  $MiniSetup = $LayoutEvidence.MiniSetup
  $MiniArchiveResourceName = if ($MiniArchive) { [string]$MiniArchive.Name } else { $null }
  $MiniSetupResourceName = if ($MiniSetup) { [string]$MiniSetup.Name } else { $null }
  $MiniArchiveFileName = if ($MiniArchive) { ($MiniArchive.Name -replace '(?i)\.packed(?=\.7z$)', '').ToLowerInvariant() } else { $null }

  $OfflineManifest = $null
  $OfflineManifestError = $null
  $OmahaPayloadInfo = $null
  # Decode Omaha's expensive LZMA/BCJ2 payload only when a signed application identity makes the
  # enclosed manifest useful, unless the caller explicitly asks for layout-only evidence.
  $OfflineManifestChecked = $Variant -eq 'Omaha' -and $Tag.IsTagged -and -not $SkipOfflineManifest
  if ($OfflineManifestChecked) {
    try {
      $OmahaPayloadInfo = Get-ChromiumOmahaPayloadInfo -Resource $LayoutEvidence.OmahaResource.Resource -ApplicationId $Tag.ApplicationId
      $OfflineManifest = $OmahaPayloadInfo.OfflineManifest
    } catch {
      $OfflineManifestError = $_.Exception.Message
    }
  }
  $IsOnlineBootstrapper = if (-not $Tag.IsTagged) { $false } elseif ($Variant -eq 'ChromiumUpdater') { $true } elseif ($OfflineManifest) { $false } elseif ($OfflineManifestChecked -and -not $OfflineManifestError) { $true } else { $null }
  $ProductCode = $null
  $ProductCodeSource = $null

  $NestedSetupInfo = $null
  $NestedSetupError = $null
  if ($Variant -eq 'ChromiumMiniInstaller') {
    try {
      # The outer stub contains only generic launcher metadata. Inspect the exact nested setup.exe
      # selected by mini_installer resource precedence for literal ARP registry evidence.
      $NestedSetupInfo = Get-ChromiumMiniInstallerNestedSetupInfo -Context $Context
      if (-not $ProductCode -and $NestedSetupInfo.ProductCode) {
        $ProductCode = $NestedSetupInfo.ProductCode
        $ProductCodeSource = $NestedSetupInfo.ProductCodeSource
      }
    } catch {
      $NestedSetupError = $_.Exception.Message
    }
  } elseif ($OmahaPayloadInfo) {
    # Tagged offline wrappers contain the target installer named by OfflineManifest.gup. Its own
    # Chromium setup metadata, not the outer updater appguid, supplies ARP identity.
    $NestedSetupInfo = $OmahaPayloadInfo.NestedSetupInfo
    $NestedSetupError = $OmahaPayloadInfo.NestedSetupError
    if ($NestedSetupInfo -and $NestedSetupInfo.ProductCode) {
      $ProductCode = $NestedSetupInfo.ProductCode
      $ProductCodeSource = "OmahaTarget/$($NestedSetupInfo.ProductCodeSource)"
    }
  }

  $SupportedScopes = @()
  $Scope = $null
  $SupportsDualScope = $false
  $UserScopeSwitch = $null
  $MachineScopeSwitch = $null
  # Scope switches differ among bare mini-installers, untagged Omaha runtime installers, and tagged
  # updater metainstallers; do not apply one family's switch to another.
  if ($Variant -eq 'ChromiumMiniInstaller') {
    $SupportedScopes = @('user', 'machine')
    $SupportsDualScope = $true
    $Scope = 'user'
    $MachineScopeSwitch = '--system-level'
  } elseif ($Variant -eq 'Omaha' -and -not $Tag.IsTagged) {
    # Untagged Google Update packages install their embedded Omaha runtime.
    # Scope is encoded in the /install runtime tag rather than --system.
    $SupportedScopes = @('user', 'machine')
    $SupportsDualScope = $true
    $Scope = 'user'
    $UserScopeSwitch = '/install "runtime=true" /enterprise'
    $MachineScopeSwitch = '/install "runtime=true&needsadmin=true" /enterprise'
  } elseif (-not $Tag.IsTagged) {
    $SupportedScopes = @('user', 'machine')
    $SupportsDualScope = $true
    $Scope = 'user'
    $MachineScopeSwitch = '--system'
  } else {
    switch -Regex ([string]$Tag.NeedsAdmin) {
      '^(?i:true|yes|1)$' { $Scope = 'machine'; $SupportedScopes = @('machine'); break }
      '^(?i:false|no|0)$' { $Scope = 'user'; $SupportedScopes = @('user'); break }
      '^(?i:prefers)$' { $SupportedScopes = @('user', 'machine'); $SupportsDualScope = $true; break }
    }
  }

  $NestedFiles = [Collections.Generic.List[string]]::new()
  $ExecutedPayloads = [Collections.Generic.List[string]]::new()
  # Report the configured execution target separately from files that are merely physically nested.
  switch ($Variant) {
    'ChromiumMiniInstaller' {
      $NestedFiles.Add('setup.exe')
      if ($MiniArchiveFileName) { $NestedFiles.Add($MiniArchiveFileName) }
      $ExecutedPayloads.Add('setup.exe')
    }
    'ChromiumUpdater' {
      $NestedFiles.Add('updater.7z')
      $NestedFiles.Add('bin\updater.exe')
      $ExecutedPayloads.Add('bin\updater.exe')
    }
    'Omaha' {
      if ($OfflineManifest) {
        $NestedFiles.Add('OfflineManifest.gup')
        foreach ($Package in $OfflineManifest.Packages) { if ($Package.Name) { $NestedFiles.Add($Package.Name) } }
        if ($OmahaPayloadInfo.TargetEntryName -and -not $NestedFiles.Contains($OmahaPayloadInfo.TargetEntryName)) { $NestedFiles.Add($OmahaPayloadInfo.TargetEntryName) }
      } else { $NestedFiles.Add('BCJ2-decoded TAR payload') }
      if ($OfflineManifest.InstallAction) {
        $CommandParts = [Collections.Generic.List[string]]::new()
        if (-not [string]::IsNullOrWhiteSpace($OfflineManifest.InstallAction.Run)) { $CommandParts.Add($OfflineManifest.InstallAction.Run) }
        if (-not [string]::IsNullOrWhiteSpace($OfflineManifest.InstallAction.Arguments)) { $CommandParts.Add($OfflineManifest.InstallAction.Arguments) }
        $ExecutedPayloads.Add([string]::Join(' ', $CommandParts))
      } else { $ExecutedPayloads.Add('first executable in BCJ2-decoded TAR payload') }
    }
  }
  $ResourceInfo = [Collections.Generic.List[object]]::new()
  foreach ($Resource in $Resources) {
    $ResourceInfo.Add([pscustomobject]@{ Type = $Resource.Type; Name = $Resource.Name; Id = $Resource.Id; Offset = $Resource.Offset; Size = $Resource.Size })
  }
  $Warnings = [Collections.Generic.List[string]]::new()
  if ($OfflineManifestError) { $Warnings.Add("The tagged Omaha payload could not be checked for OfflineManifest.gup: $OfflineManifestError") }
  if ($NestedSetupError) { $Warnings.Add("The nested Chromium setup.exe could not be checked for ARP registry identity: $NestedSetupError") }
  if ($NestedSetupInfo) { foreach ($Warning in $NestedSetupInfo.Warnings) { $Warnings.Add($Warning) } }
  if ($Tag.ApplicationId -and -not $ProductCode) { $Warnings.Add("Updater appguid '$($Tag.ApplicationId)' is update-protocol identity; this wrapper does not contain source-backed target ARP ProductCode evidence.") }
  if ($IsOnlineBootstrapper) { $Warnings.Add("This setup is a tagged online bootstrapper. Outer version '$($VersionInfo.ProductVersion)' belongs to the updater and is not target-application version evidence; final version, ARP, and switch behavior require target-package evidence.") }
  if ($Variant -eq 'Omaha' -and -not $OfflineManifest) { $Warnings.Add('Omaha executes the first EXE in its decoded TAR payload. Expand and analyze that file before composing nested installer switches.') }
  if ($Variant -eq 'Omaha' -and -not $Tag.IsTagged) { $Warnings.Add('This is an untagged Omaha runtime installer. Its /install runtime tag controls user versus machine scope; do not substitute Chromium Updater --system switches.') }
  if ($Tag.IsTagged -and -not $SupportedScopes) { $Warnings.Add("The updater tag needsadmin value '$($Tag.NeedsAdmin)' does not provide deterministic WinGet scope evidence.") }

  $WritesAppsAndFeaturesEntry = if ($Variant -eq 'ChromiumMiniInstaller' -or $ProductCode) { $true } else { $null }
  [pscustomobject][ordered]@{
    Path                         = $Context.File.FullName
    InstallerType                = 'Chromium Setup'
    ProductCode                  = $ProductCode
    UpgradeCode                  = $null
    DisplayName                  = $Tag.ApplicationName ?? $VersionInfo.ProductName
    DisplayVersion               = if ($OfflineManifest) { $OfflineManifest.Version } elseif ($Tag.IsTagged) { $null } else { $VersionInfo.ProductVersion }
    Publisher                    = $VersionInfo.CompanyName
    Scope                        = $Scope
    DefaultInstallLocation       = $null
    WritesAppsAndFeaturesEntry   = $WritesAppsAndFeaturesEntry
    AppsAndFeaturesProductCode   = $WritesAppsAndFeaturesEntry -eq $true ? $ProductCode : $null
    AppsAndFeaturesInstallerType = $WritesAppsAndFeaturesEntry -eq $true ? 'exe' : $null
    Warnings                     = [string[]]@($Warnings | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
    # A tagged updater application ID is not necessarily the visible uninstall key. Preserve an
    # existing manifest ProductCode when source-backed vendor/channel mapping cannot resolve it.
    UnresolvedFields             = [string[]]@(
      if ([string]::IsNullOrWhiteSpace($ProductCode)) { 'ProductCode' }
      if ($Tag.IsTagged -and -not $OfflineManifest) { 'DisplayVersion' }
    )
    Variant                      = $Variant
    OuterProductVersion          = $VersionInfo.ProductVersion
    OriginalFilename             = $VersionInfo.OriginalFilename
    ProductCodeSource            = $ProductCodeSource
    ApplicationId                = $Tag.ApplicationId
    ArchiveResourceName          = $MiniArchiveResourceName
    SetupResourceName            = $MiniSetupResourceName
    SupportedScopes              = @($SupportedScopes)
    SupportsDualScope            = $SupportsDualScope
    UserScopeSwitch              = $UserScopeSwitch
    MachineScopeSwitch           = $MachineScopeSwitch
    IsOnlineBootstrapper         = $IsOnlineBootstrapper
    OfflineManifestChecked       = $OfflineManifestChecked
    UpdaterTag                   = $Tag
    OfflineManifest              = $OfflineManifest
    NestedSetupInfo              = $NestedSetupInfo
    InstallModes                 = if ($NestedSetupInfo -and $NestedSetupInfo.PSObject.Properties['InstallModes']) { @($NestedSetupInfo.InstallModes) } else { @() }
    Resources                    = $ResourceInfo.ToArray()
    NestedFiles                  = $NestedFiles.ToArray()
    ExtractedFiles               = $NestedFiles.ToArray()
    ExecutedPayloads             = $ExecutedPayloads.ToArray()
    RegistryAssociationInfo      = $null
    Protocols                    = @()
    FileExtensions               = @()
    CanExpand                    = $true
    ParserVersionInfo            = [pscustomobject]@{
      Parser      = 'Dumplings.PackageModule.ChromiumSetup'
      ParserMajor = 3
      Sources     = @('Chromium mini_installer B7, BL, and BN resource precedence', 'Chromium install_static InstallConstants and GetUninstallRegistryPath construction', 'Chromium Updater metainstaller resources and UTF-8 or UTF-16 certificate tag', 'Google Omaha LZMA/BCJ2/TAR payload and OfflineManifest.gup target execution', 'Microsoft Edge UTF-16 certificate tag framing')
    }
  }
}

function Get-ChromiumSetupInfo {
  <#
  .SYNOPSIS
    Classify and read static metadata from Chromium-family setup wrappers
  .PARAMETER Path
    The path to a bare mini-installer, Chromium Updater, or Omaha wrapper
  .PARAMETER SkipOfflineManifest
    Skip expensive Omaha payload decoding when only the outer resource layout is needed
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [Parameter(DontShow)][switch]$SkipOfflineManifest
  )

  process {
    $Context = Open-ChromiumSetupContext -Path $Path
    try { Get-ChromiumSetupInfoFromContext -Context $Context -SkipOfflineManifest:$SkipOfflineManifest }
    finally { Close-ChromiumSetupContext -Context $Context }
  }
}

function Resolve-ChromiumSetupProductCode {
  <#
  .SYNOPSIS
    Resolve a Chromium-family ARP key from parsed install modes and switches
  .DESCRIPTION
    Chromium's kInstallModes table supplies each source-defined selector and
    uninstall suffix. Legacy Chromium forks expose their selected product code
    through Get-ChromiumSetupInfo's corroborated switch and registry evidence.
  .PARAMETER Info
    The result returned by Get-ChromiumSetupInfo
  .PARAMETER InstallerSwitches
    The WinGet InstallerSwitches dictionary applied to the installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][psobject]$Info,
    [Parameter(Mandatory)][System.Collections.IDictionary]$InstallerSwitches
  )

  # Prefer explicit parser identity. A bare mini-installer may expose several source-defined modes,
  # in which case the manifest switches select the effective uninstall suffix.
  $MetadataProperty = $Info.PSObject.Properties['Metadata']
  $IdentityInfo = if ($MetadataProperty -and $MetadataProperty.Value) { $MetadataProperty.Value } else { $Info }
  $ProductCodeProperty = $IdentityInfo.PSObject.Properties['ProductCode']
  $ExplicitProductCode = if ($ProductCodeProperty -and -not [string]::IsNullOrWhiteSpace([string]$ProductCodeProperty.Value)) { [string]$ProductCodeProperty.Value } else { $null }
  if ($IdentityInfo.Variant -cne 'ChromiumMiniInstaller') {
    return $ExplicitProductCode
  }

  $ModesProperty = $IdentityInfo.PSObject.Properties['InstallModes']
  $InstallModes = if ($ModesProperty -and $ModesProperty.Value) { @($ModesProperty.Value) } else { @() }
  if ($InstallModes.Count -gt 0) {
    $SwitchValues = [Collections.Generic.List[string]]::new()
    foreach ($Value in $InstallerSwitches.Values) { if ($Value -is [string]) { $SwitchValues.Add($Value) } }
    $CommandLine = [string]::Join(' ', $SwitchValues)
    $SelectedModes = [Collections.Generic.List[object]]::new()
    foreach ($Mode in $InstallModes) {
      if ([string]::IsNullOrWhiteSpace([string]$Mode.InstallSwitch)) { continue }
      $Selector = "--$($Mode.InstallSwitch)"
      if ($CommandLine -match "(?i)(?<![A-Za-z0-9-])$([regex]::Escape($Selector))(?![A-Za-z0-9-])") { $SelectedModes.Add($Mode) }
    }
    # Contradictory mode selectors are not resolved by ordering; manifest validation must fix them.
    if ($SelectedModes.Count -gt 1) { return $null }
    if ($SelectedModes.Count -eq 1) { return [string]$SelectedModes[0].ProductCode }
    $PrimaryMode = @($InstallModes | Where-Object Index -EQ 0)[0]
    if ($PrimaryMode -and -not [string]::IsNullOrWhiteSpace([string]$PrimaryMode.ProductCode)) { return [string]$PrimaryMode.ProductCode }
  }

  return $ExplicitProductCode
}

function Open-ChromiumOmahaArchive {
  <#
  .SYNOPSIS
    Decode one source-backed Omaha resource into a bounded TAR archive context
  .PARAMETER Resource
    Validated PE resource evidence with file-relative offsets and bounded lengths.
  .PARAMETER MaximumExpandedBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Resource,
    [Parameter(Mandatory)][ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes
  )

  if ($Resource.Size -lt 13 -or $Resource.Size -gt $Script:ChromiumMaximumResourceBytes) {
    throw 'The Omaha LZMA resource is truncated or exceeds the parser limit.'
  }
  $TemporaryFolder = New-TempFolder
  $PackedPath = Join-Path $TemporaryFolder 'payload.lzma'
  $Bcj2Path = Join-Path $TemporaryFolder 'payload.bcj2'
  $TarPath = Join-Path $TemporaryFolder 'payload.tar'
  $PartPaths = [string[]]::new(4)
  for ($Index = 0; $Index -lt $PartPaths.Length; $Index++) { $PartPaths[$Index] = Join-Path $TemporaryFolder "bcj2-$Index.bin" }
  $Archive = $null
  try {
    # Read directly from the original PE resource range when possible; bridge callers may instead
    # provide standalone resource bytes, which are materialized in the temporary workspace.
    $SourcePath = $Resource.Path
    $ResourceOffset = [long]$Resource.Offset
    if (-not $SourcePath) {
      $null = Export-PEResourceData -Resource $Resource -DestinationPath $PackedPath -MaximumBytes $Script:ChromiumMaximumResourceBytes
      $SourcePath = $PackedPath
      $ResourceOffset = 0L
    }
    $Source = [IO.File]::Open($SourcePath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
      # Omaha resource layer 1 is LZMA-alone: five properties bytes and an eight-byte BCJ2 size.
      $Header = Read-BinaryBytes -Stream $Source -Offset $ResourceOffset -Count 13
      $Properties = [byte[]]::new(5)
      [Array]::Copy($Header, 0, $Properties, 0, $Properties.Length)
      $Bcj2SizeValue = [BitConverter]::ToUInt64($Header, 5)
      if ($Bcj2SizeValue -eq 0 -or $Bcj2SizeValue -gt [long]::MaxValue -or $Bcj2SizeValue -gt $MaximumExpandedBytes) {
        throw 'The Omaha LZMA output exceeds the configured limit.'
      }
      $Bcj2Size = [long]$Bcj2SizeValue
      $CompressedSize = [long]$Resource.Size - 13
      $Source.Position = $ResourceOffset + 13
      $Decoder = New-InstallerDecompressionStream -Algorithm Lzma -Stream $Source -Properties $Properties -CompressedSize $CompressedSize -UncompressedSize $Bcj2Size
      $Bcj2Output = [IO.File]::Open($Bcj2Path, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
      try {
        $null = Copy-BoundedStream -Source $Decoder -Destination $Bcj2Output -MaximumBytes $Bcj2Size -ExpectedBytes $Bcj2Size
        if ($Decoder.ReadByte() -ne -1) { throw 'The Omaha LZMA decoder exceeded its declared output size.' }
      } finally { $Bcj2Output.Dispose(); $Decoder.Dispose() }
    } finally { $Source.Dispose() }
    if ((Get-Item -LiteralPath $Bcj2Path -Force).Length -ne $Bcj2Size) { throw 'The Omaha LZMA output does not match its declared size.' }

    # Layer 2 begins with original TAR size and four BCJ2 stream sizes. Require their exact sum to
    # consume the decoded container before splitting streams.
    $Bcj2 = [IO.File]::OpenRead($Bcj2Path)
    try {
      if ($Bcj2.Length -lt 20) { throw 'The Omaha BCJ2 container is truncated.' }
      $Bcj2Header = Read-BinaryBytes -Stream $Bcj2 -Offset 0 -Count 20
      $OriginalSize = [long][BitConverter]::ToUInt32($Bcj2Header, 0)
      if ($OriginalSize -le 0 -or $OriginalSize -gt $MaximumExpandedBytes) { throw 'The Omaha decoded TAR exceeds the configured output limit.' }
      $PartSizes = [long[]]::new(4)
      $PartTotal = 0L
      for ($Index = 0; $Index -lt $PartSizes.Length; $Index++) {
        $PartSizes[$Index] = [long][BitConverter]::ToUInt32($Bcj2Header, 4 + ($Index * 4))
        $PartTotal += $PartSizes[$Index]
      }
      if (20L + $PartTotal -ne $Bcj2.Length) { throw 'The Omaha BCJ2 stream table is inconsistent with the decoded payload.' }
      $PartOffset = 20L
      for ($Index = 0; $Index -lt $PartPaths.Length; $Index++) {
        $PartOutput = [IO.File]::Open($PartPaths[$Index], [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { Copy-BinaryStreamRange -Source $Bcj2 -Destination $PartOutput -Offset $PartOffset -Length $PartSizes[$Index] }
        finally { $PartOutput.Dispose() }
        $PartOffset += $PartSizes[$Index]
      }
    } finally { $Bcj2.Dispose() }

    # Recombine the four BCJ2 streams into a bounded TAR file suitable for the shared archive API.
    $PartStreams = [IO.Stream[]]::new(4)
    for ($Index = 0; $Index -lt $PartStreams.Length; $Index++) { $PartStreams[$Index] = [IO.File]::OpenRead($PartPaths[$Index]) }
    $Bcj2Decoder = $null
    $TarOutput = $null
    try {
      $Bcj2Decoder = New-InstallerBcj2DecoderStream -Stream $PartStreams -UncompressedSize $OriginalSize
      $TarOutput = [IO.File]::Open($TarPath, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
      $null = Copy-BoundedStream -Source $Bcj2Decoder -Destination $TarOutput -MaximumBytes $OriginalSize -ExpectedBytes $OriginalSize
      if ($Bcj2Decoder.ReadByte() -ne -1) { throw 'The Omaha BCJ2 decoder exceeded its declared output size.' }
    } finally {
      if ($TarOutput) { $TarOutput.Dispose() }
      if ($Bcj2Decoder) { $Bcj2Decoder.Dispose() }
      foreach ($PartStream in $PartStreams) { if ($PartStream) { $PartStream.Dispose() } }
    }
    if ((Get-Item -LiteralPath $TarPath -Force).Length -ne $OriginalSize) { throw 'The Omaha BCJ2 output does not match its declared size.' }
    $Archive = Get-InstallerArchive -Path $TarPath
    return [pscustomobject]@{ Archive = $Archive; TemporaryFolder = $TemporaryFolder }
  } catch {
    if ($Archive) { $Archive.Dispose() }
    Remove-Item -LiteralPath $TemporaryFolder -Recurse -Force -ErrorAction SilentlyContinue
    throw
  }
}

function Close-ChromiumOmahaArchive {
  <#
  .SYNOPSIS
    Close a context returned by Open-ChromiumOmahaArchive
  .PARAMETER Context
    Parsed context or metadata object produced by the corresponding format reader.
  #>
  param ([Parameter(Mandatory)][psobject]$Context)
  try { $Context.Archive.Dispose() }
  finally { Remove-Item -LiteralPath $Context.TemporaryFolder -Recurse -Force -ErrorAction SilentlyContinue }
}

function Expand-ChromiumOmahaPayload {
  <#
  .SYNOPSIS
    Decode and extract an Omaha LZMA, BCJ2, and TAR resource
  .PARAMETER Resource
    Validated PE resource evidence with file-relative offsets and bounded lengths.
  .PARAMETER DestinationPath
    Destination path for bounded extraction or decoded output; payload-relative names are resolved beneath this path.
  .PARAMETER Name
    Exact name or wildcard used to select format records or payload entries.
  .PARAMETER MaximumExpandedBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  [OutputType([System.IO.FileInfo[]])]
  param (
    [Parameter(Mandatory)][psobject]$Resource,
    [Parameter(Mandatory)][string]$DestinationPath,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][long]$MaximumExpandedBytes
  )

  $Context = Open-ChromiumOmahaArchive -Resource $Resource -MaximumExpandedBytes $MaximumExpandedBytes
  try {
    $Selection = Export-InstallerArchiveSelection -Archive $Context.Archive -DestinationPath $DestinationPath -Name $Name -MaximumExpandedBytes $MaximumExpandedBytes
    return $Selection.Files
  } finally { Close-ChromiumOmahaArchive -Context $Context }
}

function Expand-ChromiumSetupInstaller {
  <#
  .SYNOPSIS
    Extract bounded payload resources from a Chromium-family setup wrapper
  .PARAMETER Path
    The path to the Chromium-family setup wrapper
  .PARAMETER DestinationPath
    The extraction directory
  .PARAMETER Name
    A wildcard matching full payload paths or file names
  .PARAMETER MaximumExpandedBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  [OutputType([System.IO.FileInfo[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [string]$Name = '*',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 4294967296
  )

  process {
    $Context = Open-ChromiumSetupContext -Path $Path
    try {
      if ([string]::IsNullOrWhiteSpace($DestinationPath)) { $DestinationPath = New-TempFolder }
      $null = New-Item -Path $DestinationPath -ItemType Directory -Force
      $Results = [Collections.Generic.List[System.IO.FileInfo]]::new(); $Expanded = 0L
      # Each variant has a distinct physical encoding path: raw resources, CAB/LZMA resources,
      # ordinary 7z archives, or Omaha's LZMA+BCJ2+TAR stack.
      foreach ($Evidence in $Context.Evidence.SelectedResources) {
        $Resource = $Evidence.Resource
        if ($Context.Evidence.Variant -eq 'Omaha') {
          foreach ($Result in (Expand-ChromiumOmahaPayload -Resource $Resource -DestinationPath $DestinationPath -Name $Name -MaximumExpandedBytes $MaximumExpandedBytes)) { $Results.Add($Result) }
          continue
        }
        if ($Evidence.Type -eq 'BN' -or $Evidence.Type -eq 'BD') {
          if (-not (Test-ExtractionPattern -Path $Evidence.Name -Pattern $Name)) { continue }
          $Expanded += $Evidence.Size
          if ($Expanded -gt $MaximumExpandedBytes) { throw 'Chromium resource extraction exceeds the configured output limit.' }
          $OutputPath = Resolve-SafeExtractionPath -DestinationPath $DestinationPath -RelativePath $Evidence.Name
          $Results.Add((Export-PEResourceData -Resource $Resource -DestinationPath $OutputPath -MaximumBytes ($MaximumExpandedBytes - $Expanded + $Evidence.Size)))
          continue
        }
        if ($Evidence.Type -eq 'BL') {
          # BL setup.ex_ resources are cabinet streams rather than 7z archives.
          $TemporaryPath = New-TempFile
          try {
            $null = Export-PEResourceData -Resource $Resource -DestinationPath $TemporaryPath -MaximumBytes $Script:ChromiumMaximumResourceBytes
            foreach ($Result in (Export-CabinetEntry -Path $TemporaryPath -DestinationPath $DestinationPath -Name $Name -MaximumExpandedBytes ($MaximumExpandedBytes - $Expanded))) {
              $File = Get-Item -LiteralPath $Result -Force
              $Expanded += $File.Length
              $Results.Add($File)
            }
          } finally { Remove-Item -LiteralPath $TemporaryPath -Force -ErrorAction SilentlyContinue }
          continue
        }

        # Restrict archive readers to the selected PE resource so they cannot consume adjacent
        # resources or the certificate table.
        $ResourceStream = New-BoundedReadStream -Stream $Context.Stream -Offset $Evidence.Offset -Length $Evidence.Size -LeaveOpen
        $Archive = $null
        try {
          $Archive = Get-InstallerArchive -Stream $ResourceStream
          foreach ($Entry in (Get-InstallerArchiveEntry -Archive $Archive)) {
            if ($Context.Evidence.Variant -eq 'ChromiumUpdater' -and $Entry.FullName -ieq 'updater.7z') {
              # Current updater resources contain a second archive. Spill it through the shared
              # seekable-stream helper and apply the same aggregate output limit.
              $NestedInput = Open-InstallerArchiveEntry -Entry $Entry
              $NestedContext = $null
              $NestedArchive = $null
              try {
                $NestedContext = New-InstallerSeekableStream -SourceStream $NestedInput -MaximumBytes ($MaximumExpandedBytes - $Expanded)
                $NestedArchive = Get-InstallerArchive -Stream $NestedContext.Stream
                foreach ($NestedEntry in (Get-InstallerArchiveEntry -Archive $NestedArchive)) {
                  if (-not (Test-ExtractionPattern -Path $NestedEntry.FullName -Pattern $Name)) { continue }
                  $Expanded += $NestedEntry.Length
                  if ($Expanded -gt $MaximumExpandedBytes) { throw 'Chromium updater archive extraction exceeds the configured output limit.' }
                  $NestedOutputPath = Resolve-SafeExtractionPath -DestinationPath $DestinationPath -RelativePath $NestedEntry.FullName
                  $Results.Add((Export-InstallerArchiveEntry -Entry $NestedEntry -DestinationPath $NestedOutputPath -MaximumBytes ($MaximumExpandedBytes - $Expanded + $NestedEntry.Length)))
                }
              } finally {
                if ($NestedArchive) { $NestedArchive.Dispose() }
                if ($NestedContext) { $NestedContext.Dispose() }
                $NestedInput.Dispose()
              }
            }
            if (Test-ExtractionPattern -Path $Entry.FullName -Pattern $Name) {
              $Expanded += $Entry.Length
              if ($Expanded -gt $MaximumExpandedBytes) { throw 'Chromium archive extraction exceeds the configured output limit.' }
              $OutputPath = Resolve-SafeExtractionPath -DestinationPath $DestinationPath -RelativePath $Entry.FullName
              $Results.Add((Export-InstallerArchiveEntry -Entry $Entry -DestinationPath $OutputPath -MaximumBytes ($MaximumExpandedBytes - $Expanded + $Entry.Length)))
            }
          }
        } finally {
          if ($Archive) { $Archive.Dispose() }
          $ResourceStream.Dispose()
        }
      }
      if ($Results.Count -eq 0) { throw "No Chromium Setup payload matched '$Name'." }
      return $Results.ToArray()
    } finally { Close-ChromiumSetupContext -Context $Context }
  }
}

function Test-ChromiumSetup {
  <#
  .SYNOPSIS
    Test whether a PE uses a supported Chromium Setup layout
  .PARAMETER Path
    The path to the candidate installer
  #>
  [OutputType([bool])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { try { $null = Get-ChromiumSetupInfo -Path $Path; return $true } catch { return $false } }
}

function Test-ChromiumMiniInstaller {
  <#
  .SYNOPSIS
    Test whether a PE is a bare Chromium mini-installer
  .PARAMETER Path
    The path to the candidate installer
  #>
  [OutputType([bool])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { try { return (Get-ChromiumSetupInfo -Path $Path).Variant -eq 'ChromiumMiniInstaller' } catch { return $false } }
}

function Test-ChromiumUpdater {
  <#
  .SYNOPSIS
    Test whether a PE is a Chromium/Google Updater metainstaller
  .PARAMETER Path
    The path to the candidate installer
  #>
  [OutputType([bool])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { try { return (Get-ChromiumSetupInfo -Path $Path).Variant -eq 'ChromiumUpdater' } catch { return $false } }
}

function Test-OmahaInstaller {
  <#
  .SYNOPSIS
    Test whether a PE is a Google Update/Omaha metainstaller
  .PARAMETER Path
    The path to the candidate installer
  #>
  [OutputType([bool])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { try { return (Get-ChromiumSetupInfo -Path $Path).Variant -eq 'Omaha' } catch { return $false } }
}

function Read-ProductVersionFromChromiumSetup {
  <#
  .SYNOPSIS
    Read the target version when static Chromium setup evidence provides it
  .PARAMETER Path
    The path to the Chromium setup installer
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-ChromiumSetupInfo -Path $Path).DisplayVersion }
}

function Read-ProductNameFromChromiumSetup {
  <#
  .SYNOPSIS
    Read the tagged application or outer Chromium setup name
  .PARAMETER Path
    The path to the Chromium setup installer
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-ChromiumSetupInfo -Path $Path).DisplayName }
}

function Read-PublisherFromChromiumSetup {
  <#
  .SYNOPSIS
    Read the outer Chromium setup publisher
  .PARAMETER Path
    The path to the Chromium setup installer
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-ChromiumSetupInfo -Path $Path).Publisher }
}

function Read-ProductCodeFromChromiumSetup {
  <#
  .SYNOPSIS
    Return explicit Chromium setup ARP ProductCode evidence when available
  .PARAMETER Path
    The path to the Chromium setup installer
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-ChromiumSetupInfo -Path $Path).ProductCode }
}

function Read-ScopeFromChromiumSetup {
  <#
  .SYNOPSIS
    Read deterministic Chromium setup scope evidence
  .PARAMETER Path
    The path to the Chromium setup installer
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-ChromiumSetupInfo -Path $Path).Scope }
}

function Read-SupportedScopesFromChromiumSetup {
  <#
  .SYNOPSIS
    Read supported Chromium setup scopes
  .PARAMETER Path
    The path to the Chromium setup installer
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-ChromiumSetupInfo -Path $Path).SupportedScopes }
}

function Read-ProtocolsFromChromiumSetup {
  <#
  .SYNOPSIS
    Read statically proven protocol associations from Chromium setup
  .PARAMETER Path
    The path to the Chromium setup installer
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-ChromiumSetupInfo -Path $Path).Protocols }
}

function Read-FileExtensionsFromChromiumSetup {
  <#
  .SYNOPSIS
    Read statically proven file associations from Chromium setup
  .PARAMETER Path
    The path to the Chromium setup installer
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-ChromiumSetupInfo -Path $Path).FileExtensions }
}

Export-ModuleMember -Function ConvertFrom-ChromiumUpdaterTagData, Read-ChromiumInstallerTag, Get-ChromiumSetupInfo, Resolve-ChromiumSetupProductCode, Expand-ChromiumSetupInstaller, Test-ChromiumSetup, Test-ChromiumMiniInstaller, Test-ChromiumUpdater, Test-OmahaInstaller, Read-ProductVersionFromChromiumSetup, Read-ProductNameFromChromiumSetup, Read-PublisherFromChromiumSetup, Read-ProductCodeFromChromiumSetup, Read-ScopeFromChromiumSetup, Read-SupportedScopesFromChromiumSetup, Read-ProtocolsFromChromiumSetup, Read-FileExtensionsFromChromiumSetup
