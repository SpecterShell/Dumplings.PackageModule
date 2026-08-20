# SPDX-License-Identifier: Apache-2.0
# Chromium mini-installer PE resources, install constants, and nested setup metadata.

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }
$UpdaterPath = (Join-Path $PSScriptRoot 'ChromiumUpdater.psm1')
$UpdaterModule = Get-Module ChromiumUpdater | Where-Object Path -EQ $UpdaterPath | Select-Object -First 1
if (-not $UpdaterModule) { $UpdaterModule = Import-Module $UpdaterPath -Global -PassThru }
foreach ($Entry in $UpdaterModule.ExportedVariables.GetEnumerator()) {
  Set-Variable -Scope Script -Name $Entry.Key -Value $Entry.Value.Value
}
$Script:UpdaterConfiguration = Get-ChromiumParserConfiguration

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
    return Export-PEResourceData -Resource $Evidence.Resource -DestinationPath $OutputPath -MaximumBytes $MaximumExpandedBytes -CollisionAction Overwrite
  }
  if ($Evidence.Type -eq 'BL') {
    $CabinetPath = New-TempFile
    try {
      $null = Export-PEResourceData -Resource $Evidence.Resource -DestinationPath $CabinetPath -MaximumBytes $Script:UpdaterConfiguration.MaximumResourceBytes -CollisionAction Overwrite
      $Files = @(Export-CabinetEntry -Path $CabinetPath -DestinationPath $DestinationPath -Name 'setup.exe' -CollisionAction Overwrite -MaximumExpandedBytes $MaximumExpandedBytes)
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
    Parse the source-defined configuration prefix of one Chromium InstallConstants record
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
    $ApplicationId.Text -notmatch '^(?:|\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}|[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})$' -or
    [string]::IsNullOrWhiteSpace($BaseApplicationName.Text) -or $BaseApplicationName.Text -match '[\x00-\x1F\\/]' -or
    $BaseApplicationId.Text -notmatch '^[A-Za-z0-9.]+$' -or $BrowserProgIdPrefix.Text -notmatch '^[A-Za-z0-9.]+$' -or
    $DirectLaunchUrlScheme.Text -notmatch '^(?:|[A-Za-z][A-Za-z0-9+.-]{0,63})$') { return $null }

  $SupportsSystemLevelOffset = $PointerSize -eq 8 ? 204 : 144
  $SupportsSystemLevel = [bool](Read-BinaryInteger -Stream $Stream -Offset ($Offset + $SupportsSystemLevelOffset) -Size 1)
  [pscustomobject]@{
    Offset                    = $Offset
    StructureSize             = $StructureSize
    Index                     = [int]$Index
    InstallSwitch             = $InstallSwitch.Text
    InstallSuffix             = $InstallSuffix.Text
    LogoSuffix                = $LogoSuffix.Text
    ApplicationId             = $ApplicationId.Text
    BaseApplicationName       = $BaseApplicationName.Text
    BaseApplicationNameOffset = $BaseApplicationName.Offset
    BaseApplicationId         = $BaseApplicationId.Text
    BrowserProgIdPrefix       = $BrowserProgIdPrefix.Text
    DirectLaunchUrlScheme     = $DirectLaunchUrlScheme.Text
    SupportsSystemLevel       = $SupportsSystemLevel
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
  $StructureSize = $PointerSize -eq 8 ? $Script:UpdaterConfiguration.InstallConstantsSize64 : $Script:UpdaterConfiguration.InstallConstantsSize32
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

  $Warnings = [Collections.Generic.List[object]]::new()
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
    Diagnostics   = @(ConvertTo-InstallerDiagnostic -InputObject @($Warnings.ToArray()) -Source 'ChromiumMiniInstaller' -Kind Incomplete -Areas Metadata)
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
    $InstallModeInfo = $null
    $Warnings = [Collections.Generic.List[object]]::new()
    $Stream = [IO.File]::Open($SetupFile.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
      # InstallConstants describes source-defined channel selectors and system-level support. It is
      # retained as configuration evidence, but is not used to construct an ARP ProductCode.
      $Layout = Get-PELayout -Stream $Stream
      if ($Layout) { $InstallModeInfo = Get-ChromiumInstallModeInfo -Stream $Stream -Layout $Layout }
    } catch {
      $Warnings.Add("The nested Chromium setup install modes could not be parsed: $($_.Exception.Message)")
    } finally {
      $Stream.Dispose()
    }
    if ($InstallModeInfo) { foreach ($Warning in $InstallModeInfo.Diagnostics) { $Warnings.Add($Warning) } }

    [pscustomobject]@{
      ProductName            = $VersionInfo.ProductName
      ProductVersion         = $VersionInfo.ProductVersion
      Publisher              = $VersionInfo.CompanyName
      InstallModes           = if ($InstallModeInfo) { @($InstallModeInfo.InstallModes) } else { @() }
      InstallConstantsOffset = if ($InstallModeInfo) { $InstallModeInfo.Offset } else { $null }
      InstallConstantsSize   = if ($InstallModeInfo) { $InstallModeInfo.StructureSize } else { $null }
      Diagnostics            = @(ConvertTo-InstallerDiagnostic -InputObject @($Warnings.ToArray()) -Source 'ChromiumMiniInstaller' -Kind Incomplete -Areas Metadata)
    }
  } finally {
    Remove-Item -LiteralPath $TemporaryFolder -Recurse -Force -ErrorAction SilentlyContinue
  }
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

Export-ModuleMember -Function *
