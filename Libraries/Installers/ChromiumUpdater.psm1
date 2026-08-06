# SPDX-License-Identifier: Apache-2.0
# Format sources: https://chromium.googlesource.com/chromium/src/+/main/chrome/installer/mini_installer,
# https://chromium.googlesource.com/chromium/src/+/main/chrome/install_static/install_util.cc,
# https://chromium.googlesource.com/chromium/src/+/main/chrome/updater/tag.h,
# https://chromium.googlesource.com/chromium/src/+/main/docs/updater/functional_spec.md,
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
#   Updater:        B7 updater.packed.7z -> updater.7z -> bin/updater.exe and
#                   optional bin/Offline/{bundle}/{app}/target installer
#   Omaha:          B resource 102 -> LZMA -> BCJ2 -> TAR/offline manifest
#   certificate:    "Gact2.0Omaha" + uint16 BE length + UTF-8 query, or
#                   bounded UTF-16LE start/end markers (Updater/Edge)
#
# Resource RVAs are mapped through PE sections. Tags are read only inside the
# certificate-table file range. Decoders receive declared input/output bounds.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:UpdaterConfiguration = [pscustomobject]@{
  TagMarker                   = [Text.Encoding]::ASCII.GetBytes('Gact2.0Omaha')
  WideTagPrefix               = [Text.Encoding]::Unicode.GetBytes('Gact2.0Omaha')
  WideTagSuffix               = [Text.Encoding]::Unicode.GetBytes('ahamO0.2tcaG')
  MicrosoftEdgeTagPrefix      = [Text.Encoding]::Unicode.GetBytes('MSEDGE_')
  MicrosoftEdgeTagSuffix      = [Text.Encoding]::Unicode.GetBytes('_EGDESM')
  MaximumCertificateBytes     = 16777216
  MaximumResourceBytes        = 2147483648
  MaximumOfflineManifestBytes = 4194304
  InstallConstantsSize64      = 232
  InstallConstantsSize32      = 168
}

# Preserve the historical exported constants, but keep parser execution on private immutable
# state because PowerShell links exported variables into the importing module's session state.
$Script:ChromiumUpdaterTagMarker = $Script:UpdaterConfiguration.TagMarker
$Script:ChromiumUpdaterWideTagPrefix = $Script:UpdaterConfiguration.WideTagPrefix
$Script:ChromiumUpdaterWideTagSuffix = $Script:UpdaterConfiguration.WideTagSuffix
$Script:ChromiumMaximumCertificateBytes = $Script:UpdaterConfiguration.MaximumCertificateBytes
$Script:ChromiumMaximumResourceBytes = $Script:UpdaterConfiguration.MaximumResourceBytes
$Script:ChromiumMaximumOfflineManifestBytes = $Script:UpdaterConfiguration.MaximumOfflineManifestBytes
$Script:ChromiumInstallConstantsSize64 = $Script:UpdaterConfiguration.InstallConstantsSize64
$Script:ChromiumInstallConstantsSize32 = $Script:UpdaterConfiguration.InstallConstantsSize32

function Get-ChromiumParserConfiguration {
  <#
  .SYNOPSIS
    Return the immutable limits and tag markers shared by Chromium parser layers.
  #>
  [OutputType([pscustomobject])]
  param ()
  return $Script:UpdaterConfiguration
}

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
  $OmahaTagOffsets = if ($Bytes.Length -gt 0) { @(Find-BinaryPattern -Bytes $Bytes -Pattern $Script:UpdaterConfiguration.TagMarker -Maximum 32) } else { @() }
  foreach ($Offset in $OmahaTagOffsets) {
    $LengthOffset = $Offset + $Script:UpdaterConfiguration.TagMarker.Length
    if ($LengthOffset + 2 -gt $Bytes.Length) { continue }
    $Length = ([int]$Bytes[$LengthOffset] -shl 8) -bor [int]$Bytes[$LengthOffset + 1]
    $TagOffset = $LengthOffset + 2
    if ($TagOffset + $Length -gt $Bytes.Length) { continue }
    $RawTag = if ($Length -gt 0) { [Text.Encoding]::UTF8.GetString($Bytes, $TagOffset, $Length) } else { '' }
    return ConvertFrom-ChromiumQueryTag -RawTag $RawTag -Offset $Offset -Length $Length -TagFormat 'OmahaCertificateTag'
  }

  $WideTagOffsets = if ($Bytes.Length -gt 0) { @(Find-BinaryPattern -Bytes $Bytes -Pattern $Script:UpdaterConfiguration.WideTagPrefix -Maximum 32) } else { @() }
  foreach ($Offset in $WideTagOffsets) {
    $TagOffset = $Offset + $Script:UpdaterConfiguration.WideTagPrefix.Length
    $SuffixOffset = $null
    foreach ($Candidate in (Find-BinaryPattern -Bytes $Bytes -Pattern $Script:UpdaterConfiguration.WideTagSuffix -StartOffset $TagOffset -Maximum 1)) {
      $SuffixOffset = $Candidate
      break
    }
    if ($null -eq $SuffixOffset) { continue }
    $Length = [int]($SuffixOffset - $TagOffset)
    if ($Length -lt 0 -or $Length % 2 -ne 0) { continue }
    $RawTag = if ($Length -gt 0) { [Text.Encoding]::Unicode.GetString($Bytes, $TagOffset, $Length) } else { '' }
    return ConvertFrom-ChromiumQueryTag -RawTag $RawTag -Offset $Offset -Length $Length -TagFormat 'ChromiumWideCertificateTag'
  }

  $EdgeTagOffsets = if ($Bytes.Length -gt 0) { @(Find-BinaryPattern -Bytes $Bytes -Pattern $Script:UpdaterConfiguration.MicrosoftEdgeTagPrefix -Maximum 32) } else { @() }
  foreach ($Offset in $EdgeTagOffsets) {
    $TagOffset = $Offset + $Script:UpdaterConfiguration.MicrosoftEdgeTagPrefix.Length
    $SuffixOffset = $null
    foreach ($Candidate in (Find-BinaryPattern -Bytes $Bytes -Pattern $Script:UpdaterConfiguration.MicrosoftEdgeTagSuffix -StartOffset $TagOffset -Maximum 1)) {
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
  if ($Certificate.Size -gt $Script:UpdaterConfiguration.MaximumCertificateBytes -or $Certificate.Rva + $Certificate.Size -gt $FileLength) {
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

function Get-ChromiumOfflineArchivePayloadInfo {
  <#
  .SYNOPSIS
    Parse an updater offline manifest and inspect the executable it configures
  .PARAMETER Archive
    Open caller-owned archive containing the offline manifest and target package.
  .PARAMETER ApplicationId
    Installer identity value used to select or report the matching static metadata record.
  .PARAMETER SourceName
    Format name used to make malformed-payload diagnostics actionable.
  .PARAMETER SkipNestedSetup
    Parse only OfflineManifest.gup without exporting and inspecting its configured target.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Archive,
    [string]$ApplicationId,
    [Parameter(Mandatory)][string]$SourceName,
    [switch]$SkipNestedSetup
  )

  $NestedFolder = $null
  try {
    $Entries = [Collections.Generic.List[object]]::new()
    $ManifestEntry = $null
    $ApplicationManifestName = if ([string]::IsNullOrWhiteSpace($ApplicationId)) { $null } else { "$ApplicationId.gup" }
    foreach ($Entry in (Get-InstallerArchiveEntry -Archive $Archive)) {
      $Entries.Add($Entry)
      $EntryName = [IO.Path]::GetFileName($Entry.FullName)
      if ($EntryName -ine 'OfflineManifest.gup' -and
        ([string]::IsNullOrWhiteSpace($ApplicationManifestName) -or $EntryName -ine $ApplicationManifestName)) { continue }
      if ($ManifestEntry) { throw "The $SourceName contains more than one matching offline manifest entry." }
      $ManifestEntry = $Entry
    }
    if (-not $ManifestEntry) {
      return [pscustomobject]@{ OfflineManifest = $null; NestedSetupInfo = $null; NestedSetupError = $null; ManifestEntryName = $null; TargetEntryName = $null }
    }

    $Text = Read-InstallerArchiveEntryText -Entry $ManifestEntry -MaximumBytes $Script:UpdaterConfiguration.MaximumOfflineManifestBytes
    $OfflineManifest = ConvertFrom-ChromiumOmahaOfflineManifest -Text $Text -ApplicationId $ApplicationId
    if ($SkipNestedSetup) {
      return [pscustomobject]@{ OfflineManifest = $OfflineManifest; NestedSetupInfo = $null; NestedSetupError = $null; ManifestEntryName = $ManifestEntry.FullName; TargetEntryName = $null }
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
        $NestedSetupError = "OfflineManifest.gup target '$($RankedMatches[0].TargetName)' matches multiple $SourceName entries."
      } else {
        $Target = $RankedMatches[0]
        $TargetEntryName = $Target.Entry.FullName
        $NestedFolder = New-TempFolder
        $TargetPath = Resolve-SafeExtractionPath -DestinationPath $NestedFolder -RelativePath $Target.TargetName
        try {
          $TargetFile = Export-InstallerArchiveEntry -Entry $Target.Entry -DestinationPath $TargetPath -MaximumBytes $Script:UpdaterConfiguration.MaximumResourceBytes
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
      OfflineManifest   = $OfflineManifest
      NestedSetupInfo   = $NestedSetupInfo
      NestedSetupError  = $NestedSetupError
      ManifestEntryName = $ManifestEntry.FullName
      TargetEntryName   = $TargetEntryName
    }
  } finally {
    if ($NestedFolder) { Remove-Item -LiteralPath $NestedFolder -Recurse -Force -ErrorAction SilentlyContinue }
  }
}

function Get-ChromiumOmahaPayloadInfo {
  <#
  .SYNOPSIS
    Decode an Omaha payload and inspect its optional offline target
  .PARAMETER Resource
    Validated PE resource evidence with file-relative offsets and bounded lengths.
  .PARAMETER ApplicationId
    Installer identity value used to select the matching offline application record.
  .PARAMETER SkipNestedSetup
    Parse only the offline manifest without exporting and inspecting its configured target.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Resource,
    [string]$ApplicationId,
    [switch]$SkipNestedSetup
  )

  $Context = Open-ChromiumOmahaArchive -Resource $Resource -MaximumExpandedBytes $Script:UpdaterConfiguration.MaximumResourceBytes
  try {
    Get-ChromiumOfflineArchivePayloadInfo -Archive $Context.Archive -ApplicationId $ApplicationId -SourceName 'Omaha payload' -SkipNestedSetup:$SkipNestedSetup
  } finally {
    Close-ChromiumOmahaArchive -Context $Context
  }
}

function Get-ChromiumUpdaterPayloadInfo {
  <#
  .SYNOPSIS
    Inspect a Chromium Updater archive for an embedded offline application
  .PARAMETER Context
    Open Chromium setup context whose installer stream remains owned by the caller.
  .PARAMETER ApplicationId
    Installer identity value used to select the matching offline application record.
  .PARAMETER SkipNestedSetup
    Parse only the offline manifest without exporting and inspecting its configured target.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Context,
    [string]$ApplicationId,
    [switch]$SkipNestedSetup
  )

  $Evidence = $Context.Evidence.UpdaterArchive
  if (-not $Evidence) { throw 'The Chromium Updater context does not contain its selected updater archive resource.' }
  $ResourceStream = New-BoundedReadStream -Stream $Context.Stream -Offset $Evidence.Offset -Length $Evidence.Size -LeaveOpen
  $OuterArchive = $null
  $NestedInput = $null
  $NestedContext = $null
  $NestedArchive = $null
  try {
    # updater.packed.7z contains one updater.7z. Offline installers place their manifest and target
    # under bin/Offline/{bundle-guid}/ inside that second archive.
    $OuterArchive = Get-InstallerArchive -Stream $ResourceStream
    $UpdaterEntries = @(Get-InstallerArchiveEntry -Archive $OuterArchive | Where-Object { $_.FullName -ieq 'updater.7z' })
    if ($UpdaterEntries.Count -ne 1) { throw 'The Chromium Updater resource does not contain exactly one updater.7z entry.' }
    $NestedInput = Open-InstallerArchiveEntry -Entry $UpdaterEntries[0]
    $NestedContext = New-InstallerSeekableStream -SourceStream $NestedInput -MaximumBytes $Script:UpdaterConfiguration.MaximumResourceBytes
    $NestedArchive = Get-InstallerArchive -Stream $NestedContext.Stream
    Get-ChromiumOfflineArchivePayloadInfo -Archive $NestedArchive -ApplicationId $ApplicationId -SourceName 'Chromium Updater archive' -SkipNestedSetup:$SkipNestedSetup
  } finally {
    if ($NestedArchive) { $NestedArchive.Dispose() }
    if ($NestedContext) { $NestedContext.Dispose() }
    if ($NestedInput) { $NestedInput.Dispose() }
    if ($OuterArchive) { $OuterArchive.Dispose() }
    $ResourceStream.Dispose()
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

function Open-ChromiumOmahaArchive {
  <#
  .SYNOPSIS
    Decode one source-backed Omaha resource into a bounded TAR archive context
  .PARAMETER Resource
    Validated PE resource evidence with file-relative offsets and bounded lengths.
  .PARAMETER MaximumExpandedBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  .PARAMETER CollisionAction
    Behavior when an output path already exists or is selected more than once.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Resource,
    [Parameter(Mandatory)][ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes
  )

  if ($Resource.Size -lt 13 -or $Resource.Size -gt $Script:UpdaterConfiguration.MaximumResourceBytes) {
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
      $null = Export-PEResourceData -Resource $Resource -DestinationPath $PackedPath -MaximumBytes $Script:UpdaterConfiguration.MaximumResourceBytes
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
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Rename',
    [Parameter(Mandatory)][long]$MaximumExpandedBytes
  )

  $Context = Open-ChromiumOmahaArchive -Resource $Resource -MaximumExpandedBytes $MaximumExpandedBytes
  try {
    $Selection = Export-InstallerArchiveSelection -Archive $Context.Archive -DestinationPath $DestinationPath -Name $Name -CollisionAction $CollisionAction -MaximumExpandedBytes $MaximumExpandedBytes
    return $Selection.Files
  } finally { Close-ChromiumOmahaArchive -Context $Context }
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

function Read-MsiChromiumUpdaterTag {
  <#
  .SYNOPSIS
    Read an appended Omaha product tag from a Chromium enterprise MSI.
  .DESCRIPTION
    Chromium's MSI signing pipeline stores the signed package data in the MSI
    DigitalSignature stream. This helper reads only that stream, validates the
    length framing, strict UTF-8 text, query keys, and recognized updater
    fields, and therefore cannot confuse a tagged embedded EXE with the MSI's
    TAGSTRING override.
  .PARAMETER Path
    Resolved or relative path to the MSI file. The package is opened read-only.
  .PARAMETER Database
    Open caller-owned Windows Installer database. The helper closes only its
    query records and stream, never the supplied database.
  .PARAMETER MaximumSignatureBytes
    Maximum number of bytes read from the MSI DigitalSignature stream.
  .OUTPUTS
    Normalized updater-tag evidence. IsTagged is false when no valid non-empty
    outer tag is present.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(ParameterSetName = 'Path', Mandatory)]
    [string]$Path,

    [Parameter(ParameterSetName = 'Database', Mandatory)]
    [Microsoft.Deployment.WindowsInstaller.Database]$Database,

    [ValidateRange(65549, 67108864)]
    [int]$MaximumSignatureBytes = 16777216
  )

  $OwnsDatabase = $PSCmdlet.ParameterSetName -eq 'Path'
  if ($OwnsDatabase) {
    $ResolvedPath = Convert-Path -Path $Path
    $Database = [Microsoft.Deployment.WindowsInstaller.Package.InstallPackage]::new($ResolvedPath, 'ReadOnly')
  }

  $View = $null
  $ParameterRecord = $null
  $DataRecord = $null
  $SignatureStream = $null
  try {
    $View = $Database.OpenView('SELECT `Data` FROM `_Streams` WHERE `Name` = ?')
    $ParameterRecord = [Microsoft.Deployment.WindowsInstaller.Record]::new(1)
    $ParameterRecord.SetString(1, "$([char]5)DigitalSignature")
    $View.Execute($ParameterRecord)
    $DataRecord = $View.Fetch()
    if (-not $DataRecord) { $SignatureBytes = [byte[]]::new(0) } else {
      $SignatureStream = $DataRecord.GetStream(1)
      if ($SignatureStream.Length -gt $MaximumSignatureBytes) {
        throw 'The MSI DigitalSignature stream exceeds the Chromium tag parser limit.'
      }
      $SignatureBytes = [byte[]]::new([int]$SignatureStream.Length)
      $SignatureStream.ReadExactly($SignatureBytes)
    }
  } finally {
    if ($SignatureStream) { $SignatureStream.Dispose() }
    if ($DataRecord) { $DataRecord.Close() }
    if ($ParameterRecord) { $ParameterRecord.Close() }
    if ($View) { $View.Close() }
    if ($OwnsDatabase -and $Database) { $Database.Close() }
  }

  $Marker = [Text.Encoding]::ASCII.GetBytes('Gact2.0Omaha')
  $Offsets = @(Find-BinaryPattern -Bytes $SignatureBytes -Pattern $Marker -Maximum 256)
  $EmptyMarkerOffset = $null
  $Utf8 = [Text.UTF8Encoding]::new($false, $true)

  # Inspect candidates from the end of the signed file. Embedded updater
  # binaries can contain the marker as program data, so framing alone is not
  # sufficient: a non-empty tag must also be a valid query with updater keys.
  for ($Index = $Offsets.Count - 1; $Index -ge 0; $Index--) {
    $Offset = [int]$Offsets[$Index]
    $LengthOffset = $Offset + $Marker.Length
    if ($LengthOffset + 2 -gt $SignatureBytes.Length) { continue }
    $Length = ([int]$SignatureBytes[$LengthOffset] -shl 8) -bor [int]$SignatureBytes[$LengthOffset + 1]
    $TagOffset = $LengthOffset + 2
    if ($TagOffset + $Length -gt $SignatureBytes.Length) { continue }
    if ($Length -eq 0) {
      if ($null -eq $EmptyMarkerOffset) { $EmptyMarkerOffset = $Offset }
      continue
    }

    try {
      $RawTag = $Utf8.GetString($SignatureBytes, $TagOffset, $Length)
    } catch {
      continue
    }
    if ($RawTag -match '[\x00-\x1F\x7F]') { continue }

    $Parameters = [ordered]@{}
    $ValidQuery = $true
    foreach ($Part in ($RawTag -split '&')) {
      $Pair = $Part -split '=', 2
      if ($Pair.Count -ne 2 -or $Pair[0] -notmatch '^[A-Za-z][A-Za-z0-9_.-]*$') {
        $ValidQuery = $false
        break
      }
      try {
        $Key = [Uri]::UnescapeDataString($Pair[0].Replace('+', ' '))
        $Parameters[$Key] = [Uri]::UnescapeDataString($Pair[1].Replace('+', ' '))
      } catch {
        $ValidQuery = $false
        break
      }
    }
    if (-not $ValidQuery -or
      -not ($Parameters.Contains('appguid') -or $Parameters.Contains('appid') -or $Parameters.Contains('needsadmin'))) {
      continue
    }

    return [pscustomobject][ordered]@{
      MarkerFound     = $true
      IsTagged        = $true
      TagFormat       = 'OmahaMsiTailTag'
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

  return [pscustomobject][ordered]@{
    MarkerFound     = $null -ne $EmptyMarkerOffset
    IsTagged        = $false
    TagFormat       = $null -ne $EmptyMarkerOffset ? 'OmahaMsiTailTag' : $null
    Offset          = $EmptyMarkerOffset
    Length          = 0
    RawTag          = $null
    Parameters      = [pscustomobject][ordered]@{}
    ApplicationId   = $null
    ApplicationName = $null
    NeedsAdmin      = $null
    Brand           = $null
  }
}

function Get-MsiChromiumEnterpriseInfoFromStaticTableInfo {
  <#
  .SYNOPSIS
    Interpret Chromium enterprise MSI custom actions and product-tag behavior.
  .DESCRIPTION
    Recognizes the source-defined SetProductTagProperty, tag override,
    BuildInstallCommand, ExtractTagInfoFromInstaller, and deferred DoInstall
    layout. Vendor-authored property actions are retained as conditional command
    modifiers instead of being treated as Chromium defaults.
  .PARAMETER StaticTableInfo
    Immutable MSI table projection returned by Get-MsiStaticTableInfo.
  .PARAMETER Database
    Optional caller-owned database used to read the outer MSI signature tag.
    Synthetic table-only callers still receive action evidence.
  .OUTPUTS
    Structured evidence describing the effective product tag, nested silent
    mode, immediate tag extraction, deferred execution, and whether the nested
    updater requires an already elevated caller in silent mode.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]
    [psobject]$StaticTableInfo,

    [AllowNull()]
    [Microsoft.Deployment.WindowsInstaller.Database]$Database
  )

  $Actions = @($StaticTableInfo.CustomActionRows)
  $ActionNames = @($Actions.Action)
  $RequiredActions = @('SetProductTagProperty', 'BuildInstallCommand', 'ExtractTagInfoFromInstaller', 'DoInstall')
  $IsDetected = -not ($RequiredActions | Where-Object { $_ -notin $ActionNames })
  if (-not $IsDetected) {
    return [pscustomobject][ordered]@{
      IsDetected                    = $false
      DefaultProductTag             = $null
      DefaultNeedsAdmin             = $null
      OuterTag                      = $null
      ProductTagSource              = $null
      EffectiveProductTag           = $null
      EffectiveNeedsAdmin           = $null
      InstallCommand                = $null
      SilentModifierActions         = [object[]]@()
      UsesPlainSilent               = $false
      AllowsSilentUac               = $false
      IsSilentAtNoUi                = $false
      IsSilentAtBasicUi             = $false
      SilentElevationBehavior       = 'NotApplicable'
      RequiresPreElevationForSilent = $false
      HasImmediateTagExtraction     = $false
      DeferredInstallerAction       = $null
      Notices                       = [string[]]@()
    }
  }

  $SetTagAction = $Actions | Where-Object Action -CEQ 'SetProductTagProperty' | Select-Object -First 1
  $BuildAction = $Actions | Where-Object Action -CEQ 'BuildInstallCommand' | Select-Object -First 1
  $ExtractAction = $Actions | Where-Object Action -CEQ 'ExtractTagInfoFromInstaller' | Select-Object -First 1
  $InstallAction = $Actions | Where-Object Action -CEQ 'DoInstall' | Select-Object -First 1
  $DefaultProductTag = [string]$SetTagAction.Target
  $DefaultNeedsAdmin = if ($DefaultProductTag -match '(?i)(?:^|&)needsAdmin=([^&]+)') { $Matches[1] } else { $null }

  $OuterTag = if ($Database) { Read-MsiChromiumUpdaterTag -Database $Database } else { $null }
  $EffectiveProductTag = $OuterTag -and $OuterTag.IsTagged ? $OuterTag.RawTag : $DefaultProductTag
  $EffectiveNeedsAdmin = $OuterTag -and $OuterTag.IsTagged ? $OuterTag.NeedsAdmin : $DefaultNeedsAdmin
  $ProductTagSource = $OuterTag -and $OuterTag.IsTagged ? 'OuterMsiTag' : 'DefaultProductTag'
  $InstallCommand = [string]$BuildAction.Target

  # Property-setting custom actions can append vendor switches after the source
  # template builds InstallCommand. Preserve their MSI conditions so UILevel=2
  # (none/quiet) is not confused with UILevel=3 (basic/passive).
  $SilentModifierActions = [System.Collections.Generic.List[object]]::new()
  foreach ($Action in @($Actions | Where-Object {
        [int]$_.Type -eq 51 -and $_.Source -ceq 'InstallCommand' -and $_.Action -cne 'BuildInstallCommand' -and
        [string]$_.Target -match '(?i)(?:^|\s)--silent(?:=\S+)?(?:\s|$)'
      })) {
    $Sequences = @($StaticTableInfo.SequenceRows | Where-Object Action -CEQ $Action.Action)
    $SilentModifierActions.Add([pscustomobject][ordered]@{
        Action     = [string]$Action.Action
        Target     = [string]$Action.Target
        Conditions = [string[]]@($Sequences.Condition | Where-Object { $_ })
        Sequences  = [object[]]$Sequences
      })
  }

  $BaseSilentMatch = [regex]::Match($InstallCommand, '(?i)(?:^|\s)--silent(?:=([^\s"]+))?(?=\s|$)')
  $UsesPlainSilent = $BaseSilentMatch.Success -and [string]::IsNullOrWhiteSpace($BaseSilentMatch.Groups[1].Value)
  $AllowsSilentUac = $BaseSilentMatch.Success -and $BaseSilentMatch.Groups[1].Value -ieq 'allow-uac'
  $IsSilentAtNoUi = $BaseSilentMatch.Success
  $IsSilentAtBasicUi = $BaseSilentMatch.Success
  foreach ($Modifier in $SilentModifierActions) {
    $ModifierAllowsUac = [string]$Modifier.Target -match '(?i)--silent=allow-uac(?:\s|$)'
    $ModifierUsesPlainSilent = [string]$Modifier.Target -match '(?i)(?:^|\s)--silent(?=\s|$)'
    foreach ($Condition in @($Modifier.Conditions)) {
      if ($Condition -match '(?i)\bUILevel\s*=\s*2\b') {
        $IsSilentAtNoUi = $true
        $UsesPlainSilent = $UsesPlainSilent -or $ModifierUsesPlainSilent
        $AllowsSilentUac = $AllowsSilentUac -or $ModifierAllowsUac
      }
      if ($Condition -match '(?i)\bUILevel\s*=\s*3\b') { $IsSilentAtBasicUi = $true }
    }
  }

  $NeedsElevation = $EffectiveNeedsAdmin -in @('true', 'prefers')
  $RequiresPreElevation = $IsSilentAtNoUi -and $UsesPlainSilent -and -not $AllowsSilentUac -and $NeedsElevation
  $SilentElevationBehavior = if ($RequiresPreElevation) {
    'RequiresPreElevation'
  } elseif ($IsSilentAtNoUi -and $AllowsSilentUac -and $NeedsElevation) {
    'CanPromptForElevation'
  } elseif ($EffectiveNeedsAdmin -ieq 'false') {
    'ProductTagDoesNotRequireElevation'
  } else {
    'Unknown'
  }

  $ExtractSequences = @($StaticTableInfo.SequenceRows | Where-Object Action -CEQ 'ExtractTagInfoFromInstaller')
  $InstallType = [int]$InstallAction.Type
  $Notices = [System.Collections.Generic.List[string]]::new()
  if ($RequiresPreElevation) {
    $Notices.Add('The nested Chromium Updater receives plain --silent. Chromium suppresses UAC in that mode, so the silent MSI path requires an already elevated Windows Installer context.')
  }
  if ([int]$ExtractAction.Type -eq 1 -and $ExtractSequences.Count -gt 0) {
    $Notices.Add('ExtractTagInfoFromInstaller is an immediate custom action. NoImpersonate does not elevate immediate actions, so a vendor-modified tag extractor can fail before deferred installation begins.')
  }

  return [pscustomobject][ordered]@{
    IsDetected                    = $true
    DefaultProductTag             = $DefaultProductTag
    DefaultNeedsAdmin             = $DefaultNeedsAdmin
    OuterTag                      = $OuterTag
    ProductTagSource              = $ProductTagSource
    EffectiveProductTag           = $EffectiveProductTag
    EffectiveNeedsAdmin           = $EffectiveNeedsAdmin
    InstallCommand                = $InstallCommand
    SilentModifierActions         = [object[]]$SilentModifierActions.ToArray()
    UsesPlainSilent               = $UsesPlainSilent
    AllowsSilentUac               = $AllowsSilentUac
    IsSilentAtNoUi                = $IsSilentAtNoUi
    IsSilentAtBasicUi             = $IsSilentAtBasicUi
    SilentElevationBehavior       = $SilentElevationBehavior
    RequiresPreElevationForSilent = $RequiresPreElevation
    HasImmediateTagExtraction     = [int]$ExtractAction.Type -eq 1 -and $ExtractSequences.Count -gt 0
    DeferredInstallerAction       = [pscustomobject][ordered]@{
      Action        = [string]$InstallAction.Action
      Type          = $InstallType
      Source        = [string]$InstallAction.Source
      Target        = [string]$InstallAction.Target
      IsDeferred    = ($InstallType -band 0x0400) -ne 0
      NoImpersonate = ($InstallType -band 0x0800) -ne 0
      Sequences     = [object[]]@($StaticTableInfo.SequenceRows | Where-Object Action -CEQ 'DoInstall')
    }
    Notices                       = [string[]]$Notices.ToArray()
  }
}

Export-ModuleMember -Function * -Variable 'Chromium*'
