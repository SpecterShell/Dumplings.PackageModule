# SPDX-License-Identifier: MIT
# Format sources: https://chromium.googlesource.com/chromium/src/+/main/chrome/installer/mini_installer,
# https://chromium.googlesource.com/chromium/src/+/main/chrome/updater/tag.h,
# https://github.com/google/omaha/blob/main/omaha/installers/build_metainstaller.py,
# https://github.com/brave/brave-core/tree/master/chromium_src/chrome/install_static, and
# https://learn.microsoft.com/microsoft-edge/webview2/concepts/distribution.
# Static Chromium installer parser. It distinguishes the bare Chromium mini
# installer, Chromium/Google Updater, and legacy Google Update/Omaha wrappers.
# No installer payload or update command is executed.

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
$Script:BraveProductCodeByAppGuid = @{
  '{AFE6A462-C574-4B8A-AF43-4CC60DF4563B}' = 'BraveSoftware Brave-Browser'
  '{103BD053-949B-43A8-9120-2E424887DE11}' = 'BraveSoftware Brave-Browser-Beta'
  '{CB2150F2-595F-4633-891A-E39720CE0531}' = 'BraveSoftware Brave-Browser-Dev'
  '{C6CB981E-DB30-4876-8639-109F8933582C}' = 'BraveSoftware Brave-Browser-Nightly'
  '{F1EF32DE-F987-4289-81D2-6C4780027F9B}' = 'BraveSoftware Brave-Origin'
  '{56DA94FD-D872-416B-BFC4-1D7011DA7473}' = 'BraveSoftware Brave-Origin-Beta'
  '{716D6A4A-D071-47A8-AC64-DBDE3EE3797B}' = 'BraveSoftware Brave-Origin-Dev'
  '{50474E96-9CD2-4BC8-B0A7-0D4B6EF2E709}' = 'BraveSoftware Brave-Origin-Nightly'
}
$Script:MicrosoftEdgeProductCodeByAppGuid = @{
  # Microsoft documents this app ID as the WebView2 Runtime client registry key.
  '{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}' = 'Microsoft EdgeWebView'
}

function ConvertFrom-ChromiumQueryTag {
  <#
  .SYNOPSIS
    Convert one updater query string into normalized tag evidence
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
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][psobject]$Layout
  )

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
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)

  $File = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
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
  #>
  param ([Parameter(Mandatory)][psobject]$Context)
  $Context.Stream.Dispose()
}

function Resolve-BraveChromiumProductCode {
  <#
  .SYNOPSIS
    Resolve Brave's updater application identity to its uninstall registry key
  .PARAMETER ApplicationId
    The appguid from the signed Omaha tag
  .PARAMETER Publisher
    The outer executable publisher used to restrict the Brave-specific mapping
  #>
  [OutputType([string])]
  param (
    [string]$ApplicationId,
    [string]$Publisher
  )

  if ([string]::IsNullOrWhiteSpace($ApplicationId) -or ([string]$Publisher).TrimEnd('.') -cne 'BraveSoftware Inc') { return $null }
  $Script:BraveProductCodeByAppGuid[$ApplicationId.ToUpperInvariant()]
}

function Resolve-MicrosoftEdgeChromiumProductCode {
  <#
  .SYNOPSIS
    Resolve a documented Microsoft Edge updater client identity to its ARP key
  .PARAMETER ApplicationId
    The appguid from the signed Microsoft Edge certificate tag
  .PARAMETER Publisher
    The outer executable publisher used to restrict the Microsoft-specific mapping
  #>
  [OutputType([string])]
  param (
    [string]$ApplicationId,
    [string]$Publisher
  )

  if ([string]::IsNullOrWhiteSpace($ApplicationId) -or ([string]$Publisher).TrimEnd('.') -cne 'Microsoft Corporation') { return $null }
  $Script:MicrosoftEdgeProductCodeByAppGuid[$ApplicationId.ToUpperInvariant()]
}

function ConvertFrom-ChromiumOmahaOfflineManifest {
  <#
  .SYNOPSIS
    Read target package and execution evidence from OfflineManifest.gup
  .PARAMETER Path
    The path to an extracted Omaha offline manifest
  .PARAMETER ApplicationId
    The tagged application identity used to select the matching app element
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, ParameterSetName = 'Path')][string]$Path,
    [Parameter(Mandatory, ParameterSetName = 'Text')][string]$Text,
    [string]$ApplicationId
  )

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

function Get-ChromiumOmahaOfflineManifestInfo {
  <#
  .SYNOPSIS
    Extract and parse a tagged Omaha wrapper's embedded offline manifest
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Resource,
    [string]$ApplicationId
  )

  $Context = Open-ChromiumOmahaArchive -Resource $Resource -MaximumExpandedBytes $Script:ChromiumMaximumResourceBytes
  try {
    foreach ($Entry in (Get-InstallerArchiveEntry -Archive $Context.Archive)) {
      if ($Entry.FullName -ine 'OfflineManifest.gup' -and [IO.Path]::GetFileName($Entry.FullName) -ine 'OfflineManifest.gup') { continue }
      $Text = Read-InstallerArchiveEntryText -Entry $Entry -MaximumBytes $Script:ChromiumMaximumOfflineManifestBytes
      return ConvertFrom-ChromiumOmahaOfflineManifest -Text $Text -ApplicationId $ApplicationId
    }
    return $null
  } finally { Close-ChromiumOmahaArchive -Context $Context }
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
  $OfflineManifestChecked = $Variant -eq 'Omaha' -and $Tag.IsTagged -and -not $SkipOfflineManifest
  if ($OfflineManifestChecked) {
    try {
      $OfflineManifest = Get-ChromiumOmahaOfflineManifestInfo -Resource $LayoutEvidence.OmahaResource.Resource -ApplicationId $Tag.ApplicationId
    } catch {
      $OfflineManifestError = $_.Exception.Message
    }
  }
  $IsOnlineBootstrapper = if (-not $Tag.IsTagged) { $false } elseif ($Variant -eq 'ChromiumUpdater') { $true } elseif ($OfflineManifest) { $false } elseif ($OfflineManifestChecked -and -not $OfflineManifestError) { $true } else { $null }
  $ProductCode = Resolve-BraveChromiumProductCode -ApplicationId $Tag.ApplicationId -Publisher $VersionInfo.CompanyName
  if (-not $ProductCode) {
    $ProductCode = Resolve-MicrosoftEdgeChromiumProductCode -ApplicationId $Tag.ApplicationId -Publisher $VersionInfo.CompanyName
  }

  $SupportedScopes = @()
  $Scope = $null
  $SupportsDualScope = $false
  $UserScopeSwitch = $null
  $MachineScopeSwitch = $null
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
  if ($Tag.ApplicationId -and -not $ProductCode) { $Warnings.Add("Updater appguid '$($Tag.ApplicationId)' is update-protocol identity, not an ARP ProductCode.") }
  if ($IsOnlineBootstrapper) { $Warnings.Add("This setup is a tagged online bootstrapper. Outer version '$($VersionInfo.ProductVersion)' belongs to the updater and is not target-application version evidence; final version, ARP, and switch behavior require target-package evidence.") }
  if ($Variant -eq 'Omaha' -and -not $OfflineManifest) { $Warnings.Add('Omaha executes the first EXE in its decoded TAR payload. Expand and analyze that file before composing nested installer switches.') }
  if ($Variant -eq 'Omaha' -and -not $Tag.IsTagged) { $Warnings.Add('This is an untagged Omaha runtime installer. Its /install runtime tag controls user versus machine scope; do not substitute Chromium Updater --system switches.') }
  if ($Tag.IsTagged -and -not $SupportedScopes) { $Warnings.Add("The updater tag needsadmin value '$($Tag.NeedsAdmin)' does not provide deterministic WinGet scope evidence.") }

  [pscustomobject]@{
    InstallerType              = 'Chromium Setup'
    Variant                    = $Variant
    ProductName                = $VersionInfo.ProductName
    DisplayName                = $Tag.ApplicationName ?? $VersionInfo.ProductName
    DisplayVersion             = if ($OfflineManifest) { $OfflineManifest.Version } elseif ($Tag.IsTagged) { $null } else { $VersionInfo.ProductVersion }
    OuterProductVersion        = $VersionInfo.ProductVersion
    Publisher                  = $VersionInfo.CompanyName
    OriginalFilename           = $VersionInfo.OriginalFilename
    ProductCode                = $ProductCode
    ApplicationId              = $Tag.ApplicationId
    ArchiveResourceName        = $MiniArchiveResourceName
    SetupResourceName          = $MiniSetupResourceName
    Scope                      = $Scope
    SupportedScopes            = @($SupportedScopes)
    SupportsDualScope          = $SupportsDualScope
    UserScopeSwitch            = $UserScopeSwitch
    MachineScopeSwitch         = $MachineScopeSwitch
    IsOnlineBootstrapper       = $IsOnlineBootstrapper
    OfflineManifestChecked     = $OfflineManifestChecked
    UpdaterTag                 = $Tag
    OfflineManifest            = $OfflineManifest
    Resources                  = $ResourceInfo.ToArray()
    NestedFiles                = $NestedFiles.ToArray()
    ExtractedFiles             = $NestedFiles.ToArray()
    ExecutedPayloads           = $ExecutedPayloads.ToArray()
    WritesAppsAndFeaturesEntry = if ($Variant -eq 'ChromiumMiniInstaller' -or $ProductCode) { $true } else { $null }
    RegistryAssociationInfo    = $null
    Protocols                  = @()
    FileExtensions             = @()
    CanExpand                  = $true
    Warnings                   = $Warnings.ToArray()
    ParserVersionInfo          = [pscustomobject]@{
      Parser      = 'Dumplings.PackageModule.ChromiumSetup'
      ParserMajor = 2
      Sources     = @('Chromium mini_installer B7, BL, and BN resource precedence', 'Chromium Updater metainstaller resources and UTF-8 or UTF-16 certificate tag', 'Google Omaha LZMA/BCJ2/TAR payload and OfflineManifest.gup', 'Brave install-mode app GUID and uninstall-key definitions', 'Microsoft Edge UTF-16 certificate tag and documented WebView2 client identity')
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
    Resolve a Chromium-family ARP key from deterministic branding and switches
  .DESCRIPTION
    Vivaldi has one product-specific uninstall key across its mini-installer
    channels. Google uses the same mini-installer layout for multiple Chrome
    channels, whose command-line switches select different uninstall keys.
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

  $MetadataProperty = $Info.PSObject.Properties['Metadata']
  $IdentityInfo = if ($MetadataProperty -and $MetadataProperty.Value) { $MetadataProperty.Value } else { $Info }
  $ProductCodeProperty = $IdentityInfo.PSObject.Properties['ProductCode']
  if ($ProductCodeProperty -and -not [string]::IsNullOrWhiteSpace([string]$ProductCodeProperty.Value)) {
    return [string]$ProductCodeProperty.Value
  }
  if ($IdentityInfo.Variant -cne 'ChromiumMiniInstaller') {
    return $null
  }

  $ArchiveResourceName = $IdentityInfo.PSObject.Properties.Name -contains 'ArchiveResourceName' ? [string]$IdentityInfo.ArchiveResourceName : ''
  if (([string]$IdentityInfo.Publisher).TrimEnd('.') -ceq 'Vivaldi Technologies AS' -and
    $IdentityInfo.ProductName -ceq 'Vivaldi Installer' -and
    $ArchiveResourceName -match '(?i)^vivaldi(?:\.packed)?\.7z$') {
    return 'Vivaldi'
  }

  if ($IdentityInfo.Publisher -cne 'Google LLC' -or $IdentityInfo.ProductName -cne 'Google Chrome Installer') { return $null }

  $SwitchValues = [Collections.Generic.List[string]]::new()
  foreach ($Value in $InstallerSwitches.Values) { if ($Value -is [string]) { $SwitchValues.Add($Value) } }
  $CommandLine = [string]::Join(' ', $SwitchValues)
  $Channels = @(
    [pscustomobject]@{ Switch = '--chrome-sxs'; ProductCode = 'Google Chrome SxS' }
    [pscustomobject]@{ Switch = '--chrome-beta'; ProductCode = 'Google Chrome Beta' }
    [pscustomobject]@{ Switch = '--chrome-dev'; ProductCode = 'Google Chrome Dev' }
  )
  $SelectedChannel = $null
  foreach ($Channel in $Channels) {
    if ($CommandLine -notmatch "(?i)(?<!\S)$([regex]::Escape($Channel.Switch))(?!\S)") { continue }
    if ($SelectedChannel) { return $null }
    $SelectedChannel = $Channel
  }
  if ($SelectedChannel) { return $SelectedChannel.ProductCode }

  # An unqualified Google Chrome mini-installer selects the stable channel.
  return 'Google Chrome'
}

function Open-ChromiumOmahaArchive {
  <#
  .SYNOPSIS
    Decode one source-backed Omaha resource into a bounded TAR archive context
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
    $SourcePath = $Resource.Path
    $ResourceOffset = [long]$Resource.Offset
    if (-not $SourcePath) {
      $null = Export-PEResourceData -Resource $Resource -DestinationPath $PackedPath -MaximumBytes $Script:ChromiumMaximumResourceBytes
      $SourcePath = $PackedPath
      $ResourceOffset = 0L
    }
    $Source = [IO.File]::Open($SourcePath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
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
  #>
  param ([Parameter(Mandatory)][psobject]$Context)
  try { $Context.Archive.Dispose() }
  finally { Remove-Item -LiteralPath $Context.TemporaryFolder -Recurse -Force -ErrorAction SilentlyContinue }
}

function Expand-ChromiumOmahaPayload {
  <#
  .SYNOPSIS
    Decode and extract an Omaha LZMA, BCJ2, and TAR resource
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

        $ResourceStream = New-BoundedReadStream -Stream $Context.Stream -Offset $Evidence.Offset -Length $Evidence.Size -LeaveOpen
        $Archive = $null
        try {
          $Archive = Get-InstallerArchive -Stream $ResourceStream
          foreach ($Entry in (Get-InstallerArchiveEntry -Archive $Archive)) {
            if ($Context.Evidence.Variant -eq 'ChromiumUpdater' -and $Entry.FullName -ieq 'updater.7z') {
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
