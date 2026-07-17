# SPDX-License-Identifier: MIT
# Format sources: https://chromium.googlesource.com/chromium/src, https://github.com/google/omaha,
# and https://github.com/brave/brave-core/tree/master/chromium_src/chrome/install_static
# Static Chromium installer parser. It distinguishes the bare Chromium mini
# installer, Chromium/Google Updater, and legacy Google Update/Omaha wrappers.
# No installer payload or update command is executed.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:ChromiumUpdaterTagMarker = [Text.Encoding]::ASCII.GetBytes('Gact2.0Omaha')
$Script:ChromiumMaximumCertificateBytes = 16777216
$Script:ChromiumMaximumResourceBytes = 2147483648
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

function ConvertFrom-ChromiumUpdaterTagData {
  <#
  .SYNOPSIS
    Parse the Chromium Updater/Omaha tag framing from certificate bytes
  .PARAMETER Bytes
    Authenticode certificate-table bytes containing an optional updater tag
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][byte[]]$Bytes)

  foreach ($Offset in @(Find-BinaryPattern -Bytes $Bytes -Pattern $Script:ChromiumUpdaterTagMarker -Maximum 32)) {
    $LengthOffset = $Offset + $Script:ChromiumUpdaterTagMarker.Length
    if ($LengthOffset + 2 -gt $Bytes.Length) { continue }
    $Length = ([int]$Bytes[$LengthOffset] -shl 8) -bor [int]$Bytes[$LengthOffset + 1]
    $TagOffset = $LengthOffset + 2
    if ($TagOffset + $Length -gt $Bytes.Length) { continue }

    $RawTag = if ($Length -gt 0) { [Text.Encoding]::UTF8.GetString($Bytes, $TagOffset, $Length) } else { '' }
    $Parameters = [ordered]@{}
    foreach ($Part in @($RawTag -split '&')) {
      if ([string]::IsNullOrWhiteSpace($Part)) { continue }
      $Pair = $Part -split '=', 2
      $Key = [Uri]::UnescapeDataString($Pair[0].Replace('+', ' '))
      $Value = if ($Pair.Count -gt 1) { [Uri]::UnescapeDataString($Pair[1].Replace('+', ' ')) } else { '' }
      $Parameters[$Key] = $Value
    }

    return [pscustomobject]@{
      MarkerFound    = $true
      IsTagged       = $Length -gt 0
      Offset         = [long]$Offset
      Length         = [int]$Length
      RawTag         = $RawTag
      Parameters     = [pscustomobject]$Parameters
      ApplicationId  = $Parameters['appguid'] ?? $Parameters['appid']
      ApplicationName = $Parameters['appname']
      NeedsAdmin     = $Parameters['needsadmin']
      Brand          = $Parameters['brand']
    }
  }

  return [pscustomobject]@{
    MarkerFound     = $false
    IsTagged        = $false
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
    $Layout = Get-PELayout -Path $File.FullName
    if (-not $Layout) { throw 'The file is not a valid PE image.' }
    $Certificate = $Layout.DataDirectories.Certificate
    # The PE security-directory RVA is defined as a file offset.
    if (-not $Certificate -or $Certificate.Rva -eq 0 -or $Certificate.Size -eq 0) {
      return ConvertFrom-ChromiumUpdaterTagData -Bytes ([byte[]]::new(0))
    }
    if ($Certificate.Size -gt $Script:ChromiumMaximumCertificateBytes -or $Certificate.Rva + $Certificate.Size -gt $File.Length) {
      throw 'The PE certificate table exceeds the Chromium tag parser limits.'
    }
    $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
      $Bytes = Read-BinaryBytes -Stream $Stream -Offset ([long]$Certificate.Rva) -Count ([int]$Certificate.Size)
    } finally {
      $Stream.Dispose()
    }
    return ConvertFrom-ChromiumUpdaterTagData -Bytes $Bytes
  }
}

function Get-ChromiumSetupResourceEvidence {
  <#
  .SYNOPSIS
    Normalize Chromium named-resource evidence for classification
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][string]$Path)

  foreach ($Resource in @(Get-PEResourceInfo -Path $Path)) {
    $Type = if ($Resource.TypeName) { [string]$Resource.TypeName } else { [string]$Resource.TypeId }
    $Name = if ($Resource.Name) { [string]$Resource.Name } else { [string]$Resource.Id }
    if ($Type.ToUpperInvariant() -notin @('B', 'B7', 'BL', 'BN', 'BD')) { continue }
    [pscustomobject]@{
      Type       = $Type.ToUpperInvariant()
      Name       = $Name
      Id         = $Resource.Id
      Offset     = [long]$Resource.Offset
      Size       = [long]$Resource.Size
      Resource   = $Resource
    }
  }
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
    [Parameter(Mandatory)][string]$Path,
    [string]$ApplicationId
  )

  $Settings = [Xml.XmlReaderSettings]::new()
  $Settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
  $Settings.XmlResolver = $null
  $Settings.IgnoreComments = $true
  $Reader = [Xml.XmlReader]::Create($Path, $Settings)
  try {
    $Document = [Xml.XmlDocument]::new()
    $Document.XmlResolver = $null
    $Document.Load($Reader)
  } finally {
    $Reader.Dispose()
  }

  $Applications = @($Document.SelectNodes('/response/app'))
  $Application = if ([string]::IsNullOrWhiteSpace($ApplicationId)) {
    $Applications | Select-Object -First 1
  } else {
    $Applications | Where-Object { $_.GetAttribute('appid').Equals($ApplicationId, [StringComparison]::OrdinalIgnoreCase) } | Select-Object -First 1
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
  foreach ($Package in @($Manifest.SelectNodes('packages/package'))) {
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
  foreach ($Action in @($Manifest.SelectNodes('actions/action'))) {
    $Actions.Add([pscustomobject]@{
        Event      = $Action.GetAttribute('event')
        Run        = $Action.GetAttribute('run')
        Arguments  = $Action.GetAttribute('arguments').Trim()
        NeedsAdmin = $Action.GetAttribute('needsadmin')
      })
  }

  [pscustomobject]@{
    ApplicationId = $Application.GetAttribute('appid')
    Version       = $Manifest.GetAttribute('version')
    Packages      = $Packages.ToArray()
    Actions       = $Actions.ToArray()
    InstallAction = $Actions | Where-Object Event -IEQ 'install' | Select-Object -First 1
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

  $TemporaryFolder = New-TempFolder
  try {
    $ManifestFiles = @(Expand-ChromiumOmahaPayload -Resource $Resource -DestinationPath $TemporaryFolder -Name 'OfflineManifest.gup' -MaximumExpandedBytes $Script:ChromiumMaximumResourceBytes)
    if ($ManifestFiles.Count -eq 0) { return $null }
    ConvertFrom-ChromiumOmahaOfflineManifest -Path $ManifestFiles[0].FullName -ApplicationId $ApplicationId
  } finally {
    Remove-Item -LiteralPath $TemporaryFolder -Recurse -Force -ErrorAction SilentlyContinue
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
    $File = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $Layout = Get-PELayout -Path $File.FullName
    if (-not $Layout) { throw 'The file is not a valid PE image.' }
    $Resources = @(Get-ChromiumSetupResourceEvidence -Path $File.FullName)
    $VersionInfo = [Diagnostics.FileVersionInfo]::GetVersionInfo($File.FullName)
    $Tag = Read-ChromiumInstallerTag -Path $File.FullName

    # Chromium forks replace the archive prefix at build time. The resource
    # types and the paired setup payload are the stable mini-installer layout.
    $MiniArchives = @($Resources | Where-Object {
        $_.Type -in @('B7', 'BN') -and
        $_.Name -match '(?i)^(?!setup(?:[._]|$)|updater(?:[._]|$)).+(?:\.packed)?\.7z$'
      })
    $MiniSetups = @($Resources | Where-Object {
        ($_.Type -eq 'B7' -and $_.Name -match '(?i)^setup(?:_patch)?(?:\.packed)?\.7z$') -or
        ($_.Type -eq 'BL' -and $_.Name -match '(?i)^setup\.ex_$') -or
        ($_.Type -eq 'BN' -and $_.Name -match '(?i)^setup\.exe$')
      })
    $MiniArchive = $MiniArchives | Select-Object -First 1
    $MiniSetup = $MiniSetups | Select-Object -First 1
    $MiniArchiveResourceName = if ($MiniArchive) { [string]$MiniArchive.Name } else { $null }
    $MiniSetupResourceName = if ($MiniSetup) { [string]$MiniSetup.Name } else { $null }
    $MiniArchiveFileName = if ($MiniArchive) { ($MiniArchive.Name -replace '(?i)\.packed(?=\.7z$)', '').ToLowerInvariant() } else { $null }
    $HasMiniArchive = $MiniArchives.Count -eq 1
    $HasMiniSetup = $MiniSetups.Count -gt 0
    $HasUpdaterArchive = [bool]($Resources | Where-Object { $_.Type -eq 'B7' -and $_.Name -match '(?i)^updater(?:\.packed)?\.7z$' })
    $HasOmahaPayload = [bool]($Resources | Where-Object { $_.Type -eq 'B' -and ($_.Id -eq 102 -or $_.Name -eq '102') })

    $Variant = if ($HasUpdaterArchive) {
      'ChromiumUpdater'
    } elseif ($HasMiniArchive -and $HasMiniSetup) {
      'ChromiumMiniInstaller'
    } elseif ($HasOmahaPayload -and ($Tag.MarkerFound -or $VersionInfo.OriginalFilename -match '(?i)(update|updater).*setup')) {
      'Omaha'
    } else {
      throw 'The PE does not contain a supported Chromium Setup resource layout.'
    }

    $OfflineManifest = $null
    $OfflineManifestError = $null
    if ($Variant -eq 'Omaha' -and $Tag.IsTagged -and -not $SkipOfflineManifest) {
      $OmahaResource = $Resources | Where-Object { $_.Type -eq 'B' -and ($_.Id -eq 102 -or $_.Name -eq '102') } | Select-Object -First 1
      try {
        $OfflineManifest = Get-ChromiumOmahaOfflineManifestInfo -Resource $OmahaResource.Resource -ApplicationId $Tag.ApplicationId
      } catch {
        $OfflineManifestError = $_.Exception.Message
      }
    }
    $IsOnlineBootstrapper = $Tag.IsTagged -and -not $OfflineManifest
    $ProductCode = Resolve-BraveChromiumProductCode -ApplicationId $Tag.ApplicationId -Publisher $VersionInfo.CompanyName

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

    $NestedFiles = switch ($Variant) {
      'ChromiumMiniInstaller' { @('setup.exe', $MiniArchiveFileName) }
      'ChromiumUpdater' { @('updater.7z', 'bin\updater.exe') }
      'Omaha' {
        if ($OfflineManifest) { @('OfflineManifest.gup') + @($OfflineManifest.Packages.Name) }
        else { @('BCJ2-decoded TAR payload') }
      }
    }
    $ExecutedPayloads = switch ($Variant) {
      'ChromiumMiniInstaller' { @('setup.exe') }
      'ChromiumUpdater' { @('bin\updater.exe') }
      'Omaha' {
        if ($OfflineManifest.InstallAction) {
          @((@($OfflineManifest.InstallAction.Run, $OfflineManifest.InstallAction.Arguments) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join ' ')
        } else {
          @('first executable in BCJ2-decoded TAR payload')
        }
      }
    }
    $Warnings = [Collections.Generic.List[string]]::new()
    if ($OfflineManifestError) { $Warnings.Add("The tagged Omaha payload could not be checked for OfflineManifest.gup: $OfflineManifestError") }
    if ($Tag.ApplicationId -and -not $ProductCode) { $Warnings.Add("Updater appguid '$($Tag.ApplicationId)' is update-protocol identity, not an ARP ProductCode.") }
    if ($IsOnlineBootstrapper) { $Warnings.Add("This setup is a tagged online bootstrapper. Outer version '$($VersionInfo.ProductVersion)' belongs to the updater and is not target-application version evidence; final version, ARP, and switch behavior require target-package evidence.") }
    if ($Variant -eq 'Omaha' -and -not $OfflineManifest) { $Warnings.Add('Omaha executes the first EXE in its decoded TAR payload. Expand and analyze that file before composing nested installer switches.') }
    if ($Variant -eq 'Omaha' -and -not $Tag.IsTagged) { $Warnings.Add('This is an untagged Omaha runtime installer. Its /install runtime tag controls user versus machine scope; do not substitute Chromium Updater --system switches.') }
    if ($Tag.IsTagged -and -not $SupportedScopes) { $Warnings.Add("The updater tag needsadmin value '$($Tag.NeedsAdmin)' does not provide deterministic WinGet scope evidence.") }

    [pscustomobject]@{
      InstallerType               = 'Chromium Setup'
      Variant                     = $Variant
      ProductName                 = $VersionInfo.ProductName
      DisplayName                 = $Tag.ApplicationName ?? $VersionInfo.ProductName
      DisplayVersion              = if ($OfflineManifest) { $OfflineManifest.Version } elseif ($Tag.IsTagged) { $null } else { $VersionInfo.ProductVersion }
      OuterProductVersion         = $VersionInfo.ProductVersion
      Publisher                   = $VersionInfo.CompanyName
      OriginalFilename            = $VersionInfo.OriginalFilename
      ProductCode                 = $ProductCode
      ApplicationId               = $Tag.ApplicationId
      ArchiveResourceName         = $MiniArchiveResourceName
      SetupResourceName           = $MiniSetupResourceName
      Scope                       = $Scope
      SupportedScopes             = @($SupportedScopes)
      SupportsDualScope           = $SupportsDualScope
      UserScopeSwitch             = $UserScopeSwitch
      MachineScopeSwitch          = $MachineScopeSwitch
      IsOnlineBootstrapper        = $IsOnlineBootstrapper
      UpdaterTag                  = $Tag
      OfflineManifest             = $OfflineManifest
      Resources                   = @($Resources | Select-Object Type, Name, Id, Offset, Size)
      NestedFiles                 = @($NestedFiles)
      ExtractedFiles              = @($NestedFiles)
      ExecutedPayloads            = @($ExecutedPayloads)
      WritesAppsAndFeaturesEntry  = if ($Variant -eq 'ChromiumMiniInstaller' -or $ProductCode) { $true } else { $null }
      RegistryAssociationInfo     = $null
      Protocols                   = @()
      FileExtensions              = @()
      CanExpand                   = $true
      Warnings                    = @($Warnings)
      ParserVersionInfo           = [pscustomobject]@{
        Parser      = 'Dumplings.PackageModule.ChromiumSetup'
        ParserMajor = 1
        Sources     = @('Chromium mini_installer named resources', 'Chromium Updater metainstaller resources and certificate tag', 'Google Omaha LZMA/BCJ2/TAR payload and OfflineManifest.gup', 'Brave install-mode app GUID and uninstall-key definitions')
      }
    }
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

  $CommandLine = @($InstallerSwitches.Values | Where-Object { $_ -is [string] }) -join ' '
  $Channels = @(
    [pscustomobject]@{ Switch = '--chrome-sxs'; ProductCode = 'Google Chrome SxS' }
    [pscustomobject]@{ Switch = '--chrome-beta'; ProductCode = 'Google Chrome Beta' }
    [pscustomobject]@{ Switch = '--chrome-dev'; ProductCode = 'Google Chrome Dev' }
  )
  $SelectedChannels = @($Channels | Where-Object { $CommandLine -match "(?i)(?<!\S)$([regex]::Escape($_.Switch))(?!\S)" })
  if ($SelectedChannels.Count -gt 1) { return $null }
  if ($SelectedChannels.Count -eq 1) { return $SelectedChannels[0].ProductCode }

  # An unqualified Google Chrome mini-installer selects the stable channel.
  return 'Google Chrome'
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

  $TemporaryFolder = New-TempFolder
  $PackedPath = Join-Path $TemporaryFolder 'payload.lzma'
  $Bcj2Path = Join-Path $TemporaryFolder 'payload.bcj2'
  $TarPath = Join-Path $TemporaryFolder 'payload.tar'
  $PartPaths = 0..3 | ForEach-Object { Join-Path $TemporaryFolder "bcj2-$_.bin" }
  try {
    $null = Export-PEResourceData -Resource $Resource -DestinationPath $PackedPath -MaximumBytes $Script:ChromiumMaximumResourceBytes
    $Packed = [IO.File]::OpenRead($PackedPath)
    try {
      if ($Packed.Length -lt 13) { throw 'The Omaha LZMA resource is truncated.' }
      $Header = Read-BinaryBytes -Stream $Packed -Offset 0 -Count 13
      $Properties = [byte[]]$Header[0..4]
      $Bcj2Size = [BitConverter]::ToUInt64($Header, 5)
      if ($Bcj2Size -eq 0 -or $Bcj2Size -gt $MaximumExpandedBytes -or $Bcj2Size -gt [long]::MaxValue) { throw 'The Omaha LZMA output exceeds the configured limit.' }
      $Packed.Position = 13
      $Decoder = New-InstallerDecompressionStream -Algorithm Lzma -Stream $Packed -Properties $Properties -CompressedSize ($Packed.Length - 13) -UncompressedSize ([long]$Bcj2Size)
      $Output = [IO.File]::Open($Bcj2Path, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
      try {
        $Buffer = [byte[]]::new(1048576); $Written = 0L
        while (($Read = $Decoder.Read($Buffer, 0, $Buffer.Length)) -gt 0) {
          $Written += $Read
          if ($Written -gt [long]$Bcj2Size -or $Written -gt $MaximumExpandedBytes) { throw 'The Omaha LZMA decoder exceeded its declared output size.' }
          $Output.Write($Buffer, 0, $Read)
        }
        if ($Written -ne [long]$Bcj2Size) { throw 'The Omaha LZMA output does not match its declared size.' }
      } finally { $Output.Dispose(); $Decoder.Dispose() }
    } finally { $Packed.Dispose() }

    $Bcj2 = [IO.File]::OpenRead($Bcj2Path)
    try {
      if ($Bcj2.Length -lt 20) { throw 'The Omaha BCJ2 container is truncated.' }
      $Header = Read-BinaryBytes -Stream $Bcj2 -Offset 0 -Count 20
      $OriginalSize = [long][BitConverter]::ToUInt32($Header, 0)
      $PartSizes = 1..4 | ForEach-Object { [long][BitConverter]::ToUInt32($Header, $_ * 4) }
      $PartTotal = ($PartSizes | Measure-Object -Sum).Sum
      if ($OriginalSize -le 0 -or $OriginalSize -gt $MaximumExpandedBytes) { throw 'The Omaha decoded TAR exceeds the configured output limit.' }
      if (20L + $PartTotal -ne $Bcj2.Length) { throw 'The Omaha BCJ2 stream table is inconsistent with the decoded payload.' }
      $PartOffset = 20L
      for ($Index = 0; $Index -lt 4; $Index++) {
        $PartOutput = [IO.File]::Open($PartPaths[$Index], [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { Copy-BinaryStreamRange -Source $Bcj2 -Destination $PartOutput -Offset $PartOffset -Length $PartSizes[$Index] } finally { $PartOutput.Dispose() }
        $PartOffset += $PartSizes[$Index]
      }
    } finally { $Bcj2.Dispose() }

    $PartStreams = [System.IO.Stream[]]($PartPaths | ForEach-Object { [IO.File]::OpenRead($_) })
    $Bcj2Decoder = $null
    try {
      $Bcj2Decoder = New-InstallerBcj2DecoderStream -Stream $PartStreams -UncompressedSize $OriginalSize
      $TarOutput = [IO.File]::Open($TarPath, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
      try {
        $Buffer = [byte[]]::new(1048576); $Written = 0L
        while (($Read = $Bcj2Decoder.Read($Buffer, 0, $Buffer.Length)) -gt 0) {
          $Written += $Read
          if ($Written -gt $OriginalSize) { throw 'The Omaha BCJ2 decoder exceeded its declared output size.' }
          $TarOutput.Write($Buffer, 0, $Read)
        }
        if ($Written -ne $OriginalSize) { throw 'The Omaha BCJ2 output does not match its declared size.' }
      } finally { $TarOutput.Dispose() }
    } finally {
      if ($Bcj2Decoder) { $Bcj2Decoder.Dispose() }
      foreach ($PartStream in $PartStreams) { $PartStream.Dispose() }
    }

    $Archive = Get-InstallerArchive -Path $TarPath
    $Results = [Collections.Generic.List[System.IO.FileInfo]]::new(); $Expanded = 0L
    try {
      foreach ($Entry in Get-InstallerArchiveEntry -Archive $Archive) {
        if (-not (Test-ExtractionPattern -Path $Entry.FullName -Pattern $Name)) { continue }
        $Expanded += $Entry.Length
        if ($Expanded -gt $MaximumExpandedBytes) { throw 'Omaha TAR extraction exceeds the configured output limit.' }
        $OutputPath = Resolve-SafeExtractionPath -DestinationPath $DestinationPath -RelativePath $Entry.FullName
        $Results.Add((Export-InstallerArchiveEntry -Entry $Entry -DestinationPath $OutputPath -MaximumBytes $MaximumExpandedBytes))
      }
    } finally { $Archive.Dispose() }
    return $Results.ToArray()
  } finally {
    Remove-Item -LiteralPath $TemporaryFolder -Recurse -Force -ErrorAction SilentlyContinue
  }
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
    $File = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $Info = Get-ChromiumSetupInfo -Path $File.FullName -SkipOfflineManifest
    if ([string]::IsNullOrWhiteSpace($DestinationPath)) { $DestinationPath = New-TempFolder }
    $null = New-Item -Path $DestinationPath -ItemType Directory -Force
    $Resources = @(Get-ChromiumSetupResourceEvidence -Path $File.FullName)
    $Results = [Collections.Generic.List[System.IO.FileInfo]]::new(); $Expanded = 0L

    foreach ($Evidence in $Resources) {
      $Resource = $Evidence.Resource
      if ($Info.Variant -eq 'Omaha' -and $Evidence.Type -eq 'B' -and ($Evidence.Id -eq 102 -or $Evidence.Name -eq '102')) {
        foreach ($Result in @(Expand-ChromiumOmahaPayload -Resource $Resource -DestinationPath $DestinationPath -Name $Name -MaximumExpandedBytes $MaximumExpandedBytes)) { $Results.Add($Result) }
        continue
      }
      if ($Evidence.Type -in @('BN', 'BD')) {
        if (-not (Test-ExtractionPattern -Path $Evidence.Name -Pattern $Name)) { continue }
        $Expanded += $Evidence.Size
        if ($Expanded -gt $MaximumExpandedBytes) { throw 'Chromium resource extraction exceeds the configured output limit.' }
        $OutputPath = Resolve-SafeExtractionPath -DestinationPath $DestinationPath -RelativePath $Evidence.Name
        $Results.Add((Export-PEResourceData -Resource $Resource -DestinationPath $OutputPath -MaximumBytes $MaximumExpandedBytes))
        continue
      }

      $TemporaryPath = New-TempFile
      try {
        $null = Export-PEResourceData -Resource $Resource -DestinationPath $TemporaryPath -MaximumBytes $Script:ChromiumMaximumResourceBytes
        if ($Evidence.Type -eq 'BL') {
          foreach ($Result in @(Export-CabinetEntry -Path $TemporaryPath -DestinationPath $DestinationPath -Name $Name -MaximumExpandedBytes $MaximumExpandedBytes)) { $Results.Add((Get-Item -LiteralPath $Result -Force)) }
        } elseif ($Evidence.Type -eq 'B7') {
          $Archive = Get-InstallerArchive -Path $TemporaryPath
          try {
            foreach ($Entry in Get-InstallerArchiveEntry -Archive $Archive) {
              $IsUpdaterArchive = $Info.Variant -eq 'ChromiumUpdater' -and $Entry.FullName -ieq 'updater.7z'
              if ($IsUpdaterArchive) {
                $NestedArchivePath = Join-Path ([IO.Path]::GetTempPath()) ("Dumplings-ChromiumUpdater-$([guid]::NewGuid().ToString('N')).7z")
                try {
                  $null = Export-InstallerArchiveEntry -Entry $Entry -DestinationPath $NestedArchivePath -MaximumBytes $MaximumExpandedBytes
                  $NestedArchive = Get-InstallerArchive -Path $NestedArchivePath
                  try {
                    foreach ($NestedEntry in Get-InstallerArchiveEntry -Archive $NestedArchive) {
                      if (-not (Test-ExtractionPattern -Path $NestedEntry.FullName -Pattern $Name)) { continue }
                      $Expanded += $NestedEntry.Length
                      if ($Expanded -gt $MaximumExpandedBytes) { throw 'Chromium updater archive extraction exceeds the configured output limit.' }
                      $NestedOutputPath = Resolve-SafeExtractionPath -DestinationPath $DestinationPath -RelativePath $NestedEntry.FullName
                      $Results.Add((Export-InstallerArchiveEntry -Entry $NestedEntry -DestinationPath $NestedOutputPath -MaximumBytes $MaximumExpandedBytes))
                    }
                  } finally { $NestedArchive.Dispose() }
                } finally { Remove-Item -LiteralPath $NestedArchivePath -Force -ErrorAction SilentlyContinue }
              }
              if (Test-ExtractionPattern -Path $Entry.FullName -Pattern $Name) {
                $Expanded += $Entry.Length
                if ($Expanded -gt $MaximumExpandedBytes) { throw 'Chromium archive extraction exceeds the configured output limit.' }
                $OutputPath = Resolve-SafeExtractionPath -DestinationPath $DestinationPath -RelativePath $Entry.FullName
                $Results.Add((Export-InstallerArchiveEntry -Entry $Entry -DestinationPath $OutputPath -MaximumBytes $MaximumExpandedBytes))
              }
            }
          } finally { $Archive.Dispose() }
        }
      } finally { Remove-Item -LiteralPath $TemporaryPath -Force -ErrorAction SilentlyContinue }
    }
    if ($Results.Count -eq 0) { throw "No Chromium Setup payload matched '$Name'." }
    return $Results.ToArray()
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
