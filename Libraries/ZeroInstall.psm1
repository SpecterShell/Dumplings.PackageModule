# SPDX-License-Identifier: Apache-2.0
# Format sources: https://github.com/0install/0install-win,
# https://github.com/0install/0install-dotnet, and
# https://docs.0install.net/specifications/feed/
#
# Zero Install bootstrapper binary structures consumed here:
#
#   managed PE image
#   +-- IMAGE_COR20_HEADER
#   |   `-- ResourcesDirectory RVA/Size
#   +-- CLR metadata
#   |   `-- ManifestResource row
#   |       +-- Offset:u32 (relative to ResourcesDirectory)
#   |       +-- Attributes
#   |       +-- Name -> #Strings heap
#   |       `-- Implementation (nil means embedded in this PE)
#   `-- CLR managed-resource blob
#       +-- ResourceLength:u32 LE
#       `-- ResourceData[ResourceLength]
#           +-- ZeroInstall.BootstrapConfig.ini (UTF-8)
#           +-- ZeroInstall.SplashScreen.png
#           `-- ZeroInstall.content.* (feeds, archives, icons, or stub EXEs)
#
# The INI identifies the target feed and desktop-integration arguments. Target
# versions, publisher, architectures, and associations belong to the signed
# feed and are accepted only as caller-supplied XML; this module never fetches
# a feed or executes the bootstrapper.

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:ZeroInstallBootstrapConfigResource = 'ZeroInstall.BootstrapConfig.ini'
$Script:ZeroInstallMaximumConfigBytes = 1048576
$Script:ZeroInstallMaximumFeedBytes = 67108864
$Script:ZeroInstallMaximumResources = 10000

function ConvertFrom-ZeroInstallIni {
  <#
  .SYNOPSIS
    Parse the embedded Zero Install bootstrapper INI
  .PARAMETER Content
    UTF-8 INI text extracted from the managed PE resource.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][AllowEmptyString()][string]$Content)

  $Sections = [ordered]@{}
  $CurrentSection = $null
  foreach ($Line in Split-LineEndings -Content $Content) {
    $Trimmed = $Line.Trim()
    if ([string]::IsNullOrWhiteSpace($Trimmed) -or $Trimmed.StartsWith(';') -or $Trimmed.StartsWith('#')) { continue }
    if ($Trimmed -match '^\[(?<Name>[^\]]+)\]$') {
      $CurrentSection = $Matches.Name.Trim()
      if (-not $Sections.Contains($CurrentSection)) { $Sections[$CurrentSection] = [ordered]@{} }
      continue
    }
    if (-not $CurrentSection -or $Trimmed -notmatch '^(?<Key>[^=]+?)\s*=\s*(?<Value>.*)$') { continue }
    $Sections[$CurrentSection][$Matches.Key.Trim()] = $Matches.Value.Trim()
  }

  $SectionObjects = [ordered]@{}
  foreach ($Entry in $Sections.GetEnumerator()) { $SectionObjects[$Entry.Key] = [pscustomobject]$Entry.Value }
  [pscustomobject]@{ Sections = [pscustomobject]$SectionObjects; RawContent = $Content }
}

function Get-ZeroInstallIniOption {
  <#
  .SYNOPSIS
    Resolve a non-empty Zero Install INI option using bootstrapper semantics
  .PARAMETER Ini
    Parsed INI returned by ConvertFrom-ZeroInstallIni.
  .PARAMETER Section
    INI section containing the option.
  .PARAMETER Name
    Option name to resolve.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][psobject]$Ini,
    [Parameter(Mandatory)][string]$Section,
    [Parameter(Mandatory)][string]$Name
  )

  $SectionValue = $Ini.Sections.PSObject.Properties[$Section].Value
  if (-not $SectionValue) { return $null }
  $Value = [string]$SectionValue.PSObject.Properties[$Name].Value
  if ([string]::IsNullOrEmpty($Value) -or $Value.StartsWith(';')) { return $null }
  return $Value
}

function ConvertTo-ZeroInstallPrettyEscape {
  <#
  .SYNOPSIS
    Convert a canonical feed URI to Zero Install's Windows uninstall-key name
  .PARAMETER Value
    Absolute feed URI text.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][string]$Value)

  $Builder = [Text.StringBuilder]::new($Value.Length)
  foreach ($Character in $Value.ToCharArray()) {
    if ($Character -eq '/') { $null = $Builder.Append('#') }
    elseif ($Character -eq ':') { $null = $Builder.Append('%3a') }
    elseif ($Character -in '-', '_', '.' -or [char]::IsLetterOrDigit($Character)) { $null = $Builder.Append($Character) }
    else { $null = $Builder.Append('%').Append(([int]$Character).ToString('x')) }
  }
  $Builder.ToString()
}

function Get-ZeroInstallXmlDirectChildText {
  <#
  .SYNOPSIS
    Read one direct feed child without depending on a namespace prefix
  .PARAMETER Node
    Parent XML node.
  .PARAMETER LocalName
    Child element local name.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][Xml.XmlNode]$Node, [Parameter(Mandatory)][string]$LocalName)

  foreach ($Child in $Node.ChildNodes) {
    if ($Child.NodeType -eq [Xml.XmlNodeType]::Element -and $Child.LocalName -eq $LocalName) { return $Child.InnerText.Trim() }
  }
  return $null
}

function Get-ZeroInstallInheritedXmlAttribute {
  <#
  .SYNOPSIS
    Resolve the nearest inherited 0install group or implementation attribute
  .PARAMETER Node
    Implementation node from which to walk toward the interface root.
  .PARAMETER Name
    Attribute name to resolve.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][Xml.XmlNode]$Node, [Parameter(Mandatory)][string]$Name)

  for ($Current = $Node; $Current -and $Current.NodeType -ne [Xml.XmlNodeType]::Document; $Current = $Current.ParentNode) {
    $Attribute = $Current.Attributes[$Name]
    if ($Attribute -and -not [string]::IsNullOrWhiteSpace($Attribute.Value)) { return $Attribute.Value }
  }
  return $null
}

function ConvertFrom-ZeroInstallArchitecture {
  <#
  .SYNOPSIS
    Map a 0install architecture token to a concrete WinGet architecture
  .PARAMETER Architecture
    Feed architecture such as Windows-x86_64 or Windows-i486.
  #>
  [OutputType([string])]
  param ([string]$Architecture)

  if ([string]::IsNullOrWhiteSpace($Architecture)) { return $null }
  $Cpu = ($Architecture -split '-')[-1].ToLowerInvariant()
  switch -Regex ($Cpu) {
    '^x86_64$' { 'x64' }
    '^i[3-6]86$' { 'x86' }
    '^aarch64$' { 'arm64' }
    default { $null }
  }
}

function ConvertFrom-ZeroInstallFeed {
  <#
  .SYNOPSIS
    Convert caller-supplied Zero Install feed XML into static package evidence
  .DESCRIPTION
    Parses feed identity, implementation records, inherited architecture and
    stability attributes, requirements, URL protocols, and file extensions.
    It intentionally does not select an implementation because the 0install
    solver also considers dependencies, user policy, and rollout percentage.
  .PARAMETER Content
    Raw feed XML. The function never retrieves the feed URL itself.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][ValidateNotNullOrEmpty()][string]$Content)
  process {
    if ([Text.Encoding]::UTF8.GetByteCount($Content) -gt $Script:ZeroInstallMaximumFeedBytes) {
      throw "The Zero Install feed exceeds the $Script:ZeroInstallMaximumFeedBytes-byte limit."
    }

    # Prohibit DTDs and external resolution so untrusted feed text cannot read
    # local files or expand external entities during static analysis.
    $Settings = [Xml.XmlReaderSettings]::new()
    $Settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
    $Settings.XmlResolver = $null
    $Settings.MaxCharactersInDocument = $Script:ZeroInstallMaximumFeedBytes
    $StringReader = [IO.StringReader]::new($Content)
    $XmlReader = [Xml.XmlReader]::Create($StringReader, $Settings)
    $Document = [Xml.XmlDocument]::new()
    $Document.XmlResolver = $null
    try { $Document.Load($XmlReader) } finally { $XmlReader.Dispose(); $StringReader.Dispose() }

    $Root = $Document.DocumentElement
    if (-not $Root -or $Root.LocalName -notin 'interface', 'feed') { throw 'The XML is not a Zero Install interface feed.' }

    $Warnings = [Collections.Generic.List[string]]::new()
    $Implementations = [Collections.Generic.List[object]]::new()
    $ArchitectureSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($Node in $Root.SelectNodes('.//*[local-name()="implementation"]')) {
      $SourceArchitecture = Get-ZeroInstallInheritedXmlAttribute -Node $Node -Name 'arch'
      $Architecture = ConvertFrom-ZeroInstallArchitecture -Architecture $SourceArchitecture
      if ($Architecture) { $null = $ArchitectureSet.Add($Architecture) }
      elseif ($SourceArchitecture -and $SourceArchitecture -notmatch '(?i)(^|-)\*$') {
        $Warnings.Add("Unsupported or unknown Zero Install architecture '$SourceArchitecture' requires manual mapping.")
      }

      $Archive = $Node.SelectSingleNode('./*[local-name()="archive"]')
      $Stability = Get-ZeroInstallInheritedXmlAttribute -Node $Node -Name 'stability'
      if (-not $Stability) { $Stability = 'testing' }
      $Implementations.Add([pscustomobject]@{
          Id                 = [string]$Node.Attributes['id'].Value
          Version            = [string]$Node.Attributes['version'].Value
          Released           = [string]$Node.Attributes['released'].Value
          Stability          = $Stability
          RolloutPercentage  = Get-ZeroInstallInheritedXmlAttribute -Node $Node -Name 'rollout-percentage'
          SourceArchitecture = $SourceArchitecture
          Architecture       = $Architecture
          ArchiveUrl         = if ($Archive) { [string]$Archive.Attributes['href'].Value } else { $null }
          ArchiveSize        = if ($Archive) { [string]$Archive.Attributes['size'].Value } else { $null }
          ArchiveType        = if ($Archive) { [string]$Archive.Attributes['type'].Value } else { $null }
        })
    }

    $ProtocolSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($Node in $Root.SelectNodes('.//*[local-name()="url-protocol"]')) {
      $Id = [string]$Node.Attributes['id'].Value
      if (-not [string]::IsNullOrWhiteSpace($Id)) { $null = $ProtocolSet.Add($Id.ToLowerInvariant()) }
    }
    $ExtensionSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($Node in $Root.SelectNodes('.//*[local-name()="file-type"]/*[local-name()="extension"]')) {
      $Value = [string]$Node.Attributes['value'].Value
      if (-not [string]::IsNullOrWhiteSpace($Value)) { $null = $ExtensionSet.Add($Value.Trim().TrimStart('.').ToLowerInvariant()) }
    }
    $Requirements = @($Root.SelectNodes('.//*[local-name()="requires"]') | ForEach-Object {
        [pscustomobject]@{ Interface = [string]$_.Attributes['interface'].Value; Version = [string]$_.Attributes['version'].Value; Architecture = Get-ZeroInstallInheritedXmlAttribute -Node $_ -Name 'arch' }
      })

    [pscustomobject]@{
      InterfaceUri          = [string]$Root.Attributes['uri'].Value
      Name                  = Get-ZeroInstallXmlDirectChildText -Node $Root -LocalName 'name'
      Publisher             = Get-ZeroInstallXmlDirectChildText -Node $Root -LocalName 'publisher'
      Homepage              = Get-ZeroInstallXmlDirectChildText -Node $Root -LocalName 'homepage'
      Summary               = Get-ZeroInstallXmlDirectChildText -Node $Root -LocalName 'summary'
      Implementations       = $Implementations.ToArray()
      StableImplementations = @($Implementations | Where-Object Stability -EQ 'stable')
      Architectures         = @($ArchitectureSet | Sort-Object)
      Protocols             = @($ProtocolSet | Sort-Object)
      FileExtensions        = @($ExtensionSet | Sort-Object)
      Requirements          = $Requirements
      Warnings              = $Warnings.ToArray()
    }
  }
}

function Get-ZeroInstallExtractableResourceName {
  <#
  .SYNOPSIS
    Map an embedded CLR resource name to a safe parser extraction path
  .PARAMETER ResourceName
    Full CLR ManifestResource name.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][string]$ResourceName)

  switch ($ResourceName) {
    'ZeroInstall.BootstrapConfig.ini' { 'BootstrapConfig.ini' }
    'ZeroInstall.SplashScreen.png' { 'SplashScreen.png' }
    default {
      if ($ResourceName.StartsWith('ZeroInstall.content.', [StringComparison]::Ordinal)) {
        return 'content/' + $ResourceName.Substring('ZeroInstall.content.'.Length)
      }
      return $null
    }
  }
}

function Get-ZeroInstallInfo {
  <#
  .SYNOPSIS
    Read static Zero Install bootstrapper and optional feed metadata
  .DESCRIPTION
    Reads the embedded bootstrap configuration once and derives the uninstall
    key, scope support, switches, and feed URI. Optional feed XML adds package
    identity, architecture, implementation, and association evidence without
    allowing the parser to access the network.
  .PARAMETER Path
    Path to the Zero Install bootstrapper PE.
  .PARAMETER FeedContent
    Optional raw XML from AppUri, retrieved by the caller with any required
    request headers, parameters, cookies, or retry behavior.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$FeedContent
  )
  process {
    $File = Get-Item -LiteralPath $Path -Force
    $Stream = [IO.File]::Open($File.FullName, 'Open', 'Read', 'ReadWrite')
    try {
      $Layout = Get-PELayout -Stream $Stream
      if (-not $Layout) { throw 'The file is not a PE image.' }
      $Resources = @(Get-PEManagedResourceInfo -Stream $Stream -Layout $Layout -Name @(
          $Script:ZeroInstallBootstrapConfigResource,
          'ZeroInstall.SplashScreen.png',
          'ZeroInstall.content.*'
        ) -MaximumResources $Script:ZeroInstallMaximumResources -MaximumResourceBytes $File.Length)
      $ConfigResource = $Resources | Where-Object Name -EQ $Script:ZeroInstallBootstrapConfigResource | Select-Object -First 1
      if (-not $ConfigResource) { throw "The managed PE does not contain '$Script:ZeroInstallBootstrapConfigResource'." }
      $ConfigBytes = Read-PEResourceData -Resource $ConfigResource -MaximumBytes $Script:ZeroInstallMaximumConfigBytes
      try { $ConfigText = [Text.UTF8Encoding]::new($false, $true).GetString($ConfigBytes).TrimStart([char]0xFEFF) }
      catch { throw 'The embedded Zero Install bootstrap configuration is not valid UTF-8.' }
      $EmbeddedConfig = ConvertFrom-ZeroInstallIni -Content $ConfigText
    } finally { $Stream.Dispose() }

    # The upstream bootstrapper gives an adjacent same-basename INI precedence
    # over the embedded resource. This matters for ZIP distributions that ship
    # the launcher and customization sidecar together.
    $Config = $EmbeddedConfig
    $ConfigurationSource = 'Embedded CLR ManifestResource'
    $ExternalConfigPath = [IO.Path]::ChangeExtension($File.FullName, '.ini')
    if (Test-Path -LiteralPath $ExternalConfigPath -PathType Leaf) {
      $ExternalConfigFile = Get-Item -LiteralPath $ExternalConfigPath -Force
      if ($ExternalConfigFile.Length -gt $Script:ZeroInstallMaximumConfigBytes) { throw 'The adjacent Zero Install bootstrap configuration exceeds the configured size limit.' }
      $ExternalStream = [IO.File]::Open($ExternalConfigFile.FullName, 'Open', 'Read', 'ReadWrite')
      try { $ExternalBytes = Read-BinaryBytes -Stream $ExternalStream -Offset 0 -Count ([int]$ExternalConfigFile.Length) } finally { $ExternalStream.Dispose() }
      try { $ExternalText = [Text.UTF8Encoding]::new($false, $true).GetString($ExternalBytes).TrimStart([char]0xFEFF) }
      catch { throw 'The adjacent Zero Install bootstrap configuration is not valid UTF-8.' }
      $Config = ConvertFrom-ZeroInstallIni -Content $ExternalText
      $ConfigurationSource = "Adjacent INI: $($ExternalConfigFile.Name)"
    }

    $AppUriText = Get-ZeroInstallIniOption -Ini $Config -Section 'bootstrap' -Name 'app_uri'
    $AppUri = $null
    if ($AppUriText) {
      if (-not [uri]::TryCreate($AppUriText, [UriKind]::Absolute, [ref]$AppUri)) { throw "The Zero Install app_uri is not an absolute URI: $AppUriText" }
    }
    $AppName = Get-ZeroInstallIniOption -Ini $Config -Section 'bootstrap' -Name 'app_name'
    $IntegrateArgs = Get-ZeroInstallIniOption -Ini $Config -Section 'bootstrap' -Name 'integrate_args'
    $CustomizableStorePath = (Get-ZeroInstallIniOption -Ini $Config -Section 'bootstrap' -Name 'customizable_store_path') -ieq 'true'
    $EstimatedSpaceText = Get-ZeroInstallIniOption -Ini $Config -Section 'bootstrap' -Name 'estimated_required_space'
    $EstimatedSpace = 0L
    if ($EstimatedSpaceText -and -not [long]::TryParse($EstimatedSpaceText, [ref]$EstimatedSpace)) {
      throw "The Zero Install estimated_required_space value is invalid: $EstimatedSpaceText"
    }

    $FeedInfo = if ($PSBoundParameters.ContainsKey('FeedContent') -and -not [string]::IsNullOrWhiteSpace($FeedContent)) { ConvertFrom-ZeroInstallFeed -Content $FeedContent } else { $null }
    $Warnings = [Collections.Generic.List[string]]::new()
    if ($ConfigurationSource.StartsWith('Adjacent INI:', [StringComparison]::Ordinal)) {
      $Warnings.Add('The adjacent INI overrides the embedded bootstrap configuration at runtime; ensure the package delivers both files together.')
    }
    if ($FeedInfo) {
      foreach ($Warning in $FeedInfo.Warnings) { $Warnings.Add($Warning) }
      if ($FeedInfo.InterfaceUri -and $AppUri -and $FeedInfo.InterfaceUri -ne $AppUri.AbsoluteUri) {
        $Warnings.Add("The supplied feed URI '$($FeedInfo.InterfaceUri)' does not match embedded app_uri '$($AppUri.AbsoluteUri)'.")
      }
    } elseif ($AppUri) {
      $Warnings.Add('Package version, publisher, architecture, and capability evidence is feed-driven; retrieve AppUri in the task and pass its raw XML as FeedContent.')
    }

    $WritesAppsAndFeaturesEntry = [bool]($AppUri -and $IntegrateArgs)
    if ($AppUri -and -not $IntegrateArgs) {
      $Warnings.Add('The bootstrapper downloads or runs the target feed but has no integrate_args, so it does not prove a target Apps & Features entry.')
    }
    if (-not $AppUri) { $Warnings.Add('This is a generic Zero Install bootstrapper, not a bootstrapper bound to one application feed.') }
    if ($WritesAppsAndFeaturesEntry) {
      $Warnings.Add('Zero Install desktop integration does not write DisplayVersion; validate whether the target application adds or updates that value after installation or first run.')
    }

    $IsGui = $Layout.Subsystem -eq 2
    $IsAppBootstrapper = [bool]($AppUri -and $AppName)
    $InstallerSwitches = [ordered]@{}
    $InstallModes = @('interactive')
    if ($IsAppBootstrapper) {
      $InstallModes += 'silent'
      if ($IsGui) {
        $InstallModes += 'silentWithProgress'
        $InstallerSwitches['Silent'] = '--verysilent'
        $InstallerSwitches['SilentWithProgress'] = '--silent'
      } else {
        $InstallerSwitches['Silent'] = '--silent'
        $InstallerSwitches['SilentWithProgress'] = '--silent'
      }
    }
    if ($CustomizableStorePath) { $InstallerSwitches['InstallLocation'] = '--store-path="<INSTALLPATH>"' }

    $ProductCode = if ($AppUri) { ConvertTo-ZeroInstallPrettyEscape -Value $AppUri.AbsoluteUri } else { $null }
    $DisplayName = if ($FeedInfo.Name) { $FeedInfo.Name } else { $AppName }
    $ExtractableResources = @($Resources | ForEach-Object {
        $RelativePath = Get-ZeroInstallExtractableResourceName -ResourceName $_.Name
        if ($RelativePath) { [pscustomobject]@{ ResourceName = $_.Name; RelativePath = $RelativePath; Offset = $_.Offset; Size = $_.Size } }
      })
    $VersionInfo = [Diagnostics.FileVersionInfo]::GetVersionInfo($File.FullName)

    [pscustomobject][ordered]@{
      Path                         = $File.FullName
      InstallerType                = 'Zero Install'
      ProductCode                  = $ProductCode
      UpgradeCode                  = $null
      DisplayName                  = $DisplayName
      DisplayVersion               = $null
      Publisher                    = $FeedInfo.Publisher
      Scope                        = if ($WritesAppsAndFeaturesEntry) { 'user' } else { $null }
      DefaultInstallLocation       = $null
      WritesAppsAndFeaturesEntry   = $WritesAppsAndFeaturesEntry
      AppsAndFeaturesProductCode   = $WritesAppsAndFeaturesEntry ? $ProductCode : $null
      AppsAndFeaturesInstallerType = $WritesAppsAndFeaturesEntry ? 'exe' : $null
      Warnings                     = [string[]]@($Warnings | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
      UnresolvedFields             = [string[]]@()
      Family                       = 'Zero Install'
      BootstrapperVariant          = if ($IsGui) { 'GUI' } else { 'CLI' }
      BootstrapperVersion          = $VersionInfo.FileVersion
      ConfigurationSource          = $ConfigurationSource
      AppUri                       = if ($AppUri) { $AppUri.AbsoluteUri } else { $null }
      AppName                      = $AppName
      AppArgs                      = Get-ZeroInstallIniOption -Ini $Config -Section 'bootstrap' -Name 'app_args'
      IntegrateArgs                = $IntegrateArgs
      CatalogUri                   = Get-ZeroInstallIniOption -Ini $Config -Section 'bootstrap' -Name 'catalog_uri'
      SelfUpdateUri                = Get-ZeroInstallIniOption -Ini $Config -Section 'global' -Name 'self_update_uri'
      KeyFingerprint               = Get-ZeroInstallIniOption -Ini $Config -Section 'bootstrap' -Name 'key_fingerprint'
      CustomizableStorePath        = $CustomizableStorePath
      EstimatedRequiredSpace       = if ($EstimatedSpaceText) { $EstimatedSpace } else { $null }
      UninstallKeyName             = $ProductCode
      SupportedScopes              = if ($WritesAppsAndFeaturesEntry -and $IsAppBootstrapper) { @('user', 'machine') } elseif ($WritesAppsAndFeaturesEntry) { @('user') } else { @() }
      SupportsDualScope            = [bool]($WritesAppsAndFeaturesEntry -and $IsAppBootstrapper)
      AppsAndFeaturesEntries       = @()
      InstallModes                 = $InstallModes
      InstallerSwitches            = [pscustomobject]$InstallerSwitches
      ScopeSwitches                = if ($WritesAppsAndFeaturesEntry -and $IsAppBootstrapper) { [pscustomobject]@{ User = $null; Machine = '--machine' } } else { $null }
      SupportedCommandLineSwitches = @(
        '--batch', '--offline', '--refresh', '--prepare-offline', '--content-dir=<PATH>',
        $(if ($IsGui) { '--background' }),
        $(if ($CustomizableStorePath) { '--store-path=<PATH>' }),
        $(if ($IsAppBootstrapper) { '--0install-version=<VERSION>', '--0install-feed=<FEED>', '--version=<VERSION>', '--feed=<FEED>', '--no-run', '--silent' }),
        $(if ($IsAppBootstrapper -and $IsGui) { '--verysilent', '--wait' }),
        $(if ($WritesAppsAndFeaturesEntry -and $IsAppBootstrapper) { '--no-integrate', '--integrate-args=<ARGS>', '--machine' })
      ) | Where-Object { $_ }
      FeedInfo                     = $FeedInfo
      Implementations              = if ($FeedInfo) { $FeedInfo.Implementations } else { @() }
      Architectures                = if ($FeedInfo) { $FeedInfo.Architectures } else { @() }
      Protocols                    = if ($FeedInfo) { $FeedInfo.Protocols } else { @() }
      FileExtensions               = if ($FeedInfo) { $FeedInfo.FileExtensions } else { @() }
      RegistryWrites               = @()
      EmbeddedResources            = $ExtractableResources
      ExtractedFiles               = @($ExtractableResources.RelativePath)
      CanExpand                    = $true
      ParserVersionInfo            = [pscustomobject]@{
        Parser      = 'Dumplings.PackageModule.ZeroInstall'
        ParserMajor = 1
        Sources     = @('CLR ManifestResource table', 'ZeroInstall.BootstrapConfig.ini', $(if ($FeedInfo) { 'Caller-supplied Zero Install feed XML' })) | Where-Object { $_ }
      }
      BootstrapConfig              = $Config
      EmbeddedBootstrapConfig      = $EmbeddedConfig
    }
  }
}

function Expand-ZeroInstallInstaller {
  <#
  .SYNOPSIS
    Export selected embedded Zero Install resources without executing the PE
  .PARAMETER Path
    Path to the Zero Install bootstrapper.
  .PARAMETER DestinationPath
    Extraction root; omitted values create a temporary parser directory.
  .PARAMETER Name
    Wildcard matched against normalized relative resource paths.
  .PARAMETER MaximumExpandedBytes
    Maximum cumulative output bytes.
  #>
  [OutputType([IO.FileInfo[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [string]$Name = '*',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 1073741824
  )
  process {
    $File = Get-Item -LiteralPath $Path -Force
    if ([string]::IsNullOrWhiteSpace($DestinationPath)) { $DestinationPath = Join-Path ([IO.Path]::GetTempPath()) "Dumplings-ZeroInstall-$([guid]::NewGuid().ToString('N'))" }
    $null = New-Item -Path $DestinationPath -ItemType Directory -Force

    $Stream = [IO.File]::Open($File.FullName, 'Open', 'Read', 'ReadWrite')
    try {
      $Layout = Get-PELayout -Stream $Stream
      $Resources = @(Get-PEManagedResourceInfo -Stream $Stream -Layout $Layout -Name @(
          $Script:ZeroInstallBootstrapConfigResource,
          'ZeroInstall.SplashScreen.png',
          'ZeroInstall.content.*'
        ) -MaximumResources $Script:ZeroInstallMaximumResources -MaximumResourceBytes $File.Length)
      if (-not ($Resources.Name -contains $Script:ZeroInstallBootstrapConfigResource)) { throw 'The PE is not a Zero Install bootstrapper.' }

      $ExpandedBytes = 0L
      $Files = [Collections.Generic.List[IO.FileInfo]]::new()
      foreach ($Resource in $Resources) {
        $RelativePath = Get-ZeroInstallExtractableResourceName -ResourceName $Resource.Name
        if (-not $RelativePath -or -not (Test-ExtractionPattern -Path $RelativePath -Pattern $Name)) { continue }
        if ($Resource.Size -gt $MaximumExpandedBytes - $ExpandedBytes) { throw 'Zero Install extraction exceeds the configured output limit.' }
        $OutputPath = Resolve-SafeExtractionPath -DestinationPath $DestinationPath -RelativePath $RelativePath
        if (Test-Path -LiteralPath $OutputPath) { throw "Zero Install extraction refuses to overwrite '$OutputPath'." }
        $Files.Add((Export-PEResourceData -Resource $Resource -DestinationPath $OutputPath -MaximumBytes $MaximumExpandedBytes))
        $ExpandedBytes += $Resource.Size
      }
      if ($Files.Count -eq 0) { throw "No Zero Install resources matched '$Name'." }
      return $Files.ToArray()
    } finally { $Stream.Dispose() }
  }
}

function Test-ZeroInstallInstaller {
  <#
  .SYNOPSIS
    Test for a structurally valid embedded Zero Install bootstrap configuration
  .PARAMETER Path
    Path to the candidate PE.
  #>
  [OutputType([bool])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { try { $null = Get-ZeroInstallInfo -Path $Path -ErrorAction Stop; $true } catch { $false } }
}

function Read-ProductNameFromZeroInstall {
  <#
  .SYNOPSIS
    Read the target name from bootstrap configuration or caller-supplied feed
  .PARAMETER Path
    Path to the Zero Install bootstrapper.
  .PARAMETER FeedContent
    Optional raw Zero Install feed XML.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path, [string]$FeedContent)
  process { (Get-ZeroInstallInfo -Path $Path -FeedContent $FeedContent).DisplayName }
}

function Read-PublisherFromZeroInstall {
  <#
  .SYNOPSIS
    Read the publisher from caller-supplied Zero Install feed XML
  .PARAMETER Path
    Path to the Zero Install bootstrapper.
  .PARAMETER FeedContent
    Raw Zero Install feed XML.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path, [Parameter(Mandatory)][string]$FeedContent)
  process { (Get-ZeroInstallInfo -Path $Path -FeedContent $FeedContent).Publisher }
}

function Read-ProductCodeFromZeroInstall {
  <#
  .SYNOPSIS
    Read the feed-URI-derived Windows uninstall key name
  .PARAMETER Path
    Path to the Zero Install bootstrapper.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-ZeroInstallInfo -Path $Path).ProductCode }
}

function Read-ScopeFromZeroInstall {
  <#
  .SYNOPSIS
    Read the default integration scope when ARP registration is configured
  .PARAMETER Path
    Path to the Zero Install bootstrapper.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-ZeroInstallInfo -Path $Path).Scope }
}

function Read-ProtocolsFromZeroInstall {
  <#
  .SYNOPSIS
    Read URL protocol capabilities from caller-supplied Zero Install feed XML
  .PARAMETER Path
    Path to the Zero Install bootstrapper.
  .PARAMETER FeedContent
    Raw Zero Install feed XML.
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path, [Parameter(Mandatory)][string]$FeedContent)
  process { (Get-ZeroInstallInfo -Path $Path -FeedContent $FeedContent).Protocols }
}

function Read-FileExtensionsFromZeroInstall {
  <#
  .SYNOPSIS
    Read file-extension capabilities from caller-supplied Zero Install feed XML
  .PARAMETER Path
    Path to the Zero Install bootstrapper.
  .PARAMETER FeedContent
    Raw Zero Install feed XML.
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path, [Parameter(Mandatory)][string]$FeedContent)
  process { (Get-ZeroInstallInfo -Path $Path -FeedContent $FeedContent).FileExtensions }
}

Export-ModuleMember -Function ConvertFrom-ZeroInstallFeed, Get-ZeroInstallInfo, Expand-ZeroInstallInstaller, Test-ZeroInstallInstaller, Read-ProductNameFromZeroInstall, Read-PublisherFromZeroInstall, Read-ProductCodeFromZeroInstall, Read-ScopeFromZeroInstall, Read-ProtocolsFromZeroInstall, Read-FileExtensionsFromZeroInstall
