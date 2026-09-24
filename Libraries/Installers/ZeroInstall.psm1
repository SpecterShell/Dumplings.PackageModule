# SPDX-License-Identifier: Apache-2.0
# Format sources: https://github.com/0install/0install-win,
# https://github.com/0install/0install-dotnet,
# https://github.com/nano-byte/common, and
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
#           +-- no configuration resource (generic 2.11.0-2.11.5 runtime)
#           +-- ZeroInstall.EmbeddedConfig.txt (2.11.6-2.24.7)
#           |   `-- 3, 5, 6, or 7 fixed-width UTF-8 lines
#           +-- ZeroInstall.config.ini (2.24.8-2.25.2)
#           +-- ZeroInstall.BootstrapConfig.ini (2.25.3-current)
#           +-- ZeroInstall.SplashScreen.png
#           `-- ZeroInstall.content.* (feeds, archives, icons, or stub EXEs)
#
# The generation-specific configuration identifies the target feed and
# desktop-integration arguments. Target versions, publisher, architectures,
# and associations belong to the signed feed and are accepted only as
# caller-supplied XML; this module never fetches a feed or executes the
# bootstrapper.

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:ZeroInstallMaximumConfigBytes = 1048576
$Script:ZeroInstallMaximumFeedBytes = 67108864
$Script:ZeroInstallMaximumResources = 10000
$Script:ZeroInstallFeedNamespace = 'http://zero-install.sourceforge.net/2004/injector/interface'
$Script:ZeroInstallCapabilityNamespace = 'http://0install.de/schema/desktop-integration/capabilities'
$Script:ZeroInstallFormatCatalog = Import-PowerShellDataFile -LiteralPath (Join-Path $PSScriptRoot 'ZeroInstallFormatCatalog.psd1')
if ([int]$Script:ZeroInstallFormatCatalog.CatalogVersion -ne 2) { throw "Unsupported Zero Install format catalog version '$($Script:ZeroInstallFormatCatalog.CatalogVersion)'." }
$Script:ZeroInstallConfigurationResourceNames = [string[]]@($Script:ZeroInstallFormatCatalog.ConfigurationProfiles.ResourceName | Sort-Object -Unique)

function ConvertTo-ZeroInstallRuntimeVersion {
  <#
  .SYNOPSIS
    Convert a Zero Install PE file-version string to a comparable version.
  .PARAMETER Value
    FileVersion text from the bootstrapper PE.
  #>
  [OutputType([version])]
  param ([AllowNull()][string]$Value)

  if ($Value -match '(?<Version>\d+(?:\.\d+){1,3})') {
    try { return [version]$Matches.Version } catch { return $null }
  }
  return $null
}

function ConvertTo-ZeroInstallComparableRuntimeVersion {
  <#
  .SYNOPSIS
    Normalize a numeric Zero Install runtime version for range comparison.
  .PARAMETER Value
    One-to-four-component dotted numeric version text.
  #>
  [OutputType([version])]
  param ([Parameter(Mandatory)][string]$Value)

  $Parts = @($Value.Trim() -split '\.')
  if ($Parts.Count -lt 1 -or $Parts.Count -gt 4 -or @($Parts | Where-Object { $_ -cnotmatch '^\d+$' }).Count -gt 0) {
    throw "The Zero Install runtime version '$Value' is not a dotted numeric version."
  }
  $Numbers = [int[]]@(0, 0, 0, 0)
  for ($Index = 0; $Index -lt $Parts.Count; $Index++) {
    $Parsed = 0
    if (-not [int]::TryParse($Parts[$Index], [Globalization.NumberStyles]::None, [Globalization.CultureInfo]::InvariantCulture, [ref]$Parsed) -or $Parsed -lt 0) {
      throw "The Zero Install runtime version '$Value' contains an invalid component."
    }
    $Numbers[$Index] = $Parsed
  }
  return [version]::new($Numbers[0], $Numbers[1], $Numbers[2], $Numbers[3])
}

function Test-ZeroInstallRuntimeVersionRange {
  <#
  .SYNOPSIS
    Evaluate the Zero Install VersionRange grammar used by if-0install-version.
  .PARAMETER RuntimeVersion
    Numeric bootstrap runtime version.
  .PARAMETER Range
    Exact, excluded, lower-inclusive/upper-exclusive, or pipe-union expression.
  #>
  [OutputType([bool])]
  param ([Parameter(Mandatory)][version]$RuntimeVersion, [Parameter(Mandatory)][string]$Range)

  $ComparableRuntime = ConvertTo-ZeroInstallComparableRuntimeVersion -Value ($RuntimeVersion.ToString())
  if ($Range -match '^\s*\||\|\s*$|\|\s*\|') { throw "The Zero Install version range '$Range' contains an empty union part." }
  $Matched = $false
  foreach ($RawPart in $Range -split '\|') {
    $Part = $RawPart.Trim()
    if ([string]::IsNullOrEmpty($Part)) { throw "The Zero Install version range '$Range' contains an empty union part." }
    if ($Part.StartsWith('!', [StringComparison]::Ordinal) -and -not $Part.Contains('..', [StringComparison]::Ordinal)) {
      if ($ComparableRuntime -ne (ConvertTo-ZeroInstallComparableRuntimeVersion -Value ($Part.Substring(1)))) { $Matched = $true }
      continue
    }
    $Separator = $Part.IndexOf('..', [StringComparison]::Ordinal)
    if ($Separator -ge 0) {
      if ($Part.IndexOf('..', $Separator + 2, [StringComparison]::Ordinal) -ge 0) { throw "The Zero Install version range '$Part' contains more than one range separator." }
      $LowerText = $Part.Substring(0, $Separator)
      $UpperText = $Part.Substring($Separator + 2)
      $LowerMatches = [string]::IsNullOrEmpty($LowerText) -or $ComparableRuntime -ge (ConvertTo-ZeroInstallComparableRuntimeVersion -Value $LowerText)
      if (-not [string]::IsNullOrEmpty($UpperText) -and -not $UpperText.StartsWith('!', [StringComparison]::Ordinal)) { throw "The upper bound in Zero Install version range '$Part' must be exclusive and start with '!'." }
      $UpperMatches = [string]::IsNullOrEmpty($UpperText) -or $ComparableRuntime -lt (ConvertTo-ZeroInstallComparableRuntimeVersion -Value ($UpperText.Substring(1)))
      if ($LowerMatches -and $UpperMatches) { $Matched = $true }
      continue
    }
    if ($ComparableRuntime -eq (ConvertTo-ZeroInstallComparableRuntimeVersion -Value $Part)) { $Matched = $true }
  }
  return $Matched
}

function Get-ZeroInstallRuntimeApplicability {
  <#
  .SYNOPSIS
    Resolve an element and its ancestor-group if-0install-version conditions.
  .PARAMETER Node
    Feed element whose effective applicability is required.
  .PARAMETER RuntimeVersion
    Optional bootstrap runtime version. Conditional records remain unresolved when absent.
  #>
  [OutputType([Nullable[bool]])]
  param ([Parameter(Mandatory)][Xml.XmlNode]$Node, [AllowNull()][version]$RuntimeVersion)

  $HasCondition = $false
  for ($Current = $Node; $Current -and $Current.NodeType -ne [Xml.XmlNodeType]::Document; $Current = $Current.ParentNode) {
    if ($Current.NodeType -ne [Xml.XmlNodeType]::Element -or $Current.NamespaceURI -cne $Script:ZeroInstallFeedNamespace) { continue }
    $Condition = Get-ZeroInstallXmlAttribute -Node $Current -Name 'if-0install-version'
    if ([string]::IsNullOrWhiteSpace($Condition)) { continue }
    $HasCondition = $true
    if ($RuntimeVersion -and -not (Test-ZeroInstallRuntimeVersionRange -RuntimeVersion $RuntimeVersion -Range $Condition)) { return $false }
  }
  if ($HasCondition -and -not $RuntimeVersion) { return $null }
  return $true
}

function Get-ZeroInstallManagedIdentity {
  <#
  .SYNOPSIS
    Read source-backed Zero Install type identity from CLR metadata.
  .PARAMETER Stream
    Caller-owned readable and seekable PE stream. Its position is restored.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][IO.Stream]$Stream)

  if (-not $Stream.CanRead -or -not $Stream.CanSeek) { throw 'Zero Install CLR identity parsing requires a readable, seekable stream.' }
  Import-InstallerInfrastructure
  $OriginalPosition = $Stream.Position
  $PeReader = $null
  try {
    $Stream.Position = 0
    $PeReader = [Reflection.PortableExecutable.PEReader]::new(
      $Stream,
      [Reflection.PortableExecutable.PEStreamOptions]::LeaveOpen,
      [Dumplings.InstallerInfrastructure.PEImageReader]::GetReaderSize($Stream)
    )
    if (-not $PeReader.HasMetadata) { return [pscustomobject]@{ AssemblyName = $null; AssemblyVersion = $null; TypeNames = @(); IsBootstrapper = $false; Profile = $null } }
    $Reader = [Reflection.Metadata.PEReaderExtensions]::GetMetadataReader($PeReader)
    $AssemblyDefinition = $Reader.GetAssemblyDefinition()
    $AssemblyName = $Reader.GetString($AssemblyDefinition.Name)
    $TypeNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($Handle in $Reader.TypeDefinitions) {
      $Definition = $Reader.GetTypeDefinition($Handle)
      $Namespace = $Reader.GetString($Definition.Namespace)
      $Name = $Reader.GetString($Definition.Name)
      $null = $TypeNames.Add([string]::IsNullOrEmpty($Namespace) ? $Name : "$Namespace.$Name")
    }
    $IdentityProfile = $null
    foreach ($Candidate in $Script:ZeroInstallFormatCatalog.ManagedIdentityProfiles) {
      if (@($Candidate.TypeNames | Where-Object { -not $TypeNames.Contains([string]$_) }).Count -eq 0) { $IdentityProfile = $Candidate; break }
    }
    [pscustomobject]@{
      AssemblyName    = $AssemblyName
      AssemblyVersion = $AssemblyDefinition.Version
      TypeNames       = [string[]]@($TypeNames | Sort-Object)
      IsBootstrapper  = [bool]($IdentityProfile -or $TypeNames.Contains('ZeroInstall.BootstrapProcess'))
      Profile         = $IdentityProfile
    }
  } finally {
    if ($PeReader) { $PeReader.Dispose() }
    $Stream.Position = $OriginalPosition
  }
}

function Test-ZeroInstallVersionInProfile {
  <#
  .SYNOPSIS
    Test whether runtime release evidence agrees with a resource profile.
  .PARAMETER Version
    Parsed Zero Install runtime version.
  .PARAMETER FormatProfile
    Catalog profile with inclusive minimum and optional exclusive maximum.
  #>
  [OutputType([bool])]
  param ([Parameter(Mandatory)][version]$Version, [Parameter(Mandatory)][Collections.IDictionary]$FormatProfile)

  if ($FormatProfile.MinimumRuntimeVersion -and $Version -lt [version]$FormatProfile.MinimumRuntimeVersion) { return $false }
  if ($FormatProfile.MaximumRuntimeExclusive -and $Version -ge [version]$FormatProfile.MaximumRuntimeExclusive) { return $false }
  return $true
}

function Get-ZeroInstallFeatureState {
  <#
  .SYNOPSIS
    Resolve a source-backed runtime feature from version and structural evidence.
  .PARAMETER Name
    Feature name from ZeroInstallFormatCatalog.psd1.
  .PARAMETER RuntimeVersion
    Parsed PE runtime version, when available.
  .PARAMETER FormatProfile
    Structural configuration profile used as a bounded fallback.
  #>
  [OutputType([Nullable[bool]])]
  param (
    [Parameter(Mandatory)][string]$Name,
    [AllowNull()][version]$RuntimeVersion,
    [Parameter(Mandatory)][Collections.IDictionary]$FormatProfile
  )

  $Minimum = [version]$Script:ZeroInstallFormatCatalog.Features[$Name]
  if ($RuntimeVersion) { return $RuntimeVersion -ge $Minimum }

  # A structural profile can prove a feature only when its entire observed
  # version interval falls on one side of the introduction boundary.
  $ProfileMinimum = [version]$FormatProfile.MinimumRuntimeVersion
  if ($ProfileMinimum -ge $Minimum) { return $true }
  if ($FormatProfile.MaximumRuntimeExclusive -and [version]$FormatProfile.MaximumRuntimeExclusive -le $Minimum) { return $false }
  return $null
}

function Get-ZeroInstallConfigurationProfile {
  <#
  .SYNOPSIS
    Select the catalog profile for one structured managed resource.
  .PARAMETER ResourceName
    Exact CLR ManifestResource name.
  .PARAMETER Content
    Decoded UTF-8 resource text.
  .PARAMETER RuntimeVersion
    Optional PE file-version evidence used to disambiguate five-line layouts.
  #>
  [OutputType([Collections.IDictionary])]
  param (
    [Parameter(Mandatory)][string]$ResourceName,
    [Parameter(Mandatory)][AllowEmptyString()][string]$Content,
    [AllowNull()][version]$RuntimeVersion
  )

  $Candidates = @($Script:ZeroInstallFormatCatalog.ConfigurationProfiles | Where-Object ResourceName -CEQ $ResourceName)
  if ($Candidates.Count -eq 0) { throw "Unsupported Zero Install configuration resource '$ResourceName'." }
  if ($Candidates.Count -eq 1) { return $Candidates[0] }

  $Lines = [Collections.Generic.List[string]]::new()
  foreach ($Line in @(Split-LineEndings -Content $Content)) { $Lines.Add($Line) }
  while ($Lines.Count -gt 0 -and [string]::IsNullOrEmpty($Lines[$Lines.Count - 1])) { $Lines.RemoveAt($Lines.Count - 1) }
  $Candidates = @($Candidates | Where-Object { @($_.Fields).Count -eq $Lines.Count })
  if ($RuntimeVersion) {
    $VersionMatches = @($Candidates | Where-Object { Test-ZeroInstallVersionInProfile -Version $RuntimeVersion -FormatProfile $_ })
    if ($VersionMatches.Count -eq 1) { return $VersionMatches[0] }
  }
  if ($Candidates.Count -eq 2 -and $Lines.Count -eq 5) {
    $Third = $Lines[2].TrimEnd()
    $ProfileId = if ($Third -in @('run', 'integrate', 'none') -or $Third -match 'AppMode') { 'EmbeddedConfig5Mode' } else { 'EmbeddedConfig5Integrate' }
    return $Candidates | Where-Object Id -CEQ $ProfileId | Select-Object -First 1
  }
  if ($Candidates.Count -eq 2 -and $Lines.Count -eq 6) {
    $UsesAppFingerprint = $Lines[3] -match 'AppFingerprint'
    return $Candidates | Where-Object Id -CEQ ($UsesAppFingerprint ? 'EmbeddedConfig6AppFingerprint' : 'EmbeddedConfig6KeyFingerprint') | Select-Object -First 1
  }
  if ($Candidates.Count -ne 1) { throw "The Zero Install fixed-line configuration has an unsupported $($Lines.Count)-line layout." }
  return $Candidates[0]
}

function ConvertFrom-ZeroInstallIni {
  <#
  .SYNOPSIS
    Parse the embedded Zero Install bootstrapper INI
  .PARAMETER Content
    UTF-8 INI text extracted from the managed PE resource.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][AllowEmptyString()][string]$Content)

  $Parsed = ConvertFrom-Ini -Content $Content -DuplicateKeyAction Last -IgnoreComments
  $SectionObjects = [ordered]@{}
  foreach ($Entry in $Parsed.GetEnumerator()) { $SectionObjects[$Entry.Key] = [pscustomobject]$Entry.Value }
  [pscustomobject]@{ Sections = [pscustomobject]$SectionObjects; RawContent = $Content }
}

function ConvertFrom-ZeroInstallFixedConfiguration {
  <#
  .SYNOPSIS
    Decode an historical fixed-width EmbeddedConfig.txt resource.
  .PARAMETER Content
    UTF-8 text from ZeroInstall.EmbeddedConfig.txt.
  .PARAMETER FormatProfile
    Catalog profile defining line order and semantics.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][AllowEmptyString()][string]$Content,
    [Parameter(Mandatory)][Collections.IDictionary]$FormatProfile
  )

  $Lines = [Collections.Generic.List[string]]::new()
  foreach ($Line in @(Split-LineEndings -Content $Content)) { $Lines.Add($Line) }
  while ($Lines.Count -gt 0 -and [string]::IsNullOrEmpty($Lines[$Lines.Count - 1])) { $Lines.RemoveAt($Lines.Count - 1) }
  if ($Lines.Count -ne @($FormatProfile.Fields).Count) { throw "The Zero Install '$($FormatProfile.Id)' resource requires $(@($FormatProfile.Fields).Count) lines but contains $($Lines.Count)." }

  $Global = [ordered]@{}
  $Bootstrap = [ordered]@{}
  for ($Index = 0; $Index -lt $Lines.Count; $Index++) {
    $Name = [string]$FormatProfile.Fields[$Index]
    $Value = $Lines[$Index].TrimEnd()
    # 0bootstrap replaces fixed-width --Name-- placeholders in-place. A raw
    # generic launcher retains those tokens, which mean that no value is set.
    if ([string]::IsNullOrEmpty($Value) -or $Value -match '^--+[A-Za-z]+--+$') { $Value = $null }
    if ($Name -ceq 'self_update_uri') { $Global[$Name] = $Value } else { $Bootstrap[$Name] = $Value }
  }

  [pscustomobject]@{
    Sections   = [pscustomobject][ordered]@{ global = [pscustomobject]$Global; bootstrap = [pscustomobject]$Bootstrap }
    RawContent = $Content
  }
}

function Read-ZeroInstallApplicationSetting {
  <#
  .SYNOPSIS
    Read bounded appSettings overrides used before the INI redesign.
  .PARAMETER Path
    Adjacent executable configuration file.
  #>
  [OutputType([Collections.Specialized.OrderedDictionary])]
  param ([Parameter(Mandatory)][string]$Path)

  $Content = Read-BoundedTextFile -Path $Path -MaximumBytes $Script:ZeroInstallMaximumConfigBytes -FallbackEncoding utf-8
  $Document = Read-BoundedXmlDocument -Content $Content -MaximumCharacters $Script:ZeroInstallMaximumConfigBytes

  $Result = [ordered]@{}
  foreach ($Node in $Document.SelectNodes('/configuration/appSettings/add')) {
    $Key = [string]$Node.Attributes['key'].Value
    if (-not [string]::IsNullOrWhiteSpace($Key)) { $Result[$Key] = [string]$Node.Attributes['value'].Value }
  }
  return $Result
}

function Merge-ZeroInstallApplicationSetting {
  <#
  .SYNOPSIS
    Apply historical .config appSettings with release-accurate empty handling.
  .PARAMETER Configuration
    Parsed embedded fixed-line configuration.
  .PARAMETER Settings
    Ordered appSettings dictionary.
  .PARAMETER FormatProfile
    Fixed-line profile controlling historical behavior.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Configuration,
    [Parameter(Mandatory)][Collections.IDictionary]$Settings,
    [Parameter(Mandatory)][Collections.IDictionary]$FormatProfile
  )

  $Global = [ordered]@{}
  $Bootstrap = [ordered]@{}
  foreach ($Property in $Configuration.Sections.global.PSObject.Properties) { $Global[$Property.Name] = $Property.Value }
  foreach ($Property in $Configuration.Sections.bootstrap.PSObject.Properties) { $Bootstrap[$Property.Name] = $Property.Value }
  $BootstrapKeys = @('app_uri', 'app_name', 'app_mode', 'app_args', 'app_fingerprint', 'key_fingerprint', 'integrate_args', 'customizable_path', 'customizable_store_path')
  foreach ($Entry in $Settings.GetEnumerator()) {
    $Name = [string]$Entry.Key
    $Value = [string]$Entry.Value
    $TargetName = switch ($Name) { 'customizable_path' { 'customizable_store_path' } default { $Name } }
    $IsBootstrap = $TargetName -in $BootstrapKeys
    if ($FormatProfile.Id -cne 'EmbeddedConfig3Mode' -and [string]::IsNullOrEmpty($Value)) { continue }
    if ($IsBootstrap) { $Bootstrap[$TargetName] = $Value } else { $Global[$TargetName] = $Value }
  }
  [pscustomobject]@{
    Sections   = [pscustomobject][ordered]@{ global = [pscustomobject]$Global; bootstrap = [pscustomobject]$Bootstrap }
    RawContent = $Configuration.RawContent
  }
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

  $SectionProperty = $Ini.Sections.PSObject.Properties[$Section]
  if (-not $SectionProperty) { return $null }
  $ValueProperty = $SectionProperty.Value.PSObject.Properties[$Name]
  if (-not $ValueProperty) { return $null }
  $Value = [string]$ValueProperty.Value
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
  .PARAMETER NamespaceUri
    Optional namespace URI required on the child element.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][Xml.XmlNode]$Node, [Parameter(Mandatory)][string]$LocalName, [string]$NamespaceUri)

  foreach ($Child in $Node.ChildNodes) {
    if ($Child.NodeType -eq [Xml.XmlNodeType]::Element -and $Child.LocalName -eq $LocalName -and ([string]::IsNullOrEmpty($NamespaceUri) -or $Child.NamespaceURI -ceq $NamespaceUri)) { return $Child.InnerText.Trim() }
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
    if ($Current.NamespaceURI -cne $Script:ZeroInstallFeedNamespace -or $Current.LocalName -notin 'group', 'implementation', 'package-implementation') { continue }
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
  if ($Architecture -match '^(?i:\*|all|any|noarch|\(none\))$') { return 'neutral' }
  $Parts = $Architecture -split '-', 2
  if ($Parts.Count -ne 2 -or $Parts[0] -notin @('Windows', 'windows', '*', 'all', 'any')) { return $null }
  $Cpu = $Parts[1].ToLowerInvariant()
  switch -Regex ($Cpu) {
    '^(x86_64|amd64)$' { 'x64' }
    '^(i[3-6]86|x86|i86pc)$' { 'x86' }
    '^(aarch64|arm64)$' { 'arm64' }
    '^(armv6l|armv6h|armhf|armv7l)$' { 'arm' }
    '^(\*|all|any|noarch|\(none\))$' { 'neutral' }
    default { $null }
  }
}

function Get-ZeroInstallXmlAttribute {
  <#
  .SYNOPSIS
    Read an optional XML attribute without StrictMode-sensitive member access.
  .PARAMETER Node
    XML element containing the attribute.
  .PARAMETER Name
    Attribute local name.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][Xml.XmlNode]$Node, [Parameter(Mandatory)][string]$Name)

  $Attribute = $Node.Attributes[$Name]
  return $Attribute ? [string]$Attribute.Value : $null
}

function ConvertFrom-ZeroInstallXmlBoolean {
  <#
  .SYNOPSIS
    Parse the XML Schema Boolean lexical forms accepted by Zero Install feeds.
  .PARAMETER Value
    Optional true, false, 1, or 0 text.
  .PARAMETER Field
    Field name included in malformed-feed errors.
  .PARAMETER DefaultValue
    Value returned when the attribute is absent.
  #>
  [OutputType([bool])]
  param ([AllowNull()][string]$Value, [Parameter(Mandatory)][string]$Field, [bool]$DefaultValue = $false)

  if ([string]::IsNullOrEmpty($Value)) { return $DefaultValue }
  switch -CaseSensitive ($Value) {
    'true' { return $true }
    '1' { return $true }
    'false' { return $false }
    '0' { return $false }
    default { throw "The Zero Install feed attribute '$Field' is not a valid XML Boolean: $Value" }
  }
}

function Get-ZeroInstallLocalizableText {
  <#
  .SYNOPSIS
    Project direct localized text children without choosing the host UI language.
  .PARAMETER Node
    Parent feed or capability element.
  .PARAMETER LocalName
    Child element local name.
  .PARAMETER NamespaceUri
    Required namespace of the localized element.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][Xml.XmlNode]$Node, [Parameter(Mandatory)][string]$LocalName, [Parameter(Mandatory)][string]$NamespaceUri)

  $Values = [Collections.Generic.List[object]]::new()
  foreach ($Child in $Node.ChildNodes) {
    if ($Child.NodeType -ne [Xml.XmlNodeType]::Element -or $Child.LocalName -cne $LocalName -or $Child.NamespaceURI -cne $NamespaceUri) { continue }
    $Language = $Child.Attributes.GetNamedItem('lang', 'http://www.w3.org/XML/1998/namespace')
    $Values.Add([pscustomobject][ordered]@{ Language = $Language ? [string]$Language.Value : $null; Value = $Child.InnerText.Trim() })
  }
  return $Values.ToArray()
}

function ConvertFrom-ZeroInstallArgumentNode {
  <#
  .SYNOPSIS
    Project a command or runner argument without expanding runtime variables.
  .PARAMETER Node
    Feed-namespace arg or for-each element.
  .PARAMETER RuntimeVersion
    Optional bootstrap runtime version used to evaluate the element condition.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][Xml.XmlNode]$Node, [AllowNull()][version]$RuntimeVersion)

  if ($Node.LocalName -ceq 'arg') {
    if ([string]::IsNullOrWhiteSpace($Node.InnerText)) { throw 'A Zero Install <arg> element has no value.' }
    return [pscustomobject][ordered]@{ Kind = 'arg'; Value = $Node.InnerText; IfZeroInstallVersion = Get-ZeroInstallXmlAttribute -Node $Node -Name 'if-0install-version'; AppliesToRuntime = Get-ZeroInstallRuntimeApplicability -Node $Node -RuntimeVersion $RuntimeVersion }
  }
  if ($Node.LocalName -ceq 'for-each') {
    $ItemFrom = Get-ZeroInstallXmlAttribute -Node $Node -Name 'item-from'
    if ([string]::IsNullOrWhiteSpace($ItemFrom)) { throw 'A Zero Install <for-each> element is missing its required item-from attribute.' }
    $Arguments = [Collections.Generic.List[object]]::new()
    foreach ($Child in $Node.ChildNodes) {
      if ($Child.NodeType -eq [Xml.XmlNodeType]::Element -and $Child.NamespaceURI -ceq $Script:ZeroInstallFeedNamespace -and $Child.LocalName -ceq 'arg') { $Arguments.Add((ConvertFrom-ZeroInstallArgumentNode -Node $Child -RuntimeVersion $RuntimeVersion)) }
    }
    return [pscustomobject][ordered]@{ Kind = 'for-each'; ItemFrom = $ItemFrom; Separator = Get-ZeroInstallXmlAttribute -Node $Node -Name 'separator'; Arguments = $Arguments.ToArray(); ApplicableArguments = @($Arguments | Where-Object AppliesToRuntime -NE $false); IfZeroInstallVersion = Get-ZeroInstallXmlAttribute -Node $Node -Name 'if-0install-version'; AppliesToRuntime = Get-ZeroInstallRuntimeApplicability -Node $Node -RuntimeVersion $RuntimeVersion }
  }
  throw "Unsupported Zero Install argument element '$($Node.LocalName)'."
}

function ConvertFrom-ZeroInstallBindingNode {
  <#
  .SYNOPSIS
    Project one Zero Install implementation, dependency, or command binding.
  .PARAMETER Node
    Feed-namespace binding element.
  .PARAMETER SourceLevel
    Element level that declared the binding.
  .PARAMETER RuntimeVersion
    Optional bootstrap runtime version used to evaluate the element condition.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][Xml.XmlNode]$Node, [Parameter(Mandatory)][string]$SourceLevel, [AllowNull()][version]$RuntimeVersion)

  if ($Node.LocalName -notin 'binding', 'environment', 'overlay', 'executable-in-var', 'executable-in-path') { throw "Unsupported Zero Install binding '$($Node.LocalName)'." }
  $Name = Get-ZeroInstallXmlAttribute -Node $Node -Name 'name'
  if ($Node.LocalName -in 'environment', 'executable-in-var', 'executable-in-path' -and [string]::IsNullOrWhiteSpace($Name)) { throw "A Zero Install <$($Node.LocalName)> binding is missing its required name attribute." }
  [pscustomobject][ordered]@{
    Kind                 = $Node.LocalName
    Name                 = $Name
    Path                 = Get-ZeroInstallXmlAttribute -Node $Node -Name 'path'
    Value                = Get-ZeroInstallXmlAttribute -Node $Node -Name 'value'
    Insert               = Get-ZeroInstallXmlAttribute -Node $Node -Name 'insert'
    Mode                 = Get-ZeroInstallXmlAttribute -Node $Node -Name 'mode'
    Separator            = Get-ZeroInstallXmlAttribute -Node $Node -Name 'separator'
    Default              = Get-ZeroInstallXmlAttribute -Node $Node -Name 'default'
    Source               = Get-ZeroInstallXmlAttribute -Node $Node -Name 'src'
    MountPoint           = Get-ZeroInstallXmlAttribute -Node $Node -Name 'mount-point'
    Command              = Get-ZeroInstallXmlAttribute -Node $Node -Name 'command'
    IfZeroInstallVersion = Get-ZeroInstallXmlAttribute -Node $Node -Name 'if-0install-version'
    AppliesToRuntime     = Get-ZeroInstallRuntimeApplicability -Node $Node -RuntimeVersion $RuntimeVersion
    SourceLevel          = $SourceLevel
  }
}

function Get-ZeroInstallManifestDigest {
  <#
  .SYNOPSIS
    Project implementation digest attributes and legacy digest-bearing IDs.
  .PARAMETER Node
    Implementation element.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][Xml.XmlNode]$Node)

  $DigestNode = $null
  foreach ($Child in $Node.ChildNodes) {
    if ($Child.NodeType -eq [Xml.XmlNodeType]::Element -and $Child.NamespaceURI -ceq $Script:ZeroInstallFeedNamespace -and $Child.LocalName -ceq 'manifest-digest') { $DigestNode = $Child; break }
  }
  $Id = Get-ZeroInstallXmlAttribute -Node $Node -Name 'id'
  $Sha1 = $DigestNode ? (Get-ZeroInstallXmlAttribute -Node $DigestNode -Name 'sha1') : $null
  $Sha1New = $DigestNode ? (Get-ZeroInstallXmlAttribute -Node $DigestNode -Name 'sha1new') : $null
  $Sha256 = $DigestNode ? (Get-ZeroInstallXmlAttribute -Node $DigestNode -Name 'sha256') : $null
  $Sha256New = $DigestNode ? (Get-ZeroInstallXmlAttribute -Node $DigestNode -Name 'sha256new') : $null
  foreach ($Part in @($Id -split ',')) {
    if (-not $Sha1 -and $Part.StartsWith('sha1=', [StringComparison]::Ordinal)) { $Sha1 = $Part.Substring(5) }
    elseif (-not $Sha1New -and $Part.StartsWith('sha1new=', [StringComparison]::Ordinal)) { $Sha1New = $Part.Substring(8) }
    elseif (-not $Sha256 -and $Part.StartsWith('sha256=', [StringComparison]::Ordinal)) { $Sha256 = $Part.Substring(7) }
    elseif (-not $Sha256New -and $Part.StartsWith('sha256new_', [StringComparison]::Ordinal)) { $Sha256New = $Part.Substring(10) }
  }
  $Available = [Collections.Generic.List[string]]::new()
  if ($Sha256New) { $Available.Add("sha256new_$Sha256New") }
  if ($Sha256) { $Available.Add("sha256=$Sha256") }
  if ($Sha1New) { $Available.Add("sha1new=$Sha1New") }
  if ($Sha1) { $Available.Add("sha1=$Sha1") }
  [pscustomobject][ordered]@{ Sha1 = $Sha1; Sha1New = $Sha1New; Sha256 = $Sha256; Sha256New = $Sha256New; Available = $Available.ToArray(); Best = $Available.Count ? $Available[0] : $null }
}

function ConvertTo-ZeroInstallNonNegativeInteger {
  <#
  .SYNOPSIS
    Parse a bounded non-negative integer used by a Zero Install feed record.
  .PARAMETER Value
    Optional invariant-culture integer text.
  .PARAMETER Field
    Field name included in malformed-feed errors.
  .PARAMETER DefaultValue
    Value returned when the XML attribute is absent.
  .PARAMETER Maximum
    Largest accepted value.
  #>
  [OutputType([long])]
  param (
    [AllowNull()][string]$Value,
    [Parameter(Mandatory)][string]$Field,
    [long]$DefaultValue = 0,
    [ValidateRange(0, [long]::MaxValue)][long]$Maximum = [long]::MaxValue
  )

  if ([string]::IsNullOrEmpty($Value)) { return $DefaultValue }
  $Result = 0L
  if (-not [long]::TryParse($Value, [Globalization.NumberStyles]::None, [Globalization.CultureInfo]::InvariantCulture, [ref]$Result) -or $Result -lt 0 -or $Result -gt $Maximum) {
    throw "The Zero Install feed attribute '$Field' is not a valid non-negative integer: $Value"
  }
  return $Result
}

function Assert-ZeroInstallSafeIdentifier {
  <#
  .SYNOPSIS
    Validate an identifier using the Zero Install capability-model grammar.
  .PARAMETER Value
    Required identifier text.
  .PARAMETER Field
    Field name included in malformed-feed errors.
  #>
  param ([AllowNull()][string]$Value, [Parameter(Mandatory)][string]$Field)

  # ZeroInstall.Model.XmlUnknown.EnsureAttributeSafeID permits only this
  # deliberately narrow set before registry paths or association IDs are built.
  if ([string]::IsNullOrEmpty($Value) -or $Value -cnotmatch '^[a-zA-Z0-9 ._+\-]+$') {
    throw "The Zero Install $Field is missing or contains characters outside the safe identifier grammar."
  }
}

function Resolve-ZeroInstallXmlReference {
  <#
  .SYNOPSIS
    Resolve a feed reference using inherited xml:base and the caller's feed URI.
  .PARAMETER Node
    XML node that owns the URI-valued attribute.
  .PARAMETER Value
    Absolute or relative URI text.
  .PARAMETER BaseUri
    Optional URI from which the caller obtained the feed.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][Xml.XmlNode]$Node, [AllowNull()][string]$Value, [AllowNull()][uri]$BaseUri)

  if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }
  $EffectiveBase = $BaseUri
  $Ancestors = [Collections.Generic.List[Xml.XmlNode]]::new()
  for ($Current = $Node; $Current -and $Current.NodeType -ne [Xml.XmlNodeType]::Document; $Current = $Current.ParentNode) { $Ancestors.Add($Current) }
  for ($Index = $Ancestors.Count - 1; $Index -ge 0; $Index--) {
    $BaseAttribute = $Ancestors[$Index].Attributes.GetNamedItem('base', 'http://www.w3.org/XML/1998/namespace')
    if (-not $BaseAttribute -or [string]::IsNullOrWhiteSpace($BaseAttribute.Value)) { continue }
    $CandidateBase = $null
    if ($EffectiveBase) {
      if (-not [uri]::TryCreate($EffectiveBase, $BaseAttribute.Value, [ref]$CandidateBase)) { throw "The Zero Install xml:base value is invalid: $($BaseAttribute.Value)" }
    } elseif (-not [uri]::TryCreate($BaseAttribute.Value, [UriKind]::Absolute, [ref]$CandidateBase)) {
      # Without a caller-supplied document URI, a relative root xml:base cannot
      # be made absolute. Retain the unresolved reference instead of guessing.
      return $Value
    }
    $EffectiveBase = $CandidateBase
  }

  $Absolute = $null
  if ([uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$Absolute)) { return $Absolute.AbsoluteUri }
  if ($EffectiveBase -and [uri]::TryCreate($EffectiveBase, $Value, [ref]$Absolute)) { return $Absolute.AbsoluteUri }
  return $Value
}

function Get-ZeroInstallInheritedElementNode {
  <#
  .SYNOPSIS
    Return an implementation and ancestor groups in Zero Install accumulation order.
  .PARAMETER Node
    Implementation or package-implementation node.
  #>
  [OutputType([Xml.XmlNode[]])]
  param ([Parameter(Mandatory)][Xml.XmlNode]$Node)

  $Nodes = [Collections.Generic.List[Xml.XmlNode]]::new()
  for ($Current = $Node; $Current -and $Current.NodeType -ne [Xml.XmlNodeType]::Document; $Current = $Current.ParentNode) {
    if ($Current.NamespaceURI -ceq $Script:ZeroInstallFeedNamespace -and $Current.LocalName -in 'group', 'implementation', 'package-implementation') { $Nodes.Add($Current) }
  }
  return $Nodes.ToArray()
}

function ConvertFrom-ZeroInstallDependencyNode {
  <#
  .SYNOPSIS
    Project a requires or restricts element without invoking the Zero Install solver.
  .PARAMETER Node
    Feed-namespace requires or restricts element.
  .PARAMETER SourceLevel
    Group or implementation level from which this record was inherited.
  .PARAMETER BaseUri
    Optional caller-supplied feed URI used after inherited xml:base values.
  .PARAMETER RuntimeVersion
    Optional bootstrap runtime version used to evaluate the dependency and its bindings.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][Xml.XmlNode]$Node, [Parameter(Mandatory)][string]$SourceLevel, [AllowNull()][uri]$BaseUri, [AllowNull()][version]$RuntimeVersion)

  $Interface = Get-ZeroInstallXmlAttribute -Node $Node -Name 'interface'
  if ([string]::IsNullOrWhiteSpace($Interface)) { throw "The Zero Install <$($Node.LocalName)> element is missing its required interface attribute." }
  $VersionRanges = [Collections.Generic.List[object]]::new()
  $InlineVersion = Get-ZeroInstallXmlAttribute -Node $Node -Name 'version'
  if (-not [string]::IsNullOrWhiteSpace($InlineVersion)) {
    $VersionRanges.Add([pscustomobject][ordered]@{ Expression = $InlineVersion; NotBefore = $null; Before = $null })
  }
  foreach ($Constraint in $Node.ChildNodes) {
    if ($Constraint.NodeType -ne [Xml.XmlNodeType]::Element -or $Constraint.NamespaceURI -cne $Script:ZeroInstallFeedNamespace -or $Constraint.LocalName -cne 'version') { continue }
    $VersionRanges.Add([pscustomobject][ordered]@{
        Expression = $null
        NotBefore  = Get-ZeroInstallXmlAttribute -Node $Constraint -Name 'not-before'
        Before     = Get-ZeroInstallXmlAttribute -Node $Constraint -Name 'before'
      })
  }
  $Bindings = [Collections.Generic.List[object]]::new()
  foreach ($Child in $Node.ChildNodes) {
    if ($Child.NodeType -eq [Xml.XmlNodeType]::Element -and $Child.NamespaceURI -ceq $Script:ZeroInstallFeedNamespace -and $Child.LocalName -in 'binding', 'environment', 'overlay', 'executable-in-var', 'executable-in-path') {
      $Bindings.Add((ConvertFrom-ZeroInstallBindingNode -Node $Child -SourceLevel $SourceLevel -RuntimeVersion $RuntimeVersion))
    }
  }
  [pscustomobject][ordered]@{
    Kind                 = $Node.LocalName
    Interface            = $Interface
    ResolvedInterface    = Resolve-ZeroInstallXmlReference -Node $Node -Value $Interface -BaseUri $BaseUri
    Command              = Get-ZeroInstallXmlAttribute -Node $Node -Name 'command'
    Importance           = Get-ZeroInstallXmlAttribute -Node $Node -Name 'importance'
    Use                  = Get-ZeroInstallXmlAttribute -Node $Node -Name 'use'
    OperatingSystem      = Get-ZeroInstallXmlAttribute -Node $Node -Name 'os'
    Distribution         = Get-ZeroInstallXmlAttribute -Node $Node -Name 'distribution'
    IfZeroInstallVersion = Get-ZeroInstallXmlAttribute -Node $Node -Name 'if-0install-version'
    AppliesToRuntime     = Get-ZeroInstallRuntimeApplicability -Node $Node -RuntimeVersion $RuntimeVersion
    VersionRanges        = $VersionRanges.ToArray()
    Bindings             = $Bindings.ToArray()
    ApplicableBindings   = @($Bindings | Where-Object AppliesToRuntime -NE $false)
    SourceLevel          = $SourceLevel
  }
}

function ConvertFrom-ZeroInstallCommandNode {
  <#
  .SYNOPSIS
    Project an inherited Zero Install command and its command-local dependencies.
  .PARAMETER Node
    Feed-namespace command element.
  .PARAMETER SourceLevel
    Group or implementation level that declared the command.
  .PARAMETER BaseUri
    Optional caller-supplied feed URI used for command-local dependencies.
  .PARAMETER RuntimeVersion
    Optional bootstrap runtime version used to evaluate the command and its children.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][Xml.XmlNode]$Node, [Parameter(Mandatory)][string]$SourceLevel, [AllowNull()][uri]$BaseUri, [AllowNull()][version]$RuntimeVersion)

  $Name = Get-ZeroInstallXmlAttribute -Node $Node -Name 'name'
  if ([string]::IsNullOrWhiteSpace($Name)) { throw 'A Zero Install <command> element is missing its required name attribute.' }
  $Dependencies = [Collections.Generic.List[object]]::new()
  $Restrictions = [Collections.Generic.List[object]]::new()
  $Arguments = [Collections.Generic.List[object]]::new()
  $Bindings = [Collections.Generic.List[object]]::new()
  $WorkingDirectory = $null
  $Runner = $null
  foreach ($Child in $Node.ChildNodes) {
    if ($Child.NodeType -ne [Xml.XmlNodeType]::Element -or $Child.NamespaceURI -cne $Script:ZeroInstallFeedNamespace) { continue }
    if ($Child.LocalName -ceq 'requires') { $Dependencies.Add((ConvertFrom-ZeroInstallDependencyNode -Node $Child -SourceLevel "command:$Name" -BaseUri $BaseUri -RuntimeVersion $RuntimeVersion)) }
    elseif ($Child.LocalName -ceq 'restricts') { $Restrictions.Add((ConvertFrom-ZeroInstallDependencyNode -Node $Child -SourceLevel "command:$Name" -BaseUri $BaseUri -RuntimeVersion $RuntimeVersion)) }
    elseif ($Child.LocalName -in 'arg', 'for-each') { $Arguments.Add((ConvertFrom-ZeroInstallArgumentNode -Node $Child -RuntimeVersion $RuntimeVersion)) }
    elseif ($Child.LocalName -in 'binding', 'environment', 'overlay', 'executable-in-var', 'executable-in-path') { $Bindings.Add((ConvertFrom-ZeroInstallBindingNode -Node $Child -SourceLevel "command:$Name" -RuntimeVersion $RuntimeVersion)) }
    elseif ($Child.LocalName -ceq 'working-dir') { $WorkingDirectory = [pscustomobject][ordered]@{ Source = Get-ZeroInstallXmlAttribute -Node $Child -Name 'src'; IfZeroInstallVersion = Get-ZeroInstallXmlAttribute -Node $Child -Name 'if-0install-version'; AppliesToRuntime = Get-ZeroInstallRuntimeApplicability -Node $Child -RuntimeVersion $RuntimeVersion } }
    elseif ($Child.LocalName -ceq 'runner') {
      $Runner = ConvertFrom-ZeroInstallDependencyNode -Node $Child -SourceLevel "command:$Name" -BaseUri $BaseUri -RuntimeVersion $RuntimeVersion
      $RunnerArguments = [Collections.Generic.List[object]]::new()
      foreach ($RunnerChild in $Child.ChildNodes) {
        if ($RunnerChild.NodeType -eq [Xml.XmlNodeType]::Element -and $RunnerChild.NamespaceURI -ceq $Script:ZeroInstallFeedNamespace -and $RunnerChild.LocalName -in 'arg', 'for-each') { $RunnerArguments.Add((ConvertFrom-ZeroInstallArgumentNode -Node $RunnerChild -RuntimeVersion $RuntimeVersion)) }
      }
      $Runner | Add-Member -NotePropertyName Arguments -NotePropertyValue $RunnerArguments.ToArray()
    }
  }
  [pscustomobject][ordered]@{
    Name                       = $Name
    Path                       = Get-ZeroInstallXmlAttribute -Node $Node -Name 'path'
    IfZeroInstallVersion       = Get-ZeroInstallXmlAttribute -Node $Node -Name 'if-0install-version'
    AppliesToRuntime           = Get-ZeroInstallRuntimeApplicability -Node $Node -RuntimeVersion $RuntimeVersion
    Arguments                  = $Arguments.ToArray()
    ApplicableArguments        = @($Arguments | Where-Object AppliesToRuntime -NE $false)
    Bindings                   = $Bindings.ToArray()
    ApplicableBindings         = @($Bindings | Where-Object AppliesToRuntime -NE $false)
    WorkingDirectory           = $WorkingDirectory
    ApplicableWorkingDirectory = if ($WorkingDirectory -and $WorkingDirectory.AppliesToRuntime -ne $false) { $WorkingDirectory } else { $null }
    Runner                     = $Runner
    ApplicableRunner           = if ($Runner -and $Runner.AppliesToRuntime -ne $false) { $Runner } else { $null }
    Dependencies               = $Dependencies.ToArray()
    ApplicableDependencies     = @($Dependencies | Where-Object AppliesToRuntime -NE $false)
    Restrictions               = $Restrictions.ToArray()
    ApplicableRestrictions     = @($Restrictions | Where-Object AppliesToRuntime -NE $false)
    SourceLevel                = $SourceLevel
  }
}

function ConvertFrom-ZeroInstallRetrievalNode {
  <#
  .SYNOPSIS
    Project an archive, file, or recipe retrieval method in document order.
  .PARAMETER Node
    Feed-namespace retrieval-method node.
  .PARAMETER BaseUri
    Optional caller-supplied feed URI used after inherited xml:base values.
  .PARAMETER RuntimeVersion
    Optional bootstrap runtime version used to evaluate the method and recipe steps.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][Xml.XmlNode]$Node, [AllowNull()][uri]$BaseUri, [AllowNull()][version]$RuntimeVersion)

  switch ($Node.LocalName) {
    'archive' {
      $Href = Get-ZeroInstallXmlAttribute -Node $Node -Name 'href'
      if ([string]::IsNullOrWhiteSpace($Href)) { throw 'A Zero Install <archive> element is missing its required href attribute.' }
      $SizeText = Get-ZeroInstallXmlAttribute -Node $Node -Name 'size'
      $Size = ConvertTo-ZeroInstallNonNegativeInteger -Value $SizeText -Field 'archive.size'
      $StartOffset = ConvertTo-ZeroInstallNonNegativeInteger -Value (Get-ZeroInstallXmlAttribute -Node $Node -Name 'start-offset') -Field 'archive.start-offset' -Maximum ([int]::MaxValue)
      [pscustomobject][ordered]@{
        Kind                 = 'archive'
        Href                 = $Href
        ResolvedHref         = Resolve-ZeroInstallXmlReference -Node $Node -Value $Href -BaseUri $BaseUri
        Size                 = $Size
        HasDeclaredSize      = -not [string]::IsNullOrWhiteSpace($SizeText)
        DownloadSize         = $Size + $StartOffset
        Type                 = Get-ZeroInstallXmlAttribute -Node $Node -Name 'type'
        Extract              = Get-ZeroInstallXmlAttribute -Node $Node -Name 'extract'
        Destination          = Get-ZeroInstallXmlAttribute -Node $Node -Name 'dest'
        StartOffset          = $StartOffset
        IfZeroInstallVersion = Get-ZeroInstallXmlAttribute -Node $Node -Name 'if-0install-version'
        AppliesToRuntime     = Get-ZeroInstallRuntimeApplicability -Node $Node -RuntimeVersion $RuntimeVersion
      }
    }
    'file' {
      $Href = Get-ZeroInstallXmlAttribute -Node $Node -Name 'href'
      $Destination = Get-ZeroInstallXmlAttribute -Node $Node -Name 'dest'
      if ([string]::IsNullOrWhiteSpace($Href)) { throw 'A Zero Install <file> element is missing its required href attribute.' }
      if ([string]::IsNullOrWhiteSpace($Destination)) { throw 'A Zero Install <file> element is missing its required dest attribute.' }
      $SizeText = Get-ZeroInstallXmlAttribute -Node $Node -Name 'size'
      [pscustomobject][ordered]@{
        Kind                 = 'file'
        Href                 = $Href
        ResolvedHref         = Resolve-ZeroInstallXmlReference -Node $Node -Value $Href -BaseUri $BaseUri
        Size                 = ConvertTo-ZeroInstallNonNegativeInteger -Value $SizeText -Field 'file.size'
        HasDeclaredSize      = -not [string]::IsNullOrWhiteSpace($SizeText)
        Destination          = $Destination
        Executable           = (Get-ZeroInstallXmlAttribute -Node $Node -Name 'executable') -ieq 'true'
        IfZeroInstallVersion = Get-ZeroInstallXmlAttribute -Node $Node -Name 'if-0install-version'
        AppliesToRuntime     = Get-ZeroInstallRuntimeApplicability -Node $Node -RuntimeVersion $RuntimeVersion
      }
    }
    'recipe' {
      $Steps = [Collections.Generic.List[object]]::new()
      $UnknownSteps = [Collections.Generic.List[object]]::new()
      foreach ($Child in $Node.ChildNodes) {
        if ($Child.NodeType -ne [Xml.XmlNodeType]::Element -or $Child.NamespaceURI -cne $Script:ZeroInstallFeedNamespace) { continue }
        if ($Child.LocalName -in 'archive', 'file') { $Steps.Add((ConvertFrom-ZeroInstallRetrievalNode -Node $Child -BaseUri $BaseUri -RuntimeVersion $RuntimeVersion)); continue }
        if ($Child.LocalName -ceq 'rename') {
          $Source = Get-ZeroInstallXmlAttribute -Node $Child -Name 'source'
          $Destination = Get-ZeroInstallXmlAttribute -Node $Child -Name 'dest'
          if ([string]::IsNullOrWhiteSpace($Source) -or [string]::IsNullOrWhiteSpace($Destination)) { throw 'A Zero Install <rename> step requires source and dest attributes.' }
          $Steps.Add([pscustomobject][ordered]@{ Kind = 'rename'; Source = $Source; Destination = $Destination; IfZeroInstallVersion = Get-ZeroInstallXmlAttribute -Node $Child -Name 'if-0install-version'; AppliesToRuntime = Get-ZeroInstallRuntimeApplicability -Node $Child -RuntimeVersion $RuntimeVersion })
          continue
        }
        if ($Child.LocalName -ceq 'remove') {
          $RemovePath = Get-ZeroInstallXmlAttribute -Node $Child -Name 'path'
          if ([string]::IsNullOrWhiteSpace($RemovePath)) { throw 'A Zero Install <remove> step requires a path attribute.' }
          $Steps.Add([pscustomobject][ordered]@{ Kind = 'remove'; Path = $RemovePath; IfZeroInstallVersion = Get-ZeroInstallXmlAttribute -Node $Child -Name 'if-0install-version'; AppliesToRuntime = Get-ZeroInstallRuntimeApplicability -Node $Child -RuntimeVersion $RuntimeVersion })
          continue
        }
        if ($Child.LocalName -ceq 'copy-from') {
          $Steps.Add([pscustomobject][ordered]@{ Kind = 'copy-from'; Id = Get-ZeroInstallXmlAttribute -Node $Child -Name 'id'; Source = Get-ZeroInstallXmlAttribute -Node $Child -Name 'source'; Destination = Get-ZeroInstallXmlAttribute -Node $Child -Name 'dest'; IfZeroInstallVersion = Get-ZeroInstallXmlAttribute -Node $Child -Name 'if-0install-version'; AppliesToRuntime = Get-ZeroInstallRuntimeApplicability -Node $Child -RuntimeVersion $RuntimeVersion })
          continue
        }
        # Upstream retains unknown recipe elements and marks the recipe as
        # unusable. Preserve the element identity so callers do not mistake a
        # partially projected recipe for complete extraction instructions.
        $UnknownSteps.Add([pscustomobject][ordered]@{
            Name                 = $Child.LocalName
            Namespace            = $Child.NamespaceURI
            IfZeroInstallVersion = Get-ZeroInstallXmlAttribute -Node $Child -Name 'if-0install-version'
            AppliesToRuntime     = Get-ZeroInstallRuntimeApplicability -Node $Child -RuntimeVersion $RuntimeVersion
          })
      }
      [pscustomobject][ordered]@{
        Kind                 = 'recipe'
        IfZeroInstallVersion = Get-ZeroInstallXmlAttribute -Node $Node -Name 'if-0install-version'
        AppliesToRuntime     = Get-ZeroInstallRuntimeApplicability -Node $Node -RuntimeVersion $RuntimeVersion
        Steps                = $Steps.ToArray()
        ApplicableSteps      = @($Steps | Where-Object AppliesToRuntime -NE $false)
        ContainsUnknownSteps = $UnknownSteps.Count -gt 0
        UnknownSteps         = $UnknownSteps.ToArray()
      }
    }
  }
}

function Split-ZeroInstallCommandLine {
  <#
  .SYNOPSIS
    Split configured bootstrap arguments using Windows command-line quoting rules.
  .PARAMETER CommandLine
    Argument text passed through WindowsUtils.SplitArgs by the bootstrap runtime.
  #>
  [OutputType([string[]])]
  param ([AllowNull()][string]$CommandLine)

  if ([string]::IsNullOrEmpty($CommandLine)) { return [string[]]@() }
  $Arguments = [Collections.Generic.List[string]]::new()
  $Length = $CommandLine.Length
  $Index = 0
  while ($Index -lt $Length) {
    while ($Index -lt $Length -and [char]::IsWhiteSpace($CommandLine[$Index])) { $Index++ }
    if ($Index -ge $Length) { break }
    $Builder = [Text.StringBuilder]::new()
    $InQuotes = $false
    while ($Index -lt $Length) {
      if (-not $InQuotes -and [char]::IsWhiteSpace($CommandLine[$Index])) { break }
      $SlashCount = 0
      while ($Index -lt $Length -and $CommandLine[$Index] -eq [char]'\') { $SlashCount++; $Index++ }
      if ($Index -lt $Length -and $CommandLine[$Index] -eq [char]'"') {
        if ($SlashCount -gt 0) { $null = $Builder.Append([char]'\', [int]($SlashCount / 2)) }
        if (($SlashCount % 2) -eq 1) { $null = $Builder.Append([char]'"'); $Index++; continue }
        $Index++
        if ($InQuotes -and $Index -lt $Length -and $CommandLine[$Index] -eq [char]'"') { $null = $Builder.Append([char]'"'); $Index++; continue }
        $InQuotes = -not $InQuotes
        continue
      }
      if ($SlashCount -gt 0) { $null = $Builder.Append([char]'\', $SlashCount) }
      if ($Index -lt $Length) { $null = $Builder.Append($CommandLine[$Index]); $Index++ }
    }
    $Arguments.Add($Builder.ToString())
  }
  return $Arguments.ToArray()
}

function Resolve-ZeroInstallIntegrationSelection {
  <#
  .SYNOPSIS
    Resolve capability categories selected by 0install integrate arguments.
  .PARAMETER ArgumentList
    Arguments passed after the feed URI to the integrate command.
  #>
  [OutputType([pscustomobject])]
  param ([AllowEmptyCollection()][string[]]$ArgumentList = @())

  $Added = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $Removed = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $Unknown = [Collections.Generic.List[string]]::new()
  $All = @('capability-registration', 'menu-entry', 'desktop-icon', 'send-to', 'app-alias', 'auto-start', 'default-access-point')
  $Standard = @('capability-registration', 'menu-entry', 'send-to', 'app-alias')
  function ConvertCategory([string]$Value) {
    switch ($Value.ToLowerInvariant()) {
      'capabilities' { 'capability-registration' }
      'defaults' { 'default-access-point' }
      'alias' { 'app-alias' }
      'menu' { 'menu-entry' }
      'desktop' { 'desktop-icon' }
      default { $Value.ToLowerInvariant() }
    }
  }

  foreach ($Argument in $ArgumentList) {
    if ($Argument -ceq '--add-all') { foreach ($Category in $All) { $null = $Added.Add($Category) }; continue }
    if ($Argument -ceq '--add-standard') { foreach ($Category in $Standard) { $null = $Added.Add($Category) }; continue }
    if ($Argument -ceq '--remove-all') { foreach ($Category in $All) { $null = $Removed.Add($Category) }; continue }
    if ($Argument -match '^--(?<Action>add|remove)=(?<Category>.+)$') {
      $Category = ConvertCategory $Matches.Category
      if ($Category -notin $All) { $Unknown.Add($Argument); continue }
      if ($Matches.Action -ceq 'add') { $null = $Added.Add($Category) } else { $null = $Removed.Add($Category) }
    }
  }

  # IntegrateApp removes categories first and then adds them, regardless of
  # command-line order. With no requested changes it opens the integration UI,
  # so static analysis cannot claim which optional associations are selected.
  [pscustomobject][ordered]@{
    HasSpecifiedIntegrations     = $Added.Count -gt 0 -or $Removed.Count -gt 0 -or $Unknown.Count -gt 0
    IsDeterministic              = $Unknown.Count -eq 0 -and ($Added.Count -gt 0 -or $Removed.Count -gt 0)
    HasUnknownCategories         = $Unknown.Count -gt 0
    AddedCategories              = [string[]]@($Added | Sort-Object)
    RemovedCategories            = [string[]]@($Removed | Sort-Object)
    UnknownArguments             = $Unknown.ToArray()
    RegistersAllCapabilities     = $Added.Contains('capability-registration')
    RegistersDefaultCapabilities = $Added.Contains('default-access-point')
  }
}

function ConvertFrom-ZeroInstallFeed {
  <#
  .SYNOPSIS
    Convert caller-supplied Zero Install feed XML into static package evidence
  .DESCRIPTION
    Parses the official feed namespace, group inheritance, implementation and
    package-manager records, commands, requirements, restrictions, retrieval
    recipes, feed references, and Windows-compatible capabilities. It does not
    select an implementation because the Zero Install solver also considers
    local policy, trust, dependencies, and rollout percentage.
  .PARAMETER Content
    Raw feed XML. The function never retrieves the feed URL itself.
  .PARAMETER BaseUri
    Optional retrieval URI used to resolve relative archive references in local feeds.
  .PARAMETER RuntimeVersion
    Optional bootstrap runtime version used to resolve if-0install-version conditions.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][ValidateNotNullOrEmpty()][string]$Content,
    [uri]$BaseUri,
    [AllowNull()][version]$RuntimeVersion
  )
  process {
    if ([Text.Encoding]::UTF8.GetByteCount($Content) -gt $Script:ZeroInstallMaximumFeedBytes) {
      throw "The Zero Install feed exceeds the $Script:ZeroInstallMaximumFeedBytes-byte limit."
    }

    # Prohibit DTDs and external resolution so untrusted feed text cannot read
    # local files or expand external entities during static analysis.
    $Document = Read-BoundedXmlDocument -Content $Content -MaximumCharacters $Script:ZeroInstallMaximumFeedBytes

    $Root = $Document.DocumentElement
    if (-not $Root -or $Root.LocalName -cne 'interface' -or $Root.NamespaceURI -cne $Script:ZeroInstallFeedNamespace) { throw 'The XML is not a namespaced Zero Install interface feed.' }
    $FeedName = Get-ZeroInstallXmlDirectChildText -Node $Root -LocalName 'name' -NamespaceUri $Script:ZeroInstallFeedNamespace
    if ([string]::IsNullOrWhiteSpace($FeedName)) { throw 'The Zero Install interface feed is missing its required name element.' }

    $NamespaceManager = [Xml.XmlNamespaceManager]::new($Document.NameTable)
    $NamespaceManager.AddNamespace('zi', $Script:ZeroInstallFeedNamespace)
    $NamespaceManager.AddNamespace('cap', $Script:ZeroInstallCapabilityNamespace)

    $Diagnostics = [Collections.Generic.List[object]]::new()
    $Implementations = [Collections.Generic.List[object]]::new()
    $AllRequirements = [Collections.Generic.List[object]]::new()
    $AllRestrictions = [Collections.Generic.List[object]]::new()
    $ArchitectureSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $ImplementationIndex = -1
    foreach ($Node in $Root.SelectNodes('.//zi:implementation | .//zi:package-implementation', $NamespaceManager)) {
      $ImplementationIndex++
      $SourceArchitecture = Get-ZeroInstallInheritedXmlAttribute -Node $Node -Name 'arch'
      $Architecture = ConvertFrom-ZeroInstallArchitecture -Architecture $SourceArchitecture
      if ($Architecture) { $null = $ArchitectureSet.Add($Architecture) }
      elseif ($SourceArchitecture -match '^(?i:Windows|\*|all|any)-' -and $SourceArchitecture -notmatch '(?i)-(\*|all|any|noarch|src|\(none\))$') {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'ZeroInstall.Feed.ArchitectureUnknown' -Source 'ZeroInstall' -Message "Unsupported or unknown Zero Install architecture '$SourceArchitecture' requires manual mapping." -Kind Incomplete -Areas Metadata -AffectedFields Architecture -Evidence $SourceArchitecture))
      }

      # Group attributes use nearest-value inheritance. Collection entries use
      # Zero Install's child-first order: implementation, nearest group, then
      # outer groups. Preserve the declaring level on every record.
      $Requirements = [Collections.Generic.List[object]]::new()
      $Restrictions = [Collections.Generic.List[object]]::new()
      $Commands = [Collections.Generic.List[object]]::new()
      $Bindings = [Collections.Generic.List[object]]::new()
      foreach ($ElementNode in Get-ZeroInstallInheritedElementNode -Node $Node) {
        $SourceLevel = $ElementNode.LocalName -ceq 'group' ? 'group' : 'implementation'
        foreach ($Child in $ElementNode.ChildNodes) {
          if ($Child.NodeType -ne [Xml.XmlNodeType]::Element -or $Child.NamespaceURI -cne $Script:ZeroInstallFeedNamespace) { continue }
          if ($Child.LocalName -ceq 'requires') {
            $Requirement = ConvertFrom-ZeroInstallDependencyNode -Node $Child -SourceLevel $SourceLevel -BaseUri $BaseUri -RuntimeVersion $RuntimeVersion
            $Requirement | Add-Member -NotePropertyName ImplementationIndex -NotePropertyValue $ImplementationIndex
            $Requirement | Add-Member -NotePropertyName ImplementationId -NotePropertyValue (Get-ZeroInstallXmlAttribute -Node $Node -Name 'id')
            $Requirements.Add($Requirement)
            $AllRequirements.Add($Requirement)
          } elseif ($Child.LocalName -ceq 'restricts') {
            $Restriction = ConvertFrom-ZeroInstallDependencyNode -Node $Child -SourceLevel $SourceLevel -BaseUri $BaseUri -RuntimeVersion $RuntimeVersion
            $Restriction | Add-Member -NotePropertyName ImplementationIndex -NotePropertyValue $ImplementationIndex
            $Restriction | Add-Member -NotePropertyName ImplementationId -NotePropertyValue (Get-ZeroInstallXmlAttribute -Node $Node -Name 'id')
            $Restrictions.Add($Restriction)
            $AllRestrictions.Add($Restriction)
          } elseif ($Child.LocalName -ceq 'command') {
            $Commands.Add((ConvertFrom-ZeroInstallCommandNode -Node $Child -SourceLevel $SourceLevel -BaseUri $BaseUri -RuntimeVersion $RuntimeVersion))
          } elseif ($Child.LocalName -in 'binding', 'environment', 'overlay', 'executable-in-var', 'executable-in-path') {
            $Bindings.Add((ConvertFrom-ZeroInstallBindingNode -Node $Child -SourceLevel $SourceLevel -RuntimeVersion $RuntimeVersion))
          }
        }
      }

      # Retrieval methods are direct implementation children. Recipe steps are
      # retained in order because rename/remove/copy-from semantics are ordered.
      $RetrievalMethods = [Collections.Generic.List[object]]::new()
      foreach ($Child in $Node.ChildNodes) {
        if ($Child.NodeType -eq [Xml.XmlNodeType]::Element -and $Child.NamespaceURI -ceq $Script:ZeroInstallFeedNamespace -and $Child.LocalName -in 'archive', 'file', 'recipe') {
          $RetrievalMethods.Add((ConvertFrom-ZeroInstallRetrievalNode -Node $Child -BaseUri $BaseUri -RuntimeVersion $RuntimeVersion))
        }
      }
      $Archives = [Collections.Generic.List[object]]::new()
      $Files = [Collections.Generic.List[object]]::new()
      foreach ($Method in $RetrievalMethods) {
        if ($Method.Kind -ceq 'archive') { $Archives.Add($Method) }
        elseif ($Method.Kind -ceq 'file') { $Files.Add($Method) }
        elseif ($Method.Kind -ceq 'recipe') {
          if ($Method.AppliesToRuntime -ne $false -and $Method.ContainsUnknownSteps) {
            $UnknownStepNames = @($Method.UnknownSteps.Name | Sort-Object -Unique)
            $Diagnostics.Add((New-InstallerDiagnostic -Id 'ZeroInstall.Feed.RecipeStepsUnsupported' -Source 'ZeroInstall' -Message "A Zero Install retrieval recipe contains unsupported step types: $($UnknownStepNames -join ', ')." -Kind Unsupported -Areas Extraction -AffectedFields ExtractedFiles -Evidence ([pscustomobject][ordered]@{ ImplementationIndex = $ImplementationIndex; ImplementationId = Get-ZeroInstallXmlAttribute -Node $Node -Name 'id'; StepNames = $UnknownStepNames })))
          }
          foreach ($Step in $Method.Steps) {
            if ($Step.Kind -ceq 'archive') { $Archives.Add($Step) }
            elseif ($Step.Kind -ceq 'file') { $Files.Add($Step) }
          }
        }
      }
      $ApplicableArchives = @($Archives | Where-Object AppliesToRuntime -NE $false)
      $ApplicableFiles = @($Files | Where-Object AppliesToRuntime -NE $false)
      $ApplicableRetrievalMethods = @($RetrievalMethods | Where-Object AppliesToRuntime -NE $false)
      $Archive = $ApplicableArchives.Count -gt 0 ? $ApplicableArchives[0] : $null
      $IsPackageImplementation = $Node.LocalName -ceq 'package-implementation'
      $Version = Get-ZeroInstallInheritedXmlAttribute -Node $Node -Name 'version'
      $VersionModifier = Get-ZeroInstallInheritedXmlAttribute -Node $Node -Name 'version-modifier'
      if (-not $IsPackageImplementation -and [string]::IsNullOrWhiteSpace($Version)) { throw 'A Zero Install <implementation> element has no effective version attribute.' }
      if (-not $IsPackageImplementation -and -not [string]::IsNullOrEmpty($VersionModifier)) { $Version += $VersionModifier }
      $Id = Get-ZeroInstallXmlAttribute -Node $Node -Name 'id'
      if (-not $IsPackageImplementation -and [string]::IsNullOrWhiteSpace($Id)) { throw 'A Zero Install <implementation> element is missing its required id attribute.' }
      $ManifestDigest = Get-ZeroInstallManifestDigest -Node $Node
      $Stability = $IsPackageImplementation ? 'packaged' : (Get-ZeroInstallInheritedXmlAttribute -Node $Node -Name 'stability')
      if (-not $Stability) { $Stability = 'testing' }
      $RolloutPercentage = ConvertTo-ZeroInstallNonNegativeInteger -Value (Get-ZeroInstallInheritedXmlAttribute -Node $Node -Name 'rollout-percentage') -Field 'rollout-percentage' -Maximum 100
      if ($RolloutPercentage -gt 0 -and $Stability -cne 'testing') { throw 'A Zero Install rollout-percentage is valid only for testing implementations.' }
      $AppliesToRuntime = Get-ZeroInstallRuntimeApplicability -Node $Node -RuntimeVersion $RuntimeVersion
      $Implementations.Add([pscustomobject][ordered]@{
          Kind                       = $Node.LocalName
          Id                         = $Id
          IfZeroInstallVersion       = Get-ZeroInstallXmlAttribute -Node $Node -Name 'if-0install-version'
          AppliesToRuntime           = $AppliesToRuntime
          ManifestDigest             = $ManifestDigest
          Package                    = Get-ZeroInstallXmlAttribute -Node $Node -Name 'package'
          Distributions              = @((Get-ZeroInstallXmlAttribute -Node $Node -Name 'distributions') -split ' ' | Where-Object { $_ })
          Version                    = $Version
          VersionModifier            = $VersionModifier
          Released                   = Get-ZeroInstallXmlAttribute -Node $Node -Name 'released'
          Stability                  = $Stability
          RolloutPercentage          = $RolloutPercentage
          License                    = Get-ZeroInstallInheritedXmlAttribute -Node $Node -Name 'license'
          Main                       = Get-ZeroInstallInheritedXmlAttribute -Node $Node -Name 'main'
          SelfTest                   = Get-ZeroInstallInheritedXmlAttribute -Node $Node -Name 'self-test'
          DocumentationPath          = Get-ZeroInstallInheritedXmlAttribute -Node $Node -Name 'doc-dir'
          LocalPath                  = Get-ZeroInstallXmlAttribute -Node $Node -Name 'local-path'
          SourceArchitecture         = $SourceArchitecture
          Architecture               = $Architecture
          ArchiveUrl                 = $Archive ? $Archive.ResolvedHref : $null
          ArchiveSize                = $Archive ? $Archive.Size : $null
          ArchiveType                = $Archive ? $Archive.Type : $null
          Archives                   = $Archives.ToArray()
          ApplicableArchives         = $ApplicableArchives
          Files                      = $Files.ToArray()
          ApplicableFiles            = $ApplicableFiles
          RetrievalMethods           = $RetrievalMethods.ToArray()
          Requirements               = $Requirements.ToArray()
          ApplicableRequirements     = @($Requirements | Where-Object AppliesToRuntime -NE $false)
          Restrictions               = $Restrictions.ToArray()
          ApplicableRestrictions     = @($Restrictions | Where-Object AppliesToRuntime -NE $false)
          Commands                   = $Commands.ToArray()
          ApplicableCommands         = @($Commands | Where-Object AppliesToRuntime -NE $false)
          Bindings                   = $Bindings.ToArray()
          ApplicableBindings         = @($Bindings | Where-Object AppliesToRuntime -NE $false)
          ApplicableRetrievalMethods = $ApplicableRetrievalMethods
        })
    }

    # Capabilities use their own XML namespace and are scoped by an OS filter.
    # Only lists compatible with Windows contribute manifest associations.
    $ProtocolSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $ExtensionSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $DefaultProtocolSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $DefaultExtensionSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $Capabilities = [Collections.Generic.List[object]]::new()
    foreach ($CapabilityList in $Root.SelectNodes('./cap:capabilities', $NamespaceManager)) {
      $CapabilityOs = (Get-ZeroInstallXmlAttribute -Node $CapabilityList -Name 'os')
      if ([string]::IsNullOrWhiteSpace($CapabilityOs)) { $CapabilityOs = '*' }
      $WindowsCompatible = $CapabilityOs -in '*', 'Windows'
      foreach ($Capability in $CapabilityList.ChildNodes) {
        if ($Capability.NodeType -ne [Xml.XmlNodeType]::Element -or $Capability.NamespaceURI -cne $Script:ZeroInstallCapabilityNamespace) { continue }
        $Id = Get-ZeroInstallXmlAttribute -Node $Capability -Name 'id'
        $ExplicitOnly = ConvertFrom-ZeroInstallXmlBoolean -Value (Get-ZeroInstallXmlAttribute -Node $Capability -Name 'explicit-only') -Field "$($Capability.LocalName).explicit-only"
        $Extensions = [Collections.Generic.List[object]]::new()
        $KnownPrefixes = [Collections.Generic.List[string]]::new()
        if ($Capability.LocalName -ceq 'file-type') {
          Assert-ZeroInstallSafeIdentifier -Value $Id -Field 'file-type.id'
          foreach ($ExtensionNode in $Capability.ChildNodes) {
            if ($ExtensionNode.NodeType -ne [Xml.XmlNodeType]::Element -or $ExtensionNode.NamespaceURI -cne $Script:ZeroInstallCapabilityNamespace -or $ExtensionNode.LocalName -cne 'extension') { continue }
            $Value = Get-ZeroInstallXmlAttribute -Node $ExtensionNode -Name 'value'
            if ([string]::IsNullOrWhiteSpace($Value)) { throw 'A Zero Install file-type extension is missing its required value attribute.' }
            Assert-ZeroInstallSafeIdentifier -Value $Value -Field 'file-type.extension.value'
            $NormalizedValue = $Value.Trim().TrimStart('.').ToLowerInvariant()
            $Extensions.Add([pscustomobject][ordered]@{ Value = $NormalizedValue; MimeType = Get-ZeroInstallXmlAttribute -Node $ExtensionNode -Name 'mime-type'; PerceivedType = Get-ZeroInstallXmlAttribute -Node $ExtensionNode -Name 'perceived-type' })
            if ($WindowsCompatible) {
              $null = $ExtensionSet.Add($NormalizedValue)
              if (-not $ExplicitOnly) { $null = $DefaultExtensionSet.Add($NormalizedValue) }
            }
          }
        } elseif ($Capability.LocalName -ceq 'url-protocol') {
          Assert-ZeroInstallSafeIdentifier -Value $Id -Field 'url-protocol.id'
          foreach ($PrefixNode in $Capability.ChildNodes) {
            if ($PrefixNode.NodeType -ne [Xml.XmlNodeType]::Element -or $PrefixNode.NamespaceURI -cne $Script:ZeroInstallCapabilityNamespace -or $PrefixNode.LocalName -cne 'known-prefix') { continue }
            $Prefix = Get-ZeroInstallXmlAttribute -Node $PrefixNode -Name 'value'
            Assert-ZeroInstallSafeIdentifier -Value $Prefix -Field 'url-protocol.known-prefix.value'
            $KnownPrefixes.Add($Prefix.ToLowerInvariant())
          }
          if ($WindowsCompatible) {
            if ($KnownPrefixes.Count -eq 0) {
              $Protocol = $Id.ToLowerInvariant()
              $null = $ProtocolSet.Add($Protocol)
              if (-not $ExplicitOnly) { $null = $DefaultProtocolSet.Add($Protocol) }
            } else {
              foreach ($Prefix in $KnownPrefixes) {
                $null = $ProtocolSet.Add($Prefix)
                if (-not $ExplicitOnly) { $null = $DefaultProtocolSet.Add($Prefix) }
              }
            }
          }
        }
        $Attributes = [ordered]@{}
        foreach ($Attribute in $Capability.Attributes) { if ($Attribute.NamespaceURI -ne 'http://www.w3.org/2000/xmlns/') { $Attributes[$Attribute.Name] = $Attribute.Value } }
        $Verbs = [Collections.Generic.List[object]]::new()
        foreach ($Verb in $Capability.ChildNodes) {
          if ($Verb.NodeType -ne [Xml.XmlNodeType]::Element -or $Verb.NamespaceURI -cne $Script:ZeroInstallCapabilityNamespace -or $Verb.LocalName -cne 'verb') { continue }
          $VerbName = Get-ZeroInstallXmlAttribute -Node $Verb -Name 'name'
          Assert-ZeroInstallSafeIdentifier -Value $VerbName -Field "$($Capability.LocalName).verb.name"
          $Arguments = [Collections.Generic.List[string]]::new()
          foreach ($Argument in $Verb.ChildNodes) { if ($Argument.NodeType -eq [Xml.XmlNodeType]::Element -and $Argument.NamespaceURI -ceq $Script:ZeroInstallCapabilityNamespace -and $Argument.LocalName -ceq 'arg') { $Arguments.Add($Argument.InnerText) } }
          $Verbs.Add([pscustomobject][ordered]@{ Name = $VerbName; Command = Get-ZeroInstallXmlAttribute -Node $Verb -Name 'command'; ArgumentsLiteral = Get-ZeroInstallXmlAttribute -Node $Verb -Name 'args'; Arguments = $Arguments.ToArray(); SingleElementOnly = ConvertFrom-ZeroInstallXmlBoolean -Value (Get-ZeroInstallXmlAttribute -Node $Verb -Name 'single-element-only') -Field "$($Capability.LocalName).verb.single-element-only"; Extended = ConvertFrom-ZeroInstallXmlBoolean -Value (Get-ZeroInstallXmlAttribute -Node $Verb -Name 'extended') -Field "$($Capability.LocalName).verb.extended" })
        }
        $Capabilities.Add([pscustomobject][ordered]@{
            Kind              = $Capability.LocalName
            Id                = $Id
            OperatingSystem   = $CapabilityOs
            WindowsCompatible = $WindowsCompatible
            ExplicitOnly      = $ExplicitOnly
            Attributes        = [pscustomobject]$Attributes
            Descriptions      = @(Get-ZeroInstallLocalizableText -Node $Capability -LocalName 'description' -NamespaceUri $Script:ZeroInstallCapabilityNamespace)
            Extensions        = $Extensions.ToArray()
            KnownPrefixes     = $KnownPrefixes.ToArray()
            Verbs             = $Verbs.ToArray()
          })
      }
    }

    $EntryPoints = [Collections.Generic.List[object]]::new()
    foreach ($EntryPoint in $Root.SelectNodes('./zi:entry-point', $NamespaceManager)) {
      $EntryPoints.Add([pscustomobject][ordered]@{
          Command              = Get-ZeroInstallXmlAttribute -Node $EntryPoint -Name 'command'
          IfZeroInstallVersion = Get-ZeroInstallXmlAttribute -Node $EntryPoint -Name 'if-0install-version'
          AppliesToRuntime     = Get-ZeroInstallRuntimeApplicability -Node $EntryPoint -RuntimeVersion $RuntimeVersion
          BinaryName           = Get-ZeroInstallXmlAttribute -Node $EntryPoint -Name 'binary-name'
          AppId                = Get-ZeroInstallXmlAttribute -Node $EntryPoint -Name 'app-id'
          NeedsTerminal        = ConvertFrom-ZeroInstallXmlBoolean -Value (Get-ZeroInstallXmlDirectChildText -Node $EntryPoint -LocalName 'needs-terminal' -NamespaceUri $Script:ZeroInstallFeedNamespace) -Field 'entry-point.needs-terminal'
          SuggestAutoStart     = ConvertFrom-ZeroInstallXmlBoolean -Value (Get-ZeroInstallXmlDirectChildText -Node $EntryPoint -LocalName 'suggest-auto-start' -NamespaceUri $Script:ZeroInstallFeedNamespace) -Field 'entry-point.suggest-auto-start'
          SuggestSendTo        = ConvertFrom-ZeroInstallXmlBoolean -Value (Get-ZeroInstallXmlDirectChildText -Node $EntryPoint -LocalName 'suggest-send-to' -NamespaceUri $Script:ZeroInstallFeedNamespace) -Field 'entry-point.suggest-send-to'
          Names                = @(Get-ZeroInstallLocalizableText -Node $EntryPoint -LocalName 'name' -NamespaceUri $Script:ZeroInstallFeedNamespace)
          Summaries            = @(Get-ZeroInstallLocalizableText -Node $EntryPoint -LocalName 'summary' -NamespaceUri $Script:ZeroInstallFeedNamespace)
          Descriptions         = @(Get-ZeroInstallLocalizableText -Node $EntryPoint -LocalName 'description' -NamespaceUri $Script:ZeroInstallFeedNamespace)
        })
    }

    $FeedReferences = @($Root.SelectNodes('./zi:feed', $NamespaceManager) | ForEach-Object {
        $Source = Get-ZeroInstallXmlAttribute -Node $_ -Name 'src'
        if ([string]::IsNullOrWhiteSpace($Source)) { throw 'A Zero Install <feed> reference is missing its required src attribute.' }
        [pscustomobject][ordered]@{ Source = $Source; ResolvedSource = Resolve-ZeroInstallXmlReference -Node $_ -Value $Source -BaseUri $BaseUri; Architecture = Get-ZeroInstallXmlAttribute -Node $_ -Name 'arch'; Languages = Get-ZeroInstallXmlAttribute -Node $_ -Name 'langs'; IfZeroInstallVersion = Get-ZeroInstallXmlAttribute -Node $_ -Name 'if-0install-version'; AppliesToRuntime = Get-ZeroInstallRuntimeApplicability -Node $_ -RuntimeVersion $RuntimeVersion }
      })
    $FeedForReferences = @($Root.SelectNodes('./zi:feed-for', $NamespaceManager) | ForEach-Object {
        $Interface = Get-ZeroInstallXmlAttribute -Node $_ -Name 'interface'
        if ($Interface) { [pscustomobject][ordered]@{ Interface = $Interface; IfZeroInstallVersion = Get-ZeroInstallXmlAttribute -Node $_ -Name 'if-0install-version'; AppliesToRuntime = Get-ZeroInstallRuntimeApplicability -Node $_ -RuntimeVersion $RuntimeVersion } }
      })
    $FeedFor = @($FeedForReferences.Interface)
    $ReplacedByNode = $Root.SelectSingleNode('./zi:replaced-by', $NamespaceManager)
    $ReplacedBy = $ReplacedByNode ? (Get-ZeroInstallXmlAttribute -Node $ReplacedByNode -Name 'interface') : $null

    [pscustomobject]@{
      InterfaceUri                    = Get-ZeroInstallXmlAttribute -Node $Root -Name 'uri'
      MinimumInjectorVersion          = Get-ZeroInstallXmlAttribute -Node $Root -Name 'min-injector-version'
      Name                            = $FeedName
      Names                           = @(Get-ZeroInstallLocalizableText -Node $Root -LocalName 'name' -NamespaceUri $Script:ZeroInstallFeedNamespace)
      Publisher                       = Get-ZeroInstallXmlDirectChildText -Node $Root -LocalName 'publisher' -NamespaceUri $Script:ZeroInstallFeedNamespace
      Homepage                        = Get-ZeroInstallXmlDirectChildText -Node $Root -LocalName 'homepage' -NamespaceUri $Script:ZeroInstallFeedNamespace
      Summary                         = Get-ZeroInstallXmlDirectChildText -Node $Root -LocalName 'summary' -NamespaceUri $Script:ZeroInstallFeedNamespace
      Summaries                       = @(Get-ZeroInstallLocalizableText -Node $Root -LocalName 'summary' -NamespaceUri $Script:ZeroInstallFeedNamespace)
      Descriptions                    = @(Get-ZeroInstallLocalizableText -Node $Root -LocalName 'description' -NamespaceUri $Script:ZeroInstallFeedNamespace)
      RuntimeVersion                  = $RuntimeVersion
      EntryPoints                     = $EntryPoints.ToArray()
      ApplicableEntryPoints           = @($EntryPoints | Where-Object AppliesToRuntime -NE $false)
      Implementations                 = $Implementations.ToArray()
      ApplicableImplementations       = @($Implementations | Where-Object AppliesToRuntime -NE $false)
      StableImplementations           = @($Implementations | Where-Object Stability -EQ 'stable')
      ApplicableStableImplementations = @($Implementations | Where-Object { $_.AppliesToRuntime -ne $false -and $_.Stability -ceq 'stable' })
      Architectures                   = @($ArchitectureSet | Sort-Object)
      ApplicableArchitectures         = @($Implementations | Where-Object AppliesToRuntime -NE $false | ForEach-Object Architecture | Where-Object { $_ } | Sort-Object -Unique)
      Protocols                       = @($ProtocolSet | Sort-Object)
      FileExtensions                  = @($ExtensionSet | Sort-Object)
      DefaultProtocols                = @($DefaultProtocolSet | Sort-Object)
      DefaultFileExtensions           = @($DefaultExtensionSet | Sort-Object)
      Capabilities                    = $Capabilities.ToArray()
      Requirements                    = $AllRequirements.ToArray()
      ApplicableRequirements          = @($AllRequirements | Where-Object AppliesToRuntime -NE $false)
      Restrictions                    = $AllRestrictions.ToArray()
      ApplicableRestrictions          = @($AllRestrictions | Where-Object AppliesToRuntime -NE $false)
      FeedReferences                  = $FeedReferences
      ApplicableFeedReferences        = @($FeedReferences | Where-Object AppliesToRuntime -NE $false)
      FeedFor                         = $FeedFor
      FeedForReferences               = $FeedForReferences
      ApplicableFeedFor               = @($FeedForReferences | Where-Object AppliesToRuntime -NE $false | ForEach-Object Interface)
      ReplacedBy                      = $ReplacedBy
      Diagnostics                     = $Diagnostics.ToArray()
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
    'ZeroInstall.EmbeddedConfig.txt' { 'EmbeddedConfig.txt' }
    'ZeroInstall.config.ini' { 'config.ini' }
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

function Get-ZeroInstallContentEntry {
  <#
  .SYNOPSIS
    Classify one embedded or explicitly supplied Zero Install content file.
  .PARAMETER Name
    Runtime-visible content filename after the ZeroInstall.content. prefix.
  .PARAMETER Source
    EmbeddedResource or ContentDirectory.
  .PARAMETER Resource
    Optional managed-resource range for embedded content.
  .PARAMETER Path
    Optional resolved filesystem path for content-directory input.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][ValidateSet('EmbeddedResource', 'ContentDirectory')][string]$Source,
    [AllowNull()][psobject]$Resource,
    [AllowNull()][string]$Path
  )

  $Kind = 'Ignored'
  $ImportAction = $null
  $ManifestDigest = $null
  $StubDirectory = $null
  $StubFileName = $null
  if ($Name.EndsWith('.xml', [StringComparison]::OrdinalIgnoreCase)) {
    $Kind = 'Feed'
    $ImportAction = 'ImportFeed'
  } elseif ($Name.EndsWith('.png', [StringComparison]::OrdinalIgnoreCase) -or $Name.EndsWith('.ico', [StringComparison]::OrdinalIgnoreCase)) {
    $Kind = 'Icon'
    $ImportAction = 'ImportIcon'
  } elseif ($Name.EndsWith('.exe', [StringComparison]::OrdinalIgnoreCase) -and $Name.IndexOf('_', [StringComparison]::Ordinal) -gt 0) {
    $Separator = $Name.IndexOf('_', [StringComparison]::Ordinal)
    $Kind = 'StubExecutable'
    $ImportAction = 'ImportStubExe'
    $StubDirectory = $Name.Substring(0, $Separator)
    $StubFileName = $Name.Substring($Separator + 1)
  } else {
    $BaseName = [IO.Path]::GetFileNameWithoutExtension($Name)
    if ($BaseName -match '^(?:sha1=|sha1new=|sha256=|sha256new_).+') {
      $Kind = 'ImplementationArchive'
      $ImportAction = 'ImportImplementation'
      $ManifestDigest = $BaseName
    } elseif ($Name.EndsWith('.gpg', [StringComparison]::OrdinalIgnoreCase)) {
      $Kind = 'OpenPgpKey'
      $ImportAction = 'FeedSignatureKey'
    }
  }

  $ContentSize = if ($Resource) { [long]$Resource.Size } elseif (-not [string]::IsNullOrWhiteSpace($Path) -and (Test-Path -LiteralPath $Path -PathType Leaf)) { [long](Get-Item -LiteralPath $Path -Force).Length } else { $null }
  [pscustomobject][ordered]@{
    Name           = $Name
    RelativePath   = 'content/' + $Name
    Source         = $Source
    Kind           = $Kind
    ImportAction   = $ImportAction
    ManifestDigest = $ManifestDigest
    StubDirectory  = $StubDirectory
    StubFileName   = $StubFileName
    RuntimeTarget  = if ($Kind -ceq 'StubExecutable') { "desktop-integration/stubs/$StubDirectory/$StubFileName" } elseif ($Kind -ceq 'ImplementationArchive') { "implementation-store/$ManifestDigest" } else { $null }
    Offset         = $Resource ? [long]$Resource.Offset : $null
    Size           = $ContentSize
    ResourceName   = $Resource ? [string]$Resource.Name : $null
    Path           = $Path
  }
}

function Get-ZeroInstallContentCatalog {
  <#
  .SYNOPSIS
    Build the source-ordered embedded and explicit content-directory catalog.
  .PARAMETER Resource
    Selected managed PE resources.
  .PARAMETER ContentDirectoryPath
    Optional directory explicitly passed by the caller as bootstrap content.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Resource, [AllowNull()][string]$ContentDirectoryPath)

  $Entries = [Collections.Generic.List[object]]::new()
  foreach ($Item in $Resource) {
    if (-not $Item.Name.StartsWith('ZeroInstall.content.', [StringComparison]::Ordinal)) { continue }
    $Name = $Item.Name.Substring('ZeroInstall.content.'.Length)
    if ([string]::IsNullOrWhiteSpace($Name)) { continue }
    $Entries.Add((Get-ZeroInstallContentEntry -Name $Name -Source EmbeddedResource -Resource $Item))
  }
  if (-not [string]::IsNullOrWhiteSpace($ContentDirectoryPath)) {
    $ResolvedContentDirectory = Resolve-InstallerFileSystemPath -Path $ContentDirectoryPath -PathType Container
    $Files = @(Get-ChildItem -LiteralPath $ResolvedContentDirectory -File | Sort-Object Name)
    if ($Files.Count -gt $Script:ZeroInstallMaximumResources) { throw "The Zero Install content directory exceeds the $Script:ZeroInstallMaximumResources-file limit." }
    foreach ($File in $Files) { $Entries.Add((Get-ZeroInstallContentEntry -Name $File.Name -Source ContentDirectory -Path $File.FullName)) }
  }
  return $Entries.ToArray()
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
  .PARAMETER ContentDirectoryPath
    Optional exact directory supplied to the bootstrapper as content. The
    parser does not guess the runtime InstallBase content directory.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$FeedContent,
    [string]$ContentDirectoryPath
  )
  process {
    $File = Get-Item -LiteralPath $Path -Force
    $VersionInfo = [Diagnostics.FileVersionInfo]::GetVersionInfo($File.FullName)
    $RuntimeVersion = ConvertTo-ZeroInstallRuntimeVersion -Value $VersionInfo.FileVersion
    $RequestedResourceNames = [string[]]@($Script:ZeroInstallConfigurationResourceNames) + @('ZeroInstall.SplashScreen.png', 'ZeroInstall.content.*')
    $Stream = [IO.File]::Open($File.FullName, 'Open', 'Read', 'ReadWrite')
    try {
      $Layout = Get-PELayout -Stream $Stream
      if (-not $Layout) { throw 'The file is not a PE image.' }
      $ManagedIdentity = Get-ZeroInstallManagedIdentity -Stream $Stream
      if (-not $RuntimeVersion -and $ManagedIdentity.AssemblyVersion) { $RuntimeVersion = [version]$ManagedIdentity.AssemblyVersion }
      if (-not $ManagedIdentity.IsBootstrapper) { throw 'The managed PE does not contain a source-backed Zero Install bootstrapper type identity.' }
      $Resources = @(Get-PEManagedResourceInfo -Stream $Stream -Layout $Layout -Name $RequestedResourceNames -MaximumResources $Script:ZeroInstallMaximumResources -MaximumResourceBytes $File.Length)
      $ConfigResources = @($Resources | Where-Object Name -In $Script:ZeroInstallConfigurationResourceNames)
      if ($ConfigResources.Count -gt 1) { throw "The managed PE contains more than one supported Zero Install configuration resource; found $($ConfigResources.Count)." }
      if ($ConfigResources.Count -eq 1) {
        $ConfigResource = $ConfigResources[0]
        $ConfigBytes = Read-PEResourceData -Resource $ConfigResource -MaximumBytes $Script:ZeroInstallMaximumConfigBytes
        try { $ConfigText = [Text.UTF8Encoding]::new($false, $true).GetString($ConfigBytes).TrimStart([char]0xFEFF) }
        catch { throw 'The embedded Zero Install bootstrap configuration is not valid UTF-8.' }
        $ConfigurationProfile = Get-ZeroInstallConfigurationProfile -ResourceName $ConfigResource.Name -Content $ConfigText -RuntimeVersion $RuntimeVersion
        $EmbeddedConfig = if ($ConfigurationProfile.Encoding -ceq 'Ini') {
          $ParsedIni = ConvertFrom-ZeroInstallIni -Content $ConfigText
          if (-not $ParsedIni.Sections.PSObject.Properties['bootstrap']) { throw "The Zero Install '$($ConfigResource.Name)' resource has no [bootstrap] section." }
          $ParsedIni
        } else {
          ConvertFrom-ZeroInstallFixedConfiguration -Content $ConfigText -FormatProfile $ConfigurationProfile
        }
      } else {
        # Releases 2.11.0 through 2.11.5 predate customizable embedded
        # configuration. Recognize their exact CLR type identity as a generic
        # Zero Install bootstrapper rather than weakening detection to strings.
        $ConfigurationProfile = $ManagedIdentity.Profile
        if (-not $ConfigurationProfile) { throw 'The managed PE contains no supported Zero Install configuration resource or legacy bootstrapper type identity.' }
        $ConfigResource = $null
        $EmbeddedConfig = [pscustomobject]@{ Sections = [pscustomobject][ordered]@{ global = [pscustomobject][ordered]@{}; bootstrap = [pscustomobject][ordered]@{} }; RawContent = '' }
      }
    } finally { $Stream.Dispose() }

    # INI generations replace the embedded configuration with a same-basename
    # sidecar. Older generations instead overlay non-empty appSettings from the
    # adjacent executable .config file.
    $Config = $EmbeddedConfig
    $ConfigurationSource = $ConfigResource ? 'Embedded CLR ManifestResource' : 'CLR type identity; no customizable configuration'
    $ExternalConfigPath = if ($ConfigurationProfile.Encoding -ceq 'Ini') { [IO.Path]::ChangeExtension($File.FullName, '.ini') } else { "$($File.FullName).config" }
    $AppSettingsSupported = Get-ZeroInstallFeatureState -Name AppSettingsOverrides -RuntimeVersion $RuntimeVersion -FormatProfile $ConfigurationProfile
    if ($ConfigurationProfile.Encoding -ceq 'Ini' -and (Test-Path -LiteralPath $ExternalConfigPath -PathType Leaf)) {
      $ExternalConfigFile = Get-Item -LiteralPath $ExternalConfigPath -Force
      $ExternalText = Read-BoundedTextFile -Path $ExternalConfigFile.FullName -MaximumBytes $Script:ZeroInstallMaximumConfigBytes -FallbackEncoding utf-8
      $Config = ConvertFrom-ZeroInstallIni -Content $ExternalText
      if (-not $Config.Sections.PSObject.Properties['bootstrap']) { throw "The adjacent Zero Install INI '$($ExternalConfigFile.Name)' has no [bootstrap] section." }
      $ConfigurationSource = "Adjacent INI: $($ExternalConfigFile.Name)"
    } elseif ($ConfigurationProfile.Encoding -ceq 'FixedLines' -and $AppSettingsSupported -eq $true -and (Test-Path -LiteralPath $ExternalConfigPath -PathType Leaf)) {
      $ExternalConfigFile = Get-Item -LiteralPath $ExternalConfigPath -Force
      $ApplicationSettings = Read-ZeroInstallApplicationSetting -Path $ExternalConfigFile.FullName
      $Config = Merge-ZeroInstallApplicationSetting -Configuration $EmbeddedConfig -Settings $ApplicationSettings -FormatProfile $ConfigurationProfile
      $ConfigurationSource = "Embedded CLR ManifestResource + adjacent application configuration: $($ExternalConfigFile.Name)"
    }

    $AppUriText = Get-ZeroInstallIniOption -Ini $Config -Section 'bootstrap' -Name 'app_uri'
    $AppUri = $null
    if ($AppUriText) {
      if (-not [uri]::TryCreate($AppUriText, [UriKind]::Absolute, [ref]$AppUri)) { throw "The Zero Install app_uri is not an absolute URI: $AppUriText" }
    }
    $AppName = Get-ZeroInstallIniOption -Ini $Config -Section 'bootstrap' -Name 'app_name'
    $AppMode = Get-ZeroInstallIniOption -Ini $Config -Section 'bootstrap' -Name 'app_mode'
    $AppArgs = Get-ZeroInstallIniOption -Ini $Config -Section 'bootstrap' -Name 'app_args'
    $ConfiguredIntegrateArgs = Get-ZeroInstallIniOption -Ini $Config -Section 'bootstrap' -Name 'integrate_args'
    $IntegrationConfigured = $AppMode -ceq 'integrate' -or -not [string]::IsNullOrEmpty($ConfiguredIntegrateArgs)
    $IntegrateArgs = $AppMode -ceq 'integrate' ? $AppArgs : $ConfiguredIntegrateArgs
    $IntegrateArgumentList = @(Split-ZeroInstallCommandLine -CommandLine $IntegrateArgs)
    $IntegrationSelection = Resolve-ZeroInstallIntegrationSelection -ArgumentList $IntegrateArgumentList
    $CustomizableStorePath = (Get-ZeroInstallIniOption -Ini $Config -Section 'bootstrap' -Name 'customizable_store_path') -ieq 'true'
    $EstimatedSpaceText = Get-ZeroInstallIniOption -Ini $Config -Section 'bootstrap' -Name 'estimated_required_space'
    $EstimatedSpace = 0L
    if ($EstimatedSpaceText -and -not [long]::TryParse($EstimatedSpaceText, [ref]$EstimatedSpace)) {
      throw "The Zero Install estimated_required_space value is invalid: $EstimatedSpaceText"
    }

    $FeedInfo = if ($PSBoundParameters.ContainsKey('FeedContent') -and -not [string]::IsNullOrWhiteSpace($FeedContent)) { ConvertFrom-ZeroInstallFeed -Content $FeedContent -BaseUri $AppUri -RuntimeVersion $RuntimeVersion } else { $null }
    $Warnings = [Collections.Generic.List[object]]::new()
    if ($ConfigurationProfile.Id -ceq 'LegacyGenericBootstrapper') {
      $Warnings.Add((New-InstallerDiagnostic -Id 'ZeroInstall.Configuration.LegacyGenericBootstrapper' -Source 'ZeroInstall' -Message 'This runtime predates customizable embedded bootstrap configuration and therefore provides only generic Zero Install launcher evidence.' -Kind Information -Areas Detection, Metadata -Evidence ([ordered]@{ RuntimeVersion = $RuntimeVersion; ObservedReleases = $ConfigurationProfile.ObservedReleases })))
    }
    if ($RuntimeVersion -and -not (Test-ZeroInstallVersionInProfile -Version $RuntimeVersion -FormatProfile $ConfigurationProfile)) {
      $Warnings.Add((New-InstallerDiagnostic -Id 'ZeroInstall.Configuration.ProfileVersionMismatch' -Source 'ZeroInstall' -Message "The '$($ConfigurationProfile.Id)' resource layout is not expected for runtime version '$RuntimeVersion'; structural parsing was retained but version-dependent behavior requires review." -Kind Mismatch -Areas Detection, Metadata, Installability -Evidence ([ordered]@{ RuntimeVersion = $RuntimeVersion.ToString(); ConfigurationProfile = $ConfigurationProfile.Id; ObservedReleases = $ConfigurationProfile.ObservedReleases })))
    }
    if ($ConfigurationSource.StartsWith('Adjacent INI:', [StringComparison]::Ordinal)) {
      $Warnings.Add((New-InstallerDiagnostic -Id 'ZeroInstall.Configuration.AdjacentIniOverridesEmbedded' -Source 'ZeroInstall' -Message 'The adjacent INI overrides the embedded bootstrap configuration at runtime; ensure the package delivers both files together.' -Kind Information -Areas Metadata -Evidence $ExternalConfigPath))
    } elseif ($ConfigurationSource.Contains('adjacent application configuration', [StringComparison]::Ordinal)) {
      $Warnings.Add((New-InstallerDiagnostic -Id 'ZeroInstall.Configuration.AppSettingsOverrideEmbedded' -Source 'ZeroInstall' -Message 'The adjacent executable configuration contributes historical appSettings overrides; analyze and distribute it with the bootstrapper.' -Kind Information -Areas Metadata -Evidence $ExternalConfigPath))
    }
    if ($FeedInfo) {
      foreach ($Warning in $FeedInfo.Diagnostics) { $Warnings.Add($Warning) }
      if ($FeedInfo.InterfaceUri -and $AppUri -and $FeedInfo.InterfaceUri -ne $AppUri.AbsoluteUri) {
        $Warnings.Add((New-InstallerDiagnostic -Id 'ZeroInstall.Feed.UriMismatch' -Source 'ZeroInstall' -Message "The supplied feed URI '$($FeedInfo.InterfaceUri)' does not match embedded app_uri '$($AppUri.AbsoluteUri)'." -Kind Mismatch -Areas Metadata, Security -AffectedFields DisplayName, Publisher, Architecture, Protocols, FileExtensions -Evidence ([ordered]@{ Expected = $AppUri.AbsoluteUri; Actual = $FeedInfo.InterfaceUri })))
      }
    } elseif ($AppUri) {
      $Warnings.Add((New-InstallerDiagnostic -Id 'ZeroInstall.Feed.RequiredForTargetMetadata' -Source 'ZeroInstall' -Message 'Package version, publisher, architecture, and capability evidence is feed-driven; retrieve AppUri in the task and pass its raw XML as FeedContent.' -Kind Incomplete -Areas Metadata -AffectedFields DisplayName, DisplayVersion, Publisher, Architecture, Protocols, FileExtensions -Evidence $AppUri.AbsoluteUri))
    }

    # A feed describes all integrations an application can expose. The runtime
    # writes only the categories selected by IntegrateArgs; an empty selection
    # opens the integration UI and is therefore not deterministic static proof.
    $Protocols = @()
    $FileExtensions = @()
    if ($FeedInfo -and $IntegrationConfigured) {
      if ($IntegrationSelection.IsDeterministic -and $IntegrationSelection.RegistersAllCapabilities) {
        $Protocols = @($FeedInfo.Protocols)
        $FileExtensions = @($FeedInfo.FileExtensions)
      } elseif ($IntegrationSelection.IsDeterministic -and $IntegrationSelection.RegistersDefaultCapabilities) {
        $Protocols = @($FeedInfo.DefaultProtocols)
        $FileExtensions = @($FeedInfo.DefaultFileExtensions)
      }
      if (-not $IntegrationSelection.IsDeterministic) {
        $Warnings.Add((New-InstallerDiagnostic -Id 'ZeroInstall.Associations.IntegrationSelectionUnresolved' -Source 'ZeroInstall' -Message 'The bootstrapper invokes desktop integration without a fully deterministic capability-category selection; available feed associations require interactive or VM evidence.' -Kind ManualValidation -Areas Metadata -AffectedFields Protocols, FileExtensions -Evidence ([ordered]@{ IntegrateArgs = $IntegrateArgs; UnknownArguments = $IntegrationSelection.UnknownArguments })))
      }
    }

    $ArpSupported = Get-ZeroInstallFeatureState -Name AppsAndFeaturesRegistration -RuntimeVersion $RuntimeVersion -FormatProfile $ConfigurationProfile
    $SilentSupported = Get-ZeroInstallFeatureState -Name SilentSwitch -RuntimeVersion $RuntimeVersion -FormatProfile $ConfigurationProfile
    $MachineSwitchSupported = Get-ZeroInstallFeatureState -Name MachineScopeSwitch -RuntimeVersion $RuntimeVersion -FormatProfile $ConfigurationProfile
    $VerySilentSupported = Get-ZeroInstallFeatureState -Name VerySilentSwitch -RuntimeVersion $RuntimeVersion -FormatProfile $ConfigurationProfile
    $StorePathSupported = Get-ZeroInstallFeatureState -Name StorePathSwitch -RuntimeVersion $RuntimeVersion -FormatProfile $ConfigurationProfile
    $ModifyCommandSupported = Get-ZeroInstallFeatureState -Name ModifyArpCommand -RuntimeVersion $RuntimeVersion -FormatProfile $ConfigurationProfile

    $WritesAppsAndFeaturesEntry = [bool]($AppUri -and $IntegrationConfigured -and $ArpSupported -eq $true)
    if ($AppUri -and -not $IntegrationConfigured) {
      $Warnings.Add((New-InstallerDiagnostic -Id 'ZeroInstall.Arp.IntegrationNotConfigured' -Source 'ZeroInstall' -Message 'The bootstrapper downloads or runs the target feed but does not invoke desktop integration, so it does not write a target Apps & Features entry.' -Kind Information -Areas Metadata -AffectedFields ProductCode, AppsAndFeaturesEntries))
    } elseif ($AppUri -and $IntegrationConfigured -and $ArpSupported -eq $false) {
      $Warnings.Add((New-InstallerDiagnostic -Id 'ZeroInstall.Arp.UnsupportedByHistoricalRuntime' -Source 'ZeroInstall' -Message "Zero Install runtime '$RuntimeVersion' predates the 2.21 desktop-integration uninstall entry; the integration creates desktop artifacts but no Apps & Features ProductCode." -Kind Information -Areas Metadata -AffectedFields ProductCode, AppsAndFeaturesEntries -Evidence $RuntimeVersion))
    } elseif ($AppUri -and $IntegrationConfigured -and $null -eq $ArpSupported) {
      $Warnings.Add((New-InstallerDiagnostic -Id 'ZeroInstall.Arp.RuntimeVersionUnresolved' -Source 'ZeroInstall' -Message 'The configuration requests desktop integration, but the runtime version is insufficient to determine whether this generation writes an Apps & Features entry.' -Kind Incomplete -Areas Metadata -AffectedFields ProductCode, AppsAndFeaturesEntries -Evidence $ConfigurationProfile.Id))
    }
    if (-not $AppUri) {
      $Warnings.Add((New-InstallerDiagnostic -Id 'ZeroInstall.Configuration.GenericBootstrapper' -Source 'ZeroInstall' -Message 'This is a generic Zero Install bootstrapper, not a bootstrapper bound to one application feed.' -Kind Information -Areas Metadata))
    }
    if ($WritesAppsAndFeaturesEntry) {
      $Warnings.Add((New-InstallerDiagnostic -Id 'ZeroInstall.Arp.DisplayVersionNotWritten' -Source 'ZeroInstall' -Message 'Zero Install desktop integration does not write DisplayVersion; validate whether the target application adds or updates that value after installation or first run.' -Kind ManualValidation -Areas Metadata -AffectedFields DisplayVersion))
    }

    $IsGui = $Layout.Subsystem -eq 2
    $IsAppBootstrapper = [bool]($AppUri -and $AppName)
    $IsLegacyDeploymentBootstrapper = -not $AppUri -and (
      ($RuntimeVersion -and $RuntimeVersion -lt [version]'2.14.5') -or
      (-not $RuntimeVersion -and $ConfigurationProfile.MaximumRuntimeExclusive -and [version]$ConfigurationProfile.MaximumRuntimeExclusive -le [version]'2.14.5')
    )
    $EmbeddedMachineScope = [bool]($IntegrationConfigured -and $IntegrateArgumentList -ccontains '--machine')
    $SupportedScopes = if (-not $WritesAppsAndFeaturesEntry) { @() } elseif ($EmbeddedMachineScope) { @('machine') } elseif ($MachineSwitchSupported -eq $true) { @('user', 'machine') } else { @('user') }
    $Scope = $WritesAppsAndFeaturesEntry ? ($EmbeddedMachineScope ? 'machine' : 'user') : $null
    $SupportsDualScope = $SupportedScopes.Count -eq 2

    $InstallerSwitches = [ordered]@{}
    $InstallModes = [Collections.Generic.List[string]]::new()
    $InstallModes.Add('interactive')
    if ($IsLegacyDeploymentBootstrapper) {
      $InstallModes.Add('silent')
      $InstallerSwitches['Silent'] = $IsGui ? '--verysilent' : '--silent'
      if ($IsGui) {
        $InstallModes.Add('silentWithProgress')
        $InstallerSwitches['SilentWithProgress'] = '--silent'
      }
    } elseif ($IsAppBootstrapper -and $SilentSupported -eq $true) {
      if ($IsGui -and $VerySilentSupported -eq $true) {
        $InstallModes.Add('silent')
        $InstallModes.Add('silentWithProgress')
        $InstallerSwitches['Silent'] = '--verysilent'
        $InstallerSwitches['SilentWithProgress'] = '--silent'
      } elseif ($IsGui) {
        # Before 2.24.0 --silent suppresses questions and target launch but the
        # WinForms progress surface remains visible.
        $InstallModes.Add('silentWithProgress')
        $InstallerSwitches['SilentWithProgress'] = '--silent'
      } else {
        $InstallModes.Add('silent')
        $InstallerSwitches['Silent'] = '--silent'
      }
    }
    if ($InstallerSwitches.Contains('Silent') -and -not $InstallerSwitches.Contains('SilentWithProgress')) {
      # CLI-only and legacy routes have no progress UI. Populate WinGet's default
      # switch slot with the same quiet command while retaining the exact mode list.
      $InstallerSwitches['SilentWithProgress'] = $InstallerSwitches['Silent']
    }
    if ($CustomizableStorePath -and $StorePathSupported -eq $true) { $InstallerSwitches['InstallLocation'] = '--store-path="<INSTALLPATH>"' }

    $UninstallKeyNameCandidate = $AppUri ? (ConvertTo-ZeroInstallPrettyEscape -Value $AppUri.AbsoluteUri) : $null
    $ProductCode = $WritesAppsAndFeaturesEntry ? $UninstallKeyNameCandidate : $null
    $DisplayName = if ($FeedInfo -and $FeedInfo.Name) { $FeedInfo.Name } else { $AppName }
    $ExtractableResources = @($Resources | ForEach-Object {
        $RelativePath = Get-ZeroInstallExtractableResourceName -ResourceName $_.Name
        if ($RelativePath) { [pscustomobject]@{ ResourceName = $_.Name; RelativePath = $RelativePath; Offset = $_.Offset; Size = $_.Size } }
      })
    $ContentEntries = @(Get-ZeroInstallContentCatalog -Resource $Resources -ContentDirectoryPath $ContentDirectoryPath)
    $ImplementationArchives = @($ContentEntries | Where-Object Kind -EQ 'ImplementationArchive')
    if ($ImplementationArchives.Count -gt 0) {
      $Warnings.Add((New-InstallerDiagnostic -Id 'ZeroInstall.Content.ManifestDigestNotVerified' -Source 'ZeroInstall' -Message 'Raw bootstrap-content extraction does not reconstruct the complete Zero Install file manifest and is not integrity verification. Use Expand-ZeroInstallImplementation with a parsed feed and caller-supplied retrieval artifacts for verified materialization.' -Kind ManualValidation -Areas Extraction, Security -Evidence ([ordered]@{ ManifestDigests = @($ImplementationArchives.ManifestDigest | Sort-Object -Unique) })))
    }

    $PlainArpDisplayName = Get-ZeroInstallFeatureState -Name PlainArpDisplayName -RuntimeVersion $RuntimeVersion -FormatProfile $ConfigurationProfile
    $PublisherArpValue = Get-ZeroInstallFeatureState -Name PublisherArpValue -RuntimeVersion $RuntimeVersion -FormatProfile $ConfigurationProfile
    $ArpDisplayName = if ($WritesAppsAndFeaturesEntry -and $FeedInfo -and $FeedInfo.Name) { $PlainArpDisplayName -eq $false ? "$($FeedInfo.Name) (Zero Install)" : $FeedInfo.Name } else { $null }
    $ArpPublisher = if ($WritesAppsAndFeaturesEntry -and $PublisherArpValue -eq $true -and $FeedInfo) { $FeedInfo.Publisher } else { $null }
    $ArpHomepage = if ($WritesAppsAndFeaturesEntry -and $FeedInfo) { $FeedInfo.Homepage } else { $null }
    $ArpHive = $Scope -ceq 'machine' ? 'HKEY_LOCAL_MACHINE' : 'HKEY_CURRENT_USER'
    $ArpKey = $WritesAppsAndFeaturesEntry ? "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$ProductCode" : $null
    $UninstallArguments = [Collections.Generic.List[string]]::new()
    if ($WritesAppsAndFeaturesEntry) {
      $UninstallArguments.Add('remove')
      $UninstallArguments.Add($AppUri.AbsoluteUri)
      if ($Scope -ceq 'machine') { $UninstallArguments.Add('--machine') }
    }
    $ArpValues = [ordered]@{}
    if ($WritesAppsAndFeaturesEntry) {
      if ($ArpDisplayName) { $ArpValues['DisplayName'] = $ArpDisplayName }
      if ($ArpPublisher) { $ArpValues['Publisher'] = $ArpPublisher }
      if ($ArpHomepage) { $ArpValues['URLInfoAbout'] = $ArpHomepage }
      $ArpValues['NoModify'] = $ModifyCommandSupported -eq $true ? 0 : 1
      $ArpValues['NoRepair'] = 1
    }
    $ModifyArguments = [Collections.Generic.List[string]]::new()
    if ($ModifyCommandSupported -eq $true) {
      $ModifyArguments.Add('integrate')
      $ModifyArguments.Add($AppUri.AbsoluteUri)
      if ($Scope -ceq 'machine') { $ModifyArguments.Add('--machine') }
    }
    $RegistryWrites = @($ArpValues.GetEnumerator() | ForEach-Object {
        [pscustomobject][ordered]@{ Hive = $ArpHive; View = 'Process'; Key = $ArpKey; Name = $_.Key; Value = $_.Value; Type = $_.Value -is [int] ? 'REG_DWORD' : 'REG_SZ'; Source = 'Zero Install desktop integration' }
      })
    $AppsAndFeaturesEntries = if ($ArpDisplayName -and $ArpDisplayName -cne $DisplayName) { @([ordered]@{ DisplayName = $ArpDisplayName }) } else { @() }

    $SupportedSwitches = [Collections.Generic.List[string]]::new()
    foreach ($CommandLineOption in @('--batch', '--offline', '--no-existing', '--version=<VERSION>', '--feed=<FEED>')) { $SupportedSwitches.Add($CommandLineOption) }
    if ((Get-ZeroInstallFeatureState -Name ContentDirectorySwitch -RuntimeVersion $RuntimeVersion -FormatProfile $ConfigurationProfile) -eq $true) { $SupportedSwitches.Add('--content-dir=<PATH>') }
    if ((Get-ZeroInstallFeatureState -Name RefreshSwitch -RuntimeVersion $RuntimeVersion -FormatProfile $ConfigurationProfile) -eq $true) { $SupportedSwitches.Add('--refresh') }
    if ((Get-ZeroInstallFeatureState -Name PrepareOfflineSwitch -RuntimeVersion $RuntimeVersion -FormatProfile $ConfigurationProfile) -eq $true) { $SupportedSwitches.Add('--prepare-offline') }
    if ($IsLegacyDeploymentBootstrapper) { foreach ($CommandLineOption in @('--silent', '--verysilent', '--mergetasks', '--norestart')) { $SupportedSwitches.Add($CommandLineOption) } }
    if ($IsGui -and (Get-ZeroInstallFeatureState -Name BackgroundSwitch -RuntimeVersion $RuntimeVersion -FormatProfile $ConfigurationProfile) -eq $true) { $SupportedSwitches.Add('--background') }
    if ($IsAppBootstrapper -and $SilentSupported -eq $true) {
      $SupportedSwitches.Add('--no-run')
      $SupportedSwitches.Add('--silent')
    }
    if ($IsAppBootstrapper -and $IsGui -and $VerySilentSupported -eq $true) { $SupportedSwitches.Add('--verysilent') }
    if ($IsAppBootstrapper -and (Get-ZeroInstallFeatureState -Name WaitSwitch -RuntimeVersion $RuntimeVersion -FormatProfile $ConfigurationProfile) -eq $true) { $SupportedSwitches.Add('--wait') }
    if ($IntegrationConfigured -and (Get-ZeroInstallFeatureState -Name NoIntegrateSwitch -RuntimeVersion $RuntimeVersion -FormatProfile $ConfigurationProfile) -eq $true) { $SupportedSwitches.Add('--no-integrate') }
    if ($SupportsDualScope) { $SupportedSwitches.Add('--machine') }
    if ($IntegrationConfigured -and (Get-ZeroInstallFeatureState -Name IntegrateArgsSwitch -RuntimeVersion $RuntimeVersion -FormatProfile $ConfigurationProfile) -eq $true) { $SupportedSwitches.Add('--integrate-args=<ARGS>') }
    if ($CustomizableStorePath -and $StorePathSupported -eq $true) { $SupportedSwitches.Add('--store-path=<PATH>') }
    if ($IsAppBootstrapper -and (Get-ZeroInstallFeatureState -Name SplitVersionSwitches -RuntimeVersion $RuntimeVersion -FormatProfile $ConfigurationProfile) -eq $true) {
      $SupportedSwitches.Add((Get-ZeroInstallFeatureState -Name CurrentVersionSwitchNames -RuntimeVersion $RuntimeVersion -FormatProfile $ConfigurationProfile) -eq $true ? '--0install-version=<VERSION>' : '--zero-install-version=<VERSION>')
    }
    if ($IsAppBootstrapper -and (Get-ZeroInstallFeatureState -Name FeedOverrideSwitches -RuntimeVersion $RuntimeVersion -FormatProfile $ConfigurationProfile) -eq $true) { $SupportedSwitches.Add('--0install-feed=<FEED>') }

    $UnresolvedFields = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    if ($AppUri -and -not $FeedInfo) {
      foreach ($Field in @('DisplayName', 'DisplayVersion', 'Publisher', 'Architectures', 'Protocols', 'FileExtensions')) { $null = $UnresolvedFields.Add($Field) }
    }
    if ($FeedInfo -and $IntegrationConfigured -and -not $IntegrationSelection.IsDeterministic) {
      $null = $UnresolvedFields.Add('Protocols')
      $null = $UnresolvedFields.Add('FileExtensions')
    }
    if ($ImplementationArchives.Count -gt 0) { $null = $UnresolvedFields.Add('PayloadIntegrity') }
    if ($WritesAppsAndFeaturesEntry) { $null = $UnresolvedFields.Add('DisplayVersion') }

    [pscustomobject][ordered]@{
      Path                         = $File.FullName
      InstallerType                = 'exe'
      ProductCode                  = $ProductCode
      UpgradeCode                  = $null
      DisplayName                  = $DisplayName
      DisplayVersion               = $null
      Publisher                    = $FeedInfo ? $FeedInfo.Publisher : $null
      Scope                        = $Scope
      DefaultInstallLocation       = $null
      WritesAppsAndFeaturesEntry   = $WritesAppsAndFeaturesEntry
      AppsAndFeaturesProductCode   = $WritesAppsAndFeaturesEntry ? $ProductCode : $null
      AppsAndFeaturesInstallerType = $WritesAppsAndFeaturesEntry ? 'exe' : $null
      Diagnostics                  = @(Merge-InstallerDiagnostics -Diagnostic $Warnings.ToArray())
      UnresolvedFields             = [string[]]@($UnresolvedFields | Sort-Object)
      Family                       = 'Zero Install'
      BootstrapperVariant          = if ($IsGui) { 'GUI' } else { 'CLI' }
      LegacyDeploymentBootstrapper = $IsLegacyDeploymentBootstrapper
      BootstrapperVersion          = $VersionInfo.FileVersion
      RuntimeVersion               = $RuntimeVersion
      FormatGeneration             = $ConfigurationProfile.Id
      FormatCatalogVersion         = [int]$Script:ZeroInstallFormatCatalog.CatalogVersion
      ConfigurationResourceName    = $ConfigResource ? $ConfigResource.Name : $null
      ConfigurationSource          = $ConfigurationSource
      AppUri                       = if ($AppUri) { $AppUri.AbsoluteUri } else { $null }
      AppName                      = $AppName
      AppMode                      = if ($AppMode) { $AppMode } elseif ($IntegrationConfigured) { 'integrate' } elseif ($AppUri) { 'run' } else { 'none' }
      AppArgs                      = $AppArgs
      IntegrateArgs                = $IntegrateArgs
      IntegrateArgumentList        = $IntegrateArgumentList
      IntegrationSelection         = $IntegrationSelection
      IntegrationConfigured        = $IntegrationConfigured
      CatalogUri                   = Get-ZeroInstallIniOption -Ini $Config -Section 'bootstrap' -Name 'catalog_uri'
      SelfUpdateUri                = Get-ZeroInstallIniOption -Ini $Config -Section 'global' -Name 'self_update_uri'
      KeyFingerprint               = (Get-ZeroInstallIniOption -Ini $Config -Section 'bootstrap' -Name 'key_fingerprint') ?? (Get-ZeroInstallIniOption -Ini $Config -Section 'bootstrap' -Name 'app_fingerprint')
      CustomizableStorePath        = $CustomizableStorePath
      EstimatedRequiredSpace       = if ($EstimatedSpaceText) { $EstimatedSpace } else { $null }
      UninstallKeyName             = $ProductCode
      UninstallKeyNameCandidate    = $UninstallKeyNameCandidate
      SupportedScopes              = $SupportedScopes
      SupportsDualScope            = $SupportsDualScope
      AppsAndFeaturesEntries       = $AppsAndFeaturesEntries
      AppsAndFeaturesEvidence      = if ($WritesAppsAndFeaturesEntry) {
        [pscustomobject][ordered]@{
          Hive                  = $ArpHive
          RegistryView          = 'Process'
          Key                   = $ArpKey
          ProductCode           = $ProductCode
          DisplayName           = $ArpDisplayName
          Publisher             = $ArpPublisher
          Homepage              = $ArpHomepage
          DisplayVersionWritten = $false
          UninstallExecutable   = '0install-win.exe'
          UninstallArguments    = $UninstallArguments.ToArray()
          QuietArguments        = @($UninstallArguments.ToArray()) + @('--batch', '--background')
          ModifyArguments       = $ModifyArguments.ToArray()
          NoModify              = $ArpValues['NoModify']
          NoRepair              = 1
        }
      } else { $null }
      InstallModes                 = $InstallModes.ToArray()
      InstallerSwitches            = [pscustomobject]$InstallerSwitches
      ScopeSwitches                = $SupportsDualScope ? [pscustomobject]@{ User = $null; Machine = '--machine' } : $null
      SupportedCommandLineSwitches = $SupportedSwitches.ToArray()
      FeedInfo                     = $FeedInfo
      Implementations              = if ($FeedInfo) { $FeedInfo.Implementations } else { @() }
      ApplicableImplementations    = if ($FeedInfo) { $FeedInfo.ApplicableImplementations } else { @() }
      Architectures                = if ($FeedInfo) { $FeedInfo.ApplicableArchitectures } else { @() }
      Protocols                    = $Protocols
      FileExtensions               = $FileExtensions
      AvailableProtocols           = if ($FeedInfo) { $FeedInfo.Protocols } else { @() }
      AvailableFileExtensions      = if ($FeedInfo) { $FeedInfo.FileExtensions } else { @() }
      RegistryWrites               = $RegistryWrites
      EmbeddedResources            = $ExtractableResources
      ContentEntries               = $ContentEntries
      ExtractedFiles               = @($ExtractableResources.RelativePath)
      CanExpand                    = $ExtractableResources.Count -gt 0 -or $ContentEntries.Count -gt 0
      ParserVersionInfo            = [pscustomobject]@{
        Parser               = 'Dumplings.PackageModule.ZeroInstall'
        ParserMajor          = 2
        FormatCatalogVersion = [int]$Script:ZeroInstallFormatCatalog.CatalogVersion
        ConfigurationProfile = $ConfigurationProfile.Id
        Sources              = @('CLR metadata type identity', 'CLR ManifestResource table', $(if ($ConfigResource) { $ConfigResource.Name }), '0install-win tagged source behavior boundaries', '0install-dotnet uninstall-entry source', $(if ($FeedInfo) { 'Caller-supplied Zero Install feed XML' })) | Where-Object { $_ }
      }
      BootstrapConfig              = $Config
      EmbeddedBootstrapConfig      = $EmbeddedConfig
    }
  }
}

function Import-ZeroInstallManifestRuntime {
  <#
  .SYNOPSIS
    Load the bounded Zero Install manifest hasher once per process.
  #>
  if (([System.Management.Automation.PSTypeName]'Dumplings.ZeroInstall.ImplementationManifest').Type) { return }
  $SourcePath = Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath '..', 'Assets', 'Source', 'ZeroInstall', 'ZeroInstallManifest.cs'
  $null = Import-InstallerManagedSource -Path $SourcePath -TypeName 'Dumplings.ZeroInstall.ImplementationManifest'
}

function Get-ZeroInstallImplementationManifest {
  <#
  .SYNOPSIS
    Generate the normalized manifest and digest for a materialized Zero Install implementation.
  .DESCRIPTION
    Hashes files through bounded streams, preserves empty directories, applies Zero Install ordering and AppleDouble filtering, and refuses filesystem links. The function performs no network access and does not mutate the implementation directory.
  .PARAMETER Path
    Existing implementation directory to inspect.
  .PARAMETER Algorithm
    Zero Install manifest format. Sha1 is the legacy format with directory timestamps; SHA256New is the current preferred format.
  .PARAMETER ExecutablePath
    Relative paths whose manifest records use X rather than F. Windows cannot preserve Unix executable bits, so callers extracting archives must supply this evidence.
  .PARAMETER MaximumEntries
    Maximum combined number of files and directories traversed.
  .PARAMETER MaximumBytes
    Maximum aggregate file bytes hashed.
  .OUTPUTS
    A result containing Algorithm, Digest, ManifestText, DirectoryCount, FileCount, and TotalBytes.
  #>
  [OutputType([object])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [ValidateSet('Sha1', 'Sha1New', 'Sha256', 'Sha256New')][string]$Algorithm = 'Sha256New',
    [AllowEmptyCollection()][string[]]$ExecutablePath = @(),
    [ValidateRange(1, [int]::MaxValue)][int]$MaximumEntries = 65536,
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumBytes = 2147483648
  )
  process {
    $ResolvedPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Container
    Import-ZeroInstallManifestRuntime
    return [Dumplings.ZeroInstall.ImplementationManifest]::Compute($ResolvedPath, $Algorithm, [string[]]$ExecutablePath, $MaximumEntries, $MaximumBytes)
  }
}

function Test-ZeroInstallImplementationDigest {
  <#
  .SYNOPSIS
    Verify a materialized implementation against a source-backed Zero Install digest.
  .PARAMETER Path
    Existing implementation directory to hash.
  .PARAMETER Digest
    Expected sha1=, sha1new=, sha256=, or sha256new_ digest.
  .PARAMETER ExecutablePath
    Relative paths represented as executable files in the manifest.
  .PARAMETER MaximumEntries
    Maximum combined number of files and directories traversed.
  .PARAMETER MaximumBytes
    Maximum aggregate file bytes hashed.
  .PARAMETER PassThru
    Return the manifest result with ExpectedDigest and IsMatch properties rather than a Boolean.
  #>
  [OutputType([bool], [pscustomobject])]
  param (
    [Parameter(Position = 0, Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Digest,
    [AllowEmptyCollection()][string[]]$ExecutablePath = @(),
    [ValidateRange(1, [int]::MaxValue)][int]$MaximumEntries = 65536,
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumBytes = 2147483648,
    [switch]$PassThru
  )

  $Algorithm = if ($Digest.StartsWith('sha256new_', [StringComparison]::Ordinal)) { 'Sha256New' } elseif ($Digest.StartsWith('sha256=', [StringComparison]::Ordinal)) { 'Sha256' } elseif ($Digest.StartsWith('sha1new=', [StringComparison]::Ordinal)) { 'Sha1New' } elseif ($Digest.StartsWith('sha1=', [StringComparison]::Ordinal)) { 'Sha1' } else { throw "Unsupported Zero Install manifest digest: $Digest" }
  $Result = Get-ZeroInstallImplementationManifest -Path $Path -Algorithm $Algorithm -ExecutablePath $ExecutablePath -MaximumEntries $MaximumEntries -MaximumBytes $MaximumBytes
  $IsMatch = $Result.Digest -ceq $Digest
  if (-not $PassThru) { return $IsMatch }
  return [pscustomobject][ordered]@{
    Algorithm      = $Result.Algorithm
    Digest         = $Result.Digest
    ExpectedDigest = $Digest
    IsMatch        = $IsMatch
    ManifestText   = $Result.ManifestText
    DirectoryCount = $Result.DirectoryCount
    FileCount      = $Result.FileCount
    TotalBytes     = $Result.TotalBytes
  }
}

function Resolve-ZeroInstallSuppliedPath {
  <#
  .SYNOPSIS
    Resolve a retrieval URI or implementation ID through caller-supplied offline mappings.
  .PARAMETER Mapping
    Dictionary whose values are local filesystem paths.
  .PARAMETER Key
    Ordered identifiers checked without issuing network requests.
  .PARAMETER PathType
    Required filesystem item type.
  .PARAMETER Description
    Human-readable record name used in errors.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][Collections.IDictionary]$Mapping,
    [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Key,
    [Parameter(Mandatory)][ValidateSet('Leaf', 'Container')][string]$PathType,
    [Parameter(Mandatory)][string]$Description
  )

  foreach ($Candidate in $Key) {
    if ([string]::IsNullOrWhiteSpace($Candidate)) { continue }
    foreach ($MappingKey in $Mapping.Keys) {
      if ([string]$MappingKey -ceq $Candidate -or [string]$MappingKey -ieq $Candidate) {
        return Resolve-InstallerFileSystemPath -Path ([string]$Mapping[$MappingKey]) -PathType $PathType
      }
    }
  }
  throw "No caller-supplied local path was provided for $Description. Expected one of: $($Key -join ', ')"
}

function ConvertTo-ZeroInstallSafeRelativePath {
  <#
  .SYNOPSIS
    Normalize a Zero Install Unix path and prove that it stays within a staging root.
  .PARAMETER Root
    Materialization root.
  .PARAMETER Path
    Feed or archive path to validate.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Path)

  if ([string]::IsNullOrWhiteSpace($Path)) { throw 'A Zero Install implementation path is empty.' }
  $Normalized = $Path.Replace('\', '/').TrimEnd('/')
  while ($Normalized.StartsWith('./', [StringComparison]::Ordinal)) { $Normalized = $Normalized.Substring(2) }
  if ([string]::IsNullOrWhiteSpace($Normalized)) { throw 'A Zero Install implementation path resolves to the implementation root.' }
  $FullPath = Resolve-SafeExtractionPath -DestinationPath $Root -RelativePath $Normalized
  return [IO.Path]::GetRelativePath($Root, $FullPath).Replace('\', '/')
}

function Add-ZeroInstallImplementationDirectory {
  <#
  .SYNOPSIS
    Create one validated directory while accounting for recipe output limits.
  .PARAMETER Context
    Mutable offline recipe context.
  .PARAMETER RelativePath
    Implementation-relative directory path.
  .PARAMETER ModifiedTime
    Optional source archive timestamp retained for legacy sha1 manifests.
  #>
  param ([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$RelativePath, [AllowNull()]$ModifiedTime)

  $RelativePath = ConvertTo-ZeroInstallSafeRelativePath -Root $Context.Root -Path $RelativePath
  $Target = Resolve-SafeExtractionPath -DestinationPath $Context.Root -RelativePath $RelativePath
  if (Test-Path -LiteralPath $Target -PathType Leaf) { throw "A file occupies the Zero Install directory path: $RelativePath" }
  if (-not (Test-Path -LiteralPath $Target)) {
    if (++$Context.EntryCount -gt $Context.MaximumEntries) { throw "The Zero Install recipe exceeds the $($Context.MaximumEntries)-entry limit." }
    $null = New-Item -Path $Target -ItemType Directory -Force
  }
  if ($null -ne $ModifiedTime) {
    $Timestamp = [datetime]$ModifiedTime
    if ($Timestamp.Kind -eq [DateTimeKind]::Unspecified) { $Timestamp = [datetime]::SpecifyKind($Timestamp, [DateTimeKind]::Utc) }
    $Context.DirectoryTimestamps[$RelativePath] = $Timestamp.ToUniversalTime()
  }
}

function Add-ZeroInstallImplementationFile {
  <#
  .SYNOPSIS
    Stream one recipe file into the staging tree with exact metadata and limits.
  .PARAMETER Context
    Mutable offline recipe context.
  .PARAMETER RelativePath
    Implementation-relative destination.
  .PARAMETER Stream
    Caller-owned stream consumed from its current position and left open.
  .PARAMETER Length
    Expected file bytes.
  .PARAMETER ModifiedTime
    UTC modification time used in the manifest, or the Unix epoch when absent.
  .PARAMETER Executable
    Mark the resulting manifest record as executable.
  #>
  param (
    [Parameter(Mandatory)]$Context,
    [Parameter(Mandatory)][string]$RelativePath,
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$Length,
    [AllowNull()][Nullable[datetime]]$ModifiedTime,
    [bool]$Executable
  )

  $RelativePath = ConvertTo-ZeroInstallSafeRelativePath -Root $Context.Root -Path $RelativePath
  if ($RelativePath -in '.manifest', '.xbit', '.symlink') { throw "The Zero Install recipe targets reserved path '$RelativePath'." }
  if (++$Context.EntryCount -gt $Context.MaximumEntries) { throw "The Zero Install recipe exceeds the $($Context.MaximumEntries)-entry limit." }
  if ($Length -gt $Context.MaximumBytes - $Context.ExpandedBytes) { throw "The Zero Install recipe exceeds the $($Context.MaximumBytes)-byte output limit." }

  $Target = Resolve-SafeExtractionPath -DestinationPath $Context.Root -RelativePath $RelativePath
  if (Test-Path -LiteralPath $Target -PathType Container) { throw "A directory occupies the Zero Install file path: $RelativePath" }
  $Parent = [IO.Path]::GetDirectoryName($Target)
  if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
  $Output = [IO.File]::Open($Target, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
  try { $null = Copy-BoundedStream -Source $Stream -Destination $Output -MaximumBytes ($Context.MaximumBytes - $Context.ExpandedBytes) -ExpectedBytes $Length } finally { $Output.Dispose() }
  $Context.ExpandedBytes += $Length

  $Timestamp = $null -ne $ModifiedTime ? [datetime]$ModifiedTime : [DateTimeOffset]::FromUnixTimeSeconds(0).UtcDateTime
  if ($Timestamp.Kind -eq [DateTimeKind]::Unspecified) { $Timestamp = [datetime]::SpecifyKind($Timestamp, [DateTimeKind]::Utc) }
  (Get-Item -LiteralPath $Target -Force).LastWriteTimeUtc = $Timestamp.ToUniversalTime()
  if ($Executable) { $null = $Context.ExecutablePaths.Add($RelativePath) } else { $null = $Context.ExecutablePaths.Remove($RelativePath) }
}

function Get-ZeroInstallArchiveOutputPath {
  <#
  .SYNOPSIS
    Apply archive extract and destination prefixes to one entry path.
  .PARAMETER Root
    Recipe staging root used for path validation.
  .PARAMETER EntryPath
    Raw path from the archive.
  .PARAMETER Extract
    Optional archive subtree selected by the feed.
  .PARAMETER Destination
    Optional implementation directory prepended to selected entries.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$EntryPath, [AllowNull()][string]$Extract, [AllowNull()][string]$Destination)

  $Path = $EntryPath.Replace('\', '/').Trim('/')
  while ($Path.StartsWith('./', [StringComparison]::Ordinal)) { $Path = $Path.Substring(2) }
  if ([string]::IsNullOrWhiteSpace($Path) -or $Path -eq '.') { return $null }
  if (-not [string]::IsNullOrWhiteSpace($Extract)) {
    $Prefix = $Extract.Replace('\', '/').Trim('/')
    if ($Path -ceq $Prefix) { return $null }
    if (-not $Path.StartsWith("$Prefix/", [StringComparison]::Ordinal)) { return $null }
    $Path = $Path.Substring($Prefix.Length + 1)
  }
  if (-not [string]::IsNullOrWhiteSpace($Destination)) { $Path = $Destination.Replace('\', '/').Trim('/') + '/' + $Path }
  return ConvertTo-ZeroInstallSafeRelativePath -Root $Root -Path $Path
}

function Expand-ZeroInstallArchiveStep {
  <#
  .SYNOPSIS
    Apply one caller-supplied archive record to an offline recipe context.
  .PARAMETER Context
    Mutable recipe context.
  .PARAMETER Step
    Parsed archive retrieval record.
  .PARAMETER RetrievalSource
    URI-to-local-file mapping supplied by the caller.
  #>
  param ([Parameter(Mandatory)]$Context, [Parameter(Mandatory)]$Step, [Parameter(Mandatory)][Collections.IDictionary]$RetrievalSource)

  $SourcePath = Resolve-ZeroInstallSuppliedPath -Mapping $RetrievalSource -Key @([string]$Step.ResolvedHref, [string]$Step.Href) -PathType Leaf -Description "Zero Install archive '$($Step.Href)'"
  $Source = [IO.File]::Open($SourcePath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
  $Range = $null
  $Reader = $null
  $ZipArchive = $null
  try {
    $StartOffset = [long]$Step.StartOffset
    if ($StartOffset -gt $Source.Length) { throw "The Zero Install archive start offset exceeds the supplied file: $($Step.Href)" }
    $ArchiveLength = $Source.Length - $StartOffset
    if ($Step.HasDeclaredSize -and $ArchiveLength -ne [long]$Step.Size) { throw "The supplied Zero Install archive has $ArchiveLength payload bytes; the feed declares $($Step.Size)." }
    $Range = New-BoundedReadStream -Stream $Source -Offset $StartOffset -Length $ArchiveLength -LeaveOpen
    Import-InstallerArchiveDependency
    $ArchivePaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    # ZIP central-directory attributes carry Unix executable and symlink bits.
    # SharpCompress intentionally normalizes those attributes away on its
    # sequential IEntry surface, so use the platform ZIP reader for this one
    # format and retain SharpCompress for nested/compressed TAR and other media.
    if ([string]$Step.Type -ieq 'application/zip' -or [string]$Step.Href -match '(?i)\.(zip|nupkg|msix)$') {
      $ZipTimestamps = [Collections.Generic.Dictionary[string, datetime]]::new([StringComparer]::Ordinal)
      $TimestampOptions = [SharpCompress.Readers.ReaderOptions]::new()
      $TimestampOptions.LeaveStreamOpen = $true
      $TimestampReader = [SharpCompress.Readers.ReaderFactory]::Open($Range, $TimestampOptions)
      try {
        # The sequential ZIP reader honors Info-ZIP's legacy Unix timestamp
        # extra field, while ZipArchive exposes only the DOS timestamp. Keep
        # those source timestamps and use ZipArchive solely for mode bits/data.
        while ($TimestampReader.MoveToNextEntry()) {
          if ($null -ne $TimestampReader.Entry.LastModifiedTime) { $ZipTimestamps[[string]$TimestampReader.Entry.Key] = [datetime]$TimestampReader.Entry.LastModifiedTime }
        }
      } finally { $TimestampReader.Dispose() }
      $Range.Position = 0
      $ZipArchive = [IO.Compression.ZipArchive]::new($Range, [IO.Compression.ZipArchiveMode]::Read, $true)
      foreach ($Entry in $ZipArchive.Entries) {
        $RelativePath = Get-ZeroInstallArchiveOutputPath -Root $Context.Root -EntryPath $Entry.FullName -Extract ([string]$Step.Extract) -Destination ([string]$Step.Destination)
        if ([string]::IsNullOrWhiteSpace($RelativePath)) { continue }
        if (-not $ArchivePaths.Add($RelativePath)) { throw "The Zero Install archive contains a duplicate output path: $RelativePath" }
        $Mode = ([int]$Entry.ExternalAttributes -shr 16) -band 0xFFFF
        if (($Mode -band 0xF000) -eq 0xA000) { throw "Zero Install ZIP symlinks are not supported by the offline extractor: $($Entry.FullName)" }
        $DosTimestamp = $Entry.LastWriteTime.DateTime
        $ModifiedTime = $DosTimestamp
        if ($ZipTimestamps.ContainsKey($Entry.FullName)) {
          $CandidateTimestamp = $ZipTimestamps[$Entry.FullName]
          # Equal wall-clock values mean the sequential reader only projected
          # the DOS timestamp as local time. A different value proves an
          # extended Unix timestamp, which must retain its instant.
          if ($CandidateTimestamp.Ticks -ne $DosTimestamp.Ticks) { $ModifiedTime = $CandidateTimestamp }
          else { $ModifiedTime = [datetime]::SpecifyKind($DosTimestamp, [DateTimeKind]::Utc) }
        }
        if ($ModifiedTime.Year -eq 1980 -and $ModifiedTime.Month -eq 1 -and $ModifiedTime.Day -eq 1 -and $ModifiedTime.TimeOfDay -eq [TimeSpan]::Zero) { $ModifiedTime = $ModifiedTime.AddDays(-1) }
        if ($Entry.FullName.EndsWith('/', [StringComparison]::Ordinal) -or ($Mode -band 0xF000) -eq 0x4000) { Add-ZeroInstallImplementationDirectory -Context $Context -RelativePath $RelativePath -ModifiedTime $ModifiedTime; continue }
        $EntryStream = $Entry.Open()
        try { Add-ZeroInstallImplementationFile -Context $Context -RelativePath $RelativePath -Stream $EntryStream -Length $Entry.Length -ModifiedTime $ModifiedTime -Executable (($Mode -band 0x49) -ne 0) } finally { $EntryStream.Dispose() }
      }
      return
    }

    $Options = [SharpCompress.Readers.ReaderOptions]::new()
    $Options.LeaveStreamOpen = $true
    $Reader = [SharpCompress.Readers.ReaderFactory]::Open($Range, $Options)
    while ($Reader.MoveToNextEntry()) {
      $Entry = $Reader.Entry
      $RelativePath = Get-ZeroInstallArchiveOutputPath -Root $Context.Root -EntryPath ([string]$Entry.Key) -Extract ([string]$Step.Extract) -Destination ([string]$Step.Destination)
      if ([string]::IsNullOrWhiteSpace($RelativePath)) { continue }
      if (-not $ArchivePaths.Add($RelativePath)) { throw "The Zero Install archive contains a duplicate output path: $RelativePath" }
      if (-not [string]::IsNullOrWhiteSpace([string]$Entry.LinkTarget)) { throw "Zero Install archive links are not supported by the offline extractor: $($Entry.Key)" }
      if ($Entry.IsDirectory) { Add-ZeroInstallImplementationDirectory -Context $Context -RelativePath $RelativePath -ModifiedTime $Entry.LastModifiedTime; continue }
      if ([long]$Entry.Size -lt 0) { throw "The Zero Install archive entry has an unknown expanded size: $($Entry.Key)" }

      $Executable = $false
      $ModeProperty = $Entry.PSObject.Properties['Mode']
      if ($ModeProperty) { $Executable = (([int]$ModeProperty.Value -band 0x49) -ne 0) }
      elseif ($null -ne $Entry.Attrib) { $Executable = ((([int]$Entry.Attrib -shr 16) -band 0x49) -ne 0) }
      $ModifiedTime = $Entry.LastModifiedTime
      if ($ModifiedTime -and $ModifiedTime.Value.Year -eq 1980 -and $ModifiedTime.Value.Month -eq 1 -and $ModifiedTime.Value.Day -eq 1 -and $ModifiedTime.Value.TimeOfDay -eq [TimeSpan]::Zero) { $ModifiedTime = $ModifiedTime.Value.AddDays(-1) }
      $EntryStream = $Reader.OpenEntryStream()
      try { Add-ZeroInstallImplementationFile -Context $Context -RelativePath $RelativePath -Stream $EntryStream -Length ([long]$Entry.Size) -ModifiedTime $ModifiedTime -Executable $Executable } finally { $EntryStream.Dispose() }
    }
  } finally {
    if ($ZipArchive) { $ZipArchive.Dispose() }
    if ($Reader) { $Reader.Dispose() }
    if ($Range) { $Range.Dispose() }
    $Source.Dispose()
  }
}

function Copy-ZeroInstallImplementationSource {
  <#
  .SYNOPSIS
    Apply a copy-from recipe step from an explicitly supplied implementation directory.
  .PARAMETER Context
    Mutable recipe context.
  .PARAMETER Step
    Parsed copy-from record.
  .PARAMETER SourceImplementation
    Implementation-ID-to-directory mapping supplied by the caller.
  #>
  param ([Parameter(Mandatory)]$Context, [Parameter(Mandatory)]$Step, [Parameter(Mandatory)][Collections.IDictionary]$SourceImplementation)

  if ([string]::IsNullOrWhiteSpace([string]$Step.Id)) { throw 'A Zero Install copy-from step has no implementation id.' }
  $ImplementationRoot = Resolve-ZeroInstallSuppliedPath -Mapping $SourceImplementation -Key @([string]$Step.Id) -PathType Container -Description "Zero Install implementation '$($Step.Id)'"
  $SourceRelative = [string]$Step.Source
  $SourcePath = if ([string]::IsNullOrWhiteSpace($SourceRelative)) { $ImplementationRoot } else { Resolve-SafeExtractionPath -DestinationPath $ImplementationRoot -RelativePath $SourceRelative }
  if (-not (Test-Path -LiteralPath $SourcePath)) { throw "The Zero Install copy-from source does not exist: $SourceRelative" }

  $ExecutablePaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $ManifestPath = Join-Path $ImplementationRoot '.manifest'
  if (Test-Path -LiteralPath $ManifestPath -PathType Leaf) {
    $CurrentDirectory = ''
    foreach ($Line in (Read-BoundedTextFile -Path $ManifestPath -MaximumBytes 67108864 -FallbackEncoding 'utf-8') -split "`r?`n") {
      if ($Line.StartsWith('D /', [StringComparison]::Ordinal)) { $CurrentDirectory = $Line.Substring(3); continue }
      if ($Line -match '^X\s+\S+\s+-?\d+\s+\d+\s+(?<Name>.+)$') { $null = $ExecutablePaths.Add(($CurrentDirectory ? "$CurrentDirectory/$($Matches.Name)" : $Matches.Name)) }
    }
  }

  if (Test-Path -LiteralPath $SourcePath -PathType Leaf) {
    $Destination = [string]$Step.Destination
    if ([string]::IsNullOrWhiteSpace($Destination)) { $Destination = $SourceRelative }
    if ([string]::IsNullOrWhiteSpace($Destination)) { throw 'A Zero Install copy-from file step has no destination.' }
    $File = Get-Item -LiteralPath $SourcePath -Force
    $RelativeToImplementation = [IO.Path]::GetRelativePath($ImplementationRoot, $File.FullName).Replace('\', '/')
    $InputStream = $File.OpenRead()
    try { Add-ZeroInstallImplementationFile -Context $Context -RelativePath $Destination -Stream $InputStream -Length $File.Length -ModifiedTime $File.LastWriteTimeUtc -Executable $ExecutablePaths.Contains($RelativeToImplementation) } finally { $InputStream.Dispose() }
    return
  }

  $DestinationPrefix = [string]$Step.Destination
  $Queue = [Collections.Generic.Queue[IO.DirectoryInfo]]::new()
  $Queue.Enqueue((Get-Item -LiteralPath $SourcePath -Force))
  while ($Queue.Count -gt 0) {
    $Directory = $Queue.Dequeue()
    foreach ($ChildDirectory in $Directory.EnumerateDirectories()) {
      if (($ChildDirectory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Filesystem links are not supported in copy-from: $($ChildDirectory.FullName)" }
      $Queue.Enqueue($ChildDirectory)
      $ScopedRelative = [IO.Path]::GetRelativePath($SourcePath, $ChildDirectory.FullName).Replace('\', '/')
      $OutputRelative = [string]::IsNullOrWhiteSpace($DestinationPrefix) ? $ScopedRelative : "$($DestinationPrefix.Trim('/'))/$ScopedRelative"
      Add-ZeroInstallImplementationDirectory -Context $Context -RelativePath $OutputRelative
    }
    foreach ($File in $Directory.EnumerateFiles()) {
      if (($File.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Filesystem links are not supported in copy-from: $($File.FullName)" }
      $ScopedRelative = [IO.Path]::GetRelativePath($SourcePath, $File.FullName).Replace('\', '/')
      if ($ScopedRelative -in '.manifest', '.xbit', '.symlink') { continue }
      $OutputRelative = [string]::IsNullOrWhiteSpace($DestinationPrefix) ? $ScopedRelative : "$($DestinationPrefix.Trim('/'))/$ScopedRelative"
      $RelativeToImplementation = [IO.Path]::GetRelativePath($ImplementationRoot, $File.FullName).Replace('\', '/')
      $InputStream = $File.OpenRead()
      try { Add-ZeroInstallImplementationFile -Context $Context -RelativePath $OutputRelative -Stream $InputStream -Length $File.Length -ModifiedTime $File.LastWriteTimeUtc -Executable $ExecutablePaths.Contains($RelativeToImplementation) } finally { $InputStream.Dispose() }
    }
  }
}

function Expand-ZeroInstallImplementation {
  <#
  .SYNOPSIS
    Materialize one explicitly selected Zero Install implementation from local retrieval artifacts.
  .DESCRIPTION
    Executes the selected archive, file, rename, remove, and copy-from records in document order. It never downloads a feed or artifact and does not solve dependencies, rollout, trust, or implementation policy. The complete staged tree is manifest-verified before selected files are copied to the destination.
  .PARAMETER FeedInfo
    Result returned by ConvertFrom-ZeroInstallFeed.
  .PARAMETER ImplementationId
    Exact implementation ID to materialize.
  .PARAMETER RetrievalMethodIndex
    Zero-based applicable retrieval-method index. Required when more than one method remains applicable.
  .PARAMETER RetrievalSource
    Dictionary mapping each retrieval ResolvedHref or Href to an existing local file.
  .PARAMETER SourceImplementation
    Dictionary mapping copy-from implementation IDs to existing local directories.
  .PARAMETER DestinationPath
    Output directory. A temporary directory is used when omitted.
  .PARAMETER Name
    Wildcard selecting final implementation paths or file names. All files are exported when omitted.
  .PARAMETER CollisionAction
    Action applied only when a verified output collides with an existing destination file.
  .PARAMETER SkipManifestDigestCheck
    Permit materialization when the implementation has no supported digest or while researching malformed feeds. The computed SHA256New manifest is still returned.
  .PARAMETER MaximumEntries
    Maximum number of recipe and published file/directory operations.
  .PARAMETER MaximumExpandedBytes
    Maximum aggregate bytes written while staging the recipe.
  .OUTPUTS
    A result containing selected Files, output counts, implementation identity, retrieval method, manifest evidence, and whether its digest matched.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]$FeedInfo,
    [Parameter(Mandatory)][string]$ImplementationId,
    [ValidateRange(0, [int]::MaxValue)][int]$RetrievalMethodIndex,
    [Parameter(Mandatory)][Collections.IDictionary]$RetrievalSource,
    [Collections.IDictionary]$SourceImplementation = @{},
    [string]$DestinationPath,
    [string]$Name = '*',
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Prompt',
    [switch]$SkipManifestDigestCheck,
    [ValidateRange(1, [int]::MaxValue)][int]$MaximumEntries = 65536,
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 2147483648
  )

  $Implementation = @($FeedInfo.Implementations | Where-Object Id -CEQ $ImplementationId)
  if ($Implementation.Count -ne 1) { throw "Expected exactly one Zero Install implementation with id '$ImplementationId'; found $($Implementation.Count)." }
  $Implementation = $Implementation[0]
  $Methods = @($Implementation.ApplicableRetrievalMethods)
  if ($Methods.Count -eq 0) { throw "Zero Install implementation '$ImplementationId' has no applicable retrieval method." }
  if (-not $PSBoundParameters.ContainsKey('RetrievalMethodIndex')) {
    if ($Methods.Count -ne 1) { throw "Zero Install implementation '$ImplementationId' has $($Methods.Count) applicable retrieval methods; specify -RetrievalMethodIndex explicitly." }
    $RetrievalMethodIndex = 0
  }
  if ($RetrievalMethodIndex -ge $Methods.Count) { throw "Zero Install retrieval method index $RetrievalMethodIndex is outside the $($Methods.Count)-method collection." }
  $Method = $Methods[$RetrievalMethodIndex]
  if ($Method.Kind -eq 'recipe' -and $Method.ContainsUnknownSteps) { throw "The selected Zero Install recipe contains unsupported step types: $($Method.UnknownSteps.Name -join ', ')" }
  $Steps = $Method.Kind -eq 'recipe' ? @($Method.ApplicableSteps) : @($Method)

  $StagingPath = New-TempFolder
  $OwnDestination = [string]::IsNullOrWhiteSpace($DestinationPath)
  if ($OwnDestination) { $DestinationPath = New-TempFolder } else { $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent }
  $Context = [pscustomobject]@{
    Root                = $StagingPath
    EntryCount          = 0
    ExpandedBytes       = 0L
    MaximumEntries      = $MaximumEntries
    MaximumBytes        = $MaximumExpandedBytes
    ExecutablePaths     = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    DirectoryTimestamps = [Collections.Generic.Dictionary[string, datetime]]::new([StringComparer]::OrdinalIgnoreCase)
  }
  try {
    foreach ($Step in $Steps) {
      switch ($Step.Kind) {
        'archive' { Expand-ZeroInstallArchiveStep -Context $Context -Step $Step -RetrievalSource $RetrievalSource }
        'file' {
          $SourcePath = Resolve-ZeroInstallSuppliedPath -Mapping $RetrievalSource -Key @([string]$Step.ResolvedHref, [string]$Step.Href) -PathType Leaf -Description "Zero Install file '$($Step.Href)'"
          $File = Get-Item -LiteralPath $SourcePath -Force
          if ($Step.HasDeclaredSize -and $File.Length -ne [long]$Step.Size) { throw "The supplied Zero Install file has $($File.Length) bytes; the feed declares $($Step.Size)." }
          $InputStream = $File.OpenRead()
          try { Add-ZeroInstallImplementationFile -Context $Context -RelativePath ([string]$Step.Destination) -Stream $InputStream -Length $File.Length -ModifiedTime ([DateTimeOffset]::FromUnixTimeSeconds(0).UtcDateTime) -Executable ([bool]$Step.Executable) } finally { $InputStream.Dispose() }
        }
        'rename' {
          $SourceRelative = ConvertTo-ZeroInstallSafeRelativePath -Root $StagingPath -Path ([string]$Step.Source)
          $DestinationRelative = ConvertTo-ZeroInstallSafeRelativePath -Root $StagingPath -Path ([string]$Step.Destination)
          $SourcePath = Resolve-SafeExtractionPath -DestinationPath $StagingPath -RelativePath $SourceRelative
          if (-not (Test-Path -LiteralPath $SourcePath)) { throw "The Zero Install rename source does not exist: $SourceRelative" }
          $DestinationFile = Resolve-SafeExtractionPath -DestinationPath $StagingPath -RelativePath $DestinationRelative
          if (Test-Path -LiteralPath $DestinationFile) { Remove-Item -LiteralPath $DestinationFile -Recurse -Force }
          $Parent = [IO.Path]::GetDirectoryName($DestinationFile)
          if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
          Move-Item -LiteralPath $SourcePath -Destination $DestinationFile
          foreach ($ExecutablePath in @($Context.ExecutablePaths)) {
            if ($ExecutablePath -ceq $SourceRelative -or $ExecutablePath.StartsWith("$SourceRelative/", [StringComparison]::Ordinal)) {
              $null = $Context.ExecutablePaths.Remove($ExecutablePath)
              $null = $Context.ExecutablePaths.Add($DestinationRelative + $ExecutablePath.Substring($SourceRelative.Length))
            }
          }
        }
        'remove' {
          $RelativePath = ConvertTo-ZeroInstallSafeRelativePath -Root $StagingPath -Path ([string]$Step.Path)
          $Target = Resolve-SafeExtractionPath -DestinationPath $StagingPath -RelativePath $RelativePath
          if (-not (Test-Path -LiteralPath $Target)) { throw "The Zero Install remove path does not exist: $RelativePath" }
          Remove-Item -LiteralPath $Target -Recurse -Force
          foreach ($ExecutablePath in @($Context.ExecutablePaths)) {
            if ($ExecutablePath -ceq $RelativePath -or $ExecutablePath.StartsWith("$RelativePath/", [StringComparison]::Ordinal)) { $null = $Context.ExecutablePaths.Remove($ExecutablePath) }
          }
        }
        'copy-from' { Copy-ZeroInstallImplementationSource -Context $Context -Step $Step -SourceImplementation $SourceImplementation }
        default { throw "Unsupported Zero Install recipe step: $($Step.Kind)" }
      }
    }

    # File writes alter their parent directory timestamps. Restore source archive directory
    # timestamps only after every recipe operation so the legacy sha1 manifest is reproducible.
    foreach ($Entry in @($Context.DirectoryTimestamps.GetEnumerator() | Sort-Object { ($_.Key -split '/').Count } -Descending)) {
      $DirectoryPath = Resolve-SafeExtractionPath -DestinationPath $StagingPath -RelativePath $Entry.Key
      if (Test-Path -LiteralPath $DirectoryPath -PathType Container) { (Get-Item -LiteralPath $DirectoryPath -Force).LastWriteTimeUtc = $Entry.Value }
    }

    $ExpectedDigest = [string]$Implementation.ManifestDigest.Best
    if (-not $SkipManifestDigestCheck -and [string]::IsNullOrWhiteSpace($ExpectedDigest)) { throw "Zero Install implementation '$ImplementationId' has no supported manifest digest." }
    $Manifest = if ([string]::IsNullOrWhiteSpace($ExpectedDigest)) {
      Get-ZeroInstallImplementationManifest -Path $StagingPath -Algorithm Sha256New -ExecutablePath @($Context.ExecutablePaths) -MaximumEntries $MaximumEntries -MaximumBytes $MaximumExpandedBytes
    } else {
      Test-ZeroInstallImplementationDigest -Path $StagingPath -Digest $ExpectedDigest -ExecutablePath @($Context.ExecutablePaths) -MaximumEntries $MaximumEntries -MaximumBytes $MaximumExpandedBytes -PassThru
    }
    # A computed manifest without a source digest is useful evidence but cannot
    # be called verified. Avoid probing a property absent from that result type.
    $ManifestVerified = if ([string]::IsNullOrWhiteSpace($ExpectedDigest)) { $false } else { [bool]$Manifest.IsMatch }
    if (-not $SkipManifestDigestCheck -and -not $ManifestVerified) { throw "The Zero Install implementation digest does not match. Expected '$ExpectedDigest'; calculated '$($Manifest.Digest)'." }

    $Files = [Collections.Generic.List[IO.FileInfo]]::new()
    $ReservedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($File in Get-ChildItem -LiteralPath $StagingPath -File -Recurse -Force) {
      $RelativePath = [IO.Path]::GetRelativePath($StagingPath, $File.FullName).Replace('\', '/')
      if (-not (Test-ExtractionPattern -Path $RelativePath -Pattern $Name)) { continue }
      $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $RelativePath -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
      if (-not $Target.ShouldWrite) { continue }
      $Parent = [IO.Path]::GetDirectoryName($Target.Path)
      if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
      $InputStream = $File.OpenRead()
      $OutputStream = [IO.File]::Open($Target.Path, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
      try { $null = Copy-BoundedStream -Source $InputStream -Destination $OutputStream -MaximumBytes ([Math]::Max(1L, $File.Length)) -ExpectedBytes $File.Length } finally { $OutputStream.Dispose(); $InputStream.Dispose() }
      (Get-Item -LiteralPath $Target.Path -Force).LastWriteTimeUtc = $File.LastWriteTimeUtc
      $Files.Add((Get-Item -LiteralPath $Target.Path -Force))
    }
    return [pscustomobject][ordered]@{
      Files                = $Files.ToArray()
      ExpandedBytes        = [long]$Context.ExpandedBytes
      EntryCount           = [int]$Context.EntryCount
      ImplementationId     = $ImplementationId
      RetrievalMethodIndex = $RetrievalMethodIndex
      RetrievalMethod      = $Method
      ExpectedDigest       = $ExpectedDigest
      CalculatedDigest     = [string]$Manifest.Digest
      ManifestVerified     = $ManifestVerified
      ManifestText         = [string]$Manifest.ManifestText
      ExecutablePaths      = [string[]]@($Context.ExecutablePaths | Sort-Object)
      DestinationPath      = $DestinationPath
    }
  } catch {
    if ($OwnDestination -and $DestinationPath -and (Test-Path -LiteralPath $DestinationPath)) { Remove-Item -LiteralPath $DestinationPath -Recurse -Force -ErrorAction SilentlyContinue }
    throw
  } finally {
    Remove-Item -LiteralPath $StagingPath -Recurse -Force -ErrorAction SilentlyContinue
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
    Wildcard matched against normalized resource paths and, when archive
    expansion is enabled, _implementations/<digest>/ entry paths.
  .PARAMETER ContentDirectoryPath
    Optional exact directory passed to the bootstrap runtime as content.
  .PARAMETER ExpandImplementationArchives
    Also expand content files whose basename is a recognized manifest digest.
    This does not imply that the Zero Install solver selects that implementation.
  .PARAMETER MaximumExpandedBytes
    Maximum cumulative output bytes.
  .PARAMETER CollisionAction
    Behavior when an output path already exists or is selected more than once.
  #>
  [OutputType([IO.FileInfo[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [string]$Name = '*',
    [string]$ContentDirectoryPath,
    [switch]$ExpandImplementationArchives,
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Prompt',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 1073741824
  )
  process {
    $File = Get-Item -LiteralPath $Path -Force
    if ([string]::IsNullOrWhiteSpace($DestinationPath)) { $DestinationPath = Join-Path ([IO.Path]::GetTempPath()) "Dumplings-ZeroInstall-$([guid]::NewGuid().ToString('N'))" }
    $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
    $null = New-Item -Path $DestinationPath -ItemType Directory -Force

    $Stream = [IO.File]::Open($File.FullName, 'Open', 'Read', 'ReadWrite')
    try {
      $Layout = Get-PELayout -Stream $Stream
      $RequestedResourceNames = [string[]]@($Script:ZeroInstallConfigurationResourceNames) + @('ZeroInstall.SplashScreen.png', 'ZeroInstall.content.*')
      $Resources = @(Get-PEManagedResourceInfo -Stream $Stream -Layout $Layout -Name $RequestedResourceNames -MaximumResources $Script:ZeroInstallMaximumResources -MaximumResourceBytes $File.Length)
      if (@($Resources | Where-Object Name -In $Script:ZeroInstallConfigurationResourceNames).Count -ne 1) { throw 'The PE does not contain exactly one supported Zero Install bootstrap configuration.' }
      $ContentEntries = @(Get-ZeroInstallContentCatalog -Resource $Resources -ContentDirectoryPath $ContentDirectoryPath)

      $ExpandedBytes = 0L
      $Files = [Collections.Generic.List[IO.FileInfo]]::new()
      $ReservedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
      foreach ($Resource in $Resources) {
        $RelativePath = Get-ZeroInstallExtractableResourceName -ResourceName $Resource.Name
        if (-not $RelativePath -or -not (Test-ExtractionPattern -Path $RelativePath -Pattern $Name)) { continue }
        $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $RelativePath `
          -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
        if (-not $Target.ShouldWrite) { continue }
        if ($Resource.Size -gt $MaximumExpandedBytes - $ExpandedBytes) { throw 'Zero Install extraction exceeds the configured output limit.' }
        $Files.Add((Export-PEResourceData -Resource $Resource -DestinationPath $Target.Path `
              -MaximumBytes ($MaximumExpandedBytes - $ExpandedBytes) -CollisionAction Overwrite))
        $ExpandedBytes += $Resource.Size
      }

      # An explicitly supplied content directory follows the same non-recursive
      # import behavior as BootstrapProcess.ImportDirectory. Copy it into the
      # raw content namespace while retaining collision and aggregate bounds.
      foreach ($ContentEntry in $ContentEntries) {
        if ($ContentEntry.Source -cne 'ContentDirectory' -or -not (Test-ExtractionPattern -Path $ContentEntry.RelativePath -Pattern $Name)) { continue }
        $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $ContentEntry.RelativePath -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
        if (-not $Target.ShouldWrite) { continue }
        if ($ContentEntry.Size -gt $MaximumExpandedBytes - $ExpandedBytes) { throw 'Zero Install extraction exceeds the configured output limit.' }
        $Parent = [IO.Path]::GetDirectoryName($Target.Path)
        if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
        $InputStream = [IO.File]::Open($ContentEntry.Path, 'Open', 'Read', 'ReadWrite')
        $OutputStream = [IO.File]::Open($Target.Path, 'Create', 'Write', 'None')
        try { $null = Copy-BoundedStream -Source $InputStream -Destination $OutputStream -MaximumBytes ($MaximumExpandedBytes - $ExpandedBytes) -ExpectedBytes $ContentEntry.Size }
        finally { $OutputStream.Dispose(); $InputStream.Dispose() }
        $OutputFile = Get-Item -LiteralPath $Target.Path -Force
        $Files.Add($OutputFile)
        $ExpandedBytes += $OutputFile.Length
      }

      # Embedded implementation archives are seed-store evidence. Expand them
      # only on explicit request and place each under its manifest digest so
      # several alternatives cannot overwrite one another or masquerade as the
      # solver-selected application payload.
      if ($ExpandImplementationArchives) {
        foreach ($ContentEntry in $ContentEntries) {
          if ($ContentEntry.Kind -cne 'ImplementationArchive') { continue }
          $Prefix = "_implementations/$($ContentEntry.ManifestDigest)/"
          $ArchivePattern = if ($Name -ceq '*') { '*' } elseif ($Name.StartsWith($Prefix, [StringComparison]::OrdinalIgnoreCase)) { $Name.Substring($Prefix.Length) } else { $null }
          if ([string]::IsNullOrWhiteSpace($ArchivePattern)) { continue }

          $ArchiveStream = $null
          $Archive = $null
          try {
            if ($ContentEntry.Source -ceq 'EmbeddedResource') {
              $Resource = $Resources | Where-Object Name -CEQ $ContentEntry.ResourceName | Select-Object -First 1
              if (-not $Resource) { throw "The embedded Zero Install content resource '$($ContentEntry.ResourceName)' was not found." }
              $ArchiveStream = New-BoundedReadStream -Stream $Stream -Offset $Resource.Offset -Length $Resource.Size -LeaveOpen
            } else {
              $ArchiveStream = [IO.File]::Open($ContentEntry.Path, 'Open', 'Read', 'ReadWrite')
            }
            $Archive = Get-InstallerArchive -Stream $ArchiveStream
            $Remaining = $MaximumExpandedBytes - $ExpandedBytes
            if ($Remaining -le 0) { throw 'Zero Install extraction exceeds the configured output limit.' }
            $ImplementationRoot = Resolve-SafeExtractionPath -DestinationPath $DestinationPath -RelativePath $Prefix.TrimEnd('/')
            $Selection = Export-InstallerArchiveSelection -Archive $Archive -DestinationPath $ImplementationRoot -Name $ArchivePattern -CollisionAction $CollisionAction -MaximumExpandedBytes $Remaining -MaximumEntries $Script:ZeroInstallMaximumResources
            foreach ($OutputFile in $Selection.Files) { $Files.Add($OutputFile) }
            $ExpandedBytes += $Selection.ExpandedBytes
          } finally {
            if ($Archive) { $Archive.Dispose() }
            if ($ArchiveStream) { $ArchiveStream.Dispose() }
          }
        }
      }
      if ($Files.Count -eq 0) { throw "No Zero Install resources matched '$Name'." }
      return $Files.ToArray()
    } finally { $Stream.Dispose() }
  }
}

function Test-ZeroInstallInstaller {
  <#
  .SYNOPSIS
    Test for a structurally valid Zero Install bootstrapper identity and configuration
  .PARAMETER Path
    Path to the candidate PE.
  #>
  [OutputType([bool])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process {
    $Stream = $null
    try {
      $File = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
      $VersionInfo = [Diagnostics.FileVersionInfo]::GetVersionInfo($File.FullName)
      $RuntimeVersion = ConvertTo-ZeroInstallRuntimeVersion -Value $VersionInfo.FileVersion
      $Stream = [IO.File]::Open($File.FullName, 'Open', 'Read', 'ReadWrite')
      $Layout = Get-PELayout -Stream $Stream
      if (-not $Layout) { return $false }
      $ManagedIdentity = Get-ZeroInstallManagedIdentity -Stream $Stream
      if (-not $RuntimeVersion -and $ManagedIdentity.AssemblyVersion) { $RuntimeVersion = [version]$ManagedIdentity.AssemblyVersion }
      if (-not $ManagedIdentity.IsBootstrapper) { return $false }
      $Resources = @(Get-PEManagedResourceInfo -Stream $Stream -Layout $Layout -Name $Script:ZeroInstallConfigurationResourceNames -MaximumResources $Script:ZeroInstallMaximumResources -MaximumResourceBytes $File.Length)
      if ($Resources.Count -gt 1) { return $false }

      if ($Resources.Count -eq 1) {
        $Bytes = Read-PEResourceData -Resource $Resources[0] -MaximumBytes $Script:ZeroInstallMaximumConfigBytes
        $Text = [Text.UTF8Encoding]::new($false, $true).GetString($Bytes).TrimStart([char]0xFEFF)
        $null = Get-ZeroInstallConfigurationProfile -ResourceName $Resources[0].Name -Content $Text -RuntimeVersion $RuntimeVersion
        return $true
      }

      # Pre-2.11.6 launchers have no customizable configuration resource. The
      # exact CLR type plus its bounded release interval is their structure.
      if (-not $ManagedIdentity.Profile) { return $false }
      return -not $RuntimeVersion -or (Test-ZeroInstallVersionInProfile -Version $RuntimeVersion -FormatProfile $ManagedIdentity.Profile)
    } catch {
      return $false
    } finally {
      if ($Stream) { $Stream.Dispose() }
    }
  }
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

Export-ModuleMember -Function ConvertFrom-ZeroInstallFeed, Get-ZeroInstallInfo, Get-ZeroInstallImplementationManifest, Test-ZeroInstallImplementationDigest, Expand-ZeroInstallImplementation, Expand-ZeroInstallInstaller, Test-ZeroInstallInstaller, Read-ProductNameFromZeroInstall, Read-PublisherFromZeroInstall, Read-ProductCodeFromZeroInstall, Read-ScopeFromZeroInstall, Read-ProtocolsFromZeroInstall, Read-FileExtensionsFromZeroInstall
