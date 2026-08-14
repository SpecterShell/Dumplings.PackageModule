# SPDX-License-Identifier: Apache-2.0
# install4j Windows setup structures consumed here:
#
#   PE image
#   `-- overlay (absolute file offset from the PE section layout)
#       +-- D5 13 E4 E8
#       +-- legacy 3.x/4.x launcher
#       |   +-- int32 LE ANSI parameter count and records
#       |   +-- int32 LE UTF-16LE parameter count and records
#       |   `-- repeated startup payloads
#       |       +-- 3.x: int32 LE length + XOR-88 bytes
#       |       `-- 4.x: int64 LE length + XOR-88 bytes
#       +-- modern 5.x-13.x launcher
#       |   +-- uint32 LE flags and expected CRC32
#       |   +-- int64 LE bounded data length
#       |   +-- ANSI, localized, and named nested parameter maps
#       |   `-- int64 LE startup lengths + XOR-88 bytes
#       `-- optional ContentCollector table
#           +-- E8 E4 13 D5 + int32 BE count
#           +-- repeated modified-UTF8 name + int64 BE length
#           `-- contiguous payloads (0.dat or generation-4 .000 LZMA)
#
# Parameter 2000 identifies the structural launcher generation when present.
# Markerless application media can use the explicit version in a validated
# i4jparams.conf. Parameter 2003 owns the startup-file order. All ranges are
# validated before metadata or payloads are exposed; modern data is additionally
# authenticated by CRC32.
#
# Behavioral references:
# - https://www.ej-technologies.com/install4j/changelog
# - https://www.ej-technologies.com/resources/install4j/help/doc/concepts/mediaFiles.html
# - https://www.ej-technologies.com/resources/install4j/help/doc/concepts/launchers.html
#
# Historical field layouts are independently documented from official archived
# builders and controlled media generated from licensed builders inside the VM.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:Install4jUnextractedMagic = [byte[]](0xE8, 0xE4, 0x13, 0xD5)
$Script:Install4jApplicationIdPattern = '(?<ApplicationId>\d{4}-\d{4}-\d{4}-\d{4})'
$Script:Install4jMaximumScanBytes = 4194304
$Script:Install4jMaximumConfigBytes = 33554432
$Script:Install4jMaximumDictionaryBytes = 536870912
$Script:Install4jMaximumExpandedBytes = 8589934592
$Script:Install4jMaximumArchiveEntries = 100000
$Script:Install4jLauncherMagic = [byte[]](0xD5, 0x13, 0xE4, 0xE8)
$Script:Install4jLauncherTransformKey = [byte]0x88
$Script:Install4jMaximumParameterCount = 4096
$Script:Install4jMaximumParameterBytes = 8388608
$Script:Install4jCatalog = Import-PowerShellDataFile -LiteralPath (Join-Path $PSScriptRoot 'Install4jFormatCatalog.psd1')
$Script:Install4jFormats = @($Script:Install4jCatalog.Formats | ForEach-Object { [pscustomobject]$_ })
$Script:Install4jLauncherHandlers = @{
  LegacyParameterBlock32 = 'Get-Install4jLegacyLauncherConfiguration'
  LegacyParameterBlock64 = 'Get-Install4jLegacyLauncherConfiguration'
  ModernOverlayV1        = 'Get-Install4jModernLauncherConfiguration'
}
$Script:Install4jContentTableHandlers = @{
  None               = 'Get-Install4jNoEmbeddedFileTable'
  ContentCollectorV1 = 'Get-Install4jEmbeddedFileTable'
}
$Script:Install4jPayloadHandlers = @{
  InlineContentZip = 'Expand-Install4jInlineContentArchive'
  SplitLzmaArchive = 'Expand-Install4jLzmaArchiveEntry'
  LzmaZipContent   = 'Expand-Install4jLzmaArchiveEntry'
}

function Get-Install4jVersionInfo {
  <#
  .SYNOPSIS
    Read PE version-resource metadata if the install4j input is a PE launcher
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The installer file')]
    [System.IO.FileInfo]$File
  )

  try {
    $VersionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($File.FullName)
    [pscustomobject]@{
      FileDescription = $VersionInfo.FileDescription
      FileVersion     = $VersionInfo.FileVersion
      ProductName     = $VersionInfo.ProductName
      ProductVersion  = $VersionInfo.ProductVersion
      CompanyName     = $VersionInfo.CompanyName
      OriginalName    = $VersionInfo.OriginalFilename
    }
  } catch {
    $null
  }
}

function Get-Install4jScanText {
  <#
  .SYNOPSIS
    Read bounded string windows from the launcher, overlay, and tail
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The installer file')]
    [System.IO.FileInfo]$File,

    [Parameter(HelpMessage = 'Caller-owned seekable installer stream')]
    [IO.Stream]$Stream
  )

  $StringBuilder = [System.Text.StringBuilder]::new()
  $OwnsStream = $null -eq $Stream
  if ($OwnsStream) { $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite) }
  $OriginalPosition = if ($Stream.CanSeek) { $Stream.Position } else { 0L }
  try {
    # Collect only the launcher prefix, file tail, and a bounded overlay window. This fallback is
    # intentionally secondary to the structured startup and embedded-file tables.
    foreach ($Range in @(
        [pscustomobject]@{ Offset = [long]0; Count = [int][Math]::Min(4194304, $File.Length) },
        [pscustomobject]@{ Offset = [long][Math]::Max(0, $File.Length - 4194304); Count = [int][Math]::Min(4194304, $File.Length) }
      )) {
      $Bytes = Read-BinaryBytes -Stream $Stream -Offset $Range.Offset -Count $Range.Count -AllowPartial
      if ($Bytes.Length -gt 0) {
        $null = $StringBuilder.Append([System.Text.Encoding]::Latin1.GetString($Bytes))
        $null = $StringBuilder.Append("`n")
      }
    }

    if ((Get-Command -Name Get-PEOverlayOffset -ErrorAction SilentlyContinue)) {
      $OverlayOffset = try { Get-PEOverlayOffset -Stream $Stream } catch { 0 }
      if ($OverlayOffset -gt 0 -and $OverlayOffset -lt $File.Length) {
        # install4j launcher records and the embedded file list are stored near
        # the PE overlay start; a bounded read avoids scanning large payloads.
        $Bytes = Read-BinaryBytes -Stream $Stream -Offset $OverlayOffset -Count ([int][Math]::Min($Script:Install4jMaximumScanBytes, $File.Length - $OverlayOffset)) -AllowPartial
        if ($Bytes.Length -gt 0) {
          $null = $StringBuilder.Append([System.Text.Encoding]::Latin1.GetString($Bytes))
          $null = $StringBuilder.Append("`n")
        }
      }
    }
  } finally {
    if ($OwnsStream) { $Stream.Dispose() } elseif ($Stream.CanSeek) { $Stream.Position = $OriginalPosition }
  }

  return $StringBuilder.ToString()
}

function Get-Install4jXmlAttribute {
  <#
  .SYNOPSIS
    Get an XML attribute value from an install4j config node
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The XML element')]
    [System.Xml.XmlElement]$Element,

    [Parameter(Mandatory, HelpMessage = 'The attribute name')]
    [string]$Name
  )

  $Attribute = $Element.Attributes.GetNamedItem($Name)
  if ($Attribute) { return $Attribute.Value }
}

function ConvertTo-Install4jBoolean {
  <#
  .SYNOPSIS
    Convert an install4j XML boolean string to a nullable Boolean
  #>
  [OutputType([bool])]
  param (
    [Parameter(HelpMessage = 'The value to convert')]
    [AllowNull()]
    [object]$Value
  )

  if ($null -eq $Value) { return $null }
  if ($Value -is [bool]) { return $Value }
  switch -Regex ([string]$Value) {
    '^(?i:true|1|yes)$' { return $true }
    '^(?i:false|0|no)$' { return $false }
    default { return $null }
  }
}

function Get-Install4jXmlDecoderPropertyValue {
  <#
  .SYNOPSIS
    Read a java.beans.XMLDecoder property value from an install4j action object
  #>
  [OutputType([object])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The XMLDecoder object node')]
    [System.Xml.XmlElement]$ObjectNode,

    [Parameter(Mandatory, HelpMessage = 'The Java bean property name')]
    [string]$Name
  )

  foreach ($Child in $ObjectNode.ChildNodes) {
    if ($Child.NodeType -ne [System.Xml.XmlNodeType]::Element -or $Child.LocalName -ne 'void') { continue }
    if ((Get-Install4jXmlAttribute -Element $Child -Name 'property') -ne $Name) { continue }

    foreach ($ValueNode in $Child.ChildNodes) {
      if ($ValueNode.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }

      switch ($ValueNode.LocalName) {
        'string' { return $ValueNode.InnerText }
        'boolean' { return (ConvertTo-Install4jBoolean -Value $ValueNode.InnerText) }
        'int' { return [int]$ValueNode.InnerText }
        'long' { return [long]$ValueNode.InnerText }
        default { return $ValueNode.InnerText }
      }
    }
  }
}

function Get-Install4jConfigXmlText {
  <#
  .SYNOPSIS
    Locate plain install4j configuration XML in a bounded text window
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The scanned text')]
    [string]$Text
  )

  # Bound candidate XML to a complete config element and require install4j-specific root evidence
  # before handing it to the XML parser.
  $ConfigIndex = $Text.IndexOf('<config', [StringComparison]::OrdinalIgnoreCase)
  if ($ConfigIndex -lt 0) { return }

  $EndIndex = $Text.IndexOf('</config>', $ConfigIndex, [StringComparison]::OrdinalIgnoreCase)
  if ($EndIndex -lt 0) { return }

  $StartIndex = $Text.LastIndexOf('<?xml', $ConfigIndex, [StringComparison]::OrdinalIgnoreCase)
  if ($StartIndex -lt 0 -or $ConfigIndex - $StartIndex -gt 256) { $StartIndex = $ConfigIndex }

  $Candidate = $Text.Substring($StartIndex, $EndIndex + 9 - $StartIndex)
  if ($Candidate.IndexOf('install4jVersion', [StringComparison]::OrdinalIgnoreCase) -lt 0 -and $Candidate.IndexOf('applicationId', [StringComparison]::OrdinalIgnoreCase) -lt 0) { return }

  $XmlMatch = [regex]::Match($Candidate, '(?s)<\?xml[^>]*>\s*<config\s[^>]*(?:install4jVersion|archive|bitness)[^>]*>.*?</config>')
  if ($XmlMatch.Success) { return $XmlMatch.Value }

  $ConfigMatch = [regex]::Match($Candidate, '(?s)<config\s[^>]*(?:install4jVersion|archive|bitness)[^>]*>.*?</config>')
  if ($ConfigMatch.Success) { return $ConfigMatch.Value }
}

function Get-Install4jCompilerVariableMap {
  <#
  .SYNOPSIS
    Read install4j compiler variables from i4jparams.conf
  #>
  [OutputType([hashtable])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The install4j config XML document')]
    [xml]$Xml
  )

  $Variables = @{}
  foreach ($Variable in @($Xml.SelectNodes('/config/compilerVariables/variable | /config/variables/variable'))) {
    $Name = Get-Install4jXmlAttribute -Element $Variable -Name 'name'
    if ([string]::IsNullOrWhiteSpace($Name)) { continue }
    $Variables[$Name] = Get-Install4jXmlAttribute -Element $Variable -Name 'value'
  }

  return $Variables
}

function Expand-Install4jStaticText {
  <#
  .SYNOPSIS
    Expand common install4j compiler variables in statically parsed strings
  #>
  [OutputType([string])]
  param (
    [Parameter(HelpMessage = 'The string to expand')]
    [AllowNull()]
    [string]$Value,

    [Parameter(Mandatory, HelpMessage = 'The parsed general config values')]
    [hashtable]$General,

    [Parameter(Mandatory, HelpMessage = 'The parsed compiler variables')]
    [hashtable]$CompilerVariables
  )

  if ([string]::IsNullOrEmpty($Value)) { return $Value }

  $BuiltInVariables = @{
    'sys.fullName'  = $General.ApplicationName
    'sys.name'      = $General.ApplicationName
    'sys.version'   = $General.ApplicationVersion
    'sys.publisher' = $General.PublisherName
  }

  # Expand only compiler and known sys values. Runtime expressions stay literal so static metadata
  # does not invent values produced by installer scripts.
  $VariableMap = $CompilerVariables
  return [regex]::Replace($Value, '\$\{compiler:([^}]+)\}', {
      param($Match)
      $VariableName = $Match.Groups[1].Value
      if ($VariableMap.ContainsKey($VariableName)) { return [string]$VariableMap[$VariableName] }
      if ($BuiltInVariables.ContainsKey($VariableName) -and -not [string]::IsNullOrWhiteSpace($BuiltInVariables[$VariableName])) { return [string]$BuiltInVariables[$VariableName] }
      return $Match.Value
    })
}

function ConvertFrom-Install4jConfigXml {
  <#
  .SYNOPSIS
    Parse an install4j i4jparams.conf XML document
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The install4j i4jparams.conf XML text')]
    [string]$Content,

    [Parameter(HelpMessage = 'The source that provided this XML')]
    [string]$Source = 'Xml',

    [Parameter(HelpMessage = 'Catalog-selected configuration schema route')]
    [ValidateSet('Auto', 'Legacy3Xml', 'Legacy4Xml', 'ModernXml')]
    [string]$ConfigRoute = 'Auto'
  )

  [xml]$Xml = $Content
  if (-not $Xml.config) { throw 'The XML document is not an install4j config document' }

  $Root = $Xml.config
  if ($ConfigRoute -eq 'Auto') {
    $EncodedVersion = Get-Install4jXmlAttribute -Element $Root -Name 'install4jVersion'
    $ConfigRoute = if ([string]::IsNullOrWhiteSpace($EncodedVersion)) {
      'Legacy3Xml'
    } elseif ($EncodedVersion -match '^4(?:\.|$)') {
      'Legacy4Xml'
    } else {
      'ModernXml'
    }
  }
  $GeneralNode = $Xml.SelectSingleNode('/config/general')
  if (-not $GeneralNode) { throw 'The install4j config does not contain a general element' }

  $General = @{
    ApplicationName              = Get-Install4jXmlAttribute -Element $GeneralNode -Name 'applicationName'
    ApplicationVersion           = Get-Install4jXmlAttribute -Element $GeneralNode -Name 'applicationVersion'
    ApplicationId                = Get-Install4jXmlAttribute -Element $GeneralNode -Name 'applicationId'
    MediaName                    = Get-Install4jXmlAttribute -Element $GeneralNode -Name 'mediaName'
    PublisherName                = Get-Install4jXmlAttribute -Element $GeneralNode -Name 'publisherName'
    PublisherUrl                 = Get-Install4jXmlAttribute -Element $GeneralNode -Name 'publisherURL'
    DefaultInstallationDirectory = Get-Install4jXmlAttribute -Element $GeneralNode -Name 'defaultInstallationDirectory'
    UninstallerFilename          = Get-Install4jXmlAttribute -Element $GeneralNode -Name 'uninstallerFilename'
    UninstallerDirectory         = Get-Install4jXmlAttribute -Element $GeneralNode -Name 'uninstallerDirectory'
    InstallerType                = Get-Install4jXmlAttribute -Element $GeneralNode -Name 'installerType'
    JreVersion                   = Get-Install4jXmlAttribute -Element $GeneralNode -Name 'jreVersion'
    MinimumJavaVersion           = Get-Install4jXmlAttribute -Element $GeneralNode -Name 'minJavaVersion'
    LzmaCompression              = ConvertTo-Install4jBoolean -Value (Get-Install4jXmlAttribute -Element $GeneralNode -Name 'lzmaCompression')
    Pack200Compression           = ConvertTo-Install4jBoolean -Value (Get-Install4jXmlAttribute -Element $GeneralNode -Name 'pack200Compression')
    AdminRequired                = ConvertTo-Install4jBoolean -Value (Get-Install4jXmlAttribute -Element $GeneralNode -Name 'adminRequired')
    PrivilegedInstallerRequest   = ConvertTo-Install4jBoolean -Value (Get-Install4jXmlAttribute -Element $GeneralNode -Name 'privilegedInstallerRequest')
  }

  $CompilerVariables = Get-Install4jCompilerVariableMap -Xml $Xml
  # Action classes are serialized Java beans. Read only deterministic properties from the known
  # registration, privilege, and file-association action types.
  $RegisterActionNode = @($Xml.SelectNodes("//*[@class='com.install4j.runtime.beans.actions.desktop.RegisterAddRemoveAction']")) | Select-Object -First 1
  $RequestPrivilegesNode = @($Xml.SelectNodes("//*[@class='com.install4j.runtime.beans.actions.misc.RequestPrivilegesAction']")) | Select-Object -First 1
  $RegisterItemName = if ($RegisterActionNode) { Get-Install4jXmlDecoderPropertyValue -ObjectNode $RegisterActionNode -Name 'itemName' } else { $null }
  $RegisterItemName = Expand-Install4jStaticText -Value $RegisterItemName -General $General -CompilerVariables $CompilerVariables

  $RequestPrivileges = if ($RequestPrivilegesNode) {
    # These defaults are constructor defaults in RequestPrivilegesAction.
    $PrivilegeDefaults = @{
      ObtainIfAdminWin            = $true
      ObtainIfNormalWin           = $false
      FailIfNotObtainedWin        = $true
      UpdateInstallationDirectory = $true
    }
    foreach ($Property in @($PrivilegeDefaults.Keys)) {
      $Value = Get-Install4jXmlDecoderPropertyValue -ObjectNode $RequestPrivilegesNode -Name ($Property.Substring(0, 1).ToLowerInvariant() + $Property.Substring(1))
      if ($null -ne $Value) { $PrivilegeDefaults[$Property] = [bool]$Value }
    }

    [pscustomobject]$PrivilegeDefaults
  }
  $FileAssociationActions = foreach ($ActionNode in @($Xml.SelectNodes("//*[@class='com.install4j.runtime.beans.actions.desktop.CreateFileAssociationAction']"))) {
    $Extension = Get-Install4jXmlDecoderPropertyValue -ObjectNode $ActionNode -Name 'extension'
    $Extension = Expand-Install4jStaticText -Value $Extension -General $General -CompilerVariables $CompilerVariables
    $Windows = ConvertTo-Install4jBoolean -Value (Get-Install4jXmlDecoderPropertyValue -ObjectNode $ActionNode -Name 'windows')
    $Selected = ConvertTo-Install4jBoolean -Value (Get-Install4jXmlDecoderPropertyValue -ObjectNode $ActionNode -Name 'selected')
    [pscustomobject]@{
      Extension   = $Extension
      Description = Expand-Install4jStaticText -Value (Get-Install4jXmlDecoderPropertyValue -ObjectNode $ActionNode -Name 'description') -General $General -CompilerVariables $CompilerVariables
      LauncherId  = Get-Install4jXmlDecoderPropertyValue -ObjectNode $ActionNode -Name 'launcherId'
      # XMLDecoder omits constructor defaults. CreateFileAssociationAction initializes both
      # properties to true, so absence is affirmative rather than unknown or false.
      Windows     = $null -eq $Windows ? $true : $Windows
      Selected    = $null -eq $Selected ? $true : $Selected
    }
  }
  if ($ConfigRoute -eq 'Legacy3Xml') {
    # install4j 3 stores associations as direct elements rather than XMLDecoder action beans.
    $FileAssociationActions = @($FileAssociationActions) + @(
      foreach ($AssociationNode in @($Xml.SelectNodes('/config/associations/association'))) {
        [pscustomobject]@{
          Extension   = Get-Install4jXmlAttribute -Element $AssociationNode -Name 'extension'
          Description = Get-Install4jXmlAttribute -Element $AssociationNode -Name 'description'
          LauncherId  = Get-Install4jXmlAttribute -Element $AssociationNode -Name 'launcher'
          Windows     = $true
          Selected    = ConvertTo-Install4jBoolean -Value (Get-Install4jXmlAttribute -Element $AssociationNode -Name 'selected')
        }
      }
    )
  }

  # Generation 3 creates uninstall registration as part of its built-in install phase; later
  # generations serialize RegisterAddRemoveAction explicitly.
  $HasRegisterAddRemoveAction = [bool]$RegisterActionNode
  if ($ConfigRoute -eq 'Legacy3Xml' -and -not [string]::IsNullOrWhiteSpace($General.ApplicationId) -and
    -not [string]::IsNullOrWhiteSpace($General.UninstallerFilename)) {
    $HasRegisterAddRemoveAction = $true
  }

  [pscustomobject]@{
    Source                       = $Source
    ConfigRoute                  = $ConfigRoute
    Install4jVersion             = Get-Install4jXmlAttribute -Element $Root -Name 'install4jVersion'
    Install4jBuild               = Get-Install4jXmlAttribute -Element $Root -Name 'install4jBuild'
    Type                         = Get-Install4jXmlAttribute -Element $Root -Name 'type'
    Archive                      = ConvertTo-Install4jBoolean -Value (Get-Install4jXmlAttribute -Element $Root -Name 'archive')
    Bitness                      = Get-Install4jXmlAttribute -Element $Root -Name 'bitness'
    General                      = [pscustomobject]$General
    CompilerVariables            = [pscustomobject]$CompilerVariables
    HasRegisterAddRemoveAction   = $HasRegisterAddRemoveAction
    RegisterAddRemoveItemName    = $RegisterItemName
    HasRequestPrivilegesAction   = [bool]$RequestPrivilegesNode
    RequestPrivileges            = $RequestPrivileges
    MsiProductId                 = $CompilerVariables['sys.msiProductId']
    DefaultInstallationDirectory = $General.DefaultInstallationDirectory
    PrivilegedInstallerRequest   = $General.PrivilegedInstallerRequest
    FileAssociationActions       = @($FileAssociationActions)
  }
}

function Get-Install4jAssociationInfo {
  <#
  .SYNOPSIS
    Read Windows file-association actions from install4j configuration XML
  .PARAMETER Config
    Parsed format configuration used to resolve static installer metadata and payload selection.
  #>
  [OutputType([pscustomobject])]
  param ([AllowNull()][psobject]$Config)

  $Warnings = [System.Collections.Generic.List[string]]::new()
  $Associations = [System.Collections.Generic.List[object]]::new()
  $SeenExtensions = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($Action in @($Config.FileAssociationActions)) {
    if ($Action.Windows -ne $true) { continue }
    $Extension = ([string]$Action.Extension).Trim().TrimStart('.')
    if ($Extension -notmatch '^[A-Za-z0-9][A-Za-z0-9._+-]{0,254}$') {
      if (-not [string]::IsNullOrWhiteSpace($Extension)) { $Warnings.Add("Ignored non-literal install4j file extension '$Extension'.") }
      continue
    }
    if (-not $SeenExtensions.Add($Extension)) { continue }
    $Associations.Add([pscustomobject]@{
        FileExtension       = $Extension.ToLowerInvariant()
        Extension           = ".$($Extension.ToLowerInvariant())"
        Description         = $Action.Description
        LauncherId          = $Action.LauncherId
        IsSelectedByDefault = $Action.Selected
        Source              = 'install4j CreateFileAssociationAction'
        Evidence            = $Action
      })
  }

  [pscustomobject]@{
    Protocols                 = @()
    FileExtensions            = @($Associations | Select-Object -ExpandProperty FileExtension -Unique | Sort-Object)
    ProtocolAssociations      = @()
    FileExtensionAssociations = @($Associations)
    Warnings                  = @($Warnings | Select-Object -Unique)
  }
}

function Get-Install4jRuntimeInfo {
  <#
  .SYNOPSIS
    Classify whether install4j media carries a private Java runtime.
  .PARAMETER Config
    Parsed i4jparams.conf evidence. general@jreVersion records the bundled runtime version,
    while general@minJavaVersion records the minimum runtime accepted by the application.
  .PARAMETER EmbeddedFiles
    Startup-file and content-table names recovered from the installer. Modern bundled media
    normally exposes the private runtime as jre.tar.gz.
  .PARAMETER HasMediaCatalog
    Indicates that EmbeddedFiles came from a parsed installer rather than a standalone config.
  .OUTPUTS
    Structured runtime classification, version, archive name, confidence, evidence, and warnings.
  #>
  [OutputType([pscustomobject])]
  param (
    [AllowNull()][psobject]$Config,
    [AllowNull()][string[]]$EmbeddedFiles,
    [bool]$HasMediaCatalog
  )

  $Evidence = [Collections.Generic.List[string]]::new()
  $Warnings = [Collections.Generic.List[string]]::new()
  $BundledVersion = if ($Config) { [string]$Config.General.JreVersion } else { $null }
  $MinimumVersion = if ($Config) { [string]$Config.General.MinimumJavaVersion } else { $null }
  $RuntimeArchive = @($EmbeddedFiles | Where-Object { $_ -in 'jre.tar.gz', 'jre.tar', 'jre.zip' }) | Select-Object -First 1

  if (-not [string]::IsNullOrWhiteSpace($BundledVersion)) {
    $HasBundledRuntime = $true
    $Evidence.Add("i4jparams.conf declares bundled Java runtime version '$BundledVersion'.")
    if ($RuntimeArchive) {
      $Evidence.Add("The installer startup-file catalog contains '$RuntimeArchive'.")
    } elseif ($HasMediaCatalog) {
      $Warnings.Add('i4jparams.conf declares a bundled Java runtime, but the parsed media catalog does not expose its runtime archive.')
    }
  } elseif ($RuntimeArchive) {
    $HasBundledRuntime = $true
    $Evidence.Add("The installer startup-file catalog contains '$RuntimeArchive'.")
    $Warnings.Add('The installer contains a Java runtime archive, but i4jparams.conf does not declare its version.')
  } elseif ($Config) {
    $HasBundledRuntime = $false
    $Evidence.Add('i4jparams.conf does not declare a bundled Java runtime.')
  } else {
    $HasBundledRuntime = $null
  }

  if (-not [string]::IsNullOrWhiteSpace($MinimumVersion)) {
    $Evidence.Add("i4jparams.conf requires Java $MinimumVersion or later when no private runtime is used.")
  }

  [pscustomobject]@{
    HasBundledRuntime     = $HasBundledRuntime
    BundledRuntimeVersion = [string]::IsNullOrWhiteSpace($BundledVersion) ? $null : $BundledVersion
    MinimumJavaVersion    = [string]::IsNullOrWhiteSpace($MinimumVersion) ? $null : $MinimumVersion
    RuntimeArchive        = $RuntimeArchive
    Confidence            = if ($Config -and ($RuntimeArchive -or $HasBundledRuntime -eq $false)) { 'high' } elseif ($Config -or $RuntimeArchive) { 'medium' } else { 'unknown' }
    Evidence              = [string[]]@($Evidence)
    Warnings              = [string[]]@($Warnings)
  }
}

function Read-Install4jLauncherString {
  <#
  .SYNOPSIS
    Read one bounded length-prefixed launcher parameter string
  .PARAMETER Stream
    Caller-owned binary stream. Sequential readers may advance its byte position; helpers do not dispose it.
  .PARAMETER Encoding
    String encoding evidence for the current fixed or variable-length record.
  .PARAMETER DataEnd
    Byte offset in the coordinate system named by this function: absolute file, PE/resource, overlay, or record relative.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][System.IO.Stream]$Stream,
    [Parameter(Mandatory)][System.Text.Encoding]$Encoding,
    [Parameter(Mandatory)][long]$DataEnd
  )

  $Length = Read-BinarySequentialInteger -Stream $Stream -Size 4 -Signed
  if ($Length -lt 0 -or $Length -gt $Script:Install4jMaximumParameterBytes -or $Stream.Position + $Length -gt $DataEnd) {
    throw "Invalid install4j launcher string length: $Length"
  }
  if ($Length -eq 0) { return '' }
  $Bytes = Read-BinaryBytes -Stream $Stream -Offset $Stream.Position -Count ([int]$Length)
  $Stream.Position += $Length
  return $Encoding.GetString($Bytes)
}

function Read-Install4jLauncherParameterMap {
  <#
  .SYNOPSIS
    Read a bounded install4j launcher parameter map
  .PARAMETER Stream
    Caller-owned binary stream. Sequential readers may advance its byte position; helpers do not dispose it.
  .PARAMETER Encoding
    String encoding evidence for the current fixed or variable-length record.
  .PARAMETER DataEnd
    Byte offset in the coordinate system named by this function: absolute file, PE/resource, overlay, or record relative.
  #>
  [OutputType([hashtable])]
  param (
    [Parameter(Mandatory)][System.IO.Stream]$Stream,
    [Parameter(Mandatory)][System.Text.Encoding]$Encoding,
    [Parameter(Mandatory)][long]$DataEnd
  )

  $Count = Read-BinarySequentialInteger -Stream $Stream -Size 4 -Signed
  if ($Count -lt 0 -or $Count -gt $Script:Install4jMaximumParameterCount) {
    throw "Invalid install4j launcher parameter count: $Count"
  }
  $Result = @{}
  for ($Index = 0; $Index -lt $Count; $Index++) {
    $Key = Read-BinarySequentialInteger -Stream $Stream -Size 4 -Signed
    $Result[$Key] = Read-Install4jLauncherString -Stream $Stream -Encoding $Encoding -DataEnd $DataEnd
  }
  return $Result
}

function Get-Install4jModernLauncherConfiguration {
  <#
  .SYNOPSIS
    Read a generation 5 or later install4j launcher parameter block and transformed startup files
  .DESCRIPTION
    install4j writes this block at the PE overlay start. The block is bounded by
    a declared byte count and CRC32. Parameter 2003 lists startup files in the
    same order as their following length-prefixed payloads.
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, ParameterSetName = 'Path')][string]$Path,
    [Parameter(Mandatory, ParameterSetName = 'Stream')][IO.Stream]$Stream
  )

  $OwnsStream = $PSCmdlet.ParameterSetName -eq 'Path'
  if ($OwnsStream) {
    $ResolvedPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
    $Stream = [IO.File]::Open($ResolvedPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  }
  $OriginalPosition = if ($Stream.CanSeek) { $Stream.Position } else { 0L }
  try {
    # The launcher's CRC-protected parameter block must begin exactly at the PE overlay boundary.
    $OverlayOffset = Get-PEOverlayOffset -Stream $Stream
    if ($OverlayOffset -le 0 -or $OverlayOffset + 24 -gt $Stream.Length) { throw 'The install4j launcher has no configuration overlay' }
    $Magic = Read-BinaryBytes -Stream $Stream -Offset $OverlayOffset -Count 4
    if (-not (Test-BinarySequence -Left $Magic -Right $Script:Install4jLauncherMagic)) {
      throw 'The PE overlay does not start with an install4j launcher configuration block'
    }

    $Stream.Position = $OverlayOffset + 4
    $Flags = Read-BinarySequentialInteger -Stream $Stream -Size 4
    $ExpectedCrc32 = Read-BinarySequentialInteger -Stream $Stream -Size 4
    $DataLength = Read-BinarySequentialInteger -Stream $Stream -Size 8 -Signed
    $DataStart = $Stream.Position
    if ($DataLength -le 0 -or $DataLength -gt $Script:Install4jMaximumExpandedBytes -or $DataStart + $DataLength -gt $Stream.Length) {
      throw "Invalid install4j launcher configuration length: $DataLength"
    }
    $DataEnd = $DataStart + $DataLength

    # install4j serializes ANSI, localized UTF-16, and named nested parameter maps in sequence.
    $AnsiParameters = Read-Install4jLauncherParameterMap -Stream $Stream -Encoding ([System.Text.Encoding]::UTF8) -DataEnd $DataEnd
    $LocalizedParameters = Read-Install4jLauncherParameterMap -Stream $Stream -Encoding ([System.Text.Encoding]::Unicode) -DataEnd $DataEnd
    $NestedCount = Read-BinarySequentialInteger -Stream $Stream -Size 4 -Signed
    if ($NestedCount -lt 0 -or $NestedCount -gt $Script:Install4jMaximumParameterCount) {
      throw "Invalid install4j nested parameter-map count: $NestedCount"
    }
    $NestedParameters = @{}
    for ($Index = 0; $Index -lt $NestedCount; $Index++) {
      $Name = Read-Install4jLauncherString -Stream $Stream -Encoding ([System.Text.Encoding]::UTF8) -DataEnd $DataEnd
      $NestedParameters[$Name] = Read-Install4jLauncherParameterMap -Stream $Stream -Encoding ([System.Text.Encoding]::Unicode) -DataEnd $DataEnd
    }

    # Parameter 2003 is the authoritative startup-file order; each following int64 length owns the
    # next XOR-transformed byte range.
    $Names = @(([string]$AnsiParameters[2003]).Split(';', [System.StringSplitOptions]::RemoveEmptyEntries))
    if ($Names.Count -le 0 -or $Names.Count -gt $Script:Install4jMaximumParameterCount) {
      throw 'The install4j launcher does not declare a bounded startup-file list'
    }
    $Entries = [System.Collections.Generic.List[psobject]]::new()
    foreach ($Name in $Names) {
      if ($Stream.Position + 8 -gt $DataEnd) { throw 'The install4j startup-file table is truncated' }
      $Length = Read-BinarySequentialInteger -Stream $Stream -Size 8 -Signed
      if ($Length -lt 0 -or $Length -gt $Script:Install4jMaximumExpandedBytes -or $Stream.Position + $Length -gt $DataEnd) {
        throw "Invalid install4j startup-file length for '$Name': $Length"
      }
      $Entries.Add([pscustomobject]@{
          Name         = $Name
          Offset       = [long]$Stream.Position
          Length       = [long]$Length
          Transform    = 'Xor88'
          TransformKey = $Script:Install4jLauncherTransformKey
        })
      $Stream.Position += $Length
    }

    # Authenticate the complete parameter-and-startup-file region before exposing any entry.
    $CrcStream = New-BoundedReadStream -Stream $Stream -Offset $DataStart -Length $DataLength -LeaveOpen
    try { $ActualCrc32 = Get-BinaryCrc32 -Stream $CrcStream -MaximumBytes $DataLength } finally { $CrcStream.Dispose() }
    if ($ActualCrc32 -ne $ExpectedCrc32) {
      throw ('The install4j launcher configuration CRC32 is invalid: expected {0:X8}, got {1:X8}' -f $ExpectedCrc32, $ActualCrc32)
    }

    return [pscustomobject]@{
      Route               = 'ModernOverlayV1'
      Marker              = [string]$AnsiParameters[2000]
      Offset              = [long]$OverlayOffset
      Flags               = [uint32]$Flags
      DataStart           = [long]$DataStart
      DataLength          = [long]$DataLength
      DataEnd             = [long]$DataEnd
      ExpectedCrc32       = [uint32]$ExpectedCrc32
      ActualCrc32         = [uint32]$ActualCrc32
      IsCrc32Valid        = $true
      AnsiParameters      = $AnsiParameters
      LocalizedParameters = $LocalizedParameters
      NestedParameters    = $NestedParameters
      Entries             = @($Entries)
      RemainingDataBytes  = [long]($DataEnd - $Stream.Position)
    }
  } finally {
    if ($OwnsStream) { $Stream.Dispose() } elseif ($Stream.CanSeek) { $Stream.Position = $OriginalPosition }
  }
}

function Get-Install4jLegacyLauncherConfiguration {
  <#
  .SYNOPSIS
    Read a generation 3 or 4 install4j PE-overlay parameter block.
  .DESCRIPTION
    Legacy launchers place the two parameter maps directly after the common
    D5 13 E4 E8 magic. Generation 3 prefixes each XOR-transformed startup file
    with an int32 length; generation 4 uses int64 lengths.
  .PARAMETER Path
    Path to the native Windows setup executable.
  .PARAMETER LengthSize
    Width in bytes of each little-endian startup-file length.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, ParameterSetName = 'Path')][string]$Path,
    [Parameter(Mandatory, ParameterSetName = 'Stream')][IO.Stream]$Stream,
    [Parameter(Mandatory)][ValidateSet(4, 8)][int]$LengthSize
  )

  $OwnsStream = $PSCmdlet.ParameterSetName -eq 'Path'
  if ($OwnsStream) {
    $ResolvedPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
    $Stream = [IO.File]::Open($ResolvedPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  }
  $OriginalPosition = if ($Stream.CanSeek) { $Stream.Position } else { 0L }
  try {
    $OverlayOffset = Get-PEOverlayOffset -Stream $Stream
    if ($OverlayOffset -le 0 -or $OverlayOffset + 12 -gt $Stream.Length) {
      throw 'The install4j launcher has no bounded legacy configuration overlay'
    }
    $Magic = Read-BinaryBytes -Stream $Stream -Offset $OverlayOffset -Count 4
    if (-not (Test-BinarySequence -Left $Magic -Right $Script:Install4jLauncherMagic)) {
      throw 'The PE overlay does not start with the install4j launcher magic'
    }

    $Stream.Position = $OverlayOffset + 4
    $AnsiParameters = Read-Install4jLauncherParameterMap -Stream $Stream -Encoding ([Text.Encoding]::UTF8) -DataEnd $Stream.Length
    $LocalizedParameters = Read-Install4jLauncherParameterMap -Stream $Stream -Encoding ([Text.Encoding]::Unicode) -DataEnd $Stream.Length
    $Marker = [string]$AnsiParameters[2000]
    $Names = @(([string]$AnsiParameters[2003]).Split(';', [StringSplitOptions]::RemoveEmptyEntries))
    if ([string]::IsNullOrWhiteSpace($Marker) -or $Names.Count -le 0 -or $Names.Count -gt $Script:Install4jMaximumParameterCount) {
      throw 'The legacy install4j launcher does not contain the required marker and startup-file list'
    }

    $Entries = [Collections.Generic.List[psobject]]::new()
    foreach ($Name in $Names) {
      if ($Stream.Position + $LengthSize -gt $Stream.Length) { throw 'The legacy install4j startup-file table is truncated' }
      $Length = [long](Read-BinarySequentialInteger -Stream $Stream -Size $LengthSize -Signed)
      if ($Length -lt 0 -or $Length -gt $Script:Install4jMaximumExpandedBytes -or $Stream.Position + $Length -gt $Stream.Length) {
        throw "Invalid legacy install4j startup-file length for '$Name': $Length"
      }
      $Entries.Add([pscustomobject]@{
          Name         = $Name
          Offset       = [long]$Stream.Position
          Length       = $Length
          Transform    = 'Xor88'
          TransformKey = $Script:Install4jLauncherTransformKey
        })
      $Stream.Position += $Length
    }

    [pscustomobject]@{
      Route               = "LegacyParameterBlock$($LengthSize * 8)"
      Marker              = $Marker
      Offset              = [long]$OverlayOffset
      Flags               = $null
      DataStart           = [long]($OverlayOffset + 4)
      DataLength          = [long]($Stream.Position - ($OverlayOffset + 4))
      DataEnd             = [long]$Stream.Position
      ExpectedCrc32       = $null
      ActualCrc32         = $null
      IsCrc32Valid        = $null
      AnsiParameters      = $AnsiParameters
      LocalizedParameters = $LocalizedParameters
      NestedParameters    = @{}
      Entries             = @($Entries)
      RemainingDataBytes  = [long]($Stream.Length - $Stream.Position)
    }
  } finally {
    if ($OwnsStream) { $Stream.Dispose() } elseif ($Stream.CanSeek) { $Stream.Position = $OriginalPosition }
  }
}

function Resolve-Install4jFormatDescriptor {
  <#
  .SYNOPSIS
    Resolve one immutable catalog descriptor from validated launcher evidence.
  .PARAMETER Marker
    Parameter 2000 from a structurally parsed launcher map.
  .PARAMETER LauncherRoute
    Route that fully consumed the launcher parameter and startup-file records.
  .PARAMETER AllowFutureFallback
    Permit the nearest compatible modern descriptor after strict structural validation.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Marker,
    [Parameter(Mandatory)][string]$LauncherRoute,
    [switch]$AllowFutureFallback
  )

  $CatalogMatches = @($Script:Install4jFormats | Where-Object {
      $_.LauncherRoute -eq $LauncherRoute -and $Marker -match $_.MarkerPattern
    })
  if ($CatalogMatches.Count -eq 1) {
    $Descriptor = $CatalogMatches[0].PSObject.Copy()
    $Descriptor | Add-Member -NotePropertyName IsFallback -NotePropertyValue $false
    return $Descriptor
  }
  if ($CatalogMatches.Count -gt 1) { throw "The install4j marker '$Marker' ambiguously matches multiple catalog descriptors" }

  $FutureMatch = [regex]::Match($Marker, '^[LS]-M(?<Generation>\d+)-[A-Za-z0-9_]+#[0-9]+-$')
  if ($AllowFutureFallback -and $LauncherRoute -eq 'ModernOverlayV1' -and $FutureMatch.Success) {
    $Generation = [int]$FutureMatch.Groups['Generation'].Value
    $Latest = $Script:Install4jFormats | Where-Object LauncherRoute -EQ 'ModernOverlayV1' | Sort-Object Generation -Descending | Select-Object -First 1
    if ($Generation -gt $Latest.Generation) {
      $Descriptor = $Latest.PSObject.Copy()
      $Descriptor.Id = "install4j-$Generation-fallback"
      $Descriptor.Generation = $Generation
      $Descriptor.MarkerPattern = "^[LS]-M$Generation-[A-Za-z0-9_]+#[0-9]+-$"
      $Descriptor | Add-Member -NotePropertyName IsFallback -NotePropertyValue $true
      return $Descriptor
    }
  }
}

function Get-Install4jLauncherProbe {
  <#
  .SYNOPSIS
    Select exactly one catalog-compatible launcher route for a native setup executable.
  .PARAMETER Path
    Path to the native Windows setup executable.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, ParameterSetName = 'Path')][string]$Path,
    [Parameter(Mandatory, ParameterSetName = 'Stream')][IO.Stream]$Stream
  )

  $OwnsStream = $PSCmdlet.ParameterSetName -eq 'Path'
  if ($OwnsStream) {
    $ResolvedPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
    $Stream = [IO.File]::Open($ResolvedPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  }
  $Candidates = [Collections.Generic.List[psobject]]::new()
  try {
    foreach ($Probe in @(
        [pscustomobject]@{ Route = 'ModernOverlayV1'; LengthSize = 0 },
        [pscustomobject]@{ Route = 'LegacyParameterBlock32'; LengthSize = 4 },
        [pscustomobject]@{ Route = 'LegacyParameterBlock64'; LengthSize = 8 }
      )) {
      try {
        $Handler = $Script:Install4jLauncherHandlers[$Probe.Route]
        $Launcher = if ($Probe.LengthSize) { & $Handler -Stream $Stream -LengthSize $Probe.LengthSize } else { & $Handler -Stream $Stream }
        $Descriptor = if (-not [string]::IsNullOrWhiteSpace([string]$Launcher.Marker)) {
          Resolve-Install4jFormatDescriptor -Marker $Launcher.Marker -LauncherRoute $Probe.Route -AllowFutureFallback
        } else {
          $null
        }
        # Generated application media does not always serialize parameter 2000. Retain a fully
        # consumed modern launcher when it carries a bounded configuration startup file; the
        # decoded configuration may select a same-route descriptor later in the analysis.
        $CanResolveFromConfiguration = $Probe.Route -eq 'ModernOverlayV1' -and
        $Launcher.IsCrc32Valid -eq $true -and $Launcher.RemainingDataBytes -eq 0 -and
        @($Launcher.Entries | Where-Object Name -IEQ 'i4jparams.conf').Count -eq 1
        if ($Descriptor -or $Launcher.Marker -match '^[LS]-[A-Za-z0-9_-]+#[0-9]+-$' -or $CanResolveFromConfiguration) {
          $Candidates.Add([pscustomobject]@{ Launcher = $Launcher; Descriptor = $Descriptor })
        }
      } catch {
        # A route probe is speculative. Only a complete, catalog-compatible parse becomes evidence.
      }
    }
  } finally {
    if ($OwnsStream) { $Stream.Dispose() }
  }

  if ($Candidates.Count -eq 0) { return }
  if ($Candidates.Count -gt 1) { throw 'The install4j launcher matches multiple incompatible structural routes' }
  return $Candidates[0]
}

function Read-Install4jLauncherFile {
  <#
  .SYNOPSIS
    Read and decode a bounded install4j launcher startup file
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER Entry
    Validated archive or catalog entry whose bounded content is read or exported.
  .PARAMETER MaximumBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  [OutputType([byte[]])]
  param (
    [Parameter(Mandatory, ParameterSetName = 'Path')][string]$Path,
    [Parameter(Mandatory, ParameterSetName = 'Stream')][IO.Stream]$Stream,
    [Parameter(Mandatory)][psobject]$Entry,
    [ValidateRange(1, [int]::MaxValue)][int]$MaximumBytes = $Script:Install4jMaximumConfigBytes
  )

  if ($Entry.Length -gt $MaximumBytes) { throw "The install4j startup file '$($Entry.Name)' is too large to read safely" }
  $OwnsStream = $PSCmdlet.ParameterSetName -eq 'Path'
  if ($OwnsStream) {
    $ResolvedPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
    $Stream = [IO.File]::Open($ResolvedPath, 'Open', 'Read', 'ReadWrite')
  }
  $OriginalPosition = if ($Stream.CanSeek) { $Stream.Position } else { 0L }
  $Destination = [System.IO.MemoryStream]::new([int]$Entry.Length)
  try {
    $Stream.Position = $Entry.Offset
    $null = Copy-BinaryXorStream -Source $Stream -Destination $Destination -Key ([byte]$Entry.TransformKey) -ExpectedBytes $Entry.Length
    return , ($Destination.ToArray())
  } finally {
    $Destination.Dispose()
    if ($OwnsStream) { $Stream.Dispose() } elseif ($Stream.CanSeek) { $Stream.Position = $OriginalPosition }
  }
}

function ConvertFrom-Install4jModifiedUtf8 {
  <#
  .SYNOPSIS
    Decode one Java DataInput modified-UTF8 string.
  .PARAMETER Bytes
    Exact byte payload following the unsigned big-endian length field.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][byte[]]$Bytes)

  $Characters = [Collections.Generic.List[char]]::new()
  for ($Index = 0; $Index -lt $Bytes.Length; ) {
    $First = $Bytes[$Index++]
    if (($First -band 0x80) -eq 0) {
      if ($First -eq 0) { throw 'A modified-UTF8 string contains an unencoded null byte' }
      $Characters.Add([char]$First)
      continue
    }
    if (($First -band 0xE0) -eq 0xC0) {
      if ($Index -ge $Bytes.Length) { throw 'A modified-UTF8 two-byte sequence is truncated' }
      $Second = $Bytes[$Index++]
      if (($Second -band 0xC0) -ne 0x80) { throw 'A modified-UTF8 continuation byte is invalid' }
      $Characters.Add([char]((($First -band 0x1F) -shl 6) -bor ($Second -band 0x3F)))
      continue
    }
    if (($First -band 0xF0) -eq 0xE0) {
      if ($Index + 1 -ge $Bytes.Length) { throw 'A modified-UTF8 three-byte sequence is truncated' }
      $Second = $Bytes[$Index++]
      $Third = $Bytes[$Index++]
      if (($Second -band 0xC0) -ne 0x80 -or ($Third -band 0xC0) -ne 0x80) { throw 'A modified-UTF8 continuation byte is invalid' }
      $Characters.Add([char]((($First -band 0x0F) -shl 12) -bor (($Second -band 0x3F) -shl 6) -bor ($Third -band 0x3F)))
      continue
    }
    throw 'A modified-UTF8 leading byte is invalid'
  }
  return -join $Characters
}

function Get-Install4jNoEmbeddedFileTable {
  <#
  .SYNOPSIS
    Represent the generation-3 route that has no ContentCollector table.
  .PARAMETER Stream
    Caller-owned stream, unused by this route.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][IO.Stream]$Stream)
  $null = $Stream
  return @()
}

function Get-Install4jEmbeddedFileTable {
  <#
  .SYNOPSIS
    Read install4j unextracted-file tables from an installer launcher
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory, ParameterSetName = 'Path', HelpMessage = 'The path to the installer')][string]$Path,
    [Parameter(Mandatory, ParameterSetName = 'Stream', HelpMessage = 'Caller-owned seekable installer stream')][IO.Stream]$Stream
  )

  $OwnsStream = $PSCmdlet.ParameterSetName -eq 'Path'
  if ($OwnsStream) {
    $ResolvedPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
    $Stream = [IO.File]::Open($ResolvedPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  }
  $OriginalPosition = if ($Stream.CanSeek) { $Stream.Position } else { 0L }
  try {
    # Marker bytes can occur in payloads, so accept a table only when all BE names, lengths, and the
    # contiguous payload extent remain inside the installer.
    foreach ($Offset in Find-BinaryPattern -Stream $Stream -Pattern $Script:Install4jUnextractedMagic -Maximum 16) {
      try {
        $Stream.Position = $Offset
        if ((Read-BinarySequentialInteger -Stream $Stream -Size 4 -Endian BigEndian -Signed) -ne -387705899) { continue }
        $Count = Read-BinarySequentialInteger -Stream $Stream -Size 4 -Endian BigEndian -Signed
        if ($Count -le 0 -or $Count -gt 4096) { continue }

        $Entries = [System.Collections.Generic.List[psobject]]::new()
        $PayloadRelativeOffset = [long]0
        for ($Index = 0; $Index -lt $Count; $Index++) {
          $NameLength = [int](Read-BinarySequentialInteger -Stream $Stream -Size 2 -Endian BigEndian)
          if ($NameLength -le 0 -or $NameLength -gt 32767) { throw 'Invalid install4j embedded file name length' }

          $NameBytes = [byte[]]::new($NameLength)
          if ($Stream.Read($NameBytes, 0, $NameLength) -ne $NameLength) { throw 'Unexpected end of file while reading install4j embedded file name' }
          $Name = ConvertFrom-Install4jModifiedUtf8 -Bytes $NameBytes
          $Length = Read-BinarySequentialInteger -Stream $Stream -Size 8 -Endian BigEndian -Signed
          if ($Length -lt 0 -or $Length -gt $Stream.Length) { throw 'Invalid install4j embedded file length' }

          $Entries.Add([pscustomobject]@{
              Name                  = $Name
              Length                = $Length
              PayloadRelativeOffset = $PayloadRelativeOffset
              Offset                = [long]0
            })
          $PayloadRelativeOffset += $Length
        }

        # Payload bytes immediately follow the complete catalog in catalog order.
        $PayloadStart = $Stream.Position
        foreach ($Entry in $Entries) {
          $Entry.Offset = $PayloadStart + $Entry.PayloadRelativeOffset
          if ($Entry.Offset + $Entry.Length -gt $Stream.Length) { throw 'install4j embedded file entry exceeds the file length' }
        }

        [pscustomobject]@{
          Offset       = $Offset
          PayloadStart = $PayloadStart
          Count        = $Count
          Entries      = @($Entries)
        }
      } catch {
        # Continue after false-positive marker candidates; no partial table is returned.
        continue
      }
    }
  } finally {
    if ($OwnsStream) { $Stream.Dispose() } elseif ($Stream.CanSeek) { $Stream.Position = $OriginalPosition }
  }
}

function Read-Install4jEmbeddedFile {
  <#
  .SYNOPSIS
    Read a small direct embedded file from the install4j unextracted table
  #>
  [OutputType([byte[]])]
  param (
    [Parameter(Mandatory, ParameterSetName = 'Path', HelpMessage = 'The path to the installer')][string]$Path,
    [Parameter(Mandatory, ParameterSetName = 'Stream', HelpMessage = 'Caller-owned seekable installer stream')][IO.Stream]$Stream,

    [Parameter(Mandatory, HelpMessage = 'The embedded file table entry')]
    [psobject]$Entry,

    [Parameter(HelpMessage = 'The maximum number of bytes to read')]
    [int]$MaximumBytes = $Script:Install4jMaximumConfigBytes
  )

  if ($Entry.Length -gt $MaximumBytes) { throw "The install4j embedded file '$($Entry.Name)' is too large to read safely" }

  $OwnsStream = $PSCmdlet.ParameterSetName -eq 'Path'
  if ($OwnsStream) {
    $ResolvedPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
    $Stream = [IO.File]::Open($ResolvedPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  }
  $OriginalPosition = if ($Stream.CanSeek) { $Stream.Position } else { 0L }
  try {
    return , (Read-BinaryBytes -Stream $Stream -Offset $Entry.Offset -Count ([int]$Entry.Length))
  } finally {
    if ($OwnsStream) { $Stream.Dispose() } elseif ($Stream.CanSeek) { $Stream.Position = $OriginalPosition }
  }
}

function Expand-Install4jInlineContentArchive {
  <#
  .SYNOPSIS
    Decode and selectively extract a generation-3 inline content.zip startup file.
  .PARAMETER Path
    Path to the install4j setup executable.
  .PARAMETER Entry
    Validated XOR-transformed content.zip startup-file entry.
  .PARAMETER DestinationPath
    Validated extraction root.
  .PARAMETER Name
    Wildcard selector applied to archive entry paths.
  .PARAMETER CollisionAction
    Output collision policy.
  .PARAMETER MaximumExpandedBytes
    Aggregate archive output limit in bytes.
  #>
  [OutputType([IO.FileInfo[]])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][psobject]$Entry,
    [Parameter(Mandatory)][string]$DestinationPath,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction,
    [Parameter(Mandatory)][long]$MaximumExpandedBytes
  )

  if ($Entry.Length -gt $MaximumExpandedBytes) {
    throw "The inline install4j content archive exceeds the $MaximumExpandedBytes-byte limit"
  }
  $DecodedArchivePath = New-TempFile
  $Source = [IO.File]::Open((Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf), 'Open', 'Read', 'ReadWrite')
  $Destination = [IO.File]::Open($DecodedArchivePath, 'Create', 'Write', 'Read')
  try {
    $Source.Position = $Entry.Offset
    $null = Copy-BinaryXorStream -Source $Source -Destination $Destination -Key ([byte]$Entry.TransformKey) -ExpectedBytes $Entry.Length
  } finally {
    $Destination.Dispose()
    $Source.Dispose()
  }
  try {
    $Archive = Get-InstallerArchive -Path $DecodedArchivePath
    try {
      $Result = Export-InstallerArchiveSelection -Archive $Archive -DestinationPath $DestinationPath -Name $Name `
        -CollisionAction $CollisionAction -MaximumExpandedBytes $MaximumExpandedBytes -MaximumEntries $Script:Install4jMaximumArchiveEntries
      return $Result.Files
    } finally {
      $Archive.Dispose()
    }
  } finally {
    Remove-Item -LiteralPath $DecodedArchivePath -Force -ErrorAction SilentlyContinue
  }
}

function Expand-Install4jLzmaArchiveEntry {
  <#
  .SYNOPSIS
    Decode and extract an install4j LZMA-alone ZIP content entry.
  #>
  [OutputType([System.IO.FileInfo[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the install4j installer')]
    [string]$Path,

    [Parameter(Mandatory, HelpMessage = 'The 0.dat or generation-4 .000 embedded-file table entry')]
    [psobject]$Entry,

    [Parameter(Mandatory, HelpMessage = 'The extraction destination directory')]
    [string]$DestinationPath,

    [Parameter(Mandatory, HelpMessage = 'The file name or wildcard pattern')]
    [string]$Name,

    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')]
    [string]$CollisionAction = 'Rename',

    [Parameter(Mandatory, HelpMessage = 'The maximum total number of expanded bytes')]
    [long]$MaximumExpandedBytes
  )

  Import-InstallerArchiveDependency

  if ($Entry.Length -lt 14) { throw 'The install4j LZMA-alone content stream is truncated' }
  $SourceStream = [System.IO.File]::Open((Get-Item -Path $Path -Force).FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
  $DecodedArchivePath = New-TempFile
  try {
    # 0.dat is an LZMA-alone stream whose expanded bytes form a seekable ZIP archive.
    $SourceStream.Position = $Entry.Offset
    $Header = [byte[]]::new(13)
    if ($SourceStream.Read($Header, 0, $Header.Length) -ne $Header.Length) {
      throw 'The install4j LZMA-alone header is truncated'
    }

    if ($Header[0] -gt 224) { throw "The install4j LZMA properties byte is invalid: $($Header[0])" }
    $DictionarySize = [System.BitConverter]::ToUInt32($Header, 1)
    if ($DictionarySize -gt $Script:Install4jMaximumDictionaryBytes) {
      throw "The install4j LZMA dictionary is too large: $DictionarySize bytes"
    }

    $DeclaredSize = [System.BitConverter]::ToInt64($Header, 5)
    if ($DeclaredSize -lt 0) { throw 'The install4j LZMA stream does not declare a bounded output size' }
    if ($DeclaredSize -gt $MaximumExpandedBytes) {
      throw "The install4j LZMA stream expands to $DeclaredSize bytes, exceeding the $MaximumExpandedBytes-byte limit"
    }

    $Properties = [byte[]]$Header[0..4]
    $CompressedRange = New-BoundedReadStream -Stream $SourceStream -Offset ($Entry.Offset + $Header.Length) -Length ($Entry.Length - $Header.Length) -LeaveOpen
    $DecodedStream = [System.IO.File]::Open($DecodedArchivePath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::Read)
    try {
      $null = Expand-InstallerCompressedStream -Algorithm Lzma -Stream $CompressedRange -Destination $DecodedStream -MaximumBytes $MaximumExpandedBytes -Properties $Properties -CompressedSize ($Entry.Length - $Header.Length) -UncompressedSize $DeclaredSize
    } finally {
      $DecodedStream.Dispose()
      $CompressedRange.Dispose()
    }

    # Materialize only the decoded archive because SharpCompress requires random access; the
    # original installer remains streamed and bounded.
    $Archive = Get-InstallerArchive -Path $DecodedArchivePath
    try {
      $Result = Export-InstallerArchiveSelection -Archive $Archive -DestinationPath $DestinationPath -Name $Name `
        -CollisionAction $CollisionAction -MaximumExpandedBytes $MaximumExpandedBytes -MaximumEntries $Script:Install4jMaximumArchiveEntries
      return $Result.Files
    } finally {
      $Archive.Dispose()
    }
  } finally {
    $SourceStream.Dispose()
    Remove-Item -Path $DecodedArchivePath -Force -ErrorAction SilentlyContinue
  }
}

function Get-Install4jEmbeddedFilesFromText {
  <#
  .SYNOPSIS
    Recover install4j file-list names from the launcher configuration block
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The scanned text')]
    [string]$Text
  )

  $Lists = [System.Collections.Generic.List[string]]::new()
  $SearchStart = 0
  while (($Index = $Text.IndexOf('i4jparams.conf', $SearchStart, [StringComparison]::OrdinalIgnoreCase)) -ge 0) {
    $Start = [Math]::Max(0, $Index - 4096)
    $Length = [Math]::Min(65536, $Text.Length - $Start)
    $Window = $Text.Substring($Start, $Length)
    foreach ($Match in [regex]::Matches($Window, '(?:[A-Za-z0-9_@+\-./\\]+;){2,}[A-Za-z0-9_@+\-./\\]+')) {
      if ($Match.Value.IndexOf('i4jparams.conf', [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        foreach ($Name in $Match.Value -split ';') { if (-not [string]::IsNullOrWhiteSpace($Name)) { $Lists.Add($Name) } }
      }
    }
    $SearchStart = $Index + 'i4jparams.conf'.Length
  }

  $SearchStart = 0
  while ($Lists.Count -eq 0 -and ($Index = $Text.IndexOf('i4jruntime.jar', $SearchStart, [StringComparison]::OrdinalIgnoreCase)) -ge 0) {
    $Start = [Math]::Max(0, $Index - 4096)
    $Length = [Math]::Min(65536, $Text.Length - $Start)
    $Window = $Text.Substring($Start, $Length)
    foreach ($Match in [regex]::Matches($Window, '(?:[A-Za-z0-9_@+\-./\\]+;){2,}[A-Za-z0-9_@+\-./\\]+')) {
      if ($Match.Value.IndexOf('i4jruntime.jar', [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        foreach ($Name in $Match.Value -split ';') { if (-not [string]::IsNullOrWhiteSpace($Name)) { $Lists.Add($Name) } }
      }
    }
    $SearchStart = $Index + 'i4jruntime.jar'.Length
  }

  @($Lists | Select-Object -Unique)
}

function Get-Install4jApplicationIdFromText {
  <#
  .SYNOPSIS
    Recover the install4j application ID from launcher strings
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The scanned text')]
    [string]$Text
  )

  $AllInstallDirsMatch = [regex]::Match($Text, "allinstdirs$Script:Install4jApplicationIdPattern")
  if ($AllInstallDirsMatch.Success) { return $AllInstallDirsMatch.Groups['ApplicationId'].Value }

  $ApplicationIdMatch = [regex]::Match($Text, "applicationId\s*=\s*`"$Script:Install4jApplicationIdPattern`"")
  if ($ApplicationIdMatch.Success) { return $ApplicationIdMatch.Groups['ApplicationId'].Value }
}

function Get-Install4jArchitecture {
  <#
  .SYNOPSIS
    Infer the WinGet architecture from install4j config bitness or PE machine type
  #>
  [OutputType([string])]
  param (
    [Parameter(HelpMessage = 'The parsed install4j config')]
    [AllowNull()]
    [psobject]$Config,

    [Parameter(Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path
  )

  # ARM64 setup launchers can still encode generic 64-bit configuration data, so a native ARM64
  # PE machine is decisive before interpreting the configuration's less-specific bitness value.
  $Layout = if ((Get-Command -Name Get-PELayout -ErrorAction SilentlyContinue)) {
    try { Get-PELayout -Path $Path } catch { $null }
  }
  if ($Layout.MachineName -eq 'ARM64') { return 'arm64' }

  if ($Config -and $Config.Bitness) {
    switch ([string]$Config.Bitness) {
      '32' { return 'x86' }
      '64' { return 'x64' }
      'arm64' { return 'arm64' }
      'aarch64' { return 'arm64' }
    }
  }

  if ($Layout) {
    switch ($Layout.MachineName) {
      'I386' { return 'x86' }
      'AMD64' { return 'x64' }
    }
  }
}

function Get-Install4jFirstValue {
  <#
  .SYNOPSIS
    Return the first non-empty value from a list
  #>
  [OutputType([object])]
  param (
    [Parameter(ValueFromRemainingArguments, HelpMessage = 'The values to check')]
    [AllowNull()]
    [object[]]$Value
  )

  foreach ($Item in $Value) {
    if ($null -ne $Item -and -not [string]::IsNullOrWhiteSpace([string]$Item)) { return $Item }
  }
}

function Get-Install4jScopeInfo {
  <#
  .SYNOPSIS
    Infer install4j ARP scope behavior from privilege-request evidence
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(HelpMessage = 'The parsed install4j config')]
    [AllowNull()]
    [psobject]$Config
  )

  if (-not $Config -or -not $Config.HasRegisterAddRemoveAction) {
    return [pscustomobject]@{
      Scope             = $null
      DefaultScope      = $null
      SupportedScopes   = @()
      SupportsDualScope = $false
      Confidence        = 'unknown'
      Evidence          = @('RegisterAddRemoveAction was not available from parsed config XML.')
    }
  }

  $Evidence = [System.Collections.Generic.List[string]]::new()
  $Evidence.Add('RegisterAddRemoveAction creates the uninstall key under HKLM when writable, otherwise HKCU.')

  if ($Config.ConfigRoute -eq 'Legacy3Xml') {
    $Evidence.Add("Legacy general configuration: adminRequired=$($Config.General.AdminRequired).")
    if ($Config.General.AdminRequired -eq $true) {
      return [pscustomobject]@{
        Scope             = 'machine'
        DefaultScope      = 'machine'
        SupportedScopes   = @('machine')
        SupportsDualScope = $false
        Confidence        = 'medium'
        Evidence          = @($Evidence)
      }
    }
    return [pscustomobject]@{
      Scope             = $null
      DefaultScope      = $null
      SupportedScopes   = @('user', 'machine')
      SupportsDualScope = $true
      Confidence        = 'medium'
      Evidence          = @($Evidence)
    }
  }

  if ($Config.HasRequestPrivilegesAction) {
    # These action flags model elevation attempts and failure behavior. They can prove machine-only
    # behavior or elevation-dependent dual scope, but not a WinGet-selectable scope switch.
    $Request = $Config.RequestPrivileges
    $Evidence.Add("RequestPrivilegesAction: obtainIfAdminWin=$($Request.ObtainIfAdminWin), obtainIfNormalWin=$($Request.ObtainIfNormalWin), failIfNotObtainedWin=$($Request.FailIfNotObtainedWin), updateInstallationDirectory=$($Request.UpdateInstallationDirectory).")

    if ($Request.ObtainIfNormalWin -and $Request.FailIfNotObtainedWin) {
      return [pscustomobject]@{
        Scope             = 'machine'
        DefaultScope      = 'machine'
        SupportedScopes   = @('machine')
        SupportsDualScope = $false
        Confidence        = 'medium'
        Evidence          = @($Evidence)
      }
    }

    if ($Request.ObtainIfAdminWin) {
      return [pscustomobject]@{
        Scope             = 'machine'
        DefaultScope      = 'machine'
        SupportedScopes   = @('user', 'machine')
        SupportsDualScope = $true
        Confidence        = 'medium'
        Evidence          = @($Evidence)
      }
    }
  }

  if ($Config.PrivilegedInstallerRequest) {
    $Evidence.Add('privilegedInstallerRequest is true in the general install4j config.')
    return [pscustomobject]@{
      Scope             = 'machine'
      DefaultScope      = 'machine'
      SupportedScopes   = @('user', 'machine')
      SupportsDualScope = $true
      Confidence        = 'low'
      Evidence          = @($Evidence)
    }
  }

  [pscustomobject]@{
    Scope             = $null
    DefaultScope      = $null
    SupportedScopes   = @('user', 'machine')
    SupportsDualScope = $true
    Confidence        = 'low'
    Evidence          = @($Evidence)
  }
}

function Get-Install4jRegistryWrite {
  <#
  .SYNOPSIS
    Build expected install4j Apps and Features registry writes from config evidence
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The parsed install4j info object')]
    [psobject]$Info
  )

  if (-not $Info.WritesAppsAndFeaturesEntry -or [string]::IsNullOrWhiteSpace($Info.ProductCode)) { return }

  $Key = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($Info.ProductCode)"
  $Values = [ordered]@{
    DisplayName     = $Info.DisplayName
    DisplayVersion  = $Info.DisplayVersion
    Publisher       = $Info.Publisher
    URLInfoAbout    = $Info.PublisherUrl
    InstallLocation = $Info.DefaultInstallLocation
    UninstallString = if ($Info.UninstallerFilename) { "<InstallLocation>\$($Info.UninstallerFilename).exe" } else { $null }
  }

  foreach ($Name in $Values.Keys) {
    if ([string]::IsNullOrWhiteSpace([string]$Values[$Name])) { continue }
    [pscustomobject]@{
      Root  = 'HKLM-or-HKCU'
      Key   = $Key
      Name  = $Name
      Type  = 'REG_SZ'
      Value = $Values[$Name]
    }
  }
}

function Get-Install4jExplicitVersion {
  <#
  .SYNOPSIS
    Normalize a builder version or build explicitly encoded in configuration XML.
  .PARAMETER Value
    Raw install4jVersion or install4jBuild attribute value.
  #>
  [OutputType([string])]
  param ([AllowNull()][object]$Value)

  $Text = [string]$Value
  if ([string]::IsNullOrWhiteSpace($Text) -or $Text -match '^@.+@$') { return }
  if ($Text -notmatch '^\d+(?:\.\d+)*$') { return }
  return $Text
}

function Get-Install4jDescriptorFromConfig {
  <#
  .SYNOPSIS
    Resolve a catalog descriptor from explicit i4jparams.conf structure.
  .PARAMETER Config
    Parsed install4j configuration object.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][psobject]$Config)

  $Generation = if ($Config.ConfigRoute -eq 'Legacy3Xml') {
    3
  } else {
    $Version = Get-Install4jExplicitVersion -Value $Config.Install4jVersion
    if ($Version) { [int]($Version -split '\.')[0] }
  }
  if (-not $Generation) { return }
  $CatalogEntry = $Script:Install4jFormats | Where-Object Generation -EQ $Generation | Select-Object -First 1
  if (-not $CatalogEntry) { return }
  $Descriptor = $CatalogEntry.PSObject.Copy()
  $Descriptor | Add-Member -NotePropertyName IsFallback -NotePropertyValue $false
  return $Descriptor
}

function Get-Install4jAnalysisContext {
  <#
  .SYNOPSIS
    Parse one install4j source once and retain all route, table, and configuration evidence.
  .PARAMETER Path
    Path to a native Windows setup executable or extracted i4jparams.conf.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)

  $ResolvedPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
  $File = Get-Item -LiteralPath $ResolvedPath -Force
  $Warnings = [Collections.Generic.List[string]]::new()
  $Evidence = [Collections.Generic.List[string]]::new()
  $VersionInfo = Get-Install4jVersionInfo -File $File
  $Launcher = $null
  $Descriptor = $null
  $Config = $null
  $ScanText = $null
  $EmbeddedFileTables = @()
  $EmbeddedFiles = [Collections.Generic.List[string]]::new()
  $MediaType = 'Unknown'

  $Stream = [IO.File]::Open($ResolvedPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    # A standalone configuration file is accepted through XML structure, not its filename.
    if ($Stream.Length -le $Script:Install4jMaximumConfigBytes) {
      $Bytes = Read-BinaryBytes -Stream $Stream -Offset 0 -Count ([int]$Stream.Length)
      $CandidateText = [Text.Encoding]::UTF8.GetString($Bytes).TrimStart([char]0xFEFF, [char]0x0000, [char]0x0020, [char]0x0009, [char]0x000D, [char]0x000A)
      if ($CandidateText.StartsWith('<?xml', [StringComparison]::OrdinalIgnoreCase) -or
        $CandidateText.StartsWith('<config', [StringComparison]::OrdinalIgnoreCase)) {
        try {
          $Config = ConvertFrom-Install4jConfigXml -Content $CandidateText -Source 'ConfigurationFile'
          $Descriptor = Get-Install4jDescriptorFromConfig -Config $Config
          $MediaType = 'Configuration'
          $Evidence.Add('A complete install4j configuration XML document was parsed.')
        } catch {
          $Config = $null
        }
      }
    }

    if (-not $Config) {
      $Probe = Get-Install4jLauncherProbe -Stream $Stream
      if ($Probe) {
        $Launcher = $Probe.Launcher
        $Descriptor = $Probe.Descriptor
        $MediaType = 'WindowsSetupExecutable'
        $Evidence.Add("A complete '$($Launcher.Route)' launcher record was parsed from the PE overlay.")
      }

      if ($Descriptor) {
        $TableHandler = $Script:Install4jContentTableHandlers[$Descriptor.ContentTableRoute]
        if (-not $TableHandler) { throw "The install4j content-table route '$($Descriptor.ContentTableRoute)' has no handler" }
        $EmbeddedFileTables = @(& $TableHandler -Stream $Stream)
      } else {
        # Structurally valid but uncatalogued media remains identifiable. A generic table scan is
        # evidence only and does not make its payload route supported.
        $EmbeddedFileTables = @(Get-Install4jEmbeddedFileTable -Stream $Stream)
      }
      if (-not $Launcher -and $EmbeddedFileTables.Count -gt 0) {
        $MediaType = 'WindowsSetupExecutable'
        $Evidence.Add('A complete install4j ContentCollector table was parsed.')
      }

      foreach ($Entry in @($Launcher.Entries)) {
        if ($Entry -and -not $EmbeddedFiles.Contains([string]$Entry.Name)) { $EmbeddedFiles.Add([string]$Entry.Name) }
      }
      foreach ($EntryName in @($EmbeddedFileTables.Entries | Select-Object -ExpandProperty Name -ErrorAction SilentlyContinue)) {
        if (-not $EmbeddedFiles.Contains([string]$EntryName)) { $EmbeddedFiles.Add([string]$EntryName) }
      }

      if ($Launcher) {
        foreach ($Entry in @($Launcher.Entries | Where-Object Name -IEQ 'i4jparams.conf')) {
          try {
            $ConfigBytes = Read-Install4jLauncherFile -Stream $Stream -Entry $Entry
            $ConfigArguments = @{
              Content = [Text.Encoding]::UTF8.GetString($ConfigBytes)
              Source  = 'LauncherStartupFile'
            }
            if ($Descriptor) { $ConfigArguments.ConfigRoute = $Descriptor.ConfigRoute }
            $Config = ConvertFrom-Install4jConfigXml @ConfigArguments

            if (-not $Descriptor) {
              $ConfigurationDescriptor = Get-Install4jDescriptorFromConfig -Config $Config
              if ($ConfigurationDescriptor) {
                if ($ConfigurationDescriptor.LauncherRoute -ne $Launcher.Route) {
                  throw "The install4j configuration selects '$($ConfigurationDescriptor.LauncherRoute)' but the launcher uses '$($Launcher.Route)'"
                }
                if (-not [string]::IsNullOrWhiteSpace([string]$Launcher.Marker) -and
                  $Launcher.Marker -notmatch $ConfigurationDescriptor.MarkerPattern) {
                  $Warnings.Add("The launcher marker '$($Launcher.Marker)' conflicts with install4j $($Config.Install4jVersion) encoded by i4jparams.conf; no supported descriptor was selected.")
                } else {
                  $Descriptor = $ConfigurationDescriptor
                  $Evidence.Add("The launcher omitted a catalog marker; validated i4jparams.conf selected install4j generation $($Descriptor.Generation).")
                }
              }
            }
            break
          } catch {
            $Warnings.Add("Failed to parse launcher i4jparams.conf: $($_.Exception.Message)")
          }
        }
      }
      if (-not $Config) {
        foreach ($Entry in @($EmbeddedFileTables.Entries | Where-Object Name -IEQ 'i4jparams.conf')) {
          try {
            $ConfigBytes = Read-Install4jEmbeddedFile -Stream $Stream -Entry $Entry
            $ConfigArguments = @{ Content = [Text.Encoding]::UTF8.GetString($ConfigBytes); Source = 'EmbeddedFileTable' }
            if ($Descriptor) { $ConfigArguments.ConfigRoute = $Descriptor.ConfigRoute }
            $Config = ConvertFrom-Install4jConfigXml @ConfigArguments
            if (-not $Descriptor) { $Descriptor = Get-Install4jDescriptorFromConfig -Config $Config }
            break
          } catch {
            $Warnings.Add("Failed to parse direct embedded i4jparams.conf: $($_.Exception.Message)")
          }
        }
      }

      if (-not $Launcher -and $EmbeddedFileTables.Count -eq 0) {
        $ScanText = Get-Install4jScanText -File $File -Stream $Stream
        if ($ScanText.IndexOf('install4j', [StringComparison]::OrdinalIgnoreCase) -lt 0 -or
          ($ScanText.IndexOf('i4jparams.conf', [StringComparison]::OrdinalIgnoreCase) -lt 0 -and
          $ScanText.IndexOf('i4jruntime.jar', [StringComparison]::OrdinalIgnoreCase) -lt 0)) {
          throw 'The file does not contain structurally valid install4j media'
        }
        foreach ($EntryName in Get-Install4jEmbeddedFilesFromText -Text $ScanText) {
          if (-not $EmbeddedFiles.Contains([string]$EntryName)) { $EmbeddedFiles.Add([string]$EntryName) }
        }

        # Some old or partially recovered launchers expose a complete configuration document in
        # the bounded text windows even when their outer record layout is unavailable. Parse that
        # complete XML document for metadata, but retain the low-confidence structural warning.
        $ConfigText = Get-Install4jConfigXmlText -Text $ScanText
        if ($ConfigText) {
          try {
            $Config = ConvertFrom-Install4jConfigXml -Content $ConfigText -Source 'BoundedTextEvidence'
            $Descriptor = Get-Install4jDescriptorFromConfig -Config $Config
            $Evidence.Add('A complete embedded install4j configuration XML document was recovered from bounded launcher text.')
          } catch {
            $Warnings.Add("Failed to parse bounded embedded i4jparams.conf: $($_.Exception.Message)")
          }
        }
        $Warnings.Add('Only bounded install4j string evidence was found; this media generation is not structurally supported.')
      }
    }
  } finally {
    $Stream.Dispose()
  }

  if ($Descriptor -and $Descriptor.IsFallback) {
    if (-not $Launcher.IsCrc32Valid -or $Launcher.RemainingDataBytes -ne 0) {
      throw 'The future install4j launcher did not satisfy the complete modern-record fallback invariants'
    }
    $Warnings.Add("Future install4j generation $($Descriptor.Generation) reuses the generation 13 routes after full CRC and boundary validation.")
  }
  if ($Config -and $Descriptor) {
    $EncodedVersion = Get-Install4jExplicitVersion -Value $Config.Install4jVersion
    if ($EncodedVersion -and [int]($EncodedVersion -split '\.')[0] -ne $Descriptor.Generation) {
      $Warnings.Add("The configuration encodes install4j $EncodedVersion but the launcher selects generation $($Descriptor.Generation).")
    }
  }
  if (-not $Descriptor -and $MediaType -eq 'WindowsSetupExecutable') {
    $Warnings.Add('The install4j media is structurally identifiable, but no supported format descriptor could be selected from its launcher or configuration evidence.')
  }

  [pscustomobject]@{
    Path               = $ResolvedPath
    File               = $File
    VersionInfo        = $VersionInfo
    MediaType          = $MediaType
    Descriptor         = $Descriptor
    Launcher           = $Launcher
    EmbeddedFileTables = @($EmbeddedFileTables)
    EmbeddedFiles      = @($EmbeddedFiles)
    Config             = $Config
    ScanText           = $ScanText
    Evidence           = @($Evidence)
    Warnings           = @($Warnings)
  }
}

function Get-Install4jFormatInfo {
  <#
  .SYNOPSIS
    Identify the install4j Windows media generation and catalog-selected routes.
  .PARAMETER Path
    Path to a native setup executable or extracted i4jparams.conf.
  .OUTPUTS
    A structured format result. IsInstall4j can be true while IsSupported is false.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path
  )

  process {
    try {
      $Context = Get-Install4jAnalysisContext -Path $Path
    } catch {
      return [pscustomobject][ordered]@{
        IsInstall4j       = $false
        IsSupported       = $false
        FormatGeneration  = $null
        BuilderVersion    = $null
        BuilderBuild      = $null
        MediaType         = $null
        Architecture      = $null
        Marker            = $null
        LauncherRoute     = $null
        StartupFileRoute  = $null
        ContentTableRoute = $null
        PayloadRoute      = $null
        ConfigRoute       = $null
        RuntimePacking    = $null
        IsFallback        = $false
        Evidence          = @()
        Warnings          = @($_.Exception.Message)
      }
    }

    $Descriptor = $Context.Descriptor
    $Config = $Context.Config
    [pscustomobject][ordered]@{
      IsInstall4j       = $true
      IsSupported       = [bool]$Descriptor
      FormatGeneration  = $Descriptor.Generation
      BuilderVersion    = Get-Install4jExplicitVersion -Value $Config.Install4jVersion
      BuilderBuild      = Get-Install4jExplicitVersion -Value $Config.Install4jBuild
      MediaType         = $Context.MediaType
      Architecture      = Get-Install4jArchitecture -Config $Config -Path $Context.Path
      Marker            = $Context.Launcher.Marker
      LauncherRoute     = $Descriptor.LauncherRoute
      StartupFileRoute  = $Descriptor.StartupFileRoute
      ContentTableRoute = $Descriptor.ContentTableRoute
      PayloadRoute      = $Descriptor.PayloadRoute
      ConfigRoute       = if ($Descriptor) { $Descriptor.ConfigRoute } else { $Config.ConfigRoute }
      RuntimePacking    = $Descriptor.RuntimePacking
      IsFallback        = [bool]$Descriptor.IsFallback
      Evidence          = @($Context.Evidence)
      Warnings          = @($Context.Warnings)
    }
  }
}

function Get-Install4jInfo {
  <#
  .SYNOPSIS
    Get static metadata from an install4j installer or extracted i4jparams.conf
  .PARAMETER Path
    The path to the install4j installer or i4jparams.conf file
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the install4j installer or i4jparams.conf file')]
    [string]$Path
  )

  process {
    $Context = Get-Install4jAnalysisContext -Path $Path
    $File = $Context.File
    $Config = $Context.Config
    $Descriptor = $Context.Descriptor
    $VersionInfo = $Context.VersionInfo
    $Warnings = [Collections.Generic.List[string]]::new()
    foreach ($Warning in @($Context.Warnings)) { $Warnings.Add([string]$Warning) }
    $ApplicationId = if ($Config) {
      $Config.General.ApplicationId
    } elseif (-not [string]::IsNullOrWhiteSpace($Context.ScanText)) {
      Get-Install4jApplicationIdFromText -Text $Context.ScanText
    } else {
      $null
    }

    $ScopeInfo = Get-Install4jScopeInfo -Config $Config
    if (-not $Config) {
      $ScopeInfo = [pscustomobject]@{
        Scope             = $null
        DefaultScope      = $null
        SupportedScopes   = @()
        SupportsDualScope = $false
        Confidence        = 'unknown'
        Evidence          = @('i4jparams.conf was not directly extractable; scope requires config XML or VM validation.')
      }
    }

    $DisplayName = Get-Install4jFirstValue -Value @(
      $(if ($Config) { $Config.RegisterAddRemoveItemName }),
      $(if ($Config) { $Config.General.ApplicationName }),
      $VersionInfo.ProductName,
      $VersionInfo.FileDescription
    )
    $DisplayVersion = Get-Install4jFirstValue -Value @($(if ($Config) { $Config.General.ApplicationVersion }), $VersionInfo.ProductVersion, $VersionInfo.FileVersion)
    $Publisher = Get-Install4jFirstValue -Value @($(if ($Config) { $Config.General.PublisherName }), $VersionInfo.CompanyName)
    $DefaultInstallationDirectory = if ($Config) { $Config.DefaultInstallationDirectory } else { $null }
    $WritesAppsAndFeaturesEntry = if ($Config) { [bool]$Config.HasRegisterAddRemoveAction } else { $null }
    $Architecture = Get-Install4jArchitecture -Config $Config -Path $File.FullName
    $AssociationInfo = Get-Install4jAssociationInfo -Config $Config
    foreach ($Warning in @($AssociationInfo.Warnings)) { $Warnings.Add($Warning) }
    $RuntimeInfo = Get-Install4jRuntimeInfo -Config $Config -EmbeddedFiles @($Context.EmbeddedFiles) -HasMediaCatalog ([bool]($Context.Launcher -or $Context.EmbeddedFileTables.Count -gt 0))
    foreach ($Warning in @($RuntimeInfo.Warnings)) { $Warnings.Add($Warning) }

    $UnresolvedFields = [Collections.Generic.List[string]]::new()
    if (-not $Config) {
      foreach ($Field in 'ProductCode', 'WritesAppsAndFeaturesEntry', 'Scope', 'DefaultInstallLocation') {
        $UnresolvedFields.Add($Field)
      }
    }

    $Info = [pscustomobject][ordered]@{
      Path                         = $File.FullName
      InstallerType                = 'install4j'
      ProductCode                  = $ApplicationId
      UpgradeCode                  = $null
      DisplayName                  = $DisplayName
      DisplayVersion               = $DisplayVersion
      Publisher                    = $Publisher
      Scope                        = $ScopeInfo.Scope
      DefaultInstallLocation       = $DefaultInstallationDirectory
      WritesAppsAndFeaturesEntry   = $WritesAppsAndFeaturesEntry
      AppsAndFeaturesProductCode   = $WritesAppsAndFeaturesEntry -eq $true ? $ApplicationId : $null
      AppsAndFeaturesInstallerType = $WritesAppsAndFeaturesEntry -eq $true ? 'exe' : $null
      Warnings                     = [string[]]@($Warnings | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
      UnresolvedFields             = [string[]]@($UnresolvedFields)
      Family                       = 'install4j'
      IsSupported                  = [bool]$Descriptor
      FormatGeneration             = $Descriptor.Generation
      BuilderVersion               = Get-Install4jExplicitVersion -Value $Config.Install4jVersion
      BuilderBuild                 = Get-Install4jExplicitVersion -Value $Config.Install4jBuild
      MediaType                    = $Context.MediaType
      Marker                       = $Context.Launcher.Marker
      LauncherRoute                = $Descriptor.LauncherRoute
      StartupFileRoute             = $Descriptor.StartupFileRoute
      ContentTableRoute            = $Descriptor.ContentTableRoute
      PayloadRoute                 = $Descriptor.PayloadRoute
      ConfigRoute                  = if ($Descriptor) { $Descriptor.ConfigRoute } elseif ($Config) { $Config.ConfigRoute } else { $null }
      RuntimePacking               = $Descriptor.RuntimePacking
      HasBundledRuntime            = $RuntimeInfo.HasBundledRuntime
      BundledRuntimeVersion        = $RuntimeInfo.BundledRuntimeVersion
      MinimumJavaVersion           = $RuntimeInfo.MinimumJavaVersion
      BundledRuntimeArchive        = $RuntimeInfo.RuntimeArchive
      RuntimeConfidence            = $RuntimeInfo.Confidence
      RuntimeEvidence              = $RuntimeInfo.Evidence
      IsFallback                   = [bool]$Descriptor.IsFallback
      FormatEvidence               = @($Context.Evidence)
      ApplicationId                = $ApplicationId
      PackageName                  = if ($Config) { $Config.General.ApplicationName } else { $null }
      PublisherUrl                 = if ($Config) { $Config.General.PublisherUrl } else { $null }
      Architecture                 = $Architecture
      DefaultScope                 = $ScopeInfo.DefaultScope
      SupportedScopes              = $ScopeInfo.SupportedScopes
      SupportsDualScope            = $ScopeInfo.SupportsDualScope
      ScopeConfidence              = $ScopeInfo.Confidence
      ScopeEvidence                = $ScopeInfo.Evidence
      UninstallerFilename          = if ($Config) { $Config.General.UninstallerFilename } else { $null }
      UninstallerDirectory         = if ($Config) { $Config.General.UninstallerDirectory } else { $null }
      MsiProductId                 = if ($Config) { $Config.MsiProductId } else { $null }
      EmbeddedFiles                = @($Context.EmbeddedFiles)
      EmbeddedFileTables           = @($Context.EmbeddedFileTables)
      LauncherConfiguration        = $Context.Launcher
      CanExpand                    = [bool]($Descriptor -and ($Context.Launcher -or $Context.EmbeddedFileTables.Count -gt 0))
      RegistryWrites               = @()
      RegistryAssociationInfo      = $AssociationInfo
      Protocols                    = $AssociationInfo.Protocols
      FileExtensions               = $AssociationInfo.FileExtensions
      VersionInfo                  = $VersionInfo
      Config                       = $Config
      ParserVersionInfo            = [pscustomobject]@{
        Parser            = 'Dumplings.PackageModule.Install4j'
        ParserMajor       = 3
        CatalogVersion    = $Script:Install4jCatalog.CatalogVersion
        FormatGeneration  = $Descriptor.Generation
        LauncherRoute     = $Descriptor.LauncherRoute
        StartupFileRoute  = $Descriptor.StartupFileRoute
        ContentTableRoute = $Descriptor.ContentTableRoute
        PayloadRoute      = $Descriptor.PayloadRoute
        ConfigRoute       = if ($Descriptor) { $Descriptor.ConfigRoute } elseif ($Config) { $Config.ConfigRoute } else { $null }
        IsFallback        = [bool]$Descriptor.IsFallback
        Sources           = @('install4j launcher parameter block and startup-file table', 'install4j i4jparams.conf XML', 'install4j ContentCollector unextracted-file table', 'PE version resource')
      }
    }
    # Build expected uninstall writes only after all identity and scope evidence is assembled.
    $Info.RegistryWrites = @(Get-Install4jRegistryWrite -Info $Info)
    return $Info
  }
}

function Expand-Install4jInstaller {
  <#
  .SYNOPSIS
    Extract table-backed files and LZMA-compressed application payloads from an install4j installer
  .PARAMETER Path
    The path to the install4j installer
  .PARAMETER DestinationPath
    The destination directory for extracted files
  .PARAMETER Name
    The file name or wildcard pattern to extract
  .PARAMETER MaximumExpandedBytes
    The maximum number of bytes that one compressed content archive may expand to
  .PARAMETER CollisionAction
    Behavior when an output path already exists or is selected more than once.
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the install4j installer')]
    [string]$Path,

    [Parameter(HelpMessage = 'The destination directory for extracted files')]
    [string]$DestinationPath,

    [Parameter(HelpMessage = 'The file name or wildcard pattern to extract')]
    [string]$Name = '*',

    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')]
    [string]$CollisionAction = 'Prompt',

    [Parameter(HelpMessage = 'The maximum number of expanded bytes')]
    [ValidateRange(1, [long]::MaxValue)]
    [long]$MaximumExpandedBytes = $Script:Install4jMaximumExpandedBytes
  )

  process {
    $Context = Get-Install4jAnalysisContext -Path $Path
    $InstallerPath = $Context.Path
    $Descriptor = $Context.Descriptor
    $EmbeddedFileTables = @($Context.EmbeddedFileTables)
    $LauncherConfiguration = $Context.Launcher
    if (-not $Descriptor -and $EmbeddedFileTables.Count -eq 0) {
      throw 'The install4j media is structurally identifiable but its payload route is unsupported'
    }

    if ([string]::IsNullOrWhiteSpace($DestinationPath)) { $DestinationPath = New-TempFolder }
    $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
    $DestinationPath = (New-Item -Path $DestinationPath -ItemType Directory -Force).FullName

    $ExtractedFiles = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
    $ReservedPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    # Startup entries require the launcher's XOR transform; direct embedded entries do not.
    foreach ($Entry in @($LauncherConfiguration.Entries | Where-Object { $null -ne $_ })) {
      if ([string]::IsNullOrWhiteSpace([string]$Entry.Name)) { continue }
      if ($Descriptor.PayloadRoute -eq 'InlineContentZip' -and $Entry.Name -ieq 'content.zip') {
        $PayloadHandler = $Script:Install4jPayloadHandlers[$Descriptor.PayloadRoute]
        foreach ($ExtractedFile in & $PayloadHandler -Path $InstallerPath -Entry $Entry -DestinationPath $DestinationPath `
            -Name $Name -CollisionAction $CollisionAction -MaximumExpandedBytes $MaximumExpandedBytes) {
          $null = $ReservedPaths.Add($ExtractedFile.FullName)
          $ExtractedFiles.Add($ExtractedFile)
        }
        continue
      }

      if (-not (Test-ExtractionPattern -Path $Entry.Name -Pattern $Name)) { continue }
      if ($Entry.Length -gt $MaximumExpandedBytes) {
        throw "The install4j startup file '$($Entry.Name)' exceeds the $MaximumExpandedBytes-byte limit"
      }

      $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $Entry.Name `
        -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
      if (-not $Target.ShouldWrite) { continue }
      $OutputPath = $Target.Path
      $null = New-Item -Path ([System.IO.Path]::GetDirectoryName($OutputPath)) -ItemType Directory -Force
      $SourceStream = [System.IO.File]::Open($InstallerPath, 'Open', 'Read', 'ReadWrite')
      $OutputStream = [System.IO.File]::Open($OutputPath, 'Create', 'Write', 'Read')
      try {
        $SourceStream.Position = $Entry.Offset
        $null = Copy-BinaryXorStream -Source $SourceStream -Destination $OutputStream -Key ([byte]$Entry.TransformKey) -ExpectedBytes $Entry.Length
      } finally {
        $OutputStream.Dispose()
        $SourceStream.Dispose()
      }
      $ExtractedFiles.Add((Get-Item -LiteralPath $OutputPath -Force))
    }

    foreach ($Entry in @($EmbeddedFileTables.Entries)) {
      if ($null -eq $Entry -or [string]::IsNullOrWhiteSpace([string]$Entry.Name)) { continue }
      $IsPayloadEntry = ($Descriptor.PayloadRoute -eq 'LzmaZipContent' -and $Entry.Name -ieq '0.dat') -or
      ($Descriptor.PayloadRoute -eq 'SplitLzmaArchive' -and $Entry.Name -like '*.000')
      if ($IsPayloadEntry) {
        $PayloadHandler = $Script:Install4jPayloadHandlers[$Descriptor.PayloadRoute]
        foreach ($ExtractedFile in & $PayloadHandler -Path $InstallerPath -Entry $Entry -DestinationPath $DestinationPath `
            -Name $Name -CollisionAction $CollisionAction -MaximumExpandedBytes $MaximumExpandedBytes) {
          $null = $ReservedPaths.Add($ExtractedFile.FullName)
          $ExtractedFiles.Add($ExtractedFile)
        }
        continue
      }

      if (-not (Test-ExtractionPattern -Path $Entry.Name -Pattern $Name)) { continue }
      if ($Entry.Length -gt $MaximumExpandedBytes) {
        throw "The install4j embedded file '$($Entry.Name)' exceeds the $MaximumExpandedBytes-byte limit"
      }

      $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $Entry.Name `
        -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
      if (-not $Target.ShouldWrite) { continue }
      $OutputPath = $Target.Path
      $null = New-Item -Path ([System.IO.Path]::GetDirectoryName($OutputPath)) -ItemType Directory -Force

      $SourceStream = [System.IO.File]::Open($InstallerPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
      $OutputStream = [System.IO.File]::Open($OutputPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
      try {
        $SourceStream.Position = $Entry.Offset
        $Remaining = [long]$Entry.Length
        $Buffer = [byte[]]::new(1048576)
        while ($Remaining -gt 0) {
          $Read = $SourceStream.Read($Buffer, 0, [int][Math]::Min($Buffer.Length, $Remaining))
          if ($Read -le 0) { throw "The install4j embedded file '$($Entry.Name)' is truncated" }
          $OutputStream.Write($Buffer, 0, $Read)
          $Remaining -= $Read
        }
      } finally {
        $OutputStream.Dispose()
        $SourceStream.Dispose()
      }
      $ExtractedFiles.Add((Get-Item -Path $OutputPath -Force))
    }

    if ($ExtractedFiles.Count -eq 0) { throw "No install4j payload files matched the extraction selector: $Name" }
    return $DestinationPath
  }
}

function Test-Install4jInstaller {
  <#
  .SYNOPSIS
    Test whether a file contains install4j installer metadata
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
      $null = Get-Install4jInfo -Path $Path
      return $true
    } catch {
      return $false
    }
  }
}

function Read-ProtocolsFromInstall4j {
  <#
  .SYNOPSIS
    Read literal URL protocol names from install4j configuration
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-Install4jInfo -Path $Path).Protocols }
}

function Read-FileExtensionsFromInstall4j {
  <#
  .SYNOPSIS
    Read Windows file-association extensions from install4j configuration
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-Install4jInfo -Path $Path).FileExtensions }
}

function Read-ProductCodeFromInstall4j {
  <#
  .SYNOPSIS
    Read the ProductCode/uninstall key from an install4j installer
  .PARAMETER Path
    The path to the install4j installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the install4j installer')]
    [string]$Path
  )

  process {
    $Info = Get-Install4jInfo -Path $Path
    if ([string]::IsNullOrWhiteSpace($Info.ProductCode)) { throw 'The install4j installer does not expose an Application ID value' }
    return $Info.ProductCode
  }
}

function Read-ProductVersionFromInstall4j {
  <#
  .SYNOPSIS
    Read the DisplayVersion from an install4j installer
  .PARAMETER Path
    The path to the install4j installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the install4j installer')]
    [string]$Path
  )

  process {
    $Info = Get-Install4jInfo -Path $Path
    if ([string]::IsNullOrWhiteSpace($Info.DisplayVersion)) { throw 'The install4j installer does not expose a DisplayVersion value' }
    return $Info.DisplayVersion
  }
}

function Read-ProductNameFromInstall4j {
  <#
  .SYNOPSIS
    Read the product name from an install4j installer
  .PARAMETER Path
    The path to the install4j installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the install4j installer')]
    [string]$Path
  )

  process {
    $Info = Get-Install4jInfo -Path $Path
    if ([string]::IsNullOrWhiteSpace($Info.DisplayName)) { throw 'The install4j installer does not expose a product name value' }
    return $Info.DisplayName
  }
}

function Read-PublisherFromInstall4j {
  <#
  .SYNOPSIS
    Read the publisher from an install4j installer
  .PARAMETER Path
    The path to the install4j installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the install4j installer')]
    [string]$Path
  )

  process {
    $Info = Get-Install4jInfo -Path $Path
    if ([string]::IsNullOrWhiteSpace($Info.Publisher)) { throw 'The install4j installer does not expose a Publisher value' }
    return $Info.Publisher
  }
}

function Read-ScopeFromInstall4j {
  <#
  .SYNOPSIS
    Read the default Apps and Features scope from an install4j installer when statically known
  .PARAMETER Path
    The path to the install4j installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the install4j installer')]
    [string]$Path
  )

  process {
    (Get-Install4jInfo -Path $Path).Scope
  }
}

function Read-SupportedScopesFromInstall4j {
  <#
  .SYNOPSIS
    Read statically supported Apps and Features scopes from an install4j installer
  .PARAMETER Path
    The path to the install4j installer
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the install4j installer')]
    [string]$Path
  )

  process {
    (Get-Install4jInfo -Path $Path).SupportedScopes
  }
}

function Test-Install4jDualScope {
  <#
  .SYNOPSIS
    Test whether install4j scope evidence indicates user and machine ARP paths
  .PARAMETER Path
    The path to the install4j installer
  #>
  [OutputType([bool])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the install4j installer')]
    [string]$Path
  )

  process {
    (Get-Install4jInfo -Path $Path).SupportsDualScope
  }
}

Export-ModuleMember -Function Get-Install4jFormatInfo, Get-Install4jInfo, Expand-Install4jInstaller, Test-Install4jInstaller, Read-ProtocolsFromInstall4j, Read-FileExtensionsFromInstall4j, Read-ProductCodeFromInstall4j, Read-ProductVersionFromInstall4j, Read-ProductNameFromInstall4j, Read-PublisherFromInstall4j, Read-ScopeFromInstall4j, Read-SupportedScopesFromInstall4j, Test-Install4jDualScope
