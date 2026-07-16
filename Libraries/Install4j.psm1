# SPDX-License-Identifier: MIT

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# Force stop on error
$ErrorActionPreference = 'Stop'

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

function Import-Install4jSharpCompress {
  <#
  .SYNOPSIS
    Load the PackageModule copy of SharpCompress used for install4j LZMA decoding
  #>
  Import-InstallerArchiveDependency
}

function Read-Install4jFileByteRange {
  <#
  .SYNOPSIS
    Read a bounded byte range from an install4j file
  #>
  [OutputType([byte[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The file stream to read from')]
    [System.IO.Stream]$Stream,

    [Parameter(Mandatory, HelpMessage = 'The file offset to start reading at')]
    [long]$Offset,

    [Parameter(Mandatory, HelpMessage = 'The maximum number of bytes to read')]
    [int]$Count
  )

  if ($Offset -lt 0 -or $Offset -ge $Stream.Length -or $Count -le 0) { return ,([byte[]]::new(0)) }

  return ,(Read-BinaryBytes -Stream $Stream -Offset $Offset -Count $Count -AllowPartial)
}

function Read-Install4jInt32BigEndian {
  <#
  .SYNOPSIS
    Read a Java DataInputStream-style signed 32-bit integer
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The file stream to read from')]
    [System.IO.Stream]$Stream
  )

  $Offset = $Stream.Position
  $Value = Read-BinaryInteger -Stream $Stream -Offset $Offset -Size 4 -Endian BigEndian -Signed
  $Stream.Position = $Offset + 4
  return $Value
}

function Read-Install4jUInt16BigEndian {
  <#
  .SYNOPSIS
    Read a Java DataInputStream-style unsigned 16-bit integer
  #>
  [OutputType([uint16])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The file stream to read from')]
    [System.IO.Stream]$Stream
  )

  $Offset = $Stream.Position
  $Value = Read-BinaryInteger -Stream $Stream -Offset $Offset -Size 2 -Endian BigEndian
  $Stream.Position = $Offset + 2
  return $Value
}

function Read-Install4jInt64BigEndian {
  <#
  .SYNOPSIS
    Read a Java DataInputStream-style signed 64-bit integer
  #>
  [OutputType([long])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The file stream to read from')]
    [System.IO.Stream]$Stream
  )

  $Offset = $Stream.Position
  $Value = Read-BinaryInteger -Stream $Stream -Offset $Offset -Size 8 -Endian BigEndian -Signed
  $Stream.Position = $Offset + 8
  return $Value
}

function Find-Install4jBytePattern {
  <#
  .SYNOPSIS
    Find a bounded number of byte-pattern offsets in a file
  #>
  [OutputType([long[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The file to scan')]
    [string]$Path,

    [Parameter(Mandatory, HelpMessage = 'The byte pattern to locate')]
    [byte[]]$Pattern,

    [Parameter(HelpMessage = 'The maximum number of offsets to return')]
    [int]$Maximum = 32
  )

  Find-BinaryPattern -Path $Path -Pattern $Pattern -Maximum $Maximum
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
    [System.IO.FileInfo]$File
  )

  $StringBuilder = [System.Text.StringBuilder]::new()
  $Stream = [System.IO.File]::Open($File.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
  try {
    foreach ($Range in @(
        [pscustomobject]@{ Offset = [long]0; Count = [int][Math]::Min(4194304, $File.Length) },
        [pscustomobject]@{ Offset = [long][Math]::Max(0, $File.Length - 4194304); Count = [int][Math]::Min(4194304, $File.Length) }
      )) {
      $Bytes = Read-Install4jFileByteRange -Stream $Stream -Offset $Range.Offset -Count $Range.Count
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
        $Bytes = Read-Install4jFileByteRange -Stream $Stream -Offset $OverlayOffset -Count ([int][Math]::Min($Script:Install4jMaximumScanBytes, $File.Length - $OverlayOffset))
        if ($Bytes.Length -gt 0) {
          $null = $StringBuilder.Append([System.Text.Encoding]::Latin1.GetString($Bytes))
          $null = $StringBuilder.Append("`n")
        }
      }
    }
  } finally {
    $Stream.Dispose()
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
  foreach ($Variable in @($Xml.SelectNodes('/config/compilerVariables/variable'))) {
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
    [string]$Source = 'Xml'
  )

  [xml]$Xml = $Content
  if (-not $Xml.config) { throw 'The XML document is not an install4j config document' }

  $Root = $Xml.config
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
    PrivilegedInstallerRequest   = ConvertTo-Install4jBoolean -Value (Get-Install4jXmlAttribute -Element $GeneralNode -Name 'privilegedInstallerRequest')
  }

  $CompilerVariables = Get-Install4jCompilerVariableMap -Xml $Xml
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
    [pscustomobject]@{
      Extension  = $Extension
      Description = Expand-Install4jStaticText -Value (Get-Install4jXmlDecoderPropertyValue -ObjectNode $ActionNode -Name 'description') -General $General -CompilerVariables $CompilerVariables
      LauncherId = Get-Install4jXmlDecoderPropertyValue -ObjectNode $ActionNode -Name 'launcherId'
      Windows    = ConvertTo-Install4jBoolean -Value (Get-Install4jXmlDecoderPropertyValue -ObjectNode $ActionNode -Name 'windows')
      Selected   = ConvertTo-Install4jBoolean -Value (Get-Install4jXmlDecoderPropertyValue -ObjectNode $ActionNode -Name 'selected')
    }
  }

  [pscustomobject]@{
    Source                         = $Source
    Install4jVersion               = Get-Install4jXmlAttribute -Element $Root -Name 'install4jVersion'
    Install4jBuild                 = Get-Install4jXmlAttribute -Element $Root -Name 'install4jBuild'
    Type                           = Get-Install4jXmlAttribute -Element $Root -Name 'type'
    Archive                        = ConvertTo-Install4jBoolean -Value (Get-Install4jXmlAttribute -Element $Root -Name 'archive')
    Bitness                        = Get-Install4jXmlAttribute -Element $Root -Name 'bitness'
    General                        = [pscustomobject]$General
    CompilerVariables              = [pscustomobject]$CompilerVariables
    HasRegisterAddRemoveAction     = [bool]$RegisterActionNode
    RegisterAddRemoveItemName      = $RegisterItemName
    HasRequestPrivilegesAction     = [bool]$RequestPrivilegesNode
    RequestPrivileges              = $RequestPrivileges
    MsiProductId                   = $CompilerVariables['sys.msiProductId']
    DefaultInstallationDirectory   = $General.DefaultInstallationDirectory
    PrivilegedInstallerRequest     = $General.PrivilegedInstallerRequest
    FileAssociationActions          = @($FileAssociationActions)
  }
}

function Get-Install4jAssociationInfo {
  <#
  .SYNOPSIS
    Read Windows file-association actions from install4j configuration XML
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
        FileExtension      = $Extension.ToLowerInvariant()
        Extension          = ".$($Extension.ToLowerInvariant())"
        Description        = $Action.Description
        LauncherId         = $Action.LauncherId
        IsSelectedByDefault = $Action.Selected
        Source             = 'install4j CreateFileAssociationAction'
        Evidence           = $Action
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

function Read-Install4jLauncherInteger {
  <#
  .SYNOPSIS
    Read a little-endian integer from the current launcher stream position
  #>
  param (
    [Parameter(Mandatory)][System.IO.Stream]$Stream,
    [Parameter(Mandatory)][ValidateSet(4, 8)][int]$Size,
    [switch]$Unsigned
  )

  $Offset = $Stream.Position
  $Value = Read-BinaryInteger -Stream $Stream -Offset $Offset -Size $Size -Signed:(-not $Unsigned)
  $Stream.Position = $Offset + $Size
  return $Value
}

function Read-Install4jLauncherString {
  <#
  .SYNOPSIS
    Read one bounded length-prefixed launcher parameter string
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][System.IO.Stream]$Stream,
    [Parameter(Mandatory)][System.Text.Encoding]$Encoding,
    [Parameter(Mandatory)][long]$DataEnd
  )

  $Length = Read-Install4jLauncherInteger -Stream $Stream -Size 4
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
  #>
  [OutputType([hashtable])]
  param (
    [Parameter(Mandatory)][System.IO.Stream]$Stream,
    [Parameter(Mandatory)][System.Text.Encoding]$Encoding,
    [Parameter(Mandatory)][long]$DataEnd
  )

  $Count = Read-Install4jLauncherInteger -Stream $Stream -Size 4
  if ($Count -lt 0 -or $Count -gt $Script:Install4jMaximumParameterCount) {
    throw "Invalid install4j launcher parameter count: $Count"
  }
  $Result = @{}
  for ($Index = 0; $Index -lt $Count; $Index++) {
    $Key = Read-Install4jLauncherInteger -Stream $Stream -Size 4
    $Result[$Key] = Read-Install4jLauncherString -Stream $Stream -Encoding $Encoding -DataEnd $DataEnd
  }
  return $Result
}

function Get-Install4jLauncherConfiguration {
  <#
  .SYNOPSIS
    Read the install4j launcher parameter block and transformed startup files
  .DESCRIPTION
    install4j writes this block at the PE overlay start. The block is bounded by
    a declared byte count and CRC32. Parameter 2003 lists startup files in the
    same order as their following length-prefixed payloads.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)

  $File = Get-Item -LiteralPath $Path -Force
  $Stream = [System.IO.File]::Open($File.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
  try {
    $OverlayOffset = Get-PEOverlayOffset -Stream $Stream
    if ($OverlayOffset -le 0 -or $OverlayOffset + 24 -gt $Stream.Length) { throw 'The install4j launcher has no configuration overlay' }
    $Magic = Read-BinaryBytes -Stream $Stream -Offset $OverlayOffset -Count 4
    if (-not (Test-BinarySequence -Left $Magic -Right $Script:Install4jLauncherMagic)) {
      throw 'The PE overlay does not start with an install4j launcher configuration block'
    }

    $Stream.Position = $OverlayOffset + 4
    $Flags = Read-Install4jLauncherInteger -Stream $Stream -Size 4 -Unsigned
    $ExpectedCrc32 = Read-Install4jLauncherInteger -Stream $Stream -Size 4 -Unsigned
    $DataLength = Read-Install4jLauncherInteger -Stream $Stream -Size 8
    $DataStart = $Stream.Position
    if ($DataLength -le 0 -or $DataLength -gt $Script:Install4jMaximumExpandedBytes -or $DataStart + $DataLength -gt $Stream.Length) {
      throw "Invalid install4j launcher configuration length: $DataLength"
    }
    $DataEnd = $DataStart + $DataLength

    $AnsiParameters = Read-Install4jLauncherParameterMap -Stream $Stream -Encoding ([System.Text.Encoding]::UTF8) -DataEnd $DataEnd
    $LocalizedParameters = Read-Install4jLauncherParameterMap -Stream $Stream -Encoding ([System.Text.Encoding]::Unicode) -DataEnd $DataEnd
    $NestedCount = Read-Install4jLauncherInteger -Stream $Stream -Size 4
    if ($NestedCount -lt 0 -or $NestedCount -gt $Script:Install4jMaximumParameterCount) {
      throw "Invalid install4j nested parameter-map count: $NestedCount"
    }
    $NestedParameters = @{}
    for ($Index = 0; $Index -lt $NestedCount; $Index++) {
      $Name = Read-Install4jLauncherString -Stream $Stream -Encoding ([System.Text.Encoding]::UTF8) -DataEnd $DataEnd
      $NestedParameters[$Name] = Read-Install4jLauncherParameterMap -Stream $Stream -Encoding ([System.Text.Encoding]::Unicode) -DataEnd $DataEnd
    }

    $Names = @(([string]$AnsiParameters[2003]).Split(';', [System.StringSplitOptions]::RemoveEmptyEntries))
    if ($Names.Count -le 0 -or $Names.Count -gt $Script:Install4jMaximumParameterCount) {
      throw 'The install4j launcher does not declare a bounded startup-file list'
    }
    $Entries = [System.Collections.Generic.List[psobject]]::new()
    foreach ($Name in $Names) {
      if ($Stream.Position + 8 -gt $DataEnd) { throw 'The install4j startup-file table is truncated' }
      $Length = Read-Install4jLauncherInteger -Stream $Stream -Size 8
      if ($Length -lt 0 -or $Length -gt $Script:Install4jMaximumExpandedBytes -or $Stream.Position + $Length -gt $DataEnd) {
        throw "Invalid install4j startup-file length for '$Name': $Length"
      }
      $Entries.Add([pscustomobject]@{
          Name        = $Name
          Offset      = [long]$Stream.Position
          Length      = [long]$Length
          Transform   = 'Xor88'
          TransformKey = $Script:Install4jLauncherTransformKey
        })
      $Stream.Position += $Length
    }

    $CrcStream = New-BoundedReadStream -Stream $Stream -Offset $DataStart -Length $DataLength -LeaveOpen
    try { $ActualCrc32 = Get-BinaryCrc32 -Stream $CrcStream -MaximumBytes $DataLength } finally { $CrcStream.Dispose() }
    if ($ActualCrc32 -ne $ExpectedCrc32) {
      throw ('The install4j launcher configuration CRC32 is invalid: expected {0:X8}, got {1:X8}' -f $ExpectedCrc32, $ActualCrc32)
    }

    return [pscustomobject]@{
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
    $Stream.Dispose()
  }
}

function Read-Install4jLauncherFile {
  <#
  .SYNOPSIS
    Read and decode a bounded install4j launcher startup file
  #>
  [OutputType([byte[]])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][psobject]$Entry,
    [ValidateRange(1, [int]::MaxValue)][int]$MaximumBytes = $Script:Install4jMaximumConfigBytes
  )

  if ($Entry.Length -gt $MaximumBytes) { throw "The install4j startup file '$($Entry.Name)' is too large to read safely" }
  $Source = [System.IO.File]::Open((Get-Item -LiteralPath $Path -Force).FullName, 'Open', 'Read', 'ReadWrite')
  $Destination = [System.IO.MemoryStream]::new([int]$Entry.Length)
  try {
    $Source.Position = $Entry.Offset
    $null = Copy-BinaryXorStream -Source $Source -Destination $Destination -Key ([byte]$Entry.TransformKey) -ExpectedBytes $Entry.Length
    return ,($Destination.ToArray())
  } finally {
    $Destination.Dispose()
    $Source.Dispose()
  }
}

function Get-Install4jEmbeddedFileTable {
  <#
  .SYNOPSIS
    Read install4j unextracted-file tables from an installer launcher
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path
  )

  $File = Get-Item -LiteralPath $Path -Force
  foreach ($Offset in Find-Install4jBytePattern -Path $File.FullName -Pattern $Script:Install4jUnextractedMagic -Maximum 16) {
    $Stream = [System.IO.File]::Open($File.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
      $Stream.Position = $Offset
      if ((Read-Install4jInt32BigEndian -Stream $Stream) -ne -387705899) { continue }
      $Count = Read-Install4jInt32BigEndian -Stream $Stream
      if ($Count -le 0 -or $Count -gt 4096) { continue }

      $Entries = [System.Collections.Generic.List[psobject]]::new()
      $PayloadRelativeOffset = [long]0
      for ($Index = 0; $Index -lt $Count; $Index++) {
        $NameLength = [int](Read-Install4jUInt16BigEndian -Stream $Stream)
        if ($NameLength -le 0 -or $NameLength -gt 32767) { throw 'Invalid install4j embedded file name length' }

        $NameBytes = [byte[]]::new($NameLength)
        if ($Stream.Read($NameBytes, 0, $NameLength) -ne $NameLength) { throw 'Unexpected end of file while reading install4j embedded file name' }
        $Name = [System.Text.Encoding]::UTF8.GetString($NameBytes)
        $Length = Read-Install4jInt64BigEndian -Stream $Stream
        if ($Length -lt 0 -or $Length -gt $File.Length) { throw 'Invalid install4j embedded file length' }

        $Entries.Add([pscustomobject]@{
            Name                 = $Name
            Length               = $Length
            PayloadRelativeOffset = $PayloadRelativeOffset
            Offset               = [long]0
          })
        $PayloadRelativeOffset += $Length
      }

      $PayloadStart = $Stream.Position
      foreach ($Entry in $Entries) {
        $Entry.Offset = $PayloadStart + $Entry.PayloadRelativeOffset
        if ($Entry.Offset + $Entry.Length -gt $File.Length) { throw 'install4j embedded file entry exceeds the file length' }
      }

      [pscustomobject]@{
        Offset       = $Offset
        PayloadStart = $PayloadStart
        Count        = $Count
        Entries      = @($Entries)
      }
    } catch {
      continue
    } finally {
      $Stream.Dispose()
    }
  }
}

function Read-Install4jEmbeddedFile {
  <#
  .SYNOPSIS
    Read a small direct embedded file from the install4j unextracted table
  #>
  [OutputType([byte[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path,

    [Parameter(Mandatory, HelpMessage = 'The embedded file table entry')]
    [psobject]$Entry,

    [Parameter(HelpMessage = 'The maximum number of bytes to read')]
    [int]$MaximumBytes = $Script:Install4jMaximumConfigBytes
  )

  if ($Entry.Length -gt $MaximumBytes) { throw "The install4j embedded file '$($Entry.Name)' is too large to read safely" }

  $Stream = [System.IO.File]::Open((Get-Item -LiteralPath $Path -Force).FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
  try {
    return ,(Read-Install4jFileByteRange -Stream $Stream -Offset $Entry.Offset -Count ([int]$Entry.Length))
  } finally {
    $Stream.Dispose()
  }
}

function Resolve-Install4jExtractionPath {
  <#
  .SYNOPSIS
    Resolve an install4j payload path while preventing extraction outside the destination
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The extraction destination directory')]
    [string]$DestinationPath,

    [Parameter(Mandatory, HelpMessage = 'The relative payload path')]
    [string]$RelativePath
  )

  return Resolve-SafeExtractionPath -DestinationPath $DestinationPath -RelativePath $RelativePath
}

function Test-Install4jExtractionMatch {
  <#
  .SYNOPSIS
    Test a payload path against an install4j extraction selector
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The payload path')]
    [string]$Path,

    [Parameter(Mandatory, HelpMessage = 'The file name or wildcard pattern')]
    [string]$Name
  )

  return Test-ExtractionPattern -Path $Path -Pattern $Name
}

function Expand-Install4jLzmaZipEntry {
  <#
  .SYNOPSIS
    Decode and extract an install4j LZMA-alone ZIP content entry
  #>
  [OutputType([System.IO.FileInfo[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the install4j installer')]
    [string]$Path,

    [Parameter(Mandatory, HelpMessage = 'The 0.dat embedded-file table entry')]
    [psobject]$Entry,

    [Parameter(Mandatory, HelpMessage = 'The extraction destination directory')]
    [string]$DestinationPath,

    [Parameter(Mandatory, HelpMessage = 'The file name or wildcard pattern')]
    [string]$Name,

    [Parameter(Mandatory, HelpMessage = 'The maximum total number of expanded bytes')]
    [long]$MaximumExpandedBytes
  )

  Import-Install4jSharpCompress

  if ($Entry.Length -lt 14) { throw 'The install4j LZMA-alone content stream is truncated' }
  $SourceStream = [System.IO.File]::Open((Get-Item -Path $Path -Force).FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
  $DecodedArchivePath = New-TempFile
  try {
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

    $Archive = Get-InstallerArchive -Path $DecodedArchivePath
    try {
      $Result = Export-InstallerArchiveSelection -Archive $Archive -DestinationPath $DestinationPath -Name $Name -MaximumExpandedBytes $MaximumExpandedBytes -MaximumEntries $Script:Install4jMaximumArchiveEntries
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

  if ($Config -and $Config.Bitness) {
    switch ([string]$Config.Bitness) {
      '32' { return 'x86' }
      '64' { return 'x64' }
    }
  }

  if ((Get-Command -Name Get-PELayout -ErrorAction SilentlyContinue)) {
    $Layout = try { Get-PELayout -Path $Path } catch { $null }
    if ($Layout) {
      switch ($Layout.MachineName) {
        'I386' { return 'x86' }
        'AMD64' { return 'x64' }
        'ARM64' { return 'arm64' }
      }
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

  if ($Config.HasRequestPrivilegesAction) {
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
    InstallLocation = $Info.DefaultInstallationDirectory
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
    $File = Get-Item -LiteralPath $Path -Force
    $Warnings = [System.Collections.Generic.List[string]]::new()
    $VersionInfo = Get-Install4jVersionInfo -File $File
    $EmbeddedFileTables = @(Get-Install4jEmbeddedFileTable -Path $File.FullName)
    $LauncherConfiguration = try { Get-Install4jLauncherConfiguration -Path $File.FullName } catch { $null }
    $EmbeddedFiles = @()
    foreach ($Entry in @($LauncherConfiguration.Entries | Where-Object { $null -ne $_ })) {
      if ($EmbeddedFiles -notcontains $Entry.Name) { $EmbeddedFiles += $Entry.Name }
    }
    foreach ($Entry in @($EmbeddedFileTables.Entries | Select-Object -ExpandProperty Name -ErrorAction SilentlyContinue)) {
      if ($EmbeddedFiles -notcontains $Entry) { $EmbeddedFiles += $Entry }
    }

    $Config = $null
    foreach ($Entry in @($LauncherConfiguration.Entries | Where-Object { $_.Name -ieq 'i4jparams.conf' })) {
      try {
        $Bytes = Read-Install4jLauncherFile -Path $File.FullName -Entry $Entry
        $EmbeddedConfigText = [System.Text.Encoding]::UTF8.GetString($Bytes)
        $Config = ConvertFrom-Install4jConfigXml -Content $EmbeddedConfigText -Source 'LauncherStartupFile'
        break
      } catch {
        $Warnings.Add("Failed to parse launcher i4jparams.conf: $($_.Exception.Message)")
      }
    }
    if (-not $Config) {
      foreach ($Entry in @($EmbeddedFileTables.Entries | Where-Object { $_.Name -ieq 'i4jparams.conf' })) {
        try {
          $Bytes = Read-Install4jEmbeddedFile -Path $File.FullName -Entry $Entry
          $EmbeddedConfigText = [System.Text.Encoding]::UTF8.GetString($Bytes)
          $Config = ConvertFrom-Install4jConfigXml -Content $EmbeddedConfigText -Source 'EmbeddedFileTable'
          break
        } catch {
          $Warnings.Add("Failed to parse direct embedded i4jparams.conf: $($_.Exception.Message)")
        }
      }
    }

    # Large launcher scans are a fallback only. Current install4j launchers
    # expose i4jparams.conf through one of the structured file tables above.
    $ScanText = $null
    if (-not $Config) {
      $ScanText = Get-Install4jScanText -File $File
      foreach ($Entry in @(Get-Install4jEmbeddedFilesFromText -Text $ScanText)) {
        if ($EmbeddedFiles -notcontains $Entry) { $EmbeddedFiles += $Entry }
      }
      $ConfigXml = Get-Install4jConfigXmlText -Text $ScanText
      if (-not $ConfigXml -and $File.Length -le $Script:Install4jMaximumConfigBytes) {
        $Content = Get-Content -LiteralPath $File.FullName -Raw -ErrorAction SilentlyContinue
        if ($Content) { $ConfigXml = Get-Install4jConfigXmlText -Text $Content }
      }
      if ($ConfigXml) { $Config = ConvertFrom-Install4jConfigXml -Content $ConfigXml -Source 'PlainXml' }
    }

    $HasInstall4jMarkers = if ($ScanText) {
      $ScanText.IndexOf('install4j', [StringComparison]::OrdinalIgnoreCase) -ge 0 -and
      ($ScanText.IndexOf('i4jparams.conf', [StringComparison]::OrdinalIgnoreCase) -ge 0 -or $ScanText.IndexOf('i4jruntime.jar', [StringComparison]::OrdinalIgnoreCase) -ge 0)
    } else { $true }
    $ApplicationId = if ($Config) { $Config.General.ApplicationId } else { Get-Install4jApplicationIdFromText -Text $ScanText }
    if (-not $Config -and ($EmbeddedFiles -contains '0.dat')) {
      $Warnings.Add('The install4j content archive is packed as 0.dat, commonly LZMA-compressed; the pure PowerShell parser used launcher metadata and could not confirm XML-only action fields.')
    }

    if (-not $Config -and -not $HasInstall4jMarkers -and [string]::IsNullOrWhiteSpace($ApplicationId)) {
      throw 'The file does not contain install4j installer markers'
    }

    $ScopeInfo = Get-Install4jScopeInfo -Config $Config
    if (-not $Config -and $HasInstall4jMarkers) {
      $ScopeInfo = [pscustomobject]@{
        Scope             = $null
        DefaultScope      = $null
        SupportedScopes   = @()
        SupportsDualScope = $false
        Confidence        = 'unknown'
        Evidence          = @('i4jparams.conf was not directly extractable; scope requires config XML or VM validation.')
      }
    }

    $DisplayName = Get-Install4jFirstValue -Value @($Config.RegisterAddRemoveItemName, $Config.General.ApplicationName, $VersionInfo.ProductName, $VersionInfo.FileDescription)
    $DisplayVersion = Get-Install4jFirstValue -Value @($Config.General.ApplicationVersion, $VersionInfo.ProductVersion, $VersionInfo.FileVersion)
    $Publisher = Get-Install4jFirstValue -Value @($Config.General.PublisherName, $VersionInfo.CompanyName)
    $DefaultInstallationDirectory = if ($Config) { $Config.DefaultInstallationDirectory } else { $null }
    $WritesAppsAndFeaturesEntry = if ($Config) { [bool]$Config.HasRegisterAddRemoveAction } else { $null }
    $Architecture = Get-Install4jArchitecture -Config $Config -Path $File.FullName
    $AssociationInfo = Get-Install4jAssociationInfo -Config $Config
    foreach ($Warning in @($AssociationInfo.Warnings)) { $Warnings.Add($Warning) }

    $Info = [pscustomobject]@{
      InstallerType                 = 'install4j'
      Family                        = 'install4j'
      ProductCode                   = $ApplicationId
      ApplicationId                 = $ApplicationId
      PackageName                   = $Config.General.ApplicationName
      DisplayName                   = $DisplayName
      ProductName                   = Get-Install4jFirstValue -Value @($Config.General.ApplicationName, $VersionInfo.ProductName, $VersionInfo.FileDescription)
      DisplayVersion                = $DisplayVersion
      Publisher                     = $Publisher
      PublisherUrl                  = $Config.General.PublisherUrl
      Architecture                  = $Architecture
      Scope                         = $ScopeInfo.Scope
      DefaultScope                  = $ScopeInfo.DefaultScope
      SupportedScopes               = $ScopeInfo.SupportedScopes
      SupportsDualScope             = $ScopeInfo.SupportsDualScope
      ScopeConfidence               = $ScopeInfo.Confidence
      ScopeEvidence                 = $ScopeInfo.Evidence
      WritesAppsAndFeaturesEntry    = $WritesAppsAndFeaturesEntry
      DefaultInstallationDirectory  = $DefaultInstallationDirectory
      UninstallerFilename           = $Config.General.UninstallerFilename
      UninstallerDirectory          = $Config.General.UninstallerDirectory
      MsiProductId                  = $Config.MsiProductId
      EmbeddedFiles                 = @($EmbeddedFiles)
      EmbeddedFileTables            = @($EmbeddedFileTables)
      LauncherConfiguration         = $LauncherConfiguration
      CanExpand                     = [bool]($LauncherConfiguration -or $EmbeddedFileTables.Count -gt 0)
       RegistryWrites                = @()
       RegistryAssociationInfo       = $AssociationInfo
       Protocols                     = $AssociationInfo.Protocols
       FileExtensions                = $AssociationInfo.FileExtensions
      VersionInfo                   = $VersionInfo
      Config                        = $Config
      Warnings                      = @($Warnings)
      ParserVersionInfo             = [pscustomobject]@{
        Parser      = 'Dumplings.PackageModule.Install4j'
        ParserMajor = 2
        Sources     = @('install4j launcher parameter block and startup-file table', 'install4j i4jparams.conf XML', 'install4j ContentCollector unextracted-file table', 'PE version resource')
      }
    }
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
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the install4j installer')]
    [string]$Path,

    [Parameter(HelpMessage = 'The destination directory for extracted files')]
    [string]$DestinationPath,

    [Parameter(HelpMessage = 'The file name or wildcard pattern to extract')]
    [string]$Name = '*',

    [Parameter(HelpMessage = 'The maximum number of expanded bytes')]
    [ValidateRange(1, [long]::MaxValue)]
    [long]$MaximumExpandedBytes = $Script:Install4jMaximumExpandedBytes
  )

  process {
    $InstallerPath = (Get-Item -Path $Path -Force).FullName
    $EmbeddedFileTables = @(Get-Install4jEmbeddedFileTable -Path $InstallerPath)
    $LauncherConfiguration = try { Get-Install4jLauncherConfiguration -Path $InstallerPath } catch { $null }
    if (-not $EmbeddedFileTables -and -not $LauncherConfiguration) {
      throw 'The install4j installer does not contain a supported launcher or embedded-file table'
    }

    if ([string]::IsNullOrWhiteSpace($DestinationPath)) { $DestinationPath = New-TempFolder }
    $DestinationPath = (New-Item -Path $DestinationPath -ItemType Directory -Force).FullName

    $ExtractedFiles = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
    $WrittenPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($Entry in @($LauncherConfiguration.Entries | Where-Object { $null -ne $_ })) {
      if (-not (Test-Install4jExtractionMatch -Path $Entry.Name -Name $Name)) { continue }
      if ($Entry.Length -gt $MaximumExpandedBytes) {
        throw "The install4j startup file '$($Entry.Name)' exceeds the $MaximumExpandedBytes-byte limit"
      }

      $OutputPath = Resolve-Install4jExtractionPath -DestinationPath $DestinationPath -RelativePath $Entry.Name
      if (-not $WrittenPaths.Add($OutputPath)) { throw "The install4j installer contains a duplicate output path: $($Entry.Name)" }
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
      if ($Entry.Name -ieq '0.dat') {
        foreach ($ExtractedFile in Expand-Install4jLzmaZipEntry -Path $InstallerPath -Entry $Entry -DestinationPath $DestinationPath -Name $Name -MaximumExpandedBytes $MaximumExpandedBytes) {
          if ($WrittenPaths.Add($ExtractedFile.FullName)) { $ExtractedFiles.Add($ExtractedFile) }
        }
        continue
      }

      if (-not (Test-Install4jExtractionMatch -Path $Entry.Name -Name $Name)) { continue }
      if ($Entry.Length -gt $MaximumExpandedBytes) {
        throw "The install4j embedded file '$($Entry.Name)' exceeds the $MaximumExpandedBytes-byte limit"
      }

      $OutputPath = Resolve-Install4jExtractionPath -DestinationPath $DestinationPath -RelativePath $Entry.Name
      if (-not $WrittenPaths.Add($OutputPath)) { throw "The install4j installer contains a duplicate output path: $($Entry.Name)" }
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
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-Install4jInfo -Path $Path).Protocols }
}

function Read-FileExtensionsFromInstall4j {
  <#
  .SYNOPSIS
    Read Windows file-association extensions from install4j configuration
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
    if ([string]::IsNullOrWhiteSpace($Info.ProductName)) { throw 'The install4j installer does not expose a product name value' }
    return $Info.ProductName
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

Export-ModuleMember -Function Get-Install4jInfo, Expand-Install4jInstaller, Test-Install4jInstaller, Read-ProtocolsFromInstall4j, Read-FileExtensionsFromInstall4j, Read-ProductCodeFromInstall4j, Read-ProductVersionFromInstall4j, Read-ProductNameFromInstall4j, Read-PublisherFromInstall4j, Read-ScopeFromInstall4j, Read-SupportedScopesFromInstall4j, Test-Install4jDualScope
