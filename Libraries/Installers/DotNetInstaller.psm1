# SPDX-License-Identifier: Apache-2.0
# dotNetInstaller configuration, resource-cabinet, and nested-command parser.
#
# Source and format references:
# - https://github.com/dotnetinstaller/dotnetinstaller
# - InstallerLib/InstallerLinker.cs
# - dotNetInstaller/ConfigFileManager.cpp
# - dotNetInstallerLib/ExtractComponent.cpp
# - dotNetInstallerLib/InstallUILevel.cpp
#
# PE image
# +-- CUSTOM/RES_CONFIGURATION       bounded XML configuration
# |   `-- reference configurations   optional caller-supplied bounded XML
# +-- CUSTOM/RES_CAB_LIST            optional UTF-16 display summary
# `-- RES_CAB resources
#     +-- before 2009-12-01          SETUP_1, SETUP_2, ...
#     +-- 2009-12-01 through 12-08  SETUP_1 plus SETUP_<ID>_1
#     `-- 2009-12-09 and later       the same names with .CAB suffixes
#
# Each RES_CAB record is a complete or continued Microsoft Cabinet member.
# Configuration owns execution semantics; RES_CAB_LIST may truncate its file
# list and therefore remains display evidence rather than a payload authority.
# Downloaded and sidecar payloads are never fetched. Explicit CompanionPath
# inputs participate in command and nested-installer resolution as local files.

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

function Get-DotNetInstallerPropertyValue {
  <#
  .SYNOPSIS
    Read an optional object property without relying on StrictMode-sensitive access.
  .PARAMETER InputObject
    Dictionary or object containing the property.
  .PARAMETER Name
    Property name to read.
  #>
  param (
    [AllowNull()][object]$InputObject,
    [Parameter(Mandatory)][string]$Name
  )

  if ($null -eq $InputObject) { return $null }
  if ($InputObject -is [Collections.IDictionary]) { return $InputObject.Contains($Name) ? $InputObject[$Name] : $null }
  $Property = $InputObject.PSObject.Properties[$Name]
  return $null -eq $Property ? $null : $Property.Value
}

function Get-DotNetInstallerXmlAttribute {
  <#
  .SYNOPSIS
    Read one optional dotNetInstaller XML attribute.
  .PARAMETER Element
    XML element containing the attribute.
  .PARAMETER Name
    Exact attribute name.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][System.Xml.XmlElement]$Element,
    [Parameter(Mandatory)][string]$Name
  )

  if ($Element.HasAttribute($Name)) { return $Element.GetAttribute($Name) }
  return $null
}

function Get-DotNetInstallerFirstXmlAttribute {
  <#
  .SYNOPSIS
    Read the first authored value from a current or legacy attribute name.
  .PARAMETER Element
    XML element containing the attributes.
  .PARAMETER Name
    Attribute names in runtime precedence order.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][System.Xml.XmlElement]$Element,
    [Parameter(Mandatory)][string[]]$Name
  )

  foreach ($Candidate in $Name) {
    if ($Element.HasAttribute($Candidate)) { return $Element.GetAttribute($Candidate) }
  }
  return $null
}

function ConvertTo-DotNetInstallerAttributeMap {
  <#
  .SYNOPSIS
    Copy XML attributes into a deterministic dictionary.
  .PARAMETER Element
    XML element whose authored attributes are retained.
  #>
  [OutputType([Collections.Specialized.OrderedDictionary])]
  param ([Parameter(Mandatory)][System.Xml.XmlElement]$Element)

  $Result = [ordered]@{}
  foreach ($Attribute in $Element.Attributes) { $Result[$Attribute.Name] = $Attribute.Value }
  return $Result
}

function Get-DotNetInstallerChildElement {
  <#
  .SYNOPSIS
    Enumerate direct children while accepting the legacy grouped XML schema.
  .PARAMETER Element
    Parent XML element.
  .PARAMETER Name
    Child element name to return.
  .PARAMETER LegacyContainer
    Optional pre-February-2009 plural container for the requested records.
  #>
  [OutputType([System.Xml.XmlElement[]])]
  param (
    [Parameter(Mandatory)][System.Xml.XmlElement]$Element,
    [Parameter(Mandatory)][string]$Name,
    [string]$LegacyContainer
  )

  foreach ($Child in $Element.ChildNodes) {
    if ($Child -isnot [System.Xml.XmlElement]) { continue }
    if ($Child.LocalName -ceq $Name) {
      $Child
    } elseif ($LegacyContainer -and $Child.LocalName -ceq $LegacyContainer) {
      foreach ($GroupedChild in $Child.ChildNodes) {
        if ($GroupedChild -is [System.Xml.XmlElement] -and $GroupedChild.LocalName -ceq $Name) { $GroupedChild }
      }
    }
  }
}

function ConvertTo-DotNetInstallerBoolean {
  <#
  .SYNOPSIS
    Parse a source-authored Boolean using the corresponding runtime default.
  .PARAMETER Value
    Optional XML value.
  .PARAMETER DefaultValue
    Value used by the runtime when the attribute is absent or malformed.
  #>
  [OutputType([bool])]
  param (
    [AllowNull()][AllowEmptyString()][string]$Value,
    [Parameter(Mandatory)][bool]$DefaultValue
  )

  if ([string]::IsNullOrWhiteSpace($Value)) { return $DefaultValue }
  $Parsed = $false
  return [bool]::TryParse($Value, [ref]$Parsed) ? $Parsed : $DefaultValue
}

function ConvertTo-DotNetInstallerNormalizedId {
  <#
  .SYNOPSIS
    Convert a component ID to InstallerLinker's cabinet-resource token.
  .PARAMETER Id
    Component ID from configuration XML.
  #>
  [OutputType([string])]
  param ([AllowNull()][AllowEmptyString()][string]$Id)

  if ([string]::IsNullOrEmpty($Id)) { return '' }
  $Builder = [Text.StringBuilder]::new($Id.Length)
  foreach ($Character in $Id.ToCharArray()) {
    $null = $Builder.Append([char]::IsLetterOrDigit($Character) ? [char]::ToUpperInvariant($Character) : '_')
  }
  return $Builder.ToString()
}

function ConvertFrom-DotNetInstallerConfigurationByte {
  <#
  .SYNOPSIS
    Decode one bounded RES_CONFIGURATION resource.
  .PARAMETER Bytes
    Complete resource bytes; ownership remains with the caller.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes)

  if ($Bytes.Length -eq 0) { throw 'The dotNetInstaller configuration resource is empty.' }
  $Stream = [IO.MemoryStream]::new($Bytes, $false)
  try {
    # InstallerLinker writes UTF-8. StreamReader also recognizes Unicode BOMs
    # found in hand-authored legacy configuration files.
    $Reader = [IO.StreamReader]::new($Stream, [Text.UTF8Encoding]::new($false, $true), $true, 4096, $true)
    try { return $Reader.ReadToEnd().TrimStart([char]0xFEFF).TrimEnd([char]0) } finally { $Reader.Dispose() }
  } finally {
    $Stream.Dispose()
  }
}

function Get-DotNetInstallerRuntimeCapability {
  <#
  .SYNOPSIS
    Identify command-line features compiled into the launcher runtime.
  .DESCRIPTION
    InstallerLinker replaces PE product versions with package metadata, so the
    runtime release cannot be inferred safely from FileVersion. Exact native
    command-line tokens provide source-backed capability evidence instead.
  .PARAMETER Path
    Resolved dotNetInstaller PE path.
  .PARAMETER ExpectedVersion
    Schema version to verify against an exact compiled runtime token. The
    packaged PE version is deliberately ignored because InstallerLinker
    replaces it with the application version.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [AllowNull()][AllowEmptyString()][string]$ExpectedVersion
  )

  $TokenMap = [ordered]@{
    Quiet         = 'q'
    BasicUI       = 'qb'
    ForceFullUI   = 'nq'
    Logging       = 'log'
    LogFile       = 'logfile'
    ConfigFile    = 'configfile'
    NoReboot      = 'noreboot'
    NoSplash      = 'nosplash'
    ComponentArgs = 'componentArgs'
    ControlArgs   = 'controlArgs'
    ExtractCab    = 'extractCab'
    DisplayCab    = 'displayCab'
    DisplayConfig = 'displayConfig'
  }
  $Detected = [ordered]@{}
  $Stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
  try {
    $Layout = Get-PELayout -Stream $Stream
    if (-not $Layout) { throw 'The file is not a supported PE image.' }
    # Command-line literals live in executable/data sections. Excluding .rsrc
    # avoids rescanning potentially multi-gigabyte embedded cabinet resources.
    $Sections = @($Layout.Sections | Where-Object { $_.Name -cne '.rsrc' -and $_.RawSize -gt 0 })
    foreach ($Pair in $TokenMap.GetEnumerator()) {
      $Found = $false
      foreach ($Section in $Sections) {
        foreach ($Encoding in @([Text.Encoding]::Unicode, [Text.Encoding]::ASCII)) {
          $Pattern = $Encoding.GetBytes($Pair.Value + [char]0)
          if ((Find-BinaryPattern -Stream $Stream -Pattern $Pattern -StartOffset $Section.RawOffset -Length $Section.RawSize -Maximum 1).Count -gt 0) {
            $Found = $true
            break
          }
        }
        if ($Found) { break }
      }
      $Detected[$Pair.Key] = $Found
    }
    $RuntimeVersion = $null
    if (-not [string]::IsNullOrWhiteSpace($ExpectedVersion)) {
      # ConfigFileManager compares schema.version with VERSION_VALUE. Require
      # that same exact token in executable data before reporting a runtime
      # version; arbitrary version-resource strings are application metadata.
      foreach ($Section in $Sections) {
        foreach ($Encoding in @([Text.Encoding]::Unicode, [Text.Encoding]::ASCII)) {
          $Pattern = $Encoding.GetBytes($ExpectedVersion + [char]0)
          if ((Find-BinaryPattern -Stream $Stream -Pattern $Pattern -StartOffset $Section.RawOffset -Length $Section.RawSize -Maximum 1).Count -gt 0) {
            $RuntimeVersion = $ExpectedVersion
            break
          }
        }
        if ($RuntimeVersion) { break }
      }
    }
  } finally {
    $Stream.Dispose()
  }

  $CapabilityProfile = if (-not $Detected.Quiet) {
    'Unknown'
  } elseif ($Detected.NoReboot) {
    'RebootControl'
  } elseif ($Detected.NoSplash) {
    'SplashControl'
  } elseif ($Detected.BasicUI) {
    'BasicUI'
  } else {
    'LegacyQuiet'
  }
  $Result = [ordered]@{
    Profile         = $CapabilityProfile
    RuntimeVersion  = $RuntimeVersion
    VersionEvidence = $RuntimeVersion ? 'SchemaAndCompiledToken' : $null
  }
  foreach ($Name in $Detected.Keys) { $Result[$Name] = $Detected[$Name] }
  return [pscustomobject]$Result
}

function Get-DotNetInstallerModeValue {
  <#
  .SYNOPSIS
    Resolve a mode-specific value using InstallUILevelSetting::GetCommand order.
  .PARAMETER Element
    Component containing full, basic, and silent attribute variants.
  .PARAMETER BaseName
    Unsuffixed attribute name.
  .PARAMETER Mode
    Interactive, Basic, or Silent runtime mode.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][System.Xml.XmlElement]$Element,
    [Parameter(Mandatory)][string]$BaseName,
    [Parameter(Mandatory)][ValidateSet('Interactive', 'Basic', 'Silent')][string]$Mode
  )

  $Candidates = switch ($Mode) {
    'Basic' { @("${BaseName}_basic", "${BaseName}_silent", $BaseName) }
    'Silent' { @("${BaseName}_silent", "${BaseName}_basic", $BaseName) }
    default { @($BaseName) }
  }
  foreach ($AttributeName in $Candidates) {
    $Value = Get-DotNetInstallerXmlAttribute -Element $Element -Name $AttributeName
    if ([string]::IsNullOrEmpty($Value)) { continue }
    $SourceMode = if ($AttributeName.EndsWith('_silent', [StringComparison]::Ordinal)) {
      'Silent'
    } elseif ($AttributeName.EndsWith('_basic', [StringComparison]::Ordinal)) {
      'Basic'
    } else {
      'Interactive'
    }
    return [pscustomobject][ordered]@{
      Value         = $Value
      RequestedMode = $Mode
      SourceMode    = $SourceMode
      AttributeName = $AttributeName
      IsFallback    = $SourceMode -cne $Mode
    }
  }
  return [pscustomobject][ordered]@{
    Value = $null; RequestedMode = $Mode; SourceMode = $null; AttributeName = $null; IsFallback = $false
  }
}

function Test-DotNetInstallerUnattendedCommand {
  <#
  .SYNOPSIS
    Determine whether a selected nested command proves unattended behavior.
  .PARAMETER Type
    dotNetInstaller component type.
  .PARAMETER Mode
    Requested outer UI mode.
  .PARAMETER Resolution
    Mode-value resolutions used to assemble the command.
  .PARAMETER CommandLine
    Complete nested command line used as secondary switch evidence.
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory)][string]$Type,
    [Parameter(Mandatory)][ValidateSet('Interactive', 'Basic', 'Silent')][string]$Mode,
    [AllowEmptyCollection()][psobject[]]$Resolution = @(),
    [AllowNull()][AllowEmptyString()][string]$CommandLine
  )

  if ($Mode -ceq 'Interactive' -or $Type -ceq 'openfile') { return $false }
  $SourceModes = @($Resolution | Where-Object Value | ForEach-Object SourceMode | Sort-Object -Unique)
  if ($Mode -ceq 'Silent' -and $SourceModes -contains 'Silent') { return $true }
  if ($Mode -ceq 'Basic' -and ($SourceModes -contains 'Basic' -or $SourceModes -contains 'Silent')) { return $true }
  # Full attributes can still contain an explicit unattended switch. Keep this
  # test bounded to common exact switch tokens instead of guessing from names.
  $Pattern = if ($Mode -ceq 'Silent') {
    '(?i)(?:^|\s)(?:/qn!?|/quiet|/silent|/s|-s|--silent|--quiet)(?=\s|$)'
  } else {
    '(?i)(?:^|\s)(?:/qn!?|/qb[!+-]?|/quiet|/passive|/silent|/s|-s|--silent|--quiet)(?=\s|$)'
  }
  return $CommandLine -match $Pattern
}

function ConvertTo-DotNetInstallerNodeEvidence {
  <#
  .SYNOPSIS
    Convert a bounded configuration subtree to inert structured evidence.
  .PARAMETER Element
    Root element of an installed check or embedded-file record.
  .PARAMETER Depth
    Current recursion depth, bounded to reject malicious XML nesting.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][System.Xml.XmlElement]$Element,
    [ValidateRange(0, 32)][int]$Depth = 0
  )

  if ($Depth -ge 32) { throw 'The dotNetInstaller configuration nesting exceeds the parser limit.' }
  $Children = [Collections.Generic.List[object]]::new()
  foreach ($Child in $Element.ChildNodes) {
    if ($Child -is [System.Xml.XmlElement]) { $Children.Add((ConvertTo-DotNetInstallerNodeEvidence -Element $Child -Depth ($Depth + 1))) }
  }
  return [pscustomobject][ordered]@{
    Name       = $Element.LocalName
    Attributes = ConvertTo-DotNetInstallerAttributeMap -Element $Element
    Children   = $Children.ToArray()
  }
}

function Get-DotNetInstallerDownloadEvidence {
  <#
  .SYNOPSIS
    Read download and local-copy records from a download dialog.
  .PARAMETER Parent
    Component or reference configuration containing the dialog.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][System.Xml.XmlElement]$Parent)

  foreach ($Dialog in Get-DotNetInstallerChildElement -Element $Parent -Name 'downloaddialog') {
    $DialogAttributes = ConvertTo-DotNetInstallerAttributeMap -Element $Dialog
    foreach ($Download in Get-DotNetInstallerChildElement -Element $Dialog -Name 'download' -LegacyContainer 'downloads') {
      $SourceUrl = Get-DotNetInstallerXmlAttribute -Element $Download -Name 'sourceurl'
      $DestinationPath = Get-DotNetInstallerXmlAttribute -Element $Download -Name 'destinationpath'
      $DestinationName = Get-DotNetInstallerXmlAttribute -Element $Download -Name 'destinationfilename'
      if ([string]::IsNullOrWhiteSpace($DestinationName) -and $SourceUrl) {
        try { $DestinationName = [IO.Path]::GetFileName(([Uri]$SourceUrl).AbsolutePath) } catch { $DestinationName = [IO.Path]::GetFileName($SourceUrl) }
      }
      $Destination = if ($DestinationPath -and $DestinationName) { "$($DestinationPath.TrimEnd('\\'))\$DestinationName" } else { $DestinationName }
      [pscustomobject][ordered]@{
        ComponentName       = Get-DotNetInstallerXmlAttribute -Element $Download -Name 'componentname'
        SourceUrl           = $SourceUrl
        SourcePath          = Get-DotNetInstallerXmlAttribute -Element $Download -Name 'sourcepath'
        DestinationPath     = $DestinationPath
        DestinationFileName = $DestinationName
        Destination         = $Destination
        AlwaysDownload      = ConvertTo-DotNetInstallerBoolean -Value (Get-DotNetInstallerXmlAttribute -Element $Download -Name 'alwaysdownload') -DefaultValue $true
        ClearCache          = ConvertTo-DotNetInstallerBoolean -Value (Get-DotNetInstallerXmlAttribute -Element $Download -Name 'clear_cache') -DefaultValue $false
        DialogAttributes    = $DialogAttributes
        Attributes          = ConvertTo-DotNetInstallerAttributeMap -Element $Download
      }
    }
  }
}

function ConvertTo-DotNetInstallerResolutionCommandLine {
  <#
  .SYNOPSIS
    Remove source-backed runtime path prefixes before static payload matching.
  .PARAMETER CommandLine
    Authored component or completion command line.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][AllowEmptyString()][string]$CommandLine)

  return $CommandLine -replace '(?i)#(?:CABPATH|TEMPPATH|APPPATH|STARTPATH)[/\\]', ''
}

function Get-DotNetInstallerCommandCandidatePath {
  <#
  .SYNOPSIS
    Select embedded or companion candidates according to the command's runtime path variable.
  .PARAMETER CommandLine
    Authored command line containing an optional dotNetInstaller path variable.
  .PARAMETER EmbeddedPath
    Logical paths extracted beneath #CABPATH.
  .PARAMETER CompanionPath
    Resolved local files supplied for #TEMPPATH, #APPPATH, or #STARTPATH.
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Mandatory)][AllowEmptyString()][string]$CommandLine,
    [AllowEmptyCollection()][string[]]$EmbeddedPath = @(),
    [AllowEmptyCollection()][string[]]$CompanionPath = @()
  )

  if ($CommandLine -match '(?i)#CABPATH[/\\]') { return $EmbeddedPath }
  if ($CommandLine -match '(?i)#(?:TEMPPATH|APPPATH|STARTPATH)[/\\]') { return $CompanionPath }
  return @($EmbeddedPath + $CompanionPath)
}

function Get-DotNetInstallerComponentCommand {
  <#
  .SYNOPSIS
    Build source-accurate install commands for one component.
  .PARAMETER Component
    Component XML element.
  .PARAMETER ArchiveEntry
    Embedded or downloaded paths available to command resolution.
  .PARAMETER Sequence
    Install or uninstall command sequence selected by InstallerSession.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][System.Xml.XmlElement]$Component,
    [string[]]$ArchiveEntry = @(),
    [ValidateSet('Install', 'Uninstall')][string]$Sequence = 'Install'
  )

  $TypeValue = Get-DotNetInstallerXmlAttribute -Element $Component -Name 'type'
  if ([string]::IsNullOrWhiteSpace($TypeValue)) { return }
  $Type = $TypeValue.ToLowerInvariant()
  foreach ($Mode in @('Interactive', 'Basic', 'Silent')) {
    $CommandLine = $null
    $Resolutions = [Collections.Generic.List[object]]::new()
    switch ($Type) {
      'msi' {
        $Package = if ($Sequence -ceq 'Uninstall') {
          $UninstallPackage = Get-DotNetInstallerXmlAttribute -Element $Component -Name 'uninstall_package'
          [string]::IsNullOrEmpty($UninstallPackage) ? (Get-DotNetInstallerXmlAttribute -Element $Component -Name 'package') : $UninstallPackage
        } else {
          Get-DotNetInstallerXmlAttribute -Element $Component -Name 'package'
        }
        $ParameterBaseName = $Sequence -ceq 'Uninstall' ? 'uninstall_cmdparameters' : 'cmdparameters'
        $ParameterResolution = Get-DotNetInstallerModeValue -Element $Component -BaseName $ParameterBaseName -Mode $Mode
        $Resolutions.Add($ParameterResolution)
        $Action = $Sequence -ceq 'Uninstall' ? '/x' : '/i'
        if ($Package) { $CommandLine = "msiexec.exe $Action `"$Package`" $($ParameterResolution.Value)".Trim() }
      }
      'msp' {
        $Patch = if ($Sequence -ceq 'Uninstall') {
          $UninstallPatch = Get-DotNetInstallerXmlAttribute -Element $Component -Name 'uninstall_patch'
          [string]::IsNullOrEmpty($UninstallPatch) ? (Get-DotNetInstallerXmlAttribute -Element $Component -Name 'patch') : $UninstallPatch
        } else {
          Get-DotNetInstallerXmlAttribute -Element $Component -Name 'patch'
        }
        $Package = if ($Sequence -ceq 'Uninstall') {
          Get-DotNetInstallerXmlAttribute -Element $Component -Name 'uninstall_package'
        } else {
          Get-DotNetInstallerXmlAttribute -Element $Component -Name 'package'
        }
        $ParameterBaseName = $Sequence -ceq 'Uninstall' ? 'uninstall_cmdparameters' : 'cmdparameters'
        $ParameterResolution = Get-DotNetInstallerModeValue -Element $Component -BaseName $ParameterBaseName -Mode $Mode
        $Resolutions.Add($ParameterResolution)
        $Parameters = [string]$ParameterResolution.Value
        if ($Sequence -ceq 'Install') {
          $AdministrativePackage = $Package ? " /a `"$Package`"" : ''
          $Reinstall = Get-DotNetInstallerXmlAttribute -Element $Component -Name 'reinstall'
          $ReinstallMode = Get-DotNetInstallerXmlAttribute -Element $Component -Name 'reinstallmode'
          if ($Reinstall) { $Parameters = "$Parameters REINSTALL=$Reinstall".Trim() }
          if ($ReinstallMode) { $Parameters = "$Parameters REINSTALLMODE=$ReinstallMode".Trim() }
          if ($Patch) { $CommandLine = "msiexec.exe /p `"$Patch`"$AdministrativePackage $Parameters".Trim() }
        } elseif ($Patch) {
          $AffectedPackage = $Package ? " /package `"$Package`"" : ''
          $CommandLine = "msiexec.exe /uninstall `"$Patch`"$AffectedPackage $Parameters".Trim()
        }
      }
      'msu' {
        if ($Sequence -ceq 'Uninstall') { continue }
        $Package = Get-DotNetInstallerXmlAttribute -Element $Component -Name 'package'
        $ParameterResolution = Get-DotNetInstallerModeValue -Element $Component -BaseName 'cmdparameters' -Mode $Mode
        $Resolutions.Add($ParameterResolution)
        if ($Package) { $CommandLine = "wusa.exe `"$Package`" $($ParameterResolution.Value)".Trim() }
      }
      'exe' {
        $ExecutableBaseName = $Sequence -ceq 'Uninstall' ? 'uninstall_executable' : 'executable'
        $ParameterBaseName = $Sequence -ceq 'Uninstall' ? 'uninstall_exeparameters' : 'exeparameters'
        $ExecutableResolution = Get-DotNetInstallerModeValue -Element $Component -BaseName $ExecutableBaseName -Mode $Mode
        $ParameterResolution = Get-DotNetInstallerModeValue -Element $Component -BaseName $ParameterBaseName -Mode $Mode
        $Resolutions.Add($ExecutableResolution)
        $Resolutions.Add($ParameterResolution)
        if ($ExecutableResolution.Value) { $CommandLine = "`"$($ExecutableResolution.Value)`" $($ParameterResolution.Value)".Trim() }
      }
      'cmd' {
        $CommandBaseName = $Sequence -ceq 'Uninstall' ? 'uninstall_command' : 'command'
        $CommandResolution = Get-DotNetInstallerModeValue -Element $Component -BaseName $CommandBaseName -Mode $Mode
        $Resolutions.Add($CommandResolution)
        $CommandLine = $CommandResolution.Value
      }
      'openfile' {
        if ($Sequence -ceq 'Uninstall') { continue }
        $CommandLine = Get-DotNetInstallerXmlAttribute -Element $Component -Name 'file'
      }
    }
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { continue }
    # Runtime path variables select a physical namespace. This first parse may
    # know only supplied companions; context creation resolves it again after
    # cabinet catalogs are available.
    $ResolutionCommandLine = ConvertTo-DotNetInstallerResolutionCommandLine -CommandLine $CommandLine
    $UsedResolutions = @($Resolutions | Where-Object Value)
    $SourceModes = @($UsedResolutions.SourceMode | Sort-Object -Unique)
    [pscustomobject][ordered]@{
      Sequence                = $Sequence
      Mode                    = $Mode
      RawCommandLine          = $CommandLine
      Command                 = Resolve-BootstrapperCommand -CommandLine $ResolutionCommandLine -CandidatePath $ArchiveEntry
      ModeSource              = $SourceModes.Count -eq 1 ? $SourceModes[0] : ($SourceModes.Count -gt 1 ? 'Mixed' : 'Interactive')
      ModeAttributes          = @($UsedResolutions.AttributeName)
      UsesModeFallback        = @($UsedResolutions | Where-Object IsFallback).Count -gt 0
      IsUnattendedRouteProven = Test-DotNetInstallerUnattendedCommand -Type $Type -Mode $Mode -Resolution $UsedResolutions -CommandLine $CommandLine
    }
  }
}

function Get-DotNetInstallerProductCheckEvidence {
  <#
  .SYNOPSIS
    Project product and upgrade-code installed checks from an inert check tree.
  .PARAMETER Node
    Structured installed-check node returned by ConvertTo-DotNetInstallerNodeEvidence.
  .PARAMETER ComponentId
    Owning component identifier used to preserve routing context.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][psobject]$Node,
    [AllowNull()][AllowEmptyString()][string]$ComponentId
  )

  if ($Node.Name -ceq 'installedcheck' -and $Node.Attributes.type -ceq 'check_product') {
    [pscustomobject][ordered]@{
      ComponentId   = $ComponentId
      Id            = $Node.Attributes.id
      IdType        = $Node.Attributes.id_type
      PropertyName  = $Node.Attributes.propertyname
      PropertyValue = $Node.Attributes.propertyvalue
      Comparison    = $Node.Attributes.comparison
      DefaultValue  = $Node.Attributes.defaultvalue
    }
  }
  foreach ($Child in @($Node.Children)) {
    Get-DotNetInstallerProductCheckEvidence -Node $Child -ComponentId $ComponentId
  }
}

function Get-DotNetInstallerCompleteCommand {
  <#
  .SYNOPSIS
    Resolve post-install complete commands for every UI mode.
  .PARAMETER Configuration
    Install-configuration XML element.
  .PARAMETER ArchiveEntry
    Embedded or downloaded paths available to command resolution.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][System.Xml.XmlElement]$Configuration,
    [string[]]$ArchiveEntry = @()
  )

  foreach ($Mode in @('Interactive', 'Basic', 'Silent')) {
    $Resolution = Get-DotNetInstallerModeValue -Element $Configuration -BaseName 'complete_command' -Mode $Mode
    if ([string]::IsNullOrWhiteSpace($Resolution.Value)) { continue }
    $ResolutionCommandLine = ConvertTo-DotNetInstallerResolutionCommandLine -CommandLine $Resolution.Value
    [pscustomobject][ordered]@{
      Mode             = $Mode
      RawCommandLine   = $Resolution.Value
      Command          = Resolve-BootstrapperCommand -CommandLine $ResolutionCommandLine -CandidatePath $ArchiveEntry
      ModeSource       = $Resolution.SourceMode
      ModeAttribute    = $Resolution.AttributeName
      UsesModeFallback = $Resolution.IsFallback
    }
  }
}

function ConvertFrom-DotNetInstallerConfiguration {
  <#
  .SYNOPSIS
    Parse dotNetInstaller configuration XML without executing referenced content.
  .PARAMETER Content
    Complete bounded configuration XML text.
  .PARAMETER ArchiveEntry
    Embedded or downloaded paths used to resolve configured commands.
  .PARAMETER ConfigurationIndexOffset
    Starting global configuration index when this document is a nested reference.
  .PARAMETER ConfigurationSource
    Inert source label retained on configurations, components, and references.
  .PARAMETER ReferenceDepth
    Zero-based reference nesting depth used for provenance and recursion limits.
  .LINK
    https://github.com/dotnetinstaller/dotnetinstaller/blob/master/dotNetInstaller/ConfigFileManager.cpp
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Content,
    [string[]]$ArchiveEntry = @(),
    [ValidateRange(0, 1048575)][int]$ConfigurationIndexOffset = 0,
    [string]$ConfigurationSource = '<memory>',
    [ValidateRange(0, 10)][int]$ReferenceDepth = 0
  )

  $Document = Read-BoundedXmlDocument -Content $Content -MaximumCharacters 16777216
  if (-not $Document.DocumentElement -or $Document.DocumentElement.LocalName -cne 'configurations') {
    throw 'The XML root is not a dotNetInstaller configurations document.'
  }

  $Root = $Document.DocumentElement
  # XmlDocument is already bounded by character count. Bound record counts as a
  # separate defense against tiny, deeply repetitive documents that would cause
  # excessive PowerShell object allocation.
  if ($Document.SelectNodes('//*').Count -gt 65536) { throw 'The dotNetInstaller configuration exceeds the XML element limit.' }
  $GroupedNodes = @($Root.SelectNodes('.//components|.//embedfiles|.//downloads'))
  $Components = [Collections.Generic.List[object]]::new()
  $Configurations = [Collections.Generic.List[object]]::new()
  $References = [Collections.Generic.List[object]]::new()
  $AllDownloads = [Collections.Generic.List[object]]::new()
  $AllControls = [Collections.Generic.List[object]]::new()
  $ProductChecks = [Collections.Generic.List[object]]::new()
  $ConfigurationIndex = $ConfigurationIndexOffset

  $ConfigurationNodes = @(Get-DotNetInstallerChildElement -Element $Root -Name 'configuration')
  if ($ConfigurationNodes.Count -gt 1024) { throw 'The dotNetInstaller configuration exceeds the configuration-record limit.' }
  foreach ($Configuration in $ConfigurationNodes) {
    $ConfigurationType = Get-DotNetInstallerXmlAttribute -Element $Configuration -Name 'type'
    $ConfigurationAttributes = ConvertTo-DotNetInstallerAttributeMap -Element $Configuration
    $Downloads = @(Get-DotNetInstallerDownloadEvidence -Parent $Configuration)
    foreach ($Download in $Downloads) { $AllDownloads.Add($Download) }
    if ($AllDownloads.Count -gt 16384) { throw 'The dotNetInstaller configuration exceeds the download-record limit.' }
    $ConfigurationComponents = [Collections.Generic.List[object]]::new()
    $EmbeddedFiles = @(foreach ($Node in Get-DotNetInstallerChildElement -Element $Configuration -Name 'embedfile' -LegacyContainer 'embedfiles') { ConvertTo-DotNetInstallerNodeEvidence -Element $Node })
    $EmbeddedFolders = @(foreach ($Node in Get-DotNetInstallerChildElement -Element $Configuration -Name 'embedfolder') { ConvertTo-DotNetInstallerNodeEvidence -Element $Node })
    $Controls = @(foreach ($Node in Get-DotNetInstallerChildElement -Element $Configuration -Name 'control') { ConvertTo-DotNetInstallerNodeEvidence -Element $Node })
    foreach ($Control in $Controls) { $AllControls.Add($Control) }
    if ($AllControls.Count -gt 16384) { throw 'The dotNetInstaller configuration exceeds the control-record limit.' }
    $CompleteCommands = if ($ConfigurationType -ceq 'install') { @(Get-DotNetInstallerCompleteCommand -Configuration $Configuration -ArchiveEntry $ArchiveEntry) } else { @() }

    if ($ConfigurationType -ceq 'install') {
      foreach ($Component in Get-DotNetInstallerChildElement -Element $Configuration -Name 'component' -LegacyContainer 'components') {
        $ComponentDownloads = @(Get-DotNetInstallerDownloadEvidence -Parent $Component)
        foreach ($Download in $ComponentDownloads) { $AllDownloads.Add($Download) }
        if ($AllDownloads.Count -gt 16384) { throw 'The dotNetInstaller configuration exceeds the download-record limit.' }
        $InstalledChecks = @(foreach ($Child in $Component.ChildNodes) {
            if ($Child -is [System.Xml.XmlElement] -and $Child.LocalName -in @('installedcheck', 'installedcheckoperator')) { ConvertTo-DotNetInstallerNodeEvidence -Element $Child }
          })
        $ComponentEmbeddedFiles = @(foreach ($Node in Get-DotNetInstallerChildElement -Element $Component -Name 'embedfile' -LegacyContainer 'embedfiles') { ConvertTo-DotNetInstallerNodeEvidence -Element $Node })
        $ComponentEmbeddedFolders = @(foreach ($Node in Get-DotNetInstallerChildElement -Element $Component -Name 'embedfolder') { ConvertTo-DotNetInstallerNodeEvidence -Element $Node })
        $Id = Get-DotNetInstallerXmlAttribute -Element $Component -Name 'id'
        $DisplayName = Get-DotNetInstallerFirstXmlAttribute -Element $Component -Name @('display_name', 'description')
        if ([string]::IsNullOrWhiteSpace($Id)) { $Id = $DisplayName }
        $RequiredInstall = Get-DotNetInstallerFirstXmlAttribute -Element $Component -Name @('required_install', 'required')
        $SelectedInstall = Get-DotNetInstallerFirstXmlAttribute -Element $Component -Name @('selected_install', 'selected')
        if ($Components.Count -ge 16384) { throw 'The dotNetInstaller configuration exceeds the component-record limit.' }
        foreach ($InstalledCheck in $InstalledChecks) {
          foreach ($ProductCheck in Get-DotNetInstallerProductCheckEvidence -Node $InstalledCheck -ComponentId $Id) { $ProductChecks.Add($ProductCheck) }
        }
        $ComponentEvidence = [pscustomobject][ordered]@{
          ConfigurationIndex          = $ConfigurationIndex
          ConfigurationSource         = $ConfigurationSource
          ReferenceDepth              = $ReferenceDepth
          ConfigurationArchitecture   = Get-DotNetInstallerXmlAttribute -Element $Configuration -Name 'processor_architecture_filter'
          ConfigurationLanguage       = Get-DotNetInstallerXmlAttribute -Element $Configuration -Name 'language_id'
          ConfigurationLcidFilter     = Get-DotNetInstallerFirstXmlAttribute -Element $Configuration -Name @('lcid_filter', 'lcid')
          ConfigurationAttributes     = $ConfigurationAttributes
          Type                        = Get-DotNetInstallerXmlAttribute -Element $Component -Name 'type'
          Id                          = $Id
          CabinetKey                  = ConvertTo-DotNetInstallerNormalizedId -Id $Id
          DisplayName                 = $DisplayName
          SelectedInstall             = ConvertTo-DotNetInstallerBoolean -Value $SelectedInstall -DefaultValue $true
          RequiredInstall             = ConvertTo-DotNetInstallerBoolean -Value $RequiredInstall -DefaultValue $true
          SupportsInstall             = ConvertTo-DotNetInstallerBoolean -Value (Get-DotNetInstallerXmlAttribute -Element $Component -Name 'supports_install') -DefaultValue $true
          SelectedUninstall           = ConvertTo-DotNetInstallerBoolean -Value (Get-DotNetInstallerXmlAttribute -Element $Component -Name 'selected_uninstall') -DefaultValue $true
          RequiredUninstall           = ConvertTo-DotNetInstallerBoolean -Value (Get-DotNetInstallerXmlAttribute -Element $Component -Name 'required_uninstall') -DefaultValue $true
          SupportsUninstall           = ConvertTo-DotNetInstallerBoolean -Value (Get-DotNetInstallerXmlAttribute -Element $Component -Name 'supports_uninstall') -DefaultValue $false
          UninstallDisplayName        = Get-DotNetInstallerXmlAttribute -Element $Component -Name 'uninstall_display_name'
          OsFilter                    = Get-DotNetInstallerXmlAttribute -Element $Component -Name 'os_filter'
          OsFilterMin                 = Get-DotNetInstallerXmlAttribute -Element $Component -Name 'os_filter_min'
          OsFilterMax                 = Get-DotNetInstallerXmlAttribute -Element $Component -Name 'os_filter_max'
          LegacyOsFilterGreater       = Get-DotNetInstallerXmlAttribute -Element $Component -Name 'os_filter_greater'
          LegacyOsFilterSmaller       = Get-DotNetInstallerXmlAttribute -Element $Component -Name 'os_filter_smaller'
          OsTypeFilter                = Get-DotNetInstallerXmlAttribute -Element $Component -Name 'os_type_filter'
          LanguageFilter              = Get-DotNetInstallerXmlAttribute -Element $Component -Name 'os_filter_lcid'
          ProcessorArchitectureFilter = Get-DotNetInstallerXmlAttribute -Element $Component -Name 'processor_architecture_filter'
          DisableWow64Redirection     = ConvertTo-DotNetInstallerBoolean -Value (Get-DotNetInstallerXmlAttribute -Element $Component -Name 'disable_wow64_fs_redirection') -DefaultValue $false
          ExecutionMethod             = Get-DotNetInstallerXmlAttribute -Element $Component -Name 'execution_method'
          WorkingDirectory            = Get-DotNetInstallerXmlAttribute -Element $Component -Name 'working_directory'
          HideWindow                  = ConvertTo-DotNetInstallerBoolean -Value (Get-DotNetInstallerXmlAttribute -Element $Component -Name 'hide_window') -DefaultValue $false
          InstallDirectory            = Get-DotNetInstallerXmlAttribute -Element $Component -Name 'install_directory'
          ResponseFileSource          = Get-DotNetInstallerXmlAttribute -Element $Component -Name 'responsefile_source'
          ResponseFileTarget          = Get-DotNetInstallerXmlAttribute -Element $Component -Name 'responsefile_target'
          ResponseFileFormat          = Get-DotNetInstallerXmlAttribute -Element $Component -Name 'responsefile_format'
          UninstallResponseFileSource = Get-DotNetInstallerXmlAttribute -Element $Component -Name 'uninstall_responsefile_source'
          UninstallResponseFileTarget = Get-DotNetInstallerXmlAttribute -Element $Component -Name 'uninstall_responsefile_target'
          ReturnCodesSuccess          = Get-DotNetInstallerXmlAttribute -Element $Component -Name 'returncodes_success'
          ReturnCodesReboot           = Get-DotNetInstallerXmlAttribute -Element $Component -Name 'returncodes_reboot'
          MustReboot                  = ConvertTo-DotNetInstallerBoolean -Value (Get-DotNetInstallerXmlAttribute -Element $Component -Name 'mustreboot') -DefaultValue $false
          MustRebootRequired          = ConvertTo-DotNetInstallerBoolean -Value (Get-DotNetInstallerXmlAttribute -Element $Component -Name 'must_reboot_required') -DefaultValue $false
          AllowContinueOnError        = ConvertTo-DotNetInstallerBoolean -Value (Get-DotNetInstallerXmlAttribute -Element $Component -Name 'allow_continue_on_error') -DefaultValue $true
          DefaultContinueOnError      = ConvertTo-DotNetInstallerBoolean -Value (Get-DotNetInstallerXmlAttribute -Element $Component -Name 'default_continue_on_error') -DefaultValue $false
          FailedExecCommandContinue   = Get-DotNetInstallerXmlAttribute -Element $Component -Name 'failed_exec_command_continue'
          ShowProgressDialog          = ConvertTo-DotNetInstallerBoolean -Value (Get-DotNetInstallerXmlAttribute -Element $Component -Name 'show_progress_dialog') -DefaultValue $true
          ShowCabDialog               = ConvertTo-DotNetInstallerBoolean -Value (Get-DotNetInstallerXmlAttribute -Element $Component -Name 'show_cab_dialog') -DefaultValue $true
          HideComponentIfInstalled    = ConvertTo-DotNetInstallerBoolean -Value (Get-DotNetInstallerXmlAttribute -Element $Component -Name 'hide_component_if_installed') -DefaultValue $false
          Attributes                  = ConvertTo-DotNetInstallerAttributeMap -Element $Component
          InstalledChecks             = $InstalledChecks
          EmbeddedFiles               = $ComponentEmbeddedFiles
          EmbeddedFolders             = $ComponentEmbeddedFolders
          Downloads                   = $ComponentDownloads
          AvailableFiles              = [string[]]@()
          Commands                    = @(Get-DotNetInstallerComponentCommand -Component $Component -ArchiveEntry $ArchiveEntry)
          UninstallCommands           = @(Get-DotNetInstallerComponentCommand -Component $Component -ArchiveEntry $ArchiveEntry -Sequence Uninstall)
        }
        $ConfigurationComponents.Add($ComponentEvidence)
        $Components.Add($ComponentEvidence)
      }
    } elseif ($ConfigurationType -ceq 'reference') {
      $ConfigFile = Get-DotNetInstallerChildElement -Element $Configuration -Name 'configfile' | Select-Object -First 1
      $Reference = [pscustomobject][ordered]@{
        ConfigurationIndex  = $ConfigurationIndex
        ConfigurationSource = $ConfigurationSource
        ReferenceDepth      = $ReferenceDepth
        FileName            = $ConfigFile ? (Get-DotNetInstallerXmlAttribute -Element $ConfigFile -Name 'filename') : $null
        Downloads           = $Downloads
        Attributes          = $ConfigurationAttributes
      }
      $References.Add($Reference)
    }

    $Configurations.Add([pscustomobject][ordered]@{
        Index                  = $ConfigurationIndex
        ConfigurationSource    = $ConfigurationSource
        ReferenceDepth         = $ReferenceDepth
        Type                   = $ConfigurationType
        Attributes             = $ConfigurationAttributes
        AdministratorRequired  = ConvertTo-DotNetInstallerBoolean -Value (Get-DotNetInstallerXmlAttribute -Element $Configuration -Name 'administrator_required') -DefaultValue $false
        SupportsInstall        = ConvertTo-DotNetInstallerBoolean -Value (Get-DotNetInstallerXmlAttribute -Element $Configuration -Name 'supports_install') -DefaultValue $true
        SupportsUninstall      = ConvertTo-DotNetInstallerBoolean -Value (Get-DotNetInstallerXmlAttribute -Element $Configuration -Name 'supports_uninstall') -DefaultValue $true
        ArchitectureFilter     = Get-DotNetInstallerXmlAttribute -Element $Configuration -Name 'processor_architecture_filter'
        LcidFilter             = Get-DotNetInstallerFirstXmlAttribute -Element $Configuration -Name @('lcid_filter', 'lcid')
        LanguageId             = Get-DotNetInstallerXmlAttribute -Element $Configuration -Name 'language_id'
        OsFilter               = Get-DotNetInstallerXmlAttribute -Element $Configuration -Name 'os_filter'
        OsFilterMin            = Get-DotNetInstallerXmlAttribute -Element $Configuration -Name 'os_filter_min'
        OsFilterMax            = Get-DotNetInstallerXmlAttribute -Element $Configuration -Name 'os_filter_max'
        LegacyOsFilterGreater  = Get-DotNetInstallerXmlAttribute -Element $Configuration -Name 'os_filter_greater'
        LegacyOsFilterSmaller  = Get-DotNetInstallerXmlAttribute -Element $Configuration -Name 'os_filter_smaller'
        CompleteCommands       = $CompleteCommands
        WaitForCompleteCommand = ConvertTo-DotNetInstallerBoolean -Value (Get-DotNetInstallerXmlAttribute -Element $Configuration -Name 'wait_for_complete_command') -DefaultValue $true
        AvailableFiles         = [string[]]@()
        Components             = $ConfigurationComponents.ToArray()
        EmbeddedFiles          = $EmbeddedFiles
        EmbeddedFolders        = $EmbeddedFolders
        Controls               = $Controls
        Downloads              = $Downloads
      })
    $ConfigurationIndex++
  }

  $Schema = Get-DotNetInstallerChildElement -Element $Root -Name 'schema' | Select-Object -First 1
  $FileAttributes = [ordered]@{}
  $FileAttributesElement = Get-DotNetInstallerChildElement -Element $Root -Name 'fileattributes' | Select-Object -First 1
  if ($FileAttributesElement) {
    foreach ($FileAttribute in Get-DotNetInstallerChildElement -Element $FileAttributesElement -Name 'fileattribute') {
      $Name = Get-DotNetInstallerXmlAttribute -Element $FileAttribute -Name 'name'
      if ($Name) { $FileAttributes[$Name] = Get-DotNetInstallerXmlAttribute -Element $FileAttribute -Name 'value' }
    }
  }
  $DefaultUiLevel = Get-DotNetInstallerXmlAttribute -Element $Root -Name 'ui_level'
  $LegacySilentInstall = ConvertTo-DotNetInstallerBoolean -Value (Get-DotNetInstallerXmlAttribute -Element $Root -Name 'silent_install') -DefaultValue $false
  if ([string]::IsNullOrWhiteSpace($DefaultUiLevel)) { $DefaultUiLevel = $LegacySilentInstall ? 'silent' : 'full' }

  return [pscustomobject][ordered]@{
    ConfigurationSource    = $ConfigurationSource
    ReferenceDepth         = $ReferenceDepth
    FileVersion            = Get-DotNetInstallerXmlAttribute -Element $Root -Name 'fileversion'
    ProductVersion         = Get-DotNetInstallerXmlAttribute -Element $Root -Name 'productversion'
    SchemaVersion          = $Schema ? (Get-DotNetInstallerXmlAttribute -Element $Schema -Name 'version') : $null
    Generator              = $Schema ? (Get-DotNetInstallerXmlAttribute -Element $Schema -Name 'generator') : $null
    DefaultUiLevel         = $DefaultUiLevel
    XmlStorageRoute        = $GroupedNodes.Count -gt 0 ? 'GroupedCollections' : 'OrderedChildren'
    RootAttributes         = ConvertTo-DotNetInstallerAttributeMap -Element $Root
    FileAttributes         = $FileAttributes
    Configurations         = $Configurations.ToArray()
    References             = $References.ToArray()
    Components             = $Components.ToArray()
    Downloads              = $AllDownloads.ToArray()
    Controls               = $AllControls.ToArray()
    InstalledProductChecks = $ProductChecks.ToArray()
  }
}

function Resolve-DotNetInstallerSuppliedFile {
  <#
  .SYNOPSIS
    Resolve and deduplicate explicitly supplied configuration or payload files.
  .PARAMETER Path
    Leaf paths supplied by the caller. Directories are intentionally rejected.
  .PARAMETER MaximumFiles
    Maximum number of distinct files accepted by this parser operation.
  .PARAMETER MaximumFileBytes
    Optional per-file size limit. Zero leaves size enforcement to the consumer.
  #>
  [OutputType([System.IO.FileInfo[]])]
  param (
    [AllowEmptyCollection()][string[]]$Path = @(),
    [ValidateRange(1, 65536)][int]$MaximumFiles = 4096,
    [ValidateRange(0, [long]::MaxValue)][long]$MaximumFileBytes = 0
  )

  if ($Path.Count -gt $MaximumFiles) { throw "The supplied dotNetInstaller input exceeds the $MaximumFiles-file limit." }
  $Seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $Files = [Collections.Generic.List[System.IO.FileInfo]]::new()
  foreach ($ItemPath in $Path) {
    $ResolvedPath = Resolve-InstallerFileSystemPath -Path $ItemPath -PathType Leaf
    if (-not $Seen.Add($ResolvedPath)) { continue }
    $File = Get-Item -LiteralPath $ResolvedPath -Force
    if ($MaximumFileBytes -gt 0 -and $File.Length -gt $MaximumFileBytes) {
      throw "The supplied dotNetInstaller file exceeds the $MaximumFileBytes-byte limit: $ResolvedPath"
    }
    $Files.Add($File)
  }
  return $Files.ToArray()
}

function Find-DotNetInstallerSuppliedFileMatch {
  <#
  .SYNOPSIS
    Match one authored reference path to an explicitly supplied file.
  .PARAMETER File
    Deduplicated candidate files supplied by the caller.
  .PARAMETER Path
    Authored path after removing a dotNetInstaller runtime-path prefix.
  .OUTPUTS
    A result containing the selected FileInfo, resolution kind, and ambiguous candidates.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][AllowEmptyCollection()][System.IO.FileInfo[]]$File,
    [Parameter(Mandatory)][AllowEmptyString()][string]$Path
  )

  $NormalizedPath = $Path.Replace('/', '\').TrimStart('\')
  $Candidates = [Collections.Generic.List[object]]::new()
  foreach ($Candidate in $File) {
    $Candidates.Add([pscustomobject]@{ File = $Candidate; Normalized = $Candidate.FullName.Replace('/', '\') })
  }

  # A fully qualified authored path is authoritative. Do not let another file
  # with the same basename turn an exact match into an ambiguous result.
  if ([IO.Path]::IsPathFullyQualified($Path)) {
    $CandidateMatches = @($Candidates | Where-Object { $_.Normalized.Equals($Path.Replace('/', '\'), [StringComparison]::OrdinalIgnoreCase) })
    if ($CandidateMatches.Count -eq 1) { return [pscustomobject]@{ File = $CandidateMatches[0].File; Kind = 'Exact'; Candidates = @($CandidateMatches.File.FullName) } }
    if ($CandidateMatches.Count -gt 1) { return [pscustomobject]@{ File = $null; Kind = 'Ambiguous'; Candidates = @($CandidateMatches.File.FullName) } }
  }

  # Reference filenames normally use #TEMPPATH or #APPPATH. Compare their
  # remaining relative path to the host-path suffix before using a basename.
  if (-not [string]::IsNullOrWhiteSpace($NormalizedPath)) {
    $Suffix = '\' + $NormalizedPath
    $CandidateMatches = @($Candidates | Where-Object { $_.Normalized.EndsWith($Suffix, [StringComparison]::OrdinalIgnoreCase) })
    if ($CandidateMatches.Count -eq 1) { return [pscustomobject]@{ File = $CandidateMatches[0].File; Kind = 'Suffix'; Candidates = @($CandidateMatches.File.FullName) } }
    if ($CandidateMatches.Count -gt 1) { return [pscustomobject]@{ File = $null; Kind = 'Ambiguous'; Candidates = @($CandidateMatches.File.FullName) } }
  }

  $LeafName = [IO.Path]::GetFileName($NormalizedPath)
  $CandidateMatches = if ([string]::IsNullOrWhiteSpace($LeafName)) {
    @()
  } else {
    @($Candidates | Where-Object { $_.File.Name.Equals($LeafName, [StringComparison]::OrdinalIgnoreCase) })
  }
  if ($CandidateMatches.Count -eq 1) { return [pscustomobject]@{ File = $CandidateMatches[0].File; Kind = 'FileName'; Candidates = @($CandidateMatches.File.FullName) } }
  if ($CandidateMatches.Count -gt 1) { return [pscustomobject]@{ File = $null; Kind = 'Ambiguous'; Candidates = @($CandidateMatches.File.FullName) } }
  return [pscustomobject]@{ File = $null; Kind = 'NotFound'; Candidates = @() }
}

function Resolve-DotNetInstallerConfigurationSet {
  <#
  .SYNOPSIS
    Resolve caller-supplied reference documents and build one static configuration model.
  .PARAMETER PrimaryConfiguration
    Parsed embedded or explicitly overridden root configuration.
  .PARAMETER ReferenceFile
    Bounded XML files eligible to satisfy authored reference configurations.
  .PARAMETER ArchiveEntry
    Embedded and supplied payload paths used while parsing nested commands.
  .OUTPUTS
    The merged configuration, document evidence, and context-neutral diagnostics.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$PrimaryConfiguration,
    [AllowEmptyCollection()][System.IO.FileInfo[]]$ReferenceFile = @(),
    [AllowEmptyCollection()][string[]]$ArchiveEntry = @()
  )

  $Documents = [Collections.Generic.List[object]]::new()
  $Diagnostics = [Collections.Generic.List[object]]::new()
  $UnresolvedReferences = [Collections.Generic.List[object]]::new()
  $UsedFiles = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $LoadedFiles = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $Queue = [Collections.Generic.Queue[object]]::new()
  $PrimarySource = [string]$PrimaryConfiguration.ConfigurationSource
  $PrimaryAncestors = [Collections.Generic.List[string]]::new()
  if ([IO.Path]::IsPathFullyQualified($PrimarySource) -and [IO.File]::Exists($PrimarySource)) {
    $null = $LoadedFiles.Add($PrimarySource)
    $PrimaryAncestors.Add($PrimarySource)
  }
  $PrimaryDocument = [pscustomobject]@{ Configuration = $PrimaryConfiguration; Path = $PrimarySource; Depth = 0; IsPrimary = $true }
  $Documents.Add($PrimaryDocument)
  $Queue.Enqueue([pscustomobject]@{ Configuration = $PrimaryConfiguration; Depth = 0; Ancestors = $PrimaryAncestors.ToArray() })
  $NextConfigurationIndex = @($PrimaryConfiguration.Configurations).Count
  [long]$ReferenceBytes = 0

  while ($Queue.Count -gt 0) {
    $Current = $Queue.Dequeue()
    foreach ($Reference in @($Current.Configuration.References)) {
      $Reference | Add-Member -NotePropertyMembers ([ordered]@{
          ResolutionStatus = 'Missing'; ResolvedPath = $null; ResolvedDepth = $null
        }) -Force
      $AuthoredName = [string]$Reference.FileName
      $NormalizedName = $AuthoredName -replace '^(?i)#(?:TEMPPATH|APPPATH|CABPATH)[\\/]', ''
      $ReferenceMatch = Find-DotNetInstallerSuppliedFileMatch -File $ReferenceFile -Path $NormalizedName

      if ($ReferenceMatch.Kind -ceq 'NotFound') {
        $Reference.ResolutionStatus = 'Missing'
        $UnresolvedReferences.Add($Reference)
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'DotNetInstaller.Configuration.ReferenceMissing' -Source 'DotNetInstaller' -Message "The referenced configuration '$AuthoredName' was not supplied." -Kind Incomplete -Areas Metadata, Installability -AffectedFields @('ProductCode', 'AppsAndFeaturesEntries', 'InstallModes', 'InstallerSwitches') -Evidence ([pscustomobject]@{ FileName = $AuthoredName; Source = $Reference.ConfigurationSource })))
        continue
      }
      if ($ReferenceMatch.Kind -ceq 'Ambiguous') {
        $Reference.ResolutionStatus = 'Ambiguous'
        $UnresolvedReferences.Add($Reference)
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'DotNetInstaller.Configuration.ReferenceAmbiguous' -Source 'DotNetInstaller' -Message "Multiple supplied files match the referenced configuration '$AuthoredName'." -Kind Ambiguous -Areas Metadata, Installability -AffectedFields @('ProductCode', 'AppsAndFeaturesEntries', 'InstallModes', 'InstallerSwitches') -Evidence ([pscustomobject]@{ FileName = $AuthoredName; Candidates = @($ReferenceMatch.Candidates) })))
        continue
      }

      $SelectedFile = $ReferenceMatch.File
      $Reference.ResolvedPath = $SelectedFile.FullName
      $Reference.ResolvedDepth = $Current.Depth + 1
      $null = $UsedFiles.Add($SelectedFile.FullName)
      if ($Current.Ancestors -contains $SelectedFile.FullName) {
        $Reference.ResolutionStatus = 'Cycle'
        $UnresolvedReferences.Add($Reference)
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'DotNetInstaller.Configuration.ReferenceCycle' -Source 'DotNetInstaller' -Message "The referenced configuration '$AuthoredName' forms a cycle." -Kind Invalid -Areas Metadata, Installability -AffectedFields @('ProductCode', 'AppsAndFeaturesEntries', 'InstallModes', 'InstallerSwitches') -Evidence ([pscustomobject]@{ FileName = $AuthoredName; Path = $SelectedFile.FullName; Depth = $Current.Depth + 1 })))
        continue
      }
      if ($Current.Depth -ge 9) {
        $Reference.ResolutionStatus = 'DepthLimit'
        $UnresolvedReferences.Add($Reference)
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'DotNetInstaller.Configuration.ReferenceDepthLimit' -Source 'DotNetInstaller' -Message 'The reference configuration chain exceeds the runtime ten-level limit.' -Kind Invalid -Areas Metadata, Installability -AffectedFields @('ProductCode', 'AppsAndFeaturesEntries', 'InstallModes', 'InstallerSwitches') -Evidence ([pscustomobject]@{ FileName = $AuthoredName; Path = $SelectedFile.FullName; Depth = $Current.Depth + 1 })))
        continue
      }
      if (-not $LoadedFiles.Add($SelectedFile.FullName)) {
        $Reference.ResolutionStatus = 'Reused'
        continue
      }
      if ($Documents.Count -ge 1024) { throw 'The dotNetInstaller reference configuration set exceeds the document limit.' }
      if ($SelectedFile.Length -gt 67108864 - $ReferenceBytes) { throw 'The dotNetInstaller reference configurations exceed the 64-MiB aggregate limit.' }
      $ReferenceBytes += $SelectedFile.Length

      $ReferenceContent = Read-BoundedTextFile -Path $SelectedFile.FullName -MaximumBytes 16777216
      $ReferenceConfiguration = ConvertFrom-DotNetInstallerConfiguration -Content $ReferenceContent -ArchiveEntry $ArchiveEntry -ConfigurationIndexOffset $NextConfigurationIndex -ConfigurationSource $SelectedFile.FullName -ReferenceDepth ($Current.Depth + 1)
      $NextConfigurationIndex += @($ReferenceConfiguration.Configurations).Count
      $Reference.ResolutionStatus = 'Resolved'
      if ($PrimaryConfiguration.SchemaVersion -and $ReferenceConfiguration.SchemaVersion -and $PrimaryConfiguration.SchemaVersion -cne $ReferenceConfiguration.SchemaVersion) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'DotNetInstaller.Configuration.ReferenceSchemaMismatch' -Source 'DotNetInstaller' -Message "Referenced configuration '$AuthoredName' uses schema '$($ReferenceConfiguration.SchemaVersion)' while the primary configuration uses '$($PrimaryConfiguration.SchemaVersion)'." -Kind Mismatch -Areas Installability -AffectedFields @('InstallModes', 'InstallerSwitches') -Evidence ([pscustomobject]@{ FileName = $AuthoredName; Path = $SelectedFile.FullName; PrimarySchema = $PrimaryConfiguration.SchemaVersion; ReferenceSchema = $ReferenceConfiguration.SchemaVersion })))
      }
      $Document = [pscustomobject]@{ Configuration = $ReferenceConfiguration; Path = $SelectedFile.FullName; Depth = $Current.Depth + 1; IsPrimary = $false }
      $Documents.Add($Document)
      $Ancestors = [Collections.Generic.List[string]]::new()
      foreach ($Ancestor in @($Current.Ancestors)) { $Ancestors.Add($Ancestor) }
      $Ancestors.Add($SelectedFile.FullName)
      $Queue.Enqueue([pscustomobject]@{ Configuration = $ReferenceConfiguration; Depth = $Current.Depth + 1; Ancestors = $Ancestors.ToArray() })
    }
  }

  $Configurations = [Collections.Generic.List[object]]::new()
  $References = [Collections.Generic.List[object]]::new()
  $Components = [Collections.Generic.List[object]]::new()
  $Downloads = [Collections.Generic.List[object]]::new()
  $Controls = [Collections.Generic.List[object]]::new()
  $ProductChecks = [Collections.Generic.List[object]]::new()
  $DocumentEvidence = [Collections.Generic.List[object]]::new()
  foreach ($Document in $Documents) {
    $Configuration = $Document.Configuration
    foreach ($Item in @($Configuration.Configurations)) { $Configurations.Add($Item) }
    foreach ($Item in @($Configuration.References)) { $References.Add($Item) }
    foreach ($Item in @($Configuration.Components)) { $Components.Add($Item) }
    foreach ($Item in @($Configuration.Downloads)) { $Downloads.Add($Item) }
    foreach ($Item in @($Configuration.Controls)) { $Controls.Add($Item) }
    foreach ($Item in @($Configuration.InstalledProductChecks)) { $ProductChecks.Add($Item) }
    $DocumentEvidence.Add([pscustomobject][ordered]@{
        Path = $Document.Path; IsPrimary = $Document.IsPrimary; ReferenceDepth = $Document.Depth
        FileVersion = $Configuration.FileVersion; ProductVersion = $Configuration.ProductVersion
        SchemaVersion = $Configuration.SchemaVersion; Generator = $Configuration.Generator
        ConfigurationCount = @($Configuration.Configurations).Count; ComponentCount = @($Configuration.Components).Count
      })
  }
  $UnusedFiles = @($ReferenceFile | Where-Object { -not $UsedFiles.Contains($_.FullName) } | ForEach-Object FullName)
  if ($UnusedFiles.Count -gt 0) {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'DotNetInstaller.Configuration.ReferenceInputUnused' -Source 'DotNetInstaller' -Message 'One or more supplied reference-configuration files were not selected by the authored configuration graph.' -Kind Information -Areas Metadata -Evidence $UnusedFiles))
  }
  $StorageRoutes = @($Documents.Configuration.XmlStorageRoute | Sort-Object -Unique)
  $Merged = [pscustomobject][ordered]@{
    ConfigurationSource = $PrimaryConfiguration.ConfigurationSource; ReferenceDepth = 0
    FileVersion = $PrimaryConfiguration.FileVersion; ProductVersion = $PrimaryConfiguration.ProductVersion
    SchemaVersion = $PrimaryConfiguration.SchemaVersion; Generator = $PrimaryConfiguration.Generator
    DefaultUiLevel = $PrimaryConfiguration.DefaultUiLevel
    XmlStorageRoute = $StorageRoutes.Count -eq 1 ? $StorageRoutes[0] : 'Mixed'
    RootAttributes = $PrimaryConfiguration.RootAttributes; FileAttributes = $PrimaryConfiguration.FileAttributes
    Configurations = $Configurations.ToArray(); References = $References.ToArray(); Components = $Components.ToArray()
    Downloads = $Downloads.ToArray(); Controls = $Controls.ToArray(); InstalledProductChecks = $ProductChecks.ToArray()
    ConfigurationDocuments = $DocumentEvidence.ToArray(); UnresolvedReferences = $UnresolvedReferences.ToArray()
    UnusedReferencePaths = $UnusedFiles
    HasReferenceRisk = $UnresolvedReferences.Count -gt 0 -or @($Diagnostics | Where-Object Kind -In @('Mismatch', 'Invalid')).Count -gt 0
  }
  return [pscustomobject][ordered]@{ Configuration = $Merged; Diagnostics = $Diagnostics.ToArray() }
}

function Get-DotNetInstallerCabinetLayout {
  <#
  .SYNOPSIS
    Classify RES_CAB resources into independently extractable sets.
  .PARAMETER Resource
    PE resources whose type is RES_CAB.
  .PARAMETER Component
    Parsed components used to map normalized resource keys to authored IDs.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Resource,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Component
  )

  $ByKey = [ordered]@{}
  $Diagnostics = [Collections.Generic.List[object]]::new()
  $ComponentByKey = @{}
  foreach ($Item in $Component) {
    if ($Item.CabinetKey -and -not $ComponentByKey.ContainsKey($Item.CabinetKey)) { $ComponentByKey[$Item.CabinetKey] = $Item.Id }
  }

  foreach ($Item in $Resource) {
    $ResourceName = [string]$Item.Name
    $Match = [regex]::Match($ResourceName, '^(?i)SETUP_(?:(?<Component>.+)_)?(?<Part>[0-9]+)(?<Extension>\.CAB)?$')
    if ($Match.Success) {
      $Key = $Match.Groups['Component'].Value.ToUpperInvariant()
      $Part = [int]$Match.Groups['Part'].Value
      $HasExtension = $Match.Groups['Extension'].Success
    } else {
      $Key = "@UNKNOWN:$ResourceName"
      $Part = 1
      $HasExtension = $ResourceName.EndsWith('.CAB', [StringComparison]::OrdinalIgnoreCase)
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'DotNetInstaller.Cabinet.UnknownResourceName' -Source 'DotNetInstaller' -Message "The RES_CAB resource '$ResourceName' does not follow a source-backed dotNetInstaller cabinet name." -Kind Unsupported -Areas Extraction -Evidence $ResourceName))
    }
    if (-not $ByKey.Contains($Key)) { $ByKey[$Key] = [Collections.Generic.List[object]]::new() }
    $ByKey[$Key].Add([pscustomobject][ordered]@{
        Resource        = $Item
        ResourceName    = $ResourceName
        Part            = $Part
        HasCabExtension = $HasExtension
        CabinetFileName = $HasExtension ? $ResourceName : "$ResourceName.CAB"
      })
  }

  $Sets = [Collections.Generic.List[object]]::new()
  foreach ($Key in $ByKey.Keys) {
    $Members = @($ByKey[$Key] | Sort-Object Part, ResourceName)
    $Parts = @($Members.Part)
    if ($Parts.Count -ne @($Parts | Sort-Object -Unique).Count -or ($Parts.Count -gt 0 -and ($Parts[0] -ne 1 -or $Parts[-1] -ne $Parts.Count))) {
      throw "The dotNetInstaller cabinet resource set '$Key' has duplicate or non-contiguous parts."
    }
    $Sets.Add([pscustomobject][ordered]@{
        Key          = $Key
        ComponentId  = $ComponentByKey.ContainsKey($Key) ? $ComponentByKey[$Key] : $null
        IsGlobal     = [string]::IsNullOrEmpty($Key)
        Resources    = $Members
        Paths        = [string[]]@()
        Entries      = [object[]]@()
        ExpandedSize = [long]0
      })
  }

  $KnownSets = @($Sets | Where-Object { -not $_.Key.StartsWith('@UNKNOWN:', [StringComparison]::Ordinal) })
  $HasComponentSets = @($KnownSets | Where-Object { -not $_.IsGlobal }).Count -gt 0
  $HasExtension = @($KnownSets.Resources | Where-Object HasCabExtension).Count -gt 0
  $MissingExtension = @($KnownSets.Resources | Where-Object { -not $_.HasCabExtension }).Count -gt 0
  $Generation = if ($KnownSets.Count -eq 0) {
    'ConfigurationOnly'
  } elseif (-not $HasComponentSets) {
    $HasExtension ? 'GlobalCabinetNamed' : 'GlobalCabinetExtensionless'
  } elseif ($HasExtension -and -not $MissingExtension) {
    'PerComponentCabinetsNamed'
  } elseif ($MissingExtension -and -not $HasExtension) {
    'PerComponentCabinetsExtensionless'
  } else {
    'MixedCabinetNames'
  }
  return [pscustomobject][ordered]@{ Generation = $Generation; Sets = $Sets.ToArray(); Diagnostics = $Diagnostics.ToArray() }
}

function Open-DotNetInstallerContext {
  <#
  .SYNOPSIS
    Parse an installer and optionally enumerate each logical cabinet set.
  .PARAMETER Path
    Installer path resolved before managed PE access.
  .PARAMETER EnumerateCabinets
    Stage bounded cabinet resources and enumerate their catalogs.
  .PARAMETER SkipRuntimeCapability
    Skip executable-section token scans for detection-only callers.
  .PARAMETER ConfigurationPath
    Optional primary configuration file, equivalent to the runtime /ConfigFile override.
  .PARAMETER ReferencedConfigurationPath
    Explicit local XML files eligible to satisfy nested reference configurations.
  .PARAMETER CompanionPath
    Explicit local payload files eligible for command and nested-installer resolution.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [switch]$EnumerateCabinets,
    [switch]$SkipRuntimeCapability,
    [string]$ConfigurationPath,
    [AllowEmptyCollection()][string[]]$ReferencedConfigurationPath = @(),
    [AllowEmptyCollection()][string[]]$CompanionPath = @()
  )

  $Installer = Get-Item -LiteralPath (Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf) -Force
  $Resources = @(Get-PEResourceInfo -Path $Installer.FullName)
  $ConfigurationResources = @($Resources | Where-Object { $_.TypeName -ceq 'CUSTOM' -and $_.Name -ceq 'RES_CONFIGURATION' })
  $ReferenceFiles = @(Resolve-DotNetInstallerSuppliedFile -Path $ReferencedConfigurationPath -MaximumFiles 1024 -MaximumFileBytes 16777216)
  $CompanionFiles = @(Resolve-DotNetInstallerSuppliedFile -Path $CompanionPath -MaximumFiles 4096)
  $CompanionCandidates = @($CompanionFiles.FullName)
  if ($ConfigurationPath) {
    $PrimaryConfigurationFile = Get-Item -LiteralPath (Resolve-InstallerFileSystemPath -Path $ConfigurationPath -PathType Leaf) -Force
    $ConfigurationText = Read-BoundedTextFile -Path $PrimaryConfigurationFile.FullName -MaximumBytes 16777216
    $ConfigurationSource = $PrimaryConfigurationFile.FullName
  } else {
    if ($ConfigurationResources.Count -ne 1) { throw 'The PE does not contain exactly one dotNetInstaller CUSTOM/RES_CONFIGURATION resource.' }
    $ConfigurationText = ConvertFrom-DotNetInstallerConfigurationByte -Bytes (Read-PEResourceData -Resource $ConfigurationResources[0] -MaximumBytes 16777216)
    $ConfigurationSource = 'PE:CUSTOM/RES_CONFIGURATION'
  }
  $PrimaryConfiguration = ConvertFrom-DotNetInstallerConfiguration -Content $ConfigurationText -ArchiveEntry $CompanionCandidates -ConfigurationSource $ConfigurationSource
  $ConfigurationResolution = Resolve-DotNetInstallerConfigurationSet -PrimaryConfiguration $PrimaryConfiguration -ReferenceFile $ReferenceFiles -ArchiveEntry $CompanionCandidates
  $Configuration = $ConfigurationResolution.Configuration
  $RuntimeCapabilities = $SkipRuntimeCapability ? $null : (Get-DotNetInstallerRuntimeCapability -Path $Installer.FullName -ExpectedVersion $Configuration.SchemaVersion)
  $CabinetResources = @($Resources | Where-Object { $_.TypeName -ceq 'RES_CAB' })
  if ($CabinetResources.Count -gt 4096) { throw 'The dotNetInstaller resource table exceeds the cabinet-resource limit.' }
  [long]$EmbeddedBytes = 0
  foreach ($Resource in $CabinetResources) {
    if ([long]$Resource.Size -gt 1073741824 -or [long]$Resource.Size -gt 4294967296 - $EmbeddedBytes) { throw 'The dotNetInstaller cabinet resources exceed the configured input limit.' }
    $EmbeddedBytes += [long]$Resource.Size
  }
  $CabinetLayout = Get-DotNetInstallerCabinetLayout -Resource $CabinetResources -Component $Configuration.Components
  $TemporaryFolder = $null
  $PayloadCatalog = [Collections.Generic.List[object]]::new()

  if ($EnumerateCabinets -and $CabinetLayout.Sets.Count -gt 0) {
    $TemporaryFolder = New-TempFolder
    $SetIndex = 0
    foreach ($Set in $CabinetLayout.Sets) {
      $SetFolder = Join-Path $TemporaryFolder ('set-{0:D4}' -f $SetIndex)
      $null = New-Item -Path $SetFolder -ItemType Directory -Force
      $Paths = [Collections.Generic.List[string]]::new()
      foreach ($Member in $Set.Resources) {
        $CabinetPath = Resolve-SafeExtractionPath -DestinationPath $SetFolder -RelativePath $Member.CabinetFileName
        $null = Export-PEResourceData -Resource $Member.Resource -DestinationPath $CabinetPath -MaximumBytes 1073741824 -CollisionAction Error
        $Paths.Add($CabinetPath)
      }
      $Entries = @(Get-CabinetEntry -Path $Paths -MaximumEntries 65536)
      [long]$SetExpandedBytes = 0
      foreach ($Entry in $Entries) {
        if ([long]$Entry.Length -gt 4294967296 - $SetExpandedBytes) { throw "The dotNetInstaller cabinet set '$($Set.Key)' exceeds the catalog size limit." }
        $SetExpandedBytes += [long]$Entry.Length
        $PayloadCatalog.Add([pscustomobject][ordered]@{
            CabinetKey = $Set.Key; ComponentId = $Set.ComponentId; IsGlobal = $Set.IsGlobal
            FullName = $Entry.FullName; SourceName = $Entry.SourceName; Length = [long]$Entry.Length
          })
      }
      $Set.Paths = $Paths.ToArray()
      $Set.Entries = $Entries
      $Set.ExpandedSize = $SetExpandedBytes
      $SetIndex++
    }
  }

  if ($EnumerateCabinets) {
    # Global files are always extracted; component files are extracted only for
    # the selected component. Download destinations remain catalog evidence,
    # but only caller-supplied companion files prove their physical presence.
    # Run this even when no cabinet exists so #CABPATH cannot fall through to a
    # same-named sidecar in configuration-only media.
    foreach ($Component in $Configuration.Components) {
      $EmbeddedCandidates = [Collections.Generic.List[string]]::new()
      foreach ($Payload in $PayloadCatalog) {
        if ($Payload.IsGlobal -or $Payload.CabinetKey -ceq $Component.CabinetKey) { $EmbeddedCandidates.Add($Payload.FullName) }
      }
      $Component.AvailableFiles = @(($EmbeddedCandidates.ToArray() + $CompanionCandidates) | Select-Object -Unique)
      foreach ($Command in $Component.Commands) {
        $ResolutionCommandLine = ConvertTo-DotNetInstallerResolutionCommandLine -CommandLine $Command.RawCommandLine
        $Candidates = Get-DotNetInstallerCommandCandidatePath -CommandLine $Command.RawCommandLine -EmbeddedPath $EmbeddedCandidates.ToArray() -CompanionPath $CompanionCandidates
        $Command.Command = Resolve-BootstrapperCommand -CommandLine $ResolutionCommandLine -CandidatePath $Candidates
      }
      foreach ($Command in $Component.UninstallCommands) {
        $ResolutionCommandLine = ConvertTo-DotNetInstallerResolutionCommandLine -CommandLine $Command.RawCommandLine
        $Candidates = Get-DotNetInstallerCommandCandidatePath -CommandLine $Command.RawCommandLine -EmbeddedPath $EmbeddedCandidates.ToArray() -CompanionPath $CompanionCandidates
        $Command.Command = Resolve-BootstrapperCommand -CommandLine $ResolutionCommandLine -CandidatePath $Candidates
      }
    }
    foreach ($InstallConfiguration in $Configuration.Configurations | Where-Object Type -EQ 'install') {
      $EmbeddedCandidates = @($PayloadCatalog | Where-Object IsGlobal | ForEach-Object FullName)
      $InstallConfiguration.AvailableFiles = @(($EmbeddedCandidates + $CompanionCandidates) | Select-Object -Unique)
      foreach ($Command in $InstallConfiguration.CompleteCommands) {
        $ResolutionCommandLine = ConvertTo-DotNetInstallerResolutionCommandLine -CommandLine $Command.RawCommandLine
        $Candidates = Get-DotNetInstallerCommandCandidatePath -CommandLine $Command.RawCommandLine -EmbeddedPath $EmbeddedCandidates -CompanionPath $CompanionCandidates
        $Command.Command = Resolve-BootstrapperCommand -CommandLine $ResolutionCommandLine -CandidatePath $Candidates
      }
    }
  }

  $CabinetDirectoryResource = $Resources | Where-Object { $_.TypeName -ceq 'CUSTOM' -and $_.Name -ceq 'RES_CAB_LIST' } | Select-Object -First 1
  $CabinetDirectory = $null
  if ($CabinetDirectoryResource -and $CabinetDirectoryResource.Size -le 4194304) {
    $DirectoryBytes = Read-PEResourceData -Resource $CabinetDirectoryResource -MaximumBytes 4194304
    if ($DirectoryBytes.Length -gt 0) { $CabinetDirectory = [Text.Encoding]::Unicode.GetString($DirectoryBytes).TrimEnd([char]0) }
  }
  return [pscustomobject][ordered]@{
    Installer = $Installer; Resources = $Resources; Configuration = $Configuration; CabinetLayout = $CabinetLayout
    RuntimeCapabilities = $RuntimeCapabilities; CabinetDirectory = $CabinetDirectory
    PayloadCatalog = $PayloadCatalog.ToArray(); CompanionFiles = $CompanionFiles
    ConfigurationDiagnostics = $ConfigurationResolution.Diagnostics; TemporaryFolder = $TemporaryFolder
  }
}

function Get-DotNetInstallerNestedMsiEvidence {
  <#
  .SYNOPSIS
    Parse MSI payloads that configured install commands actually invoke.
  .PARAMETER Context
    Enumerated context whose temporary files remain caller-owned.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][psobject]$Context)

  $Results = [Collections.Generic.List[object]]::new()
  $Diagnostics = [Collections.Generic.List[object]]::new()
  $Groups = @{}
  $PayloadIndex = @{}
  $CabinetSetIndex = @{}
  foreach ($Entry in $Context.PayloadCatalog) {
    if (-not $PayloadIndex.ContainsKey($Entry.FullName)) { $PayloadIndex[$Entry.FullName] = [Collections.Generic.List[object]]::new() }
    $PayloadIndex[$Entry.FullName].Add($Entry)
  }
  foreach ($Set in $Context.CabinetLayout.Sets) { $CabinetSetIndex[$Set.Key] = $Set }
  foreach ($Component in $Context.Configuration.Components) {
    foreach ($Command in $Component.Commands) {
      $Payload = [string]$Command.Command.ExecutedPayload
      if ([string]::IsNullOrWhiteSpace($Payload) -or [IO.Path]::GetExtension($Payload) -ine '.msi') { continue }
      $CatalogEntry = @($PayloadIndex[$Payload] | Where-Object { $_.IsGlobal -or $_.CabinetKey -ceq $Component.CabinetKey } | Sort-Object @{ Expression = { $_.IsGlobal }; Ascending = $true }) | Select-Object -First 1
      $CompanionFile = @($Context.CompanionFiles | Where-Object { $_.FullName.Equals($Payload, [StringComparison]::OrdinalIgnoreCase) }) | Select-Object -First 1
      if (-not $CatalogEntry -and -not $CompanionFile) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'DotNetInstaller.NestedMsi.ExternalPayload' -Source 'DotNetInstaller' -Message "The configured MSI '$Payload' is downloaded or supplied beside the bootstrapper and cannot be parsed from this file." -Kind Incomplete -Areas Metadata, Extraction -AffectedFields @('ProductCode', 'AppsAndFeaturesEntries') -Evidence ([pscustomobject]@{ ComponentId = $Component.Id; RelativePath = $Payload })))
        continue
      }
      $Identity = $CompanionFile ? "@COMPANION`0$($CompanionFile.FullName)" : "$($CatalogEntry.CabinetKey)`0$($CatalogEntry.FullName)"
      if (-not $Groups.ContainsKey($Identity)) {
        $Groups[$Identity] = [pscustomobject][ordered]@{
          CatalogEntry = $CatalogEntry
          CabinetSet   = $CatalogEntry ? $CabinetSetIndex[$CatalogEntry.CabinetKey] : $null
          SourcePath   = $CompanionFile ? $CompanionFile.FullName : $null
          SourceKind   = $CompanionFile ? 'Companion' : 'Cabinet'
          RelativePath = $CompanionFile ? ([string]$Command.Command.PayloadReference -replace '^(?i)#(?:TEMPPATH|APPPATH|CABPATH)[\\/]', '') : $CatalogEntry.FullName
          Occurrences  = [Collections.Generic.List[object]]::new()
        }
      }
      $Groups[$Identity].Occurrences.Add([pscustomobject][ordered]@{
          ConfigurationIndex              = $Component.ConfigurationIndex
          ComponentId                     = $Component.Id
          Mode                            = $Command.Mode
          ConfigurationArchitectureFilter = $Component.ConfigurationArchitecture
          ComponentArchitectureFilter     = $Component.ProcessorArchitectureFilter
          ConfigurationLcidFilter         = $Component.ConfigurationLcidFilter
          ComponentLcidFilter             = $Component.LanguageFilter
        })
    }
  }

  if ($Groups.Count -eq 0) { return [pscustomobject][ordered]@{ Items = @(); Diagnostics = $Diagnostics.ToArray() } }
  if (@($Groups.Values | Where-Object SourceKind -EQ 'Cabinet').Count -gt 0 -and [string]::IsNullOrWhiteSpace([string]$Context.TemporaryFolder)) {
    throw 'The dotNetInstaller cabinet workspace is unavailable for nested MSI analysis.'
  }
  $GroupIndex = 0
  foreach ($Group in $Groups.Values) {
    $Payload = [string]$Group.RelativePath
    $Occurrence = $Group.Occurrences[0]
    try {
      if ($Group.SourceKind -ceq 'Companion') {
        $MsiPath = $Group.SourcePath
      } else {
        $OutputFolder = Join-Path $Context.TemporaryFolder ('nested-msi-{0:D4}' -f $GroupIndex)
        $Extracted = @(Export-CabinetEntry -Path $Group.CabinetSet.Paths -DestinationPath $OutputFolder -Name ([WildcardPattern]::Escape($Payload)) -CollisionAction Error)
        if ($Extracted.Count -ne 1) { throw "Expected one '$Payload' entry, but extracted $($Extracted.Count)." }
        $MsiPath = $Extracted[0]
      }
      # Parse one physical MSI once even when locale/configuration branches all
      # invoke it. Occurrences retain every route that selected the artifact.
      $MsiInfo = Get-MsiInstallerInfo -Path $MsiPath
      $Results.Add([pscustomobject][ordered]@{
          ConfigurationIndex = $Occurrence.ConfigurationIndex; ConfigurationIndices = @($Group.Occurrences.ConfigurationIndex | Sort-Object -Unique)
          ComponentId = $Occurrence.ComponentId; ComponentIds = @($Group.Occurrences.ComponentId | Select-Object -Unique)
          ConfigurationArchitectureFilter = $Occurrence.ConfigurationArchitectureFilter; ConfigurationArchitectureFilters = @($Group.Occurrences.ConfigurationArchitectureFilter | Where-Object { $_ } | Select-Object -Unique)
          ComponentArchitectureFilter = $Occurrence.ComponentArchitectureFilter; ComponentArchitectureFilters = @($Group.Occurrences.ComponentArchitectureFilter | Where-Object { $_ } | Select-Object -Unique)
          ConfigurationLcidFilter = $Occurrence.ConfigurationLcidFilter; ConfigurationLcidFilters = @($Group.Occurrences.ConfigurationLcidFilter | Where-Object { $_ } | Select-Object -Unique)
          ComponentLcidFilter = $Occurrence.ComponentLcidFilter; ComponentLcidFilters = @($Group.Occurrences.ComponentLcidFilter | Where-Object { $_ } | Select-Object -Unique)
          Occurrences = $Group.Occurrences.ToArray(); RelativePath = $Payload
          SourceKind = $Group.SourceKind; SourcePath = $Group.SourcePath
          CabinetKey = $Group.CatalogEntry ? $Group.CatalogEntry.CabinetKey : $null
          ProductCode = Get-DotNetInstallerPropertyValue $MsiInfo ProductCode; UpgradeCode = Get-DotNetInstallerPropertyValue $MsiInfo UpgradeCode
          DisplayName = Get-DotNetInstallerPropertyValue $MsiInfo DisplayName; DisplayVersion = Get-DotNetInstallerPropertyValue $MsiInfo DisplayVersion
          Publisher = Get-DotNetInstallerPropertyValue $MsiInfo Publisher; Scope = Get-DotNetInstallerPropertyValue $MsiInfo Scope
          DefaultInstallLocation = Get-DotNetInstallerPropertyValue $MsiInfo DefaultInstallLocation; InstallerType = Get-DotNetInstallerPropertyValue $MsiInfo InstallerType
          InstallerBuilder = Get-DotNetInstallerPropertyValue $MsiInfo InstallerBuilder; AppsAndFeaturesProductCode = Get-DotNetInstallerPropertyValue $MsiInfo AppsAndFeaturesProductCode
          AppsAndFeaturesInstallerType = Get-DotNetInstallerPropertyValue $MsiInfo AppsAndFeaturesInstallerType; AppsAndFeaturesEntries = @(Get-DotNetInstallerPropertyValue $MsiInfo AppsAndFeaturesEntries)
          WritesAppsAndFeaturesEntry = Get-DotNetInstallerPropertyValue $MsiInfo WritesAppsAndFeaturesEntry
          InstallLocationProperty = Get-DotNetInstallerPropertyValue $MsiInfo InstallLocationProperty; InstallLocationSwitch = Get-DotNetInstallerPropertyValue $MsiInfo InstallLocationSwitch
          SupportedArchitectures = @(Get-DotNetInstallerPropertyValue $MsiInfo SupportedArchitectures); RegistryAssociationInfo = Get-DotNetInstallerPropertyValue $MsiInfo RegistryAssociationInfo
          Protocols = @(Get-DotNetInstallerPropertyValue $MsiInfo Protocols); FileExtensions = @(Get-DotNetInstallerPropertyValue $MsiInfo FileExtensions)
          Dependencies = Get-DotNetInstallerPropertyValue $MsiInfo Dependencies
        })
    } catch {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'DotNetInstaller.NestedMsi.ParseFailed' -Source 'DotNetInstaller' -Message "The configured nested MSI '$Payload' could not be parsed: $($_.Exception.Message)" -Kind Incomplete -Areas Metadata -AffectedFields @('ProductCode', 'AppsAndFeaturesEntries') -Evidence ([pscustomobject]@{ ComponentIds = @($Group.Occurrences.ComponentId); RelativePath = $Payload })))
    }
    $GroupIndex++
  }
  return [pscustomobject][ordered]@{ Items = $Results.ToArray(); Diagnostics = $Diagnostics.ToArray() }
}

function Test-DotNetInstallerListFilter {
  <#
  .SYNOPSIS
    Evaluate dotNetInstaller's comma-delimited positive or negated filter.
  .PARAMETER Filter
    Architecture names or numeric LCIDs. Empty filters match every value.
  .PARAMETER Value
    Runtime value to compare case-insensitively.
  #>
  [OutputType([bool])]
  param (
    [AllowNull()][AllowEmptyString()][string]$Filter,
    [AllowNull()][AllowEmptyString()][string]$Value
  )

  if ([string]::IsNullOrWhiteSpace($Filter) -or [string]::IsNullOrWhiteSpace($Value)) { return $true }
  $Positive = [Collections.Generic.List[string]]::new()
  $Negative = [Collections.Generic.List[string]]::new()
  foreach ($RawToken in $Filter.Split(',')) {
    $Token = $RawToken.Trim()
    if ([string]::IsNullOrEmpty($Token)) { continue }
    if ($Token[0] -eq '!') {
      if ($Token.Length -gt 1) { $Negative.Add($Token.Substring(1)) }
    } else {
      $Positive.Add($Token)
    }
  }
  if ($Positive.Count -gt 0 -and $Negative.Count -gt 0) {
    throw "Ambiguous dotNetInstaller filter '$Filter' mixes positive and negative values."
  }
  if ($Positive.Count -gt 0) { return @($Positive).Where({ $_ -ieq $Value }).Count -gt 0 }
  if ($Negative.Count -gt 0) { return @($Negative).Where({ $_ -ieq $Value }).Count -eq 0 }
  return $true
}

function Get-DotNetInstallerNestedMsiSelection {
  <#
  .SYNOPSIS
    Select nested MSI metadata using dotNetInstaller runtime filters.
  .PARAMETER Info
    Result from Get-DotNetInstallerInfo.
  .PARAMETER Architecture
    WinGet target architecture. Neutral or an omitted value does not constrain
    architecture because no single native processor architecture is implied.
  .PARAMETER InstallerLocale
    BCP47 installer locale converted to the numeric Windows LCID used by the
    configuration and component filters.
  .OUTPUTS
    A selection result with Status Selected, Ambiguous, or NoMatch.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Info,
    [ValidateSet('x86', 'x64', 'arm', 'arm64', 'neutral')][string]$Architecture,
    [AllowNull()][AllowEmptyString()][string]$InstallerLocale
  )

  $TargetArchitecture = $Architecture -ceq 'neutral' ? $null : $Architecture
  $TargetLcid = $null
  if (-not [string]::IsNullOrWhiteSpace($InstallerLocale)) {
    try {
      $TargetLcid = [string][Globalization.CultureInfo]::GetCultureInfo($InstallerLocale).LCID
    } catch {
      throw "The installer locale '$InstallerLocale' cannot be converted to a Windows LCID."
    }
  }
  $SelectionCandidates = [Collections.Generic.List[object]]::new()
  foreach ($Candidate in @($Info.NestedInstallerInfos)) {
    $CandidateMatches = $false
    foreach ($Occurrence in @($Candidate.Occurrences)) {
      $ArchitectureMatches = (Test-DotNetInstallerListFilter -Filter $Occurrence.ConfigurationArchitectureFilter -Value $TargetArchitecture) -and
      (Test-DotNetInstallerListFilter -Filter $Occurrence.ComponentArchitectureFilter -Value $TargetArchitecture)
      $LocaleMatches = (Test-DotNetInstallerListFilter -Filter $Occurrence.ConfigurationLcidFilter -Value $TargetLcid) -and
      (Test-DotNetInstallerListFilter -Filter $Occurrence.ComponentLcidFilter -Value $TargetLcid)
      if ($ArchitectureMatches -and $LocaleMatches) {
        $CandidateMatches = $true
        break
      }
    }
    if ($CandidateMatches) { $SelectionCandidates.Add($Candidate) }
  }

  $Status = if ($SelectionCandidates.Count -eq 1) { 'Selected' } elseif ($SelectionCandidates.Count -eq 0) { 'NoMatch' } else { 'Ambiguous' }
  return [pscustomobject][ordered]@{
    Status          = $Status
    Selected        = $SelectionCandidates.Count -eq 1 ? $SelectionCandidates[0] : $null
    Candidates      = $SelectionCandidates.ToArray()
    Architecture    = $Architecture
    InstallerLocale = $InstallerLocale
    Lcid            = $TargetLcid
  }
}

function Get-DotNetInstallerInfo {
  <#
  .SYNOPSIS
    Read configuration, payload ownership, commands, and nested MSI evidence.
  .PARAMETER Path
    Path to the dotNetInstaller bootstrapper. The installer is never executed.
  .PARAMETER ConfigurationPath
    Optional primary configuration XML, matching the runtime /ConfigFile behavior.
  .PARAMETER ReferencedConfigurationPath
    Local XML files that may satisfy authored nested reference configurations.
  .PARAMETER CompanionPath
    Local payload files that may satisfy downloaded or sidecar command references.
  .OUTPUTS
    A standard parser result plus historical format routes and wrapper evidence.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$ConfigurationPath,
    [AllowEmptyCollection()][string[]]$ReferencedConfigurationPath = @(),
    [AllowEmptyCollection()][string[]]$CompanionPath = @()
  )

  process {
    $Context = $null
    try {
      $Context = Open-DotNetInstallerContext -Path $Path -EnumerateCabinets -ConfigurationPath $ConfigurationPath -ReferencedConfigurationPath $ReferencedConfigurationPath -CompanionPath $CompanionPath
      $Config = $Context.Configuration
      $NestedMsiResult = Get-DotNetInstallerNestedMsiEvidence -Context $Context
      $NestedMsi = @($NestedMsiResult.Items)
      $DistinctNestedMsi = $NestedMsi
      $PrimaryMsi = $DistinctNestedMsi.Count -eq 1 ? $DistinctNestedMsi[0] : $null
      $Commands = @($Config.Components | ForEach-Object { $_.Commands })
      $UninstallCommands = @($Config.Components | ForEach-Object { $_.UninstallCommands })
      $CompleteCommands = @($Config.Configurations | ForEach-Object { $_.CompleteCommands })
      $ExecutedPayloads = @(($Commands + $CompleteCommands) | Where-Object { $_.Command.ExecutedPayload } | ForEach-Object { $_.Command.ExecutedPayload } | Select-Object -Unique)
      $InstallConfigurations = @($Config.Configurations | Where-Object { $_.Type -ceq 'install' })
      $AdministratorValues = @($InstallConfigurations.AdministratorRequired | Sort-Object -Unique)
      $RequestedExecutionLevel = Get-PERequestedExecutionLevel -Path $Context.Installer.FullName
      $ElevationRequirement = if ($RequestedExecutionLevel -ceq 'requireAdministrator' -or ($AdministratorValues.Count -eq 1 -and $AdministratorValues[0])) { 'elevationRequired' } else { $null }
      $OuterVersionInfo = Get-PEVersionStringTable -Path $Context.Installer.FullName
      $InternalName = [string](Get-DotNetInstallerPropertyValue $OuterVersionInfo InternalName)
      $HasHtmlResources = @($Context.Resources | Where-Object { $_.TypeName -ceq 'HTM' }).Count -gt 0
      $LauncherKind = $HasHtmlResources -or $InternalName -match '(?i)^htmlInstaller' ? 'Html' : 'Native'
      $Diagnostics = [Collections.Generic.List[object]]::new()
      $UnresolvedFields = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
      foreach ($Diagnostic in $Context.CabinetLayout.Diagnostics) { $Diagnostics.Add($Diagnostic) }
      foreach ($Diagnostic in $Context.ConfigurationDiagnostics) {
        $Diagnostics.Add($Diagnostic)
        foreach ($AffectedField in @($Diagnostic.AffectedFields)) { $null = $UnresolvedFields.Add([string]$AffectedField) }
      }
      foreach ($Diagnostic in $NestedMsiResult.Diagnostics) {
        $Diagnostics.Add($Diagnostic)
        foreach ($AffectedField in @($Diagnostic.AffectedFields)) { $null = $UnresolvedFields.Add([string]$AffectedField) }
      }
      if ($Config.Components.Count -eq 0) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'DotNetInstaller.Configuration.NoInstallComponents' -Source 'DotNetInstaller' -Message 'No install components were found in the resolved configuration set.' -Kind Incomplete -Areas Metadata -AffectedFields @('ProductCode', 'AppsAndFeaturesEntries')))
        $null = $UnresolvedFields.Add('ProductCode')
        $null = $UnresolvedFields.Add('AppsAndFeaturesEntries')
      }
      foreach ($Component in $Config.Components) {
        foreach ($Command in $Component.Commands) {
          if (-not $Command.Command.IsResolved -and $Command.Command.PayloadReference -match '(?i)\.(exe|msi|msp|msu)$') {
            $IsAmbiguous = $Command.Command.ResolutionKind -ceq 'Ambiguous'
            $Diagnostics.Add((New-InstallerDiagnostic -Id ($IsAmbiguous ? 'DotNetInstaller.Component.PayloadAmbiguous' : 'DotNetInstaller.Component.PayloadUnresolved') -Source 'DotNetInstaller' -Message ($IsAmbiguous ? "Component '$($Component.Id)' matches multiple supplied payload files: $($Command.Command.PayloadReference)" : "Component '$($Component.Id)' references a payload absent from its embedded or supplied files: $($Command.Command.PayloadReference)") -Kind ($IsAmbiguous ? 'Ambiguous' : 'Incomplete') -Areas Metadata -AffectedFields @('ProductCode', 'AppsAndFeaturesEntries') -Evidence ([pscustomobject]@{ ComponentId = $Component.Id; Mode = $Command.Mode; PayloadReference = $Command.Command.PayloadReference; Candidates = @($Command.Command.CandidateMatches) })))
            $null = $UnresolvedFields.Add('ProductCode')
            $null = $UnresolvedFields.Add('AppsAndFeaturesEntries')
          }
        }
      }
      if ($DistinctNestedMsi.Count -gt 1) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'DotNetInstaller.NestedMsi.Multiple' -Source 'DotNetInstaller' -Message 'Multiple configured MSI payloads were found. Match configuration and component filters to the target installer entry.' -Kind Ambiguous -Areas Metadata -AffectedFields @('ProductCode', 'AppsAndFeaturesEntries') -Evidence @($DistinctNestedMsi | Select-Object ComponentId, RelativePath, ComponentArchitectureFilter, ProductCode)))
        $null = $UnresolvedFields.Add('ProductCode')
        $null = $UnresolvedFields.Add('AppsAndFeaturesEntries')
      }
      if ($PrimaryMsi) {
        if ($PrimaryMsi.WritesAppsAndFeaturesEntry -eq $true) {
          $Diagnostics.Add((New-InstallerDiagnostic -Id 'DotNetInstaller.Arp.NestedOwner' -Source 'DotNetInstaller' -Message 'The configured nested MSI supplies the visible Apps & Features identity.' -Kind Information -Areas Metadata -Evidence ([pscustomobject]@{ RelativePath = $PrimaryMsi.RelativePath; ProductCode = $PrimaryMsi.ProductCode })))
        } elseif ($PrimaryMsi.WritesAppsAndFeaturesEntry -eq $false) {
          $Diagnostics.Add((New-InstallerDiagnostic -Id 'DotNetInstaller.Arp.NestedMsiHidden' -Source 'DotNetInstaller' -Message 'The configured nested MSI suppresses its visible Apps & Features entry; no wrapper-owned ARP record is proven.' -Kind Incomplete -Areas Metadata -AffectedFields @('AppsAndFeaturesEntries') -Evidence ([pscustomobject]@{ RelativePath = $PrimaryMsi.RelativePath; ProductCode = $PrimaryMsi.ProductCode })))
          $null = $UnresolvedFields.Add('AppsAndFeaturesEntries')
        } else {
          $Diagnostics.Add((New-InstallerDiagnostic -Id 'DotNetInstaller.Arp.NestedMsiVisibilityUnknown' -Source 'DotNetInstaller' -Message 'The configured nested MSI did not provide conclusive Apps & Features visibility evidence.' -Kind Incomplete -Areas Metadata -AffectedFields @('ProductCode', 'AppsAndFeaturesEntries') -Evidence ([pscustomobject]@{ RelativePath = $PrimaryMsi.RelativePath; ProductCode = $PrimaryMsi.ProductCode })))
          $null = $UnresolvedFields.Add('AppsAndFeaturesEntries')
        }
      } elseif ($Config.Components.Count -gt 0 -and $DistinctNestedMsi.Count -eq 0) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'DotNetInstaller.Arp.OwnerUnresolved' -Source 'DotNetInstaller' -Message 'No parsed MSI owns the final Apps & Features entry. Nested EXE or custom registration behavior requires the corresponding parser or VM evidence.' -Kind Incomplete -Areas Metadata -AffectedFields @('ProductCode', 'AppsAndFeaturesEntries')))
        $null = $UnresolvedFields.Add('ProductCode')
        $null = $UnresolvedFields.Add('AppsAndFeaturesEntries')
      }
      if ($AdministratorValues.Count -gt 1) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'DotNetInstaller.Elevation.ConfigurationDependent' -Source 'DotNetInstaller' -Message 'Install configurations disagree on administrator_required; elevation depends on the selected route.' -Kind Ambiguous -Areas Installability -AffectedFields @('ElevationRequirement')))
      }

      $SupportedArchitectures = if ($PrimaryMsi) { @($PrimaryMsi.SupportedArchitectures) } else {
        @($Config.Components.ProcessorArchitectureFilter | ForEach-Object {
            foreach ($Token in ([string]$_ -split ',')) {
              switch ($Token.Trim().ToLowerInvariant()) { 'x86' { 'x86' }; 'x64' { 'x64' }; 'arm64' { 'arm64' } }
            }
          } | Select-Object -Unique)
      }
      $DefaultInstallComponents = @($Config.Components | Where-Object { $_.SupportsInstall -and ($_.RequiredInstall -or $_.SelectedInstall) })
      $SilentRouteFailures = @($DefaultInstallComponents | Where-Object {
          $Route = @($_.Commands | Where-Object Mode -EQ 'Silent' | Select-Object -First 1)
          $Route.Count -eq 0 -or -not $Route[0].IsUnattendedRouteProven
        })
      $BasicRouteFailures = @($DefaultInstallComponents | Where-Object {
          $Route = @($_.Commands | Where-Object Mode -EQ 'Basic' | Select-Object -First 1)
          $Route.Count -eq 0 -or -not $Route[0].IsUnattendedRouteProven
        })
      if ($Context.RuntimeCapabilities.Quiet -and ($SilentRouteFailures.Count -gt 0 -or $Config.HasReferenceRisk -or $DefaultInstallComponents.Count -eq 0)) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'DotNetInstaller.Installability.SilentRouteUnproven' -Source 'DotNetInstaller' -Message 'The launcher accepts /q, but at least one selected nested route falls back to an unproven interactive command or is supplied by unresolved configuration.' -Kind ManualValidation -Areas Installability -AffectedFields @('InstallModes', 'InstallerSwitches') -Evidence @($SilentRouteFailures | Select-Object Id, Type, Commands)))
      }
      if ($Context.RuntimeCapabilities.BasicUI -and ($BasicRouteFailures.Count -gt 0 -or $Config.HasReferenceRisk -or $DefaultInstallComponents.Count -eq 0)) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'DotNetInstaller.Installability.BasicRouteUnproven' -Source 'DotNetInstaller' -Message 'The launcher accepts /qb, but at least one selected nested route has no proven unattended basic or silent command.' -Kind ManualValidation -Areas Installability -AffectedFields @('InstallModes', 'InstallerSwitches') -Evidence @($BasicRouteFailures | Select-Object Id, Type, Commands)))
      }
      $SilentCompleteCommands = @($CompleteCommands | Where-Object { $_.Mode -ceq 'Silent' })
      if ($SilentCompleteCommands.Count -gt 0) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'DotNetInstaller.Installability.SilentCompletionCommand' -Source 'DotNetInstaller' -Message 'A post-install completion command runs in silent mode and may launch the application or perform additional side effects.' -Kind Risk -Areas Installability -AffectedFields @('InstallerSwitches') -Evidence $SilentCompleteCommands))
      }

      $InstallModes = [Collections.Generic.List[string]]::new()
      $InstallModes.Add('interactive')
      $InstallerSwitches = [ordered]@{}
      if ($Context.RuntimeCapabilities.Quiet) {
        $InstallModes.Add('silent')
        $SilentParts = [Collections.Generic.List[string]]::new()
        $SilentParts.Add('/q')
        if ($Context.RuntimeCapabilities.NoSplash) { $SilentParts.Add('/nosplash') }
        if ($Context.RuntimeCapabilities.NoReboot) { $SilentParts.Add('/noreboot') }
        $InstallerSwitches['Silent'] = $SilentParts -join ' '
      }
      if ($Context.RuntimeCapabilities.BasicUI) {
        $InstallModes.Add('silentWithProgress')
        $BasicParts = [Collections.Generic.List[string]]::new()
        $BasicParts.Add('/qb')
        if ($Context.RuntimeCapabilities.NoReboot) { $BasicParts.Add('/noreboot') }
        $InstallerSwitches['SilentWithProgress'] = $BasicParts -join ' '
      } elseif ($InstallerSwitches.Contains('Silent')) {
        # WinGet defaults to SilentWithProgress. Reuse the proven quiet route when this
        # runtime has no separate basic-UI mode, without advertising a progress mode.
        $InstallerSwitches['SilentWithProgress'] = $InstallerSwitches['Silent']
      }
      if ($Context.RuntimeCapabilities.Logging -and $Context.RuntimeCapabilities.LogFile) {
        $InstallerSwitches['Log'] = '/Log /LogFile "<LOGPATH>"'
      }
      $NestedInstallModes = [Collections.Generic.List[string]]::new()
      $NestedInstallModes.Add('interactive')
      if ($Context.RuntimeCapabilities.Quiet -and $SilentRouteFailures.Count -eq 0 -and -not $Config.HasReferenceRisk -and $DefaultInstallComponents.Count -gt 0) {
        $NestedInstallModes.Add('silent')
      }
      if ($Context.RuntimeCapabilities.BasicUI -and $BasicRouteFailures.Count -eq 0 -and -not $Config.HasReferenceRisk -and $DefaultInstallComponents.Count -gt 0) {
        $NestedInstallModes.Add('silentWithProgress')
      }

      $ArpVisibility = if ($PrimaryMsi) {
        $PrimaryMsi.WritesAppsAndFeaturesEntry
      } elseif ($DistinctNestedMsi.Count -gt 1) {
        $VisibilityValues = @($DistinctNestedMsi.WritesAppsAndFeaturesEntry | Where-Object { $null -ne $_ } | Sort-Object -Unique)
        $VisibilityValues.Count -eq 1 -and @($DistinctNestedMsi.WritesAppsAndFeaturesEntry | Where-Object { $null -eq $_ }).Count -eq 0 ? $VisibilityValues[0] : $null
      } else {
        $null
      }
      $VisiblePrimaryMsi = $PrimaryMsi -and $PrimaryMsi.WritesAppsAndFeaturesEntry -eq $true ? $PrimaryMsi : $null

      return [pscustomobject][ordered]@{
        Path = $Context.Installer.FullName; InstallerType = 'exe'
        ProductCode = $VisiblePrimaryMsi ? $VisiblePrimaryMsi.ProductCode : $null; UpgradeCode = $VisiblePrimaryMsi ? $VisiblePrimaryMsi.UpgradeCode : $null
        DisplayName = $VisiblePrimaryMsi ? $VisiblePrimaryMsi.DisplayName : $null; DisplayVersion = $VisiblePrimaryMsi ? $VisiblePrimaryMsi.DisplayVersion : $null
        Publisher = $VisiblePrimaryMsi ? $VisiblePrimaryMsi.Publisher : $null; Scope = $PrimaryMsi ? $PrimaryMsi.Scope : $null
        DefaultInstallLocation = $PrimaryMsi ? $PrimaryMsi.DefaultInstallLocation : $null; WritesAppsAndFeaturesEntry = $ArpVisibility
        AppsAndFeaturesProductCode = $VisiblePrimaryMsi ? $VisiblePrimaryMsi.AppsAndFeaturesProductCode : $null
        AppsAndFeaturesInstallerType = $VisiblePrimaryMsi ? $VisiblePrimaryMsi.AppsAndFeaturesInstallerType : $null
        Diagnostics = @(Merge-InstallerDiagnostics -Diagnostic $Diagnostics.ToArray()); UnresolvedFields = @($UnresolvedFields | Sort-Object)
        Family = 'dotNetInstaller'; Format = 'dotNetInstaller'; FormatGeneration = $Context.CabinetLayout.Generation
        XmlStorageRoute = $Config.XmlStorageRoute; RuntimeCapabilityProfile = $Context.RuntimeCapabilities.Profile
        RuntimeVersion = $Context.RuntimeCapabilities.RuntimeVersion; RuntimeVersionEvidence = $Context.RuntimeCapabilities.VersionEvidence
        RuntimeCapabilities = $Context.RuntimeCapabilities; LauncherKind = $LauncherKind; FileVersion = $Config.FileVersion
        ConfigurationProductVersion = $Config.ProductVersion; SchemaVersion = $Config.SchemaVersion; Generator = $Config.Generator
        DefaultUiLevel = $Config.DefaultUiLevel
        RootAttributes = $Config.RootAttributes; FileAttributes = $Config.FileAttributes; Configurations = $Config.Configurations
        References = $Config.References; Components = $Config.Components; Downloads = $Config.Downloads; Controls = $Config.Controls
        ConfigurationDocuments = $Config.ConfigurationDocuments; UnresolvedReferences = $Config.UnresolvedReferences
        InstalledProductChecks = $Config.InstalledProductChecks
        Commands = $Commands; UninstallCommands = $UninstallCommands; CompleteCommands = $CompleteCommands
        ExecutedPayloads = $ExecutedPayloads
        CabinetResources = @($Context.CabinetLayout.Sets | ForEach-Object { $_.Resources } | ForEach-Object { [pscustomobject]@{ ResourceName = $_.ResourceName; Offset = $_.Resource.Offset; Size = $_.Resource.Size; Part = $_.Part } })
        CabinetSets = @($Context.CabinetLayout.Sets | ForEach-Object { [pscustomobject]@{ Key = $_.Key; ComponentId = $_.ComponentId; IsGlobal = $_.IsGlobal; ResourceNames = @($_.Resources.ResourceName); EntryCount = $_.Entries.Count; ExpandedSize = $_.ExpandedSize } })
        CabinetDirectory = $Context.CabinetDirectory; PayloadCatalog = $Context.PayloadCatalog
        CompanionFiles = @($Context.CompanionFiles | ForEach-Object FullName)
        NestedFiles = @(($Context.PayloadCatalog.FullName + $Context.CompanionFiles.FullName) | Select-Object -Unique); NestedInstallerInfos = $NestedMsi
        AppsAndFeaturesEntries = $VisiblePrimaryMsi ? @($VisiblePrimaryMsi.AppsAndFeaturesEntries) : @()
        RegistryAssociationInfo = $VisiblePrimaryMsi ? $VisiblePrimaryMsi.RegistryAssociationInfo : $null
        Protocols = $VisiblePrimaryMsi ? @($VisiblePrimaryMsi.Protocols) : @(); FileExtensions = $VisiblePrimaryMsi ? @($VisiblePrimaryMsi.FileExtensions) : @()
        Dependencies = $PrimaryMsi ? $PrimaryMsi.Dependencies : $null
        InstallLocationProperty = $PrimaryMsi ? $PrimaryMsi.InstallLocationProperty : $null
        InstallLocationSwitch = $PrimaryMsi ? $PrimaryMsi.InstallLocationSwitch : $null
        SupportedArchitectures = $SupportedArchitectures; SupportedScopes = $PrimaryMsi -and $PrimaryMsi.Scope ? @($PrimaryMsi.Scope) : @()
        RequestedExecutionLevel = $RequestedExecutionLevel; ElevationRequirement = $ElevationRequirement
        InstallModes = $InstallModes.ToArray(); NestedInstallModes = $NestedInstallModes.ToArray(); InstallerSwitches = $InstallerSwitches
        ParserVersionInfo = [pscustomobject]@{ Parser = 'Dumplings.PackageModule.DotNetInstaller'; ParserMajor = 4; Sources = @('RES_CONFIGURATION XML and supplied references', 'compiled schema-version token', 'RES_CAB names and catalogs', 'install and uninstall command routes', 'installed-product checks', 'embedded and supplied nested MSI tables and selection filters') }
      }
    } finally {
      if ($Context -and $Context.TemporaryFolder) { Remove-Item -LiteralPath $Context.TemporaryFolder -Recurse -Force -ErrorAction SilentlyContinue }
    }
  }
}

function Expand-DotNetInstaller {
  <#
  .SYNOPSIS
    Expand selected installed files from all dotNetInstaller cabinet sets.
  .PARAMETER Path
    Path to the bootstrapper.
  .PARAMETER DestinationPath
    Output directory; a temporary directory is created when omitted.
  .PARAMETER Name
    Exact name or wildcard. Omitting it selects every file.
  .PARAMETER ConfigurationPath
    Optional primary configuration XML, matching the runtime /ConfigFile behavior.
  .PARAMETER ReferencedConfigurationPath
    Local XML files that may satisfy authored nested reference configurations.
  .PARAMETER CompanionPath
    Explicit sidecar or downloaded payload files to include in selection and output.
  .PARAMETER CollisionAction
    Behavior when a destination collides. Prompt asks only on a collision.
  .PARAMETER MaximumExpandedBytes
    Maximum aggregate selected output across all cabinet sets.
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [string]$Name = '*',
    [string]$ConfigurationPath,
    [AllowEmptyCollection()][string[]]$ReferencedConfigurationPath = @(),
    [AllowEmptyCollection()][string[]]$CompanionPath = @(),
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Prompt',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 4294967296
  )

  process {
    if (-not $DestinationPath) { $DestinationPath = New-TempFolder }
    $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
    $Context = $null
    try {
      $Context = Open-DotNetInstallerContext -Path $Path -EnumerateCabinets -ConfigurationPath $ConfigurationPath -ReferencedConfigurationPath $ReferencedConfigurationPath -CompanionPath $CompanionPath
      if ($Context.CabinetLayout.Sets.Count -eq 0 -and $Context.CompanionFiles.Count -eq 0) { throw 'No embedded cabinet or supplied companion payload was found.' }
      $ReservedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
      $Results = [Collections.Generic.List[string]]::new()
      [long]$RemainingBytes = $MaximumExpandedBytes
      foreach ($Set in $Context.CabinetLayout.Sets) {
        $SelectedLength = [long](($Set.Entries | Where-Object { Test-ExtractionPattern -Path $_.FullName -Pattern $Name } | Measure-Object Length -Sum).Sum)
        if ($SelectedLength -gt $RemainingBytes) { throw 'The selected dotNetInstaller files exceed the configured output limit.' }
        $Expanded = @(Export-CabinetEntry -Path $Set.Paths -DestinationPath $DestinationPath -Name $Name -CollisionAction $CollisionAction -MaximumExpandedBytes ([Math]::Max([long]1, $RemainingBytes)) -ReservedPath $ReservedPaths)
        foreach ($ExpandedPath in $Expanded) { $Results.Add($ExpandedPath) }
        $RemainingBytes -= $SelectedLength
      }
      foreach ($CompanionFile in $Context.CompanionFiles) {
        if (-not (Test-ExtractionPattern -Path $CompanionFile.Name -Pattern $Name)) { continue }
        if ($CompanionFile.Length -gt $RemainingBytes) { throw 'The selected dotNetInstaller files exceed the configured output limit.' }
        $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $CompanionFile.Name -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
        if ($Target.ShouldWrite) {
          $Parent = Split-Path -Parent $Target.Path
          if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
          $SourceStream = [IO.File]::Open($CompanionFile.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
          try {
            $DestinationStream = [IO.File]::Open($Target.Path, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try { $null = Copy-BoundedStream -Source $SourceStream -Destination $DestinationStream -MaximumBytes $RemainingBytes -ExpectedBytes $CompanionFile.Length } finally { $DestinationStream.Dispose() }
          } finally {
            $SourceStream.Dispose()
          }
          $Results.Add($Target.Path)
        }
        $RemainingBytes -= $CompanionFile.Length
      }
      return $Results.ToArray()
    } finally {
      if ($Context -and $Context.TemporaryFolder) { Remove-Item -LiteralPath $Context.TemporaryFolder -Recurse -Force -ErrorAction SilentlyContinue }
    }
  }
}

function Test-DotNetInstaller {
  <#
  .SYNOPSIS
    Test for a structurally valid embedded dotNetInstaller configuration.
  .DESCRIPTION
    Detection reads only PE resources and bounded XML; it does not stage cabinets.
  .PARAMETER Path
    Path to the candidate PE.
  .PARAMETER Resource
    Optional PE resource catalog already collected by a structural analyzer.
  .PARAMETER ConfigurationPath
    Optional primary configuration XML for a launcher without embedded configuration.
  #>
  [OutputType([bool])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [AllowEmptyCollection()][psobject[]]$Resource,
    [string]$ConfigurationPath
  )

  process {
    try {
      if ($ConfigurationPath) {
        $Context = Open-DotNetInstallerContext -Path $Path -ConfigurationPath $ConfigurationPath
        return $Context.Configuration.RootAttributes -is [Collections.IDictionary] -and $Context.RuntimeCapabilities.Profile -cne 'Unknown' -and $Context.RuntimeCapabilities.ConfigFile
      }
      if ($PSBoundParameters.ContainsKey('Resource')) {
        $ConfigurationResources = @($Resource | Where-Object { $_.TypeName -ceq 'CUSTOM' -and $_.Name -ceq 'RES_CONFIGURATION' })
        if ($ConfigurationResources.Count -ne 1) { return $false }
        $Text = ConvertFrom-DotNetInstallerConfigurationByte -Bytes (Read-PEResourceData -Resource $ConfigurationResources[0] -MaximumBytes 16777216)
        $Configuration = ConvertFrom-DotNetInstallerConfiguration -Content $Text
        return $Configuration.RootAttributes -is [Collections.IDictionary]
      }
      $Context = Open-DotNetInstallerContext -Path $Path -SkipRuntimeCapability
      return $Context.Configuration.RootAttributes -is [Collections.IDictionary]
    } catch {
      return $false
    }
  }
}

Export-ModuleMember -Function ConvertFrom-DotNetInstallerConfiguration, Get-DotNetInstallerInfo, Get-DotNetInstallerNestedMsiSelection, Expand-DotNetInstaller, Test-DotNetInstaller
