# SPDX-License-Identifier: Apache-2.0
# Format source: https://github.com/dotnetinstaller/dotnetinstaller
# Binary structure consumed here; dotNetInstaller is a PE resource wrapper:
#
#   .rsrc/CUSTOM/RES_CONFIGURATION -> UTF-8 or BOM-marked UTF-16 XML
#   .rsrc/RES_CAB/*                -> bounded MSCF cabinet resources
#   XML component conditions/commands -> named CAB payload + arguments
#
# Resource RVAs are mapped through PE sections. XML controls execution order and
# architecture/OS selection; CAB entry order is not execution evidence.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

function Get-DotNetInstallerXmlAttribute {
  <#
  .SYNOPSIS
    Read one optional dotNetInstaller XML attribute
  .PARAMETER Element
    Current structured format node or record being interpreted.
  .PARAMETER Name
    Exact name or wildcard used to select format records or payload entries.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][System.Xml.XmlElement]$Element,
    [Parameter(Mandatory)][string]$Name
  )
  if ($Element.HasAttribute($Name)) { return $Element.GetAttribute($Name) }
  return $null
}

function Get-DotNetInstallerComponentCommand {
  <#
  .SYNOPSIS
    Build source-accurate install commands for one dotNetInstaller component
  .PARAMETER Component
    Current structured format node or record being interpreted.
  .PARAMETER ArchiveEntry
    Validated archive or catalog entry whose bounded content is read or exported.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][System.Xml.XmlElement]$Component,
    [string[]]$ArchiveEntry = @()
  )

  $Type = (Get-DotNetInstallerXmlAttribute -Element $Component -Name 'type').ToLowerInvariant()
  $Modes = [ordered]@{
    Interactive = ''
    Basic       = '_basic'
    Silent      = '_silent'
  }

  # Build each execution mode independently. Mode-specific attributes fall back
  # to the unsuffixed command exactly as the bootstrapper configuration does.
  foreach ($Mode in $Modes.GetEnumerator()) {
    $Suffix = $Mode.Value
    $CommandLine = $null

    # Normalize component-specific XML attributes into the real command line
    # that would be passed to MSI, MSP, MSU, EXE, shell, or open-file handlers.
    switch ($Type) {
      'msi' {
        $Package = Get-DotNetInstallerXmlAttribute -Element $Component -Name 'package'
        $Parameters = Get-DotNetInstallerXmlAttribute -Element $Component -Name "cmdparameters$Suffix"
        if (-not $Parameters -and $Suffix) { $Parameters = Get-DotNetInstallerXmlAttribute -Element $Component -Name 'cmdparameters' }
        $CommandLine = "msiexec.exe /i `"$Package`" $Parameters".Trim()
      }
      'msp' {
        $Patch = Get-DotNetInstallerXmlAttribute -Element $Component -Name 'patch'
        $Package = Get-DotNetInstallerXmlAttribute -Element $Component -Name 'package'
        $Parameters = Get-DotNetInstallerXmlAttribute -Element $Component -Name "cmdparameters$Suffix"
        if (-not $Parameters -and $Suffix) { $Parameters = Get-DotNetInstallerXmlAttribute -Element $Component -Name 'cmdparameters' }
        $AdministrativePackage = if ($Package) { " /a `"$Package`"" } else { '' }
        $CommandLine = "msiexec.exe /p `"$Patch`"$AdministrativePackage $Parameters".Trim()
      }
      'msu' {
        $Package = Get-DotNetInstallerXmlAttribute -Element $Component -Name 'package'
        $Parameters = Get-DotNetInstallerXmlAttribute -Element $Component -Name "cmdparameters$Suffix"
        if (-not $Parameters -and $Suffix) { $Parameters = Get-DotNetInstallerXmlAttribute -Element $Component -Name 'cmdparameters' }
        $CommandLine = "wusa.exe `"$Package`" $Parameters".Trim()
      }
      'exe' {
        $Executable = Get-DotNetInstallerXmlAttribute -Element $Component -Name "executable$Suffix"
        if (-not $Executable -and $Suffix) { $Executable = Get-DotNetInstallerXmlAttribute -Element $Component -Name 'executable' }
        $Parameters = Get-DotNetInstallerXmlAttribute -Element $Component -Name "exeparameters$Suffix"
        if (-not $Parameters -and $Suffix) { $Parameters = Get-DotNetInstallerXmlAttribute -Element $Component -Name 'exeparameters' }
        if ($Executable) { $CommandLine = "`"$Executable`" $Parameters".Trim() }
      }
      'cmd' {
        $CommandLine = Get-DotNetInstallerXmlAttribute -Element $Component -Name "command$Suffix"
        if (-not $CommandLine -and $Suffix) { $CommandLine = Get-DotNetInstallerXmlAttribute -Element $Component -Name 'command' }
      }
      'openfile' {
        $CommandLine = Get-DotNetInstallerXmlAttribute -Element $Component -Name 'filename'
      }
    }
    if (-not $CommandLine) { continue }
    [pscustomobject]@{
      Mode    = $Mode.Key
      Command = Resolve-BootstrapperCommand -CommandLine $CommandLine -CandidatePath $ArchiveEntry
    }
  }
}

function ConvertFrom-DotNetInstallerConfiguration {
  <#
  .SYNOPSIS
    Parse a dotNetInstaller configuration XML document into component commands
  .PARAMETER Content
    The embedded configuration XML
  .PARAMETER ArchiveEntry
    Embedded cabinet entry paths used to resolve payload references
  .LINK
    https://github.com/dotnetinstaller/dotnetinstaller/blob/master/dotNetInstaller/ConfigFileManager.cpp
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Content,
    [string[]]$ArchiveEntry = @()
  )

  $Settings = [Xml.XmlReaderSettings]::new()

  # Disable DTD and external entity resolution before loading untrusted embedded XML.
  $Settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
  $Settings.XmlResolver = $null
  $StringReader = [IO.StringReader]::new($Content)
  $Reader = [Xml.XmlReader]::Create($StringReader, $Settings)
  $Document = [Xml.XmlDocument]::new()
  try {
    $Document.XmlResolver = $null
    $Document.Load($Reader)
  } finally {
    $Reader.Dispose()
    $StringReader.Dispose()
  }
  if ($Document.DocumentElement.Name -ne 'configurations') { throw 'The XML root is not a dotNetInstaller configurations document.' }

  $Components = [Collections.Generic.List[psobject]]::new()
  $ConfigurationIndex = 0

  # Non-install configurations describe maintenance/uninstall paths and must not
  # be reported as payloads executed during installation.
  foreach ($Configuration in @($Document.DocumentElement.SelectNodes('configuration'))) {
    if ($Configuration.GetAttribute('type') -ne 'install') {
      $ConfigurationIndex++
      continue
    }
    foreach ($Component in @($Configuration.SelectNodes('component'))) {
      $Attributes = [ordered]@{}
      foreach ($Attribute in $Component.Attributes) { $Attributes[$Attribute.Name] = $Attribute.Value }
      $Commands = @(Get-DotNetInstallerComponentCommand -Component $Component -ArchiveEntry $ArchiveEntry)
      $Components.Add([pscustomobject]@{
          ConfigurationIndex          = $ConfigurationIndex
          ConfigurationOsFilter       = $Configuration.GetAttribute('os_filter')
          ConfigurationOsFilterMin    = $Configuration.GetAttribute('os_filter_min')
          ConfigurationOsFilterMax    = $Configuration.GetAttribute('os_filter_max')
          ConfigurationArchitecture   = $Configuration.GetAttribute('processor_architecture_filter')
          ConfigurationLanguage       = $Configuration.GetAttribute('language_id')
          Type                        = $Component.GetAttribute('type')
          Id                          = $Component.GetAttribute('id')
          DisplayName                 = $Component.GetAttribute('display_name')
          SelectedInstall             = $Component.GetAttribute('selected_install')
          RequiredInstall             = $Component.GetAttribute('required_install')
          SupportsInstall             = $Component.GetAttribute('supports_install')
          OsFilter                    = $Component.GetAttribute('os_filter')
          OsFilterMin                 = $Component.GetAttribute('os_filter_min')
          OsFilterMax                 = $Component.GetAttribute('os_filter_max')
          ProcessorArchitectureFilter = $Component.GetAttribute('processor_architecture_filter')
          Attributes                  = [pscustomobject]$Attributes
          Commands                    = $Commands
        })
    }
    $ConfigurationIndex++
  }

  $Schema = $Document.SelectSingleNode('/configurations/schema')
  [pscustomobject]@{
    FileVersion    = $Document.DocumentElement.GetAttribute('fileversion')
    ProductVersion = $Document.DocumentElement.GetAttribute('productversion')
    SchemaVersion  = if ($Schema) { $Schema.GetAttribute('version') } else { $null }
    Generator      = if ($Schema) { $Schema.GetAttribute('generator') } else { $null }
    Components     = @($Components)
  }
}

function Get-DotNetInstallerInfo {
  <#
  .SYNOPSIS
    Read component commands and nested payloads from dotNetInstaller
  .PARAMETER Path
    The path to the dotNetInstaller bootstrapper
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)

  process {
    $Installer = Get-Item -LiteralPath $Path -Force
    $Resources = @(Get-PEResourceInfo -Path $Installer.FullName)
    $ConfigurationResource = $Resources | Where-Object {
      $_.TypeName -eq 'CUSTOM' -and $_.Name -eq 'RES_CONFIGURATION'
    } | Select-Object -First 1

    # Require the canonical named configuration resource rather than accepting
    # arbitrary XML strings compiled into the launcher.
    if (-not $ConfigurationResource) { throw 'The dotNetInstaller RES_CONFIGURATION resource was not found.' }

    $ConfigurationBytes = Read-PEResourceData -Resource $ConfigurationResource -MaximumBytes 16777216

    # dotNetInstaller projects are normally UTF-8 but older builders may emit a
    # UTF-16LE BOM; decode only these source-backed representations.
    $ConfigurationText = if ($ConfigurationBytes.Length -ge 2 -and $ConfigurationBytes[0] -eq 0xFF -and $ConfigurationBytes[1] -eq 0xFE) {
      [Text.Encoding]::Unicode.GetString($ConfigurationBytes, 2, $ConfigurationBytes.Length - 2)
    } else {
      [Text.Encoding]::UTF8.GetString($ConfigurationBytes).TrimStart([char]0xFEFF)
    }

    $CabinetResources = @($Resources | Where-Object { $_.TypeName -eq 'RES_CAB' })
    $Cabinets = [Collections.Generic.List[psobject]]::new()
    $NestedFiles = [Collections.Generic.List[string]]::new()
    $CabinetFolder = New-TempFolder
    try {
      $CabinetPaths = [Collections.Generic.List[string]]::new()

      # Preserve RES_CAB order because split cabinets can span multiple resources;
      # safe temporary names prevent a resource name from escaping the staging root.
      foreach ($Resource in @($CabinetResources | Sort-Object Offset)) {
        $CabinetPath = Resolve-SafeExtractionPath -DestinationPath $CabinetFolder -RelativePath $Resource.Name
        $null = Export-PEResourceData -Resource $Resource -DestinationPath $CabinetPath -MaximumBytes 1073741824
        $CabinetPaths.Add($CabinetPath)
        $Cabinets.Add([pscustomobject]@{
            ResourceName = $Resource.Name
            Offset       = $Resource.Offset
            Size         = $Resource.Size
          })
      }
      if ($CabinetPaths.Count -gt 0) {
        $Entries = @(Get-CabinetEntry -Path $CabinetPaths)
        foreach ($Entry in $Entries) { $NestedFiles.Add($Entry.FullName) }
      }
    } finally {
      Remove-Item -LiteralPath $CabinetFolder -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Resolve XML command references only after the complete cabinet catalog is known.
    $Config = ConvertFrom-DotNetInstallerConfiguration -Content $ConfigurationText -ArchiveEntry @($NestedFiles)
    $Commands = @($Config.Components | ForEach-Object { $_.Commands })
    [pscustomobject]@{
      Path             = $Installer.FullName
      Format           = 'dotNetInstaller'
      FileVersion      = $Config.FileVersion
      ProductVersion   = $Config.ProductVersion
      SchemaVersion    = $Config.SchemaVersion
      Generator        = $Config.Generator
      Components       = $Config.Components
      Commands         = $Commands
      ExecutedPayloads = @($Commands | Where-Object { $_.Command.ExecutedPayload } | ForEach-Object { $_.Command.ExecutedPayload } | Select-Object -Unique)
      CabinetResources = @($Cabinets)
      NestedFiles      = @($NestedFiles | Select-Object -Unique)
      Warnings         = @(
        if ($Config.Components.Count -eq 0) { 'No install components were found in the dotNetInstaller configuration.' }
        foreach ($Component in $Config.Components) {
          foreach ($Command in $Component.Commands) {
            if (-not $Command.Command.IsResolved -and $Command.Command.PayloadReference -match '(?i)\.(exe|msi|msp|msu)$') {
              "The $($Component.Id) $($Command.Mode) command references a payload that was not found in embedded cabinets: $($Command.Command.PayloadReference)"
            }
          }
        }
      )
    }
  }
}

function Expand-DotNetInstaller {
  <#
  .SYNOPSIS
    Expand selected files from dotNetInstaller RES_CAB resources
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER DestinationPath
    Destination path for bounded extraction or decoded output; payload-relative names are resolved beneath this path.
  .PARAMETER Name
    Exact name or wildcard used to select format records or payload entries.
  .PARAMETER MaximumExpandedBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [string]$Name = '*',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 4294967296
  )
  process {
    if (-not $DestinationPath) { $DestinationPath = New-TempFolder }
    $Resources = @(Get-PEResourceInfo -Path (Get-Item -LiteralPath $Path -Force).FullName | Where-Object { $_.TypeName -eq 'RES_CAB' })
    if ($Resources.Count -eq 0) { throw 'The dotNetInstaller RES_CAB resources were not found.' }
    $CabinetFolder = New-TempFolder
    try {
      $CabinetPaths = [Collections.Generic.List[string]]::new()

      # Reassemble ordered cabinet resources without interpreting any component
      # command, then delegate bounded selection/extraction to the CAB helper.
      foreach ($Resource in @($Resources | Sort-Object Offset)) {
        $CabinetPath = Resolve-SafeExtractionPath -DestinationPath $CabinetFolder -RelativePath $Resource.Name
        $null = Export-PEResourceData -Resource $Resource -DestinationPath $CabinetPath -MaximumBytes 1073741824
        $CabinetPaths.Add($CabinetPath)
      }
      Export-CabinetEntry -Path $CabinetPaths -DestinationPath $DestinationPath -Name $Name -MaximumExpandedBytes $MaximumExpandedBytes
    } finally {
      Remove-Item -LiteralPath $CabinetFolder -Recurse -Force -ErrorAction SilentlyContinue
    }
  }
}

function Test-DotNetInstaller {
  <#
  .SYNOPSIS
    Test whether a file is a dotNetInstaller bootstrapper
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([bool])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process {
    try { $null = Get-DotNetInstallerInfo -Path $Path; return $true } catch { return $false }
  }
}

Export-ModuleMember -Function ConvertFrom-DotNetInstallerConfiguration, Get-DotNetInstallerInfo, Expand-DotNetInstaller, Test-DotNetInstaller
