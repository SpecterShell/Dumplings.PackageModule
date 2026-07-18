# SPDX-License-Identifier: MIT
# Format sources: https://github.com/wixtoolset/wix
# Binary structure consumed here; MSI/MSP/MST are CFB containers:
#
#   D0 CF 11 E0 A1 B1 1A E1 header -> FAT/DIFAT/mini-FAT
#     -> directory/root CLSID -> _StringPool/_StringData/table streams
#
# Root CLSID 000C1084 identifies an installer database, 000C1086 a patch, and
# 000C1082 a transform. This module uses Windows Installer/DTF to read logical
# tables after storage validation; WiX/Advanced Installer/InstallShield are
# authoring classifications over the same database structure.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# Force stop on error
$ErrorActionPreference = 'Stop'

function Import-Assembly {
  <#
  .SYNOPSIS
    Load the Microsoft.Deployment.WindowsInstaller.Package.dll assembly
  #>

  # Check if the assembly is already loaded to prevent double loading
  if (-not ([System.Management.Automation.PSTypeName]'Microsoft.Deployment.WindowsInstaller').Type) {
    if (Test-Path -Path ($Path = Join-Path $PSScriptRoot '..' 'Assets' 'Microsoft.Deployment.WindowsInstaller.dll')) {
      Add-Type -Path $Path
    } else {
      throw 'The Microsoft.Deployment.WindowsInstaller.dll assembly could not be found'
    }
  }
  if (-not ([System.Management.Automation.PSTypeName]'Microsoft.Deployment.WindowsInstaller.Package').Type) {
    if (Test-Path -Path ($Path = Join-Path $PSScriptRoot '..' 'Assets' 'Microsoft.Deployment.WindowsInstaller.Package.dll')) {
      Add-Type -Path $Path
    } else {
      throw 'The Microsoft.Deployment.WindowsInstaller.Package.dll assembly could not be found'
    }
  }
}

Import-Assembly

function Expand-Msp {
  <#
  .SYNOPSIS
    Extract Transforms from the MSP file
  .PARAMETER Path
    The path to the MSP file
  .PARAMETER Database
    The patch package database object
  #>
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the MSP file')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Database', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The patch package database object')]
    [Microsoft.Deployment.WindowsInstaller.Package.PatchPackage]$Database
  )

  process {
    $Database = switch ($PSCmdlet.ParameterSetName) {
      'Path' { [Microsoft.Deployment.WindowsInstaller.Package.PatchPackage]::new((Convert-Path -Path $Path)) }
      'Database' { $Database }
      default { throw 'Invalid parameter set.' }
    }

    try {
      $Transforms = $Database.GetTransforms()
      foreach ($Transform in $Transforms) {
        $File = New-TempFile
        $Database.ExtractTransform($Transform, $File)
        Write-Output -InputObject $File
      }
    } finally {
      switch ($PSCmdlet.ParameterSetName) {
        'Path' { $Database.Close() }
        'Database' { } # Do not close user-provided stream
        default { throw 'Invalid parameter set.' }
      }
    }
  }
}

function Read-MsiProperty {
  <#
  .SYNOPSIS
    Query a value from the MSI file using SQL-like query
  .PARAMETER Path
    The path to the MSI file
  .PARAMETER PatchFile
    Indicate the file is a patch file
  .PARAMETER Database
    The database object
  .PARAMETER TransformPath
    The path to the transform files to be applied
  .PARAMETER PatchPath
    The path to the patch files to be applied
  .PARAMETER Query
    The SQL-like query
  .PARAMETER Field
    The name or number of the field to extract
  #>
  [OutputType([string])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the MSI file')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Path', HelpMessage = 'Indicate the file is a patch file')]
    [switch]$PatchFile,

    [Parameter(ParameterSetName = 'Database', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The database object')]
    [Microsoft.Deployment.WindowsInstaller.Database]$Database,

    [Parameter(HelpMessage = 'The path to the transform file to be applied')]
    [AllowNull()]
    [string]$TransformPath,

    [Parameter(HelpMessage = 'The path to the patch file to be applied')]
    [AllowNull()]
    [string]$PatchPath,

    [Parameter(Mandatory, HelpMessage = 'The SQL-like query')]
    [string]$Query,

    [Parameter(HelpMessage = 'The name or number of the field to extract')]
    $Field = 1
  )

  process {
    $Database = switch ($PSCmdlet.ParameterSetName) {
      'Path' {
        $Path = Convert-Path -Path $Path
        $PatchFile ? [Microsoft.Deployment.WindowsInstaller.Package.PatchPackage]::new($Path) : [Microsoft.Deployment.WindowsInstaller.Package.InstallPackage]::new($Path, 'ReadOnly')
      }
      'Database' { $Database }
      default { throw 'Invalid parameter set.' }
    }

    # Apply authored transforms and patch transforms to the in-memory database view before querying;
    # the original package remains opened read-only.
    # Apply the transform if specified
    if ($TransformPath) {
      $TransformPath = Convert-Path -Path $TransformPath
      $Database.ApplyTransform($TransformPath)
    }

    # Apply the patch if specified
    if ($PatchPath) {
      $PatchPath = Convert-Path -Path $PatchPath
      $TransformPaths = Expand-Msp -Path $PatchPath
      foreach ($TransformPath in $TransformPaths) {
        $Database.ApplyTransform($TransformPath)
        Remove-Item -Path $TransformPath -Force -ErrorAction SilentlyContinue
      }
    }

    try {
      $View = $Database.OpenView($Query)
      $View.Execute()
      $Record = $View.Fetch()
      $Record.GetString($Field)
    } finally {
      $Record.Close()
      $View.Close()
      switch ($PSCmdlet.ParameterSetName) {
        'Path' { $Database.Close() }
        'Database' { } # Do not close user-provided stream
        default { throw 'Invalid parameter set.' }
      }
    }
  }
}

function Get-MsiQueryRow {
  <#
  .SYNOPSIS
    Materialize rows from one read-only MSI SQL query.
  .PARAMETER Database
    Open caller-owned Windows Installer database. This function closes its view/records, not the database.
  .PARAMETER Query
    SQL query over MSI logical tables.
  .PARAMETER FieldNames
    Output property names corresponding positionally to one-based query fields.
  #>
  param (
    [Parameter(Mandatory)]
    [Microsoft.Deployment.WindowsInstaller.Database]$Database,

    [Parameter(Mandatory)]
    [string]$Query,

    [Parameter(Mandatory)]
    [string[]]$FieldNames
  )

  $Rows = [System.Collections.Generic.List[object]]::new()
  $View = $null
  $Record = $null
  try {
    $View = $Database.OpenView($Query)
    $View.Execute()
    while ($Record = $View.Fetch()) {
      try {
        $Row = [ordered]@{}
        for ($Index = 0; $Index -lt $FieldNames.Count; $Index++) {
          $Row[$FieldNames[$Index]] = $Record.GetString($Index + 1)
        }
        $Rows.Add([PSCustomObject]$Row)
      } finally {
        $Record.Close()
        $Record = $null
      }
    }
  } catch {
    $null = $_
    # Optional MSI tables are absent in valid packages; callers treat that as no rows.
  } finally {
    if ($Record) { $Record.Close() }
    if ($View) { $View.Close() }
  }

  return $Rows.ToArray()
}

function Expand-MsiFormattedPropertyValue {
  <#
  .SYNOPSIS
    Resolve literal bracketed MSI property references in a formatted value.
  .PARAMETER Value
    Formatted MSI string. Unknown references remain unchanged.
  .PARAMETER Properties
    Property table values keyed by case-sensitive MSI property name.
  #>
  param (
    [AllowNull()]
    [string]$Value,

    [Parameter(Mandatory)]
    [hashtable]$Properties
  )

  if ($null -eq $Value) { return $null }

  $ResolvedProperties = $Properties
  return [regex]::Replace($Value, '\[([^\]]+)\]', {
      param($Match)

      $PropertyName = $Match.Groups[1].Value
      if ($ResolvedProperties.ContainsKey($PropertyName)) { return $ResolvedProperties[$PropertyName] }

      return $Match.Value
    })
}

function Get-MsiStaticTableInfo {
  <#
  .SYNOPSIS
    Read the MSI table projection shared by builder, architecture, ARP, location, and association analysis.
  .PARAMETER Database
    Open caller-owned Windows Installer database. Optional absent tables produce empty row sets.
  #>
  param (
    [Parameter(Mandatory)]
    [Microsoft.Deployment.WindowsInstaller.Database]$Database
  )

  # Materialize one immutable projection so builder, architecture, ARP, install-location, and
  # association analysis do not reopen or repeatedly query the database.
  $Properties = @{}
  foreach ($Row in (Get-MsiQueryRow -Database $Database -Query 'SELECT `Property`, `Value` FROM `Property`' -FieldNames @('Property', 'Value'))) {
    $Properties[$Row.Property] = $Row.Value
  }

  $Tables = @((Get-MsiQueryRow -Database $Database -Query 'SELECT `Name` FROM `_Tables`' -FieldNames @('Name')).Name)
  $DirectoryRows = @(Get-MsiQueryRow -Database $Database -Query 'SELECT `Directory`, `Directory_Parent`, `DefaultDir` FROM `Directory`' -FieldNames @('Directory', 'DirectoryParent', 'DefaultDir'))
  $ComponentRows = @(Get-MsiQueryRow -Database $Database -Query 'SELECT `Component`, `Directory_`, `KeyPath` FROM `Component`' -FieldNames @('Component', 'Directory', 'KeyPath'))
  $CustomActionRows = @(Get-MsiQueryRow -Database $Database -Query 'SELECT `Action`, `Type`, `Source`, `Target` FROM `CustomAction`' -FieldNames @('Action', 'Type', 'Source', 'Target'))
  # Resolve only literal Property-table substitutions in Registry rows. Other MSI formatted-string
  # constructs remain intact rather than being evaluated outside Windows Installer.
  $RegistryRows = foreach ($Row in (Get-MsiQueryRow -Database $Database -Query 'SELECT `Registry`, `Root`, `Key`, `Name`, `Value`, `Component_` FROM `Registry`' -FieldNames @('Registry', 'Root', 'Key', 'Name', 'Value', 'Component'))) {
    $ResolvedKey = Expand-MsiFormattedPropertyValue -Value $Row.Key -Properties $Properties
    $ResolvedValue = Expand-MsiFormattedPropertyValue -Value $Row.Value -Properties $Properties
    [PSCustomObject]@{
      Registry      = $Row.Registry
      Root          = $Row.Root
      Key           = $ResolvedKey
      Name          = $Row.Name
      Value         = $ResolvedValue
      Component     = $Row.Component
      OriginalKey   = $Row.Key
      OriginalValue = $Row.Value
    }
  }
  $ExtensionRows = @(Get-MsiQueryRow -Database $Database -Query 'SELECT `Extension`, `Component_`, `ProgId_`, `MIME_`, `Feature_` FROM `Extension`' -FieldNames @('Extension', 'Component', 'ProgId', 'Mime', 'Feature'))
  $ProgIdRows = @(Get-MsiQueryRow -Database $Database -Query 'SELECT `ProgId`, `ProgId_Parent`, `Class_`, `Description`, `Icon_`, `IconIndex` FROM `ProgId`' -FieldNames @('ProgId', 'ParentProgId', 'Class', 'Description', 'Icon', 'IconIndex'))
  $VerbRows = @(Get-MsiQueryRow -Database $Database -Query 'SELECT `Extension_`, `Verb`, `Sequence`, `Command`, `Argument` FROM `Verb`' -FieldNames @('Extension', 'Verb', 'Sequence', 'Command', 'Argument'))
  $MimeRows = @(Get-MsiQueryRow -Database $Database -Query 'SELECT `ContentType`, `Extension_`, `CLSID` FROM `MIME`' -FieldNames @('ContentType', 'Extension', 'ClassId'))

  [PSCustomObject]@{
    Properties          = $Properties
    Tables              = $Tables
    DirectoryRows       = $DirectoryRows
    ComponentRows       = $ComponentRows
    CustomActionRows    = $CustomActionRows
    LaunchConditionRows = @(Get-MsiQueryRow -Database $Database -Query 'SELECT `Condition`, `Description` FROM `LaunchCondition`' -FieldNames @('Condition', 'Description'))
    RegistryRows        = @($RegistryRows)
    ExtensionRows       = $ExtensionRows
    ProgIdRows          = $ProgIdRows
    VerbRows            = $VerbRows
    MimeRows            = $MimeRows
    SummaryInfo         = $Database.SummaryInfo
  }
}

function Get-MsiAssociationInfoFromStaticTableInfo {
  <#
  .SYNOPSIS
    Read protocol and file-extension evidence from MSI registry and association tables
  .PARAMETER StaticTableInfo
    Previously validated layout evidence containing the coordinate ranges needed by this operation.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][psobject]$StaticTableInfo)

  $RegistryAssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite $StaticTableInfo.RegistryRows
  $FileExtensionAssociations = [System.Collections.Generic.List[object]]::new()
  foreach ($Association in @($RegistryAssociationInfo.FileExtensionAssociations)) { $FileExtensionAssociations.Add($Association) }
  $SeenTableExtensions = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $Warnings = [System.Collections.Generic.List[string]]::new()
  foreach ($Warning in @($RegistryAssociationInfo.Warnings)) { $Warnings.Add($Warning) }

  # Merge explicit Registry-table associations with MSI's normalized Extension/ProgId/Verb/MIME
  # tables, deduplicating by literal extension.
  foreach ($ExtensionRow in @($StaticTableInfo.ExtensionRows)) {
    $Extension = ([string]$ExtensionRow.Extension).Trim().TrimStart('.')
    if ($Extension -notmatch '^[A-Za-z0-9][A-Za-z0-9._+-]{0,254}$') {
      if (-not [string]::IsNullOrWhiteSpace($Extension)) { $Warnings.Add("Ignored non-literal MSI Extension table value '$Extension'.") }
      continue
    }
    if (-not $SeenTableExtensions.Add($Extension)) { continue }
    $ProgId = [string]$ExtensionRow.ProgId
    $ProgIdRow = @($StaticTableInfo.ProgIdRows | Where-Object { $_.ProgId -ieq $ProgId } | Select-Object -First 1)
    $Verbs = @($StaticTableInfo.VerbRows | Where-Object { $_.Extension -ieq $ExtensionRow.Extension } | Sort-Object { [int]$_.Sequence })
    $OpenVerb = @($Verbs | Where-Object { $_.Verb -ieq 'open' } | Select-Object -First 1)
    if ($OpenVerb.Count -eq 0) { $OpenVerb = @($Verbs | Select-Object -First 1) }
    $Mime = @($StaticTableInfo.MimeRows | Where-Object { $_.Extension -ieq $ExtensionRow.Extension } | Select-Object -First 1)
    $FileExtensionAssociations.Add([pscustomobject]@{
        FileExtension = $Extension.ToLowerInvariant()
        Extension     = ".$($Extension.ToLowerInvariant())"
        Root          = 'MSI'
        DefaultProgId = if ($ProgId) { $ProgId } else { $null }
        ProgIds       = if ($ProgId) { @($ProgId) } else { @() }
        Description   = if ($ProgIdRow.Count) { $ProgIdRow[0].Description } else { $null }
        Command       = if ($OpenVerb.Count) { $OpenVerb[0].Command } else { $null }
        Arguments     = if ($OpenVerb.Count) { $OpenVerb[0].Argument } else { $null }
        DefaultIcon   = if ($ProgIdRow.Count) { $ProgIdRow[0].Icon } else { $null }
        MimeType      = if ($Mime.Count) { $Mime[0].ContentType } else { $null }
        Component     = $ExtensionRow.Component
        Evidence      = [pscustomobject]@{ Tables = @('Extension', 'ProgId', 'Verb', 'MIME'); Extension = $ExtensionRow; ProgId = $ProgIdRow; Verb = $OpenVerb; Mime = $Mime }
      })
  }

  [pscustomobject]@{
    Protocols                 = @($RegistryAssociationInfo.Protocols | Sort-Object -Unique)
    FileExtensions            = @($FileExtensionAssociations | Select-Object -ExpandProperty FileExtension -Unique | Sort-Object)
    ProtocolAssociations      = @($RegistryAssociationInfo.ProtocolAssociations)
    FileExtensionAssociations = @($FileExtensionAssociations)
    RegistryAssociationInfo   = $RegistryAssociationInfo
    Warnings                  = @($Warnings | Select-Object -Unique)
  }
}

function Convert-MsiTemplatePlatformToSupportedArchitecture {
  <#
  .SYNOPSIS
    Convert MSI Summary Information template platforms to WinGet architecture names
  .PARAMETER Template
    The Summary Information Template value
  #>
  [OutputType([string[]])]
  param (
    [AllowNull()]
    [string]$Template
  )

  $Platforms = @($Template -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
  if (-not $Platforms) { return @() }

  $Architectures = [System.Collections.Generic.List[string]]::new()
  foreach ($Platform in $Platforms) {
    switch -Regex ($Platform) {
      '(?i)^Intel$' {
        foreach ($Architecture in @('x86', 'x64', 'arm64')) {
          if (-not $Architectures.Contains($Architecture)) { $Architectures.Add($Architecture) }
        }
      }
      '(?i)^(x64|AMD64)$' {
        foreach ($Architecture in @('x64', 'arm64')) {
          if (-not $Architectures.Contains($Architecture)) { $Architectures.Add($Architecture) }
        }
      }
      '(?i)^Arm64$' {
        if (-not $Architectures.Contains('arm64')) { $Architectures.Add('arm64') }
      }
      '(?i)^Arm$' {
        if (-not $Architectures.Contains('arm')) { $Architectures.Add('arm') }
      }
    }
  }

  return @('x86', 'x64', 'arm64') | Where-Object { $Architectures.Contains($_) }
}

function Convert-MsiTemplatePlatformToPackageArchitecture {
  <#
  .SYNOPSIS
    Convert an MSI Summary Information template platform to its package architecture
  .PARAMETER Template
    The Summary Information Template value
  #>
  [OutputType([string])]
  param (
    [AllowNull()]
    [string]$Template
  )

  $Platform = ([string]($Template -split ';' | Select-Object -First 1)).Trim()
  # Windows Installer treats an omitted Template platform as the 32-bit Intel platform.
  if ([string]::IsNullOrWhiteSpace($Platform)) { return 'x86' }
  switch -Regex ($Platform) {
    '(?i)^(x64|AMD64|Intel64)$' { return 'x64' }
    '(?i)^Arm64$' { return 'arm64' }
    '(?i)^Intel$' { return 'x86' }
    default { return $null }
  }
}

function Test-MsiArchitectureCondition {
  <#
  .SYNOPSIS
    Evaluate simple MSI architecture launch-condition expressions
  .PARAMETER Condition
    The LaunchCondition condition text
  .PARAMETER Architecture
    The WinGet architecture to test
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The LaunchCondition condition text')]
    [string]$Condition,

    [Parameter(Mandatory, HelpMessage = 'The WinGet architecture to test')]
    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture
  )

  $Values = @{
    VersionNT64 = $Architecture -in @('x64', 'arm64')
    Msix64      = $Architecture -eq 'x64'
    Arm64       = $Architecture -eq 'arm64'
    Intel       = $Architecture -in @('x86', 'x64', 'arm64')
  }

  $Expression = $Condition
  $Expression = [regex]::Replace($Expression, '(?i)\b(NOT|AND|OR)\b', { param($Match) $Match.Value.ToLowerInvariant() })
  foreach ($Name in $Values.Keys) {
    $Expression = [regex]::Replace($Expression, "(?i)\b$([regex]::Escape($Name))\b", [string]$Values[$Name])
  }

  # Evaluate only the simple boolean subset used by architecture guards. Unknown
  # identifiers are treated as true so optional product checks do not create
  # false unsupported results.
  $Expression = [regex]::Replace($Expression, '(?i)\b[A-Z_][A-Z0-9_]*\b', 'True')
  $Expression = $Expression -replace '<>|=', '-eq'
  $Expression = $Expression -replace '(?i)\bnot\b', '-not'
  $Expression = $Expression -replace '(?i)\band\b', '-and'
  $Expression = $Expression -replace '(?i)\bor\b', '-or'

  try {
    return [bool]([scriptblock]::Create($Expression).Invoke())
  } catch {
    return $true
  }
}

function Get-MsiArchitectureInfoFromStaticTableInfo {
  <#
  .SYNOPSIS
    Derive supported and package architectures from MSI summary and launch-condition evidence.
  .PARAMETER StaticTableInfo
    Immutable table projection returned by Get-MsiStaticTableInfo.
  #>
  param (
    [Parameter(Mandatory)]
    [psobject]$StaticTableInfo
  )

  $Template = $StaticTableInfo.SummaryInfo.Template
  $Supported = [System.Collections.Generic.List[string]]::new()
  foreach ($Architecture in (Convert-MsiTemplatePlatformToSupportedArchitecture -Template $Template)) {
    if (-not $Supported.Contains($Architecture)) { $Supported.Add($Architecture) }
  }

  if ($Supported.Count -eq 0) {
    foreach ($Architecture in @('x86', 'x64', 'arm64')) {
      if (-not $Supported.Contains($Architecture)) { $Supported.Add($Architecture) }
    }
  }

  # Summary Template provides the baseline platform; simple architecture launch conditions may
  # narrow that set but never widen it.
  foreach ($Row in @($StaticTableInfo.LaunchConditionRows)) {
    foreach ($Architecture in @($Supported.ToArray())) {
      if (-not (Test-MsiArchitectureCondition -Condition $Row.Condition -Architecture $Architecture)) {
        $Supported.Remove($Architecture) | Out-Null
      }
    }
  }

  $SupportedArchitectures = @('x86', 'x64', 'arm64') | Where-Object { $Supported.Contains($_) }
  [PSCustomObject]@{
    Template                 = $Template
    SupportedArchitectures   = $SupportedArchitectures
    UnsupportedArchitectures = @('x86', 'x64', 'arm64') | Where-Object { $_ -notin $SupportedArchitectures }
  }
}

function Get-MsiBuilderFromStaticTableInfo {
  <#
  .SYNOPSIS
    Classify the MSI authoring system from structured tables, properties, actions, and summary data.
  .PARAMETER StaticTableInfo
    Immutable table projection returned by Get-MsiStaticTableInfo. Unknown evidence returns Unknown rather than guessing.
  #>
  param (
    [Parameter(Mandatory)]
    [psobject]$StaticTableInfo
  )

  $Properties = $StaticTableInfo.Properties
  $Tables = @($StaticTableInfo.Tables)
  $CustomActionNames = @($StaticTableInfo.CustomActionRows.Action)
  $SummaryInfoText = @(
    # DTF maps Summary Information PID_APPNAME (shown as "Program Name" by the Windows shell) to
    # CreatingApp. CreatingApplication is not a DTF property and previously discarded Bytello's
    # explicit "Windows Installer XML Toolset (...)" authoring marker.
    $StaticTableInfo.SummaryInfo.CreatingApp
    $StaticTableInfo.SummaryInfo.Comments
    $Properties.Values
    $Properties.Keys
    $Tables
    $CustomActionNames
  ) -join "`n"

  # Prefer tool-owned tables/properties/actions over free-form summary text. Return Unknown when no
  # source-backed signature survives compilation.
  if ($Tables | Where-Object { $_ -like 'AI_*' }) { return 'AdvancedInstaller' }
  if ($Properties.Keys | Where-Object { $_ -like 'AI_*' -or $_ -in @('AI_PACKAGE_TYPE', 'AI_PRODUCTNAME_ARP') }) { return 'AdvancedInstaller' }
  if ($CustomActionNames | Where-Object { $_ -like 'AI_*' }) { return 'AdvancedInstaller' }

  if ($Tables | Where-Object { $_ -like 'IS*' -or $_ -like 'InstallShield*' }) { return 'InstallShield' }
  if ($Properties.Keys | Where-Object { $_ -like 'IS*' -or $_ -like 'InstallShield*' }) { return 'InstallShield' }
  if ($CustomActionNames | Where-Object { $_ -like 'IS*' -or $_ -like 'InstallShield*' }) { return 'InstallShield' }
  if ($SummaryInfoText -match '(?i)\bInstallShield\b') { return 'InstallShield' }

  # Chromium enterprise MSIs are compiled from WiX source but do not retain
  # generic Wix tables or properties in the resulting database.
  # Source: https://chromium.googlesource.com/chromium/src/+/main/chrome/updater/win/signing/enterprise_standalone_installer.wxs.xml
  $ChromiumWiXActionNames = @('SetProductTagProperty', 'BuildInstallCommand', 'ExtractTagInfoFromInstaller', 'DoInstall')
  $HasChromiumWiXActions = -not ($ChromiumWiXActionNames | Where-Object { $_ -notin $CustomActionNames })
  $HasChromiumWiXBinaryAction = [bool]($StaticTableInfo.CustomActionRows | Where-Object {
      $_.Action -eq 'ExtractTagInfoFromInstaller' -and $_.Source -eq 'MsiInstallerCustomActionDll'
    })
  if ($HasChromiumWiXActions -and $HasChromiumWiXBinaryAction) { return 'WiX' }

  if ($Tables | Where-Object { $_ -like 'Wix*' }) { return 'WiX' }
  if ($Properties.Keys | Where-Object { $_ -like 'Wix*' -or $_ -eq 'WIXUI_INSTALLDIR' }) { return 'WiX' }
  if ($SummaryInfoText -match '(?i)\b(WiX|Windows Installer XML)\b') { return 'WiX' }

  return 'Unknown'
}

function Get-MsiInstallLocationInfoFromStaticTableInfo {
  <#
  .SYNOPSIS
    Select an MSI public install-directory property that is connected to installed components.
  .PARAMETER StaticTableInfo
    Immutable table projection returned by Get-MsiStaticTableInfo, including Property, Directory, and Component rows.
  #>
  param (
    [Parameter(Mandatory)]
    [psobject]$StaticTableInfo
  )

  $Properties = $StaticTableInfo.Properties
  $DirectoryIds = @($StaticTableInfo.DirectoryRows.Directory)
  $ComponentDirectoryIds = @($StaticTableInfo.ComponentRows.Directory | Where-Object { $_ })
  $UsedDirectoryIds = @($ComponentDirectoryIds + @($StaticTableInfo.DirectoryRows.DirectoryParent | Where-Object { $_ }) | Sort-Object -Unique)

  # Consider known public properties first, followed by authored all-uppercase directory IDs.
  $Candidates = [System.Collections.Generic.List[string]]::new()
  if ($Properties['WIXUI_INSTALLDIR']) { $Candidates.Add($Properties['WIXUI_INSTALLDIR']) }
  foreach ($Name in @('APPDIR', 'INSTALLDIR', 'INSTALLLOCATION', 'APPLICATIONROOTDIRECTORY', 'INSTALL_ROOT')) {
    $Candidates.Add($Name)
  }
  foreach ($DirectoryId in $DirectoryIds) {
    if ($DirectoryId -cmatch '^[A-Z][A-Z0-9_]*$' -and $DirectoryId -notin @('TARGETDIR', 'SourceDir', 'ProgramFilesFolder', 'ProgramFiles64Folder', 'CommonAppDataFolder', 'DesktopFolder', 'ProgramMenuFolder')) {
      $Candidates.Add($DirectoryId)
    }
  }

  foreach ($Candidate in @($Candidates | Select-Object -Unique)) {
    if ($Candidate -notin $DirectoryIds) { continue }

    # Treat the directory property as usable only if the authored directory tree uses it.
    # This avoids reporting inert WIXUI_INSTALLDIR values from packages with no install-location UI.
    $IsUsed = $Candidate -in $UsedDirectoryIds -or [bool]($StaticTableInfo.DirectoryRows | Where-Object { $_.Directory -eq $Candidate -and $_.DefaultDir -and $_.DefaultDir -ne 'SourceDir' })
    if (-not $IsUsed) { continue }

    return [PSCustomObject]@{
      Property = $Candidate
      Switch   = "$Candidate=`"<INSTALLPATH>`""
      Source   = ($Properties['WIXUI_INSTALLDIR'] -eq $Candidate) ? 'WIXUI_INSTALLDIR' : 'Directory'
    }
  }

  return [PSCustomObject]@{
    Property = $null
    Switch   = $null
    Source   = $null
  }
}

function Get-MsiAppsAndFeaturesInfo {
  <#
  .SYNOPSIS
    Read static Apps & Features detection metadata from the MSI file
  .PARAMETER Path
    The path to the MSI file
  .PARAMETER TransformPath
    The path to the transform file to be applied
  .PARAMETER PatchPath
    The path to the patch file to be applied
  .PARAMETER Database
    The database object
  #>
  [OutputType([PSCustomObject])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the MSI file')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Database', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The database object')]
    [Microsoft.Deployment.WindowsInstaller.Database]$Database,

    [Parameter(HelpMessage = 'The path to the transform file to be applied')]
    [string]$TransformPath,

    [Parameter(HelpMessage = 'The path to the patch file to be applied')]
    [AllowNull()]
    [string]$PatchPath
  )

  process {
    $Database = switch ($PSCmdlet.ParameterSetName) {
      'Path' {
        $Path = Convert-Path -Path $Path
        [Microsoft.Deployment.WindowsInstaller.Package.InstallPackage]::new($Path, 'ReadOnly')
      }
      'Database' { $Database }
      default { throw 'Invalid parameter set.' }
    }

    try {
      if ($TransformPath) {
        $TransformPath = Convert-Path -Path $TransformPath
        $Database.ApplyTransform($TransformPath)
      }

      if ($PatchPath) {
        $PatchPath = Convert-Path -Path $PatchPath
        $TransformPaths = Expand-Msp -Path $PatchPath
        foreach ($ExtractedTransformPath in $TransformPaths) {
          $Database.ApplyTransform($ExtractedTransformPath)
          Remove-Item -Path $ExtractedTransformPath -Force -ErrorAction SilentlyContinue
        }
      }

      # Compute visible ARP ownership from one table snapshot after all requested transforms have
      # been applied.
      $StaticTableInfo = Get-MsiStaticTableInfo -Database $Database
      $Properties = $StaticTableInfo.Properties

      $ProductCode = $Properties['ProductCode']
      if (-not $ProductCode) { throw 'The ProductCode property could not be found' }

      $MsqProductCode = "$ProductCode.msq"
      $EscapedMsqProductCode = [regex]::Escape($MsqProductCode)
      $EscapedProductCode = [regex]::Escape($ProductCode)

      $RegistryRows = @($StaticTableInfo.RegistryRows)

      # MSI packages can write ARP entries under HKLM, HKLM\WOW6432Node, or HKCU.
      # The Registry table stores the path after the hive, so match only the Uninstall subkey.
      $MsqRegistryRows = @($RegistryRows | Where-Object {
          $_.Key -match "(?i)(^|\\)Microsoft\\Windows\\CurrentVersion\\Uninstall\\$EscapedMsqProductCode$"
        })
      $NativeRegistryRows = @($RegistryRows | Where-Object {
          $_.Key -match "(?i)(^|\\)Microsoft\\Windows\\CurrentVersion\\Uninstall\\$EscapedProductCode$"
        })

      # Some bootstrap-style MSIs hide their native ProductCode registration and write a parallel
      # <ProductCode>.msq or custom uninstall key.
      $HasMsqAppsAndFeaturesEntry = [bool]($MsqRegistryRows | Where-Object {
          $_.Name -in @('DisplayName', 'UninstallString', 'ModifyPath', 'DisplayVersion')
        })
      $HidesMsiAppsAndFeaturesEntry = $Properties['ARPSYSTEMCOMPONENT'] -eq '1' -or [bool]($NativeRegistryRows | Where-Object {
          $_.Name -eq 'SystemComponent' -and $_.Value -match '^(#)?1$'
        })
      $CustomAppsAndFeaturesEntry = $null
      if ($HidesMsiAppsAndFeaturesEntry) {
        $CustomAppsAndFeaturesEntry = @(
          $RegistryRows |
            Where-Object { $_.Key -match '(?i)(^|\\)Microsoft\\Windows\\CurrentVersion\\Uninstall\\[^\\]+$' } |
            Where-Object { $_.Key -notmatch "(?i)(^|\\)Microsoft\\Windows\\CurrentVersion\\Uninstall\\$EscapedProductCode(\.msq)?$" } |
            Group-Object -Property Key |
            Where-Object {
              $Names = @($_.Group.Name)
              'DisplayName' -in $Names -and ('UninstallString' -in $Names -or 'ModifyPath' -in $Names)
            } |
            Select-Object -First 1
        )
      }
      $CustomAppsAndFeaturesRegistryRows = @($CustomAppsAndFeaturesEntry.Group)
      $CustomAppsAndFeaturesProductCode = if ($CustomAppsAndFeaturesEntry) {
        [regex]::Match($CustomAppsAndFeaturesEntry.Name, '[^\\]+$').Value
      } else {
        $null
      }
      # Explicit visible custom keys outrank .msq, which in turn outranks the native MSI ProductCode.
      $AppsAndFeaturesProductCode = if ($CustomAppsAndFeaturesProductCode) {
        $CustomAppsAndFeaturesProductCode
      } elseif ($HasMsqAppsAndFeaturesEntry) {
        $MsqProductCode
      } else {
        $ProductCode
      }
      $InstallerBuilder = Get-MsiBuilderFromStaticTableInfo -StaticTableInfo $StaticTableInfo
      $VisibleAppsAndFeaturesRegistryRows = if ($CustomAppsAndFeaturesProductCode) {
        $CustomAppsAndFeaturesRegistryRows
      } elseif ($HasMsqAppsAndFeaturesEntry) {
        $MsqRegistryRows
      } else {
        @()
      }
      # WinGet classifies an ARP entry as MSI only when WindowsInstaller is 1. Native MSI
      # registration implies that value even when no custom Registry-table row exists.
      $AppsAndFeaturesWindowsInstaller = if ($VisibleAppsAndFeaturesRegistryRows.Count -gt 0) {
        [bool]($VisibleAppsAndFeaturesRegistryRows | Where-Object { $_.Name -eq 'WindowsInstaller' -and $_.Value -match '^(#)?1$' })
      } else {
        $true
      }
      $AppsAndFeaturesInstallerType = if (-not $AppsAndFeaturesWindowsInstaller) {
        'exe'
      } elseif ($InstallerBuilder -eq 'WiX') {
        'wix'
      } else {
        'msi'
      }

      [PSCustomObject]@{
        InstallerType                     = $InstallerBuilder -eq 'WiX' ? 'wix' : 'msi'
        ProductCode                       = $ProductCode
        ProductName                       = $Properties['ProductName']
        ProductVersion                    = $Properties['ProductVersion']
        UpgradeCode                       = $Properties['UpgradeCode']
        InstallerBuilder                  = $InstallerBuilder
        AppsAndFeaturesInstallerType      = $AppsAndFeaturesInstallerType
        AppsAndFeaturesWindowsInstaller   = $AppsAndFeaturesWindowsInstaller
        AppsAndFeaturesProductCode        = $AppsAndFeaturesProductCode
        HasCustomAppsAndFeaturesEntry     = [bool]$CustomAppsAndFeaturesProductCode
        HasMsqAppsAndFeaturesEntry        = $HasMsqAppsAndFeaturesEntry
        HidesMsiAppsAndFeaturesEntry      = $HidesMsiAppsAndFeaturesEntry
        CustomAppsAndFeaturesRegistryKey  = $CustomAppsAndFeaturesEntry ? $CustomAppsAndFeaturesEntry.Name : $null
        CustomAppsAndFeaturesRegistryRows = $CustomAppsAndFeaturesRegistryRows
        MsqAppsAndFeaturesRegistryKey     = $MsqRegistryRows.Count -gt 0 ? $MsqRegistryRows[0].Key : $null
        MsqAppsAndFeaturesRegistryRows    = $MsqRegistryRows
      }
    } finally {
      switch ($PSCmdlet.ParameterSetName) {
        'Path' { $Database.Close() }
        'Database' { } # Do not close user-provided stream
        default { throw 'Invalid parameter set.' }
      }
    }
  }
}

function Read-AppsAndFeaturesProductCodeFromMsi {
  <#
  .SYNOPSIS
    Read the ProductCode used by Apps & Features from the MSI file
  .PARAMETER Path
    The path to the MSI file
  .PARAMETER TransformPath
    The path to the transform file to be applied
  .PARAMETER PatchPath
    The path to the patch file to be applied
  .PARAMETER Database
    The database object
  #>
  [OutputType([string])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the MSI file')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Database', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The database object')]
    [Microsoft.Deployment.WindowsInstaller.Database]$Database,

    [Parameter(HelpMessage = 'The path to the transform file to be applied')]
    [string]$TransformPath,

    [Parameter(HelpMessage = 'The path to the patch file to be applied')]
    [AllowNull()]
    [string]$PatchPath
  )

  process {
    (Get-MsiAppsAndFeaturesInfo @PSBoundParameters).AppsAndFeaturesProductCode
  }
}

function Read-AppsAndFeaturesInstallerTypeFromMsi {
  <#
  .SYNOPSIS
    Read whether the MSI writes a visible MSI or EXE Apps & Features entry
  .PARAMETER Path
    The path to the MSI file
  .PARAMETER TransformPath
    The path to the transform file to be applied
  .PARAMETER PatchPath
    The path to the patch file to be applied
  .PARAMETER Database
    The database object
  #>
  [OutputType([string])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the MSI file')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Database', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The database object')]
    [Microsoft.Deployment.WindowsInstaller.Database]$Database,

    [Parameter(HelpMessage = 'The path to the transform file to be applied')]
    [string]$TransformPath,

    [Parameter(HelpMessage = 'The path to the patch file to be applied')]
    [AllowNull()]
    [string]$PatchPath
  )

  process {
    (Get-MsiAppsAndFeaturesInfo @PSBoundParameters).AppsAndFeaturesInstallerType
  }
}

function Test-MsiMsqAppsAndFeaturesEntry {
  <#
  .SYNOPSIS
    Test whether the MSI file writes an extra Apps & Features ProductCode ending with .msq
  .PARAMETER Path
    The path to the MSI file
  .PARAMETER TransformPath
    The path to the transform file to be applied
  .PARAMETER PatchPath
    The path to the patch file to be applied
  .PARAMETER Database
    The database object
  #>
  [OutputType([bool])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the MSI file')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Database', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The database object')]
    [Microsoft.Deployment.WindowsInstaller.Database]$Database,

    [Parameter(HelpMessage = 'The path to the transform file to be applied')]
    [string]$TransformPath,

    [Parameter(HelpMessage = 'The path to the patch file to be applied')]
    [AllowNull()]
    [string]$PatchPath
  )

  process {
    (Get-MsiAppsAndFeaturesInfo @PSBoundParameters).HasMsqAppsAndFeaturesEntry
  }
}

function Get-MsiInstallerInfo {
  <#
  .SYNOPSIS
    Read static installer metadata from the MSI file
  .PARAMETER Path
    The path to the MSI file
  .PARAMETER TransformPath
    The path to the transform file to be applied
  .PARAMETER PatchPath
    The path to the patch file to be applied
  .PARAMETER Database
    The database object
  #>
  [OutputType([PSCustomObject])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the MSI file')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Database', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The database object')]
    [Microsoft.Deployment.WindowsInstaller.Database]$Database,

    [Parameter(HelpMessage = 'The path to the transform file to be applied')]
    [string]$TransformPath,

    [Parameter(HelpMessage = 'The path to the patch file to be applied')]
    [AllowNull()]
    [string]$PatchPath
  )

  process {
    $Database = switch ($PSCmdlet.ParameterSetName) {
      'Path' {
        $Path = Convert-Path -Path $Path
        [Microsoft.Deployment.WindowsInstaller.Package.InstallPackage]::new($Path, 'ReadOnly')
      }
      'Database' { $Database }
      default { throw 'Invalid parameter set.' }
    }

    try {
      if ($TransformPath) {
        $TransformPath = Convert-Path -Path $TransformPath
        $Database.ApplyTransform($TransformPath)
      }

      if ($PatchPath) {
        $PatchPath = Convert-Path -Path $PatchPath
        $TransformPaths = Expand-Msp -Path $PatchPath
        foreach ($ExtractedTransformPath in $TransformPaths) {
          $Database.ApplyTransform($ExtractedTransformPath)
          Remove-Item -Path $ExtractedTransformPath -Force -ErrorAction SilentlyContinue
        }
      }

      # Read all dependent evidence from one logical table projection; this keeps fields mutually
      # consistent and avoids repeated DTF queries.
      $StaticTableInfo = Get-MsiStaticTableInfo -Database $Database
      $Properties = $StaticTableInfo.Properties
      $InstallLocationInfo = Get-MsiInstallLocationInfoFromStaticTableInfo -StaticTableInfo $StaticTableInfo
      $AppsAndFeaturesInfo = Get-MsiAppsAndFeaturesInfo -Database $Database
      $ArchitectureInfo = Get-MsiArchitectureInfoFromStaticTableInfo -StaticTableInfo $StaticTableInfo
      $AssociationInfo = Get-MsiAssociationInfoFromStaticTableInfo -StaticTableInfo $StaticTableInfo

      [PSCustomObject]@{
        InstallerType                   = $AppsAndFeaturesInfo.InstallerType
        ProductCode                     = $Properties['ProductCode']
        ProductName                     = $Properties['ProductName']
        ProductVersion                  = $Properties['ProductVersion']
        Publisher                       = $Properties['Manufacturer']
        UpgradeCode                     = $Properties['UpgradeCode']
        AllUsers                        = $Properties['ALLUSERS']
        InstallerBuilder                = $AppsAndFeaturesInfo.InstallerBuilder
        InstallLocationProperty         = $InstallLocationInfo.Property
        InstallLocationSwitch           = $InstallLocationInfo.Switch
        InstallLocationSource           = $InstallLocationInfo.Source
        AppsAndFeaturesInstallerType    = $AppsAndFeaturesInfo.AppsAndFeaturesInstallerType
        AppsAndFeaturesWindowsInstaller = $AppsAndFeaturesInfo.AppsAndFeaturesWindowsInstaller
        AppsAndFeaturesProductCode      = $AppsAndFeaturesInfo.AppsAndFeaturesProductCode
        HasCustomAppsAndFeaturesEntry   = $AppsAndFeaturesInfo.HasCustomAppsAndFeaturesEntry
        HidesMsiAppsAndFeaturesEntry    = $AppsAndFeaturesInfo.HidesMsiAppsAndFeaturesEntry
        Template                        = $ArchitectureInfo.Template
        PackageArchitecture             = Convert-MsiTemplatePlatformToPackageArchitecture -Template $ArchitectureInfo.Template
        SupportedArchitectures          = $ArchitectureInfo.SupportedArchitectures
        UnsupportedArchitectures        = $ArchitectureInfo.UnsupportedArchitectures
        Protocols                       = $AssociationInfo.Protocols
        FileExtensions                  = $AssociationInfo.FileExtensions
        RegistryAssociationInfo         = $AssociationInfo
        AppsAndFeaturesEntries          = $AppsAndFeaturesInfo
      }
    } finally {
      switch ($PSCmdlet.ParameterSetName) {
        'Path' { $Database.Close() }
        'Database' { } # Do not close user-provided stream
        default { throw 'Invalid parameter set.' }
      }
    }
  }
}

function Get-MsiAssociationInfo {
  <#
  .SYNOPSIS
    Read static protocol and file-extension association evidence from an MSI
  .PARAMETER Path
    The path to the MSI file
  .PARAMETER TransformPath
    The path to the transform file to be applied
  .PARAMETER PatchPath
    The path to the patch file to be applied
  .PARAMETER Database
    The database object
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [Parameter(ParameterSetName = 'Database', Position = 0, ValueFromPipeline, Mandatory)][Microsoft.Deployment.WindowsInstaller.Database]$Database,
    [string]$TransformPath,
    [AllowNull()][string]$PatchPath
  )
  process { (Get-MsiInstallerInfo @PSBoundParameters).RegistryAssociationInfo }
}

function Read-ProtocolsFromMsi {
  <#
  .SYNOPSIS
    Read literal URL protocol names registered by an MSI
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-MsiAssociationInfo -Path $Path).Protocols }
}

function Read-FileExtensionsFromMsi {
  <#
  .SYNOPSIS
    Read literal file extensions registered by an MSI
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-MsiAssociationInfo -Path $Path).FileExtensions }
}

function Read-InstallLocationPropertyFromMsi {
  <#
  .SYNOPSIS
    Read the public property used to override the MSI install location
  .PARAMETER Path
    The path to the MSI file
  .PARAMETER TransformPath
    The path to the transform file to be applied
  .PARAMETER PatchPath
    The path to the patch file to be applied
  .PARAMETER Database
    The database object
  #>
  [OutputType([string])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the MSI file')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Database', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The database object')]
    [Microsoft.Deployment.WindowsInstaller.Database]$Database,

    [Parameter(HelpMessage = 'The path to the transform file to be applied')]
    [string]$TransformPath,

    [Parameter(HelpMessage = 'The path to the patch file to be applied')]
    [AllowNull()]
    [string]$PatchPath
  )

  process {
    (Get-MsiInstallerInfo @PSBoundParameters).InstallLocationProperty
  }
}

function Read-InstallLocationSwitchFromMsi {
  <#
  .SYNOPSIS
    Read the WinGet InstallLocation switch for the MSI file
  .PARAMETER Path
    The path to the MSI file
  .PARAMETER TransformPath
    The path to the transform file to be applied
  .PARAMETER PatchPath
    The path to the patch file to be applied
  .PARAMETER Database
    The database object
  #>
  [OutputType([string])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the MSI file')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Database', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The database object')]
    [Microsoft.Deployment.WindowsInstaller.Database]$Database,

    [Parameter(HelpMessage = 'The path to the transform file to be applied')]
    [string]$TransformPath,

    [Parameter(HelpMessage = 'The path to the patch file to be applied')]
    [AllowNull()]
    [string]$PatchPath
  )

  process {
    (Get-MsiInstallerInfo @PSBoundParameters).InstallLocationSwitch
  }
}

function Read-InstallerBuilderFromMsi {
  <#
  .SYNOPSIS
    Read the likely MSI authoring tool from static MSI markers
  .PARAMETER Path
    The path to the MSI file
  .PARAMETER TransformPath
    The path to the transform file to be applied
  .PARAMETER PatchPath
    The path to the patch file to be applied
  .PARAMETER Database
    The database object
  #>
  [OutputType([string])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the MSI file')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Database', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The database object')]
    [Microsoft.Deployment.WindowsInstaller.Database]$Database,

    [Parameter(HelpMessage = 'The path to the transform file to be applied')]
    [string]$TransformPath,

    [Parameter(HelpMessage = 'The path to the patch file to be applied')]
    [AllowNull()]
    [string]$PatchPath
  )

  process {
    (Get-MsiInstallerInfo @PSBoundParameters).InstallerBuilder
  }
}

function Read-UnsupportedArchitecturesFromMsi {
  <#
  .SYNOPSIS
    Read Windows architectures that the MSI installer does not support
  .PARAMETER Path
    The path to the MSI file
  .PARAMETER TransformPath
    The path to the transform file to be applied
  .PARAMETER PatchPath
    The path to the patch file to be applied
  .PARAMETER Database
    The database object
  #>
  [OutputType([string[]])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the MSI file')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Database', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The database object')]
    [Microsoft.Deployment.WindowsInstaller.Database]$Database,

    [Parameter(HelpMessage = 'The path to the transform file to be applied')]
    [string]$TransformPath,

    [Parameter(HelpMessage = 'The path to the patch file to be applied')]
    [AllowNull()]
    [string]$PatchPath
  )

  process {
    (Get-MsiInstallerInfo @PSBoundParameters).UnsupportedArchitectures
  }
}

function Test-MsiUnsupportedArchitecture {
  <#
  .SYNOPSIS
    Test whether the MSI installer does not support a Windows architecture
  .PARAMETER Path
    The path to the MSI file
  .PARAMETER Architecture
    The Windows architecture to test
  .PARAMETER TransformPath
    The path to the transform file to be applied
  .PARAMETER PatchPath
    The path to the patch file to be applied
  .PARAMETER Database
    The database object
  #>
  [OutputType([bool])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the MSI file')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Database', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The database object')]
    [Microsoft.Deployment.WindowsInstaller.Database]$Database,

    [Parameter(Mandatory, HelpMessage = 'The Windows architecture to test')]
    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture,

    [Parameter(HelpMessage = 'The path to the transform file to be applied')]
    [string]$TransformPath,

    [Parameter(HelpMessage = 'The path to the patch file to be applied')]
    [AllowNull()]
    [string]$PatchPath
  )

  process {
    $Arguments = @{} + $PSBoundParameters
    $Arguments.Remove('Architecture')
    (Get-MsiInstallerInfo @Arguments).UnsupportedArchitectures -contains $Architecture
  }
}

function Read-ProductVersionFromMsi {
  <#
  .SYNOPSIS
    Read the ProductVersion property value from the MSI file
  .PARAMETER Path
    The path to the MSI file
  .PARAMETER TransformPath
    The path to the transform file to be applied
  .PARAMETER PatchPath
    The path to the patch files to be applied
  .PARAMETER Database
    The database object
  #>
  [OutputType([string])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the MSI file')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Database', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The database object')]
    [Microsoft.Deployment.WindowsInstaller.Database]$Database,

    [Parameter(HelpMessage = 'The path to the transform file to be applied')]
    [string]$TransformPath,

    [Parameter(HelpMessage = 'The path to the patch file to be applied')]
    [AllowNull()]
    [string]$PatchPath
  )

  process {
    Read-MsiProperty @PSBoundParameters -Query "SELECT Value FROM Property WHERE Property='ProductVersion'"
  }
}

function Read-ProductCodeFromMsi {
  <#
  .SYNOPSIS
    Read the ProductCode property value from the MSI file
  .PARAMETER Path
    The path to the MSI file
  .PARAMETER TransformPath
    The path to the transform files to be applied
  .PARAMETER PatchPath
    The path to the patch files to be applied
  .PARAMETER Database
    The database object
  #>
  [OutputType([string])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the MSI file')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Database', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The database object')]
    [Microsoft.Deployment.WindowsInstaller.Database]$Database,

    [Parameter(HelpMessage = 'The path to the transform file to be applied')]
    [string]$TransformPath,

    [Parameter(HelpMessage = 'The path to the patch file to be applied')]
    [AllowNull()]
    [string]$PatchPath
  )

  process {
    Read-MsiProperty @PSBoundParameters -Query "SELECT Value FROM Property WHERE Property='ProductCode'"
  }
}

function Read-UpgradeCodeFromMsi {
  <#
  .SYNOPSIS
    Read the UpgradeCode property value from the MSI file
  .PARAMETER Path
    The path to the MSI file
  .PARAMETER TransformPath
    The path to the transform files to be applied
  .PARAMETER PatchPath
    The path to the patch files to be applied
  .PARAMETER Database
    The database object
  #>
  [OutputType([string])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the MSI file')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Database', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The database object')]
    [Microsoft.Deployment.WindowsInstaller.Database]$Database,

    [Parameter(HelpMessage = 'The path to the transform file to be applied')]
    [string]$TransformPath,

    [Parameter(HelpMessage = 'The path to the patch file to be applied')]
    [AllowNull()]
    [string]$PatchPath
  )

  process {
    Read-MsiProperty @PSBoundParameters -Query "SELECT Value FROM Property WHERE Property='UpgradeCode'"
  }
}

function Read-ProductNameFromMsi {
  <#
  .SYNOPSIS
    Read the ProductName property value from the MSI file
  .PARAMETER Path
    The path to the MSI file
  .PARAMETER TransformPath
    The path to the transform files to be applied
  .PARAMETER PatchPath
    The path to the patch files to be applied
  .PARAMETER Database
    The database object
  #>
  [OutputType([string])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the MSI file')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Database', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The database object')]
    [Microsoft.Deployment.WindowsInstaller.Database]$Database,

    [Parameter(HelpMessage = 'The path to the transform file to be applied')]
    [string]$TransformPath,

    [Parameter(HelpMessage = 'The path to the patch file to be applied')]
    [AllowNull()]
    [string]$PatchPath
  )

  process {
    Read-MsiProperty @PSBoundParameters -Query "SELECT Value FROM Property WHERE Property='ProductName'"
  }
}

function Read-MsiSummaryInfo {
  <#
  .SYNOPSIS
    Read the summary table of the MSI file
  .PARAMETER Path
    The path to the MSI file
  .PARAMETER PatchFile
    Indicate the file is a patch file
  .PARAMETER Database
    The database object
  #>
  [OutputType([Microsoft.Deployment.WindowsInstaller.SummaryInfo])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the MSI file')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Path', HelpMessage = 'Indicate the file is a patch file')]
    [switch]$PatchFile,

    [Parameter(ParameterSetName = 'Database', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The database object')]
    [Microsoft.Deployment.WindowsInstaller.Database]$Database
  )

  process {
    $Database = switch ($PSCmdlet.ParameterSetName) {
      'Path' {
        $Path = Convert-Path -Path $Path
        $PatchFile ? [Microsoft.Deployment.WindowsInstaller.Package.PatchPackage]::new($Path) : [Microsoft.Deployment.WindowsInstaller.Package.InstallPackage]::new($Path, 'ReadOnly')
      }
      'Database' { $Database }
      default { throw 'Invalid parameter set.' }
    }

    $Database.SummaryInfo

    switch ($PSCmdlet.ParameterSetName) {
      'Path' { $Database.Close() }
      'Database' { } # Do not close user-provided stream
      default { throw 'Invalid parameter set.' }
    }
  }
}

function Test-WiXInstaller {
  <#
  .SYNOPSIS
    Test whether the MSI file contains WiX authoring markers
  .PARAMETER Path
    The path to the MSI file
  .PARAMETER TransformPath
    The path to the transform file to be applied
  .PARAMETER PatchPath
    The path to the patch files to be applied
  .PARAMETER Database
    The database object
  #>
  [OutputType([bool])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the MSI file')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Database', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The database object')]
    [Microsoft.Deployment.WindowsInstaller.Database]$Database,

    [Parameter(HelpMessage = 'The path to the transform file to be applied')]
    [string]$TransformPath,

    [Parameter(HelpMessage = 'The path to the patch file to be applied')]
    [AllowNull()]
    [string]$PatchPath
  )

  process {
    $Database = switch ($PSCmdlet.ParameterSetName) {
      'Path' {
        $Path = Convert-Path -Path $Path
        [Microsoft.Deployment.WindowsInstaller.Package.InstallPackage]::new($Path, 'ReadOnly')
      }
      'Database' { $Database }
      default { throw 'Invalid parameter set.' }
    }

    # Keep this local to avoid changing Read-MsiProperty's strict scalar behavior.
    function Test-QueryStringMatch {
      <#
      .SYNOPSIS
        Test whether any string field from an optional MSI query satisfies a predicate.
      .PARAMETER Database
        Open caller-owned Windows Installer database.
      .PARAMETER Query
        SQL query whose first field is converted to string.
      .PARAMETER Predicate
        Script block receiving each string. A truthy result stops enumeration.
      #>
      param (
        [Microsoft.Deployment.WindowsInstaller.Database]$Database,
        [string]$Query,
        [scriptblock]$Predicate
      )

      $View = $null
      $Record = $null
      try {
        $View = $Database.OpenView($Query)
        $View.Execute()
        while ($Record = $View.Fetch()) {
          try {
            if (& $Predicate $Record) { return $true }
          } finally {
            $Record.Close()
            $Record = $null
          }
        }
      } catch {
        return $false
      } finally {
        if ($Record) { $Record.Close() }
        if ($View) { $View.Close() }
      }

      return $false
    }

    try {
      if ($TransformPath) {
        $TransformPath = Convert-Path -Path $TransformPath
        $Database.ApplyTransform($TransformPath)
      }

      if ($PatchPath) {
        $PatchPath = Convert-Path -Path $PatchPath
        $TransformPaths = Expand-Msp -Path $PatchPath
        foreach ($TransformPath in $TransformPaths) {
          $Database.ApplyTransform($TransformPath)
          Remove-Item -Path $TransformPath -Force -ErrorAction SilentlyContinue
        }
      }

      $SummaryInfo = $Database.SummaryInfo
      if ($SummaryInfo) {
        foreach ($Property in $SummaryInfo.GetType().GetProperties()) {
          if (-not $Property.CanRead -or $Property.GetIndexParameters().Count -gt 0) { continue }
          try {
            $Value = [string]$Property.GetValue($SummaryInfo)
            if ($Value -match '(?i)\b(wix|windows installer xml)\b') { return $true }
          } catch {
            continue
          }
        }
      }

      if (Test-QueryStringMatch -Database $Database -Query 'SELECT `Name` FROM `_Tables`' -Predicate {
          param($Record)
          $TableName = $Record.GetString(1)
          $TableName -match '(?i)^Wix'
        }) {
        return $true
      }

      if (Test-QueryStringMatch -Database $Database -Query 'SELECT `Property`, `Value` FROM `Property`' -Predicate {
          param($Record)
          $PropertyName = $Record.GetString(1)
          $PropertyValue = $Record.GetString(2)
          $PropertyName -match '(?i)\bWix' -or $PropertyValue -match '(?i)\b(wix|windows installer xml)\b'
        }) {
        return $true
      }

      # MajorUpgrade output can be the only retained WiX signature. Require both compiler-owned
      # Upgrade action properties and the generated downgrade guard rather than accepting one
      # product-authored string that merely starts with WIX_.
      $HasWiXUpgradeDetection = Test-QueryStringMatch -Database $Database -Query 'SELECT `ActionProperty` FROM `Upgrade`' -Predicate {
        param($Record)
        $Record.GetString(1) -ceq 'WIX_UPGRADE_DETECTED'
      }
      $HasWiXDowngradeDetection = Test-QueryStringMatch -Database $Database -Query 'SELECT `ActionProperty` FROM `Upgrade`' -Predicate {
        param($Record)
        $Record.GetString(1) -ceq 'WIX_DOWNGRADE_DETECTED'
      }
      $HasWiXDowngradeCondition = Test-QueryStringMatch -Database $Database -Query 'SELECT `Condition` FROM `LaunchCondition`' -Predicate {
        param($Record)
        $Record.GetString(1) -match '(?i)^\s*\(?\s*NOT\s+WIX_DOWNGRADE_DETECTED\s*\)?\s*$'
      }
      if ($HasWiXUpgradeDetection -and $HasWiXDowngradeDetection -and $HasWiXDowngradeCondition) {
        return $true
      }

      return $false
    } finally {
      switch ($PSCmdlet.ParameterSetName) {
        'Path' { $Database.Close() }
        'Database' { } # Do not close user-provided stream
        default { throw 'Invalid parameter set.' }
      }
    }
  }
}
