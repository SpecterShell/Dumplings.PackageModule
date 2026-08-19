# SPDX-License-Identifier: MIT
# Format sources: https://github.com/wixtoolset/wix
# MSI Word Count elevation bit: https://learn.microsoft.com/windows/win32/msi/word-count-summary
# MSI runtime elevation properties: https://learn.microsoft.com/windows/win32/msi/msirunningelevated-
# MSI condition grammar: https://learn.microsoft.com/windows/win32/msi/conditional-statement-syntax
# InstallShield ISSetAllUsers behavior: https://docs.revenera.com/installshield27helplib/helplibrary/IHelpISSetAllUsers.htm
# Chromium enterprise MSI product tag: https://chromium.googlesource.com/chromium/src/+/main/chrome/updater/win/signing/enterprise_standalone_installer.wxs.xml
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

function Import-Assembly {
  <#
  .SYNOPSIS
    Load the Microsoft.Deployment.WindowsInstaller.Package.dll assembly
  #>

  # The GPL parser CLI may have imported its byte-identical runtime first. Pass PackageModule's
  # asset root explicitly so DTF resolution does not depend on global module import order.
  $AssetRoot = Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath '..', 'Assets'
  $null = Import-InstallerManagedAssembly -Name 'Microsoft.Deployment.WindowsInstaller.dll' -TypeName 'Microsoft.Deployment.WindowsInstaller.Database' -AssetRoot $AssetRoot
  $null = Import-InstallerManagedAssembly -Name 'Microsoft.Deployment.WindowsInstaller.Package.dll' -TypeName 'Microsoft.Deployment.WindowsInstaller.Package.InstallPackage' -AssetRoot $AssetRoot
}

Import-Assembly

# MSI conditions are parsed by an independent bounded grammar. Do not translate
# database-authored text into PowerShell scriptblocks: the grammars differ and
# PowerShell redirection operators can create files while evaluating malformed
# or only partially translated input.
$MsiConditionSource = Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath '..', 'Assets', 'Source', 'MSI', 'MsiConditionEvaluator.cs'
$null = Import-InstallerManagedSource -Path $MsiConditionSource -TypeName 'Dumplings.WindowsInstaller.Conditions.MsiConditionEvaluator'

# Load family-specific MSI interpretation without keeping those rules in this module.
if (-not (Get-Command Get-MsiInstallShieldProjectTypeFromStaticTableInfo -ErrorAction SilentlyContinue)) {
  Import-Module (Join-Path $PSScriptRoot 'InstallShieldMsi.psm1') -Force -Global
}
if (-not (Get-Command Get-MsiChromiumEnterpriseInfoFromStaticTableInfo -ErrorAction SilentlyContinue)) {
  Import-Module (Join-Path $PSScriptRoot 'ChromiumUpdater.psm1') -Force -Global
}

# Keep InstallShield authoring-system interpretation separate from generic MSI mechanics.






function Export-MsiBinaryTableStream {
  <#
  .SYNOPSIS
    Export one named MSI Binary-table stream through an already-open database.
  .PARAMETER Database
    Caller-owned DTF database. This helper closes only its view, records, and
    stream; it never closes the database.
  .PARAMETER Name
    Exact Binary.Name primary key selected with a parameterized MSI query.
  .PARAMETER DestinationPath
    Resolved output path for the bounded binary stream.
  .PARAMETER MaximumBytes
    Hard maximum accepted stream size. Copying stops with an error above it.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][Microsoft.Deployment.WindowsInstaller.Database]$Database,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$DestinationPath,
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumBytes = 128MB
  )

  $ResolvedDestination = [IO.Path]::GetFullPath($DestinationPath)
  $View = $ParameterRecord = $DataRecord = $InputStream = $OutputStream = $null
  try {
    $View = $Database.OpenView('SELECT `Data` FROM `Binary` WHERE `Name` = ?')
    $ParameterRecord = [Microsoft.Deployment.WindowsInstaller.Record]::new(1)
    $ParameterRecord.SetString(1, $Name)
    $View.Execute($ParameterRecord)
    $DataRecord = $View.Fetch()
    if (-not $DataRecord) { throw "MSI Binary table stream '$Name' was not found." }

    # DTF exposes the structured-storage stream without materializing it as a
    # PowerShell byte array. The shared bounded copier rejects oversized data.
    $InputStream = $DataRecord.GetStream(1)
    $OutputStream = [IO.File]::Open($ResolvedDestination, 'CreateNew', 'Write', 'None')
    $null = Copy-BoundedStream -Source $InputStream -Destination $OutputStream -MaximumBytes $MaximumBytes
    return $ResolvedDestination
  } finally {
    if ($OutputStream) { $OutputStream.Dispose() }
    if ($InputStream) { $InputStream.Dispose() }
    if ($DataRecord) { $DataRecord.Close() }
    if ($ParameterRecord) { $ParameterRecord.Close() }
    if ($View) { $View.Close() }
  }
}





function Expand-Msp {
  <#
  .SYNOPSIS
    Extract Transforms from the MSP file
  .PARAMETER Path
    The path to the MSP file
  .PARAMETER Database
    The patch package database object
  .PARAMETER DestinationPath
    Optional output directory. Temporary files are used when omitted.
  .PARAMETER Name
    Optional wildcard selecting transform names. All transforms are extracted when omitted.
  .PARAMETER CollisionAction
    Behavior when a destination transform path already exists.
  #>
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the MSP file')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Database', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The patch package database object')]
    [Microsoft.Deployment.WindowsInstaller.Package.PatchPackage]$Database,

    [string]$DestinationPath,

    [string]$Name = '*',

    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')]
    [string]$CollisionAction = 'Prompt'
  )

  process {
    $Database = switch ($PSCmdlet.ParameterSetName) {
      'Path' { [Microsoft.Deployment.WindowsInstaller.Package.PatchPackage]::new((Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf)) }
      'Database' { $Database }
      default { throw 'Invalid parameter set.' }
    }

    try {
      $Transforms = @($Database.GetTransforms())
      $OutputRoot = if ([string]::IsNullOrWhiteSpace($DestinationPath)) { $null } else {
        Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
      }
      if ($OutputRoot) { $null = New-Item -Path $OutputRoot -ItemType Directory -Force }
      $TemporaryOutputRoot = if ($OutputRoot) { $null } else { New-TempFolder }
      $ReservedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
      $Index = 0
      foreach ($Transform in $Transforms) {
        $Index++
        if (-not (Test-ExtractionPattern -Path ([string]$Transform) -Pattern $Name)) { continue }
        if ($OutputRoot) {
          $LeafName = [IO.Path]::GetFileName([string]$Transform)
          if ([string]::IsNullOrWhiteSpace($LeafName)) { $LeafName = "Transform$Index.mst" }
          if ([IO.Path]::GetExtension($LeafName) -ine '.mst') { $LeafName += '.mst' }
          $Target = Resolve-InstallerExtractionTarget -DestinationPath $OutputRoot -RelativePath $LeafName `
            -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
          if (-not $Target.ShouldWrite) { continue }
          $File = $Target.Path
        } else {
          $File = Join-Path $TemporaryOutputRoot "Transform$Index.mst"
        }
        $Database.ExtractTransform($Transform, $File)
        Write-Output -InputObject (Resolve-InstallerFileSystemPath -Path $File -PathType Leaf)
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
    $View = $null
    $Record = $null
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
      $TransformPaths = Expand-Msp -Path $PatchPath -CollisionAction Rename
      foreach ($TransformPath in $TransformPaths) {
        $Database.ApplyTransform($TransformPath)
        Remove-Item -Path $TransformPath -Force -ErrorAction SilentlyContinue
      }
    }

    try {
      $View = $Database.OpenView($Query)
      $View.Execute()
      $Record = $View.Fetch()
      if (-not $Record) { throw "The Windows Installer query returned no rows: $Query" }
      $Record.GetString($Field)
    } finally {
      if ($Record) { $Record.Close() }
      if ($View) { $View.Close() }
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
  $BinaryNames = [string[]]@((Get-MsiQueryRow -Database $Database -Query 'SELECT `Name` FROM `Binary`' -FieldNames @('Name')).Name)
  $CustomActionRows = @(Get-MsiQueryRow -Database $Database -Query 'SELECT `Action`, `Type`, `Source`, `Target` FROM `CustomAction`' -FieldNames @('Action', 'Type', 'Source', 'Target'))
  $SequenceRows = foreach ($SequenceTable in @('InstallExecuteSequence', 'InstallUISequence', 'AdminExecuteSequence', 'AdminUISequence', 'AdvtExecuteSequence')) {
    foreach ($Row in @(Get-MsiQueryRow -Database $Database -Query "SELECT ``Action``, ``Condition``, ``Sequence`` FROM ``$SequenceTable``" -FieldNames @('Action', 'Condition', 'Sequence'))) {
      [pscustomobject][ordered]@{
        Table     = $SequenceTable
        Action    = $Row.Action
        Condition = $Row.Condition
        Sequence  = $Row.Sequence
      }
    }
  }
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
  $InstallShieldTableInfo = Get-MsiInstallShieldPrerequisiteTableInfo -Database $Database

  [PSCustomObject]@{
    Properties                           = $Properties
    Tables                               = $Tables
    DirectoryRows                        = $DirectoryRows
    ComponentRows                        = $ComponentRows
    BinaryNames                          = $BinaryNames
    CustomActionRows                     = $CustomActionRows
    SequenceRows                         = [object[]]@($SequenceRows)
    LaunchConditionRows                  = @(Get-MsiQueryRow -Database $Database -Query 'SELECT `Condition`, `Description` FROM `LaunchCondition`' -FieldNames @('Condition', 'Description'))
    RegistryRows                         = @($RegistryRows)
    ExtensionRows                        = $ExtensionRows
    ProgIdRows                           = $ProgIdRows
    VerbRows                             = $VerbRows
    MimeRows                             = $MimeRows
    InstallShieldPrerequisiteRows        = $InstallShieldTableInfo.Prerequisites
    InstallShieldFeaturePrerequisiteRows = $InstallShieldTableInfo.Features
    SummaryInfo                          = $Database.SummaryInfo
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

function Resolve-MsiConditionExpression {
  <#
  .SYNOPSIS
    Parse and statically evaluate a Windows Installer conditional expression.
  .DESCRIPTION
    Evaluates the documented MSI condition grammar against an explicit virtual
    installer session. Unprovided runtime symbols are unresolved by default,
    producing Unknown rather than borrowing state from the parser host.
  .PARAMETER Condition
    MSI conditional expression from LaunchCondition, Condition, or a sequence table.
  .PARAMETER Property
    Case-sensitive MSI property values known in the virtual session.
  .PARAMETER KnownPresentProperty
    Properties known to be nonempty whose exact values are unavailable. Their
    Boolean truth is known, while comparisons involving their values remain Unknown.
  .PARAMETER KnownAbsentProperty
    Properties known to be absent. Windows Installer evaluates them as empty strings.
  .PARAMETER EnvironmentVariable
    Case-insensitive process environment-variable values used by %Name symbols.
  .PARAMETER ComponentActionState
    Numeric action states used by $Component symbols.
  .PARAMETER ComponentInstalledState
    Numeric installed states used by ?Component symbols.
  .PARAMETER FeatureActionState
    Numeric action states used by &Feature symbols.
  .PARAMETER FeatureInstalledState
    Numeric installed states used by !Feature symbols.
  .PARAMETER UnspecifiedSymbolState
    Unknown preserves incomplete static evidence. Absent models a complete MSI
    session where missing properties and environment values are empty and missing
    feature or component states are INSTALLSTATE_UNKNOWN (-1).
  .PARAMETER MaximumTokenCount
    Maximum non-EOF tokens accepted from one condition.
  .PARAMETER MaximumDepth
    Maximum nested parentheses and unary NOT depth.
  .OUTPUTS
    A structured result with State, Value, referenced and unresolved symbols,
    token count, and deterministic syntax diagnostics.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, Position = 0, ValueFromPipeline, HelpMessage = 'The MSI conditional expression')]
    [AllowEmptyString()]
    [string]$Condition,

    [Parameter()]
    [AllowNull()]
    [Collections.IDictionary]$Property,

    [Parameter()]
    [string[]]$KnownPresentProperty = @(),

    [Parameter()]
    [string[]]$KnownAbsentProperty = @(),

    [Parameter()]
    [AllowNull()]
    [Collections.IDictionary]$EnvironmentVariable,

    [Parameter()]
    [AllowNull()]
    [Collections.IDictionary]$ComponentActionState,

    [Parameter()]
    [AllowNull()]
    [Collections.IDictionary]$ComponentInstalledState,

    [Parameter()]
    [AllowNull()]
    [Collections.IDictionary]$FeatureActionState,

    [Parameter()]
    [AllowNull()]
    [Collections.IDictionary]$FeatureInstalledState,

    [Parameter()]
    [ValidateSet('Unknown', 'Absent')]
    [string]$UnspecifiedSymbolState = 'Unknown',

    [Parameter()]
    [ValidateRange(1, 65536)]
    [int]$MaximumTokenCount = 1024,

    [Parameter()]
    [ValidateRange(1, 1024)]
    [int]$MaximumDepth = 64
  )

  process {
    $Context = [Dumplings.WindowsInstaller.Conditions.MsiConditionEvaluationContext]::new()
    $Context.UnspecifiedSymbolsAreAbsent = $UnspecifiedSymbolState -eq 'Absent'

    # Populate each MSI namespace independently because only environment names
    # are case-insensitive in the Windows Installer condition language.
    if ($Property) { foreach ($Entry in $Property.GetEnumerator()) { $Context.SetProperty([string]$Entry.Key, [string]$Entry.Value) } }
    foreach ($Name in $KnownPresentProperty) { if (-not [string]::IsNullOrEmpty($Name)) { $Context.MarkPropertyPresent($Name) } }
    foreach ($Name in $KnownAbsentProperty) { if (-not [string]::IsNullOrEmpty($Name)) { $Context.MarkPropertyAbsent($Name) } }
    if ($EnvironmentVariable) { foreach ($Entry in $EnvironmentVariable.GetEnumerator()) { $Context.SetEnvironmentVariable([string]$Entry.Key, [string]$Entry.Value) } }
    if ($ComponentActionState) { foreach ($Entry in $ComponentActionState.GetEnumerator()) { $Context.SetComponentActionState([string]$Entry.Key, [long]$Entry.Value) } }
    if ($ComponentInstalledState) { foreach ($Entry in $ComponentInstalledState.GetEnumerator()) { $Context.SetComponentInstalledState([string]$Entry.Key, [long]$Entry.Value) } }
    if ($FeatureActionState) { foreach ($Entry in $FeatureActionState.GetEnumerator()) { $Context.SetFeatureActionState([string]$Entry.Key, [long]$Entry.Value) } }
    if ($FeatureInstalledState) { foreach ($Entry in $FeatureInstalledState.GetEnumerator()) { $Context.SetFeatureInstalledState([string]$Entry.Key, [long]$Entry.Value) } }

    $Evaluation = [Dumplings.WindowsInstaller.Conditions.MsiConditionEvaluator]::Evaluate($Condition, $Context, $MaximumTokenCount, $MaximumDepth)
    [pscustomobject][ordered]@{
      Expression        = [string]$Evaluation.Expression
      State             = [string]$Evaluation.State
      Value             = $Evaluation.Value
      IsValid           = [bool]$Evaluation.IsValid
      IsComplete        = [bool]$Evaluation.IsComplete
      ReferencedSymbols = [object[]]@($Evaluation.Symbols | ForEach-Object {
          [pscustomobject][ordered]@{
            Kind      = [string]$_.Kind
            Name      = [string]$_.Name
            IsKnown   = [bool]$_.IsKnown
            IsPresent = $_.IsPresent
            Value     = $_.Value
          }
        })
      UnknownSymbols    = [string[]]@($Evaluation.UnknownSymbols)
      TokenCount        = [int]$Evaluation.TokenCount
      ErrorMessage      = [string]$Evaluation.ErrorMessage
      ErrorPosition     = [int]$Evaluation.ErrorPosition
    }
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

  # Launch conditions unrelated to processor architecture must not narrow the package platform.
  # They can contain product, feature, component, or runtime state that this projection does not model.
  if ($Condition -notmatch '(?i)\b(?:VersionNT64|Msix64|Arm64|Intel)\b') { return $true }

  $Properties = [ordered]@{ Intel = '1' }
  $PresentProperties = [Collections.Generic.List[string]]::new()
  $AbsentProperties = [Collections.Generic.List[string]]::new()
  switch ($Architecture) {
    'x86' {
      foreach ($Name in 'VersionNT64', 'Msix64', 'Arm64') { $AbsentProperties.Add($Name) }
    }
    'x64' {
      $PresentProperties.Add('VersionNT64')
      $Properties['Msix64'] = '1'
      $AbsentProperties.Add('Arm64')
    }
    'arm64' {
      $PresentProperties.Add('VersionNT64')
      $Properties['Arm64'] = '1'
      $AbsentProperties.Add('Msix64')
    }
  }

  $Result = Resolve-MsiConditionExpression -Condition $Condition -Property $Properties -KnownPresentProperty $PresentProperties.ToArray() -KnownAbsentProperty $AbsentProperties.ToArray()
  # Unknown runtime properties or malformed package-authored expressions cannot
  # prove that an architecture is unsupported. Narrow only on a conclusive false.
  return $Result.State -ne 'False'
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





function Get-MsiElevationInfoFromStaticTableInfo {
  <#
  .SYNOPSIS
    Derive a WinGet elevation requirement from explicit MSI database behavior.
  .DESCRIPTION
    Treats launch conditions and scheduled custom actions as behavioral evidence.
    ALLUSERS, machine directories, privileged deferred actions, and a clear Word
    Count bit 3 are deliberately insufficient by themselves: Windows Installer
    documents a clear bit only as "elevation can be required".
  .PARAMETER StaticTableInfo
    Immutable table projection returned by Get-MsiStaticTableInfo. The function
    does not query or mutate the underlying MSI database.
  .PARAMETER ChromiumEnterpriseInfo
    Optional source-grounded Chromium enterprise MSI evidence. When supplied,
    an appended product tag overrides the default ProductTag action exactly as
    the MSI custom-action sequence does.
  .OUTPUTS
    An object containing ElevationRequirement, structured Evidence, the summary
    bit interpretation, and parser warnings for contradictory authored metadata.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]
    [psobject]$StaticTableInfo,

    [AllowNull()]
    [psobject]$ChromiumEnterpriseInfo
  )

  $Evidence = [System.Collections.Generic.List[object]]::new()
  $Warnings = [System.Collections.Generic.List[string]]::new()
  $SummaryWordCount = [int]$StaticTableInfo.SummaryInfo.WordCount
  $AllowsInstallWithoutElevation = ($SummaryWordCount -band 0x08) -ne 0

  # A LaunchCondition row is authoritative when its authored message explicitly
  # states that elevation is required. Also accept the simple standard-property
  # forms whose truth directly requires an elevated Windows Installer context.
  $ElevationRequirementPattern = '(?i)(?:\b(?:requires?|required|needs?|needed|must)\b.{0,80}\b(?:elevat(?:e|ed|ion)|administrator|administrative|admin(?:istrator)?(?:\s+rights?)?|privileg(?:e|es|ed))\b|\b(?:elevat(?:e|ed|ion)|administrator|administrative|admin(?:istrator)?(?:\s+rights?)?|privileg(?:e|es|ed))\b.{0,80}\b(?:requires?|required|needs?|needed|must)\b)'
  $SimpleElevationConditionPattern = '(?i)^\s*\(*\s*(?:(?:Installed|REMOVE\s*~?=\s*"ALL")\s+OR\s+)?(?:MsiRunningElevated|Privileged|AdminUser)\s*\)*\s*$'
  foreach ($Row in @($StaticTableInfo.LaunchConditionRows)) {
    $Condition = [string]$Row.Condition
    $Description = [string]$Row.Description
    if ($Description -match $ElevationRequirementPattern -or $Condition -match $SimpleElevationConditionPattern) {
      $Evidence.Add([pscustomobject][ordered]@{
          Kind        = 'LaunchCondition'
          Confidence  = 'Explicit'
          Action      = 'LaunchConditions'
          Condition   = $Condition
          Description = $Description
          Source      = 'LaunchCondition table'
        })
    }
  }

  $SequenceRows = @($StaticTableInfo.SequenceRows)
  foreach ($Action in @($StaticTableInfo.CustomActionRows)) {
    $ActionName = [string]$Action.Action
    $ActionSource = [string]$Action.Source
    $ActionTarget = [string]$Action.Target
    $ScheduledRows = @($SequenceRows | Where-Object {
        $_.Action -ceq $ActionName -and $_.Table -in @('InstallExecuteSequence', 'InstallUISequence')
      })

    # Chromium's enterprise MSI source passes needsAdmin=True to the nested
    # updater. This literal field is target-installer behavior, not a heuristic
    # based on the product name or the presence of a deferred custom action.
    if ([int]$Action.Type -eq 51 -and $ActionTarget -match '(?i)(?:^|[&;])needsAdmin\s*=\s*True(?:[&;]|$)') {
      # The source-defined default is superseded by TAGSTRING in tagged MSI
      # variants. ChromiumEnterpriseInfo adds evidence for the effective value.
      if ($ChromiumEnterpriseInfo -and $ChromiumEnterpriseInfo.IsDetected) { continue }
      $Evidence.Add([pscustomobject][ordered]@{
          Kind        = 'NestedInstallerProductTag'
          Confidence  = 'Explicit'
          Action      = $ActionName
          Condition   = $null
          Description = 'The nested installer product tag contains needsAdmin=True.'
          Source      = $ActionSource
        })
      continue
    }

    # Some packages schedule an immediate action whose declared purpose is to
    # restart as administrator. Require an actual sequence row so an unused
    # Binary/CustomAction-table remnant does not affect the result.
    if ($ScheduledRows.Count -gt 0 -and ($ActionName -ieq 'RestartAsAdmin' -or $ActionTarget -ieq 'RestartAsAdmin')) {
      $Evidence.Add([pscustomobject][ordered]@{
          Kind        = 'ElevationCustomAction'
          Confidence  = 'Explicit'
          Action      = $ActionName
          Condition   = ($ScheduledRows.Condition -join '; ')
          Description = 'A scheduled custom action attempts to restart installation as administrator; successful unattended continuation is not implied.'
          Source      = $ActionSource
        })
      continue
    }

    # InstallShield inserts ISSetAllUsers to synchronize upgrade context. It is
    # not itself an elevation declaration, but the early immediate action runs
    # before the normal installation transaction and is observed to terminate
    # quiet non-elevated installs in affected Basic MSI packages. Require the
    # exact vendor action layout, an early execute-sequence row, and a package
    # that has not declared non-elevated support.
    $EarlyInstallShieldRows = @($ScheduledRows | Where-Object {
        $_.Table -eq 'InstallExecuteSequence' -and [int]$_.Sequence -gt 0 -and [int]$_.Sequence -lt 1500
      })
    if (-not $AllowsInstallWithoutElevation -and
      $EarlyInstallShieldRows.Count -gt 0 -and
      $ActionName -ceq 'ISSetAllUsers' -and
      $ActionSource -ieq 'SetAllUsers.dll' -and
      $ActionTarget -ieq 'SetAllUsers') {
      $Evidence.Add([pscustomobject][ordered]@{
          Kind        = 'InstallShieldEarlyContextAction'
          Confidence  = 'Observed'
          Action      = $ActionName
          Condition   = ($EarlyInstallShieldRows.Condition -join '; ')
          Description = 'InstallShield schedules ISSetAllUsers before the normal install transaction and does not declare non-elevated support.'
          Source      = $ActionSource
        })
    }
  }

  if ($ChromiumEnterpriseInfo -and $ChromiumEnterpriseInfo.IsDetected) {
    if ($ChromiumEnterpriseInfo.RequiresPreElevationForSilent) {
      $Evidence.Add([pscustomobject][ordered]@{
          Kind        = 'ChromiumUpdaterSilentPreElevation'
          Confidence  = 'Explicit'
          Action      = 'DoInstall'
          Condition   = $ChromiumEnterpriseInfo.IsSilentAtBasicUi ? 'Nested updater is silent for no/basic UI.' : 'Nested updater is silent only for no UI.'
          Description = "The effective needsadmin value is '$($ChromiumEnterpriseInfo.EffectiveNeedsAdmin)' and plain --silent suppresses Chromium Updater UAC; silent installation requires an already elevated MSI context."
          Source      = $ChromiumEnterpriseInfo.ProductTagSource
        })
    } elseif ($ChromiumEnterpriseInfo.EffectiveNeedsAdmin -ieq 'true') {
      $Evidence.Add([pscustomobject][ordered]@{
          Kind        = 'NestedInstallerProductTag'
          Confidence  = 'Explicit'
          Action      = 'SetProductTagProperty'
          Condition   = $null
          Description = 'The effective Chromium updater product tag contains needsAdmin=True.'
          Source      = $ChromiumEnterpriseInfo.ProductTagSource
        })
    }
  }

  if ($Evidence.Count -gt 0 -and $AllowsInstallWithoutElevation) {
    $Warnings.Add('Explicit MSI elevation behavior conflicts with Summary Information Word Count bit 3, which declares that elevated privileges are not required.')
  }

  return [pscustomobject][ordered]@{
    ElevationRequirement          = $Evidence.Count -gt 0 ? 'elevationRequired' : $null
    Evidence                      = [object[]]$Evidence.ToArray()
    SummaryWordCount              = $SummaryWordCount
    AllowsInstallWithoutElevation = $AllowsInstallWithoutElevation
    Warnings                      = [string[]]$Warnings.ToArray()
  }
}

function Get-MsiBuilderEvidenceFromStaticTableInfo {
  <#
  .SYNOPSIS
    Classify the MSI authoring system and report the source of that classification.
  .PARAMETER StaticTableInfo
    Immutable table projection returned by Get-MsiStaticTableInfo. Unknown evidence returns Unknown rather than guessing.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]
    [psobject]$StaticTableInfo
  )

  $Properties = $StaticTableInfo.Properties
  $CustomActionNames = @($StaticTableInfo.CustomActionRows.Action)
  $CreatingApplication = [string]$StaticTableInfo.SummaryInfo.CreatingApp

  # PID_APPNAME is the database author's direct declaration of the creating
  # application. It outranks incidental property and custom-action names that
  # an application can carry independently of the MSI compiler.
  $SummaryBuilder = switch -Regex ($CreatingApplication) {
    '(?i)\bAdvanced Installer\b' { 'AdvancedInstaller'; break }
    '(?i)\bInstallShield\b' { 'InstallShield'; break }
    '(?i)\b(WiX|Windows Installer XML|WixSharp)\b' { 'WiX'; break }
    '(?i)\bWise(?:\s+for\s+Windows Installer|\s+Installer)?\b' { 'Wise'; break }
    default { $null }
  }
  if ($SummaryBuilder) {
    return [pscustomobject][ordered]@{
      Builder = $SummaryBuilder
      Source  = 'SummaryInformation.CreatingApp'
      Value   = $CreatingApplication
    }
  }

  # Fallbacks use explicit compiler-owned identifiers. Table names are omitted:
  # packages can import vendor tables without having been authored by that tool.
  if ($Properties.Keys | Where-Object { $_ -like 'AI_*' -or $_ -in @('AI_PACKAGE_TYPE', 'AI_PRODUCTNAME_ARP') }) {
    return [pscustomobject][ordered]@{ Builder = 'AdvancedInstaller'; Source = 'Property'; Value = $null }
  }
  if ($CustomActionNames | Where-Object { $_ -like 'AI_*' }) {
    return [pscustomobject][ordered]@{ Builder = 'AdvancedInstaller'; Source = 'CustomAction'; Value = $null }
  }
  if ($Properties.Keys | Where-Object { $_ -clike 'Wise*' -or $_ -clike '_Wise*' }) {
    return [pscustomobject][ordered]@{ Builder = 'Wise'; Source = 'Property'; Value = $null }
  }
  if ($CustomActionNames | Where-Object { $_ -clike 'Wise*' }) {
    return [pscustomobject][ordered]@{ Builder = 'Wise'; Source = 'CustomAction'; Value = $null }
  }
  # Chromium enterprise MSIs are compiled from WiX source but do not retain
  # generic Wix tables or properties in the resulting database.
  # Source: https://chromium.googlesource.com/chromium/src/+/main/chrome/updater/win/signing/enterprise_standalone_installer.wxs.xml
  $ChromiumWiXActionNames = @('SetProductTagProperty', 'BuildInstallCommand', 'ExtractTagInfoFromInstaller', 'DoInstall')
  $HasChromiumWiXActions = -not ($ChromiumWiXActionNames | Where-Object { $_ -notin $CustomActionNames })
  $HasChromiumWiXBinaryAction = [bool]($StaticTableInfo.CustomActionRows | Where-Object {
      $_.Action -eq 'ExtractTagInfoFromInstaller' -and $_.Source -eq 'MsiInstallerCustomActionDll'
    })
  if ($HasChromiumWiXActions -and $HasChromiumWiXBinaryAction) {
    return [pscustomobject][ordered]@{ Builder = 'WiX'; Source = 'ChromiumEnterpriseActions'; Value = $null }
  }
  if ($Properties.Keys | Where-Object { $_ -like 'Wix*' -or $_ -eq 'WIXUI_INSTALLDIR' }) {
    return [pscustomobject][ordered]@{ Builder = 'WiX'; Source = 'Property'; Value = $null }
  }
  if ($CustomActionNames | Where-Object { $_ -clike 'IS*' -or $_ -clike 'InstallShield*' }) {
    return [pscustomobject][ordered]@{ Builder = 'InstallShield'; Source = 'CustomAction'; Value = $null }
  }
  if ($Properties.Keys | Where-Object { $_ -clike 'IS*' -or $_ -clike 'InstallShield*' }) {
    return [pscustomobject][ordered]@{ Builder = 'InstallShield'; Source = 'Property'; Value = $null }
  }

  return [pscustomobject][ordered]@{ Builder = 'Unknown'; Source = $null; Value = $null }
}

function Get-MsiBuilderFromStaticTableInfo {
  <#
  .SYNOPSIS
    Return the MSI authoring-system name from structured database evidence.
  .PARAMETER StaticTableInfo
    Immutable table projection returned by Get-MsiStaticTableInfo.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][psobject]$StaticTableInfo)

  return (Get-MsiBuilderEvidenceFromStaticTableInfo -StaticTableInfo $StaticTableInfo).Builder
}

function Get-MsiInstallerBuilderVersionInfo {
  <#
  .SYNOPSIS
    Read an explicitly recorded installer-builder version from MSI Summary Information.
  .PARAMETER StaticTableInfo
    Immutable table projection returned by Get-MsiStaticTableInfo.
  .PARAMETER InstallerBuilder
    Builder family already classified from structured MSI evidence.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$StaticTableInfo,
    [Parameter(Mandatory)][string]$InstallerBuilder
  )

  # PID_APPNAME is an authored database field. Restrict exact version extraction to this source;
  # ProductVersion and outer EXE version resources identify the packaged application instead.
  $CreatingApplication = [string]$StaticTableInfo.SummaryInfo.CreatingApp
  $Pattern = switch ($InstallerBuilder) {
    'AdvancedInstaller' { '(?i)\bAdvanced Installer(?:\s+|/)(?<Version>\d+(?:\.\d+){1,3})\b' }
    default { $null }
  }
  if ($Pattern -and $CreatingApplication -match $Pattern) {
    return [pscustomobject][ordered]@{
      Version = $Matches.Version
      Source  = 'SummaryInformation.CreatingApp'
    }
  }

  return [pscustomobject][ordered]@{
    Version = $null
    Source  = $null
  }
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
        $TransformPaths = Expand-Msp -Path $PatchPath -CollisionAction Rename
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
      $InstallerBuilderEvidence = Get-MsiBuilderEvidenceFromStaticTableInfo -StaticTableInfo $StaticTableInfo
      $InstallerBuilder = $InstallerBuilderEvidence.Builder
      $InstallShieldProjectInfo = Get-MsiInstallShieldProjectTypeFromStaticTableInfo -StaticTableInfo $StaticTableInfo
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
        InstallerBuilderSource            = $InstallerBuilderEvidence.Source
        InstallShieldProjectType          = $InstallShieldProjectInfo.ProjectType
        InstallShieldProjectTypeEvidence  = $InstallShieldProjectInfo
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
        $TransformPaths = Expand-Msp -Path $PatchPath -CollisionAction Rename
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
      $InstallShieldProjectInfo = Get-MsiInstallShieldProjectTypeFromStaticTableInfo -StaticTableInfo $StaticTableInfo
      $InstallShieldScriptActions = [object[]]@(Get-MsiInstallShieldScriptActionInfo -StaticTableInfo $StaticTableInfo -ProjectTypeInfo $InstallShieldProjectInfo)
      $InstallShieldLauncherRequirement = Get-MsiInstallShieldLauncherRequirement `
        -ProjectTypeInfo $InstallShieldProjectInfo -ScriptActions $InstallShieldScriptActions
      # Basic MSI and InstallScript MSI can both carry compiled InstallScript
      # actions. Recover Binary.ISSetup.dll once while the database is open and
      # replace opaque fN targets with their IsConfig.ini function names.
      $InstallShieldScriptInfo = Get-MsiInstallShieldEmbeddedScriptInfo `
        -Database $Database -StaticTableInfo $StaticTableInfo -ScriptActions $InstallShieldScriptActions
      if ($InstallShieldScriptInfo) {
        $InstallShieldScriptActions = [object[]]$InstallShieldScriptInfo.Actions
      }
      $ChromiumEnterpriseInfo = Get-MsiChromiumEnterpriseInfoFromStaticTableInfo -StaticTableInfo $StaticTableInfo -Database $Database
      $ElevationInfo = Get-MsiElevationInfoFromStaticTableInfo -StaticTableInfo $StaticTableInfo -ChromiumEnterpriseInfo $ChromiumEnterpriseInfo
      $InstallerBuilderVersionInfo = Get-MsiInstallerBuilderVersionInfo -StaticTableInfo $StaticTableInfo -InstallerBuilder $AppsAndFeaturesInfo.InstallerBuilder

      [pscustomobject][ordered]@{
        Path                                = $PSCmdlet.ParameterSetName -eq 'Path' ? $Path : $null
        InstallerType                       = $AppsAndFeaturesInfo.InstallerType
        ProductCode                         = $Properties['ProductCode']
        UpgradeCode                         = $Properties['UpgradeCode']
        DisplayName                         = $Properties['ProductName']
        DisplayVersion                      = $Properties['ProductVersion']
        Publisher                           = $Properties['Manufacturer']
        Scope                               = $Properties['ALLUSERS'] -ceq '1' ? 'machine' : $null
        DefaultInstallLocation              = $null
        WritesAppsAndFeaturesEntry          = $AppsAndFeaturesInfo.HasCustomAppsAndFeaturesEntry -or -not $AppsAndFeaturesInfo.HidesMsiAppsAndFeaturesEntry
        AppsAndFeaturesProductCode          = $AppsAndFeaturesInfo.AppsAndFeaturesProductCode
        AppsAndFeaturesInstallerType        = $AppsAndFeaturesInfo.AppsAndFeaturesInstallerType
        Warnings                            = [string[]]@($ElevationInfo.Warnings + $InstallShieldLauncherRequirement.Warnings + @($InstallShieldScriptInfo.Warnings) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
        UnresolvedFields                    = [string[]]@()
        Notices                             = [string[]]@($InstallShieldScriptInfo.Notices | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
        AllUsers                            = $Properties['ALLUSERS']
        InstallerBuilder                    = $AppsAndFeaturesInfo.InstallerBuilder
        InstallerBuilderSource              = $AppsAndFeaturesInfo.InstallerBuilderSource
        InstallerBuilderVersion             = $InstallerBuilderVersionInfo.Version
        InstallerBuilderVersionSource       = $InstallerBuilderVersionInfo.Source
        SummaryCreatingApplication          = [string]$StaticTableInfo.SummaryInfo.CreatingApp
        SummaryComments                     = [string]$StaticTableInfo.SummaryInfo.Comments
        InstallShieldProjectType            = $InstallShieldProjectInfo.ProjectType
        InstallShieldProjectTypeEvidence    = $InstallShieldProjectInfo
        InstallShieldLauncherRequirement    = $InstallShieldLauncherRequirement
        SummaryWordCount                    = $ElevationInfo.SummaryWordCount
        AllowsInstallWithoutElevation       = $ElevationInfo.AllowsInstallWithoutElevation
        ElevationRequirement                = $ElevationInfo.ElevationRequirement
        ElevationRequirementEvidence        = [object[]]$ElevationInfo.Evidence
        ChromiumEnterpriseMsiInfo           = $ChromiumEnterpriseInfo
        HasInstallScript                    = [bool]($InstallShieldScriptInfo -and $InstallShieldScriptInfo.HasCompiledScript)
        InstallShieldScriptInfo             = $InstallShieldScriptInfo
        InstallShieldScriptActions          = [object[]]@($InstallShieldScriptActions)
        MsiSequenceRows                     = [object[]]@($StaticTableInfo.SequenceRows)
        InstallShieldPrerequisiteReferences = [object[]]@($StaticTableInfo.InstallShieldPrerequisiteRows)
        InstallShieldFeaturePrerequisites   = [object[]]@($StaticTableInfo.InstallShieldFeaturePrerequisiteRows)
        InstallLocationProperty             = $InstallLocationInfo.Property
        InstallLocationSwitch               = $InstallLocationInfo.Switch
        InstallLocationSource               = $InstallLocationInfo.Source
        AppsAndFeaturesWindowsInstaller     = $AppsAndFeaturesInfo.AppsAndFeaturesWindowsInstaller
        HasCustomAppsAndFeaturesEntry       = $AppsAndFeaturesInfo.HasCustomAppsAndFeaturesEntry
        HidesMsiAppsAndFeaturesEntry        = $AppsAndFeaturesInfo.HidesMsiAppsAndFeaturesEntry
        Template                            = $ArchitectureInfo.Template
        PackageArchitecture                 = Convert-MsiTemplatePlatformToPackageArchitecture -Template $ArchitectureInfo.Template
        SupportedArchitectures              = $ArchitectureInfo.SupportedArchitectures
        UnsupportedArchitectures            = $ArchitectureInfo.UnsupportedArchitectures
        Protocols                           = $AssociationInfo.Protocols
        FileExtensions                      = $AssociationInfo.FileExtensions
        RegistryAssociationInfo             = $AssociationInfo
        AppsAndFeaturesEntries              = $AppsAndFeaturesInfo
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

function Read-ElevationRequirementFromMsi {
  <#
  .SYNOPSIS
    Read an explicit or source-backed WinGet elevation requirement from an MSI.
  .PARAMETER Path
    Path to the MSI database. The path is resolved before Windows Installer
    opens the database.
  .OUTPUTS
    `elevationRequired` when the MSI contains supported elevation behavior;
    otherwise no value. Use Get-MsiInstallerInfo when other metadata is needed.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
    [string]$Path
  )

  process {
    (Get-MsiInstallerInfo -Path $Path).ElevationRequirement
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
        $TransformPaths = Expand-Msp -Path $PatchPath -CollisionAction Rename
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
