# SPDX-License-Identifier: MIT
# Format sources: https://github.com/wixtoolset/wix
# MSI Word Count elevation bit: https://learn.microsoft.com/windows/win32/msi/word-count-summary
# MSI runtime elevation properties: https://learn.microsoft.com/windows/win32/msi/msirunningelevated-
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

  # Check if the assembly is already loaded to prevent double loading
  if (-not ([System.Management.Automation.PSTypeName]'Microsoft.Deployment.WindowsInstaller').Type) {
    if (Test-Path -Path ($Path = Join-Path $PSScriptRoot '..' 'Assets' 'Assemblies' 'Microsoft.Deployment.WindowsInstaller.dll')) {
      Add-Type -Path $Path
    } else {
      throw 'The Microsoft.Deployment.WindowsInstaller.dll assembly could not be found'
    }
  }
  if (-not ([System.Management.Automation.PSTypeName]'Microsoft.Deployment.WindowsInstaller.Package').Type) {
    if (Test-Path -Path ($Path = Join-Path $PSScriptRoot '..' 'Assets' 'Assemblies' 'Microsoft.Deployment.WindowsInstaller.Package.dll')) {
      Add-Type -Path $Path
    } else {
      throw 'The Microsoft.Deployment.WindowsInstaller.Package.dll assembly could not be found'
    }
  }
}

Import-Assembly

# Keep InstallShield authoring-system interpretation separate from generic MSI mechanics.
function Get-MsiInstallShieldPrerequisiteTableInfo {
  <#
  .SYNOPSIS
    Project InstallShield prerequisite tables from an already-open MSI database.
  .PARAMETER Database
    Caller-owned DTF database. The helper does not close it.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][Microsoft.Deployment.WindowsInstaller.Database]$Database)

  # The referenced .prq document owns downloads, conditions, and command lines. These rows
  # preserve authored ordering and feature attachment without guessing missing definitions.
  return [pscustomobject][ordered]@{
    Prerequisites = @(Get-MsiQueryRow -Database $Database -Query 'SELECT `ISSetupPrerequisites`, `ISBuildSourcePath`, `Order`, `ISSetupLocation`, `ISReleaseFlags` FROM `ISSetupPrerequisites`' -FieldNames @('Name', 'BuildSourcePath', 'Order', 'SetupLocation', 'ReleaseFlags'))
    Features      = @(Get-MsiQueryRow -Database $Database -Query 'SELECT `Feature_`, `ISSetupPrerequisites_` FROM `ISFeatureSetupPrerequisites`' -FieldNames @('Feature', 'Name'))
  }
}

function Get-MsiInstallShieldProjectTypeFromStaticTableInfo {
  <#
  .SYNOPSIS
    Distinguish Basic MSI from InstallScript MSI using compiled MSI database evidence.
  .DESCRIPTION
    InstallShield can place setup.inx beside both Basic MSI and InstallScript MSI
    media, so bootstrapper files are not an authoritative project-type marker.
    InstallScript MSI projects instead retain the InstallScript runtime verifier
    and, depending on the InstallShield generation and authored script, dedicated
    InstallScript tables in the MSI database.
  .PARAMETER StaticTableInfo
    Immutable MSI table projection returned by Get-MsiStaticTableInfo.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]
    [psobject]$StaticTableInfo
  )

  $Builder = Get-MsiBuilderFromStaticTableInfo -StaticTableInfo $StaticTableInfo
  if ($Builder -ne 'InstallShield') {
    return [pscustomobject]@{
      ProjectType   = $null
      Tables        = [string[]]@()
      CustomActions = [string[]]@()
    }
  }

  # ISVerifyScriptingRuntime is added by InstallShield to InstallScript MSI
  # projects. Older and script-heavy projects may additionally expose one of
  # the InstallScript table families below. Generic IS-prefixed tables such as
  # ISSetupType are intentionally excluded because Basic MSI uses them too.
  $InstallScriptTables = [string[]]@($StaticTableInfo.Tables | Where-Object {
      $_ -in @('ISInstallScriptAction', 'ISScriptFile') -or $_ -like 'ISInstallScript*'
    } | Sort-Object -Unique)
  $InstallScriptActions = [string[]]@($StaticTableInfo.CustomActionRows.Action | Where-Object {
      $_ -eq 'ISVerifyScriptingRuntime' -or $_ -like 'ISInstallScript*'
    } | Sort-Object -Unique)

  return [pscustomobject]@{
    ProjectType   = ($InstallScriptTables.Count -or $InstallScriptActions.Count) ? 'InstallScript MSI' : 'Basic MSI'
    Tables        = $InstallScriptTables
    CustomActions = $InstallScriptActions
  }
}

function Get-MsiInstallShieldScriptActionInfo {
  <#
  .SYNOPSIS
    Project InstallScript MSI custom actions into their authored sequence slots.
  .DESCRIPTION
    Conditions are returned verbatim. They are not evaluated because MSI
    properties, feature states, and installed-product state exist only inside a
    Windows Installer session on the target system.
  .PARAMETER StaticTableInfo
    Immutable MSI table projection returned by Get-MsiStaticTableInfo.
  .PARAMETER ProjectTypeInfo
    Optional cached result from Get-MsiInstallShieldProjectTypeFromStaticTableInfo.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][psobject]$StaticTableInfo,
    [psobject]$ProjectTypeInfo
  )

  if (-not $ProjectTypeInfo) {
    $ProjectTypeInfo = Get-MsiInstallShieldProjectTypeFromStaticTableInfo -StaticTableInfo $StaticTableInfo
  }
  if (-not $ProjectTypeInfo.ProjectType) { return [object[]]@() }

  # InstallScript MSI runtime actions identify the project type. Basic MSI can
  # independently compile authored InstallScript custom actions into
  # Binary.ISSetup.dll and dispatch opaque fN exports from that binary.
  $CustomActions = [object[]]@($StaticTableInfo.CustomActionRows | Where-Object {
      $_.Action -eq 'ISVerifyScriptingRuntime' -or
      $_.Action -like 'ISInstallScript*' -or
      ($_.Source -ieq 'ISSetup.dll' -and $_.Target -match '^f\d+$')
    } | Sort-Object Action -Unique)
  foreach ($CustomAction in $CustomActions) {
    $ActionName = [string]$CustomAction.Action
    $Sequences = [object[]]@($StaticTableInfo.SequenceRows | Where-Object Action -CEQ $ActionName | Sort-Object Table, Sequence)
    [pscustomobject][ordered]@{
      Action    = $ActionName
      Kind      = if ($ActionName -eq 'ISVerifyScriptingRuntime') { 'RuntimeVerifier' } elseif ($CustomAction.Source -ieq 'ISSetup.dll' -and $CustomAction.Target -match '^f\d+$') { 'CompiledFunction' } else { 'InstallScriptRuntime' }
      Type      = $CustomAction.Type
      Source    = $CustomAction.Source
      Target    = $CustomAction.Target
      Function  = $null
      Sequences = $Sequences
      Scheduled = $Sequences.Count -gt 0
    }
  }
}

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

function Get-MsiInstallShieldEmbeddedScriptInfo {
  <#
  .SYNOPSIS
    Recover and analyze InstallShield custom-action bytecode embedded in an MSI.
  .DESCRIPTION
    InstallShield stores a PE named ISSetup.dll in the Binary table. Its
    ISSetupStream overlay contains Setup.inx, IsConfig.ini, and localized string
    resources. IsConfig.ini maps opaque custom-action targets such as f1 to the
    authored InstallScript function name. Only those mapped functions are
    emulated; standalone setup callbacks are deliberately excluded.
  .PARAMETER Database
    Caller-owned open MSI database.
  .PARAMETER StaticTableInfo
    Cached table projection containing Binary names and custom actions.
  .PARAMETER ScriptActions
    Cached InstallShield action projection from the same database.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][Microsoft.Deployment.WindowsInstaller.Database]$Database,
    [Parameter(Mandatory)][psobject]$StaticTableInfo,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$ScriptActions
  )

  $CompiledActions = [object[]]@($ScriptActions | Where-Object Kind -EQ 'CompiledFunction')
  if (-not $CompiledActions -or $StaticTableInfo.BinaryNames -inotcontains 'ISSetup.dll') { return $null }

  $Warnings = [Collections.Generic.List[string]]::new()
  $TemporaryPath = $null
  try {
    foreach ($RequiredCommand in @('New-TempFolder', 'Expand-InstallShieldInstaller', 'ConvertFrom-Ini', 'Invoke-InstallShieldInstallScriptAnalysis', 'Resolve-UniqueInstallerFile')) {
      if (-not (Get-Command $RequiredCommand -ErrorAction SilentlyContinue)) {
        throw "The required parser helper '$RequiredCommand' is unavailable."
      }
    }

    $TemporaryPath = New-TempFolder
    $BinaryPath = Join-Path $TemporaryPath 'ISSetup.dll'
    $ExtractedPath = Join-Path $TemporaryPath 'ISSetup'
    $null = Export-MsiBinaryTableStream -Database $Database -Name 'ISSetup.dll' -DestinationPath $BinaryPath
    $null = Expand-InstallShieldInstaller -Path $BinaryPath -DestinationPath $ExtractedPath -CollisionAction Rename

    $Files = [object[]]@(Get-ChildItem -LiteralPath $ExtractedPath -Recurse -File -ErrorAction Stop | Sort-Object FullName)
    $ScriptFiles = [IO.FileInfo[]]@($Files | Where-Object Extension -In @('.inx', '.ins'))
    $ScriptFile = Resolve-UniqueInstallerFile -Item $ScriptFiles -Pattern 'Setup.inx' -BasePath $ExtractedPath -Description 'MSI Binary.ISSetup.dll payload'
    $ConfigurationFiles = [IO.FileInfo[]]@($Files | Where-Object Name -IEQ 'IsConfig.ini')
    if (-not $ConfigurationFiles) { throw 'The ISSetup.dll payload does not contain IsConfig.ini action mappings.' }
    $ConfigurationPath = Resolve-UniqueInstallerFile -Item $ConfigurationFiles -Pattern 'IsConfig.ini' `
      -BasePath $ExtractedPath -Description 'MSI Binary.ISSetup.dll configuration'
    $Configuration = ConvertFrom-Ini -Path $ConfigurationPath.FullName -MaximumBytes 4MB -DuplicateKeyAction Last

    $MappedActions = [Collections.Generic.List[object]]::new()
    $EntryPoints = [Collections.Generic.List[string]]::new()
    foreach ($Action in $ScriptActions) {
      $Function = $null
      if ($Action.Kind -eq 'CompiledFunction' -and $Configuration.Contains($Action.Target)) {
        $Section = $Configuration[$Action.Target]
        if ($Section.Contains('Function')) { $Function = [string]$Section['Function'] }
      }
      if ($Action.Kind -eq 'CompiledFunction' -and [string]::IsNullOrWhiteSpace($Function)) {
        $Warnings.Add("InstallShield custom action '$($Action.Action)' target '$($Action.Target)' has no literal IsConfig.ini function mapping.")
      } elseif (-not [string]::IsNullOrWhiteSpace($Function) -and $Function -notin $EntryPoints) {
        $EntryPoints.Add($Function)
      }
      $MappedActions.Add([pscustomobject][ordered]@{
          Action = $Action.Action; Kind = $Action.Kind; Type = $Action.Type
          Source = $Action.Source; Target = $Action.Target; Function = $Function
          Sequences = [object[]]$Action.Sequences; Scheduled = $Action.Scheduled
        })
    }
    if (-not $EntryPoints.Count) { throw 'No compiled InstallScript custom-action entry point could be resolved.' }

    $StringTablePaths = [string[]]@($Files | Where-Object { $_.Name -like 'StringTable_*.ips' -or $_.Name -like 'String*.txt' } | Select-Object -ExpandProperty FullName)
    $Analysis = Invoke-InstallShieldInstallScriptAnalysis -Path $ScriptFile.FullName `
      -StringTablePath $StringTablePaths -EntryPoint $EntryPoints.ToArray() -AnalysisScope EmbeddedAction
    # The temporary extraction is removed before returning; retain only the
    # stable Binary-table and relative-file identities in public evidence.
    $Analysis.Path = $null
    foreach ($Warning in @($Analysis.Warnings)) { if ($Warning) { $Warnings.Add([string]$Warning) } }

    return [pscustomobject][ordered]@{
      BinaryName        = 'ISSetup.dll'
      HasCompiledScript = $true
      EntryPoints       = [string[]]$EntryPoints.ToArray()
      Actions           = [object[]]$MappedActions.ToArray()
      Analysis          = $Analysis
      ExtractedFiles    = [string[]]@($Files | ForEach-Object { [IO.Path]::GetRelativePath($ExtractedPath, $_.FullName) })
      Warnings          = [string[]]$Warnings.ToArray()
    }
  } catch {
    $Warnings.Add("Embedded InstallScript custom-action analysis failed: $($_.Exception.Message)")
    return [pscustomobject][ordered]@{
      BinaryName        = 'ISSetup.dll'
      HasCompiledScript = $true
      EntryPoints       = [string[]]@()
      Actions           = [object[]]$ScriptActions
      Analysis          = $null
      ExtractedFiles    = [string[]]@()
      Warnings          = [string[]]$Warnings.ToArray()
    }
  } finally {
    if ($TemporaryPath) { Remove-Item -LiteralPath $TemporaryPath -Recurse -Force -ErrorAction SilentlyContinue }
  }
}

function Get-MsiInstallShieldLauncherRequirement {
  <#
  .SYNOPSIS
    Determine whether an InstallScript MSI requires the InstallShield Setup.exe launcher.
  .DESCRIPTION
    Official InstallShield project metadata describes ISVerifyScriptingRuntime
    as the action that verifies an InstallScript MSI was launched through
    Setup.exe. This helper reports that contract separately from compiled-script
    evidence; the verifier alone does not prove that an INX payload exists.
  .PARAMETER ProjectTypeInfo
    Cached InstallShield project classification from the MSI table projection.
  .PARAMETER ScriptActions
    Cached InstallScript custom-action projection, including sequence conditions.
  .OUTPUTS
    Structured source-backed launcher evidence. RequiresSetupExe is null when an
    InstallScript MSI lacks the verifier and the requirement cannot be proved.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$ProjectTypeInfo,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$ScriptActions
  )

  if ($ProjectTypeInfo.ProjectType -ne 'InstallScript MSI') {
    return [pscustomobject][ordered]@{
      IsApplicable       = $false
      RequiresSetupExe   = $false
      VerifierAction     = $null
      SequenceConditions = [string[]]@()
      Evidence           = [string[]]@()
      Warnings           = [string[]]@()
    }
  }

  $Verifier = $ScriptActions | Where-Object Action -CEQ 'ISVerifyScriptingRuntime' | Select-Object -First 1
  $Conditions = [string[]]@($Verifier.Sequences.Condition | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
  $Evidence = [Collections.Generic.List[string]]::new()
  $Warnings = [Collections.Generic.List[string]]::new()
  if ($Verifier) {
    $Evidence.Add('ISVerifyScriptingRuntime custom action')
    foreach ($Sequence in @($Verifier.Sequences)) {
      $Evidence.Add("$($Sequence.Table):$($Sequence.Sequence):$($Sequence.Condition)")
    }
  } else {
    $Warnings.Add('The MSI is classified as InstallScript MSI, but ISVerifyScriptingRuntime is absent; a Setup.exe launcher requirement could not be proved statically.')
  }

  return [pscustomobject][ordered]@{
    IsApplicable       = $true
    RequiresSetupExe   = $Verifier ? $true : $null
    VerifierAction     = $Verifier
    SequenceConditions = $Conditions
    Evidence           = [string[]]$Evidence
    Warnings           = [string[]]$Warnings
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

function Read-MsiChromiumUpdaterTag {
  <#
  .SYNOPSIS
    Read an appended Omaha product tag from a Chromium enterprise MSI.
  .DESCRIPTION
    Chromium's MSI signing pipeline stores the signed package data in the MSI
    DigitalSignature stream. This helper reads only that stream, validates the
    length framing, strict UTF-8 text, query keys, and recognized updater
    fields, and therefore cannot confuse a tagged embedded EXE with the MSI's
    TAGSTRING override.
  .PARAMETER Path
    Resolved or relative path to the MSI file. The package is opened read-only.
  .PARAMETER Database
    Open caller-owned Windows Installer database. The helper closes only its
    query records and stream, never the supplied database.
  .PARAMETER MaximumSignatureBytes
    Maximum number of bytes read from the MSI DigitalSignature stream.
  .OUTPUTS
    Normalized updater-tag evidence. IsTagged is false when no valid non-empty
    outer tag is present.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(ParameterSetName = 'Path', Mandatory)]
    [string]$Path,

    [Parameter(ParameterSetName = 'Database', Mandatory)]
    [Microsoft.Deployment.WindowsInstaller.Database]$Database,

    [ValidateRange(65549, 67108864)]
    [int]$MaximumSignatureBytes = 16777216
  )

  $OwnsDatabase = $PSCmdlet.ParameterSetName -eq 'Path'
  if ($OwnsDatabase) {
    $ResolvedPath = Convert-Path -Path $Path
    $Database = [Microsoft.Deployment.WindowsInstaller.Package.InstallPackage]::new($ResolvedPath, 'ReadOnly')
  }

  $View = $null
  $ParameterRecord = $null
  $DataRecord = $null
  $SignatureStream = $null
  try {
    $View = $Database.OpenView('SELECT `Data` FROM `_Streams` WHERE `Name` = ?')
    $ParameterRecord = [Microsoft.Deployment.WindowsInstaller.Record]::new(1)
    $ParameterRecord.SetString(1, "$([char]5)DigitalSignature")
    $View.Execute($ParameterRecord)
    $DataRecord = $View.Fetch()
    if (-not $DataRecord) { $SignatureBytes = [byte[]]::new(0) } else {
      $SignatureStream = $DataRecord.GetStream(1)
      if ($SignatureStream.Length -gt $MaximumSignatureBytes) {
        throw 'The MSI DigitalSignature stream exceeds the Chromium tag parser limit.'
      }
      $SignatureBytes = [byte[]]::new([int]$SignatureStream.Length)
      $SignatureStream.ReadExactly($SignatureBytes)
    }
  } finally {
    if ($SignatureStream) { $SignatureStream.Dispose() }
    if ($DataRecord) { $DataRecord.Close() }
    if ($ParameterRecord) { $ParameterRecord.Close() }
    if ($View) { $View.Close() }
    if ($OwnsDatabase -and $Database) { $Database.Close() }
  }

  $Marker = [Text.Encoding]::ASCII.GetBytes('Gact2.0Omaha')
  $Offsets = @(Find-BinaryPattern -Bytes $SignatureBytes -Pattern $Marker -Maximum 256)
  $EmptyMarkerOffset = $null
  $Utf8 = [Text.UTF8Encoding]::new($false, $true)

  # Inspect candidates from the end of the signed file. Embedded updater
  # binaries can contain the marker as program data, so framing alone is not
  # sufficient: a non-empty tag must also be a valid query with updater keys.
  for ($Index = $Offsets.Count - 1; $Index -ge 0; $Index--) {
    $Offset = [int]$Offsets[$Index]
    $LengthOffset = $Offset + $Marker.Length
    if ($LengthOffset + 2 -gt $SignatureBytes.Length) { continue }
    $Length = ([int]$SignatureBytes[$LengthOffset] -shl 8) -bor [int]$SignatureBytes[$LengthOffset + 1]
    $TagOffset = $LengthOffset + 2
    if ($TagOffset + $Length -gt $SignatureBytes.Length) { continue }
    if ($Length -eq 0) {
      if ($null -eq $EmptyMarkerOffset) { $EmptyMarkerOffset = $Offset }
      continue
    }

    try {
      $RawTag = $Utf8.GetString($SignatureBytes, $TagOffset, $Length)
    } catch {
      continue
    }
    if ($RawTag -match '[\x00-\x1F\x7F]') { continue }

    $Parameters = [ordered]@{}
    $ValidQuery = $true
    foreach ($Part in ($RawTag -split '&')) {
      $Pair = $Part -split '=', 2
      if ($Pair.Count -ne 2 -or $Pair[0] -notmatch '^[A-Za-z][A-Za-z0-9_.-]*$') {
        $ValidQuery = $false
        break
      }
      try {
        $Key = [Uri]::UnescapeDataString($Pair[0].Replace('+', ' '))
        $Parameters[$Key] = [Uri]::UnescapeDataString($Pair[1].Replace('+', ' '))
      } catch {
        $ValidQuery = $false
        break
      }
    }
    if (-not $ValidQuery -or
      -not ($Parameters.Contains('appguid') -or $Parameters.Contains('appid') -or $Parameters.Contains('needsadmin'))) {
      continue
    }

    return [pscustomobject][ordered]@{
      MarkerFound     = $true
      IsTagged        = $true
      TagFormat       = 'OmahaMsiTailTag'
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

  return [pscustomobject][ordered]@{
    MarkerFound     = $null -ne $EmptyMarkerOffset
    IsTagged        = $false
    TagFormat       = $null -ne $EmptyMarkerOffset ? 'OmahaMsiTailTag' : $null
    Offset          = $EmptyMarkerOffset
    Length          = 0
    RawTag          = $null
    Parameters      = [pscustomobject][ordered]@{}
    ApplicationId   = $null
    ApplicationName = $null
    NeedsAdmin      = $null
    Brand           = $null
  }
}

function Get-MsiChromiumEnterpriseInfoFromStaticTableInfo {
  <#
  .SYNOPSIS
    Interpret Chromium enterprise MSI custom actions and product-tag behavior.
  .DESCRIPTION
    Recognizes the source-defined SetProductTagProperty, tag override,
    BuildInstallCommand, ExtractTagInfoFromInstaller, and deferred DoInstall
    layout. Vendor-authored property actions are retained as conditional command
    modifiers instead of being treated as Chromium defaults.
  .PARAMETER StaticTableInfo
    Immutable MSI table projection returned by Get-MsiStaticTableInfo.
  .PARAMETER Database
    Optional caller-owned database used to read the outer MSI signature tag.
    Synthetic table-only callers still receive action evidence.
  .OUTPUTS
    Structured evidence describing the effective product tag, nested silent
    mode, immediate tag extraction, deferred execution, and whether the nested
    updater requires an already elevated caller in silent mode.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]
    [psobject]$StaticTableInfo,

    [AllowNull()]
    [Microsoft.Deployment.WindowsInstaller.Database]$Database
  )

  $Actions = @($StaticTableInfo.CustomActionRows)
  $ActionNames = @($Actions.Action)
  $RequiredActions = @('SetProductTagProperty', 'BuildInstallCommand', 'ExtractTagInfoFromInstaller', 'DoInstall')
  $IsDetected = -not ($RequiredActions | Where-Object { $_ -notin $ActionNames })
  if (-not $IsDetected) {
    return [pscustomobject][ordered]@{
      IsDetected                    = $false
      DefaultProductTag             = $null
      DefaultNeedsAdmin             = $null
      OuterTag                      = $null
      ProductTagSource              = $null
      EffectiveProductTag           = $null
      EffectiveNeedsAdmin           = $null
      InstallCommand                = $null
      SilentModifierActions         = [object[]]@()
      UsesPlainSilent               = $false
      AllowsSilentUac               = $false
      IsSilentAtNoUi                = $false
      IsSilentAtBasicUi             = $false
      SilentElevationBehavior       = 'NotApplicable'
      RequiresPreElevationForSilent = $false
      HasImmediateTagExtraction     = $false
      DeferredInstallerAction       = $null
      Notices                       = [string[]]@()
    }
  }

  $SetTagAction = $Actions | Where-Object Action -CEQ 'SetProductTagProperty' | Select-Object -First 1
  $BuildAction = $Actions | Where-Object Action -CEQ 'BuildInstallCommand' | Select-Object -First 1
  $ExtractAction = $Actions | Where-Object Action -CEQ 'ExtractTagInfoFromInstaller' | Select-Object -First 1
  $InstallAction = $Actions | Where-Object Action -CEQ 'DoInstall' | Select-Object -First 1
  $DefaultProductTag = [string]$SetTagAction.Target
  $DefaultNeedsAdmin = if ($DefaultProductTag -match '(?i)(?:^|&)needsAdmin=([^&]+)') { $Matches[1] } else { $null }

  $OuterTag = if ($Database) { Read-MsiChromiumUpdaterTag -Database $Database } else { $null }
  $EffectiveProductTag = $OuterTag -and $OuterTag.IsTagged ? $OuterTag.RawTag : $DefaultProductTag
  $EffectiveNeedsAdmin = $OuterTag -and $OuterTag.IsTagged ? $OuterTag.NeedsAdmin : $DefaultNeedsAdmin
  $ProductTagSource = $OuterTag -and $OuterTag.IsTagged ? 'OuterMsiTag' : 'DefaultProductTag'
  $InstallCommand = [string]$BuildAction.Target

  # Property-setting custom actions can append vendor switches after the source
  # template builds InstallCommand. Preserve their MSI conditions so UILevel=2
  # (none/quiet) is not confused with UILevel=3 (basic/passive).
  $SilentModifierActions = [System.Collections.Generic.List[object]]::new()
  foreach ($Action in @($Actions | Where-Object {
        [int]$_.Type -eq 51 -and $_.Source -ceq 'InstallCommand' -and $_.Action -cne 'BuildInstallCommand' -and
        [string]$_.Target -match '(?i)(?:^|\s)--silent(?:=\S+)?(?:\s|$)'
      })) {
    $Sequences = @($StaticTableInfo.SequenceRows | Where-Object Action -CEQ $Action.Action)
    $SilentModifierActions.Add([pscustomobject][ordered]@{
        Action     = [string]$Action.Action
        Target     = [string]$Action.Target
        Conditions = [string[]]@($Sequences.Condition | Where-Object { $_ })
        Sequences  = [object[]]$Sequences
      })
  }

  $BaseSilentMatch = [regex]::Match($InstallCommand, '(?i)(?:^|\s)--silent(?:=([^\s"]+))?(?=\s|$)')
  $UsesPlainSilent = $BaseSilentMatch.Success -and [string]::IsNullOrWhiteSpace($BaseSilentMatch.Groups[1].Value)
  $AllowsSilentUac = $BaseSilentMatch.Success -and $BaseSilentMatch.Groups[1].Value -ieq 'allow-uac'
  $IsSilentAtNoUi = $BaseSilentMatch.Success
  $IsSilentAtBasicUi = $BaseSilentMatch.Success
  foreach ($Modifier in $SilentModifierActions) {
    $ModifierAllowsUac = [string]$Modifier.Target -match '(?i)--silent=allow-uac(?:\s|$)'
    $ModifierUsesPlainSilent = [string]$Modifier.Target -match '(?i)(?:^|\s)--silent(?=\s|$)'
    foreach ($Condition in @($Modifier.Conditions)) {
      if ($Condition -match '(?i)\bUILevel\s*=\s*2\b') {
        $IsSilentAtNoUi = $true
        $UsesPlainSilent = $UsesPlainSilent -or $ModifierUsesPlainSilent
        $AllowsSilentUac = $AllowsSilentUac -or $ModifierAllowsUac
      }
      if ($Condition -match '(?i)\bUILevel\s*=\s*3\b') { $IsSilentAtBasicUi = $true }
    }
  }

  $NeedsElevation = $EffectiveNeedsAdmin -in @('true', 'prefers')
  $RequiresPreElevation = $IsSilentAtNoUi -and $UsesPlainSilent -and -not $AllowsSilentUac -and $NeedsElevation
  $SilentElevationBehavior = if ($RequiresPreElevation) {
    'RequiresPreElevation'
  } elseif ($IsSilentAtNoUi -and $AllowsSilentUac -and $NeedsElevation) {
    'CanPromptForElevation'
  } elseif ($EffectiveNeedsAdmin -ieq 'false') {
    'ProductTagDoesNotRequireElevation'
  } else {
    'Unknown'
  }

  $ExtractSequences = @($StaticTableInfo.SequenceRows | Where-Object Action -CEQ 'ExtractTagInfoFromInstaller')
  $InstallType = [int]$InstallAction.Type
  $Notices = [System.Collections.Generic.List[string]]::new()
  if ($RequiresPreElevation) {
    $Notices.Add('The nested Chromium Updater receives plain --silent. Chromium suppresses UAC in that mode, so the silent MSI path requires an already elevated Windows Installer context.')
  }
  if ([int]$ExtractAction.Type -eq 1 -and $ExtractSequences.Count -gt 0) {
    $Notices.Add('ExtractTagInfoFromInstaller is an immediate custom action. NoImpersonate does not elevate immediate actions, so a vendor-modified tag extractor can fail before deferred installation begins.')
  }

  return [pscustomobject][ordered]@{
    IsDetected                    = $true
    DefaultProductTag             = $DefaultProductTag
    DefaultNeedsAdmin             = $DefaultNeedsAdmin
    OuterTag                      = $OuterTag
    ProductTagSource              = $ProductTagSource
    EffectiveProductTag           = $EffectiveProductTag
    EffectiveNeedsAdmin           = $EffectiveNeedsAdmin
    InstallCommand                = $InstallCommand
    SilentModifierActions         = [object[]]$SilentModifierActions.ToArray()
    UsesPlainSilent               = $UsesPlainSilent
    AllowsSilentUac               = $AllowsSilentUac
    IsSilentAtNoUi                = $IsSilentAtNoUi
    IsSilentAtBasicUi             = $IsSilentAtBasicUi
    SilentElevationBehavior       = $SilentElevationBehavior
    RequiresPreElevationForSilent = $RequiresPreElevation
    HasImmediateTagExtraction     = [int]$ExtractAction.Type -eq 1 -and $ExtractSequences.Count -gt 0
    DeferredInstallerAction       = [pscustomobject][ordered]@{
      Action        = [string]$InstallAction.Action
      Type          = $InstallType
      Source        = [string]$InstallAction.Source
      Target        = [string]$InstallAction.Target
      IsDeferred    = ($InstallType -band 0x0400) -ne 0
      NoImpersonate = ($InstallType -band 0x0800) -ne 0
      Sequences     = [object[]]@($StaticTableInfo.SequenceRows | Where-Object Action -CEQ 'DoInstall')
    }
    Notices                       = [string[]]$Notices.ToArray()
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

  # InstallShield-owned identifiers conventionally use an uppercase IS prefix.
  # Match that prefix case-sensitively so ordinary properties such as IsLight
  # do not outrank explicit WiX/WixSharp authoring evidence.
  if ($Tables | Where-Object { $_ -clike 'IS*' -or $_ -clike 'InstallShield*' }) { return 'InstallShield' }
  if ($Properties.Keys | Where-Object { $_ -clike 'IS*' -or $_ -clike 'InstallShield*' }) { return 'InstallShield' }
  if ($CustomActionNames | Where-Object { $_ -clike 'IS*' -or $_ -clike 'InstallShield*' }) { return 'InstallShield' }
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
      $InstallerBuilder = Get-MsiBuilderFromStaticTableInfo -StaticTableInfo $StaticTableInfo
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
        AllUsers                            = $Properties['ALLUSERS']
        InstallerBuilder                    = $AppsAndFeaturesInfo.InstallerBuilder
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
