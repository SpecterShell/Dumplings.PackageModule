# SPDX-License-Identifier: Apache-2.0
# InstallShield-specific authoring and embedded-script interpretation for MSI databases.

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

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
    $Notices = [string[]]@($Analysis.Notices | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })

    return [pscustomobject][ordered]@{
      BinaryName        = 'ISSetup.dll'
      HasCompiledScript = $true
      EntryPoints       = [string[]]$EntryPoints.ToArray()
      Actions           = [object[]]$MappedActions.ToArray()
      Analysis          = $Analysis
      ExtractedFiles    = [string[]]@($Files | ForEach-Object { [IO.Path]::GetRelativePath($ExtractedPath, $_.FullName) })
      Warnings          = [string[]]$Warnings.ToArray()
      Notices           = $Notices
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
      Notices           = [string[]]@()
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

Export-ModuleMember -Function Get-MsiInstallShieldPrerequisiteTableInfo, Get-MsiInstallShieldProjectTypeFromStaticTableInfo, Get-MsiInstallShieldScriptActionInfo, Get-MsiInstallShieldEmbeddedScriptInfo, Get-MsiInstallShieldLauncherRequirement
