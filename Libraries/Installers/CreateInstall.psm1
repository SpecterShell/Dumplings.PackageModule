# SPDX-License-Identifier: Apache-2.0
# Static CreateInstall parser for Gentee launcher programs and GEA v1/v2 archives.
# Format references:
# - https://www.createinstall.com/help/index.html
# - https://www.createinstall.com/history.html
# - https://www.gentee.com/source/src/projects/gea/index.htm
# CreateInstallFormatCatalog.psd1 separates physical GEA widths from the independently evolving
# addremove/addremoveex/addremoveext routine signatures. Observed release labels never dispatch code.
# The container logic is PowerShell; the adaptive-Huffman LZGE decoder is an
# attributed MIT asset. Binary structures consumed here use LE integers:
#
#   PE setup
#     +-- .gentee section
#     |   +-- optional embedded runtime DLL
#     |   `-- [expanded-size:u32][LZGE-compressed GE program]
#     `-- GEA overlay
#     +00 47 45 41 00 ("GEA\0")
#     +04 volume:u16, +06 id:u32, +0A/+0B version bytes
#     +14 flags:u32, +1A header-size:u32, +1E summary-size:i64
#     +26 info-size:u32, +2A/+32/+3A archive/volume sizes:i64
#     +42 moved-size:u32, +46 memory/block/solid multipliers
#     +-- catalog -> [order:u8][packed-size:u32/u64][packed data]*
#     `-- optional companions -> [GEA\0][volume:u16][id:u32][data]
#         +-- type 0: stored bytes
#         +-- type 1: LZGE adaptive-Huffman stream
#         `-- type 2: modified PPMd-I range stream + end marker
#
# Integers are LE. GEA v1 uses 32-bit file/block sizes; v2 uses 64-bit sizes.
# The launcher header is identified by "Gentee Launcher\0" and records the
# runtime/program sizes and the header's own file offset. The decoded GE program
# is a sequence of bounded object records; direct calls to CreateInstall's
# source-backed addremove family provide visible uninstall-key evidence.
# Password-protected records are never bypassed. PPMd is decoded by the bounded,
# source-shipped SharpCompress.Gentee managed provider, which preserves GEA's solid
# model state. SharpCompress's public PpmdStream implements standard H/H7Z/I1 models;
# it cannot decode GEA because Gentee changes I1 model behavior, allocator scheduling,
# and per-block framing.

# Apply default function parameters

# Public CreateInstall commands. Implementation modules are imported locally.
Import-Module (Join-Path $PSScriptRoot 'CreateInstallArchive.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'CreateInstallGentee.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'CreateInstallOperations.psm1') -ErrorAction Stop

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:CreateInstallMaximumAnalysisBytes = 268435456

function Get-CreateInstallPayloadAnalysis {
  <#
  .SYNOPSIS
    Analyze source-proven installed application executables and bounded adjacent sidecars.
  .PARAMETER Layout
    Validated GEA layout reused for selected extraction.
  .PARAMETER InstalledFile
    Installed-file projection returned by Get-CreateInstallInstallFileEvidence.
  .PARAMETER ApplicationPath
    Application paths referenced by compiled file-association commands.
  .PARAMETER DefaultInstallLocation
    Resolved package install root used only for the unambiguous executable fallback.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Layout,
    [AllowNull()][object[]]$InstalledFile,
    [AllowNull()][string[]]$ApplicationPath,
    [AllowNull()][string]$DefaultInstallLocation
  )

  $Diagnostics = [Collections.Generic.List[object]]::new()
  $Installed = @($InstalledFile | Where-Object { $_.InstalledPath -and -not $_.IsConditional })
  $Primary = @($Installed | Where-Object { $_.InstalledPath -in @($ApplicationPath | Where-Object { $_ }) } | Sort-Object ArchiveIndex -Unique)
  if ($Primary.Count -eq 0 -and $DefaultInstallLocation) {
    $Fallback = @($Installed | Where-Object { $_.InstalledPath -match '(?i)\.exe$' -and [IO.Path]::GetDirectoryName([string]$_.InstalledPath) -ieq $DefaultInstallLocation -and [IO.Path]::GetFileName([string]$_.InstalledPath) -notmatch '^(?:uninstall|update)\.exe$' })
    if ($Fallback.Count -eq 1) { $Primary = $Fallback }
  }
  if ($Primary.Count -eq 0) {
    return [pscustomobject]@{ ArchitectureInfo = @(); Architectures = @(); DependencyInfo = $null; InspectedFiles = @(); Diagnostics = @() }
  }

  # Limit primary applications and related files independently of the archive's total size. This
  # keeps metadata parsing bounded for SDKs and other packages containing many executable tools.
  $Primary = @($Primary | Select-Object -First 4)
  $Selected = [Collections.Generic.List[object]]::new()
  $SelectedIndexes = [Collections.Generic.HashSet[int]]::new()
  $AnalysisBytes = 0L
  foreach ($Item in $Primary) {
    if ($AnalysisBytes + [long]$Item.Size -gt $Script:CreateInstallMaximumAnalysisBytes) { continue }
    if ($SelectedIndexes.Add([int]$Item.ArchiveIndex)) { $Selected.Add($Item); $AnalysisBytes += [long]$Item.Size }
    $Directory = [IO.Path]::GetDirectoryName([string]$Item.InstalledPath)
    foreach ($Related in @($Installed | Where-Object { $_.ArchiveIndex -ne $Item.ArchiveIndex -and [IO.Path]::GetDirectoryName([string]$_.InstalledPath) -ieq $Directory -and $_.InstalledPath -match '(?i)\.(?:dll|deps\.json|runtimeconfig\.json)$' } | Select-Object -First 64)) {
      if ($AnalysisBytes + [long]$Related.Size -gt $Script:CreateInstallMaximumAnalysisBytes) { break }
      if ($SelectedIndexes.Add([int]$Related.ArchiveIndex)) { $Selected.Add($Related); $AnalysisBytes += [long]$Related.Size }
    }
  }
  if ($Selected.Count -eq 0) {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Payload.AnalysisLimit' -Source CreateInstall -Message 'Source-proven CreateInstall application payloads exceed the bounded static-analysis limit.' -Kind Unsupported -Areas Metadata -AffectedFields @('Architecture', 'Dependencies')))
    return [pscustomobject]@{ ArchitectureInfo = @(); Architectures = @(); DependencyInfo = $null; InspectedFiles = @(); Diagnostics = $Diagnostics.ToArray() }
  }

  $TemporaryDirectory = New-TempFolder
  try {
    $Patterns = [string[]]@($Selected | Sort-Object ArchiveIndex | Select-Object -ExpandProperty ArchivePath -Unique)
    $Files = @(Export-CreateInstallArchiveSelection -Layout $Layout -DestinationPath $TemporaryDirectory -Name $Patterns -CollisionAction Rename -MaximumExpandedBytes $Script:CreateInstallMaximumAnalysisBytes)
    $ArchitectureInfo = [Collections.Generic.List[object]]::new()
    foreach ($Item in $Primary) {
      # Match the exact archive-relative extraction path. Basename matching can select the wrong
      # executable when a package installs identically named files in several directories.
      $ExpectedPath = Resolve-SafeExtractionPath -DestinationPath $TemporaryDirectory -RelativePath ([string]$Item.ArchivePath)
      $PrimaryFile = @($Files | Where-Object FullName -EQ $ExpectedPath)
      if ($PrimaryFile.Count -ne 1) { continue }
      $RelatedFiles = @($Files | Where-Object { $_.FullName -cne $PrimaryFile[0].FullName })
      try { $ArchitectureInfo.Add((Get-PEArchitectureInfo -Path $PrimaryFile[0].FullName -RelatedFile @($RelatedFiles | Where-Object Extension -IEQ '.dll' | Select-Object -ExpandProperty FullName))) } catch {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Payload.ArchitectureUnavailable' -Source CreateInstall -Message "CreateInstall payload architecture analysis failed for '$($Item.ArchivePath)': $($_.Exception.Message)" -Kind Incomplete -Areas Metadata -AffectedFields Architecture))
      }
    }
    $DependencyInfo = $null
    if ($Primary.Count -eq 1 -and $Files.Count -gt 0) {
      $ExpectedPath = Resolve-SafeExtractionPath -DestinationPath $TemporaryDirectory -RelativePath ([string]$Primary[0].ArchivePath)
      $PrimaryFile = @($Files | Where-Object FullName -EQ $ExpectedPath)
      if ($PrimaryFile.Count -eq 1) {
        try { $DependencyInfo = Get-PEDependencyInfo -Path $PrimaryFile[0].FullName -RelatedFile @($Files | Where-Object FullName -NE $PrimaryFile[0].FullName | Select-Object -ExpandProperty FullName) } catch {
          $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Payload.DependenciesUnavailable' -Source CreateInstall -Message "CreateInstall payload dependency analysis failed: $($_.Exception.Message)" -Kind Incomplete -Areas Metadata -AffectedFields Dependencies))
        }
      }
    }
    # Aggregate child parser diagnostics explicitly. Accessing a property through a null scalar or
    # a generic list is fragile under StrictMode and can hide otherwise valid payload evidence.
    foreach ($ArchitectureResult in $ArchitectureInfo) {
      foreach ($Diagnostic in @($ArchitectureResult.Diagnostics)) { if ($Diagnostic) { $Diagnostics.Add($Diagnostic) } }
    }
    if ($null -ne $DependencyInfo) {
      foreach ($Diagnostic in @($DependencyInfo.Diagnostics)) { if ($Diagnostic) { $Diagnostics.Add($Diagnostic) } }
    }
    return [pscustomobject]@{
      ArchitectureInfo = $ArchitectureInfo.ToArray()
      Architectures    = [string[]]@($ArchitectureInfo.RecommendedWinGetArchitectures | Where-Object { $_ -in 'x86', 'x64', 'arm64' } | Sort-Object -Unique)
      DependencyInfo   = $DependencyInfo
      InspectedFiles   = [string[]]@($Selected | Select-Object -ExpandProperty InstalledPath)
      Diagnostics      = $Diagnostics.ToArray()
    }
  } finally { Remove-Item -LiteralPath $TemporaryDirectory -Recurse -Force -ErrorAction SilentlyContinue }
}

function Get-CreateInstallInfo {
  <#
  .SYNOPSIS
    Read static CreateInstall identity and GEA payload evidence
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER VolumePath
    Optional directory containing GEA companion volumes. Missing companions preserve metadata
    evidence but prevent payload expansion and payload-derived architecture analysis.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [AllowNull()][string]$VolumePath
  )

  process {
    $File = Get-Item -LiteralPath $Path -Force
    $VersionInfo = [Diagnostics.FileVersionInfo]::GetVersionInfo($File.FullName)
    $ExecutionLevel = Get-PERequestedExecutionLevel -Path $File.FullName
    # Test fixtures may expose a standalone GEA payload behind a synthetic prefix. Real installers
    # provide PE architecture evidence; retaining the null case keeps archive inspection usable.
    try { $OuterArchitectureInfo = Get-PEArchitectureInfo -Path $File.FullName } catch { $OuterArchitectureInfo = $null }
    $Is32Bit = $null -eq $OuterArchitectureInfo -or $OuterArchitectureInfo.NativeArchitecture -eq 'x86'
    $CompressionMethods = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $Diagnostics = [System.Collections.Generic.List[object]]::new()
    $UnresolvedFields = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $RegistryWrites = [System.Collections.Generic.List[object]]::new()
    # Decode the GE program once. MAINVAR contains the exact generated project values consumed by
    # common_init; direct addremove* calls identify which of those values become visible ARP state.
    $Program = $null
    $ProjectVariableEvidence = $null
    $UninstallEvidence = $null
    $ExtensionEvidence = $null
    $InstallFileEvidence = $null
    $CustomRegistryEvidence = $null
    $PayloadAnalysis = $null
    $ShortcutEvidence = $null
    $RunEvidence = $null
    $EnvironmentEvidence = $null
    $PrerequisiteEvidence = $null
    $ServiceEvidence = $null
    $RegistrationEvidence = $null
    $ScheduledTaskEvidence = $null
    $FileOperationEvidence = $null
    $DownloadEvidence = $null
    $ArchiveOperationEvidence = $null
    $ConfigurationEvidence = $null
    try { $Program = Get-CreateInstallGenteeProgram -Path $File.FullName } catch {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Program.Unavailable' -Source CreateInstall -Message "The compiled CreateInstall project program could not be decoded: $($_.Exception.Message)" -Kind Incomplete -Areas Metadata -AffectedFields @('ProductCode', 'DefaultInstallLocation', 'AppsAndFeaturesEntries')))
    }
    $Layout = $null
    $LayoutError = $null
    try { $Layout = Get-CreateInstallArchiveLayout -Path $File.FullName -VolumePath $VolumePath } catch { $LayoutError = $_ }
    if ($null -eq $Program -and $null -eq $Layout) { throw $LayoutError }
    if ($null -eq $Layout) {
      # CreateInstall permits projects without packaged files. Their compiled program remains fully
      # analyzable, but extraction and installed-file projection have no GEA source.
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Archive.Absent' -Source CreateInstall -Message 'The CreateInstall project contains no GEA payload archive.' -Kind Information -Areas Extraction))
    } elseif ($Layout.AllVolumesAvailable) {
      # Enumerate block headers without expanding payloads so capability warnings remain inexpensive.
      $ArchiveStream = [IO.File]::Open($Layout.Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
      try {
        foreach ($Entry in $Layout.Entries) { foreach ($Block in @(Get-CreateInstallBlockInfo -Layout $Layout -Entry $Entry -Stream $ArchiveStream)) { $null = $CompressionMethods.Add($Block.CompressionName) } }
      } finally { $ArchiveStream.Dispose() }
    } else {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Archive.VolumeMissing' -Source CreateInstall -Message "The CreateInstall GEA archive requires $($Layout.MissingVolumes.Count) unavailable companion volume(s); metadata is retained but payload extraction is unavailable." -Kind Incomplete -Areas Extraction -Evidence $Layout.MissingVolumes))
    }
    if ($null -ne $Program) {
      try { $ProjectVariableEvidence = Get-CreateInstallProjectVariableEvidence -Program $Program } catch {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.ProjectVariables.Incomplete' -Source CreateInstall -Message "The compiled CreateInstall project variables could not be parsed: $($_.Exception.Message)" -Kind Incomplete -Areas Metadata -AffectedFields @('DisplayName', 'DisplayVersion', 'Publisher', 'DefaultInstallLocation')))
      }
      try { $UninstallEvidence = Get-CreateInstallUninstallEvidence -Program $Program } catch {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.ARP.Incomplete' -Source CreateInstall -Message "The compiled CreateInstall Add/Remove routine could not be parsed: $($_.Exception.Message)" -Kind Incomplete -Areas Metadata -AffectedFields @('ProductCode', 'AppsAndFeaturesEntries')))
      }
      if ($null -ne $ProjectVariableEvidence) {
        try { $ExtensionEvidence = Get-CreateInstallExtensionEvidence -Program $Program -ProjectVariableEvidence $ProjectVariableEvidence -Is32Bit $Is32Bit } catch {
          $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Association.Incomplete' -Source CreateInstall -Message "Compiled CreateInstall file associations could not be parsed completely: $($_.Exception.Message)" -Kind Incomplete -Areas Metadata -AffectedFields FileExtensions))
        }
        if ($null -ne $Layout) {
          try { $InstallFileEvidence = Get-CreateInstallInstallFileEvidence -Program $Program -ProjectVariableEvidence $ProjectVariableEvidence -Layout $Layout -Is32Bit $Is32Bit } catch {
            $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.InstallGroups.Incomplete' -Source CreateInstall -Message "Compiled CreateInstall install groups could not be parsed completely: $($_.Exception.Message)" -Kind Incomplete -Areas Extraction -AffectedFields Architecture))
          }
        }
        try { $CustomRegistryEvidence = Get-CreateInstallRegistryEvidence -Program $Program -ProjectVariableEvidence $ProjectVariableEvidence -Is32Bit $Is32Bit } catch {
          $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Registry.Incomplete' -Source CreateInstall -Message "Compiled CreateInstall registry operations could not be parsed completely: $($_.Exception.Message)" -Kind Incomplete -Areas Metadata -AffectedFields @('ProductCode', 'AppsAndFeaturesEntries', 'Protocols', 'FileExtensions')))
        }
        try { $ShortcutEvidence = Get-CreateInstallShortcutEvidence -Program $Program -ProjectVariableEvidence $ProjectVariableEvidence -Is32Bit $Is32Bit } catch {
          $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Shortcut.Incomplete' -Source CreateInstall -Message "Compiled CreateInstall shortcut operations could not be parsed completely: $($_.Exception.Message)" -Kind Incomplete -Areas Metadata))
        }
        try { $RunEvidence = Get-CreateInstallRunEvidence -Program $Program -ProjectVariableEvidence $ProjectVariableEvidence -Is32Bit $Is32Bit } catch {
          $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Run.Incomplete' -Source CreateInstall -Message "Compiled CreateInstall child-process operations could not be parsed completely: $($_.Exception.Message)" -Kind Incomplete -Areas Installability))
        }
        try { $EnvironmentEvidence = Get-CreateInstallEnvironmentEvidence -Program $Program -ProjectVariableEvidence $ProjectVariableEvidence -Is32Bit $Is32Bit } catch {
          $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Environment.Incomplete' -Source CreateInstall -Message "Compiled CreateInstall environment-variable operations could not be parsed completely: $($_.Exception.Message)" -Kind Incomplete -Areas Metadata))
        }
        try { $PrerequisiteEvidence = Get-CreateInstallPrerequisiteEvidence -Program $Program -ProjectVariableEvidence $ProjectVariableEvidence -Is32Bit $Is32Bit } catch {
          $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Prerequisite.Incomplete' -Source CreateInstall -Message "Compiled CreateInstall prerequisite checks could not be parsed completely: $($_.Exception.Message)" -Kind Incomplete -Areas Installability -AffectedFields Dependencies))
        }
        try { $ServiceEvidence = Get-CreateInstallServiceEvidence -Program $Program -ProjectVariableEvidence $ProjectVariableEvidence -Is32Bit $Is32Bit } catch {
          $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Service.Incomplete' -Source CreateInstall -Message "Compiled CreateInstall service operations could not be parsed completely: $($_.Exception.Message)" -Kind Incomplete -Areas Metadata, Installability))
        }
        try { $RegistrationEvidence = Get-CreateInstallRegistrationEvidence -Program $Program -ProjectVariableEvidence $ProjectVariableEvidence -Is32Bit $Is32Bit } catch {
          $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Registration.Incomplete' -Source CreateInstall -Message "Compiled CreateInstall registration operations could not be parsed completely: $($_.Exception.Message)" -Kind Incomplete -Areas Metadata))
        }
        try { $ScheduledTaskEvidence = Get-CreateInstallScheduledTaskEvidence -Program $Program -ProjectVariableEvidence $ProjectVariableEvidence -Is32Bit $Is32Bit } catch {
          $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.ScheduledTask.Incomplete' -Source CreateInstall -Message "Compiled CreateInstall scheduled-task operations could not be parsed completely: $($_.Exception.Message)" -Kind Incomplete -Areas Metadata, Installability))
        }
        try { $FileOperationEvidence = Get-CreateInstallFileOperationEvidence -Program $Program -ProjectVariableEvidence $ProjectVariableEvidence -Is32Bit $Is32Bit } catch {
          $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Copy.Incomplete' -Source CreateInstall -Message "Compiled CreateInstall file-copy operations could not be parsed completely: $($_.Exception.Message)" -Kind Incomplete -Areas Extraction))
        }
        try { $DownloadEvidence = Get-CreateInstallDownloadEvidence -Program $Program -ProjectVariableEvidence $ProjectVariableEvidence -Is32Bit $Is32Bit } catch {
          $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Download.Incomplete' -Source CreateInstall -Message "Compiled CreateInstall download operations could not be parsed completely: $($_.Exception.Message)" -Kind Incomplete -Areas Extraction, Installability, Security))
        }
        try { $ArchiveOperationEvidence = Get-CreateInstallArchiveOperationEvidence -Program $Program -ProjectVariableEvidence $ProjectVariableEvidence -Is32Bit $Is32Bit } catch {
          $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.ArchiveOperation.Incomplete' -Source CreateInstall -Message "Compiled CreateInstall nested-archive operations could not be parsed completely: $($_.Exception.Message)" -Kind Incomplete -Areas Extraction))
        }
        try { $ConfigurationEvidence = Get-CreateInstallConfigurationEvidence -Program $Program -ProjectVariableEvidence $ProjectVariableEvidence -Is32Bit $Is32Bit } catch {
          $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Configuration.Incomplete' -Source CreateInstall -Message "Compiled CreateInstall INI operations could not be parsed completely: $($_.Exception.Message)" -Kind Incomplete -Areas Metadata))
        }
      }
    }
    $ProjectVariables = if ($null -ne $ProjectVariableEvidence) { $ProjectVariableEvidence.Variables } else { [ordered]@{} }
    $ResolveProjectVariable = {
      param([string]$Name)
      if (-not $ProjectVariables.Contains($Name)) { return $null }
      return Resolve-CreateInstallMacroValue -Value ([string]$ProjectVariables[$Name]) -Variables $ProjectVariables -Is32Bit $Is32Bit
    }
    $GetResolvedValue = {
      param([string]$Name, [string]$Fallback)
      $Resolved = & $ResolveProjectVariable $Name
      if ($null -ne $Resolved -and $Resolved.UnresolvedMacros.Count -eq 0) { return ([string]$Resolved.Value).Trim() }
      return $Fallback
    }
    $ProductName = & $GetResolvedValue 'progname' ([string]$VersionInfo.ProductName).Trim()
    $DisplayVersion = & $GetResolvedValue 'ver' ([string]$VersionInfo.ProductVersion).Trim()
    $Publisher = & $GetResolvedValue 'compname' ([string]$VersionInfo.CompanyName).Trim()
    # addremoveex/addremoveext use instlocation as a route flag, but write the value held by
    # instlocal. Projects without that route use the ordinary setuppath macro.
    $InstallLocationName = $ProjectVariables.Contains('instlocation') ? 'instlocal' : 'setuppath'
    $InstallLocationResult = & $ResolveProjectVariable $InstallLocationName
    $DefaultInstallLocation = if ($null -ne $InstallLocationResult -and $InstallLocationResult.UnresolvedMacros.Count -eq 0) { ([string]$InstallLocationResult.Value).TrimEnd([char]'\') } else { $null }
    if ($null -ne $InstallLocationResult -and $InstallLocationResult.UnresolvedMacros.Count -gt 0) {
      $null = $UnresolvedFields.Add('DefaultInstallLocation')
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.InstallLocation.Dynamic' -Source CreateInstall -Message "CreateInstall's installation path depends on unresolved runtime macro(s): $($InstallLocationResult.UnresolvedMacros -join ', ')." -Kind Incomplete -Areas Metadata -AffectedFields DefaultInstallLocation -Evidence @{ Expression = [string]$ProjectVariables[$InstallLocationName]; Macros = $InstallLocationResult.UnresolvedMacros }))
    }
    $SilentResult = & $ResolveProjectVariable 'silentpar'
    $SilentSwitch = if ($null -ne $SilentResult -and $SilentResult.UnresolvedMacros.Count -eq 0) { ([string]$SilentResult.Value).Trim() } else { $null }
    $SupportsSilentInstallation = if ($null -eq $SilentResult -or $SilentResult.UnresolvedMacros.Count -gt 0) { $null } else { -not [string]::IsNullOrWhiteSpace($SilentSwitch) }
    if ($null -ne $SilentResult -and $SilentResult.UnresolvedMacros.Count -gt 0) {
      $null = $UnresolvedFields.Add('InstallerSwitches')
      $null = $UnresolvedFields.Add('InstallModes')
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Silent.Dynamic' -Source CreateInstall -Message "CreateInstall's silent parameter depends on unresolved runtime macro(s): $($SilentResult.UnresolvedMacros -join ', ')." -Kind Incomplete -Areas Installability -AffectedFields @('InstallerSwitches', 'InstallModes') -Evidence @{ Expression = [string]$ProjectVariables['silentpar']; Macros = $SilentResult.UnresolvedMacros }))
    }

    if ($null -ne $InstallFileEvidence -and $Layout.AllVolumesAvailable -and $Layout.PasswordCount -eq 0 -and -not $CompressionMethods.Contains('Unknown')) {
      try {
        $PayloadAnalysis = Get-CreateInstallPayloadAnalysis -Layout $Layout -InstalledFile $InstallFileEvidence.InstalledFiles -ApplicationPath @($ExtensionEvidence.Calls.Application) -DefaultInstallLocation $DefaultInstallLocation
        foreach ($Diagnostic in $PayloadAnalysis.Diagnostics) { $Diagnostics.Add($Diagnostic) }
      } catch {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Payload.AnalysisFailed' -Source CreateInstall -Message "CreateInstall selected-payload analysis failed: $($_.Exception.Message)" -Kind Incomplete -Areas Metadata -AffectedFields @('Architecture', 'Dependencies')))
      }
    }

    $UninstallCalls = if ($null -ne $UninstallEvidence) { @($UninstallEvidence.Calls) } else { @() }
    foreach ($Call in $UninstallCalls) {
      $UninstallKeyResult = Resolve-CreateInstallMacroValue -Value ([string]$Call.UninstallKeyName) -Variables $ProjectVariables -Is32Bit $Is32Bit
      $UninstallKeyName = ([string]$UninstallKeyResult.Value).Trim()
      if ([string]::IsNullOrWhiteSpace($UninstallKeyName)) { $UninstallKeyName = $ProductName }
      if ([string]::IsNullOrWhiteSpace($UninstallKeyName)) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.ARP.NameEmpty' -Source CreateInstall -Message 'CreateInstall invokes its Add/Remove command but the resolved program name is empty.' -Kind Incomplete -Areas Metadata -AffectedFields @('ProductCode', 'AppsAndFeaturesEntries')))
        continue
      }
      if ($UninstallKeyResult.UnresolvedMacros.Count -gt 0) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.ARP.NameDynamic' -Source CreateInstall -Message "CreateInstall's uninstall key depends on unresolved runtime macro(s): $($UninstallKeyResult.UnresolvedMacros -join ', ')." -Kind Incomplete -Areas Metadata -AffectedFields @('ProductCode', 'AppsAndFeaturesEntries') -Evidence @{ Expression = $Call.UninstallKeyName; Macros = $UninstallKeyResult.UnresolvedMacros }))
        continue
      }
      $Root = if ($Call.ForCurrentUser) { 'HKCU' } elseif ($ExecutionLevel -ieq 'requireAdministrator') { 'HKLM' } else { 'SHCTX' }
      $UninstallKey = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$UninstallKeyName"
      $CallEvidence = "Gentee $($Call.Routine) call"
      $RegistryView = $Is32Bit ? '32-bit' : '64-bit'
      $UninstallPathResult = & $ResolveProjectVariable 'uninstexe'
      $UninstallString = if ($null -ne $UninstallPathResult -and $UninstallPathResult.UnresolvedMacros.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace([string]$UninstallPathResult.Value)) {
        $ExpandedUninstaller = [string]$UninstallPathResult.Value
        $ExpandedUninstaller.StartsWith('"', [StringComparison]::Ordinal) ? $ExpandedUninstaller : '"' + $ExpandedUninstaller + '"'
      } else { $null }
      $DisplayIconResult = if ([string]::IsNullOrWhiteSpace([string]$Call.IconFile)) {
        $UninstallPathResult
      } else {
        Join-CreateInstallMacroPath -Parent ([string]$Call.IconPath) -Child ([string]$Call.IconFile) -Variables $ProjectVariables -Is32Bit $Is32Bit
      }
      $DisplayIcon = if ($null -ne $DisplayIconResult -and $DisplayIconResult.UnresolvedMacros.Count -eq 0) { ([string]$DisplayIconResult.Value).Trim() } else { $null }
      $HelpLink = & $GetResolvedValue 'supurl' $null
      $HelpTelephone = & $GetResolvedValue 'phone' $null
      $UrlInfoAbout = & $GetResolvedValue 'produrl' $null
      $UrlUpdateInfo = & $GetResolvedValue 'updurl' $null
      $EstimatedSize = $null
      if ($Call.WritesEstimatedSize -and $Call.EstimatedSizeText -match '^\d+$') {
        $EstimatedSize = if ([uint64]$Call.EstimatedSizeText -eq 1 -and $null -ne $Layout) {
          [uint32]((($Layout.Entries | Measure-Object -Property Size -Sum).Sum -shr 10) -band [uint32]::MaxValue)
        } elseif ([uint64]$Call.EstimatedSizeText -ne 1) { [uint32]([uint64]$Call.EstimatedSizeText -band [uint32]::MaxValue) }
      }

      # addremoveext iterates this exact source-defined value list. Emit only non-empty macro
      # values, then append the generation-specific DWORD policy values.
      foreach ($Value in @(
          @{ Name = 'UninstallString'; Value = $UninstallString },
          @{ Name = 'DisplayName'; Value = $UninstallKeyName },
          @{ Name = 'DisplayIcon'; Value = $DisplayIcon },
          @{ Name = 'DisplayVersion'; Value = $DisplayVersion },
          @{ Name = 'HelpLink'; Value = $HelpLink },
          @{ Name = 'HelpTelephone'; Value = $HelpTelephone },
          @{ Name = 'InstallLocation'; Value = $Call.WritesInstallLocation ? $DefaultInstallLocation : $null },
          @{ Name = 'Publisher'; Value = $Publisher },
          @{ Name = 'URLInfoAbout'; Value = $UrlInfoAbout },
          @{ Name = 'URLUpdateInfo'; Value = $UrlUpdateInfo }
        )) {
        if (-not [string]::IsNullOrWhiteSpace([string]$Value.Value)) { $RegistryWrites.Add([pscustomobject]@{ Root = $Root; RegistryView = $RegistryView; Key = $UninstallKey; Name = $Value.Name; Value = $Value.Value; Type = 'REG_SZ'; Evidence = $CallEvidence }) }
      }
      if ($null -ne $EstimatedSize -and $EstimatedSize -gt 0) { $RegistryWrites.Add([pscustomobject]@{ Root = $Root; RegistryView = $RegistryView; Key = $UninstallKey; Name = 'EstimatedSize'; Value = $EstimatedSize; Type = 'REG_DWORD'; Evidence = $CallEvidence }) }
      if ($Call.WritesNoModify) { $RegistryWrites.Add([pscustomobject]@{ Root = $Root; RegistryView = $RegistryView; Key = $UninstallKey; Name = 'NoModify'; Value = 1; Type = 'REG_DWORD'; Evidence = "$CallEvidence implementation" }) }
      if ($Call.WritesNoRepair) { $RegistryWrites.Add([pscustomobject]@{ Root = $Root; RegistryView = $RegistryView; Key = $UninstallKey; Name = 'NoRepair'; Value = 1; Type = 'REG_DWORD'; Evidence = "$CallEvidence implementation" }) }
    }

    if ($null -ne $ExtensionEvidence) {
      foreach ($Write in $ExtensionEvidence.RegistryWrites) { $RegistryWrites.Add($Write) }
      foreach ($Diagnostic in $ExtensionEvidence.Diagnostics) { $Diagnostics.Add($Diagnostic) }
    }
    if ($null -ne $InstallFileEvidence) { foreach ($Diagnostic in $InstallFileEvidence.Diagnostics) { $Diagnostics.Add($Diagnostic) } }
    if ($null -ne $ShortcutEvidence) { foreach ($Diagnostic in $ShortcutEvidence.Diagnostics) { $Diagnostics.Add($Diagnostic) } }
    if ($null -ne $RunEvidence) { foreach ($Diagnostic in $RunEvidence.Diagnostics) { $Diagnostics.Add($Diagnostic) } }
    if ($null -ne $EnvironmentEvidence) { foreach ($Diagnostic in $EnvironmentEvidence.Diagnostics) { $Diagnostics.Add($Diagnostic) } }
    if ($null -ne $PrerequisiteEvidence) { foreach ($Diagnostic in $PrerequisiteEvidence.Diagnostics) { $Diagnostics.Add($Diagnostic) } }
    if ($null -ne $ServiceEvidence) { foreach ($Diagnostic in $ServiceEvidence.Diagnostics) { $Diagnostics.Add($Diagnostic) } }
    if ($null -ne $RegistrationEvidence) { foreach ($Diagnostic in $RegistrationEvidence.Diagnostics) { $Diagnostics.Add($Diagnostic) } }
    if ($null -ne $ScheduledTaskEvidence) { foreach ($Diagnostic in $ScheduledTaskEvidence.Diagnostics) { $Diagnostics.Add($Diagnostic) } }
    if ($null -ne $FileOperationEvidence) { foreach ($Diagnostic in $FileOperationEvidence.Diagnostics) { $Diagnostics.Add($Diagnostic) } }
    if ($null -ne $DownloadEvidence) { foreach ($Diagnostic in $DownloadEvidence.Diagnostics) { $Diagnostics.Add($Diagnostic) } }
    if ($null -ne $ArchiveOperationEvidence) { foreach ($Diagnostic in $ArchiveOperationEvidence.Diagnostics) { $Diagnostics.Add($Diagnostic) } }
    if ($null -ne $ConfigurationEvidence) { foreach ($Diagnostic in $ConfigurationEvidence.Diagnostics) { $Diagnostics.Add($Diagnostic) } }
    if ($null -ne $CustomRegistryEvidence) {
      # Custom registry commands execute after the generated setup body and therefore override
      # built-in ARP values when both address the same uninstall key and value name.
      foreach ($Write in $CustomRegistryEvidence.RegistryWrites) { $RegistryWrites.Add($Write) }
      foreach ($Diagnostic in $CustomRegistryEvidence.Diagnostics) { $Diagnostics.Add($Diagnostic) }
    }

    # Preserve every condition that the bounded evaluator could not decide. Each record includes
    # the guarded operation, known project values, and a compact bytecode view for @function
    # predicates so callers can inspect the evidence without reparsing the GE program.
    $GenteeExpressions = [Collections.Generic.List[object]]::new()
    if ($null -ne $Program -and $null -ne $ProjectVariableEvidence) {
      $AddGenteeExpression = {
        param ([string]$Operation, [object]$Item, [string[]]$AffectedFields, [object]$Context, [AllowNull()][string]$Expression)
        if (($Item.PSObject.Properties['Condition'] -and $null -ne $Item.Condition) -or [string]::IsNullOrWhiteSpace($Expression)) { return }
        $ExpressionArguments = @{
          Program        = $Program
          Variables      = $ProjectVariables
          Is32Bit        = $Is32Bit
          Operation      = $Operation
          Expression     = $Expression
          AffectedFields = $AffectedFields
          Context        = $Context
        }
        if ($Item.PSObject.Properties['CallerId'] -and $null -ne $Item.CallerId) { $ExpressionArguments['CallerId'] = [uint32]$Item.CallerId }
        if ($Item.PSObject.Properties['CallOffset'] -and $null -ne $Item.CallOffset) { $ExpressionArguments['CallOffset'] = [int]$Item.CallOffset }
        $null = $GenteeExpressions.Add((Get-CreateInstallGenteeExpressionEvidence @ExpressionArguments))
      }

      if ($null -ne $InstallFileEvidence) {
        foreach ($Call in @($InstallFileEvidence.Calls)) {
          & $AddGenteeExpression 'InstallGroup' $Call @('Architecture') ([pscustomobject]@{ GroupId = $Call.GroupId; Destination = $Call.Destination; Wildcard = $Call.Wildcard }) ([string]$Call.ConditionExpression)
        }
      }
      if ($null -ne $ExtensionEvidence) {
        foreach ($Call in @($ExtensionEvidence.Calls)) {
          & $AddGenteeExpression 'FileAssociation' $Call @('FileExtensions') ([pscustomobject]@{ Extension = $Call.Extension; ProgId = $Call.ProgId; Application = $Call.Application }) ([string]$Call.ConditionExpression)
        }
      }
      if ($null -ne $CustomRegistryEvidence) {
        foreach ($Call in @($CustomRegistryEvidence.Calls)) {
          $AffectedFields = Get-CreateInstallRegistryAffectedField -Root $Call.Root -Key $Call.Subkey -UnresolvedMacros $Call.UnresolvedMacros
          & $AddGenteeExpression 'Registry' $Call $AffectedFields ([pscustomobject]@{ Root = $Call.Root; RegistryView = $Call.RegistryView; Key = $Call.Subkey }) ([string]$Call.ConditionExpression)
        }
        foreach ($Write in @($CustomRegistryEvidence.ConditionalRegistryWrites)) {
          $AffectedFields = Get-CreateInstallRegistryAffectedField -Root $Write.Root -Key $Write.Key -UnresolvedMacros $Write.UnresolvedKeyMacros
          foreach ($Expression in @($Write.ConditionExpression)) {
            & $AddGenteeExpression 'RegistryValue' $Write $AffectedFields ([pscustomobject]@{ Root = $Write.Root; RegistryView = $Write.RegistryView; Key = $Write.Key; Name = $Write.Name; Value = $Write.Value }) ([string]$Expression)
          }
        }
      }
      if ($null -ne $ShortcutEvidence) {
        foreach ($Call in @($ShortcutEvidence.Calls)) {
          & $AddGenteeExpression 'Shortcut' $Call @() ([pscustomobject]@{ ShortcutPath = $Call.ShortcutPath; TargetPath = $Call.TargetPath; Arguments = $Call.Arguments }) ([string]$Call.ConditionExpression)
        }
      }
      if ($null -ne $RunEvidence) {
        foreach ($Call in @($RunEvidence.Calls)) {
          & $AddGenteeExpression 'Run' $Call @() ([pscustomobject]@{ Kind = $Call.Kind; Executable = $Call.Executable; NestedInstallerPath = $Call.PSObject.Properties['NestedInstallerPath'] ? $Call.NestedInstallerPath : $null; Arguments = $Call.Arguments }) ([string]$Call.ConditionExpression)
        }
      }
      if ($null -ne $EnvironmentEvidence) {
        foreach ($Change in @($EnvironmentEvidence.EnvironmentChanges)) {
          & $AddGenteeExpression 'Environment' $Change @() ([pscustomobject]@{ Operation = $Change.Operation; Name = $Change.Name; Value = $Change.Value; Scope = $Change.Scope }) ([string]$Change.ConditionExpression)
        }
      }
      if ($null -ne $PrerequisiteEvidence) {
        foreach ($Check in @($PrerequisiteEvidence.PrerequisiteChecks)) {
          & $AddGenteeExpression 'Prerequisite' $Check @('Dependencies') ([pscustomobject]@{ Kind = $Check.Kind; Architecture = $Check.Architecture; Versions = $Check.Versions; Combination = $Check.Combination }) ([string]$Check.ConditionExpression)
        }
      }
      if ($null -ne $ServiceEvidence) {
        foreach ($Service in @($ServiceEvidence.Services)) {
          & $AddGenteeExpression 'Service' $Service @() ([pscustomobject]@{ Operation = $Service.Operation; Name = $Service.Name; BinaryPath = $Service.BinaryPath }) ([string]$Service.ConditionExpression)
        }
      }
      if ($null -ne $RegistrationEvidence) {
        foreach ($Registration in @($RegistrationEvidence.Registrations)) {
          & $AddGenteeExpression 'Registration' $Registration @() ([pscustomobject]@{ Kind = $Registration.Kind; Path = $Registration.Path }) ([string]$Registration.ConditionExpression)
        }
      }
      if ($null -ne $ScheduledTaskEvidence) {
        foreach ($Task in @($ScheduledTaskEvidence.ScheduledTasks)) {
          & $AddGenteeExpression 'ScheduledTask' $Task @() ([pscustomobject]@{ Operation = $Task.Operation; Name = $Task.Name; Executable = $Task.Executable }) ([string]$Task.ConditionExpression)
        }
      }
      if ($null -ne $FileOperationEvidence) {
        foreach ($FileOperation in @($FileOperationEvidence.FileOperations)) {
          & $AddGenteeExpression 'FileOperation' $FileOperation @() ([pscustomobject]@{ Operation = $FileOperation.Operation; Source = $FileOperation.Source; Destination = $FileOperation.Destination }) ([string]$FileOperation.ConditionExpression)
        }
      }
      if ($null -ne $DownloadEvidence) {
        foreach ($Download in @($DownloadEvidence.Downloads)) {
          & $AddGenteeExpression 'Download' $Download @() ([pscustomobject]@{ Url = $Download.Url; Destination = $Download.Destination }) ([string]$Download.ConditionExpression)
        }
      }
      if ($null -ne $ArchiveOperationEvidence) {
        foreach ($ArchiveOperation in @($ArchiveOperationEvidence.ArchiveOperations)) {
          & $AddGenteeExpression 'ArchiveOperation' $ArchiveOperation @() ([pscustomobject]@{ Format = $ArchiveOperation.Format; Source = $ArchiveOperation.Source; Destination = $ArchiveOperation.Destination }) ([string]$ArchiveOperation.ConditionExpression)
        }
      }
      if ($null -ne $ConfigurationEvidence) {
        foreach ($Change in @($ConfigurationEvidence.ConfigurationChanges)) {
          & $AddGenteeExpression 'Configuration' $Change @() ([pscustomobject]@{ Operation = $Change.Operation; FilePath = $Change.FilePath; Section = $Change.Section; Key = $Change.Key }) ([string]$Change.ConditionExpression)
        }
      }
    }
    $RegistryWriteArray = $RegistryWrites.ToArray()
    $ArpEvidence = Get-CreateInstallArpEvidence -RegistryWrite $RegistryWriteArray
    foreach ($Diagnostic in $ArpEvidence.Diagnostics) { $Diagnostics.Add($Diagnostic) }
    $ProductCodes = @($ArpEvidence.ProductCodes)
    $ProductCode = if ($ProductCodes.Count -eq 1) { $ProductCodes[0] } else { $null }
    if ($ProductCodes.Count -gt 1) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.ARP.Multiple' -Source CreateInstall -Message "CreateInstall writes multiple visible uninstall keys: $(@($ProductCodes | Sort-Object) -join ', ')." -Kind Ambiguous -Areas Metadata -AffectedFields @('ProductCode', 'AppsAndFeaturesEntries'))) }
    if ($ProductCodes.Count -eq 0) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.ARP.Unproven' -Source CreateInstall -Message 'CreateInstall metadata identifies the package, but deterministic registry operations do not prove one visible uninstall key.' -Kind Incomplete -Areas Metadata -AffectedFields @('ProductCode', 'AppsAndFeaturesEntries'))) }
    $RegistryAssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite $RegistryWriteArray
    if ($ExecutionLevel -ieq 'requireAdministrator' -and $ProductCodes.Count -eq 0) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Scope.ElevationInference' -Source CreateInstall -Message 'Machine scope is inferred from an explicit requireAdministrator application manifest.' -Kind Information -Areas Metadata -AffectedFields Scope)) }
    if ($null -ne $Layout -and ($Layout.PasswordCount -gt 0 -or ($Layout.Entries | Where-Object PasswordId -GT 0 | Select-Object -First 1))) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Archive.Encrypted' -Source CreateInstall -Message 'The GEA archive contains password-protected files; encrypted entries are intentionally unsupported.' -Kind Unsupported -Areas Extraction)) }
    # Compression capability is reported independently from identity evidence. Password-protected
    # entries and unknown method nibbles remain non-expandable; PPMd is supported statically.

    $DetectedScopes = @($ArpEvidence.Scopes)
    $Scope = if ($DetectedScopes.Count -eq 1) { $DetectedScopes[0] } elseif ($DetectedScopes.Count -gt 1) { $null } elseif ($ExecutionLevel -ieq 'requireAdministrator') { 'machine' } else { $null }
    $SupportedScopes = if ($DetectedScopes.Count -gt 0) { @($DetectedScopes | Sort-Object) } elseif ($ExecutionLevel -ieq 'requireAdministrator') { @('machine') } else { @() }
    $PrimaryArp = $ArpEvidence.VisibleEntries.Count -eq 1 ? $ArpEvidence.VisibleEntries[0] : $null

    $WritesAppsAndFeaturesEntry = if ($ArpEvidence.VisibleEntries.Count -gt 0) { $true } elseif ($ArpEvidence.Entries.Count -gt 0) { $false } else { $null }
    [pscustomobject][ordered]@{
      Path                         = $File.FullName
      InstallerType                = 'exe'
      ProductCode                  = $ProductCode
      UpgradeCode                  = $null
      DisplayName                  = $PrimaryArp -and -not [string]::IsNullOrWhiteSpace([string]$PrimaryArp.DisplayName) ? $PrimaryArp.DisplayName : $ProductName
      DisplayVersion               = $PrimaryArp -and -not [string]::IsNullOrWhiteSpace([string]$PrimaryArp.DisplayVersion) ? $PrimaryArp.DisplayVersion : $DisplayVersion
      Publisher                    = $PrimaryArp -and -not [string]::IsNullOrWhiteSpace([string]$PrimaryArp.Publisher) ? $PrimaryArp.Publisher : $Publisher
      Scope                        = $Scope
      DefaultInstallLocation       = $PrimaryArp -and -not [string]::IsNullOrWhiteSpace([string]$PrimaryArp.InstallLocation) ? $PrimaryArp.InstallLocation : $DefaultInstallLocation
      InstallLocation              = $PrimaryArp -and -not [string]::IsNullOrWhiteSpace([string]$PrimaryArp.InstallLocation) ? $PrimaryArp.InstallLocation : $DefaultInstallLocation
      UninstallString              = $PrimaryArp ? $PrimaryArp.UninstallString : $null
      QuietUninstallString         = $PrimaryArp ? $PrimaryArp.QuietUninstallString : $null
      DisplayIcon                  = $PrimaryArp ? $PrimaryArp.DisplayIcon : $null
      RegistryView                 = $PrimaryArp ? $PrimaryArp.RegistryView : ($Is32Bit ? '32-bit' : '64-bit')
      WritesAppsAndFeaturesEntry   = $WritesAppsAndFeaturesEntry
      AppsAndFeaturesProductCode   = $WritesAppsAndFeaturesEntry -eq $true ? $ProductCode : $null
      AppsAndFeaturesInstallerType = $WritesAppsAndFeaturesEntry -eq $true ? 'exe' : $null
      AppsAndFeaturesEntries       = $ArpEvidence.AppsAndFeaturesEntries
      ArpEntries                   = $ArpEvidence.Entries
      Diagnostics                  = @(Merge-InstallerDiagnostics -Diagnostic $Diagnostics.ToArray())
      UnresolvedFields             = [string[]]@($UnresolvedFields | Sort-Object)
      Family                       = 'CreateInstall'
      ProductCodeEvidence          = if ($ProductCode) { "Deterministic CreateInstall uninstall registry writes: $($PrimaryArp.Evidence -join '; ')" } else { $null }
      FileDescription              = ([string]$VersionInfo.FileDescription).Trim()
      SupportedScopes              = $SupportedScopes
      ScopeEvidence                = if ($ProductCode) { 'Deterministic uninstall registry hive and view' } elseif ($ExecutionLevel -ieq 'requireAdministrator') { 'PE requestedExecutionLevel' } else { $null }
      RequestedExecutionLevel      = $ExecutionLevel
      SupportsSilentInstallation   = $SupportsSilentInstallation
      InstallerSwitches            = if ($SilentSwitch) { [ordered]@{ Silent = $SilentSwitch; SilentWithProgress = $SilentSwitch } } else { [ordered]@{} }
      InstallModes                 = [string[]]@('interactive') + $(if ($SilentSwitch) { @('silent', 'silentWithProgress') } else { @() })
      RegistryWrites               = $RegistryWriteArray
      ConditionalRegistryWrites    = if ($null -ne $CustomRegistryEvidence) { $CustomRegistryEvidence.ConditionalRegistryWrites } else { @() }
      RegistryAssociationInfo      = $RegistryAssociationInfo
      Protocols                    = $RegistryAssociationInfo.Protocols
      FileExtensions               = $RegistryAssociationInfo.FileExtensions
      ProjectVariables             = $ProjectVariables
      ProjectVariableEvidence      = if ($null -ne $ProjectVariableEvidence) { [pscustomobject]@{ BufferObjectId = $ProjectVariableEvidence.BufferObjectId; Offset = $ProjectVariableEvidence.Offset; Count = $ProjectVariableEvidence.Count } } else { $null }
      GenteeExpressions            = $GenteeExpressions.ToArray()
      FileAssociationCalls         = if ($null -ne $ExtensionEvidence) { $ExtensionEvidence.Calls } else { @() }
      CustomRegistryCalls          = if ($null -ne $CustomRegistryEvidence) { $CustomRegistryEvidence.Calls } else { @() }
      Shortcuts                    = if ($null -ne $ShortcutEvidence) { $ShortcutEvidence.Calls } else { @() }
      ExecutedPayloads             = if ($null -ne $RunEvidence) { $RunEvidence.Calls } else { @() }
      EnvironmentChanges           = if ($null -ne $EnvironmentEvidence) { $EnvironmentEvidence.EnvironmentChanges } else { @() }
      PrerequisiteChecks           = if ($null -ne $PrerequisiteEvidence) { $PrerequisiteEvidence.PrerequisiteChecks } else { @() }
      Services                     = if ($null -ne $ServiceEvidence) { $ServiceEvidence.Services } else { @() }
      Registrations                = if ($null -ne $RegistrationEvidence) { $RegistrationEvidence.Registrations } else { @() }
      ScheduledTasks               = if ($null -ne $ScheduledTaskEvidence) { $ScheduledTaskEvidence.ScheduledTasks } else { @() }
      FileOperations               = if ($null -ne $FileOperationEvidence) { $FileOperationEvidence.FileOperations } else { @() }
      Downloads                    = if ($null -ne $DownloadEvidence) { $DownloadEvidence.Downloads } else { @() }
      ArchiveOperations            = if ($null -ne $ArchiveOperationEvidence) { $ArchiveOperationEvidence.ArchiveOperations } else { @() }
      ConfigurationChanges         = if ($null -ne $ConfigurationEvidence) { $ConfigurationEvidence.ConfigurationChanges } else { @() }
      InstallGroupRoute            = if ($null -ne $InstallFileEvidence) { $InstallFileEvidence.RouteId } else { $null }
      InstallGroupCalls            = if ($null -ne $InstallFileEvidence) { $InstallFileEvidence.Calls } else { @() }
      InstalledFiles               = if ($null -ne $InstallFileEvidence) { $InstallFileEvidence.InstalledFiles } else { @() }
      GenteeProgram                = if ($null -ne $UninstallEvidence) { $UninstallEvidence.ProgramInfo } elseif ($null -ne $Program) { [pscustomobject]@{ LauncherOffset = $Program.LauncherOffset; SectionOffset = $Program.SectionOffset; RuntimeSize = $Program.RuntimeSize; StoredProgramSize = $Program.StoredProgramSize; ProgramSize = $Program.ProgramSize; Packed = $Program.Packed; VersionMajor = $Program.VersionMajor; VersionMinor = $Program.VersionMinor; ProgramProfile = $Program.ProgramProfile; ObjectCount = $Program.Records.Count; AddRemoveProfile = $null; AddRemoveRoutine = $null; AddRemoveRoutineId = $null } } else { $null }
      UninstallRegistrations       = $UninstallCalls
      OuterArchitectureInfo        = $OuterArchitectureInfo
      PayloadArchitectures         = if ($null -ne $PayloadAnalysis) { $PayloadAnalysis.Architectures } else { [string[]]@() }
      PayloadArchitectureInfo      = if ($null -ne $PayloadAnalysis) { $PayloadAnalysis.ArchitectureInfo } else { @() }
      PayloadDependencyInfo        = if ($null -ne $PayloadAnalysis) { $PayloadAnalysis.DependencyInfo } else { $null }
      PayloadAnalysisFiles         = if ($null -ne $PayloadAnalysis) { $PayloadAnalysis.InspectedFiles } else { @() }
      GEA                          = if ($null -ne $Layout) { [pscustomobject]@{ ArchiveProfile = $Layout.ArchiveProfile; MajorVersion = $Layout.MajorVersion; MinorVersion = $Layout.MinorVersion; ArchiveOffset = $Layout.ArchiveOffset; HeaderSize = $Layout.HeaderSize; SummarySize = $Layout.SummarySize; MovedSize = $Layout.MovedSize; BlockSize = $Layout.BlockSize; SolidSize = $Layout.SolidSize; EntryCount = $Layout.Entries.Count; CompressionMethods = @($CompressionMethods | Sort-Object); UnsupportedCompressionMethods = @($CompressionMethods | Where-Object { $_ -eq 'Unknown' } | Sort-Object); PasswordCount = $Layout.PasswordCount; VolumeCount = $Layout.VolumeCount; VolumePattern = $Layout.VolumePattern; VolumeDirectory = $Layout.VolumeDirectory; VolumeFiles = $Layout.VolumeFiles; MissingVolumes = $Layout.MissingVolumes; AllVolumesAvailable = $Layout.AllVolumesAvailable } } else { $null }
      ExtractedFiles               = if ($null -ne $Layout) { @($Layout.Entries.FullName) } else { @() }
      CanExpand                    = $null -ne $Layout -and $Layout.AllVolumesAvailable -and $Layout.PasswordCount -eq 0 -and -not $CompressionMethods.Contains('Unknown')
      ParserVersionInfo            = [pscustomobject]@{ Parser = 'Dumplings.PackageModule.CreateInstall'; ParserMajor = 12; FormatCatalogVersion = [int](Get-CreateInstallCatalogProfile -Section CatalogVersion); ArchiveProfile = if ($null -ne $Layout) { $Layout.ArchiveProfile } else { $null }; AddRemoveProfile = if ($null -ne $UninstallEvidence) { $UninstallEvidence.ProgramInfo.AddRemoveProfile } else { $null }; InstallGroupRoute = if ($null -ne $InstallFileEvidence) { $InstallFileEvidence.RouteId } else { $null }; Sources = @('PE version resource', 'PE application manifest', 'Gentee launcher/linkhead and GE 4.0 object serialization', 'Gentee generated MAINVAR/g_list data and imported-function records', 'CreateInstall addremove/addremoveex/addremoveext command source', 'CreateInstall registry, association, shortcut, process, environment, prerequisite, service, registration, scheduled-task, copy, download, archive, and INI command sources', 'CreateInstall unpackgroup/unpackgroupex command source', 'Gentee GEA v1/v2 single-volume and spanned-volume structures', 'Gentee LZGE decoder', 'Gentee-modified PPMd-I decoder') }
    }
  }
}

function Expand-CreateInstallInstaller {
  <#
  .SYNOPSIS
    Extract stored, LZGE-compressed, and PPMd-compressed files from a CreateInstall GEA archive
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER DestinationPath
    Destination path for bounded extraction or decoded output; payload-relative names are resolved beneath this path.
  .PARAMETER Name
    Exact name or wildcard used to select format records or payload entries.
  .PARAMETER VolumePath
    Optional directory containing companion GEA volumes named by the main archive header.
  .PARAMETER MaximumExpandedBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  .PARAMETER CollisionAction
    Behavior when an output path already exists or is selected more than once.
  #>
  [OutputType([System.IO.FileInfo[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [string[]]$Name = '*',
    [AllowNull()][string]$VolumePath,
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Prompt',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 17179869184
  )

  process {
    $Layout = Get-CreateInstallArchiveLayout -Path $Path -VolumePath $VolumePath
    if (-not $Layout.AllVolumesAvailable) { throw "The CreateInstall archive cannot be expanded because $($Layout.MissingVolumes.Count) companion volume(s) are unavailable" }
    if ([string]::IsNullOrWhiteSpace($DestinationPath)) { $DestinationPath = Join-Path ([IO.Path]::GetTempPath()) ("Dumplings-CreateInstall-$([guid]::NewGuid().ToString('N'))") }
    return Export-CreateInstallArchiveSelection -Layout $Layout -DestinationPath $DestinationPath -Name $Name -CollisionAction $CollisionAction -MaximumExpandedBytes $MaximumExpandedBytes
  }
}

function Test-CreateInstall {
  <#
  .SYNOPSIS
    Test whether a PE contains a parseable CreateInstall GE program and MAINVAR project table.
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([bool])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process {
    try {
      $ResolvedPath = (Get-Item -LiteralPath $Path -Force).FullName
      # The compiled project program is authoritative and also covers valid no-payload setups.
      # Detection avoids full metadata and selected-payload analysis so a Boolean probe never
      # decompresses application binaries.
      $null = Get-PELayout -Path $ResolvedPath
      $Program = Get-CreateInstallGenteeProgram -Path $ResolvedPath
      $null = Get-CreateInstallProjectVariableEvidence -Program $Program
      return $true
    } catch { return $false }
  }
}

function Read-ProtocolsFromCreateInstall {
  <#
  .SYNOPSIS
    Read literal URL protocol names from CreateInstall registry evidence
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-CreateInstallInfo -Path $Path).Protocols }
}

function Read-FileExtensionsFromCreateInstall {
  <#
  .SYNOPSIS
    Read literal file extensions from CreateInstall registry evidence
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-CreateInstallInfo -Path $Path).FileExtensions }
}

function Read-ProductVersionFromCreateInstall {
  <#
  .SYNOPSIS
    Read the CreateInstall PE product version
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-CreateInstallInfo -Path $Path).DisplayVersion }
}

function Read-ProductNameFromCreateInstall {
  <#
  .SYNOPSIS
    Read the CreateInstall PE product name
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-CreateInstallInfo -Path $Path).DisplayName }
}

function Read-PublisherFromCreateInstall {
  <#
  .SYNOPSIS
    Read the CreateInstall PE publisher
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-CreateInstallInfo -Path $Path).Publisher }
}

function Read-ProductCodeFromCreateInstall {
  <#
  .SYNOPSIS
    Read a literal CreateInstall uninstall key when available
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-CreateInstallInfo -Path $Path).ProductCode }
}

function Read-ScopeFromCreateInstall {
  <#
  .SYNOPSIS
    Read CreateInstall scope from explicit elevation evidence
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-CreateInstallInfo -Path $Path).Scope }
}

Export-ModuleMember -Function Get-CreateInstallInfo, Expand-CreateInstallInstaller, Test-CreateInstall, Read-ProtocolsFromCreateInstall, Read-FileExtensionsFromCreateInstall, Read-ProductVersionFromCreateInstall, Read-ProductNameFromCreateInstall, Read-PublisherFromCreateInstall, Read-ProductCodeFromCreateInstall, Read-ScopeFromCreateInstall
