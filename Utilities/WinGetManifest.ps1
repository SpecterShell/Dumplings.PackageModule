<#
.SYNOPSIS
  Create and edit complete WinGet manifest sets through PackageModule.
.DESCRIPTION
  This CLI is a thin wrapper over the logical manifest authoring APIs. It does
  not execute installers, submit manifests, create pull requests, or perform VM
  validation. Mutating commands validate and atomically replace the target leaf
  directory.
.PARAMETER Command
  new, installer-add, installer-set, installer-remove, locale-add, locale-set,
  locale-remove, value-set, value-remove, validate, or show.
.PARAMETER Path
  Leaf package-version manifest directory.
.PARAMETER RepositoryRoot
  Alternative winget-pkgs root used with PackageIdentifier and PackageVersion.
.PARAMETER PackageIdentifier
  Package identifier for new or repository-relative operations.
.PARAMETER PackageVersion
  Package version for new or repository-relative operations.
.PARAMETER Data
  Command payload as JSON or YAML text.
.PARAMETER DataPath
  File containing the command payload as JSON or YAML.
.PARAMETER Override
  Explicit installer override as JSON or YAML text.
.PARAMETER OverridePath
  File containing the explicit installer override.
.PARAMETER Match
  Exact installer selector as JSON or YAML text.
.PARAMETER MatchPath
  File containing the exact installer selector.
.PARAMETER InstallerUrl
  Installer URL for new or installer-add.
.PARAMETER InstallerPath
  Optional local copy of InstallerUrl.
.PARAMETER Architecture
  Explicit concrete installer architectures.
.PARAMETER Scope
  Explicit installer scope.
.PARAMETER NestedInstallerFile
  Exact nested payload path for an archive with multiple candidates.
.PARAMETER Index
  Zero-based installer index.
.PARAMETER PackageLocale
  Locale selector.
.PARAMETER Target
  Package, Installer, or Locale for value commands.
.PARAMETER PropertyPath
  RFC 6901 property path relative to Target.
.PARAMETER ErrorOnWarning
  Treat validation warnings as failures.
.PARAMETER PassThru
  Return structured command results.
#>
[CmdletBinding(SupportsShouldProcess)]
param (
  [Parameter(Mandatory, Position = 0)]
  [ValidateSet('new', 'installer-add', 'installer-set', 'installer-remove', 'locale-add', 'locale-set', 'locale-remove', 'value-set', 'value-remove', 'validate', 'show')]
  [string]$Command,

  [string]$Path,
  [string]$RepositoryRoot,
  [string]$PackageIdentifier,
  [string]$PackageVersion,
  [string]$Data,
  [string]$DataPath,
  [string]$Override,
  [string]$OverridePath,
  [string]$Match,
  [string]$MatchPath,
  [uri]$InstallerUrl,
  [string]$InstallerPath,
  [ValidateSet('x86', 'x64', 'arm64')][string[]]$Architecture,
  [ValidateSet('user', 'machine')][string]$Scope,
  [string]$NestedInstallerFile,
  [Nullable[int]]$Index,
  [string]$PackageLocale,
  [ValidateSet('Package', 'Installer', 'Locale')][string]$Target,
  [string]$PropertyPath,
  [switch]$ErrorOnWarning,
  [switch]$PassThru
)

Set-StrictMode -Version 3

# Load the standalone PackageModule dependency graph before dispatching. Core
# globals are not required by static analysis or local manifest persistence.
. (Join-Path $PSScriptRoot '..\Index.ps1')

function ConvertFrom-WinGetManifestCliData {
  <#
  .SYNOPSIS
    Parse one YAML or JSON CLI payload.
  .PARAMETER Content
    Inline payload text.
  .PARAMETER ContentPath
    Payload file path.
  .PARAMETER Name
    User-facing payload name for errors.
  #>
  param (
    [AllowNull()][string]$Content,
    [AllowNull()][string]$ContentPath,
    [Parameter(Mandatory)][string]$Name
  )

  if ($Content -and $ContentPath) { throw "Specify either $Name text or its file path, not both." }
  if ($ContentPath) { $Content = Get-Content -LiteralPath $ContentPath -Raw }
  if ([string]::IsNullOrWhiteSpace($Content)) { return $null }
  $Trimmed = $Content.TrimStart()
  if ($Trimmed.StartsWith('{') -or $Trimmed.StartsWith('[') -or $Trimmed -in @('null', 'true', 'false') -or $Trimmed -match '^-?\d') {
    return ConvertFrom-Json -InputObject $Content -AsHashtable -Depth 100
  }
  return ConvertFrom-Yaml -Yaml $Content
}

function Resolve-WinGetManifestCliPath {
  <#
  .SYNOPSIS
    Resolve a direct or repository-relative leaf manifest path.
  #>
  [OutputType([string])]
  param ()

  if ($Path) { return [IO.Path]::GetFullPath($Path, (Get-Location).ProviderPath) }
  if (-not $RepositoryRoot -or -not $PackageIdentifier -or -not $PackageVersion) {
    throw 'Specify Path, or RepositoryRoot with PackageIdentifier and PackageVersion.'
  }
  return Get-WinGetLocalPackagePath -RootPath $RepositoryRoot -PackageIdentifier $PackageIdentifier -PackageVersion $PackageVersion
}

function Save-WinGetManifestCliModel {
  <#
  .SYNOPSIS
    Persist one CLI mutation through the atomic authoring API.
  #>
  param ([Parameter(Mandatory)]$Manifest)

  $SaveArguments = @{ Manifest = $Manifest; Path = $ManifestPath; ErrorOnWarning = $ErrorOnWarning; PassThru = $PassThru }
  Save-WinGetManifest @SaveArguments
}

$ManifestPath = Resolve-WinGetManifestCliPath
$Payload = ConvertFrom-WinGetManifestCliData -Content $Data -ContentPath $DataPath -Name Data
$OverridePayload = ConvertFrom-WinGetManifestCliData -Content $Override -ContentPath $OverridePath -Name Override
$MatchPayload = ConvertFrom-WinGetManifestCliData -Content $Match -ContentPath $MatchPath -Name Match

switch ($Command) {
  'new' {
    if (-not $PackageIdentifier -or -not $PackageVersion) { throw 'new requires PackageIdentifier and PackageVersion.' }
    if ($Payload -isnot [System.Collections.IDictionary]) { throw 'new requires Data containing the complete default localization dictionary.' }
    if ($null -eq $InstallerUrl) { throw 'new requires InstallerUrl.' }
    $SuggestionArguments = @{ InstallerUrl = $InstallerUrl; PackageVersion = $PackageVersion }
    foreach ($Name in @('InstallerPath', 'Architecture', 'Scope', 'NestedInstallerFile')) {
      if ($PSBoundParameters.ContainsKey($Name)) { $SuggestionArguments[$Name] = $PSBoundParameters[$Name] }
    }
    if ($OverridePayload) { $SuggestionArguments.Override = $OverridePayload }
    $Suggestion = Get-WinGetInstallerManifestSuggestion @SuggestionArguments
    if ($Suggestion.HasBlockingDiagnostics) {
      throw "Installer analysis is blocked:`n$(@($Suggestion.Diagnostics | Where-Object IsBlocking | ForEach-Object { "[$($_.Id)] $($_.Message)" }) -join "`n")"
    }
    $null = Write-InstallerDiagnostics -Diagnostic @($Suggestion.Diagnostics) -Scenario ManifestAuthoring
    $Manifest = New-WinGetManifest -PackageIdentifier $PackageIdentifier -PackageVersion $PackageVersion -DefaultLocalization $Payload -Installer ([System.Collections.IDictionary[]]$Suggestion.Installers)
    Save-WinGetManifestCliModel -Manifest $Manifest
  }
  'installer-add' {
    if ($null -eq $InstallerUrl) { throw 'installer-add requires InstallerUrl.' }
    $Manifest = Read-WinGetManifest -Path $ManifestPath
    $Arguments = @{ Manifest = $Manifest; InstallerUrl = $InstallerUrl }
    foreach ($Name in @('InstallerPath', 'Architecture', 'Scope', 'NestedInstallerFile')) {
      if ($PSBoundParameters.ContainsKey($Name)) { $Arguments[$Name] = $PSBoundParameters[$Name] }
    }
    if ($OverridePayload) { $Arguments.Override = $OverridePayload }
    Save-WinGetManifestCliModel -Manifest (Add-WinGetManifestInstaller @Arguments)
  }
  'installer-set' {
    if ($Payload -isnot [System.Collections.IDictionary]) { throw 'installer-set requires Data containing a patch dictionary.' }
    $Arguments = @{ Manifest = (Read-WinGetManifest -Path $ManifestPath); Patch = $Payload }
    if ($null -ne $Index) { $Arguments.Index = [int]$Index } elseif ($MatchPayload -is [System.Collections.IDictionary]) { $Arguments.Match = $MatchPayload } else { throw 'installer-set requires Index or Match.' }
    Save-WinGetManifestCliModel -Manifest (Set-WinGetManifestInstaller @Arguments)
  }
  'installer-remove' {
    $Arguments = @{ Manifest = (Read-WinGetManifest -Path $ManifestPath) }
    if ($null -ne $Index) { $Arguments.Index = [int]$Index } elseif ($MatchPayload -is [System.Collections.IDictionary]) { $Arguments.Match = $MatchPayload } else { throw 'installer-remove requires Index or Match.' }
    Save-WinGetManifestCliModel -Manifest (Remove-WinGetManifestInstaller @Arguments)
  }
  'locale-add' {
    if ($Payload -isnot [System.Collections.IDictionary]) { throw 'locale-add requires Data containing a locale dictionary.' }
    Save-WinGetManifestCliModel -Manifest (Add-WinGetManifestLocale -Manifest (Read-WinGetManifest -Path $ManifestPath) -Localization $Payload)
  }
  'locale-set' {
    if (-not $PackageLocale -or $Payload -isnot [System.Collections.IDictionary]) { throw 'locale-set requires PackageLocale and Data containing a patch dictionary.' }
    Save-WinGetManifestCliModel -Manifest (Set-WinGetManifestLocale -Manifest (Read-WinGetManifest -Path $ManifestPath) -PackageLocale $PackageLocale -Patch $Payload)
  }
  'locale-remove' {
    if (-not $PackageLocale) { throw 'locale-remove requires PackageLocale.' }
    Save-WinGetManifestCliModel -Manifest (Remove-WinGetManifestLocale -Manifest (Read-WinGetManifest -Path $ManifestPath) -PackageLocale $PackageLocale)
  }
  'value-set' {
    if (-not $Target -or -not $PropertyPath) { throw 'value-set requires Target and PropertyPath.' }
    $Arguments = @{ Manifest = (Read-WinGetManifest -Path $ManifestPath); Target = $Target; Path = $PropertyPath; Value = $Payload }
    if ($null -ne $Index) { $Arguments.Index = [int]$Index }
    if ($MatchPayload) { $Arguments.Match = $MatchPayload }
    if ($PackageLocale) { $Arguments.PackageLocale = $PackageLocale }
    Save-WinGetManifestCliModel -Manifest (Set-WinGetManifestValue @Arguments)
  }
  'value-remove' {
    if (-not $Target -or -not $PropertyPath) { throw 'value-remove requires Target and PropertyPath.' }
    $Arguments = @{ Manifest = (Read-WinGetManifest -Path $ManifestPath); Target = $Target; Path = $PropertyPath }
    if ($null -ne $Index) { $Arguments.Index = [int]$Index }
    if ($MatchPayload) { $Arguments.Match = $MatchPayload }
    if ($PackageLocale) { $Arguments.PackageLocale = $PackageLocale }
    Save-WinGetManifestCliModel -Manifest (Remove-WinGetManifestValue @Arguments)
  }
  'validate' {
    $Result = Get-WinGetManifestValidationResult -Path $ManifestPath
    foreach ($Warning in $Result.Warnings) { Write-Warning "[$($Warning.Id)] $($Warning.Message)" }
    if ($Result.HasErrors -or ($ErrorOnWarning -and $Result.HasWarnings)) {
      $Failures = $Result.HasErrors ? $Result.Errors : $Result.Warnings
      throw "Manifest validation failed:`n$(@($Failures | ForEach-Object { "[$($_.Id)] $($_.Message)" }) -join "`n")"
    }
    if ($PassThru) { $Result }
  }
  'show' {
    $Manifest = Read-WinGetManifest -Path $ManifestPath
    if ($PassThru) { $Manifest } else { ConvertTo-Yaml -Data (ConvertTo-WinGetMergedManifest -Manifest $Manifest) -Options DisableAliases }
  }
}
