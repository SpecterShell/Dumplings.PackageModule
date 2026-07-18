# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }
# Force stop on error
$ErrorActionPreference = 'Stop'
# Force stop on undefined variables or properties
Set-StrictMode -Version 3

$ManifestVersion = '1.12.0'
$ManifestSchemaUrl = @{
  version       = "https://aka.ms/winget-manifest.version.${ManifestVersion}.schema.json"
  installer     = "https://aka.ms/winget-manifest.installer.${ManifestVersion}.schema.json"
  defaultLocale = "https://aka.ms/winget-manifest.defaultLocale.${ManifestVersion}.schema.json"
  locale        = "https://aka.ms/winget-manifest.locale.${ManifestVersion}.schema.json"
  singleton     = "https://aka.ms/winget-manifest.singleton.${ManifestVersion}.schema.json"
}
$ManifestSchemaDirectUrl = @{
  version       = "https://raw.githubusercontent.com/microsoft/winget-cli/master/schemas/JSON/manifests/v${ManifestVersion}/manifest.version.${ManifestVersion}.json"
  installer     = "https://raw.githubusercontent.com/microsoft/winget-cli/master/schemas/JSON/manifests/v${ManifestVersion}/manifest.installer.${ManifestVersion}.json"
  defaultLocale = "https://raw.githubusercontent.com/microsoft/winget-cli/master/schemas/JSON/manifests/v${ManifestVersion}/manifest.defaultLocale.${ManifestVersion}.json"
  locale        = "https://raw.githubusercontent.com/microsoft/winget-cli/master/schemas/JSON/manifests/v${ManifestVersion}/manifest.locale.${ManifestVersion}.json"
  singleton     = "https://raw.githubusercontent.com/microsoft/winget-cli/master/schemas/JSON/manifests/v${ManifestVersion}/manifest.singleton.${ManifestVersion}.json"
}

# These schema floors mirror ManifestSchemaValidation.cpp in winget-cli.
$Script:WinGetManifestSchemaVersions = @(
  '1.28.0'
  '1.12.0'
  '1.10.0'
  '1.9.0'
  '1.7.0'
  '1.6.0'
  '1.5.0'
  '1.4.0'
  '1.2.0'
  '1.1.0'
  '1.0.0'
)
$Script:ManifestSchemaRoot = Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath 'Assets', 'WinGetManifestSchemas'
$Script:ManifestSchemaCache = @{}

function Resolve-WinGetManifestSchemaVersion {
  <#
  .SYNOPSIS
    Resolve a manifest version to the schema revision used by WinGet
  .PARAMETER ManifestVersion
    The version declared by the manifest
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, Mandatory)]
    [ValidateNotNullOrWhiteSpace()]
    [string]$ManifestVersion
  )

  if ($ManifestVersion -notmatch '^(?<Major>\d+)\.(?<Minor>\d+)(?:\.(?<Patch>\d+))?') {
    throw "The manifest version '${ManifestVersion}' is invalid"
  }

  $Version = [version]::new(
    [int]$Matches.Major,
    [int]$Matches.Minor,
    ($Matches.Patch ? [int]$Matches.Patch : 0)
  )
  if ($Version.Major -gt 1) {
    throw "Unsupported manifest version: ${ManifestVersion}"
  }
  if ($Version -lt [version]'1.0.0') { return '0.1.0' }

  foreach ($Candidate in $Script:WinGetManifestSchemaVersions) {
    if ($Version -ge [version]$Candidate) { return $Candidate }
  }

  throw "Unsupported manifest version: ${ManifestVersion}"
}

function Get-WinGetManifestSchemaPath {
  <#
  .SYNOPSIS
    Get the vendored schema path used for a manifest type and version
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, Mandatory)]
    [ValidateSet('version', 'installer', 'defaultLocale', 'locale', 'singleton', 'preview')]
    [string]$ManifestType,

    [Parameter(Position = 1)]
    [string]$ManifestVersion = $Script:ManifestVersion
  )

  $SchemaVersion = Resolve-WinGetManifestSchemaVersion -ManifestVersion $ManifestVersion
  if ($SchemaVersion -ceq '0.1.0') {
    if ($ManifestType -cne 'preview') { throw "Manifest type '${ManifestType}' is unavailable for preview manifests" }
    return Join-Path -Path $Script:ManifestSchemaRoot -ChildPath 'preview' -AdditionalChildPath 'manifest.0.1.0.json'
  }
  if ($ManifestType -ceq 'preview') { throw "Manifest type 'preview' is unavailable for manifest version ${ManifestVersion}" }

  if ($SchemaVersion -ceq '1.28.0') {
    return Join-Path -Path $Script:ManifestSchemaRoot -ChildPath 'latest' -AdditionalChildPath "manifest.${ManifestType}.latest.json"
  }

  return Join-Path -Path $Script:ManifestSchemaRoot -ChildPath "v${SchemaVersion}" -AdditionalChildPath "manifest.${ManifestType}.${SchemaVersion}.json"
}

function Get-WinGetManifestSchema {
  <#
  .SYNOPSIS
    Get the vendored WinGet manifest schema for a manifest type and version
  .PARAMETER ManifestType
    The manifest type
  .PARAMETER ManifestVersion
    The manifest version whose schema floor should be selected
  .PARAMETER Raw
    Return the schema with JSON references intact
  #>
  [OutputType([hashtable])]
  param (
    [Parameter(Position = 0, Mandatory)]
    [ValidateSet('version', 'installer', 'defaultLocale', 'locale', 'singleton', 'preview')]
    [string]$ManifestType,

    [Parameter(Position = 1)]
    [string]$ManifestVersion = $Script:ManifestVersion,

    [switch]$Raw
  )

  $SchemaVersion = Resolve-WinGetManifestSchemaVersion -ManifestVersion $ManifestVersion
  $CacheKey = "${ManifestType}|${SchemaVersion}|$($Raw.IsPresent)"
  if ($Script:ManifestSchemaCache.Contains($CacheKey)) {
    return $Script:ManifestSchemaCache[$CacheKey]
  }

  $SchemaPath = Get-WinGetManifestSchemaPath -ManifestType $ManifestType -ManifestVersion $ManifestVersion
  if (-not (Test-Path -LiteralPath $SchemaPath -PathType Leaf)) {
    throw "The vendored schema is missing: ${SchemaPath}"
  }

  $Schema = Get-Content -LiteralPath $SchemaPath -Raw | ConvertFrom-Json -AsHashtable
  if (-not $Raw) {
    # Expand into a detached object. The shared schema engine never mutates
    # cached source schemas, so raw and expanded callers cannot affect one another.
    $Schema = Expand-YamlSchema -InputObject $Schema -Path (Split-Path -Path $SchemaPath -Parent)
  }
  $Script:ManifestSchemaCache[$CacheKey] = $Schema
  return $Schema
}

function Get-WinGetManifestSchemaUrl {
  <#
  .SYNOPSIS
    Get the canonical schema URL for a WinGet manifest
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, Mandatory)]
    [ValidateSet('version', 'installer', 'defaultLocale', 'locale', 'singleton')]
    [string]$ManifestType,

    [Parameter(Position = 1)]
    [string]$ManifestVersion = $Script:ManifestVersion
  )

  return "https://aka.ms/winget-manifest.${ManifestType}.${ManifestVersion}.schema.json"
}

Export-ModuleMember -Function '*' -Variable 'ManifestVersion', 'ManifestSchemaUrl', 'ManifestSchemaDirectUrl'
