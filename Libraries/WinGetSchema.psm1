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
}
$ManifestSchemaDirectUrl = @{
  version       = "https://raw.githubusercontent.com/microsoft/winget-cli/master/schemas/JSON/manifests/v${ManifestVersion}/manifest.version.${ManifestVersion}.json"
  installer     = "https://raw.githubusercontent.com/microsoft/winget-cli/master/schemas/JSON/manifests/v${ManifestVersion}/manifest.installer.${ManifestVersion}.json"
  defaultLocale = "https://raw.githubusercontent.com/microsoft/winget-cli/master/schemas/JSON/manifests/v${ManifestVersion}/manifest.defaultLocale.${ManifestVersion}.json"
  locale        = "https://raw.githubusercontent.com/microsoft/winget-cli/master/schemas/JSON/manifests/v${ManifestVersion}/manifest.locale.${ManifestVersion}.json"
}

# Cache for storing fetched schemas
$Script:ManifestSchemaCache = @{
  version       = $null
  installer     = $null
  defaultLocale = $null
  locale        = $null
}

function Get-WinGetManifestSchema {
  <#
  .SYNOPSIS
    Get the WinGet manifest schema for a specific manifest type and version
  .DESCRIPTION
    Retrieve the WinGet manifest schema from the official Microsoft repository
  .PARAMETER ManifestType
    The type of manifest to get the schema for (version, installer, defaultLocale, locale)
  .PARAMETER ManifestVersion
    The version of the manifest schema to get
  .EXAMPLE
    Get-WinGetManifestSchema -ManifestType installer -ManifestVersion '1.10.0'
  #>
  [OutputType([hashtable])]
  param (
    [Parameter(Position = 0, Mandatory, HelpMessage = 'The type of manifest to get the schema for')]
    [ValidateSet('version', 'installer', 'defaultLocale', 'locale')]
    [string]$ManifestType,

    [Parameter(Position = 1, HelpMessage = 'The version of the manifest schema to get')]
    [string]$ManifestVersion = $Script:ManifestVersion
  )

  # Check if we already have this schema cached
  if ($null -ne $Script:ManifestSchemaCache[$ManifestType]) {
    return $Script:ManifestSchemaCache[$ManifestType]
  }

  # Build the direct URL for this manifest type and version
  $SchemaUrl = $Script:ManifestSchemaDirectUrl[$ManifestType] -replace $Script:ManifestVersion, $ManifestVersion

  try {
    # Fetch the schema from the repository
    $Schema = Invoke-WebRequest -Uri $SchemaUrl | ConvertFrom-Json -AsHashtable

    # Expand the YAML schema
    Expand-YamlSchema -InputObject $Schema

    # Cache the schema for future use
    $Script:ManifestSchemaCache[$ManifestType] = $Schema

    return $Schema
  } catch {
    throw "Failed to fetch schema for manifest type '$ManifestType' version '$ManifestVersion': $_"
  }
}

function Get-WinGetManifestSchemaUrl {
  <#
  .SYNOPSIS
    Get the WinGet manifest schema URL for a specific manifest type and version
  .DESCRIPTION
    Retrieve the WinGet manifest schema URL from the official Microsoft repository
  .PARAMETER ManifestType
    The type of manifest to get the schema URL for (version, installer, defaultLocale, locale)
  .PARAMETER ManifestVersion
    The version of the manifest schema to get
  .EXAMPLE
    Get-WinGetManifestSchemaUrl -ManifestType installer -ManifestVersion '1.10.0'
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, Mandatory, HelpMessage = 'The type of manifest to get the schema URL for')]
    [ValidateSet('version', 'installer', 'defaultLocale', 'locale')]
    [string]$ManifestType,

    [Parameter(Position = 1, HelpMessage = 'The version of the manifest schema to get')]
    [string]$ManifestVersion = $Script:ManifestVersion
  )

  return $Script:ManifestSchemaUrl[$ManifestType] -replace $Script:ManifestVersion, $ManifestVersion
}

Export-ModuleMember -Function '*' -Variable 'ManifestVersion', 'ManifestSchemaUrl', 'ManifestSchemaDirectUrl'
