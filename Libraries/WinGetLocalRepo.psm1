# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }
# Force stop on error
$ErrorActionPreference = 'Stop'
# Force stop on undefined variables or properties
Set-StrictMode -Version 3

# UTF-8 without BOM encoding
$Encoding = [System.Text.UTF8Encoding]::new($false)
# The locale for sorting strings
$Culture = 'en-US'
# The scriptblock for sorting natural numbers
$ToNatural = { [regex]::Replace($_, '\d+', { $args[0].Value.PadLeft(20) }) }

class WinGetManifestRaw {
  [string]$Version
  [string]$Installer
  [System.Collections.Generic.IDictionary[string, string]]$Locale
}

function Get-WinGetLocalPackagePath {
  <#
  .SYNOPSIS
    Get the relative path of a package, a version of the package, or a manifest of the version of the package
  .DESCRIPTION
    Get the relative path of
    - a package, or
    - a version, if the version parameter is provided, or
    - a version/installer manifest, if the version parameter is provided and the manifest type parameter is set to version/installer, or
    - a locale manifest, if the version parameter is provided, the manifest type parameter is set to locale, and the locale parameter is provided.
  .PARAMETER PackageIdentifier
    The identifier of the package
  .PARAMETER PackageVersion
    The version fo the package
  .PARAMETER ManifestType
    The type of the manifest
  .PARAMETER Locale
    The locale of the locale manifest
  .PARAMETER RootPath
    The path to the root folder of the manifests repository
  .EXAMPLE
    PS> Get-WinGetLocalPackagePath -PackageIdentifier 'SpecterShell.Dumplings'

    s\SpecterShell\Dumplings
  .EXAMPLE
    PS> Get-WinGetLocalPackagePath -PackageIdentifier 'SpecterShell.Dumplings' -PackageVersion '1.14.514'

    s\SpecterShell\Dumplings\1.14.514
  .EXAMPLE
    PS> Get-WinGetLocalPackagePath -PackageIdentifier 'SpecterShell.Dumplings' -PackageVersion '1.14.514' -ManifestType 'installer'

    s\SpecterShell\Dumplings\1.14.514\SpecterShell.Dumplings.installer.yaml
  .EXAMPLE
    PS> Get-WinGetLocalPackagePath -PackageIdentifier 'SpecterShell.Dumplings' -PackageVersion '1.14.514' -ManifestType 'locale' -Locale 'en-US'

    s\SpecterShell\Dumplings\1.14.514\SpecterShell.Dumplings.locale.en-US.yaml
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The identifier of the package')]
    # TODO: Fetch validation pattern from schemas
    [ValidatePattern('^[^\.\s\\/:\*\?\"<>\|\x01-\x1f]{1,32}(\.[^\.\s\\/:\*\?\"<>\|\x01-\x1f]{1,32}){1,7}$')]
    [ValidateLength(0, 128)]
    [string]$PackageIdentifier,
    [Parameter(Position = 1, HelpMessage = 'The version of the package')]
    [ValidatePattern('^[^\\/:\*\?\"<>\|\x01-\x1f]+$')]
    [ValidateLength(0, 128)]
    [string]$PackageVersion,
    [Parameter(Position = 2, HelpMessage = 'The type of the manifest')]
    [ValidateSet('version', 'installer', 'locale')]
    [string]$ManifestType,
    [Parameter(Position = 3, HelpMessage = 'The locale of the locale manifest')]
    [ValidatePattern('^([a-zA-Z]{2,3}|[iI]-[a-zA-Z]+|[xX]-[a-zA-Z]{1,8})(-[a-zA-Z]{1,8})*$')]
    [ValidateLength(0, 20)]
    [string]$Locale,
    [Parameter(HelpMessage = 'The path to the root folder of the manifests repository')]
    [ValidateNotNull()]
    [string]$RootPath = ''
  )

  process {
    # s
    $Path = $RootPath ? (Join-Path $RootPath $PackageIdentifier.ToLower().Chars(0)) : $PackageIdentifier.ToLower().Chars(0)

    # s\SpecterShell\Dumplings
    $PackageIdentifier.Split('.').ForEach({ $Path = Join-Path $Path $_ })

    # If the package version is provided, append it to the path
    # s\SpecterShell\Dumplings\1.14.514
    if ($PackageVersion) {
      $Path = Join-Path $Path $PackageVersion

      # If the manifest type is provided, append the manifest file name to the path
      if ($ManifestType) {
        switch ($ManifestType) {
          # s\SpecterShell\Dumplings\1.14.514\SpecterShell.Dumplings.yaml
          'version' { $Path = Join-Path $Path "${PackageIdentifier}.yaml" }
          # s\SpecterShell\Dumplings\1.14.514\SpecterShell.Dumplings.installer.yaml
          'installer' { $Path = Join-Path $Path "${PackageIdentifier}.installer.yaml" }
          # s\SpecterShell\Dumplings\1.14.514\SpecterShell.Dumplings.locale.en-US.yaml
          'locale' {
            if (-not $Locale) { throw 'Locale must be provided when manifest type is locale' }
            $Path = Join-Path $Path "${PackageIdentifier}.locale.${Locale}.yaml"
          }
        }
      }
    }

    return $Path
  }
}

function Get-WinGetLocalPackageVersion {
  <#
  .SYNOPSIS
    Get the available versions of a package
  .PARAMETER PackageIdentifier
    The identifier of the package
  .PARAMETER RootPath
    The path to the root folder of the manifests repository
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The identifier of the package')]
    [string]$PackageIdentifier,
    [Parameter(Mandatory, HelpMessage = 'The path to the root folder of the manifests repository')]
    [string]$RootPath
  )

  process {
    $Prefix = Get-WinGetLocalPackagePath -PackageIdentifier $PackageIdentifier -RootPath $RootPath
    if (-not (Test-Path -Path $Prefix -PathType 'Container')) { throw "The path `"$Prefix`" does not exist or is not a directory." }

    Join-Path $Prefix '*' "${PackageIdentifier}.yaml" |
      Get-ChildItem -File | Select-Object -ExpandProperty 'Directory' | Select-Object -ExpandProperty 'Name' |
      Sort-Object -Property $Script:ToNatural -Stable -Culture $Script:Culture |
      Write-Output -NoEnumerate
  }
}

function Get-WinGetLocalManifests {
  <#
  .SYNOPSIS
    Get the available manifests of a package version
  .PARAMETER PackageIdentifier
    The identifier of the package
  .PARAMETER PackageVersion
    The version of the package
  .PARAMETER RootPath
    The path to the root folder of the manifests repository
  .PARAMETER Path
    The path to the folder containing the manifests
  #>
  [OutputType([System.IO.DirectoryInfo])]
  param (
    [Parameter(Position = 0, Mandatory, HelpMessage = 'The identifier of the package')]
    [string]$PackageIdentifier,
    [Parameter(ParameterSetName = 'RootPath', Position = 1, Mandatory, HelpMessage = 'The version of the package')]
    [string]$PackageVersion,
    [Parameter(ParameterSetName = 'RootPath', Mandatory, HelpMessage = 'The path to the root folder of the manifests repository')]
    [string]$RootPath,
    [Parameter(ParameterSetName = 'Path', Mandatory, HelpMessage = 'The path to the folder containing the manifests')]
    [string]$Path
  )

  process {
    $Prefix = $PSCmdlet.ParameterSetName -eq 'Path' ? $Path : (Get-WinGetLocalPackagePath -PackageIdentifier $PackageIdentifier -PackageVersion $PackageVersion -RootPath $RootPath)
    if (-not (Test-Path -Path $Prefix -PathType 'Container')) { throw "The path `"$Prefix`" does not exist or is not a directory." }

    Join-Path $Prefix '*.yaml' | Get-ChildItem -File |
      Where-Object -FilterScript { $_.Name -ceq "${PackageIdentifier}.yaml" -or $_.Name -ceq "${PackageIdentifier}.installer.yaml" -or $_.Name -clike "${PackageIdentifier}.locale.*.yaml" }
  }
}

function Read-WinGetLocalManifestContent {
  <#
  .SYNOPSIS
    Read the content of a manifest file
  .PARAMETER Path
    The path to the manifest
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, Mandatory, ValueFromPipeline, HelpMessage = 'The path to the manifest')]
    [string]$Path
  )

  process {
    Get-Content -Path $Path -Raw -Encoding $Script:Encoding
  }
}

function Read-WinGetLocalManifests {
  <#
  .SYNOPSIS
    Read the manifests for a package
  .DESCRIPTION
    Read the installer, locale and version manifests for a package using the provided package identifier and manifests path
  .PARAMETER PackageIdentifier
    The identifier of the package
  .PARAMETER PackageVersion
    The version of the package
  .PARAMETER RootPath
    The path to the root folder of the manifests repository
  .PARAMETER Path
    The path to the folder containing the manifests
  #>
  [OutputType([WinGetManifestRaw])]
  param (
    [Parameter(Position = 0, Mandatory, HelpMessage = 'The identifier of the package')]
    [string]$PackageIdentifier,
    [Parameter(ParameterSetName = 'RootPath', Position = 1, Mandatory, HelpMessage = 'The version of the package')]
    [string]$PackageVersion,
    [Parameter(ParameterSetName = 'RootPath', Mandatory, HelpMessage = 'The path to the root folder of the manifests repository')]
    [string]$RootPath,
    [Parameter(ParameterSetName = 'Path', Mandatory, HelpMessage = 'The path to the folder containing the manifests')]
    [string]$Path
  )

  $ManifestItems = Get-WinGetLocalManifests @PSBoundParameters

  # Process mandatory version manifest. The number of version manifests must be exactly one.
  $VersionManifestItem = @($ManifestItems | Where-Object -FilterScript { $_.Name -ceq "${PackageIdentifier}.yaml" })
  if ($VersionManifestItem.Count -gt 1) { throw "Multiple version/singleton manifests found for package '$PackageIdentifier'. Please ensure there is only one version manifest." }
  elseif ($VersionManifestItem.Count -eq 0) { throw "No version/singleton manifest found for package '$PackageIdentifier'. Please ensure the version manifest exists." }
  else { $VersionManifestContent = Read-WinGetLocalManifestContent -Path $VersionManifestItem[0] }

  # Process optional installer manifest. The number of installer manifests must be zero or one.
  $InstallerManifestContent = $null
  $InstallerManifestItem = @($ManifestItems | Where-Object -FilterScript { $_.Name -ceq "${PackageIdentifier}.installer.yaml" })
  if ($InstallerManifestItem.Count -gt 1) { throw "Multiple installer manifests found for package '$PackageIdentifier'. Please ensure there is only one installer manifest." }
  elseif ($InstallerManifestItem.Count -eq 1) { $InstallerManifestContent = Read-WinGetLocalManifestContent -Path $InstallerManifestItem[0] }

  # Process optional locale manifests. The number of locale manifests can be zero or more.
  $LocaleManifestContent = [System.Collections.Generic.OrderedDictionary[string, string]]::new($ManifestItems.Count)
  $ManifestItems | ForEach-Object -Process {
    if ($_.Name -match "^$([regex]::Escape($PackageIdentifier))\.locale\.(.+)\.yaml$") {
      $LocaleManifestContent[$Matches[1]] = Read-WinGetLocalManifestContent -Path $_.FullName
    }
  }

  return [WinGetManifestRaw]@{
    Version   = $VersionManifestContent
    Installer = $InstallerManifestContent
    Locale    = $LocaleManifestContent
  }
}

function Write-WinGetLocalManifestContent {
  <#
  .SYNOPSIS
    Write the content of a manifest file
  .PARAMETER Content
    The content of the manifest as a string
  .PARAMETER Path
    The path to the folder containing the manifests
  #>
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The content of the manifest as a string')]
    [string]$Content,
    [Parameter(Position = 1, Mandatory, HelpMessage = 'The path to the folder containing the manifests')]
    [string]$Path
  )

  process {
    Set-Content -Path $Path -Value $Content -Encoding $Script:Encoding -Force -NoNewline
  }
}

function Add-WinGetLocalManifests {
  <#
  .SYNOPSIS
    Add the new package manifests to the local WinGet repository or a specified path
  .PARAMETER PackageIdentifier
    The identifier of the package
  .PARAMETER PackageVersion
    The version of the package
  .PARAMETER RootPath
    The path to the root folder of the manifests repository
  .PARAMETER Path
    The path to the folder containing the manifests
  .PARAMETER Manifests
    The raw manifests to add
  #>
  [CmdletBinding(DefaultParameterSetName = 'RootPath')]
  param (
    [Parameter(Position = 0, Mandatory, HelpMessage = 'The identifier of the package')]
    [string]$PackageIdentifier,
    [Parameter(ParameterSetName = 'RootPath', Position = 1, Mandatory, HelpMessage = 'The version of the package')]
    [string]$PackageVersion,
    [Parameter(ParameterSetName = 'RootPath', Mandatory, HelpMessage = 'The path to the root folder of the manifests repository')]
    [string]$RootPath,
    [Parameter(ParameterSetName = 'Path', Mandatory, HelpMessage = 'The path to the folder containing the manifests')]
    [string]$Path,
    [Parameter(ValueFromPipeline, Mandatory, HelpMessage = 'The raw manifests to add')]
    [WinGetManifestRaw[]]$Manifest
  )

  process {
    $Prefix = $PSCmdlet.ParameterSetName -eq 'Path' ? $Path : (Get-WinGetLocalPackagePath -PackageIdentifier $PackageIdentifier -PackageVersion $PackageVersion -RootPath $RootPath)
    $null = New-Item -Path $Prefix -ItemType 'Directory' -Force

    # The manifests to write
    $Manifests = [ordered]@{}

    # Add version manifest to write
    if (-not $Manifest.Version) { throw 'The version manifest is null or empty.' }
    $Manifests["${PackageIdentifier}.yaml"] = $Manifest.Version

    # Add installer manifest to write if it exists
    if ($Manifest.Installer) { $Manifests["${PackageIdentifier}.installer.yaml"] = $Manifest.Installer }

    # Add locale manifests to write if they exist
    $Manifest.Locale.GetEnumerator() | ForEach-Object -Process { $Manifests["${PackageIdentifier}.locale.$($_.Key).yaml"] = $_.Value }

    # Write manifests
    $Manifests.GetEnumerator() | ForEach-Object -Process { Write-WinGetLocalManifestContent -Content $_.Value -Path (Join-Path $Prefix $_.Key) }
  }
}

function Remove-WinGetLocalManifests {
  <#
  .SYNOPSIS
    Remove the package manifests from the local WinGet repository or a specified path
  .PARAMETER PackageIdentifier
    The identifier of the package
  .PARAMETER PackageVersion
    The version of the package
  .PARAMETER RootPath
    The path to the root folder of the manifests repository
  .PARAMETER Path
    The path to the folder containing the manifests
  #>
  [CmdletBinding(DefaultParameterSetName = 'RootPath')]
  param (
    [Parameter(ValueFromPipeline, Position = 0, Mandatory, HelpMessage = 'The identifier of the package')]
    [string]$PackageIdentifier,
    [Parameter(ParameterSetName = 'RootPath', Position = 1, Mandatory, HelpMessage = 'The version of the package')]
    [string]$PackageVersion,
    [Parameter(ParameterSetName = 'RootPath', Mandatory, HelpMessage = 'The path to the root folder of the manifests repository')]
    [string]$RootPath,
    [Parameter(ParameterSetName = 'Path', Mandatory, HelpMessage = 'The path to the folder containing the manifests')]
    [string]$Path
  )

  process {
    $Manifests = Get-WinGetLocalManifests @PSBoundParameters

    # Remove manifests
    $Manifests | ForEach-Object -Process { Remove-Item -Path $_.FullName -Force -ProgressAction 'SilentlyContinue' }
  }
}

Export-ModuleMember -Function '*' -Variable 'DumplingsWinGetLocalRepoDefaultRootPath'
