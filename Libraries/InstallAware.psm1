# SPDX-License-Identifier: Apache-2.0
# Static InstallAware parser. It validates the embedded 7z project archive and
# reads PE metadata without executing either the wrapper or nested setup files.
# Binary structure consumed here:
#
#   PE launcher -> overlay -> one or more standard 7z archives
#     37 7A BC AF 27 1C -> catalog -> mia.lib/*.mia/_setup.exe/data entries
#
# InstallAware identity is established by structured archive entries, not a raw
# product string. Each candidate archive and extracted path/byte count is bounded;
# nested MSI/EXE payloads are returned for independent analysis.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:InstallAwareMaximumArchiveBytes = 8589934592

function Get-InstallAwareArchiveData {
  <#
  .SYNOPSIS
    Locate the validated InstallAware project archive after the PE image
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)

  $File = Get-Item -LiteralPath $Path -Force
  $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try { $OverlayOffset = Get-PEOverlayOffset -Stream $Stream } finally { $Stream.Dispose() }
  if ($OverlayOffset -le 0 -or $OverlayOffset -ge $File.Length) { throw 'The InstallAware PE has no project overlay' }

  # Restrict archive discovery to the PE overlay and require structured project
  # names; a standard 7z signature alone is not InstallAware identification.
  foreach ($Range in @(Get-EmbeddedSevenZipArchiveRange -Path $File.FullName -StartOffset $OverlayOffset -MaximumArchives 16 -MaximumArchiveBytes $Script:InstallAwareMaximumArchiveBytes)) {
    $Context = $null
    try {
      $Context = Open-InstallerArchiveRange -Path $File.FullName -Range $Range
      $Entries = @(Get-InstallerArchiveEntry -Archive $Context.Archive | ForEach-Object {
          [pscustomobject]@{ FullName = $_.FullName; Length = $_.Length }
        })
      $HasProjectEvidence = $Entries | Where-Object {
        $_.FullName -ieq 'mia.lib' -or $_.FullName -match '(?i)\.mia(?:/|$)' -or
        $_.FullName -match '(?i)_setup\.(?:exe|res)$' -or $_.FullName -match '(?i)^data[/\\]'
      } | Select-Object -First 1
      if (-not $HasProjectEvidence) { continue }
      return [pscustomobject]@{ SourcePath = $File.FullName; Range = $Range; Entries = $Entries }
    } catch {
      # Continue past malformed or unrelated embedded archives in the overlay.
      continue
    } finally {
      if ($Context) { Close-InstallerArchiveRange -Context $Context }
    }
  }
  throw 'The PE overlay does not contain a validated InstallAware project archive'
}

function Get-InstallAwareInfo {
  <#
  .SYNOPSIS
    Read static InstallAware metadata and nested payload evidence
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)

  process {
    $File = Get-Item -LiteralPath $Path -Force
    $ArchiveData = Get-InstallAwareArchiveData -Path $File.FullName
    $VersionInfo = [Diagnostics.FileVersionInfo]::GetVersionInfo($File.FullName)
    $DisplayName = ([string]$VersionInfo.ProductName).Trim()
    $DisplayVersion = ([string]$VersionInfo.ProductVersion).Trim()
    $Publisher = ([string]$VersionInfo.CompanyName).Trim()
    $ExecutionLevel = Get-PERequestedExecutionLevel -Path $File.FullName

    # Requested execution level proves only an unconditional machine request;
    # delegated payloads may still implement different scope behavior.
    $Scope = if ($ExecutionLevel -ieq 'requireAdministrator') { 'machine' } else { $null }

    # Surface nested installers for recursive analysis without assuming which
    # payload owns the final visible Apps & Features registration.
    $NestedInstallers = @($ArchiveData.Entries | Where-Object { $_.FullName -match '(?i)\.(?:exe|msi|msp|msix|appx)$' } | Select-Object -ExpandProperty FullName)
    $MsiPayloads = @($NestedInstallers | Where-Object { $_ -match '(?i)\.(?:msi|msp)$' })
    $RegistryWrites = @()
    $RegistryAssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite $RegistryWrites
    $Warnings = [System.Collections.Generic.List[string]]::new()
    $Warnings.Add('InstallAware PE version resources identify the package but do not prove the visible uninstall key. Validate ProductCode and ARP type in a VM.')
    if ($ExecutionLevel -ieq 'requireAdministrator') {
      $Warnings.Add('Machine scope is inferred from an explicit requireAdministrator application manifest; verify packages that delegate installation to a nested payload.')
    } elseif (-not $ExecutionLevel) {
      $Warnings.Add('The InstallAware application manifest does not expose a requested execution level; scope requires VM validation.')
    }
    if ($MsiPayloads.Count -gt 0) { $Warnings.Add('The InstallAware archive contains MSI/MSP payloads. Analyze the nested database and determine whether the visible ARP entry is MSI or EXE.') }

    [pscustomobject]@{
      InstallerType              = 'InstallAware'
      ProductCode                = $null
      PackageName                = $DisplayName
      DisplayName                = $DisplayName
      ProductName                = $DisplayName
      DisplayVersion             = $DisplayVersion
      Publisher                  = $Publisher
      FileDescription            = ([string]$VersionInfo.FileDescription).Trim()
      Scope                      = $Scope
      SupportedScopes            = if ($Scope) { @($Scope) } else { @() }
      RequestedExecutionLevel    = $ExecutionLevel
      RegistryWrites             = $RegistryWrites
      RegistryAssociationInfo    = $RegistryAssociationInfo
      Protocols                  = $RegistryAssociationInfo.Protocols
      FileExtensions             = $RegistryAssociationInfo.FileExtensions
      WritesAppsAndFeaturesEntry = $null
      ExtractedFiles             = @($ArchiveData.Entries.FullName)
      NestedInstallerFiles       = $NestedInstallers
      MsiPayloads                = $MsiPayloads
      ArchiveOffset              = $ArchiveData.Range.Offset
      ArchiveLength              = $ArchiveData.Range.Length
      Warnings                   = @($Warnings)
      ParserVersionInfo          = [pscustomobject]@{ Parser = 'Dumplings.PackageModule.InstallAware'; ParserMajor = 1; Sources = @('PE version resource', 'PE application manifest', 'validated embedded 7z project archive') }
    }
  }
}

function Expand-InstallAwareInstaller {
  <#
  .SYNOPSIS
    Extract files from the validated InstallAware project archive
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER DestinationPath
    Destination path for bounded extraction or decoded output; payload-relative names are resolved beneath this path.
  .PARAMETER Name
    Exact name or wildcard used to select format records or payload entries.
  .PARAMETER MaximumExpandedBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  [OutputType([System.IO.FileInfo[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [string]$Name = '*',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 17179869184
  )

  process {
    $ArchiveData = Get-InstallAwareArchiveData -Path $Path
    $Context = Open-InstallerArchiveRange -Path $ArchiveData.SourcePath -Range $ArchiveData.Range
    try {
      if ([string]::IsNullOrWhiteSpace($DestinationPath)) { $DestinationPath = Join-Path ([IO.Path]::GetTempPath()) ("Dumplings-InstallAware-$([guid]::NewGuid().ToString('N'))") }
      $null = New-Item -Path $DestinationPath -ItemType Directory -Force
      $Archive = $Context.Archive
      $Written = 0L
      $Result = [System.Collections.Generic.List[System.IO.FileInfo]]::new()

      # Apply selection to catalog paths, enforce aggregate output limits, and
      # resolve every destination beneath the extraction root.
      foreach ($Entry in Get-InstallerArchiveEntry -Archive $Archive) {
        if (-not (Test-ExtractionPattern -Path $Entry.FullName -Pattern $Name)) { continue }
        $Written += $Entry.Length
        if ($Written -gt $MaximumExpandedBytes) { throw 'InstallAware extraction exceeds the configured output limit' }
        $OutputPath = Resolve-SafeExtractionPath -DestinationPath $DestinationPath -RelativePath $Entry.FullName
        $Result.Add((Export-InstallerArchiveEntry -Entry $Entry -DestinationPath $OutputPath -MaximumBytes $MaximumExpandedBytes))
      }
      if ($Result.Count -eq 0) { throw "No InstallAware project files matched '$Name'" }
      return $Result.ToArray()
    } finally { Close-InstallerArchiveRange -Context $Context }
  }
}

function Test-InstallAware {
  <#
  .SYNOPSIS
    Test whether a file contains a parseable InstallAware project archive
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([bool])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { try { $null = Get-InstallAwareInfo -Path $Path; return $true } catch { return $false } }
}

function Read-ProtocolsFromInstallAware {
  <#
  .SYNOPSIS
    Read literal URL protocol names from InstallAware registry evidence
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallAwareInfo -Path $Path).Protocols }
}

function Read-FileExtensionsFromInstallAware {
  <#
  .SYNOPSIS
    Read literal file extensions from InstallAware registry evidence
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallAwareInfo -Path $Path).FileExtensions }
}

function Read-ProductVersionFromInstallAware {
  <#
  .SYNOPSIS
    Read the InstallAware PE product version
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallAwareInfo -Path $Path).DisplayVersion }
}

function Read-ProductNameFromInstallAware {
  <#
  .SYNOPSIS
    Read the InstallAware PE product name
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallAwareInfo -Path $Path).DisplayName }
}

function Read-PublisherFromInstallAware {
  <#
  .SYNOPSIS
    Read the InstallAware PE publisher
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallAwareInfo -Path $Path).Publisher }
}

function Read-ProductCodeFromInstallAware {
  <#
  .SYNOPSIS
    Read a literal InstallAware uninstall key when available
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallAwareInfo -Path $Path).ProductCode }
}

function Read-ScopeFromInstallAware {
  <#
  .SYNOPSIS
    Read InstallAware scope from explicit elevation evidence
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallAwareInfo -Path $Path).Scope }
}

Export-ModuleMember -Function Get-InstallAwareInfo, Expand-InstallAwareInstaller, Test-InstallAware, Read-ProtocolsFromInstallAware, Read-FileExtensionsFromInstallAware, Read-ProductVersionFromInstallAware, Read-ProductNameFromInstallAware, Read-PublisherFromInstallAware, Read-ProductCodeFromInstallAware, Read-ScopeFromInstallAware
