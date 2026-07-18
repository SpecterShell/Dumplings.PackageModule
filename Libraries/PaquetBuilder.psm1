# SPDX-License-Identifier: MIT
# Static Paquet Builder parser. It identifies the payload and runtime/config
# 7z archives and reads package identity from explicit PE version resources.
# Binary structure consumed here:
#
#   PE overlay -> standard 7z payload archive + standard 7z runtime archive
#   runtime catalog contains pbfprop.dat and PBCore[64].dll
#
# Both ranges begin 37 7A BC AF 27 1C and are validated independently. Catalog
# evidence, not physical order, identifies the runtime. Extraction preserves the
# distinction and enforces archive/path/count/expanded-byte limits.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:PaquetBuilderMaximumArchiveBytes = 17179869184

function Get-PaquetBuilderArchiveData {
  <#
  .SYNOPSIS
    Locate and classify validated Paquet Builder payload and runtime archives
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)

  $File = Get-Item -LiteralPath $Path -Force
  $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)

  # Paquet Builder appends its archives after the mapped PE image; signatures
  # found inside sections are not package candidates.
  try { $OverlayOffset = Get-PEOverlayOffset -Stream $Stream } finally { $Stream.Dispose() }
  if ($OverlayOffset -le 0 -or $OverlayOffset -ge $File.Length) { throw 'The Paquet Builder PE has no package overlay' }

  $Candidates = [System.Collections.Generic.List[object]]::new()

  # Enumerate validated 7z ranges independently and classify by runtime-only
  # catalog markers rather than assuming the first or second physical archive.
  foreach ($Range in @(Get-EmbeddedSevenZipArchiveRange -Path $File.FullName -StartOffset $OverlayOffset -MaximumArchives 16 -MaximumArchiveBytes $Script:PaquetBuilderMaximumArchiveBytes)) {
    $Context = $null
    try {
      $Context = Open-InstallerArchiveRange -Path $File.FullName -Range $Range
      $Entries = @(Get-InstallerArchiveEntry -Archive $Context.Archive | ForEach-Object {
          [pscustomobject]@{ FullName = $_.FullName; Length = $_.Length }
        })
      if ($Entries.Count -eq 0) { continue }
      $IsRuntimeArchive = [bool]($Entries | Where-Object { $_.FullName -ieq 'pbfprop.dat' -or $_.FullName -ieq 'PBCore64.dll' -or $_.FullName -ieq 'PBCore.dll' } | Select-Object -First 1)
      $Candidates.Add([pscustomobject]@{ SourcePath = $File.FullName; Range = $Range; Entries = $Entries; Kind = if ($IsRuntimeArchive) { 'Runtime' } else { 'Payload' } })
    } catch {
      # A damaged or unrelated 7z range does not invalidate later overlay archives.
      continue
    } finally {
      if ($Context) { Close-InstallerArchiveRange -Context $Context }
    }
  }

  # Runtime markers identify the bootstrap engine. Among remaining archives,
  # prefer the largest catalog as the application payload.
  $Runtime = $Candidates | Where-Object Kind -EQ 'Runtime' | Select-Object -First 1
  $Payload = $Candidates | Where-Object Kind -EQ 'Payload' | Sort-Object { $_.Range.Length } -Descending | Select-Object -First 1
  if (-not $Runtime -or -not $Payload) { throw 'The PE overlay does not contain both Paquet Builder payload and runtime archives' }
  return [pscustomobject]@{ Payload = $Payload; Runtime = $Runtime }
}

function Get-PaquetBuilderInfo {
  <#
  .SYNOPSIS
    Read static Paquet Builder identity, scope, and archive evidence
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)

  process {
    $File = Get-Item -LiteralPath $Path -Force
    $ArchiveData = Get-PaquetBuilderArchiveData -Path $File.FullName
    $VersionInfo = [Diagnostics.FileVersionInfo]::GetVersionInfo($File.FullName)
    $ExecutionLevel = Get-PERequestedExecutionLevel -Path $File.FullName

    # Only an explicit requireAdministrator manifest proves machine scope;
    # asInvoker and highestAvailable still require dynamic validation.
    $Scope = if ($ExecutionLevel -ieq 'requireAdministrator') { 'machine' } else { $null }

    # Nested installer candidates are catalog evidence for wrapper analysis and
    # are not executed or assumed to own the visible ARP registration.
    $NestedInstallers = @($ArchiveData.Payload.Entries | Where-Object { $_.FullName -match '(?i)\.(?:exe|msi|msp|msix|appx)$' } | Select-Object -ExpandProperty FullName)
    $RegistryWrites = @()
    $RegistryAssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite $RegistryWrites
    $Warnings = [System.Collections.Generic.List[string]]::new()
    $Warnings.Add('Paquet Builder PE version resources identify the package but do not prove the visible uninstall key. Validate ProductCode and ARP fields in a VM.')
    if ($ExecutionLevel -ieq 'requireAdministrator') {
      $Warnings.Add('Machine scope is inferred from an explicit requireAdministrator application manifest.')
    } else {
      $Warnings.Add('Paquet Builder scope could not be resolved from explicit elevation evidence; validate it in a VM.')
    }
    $Warnings.Add('Built-in /s and /silent handling depends on the Paquet Builder version and project settings. Verify the exact package before authoring InstallerSwitches.')

    [pscustomobject]@{
      InstallerType              = 'Paquet Builder'
      ProductCode                = $null
      PackageName                = ([string]$VersionInfo.ProductName).Trim()
      DisplayName                = ([string]$VersionInfo.ProductName).Trim()
      ProductName                = ([string]$VersionInfo.ProductName).Trim()
      DisplayVersion             = ([string]$VersionInfo.ProductVersion).Trim()
      Publisher                  = ([string]$VersionInfo.CompanyName).Trim()
      FileDescription            = ([string]$VersionInfo.FileDescription).Trim()
      Scope                      = $Scope
      SupportedScopes            = if ($Scope) { @($Scope) } else { @() }
      RequestedExecutionLevel    = $ExecutionLevel
      SupportsSilentInstallation = $null
      RegistryWrites             = $RegistryWrites
      RegistryAssociationInfo    = $RegistryAssociationInfo
      Protocols                  = $RegistryAssociationInfo.Protocols
      FileExtensions             = $RegistryAssociationInfo.FileExtensions
      WritesAppsAndFeaturesEntry = $null
      PayloadFiles               = @($ArchiveData.Payload.Entries.FullName)
      RuntimeFiles               = @($ArchiveData.Runtime.Entries.FullName)
      NestedInstallerFiles       = $NestedInstallers
      PayloadArchiveRange        = $ArchiveData.Payload.Range
      RuntimeArchiveRange        = $ArchiveData.Runtime.Range
      Warnings                   = @($Warnings)
      ParserVersionInfo          = [pscustomobject]@{ Parser = 'Dumplings.PackageModule.PaquetBuilder'; ParserMajor = 1; Sources = @('PE version resource', 'PE application manifest', 'validated payload and runtime 7z archives') }
    }
  }
}

function Expand-PaquetBuilderInstaller {
  <#
  .SYNOPSIS
    Extract Paquet Builder payload or runtime files without executing them
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER DestinationPath
    Destination path for bounded extraction or decoded output; payload-relative names are resolved beneath this path.
  .PARAMETER Name
    Exact name or wildcard used to select format records or payload entries.
  .PARAMETER ArchiveKind
    Detected format variant controlling version-specific parsing rules.
  .PARAMETER MaximumExpandedBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  [OutputType([System.IO.FileInfo[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [string]$Name = '*',
    [ValidateSet('Payload', 'Runtime', 'All')][string]$ArchiveKind = 'Payload',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 17179869184
  )

  process {
    $ArchiveData = Get-PaquetBuilderArchiveData -Path $Path
    if ([string]::IsNullOrWhiteSpace($DestinationPath)) { $DestinationPath = Join-Path ([IO.Path]::GetTempPath()) ("Dumplings-PaquetBuilder-$([guid]::NewGuid().ToString('N'))") }
    $null = New-Item -Path $DestinationPath -ItemType Directory -Force

    # Select payload, runtime, or both explicitly so helper binaries are not
    # mixed into application analysis unless requested.
    $Selected = switch ($ArchiveKind) {
      'Payload' { @($ArchiveData.Payload) }
      'Runtime' { @($ArchiveData.Runtime) }
      'All' { @($ArchiveData.Payload, $ArchiveData.Runtime) }
    }
    $Written = 0L
    $Result = [System.Collections.Generic.List[System.IO.FileInfo]]::new()

    # Keep each archive in its own bounded context and account declared output
    # across all selected archives before resolving traversal-safe paths.
    foreach ($ArchiveRecord in $Selected) {
      $Context = Open-InstallerArchiveRange -Path $ArchiveRecord.SourcePath -Range $ArchiveRecord.Range
      try {
        foreach ($Entry in Get-InstallerArchiveEntry -Archive $Context.Archive) {
          if (-not (Test-ExtractionPattern -Path $Entry.FullName -Pattern $Name)) { continue }
          $Written += $Entry.Length
          if ($Written -gt $MaximumExpandedBytes) { throw 'Paquet Builder extraction exceeds the configured output limit' }
          $RelativePath = if ($ArchiveKind -eq 'All') { Join-Path $ArchiveRecord.Kind $Entry.FullName } else { $Entry.FullName }
          $OutputPath = Resolve-SafeExtractionPath -DestinationPath $DestinationPath -RelativePath $RelativePath
          $Result.Add((Export-InstallerArchiveEntry -Entry $Entry -DestinationPath $OutputPath -MaximumBytes $MaximumExpandedBytes))
        }
      } finally { Close-InstallerArchiveRange -Context $Context }
    }
    if ($Result.Count -eq 0) { throw "No Paquet Builder files matched '$Name'" }
    return $Result.ToArray()
  }
}

function Test-PaquetBuilder {
  <#
  .SYNOPSIS
    Test whether a file contains parseable Paquet Builder archives
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([bool])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { try { $null = Get-PaquetBuilderInfo -Path $Path; return $true } catch { return $false } }
}

function Read-ProtocolsFromPaquetBuilder {
  <#
  .SYNOPSIS
    Read literal URL protocol names from Paquet Builder registry evidence
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-PaquetBuilderInfo -Path $Path).Protocols }
}

function Read-FileExtensionsFromPaquetBuilder {
  <#
  .SYNOPSIS
    Read literal file extensions from Paquet Builder registry evidence
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-PaquetBuilderInfo -Path $Path).FileExtensions }
}

function Read-ProductVersionFromPaquetBuilder {
  <#
  .SYNOPSIS
    Read the Paquet Builder PE product version
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-PaquetBuilderInfo -Path $Path).DisplayVersion }
}

function Read-ProductNameFromPaquetBuilder {
  <#
  .SYNOPSIS
    Read the Paquet Builder PE product name
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-PaquetBuilderInfo -Path $Path).DisplayName }
}

function Read-PublisherFromPaquetBuilder {
  <#
  .SYNOPSIS
    Read the Paquet Builder PE publisher
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-PaquetBuilderInfo -Path $Path).Publisher }
}

function Read-ProductCodeFromPaquetBuilder {
  <#
  .SYNOPSIS
    Read a literal Paquet Builder uninstall key when available
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-PaquetBuilderInfo -Path $Path).ProductCode }
}

function Read-ScopeFromPaquetBuilder {
  <#
  .SYNOPSIS
    Read Paquet Builder scope from explicit elevation evidence
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-PaquetBuilderInfo -Path $Path).Scope }
}

Export-ModuleMember -Function Get-PaquetBuilderInfo, Expand-PaquetBuilderInstaller, Test-PaquetBuilder, Read-ProtocolsFromPaquetBuilder, Read-FileExtensionsFromPaquetBuilder, Read-ProductVersionFromPaquetBuilder, Read-ProductNameFromPaquetBuilder, Read-PublisherFromPaquetBuilder, Read-ProductCodeFromPaquetBuilder, Read-ScopeFromPaquetBuilder
