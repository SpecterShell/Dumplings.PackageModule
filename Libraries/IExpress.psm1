# SPDX-License-Identifier: Apache-2.0
# IExpress/WExtract binary structure consumed here:
#
#   PE/.rsrc
#   +-- RUNPROGRAM, POSTRUNPROGRAM, ADMQCMD, USRQCMD text resources
#   `-- CABINET* -> 4D 53 43 46 ("MSCF") cabinets and payload catalogs
#
# Text may be UTF-16LE, code page 1252, or BOM-marked. The selected command maps
# to a catalog entry and arguments; resource or CAB order alone does not.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

function ConvertFrom-IExpressResourceText {
  <#
  .SYNOPSIS
    Decode a bounded IExpress text resource
  .PARAMETER Bytes
    Bounded format record or payload bytes interpreted by this function; the input array is not modified.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][byte[]]$Bytes)

  # Prefer an explicit UTF-16LE BOM, then use the high NUL-byte density emitted
  # by unmarked wide resources before falling back to the historical ANSI code page.
  if ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFF -and $Bytes[1] -eq 0xFE) {
    return [Text.Encoding]::Unicode.GetString($Bytes, 2, $Bytes.Length - 2).TrimEnd([char]0)
  }
  $ZeroCount = @($Bytes | Where-Object { $_ -eq 0 }).Count
  if ($Bytes.Length -ge 4 -and $ZeroCount -gt ($Bytes.Length / 3)) {
    return [Text.Encoding]::Unicode.GetString($Bytes).TrimEnd([char]0)
  }
  return [Text.Encoding]::GetEncoding(1252).GetString($Bytes).TrimEnd([char]0)
}

function Get-IExpressInfo {
  <#
  .SYNOPSIS
    Read configured commands and nested cabinet payloads from IExpress
  .PARAMETER Path
    The path to the IExpress/WExtract executable
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)

  process {
    $Installer = Get-Item -LiteralPath $Path -Force
    $Resources = @(Get-PEResourceInfo -Path $Installer.FullName)
    $ResourceNames = @($Resources | Where-Object Name | ForEach-Object { $_.Name.ToUpperInvariant() })
    $OriginalName = [Diagnostics.FileVersionInfo]::GetVersionInfo($Installer.FullName).OriginalFilename

    # Accept either the canonical WExtract version identity or the paired
    # CABINET/RUNPROGRAM resources used by rebuilt IExpress stubs.
    $IsWExtract = $OriginalName -match '^(?i)wextract(?:\.exe)?$' -or
    ($ResourceNames -contains 'CABINET' -and $ResourceNames -contains 'RUNPROGRAM')
    if (-not $IsWExtract) { throw 'The file does not contain the expected IExpress/WExtract resources.' }

    $TextResourceNames = @(
      'RUNPROGRAM', 'POSTRUNPROGRAM', 'ADMQCMD', 'USRQCMD', 'ADMINQUIETINSTCMD',
      'USERQUIETINSTCMD', 'INSTALLPROMPT', 'DISPLAYLICENSE', 'FINISHMESSAGE', 'TARGETNAME'
    )
    $Configuration = [ordered]@{}

    # Decode only known configuration resources; arbitrary resource text must
    # not become command-line evidence.
    foreach ($Resource in $Resources) {
      if (-not $Resource.Name -or $Resource.Name.ToUpperInvariant() -notin $TextResourceNames) { continue }
      $Value = ConvertFrom-IExpressResourceText -Bytes (Read-PEResourceData -Resource $Resource -MaximumBytes 1048576)
      $Configuration[$Resource.Name.ToUpperInvariant()] = if ($Value.Trim() -eq '<None>') { $null } else { $Value }
    }

    $CabinetResources = @($Resources | Where-Object { $_.Name -and $_.Name.ToUpperInvariant() -like 'CABINET*' })
    if ($CabinetResources.Count -eq 0) { throw 'The IExpress cabinet resource was not found.' }
    $CabinetEvidence = [Collections.Generic.List[psobject]]::new()
    $NestedFiles = [Collections.Generic.List[string]]::new()

    # Export each CAB resource to a temporary bounded file because the cabinet
    # reader requires a path, then retain only catalog metadata.
    foreach ($CabinetResource in $CabinetResources) {
      $CabinetPath = New-TempFile
      try {
        $null = Export-PEResourceData -Resource $CabinetResource -DestinationPath $CabinetPath -MaximumBytes 1073741824
        $Entries = @(Get-CabinetEntry -Path $CabinetPath)
        foreach ($Entry in $Entries) { $NestedFiles.Add($Entry.FullName) }
        $CabinetEvidence.Add([pscustomobject]@{
            ResourceName = $CabinetResource.Name
            Offset       = $CabinetResource.Offset
            Size         = $CabinetResource.Size
            Entries      = @($Entries | Select-Object FullName, Length)
          })
      } finally {
        Remove-Item -LiteralPath $CabinetPath -Force -ErrorAction SilentlyContinue
      }
    }

    $Commands = [Collections.Generic.List[psobject]]::new()

    # Resolve configured commands against the combined CAB catalogs. Physical
    # resource order does not identify which nested executable WExtract launches.
    foreach ($Name in @('RUNPROGRAM', 'POSTRUNPROGRAM', 'ADMQCMD', 'USRQCMD', 'ADMINQUIETINSTCMD', 'USERQUIETINSTCMD')) {
      if (-not $Configuration[$Name]) { continue }
      $Commands.Add([pscustomobject]@{
          Source  = $Name
          Command = Resolve-BootstrapperCommand -CommandLine $Configuration[$Name] -CandidatePath @($NestedFiles)
        })
    }

    [pscustomobject]@{
      Path             = $Installer.FullName
      Format           = 'IExpress'
      OriginalFilename = $OriginalName
      Configuration    = [pscustomobject]$Configuration
      Commands         = @($Commands)
      ExecutedPayloads = @($Commands | Where-Object { $_.Command.ExecutedPayload } | ForEach-Object { $_.Command.ExecutedPayload } | Select-Object -Unique)
      CabinetResources = @($CabinetEvidence)
      NestedFiles      = @($NestedFiles | Select-Object -Unique)
      Warnings         = @(
        if ($Commands.Count -eq 0) { 'No IExpress execution command resource was found.' }
        foreach ($Command in $Commands) {
          if (-not $Command.Command.IsResolved) { "The $($Command.Source) command did not resolve to an embedded cabinet entry: $($Command.Command.CommandLine)" }
        }
      )
    }
  }
}

function Expand-IExpressInstaller {
  <#
  .SYNOPSIS
    Expand selected files from an IExpress cabinet resource without executing it
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER DestinationPath
    Destination path for bounded extraction or decoded output; payload-relative names are resolved beneath this path.
  .PARAMETER Name
    Exact name or wildcard used to select format records or payload entries.
  .PARAMETER MaximumExpandedBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [string]$Name = '*',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 4294967296
  )
  process {
    if (-not $DestinationPath) { $DestinationPath = New-TempFolder }
    $Resources = @(Get-PEResourceInfo -Path (Get-Item -LiteralPath $Path -Force).FullName)
    $CabinetResources = @($Resources | Where-Object { $_.Name -and $_.Name.ToUpperInvariant() -like 'CABINET*' })
    if ($CabinetResources.Count -eq 0) { throw 'The IExpress cabinet resource was not found.' }

    # Preserve cabinet boundaries and extraction limits while applying the same
    # caller pattern to each resource catalog.
    foreach ($CabinetResource in $CabinetResources) {
      $CabinetPath = New-TempFile
      try {
        $null = Export-PEResourceData -Resource $CabinetResource -DestinationPath $CabinetPath -MaximumBytes 1073741824
        Export-CabinetEntry -Path $CabinetPath -DestinationPath $DestinationPath -Name $Name -MaximumExpandedBytes $MaximumExpandedBytes
      } finally {
        Remove-Item -LiteralPath $CabinetPath -Force -ErrorAction SilentlyContinue
      }
    }
  }
}

function Test-IExpress {
  <#
  .SYNOPSIS
    Test whether a file is an IExpress/WExtract package
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([bool])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process {
    try { $null = Get-IExpressInfo -Path $Path; return $true } catch { return $false }
  }
}

Export-ModuleMember -Function ConvertFrom-IExpressResourceText, Get-IExpressInfo, Expand-IExpressInstaller, Test-IExpress
