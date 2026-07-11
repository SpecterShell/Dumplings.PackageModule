# SPDX-License-Identifier: MIT
# Static DeployMaster parser. Current DeployMaster packages use a transformed
# LZMA-like overlay; identity is read from PE resources without running setup.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

function Get-DeployMasterOverlayInfo {
  <#
  .SYNOPSIS
    Validate the DeployMaster transformed LZMA-like overlay header
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)

  $File = Get-Item -LiteralPath $Path -Force
  $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    $OverlayOffset = Get-PEOverlayOffset -Stream $Stream
    if ($OverlayOffset -le 0 -or $OverlayOffset + 14 -gt $Stream.Length) { throw 'The DeployMaster PE has no package overlay' }
    $Properties = Read-BinaryBytes -Stream $Stream -Offset $OverlayOffset -Count 5
    $DictionarySize = [uint32][BitConverter]::ToUInt32($Properties, 1)
    $RawSize = [uint64](Read-BinaryInteger -Stream $Stream -Offset ($OverlayOffset + 5) -Size 8)
    $FirstPayloadByte = [byte](Read-BinaryInteger -Stream $Stream -Offset ($OverlayOffset + 13) -Size 1)
    if ($Properties[0] -gt 224 -or $DictionarySize -lt 65536 -or ($DictionarySize -band ($DictionarySize - 1)) -ne 0 -or $RawSize -eq 0) {
      throw 'The DeployMaster overlay header is invalid'
    }
    $HasTransformFlag = ($RawSize -band 0x8000000000000000) -ne 0
    [pscustomobject]@{
      OverlayOffset          = [long]$OverlayOffset
      OverlayLength          = [long]($File.Length - $OverlayOffset)
      LzmaPropertyByte       = [byte]$Properties[0]
      DictionarySize        = $DictionarySize
      RawSizeField          = $RawSize
      DeclaredSize          = [uint64]($RawSize -band 0x7FFFFFFFFFFFFFFF)
      HasTransformFlag      = $HasTransformFlag
      FirstPayloadByte      = $FirstPayloadByte
      IsDirectLzmaStream    = -not $HasTransformFlag -and $FirstPayloadByte -eq 0
    }
  } finally { $Stream.Dispose() }
}

function Get-DeployMasterInfo {
  <#
  .SYNOPSIS
    Read static DeployMaster PE identity and overlay evidence
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)

  process {
    $File = Get-Item -LiteralPath $Path -Force
    $Overlay = Get-DeployMasterOverlayInfo -Path $File.FullName
    $VersionInfo = [Diagnostics.FileVersionInfo]::GetVersionInfo($File.FullName)
    $ProductName = ([string]$VersionInfo.ProductName).Trim()
    $DisplayName = ([string]$VersionInfo.FileDescription).Trim()
    if ([string]::IsNullOrWhiteSpace($DisplayName)) { $DisplayName = $ProductName }
    $HasDeployMasterIdentity = $ProductName -match '(?i)DeployMaster' -or ([string]$VersionInfo.FileDescription) -match '(?i)DeployMaster'
    if (-not $HasDeployMasterIdentity -and -not $Overlay.HasTransformFlag) {
      throw 'The overlay resembles an LZMA stream, but PE metadata and transform flags do not identify DeployMaster'
    }
    if (-not $HasDeployMasterIdentity) {
      # Overlay validation is the primary detector, but a conflicting explicit
      # product resource should be surfaced rather than silently ignored.
      $IdentityWarning = "PE product metadata identifies '$ProductName' rather than the DeployMaster runtime."
    }
    $ExecutionLevel = Get-PERequestedExecutionLevel -Path $File.FullName
    $RegistryWrites = @()
    $RegistryAssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite $RegistryWrites
    $Warnings = [System.Collections.Generic.List[string]]::new()
    if ($IdentityWarning) { $Warnings.Add($IdentityWarning) }
    $Warnings.Add('DeployMaster PE version resources identify the package but do not prove the visible uninstall key or scope; validate both in a VM.')
    if ($Overlay.HasTransformFlag) { $Warnings.Add('The DeployMaster payload uses a transformed LZMA-like stream. Static expansion requires controlled builder comparison before the transform can be implemented safely.') }

    [pscustomobject]@{
      InstallerType              = 'DeployMaster'
      ProductCode                = $null
      PackageName                = $DisplayName
      DisplayName                = $DisplayName
      ProductName                = $DisplayName
      DisplayVersion             = ([string]$VersionInfo.ProductVersion).Trim()
      Publisher                  = ([string]$VersionInfo.CompanyName).Trim()
      RuntimeProductName         = $ProductName
      FileDescription            = ([string]$VersionInfo.FileDescription).Trim()
      Scope                      = $null
      SupportedScopes            = @()
      RequestedExecutionLevel    = $ExecutionLevel
      RegistryWrites             = $RegistryWrites
      RegistryAssociationInfo    = $RegistryAssociationInfo
      Protocols                  = $RegistryAssociationInfo.Protocols
      FileExtensions             = $RegistryAssociationInfo.FileExtensions
      WritesAppsAndFeaturesEntry = $null
      OverlayInfo                = $Overlay
      CanExpand                  = [bool]$Overlay.IsDirectLzmaStream
      Warnings                   = @($Warnings)
      ParserVersionInfo          = [pscustomobject]@{ Parser = 'Dumplings.PackageModule.DeployMaster'; ParserMajor = 1; Sources = @('PE version resource', 'PE application manifest', 'validated transformed LZMA-like overlay header') }
    }
  }
}

function Expand-DeployMasterInstaller {
  <#
  .SYNOPSIS
    Expand a directly decodable DeployMaster payload when supported
  #>
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [string]$Name = '*',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 17179869184
  )

  process {
    # Keep the extraction surface compatible while transformed payload support
    # is intentionally rejected before any destination is created.
    $null = $DestinationPath, $Name, $MaximumExpandedBytes
    $Overlay = Get-DeployMasterOverlayInfo -Path $Path
    if ($Overlay.HasTransformFlag -or -not $Overlay.IsDirectLzmaStream) {
      throw 'This DeployMaster payload uses an unsupported transformed LZMA-like stream; the installer was not executed and no files were written'
    }
    throw 'Direct DeployMaster LZMA payload expansion is not implemented for this format revision'
  }
}

function Test-DeployMaster {
  <#
  .SYNOPSIS
    Test whether a file contains a DeployMaster overlay
  #>
  [OutputType([bool])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { try { $null = Get-DeployMasterInfo -Path $Path; return $true } catch { return $false } }
}

function Read-ProtocolsFromDeployMaster {
  <#
  .SYNOPSIS
    Read literal URL protocol names from DeployMaster registry evidence
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-DeployMasterInfo -Path $Path).Protocols }
}

function Read-FileExtensionsFromDeployMaster {
  <#
  .SYNOPSIS
    Read literal file extensions from DeployMaster registry evidence
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-DeployMasterInfo -Path $Path).FileExtensions }
}

function Read-ProductVersionFromDeployMaster {
  <#
  .SYNOPSIS
    Read the DeployMaster PE product version
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-DeployMasterInfo -Path $Path).DisplayVersion }
}

function Read-ProductNameFromDeployMaster {
  <#
  .SYNOPSIS
    Read the DeployMaster package display name
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-DeployMasterInfo -Path $Path).DisplayName }
}

function Read-PublisherFromDeployMaster {
  <#
  .SYNOPSIS
    Read the DeployMaster PE publisher
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-DeployMasterInfo -Path $Path).Publisher }
}

function Read-ProductCodeFromDeployMaster {
  <#
  .SYNOPSIS
    Read a literal DeployMaster uninstall key when available
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-DeployMasterInfo -Path $Path).ProductCode }
}

function Read-ScopeFromDeployMaster {
  <#
  .SYNOPSIS
    Read DeployMaster scope when explicit static evidence is available
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-DeployMasterInfo -Path $Path).Scope }
}

Export-ModuleMember -Function Get-DeployMasterInfo, Expand-DeployMasterInstaller, Test-DeployMaster, Read-ProtocolsFromDeployMaster, Read-FileExtensionsFromDeployMaster, Read-ProductVersionFromDeployMaster, Read-ProductNameFromDeployMaster, Read-PublisherFromDeployMaster, Read-ProductCodeFromDeployMaster, Read-ScopeFromDeployMaster
