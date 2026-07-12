# SPDX-License-Identifier: MIT
# Static Tarma InstallMate detector. InstallMate's TIZ setup database and file
# archive are proprietary, so this module reports bounded evidence without
# executing setup or guessing values from compressed payload bytes.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:InstallMateMaximumHeaderScanBytes = 67108864
$Script:InstallMateMinimumHeaderBytes = 32

function Get-InstallMateScopeInfo {
  <#
  .SYNOPSIS
    Interpret documented InstallMate install-level behavior from the PE execution level
  #>
  [OutputType([pscustomobject])]
  param ([AllowNull()][string]$RequestedExecutionLevel)

  switch -Regex ($RequestedExecutionLevel) {
    '^(?i:requireAdministrator)$' {
      return [pscustomobject]@{
        Scope = 'machine'; DefaultScope = 'machine'; SupportedScopes = @('machine'); SupportsDualScope = $false
        Confidence = 'high'; Evidence = @('The PE requests requireAdministrator; InstallMate documents this mode as an all-users installation.')
      }
    }
    '^(?i:highestAvailable)$' {
      return [pscustomobject]@{
        Scope = $null; DefaultScope = $null; SupportedScopes = @('user', 'machine'); SupportsDualScope = $true
        Confidence = 'conditional'; Evidence = @('InstallMate highestAvailable installs for all users when elevated and for the current user otherwise.')
      }
    }
    '^(?i:asInvoker)$' {
      return [pscustomobject]@{
        Scope = $null; DefaultScope = 'user'; SupportedScopes = @('user', 'machine'); SupportsDualScope = $true
        Confidence = 'conditional'; Evidence = @('InstallMate asInvoker defaults to the current user, but an explicitly elevated launch can install for all users.')
      }
    }
    default {
      return [pscustomobject]@{
        Scope = $null; DefaultScope = $null; SupportedScopes = @(); SupportsDualScope = $false
        Confidence = 'unknown'; Evidence = @('The InstallMate requested execution level could not be read.')
      }
    }
  }
}

function Get-InstallMateArchiveInfo {
  <#
  .SYNOPSIS
    Locate and validate an embedded Tarma TIZ archive header
  .DESCRIPTION
    InstallMate 9 and later identify internal archives with tiz1 through tiz4.
    Only signatures after the PE image are considered, which avoids matching
    format-name strings compiled into the setup stub.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)

  $File = Get-Item -LiteralPath $Path -Force
  $Layout = Get-PELayout -Path $File.FullName
  $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    $OverlayOffset = Get-PEOverlayOffset -Stream $Stream
    if ($OverlayOffset -le 0 -or $OverlayOffset + $Script:InstallMateMinimumHeaderBytes -gt $Stream.Length) {
      throw 'The InstallMate PE has no package overlay'
    }
    $CertificateDirectory = $Layout.DataDirectories['Certificate']
    $DataEnd = if ($CertificateDirectory -and $CertificateDirectory.Rva -gt $OverlayOffset -and $CertificateDirectory.Rva -le $Stream.Length) {
      [long]$CertificateDirectory.Rva
    } else { [long]$Stream.Length }
  } finally { $Stream.Dispose() }

  $MaximumScanBytes = [Math]::Min($Script:InstallMateMaximumHeaderScanBytes, $DataEnd - $OverlayOffset)
  if ($MaximumScanBytes -lt $Script:InstallMateMinimumHeaderBytes) { throw 'The InstallMate package data is truncated' }
  foreach ($SignatureText in @('tiz4', 'tiz3', 'tiz2', 'tiz1')) {
    $Signature = [Text.Encoding]::ASCII.GetBytes($SignatureText)
    foreach ($Offset in @(Find-BinaryPattern -Path $File.FullName -Pattern $Signature -StartOffset $OverlayOffset -Length $MaximumScanBytes -Maximum 32)) {
      if ($Offset + $Script:InstallMateMinimumHeaderBytes -gt $DataEnd) { continue }
      $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
      try { $Header = Read-BinaryBytes -Stream $Stream -Offset $Offset -Count $Script:InstallMateMinimumHeaderBytes } finally { $Stream.Dispose() }
      $FormatMajor = [BitConverter]::ToUInt16($Header, 4)
      $FormatMinor = [BitConverter]::ToUInt16($Header, 6)
      $Reserved = [BitConverter]::ToUInt64($Header, 8)
      $DeclaredArchiveSize = [BitConverter]::ToUInt64($Header, 16)
      $AvailableArchiveBytes = [uint64]($DataEnd - $Offset)
      if ($FormatMajor -eq 0 -or $FormatMajor -gt 64 -or $FormatMinor -gt 64 -or $Reserved -ne 0) { continue }
      if ($DeclaredArchiveSize -lt $Script:InstallMateMinimumHeaderBytes -or $DeclaredArchiveSize -gt $AvailableArchiveBytes + 64) { continue }

      return [pscustomobject]@{
        Signature            = $SignatureText
        FormatMajor          = [uint16]$FormatMajor
        FormatMinor          = [uint16]$FormatMinor
        FormatVersion        = "$FormatMajor.$FormatMinor"
        ArchiveOffset        = [long]$Offset
        DataEndOffset        = [long]$DataEnd
        AvailableArchiveBytes = $AvailableArchiveBytes
        DeclaredArchiveSize  = $DeclaredArchiveSize
        CertificateOffset    = if ($DataEnd -lt $File.Length) { [long]$DataEnd } else { $null }
        IsComplete           = $DeclaredArchiveSize -le $AvailableArchiveBytes + 64
      }
    }
  }
  throw 'The PE overlay does not contain a supported InstallMate TIZ archive header'
}

function Get-InstallMateInfo {
  <#
  .SYNOPSIS
    Read static InstallMate identity and TIZ archive evidence
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)

  process {
    $File = Get-Item -LiteralPath $Path -Force
    $ArchiveInfo = Get-InstallMateArchiveInfo -Path $File.FullName
    $VersionInfo = [Diagnostics.FileVersionInfo]::GetVersionInfo($File.FullName)
    $VersionStrings = Get-PEVersionStringTable -Path $File.FullName -ErrorAction SilentlyContinue
    $ProductCode = ([string]$VersionStrings.ProductCode).Trim()
    if ([string]::IsNullOrWhiteSpace($ProductCode)) { $ProductCode = $null }
    $PackageCode = ([string]$VersionStrings.PackageCode).Trim()
    if ([string]::IsNullOrWhiteSpace($PackageCode)) { $PackageCode = $null }
    $ExecutionLevel = Get-PERequestedExecutionLevel -Path $File.FullName
    $ScopeInfo = Get-InstallMateScopeInfo -RequestedExecutionLevel $ExecutionLevel
    $DisplayName = ([string]$VersionInfo.ProductName).Trim()
    if ([string]::IsNullOrWhiteSpace($DisplayName)) { $DisplayName = ([string]$VersionInfo.FileDescription).Trim() }
    $RegistryWrites = @()
    $RegistryAssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite $RegistryWrites
    $Warnings = [System.Collections.Generic.List[string]]::new()
    $Warnings.Add('InstallMate PE version resources identify the package, but the proprietary compressed setup database has not been decoded. Visible ARP fields, associations, and scope require VM validation.')
    foreach ($Evidence in $ScopeInfo.Evidence) { $Warnings.Add($Evidence) }

    [pscustomobject]@{
      InstallerType              = 'InstallMate'
      ProductCode                = $ProductCode
      ProductCodeEvidence        = if ($ProductCode) { 'Named StringFileInfo.ProductCode value in the PE version resource' } else { $null }
      PackageCode                = $PackageCode
      PackageName                = $DisplayName
      DisplayName                = $DisplayName
      ProductName                = $DisplayName
      DisplayVersion             = ([string]$VersionInfo.ProductVersion).Trim()
      Publisher                  = ([string]$VersionInfo.CompanyName).Trim()
      FileDescription            = ([string]$VersionInfo.FileDescription).Trim()
      Scope                      = $ScopeInfo.Scope
      DefaultScope               = $ScopeInfo.DefaultScope
      SupportedScopes            = $ScopeInfo.SupportedScopes
      SupportsDualScope          = $ScopeInfo.SupportsDualScope
      ScopeConfidence            = $ScopeInfo.Confidence
      ScopeEvidence              = $ScopeInfo.Evidence
      RequestedExecutionLevel    = $ExecutionLevel
      RegistryWrites             = $RegistryWrites
      RegistryAssociationInfo    = $RegistryAssociationInfo
      Protocols                  = $RegistryAssociationInfo.Protocols
      FileExtensions             = $RegistryAssociationInfo.FileExtensions
      WritesAppsAndFeaturesEntry = $null
      ArchiveInfo                = $ArchiveInfo
      CanExpand                  = $false
      Warnings                   = @($Warnings)
      ParserVersionInfo          = [pscustomobject]@{ Parser = 'Dumplings.PackageModule.InstallMate'; ParserMajor = 2; Sources = @('PE StringFileInfo version resource', 'PE application manifest', 'bounded TIZ archive header', 'InstallMate documented install-level behavior') }
    }
  }
}

function Expand-InstallMateInstaller {
  <#
  .SYNOPSIS
    Reject unsupported InstallMate TIZ extraction without executing setup
  #>
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [string]$Name = '*'
  )
  process {
    $null = $DestinationPath, $Name
    $ArchiveInfo = Get-InstallMateArchiveInfo -Path $Path
    throw "InstallMate $($ArchiveInfo.Signature) setup-database extraction is not implemented; the installer was not executed and no files were written"
  }
}

function Test-InstallMate {
  <#
  .SYNOPSIS
    Test whether a file contains a supported InstallMate TIZ header
  #>
  [OutputType([bool])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { try { $null = Get-InstallMateArchiveInfo -Path $Path; return $true } catch { return $false } }
}

function Read-ProtocolsFromInstallMate {
  <#
  .SYNOPSIS
    Read protocols when explicit InstallMate registry evidence is available
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallMateInfo -Path $Path).Protocols }
}

function Read-FileExtensionsFromInstallMate {
  <#
  .SYNOPSIS
    Read file extensions when explicit InstallMate registry evidence is available
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallMateInfo -Path $Path).FileExtensions }
}

function Read-ProductVersionFromInstallMate {
  <#
  .SYNOPSIS
    Read the InstallMate PE product version
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallMateInfo -Path $Path).DisplayVersion }
}

function Read-ProductNameFromInstallMate {
  <#
  .SYNOPSIS
    Read the InstallMate PE product name
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallMateInfo -Path $Path).DisplayName }
}

function Read-PublisherFromInstallMate {
  <#
  .SYNOPSIS
    Read the InstallMate PE publisher
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallMateInfo -Path $Path).Publisher }
}

function Read-ProductCodeFromInstallMate {
  <#
  .SYNOPSIS
    Read a literal InstallMate uninstall key when available
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallMateInfo -Path $Path).ProductCode }
}

function Read-ScopeFromInstallMate {
  <#
  .SYNOPSIS
    Read InstallMate scope from explicit static evidence
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallMateInfo -Path $Path).Scope }
}

Export-ModuleMember -Function Get-InstallMateInfo, Expand-InstallMateInstaller, Test-InstallMate, Read-ProtocolsFromInstallMate, Read-FileExtensionsFromInstallMate, Read-ProductVersionFromInstallMate, Read-ProductNameFromInstallMate, Read-PublisherFromInstallMate, Read-ProductCodeFromInstallMate, Read-ScopeFromInstallMate
