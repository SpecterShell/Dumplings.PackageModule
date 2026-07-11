# SPDX-License-Identifier: MIT
# Structure references: https://github.com/dotnet/dotnet
# Static architecture policy shared by executable and DLL portable analysis.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

function Resolve-PortablePEMachineArchitecture {
  <#
  .SYNOPSIS
    Convert IMAGE_FILE_HEADER.Machine to a concrete WinGet architecture
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][uint16]$Machine)
  switch ($Machine) {
    0x014C { [pscustomobject]@{ Architecture = 'x86'; IsSupported = $true; IsArm32 = $false }; break }
    0x8664 { [pscustomobject]@{ Architecture = 'x64'; IsSupported = $true; IsArm32 = $false }; break }
    0xAA64 { [pscustomobject]@{ Architecture = 'arm64'; IsSupported = $true; IsArm32 = $false }; break }
    0x01C0 { [pscustomobject]@{ Architecture = 'arm'; IsSupported = $false; IsArm32 = $true }; break }
    0x01C2 { [pscustomobject]@{ Architecture = 'arm'; IsSupported = $false; IsArm32 = $true }; break }
    0x01C4 { [pscustomobject]@{ Architecture = 'arm'; IsSupported = $false; IsArm32 = $true }; break }
    default { [pscustomobject]@{ Architecture = $null; IsSupported = $false; IsArm32 = $false } }
  }
}

function Get-PEFileKind {
  <#
  .SYNOPSIS
    Classify a PE image from IMAGE_FILE_HEADER.Characteristics
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][psobject]$Layout)
  if (($Layout.Characteristics -band 0x2000) -ne 0) { return 'Dll' }
  if (($Layout.Characteristics -band 0x0002) -ne 0) { return 'Executable' }
  return 'UnknownPE'
}

function Get-PortableAnyCpuSupportedArchitecture {
  <#
  .SYNOPSIS
    Resolve concrete WinGet architectures for managed AnyCPU binaries
  #>
  [OutputType([string[]])]
  param (
    [AllowNull()][psobject]$TargetFramework,
    [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[string]]$Warnings
  )
  if (-not $TargetFramework) {
    $Warnings.Add('Managed AnyCPU target framework metadata was not found; reporting x86 and x64 only and requiring manual review before adding arm64.')
    return @('x86', 'x64')
  }
  if ($TargetFramework.FrameworkName -eq '.NETFramework') {
    if ($TargetFramework.VersionObject -ge [version]'4.8.1') { return @('x86', 'x64', 'arm64') }
    return @('x86', 'x64')
  }
  if ($TargetFramework.FrameworkName -in @('.NETCoreApp', '.NETStandard')) { return @('x86', 'x64', 'arm64') }
  $Warnings.Add("Managed AnyCPU target framework '$($TargetFramework.RawValue)' is not recognized; reporting x86 and x64 only and requiring manual review before adding arm64.")
  return @('x86', 'x64')
}

Export-ModuleMember -Function Resolve-PortablePEMachineArchitecture, Get-PEFileKind, Get-PortableAnyCpuSupportedArchitecture
