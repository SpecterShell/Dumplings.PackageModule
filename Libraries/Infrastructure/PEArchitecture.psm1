# SPDX-License-Identifier: Apache-2.0
# Structure references: https://github.com/dotnet/dotnet

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# Concrete package architectures only; ARM32 and neutral are not recommended for PE payloads.
$Script:PortableWinGetArchitectures = @('x86', 'x64', 'arm64')

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

function Read-ProductVersionFromExe {
  <#
  .SYNOPSIS
    Read the product version of the EXE file
  .DESCRIPTION
    Returns the ProductVersion resource verbatim. The value may be a .NET informational version containing prerelease, build-metadata, or source-revision suffixes such as +abcdef. Compare it with publisher and ARP version evidence before assigning it to a WinGet PackageVersion; this function does not normalize or discard suffixes.
  .PARAMETER Path
    The path to the EXE file
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the EXE file')]
    [string]$Path
  )

  process {
    # Obtain the absolute path of the file
    $Path = (Get-Item -Path $Path -Force).FullName

    [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path).ProductVersion.Trim()
  }
}

function Read-ProductVersionRawFromExe {
  <#
  .SYNOPSIS
    Read the raw product version of the EXE file
  .PARAMETER Path
    The path to the EXE file
  #>
  [OutputType([version])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the EXE file')]
    [string]$Path
  )

  process {
    # Obtain the absolute path of the file
    $Path = (Get-Item -Path $Path -Force).FullName

    [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path).ProductVersionRaw
  }
}

function Read-FileVersionFromExe {
  <#
  .SYNOPSIS
    Read the file version property of the EXE file
  .PARAMETER Path
    The path to the EXE file
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the EXE file')]
    [string]$Path
  )

  process {
    # Obtain the absolute path of the file
    $Path = (Get-Item -Path $Path -Force).FullName

    [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path).FileVersion.Trim()
  }
}

function Read-FileVersionRawFromExe {
  <#
  .SYNOPSIS
    Read the raw file version of the EXE file
  .PARAMETER Path
    The path to the EXE file
  #>
  [OutputType([version])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the EXE file')]
    [string]$Path
  )

  process {
    # Obtain the absolute path of the file
    $Path = (Get-Item -Path $Path -Force).FullName

    [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path).FileVersionRaw
  }
}

function Get-PEArchitectureInfo {
  <#
  .SYNOPSIS
    Statically determine concrete WinGet architecture candidates for a PE file
  .DESCRIPTION
    The function reads PE and CLR headers without executing the binary. It never recommends
    Architecture: neutral because WinGet neutral is only valid for packages without binaries.
  .PARAMETER Path
    The PE file path
  .PARAMETER RelatedFile
    Related PE files, usually adjacent native DLLs, that can narrow a managed PE file
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The PE file path')]
    [string]$Path,

    [Parameter(HelpMessage = 'Related PE files, usually adjacent native DLLs, that can narrow a managed PE file')]
    [string[]]$RelatedFile = @()
  )

  process {
    $File = Get-Item -LiteralPath $Path -Force
    $Warnings = [System.Collections.Generic.List[string]]::new()
    $Layout = Get-PELayout -Path $File.FullName
    if (-not $Layout) {
      throw "The file is not a valid PE file: $($File.FullName)"
    }

    # PE machine and CLR flags jointly determine architecture. A managed x86
    # machine header can represent AnyCPU when IL-only and no native entry point.
    $FileKind = Get-PEFileKind -Layout $Layout
    $MachineInfo = Resolve-PortablePEMachineArchitecture -Machine $Layout.Machine
    $ClrHeader = Get-PEClrHeader -Path $File.FullName
    $TargetFramework = if ($ClrHeader) { Get-PEManagedTargetFramework -Path $File.FullName } else { $null }
    $IsManaged = $null -ne $ClrHeader
    $IsAnyCpu = $false
    $PreferredArchitecture = $null
    $SupportedArchitectures = @()

    if ($MachineInfo.IsArm32) {
      $Warnings.Add('ARM32 PE file detected. ARM32 is intentionally excluded from Dumplings WinGet architecture recommendations.')
    } elseif (-not $MachineInfo.IsSupported) {
      $Warnings.Add("Unsupported or unknown PE machine value 0x$($Layout.Machine.ToString('X4')) was found.")
    } elseif ($IsManaged) {
      if ($ClrHeader.Requires32Bit) {
        $SupportedArchitectures = @('x86')
        $PreferredArchitecture = 'x86'
      } elseif ($Layout.Machine -eq 0x014C -and $ClrHeader.ILOnly -and -not $ClrHeader.NativeEntryPoint) {
        $IsAnyCpu = $true
        $SupportedArchitectures = @(Get-PortableAnyCpuSupportedArchitecture -TargetFramework $TargetFramework -Warnings $Warnings)
        if ($ClrHeader.Prefers32Bit) { $PreferredArchitecture = 'x86' }
      } else {
        $SupportedArchitectures = @($MachineInfo.Architecture)
        $PreferredArchitecture = $MachineInfo.Architecture
      }
    } else {
      $SupportedArchitectures = @($MachineInfo.Architecture)
      $PreferredArchitecture = $MachineInfo.Architecture
    }

    $SupportedArchitectures = @($SupportedArchitectures | Where-Object { $_ -in $Script:PortableWinGetArchitectures } | Sort-Object -Unique)
    # Adjacent native DLLs can narrow AnyCPU deployment support, but conflicting
    # related architectures are warnings rather than arbitrary selection.
    $RelatedArchitectureInfo = foreach ($Related in @($RelatedFile | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
      try {
        Get-PEArchitectureInfo -Path $Related
      } catch {
        [pscustomobject]@{
          Path                           = (Get-Item -LiteralPath $Related -Force -ErrorAction SilentlyContinue).FullName
          RecommendedWinGetArchitecture  = $null
          RecommendedWinGetArchitectures = @()
          SupportedArchitectures         = @()
          Diagnostics                    = @(ConvertTo-InstallerDiagnostic -InputObject @($_.Exception.Message) -Source 'PEArchitecture' -Kind Incomplete -Areas Metadata -AffectedFields Architecture)
        }
      }
    }
    $RelatedArchitectureInfo = @($RelatedArchitectureInfo)
    $RelatedConcreteArchitectures = @($RelatedArchitectureInfo | ForEach-Object -Process {
        if ($_.RecommendedWinGetArchitecture) { $_.RecommendedWinGetArchitecture }
      } | Sort-Object -Unique)

    if ($RelatedConcreteArchitectures.Count -eq 1) {
      $RelatedArchitecture = $RelatedConcreteArchitectures[0]
      if ($RelatedArchitecture -in $SupportedArchitectures) {
        if ($SupportedArchitectures.Count -gt 1) {
          $Warnings.Add("Related PE files narrow this portable executable to $RelatedArchitecture.")
        }
        $SupportedArchitectures = @($RelatedArchitecture)
      } else {
        $Warnings.Add("Related PE files are $RelatedArchitecture, which conflicts with executable architectures: $($SupportedArchitectures -join ', ').")
      }
    } elseif ($RelatedConcreteArchitectures.Count -gt 1) {
      $Warnings.Add("Related PE files contain multiple concrete architectures: $($RelatedConcreteArchitectures -join ', '). Inspect package layout manually before authoring WinGet installers.")
    }

    $RecommendedWinGetArchitecture = if ($SupportedArchitectures.Count -eq 1) { $SupportedArchitectures[0] } else { $null }
    if ($SupportedArchitectures.Count -gt 1) {
      $Warnings.Add("This binary supports multiple concrete architectures: $($SupportedArchitectures -join ', '). Do not use Architecture: neutral; author concrete WinGet installer entries instead.")
    }

    [pscustomobject]@{
      Path                           = $File.FullName
      IsPE                           = $true
      FileKind                       = $FileKind
      IsManaged                      = $IsManaged
      IsAnyCpu                       = $IsAnyCpu
      Machine                        = ('0x{0:X4}' -f $Layout.Machine)
      MachineName                    = $Layout.MachineName
      NativeArchitecture             = $MachineInfo.Architecture
      OptionalHeaderFormat           = $Layout.OptionalHeaderFormat
      ClrFlags                       = if ($ClrHeader) {
        [pscustomobject]@{
          ILOnly           = $ClrHeader.ILOnly
          Requires32Bit    = $ClrHeader.Requires32Bit
          Prefers32Bit     = $ClrHeader.Prefers32Bit
          NativeEntryPoint = $ClrHeader.NativeEntryPoint
        }
      } else {
        $null
      }
      TargetFramework                = $TargetFramework
      SupportedArchitectures         = $SupportedArchitectures
      PreferredArchitecture          = $PreferredArchitecture
      RecommendedWinGetArchitecture  = $RecommendedWinGetArchitecture
      RecommendedWinGetArchitectures = $SupportedArchitectures
      RelatedArchitectureInfo        = $RelatedArchitectureInfo
      Diagnostics                    = @(ConvertTo-InstallerDiagnostic -InputObject @($Warnings) -Source 'PEArchitecture' -Kind Incomplete -Areas Metadata -AffectedFields Architecture)
    }
  }
}

function Read-ArchitectureFromPE {
  <#
  .SYNOPSIS
    Read concrete WinGet architecture candidates from a PE file
  .PARAMETER Path
    The PE file path
  .PARAMETER RelatedFile
    Related PE files that can narrow the PE architecture
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The PE file path')]
    [string]$Path,

    [Parameter(HelpMessage = 'Related PE files that can narrow the PE architecture')]
    [string[]]$RelatedFile = @()
  )

  process {
    $Info = Get-PEArchitectureInfo -Path $Path -RelatedFile $RelatedFile
    if ($Info.RecommendedWinGetArchitecture) {
      $Info.RecommendedWinGetArchitecture
    } else {
      $Info.RecommendedWinGetArchitectures
    }
  }
}

function Test-PEArchitecture {
  <#
  .SYNOPSIS
    Test whether a PE file supports a concrete WinGet architecture
  .PARAMETER Path
    The PE file path
  .PARAMETER Architecture
    The concrete WinGet architecture to test
  .PARAMETER RelatedFile
    Related PE files that can narrow the executable architecture
  #>
  [OutputType([bool])]
  param (
    [Parameter(Position = 0, Mandatory, HelpMessage = 'The PE file path')]
    [string]$Path,

    [Parameter(Mandatory, HelpMessage = 'The concrete WinGet architecture to test')]
    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture,

    [Parameter(HelpMessage = 'Related PE files that can narrow the executable architecture')]
    [string[]]$RelatedFile = @()
  )

  $Info = Get-PEArchitectureInfo -Path $Path -RelatedFile $RelatedFile
  $Architecture -in @($Info.RecommendedWinGetArchitectures)
}

function Get-PEFileIfValid {
  <#
  .SYNOPSIS
    Resolve a path only when it points to a valid PE file
  .PARAMETER Path
    The path to test
  #>
  [OutputType([System.IO.FileInfo])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to test')]
    [string]$Path
  )

  try {
    $File = Get-Item -LiteralPath $Path -Force
    if ($File -isnot [System.IO.FileInfo]) { return $null }
    if (Get-PELayout -Path $File.FullName) { return $File }
  } catch {
    return $null
  }

  return $null
}

Export-ModuleMember -Function Resolve-PortablePEMachineArchitecture, Get-PEFileKind, Get-PortableAnyCpuSupportedArchitecture, Read-ProductVersionFromExe, Read-ProductVersionRawFromExe, Read-FileVersionFromExe, Read-FileVersionRawFromExe, Get-PEArchitectureInfo, Read-ArchitectureFromPE, Test-PEArchitecture, Get-PEFileIfValid
