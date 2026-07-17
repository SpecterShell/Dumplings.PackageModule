# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# Force stop on error
$ErrorActionPreference = 'Stop'

$Script:PortableWinGetArchitectures = @('x86', 'x64', 'arm64')
$Script:DotNetRuntimeFrameworkPackageMap = @{
  'Microsoft.NETCore.App'        = 'Microsoft.DotNet.Runtime'
  'Microsoft.WindowsDesktop.App' = 'Microsoft.DotNet.DesktopRuntime'
  'Microsoft.AspNetCore.App'     = 'Microsoft.DotNet.AspNetCore'
}
$Script:DotNetSupportedDependencyMajors = 5..10
$Script:DotNetBundledRuntimeFileNames = @('hostfxr.dll', 'hostpolicy.dll', 'coreclr.dll', 'System.Private.CoreLib.dll')
$Script:DotNetAppHostPlaceholder = 'c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2'
$Script:DotNetAppHostMaximumBindingLength = 1024
$Script:DotNetBundleHeaderSignature = [byte[]](
  0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38,
  0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32,
  0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18,
  0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae
)

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
    $RelatedArchitectureInfo = foreach ($Related in @($RelatedFile | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
      try {
        Get-PEArchitectureInfo -Path $Related
      } catch {
        [pscustomobject]@{
          Path                           = (Get-Item -LiteralPath $Related -Force -ErrorAction SilentlyContinue).FullName
          RecommendedWinGetArchitecture  = $null
          RecommendedWinGetArchitectures = @()
          SupportedArchitectures         = @()
          Warnings                       = @($_.Exception.Message)
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
      Warnings                       = @($Warnings)
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

function Read-PERuntimeConfig {
  <#
  .SYNOPSIS
    Read a .NET runtimeconfig JSON file
  .PARAMETER Path
    The runtimeconfig.json path
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The runtimeconfig.json path')]
    [string]$Path
  )

  $File = Get-Item -LiteralPath $Path -Force
  $Content = Get-Content -LiteralPath $File.FullName -Raw -Encoding UTF8
  if ([string]::IsNullOrWhiteSpace($Content)) { return $null }
  $Json = $Content | ConvertFrom-Json
  [pscustomobject]@{
    Path = $File.FullName
    Json = $Json
  }
}

function Find-PEBytePattern {
  <#
  .SYNOPSIS
    Find all offsets of a byte pattern inside a byte array
  .PARAMETER Bytes
    The byte array to search
  .PARAMETER Pattern
    The byte pattern to find
  #>
  [OutputType([int[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The byte array to search')]
    [byte[]]$Bytes,

    [Parameter(Mandatory, HelpMessage = 'The byte pattern to find')]
    [byte[]]$Pattern
  )

  @(Find-BinaryPattern -Bytes $Bytes -Pattern $Pattern) | ForEach-Object { [int]$_ }
}

function Read-PE7BitEncodedLength {
  <#
  .SYNOPSIS
    Read the 7-bit string length format used by .NET bundle manifests
  .PARAMETER Bytes
    The bundle byte array
  .PARAMETER Offset
    The offset to read from
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The bundle byte array')]
    [byte[]]$Bytes,

    [Parameter(Mandatory, HelpMessage = 'The offset to read from')]
    [int]$Offset
  )

  if ($Offset -lt 0 -or $Offset -ge $Bytes.Count) { return $null }

  $FirstByte = [int]$Bytes[$Offset]
  if (($FirstByte -band 0x80) -eq 0) {
    return [pscustomobject]@{ Length = $FirstByte; BytesRead = 1 }
  }

  if ($Offset + 1 -ge $Bytes.Count) { return $null }
  $SecondByte = [int]$Bytes[$Offset + 1]
  if (($SecondByte -band 0x80) -ne 0) { return $null }

  [pscustomobject]@{
    Length    = (($SecondByte -shl 7) -bor ($FirstByte -band 0x7F))
    BytesRead = 2
  }
}

function Read-PEBundleString {
  <#
  .SYNOPSIS
    Read a length-prefixed UTF-8 bundle manifest string
  .PARAMETER Bytes
    The bundle byte array
  .PARAMETER Offset
    The offset to read from
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The bundle byte array')]
    [byte[]]$Bytes,

    [Parameter(Mandatory, HelpMessage = 'The offset to read from')]
    [int]$Offset
  )

  $LengthInfo = Read-PE7BitEncodedLength -Bytes $Bytes -Offset $Offset
  if (-not $LengthInfo -or $LengthInfo.Length -le 0) { return $null }

  $StringOffset = $Offset + $LengthInfo.BytesRead
  if ($StringOffset + $LengthInfo.Length -gt $Bytes.Count) { return $null }

  [pscustomobject]@{
    Value     = [System.Text.Encoding]::UTF8.GetString($Bytes, $StringOffset, $LengthInfo.Length)
    BytesRead = $LengthInfo.BytesRead + $LengthInfo.Length
  }
}

function Get-PEDotNetBundleInfo {
  <#
  .SYNOPSIS
    Read .NET single-file bundle header evidence from an apphost
  .PARAMETER Path
    The PE file path
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, ParameterSetName = 'Path', HelpMessage = 'The PE file path')][string]$Path,
    [Parameter(Mandatory, ParameterSetName = 'Stream', HelpMessage = 'The caller-owned PE stream')][System.IO.Stream]$Stream
  )

  $OwnsStream = $PSCmdlet.ParameterSetName -eq 'Path'
  if ($OwnsStream) {
    $File = Get-Item -LiteralPath $Path -Force
    $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  }
  if ($Stream.Length -gt 536870912) { if ($OwnsStream) { $Stream.Dispose() }; return $null }

  $BundleHeaders = [System.Collections.Generic.List[psobject]]::new()
  try {
    foreach ($SignatureOffset in @(Find-BinaryPattern -Stream $Stream -Pattern $Script:DotNetBundleHeaderSignature -Maximum 16)) {
      if ($SignatureOffset -lt 8) { continue }
      $HeaderOffset = [BitConverter]::ToInt64((Read-BinaryBytes -Stream $Stream -Offset ($SignatureOffset - 8) -Count 8), 0)
      if ($HeaderOffset -le 0 -or $HeaderOffset + 60 -gt $Stream.Length) { continue }

      try {
        $HeaderBytes = Read-BinaryBytes -Stream $Stream -Offset $HeaderOffset -Count ([int][Math]::Min(4096, $Stream.Length - $HeaderOffset))
        $MajorVersion = [System.BitConverter]::ToUInt32($HeaderBytes, 0)
        $MinorVersion = [System.BitConverter]::ToUInt32($HeaderBytes, 4)
        $EmbeddedFileCount = [System.BitConverter]::ToInt32($HeaderBytes, 8)
        if (-not (($MajorVersion -eq 6 -and $MinorVersion -eq 0) -or ($MajorVersion -eq 2 -and $MinorVersion -eq 0))) { continue }
        if ($EmbeddedFileCount -le 0) { continue }

        $ReadOffset = 12
        $BundleId = Read-PEBundleString -Bytes $HeaderBytes -Offset $ReadOffset
        if (-not $BundleId) { continue }
        $ReadOffset += $BundleId.BytesRead

        $DepsJsonOffset = [System.BitConverter]::ToInt64($HeaderBytes, $ReadOffset)
        $DepsJsonSize = [System.BitConverter]::ToInt64($HeaderBytes, $ReadOffset + 8)
        $RuntimeConfigJsonOffset = [System.BitConverter]::ToInt64($HeaderBytes, $ReadOffset + 16)
        $RuntimeConfigJsonSize = [System.BitConverter]::ToInt64($HeaderBytes, $ReadOffset + 24)
        $Flags = [System.BitConverter]::ToUInt64($HeaderBytes, $ReadOffset + 32)

        $RuntimeConfigJson = $null
        if ($RuntimeConfigJsonOffset -gt 0 -and $RuntimeConfigJsonSize -gt 0 -and $RuntimeConfigJsonSize -lt 10485760 -and $RuntimeConfigJsonOffset + $RuntimeConfigJsonSize -le $Stream.Length) {
          $RuntimeConfigJson = [Text.Encoding]::UTF8.GetString((Read-BinaryBytes -Stream $Stream -Offset $RuntimeConfigJsonOffset -Count ([int]$RuntimeConfigJsonSize)))
        }

        $BundleHeaders.Add([pscustomobject]@{
            HeaderOffset            = $HeaderOffset
            SignatureOffset         = $SignatureOffset
            MajorVersion            = $MajorVersion
            MinorVersion            = $MinorVersion
            EmbeddedFileCount       = $EmbeddedFileCount
            BundleId                = $BundleId.Value
            DepsJsonOffset          = $DepsJsonOffset
            DepsJsonSize            = $DepsJsonSize
            RuntimeConfigJsonOffset = $RuntimeConfigJsonOffset
            RuntimeConfigJsonSize   = $RuntimeConfigJsonSize
            RuntimeConfigJson       = $RuntimeConfigJson
            Flags                   = $Flags
            IsNetCoreApp3CompatMode = ($Flags -band 1) -ne 0
          })
      } catch {
        continue
      }
    }
  } finally {
    if ($OwnsStream) { $Stream.Dispose() }
  }

  if ($BundleHeaders.Count -eq 0) { return $null }
  @($BundleHeaders | Sort-Object -Property HeaderOffset -Descending | Select-Object -First 1)[0]
}

function Get-PERuntimeConfigPath {
  <#
  .SYNOPSIS
    Find a runtimeconfig sidecar for a PE file
  .PARAMETER Path
    The PE file path
  .PARAMETER RelatedFile
    Related sidecar files
  .PARAMETER AppPath
    The managed app path resolved from apphost binding
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The PE file path')]
    [string]$Path,

    [Parameter(HelpMessage = 'Related sidecar files')]
    [string[]]$RelatedFile = @(),

    [Parameter(HelpMessage = 'The managed app path resolved from apphost binding')]
    [AllowNull()]
    [string]$AppPath
  )

  $CandidateBases = [System.Collections.Generic.List[psobject]]::new()
  if (-not [string]::IsNullOrWhiteSpace($AppPath)) {
    try {
      $AppFile = Get-Item -LiteralPath $AppPath -Force -ErrorAction SilentlyContinue
      if ($AppFile) {
        $CandidateBases.Add([pscustomobject]@{
            DirectoryName = $AppFile.DirectoryName
            BaseName      = [System.IO.Path]::GetFileNameWithoutExtension($AppFile.Name)
          })
      }
    } catch {
    }
  }

  $File = Get-Item -LiteralPath $Path -Force
  $CandidateBases.Add([pscustomobject]@{
      DirectoryName = $File.DirectoryName
      BaseName      = [System.IO.Path]::GetFileNameWithoutExtension($File.Name)
    })

  foreach ($CandidateBase in $CandidateBases) {
    $RuntimeConfigName = "$($CandidateBase.BaseName).runtimeconfig.json"
    $AdjacentPath = Join-Path -Path $CandidateBase.DirectoryName -ChildPath $RuntimeConfigName
    if (Test-Path -LiteralPath $AdjacentPath -PathType Leaf) {
      return (Get-Item -LiteralPath $AdjacentPath -Force).FullName
    }
  }

  foreach ($Related in @($RelatedFile | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
    try {
      $RelatedFileInfo = Get-Item -LiteralPath $Related -Force
      foreach ($CandidateBase in $CandidateBases) {
        $RuntimeConfigName = "$($CandidateBase.BaseName).runtimeconfig.json"
        if ($RelatedFileInfo.Name -ieq $RuntimeConfigName) { return $RelatedFileInfo.FullName }
      }
    } catch {
      continue
    }
  }

  return $null
}

function Resolve-PEDotNetAppHostBoundAssemblyPath {
  <#
  .SYNOPSIS
    Resolve an apphost-bound managed DLL path using host-relative rules
  .PARAMETER HostFile
    The apphost file
  .PARAMETER BoundAssemblyRelativePath
    The apphost-bound managed DLL relative path
  .PARAMETER RelatedFile
    Related PE and sidecar files
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The apphost file')]
    [System.IO.FileInfo]$HostFile,

    [Parameter(Mandatory, HelpMessage = 'The apphost-bound managed DLL relative path')]
    [string]$BoundAssemblyRelativePath,

    [Parameter(HelpMessage = 'Related PE and sidecar files')]
    [string[]]$RelatedFile = @()
  )

  if ([string]::IsNullOrWhiteSpace($BoundAssemblyRelativePath)) { return $null }
  if ([System.IO.Path]::IsPathRooted($BoundAssemblyRelativePath)) { return $null }

  $NormalizedRelativePath = $BoundAssemblyRelativePath -replace '/', [System.IO.Path]::DirectorySeparatorChar
  $CandidatePath = Join-Path -Path $HostFile.DirectoryName -ChildPath $NormalizedRelativePath
  if (Test-Path -LiteralPath $CandidatePath -PathType Leaf) {
    return (Get-Item -LiteralPath $CandidatePath -Force).FullName
  }

  $ComparableRelativePath = ($BoundAssemblyRelativePath -replace '\\', '/').TrimStart('/').ToLowerInvariant()
  foreach ($Related in @($RelatedFile | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
    try {
      $RelatedFileInfo = Get-Item -LiteralPath $Related -Force
      if ($RelatedFileInfo.Name -ieq ([System.IO.Path]::GetFileName($BoundAssemblyRelativePath))) {
        return $RelatedFileInfo.FullName
      }
      $RelatedComparable = ($RelatedFileInfo.FullName -replace '\\', '/').ToLowerInvariant()
      if ($RelatedComparable.EndsWith("/$ComparableRelativePath")) {
        return $RelatedFileInfo.FullName
      }
    } catch {
      continue
    }
  }

  return $null
}

function Get-PEDotNetAppHostBindingCandidate {
  <#
  .SYNOPSIS
    Find candidate apphost-bound DLL strings in a patched apphost image
  .PARAMETER Bytes
    The apphost byte array
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The apphost byte array')]
    [byte[]]$Bytes
  )

  $Candidates = [System.Collections.Generic.List[string]]::new()
  $DllNeedle = [System.Text.Encoding]::ASCII.GetBytes('.dll')
  foreach ($DllOffset in @(Find-PEBytePattern -Bytes $Bytes -Pattern $DllNeedle)) {
    $Start = $DllOffset
    while ($Start -gt 0 -and $Bytes[$Start - 1] -ne 0 -and ($DllOffset - $Start) -lt $Script:DotNetAppHostMaximumBindingLength) {
      $Start--
    }

    $End = $DllOffset + $DllNeedle.Count
    while ($End -lt $Bytes.Count -and $Bytes[$End] -ne 0 -and ($End - $Start) -lt $Script:DotNetAppHostMaximumBindingLength) {
      $End++
    }

    if ($End -le $Start -or $End - $Start -gt $Script:DotNetAppHostMaximumBindingLength) { continue }
    $Candidate = [System.Text.Encoding]::UTF8.GetString($Bytes, $Start, $End - $Start)
    if ($Candidate -notmatch '(?i)\.dll$') { continue }
    if ($Candidate -match '[\x00-\x1F]' -or $Candidate -match '^[A-Za-z]:[\\/]' -or $Candidate.StartsWith('\\')) { continue }
    if ($Candidate -match '[<>:"|?*]') { continue }
    $Candidates.Add($Candidate)
  }

  @($Candidates | Sort-Object -Unique)
}

function Get-PEDotNetAppHostInfo {
  <#
  .SYNOPSIS
    Read .NET apphost binding evidence without executing the host
  .PARAMETER Path
    The PE file path
  .PARAMETER RelatedFile
    Related PE and sidecar files
  .PARAMETER ArchitectureInfo
    Architecture information for the PE file
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The PE file path')]
    [string]$Path,

    [Parameter(HelpMessage = 'Related PE and sidecar files')]
    [string[]]$RelatedFile = @(),

    [Parameter(Mandatory, HelpMessage = 'Architecture information for the PE file')]
    [psobject]$ArchitectureInfo
  )

  $File = Get-Item -LiteralPath $Path -Force
  if ($ArchitectureInfo.FileKind -ne 'Executable' -or $ArchitectureInfo.IsManaged -or $File.Length -gt 536870912) {
    return [pscustomobject]@{
      IsAppHost                   = $false
      IsBound                     = $false
      IsUnboundTemplate           = $false
      BoundAssemblyRelativePath   = $null
      BoundAssemblyPath           = $null
      BoundAssemblyIsManaged      = $false
      CandidateBoundAssemblyPaths = @()
      PlaceholderOffset           = $null
      BundleInfo                  = $null
    }
  }

  $HostStream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    $PlaceholderBytes = [System.Text.Encoding]::UTF8.GetBytes($Script:DotNetAppHostPlaceholder)
    $PlaceholderOffset = @(Find-BinaryPattern -Stream $HostStream -Pattern $PlaceholderBytes -Maximum 1 | Select-Object -First 1)[0]
    $BundleInfo = Get-PEDotNetBundleInfo -Stream $HostStream
    $Candidates = @(Get-PEDotNetAppHostBindingCandidateFromStream -Stream $HostStream)
  } finally { $HostStream.Dispose() }
  $ResolvedCandidates = foreach ($Candidate in $Candidates) {
    $ResolvedPath = Resolve-PEDotNetAppHostBoundAssemblyPath -HostFile $File -BoundAssemblyRelativePath $Candidate -RelatedFile $RelatedFile
    if (-not $ResolvedPath) { continue }
    $ResolvedPEFile = Get-PEFileIfValid -Path $ResolvedPath
    if (-not $ResolvedPEFile) { continue }
    [pscustomobject]@{
      RelativePath = $Candidate
      Path         = $ResolvedPEFile.FullName
      IsManaged    = $null -ne (Get-PEClrHeader -Path $ResolvedPEFile.FullName)
    }
  }
  $ManagedCandidate = @($ResolvedCandidates | Where-Object { $_.IsManaged } | Select-Object -First 1)[0]

  [pscustomobject]@{
    IsAppHost                   = $null -ne $ManagedCandidate -or $null -ne $BundleInfo -or $null -ne $PlaceholderOffset
    IsBound                     = $null -ne $ManagedCandidate
    IsUnboundTemplate           = $null -ne $PlaceholderOffset
    BoundAssemblyRelativePath   = if ($ManagedCandidate) { $ManagedCandidate.RelativePath } else { $null }
    BoundAssemblyPath           = if ($ManagedCandidate) { $ManagedCandidate.Path } else { $null }
    BoundAssemblyIsManaged      = if ($ManagedCandidate) { $ManagedCandidate.IsManaged } else { $false }
    CandidateBoundAssemblyPaths = @($Candidates)
    PlaceholderOffset           = $PlaceholderOffset
    BundleInfo                  = $BundleInfo
  }
}

function Get-PEDotNetBundledRuntimeFile {
  <#
  .SYNOPSIS
    Find .NET runtime marker files that indicate a bundled runtime
  .PARAMETER Path
    The PE file path
  .PARAMETER RelatedFile
    Related sidecar files
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The PE file path')]
    [string]$Path,

    [Parameter(HelpMessage = 'Related sidecar files')]
    [string[]]$RelatedFile = @()
  )

  $File = Get-Item -LiteralPath $Path -Force
  $MarkerPaths = [System.Collections.Generic.List[string]]::new()
  foreach ($MarkerName in $Script:DotNetBundledRuntimeFileNames) {
    $CandidatePath = Join-Path -Path $File.DirectoryName -ChildPath $MarkerName
    if (Test-Path -LiteralPath $CandidatePath -PathType Leaf) {
      $MarkerPaths.Add((Get-Item -LiteralPath $CandidatePath -Force).FullName)
    }
  }

  foreach ($Related in @($RelatedFile | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
    try {
      $RelatedFileInfo = Get-Item -LiteralPath $Related -Force
      if ($RelatedFileInfo.Name -iin $Script:DotNetBundledRuntimeFileNames) {
        $MarkerPaths.Add($RelatedFileInfo.FullName)
      }
    } catch {
      continue
    }
  }

  @($MarkerPaths | Sort-Object -Unique)
}

function Get-PERelatedSameNameManagedDll {
  <#
  .SYNOPSIS
    Find a same-name managed DLL sidecar for a PE apphost
  .PARAMETER Path
    The PE file path
  .PARAMETER RelatedFile
    Related sidecar files
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The PE file path')]
    [string]$Path,

    [Parameter(HelpMessage = 'Related sidecar files')]
    [string[]]$RelatedFile = @()
  )

  $File = Get-Item -LiteralPath $Path -Force
  $DllName = "$([System.IO.Path]::GetFileNameWithoutExtension($File.Name)).dll"
  $AdjacentPath = Join-Path -Path $File.DirectoryName -ChildPath $DllName
  if (Test-Path -LiteralPath $AdjacentPath -PathType Leaf) {
    $Dll = Get-PEFileIfValid -Path $AdjacentPath
    if ($Dll -and (Get-PEClrHeader -Path $Dll.FullName)) { return $Dll.FullName }
  }

  foreach ($Related in @($RelatedFile | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
    try {
      $RelatedFileInfo = Get-Item -LiteralPath $Related -Force
      if ($RelatedFileInfo.Name -ieq $DllName) {
        $Dll = Get-PEFileIfValid -Path $RelatedFileInfo.FullName
        if ($Dll -and (Get-PEClrHeader -Path $Dll.FullName)) { return $Dll.FullName }
      }
    } catch {
      continue
    }
  }

  return $null
}

function Test-PENativeAppHostStringEvidence {
  <#
  .SYNOPSIS
    Check bounded strings for .NET apphost-related markers
  .PARAMETER Path
    The PE file path
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The PE file path')]
    [string]$Path
  )

  $File = Get-Item -LiteralPath $Path -Force
  if ($File.Length -gt 268435456) { return $false }

  $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    foreach ($Marker in @('hostfxr', '.runtimeconfig.json')) {
      if (@(Find-BinaryPattern -Stream $Stream -Pattern ([Text.Encoding]::ASCII.GetBytes($Marker)) -Maximum 1).Count) { return $true }
      if (@(Find-BinaryPattern -Stream $Stream -Pattern ([Text.Encoding]::Unicode.GetBytes($Marker)) -Maximum 1).Count) { return $true }
    }
    return $false
  } finally { $Stream.Dispose() }
}

function ConvertFrom-PERuntimeConfigFramework {
  <#
  .SYNOPSIS
    Convert runtimeconfig framework entries to dependency evidence
  .PARAMETER Framework
    A runtimeconfig framework object
  .PARAMETER Included
    Indicates whether the framework was listed in includedFrameworks
  .PARAMETER Warnings
    A list that receives warnings
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'A runtimeconfig framework object')]
    [psobject]$Framework,

    [Parameter(HelpMessage = 'Indicates whether the framework was listed in includedFrameworks')]
    [switch]$Included,

    [Parameter(Mandatory, HelpMessage = 'A list that receives warnings')]
    [AllowEmptyCollection()]
    [System.Collections.Generic.List[string]]$Warnings
  )

  $Name = [string]$Framework.name
  $Version = [string]$Framework.version
  $Major = $null
  if ($Version -match '^(?<Major>\d+)') {
    $Major = [int]$Matches.Major
  }

  $PackagePrefix = $Script:DotNetRuntimeFrameworkPackageMap[$Name]
  $PackageIdentifier = if ($PackagePrefix -and $Major -in $Script:DotNetSupportedDependencyMajors) { "$PackagePrefix.$Major" } else { $null }
  if (-not $PackagePrefix) {
    $Warnings.Add("Unknown .NET runtimeconfig framework '$Name' was found; dependency mapping requires manual review.")
  } elseif ($Major -notin $Script:DotNetSupportedDependencyMajors) {
    $Warnings.Add("Runtimeconfig framework '$Name' version '$Version' is outside the supported Microsoft.DotNet dependency majors 5-10.")
  }

  [pscustomobject]@{
    Name              = $Name
    Version           = $Version
    MajorVersion      = $Major
    IsIncluded        = $Included.IsPresent
    PackageIdentifier = $PackageIdentifier
    MinimumVersion    = if ($Version) { $Version } else { $null }
  }
}

function Get-PEDotNetRuntimeInfo {
  <#
  .SYNOPSIS
    Read static .NET runtime dependency evidence for a PE file
  .PARAMETER Path
    The PE file path
  .PARAMETER RelatedFile
    Related PE and sidecar files
  .PARAMETER ArchitectureInfo
    Architecture information for the PE file
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The PE file path')]
    [string]$Path,

    [Parameter(HelpMessage = 'Related PE and sidecar files')]
    [string[]]$RelatedFile = @(),

    [Parameter(Mandatory, HelpMessage = 'Architecture information for the PE file')]
    [psobject]$ArchitectureInfo
  )

  $Warnings = [System.Collections.Generic.List[string]]::new()
  $File = Get-Item -LiteralPath $Path -Force
  $AppHostInfo = Get-PEDotNetAppHostInfo -Path $File.FullName -RelatedFile $RelatedFile -ArchitectureInfo $ArchitectureInfo
  $RuntimeConfigPath = Get-PERuntimeConfigPath -Path $File.FullName -RelatedFile $RelatedFile -AppPath $AppHostInfo.BoundAssemblyPath
  $RuntimeConfig = if ($RuntimeConfigPath) {
    try {
      Read-PERuntimeConfig -Path $RuntimeConfigPath
    } catch {
      $Warnings.Add("Failed to parse .NET runtimeconfig '$RuntimeConfigPath': $($_.Exception.Message)")
      $null
    }
  } else {
    $null
  }
  if (-not $RuntimeConfig -and $AppHostInfo.BundleInfo -and -not [string]::IsNullOrWhiteSpace($AppHostInfo.BundleInfo.RuntimeConfigJson)) {
    try {
      $RuntimeConfig = [pscustomobject]@{
        Path = "bundle:$($File.FullName)"
        Json = $AppHostInfo.BundleInfo.RuntimeConfigJson | ConvertFrom-Json
      }
    } catch {
      $Warnings.Add("Failed to parse embedded .NET bundle runtimeconfig in '$($File.FullName)': $($_.Exception.Message)")
    }
  }
  $BundledRuntimeFiles = @(Get-PEDotNetBundledRuntimeFile -Path $File.FullName -RelatedFile $RelatedFile)
  $SameNameManagedDll = Get-PERelatedSameNameManagedDll -Path $File.FullName -RelatedFile $RelatedFile
  $HasAppHostStringEvidence = if (-not $ArchitectureInfo.IsManaged -and $ArchitectureInfo.FileKind -eq 'Executable') { Test-PENativeAppHostStringEvidence -Path $File.FullName } else { $false }
  $IsDotNetAppHost = (-not $ArchitectureInfo.IsManaged -and $ArchitectureInfo.FileKind -eq 'Executable' -and ($AppHostInfo.IsBound -or $AppHostInfo.BundleInfo -or ($RuntimeConfig -and ($SameNameManagedDll -or $HasAppHostStringEvidence))))

  $Frameworks = [System.Collections.Generic.List[psobject]]::new()
  $IncludedFrameworks = [System.Collections.Generic.List[psobject]]::new()
  if ($RuntimeConfig -and $RuntimeConfig.Json.runtimeOptions) {
    foreach ($Framework in @($RuntimeConfig.Json.runtimeOptions.framework)) {
      if ($Framework) { $Frameworks.Add((ConvertFrom-PERuntimeConfigFramework -Framework $Framework -Warnings $Warnings)) }
    }
    foreach ($Framework in @($RuntimeConfig.Json.runtimeOptions.frameworks)) {
      if ($Framework) { $Frameworks.Add((ConvertFrom-PERuntimeConfigFramework -Framework $Framework -Warnings $Warnings)) }
    }
    foreach ($Framework in @($RuntimeConfig.Json.runtimeOptions.includedFrameworks)) {
      if ($Framework) { $IncludedFrameworks.Add((ConvertFrom-PERuntimeConfigFramework -Framework $Framework -Included -Warnings $Warnings)) }
    }
  }

  $IsRuntimeBundled = $BundledRuntimeFiles.Count -gt 0 -or $IncludedFrameworks.Count -gt 0
  $DependencyCandidates = if ($IsRuntimeBundled) { @() } else { @($Frameworks | Where-Object { $_.PackageIdentifier }) }
  $SpecificMajorVersions = @($DependencyCandidates | Where-Object { $_.Name -in @('Microsoft.WindowsDesktop.App', 'Microsoft.AspNetCore.App') } | Select-Object -ExpandProperty MajorVersion -Unique)
  $DependencyCandidates = @($DependencyCandidates | Where-Object {
      -not ($_.Name -eq 'Microsoft.NETCore.App' -and $_.MajorVersion -in $SpecificMajorVersions)
    })

  $DependencyGroups = @($DependencyCandidates | Group-Object -Property PackageIdentifier)
  $RecommendedDependencies = foreach ($Group in $DependencyGroups) {
    $VersionRecords = @($Group.Group | Where-Object { $_.MinimumVersion } | ForEach-Object -Process {
        $RawVersion = [string]$_.MinimumVersion
        $ComparableVersion = $null
        try {
          $ComparableVersion = [version](($RawVersion -split '-', 2)[0])
        } catch {
          $ComparableVersion = $null
        }
        [pscustomobject]@{
          Raw        = $RawVersion
          Comparable = $ComparableVersion
        }
      })
    $ComparableVersions = @($VersionRecords | Where-Object { $_.Comparable })
    $MinimumVersion = if ($ComparableVersions.Count -gt 0) {
      @($ComparableVersions | Sort-Object -Property Comparable -Descending | Select-Object -First 1)[0].Raw
    } elseif ($VersionRecords.Count -gt 0) {
      @($VersionRecords | Sort-Object -Property Raw -Descending | Select-Object -First 1)[0].Raw
    } else {
      $null
    }
    if ($MinimumVersion) {
      [pscustomobject]@{ PackageIdentifier = $Group.Name; MinimumVersion = $MinimumVersion }
    } else {
      [pscustomobject]@{ PackageIdentifier = $Group.Name }
    }
  }

  if (-not $RuntimeConfig -and $ArchitectureInfo.IsManaged -and $ArchitectureInfo.FileKind -eq 'Dll' -and $ArchitectureInfo.TargetFramework -and $ArchitectureInfo.TargetFramework.FrameworkName -eq '.NETCoreApp' -and $ArchitectureInfo.TargetFramework.VersionObject.Major -ge 5) {
    $Warnings.Add("Managed .NET $($ArchitectureInfo.TargetFramework.Version) DLL has no runtimeconfig sidecar; inspect the application host/runtimeconfig before adding .NET runtime dependencies.")
  }

  [pscustomobject]@{
    Path                            = $File.FullName
    RuntimeConfigPath               = if ($RuntimeConfig) { $RuntimeConfig.Path } else { $null }
    HasRuntimeConfig                = $null -ne $RuntimeConfig
    IsDotNetAppHost                 = [bool]$IsDotNetAppHost
    AppHostInfo                     = $AppHostInfo
    BoundAssemblyPath               = $AppHostInfo.BoundAssemblyPath
    BoundAssemblyRelativePath       = $AppHostInfo.BoundAssemblyRelativePath
    SameNameManagedDll              = $SameNameManagedDll
    HasAppHostStringEvidence        = [bool]$HasAppHostStringEvidence
    IsRuntimeBundled                = [bool]$IsRuntimeBundled
    BundledRuntimeFiles             = $BundledRuntimeFiles
    Frameworks                      = @($Frameworks)
    IncludedFrameworks              = @($IncludedFrameworks)
    RecommendedPackageDependencies  = @($RecommendedDependencies | Sort-Object -Property PackageIdentifier)
    RecommendedPackageDependencyIds = @($RecommendedDependencies | Select-Object -ExpandProperty PackageIdentifier | Sort-Object -Unique)
    Warnings                        = @($Warnings)
  }
}

function Get-PEDependencyInfo {
  <#
  .SYNOPSIS
    Statically detect PE runtime dependency evidence
  .DESCRIPTION
    The function reads direct and delay-import DLL names without executing the binary,
    maps known Visual C++ runtime imports to WinGet package dependency identifiers,
    reports Universal C Runtime imports separately, and reads .NET runtimeconfig sidecars.
  .PARAMETER Path
    The PE file path
  .PARAMETER RelatedFile
    Related PE files and sidecar files to inspect with the PE file
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The PE file path')]
    [string]$Path,

    [Parameter(HelpMessage = 'Related PE files and sidecar files to inspect with the PE file')]
    [string[]]$RelatedFile = @()
  )

  process {
    $PrimaryFile = Get-Item -LiteralPath $Path -Force
    $InputFiles = @($Path) + @($RelatedFile)
    $Files = @($InputFiles | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object -Process { (Get-Item -LiteralPath $_ -Force).FullName } | Sort-Object -Unique)
    $PEFiles = @($Files | ForEach-Object -Process {
        $PEFile = Get-PEFileIfValid -Path $_
        if ($PEFile) { $PEFile.FullName }
      } | Sort-Object -Unique)
    $Warnings = [System.Collections.Generic.List[string]]::new()
    $AllImports = [System.Collections.Generic.List[psobject]]::new()
    $VCRedistImports = [System.Collections.Generic.List[psobject]]::new()
    $UcrtImports = [System.Collections.Generic.List[psobject]]::new()
    $RelatedPEFiles = @($RelatedFile | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object -Process {
        $RelatedPEFile = Get-PEFileIfValid -Path $_
        if ($RelatedPEFile) { $RelatedPEFile.FullName }
      } | Sort-Object -Unique)
    $PrimaryArchitectureInfo = Get-PEArchitectureInfo -Path $PrimaryFile.FullName -RelatedFile $RelatedPEFiles
    $DotNetInfo = Get-PEDotNetRuntimeInfo -Path $PrimaryFile.FullName -RelatedFile $RelatedFile -ArchitectureInfo $PrimaryArchitectureInfo

    foreach ($FilePath in $PEFiles) {
      $ArchitectureInfo = Get-PEArchitectureInfo -Path $FilePath
      $FileArchitectures = @($ArchitectureInfo.RecommendedWinGetArchitectures)
      if ($FileArchitectures.Count -eq 0) {
        $Warnings.Add("Could not determine concrete architecture for $FilePath; VCRedist package mapping may be incomplete.")
      }

      $Imports = @(
        Get-PEImportedDll -Path $FilePath
        Get-PEDelayImportedDll -Path $FilePath
      )

      foreach ($Import in $Imports) {
        $ImportRecord = [pscustomobject]@{
          Path      = $FilePath
          Directory = $Import.Directory
          DllName   = $Import.DllName
        }
        $AllImports.Add($ImportRecord)

        $RuntimeVersion = Resolve-PortableVCRedistRuntime -DllName $Import.DllName
        if ($RuntimeVersion) {
          foreach ($Architecture in $FileArchitectures) {
            $PackageIdentifier = Get-PortableVCRedistPackageIdentifier -RuntimeVersion $RuntimeVersion -Architecture $Architecture
            if ($PackageIdentifier) {
              $VCRedistImports.Add([pscustomobject]@{
                  Path              = $FilePath
                  Directory         = $Import.Directory
                  DllName           = $Import.DllName
                  RuntimeVersion    = $RuntimeVersion
                  Architecture      = $Architecture
                  PackageIdentifier = $PackageIdentifier
                })
            } else {
              $Warnings.Add("Import '$($Import.DllName)' maps to VC++ $RuntimeVersion, but no Microsoft.VCRedist.$RuntimeVersion.$Architecture package is available.")
            }
          }
          continue
        }

        if (Test-PortableUcrtImport -DllName $Import.DllName) {
          $UcrtImports.Add([pscustomobject]@{
              Path      = $FilePath
              Directory = $Import.Directory
              DllName   = $Import.DllName
            })
        }
      }
    }

    $VCRedistPackageIds = @($VCRedistImports | Select-Object -ExpandProperty PackageIdentifier -Unique | Sort-Object)
    $DotNetPackageIds = @($DotNetInfo.RecommendedPackageDependencyIds)
    $PackageIds = @($VCRedistPackageIds + $DotNetPackageIds | Sort-Object -Unique)
    $RecommendedDependencies = [System.Collections.Generic.List[psobject]]::new()
    foreach ($PackageId in $VCRedistPackageIds) {
      $RecommendedDependencies.Add([pscustomobject]@{ PackageIdentifier = $PackageId })
    }
    foreach ($Dependency in @($DotNetInfo.RecommendedPackageDependencies)) {
      $RecommendedDependencies.Add($Dependency)
    }

    [pscustomobject]@{
      Path                            = $PrimaryFile.FullName
      CheckedFiles                    = $Files
      CheckedPEFiles                  = $PEFiles
      ImportedDlls                    = @($AllImports)
      DependsOnVCRedist               = $VCRedistImports.Count -gt 0
      DependsOnUcrt                   = $UcrtImports.Count -gt 0
      DependsOnVisualCRuntime         = $VCRedistImports.Count -gt 0 -or $UcrtImports.Count -gt 0
      DependsOnDotNetRuntime          = $DotNetInfo.RecommendedPackageDependencyIds.Count -gt 0
      VCRedistImports                 = @($VCRedistImports)
      UcrtImports                     = @($UcrtImports)
      DotNetInfo                      = $DotNetInfo
      RecommendedPackageDependencyIds = $PackageIds
      RecommendedPackageDependencies  = @($RecommendedDependencies | Sort-Object -Property PackageIdentifier)
      Warnings                        = @($Warnings + $DotNetInfo.Warnings)
    }
  }
}

function Test-PEVCRedistDependency {
  <#
  .SYNOPSIS
    Test whether a PE file imports Visual C++ runtime DLLs
  .PARAMETER Path
    The PE file path
  .PARAMETER RelatedFile
    Related PE files to inspect with the PE file
  #>
  [OutputType([bool])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The PE file path')]
    [string]$Path,

    [Parameter(HelpMessage = 'Related PE files to inspect with the PE file')]
    [string[]]$RelatedFile = @()
  )

  process {
    (Get-PEDependencyInfo -Path $Path -RelatedFile $RelatedFile).DependsOnVCRedist
  }
}

function Get-PortableExecutableArchitectureInfo {
  <#
  .SYNOPSIS
    Compatibility wrapper for Get-PEArchitectureInfo
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
    [string]$Path,

    [string[]]$RelatedFile = @()
  )

  process { Get-PEArchitectureInfo -Path $Path -RelatedFile $RelatedFile }
}

function Read-ArchitectureFromPortableExecutable {
  <#
  .SYNOPSIS
    Compatibility wrapper for Read-ArchitectureFromPE
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
    [string]$Path,

    [string[]]$RelatedFile = @()
  )

  process { Read-ArchitectureFromPE -Path $Path -RelatedFile $RelatedFile }
}

function Test-PortableExecutableArchitecture {
  <#
  .SYNOPSIS
    Compatibility wrapper for Test-PEArchitecture
  #>
  [OutputType([bool])]
  param (
    [Parameter(Position = 0, Mandatory)]
    [string]$Path,

    [Parameter(Mandatory)]
    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture,

    [string[]]$RelatedFile = @()
  )

  Test-PEArchitecture -Path $Path -Architecture $Architecture -RelatedFile $RelatedFile
}

function Get-PortableExecutableVCRedistInfo {
  <#
  .SYNOPSIS
    Compatibility wrapper for Get-PEDependencyInfo
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
    [string]$Path,

    [string[]]$RelatedFile = @()
  )

  process { Get-PEDependencyInfo -Path $Path -RelatedFile $RelatedFile }
}

function Test-PortableExecutableVCRedistDependency {
  <#
  .SYNOPSIS
    Compatibility wrapper for Test-PEVCRedistDependency
  #>
  [OutputType([bool])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
    [string]$Path,

    [string[]]$RelatedFile = @()
  )

  process { Test-PEVCRedistDependency -Path $Path -RelatedFile $RelatedFile }
}

Export-ModuleMember -Function Get-PEArchitectureInfo, Read-ArchitectureFromPE, Test-PEArchitecture, Get-PEDependencyInfo, Test-PEVCRedistDependency, Get-PortableExecutableArchitectureInfo, Read-ArchitectureFromPortableExecutable, Test-PortableExecutableArchitecture, Get-PortableExecutableVCRedistInfo, Test-PortableExecutableVCRedistDependency
