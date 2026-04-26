# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# Force stop on error
$ErrorActionPreference = 'Stop'

# Constants
$INNO_SETUP_ID_SIZE = 64
$INNO_SETUP_LDR_OFFSET_TABLE_RESOURCE = 11111
$INNO_RT_RCDATA = 10
$INNO_SIGNATURE_PATTERN = '^Inno Setup Setup Data \(([^)]+)\)(?: \(([uU])\))?$'
$INNO_OFFSET_TABLE_ID = [System.Text.Encoding]::ASCII.GetString([byte[]](0x72, 0x44, 0x6C, 0x50, 0x74, 0x53, 0xCD, 0xE6, 0xD7, 0x7B, 0x0B, 0x2A))
$INNO_OFFSET_TABLE_VERSION_1_SIZE = 44
$INNO_OFFSET_TABLE_VERSION_2_SIZE = 64
$INNO_ENCRYPTION_HEADER_SIZE_6500 = 49
$INNO_MAX_CHUNK_SIZE = 4096

function Get-Assembly {
  <#
  .SYNOPSIS
    Get a managed compression assembly used for static installer parsing
  .PARAMETER Name
    The assembly file name under Modules\PackageModule\Assets
  #>
  [OutputType([System.IO.FileInfo])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The assembly file name under Modules\PackageModule\Assets')]
    [string]$Name
  )

  if (Test-Path -Path ($Path = Join-Path $PSScriptRoot '..' 'Assets' $Name)) {
    return Get-Item -Path $Path -Force
  } else {
    throw "The $Name assembly could not be found"
  }
}

function Import-Assembly {
  <#
  .SYNOPSIS
    Load the managed compression assemblies used for Inno Setup parsing
  #>

  if (-not ([System.Management.Automation.PSTypeName]'SharpCompress.Compressors.LZMA.LzmaStream').Type) {
    $LoadContext = [System.Runtime.Loader.AssemblyLoadContext]::Default

    foreach ($AssemblyName in @('ZstdSharp.dll', 'SharpCompress.dll')) {
      $AssemblyPath = (Get-Assembly -Name $AssemblyName).FullName
      $AssemblySimpleName = [System.IO.Path]::GetFileNameWithoutExtension($AssemblyName)

      if (-not [AppDomain]::CurrentDomain.GetAssemblies().Where({ $_.GetName().Name -eq $AssemblySimpleName }, 'First')) {
        $LoadContext.LoadFromAssemblyPath($AssemblyPath) | Out-Null
      }
    }
  }
}

Import-Assembly

function Import-InnoNativeMethods {
  <#
  .SYNOPSIS
    Load the Win32 resource helpers used to read the Inno Setup offset table
  #>

  if (-not ([System.Management.Automation.PSTypeName]'Dumplings.PackageModule.InnoNativeMethods').Type) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace Dumplings.PackageModule
{
    public static class InnoNativeMethods
    {
        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr LoadLibraryEx(string lpFileName, IntPtr hFile, uint dwFlags);

        [DllImport("kernel32", SetLastError = true)]
        public static extern IntPtr FindResource(IntPtr hModule, IntPtr lpName, IntPtr lpType);

        [DllImport("kernel32", SetLastError = true)]
        public static extern IntPtr LoadResource(IntPtr hModule, IntPtr hResInfo);

        [DllImport("kernel32", SetLastError = true)]
        public static extern IntPtr LockResource(IntPtr hResData);

        [DllImport("kernel32", SetLastError = true)]
        public static extern uint SizeofResource(IntPtr hModule, IntPtr hResInfo);

        [DllImport("kernel32", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool FreeLibrary(IntPtr hModule);
    }
}
'@
  }
}

function Get-InstallerCrc32 {
  <#
  .SYNOPSIS
    Calculate the CRC32 checksum for a byte array
  .PARAMETER Bytes
    The bytes to hash
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The bytes to hash')]
    [byte[]]$Bytes
  )

  begin {
    if (-not $Script:InstallerCrc32Table) {
      $Script:InstallerCrc32Table = for ($i = 0; $i -lt 256; $i++) {
        $Crc = [uint32]$i
        for ($j = 0; $j -lt 8; $j++) {
          if (($Crc -band 1) -ne 0) {
            $Crc = 0xEDB88320 -bxor ($Crc -shr 1)
          } else {
            $Crc = $Crc -shr 1
          }
        }
        $Crc
      }
    }
  }

  process {
    $Crc = [uint32]4294967295
    foreach ($Byte in $Bytes) {
      $Index = ($Crc -bxor $Byte) -band 0xFF
      $Crc = $Script:InstallerCrc32Table[$Index] -bxor ($Crc -shr 8)
    }
    return [System.BitConverter]::ToInt32([System.BitConverter]::GetBytes([uint32]($Crc -bxor [uint32]4294967295)), 0)
  }
}

function Get-InnoResourceBytes {
  <#
  .SYNOPSIS
    Read a native PE resource from an Inno installer
  .PARAMETER Path
    The path to the installer
  .PARAMETER Id
    The integer resource ID
  #>
  [OutputType([byte[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path,

    [Parameter(Mandatory, HelpMessage = 'The integer resource ID')]
    [int]$Id
  )

  Import-InnoNativeMethods

  $LibraryHandle = [Dumplings.PackageModule.InnoNativeMethods]::LoadLibraryEx((Get-Item -Path $Path -Force).FullName, [IntPtr]::Zero, 2)
  if ($LibraryHandle -eq [IntPtr]::Zero) { throw 'Failed to load the installer as a data file' }

  try {
    $ResourceHandle = [Dumplings.PackageModule.InnoNativeMethods]::FindResource($LibraryHandle, [IntPtr]$Id, [IntPtr]$Script:INNO_RT_RCDATA)
    if ($ResourceHandle -eq [IntPtr]::Zero) { throw 'The requested Inno resource could not be found' }

    $ResourceSize = [Dumplings.PackageModule.InnoNativeMethods]::SizeofResource($LibraryHandle, $ResourceHandle)
    $ResourceDataHandle = [Dumplings.PackageModule.InnoNativeMethods]::LoadResource($LibraryHandle, $ResourceHandle)
    $ResourcePointer = [Dumplings.PackageModule.InnoNativeMethods]::LockResource($ResourceDataHandle)

    $Bytes = New-Object 'byte[]' ([int]$ResourceSize)
    [System.Runtime.InteropServices.Marshal]::Copy($ResourcePointer, $Bytes, 0, [int]$ResourceSize)
    return $Bytes
  } finally {
    [Dumplings.PackageModule.InnoNativeMethods]::FreeLibrary($LibraryHandle) | Out-Null
  }
}

function Get-InnoOffsetTable {
  <#
  .SYNOPSIS
    Read and validate the Inno Setup loader offset table
  .PARAMETER Path
    The path to the installer
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path
  )

  $Bytes = Get-InnoResourceBytes -Path $Path -Id $Script:INNO_SETUP_LDR_OFFSET_TABLE_RESOURCE
  $Identifier = [System.Text.Encoding]::ASCII.GetString($Bytes, 0, 12)
  if ($Identifier -ne $Script:INNO_OFFSET_TABLE_ID) { throw 'The Inno Setup offset table identifier is invalid' }

  $Version = [System.BitConverter]::ToUInt32($Bytes, 12)

  switch ($Version) {
    1 {
      if ($Bytes.Length -lt $Script:INNO_OFFSET_TABLE_VERSION_1_SIZE) { throw 'The Inno Setup offset table is truncated' }
      $TableBytes = $Bytes[0..($Script:INNO_OFFSET_TABLE_VERSION_1_SIZE - 1)]
      $StoredCrc = [System.BitConverter]::ToInt32($TableBytes, 40)
      $ExpectedCrc = Get-InstallerCrc32 -Bytes $TableBytes[0..39]
      if ($StoredCrc -ne $ExpectedCrc) { throw 'The Inno Setup offset table CRC is invalid' }

      return [pscustomobject]@{
        Version   = $Version
        TotalSize = [System.BitConverter]::ToUInt32($TableBytes, 16)
        Offset0   = [System.BitConverter]::ToUInt32($TableBytes, 32)
        Offset1   = [System.BitConverter]::ToUInt32($TableBytes, 36)
      }
    }
    2 {
      if ($Bytes.Length -lt $Script:INNO_OFFSET_TABLE_VERSION_2_SIZE) { throw 'The Inno Setup offset table is truncated' }
      $TableBytes = $Bytes[0..($Script:INNO_OFFSET_TABLE_VERSION_2_SIZE - 1)]
      $StoredCrc = [System.BitConverter]::ToInt32($TableBytes, 60)
      $ExpectedCrc = Get-InstallerCrc32 -Bytes $TableBytes[0..59]
      if ($StoredCrc -ne $ExpectedCrc) { throw 'The Inno Setup offset table CRC is invalid' }

      return [pscustomobject]@{
        Version   = $Version
        TotalSize = [System.BitConverter]::ToInt64($TableBytes, 16)
        Offset0   = [System.BitConverter]::ToInt64($TableBytes, 40)
        Offset1   = [System.BitConverter]::ToInt64($TableBytes, 48)
      }
    }
    default { throw "Unsupported Inno Setup offset table version: $Version" }
  }
}

function Get-InnoVersionNumber {
  <#
  .SYNOPSIS
    Convert an Inno Setup signature version string to its numeric form
  .PARAMETER Version
    The version string from the setup signature
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The version string from the setup signature')]
    [string]$Version
  )

  $Match = [regex]::Match($Version, '^(\d+)\.(\d+)\.(\d+)')
  if (-not $Match.Success) { throw "Unsupported Inno Setup signature version: $Version" }

  return ([int]$Match.Groups[1].Value * 1000) + ([int]$Match.Groups[2].Value * 100) + [int]$Match.Groups[3].Value
}

function Get-InnoLayout {
  <#
  .SYNOPSIS
    Get the header layout information for a supported Inno Setup version
  .PARAMETER VersionNumber
    The numeric Inno Setup version
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The numeric Inno Setup version')]
    [int]$VersionNumber
  )

  if ($VersionNumber -ge 6700) {
    return [pscustomobject]@{ HeaderStringCount = 39; HeaderAnsiStringCount = 4; UsesInt64BlockHeader = $true }
  } elseif ($VersionNumber -ge 6500) {
    return [pscustomobject]@{ HeaderStringCount = 34; HeaderAnsiStringCount = 4; UsesInt64BlockHeader = $false }
  } elseif ($VersionNumber -ge 6300) {
    return [pscustomobject]@{ HeaderStringCount = 32; HeaderAnsiStringCount = 4; UsesInt64BlockHeader = $false }
  } elseif ($VersionNumber -ge 6000) {
    return [pscustomobject]@{ HeaderStringCount = 30; HeaderAnsiStringCount = 4; UsesInt64BlockHeader = $false }
  } else {
    throw "Unsupported Inno Setup version: $VersionNumber"
  }
}

function Test-InnoCompressedBlockHeader {
  <#
  .SYNOPSIS
    Validate the compressed block header that precedes the setup header stream
  .PARAMETER Reader
    The binary reader for the installer
  .PARAMETER Offset
    The candidate compressed block offset
  .PARAMETER UsesInt64BlockHeader
    Whether the block header stores the size as Int64
  .PARAMETER FileLength
    The installer file length
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The binary reader for the installer')]
    [System.IO.BinaryReader]$Reader,

    [Parameter(Mandatory, HelpMessage = 'The candidate compressed block offset')]
    [long]$Offset,

    [Parameter(Mandatory, HelpMessage = 'Whether the block header stores the size as Int64')]
    [bool]$UsesInt64BlockHeader,

    [Parameter(Mandatory, HelpMessage = 'The installer file length')]
    [long]$FileLength
  )

  $HeaderLength = $UsesInt64BlockHeader ? 9 : 5
  if ($Offset + 4 + $HeaderLength -gt $FileLength) { return }

  $Reader.BaseStream.Seek($Offset, 'Begin') | Out-Null
  $StoredCrc = $Reader.ReadInt32()
  $HeaderBytes = $Reader.ReadBytes($HeaderLength)
  if ($HeaderBytes.Length -ne $HeaderLength) { return }
  if ($StoredCrc -ne (Get-InstallerCrc32 -Bytes $HeaderBytes)) { return }

  $StoredSize = if ($UsesInt64BlockHeader) {
    [System.BitConverter]::ToInt64($HeaderBytes, 0)
  } else {
    [System.BitConverter]::ToUInt32($HeaderBytes, 0)
  }

  if ($StoredSize -le 0 -or $Offset + 4 + $HeaderLength + $StoredSize -gt $FileLength) { return }

  return [pscustomobject]@{
    HeaderOffset = $Offset
    StoredSize   = $StoredSize
    Compressed   = [bool]$HeaderBytes[$HeaderLength - 1]
  }
}

function Get-InnoHeaderBlock {
  <#
  .SYNOPSIS
    Read and decompress the Inno Setup header block
  .PARAMETER Path
    The path to the installer
  .PARAMETER Offset0
    The offset of the embedded setup data
  .PARAMETER Layout
    The supported Inno header layout
  .PARAMETER VersionNumber
    The numeric Inno Setup version
  #>
  [OutputType([byte[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path,

    [Parameter(Mandatory, HelpMessage = 'The offset of the embedded setup data')]
    [long]$Offset0,

    [Parameter(Mandatory, HelpMessage = 'The supported Inno header layout')]
    [pscustomobject]$Layout,

    [Parameter(Mandatory, HelpMessage = 'The numeric Inno Setup version')]
    [int]$VersionNumber
  )

  $InstallerPath = (Get-Item -Path $Path -Force).FullName
  $FileStream = [System.IO.File]::OpenRead($InstallerPath)
  $Reader = [System.IO.BinaryReader]::new($FileStream)

  try {
    $Reader.BaseStream.Seek($Offset0, 'Begin') | Out-Null

    # Offset0 points to the setup signature that precedes the compressed header stream.
    $SignatureBytes = $Reader.ReadBytes($Script:INNO_SETUP_ID_SIZE)
    if ($SignatureBytes.Length -ne $Script:INNO_SETUP_ID_SIZE) { throw 'The Inno Setup signature is truncated' }

    $HeaderOffset = $null
    $CandidateOffsets = if ($VersionNumber -ge 6500) {
      @(
        $Offset0 + $Script:INNO_SETUP_ID_SIZE + 4 + $Script:INNO_ENCRYPTION_HEADER_SIZE_6500
        $Offset0 + $Script:INNO_SETUP_ID_SIZE + 4 + 52
        $Offset0 + $Script:INNO_SETUP_ID_SIZE + 4 + 56
      )
    } else {
      @($Offset0 + $Script:INNO_SETUP_ID_SIZE)
    }

    foreach ($CandidateOffset in $CandidateOffsets) {
      $HeaderOffset = Test-InnoCompressedBlockHeader -Reader $Reader -Offset $CandidateOffset -UsesInt64BlockHeader $Layout.UsesInt64BlockHeader -FileLength $FileStream.Length
      if ($HeaderOffset) { break }
    }

    if (-not $HeaderOffset) { throw 'The Inno Setup header block could not be located' }
    if (-not $HeaderOffset.Compressed) { throw 'Only compressed Inno Setup header blocks are supported' }

    $Reader.BaseStream.Seek($HeaderOffset.HeaderOffset + 4 + ($Layout.UsesInt64BlockHeader ? 9 : 5), 'Begin') | Out-Null

    $CompressedBytes = [System.Collections.Generic.List[byte]]::new()
    $Remaining = [long]$HeaderOffset.StoredSize

    while ($Remaining -gt 0) {
      $ChunkCrc = $Reader.ReadInt32()
      $Remaining -= 4

      $ChunkLength = [int][Math]::Min($Script:INNO_MAX_CHUNK_SIZE, $Remaining)
      $ChunkBytes = $Reader.ReadBytes($ChunkLength)
      if ($ChunkBytes.Length -ne $ChunkLength) { throw 'The Inno Setup header block is truncated' }
      if ($ChunkCrc -ne (Get-InstallerCrc32 -Bytes $ChunkBytes)) { throw 'The Inno Setup header chunk CRC is invalid' }

      $CompressedBytes.AddRange($ChunkBytes)
      $Remaining -= $ChunkLength
    }

    $RawLzmaBytes = $CompressedBytes.ToArray()
    if ($RawLzmaBytes.Length -lt 6) { throw 'The Inno Setup header stream is too small' }

    # The header stream is stored as raw LZMA properties followed by the compressed bytes.
    $Properties = $RawLzmaBytes[0..4]
    $CompressedStream = [System.IO.MemoryStream]::new($RawLzmaBytes, 5, $RawLzmaBytes.Length - 5, $false)
    $Decoder = [SharpCompress.Compressors.LZMA.LzmaStream]::new($Properties, $CompressedStream)
    $Buffer = New-Object 'byte[]' $Script:INNO_MAX_CHUNK_SIZE
    $OutputStream = [System.IO.MemoryStream]::new()

    try {
      while (($Read = $Decoder.Read($Buffer, 0, $Buffer.Length)) -gt 0) {
        $OutputStream.Write($Buffer, 0, $Read)
      }

      return $OutputStream.ToArray()
    } finally {
      $Decoder.Dispose()
      $CompressedStream.Dispose()
      $OutputStream.Dispose()
    }
  } finally {
    $Reader.Close()
    $FileStream.Close()
  }
}

function Read-InnoWideStrings {
  <#
  .SYNOPSIS
    Decode the fixed-order wide string header values from an Inno Setup header stream
  .PARAMETER Bytes
    The decompressed header stream bytes
  .PARAMETER Count
    The number of wide strings to read
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The decompressed header stream bytes')]
    [byte[]]$Bytes,

    [Parameter(Mandatory, HelpMessage = 'The number of wide strings to read')]
    [int]$Count
  )

  $Stream = [System.IO.MemoryStream]::new($Bytes, $false)
  $Reader = [System.IO.BinaryReader]::new($Stream)

  try {
    $Values = [System.Collections.Generic.List[string]]::new()

    for ($i = 0; $i -lt $Count; $i++) {
      $Length = $Reader.ReadInt32()
      if ($Length -lt 0 -or $Length -gt ($Stream.Length - $Stream.Position)) { throw 'The Inno Setup header string length is invalid' }

      if ($Length -eq 0) {
        $Values.Add('')
      } else {
        $Values.Add([System.Text.Encoding]::Unicode.GetString($Reader.ReadBytes($Length)))
      }
    }

    return $Values.ToArray()
  } finally {
    $Reader.Close()
    $Stream.Close()
  }
}

function Resolve-InnoDefaultDirectory {
  <#
  .SYNOPSIS
    Resolve the common deterministic directory constants used in DefaultDirName
  .PARAMETER Value
    The raw DefaultDirName value
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The raw DefaultDirName value')]
    [AllowEmptyString()]
    [string]$Value
  )

  $Replacements = [ordered]@{
    '{autopf}'   = $env:ProgramFiles
    '{pf}'       = $env:ProgramFiles
    '{pf32}'     = (${env:ProgramFiles(x86)} ?? $env:ProgramFiles)
    '{autopf32}' = (${env:ProgramFiles(x86)} ?? $env:ProgramFiles)
    '{pf64}'     = (${env:ProgramW6432} ?? $env:ProgramFiles)
    '{autopf64}' = (${env:ProgramW6432} ?? $env:ProgramFiles)
    '{commonpf}' = $env:ProgramFiles
  }

  $ResolvedValue = $Value
  foreach ($Name in $Replacements.Keys) {
    if ($ResolvedValue.StartsWith($Name, [System.StringComparison]::OrdinalIgnoreCase)) {
      return $ResolvedValue.Replace($Name, $Replacements[$Name])
    }
  }

  return $ResolvedValue
}

function Test-InnoResolvedValue {
  <#
  .SYNOPSIS
    Test whether an Inno Setup metadata string is deterministic enough to expose directly
  .PARAMETER Value
    The metadata value
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The metadata value')]
    [AllowEmptyString()]
    [string]$Value
  )

  if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
  if ($Value -match '\{code:') { return $false }
  if ($Value -match '^\{[A-Za-z]+:[^}]+\}$') { return $false }
  return $true
}

function Get-InnoInfo {
  <#
  .SYNOPSIS
    Get static metadata from an Inno Setup installer
  .PARAMETER Path
    The path to the Inno Setup installer
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Inno Setup installer')]
    [string]$Path
  )

  process {
    $InstallerPath = (Get-Item -Path $Path -Force).FullName
    $OffsetTable = Get-InnoOffsetTable -Path $InstallerPath

    $FileStream = [System.IO.File]::OpenRead($InstallerPath)
    $Reader = [System.IO.BinaryReader]::new($FileStream)

    try {
      $Reader.BaseStream.Seek($OffsetTable.Offset0, 'Begin') | Out-Null
      $SignatureBytes = $Reader.ReadBytes($Script:INNO_SETUP_ID_SIZE)
      $Signature = [System.Text.Encoding]::ASCII.GetString($SignatureBytes).Trim([char]0)
    } finally {
      $Reader.Close()
      $FileStream.Close()
    }

    $SignatureMatch = [regex]::Match($Signature, $Script:INNO_SIGNATURE_PATTERN)
    if (-not $SignatureMatch.Success) { throw 'The file is not a supported Inno Setup installer' }

    $VersionNumber = Get-InnoVersionNumber -Version $SignatureMatch.Groups[1].Value
    $Layout = Get-InnoLayout -VersionNumber $VersionNumber
    $HeaderBytes = Get-InnoHeaderBlock -Path $InstallerPath -Offset0 $OffsetTable.Offset0 -Layout $Layout -VersionNumber $VersionNumber
    $HeaderValues = Read-InnoWideStrings -Bytes $HeaderBytes -Count $Layout.HeaderStringCount

    $AppName = $HeaderValues[0]
    $AppVerName = $HeaderValues[1]
    $AppId = $HeaderValues[2]
    $AppPublisher = $HeaderValues[4]
    $AppVersion = $HeaderValues[9]
    $DefaultDirName = $HeaderValues[10]
    $UninstallDisplayName = $HeaderValues[14]

    $DisplayName = if (Test-InnoResolvedValue -Value $UninstallDisplayName) {
      $UninstallDisplayName
    } elseif (Test-InnoResolvedValue -Value $AppVerName) {
      $AppVerName
    } else {
      $AppName
    }

    $ResolvedDefaultDirName = Resolve-InnoDefaultDirectory -Value $DefaultDirName
    $Scope = if (
      $ResolvedDefaultDirName.StartsWith($env:ProgramFiles, [System.StringComparison]::OrdinalIgnoreCase) -or
      (${env:ProgramFiles(x86)} -and $ResolvedDefaultDirName.StartsWith(${env:ProgramFiles(x86)}, [System.StringComparison]::OrdinalIgnoreCase))
    ) {
      'machine'
    } elseif (
      $ResolvedDefaultDirName.StartsWith($env:LOCALAPPDATA, [System.StringComparison]::OrdinalIgnoreCase) -or
      $ResolvedDefaultDirName.StartsWith($env:APPDATA, [System.StringComparison]::OrdinalIgnoreCase) -or
      $ResolvedDefaultDirName.StartsWith($env:USERPROFILE, [System.StringComparison]::OrdinalIgnoreCase)
    ) {
      'user'
    } else {
      $null
    }

    return [pscustomobject]@{
      Path                   = $InstallerPath
      InstallerType          = 'Inno'
      DisplayVersion         = $AppVersion
      DisplayName            = $DisplayName
      Publisher              = $AppPublisher
      ProductCode            = $AppId
      DefaultInstallLocation = $ResolvedDefaultDirName
      Scope                  = $Scope
      AppName                = $AppName
      AppVerName             = $AppVerName
      AppVersion             = $AppVersion
      AppId                  = $AppId
      UninstallDisplayName   = $UninstallDisplayName
      Signature              = $Signature
      VersionNumber          = $VersionNumber
    }
  }
}

function Read-ProductVersionFromInno {
  <#
  .SYNOPSIS
    Read the product version from an Inno Setup installer
  .PARAMETER Path
    The path to the Inno Setup installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Inno Setup installer')]
    [string]$Path
  )

  process {
    $Info = Get-InnoInfo -Path $Path

    if (Test-InnoResolvedValue -Value $Info.AppVersion) { return $Info.AppVersion }

    $Match = [regex]::Match($Info.AppVerName, '(\d+(?:[.-]\d+)+)')
    if ($Match.Success) { return $Match.Groups[1].Value }

    throw 'The Inno Setup installer does not expose a deterministic version value'
  }
}

function Read-ProductNameFromInno {
  <#
  .SYNOPSIS
    Read the product name from an Inno Setup installer
  .PARAMETER Path
    The path to the Inno Setup installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Inno Setup installer')]
    [string]$Path
  )

  process {
    $Info = Get-InnoInfo -Path $Path
    if ([string]::IsNullOrWhiteSpace($Info.DisplayName)) { throw 'The Inno Setup installer does not expose a product name' }
    return $Info.DisplayName
  }
}

function Read-PublisherFromInno {
  <#
  .SYNOPSIS
    Read the publisher from an Inno Setup installer
  .PARAMETER Path
    The path to the Inno Setup installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Inno Setup installer')]
    [string]$Path
  )

  process {
    $Info = Get-InnoInfo -Path $Path
    if ([string]::IsNullOrWhiteSpace($Info.Publisher)) { throw 'The Inno Setup installer does not expose a publisher value' }
    return $Info.Publisher
  }
}

function Read-ProductCodeFromInno {
  <#
  .SYNOPSIS
    Read the AppId value from an Inno Setup installer
  .PARAMETER Path
    The path to the Inno Setup installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Inno Setup installer')]
    [string]$Path
  )

  process {
    $Info = Get-InnoInfo -Path $Path
    if ([string]::IsNullOrWhiteSpace($Info.ProductCode)) { throw 'The Inno Setup installer does not expose an AppId value' }
    return $Info.ProductCode
  }
}

Export-ModuleMember -Function Get-InnoInfo, Read-ProductVersionFromInno, Read-ProductNameFromInno, Read-PublisherFromInno, Read-ProductCodeFromInno
