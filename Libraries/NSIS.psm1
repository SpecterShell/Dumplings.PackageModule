# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# Force stop on error
$ErrorActionPreference = 'Stop'

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
    Load the managed compression assemblies used for NSIS parsing
  #>

  if (-not ([System.Management.Automation.PSTypeName]'SharpCompress.Compressors.LZMA.LzmaStream').Type) {
    $LoadContext = [System.Runtime.Loader.AssemblyLoadContext]::Default

    # Load the dependency first so SharpCompress can resolve its optional codec reference in pwsh.
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

# Constants
$NSIS_FIRST_HEADER_SIZE = 28
$NSIS_FIRST_HEADER_SIGNATURE = [byte[]](0xEF, 0xBE, 0xAD, 0xDE, 0x4E, 0x75, 0x6C, 0x6C, 0x73, 0x6F, 0x66, 0x74, 0x49, 0x6E, 0x73, 0x74)
$NSIS_HEADER_OFFSET_LANG_TABLE_SIZE = 32
$NSIS_HEADER_OFFSET_CODE_ON_INIT = 40
$NSIS_HEADER_OFFSET_CODE_ON_INST_SUCCESS = 44
$NSIS_HEADER_OFFSET_INSTALL_DIRECTORY = 212
$NSIS_HEADER_OFFSET_INSTALL_DIRECTORY_AUTO_APPEND = 216
$NSIS_BLOCK_HEADER_COUNT = 8
$NSIS_BLOCK_HEADER_SIZE_32 = 8
$NSIS_BLOCK_HEADER_SIZE_64 = 12
$NSIS_ENTRY_SIZE = 28
$NSIS_SECTION_OFFSET_NAME = 0
$NSIS_SECTION_OFFSET_CODE = 12
$NSIS_DEFAULT_LANGUAGE = 1033
$NSIS_MAX_WATCHDOG_MULTIPLIER = 2
$NSIS_UNINSTALL_KEY_PATTERN = '(?i)^Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\'
$NSIS_UNPACKED_HEADER_SOLID_FLAG = [uint32]2147483648

$NSIS_PREDEFINED_VAR_CMDLINE = 20
$NSIS_PREDEFINED_VAR_INSTDIR = 21
$NSIS_PREDEFINED_VAR_OUTDIR = 22
$NSIS_PREDEFINED_VAR_EXEDIR = 23
$NSIS_PREDEFINED_VAR_LANGUAGE = 24
$NSIS_PREDEFINED_VAR_TEMP = 25
$NSIS_PREDEFINED_VAR_PLUGINSDIR = 26
$NSIS_PREDEFINED_VAR_EXEPATH = 27
$NSIS_PREDEFINED_VAR_EXEFILE = 28
$NSIS_PREDEFINED_VAR_HWNDPARENT = 29
$NSIS_PREDEFINED_VAR_CLICK = 30
$NSIS_PREDEFINED_VAR__OUTDIR = 31

$NSIS_EXEC_FLAG_SHELL_VAR_CONTEXT = 1
$NSIS_EXEC_FLAG_REG_VIEW = 12

$NSIS_REG_ROOT_SHCTX = [uint32]0
$NSIS_REG_ROOT_HKCR = [uint32]2147483648
$NSIS_REG_ROOT_HKCU = [uint32]2147483649
$NSIS_REG_ROOT_HKLM = [uint32]2147483650
$NSIS_REG_ROOT_HKU = [uint32]2147483651
$NSIS_REG_ROOT_HKCC = [uint32]2147483653

$NSIS_REG_TYPE_STRING = 1
$NSIS_REG_TYPE_EXPAND_STRING = 2
$NSIS_REG_TYPE_DWORD = 4

$NSIS_OPCODE_INVALID = 0
$NSIS_OPCODE_RETURN = 1
$NSIS_OPCODE_JUMP = 2
$NSIS_OPCODE_ABORT = 3
$NSIS_OPCODE_QUIT = 4
$NSIS_OPCODE_CALL = 5
$NSIS_OPCODE_CREATE_DIR = 11
$NSIS_OPCODE_IF_FILE_EXISTS = 12
$NSIS_OPCODE_SET_FLAG = 13
$NSIS_OPCODE_IF_FLAG = 14
$NSIS_OPCODE_GET_FLAG = 15
$NSIS_OPCODE_STR_LEN = 24
$NSIS_OPCODE_ASSIGN_VAR = 25
$NSIS_OPCODE_STR_CMP = 26
$NSIS_OPCODE_READ_ENV = 27
$NSIS_OPCODE_INT_CMP = 28
$NSIS_OPCODE_INT_OP = 29
$NSIS_OPCODE_INT_FMT = 30
$NSIS_OPCODE_PUSH_POP = 31
$NSIS_OPCODE_DELETE_REG = 50
$NSIS_OPCODE_WRITE_REG = 51
$NSIS_OPCODE_READ_REG = 52
$NSIS_OPCODE_WRITE_UNINSTALLER = 62

$NSIS_PUSH_OPERATION = 0
$NSIS_POP_OPERATION = 1

# Deterministic shell folder names adapted to the local machine paths used by task scripts.
$NSIS_SHELL_STRINGS = @(
  'Desktop',
  'Internet',
  'Programs',
  'Controls',
  'Printers',
  'Documents',
  'Favorites',
  'Startup',
  'Recent',
  'SendTo',
  'BitBucket',
  'StartMenu',
  $null,
  'Music',
  'Videos',
  $null,
  'Desktop',
  'Drives',
  'Network',
  'NetHood',
  'Fonts',
  'Templates',
  'StartMenu',
  'Programs',
  'Startup',
  'Desktop',
  $env:APPDATA,
  'PrintHood',
  $env:LOCALAPPDATA,
  'ALTStartUp',
  'ALTStartUp',
  'Favorites',
  'InternetCache',
  'Cookies',
  'History',
  $env:APPDATA,
  $env:windir,
  $env:windir,
  $(if (${env:ProgramW6432}) { ${env:ProgramW6432} } else { $env:ProgramFiles }),
  'Pictures',
  $env:USERPROFILE,
  (Join-Path $env:windir 'System32'),
  $(if (${env:ProgramFiles(x86)}) { ${env:ProgramFiles(x86)} } else { $env:ProgramFiles }),
  $(if (${env:CommonProgramW6432}) { ${env:CommonProgramW6432} } else { $env:CommonProgramFiles }),
  $(if (${env:CommonProgramFiles(x86)}) { ${env:CommonProgramFiles(x86)} } else { $env:CommonProgramFiles }),
  'Templates',
  'Documents',
  'AdminTools',
  'AdminTools',
  'Connections',
  $null,
  $null,
  $null,
  'Music',
  'Pictures',
  'Videos',
  'Resources',
  'ResourcesLocalized',
  'CommonOEMLinks',
  'CDBurnArea',
  $null,
  'ComputersNearMe'
)

function Get-PEInfo {
  <#
  .SYNOPSIS
    Read the PE machine type used to interpret the NSIS block headers
  .PARAMETER Path
    The path to the installer
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path
  )

  $Stream = [System.IO.File]::OpenRead((Get-Item -Path $Path -Force).FullName)
  $Reader = [System.IO.BinaryReader]::new($Stream)

  try {
    $Stream.Seek(60, 'Begin') | Out-Null
    $PEOffset = $Reader.ReadUInt32()
    $Stream.Seek($PEOffset + 4, 'Begin') | Out-Null
    $Machine = $Reader.ReadUInt16()
    $Stream.Seek($PEOffset + 24, 'Begin') | Out-Null
    $OptionalHeaderMagic = $Reader.ReadUInt16()

    return [pscustomobject]@{
      Machine  = $Machine
      Is64Bit  = $OptionalHeaderMagic -eq 0x20B
      IsArm64  = $Machine -eq 0xAA64
      IsAmd64  = $Machine -eq 0x8664
      IsX86    = $Machine -eq 0x014C
    }
  } finally {
    $Reader.Close()
    $Stream.Close()
  }
}

function Get-BytePatternOffset {
  <#
  .SYNOPSIS
    Find the first offset of a byte pattern in a byte array
  .PARAMETER Bytes
    The bytes to search
  .PARAMETER Pattern
    The byte pattern to locate
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The bytes to search')]
    [byte[]]$Bytes,

    [Parameter(Mandatory, HelpMessage = 'The byte pattern to locate')]
    [byte[]]$Pattern
  )

  for ($i = 0; $i -le $Bytes.Length - $Pattern.Length; $i++) {
    $Matched = $true
    for ($j = 0; $j -lt $Pattern.Length; $j++) {
      if ($Bytes[$i + $j] -ne $Pattern[$j]) {
        $Matched = $false
        break
      }
    }

    if ($Matched) { return $i }
  }

  return -1
}

function Test-NSISLzmaHeader {
  <#
  .SYNOPSIS
    Test whether a byte slice begins with the raw NSIS LZMA header form
  .PARAMETER Bytes
    The candidate header bytes
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The candidate header bytes')]
    [byte[]]$Bytes
  )

  return $Bytes.Length -ge 7 -and $Bytes[0] -eq 0x5D -and $Bytes[1] -eq 0x00 -and $Bytes[2] -eq 0x00 -and $Bytes[5] -eq 0x00 -and (($Bytes[6] -band 0x80) -eq 0)
}

function Get-NSISLzmaFilterLength {
  <#
  .SYNOPSIS
    Get the optional NSIS LZMA filter marker length
  .PARAMETER Bytes
    The candidate header bytes
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The candidate header bytes')]
    [byte[]]$Bytes
  )

  if (Test-NSISLzmaHeader -Bytes $Bytes) { return 0 }
  if ($Bytes.Length -ge 8 -and $Bytes[0] -le 1 -and (Test-NSISLzmaHeader -Bytes $Bytes[1..($Bytes.Length - 1)])) { return 1 }
  return -1
}

function Test-NSISBZip2Header {
  <#
  .SYNOPSIS
    Test whether a byte slice begins with the raw NSIS BZip2 header form
  .PARAMETER Bytes
    The candidate header bytes
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The candidate header bytes')]
    [byte[]]$Bytes
  )

  return $Bytes.Length -ge 2 -and $Bytes[0] -eq 0x31 -and $Bytes[1] -lt 14
}

function Test-NSISZlibHeader {
  <#
  .SYNOPSIS
    Test whether a byte slice begins with a zlib-wrapped DEFLATE header
  .PARAMETER Bytes
    The candidate header bytes
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The candidate header bytes')]
    [byte[]]$Bytes
  )

  if ($Bytes.Length -lt 2) { return $false }
  if (($Bytes[0] -band 0x0F) -ne 8) { return $false }
  if (($Bytes[0] -band 0xF0) -gt 0x70) { return $false }

  $Header = ($Bytes[0] -shl 8) -bor $Bytes[1]
  return ($Header % 31) -eq 0
}

function Get-NSISCompressionCandidates {
  <#
  .SYNOPSIS
    Get the ordered list of decoder candidates for a compressed NSIS header
  .PARAMETER Bytes
    The candidate compressed header bytes
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The candidate compressed header bytes')]
    [byte[]]$Bytes
  )

  $LzmaFilterLength = Get-NSISLzmaFilterLength -Bytes $Bytes
  if ($LzmaFilterLength -ge 0) { return @('Lzma') }
  if (Test-NSISBZip2Header -Bytes $Bytes) { return @('BZip2') }

  # Recent KDE/Prowise NSIS stubs store the payload as raw DEFLATE without the RFC1950 zlib wrapper.
  if (Test-NSISZlibHeader -Bytes $Bytes) {
    return @('Zlib', 'Deflate')
  } else {
    return @('Deflate', 'Zlib')
  }
}

function New-NSISDecoder {
  <#
  .SYNOPSIS
    Create a decoder stream for a compressed NSIS header payload
  .PARAMETER Compression
    The NSIS compression format
  .PARAMETER PayloadStream
    The compressed header payload stream
  .PARAMETER IsSolid
    Whether the NSIS header uses the solid layout
  .PARAMETER LzmaFilterLength
    The optional NSIS LZMA filter marker length
  #>
  [OutputType([System.IDisposable])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The NSIS compression format')]
    [ValidateSet('None', 'Lzma', 'BZip2', 'Zlib', 'Deflate')]
    [string]$Compression,

    [Parameter(Mandatory, HelpMessage = 'The compressed header payload stream')]
    [System.IO.Stream]$PayloadStream,

    [Parameter(Mandatory, HelpMessage = 'Whether the NSIS header uses the solid layout')]
    [bool]$IsSolid,

    [Parameter(HelpMessage = 'The optional NSIS LZMA filter marker length')]
    [int]$LzmaFilterLength = -1
  )

  switch ($Compression) {
    'Lzma' {
      if (-not $IsSolid -and $LzmaFilterLength -gt 0) { $null = $PayloadStream.ReadByte() }
      $Properties = New-Object 'byte[]' 5
      if ($PayloadStream.Read($Properties, 0, $Properties.Length) -ne $Properties.Length) { throw 'The NSIS LZMA properties are truncated' }
      return [SharpCompress.Compressors.LZMA.LzmaStream]::new($Properties, $PayloadStream)
    }
    'BZip2' { return [SharpCompress.Compressors.BZip2.BZip2Stream]::new($PayloadStream, [SharpCompress.Compressors.CompressionMode]::Decompress, $false) }
    'Zlib' { return [SharpCompress.Compressors.Deflate.ZlibStream]::new($PayloadStream, [SharpCompress.Compressors.CompressionMode]::Decompress) }
    'Deflate' { return [System.IO.Compression.DeflateStream]::new($PayloadStream, [System.IO.Compression.CompressionMode]::Decompress, $false) }
    'None' { return $PayloadStream }
    default { throw "Unsupported NSIS compression format: $Compression" }
  }
}

function Get-NSISHeaderData {
  <#
  .SYNOPSIS
    Locate and decompress the NSIS installer header without invoking external tools
  .PARAMETER Path
    The path to the installer
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path
  )

  $InstallerPath = (Get-Item -Path $Path -Force).FullName
  $Bytes = [System.IO.File]::ReadAllBytes($InstallerPath)
  $SignatureOffset = Get-BytePatternOffset -Bytes $Bytes -Pattern $Script:NSIS_FIRST_HEADER_SIGNATURE
  if ($SignatureOffset -lt 4) { throw 'The NSIS installer header could not be located' }

  $FirstHeaderOffset = $SignatureOffset - 4
  $LengthOfHeader = [System.BitConverter]::ToUInt32($Bytes, $FirstHeaderOffset + 20)
  $LengthOfFollowingData = [System.BitConverter]::ToUInt32($Bytes, $FirstHeaderOffset + 24)
  if ($LengthOfHeader -le 0) { throw 'The NSIS installer header size is invalid' }
  if ($LengthOfFollowingData -le $Script:NSIS_FIRST_HEADER_SIZE) { throw 'The NSIS installer data size is invalid' }

  $PayloadOffset = $FirstHeaderOffset + $Script:NSIS_FIRST_HEADER_SIZE
  if ($PayloadOffset + 12 -gt $Bytes.Length) { throw 'The NSIS compressed header is truncated' }

  $PayloadStream = [System.IO.MemoryStream]::new($Bytes, $PayloadOffset, $Bytes.Length - $PayloadOffset, $false)
  $Signature = New-Object 'byte[]' 12
  $null = $PayloadStream.Read($Signature, 0, $Signature.Length)

  $CompressedHeaderSize = [System.BitConverter]::ToUInt32($Signature, 0)
  $IsSolid = $true
  $CompressionCandidates = @()
  $CandidateHeader = $Signature
  $LzmaFilterLength = Get-NSISLzmaFilterLength -Bytes $Signature

  if ($CompressedHeaderSize -eq $LengthOfHeader) {
    $IsSolid = $false
    $CompressionCandidates = @('None')
  } elseif ($LzmaFilterLength -ge 0) {
    $CompressionCandidates = @('Lzma')
  } elseif (Test-NSISBZip2Header -Bytes $Signature) {
    $CompressionCandidates = @('BZip2')
  } elseif (Test-NSISZlibHeader -Bytes $Signature) {
    $CompressionCandidates = @('Zlib', 'Deflate')
  } elseif (($CompressedHeaderSize -band $Script:NSIS_UNPACKED_HEADER_SOLID_FLAG) -ne 0) {
    $IsSolid = $false
    $CompressedHeaderSize = $CompressedHeaderSize -band (-bnot $Script:NSIS_UNPACKED_HEADER_SOLID_FLAG)
    $CandidateHeader = $Signature[4..($Signature.Length - 1)]
    $CompressionCandidates = Get-NSISCompressionCandidates -Bytes $CandidateHeader
  } else {
    $CompressionCandidates = Get-NSISCompressionCandidates -Bytes $CandidateHeader
  }

  # The solid form starts directly with the codec stream. Non-solid installers prefix it with the packed header size.
  $PayloadDataOffset = $PayloadOffset + $(if ($IsSolid) { 0 } else { 4 })
  $PayloadDataLength = $Bytes.Length - $PayloadDataOffset
  $LastError = $null

  foreach ($Compression in $CompressionCandidates) {
    $PayloadStream = [System.IO.MemoryStream]::new($Bytes, $PayloadDataOffset, $PayloadDataLength, $false)
    $LzmaFilterLength = if ($Compression -eq 'Lzma') { Get-NSISLzmaFilterLength -Bytes $CandidateHeader } else { -1 }
    $Decoder = $null

    try {
      $Decoder = New-NSISDecoder -Compression $Compression -PayloadStream $PayloadStream -IsSolid $IsSolid -LzmaFilterLength $LzmaFilterLength

      if ($IsSolid -and $Compression -ne 'None') {
        $HeaderSizeBytes = New-Object 'byte[]' 4
        if ($Decoder.Read($HeaderSizeBytes, 0, $HeaderSizeBytes.Length) -ne $HeaderSizeBytes.Length) { throw 'The NSIS solid header length is truncated' }
        $EmbeddedHeaderLength = [System.BitConverter]::ToUInt32($HeaderSizeBytes, 0)
        if ($EmbeddedHeaderLength -ne $LengthOfHeader) { throw 'The NSIS solid header length does not match the first header' }
      }

      $HeaderBytes = New-Object 'byte[]' ([int]$LengthOfHeader)
      $Read = 0
      while ($Read -lt $HeaderBytes.Length) {
        $ChunkSize = $Decoder.Read($HeaderBytes, $Read, $HeaderBytes.Length - $Read)
        if ($ChunkSize -le 0) { break }
        $Read += $ChunkSize
      }
      if ($Read -ne $HeaderBytes.Length) { throw 'The NSIS header stream is truncated' }

      return [pscustomobject]@{
        Path              = $InstallerPath
        FirstHeaderOffset = $FirstHeaderOffset
        Compression       = $Compression
        IsSolid           = $IsSolid
        HeaderBytes       = $HeaderBytes
        PEInfo            = Get-PEInfo -Path $InstallerPath
      }
    } catch {
      $LastError = $_
    } finally {
      if ($Decoder -is [System.IDisposable]) { $Decoder.Dispose() }
      $PayloadStream.Dispose()
    }
  }

  throw "Failed to decode the NSIS header using $($CompressionCandidates -join ', '): $($LastError.Exception.Message)"
}

function Get-NSISBlockHeaders {
  <#
  .SYNOPSIS
    Read the NSIS block table from the decompressed header
  .PARAMETER HeaderBytes
    The decompressed NSIS header bytes
  .PARAMETER Is64Bit
    Whether the PE stub uses 64-bit NSIS block offsets
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The decompressed NSIS header bytes')]
    [byte[]]$HeaderBytes,

    [Parameter(Mandatory, HelpMessage = 'Whether the PE stub uses 64-bit NSIS block offsets')]
    [bool]$Is64Bit
  )

  # The common flags word is stored before the block table in the decompressed header stream.
  $Offset = 4
  $BlockHeaders = [System.Collections.Generic.List[object]]::new()

  for ($Index = 0; $Index -lt $Script:NSIS_BLOCK_HEADER_COUNT; $Index++) {
    $BlockOffset = if ($Is64Bit) {
      [System.BitConverter]::ToUInt64($HeaderBytes, $Offset)
    } else {
      [uint64][System.BitConverter]::ToUInt32($HeaderBytes, $Offset)
    }

    $CountOffset = if ($Is64Bit) { $Offset + 8 } else { $Offset + 4 }
    $BlockCount = [System.BitConverter]::ToUInt32($HeaderBytes, $CountOffset)

    $BlockHeaders.Add([pscustomobject]@{
        Index  = $Index
        Offset = $BlockOffset
        Count  = $BlockCount
      })

    $Offset += if ($Is64Bit) { $Script:NSIS_BLOCK_HEADER_SIZE_64 } else { $Script:NSIS_BLOCK_HEADER_SIZE_32 }
  }

  return $BlockHeaders.ToArray()
}

function Get-NSISHeaderLayout {
  <#
  .SYNOPSIS
    Get the important NSIS header pointers that drive static metadata parsing
  .PARAMETER HeaderBytes
    The decompressed NSIS header bytes
  .PARAMETER Is64Bit
    Whether the PE stub uses 64-bit NSIS block offsets
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The decompressed NSIS header bytes')]
    [byte[]]$HeaderBytes,

    [Parameter(Mandatory, HelpMessage = 'Whether the PE stub uses 64-bit NSIS block offsets')]
    [bool]$Is64Bit
  )

  $BlockHeaderSize = if ($Is64Bit) { $Script:NSIS_BLOCK_HEADER_SIZE_64 } else { $Script:NSIS_BLOCK_HEADER_SIZE_32 }
  $HeaderOffset = 4 + ($BlockHeaderSize * $Script:NSIS_BLOCK_HEADER_COUNT)

  return [pscustomobject]@{
    HeaderOffset                 = $HeaderOffset
    LanguageTableSize            = [System.BitConverter]::ToInt32($HeaderBytes, $HeaderOffset + $Script:NSIS_HEADER_OFFSET_LANG_TABLE_SIZE)
    CodeOnInit                   = [System.BitConverter]::ToInt32($HeaderBytes, $HeaderOffset + $Script:NSIS_HEADER_OFFSET_CODE_ON_INIT)
    CodeOnInstSuccess            = [System.BitConverter]::ToInt32($HeaderBytes, $HeaderOffset + $Script:NSIS_HEADER_OFFSET_CODE_ON_INST_SUCCESS)
    InstallDirectoryPointer      = [System.BitConverter]::ToInt32($HeaderBytes, $HeaderOffset + $Script:NSIS_HEADER_OFFSET_INSTALL_DIRECTORY)
    InstallDirectoryAutoAppend   = [System.BitConverter]::ToInt32($HeaderBytes, $HeaderOffset + $Script:NSIS_HEADER_OFFSET_INSTALL_DIRECTORY_AUTO_APPEND)
  }
}

function Get-NSISBlockBytes {
  <#
  .SYNOPSIS
    Slice a named NSIS block from the decompressed header
  .PARAMETER HeaderBytes
    The decompressed NSIS header bytes
  .PARAMETER BlockHeaders
    The parsed NSIS block headers
  .PARAMETER Index
    The block index
  #>
  [OutputType([byte[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The decompressed NSIS header bytes')]
    [byte[]]$HeaderBytes,

    [Parameter(Mandatory, HelpMessage = 'The parsed NSIS block headers')]
    [pscustomobject[]]$BlockHeaders,

    [Parameter(Mandatory, HelpMessage = 'The block index')]
    [int]$Index
  )

  $Start = [int]$BlockHeaders[$Index].Offset
  if ($Start -lt 0 -or $Start -gt $HeaderBytes.Length) { return @() }

  $End = $HeaderBytes.Length
  foreach ($BlockHeader in $BlockHeaders | Select-Object -Skip ($Index + 1)) {
    if ($BlockHeader.Offset -gt 0) {
      $End = [int]$BlockHeader.Offset
      break
    }
  }

  if ($End -lt $Start) { return @() }
  return $HeaderBytes[$Start..($End - 1)]
}

function Get-NSISPrimaryLanguageTable {
  <#
  .SYNOPSIS
    Select the primary NSIS language table used for string resolution
  .PARAMETER HeaderBytes
    The decompressed NSIS header bytes
  .PARAMETER BlockHeaders
    The parsed NSIS block headers
  .PARAMETER Layout
    The parsed NSIS header layout
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The decompressed NSIS header bytes')]
    [byte[]]$HeaderBytes,

    [Parameter(Mandatory, HelpMessage = 'The parsed NSIS block headers')]
    [pscustomobject[]]$BlockHeaders,

    [Parameter(Mandatory, HelpMessage = 'The parsed NSIS header layout')]
    [pscustomobject]$Layout
  )

  $LanguageTableBytes = Get-NSISBlockBytes -HeaderBytes $HeaderBytes -BlockHeaders $BlockHeaders -Index 4
  if ($LanguageTableBytes.Length -eq 0 -or $Layout.LanguageTableSize -le 0) { return $null }

  $CandidateTables = [System.Collections.Generic.List[object]]::new()
  for ($Offset = 0; $Offset + $Layout.LanguageTableSize -le $LanguageTableBytes.Length; $Offset += $Layout.LanguageTableSize) {
    $LanguageId = [System.BitConverter]::ToUInt16($LanguageTableBytes, $Offset)
    $StringOffsets = [System.Collections.Generic.List[int]]::new()

    for ($StringOffset = $Offset + 10; $StringOffset + 4 -le $Offset + $Layout.LanguageTableSize; $StringOffset += 4) {
      $StringOffsets.Add([System.BitConverter]::ToInt32($LanguageTableBytes, $StringOffset))
    }

    $CandidateTables.Add([pscustomobject]@{
        LanguageId    = $LanguageId
        DialogOffset  = [System.BitConverter]::ToUInt32($LanguageTableBytes, $Offset + 2)
        RightToLeft   = [System.BitConverter]::ToUInt32($LanguageTableBytes, $Offset + 6) -ne 0
        StringOffsets = $StringOffsets.ToArray()
      })
  }

  $PreferredTable = $CandidateTables.Where({ $_.LanguageId -eq $Script:NSIS_DEFAULT_LANGUAGE }, 'First')
  if ($PreferredTable) {
    return $PreferredTable[0]
  } else {
    return $CandidateTables | Select-Object -First 1
  }
}

function Get-NSISVersionInfo {
  <#
  .SYNOPSIS
    Detect whether the installer uses NSIS v2 or v3 string opcodes
  .PARAMETER StringsBlock
    The decompressed NSIS strings block
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The decompressed NSIS strings block')]
    [byte[]]$StringsBlock
  )

  $Unicode = $StringsBlock.Length -ge 2 -and $StringsBlock[0] -eq 0x00 -and $StringsBlock[1] -eq 0x00
  $NSIS2Count = 0
  $NSIS3Count = 0

  if ($Unicode) {
    for ($Index = 2; $Index + 3 -lt $StringsBlock.Length; $Index += 2) {
      if ($StringsBlock[$Index] -eq 0x00) {
        switch ($StringsBlock[$Index + 2]) {
          1 { $NSIS3Count++ }
          2 { $NSIS3Count++ }
          3 { $NSIS3Count++ }
          4 { $NSIS3Count++ }
          252 { $NSIS2Count++ }
          253 { $NSIS2Count++ }
          254 { $NSIS2Count++ }
          255 { $NSIS2Count++ }
        }
      }
    }
  } else {
    for ($Index = 0; $Index + 1 -lt $StringsBlock.Length; $Index++) {
      if ($StringsBlock[$Index] -eq 0x00) {
        switch ($StringsBlock[$Index + 1]) {
          1 { $NSIS3Count++ }
          2 { $NSIS3Count++ }
          3 { $NSIS3Count++ }
          4 { $NSIS3Count++ }
          252 { $NSIS2Count++ }
          253 { $NSIS2Count++ }
          254 { $NSIS2Count++ }
          255 { $NSIS2Count++ }
        }
      }
    }
  }

  return [pscustomobject]@{
    Unicode = $Unicode
    IsV3    = $NSIS3Count -ge $NSIS2Count
  }
}

function Get-NSISStringCodeKind {
  <#
  .SYNOPSIS
    Resolve an NSIS control code kind for the active installer version
  .PARAMETER Character
    The candidate control code
  .PARAMETER IsV3
    Whether the installer uses NSIS v3 control codes
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The candidate control code')]
    [uint16]$Character,

    [Parameter(Mandatory, HelpMessage = 'Whether the installer uses NSIS v3 control codes')]
    [bool]$IsV3
  )

  if ($IsV3) {
    switch ($Character) {
      1 { return 'Lang' }
      2 { return 'Shell' }
      3 { return 'Var' }
      4 { return 'Skip' }
      default { return $null }
    }
  } else {
    switch ($Character) {
      252 { return 'Skip' }
      253 { return 'Var' }
      254 { return 'Shell' }
      255 { return 'Lang' }
      default { return $null }
    }
  }
}

function Decode-NSISPackedNumber {
  <#
  .SYNOPSIS
    Decode the packed 15-bit NSIS number embedded in a string control code payload
  .PARAMETER Character
    The raw 16-bit control code payload
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The raw 16-bit control code payload')]
    [uint16]$Character
  )

  $MaskedCharacter = $Character -band 0x7F7F
  $Bytes = [System.BitConverter]::GetBytes($MaskedCharacter)
  return [int]($Bytes[0] -bor ($Bytes[1] -shl 7))
}

function Get-NSISVariableValue {
  <#
  .SYNOPSIS
    Resolve a compiled NSIS variable reference
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Index
    The compiled variable index
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The compiled variable index')]
    [int]$Index
  )

  if ($State.Variables.ContainsKey($Index)) { return [string]$State.Variables[$Index] }

  switch ($Index) {
    $Script:NSIS_PREDEFINED_VAR_CMDLINE { return '' }
    $Script:NSIS_PREDEFINED_VAR_EXEDIR { return Split-Path -Path $State.Path -Parent }
    $Script:NSIS_PREDEFINED_VAR_LANGUAGE { return [string]$State.LanguageTable.LanguageId }
    $Script:NSIS_PREDEFINED_VAR_TEMP { return [System.IO.Path]::GetTempPath().TrimEnd('\') }
    $Script:NSIS_PREDEFINED_VAR_PLUGINSDIR { return Join-Path ([System.IO.Path]::GetTempPath().TrimEnd('\')) 'NSIS' }
    $Script:NSIS_PREDEFINED_VAR_EXEPATH { return $State.Path }
    $Script:NSIS_PREDEFINED_VAR_EXEFILE { return Split-Path -Path $State.Path -Leaf }
    $Script:NSIS_PREDEFINED_VAR_CLICK { return 'Click Next to continue.' }
    default { return '' }
  }
}

function Set-NSISVariableValue {
  <#
  .SYNOPSIS
    Update a compiled NSIS variable and keep the derived install paths in sync
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Index
    The compiled variable index
  .PARAMETER Value
    The resolved string value
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The compiled variable index')]
    [int]$Index,

    [AllowEmptyString()]
    [Parameter(Mandatory, HelpMessage = 'The resolved string value')]
    [string]$Value
  )

  $State.Variables[$Index] = $Value

  switch ($Index) {
    $Script:NSIS_PREDEFINED_VAR_INSTDIR {
      $State.Variables[$Script:NSIS_PREDEFINED_VAR_OUTDIR] = $Value
      $State.Variables[$Script:NSIS_PREDEFINED_VAR__OUTDIR] = $Value
      if (-not [string]::IsNullOrWhiteSpace($Value)) { $State.Metadata.DefaultInstallLocation = $Value }
    }
    $Script:NSIS_PREDEFINED_VAR_OUTDIR { $State.Variables[$Script:NSIS_PREDEFINED_VAR__OUTDIR] = $Value }
    $Script:NSIS_PREDEFINED_VAR__OUTDIR { $State.Variables[$Script:NSIS_PREDEFINED_VAR_OUTDIR] = $Value }
    default { }
  }
}

function Resolve-NSISShellValue {
  <#
  .SYNOPSIS
    Resolve a compiled NSIS shell-folder control code
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Character
    The raw 16-bit shell payload
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The raw 16-bit shell payload')]
    [uint16]$Character
  )

  $Bytes = [System.BitConverter]::GetBytes($Character)
  $Index1 = $Bytes[0]
  $Index2 = $Bytes[1]

  if (($Index1 -band 0x80) -ne 0) {
    $StringOffset = $Index1 -band 0x3F
    $Is64BitFolder = ($Index1 -band 0x40) -ne 0
    $ShellString = Get-NSISString -State $State -RelativeOffset $StringOffset

    switch ($ShellString) {
      'ProgramFilesDir' {
        if ($Is64BitFolder) {
          return $(if (${env:ProgramW6432}) { ${env:ProgramW6432} } else { $env:ProgramFiles })
        } else {
          return $(if (${env:ProgramFiles(x86)}) { ${env:ProgramFiles(x86)} } else { $env:ProgramFiles })
        }
      }
      'CommonFilesDir' {
        if ($Is64BitFolder) {
          return $(if (${env:CommonProgramW6432}) { ${env:CommonProgramW6432} } else { $env:CommonProgramFiles })
        } else {
          return $(if (${env:CommonProgramFiles(x86)}) { ${env:CommonProgramFiles(x86)} } else { $env:CommonProgramFiles })
        }
      }
      default { return $ShellString }
    }
  }

  if ($Index1 -lt $Script:NSIS_SHELL_STRINGS.Count -and $Script:NSIS_SHELL_STRINGS[$Index1]) { return [string]$Script:NSIS_SHELL_STRINGS[$Index1] }
  if ($Index2 -lt $Script:NSIS_SHELL_STRINGS.Count -and $Script:NSIS_SHELL_STRINGS[$Index2]) { return [string]$Script:NSIS_SHELL_STRINGS[$Index2] }
  return ''
}

function Get-NSISString {
  <#
  .SYNOPSIS
    Decode a compiled NSIS string from the strings block
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER RelativeOffset
    The compiled relative string offset
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The compiled relative string offset')]
    [int]$RelativeOffset
  )

  if ($RelativeOffset -lt 0) {
    $LanguageIndex = [Math]::Abs($RelativeOffset + 1)
    if (-not $State.LanguageTable -or $LanguageIndex -ge $State.LanguageTable.StringOffsets.Count) { return '' }
    $ResolvedOffset = $State.LanguageTable.StringOffsets[$LanguageIndex]
    if ($ResolvedOffset -eq 0) { return '' }
    return Get-NSISString -State $State -RelativeOffset $ResolvedOffset
  }

  $Multiplier = if ($State.VersionInfo.Unicode) { 2 } else { 1 }
  $Offset = $RelativeOffset * $Multiplier
  if ($Offset -lt 0 -or $Offset -ge $State.StringsBlock.Length) { return '' }

  if ($State.VersionInfo.Unicode) {
    $EndOffset = $Offset
    while ($EndOffset + 1 -lt $State.StringsBlock.Length -and -not ($State.StringsBlock[$EndOffset] -eq 0x00 -and $State.StringsBlock[$EndOffset + 1] -eq 0x00)) { $EndOffset += 2 }
    if ($EndOffset -le $Offset) { return '' }
    $StringBytes = $State.StringsBlock[$Offset..($EndOffset - 1)]
  } else {
    $EndOffset = $Offset
    while ($EndOffset -lt $State.StringsBlock.Length -and $State.StringsBlock[$EndOffset] -ne 0x00) { $EndOffset++ }
    if ($EndOffset -le $Offset) { return '' }
    $StringBytes = $State.StringsBlock[$Offset..($EndOffset - 1)]
  }

  if ($StringBytes.Length -eq 0) { return '' }

  $Characters = [System.Collections.Generic.List[uint16]]::new()
  if ($State.VersionInfo.Unicode) {
    for ($Index = 0; $Index + 1 -lt $StringBytes.Length; $Index += 2) {
      $Characters.Add([System.BitConverter]::ToUInt16($StringBytes, $Index))
    }
  } else {
    foreach ($Byte in $StringBytes) { $Characters.Add([uint16]$Byte) }
  }

  $Builder = [System.Text.StringBuilder]::new()
  $Index = 0

  while ($Index -lt $Characters.Count) {
    $Current = $Characters[$Index]
    $CodeKind = Get-NSISStringCodeKind -Character $Current -IsV3 $State.VersionInfo.IsV3

    if ($CodeKind) {
      if ($Index + 1 -ge $Characters.Count) { break }

      if ($CodeKind -eq 'Skip') {
        $Current = $Characters[$Index + 1]
        $Index++
      } else {
        if ($State.VersionInfo.Unicode) {
          $Payload = $Characters[$Index + 1]
          $Index++
        } else {
          if ($Index + 2 -ge $Characters.Count) { break }
          $Payload = [uint16]($Characters[$Index + 1] -bor ($Characters[$Index + 2] -shl 8))
          $Index += 2
        }

        switch ($CodeKind) {
          'Var' { $null = $Builder.Append((Get-NSISVariableValue -State $State -Index (Decode-NSISPackedNumber -Character $Payload))) }
          'Shell' { $null = $Builder.Append((Resolve-NSISShellValue -State $State -Character $Payload)) }
          'Lang' {
            $LanguageIndex = Decode-NSISPackedNumber -Character $Payload
            if ($State.LanguageTable -and $LanguageIndex -lt $State.LanguageTable.StringOffsets.Count) {
              $StringOffset = $State.LanguageTable.StringOffsets[$LanguageIndex]
              if ($StringOffset -ne 0) { $null = $Builder.Append((Get-NSISString -State $State -RelativeOffset $StringOffset)) }
            }
          }
        }

        $Index++
        continue
      }
    }

    $null = $Builder.Append([char]$Current)
    $Index++
  }

  return $Builder.ToString()
}

function Get-NSISInt {
  <#
  .SYNOPSIS
    Resolve a compiled NSIS string operand into an integer
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER RelativeOffset
    The compiled relative string offset
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The compiled relative string offset')]
    [int]$RelativeOffset
  )

  $Value = (Get-NSISString -State $State -RelativeOffset $RelativeOffset).Trim()
  if ([string]::IsNullOrWhiteSpace($Value)) { return 0 }

  if ($Value.StartsWith('0x', [System.StringComparison]::OrdinalIgnoreCase)) {
    return [int]::Parse($Value.Substring(2), [System.Globalization.NumberStyles]::HexNumber, [System.Globalization.CultureInfo]::InvariantCulture)
  }

  $ParsedValue = 0
  if ([int]::TryParse($Value, [ref]$ParsedValue)) {
    return $ParsedValue
  } else {
    return 0
  }
}

function Resolve-NSISAddress {
  <#
  .SYNOPSIS
    Resolve an NSIS jump address, including the negative address indirection form
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Address
    The compiled jump address
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The compiled jump address')]
    [int]$Address
  )

  if ($Address -ge 0) { return $Address }

  $Index = [Math]::Abs($Address) - 1
  $VariableValue = Get-NSISVariableValue -State $State -Index $Index
  $ResolvedAddress = 0
  if ([int]::TryParse($VariableValue, [ref]$ResolvedAddress)) {
    return $ResolvedAddress
  } else {
    return 0
  }
}

function Add-NSISDirectory {
  <#
  .SYNOPSIS
    Record a directory in the simulated NSIS file system
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Path
    The directory path
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [AllowEmptyString()]
    [Parameter(Mandatory, HelpMessage = 'The directory path')]
    [string]$Path
  )

  if (-not [string]::IsNullOrWhiteSpace($Path)) { $null = $State.Directories.Add($Path.TrimEnd('\')) }
}

function Add-NSISFile {
  <#
  .SYNOPSIS
    Record a file in the simulated NSIS file system
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Path
    The file path
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [AllowEmptyString()]
    [Parameter(Mandatory, HelpMessage = 'The file path')]
    [string]$Path
  )

  if (-not [string]::IsNullOrWhiteSpace($Path)) { $null = $State.Files.Add($Path) }
}

function Test-NSISPathExists {
  <#
  .SYNOPSIS
    Test whether a simulated NSIS path exists
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Path
    The file or directory path
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [AllowEmptyString()]
    [Parameter(Mandatory, HelpMessage = 'The file or directory path')]
    [string]$Path
  )

  $NormalizedPath = $Path.TrimEnd('\')
  if ($NormalizedPath.EndsWith('\*.*', [System.StringComparison]::OrdinalIgnoreCase)) {
    return $State.Directories.Contains($NormalizedPath.Substring(0, $NormalizedPath.Length - 4).TrimEnd('\'))
  }

  return $State.Directories.Contains($NormalizedPath) -or $State.Files.Contains($Path)
}

function Resolve-NSISRegistryRoot {
  <#
  .SYNOPSIS
    Resolve an NSIS registry root to a deterministic logical hive
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Root
    The compiled NSIS registry root value
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The compiled NSIS registry root value')]
    [uint32]$Root
  )

  switch ($Root) {
    $Script:NSIS_REG_ROOT_HKCR { return 'HKCR' }
    $Script:NSIS_REG_ROOT_HKCU { return 'HKCU' }
    $Script:NSIS_REG_ROOT_HKLM { return 'HKLM' }
    $Script:NSIS_REG_ROOT_HKU { return 'HKU' }
    $Script:NSIS_REG_ROOT_HKCC { return 'HKCC' }
    $Script:NSIS_REG_ROOT_SHCTX {
      if ($State.ShellVarContext) { return $State.ShellVarContext }

      $InstallLocation = $State.Metadata.DefaultInstallLocation
      if ($InstallLocation -and (
          $InstallLocation.StartsWith($env:ProgramFiles, [System.StringComparison]::OrdinalIgnoreCase) -or
          (${env:ProgramFiles(x86)} -and $InstallLocation.StartsWith(${env:ProgramFiles(x86)}, [System.StringComparison]::OrdinalIgnoreCase))
        )) {
        return 'HKLM'
      }

      return 'HKCU'
    }
    default { return 'HKCU' }
  }
}

function Set-NSISRegistryValue {
  <#
  .SYNOPSIS
    Store a registry value in the simulated NSIS registry and update uninstall metadata
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Root
    The registry root
  .PARAMETER Key
    The registry key path
  .PARAMETER Name
    The registry value name
  .PARAMETER Value
    The registry value data
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The registry root')]
    [string]$Root,

    [Parameter(Mandatory, HelpMessage = 'The registry key path')]
    [string]$Key,

    [AllowEmptyString()]
    [Parameter(Mandatory, HelpMessage = 'The registry value name')]
    [string]$Name,

    [AllowEmptyString()]
    [Parameter(Mandatory, HelpMessage = 'The registry value data')]
    [string]$Value
  )

  if (-not $State.Registry.ContainsKey($Root)) { $State.Registry[$Root] = @{} }
  if (-not $State.Registry[$Root].ContainsKey($Key)) { $State.Registry[$Root][$Key] = @{} }
  $State.Registry[$Root][$Key][$Name] = $Value

  if ($Key -match $Script:NSIS_UNINSTALL_KEY_PATTERN) {
    $State.Metadata.ProductCode = Split-Path -Path $Key -Leaf
    $State.Metadata.Scope = if ($Root -eq 'HKLM') { 'machine' } elseif ($Root -eq 'HKCU') { 'user' } else { $State.Metadata.Scope }
    $State.Metadata.RegistryValues[$Name] = $Value

    switch ($Name) {
      'DisplayName' { $State.Metadata.DisplayName = $Value }
      'DisplayVersion' { $State.Metadata.DisplayVersion = $Value }
      'Publisher' { $State.Metadata.Publisher = $Value }
      'InstallLocation' { $State.Metadata.DefaultInstallLocation = $Value.Trim('"') }
      default { }
    }
  }
}

function Get-NSISRegistryValue {
  <#
  .SYNOPSIS
    Read a value from the simulated NSIS registry
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Root
    The registry root
  .PARAMETER Key
    The registry key path
  .PARAMETER Name
    The registry value name
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The registry root')]
    [string]$Root,

    [Parameter(Mandatory, HelpMessage = 'The registry key path')]
    [string]$Key,

    [AllowEmptyString()]
    [Parameter(Mandatory, HelpMessage = 'The registry value name')]
    [string]$Name
  )

  if ($State.Registry.ContainsKey($Root) -and $State.Registry[$Root].ContainsKey($Key) -and $State.Registry[$Root][$Key].ContainsKey($Name)) {
    return [string]$State.Registry[$Root][$Key][$Name]
  }

  return ''
}

function Remove-NSISRegistryValue {
  <#
  .SYNOPSIS
    Remove a value or key from the simulated NSIS registry
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Root
    The registry root
  .PARAMETER Key
    The registry key path
  .PARAMETER Name
    The registry value name, or an empty string to remove the whole key
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The registry root')]
    [string]$Root,

    [Parameter(Mandatory, HelpMessage = 'The registry key path')]
    [string]$Key,

    [AllowEmptyString()]
    [Parameter(Mandatory, HelpMessage = 'The registry value name, or an empty string to remove the whole key')]
    [string]$Name
  )

  if (-not ($State.Registry.ContainsKey($Root) -and $State.Registry[$Root].ContainsKey($Key))) { return }

  if ([string]::IsNullOrEmpty($Name)) {
    $null = $State.Registry[$Root].Remove($Key)
  } else {
    $null = $State.Registry[$Root][$Key].Remove($Name)
  }
}

function Get-NSISEntries {
  <#
  .SYNOPSIS
    Parse the NSIS opcode table from the decompressed header
  .PARAMETER HeaderBytes
    The decompressed NSIS header bytes
  .PARAMETER BlockHeaders
    The parsed NSIS block headers
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The decompressed NSIS header bytes')]
    [byte[]]$HeaderBytes,

    [Parameter(Mandatory, HelpMessage = 'The parsed NSIS block headers')]
    [pscustomobject[]]$BlockHeaders
  )

  $EntryBlock = Get-NSISBlockBytes -HeaderBytes $HeaderBytes -BlockHeaders $BlockHeaders -Index 2
  $EntryCount = [int]$BlockHeaders[2].Count
  if ($EntryBlock.Length -lt ($EntryCount * $Script:NSIS_ENTRY_SIZE)) { throw 'The NSIS entry table is truncated' }

  $Entries = [System.Collections.Generic.List[object]]::new()

  for ($EntryIndex = 0; $EntryIndex -lt $EntryCount; $EntryIndex++) {
    $Offset = $EntryIndex * $Script:NSIS_ENTRY_SIZE
    $Raw = New-Object 'uint32[]' 7
    $Values = New-Object 'int[]' 7

    for ($ValueIndex = 0; $ValueIndex -lt 7; $ValueIndex++) {
      $ValueOffset = $Offset + ($ValueIndex * 4)
      $Raw[$ValueIndex] = [System.BitConverter]::ToUInt32($EntryBlock, $ValueOffset)
      $Values[$ValueIndex] = [System.BitConverter]::ToInt32($EntryBlock, $ValueOffset)
    }

    $Entries.Add([pscustomobject]@{
        Opcode = $Raw[0]
        Raw    = $Raw
        Values = $Values
      })
  }

  return $Entries.ToArray()
}

function Get-NSISSections {
  <#
  .SYNOPSIS
    Parse the NSIS section table so install sections can be simulated in order
  .PARAMETER HeaderBytes
    The decompressed NSIS header bytes
  .PARAMETER BlockHeaders
    The parsed NSIS block headers
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The decompressed NSIS header bytes')]
    [byte[]]$HeaderBytes,

    [Parameter(Mandatory, HelpMessage = 'The parsed NSIS block headers')]
    [pscustomobject[]]$BlockHeaders
  )

  $SectionBlock = Get-NSISBlockBytes -HeaderBytes $HeaderBytes -BlockHeaders $BlockHeaders -Index 1
  $SectionCount = [int]$BlockHeaders[1].Count
  if ($SectionCount -eq 0 -or $SectionBlock.Length -eq 0) { return @() }

  $SectionSize = [int]($SectionBlock.Length / $SectionCount)
  $Sections = [System.Collections.Generic.List[object]]::new()

  for ($SectionIndex = 0; $SectionIndex -lt $SectionCount; $SectionIndex++) {
    $Offset = $SectionIndex * $SectionSize
    $Sections.Add([pscustomobject]@{
        NameOffset = [System.BitConverter]::ToInt32($SectionBlock, $Offset + $Script:NSIS_SECTION_OFFSET_NAME)
        CodeOffset = [System.BitConverter]::ToInt32($SectionBlock, $Offset + $Script:NSIS_SECTION_OFFSET_CODE)
      })
  }

  return $Sections.ToArray()
}

function Initialize-NSISState {
  <#
  .SYNOPSIS
    Build the mutable execution state used for deterministic NSIS metadata parsing
  .PARAMETER HeaderData
    The decompressed NSIS header data
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The decompressed NSIS header data')]
    [pscustomobject]$HeaderData
  )

  $HeaderBytes = $HeaderData.HeaderBytes
  $BlockHeaders = Get-NSISBlockHeaders -HeaderBytes $HeaderBytes -Is64Bit $HeaderData.PEInfo.Is64Bit
  $Layout = Get-NSISHeaderLayout -HeaderBytes $HeaderBytes -Is64Bit $HeaderData.PEInfo.Is64Bit
  $StringsBlock = Get-NSISBlockBytes -HeaderBytes $HeaderBytes -BlockHeaders $BlockHeaders -Index 3
  $LanguageTable = Get-NSISPrimaryLanguageTable -HeaderBytes $HeaderBytes -BlockHeaders $BlockHeaders -Layout $Layout
  $VersionInfo = Get-NSISVersionInfo -StringsBlock $StringsBlock

  $State = [pscustomobject]@{
    Path            = $HeaderData.Path
    Entries         = Get-NSISEntries -HeaderBytes $HeaderBytes -BlockHeaders $BlockHeaders
    Sections        = Get-NSISSections -HeaderBytes $HeaderBytes -BlockHeaders $BlockHeaders
    StringsBlock    = $StringsBlock
    LanguageTable   = $LanguageTable
    VersionInfo     = $VersionInfo
    Variables       = @{}
    Registry        = @{}
    Stack           = [System.Collections.Generic.List[string]]::new()
    Directories     = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    Files           = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    ExecFlags       = @{}
    LastExecFlags   = @{}
    ShellVarContext = $null
    Metadata        = [ordered]@{
      Path                   = $HeaderData.Path
      InstallerType          = 'Nullsoft'
      DisplayVersion         = $null
      DisplayName            = $null
      Publisher              = $null
      ProductCode            = $null
      DefaultInstallLocation = $null
      Scope                  = $null
      RegistryValues         = @{}
    }
  }

  Set-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_EXEPATH -Value $HeaderData.Path
  Set-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_EXEDIR -Value (Split-Path -Path $HeaderData.Path -Parent)
  Set-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_EXEFILE -Value (Split-Path -Path $HeaderData.Path -Leaf)
  $LanguageId = if ($LanguageTable) { $LanguageTable.LanguageId } else { $Script:NSIS_DEFAULT_LANGUAGE }
  Set-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_LANGUAGE -Value ([string]$LanguageId)
  Set-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_TEMP -Value ([System.IO.Path]::GetTempPath().TrimEnd('\'))

  # InstallDir and its auto-append suffix are stored as header pointers instead of script directives.
  if ($Layout.InstallDirectoryPointer -ne 0) {
    $InstallDirectory = Get-NSISString -State $State -RelativeOffset $Layout.InstallDirectoryPointer
    $AutoAppend = if ($Layout.InstallDirectoryAutoAppend -ne 0) { Get-NSISString -State $State -RelativeOffset $Layout.InstallDirectoryAutoAppend } else { '' }

    if (-not [string]::IsNullOrWhiteSpace($AutoAppend) -and -not $InstallDirectory.EndsWith($AutoAppend, [System.StringComparison]::OrdinalIgnoreCase)) {
      $InstallDirectory = Join-Path $InstallDirectory $AutoAppend
    }

    Set-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_INSTDIR -Value $InstallDirectory
    Add-NSISDirectory -State $State -Path $InstallDirectory
  }

  return [pscustomobject]@{
    State       = $State
    Layout      = $Layout
    BlockHeaders = $BlockHeaders
  }
}

function Add-NSISDirectUninstallWrites {
  <#
  .SYNOPSIS
    Apply direct uninstall registry writes that can be recovered without executing control flow
  .PARAMETER State
    The mutable NSIS execution state
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State
  )

  foreach ($Entry in $State.Entries) {
    if ($Entry.Opcode -ne $Script:NSIS_OPCODE_WRITE_REG) { continue }

    $Root = Resolve-NSISRegistryRoot -State $State -Root $Entry.Raw[1]
    $Key = Get-NSISString -State $State -RelativeOffset $Entry.Values[2]
    if ($Key -notmatch $Script:NSIS_UNINSTALL_KEY_PATTERN) { continue }

    $Name = Get-NSISString -State $State -RelativeOffset $Entry.Values[3]
    $Value = if ($Entry.Raw[5] -eq $Script:NSIS_REG_TYPE_DWORD) {
      [string](Get-NSISInt -State $State -RelativeOffset $Entry.Values[4])
    } else {
      Get-NSISString -State $State -RelativeOffset $Entry.Values[4]
    }

    Set-NSISRegistryValue -State $State -Root $Root -Key $Key -Name $Name -Value $Value
  }
}

function Invoke-NSISCodeSegment {
  <#
  .SYNOPSIS
    Simulate a compiled NSIS code segment until it returns
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Position
    The starting entry index
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The starting entry index')]
    [int]$Position
  )

  $Watchdog = 0
  $WatchdogLimit = [Math]::Max($State.Entries.Count * $Script:NSIS_MAX_WATCHDOG_MULTIPLIER, 1)

  while ($Position -ge 0 -and $Position -lt $State.Entries.Count) {
    $Result = Invoke-NSISEntry -State $State -Entry $State.Entries[$Position]

    if ($Result.Action -eq 'Return' -or $Result.Action -eq 'Quit' -or $Result.Action -eq 'Abort') {
      return $Result.Action
    }

    $ResolvedAddress = Resolve-NSISAddress -State $State -Address $Result.Address
    if ($ResolvedAddress -eq 0) {
      $Position++
    } else {
      $Position = $ResolvedAddress - 1
    }

    $Watchdog++
    if ($Watchdog -gt $WatchdogLimit) { throw 'The NSIS code segment exceeded the static execution watchdog' }
  }

  return 'Return'
}

function Invoke-NSISEntry {
  <#
  .SYNOPSIS
    Simulate one compiled NSIS entry relevant to deterministic metadata parsing
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Entry
    The parsed entry record
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The parsed entry record')]
    [pscustomobject]$Entry
  )

  $Opcode = $Entry.Opcode
  $Values = $Entry.Values
  $Raw = $Entry.Raw

  switch ($Opcode) {
    $Script:NSIS_OPCODE_INVALID { return [pscustomobject]@{ Action = 'Return'; Address = 0 } }
    $Script:NSIS_OPCODE_RETURN { return [pscustomobject]@{ Action = 'Return'; Address = 0 } }
    $Script:NSIS_OPCODE_ABORT { return [pscustomobject]@{ Action = 'Abort'; Address = 0 } }
    $Script:NSIS_OPCODE_QUIT { return [pscustomobject]@{ Action = 'Quit'; Address = 0 } }
    $Script:NSIS_OPCODE_JUMP { return [pscustomobject]@{ Action = 'Continue'; Address = $Values[1] } }
    $Script:NSIS_OPCODE_CALL {
      $Result = Invoke-NSISCodeSegment -State $State -Position ((Resolve-NSISAddress -State $State -Address $Values[1]) - 1)
      if ($Result -eq 'Quit' -or $Result -eq 'Abort') {
        return [pscustomobject]@{ Action = $Result; Address = 0 }
      } else {
        return [pscustomobject]@{ Action = 'Continue'; Address = 0 }
      }
    }
    $Script:NSIS_OPCODE_CREATE_DIR {
      $Path = Get-NSISString -State $State -RelativeOffset $Values[1]
      Add-NSISDirectory -State $State -Path $Path

      if ($Values[2] -ne 0) {
        Set-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_OUTDIR -Value $Path
        if ([string]::IsNullOrWhiteSpace((Get-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_INSTDIR))) {
          Set-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_INSTDIR -Value $Path
        }
      }

      return [pscustomobject]@{ Action = 'Continue'; Address = 0 }
    }
    $Script:NSIS_OPCODE_IF_FILE_EXISTS {
      $FileName = Get-NSISString -State $State -RelativeOffset $Values[1]
      $Address = if (Test-NSISPathExists -State $State -Path $FileName) { $Values[2] } else { $Values[3] }
      return [pscustomobject]@{ Action = 'Continue'; Address = $Address }
    }
    $Script:NSIS_OPCODE_SET_FLAG {
      $FlagType = $Values[1]
      $Value = Get-NSISInt -State $State -RelativeOffset $Values[2]
      $Mode = $Values[3]
      $RestoreControl = $Values[4]

      if ($Mode -le 0) {
        if ($State.ExecFlags.ContainsKey($FlagType)) {
          $State.LastExecFlags[$FlagType] = $State.ExecFlags[$FlagType]
        }
        $State.ExecFlags[$FlagType] = $Value
      } elseif ($State.LastExecFlags.ContainsKey($FlagType)) {
        $State.ExecFlags[$FlagType] = $State.LastExecFlags[$FlagType]
      }

      if ($FlagType -eq $Script:NSIS_EXEC_FLAG_SHELL_VAR_CONTEXT) {
        $ShellVarContextValue = if ($State.ExecFlags.ContainsKey($FlagType)) { $State.ExecFlags[$FlagType] } else { 0 }
        $State.ShellVarContext = if ($ShellVarContextValue -eq 0) { 'HKCU' } else { 'HKLM' }
      }

      if ($FlagType -eq $Script:NSIS_EXEC_FLAG_REG_VIEW -and $RestoreControl -lt 0 -and -not $State.ExecFlags.ContainsKey($FlagType)) {
        $State.ExecFlags[$FlagType] = $Value
      }

      return [pscustomobject]@{ Action = 'Continue'; Address = 0 }
    }
    $Script:NSIS_OPCODE_IF_FLAG {
      $FlagValue = if ($State.ExecFlags.ContainsKey($Values[3])) { $State.ExecFlags[$Values[3]] } else { 0 }
      return [pscustomobject]@{ Action = 'Continue'; Address = if ($FlagValue -ne 0) { $Values[1] } else { $Values[2] } }
    }
    $Script:NSIS_OPCODE_GET_FLAG {
      $FlagValue = if ($State.ExecFlags.ContainsKey($Values[2])) { $State.ExecFlags[$Values[2]] } else { 0 }
      Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[1])) -Value ([string]$FlagValue)
      return [pscustomobject]@{ Action = 'Continue'; Address = 0 }
    }
    $Script:NSIS_OPCODE_STR_LEN {
      Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[1])) -Value ([string](Get-NSISString -State $State -RelativeOffset $Values[2]).Length)
      return [pscustomobject]@{ Action = 'Continue'; Address = 0 }
    }
    $Script:NSIS_OPCODE_ASSIGN_VAR {
      $Result = Get-NSISString -State $State -RelativeOffset $Values[2]
      $Start = $Values[4]
      $MaxLengthLow = $Values[3] -band 0xFFFF
      $MaxLengthHigh = ($Values[3] -shr 16) -band 0xFFFF
      $NewLength = if ($MaxLengthHigh -eq 0) { $Result.Length } else { $MaxLengthLow }

      if ($NewLength -le 0) {
        $null = $State.Variables.Remove([Math]::Abs($Values[1]))
        return [pscustomobject]@{ Action = 'Continue'; Address = 0 }
      }

      if ($Start -lt 0) { $Start += $Result.Length }
      if ($Start -lt 0) { $Start = 0 }
      if ($Start -gt $Result.Length) { $Start = $Result.Length }

      $Result = $Result.Substring($Start)
      if ($Result.Length -gt $NewLength) { $Result = $Result.Substring(0, $NewLength) }
      Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[1])) -Value $Result
      return [pscustomobject]@{ Action = 'Continue'; Address = 0 }
    }
    $Script:NSIS_OPCODE_STR_CMP {
      $Left = Get-NSISString -State $State -RelativeOffset $Values[1]
      $Right = Get-NSISString -State $State -RelativeOffset $Values[2]
      $Equal = if ($Values[5] -eq 0) {
        $Left.Equals($Right, [System.StringComparison]::OrdinalIgnoreCase)
      } else {
        $Left -ceq $Right
      }

      return [pscustomobject]@{ Action = 'Continue'; Address = if ($Equal) { $Values[3] } else { $Values[4] } }
    }
    $Script:NSIS_OPCODE_READ_ENV {
      $EnvironmentName = Get-NSISString -State $State -RelativeOffset $Values[2]
      $EnvironmentValue = [System.Environment]::GetEnvironmentVariable($EnvironmentName)
      if ($null -eq $EnvironmentValue) { $EnvironmentValue = '' }
      Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[1])) -Value $EnvironmentValue
      return [pscustomobject]@{ Action = 'Continue'; Address = 0 }
    }
    $Script:NSIS_OPCODE_INT_CMP {
      $Left = Get-NSISInt -State $State -RelativeOffset $Values[1]
      $Right = Get-NSISInt -State $State -RelativeOffset $Values[2]

      if ($Left -eq $Right) {
        return [pscustomobject]@{ Action = 'Continue'; Address = $Values[3] }
      } elseif ($Left -lt $Right) {
        return [pscustomobject]@{ Action = 'Continue'; Address = $Values[4] }
      } else {
        return [pscustomobject]@{ Action = 'Continue'; Address = $Values[5] }
      }
    }
    $Script:NSIS_OPCODE_INT_OP {
      $Left = Get-NSISInt -State $State -RelativeOffset $Values[2]
      $Right = Get-NSISInt -State $State -RelativeOffset $Values[3]

      $Result = switch ($Values[4]) {
        0 { $Left + $Right }
        1 { $Left - $Right }
        2 { $Left * $Right }
        3 { if ($Right -eq 0) { 0 } else { [int]($Left / $Right) } }
        4 { $Left -bor $Right }
        5 { $Left -band $Right }
        6 { $Left -bxor $Right }
        7 { -bnot $Left }
        8 { [int]($Left -ne 0 -or $Right -ne 0) }
        9 { [int]($Left -ne 0 -and $Right -ne 0) }
        10 { if ($Right -eq 0) { 0 } else { $Left % $Right } }
        11 { $Left -shl $Right }
        12 { $Left -shr $Right }
        13 { [int](([uint32]$Left) -shr $Right) }
        default { $Left }
      }

      Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[1])) -Value ([string]$Result)
      return [pscustomobject]@{ Action = 'Continue'; Address = 0 }
    }
    $Script:NSIS_OPCODE_INT_FMT {
      $Format = Get-NSISString -State $State -RelativeOffset $Values[2]
      $Result = if ($Format.StartsWith('0x', [System.StringComparison]::OrdinalIgnoreCase)) {
        ('0x{0:X8}' -f [uint32]$Values[3])
      } else {
        [string]$Values[3]
      }

      Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[1])) -Value $Result
      return [pscustomobject]@{ Action = 'Continue'; Address = 0 }
    }
    $Script:NSIS_OPCODE_PUSH_POP {
      if ($Values[3] -ne 0) {
        $ExchangeIndex = $Values[3]
        if ($ExchangeIndex -lt $State.Stack.Count) {
          $TopIndex = $State.Stack.Count - 1
          $TargetIndex = $TopIndex - $ExchangeIndex
          $Temporary = $State.Stack[$TopIndex]
          $State.Stack[$TopIndex] = $State.Stack[$TargetIndex]
          $State.Stack[$TargetIndex] = $Temporary
        }
      } elseif ($Values[2] -eq $Script:NSIS_POP_OPERATION) {
        $PoppedValue = if ($State.Stack.Count -gt 0) {
          $State.Stack[$State.Stack.Count - 1]
        } else {
          ''
        }

        if ($State.Stack.Count -gt 0) { $State.Stack.RemoveAt($State.Stack.Count - 1) }
        Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[1])) -Value $PoppedValue
      } else {
        $State.Stack.Add((Get-NSISString -State $State -RelativeOffset $Values[1]))
      }

      return [pscustomobject]@{ Action = 'Continue'; Address = 0 }
    }
    $Script:NSIS_OPCODE_DELETE_REG {
      $Root = Resolve-NSISRegistryRoot -State $State -Root $Raw[2]
      $Key = Get-NSISString -State $State -RelativeOffset $Values[3]
      $Name = Get-NSISString -State $State -RelativeOffset $Values[4]
      Remove-NSISRegistryValue -State $State -Root $Root -Key $Key -Name $Name
      return [pscustomobject]@{ Action = 'Continue'; Address = 0 }
    }
    $Script:NSIS_OPCODE_WRITE_REG {
      $Root = Resolve-NSISRegistryRoot -State $State -Root $Raw[1]
      $Key = Get-NSISString -State $State -RelativeOffset $Values[2]
      $Name = Get-NSISString -State $State -RelativeOffset $Values[3]
      $Value = Get-NSISString -State $State -RelativeOffset $Values[4]

      if ($Raw[5] -eq $Script:NSIS_REG_TYPE_DWORD) {
        $Value = [string](Get-NSISInt -State $State -RelativeOffset $Values[4])
      }

      Set-NSISRegistryValue -State $State -Root $Root -Key $Key -Name $Name -Value $Value
      return [pscustomobject]@{ Action = 'Continue'; Address = 0 }
    }
    $Script:NSIS_OPCODE_READ_REG {
      $Root = Resolve-NSISRegistryRoot -State $State -Root $Raw[2]
      $Key = Get-NSISString -State $State -RelativeOffset $Values[3]
      $Name = Get-NSISString -State $State -RelativeOffset $Values[4]
      $Value = Get-NSISRegistryValue -State $State -Root $Root -Key $Key -Name $Name
      Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[1])) -Value $Value
      return [pscustomobject]@{ Action = 'Continue'; Address = 0 }
    }
    $Script:NSIS_OPCODE_WRITE_UNINSTALLER {
      $UninstallerPath = Get-NSISString -State $State -RelativeOffset $Values[1]
      Add-NSISFile -State $State -Path $UninstallerPath
      return [pscustomobject]@{ Action = 'Continue'; Address = 0 }
    }
    default {
      # Unsupported entries are ignored unless the resulting metadata stays incomplete and the caller throws.
      return [pscustomobject]@{ Action = 'Continue'; Address = 0 }
    }
  }
}

function Complete-NSISMetadata {
  <#
  .SYNOPSIS
    Apply deterministic fallbacks after the NSIS simulation completes
  .PARAMETER State
    The mutable NSIS execution state
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State
  )

  if (-not $State.Metadata.DisplayName -and $State.LanguageTable -and $State.LanguageTable.StringOffsets.Count -gt 2) {
    $NameOffset = $State.LanguageTable.StringOffsets[2]
    if ($NameOffset -ne 0) { $State.Metadata.DisplayName = Get-NSISString -State $State -RelativeOffset $NameOffset }
  }

  if (-not $State.Metadata.DisplayVersion) {
    $Major = $State.Metadata.RegistryValues['VersionMajor']
    $Minor = $State.Metadata.RegistryValues['VersionMinor']
    if (-not [string]::IsNullOrWhiteSpace($Major) -and -not [string]::IsNullOrWhiteSpace($Minor)) {
      $State.Metadata.DisplayVersion = "$Major.$Minor"
    }
  }

  if (-not $State.Metadata.DefaultInstallLocation) {
    $State.Metadata.DefaultInstallLocation = Get-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_INSTDIR
  }

  if (-not $State.Metadata.Scope) {
    if ($State.Metadata.DefaultInstallLocation -and (
        $State.Metadata.DefaultInstallLocation.StartsWith($env:ProgramFiles, [System.StringComparison]::OrdinalIgnoreCase) -or
        (${env:ProgramFiles(x86)} -and $State.Metadata.DefaultInstallLocation.StartsWith(${env:ProgramFiles(x86)}, [System.StringComparison]::OrdinalIgnoreCase))
      )) {
      $State.Metadata.Scope = 'machine'
    } else {
      $State.Metadata.Scope = 'user'
    }
  }

  return [pscustomobject]$State.Metadata
}

function Get-NSISInfo {
  <#
  .SYNOPSIS
    Get static metadata from a Nullsoft Scriptable Install System installer
  .PARAMETER Path
    The path to the NSIS installer
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path
  )

  process {
    $HeaderData = Get-NSISHeaderData -Path $Path
    $InitializedState = Initialize-NSISState -HeaderData $HeaderData
    $State = $InitializedState.State
    $Layout = $InitializedState.Layout

    # Prefer direct uninstall registry writes when they already expose a single deterministic ARP identity.
    Add-NSISDirectUninstallWrites -State $State
    $Metadata = Complete-NSISMetadata -State $State
    if (-not [string]::IsNullOrWhiteSpace($Metadata.DisplayName) -and -not [string]::IsNullOrWhiteSpace($Metadata.DisplayVersion) -and -not [string]::IsNullOrWhiteSpace($Metadata.ProductCode)) {
      return $Metadata
    }

    if ($Layout.CodeOnInit -ge 0) {
      try {
        $null = Invoke-NSISCodeSegment -State $State -Position $Layout.CodeOnInit
      } catch {
        # Continue parsing when non-metadata callbacks loop or rely on unsupported runtime state.
      }
    }

    foreach ($Section in $State.Sections) {
      if ($Section.CodeOffset -lt 0) { continue }

      try {
        $Result = Invoke-NSISCodeSegment -State $State -Position $Section.CodeOffset
      } catch {
        continue
      }
      if ($Result -eq 'Quit') { break }
    }

    if ($Layout.CodeOnInstSuccess -ge 0) {
      try {
        $null = Invoke-NSISCodeSegment -State $State -Position $Layout.CodeOnInstSuccess
      } catch {
        # Continue parsing when the success callback contains unsupported UI-only behavior.
      }
    }

    if ([string]::IsNullOrWhiteSpace($State.Metadata.DisplayVersion) -or [string]::IsNullOrWhiteSpace($State.Metadata.ProductCode)) {
      Add-NSISDirectUninstallWrites -State $State
    }

    $Metadata = Complete-NSISMetadata -State $State
    if ([string]::IsNullOrWhiteSpace($Metadata.DisplayName) -and [string]::IsNullOrWhiteSpace($Metadata.DisplayVersion)) {
      throw 'The NSIS installer does not expose deterministic uninstall metadata'
    }

    return $Metadata
  }
}

function Read-ProductVersionFromNSIS {
  <#
  .SYNOPSIS
    Read the product version from a Nullsoft installer
  .PARAMETER Path
    The path to the NSIS installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path
  )

  process {
    $Info = Get-NSISInfo -Path $Path
    if ([string]::IsNullOrWhiteSpace($Info.DisplayVersion)) { throw 'The NSIS installer does not expose a DisplayVersion value' }
    return $Info.DisplayVersion
  }
}

function Read-ProductNameFromNSIS {
  <#
  .SYNOPSIS
    Read the product name from a Nullsoft installer
  .PARAMETER Path
    The path to the NSIS installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path
  )

  process {
    $Info = Get-NSISInfo -Path $Path
    if ([string]::IsNullOrWhiteSpace($Info.DisplayName)) { throw 'The NSIS installer does not expose a DisplayName value' }
    return $Info.DisplayName
  }
}

function Read-PublisherFromNSIS {
  <#
  .SYNOPSIS
    Read the publisher from a Nullsoft installer
  .PARAMETER Path
    The path to the NSIS installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path
  )

  process {
    $Info = Get-NSISInfo -Path $Path
    if ([string]::IsNullOrWhiteSpace($Info.Publisher)) { throw 'The NSIS installer does not expose a Publisher value' }
    return $Info.Publisher
  }
}

function Read-ProductCodeFromNSIS {
  <#
  .SYNOPSIS
    Read the uninstall registry key name from a Nullsoft installer
  .PARAMETER Path
    The path to the NSIS installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path
  )

  process {
    $Info = Get-NSISInfo -Path $Path
    if ([string]::IsNullOrWhiteSpace($Info.ProductCode)) { throw 'The NSIS installer does not expose an uninstall registry key' }
    return $Info.ProductCode
  }
}

Export-ModuleMember -Function Get-NSISInfo, Read-ProductVersionFromNSIS, Read-ProductNameFromNSIS, Read-PublisherFromNSIS, Read-ProductCodeFromNSIS
