# SPDX-License-Identifier: MIT
# Format sources: https://github.com/lifenjoiner/ISx
# Setup.ini source: https://docs.revenera.com/installshield26helplib/helplibrary/SetupIniExe.htm

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# Force stop on error
$ErrorActionPreference = 'Stop'

$Script:InstallShieldMagic = [byte[]](0x13, 0x35, 0x86, 0x07)
$Script:InstallShieldPreferredBlockSize = 4096 * 64
$Script:InstallShieldOldAttributeSize = 0x138

function ConvertFrom-InstallShieldCString {
  [OutputType([string])]
  param (
    [Parameter(Mandatory)]
    [byte[]]$Bytes,

    [Parameter()]
    [System.Text.Encoding]$Encoding = [System.Text.Encoding]::Default
  )

  $Length = [Array]::IndexOf($Bytes, [byte]0)
  if ($Length -lt 0) { $Length = $Bytes.Length }
  return $Encoding.GetString($Bytes, 0, $Length).TrimEnd([char]0)
}

function Save-InstallShieldRange {
  <#
  .SYNOPSIS
    Save a byte range from the installer stream to a destination file
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)]
    [System.IO.Stream]$Stream,

    [Parameter(Mandatory)]
    [long]$Offset,

    [Parameter(Mandatory)]
    [long]$Length,

    [Parameter(Mandatory)]
    [string]$Path
  )

  $Parent = Split-Path -Path $Path -Parent
  if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }

  $Output = [System.IO.File]::Open($Path, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
  try {
    Copy-BinaryStreamRange -Source $Stream -Destination $Output -Offset $Offset -Length $Length
  } finally {
    $Output.Dispose()
  }

  return $Path
}

function Join-InstallShieldSafePath {
  <#
  .SYNOPSIS
    Join a payload relative path under an extraction root without allowing path escape
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)]
    [string]$Root,

    [Parameter(Mandatory)]
    [string]$RelativePath
  )

  Resolve-SafeExtractionPath -DestinationPath $Root -RelativePath $RelativePath
}

function ConvertFrom-InstallShieldBuffer {
  <#
  .SYNOPSIS
    Decode an InstallShield encoded payload buffer in place
  #>
  param (
    [Parameter(Mandatory)]
    [byte[]]$Data,

    [Parameter(Mandatory)]
    [int]$Start,

    [Parameter(Mandatory)]
    [int]$Length,

    [Parameter(Mandatory)]
    [int]$Offset,

    [Parameter(Mandatory)]
    [byte[]]$Seed
  )

  Import-BinaryPatternSearch
  return ,([Dumplings.InstallerInfrastructure.InstallShieldTransform]::DecodeRange($Data, $Start, $Length, $Offset, $Seed, $Script:InstallShieldMagic))
}

function ConvertFrom-InstallShieldBlocks {
  [OutputType([byte[]])]
  param (
    [Parameter(Mandatory)]
    [byte[]]$Data,

    [Parameter(Mandatory)]
    [int]$BlockSize,

    [Parameter(Mandatory)]
    [byte[]]$Seed,

    [Parameter()]
    [switch]$StreamMode
  )

  Import-BinaryPatternSearch
  return ,([Dumplings.InstallerInfrastructure.InstallShieldTransform]::Decode($Data, $BlockSize, $Seed, $Script:InstallShieldMagic, $StreamMode.IsPresent))
}

function Expand-InstallShieldZlibBuffer {
  [OutputType([byte[]])]
  param (
    [Parameter(Mandatory)]
    [byte[]]$Data
  )

  $InputStream = [System.IO.MemoryStream]::new($Data)
  $OutputStream = [System.IO.MemoryStream]::new()
  try {
    $null = Expand-InstallerCompressedStream -Algorithm Zlib -Stream $InputStream -Destination $OutputStream -MaximumBytes 1073741824
    return ,$OutputStream.ToArray()
  } catch {
    return ,$Data
  } finally {
    $OutputStream.Dispose()
    $InputStream.Dispose()
  }
}

function Get-InstallShieldHeader {
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]
    [System.IO.Stream]$Stream,

    [Parameter(Mandatory)]
    [long]$Offset
  )

  if ($Offset + 46 -gt $Stream.Length) { return $null }
  $Bytes = Read-PEFileBytes -Stream $Stream -Offset $Offset -Count 46
  $Signature = ConvertFrom-InstallShieldCString -Bytes $Bytes[0..13] -Encoding ([System.Text.Encoding]::ASCII)
  if ($Signature -notin @('InstallShield', 'ISSetupStream')) { return $null }

  $Type = [System.BitConverter]::ToUInt32($Bytes, 16)
  if ($Type -gt 4) { return $null }

  [pscustomobject]@{
    Signature = $Signature
    NumFiles  = [System.BitConverter]::ToUInt16($Bytes, 14)
    Type      = $Type
    NextOffset = $Offset + 46
    IsSetupStream = $Signature -eq 'ISSetupStream'
  }
}

function Get-InstallShieldOldAttribute {
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]
    [System.IO.Stream]$Stream,

    [Parameter(Mandatory)]
    [long]$Offset
  )

  if ($Offset + $Script:InstallShieldOldAttributeSize -gt $Stream.Length) { return $null }
  $Bytes = Read-PEFileBytes -Stream $Stream -Offset $Offset -Count $Script:InstallShieldOldAttributeSize
  $FileName = ConvertFrom-InstallShieldCString -Bytes $Bytes[0..259]
  $FileLength = [System.BitConverter]::ToUInt32($Bytes, 268)
  $DataOffset = $Offset + $Script:InstallShieldOldAttributeSize
  if ([string]::IsNullOrWhiteSpace($FileName) -or $FileLength -gt $Stream.Length - $DataOffset) { return $null }

  [pscustomobject]@{
    FileName = $FileName
    Seed = [System.Text.Encoding]::UTF8.GetBytes($FileName)
    EncodedFlags = [System.BitConverter]::ToUInt32($Bytes, 260)
    FileLength = $FileLength
    IsUnicodeLauncher = [System.BitConverter]::ToUInt16($Bytes, 280)
    DataOffset = $DataOffset
    NextOffset = $DataOffset
  }
}

function Get-InstallShieldStreamAttribute {
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]
    [System.IO.Stream]$Stream,

    [Parameter(Mandatory)]
    [long]$Offset,

    [Parameter(Mandatory)]
    [uint32]$Type
  )

  if ($Offset + 24 -gt $Stream.Length) { return $null }
  $Bytes = Read-PEFileBytes -Stream $Stream -Offset $Offset -Count 24
  $FileNameLength = [System.BitConverter]::ToUInt32($Bytes, 0)
  if ($FileNameLength -le 0 -or $FileNameLength -gt 520) { return $null }

  $NameOffset = $Offset + 24
  if ($Type -eq 4) { $NameOffset += 24 }
  if ($NameOffset + $FileNameLength -gt $Stream.Length) { return $null }

  $NameBytes = Read-PEFileBytes -Stream $Stream -Offset $NameOffset -Count $FileNameLength
  $FileName = [System.Text.Encoding]::Unicode.GetString($NameBytes).TrimEnd([char]0)
  $DataOffset = $NameOffset + $FileNameLength
  $FileLength = [System.BitConverter]::ToUInt32($Bytes, 10)
  if ([string]::IsNullOrWhiteSpace($FileName) -or $FileLength -gt $Stream.Length - $DataOffset) { return $null }

  [pscustomobject]@{
    FileName = $FileName
    Seed = [System.Text.Encoding]::UTF8.GetBytes($FileName)
    EncodedFlags = [System.BitConverter]::ToUInt32($Bytes, 4)
    FileLength = $FileLength
    IsUnicodeLauncher = [System.BitConverter]::ToUInt16($Bytes, 22)
    DataOffset = $DataOffset
    NextOffset = $DataOffset
  }
}

function Skip-InstallShieldNb10Prefix {
  [OutputType([long])]
  param (
    [Parameter(Mandatory)]
    [System.IO.Stream]$Stream,

    [Parameter(Mandatory)]
    [long]$Offset
  )

  if ($Offset + 4 -gt $Stream.Length) { return $Offset }
  $Prefix = [System.Text.Encoding]::ASCII.GetString((Read-PEFileBytes -Stream $Stream -Offset $Offset -Count 4))
  if ($Prefix -ne 'NB10') { return $Offset }

  $Scan = $Offset + 4
  $PrintableRuns = 0
  $InPrintable = $false
  while ($Scan -lt $Stream.Length -and $Scan -lt $Offset + 1024) {
    $Stream.Position = $Scan
    $Byte = $Stream.ReadByte()
    if ($Byte -ge 0x20 -and $Byte -le 0xFE) {
      if (-not $InPrintable) {
        $PrintableRuns++
        $InPrintable = $true
      }
    } else {
      $InPrintable = $false
    }
    $Scan++
    if ($PrintableRuns -ge 2 -and $Byte -lt 0x20) { return $Scan }
  }

  return $Offset
}

function Export-InstallShieldDecodedFile {
  [OutputType([string])]
  param (
    [Parameter(Mandatory)]
    [System.IO.Stream]$Stream,

    [Parameter(Mandatory)]
    [psobject]$Attribute,

    [Parameter(Mandatory)]
    [string]$DestinationPath,

    [Parameter()]
    [switch]$StreamMode
  )

  $Data = Read-PEFileBytes -Stream $Stream -Offset $Attribute.DataOffset -Count ([int]$Attribute.FileLength)
  $HasType2Or4 = ($Attribute.EncodedFlags -band 6) -ne 0
  $HasType4 = ($Attribute.EncodedFlags -band 4) -ne 0

  if ($HasType4 -and $HasType2Or4) {
    # ISSetupStream still decodes flagged payloads in 1024-byte units; only the
    # outer read buffer differs in the reference extractor.
    $Data = ConvertFrom-InstallShieldBlocks -Data $Data -BlockSize 1024 -Seed $Attribute.Seed -StreamMode:$StreamMode
  } elseif ($HasType2Or4) {
    $Data = ConvertFrom-InstallShieldBuffer -Data $Data -Start 0 -Length $Data.Length -Offset 0 -Seed $Attribute.Seed
  }

  if ($Attribute.IsUnicodeLauncher -ne 0) {
    $Data = Expand-InstallShieldZlibBuffer -Data $Data
  }

  $OutputPath = Join-InstallShieldSafePath -Root $DestinationPath -RelativePath $Attribute.FileName
  $Parent = Split-Path -Path $OutputPath -Parent
  if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
  [System.IO.File]::WriteAllBytes($OutputPath, $Data)
  return $OutputPath
}

function Expand-InstallShieldEncryptedPayload {
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]
    [System.IO.Stream]$Stream,

    [Parameter(Mandatory)]
    [long]$Offset,

    [Parameter(Mandatory)]
    [string]$DestinationPath
  )

  $Header = Get-InstallShieldHeader -Stream $Stream -Offset $Offset
  if (-not $Header) { return $null }

  $Cursor = $Header.NextOffset
  $Files = [System.Collections.Generic.List[string]]::new()
  for ($Index = 0; $Index -lt $Header.NumFiles; $Index++) {
    $Attribute = if ($Header.IsSetupStream) {
      Get-InstallShieldStreamAttribute -Stream $Stream -Offset $Cursor -Type $Header.Type
    } else {
      Get-InstallShieldOldAttribute -Stream $Stream -Offset $Cursor
    }
    if (-not $Attribute -or $Attribute.NextOffset -le $Cursor) { break }

    $Files.Add((Export-InstallShieldDecodedFile -Stream $Stream -Attribute $Attribute -DestinationPath $DestinationPath -StreamMode:$Header.IsSetupStream))
    $Cursor = $Attribute.NextOffset + $Attribute.FileLength
  }

  if ($Files.Count -eq 0) { return $null }

  [pscustomobject]@{
    Format = $Header.Signature
    ConsumedOffset = $Cursor
    ExtractedFiles = @($Files)
  }
}

function Read-InstallShieldTextToken {
  [OutputType([string])]
  param (
    [Parameter(Mandatory)]
    [System.IO.Stream]$Stream,

    [Parameter(Mandatory)]
    [ref]$Cursor,

    [Parameter()]
    [switch]$Unicode,

    [Parameter(Mandatory)]
    [int]$MaximumCharacters
  )

  $Bytes = [System.Collections.Generic.List[byte]]::new()
  $Stream.Position = $Cursor.Value
  while ($Stream.Position -lt $Stream.Length -and $Bytes.Count -lt $MaximumCharacters * $(if ($Unicode) { 2 } else { 1 })) {
    $Byte = $Stream.ReadByte()
    if ($Byte -lt 0) { break }
    if (-not $Unicode) {
      if ($Byte -ge 0x20 -and $Byte -le 0xFE) {
        $Bytes.Add([byte]$Byte)
      } elseif ($Bytes.Count -gt 0) {
        break
      }
    } else {
      $Byte2 = $Stream.ReadByte()
      if ($Byte2 -lt 0) { break }
      if (($Byte -ne 0 -or $Byte2 -ne 0) -and -not ($Byte -lt 0x20 -and $Byte2 -eq 0)) {
        $Bytes.Add([byte]$Byte)
        $Bytes.Add([byte]$Byte2)
      } elseif ($Bytes.Count -gt 0) {
        break
      }
    }
  }

  $Cursor.Value = $Stream.Position
  while ($Cursor.Value -lt $Stream.Length) {
    $Stream.Position = $Cursor.Value
    $Byte = $Stream.ReadByte()
    if ($Byte -lt 0) { break }
    if (-not $Unicode) {
      if ($Byte -ge 0x20 -and $Byte -le 0xFE) { break }
      $Cursor.Value = $Stream.Position
    } else {
      $Byte2 = $Stream.ReadByte()
      if ($Byte -ge 0x20 -or $Byte2 -ne 0) { break }
      $Cursor.Value = $Stream.Position
    }
  }

  if ($Unicode) {
    return [System.Text.Encoding]::Unicode.GetString($Bytes.ToArray()).TrimEnd([char]0)
  }
  return ConvertFrom-InstallShieldCString -Bytes $Bytes.ToArray()
}

function Get-InstallShieldPlainRecord {
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]
    [System.IO.Stream]$Stream,

    [Parameter(Mandatory)]
    [long]$Offset,

    [Parameter()]
    [switch]$Unicode
  )

  $Cursor = $Offset
  $FileName = Read-InstallShieldTextToken -Stream $Stream -Cursor ([ref]$Cursor) -Unicode:$Unicode -MaximumCharacters 260
  $DestinationName = Read-InstallShieldTextToken -Stream $Stream -Cursor ([ref]$Cursor) -Unicode:$Unicode -MaximumCharacters 260
  $Version = Read-InstallShieldTextToken -Stream $Stream -Cursor ([ref]$Cursor) -Unicode:$Unicode -MaximumCharacters 32
  $LengthText = Read-InstallShieldTextToken -Stream $Stream -Cursor ([ref]$Cursor) -Unicode:$Unicode -MaximumCharacters 32

  $Length = 0
  if ([string]::IsNullOrWhiteSpace($FileName) -or [string]::IsNullOrWhiteSpace($DestinationName) -or -not [uint32]::TryParse($LengthText, [ref]$Length)) {
    return $null
  }
  if ($Length -gt $Stream.Length - $Cursor) { return $null }

  [pscustomobject]@{
    FileName = $FileName
    DestinationName = $DestinationName
    Version = $Version
    FileLength = [uint32]$Length
    DataOffset = [long]$Cursor
  }
}

function Expand-InstallShieldPlainPayload {
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]
    [System.IO.Stream]$Stream,

    [Parameter(Mandatory)]
    [long]$Offset,

    [Parameter(Mandatory)]
    [string]$DestinationPath,

    [Parameter()]
    [switch]$Unicode
  )

  $Cursor = if ($Unicode) { $Offset + 4 } else { $Offset }
  $Files = [System.Collections.Generic.List[string]]::new()
  while ($Cursor -lt $Stream.Length) {
    $Record = Get-InstallShieldPlainRecord -Stream $Stream -Offset $Cursor -Unicode:$Unicode
    if (-not $Record) { break }
    $OutputPath = Join-InstallShieldSafePath -Root $DestinationPath -RelativePath $Record.DestinationName
    $Files.Add((Save-InstallShieldRange -Stream $Stream -Offset $Record.DataOffset -Length $Record.FileLength -Path $OutputPath))
    $Cursor = $Record.DataOffset + $Record.FileLength
  }

  if ($Files.Count -eq 0) { return $null }

  [pscustomobject]@{
    Format = if ($Unicode) { 'PlainUnicode' } else { 'Plain' }
    ConsumedOffset = $Cursor
    ExtractedFiles = @($Files)
  }
}

function Invoke-InstallShieldExtraction {
  <#
  .SYNOPSIS
    Extract InstallShield payload records without executing external tools
  .PARAMETER Path
    The path to the InstallShield installer
  .PARAMETER DestinationPath
    The destination directory for extracted files
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]
    [string]$Path,

    [Parameter(Mandatory)]
    [string]$DestinationPath
  )

  $File = Get-Item -Path $Path -Force
  $null = New-Item -Path $DestinationPath -ItemType Directory -Force
  $Stream = [System.IO.File]::Open($File.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
  try {
    $DataOffset = Get-PEOverlayOffset -Stream $Stream
    if ($DataOffset -le 0) { throw 'Not a PE InstallShield file.' }
    if ($DataOffset -ge $Stream.Length) { throw 'No InstallShield overlay data found.' }

    $LauncherPath = Join-Path $DestinationPath ($File.BaseName + '_sfx' + $File.Extension)
    $LauncherPath = Save-InstallShieldRange -Stream $Stream -Offset 0 -Length $DataOffset -Path $LauncherPath
    $CandidateOffset = Skip-InstallShieldNb10Prefix -Stream $Stream -Offset $DataOffset

    $Result = Expand-InstallShieldEncryptedPayload -Stream $Stream -Offset $CandidateOffset -DestinationPath $DestinationPath
    if (-not $Result) {
      $Result = Expand-InstallShieldPlainPayload -Stream $Stream -Offset $CandidateOffset -DestinationPath $DestinationPath -Unicode
    }
    if (-not $Result) {
      $Result = Expand-InstallShieldPlainPayload -Stream $Stream -Offset $CandidateOffset -DestinationPath $DestinationPath
    }

    if (-not $Result) {
      Remove-Item -Path $LauncherPath -Force -ErrorAction SilentlyContinue
      throw 'No InstallShield payload records were decoded.'
    }

    [pscustomobject]@{
      DestinationPath = (Get-Item -Path $DestinationPath -Force).FullName
      DataOffset = $DataOffset
      ConsumedOffset = $Result.ConsumedOffset
      Format = $Result.Format
      ExtractedFiles = @($LauncherPath) + @($Result.ExtractedFiles)
    }
  } finally {
    $Stream.Dispose()
  }
}

function Resolve-InstallShieldMatch {
  <#
  .SYNOPSIS
    Resolve a deterministic extracted InstallShield payload match
  .PARAMETER Item
    The candidate extracted files
  .PARAMETER Pattern
    The exact file name or wildcard pattern to match
  #>
  [OutputType([System.IO.FileInfo])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The candidate extracted files')]
    [System.IO.FileInfo[]]$Item,

    [Parameter(Mandatory, HelpMessage = 'The exact file name or wildcard pattern to match')]
    [string]$Pattern
  )

  if (-not $Item) { throw 'No matching files were extracted from the InstallShield payload' }

  $Match = @($Item.Where({ $_.Name -like $Pattern -or $_.FullName -like $Pattern }))
  if (-not $Match) { throw "No InstallShield payload matched the pattern: $Pattern" }

  $ExactMatch = @($Match.Where({ $_.Name -ieq $Pattern -or $_.FullName -ieq $Pattern }))
  if ($ExactMatch.Count -eq 1) { return $ExactMatch[0] }
  if ($Match.Count -eq 1) { return $Match[0] }

  throw "Multiple InstallShield payloads matched the pattern: $Pattern"
}

function Read-InstallShieldIniConfiguration {
  <#
  .SYNOPSIS
    Read a bounded extracted InstallShield Setup.ini file
  #>
  [OutputType([System.Collections.IDictionary])]
  param (
    [Parameter(Mandatory)]
    [string]$Path
  )

  $File = Get-Item -LiteralPath $Path -Force
  if ($File.Length -gt 4194304) { throw 'The extracted InstallShield Setup.ini exceeds the 4 MiB metadata limit' }

  $Bytes = [System.IO.File]::ReadAllBytes($File.FullName)
  $Text = if ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFF -and $Bytes[1] -eq 0xFE) {
    [System.Text.Encoding]::Unicode.GetString($Bytes, 2, $Bytes.Length - 2)
  } elseif ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFE -and $Bytes[1] -eq 0xFF) {
    [System.Text.Encoding]::BigEndianUnicode.GetString($Bytes, 2, $Bytes.Length - 2)
  } elseif ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) {
    [System.Text.Encoding]::UTF8.GetString($Bytes, 3, $Bytes.Length - 3)
  } elseif ($Bytes.Length -ge 4 -and $Bytes[1] -eq 0 -and $Bytes[3] -eq 0) {
    [System.Text.Encoding]::Unicode.GetString($Bytes)
  } else {
    [System.Text.Encoding]::Default.GetString($Bytes)
  }

  return $Text | ConvertFrom-Ini -IgnoreComments
}

function Get-InstallShieldIniValue {
  <#
  .SYNOPSIS
    Read one case-insensitive value from parsed InstallShield INI metadata
  #>
  param (
    [Parameter(Mandatory)]
    [System.Collections.IDictionary]$Configuration,

    [Parameter(Mandatory)]
    [string]$Section,

    [Parameter(Mandatory)]
    [string]$Name
  )

  $SectionKey = @($Configuration.Keys | Where-Object { [string]$_ -ieq $Section }) | Select-Object -First 1
  if ($null -eq $SectionKey) { return $null }
  $SectionValue = $Configuration[$SectionKey]
  if ($SectionValue -isnot [System.Collections.IDictionary]) { return $null }

  $ValueKey = @($SectionValue.Keys | Where-Object { [string]$_ -ieq $Name }) | Select-Object -First 1
  return $null -eq $ValueKey ? $null : $SectionValue[$ValueKey]
}

function ConvertTo-InstallShieldPayloadPath {
  <#
  .SYNOPSIS
    Normalize a Setup.ini payload path for comparison with extracted records
  #>
  [OutputType([string])]
  param (
    [AllowNull()]
    [string]$Path
  )

  if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
  $Result = $Path.Trim().Trim('"').Trim("'")
  if ([System.Uri]::IsWellFormedUriString($Result, [System.UriKind]::Absolute)) { return $Result }
  $Result = $Result.Replace('/', '\')
  while ($Result.StartsWith('.\', [System.StringComparison]::Ordinal)) { $Result = $Result.Substring(2) }
  return $Result.TrimStart('\')
}

function Get-InstallShieldMsiPayloadSelection {
  <#
  .SYNOPSIS
    Resolve the MSI path selected by the extracted InstallShield Setup.ini
  .PARAMETER ExtractedPath
    The extraction root
  .PARAMETER MsiFile
    The extracted MSI candidates
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]
    [string]$ExtractedPath,

    [Parameter(Mandatory)]
    [AllowEmptyCollection()]
    [System.IO.FileInfo[]]$MsiFile
  )

  $Warnings = [System.Collections.Generic.List[string]]::new()
  $SetupIniFiles = @(Get-ChildItem -LiteralPath $ExtractedPath -Filter 'Setup.ini' -Recurse -File -ErrorAction SilentlyContinue | Sort-Object FullName)
  $RootSetupIni = @($SetupIniFiles | Where-Object {
      [System.IO.Path]::GetRelativePath($ExtractedPath, $_.FullName) -ieq 'Setup.ini'
    })
  $SetupIni = if ($RootSetupIni.Count -eq 1) {
    $RootSetupIni[0]
  } elseif ($SetupIniFiles.Count -eq 1) {
    $SetupIniFiles[0]
  } else {
    if ($SetupIniFiles.Count -gt 1) { $Warnings.Add('Multiple extracted Setup.ini files prevent deterministic InstallShield MSI selection.') }
    $null
  }

  $Configuration = $null
  $PackageName = $null
  $PackageLocation = $null
  if ($SetupIni) {
    $Configuration = Read-InstallShieldIniConfiguration -Path $SetupIni.FullName
    $PackageName = [string](Get-InstallShieldIniValue -Configuration $Configuration -Section 'Startup' -Name 'PackageName')
    if (-not [string]::IsNullOrWhiteSpace($PackageName)) {
      $PackageLocation = [string](Get-InstallShieldIniValue -Configuration $Configuration -Section $PackageName -Name 'Location')
    }
  }

  $RelativeMsiFiles = @($MsiFile | ForEach-Object {
      [pscustomobject]@{
        File         = $_
        RelativePath = ConvertTo-InstallShieldPayloadPath -Path ([System.IO.Path]::GetRelativePath($ExtractedPath, $_.FullName))
      }
    })
  $ConfiguredPaths = @(@($PackageLocation, $PackageName) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object {
      ConvertTo-InstallShieldPayloadPath -Path $_
    } | Select-Object -Unique)

  $Selected = $null
  foreach ($ConfiguredPath in $ConfiguredPaths) {
    if ([System.Uri]::IsWellFormedUriString($ConfiguredPath, [System.UriKind]::Absolute)) { continue }
    $HasDirectory = $ConfiguredPath.Contains('\')
    $MatchingMsiFiles = @($RelativeMsiFiles | Where-Object {
        $_.RelativePath -ieq $ConfiguredPath -or (-not $HasDirectory -and $_.File.Name -ieq $ConfiguredPath)
      })
    if ($MatchingMsiFiles.Count -eq 1) {
      $Selected = $MatchingMsiFiles[0]
      break
    }
    if ($MatchingMsiFiles.Count -gt 1) {
      $Warnings.Add("Setup.ini path '$ConfiguredPath' matches multiple extracted MSI files.")
      break
    }
  }

  $SelectionMethod = 'Unresolved'
  $SourceKind = 'None'
  if ($Selected) {
    $SelectionMethod = 'SetupIni'
    $SourceKind = 'Embedded'
  } elseif (-not [string]::IsNullOrWhiteSpace($PackageName)) {
    $SelectionMethod = 'SetupIniUnresolved'
    $SourceKind = 'ExternalOrMissing'
    $Warnings.Add("Setup.ini selects '$PackageName', but that MSI path was not extracted.")
  } elseif ($RelativeMsiFiles.Count -eq 1) {
    $Selected = $RelativeMsiFiles[0]
    $SelectionMethod = 'SingleExtractedMsi'
    $SourceKind = 'Embedded'
    $Warnings.Add('Setup.ini did not identify the MSI; the only extracted MSI is used as a bounded fallback.')
  } elseif ($RelativeMsiFiles.Count -gt 1) {
    $Warnings.Add('Multiple MSI files were extracted, but Setup.ini did not identify which package the bootstrapper launches.')
  }

  return [pscustomobject]@{
    SelectionMethod  = $SelectionMethod
    SourceKind       = $SourceKind
    SetupIniPath     = $null -eq $SetupIni ? $null : [System.IO.Path]::GetRelativePath($ExtractedPath, $SetupIni.FullName)
    PackageName      = [string]::IsNullOrWhiteSpace($PackageName) ? $null : $PackageName
    PackageLocation  = [string]::IsNullOrWhiteSpace($PackageLocation) ? $null : $PackageLocation
    ConfiguredPaths  = @($ConfiguredPaths)
    SelectedMsiPath  = $null -eq $Selected ? $null : $Selected.RelativePath
    Configuration    = $Configuration
    Warnings         = @($Warnings)
  }
}

function Resolve-InstallShieldMsiFile {
  <#
  .SYNOPSIS
    Resolve the exact MSI path selected by the InstallShield bootstrapper
  #>
  [OutputType([System.IO.FileInfo])]
  param (
    [Parameter(Mandatory)]
    [psobject]$Installer,

    [Parameter(Mandatory)]
    [System.IO.FileInfo[]]$Item,

    [Parameter(Mandatory)]
    [string]$Pattern,

    [bool]$NameWasSpecified
  )

  if (-not $Item) { throw 'No MSI files were extracted from the InstallShield payload' }
  $SelectionProperty = $Installer.PSObject.Properties['MsiPayloadSelection']
  $Selection = $null -eq $SelectionProperty ? $null : $SelectionProperty.Value
  $SelectedRelativePath = $null -eq $Selection ? $null : [string]$Selection.SelectedMsiPath

  if (-not [string]::IsNullOrWhiteSpace($SelectedRelativePath)) {
    $Selected = @($Item | Where-Object {
        [System.IO.Path]::GetRelativePath($Installer.ExtractedPath, $_.FullName).Equals($SelectedRelativePath, [System.StringComparison]::OrdinalIgnoreCase)
      })
    if ($Selected.Count -ne 1) { throw "The Setup.ini-selected MSI path was not extracted uniquely: $SelectedRelativePath" }
    if ($NameWasSpecified -and -not ($Selected[0].Name -like $Pattern -or $Selected[0].FullName -like $Pattern -or $SelectedRelativePath -like $Pattern)) {
      throw "The Setup.ini-selected MSI path '$SelectedRelativePath' does not match the requested pattern: $Pattern"
    }
    return $Selected[0]
  }

  if (-not $NameWasSpecified) {
    $Reason = $null -eq $Selection ? 'no Setup.ini selection metadata is available' : "selection method '$($Selection.SelectionMethod)' did not resolve an embedded MSI"
    throw "InstallShield MSI selection is ambiguous because $Reason; specify -Name for a reviewed manual override"
  }

  return Resolve-InstallShieldMatch -Item $Item -Pattern $Pattern
}

function Expand-InstallShieldInstaller {
  <#
  .SYNOPSIS
    Extract files from an InstallShield executable using the in-process parser
  .PARAMETER Path
    The path to the InstallShield installer
  .PARAMETER DestinationPath
    The destination directory for extracted files
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the InstallShield installer')]
    [string]$Path,

    [Parameter(HelpMessage = 'The destination directory for extracted files')]
    [string]$DestinationPath
  )

  process {
    $InstallerPath = (Get-Item -Path $Path -Force).FullName
    if ([string]::IsNullOrWhiteSpace($DestinationPath)) {
      $DestinationPath = Join-Path (Split-Path -Path $InstallerPath -Parent) ((Split-Path -Path $InstallerPath -LeafBase) + '_u')
    }

    $DestinationPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($DestinationPath)
    Invoke-InstallShieldExtraction -Path $InstallerPath -DestinationPath $DestinationPath | Out-Null
    return $DestinationPath
  }
}

function Get-InstallShieldInfo {
  <#
  .SYNOPSIS
    Extract and classify an InstallShield installer statically
  .PARAMETER Path
    The path to the InstallShield installer
  .PARAMETER DestinationPath
    The destination directory for extracted files
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the InstallShield installer')]
    [string]$Path,

    [Parameter(HelpMessage = 'The destination directory for extracted files')]
    [string]$DestinationPath
  )

  process {
    $InstallerPath = (Get-Item -Path $Path -Force).FullName
    $ExtractedPath = Expand-InstallShieldInstaller -Path $InstallerPath -DestinationPath $DestinationPath

    $MsiFiles = @(Get-ChildItem -Path $ExtractedPath -Filter '*.msi' -Recurse -File -ErrorAction SilentlyContinue | Sort-Object FullName)
    $InxFiles = @(Get-ChildItem -Path $ExtractedPath -Include '*.inx', '*.ins' -Recurse -File -ErrorAction SilentlyContinue)
    $CabFiles = @(Get-ChildItem -Path $ExtractedPath -Include '*.cab', '*.hdr' -Recurse -File -ErrorAction SilentlyContinue)
    $SfxFiles = @(Get-ChildItem -Path $ExtractedPath -Filter '*_sfx.exe' -Recurse -File -ErrorAction SilentlyContinue)
    $MsiPayloadSelection = Get-InstallShieldMsiPayloadSelection -ExtractedPath $ExtractedPath -MsiFile $MsiFiles

    $Variant = if ($MsiFiles) {
      'Basic MSI or InstallScript MSI'
    } elseif ($InxFiles) {
      'InstallScript'
    } elseif ($CabFiles -or $SfxFiles) {
      'InstallShield payload without MSI'
    } else {
      'Unknown'
    }

    [pscustomobject]@{
      Path                = $InstallerPath
      ExtractedPath       = $ExtractedPath
      InstallerType       = 'InstallShield'
      Variant             = $Variant
      HasMsi              = [bool]$MsiFiles
      HasInstallScript    = [bool]$InxFiles
      MsiFiles            = @($MsiFiles | Select-Object -ExpandProperty FullName)
      SetupIniPath        = $MsiPayloadSelection.SetupIniPath
      SetupConfiguration  = $MsiPayloadSelection.Configuration
      MsiPayloadSelection = $MsiPayloadSelection
      SelectedMsiPath     = $MsiPayloadSelection.SelectedMsiPath
      InxFiles            = @($InxFiles | Select-Object -ExpandProperty FullName)
      CabFiles            = @($CabFiles | Select-Object -ExpandProperty FullName)
      SfxFiles            = @($SfxFiles | Select-Object -ExpandProperty FullName)
      Warnings            = @($MsiPayloadSelection.Warnings)
    }
  }
}

function Get-InstallShieldMsiInfo {
  <#
  .SYNOPSIS
    Read MSI metadata from a statically extracted InstallShield payload
  .PARAMETER Path
    The path to the InstallShield installer
  .PARAMETER Installer
    The parsed InstallShield metadata object
  .PARAMETER Name
    An optional reviewed file name or wildcard constraint; Setup.ini selection remains authoritative
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the InstallShield installer')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Installer', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The parsed InstallShield metadata object')]
    [psobject]$Installer,

    [Parameter(HelpMessage = 'The MSI file name or wildcard pattern to locate after extraction')]
    [string]$Name = '*.msi'
  )

  process {
    $NameWasSpecified = $PSBoundParameters.ContainsKey('Name')
    $TemporaryPath = $null
    $Installer = switch ($PSCmdlet.ParameterSetName) {
      'Path' {
        $TemporaryPath = New-TempFolder
        Get-InstallShieldInfo -Path $Path -DestinationPath $TemporaryPath
      }
      'Installer' { $Installer }
      default { throw 'Invalid parameter set.' }
    }

    try {
      $MsiFiles = @($Installer.MsiFiles | ForEach-Object { Get-Item -Path $_ -Force })
      $MsiFile = Resolve-InstallShieldMsiFile -Installer $Installer -Item $MsiFiles -Pattern $Name -NameWasSpecified $NameWasSpecified
      $MsiInfo = Get-MsiInstallerInfo -Path $MsiFile.FullName
      $SelectionProperty = $Installer.PSObject.Properties['MsiPayloadSelection']
      $SelectionMethod = $null -eq $SelectionProperty ? $null : $SelectionProperty.Value.SelectionMethod

      [pscustomobject]@{
        Name                         = $MsiFile.Name
        Path                         = $MsiFile.FullName
        SelectedMsiPath              = [System.IO.Path]::GetRelativePath($Installer.ExtractedPath, $MsiFile.FullName)
        SelectionMethod              = $SelectionMethod
        PackageArchitecture          = $MsiInfo.PackageArchitecture
        Template                     = $MsiInfo.Template
        ProductVersion               = $MsiInfo.ProductVersion
        ProductCode                  = $MsiInfo.ProductCode
        UpgradeCode                  = $MsiInfo.UpgradeCode
        ProductName                  = $MsiInfo.ProductName
        Publisher                    = $MsiInfo.Publisher
        InstallerBuilder             = $MsiInfo.InstallerBuilder
        InstallLocationProperty      = $MsiInfo.InstallLocationProperty
        InstallLocationSwitch        = $MsiInfo.InstallLocationSwitch
        IsWiX                        = $MsiInfo.InstallerBuilder -ceq 'WiX'
        AppsAndFeaturesInstallerType = $MsiInfo.AppsAndFeaturesInstallerType
        AppsAndFeaturesProductCode   = $MsiInfo.AppsAndFeaturesProductCode
        Protocols                    = $MsiInfo.Protocols
        FileExtensions               = $MsiInfo.FileExtensions
        RegistryAssociationInfo      = $MsiInfo.RegistryAssociationInfo
      }
    } finally {
      if ($TemporaryPath) {
        Remove-Item -Path $TemporaryPath -Recurse -Force -ErrorAction 'Continue' -ProgressAction 'SilentlyContinue'
      }
    }
  }
}

function Read-ProductVersionFromInstallShield {
  <#
  .SYNOPSIS
    Read ProductVersion from the MSI payload inside an InstallShield executable
  #>
  [OutputType([string])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory)]
    [string]$Path,

    [Parameter(ParameterSetName = 'Installer', Position = 0, ValueFromPipeline, Mandatory)]
    [psobject]$Installer,

    [string]$Name = '*.msi'
  )

  process { (Get-InstallShieldMsiInfo @PSBoundParameters).ProductVersion }
}

function Read-ProductCodeFromInstallShield {
  <#
  .SYNOPSIS
    Read ProductCode from the MSI payload inside an InstallShield executable
  #>
  [OutputType([string])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory)]
    [string]$Path,

    [Parameter(ParameterSetName = 'Installer', Position = 0, ValueFromPipeline, Mandatory)]
    [psobject]$Installer,

    [string]$Name = '*.msi'
  )

  process { (Get-InstallShieldMsiInfo @PSBoundParameters).ProductCode }
}

function Read-UpgradeCodeFromInstallShield {
  <#
  .SYNOPSIS
    Read UpgradeCode from the MSI payload inside an InstallShield executable
  #>
  [OutputType([string])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory)]
    [string]$Path,

    [Parameter(ParameterSetName = 'Installer', Position = 0, ValueFromPipeline, Mandatory)]
    [psobject]$Installer,

    [string]$Name = '*.msi'
  )

  process { (Get-InstallShieldMsiInfo @PSBoundParameters).UpgradeCode }
}

Export-ModuleMember -Function Get-InstallShieldInfo, Expand-InstallShieldInstaller, Get-InstallShieldMsiInfo, Read-ProductVersionFromInstallShield, Read-ProductCodeFromInstallShield, Read-UpgradeCodeFromInstallShield
