# SPDX-License-Identifier: MIT
# This shared source is kept byte-identical in PackageModule and InstallerParsers.

function Assert-InstallerInfrastructureLoaded {
  <#
  .SYNOPSIS
    Verify deterministic runtime loading before a shared binary operation
  #>
  if (-not ([System.Management.Automation.PSTypeName]'Dumplings.InstallerInfrastructure.BinaryIO').Type) {
    if (Get-Command -Name Import-InstallerInfrastructure -ErrorAction Ignore) { Import-InstallerInfrastructure }
    else { throw 'Runtime.psm1 must be loaded before Binary.psm1.' }
  }
}

function Import-BinaryPatternSearch {
  <#
  .SYNOPSIS
    Load the shared installer infrastructure
  .NOTES
    Retained for compatibility with callers of the former standalone matcher.
  #>
  Assert-InstallerInfrastructureLoaded
}

function New-BoundedReadStream {
  <#
  .SYNOPSIS
    Create a read-only seekable view over an exact stream range
  #>
  [OutputType([System.IO.Stream])]
  param (
    [Parameter(Mandatory)][System.IO.Stream]$Stream,
    [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$Offset,
    [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$Length,
    [switch]$LeaveOpen
  )
  Assert-InstallerInfrastructureLoaded
  return [Dumplings.InstallerInfrastructure.BoundedReadStream]::new($Stream, $Offset, $Length, $LeaveOpen.IsPresent)
}

function New-InstallerSeekableStream {
  <#
  .SYNOPSIS
    Make nested content seekable with bounded memory and automatic disk spill
  .OUTPUTS
    SeekableStreamContext. Dispose it after using its Stream property.
  #>
  param (
    [Parameter(Mandatory)][System.IO.Stream]$SourceStream,
    [Parameter(Mandatory)][ValidateRange(1, [long]::MaxValue)][long]$MaximumBytes,
    [ValidateRange(1, [long]::MaxValue)][long]$MemoryThresholdBytes = 16777216
  )
  Assert-InstallerInfrastructureLoaded
  return [Dumplings.InstallerInfrastructure.SeekableStreamContext]::Create($SourceStream, $MaximumBytes, $MemoryThresholdBytes)
}

function Read-BinaryBytes {
  <#
  .SYNOPSIS
    Read a bounded byte range and restore the stream position
  #>
  [OutputType([byte[]])]
  param (
    [Parameter(Mandatory)][System.IO.Stream]$Stream,
    [Parameter(Mandatory)][long]$Offset,
    [Parameter(Mandatory)][ValidateRange(0, [int]::MaxValue)][int]$Count,
    [switch]$AllowPartial
  )
  Assert-InstallerInfrastructureLoaded
  if (-not $Stream.CanSeek) { throw 'Random-access binary reads require a seekable stream.' }
  if ($Offset -lt 0 -or $Offset -gt $Stream.Length) { throw "Binary read offset is outside the stream: $Offset" }
  $ActualCount = if ($AllowPartial) { [int][Math]::Min($Count, $Stream.Length - $Offset) } else { $Count }
  return [Dumplings.InstallerInfrastructure.BinaryIO]::ReadExactly($Stream, $Offset, $ActualCount, $true)
}

function Read-BinaryInteger {
  <#
  .SYNOPSIS
    Read a signed or unsigned integer with explicit endianness
  #>
  param (
    [Parameter(Mandatory)][System.IO.Stream]$Stream,
    [Parameter(Mandatory)][long]$Offset,
    [Parameter(Mandatory)][ValidateSet(1, 2, 4, 8)][int]$Size,
    [ValidateSet('LittleEndian', 'BigEndian')][string]$Endian = 'LittleEndian',
    [switch]$Signed
  )
  $Bytes = Read-BinaryBytes -Stream $Stream -Offset $Offset -Count $Size
  if (($Endian -eq 'BigEndian') -eq [BitConverter]::IsLittleEndian) { [Array]::Reverse($Bytes) }
  switch ($Size) {
    1 { if ($Signed) { return [sbyte]$Bytes[0] }; return [byte]$Bytes[0] }
    2 { if ($Signed) { return [BitConverter]::ToInt16($Bytes, 0) }; return [BitConverter]::ToUInt16($Bytes, 0) }
    4 { if ($Signed) { return [BitConverter]::ToInt32($Bytes, 0) }; return [BitConverter]::ToUInt32($Bytes, 0) }
    8 { if ($Signed) { return [BitConverter]::ToInt64($Bytes, 0) }; return [BitConverter]::ToUInt64($Bytes, 0) }
  }
}

function Find-BinaryPattern {
  <#
  .SYNOPSIS
    Find bounded, optionally aligned byte-pattern offsets
  #>
  [OutputType([long[]])]
  param (
    [Parameter(Mandatory, ParameterSetName = 'File')][string]$Path,
    [Parameter(Mandatory, ParameterSetName = 'Stream')][System.IO.Stream]$Stream,
    [Parameter(Mandatory, ParameterSetName = 'Buffer')][byte[]]$Bytes,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][byte[]]$Pattern,
    [ValidateRange(0, [long]::MaxValue)][long]$StartOffset = 0,
    [ValidateRange(0, [long]::MaxValue)][long]$Length = 0,
    [ValidateRange(1, [int]::MaxValue)][int]$Maximum = 128,
    [ValidateRange(1, [int]::MaxValue)][int]$Alignment = 1,
    [switch]$Reverse
  )
  Assert-InstallerInfrastructureLoaded
  switch ($PSCmdlet.ParameterSetName) {
    'File' {
      return [Dumplings.InstallerInfrastructure.PatternSearch]::FindFile(
        (Get-Item -LiteralPath $Path -Force).FullName, $Pattern, $StartOffset, $Length, $Maximum, $Reverse.IsPresent, $Alignment)
    }
    'Stream' {
      return [Dumplings.InstallerInfrastructure.PatternSearch]::FindStream(
        $Stream, $Pattern, $StartOffset, $Length, $Maximum, $Reverse.IsPresent, $Alignment, $true)
    }
    'Buffer' {
      if ($StartOffset -gt [int]::MaxValue -or $Length -gt [int]::MaxValue) { throw 'Byte-array search bounds exceed Int32 limits.' }
      return [Dumplings.InstallerInfrastructure.PatternSearch]::FindBuffer(
        $Bytes, $Pattern, [int]$StartOffset, [int]$Length, $Maximum, $Reverse.IsPresent, $Alignment)
    }
  }
}

function Copy-BoundedStream {
  <#
  .SYNOPSIS
    Copy sequential stream content with hard input and expected-length bounds
  #>
  [OutputType([long])]
  param (
    [Parameter(Mandatory)][System.IO.Stream]$Source,
    [Parameter(Mandatory)][System.IO.Stream]$Destination,
    [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$MaximumBytes,
    [ValidateRange(0, [long]::MaxValue)][long]$ExpectedBytes
  )
  Assert-InstallerInfrastructureLoaded
  $Expected = if ($PSBoundParameters.ContainsKey('ExpectedBytes')) { $ExpectedBytes } else { -1L }
  return [Dumplings.InstallerInfrastructure.BinaryIO]::CopyBounded($Source, $Destination, $MaximumBytes, $Expected)
}

function Copy-BinaryStreamRange {
  <#
  .SYNOPSIS
    Copy an exact bounded stream range
  #>
  param (
    [Parameter(Mandatory)][System.IO.Stream]$Source,
    [Parameter(Mandatory)][System.IO.Stream]$Destination,
    [Parameter(Mandatory)][long]$Offset,
    [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$Length
  )
  $Range = New-BoundedReadStream -Stream $Source -Offset $Offset -Length $Length -LeaveOpen
  try { $null = Copy-BoundedStream -Source $Range -Destination $Destination -MaximumBytes $Length -ExpectedBytes $Length }
  finally { $Range.Dispose() }
}

function Get-BinaryCrc32 {
  <#
  .SYNOPSIS
    Calculate CRC32 from a path, stream, or byte array
  #>
  [OutputType([uint32])]
  param (
    [Parameter(Mandatory, ParameterSetName = 'Path')][string]$Path,
    [Parameter(Mandatory, ParameterSetName = 'Stream')][System.IO.Stream]$Stream,
    [Parameter(Mandatory, ParameterSetName = 'Bytes')][byte[]]$Bytes,
    [ValidateRange(0, [long]::MaxValue)][long]$MaximumBytes = [long]::MaxValue
  )
  Assert-InstallerInfrastructureLoaded
  switch ($PSCmdlet.ParameterSetName) {
    'Bytes' { return [Dumplings.InstallerInfrastructure.BinaryIO]::Crc32($Bytes) }
    'Stream' { return [Dumplings.InstallerInfrastructure.BinaryIO]::Crc32($Stream, $true, $MaximumBytes) }
    'Path' {
      $InputStream = [IO.File]::Open((Get-Item -LiteralPath $Path -Force).FullName, 'Open', 'Read', 'ReadWrite')
      try { return [Dumplings.InstallerInfrastructure.BinaryIO]::Crc32($InputStream, $false, $MaximumBytes) }
      finally { $InputStream.Dispose() }
    }
  }
}

function Test-BinarySequence {
  <#
  .SYNOPSIS
    Compare two byte arrays without PowerShell enumeration overhead
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Left,
    [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Right
  )
  Assert-InstallerInfrastructureLoaded
  return [Dumplings.InstallerInfrastructure.BinaryIO]::SequenceEqual($Left, $Right)
}

function Resolve-SafeExtractionPath {
  <#
  .SYNOPSIS
    Resolve a relative payload path without allowing extraction-root escape
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][string]$DestinationPath,
    [Parameter(Mandatory)][string]$RelativePath
  )
  if ([string]::IsNullOrWhiteSpace($RelativePath) -or $RelativePath.IndexOf([char]0) -ge 0) { throw 'The payload path is empty or invalid.' }
  $Normalized = $RelativePath.Replace('/', [IO.Path]::DirectorySeparatorChar).Replace('\', [IO.Path]::DirectorySeparatorChar)
  if ([IO.Path]::IsPathRooted($Normalized) -or $Normalized -match '^[A-Za-z]:') { throw "The payload path is rooted: $RelativePath" }
  $Root = [IO.Path]::GetFullPath($DestinationPath).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
  $Output = [IO.Path]::GetFullPath([IO.Path]::Combine($Root, $Normalized.TrimStart([IO.Path]::DirectorySeparatorChar)))
  if (-not $Output.StartsWith($Root, [StringComparison]::OrdinalIgnoreCase)) { throw "The payload path escapes the destination: $RelativePath" }
  return $Output
}

function Test-ExtractionPattern {
  <#
  .SYNOPSIS
    Test a payload path and file name against a wildcard selector
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Pattern
  )
  $NormalizedPath = $Path.Replace('\', '/')
  $NormalizedPattern = $Pattern.Replace('\', '/')
  return $NormalizedPath -like $NormalizedPattern -or [IO.Path]::GetFileName($NormalizedPath) -like $NormalizedPattern
}

Export-ModuleMember -Function Import-BinaryPatternSearch, New-BoundedReadStream, New-InstallerSeekableStream, Read-BinaryBytes, Read-BinaryInteger, Find-BinaryPattern, Copy-BoundedStream, Copy-BinaryStreamRange, Get-BinaryCrc32, Test-BinarySequence, Resolve-SafeExtractionPath, Test-ExtractionPattern
