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
  # Prevent PowerShell from expanding byte arrays into boxed pipeline objects.
  return , ([Dumplings.InstallerInfrastructure.BinaryIO]::ReadExactly($Stream, $Offset, $ActualCount, $true))
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

function Read-BinarySequentialInteger {
  <#
  .SYNOPSIS
    Consume one integer from the current position of a sequential stream.
  .PARAMETER Stream
    Caller-owned stream. The function advances it by Size bytes and does not dispose it.
  .PARAMETER Size
    Integer width in bytes.
  .PARAMETER Endian
    Byte order used by the encoded integer.
  .PARAMETER Signed
    Interpret the value as signed.
  #>
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][ValidateSet(1, 2, 4, 8)][int]$Size,
    [ValidateSet('LittleEndian', 'BigEndian')][string]$Endian = 'LittleEndian',
    [switch]$Signed
  )

  $Bytes = [byte[]]::new($Size)
  $Read = 0
  while ($Read -lt $Size) {
    $Count = $Stream.Read($Bytes, $Read, $Size - $Read)
    if ($Count -le 0) { throw 'Unexpected end of stream while reading an integer.' }
    $Read += $Count
  }
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

function Copy-BinaryXorStream {
  <#
  .SYNOPSIS
    Copy an exact sequential stream range while applying a fixed XOR byte
  #>
  [OutputType([long])]
  param (
    [Parameter(Mandatory)][System.IO.Stream]$Source,
    [Parameter(Mandatory)][System.IO.Stream]$Destination,
    [Parameter(Mandatory)][byte]$Key,
    [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$ExpectedBytes
  )
  Assert-InstallerInfrastructureLoaded
  return [Dumplings.InstallerInfrastructure.BinaryIO]::CopyXor($Source, $Destination, $Key, $ExpectedBytes)
}

function Get-BinaryCrc32 {
  <#
  .SYNOPSIS
    Calculate CRC32 from a path, stream, or byte array
  .PARAMETER Offset
    The first byte-array offset included in the checksum
  .PARAMETER Count
    The number of byte-array values to include, or -1 for the remaining values
  .PARAMETER MaximumBytes
    The maximum number of stream or file bytes to checksum
  .PARAMETER SuffixBytes
    Optional bytes incorporated after the stream or file range without buffering it.
  #>
  [OutputType([uint32])]
  param (
    [Parameter(Mandatory, ParameterSetName = 'Path')][string]$Path,
    [Parameter(Mandatory, ParameterSetName = 'Stream')][System.IO.Stream]$Stream,
    [Parameter(Mandatory, ParameterSetName = 'Bytes')][byte[]]$Bytes,
    [Parameter(ParameterSetName = 'Bytes')][ValidateRange(0, [int]::MaxValue)][int]$Offset = 0,
    [Parameter(ParameterSetName = 'Bytes')][ValidateRange(-1, [int]::MaxValue)][int]$Count = -1,
    [ValidateRange(0, [long]::MaxValue)][long]$MaximumBytes = [long]::MaxValue,
    [Parameter(ParameterSetName = 'Path')]
    [Parameter(ParameterSetName = 'Stream')]
    [AllowEmptyCollection()][byte[]]$SuffixBytes
  )
  Assert-InstallerInfrastructureLoaded
  switch ($PSCmdlet.ParameterSetName) {
    'Bytes' {
      if ($Offset -gt $Bytes.Length) { throw 'The CRC32 byte offset is outside the input array.' }
      if ($Count -lt 0) { $Count = $Bytes.Length - $Offset }
      if ($Count -gt $Bytes.Length - $Offset) { throw 'The CRC32 byte range is outside the input array.' }
      return [Dumplings.InstallerInfrastructure.BinaryIO]::Crc32($Bytes, $Offset, $Count)
    }
    'Stream' { return [Dumplings.InstallerInfrastructure.BinaryIO]::Crc32($Stream, $true, $MaximumBytes, $SuffixBytes) }
    'Path' {
      $InputStream = [IO.File]::Open((Get-Item -LiteralPath $Path -Force).FullName, 'Open', 'Read', 'ReadWrite')
      try { return [Dumplings.InstallerInfrastructure.BinaryIO]::Crc32($InputStream, $false, $MaximumBytes, $SuffixBytes) }
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

function Read-InstallerCollisionAction {
  <#
  .SYNOPSIS
    Prompt for or return a concrete extraction collision action
  .PARAMETER CollisionAction
    Requested collision behavior. Prompt displays an interactive choice; every
    other value is returned unchanged for programmatic callers.
  .PARAMETER Path
    Optional colliding output path included in the prompt message.
  #>
  [OutputType([string])]
  param (
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')]
    [string]$CollisionAction = 'Prompt',

    [string]$Path
  )

  if ($CollisionAction -ne 'Prompt') { return $CollisionAction }

  $Choices = [System.Management.Automation.Host.ChoiceDescription[]]@(
    [System.Management.Automation.Host.ChoiceDescription]::new('&Error', 'Stop extraction without changing the colliding output.')
    [System.Management.Automation.Host.ChoiceDescription]::new('&Skip', 'Keep the existing output and skip the new payload.')
    [System.Management.Automation.Host.ChoiceDescription]::new('&Overwrite', 'Replace the existing output with the new payload.')
    [System.Management.Automation.Host.ChoiceDescription]::new('&Rename', 'Keep both outputs by adding a numeric suffix to the new payload.')
  )
  $Message = if ([string]::IsNullOrWhiteSpace($Path)) {
    'Choose the behavior to use when an extraction output path collides.'
  } else {
    "Choose how to handle the extraction output collision:`n$Path"
  }
  try {
    $Selection = $Host.UI.PromptForChoice('Installer extraction collision', $Message, $Choices, 3)
  } catch {
    throw 'The host cannot prompt for an extraction collision action. Specify -CollisionAction explicitly.'
  }
  if ($Selection -lt 0 -or $Selection -ge $Choices.Count) {
    throw 'No extraction collision action was selected.'
  }
  return @('Error', 'Skip', 'Overwrite', 'Rename')[$Selection]
}

function Resolve-InstallerExtractionTarget {
  <#
  .SYNOPSIS
    Resolve a safe output path and apply the selected collision policy
  .PARAMETER DestinationPath
    Absolute or PowerShell-relative extraction root.
  .PARAMETER RelativePath
    Untrusted payload-relative file path.
  .PARAMETER CollisionAction
    Prompt, error, skip, overwrite, or deterministically rename a colliding file.
  .PARAMETER ReservedPath
    Optional case-insensitive path set used to reserve outputs before files are written.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$DestinationPath,
    [Parameter(Mandatory)][string]$RelativePath,
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Rename',
    [System.Collections.Generic.ISet[string]]$ReservedPath
  )

  $OriginalPath = Resolve-SafeExtractionPath -DestinationPath $DestinationPath -RelativePath $RelativePath
  $HasCollision = (Test-Path -LiteralPath $OriginalPath) -or ($ReservedPath -and $ReservedPath.Contains($OriginalPath))
  $OutputPath = $OriginalPath
  $Disposition = 'Create'
  $ShouldWrite = $true

  if ($HasCollision) {
    $CollisionAction = Read-InstallerCollisionAction -CollisionAction $CollisionAction -Path $OriginalPath
    switch ($CollisionAction) {
      'Error' { throw "The extraction output already exists: $OriginalPath" }
      'Skip' {
        $Disposition = 'Skip'
        $ShouldWrite = $false
      }
      'Overwrite' {
        if ((Test-Path -LiteralPath $OriginalPath -PathType Container)) {
          throw "A directory occupies the extraction output path: $OriginalPath"
        }
        $Disposition = 'Overwrite'
      }
      'Rename' {
        $Directory = [IO.Path]::GetDirectoryName($OriginalPath)
        $BaseName = [IO.Path]::GetFileNameWithoutExtension($OriginalPath)
        $Extension = [IO.Path]::GetExtension($OriginalPath)
        for ($Index = 1; $Index -le 1000000; $Index++) {
          $Candidate = Join-Path $Directory ("$BaseName ($Index)$Extension")
          if (-not (Test-Path -LiteralPath $Candidate) -and (-not $ReservedPath -or -not $ReservedPath.Contains($Candidate))) {
            $OutputPath = $Candidate
            $Disposition = 'Rename'
            break
          }
        }
        if ($OutputPath -eq $OriginalPath) { throw "No collision-free extraction path could be allocated for: $OriginalPath" }
      }
    }
  }

  if ($ShouldWrite -and $ReservedPath) { $null = $ReservedPath.Add($OutputPath) }
  return [pscustomobject]@{
    Path         = $OutputPath
    OriginalPath = $OriginalPath
    ShouldWrite  = $ShouldWrite
    Disposition  = $Disposition
  }
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

function Resolve-UniqueInstallerFile {
  <#
  .SYNOPSIS
    Resolve one deterministic file from exact or wildcard installer payload evidence
  .PARAMETER Item
    Candidate files. Null entries are ignored and the original FileInfo object is returned.
  .PARAMETER Pattern
    A file name, path relative to BasePath, absolute path, or wildcard selector.
  .PARAMETER BasePath
    Optional extraction root used to compare payload-relative paths.
  .PARAMETER Description
    Human-readable payload description used in deterministic failure messages.
  #>
  [OutputType([System.IO.FileInfo])]
  param (
    [Parameter(Mandatory)][AllowEmptyCollection()][System.IO.FileInfo[]]$Item,
    [Parameter(Mandatory)][string]$Pattern,
    [string]$BasePath,
    [string]$Description = 'installer payload'
  )

  $Candidates = @($Item | Where-Object { $null -ne $_ })
  if ($Candidates.Count -eq 0) { throw "No candidate files are available for the $Description." }
  if ([string]::IsNullOrWhiteSpace($Pattern)) { throw "The $Description selection pattern is empty." }

  $NormalizedPattern = $Pattern.Replace('\', '/')
  $ExactMatches = [Collections.Generic.List[System.IO.FileInfo]]::new()
  $WildcardMatches = [Collections.Generic.List[System.IO.FileInfo]]::new()
  foreach ($Candidate in $Candidates) {
    $FullName = $Candidate.FullName.Replace('\', '/')
    $RelativeName = if ($BasePath) {
      [IO.Path]::GetRelativePath($BasePath, $Candidate.FullName).Replace('\', '/')
    } else {
      $Candidate.Name
    }
    if ($Candidate.Name -ieq $Pattern -or $FullName -ieq $NormalizedPattern -or $RelativeName -ieq $NormalizedPattern) {
      $ExactMatches.Add($Candidate)
    }
    if (Test-ExtractionPattern -Path $RelativeName -Pattern $NormalizedPattern) {
      $WildcardMatches.Add($Candidate)
    }
  }

  # Exact configured paths take precedence over wildcard interpretation. This matters when
  # literal square brackets or wildcard characters are valid characters in a payload name.
  if ($ExactMatches.Count -eq 1) { return $ExactMatches[0] }
  if ($ExactMatches.Count -gt 1) { throw "Multiple files exactly matched the $Description pattern: $Pattern" }
  if ($WildcardMatches.Count -eq 1) { return $WildcardMatches[0] }
  if ($WildcardMatches.Count -eq 0) { throw "No $Description matched the pattern: $Pattern" }
  throw "Multiple files matched the $Description pattern: $Pattern"
}

Export-ModuleMember -Function New-BoundedReadStream, New-InstallerSeekableStream, Read-BinaryBytes, Read-BinaryInteger, Read-BinarySequentialInteger, Find-BinaryPattern, Copy-BoundedStream, Copy-BinaryStreamRange, Copy-BinaryXorStream, Get-BinaryCrc32, Test-BinarySequence, Read-InstallerCollisionAction, Resolve-InstallerExtractionTarget, Test-ExtractionPattern, Resolve-UniqueInstallerFile
