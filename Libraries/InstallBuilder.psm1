# SPDX-License-Identifier: Apache-2.0
# Format research: https://gist.github.com/mickael9/0b902da7c13207d1b86e
# Static BitRock/VMware InstallBuilder parser. InstallBuilder embeds its project
# VFS in a TclKit/Metakit container; this module reads bounded project records
# and CookFS pages but never loads Tcl, TclKit, or the installer executable.
# Binary structure consumed here (CookFS integers are BE):
#
#   PE/TclKit
#   +-- Metakit VFS -> zlib project.xml
#   `-- CookFS pages -> page-size table (u32 BE)* -> compressed index
#       -> index magic "CFS2.200" -> 16-byte footer -> "CFS0002"
#
# Footer-relative fields are IndexSize@-16, PageCount@-12, and compression@-8.
# CookFS records begin with a compression ID (stored/Deflate/BZip2/custom LZMA).
# Encrypted/custom records are rejected; page/index/count/path limits are enforced.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:InstallBuilderMaximumCandidates = 4096
$Script:InstallBuilderMaximumProjectBytes = 16777216
$Script:InstallBuilderMarkerSearchRadius = 16777216
$Script:InstallBuilderMaximumCookfsIndexBytes = 67108864
$Script:InstallBuilderMaximumCookfsPages = 1000000
$Script:InstallBuilderMaximumCookfsPageBytes = 536870912
$Script:InstallBuilderMaximumCookfsEntries = 200000
$Script:InstallBuilderCookfsPageCacheSize = 16
$Script:InstallBuilderCookfsPageCacheBytes = 67108864
$Script:InstallBuilderMaximumLzmaDictionaryBytes = 134217728

function Get-InstallBuilderCandidateOffset {
  <#
  .SYNOPSIS
    Return plausible zlib stream offsets near an embedded project.xml record
  .DESCRIPTION
    Metakit stores VFS file names and compressed payloads separately. The
    project.xml name is a stable nearby anchor; a full-file fallback supports
    layouts that place its compressed record elsewhere in the container.
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([long[]])]
  param ([Parameter(Mandatory)][string]$Path)

  $File = Get-Item -LiteralPath $Path -Force
  $ProjectMarker = [Text.Encoding]::ASCII.GetBytes('project.xml')
  $ZlibStart = [byte[]](0x78)
  $Offsets = [System.Collections.Generic.HashSet[long]]::new()
  # Metakit stores names separately from compressed records. Use each project.xml name as a local
  # search anchor instead of trying every zlib-looking byte in a large payload.
  $ProjectOffsets = @(Find-BinaryPattern -Path $File.FullName -Pattern $ProjectMarker -Maximum 32 -Reverse)
  foreach ($ProjectOffset in $ProjectOffsets) {
    $StartOffset = [Math]::Max(0, $ProjectOffset - 65536)
    $Length = [Math]::Min($Script:InstallBuilderMarkerSearchRadius, $File.Length - $StartOffset)
    foreach ($Offset in @(Find-BinaryPattern -Path $File.FullName -Pattern $ZlibStart -StartOffset $StartOffset -Length $Length -Maximum $Script:InstallBuilderMaximumCandidates)) {
      $null = $Offsets.Add($Offset)
    }
  }

  # A project record can be outside the nearby VFS-name table in older
  # InstallBuilder releases. Fall back to a bounded whole-file candidate scan.
  if ($Offsets.Count -eq 0) {
    foreach ($Offset in @(Find-BinaryPattern -Path $File.FullName -Pattern $ZlibStart -Maximum $Script:InstallBuilderMaximumCandidates)) {
      $null = $Offsets.Add($Offset)
    }
  }

  $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    foreach ($Offset in ($Offsets | Sort-Object)) {
      if ($Offset + 2 -gt $Stream.Length) { continue }
      $Header = Read-BinaryBytes -Stream $Stream -Offset $Offset -Count 2
      $Combined = (([int]$Header[0] -shl 8) -bor [int]$Header[1])
      # RFC 1950 validation: CMF/FLG must be divisible by 31 and this parser
      # deliberately rejects preset-dictionary streams it cannot validate.
      if (($Combined % 31) -eq 0 -and ($Header[1] -band 0x20) -eq 0) { [long]$Offset }
    }
  } finally {
    $Stream.Dispose()
  }
}

function Read-InstallBuilderZlibProject {
  <#
  .SYNOPSIS
    Read one bounded zlib record and return project XML when present
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER Offset
    Byte offset in the coordinate system named by this function: absolute file, PE/resource, overlay, or record relative.
  .PARAMETER MaximumExpandedBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][long]$Offset,
    [ValidateRange(1024, [long]::MaxValue)][long]$MaximumExpandedBytes = $Script:InstallBuilderMaximumProjectBytes
  )

  $File = Get-Item -LiteralPath $Path -Force
  $Source = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  $Output = [IO.MemoryStream]::new()
  try {
    # The zlib decoder stops at its own stream end; the output bound prevents an unrelated or
    # malicious candidate from expanding without limit.
    $Range = New-BoundedReadStream -Stream $Source -Offset $Offset -Length ($Source.Length - $Offset) -LeaveOpen
    try { $null = Expand-InstallerCompressedStream -Algorithm Zlib -Stream $Range -Destination $Output -MaximumBytes $MaximumExpandedBytes }
    finally { $Range.Dispose() }
    $Content = [Text.Encoding]::UTF8.GetString($Output.ToArray()).TrimStart([char]0xFEFF, [char]0)
    $Start = $Content.IndexOf('<project', [StringComparison]::OrdinalIgnoreCase)
    if ($Start -lt 0) { return $null }
    $EndTag = '</project>'
    $End = $Content.IndexOf($EndTag, $Start, [StringComparison]::OrdinalIgnoreCase)
    if ($End -lt 0) { return $null }
    [pscustomobject]@{ Offset = $Offset; Content = $Content.Substring($Start, $End - $Start + $EndTag.Length); Length = $Output.Length }
  } catch {
    return $null
  } finally {
    $Output.Dispose()
    $Source.Dispose()
  }
}

function Get-InstallBuilderProjectData {
  <#
  .SYNOPSIS
    Locate and decompress the InstallBuilder project XML from a Metakit VFS
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER MaximumExpandedBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [ValidateRange(1024, [long]::MaxValue)][long]$MaximumExpandedBytes = $Script:InstallBuilderMaximumProjectBytes
  )

  $File = Get-Item -LiteralPath $Path -Force
  $Marker = [Text.Encoding]::ASCII.GetBytes('project.xml')
  if (-not @(Find-BinaryPattern -Path $File.FullName -Pattern $Marker -Maximum 1)) {
    throw 'The file does not contain an InstallBuilder project.xml VFS marker'
  }
  # Accept the first candidate that expands to a complete project root, not merely XML fragments.
  foreach ($Offset in @(Get-InstallBuilderCandidateOffset -Path $File.FullName)) {
    $Project = Read-InstallBuilderZlibProject -Path $File.FullName -Offset $Offset -MaximumExpandedBytes $MaximumExpandedBytes
    if ($Project) { return $Project }
  }
  throw 'The InstallBuilder Metakit VFS contains project.xml but no supported bounded zlib project record was found'
}

function Get-InstallBuilderXmlValue {
  <#
  .SYNOPSIS
    Read one trimmed InstallBuilder project XML value.
  .PARAMETER Xml
    XML node used as the XPath context.
  .PARAMETER XPath
    Relative or absolute XPath identifying the requested scalar node.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][System.Xml.XmlNode]$Xml, [Parameter(Mandatory)][string]$XPath)
  $Node = $Xml.SelectSingleNode($XPath)
  if (-not $Node) { return $null }
  $Value = $Node.InnerText.Trim()
  if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
  return $Value
}

function Get-InstallBuilderRegistryWrite {
  <#
  .SYNOPSIS
    Read literal registrySet actions from an InstallBuilder project
  .PARAMETER Xml
    Parsed format configuration used to resolve static installer metadata and payload selection.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][xml]$Xml)
  # Registry metadata is returned only from literal project actions; Tcl substitutions remain
  # unresolved strings for downstream manual review.
  foreach ($Action in @($Xml.SelectNodes('//registrySet'))) {
    $Key = Get-InstallBuilderXmlValue -Xml $Action -XPath 'key'
    if ([string]::IsNullOrWhiteSpace($Key)) { continue }
    [pscustomobject]@{
      Root  = if ($Key -match '^HKEY_LOCAL_MACHINE|^HKLM') { 'HKLM' } elseif ($Key -match '^HKEY_CURRENT_USER|^HKCU') { 'HKCU' } else { $null }
      Key   = $Key -replace '^HKEY_LOCAL_MACHINE\\?', '' -replace '^HKLM\\?', '' -replace '^HKEY_CURRENT_USER\\?', '' -replace '^HKCU\\?', ''
      Name  = Get-InstallBuilderXmlValue -Xml $Action -XPath 'name'
      Value = Get-InstallBuilderXmlValue -Xml $Action -XPath 'value'
      Type  = Get-InstallBuilderXmlValue -Xml $Action -XPath 'type'
    }
  }
}

function Get-InstallBuilderScopeInfo {
  <#
  .SYNOPSIS
    Derive scope evidence from structured InstallBuilder project settings.
  .PARAMETER Xml
    Parsed project.xml document. Literal root-install and HKCU/HKLM branches are inspected without executing Tcl.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][xml]$Xml)
  $RequireAdministrator = Get-InstallBuilderXmlValue -Xml $Xml -XPath '/project/requireInstallationByRootUser'
  if ($RequireAdministrator -match '^(1|true|yes)$') {
    return [pscustomobject]@{ Scope = 'machine'; SupportedScopes = @('machine'); Confidence = 'high'; Evidence = 'requireInstallationByRootUser=1' }
  }
  # A root-install branch with both ARP hives is evidence of elevation-dependent dual scope. One
  # literal hive without such a branch is treated as a fixed scope.
  $ProjectText = $Xml.OuterXml
  $HasMachineArpPath = $ProjectText -match '(?is)HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall'
  $HasUserArpPath = $ProjectText -match '(?is)HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall'
  $UsesRootScopeBranch = $ProjectText -match '(?is)\$\{installer_is_root_install\}'
  if ($UsesRootScopeBranch -and $HasMachineArpPath -and $HasUserArpPath) {
    return [pscustomobject]@{ Scope = 'user'; SupportedScopes = @('user', 'machine'); Confidence = 'medium'; Evidence = 'Project branches on ${installer_is_root_install} and contains HKCU/HKLM uninstall paths.' }
  }
  if ($HasMachineArpPath) { return [pscustomobject]@{ Scope = 'machine'; SupportedScopes = @('machine'); Confidence = 'medium'; Evidence = 'Project contains an HKLM uninstall path.' } }
  if ($HasUserArpPath) { return [pscustomobject]@{ Scope = 'user'; SupportedScopes = @('user'); Confidence = 'medium'; Evidence = 'Project contains an HKCU uninstall path.' } }
  return [pscustomobject]@{ Scope = $null; SupportedScopes = @(); Confidence = 'unknown'; Evidence = 'InstallBuilder project does not contain statically provable uninstall scope evidence.' }
}

function Read-InstallBuilderBigEndianUInt32 {
  <#
  .SYNOPSIS
    Read a bounded unsigned 32-bit integer from a CookFS byte buffer
  .PARAMETER Bytes
    Bounded format record or payload bytes interpreted by this function; the input array is not modified.
  .PARAMETER Position
    Current record position or zero-based index within the validated table.
  #>
  [OutputType([uint32])]
  param ([Parameter(Mandatory)][byte[]]$Bytes, [Parameter(Mandatory)][ref]$Position)
  if ($Position.Value -lt 0 -or $Position.Value + 4 -gt $Bytes.Length) { throw 'The CookFS index is truncated while reading an integer' }
  $Offset = $Position.Value
  $Position.Value += 4
  return ([uint32]$Bytes[$Offset] -shl 24) -bor ([uint32]$Bytes[$Offset + 1] -shl 16) -bor ([uint32]$Bytes[$Offset + 2] -shl 8) -bor [uint32]$Bytes[$Offset + 3]
}

function Skip-InstallBuilderCookfsByteRange {
  <#
  .SYNOPSIS
    Advance a CookFS index cursor across one validated byte range.
  .PARAMETER Bytes
    Complete expanded CookFS index byte array.
  .PARAMETER Position
    Mutable record-relative cursor. It is advanced by Count on success.
  .PARAMETER Count
    Number of bytes to skip. Negative or out-of-range values throw.
  #>
  param ([Parameter(Mandatory)][byte[]]$Bytes, [Parameter(Mandatory)][ref]$Position, [Parameter(Mandatory)][int]$Count)
  if ($Count -lt 0 -or $Position.Value + $Count -gt $Bytes.Length) { throw 'The CookFS index is truncated while reading an entry' }
  $Position.Value += $Count
}

function Expand-InstallBuilderCookfsRecord {
  <#
  .SYNOPSIS
    Decompress one CookFS stored page or index record
  .PARAMETER StoredBytes
    Bounded format record or payload bytes interpreted by this function; the input array is not modified.
  .PARAMETER MaximumExpandedBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  [OutputType([byte[]])]
  param (
    [Parameter(Mandatory)][byte[]]$StoredBytes,
    [Parameter(Mandatory)][ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes
  )

  if ($StoredBytes.Length -eq 0) { throw 'The CookFS stored record is empty' }
  # CookFS prepends a one-byte handler ID to every index/page record. Handler 255 is accepted only
  # when the following bytes form InstallBuilder's unencrypted LZMA-alone record.
  $CompressionId = $StoredBytes[0]
  if ($CompressionId -notin 0, 1, 2, 255) { throw "The CookFS record uses unknown compression identifier $CompressionId" }
  if ($CompressionId -eq 0) {
    if ($StoredBytes.Length - 1 -gt $MaximumExpandedBytes) { throw 'The CookFS uncompressed record exceeds the configured output limit' }
    $Result = [byte[]]::new($StoredBytes.Length - 1)
    if ($Result.Length) { [Array]::Copy($StoredBytes, 1, $Result, 0, $Result.Length) }
    return , $Result
  }
  if ($CompressionId -eq 2 -and $StoredBytes.Length -lt 5) { throw 'The CookFS BZip2 record is truncated' }
  [long]$ExpectedLength = -1
  if ($CompressionId -eq 255) {
    # InstallBuilder's unencrypted custom CookFS handler is lzmadec. Its stored
    # page is the CookFS marker followed by an LZMA-alone header and payload.
    if ($StoredBytes.Length -lt 14 -or $StoredBytes[1] -gt 224) { throw 'The CookFS custom record is unsupported or encrypted' }
    $DictionarySize = [BitConverter]::ToUInt32($StoredBytes, 2)
    if ($DictionarySize -eq 0 -or $DictionarySize -gt $Script:InstallBuilderMaximumLzmaDictionaryBytes) { throw 'The CookFS LZMA dictionary size is invalid or exceeds the configured limit' }
    $ExpectedLength = [BitConverter]::ToInt64($StoredBytes, 6)
    if ($ExpectedLength -lt 0 -or $ExpectedLength -gt $MaximumExpandedBytes) { throw 'The CookFS LZMA record output size is invalid or exceeds the configured limit' }
  }

  # BZip2 carries a four-byte CookFS prefix; custom LZMA carries properties and expected length.
  $PayloadOffset = if ($CompressionId -eq 2) { 5 } elseif ($CompressionId -eq 255) { 14 } else { 1 }
  $InputStream = [IO.MemoryStream]::new($StoredBytes, $PayloadOffset, $StoredBytes.Length - $PayloadOffset, $false)
  $Output = [IO.MemoryStream]::new()
  try {
    $ExpandArguments = @{ Stream = $InputStream; Destination = $Output; MaximumBytes = $MaximumExpandedBytes }
    switch ($CompressionId) {
      1 { $ExpandArguments.Algorithm = 'Deflate' }
      2 { $ExpandArguments.Algorithm = 'BZip2' }
      255 {
        $ExpandArguments.Algorithm = 'Lzma'
        $ExpandArguments.Properties = [byte[]]$StoredBytes[1..5]
        $ExpandArguments.CompressedSize = $StoredBytes.Length - $PayloadOffset
        $ExpandArguments.UncompressedSize = $ExpectedLength
      }
    }
    $null = Expand-InstallerCompressedStream @ExpandArguments
    return , ($Output.ToArray())
  } finally {
    $Output.Dispose()
    $InputStream.Dispose()
  }
}

function Test-InstallBuilderCookfsLzmaRecord {
  <#
  .SYNOPSIS
    Test whether a custom CookFS page is the unencrypted InstallBuilder LZMA form
  .PARAMETER StoredBytes
    Bounded format record or payload bytes interpreted by this function; the input array is not modified.
  #>
  [OutputType([bool])]
  param ([Parameter(Mandatory)][byte[]]$StoredBytes)
  if ($StoredBytes.Length -lt 14 -or $StoredBytes[0] -ne 255 -or $StoredBytes[1] -gt 224) { return $false }
  $DictionarySize = [BitConverter]::ToUInt32($StoredBytes, 2)
  $ExpectedLength = [BitConverter]::ToInt64($StoredBytes, 6)
  return $DictionarySize -gt 0 -and $DictionarySize -le $Script:InstallBuilderMaximumLzmaDictionaryBytes -and $ExpectedLength -ge 0 -and $ExpectedLength -le $Script:InstallBuilderMaximumCookfsPageBytes
}

function Read-InstallBuilderCookfsIndexNode {
  <#
  .SYNOPSIS
    Recursively decode one CookFS CFS2.200 directory node.
  .PARAMETER Bytes
    Complete expanded CookFS index bytes; all record offsets are relative to this array.
  .PARAMETER Position
    Mutable big-endian index cursor advanced through the node and its children.
  .PARAMETER Prefix
    Already validated logical parent path for child names.
  .PARAMETER Entry
    Caller-owned typed collection receiving decoded file records.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ref]$Position,
    [Parameter(Mandatory)][AllowEmptyString()][string]$Prefix,
    [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Entry
  )

  # Directory nodes are recursive lists. A sentinel block count denotes a child directory; normal
  # entries contain page/offset/length triples.
  $ItemCount = Read-InstallBuilderBigEndianUInt32 -Bytes $Bytes -Position $Position
  if ($ItemCount -gt $Script:InstallBuilderMaximumCookfsEntries -or $Entry.Count + $ItemCount -gt $Script:InstallBuilderMaximumCookfsEntries) { throw 'The CookFS index exceeds the configured entry-count limit' }
  for ($ItemIndex = 0; $ItemIndex -lt $ItemCount; $ItemIndex++) {
    if ($Position.Value -ge $Bytes.Length) { throw 'The CookFS index is truncated while reading a file name' }
    $NameLength = [int]$Bytes[$Position.Value]
    $Position.Value++
    if ($NameLength -eq 0 -or $Position.Value + $NameLength + 1 -gt $Bytes.Length) { throw 'The CookFS index contains an invalid file name' }
    $Name = [Text.Encoding]::UTF8.GetString($Bytes, $Position.Value, $NameLength)
    $Position.Value += $NameLength
    if ($Bytes[$Position.Value] -ne 0) { throw 'The CookFS index file name is not null terminated' }
    $Position.Value++
    if ($Name.IndexOf([char]0) -ge 0 -or $Name.IndexOfAny([char[]]@('/', '\', ':')) -ge 0 -or $Name -in '.', '..') { throw 'The CookFS index contains an unsafe file name' }
    Skip-InstallBuilderCookfsByteRange -Bytes $Bytes -Position $Position -Count 8 # mtime
    $BlockCount = Read-InstallBuilderBigEndianUInt32 -Bytes $Bytes -Position $Position
    $RelativePath = if ([string]::IsNullOrEmpty($Prefix)) { $Name } else { "$Prefix/$Name" }
    if ($BlockCount -eq [uint32]::MaxValue) {
      # Descend only after the child name has passed path-component validation.
      Read-InstallBuilderCookfsIndexNode -Bytes $Bytes -Position $Position -Prefix $RelativePath -Entry $Entry
      continue
    }
    if ($BlockCount -gt 1048576 -or $BlockCount * 12 -gt $Bytes.Length - $Position.Value) { throw 'The CookFS index contains an invalid block list' }
    $Blocks = [System.Collections.Generic.List[object]]::new()
    [long]$Length = 0
    for ($BlockIndex = 0; $BlockIndex -lt $BlockCount; $BlockIndex++) {
      $Page = Read-InstallBuilderBigEndianUInt32 -Bytes $Bytes -Position $Position
      $Offset = Read-InstallBuilderBigEndianUInt32 -Bytes $Bytes -Position $Position
      $Size = Read-InstallBuilderBigEndianUInt32 -Bytes $Bytes -Position $Position
      $Length += $Size
      if ($Length -gt [long]::MaxValue -or $Size -gt $Script:InstallBuilderMaximumCookfsPageBytes) { throw 'The CookFS index contains an oversized file block' }
      $Blocks.Add([pscustomobject]@{ Page = $Page; Offset = $Offset; Length = $Size })
    }
    $Entry.Add([pscustomobject]@{ Path = $RelativePath; Length = $Length; Blocks = $Blocks.ToArray() })
  }
}

function Get-InstallBuilderCookfsInfo {
  <#
  .SYNOPSIS
    Parse the unencrypted CookFS page and file index embedded in an installer
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)

  $File = Get-Item -LiteralPath $Path -Force
  $FooterMarker = [Text.Encoding]::ASCII.GetBytes('CFS0002')
  $Markers = @(Find-BinaryPattern -Path $File.FullName -Pattern $FooterMarker -Maximum 32 -Reverse)
  $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    foreach ($MarkerOffset in $Markers) {
      $EndOffset = $MarkerOffset + $FooterMarker.Length
      if ($EndOffset -lt 16 -or $EndOffset -gt $Stream.Length) { continue }
      try {
        $IndexSize = Read-BinaryInteger -Stream $Stream -Offset ($EndOffset - 16) -Size 4 -Endian BigEndian
        $PageCount = Read-BinaryInteger -Stream $Stream -Offset ($EndOffset - 12) -Size 4 -Endian BigEndian
        $IndexCompression = Read-BinaryInteger -Stream $Stream -Offset ($EndOffset - 8) -Size 1
        if ($IndexSize -le 0 -or $IndexSize -gt $Script:InstallBuilderMaximumCookfsIndexBytes -or $PageCount -gt $Script:InstallBuilderMaximumCookfsPages) { continue }
        $IndexOffset = $EndOffset - 16 - [long]$IndexSize - ([long]$PageCount * 20)
        if ($IndexOffset -lt 0) { continue }
        $SizeOffset = $IndexOffset + ([long]$PageCount * 16)
        $StoredIndexOffset = $SizeOffset + ([long]$PageCount * 4)
        if ($StoredIndexOffset + $IndexSize -gt $EndOffset - 16) { continue }
        $PageSizes = [long[]]::new($PageCount)
        $PageOffsets = [long[]]::new($PageCount)
        for ($Index = 0; $Index -lt $PageCount; $Index++) {
          $PageSizes[$Index] = Read-BinaryInteger -Stream $Stream -Offset ($SizeOffset + ($Index * 4)) -Size 4 -Endian BigEndian
          if ($PageSizes[$Index] -le 0 -or $PageSizes[$Index] -gt $Script:InstallBuilderMaximumCookfsPageBytes) { throw 'The CookFS page table contains an invalid page size' }
        }
        # The page table follows all stored page bytes, so derive the page-data
        # start by walking backward from the index area after validating totals.
        $PageDataStart = $IndexOffset
        for ($Index = $PageCount - 1; $Index -ge 0; $Index--) { $PageDataStart -= $PageSizes[$Index] }
        if ($PageDataStart -lt 0) { throw 'The CookFS page data starts before the file' }
        $Cursor = $PageDataStart
        for ($Index = 0; $Index -lt $PageCount; $Index++) { $PageOffsets[$Index] = $Cursor; $Cursor += $PageSizes[$Index] }
        if ($Cursor -ne $IndexOffset) { throw 'The CookFS page data size does not match the index offset' }
        $StoredIndex = Read-BinaryBytes -Stream $Stream -Offset $StoredIndexOffset -Count ([int]$IndexSize)
        if ($StoredIndex[0] -ne $IndexCompression) { throw 'The CookFS footer compression identifier does not match the stored index' }
        $IndexData = Expand-InstallBuilderCookfsRecord -StoredBytes $StoredIndex -MaximumExpandedBytes $Script:InstallBuilderMaximumCookfsIndexBytes
        if ($IndexData.Length -lt 8 -or [Text.Encoding]::ASCII.GetString($IndexData, 0, 8) -ne 'CFS2.200') { throw 'The CookFS file index signature is invalid' }
        $Position = 8
        $Entries = [System.Collections.Generic.List[object]]::new()
        Read-InstallBuilderCookfsIndexNode -Bytes $IndexData -Position ([ref]$Position) -Prefix '' -Entry $Entries
        $CompressionIds = [System.Collections.Generic.HashSet[int]]::new()
        $CompressionTypes = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $HasUnsupportedCompression = $false
        for ($Index = 0; $Index -lt $PageCount; $Index++) {
          $HeaderLength = [Math]::Min(14, $PageSizes[$Index])
          $PageHeader = Read-BinaryBytes -Stream $Stream -Offset $PageOffsets[$Index] -Count ([int]$HeaderLength)
          $CompressionId = [int]$PageHeader[0]
          $null = $CompressionIds.Add($CompressionId)
          switch ($CompressionId) {
            0 { $null = $CompressionTypes.Add('None') }
            1 { $null = $CompressionTypes.Add('Deflate') }
            2 { $null = $CompressionTypes.Add('BZip2') }
            255 {
              if (Test-InstallBuilderCookfsLzmaRecord -StoredBytes $PageHeader) { $null = $CompressionTypes.Add('Lzma') } else { $null = $CompressionTypes.Add('Custom'); $HasUnsupportedCompression = $true }
            }
            default { $null = $CompressionTypes.Add("Unknown:$CompressionId"); $HasUnsupportedCompression = $true }
          }
        }
        return [pscustomobject]@{
          EndOffset                 = $EndOffset
          IndexOffset               = $IndexOffset
          PageDataOffset            = $PageDataStart
          PageCount                 = $PageCount
          IndexSize                 = $IndexSize
          CompressionIds            = @($CompressionIds | Sort-Object)
          CompressionTypes          = @($CompressionTypes | Sort-Object)
          HasUnsupportedCompression = $HasUnsupportedCompression
          PageSizes                 = $PageSizes
          PageOffsets               = $PageOffsets
          Entries                   = $Entries.ToArray()
          PageCache                 = [System.Collections.Generic.Dictionary[int, byte[]]]::new()
          PageCacheOrder            = [System.Collections.Generic.Queue[int]]::new()
          PageCacheBytes            = 0L
        }
      } catch {
        continue
      }
    }
  } finally {
    $Stream.Dispose()
  }
  throw 'The file does not contain a supported CookFS CFS0002 footer and file index'
}

function Get-InstallBuilderCookfsPage {
  <#
  .SYNOPSIS
    Decode one bounded CookFS page and retain a small in-memory cache
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER Cookfs
    Validated CookFS layout containing page offsets, stored sizes, and the bounded page cache owned by the caller.
  .PARAMETER Page
    Current structured format node or record being interpreted.
  #>
  [OutputType([byte[]])]
  param ([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$Cookfs, [Parameter(Mandatory)][uint32]$Page)
  if ($Page -ge $Cookfs.PageCount) { throw "The CookFS file index references missing page $Page" }
  # Pages are shared by many files. Reuse a bounded FIFO cache to avoid repeated decompression
  # without retaining an unbounded portion of a large installer.
  if ($Cookfs.PageCache.ContainsKey([int]$Page)) { return , $Cookfs.PageCache[[int]$Page] }
  $Stream = [IO.File]::Open((Get-Item -LiteralPath $Path -Force).FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    $StoredPage = Read-BinaryBytes -Stream $Stream -Offset $Cookfs.PageOffsets[$Page] -Count ([int]$Cookfs.PageSizes[$Page])
    $PageBytes = Expand-InstallBuilderCookfsRecord -StoredBytes $StoredPage -MaximumExpandedBytes $Script:InstallBuilderMaximumCookfsPageBytes
  } finally {
    $Stream.Dispose()
  }
  while ($Cookfs.PageCacheOrder.Count -gt 0 -and (
      $Cookfs.PageCacheOrder.Count -ge $Script:InstallBuilderCookfsPageCacheSize -or
      $Cookfs.PageCacheBytes + $PageBytes.Length -gt $Script:InstallBuilderCookfsPageCacheBytes
    )) {
    $ExpiredPage = $Cookfs.PageCacheOrder.Dequeue()
    $Cookfs.PageCacheBytes -= $Cookfs.PageCache[$ExpiredPage].Length
    $null = $Cookfs.PageCache.Remove($ExpiredPage)
  }
  if ($PageBytes.Length -le $Script:InstallBuilderCookfsPageCacheBytes) {
    $Cookfs.PageCache[[int]$Page] = $PageBytes
    $Cookfs.PageCacheOrder.Enqueue([int]$Page)
    $Cookfs.PageCacheBytes += $PageBytes.Length
  }
  return , $PageBytes
}

function Get-InstallBuilderCookfsLogicalEntry {
  <#
  .SYNOPSIS
    Merge BitRock ___bitrockBigFileN physical segments into logical files
  .PARAMETER Entry
    Validated archive or catalog entry whose bounded content is read or exported.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][object[]]$Entry)
  $Physical = @{}
  foreach ($Item in $Entry) { $Physical[$Item.Path] = $Item }
  $Logical = [System.Collections.Generic.List[object]]::new()
  # BitRock splits large logical files into numbered physical CookFS entries. Only a base entry
  # starts a logical file; consecutive numbered suffixes are appended in order.
  foreach ($Item in $Entry) {
    $Match = [regex]::Match($Item.Path, '^(?<Base>.+)___bitrockBigFile(?<Index>[1-9][0-9]*)$', [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($Match.Success) { continue }
    $Segments = [System.Collections.Generic.List[object]]::new()
    $Segments.Add($Item)
    $PartIndex = 1
    while ($Physical.ContainsKey("$($Item.Path)___bitrockBigFile$PartIndex")) {
      $Segments.Add($Physical["$($Item.Path)___bitrockBigFile$PartIndex"])
      $PartIndex++
    }
    $Logical.Add([pscustomobject]@{ Path = $Item.Path; Length = [long](@($Segments | Measure-Object -Property Length -Sum).Sum); Segments = $Segments.ToArray() })
  }
  return $Logical.ToArray()
}

function Copy-InstallBuilderCookfsEntry {
  <#
  .SYNOPSIS
    Copy one logical CookFS file to an output stream with output limits
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER Cookfs
    Validated CookFS layout used to resolve and decode each physical page referenced by the logical file.
  .PARAMETER Entry
    Validated archive or catalog entry whose bounded content is read or exported.
  .PARAMETER Destination
    Caller-owned output stream. The function writes sequential file bytes and does not dispose the stream.
  .PARAMETER TotalWritten
    Mutable cumulative output-byte counter used to enforce the extraction limit.
  .PARAMETER MaximumExpandedBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)]$Cookfs,
    [Parameter(Mandatory)]$Entry,
    [Parameter(Mandatory)][System.IO.Stream]$Destination,
    [Parameter(Mandatory)][ref]$TotalWritten,
    [Parameter(Mandatory)][long]$MaximumExpandedBytes
  )
  # Reassemble segments block-by-block from decoded pages while maintaining one operation-wide
  # output counter.
  foreach ($Segment in $Entry.Segments) {
    foreach ($Block in $Segment.Blocks) {
      $Page = Get-InstallBuilderCookfsPage -Path $Path -Cookfs $Cookfs -Page $Block.Page
      if ([long]$Block.Offset + [long]$Block.Length -gt $Page.Length) { throw "The CookFS block for '$($Entry.Path)' exceeds its decoded page" }
      if ($TotalWritten.Value + $Block.Length -gt $MaximumExpandedBytes) { throw 'InstallBuilder extraction exceeds the configured output limit' }
      $Destination.Write($Page, [int]$Block.Offset, [int]$Block.Length)
      $TotalWritten.Value += $Block.Length
    }
  }
}

function Get-InstallBuilderInfo {
  <#
  .SYNOPSIS
    Get static metadata from a BitRock or VMware InstallBuilder installer
  .DESCRIPTION
    The parser recovers zlib-compressed project XML and the CookFS file index
    held by the embedded Metakit VFS. It never mounts TclKit or executes Tcl.
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process {
    $File = Get-Item -LiteralPath $Path -Force
    # project.xml is authoritative for identity, scope actions, and registry writes. CookFS is an
    # independent optional payload index and is not required for metadata-only parsing.
    $Project = Get-InstallBuilderProjectData -Path $File.FullName
    $Xml = [xml]$Project.Content
    $ShortName = Get-InstallBuilderXmlValue -Xml $Xml -XPath '/project/shortName'
    $FullName = Get-InstallBuilderXmlValue -Xml $Xml -XPath '/project/fullName'
    $Version = Get-InstallBuilderXmlValue -Xml $Xml -XPath '/project/version'
    $ScopeInfo = Get-InstallBuilderScopeInfo -Xml $Xml
    $RegistryWrites = @(Get-InstallBuilderRegistryWrite -Xml $Xml)
    $RegistryAssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite $RegistryWrites
    $AppsAndFeaturesWrites = @($RegistryWrites | Where-Object { $_.Key -match '(^|\\)Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall(\\|$)' })
    $HasBuiltInUninstaller = [bool]($Xml.SelectSingleNode('/project/postUninstallerCreationActionList') -or $Xml.SelectSingleNode('/project/preUninstallationActionList'))
    $Warnings = [System.Collections.Generic.List[string]]::new()
    $Cookfs = $null
    try {
      $Cookfs = Get-InstallBuilderCookfsInfo -Path $File.FullName
    } catch {
      # project.xml remains useful metadata evidence in older containers that
      # expose no CookFS payload footer. A present but invalid footer is useful
      # corruption evidence and remains visible to callers.
      $FooterMarker = [Text.Encoding]::ASCII.GetBytes('CFS0002')
      if (@(Find-BinaryPattern -Path $File.FullName -Pattern $FooterMarker -Maximum 1).Count -gt 0) {
        $Warnings.Add("CookFS payload index was not available: $($_.Exception.Message)")
      }
    }
    if (-not $AppsAndFeaturesWrites -and $HasBuiltInUninstaller) { $Warnings.Add('InstallBuilder built-in uninstaller configuration is present, but its visible ARP key is not an explicit registrySet action. Validate ARP details in a VM.') }
    foreach ($Warning in @($RegistryAssociationInfo.Warnings)) { $Warnings.Add($Warning) }
    if ($Project.Content -match 'MI_oJ|tcltwofish|installbuilder\.payloadinfo') { $Warnings.Add('The installer contains encrypted-payload markers. Project metadata was recovered, but CookFS payload extraction is unsupported without the project password.') }
    if ($Cookfs -and $Cookfs.HasUnsupportedCompression) { $Warnings.Add('The CookFS payload uses unsupported custom or encrypted compression and cannot be extracted without the project password.') }
    $PayloadFiles = if ($Cookfs) { @(Get-InstallBuilderCookfsLogicalEntry -Entry $Cookfs.Entries) } else { @() }
    if ($Cookfs) {
      # Detect split segments whose base entry is missing; those cannot be safely reassembled.
      $PhysicalPaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
      foreach ($Entry in $Cookfs.Entries) { $null = $PhysicalPaths.Add($Entry.Path) }
      foreach ($Entry in $Cookfs.Entries) {
        $Match = [regex]::Match($Entry.Path, '^(?<Base>.+)___bitrockBigFile[1-9][0-9]*$', [Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if ($Match.Success -and -not $PhysicalPaths.Contains($Match.Groups['Base'].Value)) {
          $Warnings.Add("CookFS payload contains an orphaned BitRock split segment: $($Entry.Path)")
        }
      }
    }
    $UninstallerKeyName = if ($ShortName) { $ShortName } else { $FullName }
    $ProductCode = if ($UninstallerKeyName -and $Version) { "$UninstallerKeyName $Version" } else { $UninstallerKeyName }
    [pscustomobject]@{
      InstallerType                = 'InstallBuilder'
      ProductCode                  = $ProductCode
      ProductCodeEvidence          = if ($ProductCode) { 'InstallBuilder candidate uninstaller-key convention: <shortName-or-fullName> <version>; validate visible ARP key in a VM.' } else { $null }
      PackageName                  = if ($FullName) { $FullName } else { $ShortName }
      DisplayName                  = if ($FullName) { $FullName } else { $ShortName }
      ProductName                  = if ($FullName) { $FullName } else { $ShortName }
      DisplayVersion               = $Version
      Publisher                    = Get-InstallBuilderXmlValue -Xml $Xml -XPath '/project/vendor'
      DefaultInstallationDirectory = (Get-InstallBuilderXmlValue -Xml $Xml -XPath "//directoryParameter[@name='installdir']/default"), (Get-InstallBuilderXmlValue -Xml $Xml -XPath "//directoryParameter[name='InstallDir']/default") | Where-Object { $_ } | Select-Object -First 1
      Scope                        = $ScopeInfo.Scope
      SupportedScopes              = $ScopeInfo.SupportedScopes
      ScopeConfidence              = $ScopeInfo.Confidence
      ScopeEvidence                = $ScopeInfo.Evidence
      SupportsSilentInstallation   = $true
      RegistryWrites               = $RegistryWrites
      RegistryAssociationInfo      = $RegistryAssociationInfo
      Protocols                    = $RegistryAssociationInfo.Protocols
      FileExtensions               = $RegistryAssociationInfo.FileExtensions
      WritesAppsAndFeaturesEntry   = if ($AppsAndFeaturesWrites.Count) { $true } elseif ($HasBuiltInUninstaller) { $null } else { $false }
      HasBuiltInUninstaller        = $HasBuiltInUninstaller
      ProjectOffset                = $Project.Offset
      ProjectLength                = $Project.Length
      ExtractedFiles               = @('project.xml')
      PayloadFiles                 = @($PayloadFiles | ForEach-Object Path)
      PayloadFileCount             = $PayloadFiles.Count
      CookfsInfo                   = if ($Cookfs) { [pscustomobject]@{ EndOffset = $Cookfs.EndOffset; IndexOffset = $Cookfs.IndexOffset; PageDataOffset = $Cookfs.PageDataOffset; PageCount = $Cookfs.PageCount; IndexSize = $Cookfs.IndexSize; CompressionIds = $Cookfs.CompressionIds; CompressionTypes = $Cookfs.CompressionTypes; HasUnsupportedCompression = $Cookfs.HasUnsupportedCompression } } else { $null }
      Warnings                     = @($Warnings)
      ParserVersionInfo            = [pscustomobject]@{ Parser = 'Dumplings.PackageModule.InstallBuilder'; ParserMajor = 2; Sources = @('Metakit VFS project.xml marker', 'bounded zlib project record', 'CookFS CFS0002 footer and file index') }
    }
  }
}

function Expand-InstallBuilderInstaller {
  <#
  .SYNOPSIS
    Extract selected unencrypted InstallBuilder payload files without execution
  .PARAMETER Name
    Matches project.xml and logical CookFS payload paths. BitRock split payloads
    ending in ___bitrockBigFileN are reassembled under their original file name.
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER DestinationPath
    Destination path for bounded extraction or decoded output; payload-relative names are resolved beneath this path.
  .PARAMETER MaximumExpandedBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  [OutputType([System.IO.FileInfo[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [string]$Name = '*',
    [ValidateRange(1024, [long]::MaxValue)][long]$MaximumExpandedBytes = 17179869184
  )
  process {
    if ([string]::IsNullOrWhiteSpace($DestinationPath)) { $DestinationPath = Join-Path ([IO.Path]::GetTempPath()) ("Dumplings-InstallBuilder-$([guid]::NewGuid().ToString('N'))") }
    $Extracted = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
    [long]$TotalWritten = 0

    # project.xml and CookFS payloads share one output budget but have independent recovery paths.
    if (Test-ExtractionPattern -Path 'project.xml' -Pattern $Name) {
      $Project = Get-InstallBuilderProjectData -Path $Path -MaximumExpandedBytes ([Math]::Min($MaximumExpandedBytes, $Script:InstallBuilderMaximumProjectBytes))
      $Bytes = [Text.Encoding]::UTF8.GetBytes($Project.Content)
      if ($Bytes.Length -gt $MaximumExpandedBytes) { throw 'The recovered InstallBuilder project exceeds the configured output limit' }
      $OutputPath = Resolve-SafeExtractionPath -DestinationPath $DestinationPath -RelativePath 'project.xml'
      $null = New-Item -Path ([IO.Path]::GetDirectoryName($OutputPath)) -ItemType Directory -Force
      [IO.File]::WriteAllBytes($OutputPath, $Bytes)
      $TotalWritten += $Bytes.Length
      $Extracted.Add((Get-Item -LiteralPath $OutputPath -Force))
    }

    $Cookfs = $null
    try { $Cookfs = Get-InstallBuilderCookfsInfo -Path $Path } catch {
      if ($Extracted.Count -eq 0) { throw }
    }
    if ($Cookfs) {
      $LogicalEntries = @(Get-InstallBuilderCookfsLogicalEntry -Entry $Cookfs.Entries | Where-Object { Test-ExtractionPattern -Path $_.Path -Pattern $Name })
      if ($LogicalEntries.Count -gt 0 -and $Cookfs.HasUnsupportedCompression) { throw 'The CookFS payload uses unsupported custom or encrypted compression and cannot be extracted without the project password' }
      # Export logical rather than physical split-file names.
      foreach ($Entry in $LogicalEntries) {
        $OutputPath = Resolve-SafeExtractionPath -DestinationPath $DestinationPath -RelativePath $Entry.Path
        $null = New-Item -Path ([IO.Path]::GetDirectoryName($OutputPath)) -ItemType Directory -Force
        $Destination = [IO.File]::Open($OutputPath, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
          Copy-InstallBuilderCookfsEntry -Path $Path -Cookfs $Cookfs -Entry $Entry -Destination $Destination -TotalWritten ([ref]$TotalWritten) -MaximumExpandedBytes $MaximumExpandedBytes
        } finally {
          $Destination.Dispose()
        }
        $Extracted.Add((Get-Item -LiteralPath $OutputPath -Force))
      }
    }
    if ($Extracted.Count -eq 0) { throw "No InstallBuilder project or payload file matches selector '$Name'" }
    return $Extracted.ToArray()
  }
}

function Test-InstallBuilder {
  <#
  .SYNOPSIS
    Test whether a file contains a supported InstallBuilder project record
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([bool])]
  param([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { try { $null = Get-InstallBuilderInfo -Path $Path; $true } catch { $false } }
}

function Read-ProtocolsFromInstallBuilder {
  <#
  .SYNOPSIS
    Read literal URL protocol names from InstallBuilder registrySet actions
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallBuilderInfo -Path $Path).Protocols }
}

function Read-FileExtensionsFromInstallBuilder {
  <#
  .SYNOPSIS
    Read literal file extensions from InstallBuilder registrySet actions
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallBuilderInfo -Path $Path).FileExtensions }
}

function Read-ProductVersionFromInstallBuilder {
  <#
  .SYNOPSIS
    Read the version from an InstallBuilder project
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallBuilderInfo -Path $Path).DisplayVersion }
}
function Read-ProductNameFromInstallBuilder {
  <#
  .SYNOPSIS
    Read the product name from an InstallBuilder project
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallBuilderInfo -Path $Path).DisplayName }
}
function Read-PublisherFromInstallBuilder {
  <#
  .SYNOPSIS
    Read the publisher from an InstallBuilder project
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallBuilderInfo -Path $Path).Publisher }
}
function Read-ProductCodeFromInstallBuilder {
  <#
  .SYNOPSIS
    Read the candidate InstallBuilder uninstaller key
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallBuilderInfo -Path $Path).ProductCode }
}
function Read-ScopeFromInstallBuilder {
  <#
  .SYNOPSIS
    Read the statically proven InstallBuilder installation scope
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallBuilderInfo -Path $Path).Scope }
}

Export-ModuleMember -Function Get-InstallBuilderInfo, Expand-InstallBuilderInstaller, Test-InstallBuilder, Read-ProtocolsFromInstallBuilder, Read-FileExtensionsFromInstallBuilder, Read-ProductVersionFromInstallBuilder, Read-ProductNameFromInstallBuilder, Read-PublisherFromInstallBuilder, Read-ProductCodeFromInstallBuilder, Read-ScopeFromInstallBuilder
