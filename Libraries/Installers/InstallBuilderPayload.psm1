# SPDX-License-Identifier: Apache-2.0
# Internal InstallBuilder implementation. See InstallBuilder.psm1 for format sources and the binary layout.
# Pass parsed contexts explicitly and keep caller-owned streams local.

# InstallBuilder payload implementation, imported locally by the public facade.
Import-Module (Join-Path $PSScriptRoot 'InstallBuilderProject.psm1') -ErrorAction Stop

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:InstallBuilderMaximumCandidates = 4096

$Script:InstallBuilderMaximumProjectBytes = 16777216

$Script:InstallBuilderMarkerSearchRadius = 16777216

$Script:InstallBuilderMaximumCookfsIndexBytes = 67108864

$Script:InstallBuilderMaximumCookfsPages = 1000000

$Script:InstallBuilderMaximumCookfsPageBytes = 536870912

$Script:InstallBuilderMaximumCookfsEntries = 200000

$Script:InstallBuilderMaximumMetakitMetadataBytes = 67108864

$Script:InstallBuilderCookfsPageCacheSize = 16

$Script:InstallBuilderCookfsPageCacheBytes = 67108864

$Script:InstallBuilderMaximumLzmaDictionaryBytes = 134217728

$Script:InstallBuilderStrictUtf8 = [Text.UTF8Encoding]::new($false, $true)

$InstallBuilderMetakitSource = Join-Path $PSScriptRoot '..\..\Assets\Source\InstallBuilder\InstallBuilderMetakitReader.cs'

$null = Import-InstallerManagedSource -Path $InstallBuilderMetakitSource -TypeName 'Dumplings.InstallBuilder.InstallBuilderMetakitArchive'

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
  # InstallBuilder uses the maximum RFC 1950 window size. Search complete valid CMF/FLG pairs
  # instead of every 0x78 byte: old, UPX-packed runtimes can contain thousands of incidental
  # 0x78 values before project.xml, which would otherwise exhaust the candidate bound first.
  $ZlibHeaders = @(
    [byte[]](0x78, 0x01),
    [byte[]](0x78, 0x5E),
    [byte[]](0x78, 0x9C),
    [byte[]](0x78, 0xDA)
  )
  $Offsets = [System.Collections.Generic.HashSet[long]]::new()
  # Metakit stores names separately from compressed records. Use each project.xml name as a local
  # search anchor instead of trying every zlib-looking byte in a large payload.
  $ProjectOffsets = @(Find-BinaryPattern -Path $File.FullName -Pattern $ProjectMarker -Maximum 32 -Reverse)
  foreach ($ProjectOffset in $ProjectOffsets) {
    $StartOffset = [Math]::Max(0, $ProjectOffset - 65536)
    $Length = [Math]::Min($Script:InstallBuilderMarkerSearchRadius, $File.Length - $StartOffset)
    foreach ($Header in $ZlibHeaders) {
      foreach ($Offset in @(Find-BinaryPattern -Path $File.FullName -Pattern $Header -StartOffset $StartOffset -Length $Length -Maximum $Script:InstallBuilderMaximumCandidates)) {
        if ($Offsets.Count -ge $Script:InstallBuilderMaximumCandidates) { break }
        $null = $Offsets.Add($Offset)
      }
      if ($Offsets.Count -ge $Script:InstallBuilderMaximumCandidates) { break }
    }
  }

  # A project record can be outside the nearby VFS-name table in older
  # InstallBuilder releases. Fall back to a bounded whole-file candidate scan.
  if ($Offsets.Count -eq 0) {
    foreach ($Header in $ZlibHeaders) {
      foreach ($Offset in @(Find-BinaryPattern -Path $File.FullName -Pattern $Header -Maximum $Script:InstallBuilderMaximumCandidates)) {
        if ($Offsets.Count -ge $Script:InstallBuilderMaximumCandidates) { break }
        $null = $Offsets.Add($Offset)
      }
      if ($Offsets.Count -ge $Script:InstallBuilderMaximumCandidates) { break }
    }
  }
  return [long[]]@($Offsets | Sort-Object)
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
    $Content = $Script:InstallBuilderStrictUtf8.GetString($Output.ToArray()).TrimStart([char]0xFEFF, [char]0)
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
  # Prefer the catalog-owned project record whenever a real Metakit VFS is present. This proves
  # record ownership and avoids trying unrelated zlib members in the launcher or payload.
  $Layouts = @(Get-InstallBuilderMetakitLayout -Path $File.FullName)
  if ($Layouts.Count) {
    $Archive = $null
    try {
      $Archive = Open-InstallBuilderMetakitArchive -Path $File.FullName -Layout $Layouts -RequiredEntryPath 'project.xml'
      $ProjectEntry = @($Archive.Entries | Where-Object Path -CEQ 'project.xml')
      if ($ProjectEntry.Count -ne 1) { throw 'The InstallBuilder Metakit VFS does not contain one unambiguous project.xml record' }
      $Bytes = $Archive.ReadEntry([int]$ProjectEntry[0].Index, $MaximumExpandedBytes)
      $Content = $Script:InstallBuilderStrictUtf8.GetString($Bytes).TrimStart([char]0xFEFF, [char]0)
      $Start = $Content.IndexOf('<project', [StringComparison]::OrdinalIgnoreCase)
      $EndTag = '</project>'
      $End = $Start -ge 0 ? $Content.IndexOf($EndTag, $Start, [StringComparison]::OrdinalIgnoreCase) : -1
      if ($Start -lt 0 -or $End -lt 0) { throw 'The catalog-owned InstallBuilder project.xml record does not contain a complete project root' }
      $OriginEntry = @($Archive.Entries | Where-Object Path -CEQ 'origindist')
      $OriginDirectory = if ($OriginEntry.Count -eq 1) { $Script:InstallBuilderStrictUtf8.GetString($Archive.ReadEntry([int]$OriginEntry[0].Index, 4096)).Trim([char]0).Trim() } else { $null }
      return [pscustomobject]@{
        Offset          = $ProjectEntry[0].Offset
        Content         = $Content.Substring($Start, $End - $Start + $EndTag.Length)
        Length          = $Bytes.Length
        StoredLength    = $ProjectEntry[0].StoredSize
        MetakitLayout   = [pscustomobject][ordered]@{ HeaderOffset = $Archive.HeaderOffset; EndOffset = $Archive.HeaderOffset + $Archive.Length; Length = $Archive.Length; ByteOrder = ($Layouts | Where-Object HeaderOffset -EQ $Archive.HeaderOffset | Select-Object -First 1).ByteOrder; RootPosition = $Archive.RootPosition; RootLength = $Archive.RootLength }
        MetakitLayouts  = $Layouts
        MetakitEntries  = @($Archive.Entries)
        OriginDirectory = $OriginDirectory
      }
    } finally {
      if ($Archive) { $Archive.Dispose() }
    }
  }
  # Accept the first candidate that expands to a complete project root, not merely XML fragments.
  foreach ($Offset in @(Get-InstallBuilderCandidateOffset -Path $File.FullName)) {
    $Project = Read-InstallBuilderZlibProject -Path $File.FullName -Offset $Offset -MaximumExpandedBytes $MaximumExpandedBytes
    if ($Project) { return $Project }
  }
  throw 'The InstallBuilder Metakit VFS contains project.xml but no supported bounded zlib project record was found'
}

function Get-InstallBuilderMetakitLayout {
  <#
  .SYNOPSIS
    Locate bounded Metakit VFS databases embedded in an InstallBuilder executable.
  .DESCRIPTION
    Metakit stores a big-endian distance from each JL/LJ header to its logical end. The
    database can be embedded inside a PE and may be followed by Authenticode or launcher data.
    This function validates the terminal Metakit commit record before returning a layout.
  .PARAMETER Path
    Path to the installer whose embedded Metakit databases are inspected.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][string]$Path)

  $File = Get-Item -LiteralPath $Path -Force
  $Layouts = [Collections.Generic.List[object]]::new()
  foreach ($Magic in @([byte[]](0x4A, 0x4C, 0x1A, 0x00), [byte[]](0x4C, 0x4A, 0x1A, 0x00))) {
    foreach ($HeaderOffset in @(Find-BinaryPattern -Path $File.FullName -Pattern $Magic -Maximum 32)) {
      if ($HeaderOffset + 8 -gt $File.Length) { continue }
      $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
      try {
        $Distance = Read-BinaryInteger -Stream $Stream -Offset ($HeaderOffset + 4) -Size 4 -Endian BigEndian
        $EndOffset = $HeaderOffset + [long]$Distance
        if ($Distance -lt 24 -or $EndOffset -gt $Stream.Length) { continue }
        $Footer = Read-BinaryBytes -Stream $Stream -Offset ($EndOffset - 16) -Count 16
        # A committed Metakit database ends with two eight-byte marks. The second mark starts
        # with 0x80 and carries a three-byte root length plus a four-byte root position.
        if ($Footer[8] -ne 0x80) { continue }
        $RootLength = ([uint32]$Footer[9] -shl 16) -bor ([uint32]$Footer[10] -shl 8) -bor [uint32]$Footer[11]
        $RootPosition = ([uint32]$Footer[12] -shl 24) -bor ([uint32]$Footer[13] -shl 16) -bor ([uint32]$Footer[14] -shl 8) -bor [uint32]$Footer[15]
        if ($RootLength -eq 0 -or $RootPosition -ge $Distance -or [long]$RootPosition + $RootLength -gt $Distance) { continue }
        $Layouts.Add([pscustomobject][ordered]@{
            HeaderOffset = [long]$HeaderOffset
            EndOffset    = $EndOffset
            Length       = [long]$Distance
            ByteOrder    = $Magic[0] -eq 0x4A ? 'LittleEndian' : 'BigEndian'
            RootPosition = [long]$RootPosition
            RootLength   = [long]$RootLength
          })
      } finally {
        $Stream.Dispose()
      }
    }
  }
  return [object[]]@($Layouts | Sort-Object HeaderOffset -Unique)
}

function Open-InstallBuilderMetakitArchive {
  <#
  .SYNOPSIS
    Open the first supported legacy InstallBuilder TclKit VFS.
  .PARAMETER Path
    Resolved path to the installer containing the Metakit database.
  .PARAMETER Layout
    Validated Metakit layouts whose header offsets are tried in file order.
  .PARAMETER RequiredEntryPath
    Optional exact catalog path used to select the package-owned VFS when an installer embeds
    multiple valid Metakit databases.
  #>
  [OutputType([Dumplings.InstallBuilder.InstallBuilderMetakitArchive])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][object[]]$Layout,
    [string]$RequiredEntryPath
  )

  $Failures = [Collections.Generic.List[string]]::new()
  foreach ($Candidate in @($Layout | Sort-Object HeaderOffset)) {
    try {
      $Archive = [Dumplings.InstallBuilder.InstallBuilderMetakitArchive]::Open(
        $Path,
        [long]$Candidate.HeaderOffset,
        $Script:InstallBuilderMaximumCookfsEntries,
        $Script:InstallBuilderMaximumMetakitMetadataBytes
      )
      if ($RequiredEntryPath) {
        $MatchingEntries = @($Archive.Entries | Where-Object Path -CEQ $RequiredEntryPath)
        if ($MatchingEntries.Count -ne 1) {
          $Archive.Dispose()
          $Failures.Add("0x$(([long]$Candidate.HeaderOffset).ToString('X')): expected one '$RequiredEntryPath' entry, found $($MatchingEntries.Count)")
          continue
        }
      }
      return $Archive
    } catch {
      $Failures.Add("0x$(([long]$Candidate.HeaderOffset).ToString('X')): $($_.Exception.Message)")
    }
  }

  throw "No supported InstallBuilder Metakit VFS was found. $($Failures -join '; ')"
}

function Get-InstallBuilderFolderDestinationMap {
  <#
  .SYNOPSIS
    Map compiled component/folder identifiers to paths relative to the installation root.
  .PARAMETER Xml
    Parsed InstallBuilder project document.
  .PARAMETER Context
    Deterministic project variables and resolved installation directory.
  #>
  [OutputType([Collections.Generic.Dictionary[string, object]])]
  param (
    [Parameter(Mandatory)][xml]$Xml,
    [Parameter(Mandatory)]$Context
  )

  $Map = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($Folder in @($Xml.SelectNodes('//componentList/component/folderList/folder'))) {
    $FolderName = Get-InstallBuilderXmlValue -Xml $Folder -XPath 'name'
    $Component = $Folder.ParentNode.ParentNode
    $ComponentName = Get-InstallBuilderXmlValue -Xml $Component -XPath 'name'
    if ([string]::IsNullOrWhiteSpace($FolderName)) { continue }
    $DestinationExpression = Get-InstallBuilderXmlValue -Xml $Folder -XPath 'destination'
    $Destination = Resolve-InstallBuilderProjectValue -Value $DestinationExpression -Variables $Context.Variables
    $LogicalPrefix = $null
    if ($Destination.Value -and $Context.InstallLocation) {
      $NormalizedDestination = $Destination.Value.Replace('\', '/').TrimEnd('/')
      $NormalizedInstallLocation = $Context.InstallLocation.Replace('\', '/').TrimEnd('/')
      if ($NormalizedDestination -ceq $NormalizedInstallLocation) {
        $LogicalPrefix = ''
      } elseif ($NormalizedDestination.StartsWith($NormalizedInstallLocation + '/', [StringComparison]::OrdinalIgnoreCase)) {
        $LogicalPrefix = $NormalizedDestination.Substring($NormalizedInstallLocation.Length + 1)
      }
    }
    if ($null -eq $LogicalPrefix) { $LogicalPrefix = "_destinations/$FolderName" }
    $Condition = Get-InstallBuilderNodeCondition -Node $Folder -Context $Context
    $States = [Collections.Generic.List[string]]::new()
    $Conditions = [Collections.Generic.List[object]]::new()
    $States.Add($Condition.State)
    foreach ($Item in @($Condition.Conditions)) { $Conditions.Add($Item) }

    # Component selection controls the default unattended payload. A literal selected=0 excludes
    # the folder from the default install, while a runtime expression keeps it conditional.
    $SelectedExpression = Get-InstallBuilderXmlValue -Xml $Component -XPath 'selected'
    if ($null -ne $SelectedExpression) {
      $Selected = Resolve-InstallBuilderProjectValue -Value $SelectedExpression -Variables $Context.Variables
      $SelectedState = if ($null -eq $Selected.Value) {
        'Unknown'
      } elseif ($Selected.Value -match '^(?i:1|true|yes)$') {
        'True'
      } elseif ($Selected.Value -match '^(?i:0|false|no)$') {
        'False'
      } else {
        'Unknown'
      }
      $States.Add($SelectedState)
      $SelectedNode = $Component.SelectSingleNode('selected')
      $Conditions.Add([pscustomobject][ordered]@{ Type = 'ComponentSelected'; State = $SelectedState; Xml = $SelectedNode ? $SelectedNode.OuterXml : "selected=$SelectedExpression" })
    }

    # Folder platform lists use inclusive matching. A Windows installer can resolve all/windows
    # immediately; architecture-specific lists remain conditional when an x86 launcher can run on
    # more than one host architecture.
    foreach ($PlatformOwner in @($Component, $Folder)) {
      $PlatformExpression = Get-InstallBuilderXmlValue -Xml $PlatformOwner -XPath 'platforms'
      if ([string]::IsNullOrWhiteSpace($PlatformExpression)) { continue }
      $Platforms = @($PlatformExpression -split '[,;\s]+' | Where-Object { $_ })
      $PlatformState = if ($Platforms -match '^(?i:all|windows)$') {
        'True'
      } elseif ($Context.NativePlatform -and $Platforms -icontains $Context.NativePlatform) {
        'True'
      } elseif (@($Platforms | Where-Object { $_ -match '^(?i:windows-(?:x86|x64|arm64))$' }).Count) {
        $Context.IsNative64Bit ? 'False' : 'Unknown'
      } elseif (@($Platforms | Where-Object { $_ -match '^(?i:linux|linux-.+|osx|osx-.+|freebsd|solaris|aix|hpux)$' }).Count -eq $Platforms.Count) {
        'False'
      } else {
        'Unknown'
      }
      $States.Add($PlatformState)
      $PlatformNode = $PlatformOwner.SelectSingleNode('platforms')
      $Conditions.Add([pscustomobject][ordered]@{ Type = 'PlatformList'; State = $PlatformState; Xml = $PlatformNode ? $PlatformNode.OuterXml : "platforms=$PlatformExpression" })
    }

    $Value = [pscustomobject][ordered]@{
      Prefix         = $LogicalPrefix
      ConditionState = Merge-InstallerConditionState -State $States.ToArray() -Operator All
      Conditions     = $Conditions.ToArray()
      ComponentName  = $ComponentName
      FolderName     = $FolderName
    }
    $Map[$FolderName] = $Value
    if (-not [string]::IsNullOrWhiteSpace($ComponentName)) { $Map["$ComponentName/$FolderName"] = $Value }
  }
  return $Map
}

function Get-InstallBuilderLegacyPayloadEntry {
  <#
  .SYNOPSIS
    Project legacy Metakit dist records into safe logical payload paths.
  .DESCRIPTION
    TclKit stores runtime support beside package files. The root origindist record identifies the
    VFS payload directory, whose first component is the distribution name and second component is
    the compiled project folder name. The folder destination determines whether that internal
    folder name can be removed or must remain under a safe _destinations namespace.
  .PARAMETER Entry
    Complete Metakit VFS catalog returned by the bounded managed reader.
  .PARAMETER Xml
    Parsed InstallBuilder project used to map compiled folder names and destinations.
  .PARAMETER Context
    Resolved project variable and installation-directory context.
  .PARAMETER OriginDirectory
    Root VFS directory read from the structured origindist control record.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][object[]]$Entry,
    [Parameter(Mandatory)][xml]$Xml,
    [Parameter(Mandatory)][pscustomobject]$Context,
    [Parameter(Mandatory)][string]$OriginDirectory
  )

  $FolderDestinations = Get-InstallBuilderFolderDestinationMap -Xml $Xml -Context $Context

  $Prefix = $OriginDirectory.Trim('/').Replace('\', '/') + '/'
  $Projected = [Collections.Generic.List[object]]::new()
  foreach ($Item in @($Entry)) {
    if (-not $Item.Path.StartsWith($Prefix, [StringComparison]::OrdinalIgnoreCase)) { continue }
    $Remainder = $Item.Path.Substring($Prefix.Length)
    $Separator = $Remainder.IndexOf('/')
    if ($Separator -le 0 -or $Separator -eq $Remainder.Length - 1) { continue }
    $DistributionRemainder = $Remainder.Substring($Separator + 1)
    $FolderSeparator = $DistributionRemainder.IndexOf('/')
    if ($FolderSeparator -le 0 -or $FolderSeparator -eq $DistributionRemainder.Length - 1) { continue }
    $FolderName = $DistributionRemainder.Substring(0, $FolderSeparator)
    $RelativePath = $DistributionRemainder.Substring($FolderSeparator + 1)
    $FolderMapping = $FolderDestinations.ContainsKey($FolderName) ? $FolderDestinations[$FolderName] : $null
    $LogicalPrefix = $FolderMapping ? $FolderMapping.Prefix : "_destinations/$FolderName"
    $LogicalPath = [string]::IsNullOrEmpty($LogicalPrefix) ? $RelativePath : "$LogicalPrefix/$RelativePath"
    $Projected.Add([pscustomobject][ordered]@{
        Index               = $Item.Index
        Path                = $LogicalPath
        PhysicalPath        = $Item.Path
        Size                = $Item.Size
        StoredSize          = $Item.StoredSize
        Compression         = $Item.Compression
        ModifiedUnixSeconds = $Item.ModifiedUnixSeconds
        ConditionState      = $FolderMapping ? $FolderMapping.ConditionState : 'Unknown'
        Conditions          = $FolderMapping ? $FolderMapping.Conditions : @()
      })
  }

  # A malformed project can map two physical sources to one install path. Preserve both records
  # under their internal folder names rather than allowing extraction order to choose a winner.
  $DuplicatePaths = @($Projected | Group-Object Path | Where-Object Count -GT 1 | Select-Object -ExpandProperty Name)
  if ($DuplicatePaths.Count) {
    $DuplicateSet = [Collections.Generic.HashSet[string]]::new([string[]]$DuplicatePaths, [StringComparer]::OrdinalIgnoreCase)
    foreach ($Item in $Projected) {
      if (-not $DuplicateSet.Contains($Item.Path)) { continue }
      $Remainder = $Item.PhysicalPath.Substring($Prefix.Length)
      $Item.Path = "_destinations/$Remainder"
    }
  }
  return $Projected.ToArray()
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

function Read-InstallBuilderBigEndianUInt64 {
  <#
  .SYNOPSIS
    Read a bounded unsigned 64-bit integer from a CookFS byte buffer.
  .PARAMETER Bytes
    Complete expanded CookFS index byte array.
  .PARAMETER Position
    Mutable record-relative cursor advanced by eight bytes on success.
  #>
  [OutputType([uint64])]
  param ([Parameter(Mandatory)][byte[]]$Bytes, [Parameter(Mandatory)][ref]$Position)

  if ($Position.Value -lt 0 -or $Position.Value + 8 -gt $Bytes.Length) { throw 'The CookFS index is truncated while reading a wide integer' }
  [uint64]$Value = 0
  for ($Index = 0; $Index -lt 8; $Index++) { $Value = ($Value -shl 8) -bor [uint64]$Bytes[$Position.Value + $Index] }
  $Position.Value += 8
  return $Value
}

function Read-InstallBuilderCookfsIndexMetadataEntry {
  <#
  .SYNOPSIS
    Decode the optional key/value metadata table after a CookFS directory tree.
  .PARAMETER Bytes
    Complete expanded CookFS index bytes.
  .PARAMETER Position
    Mutable index cursor positioned immediately after the root directory node.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][byte[]]$Bytes, [Parameter(Mandatory)][ref]$Position)

  # Older indexes can end directly after the directory tree. Current CookFS writes a counted
  # metadata table whose values are binary strings; expose only safely decoded text and lengths.
  if ($Position.Value -eq $Bytes.Length) { return @() }
  $Count = Read-InstallBuilderBigEndianUInt32 -Bytes $Bytes -Position $Position
  if ($Count -gt $Script:InstallBuilderMaximumCookfsEntries) { throw 'The CookFS index metadata exceeds the configured entry-count limit' }
  $Metadata = [Collections.Generic.List[object]]::new()
  for ($Index = 0; $Index -lt $Count; $Index++) {
    $Size = Read-InstallBuilderBigEndianUInt32 -Bytes $Bytes -Position $Position
    if ($Size -gt $Bytes.Length - $Position.Value) { throw 'The CookFS index metadata record is truncated' }
    $Offset = $Position.Value
    $Position.Value += [int]$Size
    $Separator = [Array]::IndexOf($Bytes, [byte]0, $Offset, [int]$Size)
    if ($Separator -lt $Offset) { throw 'The CookFS index metadata record has no key terminator' }
    $Key = $Script:InstallBuilderStrictUtf8.GetString($Bytes, $Offset, $Separator - $Offset)
    if ([string]::IsNullOrWhiteSpace($Key)) { throw 'The CookFS index metadata record has an empty key' }
    $ValueOffset = $Separator + 1
    $ValueLength = $Offset + [int]$Size - $ValueOffset
    $Sensitive = $Key -match '(?i)(?:password|passphrase|secret|token|credential|privatekey)'
    $ValueText = $null
    if (-not $Sensitive) {
      try { $ValueText = $Script:InstallBuilderStrictUtf8.GetString($Bytes, $ValueOffset, $ValueLength) } catch { $ValueText = $null }
    }
    $Metadata.Add([pscustomobject][ordered]@{
        Key         = $Key
        Value       = $Sensitive ? '<redacted>' : $ValueText
        ValueLength = $ValueLength
        IsText      = $null -ne $ValueText
        IsRedacted  = $Sensitive
      })
  }
  if ($Position.Value -ne $Bytes.Length) { throw 'The CookFS index contains trailing bytes after its metadata table' }
  return $Metadata.ToArray()
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
    $ModificationTimeUnixSeconds = Read-InstallBuilderBigEndianUInt64 -Bytes $Bytes -Position $Position
    $ModificationTimeUtc = $null
    if ($ModificationTimeUnixSeconds -le [uint64][long]::MaxValue) {
      try { $ModificationTimeUtc = [DateTimeOffset]::FromUnixTimeSeconds([long]$ModificationTimeUnixSeconds).UtcDateTime } catch { $ModificationTimeUtc = $null }
    }
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
    $Entry.Add([pscustomobject]@{
        Path                        = $RelativePath
        Length                      = $Length
        ModificationTimeUnixSeconds = $ModificationTimeUnixSeconds
        ModificationTimeUtc         = $ModificationTimeUtc
        Blocks                      = $Blocks.ToArray()
      })
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
        $IndexMetadata = @(Read-InstallBuilderCookfsIndexMetadataEntry -Bytes $IndexData -Position ([ref]$Position))
        $PageHashSetting = @($IndexMetadata | Where-Object Key -CEQ 'cookfs.pagehash' | Select-Object -Last 1).Value
        $PageHashAlgorithm = [string]::IsNullOrWhiteSpace([string]$PageHashSetting) ? 'md5' : ([string]$PageHashSetting).ToLowerInvariant()
        $PageHashBytes = Read-BinaryBytes -Stream $Stream -Offset $IndexOffset -Count ([int]($PageCount * 16))
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
          PageHashAlgorithm         = $PageHashAlgorithm
          HasUnsupportedHash        = $PageHashAlgorithm -notin 'md5', 'crc32'
          PageHashBytes             = $PageHashBytes
          IndexMetadata             = $IndexMetadata
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
  .PARAMETER Stream
    Caller-owned installer stream. The function seeks but does not dispose it.
  .PARAMETER Cookfs
    Validated CookFS layout containing page offsets, stored sizes, and the bounded page cache owned by the caller.
  .PARAMETER Page
    Current structured format node or record being interpreted.
  #>
  [OutputType([byte[]])]
  param ([Parameter(Mandatory)][System.IO.Stream]$Stream, [Parameter(Mandatory)]$Cookfs, [Parameter(Mandatory)][uint32]$Page)
  if ($Page -ge $Cookfs.PageCount) { throw "The CookFS file index references missing page $Page" }
  # Pages are shared by many files. Reuse a bounded FIFO cache to avoid repeated decompression
  # without retaining an unbounded portion of a large installer.
  if ($Cookfs.PageCache.ContainsKey([int]$Page)) { return , $Cookfs.PageCache[[int]$Page] }
  $StoredPage = Read-BinaryBytes -Stream $Stream -Offset $Cookfs.PageOffsets[$Page] -Count ([int]$Cookfs.PageSizes[$Page])
  $PageBytes = Expand-InstallBuilderCookfsRecord -StoredBytes $StoredPage -MaximumExpandedBytes $Script:InstallBuilderMaximumCookfsPageBytes
  $HashOffset = [int]$Page * 16
  switch ($Cookfs.PageHashAlgorithm) {
    'md5' {
      $ActualHash = [Security.Cryptography.MD5]::HashData($PageBytes)
      for ($Index = 0; $Index -lt 16; $Index++) {
        if ($ActualHash[$Index] -ne $Cookfs.PageHashBytes[$HashOffset + $Index]) { throw "CookFS page $Page failed its MD5 integrity check" }
      }
    }
    'crc32' {
      if (@($Cookfs.PageHashBytes[$HashOffset..($HashOffset + 7)] | Where-Object { $_ -ne 0 }).Count) { throw "CookFS page $Page has an invalid CRC32 hash prefix" }
      $ExpectedLength = ([uint32]$Cookfs.PageHashBytes[$HashOffset + 8] -shl 24) -bor ([uint32]$Cookfs.PageHashBytes[$HashOffset + 9] -shl 16) -bor ([uint32]$Cookfs.PageHashBytes[$HashOffset + 10] -shl 8) -bor [uint32]$Cookfs.PageHashBytes[$HashOffset + 11]
      $ExpectedCrc32 = ([uint32]$Cookfs.PageHashBytes[$HashOffset + 12] -shl 24) -bor ([uint32]$Cookfs.PageHashBytes[$HashOffset + 13] -shl 16) -bor ([uint32]$Cookfs.PageHashBytes[$HashOffset + 14] -shl 8) -bor [uint32]$Cookfs.PageHashBytes[$HashOffset + 15]
      if ($ExpectedLength -ne $PageBytes.Length -or $ExpectedCrc32 -ne [uint32](Get-BinaryCrc32 -Bytes $PageBytes)) { throw "CookFS page $Page failed its CRC32 integrity check" }
    }
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
  .PARAMETER Xml
    Parsed project document used to translate component/folder storage prefixes.
  .PARAMETER Context
    Resolved project variables and installation directory.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][object[]]$Entry,
    [Parameter(Mandatory)][xml]$Xml,
    [Parameter(Mandatory)]$Context
  )
  $Physical = @{}
  foreach ($Item in $Entry) { $Physical[$Item.Path] = $Item }
  $FolderMap = Get-InstallBuilderFolderDestinationMap -Xml $Xml -Context $Context
  $StoragePrefixes = @($FolderMap.Keys | Where-Object { $_ -match '/' } | Sort-Object Length -Descending)
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
    $PhysicalPath = $Item.Path
    $LogicalPath = $PhysicalPath
    $Mapping = $null
    foreach ($StoragePrefix in $StoragePrefixes) {
      if ($PhysicalPath.StartsWith($StoragePrefix + '/', [StringComparison]::OrdinalIgnoreCase)) {
        $Mapping = $FolderMap[$StoragePrefix]
        $Remainder = $PhysicalPath.Substring($StoragePrefix.Length + 1)
        $LogicalPath = [string]::IsNullOrEmpty($Mapping.Prefix) ? $Remainder : "$($Mapping.Prefix)/$Remainder"
        break
      }
    }
    $Logical.Add([pscustomobject][ordered]@{
        Path                        = $LogicalPath
        PhysicalPath                = $PhysicalPath
        Length                      = [long](@($Segments | Measure-Object -Property Length -Sum).Sum)
        ModificationTimeUnixSeconds = $Item.ModificationTimeUnixSeconds
        ModificationTimeUtc         = $Item.ModificationTimeUtc
        Segments                    = $Segments.ToArray()
        ConditionState              = $Mapping ? $Mapping.ConditionState : 'Unknown'
        Conditions                  = $Mapping ? $Mapping.Conditions : @()
      })
  }
  $DuplicatePaths = @($Logical | Group-Object Path | Where-Object Count -GT 1 | Select-Object -ExpandProperty Name)
  if ($DuplicatePaths.Count) {
    $DuplicateSet = [Collections.Generic.HashSet[string]]::new([string[]]$DuplicatePaths, [StringComparer]::OrdinalIgnoreCase)
    foreach ($Item in $Logical) {
      if ($DuplicateSet.Contains($Item.Path)) { $Item.Path = "_destinations/$($Item.PhysicalPath)" }
    }
  }
  return $Logical.ToArray()
}

function Copy-InstallBuilderCookfsEntry {
  <#
  .SYNOPSIS
    Copy one logical CookFS file to an output stream with output limits
  .PARAMETER Stream
    Caller-owned installer stream. The function seeks but does not dispose it.
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
    [Parameter(Mandatory)][System.IO.Stream]$Stream,
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
      $Page = Get-InstallBuilderCookfsPage -Stream $Stream -Cookfs $Cookfs -Page $Block.Page
      if ([long]$Block.Offset + [long]$Block.Length -gt $Page.Length) { throw "The CookFS block for '$($Entry.Path)' exceeds its decoded page" }
      if ($TotalWritten.Value + $Block.Length -gt $MaximumExpandedBytes) { throw 'InstallBuilder extraction exceeds the configured output limit' }
      $Destination.Write($Page, [int]$Block.Offset, [int]$Block.Length)
      $TotalWritten.Value += $Block.Length
    }
  }
}

function Export-InstallBuilderPayloadSelection {
  <#
  .SYNOPSIS
    Materialize an already parsed InstallBuilder payload selection for static analysis.
  .PARAMETER Path
    Resolved installer path that owns the parsed payload records.
  .PARAMETER Entry
    Logical CookFS or legacy Metakit entries selected by exact logical path.
  .PARAMETER Cookfs
    Parsed CookFS layout, or null for legacy Metakit media.
  .PARAMETER MetakitLayouts
    Validated Metakit layouts used to reopen the package-owned legacy VFS.
  .PARAMETER DestinationPath
    Empty temporary directory receiving the selected logical files.
  .PARAMETER MaximumExpandedBytes
    Aggregate output limit for the selected analysis files.
  #>
  [OutputType([System.IO.FileInfo[]])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][object[]]$Entry,
    [AllowNull()][object]$Cookfs,
    [AllowNull()][object[]]$MetakitLayouts,
    [Parameter(Mandatory)][string]$DestinationPath,
    [Parameter(Mandatory)][long]$MaximumExpandedBytes
  )

  $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
  $null = New-Item -Path $DestinationPath -ItemType Directory -Force
  $Result = [Collections.Generic.List[IO.FileInfo]]::new()
  $ReservedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  [long]$TotalWritten = 0
  if ($Cookfs) {
    $Source = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
      foreach ($Item in $Entry) {
        $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $Item.Path -CollisionAction Rename -ReservedPath $ReservedPaths
        $null = New-Item -Path ([IO.Path]::GetDirectoryName($Target.Path)) -ItemType Directory -Force
        $Output = [IO.File]::Open($Target.Path, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { Copy-InstallBuilderCookfsEntry -Stream $Source -Cookfs $Cookfs -Entry $Item -Destination $Output -TotalWritten ([ref]$TotalWritten) -MaximumExpandedBytes $MaximumExpandedBytes }
        finally { $Output.Dispose() }
        $Result.Add((Get-Item -LiteralPath $Target.Path -Force))
      }
    } finally { $Source.Dispose() }
    return $Result.ToArray()
  }

  $Archive = Open-InstallBuilderMetakitArchive -Path $Path -Layout $MetakitLayouts -RequiredEntryPath 'origindist'
  try {
    foreach ($Item in $Entry) {
      if ($Item.Compression -eq 'Unknown') { throw "The legacy Metakit payload '$($Item.PhysicalPath)' uses unsupported compression framing" }
      if ($TotalWritten -gt $MaximumExpandedBytes - [long]$Item.Size) { throw 'InstallBuilder payload analysis exceeds the configured output limit' }
      $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $Item.Path -CollisionAction Rename -ReservedPath $ReservedPaths
      $null = New-Item -Path ([IO.Path]::GetDirectoryName($Target.Path)) -ItemType Directory -Force
      $Output = [IO.File]::Open($Target.Path, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
      try { $TotalWritten += $Archive.CopyEntry([int]$Item.Index, $Output, $MaximumExpandedBytes - $TotalWritten) }
      finally { $Output.Dispose() }
      $Result.Add((Get-Item -LiteralPath $Target.Path -Force))
    }
  } finally { $Archive.Dispose() }
  return $Result.ToArray()
}

Export-ModuleMember -Function Get-InstallBuilderCandidateOffset, Read-InstallBuilderZlibProject, Get-InstallBuilderProjectData, Get-InstallBuilderMetakitLayout, Open-InstallBuilderMetakitArchive, Get-InstallBuilderFolderDestinationMap, Get-InstallBuilderLegacyPayloadEntry, Read-InstallBuilderBigEndianUInt32, Read-InstallBuilderBigEndianUInt64, Read-InstallBuilderCookfsIndexMetadataEntry, Expand-InstallBuilderCookfsRecord, Test-InstallBuilderCookfsLzmaRecord, Read-InstallBuilderCookfsIndexNode, Get-InstallBuilderCookfsInfo, Get-InstallBuilderCookfsPage, Get-InstallBuilderCookfsLogicalEntry, Copy-InstallBuilderCookfsEntry, Export-InstallBuilderPayloadSelection
