# SPDX-License-Identifier: MIT
# This shared source is kept byte-identical in PackageModule and InstallerParsers.

function Read-PEFileBytes {
  <#
  .SYNOPSIS
    Read a bounded PE byte range and restore stream position
  #>
  [OutputType([byte[]])]
  param ([Parameter(Mandatory)][IO.Stream]$Stream, [Parameter(Mandatory)][long]$Offset, [Parameter(Mandatory)][int]$Count)
  return ,(Read-BinaryBytes -Stream $Stream -Offset $Offset -Count $Count)
}

function Read-PEUInt16 {
  <#
  .SYNOPSIS
    Read a little-endian PE UInt16
  #>
  [OutputType([uint16])]
  param ([Parameter(Mandatory)][IO.Stream]$Stream, [Parameter(Mandatory)][long]$Offset)
  [uint16](Read-BinaryInteger -Stream $Stream -Offset $Offset -Size 2)
}

function Read-PEUInt32 {
  <#
  .SYNOPSIS
    Read a little-endian PE UInt32
  #>
  [OutputType([uint32])]
  param ([Parameter(Mandatory)][IO.Stream]$Stream, [Parameter(Mandatory)][long]$Offset)
  [uint32](Read-BinaryInteger -Stream $Stream -Offset $Offset -Size 4)
}

function Read-PEUInt64 {
  <#
  .SYNOPSIS
    Read a little-endian PE UInt64
  #>
  [OutputType([uint64])]
  param ([Parameter(Mandatory)][IO.Stream]$Stream, [Parameter(Mandatory)][long]$Offset)
  [uint64](Read-BinaryInteger -Stream $Stream -Offset $Offset -Size 8)
}

function Convert-PEVirtualAddressToFileOffset {
  <#
  .SYNOPSIS
    Convert a PE RVA to a file offset
  #>
  [OutputType([long])]
  param ([Parameter(Mandatory)][uint32]$Rva, [Parameter(Mandatory)][Collections.IEnumerable]$Sections)
  foreach ($Section in $Sections) {
    $Start = [uint32]$Section.VirtualAddress
    $Length = [Math]::Max([uint32]$Section.VirtualSize, [uint32]$Section.RawSize)
    if ($Rva -ge $Start -and $Rva -lt $Start + $Length) { return [long]$Section.RawOffset + ($Rva - $Start) }
  }
  $FirstSectionRva = @($Sections | Sort-Object VirtualAddress | Select-Object -First 1 -ExpandProperty VirtualAddress)[0]
  if ($Rva -ne 0 -and $null -ne $FirstSectionRva -and $Rva -lt $FirstSectionRva) { return [long]$Rva }
  return -1L
}

function Get-PEMachineName {
  <#
  .SYNOPSIS
    Convert IMAGE_FILE_HEADER.Machine to a readable name
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][uint16]$Machine)
  switch ($Machine) {
    0x014C { 'I386' }; 0x0200 { 'IA64' }; 0x01C0 { 'ARM' }; 0x01C2 { 'Thumb' }; 0x01C4 { 'ARMNT' }
    0x8664 { 'AMD64' }; 0xAA64 { 'ARM64' }; default { "Unknown(0x$($Machine.ToString('X4')))" }
  }
}

function Get-PESubsystemName {
  <#
  .SYNOPSIS
    Convert a PE subsystem value to a readable name
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][uint16]$Subsystem)
  switch ($Subsystem) {
    0 { 'Unknown' }; 1 { 'Native' }; 2 { 'WindowsGui' }; 3 { 'WindowsCui' }; 5 { 'Os2Cui' }; 7 { 'PosixCui' }
    8 { 'NativeWindows' }; 9 { 'WindowsCeGui' }; 10 { 'EfiApplication' }; 11 { 'EfiBootServiceDriver' }
    12 { 'EfiRuntimeDriver' }; 13 { 'EfiRom' }; 14 { 'Xbox' }; 16 { 'WindowsBootApplication' }
    17 { 'XboxCodeCatalog' }; default { "Unknown(0x$($Subsystem.ToString('X4')))" }
  }
}

function Open-PEReaderInput {
  <#
  .SYNOPSIS
    Normalize path and caller-owned stream inputs
  #>
  param ([string]$Path, [IO.Stream]$Stream)
  if ($Stream) { return [pscustomobject]@{ Stream = $Stream; Path = $null; OwnsStream = $false } }
  $File = Get-Item -LiteralPath $Path -Force
  [pscustomobject]@{
    Stream = [IO.File]::Open($File.FullName, 'Open', 'Read', 'ReadWrite')
    Path = $File.FullName
    OwnsStream = $true
  }
}

function ConvertFrom-PEReaderLayout {
  <#
  .SYNOPSIS
    Convert native PEReader data to the stable PowerShell contract
  #>
  param ([Parameter(Mandatory)]$NativeLayout)
  $Directories = [ordered]@{}
  foreach ($Pair in $NativeLayout.DataDirectories.GetEnumerator() | Sort-Object { $_.Value.Index }) {
    $Value = $Pair.Value
    $Directories[$Pair.Key] = [pscustomobject]@{ Index = $Value.Index; Name = $Value.Name; Rva = [uint32]$Value.Rva; Size = [uint32]$Value.Size; Offset = [long]$Value.Offset }
  }
  $Sections = @($NativeLayout.Sections | ForEach-Object {
      [pscustomobject]@{ Name = $_.Name; VirtualAddress = [uint32]$_.VirtualAddress; VirtualSize = [uint32]$_.VirtualSize; RawOffset = [uint32]$_.RawOffset; RawSize = [uint32]$_.RawSize }
    })
  [pscustomobject]@{
    PeOffset = [long]$NativeLayout.PeOffset; Machine = [uint16]$NativeLayout.Machine; MachineName = Get-PEMachineName $NativeLayout.Machine
    Characteristics = [uint16]$NativeLayout.Characteristics; OptionalHeaderMagic = [uint16]$NativeLayout.OptionalHeaderMagic
    OptionalHeaderFormat = $NativeLayout.OptionalHeaderFormat; OptionalHeaderSize = [int]$NativeLayout.OptionalHeaderSize
    Subsystem = [uint16]$NativeLayout.Subsystem; SubsystemName = Get-PESubsystemName $NativeLayout.Subsystem
    ImageBase = [uint64]$NativeLayout.ImageBase; SizeOfHeaders = [uint32]$NativeLayout.SizeOfHeaders
    DataDirectories = $Directories; Sections = $Sections; ResourceRva = [uint32]$NativeLayout.ResourceRva
    ResourceSize = [uint32]$NativeLayout.ResourceSize; ResourceOffset = [long]$NativeLayout.ResourceOffset; NativeLayout = $NativeLayout
  }
}

function Get-PELayout {
  <#
  .SYNOPSIS
    Read PE layout from a path or caller-owned stream
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, ParameterSetName = 'Path')][string]$Path,
    [Parameter(Mandatory, ParameterSetName = 'Stream')][IO.Stream]$Stream
  )
  process {
    Import-BinaryPatternSearch
    $ReaderInput = Open-PEReaderInput -Path $Path -Stream $Stream
    try {
      $NativeLayout = [Dumplings.InstallerInfrastructure.PEImageReader]::ReadLayout($ReaderInput.Stream, $true)
      if ($NativeLayout) { ConvertFrom-PEReaderLayout -NativeLayout $NativeLayout }
    } finally { if ($ReaderInput.OwnsStream) { $ReaderInput.Stream.Dispose() } }
  }
}

function Get-PESubsystemInfo {
  <#
  .SYNOPSIS
    Read the Windows execution subsystem from a PE file
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process {
    $File = Get-Item -LiteralPath $Path -Force
    $Layout = Get-PELayout -Path $File.FullName
    if (-not $Layout) { throw "The file is not a supported PE image: $($File.FullName)" }
    [pscustomobject]@{ Path = $File.FullName; Subsystem = $Layout.Subsystem; Name = $Layout.SubsystemName; IsGui = $Layout.Subsystem -eq 2; IsConsole = $Layout.Subsystem -in 3, 5, 7; IsWindowsPE = $Layout.Subsystem -in 2, 3 }
  }
}

function Get-PEOverlayOffset {
  <#
  .SYNOPSIS
    Get the offset immediately after the last PE section
  #>
  [OutputType([long])]
  param (
    [Parameter(Mandatory, ParameterSetName = 'Path')][string]$Path,
    [Parameter(Mandatory, ParameterSetName = 'Stream')][IO.Stream]$Stream
  )
  $Layout = if ($PSCmdlet.ParameterSetName -eq 'Path') { Get-PELayout -Path $Path } else { Get-PELayout -Stream $Stream }
  if (-not $Layout) { return 0L }
  $End = 0L
  foreach ($Section in $Layout.Sections) { $End = [Math]::Max($End, [long]$Section.RawOffset + [long]$Section.RawSize) }
  return $End
}

function Get-PEResourceInfo {
  <#
  .SYNOPSIS
    Enumerate bounded PE leaf resources from a path or stream
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, ParameterSetName = 'Path')][string]$Path,
    [Parameter(Mandatory, ParameterSetName = 'Stream')][IO.Stream]$Stream,
    [ValidateRange(1, 100000)][int]$MaximumResources = 10000
  )
  process {
    Import-BinaryPatternSearch
    $ReaderInput = Open-PEReaderInput -Path $Path -Stream $Stream
    try {
      $Layout = [Dumplings.InstallerInfrastructure.PEImageReader]::ReadLayout($ReaderInput.Stream, $true)
      if (-not $Layout) { return }
      foreach ($Resource in [Dumplings.InstallerInfrastructure.PEImageReader]::ReadResources($ReaderInput.Stream, $Layout, $MaximumResources, $true)) {
        [pscustomobject]@{
          Path = $ReaderInput.Path; SourceStream = if ($ReaderInput.OwnsStream) { $null } else { $ReaderInput.Stream }
          TypeName = $Resource.TypeName; TypeId = $Resource.TypeId; Name = $Resource.Name; Id = $Resource.Id
          LanguageId = $Resource.LanguageId; CodePage = [uint32]$Resource.CodePage; Offset = [long]$Resource.Offset; Size = [long]$Resource.Size
        }
      }
    } finally { if ($ReaderInput.OwnsStream) { $ReaderInput.Stream.Dispose() } }
  }
}

function Read-PEResourceData {
  <#
  .SYNOPSIS
    Read one bounded PE resource
  #>
  [OutputType([byte[]])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][psobject]$Resource, [ValidateRange(1, 1073741824)][long]$MaximumBytes = 134217728)
  process {
    if ($Resource.Size -lt 0 -or $Resource.Size -gt $MaximumBytes -or $Resource.Size -gt [int]::MaxValue) { throw "The PE resource exceeds the $MaximumBytes-byte read limit." }
    if ($Resource.SourceStream) { return ,(Read-BinaryBytes -Stream $Resource.SourceStream -Offset $Resource.Offset -Count ([int]$Resource.Size)) }
    $Stream = [IO.File]::Open($Resource.Path, 'Open', 'Read', 'ReadWrite')
    try { return ,(Read-BinaryBytes -Stream $Stream -Offset $Resource.Offset -Count ([int]$Resource.Size)) } finally { $Stream.Dispose() }
  }
}

function Export-PEResourceData {
  <#
  .SYNOPSIS
    Export one bounded PE resource without buffering it
  #>
  [OutputType([IO.FileInfo])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][psobject]$Resource,
    [Parameter(Mandatory)][string]$DestinationPath,
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumBytes = 1073741824
  )
  process {
    if ($Resource.Size -gt $MaximumBytes) { throw "The PE resource exceeds the $MaximumBytes-byte output limit." }
    $Parent = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($DestinationPath)); if ($Parent) { $null = New-Item $Parent -ItemType Directory -Force }
    $Output = [IO.File]::Open($DestinationPath, 'Create', 'Write', 'None')
    $InputStream = if ($Resource.SourceStream) { $Resource.SourceStream } else { [IO.File]::Open($Resource.Path, 'Open', 'Read', 'ReadWrite') }
    try { Copy-BinaryStreamRange -Source $InputStream -Destination $Output -Offset $Resource.Offset -Length $Resource.Size }
    finally { $Output.Dispose(); if (-not $Resource.SourceStream) { $InputStream.Dispose() } }
    Get-Item -LiteralPath $DestinationPath -Force
  }
}

function Get-PERequestedExecutionLevel {
  <#
  .SYNOPSIS
    Read requestedExecutionLevel from the PE manifest resource
  #>
  [OutputType([string])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process {
    $Resource = Get-PEResourceInfo -Path $Path | Where-Object { $_.TypeId -eq 24 -and $_.Id -eq 1 } | Select-Object -First 1
    if (-not $Resource -or $Resource.Size -gt 1048576) { return $null }
    $Bytes = Read-PEResourceData -Resource $Resource -MaximumBytes 1048576
    $Text = if ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFF -and $Bytes[1] -eq 0xFE) { [Text.Encoding]::Unicode.GetString($Bytes, 2, $Bytes.Length - 2) } else { [Text.Encoding]::UTF8.GetString($Bytes).TrimStart([char]0xFEFF) }
    $Match = [regex]::Match($Text, 'requestedExecutionLevel[^>]+level\s*=\s*["''](?<Level>asInvoker|highestAvailable|requireAdministrator)["'']', 'IgnoreCase')
    if ($Match.Success) { $Match.Groups['Level'].Value }
  }
}

function Read-PEVersionResourceBlock {
  <#
  .SYNOPSIS
    Parse one bounded VS_VERSIONINFO resource block
  #>
  param ([Parameter(Mandatory)][byte[]]$Bytes, [Parameter(Mandatory)][int]$Offset, [Parameter(Mandatory)][int]$Limit, [ValidateRange(0, 32)][int]$Depth = 0)
  if ($Depth -ge 32 -or $Offset -lt 0 -or $Offset + 6 -gt $Limit -or $Limit -gt $Bytes.Length) { throw 'The PE version resource block is outside the bounded data.' }
  $Length = [BitConverter]::ToUInt16($Bytes, $Offset); $ValueLength = [BitConverter]::ToUInt16($Bytes, $Offset + 2); $Type = [BitConverter]::ToUInt16($Bytes, $Offset + 4)
  if ($Length -lt 8 -or $Offset + $Length -gt $Limit) { throw 'The PE version resource contains an invalid block length.' }
  $BlockEnd = $Offset + $Length; $KeyOffset = $Offset + 6; $KeyEnd = $KeyOffset
  while ($KeyEnd + 1 -lt $BlockEnd -and ($Bytes[$KeyEnd] -ne 0 -or $Bytes[$KeyEnd + 1] -ne 0)) { $KeyEnd += 2 }
  if ($KeyEnd + 1 -ge $BlockEnd) { throw 'The PE version resource has an unterminated key.' }
  $Key = [Text.Encoding]::Unicode.GetString($Bytes, $KeyOffset, $KeyEnd - $KeyOffset); $ValueOffset = ($KeyEnd + 5) -band -4
  $ValueByteLength = if ($Type -eq 1) { [int]$ValueLength * 2 } else { [int]$ValueLength }
  if ($ValueOffset + $ValueByteLength -gt $BlockEnd) { throw 'The PE version resource value is truncated.' }
  $Value = if ($Type -eq 1 -and $ValueByteLength -gt 0) { [Text.Encoding]::Unicode.GetString($Bytes, $ValueOffset, $ValueByteLength).TrimEnd([char]0) } else { $null }
  $Children = [Collections.Generic.List[object]]::new(); $ChildOffset = ($ValueOffset + $ValueByteLength + 3) -band -4
  while ($ChildOffset + 6 -le $BlockEnd) {
    $ChildLength = [BitConverter]::ToUInt16($Bytes, $ChildOffset); if ($ChildLength -eq 0) { break }
    $Child = Read-PEVersionResourceBlock -Bytes $Bytes -Offset $ChildOffset -Limit $BlockEnd -Depth ($Depth + 1); $Children.Add($Child)
    $ChildOffset = ($ChildOffset + $Child.Length + 3) -band -4
  }
  [pscustomobject]@{ Key = $Key; Type = [uint16]$Type; ValueLength = [uint16]$ValueLength; Value = $Value; Offset = $Offset; Length = [uint16]$Length; Children = $Children.ToArray() }
}

function Get-PEVersionStringTable {
  <#
  .SYNOPSIS
    Read named strings from PE version resources
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process {
    $Strings = [ordered]@{}
    foreach ($Resource in @(Get-PEResourceInfo -Path $Path | Where-Object TypeId -eq 16)) {
      $Bytes = Read-PEResourceData -Resource $Resource -MaximumBytes 16777216; $Root = Read-PEVersionResourceBlock -Bytes $Bytes -Offset 0 -Limit $Bytes.Length
      $Pending = [Collections.Generic.Queue[object]]::new(); $Pending.Enqueue($Root)
      while ($Pending.Count) {
        $Block = $Pending.Dequeue()
        if ($Block.Type -eq 1 -and $Block.ValueLength -gt 0 -and $Block.Children.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace($Block.Key) -and -not $Strings.Contains($Block.Key)) { $Strings[$Block.Key] = $Block.Value }
        foreach ($Child in $Block.Children) { $Pending.Enqueue($Child) }
      }
    }
    [pscustomobject]$Strings
  }
}

function Get-PEDataDirectory {
  <#
  .SYNOPSIS
    Get one named directory from PE layout metadata
  #>
  param ([Parameter(Mandatory)][psobject]$Layout, [Parameter(Mandatory)][string]$Name)
  if ($Layout.DataDirectories) { $Layout.DataDirectories[$Name] }
}

function Get-PEImportInternal {
  <#
  .SYNOPSIS
    Read regular or delay-import DLL names through the shared PE reader
  #>
  param ([string]$Path, [IO.Stream]$Stream, [switch]$Delay)
  Import-BinaryPatternSearch
  $ReaderInput = Open-PEReaderInput -Path $Path -Stream $Stream
  try {
    $Layout = [Dumplings.InstallerInfrastructure.PEImageReader]::ReadLayout($ReaderInput.Stream, $true); if (-not $Layout) { return }
    $Index = 0
    foreach ($Import in [Dumplings.InstallerInfrastructure.PEImageReader]::ReadImports($ReaderInput.Stream, $Layout, $Delay.IsPresent, $true)) {
      [pscustomobject]@{ Path = $ReaderInput.Path; Directory = if ($Delay) { 'DelayImport' } else { 'Import' }; DescriptorIndex = $Index++; DllName = $Import.Name }
    }
  } finally { if ($ReaderInput.OwnsStream) { $ReaderInput.Stream.Dispose() } }
}

function Get-PEImportedDll {
  <#
  .SYNOPSIS
    Enumerate statically imported DLL names
  #>
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory, ParameterSetName = 'Path')][string]$Path, [Parameter(Mandatory, ParameterSetName = 'Stream')][IO.Stream]$Stream)
  process { Get-PEImportInternal -Path $Path -Stream $Stream }
}

function Get-PEDelayImportedDll {
  <#
  .SYNOPSIS
    Enumerate delay-loaded DLL names
  #>
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory, ParameterSetName = 'Path')][string]$Path, [Parameter(Mandatory, ParameterSetName = 'Stream')][IO.Stream]$Stream)
  process { Get-PEImportInternal -Path $Path -Stream $Stream -Delay }
}

function Get-PEClrHeader {
  <#
  .SYNOPSIS
    Read CLR header metadata from a managed PE
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory, ParameterSetName = 'Path')][string]$Path, [Parameter(Mandatory, ParameterSetName = 'Stream')][IO.Stream]$Stream)
  process {
    Import-BinaryPatternSearch; $ReaderInput = Open-PEReaderInput -Path $Path -Stream $Stream
    try {
      $Layout = [Dumplings.InstallerInfrastructure.PEImageReader]::ReadLayout($ReaderInput.Stream, $true); if (-not $Layout) { return $null }
      $Header = [Dumplings.InstallerInfrastructure.PEImageReader]::ReadClrHeader($ReaderInput.Stream, $Layout, $true); if (-not $Header) { return $null }
      $Flags = [uint32]$Header.Flags
      [pscustomobject]@{
        HeaderSize = [uint32]$Header.HeaderSize; MajorRuntimeVersion = [uint16]$Header.MajorRuntimeVersion; MinorRuntimeVersion = [uint16]$Header.MinorRuntimeVersion
        MetaDataRva = [uint32]$Header.MetaDataRva; MetaDataSize = [uint32]$Header.MetaDataSize; Flags = $Flags; EntryPointToken = [uint32]$Header.EntryPointToken
        ILOnly = ($Flags -band 1) -ne 0; Requires32Bit = ($Flags -band 2) -ne 0; StrongNameSigned = ($Flags -band 8) -ne 0; NativeEntryPoint = ($Flags -band 0x10) -ne 0; Prefers32Bit = ($Flags -band 0x20000) -ne 0
      }
    } finally { if ($ReaderInput.OwnsStream) { $ReaderInput.Stream.Dispose() } }
  }
}

function Get-PEManagedTargetFramework {
  <#
  .SYNOPSIS
    Read target-framework evidence from the CLR metadata range
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory, ParameterSetName = 'Path')][string]$Path, [Parameter(Mandatory, ParameterSetName = 'Stream')][IO.Stream]$Stream)
  process {
    Import-BinaryPatternSearch; $ReaderInput = Open-PEReaderInput -Path $Path -Stream $Stream
    try {
      $Layout = [Dumplings.InstallerInfrastructure.PEImageReader]::ReadLayout($ReaderInput.Stream, $true); if (-not $Layout) { return $null }
      $Framework = [Dumplings.InstallerInfrastructure.PEImageReader]::ReadManagedTargetFramework($ReaderInput.Stream, $Layout, $true); if (-not $Framework) { return $null }
      [pscustomobject]@{ FrameworkName = $Framework.FrameworkName; Version = $Framework.Version; VersionObject = [version]$Framework.Version; RawValue = $Framework.RawValue }
    } finally { if ($ReaderInput.OwnsStream) { $ReaderInput.Stream.Dispose() } }
  }
}

Export-ModuleMember -Function Read-PEFileBytes, Read-PEUInt16, Read-PEUInt32, Read-PEUInt64, Convert-PEVirtualAddressToFileOffset, Get-PEMachineName, Get-PESubsystemName, Get-PELayout, Get-PESubsystemInfo, Get-PERequestedExecutionLevel, Get-PEOverlayOffset, Get-PEResourceInfo, Read-PEResourceData, Get-PEVersionStringTable, Export-PEResourceData, Get-PEDataDirectory, Get-PEImportedDll, Get-PEDelayImportedDll, Get-PEClrHeader, Get-PEManagedTargetFramework
