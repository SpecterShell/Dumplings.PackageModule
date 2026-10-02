# SPDX-License-Identifier: Apache-2.0
# Format/behavior: https://github.com/rkozlowski/TigerSetup/tree/v0.14.0
# Independently composed from footer.rs, proto/tigersetup.proto, identity.rs,
# resource/registration.rs and the setup CLI. Nothing is executed or downloaded.
#
# v1: PE engine | metadata:Protobuf | payload:ZIP | footer[128]
# v2: PE loader | engine:Zstd | solid payload:Zstd | metadata:Protobuf | footer[256]
# v3: PE loader | engine:Zstd | solid payload:Zstd | metadata:Zstd(Protobuf) | footer
#                                                                           | optional certificate
# Footer (320 bytes, LE, offsets absolute):
#   0: "TIGERSTP"[8]; 8: major:u16; 10: minor:u16; 12: length:u32
#  16/40/64: engine/payload/metadata {offset:u64, compressed:u64, expanded:u64}
#  88/120/152/184/216: SHA256[32] of compressed engine, expanded engine,
#                     compressed payload, compressed metadata, expanded metadata
# 248: reserved[60]; 308: CRC32:u32 over [0,308); 312: "PTSREGIT"[8]
# Metadata indexes contiguous uncompressed payload regions with CRC32/SHA256.
# Metadata analysis never decompresses the engine or application payload.

$Script:TigerSetupFormats = (Import-PowerShellDataFile (Join-Path $PSScriptRoot 'TigerSetupFormatCatalog.psd1')).Profiles

function Import-TigerSetupReader {
  <#
  .SYNOPSIS
    Load the bounded schema-aware Protobuf reader with race-safe assembly reuse.
  #>
  $Source = @('MetadataReader.cs', 'MetadataValidation.cs') | ForEach-Object { Join-Path $PSScriptRoot "..\..\Assets\Source\TigerSetup\$_" }
  $null = Import-InstallerManagedSource -Path $Source -TypeName 'Dumplings.TigerSetup.MetadataReader'
}

function Read-TigerSetupBlock {
  <#
  .SYNOPSIS
    Verify and decode a footer-selected stored or Zstandard block into an owned context.
  .PARAMETER Stream
    Borrowed seekable installer stream.
  .PARAMETER Block
    Absolute Offset, CompressedSize, ExpandedSize, Codec and stored/compressed Hash.
  .PARAMETER MaximumBytes
    Hard expanded-byte limit; the Zstd window is also capped at 128 MiB.
  .OUTPUTS
    Disposable SeekableStreamContext. Caller owns the returned context.
  #>
  param ([IO.Stream]$Stream, [object]$Block, [long]$MaximumBytes)
  if ($Block.ExpandedSize -gt $MaximumBytes) { throw 'TigerSetup expanded block exceeds the byte limit.' }
  if ($Block.CompressedSize -gt $MaximumBytes -and $Block.CompressedSize - $MaximumBytes -gt 1048576) { throw 'TigerSetup compressed block exceeds the byte limit plus framing allowance.' }
  $Range = New-BoundedReadStream -Stream $Stream -Offset $Block.Offset -Length $Block.CompressedSize -LeaveOpen
  try {
    $Hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Range))
    if ($Block.Hash -and $Hash -ine $Block.Hash) { throw 'TigerSetup compressed block SHA256 mismatch.' }
    $Range.Position = 0
    $Decoder = $Block.Codec -eq 'Stored' ? $Range : (New-InstallerDecompressionStream -Algorithm Zstd -Stream $Range -LeaveOpen)
    try {
      if ($Block.Codec -eq 'Zstd') { $Decoder.SetParameter([ZstdSharp.Unsafe.ZSTD_dParameter]::ZSTD_d_windowLogMax, 27) }
      $Context = New-InstallerSeekableStream -SourceStream $Decoder -MaximumBytes $MaximumBytes
      if ($Context.Stream.Length -ne $Block.ExpandedSize) {
        $Context.Dispose()
        throw 'TigerSetup expanded block length mismatch.'
      }
      return $Context
    } finally { if ($Decoder -ne $Range) { $Decoder.Dispose() } }
  } finally { $Range.Dispose() }
}

function Get-TigerSetupContext {
  <#
  .SYNOPSIS
    Validate PE/footer/metadata and cross-check the complete payload index.
  .PARAMETER Path
    PowerShell-relative source path, resolved before any managed file access.
  .OUTPUTS
    Private context owning Stream and optional ZIP catalog. Close with Close-TigerSetupContext.
  #>
  param ([Parameter(Mandatory)][string]$Path)
  Import-TigerSetupReader
  $ResolvedPath = Resolve-InstallerFileSystemPath -Path $Path
  $Stream = [IO.File]::OpenRead($ResolvedPath)
  $Archive = $null
  $ZipRange = $null
  try {
    $Layout = Get-PELayout -Stream $Stream
    if (-not $Layout) { throw 'TigerSetup requires a valid PE loader.' }
    $End = $Stream.Length
    $Certificate = $Layout.DataDirectories.Certificate
    if ($Certificate.Size -gt 0) {
      # The security directory uses a file offset, not an RVA. Signing appends
      # certificates after the logical format ending; arbitrary trailing bytes
      # are not scanned for footer-shaped markers.
      if ($Certificate.Rva % 8 -ne 0 -or $Certificate.Rva -lt 128 -or $Certificate.Rva -gt $End -or $Certificate.Size -gt $End - $Certificate.Rva) { throw 'Invalid TigerSetup PE certificate range.' }
      $End = [long]$Certificate.Rva
    }
    # Only the three source-defined positional endings are candidates. A major
    # must match its own framing; a forged version must not fall into another route.
    $FormatProfile = $null
    $Bytes = $null
    foreach ($Candidate in $Script:TigerSetupFormats) {
      if ($End -lt $Candidate.FooterLength) { continue }
      $Probe = Read-BinaryBytes -Stream $Stream -Offset ($End - $Candidate.FooterLength) -Count $Candidate.FooterLength
      if ([Text.Encoding]::ASCII.GetString($Probe, 0, 8) -cne 'TIGERSTP' -or [Text.Encoding]::ASCII.GetString($Probe, $Probe.Length - 8, 8) -cne 'PTSREGIT') { continue }
      if ([BitConverter]::ToUInt16($Probe, 8) -ne $Candidate.Major -or [BitConverter]::ToUInt32($Probe, 12) -ne $Candidate.FooterLength) { throw 'Unsupported TigerSetup footer version/size.' }
      $FormatProfile = $Candidate
      $Bytes = $Probe
      break
    }
    if (-not $FormatProfile) { throw 'TigerSetup footer magic is absent.' }
    $FooterOffset = $End - $FormatProfile.FooterLength
    $Major = [BitConverter]::ToUInt16($Bytes, 8)
    $Minor = [BitConverter]::ToUInt16($Bytes, 10)
    $Crc = [Dumplings.InstallerInfrastructure.BinaryIO]::Crc32($Bytes, 0, $FormatProfile.CrcOffset)
    if ($Crc -ne [BitConverter]::ToUInt32($Bytes, $FormatProfile.CrcOffset)) { throw 'TigerSetup footer CRC32 mismatch.' }
    $Blocks = [ordered]@{}
    foreach ($Definition in $FormatProfile.Blocks) {
      $Offset = [BitConverter]::ToUInt64($Bytes, $Definition.OffsetField)
      $Size = [BitConverter]::ToUInt64($Bytes, $Definition.LengthField)
      $Expanded = $Definition.ExpandedField -lt 0 ? $Size : [BitConverter]::ToUInt64($Bytes, $Definition.ExpandedField)
      if ($Offset -gt $FooterOffset -or $Size -gt $FooterOffset - $Offset -or $Expanded -gt [long]::MaxValue) { throw 'TigerSetup block is outside the logical file.' }
      if (($Size -eq 0) -ne ($Expanded -eq 0) -or ($Definition.Name -ne 'Payload' -and $Size -eq 0)) { throw 'Invalid empty TigerSetup block.' }
      $Blocks[$Definition.Name] = [pscustomobject]@{ Offset = [long]$Offset; CompressedSize = [long]$Size; ExpandedSize = [long]$Expanded; Hash = [Convert]::ToHexString($Bytes, $Definition.HashField, 32); Codec = $Definition.Codec }
    }
    if ($Major -eq 1) { $Blocks.Engine = [pscustomobject]@{ Offset = 0L; CompressedSize = $Blocks.Metadata.Offset; ExpandedSize = $Blocks.Metadata.Offset; Hash = $null; Codec = 'Stored' } }
    $Next = $Blocks.Engine.Offset
    foreach ($BlockName in $FormatProfile.Order) {
      $Block = $Blocks[$BlockName]
      if ($Block.Offset -ne $Next) { throw 'TigerSetup blocks are not contiguous.' }
      $Next += $Block.CompressedSize
    }
    $ImageEnd = [long]$Layout.SizeOfHeaders
    foreach ($Section in $Layout.Sections) { $ImageEnd = [Math]::Max($ImageEnd, [long]$Section.RawOffset + $Section.RawSize) }
    $ImageBoundary = $Major -eq 1 ? $Blocks.Metadata.Offset : $Blocks.Engine.Offset
    if ($ImageBoundary -lt $ImageEnd -or $Next -ne $FooterOffset) { throw 'TigerSetup overlay overlaps the PE or footer.' }
    # Only the small metadata block is decoded during identification/analysis.
    $Decoded = Read-TigerSetupBlock -Stream $Stream -Block $Blocks.Metadata -MaximumBytes 67108864
    try {
      $MetadataHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Decoded.Stream))
      if ($MetadataHash -ine [Convert]::ToHexString($Bytes, $FormatProfile.MetadataHashOffset, 32)) { throw 'TigerSetup metadata SHA256 mismatch.' }
      $RawMetadata = Read-BinaryBytes -Stream $Decoded.Stream -Offset 0 -Count ([int]$Decoded.Stream.Length)
      $Metadata = [Dumplings.TigerSetup.MetadataReader]::Read($RawMetadata)
    } finally { $Decoded.Dispose() }
    if ($Metadata.schema -ne $FormatProfile.Schema -or $Metadata.role -notin 1, 2 -or -not $Metadata.package -or -not $Metadata.install -or -not $Metadata.engine) { throw 'Unsupported or incomplete TigerSetup metadata schema/role.' }
    if ($Metadata.package.id -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$' -or -not $Metadata.package.name -or -not $Metadata.package.version) { throw 'Invalid TigerSetup package identity.' }
    if ($Metadata.install.architecture -cne 'x64' -or $Layout.MachineName -cne 'AMD64') { throw 'Unsupported TigerSetup loader/install architecture.' }
    if ($Metadata.install.scopes.Count -eq 0 -or $Metadata.install.scopes.Count -gt 2) { throw 'Invalid TigerSetup scope list.' }
    $Scopes = [Collections.Generic.HashSet[ulong]]::new()
    foreach ($Scope in $Metadata.install.scopes) {
      if ($Scope -notin 1, 2 -or -not $Scopes.Add($Scope)) { throw 'Invalid or duplicate TigerSetup scope.' }
      $Root = $Scope -eq 1 ? $Metadata.install.user_root : $Metadata.install.machine_root
      if (-not $Root) { throw 'TigerSetup scope has no install-root template.' }
    }
    # Reject invalid resources even when their default predicates disable them.
    # Otherwise a malformed custom ARP row could become authoritative metadata.
    [Dumplings.TigerSetup.MetadataValidation]::Validate($Metadata)
    # Catalog offsets are relative to the expanded solid stream. Never sort
    # them: declared stream order, including prerequisites/actions, is data.
    $Catalog = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    $Next = 0L
    if ($Metadata.payload.Count -gt 65536 -or $Metadata.files.Count -gt 65536) { throw 'TigerSetup payload entry limit exceeded.' }
    $PayloadEntries = [Collections.Generic.List[object]]::new()
    if ($Major -eq 1) {
      # The original engine carries raw schema-1 metadata followed by a ZIP.
      # Borrow the existing file, keep central-directory objects for extraction,
      # and do not inflate application files during metadata analysis.
      if ($Blocks.Payload.CompressedSize -lt 22 -or $Metadata.payload.Count -ne 0) { throw 'Invalid TigerSetup ZIP payload.' }
      $ZipRange = New-BoundedReadStream -Stream $Stream -Offset $Blocks.Payload.Offset -Length $Blocks.Payload.CompressedSize -LeaveOpen
      $Archive = Get-InstallerArchive -Stream $ZipRange
      if ($Archive.Type -ne [SharpCompress.Common.ArchiveType]::Zip -or $Archive.Entries.Count -gt 65536) { throw 'Invalid TigerSetup ZIP catalog.' }
      foreach ($Native in $Archive.Entries) {
        if ($Native.IsDirectory) { throw 'TigerSetup ZIP contains an unexpected directory entry.' }
        $null = Resolve-SafeExtractionPath -DestinationPath ([IO.Path]::GetTempPath()) -RelativePath $Native.Key
        if ($Native.IsEncrypted -or $Native.LinkTarget -or $Native.CompressionType -notin [SharpCompress.Common.CompressionType]::None, [SharpCompress.Common.CompressionType]::Deflate -or $Native.Size -lt 0) { throw 'Unsupported or oversized TigerSetup ZIP entry.' }
        $Entry = [pscustomobject]@{ entry = $Native.Key; offset = $null; length = [long]$Native.Size; crc32 = [uint32]$Native.Crc; sha256 = $null; NativeEntry = $Native }
        if (-not $Catalog.TryAdd($Entry.entry, $Entry)) { throw 'Duplicate TigerSetup ZIP entry.' }
        $PayloadEntries.Add($Entry)
      }
      $Blocks.Payload.ExpandedSize = 0L
      foreach ($Entry in $PayloadEntries) {
        if ($Entry.length -gt [long]::MaxValue - $Blocks.Payload.ExpandedSize) { throw 'TigerSetup ZIP expanded length overflow.' }
        $Blocks.Payload.ExpandedSize += $Entry.length
      }
    } else {
      foreach ($Entry in $Metadata.payload) {
        if (-not $Entry.entry -or $Entry.offset -ne $Next -or $Entry.length -gt $Blocks.Payload.ExpandedSize - $Next -or $Entry.sha256 -cnotmatch '^[0-9a-f]{64}$' -or -not $Catalog.TryAdd($Entry.entry, $Entry)) { throw 'Invalid TigerSetup payload index.' }
        $Next += [long]$Entry.length
        $PayloadEntries.Add($Entry)
      }
      if ($Next -ne $Blocks.Payload.ExpandedSize) { throw 'TigerSetup payload index length mismatch.' }
    }
    if ($Metadata.role -eq 2 -and ($PayloadEntries.Count -ne 0 -or $Metadata.uninstaller_scope -notin $Metadata.install.scopes)) { throw 'Invalid TigerSetup uninstaller payload/scope.' }
    $Paths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($File in $Metadata.files) {
      $null = Resolve-SafeExtractionPath -DestinationPath ([IO.Path]::GetTempPath()) -RelativePath $File.path
      if (-not $Paths.Add($File.path.Replace('/', '\'))) { throw 'Duplicate TigerSetup installed path.' }
      if ($Metadata.role -eq 1 -and (-not $Catalog.ContainsKey($File.entry) -or $File.size -ne $Catalog[$File.entry].length)) { throw 'TigerSetup file is not backed by its declared payload region.' }
    }
    # The runtime journals file batches, so a malformed partition is an
    # installability failure even when every individual file looks valid.
    $First = 0
    foreach ($Batch in $Metadata.file_batches) {
      if ($Batch.first_file -ne $First -or $Batch.file_count -eq 0 -or $Batch.file_count -gt $Metadata.files.Count - $First) { throw 'Invalid TigerSetup file-batch partition.' }
      $BytesInBatch = 0L
      for ($Index = 0; $Index -lt $Batch.file_count; $Index++) {
        $Size = $Metadata.files[$First + $Index].size
        if ($Size -gt [long]::MaxValue - $BytesInBatch) { throw 'TigerSetup file-batch size overflow.' }
        $BytesInBatch += [long]$Size
      }
      if ($Batch.bytes -ne $BytesInBatch) { throw 'TigerSetup file-batch length mismatch.' }
      $First += [int]$Batch.file_count
    }
    if ($FormatProfile.RequiresFileBatches -and $First -ne $Metadata.files.Count) { throw 'TigerSetup file batches do not partition the file list.' }
    $Embedded = [Collections.Generic.List[object]]::new()
    foreach ($Dependency in $Metadata.dependencies) { if ($Dependency.acquisition -and $Dependency.acquisition.source -eq 3) { $Embedded.Add($Dependency.acquisition) } }
    foreach ($Action in $Metadata.actions) { if ($Action.entry) { $Embedded.Add($Action) } }
    foreach ($Item in $Metadata.quiescence) {
      foreach ($Action in @($Item.stop, $Item.resume)) { if ($Action -and $Action.entry) { $Embedded.Add($Action) } }
    }
    foreach ($Item in $Embedded) {
      if ($Metadata.role -eq 1 -and (-not $Catalog.ContainsKey($Item.entry) -or $Catalog[$Item.entry].length -ne $Item.size -or ($Major -ne 1 -and $Catalog[$Item.entry].sha256 -cne $Item.sha256))) { throw 'TigerSetup embedded program is not backed by its payload region.' }
    }
    return [pscustomobject]@{ Path = $ResolvedPath; Stream = $Stream; Footer = $Bytes; FooterOffset = $FooterOffset; FormatVersion = "${Major}.${Minor}"; Profile = $FormatProfile; Blocks = $Blocks; Metadata = $Metadata; RawMetadata = $RawMetadata; Catalog = $Catalog; PayloadEntries = $PayloadEntries; Archive = $Archive; ZipRange = $ZipRange }
  } catch { if ($Archive) { $Archive.Dispose() }; if ($ZipRange) { $ZipRange.Dispose() }; $Stream.Dispose(); throw }
}

function Close-TigerSetupContext {
  <#
  .SYNOPSIS
    Release the owned ZIP catalog/window before closing its installer file.
  .PARAMETER Context
    Context returned by Get-TigerSetupContext; callers invoke once in finally.
  #>
  param ([object]$Context)
  try { if ($Context.Archive) { $Context.Archive.Dispose() } }
  finally { try { if ($Context.ZipRange) { $Context.ZipRange.Dispose() } } finally { $Context.Stream.Dispose() } }
}

function Resolve-TigerSetupTemplate {
  <#
  .SYNOPSIS
    Resolve package placeholders without substituting the host's known folders.
  .PARAMETER Value
    Compiled template string.
  .PARAMETER Root
    Manifest-safe install-root template for the selected scope.
  .PARAMETER Version
    Packaged application version.
  .PARAMETER PathTemplate
    Normalize known-folder names and separators only for filesystem templates.
  #>
  param ([AllowEmptyString()][string]$Value, [string]$Root, [string]$Version, [switch]$PathTemplate)
  $Resolved = $Value.Replace('%INSTALLROOT%', $Root).Replace('%VERSION%', $Version)
  if ($PathTemplate) { $Resolved = $Resolved.Replace('%PROGRAMFILESX86%', '%ProgramFiles(x86)%').Replace('%PROGRAMFILES%', '%ProgramFiles%').Replace('/', '\') }
  return $Resolved
}

function Test-TigerSetupResourceCondition {
  <#
  .SYNOPSIS
    Evaluate the format's single option-equality predicate using chosen/default options.
  .PARAMETER Resource
    Metadata resource, optionally carrying when or the legacy option field.
  .PARAMETER Values
    Validated option values; no expression language or external code is evaluated.
  #>
  param ([Collections.IDictionary]$Resource, [Collections.IDictionary]$Values)
  if ($Resource['when'] -and $Resource.when.option) {
    if ($Values.Keys -inotcontains $Resource.when.option) { throw 'TigerSetup predicate references an undeclared option.' }
    # CLI values normalize aliases, but compiled predicates compare literal
    # canonical text. A raw equals='ON' is valid yet does not equal 'true'.
    return $Values[$Resource.when.option] -ceq $Resource.when.equals
  }
  if ($Resource['option']) {
    if ($Values.Keys -inotcontains $Resource.option) { throw 'TigerSetup resource references an undeclared option.' }
    return $Values[$Resource.option] -ceq 'true'
  }
  return $true
}

function Get-TigerSetupInfo {
  <#
  .SYNOPSIS
    Statically parse TigerSetup formats 1-3 without executing its loader or engine.
  .PARAMETER Path
    Installer or generated uninstaller path.
  .PARAMETER Scope
    Explicit supported scope. Omitted on dual-scope media returns alternatives, not a guessed scope.
  .PARAMETER Option
    Boolean or choice option values used for conditional evidence. Defaults model a fresh install.
  .PARAMETER CommandLine
    Virtual authored command. Scope, install-root and option arguments affect fresh-install evidence; no command is executed.
  .OUTPUTS
    Standard parser evidence plus Metadata, ARPEntries, RegistryRoutes, PayloadCatalog,
    SystemEffects, DependencyInfo, InstallerSwitches, option evidence and neutral Diagnostics.
  #>
  [CmdletBinding()]
  param ([Parameter(Mandatory, Position = 0)][string]$Path, [ValidateSet('user', 'machine')][string]$Scope, [Collections.IDictionary]$Option = @{}, [AllowEmptyString()][string]$CommandLine = '')
  $InstallRoot = $null
  if ($CommandLine) {
    $ParsedOption = [ordered]@{}
    foreach ($Key in $Option.Keys) { $ParsedOption[$Key] = $Option[$Key] }
    $Tokens = @(Split-BootstrapperCommandLine -CommandLine $CommandLine)
    $SingletonArguments = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    for ($Index = 0; $Index -lt $Tokens.Count; $Index++) {
      $Token = [string]$Tokens[$Index]
      if ($Token -ceq '--scope' -or $Token.StartsWith('--scope=')) {
        if (-not $SingletonArguments.Add('--scope')) { throw 'Repeated TigerSetup --scope argument.' }
        $Value = $Token.StartsWith('--scope=') ? $Token.Substring(8) : (++$Index -lt $Tokens.Count ? $Tokens[$Index] : '')
        if ($Value -cnotin @('user', 'machine') -or ($Scope -and $Scope -cne $Value)) { throw 'Invalid or conflicting TigerSetup command-line scope.' }
        $Scope = $Value
      } elseif ($Token -ceq '--install-root' -or $Token.StartsWith('--install-root=')) {
        if (-not $SingletonArguments.Add('--install-root')) { throw 'Repeated TigerSetup --install-root argument.' }
        $InstallRoot = $Token.StartsWith('--install-root=') ? $Token.Substring(15) : (++$Index -lt $Tokens.Count ? [string]$Tokens[$Index] : '')
        if (-not $InstallRoot -or -not [IO.Path]::IsPathFullyQualified($InstallRoot) -or $InstallRoot -match '[\x00-\x1F"<>|]') { throw 'TigerSetup --install-root must name an absolute Windows path.' }
        $InstallRoot = $InstallRoot.Replace('/', '\')
      } elseif ($Token -ceq '--option' -or $Token.StartsWith('--option=')) {
        $Attached = $Token.StartsWith('--option=')
        $OptionName = $Attached ? $Token.Substring(9) : (++$Index -lt $Tokens.Count ? [string]$Tokens[$Index] : '')
        if (-not $OptionName -or ++$Index -ge $Tokens.Count -or $Tokens[$Index].StartsWith('--')) { throw 'Incomplete TigerSetup --option argument.' }
        $ParsedOption[$OptionName] = [string]$Tokens[$Index]
      }
    }
    $Option = $ParsedOption
  }
  $Context = Get-TigerSetupContext -Path $Path
  try {
    $M = $Context.Metadata
    $Package = $M.package
    $Registration = $M.registration
    $ProductCode = $Registration -and $Registration.key_name ? $Registration.key_name : $Package.id
    if ($ProductCode -match '[\\/\x00-\x1F]') { throw 'Invalid TigerSetup uninstall key name.' }
    $DisplayName = $Registration -and $Registration.display_name ? $Registration.display_name : $Package.name
    $DisplayVersion = $Registration -and $Registration.display_version ? $Registration.display_version : $Package.version
    $SupportedScopes = [string[]]@(foreach ($Value in $M.install.scopes) { $Value -eq 1 ? 'user' : 'machine' })
    if ($Scope -and $Scope -notin $SupportedScopes) { throw "TigerSetup does not support '$Scope' scope." }
    if ($M.role -eq 2) { $Scope = $M.uninstaller_scope -eq 1 ? 'user' : 'machine' }
    if (-not $Scope -and $SupportedScopes.Count -eq 1) { $Scope = $SupportedScopes[0] }
    $Values = [ordered]@{}
    foreach ($Declared in $M.options) {
      if ($Values.Contains($Declared.name)) { throw 'Duplicate TigerSetup option name.' }
      $Value = $Declared.kind -eq 4 ? $Declared.default_choice : ($Declared.default ? 'true' : 'false')
      if ($Option.Keys -icontains $Declared.name) {
        $Value = [string]$Option[$Declared.name]
        if ($Declared.kind -ne 4) {
          if ($Value -in 'true', 'on', 'yes', '1') { $Value = 'true' }
          elseif ($Value -in 'false', 'off', 'no', '0') { $Value = 'false' }
          else { throw "Invalid Boolean TigerSetup option '$($Declared.name)'." }
        }
      }
      if ($Declared.kind -eq 4) {
        $Choice = @($Declared.choices | Where-Object value -IEQ $Value)
        if ($Choice.Count -ne 1) { throw "Invalid TigerSetup choice '$($Declared.name)'." }
        $Value = $Choice[0].value
      }
      $Values[$Declared.name] = $Value
    }
    foreach ($Key in $Option.Keys) { if (-not $Values.Contains($Key)) { throw "Unknown TigerSetup option '$Key'." } }
    $Diagnostics = [Collections.Generic.List[object]]::new()
    $Unresolved = [Collections.Generic.List[string]]::new()
    if ($M.options.Count -gt 0) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id TigerSetup.Options.ExistingState -Source TigerSetup -Kind Information -Areas Metadata -AffectedFields Protocols, FileExtensions -Message 'Conditional resources use the selected/default options; upgrades preserve installed option choices.' -Evidence $Values))
    }
    if ($M.actions.Count -gt 0 -or $M.quiescence.Count -gt 0) {
      $Unresolved.Add('CustomActionEffects')
      $Diagnostics.Add((New-InstallerDiagnostic -Id TigerSetup.Actions.ExternalEffects -Source TigerSetup -Kind ManualValidation -Areas Metadata, Installability -AffectedFields AppsAndFeaturesEntries, Protocols, FileExtensions -Message 'Custom actions and quiescence programs can change installed state beyond declarative metadata; their side effects require separate analysis or VM validation.' -Evidence @($M.actions, $M.quiescence)))
    }
    if ($M.legacy) {
      $Unresolved.Add('LegacyInstalledState')
      $Diagnostics.Add((New-InstallerDiagnostic -Id TigerSetup.Legacy.ExistingState -Source TigerSetup -Kind ManualValidation -Areas Installability -AffectedFields AppsAndFeaturesEntries -Message 'Migration from the declared Inno registration depends on its installed state and uninstaller; the parser does not assume a fresh-install ARP tuple describes migration.' -Evidence $M.legacy))
    }
    if (-not $Context.FormatVersion.EndsWith('.0') -or $M.UnknownPaths.Count -gt 0) {
      $Unresolved.Add('FutureMetadata')
      $Diagnostics.Add((New-InstallerDiagnostic -Id TigerSetup.Metadata.FutureFields -Source TigerSetup -Kind Incomplete -Areas Metadata -Message 'Forward-compatible format or unknown metadata fields were retained as evidence; unrecognized behavior is not inferred.' -Evidence @{ FormatVersion = $Context.FormatVersion; Fields = $M.UnknownPaths }))
    }
    $Routes = [Collections.Generic.List[object]]::new()
    $Locations = [ordered]@{}
    foreach ($DeclaredScope in $SupportedScopes) {
      $Locations[$DeclaredScope] = $InstallRoot ? $InstallRoot : (Resolve-TigerSetupTemplate -Value ($DeclaredScope -eq 'user' ? $M.install.user_root : $M.install.machine_root) -Version $Package.version -Root '' -PathTemplate)
    }
    foreach ($RouteScope in ($Scope ? @($Scope) : $SupportedScopes)) {
      $Root = $Locations[$RouteScope]
      $StateRoot = $RouteScope -eq 'user' ? '%LOCALAPPDATA%' : '%PROGRAMDATA%'
      $Uninstaller = "$StateRoot\TigerSetup\$($Package.id)\uninstall.exe"
      $ValuesArp = [ordered]@{
        DisplayName = $DisplayName; DisplayVersion = $DisplayVersion; Publisher = $Package.publisher
        InstallLocation = $Root.TrimEnd('\') + '\'; UninstallString = '"' + $Uninstaller + '"'
        QuietUninstallString = '"' + $Uninstaller + '" uninstall --quiet'; NoModify = 1; NoRepair = 1
        EstimatedSize = [uint32][Math]::Min([uint32]::MaxValue, [Math]::Ceiling($M.install.estimated_size / 1024.0))
      }
      $Parts = $Package.version.Split('.')
      foreach ($Part in @(@('VersionMajor', 0), @('VersionMinor', 1))) {
        $Number = 0u
        if ($Parts.Count -gt $Part[1]) { $null = [uint32]::TryParse($Parts[$Part[1]], [ref]$Number) }
        $ValuesArp[$Part[0]] = $Number
      }
      if ($Registration -and $Registration.display_icon) { $ValuesArp.DisplayIcon = "$($Root.TrimEnd('\'))\$($Registration.display_icon.Replace('/', '\'))" }
      if ($Package.website_url) { $ValuesArp.URLInfoAbout = $Package.website_url }
      if ($Package.help_url) { $ValuesArp.HelpLink = $Package.help_url }
      $Routes.Add([pscustomobject]@{ Scope = $RouteScope; RegistryHive = ($RouteScope -eq 'user' ? 'HKCU' : 'HKLM'); RegistryView = '64-bit'; KeyPath = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$ProductCode"; ProductCode = $ProductCode; IsVisible = $true; Values = $ValuesArp; RuntimeValues = @('InstallDate') })
    }
    # Registration is written last. Declarative custom writes can still add
    # SystemComponent or independent uninstall rows; built-in fields win only
    # for names registration.rs actually writes, never for visibility flags.
    $ExtraRoutes = [Collections.Generic.List[object]]::new()
    foreach ($Route in $Routes) {
      $CustomRows = @{}
      foreach ($Write in $M.registry_values) {
        if (-not (Test-TigerSetupResourceCondition -Resource $Write -Values $Values)) { continue }
        if ($Write.root -notin 0, 1, 2) { throw 'Unsupported TigerSetup registry root.' }
        if (($Write.root -eq 1 -and $Route.Scope -ne 'machine') -or ($Write.root -eq 2 -and $Route.Scope -ne 'user')) { throw 'TigerSetup registry hive conflicts with declared scope.' }
        $Key = $Write.root -eq 0 ? 'Software\' + $Write.key : $Write.key
        if ($Key -notmatch '^Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\([^\\]+)$') { continue }
        $Code = $Matches[1]
        if (-not $CustomRows.ContainsKey($Code)) { $CustomRows[$Code] = [ordered]@{} }
        $Value = Resolve-TigerSetupTemplate -Value $Write.data -Root $Locations[$Route.Scope] -Version $Package.version
        if ($Write.kind -eq 3) {
          $Dword = 0u
          if (-not [uint32]::TryParse($Value, [ref]$Dword)) { throw 'Invalid TigerSetup registry DWORD.' }
          $Value = $Dword
        }
        $CustomRows[$Code][$Write.name] = $Value
      }
      foreach ($Code in $CustomRows.Keys) {
        if ($Code -ieq $ProductCode) {
          foreach ($Key in $CustomRows[$Code].Keys) { if (-not $Route.Values.Contains($Key)) { $Route.Values[$Key] = $CustomRows[$Code][$Key] } }
        } else {
          $ExtraRoutes.Add([pscustomobject]@{ Scope = $Route.Scope; RegistryHive = $Route.RegistryHive; RegistryView = '64-bit'; KeyPath = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$Code"; ProductCode = $Code; IsVisible = [bool]$CustomRows[$Code]['DisplayName']; Values = $CustomRows[$Code]; RuntimeValues = @() })
        }
      }
    }
    foreach ($Route in $ExtraRoutes) { $Routes.Add($Route) }
    foreach ($Route in $Routes) { if ($Route.Values['SystemComponent'] -eq 1) { $Route.IsVisible = $false } }
    $VisibleArp = @($Routes | Where-Object IsVisible)
    $BuiltInVisible = @($VisibleArp | Where-Object ProductCode -IEQ $ProductCode).Count -gt 0
    $ActiveAssociations = @($M.file_associations | Where-Object { Test-TigerSetupResourceCondition -Resource $_ -Values $Values })
    $ActiveProtocols = @($M.url_protocols | Where-Object { Test-TigerSetupResourceCondition -Resource $_ -Values $Values })
    $Files = @($M.files | Where-Object { Test-TigerSetupResourceCondition -Resource $_ -Values $Values })
    $Switches = [ordered]@{ Silent = 'install --quiet'; SilentWithProgress = 'install --quiet'; Log = '--log "<LOGPATH>"'; InstallLocation = '--install-root "<INSTALLPATH>"' }
    if ($Scope) { $Switches.Custom = "--scope $Scope" }
    $IsInstaller = $M.role -eq 1
    $WritesArp = $IsInstaller -and $VisibleArp.Count -gt 0
    [pscustomobject][ordered]@{
      Path = $Context.Path; Family = 'TigerSetup'; InstallerType = 'exe'; FormatVersion = $Context.FormatVersion; FormatProfile = $Context.Profile.Id; MetadataSchema = $M.schema
      ProductName = $Package.name; ProductVersion = $Package.version; ProductCode = ($IsInstaller -and $BuiltInVisible ? $ProductCode : $null); UpgradeCode = $null
      DisplayName = $DisplayName; DisplayVersion = $DisplayVersion; Publisher = $Package.publisher
      Description = $Package.description; Copyright = $Package.copyright; License = $Package.license; LicenseText = $Package.license_text
      WebsiteUrl = $Package.website_url; SupportUrl = $Package.support_url; HelpUrl = $Package.help_url; FileVersion = $Package.file_version
      Scope = $Scope; SupportedScopes = $SupportedScopes; SupportsDualScope = $SupportedScopes.Count -eq 2; DefaultScope = $SupportedScopes[0]; DefaultScopeIsAuthoritative = $SupportedScopes.Count -eq 1
      ScopeSwitches = [pscustomobject]@{ User = '--scope user'; Machine = '--scope machine' }
      DefaultInstallLocation = ($Scope ? $Locations[$Scope] : $null); InstallLocations = $Locations
      Architecture = 'x64'; PackageArchitecture = 'x64'; MinimumOSVersion = "10.0.$($M.install.minimum_build ? $M.install.minimum_build : 17763).0"
      ElevationRequirement = ($Scope -ceq 'machine' ? 'elevatesSelf' : $null)
      WritesAppsAndFeaturesEntry = $WritesArp; AppsAndFeaturesProductCode = ($IsInstaller -and $BuiltInVisible ? $ProductCode : $null); AppsAndFeaturesInstallerType = 'exe'
      AppsAndFeaturesEntries = [object[]]@($(if ($IsInstaller) {
            $ArpSeen = [Collections.Generic.HashSet[Tuple[string, string, string, string]]]::new()
            foreach ($Row in $VisibleArp) {
              # A product key alone cannot deduplicate scope-dependent display data.
              # Tuple identity also avoids delimiter collisions in untrusted strings.
              $Identity = [Tuple]::Create([string]$Row.ProductCode, [string]$Row.Values['DisplayName'], [string]$Row.Values['DisplayVersion'], [string]$Row.Values['Publisher'])
              if (-not $ArpSeen.Add($Identity)) { continue }
              $Entry = [ordered]@{ ProductCode = $Row.ProductCode; InstallerType = 'exe' }
              foreach ($Field in @('DisplayName', 'DisplayVersion', 'Publisher')) { if ($Row.Values[$Field]) { $Entry[$Field] = $Row.Values[$Field] } }
              $Entry
            }
          }))
      ARPEntries = @($Routes); RegistryRoutes = @($Routes); RegistryView = '64-bit'
      Protocols = [string[]]@($ActiveProtocols | ForEach-Object { $_.scheme } | Sort-Object -Unique); FileExtensions = [string[]]@($ActiveAssociations | ForEach-Object { foreach ($Extension in $_.extensions) { $Extension.TrimStart('.') } } | Sort-Object -Unique)
      RegistryAssociationInfo = [pscustomobject]@{ FileAssociations = $ActiveAssociations; UrlProtocols = $ActiveProtocols }
      # Keep borrowed SharpCompress entry objects private. Returned catalog facts
      # must remain usable after the owning archive/file has been disposed.
      RegistryWrites = @($M.registry_values); PayloadCatalog = [object[]]@(foreach ($Entry in $Context.PayloadEntries) { [pscustomobject]@{ entry = $Entry.entry; offset = $Entry.offset; length = $Entry.length; crc32 = $Entry.crc32; sha256 = $Entry.sha256 } }); PayloadFiles = $Files; ExtractedFiles = @()
      DependencyInfo = [pscustomobject]@{ Dependencies = @($M.dependencies); EmbeddedPackages = @($M.dependencies | Where-Object { $_.acquisition -and $_.acquisition.source -eq 3 }) }
      ExecutedPayloads = @($M.actions); SystemEffects = [pscustomobject]@{ Shortcuts = @($M.shortcuts); PathEntries = @($M.path_entries); EnvironmentVariables = @($M.environment_variables); AppPaths = @($M.app_paths); ContextMenuVerbs = @($M.context_menu_verbs); FirewallRules = @($M.firewall_rules); Actions = @($M.actions); Quiescence = @($M.quiescence); Launch = $M.launch; RegistryValues = @($M.registry_values) }
      Metadata = $M; OptionValues = $Values; ExistingScopePolicy = $M.install.existing_scope; Role = ($IsInstaller ? 'Installer' : 'Uninstaller')
      InstallerSwitches = ($IsInstaller ? $Switches : [ordered]@{}); InstallModes = [string[]]@($(if ($IsInstaller) { 'interactive'; 'silent'; 'silentWithProgress' }))
      DocumentedReturnCodes = @(0, 1, 2, 3, 4, 5, 6, 7, 8, 3010); UpgradeBehavior = 'install'; CanExpand = $IsInstaller
      Diagnostics = [object[]]$Diagnostics.ToArray(); UnresolvedFields = [string[]]$Unresolved.ToArray()
      ParserVersionInfo = [pscustomobject]@{ Name = 'Dumplings TigerSetup parser'; Version = 3; BuilderVersion = $M.engine.tigersetup_version; Evidence = @('PE', "format $($Context.FormatVersion) footer CRC/layout", "schema $($M.schema) Protobuf", 'metadata SHA256', 'resource contracts') }
    }
  } finally { Close-TigerSetupContext -Context $Context }
}

function Test-TigerSetupInstaller {
  <#
  .SYNOPSIS
    Recognize structurally valid TigerSetup installer media, excluding generated uninstallers.
  .PARAMETER Path
    Candidate path. Nonmatching or malformed files return false without logging.
  #>
  [OutputType([bool])]
  param ([Parameter(Mandatory, Position = 0)][string]$Path)
  try {
    $Context = Get-TigerSetupContext -Path $Path
    try { return $Context.Metadata.role -eq 1 } finally { Close-TigerSetupContext -Context $Context }
  } catch { return $false }
}

function Expand-TigerSetupInstaller {
  <#
  .SYNOPSIS
    Extract verified installed files from TigerSetup's ZIP or solid Zstandard payload.
  .PARAMETER Path
    Source installer, resolved using PowerShell filesystem semantics.
  .PARAMETER DestinationPath
    Output root, resolved before managed access.
  .PARAMETER Name
    Optional wildcard selectors. Omitted selects all packaged application files.
  .PARAMETER RawEntries
    Include prerequisite/action payloads under _tigersetup, plus loader, engine and raw metadata.
  .PARAMETER IncludeUninstaller
    Reconstruct the state-directory uninstaller under _tigersetup/state/<scope>/uninstall.exe.
  .PARAMETER Scope
    Scope for uninstaller reconstruction. Required on dual-scope media when IncludeUninstaller is used.
  .PARAMETER CollisionAction
    Prompt only on an actual collision, error, skip, overwrite or rename. Internal callers use Rename.
  .PARAMETER MaximumBytes
    Maximum total decoded payload bytes, including unselected entries in the solid stream.
  .OUTPUTS
    FileInfo objects. Extracted content is never executed.
  #>
  [CmdletBinding()]
  param (
    [Parameter(Mandatory, Position = 0)][string]$Path,
    [Parameter(Mandatory)][string]$DestinationPath,
    [string[]]$Name,
    [switch]$RawEntries,
    [switch]$IncludeUninstaller,
    [ValidateSet('user', 'machine')][string]$Scope,
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Prompt',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumBytes = 17179869184
  )
  $Context = Get-TigerSetupContext -Path $Path
  try {
    if ($Context.Metadata.role -ne 1) { throw 'A generated TigerSetup uninstaller has no installed payload.' }
    if ($IncludeUninstaller) {
      $ScopeNumber = $Scope -eq 'user' ? 1 : 2
      if (-not $Scope -and $Context.Metadata.install.scopes.Count -eq 1) {
        $ScopeNumber = [int]$Context.Metadata.install.scopes[0]
        $Scope = $ScopeNumber -eq 1 ? 'user' : 'machine'
      }
      if (-not $Scope -or $ScopeNumber -notin $Context.Metadata.install.scopes) { throw 'Choose a supported explicit scope for TigerSetup uninstaller reconstruction.' }
    }
    $Destination = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
    $Jobs = [Collections.Generic.List[object]]::new()
    foreach ($File in $Context.Metadata.files) { $Jobs.Add([pscustomobject]@{ Path = $File.path; Entry = $Context.Catalog[$File.entry] }) }
    if ($RawEntries) {
      foreach ($Entry in $Context.PayloadEntries) {
        if ($Entry.entry.StartsWith('.tigersetup/')) { $Jobs.Add([pscustomobject]@{ Path = '_tigersetup/' + $Entry.entry.Substring(12); Entry = $Entry }) }
      }
    }
    # Validate all output paths before writing anything. Collision handling is
    # independent from duplicate catalog identities, which are rejected above.
    foreach ($Job in $Jobs) { $null = Resolve-SafeExtractionPath -DestinationPath $Destination -RelativePath $Job.Path }
    $Jobs = @($Jobs | Where-Object { Test-TigerSetupExtractionSelection -Path $_.Path -Name $Name })
    $Directories = @($Context.Metadata.directories | Where-Object { Test-TigerSetupExtractionSelection -Path $_.path -Name $Name })
    foreach ($Directory in $Directories) { $null = Resolve-SafeExtractionPath -DestinationPath $Destination -RelativePath $Directory.path }
    $OutputBytes = 0L
    foreach ($Job in $Jobs) {
      if ($Name -and -not @($Name | Where-Object { Test-ExtractionPattern -Path $Job.Path -Pattern $_ }).Count) { continue }
      if ($Job.Entry.length -gt $MaximumBytes - $OutputBytes) { throw 'TigerSetup selected output exceeds the total byte limit.' }
      $OutputBytes += [long]$Job.Entry.length
    }
    if ($RawEntries) {
      $RawItems = [Collections.Generic.List[object]]::new()
      if ($Context.Profile.Major -gt 1) { $RawItems.Add(@('_tigersetup/loader.exe', $Context.Blocks.Engine.Offset)) }
      $RawItems.Add(@('_tigersetup/engine.exe', $Context.Blocks.Engine.ExpandedSize))
      $RawItems.Add(@('_tigersetup/metadata.pb', $Context.RawMetadata.Length))
      foreach ($Item in $RawItems) {
        if ($Name -and -not @($Name | Where-Object { Test-ExtractionPattern -Path $Item[0] -Pattern $_ }).Count) { continue }
        if ($Item[1] -gt $MaximumBytes - $OutputBytes) { throw 'TigerSetup raw output exceeds the total byte limit.' }
        $OutputBytes += [long]$Item[1]
      }
    }
    if ($IncludeUninstaller -and (-not $Name -or @($Name | Where-Object { Test-ExtractionPattern -Path "_tigersetup/state/$Scope/uninstall.exe" -Pattern $_ }).Count)) {
      $UninstallerMetadata = [Dumplings.TigerSetup.MetadataReader]::UninstallerMetadata($Context.RawMetadata, $ScopeNumber)
      $UninstallerFrame = $Context.Blocks.Metadata.Codec -eq 'Zstd' ? [Dumplings.TigerSetup.MetadataReader]::StoredZstd($UninstallerMetadata) : $UninstallerMetadata
      $UninstallerBytes = $Context.Blocks.Engine.Offset + $Context.Blocks.Engine.CompressedSize + $UninstallerFrame.Length + $Context.Profile.FooterLength + ($Context.Profile.Major -eq 1 ? 22 : 0)
      if ($UninstallerBytes -gt $MaximumBytes - $OutputBytes) { throw 'TigerSetup reconstructed output exceeds the total byte limit.' }
    }
    $Results = [Collections.Generic.List[object]]::new()
    $Reserved = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $Staged = [Collections.Generic.List[object]]::new()
    # Stage on the destination volume so final publication is an atomic file move.
    # No existing destination file changes until all selected content is verified.
    $Parent = $Destination
    while (-not [IO.Directory]::Exists($Parent)) {
      if ([IO.File]::Exists($Parent)) { throw 'TigerSetup destination parent is a file.' }
      $Parent = [IO.Path]::GetDirectoryName($Parent)
      if (-not $Parent) { throw 'TigerSetup destination has no existing parent directory.' }
    }
    Assert-TigerSetupOutputPath -Path $Destination
    $Stage = Join-Path $Parent ('.tigersetup-stage-' + [guid]::NewGuid().ToString('N'))
    $null = [IO.Directory]::CreateDirectory($Stage)
    $Payload = $null
    try {
      if ($Jobs.Count -gt 0 -and $Context.Archive) {
        # Legacy ZIP has no metadata region hashes. Its footer authenticates the
        # entire stored archive and each central-directory CRC checks inflated bytes.
        if ($Context.Blocks.Payload.ExpandedSize -gt $MaximumBytes) { throw 'TigerSetup ZIP expansion exceeds the byte limit.' }
        $Context.ZipRange.Position = 0
        if ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Context.ZipRange)) -ine $Context.Blocks.Payload.Hash) { throw 'TigerSetup ZIP payload SHA256 mismatch.' }
        foreach ($Entry in $Context.PayloadEntries) {
          $EntryStream = Open-InstallerArchiveEntry -Entry $Entry.NativeEntry
          try {
            $DecodedEntry = New-InstallerSeekableStream -SourceStream $EntryStream -MaximumBytes ([Math]::Max(1, $Entry.length))
            try {
              [Dumplings.TigerSetup.MetadataReader]::VerifyEntry($DecodedEntry.Stream, $Entry.length, $Entry.crc32, $null)
              foreach ($Job in $Jobs) {
                if ($Job.Entry.entry -cne $Entry.entry) { continue }
                $Staged.Add((Write-TigerSetupStagedFile -Stage $Stage -RelativePath $Job.Path -Stream $DecodedEntry.Stream -Offset 0 -Length $Entry.length))
              }
            } finally { $DecodedEntry.Dispose() }
          } finally { $EntryStream.Dispose() }
        }
      } elseif ($Jobs.Count -gt 0 -and $Context.Blocks.Payload.ExpandedSize -gt 0) {
        $Payload = Read-TigerSetupBlock -Stream $Context.Stream -Block $Context.Blocks.Payload -MaximumBytes $MaximumBytes
        # Verify every region before exporting files. Large decoded streams spill
        # to an owned temporary file rather than becoming byte[]/Object[].
        foreach ($Entry in $Context.Metadata.payload) {
          $Range = New-BoundedReadStream -Stream $Payload.Stream -Offset $Entry.offset -Length $Entry.length -LeaveOpen
          try {
            [Dumplings.TigerSetup.MetadataReader]::VerifyEntry($Range, $Entry.length, $Entry.crc32, $Entry.sha256)
          } finally { $Range.Dispose() }
        }
        foreach ($Job in $Jobs) {
          $Staged.Add((Write-TigerSetupStagedFile -Stage $Stage -RelativePath $Job.Path -Stream $Payload.Stream -Offset $Job.Entry.offset -Length $Job.Entry.length))
        }
      } elseif ($Jobs.Count -gt 0) {
        # A zero-byte file still has a catalog identity and must be emitted.
        # Upstream represents the completely empty solid stream with no frame.
        $Empty = [IO.MemoryStream]::new([byte[]]::new(0), $false)
        try {
          foreach ($Entry in $Context.PayloadEntries) { [Dumplings.TigerSetup.MetadataReader]::VerifyEntry($Empty, 0, $Entry.crc32, $Entry.sha256) }
          foreach ($Job in $Jobs) { $Staged.Add((Write-TigerSetupStagedFile -Stage $Stage -RelativePath $Job.Path -Stream $Empty -Offset 0 -Length 0)) }
        } finally { $Empty.Dispose() }
      }
      if ($RawEntries) {
        $Engine = $null
        $MetadataStream = [IO.MemoryStream]::new($Context.RawMetadata, $false)
        try {
          foreach ($RawName in @('loader.exe', 'engine.exe', 'metadata.pb')) {
            $Relative = '_tigersetup/' + $RawName
            if (-not (Test-TigerSetupExtractionSelection -Path $Relative -Name $Name)) { continue }
            $Raw = switch ($RawName) {
              'loader.exe' { @($RawName, $Context.Stream, 0, $Context.Blocks.Engine.Offset) }
              'engine.exe' {
                $Engine = Read-TigerSetupEngine -Context $Context -MaximumBytes ([Math]::Min($MaximumBytes, 536870912))
                @($RawName, $Engine.Stream, 0, $Engine.Stream.Length)
              }
              'metadata.pb' { @($RawName, $MetadataStream, 0, $Context.RawMetadata.Length) }
            }
            if ($Raw[0] -ceq 'loader.exe' -and $Context.Profile.Major -eq 1) { continue }
            $Staged.Add((Write-TigerSetupStagedFile -Stage $Stage -RelativePath $Relative -Stream $Raw[1] -Offset $Raw[2] -Length $Raw[3]))
          }
        } finally { if ($Engine) { $Engine.Dispose() }; $MetadataStream.Dispose() }
      }
      if ($IncludeUninstaller) {
        $Relative = "_tigersetup/state/$Scope/uninstall.exe"
        if (-not $Name -or @($Name | Where-Object { Test-ExtractionPattern -Path $Relative -Pattern $_ }).Count) {
          $StagePath = Join-Path $Stage ([guid]::NewGuid().ToString('N'))
          $Output = [IO.File]::Create($StagePath)
          try { Write-TigerSetupUninstaller -Context $Context -Destination $Output -Scope $ScopeNumber -MaximumBytes $MaximumBytes } finally { $Output.Dispose() }
          $Staged.Add([pscustomobject]@{ Path = $StagePath; RelativePath = $Relative })
        }
      }
      # Resolve every collision before publishing any file. Error/cancellation
      # therefore cannot leave a partially overwritten destination set.
      $Publish = [Collections.Generic.List[object]]::new()
      foreach ($File in $Staged) {
        $Target = Resolve-InstallerExtractionTarget -DestinationPath $Destination -RelativePath $File.RelativePath -CollisionAction $CollisionAction -ReservedPath $Reserved
        if ($Target.ShouldWrite) { Assert-TigerSetupOutputPath -Path $Target.Path; $Publish.Add(@($File.Path, $Target.Path)) }
      }
      foreach ($Directory in $Directories) {
        $DirectoryPath = Resolve-SafeExtractionPath -DestinationPath $Destination -RelativePath $Directory.path
        Assert-TigerSetupOutputPath -Path $DirectoryPath
        $null = [IO.Directory]::CreateDirectory($DirectoryPath)
      }
      foreach ($File in $Publish) {
        Assert-TigerSetupOutputPath -Path $File[1]
        $null = [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($File[1]))
        [IO.File]::Move($File[0], $File[1], $true)
        $Results.Add((Get-Item -LiteralPath $File[1]))
      }
      return $Results.ToArray()
    } finally {
      if ($Payload) { $Payload.Dispose() }
      # Stage is an explicitly created GUID directory, never a computed payload
      # path. Verify it remains directly under its chosen parent before deleting.
      if ([IO.Path]::GetDirectoryName($Stage) -eq $Parent -and [IO.Directory]::Exists($Stage)) { [IO.Directory]::Delete($Stage, $true) }
    }
  } finally { Close-TigerSetupContext -Context $Context }
}

function Test-TigerSetupExtractionSelection {
  <#
  .SYNOPSIS
    Match an optional extraction selector without allocating pipeline arrays.
  .PARAMETER Path
    Relative catalog path.
  .PARAMETER Name
    Omitted means every path; otherwise wildcard selectors.
  #>
  param ([string]$Path, [string[]]$Name)
  if (-not $Name) { return $true }
  foreach ($Pattern in $Name) { if (Test-ExtractionPattern -Path $Path -Pattern $Pattern) { return $true } }
  return $false
}

function Assert-TigerSetupOutputPath {
  <#
  .SYNOPSIS
    Reject existing links/junctions before staging or publishing installer output.
  .PARAMETER Path
    Absolute prospective output path; existing ancestors must be ordinary items.
  #>
  param ([string]$Path)
  while ($Path) {
    $Item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if ($Item -and $Item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'TigerSetup extraction cannot traverse a reparse point.' }
    $Path = [IO.Path]::GetDirectoryName($Path)
  }
}

function Write-TigerSetupStagedFile {
  <#
  .SYNOPSIS
    Copy a validated borrowed stream range to an operation-owned staging file.
  .PARAMETER Stage
    GUID staging directory on the output volume, owned by the extractor.
  .PARAMETER RelativePath
    Final catalog path; no destination is modified here.
  .PARAMETER Stream
    Borrowed seekable decoded stream, left open.
  .PARAMETER Offset
    Absolute stream-relative byte offset.
  .PARAMETER Length
    Exact byte count; short reads throw and the outer finally removes staging.
  #>
  param ([string]$Stage, [string]$RelativePath, [IO.Stream]$Stream, [long]$Offset, [long]$Length)
  $Path = Join-Path $Stage ([guid]::NewGuid().ToString('N'))
  $Output = [IO.File]::Create($Path)
  try { $null = Copy-BinaryStreamRange -Source $Stream -Destination $Output -Offset $Offset -Length $Length } finally { $Output.Dispose() }
  return [pscustomobject]@{ Path = $Path; RelativePath = $RelativePath }
}

function Read-TigerSetupEngine {
  <#
  .SYNOPSIS
    Materialize and verify the engine using the selected generation's hash witness.
  .PARAMETER Context
    Borrowed parsed context. Format 1 has a PE engine rather than a separate loader.
  .PARAMETER MaximumBytes
    Expanded engine byte limit. Caller disposes the returned seekable context.
  #>
  param ([object]$Context, [long]$MaximumBytes = 536870912)
  $Engine = Read-TigerSetupBlock -Stream $Context.Stream -Block $Context.Blocks.Engine -MaximumBytes $MaximumBytes
  try {
    $Expected = $Context.Profile.EngineHashOffset -ge 0 ? [Convert]::ToHexString($Context.Footer, $Context.Profile.EngineHashOffset, 32) : ($Context.Metadata.engine.engine_block_sha256 ? $Context.Metadata.engine.engine_block_sha256 : $Context.Metadata.engine.engine_sha256)
    if ($Expected -and [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Engine.Stream)) -ine $Expected) { throw 'TigerSetup expanded engine SHA256 mismatch.' }
    return $Engine
  } catch { $Engine.Dispose(); throw }
}

function Write-TigerSetupUninstaller {
  <#
  .SYNOPSIS
    Compose a payload-free uninstaller using the source generation's own framing.
  .PARAMETER Context
    Borrowed validated installer context.
  .PARAMETER Destination
    Borrowed seekable output stream, initially empty.
  .PARAMETER Scope
    Metadata scope tag, 1 for user or 2 for machine.
  .PARAMETER MaximumBytes
    Output-byte bound; loader plus compressed engine and metadata must fit.
  #>
  param ([object]$Context, [IO.Stream]$Destination, [int]$Scope, [long]$MaximumBytes)
  $Raw = [Dumplings.TigerSetup.MetadataReader]::UninstallerMetadata($Context.RawMetadata, $Scope)
  $Compressed = $Context.Blocks.Metadata.Codec -eq 'Zstd' ? [Dumplings.TigerSetup.MetadataReader]::StoredZstd($Raw) : $Raw
  # Format 1 writes a valid empty ZIP, not an absent archive. Split generations
  # instead write a zero-length solid block before their metadata.
  $EmptyPayload = $Context.Profile.Major -eq 1 ? [byte[]]::new(22) : [byte[]]::new(0)
  if ($EmptyPayload.Length) { [BitConverter]::GetBytes(0x06054B50).CopyTo($EmptyPayload, 0) }
  $Offset = $Context.Blocks.Engine.Offset + $Context.Blocks.Engine.CompressedSize
  if ($Offset + $Compressed.Length + $EmptyPayload.Length + $Context.Profile.FooterLength -gt $MaximumBytes) { throw 'TigerSetup reconstructed uninstaller exceeds the byte limit.' }
  # Prove the engine before copying it into an executable-shaped output.
  $Engine = Read-TigerSetupEngine -Context $Context
  $Engine.Dispose()
  $null = Copy-BinaryStreamRange -Source $Context.Stream -Destination $Destination -Offset 0 -Length $Offset
  # A signed source's security directory points outside the copied loader. The
  # reconstructed file is unsigned; clear that directory and its PE checksum.
  $Layout = Get-PELayout -Stream $Context.Stream
  $Destination.Position = $Layout.PeOffset + 24 + 64
  $Destination.Write([byte[]]::new(4))
  $Destination.Position = $Layout.PeOffset + 24 + 112 + 4 * 8
  $Destination.Write([byte[]]::new(8))
  $Destination.Position = $Offset
  $MetadataOffset = $Context.Profile.Major -eq 1 ? $Offset : $Offset + $EmptyPayload.Length
  $PayloadOffset = $Context.Profile.Major -eq 1 ? $Offset + $Compressed.Length : $Offset
  foreach ($Name in $Context.Profile.Order) {
    if ($Name -eq 'Metadata') { $Destination.Write($Compressed) }
    elseif ($Name -eq 'Payload') { $Destination.Write($EmptyPayload) }
  }
  $Footer = [byte[]]$Context.Footer.Clone()
  foreach ($Definition in $Context.Profile.Blocks) {
    if ($Definition.Name -eq 'Engine') { continue }
    $IsMetadata = $Definition.Name -eq 'Metadata'
    $OffsetValue = $IsMetadata ? $MetadataOffset : $PayloadOffset
    $Data = $IsMetadata ? $Compressed : $EmptyPayload
    [BitConverter]::GetBytes([uint64]$OffsetValue).CopyTo($Footer, $Definition.OffsetField)
    [BitConverter]::GetBytes([uint64]$Data.Length).CopyTo($Footer, $Definition.LengthField)
    if ($Definition.ExpandedField -ge 0) { [BitConverter]::GetBytes([uint64]($IsMetadata ? $Raw.Length : 0)).CopyTo($Footer, $Definition.ExpandedField) }
    [Security.Cryptography.SHA256]::HashData($Data).CopyTo($Footer, $Definition.HashField)
  }
  [Security.Cryptography.SHA256]::HashData($Raw).CopyTo($Footer, $Context.Profile.MetadataHashOffset)
  [BitConverter]::GetBytes([Dumplings.InstallerInfrastructure.BinaryIO]::Crc32($Footer, 0, $Context.Profile.CrcOffset)).CopyTo($Footer, $Context.Profile.CrcOffset)
  $Destination.Write($Footer)
}

function Read-ProductVersionFromTigerSetup {
  <# .SYNOPSIS
    Read the packaged application version.
  .PARAMETER Path
    Source installer path.
  #>
  param ([Parameter(Mandatory, Position = 0)][string]$Path)
  (Get-TigerSetupInfo -Path $Path).ProductVersion
}
function Read-ProductNameFromTigerSetup {
  <# .SYNOPSIS
    Read the packaged application name.
  .PARAMETER Path
    Source installer path.
  #>
  param ([Parameter(Mandatory, Position = 0)][string]$Path)
  (Get-TigerSetupInfo -Path $Path).ProductName
}
function Read-PublisherFromTigerSetup {
  <# .SYNOPSIS
    Read the compiled publisher.
  .PARAMETER Path
    Source installer path.
  #>
  param ([Parameter(Mandatory, Position = 0)][string]$Path)
  (Get-TigerSetupInfo -Path $Path).Publisher
}
function Read-ProductCodeFromTigerSetup {
  <# .SYNOPSIS
    Read the compiled uninstall registry key identity.
  .PARAMETER Path
    Source installer path.
  #>
  param ([Parameter(Mandatory, Position = 0)][string]$Path)
  (Get-TigerSetupInfo -Path $Path).ProductCode
}
function Read-ScopeFromTigerSetup {
  <# .SYNOPSIS
    Read an unambiguous scope; dual-scope media returns no single scope.
  .PARAMETER Path
    Source installer path.
  #>
  param ([Parameter(Mandatory, Position = 0)][string]$Path)
  (Get-TigerSetupInfo -Path $Path).Scope
}
function Read-ProtocolsFromTigerSetup {
  <# .SYNOPSIS
    Read URL protocols enabled by fresh-install option defaults.
  .PARAMETER Path
    Source installer path.
  #>
  param ([Parameter(Mandatory, Position = 0)][string]$Path)
  (Get-TigerSetupInfo -Path $Path).Protocols
}
function Read-FileExtensionsFromTigerSetup {
  <# .SYNOPSIS
    Read file associations enabled by fresh-install option defaults.
  .PARAMETER Path
    Source installer path.
  #>
  param ([Parameter(Mandatory, Position = 0)][string]$Path)
  (Get-TigerSetupInfo -Path $Path).FileExtensions
}

Export-ModuleMember -Function Get-TigerSetupInfo, Test-TigerSetupInstaller, Expand-TigerSetupInstaller, Read-ProductVersionFromTigerSetup, Read-ProductNameFromTigerSetup, Read-PublisherFromTigerSetup, Read-ProductCodeFromTigerSetup, Read-ScopeFromTigerSetup, Read-ProtocolsFromTigerSetup, Read-FileExtensionsFromTigerSetup
