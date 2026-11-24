# SPDX-License-Identifier: Apache-2.0
# Internal DeployMaster implementation. See DeployMaster.psm1 for format sources and the binary layout.
# Pass parsed contexts explicitly and keep caller-owned streams local.

# DeployMaster modern implementation, imported locally by the public facade.

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:DeployMasterFormatCatalog = Import-PowerShellDataFile -LiteralPath (Join-Path $PSScriptRoot 'DeployMasterFormatCatalog.psd1')

if ([int]$Script:DeployMasterFormatCatalog.CatalogVersion -ne 1) { throw "Unsupported DeployMaster format catalog version '$($Script:DeployMasterFormatCatalog.CatalogVersion)'." }

$Script:DeployMasterHeaderProfiles = [Collections.Generic.List[object]]::new()

$Script:DeployMasterHeaderProfilesById = @{}

foreach ($CatalogProfile in $Script:DeployMasterFormatCatalog.HeaderProfiles) {
  $HeaderProfile = [pscustomobject]$CatalogProfile
  if ($HeaderProfile.HeaderSize -notin 66, 70, 74 -or $HeaderProfile.Shift -notin -8, -4, 0 -or
    $HeaderProfile.RegistryRoute -notin 'Opcode', 'LegacyDelimited' -or
    $HeaderProfile.AssociationRoute -notin 'Auto', 'LengthPrefixedUtf8', 'FormFeedDelimitedAnsi' -or
    $HeaderProfile.UninstallCommandRoute -notin 'QuotedExecutableAndLog', 'UnquotedExecutableQuotedLog') { throw "DeployMaster header profile '$($HeaderProfile.Id)' has an unsupported layout." }
  if ($Script:DeployMasterHeaderProfilesById.ContainsKey([string]$HeaderProfile.Id)) { throw "The DeployMaster format catalog contains duplicate profile '$($HeaderProfile.Id)'." }
  $Script:DeployMasterHeaderProfiles.Add($HeaderProfile)
  $Script:DeployMasterHeaderProfilesById[[string]$HeaderProfile.Id] = $HeaderProfile
}

if ($Script:DeployMasterHeaderProfiles.Count -eq 0) { throw 'The DeployMaster format catalog contains no header profiles.' }

foreach ($ClassicRoute in $Script:DeployMasterFormatCatalog.ClassicRoutes) {
  if ([string]$ClassicRoute.PackageMagic -notmatch '^.{4}$' -or $ClassicRoute.RuntimeCompression -ne 'BZip2' -or $ClassicRoute.PayloadCompression -ne 'Zlib' -or
    $ClassicRoute.RegistryRoute -ne 'ClassicNullTerminatedAnsi' -or $ClassicRoute.AssociationRoute -ne 'ClassicFormFeedAnsi') {
    throw "DeployMaster classic route '$($ClassicRoute.Id)' has an unsupported layout."
  }
}

function Get-DeployMasterCatalogVersion {
  <#
  .SYNOPSIS
    Return the version of the validated family catalog for parser provenance.
  .OUTPUTS
    Catalog version integer. The mutable descriptor tables stay private to this module.
  #>
  [OutputType([int])]
  param ()
  return [int]$Script:DeployMasterFormatCatalog.CatalogVersion
}

function Get-DeployMasterClassicRoute {
  <#
  .SYNOPSIS
    Identify a structurally distinct classic DeployMaster package route.
  .PARAMETER Stream
    Caller-owned seekable installer stream. Its position is restored by the binary and PE helpers.
  .PARAMETER RuntimeIdentity
    Trusted PE version-resource identity used with the overlay magic to reject unrelated BZip2 SFX files.
  .OUTPUTS
    The matching classic-route descriptor, or no output when the artifact is not recognized.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][string]$RuntimeIdentity
  )

  if ($RuntimeIdentity -notmatch '(?im)^DeployMaster$' -or $RuntimeIdentity -notmatch '(?i)(?:built with|JGsoft\s+)DeployMaster') { return }

  $OverlayOffset = try { Get-PEOverlayOffset -Stream $Stream } catch { return }
  if ($OverlayOffset + 4 -gt $Stream.Length) { return }
  $Magic = [Text.Encoding]::ASCII.GetString((Read-BinaryBytes -Stream $Stream -Offset $OverlayOffset -Count 4))

  foreach ($RouteData in $Script:DeployMasterFormatCatalog.ClassicRoutes) {
    if ($Magic -ceq [string]$RouteData.PackageMagic) { return [pscustomobject]$RouteData }
  }
}

function ConvertTo-DeployMasterEnvironmentPath {
  <#
  .SYNOPSIS
    Convert DeployMaster-private root variables to standard Windows environment variables.
  .PARAMETER Value
    Compiled DeployMaster path. Unknown and installer-relative variables are preserved verbatim.
  .OUTPUTS
    A path suitable for installed-state comparison and WinGet manifest projection.
  #>
  [OutputType([string])]
  param ([AllowNull()][string]$Value)

  if ($null -eq $Value) { return $null }
  $Result = $Value
  foreach ($Replacement in ([ordered]@{
        '%LOCALAPPDATAROOT%'  = '%LOCALAPPDATA%'
        '%APPDATAROOT%'       = '%APPDATA%'
        '%COMMONAPPDATAROOT%' = '%ProgramData%'
      }).GetEnumerator()) {
    $Result = $Result.Replace($Replacement.Key, $Replacement.Value, [StringComparison]::OrdinalIgnoreCase)
  }
  return $Result
}

function Get-DeployMasterScopeInfo {
  <#
  .SYNOPSIS
    Convert the DeployMaster package scope byte to WinGet scope evidence
  .NOTES
    Controlled current-user, all-users, and dual-scope builds encode 0, 1,
    and 2 respectively at the normalized package-header scope offset.
  .PARAMETER Value
    Format-specific field or value interpreted according to the current record/version.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][ValidateRange(0, 255)][int]$Value)

  switch ($Value) {
    0 { [pscustomobject]@{ Scope = 'user'; DefaultScope = 'user'; SupportedScopes = @('user'); SupportsDualScope = $false } }
    1 { [pscustomobject]@{ Scope = 'machine'; DefaultScope = 'machine'; SupportedScopes = @('machine'); SupportsDualScope = $false } }
    2 { [pscustomobject]@{ Scope = $null; DefaultScope = $null; SupportedScopes = @('user', 'machine'); SupportsDualScope = $true } }
    default { [pscustomobject]@{ Scope = $null; DefaultScope = $null; SupportedScopes = @(); SupportsDualScope = $false } }
  }
}

function Get-DeployMasterPackageLocator {
  <#
  .SYNOPSIS
    Read and validate the fixed DeployMaster package locator at file offset 0x80
  .PARAMETER Stream
    Caller-owned binary stream. Sequential readers may advance its byte position; helpers do not dispose it.
  .PARAMETER MaximumIntegrityBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [ValidateRange(74, [long]::MaxValue)][long]$MaximumIntegrityBytes = 1073741824
  )

  # The locator is a fixed absolute structure in the PE stub. Validate all declared ranges and the
  # logical package size before hashing or following the package pointer. Signed media appends an
  # aligned Authenticode certificate table after the size recorded by DeployMaster.
  if (-not $Stream.CanSeek -or $Stream.Length -lt 0x98) { throw 'The file is too small for a DeployMaster package locator.' }
  $PackageOffset = [long](Read-BinaryInteger -Stream $Stream -Offset 0x80 -Size 4)
  $IntegrityLength = [long](Read-BinaryInteger -Stream $Stream -Offset 0x84 -Size 4)
  $ExpectedCrc32 = [uint32](Read-BinaryInteger -Stream $Stream -Offset 0x88 -Size 4)
  $ExpectedFileSize = [uint64](Read-BinaryInteger -Stream $Stream -Offset 0x8C -Size 8)
  $Reserved = [uint32](Read-BinaryInteger -Stream $Stream -Offset 0x94 -Size 4)

  if ($PackageOffset -lt 512 -or $IntegrityLength -lt 70 -or $IntegrityLength -gt $MaximumIntegrityBytes) {
    throw 'The DeployMaster package locator contains invalid range values.'
  }
  if ($PackageOffset + $IntegrityLength -gt $Stream.Length) { throw 'The DeployMaster integrity region is truncated.' }
  $PhysicalFileSize = [uint64]$Stream.Length
  $CertificateOffset = $null
  $CertificateSize = 0L
  $HasSignedEnvelope = $false
  if ($ExpectedFileSize -ne $PhysicalFileSize) {
    $Certificate = try { (Get-PELayout -Stream $Stream).DataDirectories['Certificate'] } catch { $null }
    if ($Certificate -and [long]$Certificate.Offset -ge 0 -and [long]$Certificate.Size -gt 0) {
      $AlignmentRemainder = $ExpectedFileSize % 8
      $AlignedExpectedFileSize = $ExpectedFileSize + ($AlignmentRemainder ? (8 - $AlignmentRemainder) : 0)
      $CertificateOffset = [long]$Certificate.Offset
      $CertificateSize = [long]$Certificate.Size
      if ([uint64]$CertificateOffset -eq $AlignedExpectedFileSize -and
        [uint64]($CertificateOffset + $CertificateSize) -eq $PhysicalFileSize) {
        $PaddingLength = [int]($AlignedExpectedFileSize - $ExpectedFileSize)
        $Padding = $PaddingLength ? (Read-BinaryBytes -Stream $Stream -Offset ([long]$ExpectedFileSize) -Count $PaddingLength) : [byte[]]::new(0)
        $HasSignedEnvelope = -not ($Padding | Where-Object { $_ -ne 0 } | Select-Object -First 1)
      }
    }
    if (-not $HasSignedEnvelope) { throw 'The DeployMaster package locator file-size check failed.' }
  }

  # CRC32 authenticates only the declared package-control region, not trailing file payloads.
  $IntegrityStream = New-BoundedReadStream -Stream $Stream -Offset $PackageOffset -Length $IntegrityLength -LeaveOpen
  try { $ActualCrc32 = [uint32](Get-BinaryCrc32 -Stream $IntegrityStream -MaximumBytes $IntegrityLength) }
  finally { $IntegrityStream.Dispose() }
  if ($ActualCrc32 -ne $ExpectedCrc32) { throw 'The DeployMaster package integrity CRC32 check failed.' }

  [pscustomobject]@{
    LocatorOffset     = 0x80L
    PackageOffset     = $PackageOffset
    IntegrityLength   = $IntegrityLength
    PackageDataOffset = $PackageOffset + $IntegrityLength
    ExpectedCrc32     = $ExpectedCrc32
    ActualCrc32       = $ActualCrc32
    ExpectedFileSize  = $ExpectedFileSize
    PhysicalFileSize  = $PhysicalFileSize
    HasSignedEnvelope = $HasSignedEnvelope
    CertificateOffset = $CertificateOffset
    CertificateSize   = $CertificateSize
    Reserved          = $Reserved
  }
}

function Get-DeployMasterPackageHeader {
  <#
  .SYNOPSIS
    Normalize catalog-backed DeployMaster package-control layouts
  .DESCRIPTION
    DeployMaster 6.0-6.1, 6.5-7.1, and 7.2+ samples use 66-, 70-, and 74-byte
    control headers. Candidate core ranges select the valid structural profile;
    the observed release ranges in the catalog are evidence, not dispatch keys.
  .PARAMETER Stream
    Caller-owned binary stream. Sequential readers may advance its byte position; helpers do not dispose it.
  .PARAMETER Locator
    Current structured format node or record being interpreted.
  .PARAMETER MaximumCoreBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][psobject]$Locator,
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumCoreBytes = 1073741824
  )

  $Properties = Read-BinaryBytes -Stream $Stream -Offset $Locator.PackageOffset -Count 5
  $DictionarySize = [uint32][BitConverter]::ToUInt32($Properties, 1)
  if ($Properties[0] -gt 224 -or $DictionarySize -lt 65536 -or $DictionarySize -gt 1073741824) {
    throw 'The DeployMaster package has invalid LZMA properties.'
  }

  # Probe every cataloged layout through its range invariants. The installer PE version fields
  # contain the packaged application's version, so they cannot safely select a runtime profile.
  $Candidates = [Collections.Generic.List[object]]::new()
  foreach ($Layout in $Script:DeployMasterHeaderProfiles) {
    $PrimaryOffset = [long](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x16 + $Layout.Shift) -Size 4)
    $PrimaryCompressedSize = [long](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x1A + $Layout.Shift) -Size 4)
    $PrimaryUncompressedSize = [long](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x1E + $Layout.Shift) -Size 4)
    $SecondaryOffsetValue = [uint32](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x22 + $Layout.Shift) -Size 4)
    $SecondaryOffset = [long]$SecondaryOffsetValue
    $SecondaryCompressedSize = [long](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x26 + $Layout.Shift) -Size 4)
    $SecondaryUncompressedSize = [long](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x2A + $Layout.Shift) -Size 4)
    $LanguageOffset = [long](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x2E + $Layout.Shift) -Size 4)
    $IntegrityEnd = $Locator.PackageOffset + $Locator.IntegrityLength
    $CoreEntries = [Collections.Generic.List[object]]::new()
    # Core offsets are absolute and must remain within the CRC-protected integrity region.
    if ($PrimaryOffset -ne 0) {
      if ($PrimaryOffset -lt $Locator.PackageOffset + $Layout.HeaderSize -or $PrimaryCompressedSize -le 0 -or
        $PrimaryUncompressedSize -le 0 -or $PrimaryUncompressedSize -gt $MaximumCoreBytes -or
        $PrimaryOffset + $PrimaryCompressedSize -gt $IntegrityEnd) { continue }
      $CoreEntries.Add([pscustomobject]@{ Architecture = 'x86'; Offset = $PrimaryOffset; CompressedSize = $PrimaryCompressedSize; UncompressedSize = $PrimaryUncompressedSize })
    } elseif ($PrimaryCompressedSize -ne 0 -or $PrimaryUncompressedSize -ne 0) { continue }
    if ($SecondaryOffsetValue -notin 0, [uint32]::MaxValue) {
      if ($SecondaryOffset -lt $Locator.PackageOffset + $Layout.HeaderSize -or $SecondaryCompressedSize -le 0 -or
        $SecondaryUncompressedSize -le 0 -or $SecondaryUncompressedSize -gt $MaximumCoreBytes -or
        $SecondaryOffset + $SecondaryCompressedSize -gt $IntegrityEnd) { continue }
      $CoreEntries.Add([pscustomobject]@{ Architecture = 'x64'; Offset = $SecondaryOffset; CompressedSize = $SecondaryCompressedSize; UncompressedSize = $SecondaryUncompressedSize })
    } elseif ($SecondaryCompressedSize -ne 0 -or $SecondaryUncompressedSize -ne 0) { continue }
    if ($CoreEntries.Count -eq 0) { continue }
    $LastCoreEnd = ($CoreEntries | ForEach-Object { $_.Offset + $_.CompressedSize } | Measure-Object -Maximum).Maximum
    if ($LanguageOffset -lt $LastCoreEnd -or $LanguageOffset + 8 -gt $IntegrityEnd) { continue }

    $ScopeValue = [int](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x15 + $Layout.Shift) -Size 1)
    if ($ScopeValue -gt 2) { continue }
    $Candidates.Add([pscustomobject]@{
        Profile              = $Layout
        Layout               = $Layout.Layout
        FormatVersion        = $Layout.Id
        HeaderSize           = $Layout.HeaderSize
        ScopeValue           = $ScopeValue
        CoreEntries          = $CoreEntries.ToArray()
        SecondaryOffsetValue = $SecondaryOffsetValue
        LanguageBlockOffset  = $LanguageOffset
      })
  }
  if ($Candidates.Count -ne 1) { throw 'The DeployMaster package-control layout could not be normalized unambiguously.' }

  $Candidate = $Candidates[0]
  $ScopeInfo = Get-DeployMasterScopeInfo -Value $Candidate.ScopeValue
  # Current media compiles either expiration mode into one final calendar date. The adjacent
  # UTF-16 message is stored directly between the runtime core and the normal language text.
  # Both source modes converge here, so do not infer whether the project used a
  # fixed date or a number of days after the release date.
  $LayoutShift = [int]$Candidate.Profile.Shift
  $ExpirationYear = [uint16](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x32 + $LayoutShift) -Size 2)
  $ExpirationMonth = [uint16](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x34 + $LayoutShift) -Size 2)
  $ExpirationDay = [uint16](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x36 + $LayoutShift) -Size 2)
  $ExpirationMessageOffset = [long](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x38 + $LayoutShift) -Size 4)
  $ExpirationMessageCharacterCount = [uint16](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x3C + $LayoutShift) -Size 2)
  $ExpirationDate = $null
  $ExpirationMessage = $null
  if ($ExpirationYear -or $ExpirationMonth -or $ExpirationDay -or $ExpirationMessageOffset -or $ExpirationMessageCharacterCount) {
    try { $ExpirationDate = [datetime]::new($ExpirationYear, $ExpirationMonth, $ExpirationDay) }
    catch { throw 'The DeployMaster package contains an invalid compiled expiration date.' }

    $LastCoreEnd = [long](($Candidate.CoreEntries | ForEach-Object { $_.Offset + $_.CompressedSize } | Measure-Object -Maximum).Maximum)
    $ExpirationMessageByteCount = [long]$ExpirationMessageCharacterCount * 2
    if ($ExpirationMessageCharacterCount -eq 0 -or $ExpirationMessageOffset -lt $LastCoreEnd -or
      $ExpirationMessageOffset + $ExpirationMessageByteCount -gt $Candidate.LanguageBlockOffset) {
      throw 'The DeployMaster expiration message is outside the bounded pre-language range.'
    }
    $ExpirationMessageBytes = Read-BinaryBytes -Stream $Stream -Offset $ExpirationMessageOffset -Count ([int]$ExpirationMessageByteCount)
    try { $ExpirationMessage = [Text.UnicodeEncoding]::new($false, $false, $true).GetString($ExpirationMessageBytes) }
    catch { throw 'The DeployMaster expiration message is not valid UTF-16LE text.' }
  }
  # The first eight control bytes are a platform bitset. Current builder differentials prove the
  # modern Windows bits below; legacy/unused bits remain available through PlatformFlags.
  $PlatformFlags = [uint64](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 5) -Size 8)
  $SupportedWindowsVersions = [Collections.Generic.List[string]]::new()
  foreach ($Platform in @(
      [pscustomobject]@{ Mask = [uint64]0x0000000000000080; Name = 'Windows7' },
      [pscustomobject]@{ Mask = [uint64]0x0000000000000100; Name = 'Windows8' },
      [pscustomobject]@{ Mask = [uint64]0x0000000000000200; Name = 'Windows8.1' },
      [pscustomobject]@{ Mask = [uint64]0x0000000000000400; Name = 'Windows10' },
      [pscustomobject]@{ Mask = [uint64]0x0000000000000800; Name = 'Windows11' }
    )) {
    if ($PlatformFlags -band $Platform.Mask) { $SupportedWindowsVersions.Add($Platform.Name) }
  }
  $PrimaryCore = @($Candidate.CoreEntries | Where-Object Architecture -EQ 'x86' | Select-Object -First 1)
  $SecondaryCore = @($Candidate.CoreEntries | Where-Object Architecture -EQ 'x64' | Select-Object -First 1)
  # A missing x64 core and the x86-only sentinel distinguish OS support from the architecture of
  # the installer stub itself.
  $ApplicationArchitectureMode = if ($PrimaryCore.Count -and $SecondaryCore.Count) {
    'x86AndX64Application'
  } elseif ($SecondaryCore.Count) {
    'x64Application'
  } elseif ($Candidate.SecondaryOffsetValue -eq [uint32]::MaxValue) {
    'x86ApplicationForX86WindowsOnly'
  } else {
    'x86ApplicationForX86AndX64Windows'
  }
  $OperatingSystemArchitectures = switch ($ApplicationArchitectureMode) {
    'x86ApplicationForX86WindowsOnly' { @('x86') }
    'x64Application' { @('x64') }
    default { @('x86', 'x64') }
  }
  # Windows release bounds were added in separate format revisions. Do not read absent fields:
  # the same bytes hold scope and core pointers in older profiles.
  $MinimumWindows10VersionCode = $null
  $MaximumWindows10VersionCode = $null
  if ($Candidate.Profile.HasWindows10Bounds) {
    $MinimumWindows10VersionCode = [uint16](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x0D) -Size 2)
    $MaximumWindows10VersionCode = [uint16](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x0F) -Size 2)
  }
  $MinimumWindows11VersionCode = $null
  $MaximumWindows11VersionCode = $null
  if ($Candidate.Profile.HasWindows11Bounds) {
    $MinimumWindows11VersionCode = [uint16](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x11) -Size 2)
    $MaximumWindows11VersionCode = [uint16](Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x13) -Size 2)
  }
  $FirstCore = $Candidate.CoreEntries | Select-Object -First 1
  [pscustomobject]@{
    Layout                                = $Candidate.Profile.Layout
    FormatProfile                         = $Candidate.Profile.Id
    FormatVersion                         = $Candidate.FormatVersion
    ObservedRuntimeRange                  = $Candidate.Profile.ObservedRuntimeRange
    ProfileEvidence                       = $Candidate.Profile.Evidence
    FileTableKind                         = $Candidate.Profile.FileTableKind
    RegistryRoute                         = $Candidate.Profile.RegistryRoute
    AssociationRoute                      = $Candidate.Profile.AssociationRoute
    HasPackageSettings                    = [bool]$Candidate.Profile.HasPackageSettings
    UninstallCommandRoute                 = [string]$Candidate.Profile.UninstallCommandRoute
    HasInstallForAllUsersSwitch           = [bool]$Candidate.Profile.HasInstallForAllUsersSwitch
    HeaderSize                            = $Candidate.HeaderSize
    LzmaProperties                        = $Properties
    LzmaPropertyByte                      = [byte]$Properties[0]
    DictionarySize                        = $DictionarySize
    PlatformFlags                         = $PlatformFlags
    SupportedWindowsVersions              = $SupportedWindowsVersions.ToArray()
    SupportsFutureWindowsVersions         = [bool]((Read-BinaryInteger -Stream $Stream -Offset ($Locator.PackageOffset + 0x0C) -Size 1) -band 0x80)
    MinimumWindows10VersionCode           = $MinimumWindows10VersionCode
    MaximumWindows10VersionCode           = $MaximumWindows10VersionCode
    MinimumWindows11VersionCode           = $MinimumWindows11VersionCode
    MaximumWindows11VersionCode           = $MaximumWindows11VersionCode
    ExpirationPolicy                      = [pscustomobject]@{
      IsTimeLimited         = $null -ne $ExpirationDate
      ExpirationDate        = $ExpirationDate
      Message               = $ExpirationMessage
      MessageOffset         = $ExpirationMessageOffset
      MessageCharacterCount = $ExpirationMessageCharacterCount
      SourceMode            = if ($ExpirationDate) { 'CompiledFinalDate' } else { $null }
    }
    ScopeValue                            = $Candidate.ScopeValue
    Scope                                 = $ScopeInfo.Scope
    DefaultScope                          = $ScopeInfo.DefaultScope
    SupportedScopes                       = $ScopeInfo.SupportedScopes
    SupportsDualScope                     = $ScopeInfo.SupportsDualScope
    CoreOffset                            = $FirstCore.Offset
    CoreCompressedSize                    = $FirstCore.CompressedSize
    CoreUncompressedSize                  = $FirstCore.UncompressedSize
    CoreEntries                           = $Candidate.CoreEntries
    ApplicationArchitectureMode           = $ApplicationArchitectureMode
    ApplicationArchitectures              = @($Candidate.CoreEntries | Select-Object -ExpandProperty Architecture)
    SupportedOperatingSystemArchitectures = $OperatingSystemArchitectures
    LanguageBlockOffset                   = $Candidate.LanguageBlockOffset
  }
}

function Test-DeployMasterRuntimeSwitch {
  <#
  .SYNOPSIS
    Confirm that a generated DeployMaster runtime recognizes a command-line switch.
  .DESCRIPTION
    Version-dependent setup switches are compiled into the compressed runtime core rather than
    the package metadata. This helper expands one bounded core and searches its UTF-16 string
    table, avoiding guesses from application-owned PE version resources.
  .PARAMETER Stream
    Caller-owned installer stream. The function does not dispose it.
  .PARAMETER Header
    Validated package header containing raw-LZMA properties and bounded runtime-core ranges.
  .PARAMETER CommandLineSwitch
    One or more literal slash-prefixed switches to locate in the runtime string table. Results are
    returned in the same order, allowing one bounded runtime expansion to serve several probes.
  .PARAMETER MaximumCoreBytes
    Maximum uncompressed runtime-core size accepted for this optional feature probe.
  #>
  [OutputType([bool[]])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][psobject]$Header,
    [Parameter(Mandatory)][ValidatePattern('^/[A-Za-z0-9]+$')][string[]]$CommandLineSwitch,
    [ValidateRange(1, 268435456)][long]$MaximumCoreBytes = 134217728
  )

  $Core = $Header.CoreEntries | Sort-Object { $_.Architecture -ne 'x86' } | Select-Object -First 1
  if (-not $Core -or $Core.UncompressedSize -gt $MaximumCoreBytes) { throw 'The DeployMaster runtime core is unavailable or exceeds the switch-probe limit.' }
  $InputStream = New-BoundedReadStream -Stream $Stream -Offset $Core.Offset -Length $Core.CompressedSize -LeaveOpen
  $OutputStream = [IO.MemoryStream]::new([int][Math]::Min($Core.UncompressedSize, [int]::MaxValue))
  try {
    $null = Expand-InstallerCompressedStream -Algorithm Lzma -Stream $InputStream -Destination $OutputStream -MaximumBytes $MaximumCoreBytes -Properties $Header.LzmaProperties -CompressedSize $Core.CompressedSize -UncompressedSize $Core.UncompressedSize
    $Results = [Collections.Generic.List[bool]]::new($CommandLineSwitch.Count)
    foreach ($RequestedSwitch in $CommandLineSwitch) {
      $Pattern = [Text.Encoding]::Unicode.GetBytes($RequestedSwitch)
      $Results.Add(@(Find-BinaryPattern -Stream $OutputStream -Pattern $Pattern -Maximum 1).Count -eq 1)
    }
    return $Results.ToArray()
  } finally {
    $InputStream.Dispose()
    $OutputStream.Dispose()
  }
}

function Read-DeployMasterDataBlock {
  <#
  .SYNOPSIS
    Decode one DeployMaster size-prefixed data block.
  .DESCRIPTION
    DeployMaster uses a signed 32-bit size discriminator. Zero represents an empty block, a
    negative value is the stored byte count, and a positive value is the uncompressed size of a
    raw-LZMA stream whose compressed size follows as another signed 32-bit integer.
  .PARAMETER Stream
    Caller-owned binary stream. Sequential readers may advance its byte position; helpers do not dispose it.
  .PARAMETER Offset
    Byte offset in the coordinate system named by this function: absolute file, PE/resource, overlay, or record relative.
  .PARAMETER Properties
    Format-specific field or value interpreted according to the current record/version.
  .PARAMETER Limit
    Absolute end offset of the integrity/package region. The complete size-prefixed block must end at or before this boundary.
  .PARAMETER MaximumBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][long]$Offset,
    [Parameter(Mandatory)][byte[]]$Properties,
    [Parameter(Mandatory)][long]$Limit,
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumBytes = 16777216
  )

  if ($Offset -lt 0 -or $Offset + 4 -gt $Limit) { throw 'The DeployMaster data-block header is outside the package bounds.' }
  $Size = [long](Read-BinaryInteger -Stream $Stream -Offset $Offset -Size 4 -Signed)
  if ($Size -eq [int]::MinValue) { throw 'The DeployMaster stored-block size cannot be negated safely.' }

  if ($Size -eq 0) {
    return [pscustomobject]@{
      Offset = $Offset; DataOffset = $Offset + 4; HeaderSize = 4; CompressedSize = 0L
      UncompressedSize = 0L; EndOffset = $Offset + 4; Compression = 'Empty'; Bytes = [byte[]]::new(0)
    }
  }

  if ($Size -lt 0) {
    $StoredSize = - $Size
    if ($StoredSize -gt $MaximumBytes -or $Offset + 4 + $StoredSize -gt $Limit -or $StoredSize -gt [int]::MaxValue) {
      throw 'The DeployMaster stored block contains invalid size values.'
    }
    return [pscustomobject]@{
      Offset = $Offset; DataOffset = $Offset + 4; HeaderSize = 4; CompressedSize = $StoredSize
      UncompressedSize = $StoredSize; EndOffset = $Offset + 4 + $StoredSize; Compression = 'Store'
      Bytes = Read-BinaryBytes -Stream $Stream -Offset ($Offset + 4) -Count ([int]$StoredSize)
    }
  }

  if ($Offset + 8 -gt $Limit) { throw 'The DeployMaster LZMA-block header is truncated.' }
  $UncompressedSize = $Size
  $CompressedSize = [long](Read-BinaryInteger -Stream $Stream -Offset ($Offset + 4) -Size 4 -Signed)
  if ($UncompressedSize -gt $MaximumBytes -or $CompressedSize -le 0 -or $Offset + 8 + $CompressedSize -gt $Limit) {
    throw 'The DeployMaster LZMA block contains invalid size values.'
  }

  # Give the decoder only the declared compressed bytes and require its output to match the record header exactly.
  $InputStream = New-BoundedReadStream -Stream $Stream -Offset ($Offset + 8) -Length $CompressedSize -LeaveOpen
  $OutputStream = [IO.MemoryStream]::new()
  try {
    $null = Expand-InstallerCompressedStream -Algorithm Lzma -Stream $InputStream -Destination $OutputStream -MaximumBytes $MaximumBytes -Properties $Properties -CompressedSize $CompressedSize -UncompressedSize $UncompressedSize
    $Bytes = $OutputStream.ToArray()
  } finally {
    $InputStream.Dispose()
    $OutputStream.Dispose()
  }

  [pscustomobject]@{
    Offset           = $Offset
    DataOffset       = $Offset + 8
    HeaderSize       = 8
    CompressedSize   = $CompressedSize
    UncompressedSize = $UncompressedSize
    EndOffset        = $Offset + 8 + $CompressedSize
    Compression      = 'Lzma'
    Bytes            = $Bytes
  }
}

function ConvertFrom-DeployMasterIdentity {
  <#
  .SYNOPSIS
    Convert the structured DeployMaster identity block to package metadata
  .PARAMETER Bytes
    Bounded format record or payload bytes interpreted by this function; the input array is not modified.
  .PARAMETER ScopeValue
    Scope or elevation evidence used to classify user, machine, or conditional installation.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][int]$ScopeValue
  )

  # Form-feed delimiters define the identity schema. Strict UTF-8 prevents replacement characters
  # from silently changing paths or ARP values.
  $Utf8 = [Text.UTF8Encoding]::new($false, $true)
  try { $Fields = $Utf8.GetString($Bytes).Split([char]12) }
  catch { throw 'The DeployMaster identity block is not valid UTF-8.' }
  if ($Fields.Count -lt 19) { throw 'The DeployMaster identity block is incomplete.' }

  $MachineLocationField = [string]$Fields[11]
  $LocationMarker = if ($MachineLocationField.Length) { [int][char]$MachineLocationField[0] } else { 0 }
  # The first identity-path byte carries the effective registry/install route. Marker 6 is the
  # current-user route with the builder's independent "require admin rights" option enabled; its
  # package-control scope byte is 1, so the identity marker is needed to avoid calling it machine.
  $IdentityScope = switch ($LocationMarker) {
    1 { [pscustomobject]@{ Scope = 'machine'; DefaultScope = 'machine'; SupportedScopes = @('machine'); SupportsDualScope = $false; RequiresAdministrativeRights = $true; RegistryRoot = 'HKLM'; EffectiveScopeValue = 1 } }
    2 { [pscustomobject]@{ Scope = 'user'; DefaultScope = 'user'; SupportedScopes = @('user'); SupportsDualScope = $false; RequiresAdministrativeRights = $false; RegistryRoot = 'HKCU'; EffectiveScopeValue = 0 } }
    3 { [pscustomobject]@{ Scope = $null; DefaultScope = $null; SupportedScopes = @('user', 'machine'); SupportsDualScope = $true; RequiresAdministrativeRights = $null; RegistryRoot = 'SHCTX'; EffectiveScopeValue = 2 } }
    6 { [pscustomobject]@{ Scope = 'user'; DefaultScope = 'user'; SupportedScopes = @('user'); SupportsDualScope = $false; RequiresAdministrativeRights = $true; RegistryRoot = 'HKCU'; EffectiveScopeValue = 0 } }
    default { $null }
  }
  $RawMachineInstallLocation = if ($IdentityScope) { $MachineLocationField.Substring(1) } else { $MachineLocationField.TrimStart([char]0) }
  $RawUserInstallLocation = [string]$Fields[12]
  $RawCommonFilesLocation = [string]$Fields[13]
  $RawCommonPublisherLocation = [string]$Fields[14]
  $RawMachineMenuLocation = [string]$Fields[15]
  $RawUserMenuLocation = [string]$Fields[16]
  $RawCommonDataLocation = [string]$Fields[17]
  $RawUserDataLocation = [string]$Fields[18]
  $MachineInstallLocation = ConvertTo-DeployMasterEnvironmentPath -Value $RawMachineInstallLocation
  $UserInstallLocation = ConvertTo-DeployMasterEnvironmentPath -Value $RawUserInstallLocation
  $ReadmeFileName = [string]$Fields[7]
  $RawLicenseFileName = [string]$Fields[8]
  $LicenseRequiredEveryInstall = $RawLicenseFileName.StartsWith('*', [StringComparison]::Ordinal)
  $LicenseFileName = $RawLicenseFileName.TrimStart('*')
  $SupportDll32FileName = [string]$Fields[9]
  $SupportDll64FileName = [string]$Fields[10]
  # Readme, license, and architecture-specific support DLLs are catalogued before ordinary payload
  # names. Readme/license aliases can identify one physical entry, but x86 and x64 support DLLs are
  # separate catalog entries even when both use the same destination file name.
  $AuxiliaryFileNames = [Collections.Generic.List[string]]::new()
  $AuxiliaryFileNameSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($AuxiliaryFileName in $ReadmeFileName, $LicenseFileName) {
    if (-not [string]::IsNullOrWhiteSpace($AuxiliaryFileName) -and $AuxiliaryFileNameSet.Add($AuxiliaryFileName)) { $AuxiliaryFileNames.Add($AuxiliaryFileName) }
  }
  foreach ($SupportDllFileName in $SupportDll32FileName, $SupportDll64FileName) {
    if (-not [string]::IsNullOrWhiteSpace($SupportDllFileName)) { $AuxiliaryFileNames.Add($SupportDllFileName) }
  }
  $ReleaseDate = $null
  $ReleaseDateValue = 0.0
  # Release dates are stored as OLE Automation dates; invalid values remain absent evidence.
  if ([double]::TryParse([string]$Fields[5], [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$ReleaseDateValue)) {
    try { $ReleaseDate = [datetime]::FromOADate($ReleaseDateValue).Date } catch {}
  }

  [pscustomobject]@{
    Publisher                    = [string]$Fields[0]
    PublisherUrl                 = [string]$Fields[1]
    DisplayName                  = [string]$Fields[2]
    PackageUrl                   = [string]$Fields[3]
    DisplayVersion               = [string]$Fields[4]
    ReleaseDateValue             = [string]$Fields[5]
    ReleaseDate                  = $ReleaseDate
    Copyright                    = [string]$Fields[6]
    ReadmeFileName               = $ReadmeFileName
    LicenseFileName              = $LicenseFileName
    LicenseRequiredEveryInstall  = $LicenseRequiredEveryInstall
    SupportDll32FileName         = $SupportDll32FileName
    SupportDll64FileName         = $SupportDll64FileName
    AuxiliaryFileNames           = $AuxiliaryFileNames.ToArray()
    MachineInstallLocation       = $MachineInstallLocation
    UserInstallLocation          = $UserInstallLocation
    RawMachineInstallLocation    = $RawMachineInstallLocation
    RawUserInstallLocation       = $RawUserInstallLocation
    CommonFilesLocation          = ConvertTo-DeployMasterEnvironmentPath -Value $RawCommonFilesLocation
    CommonPublisherLocation      = ConvertTo-DeployMasterEnvironmentPath -Value $RawCommonPublisherLocation
    MachineMenuLocation          = ConvertTo-DeployMasterEnvironmentPath -Value $RawMachineMenuLocation
    UserMenuLocation             = ConvertTo-DeployMasterEnvironmentPath -Value $RawUserMenuLocation
    CommonDataLocation           = ConvertTo-DeployMasterEnvironmentPath -Value $RawCommonDataLocation
    UserDataLocation             = ConvertTo-DeployMasterEnvironmentPath -Value $RawUserDataLocation
    RawCommonFilesLocation       = $RawCommonFilesLocation
    RawCommonPublisherLocation   = $RawCommonPublisherLocation
    RawMachineMenuLocation       = $RawMachineMenuLocation
    RawUserMenuLocation          = $RawUserMenuLocation
    RawCommonDataLocation        = $RawCommonDataLocation
    RawUserDataLocation          = $RawUserDataLocation
    LocationMarker               = $LocationMarker
    Scope                        = if ($IdentityScope) { $IdentityScope.Scope } else { $null }
    DefaultScope                 = if ($IdentityScope) { $IdentityScope.DefaultScope } else { $null }
    SupportedScopes              = if ($IdentityScope) { $IdentityScope.SupportedScopes } else { @() }
    SupportsDualScope            = if ($IdentityScope) { $IdentityScope.SupportsDualScope } else { $false }
    RequiresAdministrativeRights = if ($IdentityScope) { $IdentityScope.RequiresAdministrativeRights } else { $null }
    RegistryRoot                 = if ($IdentityScope) { $IdentityScope.RegistryRoot } else { $null }
    EffectiveScopeValue          = if ($IdentityScope) { $IdentityScope.EffectiveScopeValue } else { $ScopeValue }
    LocationMarkerMatchesScope   = $IdentityScope -and ($LocationMarker -in @{
        0 = @(2)
        1 = @(1, 6)
        2 = @(3)
      }[$ScopeValue])
    Fields                       = $Fields
  }
}

function Get-DeployMasterFileNameBlock {
  <#
  .SYNOPSIS
    Locate and validate the CRLF-delimited file-name data block before a catalog.
  .PARAMETER Stream
    Caller-owned installer stream.
  .PARAMETER SearchOffset
    Absolute lower bound for candidate data-block headers.
  .PARAMETER CatalogOffset
    Absolute beginning of the parallel file catalog.
  .PARAMETER Properties
    Five-byte raw-LZMA properties from the package header.
  .PARAMETER ExpectedCount
    Exact number of non-empty names required from the decoded block.
  .PARAMETER MaximumPaddingBytes
    Maximum reserved gap accepted between the decoded name block and the file catalog.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][long]$SearchOffset,
    [Parameter(Mandatory)][long]$CatalogOffset,
    [Parameter(Mandatory)][byte[]]$Properties,
    [Parameter(Mandatory)][ValidateRange(0, 4096)][int]$ExpectedCount,
    [ValidateRange(0, 64)][int]$MaximumPaddingBytes = 16
  )

  $Utf8 = [Text.UTF8Encoding]::new($false, $true)
  $Candidates = [Collections.Generic.List[object]]::new()
  for ($Offset = $SearchOffset; $Offset + 4 -le $CatalogOffset; $Offset++) {
    $Size = [long](Read-BinaryInteger -Stream $Stream -Offset $Offset -Size 4 -Signed)
    if ($Size -eq 0 -or $Size -eq [int]::MinValue) { continue }
    if ($Size -lt 0) { $EndOffset = $Offset + 4 - $Size }
    else {
      if ($Offset + 8 -gt $CatalogOffset -or $Size -gt 1048576) { continue }
      $StoredSize = [long](Read-BinaryInteger -Stream $Stream -Offset ($Offset + 4) -Size 4 -Signed)
      if ($StoredSize -le 0) { continue }
      $EndOffset = $Offset + 8 + $StoredSize
    }
    # Archived 6.x media leaves 32 reserved bytes between the name block and the table. Keep the
    # accepted gap small enough that unrelated earlier text blocks cannot become candidates.
    if ($EndOffset -gt $CatalogOffset -or $CatalogOffset - $EndOffset -gt $MaximumPaddingBytes) { continue }
    try {
      $Block = Read-DeployMasterDataBlock -Stream $Stream -Offset $Offset -Properties $Properties -Limit $CatalogOffset -MaximumBytes 1048576
      $Names = @($Utf8.GetString($Block.Bytes) -split "`r`n" | Where-Object { -not [string]::IsNullOrEmpty($_) })
      if ($Names.Count -ne $ExpectedCount -or $Names | Where-Object { $_ -match '[\x00-\x1F]' }) { continue }
      $Candidates.Add([pscustomobject]@{ Block = $Block; Names = [string[]]$Names; PaddingBytes = $CatalogOffset - $Block.EndOffset })
    } catch {}
  }
  if ($Candidates.Count -eq 0) { throw 'The DeployMaster file-name table could not be decoded.' }
  # Older metadata can contain an earlier data block that decodes to the same number of text lines.
  # The real name table is the valid candidate nearest the catalog; equal-distance candidates remain
  # ambiguous instead of being resolved from their text.
  $MinimumPadding = ($Candidates | Measure-Object -Property PaddingBytes -Minimum).Minimum
  $NearestCandidates = @($Candidates | Where-Object PaddingBytes -EQ $MinimumPadding)
  if ($NearestCandidates.Count -ne 1) { throw 'The DeployMaster file-name table could not be decoded unambiguously.' }
  return $NearestCandidates[0]
}

function Get-DeployMasterFileEntry {
  <#
  .SYNOPSIS
    Read the bounded DeployMaster file-offset and size tables
  .DESCRIPTION
    The file table stores a run of absolute offsets followed by parallel raw
    and stored-size arrays. File names immediately precede the arrays; the
    readme, license, and support-DLL file names are carried by the identity block.
  .PARAMETER Stream
    Caller-owned binary stream. Sequential readers may advance its byte position; helpers do not dispose it.
  .PARAMETER Identity
    Installer identity value used to select or report the matching static metadata record.
  .PARAMETER IdentityEnd
    Byte offset in the coordinate system named by this function: absolute file, PE/resource, overlay, or record relative.
  .PARAMETER PackageDataOffset
    Byte offset in the coordinate system named by this function: absolute file, PE/resource, overlay, or record relative.
  .PARAMETER Properties
    Format-specific field or value interpreted according to the current record/version.
  .PARAMETER TableKind
    Detected format variant controlling version-specific parsing rules.
  .PARAMETER MaximumEntries
    Declared record count or parser count limit; malformed or excessive counts are rejected.
  .PARAMETER MaximumMetadataBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][psobject]$Identity,
    [Parameter(Mandatory)][long]$IdentityEnd,
    [Parameter(Mandatory)][long]$PackageDataOffset,
    [Parameter(Mandatory)][byte[]]$Properties,
    [Parameter(Mandatory)][ValidateSet('Current', 'Legacy')][string]$TableKind,
    [ValidateRange(2, 4096)][int]$MaximumEntries = 4096,
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumMetadataBytes = 33554432
  )

  $MetadataLength = $PackageDataOffset - $IdentityEnd
  if ($MetadataLength -le 0 -or $MetadataLength -gt $MaximumMetadataBytes -or $MetadataLength -gt [int]::MaxValue) {
    throw 'The DeployMaster file-table region is outside the configured bounds.'
  }
  # Search only the bounded metadata gap between identity and package data for parallel offset and
  # size arrays. Structural agreement across all arrays identifies the table.
  $Metadata = Read-BinaryBytes -Stream $Stream -Offset $IdentityEnd -Count ([int]$MetadataLength)
  $Candidates = [Collections.Generic.List[object]]::new()
  for ($Index = 0; $Index + 48 -le $Metadata.Length; $Index++) {
    $FirstOffset = [uint64][BitConverter]::ToUInt64($Metadata, $Index)
    $SecondOffset = [uint64][BitConverter]::ToUInt64($Metadata, $Index + 8)
    if ($FirstOffset -lt [uint64]$IdentityEnd -or $SecondOffset -le $FirstOffset -or $SecondOffset -ge [uint64]$Stream.Length) { continue }
    # Reject suffixes of a longer valid offset run. Without this maximal-run check, every later
    # payload boundary can look like an independent table beginning at PackageDataOffset.
    if ($Index -ge 8) {
      $PreviousOffset = [uint64][BitConverter]::ToUInt64($Metadata, $Index - 8)
      if ($PreviousOffset -ge [uint64]$IdentityEnd -and $PreviousOffset -lt $FirstOffset) { continue }
    }

    $Boundaries = [Collections.Generic.List[long]]::new()
    $Cursor = $Index
    # Absolute payload offsets form a strictly increasing run terminated by the first non-offset.
    while ($Boundaries.Count -lt $MaximumEntries -and $Cursor + 8 -le $Metadata.Length) {
      $Value = [uint64][BitConverter]::ToUInt64($Metadata, $Cursor)
      if ($Value -lt [uint64]$IdentityEnd -or $Value -ge [uint64]$Stream.Length -or ($Boundaries.Count -and $Value -le [uint64]$Boundaries[$Boundaries.Count - 1])) { break }
      $Boundaries.Add([long]$Value)
      $Cursor += 8
    }
    # Current media can place an auxiliary license payload before PackageDataOffset while keeping
    # its absolute offset in the same boundary run. A valid full run must contain the package-data
    # boundary; suffixes beginning later in the payload cannot satisfy that condition.
    if ($Boundaries.Count -lt 2 -or $Boundaries -notcontains $PackageDataOffset) { continue }

    # The boundary run covers payloads stored at PackageDataOffset and later. Earlier releases can
    # keep one or more auxiliary payloads in the metadata gap as [stored-size][raw-size][data]
    # records, while retaining those entries in every parallel catalog column.
    foreach ($CandidateTableKind in $TableKind) {
      $MinimumEmbeddedCount = $CandidateTableKind -eq 'Legacy' ? 1 : 0
      # Both legacy and early Header74 media can omit metadata-resident auxiliary payload offsets
      # from the boundary run while retaining those records in every following catalog column.
      $MaximumEmbeddedCount = [Math]::Min(32, $MaximumEntries - $Boundaries.Count)
      for ($EmbeddedCount = $MinimumEmbeddedCount; $EmbeddedCount -le $MaximumEmbeddedCount; $EmbeddedCount++) {
        $EntryCount = $Boundaries.Count + $EmbeddedCount
        # Six parallel catalog columns follow: five UInt64 arrays and one UInt32 CRC32 array.
        $SerializedTableSize = (8 * $Boundaries.Count) + (36 * $EntryCount)
        if ($EntryCount -gt $MaximumEntries -or $Index + $SerializedTableSize -gt $Metadata.Length) { break }
        $RawSizes = [Collections.Generic.List[long]]::new()
        $StoredSizes = [Collections.Generic.List[long]]::new()
        $Valid = $true
        for ($EntryIndex = 0; $EntryIndex -lt $EntryCount; $EntryIndex++) {
          $Value = [uint64][BitConverter]::ToUInt64($Metadata, $Cursor + (8 * $EntryIndex))
          if ($Value -eq 0 -or $Value -gt [uint64][long]::MaxValue) { $Valid = $false; break }
          $RawSizes.Add([long]$Value)
        }
        if (-not $Valid) { continue }
        $StoredSizeOffset = $Cursor + (8 * $EntryCount)
        for ($EntryIndex = 0; $EntryIndex -lt $EntryCount; $EntryIndex++) {
          $Value = [uint64][BitConverter]::ToUInt64($Metadata, $StoredSizeOffset + (8 * $EntryIndex))
          if ($Value -eq 0 -or $Value -gt [uint64]$RawSizes[$EntryIndex]) { $Valid = $false; break }
          $StoredSizes.Add([long]$Value)
        }
        if (-not $Valid) { continue }

        $Offsets = [Collections.Generic.List[long]]::new()
        $EmbeddedSearchOffset = 0
        for ($EntryIndex = 0; $EntryIndex -lt $EmbeddedCount; $EntryIndex++) {
          if ($RawSizes[$EntryIndex] -gt [uint32]::MaxValue -or $StoredSizes[$EntryIndex] -gt [uint32]::MaxValue) { $Valid = $false; break }
          $HeaderPattern = [byte[]]::new(8)
          [BitConverter]::GetBytes([uint32]$StoredSizes[$EntryIndex]).CopyTo($HeaderPattern, 0)
          [BitConverter]::GetBytes([uint32]$RawSizes[$EntryIndex]).CopyTo($HeaderPattern, 4)
          $PatternMatches = @(Find-BinaryPattern -Bytes $Metadata -Pattern $HeaderPattern -StartOffset $EmbeddedSearchOffset -Length ($Index - $EmbeddedSearchOffset) -Maximum 2)
          $PatternMatches = @($PatternMatches | Where-Object { $_ + 8 + $StoredSizes[$EntryIndex] -le $Index })
          if ($PatternMatches.Count -ne 1) { $Valid = $false; break }
          $EmbeddedHeaderOffset = [int]$PatternMatches[0]
          $Offsets.Add($IdentityEnd + $EmbeddedHeaderOffset + 8)
          $EmbeddedSearchOffset = $EmbeddedHeaderOffset + 8 + $StoredSizes[$EntryIndex]
        }
        if (-not $Valid) { continue }
        foreach ($Boundary in $Boundaries) { $Offsets.Add($Boundary) }
        for ($EntryIndex = 0; $EntryIndex -lt $EntryCount; $EntryIndex++) {
          if ($Offsets[$EntryIndex] + $StoredSizes[$EntryIndex] -gt $Stream.Length) { $Valid = $false; break }
          if ($EntryIndex -ge $EmbeddedCount -and $EntryIndex + 1 -lt $EntryCount -and
            $Offsets[$EntryIndex] + $StoredSizes[$EntryIndex] -gt $Offsets[$EntryIndex + 1]) { $Valid = $false; break }
        }
        if ($Valid) {
          $TimestampOffset = $StoredSizeOffset + (8 * $EntryCount)
          $AttributeOffset = $TimestampOffset + (8 * $EntryCount)
          $CrcOffset = $AttributeOffset + (8 * $EntryCount)
          $Timestamps = [Collections.Generic.List[uint64]]::new()
          $Attributes = [Collections.Generic.List[uint64]]::new()
          $Crc32 = [Collections.Generic.List[uint32]]::new()
          for ($EntryIndex = 0; $EntryIndex -lt $EntryCount; $EntryIndex++) {
            $Timestamps.Add([BitConverter]::ToUInt64($Metadata, $TimestampOffset + (8 * $EntryIndex)))
            $Attributes.Add([BitConverter]::ToUInt64($Metadata, $AttributeOffset + (8 * $EntryIndex)))
            $Crc32.Add([BitConverter]::ToUInt32($Metadata, $CrcOffset + (4 * $EntryIndex)))
          }
          $Candidates.Add([pscustomobject]@{
              TableKind       = $CandidateTableKind
              TableOffset     = $Index
              TableEndOffset  = $CrcOffset + (4 * $EntryCount)
              EmbeddedCount   = $EmbeddedCount
              Offsets         = $Offsets.ToArray()
              RawSizes        = $RawSizes.ToArray()
              StoredSizes     = $StoredSizes.ToArray()
              TimestampValues = $Timestamps.ToArray()
              AttributeValues = $Attributes.ToArray()
              Crc32Values     = $Crc32.ToArray()
            })
        }
      }
    }
  }
  if ($Candidates.Count -eq 0) { throw 'The DeployMaster file table could not be located.' }

  # A table has no explicit entry count. Pair each structurally valid width with the adjacent name
  # block and retain only the width whose complete name count agrees with identity-resident files.
  $NamedCandidates = [Collections.Generic.List[object]]::new()
  foreach ($TableCandidate in $Candidates) {
    $RemainingNameCount = $TableCandidate.Offsets.Count - $Identity.AuxiliaryFileNames.Count
    if ($RemainingNameCount -lt 0) { continue }
    try {
      $NameResult = Get-DeployMasterFileNameBlock -Stream $Stream -SearchOffset ([Math]::Max($IdentityEnd, $IdentityEnd + $TableCandidate.TableOffset - 1048576)) -CatalogOffset ($IdentityEnd + $TableCandidate.TableOffset) -Properties $Properties -ExpectedCount $RemainingNameCount -MaximumPaddingBytes 64
      $NamedCandidates.Add([pscustomobject]@{ Table = $TableCandidate; Names = $NameResult })
    } catch {}
  }
  if ($NamedCandidates.Count -eq 0) { throw 'The DeployMaster file-name table does not identify a complete file catalog.' }
  if ($NamedCandidates.Count -ne 1) { throw 'The DeployMaster file table could not be located unambiguously.' }

  $Candidate = $NamedCandidates[0].Table
  $NameResult = $NamedCandidates[0].Names
  $Names = [Collections.Generic.List[string]]::new()
  foreach ($AuxiliaryFileName in $Identity.AuxiliaryFileNames) { $Names.Add($AuxiliaryFileName) }
  $NameBlock = $NameResult.Block
  $PayloadNames = $NameResult.Names
  foreach ($PayloadName in $PayloadNames) { $Names.Add($PayloadName) }
  if ($Names.Count -ne $Candidate.Offsets.Count) { throw 'The DeployMaster file-name and offset table counts differ.' }

  for ($EntryIndex = 0; $EntryIndex -lt $Names.Count; $EntryIndex++) {
    try { $Timestamp = [datetime]::FromOADate([BitConverter]::Int64BitsToDouble([int64]$Candidate.TimestampValues[$EntryIndex])) }
    catch { $Timestamp = $null }
    [pscustomobject]@{
      Index            = $EntryIndex
      Name             = $Names[$EntryIndex]
      FullName         = $Names[$EntryIndex]
      Offset           = $Candidate.Offsets[$EntryIndex]
      CompressedSize   = $Candidate.StoredSizes[$EntryIndex]
      UncompressedSize = $Candidate.RawSizes[$EntryIndex]
      Compression      = if ($Candidate.StoredSizes[$EntryIndex] -eq $Candidate.RawSizes[$EntryIndex]) { 'Store' } else { 'Lzma' }
      TimestampValue   = $Candidate.TimestampValues[$EntryIndex]
      Timestamp        = $Timestamp
      AttributeValue   = $Candidate.AttributeValues[$EntryIndex]
      Crc32            = $Candidate.Crc32Values[$EntryIndex]
      CatalogOffset    = $IdentityEnd + $Candidate.TableOffset
      CatalogEndOffset = $IdentityEnd + $Candidate.TableEndOffset
      NameBlockOffset  = $NameBlock.Offset
    }
  }
}

function Read-DeployMasterStreamString {
  <#
  .SYNOPSIS
    Read one UInt16-length-prefixed UTF-8 string from a bounded metadata stream.
  .PARAMETER Stream
    Caller-owned sequential stream. The current position advances across the encoded string.
  .PARAMETER MaximumBytes
    Maximum encoded UTF-8 byte length accepted for one string.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [ValidateRange(0, 65535)][int]$MaximumBytes = 65535
  )

  $Length = [int](Read-BinarySequentialInteger -Stream $Stream -Size 2)
  if ($Length -gt $MaximumBytes -or $Stream.Position + $Length -gt $Stream.Length) { throw 'The DeployMaster metadata string is outside its containing block.' }
  if ($Length -eq 0) { return '' }
  $Bytes = [byte[]]::new($Length)
  $Read = $Stream.Read($Bytes, 0, $Length)
  if ($Read -ne $Length) { throw 'The DeployMaster metadata string is truncated.' }
  try { return [Text.UTF8Encoding]::new($false, $true).GetString($Bytes) }
  catch { throw 'The DeployMaster metadata string is not valid UTF-8.' }
}

function ConvertFrom-DeployMasterComponentBlock {
  <#
  .SYNOPSIS
    Decode the component catalog stored before the file-name catalog.
  .PARAMETER Bytes
    Decompressed component data. The input is bounded by its enclosing DeployMaster data block.
  .PARAMETER MaximumComponents
    Maximum number of component records accepted.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [ValidateRange(1, 255)][int]$MaximumComponents = 255
  )

  $Stream = [IO.MemoryStream]::new($Bytes, $false)
  $Components = [Collections.Generic.List[object]]::new()
  try {
    if ($Stream.Length -lt 1) { throw 'The DeployMaster component catalog is empty.' }
    $Count = [int](Read-BinarySequentialInteger -Stream $Stream -Size 1)
    if ($Count -gt $MaximumComponents) { throw 'The DeployMaster component count exceeds the configured limit.' }
    for ($Index = 0; $Index -lt $Count; $Index++) {
      $Name = Read-DeployMasterStreamString -Stream $Stream
      $Flags = [byte](Read-BinarySequentialInteger -Stream $Stream -Size 1)
      $RequirementCount = [int](Read-BinarySequentialInteger -Stream $Stream -Size 1)
      if ($RequirementCount -gt $Count -or $Stream.Position + $RequirementCount -gt $Stream.Length) { throw 'The DeployMaster component requirement list is invalid.' }
      $Requirements = [byte[]]::new($RequirementCount)
      if ($RequirementCount -and $Stream.Read($Requirements, 0, $RequirementCount) -ne $RequirementCount) { throw 'The DeployMaster component requirement list is truncated.' }
      if ($Requirements | Where-Object { $_ -ge $Count }) { throw 'The DeployMaster component requirement index is outside the component catalog.' }
      $Components.Add([pscustomobject]@{
          Index            = $Index
          Name             = $Name
          InstallByDefault = [bool]($Flags -band 2)
          UserSelectable   = [bool]($Flags -band 1)
          Flags            = $Flags
          Requires         = [int[]]$Requirements
          Description      = Read-DeployMasterStreamString -Stream $Stream
        })
    }
    if ($Stream.Position -ne $Stream.Length) { throw 'The DeployMaster component catalog contains trailing data.' }
  } finally { $Stream.Dispose() }
  return $Components.ToArray()
}

function ConvertFrom-DeployMasterInstallTreeBlock {
  <#
  .SYNOPSIS
    Decode component destination trees, installed files, shortcuts, and URL shortcuts.
  .PARAMETER Bytes
    Decompressed install-tree stream shared by all components in catalog order.
  .PARAMETER Components
    Parsed component records controlling the number and identity of root trees.
  .PARAMETER FileEntries
    Parsed file catalog used to resolve file and executable indexes.
  .PARAMETER MaximumDepth
    Maximum recursive destination-folder depth.
  .PARAMETER MaximumItems
    Maximum total folder and item records accepted.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Components,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$FileEntries,
    [ValidateRange(1, 128)][int]$MaximumDepth = 32,
    [ValidateRange(1, 1048576)][int]$MaximumItems = 65536
  )

  $Stream = [IO.MemoryStream]::new($Bytes, $false)
  $Folders = [Collections.Generic.List[object]]::new()
  $Files = [Collections.Generic.List[object]]::new()
  $Shortcuts = [Collections.Generic.List[object]]::new()
  $UrlShortcuts = [Collections.Generic.List[object]]::new()
  $ItemCount = 0

  function Read-DeployMasterInstallTreeBranch([string]$ParentPath, [int]$ComponentIndex, [int]$Depth) {
    if ($Depth -gt $MaximumDepth) { throw 'The DeployMaster install-tree depth exceeds the configured limit.' }
    $Marker = [byte](Read-BinarySequentialInteger -Stream $Stream -Size 1)
    while ($Marker -lt 0xFE) {
      $ItemCount++
      if ($ItemCount -gt $MaximumItems) { throw 'The DeployMaster install-tree item count exceeds the configured limit.' }
      $CharacterCount = [int]$Marker
      $ByteCount = 2 * $CharacterCount
      if ($Stream.Position + $ByteCount + 1 -gt $Stream.Length) { throw 'The DeployMaster destination-folder record is truncated.' }
      $NameBytes = [byte[]]::new($ByteCount)
      if ($ByteCount -and $Stream.Read($NameBytes, 0, $ByteCount) -ne $ByteCount) { throw 'The DeployMaster destination-folder name is truncated.' }
      $Name = [Text.Encoding]::Unicode.GetString($NameBytes)
      $CreateIfEmpty = [bool](Read-BinarySequentialInteger -Stream $Stream -Size 1)
      $FullPath = [string]::IsNullOrEmpty($ParentPath) ? $Name : "$($ParentPath.TrimEnd('\'))\$Name"
      $Folders.Add([pscustomobject]@{ ComponentIndex = $ComponentIndex; Name = $Name; FullName = $FullPath; CreateIfEmpty = $CreateIfEmpty })
      Read-DeployMasterInstallTreeBranch -ParentPath $FullPath -ComponentIndex $ComponentIndex -Depth ($Depth + 1)
      $Marker = [byte](Read-BinarySequentialInteger -Stream $Stream -Size 1)
    }
    if ($Marker -eq 0xFF) { return }
    if ($Marker -ne 0xFE) { throw "Unsupported DeployMaster install-tree marker 0x$($Marker.ToString('X2'))." }

    $Opcode = [byte](Read-BinarySequentialInteger -Stream $Stream -Size 1)
    while ($Opcode -ne 0xFF) {
      $ItemCount++
      if ($ItemCount -gt $MaximumItems) { throw 'The DeployMaster install-tree item count exceeds the configured limit.' }
      switch ($Opcode -band 0xF0) {
        0x80 {
          $Flags = [byte](Read-BinarySequentialInteger -Stream $Stream -Size 1)
          $FileIndex = [int](Read-BinarySequentialInteger -Stream $Stream -Size 2)
          if ($FileIndex -ge $FileEntries.Count) { throw 'The DeployMaster install-tree file index is outside the file catalog.' }
          $OptionalArgument = ($Flags -band 0x10) ? (Read-DeployMasterStreamString -Stream $Stream) : $null
          $Entry = $FileEntries[$FileIndex]
          $InstalledPath = [string]::IsNullOrEmpty($ParentPath) ? $Entry.Name : "$($ParentPath.TrimEnd('\'))\$($Entry.Name)"
          $FileAction = [int]($Opcode -band 3)
          $Architectures = [Collections.Generic.List[string]]::new(2)
          if ($Flags -band 0x01) { $Architectures.Add('x86') }
          if ($Flags -band 0x02) { $Architectures.Add('x64') }
          $Files.Add([pscustomobject]@{
              ComponentIndex    = $ComponentIndex
              DestinationPath   = $InstalledPath
              Directory         = $ParentPath
              FileIndex         = $FileIndex
              SourceName        = $Entry.Name
              Included          = $Architectures.Count -gt 0
              Architectures     = $Architectures.ToArray()
              FileAction        = $FileAction
              OverwriteBehavior = switch ($FileAction) { 0 { 'AlwaysOverwrite' } 1 { 'OverwriteIfNewer' } 2 { 'NeverOverwrite' } default { 'Unknown' } }
              NeverUninstall    = [bool]($Opcode -band 0x04)
              OpcodeFlags       = [byte]($Opcode -band 0x0F)
              Flags             = $Flags
              OptionalArgument  = $OptionalArgument
            })
        }
        0x40 {
          $FileIndex = [int](Read-BinarySequentialInteger -Stream $Stream -Size 2)
          if ($FileIndex -ge $FileEntries.Count) { throw 'The DeployMaster shortcut file index is outside the file catalog.' }
          $Values = @(
            Read-DeployMasterStreamString -Stream $Stream
            Read-DeployMasterStreamString -Stream $Stream
            Read-DeployMasterStreamString -Stream $Stream
          )
          $Flags = [byte](Read-BinarySequentialInteger -Stream $Stream -Size 1)
          $Reference = [int](Read-BinarySequentialInteger -Stream $Stream -Size 2)
          $Shortcuts.Add([pscustomobject]@{
              ComponentIndex = $ComponentIndex; Directory = $ParentPath; TargetFileIndex = $FileIndex
              TargetFile = $FileEntries[$FileIndex].Name; Values = $Values; Flags = [byte]($Flags -band 0x0F)
              Reference = $Reference; OpcodeFlags = [byte]($Opcode -band 3)
            })
        }
        0x20 {
          $Name = Read-DeployMasterStreamString -Stream $Stream
          $Url = Read-DeployMasterStreamString -Stream $Stream
          $Flags = [byte](Read-BinarySequentialInteger -Stream $Stream -Size 1)
          $Reference = [int](Read-BinarySequentialInteger -Stream $Stream -Size 2)
          $UrlShortcuts.Add([pscustomobject]@{
              ComponentIndex = $ComponentIndex; Directory = $ParentPath; Name = $Name; Url = $Url
              Flags = [byte]($Flags -band 0x0F); Reference = $Reference; OpcodeFlags = [byte]($Opcode -band 3)
            })
        }
        default { throw "Unsupported DeployMaster install-tree opcode 0x$($Opcode.ToString('X2'))." }
      }
      $Opcode = [byte](Read-BinarySequentialInteger -Stream $Stream -Size 1)
    }
  }

  try {
    for ($ComponentIndex = 0; $ComponentIndex -lt $Components.Count; $ComponentIndex++) {
      Read-DeployMasterInstallTreeBranch -ParentPath '' -ComponentIndex $ComponentIndex -Depth 0
    }
    if ($Stream.Position -ne $Stream.Length) { throw 'The DeployMaster install-tree stream contains trailing data.' }
  } finally { $Stream.Dispose() }
  return [pscustomobject]@{
    Folders = $Folders.ToArray(); Files = $Files.ToArray(); Shortcuts = $Shortcuts.ToArray(); UrlShortcuts = $UrlShortcuts.ToArray()
  }
}

function ConvertFrom-DeployMasterRegistryBlock {
  <#
  .SYNOPSIS
    Decode DeployMaster's recursive registry operation stream.
  .PARAMETER Bytes
    Decompressed registry operation data.
  .PARAMETER ScopeValue
    Package scope byte used to resolve the virtual HKEY_AUTO root.
  .PARAMETER Route
    Catalog-selected registry stream grammar. Header66 media uses a legacy delimiter and opcode
    map; newer profiles use the current operation stream.
  .PARAMETER MaximumDepth
    Maximum nested registry-key depth.
  .PARAMETER MaximumOperations
    Maximum opcode count accepted across all roots.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ValidateRange(0, 255)][int]$ScopeValue,
    [ValidateSet('Opcode', 'LegacyDelimited', 'ClassicNullTerminatedAnsi')][string]$Route = 'Opcode',
    [ValidateRange(1, 128)][int]$MaximumDepth = 64,
    [ValidateRange(1, 1048576)][int]$MaximumOperations = 65536
  )

  $Stream = [IO.MemoryStream]::new($Bytes, $false)
  $Writes = [Collections.Generic.List[object]]::new()
  $DeletedKeys = [Collections.Generic.List[object]]::new()
  $OperationCount = 0

  function Read-DeployMasterRegistryString {
    if ($Route -ne 'ClassicNullTerminatedAnsi') { return Read-DeployMasterStreamString -Stream $Stream }
    $Start = $Stream.Position
    while ($Stream.Position -lt $Stream.Length -and $Stream.ReadByte() -ne 0) {
      if ($Stream.Position - $Start -gt 65535) { throw 'The classic DeployMaster registry string exceeds the configured limit.' }
    }
    if ($Stream.Position -gt $Stream.Length -or ($Stream.Position -eq $Stream.Length -and $Bytes[$Bytes.Length - 1] -ne 0)) { throw 'The classic DeployMaster registry string is not terminated.' }
    return [Text.Encoding]::GetEncoding(1252).GetString($Bytes, [int]$Start, [int]($Stream.Position - $Start - 1))
  }

  function Read-DeployMasterRegistryBranch([string]$Root, [string]$Key, [int]$Depth) {
    if ($Depth -gt $MaximumDepth) { throw 'The DeployMaster registry-tree depth exceeds the configured limit.' }
    $ValueName = ''
    $KeepExisting = $false
    while ($true) {
      $OperationCount++
      if ($OperationCount -gt $MaximumOperations) { throw 'The DeployMaster registry operation count exceeds the configured limit.' }
      $Opcode = [byte](Read-BinarySequentialInteger -Stream $Stream -Size 1)
      if ($Route -in 'LegacyDelimited', 'ClassicNullTerminatedAnsi') {
        # DeployMaster 6.0.x serializes a depth-first key tree. 0x1F separates child-key records
        # from value records, 0x02 selects a value name, and 0x04 writes its REG_SZ data.
        switch ($Opcode) {
          0x01 {
            $Child = Read-DeployMasterRegistryString
            $ChildKey = [string]::IsNullOrEmpty($Key) ? $Child : "$($Key.TrimEnd('\'))\$Child"
            Read-DeployMasterRegistryBranch -Root $Root -Key $ChildKey -Depth ($Depth + 1)
          }
          0x1F { }
          0x02 {
            $ValueName = Read-DeployMasterRegistryString
            if ($ValueName -ceq '(Default)') { $ValueName = '' }
          }
          0x04 {
            $Writes.Add([pscustomobject]@{ Root = $Root; Key = $Key; Name = $ValueName; Value = Read-DeployMasterRegistryString; Type = 'REG_SZ'; OnlyIfMissing = $false; Evidence = 'DeployMaster legacy registry operation stream' })
          }
          0x05 {
            if ($Route -ne 'ClassicNullTerminatedAnsi') { throw 'DeployMaster header-based legacy registry media uses an unsupported DWORD opcode.' }
            $Writes.Add([pscustomobject]@{ Root = $Root; Key = $Key; Name = $ValueName; Value = [uint32](Read-BinarySequentialInteger -Stream $Stream -Size 4); Type = 'REG_DWORD'; OnlyIfMissing = $false; Evidence = 'DeployMaster classic registry operation stream' })
          }
          0xFF { return }
          default { throw "Unsupported DeployMaster legacy registry opcode 0x$($Opcode.ToString('X2'))." }
        }
        continue
      }
      switch ($Opcode) {
        0x01 {
          $Child = Read-DeployMasterStreamString -Stream $Stream
          $ChildKey = [string]::IsNullOrEmpty($Key) ? $Child : "$($Key.TrimEnd('\'))\$Child"
          Read-DeployMasterRegistryBranch -Root $Root -Key $ChildKey -Depth ($Depth + 1)
        }
        0x02 { $DeletedKeys.Add([pscustomobject]@{ Root = $Root; Key = $Key; Evidence = 'DeployMaster delete-key-on-uninstall opcode' }) }
        0x03 { $ValueName = ''; $KeepExisting = $false }
        0x04 { $ValueName = Read-DeployMasterStreamString -Stream $Stream; $KeepExisting = $false }
        0x05 { $KeepExisting = $true }
        0x06 { }
        0x07 {
          $Writes.Add([pscustomobject]@{ Root = $Root; Key = $Key; Name = $ValueName; Value = Read-DeployMasterStreamString -Stream $Stream; Type = 'REG_SZ'; OnlyIfMissing = $KeepExisting; Evidence = 'DeployMaster registry operation stream' })
        }
        0x08 {
          $Writes.Add([pscustomobject]@{ Root = $Root; Key = $Key; Name = $ValueName; Value = [uint32](Read-BinarySequentialInteger -Stream $Stream -Size 4); Type = 'REG_DWORD'; OnlyIfMissing = $KeepExisting; Evidence = 'DeployMaster registry operation stream' })
        }
        0x09 {
          $Length = [long](Read-BinarySequentialInteger -Stream $Stream -Size 4 -Signed)
          if ($Length -lt 0 -or $Length -gt 16777216 -or $Stream.Position + $Length -gt $Stream.Length) { throw 'The DeployMaster binary registry value has an invalid size.' }
          $Value = [byte[]]::new([int]$Length)
          if ($Length -and $Stream.Read($Value, 0, [int]$Length) -ne $Length) { throw 'The DeployMaster binary registry value is truncated.' }
          $Writes.Add([pscustomobject]@{ Root = $Root; Key = $Key; Name = $ValueName; Value = $Value; Type = 'REG_BINARY'; OnlyIfMissing = $KeepExisting; Evidence = 'DeployMaster registry operation stream' })
        }
        0xFF { return }
        default { throw "Unsupported DeployMaster registry opcode 0x$($Opcode.ToString('X2'))." }
      }
    }
  }

  try {
    while ($Stream.Position -lt $Stream.Length) {
      $Opcode = [byte](Read-BinarySequentialInteger -Stream $Stream -Size 1)
      if ($Opcode -ne 1) { break }
      $EncodedRoot = Read-DeployMasterRegistryString
      $Root = switch ($EncodedRoot) {
        'HKEY_AUTO' { switch ($ScopeValue) { 0 { 'HKCU' } 1 { 'HKLM' } default { 'SHCTX' } } }
        'HKEY_CLASSES_ROOT' { 'HKCR' }
        'HKEY_CURRENT_USER' { 'HKCU' }
        'HKEY_LOCAL_MACHINE' { 'HKLM' }
        'HKEY_USERS' { 'HKU' }
        default { throw "Unsupported DeployMaster registry root '$EncodedRoot'." }
      }
      Read-DeployMasterRegistryBranch -Root $Root -Key '' -Depth 0
    }
    if ($Stream.Position -ne $Stream.Length) { throw 'The DeployMaster registry operation stream contains trailing data.' }
  } finally { $Stream.Dispose() }
  return [pscustomobject]@{ RegistryWrites = $Writes.ToArray(); DeletedKeys = $DeletedKeys.ToArray() }
}

function ConvertFrom-DeployMasterTextBlock {
  <#
  .SYNOPSIS
    Decode a bounded DeployMaster compressed-string payload without guessing field semantics.
  .PARAMETER Bytes
    Stored or decompressed string bytes.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes)

  if ($Bytes.Length -eq 0) { return [pscustomobject]@{ Text = ''; Fields = [string[]]@(); Encoding = 'Empty' } }
  $EncodingName = 'UTF-8'
  try {
    if ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFF -and $Bytes[1] -eq 0xFE) {
      $Text = [Text.Encoding]::Unicode.GetString($Bytes, 2, $Bytes.Length - 2)
      $EncodingName = 'UTF-16LE'
    } elseif ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFE -and $Bytes[1] -eq 0xFF) {
      $Text = [Text.Encoding]::BigEndianUnicode.GetString($Bytes, 2, $Bytes.Length - 2)
      $EncodingName = 'UTF-16BE'
    } elseif (($Bytes | Where-Object { $_ -eq 0 }).Count -gt [Math]::Floor($Bytes.Length / 4)) {
      $Text = [Text.Encoding]::Unicode.GetString($Bytes)
      $EncodingName = 'UTF-16LE'
    } else {
      $Text = [Text.UTF8Encoding]::new($false, $true).GetString($Bytes)
    }
  } catch { throw 'The DeployMaster compressed-string payload has an invalid text encoding.' }
  return [pscustomobject]@{
    Text     = $Text.TrimEnd([char]0)
    # DeployMaster uses bare CR separators in prerequisite descriptors and CRLF in file-name
    # catalogs. Preserve empty positional fields while accepting every documented line ending.
    Fields   = [string[]]@($Text.TrimEnd([char]0) -split "`r`n|`r|`n")
    Encoding = $EncodingName
  }
}

function ConvertFrom-DeployMasterDotNetFrameworkRecord {
  <#
  .SYNOPSIS
    Project the DeployMaster .NET Framework bitmask and descriptor into named prerequisite evidence.
  .PARAMETER Flags
    Builder compatibility bitmask. Bits 0 through 4 represent .NET Framework 1.0, 1.1, 2.0, 3.0,
    and 3.5; bit 5 enables the 4.x family.
  .PARAMETER VersionCode
    Minimum .NET Framework 4.x version selector used when bit 5 is set.
  .PARAMETER Descriptor
    Decoded CR-delimited descriptor block. Field 0 is an optional framework installer filename and
    field 1 is the fallback download URL.
  .PARAMETER RawValues
    Sixteen observed bytes following the descriptor. Their semantics are not assigned until a
    controlled builder differential proves them.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte]$Flags,
    [Parameter(Mandatory)][byte]$VersionCode,
    [Parameter(Mandatory)][psobject]$Descriptor,
    [Parameter(Mandatory)][byte[]]$RawValues
  )

  $VersionBits = [ordered]@{
    0x01 = '1.0'
    0x02 = '1.1'
    0x04 = '2.0'
    0x08 = '3.0'
    0x10 = '3.5'
  }
  $CompatibleVersions = [Collections.Generic.List[string]]::new()
  foreach ($Pair in $VersionBits.GetEnumerator()) {
    if ($Flags -band [byte]$Pair.Key) { $CompatibleVersions.Add([string]$Pair.Value) }
  }

  $Minimum4xVersion = $null
  if ($Flags -band 0x20) {
    $Minimum4xVersion = @('4.0', '4.5', '4.5.1', '4.5.2', '4.6', '4.6.1', '4.6.2', '4.7', '4.7.1', '4.7.2', '4.8', '4.8.1')[$VersionCode]
    if ($null -ne $Minimum4xVersion) { $CompatibleVersions.Add("$Minimum4xVersion+") }
  }

  $DescriptorFields = [string[]]@($Descriptor.Fields)
  $InstallerFileName = if ($DescriptorFields.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($DescriptorFields[0])) { $DescriptorFields[0] } else { $null }
  $DownloadUrl = if ($DescriptorFields.Count -gt 1 -and -not [string]::IsNullOrWhiteSpace($DescriptorFields[1])) { $DescriptorFields[1] } else { $null }
  return [pscustomobject]@{
    Kind                  = 'DotNetFramework'
    Flags                 = $Flags
    CompatibleVersions    = $CompatibleVersions.ToArray()
    Requires4x            = [bool]($Flags -band 0x20)
    Minimum4xVersion      = $Minimum4xVersion
    VersionCode           = $VersionCode
    InstallerFileName     = $InstallerFileName
    HasAutomaticInstaller = -not [string]::IsNullOrWhiteSpace($InstallerFileName)
    DownloadUrl           = $DownloadUrl
    Descriptor            = $Descriptor.Text
    DescriptorFields      = $DescriptorFields
    UnknownFlags          = [byte]($Flags -band 0xC0)
    RawValues             = $RawValues
  }
}

function Read-DeployMasterTrailingRecord {
  <#
  .SYNOPSIS
    Decode prerequisite, completion, launch, uninstall, and update records after file associations.
  .PARAMETER Stream
    Caller-owned installer stream.
  .PARAMETER Offset
    Absolute first byte after the file-association data block.
  .PARAMETER Limit
    Absolute package-data boundary; all trailing records must end exactly here.
  .PARAMETER Properties
    Five-byte raw-LZMA properties from the package header.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][long]$Offset,
    [Parameter(Mandatory)][long]$Limit,
    [Parameter(Mandatory)][byte[]]$Properties
  )

  function Read-DeployMasterTrailingTextBlock([ref]$Cursor) {
    $Block = Read-DeployMasterDataBlock -Stream $Stream -Offset $Cursor.Value -Properties $Properties -Limit $Limit -MaximumBytes 4194304
    $Cursor.Value = $Block.EndOffset
    $Text = ConvertFrom-DeployMasterTextBlock -Bytes $Block.Bytes
    return [pscustomobject]@{ Block = $Block; Text = $Text.Text; Fields = $Text.Fields; Encoding = $Text.Encoding }
  }
  function Read-DeployMasterTrailingInteger([ref]$Cursor, [int]$Size, [switch]$Signed) {
    if ($Cursor.Value + $Size -gt $Limit) { throw 'The DeployMaster trailing metadata is truncated.' }
    $Value = Read-BinaryInteger -Stream $Stream -Offset $Cursor.Value -Size $Size -Signed:$Signed
    $Cursor.Value += $Size
    return $Value
  }
  function ConvertTo-DeployMasterTrailingTextList([AllowNull()][psobject]$Record) {
    if ($null -eq $Record) { return [string[]]@() }
    # The builder accepts semicolon-separated values in each UI line. Normalize both delimiters
    # while retaining the original text block below for exact format evidence.
    return [string[]]@($Record.Fields | ForEach-Object { $_ -split ';' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
  }

  $Cursor = $Offset
  $Prerequisites = [Collections.Generic.List[object]]::new()
  $FrameworkFlags = [byte](Read-DeployMasterTrailingInteger -Cursor ([ref]$Cursor) -Size 1)
  $Framework = $null
  if ($FrameworkFlags) {
    $FrameworkVersionCode = [byte](Read-DeployMasterTrailingInteger -Cursor ([ref]$Cursor) -Size 1)
    $Descriptor = Read-DeployMasterTrailingTextBlock -Cursor ([ref]$Cursor)
    if ($Cursor + 16 -gt $Limit) { throw 'The DeployMaster .NET prerequisite record is truncated.' }
    $RawValues = Read-BinaryBytes -Stream $Stream -Offset $Cursor -Count 16
    $Cursor += 16
    $Framework = ConvertFrom-DeployMasterDotNetFrameworkRecord -Flags $FrameworkFlags -VersionCode $FrameworkVersionCode -Descriptor $Descriptor -RawValues $RawValues
    $Prerequisites.Add($Framework)
  }

  $CustomCount = [long](Read-DeployMasterTrailingInteger -Cursor ([ref]$Cursor) -Size 4 -Signed)
  if ($CustomCount -lt 0 -or $CustomCount -gt 256) { throw 'The DeployMaster custom prerequisite count is invalid.' }
  for ($Index = 0; $Index -lt $CustomCount; $Index++) {
    $Descriptor = Read-DeployMasterTrailingTextBlock -Cursor ([ref]$Cursor)
    if ($Cursor + 16 -gt $Limit) { throw 'The DeployMaster custom prerequisite record is truncated.' }
    $RawValues = Read-BinaryBytes -Stream $Stream -Offset $Cursor -Count 16
    $Cursor += 16
    $Prerequisites.Add([pscustomobject]@{
        Kind = 'Custom'; Index = $Index; Descriptor = $Descriptor.Text
        DescriptorFields = $Descriptor.Fields; RawValues = $RawValues
      })
  }

  # Completion flags are followed by optional architecture-specific launch indexes and arguments.
  $CompletionFlags = [byte](Read-DeployMasterTrailingInteger -Cursor ([ref]$Cursor) -Size 1)
  $Launch32FileIndex = if ($CompletionFlags -band 4) { [int](Read-DeployMasterTrailingInteger -Cursor ([ref]$Cursor) -Size 2) } else { -1 }
  $Launch64FileIndex = if ($CompletionFlags -band 8) { [int](Read-DeployMasterTrailingInteger -Cursor ([ref]$Cursor) -Size 2) } else { -1 }
  $LaunchArguments = (($CompletionFlags -band 0x0C) -ne 0) ? (Read-DeployMasterTrailingTextBlock -Cursor ([ref]$Cursor)).Text : $null

  $PreUninstall32FileIndex = [int16](Read-DeployMasterTrailingInteger -Cursor ([ref]$Cursor) -Size 2 -Signed)
  $PreUninstall64FileIndex = [int16](Read-DeployMasterTrailingInteger -Cursor ([ref]$Cursor) -Size 2 -Signed)
  # Archived 6.0/6.5 media uses two zero indexes for an absent pre-uninstall command, while 7.1+
  # uses 0xFFFF. Accept zero only when the record has exactly the fixed six-byte suffix remaining;
  # otherwise index zero remains a valid reference and must be followed by its argument block.
  if ($PreUninstall32FileIndex -eq 0 -and $PreUninstall64FileIndex -eq 0 -and $Limit - $Cursor -eq 6) {
    $PreUninstall32FileIndex = -1
    $PreUninstall64FileIndex = -1
  }
  $PreUninstallArguments = ($PreUninstall32FileIndex -ne -1 -or $PreUninstall64FileIndex -ne -1) ? (Read-DeployMasterTrailingTextBlock -Cursor ([ref]$Cursor)).Text : $null
  $UninstallShortcutFlags = [byte](Read-DeployMasterTrailingInteger -Cursor ([ref]$Cursor) -Size 1)
  $UninstallShortcutReferenceValue = [uint16](Read-DeployMasterTrailingInteger -Cursor ([ref]$Cursor) -Size 2)
  $UninstallShortcutReference = if ($UninstallShortcutReferenceValue -eq [uint16]::MaxValue) { $null } else { [int]$UninstallShortcutReferenceValue }

  # The final three-byte update header gates up to three following compressed-string records.
  $UpdateFlags = [byte](Read-DeployMasterTrailingInteger -Cursor ([ref]$Cursor) -Size 1)
  $RequiredReleaseDay = [uint16](Read-DeployMasterTrailingInteger -Cursor ([ref]$Cursor) -Size 2)
  $PatchRequirement = ($UpdateFlags -band 2) ? (Read-DeployMasterTrailingTextBlock -Cursor ([ref]$Cursor)) : $null
  $BlockedWindowClasses = ($UpdateFlags -band 4) ? (Read-DeployMasterTrailingTextBlock -Cursor ([ref]$Cursor)) : $null
  $BlockedWindowCaptions = ($UpdateFlags -band 8) ? (Read-DeployMasterTrailingTextBlock -Cursor ([ref]$Cursor)) : $null
  if ($Cursor -ne $Limit) { throw 'The DeployMaster trailing metadata contains unsupported or trailing records.' }

  return [pscustomobject]@{
    Prerequisites   = $Prerequisites.ToArray()
    DotNetFramework = $Framework
    Completion      = [pscustomobject]@{
      Flags               = $CompletionFlags
      ShowMessage         = [bool]($CompletionFlags -band 0x80)
      PromptForReboot     = [bool]($CompletionFlags -band 0x40)
      ShowStartMenuFolder = [bool]($CompletionFlags -band 0x02)
      Launch32FileIndex   = $Launch32FileIndex
      Launch64FileIndex   = $Launch64FileIndex
      LaunchArguments     = $LaunchArguments
    }
    Uninstall       = [pscustomobject]@{
      PreUninstall32FileIndex = $PreUninstall32FileIndex
      PreUninstall64FileIndex = $PreUninstall64FileIndex
      PreUninstallArguments   = $PreUninstallArguments
      ShortcutFlags           = $UninstallShortcutFlags
      CreateStartMenuShortcut = [bool]($UninstallShortcutFlags -band 1)
      ShortcutReference       = $UninstallShortcutReference
      ShortcutReferenceValue  = $UninstallShortcutReferenceValue
    }
    Update          = [pscustomobject]@{
      Flags                   = $UpdateFlags
      DeleteObsoleteFiles     = [bool]($UpdateFlags -band 1)
      IsPatchPackage          = [bool]($UpdateFlags -band 2)
      RequiresPreviousRelease = [bool]($UpdateFlags -band 2)
      RequiredReleaseDay      = $RequiredReleaseDay
      RequiredReleaseDate     = if (($UpdateFlags -band 2) -and $RequiredReleaseDay) { [datetime]::FromOADate($RequiredReleaseDay).Date } else { $null }
      PatchRequirement        = $PatchRequirement?.Text
      PatchRequirementLines   = ConvertTo-DeployMasterTrailingTextList -Record $PatchRequirement
      BlockedWindowClasses    = ConvertTo-DeployMasterTrailingTextList -Record $BlockedWindowClasses
      BlockedWindowCaptions   = ConvertTo-DeployMasterTrailingTextList -Record $BlockedWindowCaptions
      RawRecords              = [pscustomobject]@{
        PatchRequirement      = $PatchRequirement
        BlockedWindowClasses  = $BlockedWindowClasses
        BlockedWindowCaptions = $BlockedWindowCaptions
      }
    }
  }
}

function Find-DeployMasterComponentBlock {
  <#
  .SYNOPSIS
    Locate the component block when no auxiliary payload supplies its leading boundary.
  .PARAMETER Stream
    Caller-owned installer stream. Random-access reads restore its original position.
  .PARAMETER MinimumOffset
    Absolute lower bound of the metadata range following the identity block.
  .PARAMETER NameBlockOffset
    Absolute offset of the file-name block; the component block must end exactly here.
  .PARAMETER Properties
    Five-byte raw-LZMA properties from the package header.
  .PARAMETER MaximumScanBytes
    Maximum metadata suffix inspected for a size-framed component block.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][long]$MinimumOffset,
    [Parameter(Mandatory)][long]$NameBlockOffset,
    [Parameter(Mandatory)][byte[]]$Properties,
    [ValidateRange(1, 4194304)][int]$MaximumScanBytes = 1048576
  )

  $SearchOffset = [Math]::Max($MinimumOffset, $NameBlockOffset - $MaximumScanBytes)
  $SearchLength = $NameBlockOffset - $SearchOffset
  if ($SearchLength -lt 4 -or $SearchLength -gt [int]::MaxValue) { throw 'The DeployMaster component-search range is invalid.' }
  $Metadata = Read-BinaryBytes -Stream $Stream -Offset $SearchOffset -Count ([int]$SearchLength)
  $Candidates = [Collections.Generic.List[object]]::new()

  # Component records have no pointer from the surrounding metadata. Authenticate candidates by
  # their exact end boundary and by complete decoding of the component catalog.
  for ($Index = 0; $Index + 4 -le $Metadata.Length; $Index++) {
    $Size = [BitConverter]::ToInt32($Metadata, $Index)
    if ($Size -eq [int]::MinValue) { continue }
    $RelativeEnd = if ($Size -eq 0) {
      $Index + 4
    } elseif ($Size -lt 0) {
      $Index + 4 - $Size
    } elseif ($Index + 8 -le $Metadata.Length) {
      $StoredSize = [BitConverter]::ToInt32($Metadata, $Index + 4)
      $StoredSize -gt 0 ? $Index + 8 + $StoredSize : -1
    } else {
      -1
    }
    if ($RelativeEnd -ne $Metadata.Length) { continue }
    try {
      $Block = Read-DeployMasterDataBlock -Stream $Stream -Offset ($SearchOffset + $Index) -Properties $Properties -Limit $NameBlockOffset -MaximumBytes 4194304
      $Components = @(ConvertFrom-DeployMasterComponentBlock -Bytes $Block.Bytes)
      $Candidates.Add([pscustomobject]@{ Block = $Block; Components = $Components })
    } catch {}
  }

  if ($Candidates.Count -eq 0) { throw 'The DeployMaster component block could not be located before the file-name catalog.' }
  if ($Candidates.Count -ne 1) { throw 'The DeployMaster component block could not be located unambiguously.' }
  return $Candidates[0]
}

function Read-DeployMasterStructuredRecord {
  <#
  .SYNOPSIS
    Follow the exact current DeployMaster metadata record order after catalog discovery.
  .PARAMETER Stream
    Caller-owned installer stream.
  .PARAMETER Header
    Normalized DeployMaster control header.
  .PARAMETER Locator
    Validated fixed package locator.
  .PARAMETER IdentityEnd
    Absolute end of the identity data block.
  .PARAMETER FileEntries
    File catalog carrying exact catalog, name-block, and payload boundaries.
  .PARAMETER ScopeValue
    Effective registry scope after combining the package-control scope byte with the identity route.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][psobject]$Header,
    [Parameter(Mandatory)][psobject]$Locator,
    [Parameter(Mandatory)][long]$IdentityEnd,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$FileEntries,
    [Parameter(Mandatory)][ValidateRange(0, 2)][int]$ScopeValue
  )

  if ($FileEntries.Count -eq 0) { throw 'The DeployMaster structured metadata requires a decoded file catalog.' }
  $NameBlockOffset = [long]$FileEntries[0].NameBlockOffset
  $MetadataResidentFiles = @($FileEntries | Where-Object { $_.Offset -lt $NameBlockOffset })
  if ($MetadataResidentFiles.Count) {
    # Readme, license, and support-DLL payloads precede the component block when configured. Their
    # furthest physical end is therefore the exact next-record boundary.
    $ComponentOffset = [long](($MetadataResidentFiles | ForEach-Object { $_.Offset + $_.CompressedSize } | Measure-Object -Maximum).Maximum)
    $ComponentBlock = Read-DeployMasterDataBlock -Stream $Stream -Offset $ComponentOffset -Properties $Header.LzmaProperties -Limit $NameBlockOffset -MaximumBytes 4194304
    if ($ComponentBlock.EndOffset -ne $NameBlockOffset) { throw 'The DeployMaster component block is not adjacent to the file-name catalog.' }
    $Components = @(ConvertFrom-DeployMasterComponentBlock -Bytes $ComponentBlock.Bytes)
  } else {
    # License-free projects have no file-table record from which to derive the leading boundary.
    # Search only the bounded metadata suffix and require exact component-catalog consumption.
    $ComponentResult = Find-DeployMasterComponentBlock -Stream $Stream -MinimumOffset $IdentityEnd -NameBlockOffset $NameBlockOffset -Properties $Header.LzmaProperties
    $ComponentBlock = $ComponentResult.Block
    $Components = @($ComponentResult.Components)
  }

  $InstallTreeBlock = Read-DeployMasterDataBlock -Stream $Stream -Offset ([long]$FileEntries[0].CatalogEndOffset) -Properties $Header.LzmaProperties -Limit $Locator.PackageDataOffset -MaximumBytes 16777216
  $InstallTree = ConvertFrom-DeployMasterInstallTreeBlock -Bytes $InstallTreeBlock.Bytes -Components $Components -FileEntries $FileEntries
  $RegistryBlock = Read-DeployMasterDataBlock -Stream $Stream -Offset $InstallTreeBlock.EndOffset -Properties $Header.LzmaProperties -Limit $Locator.PackageDataOffset -MaximumBytes 16777216
  $Registry = if ($RegistryBlock.Bytes.Length) { ConvertFrom-DeployMasterRegistryBlock -Bytes $RegistryBlock.Bytes -ScopeValue $ScopeValue -Route $Header.RegistryRoute } else { [pscustomobject]@{ RegistryWrites = @(); DeletedKeys = @() } }
  $AssociationBlock = Read-DeployMasterDataBlock -Stream $Stream -Offset $RegistryBlock.EndOffset -Properties $Header.LzmaProperties -Limit $Locator.PackageDataOffset -MaximumBytes 4194304
  $FileAssociations = if ($AssociationBlock.Bytes.Length) { @(ConvertFrom-DeployMasterFileAssociationBlock -Bytes $AssociationBlock.Bytes -Route $Header.AssociationRoute) } else { @() }
  $Trailing = Read-DeployMasterTrailingRecord -Stream $Stream -Offset $AssociationBlock.EndOffset -Limit $Locator.PackageDataOffset -Properties $Header.LzmaProperties

  return [pscustomobject]@{
    ComponentBlock = $ComponentBlock; Components = $Components
    InstallTreeBlock = $InstallTreeBlock; InstallTree = $InstallTree
    RegistryBlock = $RegistryBlock; Registry = $Registry
    AssociationBlock = $AssociationBlock; FileAssociations = $FileAssociations
    TrailingMetadata = $Trailing
  }
}

function ConvertFrom-DeployMasterFileAssociationBlock {
  <#
  .SYNOPSIS
    Parse a structured DeployMaster file-type metadata record
  .PARAMETER Bytes
    Bounded format record or payload bytes interpreted by this function; the input array is not modified.
  .PARAMETER Route
    Catalog-selected string and record framing used by the current header profile.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [ValidateSet('Auto', 'LengthPrefixedUtf8', 'FormFeedDelimitedAnsi', 'ClassicFormFeedAnsi')][string]$Route = 'LengthPrefixedUtf8'
  )

  # The block begins with a bounded association count followed by sequential
  # variable-length records. Any trailing or truncated data rejects the block.
  if ($Bytes.Length -lt 2) { throw 'The DeployMaster file-type record is too small.' }
  $Utf8 = [Text.UTF8Encoding]::new($false, $true)
  $Cursor = 0
  $Count = [int]$Bytes[$Cursor++]
  if ($Count -lt 1 -or $Count -gt 64) { throw 'The DeployMaster file-type count is invalid.' }
  # Header74 spans the association serialization transition. Current records add a Boolean default
  # flag after the count; archived 7.2 media begins directly with a form-feed-terminated description.
  if ($Route -eq 'Auto') { $Route = $Cursor -lt $Bytes.Length -and $Bytes[$Cursor] -in 0, 1 ? 'LengthPrefixedUtf8' : 'FormFeedDelimitedAnsi' }

  function Read-DeployMasterAssociationUInt16([ref]$Position) {
    <#
    .SYNOPSIS
      Read a sequential unsigned 16-bit little-endian association field.
    .PARAMETER Position
      Mutable block-relative byte cursor advanced by two after a bounded read.
    #>
    if ($Position.Value + 2 -gt $Bytes.Length) { throw 'The DeployMaster file-type record is truncated.' }
    $Value = [uint16][BitConverter]::ToUInt16($Bytes, $Position.Value)
    $Position.Value += 2
    return $Value
  }
  function Read-DeployMasterAssociationInt16([ref]$Position) {
    <#
    .SYNOPSIS
      Read a sequential signed 16-bit little-endian association field.
    .PARAMETER Position
      Mutable block-relative byte cursor advanced by two after a bounded read.
    #>
    if ($Position.Value + 2 -gt $Bytes.Length) { throw 'The DeployMaster file-type record is truncated.' }
    $Value = [int16][BitConverter]::ToInt16($Bytes, $Position.Value)
    $Position.Value += 2
    return $Value
  }
  function Read-DeployMasterAssociationString([ref]$Position) {
    <#
    .SYNOPSIS
      Read a uint16-length-prefixed UTF-8 association string.
    .PARAMETER Position
      Mutable block-relative cursor advanced across the length field and string bytes.
    #>
    if ($Route -in 'FormFeedDelimitedAnsi', 'ClassicFormFeedAnsi') {
      $End = $Position.Value
      while ($End -lt $Bytes.Length -and $Bytes[$End] -ne 0x0C) { $End++ }
      if ($End -ge $Bytes.Length) { throw 'The legacy DeployMaster file-type string is not terminated.' }
      $Value = [Text.Encoding]::GetEncoding(1252).GetString($Bytes, $Position.Value, $End - $Position.Value)
      $Position.Value = $End + 1
      return $Value
    }
    $Length = [int](Read-DeployMasterAssociationUInt16 -Position $Position)
    if ($Position.Value + $Length -gt $Bytes.Length) { throw 'The DeployMaster file-type string is truncated.' }
    $Value = $Utf8.GetString($Bytes, $Position.Value, $Length)
    $Position.Value += $Length
    return $Value
  }

  $Associations = [Collections.Generic.List[object]]::new()
  # Each association contains architecture-specific icon references and a nested
  # action list. Preserve file indexes for later catalog resolution.
  for ($AssociationIndex = 0; $AssociationIndex -lt $Count; $AssociationIndex++) {
    if ($Route -in 'FormFeedDelimitedAnsi', 'ClassicFormFeedAnsi') {
      $CreateByDefault = $null
    } else {
      if ($Cursor -ge $Bytes.Length -or $Bytes[$Cursor] -notin 0, 1) { throw 'The DeployMaster file-type default flag is invalid.' }
      $CreateByDefault = [bool]$Bytes[$Cursor++]
    }
    $Description = Read-DeployMasterAssociationString -Position ([ref]$Cursor)
    $Extension = Read-DeployMasterAssociationString -Position ([ref]$Cursor)
    if ($Extension -notmatch '^\.[A-Za-z0-9][A-Za-z0-9._+-]{0,254}$') { throw 'The DeployMaster file-type extension is invalid.' }
    $Icon32FileIndex = Read-DeployMasterAssociationInt16 -Position ([ref]$Cursor)
    if ($Cursor -ge $Bytes.Length) { throw 'The DeployMaster 32-bit icon record is truncated.' }
    $Icon32ResourceIndex = [int]$Bytes[$Cursor++]
    if ($Route -eq 'ClassicFormFeedAnsi') {
      $Icon64FileIndex = -1
      $Icon64ResourceIndex = -1
    } else {
      $Icon64FileIndex = Read-DeployMasterAssociationInt16 -Position ([ref]$Cursor)
      if ($Cursor -ge $Bytes.Length) { throw 'The DeployMaster 64-bit icon record is truncated.' }
      $Icon64ResourceIndex = [int]$Bytes[$Cursor++]
    }
    if ($Cursor -ge $Bytes.Length) { throw 'The DeployMaster file-type action count is missing.' }
    $ActionCount = [int]$Bytes[$Cursor++]
    if ($ActionCount -gt 64) { throw 'The DeployMaster file-type action count is invalid.' }
    $Actions = [Collections.Generic.List[object]]::new()
    # Current actions carry separate x86/x64 executable indexes. Classic 2.x carries one x86 index;
    # normalize its absent x64 index to -1 and never invoke any recorded command.
    for ($ActionIndex = 0; $ActionIndex -lt $ActionCount; $ActionIndex++) {
      $ActionName = Read-DeployMasterAssociationString -Position ([ref]$Cursor)
      $Executable32FileIndex = Read-DeployMasterAssociationInt16 -Position ([ref]$Cursor)
      $Executable64FileIndex = $Route -eq 'ClassicFormFeedAnsi' ? -1 : (Read-DeployMasterAssociationInt16 -Position ([ref]$Cursor))
      $Actions.Add([pscustomobject]@{
          Name                  = $ActionName
          Executable32FileIndex = $Executable32FileIndex
          Executable64FileIndex = $Executable64FileIndex
          Parameters            = Read-DeployMasterAssociationString -Position ([ref]$Cursor)
        })
    }
    $Associations.Add([pscustomobject]@{
        Extension           = $Extension.ToLowerInvariant()
        FileExtension       = $Extension.TrimStart('.').ToLowerInvariant()
        Description         = $Description
        CreateByDefault     = $CreateByDefault
        Icon32FileIndex     = $Icon32FileIndex
        Icon32ResourceIndex = $Icon32ResourceIndex
        Icon64FileIndex     = $Icon64FileIndex
        Icon64ResourceIndex = $Icon64ResourceIndex
        Actions             = $Actions.ToArray()
      })
  }
  # Exact consumption authenticates the candidate found by the outer scanner and
  # prevents a valid prefix in unrelated package data from being accepted.
  if ($Cursor -ne $Bytes.Length) { throw 'The DeployMaster file-type record has trailing data.' }
  $Associations.ToArray()
}

function Get-DeployMasterFileAssociation {
  <#
  .SYNOPSIS
    Locate and decode structured file-type records in package metadata
  .PARAMETER Stream
    Caller-owned binary stream. Sequential readers may advance its byte position; helpers do not dispose it.
  .PARAMETER IdentityEnd
    Byte offset in the coordinate system named by this function: absolute file, PE/resource, overlay, or record relative.
  .PARAMETER PackageDataOffset
    Byte offset in the coordinate system named by this function: absolute file, PE/resource, overlay, or record relative.
  .PARAMETER Properties
    Format-specific field or value interpreted according to the current record/version.
  .PARAMETER MaximumBlocks
    Declared record count or parser count limit; malformed or excessive counts are rejected.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][long]$IdentityEnd,
    [Parameter(Mandatory)][long]$PackageDataOffset,
    [Parameter(Mandatory)][byte[]]$Properties,
    [ValidateRange(1, 128)][int]$MaximumBlocks = 128
  )

  $MetadataLength = $PackageDataOffset - $IdentityEnd
  if ($MetadataLength -le 0 -or $MetadataLength -gt 33554432 -or $MetadataLength -gt [int]::MaxValue) { return }
  $Metadata = Read-BinaryBytes -Stream $Stream -Offset $IdentityEnd -Count ([int]$MetadataLength)
  $Associations = [Collections.Generic.List[object]]::new()
  $DecodedBlockCount = 0
  for ($BlockOffset = 0; $BlockOffset + 9 -le $Metadata.Length -and $DecodedBlockCount -lt $MaximumBlocks; $BlockOffset++) {
    $RawSize = [uint32][BitConverter]::ToUInt32($Metadata, $BlockOffset)
    $StoredSize = [uint32][BitConverter]::ToUInt32($Metadata, $BlockOffset + 4)
    if ($RawSize -eq 0 -or $RawSize -gt 1048576 -or $StoredSize -eq 0 -or $StoredSize -gt $RawSize -or $BlockOffset + 8 + $StoredSize -gt $Metadata.Length) { continue }
    $InputStream = [IO.MemoryStream]::new($Metadata, $BlockOffset + 8, [int]$StoredSize, $false, $true)
    $OutputStream = [IO.MemoryStream]::new()
    try {
      $null = Expand-InstallerCompressedStream -Algorithm Lzma -Stream $InputStream -Destination $OutputStream -MaximumBytes 1048576 -Properties $Properties -CompressedSize $StoredSize -UncompressedSize $RawSize
      $DecodedBlockCount++
      $Parsed = @(ConvertFrom-DeployMasterFileAssociationBlock -Bytes $OutputStream.ToArray())
      foreach ($Association in $Parsed) { $Associations.Add($Association) }
      $BlockOffset += 7 + $StoredSize
    } catch {
    } finally {
      $InputStream.Dispose()
      $OutputStream.Dispose()
    }
  }
  $Associations.ToArray()
}

function Read-DeployMasterPackageData {
  <#
  .SYNOPSIS
    Parse one DeployMaster package from an already-open installer stream
  .PARAMETER Stream
    Caller-owned binary stream. Sequential readers may advance its byte position; helpers do not dispose it.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][IO.Stream]$Stream)

  $Locator = Get-DeployMasterPackageLocator -Stream $Stream
  $Header = Get-DeployMasterPackageHeader -Stream $Stream -Locator $Locator
  $IntegrityEnd = $Locator.PackageOffset + $Locator.IntegrityLength
  $LanguageBlock = Read-DeployMasterDataBlock -Stream $Stream -Offset $Header.LanguageBlockOffset -Properties $Header.LzmaProperties -Limit $IntegrityEnd
  $IdentityBlock = Read-DeployMasterDataBlock -Stream $Stream -Offset $LanguageBlock.EndOffset -Properties $Header.LzmaProperties -Limit $IntegrityEnd
  $Identity = ConvertFrom-DeployMasterIdentity -Bytes $IdentityBlock.Bytes -ScopeValue $Header.ScopeValue
  $Warnings = [Collections.Generic.List[object]]::new()
  if (-not $Identity.LocationMarkerMatchesScope) { $Warnings.Add((New-InstallerDiagnostic -Id 'DeployMaster.Scope.IdentityMarkerMismatch' -Source 'DeployMaster' -Message 'The DeployMaster identity scope marker does not match the package-control scope byte.' -Kind Mismatch -Areas Metadata, Installability -AffectedFields Scope -Evidence $Identity)) }
  try { $FileEntries = @(Get-DeployMasterFileEntry -Stream $Stream -Identity $Identity -IdentityEnd $IdentityBlock.EndOffset -PackageDataOffset $Locator.PackageDataOffset -Properties $Header.LzmaProperties -TableKind $Header.FileTableKind) }
  catch {
    $FileEntries = @()
    $Warnings.Add((New-InstallerDiagnostic -Id 'DeployMaster.Extraction.FileTableIncomplete' -Source 'DeployMaster' -Message "The DeployMaster payload file table was not decoded: $($_.Exception.Message)" -Kind Incomplete -Areas Metadata, Extraction -AffectedFields InstallationMetadata -Evidence $_.Exception.Message))
  }
  try {
    $StructuredMetadata = Read-DeployMasterStructuredRecord -Stream $Stream -Header $Header -Locator $Locator -IdentityEnd $IdentityBlock.EndOffset -FileEntries $FileEntries -ScopeValue $Identity.EffectiveScopeValue
    $FileAssociations = @($StructuredMetadata.FileAssociations)
  } catch {
    $StructuredError = $_.Exception.Message
    $StructuredMetadata = $null
    # Legacy packages predate some current metadata records. Preserve the proven association fallback
    # while reporting that the remaining behavioral model is incomplete.
    try { $FileAssociations = @(Get-DeployMasterFileAssociation -Stream $Stream -IdentityEnd $IdentityBlock.EndOffset -PackageDataOffset $Locator.PackageDataOffset -Properties $Header.LzmaProperties) }
    catch { $FileAssociations = @() }
    $PackageSettings = $null
    $Warnings.Add((New-InstallerDiagnostic -Id 'DeployMaster.Metadata.BehavioralStreamIncomplete' -Source 'DeployMaster' -Message "The DeployMaster behavioral metadata stream was not fully decoded: $StructuredError" -Kind Incomplete -Areas Metadata -AffectedFields RegistryWrites, FileExtensions, Protocols -Evidence $StructuredError))
  }
  $PackageSettings = $null
  if ($StructuredMetadata -and $Header.HasPackageSettings) {
    try {
      # The common record is three bytes. Portable-mode values other than Never append marker and
      # drive-policy bytes plus a compressed default-folder block; reading five bytes unconditionally
      # consumed the next record in ordinary 7.2/7.6 packages.
      $ConfigurationBytes = Read-BinaryBytes -Stream $Stream -Offset $IdentityBlock.EndOffset -Count 3
      if ($ConfigurationBytes[2] -gt 2) {
        throw 'The candidate package-settings bytes contain values outside the controlled option ranges.'
      }
      $PortableModeEnabled = $ConfigurationBytes[2] -ne 0
      $PortableBytes = if ($PortableModeEnabled) { Read-BinaryBytes -Stream $Stream -Offset ($IdentityBlock.EndOffset + 3) -Count 2 } else { [byte[]](0, 0) }
      if ($PortableBytes[0] -gt 2 -or $PortableBytes[1] -gt 1) { throw 'The candidate portable-settings bytes contain values outside the controlled option ranges.' }
      $PortableFolder = $null
      if ($PortableModeEnabled) {
        try {
          $PortableFolderBlock = Read-DeployMasterDataBlock -Stream $Stream -Offset ($IdentityBlock.EndOffset + 5) -Properties $Header.LzmaProperties -Limit $StructuredMetadata.ComponentBlock.Offset -MaximumBytes 65535
          $PortableFolder = (ConvertFrom-DeployMasterTextBlock -Bytes $PortableFolderBlock.Bytes).Text
        } catch {}
      }
      $PackageSettings = [pscustomobject]@{
        Flags                         = $ConfigurationBytes[0]
        IdentityPrompts               = [pscustomobject]@{
          AskName             = [bool]($ConfigurationBytes[1] -band 1)
          AskCompany          = [bool]($ConfigurationBytes[1] -band 2)
          AskSerialNumber     = [bool]($ConfigurationBytes[1] -band 4)
          AskRegistrationCode = [bool]($ConfigurationBytes[1] -band 8)
        }
        PortableInstallationMode      = switch ($ConfigurationBytes[2]) { 0 { 'Never' } 1 { 'UserChoice' } 2 { 'Always' } default { 'Unknown' } }
        PortableInstallationModeValue = $ConfigurationBytes[2]
        PortableMarkerMode            = switch ($PortableBytes[0]) { 0 { 'Never' } 1 { 'WhenAnyDriveIsAllowed' } 2 { 'Always' } default { 'Unknown' } }
        PortableMarkerModeValue       = $PortableBytes[0]
        PortableAllowAnyDrive         = [bool]$PortableBytes[1]
        PortableDefaultFolder         = $PortableFolder
      }
    } catch { $Warnings.Add((New-InstallerDiagnostic -Id 'DeployMaster.Metadata.PackageSettingsIncomplete' -Source 'DeployMaster' -Message "The DeployMaster current-generation package settings were not decoded: $($_.Exception.Message)" -Kind Incomplete -Areas Metadata, Installability -AffectedFields InstallerSwitches, InstallModes -Evidence $_.Exception.Message)) }
  }
  $RuntimeFeatures = [pscustomobject]@{
    PortableSwitch         = $false
    PortableSwitchAnalyzed = $false
    SkipElevationSwitch    = $false
    SkipElevationAnalyzed  = $false
  }
  # Command support lives in the compressed runtime, not the package header. Probe every relevant
  # token in one expansion and do not extrapolate /noadmin back to Header66, where it is absent.
  $RequestedRuntimeSwitches = [Collections.Generic.List[string]]::new()
  $RequestedRuntimeSwitches.Add('/noadmin')
  if ($PackageSettings -and $PackageSettings.PortableInstallationMode -ne 'Never') { $RequestedRuntimeSwitches.Add('/portable') }
  try {
    $RuntimeSwitchResults = @(Test-DeployMasterRuntimeSwitch -Stream $Stream -Header $Header -CommandLineSwitch $RequestedRuntimeSwitches.ToArray())
    $RuntimeFeatures.SkipElevationSwitch = $RuntimeSwitchResults[0]
    $RuntimeFeatures.SkipElevationAnalyzed = $true
    if ($RequestedRuntimeSwitches.Count -gt 1) {
      $RuntimeFeatures.PortableSwitch = $RuntimeSwitchResults[1]
      $RuntimeFeatures.PortableSwitchAnalyzed = $true
    }
  } catch {
    $Warnings.Add((New-InstallerDiagnostic -Id 'DeployMaster.Installability.RuntimeSwitchInspectionIncomplete' -Source 'DeployMaster' -Message "The DeployMaster runtime core could not be inspected for version-dependent command-line switches: $($_.Exception.Message)" -Kind Incomplete -Areas Installability -AffectedFields InstallerSwitches, InstallModes -Evidence $_.Exception.Message))
  }

  [pscustomobject]@{
    Locator            = $Locator
    Header             = $Header
    LanguageBlock      = $LanguageBlock
    IdentityBlock      = $IdentityBlock
    Identity           = $Identity
    FileEntries        = $FileEntries
    FileAssociations   = $FileAssociations
    StructuredMetadata = $StructuredMetadata
    Settings           = $PackageSettings
    RuntimeFeatures    = $RuntimeFeatures
    Diagnostics        = @(ConvertTo-InstallerDiagnostic -InputObject @(@($Warnings)) -Source 'DeployMaster' -Kind Incomplete -Areas Metadata)
  }
}

Export-ModuleMember -Function Get-DeployMasterCatalogVersion, Get-DeployMasterClassicRoute, ConvertTo-DeployMasterEnvironmentPath, Get-DeployMasterScopeInfo, Get-DeployMasterPackageLocator, Get-DeployMasterPackageHeader, Test-DeployMasterRuntimeSwitch, Read-DeployMasterDataBlock, ConvertFrom-DeployMasterIdentity, Get-DeployMasterFileNameBlock, Get-DeployMasterFileEntry, Read-DeployMasterStreamString, ConvertFrom-DeployMasterComponentBlock, ConvertFrom-DeployMasterInstallTreeBlock, ConvertFrom-DeployMasterRegistryBlock, ConvertFrom-DeployMasterTextBlock, ConvertFrom-DeployMasterDotNetFrameworkRecord, Read-DeployMasterTrailingRecord, Find-DeployMasterComponentBlock, Read-DeployMasterStructuredRecord, ConvertFrom-DeployMasterFileAssociationBlock, Get-DeployMasterFileAssociation, Read-DeployMasterPackageData
