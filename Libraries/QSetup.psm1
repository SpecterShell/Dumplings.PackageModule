# SPDX-License-Identifier: Apache-2.0
# Static QSetup parser. QSetup EXE packages store length-prefixed zlib records
# after the PE image; Setup.txt contains explicit project and ARP directives.
# Binary structure consumed here (overlay-relative, LE integers):
#
#   PE overlay: Version:u32 LE, Format:u8, PreambleLength:u32 LE,
#               UTF-8 |...exe| preamble
#   records:    [CompressedLength:u32 LE][zlib -> |Name[*]?|Stamp| + bytes]*
#
# Every record advances by exactly 4 + CompressedLength. Setup.txt is interpreted
# only from a complete framed record. Preamble, count, header, input/output, next
# offset, and extraction path limits reject malformed packages.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:QSetupMaximumRecordBytes = 2147483648
$Script:QSetupMaximumConfigurationBytes = 16777216
$Script:QSetupMaximumRecords = 100000

function Get-QSetupRecordStartOffset {
  <#
  .SYNOPSIS
    Validate the QSetup overlay preamble and return its first record offset
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)

  $File = Get-Item -LiteralPath $Path -Force
  $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    # QSetup starts its package at the PE overlay. Validate every preamble field
    # and its executable-name marker before trusting the first record offset.
    $OverlayOffset = Get-PEOverlayOffset -Stream $Stream
    if ($OverlayOffset -le 0 -or $OverlayOffset + 13 -gt $Stream.Length) { throw 'The QSetup PE has no valid package overlay' }
    $Version = [uint32](Read-BinaryInteger -Stream $Stream -Offset $OverlayOffset -Size 4)
    $Format = [byte](Read-BinaryInteger -Stream $Stream -Offset ($OverlayOffset + 4) -Size 1)
    $PreambleLength = [uint32](Read-BinaryInteger -Stream $Stream -Offset ($OverlayOffset + 5) -Size 4)
    if ($Version -eq 0 -or $Format -eq 0 -or $PreambleLength -eq 0 -or $PreambleLength -gt 1048576 -or $PreambleLength -gt $Stream.Length - $OverlayOffset - 9) {
      throw 'The QSetup overlay preamble is invalid'
    }
    $Preamble = [Text.Encoding]::UTF8.GetString((Read-BinaryBytes -Stream $Stream -Offset ($OverlayOffset + 9) -Count ([int]$PreambleLength)))
    if ($Preamble -notmatch '^\|.*\.exe\|') { throw 'The QSetup overlay preamble marker is invalid' }
    [pscustomobject]@{
      OverlayOffset     = [long]$OverlayOffset
      RecordStartOffset = [long]($OverlayOffset + 9 + $PreambleLength)
      FormatVersion     = $Version
      CompressionFormat = $Format
      Preamble          = $Preamble
    }
  } finally { $Stream.Dispose() }
}

function Read-QSetupRecord {
  <#
  .SYNOPSIS
    Read one bounded QSetup zlib record header and optional content
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER Offset
    Byte offset in the coordinate system named by this function: absolute file, PE/resource, overlay, or record relative.
  .PARAMETER ReadContent
    Controls whether bounded entry content is decoded in addition to catalog metadata.
  .PARAMETER MaximumContentBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][long]$Offset,
    [switch]$ReadContent,
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumContentBytes = $Script:QSetupMaximumConfigurationBytes
  )

  $File = Get-Item -LiteralPath $Path -Force
  $Source = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    if ($Offset -lt 0 -or $Offset + 4 -gt $Source.Length) { throw 'The QSetup record length is truncated' }
    # Each record is independently framed by a compressed length, so malformed
    # data cannot make the decoder consume the next record.
    $CompressedLength = [uint32](Read-BinaryInteger -Stream $Source -Offset $Offset -Size 4)
    if ($CompressedLength -eq 0 -or $CompressedLength -gt $Source.Length - $Offset - 4) { throw 'The QSetup record data is truncated' }
    $CompressedRange = New-BoundedReadStream -Stream $Source -Offset ($Offset + 4) -Length $CompressedLength -LeaveOpen
    $Decoder = New-InstallerDecompressionStream -Algorithm Zlib -Stream $CompressedRange -LeaveOpen
    try {
      # Decode only through the third pipe delimiter to enumerate a record. The
      # potentially large body is materialized only when the caller requests it.
      $HeaderBytes = [System.Collections.Generic.List[byte]]::new()
      $PipeCount = 0
      while ($HeaderBytes.Count -lt 4096 -and $PipeCount -lt 3) {
        $Value = $Decoder.ReadByte()
        if ($Value -lt 0) { break }
        $HeaderBytes.Add([byte]$Value)
        if ($Value -eq 0x7C) { $PipeCount++ }
      }
      $Header = [Text.Encoding]::ASCII.GetString($HeaderBytes.ToArray())
      $Match = [regex]::Match($Header, '^\|(?<Name>[^|*]+)(?<Required>\*)?\|(?<Stamp>\d+)\|$')
      if (-not $Match.Success) { throw 'The QSetup record header is invalid' }

      $Content = $null
      $ContentLength = $null
      if ($ReadContent) {
        # Setup.txt and other requested bodies are accumulated under an explicit
        # expanded-size limit to reject zlib bombs deterministically.
        $Output = [IO.MemoryStream]::new()
        try {
          $Buffer = [byte[]]::new(1048576)
          $Written = 0L
          while (($Read = $Decoder.Read($Buffer, 0, $Buffer.Length)) -gt 0) {
            $Written += $Read
            if ($Written -gt $MaximumContentBytes) { throw "The QSetup record exceeds the $MaximumContentBytes-byte content limit" }
            $Output.Write($Buffer, 0, $Read)
          }
          $Content = $Output.ToArray()
          $ContentLength = $Written
        } finally { $Output.Dispose() }
      }
      [pscustomobject]@{
        Name             = $Match.Groups['Name'].Value
        Required         = $Match.Groups['Required'].Success
        Stamp            = $Match.Groups['Stamp'].Value
        Offset           = [long]$Offset
        CompressedLength = [long]$CompressedLength
        NextOffset       = [long]($Offset + 4 + $CompressedLength)
        ContentLength    = $ContentLength
        Content          = $Content
      }
    } finally { $Decoder.Dispose(); $CompressedRange.Dispose() }
  } finally { $Source.Dispose() }
}

function Get-QSetupLayout {
  <#
  .SYNOPSIS
    Enumerate bounded QSetup record headers without expanding payload bodies
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER MaximumRecords
    Declared record count or parser count limit; malformed or excessive counts are rejected.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [ValidateRange(1, 100000)][int]$MaximumRecords = $Script:QSetupMaximumRecords
  )

  $File = Get-Item -LiteralPath $Path -Force
  $Preamble = Get-QSetupRecordStartOffset -Path $File.FullName
  $Records = [System.Collections.Generic.List[object]]::new()
  $Warnings = [System.Collections.Generic.List[string]]::new()
  $Offset = $Preamble.RecordStartOffset
  # Records are physically adjacent; advance by the declared compressed extent
  # and stop at the first malformed or non-advancing frame.
  while ($Offset + 4 -le $File.Length -and $Records.Count -lt $MaximumRecords) {
    try { $Record = Read-QSetupRecord -Path $File.FullName -Offset $Offset } catch { $Warnings.Add($_.Exception.Message); break }
    $Records.Add($Record)
    if ($Record.NextOffset -le $Offset) { $Warnings.Add('The QSetup record table does not advance.'); break }
    $Offset = $Record.NextOffset
  }
  if ($Records.Count -eq $MaximumRecords -and $Offset -lt $File.Length) { $Warnings.Add("The QSetup record count exceeds the $MaximumRecords-record limit.") }
  [pscustomobject]@{
    Preamble        = $Preamble
    Records         = $Records.ToArray()
    Complete        = $Offset -eq $File.Length
    ParsedEndOffset = [long]$Offset
    Warnings        = @($Warnings)
  }
}

function ConvertFrom-QSetupDirectiveText {
  <#
  .SYNOPSIS
    Parse literal SET_* directives from QSetup Setup.txt
  .PARAMETER Content
    Raw text to parse as format metadata without executing embedded commands.
  #>
  [OutputType([hashtable])]
  param ([Parameter(Mandatory)][string]$Content)

  $Result = @{}
  # Parse only literal SET_* statements. QSetup expressions or executable
  # actions are not evaluated by the static parser.
  foreach ($Line in ($Content.TrimStart([char]0, [char]0xFEFF) -split "`r?`n")) {
    $Trimmed = $Line.Trim()
    if (-not $Trimmed -or $Trimmed.StartsWith('//')) { continue }
    $Match = [regex]::Match($Trimmed, '^(?<Name>SET_[A-Z0-9_]+)(?:\((?<Value>.*)\))?;?$', [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if (-not $Match.Success) { continue }
    $Name = $Match.Groups['Name'].Value.ToUpperInvariant()
    $Value = if ($Match.Groups['Value'].Success) { $Match.Groups['Value'].Value } else { $true }
    if (-not $Result.ContainsKey($Name)) { $Result[$Name] = [System.Collections.Generic.List[object]]::new() }
    $Result[$Name].Add($Value)
  }
  return $Result
}

function Get-QSetupDirectiveValue {
  <#
  .SYNOPSIS
    Return the first literal value for a parsed QSetup directive
  .PARAMETER Directive
    Format-specific field or value interpreted according to the current record/version.
  .PARAMETER Name
    Exact name or wildcard used to select format records or payload entries.
  #>
  param ([Parameter(Mandatory)][hashtable]$Directive, [Parameter(Mandatory)][string]$Name)
  if (-not $Directive.ContainsKey($Name)) { return $null }
  return @($Directive[$Name])[0]
}

function ConvertTo-QSetupRegistryEvidence {
  <#
  .SYNOPSIS
    Convert explicit QSetup ARP and association directives to registry evidence
  .PARAMETER Directive
    Format-specific field or value interpreted according to the current record/version.
  .PARAMETER Scope
    Scope or elevation evidence used to classify user, machine, or conditional installation.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][hashtable]$Directive, [AllowNull()][string]$Scope)

  $Root = if ($Scope -eq 'machine') { 'HKLM' } elseif ($Scope -eq 'user') { 'HKCU' } else { $null }
  if (-not $Root) { return }
  $Writes = [System.Collections.Generic.List[object]]::new()
  $DisplayName = Get-QSetupDirectiveValue -Directive $Directive -Name 'SET_ADD_REMOVE_PROGRAMS_DISPLAY_NAME'
  # An ARP entry exists only when both uninstall generation and Add/Remove
  # registration are enabled; a display-name directive alone is insufficient.
  $WritesArp = $Directive.ContainsKey('SET_CREATE_UNINSTALL') -and $Directive.ContainsKey('SET_ADD_UNINSTALL_TO_ADD_REMOVE_PROGRAMS') -and $DisplayName
  if ($WritesArp) {
    $UninstallKey = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$DisplayName"
    foreach ($Value in @(
        @{ Name = 'DisplayName'; Value = $DisplayName },
        @{ Name = 'DisplayVersion'; Value = Get-QSetupDirectiveValue -Directive $Directive -Name 'SET_PROG_VERSION' },
        @{ Name = 'Publisher'; Value = Get-QSetupDirectiveValue -Directive $Directive -Name 'SET_COMPANY_NAME' },
        @{ Name = 'DisplayIcon'; Value = Get-QSetupDirectiveValue -Directive $Directive -Name 'SET_ADD_REMOVE_PROGRAMS_DISPLAY_ICON' }
      )) {
      if ($null -ne $Value.Value) { $Writes.Add([pscustomobject]@{ Root = $Root; Key = $UninstallKey; Name = $Value.Name; Value = $Value.Value; Type = 'REG_SZ' }) }
    }
  }

  # Association records are pipe-delimited structured directives. Emit only
  # literal, syntactically valid extensions and their explicit ProgID command.
  foreach ($Association in @($Directive['SET_ADD_ASSOCIATION_ITEM'])) {
    $Fields = @($Association -split '\|')
    if ($Fields.Count -lt 7) { continue }
    $ProgId = $Fields[1].Trim()
    $Description = $Fields[2].Trim()
    $Extension = $Fields[3].Trim()
    $Executable = $Fields[5].Trim()
    if ($Extension -notmatch '^\.[A-Za-z0-9][A-Za-z0-9._+-]*$' -or [string]::IsNullOrWhiteSpace($ProgId)) { continue }
    $Writes.Add([pscustomobject]@{ Root = $Root; Key = "Software\Classes\$Extension"; Name = $null; Value = $ProgId; Type = 'REG_SZ' })
    $Writes.Add([pscustomobject]@{ Root = $Root; Key = "Software\Classes\$ProgId"; Name = $null; Value = $Description; Type = 'REG_SZ' })
    if ($Executable) { $Writes.Add([pscustomobject]@{ Root = $Root; Key = "Software\Classes\$ProgId\shell\open\command"; Name = $null; Value = "`"$Executable`" `"%1`""; Type = 'REG_SZ' }) }
  }
  return $Writes.ToArray()
}

function Get-QSetupInfo {
  <#
  .SYNOPSIS
    Read QSetup project, ARP, scope, architecture, and association metadata
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)

  process {
    $File = Get-Item -LiteralPath $Path -Force
    $Layout = Get-QSetupLayout -Path $File.FullName
    # Setup.txt is the authoritative project metadata record. Generic payload
    # strings never participate in identity, scope, or ARP inference.
    $SetupRecord = $Layout.Records | Where-Object Name -ieq 'Setup.txt' | Select-Object -First 1
    if (-not $SetupRecord) { throw 'The QSetup package does not contain Setup.txt in its parsed records' }
    $SetupData = Read-QSetupRecord -Path $File.FullName -Offset $SetupRecord.Offset -ReadContent -MaximumContentBytes $Script:QSetupMaximumConfigurationBytes
    $SetupText = [Text.Encoding]::UTF8.GetString($SetupData.Content).TrimStart([char]0, [char]0xFEFF)
    $Directive = ConvertFrom-QSetupDirectiveText -Content $SetupText
    if (-not $Directive.ContainsKey('SET_COMPOSER_BUILD')) { throw 'The Setup.txt record does not contain QSetup composer evidence' }

    # Scope and ARP behavior come from explicit composer directives; unresolved
    # behavior is returned as null for VM review rather than guessed from paths.
    $Scope = if ($Directive.ContainsKey('SET_ALL_USERS')) { 'machine' } elseif ($Directive.ContainsKey('SET_CURRENT_USER')) { 'user' } else { $null }
    $DisplayName = Get-QSetupDirectiveValue -Directive $Directive -Name 'SET_ADD_REMOVE_PROGRAMS_DISPLAY_NAME'
    if (-not $DisplayName) { $DisplayName = Get-QSetupDirectiveValue -Directive $Directive -Name 'SET_PROG_NAME' }
    $WritesAppsAndFeaturesEntry = $Directive.ContainsKey('SET_CREATE_UNINSTALL') -and $Directive.ContainsKey('SET_ADD_UNINSTALL_TO_ADD_REMOVE_PROGRAMS')
    $ProductCode = if ($WritesAppsAndFeaturesEntry) { Get-QSetupDirectiveValue -Directive $Directive -Name 'SET_ADD_REMOVE_PROGRAMS_DISPLAY_NAME' } else { $null }
    $RegistryWrites = @(ConvertTo-QSetupRegistryEvidence -Directive $Directive -Scope $Scope)
    $RegistryAssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite $RegistryWrites
    # Architecture evidence is deliberately conservative: only an exclusively
    # 64-bit OS list proves x64 support in this metadata vocabulary.
    $AllowedOs = [string](Get-QSetupDirectiveValue -Directive $Directive -Name 'SET_ALLOWED_OS')
    $SupportedArchitectures = if ($AllowedOs -match '(?i)\.64' -and $AllowedOs -notmatch '(?i)(?:^|,)(?:XP|Vista|7|8|10|11)(?:,|$)') { @('x64') } else { @() }
    $Warnings = [System.Collections.Generic.List[string]]::new()
    foreach ($Warning in $Layout.Warnings) { $Warnings.Add($Warning) }
    if (-not $Layout.Complete) { $Warnings.Add('The QSetup record table is incomplete or has trailing data; metadata from the explicit Setup.txt record remains available, but full extraction requires the complete installer.') }
    if (-not $Scope) { $Warnings.Add('QSetup scope is not explicit in Setup.txt and requires VM validation.') }
    if ($Directive.ContainsKey('SET_PERFORM_EXECUTE_OP')) { $Warnings.Add('QSetup defines custom execution actions. Inspect nested executables and action arguments before finalizing dependencies or switches.') }

    [pscustomobject][ordered]@{
      Path                         = $File.FullName
      InstallerType                = 'QSetup'
      ProductCode                  = $ProductCode
      UpgradeCode                  = $null
      DisplayName                  = $DisplayName
      DisplayVersion               = Get-QSetupDirectiveValue -Directive $Directive -Name 'SET_PROG_VERSION'
      Publisher                    = Get-QSetupDirectiveValue -Directive $Directive -Name 'SET_COMPANY_NAME'
      Scope                        = $Scope
      DefaultInstallLocation       = Get-QSetupDirectiveValue -Directive $Directive -Name 'SET_TARGET_DIR'
      WritesAppsAndFeaturesEntry   = [bool]$WritesAppsAndFeaturesEntry
      AppsAndFeaturesProductCode   = $WritesAppsAndFeaturesEntry ? $ProductCode : $null
      AppsAndFeaturesInstallerType = $WritesAppsAndFeaturesEntry ? 'exe' : $null
      Warnings                     = [string[]]@($Warnings | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
      UnresolvedFields             = [string[]]@()
      PublisherUrl                 = Get-QSetupDirectiveValue -Directive $Directive -Name 'SET_COMPANY_URL'
      ProjectName                  = Get-QSetupDirectiveValue -Directive $Directive -Name 'SET_PROJECT_NAME'
      ProjectStamp                 = Get-QSetupDirectiveValue -Directive $Directive -Name 'SET_PC_STAMP'
      ComposerBuild                = Get-QSetupDirectiveValue -Directive $Directive -Name 'SET_COMPOSER_BUILD'
      MainExecutable               = Get-QSetupDirectiveValue -Directive $Directive -Name 'SET_PROG_EXE_NAME'
      SupportedScopes              = if ($Scope) { @($Scope) } else { @() }
      SupportedArchitectures       = $SupportedArchitectures
      AllowedOperatingSystems      = $AllowedOs
      RegistryWrites               = $RegistryWrites
      RegistryAssociationInfo      = $RegistryAssociationInfo
      Protocols                    = $RegistryAssociationInfo.Protocols
      FileExtensions               = $RegistryAssociationInfo.FileExtensions
      Records                      = @($Layout.Records | Select-Object Name, Required, Stamp, Offset, CompressedLength)
      ExtractedFiles               = @($Layout.Records.Name)
      SetupDirectives              = $Directive
      ParserVersionInfo            = [pscustomobject]@{ Parser = 'Dumplings.PackageModule.QSetup'; ParserMajor = 1; Sources = @('validated QSetup zlib record table', 'Setup.txt directives') }
    }
  }
}

function Export-QSetupRecord {
  <#
  .SYNOPSIS
    Export one QSetup record body to a validated destination
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER Record
    Current structured format node or record being interpreted.
  .PARAMETER DestinationPath
    Destination path for bounded extraction or decoded output; payload-relative names are resolved beneath this path.
  .PARAMETER MaximumBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  [OutputType([System.IO.FileInfo])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][psobject]$Record,
    [Parameter(Mandatory)][string]$DestinationPath,
    [Parameter(Mandatory)][ValidateRange(1, [long]::MaxValue)][long]$MaximumBytes
  )

  $Source = [IO.File]::Open((Get-Item -LiteralPath $Path -Force).FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    $CompressedRange = New-BoundedReadStream -Stream $Source -Offset ($Record.Offset + 4) -Length $Record.CompressedLength -LeaveOpen
    $Decoder = New-InstallerDecompressionStream -Algorithm Zlib -Stream $CompressedRange -LeaveOpen
    try {
      $PipeCount = 0
      $HeaderLength = 0
      # Consume the metadata prefix before exporting the remaining decoded bytes
      # as the actual file body named by the validated catalog record.
      while ($HeaderLength -lt 4096 -and $PipeCount -lt 3) { $Value = $Decoder.ReadByte(); if ($Value -lt 0) { break }; $HeaderLength++; if ($Value -eq 0x7C) { $PipeCount++ } }
      if ($PipeCount -ne 3) { throw 'The QSetup record header is invalid during extraction' }
      $OutputPath = Resolve-SafeExtractionPath -DestinationPath $DestinationPath -RelativePath $Record.Name
      $Parent = [IO.Path]::GetDirectoryName($OutputPath)
      if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
      $Output = [IO.File]::Open($OutputPath, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
      try {
        $null = Copy-BoundedStream -Source $Decoder -Destination $Output -MaximumBytes $MaximumBytes
      } finally { $Output.Dispose() }
      return Get-Item -LiteralPath $OutputPath -Force
    } finally { $Decoder.Dispose(); $CompressedRange.Dispose() }
  } finally { $Source.Dispose() }
}

function Expand-QSetupInstaller {
  <#
  .SYNOPSIS
    Extract QSetup zlib records without executing the installer
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER DestinationPath
    Destination path for bounded extraction or decoded output; payload-relative names are resolved beneath this path.
  .PARAMETER Name
    Exact name or wildcard used to select format records or payload entries.
  .PARAMETER MaximumExpandedBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  [OutputType([System.IO.FileInfo[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [string]$Name = '*',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 17179869184
  )

  process {
    $Layout = Get-QSetupLayout -Path $Path
    if (-not $Layout.Complete) { throw "The QSetup record table is incomplete: $($Layout.Warnings -join '; ')" }
    if ([string]::IsNullOrWhiteSpace($DestinationPath)) { $DestinationPath = Join-Path ([IO.Path]::GetTempPath()) ("Dumplings-QSetup-$([guid]::NewGuid().ToString('N'))") }
    $null = New-Item -Path $DestinationPath -ItemType Directory -Force
    $Written = 0L
    $Result = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
    # Enforce one aggregate output budget across all selected records, not a new
    # full allowance for each independently compressed member.
    foreach ($Record in $Layout.Records) {
      if (-not (Test-ExtractionPattern -Path $Record.Name -Pattern $Name)) { continue }
      $Remaining = $MaximumExpandedBytes - $Written
      if ($Remaining -le 0) { throw 'QSetup extraction exceeds the configured output limit' }
      $File = Export-QSetupRecord -Path $Path -Record $Record -DestinationPath $DestinationPath -MaximumBytes $Remaining
      $Written += $File.Length
      $Result.Add($File)
    }
    if ($Result.Count -eq 0) { throw "No QSetup records matched '$Name'" }
    return $Result.ToArray()
  }
}

function Test-QSetup {
  <#
  .SYNOPSIS
    Test whether a file contains a parseable QSetup project
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([bool])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { try { $null = Get-QSetupInfo -Path $Path; return $true } catch { return $false } }
}

function Read-ProtocolsFromQSetup {
  <#
  .SYNOPSIS
    Read literal URL protocol names from QSetup registry evidence
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-QSetupInfo -Path $Path).Protocols }
}

function Read-FileExtensionsFromQSetup {
  <#
  .SYNOPSIS
    Read literal file extensions from QSetup association directives
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-QSetupInfo -Path $Path).FileExtensions }
}

function Read-ProductVersionFromQSetup {
  <#
  .SYNOPSIS
    Read the QSetup project version
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-QSetupInfo -Path $Path).DisplayVersion }
}

function Read-ProductNameFromQSetup {
  <#
  .SYNOPSIS
    Read the QSetup project display name
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-QSetupInfo -Path $Path).DisplayName }
}

function Read-PublisherFromQSetup {
  <#
  .SYNOPSIS
    Read the QSetup project publisher
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-QSetupInfo -Path $Path).Publisher }
}

function Read-ProductCodeFromQSetup {
  <#
  .SYNOPSIS
    Read the explicit QSetup Apps & Features key name
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-QSetupInfo -Path $Path).ProductCode }
}

function Read-ScopeFromQSetup {
  <#
  .SYNOPSIS
    Read scope from explicit QSetup all-users/current-user directives
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-QSetupInfo -Path $Path).Scope }
}

Export-ModuleMember -Function Get-QSetupInfo, Expand-QSetupInstaller, Test-QSetup, Read-ProtocolsFromQSetup, Read-FileExtensionsFromQSetup, Read-ProductVersionFromQSetup, Read-ProductNameFromQSetup, Read-PublisherFromQSetup, Read-ProductCodeFromQSetup, Read-ScopeFromQSetup
