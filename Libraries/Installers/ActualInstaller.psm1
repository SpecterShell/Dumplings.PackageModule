# SPDX-License-Identifier: Apache-2.0
#
# Actual Installer parser, independently implemented from observed media and
# the public builder documentation:
# - https://www.actualinstaller.com/help/command-line.html
# - https://www.actualinstaller.com/help/installer-variables.html
# - https://www.actualinstaller.com/help/files-and-folders.html
# - https://www.actualinstaller.com/help/registry.html
# - https://www.actualinstaller.com/help/setup-parameters.html
# - https://www.actualinstaller.com/help/commands.html
# - https://www.actualinstaller.com/help/64-bit-installation.html
# - https://www.actualinstaller.com/articles/how-to-create-update-installer.html
#
# Binary structures consumed by this module:
#
#   Actual Installer 3.x / 4.x
#   PE image
#   `-- overlay
#       +-- metadata CAB (setup.ini or aisetup.ini)
#       +-- payload CAB 0 (one installed file)
#       +-- payload CAB 1
#       `-- ...
#
#   Actual Installer 5.x
#   PE image
#   `-- overlay
#       +-- payload CAB 0 (one installed file)
#       +-- ...
#       `-- metadata CAB (aisetup.ini, languages, helper templates)
#
#   Actual Installer 6.x and later
#   PE image
#   `-- overlay
#       +-- payload ZIP (decimal entry names index [Files])
#       `-- metadata ZIP (aisetup.ini, languages, helper templates)
#
#   Setup EXE + Data
#   +-- PE image
#   |   +-- optional numbered ZIP entries for generated outputs
#   |   `-- metadata ZIP (aisetup.ini)
#   `-- companion 7z/LZMA -> source-directory tree installed below InstallDir
#
# Cabinet offsets are absolute file offsets. CFHEADER.cbCabinet bounds each
# cabinet; CFHEADER.coffFiles points to repeated CFFILE records. ZIP ranges are
# independently derived from each archive's central directory and EOCD. The INI
# [Files] key is the logical payload index and its value begins with the target
# path. No installer or extracted payload is loaded or executed.

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:ActualInstallerMaximumConfigurationBytes = 4MB
$Script:ActualInstallerMaximumContainers = 4096
$Script:ActualInstallerMaximumEntries = 65536
$Script:ActualInstallerMaximumAnalysisFiles = 32
$Script:ActualInstallerMaximumAnalysisBytes = 64MB
$Script:ActualInstallerCatalog = Import-PowerShellDataFile -LiteralPath (Join-Path $PSScriptRoot 'ActualInstallerFormatCatalog.psd1')
$Script:ActualInstallerExitCodeEvidence = [ordered]@{
  0   = 'Installation completed successfully'
  1   = 'Setup media is corrupt'
  2   = 'The unelevated process exited after starting an elevated child'
  3   = 'Custom setup font registration failed'
  4   = 'The selected language file was not found'
  5   = 'A required prerequisite was not installed'
  6   = 'Insufficient disk space'
  7   = 'Required network access failed'
  8   = 'The user cancelled while setup was closing a running application'
  9   = 'Installation failed while applying changes'
  10  = 'Installation completed with a noncritical warning'
  11  = 'The user cancelled before installation'
  12  = 'An update-only setup did not find the installed application'
  14  = 'The installed application version is outside the update range'
  15  = 'A custom-variable HALT operation stopped setup'
  16  = 'A command HALT operation stopped setup'
  17  = 'A newer application version is already installed'
  18  = 'The companion data file for Setup EXE + Data was not found'
  19  = 'A pre-install update check found a newer release and stopped setup'
  21  = 'The temporary directory could not be created'
  22  = 'The temporary ZIP could not be created'
  23  = 'The temporary payload could not be extracted'
  24  = 'The operating system is not 64-bit'
  25  = 'The operating system is not 32-bit'
  26  = 'The Windows version is unsupported'
  27  = 'Silent installation is disabled by compiled setup policy'
  28  = 'The installation directory is empty'
  29  = 'A required custom component is not selected'
  99  = 'Setup initialization failed'
  100 = 'The setup file could not be opened because access was denied'
}

function Test-ActualInstallerBooleanValue {
  <#
  .SYNOPSIS
    Interpret the Boolean spellings emitted by Actual Installer project data.
  .PARAMETER Value
    Configuration value to interpret.
  .PARAMETER Default
    Value returned when the configuration value is absent or unrecognized.
  #>
  [OutputType([bool])]
  param (
    [AllowNull()][object]$Value,
    [bool]$Default = $false
  )

  if ($null -eq $Value) { return $Default }
  switch -Regex ([string]$Value) {
    '^(?i:1|yes|true|on)$' { return $true }
    '^(?i:0|no|false|off)$' { return $false }
    default { return $Default }
  }
}

function ConvertFrom-ActualInstallerEncodedField {
  <#
  .SYNOPSIS
    Decode the bytewise XOR-2 field encoding used by selected later builders.
  .PARAMETER Value
    One already-delimited table field. Plain fields are returned unchanged.
  .OUTPUTS
    An object containing the effective value and whether the transform was used.
  #>
  [OutputType([pscustomobject])]
  param ([AllowNull()][string]$Value)

  if ([string]::IsNullOrEmpty($Value)) { return [pscustomobject]@{ Value = $Value; IsEncoded = $false } }
  $Characters = [char[]]$Value
  for ($Index = 0; $Index -lt $Characters.Length; $Index++) { $Characters[$Index] = [char]([int]$Characters[$Index] -bxor 2) }
  $Decoded = -join $Characters

  # Actual Installer applies this transform to command fields in observed 8.x
  # and 9.x media. Require a documented command token, URL, path, switch, or
  # angle-bracket variable after decoding so arbitrary user text is untouched.
  $Recognized = '(?i)^(?:DOWNLOAD:|ZIP:|WOW64ON$|WOW64OFF$|GETVARIABLES$|SETCURRENTDIR$|CMDVAR$|https?://|[A-Z]:\\|\\\\|[/-][A-Z0-9])|(?:^|[\s"''])(?:[A-Z]:\\|<(?:(?:INSTALL|SETUPTEMP|PROGRAMFILES|SYSTEM|WINDOWS|APP)[^>]*|MAINEXE(?:CUTABLE)?|PUBLISHER|COMPANYNAME|GUID)>)(?:\\|\b|$)'
  if ($Decoded -match $Recognized -and $Value -notmatch $Recognized) { return [pscustomobject]@{ Value = $Decoded; IsEncoded = $true } }
  return [pscustomobject]@{ Value = $Value; IsEncoded = $false }
}

function Get-ActualInstallerSetupParameterInfo {
  <#
  .SYNOPSIS
    Interpret documented flags compiled into the free-form SetupParameters field.
  .PARAMETER Setup
    Parsed [Setup] section.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][Collections.IDictionary]$Setup)

  $Raw = [string](Get-DictionaryValue -Dictionary $Setup -Name @('SetupParameters'))
  $Tokens = [Collections.Generic.List[string]]::new()
  foreach ($Match in [regex]::Matches($Raw, '(?:^|\s)(?<Token>-[^\s]+)')) { $Tokens.Add($Match.Groups['Token'].Value) }
  $TokenSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($Token in $Tokens) { $null = $TokenSet.Add($Token) }
  $HasUserInformationDialog = Test-ActualInstallerBooleanValue -Value (Get-DictionaryValue -Dictionary $Setup -Name @('DialogUserInfo'))
  $AllowsSilent = -not $TokenSet.Contains('-nosilent') -and (-not $HasUserInformationDialog -or $TokenSet.Contains('-silentinstalluserinfo'))

  [pscustomobject]@{
    Raw                                     = $Raw
    Tokens                                  = $Tokens.ToArray()
    AllowsSilent                            = $AllowsSilent
    HasUserInformationDialog                = $HasUserInformationDialog
    AllowsSilentUserInformation             = $TokenSet.Contains('-silentinstalluserinfo')
    SuppressesCommandsInSilent              = $TokenSet.Contains('-nocmdifsilent')
    SuppressesCommandsInUpdate              = $TokenSet.Contains('-nocmdifupdate')
    UsesSilentUninstallerAfterSilentInstall = $TokenSet.Contains('-silentuninst')
    IncludesVersionInDisplayName            = $TokenSet.Contains('-useappver')
    DisablesMachineToUserRegistryFallback   = $TokenSet.Contains('-noChangeRootKey')
    IgnoresRegistryWriteErrors              = $TokenSet.Contains('-IgnoreRegistryWriteErrors')
    UsesElevatedAccountDirectories          = $TokenSet.Contains('-defdir')
  }
}

function Get-ActualInstallerArchitectureInfo {
  <#
  .SYNOPSIS
    Separate setup PE architecture from compiled folder and registry behavior.
  .PARAMETER Setup
    Parsed [Setup] section.
  .PARAMETER Path
    Resolved installer path used for PE machine evidence.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][Collections.IDictionary]$Setup, [Parameter(Mandatory)][string]$Path)

  $Key = @('SystemType', '64-bit', 'x64', 'x64Compliant', 'X64Compliant') | Where-Object { $Setup.Contains($_) } | Select-Object -First 1
  $RawValue = $Key ? [string]$Setup[$Key] : $null
  [Nullable[bool]]$Uses64BitLayout = $null
  $Outer = Get-PEArchitectureInfo -Path $Path

  # The older x64/64-bit keys are ordinary Boolean options. SystemType is the
  # later builder enum: 0 targets both 32-bit and 64-bit Windows with the
  # 32-bit layout, 1 is 64-bit-only, and 2 is 32-bit-only. Builder 9.8 still
  # emits an x86 setup stub for value 1 but disables WOW64 redirection at
  # runtime, so the compiled option, not the outer PE machine, selects folders
  # and the default registry view. Media without an architecture option follows
  # the native setup PE bitness.
  if ($Key -and $Key -ine 'SystemType') {
    $Uses64BitLayout = switch -Regex ($RawValue) {
      '^(?i:1|yes|true|on|64|x64|64-bit)$' { $true; break }
      '^(?i:0|no|false|off|32|x86|32-bit)$' { $false; break }
      default { $null }
    }
  } elseif ($Key) {
    $Uses64BitLayout = switch -Regex ($RawValue) {
      '^(?i:0|2|32|x86|32-bit)$' { $false; break }
      '^(?i:1|64|x64|64-bit)$' { $true; break }
      default { $null }
    }
  } elseif ($Outer.RecommendedWinGetArchitecture -cin @('x86', 'x64')) {
    $Uses64BitLayout = $Outer.RecommendedWinGetArchitecture -ceq 'x64'
  }
  $LayoutEvidenceKnown = $null -ne $Uses64BitLayout
  [pscustomobject]@{
    ConfigurationKey      = $Key
    ConfigurationValue    = $RawValue
    Uses64BitLayout       = $Uses64BitLayout
    LayoutEvidenceKnown   = $LayoutEvidenceKnown
    LayoutEvidenceSource  = $Key ? 'Configuration' : ($LayoutEvidenceKnown ? 'SetupPE' : $null)
    RegistryView          = $LayoutEvidenceKnown ? ($Uses64BitLayout ? '64-bit' : '32-bit') : $null
    SetupArchitecture     = $Outer.RecommendedWinGetArchitecture
    SetupArchitectureInfo = $Outer
  }
}

function Get-ActualInstallerRequirementInfo {
  <#
  .SYNOPSIS
    Project compiled operating-system, prerequisite, network, and running-app requirements.
  .PARAMETER Setup
    Parsed [Setup] section.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][Collections.IDictionary]$Setup)

  $AllowedWindows = [Collections.Generic.List[string]]::new()
  foreach ($Key in $Setup.Keys) {
    if ([string]$Key -match '^(?i:Windows\s|Win(?:9x|NT|2000|XP|Srv2003|Vista|7|8)$)' -and (Test-ActualInstallerBooleanValue -Value $Setup[$Key])) { $AllowedWindows.Add([string]$Key) }
  }
  $Prerequisites = [Collections.Generic.List[object]]::new()
  foreach ($Definition in @(
      @('dotNET', 'dotNETVersion', '.NET Framework'),
      @('VisualCpp', 'VisualCppVersion', 'Microsoft Visual C++ Runtime'),
      @('IE', 'IEVersion', 'Internet Explorer'),
      @('AR', 'ARVersion', 'Adobe Reader'),
      @('Java', 'JavaVersion', 'Java Runtime'),
      @('SQL', 'SQLVersion', 'SQL Server'),
      @('SQLE', 'SQLEVersion', 'SQL Server Express')
    )) {
    if (Test-ActualInstallerBooleanValue -Value (Get-DictionaryValue -Dictionary $Setup -Name @($Definition[0]))) {
      $Prerequisites.Add([pscustomobject]@{ Id = $Definition[0]; Name = $Definition[2]; Version = [string](Get-DictionaryValue -Dictionary $Setup -Name @($Definition[1])) })
    }
  }
  $CloseApplications = [Collections.Generic.List[object]]::new()
  foreach ($Suffix in '', '2') {
    if (Test-ActualInstallerBooleanValue -Value (Get-DictionaryValue -Dictionary $Setup -Name @("CloseApp$Suffix"))) {
      $CloseApplications.Add([pscustomobject]@{ File = [string](Get-DictionaryValue -Dictionary $Setup -Name @("CloseAppFile$Suffix")); Description = [string](Get-DictionaryValue -Dictionary $Setup -Name @("CloseAppText$Suffix")) })
    }
  }
  [pscustomobject]@{
    AllowedWindows          = @($AllowedWindows | Sort-Object -Unique)
    RequiresInternet        = Test-ActualInstallerBooleanValue -Value (Get-DictionaryValue -Dictionary $Setup -Name @('Internet'))
    Prerequisites           = $Prerequisites.ToArray()
    CloseApplications       = $CloseApplications.ToArray()
    ChecksInstalledVersion  = Test-ActualInstallerBooleanValue -Value (Get-DictionaryValue -Dictionary $Setup -Name @('CheckVersions'))
    MinimumInstalledVersion = Get-DictionaryValue -Dictionary $Setup -Name @('CheckMinVer')
    MaximumInstalledVersion = Get-DictionaryValue -Dictionary $Setup -Name @('CheckMaxVer')
  }
}

function Get-ActualInstallerMediaInfo {
  <#
  .SYNOPSIS
    Describe embedded, companion-data, and runtime-downloaded payload sources.
  .PARAMETER Setup
    Parsed [Setup] section.
  .PARAMETER Commands
    Decoded command records.
  .PARAMETER Variables
    Decoded custom-variable records.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][Collections.IDictionary]$Setup,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Commands,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Variables
  )

  $DataFileName = [string](Get-DictionaryValue -Dictionary $Setup -Name @('DataFileName'))
  $ExternalDownloads = @($Commands | Where-Object File -Match '^(?i:DOWNLOAD:)' | ForEach-Object { [pscustomobject]@{ Url = $_.File.Substring(9); Destination = $_.Parameters; Timing = $_.Timing; CommandIndex = $_.Index } })
  $ExternalArchivePlans = [Collections.Generic.List[object]]::new()
  foreach ($Command in $Commands) {
    # ZIP: is a documented runtime pseudo-command. Preserve the archive and
    # destination expressions; extraction remains conditional on the command's
    # timing, OS selector, and any preceding command control flow.
    if ([string]$Command.File -match '^(?i:ZIP:)(?<Archive>.+)$') {
      $ExternalArchivePlans.Add([pscustomobject][ordered]@{
          Kind = 'ZipCommand'; ArchiveExpression = $Matches.Archive.Trim(); DestinationExpression = [string]$Command.Parameters
          SourceUrl = $null; CommandIndex = $Command.Index; DownloadCommandIndex = $null; Timing = $Command.Timing; LaunchOnOS = $Command.LaunchOnOS; CanExtractWhenSupplied = $true
        })
      continue
    }

    # Current online builder media downloads a 7z file and invokes the bundled
    # 7za.exe with its documented x/e and -o grammar. This is execution-plan
    # evidence only; the parser never downloads or launches the helper.
    if ([IO.Path]::GetFileName([string]$Command.File) -ieq '7za.exe' -and [string]$Command.Parameters -match '^\s*(?<Verb>x|e)\s+(?:"(?<QuotedArchive>[^"]+)"|(?<Archive>\S+)).*?(?:^|\s)-o(?:"(?<QuotedDestination>[^"]+)"|(?<Destination>\S+))') {
      $ArchiveExpression = $Matches.QuotedArchive ? $Matches.QuotedArchive : $Matches.Archive
      $DestinationExpression = $Matches.QuotedDestination ? $Matches.QuotedDestination : $Matches.Destination
      $Download = $ExternalDownloads | Where-Object Destination -IEQ $ArchiveExpression | Select-Object -First 1
      $ExternalArchivePlans.Add([pscustomobject][ordered]@{
          Kind = 'SevenZipCommand'; ArchiveExpression = $ArchiveExpression; DestinationExpression = $DestinationExpression
          SourceUrl = $Download ? $Download.Url : $null; CommandIndex = $Command.Index; DownloadCommandIndex = $Download ? $Download.CommandIndex : $null
          Timing = $Command.Timing; LaunchOnOS = $Command.LaunchOnOS; PreserveDirectories = $Matches.Verb -ceq 'x'; CanExtractWhenSupplied = $true
        })
    }
  }
  $DynamicSources = @($Variables | Where-Object { $_.SourceKind -in 'GETURL', 'GETFILE' } | ForEach-Object { [pscustomobject]@{ Variable = $_.Name; Kind = $_.SourceKind; Source = $_.Source; FallbackValue = $_.FallbackValue } })
  [pscustomobject]@{
    EmbeddedPayload              = [string]::IsNullOrWhiteSpace($DataFileName)
    CompanionDataFile            = [string]::IsNullOrWhiteSpace($DataFileName) ? $null : $DataFileName
    CompanionArchiveFormat       = [string]::IsNullOrWhiteSpace($DataFileName) ? $null : '7z/LZMA'
    CompanionExtractionSupported = -not [string]::IsNullOrWhiteSpace($DataFileName)
    PackageType                  = Get-DictionaryValue -Dictionary $Setup -Name @('PackageType')
    ArchiveMode                  = Get-DictionaryValue -Dictionary $Setup -Name @('Archive')
    ExternalDownloads            = $ExternalDownloads
    ExternalArchivePlans         = $ExternalArchivePlans.ToArray()
    DynamicSources               = $DynamicSources
  }
}

function ConvertFrom-ActualInstallerConfigurationBuffer {
  <#
  .SYNOPSIS
    Decode bounded Actual Installer INI bytes and parse repeated keys deterministically.
  .PARAMETER Bytes
    Complete setup.ini or aisetup.ini bytes.
  #>
  [OutputType([Collections.Specialized.OrderedDictionary])]
  param ([Parameter(Mandatory)][byte[]]$Bytes)

  if ($Bytes.Length -gt $Script:ActualInstallerMaximumConfigurationBytes) {
    throw 'The Actual Installer configuration exceeds the configured size limit.'
  }

  $Stream = [IO.MemoryStream]::new($Bytes, $false)
  try {
    $Content = Read-BoundedTextStream -Stream $Stream -MaximumBytes $Script:ActualInstallerMaximumConfigurationBytes -DetectBomlessUnicode -AllowUnicodeFallback
  } finally {
    $Stream.Dispose()
  }
  return ConvertFrom-Ini -Content $Content -DuplicateKeyAction Last -IgnoreComments
}

function Read-ActualInstallerCabinetCatalog {
  <#
  .SYNOPSIS
    Validate and enumerate concatenated Microsoft cabinets in the PE overlay.
  .PARAMETER Path
    Resolved installer path.
  .PARAMETER OverlayOffset
    Absolute first byte after the PE image sections.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$OverlayOffset
  )

  $File = Get-Item -LiteralPath $Path -Force
  if ($OverlayOffset -ge $File.Length) { return @() }
  $Signature = [byte[]](0x4D, 0x53, 0x43, 0x46)
  $Stream = [IO.File]::Open($File.FullName, 'Open', 'Read', 'ReadWrite')
  $Containers = [Collections.Generic.List[object]]::new()
  try {
    $Offsets = @(Find-BinaryPattern -Stream $Stream -Pattern $Signature -StartOffset $OverlayOffset -Length ($Stream.Length - $OverlayOffset) -Maximum $Script:ActualInstallerMaximumContainers)
    [long]$AcceptedEnd = $OverlayOffset
    foreach ($Offset in $Offsets) {
      if ($Offset -lt $AcceptedEnd -or $Offset + 36 -gt $Stream.Length) { continue }
      $Header = Read-BinaryBytes -Stream $Stream -Offset $Offset -Count 36
      [long]$CabinetLength = [BitConverter]::ToUInt32($Header, 8)
      [long]$FileTableOffset = [BitConverter]::ToUInt32($Header, 16)
      [int]$FileCount = [BitConverter]::ToUInt16($Header, 28)
      if ($Header[24] -ne 3 -or $Header[25] -ne 1 -or $CabinetLength -lt 36 -or $CabinetLength -gt $Stream.Length - $Offset) { continue }
      if ($FileCount -lt 1 -or $FileCount -gt $Script:ActualInstallerMaximumEntries -or $FileTableOffset -lt 36 -or $FileTableOffset -ge $CabinetLength) { continue }

      $Entries = [Collections.Generic.List[object]]::new($FileCount)
      [long]$RecordOffset = $Offset + $FileTableOffset
      [long]$CabinetEnd = $Offset + $CabinetLength
      for ($Index = 0; $Index -lt $FileCount; $Index++) {
        if ($RecordOffset + 17 -gt $CabinetEnd) { throw 'An Actual Installer cabinet contains a truncated CFFILE record.' }
        $Record = Read-BinaryBytes -Stream $Stream -Offset $RecordOffset -Count 16
        [long]$ExpandedSize = [BitConverter]::ToUInt32($Record, 0)
        [uint16]$Attributes = [BitConverter]::ToUInt16($Record, 14)
        $NameBytes = [Collections.Generic.List[byte]]::new()
        [long]$NameOffset = $RecordOffset + 16
        $HasTerminator = $false
        while ($NameOffset -lt $CabinetEnd -and $NameBytes.Count -lt 4096) {
          $Byte = (Read-BinaryBytes -Stream $Stream -Offset $NameOffset -Count 1)[0]
          $NameOffset++
          if ($Byte -eq 0) { $HasTerminator = $true; break }
          $NameBytes.Add($Byte)
        }
        if (-not $HasTerminator) { throw 'An Actual Installer cabinet contains an unterminated file name.' }
        $NameEncoding = ($Attributes -band 0x80) -ne 0 ? [Text.Encoding]::UTF8 : [Text.Encoding]::Latin1
        $EntryName = $NameEncoding.GetString($NameBytes.ToArray())
        if ([string]::IsNullOrWhiteSpace($EntryName)) { throw 'An Actual Installer cabinet contains an empty file name.' }
        $Entries.Add([pscustomobject]@{ FullName = $EntryName.Replace('/', '\'); SourceName = $EntryName; Length = $ExpandedSize })
        $RecordOffset = $NameOffset
      }

      $Containers.Add([pscustomobject]@{ Type = 'Cabinet'; Offset = [long]$Offset; Length = [long]$CabinetLength; Entries = $Entries.ToArray() })
      $AcceptedEnd = $CabinetEnd
    }
  } finally {
    $Stream.Dispose()
  }
  return $Containers.ToArray()
}

function Get-ActualInstallerZipCatalog {
  <#
  .SYNOPSIS
    Enumerate independently bounded ZIP ranges and their central-directory entries.
  .PARAMETER Path
    Resolved installer path.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][string]$Path)

  $Containers = [Collections.Generic.List[object]]::new()
  foreach ($Range in @(Get-EmbeddedZipArchiveRange -Path $Path -MaximumArchives 64)) {
    $Context = $null
    try {
      $Context = Open-InstallerArchiveRange -Path $Path -Range $Range
      $Entries = @(Get-InstallerArchiveEntry -Archive $Context.Archive | ForEach-Object {
          [pscustomobject]@{ FullName = $_.FullName.Replace('/', '\'); SourceName = $_.FullName; Length = [long]$_.Length }
        })
      if ($Entries.Count -eq 0 -or $Entries.Count -gt $Script:ActualInstallerMaximumEntries) { continue }
      $Containers.Add([pscustomobject]@{ Type = 'Zip'; Offset = [long]$Range.Offset; Length = [long]$Range.Length; Range = $Range; Entries = $Entries })
    } catch {
      continue
    } finally {
      if ($Context) { Close-InstallerArchiveRange -Context $Context }
    }
  }
  return $Containers.ToArray()
}

function Export-ActualInstallerContainerRange {
  <#
  .SYNOPSIS
    Materialize one exact embedded container for a decoder that requires a path.
  .PARAMETER Path
    Resolved installer path.
  .PARAMETER Container
    Validated container with absolute Offset and Length.
  .PARAMETER DestinationPath
    Output path for the exact range.
  #>
  [OutputType([IO.FileInfo])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][psobject]$Container,
    [Parameter(Mandatory)][string]$DestinationPath
  )

  return Export-InstallerArchiveRange -Path $Path -Offset $Container.Offset -Length $Container.Length -DestinationPath $DestinationPath -CollisionAction Overwrite
}

function Read-ActualInstallerConfiguration {
  <#
  .SYNOPSIS
    Read setup.ini or aisetup.ini from a validated metadata container.
  .PARAMETER Path
    Resolved installer path.
  .PARAMETER Container
    Validated ZIP or cabinet metadata container.
  .PARAMETER EntryName
    Exact configuration entry name.
  #>
  [OutputType([Collections.Specialized.OrderedDictionary])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][psobject]$Container,
    [Parameter(Mandatory)][string]$EntryName
  )

  if ($Container.Type -eq 'Zip') {
    $Context = Open-InstallerArchiveRange -Path $Path -Range $Container.Range
    try {
      $Entry = Get-InstallerArchiveEntry -Archive $Context.Archive | Where-Object { $_.FullName -ieq $EntryName } | Select-Object -First 1
      if (-not $Entry) { throw "The Actual Installer metadata ZIP does not contain '$EntryName'." }
      $Bytes = Read-InstallerArchiveEntryBytes -Entry $Entry -MaximumBytes $Script:ActualInstallerMaximumConfigurationBytes
      return ConvertFrom-ActualInstallerConfigurationBuffer -Bytes $Bytes
    } finally {
      Close-InstallerArchiveRange -Context $Context
    }
  }

  $TemporaryRoot = New-TempFolder
  try {
    $CabinetPath = Join-Path $TemporaryRoot 'metadata.cab'
    $null = Export-ActualInstallerContainerRange -Path $Path -Container $Container -DestinationPath $CabinetPath
    $Entry = $Container.Entries | Where-Object { $_.FullName -ieq $EntryName } | Select-Object -First 1
    if (-not $Entry) { throw "The Actual Installer metadata cabinet does not contain '$EntryName'." }
    $ConfigurationPath = Join-Path $TemporaryRoot 'setup.ini'
    $null = Export-CabinetSelection -Path $CabinetPath -Selection @([pscustomobject]@{ SourceName = $Entry.SourceName; DestinationPath = $ConfigurationPath; Length = $Entry.Length }) -MaximumEntries 1 -MaximumExpandedBytes $Script:ActualInstallerMaximumConfigurationBytes
    return ConvertFrom-Ini -Path $ConfigurationPath -MaximumBytes $Script:ActualInstallerMaximumConfigurationBytes -FallbackEncoding Default -DuplicateKeyAction Last -IgnoreComments
  } finally {
    Remove-Item -LiteralPath $TemporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
  }
}

function Get-ActualInstallerRoute {
  <#
  .SYNOPSIS
    Select the format route from physical container type, metadata name, and position.
  .PARAMETER Containers
    Ordered validated containers.
  .PARAMETER MetadataContainer
    Container holding the setup configuration.
  .PARAMETER MetadataEntryName
    setup.ini or aisetup.ini.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][object[]]$Containers,
    [Parameter(Mandatory)][psobject]$MetadataContainer,
    [Parameter(Mandatory)][string]$MetadataEntryName
  )

  $ContainerKind = $MetadataContainer.Type -eq 'Cabinet' ? 'CabinetSequence' : 'ZipSequence'
  $MetadataIndex = [Array]::IndexOf($Containers, $MetadataContainer)
  $MetadataPosition = $MetadataIndex -eq 0 ? 'First' : ($MetadataIndex -eq $Containers.Count - 1 ? 'Last' : 'Middle')
  $Route = $Script:ActualInstallerCatalog.Routes | Where-Object {
    $_.Container -eq $ContainerKind -and $_.MetadataEntry -ieq $MetadataEntryName -and $_.MetadataPosition -eq $MetadataPosition -and
    (-not $_.ContainsKey('ContainerCount') -or [int]$_.ContainerCount -eq $Containers.Count)
  } | Select-Object -First 1
  if (-not $Route) { throw "The Actual Installer container sequence is unsupported: $ContainerKind/$MetadataEntryName/$MetadataPosition." }
  return [pscustomobject]$Route
}

function Split-ActualInstallerRecord {
  <#
  .SYNOPSIS
    Split one Actual Installer table record without interpreting its fields.
  .PARAMETER Value
    Raw INI record value.
  .PARAMETER AllowLegacyQuestionDelimiter
    Permit the bare question-mark delimiter used by 3.x and 4.x file rows.
  #>
  [OutputType([string[]])]
  param (
    [AllowNull()][string]$Value,
    [switch]$AllowLegacyQuestionDelimiter
  )

  if ($null -eq $Value) { return , ([string[]]@()) }
  if ($Value.Contains('*?')) { return , ([string[]]($Value -split '\*\?')) }
  if ($AllowLegacyQuestionDelimiter) { return , ([string[]]($Value -split '\?')) }
  return , ([string[]]@($Value))
}

function Get-ActualInstallerFileRecord {
  <#
  .SYNOPSIS
    Decode ordered [Files] rows into logical payload records.
  .PARAMETER FilesSection
    Parsed [Files] section.
  .PARAMETER Route
    Structurally selected format route. The route determines which compact
    policy encodings have been verified for the record generation.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [AllowNull()][Collections.IDictionary]$FilesSection,
    [Parameter(Mandatory)][psobject]$Route
  )

  if ($null -eq $FilesSection) { return @() }
  $Records = [Collections.Generic.List[object]]::new()
  foreach ($Key in $FilesSection.Keys) {
    [int]$Index = 0
    if (-not [int]::TryParse([string]$Key, [Globalization.NumberStyles]::Integer, [Globalization.CultureInfo]::InvariantCulture, [ref]$Index) -or $Index -lt 0) { continue }
    $Fields = Split-ActualInstallerRecord -Value ([string]$FilesSection[$Key]) -AllowLegacyQuestionDelimiter
    if ($Fields.Count -eq 0 -or [string]::IsNullOrWhiteSpace($Fields[0])) { continue }
    $RecordValue = $Fields.Count -gt 1 ? $Fields[1] : $null
    $IfExistsMode = $null
    $RemoveOnUninstall = $null
    $PolicyEncoding = 'Unknown'
    $AdditionalFieldStart = 2

    if ($Fields.Count -ge 4 -and $Fields[2] -match '^(?i:Ask|Overwrite|Never|IfNewer|OverwriteIfNewer|IfDifferent|Skip)$') {
      # Cabinet generations and expanded synthetic/current records store two
      # literal policy fields after the physical length or control value.
      $IfExistsMode = switch -Regex ($Fields[2]) {
        '^(?i:IfNewer|OverwriteIfNewer)$' { 'OverwriteIfNewer'; break }
        '^(?i:Never|Skip)$' { 'Skip'; break }
        default { $Fields[2] }
      }
      $RemoveOnUninstall = Test-ActualInstallerBooleanValue -Value $Fields[3]
      $PolicyEncoding = 'LegacyFields'
      $AdditionalFieldStart = 4
    } elseif ($Fields.Count -eq 2 -and $RecordValue -match '^(?<Exists>[0-3])(?<Remove>[01])$') {
      # Current builders compact the If File Exists list index and the Remove
      # on Uninstall checkbox into a two-character token.
      $IfExistsMode = @('Ask', 'Overwrite', 'OverwriteIfNewer', 'Skip')[[int]$Matches.Exists]
      $RemoveOnUninstall = $Matches.Remove -eq '1'
      $PolicyEncoding = 'CompactIndexes'
      $AdditionalFieldStart = 2
    } elseif ($Route.PayloadEncoding -eq 'NumberedZipEntries' -and $Fields.Count -ge 3 -and $RecordValue -match '^[0-3]$') {
      # The first numbered-ZIP generation emits the list index separately. Its
      # remaining field has not been assigned semantics and stays observable.
      $IfExistsMode = @('Ask', 'Overwrite', 'OverwriteIfNewer', 'Skip')[[int]$RecordValue]
      $PolicyEncoding = 'SplitIndex'
      $AdditionalFieldStart = 2
    }

    $AdditionalFields = if ($Fields.Count -gt $AdditionalFieldStart) { [string[]]$Fields[$AdditionalFieldStart..($Fields.Count - 1)] } else { [string[]]@() }
    $Records.Add([pscustomobject]@{
        Index             = $Index
        Destination       = $Fields[0].Trim()
        RecordValue       = $RecordValue
        IfExistsMode      = $IfExistsMode
        OverwriteMode     = $IfExistsMode
        RemoveOnUninstall = $RemoveOnUninstall
        PolicyEncoding    = $PolicyEncoding
        ConditionState    = 'Unconditional'
        AdditionalFields  = $AdditionalFields
        Fields            = [string[]]$Fields
      })
  }
  return @($Records | Sort-Object Index)
}

function Resolve-ActualInstallerLiteralExpression {
  <#
  .SYNOPSIS
    Resolve only deterministic built-in Actual Installer variables.
  .PARAMETER Value
    Authored text or path expression.
  .PARAMETER Setup
    Parsed [Setup] section supplying literal package values.
  .PARAMETER Is64Bit
    Whether generic folder variables use their 64-bit variants.
  .PARAMETER InstallLocation
    Already-resolved installation directory, when available.
  #>
  [OutputType([string])]
  param (
    [AllowNull()][string]$Value,
    [Parameter(Mandatory)][Collections.IDictionary]$Setup,
    [Nullable[bool]]$Is64Bit,
    [AllowNull()][string]$InstallLocation
  )

  if ($null -eq $Value) { return $null }
  $Variables = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
  if ($null -ne $Is64Bit) {
    $Variables['ProgramFiles'] = $Is64Bit ? '%ProgramFiles%' : '%ProgramFiles(x86)%'
    $Variables['CommonFiles'] = $Is64Bit ? '%CommonProgramFiles%' : '%CommonProgramFiles(x86)%'
    $Variables['System'] = $Is64Bit ? '%SystemRoot%\System32' : '%SystemRoot%\SysWOW64'
    $Variables['SystemDir'] = $Variables['System']
  }
  $Variables['ProgramFiles64'] = '%ProgramFiles%'
  $Variables['ProgramFiles86'] = '%ProgramFiles(x86)%'
  $Variables['AppData'] = '%APPDATA%'
  $Variables['LocalAppData'] = '%LOCALAPPDATA%'
  $Variables['CommonAppData'] = '%ProgramData%'
  $Variables['Windows'] = '%WINDIR%'
  $Variables['WindowsDir'] = '%WINDIR%'
  $Variables['SystemDir64'] = '%SystemRoot%\System32'
  if (-not [string]::IsNullOrWhiteSpace($InstallLocation)) { $Variables['InstallDir'] = $InstallLocation }

  foreach ($Pair in @(
      @('AppName', @('AppName')),
      @('AppEdition', @('AppEdition')),
      @('AppVersion', @('AppVersion')),
      @('CompanyName', @('CompanyName', 'Publisher')),
      @('Publisher', @('Publisher', 'CompanyName')),
      @('GUID', @('GUID', 'Guid', 'ProductGUID')),
      @('MainExe', @('MainExe', 'MainExecutable')),
      @('MainExecutable', @('MainExecutable', 'MainExe'))
    )) {
    $Resolved = [string](Get-DictionaryValue -Dictionary $Setup -Name $Pair[1])
    if (-not [string]::IsNullOrWhiteSpace($Resolved) -and $Resolved -notmatch '^<[^>]+>$') { $Variables[$Pair[0]] = $Resolved }
  }
  if ($Variables.ContainsKey('AppName') -and $Variables.ContainsKey('AppVersion')) { $Variables['AppNameVersion'] = "$($Variables['AppName']) $($Variables['AppVersion'])" }

  $Result = $Value
  for ($Depth = 0; $Depth -lt 8; $Depth++) {
    $Evaluator = [Text.RegularExpressions.MatchEvaluator] {
      param($Match)
      $Name = $Match.Groups['Name'].Value
      if (-not $Variables.ContainsKey($Name)) { return $Match.Value }
      return $Variables[$Name]
    }
    $Next = [regex]::Replace($Result, '<(?<Name>[^>%]+)>', $Evaluator)
    if ($Next -ceq $Result) { break }
    $Result = $Next
  }
  if ($Result -match '<[^>]+>') { return $null }
  return $Result
}

function ConvertTo-ActualInstallerManifestPath {
  <#
  .SYNOPSIS
    Resolve deterministic Actual Installer variables to manifest-safe environment paths.
  .PARAMETER Value
    Authored path expression.
  .PARAMETER Setup
    Parsed [Setup] section supplying literal product values.
  .PARAMETER Is64Bit
    Indicates that the builder selected 64-bit compliant paths and registry view.
  #>
  [OutputType([string])]
  param (
    [AllowNull()][string]$Value,
    [Parameter(Mandatory)][Collections.IDictionary]$Setup,
    [Nullable[bool]]$Is64Bit
  )

  if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
  $Result = Resolve-ActualInstallerLiteralExpression -Value $Value.Trim().Trim('"') -Setup $Setup -Is64Bit $Is64Bit
  if ($null -eq $Result) { return $null }
  return $Result.Replace('/', '\')
}

function Join-ActualInstallerManifestPath {
  <#
  .SYNOPSIS
    Join a manifest environment path and one installer-relative child path.
  .PARAMETER BasePath
    Resolved manifest-safe base path.
  .PARAMETER ChildPath
    Child path, optionally rooted at InstallDir.
  #>
  [OutputType([string])]
  param ([AllowNull()][string]$BasePath, [AllowNull()][string]$ChildPath)

  if ([string]::IsNullOrWhiteSpace($BasePath) -or [string]::IsNullOrWhiteSpace($ChildPath)) { return $null }
  $Relative = $ChildPath.Trim().Trim('"').Replace('/', '\') -replace '^(?i:<InstallDir>\\?)', ''
  if ($Relative -match '<[^>]+>' -or [IO.Path]::IsPathRooted($Relative)) { return $null }
  return $BasePath.TrimEnd('\') + '\' + $Relative.TrimStart('\')
}

function Get-ActualInstallerScopeInfo {
  <#
  .SYNOPSIS
    Decode the documented InstallLevel values and legacy elevation configuration.
  .PARAMETER Setup
    Parsed [Setup] section.
  .PARAMETER RequestedExecutionLevel
    PE requestedExecutionLevel evidence.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][Collections.IDictionary]$Setup, [AllowNull()][string]$RequestedExecutionLevel)

  $RawInstallLevel = Get-DictionaryValue -Dictionary $Setup -Name @('InstallLevel')
  [int]$InstallLevel = -1
  $HasInstallLevel = $null -ne $RawInstallLevel -and [int]::TryParse([string]$RawInstallLevel, [ref]$InstallLevel) -and $InstallLevel -in 0..3
  if ($HasInstallLevel) {
    switch ($InstallLevel) {
      0 { return [pscustomobject]@{ Scope = 'user'; SupportedScopes = @('user'); DefaultScope = 'user'; InstallLevel = 0; ScopeSwitches = $null } }
      1 { return [pscustomobject]@{ Scope = 'machine'; SupportedScopes = @('machine'); DefaultScope = 'machine'; InstallLevel = 1; ScopeSwitches = $null } }
      2 { return [pscustomobject]@{ Scope = $null; SupportedScopes = @('user', 'machine'); DefaultScope = 'machine'; InstallLevel = 2; ScopeSwitches = [pscustomobject]@{ User = '/CU'; Machine = '/RUNAS /ALL' } } }
      3 { return [pscustomobject]@{ Scope = $null; SupportedScopes = @('user', 'machine'); DefaultScope = 'user'; InstallLevel = 3; ScopeSwitches = [pscustomobject]@{ User = '/CU'; Machine = '/RUNAS /ALL' } } }
    }
  }

  $RequiresAdmin = Test-ActualInstallerBooleanValue -Value (Get-DictionaryValue -Dictionary $Setup -Name @('Admin', 'RunAsAdmin')) -Default ($RequestedExecutionLevel -eq 'requireAdministrator')
  if ($RequiresAdmin -or $RequestedExecutionLevel -eq 'requireAdministrator') { return [pscustomobject]@{ Scope = 'machine'; SupportedScopes = @('machine'); DefaultScope = 'machine'; InstallLevel = $null; ScopeSwitches = $null } }
  return [pscustomobject]@{ Scope = 'user'; SupportedScopes = @('user'); DefaultScope = 'user'; InstallLevel = $null; ScopeSwitches = $null }
}

function Get-ActualInstallerDefaultInstallLocation {
  <#
  .SYNOPSIS
    Select and resolve the installation path used by the configured default scope.
  .PARAMETER Setup
    Parsed [Setup] section.
  .PARAMETER ScopeInfo
    Decoded scope policy.
  .PARAMETER Is64Bit
    Indicates 64-bit compliant folder behavior.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][Collections.IDictionary]$Setup, [Parameter(Mandatory)][psobject]$ScopeInfo, [Nullable[bool]]$Is64Bit)

  $Primary = [string](Get-DictionaryValue -Dictionary $Setup -Name @('InstallDir', 'InstallationPath'))
  $Alternate = [string](Get-DictionaryValue -Dictionary $Setup -Name @('AltInstallDir', 'AlternateInstallationPath'))
  $Candidate = $Primary
  if ($Alternate) {
    if ($ScopeInfo.DefaultScope -eq 'user' -and $Primary -notmatch '(?i)<(?:Local)?AppData>' -and $Alternate -match '(?i)<(?:Local)?AppData>') { $Candidate = $Alternate }
    if ($ScopeInfo.DefaultScope -eq 'machine' -and $Primary -notmatch '(?i)<ProgramFiles>' -and $Alternate -match '(?i)<ProgramFiles>') { $Candidate = $Alternate }
  }
  return ConvertTo-ActualInstallerManifestPath -Value $Candidate -Setup $Setup -Is64Bit $Is64Bit
}

function ConvertFrom-ActualInstallerRegistryRecord {
  <#
  .SYNOPSIS
    Decode one literal [Registry] row into normalized registry-write evidence.
  .PARAMETER Value
    Raw Actual Installer registry record.
  .PARAMETER DefaultScope
    Scope used to resolve HKEY_DEFAULT/HKDE.
  .PARAMETER Setup
    Parsed setup values used to resolve deterministic variables.
  .PARAMETER Is64Bit
    Whether Default registry view and generic folder variables are 64-bit.
  .PARAMETER InstallLocation
    Resolved default installation location.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Value,
    [Parameter(Mandatory)][ValidateSet('user', 'machine')][string]$DefaultScope,
    [Parameter(Mandatory)][Collections.IDictionary]$Setup,
    [Nullable[bool]]$Is64Bit,
    [AllowNull()][string]$InstallLocation
  )

  $Fields = Split-ActualInstallerRecord -Value $Value
  if ($Fields.Count -lt 3) { return $null }
  $PathExpression = $Fields[0].Trim()
  $KeyMatch = [regex]::Match($PathExpression, '^(?<Root>HKEY_CURRENT_USER|HKCU|HKEY_LOCAL_MACHINE|HKLM|HKEY_CLASSES_ROOT|HKCR|HKEY_DEFAULT|HKDE)\\(?<Key>.+)$', 'IgnoreCase')
  if (-not $KeyMatch.Success) { return $null }
  $RootToken = $KeyMatch.Groups['Root'].Value
  $Root = switch -Regex ($RootToken) {
    '^(?i:HKEY_CURRENT_USER|HKCU)$' { 'HKCU'; break }
    '^(?i:HKEY_LOCAL_MACHINE|HKLM)$' { 'HKLM'; break }
    '^(?i:HKEY_CLASSES_ROOT|HKCR)$' { 'HKCR'; break }
    default { $DefaultScope -eq 'machine' ? 'HKLM' : 'HKCU' }
  }
  $Type = switch -Regex ($Fields[2]) {
    '^(?i:REG_DWORD|DWORD)$' { 'REG_DWORD'; break }
    '^(?i:REG_EXPAND_SZ|EXPAND_SZ)$' { 'REG_EXPAND_SZ'; break }
    '^(?i:REG_MULTI_SZ|MULTI_SZ)$' { 'REG_MULTI_SZ'; break }
    '^(?i:REG_BINARY|BINARY)$' { 'REG_BINARY'; break }
    default { 'REG_SZ' }
  }
  $RawData = $Fields.Count -gt 3 ? $Fields[3] : $null
  $KeyExpression = $KeyMatch.Groups['Key'].Value
  $ResolvedKey = Resolve-ActualInstallerLiteralExpression -Value $KeyExpression -Setup $Setup -Is64Bit $Is64Bit -InstallLocation $InstallLocation
  $ResolvedData = Resolve-ActualInstallerLiteralExpression -Value $RawData -Setup $Setup -Is64Bit $Is64Bit -InstallLocation $InstallLocation
  $CanProject = -not [string]::IsNullOrWhiteSpace($ResolvedKey) -and ($null -eq $RawData -or $null -ne $ResolvedData)
  $ViewToken = $Fields.Count -gt 6 ? $Fields[6].Trim() : 'Default'
  $RegistryView = switch -Regex ($ViewToken) {
    '^(?i:64|64-bit|x64)$' { '64-bit'; break }
    '^(?i:32|32-bit|x86)$' { '32-bit'; break }
    default { $null -ne $Is64Bit ? ($Is64Bit ? '64-bit' : '32-bit') : $null }
  }
  return [pscustomobject]@{
    Root                      = $Root
    Key                       = $null -ne $ResolvedKey ? $ResolvedKey : $KeyExpression
    KeyExpression             = $KeyExpression
    Name                      = $Fields[1]
    Type                      = $Type
    Value                     = $null -ne $ResolvedData ? $ResolvedData : $RawData
    ValueExpression           = $RawData
    OverwriteIfExists         = $Fields.Count -gt 4 ? (Test-ActualInstallerBooleanValue -Value $Fields[4]) : $null
    RemoveOnUninstall         = $Fields.Count -gt 5 ? (Test-ActualInstallerBooleanValue -Value $Fields[5]) : $null
    RegistryView              = $RegistryView
    RegistryViewExpression    = $ViewToken
    CanProject                = $CanProject
    ConditionState            = 'Unconditional'
    RequiresRuntimeEvaluation = -not $CanProject
    AdditionalFields          = $Fields.Count -gt 7 ? [string[]]$Fields[7..($Fields.Count - 1)] : [string[]]@()
    Fields                    = [string[]]$Fields
    Source                    = $Value
  }
}

function Get-ActualInstallerRegistryWrite {
  <#
  .SYNOPSIS
    Decode all literal custom registry rows.
  .PARAMETER RegistrySection
    Parsed [Registry] section.
  .PARAMETER DefaultScope
    Scope used to resolve HKEY_DEFAULT/HKDE.
  .PARAMETER Setup
    Parsed setup values used to resolve deterministic variables.
  .PARAMETER Is64Bit
    Whether Default registry view and generic folder variables are 64-bit.
  .PARAMETER InstallLocation
    Resolved default installation location.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [AllowNull()][Collections.IDictionary]$RegistrySection,
    [Parameter(Mandatory)][ValidateSet('user', 'machine')][string]$DefaultScope,
    [Parameter(Mandatory)][Collections.IDictionary]$Setup,
    [Nullable[bool]]$Is64Bit,
    [AllowNull()][string]$InstallLocation
  )

  if ($null -eq $RegistrySection) { return @() }
  return @($RegistrySection.Keys | ForEach-Object { ConvertFrom-ActualInstallerRegistryRecord -Value ([string]$RegistrySection[$_]) -DefaultScope $DefaultScope -Setup $Setup -Is64Bit $Is64Bit -InstallLocation $InstallLocation } | Where-Object { $null -ne $_ })
}

function Get-ActualInstallerExtensionInfo {
  <#
  .SYNOPSIS
    Decode literal file-extension rows from the dedicated [Extensions] table.
  .PARAMETER ExtensionsSection
    Parsed [Extensions] section.
  .PARAMETER Setup
    Parsed setup values used to resolve deterministic paths.
  .PARAMETER Is64Bit
    Whether generic folder variables use their 64-bit variants.
  .PARAMETER InstallLocation
    Resolved default installation location.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [AllowNull()][Collections.IDictionary]$ExtensionsSection,
    [Parameter(Mandatory)][Collections.IDictionary]$Setup,
    [Nullable[bool]]$Is64Bit,
    [AllowNull()][string]$InstallLocation
  )

  if ($null -eq $ExtensionsSection) { return @() }
  $Result = [Collections.Generic.List[object]]::new()
  foreach ($Key in $ExtensionsSection.Keys) {
    $Fields = Split-ActualInstallerRecord -Value ([string]$ExtensionsSection[$Key])
    if ($Fields.Count -eq 0) { continue }
    $Extension = $Fields[0].Trim().TrimStart('.')
    if ($Extension -notmatch '^[A-Za-z0-9][A-Za-z0-9._+-]{0,254}$') { continue }
    $IsModern = $Fields.Count -ge 8
    $ExecutableExpression = $Fields.Count -gt 1 ? $Fields[1] : $null
    $ParametersExpression = $IsModern ? $Fields[3] : $null
    $WorkingDirectoryExpression = $IsModern ? $Fields[4] : $null
    $IconIndex = $IsModern ? $Fields[5] : $null
    $IconExpression = $IsModern ? $Fields[6] : ($Fields.Count -gt 3 ? $Fields[3] : $null)
    $Result.Add([pscustomobject][ordered]@{
        FileExtension    = $Extension.ToLowerInvariant()
        Extension        = '.' + $Extension.ToLowerInvariant()
        Format           = $IsModern ? 'Modern8' : 'Legacy5'
        Command          = $ExecutableExpression
        Executable       = Resolve-ActualInstallerLiteralExpression -Value $ExecutableExpression -Setup $Setup -Is64Bit $Is64Bit -InstallLocation $InstallLocation
        Parameters       = Resolve-ActualInstallerLiteralExpression -Value $ParametersExpression -Setup $Setup -Is64Bit $Is64Bit -InstallLocation $InstallLocation
        Description      = $Fields.Count -gt 2 ? $Fields[2] : $null
        WorkingDirectory = Resolve-ActualInstallerLiteralExpression -Value $WorkingDirectoryExpression -Setup $Setup -Is64Bit $Is64Bit -InstallLocation $InstallLocation
        DefaultIcon      = Resolve-ActualInstallerLiteralExpression -Value $IconExpression -Setup $Setup -Is64Bit $Is64Bit -InstallLocation $InstallLocation
        IconIndex        = $IconIndex
        MakeDefault      = $Fields.Count -gt 4 ? (Test-ActualInstallerBooleanValue -Value $Fields[$Fields.Count - 1]) : $null
        ConditionState   = 'Unconditional'
        Fields           = [string[]]$Fields
        Source           = [string]$ExtensionsSection[$Key]
      })
  }
  return $Result.ToArray()
}

function Get-ActualInstallerCommandInfo {
  <#
  .SYNOPSIS
    Decode ordered [Commands] rows and their documented execution fields.
  .PARAMETER CommandsSection
    Parsed [Commands] section.
  .PARAMETER Setup
    Parsed setup values used by the bounded literal condition evaluator.
  .PARAMETER Is64Bit
    Whether generic folder variables use their 64-bit variants.
  .PARAMETER InstallLocation
    Resolved default installation location.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [AllowNull()][Collections.IDictionary]$CommandsSection,
    [Parameter(Mandatory)][Collections.IDictionary]$Setup,
    [Nullable[bool]]$Is64Bit,
    [AllowNull()][string]$InstallLocation
  )

  if ($null -eq $CommandsSection) { return @() }
  $Result = [Collections.Generic.List[object]]::new()
  foreach ($Key in $CommandsSection.Keys) {
    [int]$Index = 0
    if (-not [int]::TryParse([string]$Key, [ref]$Index) -or $Index -lt 0) { continue }
    $Fields = Split-ActualInstallerRecord -Value ([string]$CommandsSection[$Key])
    if ($Fields.Count -eq 0) { continue }
    $DecodedFields = [string[]]::new($Fields.Count)
    $EncodedFields = [Collections.Generic.List[int]]::new()
    for ($FieldIndex = 0; $FieldIndex -lt $Fields.Count; $FieldIndex++) {
      $Decoded = ConvertFrom-ActualInstallerEncodedField -Value $Fields[$FieldIndex]
      $DecodedFields[$FieldIndex] = $Decoded.Value
      if ($Decoded.IsEncoded) { $EncodedFields.Add($FieldIndex) }
    }
    $Condition = Resolve-ActualInstallerCommandCondition -Expression $DecodedFields[0] -Action $DecodedFields[1] -Setup $Setup -Is64Bit $Is64Bit -InstallLocation $InstallLocation
    $Result.Add([pscustomobject]@{
        Index               = $Index
        File                = $DecodedFields[0]
        Parameters          = $DecodedFields.Count -gt 1 ? $DecodedFields[1] : $null
        Show                = $DecodedFields.Count -gt 2 ? $DecodedFields[2] : $null
        Timing              = $DecodedFields.Count -gt 3 ? $DecodedFields[3] : $null
        Wait                = $DecodedFields.Count -gt 4 ? (Test-ActualInstallerBooleanValue -Value $DecodedFields[4]) : $null
        LaunchOnOS          = $DecodedFields.Count -gt 5 ? $DecodedFields[5] : $null
        RunAsAdmin          = $DecodedFields.Count -gt 6 ? (Test-ActualInstallerBooleanValue -Value $DecodedFields[6]) : $null
        Condition           = $Condition
        ConditionState      = $Condition.State
        ActionKind          = $Condition.ActionKind
        EncodedFieldIndexes = $EncodedFields.ToArray()
        Fields              = $DecodedFields
        Source              = [string]$CommandsSection[$Key]
      })
  }
  return @($Result | Sort-Object Index)
}

function Compare-ActualInstallerConditionValue {
  <#
  .SYNOPSIS
    Compare two resolved condition operands without consulting host state.
  .PARAMETER Left
    Resolved left operand.
  .PARAMETER Right
    Resolved right operand.
  #>
  [OutputType([int])]
  param ([Parameter(Mandatory)][AllowEmptyString()][string]$Left, [Parameter(Mandatory)][AllowEmptyString()][string]$Right)

  [decimal]$LeftNumber = 0
  [decimal]$RightNumber = 0
  if ([decimal]::TryParse($Left, [Globalization.NumberStyles]::Number, [Globalization.CultureInfo]::InvariantCulture, [ref]$LeftNumber) -and [decimal]::TryParse($Right, [Globalization.NumberStyles]::Number, [Globalization.CultureInfo]::InvariantCulture, [ref]$RightNumber)) {
    return $LeftNumber.CompareTo($RightNumber)
  }

  [version]$LeftVersion = $null
  [version]$RightVersion = $null
  if ([version]::TryParse($Left, [ref]$LeftVersion) -and [version]::TryParse($Right, [ref]$RightVersion)) { return $LeftVersion.CompareTo($RightVersion) }
  return [StringComparer]::OrdinalIgnoreCase.Compare($Left, $Right)
}

function Resolve-ActualInstallerCommandCondition {
  <#
  .SYNOPSIS
    Resolve the documented IF comparison grammar when both operands are static.
  .PARAMETER Expression
    Decoded command-file field containing IF or IFMSG control flow.
  .PARAMETER Action
    Decoded command-parameter field containing the guarded operation.
  .PARAMETER Setup
    Parsed setup values available to the literal evaluator.
  .PARAMETER Is64Bit
    Whether generic folder variables use their 64-bit variants.
  .PARAMETER InstallLocation
    Resolved default installation location.
  #>
  [OutputType([pscustomobject])]
  param (
    [AllowNull()][string]$Expression,
    [AllowNull()][string]$Action,
    [Parameter(Mandatory)][Collections.IDictionary]$Setup,
    [Nullable[bool]]$Is64Bit,
    [AllowNull()][string]$InstallLocation
  )

  $ActionKind = if ([string]$Action -match '^\s*(?<Kind>HALT|STOP|EXIT|IFMSG|MSG|DOWNLOAD|ZIP)(?:\b|\()') { $Matches.Kind.ToUpperInvariant() } else { 'Execute' }
  if ([string]::IsNullOrWhiteSpace($Expression) -or $Expression -notmatch '^\s*(?i:IF)') {
    return [pscustomobject][ordered]@{ Expression = $Expression; State = 'Unconditional'; Operator = $null; Left = $null; Right = $null; ResolvedLeft = $null; ResolvedRight = $null; ActionKind = $ActionKind; RequiresRuntimeEvaluation = $false }
  }
  if ($Expression.Length -gt 4096) {
    return [pscustomobject][ordered]@{ Expression = $Expression; State = 'Unknown'; Operator = $null; Left = $null; Right = $null; ResolvedLeft = $null; ResolvedRight = $null; ActionKind = $ActionKind; RequiresRuntimeEvaluation = $true; Reason = 'ConditionLengthLimit' }
  }
  if ($Expression -match '^\s*(?i:IFMSG)(?:\b|\()') {
    return [pscustomobject][ordered]@{ Expression = $Expression; State = 'Unknown'; Operator = $null; Left = $null; Right = $null; ResolvedLeft = $null; ResolvedRight = $null; ActionKind = 'IFMSG'; RequiresRuntimeEvaluation = $true; Reason = 'InteractivePrompt' }
  }

  # Prefer complete quoted strings and <Variable> tokens so angle brackets in
  # variable syntax are never mistaken for comparison operators.
  $OperandPattern = '"(?:[^"]|"")*"|''(?:[^'']|'''')*''|<[^>]+>|[^!=<>]+?'
  $Match = [regex]::Match($Expression, "^\s*IF\s+(?<Left>$OperandPattern)\s*(?<Operator>!=|>=|<=|=|>|<)\s*(?<Right>.+?)\s*$", 'IgnoreCase')
  if (-not $Match.Success) {
    return [pscustomobject][ordered]@{ Expression = $Expression; State = 'Unknown'; Operator = $null; Left = $null; Right = $null; ResolvedLeft = $null; ResolvedRight = $null; ActionKind = $ActionKind; RequiresRuntimeEvaluation = $true; Reason = 'UnsupportedGrammar' }
  }

  $Left = $Match.Groups['Left'].Value.Trim()
  $Right = $Match.Groups['Right'].Value.Trim()
  $ResolvedLeft = Resolve-ActualInstallerLiteralExpression -Value $Left.Trim('"', "'") -Setup $Setup -Is64Bit $Is64Bit -InstallLocation $InstallLocation
  $ResolvedRight = Resolve-ActualInstallerLiteralExpression -Value $Right.Trim('"', "'") -Setup $Setup -Is64Bit $Is64Bit -InstallLocation $InstallLocation
  if ($null -eq $ResolvedLeft -or $null -eq $ResolvedRight) {
    return [pscustomobject][ordered]@{ Expression = $Expression; State = 'Unknown'; Operator = $Match.Groups['Operator'].Value; Left = $Left; Right = $Right; ResolvedLeft = $ResolvedLeft; ResolvedRight = $ResolvedRight; ActionKind = $ActionKind; RequiresRuntimeEvaluation = $true; Reason = 'RuntimeOperand' }
  }

  $Comparison = Compare-ActualInstallerConditionValue -Left $ResolvedLeft -Right $ResolvedRight
  $Applies = switch ($Match.Groups['Operator'].Value) {
    '=' { $Comparison -eq 0 }
    '!=' { $Comparison -ne 0 }
    '>' { $Comparison -gt 0 }
    '<' { $Comparison -lt 0 }
    '>=' { $Comparison -ge 0 }
    '<=' { $Comparison -le 0 }
  }
  return [pscustomobject][ordered]@{ Expression = $Expression; State = $Applies ? 'True' : 'False'; Operator = $Match.Groups['Operator'].Value; Left = $Left; Right = $Right; ResolvedLeft = $ResolvedLeft; ResolvedRight = $ResolvedRight; ActionKind = $ActionKind; RequiresRuntimeEvaluation = $false }
}

function Get-ActualInstallerShortcutInfo {
  <#
  .SYNOPSIS
    Decode legacy path-based and current destination/name shortcut rows.
  .PARAMETER ShortcutsSection
    Parsed [Shortcuts] section.
  .PARAMETER Setup
    Parsed setup values used to resolve deterministic shortcut paths.
  .PARAMETER Is64Bit
    Whether generic folder variables use their 64-bit variants.
  .PARAMETER InstallLocation
    Resolved default installation location.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [AllowNull()][Collections.IDictionary]$ShortcutsSection,
    [Parameter(Mandatory)][Collections.IDictionary]$Setup,
    [Nullable[bool]]$Is64Bit,
    [AllowNull()][string]$InstallLocation
  )

  if ($null -eq $ShortcutsSection) { return @() }
  $Result = [Collections.Generic.List[object]]::new()
  foreach ($Key in $ShortcutsSection.Keys) {
    [int]$Index = 0
    if (-not [int]::TryParse([string]$Key, [ref]$Index) -or $Index -lt 0) { continue }
    $Fields = Split-ActualInstallerRecord -Value ([string]$ShortcutsSection[$Key])
    if ($Fields.Count -lt 2) { continue }
    $UsesSplitDestination = $Fields[0] -notmatch '(?i)\.lnk$' -and $Fields.Count -ge 9
    $ShortcutPath = $UsesSplitDestination ? $null : $Fields[0]
    $Destination = $UsesSplitDestination ? $Fields[0] : $null
    $Target = $UsesSplitDestination ? $Fields[2] : $Fields[1]
    $Parameters = $UsesSplitDestination ? ($Fields.Count -gt 3 ? $Fields[3] : $null) : ($Fields.Count -gt 2 ? $Fields[2] : $null)
    $WorkingDirectory = $UsesSplitDestination ? ($Fields.Count -gt 5 ? $Fields[5] : $null) : ($Fields.Count -gt 4 ? $Fields[4] : $null)
    $Icon = $UsesSplitDestination ? ($Fields.Count -gt 6 ? $Fields[6] : $null) : ($Fields.Count -gt 5 ? $Fields[5] : $null)
    $Result.Add([pscustomobject]@{
        Index                    = $Index
        Format                   = $UsesSplitDestination ? 'DestinationAndName' : 'ShortcutPath'
        ShortcutPath             = $ShortcutPath
        Destination              = $Destination
        Name                     = $UsesSplitDestination ? $Fields[1] : [IO.Path]::GetFileNameWithoutExtension($Fields[0])
        Target                   = $Target
        Parameters               = $Parameters
        WorkingDirectory         = $WorkingDirectory
        Icon                     = $Icon
        IconIndex                = $UsesSplitDestination ? ($Fields.Count -gt 7 ? $Fields[7] : $null) : ($Fields.Count -gt 6 ? $Fields[6] : $null)
        Show                     = $UsesSplitDestination ? ($Fields.Count -gt 8 ? $Fields[8] : $null) : ($Fields.Count -gt 7 ? $Fields[7] : $null)
        RunAsAdmin               = $UsesSplitDestination -and $Fields.Count -gt 9 ? (Test-ActualInstallerBooleanValue -Value $Fields[9]) : $null
        ResolvedShortcutPath     = Resolve-ActualInstallerLiteralExpression -Value $ShortcutPath -Setup $Setup -Is64Bit $Is64Bit -InstallLocation $InstallLocation
        ResolvedDestination      = Resolve-ActualInstallerLiteralExpression -Value $Destination -Setup $Setup -Is64Bit $Is64Bit -InstallLocation $InstallLocation
        ResolvedTarget           = Resolve-ActualInstallerLiteralExpression -Value $Target -Setup $Setup -Is64Bit $Is64Bit -InstallLocation $InstallLocation
        ResolvedParameters       = Resolve-ActualInstallerLiteralExpression -Value $Parameters -Setup $Setup -Is64Bit $Is64Bit -InstallLocation $InstallLocation
        ResolvedWorkingDirectory = Resolve-ActualInstallerLiteralExpression -Value $WorkingDirectory -Setup $Setup -Is64Bit $Is64Bit -InstallLocation $InstallLocation
        ResolvedIcon             = Resolve-ActualInstallerLiteralExpression -Value $Icon -Setup $Setup -Is64Bit $Is64Bit -InstallLocation $InstallLocation
        ConditionState           = 'Unconditional'
        Fields                   = [string[]]$Fields
        Source                   = [string]$ShortcutsSection[$Key]
      })
  }
  return @($Result | Sort-Object Index)
}

function Get-ActualInstallerVariableInfo {
  <#
  .SYNOPSIS
    Decode custom-variable records while preserving source-dependent fields.
  .PARAMETER VariablesSection
    Parsed [Variables] section.
  #>
  [OutputType([pscustomobject[]])]
  param ([AllowNull()][Collections.IDictionary]$VariablesSection)

  if ($null -eq $VariablesSection) { return @() }
  $Result = [Collections.Generic.List[object]]::new()
  foreach ($Key in $VariablesSection.Keys) {
    [int]$Index = 0
    if (-not [int]::TryParse([string]$Key, [ref]$Index) -or $Index -lt 0) { continue }
    $Fields = Split-ActualInstallerRecord -Value ([string]$VariablesSection[$Key])
    if ($Fields.Count -eq 0) { continue }
    $SourceExpression = $Fields.Count -gt 1 ? $Fields[1] : $null
    $IsRegistrySource = $SourceExpression -match '^(?i:HK(?:CU|LM)|HKEY_)\\'
    $SourceKind = if ($IsRegistrySource) { 'Registry' } elseif ([string]::IsNullOrWhiteSpace($SourceExpression)) { 'Literal' } else { $SourceExpression }
    $Result.Add([pscustomobject]@{
        Index         = $Index
        Name          = $Fields[0]
        SourceKind    = $SourceKind
        Source        = $IsRegistrySource ? $SourceExpression : ($Fields.Count -gt 2 ? $Fields[2] : $null)
        ValueName     = $IsRegistrySource -and $Fields.Count -gt 2 ? $Fields[2] : $null
        ValueType     = $Fields.Count -gt 3 ? $Fields[3] : $null
        FallbackValue = $Fields.Count -gt 4 ? $Fields[4] : $null
        RegistryView  = $Fields.Count -gt 5 ? $Fields[5] : $null
        IsDynamic     = $SourceKind -ne 'Literal'
        Fields        = [string[]]$Fields
        Raw           = [string]$VariablesSection[$Key]
      })
  }
  return @($Result | Sort-Object Index)
}

function Get-ActualInstallerCustomAppsAndFeaturesEntry {
  <#
  .SYNOPSIS
    Project complete, literal custom uninstall-registry groups into visible ARP entries.
  .PARAMETER RegistryWrite
    Decoded registry writes with resolved deterministic values.
  #>
  [OutputType([pscustomobject[]])]
  param ([AllowNull()][object[]]$RegistryWrite)

  $Groups = @($RegistryWrite | Where-Object { $_.Root -in 'HKCU', 'HKLM' -and $_.Key -match '^(?i:Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\)[^\\]+$' } | Group-Object Root, RegistryView, Key)
  foreach ($Group in $Groups) {
    $Values = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($Write in $Group.Group) { $Values[[string]$Write.Name] = $Write.Value }
    [long]$SystemComponent = 0
    $Hidden = $Values.ContainsKey('SystemComponent') -and [long]::TryParse([string]$Values['SystemComponent'], [ref]$SystemComponent) -and $SystemComponent -ne 0
    if ($Hidden -or -not $Values.ContainsKey('DisplayName') -or [string]::IsNullOrWhiteSpace([string]$Values['DisplayName'])) { continue }
    $ProductCode = ([string]$Group.Group[0].Key -split '\\')[-1]
    $Entry = [ordered]@{ ProductCode = $ProductCode; InstallerType = 'exe' }
    foreach ($Name in 'DisplayName', 'DisplayVersion', 'Publisher') {
      if ($Values.ContainsKey($Name) -and -not [string]::IsNullOrWhiteSpace([string]$Values[$Name])) { $Entry[$Name] = [string]$Values[$Name] }
    }
    [pscustomobject]@{
      ProductCode    = $ProductCode
      Root           = $Group.Group[0].Root
      RegistryView   = $Group.Group[0].RegistryView
      ManifestEntry  = [pscustomobject]$Entry
      Values         = $Values
      RegistryWrites = @($Group.Group)
    }
  }
}

function Merge-ActualInstallerAppsAndFeaturesEntry {
  <#
  .SYNOPSIS
    Merge built-in and explicit ARP projections by case-insensitive ProductCode.
  .PARAMETER Entry
    Candidate manifest entries in increasing precedence order.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Entry)

  $ByProductCode = [Collections.Specialized.OrderedDictionary]::new([StringComparer]::OrdinalIgnoreCase)
  $WithoutProductCode = [Collections.Generic.List[object]]::new()
  foreach ($Candidate in $Entry) {
    $ProductCode = [string]$Candidate.ProductCode
    if ([string]::IsNullOrWhiteSpace($ProductCode)) { $WithoutProductCode.Add($Candidate); continue }
    $Values = [ordered]@{}
    if ($ByProductCode.Contains($ProductCode)) { foreach ($Property in $ByProductCode[$ProductCode].PSObject.Properties) { $Values[$Property.Name] = $Property.Value } }
    foreach ($Property in $Candidate.PSObject.Properties) {
      if ($null -ne $Property.Value -and -not ($Property.Value -is [string] -and [string]::IsNullOrWhiteSpace($Property.Value))) { $Values[$Property.Name] = $Property.Value }
    }
    $ByProductCode[$ProductCode] = [pscustomobject]$Values
  }
  return [object[]]@($WithoutProductCode.ToArray() + @($ByProductCode.Values))
}

function ConvertTo-ActualInstallerPayloadRelativePath {
  <#
  .SYNOPSIS
    Map an authored destination to a traversal-safe extraction namespace.
  .PARAMETER Destination
    Authored file destination from [Files].
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][string]$Destination)

  $Normalized = $Destination.Trim().Trim('"').Replace('/', '\')
  if ($Normalized -match '^(?i:<InstallDir>)(?:\\)?(?<Tail>.*)$') { return $Matches.Tail.TrimStart('\') }
  if ($Normalized -match '^<(?<Root>[^>]+)>(?:\\)?(?<Tail>.*)$') {
    $Root = ($Matches.Root -replace '[^A-Za-z0-9._-]', '_')
    return Join-Path (Join-Path '_destinations' $Root) $Matches.Tail.TrimStart('\')
  }
  $Leaf = $Normalized -replace '^[A-Za-z]:', ''
  return Join-Path (Join-Path '_destinations' 'Literal') $Leaf.TrimStart('\')
}

function Get-ActualInstallerPayloadCatalog {
  <#
  .SYNOPSIS
    Join [Files] logical indexes to their physical ZIP entries or cabinet sequence.
  .PARAMETER Route
    Selected format route.
  .PARAMETER Containers
    Ordered validated containers.
  .PARAMETER MetadataContainer
    Container excluded from normal payload mapping.
  .PARAMETER FileRecords
    Ordered logical [Files] records.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][psobject]$Route, [Parameter(Mandatory)][object[]]$Containers, [Parameter(Mandatory)][psobject]$MetadataContainer, [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$FileRecords)

  $PhysicalByIndex = @{}
  if ($Route.PayloadEncoding -eq 'ExternalSevenZip') {
    return @($FileRecords | ForEach-Object {
        [pscustomobject]@{
          Index = $_.Index; Destination = $_.Destination; RelativePath = ConvertTo-ActualInstallerPayloadRelativePath -Destination $_.Destination; RecordValue = $_.RecordValue; OverwriteMode = $_.OverwriteMode; RemoveOnUninstall = $_.RemoveOnUninstall; Fields = $_.Fields
          Available = $false; ContainerType = $null; ContainerOffset = $null; ContainerLength = $null; SourceName = $null; Length = -1L; Container = $null; ExternalData = $true
        }
      })
  }
  if ($Route.PayloadEncoding -eq 'NumberedZipEntries') {
    foreach ($Container in $Containers) {
      if ([object]::ReferenceEquals($Container, $MetadataContainer)) { continue }
      foreach ($Entry in $Container.Entries) {
        [int]$Index = 0
        if ([int]::TryParse([IO.Path]::GetFileName([string]$Entry.FullName), [ref]$Index)) {
          if ($PhysicalByIndex.ContainsKey($Index)) { throw "Actual Installer contains more than one physical ZIP entry for logical file index $Index." }
          $PhysicalByIndex[$Index] = [pscustomobject]@{ Container = $Container; Entry = $Entry }
        }
      }
    }
  } else {
    $PayloadContainers = @($Containers | Where-Object { -not [object]::ReferenceEquals($_, $MetadataContainer) })
    [int]$PhysicalIndex = 0
    for ($LogicalIndex = 0; $LogicalIndex -lt $FileRecords.Count; $LogicalIndex++) {
      [long]$ExpectedCabinetLength = 0
      $HasExpectedLength = [long]::TryParse([string]$FileRecords[$LogicalIndex].RecordValue, [Globalization.NumberStyles]::Integer, [Globalization.CultureInfo]::InvariantCulture, [ref]$ExpectedCabinetLength) -and $ExpectedCabinetLength -gt 0
      if (-not $HasExpectedLength) { continue }
      if ($PhysicalIndex -ge $PayloadContainers.Count) { continue }
      $Container = $PayloadContainers[$PhysicalIndex]
      if ($Container.Length -ne $ExpectedCabinetLength) {
        # A generated record may appear between physical cabinets. Only skip
        # the logical row when the current cabinet is proven to belong to a
        # later row; otherwise positional extraction would silently shift all
        # subsequent files.
        $MatchesLaterRecord = $false
        for ($LaterIndex = $LogicalIndex + 1; $LaterIndex -lt $FileRecords.Count; $LaterIndex++) {
          [long]$LaterLength = 0
          if ([long]::TryParse([string]$FileRecords[$LaterIndex].RecordValue, [ref]$LaterLength) -and $LaterLength -eq $Container.Length) { $MatchesLaterRecord = $true; break }
        }
        if ($MatchesLaterRecord) { continue }
        throw "Actual Installer cabinet length $($Container.Length) does not match logical file index $($FileRecords[$LogicalIndex].Index), which declares $ExpectedCabinetLength bytes."
      }
      $Entry = $Container.Entries | Select-Object -First 1
      if (-not $Entry) { throw "Actual Installer payload cabinet $PhysicalIndex contains no file entry." }
      $PhysicalByIndex[$FileRecords[$LogicalIndex].Index] = [pscustomobject]@{ Container = $Container; Entry = $Entry }
      $PhysicalIndex++
    }
    if ($PhysicalIndex -ne $PayloadContainers.Count) { throw 'Actual Installer contains payload cabinets that cannot be mapped uniquely to the compiled file table.' }
  }

  return @($FileRecords | ForEach-Object {
      $Physical = $PhysicalByIndex[$_.Index]
      [pscustomobject]@{
        Index = $_.Index; Destination = $_.Destination; RelativePath = ConvertTo-ActualInstallerPayloadRelativePath -Destination $_.Destination; RecordValue = $_.RecordValue; OverwriteMode = $_.OverwriteMode; RemoveOnUninstall = $_.RemoveOnUninstall; Fields = $_.Fields
        Available = $null -ne $Physical; ContainerType = $null -ne $Physical ? $Physical.Container.Type : $null; ContainerOffset = $null -ne $Physical ? [long]$Physical.Container.Offset : $null
        ContainerLength = $null -ne $Physical ? [long]$Physical.Container.Length : $null; SourceName = $null -ne $Physical ? [string]$Physical.Entry.SourceName : $null
        Length = $null -ne $Physical ? [long]$Physical.Entry.Length : -1L; Container = $null -ne $Physical ? $Physical.Container : $null; ExternalData = $false
      }
    })
}

function Get-ActualInstallerCommandApplicability {
  <#
  .SYNOPSIS
    Project source-backed scenario gates for compiled command records.
  .PARAMETER Command
    Decoded ordered command records.
  .PARAMETER SetupParameterInfo
    Parsed global command suppression policy.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Command,
    [Parameter(Mandatory)][psobject]$SetupParameterInfo
  )

  foreach ($Item in $Command) {
    $Platform = switch -Regex ([string]$Item.LaunchOnOS) {
      '^(?i:Any|All)$' { 'Any'; break }
      '^(?i:32|x86|32-bit)$' { 'x86'; break }
      '^(?i:64|x64|64-bit)$' { 'x64'; break }
      '^$' { 'Unknown'; break }
      default { 'WindowsSelection' }
    }
    $Condition = $Item.Condition
    $MayStop = $Condition.ActionKind -in 'HALT', 'STOP', 'EXIT'
    [pscustomobject][ordered]@{
      CommandIndex              = $Item.Index
      Timing                    = $Item.Timing
      Platform                  = $Platform
      PlatformExpression        = $Item.LaunchOnOS
      RunsInInteractive         = $true
      RunsInSilent              = -not $SetupParameterInfo.SuppressesCommandsInSilent
      RunsInUpdate              = -not $SetupParameterInfo.SuppressesCommandsInUpdate
      ConditionState            = $Condition.State
      Condition                 = $Condition
      MayStopCurrentPhase       = $MayStop
      RequiresRuntimeEvaluation = $Condition.RequiresRuntimeEvaluation -or $Platform -in 'Unknown', 'WindowsSelection'
    }
  }
}

function Get-ActualInstallerGeneratedOutputInfo {
  <#
  .SYNOPSIS
    Classify logical outputs that are duplicated, generated from metadata helpers, or unresolved.
  .PARAMETER Layout
    Parsed Actual Installer layout containing payload and metadata catalogs.
  .PARAMETER Uninstaller
    Configured uninstaller path relative to the installation directory.
  .PARAMETER UninstallEnabled
    Whether the built-in uninstaller is enabled.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][psobject]$Layout,
    [AllowNull()][string]$Uninstaller,
    [bool]$UninstallEnabled
  )

  $Results = [Collections.Generic.List[object]]::new()
  $AvailableDestinations = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($Item in $Layout.PayloadCatalog) {
    if ($Item.Available) { $null = $AvailableDestinations.Add($Item.Destination.Trim().Trim('"').Replace('/', '\')) }
  }
  $MetadataHelpers = @($Layout.MetadataContainer.Entries | Where-Object { [IO.Path]::GetFileName([string]$_.FullName) -match '^(?i:(?:AI|A)?(?:Uninstall|Updater)\.exe)$' })
  $GeneratedUninstallerMode = $Layout.Route.PSObject.Properties['GeneratedUninstallerMode'] ? [string]$Layout.Route.GeneratedUninstallerMode : 'Unverified'

  foreach ($Item in @($Layout.PayloadCatalog | Where-Object { -not $_.Available -and -not $_.ExternalData })) {
    $Destination = $Item.Destination.Trim().Trim('"').Replace('/', '\')
    if ($AvailableDestinations.Contains($Destination)) {
      $Results.Add([pscustomobject][ordered]@{ Kind = 'DuplicateLogicalRecord'; Destination = $Item.Destination; RelativePath = $Item.RelativePath; FileRecordIndex = $Item.Index; TemplateEntry = $null; TemplateLength = $null; CanReconstruct = $true; ReconstructionMode = 'ExistingPayload'; Reason = 'Another physical payload record supplies the same destination.' })
      continue
    }
    $Leaf = [IO.Path]::GetFileName($Destination)
    $Stem = [IO.Path]::GetFileNameWithoutExtension($Leaf)
    $TemplateMatches = @($MetadataHelpers | Where-Object { [IO.Path]::GetFileName([string]$_.FullName) -iin @($Leaf, "A$Leaf", "AI$Leaf") })
    $Template = $TemplateMatches.Count -eq 1 ? $TemplateMatches[0] : $null
    $Kind = $Stem -imatch 'uninstall' ? 'GeneratedUninstaller' : ($Stem -imatch 'updater' ? 'GeneratedUpdater' : 'UnresolvedLogicalOutput')
    $CanReconstruct = $null -ne $Template -and $Kind -eq 'GeneratedUninstaller' -and $GeneratedUninstallerMode -eq 'ExactCopy'
    $Reason = if ($CanReconstruct) { 'The installed uninstaller is a byte-for-byte copy of the metadata helper on this structural route.' } elseif ($Template) { 'The metadata container supplies a helper template, but final helper bytes are not proven for this output kind and route.' } else { 'No physical payload or unique helper template supplies this logical output.' }
    $Results.Add([pscustomobject][ordered]@{ Kind = $Kind; Destination = $Item.Destination; RelativePath = $Item.RelativePath; FileRecordIndex = $Item.Index; TemplateEntry = $Template ? [string]$Template.SourceName : $null; TemplateLength = $Template ? [long]$Template.Length : $null; CanReconstruct = $CanReconstruct; ReconstructionMode = $CanReconstruct ? 'ExactCopy' : $null; Reason = $Reason })
  }

  # Some later builders omit the generated uninstaller from [Files] entirely.
  # Add evidence only when the expected destination has no direct payload and a
  # unique metadata helper identifies the generation source.
  if ($UninstallEnabled -and -not [string]::IsNullOrWhiteSpace($Uninstaller)) {
    $ExpectedDestination = '<InstallDir>\' + $Uninstaller.Trim().Trim('"').TrimStart('\')
    $AlreadyRepresented = @($Results | Where-Object Destination -IEQ $ExpectedDestination).Count -gt 0
    if (-not $AlreadyRepresented -and -not $AvailableDestinations.Contains($ExpectedDestination)) {
      $Leaf = [IO.Path]::GetFileName($Uninstaller)
      $TemplateMatches = @($MetadataHelpers | Where-Object { [IO.Path]::GetFileName([string]$_.FullName) -iin @($Leaf, "A$Leaf", "AI$Leaf") })
      if ($TemplateMatches.Count -eq 1) {
        $CanReconstruct = $GeneratedUninstallerMode -eq 'ExactCopy'
        $Reason = $CanReconstruct ? 'The installed uninstaller is a byte-for-byte copy of the metadata helper on this structural route.' : 'The metadata container supplies a helper template, but final helper bytes are not proven for this route.'
        $Results.Add([pscustomobject][ordered]@{ Kind = 'GeneratedUninstaller'; Destination = $ExpectedDestination; RelativePath = ConvertTo-ActualInstallerPayloadRelativePath -Destination $ExpectedDestination; FileRecordIndex = $null; TemplateEntry = [string]$TemplateMatches[0].SourceName; TemplateLength = [long]$TemplateMatches[0].Length; CanReconstruct = $CanReconstruct; ReconstructionMode = $CanReconstruct ? 'ExactCopy' : $null; Reason = $Reason })
      }
    }
  }
  return $Results.ToArray()
}

function Export-ActualInstallerContainerSelection {
  <#
  .SYNOPSIS
    Export multiple entries from one embedded container while opening it once.
  .PARAMETER Layout
    Parsed Actual Installer layout owning the embedded container.
  .PARAMETER Container
    Validated ZIP or cabinet container from the layout.
  .PARAMETER Selection
    SourceName, DestinationPath, and Length records with collision-safe outputs.
  .PARAMETER MaximumExpandedBytes
    Maximum aggregate output for this container selection.
  #>
  [OutputType([IO.FileInfo[]])]
  param (
    [Parameter(Mandatory)][psobject]$Layout,
    [Parameter(Mandatory)][psobject]$Container,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Selection,
    [Parameter(Mandatory)][ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes
  )

  if ($Selection.Count -eq 0) { return @() }
  if ($Selection.Count -gt $Script:ActualInstallerMaximumEntries) { throw 'The Actual Installer container selection exceeds the configured entry limit.' }
  [long]$DeclaredBytes = 0
  foreach ($Item in $Selection) {
    if ([string]::IsNullOrWhiteSpace([string]$Item.SourceName)) { throw 'An Actual Installer container selection has no source entry name.' }
    if ([string]::IsNullOrWhiteSpace([string]$Item.DestinationPath)) { throw "Actual Installer entry '$($Item.SourceName)' has no output path." }
    if ([long]$Item.Length -lt 0 -or [long]$Item.Length -gt $MaximumExpandedBytes - $DeclaredBytes) { throw 'The Actual Installer container selection exceeds the configured output limit.' }
    $DeclaredBytes += [long]$Item.Length
  }

  $Results = [Collections.Generic.List[IO.FileInfo]]::new($Selection.Count)
  if ($Container.Type -eq 'Zip') {
    $Context = Open-InstallerArchiveRange -Path $Layout.Path -Range $Container.Range
    try {
      $Entries = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
      $Duplicates = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
      foreach ($Entry in Get-InstallerArchiveEntry -Archive $Context.Archive) {
        if (-not $Entries.TryAdd([string]$Entry.FullName, $Entry)) { $null = $Duplicates.Add([string]$Entry.FullName) }
      }
      foreach ($Item in $Selection) {
        $SourceName = [string]$Item.SourceName
        if ($Duplicates.Contains($SourceName) -or -not $Entries.ContainsKey($SourceName)) { throw "Expected one Actual Installer ZIP entry '$SourceName'." }
        $Entry = $Entries[$SourceName]
        if ([long]$Entry.Length -ne [long]$Item.Length) { throw "Actual Installer ZIP entry '$SourceName' does not match its catalog length." }
        $EntryLimit = [Math]::Max(1L, [long]$Item.Length)
        $Results.Add((Export-InstallerArchiveEntry -Entry $Entry -DestinationPath ([string]$Item.DestinationPath) -MaximumBytes $EntryLimit -CollisionAction Overwrite))
      }
    } finally { Close-InstallerArchiveRange -Context $Context }
    return $Results.ToArray()
  }

  $TemporaryRoot = New-TempFolder
  try {
    $CabinetPath = Join-Path $TemporaryRoot 'container.cab'
    $null = Export-ActualInstallerContainerRange -Path $Layout.Path -Container $Container -DestinationPath $CabinetPath
    $null = Export-CabinetSelection -Path $CabinetPath -Selection $Selection -MaximumEntries $Script:ActualInstallerMaximumEntries -MaximumExpandedBytes $MaximumExpandedBytes
    foreach ($Item in $Selection) { $Results.Add((Get-Item -LiteralPath ([string]$Item.DestinationPath) -Force)) }
    return $Results.ToArray()
  } finally { Remove-Item -LiteralPath $TemporaryRoot -Recurse -Force -ErrorAction SilentlyContinue }
}

function Export-ActualInstallerPayloadSelection {
  <#
  .SYNOPSIS
    Batch mapped payload outputs by physical container.
  .PARAMETER Layout
    Parsed Actual Installer layout.
  .PARAMETER Selection
    Records containing Item and an already reserved DestinationPath.
  .PARAMETER MaximumExpandedBytes
    Maximum aggregate output across all selected containers.
  #>
  [OutputType([IO.FileInfo[]])]
  param (
    [Parameter(Mandatory)][psobject]$Layout,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Selection,
    [Parameter(Mandatory)][ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes
  )

  if ($Selection.Count -eq 0) { return @() }
  $Groups = [Collections.Generic.Dictionary[string, Collections.Generic.List[object]]]::new([StringComparer]::Ordinal)
  [long]$ExpandedBytes = 0
  foreach ($Output in $Selection) {
    $Item = $Output.Item
    if (-not $Item.Available -or -not $Item.Container) { throw "Actual Installer logical file index $($Item.Index) has no physical payload." }
    if ([long]$Item.Length -lt 0 -or [long]$Item.Length -gt $MaximumExpandedBytes - $ExpandedBytes) { throw 'The Actual Installer payload exceeds the configured output limit.' }
    $ExpandedBytes += [long]$Item.Length
    $Key = "$($Item.Container.Type):$($Item.Container.Offset):$($Item.Container.Length)"
    if (-not $Groups.ContainsKey($Key)) { $Groups[$Key] = [Collections.Generic.List[object]]::new() }
    $Groups[$Key].Add([pscustomobject]@{ SourceName = $Item.SourceName; DestinationPath = $Output.DestinationPath; Length = [long]$Item.Length; Container = $Item.Container })
  }

  foreach ($Group in $Groups.Values) {
    $Container = $Group[0].Container
    $ContainerSelection = @($Group | ForEach-Object { [pscustomobject]@{ SourceName = $_.SourceName; DestinationPath = $_.DestinationPath; Length = $_.Length } })
    $null = Export-ActualInstallerContainerSelection -Layout $Layout -Container $Container -Selection $ContainerSelection -MaximumExpandedBytes $MaximumExpandedBytes
  }
  return [IO.FileInfo[]]@($Selection | ForEach-Object { Get-Item -LiteralPath ([string]$_.DestinationPath) -Force })
}

function Export-ActualInstallerMetadataSelection {
  <#
  .SYNOPSIS
    Export selected files from the validated Actual Installer metadata container.
  .PARAMETER Layout
    Reusable parsed installer layout.
  .PARAMETER DestinationPath
    Resolved extraction root.
  .PARAMETER Name
    Wildcard matched against `_actual\metadata` relative paths.
  .PARAMETER CollisionAction
    Collision policy applied after a matching entry is found.
  .PARAMETER MaximumExpandedBytes
    Maximum aggregate metadata output in bytes.
  .PARAMETER ReservedPath
    Caller-owned set of already reserved output paths.
  #>
  [OutputType([IO.FileInfo[]])]
  param (
    [Parameter(Mandatory)][psobject]$Layout,
    [Parameter(Mandatory)][string]$DestinationPath,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction,
    [Parameter(Mandatory)][ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes,
    [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.ISet[string]]$ReservedPath
  )

  $Selected = [Collections.Generic.List[object]]::new()
  [long]$ExpandedBytes = 0
  foreach ($Entry in $Layout.MetadataContainer.Entries) {
    $RelativePath = Join-Path '_actual\metadata' ([string]$Entry.FullName).TrimStart('\', '/')
    if (-not (Test-ExtractionPattern -Path $RelativePath -Pattern $Name)) { continue }
    if ($Selected.Count -ge $Script:ActualInstallerMaximumEntries) { throw 'The Actual Installer metadata selection exceeds the configured entry limit.' }
    if ([long]$Entry.Length -lt 0 -or [long]$Entry.Length -gt $MaximumExpandedBytes - $ExpandedBytes) { throw 'The Actual Installer metadata selection exceeds the configured output limit.' }
    $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $RelativePath -CollisionAction $CollisionAction -ReservedPath $ReservedPath
    if (-not $Target.ShouldWrite) { continue }
    $Selected.Add([pscustomobject]@{ Entry = $Entry; DestinationPath = $Target.Path })
    $ExpandedBytes += [long]$Entry.Length
  }
  if ($Selected.Count -eq 0) { return @() }

  $ContainerSelection = @($Selected | ForEach-Object { [pscustomobject]@{ SourceName = $_.Entry.SourceName; DestinationPath = $_.DestinationPath; Length = [long]$_.Entry.Length } })
  return Export-ActualInstallerContainerSelection -Layout $Layout -Container $Layout.MetadataContainer -Selection $ContainerSelection -MaximumExpandedBytes $MaximumExpandedBytes
}

function Open-ActualInstallerCompanionContext {
  <#
  .SYNOPSIS
    Open and validate one explicitly supplied Setup EXE + Data archive.
  .PARAMETER Layout
    Parsed Actual Installer layout whose configuration names the companion data file.
  .PARAMETER CompanionFile
    Local 7z data file supplied alongside the setup executable; it is never downloaded.
  .PARAMETER MaximumCatalogBytes
    Maximum aggregate declared uncompressed size accepted in the catalog.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Layout,
    [Parameter(Mandatory)][string]$CompanionFile,
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumCatalogBytes = 16GB
  )

  $Setup = $Layout.Configuration['Setup']
  $ExpectedName = [string](Get-DictionaryValue -Dictionary $Setup -Name @('DataFileName'))
  if ([string]::IsNullOrWhiteSpace($ExpectedName)) { throw 'The Actual Installer configuration does not declare a Setup EXE + Data companion file.' }
  $ResolvedCompanion = Resolve-InstallerFileSystemPath -Path $CompanionFile -PathType Leaf
  $CompanionLength = (Get-Item -LiteralPath $ResolvedCompanion -Force).Length
  if ($ExpectedName -notmatch '<[^>]+>') {
    $ExpectedLeaf = [IO.Path]::GetFileName($ExpectedName.Trim().Trim('"').Replace('/', '\'))
    if (-not [string]::IsNullOrWhiteSpace($ExpectedLeaf) -and [IO.Path]::GetFileName($ResolvedCompanion) -ine $ExpectedLeaf) {
      throw "The supplied companion file does not match compiled DataFileName '$ExpectedName'."
    }
  }
  [long]$ExpectedLength = 0
  $RawExpectedLength = Get-DictionaryValue -Dictionary $Setup -Name @('DataFileSize')
  if ($null -ne $RawExpectedLength -and [long]::TryParse([string]$RawExpectedLength, [Globalization.NumberStyles]::Integer, [Globalization.CultureInfo]::InvariantCulture, [ref]$ExpectedLength) -and $ExpectedLength -gt 0 -and $CompanionLength -ne $ExpectedLength) {
    throw "The supplied companion file length $CompanionLength does not match compiled DataFileSize $ExpectedLength."
  }

  $Archive = $null
  try {
    $Archive = Get-InstallerArchive -Path $ResolvedCompanion
    if ([string]$Archive.Type -cne 'SevenZip') { throw 'The Actual Installer companion data file is not a supported 7z archive.' }
    $Catalog = [Collections.Generic.List[object]]::new()
    $SeenPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    [long]$ExpandedBytes = 0
    foreach ($Entry in Get-InstallerArchiveEntry -Archive $Archive) {
      if ($Catalog.Count -ge $Script:ActualInstallerMaximumEntries) { throw 'The Actual Installer companion catalog exceeds the configured entry limit.' }
      if ($Entry.IsEncrypted) { throw "The Actual Installer companion entry is encrypted: $($Entry.FullName)" }
      if (-not [string]::IsNullOrWhiteSpace($Entry.LinkTarget)) { throw "Actual Installer companion links are not supported: $($Entry.FullName)" }
      $RelativePath = ([string]$Entry.FullName).Replace('/', '\').TrimStart('\')
      $null = Resolve-SafeExtractionPath -DestinationPath ([IO.Path]::GetTempPath()) -RelativePath $RelativePath
      if (-not $SeenPaths.Add($RelativePath)) { throw "The Actual Installer companion archive contains duplicate path '$RelativePath'." }
      if ([long]$Entry.Length -lt 0 -or [long]$Entry.Length -gt $MaximumCatalogBytes - $ExpandedBytes) { throw 'The Actual Installer companion catalog exceeds the configured output limit.' }
      $ExpandedBytes += [long]$Entry.Length
      $Catalog.Add([pscustomobject][ordered]@{
          Index             = $null
          Destination       = '<InstallDir>\' + $RelativePath
          RelativePath      = $RelativePath
          RecordValue       = $null
          IfExistsMode      = $null
          OverwriteMode     = $null
          RemoveOnUninstall = $null
          PolicyEncoding    = 'CompanionArchive'
          ConditionState    = 'Unconditional'
          Fields            = [string[]]@()
          Available         = $true
          ContainerType     = 'SevenZipCompanion'
          ContainerOffset   = 0L
          ContainerLength   = $CompanionLength
          SourceName        = [string]$Entry.FullName
          Length            = [long]$Entry.Length
          Container         = $null
          ExternalData      = $true
          ArchiveEntry      = $Entry
        })
    }
    return [pscustomobject]@{ Path = $ResolvedCompanion; Archive = $Archive; Catalog = $Catalog.ToArray(); EntryCount = $Catalog.Count; ExpandedBytes = $ExpandedBytes }
  } catch {
    if ($Archive) { $Archive.Dispose() }
    throw
  }
}

function Close-ActualInstallerCompanionContext {
  <#
  .SYNOPSIS
    Dispose a context returned by Open-ActualInstallerCompanionContext.
  .PARAMETER Context
    Open companion archive context.
  #>
  param ([Parameter(Mandatory, ValueFromPipeline)][psobject]$Context)
  process { if ($Context.Archive) { $Context.Archive.Dispose() } }
}

function Export-ActualInstallerCompanionSelection {
  <#
  .SYNOPSIS
    Export selected companion entries through one already-open archive.
  .PARAMETER Context
    Open validated companion context.
  .PARAMETER Selection
    Records containing Item and an already reserved DestinationPath.
  .PARAMETER MaximumExpandedBytes
    Maximum aggregate output for the selection.
  #>
  [OutputType([IO.FileInfo[]])]
  param (
    [Parameter(Mandatory)][psobject]$Context,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Selection,
    [Parameter(Mandatory)][ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes
  )

  if (-not $Context.Archive) { throw 'The Actual Installer companion context is closed or invalid.' }
  if ($Selection.Count -gt $Script:ActualInstallerMaximumEntries) { throw 'The Actual Installer companion selection exceeds the configured entry limit.' }
  $Files = [Collections.Generic.List[IO.FileInfo]]::new($Selection.Count)
  [long]$ExpandedBytes = 0
  foreach ($Output in $Selection) {
    $Item = $Output.Item
    if (-not $Item.ExternalData -or -not $Item.ArchiveEntry) { throw 'An Actual Installer companion selection does not reference a validated archive entry.' }
    if ([long]$Item.Length -lt 0 -or [long]$Item.Length -gt $MaximumExpandedBytes - $ExpandedBytes) { throw 'The Actual Installer companion selection exceeds the configured output limit.' }
    $ExpandedBytes += [long]$Item.Length
    $EntryLimit = [Math]::Max(1L, [long]$Item.Length)
    $Files.Add((Export-InstallerArchiveEntry -Entry $Item.ArchiveEntry -DestinationPath ([string]$Output.DestinationPath) -MaximumBytes $EntryLimit -CollisionAction Overwrite))
  }
  return $Files.ToArray()
}

function Export-ActualInstallerCompanionData {
  <#
  .SYNOPSIS
    Extract a caller-supplied Setup EXE + Data archive into its installation-root layout.
  .PARAMETER Layout
    Parsed Actual Installer layout whose configuration names the companion data file.
  .PARAMETER CompanionFile
    Local 7z data file supplied alongside the setup executable; it is never downloaded.
  .PARAMETER DestinationPath
    Resolved extraction root corresponding to `<InstallDir>`.
  .PARAMETER Name
    Optional wildcard matched against paths inside the companion archive.
  .PARAMETER CollisionAction
    Collision behavior applied only after a selected output conflicts.
  .PARAMETER MaximumExpandedBytes
    Maximum aggregate expanded output in bytes.
  .PARAMETER ReservedPath
    Optional caller-owned path set shared with embedded payload selection.
  #>
  [OutputType([IO.FileInfo[]])]
  param (
    [Parameter(Mandatory)][psobject]$Layout,
    [Parameter(Mandatory)][string]$CompanionFile,
    [Parameter(Mandatory)][string]$DestinationPath,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction,
    [Parameter(Mandatory)][ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes,
    [Collections.Generic.ISet[string]]$ReservedPath
  )

  if (-not $ReservedPath) { $ReservedPath = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase) }
  $Context = Open-ActualInstallerCompanionContext -Layout $Layout -CompanionFile $CompanionFile -MaximumCatalogBytes $MaximumExpandedBytes
  try {
    $Selection = [Collections.Generic.List[object]]::new()
    foreach ($Item in $Context.Catalog) {
      if (-not (Test-ExtractionPattern -Path $Item.RelativePath -Pattern $Name)) { continue }
      $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $Item.RelativePath -CollisionAction $CollisionAction -ReservedPath $ReservedPath
      if ($Target.ShouldWrite) { $Selection.Add([pscustomobject]@{ Item = $Item; DestinationPath = $Target.Path }) }
    }
    return Export-ActualInstallerCompanionSelection -Context $Context -Selection $Selection.ToArray() -MaximumExpandedBytes $MaximumExpandedBytes
  } finally { Close-ActualInstallerCompanionContext -Context $Context }
}

function Get-ActualInstallerPayloadEvidence {
  <#
  .SYNOPSIS
    Analyze the configured main executable and bounded adjacent sidecars.
  .PARAMETER Layout
    Reusable Actual Installer layout.
  .PARAMETER MainExecutable
    Compiled main-executable destination expression.
  .PARAMETER Diagnostics
    Mutable structured diagnostic list.
  .PARAMETER CompanionContext
    Optional validated companion archive used by Setup EXE + Data media.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Layout,
    [AllowNull()][string]$MainExecutable,
    [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[object]]$Diagnostics,
    [AllowNull()][psobject]$CompanionContext
  )

  $Empty = [pscustomobject]@{ Architectures = @(); ArchitectureInfo = $null; DependencyInfo = $null }
  if ([string]::IsNullOrWhiteSpace($MainExecutable)) { return $Empty }
  $NormalizedMain = $MainExecutable.Trim().Trim('"').Replace('/', '\')
  $AvailableCatalog = [Collections.Generic.List[object]]::new()
  foreach ($Item in $Layout.PayloadCatalog) { if ($Item.Available) { $AvailableCatalog.Add($Item) } }
  if ($CompanionContext) { foreach ($Item in $CompanionContext.Catalog) { $AvailableCatalog.Add($Item) } }
  $MainCandidates = @($AvailableCatalog | Where-Object { $_.Destination.Trim().Trim('"').Replace('/', '\') -ieq $NormalizedMain })
  if ($MainCandidates.Count -ne 1) {
    $Kind = $MainCandidates.Count -eq 0 ? 'not present in the mapped payload' : 'ambiguous in the mapped payload'
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'ActualInstaller.Payload.MainExecutableUnresolved' -Source ActualInstaller -Message "The configured main executable '$MainExecutable' is $Kind; payload architecture and dependency evidence is unavailable." -Kind Incomplete -Areas Metadata -AffectedFields Architecture, Dependencies))
    return $Empty
  }

  $Main = $MainCandidates[0]
  $Directory = [IO.Path]::GetDirectoryName($Main.RelativePath)
  $Related = @($AvailableCatalog | Where-Object {
      -not [object]::ReferenceEquals($_, $Main) -and [IO.Path]::GetDirectoryName($_.RelativePath) -ieq $Directory -and [IO.Path]::GetExtension($_.RelativePath) -iin '.dll', '.json'
    } | Select-Object -First ($Script:ActualInstallerMaximumAnalysisFiles - 1))
  $Selection = @($Main) + $Related
  [long]$DeclaredBytes = ($Selection | Measure-Object -Property Length -Sum).Sum
  if ($DeclaredBytes -gt $Script:ActualInstallerMaximumAnalysisBytes) {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'ActualInstaller.Payload.AnalysisLimit' -Source ActualInstaller -Message "Main-executable analysis requires $DeclaredBytes bytes, above the $Script:ActualInstallerMaximumAnalysisBytes-byte limit." -Kind Incomplete -Areas Metadata -AffectedFields Architecture, Dependencies))
    return $Empty
  }

  $TemporaryRoot = New-TempFolder
  try {
    $EmbeddedSelection = [Collections.Generic.List[object]]::new()
    $CompanionSelection = [Collections.Generic.List[object]]::new()
    $Files = [Collections.Generic.List[string]]::new($Selection.Count)
    foreach ($Item in $Selection) {
      $DestinationPath = Resolve-SafeExtractionPath -DestinationPath $TemporaryRoot -RelativePath $Item.RelativePath
      $Output = [pscustomobject]@{ Item = $Item; DestinationPath = $DestinationPath }
      if ($Item.ExternalData) { $CompanionSelection.Add($Output) } else { $EmbeddedSelection.Add($Output) }
      $Files.Add($DestinationPath)
    }
    $null = Export-ActualInstallerPayloadSelection -Layout $Layout -Selection $EmbeddedSelection.ToArray() -MaximumExpandedBytes $Script:ActualInstallerMaximumAnalysisBytes
    if ($CompanionSelection.Count -gt 0) {
      if (-not $CompanionContext) { throw 'Companion payload analysis was selected without an open companion archive.' }
      $null = Export-ActualInstallerCompanionSelection -Context $CompanionContext -Selection $CompanionSelection.ToArray() -MaximumExpandedBytes $Script:ActualInstallerMaximumAnalysisBytes
    }
    $MainPath = $Files[0]
    try {
      $ArchitectureInfo = Get-PEArchitectureInfo -Path $MainPath -RelatedFile @($Files | Select-Object -Skip 1 | Where-Object { [IO.Path]::GetExtension($_) -ieq '.dll' })
      $Architectures = @($ArchitectureInfo.RecommendedWinGetArchitectures | Where-Object { $_ -in 'x86', 'x64', 'arm64' } | Sort-Object -Unique)
    } catch {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'ActualInstaller.Payload.ArchitectureAnalysisFailed' -Source ActualInstaller -Message "The configured main executable could not be analyzed as PE architecture evidence: $($_.Exception.Message)" -Kind Incomplete -Areas Metadata -AffectedFields Architecture))
      $ArchitectureInfo = $null
      $Architectures = @()
    }
    try { $DependencyInfo = Get-PEDependencyInfo -Path $MainPath -RelatedFile @($Files | Select-Object -Skip 1) }
    catch {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'ActualInstaller.Payload.DependencyAnalysisFailed' -Source ActualInstaller -Message "The configured main executable dependency analysis failed: $($_.Exception.Message)" -Kind Incomplete -Areas Metadata -AffectedFields Dependencies))
      $DependencyInfo = $null
    }
    return [pscustomobject]@{ Architectures = $Architectures; ArchitectureInfo = $ArchitectureInfo; DependencyInfo = $DependencyInfo }
  } finally { Remove-Item -LiteralPath $TemporaryRoot -Recurse -Force -ErrorAction SilentlyContinue }
}

function Get-ActualInstallerLayout {
  <#
  .SYNOPSIS
    Parse the PE, container sequence, metadata configuration, and payload catalog once.
  .PARAMETER Path
    Installer path. It is resolved before use by managed APIs.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)

  $File = Get-Item -LiteralPath (Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf) -Force
  $PELayout = Get-PELayout -Path $File.FullName
  if (-not $PELayout) { throw 'The file is not a valid PE image.' }
  $OverlayOffset = Get-PEOverlayOffset -Path $File.FullName
  $Containers = @(Read-ActualInstallerCabinetCatalog -Path $File.FullName -OverlayOffset $OverlayOffset)
  $CabinetHasConfiguration = @($Containers.Entries | Where-Object { $_.FullName -iin @('setup.ini', 'aisetup.ini') }).Count -gt 0

  # A modern payload ZIP can itself store a CAB file. Such nested bytes are a
  # valid cabinet signature but not an outer Cabinet3/4/5 route. Prefer the ZIP
  # route unless a discovered top-level cabinet names the setup configuration.
  if ($Containers.Count -eq 0 -or -not $CabinetHasConfiguration) { $Containers = @(Get-ActualInstallerZipCatalog -Path $File.FullName) }
  if ($Containers.Count -eq 0) { throw 'The PE does not contain a supported Actual Installer container sequence.' }
  $Containers = @($Containers | Sort-Object Offset)

  $MetadataCandidates = @($Containers | ForEach-Object {
      $Container = $_
      $Container.Entries | Where-Object { $_.FullName -iin @('setup.ini', 'aisetup.ini') } | ForEach-Object { [pscustomobject]@{ Container = $Container; EntryName = $_.SourceName } }
    })
  if ($MetadataCandidates.Count -ne 1) { throw "Expected one Actual Installer setup configuration, found $($MetadataCandidates.Count)." }
  $MetadataContainer = $MetadataCandidates[0].Container
  $MetadataEntryName = $MetadataCandidates[0].EntryName
  $Route = Get-ActualInstallerRoute -Containers $Containers -MetadataContainer $MetadataContainer -MetadataEntryName $MetadataEntryName
  $Configuration = Read-ActualInstallerConfiguration -Path $File.FullName -Container $MetadataContainer -EntryName $MetadataEntryName
  $Setup = $Configuration['Setup']
  if ($null -eq $Setup -or [string]::IsNullOrWhiteSpace([string](Get-DictionaryValue -Dictionary $Setup -Name @('AppName')))) { throw 'The Actual Installer configuration does not contain a valid [Setup] product identity.' }
  $FileRecords = @(Get-ActualInstallerFileRecord -FilesSection $Configuration['Files'] -Route $Route)
  $CompanionDataFile = [string](Get-DictionaryValue -Dictionary $Setup -Name @('DataFileName'))
  if ($FileRecords.Count -eq 0 -and [string]::IsNullOrWhiteSpace($CompanionDataFile)) { throw 'The Actual Installer configuration does not contain a supported [Files] table or companion data file.' }
  if ($Route.PayloadEncoding -eq 'ExternalSevenZip' -and [string]::IsNullOrWhiteSpace($CompanionDataFile)) { throw 'The metadata-only Actual Installer route does not declare a companion data file.' }
  $PayloadCatalog = @(Get-ActualInstallerPayloadCatalog -Route $Route -Containers $Containers -MetadataContainer $MetadataContainer -FileRecords $FileRecords)
  [pscustomobject]@{ Path = $File.FullName; FileLength = [long]$File.Length; PELayout = $PELayout; OverlayOffset = [long]$OverlayOffset; Route = $Route; Containers = $Containers; MetadataContainer = $MetadataContainer; MetadataEntryName = $MetadataEntryName; Configuration = $Configuration; FileRecords = $FileRecords; PayloadCatalog = $PayloadCatalog }
}

function Get-ActualInstallerInfo {
  <#
  .SYNOPSIS
    Parse Actual Installer metadata, ARP behavior, scope, switches, and payload evidence.
  .PARAMETER Path
    Installer path. The parser does not execute or load the installer.
  .PARAMETER CompanionFile
    Optional local Setup EXE + Data archive. When supplied, its catalog and the
    configured main executable participate in architecture/dependency analysis.
  .OUTPUTS
    A common installer-info object plus Actual Installer route, configuration,
    payload, registry, association, switch, and parser-version evidence.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$CompanionFile
  )

  process {
    $Layout = Get-ActualInstallerLayout -Path $Path
    $Setup = $Layout.Configuration['Setup']
    $Diagnostics = [Collections.Generic.List[object]]::new()
    $Unresolved = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $RequestedExecutionLevel = Get-PERequestedExecutionLevel -Path $Layout.Path
    $ArchitectureConfiguration = Get-ActualInstallerArchitectureInfo -Setup $Setup -Path $Layout.Path
    $Is64Bit = $ArchitectureConfiguration.Uses64BitLayout
    $ScopeInfo = Get-ActualInstallerScopeInfo -Setup $Setup -RequestedExecutionLevel $RequestedExecutionLevel
    $DefaultInstallLocation = Get-ActualInstallerDefaultInstallLocation -Setup $Setup -ScopeInfo $ScopeInfo -Is64Bit $Is64Bit
    $SetupParameterInfo = Get-ActualInstallerSetupParameterInfo -Setup $Setup
    if ($ArchitectureConfiguration.ConfigurationKey -and -not $ArchitectureConfiguration.LayoutEvidenceKnown) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'ActualInstaller.Architecture.UnknownConfiguration' -Source ActualInstaller -Message "The compiled architecture value '$($ArchitectureConfiguration.ConfigurationValue)' under '$($ArchitectureConfiguration.ConfigurationKey)' is not a recognized Actual Installer layout value." -Kind Incomplete -Areas Metadata -AffectedFields Architecture))
    }

    $DisplayVersion = [string](Get-DictionaryValue -Dictionary $Setup -Name @('AppVersion'))
    if ($DisplayVersion -match '^<[^>]+>$') {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'ActualInstaller.Metadata.DynamicVersion' -Source 'ActualInstaller' -Message "The Actual Installer AppVersion '$DisplayVersion' is a runtime expression and is not static product-version evidence." -Kind Incomplete -Areas Metadata -AffectedFields DisplayVersion))
      $null = $Unresolved.Add('DisplayVersion')
      $DisplayVersion = $null
    }
    $BuilderVersion = [string](Get-DictionaryValue -Dictionary $Setup -Name @('AIVer', 'Version'))
    if ([string]::IsNullOrWhiteSpace($BuilderVersion)) { try { $BuilderVersion = [string](Read-ProductVersionRawFromExe -Path $Layout.Path) } catch { $BuilderVersion = $null } }
    [int]$BuilderMajor = 0
    if ($BuilderVersion -match '^(?<Major>\d+)') { $BuilderMajor = [int]$Matches.Major }
    if ($BuilderMajor -gt 0 -and ($BuilderMajor -lt [int]$Layout.Route.MinimumMajor -or $BuilderMajor -gt [int]$Layout.Route.MaximumMajor)) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'ActualInstaller.Format.VersionRouteMismatch' -Source 'ActualInstaller' -Message "Actual Installer builder version '$BuilderVersion' conflicts with structural route '$($Layout.Route.Id)'; the structural route remains authoritative." -Kind Mismatch -Areas Detection, Metadata -Evidence ([ordered]@{ BuilderVersion = $BuilderVersion; Route = $Layout.Route.Id })))
    }

    $DisplayName = [string](Get-DictionaryValue -Dictionary $Setup -Name @('AppName'))
    $Publisher = [string](Get-DictionaryValue -Dictionary $Setup -Name @('CompanyName', 'Publisher'))
    $MainExecutable = [string](Get-DictionaryValue -Dictionary $Setup -Name @('MainExecutable', 'MainExe'))
    $UninstallValue = Get-DictionaryValue -Dictionary $Setup -Name @('Uninstall')
    $UninstallEnabled = Test-ActualInstallerBooleanValue -Value $UninstallValue -Default $true
    $ShowValue = Get-DictionaryValue -Dictionary $Setup -Name @('ShowAddRemove', 'ShowInAddRemovePrograms')
    $WritesBuiltInAppsAndFeaturesEntry = $UninstallEnabled -and (Test-ActualInstallerBooleanValue -Value $ShowValue -Default $UninstallEnabled)
    $Guid = [string](Get-DictionaryValue -Dictionary $Setup -Name @('GUID', 'Guid', 'ProductGUID'))
    if ($Guid -notmatch '^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$') { $Guid = $null }
    # The Cabinet4 runtime predates Product GUID storage. VM validation of the
    # official 4.8 builder media proves that it uses AppName verbatim as the
    # uninstall-key name and appends AppVersion to the visible DisplayName.
    # Cabinet3 remains unresolved because its silent route did not complete and
    # therefore supplied no installed-state evidence.
    $UsesCabinet4NameKey = $WritesBuiltInAppsAndFeaturesEntry -and $Layout.Route.Id -ceq 'Cabinet4'
    $BuiltInProductCode = if (-not $WritesBuiltInAppsAndFeaturesEntry) { $null } elseif ($Guid) { $Guid } elseif ($UsesCabinet4NameKey) { $DisplayName } else { $null }
    if ($WritesBuiltInAppsAndFeaturesEntry -and -not $BuiltInProductCode) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'ActualInstaller.ARP.LegacyKeyUnresolved' -Source 'ActualInstaller' -Message 'The configuration enables a visible Apps & Features entry but this legacy generation does not expose the uninstall-key identity as a Product GUID.' -Kind Incomplete -Areas Metadata -AffectedFields ProductCode, AppsAndFeaturesEntries))
      $null = $Unresolved.Add('ProductCode')
    }

    $RegistryOperations = @(Get-ActualInstallerRegistryWrite -RegistrySection $Layout.Configuration['Registry'] -DefaultScope ([string]$ScopeInfo.DefaultScope) -Setup $Setup -Is64Bit $Is64Bit -InstallLocation $DefaultInstallLocation)
    $RegistryWrites = @($RegistryOperations | Where-Object CanProject)
    $RegistryAssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite $RegistryWrites
    foreach ($Diagnostic in @($RegistryAssociationInfo.Diagnostics)) { $Diagnostics.Add($Diagnostic) }
    $ExtensionAssociations = @(Get-ActualInstallerExtensionInfo -ExtensionsSection $Layout.Configuration['Extensions'] -Setup $Setup -Is64Bit $Is64Bit -InstallLocation $DefaultInstallLocation)
    $FileExtensions = @(@($RegistryAssociationInfo.FileExtensions) + @($ExtensionAssociations.FileExtension) | Sort-Object -Unique)
    $Commands = @(Get-ActualInstallerCommandInfo -CommandsSection $Layout.Configuration['Commands'] -Setup $Setup -Is64Bit $Is64Bit -InstallLocation $DefaultInstallLocation)
    $CommandApplicability = @(Get-ActualInstallerCommandApplicability -Command $Commands -SetupParameterInfo $SetupParameterInfo)
    $Shortcuts = @(Get-ActualInstallerShortcutInfo -ShortcutsSection $Layout.Configuration['Shortcuts'] -Setup $Setup -Is64Bit $Is64Bit -InstallLocation $DefaultInstallLocation)
    $Variables = @(Get-ActualInstallerVariableInfo -VariablesSection $Layout.Configuration['Variables'])
    $Requirements = Get-ActualInstallerRequirementInfo -Setup $Setup
    $MediaInfo = Get-ActualInstallerMediaInfo -Setup $Setup -Commands $Commands -Variables $Variables
    $RuntimeRegistryOperations = @($RegistryOperations | Where-Object { -not $_.CanProject })
    if ($RuntimeRegistryOperations.Count -gt 0) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'ActualInstaller.Registry.RuntimeExpression' -Source ActualInstaller -Message "$($RuntimeRegistryOperations.Count) registry operation(s) contain runtime-only key or value expressions and are excluded from static ARP and association projection." -Kind Incomplete -Areas Metadata -AffectedFields ProductCode, AppsAndFeaturesEntries, Protocols, FileExtensions -Evidence ([ordered]@{ Sources = @($RuntimeRegistryOperations.Source) })))
    }
    $RuntimeCommandConditions = @($Commands | Where-Object { $_.Condition.State -eq 'Unknown' })
    if ($RuntimeCommandConditions.Count -gt 0) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'ActualInstaller.Commands.RuntimeCondition' -Source ActualInstaller -Message "$($RuntimeCommandConditions.Count) command condition(s) require runtime or interactive evidence; guarded side effects are not treated as unconditional." -Kind Ambiguous -Areas Extraction, Installability -Evidence ([ordered]@{ CommandIndexes = @($RuntimeCommandConditions.Index); Reasons = @($RuntimeCommandConditions.Condition.Reason | Sort-Object -Unique) })))
    }
    $EncodedCommandCount = @($Commands | Where-Object { $_.EncodedFieldIndexes.Count -gt 0 }).Count
    if ($EncodedCommandCount -gt 0) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'ActualInstaller.Configuration.EncodedCommandsDecoded' -Source ActualInstaller -Message "$EncodedCommandCount command record(s) used the validated Actual Installer XOR-2 field encoding and were decoded." -Kind Information -Areas Metadata -Evidence ([ordered]@{ CommandIndexes = @($Commands | Where-Object { $_.EncodedFieldIndexes.Count -gt 0 } | Select-Object -ExpandProperty Index) })))
    }
    if ($MediaInfo.CompanionDataFile -and -not $PSBoundParameters.ContainsKey('CompanionFile')) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'ActualInstaller.Extraction.CompanionDataRequired' -Source ActualInstaller -Message "The compiled setup expects companion 7z data file '$($MediaInfo.CompanionDataFile)'. Supply the local file to Expand-ActualInstallerInstaller through -CompanionFile; static analysis does not discover or download it." -Kind Incomplete -Areas Extraction -AffectedFields ExtractedFiles -Evidence ([ordered]@{ DataFileName = $MediaInfo.CompanionDataFile; ArchiveFormat = $MediaInfo.CompanionArchiveFormat })))
    } elseif (-not $MediaInfo.CompanionDataFile -and $PSBoundParameters.ContainsKey('CompanionFile')) {
      throw 'CompanionFile was supplied, but the Actual Installer configuration does not declare external setup data.'
    }
    if ($MediaInfo.ExternalDownloads.Count -gt 0) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'ActualInstaller.Extraction.RuntimeDownload' -Source ActualInstaller -Message "$($MediaInfo.ExternalDownloads.Count) payload download(s) are performed by compiled commands at installation time and are not fetched by static parsing." -Kind Incomplete -Areas Extraction, Installability -Evidence ([ordered]@{ Urls = @($MediaInfo.ExternalDownloads.Url) })))
    }
    $CustomAppsAndFeaturesEvidence = @(Get-ActualInstallerCustomAppsAndFeaturesEntry -RegistryWrite $RegistryWrites)
    $Uninstaller = [string](Get-DictionaryValue -Dictionary $Setup -Name @('UninstallFile', 'UninstallFileName', 'Uninstaller'))
    if ($UninstallEnabled -and [string]::IsNullOrWhiteSpace($Uninstaller)) { $Uninstaller = 'Uninstall.exe' }
    $DisplayIcon = Join-ActualInstallerManifestPath -BasePath $DefaultInstallLocation -ChildPath $MainExecutable
    $UninstallString = Join-ActualInstallerManifestPath -BasePath $DefaultInstallLocation -ChildPath $Uninstaller
    $QuietUninstallString = $null
    if (-not $DefaultInstallLocation) { $null = $Unresolved.Add('DefaultInstallLocation') }

    $GeneratedOutputs = @(Get-ActualInstallerGeneratedOutputInfo -Layout $Layout -Uninstaller $Uninstaller -UninstallEnabled $UninstallEnabled)
    $GeneratedFromTemplate = @($GeneratedOutputs | Where-Object { $_.Kind -in 'GeneratedUninstaller', 'GeneratedUpdater' -and -not $_.CanReconstruct })
    if ($GeneratedFromTemplate.Count -gt 0) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'ActualInstaller.Extraction.GeneratedTemplateOutput' -Source ActualInstaller -Message "$($GeneratedFromTemplate.Count) generated output(s) have source-backed metadata helper templates, but their final bytes are not established for the selected route." -Kind Incomplete -Areas Extraction -Evidence ([ordered]@{ Outputs = @($GeneratedFromTemplate | ForEach-Object { [ordered]@{ Destination = $_.Destination; TemplateEntry = $_.TemplateEntry } }) })))
    }
    $ReconstructableOutputs = @($GeneratedOutputs | Where-Object { $_.Kind -in 'GeneratedUninstaller', 'GeneratedUpdater' -and $_.CanReconstruct })
    if ($ReconstructableOutputs.Count -gt 0) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'ActualInstaller.Extraction.GeneratedHelperExactCopy' -Source ActualInstaller -Message "$($ReconstructableOutputs.Count) generated uninstaller output(s) can be reconstructed as exact copies of their metadata helpers on this structural route." -Kind Information -Areas Extraction -Evidence ([ordered]@{ Outputs = @($ReconstructableOutputs | ForEach-Object { [ordered]@{ Destination = $_.Destination; TemplateEntry = $_.TemplateEntry; Mode = $_.ReconstructionMode } }) })))
    }
    $UnresolvedOutputs = @($GeneratedOutputs | Where-Object Kind -EQ 'UnresolvedLogicalOutput')
    if ($UnresolvedOutputs.Count -gt 0) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'ActualInstaller.Extraction.MissingPayload' -Source ActualInstaller -Message "$($UnresolvedOutputs.Count) logical file record(s) have neither a direct payload entry nor a unique metadata helper template." -Kind Incomplete -Areas Extraction -Evidence ([ordered]@{ Indexes = @($UnresolvedOutputs.FileRecordIndex) })))
    }
    $BuiltInAppsAndFeaturesEntry = if ($WritesBuiltInAppsAndFeaturesEntry) {
      $ArpDisplayName = if (($UsesCabinet4NameKey -or $SetupParameterInfo.IncludesVersionInDisplayName) -and $DisplayVersion) { "$DisplayName $DisplayVersion" } else { $DisplayName }
      $Entry = [ordered]@{ DisplayName = $ArpDisplayName; Publisher = $Publisher; InstallerType = 'exe' }
      if ($BuiltInProductCode) { $Entry['ProductCode'] = $BuiltInProductCode }
      if ($DisplayVersion) { $Entry['DisplayVersion'] = $DisplayVersion }
      [pscustomobject]$Entry
    } else { $null }
    $AppsAndFeaturesCandidates = @($BuiltInAppsAndFeaturesEntry) + @($CustomAppsAndFeaturesEvidence.ManifestEntry)
    $AppsAndFeaturesEntries = @(Merge-ActualInstallerAppsAndFeaturesEntry -Entry @($AppsAndFeaturesCandidates | Where-Object { $null -ne $_ }))
    $WritesAppsAndFeaturesEntry = $AppsAndFeaturesEntries.Count -gt 0
    $ProductCode = if ($BuiltInProductCode) { $BuiltInProductCode } elseif ($CustomAppsAndFeaturesEvidence.Count -eq 1) { $CustomAppsAndFeaturesEvidence[0].ProductCode } else { $null }
    if (-not $BuiltInProductCode -and $CustomAppsAndFeaturesEvidence.Count -eq 1) {
      $null = $Unresolved.Remove('ProductCode')
      $CustomValues = $CustomAppsAndFeaturesEvidence[0].Values
      if ($CustomValues.ContainsKey('InstallLocation')) { $DefaultInstallLocation = [string]$CustomValues['InstallLocation'] }
      if ($CustomValues.ContainsKey('DisplayIcon')) { $DisplayIcon = [string]$CustomValues['DisplayIcon'] }
      if ($CustomValues.ContainsKey('UninstallString')) { $UninstallString = [string]$CustomValues['UninstallString'] }
      if ($CustomValues.ContainsKey('QuietUninstallString')) { $QuietUninstallString = [string]$CustomValues['QuietUninstallString'] }
    }
    if ($CustomAppsAndFeaturesEvidence.Count -gt 1 -and -not $BuiltInProductCode) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'ActualInstaller.ARP.MultipleCustomEntries' -Source ActualInstaller -Message 'The installer defines more than one complete custom Apps & Features entry; no single ProductCode can be selected without scenario evidence.' -Kind Ambiguous -Areas Metadata -AffectedFields ProductCode, AppsAndFeaturesEntries -Evidence ([ordered]@{ ProductCodes = @($CustomAppsAndFeaturesEvidence.ProductCode) })))
      $null = $Unresolved.Add('ProductCode')
    }

    if (-not $SetupParameterInfo.AllowsSilent) {
      $Reason = $SetupParameterInfo.Tokens -icontains '-nosilent' ? 'the compiled -nosilent setup parameter' : 'a compiled User Information dialog without -silentinstalluserinfo'
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'ActualInstaller.Installability.SilentDisabled' -Source ActualInstaller -Message "Silent installation is disabled by $Reason." -Kind Unsupported -Areas Installability -AffectedFields InstallerSwitches, InstallModes))
    }
    $InstallerSwitches = [ordered]@{ InstallLocation = '/D "<INSTALLPATH>"' }
    $InstallModes = @('interactive')
    if ($SetupParameterInfo.AllowsSilent) {
      $InstallerSwitches['Silent'] = '/S'
      $InstallerSwitches['SilentWithProgress'] = '/S'
      $InstallModes += 'silent'
    }
    $CompanionContext = $null
    $CompanionPayloadCatalog = @()
    try {
      if ($PSBoundParameters.ContainsKey('CompanionFile')) {
        $CompanionContext = Open-ActualInstallerCompanionContext -Layout $Layout -CompanionFile $CompanionFile
        $CompanionPayloadCatalog = @($CompanionContext.Catalog | Select-Object -Property * -ExcludeProperty ArchiveEntry, Container)
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'ActualInstaller.Extraction.CompanionDataAnalyzed' -Source ActualInstaller -Message "The supplied companion data archive contributed $($CompanionContext.EntryCount) installed payload record(s) to static analysis." -Kind Information -Areas Extraction, Metadata -Evidence ([ordered]@{ DataFileName = [IO.Path]::GetFileName($CompanionContext.Path); EntryCount = $CompanionContext.EntryCount; ExpandedBytes = $CompanionContext.ExpandedBytes })))
      }
      $PayloadEvidence = Get-ActualInstallerPayloadEvidence -Layout $Layout -MainExecutable $MainExecutable -Diagnostics $Diagnostics -CompanionContext $CompanionContext
    } finally {
      if ($CompanionContext) { Close-ActualInstallerCompanionContext -Context $CompanionContext }
    }
    $ElevationRequirement = if ($ScopeInfo.Scope -eq 'machine' -and $RequestedExecutionLevel -eq 'requireAdministrator') { 'elevatesSelf' } else { $null }
    $RegistryHive = if ($WritesBuiltInAppsAndFeaturesEntry -and $ScopeInfo.Scope -eq 'machine') { 'HKLM' } elseif ($WritesBuiltInAppsAndFeaturesEntry -and $ScopeInfo.Scope -eq 'user') { 'HKCU' } elseif (-not $WritesBuiltInAppsAndFeaturesEntry -and $CustomAppsAndFeaturesEvidence.Count -eq 1) { $CustomAppsAndFeaturesEvidence[0].Root } else { $null }
    $RegistryView = if (-not $WritesBuiltInAppsAndFeaturesEntry -and $CustomAppsAndFeaturesEvidence.Count -eq 1) { $CustomAppsAndFeaturesEvidence[0].RegistryView } else { $ArchitectureConfiguration.RegistryView }
    $SilentUninstallCommand = if ($QuietUninstallString) { $QuietUninstallString } elseif ($WritesBuiltInAppsAndFeaturesEntry -and $UninstallString) { '"' + $UninstallString.Trim('"') + '" /S' } else { $null }
    $UninstallerCommandEvidence = [pscustomobject][ordered]@{
      Source                             = $WritesBuiltInAppsAndFeaturesEntry ? 'BuiltInRegistration' : ($CustomAppsAndFeaturesEvidence.Count -eq 1 ? 'CustomRegistry' : 'None')
      RegistryUninstallString            = $UninstallString
      RegistryQuietUninstallString       = $QuietUninstallString
      SilentCommand                      = $SilentUninstallCommand
      SilentSwitch                       = $WritesBuiltInAppsAndFeaturesEntry ? '/S' : $null
      RegistryStoresQuietUninstallString = $WritesBuiltInAppsAndFeaturesEntry ? $false : ($null -ne $QuietUninstallString)
      Quoting                            = $WritesBuiltInAppsAndFeaturesEntry ? 'ARP stores the generated uninstaller path without quotes; invoke the executable path quoted when appending /S.' : 'Authored custom registry value'
    }
    $PublicPayloadCatalog = @($Layout.PayloadCatalog | Select-Object -Property * -ExcludeProperty Container)
    $InstalledPayloadCatalog = @($PublicPayloadCatalog + $CompanionPayloadCatalog)
    $Operations = [pscustomobject][ordered]@{ Files = @($Layout.FileRecords); Registry = $RegistryOperations; Extensions = $ExtensionAssociations; Shortcuts = $Shortcuts; Commands = $Commands }

    [pscustomobject][ordered]@{
      Path = $Layout.Path; InstallerType = 'exe'; ProductCode = $ProductCode; UpgradeCode = $null; DisplayName = $DisplayName; DisplayVersion = $DisplayVersion; Publisher = $Publisher; Scope = $ScopeInfo.Scope
      DefaultInstallLocation = $DefaultInstallLocation; WritesAppsAndFeaturesEntry = $WritesAppsAndFeaturesEntry; AppsAndFeaturesProductCode = $ProductCode; AppsAndFeaturesInstallerType = $WritesAppsAndFeaturesEntry ? 'exe' : $null
      Diagnostics = @(Merge-InstallerDiagnostics -Diagnostic $Diagnostics.ToArray()); UnresolvedFields = [string[]]@($Unresolved | Sort-Object); Family = 'Actual Installer'; FormatGeneration = $Layout.Route.Id; ContainerRoute = $Layout.Route.Container; BuilderVersion = $BuilderVersion
      Configuration = $Layout.Configuration; PayloadCatalog = $PublicPayloadCatalog; CompanionPayloadCatalog = $CompanionPayloadCatalog; InstalledPayloadCatalog = $InstalledPayloadCatalog; EmbeddedContainers = @($Layout.Containers | ForEach-Object { [pscustomobject]@{ Type = $_.Type; Offset = $_.Offset; Length = $_.Length; Entries = @($_.Entries) } })
      PublisherUrl = Get-DictionaryValue -Dictionary $Setup -Name @('WebSite', 'PublisherUrl'); SupportUrl = Get-DictionaryValue -Dictionary $Setup -Name @('SupportLink', 'SupportUrl')
      MainExecutable = $MainExecutable; Uninstaller = $Uninstaller; UninstallString = $UninstallString; QuietUninstallString = $QuietUninstallString; UninstallerCommandEvidence = $UninstallerCommandEvidence; DisplayIcon = $DisplayIcon; AppsAndFeaturesEntries = $AppsAndFeaturesEntries; BuiltInAppsAndFeaturesEntry = $BuiltInAppsAndFeaturesEntry; CustomAppsAndFeaturesEvidence = $CustomAppsAndFeaturesEvidence
      RegistryHive = $RegistryHive; RegistryView = $RegistryView; SupportedScopes = [string[]]$ScopeInfo.SupportedScopes; DefaultScope = $ScopeInfo.DefaultScope; ScopeSwitches = $ScopeInfo.ScopeSwitches; InstallLevel = $ScopeInfo.InstallLevel
      RequestedExecutionLevel = $RequestedExecutionLevel; ElevationRequirement = $ElevationRequirement; InstallerSwitches = $InstallerSwitches; InstallModes = $InstallModes; InstallerSuccessCodes = @()
      ExitCodeEvidence = $Script:ActualInstallerExitCodeEvidence; SetupParameterInfo = $SetupParameterInfo; UninstallerSwitches = [ordered]@{ Silent = '/S' }; ArchitectureConfiguration = $ArchitectureConfiguration; Architecture = $PayloadEvidence.Architectures.Count -eq 1 ? $PayloadEvidence.Architectures[0] : $ArchitectureConfiguration.SetupArchitecture; PayloadArchitectures = @($PayloadEvidence.Architectures); PayloadArchitectureInfo = $PayloadEvidence.ArchitectureInfo; PayloadDependencyInfo = $PayloadEvidence.DependencyInfo
      RegistryWrites = $RegistryWrites; RegistryOperations = $RegistryOperations; RegistryAssociationInfo = $RegistryAssociationInfo; Protocols = [string[]]$RegistryAssociationInfo.Protocols; FileExtensionAssociations = $ExtensionAssociations; FileExtensions = [string[]]$FileExtensions
      Shortcuts = $Shortcuts; Commands = $Commands; CommandApplicability = $CommandApplicability; Variables = $Variables; Requirements = $Requirements; MediaInfo = $MediaInfo; ExternalPayloads = @($MediaInfo.ExternalDownloads); ExternalArchivePlans = @($MediaInfo.ExternalArchivePlans)
      GeneratedOutputs = $GeneratedOutputs; GeneratedUninstaller = $GeneratedOutputs | Where-Object Kind -EQ 'GeneratedUninstaller' | Select-Object -First 1; Operations = $Operations; MetadataEntries = @($Layout.MetadataContainer.Entries)
      ParserVersionInfo = [pscustomobject]@{ Parser = 'Dumplings.PackageModule.ActualInstaller'; ParserMajor = 4; CatalogVersion = $Script:ActualInstallerCatalog.CatalogVersion; Sources = @('PE overlay', 'Microsoft Cabinet CFFILE table', 'ZIP central directory', 'explicit companion 7z catalog', $Layout.MetadataEntryName, '[Files] payload index', '[Registry]', '[Extensions]', '[Shortcuts]', '[Commands]', '[Variables]') }
    }
  }
}

function Expand-ActualInstallerInstaller {
  <#
  .SYNOPSIS
    Extract installed payload files or exact raw Actual Installer containers.
  .PARAMETER Path
    Installer path. Relative paths are resolved before managed decoder access.
  .PARAMETER DestinationPath
    Safe extraction root. A temporary directory is created when omitted.
  .PARAMETER Name
    Optional wildcard matched against installed relative paths. Omission selects all files.
  .PARAMETER CollisionAction
    Action used only when an output collision is detected. Internal callers should use Rename.
  .PARAMETER MaximumExpandedBytes
    Maximum aggregate output in bytes.
  .PARAMETER RawEntries
    Export exact physical CAB/ZIP ranges under _actual instead of installed files.
  .PARAMETER MetadataEntries
    Export selected files from the metadata container under _actual\metadata. This exposes language, image, and helper-template inputs without representing them as installed files.
  .PARAMETER CompanionFile
    Local 7z file named by the compiled DataFileName value. It is expanded as the source-directory tree below the installation root; the parser never downloads it.
  #>
  [OutputType([IO.FileInfo[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [AllowEmptyString()][string]$Name,
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Prompt',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 16GB,
    [switch]$RawEntries,
    [switch]$MetadataEntries,
    [string]$CompanionFile
  )

  process {
    $Layout = Get-ActualInstallerLayout -Path $Path
    if ([string]::IsNullOrWhiteSpace($DestinationPath)) { $DestinationPath = Join-Path ([IO.Path]::GetTempPath()) ("Dumplings-ActualInstaller-$([guid]::NewGuid().ToString('N'))") }
    $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
    $null = New-Item -Path $DestinationPath -ItemType Directory -Force
    $Pattern = $PSBoundParameters.ContainsKey('Name') -and -not [string]::IsNullOrWhiteSpace($Name) ? $Name : '*'
    $ReservedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $Results = [Collections.Generic.List[IO.FileInfo]]::new()
    [long]$ExpandedBytes = 0

    if ($RawEntries -and $MetadataEntries) { throw 'RawEntries and MetadataEntries are mutually exclusive.' }
    if (($RawEntries -or $MetadataEntries) -and $PSBoundParameters.ContainsKey('CompanionFile')) { throw 'CompanionFile can be used only with installed-payload extraction.' }

    if ($RawEntries) {
      for ($Index = 0; $Index -lt $Layout.Containers.Count; $Index++) {
        $Container = $Layout.Containers[$Index]
        $Extension = $Container.Type -eq 'Cabinet' ? 'cab' : 'zip'
        $RelativePath = "_actual\container-$('{0:D4}' -f $Index).$Extension"
        if (-not (Test-ExtractionPattern -Path $RelativePath -Pattern $Pattern)) { continue }
        $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $RelativePath -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
        if (-not $Target.ShouldWrite) { continue }
        if ($Container.Length -gt $MaximumExpandedBytes - $ExpandedBytes) { throw 'Actual Installer raw entries exceed the configured output limit.' }
        $File = Export-InstallerArchiveRange -Path $Layout.Path -Offset $Container.Offset -Length $Container.Length -DestinationPath $Target.Path -CollisionAction Overwrite
        $ExpandedBytes += $File.Length
        $Results.Add($File)
      }
    } elseif ($MetadataEntries) {
      foreach ($File in @(Export-ActualInstallerMetadataSelection -Layout $Layout -DestinationPath $DestinationPath -Name $Pattern -CollisionAction $CollisionAction -MaximumExpandedBytes $MaximumExpandedBytes -ReservedPath $ReservedPaths)) {
        $ExpandedBytes += $File.Length
        $Results.Add($File)
      }
    } else {
      $Selected = @($Layout.PayloadCatalog | Where-Object { $_.Available -and (Test-ExtractionPattern -Path $_.RelativePath -Pattern $Pattern) })
      if ($Selected.Count -gt $Script:ActualInstallerMaximumEntries) { throw 'The Actual Installer selection exceeds the configured entry limit.' }
      $PayloadSelection = [Collections.Generic.List[object]]::new($Selected.Count)
      foreach ($Item in $Selected) {
        if ($Item.Length -lt 0 -or $Item.Length -gt $MaximumExpandedBytes - $ExpandedBytes) { throw 'The Actual Installer payload exceeds the configured output limit.' }
        $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $Item.RelativePath -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
        if (-not $Target.ShouldWrite) { continue }
        $PayloadSelection.Add([pscustomobject]@{ Item = $Item; DestinationPath = $Target.Path })
        $ExpandedBytes += [long]$Item.Length
      }
      foreach ($File in @(Export-ActualInstallerPayloadSelection -Layout $Layout -Selection $PayloadSelection.ToArray() -MaximumExpandedBytes $MaximumExpandedBytes)) { $Results.Add($File) }

      # Cabinet5 and numbered-ZIP runtimes were observed installing the helper
      # bytes unchanged. Materialize only outputs explicitly marked ExactCopy;
      # updater helpers and unverified generations remain metadata evidence.
      $Setup = $Layout.Configuration['Setup']
      $UninstallEnabled = Test-ActualInstallerBooleanValue -Value (Get-DictionaryValue -Dictionary $Setup -Name @('Uninstall')) -Default $true
      $Uninstaller = [string](Get-DictionaryValue -Dictionary $Setup -Name @('UninstallFile', 'UninstallFileName', 'Uninstaller'))
      if ($UninstallEnabled -and [string]::IsNullOrWhiteSpace($Uninstaller)) { $Uninstaller = 'Uninstall.exe' }
      $GeneratedSelection = [Collections.Generic.List[object]]::new()
      foreach ($Generated in @(Get-ActualInstallerGeneratedOutputInfo -Layout $Layout -Uninstaller $Uninstaller -UninstallEnabled $UninstallEnabled | Where-Object { $_.CanReconstruct -and $_.ReconstructionMode -eq 'ExactCopy' -and (Test-ExtractionPattern -Path $_.RelativePath -Pattern $Pattern) })) {
        if ([long]$Generated.TemplateLength -lt 0 -or [long]$Generated.TemplateLength -gt $MaximumExpandedBytes - $ExpandedBytes) { throw 'The Actual Installer generated output exceeds the configured output limit.' }
        $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $Generated.RelativePath -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
        if (-not $Target.ShouldWrite) { continue }
        $GeneratedSelection.Add([pscustomobject]@{ SourceName = $Generated.TemplateEntry; DestinationPath = $Target.Path; Length = [long]$Generated.TemplateLength })
        $ExpandedBytes += [long]$Generated.TemplateLength
      }
      if ($GeneratedSelection.Count -gt 0) {
        foreach ($File in @(Export-ActualInstallerContainerSelection -Layout $Layout -Container $Layout.MetadataContainer -Selection $GeneratedSelection.ToArray() -MaximumExpandedBytes $MaximumExpandedBytes)) { $Results.Add($File) }
      }
      $CompanionDataFile = [string](Get-DictionaryValue -Dictionary $Layout.Configuration['Setup'] -Name @('DataFileName'))
      if (-not [string]::IsNullOrWhiteSpace($CompanionDataFile)) {
        if (-not $PSBoundParameters.ContainsKey('CompanionFile') -or [string]::IsNullOrWhiteSpace($CompanionFile)) { throw "Actual Installer extraction requires companion data file '$CompanionDataFile'." }
        foreach ($File in @(Export-ActualInstallerCompanionData -Layout $Layout -CompanionFile $CompanionFile -DestinationPath $DestinationPath -Name $Pattern -CollisionAction $CollisionAction -MaximumExpandedBytes ($MaximumExpandedBytes - $ExpandedBytes) -ReservedPath $ReservedPaths)) {
          $ExpandedBytes += $File.Length
          $Results.Add($File)
        }
      } elseif ($PSBoundParameters.ContainsKey('CompanionFile')) {
        throw 'CompanionFile was supplied, but the Actual Installer configuration does not declare external setup data.'
      }
    }

    if ($Results.Count -eq 0) { throw "No Actual Installer files matched '$Pattern'." }
    return $Results.ToArray()
  }
}

function Test-ActualInstaller {
  <#
  .SYNOPSIS
    Test for a structurally valid supported Actual Installer artifact.
  .PARAMETER Path
    Candidate installer path.
  #>
  [OutputType([bool])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { try { $null = Get-ActualInstallerLayout -Path $Path; return $true } catch { return $false } }
}

function Read-ProductVersionFromActualInstaller {
  <#
  .SYNOPSIS
    Read the statically resolved application version.
  .PARAMETER Path
    Installer path.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-ActualInstallerInfo -Path $Path).DisplayVersion }
}

function Read-ProductNameFromActualInstaller {
  <#
  .SYNOPSIS
    Read the configured application name.
  .PARAMETER Path
    Installer path.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-ActualInstallerInfo -Path $Path).DisplayName }
}

function Read-PublisherFromActualInstaller {
  <#
  .SYNOPSIS
    Read the configured publisher.
  .PARAMETER Path
    Installer path.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-ActualInstallerInfo -Path $Path).Publisher }
}

function Read-ProductCodeFromActualInstaller {
  <#
  .SYNOPSIS
    Read a proven visible Actual Installer ARP ProductCode.
  .PARAMETER Path
    Installer path.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-ActualInstallerInfo -Path $Path).ProductCode }
}

function Read-ScopeFromActualInstaller {
  <#
  .SYNOPSIS
    Read the single configured installation scope, or null for dual-scope media.
  .PARAMETER Path
    Installer path.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-ActualInstallerInfo -Path $Path).Scope }
}

function Read-ProtocolsFromActualInstaller {
  <#
  .SYNOPSIS
    Read source-proven literal URL protocols.
  .PARAMETER Path
    Installer path.
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-ActualInstallerInfo -Path $Path).Protocols }
}

function Read-FileExtensionsFromActualInstaller {
  <#
  .SYNOPSIS
    Read source-proven literal file extensions.
  .PARAMETER Path
    Installer path.
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-ActualInstallerInfo -Path $Path).FileExtensions }
}

Export-ModuleMember -Function Get-ActualInstallerInfo, Expand-ActualInstallerInstaller, Test-ActualInstaller, Read-ProductVersionFromActualInstaller, Read-ProductNameFromActualInstaller, Read-PublisherFromActualInstaller, Read-ProductCodeFromActualInstaller, Read-ScopeFromActualInstaller, Read-ProtocolsFromActualInstaller, Read-FileExtensionsFromActualInstaller
