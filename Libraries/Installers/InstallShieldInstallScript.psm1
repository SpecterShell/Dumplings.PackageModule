# SPDX-License-Identifier: Apache-2.0
# Format references:
# - https://docs.revenera.com/installshield/helplibrary/IHelpSetup_EXECmdLine.htm
# - https://docs.revenera.com/installshield/helplibrary/SetupIni.htm
# - https://docs.revenera.com/installshield/helplibrary/StartupSection.htm
# - https://docs.revenera.com/installshield/LangRef/LangrefMaintenanceStart.htm
# - https://docs.revenera.com/installshield/LangRef/LangrefPRODUCT_GUID.htm
# - https://docs.revenera.com/installshield/LangRef/RegSpecialFuncs.htm
# - https://docs.revenera.com/installshield/LangRef/LangrefRegDBSetDefaultRoot.htm
# - https://docs.revenera.com/installshield/LangRef/LangrefRegDBSetKeyValueEx.htm
# - https://docs.revenera.com/installshield/LangRef/LangrefCreateRegistrySet.htm
# - https://docs.revenera.com/installshield/LangRef/LangrefCreateShellObjects.htm
# - https://docs.revenera.com/installshield/LangRef/LangrefLaunchAppAndWait.htm
# - https://docs.revenera.com/installshield28helplib/LangRef/LangrefMODE.htm
# - https://docs.revenera.com/installshield28helplib/helplibrary/CreatetheResponseFile.htm
# - https://github.com/jte/installscript-decompiler
#
# InstallScript media layout consumed by this module:
#
#   InstallShield launcher/extracted Disk1
#   +-- setup.ini
#   |   `-- [Startup]: Product, ProductGUID, CompanyName
#   +-- setup.inx / setup.ins: compiled InstallScript
#   |   +-- 0x00: source-backed header route
#   |   |   +-- B8 C9 0C 00 -> INS-Old event/action stream
#   |   |   +-- 48 4F F3 C9 -> OBS
#   |   |   +-- 61 4C 75 5A -> aLuZ
#   |   |   +-- 6B 55 74 5A -> kUtZ
#   |   |   `-- 70 4F 64 41 -> OBL authoring-library catalog
#   |   +-- INS-Old
#   |   |   +-- uint16-length info string and event count
#   |   |   +-- globals, structures, and function/DLL prototypes
#   |   |   `-- repeated event headers and tagged action records
#   |   +-- OBS object module
#   |   |   +-- fixed 0x100-byte header
#   |   |   +-- extern, prototype, typedef, address-resolution, and BB tables
#   |   |   `-- independently decodable compiler/linker input
#   |   +-- OBL
#   |   |   +-- version and member count, uint32 LE
#   |   |   +-- uint16-length name + uint32 offset + uint32 length
#   |   |   `-- bounded embedded INS/OBS/aLuZ/kUtZ compiler inputs
#   |   `-- decoded OBS/aLuZ/kUtZ program profile
#   |       +-- compiler metadata and bounded table offsets
#   |       +-- type/function/label catalogs
#   |       +-- typed function prototypes and absolute label offsets
#   |       +-- function-start / variable-length action records
#   |       `-- function-end records
#   +-- setup.iss: optional default silent-response file
#   +-- StringTable_0xLLLL.ips: localized compiler resources
#   `-- data1.hdr: cabinet and project-media descriptor
#       +-- descriptor+0x27E -> shell-folder/shortcut pointer graph
#       `-- descriptor+0x282 -> registry-set/root/key/value pointer graph
#
# Modern INX bytes may be scrambled independently at each byte position:
# decoded = ROR8(encoded XOR 0xF1, 2) - (absoluteOffset modulo 71).
# The structural reader and bounded abstract interpreter never invoke imported
# native functions. They reconstruct callsite-backed response dialog order,
# documented registry/process/file/shortcut effects, localized resources, and
# MaintenanceStart defaults. Compiler-generated 0x003B property proxies are
# returned as structural getter/setter/handle evidence but are not invoked. The
# cabinet reader supplies media-authored records;
# this module joins them to CreateRegistrySet/CreateShellObjects and component
# transfer semantics. Unsupported behavior remains explicit rather than guessed.

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# The mechanical bytecode reader is compiled once per process. It emits a
# structural IR only; installer imports and instructions are never executed.
$InstallScriptSource = @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot '..\..\Assets\Source\InstallShieldInstallScript') -Filter '*.cs' -File | Sort-Object Name | Select-Object -ExpandProperty FullName)
$null = Import-InstallerManagedSource -Path $InstallScriptSource -TypeName 'Dumplings.InstallShield.InstallScript.InstallScriptBytecodeReader'

$Script:InstallScriptCopyrightMarkers = [string[]]@(
  'Copyright (c) 1990-2002 InstallShield Software Corp. All Rights Reserved.'
  'Copyright (c) 1990-1999 Stirling Technologies, Ltd. All Rights Reserved.'
)
$Script:InstallScriptMaximumBytes = 32MB
$Script:InstallScriptMaximumStrings = 32768
$Script:InstallScriptDialogPattern = '^(?:Sd(?:Welcome(?:Maint)?|License(?:Rtf)?|AskDestPath\d*|StartCopy\d*|Finish(?:Reboot|Update)?|FeatureTree|ComponentTree|SetupCompleteError)|LicenseDialog|MessageBox(?:Ex|W)?|SelectDir)$'
$Script:InstallScriptInstallPattern = '^(?:FeatureTransferData|ComponentMoveData|CopyFile|XCopyFile|LaunchApp(?:AndWait)?|RegDBSet|AddFolderIcon|CreateDir)'
$Script:InstallScriptUninstallRegistryPath = 'Software\Microsoft\Windows\CurrentVersion\Uninstall'

function Get-InstallShieldInstallScriptHeaderKind {
  <#
  .SYNOPSIS
    Classify a bounded compiled InstallScript header by source-backed magic bytes.
  .PARAMETER Bytes
    At least four bytes from offset zero of the decoded or encoded script file.
  .PARAMETER DecodeScrambled
    Apply InstallShield's position-dependent F1/ROR2 transform before testing
    aLuZ and kUtZ. The input array is not modified.
  .OUTPUTS
    HeaderKind, scrambling evidence, magic bytes, and handler support status.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [switch]$DecodeScrambled
  )

  if ($Bytes.Length -lt 4) { return $null }
  $Probe = if ($DecodeScrambled) {
    $Decoded = [byte[]]::new($Bytes.Length)
    for ($Index = 0; $Index -lt $Bytes.Length; $Index++) {
      $Value = $Bytes[$Index] -bxor 0xF1
      $Rotated = (($Value -shr 2) -bor (($Value -shl 6) -band 0xFF)) -band 0xFF
      $Decoded[$Index] = [byte](($Rotated - ($Index % 71)) -band 0xFF)
    }
    $Decoded
  } else { $Bytes }

  $MagicAscii = [Text.Encoding]::ASCII.GetString($Probe, 0, 4)
  $HeaderKind = if ($Probe[0] -eq 0x48 -and $Probe[1] -eq 0x4F -and $Probe[2] -eq 0xF3 -and $Probe[3] -eq 0xC9) {
    'OBS'
  } elseif ($MagicAscii -ceq 'pOdA') {
    'OBL'
  } elseif ($MagicAscii -ceq 'aLuZ') {
    'aLuZ'
  } elseif ($MagicAscii -ceq 'kUtZ') {
    'kUtZ'
  } elseif ($Probe[0] -eq 0xB8 -and $Probe[1] -eq 0xC9 -and $Probe[2] -eq 0x0C -and $Probe[3] -eq 0x00) {
    'INS-Old'
  } else { $null }
  if (-not $HeaderKind) { return $null }

  $SupportStatus = 'Supported'
  [pscustomobject][ordered]@{
    HeaderKind    = $HeaderKind
    WasScrambled  = [bool]$DecodeScrambled
    MagicHex      = [Convert]::ToHexString($Probe[0..3])
    MagicAscii    = $MagicAscii
    SupportStatus = $SupportStatus
    Handler       = $HeaderKind -eq 'INS-Old' ? 'InstallScript old-layout reader' : ($HeaderKind -eq 'OBL' ? 'InstallScript OBL library reader' : 'InstallScriptBytecodeReader')
    Limitations   = [string[]]@(
      if ($HeaderKind -eq 'INS-Old') { 'Old INS event/action records are decoded; generation-dependent actions remain explicit opaque evidence.' }
      if ($HeaderKind -eq 'OBL') { 'OBL is a build-time object library. Analyze the final linked INX when installer-runtime behavior is required.' }
    )
  }
}

function Get-InstallShieldInstallScriptHeaderInfo {
  <#
  .SYNOPSIS
    Read and classify only the bounded header of a compiled InstallScript file.
  .PARAMETER Path
    Path to setup.inx, setup.ins, an OBS object, or an OBL library.
  .OUTPUTS
    Structural header evidence without decoding the complete instruction stream.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory, Position = 0, ValueFromPipeline)][string]$Path)

  process {
    $ResolvedPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
    $Stream = [IO.File]::Open($ResolvedPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
      $Length = [int][Math]::Min(512L, $Stream.Length)
      if ($Length -lt 4) { throw 'The compiled InstallScript header is truncated.' }
      $Bytes = Read-BinaryBytes -Stream $Stream -Offset 0 -Count $Length
    } finally { $Stream.Dispose() }

    $Info = Get-InstallShieldInstallScriptHeaderKind -Bytes $Bytes
    if (-not $Info) { $Info = Get-InstallShieldInstallScriptHeaderKind -Bytes $Bytes -DecodeScrambled }
    if (-not $Info) { throw 'The file does not contain a recognized OBS, aLuZ, kUtZ, OBL, or old INS header.' }
    $Info | Add-Member -NotePropertyName Path -NotePropertyValue $ResolvedPath
    return $Info
  }
}

# InstallScript configuration and response-file handling.
function Get-InstallShieldInstallScriptConfigurationValue {
  <#
  .SYNOPSIS
    Read one case-insensitive value from parsed Setup.ini configuration.
  .PARAMETER Configuration
    Section dictionaries produced while parsing the extracted Setup.ini file.
  .PARAMETER Section
    Setup.ini section name, such as Startup.
  .PARAMETER Name
    Key name within the selected section.
  .OUTPUTS
    The authored scalar value, or null when the section or key is absent.
  #>
  param (
    [AllowNull()]
    [System.Collections.IDictionary]$Configuration,

    [Parameter(Mandatory)]
    [string]$Section,

    [Parameter(Mandatory)]
    [string]$Name
  )

  if ($null -eq $Configuration) { return $null }
  $SectionValue = $Configuration[$Section]
  if ($SectionValue -isnot [System.Collections.IDictionary]) { return $null }
  return $SectionValue[$Name]
}

function Read-InstallShieldInstallScriptConfiguration {
  <#
  .SYNOPSIS
    Parse the small extracted Setup.ini used by a standalone parser call.
  .PARAMETER Path
    Resolved Setup.ini path. The file is metadata and is limited to 4 MiB.
  .OUTPUTS
    Ordered section dictionaries preserving the last authored key value.
  #>
  [OutputType([System.Collections.IDictionary])]
  param (
    [Parameter(Mandatory)]
    [string]$Path
  )

  return ConvertFrom-Ini -Path $Path -MaximumBytes 4MB -DuplicateKeyAction Last -IgnoreComments
}

function ConvertTo-InstallShieldInstallScriptProductCode {
  <#
  .SYNOPSIS
    Normalize Setup.ini ProductGUID to the InstallScript uninstall-key form.
  .PARAMETER Value
    ProductGUID text from Setup.ini. Braces are accepted but not required.
  .OUTPUTS
    An uppercase braced GUID, or null when the value is not a GUID.
  #>
  [OutputType([string])]
  param (
    [AllowNull()]
    [string]$Value
  )

  if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
  $Guid = [guid]::Empty
  if (-not [guid]::TryParse($Value.Trim(), [ref]$Guid)) { return $null }
  return '{' + $Guid.ToString('D').ToUpperInvariant() + '}'
}

function Read-InstallShieldResponseFile {
  <#
  .SYNOPSIS
    Validate an embedded InstallShield silent response file and return its dialog evidence.
  .PARAMETER Path
    Path to the extracted setup.iss candidate.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]
    [string]$Path
  )

  $File = Get-Item -LiteralPath $Path -Force
  if ($File.Length -gt 4MB) { throw 'The embedded InstallShield response file exceeds the 4 MiB metadata limit.' }
  $Text = [IO.File]::ReadAllText($File.FullName)
  if ($Text -notmatch '(?im)^\s*\[InstallShield Silent\]\s*$' -or $Text -notmatch '(?im)^\s*File\s*=\s*Response File\s*$') {
    throw 'The embedded setup.iss does not contain a valid InstallShield Silent header.'
  }
  $Sections = [ordered]@{}
  $CurrentSection = $null
  foreach ($Line in $Text -split '\r?\n') {
    $Trimmed = $Line.Trim()
    if (-not $Trimmed -or $Trimmed.StartsWith(';', [StringComparison]::Ordinal) -or $Trimmed.StartsWith('#', [StringComparison]::Ordinal)) { continue }
    if ($Trimmed -match '^\[(?<Section>[^\]]+)\]$') {
      $CurrentSection = $Matches.Section
      if (-not $Sections.Contains($CurrentSection)) { $Sections[$CurrentSection] = [ordered]@{} }
      continue
    }
    if ($CurrentSection -and $Trimmed -match '^(?<Name>[^=]+)=(?<Value>.*)$') {
      $Sections[$CurrentSection][$Matches.Name.Trim()] = $Matches.Value.Trim()
    }
  }

  # The DlgOrder section is authoritative. Other dialog sections can describe
  # maintenance or reboot paths that are not part of this recorded scenario.
  $OrderSectionName = @($Sections.Keys | Where-Object { $_ -match '-DlgOrder$' }) | Select-Object -First 1
  $Dialogs = [Collections.Generic.List[string]]::new()
  $DialogNames = [Collections.Generic.List[string]]::new()
  $ProductCode = $null
  if ($OrderSectionName) {
    if ($OrderSectionName -match '^(?<Guid>\{[0-9A-Fa-f-]{36}\})-DlgOrder$') { $ProductCode = $Matches.Guid.ToUpperInvariant() }
    $OrderSection = $Sections[$OrderSectionName]
    $OrderKeys = @($OrderSection.Keys | Where-Object { $_ -match '^Dlg\d+$' } | Sort-Object { [int]($_ -replace '^Dlg') })
    foreach ($Key in $OrderKeys) {
      $DialogIdentifier = [string]$OrderSection[$Key]
      $Dialogs.Add($DialogIdentifier)
      if ($DialogIdentifier -match '^\{[0-9A-Fa-f-]{36}\}-(?<Name>.+)-\d+$') { $DialogNames.Add($Matches.Name) }
      else { $DialogNames.Add($DialogIdentifier) }
    }
  }
  [pscustomobject][ordered]@{
    Path        = $File.FullName
    Length      = $File.Length
    ProductCode = $ProductCode
    Dialogs     = [string[]]$Dialogs.ToArray()
    DialogNames = [string[]]$DialogNames.ToArray()
    DialogCount = $Dialogs.Count
    Sections    = $Sections
    Content     = $Text
  }
}

function New-InstallShieldResponseFileTemplate {
  <#
  .SYNOPSIS
    Create an InstallShield response-file template from a static dialog trace.
  .DESCRIPTION
    The function creates the documented InstallShield Silent and DlgOrder
    sections and known built-in dialog keys. Conditional/custom dialogs remain
    explicit comments and make IsComplete false; their values are never guessed.
  .PARAMETER Trace
    One trace returned by Get-InstallShieldInstallScriptDialogTrace.
  .PARAMETER ProductCode
    Product GUID used as the response section prefix. If unresolved, the literal
    placeholder {PRODUCT-GUID} is used and the result is incomplete.
  .PARAMETER Path
    Optional output path. Parent directories are not created implicitly.
  .PARAMETER AllowIncomplete
    Permit writing a template containing unresolved alternatives/placeholders.
    Without this switch, incomplete content is returned but not written.
  .OUTPUTS
    A template result containing Content, IsComplete, Dialogs, Warnings, and Path.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, ValueFromPipeline)]
    [psobject]$Trace,

    [string]$ProductCode,

    [string]$Path,

    [switch]$AllowIncomplete
  )

  process {
    $Warnings = [Collections.Generic.List[string]]::new()
    foreach ($Warning in @($Trace.Warnings)) {
      if (-not [string]::IsNullOrWhiteSpace([string]$Warning)) { $Warnings.Add([string]$Warning) }
    }
    $NormalizedProductCode = ConvertTo-InstallShieldInstallScriptProductCode -Value $ProductCode
    if (-not $NormalizedProductCode) {
      $NormalizedProductCode = '{PRODUCT-GUID}'
      $Warnings.Add('Replace {PRODUCT-GUID} with the InstallScript ProductGUID before use.')
    }
    $Dialogs = [Collections.Generic.List[string]]::new()
    foreach ($Step in @($Trace.Steps)) {
      if ($Step.Dialog) { $Dialogs.Add([string]$Step.Dialog) }
      elseif (@($Step.Alternatives).Count) {
        $Warnings.Add("Resolve the conditional dialog at offset 0x$(([long]$Step.Offset).ToString('X')): $(@($Step.Alternatives) -join ', ').")
      }
    }

    $Lines = [Collections.Generic.List[string]]::new()
    $Lines.Add('[InstallShield Silent]')
    $Lines.Add('Version=v7.00')
    $Lines.Add('File=Response File')
    $Lines.Add('[File Transfer]')
    $Lines.Add('OverwrittenReadOnly=NoToAll')
    $Lines.Add("[$NormalizedProductCode-DlgOrder]")
    for ($Index = 0; $Index -lt $Dialogs.Count; $Index++) { $Lines.Add("Dlg$Index=$NormalizedProductCode-$($Dialogs[$Index])-0") }
    $Lines.Add("Count=$($Dialogs.Count)")

    foreach ($Dialog in $Dialogs) {
      $Lines.Add("[$NormalizedProductCode-$Dialog-0]")
      switch -Regex ($Dialog) {
        '^SdAskDestPath\d*$' { $Lines.Add('szDir=<INSTALLPATH>'); $Lines.Add('Result=1'); break }
        '^SdFinish$' { $Lines.Add('Result=1'); $Lines.Add('bOpt1=0'); $Lines.Add('bOpt2=0'); break }
        '^SdFinishReboot$' { $Lines.Add('Result=1'); $Lines.Add('BootOption=0'); break }
        '^(?:SdComponentTree|SdFeatureTree)$' {
          $Lines.Add('; TODO: record this dialog in the validation VM to obtain feature state data.')
          $Lines.Add('Result=1')
          $Warnings.Add("Dialog '$Dialog' contains project-specific feature data that cannot be generated statically.")
          break
        }
        default { $Lines.Add('Result=1') }
      }
    }
    foreach ($Step in @($Trace.Steps | Where-Object { @($_.Alternatives).Count })) {
      $Lines.Add("; TODO at 0x$(([long]$Step.Offset).ToString('X')): choose one of $(@($Step.Alternatives) -join ', ')")
    }

    $IsComplete = [bool]($Trace.IsComplete -and $Warnings.Count -eq 0)
    $Content = ($Lines -join "`r`n") + "`r`n"
    $ResolvedPath = $null
    if ($Path) {
      $ResolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
      if ($IsComplete -or $AllowIncomplete) { [IO.File]::WriteAllText($ResolvedPath, $Content, [Text.UTF8Encoding]::new($false)) }
      else { $Warnings.Add('The incomplete template was not written. Use -AllowIncomplete after reviewing its TODO entries.') }
    }
    [pscustomobject][ordered]@{
      Content    = $Content
      IsComplete = $IsComplete
      Dialogs    = [string[]]$Dialogs.ToArray()
      Warnings   = [string[]]$Warnings.ToArray()
      Path       = ($ResolvedPath -and (Test-Path -LiteralPath $ResolvedPath)) ? $ResolvedPath : $null
    }
  }
}

function Test-InstallShieldResponseFile {
  <#
  .SYNOPSIS
    Compare a response file with a statically reconstructed dialog trace.
  .PARAMETER Path
    Response file to parse and validate.
  .PARAMETER Trace
    Dialog trace returned by Get-InstallShieldInstallScriptDialogTrace.
  .OUTPUTS
    A structured result containing IsValid and ordered diagnostics.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, Position = 0)]
    [string]$Path,

    [Parameter(Mandatory)]
    [psobject]$Trace
  )

  $Response = Read-InstallShieldResponseFile -Path $Path
  $Diagnostics = [Collections.Generic.List[object]]::new()
  $Expected = [object[]]@($Trace.Steps | Where-Object { $_.Dialog -or @($_.Alternatives).Where({ $_ }).Count })
  $Actual = [string[]]@($Response.DialogNames)
  $Maximum = [Math]::Max($Expected.Count, $Actual.Count)
  for ($Index = 0; $Index -lt $Maximum; $Index++) {
    $ExpectedStep = $Index -lt $Expected.Count ? $Expected[$Index] : $null
    $ExpectedValue = $ExpectedStep ? $ExpectedStep.Dialog : $null
    $ExpectedAlternatives = $ExpectedStep ? [string[]]@($ExpectedStep.Alternatives | Where-Object { $_ }) : [string[]]@()
    $ActualValue = $Index -lt $Actual.Count ? $Actual[$Index] : $null
    if (($ExpectedValue -and $ExpectedValue -cne $ActualValue) -or ($ExpectedAlternatives.Count -and $ActualValue -cnotin $ExpectedAlternatives) -or (-not $ExpectedStep -and $ActualValue)) {
      $ExpectedDescription = $ExpectedAlternatives.Count ? ($ExpectedAlternatives -join ' or ') : $ExpectedValue
      $Diagnostics.Add([pscustomobject][ordered]@{
          Severity = 'Error'
          Id       = 'DialogOrderMismatch'
          Index    = $Index
          Expected = $ExpectedDescription
          Actual   = $ActualValue
          Message  = "Dialog position $Index expects '$ExpectedDescription' but the response file contains '$ActualValue'."
        })
    }
  }
  if (-not $Trace.IsComplete) {
    $Diagnostics.Add([pscustomobject][ordered]@{
        Severity = 'Warning'; Id = 'IncompleteStaticTrace'; Index = $null; Expected = $null; Actual = $null
        Message = 'The static trace contains conditional or opaque paths; a matching result still requires VM validation.'
      })
  }
  [pscustomobject][ordered]@{
    IsValid     = -not [bool]($Diagnostics | Where-Object Severity -EQ 'Error')
    Response    = $Response
    Trace       = $Trace
    Diagnostics = [object[]]$Diagnostics.ToArray()
  }
}

# InstallScript bytecode decoding.
function ConvertFrom-InstallShieldInstallScriptByteStream {
  <#
  .SYNOPSIS
    Validate and, when necessary, descramble a compiled InstallScript file.
  .PARAMETER Path
    Resolved path to an extracted setup.inx or setup.ins file.
  .OUTPUTS
    An object containing decoded bytes, encoding state, and bounded header evidence.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, Position = 0)]
    [string]$Path
  )

  $File = Get-Item -LiteralPath $Path -Force
  if ($File.Length -lt 4) { throw 'The compiled InstallScript file is truncated.' }
  if ($File.Length -gt $Script:InstallScriptMaximumBytes) { throw 'The compiled InstallScript file exceeds the 32 MiB analysis limit.' }
  $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try { $Bytes = Read-BinaryBytes -Stream $Stream -Offset 0 -Count ([int]$File.Length) }
  finally { $Stream.Dispose() }
  $Ascii = [Text.Encoding]::ASCII
  $HeaderKindInfo = Get-InstallShieldInstallScriptHeaderKind -Bytes $Bytes

  # Decoded generations expose the copyright marker immediately after the
  # CRC/version prefix. Search only the bounded header instead of accepting a
  # marker copied into arbitrary script data.
  $HeaderLength = [Math]::Min(512, $Bytes.Length)
  $HeaderText = $Ascii.GetString($Bytes, 0, $HeaderLength)
  $CopyrightMarker = $Script:InstallScriptCopyrightMarkers | Where-Object {
    $HeaderText.Contains($_, [StringComparison]::Ordinal)
  } | Select-Object -First 1
  $WasScrambled = $false
  if (-not $CopyrightMarker -and -not $HeaderKindInfo) {
    $Decoded = [byte[]]::new($Bytes.Length)
    for ($Index = 0; $Index -lt $Bytes.Length; $Index++) {
      $Value = $Bytes[$Index] -bxor 0xF1
      $Rotated = (($Value -shr 2) -bor (($Value -shl 6) -band 0xFF)) -band 0xFF
      $Decoded[$Index] = [byte](($Rotated - ($Index % 71)) -band 0xFF)
    }
    $HeaderText = $Ascii.GetString($Decoded, 0, $HeaderLength)
    $CopyrightMarker = $Script:InstallScriptCopyrightMarkers | Where-Object {
      $HeaderText.Contains($_, [StringComparison]::Ordinal)
    } | Select-Object -First 1
    if (-not $CopyrightMarker) {
      throw 'The file does not contain a supported decoded or scrambled InstallScript header.'
    }
    $Bytes = $Decoded
    $WasScrambled = $true
    $HeaderKindInfo = Get-InstallShieldInstallScriptHeaderKind -Bytes $Bytes
  }

  $MarkerOffset = $CopyrightMarker ? $HeaderText.IndexOf($CopyrightMarker, [StringComparison]::Ordinal) : -1
  if ($CopyrightMarker -and ($MarkerOffset -lt 4 -or $MarkerOffset + $CopyrightMarker.Length -gt $HeaderLength)) {
    throw 'The InstallScript copyright marker is outside the validated header range.'
  }
  if (-not $HeaderKindInfo) {
    # Existing builder generations with the validated compiler notice retain
    # the legacy INX route even if their first DWORD is not one of the newer
    # decompiler's named action-file magics.
    $HeaderKindInfo = [pscustomobject]@{ HeaderKind = ($File.Extension -ieq '.ins' ? 'INS-Old' : 'INX'); WasScrambled = $WasScrambled; SupportStatus = 'Partial' }
  }

  # The first DWORD is checksum-like metadata. The following WORD and offset
  # table vary across generations, so expose them as observed values and never
  # assign unsupported semantics to them.
  [pscustomobject][ordered]@{
    Path            = $File.FullName
    Bytes           = $Bytes
    WasScrambled    = $WasScrambled
    Checksum        = [BitConverter]::ToUInt32($Bytes, 0)
    HeaderValue     = [BitConverter]::ToUInt16($Bytes, 4)
    MarkerOffset    = $MarkerOffset
    CopyrightMarker = $CopyrightMarker
    HeaderKind      = $HeaderKindInfo.HeaderKind
    SupportStatus   = $HeaderKindInfo.SupportStatus
    Format          = $HeaderKindInfo.HeaderKind
  }
}

function Get-InstallShieldInstallScriptLibraryInfo {
  <#
  .SYNOPSIS
    Read the bounded member catalog from an InstallScript OBL library.
  .PARAMETER Path
    Path to a pOdA OBL file. The function resolves the path and reads no member
    outside its declared offset and length.
  .OUTPUTS
    OBL version, member names, byte ranges, structural member profiles, and
    parser warnings. Member payload bytes are not returned.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory, Position = 0, ValueFromPipeline)][string]$Path)

  process {
    $Decoded = ConvertFrom-InstallShieldInstallScriptByteStream -Path $Path
    if ($Decoded.HeaderKind -ne 'OBL') { throw 'The compiled script is not an InstallScript OBL library.' }
    $Library = [Dumplings.InstallShield.InstallScript.InstallScriptLibraryReader]::Read($Decoded.Bytes)
    [pscustomobject][ordered]@{
      Path              = $Decoded.Path
      Version           = $Library.Version
      CatalogLength     = $Library.CatalogLength
      MemberCount       = $Library.Members.Count
      Members           = [object[]]$Library.Members
      Warnings          = [string[]]$Library.Warnings
      ParserVersionInfo = [pscustomobject][ordered]@{
        Parser        = 'Dumplings.PackageModule.InstallShieldInstallScript'
        ParserMajor   = 11
        Format        = 'OBL'
        HeaderKind    = 'OBL'
        SupportStatus = 'Supported'
      }
    }
  }
}

function Resolve-InstallShieldInstallScriptProgramContent {
  <#
  .SYNOPSIS
    Select the byte range that contains one analyzable InstallScript program.
  .PARAMETER Decoded
    Result from ConvertFrom-InstallShieldInstallScriptByteStream.
  .PARAMETER LibraryMemberName
    Exact OBL member name. It may be omitted only when the library has one
    structurally recognized program member.
  .OUTPUTS
    Selected bytes, optional OBL member name, member count, and format profile.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][pscustomobject]$Decoded,
    [string]$LibraryMemberName
  )

  if ($Decoded.HeaderKind -ne 'OBL') {
    return [pscustomobject]@{ Bytes = $Decoded.Bytes; LibraryMemberName = $null; LibraryMemberCount = 0; Format = $Decoded.Format }
  }

  $Library = [Dumplings.InstallShield.InstallScript.InstallScriptLibraryReader]::Read($Decoded.Bytes)
  $Candidates = if ($LibraryMemberName) {
    @($Library.Members | Where-Object Name -CEQ $LibraryMemberName)
  } else {
    @($Library.Members | Where-Object FormatProfile -NE 'Unknown')
  }
  if ($Candidates.Count -ne 1) {
    $Available = [string]::Join(', ', [string[]]@($Library.Members.Name))
    if ($LibraryMemberName) { throw "The OBL library does not contain exactly one member named '$LibraryMemberName'. Available members: $Available" }
    throw "The OBL library contains $($Candidates.Count) analyzable members. Select one with -LibraryMemberName. Available members: $Available"
  }

  $Member = $Candidates[0]
  $MemberBytes = [Dumplings.InstallShield.InstallScript.InstallScriptLibraryReader]::ReadMember(
    $Decoded.Bytes, $Member, $Script:InstallScriptMaximumBytes)
  [pscustomobject]@{
    Bytes              = $MemberBytes
    LibraryMemberName  = $Member.Name
    LibraryMemberCount = $Library.Members.Count
    Format             = $Member.FormatProfile
  }
}

function Read-InstallShieldInstallScriptProgram {
  <#
  .SYNOPSIS
    Decode a modern compiled InstallScript file into a bounded structural IR.
  .DESCRIPTION
    The returned program contains function prototypes, instructions, operands,
    labels, calls, and parser warnings. It is an analysis model, not a runtime:
    DLL imports, registry operations, file operations, and child processes are
    never invoked.
  .PARAMETER Path
    Path to an extracted setup.inx. The path is resolved before the C# reader is
    called because the CLR working directory can differ from PowerShell's.
  .PARAMETER MaximumInstructions
    Upper bound for decoded instructions across the program. This prevents a
    malformed catalog from producing unbounded parser work.
  .PARAMETER LibraryMemberName
    Exact member name when Path is an OBL library. Omit it only when the OBL has
    exactly one structurally recognized program member.
  .OUTPUTS
    Dumplings.InstallShield.InstallScript.InstallScriptProgram.
  #>
  [OutputType([Dumplings.InstallShield.InstallScript.InstallScriptProgram])]
  param (
    [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
    [string]$Path,

    [ValidateRange(1, 10000000)]
    [int]$MaximumInstructions = 1000000,

    [string]$LibraryMemberName
  )

  process {
    $Decoded = ConvertFrom-InstallShieldInstallScriptByteStream -Path $Path
    $Selected = Resolve-InstallShieldInstallScriptProgramContent -Decoded $Decoded -LibraryMemberName $LibraryMemberName
    # The byte array is caller-owned by PowerShell and remains valid for the
    # duration of this synchronous parse. The returned IR does not retain it.
    $Program = if ($Selected.LibraryMemberName) {
      [Dumplings.InstallShield.InstallScript.InstallScriptLibraryReader]::ReadProgram($Selected.Bytes, $Selected.LibraryMemberName, $MaximumInstructions)
    } else {
      [Dumplings.InstallShield.InstallScript.InstallScriptBytecodeReader]::Read($Selected.Bytes, $MaximumInstructions)
    }
    return $Program
  }
}

function Get-InstallShieldInstallScriptStringEvidence {
  <#
  .SYNOPSIS
    Extract bounded ANSI and UTF-16 string evidence from decoded InstallScript bytes.
  .PARAMETER Bytes
    Decoded compiled-script bytes. The caller retains ownership of the array.
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Mandatory)]
    [byte[]]$Bytes
  )

  $Seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  $Values = [Collections.Generic.List[string]]::new()
  foreach ($Encoding in @([Text.Encoding]::ASCII, [Text.Encoding]::Unicode)) {
    $Text = $Encoding.GetString($Bytes)
    foreach ($Match in [regex]::Matches($Text, '[\x20-\x7E]{4,}')) {
      $Value = $Match.Value.Trim()
      if ($Value.Length -le 1024 -and $Seen.Add($Value)) {
        $Values.Add($Value)
        if ($Values.Count -ge $Script:InstallScriptMaximumStrings) { return [string[]]$Values.ToArray() }
      }
    }
  }
  return [string[]]$Values.ToArray()
}

function Read-InstallShieldInstallScriptStringTable {
  <#
  .SYNOPSIS
    Read localized InstallScript string identifiers from extracted IPS tables.
  .DESCRIPTION
    InstallShield stores compiler string resources in BOM-aware INI-like
    StringTable_*.ips files. Values from multiple locales are retained as
    alternatives so static emulation can project localized registry writes
    without selecting an arbitrary locale.
  .PARAMETER Path
    Paths to extracted StringTable_*.ips files. Each file is limited to 4 MiB
    and aggregate resource text is limited to 32 MiB.
  .OUTPUTS
    A case-sensitive dictionary whose values are arrays of distinct strings.
  #>
  [OutputType([Collections.Generic.Dictionary[string, string[]]])]
  param (
    [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
    [string[]]$Path
  )

  begin {
    $Values = [Collections.Generic.Dictionary[string, Collections.Generic.HashSet[string]]]::new([StringComparer]::Ordinal)
    $TotalBytes = 0L
  }
  process {
    foreach ($Candidate in $Path) {
      $File = Get-Item -LiteralPath $Candidate -Force
      if ($File.Length -gt 4MB) { throw "InstallScript string table '$($File.Name)' exceeds the 4 MiB limit." }
      if ($File.Length -gt 32MB - $TotalBytes) { throw 'InstallScript string tables exceed the 32 MiB aggregate limit.' }
      $TotalBytes += $File.Length
      $Reader = [IO.StreamReader]::new($File.FullName, [Text.Encoding]::UTF8, $true)
      try {
        while (-not $Reader.EndOfStream) {
          $Line = $Reader.ReadLine()
          if ([string]::IsNullOrWhiteSpace($Line) -or $Line.StartsWith(';', [StringComparison]::Ordinal) -or $Line.StartsWith('[', [StringComparison]::Ordinal)) { continue }
          $Separator = $Line.IndexOf('=')
          if ($Separator -le 0) { continue }
          $Key = $Line.Substring(0, $Separator).Trim()
          $Value = $Line.Substring($Separator + 1)
          if (-not $Values.ContainsKey($Key)) { $Values.Add($Key, [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)) }
          $null = $Values[$Key].Add($Value)
        }
      } finally {
        $Reader.Dispose()
      }
    }
  }
  end {
    $Result = [Collections.Generic.Dictionary[string, string[]]]::new([StringComparer]::Ordinal)
    foreach ($Pair in $Values.GetEnumerator()) { $Result.Add($Pair.Key, [string[]]@($Pair.Value | Sort-Object)) }
    return $Result
  }
}

# InstallScript dialog, media, ARP, and result analysis.
function Get-InstallShieldInstallScriptDialogTrace {
  <#
  .SYNOPSIS
    Build ordered response-dialog traces from InstallScript entry points.
  .DESCRIPTION
    Each call in an entry point is correlated with its target function and the
    literal dialog identifiers used by generated InstallShield wrappers. A
    trace is marked incomplete when a wrapper contains conditional alternatives
    or an instruction body could not be decoded.
  .PARAMETER Program
    Parsed InstallScriptProgram returned by Read-InstallShieldInstallScriptProgram.
  .PARAMETER EntryPoint
    Entry-point names to analyze. Fresh-install and maintenance UI handlers are
    selected by default.
  .OUTPUTS
    Trace objects containing Scenario, Steps, Dialogs, IsComplete, and Warnings.
  #>
  [OutputType([Dumplings.InstallShield.InstallScript.InstallScriptDialogTrace[]])]
  param (
    [Parameter(Mandatory, ValueFromPipeline)]
    [Dumplings.InstallShield.InstallScript.InstallScriptProgram]$Program,

    [string[]]$EntryPoint
  )

  process {
    # Call-graph traversal is mechanical and touches thousands of IR objects.
    # Keep it in the source-visible C# analyzer to avoid PowerShell pipeline
    # materialization while retaining response-file policy in this module.
    [Dumplings.InstallShield.InstallScript.InstallScriptDialogAnalyzer]::GetTraces($Program, $EntryPoint)
  }
}

function Invoke-InstallShieldInstallScriptAnalysis {
  <#
  .SYNOPSIS
    Perform bounded static analysis of a compiled InstallScript file.
  .PARAMETER Path
    Path to an extracted setup.inx or setup.ins file.
  .PARAMETER EmbeddedResponseFile
    Optional response file shipped beside the script and selected by InstallShield's default /s behavior.
  .PARAMETER StringTablePath
    Optional extracted StringTable_*.ips or String*.txt files used to resolve
    localized __LoadString calls during bounded static emulation.
  .PARAMETER EntryPoint
    Optional compiled function names that own the operation being analyzed.
    MSI and Advanced UI callers use this to avoid traversing unrelated
    standalone setup callbacks in the same compiled script.
  .PARAMETER AnalysisScope
    StandaloneInstaller applies InstallShield Silent response-file rules.
    EmbeddedAction records only behavior reachable from selected custom actions
    because the containing MSI or suite owns silent invocation.
  .PARAMETER LibraryMemberName
    Exact OBL member to analyze. Omit it only when the library contains one
    structurally recognized program member.
  .OUTPUTS
    Conservative silent-capability, opcode, registry, association, launch,
    file-operation, and shortcut evidence. No installer instruction is executed.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, Position = 0)]
    [string]$Path,

    [Parameter()]
    [string]$EmbeddedResponseFile,

    [string[]]$StringTablePath,

    [string[]]$EntryPoint,

    [ValidateSet('StandaloneInstaller', 'EmbeddedAction')]
    [string]$AnalysisScope = 'StandaloneInstaller',

    [string]$LibraryMemberName
  )

  $SelectedEntryPoints = [string[]]@($EntryPoint | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)

  $Decoded = ConvertFrom-InstallShieldInstallScriptByteStream -Path $Path
  $SelectedProgram = Resolve-InstallShieldInstallScriptProgramContent -Decoded $Decoded -LibraryMemberName $LibraryMemberName
  $Strings = Get-InstallShieldInstallScriptStringEvidence -Bytes $SelectedProgram.Bytes
  # Compiled symbol names may carry one-byte flag characters rendered as
  # punctuation by a broad string scan. Normalize only trailing punctuation;
  # do not rewrite paths, messages, or arbitrary string constants.
  $Symbols = @($Strings | Where-Object Length -LE 128 | ForEach-Object { $_.TrimEnd('?', '!', ';', ':') } | Sort-Object -Unique)
  $Program = $null
  $DialogTraces = @()
  $StaticAnalysis = $null
  $IrWarnings = [Collections.Generic.List[string]]::new()
  try {
    # Parse the already-decoded bytes once. Passing the array directly avoids a
    # second file read and descramble pass when the higher-level analyzer is used.
    $Program = if ($SelectedProgram.LibraryMemberName) {
      [Dumplings.InstallShield.InstallScript.InstallScriptLibraryReader]::ReadProgram($SelectedProgram.Bytes, $SelectedProgram.LibraryMemberName, 1000000)
    } else {
      [Dumplings.InstallShield.InstallScript.InstallScriptBytecodeReader]::Read($SelectedProgram.Bytes, 1000000)
    }
    $DialogTraces = @(Get-InstallShieldInstallScriptDialogTrace -Program $Program -EntryPoint $SelectedEntryPoints)
    $Resources = if ($StringTablePath) {
      Read-InstallShieldInstallScriptStringTable -Path $StringTablePath
    } else {
      [Collections.Generic.Dictionary[string, string[]]]::new([StringComparer]::Ordinal)
    }
    # The C# interpreter evaluates bytecode and generated wrappers but records
    # imported calls as evidence instead of invoking them. Limits bound loops,
    # recursion, branch alternatives, and emitted effects.
    $StaticAnalysis = [Dumplings.InstallShield.InstallScript.InstallScriptStaticAnalyzer]::Analyze(
      $Program,
      $Resources,
      $SelectedEntryPoints,
      1000000,
      16,
      50000
    )
    foreach ($Warning in $Program.Warnings) { $IrWarnings.Add([string]$Warning) }
    foreach ($Warning in $StaticAnalysis.Warnings) { $IrWarnings.Add([string]$Warning) }
  } catch {
    $IrWarnings.Add("Structured bytecode analysis was unavailable: $($_.Exception.Message)")
  }
  $DialogCalls = if ($DialogTraces) {
    [string[]]@($DialogTraces.Steps | ForEach-Object { @($_.Dialog) + @($_.Alternatives) } | Where-Object { $_ } | Select-Object -Unique)
  } else {
    # Unsupported generations retain conservative literal evidence instead of
    # losing the existing silent-support signal.
    [string[]]@($Symbols | Where-Object { $_ -cmatch $Script:InstallScriptDialogPattern })
  }
  $InstallOperations = @($Symbols | Where-Object { $_ -match $Script:InstallScriptInstallPattern })
  $ResponseReferences = @($Strings | Where-Object { $_ -match '(?i)(?:setup\.iss|response file|ResponseResult|InstallShield Silent)' } | Sort-Object -Unique)
  # Keep only InstallScript runtime names and uninstall-path literals that are
  # relevant to ARP registration. The full string table can contain tens of
  # thousands of values and must not become parser output or version-probing input.
  $ArpRuntimeEvidence = @($Symbols | Where-Object {
      $_ -cin @('MaintenanceStart', 'DeinstallStart', 'OnMoveData', 'OnCustomizeUninstInfo', 'ProductGuid', 'DisplayName', 'DisplayVersion', 'Publisher', 'UninstallKey') -or
      $_ -like "$($Script:InstallScriptUninstallRegistryPath)*"
    } | Sort-Object -Unique)
  $Warnings = [Collections.Generic.List[string]]::new()
  if ($IrWarnings.Count -eq 1 -and $IrWarnings[0].StartsWith('Structured bytecode analysis was unavailable:', [StringComparison]::Ordinal)) {
    $Warnings.Add($IrWarnings[0])
  } elseif ($IrWarnings.Count) {
    $Warnings.Add("Structured bytecode analysis reported $($IrWarnings.Count) bounded, conservative, or malformed path condition(s); affected evidence may be incomplete.")
  }
  foreach ($Warning in @($DialogTraces.Warnings)) { if ($Warning) { $Warnings.Add([string]$Warning) } }
  $AssociationInfo = if ($StaticAnalysis -and (Get-Command Get-InstallerRegistryAssociationInfo -ErrorAction SilentlyContinue)) {
    Get-InstallerRegistryAssociationInfo -RegistryWrite ([object[]]$StaticAnalysis.RegistryWrites)
  } else {
    [pscustomobject]@{ Protocols = @(); FileExtensions = @(); ProtocolAssociations = @(); FileExtensionAssociations = @(); Warnings = @() }
  }
  foreach ($Warning in @($AssociationInfo.Warnings)) { if ($Warning) { $Warnings.Add("InstallScript: $Warning") } }
  if (@($StaticAnalysis.DllOperations).Count) {
    $Warnings.Add('The compiled InstallScript loads an external DLL; its exported-function side effects remain opaque and require static inspection or VM validation.')
  }
  $ResponseInfo = $null
  $ResponseValidation = $null

  if ($EmbeddedResponseFile) {
    try { $ResponseInfo = Read-InstallShieldResponseFile -Path $EmbeddedResponseFile }
    catch { $Warnings.Add("The embedded response-file candidate is invalid: $($_.Exception.Message)") }
  }
  if ($ResponseInfo -and $DialogTraces) {
    $FreshTrace = $DialogTraces | Where-Object Scenario -EQ 'FreshInstall' | Select-Object -First 1
    if ($FreshTrace) {
      $ResponseValidation = Test-InstallShieldResponseFile -Path $EmbeddedResponseFile -Trace $FreshTrace
      if (-not $ResponseValidation.IsValid) {
        $Warnings.Add('The embedded response file does not match the statically reconstructed fresh-install dialog order.')
      }
    }
  }

  # Embedded custom actions inherit invocation and UI policy from their MSI or
  # Advanced UI container. Standalone response-file conclusions would be
  # misleading, but reachable dialogs remain important review evidence.
  if ($AnalysisScope -eq 'EmbeddedAction') {
    $SilentSupport = 'NotApplicable'
    $ResponseRequirement = 'None'
    if ($DialogCalls) {
      $Warnings.Add('An embedded InstallScript action reaches dialog functions; validate the containing MSI or suite sequence and silent mode in a VM.')
    }
    # A valid setup.iss beside setup.inx is the documented default source used by
    # Setup.exe /s. This proves the package is self-contained even though the
    # script still uses response-backed dialogs internally.
  } elseif ($ResponseInfo -and (-not $ResponseValidation -or $ResponseValidation.IsValid)) {
    $SilentSupport = 'Supported'
    $ResponseRequirement = 'Embedded'
  } elseif ($DialogCalls -and @($DialogTraces | Where-Object Source -EQ 'FrameworkCallback').Count) {
    # Official InstallShield framework source routes program-style projects
    # through _ShowWizardPages and the exported IfxOnShowWizardPages callback.
    # Reachable Sd* dialogs on that path use InstallShield Silent response
    # sections even when the literal setup.iss filename is absent from the INX.
    $SilentSupport = 'ResponseFileRequired'
    $ResponseRequirement = 'External'
    if (-not $ResponseInfo) {
      $Warnings.Add('The InstallShield framework callback reaches response-backed dialogs but the media does not ship a valid fresh-install setup.iss.')
    }
  } elseif ($DialogCalls -and $ResponseReferences) {
    # Revenera's InstallShield Silent contract reads built-in/Sd dialog answers
    # from setup.iss. Imported dialog and response-runtime evidence without a
    # shipped default file therefore requires caller-supplied response data.
    $SilentSupport = 'ResponseFileRequired'
    $ResponseRequirement = 'External'
    if (-not $ResponseInfo) {
      $Warnings.Add('The compiled script uses InstallShield response-backed dialog support but the media does not ship a valid fresh-install setup.iss.')
    }
  } else {
    $SilentSupport = 'Indeterminate'
    $ResponseRequirement = if ($ResponseReferences -or $DialogCalls) { 'Unknown' } else { 'None' }
    if ($DialogCalls) {
      $Warnings.Add('InstallScript dialog functions are present, but static string evidence alone does not prove they are reachable in SILENTMODE.')
    }
    if ($ResponseReferences) {
      $Warnings.Add('The compiled script contains response-file runtime evidence but no valid embedded setup.iss was found.')
    }
    $Warnings.Add('InstallScript control-flow evidence is incomplete for this bytecode generation; response-file-free silent support is not proven.')
  }

  [pscustomobject][ordered]@{
    Path                       = $Decoded.Path
    SilentSupport              = $SilentSupport
    ResponseFileRequirement    = $ResponseRequirement
    SilentSwitches             = if ($SilentSupport -eq 'Supported') { [string[]]@('/s') } else { [string[]]@() }
    InstallEntryPoints         = if ($SelectedEntryPoints) { $SelectedEntryPoints } elseif ($Program) { [string[]]@($Program.Functions.Name | Where-Object { $_ -match '^(?:program|Preprogram|Postprogram|OnFirstUIBefore|OnMaintUIBefore)$' }) } else { [string[]]@($Symbols | Where-Object { $_ -match '^(?:program|Preprogram|Postprogram|OnFirstUIBefore|OnMaintUIBefore)$' }) }
    DialogCalls                = [string[]]$DialogCalls
    DialogTraces               = [object[]]$DialogTraces
    ResponseFileAccesses       = [string[]]$ResponseReferences
    RegistryWrites             = [object[]]@($StaticAnalysis.RegistryWrites)
    RegistryItems              = [object[]]@($StaticAnalysis.RegistryItems)
    Protocols                  = [string[]]@($AssociationInfo.Protocols)
    FileExtensions             = [string[]]@($AssociationInfo.FileExtensions)
    ProtocolAssociations       = [object[]]@($AssociationInfo.ProtocolAssociations)
    FileExtensionAssociations  = [object[]]@($AssociationInfo.FileExtensionAssociations)
    RegistryAssociationInfo    = $AssociationInfo
    ExecutedPayloads           = [object[]]@($StaticAnalysis.ExecutedPayloads)
    FileOperations             = [object[]]@($StaticAnalysis.FileOperations)
    DllOperations              = [object[]]@($StaticAnalysis.DllOperations)
    PropertyHandlers           = [object[]]@($StaticAnalysis.PropertyHandlers)
    Shortcuts                  = [object[]]@($StaticAnalysis.Shortcuts)
    StaticCalls                = [object[]]@($StaticAnalysis.Calls)
    ExternalSymbols            = if ($Program) { [object[]]@($Program.ExternalSymbols) } else { [object[]]@() }
    AddressResolutions         = if ($Program) { [object[]]@($Program.AddressResolutions) } else { [object[]]@() }
    ExportedFunctions          = if ($Program) { [string[]]@($Program.Functions | Where-Object IsExported | ForEach-Object Name) } else { [string[]]@() }
    OpcodeCoverage             = [object[]]@($StaticAnalysis.OpcodeCoverage)
    UnsupportedOpcodes         = [string[]]@($StaticAnalysis.UnsupportedOpcodes)
    UnresolvedCalls            = [string[]]$IrWarnings.ToArray()
    InstallOperations          = [string[]]$InstallOperations
    ArpRuntimeEvidence         = [string[]]$ArpRuntimeEvidence
    EmbeddedResponseFile       = $ResponseInfo
    EmbeddedResponseValidation = $ResponseValidation
    Warnings                   = [string[]]$Warnings.ToArray()
    ParserVersionInfo          = [pscustomobject][ordered]@{
      Parser                   = 'Dumplings.PackageModule.InstallShieldInstallScript'
      ParserMajor              = 11
      Format                   = $SelectedProgram.Format
      BytecodeProfile          = $Program ? $Program.FormatProfile : $SelectedProgram.Format
      CompilerVersion          = $Program ? $Program.CompilerVersion : $null
      HeaderKind               = $Decoded.HeaderKind
      SupportStatus            = $Decoded.SupportStatus
      LibraryMemberName        = $SelectedProgram.LibraryMemberName
      LibraryMemberCount       = $SelectedProgram.LibraryMemberCount
      WasScrambled             = $Decoded.WasScrambled
      HeaderValue              = $Decoded.HeaderValue
      MarkerOffset             = $Decoded.MarkerOffset
      CopyrightMarker          = $Decoded.CopyrightMarker
      AnalysisMode             = $Program ? 'BoundedStaticEmulation' : 'ConservativeStaticEvidenceFallback'
      AnalysisScope            = $AnalysisScope
      FunctionCount            = $Program ? $Program.Functions.Count : 0
      ExportedFunctionCount    = $Program ? @($Program.Functions | Where-Object IsExported).Count : 0
      ExternalSymbolCount      = $Program ? $Program.ExternalSymbols.Count : 0
      AddressResolutionCount   = $Program ? $Program.AddressResolutions.Count : 0
      InstructionCount         = $Program ? $Program.InstructionCount : 0
      ExploredInstructionCount = $StaticAnalysis ? $StaticAnalysis.ExploredInstructionCount : 0
      EmulationTruncated       = $StaticAnalysis ? $StaticAnalysis.Truncated : $false
      ResourceTableCount       = @($StringTablePath).Count
      PropertyHandlerCount     = $StaticAnalysis ? $StaticAnalysis.PropertyHandlers.Count : 0
    }
  }
}

function Merge-InstallShieldInstallScriptMediaEvidence {
  <#
  .SYNOPSIS
    Select InstallScript media registry and shell records using compiled-call evidence.
  .DESCRIPTION
    InstallShield stores CreateRegistrySet and CreateShellObjects payloads in
    data*.hdr rather than as literal operands in setup.inx. This helper joins
    the independently parsed media graph with the compiled-script call graph.
    The standard <Default> registry set is created during normal file transfer;
    named sets remain conditional unless a complete literal call selects them.
  .PARAMETER Installer
    Existing Get-InstallShieldInfo result containing InstallShieldCabinetSupport.
  .PARAMETER Analysis
    Existing setup.inx static-analysis result. The helper adds media evidence
    and updates registry-association projections on this in-memory result.
  .OUTPUTS
    The same analysis object with selected and conditional media evidence.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]
    [psobject]$Installer,

    [Parameter(Mandatory)]
    [psobject]$Analysis
  )

  $SupportProperty = $Installer.PSObject.Properties['InstallShieldCabinetSupport']
  $Support = $SupportProperty ? $SupportProperty.Value : $null
  $MediaRegistrySets = [object[]]@($Support.RegistrySets)
  $MediaRegistryWrites = [object[]]@($Support.RegistryWrites)
  $CabinetFileGroups = [object[]]@($Support.CabinetFileGroups)
  $CabinetComponents = [object[]]@($Support.CabinetComponents)
  $MediaSetupTypes = [object[]]@($Support.MediaSetupTypes)
  $MediaShellFolders = [object[]]@($Support.ShellFolders)
  $MediaShortcuts = [object[]]@($Support.Shortcuts)
  $SelectedSetNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  # InstallShield creates the default set immediately after OnMoving during
  # normal file transfer; it does not require a literal CreateRegistrySet call.
  [void]$SelectedSetNames.Add('<Default>')
  $SelectAllRegistrySets = $false

  # CreateRegistrySet("") selects every authored set. A complete literal name
  # selects only that set; unresolved arguments cannot safely promote records.
  foreach ($Call in @($Analysis.StaticCalls | Where-Object { $_.Target -match '(?i)(?:^|[._])_?CreateRegistrySet$' })) {
    if (-not $Call.Complete) { continue }
    $Arguments = @($Call.Arguments)
    if (-not $Arguments) { continue }
    $SetName = ([string]$Arguments[0]).Trim('"')
    if ([string]::IsNullOrEmpty($SetName)) {
      $SelectAllRegistrySets = $true
    } else {
      [void]$SelectedSetNames.Add($SetName)
    }
  }

  $SelectedRegistryWrites = [Collections.Generic.List[object]]::new()
  $ConditionalRegistryWrites = [Collections.Generic.List[object]]::new()
  foreach ($RegistryWrite in $MediaRegistryWrites) {
    $IsComponentAssociated = @($RegistryWrite.Components).Count -gt 0
    # CreateRegistrySet has no effect on component-associated sets. Their
    # records are installed by component transfer and remain conditional until
    # selected-feature/component state is known.
    $IsSelected = $RegistryWrite.IsDefaultSet -or (
      -not $IsComponentAssociated -and (
        $SelectAllRegistrySets -or $SelectedSetNames.Contains([string]$RegistryWrite.RegistrySet)
      )
    )
    $Evidence = [ordered]@{}
    foreach ($Property in $RegistryWrite.PSObject.Properties) { $Evidence[$Property.Name] = $Property.Value }
    if ($IsSelected) {
      $Evidence.Confidence = $RegistryWrite.IsDefaultSet ? 'DefaultMediaSet' : 'ReachedMediaSet'
      $SelectedRegistryWrites.Add([pscustomobject]$Evidence)
    } else {
      $Evidence.Confidence = $IsComponentAssociated ? 'ComponentTransfer' : 'ConditionalMediaSet'
      $ConditionalRegistryWrites.Add([pscustomobject]$Evidence)
    }
  }

  $HasReachedShellCreation = [bool](@($Analysis.StaticCalls | Where-Object {
        $_.Complete -and $_.Target -match '(?i)(?:^|[._])_?CreateShellObjects$'
      }) | Select-Object -First 1)
  $ReachedMediaShortcuts = if ($HasReachedShellCreation) {
    [object[]]@($MediaShortcuts | Where-Object { [string]::IsNullOrWhiteSpace([string]$_.Component) } | ForEach-Object {
        $Evidence = [ordered]@{}
        foreach ($Property in $_.PSObject.Properties) { $Evidence[$Property.Name] = $Property.Value }
        $Evidence.Confidence = 'ReachedMediaShellObjects'
        [pscustomobject]$Evidence
      })
  } else {
    [object[]]@()
  }

  # Selected media records have the same registry semantics as literal
  # RegDB* calls. Recompute association evidence after joining both sources.
  $Analysis.RegistryWrites = [object[]]@(@($Analysis.RegistryWrites) + $SelectedRegistryWrites.ToArray())
  $Analysis.Shortcuts = [object[]]@(@($Analysis.Shortcuts) + $ReachedMediaShortcuts)
  $Analysis | Add-Member -NotePropertyName MediaRegistrySets -NotePropertyValue $MediaRegistrySets -Force
  $Analysis | Add-Member -NotePropertyName MediaRegistryWrites -NotePropertyValue ([object[]]$SelectedRegistryWrites.ToArray()) -Force
  $Analysis | Add-Member -NotePropertyName ConditionalMediaRegistryWrites -NotePropertyValue ([object[]]$ConditionalRegistryWrites.ToArray()) -Force
  $Analysis | Add-Member -NotePropertyName CabinetFileGroups -NotePropertyValue $CabinetFileGroups -Force
  $Analysis | Add-Member -NotePropertyName CabinetComponents -NotePropertyValue $CabinetComponents -Force
  $Analysis | Add-Member -NotePropertyName MediaSetupTypes -NotePropertyValue $MediaSetupTypes -Force
  $Analysis | Add-Member -NotePropertyName MediaShellFolders -NotePropertyValue $MediaShellFolders -Force
  $Analysis | Add-Member -NotePropertyName MediaShortcuts -NotePropertyValue $MediaShortcuts -Force
  $Analysis | Add-Member -NotePropertyName ConditionalMediaShortcuts -NotePropertyValue ([object[]]@($MediaShortcuts | Where-Object {
        -not [string]::IsNullOrWhiteSpace([string]$_.Component) -or -not $HasReachedShellCreation
      })) -Force

  if (Get-Command Get-InstallerRegistryAssociationInfo -ErrorAction SilentlyContinue) {
    $AssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite ([object[]]@($Analysis.RegistryWrites | Where-Object Complete))
    $ConditionalAssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite ([object[]]@($ConditionalRegistryWrites | Where-Object Complete))
    $Analysis.RegistryAssociationInfo = $AssociationInfo
    $Analysis.Protocols = [string[]]@($AssociationInfo.Protocols)
    $Analysis.FileExtensions = [string[]]@($AssociationInfo.FileExtensions)
    $Analysis.ProtocolAssociations = [object[]]@($AssociationInfo.ProtocolAssociations)
    $Analysis.FileExtensionAssociations = [object[]]@($AssociationInfo.FileExtensionAssociations)
    $Analysis | Add-Member -NotePropertyName ConditionalRegistryAssociationInfo -NotePropertyValue $ConditionalAssociationInfo -Force
    $Analysis | Add-Member -NotePropertyName ConditionalProtocols -NotePropertyValue ([string[]]@($ConditionalAssociationInfo.Protocols)) -Force
    $Analysis | Add-Member -NotePropertyName ConditionalFileExtensions -NotePropertyValue ([string[]]@($ConditionalAssociationInfo.FileExtensions)) -Force
    $Analysis.Warnings = [string[]]@($Analysis.Warnings + @($AssociationInfo.Warnings | ForEach-Object { "InstallScript: $_" }))
  } else {
    $Analysis | Add-Member -NotePropertyName ConditionalRegistryAssociationInfo -NotePropertyValue $null -Force
    $Analysis | Add-Member -NotePropertyName ConditionalProtocols -NotePropertyValue ([string[]]@()) -Force
    $Analysis | Add-Member -NotePropertyName ConditionalFileExtensions -NotePropertyValue ([string[]]@()) -Force
  }

  if ($ConditionalRegistryWrites.Count) {
    $UnselectedNames = [string[]]@($ConditionalRegistryWrites | Where-Object Confidence -EQ 'ConditionalMediaSet' | ForEach-Object RegistrySet | Sort-Object -Unique)
    if ($UnselectedNames) {
      $Analysis.Warnings = [string[]]@($Analysis.Warnings + "InstallShield media defines unassociated registry set(s) '$($UnselectedNames -join "', '")'; no complete literal CreateRegistrySet call selected them.")
    }
  }
  $UnassociatedShortcuts = @($MediaShortcuts | Where-Object { [string]::IsNullOrWhiteSpace([string]$_.Component) })
  if ($UnassociatedShortcuts -and -not $HasReachedShellCreation) {
    $Analysis.Warnings = [string[]]@($Analysis.Warnings + 'InstallShield media defines unassociated shell folders or shortcuts, but no complete CreateShellObjects call was reached; the records remain conditional evidence.')
  }
  return $Analysis
}

function Get-InstallShieldInstallScriptArpInfo {
  <#
  .SYNOPSIS
    Reconstruct documented InstallScript Apps & Features defaults.
  .DESCRIPTION
    InstallShield's MaintenanceStart function creates the uninstall key from
    PRODUCT_GUID and writes values from IFX_PRODUCT_NAME, IFX_PRODUCT_VERSION,
    IFX_COMPANY_NAME, TARGETDIR, and UNINSTALL_STRING. Setup.ini exposes only
    the product GUID, product name, and company name directly. Complete
    RegDBSetItem and explicit uninstall registry writes from bounded static
    emulation take precedence; other runtime-controlled values stay unresolved.
  .PARAMETER Installer
    Existing InstallShield extraction result containing SetupConfiguration.
  .PARAMETER Analysis
    Bounded compiled-script analysis from Invoke-InstallShieldInstallScriptAnalysis.
  .OUTPUTS
    ARP identity, registry-write projections, unresolved fields, and warnings.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]
    [psobject]$Installer,

    [Parameter(Mandatory)]
    [psobject]$Analysis
  )

  $Warnings = [Collections.Generic.List[string]]::new()
  $UnresolvedFields = [Collections.Generic.List[string]]::new()
  $ConfigurationProperty = $Installer.PSObject.Properties['SetupConfiguration']
  $Configuration = $null -eq $ConfigurationProperty ? $null : $ConfigurationProperty.Value
  if ($Configuration -isnot [System.Collections.IDictionary]) { $Configuration = $null }

  # Setup.ini is generated from the InstallScript project at build time. Its
  # ProductGUID is the registered product code and, for InstallShield 6+, the
  # default uninstall-key name. Product and CompanyName are the documented
  # defaults behind IFX_PRODUCT_NAME and IFX_COMPANY_NAME.
  $RawProductCode = [string](Get-InstallShieldInstallScriptConfigurationValue -Configuration $Configuration -Section 'Startup' -Name 'ProductGUID')
  $ProjectProductCode = ConvertTo-InstallShieldInstallScriptProductCode -Value $RawProductCode
  $ProjectName = [string](Get-InstallShieldInstallScriptConfigurationValue -Configuration $Configuration -Section 'Startup' -Name 'Product')
  $ProjectNameSource = 'Setup.ini:[Startup].Product'
  if ([string]::IsNullOrWhiteSpace($ProjectName)) {
    # PackageForTheWeb projects generated by older Stirling-era builders use
    # AppName instead of Product. Preserve it as project identity only; ARP
    # fields still require compiled registration evidence below.
    $ProjectName = [string](Get-InstallShieldInstallScriptConfigurationValue -Configuration $Configuration -Section 'Startup' -Name 'AppName')
    $ProjectNameSource = 'Setup.ini:[Startup].AppName'
  }
  $ProjectPublisher = [string](Get-InstallShieldInstallScriptConfigurationValue -Configuration $Configuration -Section 'Startup' -Name 'CompanyName')
  if ([string]::IsNullOrWhiteSpace($ProjectName)) { $ProjectName = $null }
  if ([string]::IsNullOrWhiteSpace($ProjectPublisher)) { $ProjectPublisher = $null }

  if ([string]::IsNullOrWhiteSpace($RawProductCode)) {
    $Warnings.Add('Setup.ini does not expose ProductGUID, so the InstallScript uninstall-key identity is unresolved.')
  } elseif (-not $ProjectProductCode) {
    $Warnings.Add("Setup.ini ProductGUID '$RawProductCode' is not a valid GUID and is not used as ProductCode evidence.")
  }
  if (-not $ProjectName) { $Warnings.Add('Setup.ini does not expose Startup.Product or Startup.AppName, so the default InstallScript ARP DisplayName is unresolved.') }

  $RuntimeEvidence = @($Analysis.ArpRuntimeEvidence)
  # RegDBSetItem configures the values later materialized by MaintenanceStart.
  # Keep only complete, source-defined item IDs and let the last reachable
  # assignment to an item win, matching imperative InstallScript behavior.
  $RegistryItems = [ordered]@{}
  foreach ($RegistryItem in @($Analysis.RegistryItems)) {
    if ($RegistryItem.Complete -and -not [string]::IsNullOrWhiteSpace([string]$RegistryItem.Name)) {
      $RegistryItems[[string]$RegistryItem.Name] = [string]$RegistryItem.Data
    }
  }
  $ExplicitArpEntries = [Collections.Generic.List[object]]::new()
  $UninstallPathPattern = '^(?i:' + [regex]::Escape($Script:InstallScriptUninstallRegistryPath) + ')\\(?<ProductCode>[^\\]+)$'
  $ExplicitWrites = @($Analysis.RegistryWrites | Where-Object {
      $_.Complete -and $_.Root -in @('HKLM', 'HKCU', 'SHCTX') -and $_.Key -match $UninstallPathPattern
    })
  foreach ($Group in @($ExplicitWrites | Group-Object -Property Root, Key)) {
    $Writes = @($Group.Group)
    $DisplayNameWrite = $Writes | Where-Object Name -IEQ 'DisplayName' | Select-Object -Last 1
    if (-not $DisplayNameWrite -or [string]::IsNullOrWhiteSpace([string]$DisplayNameWrite.Data)) { continue }
    $SystemComponent = $Writes | Where-Object Name -IEQ 'SystemComponent' | Select-Object -Last 1
    if ($SystemComponent -and [string]$SystemComponent.Data -match '^(?:1|true)$') {
      $Warnings.Add("The script writes hidden uninstall entry '$($Writes[0].Key)' with SystemComponent=1; it is excluded from visible Apps & Features evidence.")
      continue
    }

    $ProductCode = [IO.Path]::GetFileName([string]$Writes[0].Key)
    $PublisherWrite = $Writes | Where-Object Name -IEQ 'Publisher' | Select-Object -Last 1
    $VersionWrite = $Writes | Where-Object Name -IEQ 'DisplayVersion' | Select-Object -Last 1
    $LocationWrite = $Writes | Where-Object Name -IEQ 'InstallLocation' | Select-Object -Last 1
    $UninstallWrite = $Writes | Where-Object Name -IEQ 'UninstallString' | Select-Object -Last 1
    $QuietUninstallWrite = $Writes | Where-Object Name -IEQ 'QuietUninstallString' | Select-Object -Last 1
    $DisplayIconWrite = $Writes | Where-Object Name -IEQ 'DisplayIcon' | Select-Object -Last 1
    $UrlInfoAboutWrite = $Writes | Where-Object Name -IEQ 'URLInfoAbout' | Select-Object -Last 1
    $HelpLinkWrite = $Writes | Where-Object Name -IEQ 'HelpLink' | Select-Object -Last 1
    $WindowsInstaller = $Writes | Where-Object Name -IEQ 'WindowsInstaller' | Select-Object -Last 1
    $ExplicitArpEntries.Add([pscustomobject][ordered]@{
        ProductCode            = $ProductCode
        DisplayName            = [string]$DisplayNameWrite.Data
        DisplayVersion         = $VersionWrite ? [string]$VersionWrite.Data : $null
        Publisher              = $PublisherWrite ? [string]$PublisherWrite.Data : $null
        Scope                  = $Writes[0].Root -eq 'HKCU' ? 'user' : ($Writes[0].Root -eq 'HKLM' ? 'machine' : $null)
        DefaultInstallLocation = $LocationWrite ? [string]$LocationWrite.Data : $null
        UninstallString        = $UninstallWrite ? [string]$UninstallWrite.Data : $null
        QuietUninstallString   = $QuietUninstallWrite ? [string]$QuietUninstallWrite.Data : $null
        DisplayIcon            = $DisplayIconWrite ? [string]$DisplayIconWrite.Data : $null
        URLInfoAbout           = $UrlInfoAboutWrite ? [string]$UrlInfoAboutWrite.Data : $null
        HelpLink               = $HelpLinkWrite ? [string]$HelpLinkWrite.Data : $null
        InstallerType          = ($WindowsInstaller -and [string]$WindowsInstaller.Data -match '^(?:1|true)$') ? 'msi' : 'exe'
        RegistryRoot           = [string]$Writes[0].Root
        RegistryKey            = [string]$Writes[0].Key
        Source                 = 'ExplicitStaticRegistryWrites'
      })
  }
  $HasMaintenanceRuntime = $RuntimeEvidence -ccontains 'MaintenanceStart' -or $RuntimeEvidence -ccontains 'DeinstallStart'
  $HasUninstallRegistryPath = [bool]($RuntimeEvidence | Where-Object { $_ -like "$($Script:InstallScriptUninstallRegistryPath)*" } | Select-Object -First 1)
  $ConfiguredProductCode = if ($RegistryItems.ProductGuid) {
    ConvertTo-InstallShieldInstallScriptProductCode -Value $RegistryItems.ProductGuid
  } else {
    $ProjectProductCode
  }
  $HasBuiltInRegistration = [bool]($ConfiguredProductCode -and $HasMaintenanceRuntime -and $HasUninstallRegistryPath)
  $HasExplicitRegistration = $ExplicitArpEntries.Count -gt 0
  $WritesAppsAndFeaturesEntry = ($HasExplicitRegistration -or $HasBuiltInRegistration) ? $true : $null
  # Keep project identity separate from ARP identity. ProductGUID alone does
  # not prove that this compiled script invokes the built-in registration path.
  $ProductCode = if ($ExplicitArpEntries.Count -eq 1) { $ExplicitArpEntries[0].ProductCode } elseif ($ExplicitArpEntries.Count -eq 0 -and $HasBuiltInRegistration) { $ConfiguredProductCode } else { $null }
  $DisplayName = if ($ExplicitArpEntries.Count -eq 1) { $ExplicitArpEntries[0].DisplayName } elseif ($ExplicitArpEntries.Count -eq 0 -and $HasBuiltInRegistration) { $RegistryItems.DisplayName ?? $ProjectName } else { $null }
  $DisplayVersion = if ($ExplicitArpEntries.Count -eq 1) { $ExplicitArpEntries[0].DisplayVersion } elseif ($ExplicitArpEntries.Count -eq 0 -and $HasBuiltInRegistration) { $RegistryItems.DisplayVersion } else { $null }
  $Publisher = if ($ExplicitArpEntries.Count -eq 1) { $ExplicitArpEntries[0].Publisher } elseif ($ExplicitArpEntries.Count -eq 0 -and $HasBuiltInRegistration) { $RegistryItems.Publisher ?? $ProjectPublisher } else { $null }
  $Scope = $ExplicitArpEntries.Count -eq 1 ? $ExplicitArpEntries[0].Scope : $null
  $DefaultInstallLocation = if ($ExplicitArpEntries.Count -eq 1) { $ExplicitArpEntries[0].DefaultInstallLocation } elseif ($ExplicitArpEntries.Count -eq 0 -and $HasBuiltInRegistration) { $RegistryItems.InstallLocation } else { $null }
  $UninstallString = if ($ExplicitArpEntries.Count -eq 1) { $ExplicitArpEntries[0].UninstallString } elseif ($ExplicitArpEntries.Count -eq 0 -and $HasBuiltInRegistration) { $RegistryItems.UninstallString } else { $null }
  $QuietUninstallString = $ExplicitArpEntries.Count -eq 1 ? $ExplicitArpEntries[0].QuietUninstallString : $null
  $DisplayIcon = if ($ExplicitArpEntries.Count -eq 1) { $ExplicitArpEntries[0].DisplayIcon } elseif ($ExplicitArpEntries.Count -eq 0 -and $HasBuiltInRegistration) { $RegistryItems.DisplayIcon } else { $null }
  $URLInfoAbout = if ($ExplicitArpEntries.Count -eq 1) { $ExplicitArpEntries[0].URLInfoAbout } elseif ($ExplicitArpEntries.Count -eq 0 -and $HasBuiltInRegistration) { $RegistryItems.UrlInfoAbout } else { $null }
  $HelpLink = if ($ExplicitArpEntries.Count -eq 1) { $ExplicitArpEntries[0].HelpLink } elseif ($ExplicitArpEntries.Count -eq 0 -and $HasBuiltInRegistration) { $RegistryItems.HelpLink } else { $null }

  if ($HasBuiltInRegistration -and $RegistryItems.SystemComponent -match '^(?:1|true)$') {
    $Warnings.Add('RegDBSetItem configures SystemComponent=1, so the built-in uninstall entry is hidden and excluded from visible Apps & Features evidence.')
    $HasBuiltInRegistration = $false
    $WritesAppsAndFeaturesEntry = $HasExplicitRegistration ? $true : $false
    if (-not $HasExplicitRegistration) {
      $ProductCode = $null
      $DisplayName = $null
      $DisplayVersion = $null
      $Publisher = $null
      $DefaultInstallLocation = $null
      $UninstallString = $null
      $QuietUninstallString = $null
      $DisplayIcon = $null
      $URLInfoAbout = $null
      $HelpLink = $null
    }
  }

  # A default media registry set can create an additional visible uninstall
  # key alongside MaintenanceStart's GUID key. Keep the built-in registration
  # as the primary package identity and expose every distinct entry below.
  # Only fall back to a single explicit entry when built-in registration is not
  # proven; multiple explicit entries do not have a deterministic primary.
  if ($HasBuiltInRegistration) {
    $ProductCode = $ConfiguredProductCode
    $DisplayName = $RegistryItems.DisplayName ?? $ProjectName
    $DisplayVersion = $RegistryItems.DisplayVersion
    $Publisher = $RegistryItems.Publisher ?? $ProjectPublisher
    $Scope = $null
    $DefaultInstallLocation = $RegistryItems.InstallLocation
    $UninstallString = $RegistryItems.UninstallString
    $QuietUninstallString = $null
    $DisplayIcon = $RegistryItems.DisplayIcon
    $URLInfoAbout = $RegistryItems.UrlInfoAbout
    $HelpLink = $RegistryItems.HelpLink
  } elseif ($ExplicitArpEntries.Count -eq 1) {
    $ProductCode = $ExplicitArpEntries[0].ProductCode
    $DisplayName = $ExplicitArpEntries[0].DisplayName
    $DisplayVersion = $ExplicitArpEntries[0].DisplayVersion
    $Publisher = $ExplicitArpEntries[0].Publisher
    $Scope = $ExplicitArpEntries[0].Scope
    $DefaultInstallLocation = $ExplicitArpEntries[0].DefaultInstallLocation
    $UninstallString = $ExplicitArpEntries[0].UninstallString
    $QuietUninstallString = $ExplicitArpEntries[0].QuietUninstallString
    $DisplayIcon = $ExplicitArpEntries[0].DisplayIcon
    $URLInfoAbout = $ExplicitArpEntries[0].URLInfoAbout
    $HelpLink = $ExplicitArpEntries[0].HelpLink
  } else {
    $ProductCode = $null
    $DisplayName = $null
    $DisplayVersion = $null
    $Publisher = $null
    $Scope = $null
    $DefaultInstallLocation = $null
    $UninstallString = $null
    $QuietUninstallString = $null
    $DisplayIcon = $null
    $URLInfoAbout = $null
    $HelpLink = $null
  }

  if ($HasExplicitRegistration -and $HasBuiltInRegistration) {
    $Warnings.Add("InstallShield defines $($ExplicitArpEntries.Count) additional visible uninstall registration path(s) alongside the built-in MaintenanceStart GUID entry; all distinct entries are returned.")
  } elseif ($HasExplicitRegistration) {
    $Warnings.Add("The script or selected media sets contain $($ExplicitArpEntries.Count) complete visible uninstall registration path(s).")
  } elseif (-not $HasBuiltInRegistration) {
    $Warnings.Add('The compiled script does not provide enough MaintenanceStart and uninstall-path evidence to prove creation of the built-in InstallScript Apps & Features entry.')
  } else {
    # Static bytecode evidence proves that the InstallScript registration
    # runtime is linked, but project code may assign different IFX/UNINSTALL
    # values or set ADDREMOVE_SYSTEMCOMPONENT before the event handler runs.
    $Warnings.Add('Apps & Features values are reconstructed from InstallShield MaintenanceStart defaults; custom script assignments and SystemComponent visibility still require VM validation.')
  }

  # Setup.ini does not carry IFX_PRODUCT_VERSION, TARGETDIR, UNINSTALL_STRING,
  # or the final ALLUSERS/ProgDefGroupType state. A setup.iss [Application]
  # section is response-file metadata and can be stale, so it is deliberately
  # excluded from the ARP model.
  foreach ($Field in @('DisplayVersion', 'Scope', 'DefaultInstallLocation')) {
    if ($null -eq (Get-Variable -Name $Field -ValueOnly)) { $UnresolvedFields.Add($Field) }
  }

  $RegistryWrites = [Collections.Generic.List[object]]::new()
  $AppsAndFeaturesEntries = [Collections.Generic.List[object]]::new()
  foreach ($ExplicitEntry in $ExplicitArpEntries) {
    $Entry = [ordered]@{ ProductCode = $ExplicitEntry.ProductCode }
    foreach ($Property in @('DisplayName', 'DisplayVersion', 'Publisher', 'InstallerType')) {
      if (-not [string]::IsNullOrWhiteSpace([string]$ExplicitEntry.$Property)) { $Entry[$Property] = $ExplicitEntry.$Property }
    }
    $AppsAndFeaturesEntries.Add([pscustomobject]$Entry)
  }
  if ($HasBuiltInRegistration) {
    $RegistryPath = "$($Script:InstallScriptUninstallRegistryPath)\$ProductCode"
    foreach ($Value in @(
        [pscustomobject][ordered]@{ Name = 'ProductGuid'; Data = $ProductCode; Source = 'MaintenanceStart:PRODUCT_GUID' },
        [pscustomobject][ordered]@{ Name = 'DisplayName'; Data = $DisplayName; Source = 'MaintenanceStart:IFX_PRODUCT_NAME' },
        [pscustomobject][ordered]@{ Name = 'Publisher'; Data = $Publisher; Source = 'MaintenanceStart:IFX_COMPANY_NAME' }
      )) {
      if ($null -eq $Value.Data) { continue }
      $RegistryWrites.Add([pscustomobject][ordered]@{
          RootCandidates = [string[]]@('HKCU', 'HKLM')
          Key            = $RegistryPath
          Name           = $Value.Name
          Type           = 'REG_SZ'
          Data           = $Value.Data
          Source         = $Value.Source
          Confidence     = 'InstallShieldDefault'
        })
    }

    if ($ExplicitArpEntries.ProductCode -notcontains $ProductCode) {
      $Entry = [ordered]@{ ProductCode = $ProductCode }
      if ($DisplayName) { $Entry.DisplayName = $DisplayName }
      if ($Publisher) { $Entry.Publisher = $Publisher }
      $Entry.InstallerType = 'exe'
      $AppsAndFeaturesEntries.Add([pscustomobject]$Entry)
    }
  }

  return [pscustomobject][ordered]@{
    ProductCode                  = $ProductCode
    ProjectProductCode           = $ProjectProductCode
    ProjectName                  = $ProjectName
    ProjectPublisher             = $ProjectPublisher
    DisplayName                  = $DisplayName
    DisplayVersion               = $DisplayVersion
    Publisher                    = $Publisher
    Scope                        = $Scope
    DefaultInstallLocation       = $DefaultInstallLocation
    UninstallString              = $UninstallString
    QuietUninstallString         = $QuietUninstallString
    DisplayIcon                  = $DisplayIcon
    URLInfoAbout                 = $URLInfoAbout
    HelpLink                     = $HelpLink
    WritesAppsAndFeaturesEntry   = $WritesAppsAndFeaturesEntry
    AppsAndFeaturesProductCode   = $WritesAppsAndFeaturesEntry -and $AppsAndFeaturesEntries.Count -eq 1 ? $ProductCode : $null
    AppsAndFeaturesInstallerType = $AppsAndFeaturesEntries.Count -eq 1 ? $AppsAndFeaturesEntries[0].InstallerType : $null
    AppsAndFeaturesEntries       = [object[]]$AppsAndFeaturesEntries.ToArray()
    RegistryWrites               = [object[]]$RegistryWrites.ToArray()
    RegistrationMode             = ($HasExplicitRegistration -and $HasBuiltInRegistration) ? 'ExplicitAndMaintenanceDefaults' : ($HasExplicitRegistration ? 'ExplicitStaticRegistryWrites' : ($HasBuiltInRegistration ? 'MaintenanceStartDefaults' : 'Unresolved'))
    RuntimeEvidence              = [string[]]$RuntimeEvidence
    ValueSources                 = [pscustomobject][ordered]@{
      ProjectProductCode = 'Setup.ini:[Startup].ProductGUID -> PRODUCT_GUID/UNINSTALLKEY'
      ProductCode        = $HasBuiltInRegistration ? 'ProjectProductCode plus compiled MaintenanceStart/uninstall-path evidence' : 'Explicit static uninstall registry path'
      DisplayName        = $HasBuiltInRegistration ? "$ProjectNameSource -> IFX_PRODUCT_NAME/AppName project default" : 'Explicit static uninstall DisplayName write'
      Publisher          = $HasBuiltInRegistration ? 'Setup.ini:[Startup].CompanyName -> IFX_COMPANY_NAME default' : 'Explicit static uninstall Publisher write'
      RegistryItems      = 'Compiled RegDBSetItem calls applied before MaintenanceStart'
    }
    Warnings                     = [string[]]$Warnings.ToArray()
    UnresolvedFields             = [string[]]$UnresolvedFields.ToArray()
  }
}

function Get-InstallShieldInstallScriptInfo {
  <#
  .SYNOPSIS
    Analyze InstallScript evidence from an installer or an existing InstallShield extraction result.
  .PARAMETER Path
    Path to an InstallShield installer. It is extracted once through Get-InstallShieldInfo.
  .PARAMETER Installer
    Existing Get-InstallShieldInfo result whose extracted files are reused.
  .PARAMETER EntryPoint
    Optional compiled function names selected by an MSI custom-action table or
    Advanced UI CallInstallScript action.
  .PARAMETER AnalysisScope
    Selects standalone installer semantics or scoped embedded-action analysis.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, ParameterSetName = 'Path', Position = 0, ValueFromPipeline)]
    [string]$Path,

    [Parameter(Mandatory, ParameterSetName = 'Installer', Position = 0, ValueFromPipeline)]
    [psobject]$Installer,

    [string[]]$EntryPoint,

    [ValidateSet('StandaloneInstaller', 'EmbeddedAction')]
    [string]$AnalysisScope = 'StandaloneInstaller'
  )

  process {
    if ($PSCmdlet.ParameterSetName -eq 'Path') {
      $TemporaryPath = New-TempFolder
      try {
        # The outer parser also recovers setup.inx when it is stored inside a
        # proprietary data*.hdr/data*.cab set. Reuse its completed focused
        # result rather than extracting or decoding the same installer twice.
        $Installer = Get-InstallShieldInfo -Path $Path -DestinationPath $TemporaryPath
        if (-not $Installer.InstallScriptInfo) { throw 'The InstallShield payload does not contain supported compiled InstallScript metadata.' }
        $Result = $Installer.InstallScriptInfo
        # The temporary extraction is deleted below. Keep the public Path on
        # the caller's installer and avoid returning a stale extracted path.
        $Result.Path = $Installer.Path
        $Result.CompiledScriptPath = $null
        return $Result
      } finally {
        Remove-Item -LiteralPath $TemporaryPath -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
    if (-not $Installer.HasInstallScript -or -not $Installer.InxFiles) { throw 'The InstallShield payload does not contain a compiled InstallScript file.' }
    $InxFiles = [IO.FileInfo[]]@($Installer.InxFiles | ForEach-Object { Get-Item -LiteralPath $_ -Force })
    $ScriptFile = if ($InxFiles.Count -eq 1) {
      $InxFiles[0]
    } else {
      # Advanced UI extraction can recover historical or parcel-local scripts
      # as Setup (n).inx while retaining the suite dispatcher as exact
      # Setup.inx. Select only that canonical file; multiple exact matches stay
      # ambiguous and fail rather than relying on traversal order.
      Resolve-UniqueInstallerFile -Item $InxFiles -Pattern 'Setup.inx' `
        -BasePath $Installer.ExtractedPath -Description 'InstallShield compiled-script payload'
    }
    $ScriptPath = $ScriptFile.FullName
    $ScriptDirectory = [IO.Path]::GetDirectoryName($ScriptPath)
    $ResponseCandidate = Get-ChildItem -LiteralPath $ScriptDirectory -Filter 'setup.iss' -File -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $ResponseCandidate) {
      # Focused cabinet extraction stores setup.inx under an artificial ordinal
      # directory, while InstallShield reads setup.iss from the original media
      # directory beside dataN.hdr. Follow that source relationship before a
      # bounded exact-name fallback across the already enumerated extraction.
      $CabinetSupportProperty = $Installer.PSObject.Properties['InstallShieldCabinetSupport']
      $SupportEntries = if ($CabinetSupportProperty -and $CabinetSupportProperty.Value) {
        @($CabinetSupportProperty.Value.SupportEntries)
      } else {
        @()
      }
      $ScriptHeader = @($SupportEntries | Where-Object Name -CEQ $ScriptFile.Name | Select-Object -First 1).HeaderPath
      if ($ScriptHeader) {
        $MediaResponsePath = Join-Path ([IO.Path]::GetDirectoryName([string]$ScriptHeader)) 'setup.iss'
        if (Test-Path -LiteralPath $MediaResponsePath -PathType Leaf) {
          $ResponseCandidate = Get-Item -LiteralPath $MediaResponsePath -Force
        }
      }
    }
    if (-not $ResponseCandidate) {
      $ExtractedFilesProperty = $Installer.PSObject.Properties['ExtractedFiles']
      $ResponseCandidates = if ($ExtractedFilesProperty) {
        @($ExtractedFilesProperty.Value | Where-Object { [IO.Path]::GetFileName([string]$_) -ceq 'setup.iss' })
      } else {
        @()
      }
      if ($ResponseCandidates.Count -eq 1) { $ResponseCandidate = Get-Item -LiteralPath $ResponseCandidates[0] -Force }
    }
    $StringTablePaths = [string[]]@($Installer.ExtractedFiles | Where-Object {
        $FileName = [IO.Path]::GetFileName($_)
        $FileName -like 'StringTable_*.ips' -or $FileName -like 'String*.txt'
      })
    $Analysis = Invoke-InstallShieldInstallScriptAnalysis -Path $ScriptPath `
      -EmbeddedResponseFile $ResponseCandidate.FullName -StringTablePath $StringTablePaths `
      -EntryPoint $EntryPoint -AnalysisScope $AnalysisScope
    $Analysis = Merge-InstallShieldInstallScriptMediaEvidence -Installer $Installer -Analysis $Analysis
    $ArpInfo = if ($AnalysisScope -eq 'EmbeddedAction') {
      # The containing MSI or Advanced UI suite owns its uninstall identity.
      # Keep explicit registry writes from the selected function in Analysis,
      # but do not project standalone MaintenanceStart defaults or emit missing
      # Setup.ini identity warnings for a custom-action-only call graph.
      [pscustomobject][ordered]@{
        ProductCode = $null; DisplayName = $null; DisplayVersion = $null; Publisher = $null
        Scope = $null; DefaultInstallLocation = $null; UninstallString = $null
        QuietUninstallString = $null; DisplayIcon = $null; URLInfoAbout = $null; HelpLink = $null
        WritesAppsAndFeaturesEntry = $null; AppsAndFeaturesProductCode = $null
        AppsAndFeaturesInstallerType = $null; AppsAndFeaturesEntries = [object[]]@()
        RegistryWrites = [object[]]@(); ProjectProductCode = $null; ProjectName = $null
        ProjectPublisher = $null; RegistrationMode = 'EmbeddedAction'
        RuntimeEvidence = [string[]]$Analysis.ArpRuntimeEvidence; ValueSources = [ordered]@{}
        Warnings = [string[]]@(); UnresolvedFields = [string[]]@()
      }
    } else {
      Get-InstallShieldInstallScriptArpInfo -Installer $Installer -Analysis $Analysis
    }
    $Warnings = [string[]]@((@($Analysis.Warnings) + @($ArpInfo.Warnings)) | Select-Object -Unique)
    # Select-Object -Unique compares custom objects as their type name and can
    # collapse unrelated values. Deduplicate registry evidence by its stable
    # registry identity while retaining the first, most direct source.
    $RegistryWrites = [Collections.Generic.List[object]]::new()
    $RegistryWriteKeys = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($RegistryWrite in @($Analysis.RegistryWrites) + @($ArpInfo.RegistryWrites)) {
      if ($null -eq $RegistryWrite) { continue }
      $Roots = if ($RegistryWrite.PSObject.Properties['Root']) {
        [string]$RegistryWrite.Root
      } else {
        [string]::Join('|', [string[]]@($RegistryWrite.RootCandidates))
      }
      $Identity = $Roots + "`0" + [string]$RegistryWrite.Key + "`0" + [string]$RegistryWrite.Name + "`0" + [string]$RegistryWrite.Type + "`0" + [string]$RegistryWrite.Data
      if ($RegistryWriteKeys.Add($Identity)) { $RegistryWrites.Add($RegistryWrite) }
    }

    # Return the common parser envelope first, followed by InstallScript-only
    # silent, registry, and compiled-script evidence. This lets the analyzer and
    # manifest updater consume one result without reparsing setup.inx.
    return [pscustomobject][ordered]@{
      Path                               = $Installer.PSObject.Properties['Path'] ? [string]$Installer.Path : $Analysis.Path
      InstallerType                      = 'InstallShield InstallScript'
      ProductCode                        = $ArpInfo.ProductCode
      UpgradeCode                        = $null
      DisplayName                        = $ArpInfo.DisplayName
      DisplayVersion                     = $ArpInfo.DisplayVersion
      Publisher                          = $ArpInfo.Publisher
      Scope                              = $ArpInfo.Scope
      DefaultInstallLocation             = $ArpInfo.DefaultInstallLocation
      UninstallString                    = $ArpInfo.UninstallString
      QuietUninstallString               = $ArpInfo.QuietUninstallString
      DisplayIcon                        = $ArpInfo.DisplayIcon
      URLInfoAbout                       = $ArpInfo.URLInfoAbout
      HelpLink                           = $ArpInfo.HelpLink
      WritesAppsAndFeaturesEntry         = $ArpInfo.WritesAppsAndFeaturesEntry
      AppsAndFeaturesProductCode         = $ArpInfo.AppsAndFeaturesProductCode
      AppsAndFeaturesInstallerType       = $ArpInfo.AppsAndFeaturesInstallerType
      Warnings                           = $Warnings
      UnresolvedFields                   = [string[]]$ArpInfo.UnresolvedFields
      AppsAndFeaturesEntries             = [object[]]$ArpInfo.AppsAndFeaturesEntries
      RegistryWrites                     = [object[]]$RegistryWrites.ToArray()
      RegistryItems                      = [object[]]$Analysis.RegistryItems
      MediaRegistrySets                  = [object[]]$Analysis.MediaRegistrySets
      MediaRegistryWrites                = [object[]]$Analysis.MediaRegistryWrites
      ConditionalMediaRegistryWrites     = [object[]]$Analysis.ConditionalMediaRegistryWrites
      CabinetFileGroups                  = [object[]]$Analysis.CabinetFileGroups
      CabinetComponents                  = [object[]]$Analysis.CabinetComponents
      MediaSetupTypes                    = [object[]]$Analysis.MediaSetupTypes
      MediaShellFolders                  = [object[]]$Analysis.MediaShellFolders
      MediaShortcuts                     = [object[]]$Analysis.MediaShortcuts
      ConditionalMediaShortcuts          = [object[]]$Analysis.ConditionalMediaShortcuts
      ConditionalRegistryAssociationInfo = $Analysis.ConditionalRegistryAssociationInfo
      ConditionalProtocols               = [string[]]$Analysis.ConditionalProtocols
      ConditionalFileExtensions          = [string[]]$Analysis.ConditionalFileExtensions
      Protocols                          = [string[]]$Analysis.Protocols
      FileExtensions                     = [string[]]$Analysis.FileExtensions
      ProtocolAssociations               = [object[]]$Analysis.ProtocolAssociations
      FileExtensionAssociations          = [object[]]$Analysis.FileExtensionAssociations
      RegistryAssociationInfo            = $Analysis.RegistryAssociationInfo
      ProjectProductCode                 = $ArpInfo.ProjectProductCode
      ProjectName                        = $ArpInfo.ProjectName
      ProjectPublisher                   = $ArpInfo.ProjectPublisher
      CompiledScriptPath                 = $Analysis.Path
      CompiledScriptName                 = [IO.Path]::GetFileName($Analysis.Path)
      ArpRegistrationMode                = $ArpInfo.RegistrationMode
      ArpRuntimeEvidence                 = [string[]]$ArpInfo.RuntimeEvidence
      ArpValueSources                    = $ArpInfo.ValueSources
      SilentSupport                      = $Analysis.SilentSupport
      ResponseFileRequirement            = $Analysis.ResponseFileRequirement
      SilentSwitches                     = [string[]]$Analysis.SilentSwitches
      InstallEntryPoints                 = [string[]]$Analysis.InstallEntryPoints
      DialogCalls                        = [string[]]$Analysis.DialogCalls
      DialogTraces                       = [object[]]$Analysis.DialogTraces
      ResponseFileAccesses               = [string[]]$Analysis.ResponseFileAccesses
      ExecutedPayloads                   = [object[]]$Analysis.ExecutedPayloads
      FileOperations                     = [object[]]$Analysis.FileOperations
      DllOperations                      = [object[]]$Analysis.DllOperations
      PropertyHandlers                   = [object[]]$Analysis.PropertyHandlers
      Shortcuts                          = [object[]]$Analysis.Shortcuts
      StaticCalls                        = [object[]]$Analysis.StaticCalls
      ExternalSymbols                    = [object[]]$Analysis.ExternalSymbols
      AddressResolutions                 = [object[]]$Analysis.AddressResolutions
      ExportedFunctions                  = [string[]]$Analysis.ExportedFunctions
      OpcodeCoverage                     = [object[]]$Analysis.OpcodeCoverage
      UnsupportedOpcodes                 = [string[]]$Analysis.UnsupportedOpcodes
      UnresolvedCalls                    = [string[]]$Analysis.UnresolvedCalls
      InstallOperations                  = [string[]]$Analysis.InstallOperations
      EmbeddedResponseFile               = $Analysis.EmbeddedResponseFile
      EmbeddedResponseValidation         = $Analysis.EmbeddedResponseValidation
      ParserVersionInfo                  = [pscustomobject][ordered]@{
        Parser                   = 'Dumplings.PackageModule.InstallShieldInstallScript'
        ParserMajor              = 11
        Format                   = $Analysis.ParserVersionInfo.Format
        BytecodeProfile          = $Analysis.ParserVersionInfo.BytecodeProfile
        CompilerVersion          = $Analysis.ParserVersionInfo.CompilerVersion
        HeaderKind               = $Analysis.ParserVersionInfo.HeaderKind
        SupportStatus            = $Analysis.ParserVersionInfo.SupportStatus
        WasScrambled             = $Analysis.ParserVersionInfo.WasScrambled
        HeaderValue              = $Analysis.ParserVersionInfo.HeaderValue
        MarkerOffset             = $Analysis.ParserVersionInfo.MarkerOffset
        CopyrightMarker          = $Analysis.ParserVersionInfo.CopyrightMarker
        AnalysisMode             = $AnalysisScope -eq 'EmbeddedAction' ? 'ScopedBoundedStaticEmulation' : 'BoundedStaticEmulationAndMaintenanceDefaults'
        AnalysisScope            = $AnalysisScope
        FunctionCount            = $Analysis.ParserVersionInfo.FunctionCount
        ExportedFunctionCount    = $Analysis.ParserVersionInfo.ExportedFunctionCount
        ExternalSymbolCount      = $Analysis.ParserVersionInfo.ExternalSymbolCount
        AddressResolutionCount   = $Analysis.ParserVersionInfo.AddressResolutionCount
        InstructionCount         = $Analysis.ParserVersionInfo.InstructionCount
        ExploredInstructionCount = $Analysis.ParserVersionInfo.ExploredInstructionCount
        EmulationTruncated       = $Analysis.ParserVersionInfo.EmulationTruncated
        ResourceTableCount       = $Analysis.ParserVersionInfo.ResourceTableCount
        PropertyHandlerCount     = @($Analysis.PropertyHandlers).Count
        CabinetFileGroupCount    = @($Analysis.CabinetFileGroups).Count
        CabinetComponentCount    = @($Analysis.CabinetComponents).Count
        MediaSetupTypeCount      = @($Analysis.MediaSetupTypes).Count
      }
    }
  }
}

Export-ModuleMember -Function @(
  'Get-InstallShieldInstallScriptInfo'
  'Get-InstallShieldInstallScriptHeaderInfo'
  'Get-InstallShieldInstallScriptLibraryInfo'
  'Get-InstallShieldInstallScriptArpInfo'
  'Invoke-InstallShieldInstallScriptAnalysis'
  'Read-InstallShieldInstallScriptProgram'
  'Get-InstallShieldInstallScriptDialogTrace'
  'Read-InstallShieldInstallScriptStringTable'
  'New-InstallShieldResponseFileTemplate'
  'Test-InstallShieldResponseFile'
)
