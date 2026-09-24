# SPDX-License-Identifier: Apache-2.0
# Paquet Builder parser independently derived from archived builder output, the
# shipped PBCore C ABI, controlled projects, and PE/7z/MSI specifications.
# References:
# - https://www.installpackbuilder.com/help/automation-command-line/package-installer-command-line
# - https://web.archive.org/web/*/https://download.installpackbuilder.com/pbinst.exe
# - https://web.archive.org/web/*/http://www.installpackbuilder.com/files/pbinst.exe
# - https://web.archive.org/web/*/http://www.gdgsoft.com/files/pbinst.exe
# - https://web.archive.org/web/*/https://download.gdgsoftware.com/pb/pbinst.exe
# - https://web.archive.org/web/*/https://files.gdgsoft.com/pb/pbinst.exe
# - https://web.archive.org/web/*/https://download.gdgsoftware.com/pb/pbinst64.exe
# - https://github.com/upx/upx (format behavior only; no GPL source copied)
#
# Structural generations consumed here:
#
#   Classic2 (observed 2.6.x)
#   PE image
#   +-- .rsrc/RCDATA: DESCRIPTION, DVCLAL, PACKAGEINFO
#   `-- overlay
#       +-- 20-byte envelope + @GDG GPacker/LZHUF control block
#       `-- ZIP package: SETUP*.GAF records + setup runtime
#
#   Cabinet2 (observed 2.7.x)
#   PE image
#   +-- .rsrc/RCDATA/ENG: MZ cabinet runtime
#   +-- .rsrc/RCDATA/ISFX: exact package and payload offsets
#   `-- proprietary cabinet/configuration payload
#
#   Legacy2 / Resource2 (observed 2.8.x / 2.9.x)
#   PE image
#   +-- .rsrc/RCDATA/ENG: MZ runtime or GP-framed raw-LZMA runtime
#   +-- .rsrc/RCDATA/ISFX: optional launcher descriptor
#   `-- overlay: one independent 7z payload archive
#
#   Split3 (observed 3.x-current)
#   PE image importing PBCore[64].dll!SetVar
#   +-- optional UPX 13/LZMA wrapper in observed 3.0 and 3.2 media
#   `-- overlay
#       +-- application payload 7z
#       `-- runtime 7z
#           +-- pbfprop.dat: repeated five-line payload records
#           +-- pbdlg.dat / pblng.dat: UI and locale records
#           +-- pbremove.dat: generated-uninstaller template
#           `-- PBCore*.dll: native package runtime

# Apply default function parameters supplied by the Dumplings runner.
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:PaquetBuilderMaximumArchiveBytes = 17179869184L
$Script:PaquetBuilderMaximumMappedPeBytes = 268435456
$Script:PaquetBuilderMaximumRuntimeMetadataBytes = 4194304
$Script:PaquetBuilderMaximumClassicControlBytes = 67108864
$Script:PaquetBuilderMaximumClassicControllerBytes = 268435456
$Script:PaquetBuilderMaximumClassicRecordCount = 65536
$Script:PaquetBuilderMaximumPackageResourceCount = 1024
$Script:PaquetBuilderMaximumUpxHeaderSearchBytes = 1048576
$Script:PaquetBuilderFormatCatalog = Import-PowerShellDataFile -LiteralPath (Join-Path $PSScriptRoot 'PaquetBuilderFormatCatalog.psd1')
$Script:PaquetBuilderScannerSource = Join-Path $PSScriptRoot '..\..\Assets\Source\PaquetBuilder\PaquetBuilderPeScanner.cs'
$Script:PaquetBuilderClassicDecoderSource = Join-Path $PSScriptRoot '..\..\Assets\Source\PaquetBuilder\PaquetBuilderClassicDecoder.cs'
$Script:PaquetBuilderApLibDecoderSource = Join-Path $PSScriptRoot '..\..\Assets\Source\PaquetBuilder\PaquetBuilderApLibDecoder.cs'
$null = Import-InstallerManagedSource -Path $Script:PaquetBuilderScannerSource -TypeName 'Dumplings.PaquetBuilder.PaquetBuilderPeScanner'
$null = Import-InstallerManagedSource -Path $Script:PaquetBuilderClassicDecoderSource -TypeName 'Dumplings.PaquetBuilder.PaquetBuilderClassicDecoder'
$null = Import-InstallerManagedSource -Path $Script:PaquetBuilderApLibDecoderSource -TypeName 'Dumplings.PaquetBuilder.PaquetBuilderApLibDecoder'

function Get-PaquetBuilderFormatProfile {
  <#
  .SYNOPSIS
    Return one data-driven Paquet Builder structural profile.
  .PARAMETER Id
    Stable profile identifier from PaquetBuilderFormatCatalog.psd1.
  #>
  param ([Parameter(Mandatory)][string]$Id)

  $FormatProfile = @($Script:PaquetBuilderFormatCatalog.Profiles | Where-Object Id -CEQ $Id)[0]
  if (-not $FormatProfile) { throw "Unknown Paquet Builder format profile '$Id'." }
  return $FormatProfile
}

function ConvertTo-PaquetBuilderDiagnostic {
  <#
  .SYNOPSIS
    Create one context-neutral Paquet Builder parser diagnostic.
  .PARAMETER Id
    Stable condition identifier without the PaquetBuilder prefix.
  .PARAMETER Message
    Human-readable explanation of the evidence or limitation.
  .PARAMETER Kind
    Context-neutral diagnostic kind resolved later by the workflow.
  .PARAMETER Areas
    Parser areas affected by the condition.
  .PARAMETER AffectedFields
    Manifest metadata fields affected by the condition.
  .PARAMETER Evidence
    Optional structured source evidence.
  #>
  param (
    [Parameter(Mandatory)][string]$Id,
    [Parameter(Mandatory)][string]$Message,
    [Parameter(Mandatory)][ValidateSet('Information', 'Fallback', 'Incomplete', 'Ambiguous', 'Unsupported', 'Mismatch', 'ManualValidation', 'Risk', 'Invalid')][string]$Kind,
    [Parameter(Mandatory)][string[]]$Areas,
    [string[]]$AffectedFields = @(),
    [AllowNull()][object]$Evidence
  )

  New-InstallerDiagnostic -Id "PaquetBuilder.$Id" -Source 'PaquetBuilder' -Message $Message -Kind $Kind -Areas $Areas -AffectedFields $AffectedFields -Evidence $Evidence
}

function Read-PaquetBuilderResourceData {
  <#
  .SYNOPSIS
    Read one bounded PE resource from the parser-owned installer stream.
  .PARAMETER Stream
    Parser-owned seekable installer stream. Its position is restored.
  .PARAMETER Resource
    Resource range returned by Get-PEResourceInfo.
  .PARAMETER MaximumBytes
    Maximum accepted resource size in bytes.
  #>
  [OutputType([byte[]])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)]$Resource,
    [Parameter(Mandatory)][ValidateRange(1, [int]::MaxValue)][int]$MaximumBytes
  )

  if ($Resource.Size -lt 0 -or $Resource.Size -gt $MaximumBytes) { throw "Paquet Builder resource '$($Resource.Name)' exceeds the $MaximumBytes-byte limit." }
  return , (Read-BinaryBytes -Stream $Stream -Offset $Resource.Offset -Count ([int]$Resource.Size))
}

function Read-PaquetBuilderIsfxDescriptor {
  <#
  .SYNOPSIS
    Parse the fixed RCDATA/ISFX descriptor used by Paquet Builder 2.7 and 2.8 media.
  .PARAMETER Stream
    Parser-owned seekable installer stream. Its position is restored.
  .PARAMETER Resource
    ISFX resource range returned by Get-PEResourceInfo.
  .PARAMETER FileLength
    Complete installer length used to validate the absolute package offsets.
  #>
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)]$Resource,
    [Parameter(Mandatory)][ValidateRange(1, [long]::MaxValue)][long]$FileLength
  )

  if ($Resource.Size -ne 24) { throw 'The Paquet Builder ISFX descriptor does not have the expected 24-byte size.' }
  $Bytes = Read-PaquetBuilderResourceData -Stream $Stream -Resource $Resource -MaximumBytes 24
  if ($Bytes[0] -ne 3 -or [Text.Encoding]::ASCII.GetString($Bytes, 1, 3) -cne 'GDG') { throw 'The Paquet Builder ISFX descriptor magic is invalid.' }
  $PackageOffset = [long][BitConverter]::ToUInt32($Bytes, 8)
  $PayloadOffset = [long][BitConverter]::ToUInt32($Bytes, 12)
  if ($PackageOffset -le 0 -or $PayloadOffset -le $PackageOffset -or $PayloadOffset -ge $FileLength) { throw 'The Paquet Builder ISFX package offsets are outside the installer.' }

  [pscustomobject][ordered]@{
    Version           = [int]$Bytes[0]
    PackageOffset     = $PackageOffset
    PayloadOffset     = $PayloadOffset
    ConfigurationSize = $PayloadOffset - $PackageOffset
    PayloadSize       = $FileLength - $PayloadOffset
    ObservedField     = [BitConverter]::ToUInt32($Bytes, 4)
    Reserved          = [Convert]::ToHexString($Bytes[16..23])
  }
}

function ConvertFrom-PaquetBuilderPackageCipher {
  <#
  .SYNOPSIS
    Decode the package-specific byte transform used before Paquet Builder 2.7 and 2.8 configuration containers.
  .PARAMETER Bytes
    Complete ISFX-declared configuration range. The caller's array is not modified.
  #>
  [OutputType([byte[]])]
  param ([Parameter(Mandatory)][byte[]]$Bytes)

  $Decoded = [byte[]]::new($Bytes.Length)
  [uint32]$State = 0xDE27
  for ($Index = 0; $Index -lt $Bytes.Length; $Index++) {
    $CipherByte = [byte]$Bytes[$Index]
    $Decoded[$Index] = [byte]($CipherByte -bxor ($State -shr 8))
    # The runtime updates a 16-bit linear state from the original ciphertext byte.
    $State = ((($State + $CipherByte) * 0x75BA) + 0xC78A) -band 0xFFFF
  }
  return , $Decoded
}

function Read-PaquetBuilderPackageResourceTable {
  <#
  .SYNOPSIS
    Parse the bounded named-resource table produced by the 2.7 package decoder.
  .PARAMETER Bytes
    Complete expanded resource table beginning with the fixed 01..08 marker.
  #>
  param ([Parameter(Mandatory)][byte[]]$Bytes)

  $Marker = [byte[]](1, 2, 3, 4, 5, 6, 7, 8)
  if ($Bytes.Length -lt 12 -or -not (Test-BinarySequence -Left $Bytes[0..7] -Right $Marker)) { throw 'The Paquet Builder package resource-table marker is invalid.' }
  $Count = [long][BitConverter]::ToUInt32($Bytes, 8)
  if ($Count -le 0 -or $Count -gt $Script:PaquetBuilderMaximumPackageResourceCount) { throw 'The Paquet Builder package resource count is outside the configured limit.' }

  $Resources = [Collections.Generic.List[object]]::new([int]$Count)
  $Names = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $Offset = 12
  for ($Index = 0; $Index -lt $Count; $Index++) {
    if ($Offset + 2 -gt $Bytes.Length) { throw 'The Paquet Builder package resource name length is truncated.' }
    $NameLength = [int][BitConverter]::ToUInt16($Bytes, $Offset)
    $Offset += 2
    if ($NameLength -le 0 -or $NameLength -gt 1024 -or $Offset + $NameLength + 4 -gt $Bytes.Length) { throw 'A Paquet Builder package resource name exceeds its bounded record.' }
    $Name = [Text.Encoding]::GetEncoding(1252).GetString($Bytes, $Offset, $NameLength)
    $Offset += $NameLength
    if ($Name.IndexOf([char]0) -ge 0 -or -not $Names.Add($Name)) { throw "The Paquet Builder package resource name '$Name' is invalid or duplicated." }

    $Length = [long][BitConverter]::ToUInt32($Bytes, $Offset)
    $Offset += 4
    if ($Length -gt $Bytes.Length - $Offset) { throw "Paquet Builder package resource '$Name' exceeds the expanded table." }
    $Content = [byte[]]::new([int]$Length)
    if ($Length -gt 0) { [Array]::Copy($Bytes, $Offset, $Content, 0, [int]$Length) }
    $Resources.Add([pscustomobject][ordered]@{ Index = $Index; Name = $Name; Offset = $Offset; Length = $Length; Content = $Content })
    $Offset += [int]$Length
  }
  if ($Offset -ne $Bytes.Length) { throw 'The Paquet Builder package resource table contains trailing bytes outside its declared records.' }
  return $Resources.ToArray()
}

function Split-PaquetBuilderScriptArgument {
  <#
  .SYNOPSIS
    Split a Paquet Builder script command's comma-delimited arguments without breaking quoted text.
  .PARAMETER Text
    Argument text following the command name.
  #>
  [OutputType([string[]])]
  param ([Parameter(Mandatory)][AllowEmptyString()][string]$Text)

  $Arguments = [Collections.Generic.List[string]]::new()
  $Buffer = [Text.StringBuilder]::new()
  $InQuote = $false
  for ($Index = 0; $Index -lt $Text.Length; $Index++) {
    $Character = $Text[$Index]
    if ($Character -eq '"') {
      if ($InQuote -and $Index + 1 -lt $Text.Length -and $Text[$Index + 1] -eq '"') {
        $null = $Buffer.Append('"')
        $Index++
      } else {
        $InQuote = -not $InQuote
      }
      continue
    }
    if ($Character -eq ',' -and -not $InQuote) {
      $Arguments.Add($Buffer.ToString().Trim())
      $null = $Buffer.Clear()
      continue
    }
    $null = $Buffer.Append($Character)
  }
  if ($InQuote) { throw 'A Paquet Builder script command contains an unterminated quoted argument.' }
  $Arguments.Add($Buffer.ToString().Trim())
  return $Arguments.ToArray()
}

function Read-PaquetBuilderScriptProgram {
  <#
  .SYNOPSIS
    Project literal assignments and nested execution commands from a decoded GINFOS program.
  .PARAMETER Text
    Complete Windows-1252 GINFOS source text.
  #>
  param ([Parameter(Mandatory)][string]$Text)

  $Assignments = [Collections.Generic.List[object]]::new()
  $Commands = [Collections.Generic.List[object]]::new()
  $ExecutedPayloads = [Collections.Generic.List[object]]::new()
  $NestedInstallerReferences = [Collections.Generic.List[object]]::new()
  $RegistryWrites = [Collections.Generic.List[object]]::new()
  $Shortcuts = [Collections.Generic.List[object]]::new()
  $FileOperations = [Collections.Generic.List[object]]::new()
  $UninstallOperations = [Collections.Generic.List[object]]::new()
  $UnsupportedCommands = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $Lines = [regex]::Split($Text, '\r\n|\n|\r')
  for ($Index = 0; $Index -lt $Lines.Length; $Index++) {
    $Line = $Lines[$Index].Trim()
    if ([string]::IsNullOrWhiteSpace($Line) -or $Line.StartsWith(';')) { continue }
    $CommandName = [regex]::Match($Line, '^(?<Name>[A-Za-z][A-Za-z0-9_]*)').Groups['Name'].Value.ToUpperInvariant()
    if ([string]::IsNullOrWhiteSpace($CommandName)) { continue }
    $Commands.Add([pscustomobject][ordered]@{ LineNumber = $Index + 1; Name = $CommandName; Text = $Line })

    $AssignmentMatch = [regex]::Match($Line, '^(?i:SET)\s+(?<Name>[A-Za-z][A-Za-z0-9_]*)\s+(?i:TO)\s+(?<Expression>.+?)\s*$')
    if ($AssignmentMatch.Success) {
      $Expression = $AssignmentMatch.Groups['Expression'].Value
      $LiteralMatch = [regex]::Match($Expression, '^"(?<Value>(?:""|[^"])*)"$')
      $Assignments.Add([pscustomobject][ordered]@{
          Name       = $AssignmentMatch.Groups['Name'].Value
          Value      = $LiteralMatch.Success ? $LiteralMatch.Groups['Value'].Value.Replace('""', '"') : $null
          Expression = $Expression
          IsLiteral  = $LiteralMatch.Success
          LineNumber = $Index + 1
        })
      continue
    }

    $OperationMatch = [regex]::Match($Line, '^(?<Name>(?i:SHORTCUT|CREATEFOLDER|COPY|DELETE|DELFOLDER|WRITEF|ADDUNCOM))\s+(?<Arguments>.+)$')
    if ($OperationMatch.Success) {
      $RawArguments = $OperationMatch.Groups['Arguments'].Value
      $Arguments = @(Split-PaquetBuilderScriptArgument -Text $RawArguments)
      switch ($CommandName) {
        'SHORTCUT' {
          if ($Arguments.Count -lt 3) { $null = $UnsupportedCommands.Add($CommandName); continue }
          $Shortcuts.Add([pscustomobject][ordered]@{
              ShortcutPath = $Arguments[0]
              Description  = $Arguments[1]
              TargetPath   = $Arguments[2]
              Arguments    = $Arguments.Count -gt 3 ? $Arguments[3] : ''
              WorkingPath  = $Arguments.Count -gt 4 ? $Arguments[4] : ''
              Icon         = $Arguments.Count -gt 5 ? $Arguments[5] : ''
              Options      = $Arguments.Count -gt 6 ? [string[]]$Arguments[6..($Arguments.Count - 1)] : @()
              RawArguments = $RawArguments
              LineNumber   = $Index + 1
            })
        }
        'ADDUNCOM' {
          if ($Arguments.Count -lt 1) { $null = $UnsupportedCommands.Add($CommandName); continue }
          $UninstallOperations.Add([pscustomobject][ordered]@{
              Operation    = $Arguments[0]
              Arguments    = $Arguments.Count -gt 1 ? [string[]]$Arguments[1..($Arguments.Count - 1)] : @()
              RawArguments = $RawArguments
              LineNumber   = $Index + 1
            })
        }
        default {
          $FileOperations.Add([pscustomobject][ordered]@{
              Operation    = $CommandName
              Source       = $CommandName -in @('COPY', 'WRITEF') -and $Arguments.Count -gt 0 ? $Arguments[0] : $null
              Destination  = $CommandName -in @('COPY', 'WRITEF') -and $Arguments.Count -gt 1 ? $Arguments[1] : ($Arguments.Count -gt 0 ? $Arguments[0] : $null)
              Options      = $CommandName -in @('COPY', 'WRITEF') -and $Arguments.Count -gt 2 ? [string[]]$Arguments[2..($Arguments.Count - 1)] : ($Arguments.Count -gt 1 ? [string[]]$Arguments[1..($Arguments.Count - 1)] : @())
              RawArguments = $RawArguments
              LineNumber   = $Index + 1
            })
        }
      }
      continue
    }

    $ExecutionMatch = [regex]::Match($Line, '^(?<Name>(?i:EXEC|EXECUTE|EXECWAIT))\s+(?<Arguments>.+)$')
    if ($ExecutionMatch.Success) {
      $RawArguments = $ExecutionMatch.Groups['Arguments'].Value
      $Arguments = @(Split-PaquetBuilderScriptArgument -Text $RawArguments)
      $ExecutedPayloads.Add([pscustomobject][ordered]@{
          Command      = $ExecutionMatch.Groups['Name'].Value.ToUpperInvariant()
          Path         = $Arguments.Count -gt 0 ? $Arguments[0] : ''
          Arguments    = $Arguments.Count -gt 1 ? $Arguments[1] : ''
          Options      = $Arguments.Count -gt 2 ? [string[]]$Arguments[2..($Arguments.Count - 1)] : @()
          RawArguments = $RawArguments
          LineNumber   = $Index + 1
        })
      continue
    }

    $CallDllMatch = [regex]::Match($Line, '^(?i:CALLDLL)\s+(?<Arguments>.+)$')
    if ($CallDllMatch.Success) {
      $RawArguments = $CallDllMatch.Groups['Arguments'].Value
      $Arguments = @(Split-PaquetBuilderScriptArgument -Text $RawArguments)
      if ($Arguments.Count -ge 2 -and $Arguments[0] -match '(?i)\*PBExecMSI$' -and $Arguments[1] -match '^(?i:%DESTPATH%)[\\/](?<Path>.+\.msi)$') {
        $NestedInstallerReferences.Add([pscustomobject][ordered]@{
            InstallerType = 'msi'
            RelativePath  = $Matches.Path.Replace([char]47, [char]92)
            Function      = $Arguments[0]
            RawArguments  = $RawArguments
            LineNumber    = $Index + 1
          })
      }
      if ($Arguments.Count -lt 2 -or $Arguments[0] -notmatch '(?i)\*PBExecMSI$') { $null = $UnsupportedCommands.Add($CommandName) }
      continue
    }

    $RegistryMatch = [regex]::Match($Line, '^(?i:WRITEREG)\s+(?<Arguments>.+)$')
    if ($RegistryMatch.Success) {
      $RawArguments = $RegistryMatch.Groups['Arguments'].Value
      $Arguments = @(Split-PaquetBuilderScriptArgument -Text $RawArguments)
      if ($Arguments.Count -lt 5 -or $Arguments[0] -notmatch '^\d+$') {
        $null = $UnsupportedCommands.Add($CommandName)
        continue
      }
      $RootCode = [int]$Arguments[0]
      $Root = switch ($RootCode) { 0 { 'HKCR' }; 2 { 'HKCU' }; 4 { 'HKLM' }; default { $null } }
      $ValueType = switch ($Arguments[4]) { '0' { 'String' }; '1' { 'DWord' }; default { 'Unknown' } }
      $RegistryWrites.Add([pscustomobject][ordered]@{
          Root         = $Root
          Key          = $Arguments[1]
          Name         = $Arguments[2]
          Value        = $Arguments[3]
          Type         = $ValueType
          RootCode     = $RootCode
          TypeCode     = $Arguments[4]
          Options      = $Arguments.Count -gt 5 ? [string[]]$Arguments[5..($Arguments.Count - 1)] : @()
          RawArguments = $RawArguments
          LineNumber   = $Index + 1
        })
      if (-not $Root -or $ValueType -eq 'Unknown') { $null = $UnsupportedCommands.Add($CommandName) }
      continue
    }

    if ($CommandName -notin @('IF', 'END', 'EXIT', 'CUSTOMDLG', 'SETBAL', 'MSG', 'UNZIP', 'DELFOLDER', 'UNINSTALLINFO')) { $null = $UnsupportedCommands.Add($CommandName) }
  }

  [pscustomobject][ordered]@{
    Text                      = $Text
    Commands                  = $Commands.ToArray()
    Assignments               = $Assignments.ToArray()
    ExecutedPayloads          = $ExecutedPayloads.ToArray()
    NestedInstallerReferences = $NestedInstallerReferences.ToArray()
    RegistryWrites            = $RegistryWrites.ToArray()
    Shortcuts                 = $Shortcuts.ToArray()
    FileOperations            = $FileOperations.ToArray()
    UninstallOperations       = $UninstallOperations.ToArray()
    UnsupportedCommands       = [string[]]@($UnsupportedCommands | Sort-Object)
  }
}

function Read-PaquetBuilderPackageConfiguration {
  <#
  .SYNOPSIS
    Decode and validate the ISFX-declared Paquet Builder package configuration.
  .PARAMETER Stream
    Parser-owned installer stream. Its position is restored and it is not disposed.
  .PARAMETER Descriptor
    Validated ISFX descriptor containing the exact encoded range.
  #>
  param ([Parameter(Mandatory)][IO.Stream]$Stream, [Parameter(Mandatory)]$Descriptor)

  if ($Descriptor.ConfigurationSize -lt 24 -or $Descriptor.ConfigurationSize -gt $Script:PaquetBuilderMaximumRuntimeMetadataBytes) { throw 'The Paquet Builder package configuration exceeds the configured limit.' }
  $Encoded = Read-BinaryBytes -Stream $Stream -Offset $Descriptor.PackageOffset -Count ([int]$Descriptor.ConfigurationSize)
  $Container = ConvertFrom-PaquetBuilderPackageCipher -Bytes $Encoded
  $Magic = [Text.Encoding]::ASCII.GetString($Container, 0, 4)

  if ($Magic -ceq 'AP32') {
    $HeaderSize = [long][BitConverter]::ToUInt32($Container, 4)
    $CompressedSize = [long][BitConverter]::ToUInt32($Container, 8)
    $ExpectedCompressedCrc32 = [uint32][BitConverter]::ToUInt32($Container, 12)
    $UncompressedSize = [long][BitConverter]::ToUInt32($Container, 16)
    $ExpectedUncompressedCrc32 = [uint32][BitConverter]::ToUInt32($Container, 20)
    if ($HeaderSize -ne 24 -or $CompressedSize -ne $Container.Length - $HeaderSize -or $UncompressedSize -le 0 -or $UncompressedSize -gt $Script:PaquetBuilderMaximumRuntimeMetadataBytes) { throw 'The Paquet Builder AP32 package header contains invalid bounds.' }
    $ActualCompressedCrc32 = [uint32](Get-BinaryCrc32 -Bytes $Container -Offset ([int]$HeaderSize) -Count ([int]$CompressedSize))
    if ($ActualCompressedCrc32 -ne $ExpectedCompressedCrc32) { throw 'The Paquet Builder AP32 compressed configuration fails its CRC32 check.' }

    $Decoded = [Dumplings.PaquetBuilder.PaquetBuilderApLibDecoder]::Decode($Container, [int]$HeaderSize, [int]$CompressedSize, [int]$UncompressedSize)
    $ActualUncompressedCrc32 = [uint32](Get-BinaryCrc32 -Bytes $Decoded.Data)
    if ($ActualUncompressedCrc32 -ne $ExpectedUncompressedCrc32) { throw ('The Paquet Builder AP32 expanded configuration fails its CRC32 check: expected {0:X8}, got {1:X8}.' -f $ExpectedUncompressedCrc32, $ActualUncompressedCrc32) }

    $Resources = @(Read-PaquetBuilderPackageResourceTable -Bytes $Decoded.Data)
    $ScriptResource = @($Resources | Where-Object Name -IEQ 'GINFOS')
    if ($ScriptResource.Count -ne 1) { throw 'The Paquet Builder AP32 package does not contain one unambiguous GINFOS program.' }
    $Encoding = [Text.Encoding]::GetEncoding(1252)
    $ScriptProgram = Read-PaquetBuilderScriptProgram -Text $Encoding.GetString($ScriptResource[0].Content)
    $TextResources = [ordered]@{}
    foreach ($Name in @('GFICHS', 'GSTRINGS', 'GTABLE')) {
      $Resource = @($Resources | Where-Object Name -IEQ $Name)[0]
      if ($Resource) { $TextResources[$Name] = $Encoding.GetString($Resource.Content) }
    }

    return [pscustomobject][ordered]@{
      Format                    = 'AP32'
      EncodedOffset             = [long]$Descriptor.PackageOffset
      EncodedSize               = [long]$Descriptor.ConfigurationSize
      HeaderSize                = $HeaderSize
      CompressedSize            = $CompressedSize
      ExpectedCompressedCrc32   = $ExpectedCompressedCrc32
      UncompressedSize          = $UncompressedSize
      ExpectedUncompressedCrc32 = $ExpectedUncompressedCrc32
      ExpectedCrc32             = $null
      ActualCrc32               = $ActualUncompressedCrc32
      DecoderBytesRead          = $Decoded.BytesConsumed
      DecoderPaddingBytes       = $null
      DecoderTrailingBytes      = 0L
      ObservedField             = $null
      IsDecoded                 = $true
      Resources                 = $Resources
      ScriptProgram             = $ScriptProgram
      TextResources             = $TextResources
    }
  }
  if ($Magic -cne '@GDG') { throw "Unsupported Paquet Builder package configuration magic '$Magic'." }

  $UncompressedSize = [long][BitConverter]::ToUInt32($Container, 4)
  $ExpectedCrc32 = [uint32][BitConverter]::ToUInt32($Container, 8)
  if ($UncompressedSize -le 0 -or $UncompressedSize -gt $Script:PaquetBuilderMaximumRuntimeMetadataBytes) { throw 'The Paquet Builder @GDG package output exceeds the configured limit.' }
  $CompressedInput = [IO.MemoryStream]::new($Container, $false)
  try { $Decoded = [Dumplings.PaquetBuilder.PaquetBuilderClassicDecoder]::Decode($CompressedInput, 12, $Container.Length - 12, [int]$UncompressedSize, 1) } finally { $CompressedInput.Dispose() }
  if ($Decoded.PaddingBytes -gt 1) { throw 'The Paquet Builder @GDG package decoder exceeded its one-byte EOF padding allowance.' }
  $ActualCrc32 = [uint32](Get-BinaryCrc32 -Bytes $Decoded.Data)
  if ($ActualCrc32 -ne $ExpectedCrc32) { throw ('The Paquet Builder @GDG package CRC32 is invalid: expected {0:X8}, got {1:X8}.' -f $ExpectedCrc32, $ActualCrc32) }

  $Resources = @(Read-PaquetBuilderPackageResourceTable -Bytes $Decoded.Data)
  $ScriptResource = @($Resources | Where-Object Name -IEQ 'GINFOS')
  if ($ScriptResource.Count -ne 1) { throw 'The Paquet Builder package does not contain one unambiguous GINFOS program.' }
  $Encoding = [Text.Encoding]::GetEncoding(1252)
  $ScriptProgram = Read-PaquetBuilderScriptProgram -Text $Encoding.GetString($ScriptResource[0].Content)
  $TextResources = [ordered]@{}
  foreach ($Name in @('GFICHS', 'GSTRINGS', 'GTABLE')) {
    $Resource = @($Resources | Where-Object Name -IEQ $Name)[0]
    if ($Resource) { $TextResources[$Name] = $Encoding.GetString($Resource.Content) }
  }

  [pscustomobject][ordered]@{
    Format                    = 'GDG-LZHUF'
    EncodedOffset             = [long]$Descriptor.PackageOffset
    EncodedSize               = [long]$Descriptor.ConfigurationSize
    HeaderSize                = 12
    CompressedSize            = [long]$Container.Length - 12
    UncompressedSize          = $UncompressedSize
    ExpectedCrc32             = $ExpectedCrc32
    ActualCrc32               = $ActualCrc32
    ExpectedCompressedCrc32   = $null
    ExpectedUncompressedCrc32 = $ExpectedCrc32
    DecoderBytesRead          = [long]$Decoded.BytesConsumed
    DecoderPaddingBytes       = [int]$Decoded.PaddingBytes
    DecoderTrailingBytes      = 0L
    ObservedField             = $null
    IsDecoded                 = $true
    Resources                 = $Resources
    ScriptProgram             = $ScriptProgram
    TextResources             = [pscustomobject]$TextResources
  }
}

function Read-PaquetBuilderGpRuntime {
  <#
  .SYNOPSIS
    Decode the GP-framed raw-LZMA runtime resource used by Paquet Builder 2.9.
  .PARAMETER Stream
    Parser-owned seekable installer stream. Its position is restored.
  .PARAMETER Resource
    RCDATA/ENG resource range returned by Get-PEResourceInfo.
  #>
  param ([Parameter(Mandatory)][IO.Stream]$Stream, [Parameter(Mandatory)]$Resource)

  if ($Resource.Size -lt 20 -or $Resource.Size -gt $Script:PaquetBuilderMaximumRuntimeMetadataBytes) { throw 'The Paquet Builder GP runtime resource has an invalid bounded size.' }
  $Header = Read-BinaryBytes -Stream $Stream -Offset $Resource.Offset -Count 19
  if ($Header[0] -ne 0x47 -or $Header[1] -ne 0x50) { throw 'The Paquet Builder GP runtime resource magic is invalid.' }
  $UncompressedSize = [long][BitConverter]::ToUInt32($Header, 2)
  $TrailingSize = [long][BitConverter]::ToUInt32($Header, 6)
  $CompressedSize = [long]$Resource.Size - 19 - $TrailingSize
  if ($UncompressedSize -le 0 -or $UncompressedSize -gt $Script:PaquetBuilderMaximumMappedPeBytes) { throw 'The Paquet Builder GP runtime output exceeds the bounded PE limit.' }
  if ($TrailingSize -lt 0 -or $CompressedSize -le 0) { throw 'The Paquet Builder GP runtime framing is malformed.' }

  $Properties = [byte[]]$Header[14..18]
  $Compressed = New-BoundedReadStream -Stream $Stream -Offset ($Resource.Offset + 19) -Length $CompressedSize -LeaveOpen
  $Output = [IO.MemoryStream]::new([int]$UncompressedSize)
  try {
    $null = Expand-InstallerCompressedStream -Algorithm Lzma -Stream $Compressed -Destination $Output -MaximumBytes $UncompressedSize -Properties $Properties -CompressedSize $CompressedSize -UncompressedSize $UncompressedSize
    $RuntimeBytes = $Output.ToArray()
  } finally {
    $Output.Dispose()
    $Compressed.Dispose()
  }
  if ($RuntimeBytes.Length -ne $UncompressedSize -or $RuntimeBytes.Length -lt 2 -or $RuntimeBytes[0] -ne 0x4D -or $RuntimeBytes[1] -ne 0x5A) { throw 'The decoded Paquet Builder GP runtime is not the declared PE image.' }

  $RuntimeStream = [IO.MemoryStream]::new($RuntimeBytes, $false)
  try {
    $Layout = Get-PELayout -Stream $RuntimeStream
    $VersionStrings = try { Get-PEVersionStringTable -Stream $RuntimeStream -Layout $Layout } catch { $null }
    $Resources = @(Get-PEResourceInfo -Stream $RuntimeStream -Layout $Layout)
  } finally {
    $RuntimeStream.Dispose()
  }

  [pscustomobject][ordered]@{
    HeaderSize         = 19
    CompressedOffset   = [long]$Resource.Offset + 19
    CompressedSize     = $CompressedSize
    UncompressedSize   = $UncompressedSize
    TrailingOffset     = [long]$Resource.Offset + 19 + $CompressedSize
    TrailingSize       = $TrailingSize
    ObservedField      = [BitConverter]::ToUInt32($Header, 10)
    LzmaProperties     = $Properties
    RuntimeBytes       = $RuntimeBytes
    RuntimeLayout      = $Layout
    RuntimeResources   = $Resources
    RuntimeVersionInfo = $VersionStrings
  }
}

function Read-PaquetBuilderGpPackageConfiguration {
  <#
  .SYNOPSIS
    Decode the package-specific GP/LZMA resource table appended to a Paquet Builder 2.9 runtime.
  .PARAMETER Stream
    Parser-owned seekable installer stream. Its position is restored and it is not disposed.
  .PARAMETER Runtime
    Validated outer GP runtime record containing the exact trailing configuration range.
  #>
  param ([Parameter(Mandatory)][IO.Stream]$Stream, [Parameter(Mandatory)]$Runtime)

  if ($Runtime.TrailingSize -lt 16 -or $Runtime.TrailingSize -gt $Script:PaquetBuilderMaximumRuntimeMetadataBytes) { throw 'The Paquet Builder GP package configuration exceeds the configured limit.' }
  $Encoded = Read-BinaryBytes -Stream $Stream -Offset $Runtime.TrailingOffset -Count ([int]$Runtime.TrailingSize)
  $Container = ConvertFrom-PaquetBuilderPackageCipher -Bytes $Encoded
  if ($Container[0] -ne 0x47 -or $Container[1] -ne 0x50) { throw 'The Paquet Builder GP package-configuration magic is invalid.' }

  $HeaderSize = 15
  $UncompressedSize = [long][BitConverter]::ToUInt32($Container, 2)
  $CompressedSize = [long]$Container.Length - $HeaderSize
  if ($UncompressedSize -le 0 -or $UncompressedSize -gt $Script:PaquetBuilderMaximumRuntimeMetadataBytes -or $CompressedSize -le 0) { throw 'The Paquet Builder GP package-configuration bounds are invalid.' }

  $Properties = [byte[]]$Container[10..14]
  $CompressedInput = [IO.MemoryStream]::new($Container, $false)
  $CompressedInput.Position = $HeaderSize
  $Output = [IO.MemoryStream]::new([int]$UncompressedSize)
  $Decoder = $null
  try {
    # This frame declares its output size and has no LZMA end marker. Copy exactly
    # that output instead of probing for another byte, which SharpCompress treats
    # as a request to decode beyond the package's range-coder termination bytes.
    $Decoder = New-InstallerDecompressionStream -Algorithm Lzma -Stream $CompressedInput -Properties $Properties -CompressedSize $CompressedSize -UncompressedSize $UncompressedSize -LeaveOpen
    $null = Copy-BoundedStream -Source $Decoder -Destination $Output -MaximumBytes $UncompressedSize -ExpectedBytes $UncompressedSize
    $DecoderBytesRead = $CompressedInput.Position - $HeaderSize
    $DecoderTrailingBytes = $CompressedSize - $DecoderBytesRead
    if ($DecoderBytesRead -le 0 -or $DecoderTrailingBytes -lt 0 -or $DecoderTrailingBytes -gt 8) { throw 'The Paquet Builder GP package decoder did not consume a valid bounded LZMA frame.' }
    $DecodedBytes = $Output.ToArray()
  } finally {
    if ($Decoder) { $Decoder.Dispose() }
    $Output.Dispose()
    $CompressedInput.Dispose()
  }

  $Resources = @(Read-PaquetBuilderPackageResourceTable -Bytes $DecodedBytes)
  $ScriptResource = @($Resources | Where-Object Name -IEQ 'GINFOS')
  if ($ScriptResource.Count -ne 1) { throw 'The Paquet Builder GP package does not contain one unambiguous GINFOS program.' }
  $Encoding = [Text.Encoding]::GetEncoding(1252)
  $ScriptProgram = Read-PaquetBuilderScriptProgram -Text $Encoding.GetString($ScriptResource[0].Content)
  $TextResources = [ordered]@{}
  foreach ($Name in @('GFICHS', 'GSTRINGS', 'GTABLE')) {
    $Resource = @($Resources | Where-Object Name -IEQ $Name)[0]
    if ($Resource) { $TextResources[$Name] = $Encoding.GetString($Resource.Content) }
  }

  [pscustomobject][ordered]@{
    Format                    = 'GP-LZMA'
    EncodedOffset             = [long]$Runtime.TrailingOffset
    EncodedSize               = [long]$Runtime.TrailingSize
    HeaderSize                = $HeaderSize
    CompressedSize            = $CompressedSize
    UncompressedSize          = $UncompressedSize
    ExpectedCrc32             = $null
    ActualCrc32               = [uint32](Get-BinaryCrc32 -Bytes $DecodedBytes)
    ExpectedCompressedCrc32   = $null
    ExpectedUncompressedCrc32 = $null
    DecoderBytesRead          = $DecoderBytesRead
    DecoderPaddingBytes       = $null
    DecoderTrailingBytes      = $DecoderTrailingBytes
    ObservedField             = [uint32][BitConverter]::ToUInt32($Container, 6)
    LzmaProperties            = $Properties
    IsDecoded                 = $true
    Resources                 = $Resources
    ScriptProgram             = $ScriptProgram
    TextResources             = [pscustomobject]$TextResources
  }
}

function Read-PaquetBuilderClassicEnvelope {
  <#
  .SYNOPSIS
    Validate the Classic 2.6 envelope and decode its GPacker/LZHUF control block.
  .PARAMETER Stream
    Parser-owned seekable installer stream. Its position is restored.
  .PARAMETER OverlayOffset
    Absolute start of the PE overlay.
  #>
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$OverlayOffset
  )

  if ($OverlayOffset + 32 -gt $Stream.Length) { throw 'The Classic Paquet Builder envelope is truncated.' }
  $Header = Read-BinaryBytes -Stream $Stream -Offset $OverlayOffset -Count 32
  if ($Header[0] -ne 3 -or [Text.Encoding]::ASCII.GetString($Header, 20, 4) -cne '@GDG') { throw 'The Classic Paquet Builder envelope magic is invalid.' }
  $PackedBlockSize = [long][BitConverter]::ToUInt32($Header, 12)
  $UncompressedSize = [long][BitConverter]::ToUInt32($Header, 24)
  $ExpectedCrc32 = [uint32][BitConverter]::ToUInt32($Header, 28)
  if ($PackedBlockSize -le 12 -or $UncompressedSize -le 0 -or $UncompressedSize -gt $Script:PaquetBuilderMaximumClassicControlBytes) { throw 'The Classic Paquet Builder GPacker bounds are invalid.' }
  $ArchiveOffset = $OverlayOffset + 20 + $PackedBlockSize
  if ($ArchiveOffset -gt $Stream.Length) { throw 'The Classic Paquet Builder package offset is outside the installer.' }

  $CompressedSize = $PackedBlockSize - 12
  # The historical bit reader prefetches one byte beyond the encoded block. The
  # envelope remains authoritative for the following ZIP boundary.
  $MaximumDecodeBytes = [Math]::Min($CompressedSize + 1, $Stream.Length - ($OverlayOffset + 32))
  $Decoded = [Dumplings.PaquetBuilder.PaquetBuilderClassicDecoder]::Decode($Stream, $OverlayOffset + 32, $MaximumDecodeBytes, [int]$UncompressedSize)
  $ActualCrc32 = Get-BinaryCrc32 -Bytes $Decoded.Data
  if ($ActualCrc32 -ne $ExpectedCrc32) { throw ('The Classic Paquet Builder GPacker CRC32 is invalid: expected {0:X8}, got {1:X8}.' -f $ExpectedCrc32, $ActualCrc32) }
  if ($Decoded.BytesConsumed -gt $CompressedSize + 1) { throw 'The Classic Paquet Builder GPacker decoder crossed the declared block boundary.' }

  [pscustomobject][ordered]@{
    EnvelopeOffset      = $OverlayOffset
    EnvelopeVersion     = [int]$Header[0]
    PackedBlockOffset   = $OverlayOffset + 20
    PackedBlockSize     = $PackedBlockSize
    CompressedOffset    = $OverlayOffset + 32
    CompressedSize      = $CompressedSize
    DecoderBytesRead    = [long]$Decoded.BytesConsumed
    UncompressedSize    = $UncompressedSize
    ExpectedCrc32       = $ExpectedCrc32
    ArchiveOffset       = $ArchiveOffset
    ControlBytes        = $Decoded.Data
    ObservedPrefix      = [Convert]::ToHexString($Header[1..11])
    ObservedTrailerWord = [BitConverter]::ToUInt32($Header, 16)
  }
}

function Read-PaquetBuilderClassicShortString {
  <#
  .SYNOPSIS
    Decode one fixed-width Windows-1252 short-string field from a Classic controller record.
  .PARAMETER Bytes
    Complete decompressed controller record.
  .PARAMETER Offset
    Record-relative offset of the one-byte string length.
  .PARAMETER FieldSize
    Total field width, including the length byte and zero padding.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ValidateRange(0, [int]::MaxValue)][int]$Offset,
    [Parameter(Mandatory)][ValidateRange(1, [int]::MaxValue)][int]$FieldSize
  )

  if ($Offset -gt $Bytes.Length - $FieldSize) { throw 'The Classic Paquet Builder short-string field is outside its record.' }
  $Length = [int]$Bytes[$Offset]
  if ($Length -gt $FieldSize - 1) { throw 'The Classic Paquet Builder short-string length exceeds its fixed field.' }
  if ($Length -eq 0) { return '' }
  return [Text.Encoding]::GetEncoding(1252).GetString($Bytes, $Offset + 1, $Length)
}

function Read-PaquetBuilderClassicFixedString {
  <#
  .SYNOPSIS
    Decode one fixed-width, null-terminated Windows-1252 controller field.
  .PARAMETER Bytes
    Complete decompressed controller record.
  .PARAMETER Offset
    Record-relative start of the fixed character buffer.
  .PARAMETER FieldSize
    Maximum byte width of the character buffer.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ValidateRange(0, [int]::MaxValue)][int]$Offset,
    [Parameter(Mandatory)][ValidateRange(1, [int]::MaxValue)][int]$FieldSize
  )

  if ($Offset -gt $Bytes.Length - $FieldSize) { throw 'The Classic Paquet Builder fixed string is outside its record.' }
  $Length = 0
  while ($Length -lt $FieldSize -and $Bytes[$Offset + $Length] -ne 0) { $Length++ }
  if ($Length -eq 0) { return '' }
  return [Text.Encoding]::GetEncoding(1252).GetString($Bytes, $Offset, $Length)
}

function Read-PaquetBuilderClassicControllerCatalog {
  <#
  .SYNOPSIS
    Decode the zlib record catalog appended to the packed GInstall controller used by Classic Paquet Builder media.
  .PARAMETER Stream
    Parser-owned seekable stream for SETUP.EXE. Its position is restored by bounded reads and it is not disposed.
  #>
  param ([Parameter(Mandatory)][IO.Stream]$Stream)

  if (-not $Stream.CanSeek) { throw 'The Classic Paquet Builder controller requires a seekable stream.' }
  $Layout = Get-PELayout -Stream $Stream
  $CatalogOffset = [long]$Layout.SizeOfHeaders
  foreach ($Section in $Layout.Sections) { $CatalogOffset = [Math]::Max($CatalogOffset, [long]$Section.RawOffset + [long]$Section.RawSize) }
  if ($CatalogOffset -lt 0 -or $CatalogOffset + 22 -gt $Stream.Length) { throw 'The Classic Paquet Builder controller catalog is outside the packed executable.' }

  $CatalogLength = $Stream.Length - $CatalogOffset
  if ($CatalogLength -gt $Script:PaquetBuilderMaximumClassicControlBytes) { throw 'The Classic Paquet Builder controller catalog exceeds the configured limit.' }
  $CatalogBytes = Read-BinaryBytes -Stream $Stream -Offset $CatalogOffset -Count ([int]$CatalogLength)
  if ([Text.Encoding]::ASCII.GetString($CatalogBytes, 0, 5) -cne 'gw2sc' -or $CatalogBytes[5] -ne 0x1C) { throw 'The Classic Paquet Builder packed-controller marker is invalid.' }

  $Records = [Collections.Generic.List[object]]::new()
  $Cursor = 6
  $CandidateCount = 0
  $ExpandedTotal = 0L
  while ($Cursor + 18 -le $CatalogBytes.Length) {
    # A record has a 16-byte descriptor immediately followed by an RFC 1950 zlib member.
    if ($CatalogBytes[$Cursor + 16] -ne 0x78) { $Cursor++; continue }
    $CompressionMethod = $CatalogBytes[$Cursor + 16]
    $CompressionFlags = $CatalogBytes[$Cursor + 17]
    if (($CompressionMethod -band 0x0F) -ne 8 -or (([int]$CompressionMethod * 256 + [int]$CompressionFlags) % 31) -ne 0) { $Cursor++; continue }

    $CandidateCount++
    if ($CandidateCount -gt $Script:PaquetBuilderMaximumClassicRecordCount) { throw 'The Classic Paquet Builder controller exceeds the record-candidate limit.' }
    $CompressedSize = [long][BitConverter]::ToUInt32($CatalogBytes, $Cursor + 4)
    $UncompressedSize = [long][BitConverter]::ToUInt32($CatalogBytes, $Cursor + 8)
    $ExpectedAdler32 = [uint32][BitConverter]::ToUInt32($CatalogBytes, $Cursor + 12)
    $DataOffset = $Cursor + 16
    if ($CompressedSize -lt 6 -or $UncompressedSize -le 0 -or $UncompressedSize -gt $Script:PaquetBuilderMaximumClassicControlBytes -or $CompressedSize -gt $CatalogBytes.Length - $DataOffset) { $Cursor++; continue }

    # The descriptor repeats the zlib trailer checksum in little-endian form. Checking it before decompression rejects incidental 78xx byte sequences cheaply.
    $FooterOffset = $DataOffset + [int]$CompressedSize - 4
    $FooterAdler32 = [uint32](([uint32]$CatalogBytes[$FooterOffset] -shl 24) -bor ([uint32]$CatalogBytes[$FooterOffset + 1] -shl 16) -bor ([uint32]$CatalogBytes[$FooterOffset + 2] -shl 8) -bor [uint32]$CatalogBytes[$FooterOffset + 3])
    if ($FooterAdler32 -ne $ExpectedAdler32) { $Cursor++; continue }
    if ($UncompressedSize -gt $Script:PaquetBuilderMaximumClassicControlBytes - $ExpandedTotal) { throw 'The Classic Paquet Builder controller exceeds the aggregate expanded-record limit.' }

    $Compressed = [IO.MemoryStream]::new($CatalogBytes, $DataOffset, [int]$CompressedSize, $false)
    $Output = [IO.MemoryStream]::new([int]$UncompressedSize)
    try {
      $ActualSize = Expand-InstallerCompressedStream -Algorithm Zlib -Stream $Compressed -Destination $Output -MaximumBytes $UncompressedSize -CompressedSize $CompressedSize -UncompressedSize $UncompressedSize
      if ($ActualSize -ne $UncompressedSize) { throw 'A Classic Paquet Builder controller record has an unexpected expanded size.' }
      $RecordBytes = $Output.ToArray()
    } catch {
      $Cursor++
      continue
    } finally {
      $Output.Dispose()
      $Compressed.Dispose()
    }

    $Records.Add([pscustomobject][ordered]@{
        Index            = $Records.Count
        HeaderOffset     = $CatalogOffset + $Cursor
        ObservedTag      = [uint32][BitConverter]::ToUInt32($CatalogBytes, $Cursor)
        CompressedOffset = $CatalogOffset + $DataOffset
        CompressedSize   = $CompressedSize
        UncompressedSize = $UncompressedSize
        Adler32          = $ExpectedAdler32
        Bytes            = $RecordBytes
      })
    $ExpandedTotal += $UncompressedSize
    $Cursor = $DataOffset + [int]$CompressedSize
  }

  if ($Records.Count -lt 3 -or $Records[0].HeaderOffset -ne $CatalogOffset + 6) { throw 'The Classic Paquet Builder controller contains no complete leading metadata record set.' }
  $General = $Records[0].Bytes
  if ($General.Length -ne 494) { throw 'The Classic Paquet Builder general record has an unsupported layout.' }
  $Counts = [ordered]@{
    Directory = [int][BitConverter]::ToUInt32($General, 448)
    File      = [int][BitConverter]::ToUInt32($General, 452)
    Shortcut  = [int][BitConverter]::ToUInt32($General, 456)
    Unknown   = [int][BitConverter]::ToUInt32($General, 460)
    Registry  = [int][BitConverter]::ToUInt32($General, 464)
    Auxiliary = [int][BitConverter]::ToUInt32($General, 468)
    Execution = [int][BitConverter]::ToUInt32($General, 472)
  }
  $ExpectedRecordCount = 3 + ($Counts.Values | Measure-Object -Sum).Sum
  if ($ExpectedRecordCount -gt $Script:PaquetBuilderMaximumClassicRecordCount -or $Records.Count -lt $ExpectedRecordCount) { throw 'The Classic Paquet Builder controller record counts exceed the validated catalog.' }

  $Metadata = [pscustomobject][ordered]@{
    SetupTitle           = Read-PaquetBuilderClassicShortString -Bytes $General -Offset 0 -FieldSize 64
    ApplicationName      = Read-PaquetBuilderClassicShortString -Bytes $General -Offset 64 -FieldSize 64
    ApplicationTitle     = Read-PaquetBuilderClassicShortString -Bytes $General -Offset 128 -FieldSize 64
    Copyright            = Read-PaquetBuilderClassicShortString -Bytes $General -Offset 192 -FieldSize 64
    ProductName          = Read-PaquetBuilderClassicShortString -Bytes $General -Offset 256 -FieldSize 64
    DisplayVersion       = Read-PaquetBuilderClassicShortString -Bytes $General -Offset 320 -FieldSize 64
    UninstallDisplayName = Read-PaquetBuilderClassicShortString -Bytes $General -Offset 384 -FieldSize 64
    Counts               = [pscustomobject]$Counts
    LicenseTextSize      = [uint32][BitConverter]::ToUInt32($General, 476)
    DescriptionTextSize  = [uint32][BitConverter]::ToUInt32($General, 480)
    ObservedFlags        = [Convert]::ToHexString($General[484..493])
  }

  $Index = 3
  $Directories = [Collections.Generic.List[object]]::new()
  for ($Item = 0; $Item -lt $Counts.Directory; $Item++, $Index++) {
    $Bytes = $Records[$Index].Bytes
    if ($Bytes.Length -ne 49) { throw 'A Classic Paquet Builder directory record has an unsupported layout.' }
    $Directories.Add([pscustomobject][ordered]@{ Destination = Read-PaquetBuilderClassicShortString -Bytes $Bytes -Offset 0 -FieldSize 49; EvidenceRecord = $Records[$Index].Index })
  }

  $Files = [Collections.Generic.List[object]]::new()
  for ($Item = 0; $Item -lt $Counts.File; $Item++, $Index++) {
    $Bytes = $Records[$Index].Bytes
    if ($Bytes.Length -ne 95) { throw 'A Classic Paquet Builder file record has an unsupported layout.' }
    $Files.Add([pscustomobject][ordered]@{
        Index              = $Item
        Destination        = Read-PaquetBuilderClassicShortString -Bytes $Bytes -Offset 0 -FieldSize 65
        ObservedTimestamp  = [Convert]::ToHexString($Bytes[65..72])
        ObservedAttributes = [Convert]::ToHexString($Bytes[73..79])
        UncompressedSize   = [long][BitConverter]::ToUInt32($Bytes, 80)
        CompressedSize     = [long][BitConverter]::ToUInt32($Bytes, 84)
        Adler32            = [uint32][BitConverter]::ToUInt32($Bytes, 88)
        ObservedFlags      = [Convert]::ToHexString($Bytes[92..94])
        EvidenceRecord     = $Records[$Index].Index
      })
  }

  $Shortcuts = [Collections.Generic.List[object]]::new()
  for ($Item = 0; $Item -lt $Counts.Shortcut; $Item++, $Index++) {
    $Bytes = $Records[$Index].Bytes
    if ($Bytes.Length -ne 356) { throw 'A Classic Paquet Builder shortcut record has an unsupported layout.' }
    $Shortcuts.Add([pscustomobject][ordered]@{
        ShortcutPath   = Read-PaquetBuilderClassicShortString -Bytes $Bytes -Offset 0 -FieldSize 48
        TargetPath     = Read-PaquetBuilderClassicShortString -Bytes $Bytes -Offset 48 -FieldSize 128
        ObservedFields = [Convert]::ToHexString($Bytes[176..355])
        EvidenceRecord = $Records[$Index].Index
      })
  }

  $UnknownRecords = [Collections.Generic.List[object]]::new()
  for ($Item = 0; $Item -lt $Counts.Unknown; $Item++, $Index++) { $UnknownRecords.Add($Records[$Index]) }

  $RegistryWrites = [Collections.Generic.List[object]]::new()
  for ($Item = 0; $Item -lt $Counts.Registry; $Item++, $Index++) {
    $Bytes = $Records[$Index].Bytes
    if ($Bytes.Length -ne 438) { throw 'A Classic Paquet Builder registry record has an unsupported layout.' }
    $RootValue = [uint32][BitConverter]::ToUInt32($Bytes, 0)
    $Root = if ($RootValue -eq 2147483648) { 'HKCR' } elseif ($RootValue -eq 2147483649) { 'HKCU' } elseif ($RootValue -eq 2147483650) { 'HKLM' } else { $null }
    $RegistryWrites.Add([pscustomobject][ordered]@{
        Root           = $Root
        Key            = Read-PaquetBuilderClassicFixedString -Bytes $Bytes -Offset 4 -FieldSize 128
        Name           = Read-PaquetBuilderClassicFixedString -Bytes $Bytes -Offset 132 -FieldSize 48
        Value          = Read-PaquetBuilderClassicFixedString -Bytes $Bytes -Offset 180 -FieldSize 256
        Type           = 'String'
        RootValue      = $RootValue
        ObservedFlags  = [Convert]::ToHexString($Bytes[436..437])
        EvidenceRecord = $Records[$Index].Index
      })
  }

  $AuxiliaryPaths = [Collections.Generic.List[object]]::new()
  for ($Item = 0; $Item -lt $Counts.Auxiliary; $Item++, $Index++) {
    $Bytes = $Records[$Index].Bytes
    if ($Bytes.Length -ne 64) { throw 'A Classic Paquet Builder auxiliary path record has an unsupported layout.' }
    $AuxiliaryPaths.Add([pscustomobject][ordered]@{ Path = Read-PaquetBuilderClassicShortString -Bytes $Bytes -Offset 0 -FieldSize 64; EvidenceRecord = $Records[$Index].Index })
  }

  $ExecutedPayloads = [Collections.Generic.List[object]]::new()
  for ($Item = 0; $Item -lt $Counts.Execution; $Item++, $Index++) {
    $Bytes = $Records[$Index].Bytes
    if ($Bytes.Length -ne 193) { throw 'A Classic Paquet Builder execution record has an unsupported layout.' }
    $ExecutedPayloads.Add([pscustomobject][ordered]@{
        Path           = Read-PaquetBuilderClassicShortString -Bytes $Bytes -Offset 0 -FieldSize 64
        Arguments      = Read-PaquetBuilderClassicShortString -Bytes $Bytes -Offset 64 -FieldSize 64
        WorkingPath    = Read-PaquetBuilderClassicShortString -Bytes $Bytes -Offset 128 -FieldSize 64
        ObservedFlags  = [Convert]::ToHexString($Bytes[192..192])
        EvidenceRecord = $Records[$Index].Index
      })
  }

  [pscustomobject][ordered]@{
    Format              = 'GInstallPackedController'
    CatalogOffset       = $CatalogOffset
    CatalogLength       = $CatalogLength
    Metadata            = $Metadata
    Directories         = $Directories.ToArray()
    Files               = $Files.ToArray()
    Shortcuts           = $Shortcuts.ToArray()
    RegistryWrites      = $RegistryWrites.ToArray()
    AuxiliaryPaths      = $AuxiliaryPaths.ToArray()
    ExecutedPayloads    = $ExecutedPayloads.ToArray()
    UnknownRecords      = $UnknownRecords.ToArray()
    AdditionalRecords   = @($Records | Select-Object -Skip $ExpectedRecordCount)
    RecordCount         = $Records.Count
    ExpandedRecordBytes = $ExpandedTotal
  }
}

function Read-PaquetBuilderClassicGafCatalog {
  <#
  .SYNOPSIS
    Correlate Classic controller file descriptors with sequential GAF zlib members.
  .PARAMETER Stream
    Parser-owned seekable SETUP*.GAF stream. It is not disposed.
  .PARAMETER ControllerCatalog
    Validated controller catalog containing the ordered file descriptors.
  #>
  param ([Parameter(Mandatory)][IO.Stream]$Stream, [Parameter(Mandatory)]$ControllerCatalog)

  if (-not $Stream.CanSeek) { throw 'The Classic Paquet Builder GAF catalog requires a seekable stream.' }
  if ($Stream.Length -lt 10) { throw 'The Classic Paquet Builder GAF stream is truncated.' }
  $PackageHeader = Read-BinaryBytes -Stream $Stream -Offset 0 -Count 10
  if ([Convert]::ToHexString($PackageHeader[0..5]) -cne '4741466E641C' -or [long][BitConverter]::ToUInt32($PackageHeader, 6) -ne $Stream.Length) { throw 'The Classic Paquet Builder GAF package header is invalid.' }
  $Files = [Collections.Generic.List[object]]::new()
  $Offset = 10L
  foreach ($Descriptor in $ControllerCatalog.Files) {
    if ($Offset + 10 -gt $Stream.Length -or $Descriptor.CompressedSize -lt 6 -or $Descriptor.CompressedSize -gt $Stream.Length - $Offset - 4) { throw 'A Classic Paquet Builder GAF member exceeds the package stream.' }
    $Magic = Read-BinaryBytes -Stream $Stream -Offset $Offset -Count 4
    if ([Convert]::ToHexString($Magic) -cne '4741461C') { throw 'A Classic Paquet Builder GAF member magic is invalid.' }
    $ZlibHeader = Read-BinaryBytes -Stream $Stream -Offset ($Offset + 4) -Count 2
    if (($ZlibHeader[0] -band 0x0F) -ne 8 -or (([int]$ZlibHeader[0] * 256 + [int]$ZlibHeader[1]) % 31) -ne 0) { throw 'A Classic Paquet Builder GAF member has an invalid zlib header.' }
    $Footer = Read-BinaryBytes -Stream $Stream -Offset ($Offset + 4 + $Descriptor.CompressedSize - 4) -Count 4
    $FooterAdler32 = [uint32](([uint32]$Footer[0] -shl 24) -bor ([uint32]$Footer[1] -shl 16) -bor ([uint32]$Footer[2] -shl 8) -bor [uint32]$Footer[3])
    if ($FooterAdler32 -ne $Descriptor.Adler32) { throw 'A Classic Paquet Builder GAF member does not match its controller checksum.' }
    $Files.Add([pscustomobject][ordered]@{
        Index              = $Descriptor.Index
        Destination        = $Descriptor.Destination
        GafRecordOffset    = $Offset
        CompressedOffset   = $Offset + 4
        CompressedSize     = $Descriptor.CompressedSize
        UncompressedSize   = $Descriptor.UncompressedSize
        Adler32            = $Descriptor.Adler32
        ObservedTimestamp  = $Descriptor.ObservedTimestamp
        ObservedAttributes = $Descriptor.ObservedAttributes
        ObservedFlags      = $Descriptor.ObservedFlags
      })
    $Offset += 4 + $Descriptor.CompressedSize
  }
  if ($Offset -ne $Stream.Length) { throw 'The Classic Paquet Builder GAF stream contains bytes outside the declared file table.' }
  return $Files.ToArray()
}

function ConvertFrom-PaquetBuilderClassicDestination {
  <#
  .SYNOPSIS
    Convert a Classic destination variable to a safe extraction-relative path.
  .PARAMETER Destination
    Source-backed destination such as {app}\file.exe or {win}\file.dll.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][string]$Destination)

  if ($Destination -notmatch '^\{(?<Root>[A-Za-z0-9_]+)\}[\\/](?<Path>.+)$') { throw "Unsupported Classic Paquet Builder destination '$Destination'." }
  $Root = $Matches.Root.ToLowerInvariant()
  $RelativePath = $Matches.Path -replace '/', '\'
  if ($Root -eq 'app') { return $RelativePath }
  return Join-Path (Join-Path '_destinations' $Root) $RelativePath
}

function Get-PaquetBuilderRequestedExecutionLevel {
  <#
  .SYNOPSIS
    Read requestedExecutionLevel from already-enumerated PE resources.
  .PARAMETER Stream
    Parser-owned installer stream.
  .PARAMETER Resources
    PE resource catalog from the same stream.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][IO.Stream]$Stream, [Parameter(Mandatory)][object[]]$Resources)

  $Manifest = @($Resources | Where-Object { $_.TypeId -eq 24 -and $_.Id -eq 1 })[0]
  if (-not $Manifest -or $Manifest.Size -gt 1048576) { return $null }
  $Bytes = Read-PaquetBuilderResourceData -Stream $Stream -Resource $Manifest -MaximumBytes 1048576
  $Text = if ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFF -and $Bytes[1] -eq 0xFE) { [Text.Encoding]::Unicode.GetString($Bytes, 2, $Bytes.Length - 2) } else { [Text.Encoding]::UTF8.GetString($Bytes).TrimStart([char]0xFEFF) }
  $Match = [regex]::Match($Text, 'requestedExecutionLevel[^>]+level\s*=\s*["''](?<Level>asInvoker|highestAvailable|requireAdministrator)["'']', 'IgnoreCase')
  if ($Match.Success) { return $Match.Groups['Level'].Value }
  return $null
}

function Get-PaquetBuilderPeScriptEvidence {
  <#
  .SYNOPSIS
    Recover literal PBCore.SetVar calls and uninstall-key identities from mapped PE bytes.
  .DESCRIPTION
    Only PE headers and file-backed sections are materialized. The potentially large installer overlay is excluded.
  .PARAMETER Stream
    Parser-owned installer stream. Its position is restored.
  .PARAMETER Layout
    Parsed PE layout for Stream.
  #>
  param ([Parameter(Mandatory)][IO.Stream]$Stream, [Parameter(Mandatory)]$Layout)

  $MappedLength = [long]$Layout.SizeOfHeaders
  foreach ($Section in $Layout.Sections) { $MappedLength = [Math]::Max($MappedLength, [long]$Section.RawOffset + [long]$Section.RawSize) }
  if ($MappedLength -le 0 -or $MappedLength -gt $Script:PaquetBuilderMaximumMappedPeBytes -or $MappedLength -gt $Stream.Length) {
    throw "The mapped Paquet Builder PE exceeds the $($Script:PaquetBuilderMaximumMappedPeBytes)-byte analysis limit."
  }

  $Image = Read-BinaryBytes -Stream $Stream -Offset 0 -Count ([int]$MappedLength)
  $ExecutableSectionIndexes = [Collections.Generic.List[uint32]]::new()
  for ($Index = 0; $Index -lt $Layout.Sections.Count; $Index++) {
    if (([uint32]$Layout.Sections[$Index].Characteristics -band 0x20000000) -ne 0) { $ExecutableSectionIndexes.Add([uint32]$Index) }
  }
  $Import = $Layout.DataDirectories['Import']
  $DelayImport = $Layout.DataDirectories['DelayImport']
  $Evidence = [Dumplings.PaquetBuilder.PaquetBuilderPeScanner]::Scan(
    $Image,
    [uint64]$Layout.ImageBase,
    ($Layout.OptionalHeaderFormat -eq 'PE32+'),
    [uint32]$Layout.SizeOfHeaders,
    [uint32[]]@($Layout.Sections.VirtualAddress),
    [uint32[]]@($Layout.Sections.VirtualSize),
    [uint32[]]@($Layout.Sections.RawOffset),
    [uint32[]]@($Layout.Sections.RawSize),
    [uint32]$Import.Rva,
    [uint32]$Import.Size,
    [uint32]$DelayImport.Rva,
    [uint32]$DelayImport.Size,
    $ExecutableSectionIndexes.ToArray())

  [pscustomobject]@{
    MappedBytes           = $Image
    SetVarImportFound     = [bool]$Evidence.SetVarImportFound
    Assignments           = @($Evidence.Assignments)
    UninstallProductCodes = [string[]]@($Evidence.UninstallProductCodes)
  }
}

function Get-PaquetBuilderAdler32 {
  <#
  .SYNOPSIS
    Calculate the Adler-32 value used by a Paquet Builder UPX wrapper.
  .PARAMETER Bytes
    Bounded compressed or expanded byte array to checksum.
  #>
  [OutputType([uint32])]
  param ([Parameter(Mandatory)][byte[]]$Bytes)

  [uint32]$First = 1
  [uint32]$Second = 0
  foreach ($Byte in $Bytes) {
    $First = ($First + $Byte) % 65521
    $Second = ($Second + $First) % 65521
  }
  return [uint32](($Second -shl 16) -bor $First)
}

function Get-PaquetBuilderUpxPeScriptEvidence {
  <#
  .SYNOPSIS
    Reconstruct the bounded PE image carried by an older UPX/LZMA Paquet Builder launcher.
  .DESCRIPTION
    Paquet Builder 3.0 and 3.2 compress the launcher sections that contain PBCore.SetVar calls. This routine accepts only the observed UPX 13 Win32/LZMA header, validates both Adler-32 values, rebuilds file-backed PE sections in memory, and passes that image to the normal native-evidence scanner. It does not execute the UPX stub or depend on an external unpacker.
  .PARAMETER Stream
    Parser-owned stream for the packed installer. Its position is restored by shared binary helpers.
  .PARAMETER Layout
    Parsed layout of the packed outer PE.
  #>
  param ([Parameter(Mandatory)][IO.Stream]$Stream, [Parameter(Mandatory)]$Layout)

  $SectionNames = @($Layout.Sections.Name)
  if ($SectionNames -inotcontains 'UPX0' -or $SectionNames -inotcontains 'UPX1') { return $null }

  $MappedLength = [long]$Layout.SizeOfHeaders
  foreach ($Section in $Layout.Sections) { $MappedLength = [Math]::Max($MappedLength, [long]$Section.RawOffset + [long]$Section.RawSize) }
  $SearchLength = [Math]::Min($MappedLength, [long]$Script:PaquetBuilderMaximumUpxHeaderSearchBytes)
  $HeaderOffsets = @(Find-BinaryPattern -Stream $Stream -Pattern ([Text.Encoding]::ASCII.GetBytes('UPX!')) -StartOffset 0 -Length $SearchLength -Maximum 8)

  foreach ($HeaderOffset in $HeaderOffsets) {
    if ($HeaderOffset + 32 -gt $Stream.Length) { continue }
    $Header = Read-BinaryBytes -Stream $Stream -Offset $HeaderOffset -Count 32

    # Version 13, format 9, and method 14 identify the observed Win32 PE/LZMA framing. Accept later header versions only when the same fixed 32-byte fields remain valid.
    $HeaderVersion = [int]$Header[4]
    $Format = [int]$Header[5]
    $Method = [int]$Header[6]
    if ($HeaderVersion -lt 10 -or $HeaderVersion -eq 0xFF -or $Format -ne 9 -or $Method -ne 14) { continue }

    $Checksum = 0
    for ($Index = 4; $Index -lt 31; $Index++) { $Checksum += $Header[$Index] }
    if ([byte]($Checksum % 251) -ne $Header[31]) { continue }

    $ExpectedExpandedAdler32 = [uint32][BitConverter]::ToUInt32($Header, 8)
    $ExpectedCompressedAdler32 = [uint32][BitConverter]::ToUInt32($Header, 12)
    $ExpandedSize = [long][BitConverter]::ToUInt32($Header, 16)
    $CompressedSize = [long][BitConverter]::ToUInt32($Header, 20)
    $OriginalFileSize = [long][BitConverter]::ToUInt32($Header, 24)
    $CompressedOffset = $HeaderOffset + 32
    if ($ExpandedSize -lt 64 -or $ExpandedSize -gt $Script:PaquetBuilderMaximumMappedPeBytes -or $CompressedSize -lt 3 -or $CompressedSize -gt $ExpandedSize -or $CompressedOffset + $CompressedSize -gt $MappedLength) {
      throw 'The Paquet Builder UPX header declares invalid or unbounded image sizes.'
    }

    $CompressedBytes = Read-BinaryBytes -Stream $Stream -Offset $CompressedOffset -Count ([int]$CompressedSize)
    if ((Get-PaquetBuilderAdler32 -Bytes $CompressedBytes) -ne $ExpectedCompressedAdler32) { throw 'The Paquet Builder UPX compressed image fails its Adler-32 check.' }

    # UPX stores pb in byte zero and lp/lc in byte one. Convert those two bytes into the ordinary five-byte LZMA property block accepted by the shared decoder. UPX omits a dictionary size because its stub decodes into the complete image buffer; the bounded expanded size is an equivalent upper bound here.
    $PositionBits = $CompressedBytes[0] -band 7
    $LiteralPositionBits = $CompressedBytes[1] -shr 4
    $LiteralContextBits = $CompressedBytes[1] -band 15
    if ($PositionBits -ge 5 -or $LiteralPositionBits -ge 5 -or $LiteralContextBits -ge 9 -or ($CompressedBytes[0] -shr 3) -ne $LiteralPositionBits + $LiteralContextBits) {
      throw 'The Paquet Builder UPX image contains invalid LZMA properties.'
    }
    $Properties = [byte[]]::new(5)
    $Properties[0] = [byte](($PositionBits * 5 + $LiteralPositionBits) * 9 + $LiteralContextBits)
    [BitConverter]::GetBytes([uint32]$ExpandedSize).CopyTo($Properties, 1)

    $CompressedStream = [IO.MemoryStream]::new($CompressedBytes, 2, $CompressedBytes.Length - 2, $false, $true)
    $ExpandedStream = [IO.MemoryStream]::new([int]$ExpandedSize)
    try {
      $null = Expand-InstallerCompressedStream -Algorithm Lzma -Stream $CompressedStream -Destination $ExpandedStream -MaximumBytes $ExpandedSize -Properties $Properties -CompressedSize ($CompressedSize - 2) -UncompressedSize $ExpandedSize
      $ExpandedBytes = $ExpandedStream.ToArray()
    } finally {
      $ExpandedStream.Dispose()
      $CompressedStream.Dispose()
    }
    if ((Get-PaquetBuilderAdler32 -Bytes $ExpandedBytes) -ne $ExpectedExpandedAdler32) { throw 'The Paquet Builder UPX expanded image fails its Adler-32 check.' }

    # The expanded buffer is a virtual image followed by the original PE header and section table. Its final UInt32 points to that header. Rebuild only file-backed PE data; the large installer overlay stays outside this temporary image.
    $OriginalHeaderOffset = [long][BitConverter]::ToUInt32($ExpandedBytes, $ExpandedBytes.Length - 4)
    if ($OriginalHeaderOffset -lt 0 -or $OriginalHeaderOffset + 24 -gt $ExpandedBytes.Length - 4 -or [BitConverter]::ToUInt32($ExpandedBytes, [int]$OriginalHeaderOffset) -ne 0x00004550) {
      throw 'The Paquet Builder UPX image does not contain a bounded original PE header.'
    }
    $SectionCount = [int][BitConverter]::ToUInt16($ExpandedBytes, [int]$OriginalHeaderOffset + 6)
    $OptionalHeaderSize = [int][BitConverter]::ToUInt16($ExpandedBytes, [int]$OriginalHeaderOffset + 20)
    if ($SectionCount -lt 1 -or $SectionCount -gt 96 -or $OptionalHeaderSize -lt 96 -or $OptionalHeaderSize -gt 512) { throw 'The Paquet Builder UPX image contains invalid PE header dimensions.' }
    $OriginalSectionTableOffset = [int]$OriginalHeaderOffset + 24 + $OptionalHeaderSize
    $OriginalHeaderLength = 24 + $OptionalHeaderSize + 40 * $SectionCount
    if ($OriginalHeaderOffset + $OriginalHeaderLength -gt $ExpandedBytes.Length - 4) { throw 'The Paquet Builder UPX original PE section table is truncated.' }

    # UPX filter 0x26 stores relative x86 CALL/JMP operands in big-endian form with the configured high-byte marker. Restore that bounded code range before the normal instruction scanner follows call sites. No other filter is accepted on this independently verified route.
    $Filter = [int]$Header[28]
    if ($Filter -ne 0 -and $Filter -ne 0x26) { throw "The Paquet Builder UPX image uses unsupported executable filter 0x$($Filter.ToString('X2'))." }
    if ($Filter -eq 0x26) {
      $SizeOfCode = [long][BitConverter]::ToUInt32($ExpandedBytes, [int]$OriginalHeaderOffset + 28)
      $BaseOfCode = [long][BitConverter]::ToUInt32($ExpandedBytes, [int]$OriginalHeaderOffset + 44)
      $FirstSectionVirtualAddressForFilter = [long][BitConverter]::ToUInt32($ExpandedBytes, $OriginalSectionTableOffset + 12)
      $CodeOffset = $BaseOfCode - $FirstSectionVirtualAddressForFilter
      if ($CodeOffset -lt 0 -or $SizeOfCode -lt 0 -or $CodeOffset + $SizeOfCode -gt $OriginalHeaderOffset) { throw 'The Paquet Builder UPX executable-filter range is outside the expanded image.' }
      [uint32]$FilterMarker = [uint32]$Header[29] -shl 24
      $CodeEnd = [int]($CodeOffset + $SizeOfCode - 5)
      for ($Cursor = [int]$CodeOffset; $Cursor -lt $CodeEnd; $Cursor++) {
        if ($ExpandedBytes[$Cursor] -notin 0xE8, 0xE9 -or $ExpandedBytes[$Cursor + 1] -ne $Header[29]) { continue }
        [uint32]$EncodedTarget = ([uint32]$ExpandedBytes[$Cursor + 1] -shl 24) -bor ([uint32]$ExpandedBytes[$Cursor + 2] -shl 16) -bor ([uint32]$ExpandedBytes[$Cursor + 3] -shl 8) -bor [uint32]$ExpandedBytes[$Cursor + 4]
        [uint32]$RelativeTarget = [uint32](([int64]$EncodedTarget - ($Cursor - $CodeOffset) - 1 - $CodeOffset - $FilterMarker) -band 0xFFFFFFFFL)
        [BitConverter]::GetBytes($RelativeTarget).CopyTo($ExpandedBytes, $Cursor + 1)
        $Cursor += 4
      }
    }

    # Relocatable UPX images keep absolute pointers as big-endian relative values and append a delta-coded relocation stream after the saved headers. Reapply only those declared fixups so delay-import descriptors, IAT operands, and literal arguments regain their original virtual addresses.
    $OptionalHeaderOffset = [int]$OriginalHeaderOffset + 24
    $OptionalHeaderMagic = [BitConverter]::ToUInt16($ExpandedBytes, $OptionalHeaderOffset)
    $DataDirectoryOffset = switch ($OptionalHeaderMagic) { 0x010B { $OptionalHeaderOffset + 96 }; 0x020B { $OptionalHeaderOffset + 112 }; default { throw 'The Paquet Builder UPX image uses an unsupported PE optional header.' } }
    $ImageBase = if ($OptionalHeaderMagic -eq 0x020B) { [uint64][BitConverter]::ToUInt64($ExpandedBytes, $OptionalHeaderOffset + 24) } else { [uint64][BitConverter]::ToUInt32($ExpandedBytes, $OptionalHeaderOffset + 28) }
    $ImportSize = [uint32][BitConverter]::ToUInt32($ExpandedBytes, $DataDirectoryOffset + 12)
    $RelocationRva = [uint32][BitConverter]::ToUInt32($ExpandedBytes, $DataDirectoryOffset + 40)
    $RelocationSize = [uint32][BitConverter]::ToUInt32($ExpandedBytes, $DataDirectoryOffset + 44)
    $CoffFlags = [uint16][BitConverter]::ToUInt16($ExpandedBytes, [int]$OriginalHeaderOffset + 22)
    $ExtraInfoOffset = $OriginalSectionTableOffset + 40 * $SectionCount
    if ($ImportSize -gt 20) { $ExtraInfoOffset += 8 }
    if ($RelocationRva -ne 0 -and $RelocationSize -gt 8 -and ($CoffFlags -band 1) -eq 0) {
      if ($ExtraInfoOffset + 5 -gt $ExpandedBytes.Length - 4) { throw 'The Paquet Builder UPX relocation metadata is truncated.' }
      $CompressedRelocationOffset = [long][BitConverter]::ToUInt32($ExpandedBytes, $ExtraInfoOffset)
      if ($CompressedRelocationOffset -lt 0 -or $CompressedRelocationOffset -ge $OriginalHeaderOffset) { throw 'The Paquet Builder UPX relocation stream is outside the expanded image.' }
      $RelocationCursor = [int]$CompressedRelocationOffset
      [long]$RelocationTarget = -4
      $RelocationCount = 0
      while ($true) {
        if ($RelocationCursor -ge $OriginalHeaderOffset) { throw 'The Paquet Builder UPX relocation stream is unterminated.' }
        $DeltaPrefix = [int]$ExpandedBytes[$RelocationCursor++]
        if ($DeltaPrefix -eq 0) { break }
        if ($DeltaPrefix -lt 0xF0) {
          $Delta = $DeltaPrefix
        } else {
          if ($RelocationCursor + 2 -gt $OriginalHeaderOffset) { throw 'The Paquet Builder UPX relocation delta is truncated.' }
          $Delta = (($DeltaPrefix -band 0x0F) -shl 16) + [BitConverter]::ToUInt16($ExpandedBytes, $RelocationCursor)
          $RelocationCursor += 2
          if ($Delta -eq 0) {
            if ($RelocationCursor + 4 -gt $OriginalHeaderOffset) { throw 'The Paquet Builder UPX extended relocation delta is truncated.' }
            $Delta = [long][BitConverter]::ToUInt32($ExpandedBytes, $RelocationCursor)
            $RelocationCursor += 4
          }
        }
        if ($Delta -lt 4) { throw 'The Paquet Builder UPX relocation stream contains overlapping fixups.' }
        $RelocationTarget += $Delta
        $PointerSize = $OptionalHeaderMagic -eq 0x020B ? 8 : 4
        if ($RelocationTarget -lt 0 -or $RelocationTarget + $PointerSize -gt $OriginalHeaderOffset) { throw 'A Paquet Builder UPX relocation points outside the expanded image.' }
        if ($PointerSize -eq 4) {
          [uint64]$RelativePointer = ([uint32]$ExpandedBytes[$RelocationTarget] -shl 24) -bor ([uint32]$ExpandedBytes[$RelocationTarget + 1] -shl 16) -bor ([uint32]$ExpandedBytes[$RelocationTarget + 2] -shl 8) -bor [uint32]$ExpandedBytes[$RelocationTarget + 3]
          [uint32]$AbsolutePointer = [uint32](($RelativePointer + $ImageBase + $FirstSectionVirtualAddressForFilter) -band 0xFFFFFFFFL)
          [BitConverter]::GetBytes($AbsolutePointer).CopyTo($ExpandedBytes, [int]$RelocationTarget)
        } else {
          [uint64]$RelativePointer64 = 0
          for ($ByteIndex = 0; $ByteIndex -lt 8; $ByteIndex++) { $RelativePointer64 = ($RelativePointer64 -shl 8) -bor $ExpandedBytes[$RelocationTarget + $ByteIndex] }
          [uint64]$AbsolutePointer64 = $RelativePointer64 + $ImageBase + [uint64]$FirstSectionVirtualAddressForFilter
          [BitConverter]::GetBytes($AbsolutePointer64).CopyTo($ExpandedBytes, [int]$RelocationTarget)
        }
        if (++$RelocationCount -gt 1048576) { throw 'The Paquet Builder UPX relocation count exceeds the parser limit.' }
      }
    }

    $DosHeader = Read-BinaryBytes -Stream $Stream -Offset 0 -Count 64
    $PeHeaderOffset = [long][BitConverter]::ToUInt32($DosHeader, 60)
    if ($PeHeaderOffset -lt 64 -or $PeHeaderOffset + $OriginalHeaderLength -gt $Script:PaquetBuilderMaximumMappedPeBytes) { throw 'The Paquet Builder UPX DOS header points outside the bounded image.' }

    $FirstSectionVirtualAddress = [long][BitConverter]::ToUInt32($ExpandedBytes, $OriginalSectionTableOffset + 12)
    $SyntheticLength = [Math]::Max($OriginalFileSize, $PeHeaderOffset + $OriginalHeaderLength)
    for ($Index = 0; $Index -lt $SectionCount; $Index++) {
      $SectionOffset = $OriginalSectionTableOffset + 40 * $Index
      $RawSize = [long][BitConverter]::ToUInt32($ExpandedBytes, $SectionOffset + 16)
      $RawOffset = [long][BitConverter]::ToUInt32($ExpandedBytes, $SectionOffset + 20)
      if ($RawOffset + $RawSize -gt $Script:PaquetBuilderMaximumMappedPeBytes) { throw 'A Paquet Builder UPX section exceeds the mapped-image limit.' }
      $SyntheticLength = [Math]::Max($SyntheticLength, $RawOffset + $RawSize)
    }
    if ($SyntheticLength -le 0 -or $SyntheticLength -gt $Script:PaquetBuilderMaximumMappedPeBytes) { throw 'The reconstructed Paquet Builder PE exceeds the mapped-image limit.' }

    $SyntheticImage = [byte[]]::new([int]$SyntheticLength)
    $DosStub = Read-BinaryBytes -Stream $Stream -Offset 0 -Count ([int]$PeHeaderOffset)
    [Array]::Copy($DosStub, 0, $SyntheticImage, 0, $DosStub.Length)
    [Array]::Copy($ExpandedBytes, [int]$OriginalHeaderOffset, $SyntheticImage, [int]$PeHeaderOffset, $OriginalHeaderLength)
    for ($Index = 0; $Index -lt $SectionCount; $Index++) {
      $SectionOffset = $OriginalSectionTableOffset + 40 * $Index
      $VirtualAddress = [long][BitConverter]::ToUInt32($ExpandedBytes, $SectionOffset + 12)
      $RawSize = [long][BitConverter]::ToUInt32($ExpandedBytes, $SectionOffset + 16)
      $RawOffset = [long][BitConverter]::ToUInt32($ExpandedBytes, $SectionOffset + 20)
      if ($RawSize -eq 0) { continue }
      $ExpandedSectionOffset = $VirtualAddress - $FirstSectionVirtualAddress
      if ($ExpandedSectionOffset -lt 0 -or $ExpandedSectionOffset + $RawSize -gt $OriginalHeaderOffset) { throw 'A Paquet Builder UPX section points outside the expanded virtual image.' }
      [Array]::Copy($ExpandedBytes, [int]$ExpandedSectionOffset, $SyntheticImage, [int]$RawOffset, [int]$RawSize)
    }

    $SyntheticStream = [IO.MemoryStream]::new($SyntheticImage, $false)
    try {
      $SyntheticLayout = Get-PELayout -Stream $SyntheticStream
      if (-not $SyntheticLayout) { throw 'The reconstructed Paquet Builder image is not a valid PE.' }
      $Evidence = Get-PaquetBuilderPeScriptEvidence -Stream $SyntheticStream -Layout $SyntheticLayout
    } finally {
      $SyntheticStream.Dispose()
    }
    $Evidence | Add-Member -NotePropertyName PackedPeInfo -NotePropertyValue ([pscustomobject][ordered]@{
        Format                    = 'UPX-LZMA'
        HeaderVersion             = $HeaderVersion
        HeaderOffset              = [long]$HeaderOffset
        CompressedOffset          = [long]$CompressedOffset
        CompressedSize            = $CompressedSize
        ExpandedSize              = $ExpandedSize
        OriginalFileSize          = $OriginalFileSize
        Filter                    = $Filter
        FilterMarker              = [int]$Header[29]
        ExpectedCompressedAdler32 = $ExpectedCompressedAdler32
        ExpectedExpandedAdler32   = $ExpectedExpandedAdler32
      })
    return $Evidence
  }
  return $null
}

function Read-PaquetBuilderRuntimeCatalog {
  <#
  .SYNOPSIS
    Decode the bounded metadata files in a modern Paquet Builder runtime archive.
  .PARAMETER Entries
    Normalized entries from Archive.
  #>
  param ([Parameter(Mandatory)][object[]]$Entries)

  $PropertyEntry = @($Entries | Where-Object FullName -IEQ 'pbfprop.dat')[0]
  $DialogEntry = @($Entries | Where-Object FullName -IEQ 'pbdlg.dat')[0]
  $LanguageEntry = @($Entries | Where-Object FullName -IEQ 'pblng.dat')[0]
  $RemoveEntry = @($Entries | Where-Object FullName -IEQ 'pbremove.dat')[0]
  $Records = [Collections.Generic.List[object]]::new()
  $MalformedPropertyCatalog = $false

  # pbfprop.dat stores exactly five CRLF-delimited values per packaged item.
  if ($PropertyEntry) {
    $Text = Read-InstallerArchiveEntryText -Entry $PropertyEntry -MaximumBytes $Script:PaquetBuilderMaximumRuntimeMetadataBytes -Encoding ([Text.UTF8Encoding]::new($false, $false))
    $Lines = [Collections.Generic.List[string]]::new()
    foreach ($Line in [regex]::Split($Text, '\r\n|\n|\r')) { $Lines.Add($Line) }
    while ($Lines.Count -gt 0 -and [string]::IsNullOrEmpty($Lines[$Lines.Count - 1])) { $Lines.RemoveAt($Lines.Count - 1) }
    if ($Lines.Count % 5 -ne 0) {
      $MalformedPropertyCatalog = $true
    } else {
      for ($Index = 0; $Index -lt $Lines.Count; $Index += 5) {
        $Flags = 0
        $HasFlags = [int]::TryParse($Lines[$Index + 4], [Globalization.NumberStyles]::Integer, [Globalization.CultureInfo]::InvariantCulture, [ref]$Flags)
        $Records.Add([pscustomobject][ordered]@{
            Path              = $Lines[$Index]
            ObservedField1    = $Lines[$Index + 1]
            ObservedField2    = $Lines[$Index + 2]
            ComponentVariable = $Lines[$Index + 3]
            Flags             = $HasFlags ? $Flags : $null
          })
      }
    }
  }

  # pblng.dat repeats a small [PBLang], language-name, LCID tuple.
  $Languages = [Collections.Generic.List[object]]::new()
  if ($LanguageEntry) {
    $LanguageText = Read-InstallerArchiveEntryText -Entry $LanguageEntry -MaximumBytes $Script:PaquetBuilderMaximumRuntimeMetadataBytes -Encoding ([Text.UTF8Encoding]::new($false, $false))
    $LanguageLines = [regex]::Split($LanguageText, '\r\n|\n|\r')
    for ($Index = 0; $Index + 2 -lt $LanguageLines.Count; $Index++) {
      if ($LanguageLines[$Index] -cne '[PBLang]') { continue }
      $Lcid = 0
      $null = [int]::TryParse($LanguageLines[$Index + 2], [ref]$Lcid)
      $Languages.Add([pscustomobject]@{ Name = $LanguageLines[$Index + 1]; Lcid = $Lcid })
      $Index += 2
    }
  }

  $Dialogs = [Collections.Generic.List[string]]::new()
  if ($DialogEntry) {
    $DialogText = Read-InstallerArchiveEntryText -Entry $DialogEntry -MaximumBytes $Script:PaquetBuilderMaximumRuntimeMetadataBytes -Encoding ([Text.UTF8Encoding]::new($false, $false))
    foreach ($Match in [regex]::Matches($DialogText, '(?m)^\[(?<Name>[^\]\r\n]+)\]\s*$')) { $Dialogs.Add($Match.Groups['Name'].Value) }
  }

  [pscustomobject][ordered]@{
    PropertyRecords          = $Records.ToArray()
    PropertyCatalogMalformed = $MalformedPropertyCatalog
    Languages                = $Languages.ToArray()
    Dialogs                  = [string[]]@($Dialogs | Select-Object -Unique)
    HasUninstallerTemplate   = [bool]$RemoveEntry
    UninstallerTemplateSize  = $RemoveEntry ? [long]$RemoveEntry.Length : 0L
  }
}

function Get-PaquetBuilderNestedMsiInfo {
  <#
  .SYNOPSIS
    Parse the sole nested MSI from an already-open legacy payload archive.
  .PARAMETER Entries
    Normalized payload entries.
  #>
  param ([Parameter(Mandatory)][object[]]$Entries)

  $MsiEntries = @($Entries | Where-Object FullName -Match '(?i)\.msi$')
  if ($MsiEntries.Count -ne 1) { return [pscustomobject]@{ Entry = $null; Info = $null; Error = $null; CandidateCount = $MsiEntries.Count } }
  $TempFolder = New-TempFolder
  try {
    $TempPath = Join-Path $TempFolder ([IO.Path]::GetFileName($MsiEntries[0].FullName))
    $null = Export-InstallerArchiveEntry -Entry $MsiEntries[0] -DestinationPath $TempPath -MaximumBytes 2147483648 -CollisionAction Overwrite
    try {
      $Info = Get-MsiInstallerInfo -Path $TempPath
      return [pscustomobject]@{ Entry = $MsiEntries[0].FullName; Info = $Info; Error = $null; CandidateCount = 1 }
    } catch {
      return [pscustomobject]@{ Entry = $MsiEntries[0].FullName; Info = $null; Error = $_.Exception.Message; CandidateCount = 1 }
    }
  } finally {
    Remove-Item -LiteralPath $TempFolder -Recurse -Force -ErrorAction SilentlyContinue
  }
}

function Get-PaquetBuilderCabinetData {
  <#
  .SYNOPSIS
    Enumerate the exact Microsoft cabinet referenced by a Paquet Builder ISFX descriptor.
  .PARAMETER Path
    Resolved path to the complete installer.
  .PARAMETER Descriptor
    Validated ISFX descriptor containing the absolute cabinet offset.
  .PARAMETER IncludeMetadata
    Parse a sole nested MSI while the temporary bounded cabinet is available.
  #>
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)]$Descriptor,
    [switch]$IncludeMetadata
  )

  $SourcePath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
  $Source = [IO.File]::Open($SourcePath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    if ($Descriptor.PayloadOffset + 36 -gt $Source.Length) { throw 'The Paquet Builder cabinet header is truncated.' }
    $Header = Read-BinaryBytes -Stream $Source -Offset $Descriptor.PayloadOffset -Count 36
    if ([Text.Encoding]::ASCII.GetString($Header, 0, 4) -cne 'MSCF') { throw 'The Paquet Builder ISFX payload is not a Microsoft cabinet.' }
    $CabinetSize = [long][BitConverter]::ToUInt32($Header, 8)
    if ($CabinetSize -lt 36 -or $CabinetSize -gt $Script:PaquetBuilderMaximumArchiveBytes -or $CabinetSize -gt $Source.Length - $Descriptor.PayloadOffset) { throw 'The Paquet Builder cabinet declares an invalid bounded size.' }
  } finally {
    $Source.Dispose()
  }

  $CabinetPath = New-TempFile
  try {
    $null = Export-InstallerArchiveRange -Path $SourcePath -Offset $Descriptor.PayloadOffset -Length $CabinetSize -DestinationPath $CabinetPath -CollisionAction Overwrite
    $Entries = @(Get-CabinetEntry -Path $CabinetPath -MaximumEntries 65536)
    if ($Entries.Count -eq 0) { throw 'The Paquet Builder cabinet contains no files.' }
    $NestedMsi = [pscustomobject]@{ Entry = $null; Info = $null; Error = $null; CandidateCount = @($Entries | Where-Object FullName -Match '(?i)\.msi$').Count }
    if ($IncludeMetadata -and $NestedMsi.CandidateCount -eq 1) {
      $MsiEntry = @($Entries | Where-Object FullName -Match '(?i)\.msi$')[0]
      $MsiPath = New-TempFile
      try {
        $null = Export-CabinetSelection -Path $CabinetPath -Selection @([pscustomobject]@{ SourceName = $MsiEntry.SourceName; DestinationPath = $MsiPath; Length = $MsiEntry.Length }) -MaximumEntries 1 -MaximumExpandedBytes 2147483648
        try {
          $NestedMsi = [pscustomobject]@{ Entry = $MsiEntry.FullName; Info = Get-MsiInstallerInfo -Path $MsiPath; Error = $null; CandidateCount = 1 }
        } catch {
          $NestedMsi = [pscustomobject]@{ Entry = $MsiEntry.FullName; Info = $null; Error = $_.Exception.Message; CandidateCount = 1 }
        }
      } finally {
        Remove-Item -LiteralPath $MsiPath -Force -ErrorAction SilentlyContinue
      }
    }

    [pscustomobject]@{
      SourcePath     = $SourcePath
      Range          = [pscustomobject]@{ Offset = [long]$Descriptor.PayloadOffset; Length = $CabinetSize; Format = 'Cabinet' }
      Entries        = $Entries
      Kind           = 'Payload'
      RuntimeCatalog = $null
      NestedMsi      = $NestedMsi
    }
  } finally {
    Remove-Item -LiteralPath $CabinetPath -Force -ErrorAction SilentlyContinue
  }
}

function Get-PaquetBuilderArchiveData {
  <#
  .SYNOPSIS
    Parse and structurally classify Paquet Builder PE resources and archive ranges.
  .PARAMETER Path
    Path to a Paquet Builder installer. The file is opened once by this operation.
  .PARAMETER IncludeMetadata
    Decode modern runtime catalogs and a sole legacy nested MSI while archives are open.
  #>
  param ([Parameter(Mandatory)][string]$Path, [switch]$IncludeMetadata)

  $SourcePath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
  $File = Get-Item -LiteralPath $SourcePath -Force
  $Stream = [IO.File]::Open($SourcePath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    $Layout = Get-PELayout -Stream $Stream
    if (-not $Layout) { throw 'The file is not a supported PE image.' }
    $OverlayOffset = Get-PEOverlayOffset -Stream $Stream
    $Resources = @(Get-PEResourceInfo -Stream $Stream -Layout $Layout | ForEach-Object {
        [pscustomobject]@{ Path = $SourcePath; TypeName = $_.TypeName; TypeId = $_.TypeId; Name = $_.Name; Id = $_.Id; LanguageId = $_.LanguageId; CodePage = $_.CodePage; Offset = $_.Offset; Size = $_.Size }
      })
    try {
      $VersionStrings = Get-PEVersionStringTable -Stream $Stream -Layout $Layout
      $VersionResourceError = $null
    } catch {
      # Some historical Delphi launchers contain version-resource padding that
      # the strict shared decoder rejects. FileVersionInfo is a safe metadata
      # fallback and does not weaken structural family detection.
      $FallbackVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($SourcePath)
      $VersionStrings = [pscustomobject]@{
        ProductName     = $FallbackVersion.ProductName
        ProductVersion  = $FallbackVersion.ProductVersion
        CompanyName     = $FallbackVersion.CompanyName
        FileDescription = $FallbackVersion.FileDescription
        Comments        = $FallbackVersion.Comments
      }
      $VersionResourceError = $_.Exception.Message
    }
    $ExecutionLevel = Get-PaquetBuilderRequestedExecutionLevel -Stream $Stream -Resources $Resources
    try {
      $ScriptEvidence = Get-PaquetBuilderPeScriptEvidence -Stream $Stream -Layout $Layout
      $ScriptScanError = $null
      if ($ScriptEvidence.Assignments.Count -eq 0 -and @($Layout.Sections.Name) -icontains 'UPX0') {
        $PackedScriptEvidence = Get-PaquetBuilderUpxPeScriptEvidence -Stream $Stream -Layout $Layout
        if ($PackedScriptEvidence) { $ScriptEvidence = $PackedScriptEvidence }
      }
    } catch {
      # Script scanning is additive metadata analysis. A historical import-table
      # shape must not invalidate an otherwise proven Paquet Builder container.
      $ScriptEvidence = [pscustomobject]@{ MappedBytes = $null; SetVarImportFound = $false; Assignments = @(); UninstallProductCodes = @(); PackedPeInfo = $null }
      $ScriptScanError = $_.Exception.Message
    }

    $ResourceNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($Resource in $Resources) { if ($Resource.TypeId -eq 10 -and -not [string]::IsNullOrWhiteSpace($Resource.Name)) { $null = $ResourceNames.Add($Resource.Name) } }
    $EngResource = @($Resources | Where-Object { $_.TypeId -eq 10 -and $_.Name -ieq 'ENG' })[0]
    $IsfxResource = @($Resources | Where-Object { $_.TypeId -eq 10 -and $_.Name -ieq 'ISFX' })[0]
    $EngMagic = $null
    if ($EngResource -and $EngResource.Size -ge 2) { $EngMagic = [Convert]::ToHexString((Read-BinaryBytes -Stream $Stream -Offset $EngResource.Offset -Count 2)) }

    $IdentityText = @($VersionStrings.ProductName, $VersionStrings.FileDescription, $VersionStrings.CompanyName, $VersionStrings.Comments) -join "`n"
    $HasPaquetIdentity = $IdentityText -match '(?i)Paquet\s*Builder|G\.?D\.?G\.?\s*Software|installpackbuilder'
    $IsfxDescriptor = if ($IsfxResource -and $HasPaquetIdentity) { Read-PaquetBuilderIsfxDescriptor -Stream $Stream -Resource $IsfxResource -FileLength $File.Length } else { $null }
    $PackageConfiguration = $null
    $PackageConfigurationError = $null
    if ($IsfxDescriptor) {
      try { $PackageConfiguration = Read-PaquetBuilderPackageConfiguration -Stream $Stream -Descriptor $IsfxDescriptor } catch { $PackageConfigurationError = $_.Exception.Message }
    }
    $GpRuntime = if ($EngResource -and $EngMagic -ceq '4750' -and $HasPaquetIdentity) { Read-PaquetBuilderGpRuntime -Stream $Stream -Resource $EngResource } else { $null }
    if ($GpRuntime -and $GpRuntime.TrailingSize -gt 0) {
      try { $PackageConfiguration = Read-PaquetBuilderGpPackageConfiguration -Stream $Stream -Runtime $GpRuntime } catch { $PackageConfigurationError = $_.Exception.Message }
    }
    $MissingClassicResource = @('DESCRIPTION', 'DVCLAL', 'PACKAGEINFO') | Where-Object { -not $ResourceNames.Contains($_) }
    $ClassicEnvelope = if (-not $MissingClassicResource -and $HasPaquetIdentity) { Read-PaquetBuilderClassicEnvelope -Stream $Stream -OverlayOffset $OverlayOffset } else { $null }
  } finally {
    $Stream.Dispose()
  }

  # Archive ranges are independently validated so an incidental 7z signature is not accepted.
  $Candidates = [Collections.Generic.List[object]]::new()
  if ($OverlayOffset -gt 0 -and $OverlayOffset -lt $File.Length) {
    foreach ($Range in @(Get-EmbeddedSevenZipArchiveRange -Path $SourcePath -StartOffset $OverlayOffset -MaximumArchives 16 -MaximumArchiveBytes $Script:PaquetBuilderMaximumArchiveBytes)) {
      $Context = $null
      try {
        $Context = Open-InstallerArchiveRange -Path $SourcePath -Range $Range
        $Entries = @(Get-InstallerArchiveEntry -Archive $Context.Archive)
        if ($Entries.Count -eq 0) { continue }
        $RuntimeMarkers = @($Entries | Where-Object { $_.FullName -ieq 'pbfprop.dat' -or $_.FullName -match '(?i)^PBCore(?:64|A64)?\.dll$' })
        $Kind = $RuntimeMarkers.Count -gt 0 ? 'Runtime' : 'Payload'
        $RuntimeCatalog = $null
        $NestedMsi = $null
        if ($IncludeMetadata -and $Kind -eq 'Runtime') { $RuntimeCatalog = Read-PaquetBuilderRuntimeCatalog -Entries $Entries }
        if ($IncludeMetadata -and $Kind -eq 'Payload') { $NestedMsi = Get-PaquetBuilderNestedMsiInfo -Entries $Entries }
        $Candidates.Add([pscustomobject]@{ SourcePath = $SourcePath; Range = $Range; Entries = $Entries; Kind = $Kind; RuntimeCatalog = $RuntimeCatalog; NestedMsi = $NestedMsi })
      } catch {
        continue
      } finally {
        if ($Context) { Close-InstallerArchiveRange -Context $Context }
      }
    }
  }

  $Runtime = @($Candidates | Where-Object Kind -EQ 'Runtime' | Sort-Object { $_.Range.Offset })[0]
  $Payloads = @($Candidates | Where-Object Kind -EQ 'Payload' | Sort-Object { $_.Range.Length } -Descending)
  $Payload = $Payloads.Count -gt 0 ? $Payloads[0] : $null
  $CabinetPackage = if ($Candidates.Count -eq 0 -and $EngMagic -ceq '4D5A' -and $IsfxDescriptor -and $HasPaquetIdentity) { Get-PaquetBuilderCabinetData -Path $SourcePath -Descriptor $IsfxDescriptor -IncludeMetadata:$IncludeMetadata } else { $null }
  $ClassicPackage = $null
  $ClassicPackageError = $null
  $ClassicCatalogError = $null
  if ($ClassicEnvelope) {
    $ClassicRange = @(Get-EmbeddedZipArchiveRange -Path $SourcePath -MaximumArchives 16 | Where-Object Offset -EQ $ClassicEnvelope.ArchiveOffset)[0]
    if ($ClassicRange) {
      $Context = $null
      try {
        $Context = Open-InstallerArchiveRange -Path $SourcePath -Range $ClassicRange
        $Entries = @(Get-InstallerArchiveEntry -Archive $Context.Archive)
        if ($Entries.Count -eq 0) { throw 'The Classic Paquet Builder package archive contains no entries.' }
        $ClassicCatalog = $null
        try {
          $ControllerEntries = @($Entries | Where-Object FullName -Match '(?i)(?:^|/)SETUP(?:\d+)?\.EXE$')
          $GafEntries = @($Entries | Where-Object FullName -Match '(?i)(?:^|/)SETUP\d*\.GAF$')
          if ($ControllerEntries.Count -ne 1 -or $GafEntries.Count -ne 1) { throw 'The Classic Paquet Builder ZIP does not contain one unambiguous setup controller and GAF stream.' }

          $ControllerBytes = Read-InstallerArchiveEntryBytes -Entry $ControllerEntries[0] -MaximumBytes $Script:PaquetBuilderMaximumClassicControllerBytes
          $ControllerStream = [IO.MemoryStream]::new($ControllerBytes, $false)
          try { $ControllerCatalog = Read-PaquetBuilderClassicControllerCatalog -Stream $ControllerStream } finally { $ControllerStream.Dispose() }

          # SharpCompress entry streams are not guaranteed to seek. The shared context keeps small GAF files in memory and spills large ones to a temporary file.
          $GafEntryStream = Open-InstallerArchiveEntry -Entry $GafEntries[0]
          $SeekableGaf = $null
          try {
            $SeekableGaf = New-InstallerSeekableStream -SourceStream $GafEntryStream -MaximumBytes $Script:PaquetBuilderMaximumArchiveBytes
            $GafFiles = @(Read-PaquetBuilderClassicGafCatalog -Stream $SeekableGaf.Stream -ControllerCatalog $ControllerCatalog)
          } finally {
            if ($SeekableGaf) { $SeekableGaf.Dispose() }
            $GafEntryStream.Dispose()
          }
          $ClassicCatalog = [pscustomobject][ordered]@{
            ControllerEntry   = $ControllerEntries[0].FullName
            GafEntry          = $GafEntries[0].FullName
            Metadata          = $ControllerCatalog.Metadata
            Directories       = $ControllerCatalog.Directories
            Files             = $GafFiles
            Shortcuts         = $ControllerCatalog.Shortcuts
            RegistryWrites    = $ControllerCatalog.RegistryWrites
            AuxiliaryPaths    = $ControllerCatalog.AuxiliaryPaths
            ExecutedPayloads  = $ControllerCatalog.ExecutedPayloads
            UnknownRecords    = @($ControllerCatalog.UnknownRecords | Select-Object Index, HeaderOffset, ObservedTag, CompressedOffset, CompressedSize, UncompressedSize, Adler32)
            AdditionalRecords = @($ControllerCatalog.AdditionalRecords | Select-Object Index, HeaderOffset, ObservedTag, CompressedOffset, CompressedSize, UncompressedSize, Adler32)
            Controller        = [pscustomobject][ordered]@{ Format = $ControllerCatalog.Format; CatalogOffset = $ControllerCatalog.CatalogOffset; CatalogLength = $ControllerCatalog.CatalogLength; RecordCount = $ControllerCatalog.RecordCount; ExpandedRecordBytes = $ControllerCatalog.ExpandedRecordBytes }
          }
        } catch {
          $ClassicCatalogError = $_.Exception.Message
        }
        $ClassicPackage = [pscustomobject]@{ SourcePath = $SourcePath; Range = $ClassicRange; Entries = $Entries; Kind = 'ClassicPackage'; RuntimeCatalog = $null; NestedMsi = $null; ClassicCatalog = $ClassicCatalog }
      } catch {
        $ClassicPackageError = $_.Exception.Message
      } finally {
        if ($Context) { Close-InstallerArchiveRange -Context $Context }
      }
    } elseif ($ClassicEnvelope.ArchiveOffset -lt $File.Length) {
      $ClassicPackageError = 'No complete ZIP central directory was found at the Classic package boundary.'
    }
  }

  $ProfileId = $null
  if ($Runtime -and $Payload) {
    $ProfileId = 'SplitArchiveRuntime'
  } elseif ($Candidates.Count -eq 1 -and $Payload -and $EngMagic -ceq '4D5A' -and $HasPaquetIdentity) {
    $ProfileId = 'LegacyEmbeddedPeRuntime'
  } elseif ($Candidates.Count -eq 1 -and $Payload -and $EngMagic -ceq '4750' -and $HasPaquetIdentity) {
    $ProfileId = 'CompressedResourceRuntime'
  } elseif ($CabinetPackage) {
    $ProfileId = 'CabinetPackageRuntime'
  } elseif ($Candidates.Count -eq 0 -and $ClassicEnvelope -and $HasPaquetIdentity) {
    $ProfileId = 'ClassicResourcePackage'
  }
  if (-not $ProfileId) { throw 'The PE does not contain a supported Paquet Builder structural layout.' }
  if ($ProfileId -eq 'ClassicResourcePackage' -and $ClassicPackage) { $Payload = $ClassicPackage }
  if ($ProfileId -eq 'CabinetPackageRuntime') { $Payload = $CabinetPackage }

  $AllArchives = [Collections.Generic.List[object]]::new()
  foreach ($Archive in $Candidates) { $AllArchives.Add($Archive) }
  if ($CabinetPackage) { $AllArchives.Add($CabinetPackage) }
  if ($ClassicPackage) { $AllArchives.Add($ClassicPackage) }

  [pscustomobject][ordered]@{
    Path                      = $SourcePath
    File                      = $File
    Layout                    = $Layout
    OverlayOffset             = $OverlayOffset
    Profile                   = Get-PaquetBuilderFormatProfile -Id $ProfileId
    Resources                 = $Resources
    EngResource               = $EngResource
    EngMagic                  = $EngMagic
    IsfxDescriptor            = $IsfxDescriptor
    PackageConfiguration      = $PackageConfiguration
    PackageConfigurationError = $PackageConfigurationError
    GpRuntime                 = $GpRuntime
    ClassicEnvelope           = $ClassicEnvelope
    ClassicPackageError       = $ClassicPackageError
    ClassicCatalogError       = $ClassicCatalogError
    VersionStrings            = $VersionStrings
    RequestedExecutionLevel   = $ExecutionLevel
    ScriptEvidence            = $ScriptEvidence
    ScriptScanError           = $ScriptScanError
    VersionResourceError      = $VersionResourceError
    Archives                  = $AllArchives.ToArray()
    Payload                   = $Payload
    Runtime                   = $Runtime
  }
}

function Get-PaquetBuilderAssignmentValue {
  <#
  .SYNOPSIS
    Return distinct values assigned to a compiled PBCore variable.
  .PARAMETER Assignments
    Literal assignments recovered by the native PE scanner.
  .PARAMETER Name
    Case-insensitive PBCore variable name.
  #>
  [OutputType([string[]])]
  param ([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Assignments, [Parameter(Mandatory)][string]$Name)

  return [string[]]@($Assignments | Where-Object Name -IEQ $Name | Select-Object -ExpandProperty Value -Unique)
}

function ConvertFrom-PaquetBuilderRuntimePath {
  <#
  .SYNOPSIS
    Convert a literal Paquet Builder destination expression to a manifest-safe path.
  .PARAMETER Path
    Literal runtime path expression.
  .PARAMETER Scope
    Singular proven installation scope used to resolve PBINSTALLSCOPEDIR.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][string]$Path, [string]$Scope)

  $Result = $Path.Trim()
  if ([string]::IsNullOrWhiteSpace($Result)) { return $null }
  $ScopeRoot = $Scope -eq 'user' ? '%LOCALAPPDATA%\Programs' : ($Scope -eq 'machine' ? '%ProgramFiles%' : $null)
  if ($Result -match '(?i)%PBINSTALLSCOPEDIR%' -and -not $ScopeRoot) { return $null }
  $Result = $Result -ireplace '%PBINSTALLSCOPEDIR%', $ScopeRoot
  $Result = $Result -ireplace '%PROGFILESDIR%', '%ProgramFiles%'
  $Result = $Result -ireplace '%LOCALAPPDATADIR%', '%LOCALAPPDATA%'
  $Result = $Result -ireplace '%APPDATADIR%', '%APPDATA%'
  $AllowedManifestVariables = @('ProgramFiles', 'LOCALAPPDATA', 'APPDATA')
  foreach ($Match in [regex]::Matches($Result, '%(?<Name>[A-Za-z0-9_]+)%')) {
    if ($Match.Groups['Name'].Value -notin $AllowedManifestVariables) { return $null }
  }
  return $Result
}

function Resolve-PaquetBuilderScriptValue {
  <#
  .SYNOPSIS
    Resolve deterministic percent variables in one Paquet Builder script value.
  .PARAMETER Value
    Literal script value that may contain percent-delimited variables.
  .PARAMETER Assignments
    Parsed GINFOS assignments used only when a variable has one literal value.
  .PARAMETER Scope
    Singular proven scope used to resolve PBINSTALLSCOPEDIR.
  .PARAMETER DefaultInstallLocation
    Source-backed final destination used for DESTPATH references.
  #>
  [OutputType([string])]
  param (
    [AllowNull()][string]$Value,
    [AllowNull()][object[]]$Assignments,
    [AllowNull()][string]$Scope,
    [AllowNull()][string]$DefaultInstallLocation
  )

  if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }
  $Resolved = $Value
  $KnownValues = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
  $KnownValues['PROGFILESDIR'] = '%ProgramFiles%'
  $KnownValues['LOCALAPPDATADIR'] = '%LOCALAPPDATA%'
  $KnownValues['APPDATADIR'] = '%APPDATA%'
  if ($DefaultInstallLocation) { $KnownValues['DESTPATH'] = $DefaultInstallLocation }
  if ($Scope -eq 'user') { $KnownValues['PBINSTALLSCOPEDIR'] = '%LOCALAPPDATA%\Programs' }
  if ($Scope -eq 'machine') { $KnownValues['PBINSTALLSCOPEDIR'] = '%ProgramFiles%' }

  foreach ($AssignmentGroup in @($Assignments | Where-Object IsLiteral | Group-Object Name)) {
    $Values = @($AssignmentGroup.Group.Value | Where-Object { $null -ne $_ } | Select-Object -Unique)
    if ($Values.Count -eq 1 -and $Values[0] -notmatch "^(?i:%$([regex]::Escape($AssignmentGroup.Name))%)$") { $KnownValues[$AssignmentGroup.Name] = [string]$Values[0] }
  }

  for ($Pass = 0; $Pass -lt 16; $Pass++) {
    $Changed = $false
    foreach ($Match in @([regex]::Matches($Resolved, '%(?<Name>[A-Za-z_][A-Za-z0-9_]*)%'))) {
      $Name = $Match.Groups['Name'].Value
      if ($Name -in @('ProgramFiles', 'LOCALAPPDATA', 'APPDATA') -or -not $KnownValues.ContainsKey($Name)) { continue }
      $Next = $Resolved.Replace($Match.Value, $KnownValues[$Name], [StringComparison]::OrdinalIgnoreCase)
      if ($Next -cne $Resolved) { $Resolved = $Next; $Changed = $true }
    }
    if (-not $Changed) { break }
  }

  foreach ($Match in [regex]::Matches($Resolved, '%(?<Name>[A-Za-z_][A-Za-z0-9_]*)%')) {
    if ($Match.Groups['Name'].Value -notin @('ProgramFiles', 'LOCALAPPDATA', 'APPDATA')) { return $null }
  }
  return $Resolved
}

function ConvertTo-PaquetBuilderVersionString {
  <#
  .SYNOPSIS
    Normalize historical comma-separated numeric PE version strings.
  .PARAMETER Version
    Version-resource text. Non-numeric formats are preserved verbatim.
  #>
  [OutputType([string])]
  param ([AllowNull()][string]$Version)

  $Value = $Version.Trim()
  if ($Value -match '^\d+(?:,\s*\d+)+$') { return $Value -replace ',\s*', '.' }
  return $Value
}

function Get-PaquetBuilderInfo {
  <#
  .SYNOPSIS
    Read source-backed Paquet Builder metadata, scope, ARP, switch, and payload evidence.
  .PARAMETER Path
    Path to a Paquet Builder installer. No installer or payload is executed.
  .OUTPUTS
    Common installer parser fields plus FormatGeneration, StructuralRoute, archives, runtime catalogs, compiled assignments, switches, modes, diagnostics, and unresolved fields.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)

  process {
    $Data = Get-PaquetBuilderArchiveData -Path $Path -IncludeMetadata
    $Diagnostics = [Collections.Generic.List[object]]::new()
    $UnresolvedFields = [Collections.Generic.List[string]]::new()
    $PackageScript = $Data.PackageConfiguration ? $Data.PackageConfiguration.ScriptProgram : $null
    $ScriptAssignments = $PackageScript ? @($PackageScript.Assignments) : @()
    $PackageAssignments = @($ScriptAssignments | Where-Object IsLiteral | Select-Object Name, Value, Expression, LineNumber)
    $Assignments = @($Data.ScriptEvidence.Assignments) + $PackageAssignments
    # The verified 2.7 and 2.8 routes can be MSI bootstrappers. Later payload
    # archives can contain MSI files as ordinary application data, so a 2.9 MSI
    # is selected only when GINFOS calls the package's PBExecMSI helper for it.
    $ReferencedMsiPaths = $PackageScript ? @($PackageScript.NestedInstallerReferences.RelativePath | Select-Object -Unique) : @()
    $PayloadMsi = $Data.Payload ? $Data.Payload.NestedMsi : $null
    $ScriptSelectsPayloadMsi = $PayloadMsi -and $PayloadMsi.Entry -and $ReferencedMsiPaths -icontains $PayloadMsi.Entry
    $NestedMsi = ($Data.Profile.Id -in @('CabinetPackageRuntime', 'LegacyEmbeddedPeRuntime') -or ($Data.Profile.Id -eq 'CompressedResourceRuntime' -and $ScriptSelectsPayloadMsi)) -and $Data.Payload ? $PayloadMsi : $null
    $NestedMsiInfo = $NestedMsi ? $NestedMsi.Info : $null
    $ClassicCatalog = if ($Data.Profile.Id -eq 'ClassicResourcePackage' -and $Data.Payload -and $Data.Payload.PSObject.Properties['ClassicCatalog']) { $Data.Payload.ClassicCatalog } else { $null }
    $RegistryWriteList = [Collections.Generic.List[object]]::new()
    if ($ClassicCatalog) { foreach ($Write in $ClassicCatalog.RegistryWrites) { $RegistryWriteList.Add($Write) } }
    if ($PackageScript) { foreach ($Write in $PackageScript.RegistryWrites) { $RegistryWriteList.Add($Write) } }
    $RegistryWrites = $RegistryWriteList.ToArray()
    if ($Data.ScriptScanError) {
      $Diagnostics.Add((ConvertTo-PaquetBuilderDiagnostic -Id 'Script.ScanIncomplete' -Message "Compiled PBCore metadata analysis was incomplete: $($Data.ScriptScanError)" -Kind Incomplete -Areas Metadata -AffectedFields @('ProductCode', 'Scope', 'DefaultInstallLocation', 'InstallerSwitches')))
    }
    if ($Data.ScriptEvidence.PSObject.Properties['PackedPeInfo'] -and $Data.ScriptEvidence.PackedPeInfo) {
      $Diagnostics.Add((ConvertTo-PaquetBuilderDiagnostic -Id 'Script.PackedPeRecovered' -Message 'Literal package metadata was recovered from an integrity-checked UPX/LZMA launcher image.' -Kind Information -Areas Metadata -AffectedFields @('ProductCode', 'Scope', 'DefaultInstallLocation', 'InstallerSwitches') -Evidence $Data.ScriptEvidence.PackedPeInfo))
    }
    if ($Data.VersionResourceError) {
      $Diagnostics.Add((ConvertTo-PaquetBuilderDiagnostic -Id 'VersionResource.Fallback' -Message 'The strict PE version-resource decoder rejected the historical layout; Windows FileVersionInfo supplied identity metadata.' -Kind Fallback -Areas Metadata -Evidence $Data.VersionResourceError))
    }
    $ScopeValues = @(Get-PaquetBuilderAssignmentValue -Assignments $Assignments -Name 'PBINSTALLSCOPE' | Where-Object { $_ -cin @('0', '1') })
    $SupportedScopes = [Collections.Generic.List[string]]::new()
    if ($ScopeValues -ccontains '0') { $SupportedScopes.Add('user') }
    if ($ScopeValues -ccontains '1') { $SupportedScopes.Add('machine') }
    $Scope = $SupportedScopes.Count -eq 1 ? $SupportedScopes[0] : $null
    if ($SupportedScopes.Count -eq 0 -and $Data.RequestedExecutionLevel -ieq 'requireAdministrator') { $Scope = 'machine'; $SupportedScopes.Add('machine') }
    if ($SupportedScopes.Count -eq 0 -and $NestedMsiInfo -and $NestedMsiInfo.Scope) { $Scope = [string]$NestedMsiInfo.Scope; $SupportedScopes.Add($Scope) }
    if ($SupportedScopes.Count -eq 0 -and $ClassicCatalog) {
      # A system-directory file or literal HKLM write is direct machine-state evidence even though this pre-UAC controller has no requestedExecutionLevel manifest.
      $ClassicMachineEvidence = @($ClassicCatalog.Files | Where-Object Destination -Match '(?i)^\{(?:win|sys|syswow64)\}[\\/]') + @($RegistryWrites | Where-Object Root -EQ 'HKLM')
      if ($ClassicMachineEvidence.Count -gt 0) { $Scope = 'machine'; $SupportedScopes.Add('machine') }
    }
    if ($SupportedScopes.Count -eq 0) {
      $ArpRoots = @($RegistryWrites | Where-Object { $_.Root -in @('HKCU', 'HKLM') -and $_.Key -match '^(?i:Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\)[^\\]+$' } | Select-Object -ExpandProperty Root -Unique)
      if ($ArpRoots.Count -eq 1) {
        $Scope = $ArpRoots[0] -eq 'HKCU' ? 'user' : 'machine'
        $SupportedScopes.Add($Scope)
      }
    }

    if ($SupportedScopes.Count -gt 1) {
      $Diagnostics.Add((ConvertTo-PaquetBuilderDiagnostic -Id 'Scope.Conditional' -Message 'Compiled PBCore assignments contain both user and machine installation-scope routes.' -Kind Ambiguous -Areas Metadata -AffectedFields Scope -Evidence $ScopeValues))
      $UnresolvedFields.Add('Scope')
    } elseif ($SupportedScopes.Count -eq 0) {
      $Diagnostics.Add((ConvertTo-PaquetBuilderDiagnostic -Id 'Scope.Unresolved' -Message 'No exact compiled installation-scope assignment or requireAdministrator manifest proves the package scope.' -Kind Incomplete -Areas Metadata -AffectedFields Scope))
      $UnresolvedFields.Add('Scope')
    }

    $ElevationRequirement = $Data.RequestedExecutionLevel -ieq 'requireAdministrator' ? 'elevationRequired' : $null
    $RegistryProductCodes = @($RegistryWrites | ForEach-Object {
        if ($_.Root -in @('HKCU', 'HKLM') -and $_.Key -match '^(?i:Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\)(?<ProductCode>[^\\]+)$') { $Matches.ProductCode }
      })
    $ScriptUninstallKeys = if ($PackageScript -and $PackageScript.Commands.Name -icontains 'UNINSTALLINFO') {
      @($PackageScript.Assignments | Where-Object { $_.Name -ieq 'UNINSTKEY' -and $_.IsLiteral -and $_.Value -notmatch '[\\/%\x00-\x1F]' } | Select-Object -ExpandProperty Value -Unique)
    } else { @() }
    $ProductCodes = @(($Data.ScriptEvidence.UninstallProductCodes + $RegistryProductCodes + $ScriptUninstallKeys) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
    if ($NestedMsi -and $NestedMsi.Error) {
      $Diagnostics.Add((ConvertTo-PaquetBuilderDiagnostic -Id 'NestedMsi.ParseFailed' -Message "The sole nested MSI could not be parsed: $($NestedMsi.Error)" -Kind Incomplete -Areas Metadata -AffectedFields @('ProductCode', 'UpgradeCode', 'AppsAndFeaturesEntries') -Evidence $NestedMsi.Entry))
    } elseif ($NestedMsi -and $NestedMsi.CandidateCount -gt 1) {
      $Diagnostics.Add((ConvertTo-PaquetBuilderDiagnostic -Id 'NestedMsi.Ambiguous' -Message 'The legacy payload contains multiple MSI files, so no nested package was selected without architecture evidence.' -Kind Ambiguous -Areas Metadata -AffectedFields @('ProductCode', 'UpgradeCode', 'AppsAndFeaturesEntries') -Evidence $NestedMsi.CandidateCount))
    }

    $ProductCode = if ($NestedMsiInfo -and $NestedMsiInfo.ProductCode) { $NestedMsiInfo.ProductCode } elseif ($ProductCodes.Count -eq 1) { $ProductCodes[0] } else { $null }
    $UpgradeCode = $NestedMsiInfo ? $NestedMsiInfo.UpgradeCode : $null
    if ($ProductCodes.Count -gt 1) {
      $Diagnostics.Add((ConvertTo-PaquetBuilderDiagnostic -Id 'Arp.MultipleLiteralKeys' -Message 'The package contains multiple literal uninstall-key identities; conditional runtime evidence is required to select one.' -Kind Ambiguous -Areas Metadata -AffectedFields @('ProductCode', 'AppsAndFeaturesEntries') -Evidence $ProductCodes))
    }
    if (-not $ProductCode) {
      $Diagnostics.Add((ConvertTo-PaquetBuilderDiagnostic -Id 'Arp.Unresolved' -Message 'The package contains no unique source-backed visible uninstall identity.' -Kind Incomplete -Areas Metadata -AffectedFields @('ProductCode', 'AppsAndFeaturesEntries')))
      $UnresolvedFields.Add('ProductCode')
      $UnresolvedFields.Add('AppsAndFeaturesEntries')
    }

    $ArpValues = [ordered]@{}
    if ($ProductCode) {
      foreach ($Write in @($RegistryWrites | Where-Object { $_.Root -in @('HKCU', 'HKLM') -and $_.Key -ieq "Software\Microsoft\Windows\CurrentVersion\Uninstall\$ProductCode" })) {
        if (-not [string]::IsNullOrWhiteSpace([string]$Write.Name)) { $ArpValues[[string]$Write.Name] = $Write.Value }
      }
    }
    $VersionStrings = $Data.VersionStrings
    $DisplayName = if ($NestedMsiInfo -and $NestedMsiInfo.DisplayName) { [string]$NestedMsiInfo.DisplayName } elseif ($ArpValues.DisplayName) { [string]$ArpValues.DisplayName } elseif ($VersionStrings.ProductName) { [string]$VersionStrings.ProductName } elseif ($ClassicCatalog) { [string]$ClassicCatalog.Metadata.ProductName } else { '' }
    $DisplayVersion = if ($NestedMsiInfo -and $NestedMsiInfo.DisplayVersion) { [string]$NestedMsiInfo.DisplayVersion } elseif ($ArpValues.DisplayVersion) { [string]$ArpValues.DisplayVersion } else { ConvertTo-PaquetBuilderVersionString -Version ([string]$VersionStrings.ProductVersion) }
    $Publisher = if ($NestedMsiInfo -and $NestedMsiInfo.Publisher) { [string]$NestedMsiInfo.Publisher } elseif ($ArpValues.Publisher) { [string]$ArpValues.Publisher } else { [string]$VersionStrings.CompanyName }
    $DisplayName = $DisplayName.Trim()
    $DisplayVersion = $DisplayVersion.Trim()
    $Publisher = $Publisher.Trim()

    $DestinationValues = @(Get-PaquetBuilderAssignmentValue -Assignments $Assignments -Name 'DESTPATH' | Where-Object { $_ -match '^(?:%[A-Za-z0-9_]+%|[A-Za-z]:[\\/])' })
    $ResolvedDestinationValues = @($DestinationValues | ForEach-Object { ConvertFrom-PaquetBuilderRuntimePath -Path $_ -Scope $Scope } | Where-Object { $_ } | Select-Object -Unique)
    $DefaultInstallLocation = $ResolvedDestinationValues.Count -eq 1 ? $ResolvedDestinationValues[0] : $null
    if ($DestinationValues.Count -gt 0 -and $ResolvedDestinationValues.Count -ne 1) {
      $Diagnostics.Add((ConvertTo-PaquetBuilderDiagnostic -Id 'InstallLocation.Dynamic' -Message 'The compiled destination path is conditional or contains unresolved runtime variables.' -Kind Incomplete -Areas Metadata -AffectedFields DefaultInstallLocation -Evidence $DestinationValues))
      $UnresolvedFields.Add('DefaultInstallLocation')
    } elseif ($ClassicCatalog -and -not $DefaultInstallLocation) {
      $Diagnostics.Add((ConvertTo-PaquetBuilderDiagnostic -Id 'InstallLocation.ClassicRootUnresolved' -Message 'The Classic controller provides complete destinations relative to {app}, but the selected application root is not stored as a literal path in the decoded catalog.' -Kind Incomplete -Areas Metadata -AffectedFields DefaultInstallLocation -Evidence $ClassicCatalog.Directories))
      $UnresolvedFields.Add('DefaultInstallLocation')
    }
    $DisplayIcon = Resolve-PaquetBuilderScriptValue -Value ([string]$ArpValues.DisplayIcon) -Assignments $ScriptAssignments -Scope $Scope -DefaultInstallLocation $DefaultInstallLocation
    $UninstallString = Resolve-PaquetBuilderScriptValue -Value ([string]$ArpValues.UninstallString) -Assignments $ScriptAssignments -Scope $Scope -DefaultInstallLocation $DefaultInstallLocation

    $SilentValues = @(Get-PaquetBuilderAssignmentValue -Assignments $Assignments -Name 'SILENT' | Where-Object { $_ -ceq '1' })
    $SupportsSilentInstallation = $Data.Profile.Id -eq 'SplitArchiveRuntime' -and $SilentValues.Count -gt 0
    $InstallerSwitches = $SupportsSilentInstallation ? [ordered]@{ Silent = '/s'; SilentWithProgress = '/s' } : $null
    $InstallModes = $SupportsSilentInstallation ? @('interactive', 'silent') : @('interactive')
    if ($Data.Profile.Id -ne 'SplitArchiveRuntime') {
      $Diagnostics.Add((ConvertTo-PaquetBuilderDiagnostic -Id 'Installability.GenerationSpecific' -Message 'Silent-install support is not projected for this historical structural route without exact compiled switch evidence.' -Kind ManualValidation -Areas Installability -AffectedFields @('InstallerSwitches', 'InstallModes') -Evidence $Data.Profile.Id))
    }

    if ($Data.Profile.Id -eq 'ClassicResourcePackage') {
      if ($ClassicCatalog) {
        if ($ClassicCatalog.UnknownRecords.Count -gt 0 -or $ClassicCatalog.AdditionalRecords.Count -gt 0) {
          $Diagnostics.Add((ConvertTo-PaquetBuilderDiagnostic -Id 'Metadata.ClassicAdditionalRecords' -Message 'The Classic controller contains bounded records outside the decoded directory, file, shortcut, registry, auxiliary-path, and execution groups.' -Kind Unsupported -Areas Metadata, Extraction -Evidence ([pscustomobject]@{ UnknownCount = $ClassicCatalog.UnknownRecords.Count; AdditionalCount = $ClassicCatalog.AdditionalRecords.Count })))
        }
        if ($ClassicCatalog.AuxiliaryPaths.Count -gt 0) {
          $Diagnostics.Add((ConvertTo-PaquetBuilderDiagnostic -Id 'Extraction.ClassicAuxiliaryPathSemantics' -Message 'The Classic controller exposes auxiliary paths whose operation semantics are not yet assigned; they are preserved separately from installed files.' -Kind Incomplete -Areas Extraction -Evidence $ClassicCatalog.AuxiliaryPaths))
        }
      } elseif ($Data.Payload) {
        $Diagnostics.Add((ConvertTo-PaquetBuilderDiagnostic -Id 'Extraction.ClassicCatalogUnsupported' -Message "The Classic ZIP is complete, but its packed controller catalog could not be decoded: $($Data.ClassicCatalogError)" -Kind Unsupported -Areas Metadata, Extraction -AffectedFields @('Scope', 'DefaultInstallLocation') -Evidence $Data.Payload.Entries.FullName))
      } else {
        $Diagnostics.Add((ConvertTo-PaquetBuilderDiagnostic -Id 'Extraction.ClassicArchiveIncomplete' -Message "The Classic GPacker control block is valid, but its following ZIP package is absent or incomplete: $($Data.ClassicPackageError)" -Kind Invalid -Areas Extraction))
      }
    } elseif ($Data.PackageConfigurationError) {
      $ConfigurationEvidence = $Data.IsfxDescriptor ? $Data.IsfxDescriptor : ([pscustomobject]@{ Offset = $Data.GpRuntime.TrailingOffset; Size = $Data.GpRuntime.TrailingSize })
      $Diagnostics.Add((ConvertTo-PaquetBuilderDiagnostic -Id 'Metadata.PackageConfigurationInvalid' -Message "The package configuration could not be decoded: $($Data.PackageConfigurationError)" -Kind Incomplete -Areas Metadata -AffectedFields @('ProductCode', 'Scope', 'InstallerSwitches') -Evidence $ConfigurationEvidence))
    } elseif ($Data.PackageConfiguration -and -not $Data.PackageConfiguration.IsDecoded) {
      $Diagnostics.Add((ConvertTo-PaquetBuilderDiagnostic -Id 'Metadata.PackageConfigurationCompressionUnsupported' -Message "The '$($Data.PackageConfiguration.Format)' package configuration is structurally validated, but its compressed resource stream is not yet decoded." -Kind Unsupported -Areas Metadata -AffectedFields @('ProductCode', 'Scope', 'InstallerSwitches') -Evidence $Data.PackageConfiguration))
    }
    if ($PackageScript -and $PackageScript.UnsupportedCommands.Count -gt 0) {
      $Diagnostics.Add((ConvertTo-PaquetBuilderDiagnostic -Id 'Script.CommandsUnsupported' -Message "The GINFOS program uses operation or control-flow commands that are preserved but not simulated: $($PackageScript.UnsupportedCommands -join ', ')." -Kind Unsupported -Areas Metadata, Extraction -Evidence $PackageScript.UnsupportedCommands))
    }
    $RuntimeCatalog = $Data.Runtime ? $Data.Runtime.RuntimeCatalog : $null
    if ($RuntimeCatalog -and $RuntimeCatalog.PropertyCatalogMalformed) {
      $Diagnostics.Add((ConvertTo-PaquetBuilderDiagnostic -Id 'Runtime.PropertyCatalogMalformed' -Message 'The pbfprop.dat catalog does not contain complete five-line records.' -Kind Invalid -Areas Extraction))
    }

    $WritesAppsAndFeaturesEntry = if ($NestedMsiInfo) { $true } elseif ($RegistryProductCodes.Count -gt 0) { $true } elseif ($ProductCode -and $PackageScript -and $PackageScript.Commands.Name -icontains 'UNINSTALLINFO') { $true } elseif ($ProductCode -and $RuntimeCatalog -and $RuntimeCatalog.HasUninstallerTemplate) { $true } else { $null }
    $AppsAndFeaturesInstallerType = $NestedMsiInfo ? $NestedMsiInfo.InstallerType : $null
    $AppsAndFeaturesEntries = @()
    if ($ProductCode) {
      $ArpEntry = [ordered]@{ ProductCode = $ProductCode }
      if ($DisplayName) { $ArpEntry.DisplayName = $DisplayName }
      if ($DisplayVersion) { $ArpEntry.DisplayVersion = $DisplayVersion }
      if ($Publisher) { $ArpEntry.Publisher = $Publisher }
      $AppsAndFeaturesEntries = @($ArpEntry)
    }
    $NestedInstallerFiles = if ($Data.Profile.Id -eq 'ClassicResourcePackage') { @() } elseif ($Data.Payload) { @($Data.Payload.Entries | Where-Object FullName -Match '(?i)\.(?:exe|msi|msp|msix|appx)$' | Select-Object -ExpandProperty FullName) } else { @() }
    $RegistryAssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite $RegistryWrites
    foreach ($Diagnostic in $RegistryAssociationInfo.Diagnostics) { $Diagnostics.Add($Diagnostic) }
    $LauncherArchitecture = switch ([uint16]$Data.Layout.Machine) { 0x014C { 'x86' }; 0x8664 { 'x64' }; 0xAA64 { 'arm64' }; default { $null } }
    $ExecutedPayloads = [Collections.Generic.List[object]]::new()
    if ($ClassicCatalog) { foreach ($Execution in $ClassicCatalog.ExecutedPayloads) { $ExecutedPayloads.Add($Execution) } }
    if ($PackageScript) { foreach ($Execution in $PackageScript.ExecutedPayloads) { $ExecutedPayloads.Add($Execution) } }
    $Shortcuts = [Collections.Generic.List[object]]::new()
    if ($ClassicCatalog) { foreach ($Shortcut in $ClassicCatalog.Shortcuts) { $Shortcuts.Add($Shortcut) } }
    if ($PackageScript) { foreach ($Shortcut in $PackageScript.Shortcuts) { $Shortcuts.Add($Shortcut) } }

    [pscustomobject][ordered]@{
      Path                         = $Data.Path
      InstallerType                = 'exe'
      ProductCode                  = $ProductCode
      UpgradeCode                  = $UpgradeCode
      DisplayName                  = $DisplayName
      DisplayVersion               = $DisplayVersion
      Publisher                    = $Publisher
      Scope                        = $Scope
      DefaultInstallLocation       = $DefaultInstallLocation
      DisplayIcon                  = $DisplayIcon
      UninstallString              = $UninstallString
      WritesAppsAndFeaturesEntry   = $WritesAppsAndFeaturesEntry
      AppsAndFeaturesProductCode   = $ProductCode
      AppsAndFeaturesInstallerType = $AppsAndFeaturesInstallerType
      AppsAndFeaturesEntries       = $AppsAndFeaturesEntries
      Diagnostics                  = @(Merge-InstallerDiagnostics -Diagnostic $Diagnostics.ToArray())
      UnresolvedFields             = [string[]]@($UnresolvedFields | Select-Object -Unique)
      Family                       = 'Paquet Builder'
      FormatGeneration             = $Data.Profile.Generation
      StructuralRoute              = $Data.Profile.Id
      ObservedBuilderRange         = $Data.Profile.ObservedBuilders
      FileDescription              = ([string]$VersionStrings.FileDescription).Trim()
      LauncherArchitecture         = $LauncherArchitecture
      RequestedExecutionLevel      = $Data.RequestedExecutionLevel
      ElevationRequirement         = $ElevationRequirement
      SupportedScopes              = $SupportedScopes.ToArray()
      SupportsSilentInstallation   = $SupportsSilentInstallation
      InstallModes                 = [string[]]$InstallModes
      InstallerSwitches            = $InstallerSwitches
      InstallerSuccessCodes        = @()
      CompiledVariableAssignments  = $Assignments
      PackedPeInfo                 = $Data.ScriptEvidence.PSObject.Properties['PackedPeInfo'] ? $Data.ScriptEvidence.PackedPeInfo : $null
      PackageScript                = $PackageScript
      PackageConfiguration         = if ($Data.PackageConfiguration) {
        [pscustomobject][ordered]@{
          Format                    = $Data.PackageConfiguration.Format
          EncodedOffset             = $Data.PackageConfiguration.EncodedOffset
          EncodedSize               = $Data.PackageConfiguration.EncodedSize
          HeaderSize                = $Data.PackageConfiguration.HeaderSize
          CompressedSize            = $Data.PackageConfiguration.CompressedSize
          UncompressedSize          = $Data.PackageConfiguration.UncompressedSize
          ExpectedCrc32             = $Data.PackageConfiguration.ExpectedCrc32
          ActualCrc32               = $Data.PackageConfiguration.ActualCrc32
          ExpectedCompressedCrc32   = $Data.PackageConfiguration.ExpectedCompressedCrc32
          ExpectedUncompressedCrc32 = $Data.PackageConfiguration.ExpectedUncompressedCrc32
          DecoderBytesRead          = $Data.PackageConfiguration.DecoderBytesRead
          DecoderPaddingBytes       = $Data.PackageConfiguration.DecoderPaddingBytes
          DecoderTrailingBytes      = $Data.PackageConfiguration.DecoderTrailingBytes
          ObservedField             = $Data.PackageConfiguration.ObservedField
          IsDecoded                 = $Data.PackageConfiguration.IsDecoded
          Resources                 = @($Data.PackageConfiguration.Resources | Select-Object Index, Name, Offset, Length)
          TextResources             = $Data.PackageConfiguration.TextResources
        }
      } else { $null }
      RuntimeCatalog               = $RuntimeCatalog
      ClassicCatalog               = $ClassicCatalog
      RegistryWrites               = $RegistryWrites
      RegistryAssociationInfo      = $RegistryAssociationInfo
      Protocols                    = $RegistryAssociationInfo.Protocols
      FileExtensions               = $RegistryAssociationInfo.FileExtensions
      PayloadFiles                 = if ($ClassicCatalog) { [string[]]@($ClassicCatalog.Files.Destination) } elseif ($Data.Payload) { [string[]]@($Data.Payload.Entries.FullName) } else { @() }
      InstalledFiles               = $ClassicCatalog ? @($ClassicCatalog.Files) : @()
      Shortcuts                    = $Shortcuts.ToArray()
      FileOperations               = $PackageScript ? @($PackageScript.FileOperations) : @()
      UninstallOperations          = $PackageScript ? @($PackageScript.UninstallOperations) : @()
      ExecutedPayloads             = $ExecutedPayloads.ToArray()
      RuntimeFiles                 = if ($Data.Runtime) { [string[]]@($Data.Runtime.Entries.FullName) } elseif ($Data.GpRuntime) { [string[]]@('ENG.exe', $(if ($Data.GpRuntime.TrailingSize -gt 0) { 'ENG.tail.bin' })) } else { @() }
      NestedInstallerFiles         = [string[]]$NestedInstallerFiles
      NestedMsiPath                = $NestedMsi ? $NestedMsi.Entry : $null
      PayloadArchiveRange          = $Data.Payload ? $Data.Payload.Range : $null
      RuntimeArchiveRange          = $Data.Runtime ? $Data.Runtime.Range : $null
      RuntimeResource              = $Data.EngResource
      RuntimeResourceInfo          = if ($Data.GpRuntime) { [pscustomobject][ordered]@{ HeaderSize = $Data.GpRuntime.HeaderSize; CompressedOffset = $Data.GpRuntime.CompressedOffset; CompressedSize = $Data.GpRuntime.CompressedSize; UncompressedSize = $Data.GpRuntime.UncompressedSize; TrailingOffset = $Data.GpRuntime.TrailingOffset; TrailingSize = $Data.GpRuntime.TrailingSize; ObservedField = $Data.GpRuntime.ObservedField; RuntimeVersionInfo = $Data.GpRuntime.RuntimeVersionInfo } } else { $null }
      IsfxDescriptor               = $Data.IsfxDescriptor
      ClassicEnvelope              = if ($Data.ClassicEnvelope) { [pscustomobject][ordered]@{ EnvelopeOffset = $Data.ClassicEnvelope.EnvelopeOffset; EnvelopeVersion = $Data.ClassicEnvelope.EnvelopeVersion; PackedBlockOffset = $Data.ClassicEnvelope.PackedBlockOffset; PackedBlockSize = $Data.ClassicEnvelope.PackedBlockSize; CompressedOffset = $Data.ClassicEnvelope.CompressedOffset; CompressedSize = $Data.ClassicEnvelope.CompressedSize; DecoderBytesRead = $Data.ClassicEnvelope.DecoderBytesRead; UncompressedSize = $Data.ClassicEnvelope.UncompressedSize; ExpectedCrc32 = $Data.ClassicEnvelope.ExpectedCrc32; ArchiveOffset = $Data.ClassicEnvelope.ArchiveOffset } } else { $null }
      ParserVersionInfo            = [pscustomobject]@{ Parser = 'Dumplings.PackageModule.PaquetBuilder'; ParserMajor = 7; FormatCatalogVersion = $Script:PaquetBuilderFormatCatalog.CatalogVersion; Sources = @('PE resources', 'validated ZIP, GAF, cabinet, and 7z ranges', 'GPacker/LZHUF outer control records', 'packed GInstall controller records', 'ISFX package cipher and named resource tables', 'AP32/aPLib package resources', 'GP/LZMA runtime and package records', 'bounded UPX/LZMA PE reconstruction', 'PBCore.SetVar call sites', 'nested MSI metadata') }
    }
  }
}

function Export-PaquetBuilderClassicSelection {
  <#
  .SYNOPSIS
    Expand selected Classic GAF members to their source-backed installed destinations.
  .PARAMETER Data
    Parsed Paquet Builder layout containing a validated Classic catalog.
  .PARAMETER DestinationPath
    Resolved extraction root.
  .PARAMETER Name
    Wildcard matched against the installed path and original destination expression.
  .PARAMETER CollisionAction
    Output collision behavior.
  .PARAMETER MaximumExpandedBytes
    Aggregate output limit in bytes.
  .PARAMETER Prefix
    Optional relative output directory.
  #>
  param ($Data, [string]$DestinationPath, [string]$Name, [string]$CollisionAction, [long]$MaximumExpandedBytes, [string]$Prefix)

  $Catalog = $Data.Payload.ClassicCatalog
  if (-not $Catalog) { throw "The Classic Paquet Builder installed-file catalog is unavailable: $($Data.ClassicCatalogError)" }
  $Archive = Open-InstallerArchiveRange -Path $Data.Path -Range $Data.Payload.Range
  $GafEntryStream = $null
  $SeekableGaf = $null
  try {
    $Entries = @(Get-InstallerArchiveEntry -Archive $Archive.Archive)
    $GafEntry = @($Entries | Where-Object FullName -IEQ $Catalog.GafEntry)[0]
    if (-not $GafEntry) { throw 'The validated Classic GAF entry is no longer present in the package archive.' }
    $GafEntryStream = Open-InstallerArchiveEntry -Entry $GafEntry
    $SeekableGaf = New-InstallerSeekableStream -SourceStream $GafEntryStream -MaximumBytes $Script:PaquetBuilderMaximumArchiveBytes

    $Results = [Collections.Generic.List[IO.FileInfo]]::new()
    $ReservedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $Written = 0L
    foreach ($FileRecord in $Catalog.Files) {
      $RelativePath = ConvertFrom-PaquetBuilderClassicDestination -Destination $FileRecord.Destination
      if (-not (Test-ExtractionPattern -Path $RelativePath -Pattern $Name) -and -not (Test-ExtractionPattern -Path $FileRecord.Destination -Pattern $Name)) { continue }
      if ($Prefix) { $RelativePath = Join-Path $Prefix $RelativePath }
      $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $RelativePath -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
      if (-not $Target.ShouldWrite) { continue }
      if ($FileRecord.UncompressedSize -gt $MaximumExpandedBytes - $Written) { throw 'Classic Paquet Builder extraction exceeds the configured output limit.' }

      $Parent = [IO.Path]::GetDirectoryName($Target.Path)
      if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
      $Compressed = New-BoundedReadStream -Stream $SeekableGaf.Stream -Offset $FileRecord.CompressedOffset -Length $FileRecord.CompressedSize -LeaveOpen
      $Output = [IO.File]::Open($Target.Path, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
      try {
        $ActualSize = Expand-InstallerCompressedStream -Algorithm Zlib -Stream $Compressed -Destination $Output -MaximumBytes $FileRecord.UncompressedSize -CompressedSize $FileRecord.CompressedSize -UncompressedSize $FileRecord.UncompressedSize
        if ($ActualSize -ne $FileRecord.UncompressedSize) { throw 'A Classic Paquet Builder GAF member has an unexpected expanded size.' }
      } catch {
        $Output.Dispose()
        Remove-Item -LiteralPath $Target.Path -Force -ErrorAction SilentlyContinue
        throw
      } finally {
        if ($Output) { $Output.Dispose() }
        $Compressed.Dispose()
      }
      $Extracted = Get-Item -LiteralPath $Target.Path -Force
      $Written += $Extracted.Length
      $Results.Add($Extracted)
    }
    return $Results.ToArray()
  } finally {
    if ($SeekableGaf) { $SeekableGaf.Dispose() }
    if ($GafEntryStream) { $GafEntryStream.Dispose() }
    Close-InstallerArchiveRange -Context $Archive
  }
}

function Export-PaquetBuilderResourceSelection {
  <#
  .SYNOPSIS
    Export selected Paquet Builder PE resources with collision and aggregate limits.
  .PARAMETER Data
    Parsed Paquet Builder layout.
  .PARAMETER DestinationPath
    Resolved extraction root.
  .PARAMETER Name
    Wildcard matching resource output names.
  .PARAMETER CollisionAction
    Output collision behavior.
  .PARAMETER MaximumExpandedBytes
    Aggregate output limit in bytes.
  .PARAMETER Prefix
    Optional relative output directory.
  #>
  param ($Data, [string]$DestinationPath, [string]$Name, [string]$CollisionAction, [long]$MaximumExpandedBytes, [string]$Prefix)

  $Results = [Collections.Generic.List[IO.FileInfo]]::new()
  $ReservedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $Written = 0L
  foreach ($Resource in @($Data.Resources | Where-Object TypeId -EQ 10)) {
    $ResourceName = if ($Resource.Name) { [string]$Resource.Name } else { "RCDATA-$($Resource.Id)" }
    if ($ResourceName -ieq 'ENG' -and $Data.GpRuntime) {
      # The GP resource contains two physical outputs: a decoded PE and a
      # separately sized package tail. Exporting the raw wrapper would conceal
      # the useful runtime and force callers to repeat the transform.
      $GpOutputs = [Collections.Generic.List[object]]::new()
      $GpOutputs.Add([pscustomobject]@{ Name = 'ENG.exe'; Length = [long]$Data.GpRuntime.RuntimeBytes.Length; Bytes = $Data.GpRuntime.RuntimeBytes; Offset = 0L })
      if ($Data.GpRuntime.TrailingSize -gt 0) { $GpOutputs.Add([pscustomobject]@{ Name = 'ENG.tail.bin'; Length = [long]$Data.GpRuntime.TrailingSize; Bytes = $null; Offset = [long]$Data.GpRuntime.TrailingOffset }) }
      foreach ($GpOutput in $GpOutputs) {
        if (-not (Test-ExtractionPattern -Path $GpOutput.Name -Pattern $Name)) { continue }
        $RelativePath = $Prefix ? (Join-Path $Prefix $GpOutput.Name) : $GpOutput.Name
        $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $RelativePath -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
        if (-not $Target.ShouldWrite) { continue }
        if ($GpOutput.Length -gt $MaximumExpandedBytes - $Written) { throw 'Paquet Builder resource extraction exceeds the configured output limit.' }
        $Parent = [IO.Path]::GetDirectoryName($Target.Path)
        if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
        if ($GpOutput.Bytes) {
          [IO.File]::WriteAllBytes($Target.Path, $GpOutput.Bytes)
        } else {
          $Source = [IO.File]::Open($Data.Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
          $Destination = [IO.File]::Open($Target.Path, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
          try { Copy-BinaryStreamRange -Source $Source -Destination $Destination -Offset $GpOutput.Offset -Length $GpOutput.Length } finally { $Destination.Dispose(); $Source.Dispose() }
        }
        $File = Get-Item -LiteralPath $Target.Path -Force
        $Written += $File.Length
        $Results.Add($File)
      }
      continue
    }
    $Extension = if ($ResourceName -ieq 'ENG' -and $Data.EngMagic -ceq '4D5A') { '.exe' } else { '.bin' }
    $RelativePath = "$ResourceName$Extension"
    if (-not (Test-ExtractionPattern -Path $RelativePath -Pattern $Name)) { continue }
    if ($Prefix) { $RelativePath = Join-Path $Prefix $RelativePath }
    $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $RelativePath -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
    if (-not $Target.ShouldWrite) { continue }
    if ($Resource.Size -gt $MaximumExpandedBytes - $Written) { throw 'Paquet Builder resource extraction exceeds the configured output limit.' }
    $File = Export-PEResourceData -Resource $Resource -DestinationPath $Target.Path -MaximumBytes ($MaximumExpandedBytes - $Written) -CollisionAction Overwrite
    $Written += $File.Length
    $Results.Add($File)
  }
  return $Results.ToArray()
}

function Expand-PaquetBuilderInstaller {
  <#
  .SYNOPSIS
    Extract Paquet Builder payload or runtime files without executing them.
  .PARAMETER Path
    Path to the installer.
  .PARAMETER DestinationPath
    Extraction root. A temporary directory is created when omitted.
  .PARAMETER Name
    Optional exact name or wildcard. Every file is selected when omitted.
  .PARAMETER ArchiveKind
    Payload, runtime resources, or both physical groups.
  .PARAMETER CollisionAction
    Behavior when an output path collides. Prompt asks only after a collision occurs.
  .PARAMETER MaximumExpandedBytes
    Aggregate maximum output bytes.
  #>
  [OutputType([IO.FileInfo[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [string]$Name = '*',
    [ValidateSet('Payload', 'Runtime', 'All')][string]$ArchiveKind = 'Payload',
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Prompt',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 17179869184L
  )

  process {
    $Data = Get-PaquetBuilderArchiveData -Path $Path -IncludeMetadata
    if ([string]::IsNullOrWhiteSpace($DestinationPath)) { $DestinationPath = Join-Path ([IO.Path]::GetTempPath()) "Dumplings-PaquetBuilder-$([guid]::NewGuid().ToString('N'))" }
    $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
    $null = New-Item -Path $DestinationPath -ItemType Directory -Force
    $Results = [Collections.Generic.List[IO.FileInfo]]::new()
    $Written = 0L

    if ($ArchiveKind -in @('Payload', 'All')) {
      if (-not $Data.Payload) { throw "Paquet Builder payload extraction is unsupported for structural route '$($Data.Profile.Id)'." }
      $TargetRoot = $ArchiveKind -eq 'All' ? (Join-Path $DestinationPath 'Payload') : $DestinationPath
      if ($Data.Profile.Id -eq 'ClassicResourcePackage') {
        $Prefix = $ArchiveKind -eq 'All' ? 'Payload' : ''
        foreach ($File in @(Export-PaquetBuilderClassicSelection -Data $Data -DestinationPath $DestinationPath -Name $Name -CollisionAction $CollisionAction -MaximumExpandedBytes ($MaximumExpandedBytes - $Written) -Prefix $Prefix)) {
          $Results.Add($File)
          $Written += $File.Length
        }
      } elseif ($Data.Profile.Id -eq 'CabinetPackageRuntime') {
        # The cabinet API requires a filesystem path, so materialize only the
        # exact ISFX-declared range and remove it immediately after extraction.
        $CabinetPath = New-TempFile
        try {
          $null = Export-InstallerArchiveRange -Path $Data.Path -Offset $Data.Payload.Range.Offset -Length $Data.Payload.Range.Length -DestinationPath $CabinetPath -CollisionAction Overwrite
          foreach ($ExtractedPath in @(Export-CabinetEntry -Path $CabinetPath -DestinationPath $TargetRoot -Name $Name -CollisionAction $CollisionAction -MaximumEntries 65536 -MaximumExpandedBytes ($MaximumExpandedBytes - $Written))) {
            $File = Get-Item -LiteralPath $ExtractedPath -Force
            $Results.Add($File)
            $Written += $File.Length
          }
        } finally {
          Remove-Item -LiteralPath $CabinetPath -Force -ErrorAction SilentlyContinue
        }
      } else {
        $Context = Open-InstallerArchiveRange -Path $Data.Path -Range $Data.Payload.Range
        try {
          $Selection = Export-InstallerArchiveSelection -Archive $Context.Archive -DestinationPath $TargetRoot -Name $Name -CollisionAction $CollisionAction -MaximumExpandedBytes ($MaximumExpandedBytes - $Written)
          foreach ($File in $Selection.Files) { $Results.Add($File) }
          $Written += $Selection.ExpandedBytes
        } finally { Close-InstallerArchiveRange -Context $Context }
      }
    }

    if ($ArchiveKind -in @('Runtime', 'All')) {
      $TargetRoot = $ArchiveKind -eq 'All' ? (Join-Path $DestinationPath 'Runtime') : $DestinationPath
      if ($Data.Runtime) {
        $Context = Open-InstallerArchiveRange -Path $Data.Path -Range $Data.Runtime.Range
        try {
          $Selection = Export-InstallerArchiveSelection -Archive $Context.Archive -DestinationPath $TargetRoot -Name $Name -CollisionAction $CollisionAction -MaximumExpandedBytes ($MaximumExpandedBytes - $Written)
          foreach ($File in $Selection.Files) { $Results.Add($File) }
          $Written += $Selection.ExpandedBytes
        } finally { Close-InstallerArchiveRange -Context $Context }
      } else {
        $Prefix = $ArchiveKind -eq 'All' ? 'Runtime' : ''
        foreach ($File in @(Export-PaquetBuilderResourceSelection -Data $Data -DestinationPath $DestinationPath -Name $Name -CollisionAction $CollisionAction -MaximumExpandedBytes ($MaximumExpandedBytes - $Written) -Prefix $Prefix)) {
          $Results.Add($File)
          $Written += $File.Length
        }
      }
    }

    if ($Results.Count -eq 0) { throw "No Paquet Builder files matched '$Name'." }
    return $Results.ToArray()
  }
}

function Test-PaquetBuilder {
  <#
  .SYNOPSIS
    Test whether a file contains a supported structural Paquet Builder layout.
  .PARAMETER Path
    Path to the candidate installer.
  #>
  [OutputType([bool])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { try { $null = Get-PaquetBuilderArchiveData -Path $Path; return $true } catch { return $false } }
}

function Read-ProtocolsFromPaquetBuilder {
  <#
  .SYNOPSIS
    Reads literal protocols from Paquet Builder registry evidence.
  .PARAMETER Path
    Path to the Paquet Builder installer.
  .OUTPUTS
    System.String[]. Literal protocol names, or an empty array when none are proven.
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-PaquetBuilderInfo -Path $Path).Protocols }
}

function Read-FileExtensionsFromPaquetBuilder {
  <#
  .SYNOPSIS
    Reads literal file extensions from Paquet Builder registry evidence.
  .PARAMETER Path
    Path to the Paquet Builder installer.
  .OUTPUTS
    System.String[]. Literal file extensions, or an empty array when none are proven.
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-PaquetBuilderInfo -Path $Path).FileExtensions }
}

function Read-ProductVersionFromPaquetBuilder {
  <#
  .SYNOPSIS
    Reads the package display version from Paquet Builder metadata.
  .PARAMETER Path
    Path to the Paquet Builder installer.
  .OUTPUTS
    System.String. The source-backed display version, or null when unresolved.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-PaquetBuilderInfo -Path $Path).DisplayVersion }
}

function Read-ProductNameFromPaquetBuilder {
  <#
  .SYNOPSIS
    Reads the package display name from Paquet Builder metadata.
  .PARAMETER Path
    Path to the Paquet Builder installer.
  .OUTPUTS
    System.String. The source-backed display name, or null when unresolved.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-PaquetBuilderInfo -Path $Path).DisplayName }
}

function Read-PublisherFromPaquetBuilder {
  <#
  .SYNOPSIS
    Reads the package publisher from Paquet Builder metadata.
  .PARAMETER Path
    Path to the Paquet Builder installer.
  .OUTPUTS
    System.String. The source-backed publisher, or null when unresolved.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-PaquetBuilderInfo -Path $Path).Publisher }
}

function Read-ProductCodeFromPaquetBuilder {
  <#
  .SYNOPSIS
    Reads a source-backed uninstall key or nested MSI ProductCode.
  .PARAMETER Path
    Path to the Paquet Builder installer.
  .OUTPUTS
    System.String. The literal uninstall identity, nested MSI ProductCode, or null when unresolved.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-PaquetBuilderInfo -Path $Path).ProductCode }
}

function Read-ScopeFromPaquetBuilder {
  <#
  .SYNOPSIS
    Reads the source-backed Paquet Builder installation scope.
  .PARAMETER Path
    Path to the Paquet Builder installer.
  .OUTPUTS
    System.String. User or machine when one scope is proven, otherwise null.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-PaquetBuilderInfo -Path $Path).Scope }
}

Export-ModuleMember -Function Get-PaquetBuilderInfo, Expand-PaquetBuilderInstaller, Test-PaquetBuilder, Read-ProtocolsFromPaquetBuilder, Read-FileExtensionsFromPaquetBuilder, Read-ProductVersionFromPaquetBuilder, Read-ProductNameFromPaquetBuilder, Read-PublisherFromPaquetBuilder, Read-ProductCodeFromPaquetBuilder, Read-ScopeFromPaquetBuilder
