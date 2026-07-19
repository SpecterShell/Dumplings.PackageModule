# SPDX-License-Identifier: Apache-2.0
# Format source: https://github.com/ip7z/7zip/blob/main/CPP/7zip/Bundles/SFXSetup/SfxSetup.cpp
# 7z SFX binary structure consumed here:
#
#   PE SFX stub -> ";!@Install@!UTF-8!" configuration
#     -> UTF-8 key/value records -> ";!@InstallEnd@!"
#     -> 37 7A BC AF 27 1C standard 7z archive and catalog
#
# RunProgram/ExecuteFile/AutoInstall values point to archive entries and arguments;
# they are not physically adjacent payloads. Config and archive searches are
# bounded, and extraction uses shared safe-path/count/output checks.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

function Resolve-SevenZipSfxConfiguredCommand {
  <#
  .SYNOPSIS
    Remove 7zSFX execution prefixes and resolve the remaining command
  .PARAMETER CommandLine
    Raw text to parse as format metadata without executing embedded commands.
  .PARAMETER ArchiveEntry
    Validated archive or catalog entry whose bounded content is read or exported.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$CommandLine,
    [string[]]$ArchiveEntry = @()
  )

  $Prefixes = [Collections.Generic.List[string]]::new()
  $EffectiveCommand = $CommandLine

  # Strip only the execution-mode prefixes recognized by the upstream SFX
  # runtime; preserve them separately because they affect window/wait behavior.
  while ($EffectiveCommand -match '^(?<Prefix>(?i:hidcon|nowait|fm\d+)):(?<Command>.*)$') {
    $Prefixes.Add($Matches.Prefix)
    $EffectiveCommand = $Matches.Command
  }
  [pscustomobject]@{
    ConfiguredCommand = $CommandLine
    ExecutionPrefixes = @($Prefixes)
    Command           = Resolve-BootstrapperCommand -CommandLine $EffectiveCommand -CandidatePath $ArchiveEntry
  }
}

function ConvertFrom-SevenZipSfxConfiguration {
  <#
  .SYNOPSIS
    Parse a 7-Zip SFX UTF-8 configuration block
  .PARAMETER Content
    The text between the 7-Zip SFX configuration markers
  .PARAMETER ArchiveEntry
    Embedded archive entry paths used to resolve the launched payload
  .LINK
    https://github.com/ip7z/7zip/blob/main/CPP/7zip/Bundles/SFXSetup/SfxSetup.cpp
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][AllowEmptyString()][string]$Content,
    [string[]]$ArchiveEntry = @()
  )

  $Values = [ordered]@{}
  $Entries = [Collections.Generic.List[psobject]]::new()

  # Retain duplicate ordered records as well as last-value lookup semantics:
  # RunProgram and AutoInstall may legally appear more than once.
  foreach ($Line in Split-LineEndings -Content $Content) {
    $Trimmed = $Line.Trim()
    if (-not $Trimmed -or $Trimmed.StartsWith(';')) { continue }
    if ($Trimmed -notmatch '^(?<Key>[A-Za-z][A-Za-z0-9]*)\s*=\s*"(?<Value>(?:\\.|[^"])*)"\s*$') { continue }
    $Value = $Matches.Value
    $Value = $Value.Replace('\n', "`n").Replace('\t', "`t").Replace('\"', '"').Replace('\\', '\')
    $Key = $Matches.Key
    $Values[$Key] = $Value
    $Entries.Add([pscustomobject]@{ Key = $Key; Value = $Value })
  }

  $Commands = [Collections.Generic.List[psobject]]::new()

  # SfxSetup gives ExecuteFile/ExecuteParameters precedence over RunProgram;
  # when neither is authored it falls back to setup.exe.
  if ($Values.ExecuteFile) {
    $CommandLine = '"' + $Values.ExecuteFile + '"'
    if ($Values.ExecuteParameters) { $CommandLine += ' ' + $Values.ExecuteParameters }
    $Commands.Add([pscustomobject]@{
        Source  = 'ExecuteFile'
        Trigger = 'default'
        Detail  = Resolve-SevenZipSfxConfiguredCommand -CommandLine $CommandLine -ArchiveEntry $ArchiveEntry
      })
  } else {
    $RunPrograms = @($Entries | Where-Object Key -EQ 'RunProgram')
    if ($RunPrograms.Count -gt 0) {
      foreach ($RunProgram in $RunPrograms) {
        $Commands.Add([pscustomobject]@{
            Source  = 'RunProgram'
            Trigger = 'default'
            Detail  = Resolve-SevenZipSfxConfiguredCommand -CommandLine $RunProgram.Value -ArchiveEntry $ArchiveEntry
          })
      }
    } else {
      $Commands.Add([pscustomobject]@{
          Source  = 'DefaultRunProgram'
          Trigger = 'default'
          Detail  = Resolve-SevenZipSfxConfiguredCommand -CommandLine 'setup.exe' -ArchiveEntry $ArchiveEntry
        })
    }
  }

  # AutoInstall records are alternate entry points selected by -ai or -aiX,
  # not commands that run during the default installation path.
  foreach ($AutoInstall in @($Entries | Where-Object { $_.Key -match '^(?i)AutoInstall(?<Scenario>[0-9A-Za-z]?)$' })) {
    $Scenario = [regex]::Match($AutoInstall.Key, '^(?i)AutoInstall(?<Scenario>[0-9A-Za-z]?)$').Groups['Scenario'].Value
    $Commands.Add([pscustomobject]@{
        Source  = $AutoInstall.Key
        Trigger = if ($Scenario) { "-ai$Scenario" } else { '-ai' }
        Detail  = Resolve-SevenZipSfxConfiguredCommand -CommandLine $AutoInstall.Value -ArchiveEntry $ArchiveEntry
      })
  }
  $Primary = @($Commands | Where-Object Trigger -EQ 'default' | Select-Object -First 1)[0]

  [pscustomobject]@{
    Values                    = [pscustomobject]$Values
    Entries                   = @($Entries)
    Commands                  = @($Commands)
    CommandSource             = $Primary.Source
    Command                   = $Primary.Detail.Command
    PassesAdditionalArguments = $true
  }
}

function Get-SevenZipSfxInfo {
  <#
  .SYNOPSIS
    Read the configured command and nested payload from a 7-Zip SFX
  .PARAMETER Path
    The path to the 7-Zip SFX executable
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)

  process {
    $Installer = Get-Item -LiteralPath $Path -Force
    if (-not (Get-PELayout -Path $Installer.FullName)) { throw 'The file is not a valid PE executable.' }
    $StartMarker = [Text.Encoding]::ASCII.GetBytes(';!@Install@!UTF-8!')
    $EndMarker = [Text.Encoding]::ASCII.GetBytes(';!@InstallEnd@!')
    $ArchiveMarker = [byte[]](0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C)
    # The upstream SFX module searches for its configuration in the first 2 MiB.
    $ScanLength = [Math]::Min([long]$Installer.Length, 2097152)

    # Locate a complete bounded marker pair before accepting the following 7z
    # signature as the configured payload archive.
    $ConfigStart = @(Find-BinaryPattern -Path $Installer.FullName -Pattern $StartMarker -Length $ScanLength -Maximum 1)[0]
    if ($null -eq $ConfigStart) { throw 'The 7-Zip SFX configuration marker was not found.' }
    $ContentStart = $ConfigStart + $StartMarker.Length
    $ConfigEnd = @(Find-BinaryPattern -Path $Installer.FullName -Pattern $EndMarker -StartOffset $ContentStart -Length ([Math]::Min(2097152, $Installer.Length - $ContentStart)) -Maximum 1)[0]
    if ($null -eq $ConfigEnd) { throw 'The 7-Zip SFX configuration end marker was not found.' }
    $ArchiveOffset = @(Find-BinaryPattern -Path $Installer.FullName -Pattern $ArchiveMarker -StartOffset ($ConfigEnd + $EndMarker.Length) -Length ($Installer.Length - ($ConfigEnd + $EndMarker.Length)) -Maximum 1)[0]
    if ($null -eq $ArchiveOffset) { throw 'The embedded 7-Zip archive marker was not found.' }

    $Stream = [IO.File]::OpenRead($Installer.FullName)
    try {
      $ContentBytes = Read-BinaryBytes -Stream $Stream -Offset $ContentStart -Count ([int]($ConfigEnd - $ContentStart))
    } finally {
      $Stream.Dispose()
    }
    $Content = [Text.Encoding]::UTF8.GetString($ContentBytes).Trim([char]0, "`r", "`n")

    # Materialize only the archive range because SharpCompress needs a container
    # beginning at offset zero; the original installer remains read-only.
    $ArchivePath = New-TempFile
    $InputStream = [IO.File]::OpenRead($Installer.FullName)
    $OutputStream = [IO.File]::Open($ArchivePath, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
      Copy-BinaryStreamRange -Source $InputStream -Destination $OutputStream -Offset $ArchiveOffset -Length ($Installer.Length - $ArchiveOffset)
    } finally {
      $OutputStream.Dispose()
      $InputStream.Dispose()
    }
    try {
      $Archive = Get-InstallerArchive -Path $ArchivePath
      try {
        # Resolve commands only after catalog enumeration so configured payload
        # names can be distinguished from arbitrary command tokens.
        $Entries = @(Get-InstallerArchiveEntry -Archive $Archive)
        $Config = ConvertFrom-SevenZipSfxConfiguration -Content $Content -ArchiveEntry $Entries.FullName
      } finally {
        $Archive.Dispose()
      }
    } finally {
      Remove-Item -LiteralPath $ArchivePath -Force
    }

    [pscustomobject]@{
      Path                      = $Installer.FullName
      Format                    = '7z SFX'
      ConfigOffset              = $ConfigStart
      ArchiveOffset             = $ArchiveOffset
      Configuration             = $Config.Values
      CommandSource             = $Config.CommandSource
      CommandLine               = $Config.Command.CommandLine
      ExecutedPayload           = $Config.Command.ExecutedPayload
      ExecutedPayloads          = @($Config.Commands | Where-Object { $_.Detail.Command.ExecutedPayload } | ForEach-Object { $_.Detail.Command.ExecutedPayload } | Select-Object -Unique)
      PayloadReference          = $Config.Command.PayloadReference
      PayloadArguments          = $Config.Command.ArgumentList
      Commands                  = $Config.Commands
      PassesAdditionalArguments = $Config.PassesAdditionalArguments
      NestedFiles               = @($Entries.FullName)
      Warnings                  = @(
        foreach ($Command in $Config.Commands) {
          if (-not $Command.Detail.Command.IsResolved) { "The $($Command.Source) command did not resolve to an embedded archive entry: $($Command.Detail.Command.CommandLine)" }
        }
      )
    }
  }
}

function Expand-SevenZipSfx {
  <#
  .SYNOPSIS
    Expand selected files from a 7-Zip SFX without executing it
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER DestinationPath
    Destination path for bounded extraction or decoded output; payload-relative names are resolved beneath this path.
  .PARAMETER Name
    Exact name or wildcard used to select format records or payload entries.
  .PARAMETER MaximumExpandedBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [string]$Name = '*',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 17179869184
  )

  process {
    if (-not $DestinationPath) { $DestinationPath = New-TempFolder }
    $Info = Get-SevenZipSfxInfo -Path $Path
    $Installer = Get-Item -LiteralPath $Path -Force
    $ArchivePath = New-TempFile
    $InputStream = [IO.File]::OpenRead($Installer.FullName)
    $OutputStream = [IO.File]::Open($ArchivePath, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
      Copy-BinaryStreamRange -Source $InputStream -Destination $OutputStream -Offset $Info.ArchiveOffset -Length ($Installer.Length - $Info.ArchiveOffset)
    } finally {
      $OutputStream.Dispose()
      $InputStream.Dispose()
    }
    try {
      $Archive = Get-InstallerArchive -Path $ArchivePath
      try {
        # Calculate selected output before writing and resolve each archive name
        # beneath the caller destination to reject traversal.
        $Entries = @(Get-InstallerArchiveEntry -Archive $Archive | Where-Object { Test-ExtractionPattern -Path $_.FullName -Pattern $Name })
        $Total = [long](($Entries | Measure-Object Length -Sum).Sum)
        if ($Total -gt $MaximumExpandedBytes) { throw 'The selected 7-Zip entries exceed the configured output limit.' }
        foreach ($Entry in $Entries) {
          $OutputPath = Resolve-SafeExtractionPath -DestinationPath $DestinationPath -RelativePath $Entry.FullName
          (Export-InstallerArchiveEntry -Entry $Entry -DestinationPath $OutputPath -MaximumBytes $MaximumExpandedBytes).FullName
        }
      } finally {
        $Archive.Dispose()
      }
    } finally {
      Remove-Item -LiteralPath $ArchivePath -Force
    }
  }
}

function Test-SevenZipSfx {
  <#
  .SYNOPSIS
    Test whether a file is a supported 7-Zip SFX
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([bool])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process {
    try { $null = Get-SevenZipSfxInfo -Path $Path; return $true } catch { return $false }
  }
}

Export-ModuleMember -Function Resolve-SevenZipSfxConfiguredCommand, ConvertFrom-SevenZipSfxConfiguration, Get-SevenZipSfxInfo, Expand-SevenZipSfx, Test-SevenZipSfx
