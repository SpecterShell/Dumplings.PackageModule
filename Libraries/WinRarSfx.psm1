# SPDX-License-Identifier: MIT

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

function ConvertFrom-WinRarSfxConfiguration {
  <#
  .SYNOPSIS
    Parse a WinRAR GUI SFX archive comment
  .PARAMETER Content
    The decompressed WinRAR SFX comment
  .PARAMETER ArchiveEntry
    Embedded archive entry paths used to resolve launched payloads
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][AllowEmptyString()][string]$Content,
    [string[]]$ArchiveEntry = @()
  )

  $Values = [ordered]@{}
  $SetupCommands = [Collections.Generic.List[string]]::new()
  $PresetupCommands = [Collections.Generic.List[string]]::new()
  foreach ($Line in Split-LineEndings -Content $Content) {
    $Trimmed = $Line.Trim()
    if (-not $Trimmed -or $Trimmed.StartsWith(';')) { continue }
    if ($Trimmed -notmatch '^(?<Key>[^=]+?)(?:=(?<Value>.*))?$') { continue }
    $Key = $Matches.Key.Trim()
    $Value = if ($null -ne $Matches.Value) { $Matches.Value.Trim() } else { '' }
    switch -Regex ($Key) {
      '^(?i)Setup$' { $SetupCommands.Add($Value); continue }
      '^(?i)Presetup$' { $PresetupCommands.Add($Value); continue }
      default { $Values[$Key] = $Value }
    }
  }

  $Commands = [Collections.Generic.List[psobject]]::new()
  foreach ($CommandLine in $PresetupCommands) {
    $Commands.Add([pscustomobject]@{ Stage = 'Presetup'; Command = Resolve-BootstrapperCommand -CommandLine $CommandLine -CandidatePath $ArchiveEntry })
  }
  foreach ($CommandLine in $SetupCommands) {
    $Commands.Add([pscustomobject]@{ Stage = 'Setup'; Command = Resolve-BootstrapperCommand -CommandLine $CommandLine -CandidatePath $ArchiveEntry })
  }

  [pscustomobject]@{
    Values   = [pscustomobject]$Values
    Commands = @($Commands)
  }
}

function Get-WinRarSfxInfo {
  <#
  .SYNOPSIS
    Read configured commands and nested payloads from a WinRAR GUI SFX
  .PARAMETER Path
    The path to the WinRAR GUI SFX executable
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)

  process {
    $Installer = Get-Item -LiteralPath $Path -Force
    if (-not (Get-PELayout -Path $Installer.FullName)) { throw 'The file is not a valid PE executable.' }
    $Rar4Marker = [byte[]](0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00)
    $Rar5Marker = [byte[]](0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00)
    $ScanLength = [Math]::Min([long]$Installer.Length, 16777216)
    $Rar4Offset = @(Find-BinaryPattern -Path $Installer.FullName -Pattern $Rar4Marker -Length $ScanLength -Maximum 1)[0]
    $Rar5Offset = @(Find-BinaryPattern -Path $Installer.FullName -Pattern $Rar5Marker -Length $ScanLength -Maximum 1)[0]
    $ArchiveOffset = @($Rar4Offset, $Rar5Offset | Where-Object { $null -ne $_ } | Sort-Object | Select-Object -First 1)[0]
    if ($null -eq $ArchiveOffset) { throw 'The embedded RAR archive marker was not found.' }

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
      try { $Entries = @(Get-InstallerArchiveEntry -Archive $Archive) } finally { $Archive.Dispose() }
      $Comment = Read-RarArchiveComment -Path $ArchivePath
      if ([string]::IsNullOrWhiteSpace($Comment)) { throw 'The WinRAR SFX comment/configuration was not found.' }
      $Config = ConvertFrom-WinRarSfxConfiguration -Content $Comment -ArchiveEntry $Entries.FullName
    } finally {
      Remove-Item -LiteralPath $ArchivePath -Force
    }

    [pscustomobject]@{
      Path             = $Installer.FullName
      Format           = if ($null -ne $Rar5Offset -and $ArchiveOffset -eq $Rar5Offset) { 'WinRAR GUI SFX (RAR5)' } else { 'WinRAR GUI SFX (RAR4)' }
      ArchiveOffset    = $ArchiveOffset
      Configuration    = $Config.Values
      Comment          = $Comment
      Commands         = @($Config.Commands)
      ExecutedPayloads = @($Config.Commands | Where-Object { $_.Command.ExecutedPayload } | ForEach-Object { $_.Command.ExecutedPayload })
      NestedFiles      = @($Entries.FullName)
      Warnings         = @(
        if ($Config.Commands.Count -eq 0) { 'The WinRAR SFX comment does not contain Setup or Presetup commands.' }
        foreach ($Command in $Config.Commands) {
          if (-not $Command.Command.IsResolved) { "The $($Command.Stage) command did not resolve to an embedded archive entry: $($Command.Command.CommandLine)" }
        }
      )
    }
  }
}

function Expand-WinRarSfx {
  <#
  .SYNOPSIS
    Expand selected files from a WinRAR GUI SFX without executing it
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
    $Info = Get-WinRarSfxInfo -Path $Path
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
        $Entries = @(Get-InstallerArchiveEntry -Archive $Archive | Where-Object { Test-ExtractionPattern -Path $_.FullName -Pattern $Name })
        $Total = [long](($Entries | Measure-Object Length -Sum).Sum)
        if ($Total -gt $MaximumExpandedBytes) { throw 'The selected RAR entries exceed the configured output limit.' }
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

function Test-WinRarSfx {
  <#
  .SYNOPSIS
    Test whether a file is a supported WinRAR GUI SFX
  #>
  [OutputType([bool])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process {
    try { $null = Get-WinRarSfxInfo -Path $Path; return $true } catch { return $false }
  }
}

Export-ModuleMember -Function ConvertFrom-WinRarSfxConfiguration, Get-WinRarSfxInfo, Expand-WinRarSfx, Test-WinRarSfx
