# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# Force stop on error
$ErrorActionPreference = 'Stop'

# Constants
$ADVANCED_INSTALLER_MAGIC = [System.Text.Encoding]::ASCII.GetBytes('ADVINSTSFX')
$ADVANCED_INSTALLER_FOOTER_SIZE = 72
$ADVANCED_INSTALLER_FOOTER_MAGIC_OFFSET = 60
$ADVANCED_INSTALLER_FOOTER_SEARCH_BACK = 10000
$ADVANCED_INSTALLER_FILE_ENTRY_SIZE = 24
$ADVANCED_INSTALLER_XOR_HEADER_SIZE = 512
$ADVANCED_INSTALLER_BUFFER_SIZE = 81920

function Get-AdvancedInstallerAssembly {
  <#
  .SYNOPSIS
    Get a managed compression assembly used for static Advanced Installer extraction
  .PARAMETER Name
    The assembly file name under Modules\PackageModule\Assets
  #>
  [OutputType([System.IO.FileInfo])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The assembly file name under Modules\PackageModule\Assets')]
    [string]$Name
  )

  if (Test-Path -Path ($Path = Join-Path $PSScriptRoot '..' 'Assets' $Name)) {
    return Get-Item -Path $Path -Force
  } else {
    throw "The $Name assembly could not be found"
  }
}

function Import-AdvancedInstallerAssembly {
  <#
  .SYNOPSIS
    Load the managed compression assemblies used for Advanced Installer extraction
  #>

  if (-not ([System.Management.Automation.PSTypeName]'SharpCompress.Archives.ArchiveFactory').Type) {
    $LoadContext = [System.Runtime.Loader.AssemblyLoadContext]::Default

    foreach ($AssemblyName in @('ZstdSharp.dll', 'SharpCompress.dll')) {
      $AssemblyPath = (Get-AdvancedInstallerAssembly -Name $AssemblyName).FullName
      $AssemblySimpleName = [System.IO.Path]::GetFileNameWithoutExtension($AssemblyName)

      if (-not [AppDomain]::CurrentDomain.GetAssemblies().Where({ $_.GetName().Name -eq $AssemblySimpleName }, 'First')) {
        $LoadContext.LoadFromAssemblyPath($AssemblyPath) | Out-Null
      }
    }
  }
}

Import-AdvancedInstallerAssembly

function Import-AdvancedInstallerMsiModule {
  <#
  .SYNOPSIS
    Load the MSI helper module required to read embedded MSI metadata
  #>

  if (-not (Get-Command -Name 'Read-ProductVersionFromMsi' -ErrorAction SilentlyContinue)) {
    Import-Module (Join-Path $PSScriptRoot 'MSI.psm1') -Force
  }
}

function Find-AdvancedInstallerBytePattern {
  <#
  .SYNOPSIS
    Find the last occurrence of a byte pattern in a byte array
  .PARAMETER Bytes
    The bytes to search
  .PARAMETER Pattern
    The byte pattern to find
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The bytes to search')]
    [byte[]]$Bytes,

    [Parameter(Mandatory, HelpMessage = 'The byte pattern to find')]
    [byte[]]$Pattern
  )

  for ($Index = $Bytes.Length - $Pattern.Length; $Index -ge 0; $Index--) {
    $Matched = $true

    for ($PatternIndex = 0; $PatternIndex -lt $Pattern.Length; $PatternIndex++) {
      if ($Bytes[$Index + $PatternIndex] -ne $Pattern[$PatternIndex]) {
        $Matched = $false
        break
      }
    }

    if ($Matched) { return $Index }
  }

  return -1
}

function Resolve-AdvancedInstallerExtractionPath {
  <#
  .SYNOPSIS
    Resolve a payload-relative path under the extraction root and block path traversal
  .PARAMETER DestinationPath
    The extraction root
  .PARAMETER RelativePath
    The payload-relative path from the installer metadata
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The extraction root')]
    [string]$DestinationPath,

    [Parameter(Mandatory, HelpMessage = 'The payload-relative path from the installer metadata')]
    [string]$RelativePath
  )

  $DestinationPath = [System.IO.Path]::GetFullPath((Get-Item -Path $DestinationPath -Force).FullName)
  $RelativePath = $RelativePath -replace '/', '\'
  $RelativePath = $RelativePath.TrimStart('\')

  if ([System.IO.Path]::IsPathRooted($RelativePath)) { throw 'Advanced Installer extraction does not allow rooted payload paths' }

  # The installer can embed nested folders. Keep them relative to the extraction root only.
  $TargetPath = [System.IO.Path]::GetFullPath((Join-Path $DestinationPath $RelativePath))
  $DestinationPrefix = if ($DestinationPath.EndsWith('\')) { $DestinationPath } else { "${DestinationPath}\" }

  if (-not $TargetPath.StartsWith($DestinationPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Advanced Installer extraction blocked a path traversal attempt: $RelativePath"
  }

  return $TargetPath
}

function Write-AdvancedInstallerStream {
  <#
  .SYNOPSIS
    Copy an exact byte range from a source stream to a destination stream
  .PARAMETER SourceStream
    The source stream
  .PARAMETER DestinationStream
    The destination stream
  .PARAMETER Length
    The number of bytes to copy
  #>
  param (
    [Parameter(Mandatory, HelpMessage = 'The source stream')]
    [System.IO.Stream]$SourceStream,

    [Parameter(Mandatory, HelpMessage = 'The destination stream')]
    [System.IO.Stream]$DestinationStream,

    [Parameter(Mandatory, HelpMessage = 'The number of bytes to copy')]
    [long]$Length
  )

  $Buffer = New-Object 'byte[]' $Script:ADVANCED_INSTALLER_BUFFER_SIZE
  $Remaining = $Length

  while ($Remaining -gt 0) {
    $ChunkSize = [int][Math]::Min($Buffer.Length, $Remaining)
    $Read = $SourceStream.Read($Buffer, 0, $ChunkSize)
    if ($Read -le 0) { throw 'Unexpected end of stream while extracting an Advanced Installer payload' }
    $DestinationStream.Write($Buffer, 0, $Read)
    $Remaining -= $Read
  }
}

function Write-AdvancedInstallerEntry {
  <#
  .SYNOPSIS
    Extract a single embedded Advanced Installer payload to disk
  .PARAMETER Path
    The path to the installer
  .PARAMETER Entry
    The parsed Advanced Installer payload entry
  .PARAMETER DestinationPath
    The target file path
  #>
  [OutputType([System.IO.FileInfo])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path,

    [Parameter(Mandatory, HelpMessage = 'The parsed Advanced Installer payload entry')]
    [psobject]$Entry,

    [Parameter(Mandatory, HelpMessage = 'The target file path')]
    [string]$DestinationPath
  )

  $null = New-Item -Path ([System.IO.Path]::GetDirectoryName($DestinationPath)) -ItemType Directory -Force

  $SourceStream = [System.IO.File]::OpenRead((Get-Item -Path $Path -Force).FullName)
  $DestinationStream = [System.IO.File]::Open($DestinationPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)

  try {
    $null = $SourceStream.Seek($Entry.Offset, 'Begin')

    # Advanced Installer marks some payloads with an XOR-obfuscated header. Only the leading block is transformed.
    $DecodedHeaderLength = [int][Math]::Min([long]$Entry.XorLength, [long]$Entry.Size)
    if ($DecodedHeaderLength -gt 0) {
      $HeaderBytes = New-Object 'byte[]' $DecodedHeaderLength
      $Read = $SourceStream.Read($HeaderBytes, 0, $DecodedHeaderLength)
      if ($Read -ne $DecodedHeaderLength) { throw 'Unexpected end of stream while decoding an Advanced Installer payload header' }
      for ($Index = 0; $Index -lt $DecodedHeaderLength; $Index++) {
        $HeaderBytes[$Index] = $HeaderBytes[$Index] -bxor 0xFF
      }
      $DestinationStream.Write($HeaderBytes, 0, $HeaderBytes.Length)
    }

    Write-AdvancedInstallerStream -SourceStream $SourceStream -DestinationStream $DestinationStream -Length ($Entry.Size - $DecodedHeaderLength)
    return Get-Item -Path $DestinationPath -Force
  } finally {
    $DestinationStream.Close()
    $SourceStream.Close()
  }
}

function Expand-AdvancedInstallerArchive {
  <#
  .SYNOPSIS
    Expand a nested 7z payload produced by Advanced Installer
  .PARAMETER Path
    The path to the extracted archive
  .PARAMETER DestinationPath
    The directory where the archive contents should be written
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the extracted archive')]
    [string]$Path,

    [Parameter(Mandatory, HelpMessage = 'The directory where the archive contents should be written')]
    [string]$DestinationPath
  )

  $null = New-Item -Path $DestinationPath -ItemType Directory -Force
  $Archive = [SharpCompress.Archives.ArchiveFactory]::Open((Get-Item -Path $Path -Force).FullName)

  try {
    foreach ($ArchiveEntry in $Archive.Entries.Where({ -not $_.IsDirectory })) {
      $ArchiveEntryPath = Resolve-AdvancedInstallerExtractionPath -DestinationPath $DestinationPath -RelativePath $ArchiveEntry.Key
      $null = New-Item -Path ([System.IO.Path]::GetDirectoryName($ArchiveEntryPath)) -ItemType Directory -Force

      try {
        $EntryStream = $ArchiveEntry.OpenEntryStream()
      } catch {
        if ($ArchiveEntry.Size -eq 0 -and $_.Exception.Message -match 'does not have a stream') {
          [System.IO.File]::Open($ArchiveEntryPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read).Close()
          continue
        }
        throw
      }

      $FileStream = [System.IO.File]::Open($ArchiveEntryPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)

      try {
        $EntryStream.CopyTo($FileStream)
      } finally {
        $FileStream.Close()
        $EntryStream.Close()
      }
    }

    return (Get-Item -Path $DestinationPath -Force).FullName
  } finally {
    $Archive.Dispose()
  }
}

function Test-AdvancedInstallerArchiveHasMsi {
  <#
  .SYNOPSIS
    Test whether a nested Advanced Installer archive contains MSI payloads
  .PARAMETER Path
    The path to the extracted archive
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the extracted archive')]
    [string]$Path
  )

  $Archive = [SharpCompress.Archives.ArchiveFactory]::Open((Get-Item -Path $Path -Force).FullName)
  try {
    return [bool]$Archive.Entries.Where({ -not $_.IsDirectory -and $_.Key -like '*.msi' }, 'First')
  } finally {
    $Archive.Dispose()
  }
}

function Resolve-AdvancedInstallerMatch {
  <#
  .SYNOPSIS
    Resolve a deterministic payload match from an Advanced Installer extraction
  .PARAMETER Item
    The collection to search
  .PARAMETER Pattern
    The file name or wildcard pattern
  #>
  [OutputType([System.IO.FileInfo])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The collection to search')]
    [System.IO.FileInfo[]]$Item,

    [Parameter(Mandatory, HelpMessage = 'The file name or wildcard pattern')]
    [string]$Pattern
  )

  $Match = $Item.Where({ $_.Name -like $Pattern -or $_.FullName -like "*\$Pattern" })
  if (-not $Match) { throw "No MSI files matched the Advanced Installer pattern: $Pattern" }

  $ExactMatches = $Match.Where({ $_.Name -eq $Pattern -or $_.FullName.EndsWith($Pattern, [System.StringComparison]::OrdinalIgnoreCase) })
  if ($ExactMatches.Count -eq 1) { return $ExactMatches[0] }
  if ($Match.Count -eq 1) { return $Match[0] }

  throw "Multiple MSI files matched the Advanced Installer pattern: $Pattern"
}

function New-AdvancedInstallerTempFolder {
  <#
  .SYNOPSIS
    Create a temporary directory for transient Advanced Installer extraction work
  #>
  [OutputType([string])]
  param ()

  $Path = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString('N'))
  $null = New-Item -Path $Path -ItemType Directory -Force
  return $Path
}

function Get-AdvancedInstallerInfo {
  <#
  .SYNOPSIS
    Get metadata from an Advanced Installer executable
  .PARAMETER Path
    The path to the installer
  .LINK
    https://raw.githubusercontent.com/HydraDragonAntivirus/HydraDragonAntivirus/refs/heads/development-version/hydradragon/decompilers/advancedInstallerExtractor.py
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path
  )

  process {
    $InstallerPath = (Get-Item -Path $Path -Force).FullName
    $Stream = [System.IO.File]::OpenRead($InstallerPath)
    $Reader = [System.IO.BinaryReader]::new($Stream)

    try {
      $SearchWindowSize = [int][Math]::Min($Stream.Length, $Script:ADVANCED_INSTALLER_FOOTER_SEARCH_BACK + $Script:ADVANCED_INSTALLER_FOOTER_SIZE)
      $SearchWindowOffset = $Stream.Length - $SearchWindowSize
      $null = $Stream.Seek($SearchWindowOffset, 'Begin')
      $SearchWindowBytes = $Reader.ReadBytes($SearchWindowSize)

      $MagicOffset = Find-AdvancedInstallerBytePattern -Bytes $SearchWindowBytes -Pattern $Script:ADVANCED_INSTALLER_MAGIC
      if ($MagicOffset -lt 0) { throw 'The installer does not contain an Advanced Installer footer' }

      # The footer stores the ADVINSTSFX marker near the end of the record.
      $FooterOffset = $SearchWindowOffset + $MagicOffset - $Script:ADVANCED_INSTALLER_FOOTER_MAGIC_OFFSET
      if ($FooterOffset -lt 0) { throw 'The Advanced Installer footer offset is invalid' }

      $null = $Stream.Seek($FooterOffset, 'Begin')
      $FooterBytes = $Reader.ReadBytes($Script:ADVANCED_INSTALLER_FOOTER_SIZE)
      if ($FooterBytes.Length -ne $Script:ADVANCED_INSTALLER_FOOTER_SIZE) { throw 'The Advanced Installer footer is truncated' }

      $FooterMagic = [System.Text.Encoding]::ASCII.GetString($FooterBytes, $Script:ADVANCED_INSTALLER_FOOTER_MAGIC_OFFSET, $Script:ADVANCED_INSTALLER_MAGIC.Length)
      if ($FooterMagic -ne 'ADVINSTSFX') { throw 'The Advanced Installer footer signature is invalid' }

      $FileCount = [System.BitConverter]::ToUInt32($FooterBytes, 4)
      $InfoOffset = [System.BitConverter]::ToUInt32($FooterBytes, 16)
      $FileOffset = [System.BitConverter]::ToUInt32($FooterBytes, 20)

      $null = $Stream.Seek($InfoOffset, 'Begin')
      $Files = [System.Collections.Generic.List[object]]::new()

      for ($Index = 0; $Index -lt $FileCount; $Index++) {
        $EntryBytes = $Reader.ReadBytes($Script:ADVANCED_INSTALLER_FILE_ENTRY_SIZE)
        if ($EntryBytes.Length -ne $Script:ADVANCED_INSTALLER_FILE_ENTRY_SIZE) { throw 'The Advanced Installer file table is truncated' }

        $XorFlag = [System.BitConverter]::ToUInt32($EntryBytes, 8)
        $EntrySize = [System.BitConverter]::ToUInt32($EntryBytes, 12)
        $EntryOffset = [System.BitConverter]::ToUInt32($EntryBytes, 16)
        $NameLength = [int][System.BitConverter]::ToUInt32($EntryBytes, 20)
        if ($NameLength -lt 0) { throw 'The Advanced Installer payload name length is invalid' }

        $NameBytes = $Reader.ReadBytes($NameLength * 2)
        if ($NameBytes.Length -ne ($NameLength * 2)) { throw 'The Advanced Installer payload name is truncated' }

        $Name = if ($NameLength -eq 0) { "unnamed_file_${Index}.bin" } else { [System.Text.Encoding]::Unicode.GetString($NameBytes).TrimEnd([char]0) }

        $Files.Add([pscustomobject]@{
            Name      = $Name
            Size      = [long]$EntrySize
            Offset    = [long]$EntryOffset
            XorLength = $XorFlag -eq 2 ? $Script:ADVANCED_INSTALLER_XOR_HEADER_SIZE : 0
          })
      }

      return [pscustomobject]@{
        InstallerType = 'AdvancedInstaller'
        Path          = $InstallerPath
        FooterOffset  = [long]$FooterOffset
        FileOffset    = [long]$FileOffset
        FileCount     = [int]$FileCount
        Files         = $Files
      }
    } finally {
      $Reader.Close()
      $Stream.Close()
    }
  }
}

function Expand-AdvancedInstaller {
  <#
  .SYNOPSIS
    Extract the embedded payloads from an Advanced Installer executable
  .PARAMETER Path
    The path to the installer
  .PARAMETER Installer
    The parsed Advanced Installer metadata object
  .PARAMETER DestinationPath
    The destination directory for the extracted payloads
  #>
  [OutputType([string])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Installer', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The parsed Advanced Installer metadata object')]
    [psobject]$Installer,

    [Parameter(HelpMessage = 'The destination directory for the extracted payloads')]
    [string]$DestinationPath
  )

  process {
    Import-AdvancedInstallerMsiModule

    $Installer = switch ($PSCmdlet.ParameterSetName) {
      'Path' { Get-AdvancedInstallerInfo -Path $Path }
      'Installer' { $Installer }
      default { throw 'Invalid parameter set.' }
    }

    if ([string]::IsNullOrWhiteSpace($DestinationPath)) {
      $DestinationPath = Split-Path -Path $Installer.Path -Parent
    }
    $null = New-Item -Path $DestinationPath -ItemType Directory -Force

    foreach ($Entry in $Installer.Files) {
      $EntryPath = Resolve-AdvancedInstallerExtractionPath -DestinationPath $DestinationPath -RelativePath $Entry.Name
      $EntryFile = Write-AdvancedInstallerEntry -Path $Installer.Path -Entry $Entry -DestinationPath $EntryPath

      # Advanced Installer commonly nests the actual MSI payload inside a dedicated 7z archive.
      # Skip non-MSI archives such as FILES.7z to keep validation and task runs bounded.
      if ($EntryFile.Extension -ieq '.7z' -and (Test-AdvancedInstallerArchiveHasMsi -Path $EntryFile.FullName)) {
        Expand-AdvancedInstallerArchive -Path $EntryFile.FullName -DestinationPath $EntryFile.DirectoryName | Out-Null
      }
    }

    return (Get-Item -Path $DestinationPath -Force).FullName
  }
}

function Get-AdvancedInstallerMsiInfo {
  <#
  .SYNOPSIS
    Read MSI metadata from a statically extracted Advanced Installer payload
  .PARAMETER Path
    The path to the installer
  .PARAMETER Installer
    The parsed Advanced Installer metadata object
  .PARAMETER Name
    The MSI file name or wildcard pattern to locate after extraction
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Installer', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The parsed Advanced Installer metadata object')]
    [psobject]$Installer,

    [Parameter(HelpMessage = 'The MSI file name or wildcard pattern to locate after extraction')]
    [string]$Name = '*.msi'
  )

  process {
    $Installer = switch ($PSCmdlet.ParameterSetName) {
      'Path' { Get-AdvancedInstallerInfo -Path $Path }
      'Installer' { $Installer }
      default { throw 'Invalid parameter set.' }
    }

    $ExpandedPath = New-AdvancedInstallerTempFolder

    try {
      Expand-AdvancedInstaller -Installer $Installer -DestinationPath $ExpandedPath | Out-Null
      $MsiFiles = @(Get-ChildItem -Path $ExpandedPath -Filter '*.msi' -Recurse -File)
      $MsiFile = Resolve-AdvancedInstallerMatch -Item $MsiFiles -Pattern $Name

      return [pscustomobject]@{
        Name           = $MsiFile.Name
        Path           = $MsiFile.FullName
        ProductVersion = $MsiFile.FullName | Read-ProductVersionFromMsi
        ProductCode    = $MsiFile.FullName | Read-ProductCodeFromMsi
        UpgradeCode    = $MsiFile.FullName | Read-UpgradeCodeFromMsi
      }
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction 'Continue' -ProgressAction 'SilentlyContinue'
    }
  }
}

function Read-ProductVersionFromAdvancedInstaller {
  <#
  .SYNOPSIS
    Read the ProductVersion property value from the MSI payload inside an Advanced Installer executable
  .PARAMETER Path
    The path to the installer
  .PARAMETER Installer
    The parsed Advanced Installer metadata object
  .PARAMETER Name
    The MSI file name or wildcard pattern to locate after extraction
  #>
  [OutputType([string])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Installer', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The parsed Advanced Installer metadata object')]
    [psobject]$Installer,

    [Parameter(HelpMessage = 'The MSI file name or wildcard pattern to locate after extraction')]
    [string]$Name = '*.msi'
  )

  process {
    (Get-AdvancedInstallerMsiInfo @PSBoundParameters).ProductVersion
  }
}

function Read-ProductCodeFromAdvancedInstaller {
  <#
  .SYNOPSIS
    Read the ProductCode property value from the MSI payload inside an Advanced Installer executable
  .PARAMETER Path
    The path to the installer
  .PARAMETER Installer
    The parsed Advanced Installer metadata object
  .PARAMETER Name
    The MSI file name or wildcard pattern to locate after extraction
  #>
  [OutputType([string])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Installer', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The parsed Advanced Installer metadata object')]
    [psobject]$Installer,

    [Parameter(HelpMessage = 'The MSI file name or wildcard pattern to locate after extraction')]
    [string]$Name = '*.msi'
  )

  process {
    (Get-AdvancedInstallerMsiInfo @PSBoundParameters).ProductCode
  }
}

function Read-UpgradeCodeFromAdvancedInstaller {
  <#
  .SYNOPSIS
    Read the UpgradeCode property value from the MSI payload inside an Advanced Installer executable
  .PARAMETER Path
    The path to the installer
  .PARAMETER Installer
    The parsed Advanced Installer metadata object
  .PARAMETER Name
    The MSI file name or wildcard pattern to locate after extraction
  #>
  [OutputType([string])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Installer', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The parsed Advanced Installer metadata object')]
    [psobject]$Installer,

    [Parameter(HelpMessage = 'The MSI file name or wildcard pattern to locate after extraction')]
    [string]$Name = '*.msi'
  )

  process {
    (Get-AdvancedInstallerMsiInfo @PSBoundParameters).UpgradeCode
  }
}

Export-ModuleMember -Function Get-AdvancedInstallerInfo, Expand-AdvancedInstaller, Get-AdvancedInstallerMsiInfo, Read-ProductVersionFromAdvancedInstaller, Read-ProductCodeFromAdvancedInstaller, Read-UpgradeCodeFromAdvancedInstaller
