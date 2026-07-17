# SPDX-License-Identifier: MIT
# Format sources: https://github.com/Squirrel/Squirrel.Windows and https://github.com/velopack/velopack

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# Force stop on error
$ErrorActionPreference = 'Stop'

$Script:SquirrelBundleSignature = [byte[]](
  0x94, 0xF0, 0xB1, 0x7B, 0x68, 0x93, 0xE0, 0x29,
  0x37, 0xEB, 0x34, 0xEF, 0x53, 0xAA, 0xE7, 0xD4,
  0x2B, 0x54, 0xF5, 0x70, 0x7E, 0xF5, 0xD6, 0xF5,
  0x78, 0x54, 0x98, 0x3E, 0x5E, 0x94, 0xED, 0x7D
)

$Script:SquirrelResourceType = 'DATA'
$Script:SquirrelResourceId = 131

function Get-SquirrelPeResourceZipCandidate {
  <#
  .SYNOPSIS
    Find the embedded Squirrel update ZIP stored in the setup PE resources
  .PARAMETER Path
    The path to the installer
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path
  )

  foreach ($Resource in Get-PEResourceInfo -Path $Path) {
    if ($Resource.TypeName -eq $Script:SquirrelResourceType -and $Resource.Id -eq $Script:SquirrelResourceId -and $Resource.Size -gt 0) {
      [pscustomobject]@{ Offset = [long]$Resource.Offset; Length = [long]$Resource.Size }
    }
  }
}

function Find-SquirrelBytePattern {
  <#
  .SYNOPSIS
    Find byte pattern offsets inside a file
  .PARAMETER Path
    The path to scan
  .PARAMETER Pattern
    The byte pattern to locate
  .PARAMETER Maximum
    The maximum number of offsets to return
  #>
  [OutputType([long[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to scan')]
    [string]$Path,

    [Parameter(Mandatory, HelpMessage = 'The byte pattern to locate')]
    [byte[]]$Pattern,

    [Parameter(HelpMessage = 'The maximum number of offsets to return')]
    [int]$Maximum = 128,

    [Parameter(HelpMessage = 'The maximum number of bytes to scan')]
    [long]$MaximumBytes = 0
  )

  $Length = if ($MaximumBytes -gt 0) { $MaximumBytes } else { 0 }
  Find-BinaryPattern -Path $Path -Pattern $Pattern -Length $Length -Maximum $Maximum
}

function Get-SquirrelBundleHeader {
  <#
  .SYNOPSIS
    Read the Velopack setup bundle header if present
  .PARAMETER Path
    The path to the installer
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path
  )

  $File = Get-Item -Path $Path -Force
  # Velopack stores the bundle placeholder in the setup launcher, so a bounded
  # front scan avoids penalizing ordinary Squirrel installers with large payloads.
  foreach ($SignatureOffset in Find-SquirrelBytePattern -Path $File.FullName -Pattern $Script:SquirrelBundleSignature -Maximum 8 -MaximumBytes 16777216) {
    if ($SignatureOffset -lt 16) { continue }

    $Stream = [System.IO.File]::Open($File.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
      $HeaderBytes = Read-BinaryBytes -Stream $Stream -Offset ($SignatureOffset - 16) -Count 16

      $Offset = [System.BitConverter]::ToInt64($HeaderBytes, 0)
      $Length = [System.BitConverter]::ToInt64($HeaderBytes, 8)
      if ($Offset -gt 0 -and $Length -gt 0 -and $Offset + $Length -le $File.Length) {
        return [pscustomobject]@{
          Offset = $Offset
          Length = $Length
        }
      }
    } finally {
      $Stream.Dispose()
    }
  }
}

function Get-SquirrelZipLocalHeaderOffset {
  <#
  .SYNOPSIS
    Find candidate ZIP local file headers inside an installer
  .PARAMETER Path
    The path to the installer
  .PARAMETER Maximum
    The maximum number of candidate offsets to return
  #>
  [OutputType([long[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path,

    [Parameter(HelpMessage = 'The maximum number of candidate offsets to return')]
    [int]$Maximum = 128
  )

  $Signature = [byte[]](0x50, 0x4B, 0x03, 0x04)
  Find-BinaryPattern -Path $Path -Pattern $Signature -Maximum $Maximum
}

function Copy-SquirrelEmbeddedZip {
  <#
  .SYNOPSIS
    Copy an embedded ZIP candidate from a setup executable to a temporary file
  .PARAMETER Path
    The path to the installer
  .PARAMETER Offset
    The offset where the ZIP local file header starts
  .PARAMETER DestinationPath
    The path of the temporary ZIP file to create
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path,

    [Parameter(Mandatory, HelpMessage = 'The offset where the ZIP local file header starts')]
    [long]$Offset,

    [Parameter(Mandatory, HelpMessage = 'The path of the temporary ZIP file to create')]
    [string]$DestinationPath,

    [Parameter(HelpMessage = 'The number of bytes to copy')]
    [long]$Length
  )

  $InputStream = [System.IO.File]::Open((Get-Item -Path $Path -Force).FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
  $Output = [System.IO.File]::Open($DestinationPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::Read)
  try {
    $Available = $InputStream.Length - $Offset
    if ($Offset -lt 0 -or $Available -lt 0) { throw 'The Squirrel ZIP offset is outside the installer.' }
    $RangeLength = if ($Length -gt 0) { $Length } else { $Available }
    $Range = New-BoundedReadStream -Stream $InputStream -Offset $Offset -Length $RangeLength -LeaveOpen
    if ($Length -gt 0) {
      $null = Copy-BoundedStream -Source $Range -Destination $Output -MaximumBytes $Length -ExpectedBytes $Length
    } else {
      $null = Copy-BoundedStream -Source $Range -Destination $Output -MaximumBytes $Available -ExpectedBytes $Available
    }
  } finally {
    if ($Range) { $Range.Dispose() }
    $Output.Dispose()
    $InputStream.Dispose()
  }

  return $DestinationPath
}

function Read-SquirrelNuspecFromZipArchive {
  <#
  .SYNOPSIS
    Read nuspec metadata from an opened ZIP archive
  .PARAMETER Archive
    The ZIP archive to inspect
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The ZIP archive to inspect')]
    $Archive
  )

  $Entry = Get-InstallerArchiveEntry -Archive $Archive | Where-Object { $_.FullName.EndsWith('.nuspec', [StringComparison]::OrdinalIgnoreCase) } | Select-Object -First 1
  if (-not $Entry) { return $null }

  [xml]$Xml = Read-InstallerArchiveEntryText -Entry $Entry -MaximumBytes 16777216

  $Metadata = $Xml.package.metadata
  if (-not $Metadata) { return $null }

  [pscustomobject]@{
    Id          = [string]$Metadata.id
    Title       = [string]$Metadata.title
    Version     = [string]$Metadata.version
    Authors     = [string]$Metadata.authors
    Description = [string]$Metadata.description
    NuspecPath  = $Entry.FullName
  }
}

function Read-SquirrelNuspecFromNupkgEntry {
  <#
  .SYNOPSIS
    Read nuspec metadata from a nested nupkg entry without executing the installer
  .PARAMETER Entry
    The nested nupkg entry
  .PARAMETER DestinationPath
    The temporary path used to materialize the nupkg
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The nested nupkg entry')]
    $Entry,

    [Parameter(Mandatory, HelpMessage = 'The temporary path used to materialize the nupkg')]
    [string]$DestinationPath
  )

  $null = Export-InstallerArchiveEntry -Entry $Entry -DestinationPath $DestinationPath -MaximumBytes 1073741824
  $NestedArchive = Get-InstallerArchive -Path $DestinationPath
  try {
    Read-SquirrelNuspecFromZipArchive -Archive $NestedArchive
  } finally {
    $NestedArchive.Dispose()
  }
}

function New-SquirrelInfo {
  <#
  .SYNOPSIS
    Build the static Squirrel metadata object returned by the parser
  .PARAMETER Path
    The path to the installer
  .PARAMETER Family
    The detected Squirrel-family name
  .PARAMETER Confidence
    The confidence level of the static detection
  .PARAMETER ZipOffset
    The ZIP payload offset inside the installer
  .PARAMETER Nuspec
    The nuspec metadata object
  .PARAMETER NupkgPath
    The optional nested nupkg path
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path,

    [Parameter(Mandatory, HelpMessage = 'The detected Squirrel-family name')]
    [string]$Family,

    [Parameter(Mandatory, HelpMessage = 'The confidence level of the static detection')]
    [string]$Confidence,

    [Parameter(Mandatory, HelpMessage = 'The ZIP payload offset inside the installer')]
    [long]$ZipOffset,

    [Parameter(Mandatory, HelpMessage = 'The nuspec metadata object')]
    [pscustomobject]$Nuspec,

    [Parameter(HelpMessage = 'The optional nested nupkg path')]
    [string]$NupkgPath
  )

  $DisplayName = if ([string]::IsNullOrWhiteSpace($Nuspec.Title)) { $Nuspec.Id } else { $Nuspec.Title }
  # Squirrel.Windows and Velopack both use LocalAppData\<package ID> as the
  # default root unless an explicit install directory overrides it.
  $DefaultInstallLocation = if ($Nuspec.Id -cmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$') {
    '%LocalAppData%\' + $Nuspec.Id
  } else {
    $null
  }

  [pscustomobject]@{
    Path                    = (Get-Item -Path $Path -Force).FullName
    InstallerType           = 'Squirrel'
    Family                  = $Family
    Confidence              = $Confidence
    ZipOffset               = $ZipOffset
    NupkgPath               = $NupkgPath
    Nuspec                  = $Nuspec
    ProductCode             = $Nuspec.Id
    DisplayName             = $DisplayName
    DisplayVersion          = $Nuspec.Version
    Publisher               = $Nuspec.Authors
    Scope                   = 'user'
    DefaultInstallLocation  = $DefaultInstallLocation
    SuggestedManifestFields = [pscustomobject]@{
      InstallerType        = 'exe # Squirrel'
      Scope                = 'user'
      ProductCode          = $Nuspec.Id
      DisplayName          = $DisplayName
      Publisher            = $Nuspec.Authors
      DisplayVersion       = $Nuspec.Version
      InstallationMetadata = [pscustomobject]@{ DefaultInstallLocation = $DefaultInstallLocation }
    }
  }
}

function ConvertFrom-SquirrelReleases {
  <#
  .SYNOPSIS
    Convert Squirrel releases into organized hashtable
  .PARAMETER Content
    The string containing Squirrel releases information
  .LINK
    https://github.com/Squirrel/Squirrel.Windows/blob/HEAD/src/Squirrel/Utility.cs
  #>
  param (
    [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory, HelpMessage = 'The string containing Squirrel releases information')]
    [string]$Content
  )

  begin {
    $EntryRegex = [regex]::new('^([0-9a-fA-F]{40})\s+(\S+)\s+(\d+)[\r]*$', [System.Text.RegularExpressions.RegexOptions]::Compiled)
    $CommentRegex = [regex]::new('\s*#.*$', [System.Text.RegularExpressions.RegexOptions]::Compiled)
    $StagingRegex = [regex]::new('#\s+(\d{1,3})%$', [System.Text.RegularExpressions.RegexOptions]::Compiled)
    $SuffixRegex = [regex]::new('(-full|-delta)?\.nupkg$', [System.Text.RegularExpressions.RegexOptions]::Compiled)
    $VersionRegex = [regex]::new('\d+(\.\d+){0,3}(-[A-Za-z][0-9A-Za-z-]*)?', [System.Text.RegularExpressions.RegexOptions]::Compiled)

    $Result = @()
  }

  process {
    $Result += $Content | Split-LineEndings | Where-Object -FilterScript { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object -Process {
      $Entry = $_

      $StagingPercentage = $Entry -match $StagingRegex ? $Matches[1] / 100 : $null

      $Entry = $Entry -replace $CommentRegex
      if ([string]::IsNullOrWhiteSpace($Entry)) {
        return
      }

      $Match = $EntryRegex.Match($Entry)
      if (-not $Match.Success -or $Match.Groups.Count -ne 4) {
        throw "Invalid release entry: ${Entry}"
      }

      $Filename = $Match.Groups[2].Value

      $BaseUrl = $null
      $Query = $null

      $Uri = [uri]$null
      if ([uri]::TryCreate($Filename, [System.UriKind]::Absolute, [ref]$Uri) -and $Uri.Scheme -in @([uri]::UriSchemeHttp, [uri]::UriSchemeHttps)) {
        $Path = $Uri.LocalPath
        $Authority = $Uri.GetLeftPart([System.UriPartial]::Authority)

        if ([string]::IsNullOrEmpty($Path) -or [string]::IsNullOrEmpty($Authority)) {
          throw "Invalid URL: ${Filename}"
        }

        $IndexOfLastPathSeparator = $Path.LastIndexOf('/') + 1
        $BaseUrl = $Authority + $Path.Substring(0, $IndexOfLastPathSeparator)
        $Filename = $Path.Substring($IndexOfLastPathSeparator)

        if (-not [string]::IsNullOrEmpty($Uri.Query)) {
          $Query = $Uri.Query
        }
      }

      if ($Filename.IndexOfAny([System.IO.Path]::GetInvalidFileNameChars()) -gt -1) {
        throw "Filename can either be an absolute HTTP[s] URL, *or* a file name: ${Filename}"
      }

      return [pscustomobject]@{
        Version           = $VersionRegex.Match($SuffixRegex.Replace($Filename, '')).Value
        Sha1              = $Match.Groups[1].Value
        Filename          = $Filename
        Filesize          = [Int64]::Parse($Match.Groups[3].Value)
        IsDelta           = $Filename.EndsWith('-delta.nupkg', [System.StringComparison]::InvariantCultureIgnoreCase)
        BaseUrl           = $BaseUrl
        Query             = $Query
        StagingPercentage = $StagingPercentage
      }
    }
  }

  end {
    return $Result
  }
}

function Get-SquirrelInfoFromZipCandidate {
  <#
  .SYNOPSIS
    Read Squirrel or Velopack metadata from one embedded ZIP candidate
  .PARAMETER Path
    The path to the installer
  .PARAMETER Offset
    The ZIP payload offset inside the installer
  .PARAMETER TemporaryPath
    The temporary workspace used for ZIP materialization
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path,

    [Parameter(Mandatory, HelpMessage = 'The ZIP payload offset inside the installer')]
    [long]$Offset,

    [Parameter(HelpMessage = 'The ZIP payload length inside the installer')]
    [long]$Length,

    [Parameter(Mandatory, HelpMessage = 'The temporary workspace used for ZIP materialization')]
    [string]$TemporaryPath
  )

  $ZipPath = Join-Path $TemporaryPath "candidate-$Offset.zip"
  Copy-SquirrelEmbeddedZip -Path $Path -Offset $Offset -Length $Length -DestinationPath $ZipPath | Out-Null

  $Archive = Get-InstallerArchive -Path $ZipPath
  try {
    $NupkgEntry = Get-InstallerArchiveEntry -Archive $Archive | Where-Object { $_.FullName.EndsWith('.nupkg', [StringComparison]::OrdinalIgnoreCase) } | Select-Object -First 1
    if ($NupkgEntry) {
      $NupkgPath = Join-Path $TemporaryPath ([System.IO.Path]::GetFileName($NupkgEntry.FullName))
      $Nuspec = Read-SquirrelNuspecFromNupkgEntry -Entry $NupkgEntry -DestinationPath $NupkgPath
      if ($Nuspec -and -not [string]::IsNullOrWhiteSpace($Nuspec.Id)) {
        return New-SquirrelInfo -Path $Path -Family 'Squirrel' -Confidence 'medium' -ZipOffset $Offset -NupkgPath $NupkgEntry.FullName -Nuspec $Nuspec
      }
    }

    $DirectNuspec = Read-SquirrelNuspecFromZipArchive -Archive $Archive
    if ($DirectNuspec -and -not [string]::IsNullOrWhiteSpace($DirectNuspec.Id)) {
      return New-SquirrelInfo -Path $Path -Family 'Velopack/Squirrel nupkg' -Confidence 'low' -ZipOffset $Offset -Nuspec $DirectNuspec
    }
  } finally {
    $Archive.Dispose()
  }
}

function Get-SquirrelInfo {
  <#
  .SYNOPSIS
    Get static metadata from a Squirrel or Velopack installer
  .PARAMETER Path
    The path to the installer
  .PARAMETER MaximumOffsets
    The maximum number of embedded ZIP offsets to try
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path,

    [Parameter(HelpMessage = 'The maximum number of embedded ZIP offsets to try')]
    [int]$MaximumOffsets = 64
  )

  process {
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    $File = Get-Item -Path $Path -Force
    $TemporaryPath = New-TempFolder
    try {
      $Candidates = [System.Collections.Generic.List[psobject]]::new()
      foreach ($ResourceCandidate in Get-SquirrelPeResourceZipCandidate -Path $File.FullName) {
        $Candidates.Add([pscustomobject]@{ Offset = [long]$ResourceCandidate.Offset; Length = [long]$ResourceCandidate.Length })
      }

      $BundleHeader = Get-SquirrelBundleHeader -Path $File.FullName
      if ($BundleHeader) {
        if (-not @($Candidates).Where({ $_.Offset -eq $BundleHeader.Offset }, 'First')) {
          $Candidates.Add([pscustomobject]@{ Offset = [long]$BundleHeader.Offset; Length = [long]$BundleHeader.Length })
        }
      }

      foreach ($Offset in Get-SquirrelZipLocalHeaderOffset -Path $File.FullName -Maximum $MaximumOffsets) {
        if (-not @($Candidates).Where({ $_.Offset -eq $Offset }, 'First')) {
          $Candidates.Add([pscustomobject]@{ Offset = [long]$Offset; Length = [long]0 })
        }
      }

      foreach ($Candidate in $Candidates) {
        try {
          $Info = Get-SquirrelInfoFromZipCandidate -Path $File.FullName -Offset $Candidate.Offset -Length $Candidate.Length -TemporaryPath $TemporaryPath
          if ($Info) { return $Info }
        } catch {
          continue
        }
      }
    } finally {
      Remove-Item -Path $TemporaryPath -Recurse -Force -ErrorAction SilentlyContinue
    }

    throw 'The installer does not expose embedded Squirrel or Velopack nuspec metadata'
  }
}

function Read-ProductCodeFromSquirrel {
  <#
  .SYNOPSIS
    Read the product code from a Squirrel or Velopack installer
  .PARAMETER Path
    The path to the installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path
  )

  process {
    $Info = Get-SquirrelInfo -Path $Path
    if ([string]::IsNullOrWhiteSpace($Info.ProductCode)) { throw 'The Squirrel installer does not expose a ProductCode value' }
    return $Info.ProductCode
  }
}

function Test-SquirrelInstaller {
  <#
  .SYNOPSIS
    Test whether an installer exposes static Squirrel or Velopack metadata
  .PARAMETER Path
    The path to the installer
  #>
  [OutputType([bool])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path
  )

  process {
    try {
      $null = Get-SquirrelInfo -Path $Path
      return $true
    } catch {
      return $false
    }
  }
}

function Read-ProductVersionFromSquirrel {
  <#
  .SYNOPSIS
    Read the product version from a Squirrel or Velopack installer
  .PARAMETER Path
    The path to the installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path
  )

  process {
    $Info = Get-SquirrelInfo -Path $Path
    if ([string]::IsNullOrWhiteSpace($Info.DisplayVersion)) { throw 'The Squirrel installer does not expose a DisplayVersion value' }
    return $Info.DisplayVersion
  }
}

function Read-ProductNameFromSquirrel {
  <#
  .SYNOPSIS
    Read the product name from a Squirrel or Velopack installer
  .PARAMETER Path
    The path to the installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path
  )

  process {
    $Info = Get-SquirrelInfo -Path $Path
    if ([string]::IsNullOrWhiteSpace($Info.DisplayName)) { throw 'The Squirrel installer does not expose a DisplayName value' }
    return $Info.DisplayName
  }
}

function Read-PublisherFromSquirrel {
  <#
  .SYNOPSIS
    Read the publisher from a Squirrel or Velopack installer
  .PARAMETER Path
    The path to the installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path
  )

  process {
    $Info = Get-SquirrelInfo -Path $Path
    if ([string]::IsNullOrWhiteSpace($Info.Publisher)) { throw 'The Squirrel installer does not expose a Publisher value' }
    return $Info.Publisher
  }
}

Export-ModuleMember -Function Get-SquirrelInfo, Test-SquirrelInstaller, ConvertFrom-SquirrelReleases, Read-ProductCodeFromSquirrel, Read-ProductVersionFromSquirrel, Read-ProductNameFromSquirrel, Read-PublisherFromSquirrel
