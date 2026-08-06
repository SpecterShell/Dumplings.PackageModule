#Requires -Version 7.4

# Apply default function parameters supplied by the Dumplings runner.
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

function Resolve-InstallerFileSystemPath {
  <#
  .SYNOPSIS
    Resolve a filesystem path against PowerShell's current provider location
  .PARAMETER Path
    Existing or prospective filesystem path to resolve.
  .PARAMETER AllowNonexistent
    Allow the final path component to be absent, as required for extraction destinations.
  .PARAMETER PathType
    Optional existing-item type constraint.
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [switch]$AllowNonexistent,
    [ValidateSet('Any', 'Leaf', 'Container')][string]$PathType = 'Any'
  )

  process {
    if ([string]::IsNullOrWhiteSpace($Path)) { throw 'The filesystem path is empty.' }

    if ($AllowNonexistent) {
      $Provider = $null
      $Drive = $null
      $ResolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(
        $Path, [ref]$Provider, [ref]$Drive)
      if ($Provider.Name -ne 'FileSystem') { throw "The path is not in the FileSystem provider: $Path" }
    } else {
      $Item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
      if ($Item.PSProvider.Name -ne 'FileSystem') { throw "The path is not in the FileSystem provider: $Path" }
      $ResolvedPath = $Item.FullName
      if ($PathType -eq 'Leaf' -and -not $Item.PSIsContainer) { return $ResolvedPath }
      if ($PathType -eq 'Container' -and $Item.PSIsContainer) { return $ResolvedPath }
      if ($PathType -ne 'Any') { throw "The path is not a $($PathType.ToLowerInvariant()) filesystem item: $Path" }
    }

    return [IO.Path]::GetFullPath($ResolvedPath)
  }
}

function Resolve-SafeExtractionPath {
  <#
  .SYNOPSIS
    Resolve a relative payload path without allowing extraction-root escape
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][string]$DestinationPath,
    [Parameter(Mandatory)][string]$RelativePath
  )
  if ([string]::IsNullOrWhiteSpace($RelativePath) -or $RelativePath.IndexOf([char]0) -ge 0) { throw 'The payload path is empty or invalid.' }
  $Normalized = $RelativePath.Replace('/', [IO.Path]::DirectorySeparatorChar).Replace('\', [IO.Path]::DirectorySeparatorChar)
  if ([IO.Path]::IsPathRooted($Normalized) -or $Normalized -match '^[A-Za-z]:') { throw "The payload path is rooted: $RelativePath" }
  # Resolve with PowerShell semantics before using System.IO. The process-wide
  # .NET current directory can differ from the runspace's current location.
  $ResolvedDestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
  $Root = $ResolvedDestinationPath.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
  $Output = [IO.Path]::GetFullPath([IO.Path]::Combine($Root, $Normalized.TrimStart([IO.Path]::DirectorySeparatorChar)))
  if (-not $Output.StartsWith($Root, [StringComparison]::OrdinalIgnoreCase)) { throw "The payload path escapes the destination: $RelativePath" }
  return $Output
}

function New-TempFile {
  <#
  .SYNOPSIS
    Create a new temporary file in DumplingsCache or system temp folder
  .OUTPUTS
    The path to the new temporary file
  #>
  [OutputType([string])]

  $Parent = (Test-Path -Path Variable:\DumplingsCache) -and (Test-Path -Path $Global:DumplingsCache) ? $Global:DumplingsCache : [System.IO.Path]::GetTempPath()
  $Path = (New-Item -Path $Parent -Name (New-Guid).Guid -ItemType File -Force).FullName
  return $Path
}

function New-TempFolder {
  <#
  .SYNOPSIS
    Create a new temporary folder in DumplingsCache or system temp folder
  .OUTPUTS
    The path to the new temporary folder
  #>
  [OutputType([string])]

  $Parent = (Test-Path -Path Variable:\DumplingsCache) -and (Test-Path -Path $Global:DumplingsCache) ? $Global:DumplingsCache : [System.IO.Path]::GetTempPath()
  $Path = (New-Item -Path $Parent -Name (New-Guid).Guid -ItemType Directory -Force).FullName
  return $Path
}

function Get-TempFile {
  <#
  .SYNOPSIS
    Download the file from the given URL to a temporary file and return its path
  .NOTES
    All the parameters except '-OutFile' will be passed to Invoke-WebRequest
  .OUTPUTS
    The path to the new temporary file
  #>
  [OutputType([string])]

  $FilePath = New-TempFile
  Invoke-WebRequest -OutFile $FilePath @args
  return $FilePath
}

function Expand-TempArchive {
  <#
  .SYNOPSIS
    Extract files from the given ZIP archive to a temporary folder and return the path of the destination folder
  .PARAMETER Path
    The path of the ZIP archive to be extracted
  .PARAMETER Name
    Optional wildcard selecting archive paths or file names. All entries are extracted when omitted.
  .PARAMETER CollisionAction
    Behavior when an output path already exists or multiple entries resolve to the same path.
  .PARAMETER MaximumExpandedBytes
    Maximum aggregate number of bytes written from the archive.
  .OUTPUTS
    The path of the destination folder
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the ZIP archive')]
    [string]$Path,

    [Alias('RelativeFilePath')]
    [Parameter(HelpMessage = 'The wildcard selecting archive entries to extract')]
    [string]$Name = '*',

    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')]
    [string]$CollisionAction = 'Prompt',

    [ValidateRange(1, [long]::MaxValue)]
    [long]$MaximumExpandedBytes = 2147483648
  )

  process {
    $TempFolderPath = New-TempFolder
    try {
      $ArchivePath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
      $Archive = Get-InstallerArchive -Path $ArchivePath
      try {
        # Route ZIP extraction through the shared bounded archive layer so large
        # archives are streamed and every selected path receives the same
        # traversal, collision, and aggregate-output handling as installers.
        $Result = Export-InstallerArchiveSelection -Archive $Archive -DestinationPath $TempFolderPath -Name $Name `
          -CollisionAction $CollisionAction -MaximumExpandedBytes $MaximumExpandedBytes
        if ($Name -ne '*' -and $Result.EntryCount -eq 0) {
          throw "The ZIP archive does not contain an entry matching: $Name"
        }
      } finally {
        $Archive.Dispose()
      }
      return $TempFolderPath
    } catch {
      Remove-Item -LiteralPath $TempFolderPath -Recurse -Force -ErrorAction SilentlyContinue
      throw
    }
  }
}

Export-ModuleMember -Function Resolve-InstallerFileSystemPath, Resolve-SafeExtractionPath, New-TempFile, New-TempFolder, Get-TempFile, Expand-TempArchive
