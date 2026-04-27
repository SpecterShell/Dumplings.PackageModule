# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# Force stop on error
$ErrorActionPreference = 'Stop'

function Get-InstallerBridgePowerShell {
  <#
  .SYNOPSIS
    Resolve the PowerShell host used to invoke external installer parser modules
  #>
  [OutputType([System.IO.FileInfo])]
  param ()

  $Candidates = @(
    (Join-Path $PSHOME 'pwsh.exe'),
    (Join-Path $PSHOME 'pwsh')
  )

  foreach ($Candidate in $Candidates) {
    if (-not [string]::IsNullOrWhiteSpace($Candidate) -and (Test-Path -Path $Candidate)) {
      return Get-Item -Path $Candidate -Force
    }
  }

  if ($Command = Get-Command -Name 'pwsh' -ErrorAction 'SilentlyContinue') {
    return Get-Item -Path $Command.Source -Force
  }

  throw 'The external installer parser bridge requires pwsh to be available'
}

function Resolve-InstallerBridgeModulePath {
  <#
  .SYNOPSIS
    Resolve the path to a separately licensed installer parser module
  .PARAMETER Name
    The parser module directory name under Modules
  #>
  [OutputType([System.IO.DirectoryInfo])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The parser module directory name under Modules')]
    [ValidateSet('InstallerParsers')]
    [string]$Name
  )

  $ModulePath = Join-Path $PSScriptRoot "..\..\$Name"
  if (-not (Test-Path -Path $ModulePath)) {
    throw "The separate installer parser module '$Name' could not be found at $ModulePath"
  }

  return Get-Item -Path $ModulePath -Force
}

function Resolve-InstallerBridgeCliPath {
  <#
  .SYNOPSIS
    Resolve the CLI entrypoint for a separately licensed installer parser module
  .PARAMETER Name
    The parser module directory name under Modules
  #>
  [OutputType([System.IO.FileInfo])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The parser module directory name under Modules')]
    [ValidateSet('InstallerParsers')]
    [string]$Name
  )

  $CliPath = Join-Path (Resolve-InstallerBridgeModulePath -Name $Name).FullName 'Cli.ps1'
  if (-not (Test-Path -Path $CliPath)) {
    throw "The installer parser CLI for '$Name' could not be found at $CliPath"
  }

  return Get-Item -Path $CliPath -Force
}

function Invoke-InstallerBridgeCommand {
  <#
  .SYNOPSIS
    Invoke a separately licensed installer parser module through an external PowerShell process
  .PARAMETER ModuleName
    The parser module directory name under Modules
  .PARAMETER Action
    The CLI action to invoke
  .PARAMETER Argument
    The CLI arguments to forward
  #>
  param (
    [Parameter(Mandatory, HelpMessage = 'The parser module directory name under Modules')]
    [ValidateSet('InstallerParsers')]
    [string]$ModuleName,

    [Parameter(Mandatory, HelpMessage = 'The CLI action to invoke')]
    [string]$Action,

    [Parameter(HelpMessage = 'The CLI arguments to forward')]
    [hashtable]$Argument = @{}
  )

  $PowerShellPath = (Get-InstallerBridgePowerShell).FullName
  $CliPath = (Resolve-InstallerBridgeCliPath -Name $ModuleName).FullName

  $StartInfo = [System.Diagnostics.ProcessStartInfo]::new()
  $StartInfo.FileName = $PowerShellPath
  $StartInfo.UseShellExecute = $false
  $StartInfo.RedirectStandardOutput = $true
  $StartInfo.RedirectStandardError = $true
  $StartInfo.StandardOutputEncoding = [System.Text.Encoding]::UTF8
  $StartInfo.StandardErrorEncoding = [System.Text.Encoding]::UTF8

  foreach ($Value in @('-NoLogo', '-NoProfile', '-File', $CliPath, '-Action', $Action)) {
    $null = $StartInfo.ArgumentList.Add($Value)
  }

  foreach ($Entry in $Argument.GetEnumerator()) {
    if ($null -eq $Entry.Value) { continue }
    if ($Entry.Value -is [string] -and [string]::IsNullOrWhiteSpace($Entry.Value)) { continue }

    $null = $StartInfo.ArgumentList.Add("-$($Entry.Key)")
    $null = $StartInfo.ArgumentList.Add([string]$Entry.Value)
  }

  $Process = [System.Diagnostics.Process]::new()
  $Process.StartInfo = $StartInfo

  try {
    $null = $Process.Start()
    $StandardOutput = $Process.StandardOutput.ReadToEnd()
    $StandardError = $Process.StandardError.ReadToEnd()
    $Process.WaitForExit()

    if ($Process.ExitCode -ne 0) {
      $Message = if ([string]::IsNullOrWhiteSpace($StandardError)) {
        "The installer parser CLI '$Action' failed with exit code $($Process.ExitCode)"
      } else {
        "The installer parser CLI '$Action' failed with exit code $($Process.ExitCode): $StandardError"
      }
      throw $Message.Trim()
    }

    if ([string]::IsNullOrWhiteSpace($StandardOutput)) { return $null }
    return $StandardOutput | ConvertFrom-Json -Depth 100
  } finally {
    $Process.Dispose()
  }
}

function Convert-InstallerBridgePathsToFileInfo {
  <#
  .SYNOPSIS
    Convert JSON path results from the installer bridge to FileInfo objects
  .PARAMETER Path
    The file paths returned by the external parser module
  #>
  [OutputType([System.IO.FileInfo[]])]
  param (
    [Parameter(HelpMessage = 'The file paths returned by the external parser module')]
    [AllowNull()]
    [object[]]$Path
  )

  $Result = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
  foreach ($Item in @($Path)) {
    if ($null -eq $Item) { continue }
    $Result.Add((Get-Item -Path ([string]$Item) -Force))
  }
  return $Result.ToArray()
}

Export-ModuleMember -Function Invoke-InstallerBridgeCommand, Convert-InstallerBridgePathsToFileInfo
