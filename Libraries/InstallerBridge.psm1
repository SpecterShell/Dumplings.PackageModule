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

function ConvertTo-InstallerBridgeObject {
  <#
  .SYNOPSIS
    Restore normal JSON objects while preserving member names that PowerShell cannot represent on PSCustomObject
  .PARAMETER InputObject
    A value produced by ConvertFrom-Json -AsHashtable, including nested dictionaries and arrays
  #>
  param (
    [Parameter(ValueFromPipeline, Mandatory, HelpMessage = 'A losslessly deserialized installer parser value')]
    [AllowNull()]
    [object]$InputObject
  )

  process {
    if ($null -eq $InputObject) { return $null }

    if ($InputObject -is [System.Collections.IDictionary]) {
      $Converted = [ordered]@{}
      $MemberNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
      $RequiresDictionary = $false

      foreach ($Entry in $InputObject.GetEnumerator()) {
        $MemberName = [string]$Entry.Key
        # PSCustomObject rejects an empty member name and folds names that differ
        # only by case. Keep such JSON objects as dictionaries to avoid data loss.
        if ([string]::IsNullOrEmpty($MemberName) -or -not $MemberNames.Add($MemberName)) {
          $RequiresDictionary = $true
        }
        $ConvertedValue = ConvertTo-InstallerBridgeObject -InputObject $Entry.Value
        if ($MemberName -in @('Warnings', 'UnresolvedFields')) {
          # JSON arrays lose their element type. Restore the documented parser
          # diagnostic contract as part of transport deserialization only.
          $ConvertedValue = [string[]]@($ConvertedValue)
        }
        $Converted[$MemberName] = $ConvertedValue
      }

      if ($RequiresDictionary) {
        # Unary-comma return preserves IDictionary as one value. In PowerShell
        # 7.6, Write-Output -NoEnumerate can wrap OrderedDictionary in a List.
        return , $Converted
      } else {
        [pscustomobject]$Converted
      }
      return
    }

    if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
      $Converted = [System.Collections.Generic.List[object]]::new()
      foreach ($Item in $InputObject) {
        $Converted.Add((ConvertTo-InstallerBridgeObject -InputObject $Item))
      }
      return , $Converted.ToArray()
    }

    return $InputObject
  }
}

function ConvertFrom-InstallerBridgeJson {
  <#
  .SYNOPSIS
    Deserialize installer parser JSON without rejecting unnamed registry values
  .PARAMETER Json
    JSON emitted by the separately licensed installer parser CLI
  #>
  [OutputType([pscustomobject], [System.Collections.IDictionary], [object[]])]
  param (
    [Parameter(ValueFromPipeline, Mandatory, HelpMessage = 'JSON emitted by an installer parser CLI')]
    [string]$Json
  )

  process {
    # Registry default values legitimately use an empty value name. PowerShell's
    # normal JSON mode rejects those members, while -AsHashtable retains them.
    $Value = $Json | ConvertFrom-Json -AsHashtable -Depth 100
    ConvertTo-InstallerBridgeObject -InputObject $Value
  }
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
  .PARAMETER TimeoutSeconds
    Maximum runtime before the parser process and its descendants are terminated
  #>
  param (
    [Parameter(Mandatory, HelpMessage = 'The parser module directory name under Modules')]
    [ValidateSet('InstallerParsers')]
    [string]$ModuleName,

    [Parameter(Mandatory, HelpMessage = 'The CLI action to invoke')]
    [string]$Action,

    [Parameter(HelpMessage = 'The CLI arguments to forward')]
    [hashtable]$Argument = @{},

    [Parameter(HelpMessage = 'Maximum parser runtime in seconds')]
    [ValidateRange(1, 3600)]
    [int]$TimeoutSeconds = 300
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
    # Drain both redirected streams concurrently so a verbose parser cannot
    # deadlock while its sibling pipe is waiting to be read.
    $StandardOutputTask = $Process.StandardOutput.ReadToEndAsync()
    $StandardErrorTask = $Process.StandardError.ReadToEndAsync()
    if (-not $Process.WaitForExit($TimeoutSeconds * 1000)) {
      try { $Process.Kill($true) } catch { }
      throw "The installer parser CLI '$Action' exceeded the $TimeoutSeconds-second timeout"
    }
    $Process.WaitForExit()
    $StandardOutput = $StandardOutputTask.GetAwaiter().GetResult()
    $StandardError = $StandardErrorTask.GetAwaiter().GetResult()

    if ($Process.ExitCode -ne 0) {
      $Message = if ([string]::IsNullOrWhiteSpace($StandardError)) {
        "The installer parser CLI '$Action' failed with exit code $($Process.ExitCode)"
      } else {
        "The installer parser CLI '$Action' failed with exit code $($Process.ExitCode): $StandardError"
      }
      throw $Message.Trim()
    }

    if ([string]::IsNullOrWhiteSpace($StandardOutput)) { return $null }
    return $StandardOutput | ConvertFrom-InstallerBridgeJson
  } finally {
    try { if (-not $Process.HasExited) { $Process.Kill($true) } } catch { }
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
