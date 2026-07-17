# SPDX-License-Identifier: MIT
# Diagnostic benchmark only. It records evidence and enforces no CI threshold.

[CmdletBinding()]
param (
  [string]$NSISPath,
  [string]$NSISBaselineModulePath,
  [string]$ChromiumPath,
  [string]$InnoPath,
  [string]$InnoExtractName,
  [string]$SetupFactoryPath,
  [string]$AdvancedInstallerPath,
  [string]$QtInstallerFrameworkPath,
  [string]$Install4jPath,
  [string]$InstallBuilderPath,
  [string]$SquirrelPath,
  [string]$BurnPath,
  [string]$MsiPath,
  [string]$OutputPath
)

$RepositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))

function Invoke-InstallerParserBenchmark {
  <#
  .SYNOPSIS
    Run one parser in an isolated PowerShell process and record time and peak working set
  #>
  param (
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Expression
  )

  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
  $ResolvedPath = (Get-Item -LiteralPath $Path -Force).FullName
  $ScriptText = @"
`$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath '$($RepositoryRoot.Replace("'", "''"))'
`$InstallerPath = '$($ResolvedPath.Replace("'", "''"))'
[GC]::Collect()
[GC]::WaitForPendingFinalizers()
[GC]::Collect()
`$AllocatedBefore = [GC]::GetTotalAllocatedBytes(`$true)
`$OperationStopwatch = [Diagnostics.Stopwatch]::StartNew()
& {
$Expression
} | Out-Null
`$OperationStopwatch.Stop()
`$Metrics = [pscustomobject]@{
  OperationElapsedMilliseconds = `$OperationStopwatch.Elapsed.TotalMilliseconds
  AllocatedBytes = [GC]::GetTotalAllocatedBytes(`$true) - `$AllocatedBefore
  ManagedBytesAfter = [GC]::GetTotalMemory(`$false)
}
[Console]::Out.WriteLine('__DUMPLINGS_BENCHMARK__:' + (`$Metrics | ConvertTo-Json -Compress))
"@
  $EncodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($ScriptText))
  $StandardOutput = Join-Path ([IO.Path]::GetTempPath()) "Dumplings-Benchmark-$([guid]::NewGuid().ToString('N')).out"
  $StandardError = "$StandardOutput.err"
  $Stopwatch = [Diagnostics.Stopwatch]::StartNew()
  $Process = Start-Process -FilePath (Get-Command pwsh).Source -ArgumentList '-NoLogo', '-NoProfile', '-EncodedCommand', $EncodedCommand -WindowStyle Hidden -PassThru -RedirectStandardOutput $StandardOutput -RedirectStandardError $StandardError
  $PeakWorkingSetBytes = 0L
  while (-not $Process.HasExited) {
    try { $Process.Refresh(); $PeakWorkingSetBytes = [Math]::Max($PeakWorkingSetBytes, $Process.WorkingSet64) } catch { }
    Start-Sleep -Milliseconds 50
  }
  $Process.WaitForExit()
  $Stopwatch.Stop()
  try {
    $Metrics = $null
    if ($Process.ExitCode -eq 0) {
      $MetricsLine = Get-Content -LiteralPath $StandardOutput | Where-Object { $_.StartsWith('__DUMPLINGS_BENCHMARK__:') } | Select-Object -Last 1
      if ($MetricsLine) { $Metrics = $MetricsLine.Substring('__DUMPLINGS_BENCHMARK__:'.Length) | ConvertFrom-Json }
    }
    [pscustomobject]@{
      Name                         = $Name
      Path                         = $ResolvedPath
      Length                       = (Get-Item -LiteralPath $ResolvedPath).Length
      ElapsedMilliseconds          = $Stopwatch.ElapsedMilliseconds
      OperationElapsedMilliseconds = $Metrics ? [Math]::Round([double]$Metrics.OperationElapsedMilliseconds, 2) : $null
      AllocatedBytes               = $Metrics ? [long]$Metrics.AllocatedBytes : $null
      ManagedBytesAfter            = $Metrics ? [long]$Metrics.ManagedBytesAfter : $null
      PeakWorkingSetBytes          = $PeakWorkingSetBytes
      ExitCode                     = $Process.ExitCode
      Error                        = if ($Process.ExitCode -ne 0) { Get-Content -LiteralPath $StandardError -Raw } else { $null }
    }
  } finally {
    Remove-Item -LiteralPath $StandardOutput, $StandardError -Force -ErrorAction SilentlyContinue
  }
}

$Results = @(
  if ($NSISPath) {
    if ($NSISBaselineModulePath -and (Test-Path -LiteralPath $NSISBaselineModulePath)) {
      $BaselineModule = (Get-Item -LiteralPath $NSISBaselineModulePath -Force).FullName.Replace("'", "''")
      Invoke-InstallerParserBenchmark -Name NSISBaseline -Path $NSISPath -Expression "if (-not `$env:windir) { `$env:windir = 'C:\Windows' }; Import-Module .\Modules\InstallerParsers\Libraries\Runtime.psm1 -Force; Import-Module .\Modules\InstallerParsers\Libraries\Binary.psm1 -Force; Import-Module .\Modules\InstallerParsers\Libraries\Compression.psm1 -Force; Import-Module .\Modules\InstallerParsers\Libraries\Archive.psm1 -Force; Import-Module .\Modules\InstallerParsers\Libraries\PE.psm1 -Force; Import-Module .\Modules\InstallerParsers\Libraries\RegistryAssociations.psm1 -Force; Import-Module '$BaselineModule' -Force; Get-NSISInfo -Path `$InstallerPath"
    }
    Invoke-InstallerParserBenchmark -Name NSIS -Path $NSISPath -Expression "Import-Module .\Modules\InstallerParsers\Libraries\Runtime.psm1 -Force; Import-Module .\Modules\InstallerParsers\Libraries\Binary.psm1 -Force; Import-Module .\Modules\InstallerParsers\Libraries\Compression.psm1 -Force; Import-Module .\Modules\InstallerParsers\Libraries\Archive.psm1 -Force; Import-Module .\Modules\InstallerParsers\Libraries\PE.psm1 -Force; Import-Module .\Modules\InstallerParsers\Libraries\RegistryAssociations.psm1 -Force; Import-Module .\Modules\InstallerParsers\Libraries\NSIS.psm1 -Force; Get-NSISInfo -Path `$InstallerPath"
  }
  if ($ChromiumPath) {
    Invoke-InstallerParserBenchmark -Name Chromium -Path $ChromiumPath -Expression ". .\Modules\PackageModule\Index.ps1; Get-ChromiumSetupInfo -Path `$InstallerPath"
  }
  if ($InnoPath) {
    Invoke-InstallerParserBenchmark -Name Inno -Path $InnoPath -Expression "Import-Module .\Modules\InstallerParsers\Libraries\Runtime.psm1 -Force; Import-Module .\Modules\InstallerParsers\Libraries\Binary.psm1 -Force; Import-Module .\Modules\InstallerParsers\Libraries\Compression.psm1 -Force; Import-Module .\Modules\InstallerParsers\Libraries\Archive.psm1 -Force; Import-Module .\Modules\InstallerParsers\Libraries\PE.psm1 -Force; Import-Module .\Modules\InstallerParsers\Libraries\RegistryAssociations.psm1 -Force; Import-Module .\Modules\InstallerParsers\Libraries\Inno.psm1 -Force; Get-InnoInfo -Path `$InstallerPath"
    if ($InnoExtractName) {
      $ExtractName = $InnoExtractName.Replace("'", "''")
      Invoke-InstallerParserBenchmark -Name InnoExtract -Path $InnoPath -Expression "Import-Module .\Modules\InstallerParsers\Libraries\Runtime.psm1 -Force; Import-Module .\Modules\InstallerParsers\Libraries\Binary.psm1 -Force; Import-Module .\Modules\InstallerParsers\Libraries\Compression.psm1 -Force; Import-Module .\Modules\InstallerParsers\Libraries\Archive.psm1 -Force; Import-Module .\Modules\InstallerParsers\Libraries\PE.psm1 -Force; Import-Module .\Modules\InstallerParsers\Libraries\RegistryAssociations.psm1 -Force; Import-Module .\Modules\InstallerParsers\Libraries\Inno.psm1 -Force; `$DestinationPath = Join-Path ([IO.Path]::GetTempPath()) ('Dumplings-InnoBenchmark-' + [guid]::NewGuid().ToString('N')); try { Expand-InnoInstaller -Path `$InstallerPath -DestinationPath `$DestinationPath -Name '$ExtractName' } finally { Remove-Item -LiteralPath `$DestinationPath -Recurse -Force -ErrorAction SilentlyContinue }"
    }
  }
  if ($SetupFactoryPath) {
    Invoke-InstallerParserBenchmark -Name SetupFactory -Path $SetupFactoryPath -Expression "Import-Module .\Modules\InstallerParsers\Libraries\Runtime.psm1 -Force; Import-Module .\Modules\InstallerParsers\Libraries\Binary.psm1 -Force; Import-Module .\Modules\InstallerParsers\Libraries\Compression.psm1 -Force; Import-Module .\Modules\InstallerParsers\Libraries\Archive.psm1 -Force; Import-Module .\Modules\InstallerParsers\Libraries\PE.psm1 -Force; Import-Module .\Modules\InstallerParsers\Libraries\RegistryAssociations.psm1 -Force; Import-Module .\Modules\InstallerParsers\Libraries\SetupFactory.psm1 -Force; Get-SetupFactoryInfo -Path `$InstallerPath"
  }
  if ($AdvancedInstallerPath) {
    Invoke-InstallerParserBenchmark -Name AdvancedInstaller -Path $AdvancedInstallerPath -Expression "Import-Module .\Modules\InstallerParsers\Libraries\Runtime.psm1 -Force; Import-Module .\Modules\InstallerParsers\Libraries\Binary.psm1 -Force; Import-Module .\Modules\InstallerParsers\Libraries\Compression.psm1 -Force; Import-Module .\Modules\InstallerParsers\Libraries\Archive.psm1 -Force; Import-Module .\Modules\InstallerParsers\Libraries\PE.psm1 -Force; Import-Module .\Modules\InstallerParsers\Libraries\RegistryAssociations.psm1 -Force; Import-Module .\Modules\InstallerParsers\Libraries\AdvancedInstaller.psm1 -Force; Get-AdvancedInstallerInfo -Path `$InstallerPath"
  }
  if ($QtInstallerFrameworkPath) {
    Invoke-InstallerParserBenchmark -Name QtInstallerFramework -Path $QtInstallerFrameworkPath -Expression "Import-Module .\Modules\InstallerParsers\Libraries\Runtime.psm1 -Force; Import-Module .\Modules\InstallerParsers\Libraries\Binary.psm1 -Force; Import-Module .\Modules\InstallerParsers\Libraries\Compression.psm1 -Force; Import-Module .\Modules\InstallerParsers\Libraries\Archive.psm1 -Force; Import-Module .\Modules\InstallerParsers\Libraries\PE.psm1 -Force; Import-Module .\Modules\InstallerParsers\Libraries\RegistryAssociations.psm1 -Force; Import-Module .\Modules\InstallerParsers\Libraries\QtInstallerFramework.psm1 -Force; Get-QtInstallerFrameworkInfo -Path `$InstallerPath"
  }
  if ($Install4jPath) {
    Invoke-InstallerParserBenchmark -Name Install4j -Path $Install4jPath -Expression ". .\Modules\PackageModule\Index.ps1; Get-Install4jInfo -Path `$InstallerPath"
  }
  if ($InstallBuilderPath) {
    Invoke-InstallerParserBenchmark -Name InstallBuilder -Path $InstallBuilderPath -Expression ". .\Modules\PackageModule\Index.ps1; Get-InstallBuilderInfo -Path `$InstallerPath"
  }
  if ($SquirrelPath) {
    Invoke-InstallerParserBenchmark -Name Squirrel -Path $SquirrelPath -Expression ". .\Modules\PackageModule\Index.ps1; Get-SquirrelInfo -Path `$InstallerPath"
  }
  if ($BurnPath) {
    Invoke-InstallerParserBenchmark -Name Burn -Path $BurnPath -Expression ". .\Modules\PackageModule\Index.ps1; `$Info = Get-BurnInfo -Path `$InstallerPath; `$Stub = Get-BurnStub -Path `$InstallerPath; try { Get-BurnManifest -StubPath `$Stub } finally { Remove-Item -LiteralPath `$Stub -Force -ErrorAction SilentlyContinue }"
  }
  if ($MsiPath) {
    Invoke-InstallerParserBenchmark -Name MSI -Path $MsiPath -Expression ". .\Modules\PackageModule\Index.ps1; Get-MsiInstallerInfo -Path `$InstallerPath"
  }
) | Where-Object { $null -ne $_ }

$Report = [pscustomobject]@{
  RecordedAt = [DateTimeOffset]::Now
  PowerShell = $PSVersionTable.PSVersion.ToString()
  Results    = $Results
}
if ($OutputPath) {
  $Parent = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($OutputPath))
  if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
  $Report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding utf8NoBOM
}
$Report
