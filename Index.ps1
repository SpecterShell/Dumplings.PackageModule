# Import the manifest-backed command module into the caller's session. Core dot-sources this
# bootstrap in coordinator and worker runspaces, so the exported commands must be global.
param ([switch]$Reload)
Import-Module (Join-Path $PSScriptRoot 'PackageModule.psd1') -Force:$Reload -ArgumentList ([bool]$Reload) -Global -ErrorAction Stop

# Task models are scripts rather than ordinary module exports. Dot-source them into the runner
# scope so New-Object can resolve the configured PackageTask or SimpleTask class by name.
$Private:ModelPath = Join-Path $PSScriptRoot 'Models'
if (Test-Path -LiteralPath $Private:ModelPath -PathType Container) {
  foreach ($ModelName in 'TaskBase', 'SimpleTask', 'PackageTask') {
    . (Join-Path $Private:ModelPath "$ModelName.ps1")
  }
}
