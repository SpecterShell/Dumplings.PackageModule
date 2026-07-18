# Load the version comparison classes from code
if (-not ([System.Management.Automation.PSTypeName]'Dumplings.Versioning.WinGetVersion').Type) {
  Add-Type -Path (Join-Path $PSScriptRoot 'Assets' 'Versioning.cs')
}

# Add type accelerators for the version comparison classes
$TypeAcceleratorsClass = [psobject].Assembly.GetType('System.Management.Automation.TypeAccelerators')
$TypeAccelerators = $TypeAcceleratorsClass::Get
@(
  [Dumplings.Versioning.WinGetVersion]
  [Dumplings.Versioning.ChunkVersion]
) | ForEach-Object -Process { if (-not $TypeAccelerators.ContainsKey($_.Name)) { $TypeAcceleratorsClass::Add($_.Name, $_) } }

# Import libraries
$Private:LibraryPath = Join-Path $PSScriptRoot 'Libraries'
if (Test-Path -Path $LibraryPath) {
  # Mechanical infrastructure has deterministic dependencies and must be
  # available before independently authored installer-format modules load.
  $Private:InfrastructureModules = @('Runtime.psm1', 'Binary.psm1', 'Compression.psm1', 'Archive.psm1', 'PE.psm1', 'RegistryAssociations.psm1')
  foreach ($InfrastructureModule in $InfrastructureModules) {
    Import-Module (Join-Path $LibraryPath $InfrastructureModule) -Force
  }

  # Manifest parsing has an explicit dependency chain. Load general helpers and
  # the schema/model/serialization boundary first, then parser libraries, and
  # finally validation, update, and submission orchestration.
  $Private:ManifestFoundationModules = @('General.psm1', 'YamlSchema.psm1', 'WinGetManifestSchema.psm1', 'WinGetManifestModel.psm1', 'WinGetManifestSerialization.psm1')
  foreach ($ManifestModule in $ManifestFoundationModules) {
    Import-Module (Join-Path $LibraryPath $ManifestModule) -Force
  }
  $Private:ManifestConsumerModules = @('WinGetManifestValidation.psm1', 'WinGetManifestUpdate.psm1', 'WinGetSubmission.psm1')
  $Private:OrderedModules = @($InfrastructureModules) + @($ManifestFoundationModules) + @($ManifestConsumerModules)
  Get-ChildItem -LiteralPath $LibraryPath -Filter '*.psm1' -Recurse -File |
    Where-Object Name -NotIn $OrderedModules |
    Import-Module -Force
  foreach ($ManifestModule in $ManifestConsumerModules) {
    Import-Module (Join-Path $LibraryPath $ManifestModule) -Force
  }
}

# Import models
$Private:ModelPath = Join-Path $PSScriptRoot 'Models'
if (Test-Path -Path $ModelPath) {
  $Private:ModelPath | Get-ChildItem -Include '*.ps1' -Recurse -File | ForEach-Object -Process { . $_ }
}
