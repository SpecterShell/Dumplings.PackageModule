# Load the Versioning class from codes
if (-not ([System.Management.Automation.PSTypeName]'Dumplings.Versioning.Versioning').Type) {
  Add-Type -Path (Join-Path $PSScriptRoot 'Assets' 'Versioning.cs')
}

# Add type accelerator for the Versioning class
$TypeAcceleratorsClass = [psobject].Assembly.GetType('System.Management.Automation.TypeAccelerators')
$TypeAccelerators = $TypeAcceleratorsClass::Get
@(
  [Dumplings.Versioning.Versioning]
  [Dumplings.Versioning.SemanticVersion]
  [Dumplings.Versioning.GeneralVersion]
  [Dumplings.Versioning.ComplexVersion]
  [Dumplings.Versioning.RawVersion]
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
  Get-ChildItem -LiteralPath $LibraryPath -Filter '*.psm1' -Recurse -File |
    Where-Object Name -NotIn $InfrastructureModules |
    Import-Module -Force
}

# Import models
$Private:ModelPath = Join-Path $PSScriptRoot 'Models'
if (Test-Path -Path $ModelPath) {
  $Private:ModelPath | Get-ChildItem -Include '*.ps1' -Recurse -File | ForEach-Object -Process { . $_ }
}
