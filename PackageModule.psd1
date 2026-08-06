@{
  RootModule           = 'PackageModule.psm1'
  ModuleVersion        = '1.0.0'
  GUID                 = '8d6efe93-f136-4728-bc77-1e463676e1a6'
  Author               = 'Dumplings contributors'
  CompanyName          = 'Dumplings'
  Copyright            = 'Copyright (c) Dumplings contributors'
  Description          = 'Package automation, installer analysis, and WinGet manifest tooling for Dumplings.'
  PowerShellVersion    = '7.4'
  CompatiblePSEditions = @('Core')
  FunctionsToExport    = '*'
  CmdletsToExport      = @()
  VariablesToExport    = '*'
  AliasesToExport      = '*'
  PrivateData          = @{
    PSData = @{
      LicenseUri = 'https://www.apache.org/licenses/LICENSE-2.0'
      ProjectUri = 'https://github.com/SpecterShell/Dumplings'
      Tags       = @('Dumplings', 'WinGet', 'Installer')
    }
  }
}
