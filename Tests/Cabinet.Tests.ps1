# SPDX-License-Identifier: Apache-2.0

BeforeAll {
  foreach ($ModuleName in @('Runtime', 'Binary', 'General', 'Cabinet')) {
    Import-Module (Join-Path $PSScriptRoot "..\Libraries\$ModuleName.psm1") -Force
  }
  Import-CabinetDependency
}

Describe 'Generic cabinet extraction' {
  BeforeEach {
    $Source = Join-Path $TestDrive 'CabinetSource'
    $null = New-Item -Path $Source -ItemType Directory -Force
    1..3 | ForEach-Object { [IO.File]::WriteAllText((Join-Path $Source "file$_.txt"), "value $_") }
    $Script:CabinetPath = Join-Path $TestDrive 'sample.cab'
    $Cabinet = [Microsoft.Deployment.Compression.Cab.CabInfo]::new($Script:CabinetPath)
    $Cabinet.Pack($Source)
  }

  It 'enforces catalog entry limits before enumeration or extraction' {
    { Get-CabinetEntry -Path $Script:CabinetPath -MaximumEntries 2 } | Should -Throw '*entry limit*'
    { Export-CabinetEntry -Path $Script:CabinetPath -DestinationPath (Join-Path $TestDrive 'Out') -MaximumEntries 2 } |
      Should -Throw '*entry limit*'
  }

  It 'exports selected entries through collision-safe relative paths' {
    $Destination = Join-Path $TestDrive 'Selected'
    $Result = @(Export-CabinetEntry -Path $Script:CabinetPath -DestinationPath $Destination -Name 'file2.txt' -CollisionAction Error)

    $Result | Should -HaveCount 1
    [IO.File]::ReadAllText($Result[0]) | Should -Be 'value 2'
  }
}
