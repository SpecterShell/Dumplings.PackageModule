. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')
. (Join-Path $PSScriptRoot '..\Support\InstallerInfrastructureTestSetup.ps1')

Describe 'Test-ExtractionPattern' {
  It 'matches archive paths across slash conventions' {
    Test-ExtractionPattern -Path 'bin/updater.exe' -Pattern 'bin\updater.exe' | Should -BeTrue
    Test-ExtractionPattern -Path 'bin\updater.exe' -Pattern 'bin/updater.exe' | Should -BeTrue
  }
}

Describe 'Resolve-UniqueInstallerFile' {
  It 'reports an empty candidate set without a parameter-binding failure' {
    { Resolve-UniqueInstallerFile -Item ([System.IO.FileInfo[]]@()) -Pattern 'Setup.inx' -Description 'MSI Binary.ISSetup.dll payload' } |
      Should -Throw 'No candidate files are available for the MSI Binary.ISSetup.dll payload.'
  }

  It 'prefers one exact relative path over wildcard interpretation' {
    $Root = Join-Path $TestDrive 'UniqueSelection'
    $null = New-Item -Path (Join-Path $Root 'x64') -ItemType Directory -Force
    $null = New-Item -Path (Join-Path $Root 'arm64') -ItemType Directory -Force
    [IO.File]::WriteAllText((Join-Path $Root 'x64\package.msi'), 'x64')
    [IO.File]::WriteAllText((Join-Path $Root 'arm64\package.msi'), 'arm64')
    $Files = @(Get-ChildItem -LiteralPath $Root -Recurse -File)

    (Resolve-UniqueInstallerFile -Item $Files -Pattern 'x64\package.msi' -BasePath $Root).FullName |
      Should -Be (Join-Path $Root 'x64\package.msi')
    { Resolve-UniqueInstallerFile -Item $Files -Pattern '*.msi' -BasePath $Root } | Should -Throw '*Multiple files matched*'
  }
}

Describe 'Installer condition evaluation' {
  It 'applies Boolean precedence while preserving unknown identifiers' {
    $Result = Resolve-InstallerBooleanExpression -Expression 'WINDOWS || DYNAMIC && false' -IdentifierState ([ordered]@{
        WINDOWS = 'True'
        DYNAMIC = 'Unknown'
      })

    $Result.State | Should -Be 'True'
    $Result.Identifiers | Should -Be @('DYNAMIC', 'WINDOWS')
    $Result.UnknownIdentifiers | Should -Contain 'DYNAMIC'
    Merge-InstallerConditionState -State @('False', 'Unknown') -Operator All | Should -Be 'False'
    Merge-InstallerConditionState -State @('False', 'Unknown') -Operator Any | Should -Be 'Unknown'
    Merge-InstallerConditionState -State @('False', 'False') -Operator None | Should -Be 'True'
  }

  It 'rejects malformed and over-deep expressions without throwing' {
    (Resolve-InstallerBooleanExpression -Expression 'a + b' -IdentifierState @{}).State | Should -Be 'Unknown'
    (Resolve-InstallerBooleanExpression -Expression ('(' * 40 + 'true' + ')' * 40) -IdentifierState @{} -MaximumDepth 8).State | Should -Be 'Unknown'
  }
}
