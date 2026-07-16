BeforeAll {
  if (-not ([System.Management.Automation.PSTypeName]'Dumplings.Versioning.WinGetVersion').Type) {
    Add-Type -Path (Join-Path $PSScriptRoot 'Versioning.cs')
  }

  $TypeAcceleratorsClass = [psobject].Assembly.GetType('System.Management.Automation.TypeAccelerators')
  $TypeAccelerators = $TypeAcceleratorsClass::Get
  @(
    [Dumplings.Versioning.WinGetVersion]
    [Dumplings.Versioning.ChunkVersion]
  ) | ForEach-Object -Process {
    if (-not $TypeAccelerators.ContainsKey($_.Name)) {
      $TypeAcceleratorsClass::Add($_.Name, $_)
    }
  }

  Import-Module (Join-Path $PSScriptRoot '..\Libraries\WinGetLocalRepo.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\WinGetGitHubRepo.psm1') -Force
  $Script:WinGetGitHubRepoModule = Get-Module -Name WinGetGitHubRepo
  & $Script:WinGetGitHubRepoModule {
    function script:Invoke-GitHubApi {
      $Script:VersioningTestGitHubResponse
    }
  }

  function Assert-VersionLessThan {
    param (
      [Parameter(Mandatory)]
      [type]$Type,
      [Parameter(Mandatory)]
      [AllowEmptyString()]
      [string]$Left,
      [Parameter(Mandatory)]
      [AllowEmptyString()]
      [string]$Right
    )

    $LeftVersion = $Left -as $Type
    $RightVersion = $Right -as $Type
    $LeftVersion.CompareTo($RightVersion) | Should -BeLessThan 0
    $RightVersion.CompareTo($LeftVersion) | Should -BeGreaterThan 0
  }

  function Assert-VersionEqual {
    param (
      [Parameter(Mandatory)]
      [type]$Type,
      [Parameter(Mandatory)]
      [AllowEmptyString()]
      [string]$Left,
      [Parameter(Mandatory)]
      [AllowEmptyString()]
      [string]$Right
    )

    $LeftVersion = $Left -as $Type
    $RightVersion = $Right -as $Type
    $LeftVersion.CompareTo($RightVersion) | Should -Be 0
    $RightVersion.CompareTo($LeftVersion) | Should -Be 0
    $LeftVersion.Equals($RightVersion) | Should -BeTrue
    $LeftVersion.GetHashCode() | Should -Be $RightVersion.GetHashCode()
  }
}

Describe 'WinGetVersion' {
  It 'parses versions with whitespace and preambles like WinGet' {
    Assert-VersionEqual -Type ([Dumplings.Versioning.WinGetVersion]) -Left '1.0' -Right '1. 0 '
    Assert-VersionEqual -Type ([Dumplings.Versioning.WinGetVersion]) -Left '1.0' -Right 'Version 1.0'
    Assert-VersionEqual -Type ([Dumplings.Versioning.WinGetVersion]) -Left 'foo1' -Right 'bar1'
  }

  It 'normalizes leading and trailing zero parts' {
    Assert-VersionEqual -Type ([Dumplings.Versioning.WinGetVersion]) -Left '1.2.00.3' -Right '01.02.0.3'
    Assert-VersionEqual -Type ([Dumplings.Versioning.WinGetVersion]) -Left '1.2' -Right '1.2.0.0'
    Assert-VersionEqual -Type ([Dumplings.Versioning.WinGetVersion]) -Left '' -Right '0'
  }

  It 'orders numeric and suffixed parts like WinGet' {
    $Pairs = @(
      [Tuple]::Create('1', '2')
      [Tuple]::Create('0.0.1-beta', '0.0.2-alpha')
      [Tuple]::Create('13.9.8', '14.1')
      [Tuple]::Create('1-rc', '1')
      [Tuple]::Create('1.2-rc', '1.2')
      [Tuple]::Create('1.0.0-rc', '1')
      [Tuple]::Create('22.0.0-rc.1', '22.0.0')
      [Tuple]::Create('22.0.0-rc.1', '22.0.0.1')
      [Tuple]::Create('22.0.0-rc.1', '22.0.0-rc.1.1')
      [Tuple]::Create('22.0.0-rc.1.2', '22.0.0-rc.2')
      [Tuple]::Create('1.a2', '1.b1')
      [Tuple]::Create('alpha', 'beta')
    )

    foreach ($Pair in $Pairs) {
      Assert-VersionLessThan -Type ([Dumplings.Versioning.WinGetVersion]) -Left $Pair.Item1 -Right $Pair.Item2
    }
  }

  It 'uses source-compatible overflow fallback for an oversized integer part' {
    Assert-VersionLessThan -Type ([Dumplings.Versioning.WinGetVersion]) -Left '18446744073709551616' -Right '1'
  }

  It 'orders Unknown and Latest sentinels case-insensitively' {
    ([Dumplings.Versioning.WinGetVersion]'LATEST').IsLatest | Should -BeTrue
    ([Dumplings.Versioning.WinGetVersion]'unknown').IsUnknown | Should -BeTrue
    Assert-VersionEqual -Type ([Dumplings.Versioning.WinGetVersion]) -Left 'latest' -Right 'LATEST'
    Assert-VersionEqual -Type ([Dumplings.Versioning.WinGetVersion]) -Left 'unknown' -Right 'UNKNOWN'
    Assert-VersionLessThan -Type ([Dumplings.Versioning.WinGetVersion]) -Left 'unknown' -Right '1.0'
    Assert-VersionLessThan -Type ([Dumplings.Versioning.WinGetVersion]) -Left '1.0' -Right 'latest'
  }

  It 'orders approximate versions around an equal base version' {
    Assert-VersionLessThan -Type ([Dumplings.Versioning.WinGetVersion]) -Left '< 1.0' -Right '1.0'
    Assert-VersionLessThan -Type ([Dumplings.Versioning.WinGetVersion]) -Left '< 1.0' -Right '> 1.0'
    Assert-VersionLessThan -Type ([Dumplings.Versioning.WinGetVersion]) -Left '1.0' -Right '> 1.0'
    Assert-VersionLessThan -Type ([Dumplings.Versioning.WinGetVersion]) -Left '0.9' -Right '< 1.0'
    { [Dumplings.Versioning.WinGetVersion]'< Unknown' } | Should -Throw
  }

  It 'can be used directly as a Sort-Object key' {
    $Versions = @('1.2', '1.2-rc', '1.10', '1.2.0.1') |
      Sort-Object -Property { [Dumplings.Versioning.WinGetVersion]$_ }
    $Versions | Should -Be @('1.2-rc', '1.2', '1.2.0.1', '1.10')
  }
}

Describe 'ChunkVersion' {
  It 'splits mixed numeric and textual runs when comparing versions' {
    $Versions = @('10', '10rc2', '10rc1', '10beta1', '10alpha2') |
      Sort-Object -Property { [Dumplings.Versioning.ChunkVersion]$_ }
    $Versions | Should -Be @('10alpha2', '10beta1', '10rc1', '10rc2', '10')
  }

  It 'orders prerelease text below a final release and numeric revisions above it' {
    $Versions = @('1.2.3-1', '1.2.3', '1.2.3-rc', '1.2.3-beta', '1.2.3-alpha') |
      Sort-Object -Property { [Dumplings.Versioning.ChunkVersion]$_ }
    $Versions | Should -Be @('1.2.3-alpha', '1.2.3-beta', '1.2.3-rc', '1.2.3', '1.2.3-1')
  }

  It 'normalizes zero-only trailing parts and groups' {
    Assert-VersionEqual -Type ([Dumplings.Versioning.ChunkVersion]) -Left '1.2.3' -Right '1.2.3.0.0'
    Assert-VersionEqual -Type ([Dumplings.Versioning.ChunkVersion]) -Left '1.2.3' -Right '1.2.3-0'
    Assert-VersionEqual -Type ([Dumplings.Versioning.ChunkVersion]) -Left '1.2.3' -Right '1.2.3-0.0.0'
  }

  It 'compares dot-separated values inside distinct release groups' {
    Assert-VersionLessThan -Type ([Dumplings.Versioning.ChunkVersion]) -Left '1.2.3-3.4.5' -Right '1.2.3-3.4.6'
    Assert-VersionLessThan -Type ([Dumplings.Versioning.ChunkVersion]) -Left '1.2.3-3.4.5' -Right '1.2.3-3.5'
    Assert-VersionLessThan -Type ([Dumplings.Versioning.ChunkVersion]) -Left '1.2.3-3.4.5' -Right '1.2.4'
  }

  It 'treats numeric build metadata as significant' {
    Assert-VersionLessThan -Type ([Dumplings.Versioning.ChunkVersion]) -Left '1.1.8+411' -Right '1.1.8+412'
    Assert-VersionLessThan -Type ([Dumplings.Versioning.ChunkVersion]) -Left '1.1.8' -Right '1.1.8+1'
  }

  It 'compares numeric runs without a fixed-width or integer-size limit' {
    Assert-VersionLessThan -Type ([Dumplings.Versioning.ChunkVersion]) -Left '1.999999999999999999999999999999' -Right '1.1000000000000000000000000000000'
    Assert-VersionEqual -Type ([Dumplings.Versioning.ChunkVersion]) -Left '1.0000000000000000000002' -Right '1.2'
  }

  It 'sorts representative task filenames and release values naturally' {
    $Squirrel = @('1.2.10', '1.2.9', '1.2.10-beta') |
      Sort-Object -Property { [Dumplings.Versioning.ChunkVersion]$_ }
    $Squirrel | Should -Be @('1.2.9', '1.2.10-beta', '1.2.10')

    $Files = @('Anaconda3-2024.10-1-Windows-x86_64.exe', 'Anaconda3-2024.2-1-Windows-x86_64.exe') |
      Sort-Object -Property { [Dumplings.Versioning.ChunkVersion]$_ }
    $Files[-1] | Should -Be 'Anaconda3-2024.10-1-Windows-x86_64.exe'

    $Builds = @(@{ distro_version = @(21, 0, 5) }, @{ distro_version = @(21, 0, 12) }) |
      Sort-Object -Property { [Dumplings.Versioning.ChunkVersion]($_.distro_version -join '.') }
    $Builds[-1].distro_version | Should -Be @(21, 0, 12)
  }
}

Describe 'WinGet manifest version listing' {
  It 'sorts local manifest directories with WinGetVersion' {
    $RootPath = Join-Path $TestDrive 'manifests'
    $PackageIdentifier = 'Example.Versioning'
    foreach ($Version in @('1.2', '1.2-rc', '1.10', '1.2.0.1')) {
      $VersionPath = Get-WinGetLocalPackagePath -PackageIdentifier $PackageIdentifier -PackageVersion $Version -RootPath $RootPath
      $null = New-Item -Path $VersionPath -ItemType Directory -Force
      Set-Content -LiteralPath (Join-Path $VersionPath "${PackageIdentifier}.yaml") -Value "PackageVersion: ${Version}"
    }

    $Versions = Get-WinGetLocalPackageVersion -PackageIdentifier $PackageIdentifier -RootPath $RootPath
    $Versions | Should -Be @('1.2-rc', '1.2', '1.2.0.1', '1.10')
  }

  It 'sorts GitHub manifest tree versions with WinGetVersion' {
    $Response = [pscustomobject]@{
      tree = @(
        [pscustomobject]@{ type = 'blob'; path = '1.2/Example.Versioning.yaml' }
        [pscustomobject]@{ type = 'blob'; path = '1.10/Example.Versioning.yaml' }
        [pscustomobject]@{ type = 'blob'; path = '1.2-rc/Example.Versioning.yaml' }
        [pscustomobject]@{ type = 'blob'; path = '1.2.0.1/Example.Versioning.yaml' }
      )
    }
    & $Script:WinGetGitHubRepoModule { param ($Value) $Script:VersioningTestGitHubResponse = $Value } $Response

    $Versions = Get-WinGetGitHubPackageVersion -PackageIdentifier 'Example.Versioning' -RepoOwner owner -RepoName repo -RepoBranch master -RootPath manifests
    $Versions | Should -Be @('1.2-rc', '1.2', '1.2.0.1', '1.10')
  }
}
