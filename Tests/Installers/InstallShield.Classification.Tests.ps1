. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')
. (Join-Path $PSScriptRoot '..\Support\InstallShieldTestSetup.ps1')

Describe 'InstallShield container classification' -Tag Unit {
  It 'maps every source-backed project schema without collapsing reported aliases' {
    $ExpectedReleases = [ordered]@{
      755 = @('InstallShield DevStudio 9')
      761 = @('InstallShield 11')
      763 = @('InstallShield 11.5')
      765 = @('InstallShield 12')
      766 = @('InstallShield 2008')
      767 = @('InstallShield 2008')
      768 = @('InstallShield 2009')
      769 = @('InstallShield 2010')
      770 = @('InstallShield 2010')
      771 = @('InstallShield 2011')
      772 = @('InstallShield 2012')
      773 = @('InstallShield 2012 Spring')
      774 = @('InstallShield 2013')
      775 = @('InstallShield 2014')
      776 = @('InstallShield 2015')
      777 = @('InstallShield 2016')
      778 = @('InstallShield 2018 R1')
      779 = @('InstallShield 2018 R2')
      780 = @('InstallShield 2019')
      781 = @('InstallShield 2019 R2')
      782 = @('InstallShield 2019 R3')
      783 = @('InstallShield 2020 R1')
      784 = @('InstallShield 2020 R2', 'InstallShield 2020 R3')
      785 = @('InstallShield 2021 R1')
      787 = @('InstallShield 2022 R2')
      789 = @('InstallShield 2023 R2')
      791 = @('InstallShield 2025 R1')
      792 = @('InstallShield 2026 R1')
    }

    foreach ($Entry in $ExpectedReleases.GetEnumerator()) {
      $Candidates = InModuleScope InstallShield { param($Version) Get-InstallShieldSchemaReleaseCandidate -SchemaVersion $Version } -Parameters @{ Version = $Entry.Key }
      $Candidates.Name | Should -Be $Entry.Value
    }
  }

  It 'reads schema versions only from a structured InstallShield project table' {
    $Project = Join-Path $TestDrive 'sample.ism'
    @'
<?xml version="1.0" encoding="UTF-8"?>
<msi><table name="InstallShield"><row><td>SchemaVersion</td><td>792</td></row></table></msi>
'@.Trim() | Set-Content -LiteralPath $Project -NoNewline

    $Release = Get-InstallShieldProjectReleaseInfo -Path $Project

    $Release.ReleaseName | Should -Be 'InstallShield 2026 R1'
    $Release.ProductVersion | Should -Be '32'
    $Release.SchemaVersion | Should -Be 792
    $Release.SourceFormat | Should -Be 'Xml'
    $Release.Confidence | Should -Be 'Authoritative'
  }

  It 'reads SchemaVersion from an official binary InstallShield project database' {
    $Project = Join-Path $Script:InstallShieldBuilderRoot '11.5\Reference\Othello.ism'
    if (-not (Test-Path -LiteralPath $Project -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The official InstallShield 11.5 binary project fixture is unavailable.'
      return
    }
    Get-DumplingsTestFixtureHash -Path $Project | Should -Be '3A031CAB6DEEBCFCF9C7CCE1FD06D43B60D966B21973D293970A0BA35F8C50EA'

    $Release = Get-InstallShieldProjectReleaseInfo -Path $Project

    $Release.SchemaVersion | Should -Be 763
    $Release.ReleaseName | Should -Be 'InstallShield 11.5'
    $Release.SourceFormat | Should -Be 'WindowsInstallerDatabase'
  }

  It 'recognizes release schemas from additional official builder projects' {
    $Cases = @(
      [pscustomobject]@{ RelativePath = '2008\Reference\Othello.ism'; Hash = '93873F57FE10FB0E92BE2631F146BFDB9E180CD042D055AC1DAE03330383A91B'; Schema = 766; Release = 'InstallShield 2008' }
      [pscustomobject]@{ RelativePath = '2009\Reference\Othello.ism'; Hash = '648C055A3B5FEAB66DB7116A597F8EE951AF7ECDE023EE28166B0E23A025F96D'; Schema = 768; Release = 'InstallShield 2009' }
      [pscustomobject]@{ RelativePath = '2010\Reference\Othello.ism'; Hash = '1FE6A59F21BFBF1645F15EC81294D6B55B8EC8E06E6703A2E1E1E1A6486E0DD8'; Schema = 769; Release = 'InstallShield 2010' }
      [pscustomobject]@{ RelativePath = '2011\Reference\Othello.ism'; Hash = '1613EE01BEBE3C7470F3A18FAE4F9D52AC4539CD39082A38410E098DC94169C1'; Schema = 771; Release = 'InstallShield 2011' }
      [pscustomobject]@{ RelativePath = '2012Spring\Reference\Othello.ism'; Hash = 'FA3C13477A316CDAA411670045D05525DD0944F1F5D15FD63BCC7245BC0B87B3'; Schema = 773; Release = 'InstallShield 2012 Spring' }
      [pscustomobject]@{ RelativePath = '2013\Reference\Othello.ism'; Hash = '8639FBA7D9DE0E06169268116E188C7AD2414152AF97113D5701D990E772CA17'; Schema = 774; Release = 'InstallShield 2013' }
      [pscustomobject]@{ RelativePath = '2015\Reference\Othello.ism'; Hash = 'CDEC1FDF0B7C3A79EF1DF9F96E911687D7C7E146ACFF50A58B29014AC3773610'; Schema = 776; Release = 'InstallShield 2015' }
      [pscustomobject]@{ RelativePath = '2019R2\Reference\Othello.ism'; Hash = '95B5043F4FDF78F6C12C94E2B0BC6B1AEA9662A0289E60A658165AAACBCA4798'; Schema = 781; Release = 'InstallShield 2019 R2' }
      [pscustomobject]@{ RelativePath = '2019R3\Reference\Othello.ism'; Hash = '8E9019DC74EBE5379A6E1536C57CE8CE5FF31EFAB40F7A21151C71E15295B75B'; Schema = 782; Release = 'InstallShield 2019 R3' }
      [pscustomobject]@{ RelativePath = '2020R1\Reference\Othello.ism'; Hash = 'D2AF432501715002F1C8E1C94272A7E5A2F019B37140A94710318CBC727F5542'; Schema = 783; Release = 'InstallShield 2020 R1' }
      [pscustomobject]@{ RelativePath = '2021R1\Reference\Othello.ism'; Hash = '8FF2364E3546FCAEDBD3195AB556CA8BC33964707A220E96B3B5DEA0DB8CA725'; Schema = 785; Release = 'InstallShield 2021 R1' }
    )

    foreach ($Case in $Cases) {
      $Project = Join-Path $Script:InstallShieldBuilderRoot $Case.RelativePath
      if (-not (Test-Path -LiteralPath $Project -PathType Leaf)) {
        Set-ItResult -Skipped -Because "The official InstallShield project fixture '$($Case.RelativePath)' is unavailable."
        return
      }
      Get-DumplingsTestFixtureHash -Path $Project | Should -Be $Case.Hash
      $Release = Get-InstallShieldProjectReleaseInfo -Path $Project
      $Release.SchemaVersion | Should -Be $Case.Schema
      $Release.ReleaseName | Should -Be $Case.Release
      $Release.Confidence | Should -Be 'OfficialBuilder'
    }
  }

  It 'rejects an arbitrary file that merely contains a SchemaVersion string' {
    $Path = Join-Path $TestDrive 'not-a-project.exe'
    [IO.File]::WriteAllText($Path, 'SchemaVersion=792')
    { Get-InstallShieldProjectReleaseInfo -Path $Path } | Should -Throw
  }

  It 'preserves an unmapped structured schema value for future classification' {
    $Project = Join-Path $TestDrive 'future.ism'
    '<msi><table name="InstallShield"><row><td>SchemaVersion</td><td>999</td></row></table></msi>' |
      Set-Content -LiteralPath $Project -NoNewline

    $Release = Get-InstallShieldProjectReleaseInfo -Path $Project

    $Release.SchemaVersion | Should -Be 999
    $Release.ReleaseName | Should -BeNullOrEmpty
    $Release.Confidence | Should -Be 'Unknown'
  }

  It 'distinguishes incomplete binary templates and proprietary project representations' {
    $EmptyProject = Join-Path $Script:InstallShieldBuilderRoot '11.5\Reference\IsBlank.ism'
    $ProprietaryProject = Join-Path $Script:InstallShieldBuilderRoot '11.5\Reference\Phobos.ism'
    if (-not (Test-Path -LiteralPath $EmptyProject -PathType Leaf) -or -not (Test-Path -LiteralPath $ProprietaryProject -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The official InstallShield 11.5 project-template fixtures are unavailable.'
      return
    }
    Get-DumplingsTestFixtureHash -Path $EmptyProject | Should -Be '61996698AA765F6202C470194BEAFCDE6D26BF610B11E99918DAA3F543D51852'
    Get-DumplingsTestFixtureHash -Path $ProprietaryProject | Should -Be 'C24301D7B9E690B833A7E18309FA5BBF1FF266C405F8BB811AE9793ACCA27F09'

    { Get-InstallShieldProjectReleaseInfo -Path $EmptyProject } | Should -Throw '*does not contain a readable InstallShield.SchemaVersion row*'
    { Get-InstallShieldProjectReleaseInfo -Path $ProprietaryProject } | Should -Throw '*unsupported structured representation*'
  }

  It 'recognizes the cached official InstallShield 2026 R1 project schema' {
    $Project = Join-Path $Script:InstallShieldBuilderRoot '2026R1\Differential\Baseline2\ALLUSERS Sample Project.ism'
    if (-not (Test-Path -LiteralPath $Project -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The official InstallShield 2026 R1 project fixture is unavailable.'
      return
    }

    $Release = Get-InstallShieldProjectReleaseInfo -Path $Project

    $Release.SchemaVersion | Should -Be 792
    $Release.ReleaseName | Should -Be 'InstallShield 2026 R1'
    $Release.Confidence | Should -Be 'Authoritative'
  }

  It 'preserves reported schema aliases without inventing a conflict' {
    $Candidates = InModuleScope InstallShield { Get-InstallShieldSchemaReleaseCandidate -SchemaVersion 769 }
    $Candidates.Name | Should -Be 'InstallShield 2010'
    $Candidates.Confidence | Should -Be 'OfficialBuilder'
    $Candidates = InModuleScope InstallShield { Get-InstallShieldSchemaReleaseCandidate -SchemaVersion 770 }
    $Candidates.Name | Should -Be 'InstallShield 2010'
    $Candidates.Confidence | Should -Be 'ReportedAlias'
    $Candidates = InModuleScope InstallShield { Get-InstallShieldSchemaReleaseCandidate -SchemaVersion 784 }
    $Candidates.Name | Should -Be @('InstallShield 2020 R2', 'InstallShield 2020 R3')
  }

  It 'narrows trusted product versions and names to official point releases' {
    $Cases = @(
      [pscustomobject]@{ Version = '25'; ProductName = ''; Releases = @('InstallShield 2019') }
      [pscustomobject]@{ Version = '25.0.676'; ProductName = 'InstallShield 2019 R2'; Releases = @('InstallShield 2019 R2') }
      [pscustomobject]@{ Version = '25.1.0000'; ProductName = ''; Releases = @('InstallShield 2019 R2') }
      [pscustomobject]@{ Version = '25.0.764'; ProductName = 'InstallShield 2019 R3'; Releases = @('InstallShield 2019 R3') }
      [pscustomobject]@{ Version = '25.2.0000'; ProductName = ''; Releases = @('InstallShield 2019 R3') }
      [pscustomobject]@{ Version = '26.0.546'; ProductName = 'InstallShield 2020 R1'; Releases = @('InstallShield 2020 R1') }
      [pscustomobject]@{ Version = '26.00.0000'; ProductName = ''; Releases = @('InstallShield 2020 R1') }
      [pscustomobject]@{ Version = '27.0.58'; ProductName = 'InstallShield 2021 R1'; Releases = @('InstallShield 2021 R1') }
    )
    foreach ($Case in $Cases) {
      $Candidates = InModuleScope InstallShield -Parameters @{ Version = $Case.Version; ProductName = $Case.ProductName } {
        param($Version, $ProductName)
        Get-InstallShieldProductReleaseCandidate -ProductVersion $Version -ProductName $ProductName
      }
      $Candidates.Name | Should -Be $Case.Releases
    }
  }

  It 'returns no release candidates for an unknown runtime major' {
    $Candidates = InModuleScope InstallShield { Get-InstallShieldProductReleaseCandidate -ProductVersion '99.1.2.3' -ProductName 'InstallShield Future' }
    $Candidates | Should -BeNullOrEmpty
  }

  It 'uses exact runtime identity to refine a broad Advanced UI year' {
    $Release = InModuleScope InstallShield {
      $Broad = ConvertTo-InstallShieldReleaseEvidence -Source AdvancedUI -Value 2019 -Candidate ([ordered]@{ Name = 'InstallShield 2019'; ProductVersion = '25'; Year = 2019 }) -Confidence ExactSuiteNamespace -Rank 100 -Detail Suite
      $Exact = ConvertTo-InstallShieldReleaseEvidence -Source RuntimePE -Value '25.0.676' -Candidate ([ordered]@{ Name = 'InstallShield 2019 R2'; ProductVersion = '25'; Year = 2019; Specificity = 20 }) -Confidence TrustedRuntimeVersion -Rank 50 -Detail Runtime
      Resolve-InstallShieldRelease -Evidence @($Broad, $Exact)
    }

    $Release.ReleaseName | Should -Be 'InstallShield 2019 R2'
    $Release.Confidence | Should -Be 'TrustedRuntimeVersion'
    $Release.Warnings | Should -BeNullOrEmpty
  }

  It 'reports conflicting exact point-release evidence without changing dispatch' {
    $Release = InModuleScope InstallShield {
      $Schema = ConvertTo-InstallShieldReleaseEvidence -Source ProjectSchema -Value 781 -Candidate ([ordered]@{ Name = 'InstallShield 2019 R2'; ProductVersion = '25'; Year = 2019; Specificity = 20 }) -Confidence OfficialBuilder -Rank 120 -Detail Project
      $Runtime = ConvertTo-InstallShieldReleaseEvidence -Source RuntimePE -Value '25.0.764' -Candidate ([ordered]@{ Name = 'InstallShield 2019 R3'; ProductVersion = '25'; Year = 2019; Specificity = 20 }) -Confidence TrustedRuntimeVersion -Rank 50 -Detail Runtime
      Resolve-InstallShieldRelease -Evidence @($Schema, $Runtime)
    }

    $Release.ReleaseName | Should -Be 'InstallShield 2019 R2'
    $Release.Confidence | Should -Be 'Conflicting'
    $Release.Warnings | Should -Match 'Structural routes remain authoritative'
  }

  It 'keeps conflicting release evidence separate from structural dispatch' {
    $Release = InModuleScope InstallShield {
      $First = ConvertTo-InstallShieldReleaseEvidence -Source ProjectSchema -Value 792 -Candidate ([pscustomobject]@{ Name = 'InstallShield 2026 R1'; ProductVersion = '32'; Year = 2026 }) -Confidence Authoritative -Rank 120 -Detail Project
      $Second = ConvertTo-InstallShieldReleaseEvidence -Source CabinetHeader -Value 6 -Candidate ([pscustomobject]@{ Name = 'InstallShield Professional 6'; ProductVersion = '6'; Year = 1999 }) -Confidence StructuralMediaVersion -Rank 90 -Detail Media
      Resolve-InstallShieldRelease -Evidence @($First, $Second)
    }

    $Release.ReleaseName | Should -Be 'InstallShield 2026 R1'
    $Release.Confidence | Should -Be 'Conflicting'
    $Release.Warnings | Should -Match 'Structural routes remain authoritative'
  }

  It 'does not treat a cabinet format generation as a builder product release' {
    $Release = InModuleScope InstallShield {
      $Media = ConvertTo-InstallShieldReleaseEvidence -Source CabinetHeader -Value ([uint32]0x01009500) -Candidate $null `
        -Confidence StructuralMediaVersion -Rank 0 -Detail 'ISc( cabinet format 9'
      $RuntimeCandidate = Get-InstallShieldProductReleaseCandidate -ProductVersion '11.50.0' | Select-Object -First 1
      $Runtime = ConvertTo-InstallShieldReleaseEvidence -Source RuntimePE -Value '11.50.0' -Candidate $RuntimeCandidate `
        -Confidence TrustedRuntimeVersion -Rank 50 -Detail Runtime
      Resolve-InstallShieldRelease -Evidence @($Media, $Runtime)
    }

    $Release.ReleaseName | Should -Be 'InstallShield 11.5'
    $Release.Confidence | Should -Be 'TrustedRuntimeVersion'
    $Release.Evidence | Where-Object Source -EQ CabinetHeader | Select-Object -ExpandProperty ReleaseName | Should -BeNullOrEmpty
    $Release.Warnings | Should -BeNullOrEmpty
  }

  It 'uses compatible runtime detail without replacing stronger release identity' {
    $Release = InModuleScope InstallShield {
      $Candidate = [pscustomobject]@{ Name = 'InstallShield 2026 R1'; ProductVersion = '32'; Year = 2026 }
      $Schema = ConvertTo-InstallShieldReleaseEvidence -Source ProjectSchema -Value 792 -Candidate $Candidate -Confidence Authoritative -Rank 120 -Detail Project
      $Runtime = ConvertTo-InstallShieldReleaseEvidence -Source RuntimePE -Value '32.0 SP2.144' -Candidate $Candidate -Confidence TrustedRuntimeVersion -Rank 50 -Detail Runtime
      $Runtime.ServicePack = '2'
      $Runtime.Build = '144'
      Resolve-InstallShieldRelease -Evidence @($Schema, $Runtime)
    }

    $Release.ReleaseName | Should -Be 'InstallShield 2026 R1'
    $Release.SchemaVersion | Should -Be 792
    $Release.ServicePack | Should -Be '2'
    $Release.Build | Should -Be '144'
  }

  It 'uses source-backed product and file versions from official runtime stubs' {
    $Cases = @(
      [pscustomobject]@{ Path = Join-Path $Script:InstallShieldBuilderRoot '11.5\Reference\RuntimeStubs\setup-7.exe'; Hash = 'CFB39234D54F3D968B405FD197078AF8C4B87A19BD4F0752FE4935BC4EB757B9'; Release = 'InstallShield Developer 7'; Build = '262' }
      [pscustomobject]@{ Path = Join-Path $Script:InstallShieldBuilderRoot '11.5\Reference\RuntimeStubs\setup-8.exe'; Hash = '327564AAE042851953F52D1C030913EBE127F95521FEFAF4EE2BF55A640CBF79'; Release = 'InstallShield Developer 8'; Build = '160' }
      [pscustomobject]@{ Path = Join-Path $Script:InstallShieldBuilderRoot '11.5\Reference\RuntimeStubs\setup-9.exe'; Hash = '90AEE2AE77B05500DB7D5623B7B152229207C24529D433542FDEAD722219F1F6'; Release = 'InstallShield DevStudio 9'; Build = '333' }
      [pscustomobject]@{ Path = Join-Path $Script:InstallShieldBuilderRoot '11.5\Reference\RuntimeStubs\setup-10.exe'; Hash = 'FA240AABE0C6B20D556D72CF3954BB440756E852D49957F841EC4E13351AA1F0'; Release = 'InstallShield X/10.5'; Build = '238' }
      [pscustomobject]@{ Path = Join-Path $Script:InstallShieldBuilderRoot '11.5\Reference\RuntimeStubs\setup-11.exe'; Hash = '0639408923040D69FFDC18A1F57ECA4E598489A649BD4C3476401A7F415B62BA'; Release = 'InstallShield 11'; Build = '28844' }
      [pscustomobject]@{ Path = Join-Path $Script:InstallShieldBuilderRoot '11.5\Reference\setup.dll'; Hash = '47B4E860B81058CFF4D52DE76764EC801D0A26549214D80356D05FCBEAA3CC60'; Release = 'InstallShield 11.5'; Build = '42618' }
      [pscustomobject]@{ Path = Join-Path $Script:InstallShieldBuilderRoot '2026R1\Reference\setup.exe'; Hash = 'CAA788B72688266BD6BDFD6BD11820B4A79132BD97D95C1AE058E66EF5BE5CA8'; Release = 'InstallShield 2026 R1'; Build = '68' }
    )
    foreach ($Case in $Cases) {
      if (-not (Test-Path -LiteralPath $Case.Path -PathType Leaf)) {
        Set-ItResult -Skipped -Because "The official runtime fixture '$($Case.Path)' is unavailable."
        return
      }
      Get-DumplingsTestFixtureHash -Path $Case.Path | Should -Be $Case.Hash
      $Evidence = InModuleScope InstallShield -Parameters @{ RuntimePath = $Case.Path } {
        param($RuntimePath)
        Get-InstallShieldRuntimeReleaseEvidence -Path $RuntimePath | Select-Object -First 1
      }
      $Evidence.ReleaseName | Should -Be $Case.Release
      $Evidence.Build | Should -Be $Case.Build
    }
  }

  It 'keeps classic and future cabinet profiles as independent structural routes' {
    $Routes = InModuleScope InstallShield {
      $Context = [pscustomobject]@{
        PackageForTheWebCabinet = $null
        Extraction              = $null
        Classic3Info            = [pscustomobject]@{
          SupportStatus = 'Supported'
          Evidence      = @([pscustomobject]@{ Signature = 'Setup30 footer' })
          Limitations   = @()
          Entries       = @([pscustomobject]@{ Name = 'setup.ins' })
        }
        CabinetSupport          = [pscustomobject]@{
          MediaVersions = @([pscustomobject]@{
              MajorVersion  = 33
              RawVersion    = [uint32]0x01021000
              SupportStatus = 'Partial'
              Limitations   = @('Future catalog extensions are unresolved.')
            })
        }
        InstallScriptHeaders    = @()
        SelectedMsiInfo         = $null
        AdvancedUiInfo          = $null
      }
      Get-InstallShieldStructuralRoute -Context $Context -Result ([pscustomobject]@{ InstallScriptInfo = $null })
    }

    $Routes.RouteId | Should -Be @('Classic3/Package', 'Classic3/INS', 'Cabinet17/UnicodeCatalog')
    ($Routes | Where-Object RouteId -EQ 'Classic3/INS').SupportStatus | Should -Be 'Supported'
    ($Routes | Where-Object RouteId -EQ 'Cabinet17/UnicodeCatalog').SupportStatus | Should -Be 'Partial'
    ($Routes | Where-Object RouteId -EQ 'Cabinet17/UnicodeCatalog').Limitations | Should -Contain 'Future catalog extensions are unresolved.'
  }
}
