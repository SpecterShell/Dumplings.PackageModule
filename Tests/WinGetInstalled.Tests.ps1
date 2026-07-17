BeforeAll {
  Import-Module (Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath 'Libraries', 'WinGetARP.psm1') -Force

  $Script:Manifest = [ordered]@{
    Version   = [ordered]@{
      PackageIdentifier = 'Contoso.App'
      PackageVersion    = '1.2.3'
      DefaultLocale     = 'en-US'
    }
    Installer = [ordered]@{
      ManifestType = 'installer'
      ProductCode  = '{11111111-1111-1111-1111-111111111111}'
      Installers   = @(
        [ordered]@{
          Architecture           = 'x64'
          InstallerType          = 'msi'
          AppsAndFeaturesEntries = @(
            [ordered]@{
              DisplayName = 'Contoso Desktop'
              Publisher   = 'Contoso, Ltd.'
              UpgradeCode = '{22222222-2222-2222-2222-222222222222}'
            }
          )
        },
        [ordered]@{
          Architecture      = 'arm64'
          InstallerType     = 'msix'
          PackageFamilyName = 'Contoso.App_1234567890abc'
          ProductCode       = '{33333333-3333-3333-3333-333333333333}'
        }
      )
    }
    Locale    = @(
      [ordered]@{
        ManifestType  = 'defaultLocale'
        PackageLocale = 'en-US'
        PackageName   = 'Contoso App'
        Publisher     = 'Contoso, Ltd.'
      },
      [ordered]@{
        ManifestType  = 'locale'
        PackageLocale = 'fr-FR'
        PackageName   = 'Contoso Application'
      }
    )
  }
}

Describe 'WinGet installed-entry matching helpers' {
  It 'Should normalize name and publisher by removing common version, architecture, and legal suffix noise' {
    $Normalized = ConvertTo-WinGetNormalizedNameAndPublisher -Name 'Contoso App 1.2.3 (x64)' -Publisher 'Contoso, Ltd.'

    $Normalized.NormalizedName | Should -Be 'ContosoApp'
    $Normalized.NormalizedPublisher | Should -Be 'Contoso'
    $Normalized.NormalizedNameAndPublisher | Should -Be 'Contoso.ContosoApp'
  }

  It 'Should build manifest match keys from installer-level and manifest-level fields' {
    $Keys = Get-WinGetManifestMatchKey -Manifest $Script:Manifest

    $Keys.ProductCodes | Should -Contain '{11111111-1111-1111-1111-111111111111}'
    $Keys.ProductCodes | Should -Contain '{33333333-3333-3333-3333-333333333333}'
    $Keys.UpgradeCodes | Should -Contain '{22222222-2222-2222-2222-222222222222}'
    $Keys.PackageFamilyNames | Should -Contain 'Contoso.App_1234567890abc'
    $Keys.NormalizedNameAndPublisher.NormalizedNameAndPublisher | Should -Contain 'Contoso.ContosoApp'
    $Keys.NormalizedNameAndPublisher.NormalizedNameAndPublisher | Should -Contain 'Contoso.ContosoDesktop'
  }

  It 'Should match an ARP entry by ProductCode' {
    $Entry = [pscustomobject]@{
      Source      = 'ARP'
      ProductCode = '{11111111-1111-1111-1111-111111111111}'
      DisplayName = 'Unexpected Name'
      Publisher   = 'Unexpected Publisher'
    }

    $Match = Find-WinGetManifestInstalledEntryMatch -Manifest $Script:Manifest -InstalledEntry $Entry

    $Match.IsMatch | Should -BeTrue
    $Match.MatchFields | Should -Contain 'ProductCode'
  }

  It 'Should match an ARP entry by UpgradeCode' {
    $Entry = [pscustomobject]@{
      Source      = 'ARP'
      ProductCode = '{44444444-4444-4444-4444-444444444444}'
      UpgradeCode = '{22222222-2222-2222-2222-222222222222}'
      DisplayName = 'Unexpected Name'
      Publisher   = 'Unexpected Publisher'
    }

    $Match = Find-WinGetManifestInstalledEntryMatch -Manifest $Script:Manifest -InstalledEntry $Entry

    $Match.IsMatch | Should -BeTrue
    $Match.MatchFields | Should -Contain 'UpgradeCode'
  }

  It 'Should match an AppX/MSIX entry by PackageFamilyName' {
    $Entry = [pscustomobject]@{
      Source            = 'AppX'
      PackageFamilyName = 'Contoso.App_1234567890abc'
      DisplayName       = 'Unexpected Name'
      Publisher         = 'Unexpected Publisher'
    }

    $Match = Find-WinGetManifestInstalledEntryMatch -Manifest $Script:Manifest -InstalledEntry $Entry

    $Match.IsMatch | Should -BeTrue
    $Match.MatchFields | Should -Contain 'PackageFamilyName'
  }

  It 'Should match an ARP entry by normalized AppsAndFeatures DisplayName and Publisher' {
    $Entry = [pscustomobject]@{
      Source      = 'ARP'
      ProductCode = 'Contoso Custom Key'
      DisplayName = 'Contoso Desktop 1.2.3'
      Publisher   = 'Contoso Ltd'
    }

    $Match = Find-WinGetManifestInstalledEntryMatch -Manifest $Script:Manifest -InstalledEntry $Entry

    $Match.IsMatch | Should -BeTrue
    $Match.MatchFields | Should -Contain 'NormalizedNameAndPublisher'
  }

  It 'Should return false when no manifest key matches an installed entry' {
    $Entry = [pscustomobject]@{
      Source            = 'ARP'
      ProductCode       = '{55555555-5555-5555-5555-555555555555}'
      UpgradeCode       = '{66666666-6666-6666-6666-666666666666}'
      PackageFamilyName = 'Different.App_1234567890abc'
      DisplayName       = 'Different App'
      Publisher         = 'Different Publisher'
    }

    Test-WinGetManifestInstalledEntryMatch -Manifest $Script:Manifest -InstalledEntry $Entry | Should -BeFalse
  }
}

Describe 'MSI UserData install-context helpers' {
  It 'Should convert MSI ProductCode values to and from packed registry GUIDs' {
    $ProductCode = '{FECAFEB5-8D0E-4AE4-8FA0-745BAA835C35}'
    $Packed = ConvertTo-WinGetMsiPackedGuid -Guid $ProductCode

    $Packed | Should -Be '5BEFACEFE0D84EA4F80A47B5AA38C553'
    ConvertFrom-WinGetMsiPackedGuid -PackedGuid $Packed | Should -Be $ProductCode
  }

  It 'Should classify S-1-5-18 MSI UserData evidence as machine context' {
    $Context = Resolve-WinGetMsiARPInstallContext -ProductCode '{11111111-1111-1111-1111-111111111111}' -CurrentUserSid 'S-1-5-21-1000' -UserDataEntry @(
      [pscustomobject]@{ Sid = 'S-1-5-18'; Context = 'machine' }
    )

    $Context.InstallContext | Should -Be 'machine'
    $Context.IsMachine | Should -BeTrue
    $Context.IsCurrentUser | Should -BeFalse
    $Context.IsOtherUser | Should -BeFalse
  }

  It 'Should classify current-user MSI UserData evidence as user context' {
    $Context = Resolve-WinGetMsiARPInstallContext -ProductCode '{11111111-1111-1111-1111-111111111111}' -CurrentUserSid 'S-1-5-21-1000' -UserDataEntry @(
      [pscustomobject]@{ Sid = 'S-1-5-21-1000'; Context = 'user' }
    )

    $Context.InstallContext | Should -Be 'user'
    $Context.IsMachine | Should -BeFalse
    $Context.IsCurrentUser | Should -BeTrue
    $Context.IsOtherUser | Should -BeFalse
  }

  It 'Should classify another user SID as otherUser context' {
    $Context = Resolve-WinGetMsiARPInstallContext -ProductCode '{11111111-1111-1111-1111-111111111111}' -CurrentUserSid 'S-1-5-21-1000' -UserDataEntry @(
      [pscustomobject]@{ Sid = 'S-1-5-21-2000'; Context = 'otherUser' }
    )

    $Context.InstallContext | Should -Be 'otherUser'
    $Context.IsMachine | Should -BeFalse
    $Context.IsCurrentUser | Should -BeFalse
    $Context.IsOtherUser | Should -BeTrue
    $Context.OtherUserSids | Should -Contain 'S-1-5-21-2000'
  }

  It 'Should classify multiple MSI UserData contexts as mixed' {
    $Context = Resolve-WinGetMsiARPInstallContext -ProductCode '{11111111-1111-1111-1111-111111111111}' -CurrentUserSid 'S-1-5-21-1000' -UserDataEntry @(
      [pscustomobject]@{ Sid = 'S-1-5-18'; Context = 'machine' },
      [pscustomobject]@{ Sid = 'S-1-5-21-1000'; Context = 'user' }
    )

    $Context.InstallContext | Should -Be 'mixed'
    $Context.IsMachine | Should -BeTrue
    $Context.IsCurrentUser | Should -BeTrue
  }
}
