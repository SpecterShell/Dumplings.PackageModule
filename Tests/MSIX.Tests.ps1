BeforeAll {
  Import-Module (Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath 'Libraries', 'MSIX.psm1') -Force
}

Describe 'MSIX/AppX dependency filtering' {
  It 'Should read protocol and file association declarations from an AppX manifest' {
    [xml]$Manifest = @'
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10" xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10">
  <Applications>
    <Application Id="App" Executable="Example.exe" EntryPoint="Windows.FullTrustApplication">
      <Extensions>
        <uap:Extension Category="windows.protocol" Executable="Example.exe" EntryPoint="Windows.FullTrustApplication">
          <uap:Protocol Name="example" />
        </uap:Extension>
        <uap:Extension Category="windows.fileTypeAssociation" Executable="Example.exe" EntryPoint="Windows.FullTrustApplication">
          <uap:FileTypeAssociation Name="example.document">
            <uap:SupportedFileTypes><uap:FileType>.example</uap:FileType><uap:FileType>.exdoc</uap:FileType></uap:SupportedFileTypes>
          </uap:FileTypeAssociation>
        </uap:Extension>
      </Extensions>
    </Application>
  </Applications>
</Package>
'@

    $Info = ConvertTo-MSIXManifestAssociationInfo -Manifest @($Manifest)

    $Info.Protocols | Should -Be @('example')
    $Info.FileExtensions | Should -Be @('example', 'exdoc')
    $Info.ProtocolAssociations[0].Executable | Should -Be 'Example.exe'
    ($Info.FileExtensionAssociations | Where-Object FileExtension -eq 'example').AssociationName | Should -Be 'example.document'
  }

  It 'Should include only approved framework dependencies and preserve minimum versions' {
    $Dependencies = @(
      [pscustomobject]@{ PackageIdentifier = 'Microsoft.VCLibs.Desktop.14'; MinimumVersion = '14.0.33728.0'; Publisher = 'CN=Microsoft Corporation' },
      [pscustomobject]@{ PackageIdentifier = 'Microsoft.VCLibs.14'; MinimumVersion = '14.0.33519.0'; Publisher = 'CN=Microsoft Corporation' },
      [pscustomobject]@{ PackageIdentifier = 'Microsoft.WindowsAppRuntime.1.6'; MinimumVersion = '6000.0.0.0'; Publisher = 'CN=Microsoft Corporation' },
      [pscustomobject]@{ PackageIdentifier = 'Microsoft.UI.Xaml.2.8'; MinimumVersion = '8.2310.30001.0'; Publisher = 'CN=Microsoft Corporation' },
      [pscustomobject]@{ PackageIdentifier = 'Contoso.CustomFramework'; MinimumVersion = '1.0.0.0'; Publisher = 'CN=Contoso' }
    )

    $Info = ConvertTo-MSIXManifestDependencyInfo -PackageDependencies $Dependencies

    $Info.Dependencies.PackageDependencies.PackageIdentifier | Should -Contain 'Microsoft.VCLibs.Desktop.14'
    $Info.Dependencies.PackageDependencies.PackageIdentifier | Should -Contain 'Microsoft.VCLibs.14'
    $Info.Dependencies.PackageDependencies.PackageIdentifier | Should -Contain 'Microsoft.WindowsAppRuntime.1.6'
    $Info.Dependencies.PackageDependencies.PackageIdentifier | Should -Contain 'Microsoft.UI.Xaml.2.8'
    $Info.Dependencies.PackageDependencies.PackageIdentifier | Should -Not -Contain 'Contoso.CustomFramework'
    ($Info.Dependencies.PackageDependencies | Where-Object PackageIdentifier -eq 'Microsoft.WindowsAppRuntime.1.6').MinimumVersion | Should -Be '6000.0.0.0'
    $Info.UnknownPackageDependencies.PackageIdentifier | Should -Contain 'Contoso.CustomFramework'
    $Info.Warnings[0] | Should -BeLike "*Contoso.CustomFramework*not included*"
  }

  It 'Should keep the highest minimum version for duplicate allowed dependencies' {
    $Dependencies = @(
      [pscustomobject]@{ PackageIdentifier = 'Microsoft.UI.Xaml.2.8'; MinimumVersion = '8.2200.0.0'; Publisher = 'CN=Microsoft Corporation' },
      [pscustomobject]@{ PackageIdentifier = 'Microsoft.UI.Xaml.2.8'; MinimumVersion = '8.2310.30001.0'; Publisher = 'CN=Microsoft Corporation' }
    )

    $Info = ConvertTo-MSIXManifestDependencyInfo -PackageDependencies $Dependencies

    $Info.Dependencies.PackageDependencies | Should -HaveCount 1
    $Info.Dependencies.PackageDependencies[0].MinimumVersion | Should -Be '8.2310.30001.0'
  }

  It 'Should recognize only the supported dependency package patterns' {
    Test-MSIXAllowedDependencyPackage -PackageIdentifier 'Microsoft.VCLibs.Desktop.14' | Should -BeTrue
    Test-MSIXAllowedDependencyPackage -PackageIdentifier 'Microsoft.VCLibs.14' | Should -BeTrue
    Test-MSIXAllowedDependencyPackage -PackageIdentifier 'Microsoft.WindowsAppRuntime.1.7' | Should -BeTrue
    Test-MSIXAllowedDependencyPackage -PackageIdentifier 'Microsoft.UI.Xaml.2.8' | Should -BeTrue
    Test-MSIXAllowedDependencyPackage -PackageIdentifier 'Microsoft.NET.Native.Framework.2.2' | Should -BeFalse
  }
}
