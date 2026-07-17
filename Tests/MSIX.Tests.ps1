BeforeAll {
  Import-Module (Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath 'Libraries', 'MSIX.psm1') -Force
}

Describe 'MSIX/AppX dependency filtering' {
  It 'Should map package and bundle extensions to WinGet installer types' {
    Get-MSIXInstallerType -Path 'https://example.test/Product.appx?token=value' | Should -Be 'appx'
    Get-MSIXInstallerType -Path 'https://example.test/Product.appxbundle' | Should -Be 'appx'
    Get-MSIXInstallerType -Path 'https://example.test/Product.msix' | Should -Be 'msix'
    Get-MSIXInstallerType -Path 'https://example.test/Product.msixbundle' | Should -Be 'msix'
  }

  It 'Should map every item received from the pipeline' {
    $Types = 'Product.appx', 'Product.appxbundle', 'Product.msix', 'Product.msixbundle' | Get-MSIXInstallerType
    $Types | Should -Be @('appx', 'appx', 'msix', 'msix')
  }

  It 'Should use a known installer type for an extensionless cached package' {
    Get-MSIXInstallerType -Path (Join-Path $TestDrive 'cached-installer') -InstallerTypeHint appx | Should -Be 'appx'
    Get-MSIXInstallerType -Path (Join-Path $TestDrive 'cached-installer') -InstallerTypeHint msix | Should -Be 'msix'
  }

  It 'Should read package metadata from an extensionless cached package' {
    $PackageDirectory = New-Item -Path (Join-Path $TestDrive 'appx-content') -ItemType Directory
    Set-Content -LiteralPath (Join-Path $PackageDirectory.FullName 'AppxManifest.xml') -Value @'
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="Example.App" Publisher="CN=Example" Version="1.2.3.4" ProcessorArchitecture="x64" />
  <Properties>
    <DisplayName>Example App</DisplayName>
    <PublisherDisplayName>Example Publisher</PublisherDisplayName>
  </Properties>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.19041.0" MaxVersionTested="10.0.26100.0" />
  </Dependencies>
</Package>
'@
    [System.IO.File]::WriteAllBytes((Join-Path $PackageDirectory.FullName 'AppxSignature.p7x'), [byte[]](1, 2, 3, 4))
    $PackagePath = Join-Path $TestDrive 'cached-installer'
    [System.IO.Compression.ZipFile]::CreateFromDirectory($PackageDirectory.FullName, $PackagePath)

    Get-MSIXPackageKind -Path $PackagePath | Should -Be 'Package'
    $Info = Get-MSIXInfo -Path $PackagePath

    $Info.InstallerType | Should -Be 'msix'
    $Info.PackageKind | Should -Be 'Package'
    $Info.InstallerTypeEvidence | Should -Be 'WinGetCompatibleFallback'
    $Info.InstallerTypeAmbiguous | Should -BeTrue
    $Info.Warnings | Should -Contain 'The archive is an AppX/MSIX package, but AppX and MSIX cannot be distinguished from package content alone. Using the WinGet-compatible msix fallback.'
    $Info.Name | Should -Be 'Example.App'
    $Info.Version | Should -Be '1.2.3.4'
    $Info.PackageFamilyName | Should -Be 'Example.App_s2ne61n4j7kre'
  }

  It 'Should resolve an extensionless bundle from embedded payload filenames' {
    $BundleDirectory = New-Item -Path (Join-Path $TestDrive 'bundle-content') -ItemType Directory
    $MetadataDirectory = New-Item -Path (Join-Path $BundleDirectory.FullName 'AppxMetadata') -ItemType Directory
    Set-Content -LiteralPath (Join-Path $MetadataDirectory.FullName 'AppxBundleManifest.xml') -Value @'
<Bundle xmlns="http://schemas.microsoft.com/appx/2013/bundle">
  <Identity Name="Example.Bundle" Publisher="CN=Example" Version="1.2.3.4" />
  <Packages><Package Type="application" Architecture="x64" FileName="Example.App.appx" /></Packages>
</Bundle>
'@
    Set-Content -LiteralPath (Join-Path $BundleDirectory.FullName 'Example.App.appx') -Value 'payload'
    $BundlePath = Join-Path $TestDrive 'cached-bundle'
    [System.IO.Compression.ZipFile]::CreateFromDirectory($BundleDirectory.FullName, $BundlePath)

    $TypeInfo = Get-MSIXPackageTypeInfo -Path $BundlePath

    $TypeInfo.PackageKind | Should -Be 'Bundle'
    $TypeInfo.InstallerType | Should -Be 'appx'
    $TypeInfo.Evidence | Should -Be 'BundlePayloadFileName'
    $TypeInfo.IsAmbiguous | Should -BeFalse
  }

  It 'Should use HTTP content type when the URI has no package extension' {
    $TypeInfo = Get-MSIXPackageTypeInfo -Path 'https://example.test/download' -ContentType 'application/msixbundle; charset=binary'

    $TypeInfo.InstallerType | Should -Be 'msix'
    $TypeInfo.PackageKind | Should -Be 'Bundle'
    $TypeInfo.Evidence | Should -Be 'HttpContentType'

    Get-MSIXInstallerType -Path 'https://example.test/download' -ContentType 'application/vns.ms-appx' | Should -Be 'appx'
  }

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
    ($Info.FileExtensionAssociations | Where-Object FileExtension -EQ 'example').AssociationName | Should -Be 'example.document'
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
    ($Info.Dependencies.PackageDependencies | Where-Object PackageIdentifier -EQ 'Microsoft.WindowsAppRuntime.1.6').MinimumVersion | Should -Be '6000.0.0.0'
    $Info.UnknownPackageDependencies.PackageIdentifier | Should -Contain 'Contoso.CustomFramework'
    $Info.Warnings[0] | Should -BeLike '*Contoso.CustomFramework*not included*'
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
