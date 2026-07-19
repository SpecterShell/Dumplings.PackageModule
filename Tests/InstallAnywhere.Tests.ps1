BeforeAll {
  . (Join-Path $PSScriptRoot 'TestFixture.ps1')
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Runtime.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Binary.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Compression.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Archive.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'RegistryAssociations.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'InstallAnywhere.psm1') -Force

  $Script:FixtureDirectory = Get-DumplingsTestFixtureDirectory -Name 'PackageModule\GenericExeParsers'

  function New-TestZipFile {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][hashtable]$Entry)
    Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    $Archive = [IO.Compression.ZipFile]::Open($Path, [IO.Compression.ZipArchiveMode]::Create)
    try {
      foreach ($Name in $Entry.Keys) {
        $ZipEntry = $Archive.CreateEntry($Name)
        $Writer = [IO.StreamWriter]::new($ZipEntry.Open(), [Text.Encoding]::UTF8)
        try { $Writer.Write([string]$Entry[$Name]) } finally { $Writer.Dispose() }
      }
    } finally { $Archive.Dispose() }
  }

  function New-TestEmbeddedZipFixture {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$ZipPath)
    $Fixture = Join-Path $Script:FixtureDirectory $Name
    Remove-Item -LiteralPath $Fixture -Force -ErrorAction SilentlyContinue
    $Stub = [byte[]](0x4d, 0x5a, 0, 0, 0, 0, 0, 0)
    $Payload = [IO.File]::ReadAllBytes($ZipPath)
    [IO.File]::WriteAllBytes($Fixture, $Stub + $Payload)
    return $Fixture
  }
}

Describe 'InstallAnywhere static parser' {
  It 'Should parse product identity from nested InstallScript.iap_xml' {
    $ExecuteZip = Join-Path $Script:FixtureDirectory 'execute.zip'
    $OuterZip = Join-Path $Script:FixtureDirectory 'installanywhere.zip'
    $ProjectXml = @'
<InstallAnywhere_Deployment_Project><property name="productName"><string>Example IA</string></property><property name="productID"><object><method><string>11111111-1111-1111-1111-111111111111</string></method></object></property><property name="upgradeCode"><object><method><string>22222222-2222-2222-2222-222222222222</string></method></object></property><property name="vendorName"><string>Example Vendor</string></property><property name="productVersion"><object><property name="major"><int>1</int></property><property name="minor"><int>2</int></property><property name="revision"><int>3</int></property><property name="subRevision"><int>4</int></property></object></property></InstallAnywhere_Deployment_Project>
'@
    New-TestZipFile -Path $ExecuteZip -Entry @{ 'InstallScript.iap_xml' = $ProjectXml }
    $ExecuteBytes = [Convert]::ToBase64String([IO.File]::ReadAllBytes($ExecuteZip))
    # ZipArchive entry content is text in this fixture, so decode the base64
    # payload in the parser fixture setup before constructing the outer ZIP.
    Remove-Item -LiteralPath $OuterZip -Force -ErrorAction SilentlyContinue
    $OuterArchive = [IO.Compression.ZipFile]::Open($OuterZip, [IO.Compression.ZipArchiveMode]::Create)
    try {
      $Entry = $OuterArchive.CreateEntry('InstallerData/Execute.zip')
      $Stream = $Entry.Open(); try { $Bytes = [Convert]::FromBase64String($ExecuteBytes); $Stream.Write($Bytes, 0, $Bytes.Length) } finally { $Stream.Dispose() }
      $Marker = $OuterArchive.CreateEntry('InstallerData/IAClasses.zip'); $Marker.Open().Dispose()
    } finally { $OuterArchive.Dispose() }
    $Fixture = New-TestEmbeddedZipFixture -Name 'installanywhere.exe' -ZipPath $OuterZip

    $Info = Get-InstallAnywhereInfo -Path $Fixture

    $Info.ProductCode | Should -Be '11111111-1111-1111-1111-111111111111'
    $Info.UpgradeCode | Should -Be '22222222-2222-2222-2222-222222222222'
    $Info.DisplayName | Should -Be 'Example IA'
    $Info.DisplayVersion | Should -Be '1.2.3.4'
    $Info.Publisher | Should -Be 'Example Vendor'
    $Info.WritesAppsAndFeaturesEntry | Should -BeNullOrEmpty
  }
}
