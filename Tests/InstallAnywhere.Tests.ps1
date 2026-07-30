BeforeAll {
  . (Join-Path $PSScriptRoot 'TestFixture.ps1')
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Runtime.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Binary.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Compression.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Archive.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'InstallerCondition.psm1') -Force
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
  It 'builds one analysis context without reparsing the archive or project XML' {
    InModuleScope InstallAnywhere {
      Mock Get-InstallAnywhereArchiveData { [pscustomobject]@{ Path = 'synthetic.exe' } }
      Mock Get-InstallAnywhereProjectXml { '<InstallAnywhere_Deployment_Project />' }
      Mock Get-InstallAnywhereObject {
        param($Xml, $ClassName)
        if ($ClassName -eq 'com.zerog.ia.installer.util.InstallerInfoData') { return [pscustomobject]@{ Kind = 'Info' } }
        return [pscustomobject]@{ Kind = 'Installer' }
      }
      Mock Get-InstallAnywhereRegistryWrite { @() }
      Mock Get-InstallerRegistryAssociationInfo { [pscustomobject]@{ Protocols = @(); FileExtensions = @() } }
      Mock Get-InstallAnywhereActionAndRuleInfo { [pscustomobject]@{ Actions = @(); Rules = @() } }

      $Context = New-InstallAnywhereAnalysisContext -Path 'synthetic.exe'

      $Context.ArchiveData.Path | Should -Be 'synthetic.exe'
      Should -Invoke Get-InstallAnywhereArchiveData -Exactly 1
      Should -Invoke Get-InstallAnywhereProjectXml -Exactly 1
      Should -Invoke Get-InstallAnywhereRegistryWrite -Exactly 1
      Should -Invoke Get-InstallAnywhereActionAndRuleInfo -Exactly 1
    }
  }

  It 'Should parse product identity from nested InstallScript.iap_xml' {
    $ExecuteZip = Join-Path $Script:FixtureDirectory 'execute.zip'
    $OuterZip = Join-Path $Script:FixtureDirectory 'installanywhere.zip'
    $ProjectXml = @'
<InstallAnywhere_Deployment_Project>
  <object class="com.zerog.ia.installer.Installer">
    <property name="supportsSilentUI"><boolean>true</boolean></property>
    <property name="supportsConsoleUI"><boolean>false</boolean></property>
    <property name="responseFileEnabled"><boolean>false</boolean></property>
    <property name="notUpdateGlobalRegistry"><boolean>false</boolean></property>
    <property name="instanceDefinition"><object class="com.zerog.ia.installer.InstanceDefinition"><property name="enableInstanceManagement"><boolean>false</boolean></property></object></property>
  </object>
  <object class="com.zerog.ia.installer.util.InstallerInfoData">
    <property name="productName"><string>Example IA</string></property>
    <property name="productID"><object class="com.zerog.registry.UUID"><method name="update"><string>11111111-1111-1111-1111-111111111111</string></method></object></property>
    <property name="upgradeCode"><object class="com.zerog.registry.UUID"><method name="update"><string>22222222-2222-2222-2222-222222222222</string></method></object></property>
    <property name="vendorName"><string>Example Vendor</string></property>
    <property name="productVersion"><object><property name="major"><int>1</int></property><property name="minor"><int>2</int></property><property name="revision"><int>3</int></property><property name="subRevision"><int>4</int></property></object></property>
  </object>
  <object class="com.zerog.ia.installer.actions.InstallUninstaller">
    <property name="shouldUninstall"><boolean>true</boolean></property>
    <property name="destinationName"><string>Change-Example-Installation</string></property>
    <property name="execLevel"><int>1</int></property>
  </object>
  <object class="com.zerog.ia.installer.actions.SpeedRegistry">
    <property name="propertyList"><object><method name="addElement"><object class="com.zerog.ia.installer.util.SpeedRegistryData"><property name="keyPath"><string>HKEY_CLASSES_ROOT\.example</string></property><property name="dataType"><string>STRING</string></property><property name="data"><string>Example.File</string></property></object></method></object></property>
  </object>
  <object class="com.zerog.ia.installer.actions.InstallFile" objectID="payload1"><property name="sourceName"><string>helper.exe</string></property><property name="destinationName"><string>helper.exe</string></property><property name="fileSize"><long>1234</long></property><property name="ruleExpression"><string>WINRULE</string></property></object>
  <object class="com.zerog.ia.installer.actions.ExecFile" objectID="exec1"><property name="targetAction"><object refID="payload1" /></property><property name="commandLineArgs"><string>$EXECUTE_FILE_TARGET$ /quiet</string></property><property name="waitForProcess"><boolean>true</boolean></property><property name="ruleExpression"><string>WINRULE</string></property></object>
  <object class="com.zerog.ia.installer.rules.PlatformChk" objectID="rule1"><property name="installOnPlatformList"><object class="java.util.Vector"><method name="addElement"><string>^Windows.*</string></method></object></property><property name="ruleId"><string>WINRULE</string></property></object>
</InstallAnywhere_Deployment_Project>
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

    $Info.ProductCode | Should -Be 'Example IA'
    $Info.ProjectProductId | Should -Be '11111111-1111-1111-1111-111111111111'
    $Info.UpgradeCode | Should -Be '22222222-2222-2222-2222-222222222222'
    $Info.DisplayName | Should -Be 'Example IA'
    $Info.DisplayVersion | Should -Be '1.2.3.4'
    $Info.Publisher | Should -Be 'Example Vendor'
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.SupportsSilentUI | Should -BeTrue
    $Info.ResponseFileEnabled | Should -BeFalse
    $Info.FileExtensions | Should -Contain 'example'
    $Info.InstalledPayloads.DestinationName | Should -Contain 'helper.exe'
    $Info.ExecutedPayloads.Target | Should -Be 'helper.exe'
    $Info.ExecutedPayloads.Arguments | Should -Be '$EXECUTE_FILE_TARGET$ /quiet'
    $Info.Rules.Id | Should -Contain 'WINRULE'
    $Info.ConditionalActionCount | Should -Be 2

    (Get-InstallAnywhereActionEligibility -Info $Info -PlatformName 'Windows 11' | Where-Object ObjectId -EQ 'payload1').State | Should -Be 'True'
    (Get-InstallAnywhereActionEligibility -Info $Info -PlatformName 'Linux' | Where-Object ObjectId -EQ 'payload1').State | Should -Be 'False'
  }

  It 'Should apply Boolean precedence while preserving target-state rules as unknown' {
    $Rules = @(
      [pscustomobject]@{ Id = 'WINDOWS'; Type = 'PlatformChk'; Properties = [ordered]@{ installOnPlatformList = @('^Windows.*'); doNotInstallOnPlatformList = @('Linux') } },
      [pscustomobject]@{ Id = 'DYNAMIC'; Type = 'CompareVariable'; Properties = [ordered]@{} }
    )

    $KnownOrUnknown = Resolve-InstallAnywhereRuleExpression -Expression 'WINDOWS || DYNAMIC' -Rule $Rules -PlatformName 'Windows 11'
    $FalseAndUnknown = Resolve-InstallAnywhereRuleExpression -Expression 'WINDOWS && !DYNAMIC' -Rule $Rules -PlatformName 'Linux'
    $Parenthesized = Resolve-InstallAnywhereRuleExpression -Expression '!(WINDOWS || false)' -Rule $Rules -PlatformName 'Linux'

    $KnownOrUnknown.State | Should -Be 'True'
    $KnownOrUnknown.UnknownRuleIds | Should -Contain 'DYNAMIC'
    $FalseAndUnknown.State | Should -Be 'False'
    $Parenthesized.State | Should -Be 'True'
  }

  It 'Should parse the source-backed built-in ARP key and registry actions from FlowJo 10' {
    $Fixture = Join-Path $Script:FixtureDirectory 'FlowJo-Win64-10.10.0.exe'
    if (-not (Test-Path -LiteralPath $Fixture -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The persistent FlowJo InstallAnywhere fixture is unavailable'
      return
    }

    $Info = Get-InstallAnywhereInfo -Path $Fixture

    $Info.ProductCode | Should -Be 'FlowJo 10.10.0'
    $Info.ProjectProductId | Should -Be '0dd90bab-1f4a-11b2-a6b8-e5137808d66b'
    $Info.UpgradeCode | Should -Be 'c1599e08-1f2b-11b2-a7ae-869c7b752225'
    $Info.DefaultInstallLocation | Should -Be '%ProgramFiles%\FlowJo 10.10.0'
    $Info.SupportsSilentUI | Should -BeTrue
    $Info.InstanceManagementEnabled | Should -BeFalse
    $Info.FileExtensions | Should -Contain 'wsp'
    $Info.RegistryWrites.Count | Should -BeGreaterThan 10
    $Info.ExecutedPayloads.Target | Should -Contain 'vcredist_x64.exe'
    $Info.Launchers.Name | Should -Contain 'FlowJo_v10.10.0'
    $Info.Rules.Type | Should -Contain 'PlatformChk'
    $Info.Warnings | Should -Contain 'InstallAnywhere chooses the built-in uninstall entry hive at runtime and can fall back from HKLM to HKCU. Validate scope in a VM.'
  }
}
