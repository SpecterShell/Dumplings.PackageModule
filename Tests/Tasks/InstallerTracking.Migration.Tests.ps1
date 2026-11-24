# SPDX-License-Identifier: Apache-2.0
. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

$Root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..\..'))
$Cases = @(
  @{ Name = '1IC.BPMN-RPAStudio'; Count = 1; Downloads = 1 }
  @{ Name = 'AnyDesk.AnyDesk'; Count = 1; Downloads = 1 }
  @{ Name = 'Ardisk.Ardisk'; Count = 1; Downloads = 1 }
  @{ Name = 'Alibaba.Taobao'; Count = 1; Downloads = 1 }
  @{ Name = 'ABC.PowerExtension'; Count = 1; Downloads = 1 }
  @{ Name = 'Untis.Untis.2026'; Count = 2; Downloads = 2 }
  @{ Name = 'Cjwdev.ADAccountResetTool'; Count = 2; Downloads = 1 }
  @{ Name = 'Bazwise.FolderSizeExplorer'; Count = 1; Downloads = 1 }
)

Describe 'Migrated versionless task scripts' -Tag Unit -Skip:(-not (Test-Path (Join-Path $Root 'Tasks/1IC.BPMN-RPAStudio/Script.ps1'))) {
  BeforeAll {
    . (Join-Path $PSScriptRoot '..\..\Index.ps1')
    $Root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..\..'))
    function global:Write-Log { param($Object, $Level) }
    # A stub keeps this suite independent of installed extraction utilities. It
    # produces only the two requested synthetic members, never runs a payload.
    function global:7z.exe {
      $Destination = @($args | Where-Object { $_ -like '-o*' })[0].Substring(2)
      [IO.File]::WriteAllText((Join-Path $Destination 'FolderSizeExplorer.msi'), 'fixture')
      [IO.File]::WriteAllText((Join-Path $Destination 'ReleaseNotes.txt'), "Version 2026.1.2.3 22-September-2026`n`nFixed an issue.`nVersion 2026.0.0.0")
    }
  }
  BeforeEach {
    $Global:DumplingsPreference = @{}
    Mock Invoke-WebRequest {
      param($Uri)
      if ($Uri -like '*VersionHistory.txt') {
        return @{ RawContentStream = [IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes("Version 2026.1.2.3`nFixed an issue.`nVersion 1.0")) }
      }
      if ($Uri -like '*jianghu*') { return '<div id="detailContent"><p><strong>V2026.1.2.3</strong> 2026.09.22</p><p>Fixed an issue.</p></div>' }
      if ($Uri -like '*releasenotes*') { return '<h2>2026.1.2 22.09.2026</h2><p>Fixed an issue.</p>' }
      return @{ Links = @(@{ href = 'fixture.zip' }, @{ href = 'fixture.exe' }) }
    }
    Mock Get-RedirectedUrl { 'https://example.test/folder-size.exe' }
    Mock Read-ProductVersionFromMsi { '2026.1.2.3' }
    Mock Read-ProductVersionFromExe { '2026.1.2.3' }
    Mock Read-FileVersionFromExe { '2026.1.2.3' }
    Mock Read-ProductVersionRawFromExe { [version]'2026.1.2.3' }
    Mock Expand-TempArchive { New-TempFolder }
    Mock Get-AdvancedInstallerMsiInfo { @{ DisplayVersion = '2026.1.2.3' } }
    Mock Get-WinGetInstallerReleaseDate -ModuleName WinGetManifestUpdate { $null }
    Mock Get-FileHash -ModuleName WinGetManifestUpdate { throw 'Tracking hashes should be reused' }
    Mock New-TempFile -ModuleName InstallerTracking { Join-Path $TestDrive ([guid]::NewGuid().ToString('N')) }
    Mock Invoke-WinGetInstallerDownload -ModuleName InstallerTracking {
      param($Uri, $DestinationPath)
      [IO.File]::WriteAllBytes($DestinationPath, [byte[]](1, 2, 3))
      @{ DestinationPath = $DestinationPath; FinalUri = [string]$Uri; HttpStatusCode = 200; ResponseHeaders = "HTTP/1.1 200 OK`r`nETag: sample`r`nLast-Modified: Tue, 22 Sep 2026 10:00:00 GMT`r`nContent-Length: 3`r`nContent-MD5: opaque`r`nx-goog-hash: md5=opaque`r`n"; Sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([byte[]](1, 2, 3))) }
    }
    Mock Get-WinGetWinINetResponseHeader -ModuleName InstallerTracking {
      @{ StatusCode = 200; Headers = @{ ETag = 'sample'; 'Last-Modified' = 'Tue, 22 Sep 2026 10:00:00 GMT'; 'Content-Length' = '3'; 'Content-MD5' = 'opaque'; 'x-goog-hash' = 'md5=opaque' } }
    }
  }

  It 'runs <Name> with synthetic responses and reuses its accepted validators' -ForEach $Cases {
    $Directory = New-Item (Join-Path $TestDrive $Name) -ItemType Directory -Force
    Copy-Item -LiteralPath (Join-Path $Root "Tasks/$Name/Script.ps1") -Destination $Directory.FullName
    $Task = [PackageTask]::new(@{ Name = $Name; Path = $Directory.FullName; Config = @{ WinGetIdentifier = $Name } })
    try {
      # Execute the real task script in the mocking scope, with its normal $this.
      $this = $Task
      & $Task.ScriptPath
      $Task.CurrentState.Version | Should -Be '2026.1.2.3'
      $Task.CurrentState.Installer.Count | Should -Be $Count
      $Task.CurrentState.InstallerTracking.Artifacts.Count | Should -Be $Count
      $Task.InstallerFiles.Count | Should -Be $Downloads
      $Task.Config.Contains('IgnorePRCheck') | Should -BeFalse
      foreach ($Installer in $Task.CurrentState.Installer) { $Installer.InstallerSha256 | Should -Match '^[A-F0-9]{64}$' }
      if ($Name -eq 'Untis.Untis.2026') { $Task.CurrentState.RealVersion | Should -Be '2026' }
      if ($Name -eq 'Cjwdev.ADAccountResetTool') {
        Should -Invoke Get-AdvancedInstallerMsiInfo -Times 1 -Exactly -ParameterFilter { $Architecture -eq 'x86' }
        Should -Invoke Get-AdvancedInstallerMsiInfo -Times 1 -Exactly -ParameterFilter { $Architecture -eq 'x64' }
      }
      if ($Name -in 'Alibaba.Taobao', 'Untis.Untis.2026', 'Cjwdev.ADAccountResetTool', 'Bazwise.FolderSizeExplorer') { $Task.CurrentState.Locale[0].Value | Should -Match 'Fixed an issue' }
      $OldInstallers = @($Task.CurrentState.Installer | ForEach-Object {
          [ordered]@{ Architecture = $_.Architecture ?? 'x64'; InstallerType = 'msi'; InstallerUrl = 'https://example.test/previous.msi'; InstallerSha256 = 'A' * 64; ProductCode = '{00000000-0000-0000-0000-000000000001}' }
        })
      $Locale = @{ PackageLocale = if ($Name -eq 'Untis.Untis.2026') { 'de-AT' } else { 'en-US' }; PackageName = $Name; Publisher = 'Test'; License = 'MIT'; ShortDescription = 'Synthetic migration check' }
      $Manifest = New-WinGetManifest -PackageIdentifier $Name -PackageVersion '1.0' -Installer $OldInstallers -DefaultLocalization $Locale
      $Updated = Update-WinGetManifest -Manifest $Manifest -PackageVersion ($Task.CurrentState.RealVersion ?? $Task.CurrentState.Version) -InstallerEntries $Task.CurrentState.Installer -LocaleEntries $Task.CurrentState.Locale -InstallerFiles $Task.InstallerFiles -InstallerFileEvidence $Task.InstallerFileEvidence -SkipInstallerAnalysis -Logger {}
      $Updated.Installers.Count | Should -Be $Count
      for ($Index = 0; $Index -lt $Count; $Index++) {
        $Updated.Installers[$Index].InstallerUrl | Should -Be ([uri]$Task.CurrentState.Installer[$Index].InstallerUrl).AbsoluteUri
        $Updated.Installers[$Index].InstallerSha256 | Should -Be $Task.CurrentState.Installer[$Index].InstallerSha256
        $Updated.Installers[$Index].ProductCode | Should -Be $OldInstallers[$Index].ProductCode
      }
      (Get-WinGetManifestValidationResult -Manifest $Updated).HasErrors | Should -BeFalse
      Should -Invoke Get-FileHash -ModuleName WinGetManifestUpdate -Times 0 -Exactly
      $Task.LastState = Copy-Object $Task.CurrentState
      $Task.CurrentState = [ordered]@{ Version = $null; Installer = @(); Locale = @() }
      $Task.Status.Clear()
      & $Task.ScriptPath
      Test-ObjectValueEqual $Task.LastState $Task.CurrentState | Should -BeTrue
      Should -Invoke Invoke-WinGetInstallerDownload -ModuleName InstallerTracking -Times $Downloads -Exactly
      Test-Path (Join-Path $Directory.FullName 'State.yaml') | Should -BeFalse
    } finally { $Task.Dispose() }
  }
  AfterAll { Remove-Item Function:\Write-Log, Function:\7z.exe -ErrorAction Ignore }
}
