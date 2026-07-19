BeforeAll {
  . (Join-Path $PSScriptRoot 'TestFixture.ps1')
  $LibraryPath = Join-Path $PSScriptRoot '..\Libraries'
  foreach ($ModuleName in @('Runtime', 'Binary', 'Compression', 'Archive', 'PE', 'RegistryAssociations', 'PaquetBuilder')) {
    Import-Module (Join-Path $LibraryPath "$ModuleName.psm1") -Force
  }

  $Script:FixtureDirectory = Get-DumplingsTestFixtureDirectory -Name 'PackageModule\AdditionalGenericExeParsers'
}

Describe 'Paquet Builder static parser' {
  It 'Should classify independent payload and runtime archives' {
    $PayloadBytes = [Convert]::FromBase64String('N3q8ryccAAQ9qmANEQAAAAAAAABaAAAAAAAAAMFZj+oBAAzvu79NWiBwYXlsb2FkAAEEBgABCREABwsBAAEhIQEADA0ACAoBlIuc5QAABQEZDAAAAAAAAAAAAAAAABERAGEAcABwAC4AZQB4AGUAAAAZAgAAFAoBAB62AVRLEN0BFQYBACAAAAAAAA==')
    $RuntimeBytes = [Convert]::FromBase64String('N3q8ryccAARvFqxziQAAAAAAAAAhAAAAAAAAAIeEEHoBABHvu79NWiBjb3Jl77u/cHJvcHMAAACBMweuD89dLwwHyEN/QbH6/eXHfeltPRF+KAQ4jdN8i3B2bHASkmtshsURP/CTxIVxKBlS3RJpSTQfS1uagxDwitrxEOECC63BwAFZFPCO/UlgqXK0gK4zcbXJH8lrfwIF5lsbjlRuLVrCC1IqcmXAABcGFgEJcwAHCwEAASMDAQEFXQAQAAAMgIYKASqU5xkAAA==')
    $FixturePath = Join-Path $Script:FixtureDirectory 'paquet-archives.bin'
    [IO.File]::WriteAllBytes($FixturePath, ([byte[]]::new(2048) + $PayloadBytes + [byte[]]::new(73) + $RuntimeBytes))

    InModuleScope PaquetBuilder -Parameters @{ FixturePath = $FixturePath } {
      param($FixturePath)
      Mock Get-PEOverlayOffset { 512 }
      $ArchiveData = Get-PaquetBuilderArchiveData -Path $FixturePath
      $ArchiveData.Payload.Entries.FullName | Should -Be @('app.exe')
      $ArchiveData.Runtime.Entries.FullName | Should -Contain 'pbfprop.dat'
      $ArchiveData.Runtime.Entries.FullName | Should -Contain 'PBCore64.dll'
      $ArchiveData.Payload.SourcePath | Should -Be (Get-Item -LiteralPath $FixturePath).FullName
      $ArchiveData.Runtime.SourcePath | Should -Be (Get-Item -LiteralPath $FixturePath).FullName
    }
  }
}
