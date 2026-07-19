BeforeAll {
  $LibraryPath = Join-Path $PSScriptRoot '..\Libraries'
  foreach ($ModuleName in @('Runtime', 'General', 'Binary', 'Compression', 'Archive', 'PE', 'Bootstrapper', 'SevenZipSfx')) {
    Import-Module (Join-Path $LibraryPath "$ModuleName.psm1") -Force
  }
}

Describe '7-Zip SFX configuration parser' {
  It 'Prefers ExecuteFile and preserves ExecuteParameters' {
    $Content = @'
; comment
Title="Example"
ExecuteFile="payload\Product.msi"
ExecuteParameters="/qn /norestart"
'@
    $Result = ConvertFrom-SevenZipSfxConfiguration -Content $Content -ArchiveEntry @('payload\Product.msi')

    $Result.CommandSource | Should -Be 'ExecuteFile'
    $Result.Command.ExecutedPayload | Should -Be 'payload\Product.msi'
    $Result.Command.ArgumentList | Should -Be @('/qn', '/norestart')
    $Result.PassesAdditionalArguments | Should -BeTrue
  }

  It 'Uses setup.exe when RunProgram and ExecuteFile are absent' {
    $Result = ConvertFrom-SevenZipSfxConfiguration -Content 'Title="Example"' -ArchiveEntry @('setup.exe')

    $Result.CommandSource | Should -Be 'DefaultRunProgram'
    $Result.Command.ExecutedPayload | Should -Be 'setup.exe'
  }

  It 'Preserves repeated RunProgram and AutoInstall scenarios with execution prefixes' {
    $Content = @'
RunProgram="hidcon:fm0:prepare.cmd /q"
RunProgram="nowait:setup.exe /S"
AutoInstall="payload\Product.msi /qn"
AutoInstall3="cleanup.cmd"
'@
    $Result = ConvertFrom-SevenZipSfxConfiguration -Content $Content -ArchiveEntry @('prepare.cmd', 'setup.exe', 'payload\Product.msi', 'cleanup.cmd')

    $Result.Commands.Count | Should -Be 4
    $Result.Commands[0].Detail.ExecutionPrefixes | Should -Be @('hidcon', 'fm0')
    $Result.Commands[1].Detail.Command.ExecutedPayload | Should -Be 'setup.exe'
    $Result.Commands[2].Trigger | Should -Be '-ai'
    $Result.Commands[2].Detail.Command.ExecutedPayload | Should -Be 'payload\Product.msi'
    $Result.Commands[3].Trigger | Should -Be '-ai3'
  }
}
