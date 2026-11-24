. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  $Script:DumplingsModulesRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..'))
  $Script:DumplingsRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModulesRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'PackageModule.psd1') -Force -Global

  $Script:FixtureDirectory = $TestDrive

  function ConvertTo-TestQSetupRecord {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][byte[]]$Content, [switch]$Required)
    $RequiredMarker = if ($Required) { '*' } else { '' }
    $Header = [Text.Encoding]::ASCII.GetBytes("|$Name$RequiredMarker|123456|")
    $Compressed = [IO.MemoryStream]::new()
    $Encoder = [IO.Compression.ZLibStream]::new($Compressed, [IO.Compression.CompressionLevel]::SmallestSize, $true)
    try { $Encoder.Write($Header, 0, $Header.Length); $Encoder.WriteByte(0); $Encoder.Write($Content, 0, $Content.Length) } finally { $Encoder.Dispose() }
    return [BitConverter]::GetBytes([uint32]$Compressed.Length) + $Compressed.ToArray()
  }

  function ConvertTo-TestQSetupFooter {
    param(
      [Parameter(Mandatory)][uint32]$OverlayOffset,
      [Parameter(Mandatory)][uint32]$RecordCount,
      [ValidateSet('Compact12', 'Legacy74', 'Modern74')][string]$Route = 'Modern74'
    )
    if ($Route -eq 'Compact12') {
      return [BitConverter]::GetBytes($RecordCount) + [BitConverter]::GetBytes($OverlayOffset) + [BitConverter]::GetBytes([uint32]0x4A3B2C1D)
    }
    $Footer = [byte[]]::new(74)
    foreach ($Value in @(
        @{ Offset = 0; Value = [uint32]0x201 },
        @{ Offset = 4; Value = $OverlayOffset },
        @{ Offset = 8; Value = $RecordCount },
        @{ Offset = 12; Value = [uint32]0x4A3B2C1D },
        @{ Offset = 16; Value = $Route -eq 'Modern74' ? [uint32]1234 : [uint32]0x10203040 },
        @{ Offset = 70; Value = [uint32]$Footer.Length }
      )) {
      [Buffer]::BlockCopy([BitConverter]::GetBytes($Value.Value), 0, $Footer, $Value.Offset, 4)
    }
    return $Footer
  }

  function ConvertTo-TestQSetupPreamble {
    param([Parameter(Mandatory)][string]$Secret)
    $Text = [Text.Encoding]::ASCII.GetBytes("|http:|.info|.exe|$Secret|0|")
    return [BitConverter]::GetBytes([uint32]1) + [byte]2 + [BitConverter]::GetBytes([uint32]$Text.Length) + $Text
  }

  function ConvertTo-TestQSetupSplitDescriptor {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Secret, [Nullable[long]]$DeclaredLength)
    $Text = $PSBoundParameters.ContainsKey('DeclaredLength') ? "|C:\QSetupFixture|$Name|0|$Secret|$DeclaredLength|" : "|C:\QSetupFixture|$Name|0|$Secret|"
    $Bytes = [Text.Encoding]::UTF8.GetBytes($Text)
    return [BitConverter]::GetBytes([uint32]$Bytes.Length) + $Bytes
  }
}

Describe 'QSetup static parser' {
  It 'Should parse explicit Setup.txt ARP, scope, architecture, and association directives' {
    $SetupText = @'
SET_PROG_NAME(Example QSetup Product);
SET_PROJECT_NAME(ExampleProject);
SET_PROG_VERSION(4.5.6);
SET_COMPANY_NAME(Example Publisher);
SET_COMPOSER_BUILD(12.0.0.5);
SET_TARGET_DIR(<ProgramFiles>\Example);
SET_PROG_EXE_NAME(<Application Folder>\Example.exe);
SET_CREATE_UNINSTALL;
SET_ADD_UNINSTALL_TO_ADD_REMOVE_PROGRAMS;
SET_ADD_REMOVE_PROGRAMS_DISPLAY_NAME(Example QSetup ARP);
SET_UNINSTALL_EXE_NAME(uninstall_example.exe);
SET_ALL_USERS;
SET_ALLOWED_OS(10.64,11.64);
SET_SUB_DIR(<Application Folder>\bin);
SET_COPY_FILES(Engine.exe);
SET_ADD_ASSOCIATION_ITEM(|Example.Document|Example document|.example|Example|<Application Folder>\Example.exe|<Application Folder>\Example.exe|0|Create|Remove||);
SET_PERFORM_EXECUTE_OP(*||Install prerequisite|Setup Start|10|UnConditional|0|0|File Found||0|0|0|File Found||0|0|0|File Found||1|Run Executable and Wait||0|Display Message||0|Display Message||0|Display Message||0|Display Message||0|Display Message||0|*|||=||||=||||=|||<SrcDir>\runtime.exe|/quiet /norestart||||||||||||||||||*);
'@
    $Preamble = [Text.Encoding]::ASCII.GetBytes('|http:|.info|.exe|fixture|0|')
    $FixtureBytes = [byte[]]::new(512) + [BitConverter]::GetBytes([uint32]1) + [byte]2 + [BitConverter]::GetBytes([uint32]$Preamble.Length) + $Preamble
    $FixtureBytes += ConvertTo-TestQSetupRecord -Name 'Engine.exe' -Content ([Text.Encoding]::ASCII.GetBytes('MZ engine')) -Required
    $FixtureBytes += ConvertTo-TestQSetupRecord -Name 'Setup.txt' -Content ([Text.Encoding]::UTF8.GetBytes($SetupText))
    $FixturePath = Join-Path $Script:FixtureDirectory 'synthetic-qsetup.exe'
    [IO.File]::WriteAllBytes($FixturePath, $FixtureBytes)

    InModuleScope QSetup -Parameters @{ FixturePath = $FixturePath } {
      param($FixturePath)
      Mock Get-PEOverlayOffset { 512 }
      $Info = Get-QSetupInfo -Path $FixturePath

      $Info.DisplayName | Should -Be 'Example QSetup ARP'
      $Info.DisplayVersion | Should -Be '4.5.6'
      $Info.Publisher | Should -Be 'Example Publisher'
      $Info.ProductCode | Should -Be 'Example QSetup ARP'
      $Info.Scope | Should -Be 'machine'
      $Info.DefaultInstallLocation | Should -Be '%ProgramFiles%\Example'
      $Info.SupportedArchitectures | Should -Be @('x64')
      $Info.RegistryView | Should -Be '64-bit'
      @($Info.RegistryWrites | Where-Object { $_.RegistryView -ne '64-bit' }) | Should -BeNullOrEmpty
      $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
      $Info.FileExtensions | Should -Be @('example')
      $Info.Records.Name | Should -Be @('Engine.exe', 'Setup.txt')
      @($Info.Diagnostics | Where-Object Kind -NE Information).Id | Should -Be @('QSetup.Payload.MainExecutableUnresolved')
      @($Info.Diagnostics | Where-Object Kind -EQ Information) | Should -HaveCount 1
      $Info.ExecutionActions | Should -HaveCount 1
      $Info.ExecutedPayloads | Should -HaveCount 1
      $Info.ExecutedPayloads[0].Command | Should -Be '<SrcDir>\runtime.exe'
      $Info.ExecutedPayloads[0].Parameters | Should -Be '/quiet /norestart'
      $Info.PayloadCatalog | Should -HaveCount 1
      $Info.PayloadCatalog[0].InstalledPath | Should -Be '%ProgramFiles%\Example\bin\Engine.exe'

      $Destination = Join-Path $TestDrive 'qsetup-installed-extraction'
      $Files = Expand-QSetupInstaller -Path $FixturePath -DestinationPath $Destination -CollisionAction Error
      $Files | Should -HaveCount 1
      $Files[0].FullName | Should -Be (Join-Path $Destination 'bin\Engine.exe')
      [IO.File]::ReadAllText($Files[0].FullName) | Should -Be 'MZ engine'
    }
  }

  It 'Should decode custom registry, INI, XML, protocol, and ARP operations' {
    $SetupText = @'
SET_PROG_NAME(Built-in Name);
SET_PROG_VERSION(1.2.3);
SET_COMPANY_NAME(Built-in Publisher);
SET_COMPOSER_BUILD(12.0.0.5);
SET_TARGET_DIR(<ProgramFiles>\OperationProbe);
SET_ALL_USERS;
SET_PERFORM_REGISTRY_OP(|HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\Custom.Product|DisplayName|Custom Product|Create|Ignore|String|);
SET_PERFORM_REGISTRY_OP(|HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\Custom.Product|DisplayVersion|9.8.7|Create|Ignore|String|);
SET_PERFORM_REGISTRY_OP(|HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\Custom.Product|Publisher|Custom Publisher|Create|Ignore|String|);
SET_PERFORM_REGISTRY_OP(|HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\Custom.Product|UninstallString|"<InstallDir>\remove.exe" /quiet|Create|Ignore|ExpandString|);
SET_PERFORM_REGISTRY_OP(|HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\Hidden.Product|DisplayName|Hidden Product|Create|Ignore|String|);
SET_PERFORM_REGISTRY_OP(|HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\Hidden.Product|SystemComponent|1|Create|Ignore|Integer|);
SET_PERFORM_REGISTRY_OP(|HKEY_CLASSES_ROOT\custom|URL Protocol||Create|Remove Value|String|);
SET_PERFORM_REGISTRY_OP(|HKEY_CLASSES_ROOT\custom\shell\open\command||"<InstallDir>\probe.exe" "%1"|Create|Remove Key|String|);
SET_PERFORM_INI_OP(|<InstallDir>\probe.ini|General|Name|Value|Create|Remove Value|);
SET_PERFORM_XML_OP(|<InstallDir>\probe.xml|/root/name|Value|Create|Remove|);
'@
    $Preamble = ConvertTo-TestQSetupPreamble -Secret ('a' * 32)
    $FixtureBytes = [byte[]]::new(512) + $Preamble + (ConvertTo-TestQSetupRecord -Name 'Setup.txt' -Content ([Text.Encoding]::UTF8.GetBytes($SetupText)))
    $FixtureBytes += ConvertTo-TestQSetupFooter -OverlayOffset 512 -RecordCount 1
    $FixturePath = Join-Path $Script:FixtureDirectory 'synthetic-qsetup-operations.exe'
    [IO.File]::WriteAllBytes($FixturePath, $FixtureBytes)

    InModuleScope QSetup -Parameters @{ FixturePath = $FixturePath } {
      param($FixturePath)
      Mock Get-PEOverlayOffset { 512 }
      Mock Get-PERequestedExecutionLevel { 'requireAdministrator' }
      Mock Get-PELayout { [pscustomobject]@{ MachineName = 'I386' } }
      $Info = Get-QSetupInfo -Path $FixturePath
      $Info.ProductCode | Should -Be 'Custom.Product'
      $Info.DisplayName | Should -Be 'Custom Product'
      $Info.DisplayVersion | Should -Be '9.8.7'
      $Info.Publisher | Should -Be 'Custom Publisher'
      $Info.UninstallString | Should -Be '"%ProgramFiles%\OperationProbe\remove.exe" /quiet'
      $Info.Protocols | Should -Be @('custom')
      $Info.RegistryView | Should -Be '32-bit'
      $Info.RegistryOperations | Should -HaveCount 8
      $Info.CustomArpEntries | Should -HaveCount 2
      @($Info.CustomArpEntries | Where-Object ProductCode -EQ 'Hidden.Product')[0].Visible | Should -BeFalse
      $Info.AppsAndFeaturesEntries | Should -HaveCount 1
      $Info.IniFileOperations[0].Path | Should -Be '%ProgramFiles%\OperationProbe\probe.ini'
      $Info.XmlOperations[0].NodePath | Should -Be '/root/name'
    }
  }

  It 'Should decode modern condition slots and classify conditional system effects' {
    InModuleScope QSetup {
      $Fields = [string[]]::new(73)
      $Fields[0] = '*'; $Fields[2] = 'Install service'; $Fields[3] = 'Setup Start'; $Fields[4] = '10'; $Fields[5] = 'Conditional'
      $Fields[7] = '1'; $Fields[8] = 'Registry Key Found'; $Fields[20] = '1'; $Fields[21] = 'Install Service'; $Fields[39] = '*'
      $Fields[41] = 'HKLM\Software\Example'; $Fields[42] = '='; $Fields[53] = 'ExampleService'; $Fields[54] = '<InstallDir>\service.exe'; $Fields[72] = '*'
      $Action = ConvertFrom-QSetupExecutionAction -Content ($Fields -join '|')
      $Effects = Get-QSetupSystemEffectInfo -ExecutionAction @($Action) -DirectiveRecord @()
      $Action.ConditionState | Should -Be 'Unknown'
      $Action.Conditions | Should -HaveCount 1
      $Action.Conditions[0].Predicate | Should -Be 'Registry Key Found'
      $Action.Conditions[0].Category | Should -Be 'Registry'
      $Action.Conditions[0].RequiresRuntimeState | Should -BeTrue
      $Action.Conditions[0].RequiresUserInteraction | Should -BeFalse
      $Effects.Services | Should -HaveCount 1
      $Effects.Services[0].ConditionState | Should -Be 'Unknown'
    }
  }

  It 'Should classify Execution Engine associations and interactive predicates without over-promoting conditional evidence' {
    InModuleScope QSetup {
      $AssociationFields = [string[]]::new(73)
      $AssociationFields[0] = '*'; $AssociationFields[2] = 'Create document association'; $AssociationFields[3] = 'Setup End'; $AssociationFields[4] = '10'; $AssociationFields[5] = 'UnConditional'
      $AssociationFields[20] = '1'; $AssociationFields[21] = 'Create File Association'; $AssociationFields[39] = '*'
      $AssociationFields[53] = 'Example Document'; $AssociationFields[54] = '<InstallDir>\Example.exe'; $AssociationFields[55] = '.example'; $AssociationFields[72] = '*'
      $AssociationAction = ConvertFrom-QSetupExecutionAction -Content ($AssociationFields -join '|')

      $PromptFields = [string[]]::new(73)
      $PromptFields[0] = '*'; $PromptFields[2] = 'Prompt before operation'; $PromptFields[3] = 'Setup Start'; $PromptFields[4] = '10'; $PromptFields[5] = 'Conditional'
      $PromptFields[7] = '1'; $PromptFields[8] = 'Ask Yes/No'; $PromptFields[20] = '1'; $PromptFields[21] = 'Create File Association'; $PromptFields[39] = '*'
      $PromptFields[41] = 'Continue?'; $PromptFields[53] = 'Prompted Document'; $PromptFields[54] = '<InstallDir>\Prompted.exe'; $PromptFields[55] = '.prompted'; $PromptFields[72] = '*'
      $PromptAction = ConvertFrom-QSetupExecutionAction -Content ($PromptFields -join '|')

      $Effects = Get-QSetupSystemEffectInfo -ExecutionAction @($AssociationAction, $PromptAction) -DirectiveRecord @()
      $Effects.FileAssociations | Should -HaveCount 2
      $Effects.FileAssociations[0].ConditionState | Should -Be 'True'
      $Effects.FileAssociations[1].ConditionState | Should -Be 'Unknown'
      $PromptAction.Conditions[0].Category | Should -Be 'UserInteraction'
      $PromptAction.Conditions[0].RequiresUserInteraction | Should -BeTrue
    }
  }

  It 'Should project only unconditional Execution Engine association creation as manifest evidence' {
    $AssociationFields = [string[]]::new(73)
    $AssociationFields[0] = '*'; $AssociationFields[2] = 'Create document association'; $AssociationFields[3] = 'Setup End'; $AssociationFields[4] = '10'; $AssociationFields[5] = 'UnConditional'
    $AssociationFields[20] = '1'; $AssociationFields[21] = 'Create File Association'; $AssociationFields[39] = '*'
    $AssociationFields[53] = 'Example Document'; $AssociationFields[54] = '<InstallDir>\Example.exe'; $AssociationFields[55] = '.example'; $AssociationFields[72] = '*'
    $PromptFields = [string[]]::new(73)
    $PromptFields[0] = '*'; $PromptFields[2] = 'Prompted association'; $PromptFields[3] = 'Setup End'; $PromptFields[4] = '10'; $PromptFields[5] = 'Conditional'
    $PromptFields[7] = '1'; $PromptFields[8] = 'Ask Yes/No'; $PromptFields[20] = '1'; $PromptFields[21] = 'Create File Association'; $PromptFields[39] = '*'
    $PromptFields[41] = 'Continue?'; $PromptFields[53] = 'Prompted Document'; $PromptFields[54] = '<InstallDir>\Prompted.exe'; $PromptFields[55] = '.prompted'; $PromptFields[72] = '*'
    $SetupText = "SET_PROG_NAME(Association Product);`r`nSET_COMPOSER_BUILD(12.0.0.5);`r`nSET_CURRENT_USER;`r`nSET_TARGET_DIR(<LocalAppData>\Association Product);`r`nSET_PERFORM_EXECUTE_OP($($AssociationFields -join '|'));`r`nSET_PERFORM_EXECUTE_OP($($PromptFields -join '|'));"
    $Preamble = ConvertTo-TestQSetupPreamble -Secret ('f' * 32)
    $FixtureBytes = [byte[]]::new(512) + $Preamble + (ConvertTo-TestQSetupRecord -Name 'Setup.txt' -Content ([Text.Encoding]::UTF8.GetBytes($SetupText)))
    $FixtureBytes += ConvertTo-TestQSetupFooter -OverlayOffset 512 -RecordCount 1
    $FixturePath = Join-Path $Script:FixtureDirectory 'synthetic-qsetup-execution-associations.exe'
    [IO.File]::WriteAllBytes($FixturePath, $FixtureBytes)

    InModuleScope QSetup -Parameters @{ FixturePath = $FixturePath } {
      param($FixturePath)
      Mock Get-PEOverlayOffset { 512 }
      Mock Get-PERequestedExecutionLevel { 'asInvoker' }
      Mock Get-PELayout { [pscustomobject]@{ MachineName = 'I386' } }
      $Info = Get-QSetupInfo -Path $FixturePath
      $Info.FileExtensions | Should -Be @('example')
      $Info.FileAssociationOperations | Should -HaveCount 2
      $Info.Diagnostics.Id | Should -Contain 'QSetup.Execution.UserInteraction'
    }
  }

  It 'Should select generated uninstaller naming from the format catalog' -ForEach @(
    @{ ComposerBuild = '7.5.0.8'; Name = 'UnInstall_12345.exe'; Route = 'HistoricalGeneratedName' }
    @{ ComposerBuild = '12.0.0.5'; Name = 'ProductSetup_12345.exe'; Route = 'CurrentGeneratedName' }
  ) {
    InModuleScope QSetup -Parameters @{ ComposerBuild = $ComposerBuild; ExpectedName = $Name; ExpectedRoute = $Route } {
      param($ComposerBuild, $ExpectedName, $ExpectedRoute)
      $Info = Get-QSetupUninstallerInfo -Directive @{ SET_MEDIA_NAME = 'ProductSetup'; SET_PROG_STAMP = '12345'; SET_COMPOSER_BUILD = $ComposerBuild } -InstallLocation '%ProgramFiles%\Product'
      $Info.Name | Should -Be $ExpectedName
      $Info.NamingRoute | Should -Be $ExpectedRoute
      $Info.RegistryCommand | Should -Be ('"%ProgramFiles%\Product\' + $ExpectedName + '"')
    }
  }

  It 'Should prefer a compiled historical shortcut and avoid an unverified 8-11 fallback' {
    InModuleScope QSetup {
      $CompiledDirective = @{
        SET_COMPOSER_BUILD          = [Collections.Generic.List[object]]@('8.1.0.2')
        SET_MEDIA_NAME              = [Collections.Generic.List[object]]@('ProductSetup')
        SET_PROG_STAMP              = [Collections.Generic.List[object]]@('12345')
        SET_START_PROGRAM_LINK_ITEM = [Collections.Generic.List[object]]@('|Uninstall Product|<Application Folder>UnInstall_12345.exe|')
      }
      $Compiled = Get-QSetupUninstallerInfo -Directive $CompiledDirective -InstallLocation '%ProgramFiles%\Product'
      $Compiled.Name | Should -Be 'UnInstall_12345.exe'
      $Compiled.NamingRoute | Should -Be 'CompiledShortcutTarget'

      $UnprovenDirective = @{
        SET_COMPOSER_BUILD = [Collections.Generic.List[object]]@('8.1.0.2')
        SET_MEDIA_NAME     = [Collections.Generic.List[object]]@('ProductSetup')
        SET_PROG_STAMP     = [Collections.Generic.List[object]]@('12345')
      }
      $Unproven = Get-QSetupUninstallerInfo -Directive $UnprovenDirective -InstallLocation '%ProgramFiles%\Product'
      $Unproven.Name | Should -BeNullOrEmpty
      $Unproven.NamingRoute | Should -BeNullOrEmpty
    }
  }

  It 'Should decode comma, compact-pipe, and extended shortcut records' {
    InModuleScope QSetup {
      $Directive = @{
        SET_TARGET_DIR              = [Collections.Generic.List[object]]@('<ProgramFiles>\Product')
        SET_START_PROGRAM_LINK_ITEM = [Collections.Generic.List[object]]@(
          'Uninstall Product,<Application Folder>UnInstall_12345.exe',
          '|Product site|https://example.test/|',
          '|Launch Product|<Application Folder>Product.exe||--open|<Application Folder>|Normal Window|<Application Folder>Product.exe|2|1|0|'
        )
      }
      $Shortcuts = Get-QSetupShortcutInfo -Directive $Directive
      $Shortcuts.LayoutRoute | Should -Be @('CompactComma', 'CompactPipe', 'ExtendedPipe')
      $Shortcuts[0].Target | Should -Be '%ProgramFiles%\Product\UnInstall_12345.exe'
      $Shortcuts[1].Target | Should -Be 'https://example.test/'
      $Shortcuts[2].Parameters | Should -Be '--open'
      $Shortcuts[2].IconIndex | Should -Be 2
    }
  }

  It 'Should authenticate and parse an explicitly supplied split companion' {
    $Secret = 's' * 40
    $Preamble = ConvertTo-TestQSetupPreamble -Secret $Secret
    $SetupText = "SET_PROG_NAME(Split Product);`r`nSET_PROG_VERSION(2.0);`r`nSET_COMPOSER_BUILD(12.0.0.5);`r`nSET_ALL_USERS;"
    $CompanionName = 'split-fixture.split.bin'
    $CompanionRecord = ConvertTo-TestQSetupRecord -Name 'Setup.txt' -Content ([Text.Encoding]::UTF8.GetBytes($SetupText))
    $CompanionDescriptor = ConvertTo-TestQSetupSplitDescriptor -Name $CompanionName -Secret $Secret
    $CompanionBytes = $Preamble + $CompanionDescriptor + $CompanionRecord + (ConvertTo-TestQSetupFooter -OverlayOffset 0 -RecordCount 1)
    $CompanionPath = Join-Path $Script:FixtureDirectory $CompanionName
    [IO.File]::WriteAllBytes($CompanionPath, $CompanionBytes)
    $MainDescriptor = ConvertTo-TestQSetupSplitDescriptor -Name $CompanionName -Secret $Secret -DeclaredLength $CompanionBytes.Length
    $MainBytes = [byte[]]::new(512) + $Preamble + $MainDescriptor + (ConvertTo-TestQSetupFooter -OverlayOffset 512 -RecordCount 0)
    $MainPath = Join-Path $Script:FixtureDirectory 'split-fixture.exe'
    [IO.File]::WriteAllBytes($MainPath, $MainBytes)

    InModuleScope QSetup -Parameters @{ MainPath = $MainPath; CompanionPath = $CompanionPath } {
      param($MainPath, $CompanionPath)
      Mock Get-PEOverlayOffset { 512 }
      Mock Get-PERequestedExecutionLevel { 'asInvoker' }
      Mock Get-PELayout { [pscustomobject]@{ MachineName = 'I386' } }
      Test-QSetup -Path $MainPath | Should -BeTrue
      { Get-QSetupInfo -Path $MainPath } | Should -Throw '*requires the explicitly supplied companion*'
      $Info = Get-QSetupInfo -Path $MainPath -CompanionPath $CompanionPath
      $Info.DisplayName | Should -Be 'Split Product'
      $Info.MediaRoute | Should -Be 'SplitKernel'
      $Info.StructuralRoutes | Should -Contain 'SplitDescriptor'
      $Info.StructuralRoutes | Should -Contain 'SplitCompanion'
      $Destination = Join-Path $TestDrive 'split-records'
      $Extracted = Expand-QSetupInstaller -Path $MainPath -CompanionPath $CompanionPath -DestinationPath $Destination -RawRecords -Name Setup.txt -CollisionAction Error
      $Extracted | Should -HaveCount 1
    }
  }

  It 'Should extract an explicitly supplied non-SFX payload' {
    $SetupText = "SET_PROG_NAME(External Product);`r`nSET_COMPOSER_BUILD(12.0.0.5);`r`nSET_TARGET_DIR(<ProgramFiles>\External);`r`nSET_SUB_DIR(<InstallDir>\bin);`r`nSET_COPY_FILES(External.dat);"
    $Preamble = ConvertTo-TestQSetupPreamble -Secret ('e' * 32)
    $FixtureBytes = [byte[]]::new(512) + $Preamble + (ConvertTo-TestQSetupRecord -Name 'Setup.txt' -Content ([Text.Encoding]::UTF8.GetBytes($SetupText)))
    $FixtureBytes += ConvertTo-TestQSetupFooter -OverlayOffset 512 -RecordCount 1
    $FixturePath = Join-Path $Script:FixtureDirectory 'external-qsetup.exe'
    $ExternalPath = Join-Path $Script:FixtureDirectory 'External.dat'
    [IO.File]::WriteAllBytes($FixturePath, $FixtureBytes)
    [IO.File]::WriteAllText($ExternalPath, 'external payload')

    InModuleScope QSetup -Parameters @{ FixturePath = $FixturePath; ExternalPath = $ExternalPath } {
      param($FixturePath, $ExternalPath)
      Mock Get-PEOverlayOffset { 512 }
      Mock Get-PERequestedExecutionLevel { 'asInvoker' }
      Mock Get-PELayout { [pscustomobject]@{ MachineName = 'I386' } }
      $Info = Get-QSetupInfo -Path $FixturePath -CompanionPath $ExternalPath
      $Info.CanExpandAllPayloads | Should -BeTrue
      $Info.PayloadCatalog[0].Storage | Should -Be 'ExternalCompanion'
      $Info.StructuralRoutes | Should -Contain 'ExternalPayload'
      $Destination = Join-Path $TestDrive 'external-payload'
      $Extracted = Expand-QSetupInstaller -Path $FixturePath -CompanionPath $ExternalPath -DestinationPath $Destination -CollisionAction Error
      [IO.File]::ReadAllText($Extracted.FullName) | Should -Be 'external payload'

      $DuplicateDirectory = Join-Path $TestDrive 'duplicate-external'
      $null = New-Item -Path $DuplicateDirectory -ItemType Directory
      $DuplicatePath = Join-Path $DuplicateDirectory 'External.dat'
      [IO.File]::WriteAllText($DuplicatePath, 'ambiguous payload')
      { Get-QSetupInfo -Path $FixturePath -CompanionPath $ExternalPath, $DuplicatePath } | Should -Throw '*More than one explicit QSetup companion*'
    }
  }

  It 'Should decode an explicitly supplied compressed non-SFX payload' {
    $SetupText = "SET_PROG_NAME(Compressed External Product);`r`nSET_COMPOSER_BUILD(12.0.0.5);`r`nSET_TARGET_DIR(<ProgramFiles>\External);`r`nSET_SUB_DIR(<InstallDir>\bin);`r`nSET_COPY_FILES(External.dat);"
    $Preamble = ConvertTo-TestQSetupPreamble -Secret ('z' * 32)
    $FixtureBytes = [byte[]]::new(512) + $Preamble + (ConvertTo-TestQSetupRecord -Name 'Setup.txt' -Content ([Text.Encoding]::UTF8.GetBytes($SetupText)))
    $FixtureBytes += ConvertTo-TestQSetupFooter -OverlayOffset 512 -RecordCount 1
    $FixturePath = Join-Path $Script:FixtureDirectory 'compressed-external-qsetup.exe'
    $CompressedPath = Join-Path $Script:FixtureDirectory 'External.dat._z'
    [IO.File]::WriteAllBytes($FixturePath, $FixtureBytes)
    $Output = [IO.File]::Open($CompressedPath, [IO.FileMode]::Create, [IO.FileAccess]::Write)
    $Encoder = [IO.Compression.ZLibStream]::new($Output, [IO.Compression.CompressionLevel]::SmallestSize, $true)
    try {
      $Content = [Text.Encoding]::UTF8.GetBytes('compressed external payload')
      $Encoder.Write($Content, 0, $Content.Length)
    } finally { $Encoder.Dispose(); $Output.Dispose() }

    InModuleScope QSetup -Parameters @{ FixturePath = $FixturePath; CompressedPath = $CompressedPath } {
      param($FixturePath, $CompressedPath)
      Mock Get-PEOverlayOffset { 512 }
      Mock Get-PERequestedExecutionLevel { 'asInvoker' }
      Mock Get-PELayout { [pscustomobject]@{ MachineName = 'I386' } }
      $Info = Get-QSetupInfo -Path $FixturePath -CompanionPath $CompressedPath
      $Info.PayloadCatalog[0].ExternalSource.Compression | Should -Be 'Zlib'
      $Destination = Join-Path $TestDrive 'compressed-external-payload'
      $Extracted = Expand-QSetupInstaller -Path $FixturePath -CompanionPath $CompressedPath -DestinationPath $Destination -CollisionAction Error
      [IO.File]::ReadAllText($Extracted.FullName) | Should -Be 'compressed external payload'
    }
  }

  It 'Should reconstruct caller-supplied spanned media in strict order' {
    $SetupText = "SET_PROG_NAME(Spanned Product);`r`nSET_PROG_VERSION(3.0);`r`nSET_COMPOSER_BUILD(12.0.0.5);`r`nSET_ALL_USERS;"
    $Preamble = ConvertTo-TestQSetupPreamble -Secret ('p' * 32)
    $FullBytes = [byte[]]::new(512) + $Preamble + (ConvertTo-TestQSetupRecord -Name 'Setup.txt' -Content ([Text.Encoding]::UTF8.GetBytes($SetupText)))
    $FullBytes += ConvertTo-TestQSetupFooter -OverlayOffset 512 -RecordCount 1
    $MainPath = Join-Path $Script:FixtureDirectory 'spanned-fixture.exe'
    $PartPath = "$MainPath.001"
    $SplitOffset = 600
    [IO.File]::WriteAllBytes($MainPath, $FullBytes[0..($SplitOffset - 1)])
    [IO.File]::WriteAllBytes($PartPath, $FullBytes[$SplitOffset..($FullBytes.Length - 1)])

    InModuleScope QSetup -Parameters @{ MainPath = $MainPath; PartPath = $PartPath } {
      param($MainPath, $PartPath)
      Mock Get-PEOverlayOffset { 512 }
      Mock Get-PERequestedExecutionLevel { 'asInvoker' }
      Mock Get-PELayout { [pscustomobject]@{ MachineName = 'I386' } }
      $Info = Get-QSetupInfo -Path $MainPath -CompanionPath $PartPath
      $Info.DisplayName | Should -Be 'Spanned Product'
      $Info.MediaRoute | Should -Be 'SpannedConcatenation'
      $Info.StructuralRoutes[0] | Should -Be 'SpannedConcatenation'
      $Info.MediaParts | Should -HaveCount 2
      @($Info.Records.SourcePath | Where-Object { $_ }) | Should -BeNullOrEmpty
      $Destination = Join-Path $TestDrive 'spanned-records'
      $Extracted = Expand-QSetupInstaller -Path $MainPath -CompanionPath $PartPath -DestinationPath $Destination -RawRecords -Name Setup.txt -CollisionAction Error
      $Extracted | Should -HaveCount 1
    }
  }

  It 'Should reject a gap in explicitly supplied spanned media' {
    $MainPath = Join-Path $Script:FixtureDirectory 'gap-fixture.exe'
    $PartPath = "$MainPath.002"
    [IO.File]::WriteAllBytes($MainPath, [byte[]]::new(32))
    [IO.File]::WriteAllBytes($PartPath, [byte[]]::new(32))
    InModuleScope QSetup -Parameters @{ MainPath = $MainPath; PartPath = $PartPath } {
      param($MainPath, $PartPath)
      $Inventory = Get-QSetupCompanionInventory -CompanionPath $PartPath
      { Get-QSetupSpannedPartPath -InstallerPath $MainPath -CompanionFile $Inventory } | Should -Throw '*.001*'
    }
  }

  It 'Should recurse into a bounded nested QSetup wrapper record' {
    $InnerSetupText = "SET_PROG_NAME(Nested Product);`r`nSET_PROG_VERSION(4.0);`r`nSET_COMPOSER_BUILD(12.0.0.5);`r`nSET_ALL_USERS;"
    $Preamble = ConvertTo-TestQSetupPreamble -Secret ('n' * 32)
    $InnerBytes = [byte[]]::new(512) + $Preamble + (ConvertTo-TestQSetupRecord -Name 'Setup.txt' -Content ([Text.Encoding]::UTF8.GetBytes($InnerSetupText)))
    $InnerBytes += ConvertTo-TestQSetupFooter -OverlayOffset 512 -RecordCount 1
    $OuterBytes = [byte[]]::new(512) + $Preamble + (ConvertTo-TestQSetupRecord -Name 'NestedSetup.exe' -Content $InnerBytes)
    $OuterBytes += ConvertTo-TestQSetupFooter -OverlayOffset 512 -RecordCount 1
    $OuterPath = Join-Path $Script:FixtureDirectory 'nested-wrapper.exe'
    [IO.File]::WriteAllBytes($OuterPath, $OuterBytes)

    InModuleScope QSetup -Parameters @{ OuterPath = $OuterPath } {
      param($OuterPath)
      Mock Get-PEOverlayOffset { 512 }
      Mock Get-PERequestedExecutionLevel { 'asInvoker' }
      Mock Get-PELayout { [pscustomobject]@{ MachineName = 'I386' } }
      $Info = Get-QSetupInfo -Path $OuterPath
      $Info.DisplayName | Should -Be 'Nested Product'
      $Info.MediaRoute | Should -Be 'NestedSfxWrapper'
      $Info.NestedInstallerRecord | Should -Be 'NestedSetup.exe'
      $Info.StructuralRoutes[0] | Should -Be 'NestedSfxWrapper'
      @($Info.PayloadCatalog.Record.SourcePath | Where-Object { $_ }) | Should -BeNullOrEmpty

      $Destination = Join-Path $TestDrive 'nested-wrapper-raw'
      $Raw = Expand-QSetupInstaller -Path $OuterPath -DestinationPath $Destination -RawRecords -Name NestedSetup.exe -CollisionAction Error
      [Convert]::ToHexString([IO.File]::ReadAllBytes($Raw.FullName)[0..1]) | Should -Be '0000'
    }
  }

  It 'Should stop at the validated QSetup footer instead of treating it as a compressed record' {
    $SetupText = "SET_PROG_NAME(Footer Product);`r`nSET_PROG_VERSION(1.0);`r`nSET_COMPOSER_BUILD(12.0.0.5);`r`nSET_ALL_USERS;"
    $Preamble = [Text.Encoding]::ASCII.GetBytes('|http:|.info|.exe|fixture|0|')
    $FixtureBytes = [byte[]]::new(512) + [BitConverter]::GetBytes([uint32]1) + [byte]2 + [BitConverter]::GetBytes([uint32]$Preamble.Length) + $Preamble
    $FixtureBytes += ConvertTo-TestQSetupRecord -Name 'Engine.exe' -Content ([Text.Encoding]::ASCII.GetBytes('MZ engine')) -Required
    $FixtureBytes += ConvertTo-TestQSetupRecord -Name 'Setup.txt' -Content ([Text.Encoding]::UTF8.GetBytes($SetupText))
    $FixtureBytes += ConvertTo-TestQSetupFooter -OverlayOffset 512 -RecordCount 2
    $FixturePath = Join-Path $Script:FixtureDirectory 'synthetic-footer-qsetup.exe'
    [IO.File]::WriteAllBytes($FixturePath, $FixtureBytes)

    InModuleScope QSetup -Parameters @{ FixturePath = $FixturePath } {
      param($FixturePath)
      Mock Get-PEOverlayOffset { 512 }
      $Info = Get-QSetupInfo -Path $FixturePath
      $Info.Diagnostics | Should -BeNullOrEmpty
      $Info.Records | Should -HaveCount 2
      $Info.PackageFooter.DeclaredRecordCount | Should -Be 2
      $Info.Certificate | Should -BeNullOrEmpty

      $Destination = Join-Path $TestDrive 'qsetup-footer-extraction'
      $Files = Expand-QSetupInstaller -Path $FixturePath -DestinationPath $Destination -Name 'Setup.txt' -RawRecords -CollisionAction Error
      $Files | Should -HaveCount 1
      $Files[0].Name | Should -Be 'Setup.txt'
      $Files[0].FullName | Should -Be (Join-Path $Destination '_qsetup\records\Setup.txt')
    }
  }

  It 'Should classify the direct-record and double-pipe historical routes' -ForEach @(
    @{ Name = 'direct'; Prefix = $null; FooterRoute = 'Compact12'; Generation = 'Legacy1-2'; PreambleRoute = 'DirectRecords' }
    @{ Name = 'double-pipe'; Prefix = 'DoublePipe'; FooterRoute = 'Legacy74'; Generation = 'Legacy3-6'; PreambleRoute = 'DoublePipePreamble' }
  ) {
    $SetupText = "SET_COMPOSER_BUILD(5.0);`r`nSET_PROG_NAME(Historical QSetup);"
    $RecordBytes = ConvertTo-TestQSetupRecord -Name 'Setup.txt' -Content ([Text.Encoding]::UTF8.GetBytes($SetupText))
    if ($Prefix -eq 'DoublePipe') {
      $Preamble = [Text.Encoding]::ASCII.GetBytes('|http:|.info|.exe|historical|0|')
      $PackagePrefix = [BitConverter]::GetBytes([uint32]5) + [Text.Encoding]::ASCII.GetBytes('||') + [BitConverter]::GetBytes([uint32]$Preamble.Length) + $Preamble
    } else {
      $PackagePrefix = [byte[]]@()
    }
    $FixtureBytes = [byte[]]::new(512) + $PackagePrefix + $RecordBytes
    $FixtureBytes += ConvertTo-TestQSetupFooter -OverlayOffset 512 -RecordCount 1 -Route $FooterRoute
    $FixturePath = Join-Path $Script:FixtureDirectory "synthetic-$Name-qsetup.exe"
    [IO.File]::WriteAllBytes($FixturePath, $FixtureBytes)

    InModuleScope QSetup -Parameters @{ FixturePath = $FixturePath; Generation = $Generation; PreambleRoute = $PreambleRoute; FooterRoute = $FooterRoute } {
      param($FixturePath, $Generation, $PreambleRoute, $FooterRoute)
      Mock Get-PEOverlayOffset { 512 }
      $Layout = Get-QSetupLayout -Path $FixturePath
      $Layout.Complete | Should -BeTrue
      $Layout.FormatGeneration | Should -Be $Generation
      $Layout.StructuralRoutes | Should -Be @($PreambleRoute, 'Record/Zlib', $FooterRoute)
    }
  }

  It 'Should decode the legacy four-command execution layout' {
    InModuleScope QSetup {
      $Fields = [string[]]::new(59)
      $Fields[0] = '*'
      $Fields[2] = 'Legacy prerequisite'
      $Fields[3] = 'Setup Start'
      $Fields[20] = '1'
      $Fields[21] = 'Run Executable and Wait'
      $Fields[32] = '*'
      $Fields[46] = '<SrcDir>\legacy.exe'
      $Fields[47] = '/silent'
      $Fields[58] = '*'
      $Action = ConvertFrom-QSetupExecutionAction -Content ($Fields -join '|')
      $Action.LayoutRoute | Should -Be 'LegacyFourCommand'
      $Action.Commands | Should -HaveCount 1
      $Action.Commands[0].Argument1 | Should -Be '<SrcDir>\legacy.exe'
    }
  }

  It 'Should decode the QSetup 6 transitional execution layout' {
    InModuleScope QSetup {
      $Fields = [string[]]::new(67)
      $Fields[0] = '^'
      $Fields[2] = 'Remove marker'
      $Fields[3] = 'UnInstall End'
      $Fields[4] = '10'
      $Fields[5] = 'Conditional'
      $Fields[7] = '1'
      $Fields[8] = 'Environment Variable Is'
      $Fields[20] = '1'
      $Fields[21] = 'Remove Registry Key'
      $Fields[33] = '^'
      $Fields[35] = 'MARKER'
      $Fields[36] = '='
      $Fields[37] = '1'
      $Fields[47] = 'HKEY_CURRENT_USER\Software\Example'
      $Fields[66] = '^'

      $Action = ConvertFrom-QSetupExecutionAction -Content ($Fields -join '|')

      $Action.LayoutRoute | Should -Be 'TransitionalFourCommand'
      $Action.ConditionMode | Should -Be 'Conditional'
      $Action.Conditions | Should -HaveCount 1
      $Action.Conditions[0].Predicate | Should -Be 'Environment Variable Is'
      $Action.Conditions[0].Argument1 | Should -Be 'MARKER'
      $Action.Commands | Should -HaveCount 1
      $Action.Commands[0].Name | Should -Be 'Remove Registry Key'
      $Action.Commands[0].Argument1 | Should -Be 'HKEY_CURRENT_USER\Software\Example'
      $Action.ObservedTrailingFields | Should -HaveCount 7
    }
  }

  It 'Should normalize deterministic aliases and parent segments' {
    InModuleScope QSetup {
      $Directive = @{
        SET_TARGET_DIR = [Collections.Generic.List[object]]@('<ProgramFiles>\Vendor\App')
        SET_COMMON_DIR = [Collections.Generic.List[object]]@('<InstallDir>\..\Shared')
      }
      ConvertTo-QSetupManifestPath -Value '<Application Folder>\bin\app.exe' -Directive $Directive | Should -Be '%ProgramFiles%\Vendor\App\bin\app.exe'
      ConvertTo-QSetupManifestPath -Value '<Common Folder>\data' -Directive $Directive | Should -Be '%ProgramFiles%\Vendor\Shared\data'
      ConvertTo-QSetupManifestPath -Value '<Application Folder>\..\..\..\escape.exe' -Directive $Directive | Should -BeNullOrEmpty
    }
  }

  It 'Should retain malformed execution-action records as warnings' {
    InModuleScope QSetup {
      $Directive = @{ SET_PERFORM_EXECUTE_OP = [Collections.Generic.List[object]]@('unsupported-layout') }
      $Result = Get-QSetupExecutionActionInfo -Directive $Directive
      $Result.Actions | Should -BeNullOrEmpty
      $Result.ExecutedPayloads | Should -BeNullOrEmpty
      $Result.Diagnostics | Should -HaveCount 1
    }
  }

  It 'Should parse representative historical Pantaray media' -ForEach @(
    @{ Version = '1.0.0.1'; Sha256 = 'C9C3F625295DCB5CB3675B79DFEE8EB5C9FF9E4B7ADEB93D395AF53D40A70EFB'; Generation = 'Legacy1-2'; Footer = 'Compact12'; ActionRoute = 'LegacyFourCommand'; UninstallerName = 'UnInstall_24376.exe'; UninstallerRoute = 'CompiledShortcutTarget' }
    @{ Version = '5.0.0.0'; Sha256 = '606EF42EF079CC630F79D6E9013F65BE67EBA64E2D7AF99CEDBEA6F07089D629'; Generation = 'Legacy3-6'; Footer = 'Legacy74'; ActionRoute = 'LegacyFourCommand'; UninstallerName = 'UnInstall_17836.exe'; UninstallerRoute = 'CompiledShortcutTarget' }
    @{ Version = '6.0.0.0'; Sha256 = 'B79B711D651C0C81B5C615F799355448F9E32A78613955AED297493833ACA455'; Generation = 'Legacy3-6'; Footer = 'Legacy74'; ActionRoute = 'TransitionalFourCommand'; UninstallerName = 'UnInstall_17836.exe'; UninstallerRoute = 'CompiledShortcutTarget' }
    @{ Version = '8.1.0.2'; Sha256 = '88C8F4BD3819696C765A1FF33935BA769BE6658DB9E1334FB1CD89FCA74C189C'; Generation = 'Legacy7-11'; Footer = 'Legacy74'; ActionRoute = 'ModernSixCommand'; UninstallerName = 'un_qstp.exe'; UninstallerRoute = 'ExplicitName' }
    @{ Version = '9.1.0.6'; Sha256 = 'D1333B3ADED325EC53FAFEBBC1A1A25A0B98196CF3B23346F13F147A42444CCB'; Generation = 'Legacy7-11'; Footer = 'Legacy74'; ActionRoute = 'ModernSixCommand'; UninstallerName = 'un_qstp.exe'; UninstallerRoute = 'ExplicitName' }
    @{ Version = '10.0.2.1'; Sha256 = 'DA057E341AE9B38AB2DB1E912C5A047561D2E601E2CE5F1AE765943216EF6724'; Generation = 'Legacy7-11'; Footer = 'Legacy74'; ActionRoute = 'ModernSixCommand'; UninstallerName = 'uninstall_qstp.exe'; UninstallerRoute = 'ExplicitName' }
    @{ Version = '11.0.0.0'; Sha256 = 'C319CB5AF27757FFCB2333B02911C2F28964B57DE23B95278F9FFD22919133AB'; Generation = 'Legacy7-11'; Footer = 'Legacy74'; ActionRoute = 'ModernSixCommand'; UninstallerName = 'uninstall_qstp.exe'; UninstallerRoute = 'ExplicitName' }
  ) {
    $RelativePath = "Installers\QSetup\Pantaray.QSetup\$Version\qstp.exe"
    $Fixture = Resolve-DumplingsTestFixturePath -RelativePath $RelativePath
    if (-not (Test-DumplingsTestFixtureCacheEntry -Path $Fixture -Sha256 $Sha256)) {
      Set-ItResult -Skipped -Because "Cache the historical QSetup $Version fixture from the source URL recorded in the QSetup internals reference."
      return
    }

    $Info = Get-QSetupInfo -Path $Fixture
    $Info.DisplayVersion | Should -Be $Version
    $Info.FormatGeneration | Should -Be $Generation
    $Info.PackageFooter.RouteId | Should -Be $Footer
    $Info.ExecutionActions | Should -Not -BeNullOrEmpty
    $Info.ExecutionActions[0].LayoutRoute | Should -Be $ActionRoute
    $Info.Uninstaller.Name | Should -Be $UninstallerName
    $Info.Uninstaller.NamingRoute | Should -Be $UninstallerRoute
    $Info.UnresolvedFields | Should -BeNullOrEmpty
    $Info.CanExpand | Should -BeTrue
    $Info.PayloadCatalog | Should -Not -BeNullOrEmpty
    @($Info.PayloadCatalog | Where-Object { -not $_.InstalledPath }) | Should -BeNullOrEmpty
  }

  It 'Should recover current QSetup ARP, association, path, and payload evidence' {
    $RelativePath = 'Installers\QSetup\Pantaray.QSetup\12.0.0.5\qstp.exe'
    $Sha256 = 'E75A31A8E51757C9CA7C33EF836EAE8387139884F2C0B94A9BBD228EFA212ED7'
    $Fixture = Resolve-DumplingsTestFixturePath -RelativePath $RelativePath
    if (-not (Test-DumplingsTestFixtureCacheEntry -Path $Fixture -Sha256 $Sha256)) {
      Set-ItResult -Skipped -Because 'Cache the official QSetup 12.0.0.5 fixture.'
      return
    }

    $Info = Get-QSetupInfo -Path $Fixture
    $Info.DisplayName | Should -Be 'QSetup Installation Suite'
    $Info.ProductCode | Should -Be 'QSetup Installation Suite'
    $Info.Scope | Should -Be 'machine'
    $Info.RegistryView | Should -Be '32-bit'
    $Info.DefaultInstallLocation | Should -Be '%ProgramFiles%\Pantaray'
    $Info.UninstallString | Should -Be '"%ProgramFiles%\Pantaray\uninstall_qstp.exe"'
    $Info.FileExtensions | Should -Contain 'qsp'
    $Info.FormatGeneration | Should -Be 'Modern12'
    $Info.PayloadCatalog.Count | Should -BeGreaterThan 100
    $Info.PayloadCatalog.InstalledPath | Should -Contain '%ProgramFiles%\Pantaray\QSetup\Composer.exe'
    $Info.Shortcuts.Target | Should -Contain '%ProgramFiles%\Pantaray\QSetup\Composer.exe'
    $Info.Shortcuts.Target | Should -Contain 'http://www.pantaray.com'

    $Destination = Join-Path $TestDrive 'qsetup-current-extraction'
    $Composer = Expand-QSetupInstaller -Path $Fixture -DestinationPath $Destination -Name Composer.exe -CollisionAction Error
    [Convert]::ToHexString((Get-Content $Composer.FullName -AsByteStream -ReadCount 2 -TotalCount 2)) | Should -Be '4D5A'
  }

  It 'Should decode the legacy environment-operation record' {
    $RelativePath = 'Installers\QSetup\Pantaray.QSetup\4.0.0.4\qstp.exe'
    $Sha256 = 'BFEC5B30D618A4624A2F1957425F7862C26238951218B4A7E4BEC07334E046FE'
    $Fixture = Resolve-DumplingsTestFixturePath -RelativePath $RelativePath
    if (-not (Test-DumplingsTestFixtureCacheEntry -Path $Fixture -Sha256 $Sha256)) {
      Set-ItResult -Skipped -Because 'Cache the historical QSetup 4.0.0.4 fixture.'
      return
    }

    $Info = Get-QSetupInfo -Path $Fixture
    $Info.EnvironmentChanges | Should -HaveCount 1
    $Info.EnvironmentChanges[0].Name | Should -Be 'FRIDA'
    $Info.EnvironmentChanges[0].Value | Should -Be 'Gonen'
    $Info.EnvironmentChanges[0].Operation | Should -Be 'Append'
    $Info.EnvironmentChanges[0].UninstallAction | Should -Be 'Remove'
    $Info.EnvironmentChanges[0].Scope | Should -Be 'user'
  }

  It 'Should parse the complete signed AGTEK execution-action layout' {
    $RelativePath = 'Installers\QSetup\AGTEK.Trackwork\2.25.5.6\Trackwork4D225.5.6x64.exe'
    $Sha256 = '6EC7D39B466DF83024E1320A8755669CFA7FEB104166D615480D2FD17F42FE62'
    $Fixture = Resolve-DumplingsTestFixturePath -RelativePath $RelativePath
    if (-not (Test-DumplingsTestFixtureCacheEntry -Path $Fixture -Sha256 $Sha256)) {
      if ($env:DUMPLINGS_DOWNLOAD_LARGE_TEST_FIXTURES -eq '1') {
        $Fixture = Get-DumplingsTestFixture -RelativePath $RelativePath -Uri 'https://agtek.s3.amazonaws.com/Agtek/n9KWMWYsnSRr' -Sha256 $Sha256
      } else {
        Set-ItResult -Skipped -Because 'Set DUMPLINGS_DOWNLOAD_LARGE_TEST_FIXTURES=1 to cache the 125 MiB signed QSetup regression.'
        return
      }
    }

    $Info = Get-QSetupInfo -Path $Fixture
    @($Info.Diagnostics | Where-Object Id -EQ 'QSetup.UninstallString.Unresolved') | Should -BeNullOrEmpty
    $Info.UninstallString | Should -Be '"C:\AGTEK\Trackwork 64\TrackworkSetup64_21377.exe"'
    @($Info.Diagnostics | Where-Object { $_.Kind -ne 'Information' -and $_.Id -notin @('QSetup.ExecutionConditions.RuntimeDependent', 'QSetup.Execution.UserInteraction') }) | Should -BeNullOrEmpty
    $Info.Diagnostics.Id | Should -Contain 'QSetup.Execution.UserInteraction'
    $Info.PackageFooter.DeclaredRecordCount | Should -Be 241
    $Info.Records | Should -HaveCount 241
    $Info.Certificate.Offset | Should -BeGreaterThan $Info.PackageFooter.Offset
    $Info.ExecutionActions.Count | Should -BeGreaterThan 10
    $Info.ExecutedPayloads.Command | Should -Contain '<SrcDir>\vc100redist_x86.exe'
    $Info.ExecutedPayloads.Parameters | Should -Contain '/passive /norestart'
  }
}
