# SPDX-License-Identifier: Apache-2.0
# Format sources:
# - https://www.thraexsoftware.com/
# - https://web.archive.org/web/20120410054204id_/http://www.thraexsoftware.com/aiw/version_history.txt
# - Controlled and archived Astrum InstallWizard builder output from 1.80 through 2.29.50
#
# This catalog contains declarative wire-layout evidence only. The parser selects a format from
# validated footer length and trailer structure, then consumes the named fields without branching
# on an application's authored version.
@{
  CatalogVersion        = 1
  OperationSemantics    = @{
    # Compiler enum order recovered from the builder runtime. Interactive UI order differs.
    TextActions        = @(
      'Add to beginning of file'
      'Add to end of file'
      'Append to search line'
      'Delete search line'
      'Insert after search line'
      'Insert before search line'
      'Delete line starting with'
      'Replace text'
    )
    FileActions        = @(
      'Copy'
      'Delete'
      'Move'
      'Rename'
      'Make directory'
      'Remove directory'
    )
    InteractiveActions = @(
      'Execute program'
      'Open document'
      'Open web site'
      'Explore folder'
      'Show message'
      'End installation'
      'Execute program and wait'
      'Ask yes/no question'
      'Show text box'
      'Assign variable value'
    )
    Timings            = @(
      'At program startup'
      'After language dialog'
      'After welcome dialog'
      'After license agreement dialog'
      'After readme dialog'
      'After system information dialog'
      'After user information dialog'
      'After destination directory dialog'
      'After shortcut folder dialog'
      'After installation type dialog'
      'After options dialog'
      'After summary dialog'
      'After installation'
      'On shutdown'
    )
    ConditionOperators = @(
      'Equals'
      'Not equal'
      'Greater than'
      'Less than'
      'Greater than or equal'
      'Less than or equal'
      'Contains / Binary and'
    )
  }
  VariableSemantics     = @{
    Types   = @(
      'Text'
      'Number'
    )
    # The builder writes -1 for Nowhere and zero-based values for the three runtime sources.
    Sources = @{
      '0'          = 'Registry'
      '1'          = 'INI'
      '2'          = 'Find file location'
      '4294967295' = 'Nowhere'
    }
    Flags   = @{
      StoreDriveOnly  = 0x01
      SetTrueIfExists = 0x02
      UserVisible     = 0x04
    }
  }
  Formats               = @(
    @{
      Id                                 = 'astrum-1'
      Generation                         = '1.x'
      ObservedVersionRange               = '1.80-1.95.5'
      FooterLength                       = 0xE8
      FooterOffsets                      = @{
        ConfigurationOffset       = 0x00
        ConfigurationSize         = 0x04
        UninstallerCompressedSize = 0xA4
        UninstallerOffset         = 0xA8
        InstallationItemCount     = 0xAC
        InstallationItemOffset    = 0xB0
        InstallationItemSize      = 0xB4
        FileCount                 = 0xB8
        FileOffset                = 0xBC
        PayloadSize               = 0xC0
        ExpandedSize              = 0xC4
        InstalledSize             = 0xC8
        SelfPointer               = 0xE4
      }
      TrailerRoutes                      = @('LegacyNoMagic', 'DualMagic')
      RequireRuntimeIdentityWithoutMagic = $true
      FileDescriptorSize                 = 60
      FileConditionWordIndex             = -1
      HasRecordConditions                = $false
      RegistryChildRoute                 = 'NameOnly'
      OperationTailRoute                 = 'ObservedUInt32'
      InteractiveOperationRoute          = 'LegacyWithoutTail'
      InteractiveActionCount             = 8
      HasPostInteractiveTable            = $false
      ConfigurationProfileRoute          = 'Fixed'
      DefaultConfigurationProfile        = 'Legacy1'
      RuntimeWordProfile                 = $null
      RuntimeWordMaximum                 = $null
      ContainerRoutePrefix               = 'Astrum1'
      SupportsTiny                       = $true
      SupportsSpanned                    = $false
      InstallerSuccessCodes              = @()
      ValidationInvariants               = @('PEImage', 'RuntimeIdentityForNoMagic', 'FooterSelfPointer', 'ProtectedConfiguration', 'CompleteInstallationItemTable', 'CompleteFileCatalog')
    }
    @{
      Id                                 = 'astrum-2'
      Generation                         = '2.x'
      ObservedVersionRange               = '2.01.50-2.29.50'
      FooterLength                       = 0xEC
      FooterOffsets                      = @{
        ConfigurationOffset       = 0x00
        ConfigurationSize         = 0x04
        UninstallerCompressedSize = 0xA8
        UninstallerOffset         = 0xAC
        InstallationItemCount     = 0xB0
        InstallationItemOffset    = 0xB4
        InstallationItemSize      = 0xB8
        FileCount                 = 0xBC
        FileOffset                = 0xC0
        PayloadSize               = 0xC4
        ExpandedSize              = 0xC8
        InstalledSize             = 0xCC
        SelfPointer               = 0xE8
      }
      TrailerRoutes                      = @('DualMagic')
      RequireRuntimeIdentityWithoutMagic = $false
      FileDescriptorSize                 = 64
      FileConditionWordIndex             = 15
      HasRecordConditions                = $true
      RegistryChildRoute                 = 'UninstallAndCondition'
      OperationTailRoute                 = 'Condition'
      InteractiveOperationRoute          = 'CurrentWithCondition'
      InteractiveActionCount             = 10
      HasPostInteractiveTable            = $true
      ConfigurationProfileRoute          = 'LeadingRuntimeWord'
      DefaultConfigurationProfile        = 'Early2'
      RuntimeWordProfile                 = 'Modern2'
      RuntimeWordMaximum                 = 0xFFFF
      ContainerRoutePrefix               = 'Astrum2'
      SupportsTiny                       = $true
      SupportsSpanned                    = $true
      InstallerSuccessCodes              = @(1)
      ValidationInvariants               = @('PEImage', 'DualTrailerMagic', 'FooterSelfPointer', 'ProtectedConfiguration', 'CompleteInstallationItemTable', 'CompleteFileCatalog')
    }
  )
  ConfigurationProfiles = @{
    Legacy1 = @{
      Id                   = 'Legacy1'
      Generation           = '1.x'
      ObservedVersionRange = '1.80-1.95.5'
      IdentityRoute        = 'Legacy'
      OptionRoute          = 'Opaque'
      SilentRoute          = 'RuntimeSwitchEvidence'
      OptionFields         = @()
    }
    Early2  = @{
      Id                          = 'Early2'
      Generation                  = '2.x'
      ObservedVersionRange        = '2.01.50-2.04.20'
      IdentityRoute               = 'Legacy'
      OptionRoute                 = 'Opaque'
      SilentRoute                 = 'Documented2'
      UserInformationBlocksSilent = $true
      UserInformationEvidence     = 'Astrum documentation states the User Information dialog makes /silent fail; no VM proof exists for this generation.'
      OptionFields                = @()
    }
    Modern2 = @{
      Id                          = 'Modern2'
      Generation                  = '2.x'
      ObservedVersionRange        = '2.21.20-2.29.50'
      IdentityRoute               = 'Modern'
      OptionRoute                 = 'SparseModern2'
      SilentRoute                 = 'Documented2'
      UserInformationBlocksSilent = $false
      UserInformationEvidence     = 'Controlled VM installation of a 2.29.50 build that compiles the User Information dialog completes /silent with exit code 1 and full ARP registration.'
      OptionFields                = @(
        @{ Name = 'MinimumCpuSpeedMHz'; Group = 'Requirements'; Origin = 'Option'; Offset = 0x48; Type = 'UInt32'; Endian = 'BigEndian' }
        @{ Name = 'CpuManufacturerCode'; Group = 'Requirements'; Origin = 'Option'; Offset = 0x4C; Type = 'UInt32'; Endian = 'BigEndian' }
        @{ Name = 'CpuVendorMask'; Group = 'Requirements'; Origin = 'Option'; Offset = 0x50; Type = 'UInt32'; Endian = 'BigEndian' }
        @{ Name = 'CpuFeatureFlags'; Group = 'Requirements'; Origin = 'Option'; Offset = 0x54; Type = 'UInt32'; Endian = 'BigEndian' }
        @{ Name = 'MinimumMemoryMiB'; Group = 'Requirements'; Origin = 'Option'; Offset = 0x58; Type = 'UInt32'; Endian = 'BigEndian' }
        @{ Name = 'WindowsPlatformMask'; Group = 'Requirements'; Origin = 'Option'; Offset = 0x5C; Type = 'UInt32'; Endian = 'BigEndian' }
        @{ Name = 'MinimumWindows9xBuild'; Group = 'Requirements'; Origin = 'Option'; Offset = 0x60; Type = 'UInt32'; Endian = 'BigEndian' }
        @{ Name = 'MinimumWindowsNtMajor'; Group = 'Requirements'; Origin = 'Option'; Offset = 0x64; Type = 'UInt32'; Endian = 'BigEndian' }
        @{ Name = 'MinimumWindowsNtMinor'; Group = 'Requirements'; Origin = 'Option'; Offset = 0x68; Type = 'UInt32'; Endian = 'BigEndian' }
        @{ Name = 'MinimumNtServicePack'; Group = 'Requirements'; Origin = 'Option'; Offset = 0x6C; Type = 'UInt32'; Endian = 'BigEndian' }
        @{ Name = 'MinimumDirectXMajor'; Group = 'Requirements'; Origin = 'Option'; Offset = 0x70; Type = 'UInt16'; Endian = 'BigEndian' }
        @{ Name = 'MinimumDirectXMinor'; Group = 'Requirements'; Origin = 'Option'; Offset = 0x72; Type = 'UInt16'; Endian = 'BigEndian' }
        @{ Name = 'MinimumResolutionWidth'; Group = 'Requirements'; Origin = 'Option'; Offset = 0x74; Type = 'UInt32'; Endian = 'BigEndian' }
        @{ Name = 'MinimumResolutionHeight'; Group = 'Requirements'; Origin = 'Option'; Offset = 0x78; Type = 'UInt32'; Endian = 'BigEndian' }
        @{ Name = 'MinimumResolutionBitsPerPixel'; Group = 'Requirements'; Origin = 'Option'; Offset = 0x7C; Type = 'UInt32'; Endian = 'BigEndian' }
        @{ Name = 'MinimumDotNetFrameworkCode'; Group = 'Requirements'; Origin = 'Option'; Offset = 0x80; Type = 'UInt32'; Endian = 'BigEndian' }
        @{ Name = 'MinimumJavaVersion'; Group = 'Requirements'; Origin = 'Option'; Offset = 0x84; Type = 'NullTerminatedString' }
        @{ Name = 'RequiresWavePlayback'; Group = 'Requirements'; Origin = 'AfterJavaVersion'; Offset = 0x0C; Type = 'BooleanUInt32'; Endian = 'BigEndian' }
        @{ Name = 'RequiresMidiPlayback'; Group = 'Requirements'; Origin = 'AfterJavaVersion'; Offset = 0x10; Type = 'BooleanUInt32'; Endian = 'BigEndian' }
        @{ Name = 'RequiresJoystick'; Group = 'Requirements'; Origin = 'AfterJavaVersion'; Offset = 0x14; Type = 'BooleanUInt32'; Endian = 'BigEndian' }
        @{ Name = 'UserInformationFlags'; Group = 'Configuration'; Origin = 'AfterJavaVersion'; Offset = 0x18; Type = 'UInt32'; Endian = 'BigEndian' }
        @{ Name = 'SilentInstallationDefault'; Group = 'Configuration'; Origin = 'AfterJavaVersion'; Offset = 0x68; Type = 'BooleanUInt32'; Endian = 'BigEndian' }
        @{ Name = 'NoUninstallation'; Group = 'Configuration'; Origin = 'AfterJavaVersion'; Offset = 0x6C; Type = 'BooleanUInt32'; Endian = 'BigEndian' }
        @{ Name = 'X64ComplianceMode'; Group = 'Configuration'; Origin = 'AfterJavaVersion'; Offset = 0xA9; Type = 'BooleanUInt32'; Endian = 'BigEndian' }
        @{ Name = 'RequireAdmin'; Group = 'Configuration'; Origin = 'AfterJavaVersion'; Offset = 0xAD; Type = 'BooleanUInt32'; Endian = 'BigEndian' }
        @{ Name = 'DirectLicenseApproval'; Group = 'Configuration'; Origin = 'End'; Distance = 29; Type = 'BooleanByte' }
        @{ Name = 'ProhibitSilentInstallation'; Group = 'Configuration'; Origin = 'End'; Distance = 25; Type = 'BooleanByte' }
      )
    }
  }
}
