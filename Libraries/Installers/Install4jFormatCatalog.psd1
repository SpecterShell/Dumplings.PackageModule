@{
  CatalogVersion = '1.0'
  Formats        = @(
    @{
      Id                       = 'install4j-3'
      Generation               = 3
      MarkerPattern            = '^L-INGO#[0-9]+-$'
      LauncherRoute            = 'LegacyParameterBlock32'
      StartupFileRoute         = 'Xor88Int32'
      ContentTableRoute        = 'None'
      PayloadRoute             = 'InlineContentZip'
      ConfigRoute              = 'Legacy3Xml'
      RuntimePacking           = 'Jar'
      ArchitectureCapabilities = @('x86')
      ValidationInvariants     = @('OverlayMagic', 'CompleteParameterMaps', 'CompleteStartupFileTable', 'PayloadBoundaries')
    }
    @{
      Id                       = 'install4j-4'
      Generation               = 4
      MarkerPattern            = '^L-(?:M4-)?(?:EJ_TECHNOLOGIES|EJT)(?:_BUILD)?#[0-9]+-$'
      LauncherRoute            = 'LegacyParameterBlock64'
      StartupFileRoute         = 'Xor88Int64'
      ContentTableRoute        = 'ContentCollectorV1'
      PayloadRoute             = 'SplitLzmaArchive'
      ConfigRoute              = 'Legacy4Xml'
      RuntimePacking           = 'Pack200Optional'
      ArchitectureCapabilities = @('x86', 'x64')
      ValidationInvariants     = @('OverlayMagic', 'CompleteParameterMaps', 'CompleteStartupFileTable', 'ContentCollectorBoundaries', 'PayloadBoundaries')
    }
    @{
      Id                       = 'install4j-5'
      Generation               = 5
      MarkerPattern            = '^[LS]-M5-[A-Za-z0-9_]+#[0-9]+-$'
      LauncherRoute            = 'ModernOverlayV1'
      StartupFileRoute         = 'Xor88Int64'
      ContentTableRoute        = 'ContentCollectorV1'
      PayloadRoute             = 'LzmaZipContent'
      ConfigRoute              = 'ModernXml'
      RuntimePacking           = 'Pack200Optional'
      ArchitectureCapabilities = @('x86', 'x64')
      ValidationInvariants     = @('OverlayMagic', 'LauncherCrc32', 'CompleteParameterMaps', 'CompleteStartupFileTable', 'ContentCollectorBoundaries', 'PayloadBoundaries')
    }
    @{
      Id                       = 'install4j-6'
      Generation               = 6
      MarkerPattern            = '^[LS]-M6-[A-Za-z0-9_]+#[0-9]+-$'
      LauncherRoute            = 'ModernOverlayV1'
      StartupFileRoute         = 'Xor88Int64'
      ContentTableRoute        = 'ContentCollectorV1'
      PayloadRoute             = 'LzmaZipContent'
      ConfigRoute              = 'ModernXml'
      RuntimePacking           = 'Pack200Optional'
      ArchitectureCapabilities = @('x86', 'x64')
      ValidationInvariants     = @('OverlayMagic', 'LauncherCrc32', 'CompleteParameterMaps', 'CompleteStartupFileTable', 'ContentCollectorBoundaries', 'PayloadBoundaries')
    }
    @{
      Id                       = 'install4j-7'
      Generation               = 7
      MarkerPattern            = '^[LS]-M7-[A-Za-z0-9_]+#[0-9]+-$'
      LauncherRoute            = 'ModernOverlayV1'
      StartupFileRoute         = 'Xor88Int64'
      ContentTableRoute        = 'ContentCollectorV1'
      PayloadRoute             = 'LzmaZipContent'
      ConfigRoute              = 'ModernXml'
      RuntimePacking           = 'Pack200Optional'
      ArchitectureCapabilities = @('x86', 'x64')
      ValidationInvariants     = @('OverlayMagic', 'LauncherCrc32', 'CompleteParameterMaps', 'CompleteStartupFileTable', 'ContentCollectorBoundaries', 'PayloadBoundaries')
    }
    @{
      Id                       = 'install4j-8'
      Generation               = 8
      MarkerPattern            = '^[LS]-M8-[A-Za-z0-9_]+#[0-9]+-$'
      LauncherRoute            = 'ModernOverlayV1'
      StartupFileRoute         = 'Xor88Int64'
      ContentTableRoute        = 'ContentCollectorV1'
      PayloadRoute             = 'LzmaZipContent'
      ConfigRoute              = 'ModernXml'
      RuntimePacking           = 'Pack200Optional'
      ArchitectureCapabilities = @('x86', 'x64')
      ValidationInvariants     = @('OverlayMagic', 'LauncherCrc32', 'CompleteParameterMaps', 'CompleteStartupFileTable', 'ContentCollectorBoundaries', 'PayloadBoundaries')
    }
    @{
      Id                       = 'install4j-9'
      Generation               = 9
      MarkerPattern            = '^[LS]-M9-[A-Za-z0-9_]+#[0-9]+-$'
      LauncherRoute            = 'ModernOverlayV1'
      StartupFileRoute         = 'Xor88Int64'
      ContentTableRoute        = 'ContentCollectorV1'
      PayloadRoute             = 'LzmaZipContent'
      ConfigRoute              = 'ModernXml'
      RuntimePacking           = 'Pack200Optional'
      ArchitectureCapabilities = @('x86', 'x64')
      ValidationInvariants     = @('OverlayMagic', 'LauncherCrc32', 'CompleteParameterMaps', 'CompleteStartupFileTable', 'ContentCollectorBoundaries', 'PayloadBoundaries')
    }
    @{
      Id                       = 'install4j-10'
      Generation               = 10
      MarkerPattern            = '^[LS]-M10-[A-Za-z0-9_]+#[0-9]+-$'
      LauncherRoute            = 'ModernOverlayV1'
      StartupFileRoute         = 'Xor88Int64'
      ContentTableRoute        = 'ContentCollectorV1'
      PayloadRoute             = 'LzmaZipContent'
      ConfigRoute              = 'ModernXml'
      RuntimePacking           = 'Jar'
      ArchitectureCapabilities = @('x86', 'x64', 'arm64')
      ValidationInvariants     = @('OverlayMagic', 'LauncherCrc32', 'CompleteParameterMaps', 'CompleteStartupFileTable', 'ContentCollectorBoundaries', 'PayloadBoundaries')
    }
    @{
      Id                       = 'install4j-11'
      Generation               = 11
      MarkerPattern            = '^[LS]-M11-[A-Za-z0-9_]+#[0-9]+-$'
      LauncherRoute            = 'ModernOverlayV1'
      StartupFileRoute         = 'Xor88Int64'
      ContentTableRoute        = 'ContentCollectorV1'
      PayloadRoute             = 'LzmaZipContent'
      ConfigRoute              = 'ModernXml'
      RuntimePacking           = 'Jar'
      ArchitectureCapabilities = @('x86', 'x64', 'arm64')
      ValidationInvariants     = @('OverlayMagic', 'LauncherCrc32', 'CompleteParameterMaps', 'CompleteStartupFileTable', 'ContentCollectorBoundaries', 'PayloadBoundaries')
    }
    @{
      Id                       = 'install4j-12'
      Generation               = 12
      MarkerPattern            = '^[LS]-M12-[A-Za-z0-9_]+#[0-9]+-$'
      LauncherRoute            = 'ModernOverlayV1'
      StartupFileRoute         = 'Xor88Int64'
      ContentTableRoute        = 'ContentCollectorV1'
      PayloadRoute             = 'LzmaZipContent'
      ConfigRoute              = 'ModernXml'
      RuntimePacking           = 'Jar'
      ArchitectureCapabilities = @('x86', 'x64', 'arm64')
      ValidationInvariants     = @('OverlayMagic', 'LauncherCrc32', 'CompleteParameterMaps', 'CompleteStartupFileTable', 'ContentCollectorBoundaries', 'PayloadBoundaries')
    }
    @{
      Id                       = 'install4j-13'
      Generation               = 13
      MarkerPattern            = '^[LS]-M13-[A-Za-z0-9_]+#[0-9]+-$'
      LauncherRoute            = 'ModernOverlayV1'
      StartupFileRoute         = 'Xor88Int64'
      ContentTableRoute        = 'ContentCollectorV1'
      PayloadRoute             = 'LzmaZipContent'
      ConfigRoute              = 'ModernXml'
      RuntimePacking           = 'Jar'
      ArchitectureCapabilities = @('x86', 'x64', 'arm64')
      ValidationInvariants     = @('OverlayMagic', 'LauncherCrc32', 'CompleteParameterMaps', 'CompleteStartupFileTable', 'ContentCollectorBoundaries', 'PayloadBoundaries')
    }
  )
}
