# SPDX-License-Identifier: Apache-2.0
# QSetup structural profiles derived independently from official Pantaray media.
# Release labels are evidence for reporting; parser dispatch uses the byte-level
# predicates documented by each route instead of trusting PE version resources.
@{
  CatalogVersion    = 4

  PreambleRoutes    = @(
    @{
      Id               = 'DirectRecords'
      ObservedReleases = '1.0-2.0'
      Description      = 'The PE overlay begins directly with a uint32 compressed length and zlib member.'
    }
    @{
      Id               = 'DoublePipePreamble'
      ObservedReleases = '3.0-6.0'
      Description      = 'The overlay contains Version:u32, literal ||, PreambleLength:u32, and UTF-8 preamble text.'
    }
    @{
      Id               = 'VersionedPreamble'
      ObservedReleases = '7.0-12.0'
      Description      = 'The overlay contains Version:u32, CompressionFormat:u8, PreambleLength:u32, and UTF-8 preamble text.'
    }
  )

  MediaRoutes       = @(
    @{
      Id               = 'SingleFileSfx'
      ObservedReleases = '1.0-12.0'
      Description      = 'The PE overlay owns the preamble, records, footer, and optional certificate table.'
    }
    @{
      Id               = 'SplitKernel'
      ObservedReleases = '12.0'
      Description      = 'The PE kernel owns a split descriptor and zero-record footer; an explicitly supplied companion owns a matching descriptor and payload records.'
    }
    @{
      Id               = 'SplitCompanion'
      ObservedReleases = '12.0'
      Description      = 'A non-PE stream begins at offset zero with a versioned preamble and authenticated split descriptor.'
    }
    @{
      Id               = 'SpannedConcatenation'
      ObservedReleases = '2.0-12.0'
      Description      = 'Caller-supplied .001, .002, and later parts continue the original byte stream in strict numeric order.'
    }
    @{
      Id               = 'ExternalPayload'
      ObservedReleases = '1.0-12.0'
      Description      = 'A SET_COPY_FILES item absent from the embedded record table is resolved only from explicitly supplied files or directories.'
    }
  )

  FooterRoutes      = @(
    @{
      Id               = 'Compact12'
      ObservedReleases = '1.0-2.0'
      Length           = 12
      Description      = 'RecordCount:u32, OverlayOffset:u32, Magic:u32.'
    }
    @{
      Id               = 'Legacy74'
      ObservedReleases = '3.0-11.0'
      Length           = 74
      Description      = 'Version:u32, OverlayOffset:u32, RecordCount:u32, Magic:u32, legacy fields, FooterLength:u32.'
    }
    @{
      Id               = 'Modern74'
      ObservedReleases = '12.0'
      Length           = 74
      Description      = 'Version:u32, OverlayOffset:u32, RecordCount:u32, Magic:u32, Marker=1234, fields, FooterLength:u32.'
    }
  )

  ExecutionRoutes   = @(
    @{
      Id                      = 'LegacyFourCommand'
      ObservedReleases        = '1.0-5.0'
      FieldCounts             = @(59, 60)
      CommandStart            = 20
      CommandCount            = 4
      ArgumentStart           = 46
      MiddleSentinel          = 32
      HasStructuredConditions = $false
      ConditionArgumentStart  = $null
      TrailingStart           = $null
      TrailingEnd             = $null
    }
    @{
      Id                      = 'TransitionalFourCommand'
      ObservedReleases        = '6.0'
      FieldCounts             = @(67)
      CommandStart            = 20
      CommandCount            = 4
      ArgumentStart           = 47
      MiddleSentinel          = 33
      HasStructuredConditions = $true
      ConditionArgumentStart  = 35
      TrailingStart           = 59
      TrailingEnd             = 65
    }
    @{
      Id                      = 'ModernSixCommand'
      ObservedReleases        = '7.0-12.0'
      FieldCounts             = @(73)
      CommandStart            = 20
      CommandCount            = 6
      ArgumentStart           = 53
      MiddleSentinel          = 39
      HasStructuredConditions = $true
      ConditionArgumentStart  = 41
      TrailingStart           = $null
      TrailingEnd             = $null
    }
  )

  OperationRoutes   = @(
    @{
      Id          = 'RegistryPipe8'
      Directive   = 'SET_PERFORM_REGISTRY_OP'
      FieldCount  = 8
      Description = 'Leading sentinel, key, value name, data, setup action, uninstall action, value type, trailing sentinel.'
    }
    @{
      Id          = 'IniPipe8'
      Directive   = 'SET_PERFORM_INI_OP'
      FieldCount  = 8
      Description = 'Leading sentinel, file, section, value name, data, setup action, uninstall action, trailing sentinel.'
    }
    @{
      Id          = 'XmlPipe7'
      Directive   = 'SET_PERFORM_XML_OP'
      FieldCount  = 7
      Description = 'Leading sentinel, file, node path, value, setup action, uninstall action, trailing sentinel.'
    }
  )

  UninstallerRoutes = @(
    @{
      Id               = 'HistoricalGeneratedName'
      MaximumMajor     = 7
      Template         = 'UnInstall_{Stamp}.exe'
      ObservedReleases = 'compiled QSetup 1.0 through 7.5 shortcut targets'
    }
    @{
      Id               = 'CurrentGeneratedName'
      MinimumMajor     = 12
      Template         = '{Media}_{Stamp}.exe'
      ObservedReleases = '12.0 controlled VM installation'
    }
  )
}
