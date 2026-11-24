# SPDX-License-Identifier: Apache-2.0
# Format sources:
# - https://www.deploymaster.com/manual.html
# - https://www.deploymaster.com/history.html
# - Archived DeployMaster 2.5.3, 2.5.4, 2.5.5, 6.0.1, 6.1.2, 6.5.1, 6.5.2, 6.5.3, 7.1.1, 7.2.0, and 7.6.0 media
# - Controlled DeployMaster 7.7 builder output
#
# The profiles describe wire layouts, not application or builder versions. Runtime ranges record
# only the releases observed in fixtures. Parser dispatch always follows validated byte ranges.
@{
  CatalogVersion  = 1
  HeaderProfiles  = @(
    @{
      Id                          = 'Header74'
      Layout                      = 'Current'
      HeaderSize                  = 74
      Shift                       = 0
      FileTableKind               = 'Current'
      RegistryRoute               = 'Opcode'
      AssociationRoute            = 'Auto'
      HasWindows10Bounds          = $true
      HasWindows11Bounds          = $true
      HasPackageSettings          = $true
      UninstallCommandRoute       = 'QuotedExecutableAndLog'
      HasInstallForAllUsersSwitch = $true
      ObservedRuntimeRange        = '7.2.0-7.7.0'
      Evidence                    = 'Archived 7.2.0 and 7.6.0 media plus controlled 7.7 output'
    }
    @{
      Id                          = 'Header70'
      Layout                      = 'Legacy'
      HeaderSize                  = 70
      Shift                       = -4
      FileTableKind               = 'Legacy'
      RegistryRoute               = 'Opcode'
      AssociationRoute            = 'FormFeedDelimitedAnsi'
      HasWindows10Bounds          = $true
      HasWindows11Bounds          = $false
      HasPackageSettings          = $false
      UninstallCommandRoute       = 'UnquotedExecutableQuotedLog'
      HasInstallForAllUsersSwitch = $true
      ObservedRuntimeRange        = '6.5.1-7.1.1'
      Evidence                    = 'Archived 6.5.1, 6.5.2, 6.5.3, and 7.1.1 media'
    }
    @{
      Id                          = 'Header66'
      Layout                      = 'Legacy'
      HeaderSize                  = 66
      Shift                       = -8
      FileTableKind               = 'Legacy'
      RegistryRoute               = 'LegacyDelimited'
      AssociationRoute            = 'FormFeedDelimitedAnsi'
      HasWindows10Bounds          = $false
      HasWindows11Bounds          = $false
      HasPackageSettings          = $false
      UninstallCommandRoute       = 'UnquotedExecutableQuotedLog'
      HasInstallForAllUsersSwitch = $false
      ObservedRuntimeRange        = '6.0.1-6.1.2'
      Evidence                    = 'Archived 6.0.1 and 6.1.2 media'
    }
  )
  RuntimeFeatures = @{
    PortableSwitch = @{
      MinimumVersion = '7.5.0'
      Evidence       = 'DeployMaster 7.5.0 version history'
    }
  }
  ClassicRoutes   = @(
    @{
      Id                   = 'ClassicBZip2'
      ObservedRuntimeRange = '2.5.3-2.5.5'
      PackageMagic         = 'BZh9'
      Status               = 'Partial'
      RuntimeCompression   = 'BZip2'
      PayloadCompression   = 'Zlib'
      RegistryRoute        = 'ClassicNullTerminatedAnsi'
      AssociationRoute     = 'ClassicFormFeedAnsi'
      Evidence             = 'Archived 2.5.3 through 2.5.5 media uses a BZip2 runtime followed by length-prefixed zlib metadata, behavior, and payload records'
    }
  )
}
