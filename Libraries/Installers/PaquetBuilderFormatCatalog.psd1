# SPDX-License-Identifier: Apache-2.0
# Structural Paquet Builder media profiles derived from archived builder
# installers, current builder output, and the shipped runtime ABI.
@{
  CatalogVersion = 3
  Profiles       = @(
    @{
      Id                    = 'ClassicResourcePackage'
      Generation            = 'Classic2'
      PayloadArchiveCount   = 1
      RuntimeContainer      = 'PeResourcesAndOverlay'
      RequiredResources     = @('DESCRIPTION', 'DVCLAL', 'PACKAGEINFO')
      SupportsFileExpansion = $true
      SupportsScriptScan    = $false
      ObservedBuilders      = '2.6.x'
    }
    @{
      Id                    = 'CabinetPackageRuntime'
      Generation            = 'Cabinet2'
      PayloadArchiveCount   = 1
      RuntimeContainer      = 'PeResource'
      RuntimeResourceName   = 'ENG'
      RuntimeMagic          = '4D5A'
      DescriptorResource    = 'ISFX'
      SupportsFileExpansion = $true
      SupportsScriptScan    = $true
      ObservedBuilders      = '2.7.x'
    }
    @{
      Id                    = 'LegacyEmbeddedPeRuntime'
      Generation            = 'Legacy2'
      PayloadArchiveCount   = 1
      RuntimeContainer      = 'PeResource'
      RuntimeResourceName   = 'ENG'
      RuntimeMagic          = '4D5A'
      OptionalResourceName  = 'ISFX'
      SupportsFileExpansion = $true
      SupportsScriptScan    = $true
      ObservedBuilders      = '2.8.x'
    }
    @{
      Id                    = 'CompressedResourceRuntime'
      Generation            = 'Resource2'
      PayloadArchiveCount   = 1
      RuntimeContainer      = 'PeResource'
      RuntimeResourceName   = 'ENG'
      RuntimeMagic          = '4750'
      SupportsFileExpansion = $true
      SupportsScriptScan    = $true
      ObservedBuilders      = '2.9.x'
    }
    @{
      Id                    = 'SplitArchiveRuntime'
      Generation            = 'Split3'
      PayloadArchiveCount   = 1
      RuntimeContainer      = 'SevenZip'
      RuntimeMarkers        = @('pbfprop.dat', 'PBCore.dll', 'PBCore64.dll', 'PBCoreA64.dll')
      SupportsFileExpansion = $true
      SupportsScriptScan    = $true
      ObservedBuilders      = '3.x-current'
    }
  )
}
