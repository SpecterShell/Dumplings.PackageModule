# SPDX-License-Identifier: Apache-2.0
# Data-only routing catalog for physical Actual Installer container generations.
# Release bounds validate a selected route; they never dispatch the parser.
@{
  CatalogVersion = 3

  # Routes are selected from physical container structure first. Builder-version
  # ranges are compatibility checks and never override a validated container.
  Routes         = @(
    @{
      Id               = 'Cabinet3'
      Container        = 'CabinetSequence'
      MetadataEntry    = 'setup.ini'
      MetadataPosition = 'First'
      MinimumMajor     = 3
      MaximumMajor     = 3
      VerifiedVersions = @('3.8')
      PayloadEncoding  = 'OneCabinetPerFile'
    }
    @{
      Id               = 'Cabinet4'
      Container        = 'CabinetSequence'
      MetadataEntry    = 'aisetup.ini'
      MetadataPosition = 'First'
      MinimumMajor     = 4
      MaximumMajor     = 4
      VerifiedVersions = @('4.8')
      PayloadEncoding  = 'OneCabinetPerFile'
    }
    @{
      Id                       = 'Cabinet5'
      Container                = 'CabinetSequence'
      MetadataEntry            = 'aisetup.ini'
      MetadataPosition         = 'Last'
      MinimumMajor             = 5
      MaximumMajor             = 5
      VerifiedVersions         = @('5.2')
      PayloadEncoding          = 'OneCabinetPerFile'
      GeneratedUninstallerMode = 'ExactCopy'
    }
    @{
      Id                       = 'Zip6Plus'
      Container                = 'ZipSequence'
      MetadataEntry            = 'aisetup.ini'
      MetadataPosition         = 'Last'
      MinimumMajor             = 6
      MaximumMajor             = 2147483647
      VerifiedVersions         = @('6.6', '6.7', '8.0', '8.2', '8.3', '8.4', '9.2', '9.6', '9.8')
      PayloadEncoding          = 'NumberedZipEntries'
      GeneratedUninstallerMode = 'ExactCopy'
    }
    @{
      # Setup EXE + Data keeps only setup metadata in the executable. The
      # source-directory tree is stored in the separately supplied 7z file.
      Id               = 'ZipExternalData'
      Container        = 'ZipSequence'
      MetadataEntry    = 'aisetup.ini'
      MetadataPosition = 'First'
      ContainerCount   = 1
      MinimumMajor     = 6
      MaximumMajor     = 2147483647
      VerifiedVersions = @()
      PayloadEncoding  = 'ExternalSevenZip'
    }
  )
}
