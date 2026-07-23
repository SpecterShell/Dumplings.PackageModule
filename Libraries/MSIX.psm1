# SPDX-License-Identifier: Apache-2.0
# Format sources: https://github.com/microsoft/msix-packaging
# MSIX/AppX binary structure consumed here:
#
#   ZIP/OPC -> [Content_Types].xml, AppxManifest.xml, AppxBlockMap.xml,
#              AppxSignature.p7x, payload files
#   bundle  -> AppxMetadata/AppxBundleManifest.xml -> nested packages
#
# Type detection uses required entries, not filename extension. ZIP paths and
# sizes are bounded; XML supplies identity/dependencies/capabilities. Signature
# presence/hash and Windows trust validation are separate checks.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# Force stop on error
$ErrorActionPreference = 'Stop'

$Script:MSIXAllowedDependencyPackagePatterns = @(
  'Microsoft.VCLibs.Desktop.14',
  'Microsoft.VCLibs.14',
  'Microsoft.WindowsAppRuntime.*.*',
  'Microsoft.UI.Xaml.*.*'
)

function Get-MSIXZipArchive {
  <#
  .SYNOPSIS
    Open the MSIX/AppX package ZIP archive
  .PARAMETER Path
    The path to the MSIX/AppX package
  #>
  [OutputType([System.IO.Compression.ZipArchive])]
  param (
    [Parameter(Position = 0, Mandatory, HelpMessage = 'The path to the MSIX/AppX package')]
    [string]$Path
  )

  Add-Type -AssemblyName System.IO.Compression.FileSystem
  [System.IO.Compression.ZipFile]::OpenRead((Get-Item -Path $Path -Force).FullName)
}

function Read-MSIXZipEntryText {
  <#
  .SYNOPSIS
    Read a text entry from an opened ZIP archive
  .PARAMETER Archive
    The ZIP archive to inspect
  .PARAMETER Name
    The entry name to read
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The ZIP archive to inspect')]
    [System.IO.Compression.ZipArchive]$Archive,

    [Parameter(Mandatory, HelpMessage = 'The entry name to read')]
    [string]$Name
  )

  $Entry = $Archive.GetEntry($Name)
  if (-not $Entry) { return $null }

  $Stream = $Entry.Open()
  $Reader = [System.IO.StreamReader]::new($Stream)
  try {
    $Reader.ReadToEnd()
  } finally {
    $Reader.Dispose()
    $Stream.Dispose()
  }
}

function Get-MSIXManifestXmlList {
  <#
  .SYNOPSIS
    Read package manifests from a direct MSIX/AppX package or bundle
  .PARAMETER Path
    The path to the MSIX/AppX package
  #>
  [OutputType([xml[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the MSIX/AppX package')]
    [string]$Path
  )

  process {
    $Archive = Get-MSIXZipArchive -Path $Path

    try {
      # A direct package contributes one manifest. A bundle contributes its bundle manifest plus
      # each nested package manifest needed for architecture/dependency evidence.
      $ManifestText = Read-MSIXZipEntryText -Archive $Archive -Name 'AppxManifest.xml'
      if ($ManifestText) {
        [xml]$ManifestText
        return
      }

      $BundleManifestText = Read-MSIXZipEntryText -Archive $Archive -Name 'AppxMetadata/AppxBundleManifest.xml'
      if ($BundleManifestText) { [xml]$BundleManifestText }

      # Bundles store real package metadata in nested appx/msix payloads.
      # Nested package entries may be non-seekable; use the shared spill-to-disk context instead of
      # loading multi-gigabyte bundle members into a PowerShell byte array.
      foreach ($Entry in $Archive.Entries | Where-Object { $_.FullName -match '\.(appx|msix)$' }) {
        $EntryStream = $Entry.Open()
        $SeekableContext = $null
        try {
          $SeekableContext = New-InstallerSeekableStream -SourceStream $EntryStream -MaximumBytes 4294967296
          $NestedArchive = [System.IO.Compression.ZipArchive]::new($SeekableContext.Stream, [System.IO.Compression.ZipArchiveMode]::Read, $true)
          try {
            $NestedManifestText = Read-MSIXZipEntryText -Archive $NestedArchive -Name 'AppxManifest.xml'
            if ($NestedManifestText) { [xml]$NestedManifestText }
          } finally {
            $NestedArchive.Dispose()
          }
        } finally {
          if ($SeekableContext) { $SeekableContext.Dispose() }
          $EntryStream.Dispose()
        }
      }
    } finally {
      $Archive.Dispose()
    }
  }
}

function Get-MSIXPackageLayout {
  <#
  .SYNOPSIS
    Detect an AppX/MSIX package or bundle from its archive contents
  .PARAMETER Path
    The local package path
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The local package path')]
    [string]$Path
  )

  process {
    $Archive = Get-MSIXZipArchive -Path $Path
    try {
      # Package-vs-bundle classification comes from mutually exclusive OPC manifest paths, not the
      # local filename extension.
      $EntryNames = @($Archive.Entries | ForEach-Object { $_.FullName.Replace('\', '/').TrimStart('/') })
      $HasPackageManifest = @($EntryNames | Where-Object { $_ -ieq 'AppxManifest.xml' }).Count -gt 0
      $HasBundleManifest = @($EntryNames | Where-Object { $_ -ieq 'AppxMetadata/AppxBundleManifest.xml' }).Count -gt 0

      if ($HasPackageManifest -eq $HasBundleManifest) {
        if ($HasPackageManifest) { throw 'The archive contains both package and bundle manifests' }
        throw 'The archive does not contain an AppxManifest.xml or AppxBundleManifest.xml file'
      }

      $Warnings = [System.Collections.Generic.List[string]]::new()
      $PayloadInstallerTypes = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
      if ($HasBundleManifest) {
        # Bundle package declarations are primary type evidence; nested root filenames are retained
        # only as a fallback for incomplete bundle metadata.
        $BundleManifestText = Read-MSIXZipEntryText -Archive $Archive -Name 'AppxMetadata/AppxBundleManifest.xml'
        try {
          [xml]$BundleManifest = $BundleManifestText
          foreach ($Package in $BundleManifest.GetElementsByTagName('Package')) {
            switch ([System.IO.Path]::GetExtension([string]$Package.FileName).ToLowerInvariant()) {
              '.appx' { $null = $PayloadInstallerTypes.Add('appx') }
              '.msix' { $null = $PayloadInstallerTypes.Add('msix') }
            }
          }
        } catch {
          $Warnings.Add("The AppX/MSIX bundle manifest could not be parsed: $($_.Exception.Message)")
        }

        # Retain root archive names as secondary evidence when bundle XML omits a payload filename.
        foreach ($EntryName in $EntryNames) {
          switch ([System.IO.Path]::GetExtension($EntryName).ToLowerInvariant()) {
            '.appx' { $null = $PayloadInstallerTypes.Add('appx') }
            '.msix' { $null = $PayloadInstallerTypes.Add('msix') }
          }
        }
      }

      [pscustomobject]@{
        PackageKind        = $HasBundleManifest ? 'Bundle' : 'Package'
        HasContentTypes    = @($EntryNames | Where-Object { $_ -ieq '[Content_Types].xml' }).Count -gt 0
        HasBlockMap        = @($EntryNames | Where-Object { $_ -ieq 'AppxBlockMap.xml' }).Count -gt 0
        HasSignature       = @($EntryNames | Where-Object { $_ -ieq 'AppxSignature.p7x' }).Count -gt 0
        ManifestPath       = $HasBundleManifest ? 'AppxMetadata/AppxBundleManifest.xml' : 'AppxManifest.xml'
        BundlePayloadTypes = @($PayloadInstallerTypes | Sort-Object)
        Warnings           = @($Warnings)
      }
    } finally {
      $Archive.Dispose()
    }
  }
}

function Get-MSIXPackageKind {
  <#
  .SYNOPSIS
    Read whether an AppX/MSIX archive is a direct package or bundle
  .PARAMETER Path
    The local package path
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The local package path')]
    [string]$Path
  )

  process { (Get-MSIXPackageLayout -Path $Path).PackageKind }
}

function Get-MSIXPackageTypeInfo {
  <#
  .SYNOPSIS
    Resolve the WinGet installer type and package kind from authoritative hints and package contents
  .PARAMETER Path
    The package path or URI
  .PARAMETER InstallerTypeHint
    The known WinGet installer type, such as the type retained from an existing manifest
  .PARAMETER ContentType
    The package HTTP Content-Type value
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The package path or URI')]
    [string]$Path,

    [Parameter(HelpMessage = 'The known WinGet installer type')]
    [AllowNull()]
    [AllowEmptyString()]
    [ValidateScript({ [string]::IsNullOrWhiteSpace($_) -or $_ -in @('appx', 'msix') })]
    [string]$InstallerTypeHint,

    [Parameter(HelpMessage = 'The package HTTP Content-Type value')]
    [string]$ContentType
  )

  process {
    $Warnings = [System.Collections.Generic.List[string]]::new()
    $Layout = if (Test-Path -LiteralPath $Path -PathType Leaf) { Get-MSIXPackageLayout -Path $Path } else { $null }
    if ($Layout) { foreach ($Warning in $Layout.Warnings) { $Warnings.Add($Warning) } }

    # Extension and content type distinguish AppX from MSIX when available. Their physical OPC
    # structures are otherwise equivalent, so content alone can prove only package/bundle.
    $PathForExtension = if ([uri]::IsWellFormedUriString($Path, [System.UriKind]::Absolute)) { ([uri]$Path).AbsolutePath } else { $Path }
    $Extension = [System.IO.Path]::GetExtension($PathForExtension).ToLowerInvariant()
    $ExtensionInstallerType = switch ($Extension) {
      { $_ -in @('.appx', '.appxbundle') } { 'appx'; break }
      { $_ -in @('.msix', '.msixbundle') } { 'msix'; break }
    }
    $ExtensionPackageKind = switch ($Extension) {
      { $_ -in @('.appxbundle', '.msixbundle') } { 'Bundle'; break }
      { $_ -in @('.appx', '.msix') } { 'Package'; break }
    }

    $NormalizedContentType = if ([string]::IsNullOrWhiteSpace($ContentType)) { '' } else { $ContentType.Split(';', 2)[0].Trim().ToLowerInvariant() }
    $ContentTypeInstallerType = switch ($NormalizedContentType) {
      { $_ -in @('application/vnd.ms-appx', 'application/vnd.ms-appx.bundle', 'application/vns.ms-appx') } { 'appx'; break }
      { $_ -in @('application/msix', 'application/msixbundle') } { 'msix'; break }
    }
    $ContentTypePackageKind = switch ($NormalizedContentType) {
      { $_ -in @('application/vnd.ms-appx.bundle', 'application/msixbundle') } { 'Bundle'; break }
      { $_ -in @('application/vnd.ms-appx', 'application/msix') } { 'Package'; break }
    }

    $InstallerType = $null
    $Evidence = $null
    $IsAmbiguous = $false
    # Prefer the authored URL/path extension, then a manifest hint, HTTP type, and finally bundle
    # member names. Direct ambiguous packages use WinGet's compatible msix path with a warning.
    if ($ExtensionInstallerType) {
      $InstallerType = $ExtensionInstallerType
      $Evidence = 'PathExtension'
    } elseif (-not [string]::IsNullOrWhiteSpace($InstallerTypeHint)) {
      $InstallerType = $InstallerTypeHint
      $Evidence = 'InstallerTypeHint'
    } elseif ($ContentTypeInstallerType) {
      $InstallerType = $ContentTypeInstallerType
      $Evidence = 'HttpContentType'
    } elseif ($Layout -and $Layout.PackageKind -eq 'Bundle' -and $Layout.BundlePayloadTypes.Count -eq 1) {
      $InstallerType = $Layout.BundlePayloadTypes[0]
      $Evidence = 'BundlePayloadFileName'
    } elseif ($Layout) {
      # AppX and MSIX direct packages share the same package structures and WinGet execution path.
      $InstallerType = 'msix'
      $Evidence = 'WinGetCompatibleFallback'
      $IsAmbiguous = $true
      $Warnings.Add('The archive is an AppX/MSIX package, but AppX and MSIX cannot be distinguished from package content alone. Using the WinGet-compatible msix fallback.')
    } else {
      throw "Unsupported AppX/MSIX installer extension: $Extension. Supply a local package, InstallerTypeHint, or ContentType."
    }

    if ($Layout -and $ExtensionPackageKind -and $Layout.PackageKind -ne $ExtensionPackageKind) {
      $Warnings.Add("The extension indicates an AppX/MSIX $ExtensionPackageKind, but package content identifies a $($Layout.PackageKind).")
    }
    if ($Layout -and $ContentTypePackageKind -and $Layout.PackageKind -ne $ContentTypePackageKind) {
      $Warnings.Add("The HTTP content type indicates an AppX/MSIX $ContentTypePackageKind, but package content identifies a $($Layout.PackageKind).")
    }
    if ($ExtensionInstallerType -and $InstallerTypeHint -and $ExtensionInstallerType -ne $InstallerTypeHint) {
      $Warnings.Add("The path extension indicates installer type '$ExtensionInstallerType', but the supplied hint is '$InstallerTypeHint'. The path extension was preferred.")
    }

    [pscustomobject]@{
      InstallerType   = $InstallerType
      PackageKind     = $Layout ? $Layout.PackageKind : ($ExtensionPackageKind ?? $ContentTypePackageKind)
      Evidence        = $Evidence
      IsAmbiguous     = $IsAmbiguous
      ContentEvidence = $Layout
      Warnings        = @($Warnings | Select-Object -Unique)
    }
  }
}

function Get-MSIXInstallerType {
  <#
  .SYNOPSIS
    Get the WinGet installer type from AppX/MSIX package evidence
  .PARAMETER Path
    The package path or URI
  .PARAMETER InstallerTypeHint
    The known WinGet installer type when the local package path has no meaningful extension
  .PARAMETER ContentType
    The package HTTP Content-Type value
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The package path or URI')]
    [string]$Path,

    [Parameter(HelpMessage = 'The known WinGet installer type')]
    [ValidateSet('appx', 'msix')]
    [string]$InstallerTypeHint,

    [Parameter(HelpMessage = 'The package HTTP Content-Type value')]
    [string]$ContentType
  )

  process { (Get-MSIXPackageTypeInfo -Path $Path -InstallerTypeHint $InstallerTypeHint -ContentType $ContentType).InstallerType }
}

function Get-MSIXManifest {
  <#
  .SYNOPSIS
    Read the MSIX/AppX package manifest
  .PARAMETER Path
    The path to the MSIX/AppX package
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the MSIX/AppX package')]
    [string]$Path
  )

  process {
    $ZipFile = Get-MSIXZipArchive -Path $Path

    try {
      $ManifestText = (Read-MSIXZipEntryText -Archive $ZipFile -Name 'AppxManifest.xml') ?? (Read-MSIXZipEntryText -Archive $ZipFile -Name 'AppxMetadata/AppxBundleManifest.xml')
      if (-not $ManifestText) { throw 'The AppxManifest.xml or AppxBundleManifest.xml file does not exist in the package' }
      Write-Output -InputObject $ManifestText
    } finally {
      $ZipFile.Dispose()
    }
  }
}

function Get-MSIXPublisherHash {
  <#
  .SYNOPSIS
    Calculate the hash part of the MSIX package family name
  .PARAMETER PublisherName
    The publisher name
  .LINK
    https://marcinotorowski.com/2021/12/19/calculating-hash-part-of-msix-package-family-name
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The publisher name')]
    [ValidateNotNullOrEmpty()]
    [string]$PublisherName
  )

  begin {
    $EncodingTable = '0123456789abcdefghjkmnpqrstvwxyz'
  }

  process {
    # Package family names encode the first 64 SHA-256 bits of the UTF-16 publisher using Microsoft's
    # 32-character alphabet; the padded 65th bit completes thirteen groups.
    $PublisherNameSha256 = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::Unicode.GetBytes($PublisherName))
    $PublisherNameSha256First8Binary = $PublisherNameSha256[0..7] | ForEach-Object { [System.Convert]::ToString($_, 2).PadLeft(8, '0') }
    $PublisherNameSha256Fisrt8BinaryPadded = [System.String]::Concat($PublisherNameSha256First8Binary).PadRight(65, '0')

    $Result = for ($i = 0; $i -lt $PublisherNameSha256Fisrt8BinaryPadded.Length; $i += 5) {
      $EncodingTable[[System.Convert]::ToInt32($PublisherNameSha256Fisrt8BinaryPadded.Substring($i, 5), 2)]
    }

    return [System.String]::Concat($Result)
  }
}

function Read-FamilyNameFromMSIX {
  <#
  .SYNOPSIS
    Read the family name of the MSIX/AppX package
  .PARAMETER Path
    The path to the MSIX/AppX package
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the MSIX/AppX package')]
    [string]$Path
  )

  process {
    (Get-MSIXInfo -Path $Path).PackageFamilyName
  }
}

function Read-ProductVersionFromMSIX {
  <#
  .SYNOPSIS
    Read the product version of the MSIX/AppX package
  .PARAMETER Path
    The path to the MSIX/AppX package
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the MSIX/AppX package')]
    [string]$Path
  )

  process {
    (Get-MSIXInfo -Path $Path).Version
  }
}

function Get-MSIXSignatureHash {
  <#
  .SYNOPSIS
    Calculate the hash of the MSIX/AppX package signature
  .PARAMETER Path
    The path to the MSIX/AppX package
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the MSIX/AppX package')]
    [string]$Path
  )

  process {
    $ZipFile = Get-MSIXZipArchive -Path $Path

    try {
      $SignatureEntry = $ZipFile.GetEntry('AppxSignature.p7x')
      if (-not $SignatureEntry) { throw 'The AppxSignature.p7x file does not exist in the package' }

      $SignatureStream = $SignatureEntry.Open()
      try {
        Write-Output -InputObject ([System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::HashData($SignatureStream)) -replace '-', '')
      } finally {
        $SignatureStream.Dispose()
      }
    } finally {
      $ZipFile.Dispose()
    }
  }
}

# Keep the manifest-field name available without duplicating the implementation.
Set-Alias -Name 'Read-SignatureSha256FromMSIX' -Value 'Get-MSIXSignatureHash'


function Test-MSIXAllowedDependencyPackage {
  <#
  .SYNOPSIS
    Test whether an MSIX/AppX dependency package should be written to a WinGet manifest
  .PARAMETER PackageIdentifier
    The dependency package identity name
  #>
  [OutputType([bool])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The dependency package identity name')]
    [string]$PackageIdentifier
  )

  process {
    foreach ($Pattern in $Script:MSIXAllowedDependencyPackagePatterns) {
      if ($PackageIdentifier -clike $Pattern) { return $true }
    }

    return $false
  }
}

function Compare-MSIXDependencyMinimumVersion {
  <#
  .SYNOPSIS
    Compare two MSIX framework dependency minimum-version strings.
  .PARAMETER Left
    First version string. A missing value sorts before a present value.
  .PARAMETER Right
    Second version string. Valid System.Version values use numeric ordering; malformed values use ordinal ordering.
  #>
  param (
    [Parameter()]
    [string]$Left,

    [Parameter()]
    [string]$Right
  )

  if ([string]::IsNullOrWhiteSpace($Left)) { return -1 }
  if ([string]::IsNullOrWhiteSpace($Right)) { return 1 }

  try {
    return ([version]$Left).CompareTo([version]$Right)
  } catch {
    return [string]::CompareOrdinal($Left, $Right)
  }
}

function ConvertTo-MSIXManifestDependencyInfo {
  <#
  .SYNOPSIS
    Filter MSIX/AppX package dependencies for WinGet manifest authoring
  .DESCRIPTION
    Include only framework dependencies accepted by the Dumplings MSIX/AppX workflow, and report unknown dependencies as warnings for manual review.
  .PARAMETER PackageDependencies
    Raw dependency entries read from AppxManifest.xml files
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, Mandatory, HelpMessage = 'Raw dependency entries read from AppxManifest.xml files')]
    [AllowEmptyCollection()]
    [psobject[]]$PackageDependencies
  )

  $AllowedById = [ordered]@{}
  $UnknownById = [ordered]@{}

  # Keep only the framework package families accepted by the authoring workflow. Unknown identities
  # remain explicit warnings rather than silently becoming manifest dependencies.
  foreach ($Dependency in $PackageDependencies) {
    if ([string]::IsNullOrWhiteSpace($Dependency.PackageIdentifier)) { continue }

    $PackageIdentifier = [string]$Dependency.PackageIdentifier
    $MinimumVersion = [string]$Dependency.MinimumVersion
    $Publisher = [string]$Dependency.Publisher
    $Target = (Test-MSIXAllowedDependencyPackage -PackageIdentifier $PackageIdentifier) ? $AllowedById : $UnknownById

    if (-not $Target.Contains($PackageIdentifier)) {
      $Target[$PackageIdentifier] = [pscustomobject]@{
        PackageIdentifier = $PackageIdentifier
        MinimumVersion    = $MinimumVersion
        Publisher         = $Publisher
      }
      continue
    }

    # Preserve the highest minimum version when bundles contain duplicate dependency entries.
    if ((Compare-MSIXDependencyMinimumVersion -Left $MinimumVersion -Right $Target[$PackageIdentifier].MinimumVersion) -gt 0) {
      $Target[$PackageIdentifier].MinimumVersion = $MinimumVersion
    }
    if ([string]::IsNullOrWhiteSpace($Target[$PackageIdentifier].Publisher) -and -not [string]::IsNullOrWhiteSpace($Publisher)) {
      $Target[$PackageIdentifier].Publisher = $Publisher
    }
  }

  $Allowed = @($AllowedById.Values | Sort-Object -Property PackageIdentifier | ForEach-Object -Process {
      $Entry = [ordered]@{
        PackageIdentifier = $_.PackageIdentifier
      }
      if (-not [string]::IsNullOrWhiteSpace($_.MinimumVersion)) { $Entry.MinimumVersion = $_.MinimumVersion }
      [pscustomobject]$Entry
    })

  $Unknown = @($UnknownById.Values | Sort-Object -Property PackageIdentifier)
  $Warnings = @($Unknown | ForEach-Object -Process {
      "Unknown MSIX/AppX package dependency '$($_.PackageIdentifier)' was found and was not included in manifest Dependencies."
    })

  [pscustomobject]@{
    Dependencies               = [pscustomobject]@{
      PackageDependencies = $Allowed
    }
    UnknownPackageDependencies = $Unknown
    Warnings                   = $Warnings
  }
}

function ConvertTo-MSIXManifestAssociationInfo {
  <#
  .SYNOPSIS
    Extract protocol and file-extension declarations from AppX/MSIX manifests
  .PARAMETER Manifest
    Parsed context or metadata object produced by the corresponding format reader.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][xml[]]$Manifest)

  $Protocols = [System.Collections.Generic.List[object]]::new()
  $FileExtensions = [System.Collections.Generic.List[object]]::new()
  $Warnings = [System.Collections.Generic.List[string]]::new()
  $SeenProtocols = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $SeenExtensions = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

  # Namespace prefixes vary across manifest schema revisions, so classify extension declarations by
  # LocalName and Category instead of hard-coding one XML namespace.
  foreach ($Item in $Manifest) {
    foreach ($Extension in @($Item.GetElementsByTagName('*') | Where-Object { $_.LocalName -eq 'Extension' })) {
      $Category = [string]$Extension.GetAttribute('Category')
      if ($Category -eq 'windows.protocol') {
        foreach ($ProtocolNode in @($Extension.SelectNodes('.//*[local-name()="Protocol"]'))) {
          $Name = [string]$ProtocolNode.GetAttribute('Name')
          if ($Name -notmatch '^[A-Za-z][A-Za-z0-9+.-]{0,254}$') {
            if (-not [string]::IsNullOrWhiteSpace($Name)) { $Warnings.Add("Ignored non-literal MSIX protocol '$Name'.") }
            continue
          }
          if (-not $SeenProtocols.Add($Name)) { continue }
          $Protocols.Add([pscustomobject]@{
              Protocol    = $Name.ToLowerInvariant()
              Executable  = if ($Extension.HasAttribute('Executable')) { [string]$Extension.GetAttribute('Executable') } else { $null }
              EntryPoint  = if ($Extension.HasAttribute('EntryPoint')) { [string]$Extension.GetAttribute('EntryPoint') } else { $null }
              Source      = 'AppxManifest.xml windows.protocol extension'
              Declaration = $ProtocolNode.OuterXml
            })
        }
      } elseif ($Category -eq 'windows.fileTypeAssociation') {
        foreach ($AssociationNode in @($Extension.SelectNodes('.//*[local-name()="FileTypeAssociation"]'))) {
          $AssociationName = [string]$AssociationNode.GetAttribute('Name')
          foreach ($FileTypeNode in @($AssociationNode.SelectNodes('.//*[local-name()="FileType"]'))) {
            $ExtensionValue = ([string]$FileTypeNode.InnerText).Trim()
            if ($ExtensionValue -notmatch '^\.[A-Za-z0-9][A-Za-z0-9._+-]{0,254}$') {
              if (-not [string]::IsNullOrWhiteSpace($ExtensionValue)) { $Warnings.Add("Ignored non-literal MSIX file extension '$ExtensionValue'.") }
              continue
            }
            if (-not $SeenExtensions.Add($ExtensionValue)) { continue }
            $FileExtensions.Add([pscustomobject]@{
                FileExtension   = $ExtensionValue.TrimStart('.').ToLowerInvariant()
                Extension       = $ExtensionValue.ToLowerInvariant()
                AssociationName = $AssociationName
                Executable      = if ($Extension.HasAttribute('Executable')) { [string]$Extension.GetAttribute('Executable') } else { $null }
                EntryPoint      = if ($Extension.HasAttribute('EntryPoint')) { [string]$Extension.GetAttribute('EntryPoint') } else { $null }
                Source          = 'AppxManifest.xml windows.fileTypeAssociation extension'
                Declaration     = $AssociationNode.OuterXml
              })
          }
        }
      }
    }
  }

  [pscustomobject]@{
    Protocols                 = @($Protocols | Select-Object -ExpandProperty Protocol -Unique | Sort-Object)
    FileExtensions            = @($FileExtensions | Select-Object -ExpandProperty FileExtension -Unique | Sort-Object)
    ProtocolAssociations      = @($Protocols)
    FileExtensionAssociations = @($FileExtensions)
    Warnings                  = @($Warnings | Select-Object -Unique)
  }
}

function Get-MSIXAssociationInfo {
  <#
  .SYNOPSIS
    Read declared protocol and file-extension associations from an MSIX/AppX package
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { ConvertTo-MSIXManifestAssociationInfo -Manifest @(Get-MSIXManifestXmlList -Path $Path) }
}


function Get-MSIXInfo {
  <#
  .SYNOPSIS
    Read WinGet manifest metadata from an MSIX/AppX package
  .PARAMETER Path
    The path to the MSIX/AppX package
  .PARAMETER InstallerTypeHint
    The known WinGet installer type when the local package path has no meaningful extension
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the MSIX/AppX package')]
    [string]$Path,

    [Parameter(HelpMessage = 'The known WinGet installer type')]
    [ValidateSet('appx', 'msix')]
    [string]$InstallerTypeHint
  )

  process {
    $File = Get-Item -Path $Path -Force
    $PackageTypeInfo = Get-MSIXPackageTypeInfo -Path $File.FullName -InstallerTypeHint $InstallerTypeHint
    $Manifests = @(Get-MSIXManifestXmlList -Path $File.FullName)
    if ($Manifests.Count -eq 0) { throw 'No AppX/MSIX manifest could be read from the package' }

    # The first complete package identity supplies family-name fields; all manifests still
    # contribute platform, dependency, capability, and association evidence.
    $Identity = $Manifests | ForEach-Object { $_.GetElementsByTagName('Identity')[0] } | Where-Object { $_ -and $_.Name -and $_.Publisher } | Select-Object -First 1
    if (-not $Identity) { throw 'No package identity could be read from the AppX/MSIX manifest' }

    $TargetDeviceFamilies = foreach ($Manifest in $Manifests) {
      foreach ($Element in $Manifest.GetElementsByTagName('TargetDeviceFamily')) {
        [pscustomobject]@{
          Name       = [string]$Element.Name
          MinVersion = [string]$Element.MinVersion
        }
      }
    }

    $PackageDependencies = foreach ($Manifest in $Manifests) {
      foreach ($Element in $Manifest.GetElementsByTagName('PackageDependency')) {
        [pscustomobject]@{
          PackageIdentifier = [string]$Element.Name
          MinimumVersion    = [string]$Element.MinVersion
          Publisher         = [string]$Element.Publisher
        }
      }
    }
    $DependencyInfo = ConvertTo-MSIXManifestDependencyInfo -PackageDependencies @($PackageDependencies)
    $AssociationInfo = ConvertTo-MSIXManifestAssociationInfo -Manifest $Manifests

    # Separate restricted capabilities by the rescap prefix while retaining ordinary and device
    # capabilities in the normal manifest field.
    $Capabilities = foreach ($Manifest in $Manifests) {
      foreach ($Element in $Manifest.GetElementsByTagName('*')) {
        if ($Element.LocalName -notin @('Capability', 'DeviceCapability')) { continue }
        if ($Element.Prefix -eq 'rescap') { continue }
        if (-not [string]::IsNullOrWhiteSpace($Element.Name)) { [string]$Element.Name }
      }
    }

    $RestrictedCapabilities = foreach ($Manifest in $Manifests) {
      foreach ($Element in $Manifest.GetElementsByTagName('*')) {
        if ($Element.LocalName -ne 'Capability' -or $Element.Prefix -ne 'rescap') { continue }
        if (-not [string]::IsNullOrWhiteSpace($Element.Name)) { [string]$Element.Name }
      }
    }

    $DisplayName = ($Manifests | ForEach-Object { $_.GetElementsByTagName('DisplayName')[0] } | Where-Object { $_ } | Select-Object -First 1).'#text'
    $PublisherDisplayName = ($Manifests | ForEach-Object { $_.GetElementsByTagName('PublisherDisplayName')[0] } | Where-Object { $_ } | Select-Object -First 1).'#text'
    $MinimumOSVersion = ($TargetDeviceFamilies | Where-Object { -not [string]::IsNullOrWhiteSpace($_.MinVersion) } | Sort-Object -Property { [System.Version]$_.MinVersion } | Select-Object -First 1).MinVersion

    # Package identity and registration are defined by AppxManifest.xml rather
    # than an uninstall registry key. Keep ProductCode null and expose PFN as
    # its own structured identity field.
    [pscustomobject][ordered]@{
      Path                         = $File.FullName
      InstallerType                = $PackageTypeInfo.InstallerType
      ProductCode                  = $null
      UpgradeCode                  = $null
      DisplayName                  = [string]$DisplayName
      DisplayVersion               = [string]$Identity.Version
      Publisher                    = [string]$PublisherDisplayName
      Scope                        = $null
      DefaultInstallLocation       = $null
      WritesAppsAndFeaturesEntry   = $true
      AppsAndFeaturesProductCode   = $null
      AppsAndFeaturesInstallerType = $PackageTypeInfo.InstallerType.ToLowerInvariant()
      Warnings                     = [string[]]@($PackageTypeInfo.Warnings + $DependencyInfo.Warnings + $AssociationInfo.Warnings | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
      UnresolvedFields             = [string[]]@()
      PackageKind                  = $PackageTypeInfo.PackageKind
      InstallerTypeEvidence        = $PackageTypeInfo.Evidence
      InstallerTypeAmbiguous       = $PackageTypeInfo.IsAmbiguous
      IdentityName                 = [string]$Identity.Name
      Name                         = [string]$Identity.Name
      IdentityPublisher            = [string]$Identity.Publisher
      IdentityVersion              = [string]$Identity.Version
      Version                      = [string]$Identity.Version
      Architecture                 = [string]$Identity.ProcessorArchitecture
      PublisherDisplayName         = [string]$PublisherDisplayName
      PackageFamilyName            = "$($Identity.Name)_$(Get-MSIXPublisherHash -PublisherName $Identity.Publisher)"
      Platform                     = @($TargetDeviceFamilies | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Name) } | Select-Object -ExpandProperty Name -Unique)
      MinimumOSVersion             = $MinimumOSVersion
      Dependencies                 = $DependencyInfo.Dependencies
      UnknownPackageDependencies   = $DependencyInfo.UnknownPackageDependencies
      Protocols                    = $AssociationInfo.Protocols
      FileExtensions               = $AssociationInfo.FileExtensions
      RegistryAssociationInfo      = $AssociationInfo
      Capabilities                 = @($Capabilities | Sort-Object -Unique)
      RestrictedCapabilities       = @($RestrictedCapabilities | Sort-Object -Unique)
      SignatureSha256              = Read-SignatureSha256FromMSIX -Path $File.FullName
      AppsAndFeaturesEntries       = @([pscustomobject]@{
          DisplayName    = [string]$DisplayName
          Publisher      = [string]$PublisherDisplayName
          DisplayVersion = [string]$Identity.Version
        })
    }
  }
}

function Read-ProtocolsFromMSIX {
  <#
  .SYNOPSIS
    Read declared URL protocol names from an MSIX/AppX package
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-MSIXAssociationInfo -Path $Path).Protocols }
}

function Read-FileExtensionsFromMSIX {
  <#
  .SYNOPSIS
    Read declared file extensions from an MSIX/AppX package
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-MSIXAssociationInfo -Path $Path).FileExtensions }
}

function Read-PlatformFromMSIX {
  <#
  .SYNOPSIS
    Read Platform values from the MSIX/AppX package
  .PARAMETER Path
    The path to the MSIX/AppX package
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the MSIX/AppX package')]
    [string]$Path
  )

  process { (Get-MSIXInfo -Path $Path).Platform }
}

function Read-MinimumOSVersionFromMSIX {
  <#
  .SYNOPSIS
    Read the MinimumOSVersion value from the MSIX/AppX package
  .PARAMETER Path
    The path to the MSIX/AppX package
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the MSIX/AppX package')]
    [string]$Path
  )

  process { (Get-MSIXInfo -Path $Path).MinimumOSVersion }
}

function Read-DependenciesFromMSIX {
  <#
  .SYNOPSIS
    Read Dependencies values from the MSIX/AppX package
  .PARAMETER Path
    The path to the MSIX/AppX package
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the MSIX/AppX package')]
    [string]$Path
  )

  process { (Get-MSIXInfo -Path $Path).Dependencies }
}

function Read-CapabilitiesFromMSIX {
  <#
  .SYNOPSIS
    Read Capabilities values from the MSIX/AppX package
  .PARAMETER Path
    The path to the MSIX/AppX package
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the MSIX/AppX package')]
    [string]$Path
  )

  process { (Get-MSIXInfo -Path $Path).Capabilities }
}

function Read-RestrictedCapabilitiesFromMSIX {
  <#
  .SYNOPSIS
    Read RestrictedCapabilities values from the MSIX/AppX package
  .PARAMETER Path
    The path to the MSIX/AppX package
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the MSIX/AppX package')]
    [string]$Path
  )

  process { (Get-MSIXInfo -Path $Path).RestrictedCapabilities }
}

function Get-AppInstallerInfo {
  <#
  .SYNOPSIS
    Read the real AppX/MSIX package URL from an .appinstaller file
  .PARAMETER Uri
    The URI to the .appinstaller file
  .PARAMETER Path
    The path to the .appinstaller file
  .PARAMETER Content
    The .appinstaller XML content
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(ParameterSetName = 'Uri', Position = 0, Mandatory, HelpMessage = 'The URI to the .appinstaller file')]
    [uri]$Uri,

    [Parameter(ParameterSetName = 'Path', Position = 0, Mandatory, HelpMessage = 'The path to the .appinstaller file')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Content', Position = 0, Mandatory, ValueFromPipeline, HelpMessage = 'The .appinstaller XML content')]
    [string]$Content
  )

  process {
    # Preserve the document URI so relative MainPackage/MainBundle references can
    # be resolved exactly as an App Installer client would resolve them.
    $BaseUri = $null
    $XmlContent = switch ($PSCmdlet.ParameterSetName) {
      'Uri' {
        $BaseUri = $Uri
        $Response = Invoke-WebRequest -Uri $Uri
        # Prefer response bytes/stream over implicit string conversion so XML
        # encoding declarations and BOMs remain available to the XML parser.
        if ($Response.RawContentStream) {
          $Response.RawContentStream.Position = 0
          $Reader = [System.IO.StreamReader]::new($Response.RawContentStream)
          try {
            $Reader.ReadToEnd()
          } finally {
            $Reader.Dispose()
          }
        } elseif ($Response.Content -is [byte[]]) {
          [System.Text.Encoding]::UTF8.GetString($Response.Content)
        } else {
          [string]$Response.Content
        }
      }
      'Path' {
        $ContentPath = Get-Item -Path $Path -Force
        $BaseUri = [uri]$ContentPath.FullName
        Get-Content -Path $ContentPath.FullName -Raw
      }
      'Content' { $Content }
      default { throw 'Invalid parameter set.' }
    }

    # AppInstaller itself is not a WinGet-supported installer. It is a signed-
    # package locator, so require one explicit main package or bundle element.
    [xml]$Xml = $XmlContent
    $AppInstaller = $Xml.GetElementsByTagName('AppInstaller')[0]
    if (-not $AppInstaller) { throw 'The AppInstaller element does not exist in the .appinstaller file' }

    $MainElement = ($Xml.GetElementsByTagName('MainPackage') | Select-Object -First 1) ?? ($Xml.GetElementsByTagName('MainBundle') | Select-Object -First 1)
    if (-not $MainElement) { throw 'The .appinstaller file does not contain MainPackage or MainBundle' }

    # Resolve relative URIs against the source document; raw Content input has no
    # trustworthy base and therefore leaves the authored value unchanged.
    $InstallerUri = if ($BaseUri -and -not [uri]::IsWellFormedUriString($MainElement.Uri, [System.UriKind]::Absolute)) {
      [uri]::new($BaseUri, [string]$MainElement.Uri).AbsoluteUri
    } else {
      [string]$MainElement.Uri
    }

    [pscustomobject]@{
      Version       = [string]($AppInstaller.Version ?? $MainElement.Version)
      MainKind      = $MainElement.LocalName
      InstallerUrl  = $InstallerUri
      # Get-MSIXInstallerType may inspect content when the URL suffix is absent or
      # misleading, avoiding extension-only package classification.
      InstallerType = Get-MSIXInstallerType -Path $InstallerUri
      Name          = [string]$MainElement.Name
      Publisher     = [string]$MainElement.Publisher
      Architecture  = [string]$MainElement.ProcessorArchitecture
    }
  }
}

Export-ModuleMember -Function * -Alias Read-SignatureSha256FromMSIX
