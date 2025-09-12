# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# Force stop on error
$ErrorActionPreference = 'Stop'

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
    $ZipFile = [System.IO.Compression.ZipFile]::OpenRead((Get-Item -Path $Path -Force).FullName)

    $ManifestEntry = $ZipFile.GetEntry('AppxManifest.xml') ?? $ZipFile.GetEntry('AppxMetadata/AppxBundleManifest.xml')
    if (-not $ManifestEntry) { throw 'The AppxManifest.xml or AppxBundleManifest.xml file does not exist in the package' }

    $ManifestStream = $ManifestEntry.Open()
    $ManifestStreamReader = [System.IO.StreamReader]::new($ManifestStream)
    Write-Output -InputObject ($ManifestStreamReader.ReadToEnd())
    $ManifestStreamReader.Dispose()
    $ManifestStream.Dispose()

    $ZipFile.Dispose()
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
    $Manifest = Get-MSIXManifest @PSBoundParameters | ConvertFrom-Xml
    $Identity = $Manifest.GetElementsByTagName('Identity')[0]
    Write-Output -InputObject "$($Identity.Name)_$(Get-MSIXPublisherHash -PublisherName $Identity.Publisher)"
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
    $Manifest = Get-MSIXManifest @PSBoundParameters | ConvertFrom-Xml
    Write-Output -InputObject $Manifest.GetElementsByTagName('Identity')[0].Version
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
    $ZipFile = [System.IO.Compression.ZipFile]::OpenRead((Get-Item -Path $Path -Force).FullName)

    $SignatureEntry = $ZipFile.GetEntry('AppxSignature.p7x')
    if (-not $SignatureEntry) { throw 'The AppxSignature.p7x file does not exist in the package' }

    $SignatureStream = $SignatureEntry.Open()
    Write-Output -InputObject ([System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::HashData($SignatureStream)) -replace '-', '')
    $SignatureStream.Dispose()

    $ZipFile.Dispose()
  }
}
