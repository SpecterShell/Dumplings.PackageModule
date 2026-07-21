# SPDX-License-Identifier: Apache-2.0
# Forge- and storage-aware installer source identity normalization.
# Ported from winget-source-validator (crates/validator-core/src/domain.rs).

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }
# Force stop on error
$ErrorActionPreference = 'Stop'
# Force stop on undefined variables or properties
Set-StrictMode -Version 3

$KnownGenericS3CompatibleHostSuffixes = @(
  'arvanstorage.ir',
  'bizflycloud.vn',
  'cloud-object-storage.appdomain.cloud',
  'cubbit.eu',
  'dream.io',
  'filelu.com',
  'io.cloud.ovh.net',
  'linodeobjects.com',
  'liara.space',
  'lyvecloud.seagate.com',
  'qiniucs.com',
  'scw.cloud',
  'stackpathstorage.com',
  'storage.selcloud.ru',
  'storjshare.io',
  'wasabisys.com'
)

$KnownS3CompatibleProviderHints = @(
  'arvan',
  'bizfly',
  'cmecloud',
  'cubbit',
  'dream',
  'exaba',
  'filelu',
  'flashblade',
  'idrivee2',
  'intercolo',
  'ionos',
  'leviia',
  'liara',
  'linode',
  'lyvecloud',
  'magalu',
  'mega',
  'netease',
  'outscale',
  'ovh',
  'petabox',
  'qiniu',
  'rabata',
  'rackcorp',
  'scaleway',
  'scw',
  'selectel',
  'selcloud',
  'servercore',
  'spectra',
  'stackpath',
  'storj',
  'wasabi',
  'zata'
)

$S3CompatibleServiceHints = @('bucket', 'cos', 'e2', 'gateway', 'object', 'objects', 'obs', 'oss', 'r2', 's3', 'storage')

function Get-OwnerRepoIdentity {
  <#
  .SYNOPSIS
    Extract a host/owner/repo identity for hosts with a two-segment repository model
  .PARAMETER Host
    The lowercased host name
  .PARAMETER Segments
    The parsed path segments
  .PARAMETER StopMarkers
    Segments that terminate repository identity parsing
  #>
  [OutputType([string])]
  param ([string]$HostName, [string[]]$Segments, [string[]]$StopMarkers)

  if ($Segments.Count -lt 2) { return $HostName }
  $Repo = $null
  foreach ($Segment in $Segments[1..($Segments.Count - 1)]) {
    if ($Segment -cin $StopMarkers) { break }
    $Repo = $Segment
    break
  }
  return "${HostName}/$($Segments[0])/$($Repo ?? $Segments[1])"
}

function Get-NamespaceIdentity {
  <#
  .SYNOPSIS
    Extract a host/namespace/project identity for forge-like hosts with nested namespaces
  .PARAMETER Host
    The lowercased host name
  .PARAMETER Segments
    The parsed path segments
  .PARAMETER StopMarkers
    Segments that terminate project identity parsing
  #>
  [OutputType([string])]
  param ([string]$HostName, [string[]]$Segments, [string[]]$StopMarkers)

  $Namespace = [System.Collections.Generic.List[string]]::new()
  foreach ($Segment in $Segments) {
    if ($Segment -cin $StopMarkers) { break }
    $Namespace.Add($Segment)
  }
  if ($Namespace.Count -eq 0) { return $HostName }
  return "${HostName}/$($Namespace -join '/')"
}

function Get-SourceForgeIdentity {
  <#
  .SYNOPSIS
    Extract the SourceForge project identity from a download URL
  .PARAMETER Host
    The lowercased host name
  .PARAMETER Segments
    The parsed path segments
  #>
  [OutputType([string])]
  param ([string]$HostName, [string[]]$Segments)

  if ($Segments.Count -ge 2 -and $Segments[0] -ceq 'projects') { return "${HostName}/projects/$($Segments[1])" }
  if ($Segments.Count -ge 2 -and $Segments[0] -ceq 'project') { return "${HostName}/project/$($Segments[1])" }
  return $HostName
}

function Test-S3PathStyleHost {
  # Whether the host is an S3-compatible path-style endpoint, e.g. s3.amazonaws.com
  [OutputType([bool])]
  param ([string]$HostName)

  return $HostName -cin @('s3.amazonaws.com', 'storage.googleapis.com') -or $HostName.StartsWith('s3.') -or $HostName.StartsWith('s3-')
}

function Test-S3VirtualHostedHost {
  # Whether the host is an S3-compatible virtual-hosted endpoint, e.g. example-bucket.s3.amazonaws.com
  [OutputType([bool])]
  param ([string]$HostName)

  $Parts = $HostName.Split('.')
  if ($Parts.Count -lt 4) { return $false }

  return ($Parts[1] -ceq 's3' -and $Parts[2] -ceq 'amazonaws' -and $Parts[3] -ceq 'com') -or
  ($Parts[1] -ceq 's3' -and $Parts[2] -ceq 'dualstack') -or
  ($Parts[1].StartsWith('s3-') -and $Parts[2] -ceq 'amazonaws' -and $Parts[3] -ceq 'com')
}

function Get-S3PathStyleIdentity {
  # Extract host/bucket/<bucket> for S3-style path endpoints
  [OutputType([string])]
  param ([string]$HostName, [string[]]$Segments)

  if ($Segments.Count -eq 0) { return $null }
  return "${HostName}/bucket/$($Segments[0])"
}

function Get-S3VirtualHostedIdentity {
  # Extract storage-root/bucket/<bucket> for S3 virtual-hosted endpoints
  [OutputType([string])]
  param ([string]$HostName)

  $Parts = $HostName.Split('.')
  if ($Parts.Count -lt 4) { return $HostName }
  return "$($Parts[1..($Parts.Count - 1)] -join '.')/bucket/$($Parts[0])"
}

function Test-AlibabaOssPathStyleHost {
  # Whether the host is an Alibaba Cloud OSS path-style endpoint
  [OutputType([bool])]
  param ([string]$HostName)

  $Parts = $HostName.Split('.')
  return $HostName -ceq 'oss.aliyuncs.com' -or
  ($HostName.StartsWith('oss-') -and $HostName.EndsWith('.aliyuncs.com')) -or
  ($HostName.StartsWith('s3.oss-') -and $HostName.EndsWith('.aliyuncs.com')) -or
  ($Parts.Count -eq 4 -and $Parts[1] -ceq 'oss' -and $Parts[2] -ceq 'aliyuncs' -and $Parts[3] -ceq 'com')
}

function Test-AlibabaOssVirtualHostedHost {
  # Whether the host is an Alibaba Cloud OSS virtual-hosted endpoint
  [OutputType([bool])]
  param ([string]$HostName)

  $Parts = $HostName.Split('.')
  return ($Parts.Count -ge 4 -and $Parts[1].StartsWith('oss-') -and $HostName.EndsWith('.aliyuncs.com')) -or
  ($Parts.Count -ge 5 -and $Parts[1] -ceq 's3' -and $Parts[2].StartsWith('oss-') -and $HostName.EndsWith('.aliyuncs.com')) -or
  ($Parts.Count -ge 5 -and $Parts[2] -ceq 'oss' -and $Parts[3] -ceq 'aliyuncs' -and $Parts[4] -ceq 'com')
}

function Test-TencentCosPathStyleHost {
  # Whether the host is a Tencent Cloud COS path-style endpoint
  [OutputType([bool])]
  param ([string]$HostName)

  return ($HostName.StartsWith('cos.') -and $HostName.EndsWith('.myqcloud.com')) -or
  ($HostName.StartsWith('cos.') -and $HostName.EndsWith('.tencentcos.cn'))
}

function Test-SuffixAfterBucket {
  # Whether the host has a bucket label followed by a known fixed-domain storage root
  [OutputType([bool])]
  param ([string]$HostName, [string]$Prefix, [string]$Suffix)

  $Parts = $HostName.Split('.')
  if ($Parts.Count -lt 4) { return $false }

  $StorageRoot = $Parts[1..($Parts.Count - 1)] -join '.'
  return $StorageRoot.StartsWith($Prefix) -and $StorageRoot.EndsWith($Suffix)
}

function Test-TencentCosVirtualHostedHost {
  # Whether the host is a Tencent Cloud COS virtual-hosted endpoint
  [OutputType([bool])]
  param ([string]$HostName)

  return (Test-SuffixAfterBucket -HostName $HostName -Prefix 'cos.' -Suffix '.myqcloud.com') -or
  (Test-SuffixAfterBucket -HostName $HostName -Prefix 'cos.' -Suffix '.tencentcos.cn')
}

function Test-HuaweiObsPathStyleHost {
  # Whether the host is a Huawei OBS path-style endpoint
  [OutputType([bool])]
  param ([string]$HostName)

  return $HostName.StartsWith('obs.') -and $HostName.EndsWith('.myhuaweicloud.com')
}

function Test-HuaweiObsVirtualHostedHost {
  # Whether the host is a Huawei OBS virtual-hosted endpoint
  [OutputType([bool])]
  param ([string]$HostName)

  return Test-SuffixAfterBucket -HostName $HostName -Prefix 'obs.' -Suffix '.myhuaweicloud.com'
}

function Test-GoogleCloudStorageHost {
  # Whether the host is a Google Cloud Storage endpoint with a fixed service domain
  [OutputType([bool])]
  param ([string]$HostName)

  return $HostName -ceq 'storage.googleapis.com' -or $HostName.EndsWith('.storage.googleapis.com')
}

function Get-GoogleCloudStorageIdentity {
  # Extract bucket-aware identities for Google Cloud Storage URLs
  [OutputType([string])]
  param ([string]$HostName, [string[]]$Segments)

  if ($HostName -ceq 'storage.googleapis.com') {
    if ($Segments.Count -eq 0) { return $HostName }
    return "${HostName}/bucket/$($Segments[0])"
  }

  $Bucket = $HostName -replace '\.storage\.googleapis\.com$', ''
  return "storage.googleapis.com/bucket/${Bucket}"
}

function Test-DigitalOceanSpacesHost {
  # Whether the host is a DigitalOcean Spaces endpoint
  [OutputType([bool])]
  param ([string]$HostName)

  return $HostName.EndsWith('.digitaloceanspaces.com')
}

function Get-DigitalOceanSpacesIdentity {
  # Extract bucket-aware identities for DigitalOcean Spaces URLs
  [OutputType([string])]
  param ([string]$HostName)

  $Parts = [System.Collections.Generic.List[string]]::new([string[]]$HostName.Split('.'))
  if ($Parts.Count -lt 3) { return $HostName }
  $Bucket = $Parts[0]
  $Parts.RemoveAt(0)
  return "$($Parts -join '.')/bucket/${Bucket}"
}

function Test-CloudflareR2Host {
  # Whether the URL targets a Cloudflare R2 fixed-domain endpoint
  [OutputType([bool])]
  param ([string]$HostName, [string[]]$Segments)

  return $HostName.EndsWith('.r2.cloudflarestorage.com') -and $Segments.Count -gt 0
}

function Get-CloudflareR2Identity {
  # Extract bucket-aware identities for Cloudflare R2 path-style endpoints
  [OutputType([string])]
  param ([string]$HostName, [string[]]$Segments)

  if ($Segments.Count -eq 0) { return $null }
  return "${HostName}/bucket/$($Segments[0])"
}

function Test-AzureBlobHost {
  # Whether the host is an Azure Blob Storage endpoint
  [OutputType([bool])]
  param ([string]$HostName)

  return $HostName.EndsWith('.blob.core.windows.net') -or
  $HostName.EndsWith('.blob.core.usgovcloudapi.net') -or
  $HostName.EndsWith('.blob.core.chinacloudapi.cn') -or
  $HostName.EndsWith('.blob.core.cloudapi.de') -or
  $HostName.Contains('.blob.storage.azure.net')
}

function Get-AzureBlobIdentity {
  # Extract host/container/<container> for Azure Blob Storage endpoints
  [OutputType([string])]
  param ([string]$HostName, [string[]]$Segments)

  $Container = $Segments.Count -gt 0 ? $Segments[0] : '$root'
  return "${HostName}/container/${Container}"
}

function Get-GenericS3VirtualHostedIdentity {
  # Extract storage-root/bucket/<bucket> for known public S3-compatible virtual hosts
  [OutputType([string])]
  param ([string]$HostName)

  foreach ($Suffix in $Script:KnownGenericS3CompatibleHostSuffixes) {
    $DottedSuffix = ".${Suffix}"
    if (-not $HostName.EndsWith($DottedSuffix)) { continue }
    $Prefix = $HostName.Substring(0, $HostName.Length - $DottedSuffix.Length)
    $SeparatorIndex = $Prefix.IndexOf('.')
    if ($SeparatorIndex -lt 0) { continue }
    $Bucket = $Prefix.Substring(0, $SeparatorIndex)
    $StorageRoot = "$($Prefix.Substring($SeparatorIndex + 1)).${Suffix}"
    return "${StorageRoot}/bucket/${Bucket}"
  }
  return $null
}

function Test-AnyStorageRootSuffix {
  # Whether the host matches one of the built-in storage-root suffixes
  [OutputType([bool])]
  param ([string]$HostName, [string[]]$Suffixes)

  foreach ($Suffix in $Suffixes) {
    if ($HostName -ceq $Suffix -or $HostName.EndsWith(".${Suffix}")) { return $true }
  }
  return $false
}

function Get-GenericS3PathStyleIdentity {
  # Extract host/bucket/<bucket> for known public S3-compatible path hosts
  [OutputType([string])]
  param ([string]$HostName, [string[]]$Segments)

  if (-not (Test-AnyStorageRootSuffix -HostName $HostName -Suffixes $Script:KnownGenericS3CompatibleHostSuffixes)) { return $null }
  if ($Segments.Count -eq 0) { return $null }
  return "${HostName}/bucket/$($Segments[0])"
}

function Test-S3CompatibleStorageHostLike {
  <#
  .SYNOPSIS
    Whether the host looks like a provider-branded S3-compatible storage endpoint
  .DESCRIPTION
    Low-confidence fallback for providers whose public S3 endpoints do not use
    one of the built-in fixed domain families. It intentionally requires both a
    provider hint and a storage-service hint to avoid classifying generic
    download sites too aggressively.
  #>
  [OutputType([bool])]
  param ([string]$HostName)

  $HasProviderHint = $false
  foreach ($Hint in $Script:KnownS3CompatibleProviderHints) {
    if ($HostName.Contains($Hint)) { $HasProviderHint = $true; break }
  }
  if (-not $HasProviderHint) { return $false }

  foreach ($Hint in $Script:S3CompatibleServiceHints) {
    if ($HostName.Contains($Hint)) { return $true }
  }
  return $false
}

function Get-HintedS3VirtualHostedIdentity {
  # Extract bucket-aware identities for provider-branded S3-compatible virtual hosts
  [OutputType([string])]
  param ([string]$HostName)

  if (-not (Test-S3CompatibleStorageHostLike -HostName $HostName)) { return $null }

  $SeparatorIndex = $HostName.IndexOf('.')
  if ($SeparatorIndex -lt 0) { return $null }
  $Bucket = $HostName.Substring(0, $SeparatorIndex)
  $StorageRoot = $HostName.Substring($SeparatorIndex + 1)
  if (-not (Test-S3CompatibleStorageHostLike -HostName $StorageRoot)) { return $null }

  return "${StorageRoot}/bucket/${Bucket}"
}

function Get-HintedS3PathStyleIdentity {
  # Extract bucket-aware identities for provider-branded S3-compatible path hosts
  [OutputType([string])]
  param ([string]$HostName, [string[]]$Segments)

  if (-not (Test-S3CompatibleStorageHostLike -HostName $HostName)) { return $null }
  if ($Segments.Count -eq 0) { return $null }
  return "${HostName}/bucket/$($Segments[0])"
}

function Get-InstallerSourceIdentity {
  <#
  .SYNOPSIS
    Normalize a download URL into a forge-aware source identity
  .DESCRIPTION
    Examples:
    - https://github.com/example/repo/releases/download/v1/app.exe -> github.com/example/repo
    - https://gitlab.example/group/subgroup/project/-/releases/v1/downloads/app.exe -> gitlab.example/group/subgroup/project
    - https://s3.amazonaws.com/example-bucket/releases/app.exe -> s3.amazonaws.com/bucket/example-bucket
    - https://example-1250000000.cos.ap-guangzhou.myqcloud.com/releases/app.exe -> cos.ap-guangzhou.myqcloud.com/bucket/example-1250000000
    - https://mystorage.blob.core.windows.net/mycontainer/releases/app.exe -> mystorage.blob.core.windows.net/container/mycontainer
  .PARAMETER Uri
    The installer URL to classify
  .OUTPUTS
    The normalized source identity, or $null when the URL cannot be parsed.
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The installer URL to classify')]
    [AllowNull()]
    [string]$Uri
  )

  process {
    if ([string]::IsNullOrWhiteSpace($Uri)) { return $null }

    $Parsed = $null
    try { $Parsed = [uri]::new($Uri) } catch { return $null }
    if ([string]::IsNullOrWhiteSpace($Parsed.Host)) { return $null }

    $HostName = $Parsed.Host.ToLowerInvariant()
    $Segments = [string[]]@($Parsed.AbsolutePath -split '/' | Where-Object { -not [string]::IsNullOrEmpty($_) })

    if ($HostName -cin @('github.com', 'raw.githubusercontent.com')) {
      return Get-OwnerRepoIdentity -HostName $HostName -Segments $Segments -StopMarkers @('releases', 'download', 'blob', 'raw')
    }

    if ($HostName.Contains('gitlab') -or $HostName.Contains('gitea') -or $HostName.Contains('codeberg') -or $HostName.Contains('gitcode') -or $HostName.Contains('gitee')) {
      return Get-NamespaceIdentity -HostName $HostName -Segments $Segments -StopMarkers @('-', 'releases', 'archive', 'downloads', 'blob', 'raw')
    }

    if ($HostName.Contains('bitbucket')) {
      return Get-OwnerRepoIdentity -HostName $HostName -Segments $Segments -StopMarkers @('downloads', 'src', 'raw')
    }

    if ($HostName.Contains('sourceforge')) {
      return Get-SourceForgeIdentity -HostName $HostName -Segments $Segments
    }

    if (Test-S3VirtualHostedHost -HostName $HostName) { return Get-S3VirtualHostedIdentity -HostName $HostName }
    if (Test-S3PathStyleHost -HostName $HostName) { return Get-S3PathStyleIdentity -HostName $HostName -Segments $Segments }
    if (Test-AlibabaOssVirtualHostedHost -HostName $HostName) { return Get-S3VirtualHostedIdentity -HostName $HostName }
    if (Test-AlibabaOssPathStyleHost -HostName $HostName) { return Get-S3PathStyleIdentity -HostName $HostName -Segments $Segments }
    if (Test-TencentCosVirtualHostedHost -HostName $HostName) { return Get-S3VirtualHostedIdentity -HostName $HostName }
    if (Test-TencentCosPathStyleHost -HostName $HostName) { return Get-S3PathStyleIdentity -HostName $HostName -Segments $Segments }
    if (Test-HuaweiObsVirtualHostedHost -HostName $HostName) { return Get-S3VirtualHostedIdentity -HostName $HostName }
    if (Test-HuaweiObsPathStyleHost -HostName $HostName) { return Get-S3PathStyleIdentity -HostName $HostName -Segments $Segments }
    if (Test-GoogleCloudStorageHost -HostName $HostName) { return Get-GoogleCloudStorageIdentity -HostName $HostName -Segments $Segments }
    if (Test-DigitalOceanSpacesHost -HostName $HostName) { return Get-DigitalOceanSpacesIdentity -HostName $HostName }
    if (Test-CloudflareR2Host -HostName $HostName -Segments $Segments) { return Get-CloudflareR2Identity -HostName $HostName -Segments $Segments }
    if (Test-AzureBlobHost -HostName $HostName) { return Get-AzureBlobIdentity -HostName $HostName -Segments $Segments }
    if ($Identity = Get-GenericS3VirtualHostedIdentity -HostName $HostName) { return $Identity }
    if ($Identity = Get-GenericS3PathStyleIdentity -HostName $HostName -Segments $Segments) { return $Identity }
    if ($Identity = Get-HintedS3VirtualHostedIdentity -HostName $HostName) { return $Identity }
    if ($Identity = Get-HintedS3PathStyleIdentity -HostName $HostName -Segments $Segments) { return $Identity }

    return $HostName
  }
}

Export-ModuleMember -Function Get-InstallerSourceIdentity
