# SPDX-License-Identifier: Apache-2.0
# Public InstallShield orchestration over container, Advanced UI, and InstallScript evidence.
# Release-map references:
# - https://stackoverflow.com/questions/29690042/find-installshield-version-used-for-creating-an-ism-file
# - https://zzz.buzz/notes/links-to-installshield-downloads-and-documentation/
# Structural route references:
# - https://github.com/jte/installscript-decompiler
# - https://hackmag.com/coding/installshield-reverse

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$InfrastructurePath = Join-Path $PSScriptRoot '..\Infrastructure'
foreach ($Name in 'Runtime', 'Binary', 'Archive', 'PE', 'InstallerEvidence', 'Cabinet') {
  Import-Module (Join-Path $InfrastructurePath "$Name.psm1") -Force -Global
}
Import-Module (Join-Path $PSScriptRoot 'MSI.psm1') -Force -Global
Import-Module (Join-Path $PSScriptRoot 'InstallShieldInstallScript.psm1') -Force -Global
Import-Module (Join-Path $PSScriptRoot 'InstallShieldContainer.psm1') -Force -Global
Import-Module (Join-Path $PSScriptRoot 'InstallShieldAdvancedUI.psm1') -Force -Global

$Script:InstallShieldReleaseCatalogPath = Join-Path $PSScriptRoot '..\..\Assets\InstallShieldReleases.psd1'
$Script:InstallShieldReleaseCatalog = $null

function Get-InstallShieldReleaseCatalog {
  <#
  .SYNOPSIS
    Load the data-backed InstallShield project-schema and product-release map.
  .OUTPUTS
    A read-only-by-convention dictionary with Schemas and Products maps.
  #>
  [OutputType([System.Collections.IDictionary])]
  param ()

  if ($null -eq $Script:InstallShieldReleaseCatalog) {
    $Script:InstallShieldReleaseCatalog = Import-PowerShellDataFile -LiteralPath $Script:InstallShieldReleaseCatalogPath
  }
  return $Script:InstallShieldReleaseCatalog
}

function ConvertTo-InstallShieldReleaseEvidence {
  <#
  .SYNOPSIS
    Create one normalized release-evidence record without changing parser dispatch.
  .PARAMETER Source
    Structured source that supplied the value, such as ProjectSchema, AdvancedUI,
    CabinetHeader, MsiSummary, RuntimePE, or ClassicMedia.
  .PARAMETER Value
    Raw source value retained for diagnostics.
  .PARAMETER Candidate
    Optional release-map candidate associated with the source value.
  .PARAMETER Confidence
    Confidence assigned to this evidence source.
  .PARAMETER Rank
    Resolver precedence. This affects release identity only, never structural routing.
  .PARAMETER Detail
    Human-readable explanation of the exact structure that supplied the value.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Source,
    [Parameter(Mandatory)]$Value,
    [AllowNull()][psobject]$Candidate,
    [Parameter(Mandatory)][string]$Confidence,
    [Parameter(Mandatory)][int]$Rank,
    [Parameter(Mandatory)][string]$Detail
  )

  [pscustomobject][ordered]@{
    Source         = $Source
    Value          = $Value
    ReleaseName    = $Candidate ? [string]$Candidate.Name : $null
    ProductVersion = $Candidate ? [string]$Candidate.ProductVersion : $null
    SchemaVersion  = $Source -eq 'ProjectSchema' ? [int]$Value : $null
    Year           = $Candidate -and $Candidate.Year ? [int]$Candidate.Year : $null
    ServicePack    = $null
    Build          = $null
    Confidence     = $Confidence
    Rank           = $Rank
    Detail         = $Detail
  }
}

function Get-InstallShieldSchemaReleaseCandidate {
  <#
  .SYNOPSIS
    Resolve all release candidates for one authored InstallShield SchemaVersion.
  .PARAMETER SchemaVersion
    Integer value from the InstallShield table of a structured .ism project.
  #>
  [OutputType([object[]])]
  param ([Parameter(Mandatory)][ValidateRange(1, [int]::MaxValue)][int]$SchemaVersion)

  $Catalog = Get-InstallShieldReleaseCatalog
  return [object[]]@($Catalog.Schemas[[string]$SchemaVersion])
}

function Get-InstallShieldProductReleaseCandidate {
  <#
  .SYNOPSIS
    Resolve release candidates for an InstallShield product/runtime major version.
  .PARAMETER ProductVersion
    Product or media version. Only its leading numeric major is used for lookup.
  #>
  [OutputType([object[]])]
  param ([Parameter(Mandatory)][string]$ProductVersion)

  $Match = [regex]::Match($ProductVersion, '^\s*(?<Major>\d+)')
  if (-not $Match.Success) { return [object[]]@() }
  $Catalog = Get-InstallShieldReleaseCatalog
  $Candidates = [object[]]@($Catalog.Products[$Match.Groups['Major'].Value])
  # A bare major from ISc( media cannot distinguish point releases. Exact PE
  # or MSI versions may select a source-backed candidate pattern.
  if ($ProductVersion.Trim() -notmatch '^\d+$') {
    $Exact = [object[]]@($Candidates | Where-Object {
        $_.VersionPattern -and $ProductVersion.Trim() -match [string]$_.VersionPattern
      })
    if ($Exact) { return $Exact }
  }
  return $Candidates
}

function Resolve-InstallShieldRelease {
  <#
  .SYNOPSIS
    Resolve release identity from independent structured evidence.
  .DESCRIPTION
    The highest-ranked consistent evidence supplies the selected identity. Other
    candidates remain visible. Conflicts lower confidence and emit a warning but
    never select or replace a structural parser route.
  .PARAMETER Evidence
    Normalized records produced by ConvertTo-InstallShieldReleaseEvidence.
  #>
  [OutputType([pscustomobject])]
  param ([AllowEmptyCollection()][object[]]$Evidence = @())

  $Evidence = [object[]]@($Evidence | Where-Object { $null -ne $_ })
  $Warnings = [Collections.Generic.List[string]]::new()
  $Candidates = [Collections.Generic.List[object]]::new()
  $CandidateKeys = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($Item in $Evidence) {
    if ([string]::IsNullOrWhiteSpace([string]$Item.ReleaseName)) { continue }
    $Key = "$( $Item.ReleaseName )|$( $Item.ProductVersion )|$( $Item.SchemaVersion )|$( $Item.Year )"
    if ($CandidateKeys.Add($Key)) {
      $Candidates.Add([pscustomobject][ordered]@{
          ReleaseName    = $Item.ReleaseName
          ProductVersion = $Item.ProductVersion
          SchemaVersion  = $Item.SchemaVersion
          Year           = $Item.Year
          Source         = $Item.Source
          Confidence     = $Item.Confidence
        })
    }
  }

  $MappedEvidence = [object[]]@($Evidence | Where-Object ReleaseName)
  # Several candidates emitted from one source value are alternatives, not a
  # conflict. Intersect independent source groups first; an exact trusted
  # runtime can therefore narrow a broad cabinet-major mapping.
  $EvidenceGroups = [object[]]@($MappedEvidence | Group-Object { "$($_.Source)|$($_.Value)|$($_.Rank)" })
  $CommonIdentityKeys = [string[]]@()
  foreach ($Group in $EvidenceGroups) {
    $GroupIdentityKeys = [string[]]@($Group.Group | ForEach-Object { "$($_.ProductVersion)|$($_.Year)" } | Sort-Object -Unique)
    if ($CommonIdentityKeys.Count -eq 0) {
      $CommonIdentityKeys = $GroupIdentityKeys
    } else {
      $CommonIdentityKeys = [string[]]@($CommonIdentityKeys | Where-Object { $GroupIdentityKeys -contains $_ })
    }
  }
  $HasConflict = $EvidenceGroups.Count -gt 1 -and $CommonIdentityKeys.Count -eq 0
  $EligibleEvidence = if (-not $HasConflict -and $CommonIdentityKeys.Count -gt 0) {
    [object[]]@($MappedEvidence | Where-Object { $CommonIdentityKeys -contains "$($_.ProductVersion)|$($_.Year)" })
  } else { $MappedEvidence }
  $HighestRank = ($EligibleEvidence | Measure-Object -Property Rank -Maximum).Maximum
  $TopEvidence = [object[]]@($EligibleEvidence | Where-Object Rank -EQ $HighestRank)
  $Selected = $TopEvidence | Select-Object -First 1
  $DistinctReleaseNames = [string[]]@($MappedEvidence.ReleaseName | Where-Object { $_ } | Sort-Object -Unique)
  $TopReleaseNames = [string[]]@($TopEvidence.ReleaseName | Where-Object { $_ } | Sort-Object -Unique)
  $TopIdentityKeys = [string[]]@($TopEvidence | ForEach-Object { "$($_.ProductVersion)|$($_.Year)" } | Sort-Object -Unique)
  $HasAmbiguity = -not $HasConflict -and ($TopReleaseNames.Count -gt 1 -or $TopIdentityKeys.Count -gt 1)
  if ($HasConflict) {
    $Warnings.Add("InstallShield release evidence disagrees: $($DistinctReleaseNames -join '; '). Structural routes remain authoritative for parser dispatch.")
  } elseif ($HasAmbiguity) {
    $Warnings.Add("InstallShield release evidence leaves multiple candidates: $($TopReleaseNames -join '; '). Preserve the candidate set unless stronger structured evidence is available.")
  }

  # A trusted runtime may carry a service-pack or build suffix while a stronger
  # schema/suite/catalog record supplies the release identity. Reuse only
  # compatible detail so conflicting release evidence cannot decorate the
  # selected release with an unrelated build number.
  $CompatibleEvidence = if ($Selected) {
    @($Evidence | Where-Object {
        $_.ProductVersion -eq $Selected.ProductVersion -and $_.Year -eq $Selected.Year
      } | Sort-Object Rank -Descending)
  } else { @() }
  $ServicePack = @($CompatibleEvidence.ServicePack | Where-Object { $_ }) | Select-Object -First 1
  $Build = @($CompatibleEvidence.Build | Where-Object { $_ }) | Select-Object -First 1
  $Confidence = if (-not $Selected) { 'Unknown' } elseif ($HasConflict) { 'Conflicting' } elseif ($HasAmbiguity) { 'Ambiguous' } else { [string]$Selected.Confidence }
  [pscustomobject][ordered]@{
    ReleaseName    = $Selected ? $Selected.ReleaseName : $null
    ProductVersion = $Selected ? $Selected.ProductVersion : $null
    SchemaVersion  = $Selected ? $Selected.SchemaVersion : $null
    Year           = $Selected ? $Selected.Year : $null
    ServicePack    = $ServicePack
    Build          = $Build
    Confidence     = $Confidence
    Candidates     = [object[]]$Candidates.ToArray()
    Evidence       = $Evidence
    Warnings       = [string[]]$Warnings.ToArray()
  }
}

function Get-InstallShieldProjectReleaseInfo {
  <#
  .SYNOPSIS
    Read SchemaVersion from a structured InstallShield .ism project.
  .DESCRIPTION
    Reads the InstallShield table from either an XML project export or the
    Windows Installer database form used by binary .ism projects. The function
    does not scan arbitrary installer strings and does not infer a schema from
    a shipped setup executable.
  .PARAMETER Path
    Path to an XML or Windows Installer database .ism project.
  .PARAMETER MaximumBytes
    Maximum project size accepted before XML or database parsing.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, Position = 0, ValueFromPipeline)][string]$Path,
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumBytes = 256MB
  )

  process {
    $ProjectPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
    $File = Get-Item -LiteralPath $ProjectPath -Force
    if ($File.Length -gt $MaximumBytes) { throw "The InstallShield project exceeds the $MaximumBytes-byte limit." }

    $InputStream = [IO.File]::Open($ProjectPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
      $Prefix = Read-BinaryBytes -Stream $InputStream -Offset 0 -Count ([Math]::Min(8, $InputStream.Length))
    } finally {
      $InputStream.Dispose()
    }

    $CompoundFileMagic = [byte[]](0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1)
    if ($Prefix.Length -eq $CompoundFileMagic.Length -and (Test-BinarySequence -Left $Prefix -Right $CompoundFileMagic)) {
      # Binary .ism projects are Windows Installer databases with authoring
      # tables that are not emitted into the built MSI. Query the exact row;
      # arbitrary CFB strings are not release evidence.
      try {
        $SchemaText = Read-MsiProperty -Path $ProjectPath -Query "SELECT ``Value`` FROM ``InstallShield`` WHERE ``Property``='SchemaVersion'"
      } catch {
        throw "The binary InstallShield project does not contain a readable InstallShield.SchemaVersion row: $($_.Exception.Message)"
      }
      $SourceFormat = 'WindowsInstallerDatabase'
    } else {
      $PrefixText = [Text.Encoding]::ASCII.GetString($Prefix).TrimStart()
      $HasUnicodeBom = $Prefix.Length -ge 2 -and (($Prefix[0] -eq 0xFF -and $Prefix[1] -eq 0xFE) -or ($Prefix[0] -eq 0xFE -and $Prefix[1] -eq 0xFF))
      $HasUtf8Bom = $Prefix.Length -ge 3 -and $Prefix[0] -eq 0xEF -and $Prefix[1] -eq 0xBB -and $Prefix[2] -eq 0xBF
      if (-not $PrefixText.StartsWith('<', [StringComparison]::Ordinal) -and -not $HasUnicodeBom -and -not $HasUtf8Bom) {
        $Magic = ($Prefix | ForEach-Object { $_.ToString('X2') }) -join ' '
        throw "The InstallShield project uses an unsupported structured representation (magic: $Magic); expected XML or a Windows Installer compound database."
      }
      $Settings = [Xml.XmlReaderSettings]::new()
      $Settings.DtdProcessing = [Xml.DtdProcessing]::Ignore
      $Settings.XmlResolver = $null
      $Reader = [Xml.XmlReader]::Create($ProjectPath, $Settings)
      try {
        $Document = [Xml.XmlDocument]::new()
        $Document.XmlResolver = $null
        $Document.Load($Reader)
      } finally {
        $Reader.Dispose()
      }
      if ($Document.DocumentElement.LocalName -ne 'msi') { throw 'The file is not a structured InstallShield XML project database.' }

      $SchemaRow = $Document.SelectSingleNode("/*[local-name()='msi']/*[local-name()='table' and @name='InstallShield']/*[local-name()='row'][*[local-name()='td'][1][normalize-space(.)='SchemaVersion']]")
      if (-not $SchemaRow -or $SchemaRow.SelectNodes("./*[local-name()='td']").Count -lt 2) {
        throw 'The InstallShield project does not contain InstallShield.SchemaVersion.'
      }
      $SchemaText = $SchemaRow.SelectNodes("./*[local-name()='td']")[1].InnerText.Trim()
      $SourceFormat = 'Xml'
    }

    $SchemaText = [string]$SchemaText
    $SchemaVersion = 0
    if (-not [int]::TryParse($SchemaText, [Globalization.NumberStyles]::None, [Globalization.CultureInfo]::InvariantCulture, [ref]$SchemaVersion)) {
      throw "The InstallShield project SchemaVersion '$SchemaText' is not an integer."
    }
    $Candidates = Get-InstallShieldSchemaReleaseCandidate -SchemaVersion $SchemaVersion
    $Evidence = foreach ($Candidate in $Candidates) {
      ConvertTo-InstallShieldReleaseEvidence -Source ProjectSchema -Value $SchemaVersion -Candidate $Candidate `
        -Confidence ([string]$Candidate.Confidence) -Rank 120 `
        -Detail "InstallShield table row SchemaVersion=$SchemaVersion in '$ProjectPath'"
    }
    if (-not $Evidence) {
      $Evidence = ConvertTo-InstallShieldReleaseEvidence -Source ProjectSchema -Value $SchemaVersion -Candidate $null `
        -Confidence UnknownSchema -Rank 120 -Detail "Unmapped InstallShield table row SchemaVersion=$SchemaVersion in '$ProjectPath'"
    }
    $Release = Resolve-InstallShieldRelease -Evidence $Evidence
    # Preserve the exact structured value even when the release catalog has no
    # authoritative mapping for this schema revision.
    if ($null -eq $Release.SchemaVersion) { $Release.SchemaVersion = $SchemaVersion }
    $Release | Add-Member -NotePropertyName Path -NotePropertyValue $ProjectPath
    $Release | Add-Member -NotePropertyName SourceFormat -NotePropertyValue $SourceFormat
    return $Release
  }
}

function ConvertTo-InstallShieldStructuralRoute {
  <#
  .SYNOPSIS
    Create one physical-layer parser-route record.
  .PARAMETER RouteId
    Stable route identifier such as Cabinet6/AnsiCatalog.
  .PARAMETER Layer
    Physical layer: Wrapper, Overlay, Cabinet, Script, MSI, Suite, or Classic.
  .PARAMETER StructuralProfile
    Human-readable format profile selected from structural evidence.
  .PARAMETER FormatVersion
    Raw or normalized format version associated with the layer.
  .PARAMETER Handler
    Dumplings parser component responsible for the layer.
  .PARAMETER Capabilities
    Operations supported by the handler.
  .PARAMETER SupportStatus
    Supported, Partial, Unsupported, or Malformed.
  .PARAMETER Evidence
    Exact magic/header/catalog evidence selecting the route.
  .PARAMETER Limitations
    Known route-specific gaps that require another route or VM evidence.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$RouteId,
    [Parameter(Mandatory)][string]$Layer,
    [Parameter(Mandatory)][string]$StructuralProfile,
    [AllowNull()]$FormatVersion,
    [Parameter(Mandatory)][string]$Handler,
    [string[]]$Capabilities = @(),
    [ValidateSet('Supported', 'Partial', 'Unsupported', 'Malformed')][string]$SupportStatus = 'Supported',
    [object[]]$Evidence = @(),
    [string[]]$Limitations = @()
  )

  [pscustomobject][ordered]@{
    RouteId       = $RouteId
    Layer         = $Layer
    Profile       = $StructuralProfile
    FormatVersion = $FormatVersion
    Handler       = $Handler
    Capabilities  = [string[]]$Capabilities
    SupportStatus = $SupportStatus
    Evidence      = [object[]]$Evidence
    Limitations   = [string[]]$Limitations
  }
}

function Get-InstallShieldRuntimeReleaseEvidence {
  <#
  .SYNOPSIS
    Read trusted InstallShield launcher identity from PE version resources.
  .PARAMETER Path
    Resolved PE launcher path. Product-specific version resources are ignored.
  #>
  [OutputType([object[]])]
  param ([Parameter(Mandatory)][string]$Path)

  try { $VersionInfo = [Diagnostics.FileVersionInfo]::GetVersionInfo($Path) }
  catch { return [object[]]@() }
  # Copyright commonly identifies the licensed InstallShield runtime even when
  # ProductVersion belongs to the customer's application. Require one of the
  # version-bearing identity fields itself to name InstallShield.
  $Identity = @($VersionInfo.ProductName, $VersionInfo.FileDescription, $VersionInfo.CompanyName) -join ' | '
  if ($Identity -notmatch '(?i)\b(?:InstallShield|InstallScript|InstallShield Software|Macrovision|Flexera|Revenera)\b') {
    return [object[]]@()
  }

  $Version = @($VersionInfo.ProductVersion, $VersionInfo.FileVersion) | Where-Object { $_ -match '^\s*\d+' } | Select-Object -First 1
  if (-not $Version) { return [object[]]@() }
  $FileVersion = @($VersionInfo.FileVersion, $VersionInfo.ProductVersion) | Where-Object { $_ -match '^\s*\d+' } | Select-Object -First 1
  $Detail = "Trusted InstallShield PE identity: $Identity; ProductVersion='$($VersionInfo.ProductVersion)'; FileVersion='$($VersionInfo.FileVersion)'"
  $Candidates = Get-InstallShieldProductReleaseCandidate -ProductVersion $Version
  if (-not $Candidates) {
    return , (ConvertTo-InstallShieldReleaseEvidence -Source RuntimePE -Value $Version -Candidate $null -Confidence TrustedRuntimeVersion -Rank 50 `
        -Detail $Detail)
  }

  return [object[]]@($Candidates | ForEach-Object {
      $Item = ConvertTo-InstallShieldReleaseEvidence -Source RuntimePE -Value $Version -Candidate $_ -Confidence TrustedRuntimeVersion -Rank 50 `
        -Detail $Detail
      $ServicePackMatch = [regex]::Match("$Version $FileVersion", '(?i)\bSP\s*(?<ServicePack>\d+)')
      if ($ServicePackMatch.Success) { $Item.ServicePack = $ServicePackMatch.Groups['ServicePack'].Value }
      $Parts = [Collections.Generic.List[string]]::new()
      foreach ($Part in [regex]::Matches([string]$FileVersion, '\d+')) { $Parts.Add($Part.Value) }
      # Runtime PE files use major.minor.build[.revision]. Trim zero-only tail
      # components so 3.00.117.0 reports build 117 rather than revision 0.
      while ($Parts.Count -gt 3 -and [uint64]::Parse($Parts[$Parts.Count - 1], [Globalization.CultureInfo]::InvariantCulture) -eq 0) {
        $Parts.RemoveAt($Parts.Count - 1)
      }
      if ($Parts.Count -gt 2) {
        $BuildParts = [string[]]$Parts.GetRange(2, $Parts.Count - 2).ToArray()
        if ($BuildParts | Where-Object { [uint64]::Parse($_, [Globalization.CultureInfo]::InvariantCulture) -ne 0 }) {
          $Item.Build = $BuildParts -join '.'
        }
      }
      $Item
    })
}

function Get-InstallShieldClassicEngineInfo {
  <#
  .SYNOPSIS
    Identify a reusable InstallShield 3 setup engine without package media.
  .DESCRIPTION
    InstallShield 3 distributed setup32.exe separately from Setup30 package
    catalogs. This narrow classifier requires vendor, product, description, and
    major-version evidence. It does not claim that payloads or ARP metadata are
    embedded in the engine.
  .PARAMETER Path
    Resolved PE path whose version resource is inspected.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)

  try { $VersionInfo = [Diagnostics.FileVersionInfo]::GetVersionInfo($Path) }
  catch { return $null }
  if ($VersionInfo.ProductName -ine 'InstallShield' -or
    $VersionInfo.FileDescription -ine 'InstallShield Engine EXE' -or
    $VersionInfo.CompanyName -notmatch '(?i)^InstallShield Corporation' -or
    $VersionInfo.ProductVersion -notmatch '^3(?:\.|$)') {
    return $null
  }

  return [pscustomobject][ordered]@{
    Profile        = 'InstallShield 3 reusable setup32 engine'
    ProductVersion = [string]$VersionInfo.ProductVersion
    FileVersion    = [string]$VersionInfo.FileVersion
    Evidence       = [object[]]@([pscustomobject][ordered]@{
        ProductName     = [string]$VersionInfo.ProductName
        ProductVersion  = [string]$VersionInfo.ProductVersion
        FileDescription = [string]$VersionInfo.FileDescription
        FileVersion     = [string]$VersionInfo.FileVersion
        CompanyName     = [string]$VersionInfo.CompanyName
      })
    SupportStatus  = 'Partial'
    Limitations    = [string[]]@('The engine contains no validated Setup30 package catalog; payload, script, ARP, and switch evidence require the accompanying media files.')
  }
}

function Get-InstallShieldReleaseEvidenceFromContext {
  <#
  .SYNOPSIS
    Compose shipped-media release evidence from one completed analysis context.
  .PARAMETER Context
    Context returned by New-InstallShieldAnalysisContext.
  #>
  [OutputType([object[]])]
  param ([Parameter(Mandatory)][psobject]$Context)

  $Evidence = [Collections.Generic.List[object]]::new()
  if ($Context.AdvancedUiInfo -and $Context.AdvancedUiInfo.Namespace -match '^installshield/(?<Year>\d{4})(?:\.\d+)?/bootstrap$') {
    $Year = [int]$Matches.Year
    $Catalog = Get-InstallShieldReleaseCatalog
    $Candidates = @($Catalog.Products.Values | ForEach-Object { $_ } | Where-Object { $_.Year -eq $Year })
    if (-not $Candidates) {
      $Evidence.Add((ConvertTo-InstallShieldReleaseEvidence -Source AdvancedUI -Value $Year -Candidate $null -Confidence ExactSuiteNamespace -Rank 100 `
            -Detail "Advanced UI namespace '$($Context.AdvancedUiInfo.Namespace)'"))
    } else {
      foreach ($Candidate in $Candidates) {
        $Evidence.Add((ConvertTo-InstallShieldReleaseEvidence -Source AdvancedUI -Value $Year -Candidate $Candidate -Confidence ExactSuiteNamespace -Rank 100 `
              -Detail "Advanced UI namespace '$($Context.AdvancedUiInfo.Namespace)'"))
      }
    }
  }

  foreach ($MediaVersion in @($Context.CabinetSupport.MediaVersions)) {
    $RawVersion = [uint32]$MediaVersion.RawVersion
    $VersionFamily = $RawVersion -shr 24
    $Detail = "$($MediaVersion.HeaderPath): ISc( cabinet format $($MediaVersion.MajorVersion), family $VersionFamily, raw version 0x$($RawVersion.ToString('X8'))"
    # Legacy family 1 encodes a cabinet-format generation: official 11.5 media
    # emits 0x01009500 (format 9.5). Families 2 and 4 use the builder-aligned
    # version/100 representation observed in official modern media, including
    # 2025 major 31 and 2026 major 32 outputs.
    $Candidates = if ($VersionFamily -in 2, 4) {
      @(Get-InstallShieldProductReleaseCandidate -ProductVersion ([string]$MediaVersion.MajorVersion))
    } else { @() }
    if ($Candidates) {
      foreach ($Candidate in $Candidates) {
        $Evidence.Add((ConvertTo-InstallShieldReleaseEvidence -Source CabinetHeader -Value $RawVersion -Candidate $Candidate `
              -Confidence StructuralMediaVersion -Rank 90 -Detail $Detail))
      }
    } else {
      $Evidence.Add((ConvertTo-InstallShieldReleaseEvidence -Source CabinetHeader -Value $RawVersion -Candidate $null `
            -Confidence StructuralMediaVersion -Rank 0 -Detail $Detail))
    }
  }

  $ExternalMediaInfo = $Context.PSObject.Properties['ExternalMediaInfo'] ? $Context.ExternalMediaInfo : $null
  $SetupConfiguration = $Context.PSObject.Properties['SetupConfiguration'] ? $Context.SetupConfiguration : $null
  $SetupEngineVersion = $SetupConfiguration ? [string](Get-InstallShieldIniValue -Configuration $SetupConfiguration -Section Startup -Name EngineVersion) : $null
  if (-not [string]::IsNullOrWhiteSpace($SetupEngineVersion)) {
    $SetupIniPath = if ($Context.MsiPayloadSelection -and $Context.MsiPayloadSelection.SetupIniResolvedPath) {
      $Context.MsiPayloadSelection.SetupIniResolvedPath
    } elseif ($ExternalMediaInfo) { $ExternalMediaInfo.SetupIniPath } else { 'Setup.ini' }
    $Candidates = Get-InstallShieldProductReleaseCandidate -ProductVersion $SetupEngineVersion
    foreach ($Candidate in @($Candidates)) {
      $Evidence.Add((ConvertTo-InstallShieldReleaseEvidence -Source SetupIniEngine -Value $SetupEngineVersion -Candidate $Candidate `
            -Confidence StructuredEngineVersion -Rank 80 -Detail "${SetupIniPath}: [Startup] EngineVersion"))
    }
  }

  $SummaryCreatingApp = if ($Context.SelectedMsiInfo -and $Context.SelectedMsiInfo.PSObject.Properties['SummaryCreatingApplication']) {
    $Context.SelectedMsiInfo.PSObject.Properties['SummaryCreatingApplication'].Value
  } else { $null }
  if ($SummaryCreatingApp -match '(?i)InstallShield(?:R|\u00AE)?') {
    $EditionVersionMatch = [regex]::Match($SummaryCreatingApp, '(?i)(?:Edition|Version)\s+(?<Version>\d+(?:\.\d+)*)\s*$')
    $OrdinaryVersionMatch = [regex]::Match($SummaryCreatingApp, '(?i)InstallShield(?:R|\u00AE)?\s+(?<Version>\d+(?:\.\d+)*)')
    $SummaryVersion = if ($EditionVersionMatch.Success) { $EditionVersionMatch.Groups['Version'].Value } elseif ($OrdinaryVersionMatch.Success) { $OrdinaryVersionMatch.Groups['Version'].Value } else { $null }
    $Candidates = $SummaryVersion ? (Get-InstallShieldProductReleaseCandidate -ProductVersion $SummaryVersion) : @()
    if (-not $Candidates) {
      $Evidence.Add((ConvertTo-InstallShieldReleaseEvidence -Source MsiSummary -Value $SummaryCreatingApp -Candidate $null -Confidence InstallShieldMsiSummary -Rank 70 `
            -Detail "MSI Summary Information CreatingApp='$SummaryCreatingApp'"))
    } else {
      foreach ($Candidate in $Candidates) {
        $Evidence.Add((ConvertTo-InstallShieldReleaseEvidence -Source MsiSummary -Value $SummaryCreatingApp -Candidate $Candidate -Confidence InstallShieldMsiSummary -Rank 70 `
              -Detail "MSI Summary Information CreatingApp='$SummaryCreatingApp'"))
      }
    }
  }

  $RuntimePaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  if ($RuntimePaths.Add([string]$Context.SourcePath)) {
    $RuntimeEvidence = if ($ExternalMediaInfo) { @($ExternalMediaInfo.RuntimeEvidence) } else { @(Get-InstallShieldRuntimeReleaseEvidence -Path $Context.SourcePath) }
    foreach ($Item in $RuntimeEvidence) { $Evidence.Add($Item) }
  }
  # PackageForTheWeb and other wrappers may carry the trusted InstallShield
  # launcher as an exact nested Setup.exe while the outer PE identifies only
  # the publisher's application. Restrict probing to canonical runtime names.
  foreach ($RuntimeFile in @($Context.Files | Where-Object Name -IMatch '^setup\.(?:exe|dll)$')) {
    if (-not $RuntimePaths.Add($RuntimeFile.FullName)) { continue }
    foreach ($Item in @(Get-InstallShieldRuntimeReleaseEvidence -Path $RuntimeFile.FullName)) { $Evidence.Add($Item) }
  }
  if ($Context.Classic3Info -and @($Context.Classic3Info.Entries).Count -gt 0) {
    $Candidate = @(Get-InstallShieldProductReleaseCandidate -ProductVersion '3') | Select-Object -First 1
    $Evidence.Add((ConvertTo-InstallShieldReleaseEvidence -Source ClassicMedia -Value 'Setup30' -Candidate $Candidate -Confidence StructuralFamily -Rank 40 `
          -Detail 'Classic Setup30 footer catalog and TTCOMP member framing'))
  }
  return [object[]]$Evidence.ToArray()
}

function Get-InstallShieldStructuralRoute {
  <#
  .SYNOPSIS
    Build ordered physical parser routes for a completed InstallShield analysis.
  .PARAMETER Context
    Reused extraction/classification context.
  .PARAMETER Result
    Final composed result containing suite, MSI, and InstallScript evidence.
  #>
  [OutputType([object[]])]
  param (
    [Parameter(Mandatory)][psobject]$Context,
    [Parameter(Mandatory)][psobject]$Result
  )

  $Routes = [Collections.Generic.List[object]]::new()
  if ($Context.PackageForTheWebCabinet) {
    $Routes.Add((ConvertTo-InstallShieldStructuralRoute -RouteId 'Wrapper/PackageForTheWeb' -Layer Wrapper `
          -StructuralProfile 'Microsoft Cabinet wrapper ending at PE EOF' -FormatVersion 'CAB 1.3' -Handler 'Expand-InstallShieldPackageForTheWebCabinet' `
          -Capabilities @('Catalog', 'Extraction', 'Nested payload selection') -Evidence @($Context.PackageForTheWebCabinet)))
  }

  $ExternalMediaInfo = $Context.PSObject.Properties['ExternalMediaInfo'] ? $Context.ExternalMediaInfo : $null
  if ($ExternalMediaInfo) {
    $Routes.Add((ConvertTo-InstallShieldStructuralRoute -RouteId 'Media/External' -Layer Media `
          -StructuralProfile 'Trusted setup.exe with direct Setup.ini and external payload media' `
          -FormatVersion $ExternalMediaInfo.EngineVersion -Handler 'Get-InstallShieldExternalMediaInfo' `
          -Capabilities @('Bounded Setup.ini', 'Direct sidecar selection', 'External cabinet and InstallScript routing') `
          -Evidence @($ExternalMediaInfo.Evidence)))
  }

  if ($Context.Extraction -and $Context.Extraction.Format -in @('InstallShield', 'ISSetupStream', 'Plain', 'PlainUnicode')) {
    $RouteId = $Context.Extraction.Format -eq 'ISSetupStream' ? 'Overlay/ISSetupStream' : 'Overlay/InstallShield'
    $Routes.Add((ConvertTo-InstallShieldStructuralRoute -RouteId $RouteId -Layer Overlay -StructuralProfile $Context.Extraction.Format `
          -FormatVersion $null -Handler 'Invoke-InstallShieldExtraction' -Capabilities @('Overlay catalog', 'Bounded extraction') `
          -Evidence @([pscustomobject]@{ Format = $Context.Extraction.Format; DataOffset = $Context.Extraction.DataOffset })))
  }

  if ($Context.Classic3Info) {
    $Routes.Add((ConvertTo-InstallShieldStructuralRoute -RouteId 'Classic3/Package' -Layer Classic `
          -StructuralProfile 'Setup30 footer catalog with TTCOMP members' -FormatVersion 3 -Handler 'InstallShieldClassicExtractor' `
          -Capabilities @('Setup.pkg/_setup.lib/data.z catalog', 'TTCOMP extraction', 'Multipart media') `
          -SupportStatus ($Context.Classic3Info.SupportStatus ?? 'Supported') -Evidence @($Context.Classic3Info.Evidence) `
          -Limitations @($Context.Classic3Info.Limitations)))

    # Setup.ins is both a physical member of classic media and an independently
    # decoded script layer. Keep that distinction visible even though actions
    # without source-backed semantics remain opaque in the bounded IR.
    $ClassicInsEntries = @($Context.Classic3Info.Entries | Where-Object Name -IMatch '(?:^|[\\/])setup\.ins$')
    if ($ClassicInsEntries) {
      $Routes.Add((ConvertTo-InstallShieldStructuralRoute -RouteId 'Classic3/INS' -Layer Script `
            -StructuralProfile 'InstallShield 3 compiled INS program' -FormatVersion 3 -Handler 'InstallScriptBytecodeReader' `
            -Capabilities @('Header classification', 'Legacy event/action IR', 'Bounded static simulation') -SupportStatus Supported `
            -Evidence $ClassicInsEntries -Limitations @('Generation-dependent INS actions remain explicit opaque evidence.')))
    }
  }
  $Classic3EngineInfo = $Context.PSObject.Properties['Classic3EngineInfo'] ? $Context.Classic3EngineInfo : $null
  if ($Classic3EngineInfo -and -not $Context.Classic3Info) {
    $Routes.Add((ConvertTo-InstallShieldStructuralRoute -RouteId 'Classic3/Engine' -Layer Classic `
          -StructuralProfile $Classic3EngineInfo.Profile -FormatVersion 3 -Handler 'Get-InstallShieldClassicEngineInfo' `
          -Capabilities @('Release identification', 'Runtime PE classification') -SupportStatus Partial `
          -Evidence @($Classic3EngineInfo.Evidence) -Limitations @($Classic3EngineInfo.Limitations)))
  }

  foreach ($MediaVersion in @($Context.CabinetSupport.MediaVersions)) {
    $RouteId = switch ([int]$MediaVersion.MajorVersion) {
      0 { 'Cabinet5/LegacyDescriptor' }
      5 { 'Cabinet5/LegacyDescriptor' }
      { $_ -ge 17 } { 'Cabinet17/UnicodeCatalog'; break }
      default { 'Cabinet6/AnsiCatalog' }
    }
    $StructuralProfile = switch ($RouteId) {
      'Cabinet5/LegacyDescriptor' {
        if ([int]$MediaVersion.MajorVersion -eq 0) { '0x2A file descriptors without MD5 and 40-byte volume headers' }
        else { '0x3A file descriptors with MD5 and 40-byte volume headers' }
      }
      'Cabinet17/UnicodeCatalog' { '0x57 descriptors with UTF-16 catalog strings' }
      default { '0x57 descriptors with ANSI catalog strings' }
    }
    $Capabilities = [Collections.Generic.List[string]]::new()
    foreach ($Capability in @('Catalog', 'Selected extraction', 'Split volumes')) { $Capabilities.Add($Capability) }
    if ([int]$MediaVersion.MajorVersion -ne 0) { $Capabilities.Add('MD5 validation') }
    $Routes.Add((ConvertTo-InstallShieldStructuralRoute -RouteId $RouteId -Layer Cabinet -StructuralProfile $StructuralProfile `
          -FormatVersion $MediaVersion.MajorVersion -Handler 'InstallShieldCabinetExtractor' `
          -Capabilities $Capabilities.ToArray() `
          -SupportStatus ($MediaVersion.SupportStatus ?? 'Supported') -Evidence @($MediaVersion) `
          -Limitations @($MediaVersion.Limitations)))
  }

  $ScriptProfiles = [Collections.Generic.List[object]]::new()
  foreach ($HeaderInfo in @($Context.InstallScriptHeaders)) { $ScriptProfiles.Add($HeaderInfo) }
  if ($Result.InstallScriptInfo -and $Result.InstallScriptInfo.ParserVersionInfo) {
    $ParserHeaderKind = [string]$Result.InstallScriptInfo.ParserVersionInfo.HeaderKind
    if ([string]::IsNullOrWhiteSpace($ParserHeaderKind)) { $ParserHeaderKind = [string]$Result.InstallScriptInfo.ParserVersionInfo.Format }
    $ExistingHeader = $ScriptProfiles | Where-Object HeaderKind -EQ $ParserHeaderKind | Select-Object -First 1
    if ($ExistingHeader) {
      $ExistingHeader | Add-Member -NotePropertyName ParserVersionInfo -NotePropertyValue $Result.InstallScriptInfo.ParserVersionInfo -Force
    } else {
      $ScriptProfiles.Add([pscustomobject]@{
          HeaderKind        = $ParserHeaderKind
          SupportStatus     = 'Supported'
          ParserVersionInfo = $Result.InstallScriptInfo.ParserVersionInfo
          Path              = $Result.InstallScriptInfo.Path
          Limitations       = [string[]]@()
        })
    }
  }
  foreach ($ScriptInfo in $ScriptProfiles) {
    $HeaderKind = [string]$ScriptInfo.HeaderKind
    $RouteId = switch -Regex ($HeaderKind) {
      'INS-Old|Legacy INS' { 'Script/INS-Old'; break }
      '^OBS$' { 'Script/OBS'; break }
      '^aLuZ$' { 'Script/aLuZ'; break }
      '^kUtZ$' { 'Script/kUtZ'; break }
      '^OBL$' { 'Script/OBL'; break }
      default { 'Script/Unknown' }
    }
    $Status = $ScriptInfo.SupportStatus ?? ($RouteId -eq 'Script/Unknown' ? 'Partial' : 'Supported')
    $ParserVersionInfo = $ScriptInfo.PSObject.Properties['ParserVersionInfo'] ? $ScriptInfo.ParserVersionInfo : $ScriptInfo
    $Limitations = [Collections.Generic.List[string]]::new()
    foreach ($Limitation in @($ScriptInfo.Limitations)) {
      if (-not [string]::IsNullOrWhiteSpace([string]$Limitation)) { $Limitations.Add([string]$Limitation) }
    }
    if ($Status -eq 'Partial' -and $Limitations.Count -eq 0) {
      $Limitations.Add('Unsupported actions remain explicit instead of receiving guessed opcode semantics.')
    }
    $Capabilities = if ($RouteId -eq 'Script/OBL') {
      @('Member catalog', 'Bounded member ranges', 'Selected-member instruction IR')
    } elseif ($RouteId -eq 'Script/OBS') {
      @('Prototype and extern catalogs', 'Address-resolution records', 'Basic-block instruction IR')
    } else {
      @('Function catalog', 'Instruction IR', 'Bounded static simulation')
    }
    $Routes.Add((ConvertTo-InstallShieldStructuralRoute -RouteId $RouteId -Layer Script -StructuralProfile $HeaderKind `
          -FormatVersion $ParserVersionInfo.HeaderValue -Handler ($ScriptInfo.Handler ?? 'InstallScriptBytecodeReader') `
          -Capabilities $Capabilities -SupportStatus $Status `
          -Evidence @($ParserVersionInfo) -Limitations $Limitations.ToArray()))
  }

  if ($Context.SelectedMsiInfo) {
    $IsInstallScriptMsi = $Context.SelectedMsiInfo.InstallShieldProjectType -eq 'InstallScript MSI'
    $Routes.Add((ConvertTo-InstallShieldStructuralRoute -RouteId ($IsInstallScriptMsi ? 'MSI/InstallScript' : 'MSI/Basic') -Layer MSI `
          -StructuralProfile ($Context.SelectedMsiInfo.InstallShieldProjectType ?? 'Basic MSI') -FormatVersion $null -Handler 'Get-MsiInstallerInfo' `
          -Capabilities @('MSI tables', 'ARP metadata', 'InstallScript custom actions') `
          -Evidence @($Context.SelectedMsiInfo.InstallShieldProjectTypeEvidence)))
  }
  if ($Context.AdvancedUiInfo) {
    $Routes.Add((ConvertTo-InstallShieldStructuralRoute -RouteId 'Suite/AdvancedUI' -Layer Suite -StructuralProfile 'Advanced UI bootstrap catalog' `
          -FormatVersion $Context.AdvancedUiInfo.Namespace -Handler 'Get-InstallShieldAdvancedUiInfo' `
          -Capabilities @('Suite ARP', 'Parcel catalog', 'Conditions', 'Nested command lines') -Evidence @($Context.AdvancedUiInfo.Namespace)))
  }

  return [object[]]$Routes.ToArray()
}

function Expand-InstallShield {
  <#
  .SYNOPSIS
    Extract files from an InstallShield executable using the in-process parser.
  .PARAMETER Path
    The path to the InstallShield installer.
  .PARAMETER DestinationPath
    The destination directory, or the legacy sibling `_u` directory when omitted.
  .PARAMETER Name
    Optional wildcard selecting payload paths or file names.
  .PARAMETER CollisionAction
    Behavior when an output path already exists.
  .PARAMETER MaximumExpandedBytes
    Maximum total bytes decoded from the InstallShield container.
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [string]$Name = '*',
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Prompt',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 8GB
  )
  process {
    Expand-InstallShieldInstaller -Path $Path -DestinationPath $DestinationPath -Name $Name `
      -CollisionAction $CollisionAction -MaximumExpandedBytes $MaximumExpandedBytes
  }
}

function Get-InstallShieldExternalMediaInfo {
  <#
  .SYNOPSIS
    Identify direct external InstallShield media associated with a trusted setup launcher.
  .DESCRIPTION
    InstallShield can emit setup.exe as a reusable launcher while keeping
    Setup.ini, setup.inx, and data*.hdr/data*.cab beside it. This function
    accepts only direct canonical sidecars and an InstallShield-identifying PE;
    it never recursively searches the surrounding download directory.
  .PARAMETER Path
    Resolved path to the candidate setup launcher.
  .OUTPUTS
    External media root, parsed Setup.ini, canonical sidecars, runtime evidence,
    and exact structural evidence, or null when the relationship is not proven.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)

  $InstallerPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
  $RuntimeEvidence = [object[]]@(Get-InstallShieldRuntimeReleaseEvidence -Path $InstallerPath)
  if (-not $RuntimeEvidence) { return $null }

  $MediaRoot = [IO.Path]::GetDirectoryName($InstallerPath)
  $DirectFiles = [IO.FileInfo[]]@(Get-ChildItem -LiteralPath $MediaRoot -File -Force | Sort-Object Name)
  $SetupIniFiles = [IO.FileInfo[]]@($DirectFiles | Where-Object Name -IEQ 'Setup.ini')
  if ($SetupIniFiles.Count -ne 1) { return $null }
  $SetupIniFile = $SetupIniFiles[0]
  try { $Configuration = Read-InstallShieldIniConfiguration -Path $SetupIniFile.FullName }
  catch { return $null }

  $EngineVersion = [string](Get-InstallShieldIniValue -Configuration $Configuration -Section Startup -Name EngineVersion)
  $ProductGuid = [string](Get-InstallShieldIniValue -Configuration $Configuration -Section Startup -Name ProductGUID)
  $PackageName = [string](Get-InstallShieldIniValue -Configuration $Configuration -Section Startup -Name PackageName)
  $MsiSelection = Get-InstallShieldExternalMediaSelection -InstallerPath $InstallerPath -ExtractedPath $MediaRoot -Configuration $Configuration
  $ScriptFiles = [IO.FileInfo[]]@($DirectFiles | Where-Object Name -IMatch '^setup\.(?:inx|ins)$')
  $HeaderFiles = [IO.FileInfo[]]@($DirectFiles | Where-Object Name -CMatch '^data\d+\.hdr$')
  $ValidHeaderFiles = [Collections.Generic.List[IO.FileInfo]]::new()
  foreach ($HeaderFile in $HeaderFiles) {
    $Stream = [IO.File]::Open($HeaderFile.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
      if ($Stream.Length -ge 4 -and [Text.Encoding]::ASCII.GetString((Read-BinaryBytes -Stream $Stream -Offset 0 -Count 4)) -ceq 'ISc(') {
        $ValidHeaderFiles.Add($HeaderFile)
      }
    } finally { $Stream.Dispose() }
  }

  # Setup.ini plus a compiled script, a validated cabinet catalog, or an exact
  # configured package proves that this is application media rather than
  # an unrelated INI file beside an InstallShield-authored executable.
  if (-not $ScriptFiles -and $ValidHeaderFiles.Count -eq 0 -and -not $MsiSelection.SelectedMsiResolvedPath) { return $null }

  $MediaFiles = [Collections.Generic.List[IO.FileInfo]]::new()
  $MediaFilePaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($File in $DirectFiles) {
    $IsCanonical = $File.Name -imatch '^(?:setup\.(?:ini|inx|ins|iss|ibt|xml)|layout\.bin|_setup\.dll|data\d+\.(?:hdr|cab)|engine\d*\.cab|.+\.(?:obl|prq))$'
    if ($IsCanonical -and $MediaFilePaths.Add($File.FullName)) { $MediaFiles.Add($File) }
  }
  if ($MsiSelection.SelectedMsiResolvedPath -and $MediaFilePaths.Add($MsiSelection.SelectedMsiResolvedPath)) {
    $MediaFiles.Add((Get-Item -LiteralPath $MsiSelection.SelectedMsiResolvedPath -Force))
  }

  [pscustomobject][ordered]@{
    MediaRoot       = $MediaRoot
    SetupIniPath    = $SetupIniFile.FullName
    Configuration   = $Configuration
    EngineVersion   = [string]::IsNullOrWhiteSpace($EngineVersion) ? $null : $EngineVersion.Trim()
    ProductGuid     = [string]::IsNullOrWhiteSpace($ProductGuid) ? $null : $ProductGuid.Trim()
    PackageName     = [string]::IsNullOrWhiteSpace($PackageName) ? $null : $PackageName.Trim()
    ScriptFiles     = [IO.FileInfo[]]$ScriptFiles
    HeaderFiles     = [IO.FileInfo[]]$ValidHeaderFiles.ToArray()
    Files           = [IO.FileInfo[]]$MediaFiles.ToArray()
    RuntimeEvidence = $RuntimeEvidence
    MsiSelection    = $MsiSelection
    Evidence        = [object[]]@(
      [pscustomobject][ordered]@{
        SetupIniPath  = $SetupIniFile.FullName
        EngineVersion = [string]::IsNullOrWhiteSpace($EngineVersion) ? $null : $EngineVersion.Trim()
        ProductGuid   = [string]::IsNullOrWhiteSpace($ProductGuid) ? $null : $ProductGuid.Trim()
        ScriptCount   = $ScriptFiles.Count
        HeaderCount   = $ValidHeaderFiles.Count
      }
    )
  }
}

function New-InstallShieldAnalysisContext {
  <#
  .SYNOPSIS
    Build the immutable extraction and classification context for one InstallShield analysis.
  .PARAMETER Path
    Resolved installer path. The source file is opened once for both probing and extraction.
  .PARAMETER DestinationPath
    Optional extraction destination. A sibling `_u` directory is used when omitted.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [string]$DestinationPath
  )

  $ContainerFormat = 'InstallShield Overlay'
  $PackageForTheWebCabinet = $null
  $Classic3Info = $null
  $ExternalMediaInfo = $null
  $Classic3EngineInfo = Get-InstallShieldClassicEngineInfo -Path $Path
  $Warnings = [Collections.Generic.List[string]]::new()
  $ExtractedPath = if ([string]::IsNullOrWhiteSpace($DestinationPath)) {
    Join-Path (Split-Path -Path $Path -Parent) ((Split-Path -Path $Path -LeafBase) + '_u')
  } else {
    Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
  }

  # The outer launcher's PE manifest is independent from MSI and prerequisite
  # metadata. Preserve it as direct UAC evidence instead of inferring elevation
  # from a machine-scope payload.
  $RequestedExecutionLevel = $null
  try {
    $RequestedExecutionLevel = Get-PERequestedExecutionLevel -Path $Path
  } catch {
    $Warnings.Add("The InstallShield launcher's requested execution level could not be read: $($_.Exception.Message)")
  }

  $SourceStream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    $OverlayOffset = Get-PEOverlayOffset -Stream $SourceStream
    if ($OverlayOffset -gt 0 -and $OverlayOffset -lt $SourceStream.Length) {
      $PackageForTheWebCabinet = Get-InstallShieldPackageForTheWebCabinet -Stream $SourceStream -OverlayOffset $OverlayOffset
      if ($PackageForTheWebCabinet) { $ContainerFormat = 'PackageForTheWeb Cabinet' }
    }
    try {
      $Extraction = Invoke-InstallShieldExtractionWithClassicFallback -Path $Path -SourceStream $SourceStream -DestinationPath $ExtractedPath -CollisionAction Rename
    } catch {
      $ExtractionError = $_
      $ExternalMediaInfo = Get-InstallShieldExternalMediaInfo -Path $Path
      if ($ExternalMediaInfo) {
        # The launcher owns no application payload bytes. Keep the source media
        # read-only and direct focused support extraction to the caller's output.
        $null = New-Item -Path $ExtractedPath -ItemType Directory -Force
        $Extraction = [pscustomobject][ordered]@{
          Format          = 'InstallShield External Media'
          DestinationPath = $ExtractedPath
          ExtractedFiles  = [string[]]@($ExternalMediaInfo.Files.FullName)
          DataOffset      = $null
        }
        $ContainerFormat = 'InstallShield External Media'
      } elseif ($Classic3EngineInfo) {
        # A standalone 3.x setup32.exe is a runtime engine, not malformed modern
        # media. Preserve classification while keeping extraction evidence empty.
        $null = New-Item -Path $ExtractedPath -ItemType Directory -Force
        $Extraction = [pscustomobject][ordered]@{
          Format          = 'InstallShield 3 Engine'
          DestinationPath = $ExtractedPath
          ExtractedFiles  = [string[]]@()
          DataOffset      = $null
        }
        $Warnings.Add('The file is a reusable InstallShield 3 setup engine without a validated embedded Setup30 package. Analyze the accompanying Setup.pkg, _setup.lib, data.z, or disk files for payload and installer behavior.')
        $ContainerFormat = 'InstallShield 3 Engine'
      } else {
        throw $ExtractionError
      }
    }
    if ($Extraction.Format -eq 'InstallShield 3 Setup30') {
      $Classic3Info = $Extraction
      $ContainerFormat = 'InstallShield 3 Setup30'
    }
  } finally {
    $SourceStream.Dispose()
  }

  # Proprietary media may hide setup.inx inside data*.cab. Expand only bounded support
  # metadata, then enumerate the complete extraction tree exactly once.
  $MediaRoot = $ExternalMediaInfo ? $ExternalMediaInfo.MediaRoot : $ExtractedPath
  $CabinetSupport = Expand-InstallShieldCabinetSupport -ExtractedPath $MediaRoot -DestinationPath $ExtractedPath -CollisionAction Rename
  if ($ExternalMediaInfo) {
    $FilePaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $FileList = [Collections.Generic.List[IO.FileInfo]]::new()
    foreach ($File in @($ExternalMediaInfo.Files) + @($CabinetSupport.ExtractedFiles | ForEach-Object { Get-Item -LiteralPath $_ -Force })) {
      if ($FilePaths.Add($File.FullName)) { $FileList.Add($File) }
    }
    $Files = [object[]]@($FileList | Sort-Object FullName)
  } else {
    $Files = @(Get-ChildItem -LiteralPath $ExtractedPath -Recurse -File -ErrorAction SilentlyContinue | Sort-Object FullName)
  }
  $MsiFiles = @($Files | Where-Object Extension -EQ '.msi')
  $InxFiles = if ($ExternalMediaInfo.ScriptFiles) { [object[]]@($ExternalMediaInfo.ScriptFiles) } else { @($Files | Where-Object Extension -In @('.inx', '.ins')) }
  $OblFiles = @($Files | Where-Object Extension -EQ '.obl')
  $CabFiles = @($Files | Where-Object Extension -In @('.cab', '.hdr'))
  $SfxFiles = @($Files | Where-Object Name -Like '*_sfx.exe')
  $Prerequisites = [Collections.Generic.List[object]]::new()
  $InstallScriptHeaders = [Collections.Generic.List[object]]::new()
  $InstallScriptLibraries = [Collections.Generic.List[object]]::new()
  foreach ($ScriptFile in @($InxFiles) + @($OblFiles)) {
    try {
      $HeaderInfo = Get-InstallShieldInstallScriptHeaderInfo -Path $ScriptFile.FullName
      if ($HeaderInfo.HeaderKind -eq 'OBL') {
        # OBL is a compiler library, not an executable setup program. Preserve
        # its member catalog as auxiliary evidence without creating an active
        # Script/OBL route for a product that merely installs builder assets.
        $InstallScriptLibraries.Add((Get-InstallShieldInstallScriptLibraryInfo -Path $ScriptFile.FullName))
      } else {
        $InstallScriptHeaders.Add($HeaderInfo)
      }
    } catch { $Warnings.Add("The InstallScript header '$($ScriptFile.FullName)' could not be classified: $($_.Exception.Message)") }
  }
  foreach ($PrerequisiteFile in @($Files | Where-Object Extension -EQ '.prq')) {
    try { $Prerequisites.Add((Get-InstallShieldPrerequisiteInfo -Path $PrerequisiteFile.FullName)) }
    catch { $Warnings.Add("The prerequisite definition '$($PrerequisiteFile.FullName)' could not be parsed: $($_.Exception.Message)") }
  }

  $AdvancedUiInfo = $null
  $AdvancedUiSetupXml = $Files | Where-Object Name -CEQ 'Setup.xml' | Select-Object -First 1
  if ($AdvancedUiSetupXml) {
    try {
      $AdvancedUiInfo = Get-InstallShieldAdvancedUiInfo -Path $AdvancedUiSetupXml.FullName -ExtractedPath $ExtractedPath
    } catch {
      # Setup.xml also occurs in unrelated payloads; warn only for an InstallShield bootstrap namespace.
      if ((Get-Content -LiteralPath $AdvancedUiSetupXml.FullName -TotalCount 2 -ErrorAction SilentlyContinue) -match 'installshield/\d{4}(?:\.\d+)?/bootstrap') {
        $Warnings.Add("The Advanced UI package catalog could not be parsed: $($_.Exception.Message)")
      }
    }
  }

  $MsiSelection = if ($ExternalMediaInfo) {
    $ExternalMediaInfo.MsiSelection
  } else {
    Get-InstallShieldMsiPayloadSelection -ExtractedPath $ExtractedPath -MsiFile $MsiFiles
  }
  if (-not $ExternalMediaInfo -and -not $MsiSelection.Configuration) {
    # InstallShield 11.x and other external-media launchers keep Setup.ini and
    # the MSI beside setup.exe. Resolve only the exact configured sibling path;
    # never widen this into a directory scan or wildcard selection.
    $ExternalMsiSelection = Get-InstallShieldExternalMediaSelection -InstallerPath $Path -ExtractedPath $ExtractedPath
    if ($ExternalMsiSelection) {
      $MsiSelection = $ExternalMsiSelection
      if ($MsiSelection.SelectedMsiResolvedPath) {
        $MsiFiles = @($MsiFiles) + @(Get-Item -LiteralPath $MsiSelection.SelectedMsiResolvedPath -Force)
      }
    }
  }
  $SelectedMsiInfo = $null
  if ($MsiSelection.SelectedMsiPath) {
    try {
      $SelectionContext = [pscustomobject]@{ ExtractedPath = $ExtractedPath; MsiPayloadSelection = $MsiSelection }
      $SelectedMsiFile = Resolve-InstallShieldMsiFile -Installer $SelectionContext -Item $MsiFiles -Pattern '*.msi' -NameWasSpecified $false
      $SelectedMsiInfo = Get-MsiInstallerInfo -Path $SelectedMsiFile.FullName
    } catch {
      $Warnings.Add("The selected InstallShield MSI could not be classified: $($_.Exception.Message)")
    }
  }

  $Variant = if ($AdvancedUiInfo) {
    'Advanced UI'
  } elseif ($MsiFiles) {
    $SelectedMsiInfo.InstallShieldProjectType ? $SelectedMsiInfo.InstallShieldProjectType : 'Basic MSI or InstallScript MSI'
  } elseif ($InxFiles) {
    'InstallScript'
  } elseif ($CabFiles -or $SfxFiles) {
    'InstallShield payload without MSI'
  } elseif ($Classic3EngineInfo) {
    'InstallShield 3 engine without package media'
  } else {
    'Unknown'
  }

  return [pscustomobject][ordered]@{
    SourcePath              = $Path
    ContainerFormat         = $ContainerFormat
    PackageForTheWebCabinet = $PackageForTheWebCabinet
    Classic3Info            = $Classic3Info
    Classic3EngineInfo      = $Classic3EngineInfo
    ExternalMediaInfo       = $ExternalMediaInfo
    MediaRoot               = $MediaRoot
    Extraction              = $Extraction
    ExtractedPath           = $ExtractedPath
    Files                   = [object[]]$Files
    MsiFiles                = [object[]]$MsiFiles
    InxFiles                = [object[]]$InxFiles
    OblFiles                = [object[]]$OblFiles
    InstallScriptHeaders    = [object[]]$InstallScriptHeaders.ToArray()
    InstallScriptLibraries  = [object[]]$InstallScriptLibraries.ToArray()
    CabFiles                = [object[]]$CabFiles
    SfxFiles                = [object[]]$SfxFiles
    CabinetSupport          = $CabinetSupport
    SetupConfiguration      = $MsiSelection.Configuration
    MsiPayloadSelection     = $MsiSelection
    SelectedMsiInfo         = $SelectedMsiInfo
    RequestedExecutionLevel = $RequestedExecutionLevel
    PrerequisiteDefinitions = [object[]]$Prerequisites
    AdvancedUiInfo          = $AdvancedUiInfo
    Variant                 = $Variant
    ClassificationWarnings  = $Warnings
  }
}

function Merge-InstallShieldAdvancedUiResult {
  <#
  .SYNOPSIS
    Apply Advanced UI suite-owned metadata to an InstallShield result.
  .PARAMETER Result
    Mutable parser result being composed for the outer installer.
  .PARAMETER AdvancedUiInfo
    Parsed suite catalog. Suite identity remains authoritative over nested parcels.
  #>
  param ([Parameter(Mandatory)][psobject]$Result, [Parameter(Mandatory)][psobject]$AdvancedUiInfo)

  foreach ($PropertyName in @(
      'ProductCode', 'DisplayName', 'DisplayVersion', 'Publisher', 'Scope',
      'DefaultInstallLocation', 'UninstallString', 'QuietUninstallString',
      'DisplayIcon', 'URLInfoAbout', 'HelpLink', 'WritesAppsAndFeaturesEntry',
      'AppsAndFeaturesProductCode', 'AppsAndFeaturesInstallerType', 'ExecutedPayloads'
    )) {
    $Result.$PropertyName = $AdvancedUiInfo.$PropertyName
  }
  $Result.Warnings = [string[]]@($Result.Warnings + $AdvancedUiInfo.Warnings)
  $Result.UnresolvedFields = [string[]]@($AdvancedUiInfo.UnresolvedFields)
  return $Result
}

function Merge-InstallShieldInstallScriptResult {
  <#
  .SYNOPSIS
    Apply InstallScript-owned evidence without overriding an embedded MSI identity.
  .PARAMETER Result
    Mutable outer InstallShield result.
  .PARAMETER InstallScriptInfo
    Focused compiled-script analysis produced from the same extraction context.
  .PARAMETER Supplemental
    Retain the script as nested action evidence without applying its identity or
    standalone silent-install conclusions to the outer MSI or suite.
  #>
  param (
    [Parameter(Mandatory)][psobject]$Result,
    [Parameter(Mandatory)][psobject]$InstallScriptInfo,
    [switch]$Supplemental
  )

  $Result.InstallScriptInfo = $InstallScriptInfo
  if (-not $Supplemental -and -not $Result.HasMsi) {
    $Result.SilentSupport = $InstallScriptInfo.SilentSupport
    $Result.ResponseFileRequirement = $InstallScriptInfo.ResponseFileRequirement
    $Result.SilentSwitches = [string[]]@($InstallScriptInfo.SilentSwitches)
    foreach ($PropertyName in @(
        'ProductCode', 'DisplayName', 'DisplayVersion', 'Publisher', 'Scope',
        'DefaultInstallLocation', 'UninstallString', 'QuietUninstallString',
        'DisplayIcon', 'URLInfoAbout', 'HelpLink', 'WritesAppsAndFeaturesEntry',
        'AppsAndFeaturesProductCode', 'AppsAndFeaturesInstallerType',
        'AppsAndFeaturesEntries', 'RegistryWrites', 'RegistryItems', 'Protocols',
        'MediaRegistrySets', 'MediaRegistryWrites', 'ConditionalMediaRegistryWrites',
        'CabinetFileGroups', 'CabinetComponents', 'MediaSetupTypes',
        'MediaShellFolders', 'MediaShortcuts', 'ConditionalMediaShortcuts',
        'ConditionalRegistryAssociationInfo', 'ConditionalProtocols', 'ConditionalFileExtensions',
        'FileExtensions', 'ProtocolAssociations', 'FileExtensionAssociations',
        'RegistryAssociationInfo', 'ExecutedPayloads', 'FileOperations', 'DllOperations', 'Shortcuts',
        'PropertyHandlers', 'StaticCalls', 'OpcodeCoverage', 'UnsupportedOpcodes'
      )) {
      $Result.$PropertyName = $InstallScriptInfo.$PropertyName
    }
  }
  $Result.UnresolvedFields = [string[]]@((@($Result.UnresolvedFields) + @($InstallScriptInfo.UnresolvedFields)) | Select-Object -Unique)
  $Result.Warnings = [string[]]@($Result.Warnings + @($InstallScriptInfo.Warnings))
  return $Result
}

function Get-InstallShieldInfo {
  <#
  .SYNOPSIS
    Extract and classify an InstallShield installer statically
  .PARAMETER Path
    The path to the InstallShield installer
  .PARAMETER DestinationPath
    The destination directory for extracted files
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the InstallShield installer')]
    [string]$Path,

    [Parameter(HelpMessage = 'The destination directory for extracted files')]
    [string]$DestinationPath
  )

  process {
    $InstallerPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
    $Context = New-InstallShieldAnalysisContext -Path $InstallerPath -DestinationPath $DestinationPath
    $ContainerFormat = $Context.ContainerFormat
    $PackageForTheWebCabinet = $Context.PackageForTheWebCabinet
    $ExtractedPath = $Context.ExtractedPath
    $InstallShieldCabinetSupport = $Context.CabinetSupport
    $ExtractedFiles = [object[]]$Context.Files
    $MsiFiles = [object[]]$Context.MsiFiles
    $InxFiles = [object[]]$Context.InxFiles
    $OblFiles = if ($Context.PSObject.Properties['OblFiles']) { [object[]]$Context.OblFiles } else { [object[]]@() }
    $CabFiles = [object[]]$Context.CabFiles
    $SfxFiles = [object[]]$Context.SfxFiles
    $ClassificationWarnings = $Context.ClassificationWarnings
    $PrerequisiteDefinitions = [object[]]$Context.PrerequisiteDefinitions
    $AdvancedUiInfo = $Context.AdvancedUiInfo
    $MsiPayloadSelection = $Context.MsiPayloadSelection
    $SelectedMsiInfo = $Context.SelectedMsiInfo
    $Variant = $Context.Variant
    $InstallShieldProjectType = if ($AdvancedUiInfo) {
      'Advanced UI'
    } elseif ($SelectedMsiInfo.InstallShieldProjectType) {
      $SelectedMsiInfo.InstallShieldProjectType
    } elseif ($InxFiles) {
      'InstallScript'
    } else { $null }
    $PayloadSelectionWarnings = if ($AdvancedUiInfo) { @() } else { @($MsiPayloadSelection.Warnings) }
    $PackageForTheWebInfo = if ($PackageForTheWebCabinet) {
      $Configuration = $MsiPayloadSelection.Configuration
      $RootSetupFiles = [object[]]@($ExtractedFiles | Where-Object {
          $_.Name -ieq 'Setup.exe' -and [IO.Path]::GetRelativePath($ExtractedPath, $_.FullName) -notmatch '[\\/]'
        })
      $NestedSetupFile = if ($RootSetupFiles.Count -eq 1) {
        $RootSetupFiles[0]
      } else {
        $AllSetupFiles = [object[]]@($ExtractedFiles | Where-Object Name -IEQ 'Setup.exe')
        $AllSetupFiles.Count -eq 1 ? $AllSetupFiles[0] : $null
      }
      $NestedPayloadPath = if ($MsiPayloadSelection.SelectedMsiPath) {
        $MsiPayloadSelection.SelectedMsiPath
      } elseif ($InxFiles.Count -eq 1) {
        [IO.Path]::GetRelativePath($ExtractedPath, $InxFiles[0].FullName)
      } else { $null }
      $NestedPayloadKind = if ($MsiPayloadSelection.SelectedMsiPath) { 'MSI' } elseif ($InxFiles.Count -eq 1) { 'InstallScript program' } else { $null }
      $ConfiguredCommandLine = $Configuration ? (Get-InstallShieldIniValue -Configuration $Configuration -Section 'Startup' -Name 'CmdLine') : $null
      $LaunchChain = [Collections.Generic.List[object]]::new()
      if ($NestedSetupFile) {
        $LaunchChain.Add([pscustomobject][ordered]@{
            Stage     = 'PackageForTheWeb'
            Target    = [IO.Path]::GetRelativePath($ExtractedPath, $NestedSetupFile.FullName)
            Arguments = $null
            Evidence  = 'Unique root Setup.exe in the validated PackageForTheWeb cabinet'
          })
      }
      if ($NestedPayloadPath) {
        $LaunchChain.Add([pscustomobject][ordered]@{
            Stage     = 'InstallShield setup launcher'
            Target    = $NestedPayloadPath
            Arguments = $ConfiguredCommandLine
            Evidence  = $MsiPayloadSelection.SelectedMsiPath ? 'Setup.ini package Location' : 'Sole extracted InstallScript program'
          })
      }
      [pscustomobject][ordered]@{
        Cabinet                 = $PackageForTheWebCabinet
        SetupIniPath            = $MsiPayloadSelection.SetupIniPath
        Product                 = $Configuration ? ((Get-InstallShieldIniValue -Configuration $Configuration -Section 'Startup' -Name 'Product') ?? (Get-InstallShieldIniValue -Configuration $Configuration -Section 'Startup' -Name 'AppName')) : $null
        ProductGuid             = $Configuration ? (Get-InstallShieldIniValue -Configuration $Configuration -Section 'Startup' -Name 'ProductGUID') : $null
        ConfiguredCommandLine   = $ConfiguredCommandLine
        PackageName             = $Configuration ? (Get-InstallShieldIniValue -Configuration $Configuration -Section 'Startup' -Name 'PackageName') : $null
        NestedSetupPath         = $NestedSetupFile ? [IO.Path]::GetRelativePath($ExtractedPath, $NestedSetupFile.FullName) : $null
        NestedSetupResolvedPath = $NestedSetupFile ? $NestedSetupFile.FullName : $null
        NestedPayloadPath       = $NestedPayloadPath
        NestedPayloadKind       = $NestedPayloadKind
        LaunchChain             = [object[]]$LaunchChain
        ExtractedFiles          = [string[]]@($ExtractedFiles | ForEach-Object { [IO.Path]::GetRelativePath($ExtractedPath, $_.FullName) })
      }
    } else { $null }
    # Setup.ini is authoritative for setup-level prerequisites. MSI table rows
    # retain feature prerequisite evidence, so merge both sources while
    # suppressing only exact duplicate names.
    $SetupPrerequisiteReferences = $MsiPayloadSelection.Configuration ? [object[]]@(
      Get-InstallShieldSetupPrerequisiteReference -Configuration $MsiPayloadSelection.Configuration
    ) : [object[]]@()
    $MsiPrerequisiteReferences = $SelectedMsiInfo ? [object[]]@($SelectedMsiInfo.InstallShieldPrerequisiteReferences) : [object[]]@()
    $PrerequisiteReferenceList = [Collections.Generic.List[object]]::new()
    $SeenPrerequisiteReferences = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($PrerequisiteReference in @($SetupPrerequisiteReferences) + @($MsiPrerequisiteReferences)) {
      $ReferenceName = [string]$PrerequisiteReference.Name
      if ([string]::IsNullOrWhiteSpace($ReferenceName) -or -not $SeenPrerequisiteReferences.Add($ReferenceName)) { continue }
      $PrerequisiteReferenceList.Add($PrerequisiteReference)
    }
    $PrerequisiteReferences = [object[]]$PrerequisiteReferenceList
    $PrerequisiteEvidence = [object[]]@(Join-InstallShieldPrerequisiteEvidence -Reference $PrerequisiteReferences -Definition ([object[]]$PrerequisiteDefinitions))
    foreach ($PrerequisiteWarning in @($PrerequisiteEvidence | Where-Object { $_.Reference -and $_.Warning } | ForEach-Object Warning)) {
      $ClassificationWarnings.Add($PrerequisiteWarning)
    }
    $ElevationRequirementEvidence = Get-InstallShieldElevationInfo `
      -RequestedExecutionLevel $Context.RequestedExecutionLevel `
      -PrerequisiteEvidence $PrerequisiteEvidence
    foreach ($ElevationWarning in @($ElevationRequirementEvidence.Warnings)) {
      $ClassificationWarnings.Add($ElevationWarning)
    }

    # The InstallShield launcher classification does not prove which nested
    # package owns ARP. Get-InstallShieldMsiInfo supplies identity only after
    # Setup.ini has selected an MSI payload.
    $Result = [pscustomobject][ordered]@{
      Path                               = $InstallerPath
      InstallerType                      = 'InstallShield'
      ProductCode                        = $null
      UpgradeCode                        = $null
      DisplayName                        = $null
      DisplayVersion                     = $null
      Publisher                          = $null
      Scope                              = $null
      ElevationRequirement               = $ElevationRequirementEvidence.ElevationRequirement
      RequestedExecutionLevel            = $Context.RequestedExecutionLevel
      ElevationRequirementEvidence       = $ElevationRequirementEvidence
      DefaultInstallLocation             = $null
      UninstallString                    = $null
      QuietUninstallString               = $null
      DisplayIcon                        = $null
      URLInfoAbout                       = $null
      HelpLink                           = $null
      WritesAppsAndFeaturesEntry         = $null
      AppsAndFeaturesProductCode         = $null
      AppsAndFeaturesInstallerType       = $null
      Warnings                           = [string[]]@($PayloadSelectionWarnings + $InstallShieldCabinetSupport.Warnings + $ClassificationWarnings + @($SelectedMsiInfo.InstallShieldScriptInfo.Warnings) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
      UnresolvedFields                   = [string[]]@()
      AppsAndFeaturesEntries             = [object[]]@()
      RegistryWrites                     = [object[]]@()
      RegistryItems                      = [object[]]@()
      MediaRegistrySets                  = [object[]]@()
      MediaRegistryWrites                = [object[]]@()
      ConditionalMediaRegistryWrites     = [object[]]@()
      CabinetFileGroups                  = [object[]]$InstallShieldCabinetSupport.CabinetFileGroups
      CabinetComponents                  = [object[]]$InstallShieldCabinetSupport.CabinetComponents
      MediaSetupTypes                    = [object[]]$InstallShieldCabinetSupport.MediaSetupTypes
      MediaShellFolders                  = [object[]]@()
      MediaShortcuts                     = [object[]]@()
      ConditionalMediaShortcuts          = [object[]]@()
      ConditionalRegistryAssociationInfo = $null
      ConditionalProtocols               = [string[]]@()
      ConditionalFileExtensions          = [string[]]@()
      Protocols                          = [string[]]@()
      FileExtensions                     = [string[]]@()
      ProtocolAssociations               = [object[]]@()
      FileExtensionAssociations          = [object[]]@()
      RegistryAssociationInfo            = $null
      ExecutedPayloads                   = [object[]]@()
      FileOperations                     = [object[]]@()
      DllOperations                      = [object[]]@()
      PropertyHandlers                   = [object[]]@()
      Shortcuts                          = [object[]]@()
      StaticCalls                        = [object[]]@()
      OpcodeCoverage                     = [object[]]@()
      UnsupportedOpcodes                 = [string[]]@()
      ExtractedPath                      = $ExtractedPath
      ExtractedFiles                     = [string[]]@($ExtractedFiles | Select-Object -ExpandProperty FullName)
      ContainerFormat                    = $ContainerFormat
      PackageForTheWebCabinet            = $PackageForTheWebCabinet
      PackageForTheWebInfo               = $PackageForTheWebInfo
      Classic3EngineInfo                 = $Context.Classic3EngineInfo
      ExternalMediaInfo                  = $Context.ExternalMediaInfo
      InstallShieldCabinetSupport        = $InstallShieldCabinetSupport
      Variant                            = $Variant
      HasMsi                             = [bool]$MsiFiles
      HasInstallScript                   = [bool]($InxFiles -or $SelectedMsiInfo.HasInstallScript)
      MsiFiles                           = @($MsiFiles | Select-Object -ExpandProperty FullName)
      SetupIniPath                       = $MsiPayloadSelection.SetupIniPath
      SetupConfiguration                 = $MsiPayloadSelection.Configuration
      MsiPayloadSelection                = $MsiPayloadSelection
      SelectedMsiPath                    = $MsiPayloadSelection.SelectedMsiPath
      SelectedMsiInfo                    = $SelectedMsiInfo
      InstallShieldProjectType           = $InstallShieldProjectType
      InstallShieldProjectTypeEvidence   = $SelectedMsiInfo.InstallShieldProjectTypeEvidence
      InstallShieldLauncherRequirement   = $SelectedMsiInfo.InstallShieldLauncherRequirement
      PrerequisiteDefinitions            = [object[]]$PrerequisiteDefinitions
      PrerequisiteReferences             = $PrerequisiteReferences
      PrerequisiteEvidence               = $PrerequisiteEvidence
      InxFiles                           = @($InxFiles | Select-Object -ExpandProperty FullName)
      OblFiles                           = @($OblFiles | Select-Object -ExpandProperty FullName)
      InstallScriptLibraries             = [object[]]$Context.InstallScriptLibraries
      CabFiles                           = @($CabFiles | Select-Object -ExpandProperty FullName)
      SfxFiles                           = @($SfxFiles | Select-Object -ExpandProperty FullName)
      InstallScriptInfo                  = $SelectedMsiInfo.InstallShieldScriptInfo
      SilentSupport                      = $null
      ResponseFileRequirement            = $null
      SilentSwitches                     = [string[]]@()
      AdvancedUiInfo                     = $AdvancedUiInfo
      SuitePackages                      = $AdvancedUiInfo ? [object[]]@($AdvancedUiInfo.Packages) : [object[]]@()
      InstallShieldRelease               = $null
      InstallShieldStructuralRoutes      = [object[]]@()
    }

    if ($AdvancedUiInfo) {
      # Advanced UI owns its ARP identity through SuiteId. Nested MSI metadata
      # describes parcel installation only and must not replace the outer key.
      $Result = Merge-InstallShieldAdvancedUiResult -Result $Result -AdvancedUiInfo $AdvancedUiInfo
    }

    # Advanced UI CallInstallScript actions name the exact compiled functions
    # dispatched by suite events. Analyze only those roots and keep suite ARP
    # identity and command-line behavior authoritative.
    if ($AdvancedUiInfo -and $AdvancedUiInfo.InstallScriptEntryPoints -and $InxFiles -and (Get-Command Get-InstallShieldInstallScriptInfo -ErrorAction SilentlyContinue)) {
      try {
        $InstallScriptInfo = Get-InstallShieldInstallScriptInfo -Installer $Result `
          -EntryPoint $AdvancedUiInfo.InstallScriptEntryPoints -AnalysisScope EmbeddedAction
        $Result = Merge-InstallShieldInstallScriptResult -Result $Result -InstallScriptInfo $InstallScriptInfo -Supplemental
      } catch {
        $Result.Warnings = [string[]]@($Result.Warnings + "Advanced UI InstallScript action analysis failed: $($_.Exception.Message)")
      }
      # Reuse this extraction and analyze setup.inx/setup.iss once for a
      # standalone InstallScript package, where the script owns ARP and silent behavior.
    } elseif (-not $AdvancedUiInfo -and $InxFiles -and (Get-Command Get-InstallShieldInstallScriptInfo -ErrorAction SilentlyContinue)) {
      try {
        $InstallScriptInfo = Get-InstallShieldInstallScriptInfo -Installer $Result
        $Result = Merge-InstallShieldInstallScriptResult -Result $Result -InstallScriptInfo $InstallScriptInfo
      } catch {
        $Result.Warnings = [string[]]@($Result.Warnings + "InstallScript analysis failed: $($_.Exception.Message)")
      }
    }
    $Result.InstallShieldStructuralRoutes = Get-InstallShieldStructuralRoute -Context $Context -Result $Result
    $Result.InstallShieldRelease = Resolve-InstallShieldRelease -Evidence (Get-InstallShieldReleaseEvidenceFromContext -Context $Context)
    $Result.Warnings = [string[]]@($Result.Warnings + $Result.InstallShieldRelease.Warnings | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
    return $Result
  }
}

Export-ModuleMember -Function Get-InstallShieldInfo, Get-InstallShieldProjectReleaseInfo, Get-InstallShieldAdvancedUiInfo, Get-InstallShieldAdvancedUiPackageEligibility, Get-InstallShieldAdvancedUiNestedPackageInfo, Resolve-InstallShieldSuiteCondition, Get-InstallShieldPrerequisiteInfo, Expand-InstallShield, Expand-InstallShieldInstaller, Expand-InstallShieldCabinet, Get-InstallShieldMsiInfo, Read-ProductVersionFromInstallShield, Read-ProductCodeFromInstallShield, Read-UpgradeCodeFromInstallShield
