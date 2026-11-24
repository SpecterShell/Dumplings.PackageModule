# SPDX-License-Identifier: Apache-2.0
# Versionless installer tracking. HTTP validators are bandwidth-saving hints;
# accepted version evidence belongs to SHA256-confirmed bytes, never to a probe.
# No installer or extracted payload is executed by this module.
#Requires -Version 7.4

function Get-InstallerTrackingValue {
  param ($Object, [string]$Name)
  if ($null -eq $Object) { return $null }
  if ($Object -is [Collections.IDictionary]) { return $Object[$Name] }
  $Property = $Object.PSObject.Properties[$Name]
  if ($Property) { return $Property.Value }
}

function Get-InstallerTrackingDigest {
  param ([string]$Value)
  return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($Value)))
}

function Get-InstallerTrackingFileIdentity {
  <#
  .SYNOPSIS
    Identify a local artifact for operation-owned hash reuse.
  .PARAMETER Path
    Existing filesystem file; resolved against PowerShell's location.
  .OUTPUTS
    Absolute path, length, creation time, and last-write time. This is a cache
    invalidation stamp, not proof against adversarial timestamp restoration.
  #>
  param ([Parameter(Mandatory)][string]$Path)
  $File = Get-Item -LiteralPath $Path -ErrorAction Stop
  if ($File -isnot [IO.FileInfo]) { throw 'Installer tracking requires a filesystem file.' }
  return "$($File.FullName)|$($File.Length)|$($File.CreationTimeUtc.Ticks)|$($File.LastWriteTimeUtc.Ticks)"
}

function Get-InstallerTrackingKey {
  param ([Collections.IDictionary]$Installer, [string]$Key)
  if (-not [string]::IsNullOrWhiteSpace($Key)) { return $Key }
  if ($Installer.Contains('Query')) { throw 'Query-based installer selectors require an explicit tracking Key.' }
  $Selectors = [ordered]@{}
  foreach ($Name in 'InstallerLocale', 'Architecture', 'InstallerType', 'NestedInstallerType', 'Scope') {
    if (-not $Installer.Contains($Name)) { continue }
    if ($Installer[$Name] -isnot [string]) { throw 'Query-based installer selectors require an explicit tracking Key.' }
    $Selectors[$Name] = $Installer[$Name]
  }
  return 'auto:' + (Get-InstallerTrackingDigest ($Selectors | ConvertTo-Json -Compress))
}

function Get-InstallerTrackingRequestIdentity {
  param ([uri]$Uri, [Collections.IDictionary]$Options)
  # Canonicalize request settings, including callback identity. Only the digest
  # is persisted: headers, credentials, callback source and URLs stay transient.
  $Headers = [ordered]@{}
  foreach ($Name in @($Options.Headers.Keys | Sort-Object -CaseSensitive)) {
    $Headers[$Name.ToLowerInvariant()] = [string[]]@($Options.Headers[$Name])
  }
  $Identity = [ordered]@{ Uri = $Uri.AbsoluteUri; Headers = $Headers }
  foreach ($Name in 'Method', 'Proxy', 'UserAgent', 'RequestKey', 'Probe', 'Download') { $Identity[$Name] = [string]$Options[$Name] }
  return Get-InstallerTrackingDigest ($Identity | ConvertTo-Json -Depth 8 -Compress)
}

function ConvertTo-InstallerTrackingValidator {
  param ([string]$Kind, [AllowNull()]$Value)
  if ($null -eq $Value -or @($Value).Count -ne 1) { return $null }
  if ($Kind -eq 'LastModified') {
    if ($Value -is [DateTimeOffset]) { return $Value.ToUniversalTime().ToString('o') }
    if ($Value -is [datetime]) {
      if ($Value.Kind -eq [DateTimeKind]::Unspecified) { $Value = [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc) }
      return ([DateTimeOffset]$Value).ToUniversalTime().ToString('o')
    }
  }
  $Text = [string]@($Value)[0]
  if ([string]::IsNullOrWhiteSpace($Text) -or $Text -match '[\x00-\x1f\x7f]') { return $null }
  switch ($Kind) {
    'LastModified' {
      $Date = [DateTimeOffset]::MinValue
      if ([DateTimeOffset]::TryParse($Text, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$Date)) { return $Date.ToUniversalTime().ToString('o') }
      return $null
    }
    'ContentLength' {
      $Length = 0L
      if ([long]::TryParse($Text, [Globalization.NumberStyles]::None, [Globalization.CultureInfo]::InvariantCulture, [ref]$Length) -and $Length -ge 0) { return $Length.ToString([Globalization.CultureInfo]::InvariantCulture) }
      return $null
    }
    default { return $Text }
  }
}

function Get-InstallerTrackingValidator {
  param ($Response, [Collections.IDictionary]$Options)
  $Headers = [hashtable]::new([StringComparer]::OrdinalIgnoreCase)
  $InputHeaders = Get-InstallerTrackingValue $Response Headers
  if ($InputHeaders) { foreach ($Name in $InputHeaders.Keys) { $Headers[$Name] = $InputHeaders[$Name] } }
  $Kinds = if ($Options.Validator -eq 'Auto') { @('Header', 'ETag', 'LastModified', 'ContentLength') } else { @($Options.Validator) }
  foreach ($Kind in $Kinds) {
    $Name = switch ($Kind) {
      Header { [string]$Options.HeaderName }
      ETag { 'ETag' }
      LastModified { 'Last-Modified' }
      ContentLength { 'Content-Length' }
      Hash { '' }
    }
    if (-not $Name) { continue }
    $RawValue = $Headers[$Name]
    if ($Kind -eq 'Header' -and $Options.SelectValue) { $RawValue = & $Options.SelectValue $RawValue }
    $Value = ConvertTo-InstallerTrackingValidator $Kind $RawValue
    if ($null -ne $Value) { return [ordered]@{ Kind = $Kind; Name = $Name; Value = $Value } }
  }
  return [ordered]@{ Kind = 'Hash'; Name = 'SHA256'; Value = $null }
}

function Invoke-InstallerTrackingProbe {
  param ([uri]$Uri, [Collections.IDictionary]$Options)
  if ($Options.Probe) { $Response = & $Options.Probe $Uri $Options }
  else {
    $Arguments = @{ Uri = $Uri; Method = $Options.Method; Header = $Options.Headers }
    foreach ($Name in 'UserAgent', 'Proxy') { if ($Options.Contains($Name)) { $Arguments[$Name] = $Options[$Name] } }
    $Response = Get-WinGetWinINetResponseHeader @Arguments
    if ($Arguments.Method -eq 'HEAD' -and $Response.StatusCode -in 405, 501) {
      $Arguments.Method = 'GET'
      $Response = Get-WinGetWinINetResponseHeader @Arguments
    }
  }
  $Status = Get-InstallerTrackingValue $Response StatusCode
  if ($null -eq $Status -or [int]$Status -ne 200) { throw "Installer tracking probe failed (HTTP $Status); no validator was accepted." }
  return $Response
}

function Get-InstallerTrackingLegacyRecord {
  param ($Task, [Collections.IDictionary]$Options)
  $Mapping = $Options.LegacyState
  if (-not $Mapping) { return $null }
  if ($Mapping -isnot [Collections.IDictionary] -or -not $Mapping.Contains('ValidatorField')) { throw 'LegacyState requires ValidatorField and, for multiple old installers, InstallerIndex.' }
  if ($Mapping.ValidatorField -isnot [string] -or [string]::IsNullOrWhiteSpace($Mapping.ValidatorField) -or $Mapping.ValidatorField -in 'Version', 'RealVersion', 'Installer', 'Locale', 'InstallerTracking', 'ReleaseTime') { throw 'LegacyState.ValidatorField must name a dedicated validator field.' }
  if ($Options.Validator -eq 'Auto') { throw 'LegacyState requires an explicit validator, not Auto.' }
  if ($Task.LastState['InstallerTracking']) { return $null }
  $OldInstallers = @($Task.LastState.Installer)
  if ($Mapping.Contains('InstallerIndex')) { $Index = [int]$Mapping.InstallerIndex }
  elseif ($OldInstallers.Count -eq 1) { $Index = 0 }
  else { return $null }
  if ($Index -lt 0 -or $Index -ge $OldInstallers.Count) { return $null }
  $Old = $OldInstallers[$Index]
  # Legacy state can identify previous bytes, but cannot prove which request or
  # version reader produced them. Verify once before trusting the new fast path;
  # this also catches old multi-architecture scripts that read only one version.
  $Kind = $Options.Validator
  $Values = [Collections.Generic.List[string]]::new()
  foreach ($Raw in @($Task.LastState[$Mapping.ValidatorField])) {
    $Value = ConvertTo-InstallerTrackingValidator $Kind $Raw
    if ($null -ne $Value) { $Values.Add($Value) }
  }
  $Validator = Get-InstallerTrackingValidator $null $Options
  $Name = switch ($Kind) { Header { $Options.HeaderName } ETag { 'ETag' } LastModified { 'Last-Modified' } ContentLength { 'Content-Length' } default { $Validator.Name } }
  return [ordered]@{
    RequestIdentity = ''
    SourceIdentity = Get-InstallerTrackingDigest ([string]$Old.InstallerUrl)
    ValidatorKind = $Kind; ValidatorName = $Name; AcceptedValues = $Values.ToArray()
    Sha256 = [string]$Old.InstallerSha256; Version = [string]$Task.LastState.Version
    RealVersion = [string]$Task.LastState['RealVersion']
    VersionReaderIdentity = ''
  }
}

function Get-PackageTaskInstallerUpdate {
  <#
  .SYNOPSIS
    Prepare a versionless PackageTask decision without publishing or persisting it.
  .PARAMETER Task
    PackageTask supplying LastState, CurrentState and existing InstallerFiles.
  .PARAMETER Options
    Validator (Auto/ETag/LastModified/ContentLength/Header/Hash), required
    ReadVersion(Path, Installer), HeaderName, SelectValue(values), Method,
    Headers, UserAgent, Proxy, Probe(Uri, Options), Download(Uri, DestinationPath,
    Options), RequestKey, VersionKey, AllowRollback and per-entry Installers overrides.
    Overrides require InstallerIndex; Key disambiguates nonliteral selectors.
    LegacyState maps ValidatorField and optional old InstallerIndex explicitly.
  .PARAMETER Force
    Re-download and read every artifact, ignoring accepted validators and hashes.
  .OUTPUTS
    A runtime-only decision with CandidateState, artifact evidence, file ownership,
    and action flags. PackageTask owns applying and completing this decision.
    Custom downloads return Path, OwnsFile (false by default), and optional Response
    with StatusCode/Headers/RequestUri. Supplied hashes are never blindly trusted.
  #>
  [CmdletBinding()]
  param ([Parameter(Mandatory)]$Task, [Parameter(Mandatory)][Collections.IDictionary]$Options, [switch]$Force)

  $Allowed = @('Validator', 'ReadVersion', 'HeaderName', 'SelectValue', 'Method', 'Headers', 'UserAgent', 'Proxy', 'Probe', 'Download', 'RequestKey', 'VersionKey', 'AllowRollback', 'Installers', 'Key', 'LegacyState', 'InstallerIndex')
  foreach ($Name in $Options.Keys) { if ($Name -notin $Allowed -or $Name -eq 'InstallerIndex') { throw "Unknown installer tracking option '$Name'." } }
  $Defaults = @{ Validator = 'Auto'; Method = 'HEAD'; Headers = @{} }
  foreach ($Name in $Options.Keys) { $Defaults[$Name] = $Options[$Name] }
  $Overrides = @{}
  foreach ($Override in @($Options.Installers)) {
    if ($null -eq $Override) { continue }
    if ($Override -isnot [Collections.IDictionary] -or -not $Override.Contains('InstallerIndex')) { throw 'An installer tracking override requires InstallerIndex.' }
    foreach ($Name in $Override.Keys) { if ($Name -notin $Allowed -or $Name -in 'Installers', 'AllowRollback') { throw "Unknown per-installer tracking option '$Name'." } }
    $Index = [int]$Override.InstallerIndex
    if ($Index -lt 0 -or $Index -ge $Task.CurrentState.Installer.Count -or $Overrides.Contains($Index)) { throw 'Invalid or duplicate installer tracking override index.' }
    $Overrides[$Index] = $Override
  }
  if ($Task.CurrentState.Installer.Count -eq 0) { throw 'Installer tracking requires at least one installer.' }
  $Tracking = $Task.LastState['InstallerTracking']
  if ($Tracking -and ($Tracking -isnot [Collections.IDictionary] -or $Tracking.SchemaVersion -ne 1 -or $Tracking.Artifacts -isnot [Collections.IDictionary])) { throw 'Unsupported or malformed InstallerTracking state.' }
  $Candidate = Copy-Object $Task.CurrentState
  $NewTracking = [ordered]@{ SchemaVersion = 1; Artifacts = [ordered]@{} }
  $Records = [Collections.Generic.List[object]]::new()
  $Keys = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $OwnedFiles = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $Files = [ordered]@{}
  $FileEvidence = [ordered]@{}
  $Requests = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
  $DownloadIdentities = @{}
  $KeepFiles = $false
  $Messages = [Collections.Generic.List[string]]::new()
  try {
    # Validate all selectors/options before any network activity. Each entry keeps
    # its own version reader even when several entries share physical bytes.
    for ($Index = 0; $Index -lt $Candidate.Installer.Count; $Index++) {
      $Installer = $Candidate.Installer[$Index]
      $Settings = Copy-Object $Defaults
      if ($Overrides.Contains($Index)) { foreach ($Name in $Overrides[$Index].Keys) { $Settings[$Name] = $Overrides[$Index][$Name] } }
      if ($Settings.Validator -notin 'Auto', 'ETag', 'LastModified', 'ContentLength', 'Header', 'Hash') { throw 'Unknown installer tracking validator.' }
      if ($Settings.Method -notin 'HEAD', 'GET') { throw 'Installer tracking Method must be HEAD or GET.' }
      if ($Settings.ReadVersion -isnot [scriptblock]) { throw 'Installer tracking requires a ReadVersion scriptblock.' }
      if ($Settings.Headers -isnot [Collections.IDictionary]) { throw 'Installer tracking Headers must be a dictionary.' }
      foreach ($Name in 'Probe', 'Download', 'SelectValue') { if ($Settings[$Name] -and $Settings[$Name] -isnot [scriptblock]) { throw "$Name must be a scriptblock." } }
      if (($Settings.Probe -or $Settings.Download) -and [string]::IsNullOrWhiteSpace($Settings.RequestKey)) { throw 'Custom Probe/Download callbacks require a stable, non-secret RequestKey.' }
      if ($Settings.Validator -eq 'Header' -and [string]::IsNullOrWhiteSpace($Settings.HeaderName)) { throw 'Header tracking requires HeaderName.' }
      $Uri = $null
      if (-not [uri]::TryCreate([string]$Installer.InstallerUrl, [UriKind]::Absolute, [ref]$Uri) -or $Uri.Scheme -notin 'https', 'http' -or $Uri.UserInfo) { throw 'Installer tracking requires an HTTP(S) URL without embedded credentials.' }
      $Key = Get-InstallerTrackingKey $Installer $Settings.Key
      if (-not $Keys.Add($Key)) { throw 'Ambiguous installer tracking selectors; assign distinct Key values in Installers overrides.' }
      $Identity = Get-InstallerTrackingRequestIdentity $Uri $Settings
      if ($DownloadIdentities.Contains($Uri.AbsoluteUri) -and $DownloadIdentities[$Uri.AbsoluteUri] -cne $Identity) { throw 'Different download requests for the same InstallerUrl cannot share InstallerFiles; use distinct artifact URLs.' }
      $DownloadIdentities[$Uri.AbsoluteUri] = $Identity
      $Previous = Get-InstallerTrackingLegacyRecord -Task $Task -Options $Settings
      if ($Tracking) { $Previous = $Tracking.Artifacts[$Key] }
      if ($null -ne $Previous -and $Previous -isnot [Collections.IDictionary]) { throw 'Malformed installer tracking artifact record.' }
      $Records.Add([pscustomobject]@{ Key = $Key; InstallerIndex = $Index; Uri = $Uri; Options = $Settings; Previous = $Previous; RequestIdentity = $Identity; HasPrevious = $false; SameReader = $false; ReaderIdentity = ''; SourceIdentity = ''; FastMatch = $false })
    }

    $Artifacts = [Collections.Generic.List[object]]::new()
    $BytesChanged = $false
    $UrlsChanged = $false
    $NewTask = $Task.Status.Contains('New') -or [string]::IsNullOrWhiteSpace([string]$Task.LastState.Version)
    $VerifyRequests = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($Record in $Records) {
      $Settings = $Record.Options
      $Previous = $Record.Previous
      $HasPrevious = $Previous -and [string]$Previous.Sha256 -match '^[a-fA-F0-9]{64}$' -and -not [string]::IsNullOrWhiteSpace([string]$Previous.Version)
      $ReaderIdentity = Get-InstallerTrackingDigest ([string]$Settings.ReadVersion + '|' + [string]$Settings.VersionKey)
      $SameReader = $HasPrevious -and $Previous.VersionReaderIdentity -ceq $ReaderIdentity
      $SourceIdentity = Get-InstallerTrackingDigest ([string]$Candidate.Installer[$Record.InstallerIndex].InstallerUrl)
      if ($Previous -and $Previous.SourceIdentity -cne $SourceIdentity) { $UrlsChanged = $true }
      if (-not $Requests.ContainsKey($Record.RequestIdentity)) { $Requests[$Record.RequestIdentity] = @{ Probe = $null; Download = $null } }
      $Request = $Requests[$Record.RequestIdentity]
      $Validator = @{ Kind = 'Hash'; Name = 'SHA256'; Value = $null }
      if ($Settings.Validator -ne 'Hash' -and -not $Force -and -not $NewTask) {
        if (-not $Request.Probe) { $Request.Probe = Invoke-InstallerTrackingProbe $Record.Uri $Settings }
        $Validator = Get-InstallerTrackingValidator $Request.Probe $Settings
      }
      $RegressedDate = $false
      if ($HasPrevious -and $Validator.Kind -eq 'LastModified' -and $Previous.ValidatorKind -eq 'LastModified' -and @($Previous.AcceptedValues).Count) {
        $Newest = @($Previous.AcceptedValues | Sort-Object -Descending)[0]
        $RegressedDate = $Validator.Value -clt $Newest
        if ($RegressedDate) { $Messages.Add("Artifact '$($Record.Key)' returned an older Last-Modified value; verifying its bytes.") }
      }
      $FastMatch = -not $Force -and -not $NewTask -and -not $RegressedDate -and $SameReader -and $Previous.RequestIdentity -ceq $Record.RequestIdentity -and $Validator.Kind -cne 'Hash' -and $Previous.ValidatorKind -ceq $Validator.Kind -and $Previous.ValidatorName -ieq $Validator.Name -and $Validator.Value -cin @($Previous.AcceptedValues)
      $Record.HasPrevious = $HasPrevious
      $Record.SameReader = $SameReader
      $Record.ReaderIdentity = $ReaderIdentity
      $Record.SourceIdentity = $SourceIdentity
      $Record.FastMatch = $FastMatch
      if (-not $FastMatch) { $null = $VerifyRequests.Add($Record.RequestIdentity) }
    }

    # One verified response replaces probe assumptions for every entry sharing
    # those bytes, including entries that could otherwise take the fast path.
    foreach ($Record in $Records) {
      $Settings = $Record.Options
      $Previous = $Record.Previous
      $HasPrevious = $Record.HasPrevious
      $SameReader = $Record.SameReader
      $ReaderIdentity = $Record.ReaderIdentity
      $SourceIdentity = $Record.SourceIdentity
      $Request = $Requests[$Record.RequestIdentity]
      $FastMatch = $Record.FastMatch -and -not $VerifyRequests.Contains($Record.RequestIdentity)
      $Path = $null
      if ($FastMatch) {
        $Sha256 = [string]$Previous.Sha256
        $Version = [string]$Previous.Version
        $RealVersion = [string]$Previous.RealVersion
        # Persist only the tracking contract, even when an old record contains
        # unrelated properties. Runtime response objects must never leak to YAML.
        $State = [ordered]@{}
        foreach ($Name in 'RequestIdentity', 'SourceIdentity', 'VersionReaderIdentity', 'ValidatorKind', 'ValidatorName', 'AcceptedValues', 'Sha256', 'Version', 'RealVersion') { $State[$Name] = Copy-Object $Previous[$Name] }
      } else {
        if (-not $Request.Download) {
          $Destination = New-TempFile
          $null = $OwnedFiles.Add($Destination)
          if ($Settings.Download) {
            $Downloaded = & $Settings.Download $Record.Uri $Destination $Settings
            $Path = [string](Get-InstallerTrackingValue $Downloaded Path)
            if ([string]::IsNullOrWhiteSpace($Path)) { throw 'Custom Download must return Path, optional OwnsFile, and optional Response.' }
            $Path = (Get-Item -LiteralPath $Path -ErrorAction Stop).FullName
            if (Get-InstallerTrackingValue $Downloaded OwnsFile) { $null = $OwnedFiles.Add($Path) }
            $Response = Get-InstallerTrackingValue $Downloaded Response
            $IdentityBefore = Get-InstallerTrackingFileIdentity $Path
            $Sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
          } else {
            $Arguments = @{ Uri = $Record.Uri; DestinationPath = $Destination; Header = $Settings.Headers }
            foreach ($Name in 'UserAgent', 'Proxy') { if ($Settings.Contains($Name)) { $Arguments[$Name] = $Settings[$Name] } }
            $Downloaded = Invoke-WinGetInstallerDownload @Arguments
            $Path = (Get-Item -LiteralPath $Downloaded.DestinationPath -ErrorAction Stop).FullName
            $null = $OwnedFiles.Add($Path)
            $IdentityBefore = Get-InstallerTrackingFileIdentity $Path
            $Sha256 = $Downloaded.Sha256
            if ([string]$Sha256 -notmatch '^[a-fA-F0-9]{64}$') { $Sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash }
            $Response = ConvertFrom-WinGetDownloadResponseHeader -Result $Downloaded -Uri $Record.Uri
            # The native downloader has already validated complete-file success.
            # DO may omit HTTP evidence, or expose a successful range response.
            # Neither absence nor a partial Content-Length proves a validator.
            if ($null -eq $Response.StatusCode) { $Response = $null }
            elseif ($Response.StatusCode -eq 206) { $Response.Headers.Remove('Content-Length') }
          }
          if ($Response -and [int](Get-InstallerTrackingValue $Response StatusCode) -ne 200 -and ($Settings.Download -or [int]$Response.StatusCode -ne 206)) { throw 'Downloaded installer response did not have an accepted HTTP success status.' }
          if ($IdentityBefore -cne (Get-InstallerTrackingFileIdentity $Path)) { throw 'Installer changed while its hash was being calculated.' }
          $Request.Download = @{ Path = $Path; Sha256 = $Sha256.ToUpperInvariant(); Response = $Response; Identity = $IdentityBefore }
        }
        $File = $Request.Download
        $Path = $File.Path
        $Sha256 = $File.Sha256
        $SameBytes = $HasPrevious -and $Sha256 -ieq $Previous.Sha256
        if (-not $SameBytes) { $BytesChanged = $true }
        if ($SameBytes -and $SameReader -and -not $Force) { $Version = [string]$Previous.Version; $RealVersion = [string]$Previous.RealVersion }
        else {
          $Resolved = & $Settings.ReadVersion $Path (Copy-Object $Candidate.Installer[$Record.InstallerIndex])
          if ($Resolved -is [string]) { $Version = $Resolved; $RealVersion = '' }
          elseif ($Resolved -is [Collections.IDictionary] -or $Resolved -is [pscustomobject]) { $Version = [string](Get-InstallerTrackingValue $Resolved Version); $RealVersion = [string](Get-InstallerTrackingValue $Resolved RealVersion) }
          else { throw 'ReadVersion must return exactly one version string or a Version/RealVersion record.' }
          if ([string]::IsNullOrWhiteSpace($Version)) { throw 'ReadVersion returned an empty version.' }
        }
        if ($File.Identity -cne (Get-InstallerTrackingFileIdentity $Path)) { throw 'ReadVersion modified its installer input.' }
        $Files[[string]$Candidate.Installer[$Record.InstallerIndex].InstallerUrl] = $Path
        $FileEvidence[$Path] = [ordered]@{ Identity = $File.Identity; Sha256 = $Sha256 }
        $Validator = Get-InstallerTrackingValidator $File.Response $Settings
        $Accepted = [Collections.Generic.List[string]]::new()
        if ($SameBytes -and $Previous.RequestIdentity -ceq $Record.RequestIdentity -and $Previous.ValidatorKind -ceq $Validator.Kind -and $Previous.ValidatorName -ieq $Validator.Name) {
          foreach ($Value in @($Previous.AcceptedValues)) { if ($Value -cne $Validator.Value -and -not [string]::IsNullOrWhiteSpace($Value)) { $Accepted.Add($Value) } }
        }
        if ($null -ne $Validator.Value) { $Accepted.Add($Validator.Value) }
        while ($Accepted.Count -gt 16) { $Accepted.RemoveAt(0) }
        $State = [ordered]@{ RequestIdentity = $Record.RequestIdentity; SourceIdentity = $SourceIdentity; VersionReaderIdentity = $ReaderIdentity; ValidatorKind = $Validator.Kind; ValidatorName = $Validator.Name; AcceptedValues = $Accepted.ToArray(); Sha256 = $Sha256; Version = $Version; RealVersion = $RealVersion }
      }
      $Candidate.Installer[$Record.InstallerIndex]['InstallerSha256'] = $Sha256
      $NewTracking.Artifacts[$Record.Key] = $State
      $Artifacts.Add([pscustomobject]@{ Key = $Record.Key; InstallerIndex = $Record.InstallerIndex; Downloaded = -not $FastMatch; Path = $Path; Sha256 = $Sha256; Version = $Version; RealVersion = $RealVersion })
    }

    # Reject staggered architecture releases before replacing any accepted state.
    $Version = $Artifacts[0].Version
    $RealVersion = $Artifacts[0].RealVersion
    foreach ($Artifact in $Artifacts) {
      if ($Artifact.Version -cne $Version -or $Artifact.RealVersion -cne $RealVersion) { throw 'Tracked installers report inconsistent Version/RealVersion values; accepted state is retained.' }
    }
    $Candidate.Version = $Version
    if ($RealVersion) { $Candidate['RealVersion'] = $RealVersion } else { $Candidate.Remove('RealVersion') }
    $Candidate['InstallerTracking'] = $NewTracking
    # Only explicitly mapped legacy keys are retired, never arbitrary task data.
    foreach ($Record in $Records) { if ($Record.Options.LegacyState) { $Candidate.Remove([string]$Record.Options.LegacyState.ValidatorField) } }
    $Comparison = if ($NewTask) { 0 } else { ([ChunkVersion]$Version).CompareTo([ChunkVersion]$Task.LastState.Version) }
    if ($Tracking -and $Tracking.Artifacts.Count -ne $NewTracking.Artifacts.Count) { $UrlsChanged = $true }
    $Outcome = if ($Force) { 'Forced' } elseif ($NewTask) { 'New' } elseif ($Comparison -lt 0) { 'Rollbacked' } elseif ($Comparison -gt 0 -or $RealVersion -cne [string]$Task.LastState['RealVersion']) { 'Updated' } elseif ($BytesChanged) { 'Rebuilt' } elseif ($UrlsChanged) { 'Changed' } elseif (-not (Test-ObjectValueEqual $Tracking $NewTracking)) { 'EvidenceChanged' } else { 'Unchanged' }
    $AllowedRollback = [bool]$Options.AllowRollback
    $Accepted = $Outcome -ne 'Rollbacked' -or $AllowedRollback
    if (-not $Accepted) { $Messages.Add("Installer version regressed from '$($Task.LastState.Version)' to '$Version'; accepted state is retained.") }
    if ($Outcome -in 'Unchanged', 'EvidenceChanged') {
      # Header churn must not erase locale/ARP fields absent from today's discovery.
      $Candidate = Copy-Object $Task.LastState
      $Candidate['InstallerTracking'] = $NewTracking
      foreach ($Record in $Records) { if ($Record.Options.LegacyState) { $Candidate.Remove([string]$Record.Options.LegacyState.ValidatorField) } }
    }
    $Publish = $Outcome -in 'Forced', 'Updated', 'Rebuilt' -or ($Outcome -eq 'Rollbacked' -and $AllowedRollback)
    $KeepFiles = $Accepted
    return [pscustomobject]@{
      Outcome = $Outcome; NeedsMetadata = $Accepted -and $Outcome -in 'Forced', 'New', 'Updated', 'Rebuilt', 'Changed', 'Rollbacked'
      ShouldWrite = $Accepted -and $Outcome -ne 'Unchanged'; ShouldMessage = $Publish -or $Outcome -eq 'Changed'; ShouldSubmit = $Publish
      Accepted = $Accepted; CandidateState = $Candidate; Artifacts = $Artifacts.ToArray(); Warnings = $Messages.ToArray()
      Files = $Files; FileEvidence = $FileEvidence; OwnedFiles = [string[]]@($OwnedFiles); Completed = $false
    }
  } finally {
    foreach ($Path in $OwnedFiles) {
      if ((-not $KeepFiles -or $Path -notin @($Files.Values)) -and (Test-Path -LiteralPath $Path)) { Remove-Item -LiteralPath $Path -Force -ErrorAction Continue }
    }
  }
}

Export-ModuleMember -Function Get-PackageTaskInstallerUpdate, Get-InstallerTrackingFileIdentity
