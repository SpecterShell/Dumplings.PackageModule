# SPDX-License-Identifier: Apache-2.0
# Public Chromium Setup facade over mini-installer and Updater/Omaha formats.

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }
$UpdaterPath = Join-Path $PSScriptRoot 'ChromiumUpdater.psm1'
$UpdaterModule = Get-Module ChromiumUpdater | Where-Object Path -EQ $UpdaterPath | Select-Object -First 1
if (-not $UpdaterModule) { $UpdaterModule = Import-Module $UpdaterPath -Global -PassThru }
foreach ($Entry in $UpdaterModule.ExportedVariables.GetEnumerator()) {
  Set-Variable -Scope Script -Name $Entry.Key -Value $Entry.Value.Value
}
$Script:UpdaterConfiguration = Get-ChromiumParserConfiguration

$MiniInstallerPath = Join-Path $PSScriptRoot 'ChromiumMiniInstaller.psm1'
if (-not (Get-Module ChromiumMiniInstaller | Where-Object Path -EQ $MiniInstallerPath)) {
  Import-Module $MiniInstallerPath -Global
}

function Get-ChromiumSetupInfoFromContext {
  <#
  .SYNOPSIS
    Classify and read static metadata from Chromium-family setup wrappers
  .PARAMETER Context
    An open Chromium setup parser context
  .PARAMETER SkipOfflineManifest
    Skip expensive Omaha payload decoding when only the outer resource layout is needed
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Context,
    [Parameter(DontShow)][switch]$SkipOfflineManifest
  )

  $Resources = $Context.Resources
  $VersionInfo = $Context.VersionInfo
  $Tag = $Context.Tag
  $LayoutEvidence = $Context.Evidence
  $Variant = $LayoutEvidence.Variant
  $MiniArchive = $LayoutEvidence.MiniArchive
  $MiniSetup = $LayoutEvidence.MiniSetup
  $MiniArchiveResourceName = if ($MiniArchive) { [string]$MiniArchive.Name } else { $null }
  $MiniSetupResourceName = if ($MiniSetup) { [string]$MiniSetup.Name } else { $null }
  $MiniArchiveFileName = if ($MiniArchive) { ($MiniArchive.Name -replace '(?i)\.packed(?=\.7z$)', '').ToLowerInvariant() } else { $null }

  $OfflineManifest = $null
  $OfflineManifestError = $null
  $OfflinePayloadInfo = $null
  # A tag may select either a network application or an application embedded beside the updater.
  # Inspect both supported wrapper formats before classifying the setup as an online bootstrapper.
  $OfflineManifestChecked = ($Variant -eq 'Omaha' -or $Variant -eq 'ChromiumUpdater') -and $Tag.IsTagged -and -not $SkipOfflineManifest
  if ($OfflineManifestChecked) {
    try {
      $OfflinePayloadInfo = if ($Variant -eq 'ChromiumUpdater') {
        Get-ChromiumUpdaterPayloadInfo -Context $Context -ApplicationId $Tag.ApplicationId
      } else {
        Get-ChromiumOmahaPayloadInfo -Resource $LayoutEvidence.OmahaResource.Resource -ApplicationId $Tag.ApplicationId
      }
      $OfflineManifest = $OfflinePayloadInfo.OfflineManifest
    } catch {
      $OfflineManifestError = $_.Exception.Message
    }
  }
  $IsOnlineBootstrapper = if (-not $Tag.IsTagged) { $false } elseif ($OfflineManifest) { $false } elseif ($OfflineManifestChecked -and -not $OfflineManifestError) { $true } else { $null }
  $NestedSetupInfo = $null
  $NestedSetupError = $null
  if ($Variant -eq 'ChromiumMiniInstaller') {
    try {
      # The outer stub contains only generic launcher metadata. Inspect the exact nested setup.exe
      # selected by mini_installer resource precedence for version and install-mode evidence.
      $NestedSetupInfo = Get-ChromiumMiniInstallerNestedSetupInfo -Context $Context
    } catch {
      $NestedSetupError = $_.Exception.Message
    }
  } elseif ($OfflinePayloadInfo) {
    # Tagged offline wrappers contain the target installer named by OfflineManifest.gup. Its own
    # parser result supplies target metadata without treating the updater appguid as ARP identity.
    $NestedSetupInfo = $OfflinePayloadInfo.NestedSetupInfo
    $NestedSetupError = $OfflinePayloadInfo.NestedSetupError
  }

  $SupportedScopes = @()
  $Scope = $null
  $SupportsDualScope = $false
  $UserScopeSwitch = $null
  $MachineScopeSwitch = $null
  # Scope switches differ among bare mini-installers, untagged Omaha runtime installers, and tagged
  # updater metainstallers; do not apply one family's switch to another.
  if ($Variant -eq 'ChromiumMiniInstaller') {
    $SupportedScopes = @('user', 'machine')
    $SupportsDualScope = $true
    $Scope = 'user'
    $MachineScopeSwitch = '--system-level'
  } elseif ($Variant -eq 'Omaha' -and -not $Tag.IsTagged) {
    # Untagged Google Update packages install their embedded Omaha runtime.
    # Scope is encoded in the /install runtime tag rather than --system.
    $SupportedScopes = @('user', 'machine')
    $SupportsDualScope = $true
    $Scope = 'user'
    $UserScopeSwitch = '/install "runtime=true" /enterprise'
    $MachineScopeSwitch = '/install "runtime=true&needsadmin=true" /enterprise'
  } elseif (-not $Tag.IsTagged) {
    $SupportedScopes = @('user', 'machine')
    $SupportsDualScope = $true
    $Scope = 'user'
    $MachineScopeSwitch = '--system'
  } else {
    switch -Regex ([string]$Tag.NeedsAdmin) {
      '^(?i:true|yes|1)$' { $Scope = 'machine'; $SupportedScopes = @('machine'); break }
      '^(?i:false|no|0)$' { $Scope = 'user'; $SupportedScopes = @('user'); break }
      '^(?i:prefers)$' { $SupportedScopes = @('user', 'machine'); $SupportsDualScope = $true; break }
    }
  }

  $NestedFiles = [Collections.Generic.List[string]]::new()
  $ExecutedPayloads = [Collections.Generic.List[string]]::new()
  # Report the configured execution target separately from files that are merely physically nested.
  switch ($Variant) {
    'ChromiumMiniInstaller' {
      $NestedFiles.Add('setup.exe')
      if ($MiniArchiveFileName) { $NestedFiles.Add($MiniArchiveFileName) }
      $ExecutedPayloads.Add('setup.exe')
    }
    'ChromiumUpdater' {
      $NestedFiles.Add('updater.7z')
      $NestedFiles.Add('bin\updater.exe')
      $ExecutedPayloads.Add('bin\updater.exe')
      if ($OfflineManifest) {
        if ($OfflinePayloadInfo.ManifestEntryName) { $NestedFiles.Add($OfflinePayloadInfo.ManifestEntryName) }
        foreach ($Package in $OfflineManifest.Packages) { if ($Package.Name) { $NestedFiles.Add($Package.Name) } }
        if ($OfflinePayloadInfo.TargetEntryName -and -not $NestedFiles.Contains($OfflinePayloadInfo.TargetEntryName)) { $NestedFiles.Add($OfflinePayloadInfo.TargetEntryName) }
        if ($OfflineManifest.InstallAction) {
          $CommandParts = [Collections.Generic.List[string]]::new()
          if (-not [string]::IsNullOrWhiteSpace($OfflineManifest.InstallAction.Run)) { $CommandParts.Add($OfflineManifest.InstallAction.Run) }
          if (-not [string]::IsNullOrWhiteSpace($OfflineManifest.InstallAction.Arguments)) { $CommandParts.Add($OfflineManifest.InstallAction.Arguments) }
          $ExecutedPayloads.Add([string]::Join(' ', $CommandParts))
        }
      }
    }
    'Omaha' {
      if ($OfflineManifest) {
        $NestedFiles.Add('OfflineManifest.gup')
        foreach ($Package in $OfflineManifest.Packages) { if ($Package.Name) { $NestedFiles.Add($Package.Name) } }
        if ($OfflinePayloadInfo.TargetEntryName -and -not $NestedFiles.Contains($OfflinePayloadInfo.TargetEntryName)) { $NestedFiles.Add($OfflinePayloadInfo.TargetEntryName) }
      } else { $NestedFiles.Add('BCJ2-decoded TAR payload') }
      if ($OfflineManifest.InstallAction) {
        $CommandParts = [Collections.Generic.List[string]]::new()
        if (-not [string]::IsNullOrWhiteSpace($OfflineManifest.InstallAction.Run)) { $CommandParts.Add($OfflineManifest.InstallAction.Run) }
        if (-not [string]::IsNullOrWhiteSpace($OfflineManifest.InstallAction.Arguments)) { $CommandParts.Add($OfflineManifest.InstallAction.Arguments) }
        $ExecutedPayloads.Add([string]::Join(' ', $CommandParts))
      } else { $ExecutedPayloads.Add('first executable in BCJ2-decoded TAR payload') }
    }
  }
  $ResourceInfo = [Collections.Generic.List[object]]::new()
  foreach ($Resource in $Resources) {
    $ResourceInfo.Add([pscustomobject]@{ Type = $Resource.Type; Name = $Resource.Name; Id = $Resource.Id; Offset = $Resource.Offset; Size = $Resource.Size })
  }
  $Warnings = [Collections.Generic.List[object]]::new()
  if ($OfflineManifestError) { $Warnings.Add("The tagged Chromium payload could not be checked for an offline manifest: $OfflineManifestError") }
  if ($NestedSetupError) { $Warnings.Add("The nested Chromium setup.exe could not be inspected: $NestedSetupError") }
  if ($NestedSetupInfo) { foreach ($Warning in $NestedSetupInfo.Diagnostics) { $Warnings.Add($Warning) } }
  if ($IsOnlineBootstrapper) { $Warnings.Add("This setup is a tagged online bootstrapper. Outer version '$($VersionInfo.ProductVersion)' belongs to the updater and is not target-application version evidence; final version, ARP, and switch behavior require target-package evidence.") }
  if ($Variant -eq 'Omaha' -and -not $OfflineManifest) { $Warnings.Add('Omaha executes the first EXE in its decoded TAR payload. Expand and analyze that file before composing nested installer switches.') }
  if ($Variant -eq 'Omaha' -and -not $Tag.IsTagged) { $Warnings.Add('This is an untagged Omaha runtime installer. Its /install runtime tag controls user versus machine scope; do not substitute Chromium Updater --system switches.') }
  if ($Tag.IsTagged -and -not $SupportedScopes) { $Warnings.Add("The updater tag needsadmin value '$($Tag.NeedsAdmin)' does not provide deterministic WinGet scope evidence.") }

  $WritesAppsAndFeaturesEntry = if ($Variant -eq 'ChromiumMiniInstaller') { $true } else { $null }
  [pscustomobject][ordered]@{
    Path                         = $Context.File.FullName
    InstallerType                = 'Chromium Setup'
    ProductCode                  = $null
    UpgradeCode                  = $null
    DisplayName                  = $Tag.ApplicationName ?? $VersionInfo.ProductName
    DisplayVersion               = if ($OfflineManifest) { $OfflineManifest.Version } elseif ($Tag.IsTagged) { $null } else { $VersionInfo.ProductVersion }
    Publisher                    = $VersionInfo.CompanyName
    Scope                        = $Scope
    DefaultInstallLocation       = $null
    WritesAppsAndFeaturesEntry   = $WritesAppsAndFeaturesEntry
    AppsAndFeaturesProductCode   = $null
    AppsAndFeaturesInstallerType = $WritesAppsAndFeaturesEntry -eq $true ? 'exe' : $null
    Diagnostics                  = @(Merge-InstallerDiagnostics -Diagnostic @(ConvertTo-InstallerDiagnostic -InputObject @([object[]]$Warnings) -Source 'ChromiumSetup' -Kind Incomplete -Areas Metadata))
    # Chromium setup variants do not expose one stable source-backed ARP identity contract across
    # vendors and channels. Keep an authored ProductCode unresolved so update processing preserves it.
    UnresolvedFields             = [string[]]@(
      'ProductCode'
      if ($Tag.IsTagged -and -not $OfflineManifest) { 'DisplayVersion' }
    )
    Variant                      = $Variant
    OuterProductVersion          = $VersionInfo.ProductVersion
    OriginalFilename             = $VersionInfo.OriginalFilename
    ApplicationId                = $Tag.ApplicationId
    ArchiveResourceName          = $MiniArchiveResourceName
    SetupResourceName            = $MiniSetupResourceName
    SupportedScopes              = @($SupportedScopes)
    SupportsDualScope            = $SupportsDualScope
    UserScopeSwitch              = $UserScopeSwitch
    MachineScopeSwitch           = $MachineScopeSwitch
    IsOnlineBootstrapper         = $IsOnlineBootstrapper
    OfflineManifestChecked       = $OfflineManifestChecked
    UpdaterTag                   = $Tag
    OfflineManifest              = $OfflineManifest
    NestedSetupInfo              = $NestedSetupInfo
    InstallModes                 = if ($NestedSetupInfo -and $NestedSetupInfo.PSObject.Properties['InstallModes']) { @($NestedSetupInfo.InstallModes) } else { @() }
    Resources                    = $ResourceInfo.ToArray()
    NestedFiles                  = $NestedFiles.ToArray()
    ExtractedFiles               = $NestedFiles.ToArray()
    ExecutedPayloads             = $ExecutedPayloads.ToArray()
    RegistryAssociationInfo      = $null
    Protocols                    = @()
    FileExtensions               = @()
    CanExpand                    = $true
    ParserVersionInfo            = [pscustomobject]@{
      Parser      = 'Dumplings.PackageModule.ChromiumSetup'
      ParserMajor = 5
      Sources     = @('Chromium mini_installer B7, BL, and BN resource precedence', 'Chromium install_static InstallConstants layout and system-level support', 'Chromium Updater metainstaller resources, offline payload layout, and UTF-8 or UTF-16 certificate tag', 'Google Omaha LZMA/BCJ2/TAR payload and OfflineManifest.gup target execution', 'Microsoft Edge UTF-16 certificate tag framing')
    }
  }
}

function Get-ChromiumSetupInfo {
  <#
  .SYNOPSIS
    Classify and read static metadata from Chromium-family setup wrappers
  .PARAMETER Path
    The path to a bare mini-installer, Chromium Updater, or Omaha wrapper
  .PARAMETER SkipOfflineManifest
    Skip expensive Omaha payload decoding when only the outer resource layout is needed
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [Parameter(DontShow)][switch]$SkipOfflineManifest
  )

  process {
    $Context = Open-ChromiumSetupContext -Path $Path
    try { Get-ChromiumSetupInfoFromContext -Context $Context -SkipOfflineManifest:$SkipOfflineManifest }
    finally { Close-ChromiumSetupContext -Context $Context }
  }
}

function Expand-ChromiumSetupInstaller {
  <#
  .SYNOPSIS
    Extract bounded payload resources from a Chromium-family setup wrapper
  .PARAMETER Path
    The path to the Chromium-family setup wrapper
  .PARAMETER DestinationPath
    The extraction directory
  .PARAMETER Name
    A wildcard matching full payload paths or file names
  .PARAMETER MaximumExpandedBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  .PARAMETER CollisionAction
    Behavior when an output path already exists or is selected more than once.
  #>
  [OutputType([System.IO.FileInfo[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [string]$Name = '*',
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Prompt',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 4294967296
  )

  process {
    $Context = Open-ChromiumSetupContext -Path $Path
    try {
      if ([string]::IsNullOrWhiteSpace($DestinationPath)) { $DestinationPath = New-TempFolder }
      $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
      $null = New-Item -Path $DestinationPath -ItemType Directory -Force
      $Results = [Collections.Generic.List[System.IO.FileInfo]]::new(); $Expanded = 0L
      $ReservedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
      # Each variant has a distinct physical encoding path: raw resources, CAB/LZMA resources,
      # ordinary 7z archives, or Omaha's LZMA+BCJ2+TAR stack.
      foreach ($Evidence in $Context.Evidence.SelectedResources) {
        $Resource = $Evidence.Resource
        if ($Context.Evidence.Variant -eq 'Omaha') {
          foreach ($Result in (Expand-ChromiumOmahaPayload -Resource $Resource -DestinationPath $DestinationPath -Name $Name -CollisionAction $CollisionAction -MaximumExpandedBytes $MaximumExpandedBytes)) { $Results.Add($Result) }
          continue
        }
        if ($Evidence.Type -eq 'BN' -or $Evidence.Type -eq 'BD') {
          if (-not (Test-ExtractionPattern -Path $Evidence.Name -Pattern $Name)) { continue }
          $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $Evidence.Name -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
          if (-not $Target.ShouldWrite) { continue }
          $Expanded += $Evidence.Size
          if ($Expanded -gt $MaximumExpandedBytes) { throw 'Chromium resource extraction exceeds the configured output limit.' }
          $Results.Add((Export-PEResourceData -Resource $Resource -DestinationPath $Target.Path -MaximumBytes ($MaximumExpandedBytes - $Expanded + $Evidence.Size) -CollisionAction Overwrite))
          continue
        }
        if ($Evidence.Type -eq 'BL') {
          # BL setup.ex_ resources are cabinet streams rather than 7z archives.
          $TemporaryPath = New-TempFile
          try {
            $null = Export-PEResourceData -Resource $Resource -DestinationPath $TemporaryPath -MaximumBytes $Script:UpdaterConfiguration.MaximumResourceBytes -CollisionAction Overwrite
            foreach ($Result in (Export-CabinetEntry -Path $TemporaryPath -DestinationPath $DestinationPath -Name $Name -CollisionAction $CollisionAction -MaximumExpandedBytes ($MaximumExpandedBytes - $Expanded))) {
              $File = Get-Item -LiteralPath $Result -Force
              $Expanded += $File.Length
              $Results.Add($File)
            }
          } finally { Remove-Item -LiteralPath $TemporaryPath -Force -ErrorAction SilentlyContinue }
          continue
        }

        # Restrict archive readers to the selected PE resource so they cannot consume adjacent
        # resources or the certificate table.
        $ResourceStream = New-BoundedReadStream -Stream $Context.Stream -Offset $Evidence.Offset -Length $Evidence.Size -LeaveOpen
        $Archive = $null
        try {
          $Archive = Get-InstallerArchive -Stream $ResourceStream
          foreach ($Entry in (Get-InstallerArchiveEntry -Archive $Archive)) {
            if ($Context.Evidence.Variant -eq 'ChromiumUpdater' -and $Entry.FullName -ieq 'updater.7z') {
              # Current updater resources contain a second archive. Spill it through the shared
              # seekable-stream helper and apply the same aggregate output limit.
              $NestedInput = Open-InstallerArchiveEntry -Entry $Entry
              $NestedContext = $null
              $NestedArchive = $null
              try {
                $NestedContext = New-InstallerSeekableStream -SourceStream $NestedInput -MaximumBytes ($MaximumExpandedBytes - $Expanded)
                $NestedArchive = Get-InstallerArchive -Stream $NestedContext.Stream
                foreach ($NestedEntry in (Get-InstallerArchiveEntry -Archive $NestedArchive)) {
                  if (-not (Test-ExtractionPattern -Path $NestedEntry.FullName -Pattern $Name)) { continue }
                  $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $NestedEntry.FullName -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
                  if (-not $Target.ShouldWrite) { continue }
                  $Expanded += $NestedEntry.Length
                  if ($Expanded -gt $MaximumExpandedBytes) { throw 'Chromium updater archive extraction exceeds the configured output limit.' }
                  $Results.Add((Export-InstallerArchiveEntry -Entry $NestedEntry -DestinationPath $Target.Path -MaximumBytes ($MaximumExpandedBytes - $Expanded + $NestedEntry.Length) -CollisionAction Overwrite))
                }
              } finally {
                if ($NestedArchive) { $NestedArchive.Dispose() }
                if ($NestedContext) { $NestedContext.Dispose() }
                $NestedInput.Dispose()
              }
            }
            if (Test-ExtractionPattern -Path $Entry.FullName -Pattern $Name) {
              $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $Entry.FullName -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
              if (-not $Target.ShouldWrite) { continue }
              $Expanded += $Entry.Length
              if ($Expanded -gt $MaximumExpandedBytes) { throw 'Chromium archive extraction exceeds the configured output limit.' }
              $Results.Add((Export-InstallerArchiveEntry -Entry $Entry -DestinationPath $Target.Path -MaximumBytes ($MaximumExpandedBytes - $Expanded + $Entry.Length) -CollisionAction Overwrite))
            }
          }
        } finally {
          if ($Archive) { $Archive.Dispose() }
          $ResourceStream.Dispose()
        }
      }
      if ($Results.Count -eq 0) { throw "No Chromium Setup payload matched '$Name'." }
      return $Results.ToArray()
    } finally { Close-ChromiumSetupContext -Context $Context }
  }
}

function Test-ChromiumSetup {
  <#
  .SYNOPSIS
    Test whether a PE uses a supported Chromium Setup layout
  .PARAMETER Path
    The path to the candidate installer
  #>
  [OutputType([bool])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { try { $null = Get-ChromiumSetupInfo -Path $Path; return $true } catch { return $false } }
}

function Read-ProductVersionFromChromiumSetup {
  <#
  .SYNOPSIS
    Read the target version when static Chromium setup evidence provides it
  .PARAMETER Path
    The path to the Chromium setup installer
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-ChromiumSetupInfo -Path $Path).DisplayVersion }
}

function Read-ProductNameFromChromiumSetup {
  <#
  .SYNOPSIS
    Read the tagged application or outer Chromium setup name
  .PARAMETER Path
    The path to the Chromium setup installer
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-ChromiumSetupInfo -Path $Path).DisplayName }
}

function Read-PublisherFromChromiumSetup {
  <#
  .SYNOPSIS
    Read the outer Chromium setup publisher
  .PARAMETER Path
    The path to the Chromium setup installer
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-ChromiumSetupInfo -Path $Path).Publisher }
}

function Read-ScopeFromChromiumSetup {
  <#
  .SYNOPSIS
    Read deterministic Chromium setup scope evidence
  .PARAMETER Path
    The path to the Chromium setup installer
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-ChromiumSetupInfo -Path $Path).Scope }
}

function Read-SupportedScopesFromChromiumSetup {
  <#
  .SYNOPSIS
    Read supported Chromium setup scopes
  .PARAMETER Path
    The path to the Chromium setup installer
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-ChromiumSetupInfo -Path $Path).SupportedScopes }
}

function Read-ProtocolsFromChromiumSetup {
  <#
  .SYNOPSIS
    Read statically proven protocol associations from Chromium setup
  .PARAMETER Path
    The path to the Chromium setup installer
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-ChromiumSetupInfo -Path $Path).Protocols }
}

function Read-FileExtensionsFromChromiumSetup {
  <#
  .SYNOPSIS
    Read statically proven file associations from Chromium setup
  .PARAMETER Path
    The path to the Chromium setup installer
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-ChromiumSetupInfo -Path $Path).FileExtensions }
}

Export-ModuleMember -Function ConvertFrom-ChromiumUpdaterTagData, Read-ChromiumInstallerTag, Get-ChromiumSetupInfo, Expand-ChromiumSetupInstaller, Test-ChromiumSetup, Test-ChromiumMiniInstaller, Test-ChromiumUpdater, Test-OmahaInstaller, Read-ProductVersionFromChromiumSetup, Read-ProductNameFromChromiumSetup, Read-PublisherFromChromiumSetup, Read-ScopeFromChromiumSetup, Read-SupportedScopesFromChromiumSetup, Read-ProtocolsFromChromiumSetup, Read-FileExtensionsFromChromiumSetup
