# SPDX-License-Identifier: Apache-2.0
# Format source: https://github.com/lemutec/MicaSetup
# Resource format source: https://github.com/dotnet/runtime/blob/main/src/libraries/System.Private.CoreLib/src/System/Resources/ResourceReader.cs
#
# MicaSetup binary structures consumed by this parser:
#
#   managed PE image
#   +-- IMAGE_COR20_HEADER
#   |   +-- CLR metadata
#   |   |   +-- v1.0: TypeRef MicaSetup.Core.Pack + UsePack
#   |   |   +-- later: TypeDef MicaSetup.Option + UseOptions
#   |   |   +-- MethodDef/MemberRef: UseElevated
#   |   |   +-- generated option-initializer IL
#   |   |   `-- assembly custom attributes
#   |   `-- ResourcesDirectory
#   |       `-- ManifestResource: <assembly>.g.resources
#   |           +-- ResourceManager header: BEEFCACE
#   |           +-- hash/name-position tables
#   |           +-- UTF-16 name section
#   |           `-- data section
#   |               +-- resources/setups/publish.7z: ResourceTypeCode.Stream
#   |               +-- resources/setups/uninst.exe: ResourceTypeCode.Stream
#   |               `-- optional icons, licenses, certificate, fonts, and BAML
#   `-- Authenticode data and ordinary PE resources
#
#   publish.7z
#   +-- application executable
#   +-- managed/native sidecars
#   `-- installed data files
#
# Offsets returned by the managed reader are absolute file offsets. Resource stream lengths
# exclude the .resources type code and length prefix. The payload archive is never loaded as an
# assembly and no embedded executable is run.

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:MicaSetupMaximumResources = 8192
$Script:MicaSetupMaximumMethods = 32768
$Script:MicaSetupMaximumInstructions = 250000
$Script:MicaSetupMaximumPayloadEntries = 65536
$Script:MicaSetupMaximumAnalysisFiles = 256
$Script:MicaSetupMaximumAnalysisBytes = 536870912
$Script:MicaSetupPayloadResourceName = 'resources/setups/publish.7z'
$Script:MicaSetupUninstallerResourceName = 'resources/setups/uninst.exe'

function Import-MicaSetupReader {
  <#
  .SYNOPSIS
    Load the bounded MicaSetup CLR and WPF resource reader once per process.
  #>
  $SourcePath = Join-Path $PSScriptRoot '..\..\Assets\Source\MicaSetup\MicaSetupReader.cs'
  $null = Import-InstallerManagedSource -Path $SourcePath -TypeName 'Dumplings.MicaSetup.MicaSetupReader'
}

function Get-MicaSetupManagedInfo {
  <#
  .SYNOPSIS
    Read MicaSetup managed metadata from a caller-owned installer stream.
  .PARAMETER Stream
    Readable, seekable installer stream. The reader restores its original position and leaves it open.
  #>
  [OutputType([object])]
  param ([Parameter(Mandatory)][IO.Stream]$Stream)

  Import-MicaSetupReader
  return [Dumplings.MicaSetup.MicaSetupReader]::Analyze(
    $Stream,
    $Script:MicaSetupMaximumResources,
    $Script:MicaSetupMaximumMethods,
    $Script:MicaSetupMaximumInstructions)
}

function ConvertTo-MicaSetupOptionMap {
  <#
  .SYNOPSIS
    Convert evaluated option evidence into deterministic internal and public maps.
  .PARAMETER Evidence
    Option assignments returned by the managed reader.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][Collections.IEnumerable]$Evidence)

  $Internal = [ordered]@{}
  $Public = [ordered]@{}
  $PublicEvidence = [Collections.Generic.List[object]]::new()
  foreach ($Item in $Evidence) {
    $Internal[$Item.Name] = $Item
    if ($Item.Name -ne 'UnpackingPassword') {
      $Public[$Item.Name] = if ($Item.IsResolved) { $Item.Value } else { $null }
    }
    $PublicEvidence.Add([pscustomobject]@{
        Name        = $Item.Name
        Value       = if ($Item.Name -eq 'UnpackingPassword') { $null } elseif ($Item.IsResolved) { $Item.Value } else { $null }
        IsResolved  = [bool]$Item.IsResolved
        IsSensitive = $Item.Name -eq 'UnpackingPassword'
        Expression  = if ($Item.Name -eq 'UnpackingPassword') { if ($Item.IsResolved) { 'constant string (redacted)' } else { 'unresolved (redacted)' } } else { $Item.Expression }
        Method      = $Item.Method
        IlOffset    = $Item.IlOffset
        ArrayLength = $Item.ArrayLength
      })
  }
  [pscustomobject]@{ Internal = $Internal; Public = [pscustomobject]$Public; Evidence = @($PublicEvidence) }
}

function Get-MicaSetupOptionValue {
  <#
  .SYNOPSIS
    Resolve one explicit MicaSetup option or a source-backed generation default.
  .PARAMETER OptionMap
    Internal option evidence map returned by ConvertTo-MicaSetupOptionMap.
  .PARAMETER Name
    Option property name.
  .PARAMETER DefaultValue
    Source-backed default used when the generated initializer did not assign the property.
  #>
  param (
    [Parameter(Mandatory)][Collections.IDictionary]$OptionMap,
    [Parameter(Mandatory)][string]$Name,
    $DefaultValue
  )

  if ($OptionMap.Contains($Name)) {
    $Evidence = $OptionMap[$Name]
    if ($Evidence.IsResolved) { return $Evidence.Value }
    return $null
  }
  return $DefaultValue
}

function Open-MicaSetupPayloadArchive {
  <#
  .SYNOPSIS
    Open the bounded publish.7z resource with the compiled constant password when present.
  .PARAMETER Stream
    Caller-owned installer stream.
  .PARAMETER Resource
    publish.7z resource descriptor with absolute Offset and Length.
  .PARAMETER ArchiveKey
    Internal constant archive key. It is passed directly to SharpCompress and is never returned or logged.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)]$Resource,
    [AllowNull()][string]$ArchiveKey
  )

  Import-InstallerArchiveDependency
  $Range = New-BoundedReadStream -Stream $Stream -Offset $Resource.Offset -Length $Resource.Length -LeaveOpen
  try {
    $ReaderOptions = [SharpCompress.Readers.ReaderOptions]::new()
    $ReaderOptions.LookForHeader = $true
    $ReaderOptions.LeaveStreamOpen = $true
    if (-not [string]::IsNullOrEmpty($ArchiveKey)) { $ReaderOptions.Password = $ArchiveKey }
    $Archive = [SharpCompress.Archives.ArchiveFactory]::Open($Range, $ReaderOptions)
    return [pscustomobject]@{ Archive = $Archive; Range = $Range }
  } catch {
    $Range.Dispose()
    throw
  }
}

function Close-MicaSetupPayloadArchive {
  <#
  .SYNOPSIS
    Dispose a payload archive context without disposing its caller-owned installer stream.
  .PARAMETER Context
    Context returned by Open-MicaSetupPayloadArchive.
  #>
  param ([Parameter(Mandatory)]$Context)

  try {
    if ($Context.Archive) { $Context.Archive.Dispose() }
  } finally {
    if ($Context.Range) { $Context.Range.Dispose() }
  }
}

function Get-MicaSetupManifestPath {
  <#
  .SYNOPSIS
    Convert a MicaSetup default installation directory into manifest-safe environment syntax.
  .PARAMETER Generation
    MicaSetup builder generation.
  .PARAMETER Scope
    Resolved installation scope.
  .PARAMETER KeyName
    Resolved application/uninstall key name.
  .PARAMETER OptionMap
    Internal option evidence map.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][ValidateSet('v1', 'v2')][string]$Generation,
    [ValidateSet('user', 'machine')][string]$Scope,
    [string]$KeyName,
    [Parameter(Mandatory)][Collections.IDictionary]$OptionMap
  )

  if ([string]::IsNullOrWhiteSpace($KeyName) -or [string]::IsNullOrWhiteSpace($Scope)) { return $null }
  $PreferX86 = [bool](Get-MicaSetupOptionValue -OptionMap $OptionMap -Name $(if ($Generation -eq 'v1') { 'UseInstallPathPreferX86' } else { 'IsUseInstallPathPreferX86' }) -DefaultValue $false)
  if ($Generation -eq 'v1') {
    return Join-Path $(if ($PreferX86) { '%ProgramFiles(x86)%' } else { '%ProgramFiles%' }) $KeyName
  }

  $PreferLocalPrograms = [bool](Get-MicaSetupOptionValue -OptionMap $OptionMap -Name 'IsUseInstallPathPreferAppDataLocalPrograms' -DefaultValue $false)
  $PreferRoaming = [bool](Get-MicaSetupOptionValue -OptionMap $OptionMap -Name 'IsUseInstallPathPreferAppDataRoaming' -DefaultValue $false)
  if ($Scope -eq 'machine') {
    if ($PreferX86) { return Join-Path '%ProgramFiles(x86)%' $KeyName }
    if ($PreferLocalPrograms) { return Join-Path '%LOCALAPPDATA%\Programs' $KeyName }
    if ($PreferRoaming) { return Join-Path '%APPDATA%' $KeyName }
    return Join-Path '%ProgramFiles%' $KeyName
  }
  if ($PreferLocalPrograms) { return Join-Path '%LOCALAPPDATA%\Programs' $KeyName }
  return Join-Path '%APPDATA%' $KeyName
}

function Get-MicaSetupPayloadEvidence {
  <#
  .SYNOPSIS
    Enumerate the payload and selectively analyze its configured executable and adjacent sidecars.
  .PARAMETER Archive
    Open SharpCompress archive.
  .PARAMETER ExeName
    Configured application executable name.
  .PARAMETER Warnings
    Mutable warning list receiving bounded-analysis failures.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]$Archive,
    [string]$ExeName,
    [AllowEmptyCollection()][Collections.Generic.List[string]]$Warnings
  )

  $Catalog = [Collections.Generic.List[object]]::new()
  $EntryList = [Collections.Generic.List[object]]::new()
  foreach ($Entry in Get-InstallerArchiveEntry -Archive $Archive) {
    if ($EntryList.Count -ge $Script:MicaSetupMaximumPayloadEntries) { throw "The MicaSetup payload exceeds the $Script:MicaSetupMaximumPayloadEntries-entry analysis limit." }
    if ($Entry.Length -lt 0 -or $Entry.CompressedSize -lt 0) { throw "The MicaSetup payload entry '$($Entry.FullName)' has an invalid size." }
    $EntryList.Add($Entry)
    $Catalog.Add([pscustomobject]@{ Path = $Entry.FullName; Size = $Entry.Length; CompressedSize = $Entry.CompressedSize })
  }
  $Entries = @($EntryList)

  $ArchitectureInfo = $null
  $DependencyInfo = $null
  $Architectures = @()
  if (-not [string]::IsNullOrWhiteSpace($ExeName)) {
    $MainEntry = @($Entries | Where-Object { [IO.Path]::GetFileName($_.FullName) -ieq $ExeName })
    if ($MainEntry.Count -gt 1) {
      $Warnings.Add("The MicaSetup payload contains more than one '$ExeName'; architecture and dependency analysis is ambiguous.")
    } elseif ($MainEntry.Count -eq 1) {
      $MainEntry = $MainEntry[0]
      $Directory = [IO.Path]::GetDirectoryName($MainEntry.FullName.Replace('/', '\'))
      $RelatedEntries = @($Entries | Where-Object {
          $EntryDirectory = [IO.Path]::GetDirectoryName($_.FullName.Replace('/', '\'))
          $Extension = [IO.Path]::GetExtension($_.FullName)
          $EntryDirectory -ieq $Directory -and ($Extension -iin '.dll', '.json')
        } | Select-Object -First ($Script:MicaSetupMaximumAnalysisFiles - 1))
      $AnalysisEntries = @($MainEntry) + $RelatedEntries
      if (($AnalysisEntries | Measure-Object -Property Length -Sum).Sum -le $Script:MicaSetupMaximumAnalysisBytes) {
        $TempFolder = New-TempFolder
        try {
          $Extracted = [Collections.Generic.List[string]]::new()
          foreach ($Entry in $AnalysisEntries) {
            $LeafName = [IO.Path]::GetFileName($Entry.FullName)
            $TargetPath = Join-Path $TempFolder $LeafName
            $File = Export-InstallerArchiveEntry -Entry $Entry -DestinationPath $TargetPath -MaximumBytes $Script:MicaSetupMaximumAnalysisBytes -CollisionAction Rename
            $Extracted.Add($File.FullName)
          }
          $MainPath = $Extracted[0]
          $RelatedFiles = @($Extracted | Select-Object -Skip 1)
          try {
            $ArchitectureInfo = Get-PEArchitectureInfo -Path $MainPath -RelatedFile @($RelatedFiles | Where-Object { [IO.Path]::GetExtension($_) -ieq '.dll' })
            $Architectures = @($ArchitectureInfo.RecommendedWinGetArchitectures)
          } catch { $Warnings.Add("MicaSetup payload architecture analysis failed: $($_.Exception.Message)") }
          try { $DependencyInfo = Get-PEDependencyInfo -Path $MainPath -RelatedFile $RelatedFiles }
          catch { $Warnings.Add("MicaSetup payload dependency analysis failed: $($_.Exception.Message)") }
        } finally {
          if (Test-Path -LiteralPath $TempFolder) { Remove-Item -LiteralPath $TempFolder -Recurse -Force -ErrorAction SilentlyContinue }
        }
      } else {
        $Warnings.Add("MicaSetup payload PE analysis was skipped because selected files exceed the $Script:MicaSetupMaximumAnalysisBytes-byte limit.")
      }
    } else {
      $Warnings.Add("The configured MicaSetup executable '$ExeName' was not found in publish.7z.")
    }
  }

  [pscustomobject]@{
    Catalog          = @($Catalog)
    Architectures    = @($Architectures)
    ArchitectureInfo = $ArchitectureInfo
    DependencyInfo   = $DependencyInfo
  }
}

function Get-MicaSetupInfo {
  <#
  .SYNOPSIS
    Read static metadata, payload, ARP, scope, and system-effect evidence from a MicaSetup installer.
  .DESCRIPTION
    The parser reads CLR metadata, generated Pack/Option initializer IL, WPF .g.resources tables, and the embedded publish.7z without loading or executing the installer assembly. Constant payload passwords are used only inside the archive operation and are never returned.
  .PARAMETER Path
    Path to the MicaSetup installer executable.
  .OUTPUTS
    A parser evidence object following the shared installer contract plus MicaSetup-specific option, resource, payload, and system-effect properties.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)

  process {
    $File = Get-Item -LiteralPath (Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf) -Force -ErrorAction Stop
    $Warnings = [Collections.Generic.List[string]]::new()
    $Diagnostics = [Collections.Generic.List[object]]::new()
    $InformationMessages = [Collections.Generic.List[string]]::new()
    $UnresolvedFields = [Collections.Generic.List[string]]::new()
    $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
      $Managed = Get-MicaSetupManagedInfo -Stream $Stream
      $PayloadResource = @($Managed.Resources | Where-Object { $_.Name -ieq $Script:MicaSetupPayloadResourceName -and $_.TypeCode -eq 33 })
      $HasConfigurationHost = $Managed.FileKind -eq 'Executable' -and (($Managed.HasOptionType -and $Managed.HasUseOptionsMethod) -or ($Managed.HasPackType -and $Managed.HasUsePackMethod))
      if (-not $HasConfigurationHost -or $PayloadResource.Count -ne 1) {
        throw 'The PE does not contain the CLR Option/UseOptions or Pack/UsePack configuration host and WPF publish.7z structures required for MicaSetup.'
      }
      foreach ($Warning in $Managed.Warnings) { $Warnings.Add("MicaSetup CLR analysis: $Warning") }
      $Options = ConvertTo-MicaSetupOptionMap -Evidence $Managed.Options
      $UnresolvedExpressions = @($Options.Evidence | Where-Object { -not $_.IsResolved } | ForEach-Object {
          [pscustomobject]@{ Name = $_.Name; Expression = $_.Expression; Method = $_.Method; IlOffset = $_.IlOffset }
        })
      if ($UnresolvedExpressions.Count -gt 0) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'MicaSetup.Configuration.ExpressionsUnresolved' -Source 'MicaSetup' -Message "MicaSetup contains $($UnresolvedExpressions.Count) unresolved compiled configuration expression(s); affected effects require source inspection or VM validation." -Kind Incomplete -Areas Metadata -Evidence $UnresolvedExpressions))
      }
      $Generation = $Managed.BuilderGeneration
      $ConfigurationModel = $Managed.ConfigurationModel
      if ($Generation -notin 'v1', 'v2') { throw 'The MicaSetup option schema generation is unsupported.' }

      $UseElevated = if ($Generation -eq 'v1') { $true } elseif ($null -ne $Managed.UseElevated) { [bool]$Managed.UseElevated } elseif ($Managed.RequestExecutionLevel -ieq 'admin') { $true } elseif ($Managed.RequestExecutionLevel -ieq 'user') { $false } else { $null }
      $Scope = if ($UseElevated -eq $true) { 'machine' } elseif ($UseElevated -eq $false) { 'user' } else { $null }
      $SupportedScopes = if ($Scope) { @($Scope) } else { @('user', 'machine') }
      if (-not $Scope) { $Warnings.Add('The MicaSetup UseElevated/request-execution-level expression is unresolved; scope requires VM validation.'); $UnresolvedFields.Add('Scope') }

      $AppName = [string](Get-MicaSetupOptionValue -OptionMap $Options.Internal -Name 'AppName')
      $KeyName = [string](Get-MicaSetupOptionValue -OptionMap $Options.Internal -Name 'KeyName')
      $ExeName = [string](Get-MicaSetupOptionValue -OptionMap $Options.Internal -Name 'ExeName')
      $DisplayName = [string](Get-MicaSetupOptionValue -OptionMap $Options.Internal -Name 'DisplayName')
      $DisplayVersion = [string](Get-MicaSetupOptionValue -OptionMap $Options.Internal -Name 'DisplayVersion')
      $Publisher = [string](Get-MicaSetupOptionValue -OptionMap $Options.Internal -Name 'Publisher')
      $DisplayIconOption = [string](Get-MicaSetupOptionValue -OptionMap $Options.Internal -Name 'DisplayIcon')
      if ([string]::IsNullOrWhiteSpace($DisplayName)) { $DisplayName = $AppName }
      $CreateRegistry = [bool](Get-MicaSetupOptionValue -OptionMap $Options.Internal -Name 'IsCreateRegistryKeys' -DefaultValue $true)
      $CreateUninstaller = [bool](Get-MicaSetupOptionValue -OptionMap $Options.Internal -Name 'IsCreateUninst' -DefaultValue $true)
      $UninstallerLower = $Generation -eq 'v2' -and [bool](Get-MicaSetupOptionValue -OptionMap $Options.Internal -Name 'IsUninstLower' -DefaultValue $false)
      $SystemComponent = [bool](Get-MicaSetupOptionValue -OptionMap $Options.Internal -Name 'SystemComponent' -DefaultValue $false)
      $RegistryX86 = Get-MicaSetupOptionValue -OptionMap $Options.Internal -Name 'IsUseRegistryPreferX86' -DefaultValue $null
      $RegistryView = if ($RegistryX86 -eq $true) { '32-bit' } elseif ($RegistryX86 -eq $false) { '64-bit' } else { 'default' }
      $DefaultInstallLocation = Get-MicaSetupManifestPath -Generation $Generation -Scope $Scope -KeyName $KeyName -OptionMap $Options.Internal
      $UninstallerName = if ($UninstallerLower) { 'uninst.exe' } else { 'Uninst.exe' }
      $UninstallString = if ($DefaultInstallLocation -and $CreateUninstaller) { Join-Path $DefaultInstallLocation $UninstallerName } else { $null }
      $DisplayIcon = if ($DefaultInstallLocation) { Join-Path $DefaultInstallLocation $(if ($DisplayIconOption) { $DisplayIconOption } else { $ExeName }) } else { $DisplayIconOption }

      $WritesArp = $Scope -eq 'machine' -and $CreateRegistry -and -not [string]::IsNullOrWhiteSpace($KeyName)
      $VisibleArp = $WritesArp -and -not $SystemComponent
      if ($Scope -eq 'user' -and $CreateRegistry) { $InformationMessages.Add('MicaSetup v2 user-mode installations write Uninst.dat instead of a Windows uninstall registry entry.') }
      if ($WritesArp -and $SystemComponent) { $InformationMessages.Add('MicaSetup writes a hidden uninstall entry because SystemComponent is enabled.') }
      if (-not $CreateRegistry) { $InformationMessages.Add('MicaSetup registry/uninstall entry creation is disabled by IsCreateRegistryKeys.') }

      # Project the built-in uninstall entry as individual registry values so it has the same shape
      # as explicit custom writes and can be consumed by shared registry-evidence helpers.
      $RegistryWrites = [Collections.Generic.List[object]]::new()
      if ($WritesArp) {
        $UninstallKey = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$KeyName"
        $UninstallValues = [ordered]@{
          DisplayName = $DisplayName; DisplayIcon = $DisplayIcon; DisplayVersion = $DisplayVersion
          InstallLocation = $DefaultInstallLocation; Publisher = $Publisher; UninstallString = $UninstallString
          NoModify = 1; NoRepair = 1; SystemComponent = [int]$SystemComponent
        }
        foreach ($Value in $UninstallValues.GetEnumerator()) {
          $RegistryWrites.Add([pscustomobject]@{
              Hive = 'HKEY_LOCAL_MACHINE'; Root = 'HKLM'; View = $RegistryView; Key = $UninstallKey
              Name = $Value.Key; Value = $Value.Value; Type = if ($Value.Value -is [int]) { 'REG_DWORD' } else { 'REG_SZ' }
              Source = 'MicaSetup built-in uninstall registration'
            })
        }
      }

      # Custom MicaSetup source can write associations directly. Accept only literal static
      # Registry.SetValue calls recovered by the IL reader; computed/custom object behavior stays unresolved.
      foreach ($Write in $Managed.RegistryWrites) {
        if (-not $Write.IsResolved -or [string]::IsNullOrWhiteSpace($Write.Key)) { continue }
        $RegistryWrites.Add([pscustomobject]@{
            Root = $null; Key = $Write.Key; Name = $Write.Name; Value = $Write.Value
            Type = switch ($Write.ValueKind) { 1 { 'REG_SZ' } 2 { 'REG_EXPAND_SZ' } 4 { 'REG_DWORD' } 7 { 'REG_MULTI_SZ' } 11 { 'REG_QWORD' } default { $null } }
            Source = "CLR $($Write.Method) IL_$($Write.IlOffset.ToString('X4'))"
          })
      }
      $AssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite @($RegistryWrites)
      foreach ($Diagnostic in $AssociationInfo.Diagnostics) { $Diagnostics.Add($Diagnostic) }

      $PasswordEvidence = $Options.Internal['UnpackingPassword']
      $PayloadEncrypted = $PasswordEvidence -and $PasswordEvidence.IsResolved -and -not [string]::IsNullOrEmpty([string]$PasswordEvidence.Value)
      $Password = if ($PayloadEncrypted) { [string]$PasswordEvidence.Value } else { $null }
      if ($PasswordEvidence -and -not $PasswordEvidence.IsResolved) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'MicaSetup.Extraction.PasswordUnresolved' -Source 'MicaSetup' -Message 'The MicaSetup payload password expression is not constant; static extraction is unavailable without manual evidence.' -Kind Unsupported -Areas Extraction -AffectedFields PayloadPassword))
        $UnresolvedFields.Add('PayloadPassword')
      }

      $PayloadEvidence = [pscustomobject]@{ Catalog = @(); Architectures = @(); ArchitectureInfo = $null; DependencyInfo = $null }
      $DecryptionSucceeded = if ($PayloadEncrypted) { $false } else { $null }
      $CanExpand = -not ($PasswordEvidence -and -not $PasswordEvidence.IsResolved)
      if ($CanExpand) {
        $ArchiveContext = $null
        try {
          $ArchiveContext = Open-MicaSetupPayloadArchive -Stream $Stream -Resource $PayloadResource[0] -ArchiveKey $Password
          $PayloadEvidence = Get-MicaSetupPayloadEvidence -Archive $ArchiveContext.Archive -ExeName $ExeName -Warnings $Warnings
          if ($PayloadEncrypted) {
            $ProbeEntry = Get-InstallerArchiveEntry -Archive $ArchiveContext.Archive | Where-Object Length -GT 0 | Select-Object -First 1
            if ($ProbeEntry) {
              $ProbeStream = Open-InstallerArchiveEntry -Entry $ProbeEntry
              try { $null = $ProbeStream.ReadByte(); $DecryptionSucceeded = $true } finally { $ProbeStream.Dispose() }
            }
          }
        } catch {
          $CanExpand = $false
          if ($PayloadEncrypted) { $DecryptionSucceeded = $false }
          $Warnings.Add("MicaSetup payload archive analysis failed: $($_.Exception.Message)")
        } finally {
          if ($ArchiveContext) { Close-MicaSetupPayloadArchive -Context $ArchiveContext }
        }
      }
      if ($PayloadEvidence.ArchitectureInfo) {
        foreach ($Diagnostic in @($PayloadEvidence.ArchitectureInfo.Diagnostics)) { if ($Diagnostic) { $Diagnostics.Add($Diagnostic) } }
      }
      if ($PayloadEvidence.DependencyInfo) {
        foreach ($Diagnostic in @($PayloadEvidence.DependencyInfo.Diagnostics)) { if ($Diagnostic) { $Diagnostics.Add($Diagnostic) } }
      }

      $HasModernOptions = $ConfigurationModel -ne 'Pack'
      $Shortcuts = @(
        if ([bool](Get-MicaSetupOptionValue -OptionMap $Options.Internal -Name 'IsCreateDesktopShortcut' -DefaultValue $true)) { [pscustomobject]@{ Location = 'Desktop'; Name = $DisplayName; Target = $ExeName } }
        if ([bool](Get-MicaSetupOptionValue -OptionMap $Options.Internal -Name 'IsCreateStartMenu' -DefaultValue $HasModernOptions)) { [pscustomobject]@{ Location = 'StartMenu'; Name = $DisplayName; Target = $ExeName } }
        if ([bool](Get-MicaSetupOptionValue -OptionMap $Options.Internal -Name 'IsCreateQuickLaunch' -DefaultValue $false)) { [pscustomobject]@{ Location = 'QuickLaunch'; Name = $DisplayName; Target = $ExeName } }
      )
      $Autorun = if ([bool](Get-MicaSetupOptionValue -OptionMap $Options.Internal -Name 'IsCreateAsAutoRun' -DefaultValue $false)) {
        @([pscustomobject]@{ Hive = 'HKEY_CURRENT_USER'; Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; Name = $KeyName; Command = "$ExeName $([string](Get-MicaSetupOptionValue -OptionMap $Options.Internal -Name 'AutoRunLaunchCommand' -DefaultValue ''))".Trim() })
      } else { @() }
      $EnvironmentChanges = if ($Generation -eq 'v2' -and [bool](Get-MicaSetupOptionValue -OptionMap $Options.Internal -Name 'IsEnvironmentVariable' -DefaultValue $false)) { @([pscustomobject]@{ Variable = 'PATH'; Action = 'AppendInstallLocationAndSubdirectories' }) } else { @() }
      $FirewallRules = if ([bool](Get-MicaSetupOptionValue -OptionMap $Options.Internal -Name 'IsAllowFirewall' -DefaultValue $HasModernOptions)) { @([pscustomobject]@{ Action = 'AllowApplication'; Target = $ExeName; ConditionalOnElevation = $true }) } else { @() }
      $Certificates = if ([bool](Get-MicaSetupOptionValue -OptionMap $Options.Internal -Name 'IsInstallCertificate' -DefaultValue $false)) { @($Managed.Resources | Where-Object Name -Like 'resources/setups/*.cer' | ForEach-Object { [pscustomobject]@{ Resource = $_.Name; ConditionalOnElevation = $true } }) } else { @() }
      $CloseApplicationsEvidence = $Options.Internal['CloseApplications']
      $CloseApplications = if ($CloseApplicationsEvidence -and $CloseApplicationsEvidence.ArrayLength -ge 0) { [pscustomobject]@{ Count = $CloseApplicationsEvidence.ArrayLength; DetailsResolved = $CloseApplicationsEvidence.IsResolved } } else { $null }
      if ($CloseApplications -and $CloseApplications.Count -gt 0 -and -not $CloseApplications.DetailsResolved) { $InformationMessages.Add("MicaSetup configures $($CloseApplications.Count) application-close record(s); detailed object initializers require VM validation.") }

      $AppsAndFeaturesEntries = if ($VisibleArp) { @([ordered]@{ ProductCode = $KeyName; DisplayName = $DisplayName; DisplayVersion = $DisplayVersion; Publisher = $Publisher; InstallerType = 'exe' }) } else { @() }
      $RequestedExecutionLevel = if ($Scope -eq 'machine') { 'requireAdministrator' } elseif ($Scope -eq 'user') { 'asInvoker' } else { $null }
      if ($Managed.RequestExecutionLevel) { $RequestedExecutionLevel = if ($Managed.RequestExecutionLevel -ieq 'admin') { 'requireAdministrator' } elseif ($Managed.RequestExecutionLevel -ieq 'user') { 'asInvoker' } else { $Managed.RequestExecutionLevel } }
      if ($Generation -eq 'v1') { $InformationMessages.Add('MicaSetup v1 calls UseElevated unconditionally and is treated as a machine-scope installer.') }
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'MicaSetup.Installability.SilentUnsupported' -Source 'MicaSetup' -Message 'Upstream MicaSetup documents /q and /a as unfinished; no silent switch is returned without compiled command-line evidence.' -Kind Unsupported -Areas Installability -AffectedFields InstallerSwitches, InstallModes))

      return [pscustomobject]@{
        Path                           = $File.FullName
        InstallerType                  = 'exe'
        BuilderGeneration              = $Generation
        ConfigurationModel             = $ConfigurationModel
        TargetFramework                = $Managed.TargetFramework
        RequestedExecutionLevel        = $RequestedExecutionLevel
        SupportedScopes                = $SupportedScopes
        Scope                          = $Scope
        ProductCode                    = if ($VisibleArp) { $KeyName } else { $null }
        UpgradeCode                    = $null
        DisplayName                    = $DisplayName
        DisplayVersion                 = $DisplayVersion
        Publisher                      = $Publisher
        DefaultInstallLocation         = $DefaultInstallLocation
        InstallLocation                = $DefaultInstallLocation
        UninstallString                = $UninstallString
        QuietUninstallString           = $null
        DisplayIcon                    = $DisplayIcon
        SystemComponent                = $SystemComponent
        RegistryView                   = $RegistryView
        WritesAppsAndFeaturesEntry     = $VisibleArp
        AppsAndFeaturesProductCode     = if ($VisibleArp) { $KeyName } else { $null }
        AppsAndFeaturesInstallerType   = if ($VisibleArp) { 'exe' } else { $null }
        AppsAndFeaturesEntries         = $AppsAndFeaturesEntries
        RegistryWrites                 = @($RegistryWrites)
        AppName                        = $AppName
        KeyName                        = $KeyName
        ExeName                        = $ExeName
        IsCreateUninstaller            = $CreateUninstaller
        UninstallerName                = $UninstallerName
        OptionValues                   = $Options.Public
        OptionEvidence                 = $Options.Evidence
        UnresolvedExpressions          = $UnresolvedExpressions
        EmbeddedResources              = @($Managed.Resources | ForEach-Object { [pscustomobject]@{ Name = $_.Name; TypeCode = $_.TypeCode; TypeName = $_.TypeName; Offset = $_.Offset; Length = $_.Length } })
        PayloadFiles                   = @($PayloadEvidence.Catalog)
        PayloadArchitectures           = @($PayloadEvidence.Architectures)
        PayloadArchitectureInfo        = $PayloadEvidence.ArchitectureInfo
        DependencyInfo                 = $PayloadEvidence.DependencyInfo
        PayloadEncrypted               = [bool]$PayloadEncrypted
        PayloadDecryptionSucceeded     = $DecryptionSucceeded
        CanExpand                      = $CanExpand
        Shortcuts                      = $Shortcuts
        AutorunEntries                 = $Autorun
        EnvironmentChanges             = $EnvironmentChanges
        FirewallRules                  = $FirewallRules
        Certificates                   = $Certificates
        CloseApplications              = $CloseApplications
        Protocols                      = @($AssociationInfo.Protocols)
        FileExtensions                 = @($AssociationInfo.FileExtensions)
        ProtocolAssociations           = @($AssociationInfo.ProtocolAssociations)
        FileExtensionAssociations      = @($AssociationInfo.FileExtensionAssociations)
        RegistryAssociationInfo        = $AssociationInfo
        InstallModes                   = @('interactive')
        InstallerSwitches              = [ordered]@{}
        SupportedCommandLineSwitches   = @()
        RecommendedPackageDependencies = if ($PayloadEvidence.DependencyInfo) { @($PayloadEvidence.DependencyInfo.RecommendedPackageDependencies) } else { @() }

        Diagnostics                    = @(
          Merge-InstallerDiagnostics -Diagnostic @(
            $Diagnostics
            @(ConvertTo-InstallerDiagnostic -InputObject @($Warnings) -Source 'MicaSetup' -Kind Incomplete -Areas Metadata -AffectedFields $UnresolvedFields)
            @(ConvertTo-InstallerDiagnostic -InputObject @($InformationMessages) -Source 'MicaSetup' -Kind Information -Areas Metadata)
          )
        )
        UnresolvedFields               = @($UnresolvedFields | Sort-Object -Unique)
        Family                         = 'MicaSetup'
        ParserVersionInfo              = [pscustomobject]@{ Name = 'Dumplings MicaSetup parser'; Version = 1; Generation = $Generation; Evidence = @($Managed.Evidence) }
      }
    } finally {
      $Stream.Dispose()
    }
  }
}

function Test-MicaSetupInstaller {
  <#
  .SYNOPSIS
    Test for MicaSetup CLR type/method evidence and the embedded WPF publish.7z stream.
  .PARAMETER Path
    Candidate installer path.
  #>
  [OutputType([bool])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)

  process {
    try {
      $File = Get-Item -LiteralPath (Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf) -Force -ErrorAction Stop
      $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
      try {
        $Info = Get-MicaSetupManagedInfo -Stream $Stream
        $HasConfigurationHost = $Info.FileKind -eq 'Executable' -and (($Info.HasOptionType -and $Info.HasUseOptionsMethod) -or ($Info.HasPackType -and $Info.HasUsePackMethod))
        return $HasConfigurationHost -and @($Info.Resources | Where-Object { $_.Name -ieq $Script:MicaSetupPayloadResourceName -and $_.TypeCode -eq 33 }).Count -eq 1
      } finally { $Stream.Dispose() }
    } catch { return $false }
  }
}

function Expand-MicaSetupInstaller {
  <#
  .SYNOPSIS
    Expand a MicaSetup installed payload or its raw WPF stream resources.
  .PARAMETER Path
    Path to the MicaSetup installer.
  .PARAMETER DestinationPath
    Output directory. A new temporary directory is used when omitted.
  .PARAMETER Name
    Wildcard selection. Omit it to extract all installed payload files.
  .PARAMETER RawResources
    Export supported primitive stream/byte-array WPF resources instead of publish.7z contents.
  .PARAMETER CollisionAction
    Existing or duplicate path behavior. Prompt asks only when a collision is encountered.
  .PARAMETER MaximumExpandedBytes
    Aggregate output limit in bytes.
  .PARAMETER MaximumEntries
    Maximum selected output file count.
  .OUTPUTS
    FileInfo objects for extracted files.
  #>
  [OutputType([IO.FileInfo[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [string]$Name = '*',
    [switch]$RawResources,
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Prompt',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 4294967296,
    [ValidateRange(1, [int]::MaxValue)][int]$MaximumEntries = 65536
  )

  process {
    $File = Get-Item -LiteralPath (Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf) -Force -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($DestinationPath)) { $DestinationPath = New-TempFolder }
    $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
    $null = New-Item -Path $DestinationPath -ItemType Directory -Force
    $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
      $Managed = Get-MicaSetupManagedInfo -Stream $Stream
      $HasConfigurationHost = $Managed.FileKind -eq 'Executable' -and (($Managed.HasOptionType -and $Managed.HasUseOptionsMethod) -or ($Managed.HasPackType -and $Managed.HasUsePackMethod))
      if (-not $HasConfigurationHost) { throw 'The PE is not a supported MicaSetup installer.' }
      $Options = ConvertTo-MicaSetupOptionMap -Evidence $Managed.Options
      $PasswordEvidence = $Options.Internal['UnpackingPassword']
      if ($PasswordEvidence -and -not $PasswordEvidence.IsResolved) { throw 'The MicaSetup payload password is dynamic and cannot be recovered statically.' }
      $Password = if ($PasswordEvidence -and -not [string]::IsNullOrEmpty([string]$PasswordEvidence.Value)) { [string]$PasswordEvidence.Value } else { $null }

      if ($RawResources) {
        $Files = [Collections.Generic.List[IO.FileInfo]]::new()
        $ReservedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $ExpandedBytes = 0L
        $EntryCount = 0
        foreach ($Resource in $Managed.Resources) {
          if ($Resource.TypeCode -notin 32, 33 -or -not (Test-ExtractionPattern -Path $Resource.Name -Pattern $Name)) { continue }
          if (++$EntryCount -gt $MaximumEntries) { throw "The MicaSetup resource selection exceeds the $MaximumEntries-entry limit." }
          if ($Resource.Length -gt $MaximumExpandedBytes - $ExpandedBytes) { throw "The MicaSetup resource selection exceeds the $MaximumExpandedBytes-byte output limit." }
          $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $Resource.Name -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
          if (-not $Target.ShouldWrite) { continue }
          $Parent = Split-Path -Parent $Target.Path
          $null = New-Item -Path $Parent -ItemType Directory -Force
          $Output = [IO.File]::Open($Target.Path, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
          try { Copy-BinaryStreamRange -Source $Stream -Destination $Output -Offset $Resource.Offset -Length $Resource.Length } finally { $Output.Dispose() }
          $OutputFile = Get-Item -LiteralPath $Target.Path -Force
          $ExpandedBytes += $OutputFile.Length
          $Files.Add($OutputFile)
        }
        return @($Files)
      }

      $Payload = @($Managed.Resources | Where-Object { $_.Name -ieq $Script:MicaSetupPayloadResourceName -and $_.TypeCode -eq 33 })
      if ($Payload.Count -ne 1) { throw 'The MicaSetup publish.7z resource is absent or ambiguous.' }
      $ArchiveContext = Open-MicaSetupPayloadArchive -Stream $Stream -Resource $Payload[0] -ArchiveKey $Password
      try {
        $Selection = Export-InstallerArchiveSelection -Archive $ArchiveContext.Archive -DestinationPath $DestinationPath -Name $Name -CollisionAction $CollisionAction -MaximumExpandedBytes $MaximumExpandedBytes -MaximumEntries $MaximumEntries
        $Files = [Collections.Generic.List[IO.FileInfo]]::new()
        foreach ($OutputFile in $Selection.Files) { $Files.Add($OutputFile) }

        $CreateUninstaller = [bool](Get-MicaSetupOptionValue -OptionMap $Options.Internal -Name 'IsCreateUninst' -DefaultValue $true)
        $UninstallerResource = @($Managed.Resources | Where-Object Name -IEQ $Script:MicaSetupUninstallerResourceName)
        $UninstallerLower = $Managed.BuilderGeneration -eq 'v2' -and [bool](Get-MicaSetupOptionValue -OptionMap $Options.Internal -Name 'IsUninstLower' -DefaultValue $false)
        $UninstallerName = if ($UninstallerLower) { 'uninst.exe' } else { 'Uninst.exe' }
        if ($CreateUninstaller -and $UninstallerResource.Count -eq 1 -and (Test-ExtractionPattern -Path $UninstallerName -Pattern $Name)) {
          if ($Files.Count -ge $MaximumEntries) { throw "The MicaSetup output exceeds the $MaximumEntries-entry limit." }
          if ($UninstallerResource[0].Length -gt $MaximumExpandedBytes - $Selection.ExpandedBytes) { throw "The MicaSetup output exceeds the $MaximumExpandedBytes-byte output limit." }
          $ReservedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
          foreach ($OutputFile in $Files) { $null = $ReservedPaths.Add($OutputFile.FullName) }
          $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $UninstallerName -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
          if ($Target.ShouldWrite) {
            $Output = [IO.File]::Open($Target.Path, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try { Copy-BinaryStreamRange -Source $Stream -Destination $Output -Offset $UninstallerResource[0].Offset -Length $UninstallerResource[0].Length } finally { $Output.Dispose() }
            $Files.Add((Get-Item -LiteralPath $Target.Path -Force))
          }
        }
        return @($Files)
      } finally { Close-MicaSetupPayloadArchive -Context $ArchiveContext }
    } finally { $Stream.Dispose() }
  }
}

function Read-ProductVersionFromMicaSetup {
  <#
  .SYNOPSIS
    Read the configured MicaSetup DisplayVersion.
  .PARAMETER Path
    Path to the MicaSetup installer.
  #>
  [OutputType([string])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { return (Get-MicaSetupInfo -Path $Path).DisplayVersion }
}

function Read-ProductNameFromMicaSetup {
  <#
  .SYNOPSIS
    Read the configured MicaSetup DisplayName.
  .PARAMETER Path
    Path to the MicaSetup installer.
  #>
  [OutputType([string])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { return (Get-MicaSetupInfo -Path $Path).DisplayName }
}

function Read-PublisherFromMicaSetup {
  <#
  .SYNOPSIS
    Read the configured MicaSetup Publisher.
  .PARAMETER Path
    Path to the MicaSetup installer.
  #>
  [OutputType([string])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { return (Get-MicaSetupInfo -Path $Path).Publisher }
}

function Read-ProductCodeFromMicaSetup {
  <#
  .SYNOPSIS
    Read a visible MicaSetup uninstall key name.
  .PARAMETER Path
    Path to the MicaSetup installer.
  #>
  [OutputType([string])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { return (Get-MicaSetupInfo -Path $Path).ProductCode }
}

function Read-ScopeFromMicaSetup {
  <#
  .SYNOPSIS
    Read the resolved MicaSetup installation scope.
  .PARAMETER Path
    Path to the MicaSetup installer.
  #>
  [OutputType([string])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { return (Get-MicaSetupInfo -Path $Path).Scope }
}

function Read-ProtocolsFromMicaSetup {
  <#
  .SYNOPSIS
    Read literal protocol associations proven by the MicaSetup parser.
  .PARAMETER Path
    Path to the MicaSetup installer.
  #>
  [OutputType([string[]])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { return @((Get-MicaSetupInfo -Path $Path).Protocols) }
}

function Read-FileExtensionsFromMicaSetup {
  <#
  .SYNOPSIS
    Read literal file-extension associations proven by the MicaSetup parser.
  .PARAMETER Path
    Path to the MicaSetup installer.
  #>
  [OutputType([string[]])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { return @((Get-MicaSetupInfo -Path $Path).FileExtensions) }
}

Export-ModuleMember -Function Get-MicaSetupInfo, Test-MicaSetupInstaller, Expand-MicaSetupInstaller, Read-ProductVersionFromMicaSetup, Read-ProductNameFromMicaSetup, Read-PublisherFromMicaSetup, Read-ProductCodeFromMicaSetup, Read-ScopeFromMicaSetup, Read-ProtocolsFromMicaSetup, Read-FileExtensionsFromMicaSetup
