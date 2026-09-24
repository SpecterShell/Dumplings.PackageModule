# SPDX-License-Identifier: Apache-2.0
# Format research: https://gist.github.com/mickael9/0b902da7c13207d1b86e
# Metakit format and X/MIT-licensed reference: https://www.equi4.com/metakit/format.html
# https://github.com/jcw/metakit
# Static BitRock/VMware InstallBuilder parser. InstallBuilder embeds its project
# VFS in a TclKit/Metakit container; this module reads bounded project records
# and CookFS pages but never loads Tcl, TclKit, or the installer executable.
# Binary structure consumed here (CookFS integers are BE):
#
#   PE/TclKit
#   `-- Metakit VFS -> dirs[name:S,parent:I,files[name:S,size:I,date:I,contents:B]]
#       +-- exact project.xml and origindist control records
#       +-- stored/zlib legacy payload records
#       `-- optional CookFS pages -> page-size table (u32 BE)* -> compressed index
#           -> index magic "CFS2.200" -> 16-byte footer -> "CFS0002"
#
# Footer-relative fields are IndexSize@-16, PageCount@-12, and compression@-8.
# CookFS records begin with a compression ID (stored/Deflate/BZip2/custom LZMA).
# Encrypted/custom records are rejected; page/index/count/path limits are enforced.

# Apply default function parameters

# InstallBuilder Public layer. Internal modules are imported locally; public commands stay in the facade.
Import-Module (Join-Path $PSScriptRoot 'InstallBuilderPayload.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'InstallBuilderProject.psm1') -ErrorAction Stop

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:InstallBuilderMaximumProjectBytes = 16777216

$Script:InstallBuilderMaximumPayloadAnalysisBytes = 536870912

$Script:InstallBuilderStrictUtf8 = [Text.UTF8Encoding]::new($false, $true)

function Get-InstallBuilderPrimaryPayloadAnalysis {
  <#
  .SYNOPSIS
    Analyze source-referenced installed executables and bounded adjacent sidecars.
  .PARAMETER Path
    Resolved installer path.
  .PARAMETER Payload
    Logical payload catalog produced by the current top-level parse.
  .PARAMETER PrimaryExecutableCandidate
    Logical executable paths referenced by shortcuts or execution actions.
  .PARAMETER Cookfs
    Parsed CookFS layout, or null for legacy Metakit media.
  .PARAMETER MetakitLayouts
    Validated Metakit layouts used for legacy selected extraction.
  .PARAMETER MaximumAnalysisBytes
    Maximum aggregate bytes materialized for architecture and dependency analysis.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [AllowNull()][object[]]$Payload,
    [AllowNull()][string[]]$PrimaryExecutableCandidate,
    [AllowNull()][object]$Cookfs,
    [AllowNull()][object[]]$MetakitLayouts,
    [ValidateRange(1048576, [long]::MaxValue)][long]$MaximumAnalysisBytes = $Script:InstallBuilderMaximumPayloadAnalysisBytes
  )

  $Diagnostics = [Collections.Generic.List[object]]::new()
  $DefaultPayload = @($Payload | Where-Object ConditionState -EQ 'True')
  $Primary = [Collections.Generic.List[object]]::new()
  foreach ($Candidate in @($PrimaryExecutableCandidate | Select-Object -Unique)) {
    $Match = @($DefaultPayload | Where-Object Path -CEQ $Candidate)
    if ($Match.Count -eq 1) { $Primary.Add($Match[0]) }
  }
  if ($Primary.Count -eq 0) {
    return [pscustomobject]@{ ArchitectureInfo = @(); Architectures = @(); DependencyInfo = @(); InspectedFiles = @(); Diagnostics = @() }
  }
  if ($Primary.Count -gt 4) {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Payload.PrimaryExecutableLimit' -Source InstallBuilder -Message 'Only the first four source-referenced primary executables were inspected.' -Kind Information -Areas Metadata -AffectedFields @('Architecture', 'Dependencies') -Evidence ([pscustomobject]@{ CandidateCount = $Primary.Count; Limit = 4 })))
    $Primary = [Collections.Generic.List[object]]@($Primary | Select-Object -First 4)
  }

  $Selected = [Collections.Generic.List[object]]::new()
  $SelectedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  [long]$SelectedBytes = 0
  foreach ($Item in $Primary) {
    $ItemLength = $Item.PSObject.Properties['Length'] ? [long]$Item.Length : [long]$Item.Size
    if ($SelectedBytes -gt $MaximumAnalysisBytes - $ItemLength) { continue }
    if ($SelectedPaths.Add([string]$Item.Path)) { $Selected.Add($Item); $SelectedBytes += $ItemLength }
    $Directory = [IO.Path]::GetDirectoryName(([string]$Item.Path).Replace('/', '\'))
    foreach ($Related in @($DefaultPayload | Where-Object {
          $RelatedPath = ([string]$_.Path).Replace('/', '\')
          [IO.Path]::GetDirectoryName($RelatedPath) -ieq $Directory -and $RelatedPath -match '(?i)\.(?:dll|deps\.json|runtimeconfig\.json)$'
        } | Select-Object -First 64)) {
      $RelatedLength = $Related.PSObject.Properties['Length'] ? [long]$Related.Length : [long]$Related.Size
      if ($SelectedBytes -gt $MaximumAnalysisBytes - $RelatedLength) { break }
      if ($SelectedPaths.Add([string]$Related.Path)) { $Selected.Add($Related); $SelectedBytes += $RelatedLength }
    }
  }
  if ($Selected.Count -eq 0) {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Payload.AnalysisLimit' -Source InstallBuilder -Message 'The source-referenced primary executable payloads exceed the configured static-analysis limit.' -Kind Unsupported -Areas Metadata -AffectedFields @('Architecture', 'Dependencies') -Evidence ([pscustomobject]@{ MaximumAnalysisBytes = $MaximumAnalysisBytes })))
    return [pscustomobject]@{ ArchitectureInfo = @(); Architectures = @(); DependencyInfo = @(); InspectedFiles = @(); Diagnostics = $Diagnostics.ToArray() }
  }

  $TemporaryDirectory = New-TempFolder
  try {
    $Files = @(Export-InstallBuilderPayloadSelection -Path $Path -Entry $Selected.ToArray() -Cookfs $Cookfs -MetakitLayouts $MetakitLayouts -DestinationPath $TemporaryDirectory -MaximumExpandedBytes $MaximumAnalysisBytes)
    $ArchitectureInfo = [Collections.Generic.List[object]]::new()
    $DependencyInfo = [Collections.Generic.List[object]]::new()
    foreach ($Item in $Primary) {
      if (-not $SelectedPaths.Contains([string]$Item.Path)) { continue }
      $ExpectedPath = Resolve-SafeExtractionPath -DestinationPath $TemporaryDirectory -RelativePath ([string]$Item.Path)
      $PrimaryFile = @($Files | Where-Object FullName -EQ $ExpectedPath)
      if ($PrimaryFile.Count -ne 1) { continue }
      $Directory = $PrimaryFile[0].DirectoryName
      $RelatedFiles = @($Files | Where-Object { $_.FullName -cne $PrimaryFile[0].FullName -and $_.DirectoryName -ieq $Directory })
      try {
        $ArchitectureInfo.Add((Get-PEArchitectureInfo -Path $PrimaryFile[0].FullName -RelatedFile @($RelatedFiles | Where-Object Extension -IEQ '.dll' | Select-Object -ExpandProperty FullName)))
      } catch {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Payload.ArchitectureUnavailable' -Source InstallBuilder -Message "Payload architecture analysis failed for '$($Item.Path)': $($_.Exception.Message)" -Kind Incomplete -Areas Metadata -AffectedFields Architecture))
      }
      try {
        $DependencyInfo.Add((Get-PEDependencyInfo -Path $PrimaryFile[0].FullName -RelatedFile @($RelatedFiles | Select-Object -ExpandProperty FullName)))
      } catch {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Payload.DependenciesUnavailable' -Source InstallBuilder -Message "Payload dependency analysis failed for '$($Item.Path)': $($_.Exception.Message)" -Kind Incomplete -Areas Metadata -AffectedFields Dependencies))
      }
    }
    foreach ($Child in @($ArchitectureInfo) + @($DependencyInfo)) {
      foreach ($Diagnostic in @($Child.Diagnostics)) { if ($Diagnostic) { $Diagnostics.Add($Diagnostic) } }
    }
    return [pscustomobject]@{
      ArchitectureInfo = $ArchitectureInfo.ToArray()
      Architectures    = [string[]]@($ArchitectureInfo.RecommendedWinGetArchitectures | Where-Object { $_ -in 'x86', 'x64', 'arm64' } | Sort-Object -Unique)
      DependencyInfo   = $DependencyInfo.ToArray()
      InspectedFiles   = [string[]]@($Selected.Path)
      Diagnostics      = @(Merge-InstallerDiagnostics -Diagnostic $Diagnostics.ToArray())
    }
  } finally { Remove-Item -LiteralPath $TemporaryDirectory -Recurse -Force -ErrorAction SilentlyContinue }
}

function Get-InstallBuilderShortcutInfo {
  <#
  .SYNOPSIS
    Read compiled shortcut targets and their inherited runtime conditions.
  .PARAMETER Xml
    Parsed InstallBuilder project document.
  .PARAMETER Context
    Deterministic project variables and condition evidence.
  .PARAMETER Payload
    Logical payload catalog used only to identify embedded shortcut targets.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][xml]$Xml,
    [Parameter(Mandatory)]$Context,
    [AllowEmptyCollection()][object[]]$Payload = @()
  )

  $PayloadPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($Item in @($Payload)) { $null = $PayloadPaths.Add(([string]$Item.Path).Replace('\', '/')) }

  foreach ($Shortcut in @($Xml.SelectNodes('//shortcut'))) {
    $Condition = Get-InstallBuilderNodeCondition -Node $Shortcut -Context $Context
    $Resolve = {
      param([string]$Name)
      $Raw = (Get-InstallBuilderXmlValue -Xml $Shortcut -XPath $Name) ?? $Shortcut.GetAttribute($Name)
      (Resolve-InstallBuilderProjectValue -Value $Raw -Variables $Context.Variables).Value
    }
    $Target = (& $Resolve 'windowsExec') ?? (& $Resolve 'exec')
    $PayloadPath = Resolve-InstallBuilderPayloadPath -Path $Target -Context $Context -PayloadPath $PayloadPaths
    [pscustomobject][ordered]@{
      Name              = & $Resolve 'name'
      Target            = $Target
      Arguments         = & $Resolve 'windowsExecArgs'
      WorkingDirectory  = (& $Resolve 'windowsPath') ?? (& $Resolve 'path')
      Icon              = (& $Resolve 'windowsIcon') ?? (& $Resolve 'icon')
      Platforms         = & $Resolve 'platforms'
      PayloadPath       = $PayloadPath
      IsEmbeddedPayload = [bool]$PayloadPath
      ConditionState    = $Condition.State
      Conditions        = $Condition.Conditions
    }
  }
}

function Get-InstallBuilderRequirementInfo {
  <#
  .SYNOPSIS
    Project structured Java and Windows-version requirements without resolving host state.
  .PARAMETER Xml
    Parsed InstallBuilder project document.
  .PARAMETER Context
    Deterministic project variables and target-platform evidence used for inherited conditions.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][xml]$Xml,
    [Parameter(Mandatory)]$Context
  )

  $Java = [Collections.Generic.List[object]]::new()
  foreach ($Action in @($Xml.SelectNodes('//autodetectJava'))) {
    $Condition = Get-InstallBuilderNodeCondition -Node $Action -Context $Context
    $Versions = [Collections.Generic.List[object]]::new()
    foreach ($ValidVersion in @($Action.SelectNodes('validVersionList/validVersion'))) {
      $Versions.Add([pscustomobject][ordered]@{
          MinimumVersion = Get-InstallBuilderXmlValue -Xml $ValidVersion -XPath 'minVersion'
          MaximumVersion = Get-InstallBuilderXmlValue -Xml $ValidVersion -XPath 'maxVersion'
          Vendor         = Get-InstallBuilderXmlValue -Xml $ValidVersion -XPath 'vendor'
          Bitness        = Get-InstallBuilderXmlValue -Xml $ValidVersion -XPath 'bitness'
          RequireJdk     = Test-InstallBuilderTrueValue (Get-InstallBuilderXmlValue -Xml $ValidVersion -XPath 'requireJDK')
        })
    }
    $Java.Add([pscustomobject][ordered]@{
        PromptUser     = Test-InstallBuilderTrueValue (Get-InstallBuilderXmlValue -Xml $Action -XPath 'promptUser')
        ValidVersions  = $Versions.ToArray()
        ConditionState = $Condition.State
        Conditions     = $Condition.Conditions
      })
  }

  # autodetectDotNetFramework is a declarative version-range probe. Preserve the accepted ranges
  # as dependency evidence without mapping them to a particular package-provider identifier.
  $DotNetFramework = [Collections.Generic.List[object]]::new()
  foreach ($Action in @($Xml.SelectNodes('//autodetectDotNetFramework'))) {
    $Condition = Get-InstallBuilderNodeCondition -Node $Action -Context $Context
    $Versions = [Collections.Generic.List[object]]::new()
    foreach ($ValidVersion in @($Action.SelectNodes('validDotNetVersionList/validDotNetVersion'))) {
      $Versions.Add([pscustomobject][ordered]@{
          MinimumVersion = Get-InstallBuilderXmlValue -Xml $ValidVersion -XPath 'minVersion'
          MaximumVersion = Get-InstallBuilderXmlValue -Xml $ValidVersion -XPath 'maxVersion'
        })
    }
    $DotNetFramework.Add([pscustomobject][ordered]@{
        ValidVersions  = $Versions.ToArray()
        ConditionState = $Condition.State
        Conditions     = $Condition.Conditions
      })
  }

  $Windows = [Collections.Generic.List[object]]::new()
  foreach ($Rule in @($Xml.SelectNodes('//compareVersions'))) {
    $Version1 = (Get-InstallBuilderXmlValue -Xml $Rule -XPath 'version1') ?? $Rule.GetAttribute('version1')
    $Version2 = (Get-InstallBuilderXmlValue -Xml $Rule -XPath 'version2') ?? $Rule.GetAttribute('version2')
    if ($Version1 -notmatch '\$\{windows_os_version_number\}' -and $Version2 -notmatch '\$\{windows_os_version_number\}') { continue }
    $Windows.Add([pscustomobject][ordered]@{
        Version1 = $Version1
        Version2 = $Version2
        Logic    = (Get-InstallBuilderXmlValue -Xml $Rule -XPath 'logic') ?? $Rule.GetAttribute('logic')
        State    = (Resolve-InstallBuilderRuleState -Rule $Rule -Context $Context).State
        Xml      = $Rule.OuterXml
      })
  }
  [pscustomobject][ordered]@{
    Java                = $Java.ToArray()
    DotNetFramework     = $DotNetFramework.ToArray()
    WindowsVersionRules = $Windows.ToArray()
  }
}

function Get-InstallBuilderArpInfo {
  <#
  .SYNOPSIS
    Reconstruct built-in and literal custom InstallBuilder ARP entries.
  .PARAMETER Xml
    Parsed InstallBuilder project document.
  .PARAMETER Context
    Shared project context containing deterministic variables and PE evidence.
  .PARAMETER RegistryWrite
    Effective registrySet actions. Conditional actions remain evidence but do not become authoritative entries.
  .PARAMETER RegistryDelete
    Parsed registryDelete actions used to account for changes after built-in uninstaller creation.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][xml]$Xml,
    [Parameter(Mandatory)]$Context,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$RegistryWrite,
    [AllowEmptyCollection()][object[]]$RegistryDelete = @()
  )

  $InstallationType = Get-InstallBuilderProjectProperty -Xml $Xml -Name installationType
  $CreateUninstaller = Test-InstallBuilderTrueValue (Get-InstallBuilderProjectProperty -Xml $Xml -Name createUninstaller)
  $CreateWindowsArpEntry = Test-InstallBuilderTrueValue (Get-InstallBuilderProjectProperty -Xml $Xml -Name createWindowsARPEntry)
  $HasBuiltInUninstaller = $InstallationType -ieq 'normal' -and $CreateUninstaller
  $WritesBuiltInArp = $HasBuiltInUninstaller -and $CreateWindowsArpEntry
  $EntryMap = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
  $Diagnostics = [Collections.Generic.List[object]]::new()

  $BuiltInProductCode = $null
  if ($WritesBuiltInArp) {
    $PrefixResult = Resolve-InstallBuilderProjectValue -Value (Get-InstallBuilderProjectProperty -Xml $Xml -Name windowsARPRegistryPrefix) -Variables $Context.Variables
    $DisplayNameResult = Resolve-InstallBuilderProjectValue -Value (Get-InstallBuilderProjectProperty -Xml $Xml -Name productDisplayName) -Variables $Context.Variables
    if ($PrefixResult.Value) {
      $BuiltInProductCode = $PrefixResult.Value
      $ResolveProperty = {
        param([string]$Name)
        (Resolve-InstallBuilderProjectValue -Value (Get-InstallBuilderProjectProperty -Xml $Xml -Name $Name) -Variables $Context.Variables).Value
      }
      $UninstallerName = $Context.UninstallerName
      if ($UninstallerName -and -not $UninstallerName.EndsWith('.exe', [StringComparison]::OrdinalIgnoreCase)) { $UninstallerName += '.exe' }
      $UninstallerPath = if ($Context.UninstallerDirectory -and $UninstallerName) { "$($Context.UninstallerDirectory.TrimEnd('/', '\'))\$UninstallerName".Replace('/', '\') } else { $null }
      $EntryMap["HKLM|$($Context.RegistryView)|$BuiltInProductCode"] = [pscustomobject][ordered]@{
        ProductCode          = $BuiltInProductCode
        DisplayName          = $DisplayNameResult.Value
        DisplayVersion       = $Context.Identity.Version.Value
        Publisher            = $Context.Identity.Vendor.Value
        InstallerType        = 'exe'
        RegistryHive         = 'HKLM'
        RegistryView         = $Context.RegistryView
        RegistryKey          = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$BuiltInProductCode"
        UninstallString      = $UninstallerPath ? "`"$UninstallerPath`"" : $null
        QuietUninstallString = $null
        DisplayIcon          = & $ResolveProperty 'productDisplayIcon'
        InstallLocation      = $Context.InstallLocation
        UrlInfoAbout         = & $ResolveProperty 'productUrlInfoAbout'
        Comments             = & $ResolveProperty 'productComments'
        Contact              = & $ResolveProperty 'productContact'
        HelpLink             = & $ResolveProperty 'productUrlHelpLink'
        SystemComponent      = $null
        NoModify             = 1
        NoRepair             = 1
        EstimatedSize        = $null
        InstallDate          = $null
        IsVisible            = $true
        ConditionState       = 'True'
        Conditions           = @()
        Source               = 'BuiltInWindowsARP'
      }
      $UnresolvedBuiltInValues = [ordered]@{}
      if (@($DisplayNameResult.UnresolvedVariables).Count) { $UnresolvedBuiltInValues.DisplayName = $DisplayNameResult.UnresolvedVariables }
      if (@($Context.Identity.Version.UnresolvedVariables).Count) { $UnresolvedBuiltInValues.DisplayVersion = $Context.Identity.Version.UnresolvedVariables }
      if (@($Context.Identity.Vendor.UnresolvedVariables).Count) { $UnresolvedBuiltInValues.Publisher = $Context.Identity.Vendor.UnresolvedVariables }
      if ($UnresolvedBuiltInValues.Count) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.ARP.BuiltInValuesUnresolved' -Source InstallBuilder -Message 'The built-in ARP key is known, but one or more display values depend on unresolved runtime variables.' -Kind Incomplete -Areas Metadata -AffectedFields @('AppsAndFeaturesEntries') -Evidence ([pscustomobject]$UnresolvedBuiltInValues)))
      }
    } else {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.ARP.BuiltInPrefixUnresolved' -Source InstallBuilder -Message "The built-in ARP registry prefix contains unresolved variables: $($PrefixResult.UnresolvedVariables -join ', ')" -Kind Incomplete -Areas Metadata -AffectedFields @('ProductCode', 'AppsAndFeaturesEntries')))
    }
  }

  # Custom registrySet actions can replace, hide, or supplement the built-in entry. Group all
  # records first so a SystemComponent override on the built-in key affects visibility.
  $CustomGroups = @($RegistryWrite | Where-Object { $_.Lifecycle -eq 'Installation' -and $_.Key -match '(^|\\)Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\.+' } | Group-Object -Property { "$($_.Root)|$($_.RawKey)" })
  foreach ($Group in $CustomGroups) {
    $RawKey = [string]$Group.Group[0].RawKey
    $KeyResult = Resolve-InstallBuilderProjectValue -Value $RawKey -Variables $Context.Variables
    if (-not $KeyResult.Value) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.ARP.CustomKeyUnresolved' -Source InstallBuilder -Message "A custom ARP registry key contains unresolved variables: $($KeyResult.UnresolvedVariables -join ', ')" -Kind Incomplete -Areas Metadata -AffectedFields @('ProductCode', 'AppsAndFeaturesEntries') -Evidence ([pscustomobject]@{ Key = $RawKey; Variables = $KeyResult.UnresolvedVariables })))
      continue
    }
    $ProductCode = Split-Path -Path $KeyResult.Value.Replace('/', '\') -Leaf
    if ([string]::IsNullOrWhiteSpace($ProductCode)) { continue }
    $Root = @($Group.Group.Root | Where-Object { $_ } | Select-Object -Unique)
    $WowMode = @($Group.Group.WowMode | Where-Object { $_ } | Select-Object -Unique)
    $RegistryView = if ($WowMode -contains '32') { '32-bit' } elseif ($WowMode -contains '64') { '64-bit' } else { $Context.RegistryView }
    $Identity = "$($Root.Count -eq 1 ? $Root[0] : '')|$RegistryView|$ProductCode"
    $Existing = $EntryMap.ContainsKey($Identity) ? $EntryMap[$Identity] : $null
    $Values = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
    if ($Existing) { foreach ($Property in $Existing.PSObject.Properties) { $Values[$Property.Name] = $Property.Value } }
    foreach ($Write in @($Group.Group | Where-Object ConditionState -EQ 'True')) {
      if ([string]::IsNullOrWhiteSpace($Write.Name)) { continue }
      $ValueResult = Resolve-InstallBuilderProjectValue -Value $Write.Value -Variables $Context.Variables
      if ($null -ne $ValueResult.Value) { $Values[$Write.Name] = $ValueResult.Value }
    }
    $UnknownWrites = @($Group.Group | Where-Object ConditionState -EQ 'Unknown')
    $HasTrueWrite = @($Group.Group | Where-Object ConditionState -EQ 'True').Count -gt 0
    if (-not $HasTrueWrite -and -not $Existing -and -not $UnknownWrites.Count) { continue }
    $SystemComponent = $Values.ContainsKey('SystemComponent') ? $Values['SystemComponent'] : $null
    $VisibilityUnknown = @($UnknownWrites | Where-Object Name -IEQ 'SystemComponent').Count -gt 0
    $SystemComponentNumber = 0L
    $IsHidden = if ($null -eq $SystemComponent) {
      $false
    } elseif ([long]::TryParse([string]$SystemComponent, [Globalization.NumberStyles]::Integer, [Globalization.CultureInfo]::InvariantCulture, [ref]$SystemComponentNumber)) {
      $SystemComponentNumber -ne 0
    } else {
      Test-InstallBuilderTrueValue ([string]$SystemComponent)
    }
    $IsVisible = $VisibilityUnknown ? $null : -not $IsHidden
    $EntryMap[$Identity] = [pscustomobject][ordered]@{
      ProductCode          = $ProductCode
      DisplayName          = $Values.ContainsKey('DisplayName') ? $Values['DisplayName'] : $null
      DisplayVersion       = $Values.ContainsKey('DisplayVersion') ? $Values['DisplayVersion'] : $null
      Publisher            = $Values.ContainsKey('Publisher') ? $Values['Publisher'] : $null
      InstallerType        = 'exe'
      RegistryHive         = $Root.Count -eq 1 ? $Root[0] : $null
      RegistryView         = $RegistryView
      RegistryKey          = ($KeyResult.Value -replace '^HKEY_LOCAL_MACHINE\\?', '' -replace '^HKLM\\?', '' -replace '^HKEY_CURRENT_USER\\?', '' -replace '^HKCU\\?', '')
      UninstallString      = $Values.ContainsKey('UninstallString') ? $Values['UninstallString'] : $null
      QuietUninstallString = $Values.ContainsKey('QuietUninstallString') ? $Values['QuietUninstallString'] : $null
      DisplayIcon          = $Values.ContainsKey('DisplayIcon') ? $Values['DisplayIcon'] : $null
      InstallLocation      = $Values.ContainsKey('InstallLocation') ? $Values['InstallLocation'] : $null
      UrlInfoAbout         = $Values.ContainsKey('UrlInfoAbout') ? $Values['UrlInfoAbout'] : $null
      Comments             = $Values.ContainsKey('Comments') ? $Values['Comments'] : $null
      Contact              = $Values.ContainsKey('Contact') ? $Values['Contact'] : $null
      HelpLink             = $Values.ContainsKey('HelpLink') ? $Values['HelpLink'] : $null
      SystemComponent      = $SystemComponent
      NoModify             = $Values.ContainsKey('NoModify') ? $Values['NoModify'] : $null
      NoRepair             = $Values.ContainsKey('NoRepair') ? $Values['NoRepair'] : $null
      EstimatedSize        = $Values.ContainsKey('EstimatedSize') ? $Values['EstimatedSize'] : $null
      InstallDate          = $Values.ContainsKey('InstallDate') ? $Values['InstallDate'] : $null
      IsVisible            = $IsVisible
      ConditionState       = ($Existing -or $HasTrueWrite) ? 'True' : 'Unknown'
      Conditions           = @($Group.Group.Conditions)
      Source               = $Existing ? 'BuiltInWindowsARP+RegistrySet' : 'RegistrySet'
    }
    if ($UnknownWrites.Count) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.ARP.ConditionalValues' -Source InstallBuilder -Message "The custom uninstall key '$ProductCode' has condition-dependent values; unconditional identity remains usable, but affected ARP values require runtime evidence." -Kind Ambiguous -Areas Metadata -AffectedFields @('AppsAndFeaturesEntries') -Evidence ([pscustomobject]@{ ProductCode = $ProductCode; ConditionalValueNames = @($UnknownWrites.Name | Where-Object { $_ } | Select-Object -Unique) })))
    }
  }

  # InstallBuilder creates its built-in uninstaller and ARP entry after postInstallationActionList
  # and before postUninstallerCreationActionList. Only the latter list can remove the final built-in
  # registration; earlier deletes are followed by built-in recreation.
  if ($BuiltInProductCode) {
    $BuiltInIdentity = "HKLM|$($Context.RegistryView)|$BuiltInProductCode"
    $BuiltInKey = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$BuiltInProductCode"
    $ArpValueProperty = @{
      DisplayName          = 'DisplayName'
      DisplayVersion       = 'DisplayVersion'
      Publisher            = 'Publisher'
      UninstallString      = 'UninstallString'
      QuietUninstallString = 'QuietUninstallString'
      DisplayIcon          = 'DisplayIcon'
      InstallLocation      = 'InstallLocation'
      URLInfoAbout         = 'UrlInfoAbout'
      Comments             = 'Comments'
      Contact              = 'Contact'
      HelpLink             = 'HelpLink'
      SystemComponent      = 'SystemComponent'
      NoModify             = 'NoModify'
      NoRepair             = 'NoRepair'
      EstimatedSize        = 'EstimatedSize'
      InstallDate          = 'InstallDate'
    }
    foreach ($Delete in @($RegistryDelete | Where-Object { $_.Lifecycle -eq 'Installation' -and $_.Phase -eq 'postUninstallerCreationActionList' -and $_.Root -eq 'HKLM' -and $_.RegistryView -eq $Context.RegistryView -and $_.ResolvedKey })) {
      $DeleteKey = $Delete.ResolvedKey.Trim('\')
      $DeletesWholeKey = [string]::IsNullOrWhiteSpace([string]$Delete.Name)
      $MatchesKey = if ($DeletesWholeKey) {
        $BuiltInKey -ieq $DeleteKey -or $BuiltInKey.StartsWith($DeleteKey + '\', [StringComparison]::OrdinalIgnoreCase)
      } else {
        $BuiltInKey -ieq $DeleteKey
      }
      if (-not $MatchesKey -or -not $EntryMap.ContainsKey($BuiltInIdentity)) { continue }

      $Entry = $EntryMap[$BuiltInIdentity]
      if ($Delete.ConditionState -ne 'True' -or @($Delete.UnresolvedVariables).Count) {
        $Entry.ConditionState = 'Unknown'
        if ($DeletesWholeKey -or $Delete.Name -in 'DisplayName', 'SystemComponent') { $Entry.IsVisible = $null }
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.ARP.PostCreationDeleteConditional' -Source InstallBuilder -Message "A condition-dependent post-uninstaller action can delete built-in ARP registry evidence for '$BuiltInProductCode'." -Kind Ambiguous -Areas Metadata -AffectedFields @('ProductCode', 'AppsAndFeaturesEntries') -Evidence $Delete))
        continue
      }
      if ($DeletesWholeKey) {
        $null = $EntryMap.Remove($BuiltInIdentity)
      } elseif ($ArpValueProperty.ContainsKey([string]$Delete.Name)) {
        $Property = $ArpValueProperty[[string]$Delete.Name]
        $Entry.$Property = $null
        if ($Property -eq 'DisplayName') { $Entry.IsVisible = $false }
      }
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.ARP.PostCreationDeleteApplied' -Source InstallBuilder -Message "A post-uninstaller action deletes built-in ARP registry evidence for '$BuiltInProductCode'; final ARP projection reflects the deletion." -Kind Information -Areas Metadata -AffectedFields @('ProductCode', 'AppsAndFeaturesEntries') -Evidence $Delete))
    }
  }

  $UniqueEntries = @($EntryMap.Values | Sort-Object RegistryHive, RegistryView, ProductCode)
  $VisibleEntries = @($UniqueEntries | Where-Object { $_.IsVisible -eq $true -and $_.ConditionState -eq 'True' })
  $UncertainEntries = @($UniqueEntries | Where-Object { $null -eq $_.IsVisible -or $_.ConditionState -eq 'Unknown' })
  $HiddenEntries = @($UniqueEntries | Where-Object IsVisible -EQ $false)
  if ($HiddenEntries.Count -and -not $VisibleEntries.Count) {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.ARP.HiddenOnly' -Source InstallBuilder -Message 'The installer writes only hidden uninstall registration evidence; hidden SystemComponent entries are not projected as WinGet AppsAndFeaturesEntries.' -Kind Information -Areas Metadata -AffectedFields @('ProductCode', 'AppsAndFeaturesEntries') -Evidence ([pscustomobject]@{ ProductCodes = @($HiddenEntries.ProductCode) })))
  }
  $VisibleBuiltInEntry = if ($BuiltInProductCode) { $VisibleEntries | Where-Object ProductCode -EQ $BuiltInProductCode | Select-Object -First 1 } else { $null }
  # Prefer the runtime-owned built-in entry while it survives. If a final action removes or hides
  # that row, one unambiguous custom visible entry becomes the package's effective ARP identity.
  $Primary = if ($VisibleBuiltInEntry) { $VisibleBuiltInEntry } elseif ($VisibleEntries.Count -eq 1) { $VisibleEntries[0] } else { $null }
  [pscustomobject]@{
    InstallationType      = $InstallationType
    HasBuiltInUninstaller = $HasBuiltInUninstaller
    WritesBuiltInArp      = $WritesBuiltInArp
    WritesAppsAndFeatures = if ($VisibleEntries.Count) { $true } elseif ($UncertainEntries.Count -or $InstallationType -ieq 'upgrade') { $null } else { $false }
    ProductCode           = $Primary ? $Primary.ProductCode : $null
    PrimaryEntry          = $Primary
    Entries               = $UniqueEntries
    VisibleEntries        = $VisibleEntries
    HiddenEntries         = $HiddenEntries
    UncertainEntries      = $UncertainEntries
    Diagnostics           = $Diagnostics.ToArray()
  }
}

function Get-InstallBuilderInfo {
  <#
  .SYNOPSIS
    Get static metadata from a BitRock or VMware InstallBuilder installer
  .DESCRIPTION
    The parser recovers zlib-compressed project XML and the CookFS file index
    held by the embedded Metakit VFS. It never mounts TclKit or executes Tcl.
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER AnalyzePrimaryExecutables
    Selectively extract source-referenced application executables and adjacent sidecars, then run
    bounded PE architecture and dependency analysis. This is opt-in because large application
    payloads can materially increase parsing time and temporary disk use.
  .PARAMETER MaximumPayloadAnalysisBytes
    Maximum aggregate bytes materialized when AnalyzePrimaryExecutables is specified.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [switch]$AnalyzePrimaryExecutables,
    [ValidateRange(1048576, [long]::MaxValue)][long]$MaximumPayloadAnalysisBytes = $Script:InstallBuilderMaximumPayloadAnalysisBytes
  )
  process {
    $File = Get-Item -LiteralPath $Path -Force
    # project.xml is authoritative for identity, scope actions, and registry writes. CookFS is an
    # independent optional payload index and is not required for metadata-only parsing.
    $Project = Get-InstallBuilderProjectData -Path $File.FullName
    $Xml = [xml]$Project.Content
    $RawFullName = Get-InstallBuilderXmlValue -Xml $Xml -XPath '/project/fullName'
    $Context = Get-InstallBuilderProjectContext -Xml $Xml -Path $File.FullName
    $ShortName = $Context.Identity.ShortName.Value
    $FullName = $Context.Identity.FullName.Value
    $Version = $Context.Identity.Version.Value
    $Vendor = $Context.Identity.Vendor.Value
    $DisplayName = $null -ne $RawFullName ? $FullName : $ShortName
    $RegistryOperations = @(Get-InstallBuilderRegistryOperation -Xml $Xml -Context $Context)
    $RegistryWrites = @($RegistryOperations | Where-Object Operation -EQ 'Set')
    $RegistryDeletes = @($RegistryOperations | Where-Object Operation -EQ 'Delete')
    $RegistryState = Resolve-InstallBuilderRegistryState -RegistryOperation $RegistryOperations
    # Preserve conditional and unresolved sets as uncertain ARP evidence, while deterministic
    # deletes are applied before either ARP or class-association projection.
    $RegistryProjectionWrites = @($RegistryState.Writes) + @($RegistryState.DeferredOperations | Where-Object Operation -EQ 'Set')
    $ArpInfo = Get-InstallBuilderArpInfo -Xml $Xml -Context $Context -RegistryWrite $RegistryProjectionWrites -RegistryDelete $RegistryDeletes
    $ScopeInfo = Get-InstallBuilderScopeInfo -Xml $Xml -Context $Context -ArpInfo $ArpInfo
    # ARP and association projection use only writes that persist after a successful installation.
    # Other phases remain available in RegistryWrites for manual analysis.
    $InstallationRegistryOperations = @($RegistryOperations | Where-Object Lifecycle -EQ 'Installation')
    $ResolvedAssociationWrites = @($RegistryState.Writes | ForEach-Object {
        [pscustomobject]@{ Root = $_.Root; Key = $_.ResolvedKey; Name = $_.Name; Value = $_.ResolvedValue; Type = $_.Type; Source = $_ }
      })
    $RegistryAssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite $ResolvedAssociationWrites
    $Diagnostics = [System.Collections.Generic.List[object]]::new()
    $UnresolvedFields = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $UnresolvedIdentity = [ordered]@{}
    $DisplayNameIdentity = $null -ne $RawFullName ? $Context.Identity.FullName : $Context.Identity.ShortName
    if (@($DisplayNameIdentity.UnresolvedVariables).Count) { $null = $UnresolvedFields.Add('DisplayName'); $UnresolvedIdentity.DisplayName = $DisplayNameIdentity.UnresolvedVariables }
    if (@($Context.Identity.Version.UnresolvedVariables).Count) { $null = $UnresolvedFields.Add('DisplayVersion'); $UnresolvedIdentity.DisplayVersion = $Context.Identity.Version.UnresolvedVariables }
    if (@($Context.Identity.Vendor.UnresolvedVariables).Count) { $null = $UnresolvedFields.Add('Publisher'); $UnresolvedIdentity.Publisher = $Context.Identity.Vendor.UnresolvedVariables }
    if ($UnresolvedIdentity.Count) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Metadata.IdentityUnresolved' -Source InstallBuilder -Message 'One or more package identity fields depend on unresolved runtime variables and were not returned as literal metadata.' -Kind Incomplete -Areas Metadata -AffectedFields @($UnresolvedIdentity.Keys) -Evidence ([pscustomobject]$UnresolvedIdentity)))
    }
    $ProjectMetakitLayout = $Project.PSObject.Properties['MetakitLayout']
    $ProjectMetakitLayouts = $Project.PSObject.Properties['MetakitLayouts']
    $ProjectMetakitEntries = $Project.PSObject.Properties['MetakitEntries']
    $ProjectOriginDirectory = $Project.PSObject.Properties['OriginDirectory']
    $MetakitLayouts = $ProjectMetakitLayouts ? @($ProjectMetakitLayouts.Value) : @(Get-InstallBuilderMetakitLayout -Path $File.FullName)
    $Cookfs = $null
    $MetakitInfo = $null
    $LegacyPayloadFiles = @()
    try {
      $Cookfs = Get-InstallBuilderCookfsInfo -Path $File.FullName
    } catch {
      # project.xml remains useful metadata evidence in older containers that
      # expose no CookFS payload footer. A present but invalid footer is useful
      # corruption evidence and remains visible to callers.
      $FooterMarker = [Text.Encoding]::ASCII.GetBytes('CFS0002')
      if (@(Find-BinaryPattern -Path $File.FullName -Pattern $FooterMarker -Maximum 1).Count -gt 0) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Payload.CookfsIndexInvalid' -Source InstallBuilder -Message "The CookFS payload index was not available: $($_.Exception.Message)" -Kind Invalid -Areas Extraction -AffectedFields @()))
      }
    }
    if (-not $Cookfs -and $MetakitLayouts.Count) {
      $LegacyArchive = $null
      try {
        if ($ProjectMetakitEntries -and $ProjectMetakitEntries.Value) {
          $MetakitEntries = @($ProjectMetakitEntries.Value)
          $OriginDirectory = $ProjectOriginDirectory.Value
          $MetakitHeaderOffset = $ProjectMetakitLayout.Value.HeaderOffset
          $MetakitLength = $ProjectMetakitLayout.Value.Length
          $MetakitRootPosition = $ProjectMetakitLayout.Value.RootPosition
          $MetakitRootLength = $ProjectMetakitLayout.Value.RootLength
        } else {
          $LegacyArchive = Open-InstallBuilderMetakitArchive -Path $File.FullName -Layout $MetakitLayouts -RequiredEntryPath 'origindist'
          $MetakitEntries = @($LegacyArchive.Entries)
          $OriginEntry = @($MetakitEntries | Where-Object Path -CEQ 'origindist')
          if ($OriginEntry.Count -ne 1) { throw 'The legacy TclKit VFS does not contain one unambiguous origindist control record' }
          $OriginDirectory = $Script:InstallBuilderStrictUtf8.GetString($LegacyArchive.ReadEntry([int]$OriginEntry[0].Index, 4096)).Trim([char]0).Trim()
          $MetakitHeaderOffset = $LegacyArchive.HeaderOffset
          $MetakitLength = $LegacyArchive.Length
          $MetakitRootPosition = $LegacyArchive.RootPosition
          $MetakitRootLength = $LegacyArchive.RootLength
        }
        if ([string]::IsNullOrWhiteSpace($OriginDirectory) -or $OriginDirectory.IndexOfAny([char[]]'\/') -ge 0) { throw 'The legacy TclKit origindist control record is invalid' }
        $LegacyPayloadFiles = @(Get-InstallBuilderLegacyPayloadEntry -Entry $MetakitEntries -Xml $Xml -Context $Context -OriginDirectory $OriginDirectory)
        $MetakitInfo = [pscustomobject][ordered]@{
          HeaderOffset     = $MetakitHeaderOffset
          Length           = $MetakitLength
          RootPosition     = $MetakitRootPosition
          RootLength       = $MetakitRootLength
          EntryCount       = $MetakitEntries.Count
          PayloadFileCount = $LegacyPayloadFiles.Count
          OriginDirectory  = $OriginDirectory
          CompressionTypes = @($LegacyPayloadFiles.Compression | Sort-Object -Unique)
        }
        if ($LegacyPayloadFiles.Count -eq 0) {
          $null = $UnresolvedFields.Add('PayloadFiles')
          $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Payload.LegacyDistAbsent' -Source 'InstallBuilder' -Message 'The legacy Metakit VFS is valid, but no package payload records match the compiled dist/<shortName>/<folderName> layout.' -Kind Incomplete -Areas Extraction -AffectedFields @()))
        }
        $UnsupportedLegacyCompression = @($LegacyPayloadFiles | Where-Object Compression -EQ 'Unknown')
        if ($UnsupportedLegacyCompression.Count) {
          $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Payload.LegacyCompressionUnsupported' -Source 'InstallBuilder' -Message "$($UnsupportedLegacyCompression.Count) legacy Metakit payload record(s) use unsupported compression framing and cannot be extracted." -Kind Unsupported -Areas Extraction -AffectedFields @()))
        }
      } catch {
        $null = $UnresolvedFields.Add('PayloadFiles')
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Payload.LegacyMetakitUnsupported' -Source 'InstallBuilder' -Message "The legacy Metakit VFS payload catalog could not be decoded: $($_.Exception.Message)" -Kind Unsupported -Areas Extraction -AffectedFields @()))
      } finally {
        if ($LegacyArchive) { $LegacyArchive.Dispose() }
      }
    }
    foreach ($Diagnostic in @($ArpInfo.Diagnostics)) { $Diagnostics.Add($Diagnostic) }
    foreach ($Diagnostic in @($RegistryAssociationInfo.Diagnostics)) { $Diagnostics.Add($Diagnostic) }
    $ExcludedRegistryOperations = @($RegistryOperations | Where-Object Lifecycle -NE 'Installation')
    if ($ExcludedRegistryOperations.Count) {
      $ExcludedPhases = @($ExcludedRegistryOperations.Phase | Sort-Object -Unique)
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Registry.NonInstallPhaseExcluded' -Source InstallBuilder -Message "$($ExcludedRegistryOperations.Count) registry operation(s) belong to non-installation or unresolved action phases and were excluded from authoritative ARP and association projection." -Kind Information -Areas Metadata -AffectedFields @('ProductCode', 'AppsAndFeaturesEntries', 'Protocols', 'FileExtensions') -Evidence ([pscustomobject]@{ Phases = $ExcludedPhases; Count = $ExcludedRegistryOperations.Count })))
    }
    if ($Project.Content -match 'MI_oJ|tcltwofish|installbuilder\.payloadinfo') {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Payload.Encrypted' -Source InstallBuilder -Message 'The installer contains encrypted-payload markers. Project metadata was recovered, but payload extraction requires the project password.' -Kind Unsupported -Areas Extraction -AffectedFields @()))
    }
    if ($Cookfs -and $Cookfs.HasUnsupportedCompression) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Payload.CompressionUnsupported' -Source InstallBuilder -Message 'The CookFS payload uses unsupported custom or encrypted compression and cannot be extracted without the project password.' -Kind Unsupported -Areas Extraction -AffectedFields @()))
    }
    if ($Cookfs -and $Cookfs.HasUnsupportedHash) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Payload.HashUnsupported' -Source InstallBuilder -Message "The CookFS payload declares unsupported page hash algorithm '$($Cookfs.PageHashAlgorithm)'; extraction cannot verify page integrity." -Kind Unsupported -Areas Extraction -AffectedFields @()))
    }
    $PayloadCatalog = if ($Cookfs) { @(Get-InstallBuilderCookfsLogicalEntry -Entry $Cookfs.Entries -Xml $Xml -Context $Context) } else { @($LegacyPayloadFiles) }
    $PayloadFiles = @($PayloadCatalog | Where-Object ConditionState -EQ 'True')
    $ConditionalPayloadFiles = @($PayloadCatalog | Where-Object ConditionState -EQ 'Unknown')
    $ExcludedPayloadFiles = @($PayloadCatalog | Where-Object ConditionState -EQ 'False')
    if ($Cookfs) {
      # Detect split segments whose base entry is missing; those cannot be safely reassembled.
      $PhysicalPaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
      foreach ($Entry in $Cookfs.Entries) { $null = $PhysicalPaths.Add($Entry.Path) }
      foreach ($Entry in $Cookfs.Entries) {
        $Match = [regex]::Match($Entry.Path, '^(?<Base>.+)___bitrockBigFile[1-9][0-9]*$', [Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if ($Match.Success -and -not $PhysicalPaths.Contains($Match.Groups['Base'].Value)) {
          $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Payload.OrphanedSplitSegment' -Source InstallBuilder -Message "CookFS payload contains an orphaned BitRock split segment: $($Entry.Path)" -Kind Invalid -Areas Extraction -AffectedFields @() -Evidence ([pscustomobject]@{ Path = $Entry.Path })))
        }
      }
    }
    if ($Context.InstallLocationResult.UnresolvedVariables.Count) {
      $null = $UnresolvedFields.Add('DefaultInstallLocation')
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Metadata.InstallLocationUnresolved' -Source InstallBuilder -Message "The installation directory contains unresolved runtime variables: $($Context.InstallLocationResult.UnresolvedVariables -join ', ')" -Kind Incomplete -Areas Metadata -AffectedFields @('DefaultInstallLocation') -Evidence ([pscustomobject]@{ Variables = $Context.InstallLocationResult.UnresolvedVariables })))
    }
    # Execution matching needs every packaged path so a conditional nested payload remains visible,
    # while PayloadFiles itself represents only the default-install selection.
    $ExecutionInfo = Get-InstallBuilderExecutionInfo -Xml $Xml -Context $Context -Payload $PayloadCatalog
    $ProjectActions = @(Get-InstallBuilderProjectActionInfo -Xml $Xml -Context $Context)
    $DynamicProjectLogic = @(Get-InstallBuilderDynamicLogicInfo -Xml $Xml -Context $Context -ProjectAction $ProjectActions)
    $ActionAssociationInfo = Get-InstallBuilderFileAssociationInfo -Xml $Xml -Context $Context
    $SystemEffectInfo = Get-InstallBuilderSystemEffectInfo -ProjectAction $ProjectActions
    foreach ($Diagnostic in @($ActionAssociationInfo.Diagnostics)) { $Diagnostics.Add($Diagnostic) }
    foreach ($Field in @($ActionAssociationInfo.UnresolvedFields)) { $null = $UnresolvedFields.Add($Field) }
    # Registry writes and the native association action are separate runtime routes. Preserve both
    # evidence sets while exposing one authoritative installed-state list to provider projections.
    $FileExtensions = @($RegistryAssociationInfo.FileExtensions) + @($ActionAssociationInfo.FileExtensions) | Sort-Object -Unique
    $FileExtensionAssociations = @($RegistryAssociationInfo.FileExtensionAssociations) + @($ActionAssociationInfo.FileExtensionAssociations)
    $AssociationInfo = [pscustomobject][ordered]@{
      Protocols                 = @($RegistryAssociationInfo.Protocols)
      FileExtensions            = [string[]]$FileExtensions
      ProtocolAssociations      = @($RegistryAssociationInfo.ProtocolAssociations)
      FileExtensionAssociations = [object[]]$FileExtensionAssociations
      RegistryWrites            = @($RegistryAssociationInfo.RegistryWrites)
      ActionAssociations        = @($ActionAssociationInfo.FileExtensionAssociations)
      Diagnostics               = @(Merge-InstallerDiagnostics -Diagnostic (@($RegistryAssociationInfo.Diagnostics) + @($ActionAssociationInfo.Diagnostics)))
    }
    $Shortcuts = @(Get-InstallBuilderShortcutInfo -Xml $Xml -Context $Context -Payload $PayloadCatalog)
    $PrimaryExecutableCandidates = @(
      @($Shortcuts | Where-Object { $_.IsEmbeddedPayload -and $_.PayloadPath -match '(?i)\.exe$' } | ForEach-Object PayloadPath)
      @($ExecutionInfo.Actions | Where-Object { $_.IsEmbeddedPayload -and $_.PayloadPath -match '(?i)\.exe$' -and $_.Purpose -in 'InstallerAction', 'ApplicationLaunch' } | ForEach-Object PayloadPath)
    ) | Select-Object -Unique
    $PayloadAnalysis = if ($AnalyzePrimaryExecutables) {
      Get-InstallBuilderPrimaryPayloadAnalysis -Path $File.FullName -Payload $PayloadCatalog -PrimaryExecutableCandidate $PrimaryExecutableCandidates -Cookfs $Cookfs -MetakitLayouts $MetakitLayouts -MaximumAnalysisBytes $MaximumPayloadAnalysisBytes
    } else {
      [pscustomobject]@{ ArchitectureInfo = @(); Architectures = @(); DependencyInfo = @(); InspectedFiles = @(); Diagnostics = @() }
    }
    foreach ($Diagnostic in @($PayloadAnalysis.Diagnostics)) { if ($Diagnostic) { $Diagnostics.Add($Diagnostic) } }
    $ReviewableLogic = @($DynamicProjectLogic | Where-Object EvidenceKind -In 'Rule', 'ScriptOrExpression')
    if ($ReviewableLogic.Count) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Project.DynamicLogic' -Source InstallBuilder -Message "$($ReviewableLogic.Count) project rule or script expression(s) require source review; inspect DynamicProjectLogic for exact source and referenced variable evidence." -Kind ManualValidation -Areas @('Metadata', 'Installability') -AffectedFields @($ReviewableLogic.AffectedFields | Sort-Object -Unique) -Evidence ([pscustomobject]@{ Count = $ReviewableLogic.Count })))
    }
    $Requirements = Get-InstallBuilderRequirementInfo -Xml $Xml -Context $Context
    if ($ExecutionInfo.NestedInstallerCandidates.Count) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Execution.NestedInstallerCandidates' -Source InstallBuilder -Message "The compiled project executes $($ExecutionInfo.NestedInstallerCandidates.Count) embedded installer-like payload(s); inspect NestedInstallerCandidates before assigning outer ARP ownership or switches." -Kind ManualValidation -Areas @('Metadata', 'Installability') -AffectedFields @('ProductCode', 'AppsAndFeaturesEntries', 'InstallerSwitches') -Evidence ([pscustomobject]@{ Payloads = @($ExecutionInfo.NestedInstallerCandidates.PayloadPath) })))
    }
    if ($Requirements.Java.Count) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Requirement.Java' -Source InstallBuilder -Message "The compiled project contains $($Requirements.Java.Count) Java runtime detection action(s); review RuntimeRequirements before deciding whether the package needs an external dependency." -Kind Information -Areas Installability -AffectedFields @('Dependencies') -Evidence $Requirements.Java))
    }
    if ($Requirements.DotNetFramework.Count) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Requirement.DotNetFramework' -Source InstallBuilder -Message "The compiled project contains $($Requirements.DotNetFramework.Count) .NET Framework runtime detection action(s); review RuntimeRequirements before deciding whether the package needs an external dependency." -Kind Information -Areas Installability -AffectedFields @('Dependencies') -Evidence $Requirements.DotNetFramework))
    }
    $ConditionalRegistryOperations = @($InstallationRegistryOperations | Where-Object ConditionState -EQ 'Unknown')
    if ($ConditionalRegistryOperations.Count) {
      $AffectedFields = @($ConditionalRegistryOperations | ForEach-Object { Get-InstallBuilderRegistryAffectedField -Operation $_ } | Sort-Object -Unique)
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Registry.ConditionsUnresolved' -Source InstallBuilder -Message "$($ConditionalRegistryOperations.Count) registry operation(s) depend on runtime rules; those operations are retained as evidence but excluded from authoritative ARP and association projection." -Kind Incomplete -Areas Metadata -AffectedFields $AffectedFields))
    }
    $UnresolvedRegistryOperations = @($InstallationRegistryOperations | Where-Object { @($_.UnresolvedVariables).Count })
    if ($UnresolvedRegistryOperations.Count) {
      $AffectedFields = @($UnresolvedRegistryOperations | ForEach-Object { Get-InstallBuilderRegistryAffectedField -Operation $_ } | Sort-Object -Unique)
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Registry.ValuesUnresolved' -Source InstallBuilder -Message "$($UnresolvedRegistryOperations.Count) installation-time registry operation(s) contain runtime variables and were excluded where exact registry state could not be established." -Kind Incomplete -Areas Metadata -AffectedFields $AffectedFields -Evidence ([pscustomobject]@{ Variables = @($UnresolvedRegistryOperations.UnresolvedVariables | Sort-Object -Unique) })))
    }
    if ($ConditionalPayloadFiles.Count) {
      $null = $UnresolvedFields.Add('PayloadFiles')
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Payload.ConditionsUnresolved' -Source InstallBuilder -Message "$($ConditionalPayloadFiles.Count) packaged payload file(s) depend on unresolved component, platform, or runtime conditions and were excluded from the default-install payload projection." -Kind Incomplete -Areas Extraction -AffectedFields @() -Evidence ([pscustomobject]@{ Count = $ConditionalPayloadFiles.Count })))
    }
    if ($ScopeInfo.Confidence -eq 'unknown') { $null = $UnresolvedFields.Add('Scope') }
    if ($null -eq $ArpInfo.WritesAppsAndFeatures) {
      $null = $UnresolvedFields.Add('ProductCode')
      $null = $UnresolvedFields.Add('AppsAndFeaturesEntries')
    }
    foreach ($Field in @($Diagnostics | Where-Object { $_.Id -in 'InstallBuilder.ARP.BuiltInPrefixUnresolved', 'InstallBuilder.ARP.BuiltInValuesUnresolved', 'InstallBuilder.ARP.CustomKeyUnresolved', 'InstallBuilder.ARP.ConditionalValues', 'InstallBuilder.ARP.PostCreationDeleteConditional', 'InstallBuilder.Registry.ConditionsUnresolved', 'InstallBuilder.Registry.ValuesUnresolved' } | ForEach-Object AffectedFields)) {
      $null = $UnresolvedFields.Add([string]$Field)
    }
    $AllowedModes = Get-InstallBuilderProjectProperty -Xml $Xml -Name allowedInstallationModes -NoDefault
    $AllowedModeTokens = @([string]$AllowedModes -split '[\s,;]+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $SupportsInteractive = $AllowedModeTokens.Count -eq 0 -or @($AllowedModeTokens | Where-Object { $_ -ine 'unattended' }).Count -gt 0
    $SupportsUnattended = $AllowedModeTokens.Count -eq 0 -or $AllowedModeTokens -icontains 'unattended'
    # Legacy Metakit runtimes document unattended mode but predate unattendedModeUI. CookFS-era
    # projects can force silent or progress UI independently of the compiled project default.
    $SupportsUnattendedModeUi = $null -ne $Cookfs -or -not [string]::IsNullOrWhiteSpace((Get-InstallBuilderProjectProperty -Xml $Xml -Name unattendedModeUI -NoDefault))
    $InstallModes = [Collections.Generic.List[string]]::new()
    if ($SupportsInteractive) { $InstallModes.Add('interactive') }
    if ($SupportsUnattended) {
      $InstallModes.Add('silent')
      if ($SupportsUnattendedModeUi) { $InstallModes.Add('silentWithProgress') }
    }
    $InstallerSwitches = [ordered]@{}
    if ($SupportsUnattended) {
      $InstallerSwitches.Silent = $SupportsUnattendedModeUi ? '--mode unattended --unattendedmodeui none' : '--mode unattended'
      if ($SupportsUnattendedModeUi) { $InstallerSwitches.SilentWithProgress = '--mode unattended --unattendedmodeui minimal' }
      else { $InstallerSwitches.SilentWithProgress = $InstallerSwitches.Silent }
    }
    $InstallCliOption = if ($Context.InstallParameter) { Get-InstallBuilderXmlValue -Xml $Context.InstallParameter -XPath 'cliOptionName' } else { $null }
    if ([string]::IsNullOrWhiteSpace($InstallCliOption) -and $Context.InstallParameter) { $InstallCliOption = 'installdir' }
    if ($InstallCliOption) { $InstallerSwitches.InstallLocation = "--$InstallCliOption `"<INSTALLPATH>`"" }
    $InstallerSwitches.Log = '--debugtrace "<LOGPATH>"'
    $ElevationRequirement = if ($Context.RequestedExecutionLevel -ieq 'requireAdministrator') { 'elevatesSelf' } elseif (Test-InstallBuilderTrueValue (Get-InstallBuilderProjectProperty -Xml $Xml -Name requireInstallationByRootUser)) { 'elevationRequired' } else { $null }
    $ManifestArpEntries = @($ArpInfo.VisibleEntries | ForEach-Object {
        $Entry = [ordered]@{}
        foreach ($Name in 'DisplayName', 'Publisher', 'DisplayVersion', 'ProductCode', 'InstallerType') {
          if ($null -ne $_.$Name -and -not [string]::IsNullOrWhiteSpace([string]$_.$Name)) { $Entry[$Name] = $_.$Name }
        }
        [pscustomobject]$Entry
      })
    [pscustomobject][ordered]@{
      Path                         = $File.FullName
      InstallerType                = 'exe'
      ProductCode                  = $ArpInfo.ProductCode
      UpgradeCode                  = $null
      DisplayName                  = $DisplayName
      DisplayVersion               = $Version
      Publisher                    = $Vendor
      Scope                        = $ScopeInfo.Scope
      DefaultInstallLocation       = $Context.InstallLocation
      WritesAppsAndFeaturesEntry   = $ArpInfo.WritesAppsAndFeatures
      AppsAndFeaturesProductCode   = $ArpInfo.WritesAppsAndFeatures -eq $true ? $ArpInfo.ProductCode : $null
      AppsAndFeaturesInstallerType = $ArpInfo.WritesAppsAndFeatures -eq $true ? 'exe' : $null
      Diagnostics                  = @(Merge-InstallerDiagnostics -Diagnostic $Diagnostics.ToArray())
      UnresolvedFields             = [string[]]@($UnresolvedFields | Sort-Object)
      Family                       = 'InstallBuilder'
      FormatGeneration             = $Cookfs ? 'CookFS2' : ($MetakitLayouts.Count ? 'LegacyMetakit' : 'ProjectRecord')
      ContainerRoute               = $Cookfs ? 'PE/MetakitVfs/CookFS2' : ($MetakitLayouts.Count ? 'PE/MetakitVfs' : 'ProjectRecord')
      ProjectSchemaVersion         = Get-InstallBuilderXmlValue -Xml $Xml -XPath '/project/projectSchemaVersion'
      ProductCodeEvidence          = if ($ArpInfo.ProductCode) { 'InstallBuilder built-in windowsARPRegistryPrefix or unconditional literal registrySet ARP key.' } else { $null }
      SupportedScopes              = $ScopeInfo.SupportedScopes
      ScopeConfidence              = $ScopeInfo.Confidence
      ScopeEvidence                = $ScopeInfo.Evidence
      ShortcutScope                = Get-InstallBuilderProjectProperty -Xml $Xml -Name installationScope
      RequestedExecutionLevel      = $Context.RequestedExecutionLevel
      ElevationRequirement         = $ElevationRequirement
      RegistryView                 = $Context.RegistryView
      SupportsSilentInstallation   = $SupportsUnattended
      InstallModes                 = $InstallModes.ToArray()
      InstallerSwitches            = $InstallerSwitches
      InstallerSuccessCodes        = @()
      RegistryOperations           = $RegistryOperations
      RegistryWrites               = $RegistryWrites
      RegistryDeletes              = $RegistryDeletes
      EffectiveRegistryWrites      = @($RegistryState.Writes)
      RegistryAssociationInfo      = $RegistryAssociationInfo
      AssociationInfo              = $AssociationInfo
      Protocols                    = $AssociationInfo.Protocols
      ProtocolAssociations         = $AssociationInfo.ProtocolAssociations
      FileExtensions               = $AssociationInfo.FileExtensions
      FileExtensionAssociations    = $AssociationInfo.FileExtensionAssociations
      EnvironmentChanges           = $SystemEffectInfo.EnvironmentChanges
      PathChanges                  = $SystemEffectInfo.PathChanges
      WindowsServices              = $SystemEffectInfo.WindowsServices
      ScheduledTasks               = $SystemEffectInfo.ScheduledTasks
      FontChanges                  = $SystemEffectInfo.FontChanges
      SharedDllChanges             = $SystemEffectInfo.SharedDllChanges
      WindowsAclChanges            = $SystemEffectInfo.WindowsAclChanges
      SystemEffects                = $SystemEffectInfo
      HasBuiltInUninstaller        = $ArpInfo.HasBuiltInUninstaller
      WritesBuiltInArp             = $ArpInfo.WritesBuiltInArp
      AppsAndFeaturesEntries       = $ManifestArpEntries
      ArpEntries                   = $ArpInfo.Entries
      VisibleArpEntries            = $ArpInfo.VisibleEntries
      HiddenArpEntries             = $ArpInfo.HiddenEntries
      UncertainArpEntries          = $ArpInfo.UncertainEntries
      Shortcuts                    = $Shortcuts
      PrimaryExecutableCandidates  = [string[]]$PrimaryExecutableCandidates
      PayloadArchitectureInfo      = $PayloadAnalysis.ArchitectureInfo
      PayloadArchitectures         = $PayloadAnalysis.Architectures
      PayloadDependencyInfo        = $PayloadAnalysis.DependencyInfo
      PayloadAnalysisFiles         = $PayloadAnalysis.InspectedFiles
      ProjectActions               = $ProjectActions
      DynamicProjectLogic          = $DynamicProjectLogic
      ExecutionActions             = $ExecutionInfo.Actions
      ExecutedPayloads             = $ExecutionInfo.ExecutedPayloads
      NestedInstallerCandidates    = $ExecutionInfo.NestedInstallerCandidates
      RuntimeRequirements          = $Requirements
      ProjectOffset                = $Project.Offset
      ProjectLength                = $Project.Length
      ExtractedFiles               = @('project.xml') + @($PayloadCatalog | ForEach-Object Path)
      PayloadCatalog               = $PayloadCatalog
      PackagedPayloadFiles         = @($PayloadCatalog | ForEach-Object Path)
      PayloadFiles                 = @($PayloadFiles | ForEach-Object Path)
      PayloadFileCount             = $PayloadFiles.Count
      PackagedPayloadFileCount     = $PayloadCatalog.Count
      ConditionalPayloadFiles      = @($ConditionalPayloadFiles | ForEach-Object Path)
      ConditionalPayloadFileCount  = $ConditionalPayloadFiles.Count
      ExcludedPayloadFiles         = @($ExcludedPayloadFiles | ForEach-Object Path)
      ExcludedPayloadFileCount     = $ExcludedPayloadFiles.Count
      CookfsInfo                   = if ($Cookfs) { [pscustomobject]@{ EndOffset = $Cookfs.EndOffset; IndexOffset = $Cookfs.IndexOffset; PageDataOffset = $Cookfs.PageDataOffset; PageCount = $Cookfs.PageCount; IndexSize = $Cookfs.IndexSize; CompressionIds = $Cookfs.CompressionIds; CompressionTypes = $Cookfs.CompressionTypes; HasUnsupportedCompression = $Cookfs.HasUnsupportedCompression; PageHashAlgorithm = $Cookfs.PageHashAlgorithm; HasUnsupportedHash = $Cookfs.HasUnsupportedHash; IndexMetadata = $Cookfs.IndexMetadata } } else { $null }
      MetakitInfo                  = $MetakitInfo
      MetakitLayouts               = $MetakitLayouts
      ParserVersionInfo            = [pscustomobject]@{ Parser = 'Dumplings.PackageModule.InstallBuilder'; ParserMajor = 7; Sources = @('Metakit VFS JL/LJ header, column descriptors, and TclKit file schema', 'bounded zlib project record', 'CookFS CFS0002 footer, file index, entry timestamps, metadata, and page hashes', 'phase-aware nested project action and payload selection model', 'ordered registry set/delete state', 'source-preserving dynamic project logic evidence', 'native file-association add/remove, environment, PATH, and Windows-service actions', 'Java and .NET Framework runtime requirement actions') }
    }
  }
}

function Expand-InstallBuilderInstaller {
  <#
  .SYNOPSIS
    Extract selected unencrypted InstallBuilder payload files without execution
  .PARAMETER Name
    Matches project.xml and logical CookFS payload paths. BitRock split payloads
    ending in ___bitrockBigFileN are reassembled under their original file name.
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER DestinationPath
    Destination path for bounded extraction or decoded output; payload-relative names are resolved beneath this path.
  .PARAMETER MaximumExpandedBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  [OutputType([System.IO.FileInfo[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [string]$Name = '*',
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Prompt',
    [ValidateRange(1024, [long]::MaxValue)][long]$MaximumExpandedBytes = 17179869184
  )
  process {
    $Path = (Get-Item -LiteralPath $Path -Force).FullName
    if ([string]::IsNullOrWhiteSpace($DestinationPath)) { $DestinationPath = Join-Path ([IO.Path]::GetTempPath()) ("Dumplings-InstallBuilder-$([guid]::NewGuid().ToString('N'))") }
    $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
    $Extracted = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
    [long]$TotalWritten = 0
    $ReservedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $Project = $null

    # project.xml and CookFS payloads share one output budget but have independent recovery paths.
    if (Test-ExtractionPattern -Path 'project.xml' -Pattern $Name) {
      $Project = Get-InstallBuilderProjectData -Path $Path -MaximumExpandedBytes ([Math]::Min($MaximumExpandedBytes, $Script:InstallBuilderMaximumProjectBytes))
      $Bytes = [Text.Encoding]::UTF8.GetBytes($Project.Content)
      $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath 'project.xml' `
        -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
      if ($Target.ShouldWrite) {
        if ($Bytes.Length -gt $MaximumExpandedBytes) { throw 'The recovered InstallBuilder project exceeds the configured output limit' }
        $null = New-Item -Path ([IO.Path]::GetDirectoryName($Target.Path)) -ItemType Directory -Force
        [IO.File]::WriteAllBytes($Target.Path, $Bytes)
        $TotalWritten += $Bytes.Length
        $Extracted.Add((Get-Item -LiteralPath $Target.Path -Force))
      }
    }

    $Cookfs = $null
    $MetakitLayouts = @()
    try { $Cookfs = Get-InstallBuilderCookfsInfo -Path $Path } catch {
      $MetakitLayouts = @(Get-InstallBuilderMetakitLayout -Path $Path)
      if (-not $MetakitLayouts.Count -and $Extracted.Count -eq 0) { throw }
    }
    if ($Cookfs) {
      if (-not $Project) { $Project = Get-InstallBuilderProjectData -Path $Path -MaximumExpandedBytes ([Math]::Min($MaximumExpandedBytes, $Script:InstallBuilderMaximumProjectBytes)) }
      $Xml = [xml]$Project.Content
      $Context = Get-InstallBuilderProjectContext -Xml $Xml -Path $Path
      $LogicalEntries = @(Get-InstallBuilderCookfsLogicalEntry -Entry $Cookfs.Entries -Xml $Xml -Context $Context | Where-Object {
          (Test-ExtractionPattern -Path $_.Path -Pattern $Name) -or (Test-ExtractionPattern -Path $_.PhysicalPath -Pattern $Name)
        })
      if ($LogicalEntries.Count -gt 0 -and $Cookfs.HasUnsupportedCompression) { throw 'The CookFS payload uses unsupported custom or encrypted compression and cannot be extracted without the project password' }
      # Export logical rather than physical split-file names.
      $Source = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
      try {
        foreach ($Entry in $LogicalEntries) {
          $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $Entry.Path `
            -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
          if (-not $Target.ShouldWrite) { continue }
          $null = New-Item -Path ([IO.Path]::GetDirectoryName($Target.Path)) -ItemType Directory -Force
          $Destination = [IO.File]::Open($Target.Path, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
          try {
            Copy-InstallBuilderCookfsEntry -Stream $Source -Cookfs $Cookfs -Entry $Entry -Destination $Destination -TotalWritten ([ref]$TotalWritten) -MaximumExpandedBytes $MaximumExpandedBytes
          } finally {
            $Destination.Dispose()
          }
          $ExtractedFile = Get-Item -LiteralPath $Target.Path -Force
          if ($Entry.ModificationTimeUtc) { $ExtractedFile.LastWriteTimeUtc = $Entry.ModificationTimeUtc }
          $Extracted.Add($ExtractedFile)
        }
      } finally {
        $Source.Dispose()
      }
    }
    if (-not $Cookfs -and $MetakitLayouts.Count) {
      $LegacyArchive = $null
      try {
        if (-not $Project) { $Project = Get-InstallBuilderProjectData -Path $Path -MaximumExpandedBytes ([Math]::Min($MaximumExpandedBytes, $Script:InstallBuilderMaximumProjectBytes)) }
        $Xml = [xml]$Project.Content
        $Context = Get-InstallBuilderProjectContext -Xml $Xml -Path $Path
        $LegacyArchive = Open-InstallBuilderMetakitArchive -Path $Path -Layout $MetakitLayouts -RequiredEntryPath 'origindist'
        $OriginEntry = @($LegacyArchive.Entries | Where-Object Path -CEQ 'origindist')
        if ($OriginEntry.Count -ne 1) { throw 'The legacy TclKit VFS does not contain one unambiguous origindist control record' }
        $OriginDirectory = $Script:InstallBuilderStrictUtf8.GetString($LegacyArchive.ReadEntry([int]$OriginEntry[0].Index, 4096)).Trim([char]0).Trim()
        if ([string]::IsNullOrWhiteSpace($OriginDirectory) -or $OriginDirectory.IndexOfAny([char[]]'\/') -ge 0) { throw 'The legacy TclKit origindist control record is invalid' }
        $LegacyEntries = @(Get-InstallBuilderLegacyPayloadEntry -Entry @($LegacyArchive.Entries) -Xml $Xml -Context $Context -OriginDirectory $OriginDirectory | Where-Object {
            (Test-ExtractionPattern -Path $_.Path -Pattern $Name) -or (Test-ExtractionPattern -Path $_.PhysicalPath -Pattern $Name)
          })
        foreach ($Entry in $LegacyEntries) {
          if ($Entry.Compression -eq 'Unknown') { throw "The legacy Metakit payload '$($Entry.PhysicalPath)' uses unsupported compression framing" }
          if ($TotalWritten -gt $MaximumExpandedBytes - $Entry.Size) { throw 'The InstallBuilder payload exceeds the configured output limit' }
          $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $Entry.Path `
            -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
          if (-not $Target.ShouldWrite) { continue }
          $null = New-Item -Path ([IO.Path]::GetDirectoryName($Target.Path)) -ItemType Directory -Force
          $Destination = [IO.File]::Open($Target.Path, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
          try {
            $Written = $LegacyArchive.CopyEntry([int]$Entry.Index, $Destination, $MaximumExpandedBytes - $TotalWritten)
            $TotalWritten += $Written
          } catch {
            # Close the partial output before deleting it; the stream deliberately denies sharing.
            $Destination.Dispose()
            $Destination = $null
            Remove-Item -LiteralPath $Target.Path -Force -ErrorAction SilentlyContinue
            throw
          } finally {
            if ($Destination) { $Destination.Dispose() }
          }
          $Extracted.Add((Get-Item -LiteralPath $Target.Path -Force))
        }
      } finally {
        if ($LegacyArchive) { $LegacyArchive.Dispose() }
      }
    }
    if ($Extracted.Count -eq 0) { throw "No InstallBuilder project or payload file matches selector '$Name'" }
    return $Extracted.ToArray()
  }
}

function Test-InstallBuilder {
  <#
  .SYNOPSIS
    Test whether a PE contains a supported structured InstallBuilder container
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([bool])]
  param([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process {
    try {
      # A recoverable project record is useful to low-level callers, but detection additionally
      # requires a real PE and a validated Metakit or CookFS container relationship.
      if (-not (Get-PELayout -Path $Path)) { return $false }
      $Info = Get-InstallBuilderInfo -Path $Path
      return [bool]($Info.CookfsInfo -or @($Info.MetakitLayouts).Count)
    } catch {
      return $false
    }
  }
}

function Read-ProtocolsFromInstallBuilder {
  <#
  .SYNOPSIS
    Read literal URL protocol names from InstallBuilder registrySet actions
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallBuilderInfo -Path $Path).Protocols }
}

function Read-FileExtensionsFromInstallBuilder {
  <#
  .SYNOPSIS
    Read literal file extensions from InstallBuilder registrySet actions
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallBuilderInfo -Path $Path).FileExtensions }
}

function Read-ProductVersionFromInstallBuilder {
  <#
  .SYNOPSIS
    Read the version from an InstallBuilder project
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallBuilderInfo -Path $Path).DisplayVersion }
}

function Read-ProductNameFromInstallBuilder {
  <#
  .SYNOPSIS
    Read the product name from an InstallBuilder project
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallBuilderInfo -Path $Path).DisplayName }
}

function Read-PublisherFromInstallBuilder {
  <#
  .SYNOPSIS
    Read the publisher from an InstallBuilder project
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallBuilderInfo -Path $Path).Publisher }
}

function Read-ProductCodeFromInstallBuilder {
  <#
  .SYNOPSIS
    Read the candidate InstallBuilder uninstaller key
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallBuilderInfo -Path $Path).ProductCode }
}

function Read-ScopeFromInstallBuilder {
  <#
  .SYNOPSIS
    Read the statically proven InstallBuilder installation scope
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallBuilderInfo -Path $Path).Scope }
}

Export-ModuleMember -Function Get-InstallBuilderInfo, Expand-InstallBuilderInstaller, Test-InstallBuilder, Read-ProtocolsFromInstallBuilder, Read-FileExtensionsFromInstallBuilder, Read-ProductVersionFromInstallBuilder, Read-ProductNameFromInstallBuilder, Read-PublisherFromInstallBuilder, Read-ProductCodeFromInstallBuilder, Read-ScopeFromInstallBuilder
