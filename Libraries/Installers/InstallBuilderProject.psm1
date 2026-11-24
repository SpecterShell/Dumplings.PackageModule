# SPDX-License-Identifier: Apache-2.0
# Internal InstallBuilder implementation. See InstallBuilder.psm1 for format sources and the binary layout.
# Pass parsed contexts explicitly and keep caller-owned streams local.

# InstallBuilder project implementation, imported locally by the public facade.

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:InstallBuilderMaximumDynamicLogicRecords = 4096

$Script:InstallBuilderProjectDefaults = [ordered]@{
  installationType              = 'normal'
  createUninstaller             = '1'
  createWindowsARPEntry         = '1'
  windowsARPRegistryPrefix      = '${project.fullName} ${project.version}'
  productDisplayName            = '${product_fullname}'
  productDisplayIcon            = ''
  productUrlInfoAbout           = ''
  productComments               = ''
  productContact                = ''
  productUrlHelpLink            = ''
  uninstallerName               = 'uninstall'
  uninstallerDirectory          = '${installdir}'
  requireInstallationByRootUser = '0'
  requestedExecutionLevel       = 'requireAdministrator'
  windows64bitMode              = '0'
  installationScope             = 'auto'
  unattendedModeUI              = 'none'
}

function Get-InstallBuilderXmlValue {
  <#
  .SYNOPSIS
    Read one trimmed InstallBuilder project XML value.
  .PARAMETER Xml
    XML node used as the XPath context.
  .PARAMETER XPath
    Relative or absolute XPath identifying the requested scalar node.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][System.Xml.XmlNode]$Xml, [Parameter(Mandatory)][string]$XPath)
  $Node = $Xml.SelectSingleNode($XPath)
  if ($Node) {
    $Value = $Node.InnerText.Trim()
  } elseif ($XPath -match '^[A-Za-z_][A-Za-z0-9_.-]*$' -and $Xml.Attributes) {
    $Value = $Xml.GetAttribute($XPath).Trim()
  } else {
    return $null
  }
  if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
  return $Value
}

function Get-InstallBuilderProjectProperty {
  <#
  .SYNOPSIS
    Read an explicit InstallBuilder project property or its documented default.
  .PARAMETER Xml
    Parsed InstallBuilder project document.
  .PARAMETER Name
    Case-sensitive project property name.
  .PARAMETER NoDefault
    Return null rather than applying a documented runtime default.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][xml]$Xml,
    [Parameter(Mandatory)][string]$Name,
    [switch]$NoDefault
  )

  $Value = Get-InstallBuilderXmlValue -Xml $Xml -XPath "/project/$Name"
  if ($null -ne $Value -or $NoDefault) { return $Value }
  if ($Script:InstallBuilderProjectDefaults.Contains($Name)) { return [string]$Script:InstallBuilderProjectDefaults[$Name] }
  return $null
}

function Test-InstallBuilderTrueValue {
  <#
  .SYNOPSIS
    Interpret the literal Boolean spellings accepted by InstallBuilder projects.
  .PARAMETER Value
    Literal XML property value. Dynamic expressions are not treated as true.
  #>
  [OutputType([bool])]
  param ([AllowNull()][string]$Value)
  return $Value -match '^(?i:1|true|yes)$'
}

function Resolve-InstallBuilderProjectValue {
  <#
  .SYNOPSIS
    Expand deterministic InstallBuilder project and product variables.
  .PARAMETER Value
    Project expression to resolve.
  .PARAMETER Variables
    Case-insensitive dictionary of source-backed variable values.
  #>
  [OutputType([pscustomobject])]
  param (
    [AllowNull()][string]$Value,
    [Parameter(Mandatory)][Collections.Generic.Dictionary[string, string]]$Variables
  )

  if ($null -eq $Value) { return [pscustomobject]@{ Value = $null; UnresolvedVariables = @() } }
  $Resolved = $Value
  $Unresolved = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  # InstallBuilder substitutions can be nested. Resolve only values already proven by project or PE
  # metadata, and leave Tcl expressions and runtime state unresolved.
  for ($Pass = 0; $Pass -lt 16; $Pass++) {
    $Before = $Resolved
    # Work from distinct matches rather than a callback so variable lookup remains in the current
    # PowerShell scope and ScriptAnalyzer can verify that the dictionary parameter is consumed.
    foreach ($Match in @([regex]::Matches($Resolved, '\$\{(?<Name>[^{}]+)\}'))) {
      $Name = $Match.Groups['Name'].Value
      if ($Variables.ContainsKey($Name) -and $null -ne $Variables[$Name]) {
        $Resolved = $Resolved.Replace($Match.Value, $Variables[$Name])
      } else {
        $null = $Unresolved.Add($Name)
      }
    }
    if ($Resolved -ceq $Before) { break }
  }
  foreach ($Match in [regex]::Matches($Resolved, '\$\{(?<Name>[^{}]+)\}')) { $null = $Unresolved.Add($Match.Groups['Name'].Value) }
  [pscustomobject]@{
    Value               = $Unresolved.Count -eq 0 ? $Resolved : $null
    UnresolvedVariables = [string[]]@($Unresolved | Sort-Object)
  }
}

function Get-InstallBuilderProjectContext {
  <#
  .SYNOPSIS
    Build deterministic variable, platform, and execution-level evidence once.
  .PARAMETER Xml
    Parsed InstallBuilder project document.
  .PARAMETER Path
    Resolved Windows installer path used for PE evidence.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][xml]$Xml, [Parameter(Mandatory)][string]$Path)

  $Layout = try { Get-PELayout -Path $Path } catch { $null }
  $RequestedExecutionLevel = try { Get-PERequestedExecutionLevel -Path $Path } catch { $null }
  if ([string]::IsNullOrWhiteSpace($RequestedExecutionLevel)) {
    $RequestedExecutionLevel = Get-InstallBuilderProjectProperty -Xml $Xml -Name requestedExecutionLevel
  }
  $Windows64BitMode = Test-InstallBuilderTrueValue (Get-InstallBuilderProjectProperty -Xml $Xml -Name windows64bitMode)
  $IsNative64Bit = $Layout -and $Layout.MachineName -in 'AMD64', 'ARM64', 'IA64'
  $NativePlatform = switch ($Layout.MachineName) {
    'AMD64' { 'windows-x64' }
    'ARM64' { 'windows-arm64' }
    'I386' { 'windows-x86' }
    default { $null }
  }
  $ProgramFiles = ($IsNative64Bit -or $Windows64BitMode) ? '%ProgramFiles%' : '%ProgramFiles(x86)%'
  $Variables = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
  $ShortName = Get-InstallBuilderXmlValue -Xml $Xml -XPath '/project/shortName'
  $FullName = Get-InstallBuilderXmlValue -Xml $Xml -XPath '/project/fullName'
  $Version = Get-InstallBuilderXmlValue -Xml $Xml -XPath '/project/version'
  $Vendor = Get-InstallBuilderXmlValue -Xml $Xml -XPath '/project/vendor'
  foreach ($Pair in @(
      @('project.shortName', $ShortName), @('project.fullName', $FullName), @('project.version', $Version), @('project.vendor', $Vendor),
      @('product_shortname', $ShortName), @('product_fullname', $FullName), @('product_version', $Version),
      @('platform_install_prefix', $ProgramFiles), @('platform_name', 'windows'), @('platform', 'windows'),
      # Resolve stable Windows folder variables to manifest-safe environment forms. User-specific
      # shell folders retain environment variables rather than embedding the parser host's paths.
      @('windows_folder_program_files', $ProgramFiles),
      @('windows_folder_program_files_common', (($IsNative64Bit -or $Windows64BitMode) ? '%CommonProgramFiles%' : '%CommonProgramFiles(x86)%')),
      @('windows_folder_windows', '%SystemRoot%'), @('windows_folder_systemroot', '%SystemRoot%'), @('windows_folder_system', '%SystemRoot%\System32'),
      @('windows_folder_appdata', '%APPDATA%'), @('windows_folder_local_appdata', '%LOCALAPPDATA%'),
      @('windows_folder_common_appdata', '%ProgramData%'), @('user_home_directory', '%USERPROFILE%'),
      @('windows_folder_personal', '%USERPROFILE%\Documents'), @('windows_folder_desktopdirectory', '%USERPROFILE%\Desktop'),
      @('windows_folder_profile', '%USERPROFILE%'), @('windows_folder_favorites', '%USERPROFILE%\Favorites'),
      @('windows_folder_mymusic', '%USERPROFILE%\Music'), @('windows_folder_mypictures', '%USERPROFILE%\Pictures'),
      @('windows_folder_myvideo', '%USERPROFILE%\Videos'), @('windows_folder_admintools', '%APPDATA%\Microsoft\Windows\Start Menu\Programs\Administrative Tools'),
      @('windows_folder_nethood', '%APPDATA%\Microsoft\Windows\Network Shortcuts'), @('windows_folder_printhood', '%APPDATA%\Microsoft\Windows\Printer Shortcuts'),
      @('windows_folder_programs', '%APPDATA%\Microsoft\Windows\Start Menu\Programs'), @('windows_folder_recent', '%APPDATA%\Microsoft\Windows\Recent'),
      @('windows_folder_sendto', '%APPDATA%\Microsoft\Windows\SendTo'), @('windows_folder_startmenu', '%APPDATA%\Microsoft\Windows\Start Menu'),
      @('windows_folder_startup', '%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup'), @('windows_folder_templates', '%APPDATA%\Microsoft\Windows\Templates'),
      @('windows_folder_common_admintools', '%ProgramData%\Microsoft\Windows\Start Menu\Programs\Administrative Tools'),
      @('windows_folder_common_desktopdirectory', '%PUBLIC%\Desktop'), @('windows_folder_common_documents', '%PUBLIC%\Documents'),
      @('windows_folder_common_music', '%PUBLIC%\Music'), @('windows_folder_common_pictures', '%PUBLIC%\Pictures'),
      @('windows_folder_common_programs', '%ProgramData%\Microsoft\Windows\Start Menu\Programs'),
      @('windows_folder_common_startmenu', '%ProgramData%\Microsoft\Windows\Start Menu'),
      @('windows_folder_common_startup', '%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup'),
      @('windows_folder_common_templates', '%ProgramData%\Microsoft\Windows\Templates'), @('windows_folder_common_video', '%PUBLIC%\Videos')
    )) { if ($null -ne $Pair[1]) { $Variables[$Pair[0]] = [string]$Pair[1] } }

  # Identity fields may themselves use deterministic project substitutions. Resolve them before
  # ARP and top-level metadata projection so literal expressions are never returned as values.
  $Identity = [ordered]@{}
  $IdentitySources = [ordered]@{ ShortName = $ShortName; FullName = $FullName; Version = $Version; Vendor = $Vendor }
  $IdentityAliases = [ordered]@{
    ShortName = @('project.shortName', 'product_shortname')
    FullName  = @('project.fullName', 'product_fullname')
    Version   = @('project.version', 'product_version')
    Vendor    = @('project.vendor')
  }
  foreach ($IdentityName in $IdentitySources.Keys) {
    $Result = Resolve-InstallBuilderProjectValue -Value $IdentitySources[$IdentityName] -Variables $Variables
    $Identity[$IdentityName] = $Result
    foreach ($Alias in $IdentityAliases[$IdentityName]) {
      if ($null -ne $Result.Value) { $Variables[$Alias] = [string]$Result.Value } else { $null = $Variables.Remove($Alias) }
    }
  }

  # The install directory parameter uses value first and default only when value is empty.
  $Upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
  $Lower = 'abcdefghijklmnopqrstuvwxyz'
  $InstallParameter = $Xml.SelectSingleNode("//directoryParameter[translate(normalize-space(name),'$Upper','$Lower')='installdir' or translate(@name,'$Upper','$Lower')='installdir']")
  $InstallExpression = if ($InstallParameter) {
    (Get-InstallBuilderXmlValue -Xml $InstallParameter -XPath 'value'), (Get-InstallBuilderXmlValue -Xml $InstallParameter -XPath 'default') | Where-Object { $null -ne $_ } | Select-Object -First 1
  } else { $null }
  $InstallLocationResult = Resolve-InstallBuilderProjectValue -Value $InstallExpression -Variables $Variables
  $InstallLocation = if ($InstallLocationResult.Value) { $InstallLocationResult.Value.Replace('/', '\') } else { $null }
  if ($InstallLocation) { $Variables['installdir'] = $InstallLocation }

  # These project variables are consumed by the built-in Windows ARP writer and by project
  # actions. Resolve them after installdir because uninstallerDirectory defaults to it.
  $UninstallerName = Get-InstallBuilderProjectProperty -Xml $Xml -Name uninstallerName
  $UninstallerDirectoryResult = Resolve-InstallBuilderProjectValue -Value (Get-InstallBuilderProjectProperty -Xml $Xml -Name uninstallerDirectory) -Variables $Variables
  if ($UninstallerName) {
    $Variables['project.uninstallerName'] = $UninstallerName
    $Variables['uninstallerName'] = $UninstallerName
  }
  if ($UninstallerDirectoryResult.Value) {
    $Variables['project.uninstallerDirectory'] = $UninstallerDirectoryResult.Value
    $Variables['uninstallerDirectory'] = $UninstallerDirectoryResult.Value
  }

  [pscustomobject]@{
    Layout                     = $Layout
    RequestedExecutionLevel    = $RequestedExecutionLevel
    IsNative64Bit              = [bool]$IsNative64Bit
    NativePlatform             = $NativePlatform
    Windows64BitMode           = $Windows64BitMode
    RegistryView               = ($IsNative64Bit -or $Windows64BitMode) ? '64-bit' : '32-bit'
    Variables                  = $Variables
    Identity                   = [pscustomobject]$Identity
    InstallParameter           = $InstallParameter
    InstallLocation            = $InstallLocation
    InstallLocationResult      = $InstallLocationResult
    UninstallerName            = $UninstallerName
    UninstallerDirectory       = $UninstallerDirectoryResult.Value
    UninstallerDirectoryResult = $UninstallerDirectoryResult
  }
}

function Resolve-InstallBuilderRuleState {
  <#
  .SYNOPSIS
    Evaluate the small source-backed subset of InstallBuilder rules needed for static evidence.
  .PARAMETER Rule
    One compiled rule node. Rules that depend on host state or arbitrary Tcl remain Unknown.
  .PARAMETER Context
    Deterministic project variables and PE platform evidence.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][System.Xml.XmlNode]$Rule,
    [Parameter(Mandatory)]$Context
  )

  $State = 'Unknown'
  $Detail = $Rule.OuterXml
  switch ($Rule.LocalName) {
    'isTrue' {
      $Result = Resolve-InstallBuilderProjectValue -Value ((Get-InstallBuilderXmlValue -Xml $Rule -XPath 'value') ?? $Rule.GetAttribute('value')) -Variables $Context.Variables
      if ($null -ne $Result.Value) { $State = (Test-InstallBuilderTrueValue $Result.Value) ? 'True' : 'False' }
    }
    'isFalse' {
      $Result = Resolve-InstallBuilderProjectValue -Value ((Get-InstallBuilderXmlValue -Xml $Rule -XPath 'value') ?? $Rule.GetAttribute('value')) -Variables $Context.Variables
      if ($null -ne $Result.Value) { $State = (Test-InstallBuilderTrueValue $Result.Value) ? 'False' : 'True' }
    }
    'compareText' {
      $Left = Resolve-InstallBuilderProjectValue -Value ((Get-InstallBuilderXmlValue -Xml $Rule -XPath 'text') ?? $Rule.GetAttribute('text')) -Variables $Context.Variables
      $Right = Resolve-InstallBuilderProjectValue -Value ((Get-InstallBuilderXmlValue -Xml $Rule -XPath 'value') ?? $Rule.GetAttribute('value')) -Variables $Context.Variables
      $Logic = (Get-InstallBuilderXmlValue -Xml $Rule -XPath 'logic') ?? $Rule.GetAttribute('logic')
      if ([string]::IsNullOrWhiteSpace($Logic)) { $Logic = 'equals' }
      $NoCase = Test-InstallBuilderTrueValue ((Get-InstallBuilderXmlValue -Xml $Rule -XPath 'nocase') ?? $Rule.GetAttribute('nocase'))
      if ($null -ne $Left.Value -and $null -ne $Right.Value) {
        switch -Regex ($Logic) {
          '^(?i:equals)$' { $State = ($NoCase ? ($Left.Value -ieq $Right.Value) : ($Left.Value -ceq $Right.Value)) ? 'True' : 'False' }
          '^(?i:does_not_equal|not_equals)$' { $State = ($NoCase ? ($Left.Value -ine $Right.Value) : ($Left.Value -cne $Right.Value)) ? 'True' : 'False' }
          '^(?i:contains)$' { $State = $Left.Value.IndexOf($Right.Value, ($NoCase ? [StringComparison]::OrdinalIgnoreCase : [StringComparison]::Ordinal)) -ge 0 ? 'True' : 'False' }
          '^(?i:does_not_contain)$' { $State = $Left.Value.IndexOf($Right.Value, ($NoCase ? [StringComparison]::OrdinalIgnoreCase : [StringComparison]::Ordinal)) -lt 0 ? 'True' : 'False' }
        }
      }
    }
    'compareTextLength' {
      $Text = Resolve-InstallBuilderProjectValue -Value ((Get-InstallBuilderXmlValue -Xml $Rule -XPath 'text') ?? $Rule.GetAttribute('text')) -Variables $Context.Variables
      $LengthText = Resolve-InstallBuilderProjectValue -Value ((Get-InstallBuilderXmlValue -Xml $Rule -XPath 'length') ?? $Rule.GetAttribute('length')) -Variables $Context.Variables
      $ExpectedLength = 0L
      if ($null -ne $Text.Value -and $null -ne $LengthText.Value -and [long]::TryParse($LengthText.Value, [Globalization.NumberStyles]::Integer, [Globalization.CultureInfo]::InvariantCulture, [ref]$ExpectedLength)) {
        $Comparison = [long]$Text.Value.Length - $ExpectedLength
        $Logic = (Get-InstallBuilderXmlValue -Xml $Rule -XPath 'logic') ?? $Rule.GetAttribute('logic')
        switch -Regex ($Logic) {
          '^(?i:equals)$' { $State = $Comparison -eq 0 ? 'True' : 'False' }
          '^(?i:does_not_equal|not_equals)$' { $State = $Comparison -ne 0 ? 'True' : 'False' }
          '^(?i:greater|greater_than)$' { $State = $Comparison -gt 0 ? 'True' : 'False' }
          '^(?i:greater_or_equal|greater_than_or_equal)$' { $State = $Comparison -ge 0 ? 'True' : 'False' }
          '^(?i:less|less_than)$' { $State = $Comparison -lt 0 ? 'True' : 'False' }
          '^(?i:less_or_equal|less_than_or_equal)$' { $State = $Comparison -le 0 ? 'True' : 'False' }
        }
      }
    }
    'compareValues' {
      $Left = Resolve-InstallBuilderProjectValue -Value ((Get-InstallBuilderXmlValue -Xml $Rule -XPath 'value1') ?? $Rule.GetAttribute('value1')) -Variables $Context.Variables
      $Right = Resolve-InstallBuilderProjectValue -Value ((Get-InstallBuilderXmlValue -Xml $Rule -XPath 'value2') ?? $Rule.GetAttribute('value2')) -Variables $Context.Variables
      $Logic = (Get-InstallBuilderXmlValue -Xml $Rule -XPath 'logic') ?? $Rule.GetAttribute('logic')
      if ($null -ne $Left.Value -and $null -ne $Right.Value) {
        $LeftNumber = 0.0
        $RightNumber = 0.0
        $HasNumbers = [double]::TryParse($Left.Value, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$LeftNumber) -and [double]::TryParse($Right.Value, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$RightNumber)
        $Comparison = $HasNumbers ? $LeftNumber.CompareTo($RightNumber) : [string]::CompareOrdinal($Left.Value, $Right.Value)
        switch -Regex ($Logic) {
          '^(?i:equals)$' { $State = $Comparison -eq 0 ? 'True' : 'False' }
          '^(?i:does_not_equal|not_equals)$' { $State = $Comparison -ne 0 ? 'True' : 'False' }
          '^(?i:greater|greater_than)$' { $State = $Comparison -gt 0 ? 'True' : 'False' }
          '^(?i:greater_or_equal|greater_than_or_equal)$' { $State = $Comparison -ge 0 ? 'True' : 'False' }
          '^(?i:less|less_than)$' { $State = $Comparison -lt 0 ? 'True' : 'False' }
          '^(?i:less_or_equal|less_than_or_equal)$' { $State = $Comparison -le 0 ? 'True' : 'False' }
        }
      }
    }
    'compareVersions' {
      $Left = Resolve-InstallBuilderProjectValue -Value ((Get-InstallBuilderXmlValue -Xml $Rule -XPath 'version1') ?? $Rule.GetAttribute('version1')) -Variables $Context.Variables
      $Right = Resolve-InstallBuilderProjectValue -Value ((Get-InstallBuilderXmlValue -Xml $Rule -XPath 'version2') ?? $Rule.GetAttribute('version2')) -Variables $Context.Variables
      $Logic = (Get-InstallBuilderXmlValue -Xml $Rule -XPath 'logic') ?? $Rule.GetAttribute('logic')
      $LeftVersion = $null
      $RightVersion = $null
      if ($null -ne $Left.Value -and $null -ne $Right.Value -and [version]::TryParse($Left.Value, [ref]$LeftVersion) -and [version]::TryParse($Right.Value, [ref]$RightVersion)) {
        $Comparison = $LeftVersion.CompareTo($RightVersion)
        switch -Regex ($Logic) {
          '^(?i:equals)$' { $State = $Comparison -eq 0 ? 'True' : 'False' }
          '^(?i:does_not_equal|not_equals)$' { $State = $Comparison -ne 0 ? 'True' : 'False' }
          '^(?i:greater|greater_than)$' { $State = $Comparison -gt 0 ? 'True' : 'False' }
          '^(?i:greater_or_equal|greater_than_or_equal)$' { $State = $Comparison -ge 0 ? 'True' : 'False' }
          '^(?i:less|less_than)$' { $State = $Comparison -lt 0 ? 'True' : 'False' }
          '^(?i:less_or_equal|less_than_or_equal)$' { $State = $Comparison -le 0 ? 'True' : 'False' }
        }
      }
    }
    'platformTest' {
      $Platform = (Get-InstallBuilderXmlValue -Xml $Rule -XPath 'type') ?? $Rule.GetAttribute('type')
      if ($Platform -match '^(?i:all|windows)$') { $State = 'True' }
      elseif ($Platform -in 'windows-x64', 'windows-arm64') {
        # A native 64-bit launcher proves its own required platform. An x86 launcher can run on
        # several Windows architectures, so target-architecture rules remain runtime-dependent.
        $State = $Context.IsNative64Bit ? ($Platform -ieq $Context.NativePlatform ? 'True' : 'False') : 'Unknown'
      } elseif ($Platform -ieq 'windows-x86') {
        $State = $Context.IsNative64Bit ? 'False' : 'Unknown'
      } elseif ($Platform -match '^(?i:unix|linux|linux-.+|osx|osx-.+|freebsd|freebsd.+|openbsd|openbsd.+|solaris|solaris-.+|aix|hpux|hpux-.+|irix|irix-.+)$') { $State = 'False' }
    }
    'regExMatch' {
      $Text = Resolve-InstallBuilderProjectValue -Value ((Get-InstallBuilderXmlValue -Xml $Rule -XPath 'text') ?? $Rule.GetAttribute('text')) -Variables $Context.Variables
      $Pattern = Resolve-InstallBuilderProjectValue -Value ((Get-InstallBuilderXmlValue -Xml $Rule -XPath 'pattern') ?? $Rule.GetAttribute('pattern')) -Variables $Context.Variables
      $Logic = (Get-InstallBuilderXmlValue -Xml $Rule -XPath 'logic') ?? $Rule.GetAttribute('logic')
      if ([string]::IsNullOrWhiteSpace($Logic)) { $Logic = 'matches' }
      # Tcl and .NET regular expressions overlap for ordinary literals, anchors, groups, and
      # character classes. Leave Tcl-specific constructs unresolved instead of changing meaning.
      if ($null -ne $Text.Value -and $null -ne $Pattern.Value -and $Pattern.Value -notmatch '\[\[:|\\[mMyYAQEZ]|\(\?[a-z-]+\)') {
        try {
          $Matched = [regex]::IsMatch($Text.Value, $Pattern.Value, [Text.RegularExpressions.RegexOptions]::CultureInvariant, [TimeSpan]::FromMilliseconds(250))
          if ($Logic -match '^(?i:matches)$') { $State = $Matched ? 'True' : 'False' }
          elseif ($Logic -match '^(?i:does_not_match)$') { $State = $Matched ? 'False' : 'True' }
        } catch [Text.RegularExpressions.RegexMatchTimeoutException] {
          $State = 'Unknown'
        } catch [ArgumentException] {
          $State = 'Unknown'
        }
      }
    }
    'ruleGroup' {
      $Nested = Resolve-InstallBuilderRuleList -RuleList $Rule.SelectSingleNode('ruleList') -Owner $Rule -Context $Context
      $State = $Nested.State
    }
  }
  if (Test-InstallBuilderTrueValue ($Rule.GetAttribute('negate'))) {
    $State = $State -eq 'True' ? 'False' : ($State -eq 'False' ? 'True' : 'Unknown')
  }
  [pscustomobject][ordered]@{ Type = $Rule.LocalName; State = $State; Xml = $Detail }
}

function Resolve-InstallBuilderRuleList {
  <#
  .SYNOPSIS
    Combine one InstallBuilder rule list using its documented and/or evaluation logic.
  .PARAMETER RuleList
    ruleList or conditionRuleList node. A missing or empty list is true.
  .PARAMETER Owner
    Element that owns the rule list and its evaluation-logic property.
  .PARAMETER Context
    Deterministic project variables and PE platform evidence.
  #>
  [OutputType([pscustomobject])]
  param (
    [AllowNull()][System.Xml.XmlNode]$RuleList,
    [Parameter(Mandatory)][System.Xml.XmlNode]$Owner,
    [Parameter(Mandatory)]$Context
  )

  if (-not $RuleList -or $RuleList.ChildNodes.Count -eq 0) { return [pscustomobject]@{ State = 'True'; Conditions = @() } }
  $Conditions = [Collections.Generic.List[object]]::new()
  foreach ($Rule in @($RuleList.ChildNodes | Where-Object NodeType -EQ Element)) {
    $Conditions.Add((Resolve-InstallBuilderRuleState -Rule $Rule -Context $Context))
  }
  # InstallBuilder 3.x called this property ruleLogic; later schemas renamed it to
  # ruleEvaluationLogic, while if/while containers may use conditionRuleEvaluationLogic.
  $Logic = (Get-InstallBuilderXmlValue -Xml $Owner -XPath 'ruleEvaluationLogic') ?? (Get-InstallBuilderXmlValue -Xml $Owner -XPath 'conditionRuleEvaluationLogic') ?? (Get-InstallBuilderXmlValue -Xml $Owner -XPath 'ruleLogic') ?? $Owner.GetAttribute('ruleEvaluationLogic') ?? $Owner.GetAttribute('ruleLogic')
  $Operator = $Logic -ieq 'or' ? 'Any' : 'All'
  [pscustomobject]@{
    State      = Merge-InstallerConditionState -State @($Conditions.State) -Operator $Operator
    Conditions = $Conditions.ToArray()
  }
}

function Get-InstallBuilderNodeCondition {
  <#
  .SYNOPSIS
    Resolve direct and inherited conditions that govern one compiled project node.
  .PARAMETER Node
    Action, shortcut, folder, or component whose ancestor rule lists are inspected.
  .PARAMETER Context
    Deterministic project variables and PE platform evidence.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][System.Xml.XmlNode]$Node,
    [Parameter(Mandatory)]$Context
  )

  $States = [Collections.Generic.List[string]]::new()
  $Conditions = [Collections.Generic.List[object]]::new()
  $Current = $Node
  while ($Current -and $Current.NodeType -ne [Xml.XmlNodeType]::Document) {
    $List = $Current.SelectSingleNode('ruleList')
    if ($List) {
      $Result = Resolve-InstallBuilderRuleList -RuleList $List -Owner $Current -Context $Context
      $States.Add($Result.State)
      foreach ($Condition in @($Result.Conditions)) { $Conditions.Add($Condition) }
    }

    # Actions nested under an if/else inherit the conditionRuleList even though that list is a
    # sibling of actionList rather than a direct ancestor of the action itself.
    if ($Current.LocalName -in 'actionList', 'elseActionList' -and $Current.ParentNode.LocalName -in 'if', 'while') {
      $Owner = $Current.ParentNode
      $Result = Resolve-InstallBuilderRuleList -RuleList $Owner.SelectSingleNode('conditionRuleList') -Owner $Owner -Context $Context
      $State = $Result.State
      if ($Current.LocalName -eq 'elseActionList') { $State = $State -eq 'True' ? 'False' : ($State -eq 'False' ? 'True' : 'Unknown') }
      $States.Add($State)
      foreach ($Condition in @($Result.Conditions)) { $Conditions.Add($Condition) }
    }
    $Current = $Current.ParentNode
  }
  [pscustomobject]@{
    State      = Merge-InstallerConditionState -State $States.ToArray() -Operator All
    Conditions = $Conditions.ToArray()
  }
}

function Get-InstallBuilderRegistryOperation {
  <#
  .SYNOPSIS
    Read ordered registrySet and registryDelete actions from an InstallBuilder project.
  .PARAMETER Xml
    Parsed format configuration used to resolve static installer metadata and payload selection.
  .PARAMETER Context
    Deterministic project variables and target-platform evidence.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][xml]$Xml,
    [Parameter(Mandatory)]$Context
  )

  # XPath union retains document order, which is significant when a later delete cancels a set.
  $Sequence = 0
  foreach ($Action in @($Xml.SelectNodes('//registrySet | //registryDelete'))) {
    $Sequence++
    $RawKey = Get-InstallBuilderXmlValue -Xml $Action -XPath 'key'
    if ([string]::IsNullOrWhiteSpace($RawKey)) { continue }
    $Operation = $Action.LocalName -ceq 'registryDelete' ? 'Delete' : 'Set'
    $RawName = Get-InstallBuilderXmlValue -Xml $Action -XPath 'name'
    $RawValue = $Operation -eq 'Set' ? (Get-InstallBuilderXmlValue -Xml $Action -XPath 'value') : $null
    $KeyResult = Resolve-InstallBuilderProjectValue -Value $RawKey -Variables $Context.Variables
    $NameResult = Resolve-InstallBuilderProjectValue -Value $RawName -Variables $Context.Variables
    $ValueResult = Resolve-InstallBuilderProjectValue -Value $RawValue -Variables $Context.Variables
    $ResolvedRawKey = $KeyResult.Value
    $RootSource = $ResolvedRawKey ?? $RawKey
    $Root = if ($RootSource -match '^HKEY_LOCAL_MACHINE|^HKLM') { 'HKLM' } elseif ($RootSource -match '^HKEY_CURRENT_USER|^HKCU') { 'HKCU' } elseif ($RootSource -match '^HKEY_CLASSES_ROOT|^HKCR') { 'HKCR' } else { $null }
    $Condition = Get-InstallBuilderNodeCondition -Node $Action -Context $Context
    $Phase = Get-InstallBuilderActionPhase -Node $Action
    $StripRoot = { param([string]$Key) $Key -replace '^HKEY_LOCAL_MACHINE\\?', '' -replace '^HKLM\\?', '' -replace '^HKEY_CURRENT_USER\\?', '' -replace '^HKCU\\?', '' -replace '^HKEY_CLASSES_ROOT\\?', '' -replace '^HKCR\\?', '' }
    $WowMode = (Get-InstallBuilderXmlValue -Xml $Action -XPath 'wowMode') ?? $Action.GetAttribute('wowMode')
    [pscustomobject][ordered]@{
      Operation           = $Operation
      Sequence            = $Sequence
      Root                = $Root
      Key                 = & $StripRoot $RawKey
      RawKey              = $RawKey
      ResolvedKey         = $ResolvedRawKey ? (& $StripRoot $ResolvedRawKey) : $null
      ResolvedRawKey      = $ResolvedRawKey
      Name                = $NameResult.Value
      RawName             = $RawName
      Value               = $RawValue
      ResolvedValue       = $ValueResult.Value
      Type                = Get-InstallBuilderXmlValue -Xml $Action -XPath 'type'
      WowMode             = $WowMode
      RegistryView        = if ($WowMode -eq '32') { '32-bit' } elseif ($WowMode -eq '64') { '64-bit' } else { $Context.RegistryView }
      Phase               = $Phase
      Lifecycle           = Get-InstallBuilderActionLifecycle -Phase $Phase
      UnresolvedVariables = [string[]]@($KeyResult.UnresolvedVariables + $NameResult.UnresolvedVariables + $ValueResult.UnresolvedVariables | Sort-Object -Unique)
      ConditionState      = $Condition.State
      Conditions          = $Condition.Conditions
      IsConditional       = $Condition.State -ne 'True'
    }
  }
}

function Get-InstallBuilderRegistryAffectedField {
  <#
  .SYNOPSIS
    Map a registry operation to only the manifest fields its target can affect.
  .PARAMETER Operation
    Parsed registry operation or generic action containing root and key evidence.
  #>
  [OutputType([string[]])]
  param ([Parameter(Mandatory)]$Operation)

  $Root = [string]($Operation.PSObject.Properties['Root'] ? $Operation.Root : $null)
  $Key = [string]($Operation.PSObject.Properties['ResolvedKey'] ? $Operation.ResolvedKey : $null)
  if ([string]::IsNullOrWhiteSpace($Key) -and $Operation.PSObject.Properties['RawKey']) { $Key = [string]$Operation.RawKey }
  if ([string]::IsNullOrWhiteSpace($Key) -and $Operation.PSObject.Properties['Properties']) { $Key = [string]$Operation.Properties.key }
  $NormalizedKey = $Key -replace '^(?i:HKEY_LOCAL_MACHINE|HKLM|HKEY_CURRENT_USER|HKCU|HKEY_CLASSES_ROOT|HKCR)\\?', ''
  if ($NormalizedKey -match '^(?i:Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall)(?:\\|$)') { return @('ProductCode', 'AppsAndFeaturesEntries') }
  if ($Root -eq 'HKCR' -or $Key -match '^(?i:HKEY_CLASSES_ROOT|HKCR)(?:\\|$)' -or $NormalizedKey -match '^(?i:Software\\Classes)(?:\\|$)') { return @('Protocols', 'FileExtensions') }
  # A completely computed key has no safe static namespace. Retain all registry-derived fields as
  # unresolved; a literal nonmatching prefix cannot affect ARP or class registration.
  if ($Key -match '^\s*\$\{[^{}]+\}\s*$') { return @('ProductCode', 'AppsAndFeaturesEntries', 'Protocols', 'FileExtensions') }
  return @()
}

function Resolve-InstallBuilderRegistryState {
  <#
  .SYNOPSIS
    Apply deterministic installation-time registry operations in runtime phase order.
  .PARAMETER RegistryOperation
    RegistrySet and registryDelete records returned by Get-InstallBuilderRegistryOperation.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$RegistryOperation)

  # Top-level action lists execute in this documented order. Sequence preserves XML order inside
  # one list, including adjacent set/delete operations.
  $PhaseRank = @{
    preInstallationActionList         = 100
    readyToInstallActionList          = 200
    folderActionList                  = 300
    postInstallationActionList        = 400
    postUninstallerCreationActionList = 500
  }
  $State = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
  $AppliedDeletes = [Collections.Generic.List[object]]::new()
  $Deferred = [Collections.Generic.List[object]]::new()
  $Ordered = @($RegistryOperation | Where-Object Lifecycle -EQ 'Installation' | Sort-Object @{ Expression = { $PhaseRank.ContainsKey($_.Phase) ? $PhaseRank[$_.Phase] : 1000 } }, Sequence)
  foreach ($Operation in $Ordered) {
    if ($Operation.ConditionState -eq 'False') { continue }
    if ($Operation.ConditionState -ne 'True' -or @($Operation.UnresolvedVariables).Count -or [string]::IsNullOrWhiteSpace($Operation.Root) -or [string]::IsNullOrWhiteSpace($Operation.ResolvedKey)) {
      $Deferred.Add($Operation)
      continue
    }

    $Key = $Operation.ResolvedKey.Trim('\')
    $ValueName = [string]$Operation.Name
    $Identity = "$($Operation.Root)|$($Operation.RegistryView)|$Key|$ValueName"
    if ($Operation.Operation -eq 'Set') {
      $State[$Identity] = $Operation
      continue
    }

    $AppliedDeletes.Add($Operation)
    if (-not [string]::IsNullOrWhiteSpace($ValueName)) {
      $null = $State.Remove($Identity)
      continue
    }

    # A key-only registryDelete removes that key and its descendants. Snapshot keys before
    # mutation so dictionary enumeration remains valid.
    foreach ($Candidate in @($State.Keys)) {
      $Parts = $Candidate -split '\|', 4
      if ($Parts[0] -ne $Operation.Root -or $Parts[1] -ne $Operation.RegistryView) { continue }
      if ($Parts[2] -ieq $Key -or $Parts[2].StartsWith($Key + '\', [StringComparison]::OrdinalIgnoreCase)) { $null = $State.Remove($Candidate) }
    }
  }

  [pscustomobject][ordered]@{
    Writes             = @($State.Values | Sort-Object Sequence)
    Deletes            = $AppliedDeletes.ToArray()
    DeferredOperations = $Deferred.ToArray()
  }
}

function Get-InstallBuilderScopeInfo {
  <#
  .SYNOPSIS
    Derive scope evidence from structured InstallBuilder project settings.
  .PARAMETER Xml
    Parsed project.xml document.
  .PARAMETER Context
    Resolved installation path and PE elevation evidence.
  .PARAMETER ArpInfo
    Reconstructed built-in and custom uninstall registrations.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][xml]$Xml,
    [Parameter(Mandatory)]$Context,
    [Parameter(Mandatory)]$ArpInfo
  )
  $DefiniteHives = @($ArpInfo.Entries | Where-Object ConditionState -EQ 'True' | ForEach-Object RegistryHive | Where-Object { $_ } | Select-Object -Unique)
  $PossibleHives = @($ArpInfo.Entries | Where-Object ConditionState -EQ 'Unknown' | ForEach-Object RegistryHive | Where-Object { $_ } | Select-Object -Unique)
  if ($DefiniteHives.Count -eq 1 -and -not $PossibleHives.Count) {
    $Scope = $DefiniteHives[0] -eq 'HKCU' ? 'user' : 'machine'
    return [pscustomobject]@{ Scope = $Scope; SupportedScopes = @($Scope); Confidence = 'high'; Evidence = "The compiled uninstall registration writes $($DefiniteHives[0])." }
  }
  $AllHives = @($DefiniteHives + $PossibleHives | Select-Object -Unique)
  if ($AllHives -contains 'HKLM' -and $AllHives -contains 'HKCU') {
    return [pscustomobject]@{ Scope = $null; SupportedScopes = @('user', 'machine'); Confidence = 'medium'; Evidence = 'Compiled uninstall registrations can target both HKCU and HKLM under runtime conditions.' }
  }
  $RequireAdministrator = Get-InstallBuilderProjectProperty -Xml $Xml -Name requireInstallationByRootUser
  if (Test-InstallBuilderTrueValue $RequireAdministrator) {
    return [pscustomobject]@{ Scope = 'machine'; SupportedScopes = @('machine'); Confidence = 'high'; Evidence = 'requireInstallationByRootUser=1' }
  }
  if ($Context.RequestedExecutionLevel -ieq 'requireAdministrator') {
    return [pscustomobject]@{ Scope = 'machine'; SupportedScopes = @('machine'); Confidence = 'high'; Evidence = 'PE requestedExecutionLevel=requireAdministrator' }
  }
  if ($Context.InstallLocation -match '^%(?i:ProgramFiles|ProgramFiles\(x86\))%') {
    return [pscustomobject]@{ Scope = 'machine'; SupportedScopes = @('machine'); Confidence = 'medium'; Evidence = 'The resolved default destination is under Program Files.' }
  }
  return [pscustomobject]@{ Scope = $null; SupportedScopes = @(); Confidence = 'unknown'; Evidence = 'InstallBuilder project does not contain statically provable uninstall scope evidence.' }
}

function Get-InstallBuilderActionPhase {
  <#
  .SYNOPSIS
    Find the enclosing runtime action-list phase for a compiled project action.
  .PARAMETER Node
    Action element in the parsed project. Its ancestors are inspected without modifying the XML.
  .OUTPUTS
    The owning action-list name, or actionList when no more specific phase is present.
  #>
  param ([Parameter(Mandatory)][System.Xml.XmlNode]$Node)

  $Current = $Node.ParentNode
  while ($Current -and $Current.NodeType -ne [Xml.XmlNodeType]::Document) {
    # A folder-owned actionList runs immediately after that folder's files are unpacked. Treating
    # this list as an unknown phase would discard persistent registry and association effects.
    if ($Current.LocalName -ceq 'actionList' -and $Current.ParentNode.LocalName -ceq 'folder') { return 'folderActionList' }
    if ($Current.LocalName -cmatch 'ActionList$' -and $Current.LocalName -notin 'actionList', 'elseActionList') { return $Current.LocalName }
    $Current = $Current.ParentNode
  }
  return 'actionList'
}

function Get-InstallBuilderActionLifecycle {
  <#
  .SYNOPSIS
    Classify an InstallBuilder action-list name by the runtime phase that owns its effects.
  .PARAMETER Phase
    Compiled action-list element name returned by Get-InstallBuilderActionPhase.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][string]$Phase)

  # Only persistent installation phases may contribute authoritative installed-state evidence.
  # Startup, page, failure, rollback, and uninstall actions remain useful raw evidence but do not
  # describe the state produced by a successful default installation.
  if ($Phase -in 'readyToInstallActionList', 'preInstallationActionList', 'folderActionList', 'postInstallationActionList', 'postUninstallerCreationActionList') { return 'Installation' }
  if ($Phase -match '(?i)uninstall') { return 'Uninstallation' }
  if ($Phase -match '(?i)rollback|aborted|cancel|failure|error') { return 'Rollback' }
  if ($Phase -match '(?i)finalPage|preShow|postShow|pageAction') { return 'Presentation' }
  if ($Phase -match '(?i)initialization|startup') { return 'Initialization' }
  return 'Unknown'
}

function Get-InstallBuilderProjectActionInfo {
  <#
  .SYNOPSIS
    Return phase-aware records for every compiled leaf action in an InstallBuilder project.
  .PARAMETER Xml
    Parsed InstallBuilder project document.
  .PARAMETER Context
    Deterministic project variables and inherited-condition evidence.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][xml]$Xml,
    [Parameter(Mandatory)]$Context
  )

  $ContainerNames = @('actionGroup', 'if', 'while')
  foreach ($Action in @($Xml.SelectNodes('//*') | Where-Object {
        $_.NodeType -eq [Xml.XmlNodeType]::Element -and
        $_.ParentNode -and
        ($_.ParentNode.LocalName -ceq 'actionList' -or $_.ParentNode.LocalName -cmatch 'ActionList$') -and
        $_.LocalName -notin $ContainerNames
      })) {
    $Phase = Get-InstallBuilderActionPhase -Node $Action
    $Lifecycle = Get-InstallBuilderActionLifecycle -Phase $Phase
    $Condition = Get-InstallBuilderNodeCondition -Node $Action -Context $Context
    $Properties = [ordered]@{}
    $SensitiveProperties = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    # Attributes and scalar direct children are the stable compiled action parameters. Nested rule
    # and action lists are represented separately by condition and phase evidence.
    foreach ($Attribute in @($Action.Attributes)) {
      $IsSensitive = $Attribute.LocalName -match '(?i)(?:password|passphrase|secret|token|credential|privatekey)'
      $Properties[$Attribute.LocalName] = $IsSensitive -and -not [string]::IsNullOrEmpty($Attribute.Value) ? '<redacted>' : $Attribute.Value
      if ($IsSensitive -and -not [string]::IsNullOrEmpty($Attribute.Value)) { $null = $SensitiveProperties.Add($Attribute.LocalName) }
    }
    foreach ($Child in @($Action.ChildNodes | Where-Object NodeType -EQ Element)) {
      if ($Child.LocalName -match '(?i)(?:ActionList|RuleList)$' -or @($Child.ChildNodes | Where-Object NodeType -EQ Element).Count) { continue }
      $Value = $Child.InnerText.Trim()
      $IsSensitive = $Child.LocalName -match '(?i)(?:password|passphrase|secret|token|credential|privatekey)'
      if ($IsSensitive -and -not [string]::IsNullOrEmpty($Value)) {
        $Value = '<redacted>'
        $null = $SensitiveProperties.Add($Child.LocalName)
      }
      if ($Properties.Contains($Child.LocalName)) {
        $Properties[$Child.LocalName] = @($Properties[$Child.LocalName]) + $Value
      } else {
        $Properties[$Child.LocalName] = $Value
      }
    }

    $ResolvedProperties = [ordered]@{}
    $UnresolvedVariables = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($Name in $Properties.Keys) {
      if ($Properties[$Name] -isnot [string]) { $ResolvedProperties[$Name] = $Properties[$Name]; continue }
      $Resolved = Resolve-InstallBuilderProjectValue -Value $Properties[$Name] -Variables $Context.Variables
      $ResolvedProperties[$Name] = $Resolved.Value
      foreach ($Variable in @($Resolved.UnresolvedVariables)) { $null = $UnresolvedVariables.Add($Variable) }
    }

    $ActionType = $Action.LocalName
    $Category = switch -Regex ($ActionType) {
      '(?i)^registry' { 'Registry'; break }
      '(?i)service' { 'Service'; break }
      '(?i)^(?:download|contactUpdateServer|launchBrowser)$' { 'Network'; break }
      '(?i)^(?:run|execute)' { 'Execution'; break }
      '(?i)environment' { 'Environment'; break }
      '(?i)(?:file|folder|directory|unpack|substitute)' { 'FileSystem'; break }
      '(?i)(?:setInstallerVariable|setVariable|properties|pathManipulation)' { 'Configuration'; break }
      default { 'Other' }
    }
    [pscustomobject][ordered]@{
      ActionType          = $ActionType
      Category            = $Category
      Phase               = $Phase
      Lifecycle           = $Lifecycle
      ConditionState      = $Condition.State
      Conditions          = $Condition.Conditions
      Properties          = [pscustomobject]$Properties
      ResolvedProperties  = [pscustomobject]$ResolvedProperties
      UnresolvedVariables = [string[]]@($UnresolvedVariables | Sort-Object)
      SensitiveProperties = [string[]]@($SensitiveProperties | Sort-Object)
    }
  }
}

function Get-InstallBuilderDynamicLogicInfo {
  <#
  .SYNOPSIS
    Collect exact unresolved InstallBuilder expressions and rule source for agent review.
  .DESCRIPTION
    The parser does not execute Tcl or external scripts. This projection returns the source text
    stored in project.xml together with values for referenced deterministic variables, parameter
    defaults, and setInstallerVariable assignments. Password-like values are redacted.
  .PARAMETER Xml
    Parsed InstallBuilder project document.
  .PARAMETER Context
    Deterministic project context used by the bounded static evaluator.
  .PARAMETER ProjectAction
    Phase-aware project actions used to associate variable assignments and affected operations.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][xml]$Xml,
    [Parameter(Mandatory)]$Context,
    [AllowNull()][object[]]$ProjectAction
  )

  $VariableFacts = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
  $AddVariableFact = {
    param ([string]$Name, [string]$Source, [AllowNull()][string]$Value, [bool]$IsKnown, [bool]$IsRuntimeMutable, [bool]$IsSensitive)
    if ([string]::IsNullOrWhiteSpace($Name)) { return }
    if (-not $VariableFacts.ContainsKey($Name)) { $VariableFacts[$Name] = [Collections.Generic.List[object]]::new() }
    $VariableFacts[$Name].Add([pscustomobject][ordered]@{
        Name             = $Name
        Source           = $Source
        Value            = $IsSensitive -and $null -ne $Value ? '<redacted>' : $Value
        IsKnown          = $IsKnown
        IsRuntimeMutable = $IsRuntimeMutable
        IsRedacted       = $IsSensitive -and $null -ne $Value
      })
  }

  foreach ($Name in $Context.Variables.Keys) {
    $Sensitive = $Name -match '(?i)(?:password|passphrase|secret|token|credential|privatekey)'
    & $AddVariableFact $Name 'DeterministicProjectContext' $Context.Variables[$Name] $true $false $Sensitive
  }
  foreach ($ParameterNode in @($Xml.SelectNodes('//parameterList//*'))) {
    if ($ParameterNode.NodeType -ne [Xml.XmlNodeType]::Element) { continue }
    $Name = (Get-InstallBuilderXmlValue -Xml $ParameterNode -XPath 'name') ?? $ParameterNode.GetAttribute('name')
    if ([string]::IsNullOrWhiteSpace($Name)) { continue }
    $ConfiguredValue = (Get-InstallBuilderXmlValue -Xml $ParameterNode -XPath 'value') ?? $ParameterNode.GetAttribute('value')
    if ($null -eq $ConfiguredValue) { $ConfiguredValue = (Get-InstallBuilderXmlValue -Xml $ParameterNode -XPath 'default') ?? $ParameterNode.GetAttribute('default') }
    $Sensitive = $ParameterNode.LocalName -match '(?i)password' -or $Name -match '(?i)(?:password|passphrase|secret|token|credential|privatekey)'
    & $AddVariableFact $Name "ParameterDefault:$($ParameterNode.LocalName)" $ConfiguredValue ($null -ne $ConfiguredValue) $true $Sensitive
  }
  foreach ($Action in @($ProjectAction | Where-Object ActionType -EQ 'setInstallerVariable')) {
    $Name = [string]$Action.Properties.name
    $Value = [string]$Action.Properties.value
    $Sensitive = $Name -match '(?i)(?:password|passphrase|secret|token|credential|privatekey)'
    & $AddVariableFact $Name "setInstallerVariable:$($Action.Phase)" $Value ($Action.ConditionState -eq 'True') $true $Sensitive
  }

  $Records = [Collections.Generic.List[object]]::new()
  $Seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  $AddRecord = {
    param (
      [string]$EvidenceKind,
      [string]$OwnerType,
      [AllowNull()][string]$Property,
      [AllowNull()][string]$Phase,
      [AllowNull()][string]$Lifecycle,
      [string]$SourceCode,
      [AllowNull()][string[]]$AffectedFields
    )
    if ([string]::IsNullOrWhiteSpace($SourceCode) -or $Records.Count -ge $Script:InstallBuilderMaximumDynamicLogicRecords) { return }
    if ($Property -match '(?i)(?:password|passphrase|secret|token|credential|privatekey)') { $SourceCode = '<redacted>' }
    $Identity = "$EvidenceKind`0$OwnerType`0$Property`0$Phase`0$SourceCode"
    if (-not $Seen.Add($Identity)) { return }
    $Variables = [Collections.Generic.List[object]]::new()
    foreach ($Match in [regex]::Matches($SourceCode, '\$\{(?<Name>[^{}]+)\}')) {
      $Name = $Match.Groups['Name'].Value
      if ($VariableFacts.ContainsKey($Name)) {
        foreach ($Fact in $VariableFacts[$Name]) { $Variables.Add($Fact) }
      } else {
        $Variables.Add([pscustomobject][ordered]@{ Name = $Name; Source = 'RuntimeOrUnknown'; Value = $null; IsKnown = $false; IsRuntimeMutable = $true; IsRedacted = $false })
      }
    }
    $Records.Add([pscustomobject][ordered]@{
        EvidenceKind        = $EvidenceKind
        Language            = $EvidenceKind -eq 'Rule' ? 'InstallBuilderRuleXml' : 'InstallBuilderExpression'
        OwnerType           = $OwnerType
        Property            = $Property
        Phase               = $Phase
        Lifecycle           = $Lifecycle
        SourceCode          = $SourceCode
        ReferencedVariables = [string[]]@($Variables.Name | Sort-Object -Unique)
        VariableValues      = [object[]]@($Variables | Sort-Object Name, Source -Unique)
        AffectedFields      = [string[]]@($AffectedFields | Where-Object { $_ } | Sort-Object -Unique)
      })
  }

  # Unknown rule results retain their exact XML rather than being translated into another
  # expression language. The surrounding action identifies the operation the rule controls.
  foreach ($Action in @($ProjectAction)) {
    # Only successful installation phases can change installed-state metadata. Keep source from
    # presentation, uninstall, and rollback logic available without promoting it into unrelated
    # manifest-update warnings. Unknown phases stay conservative because their timing is unproven.
    $AffectedFields = if ($Action.Lifecycle -in 'Installation', 'Unknown') {
      switch ($Action.Category) {
        'Registry' { @(Get-InstallBuilderRegistryAffectedField -Operation $Action) }
        'Execution' { @('ProductCode', 'AppsAndFeaturesEntries', 'InstallerSwitches') }
        'FileSystem' { @('Architecture', 'Dependencies') }
        default { @() }
      }
    } elseif ($Action.Lifecycle -eq 'Initialization' -and $Action.Category -eq 'Execution') {
      @('InstallerSwitches', 'Dependencies')
    } else {
      @()
    }
    foreach ($Condition in @($Action.Conditions | Where-Object State -EQ 'Unknown')) {
      & $AddRecord 'Rule' $Action.ActionType $Condition.Type $Action.Phase $Action.Lifecycle ([string]$Condition.Xml) $AffectedFields
    }
    foreach ($PropertyInfo in @($Action.Properties.PSObject.Properties)) {
      if ($PropertyInfo.Name -in @($Action.SensitiveProperties) -or $PropertyInfo.Value -isnot [string]) { continue }
      $Resolved = Resolve-InstallBuilderProjectValue -Value ([string]$PropertyInfo.Value) -Variables $Context.Variables
      if ($Resolved.UnresolvedVariables.Count -eq 0) { continue }
      & $AddRecord 'Expression' $Action.ActionType $PropertyInfo.Name $Action.Phase $Action.Lifecycle ([string]$PropertyInfo.Value) $AffectedFields
    }
  }

  # Project properties and parameter values can affect payload selection and installer behavior
  # without belonging to an action list. Retain only unresolved substitutions or explicit script,
  # code, and expression fields to avoid duplicating ordinary resolved metadata.
  foreach ($Node in @($Xml.SelectNodes('//*[not(*)]'))) {
    if ($Node.NodeType -ne [Xml.XmlNodeType]::Element) { continue }
    $SourceCode = $Node.InnerText.Trim()
    if ([string]::IsNullOrWhiteSpace($SourceCode)) { continue }
    $Resolved = Resolve-InstallBuilderProjectValue -Value $SourceCode -Variables $Context.Variables
    $IsExplicitLogic = $Node.LocalName -match '(?i)(?:script|expression|code)$'
    if (-not $IsExplicitLogic -and $Resolved.UnresolvedVariables.Count -eq 0) { continue }
    $Owner = $Node.ParentNode -and $Node.ParentNode.NodeType -eq [Xml.XmlNodeType]::Element ? $Node.ParentNode.LocalName : 'project'
    $Phase = try { Get-InstallBuilderActionPhase -Node $Node } catch { $null }
    if ($Phase -eq 'actionList') { $Phase = $null }
    & $AddRecord ($IsExplicitLogic ? 'ScriptOrExpression' : 'Expression') $Owner $Node.LocalName $Phase ($Phase ? (Get-InstallBuilderActionLifecycle -Phase $Phase) : $null) $SourceCode @()
  }

  return $Records.ToArray()
}

function Get-InstallBuilderFileAssociationInfo {
  <#
  .SYNOPSIS
    Project native InstallBuilder file-association actions into structured evidence.
  .DESCRIPTION
    InstallBuilder's associateWindowsFileExtension action writes one ProgID and one or more
    extension registrations. This function resolves only deterministic project variables and
    retains lifecycle and condition evidence so callers can distinguish installed state from
    uninstall, presentation, and conditional actions.
  .PARAMETER Xml
    Parsed InstallBuilder project document containing compiled action lists.
  .PARAMETER Context
    Deterministic project variables and PE platform evidence used by value and condition
    resolution.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][xml]$Xml,
    [Parameter(Mandatory)]$Context
  )

  $Associations = [Collections.Generic.List[object]]::new()
  $Diagnostics = [Collections.Generic.List[object]]::new()
  $UnresolvedFields = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $Sequence = 0
  foreach ($Action in @($Xml.SelectNodes('//associateWindowsFileExtension | //removeWindowsFileAssociation'))) {
    $Sequence++
    $Operation = $Action.LocalName -ceq 'removeWindowsFileAssociation' ? 'Remove' : 'Add'
    $Phase = Get-InstallBuilderActionPhase -Node $Action
    $Lifecycle = Get-InstallBuilderActionLifecycle -Phase $Phase
    $Condition = Get-InstallBuilderNodeCondition -Node $Action -Context $Context
    $ResolvedValues = [ordered]@{}
    $UnresolvedVariables = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $UnresolvedProperties = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($Name in 'extensions', 'progID', 'icon', 'scope', 'mimeType', 'friendlyName') {
      $Expression = Get-InstallBuilderXmlValue -Xml $Action -XPath $Name
      if ($Name -eq 'scope' -and [string]::IsNullOrWhiteSpace($Expression)) { $Expression = 'system' }
      $Resolved = Resolve-InstallBuilderProjectValue -Value $Expression -Variables $Context.Variables
      $ResolvedValues[$Name] = $Resolved.Value
      foreach ($Variable in @($Resolved.UnresolvedVariables)) {
        $null = $UnresolvedVariables.Add($Variable)
        $null = $UnresolvedProperties.Add($Name)
      }
    }

    $Commands = [Collections.Generic.List[object]]::new()
    foreach ($CommandNode in @($Action.SelectNodes('./commandList/command'))) {
      $CommandCondition = Get-InstallBuilderNodeCondition -Node $CommandNode -Context $Context
      $CommandValues = [ordered]@{}
      $CommandUnresolved = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
      foreach ($Name in 'verb', 'runProgram', 'runProgramArguments') {
        $Resolved = Resolve-InstallBuilderProjectValue -Value (Get-InstallBuilderXmlValue -Xml $CommandNode -XPath $Name) -Variables $Context.Variables
        $CommandValues[$Name] = $Resolved.Value
        foreach ($Variable in @($Resolved.UnresolvedVariables)) {
          $null = $CommandUnresolved.Add($Variable)
          $null = $UnresolvedVariables.Add($Variable)
        }
      }
      $Program = ([string]$CommandValues.runProgram).Replace('/', '\')
      $Arguments = [string]$CommandValues.runProgramArguments
      $CommandLine = $null
      if (-not [string]::IsNullOrWhiteSpace($Program)) {
        # InstallBuilder stores executable and arguments separately. Quote a path containing
        # whitespace in the projected command line without modifying an already quoted value.
        $CommandProgram = if ($Program -match '^\s*".*"\s*$' -or ($Program -notmatch '\s' -and $Program -notmatch '%[^%]+%')) { $Program } else { '"' + $Program + '"' }
        $CommandLine = [string]::IsNullOrWhiteSpace($Arguments) ? $CommandProgram : "$CommandProgram $Arguments"
      }
      $Commands.Add([pscustomobject][ordered]@{
          Verb                = [string]$CommandValues.verb
          Executable          = $Program
          Arguments           = $Arguments
          Command             = $CommandLine
          # Node-condition evaluation already walks the association ancestor, so the command
          # state includes both command-local and parent-action rules without double counting.
          ConditionState      = $CommandCondition.State
          Conditions          = $CommandCondition.Conditions
          UnresolvedVariables = [string[]]@($CommandUnresolved | Sort-Object)
        })
    }

    $Extensions = @([string]$ResolvedValues.extensions -split '\s+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($Lifecycle -eq 'Installation' -and $UnresolvedProperties.Contains('extensions')) {
      $null = $UnresolvedFields.Add('FileExtensions')
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Association.ExtensionsUnresolved' -Source InstallBuilder -Message 'A native file-association action contains an unresolved extension expression, so the installed extension set is incomplete.' -Kind Incomplete -Areas Metadata -AffectedFields FileExtensions -Evidence ([pscustomobject]@{ Operation = $Operation; Phase = $Phase; Variables = @($UnresolvedVariables | Sort-Object) })))
    }
    $AssociationScope = switch ([string]$ResolvedValues.scope) {
      { $_ -ieq 'user' } { 'user'; break }
      { $_ -ieq 'system' } { 'machine'; break }
      default { $null }
    }
    foreach ($ExtensionText in $Extensions) {
      $Extension = $ExtensionText.StartsWith('.') ? $ExtensionText : ".$ExtensionText"
      if ($Extension -notmatch '^\.[A-Za-z0-9][A-Za-z0-9._+-]{0,254}$') {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Association.ExtensionInvalid' -Source InstallBuilder -Message "The associateWindowsFileExtension action contains an invalid literal extension '$ExtensionText'." -Kind Incomplete -Areas Metadata -AffectedFields FileExtensions -Evidence ([pscustomobject]@{ Extension = $ExtensionText; Phase = $Phase })))
        continue
      }
      $PrimaryCommand = @($Commands | Where-Object { $_.Verb -ieq 'open' } | Select-Object -First 1)
      if ($PrimaryCommand.Count -eq 0) { $PrimaryCommand = @($Commands | Select-Object -First 1) }
      $Associations.Add([pscustomobject][ordered]@{
          Operation            = $Operation
          Sequence             = $Sequence
          FileExtension        = $Extension.TrimStart('.').ToLowerInvariant()
          Extension            = $Extension.ToLowerInvariant()
          Root                 = $AssociationScope -eq 'user' ? 'HKCU' : ($AssociationScope -eq 'machine' ? 'HKLM' : $null)
          DefaultProgId        = [string]$ResolvedValues.progID
          ProgIds              = [string[]]@($ResolvedValues.progID | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
          Description          = [string]$ResolvedValues.friendlyName
          Command              = $PrimaryCommand.Count ? $PrimaryCommand[0].Command : $null
          Executable           = $PrimaryCommand.Count ? $PrimaryCommand[0].Executable : $null
          Arguments            = $PrimaryCommand.Count ? $PrimaryCommand[0].Arguments : $null
          DefaultIcon          = ([string]$ResolvedValues.icon).Replace('/', '\')
          MimeType             = [string]$ResolvedValues.mimeType
          Scope                = $AssociationScope
          Commands             = $Commands.ToArray()
          Phase                = $Phase
          Lifecycle            = $Lifecycle
          ConditionState       = $Condition.State
          Conditions           = $Condition.Conditions
          UnresolvedVariables  = [string[]]@($UnresolvedVariables | Sort-Object)
          UnresolvedProperties = [string[]]@($UnresolvedProperties | Sort-Object)
          Source               = $Action.LocalName
          Evidence             = @($Action.OuterXml)
        })
    }
  }

  $Conditional = @($Associations | Where-Object { $_.Lifecycle -eq 'Installation' -and $_.ConditionState -eq 'Unknown' })
  if ($Conditional.Count) {
    $null = $UnresolvedFields.Add('FileExtensions')
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Association.ConditionsUnresolved' -Source InstallBuilder -Message "$($Conditional.Count) file-extension association(s) depend on runtime rules and were excluded from authoritative installed-state projection." -Kind Incomplete -Areas Metadata -AffectedFields FileExtensions -Evidence ([pscustomobject]@{ Extensions = @($Conditional.Extension | Sort-Object -Unique) })))
  }
  $Unresolved = @($Associations | Where-Object { $_.Lifecycle -eq 'Installation' -and @($_.UnresolvedVariables).Count })
  if ($Unresolved.Count) {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallBuilder.Association.ValuesUnresolved' -Source InstallBuilder -Message "$($Unresolved.Count) file-extension association record(s) contain unresolved optional values; inspect FileExtensionAssociations for the exact affected properties." -Kind Incomplete -Areas Metadata -AffectedFields @() -Evidence ([pscustomobject]@{ Variables = @($Unresolved.UnresolvedVariables | Sort-Object -Unique); Properties = @($Unresolved.UnresolvedProperties | Sort-Object -Unique) })))
  }

  # Simulate deterministic add/remove operations. Unknown removals invalidate only the concrete
  # extension and scope they can affect; optional unresolved command/icon text does not erase a
  # proven extension registration.
  $PhaseRank = @{ preInstallationActionList = 100; readyToInstallActionList = 200; folderActionList = 300; postInstallationActionList = 400; postUninstallerCreationActionList = 500 }
  $Effective = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
  $UncertainExtensions = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($Association in @($Associations | Where-Object Lifecycle -EQ 'Installation' | Sort-Object @{ Expression = { $PhaseRank.ContainsKey($_.Phase) ? $PhaseRank[$_.Phase] : 1000 } }, Sequence)) {
    $Identity = "$($Association.Root)|$($Association.Extension)"
    if ($Association.ConditionState -eq 'False') { continue }
    if ($Association.ConditionState -ne 'True') {
      $null = $UncertainExtensions.Add($Association.Extension)
      continue
    }
    if ($Association.Operation -eq 'Add') {
      $Effective[$Identity] = $Association
      continue
    }
    if ($Association.UnresolvedProperties -contains 'progID' -or -not $Association.Root) {
      $null = $UncertainExtensions.Add($Association.Extension)
      $null = $UnresolvedFields.Add('FileExtensions')
      continue
    }
    if (-not $Effective.ContainsKey($Identity)) { continue }
    if (-not $Association.DefaultProgId -or $Effective[$Identity].DefaultProgId -ieq $Association.DefaultProgId) { $null = $Effective.Remove($Identity) }
  }
  $EffectiveAssociations = @($Effective.Values | Where-Object { -not $UncertainExtensions.Contains($_.Extension) } | Sort-Object Root, Extension)
  [pscustomobject][ordered]@{
    FileExtensions            = @($EffectiveAssociations | Select-Object -ExpandProperty FileExtension -Unique | Sort-Object)
    FileExtensionAssociations = $Associations.ToArray()
    EffectiveAssociations     = [object[]]$EffectiveAssociations
    UnresolvedFields          = [string[]]@($UnresolvedFields | Sort-Object)
    Diagnostics               = @(Merge-InstallerDiagnostics -Diagnostic $Diagnostics.ToArray())
  }
}

function Get-InstallBuilderSystemEffectInfo {
  <#
  .SYNOPSIS
    Normalize source-backed persistent system-effect actions.
  .PARAMETER ProjectAction
    Phase-aware records returned by Get-InstallBuilderProjectActionInfo.
  #>
  [OutputType([pscustomobject])]
  param ([AllowNull()][object[]]$ProjectAction)

  $EnvironmentChanges = [Collections.Generic.List[object]]::new()
  $PathChanges = [Collections.Generic.List[object]]::new()
  $WindowsServices = [Collections.Generic.List[object]]::new()
  $ScheduledTasks = [Collections.Generic.List[object]]::new()
  $FontChanges = [Collections.Generic.List[object]]::new()
  $SharedDllChanges = [Collections.Generic.List[object]]::new()
  $WindowsAclChanges = [Collections.Generic.List[object]]::new()
  foreach ($Action in @($ProjectAction)) {
    $Values = $Action.ResolvedProperties
    $Value = [ordered]@{}
    foreach ($Name in 'scope', 'insertAt', 'path', 'name', 'value', 'username', 'serviceName', 'displayName', 'description', 'program', 'programArguments', 'startType', 'account', 'password', 'dependencies', 'delay', 'abortOnError', 'type', 'runAsAdmin', 'executionTimeLimit', 'weekDays', 'startTime', 'runOnlyIfLoggedOn', 'endDate', 'interval', 'dayOfMonth', 'runAs', 'period', 'startDate', 'disallowStartIfOnBatteries', 'workingDirectory', 'duration', 'files', 'excludeFiles', 'matchHiddenFiles', 'permissions', 'recurseOneLevelOnly', 'users', 'self', 'action', 'recurseObjects', 'recurseContainers', 'owner') {
      $Property = $Values.PSObject.Properties[$Name]
      $Value[$Name] = $Property ? [string]$Property.Value : $null
    }
    $ScopeProperty = $Values.PSObject.Properties['scope']
    $Scope = if (-not $ScopeProperty) { 'machine' } elseif ($Value.scope -ieq 'user') { 'user' } elseif ($Value.scope -ieq 'system') { 'machine' } else { $null }
    $AppliesToInstalledState = $Action.Lifecycle -eq 'Installation' -and $Action.ConditionState -eq 'True' -and @($Action.UnresolvedVariables).Count -eq 0
    $Common = [ordered]@{
      ActionType              = $Action.ActionType
      Phase                   = $Action.Phase
      Lifecycle               = $Action.Lifecycle
      ConditionState          = $Action.ConditionState
      Conditions              = $Action.Conditions
      UnresolvedVariables     = $Action.UnresolvedVariables
      AppliesToInstalledState = $AppliesToInstalledState
    }
    switch ($Action.ActionType) {
      'addDirectoryToPath' {
        $PathChanges.Add([pscustomobject]($Common + [ordered]@{ Action = 'Add'; Path = ([string]$Value.path).Replace('/', '\'); Scope = $Scope; Position = ([string]::IsNullOrWhiteSpace($Value.insertAt) ? 'end' : $Value.insertAt); PositionAppliesOnWindows = $false; Persistent = $true }))
      }
      'removeDirectoryFromPath' {
        $PathChanges.Add([pscustomobject]($Common + [ordered]@{ Action = 'Remove'; Path = ([string]$Value.path).Replace('/', '\'); Scope = $Scope; Position = $null; PositionAppliesOnWindows = $false; Persistent = $true }))
      }
      'addEnvironmentVariable' {
        $EnvironmentChanges.Add([pscustomobject]($Common + [ordered]@{ Action = 'Add'; Name = $Value.name; Value = $Value.value; Scope = $Scope; Username = $Value.username; Persistent = $true }))
      }
      'deleteEnvironmentVariable' {
        $EnvironmentChanges.Add([pscustomobject]($Common + [ordered]@{ Action = 'Delete'; Name = $Value.name; Value = $null; Scope = $Scope; Username = $Value.username; Persistent = $true }))
      }
      'setEnvironmentVariable' {
        # The documented setEnvironmentVariable action changes only the installer's process
        # environment. Preserve it as execution evidence without claiming installed state.
        $ProcessEffect = [pscustomobject]($Common + [ordered]@{ Action = 'SetProcess'; Name = $Value.name; Value = $Value.value; Scope = 'process'; Username = $null; Persistent = $false })
        $ProcessEffect.AppliesToInstalledState = $false
        $EnvironmentChanges.Add($ProcessEffect)
      }
      { $_ -in 'createWindowsService', 'deleteWindowsService', 'startWindowsService', 'stopWindowsService', 'restartWindowsService' } {
        $Operation = switch ($_) { 'createWindowsService' { 'Create' } 'deleteWindowsService' { 'Delete' } 'startWindowsService' { 'Start' } 'stopWindowsService' { 'Stop' } 'restartWindowsService' { 'Restart' } }
        $DelayMilliseconds = 0L
        $HasDelay = [long]::TryParse($Value.delay, [Globalization.NumberStyles]::Integer, [Globalization.CultureInfo]::InvariantCulture, [ref]$DelayMilliseconds)
        if (-not $HasDelay -and $Operation -in 'Start', 'Stop', 'Restart') { $DelayMilliseconds = 15000; $HasDelay = $true }
        $WindowsServices.Add([pscustomobject]($Common + [ordered]@{
              Operation          = $Operation
              ServiceName        = $Value.serviceName
              DisplayName        = $Value.displayName
              Description        = $Value.description
              Program            = ([string]$Value.program).Replace('/', '\')
              ProgramArguments   = $Value.programArguments
              StartType          = if (-not [string]::IsNullOrWhiteSpace($Value.startType)) { $Value.startType } elseif ($Operation -eq 'Create') { 'auto' } else { $null }
              Account            = if (-not [string]::IsNullOrWhiteSpace($Value.account)) { $Value.account } elseif ($Operation -eq 'Create') { 'LocalSystem' } else { $null }
              PasswordConfigured = -not [string]::IsNullOrWhiteSpace($Value.password)
              Dependencies       = @($Value.dependencies -split '\s*,\s*' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
              DelayMilliseconds  = $HasDelay ? $DelayMilliseconds : $null
              AbortOnError       = Test-InstallBuilderTrueValue $Value.abortOnError
            }))
      }
      { $_ -in 'addScheduledTask', 'deleteScheduledTask' } {
        $Operation = $_ -eq 'addScheduledTask' ? 'CreateOrUpdate' : 'Delete'
        $IsCreateTask = $Operation -eq 'CreateOrUpdate'
        $ScheduledTasks.Add([pscustomobject]($Common + [ordered]@{
              Operation                  = $Operation
              Name                       = $Value.name
              TriggerType                = $IsCreateTask ? ([string]::IsNullOrWhiteSpace($Value.type) ? 'DAILY' : $Value.type.ToUpperInvariant()) : $null
              Program                    = $IsCreateTask ? ([string]$Value.program).Replace('/', '\') : $null
              Arguments                  = $IsCreateTask ? $Value.programArguments : $null
              WorkingDirectory           = $IsCreateTask ? ([string]$Value.workingDirectory).Replace('/', '\') : $null
              RunAs                      = $IsCreateTask ? $Value.runAs : $null
              PasswordConfigured         = $IsCreateTask ? (-not [string]::IsNullOrWhiteSpace($Value.password)) : $null
              RunAsAdministrator         = $IsCreateTask ? (Test-InstallBuilderTrueValue $Value.runAsAdmin) : $null
              RunOnlyIfLoggedOn          = $IsCreateTask ? (Test-InstallBuilderTrueValue $Value.runOnlyIfLoggedOn) : $null
              DisallowStartIfOnBatteries = $IsCreateTask ? ([string]::IsNullOrWhiteSpace($Value.disallowStartIfOnBatteries) -or (Test-InstallBuilderTrueValue $Value.disallowStartIfOnBatteries)) : $null
              StartDate                  = $IsCreateTask ? $Value.startDate : $null
              EndDate                    = $IsCreateTask ? $Value.endDate : $null
              StartTime                  = $IsCreateTask ? $Value.startTime : $null
              WeekDays                   = $IsCreateTask ? $Value.weekDays : $null
              DayOfMonth                 = $IsCreateTask ? ([string]::IsNullOrWhiteSpace($Value.dayOfMonth) ? '1' : $Value.dayOfMonth) : $null
              Period                     = $IsCreateTask ? ([string]::IsNullOrWhiteSpace($Value.period) ? '1' : $Value.period) : $null
              IntervalMinutes            = $IsCreateTask ? $Value.interval : $null
              DurationMinutes            = $IsCreateTask ? $Value.duration : $null
              ExecutionTimeLimitHours    = $IsCreateTask ? ([string]::IsNullOrWhiteSpace($Value.executionTimeLimit) ? '72' : $Value.executionTimeLimit) : $null
            }))
      }
      { $_ -in 'addFonts', 'removeFonts' } {
        $FontChanges.Add([pscustomobject]($Common + [ordered]@{
              Operation        = $_ -eq 'addFonts' ? 'Add' : 'Remove'
              Files            = ([string]$Value.files).Replace('/', '\')
              ExcludeFiles     = ([string]$Value.excludeFiles).Replace('/', '\')
              MatchHiddenFiles = Test-InstallBuilderTrueValue $Value.matchHiddenFiles
            }))
      }
      { $_ -in 'addSharedDLL', 'removeSharedDLL' } {
        $SharedDllChanges.Add([pscustomobject]($Common + [ordered]@{
              Operation = $_ -eq 'addSharedDLL' ? 'IncrementReference' : 'DecrementReference'
              Path      = ([string]$Value.path).Replace('/', '\')
            }))
      }
      { $_ -in 'setWindowsACL', 'clearWindowsACL' } {
        $WindowsAclChanges.Add([pscustomobject]($Common + [ordered]@{
              Operation           = $_ -eq 'setWindowsACL' ? 'Set' : 'Clear'
              Files               = ([string]$Value.files).Replace('/', '\')
              ExcludeFiles        = ([string]$Value.excludeFiles).Replace('/', '\')
              MatchHiddenFiles    = Test-InstallBuilderTrueValue $Value.matchHiddenFiles
              Permissions         = $_ -eq 'setWindowsACL' ? ([string]::IsNullOrWhiteSpace($Value.permissions) ? 'generic_all' : $Value.permissions) : $null
              Users               = $_ -eq 'setWindowsACL' ? ([string]::IsNullOrWhiteSpace($Value.users) ? 'S-1-1-0' : $Value.users) : $null
              Access              = $_ -eq 'setWindowsACL' ? ([string]::IsNullOrWhiteSpace($Value.action) ? 'allow' : $Value.action) : $null
              Owner               = $_ -eq 'setWindowsACL' ? $Value.owner : $null
              ApplyToSelf         = $_ -eq 'setWindowsACL' ? ([string]::IsNullOrWhiteSpace($Value.self) -or (Test-InstallBuilderTrueValue $Value.self)) : $null
              RecurseObjects      = $_ -eq 'setWindowsACL' ? (Test-InstallBuilderTrueValue $Value.recurseObjects) : $null
              RecurseContainers   = $_ -eq 'setWindowsACL' ? (Test-InstallBuilderTrueValue $Value.recurseContainers) : $null
              RecurseOneLevelOnly = $_ -eq 'setWindowsACL' ? (Test-InstallBuilderTrueValue $Value.recurseOneLevelOnly) : $null
            }))
      }
    }
  }
  [pscustomobject][ordered]@{
    EnvironmentChanges = $EnvironmentChanges.ToArray()
    PathChanges        = $PathChanges.ToArray()
    WindowsServices    = $WindowsServices.ToArray()
    ScheduledTasks     = $ScheduledTasks.ToArray()
    FontChanges        = $FontChanges.ToArray()
    SharedDllChanges   = $SharedDllChanges.ToArray()
    WindowsAclChanges  = $WindowsAclChanges.ToArray()
  }
}

function Resolve-InstallBuilderPayloadPath {
  <#
  .SYNOPSIS
    Match a resolved installed path to one logical InstallBuilder payload path.
  .PARAMETER Path
    Resolved action or shortcut target.
  .PARAMETER Context
    Project context containing the resolved installation directory.
  .PARAMETER PayloadPath
    Case-insensitive set of logical packaged payload paths.
  #>
  [OutputType([string])]
  param (
    [AllowNull()][string]$Path,
    [Parameter(Mandatory)]$Context,
    [AllowNull()][Collections.Generic.HashSet[string]]$PayloadPath
  )

  if ($null -eq $PayloadPath) { $PayloadPath = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase) }
  if ([string]::IsNullOrWhiteSpace($Path) -or [string]::IsNullOrWhiteSpace($Context.InstallLocation)) { return $null }
  $NormalizedPath = $Path.Replace('\', '/')
  $NormalizedInstallLocation = $Context.InstallLocation.Replace('\', '/').TrimEnd('/')
  if (-not $NormalizedPath.StartsWith($NormalizedInstallLocation + '/', [StringComparison]::OrdinalIgnoreCase)) { return $null }
  $RelativePath = $NormalizedPath.Substring($NormalizedInstallLocation.Length + 1)
  if (-not $PayloadPath.Contains($RelativePath) -and $PayloadPath.Contains($RelativePath + '.exe')) { $RelativePath += '.exe' }
  return $PayloadPath.Contains($RelativePath) ? $RelativePath : $null
}

function Get-InstallBuilderExecutionInfo {
  <#
  .SYNOPSIS
    Project compiled runProgram actions without executing or classifying arbitrary programs.
  .PARAMETER Xml
    Parsed InstallBuilder project document.
  .PARAMETER Context
    Deterministic project variables and inherited-condition evidence.
  .PARAMETER Payload
    Logical payload catalog used only to mark source-backed embedded executable matches.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][xml]$Xml,
    [Parameter(Mandatory)]$Context,
    [AllowEmptyCollection()][object[]]$Payload = @()
  )

  $PayloadPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($Item in @($Payload)) { $null = $PayloadPaths.Add(([string]$Item.Path).Replace('\', '/')) }
  $Actions = [Collections.Generic.List[object]]::new()
  $NestedCandidates = [Collections.Generic.List[object]]::new()
  foreach ($Action in @($Xml.SelectNodes('//runProgram'))) {
    $RawProgram = (Get-InstallBuilderXmlValue -Xml $Action -XPath 'program') ?? $Action.GetAttribute('program')
    if ([string]::IsNullOrWhiteSpace($RawProgram)) { continue }
    $RawArguments = (Get-InstallBuilderXmlValue -Xml $Action -XPath 'programArguments') ?? $Action.GetAttribute('programArguments')
    $RawWorkingDirectory = (Get-InstallBuilderXmlValue -Xml $Action -XPath 'workingDirectory') ?? $Action.GetAttribute('workingDirectory')
    $Program = Resolve-InstallBuilderProjectValue -Value $RawProgram -Variables $Context.Variables
    $Arguments = Resolve-InstallBuilderProjectValue -Value $RawArguments -Variables $Context.Variables
    $WorkingDirectory = Resolve-InstallBuilderProjectValue -Value $RawWorkingDirectory -Variables $Context.Variables
    $Condition = Get-InstallBuilderNodeCondition -Node $Action -Context $Context
    $Phase = Get-InstallBuilderActionPhase -Node $Action
    $Lifecycle = Get-InstallBuilderActionLifecycle -Phase $Phase
    $RelativeProgram = Resolve-InstallBuilderPayloadPath -Path $Program.Value -Context $Context -PayloadPath $PayloadPaths
    $Record = [pscustomobject][ordered]@{
      Phase               = $Phase
      Lifecycle           = $Lifecycle
      Program             = $Program.Value
      ProgramExpression   = $RawProgram
      Arguments           = $Arguments.Value
      ArgumentsExpression = $RawArguments
      WorkingDirectory    = $WorkingDirectory.Value
      ConditionState      = $Condition.State
      Conditions          = $Condition.Conditions
      PayloadPath         = $RelativeProgram
      IsEmbeddedPayload   = [bool]($RelativeProgram -and $PayloadPaths.Contains($RelativeProgram))
      Purpose             = $Lifecycle -eq 'Presentation' ? 'ApplicationLaunch' : ($Lifecycle -eq 'Uninstallation' ? 'UninstallAction' : ($Lifecycle -eq 'Installation' ? 'InstallerAction' : 'OtherAction'))
    }
    $Actions.Add($Record)
    if ($Record.Purpose -eq 'InstallerAction' -and $Record.IsEmbeddedPayload -and $RelativeProgram -match '(?i)\.(?:exe|msi|msp|msix|appx|bat|cmd|ps1)$') {
      $NestedCandidates.Add($Record)
    }
  }
  [pscustomobject]@{
    Actions                   = $Actions.ToArray()
    ExecutedPayloads          = @($Actions | Where-Object IsEmbeddedPayload | ForEach-Object PayloadPath | Select-Object -Unique)
    NestedInstallerCandidates = $NestedCandidates.ToArray()
  }
}

Export-ModuleMember -Function Get-InstallBuilderXmlValue, Get-InstallBuilderProjectProperty, Test-InstallBuilderTrueValue, Resolve-InstallBuilderProjectValue, Get-InstallBuilderProjectContext, Resolve-InstallBuilderRuleState, Resolve-InstallBuilderRuleList, Get-InstallBuilderNodeCondition, Get-InstallBuilderRegistryOperation, Get-InstallBuilderRegistryAffectedField, Resolve-InstallBuilderRegistryState, Get-InstallBuilderScopeInfo, Get-InstallBuilderActionPhase, Get-InstallBuilderActionLifecycle, Get-InstallBuilderProjectActionInfo, Get-InstallBuilderDynamicLogicInfo, Get-InstallBuilderFileAssociationInfo, Get-InstallBuilderSystemEffectInfo, Resolve-InstallBuilderPayloadPath, Get-InstallBuilderExecutionInfo
