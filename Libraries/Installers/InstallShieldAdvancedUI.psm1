# SPDX-License-Identifier: Apache-2.0
# InstallShield Advanced UI/Suite catalog, conditions, prerequisites, and nested packages.

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

function Resolve-InstallShieldSuiteString {
  <#
  .SYNOPSIS
    Resolve an Advanced UI string-table identifier in the default language.
  .PARAMETER Xml
    Parsed Setup.xml document using an installshield/<year>/bootstrap namespace.
  .PARAMETER Value
    Literal text or XML element name used as a localized string identifier.
  .PARAMETER Language
    Default LCID selected by the suite's LanguageSelection element.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][xml]$Xml,
    [string]$Value,
    [string]$Language
  )

  if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
  if ($Value -notmatch '^[A-Za-z_][A-Za-z0-9_.-]*$') { return $Value }

  # Element names are fixed builder identifiers, so namespace-agnostic XPath
  # avoids coupling the parser to a particular InstallShield release year.
  $LanguageNode = if ($Language) {
    $Xml.SelectSingleNode("/*[local-name()='Setup']/*[local-name()='Languages']/*[local-name()='Language' and @lcid='$Language']")
  } else {
    $null
  }
  if (-not $LanguageNode) { $LanguageNode = $Xml.SelectSingleNode("/*[local-name()='Setup']/*[local-name()='Languages']/*[local-name()='Language'][1]") }
  $StringNode = if ($LanguageNode) { $LanguageNode.SelectSingleNode("./*[local-name()='$Value']") } else { $null }
  if ($StringNode -and -not [string]::IsNullOrWhiteSpace($StringNode.InnerText)) { return $StringNode.InnerText.Trim() }
  return $Value
}

function ConvertFrom-InstallShieldSuiteCondition {
  <#
  .SYNOPSIS
    Convert one Advanced UI condition subtree into bounded structured evidence.
  .DESCRIPTION
    InstallShield condition elements are declarative expression nodes such as
    All, Any, Not, RegistryValue, Platform, and ParcelRef. This function keeps
    their exact attributes and hierarchy. It does not evaluate registry,
    installed-state, property, or custom predicates against the analysis host.
  .PARAMETER Node
    Condition element whose offsets are XML-relative rather than installer-byte-relative.
  .PARAMETER Depth
    Internal recursion depth. Setup.xml trees deeper than 32 nodes are rejected.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][System.Xml.XmlNode]$Node,
    [ValidateRange(0, 32)][int]$Depth = 0
  )

  if ($Depth -ge 32) { throw 'The Advanced UI condition tree exceeds the 32-level parser limit.' }
  $Attributes = [ordered]@{}
  foreach ($Attribute in @($Node.Attributes)) { $Attributes[$Attribute.Name] = $Attribute.Value }
  $ElementChildren = @($Node.ChildNodes | Where-Object NodeType -EQ ([Xml.XmlNodeType]::Element))
  $Children = foreach ($Child in $ElementChildren) {
    ConvertFrom-InstallShieldSuiteCondition -Node $Child -Depth ($Depth + 1)
  }
  $Text = if ($ElementChildren.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace($Node.InnerText)) { $Node.InnerText.Trim() } else { $null }

  [pscustomobject][ordered]@{
    Type       = $Node.LocalName
    Attributes = $Attributes
    Value      = $Text
    Children   = [object[]]@($Children)
  }
}

function ConvertTo-InstallShieldSuiteConditionResult {
  <#
  .SYNOPSIS
    Create one normalized three-valued Advanced UI condition result.
  .PARAMETER State
    Static result: True, False, or Unknown.
  .PARAMETER ConditionType
    InstallShield XML element that produced the result.
  .PARAMETER Reasons
    Human-readable evidence explaining the known result.
  .PARAMETER UnknownPredicates
    Predicates that require target-machine or run-time state.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][ValidateSet('True', 'False', 'Unknown')][string]$State,
    [Parameter(Mandatory)][string]$ConditionType,
    [string[]]$Reasons = @(),
    [string[]]$UnknownPredicates = @()
  )

  [pscustomobject][ordered]@{
    State             = $State
    ConditionType     = $ConditionType
    Reasons           = [string[]]@($Reasons | Where-Object { $_ } | Select-Object -Unique)
    UnknownPredicates = [string[]]@($UnknownPredicates | Where-Object { $_ } | Select-Object -Unique)
  }
}

function Merge-InstallShieldSuiteConditionResult {
  <#
  .SYNOPSIS
    Apply InstallShield All, Any, or Not group semantics to child results.
  .PARAMETER Type
    Group operation. When and Eligible use All semantics; Not means none of its children.
  .PARAMETER Result
    Child condition results to combine.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][ValidateSet('All', 'Any', 'Not', 'When', 'Eligible')][string]$Type,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Result
  )

  $Results = [object[]]@($Result)
  $Reasons = [string[]]@($Results.Reasons)
  $UnknownPredicates = [string[]]@($Results.UnknownPredicates)
  if ($Results.Count -eq 0) {
    return ConvertTo-InstallShieldSuiteConditionResult -State Unknown -ConditionType $Type -Reasons "The $Type condition group has no child predicates."
  }

  # InstallShield calls the Not group "None": it succeeds only when no child
  # condition succeeds, so multiple children are negated as an Any group.
  $EffectiveType = $Type -in @('When', 'Eligible') ? 'All' : $Type
  $Operator = $EffectiveType -eq 'Not' ? 'None' : $EffectiveType
  $State = Merge-InstallerConditionState -State ([string[]]$Results.State) -Operator $Operator

  ConvertTo-InstallShieldSuiteConditionResult -State $State -ConditionType $Type -Reasons $Reasons -UnknownPredicates $UnknownPredicates
}

function Test-InstallShieldSuiteRange {
  <#
  .SYNOPSIS
    Evaluate an InstallShield exact/minimum/maximum numeric or version range.
  .PARAMETER Value
    Target value supplied by the caller, never read from the analysis host.
  .PARAMETER Range
    Authored exact value or range such as 6.1, 6.1-, -10.0, or 6.1-10.0.
  .PARAMETER Version
    Parse the values as System.Version rather than integers.
  #>
  [OutputType([Nullable[bool]])]
  param (
    [Parameter(Mandatory)][string]$Value,
    [Parameter(Mandatory)][string]$Range,
    [switch]$Version
  )

  try {
    $Convert = if ($Version) {
      { param($InputValue) [version]$InputValue }
    } else {
      { param($InputValue) [long]::Parse($InputValue, [Globalization.CultureInfo]::InvariantCulture) }
    }
    $Actual = & $Convert $Value
    if ($Range -notmatch '-') { return $Actual -eq (& $Convert $Range) }

    $Parts = $Range -split '-', 2
    if ($Parts[0] -and $Actual -lt (& $Convert $Parts[0])) { return $false }
    if ($Parts[1] -and $Actual -gt (& $Convert $Parts[1])) { return $false }
    return $true
  } catch {
    return $null
  }
}

function Resolve-InstallShieldSuiteCondition {
  <#
  .SYNOPSIS
    Evaluate the statically knowable portion of an Advanced UI condition tree.
  .DESCRIPTION
    The evaluator is intentionally three-valued. Platform facts supplied by the
    caller can produce True or False. Registry, file, installed-product,
    property, locale, package-reference, UWP, and extension-DLL predicates stay
    Unknown because evaluating them against the analysis host would be unsafe
    and would not describe the eventual target system.
  .PARAMETER Condition
    Structured condition returned by ConvertFrom-InstallShieldSuiteCondition.
  .PARAMETER Architecture
    Optional target architecture: x86, x64, arm, arm64, or ia64.
  .PARAMETER OSVersion
    Optional target Windows major/minor version, such as 10.0.
  .PARAMETER BuildNumber
    Optional target Windows build number.
  .PARAMETER ServicePack
    Optional target service-pack major number.
  .PARAMETER CSDVersion
    Optional target CSD display string.
  .PARAMETER ProductType
    Optional target product type: Workstation, Server, or DomainController.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][object]$Condition,
    [ValidateSet('x86', 'x64', 'arm', 'arm64', 'ia64')][string]$Architecture,
    [string]$OSVersion,
    [Nullable[int]]$BuildNumber,
    [Nullable[int]]$ServicePack,
    [string]$CSDVersion,
    [ValidateScript({ [string]::IsNullOrEmpty($_) -or $_ -in @('Workstation', 'Server', 'DomainController') })][string]$ProductType
  )

  process {
    if (-not $Condition.Type) {
      return ConvertTo-InstallShieldSuiteConditionResult -State Unknown -ConditionType Unknown -Reasons 'The condition object has no element type.'
    }

    $Type = [string]$Condition.Type
    if ($Type -in @('All', 'Any', 'Not', 'When', 'Eligible')) {
      $ChildResults = foreach ($Child in @($Condition.Children)) {
        Resolve-InstallShieldSuiteCondition -Condition $Child -Architecture $Architecture -OSVersion $OSVersion -BuildNumber $BuildNumber -ServicePack $ServicePack -CSDVersion $CSDVersion -ProductType $ProductType
      }
      return Merge-InstallShieldSuiteConditionResult -Type $Type -Result ([object[]]@($ChildResults))
    }

    if ($Type -ne 'Platform') {
      return ConvertTo-InstallShieldSuiteConditionResult -State Unknown -ConditionType $Type -UnknownPredicates $Type -Reasons "The $Type predicate depends on target or run-time state."
    }

    $Checks = [Collections.Generic.List[object]]::new()
    $Attributes = $Condition.Attributes
    if ($Attributes['Architecture']) {
      if (-not $Architecture) {
        $Checks.Add((ConvertTo-InstallShieldSuiteConditionResult -State Unknown -ConditionType Platform -UnknownPredicates 'Platform.Architecture' -Reasons 'No target architecture was supplied.'))
      } else {
        $AcceptedArchitectures = [string[]]@($Attributes['Architecture'] -split '[,;|\s]+' | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() })
        $MatchesArchitecture = $Architecture.ToLowerInvariant() -in $AcceptedArchitectures
        $Checks.Add((ConvertTo-InstallShieldSuiteConditionResult -State ($MatchesArchitecture ? 'True' : 'False') -ConditionType Platform -Reasons "Target architecture '$Architecture' $($MatchesArchitecture ? 'matches' : 'does not match') '$($Attributes['Architecture'])'."))
      }
    }
    if ($Attributes['OSVersion']) {
      if (-not $OSVersion) {
        $Checks.Add((ConvertTo-InstallShieldSuiteConditionResult -State Unknown -ConditionType Platform -UnknownPredicates 'Platform.OSVersion' -Reasons 'No target OS version was supplied.'))
      } else {
        $RangeResult = Test-InstallShieldSuiteRange -Value $OSVersion -Range $Attributes['OSVersion'] -Version
        $State = $null -eq $RangeResult ? 'Unknown' : ($RangeResult ? 'True' : 'False')
        $Unknown = $null -eq $RangeResult ? 'Platform.OSVersion' : @()
        $Checks.Add((ConvertTo-InstallShieldSuiteConditionResult -State $State -ConditionType Platform -UnknownPredicates $Unknown -Reasons "Target OS version '$OSVersion' was compared with '$($Attributes['OSVersion'])'."))
      }
    }
    if ($Attributes['BuildNumber']) {
      if ($null -eq $BuildNumber) {
        $Checks.Add((ConvertTo-InstallShieldSuiteConditionResult -State Unknown -ConditionType Platform -UnknownPredicates 'Platform.BuildNumber' -Reasons 'No target build number was supplied.'))
      } else {
        $MinimumBuild = 0L
        $Parsed = [long]::TryParse($Attributes['BuildNumber'], [ref]$MinimumBuild)
        $State = -not $Parsed ? 'Unknown' : ([long]$BuildNumber -ge $MinimumBuild ? 'True' : 'False')
        $Checks.Add((ConvertTo-InstallShieldSuiteConditionResult -State $State -ConditionType Platform -UnknownPredicates (-not $Parsed ? 'Platform.BuildNumber' : @()) -Reasons "Target build '$BuildNumber' was compared with minimum '$($Attributes['BuildNumber'])'."))
      }
    }
    if ($Attributes['ServicePack']) {
      if ($null -eq $ServicePack) {
        $Checks.Add((ConvertTo-InstallShieldSuiteConditionResult -State Unknown -ConditionType Platform -UnknownPredicates 'Platform.ServicePack' -Reasons 'No target service-pack number was supplied.'))
      } else {
        $RangeResult = Test-InstallShieldSuiteRange -Value ([string]$ServicePack) -Range $Attributes['ServicePack']
        $State = $null -eq $RangeResult ? 'Unknown' : ($RangeResult ? 'True' : 'False')
        $Checks.Add((ConvertTo-InstallShieldSuiteConditionResult -State $State -ConditionType Platform -UnknownPredicates ($null -eq $RangeResult ? 'Platform.ServicePack' : @()) -Reasons "Target service pack '$ServicePack' was compared with '$($Attributes['ServicePack'])'."))
      }
    }
    if ($Attributes['CSDVersion']) {
      if (-not $CSDVersion) {
        $Checks.Add((ConvertTo-InstallShieldSuiteConditionResult -State Unknown -ConditionType Platform -UnknownPredicates 'Platform.CSDVersion' -Reasons 'No target CSD version was supplied.'))
      } else {
        $MatchesCsd = $CSDVersion -ieq $Attributes['CSDVersion']
        $Checks.Add((ConvertTo-InstallShieldSuiteConditionResult -State ($MatchesCsd ? 'True' : 'False') -ConditionType Platform -Reasons "Target CSD version '$CSDVersion' $($MatchesCsd ? 'matches' : 'does not match') '$($Attributes['CSDVersion'])'."))
      }
    }
    if ($Attributes['ProductType']) {
      if (-not $ProductType) {
        $Checks.Add((ConvertTo-InstallShieldSuiteConditionResult -State Unknown -ConditionType Platform -UnknownPredicates 'Platform.ProductType' -Reasons 'No target product type was supplied.'))
      } else {
        $AcceptedProductTypes = [string[]]@($Attributes['ProductType'] -split '[,;|\s]+' | Where-Object { $_ })
        $MatchesProductType = $ProductType -in $AcceptedProductTypes
        $Checks.Add((ConvertTo-InstallShieldSuiteConditionResult -State ($MatchesProductType ? 'True' : 'False') -ConditionType Platform -Reasons "Target product type '$ProductType' $($MatchesProductType ? 'matches' : 'does not match') '$($Attributes['ProductType'])'."))
      }
    }

    if ($Checks.Count -eq 0) {
      return ConvertTo-InstallShieldSuiteConditionResult -State Unknown -ConditionType Platform -UnknownPredicates Platform -Reasons 'The Platform predicate contains no supported static attributes.'
    }
    Merge-InstallShieldSuiteConditionResult -Type All -Result ([object[]]$Checks)
  }
}

function Get-InstallShieldAdvancedUiPackageEligibility {
  <#
  .SYNOPSIS
    Resolve static eligibility for every package in an Advanced UI catalog.
  .DESCRIPTION
    Package architecture, package-level Eligible conditions, and SelectionTree
    install conditions are combined. Detect conditions are intentionally not
    considered: they describe installed state and operation planning, not
    whether a package can run on the target platform.
  .PARAMETER Info
    Result from Get-InstallShieldAdvancedUiInfo.
  .PARAMETER Architecture
    Optional target architecture.
  .PARAMETER OSVersion
    Optional target Windows major/minor version.
  .PARAMETER BuildNumber
    Optional target Windows build number.
  .PARAMETER ServicePack
    Optional target service-pack number.
  .PARAMETER CSDVersion
    Optional target CSD version text.
  .PARAMETER ProductType
    Optional target product type.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][object]$Info,
    [ValidateSet('x86', 'x64', 'arm', 'arm64', 'ia64')][string]$Architecture,
    [string]$OSVersion,
    [Nullable[int]]$BuildNumber,
    [Nullable[int]]$ServicePack,
    [string]$CSDVersion,
    [ValidateScript({ [string]::IsNullOrEmpty($_) -or $_ -in @('Workstation', 'Server', 'DomainController') })][string]$ProductType
  )

  process {
    foreach ($Package in @($Info.Packages)) {
      $Checks = [Collections.Generic.List[object]]::new()
      if ($Architecture -and $Package.Architecture) {
        $MatchesArchitecture = $Architecture -ieq $Package.Architecture
        $Checks.Add((ConvertTo-InstallShieldSuiteConditionResult -State ($MatchesArchitecture ? 'True' : 'False') -ConditionType PackageArchitecture -Reasons "Package architecture '$($Package.Architecture)' $($MatchesArchitecture ? 'matches' : 'does not match') target '$Architecture'."))
      }
      if ($Package.EligibilityCondition) {
        $Checks.Add((Resolve-InstallShieldSuiteCondition -Condition $Package.EligibilityCondition -Architecture $Architecture -OSVersion $OSVersion -BuildNumber $BuildNumber -ServicePack $ServicePack -CSDVersion $CSDVersion -ProductType $ProductType))
      }

      # Multiple selections can install the same parcel. Any applicable
      # selection is sufficient, whereas all independent package checks must pass.
      $InstallSelections = [object[]]@($Info.Selections | Where-Object { $Package.Id -in $_.InstallPackageIds })
      if ($InstallSelections.Count -gt 0) {
        $SelectionResults = foreach ($Selection in $InstallSelections) {
          if ($Selection.Condition) {
            Resolve-InstallShieldSuiteCondition -Condition $Selection.Condition -Architecture $Architecture -OSVersion $OSVersion -BuildNumber $BuildNumber -ServicePack $ServicePack -CSDVersion $CSDVersion -ProductType $ProductType
          } else {
            ConvertTo-InstallShieldSuiteConditionResult -State True -ConditionType Selection -Reasons "Selection '$($Selection.Name)' has no condition."
          }
        }
        $Checks.Add((Merge-InstallShieldSuiteConditionResult -Type Any -Result ([object[]]@($SelectionResults))))
      }

      $Combined = if ($Checks.Count -gt 0) {
        Merge-InstallShieldSuiteConditionResult -Type All -Result ([object[]]$Checks)
      } else {
        ConvertTo-InstallShieldSuiteConditionResult -State True -ConditionType Package -Reasons 'The package has no authored static eligibility restrictions.'
      }
      [pscustomobject][ordered]@{
        PackageId         = $Package.Id
        Type              = $Package.Type
        Architecture      = $Package.Architecture
        State             = $Combined.State
        Reasons           = [string[]]$Combined.Reasons
        UnknownPredicates = [string[]]$Combined.UnknownPredicates
        SelectedBy        = [string[]]@($InstallSelections.Name)
      }
    }
  }
}

function Get-InstallShieldAdvancedUiPackageTargetFile {
  <#
  .SYNOPSIS
    Resolve the exact locally extracted file launched by an Advanced UI parcel.
  .PARAMETER Package
    Package record returned in Get-InstallShieldAdvancedUiInfo.Packages.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][object]$Package)

  $Files = [object[]]@($Package.Files)
  $InstallOperation = $Package.Operations | Where-Object Name -CEQ 'Install' | Select-Object -First 1
  $Target = [string]$InstallOperation.Target
  if ($Target) {
    # Operation.Target normally contains a basename while File.Name can include
    # a GUID staging directory. Compare both normalized relative path and basename.
    $NormalizedTarget = $Target.Replace('/', '\').TrimStart('.\')
    $TargetMatches = [object[]]@($Files | Where-Object {
        $RelativePath = ([string]$_.RelativePath).Replace('/', '\').TrimStart('.\')
        $RelativePath -ceq $NormalizedTarget -or [IO.Path]::GetFileName($RelativePath) -ceq [IO.Path]::GetFileName($NormalizedTarget)
      })
    if ($TargetMatches.Count -eq 1) {
      return [pscustomobject][ordered]@{ File = $TargetMatches[0]; Target = $Target; SelectionMethod = 'OperationTarget'; Warning = $null }
    }
    if ($TargetMatches.Count -gt 1) {
      return [pscustomobject][ordered]@{ File = $null; Target = $Target; SelectionMethod = 'AmbiguousOperationTarget'; Warning = "Operation target '$Target' matches more than one catalog file." }
    }
  }

  $Extensions = switch ($Package.Type) {
    'Msi' { @('.msi') }
    'Msp' { @('.msp') }
    { $_ -in @('Exe', 'IsmMsi', 'IsmIsp', 'InstallScript') } { @('.exe'); break }
    'Appx' { @('.appx', '.msix') }
    'AppxBundle' { @('.appxbundle', '.msixbundle') }
    { $_ -in @('Prq', 'Prerequisite') } { @('.prq'); break }
    default { @() }
  }
  $Candidates = if ($Extensions.Count -gt 0) {
    [object[]]@($Files | Where-Object { [IO.Path]::GetExtension([string]$_.RelativePath) -in $Extensions })
  } else {
    [object[]]@()
  }
  if ($Candidates.Count -eq 1) {
    return [pscustomobject][ordered]@{ File = $Candidates[0]; Target = $Target; SelectionMethod = 'SingleTypedCatalogFile'; Warning = $null }
  }

  $Warning = if ($Target) {
    "Operation target '$Target' does not resolve to one local catalog file."
  } elseif ($Candidates.Count -gt 1) {
    "The parcel contains $($Candidates.Count) format-matching files but no exact install operation target."
  } else {
    'The parcel does not identify one supported nested target file.'
  }
  [pscustomobject][ordered]@{ File = $null; Target = $Target; SelectionMethod = 'Unresolved'; Warning = $Warning }
}

function Get-InstallShieldAdvancedUiNestedPackageInfo {
  <#
  .SYNOPSIS
    Dispatch local Advanced UI parcel targets to their canonical static parsers.
  .DESCRIPTION
    Statically false packages are skipped. True and Unknown packages are parsed
    when their exact target is present beneath the extracted suite. External
    SourceUrl payloads are never downloaded by this function.
  .PARAMETER Info
    Result from Get-InstallShieldAdvancedUiInfo.
  .PARAMETER Architecture
    Optional target architecture used by package eligibility.
  .PARAMETER OSVersion
    Optional target Windows major/minor version used by package eligibility.
  .PARAMETER BuildNumber
    Optional target Windows build number used by package eligibility.
  .PARAMETER ServicePack
    Optional target service-pack number used by package eligibility.
  .PARAMETER CSDVersion
    Optional target CSD version used by package eligibility.
  .PARAMETER ProductType
    Optional target product type used by package eligibility.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][object]$Info,
    [ValidateSet('x86', 'x64', 'arm', 'arm64', 'ia64')][string]$Architecture,
    [string]$OSVersion,
    [Nullable[int]]$BuildNumber,
    [Nullable[int]]$ServicePack,
    [string]$CSDVersion,
    [ValidateScript({ [string]::IsNullOrEmpty($_) -or $_ -in @('Workstation', 'Server', 'DomainController') })][string]$ProductType
  )

  process {
    $Eligibility = [object[]]@(Get-InstallShieldAdvancedUiPackageEligibility -Info $Info -Architecture $Architecture -OSVersion $OSVersion -BuildNumber $BuildNumber -ServicePack $ServicePack -CSDVersion $CSDVersion -ProductType $ProductType)
    foreach ($Package in @($Info.Packages)) {
      $PackageEligibility = $Eligibility | Where-Object PackageId -CEQ $Package.Id | Select-Object -First 1
      $Warnings = [Collections.Generic.List[string]]::new()
      $Parser = $null
      $NestedInfo = $null
      $Success = $false
      $TargetInfo = $null

      if ($PackageEligibility.State -eq 'False') {
        $Warnings.Add('The package is statically ineligible for the supplied target facts and was not parsed.')
      } else {
        $TargetInfo = Get-InstallShieldAdvancedUiPackageTargetFile -Package $Package
        if ($TargetInfo.Warning) { $Warnings.Add($TargetInfo.Warning) }
        $TargetFile = $TargetInfo.File
        if ($TargetFile -and -not $TargetFile.ResolvedPath) {
          $SourceUrl = [string]$TargetFile.SourceUrl
          $Warnings.Add($SourceUrl ? "The exact parcel target is external or was not extracted; it was not downloaded from '$SourceUrl'." : 'The exact parcel target is not present beneath the extracted suite path.')
        } elseif ($TargetFile -and $TargetFile.ResolvedPath) {
          try {
            # Package types select format-specific parsers. Generic EXE and MSP
            # targets use the analyzer so content magic, not the catalog label,
            # determines the nested installer family.
            switch ($Package.Type) {
              'Msi' {
                $Parser = 'Windows Installer'
                $NestedInfo = Get-MsiInstallerInfo -Path $TargetFile.ResolvedPath
              }
              { $_ -in @('Appx', 'AppxBundle') } {
                $Parser = 'MSIX/AppX'
                $NestedInfo = Get-MSIXInfo -Path $TargetFile.ResolvedPath
                break
              }
              { $_ -in @('IsmMsi', 'IsmIsp', 'InstallScript') } {
                $Parser = 'InstallShield'
                $NestedInfo = Get-InstallShieldInfo -Path $TargetFile.ResolvedPath
                break
              }
              { $_ -in @('Prq', 'Prerequisite') } {
                $Parser = 'InstallShield prerequisite'
                $NestedInfo = Get-InstallShieldPrerequisiteInfo -Path $TargetFile.ResolvedPath
                break
              }
              { $_ -in @('Exe', 'Msp') } {
                $Parser = 'WinGet installer analyzer'
                if (-not (Get-Command Get-WinGetInstallerAnalysis -ErrorAction SilentlyContinue)) {
                  throw 'Get-WinGetInstallerAnalysis is not loaded in the current runspace.'
                }
                $NestedInfo = Get-WinGetInstallerAnalysis -Path $TargetFile.ResolvedPath
                break
              }
              default {
                $Warnings.Add("No static nested parser is registered for Advanced UI package type '$($Package.Type)'.")
              }
            }
            $Success = $null -ne $NestedInfo
          } catch {
            $Warnings.Add("$Parser nested analysis failed: $($_.Exception.Message)")
          }
        }
      }

      [pscustomobject][ordered]@{
        PackageId          = $Package.Id
        PackageType        = $Package.Type
        EligibilityState   = $PackageEligibility.State
        EligibilityReasons = [string[]]@($PackageEligibility.Reasons)
        UnknownPredicates  = [string[]]@($PackageEligibility.UnknownPredicates)
        Target             = $TargetInfo ? $TargetInfo.Target : $null
        SourcePath         = ($TargetInfo -and $TargetInfo.File) ? $TargetInfo.File.ResolvedPath : $null
        SourceUrl          = ($TargetInfo -and $TargetInfo.File) ? $TargetInfo.File.SourceUrl : $null
        SelectionMethod    = $TargetInfo ? $TargetInfo.SelectionMethod : $null
        Parser             = $Parser
        Success            = $Success
        Info               = $NestedInfo
        Diagnostics        = @(ConvertTo-InstallerDiagnostic -InputObject @([object[]]$Warnings) -Source 'InstallShieldAdvancedUI' -Kind Incomplete -Areas Metadata)
      }
    }
  }
}

function ConvertFrom-InstallShieldIntegerList {
  <#
  .SYNOPSIS
    Parse a bounded InstallShield comma/semicolon-delimited integer list.
  .PARAMETER Value
    Raw property or XML attribute value containing decimal return codes.
  #>
  [OutputType([pscustomobject])]
  param ([AllowNull()][string]$Value)

  $Values = [Collections.Generic.List[int]]::new()
  $InvalidValues = [Collections.Generic.List[string]]::new()
  foreach ($Part in @($Value -split '[,;]' | ForEach-Object Trim | Where-Object { $_ })) {
    $Code = 0
    if ([int]::TryParse($Part, [Globalization.NumberStyles]::Integer, [Globalization.CultureInfo]::InvariantCulture, [ref]$Code)) {
      $Values.Add($Code)
    } else {
      $InvalidValues.Add($Part)
    }
  }
  [pscustomobject][ordered]@{
    Values        = [int[]]$Values
    InvalidValues = [string[]]$InvalidValues
  }
}

function Join-InstallShieldPrerequisiteEvidence {
  <#
  .SYNOPSIS
    Correlate MSI prerequisite table references with extracted .prq definitions.
  .DESCRIPTION
    Only exact identifiers, descriptions, filenames, or filename stems are
    accepted. Fuzzy matching could attach the wrong download or silent command
    to a similarly named prerequisite and is therefore intentionally omitted.
  .PARAMETER Reference
    ISSetupPrerequisites table rows from Get-MsiInstallerInfo.
  .PARAMETER Definition
    Parsed .prq records from Get-InstallShieldPrerequisiteInfo.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [AllowEmptyCollection()][object[]]$Reference = @(),
    [AllowEmptyCollection()][object[]]$Definition = @()
  )

  $MatchedDefinitionPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($ReferenceItem in @($Reference)) {
    $ReferenceName = [string]$ReferenceItem.Name
    $DefinitionMatches = [object[]]@($Definition | Where-Object {
        $FileName = [IO.Path]::GetFileName([string]$_.Path)
        $FileStem = [IO.Path]::GetFileNameWithoutExtension($FileName)
        $ReferenceName -ieq $_.Id -or $ReferenceName -ieq $_.Description -or $ReferenceName -ieq $FileName -or $ReferenceName -ieq $FileStem
      })
    $Match = $DefinitionMatches.Count -eq 1 ? $DefinitionMatches[0] : $null
    if ($Match) { [void]$MatchedDefinitionPaths.Add([string]$Match.Path) }
    [pscustomobject][ordered]@{
      Reference   = $ReferenceItem
      Definition  = $Match
      MatchMethod = $Match ? 'ExactIdentityOrName' : ($DefinitionMatches.Count -gt 1 ? 'Ambiguous' : 'Unresolved')
      Warning     = if ($DefinitionMatches.Count -gt 1) {
        "Prerequisite reference '$ReferenceName' matches more than one extracted definition."
      } elseif (-not $Match) {
        "Prerequisite reference '$ReferenceName' has no exact extracted definition."
      } else { $null }
    }
  }

  # Preserve definitions that are present on the media but not referenced by
  # the selected MSI. Presence alone does not prove they run for this release.
  foreach ($DefinitionItem in @($Definition)) {
    if ($MatchedDefinitionPaths.Contains([string]$DefinitionItem.Path)) { continue }
    [pscustomobject][ordered]@{
      Reference   = $null
      Definition  = $DefinitionItem
      MatchMethod = 'UnreferencedDefinition'
      Warning     = 'The prerequisite definition is present but is not referenced by the selected MSI.'
    }
  }
}

function Get-InstallShieldElevationInfo {
  <#
  .SYNOPSIS
    Derive a conservative WinGet elevation recommendation from InstallShield metadata.
  .DESCRIPTION
    A requireAdministrator PE manifest is direct evidence. An exactly matched,
    release-selected .prq definition is also sufficient when its Behavior page
    requires administrative privileges. Machine scope and unreferenced .prq
    files are intentionally not treated as elevation evidence.
  .PARAMETER RequestedExecutionLevel
    requestedExecutionLevel read from the outer InstallShield PE manifest.
  .PARAMETER PrerequisiteEvidence
    Exact reference-to-definition correlations produced by
    Join-InstallShieldPrerequisiteEvidence.
  #>
  [OutputType([pscustomobject])]
  param (
    [AllowNull()][string]$RequestedExecutionLevel,
    [AllowEmptyCollection()][object[]]$PrerequisiteEvidence = @()
  )

  $Reasons = [Collections.Generic.List[string]]::new()
  $Warnings = [Collections.Generic.List[object]]::new()
  $AdministrativePrerequisites = [Collections.Generic.List[object]]::new()
  $SeenDefinitionPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

  if ($RequestedExecutionLevel -ieq 'requireAdministrator') {
    $Reasons.Add('The outer PE manifest requests requireAdministrator.')
  }

  foreach ($Evidence in @($PrerequisiteEvidence)) {
    # Only an exact release reference proves that this definition can run.
    # Unreferenced definitions may be builder/media residue from another setup.
    if (-not $Evidence.Reference -or $Evidence.MatchMethod -ne 'ExactIdentityOrName' -or -not $Evidence.Definition) { continue }
    if ($Evidence.Definition.RequiresAdministrativePrivileges -ne $true) { continue }
    $DefinitionPath = [string]$Evidence.Definition.Path
    if (-not $SeenDefinitionPaths.Add($DefinitionPath)) { continue }

    $AdministrativePrerequisites.Add($Evidence.Definition)
    $PrerequisiteName = [string]$Evidence.Definition.Description
    if ([string]::IsNullOrWhiteSpace($PrerequisiteName)) { $PrerequisiteName = [string]$Evidence.Reference.Name }
    $Reasons.Add("The selected prerequisite '$PrerequisiteName' requires administrative privileges.")

    # Elevation can make the prerequisite runnable, but it cannot manufacture
    # an unattended command line that the prerequisite author did not provide.
    if ([string]::IsNullOrWhiteSpace([string]$Evidence.Definition.SilentCommandLine)) {
      $Warnings.Add((New-InstallerDiagnostic -Id 'InstallShield.Prerequisite.SilentCommandMissing' -Source 'InstallShieldAdvancedUI' -Message "Selected prerequisite '$PrerequisiteName' requires administrative privileges but does not define a silent command line; elevation does not prove unattended installation support." -Kind Unsupported -Areas Installability -AffectedFields InstallerSwitches, InstallModes, ElevationRequirement -Evidence ([ordered]@{ Name = $PrerequisiteName; Path = $DefinitionPath })))
    }
  }

  $HasDirectLauncherEvidence = $RequestedExecutionLevel -ieq 'requireAdministrator'
  $HasPrerequisiteEvidence = $AdministrativePrerequisites.Count -gt 0
  [pscustomobject][ordered]@{
    ElevationRequirement                = ($HasDirectLauncherEvidence -or $HasPrerequisiteEvidence) ? 'elevationRequired' : $null
    RequestedExecutionLevel             = [string]::IsNullOrWhiteSpace($RequestedExecutionLevel) ? $null : $RequestedExecutionLevel
    Confidence                          = $HasDirectLauncherEvidence ? 'DirectPEManifest' : ($HasPrerequisiteEvidence ? 'SelectedPrerequisiteDefinition' : 'Unknown')
    SelectedAdministrativePrerequisites = [object[]]$AdministrativePrerequisites
    Reasons                             = [string[]]$Reasons
    Diagnostics                         = @(Merge-InstallerDiagnostics -Diagnostic @(ConvertTo-InstallerDiagnostic -InputObject @([object[]]$Warnings) -Source 'InstallShieldAdvancedUI' -Kind Incomplete -Areas Metadata))
  }
}

function ConvertFrom-InstallShieldPrerequisiteCondition {
  <#
  .SYNOPSIS
    Decode one numeric InstallShield .prq condition into typed evidence.
  .PARAMETER Node
    A condition element from SetupPrereq/conditions.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][Xml.XmlNode]$Node)

  process {
    $Structured = ConvertFrom-InstallShieldSuiteCondition -Node $Node
    $TypeCode = 0
    $ComparisonCode = 0
    $HasType = [int]::TryParse([string]$Structured.Attributes['Type'], [ref]$TypeCode)
    $HasComparison = [int]::TryParse([string]$Structured.Attributes['Comparison'], [ref]$ComparisonCode)
    $PredicateKind = if (-not $HasType) {
      'Unknown'
    } else {
      switch ($TypeCode) {
        1 { 'RegistryKey' }
        2 { 'RegistryValue' }
        4 { 'File' }
        8 { 'FileDate' }
        16 { 'FileVersion' }
        32 { 'RegistryVersion' }
        64 { 'AppPackage' }
        default { 'Unknown' }
      }
    }
    $Comparison = switch ("$TypeCode/$ComparisonCode") {
      '1/1' { 'Exists' }
      '1/2' { 'DoesNotExist' }
      '2/1' { 'Equals' }
      '4/1' { 'Exists' }
      '4/2' { 'DoesNotExist' }
      '8/1' { 'EqualDate' }
      '8/2' { 'EarlierOrMissing' }
      '8/3' { 'Later' }
      '16/1' { 'EqualVersion' }
      '16/2' { 'LessThanOrMissing' }
      '16/3' { 'GreaterThan' }
      '32/1' { 'EqualVersion' }
      '32/2' { 'LessThan' }
      '32/3' { 'GreaterThan' }
      '64/0' { 'MissingOrVersionLess' }
      default { 'Unknown' }
    }
    $Path = [string]$Structured.Attributes['Path']
    $Name = [string]$Structured.Attributes['FileName']
    $Bits = [string]$Structured.Attributes['Bits']
    $QualifiedName = if ([string]::IsNullOrEmpty($Name) -or $Path.EndsWith('\', [StringComparison]::Ordinal)) { "$Path$Name" } else { "$Path\$Name" }
    $EvidenceKey = switch ($PredicateKind) {
      'RegistryKey' { "RegistryKey:$Path|$Bits" }
      { $_ -in @('RegistryValue', 'RegistryVersion') } { "RegistryValue:$QualifiedName|$Bits" }
      { $_ -in @('File', 'FileDate', 'FileVersion') } { "File:$QualifiedName" }
      'AppPackage' { "AppPackage:$Name|$Path" }
      default { "Unknown:$TypeCode/$ComparisonCode" }
    }

    [pscustomobject][ordered]@{
      Type           = $Structured.Type
      Attributes     = $Structured.Attributes
      Value          = $Structured.Value
      Children       = $Structured.Children
      TypeCode       = $HasType ? $TypeCode : $null
      PredicateKind  = $PredicateKind
      ComparisonCode = $HasComparison ? $ComparisonCode : $null
      Comparison     = $Comparison
      EvidenceKey    = $EvidenceKey
      ExpectedValue  = [string]$Structured.Attributes['ReturnValue']
      RegistryView   = switch ($Bits) { '1' { 'Registry32' } '2' { 'Registry64' } default { 'Default32' } }
    }
  }
}

function Get-InstallShieldPrerequisiteEvidenceValue {
  <#
  .SYNOPSIS
    Resolve one case-insensitive prerequisite evidence key without host access.
  .PARAMETER Evidence
    Caller-provided target-state dictionary.
  .PARAMETER Key
    Canonical EvidenceKey emitted by the condition decoder.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][Collections.IDictionary]$Evidence,
    [Parameter(Mandatory)][string]$Key
  )

  $MatchedKey = @($Evidence.Keys | Where-Object { [string]$_ -ieq $Key } | Select-Object -First 1)
  if ($MatchedKey.Count -eq 0) {
    return [pscustomobject]@{ IsKnown = $false; Exists = $null; Value = $null }
  }
  $Item = $Evidence[$MatchedKey[0]]
  if ($Item -is [bool]) {
    return [pscustomobject]@{ IsKnown = $true; Exists = [bool]$Item; Value = $null }
  }
  if ($null -eq $Item) {
    return [pscustomobject]@{ IsKnown = $true; Exists = $false; Value = $null }
  }
  if ($Item -is [Collections.IDictionary]) {
    $ExistsKey = @($Item.Keys | Where-Object { [string]$_ -ieq 'Exists' } | Select-Object -First 1)
    $ValueKey = @($Item.Keys | Where-Object { [string]$_ -in @('Value', 'Version', 'Date') } | Select-Object -First 1)
    return [pscustomobject]@{
      IsKnown = $true
      Exists  = $ExistsKey.Count -eq 0 ? $true : [bool]$Item[$ExistsKey[0]]
      Value   = $ValueKey.Count -eq 0 ? $Item : $Item[$ValueKey[0]]
    }
  }
  $ExistsProperty = $Item.PSObject.Properties['Exists']
  $ValueProperty = @('Value', 'Version', 'Date') | ForEach-Object { $Item.PSObject.Properties[$_] } | Where-Object { $null -ne $_ } | Select-Object -First 1
  [pscustomobject]@{
    IsKnown = $true
    Exists  = $null -eq $ExistsProperty ? $true : [bool]$ExistsProperty.Value
    Value   = $null -eq $ValueProperty ? $Item : $ValueProperty.Value
  }
}

function Compare-InstallShieldPrerequisiteVersion {
  <#
  .SYNOPSIS
    Compare two prerequisite version strings without using host state.
  .PARAMETER Actual
    Version observed in caller-supplied target evidence.
  .PARAMETER Expected
    Version serialized in the .prq condition.
  #>
  [OutputType([Nullable[int]])]
  param ([string]$Actual, [string]$Expected)

  try {
    return ([version]$Actual).CompareTo([version]$Expected)
  } catch {
    return $null
  }
}

function Resolve-InstallShieldPrerequisiteCondition {
  <#
  .SYNOPSIS
    Evaluate one typed .prq install condition against explicit target evidence.
  .DESCRIPTION
    A True result means that this condition asks InstallShield to run the
    prerequisite. Unsupported comparison codes and absent evidence remain
    Unknown instead of being evaluated against the analysis host.
  .PARAMETER Condition
    Result from ConvertFrom-InstallShieldPrerequisiteCondition.
  .PARAMETER Evidence
    Target-state dictionary keyed by Condition.EvidenceKey.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][object]$Condition,
    [Collections.IDictionary]$Evidence = @{}
  )

  process {
    $Observed = Get-InstallShieldPrerequisiteEvidenceValue -Evidence $Evidence -Key ([string]$Condition.EvidenceKey)
    if ($Condition.PredicateKind -eq 'Unknown' -or $Condition.Comparison -eq 'Unknown') {
      return ConvertTo-InstallShieldSuiteConditionResult -State Unknown -ConditionType "Prerequisite.$($Condition.PredicateKind)" -UnknownPredicates $Condition.EvidenceKey -Reasons "InstallShield prerequisite condition type/comparison '$($Condition.TypeCode)/$($Condition.ComparisonCode)' is not structurally supported."
    }
    if (-not $Observed.IsKnown) {
      return ConvertTo-InstallShieldSuiteConditionResult -State Unknown -ConditionType "Prerequisite.$($Condition.PredicateKind)" -UnknownPredicates $Condition.EvidenceKey -Reasons "No target-state evidence was supplied for '$($Condition.EvidenceKey)'."
    }

    $ConditionMatches = switch ($Condition.Comparison) {
      'Exists' { [bool]$Observed.Exists }
      'DoesNotExist' { -not [bool]$Observed.Exists }
      'Equals' { [bool]$Observed.Exists -and [string]$Observed.Value -ceq [string]$Condition.ExpectedValue }
      'EqualDate' {
        if (-not $Observed.Exists) { $false } else {
          try { [datetime]$Observed.Value -eq [datetime]$Condition.ExpectedValue } catch { $null }
        }
      }
      'EarlierOrMissing' {
        if (-not $Observed.Exists) { $true } else {
          try { [datetime]$Observed.Value -le [datetime]$Condition.ExpectedValue } catch { $null }
        }
      }
      'Later' {
        if (-not $Observed.Exists) { $false } else {
          try { [datetime]$Observed.Value -gt [datetime]$Condition.ExpectedValue } catch { $null }
        }
      }
      'EqualVersion' {
        if (-not $Observed.Exists) { $false } else {
          $Comparison = Compare-InstallShieldPrerequisiteVersion -Actual ([string]$Observed.Value) -Expected ([string]$Condition.ExpectedValue)
          $null -eq $Comparison ? $null : $Comparison -eq 0
        }
      }
      'LessThan' {
        if (-not $Observed.Exists) { $false } else {
          $Comparison = Compare-InstallShieldPrerequisiteVersion -Actual ([string]$Observed.Value) -Expected ([string]$Condition.ExpectedValue)
          $null -eq $Comparison ? $null : $Comparison -lt 0
        }
      }
      'LessThanOrMissing' {
        if (-not $Observed.Exists) { $true } else {
          $Comparison = Compare-InstallShieldPrerequisiteVersion -Actual ([string]$Observed.Value) -Expected ([string]$Condition.ExpectedValue)
          $null -eq $Comparison ? $null : $Comparison -lt 0
        }
      }
      'GreaterThan' {
        if (-not $Observed.Exists) { $false } else {
          $Comparison = Compare-InstallShieldPrerequisiteVersion -Actual ([string]$Observed.Value) -Expected ([string]$Condition.ExpectedValue)
          $null -eq $Comparison ? $null : $Comparison -gt 0
        }
      }
      'MissingOrVersionLess' {
        if (-not $Observed.Exists) { $true } else {
          $Comparison = Compare-InstallShieldPrerequisiteVersion -Actual ([string]$Observed.Value) -Expected ([string]$Condition.ExpectedValue)
          $null -eq $Comparison ? $null : $Comparison -lt 0
        }
      }
      default { $null }
    }
    if ($null -eq $ConditionMatches) {
      return ConvertTo-InstallShieldSuiteConditionResult -State Unknown -ConditionType "Prerequisite.$($Condition.PredicateKind)" -UnknownPredicates $Condition.EvidenceKey -Reasons "The supplied value could not be compared using '$($Condition.Comparison)'."
    }
    ConvertTo-InstallShieldSuiteConditionResult -State ($ConditionMatches ? 'True' : 'False') -ConditionType "Prerequisite.$($Condition.PredicateKind)" -Reasons "Target evidence '$($Condition.EvidenceKey)' $($ConditionMatches ? 'meets' : 'does not meet') the '$($Condition.Comparison)' install condition."
  }
}

function Resolve-InstallShieldPrerequisiteOperatingSystemCondition {
  <#
  .SYNOPSIS
    Evaluate one .prq operating-system condition from caller-supplied facts.
  .PARAMETER Condition
    Structured operatingsystemcondition XML evidence.
  .PARAMETER Architecture
    Optional target architecture.
  .PARAMETER OSVersion
    Optional target Windows major/minor version.
  .PARAMETER BuildNumber
    Optional target build number.
  .PARAMETER ServicePack
    Optional target service-pack major version.
  .PARAMETER ProductType
    Optional target Windows product type.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][object]$Condition,
    [ValidateSet('x86', 'x64', 'arm', 'arm64', 'ia64')][string]$Architecture,
    [string]$OSVersion,
    [Nullable[int]]$BuildNumber,
    [Nullable[int]]$ServicePack,
    [ValidateScript({ [string]::IsNullOrEmpty($_) -or $_ -in @('Workstation', 'Server', 'DomainController') })][string]$ProductType
  )

  process {
    $Attributes = $Condition.Attributes
    $Checks = [Collections.Generic.List[object]]::new()
    if ($Attributes['PlatformId'] -and [string]$Attributes['PlatformId'] -ne '2') {
      $Checks.Add((ConvertTo-InstallShieldSuiteConditionResult -State False -ConditionType PrerequisiteOS -Reasons "PlatformId '$($Attributes['PlatformId'])' is not Windows NT (2)."))
    }
    if ($Attributes['MajorVersion'] -or $Attributes['MinorVersion']) {
      if (-not $OSVersion) {
        $Checks.Add((ConvertTo-InstallShieldSuiteConditionResult -State Unknown -ConditionType PrerequisiteOS -UnknownPredicates OSVersion -Reasons 'No target OS version was supplied.'))
      } else {
        $ExpectedVersion = "$($Attributes['MajorVersion']).$($Attributes['MinorVersion'])"
        $ConditionMatches = [version]$OSVersion -eq [version]$ExpectedVersion
        $Checks.Add((ConvertTo-InstallShieldSuiteConditionResult -State ($ConditionMatches ? 'True' : 'False') -ConditionType PrerequisiteOS -Reasons "Target OS version '$OSVersion' was compared with '$ExpectedVersion'."))
      }
    }
    if ($Attributes['BuildNumber']) {
      if ($null -eq $BuildNumber) {
        $Checks.Add((ConvertTo-InstallShieldSuiteConditionResult -State Unknown -ConditionType PrerequisiteOS -UnknownPredicates BuildNumber -Reasons 'No target build number was supplied.'))
      } else {
        $Minimum = [int]$Attributes['BuildNumber']
        $ConditionMatches = $BuildNumber -ge $Minimum
        $Checks.Add((ConvertTo-InstallShieldSuiteConditionResult -State ($ConditionMatches ? 'True' : 'False') -ConditionType PrerequisiteOS -Reasons "Target build '$BuildNumber' was compared with minimum '$Minimum'."))
      }
    }
    if ($Attributes['ServicePackMajorMin'] -or $Attributes['ServicePackMajorMax']) {
      if ($null -eq $ServicePack) {
        $Checks.Add((ConvertTo-InstallShieldSuiteConditionResult -State Unknown -ConditionType PrerequisiteOS -UnknownPredicates ServicePack -Reasons 'No target service-pack number was supplied.'))
      } else {
        $Minimum = [string]::IsNullOrWhiteSpace([string]$Attributes['ServicePackMajorMin']) ? 0 : [int]$Attributes['ServicePackMajorMin']
        $Maximum = [string]::IsNullOrWhiteSpace([string]$Attributes['ServicePackMajorMax']) ? [int]::MaxValue : [int]$Attributes['ServicePackMajorMax']
        $ConditionMatches = $ServicePack -ge $Minimum -and $ServicePack -le $Maximum
        $Checks.Add((ConvertTo-InstallShieldSuiteConditionResult -State ($ConditionMatches ? 'True' : 'False') -ConditionType PrerequisiteOS -Reasons "Target service pack '$ServicePack' was compared with '$Minimum-$Maximum'."))
      }
    }
    if ($Attributes['ProductType']) {
      if (-not $ProductType) {
        $Checks.Add((ConvertTo-InstallShieldSuiteConditionResult -State Unknown -ConditionType PrerequisiteOS -UnknownPredicates ProductType -Reasons 'No target product type was supplied.'))
      } else {
        $ProductTypeCode = @{ Workstation = '1'; DomainController = '2'; Server = '3' }[$ProductType]
        $ConditionMatches = $ProductTypeCode -in @([string]$Attributes['ProductType'] -split '\|')
        $Checks.Add((ConvertTo-InstallShieldSuiteConditionResult -State ($ConditionMatches ? 'True' : 'False') -ConditionType PrerequisiteOS -Reasons "Target product type '$ProductType' was compared with '$($Attributes['ProductType'])'."))
      }
    }
    if ($Attributes['Bits']) {
      if (-not $Architecture) {
        $Checks.Add((ConvertTo-InstallShieldSuiteConditionResult -State Unknown -ConditionType PrerequisiteOS -UnknownPredicates Architecture -Reasons 'No target architecture was supplied.'))
      } else {
        $Bits = [int]$Attributes['Bits']
        $ArchitectureMask = switch ($Architecture) { 'x86' { 1 } 'x64' { 2 -bor 4 } 'ia64' { 2 -bor 8 } 'arm' { 16 } 'arm64' { 2 -bor 32 } }
        $ConditionMatches = ($Bits -band $ArchitectureMask) -ne 0
        $Checks.Add((ConvertTo-InstallShieldSuiteConditionResult -State ($ConditionMatches ? 'True' : 'False') -ConditionType PrerequisiteOS -Reasons "Target architecture '$Architecture' was compared with prerequisite Bits '$Bits'."))
      }
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$Attributes['CSDVersion'])) {
      $Checks.Add((ConvertTo-InstallShieldSuiteConditionResult -State Unknown -ConditionType PrerequisiteOS -UnknownPredicates CSDVersion -Reasons 'CSDVersion ordering is locale-sensitive and requires VM evidence.'))
    }
    if ($Checks.Count -eq 0) {
      return ConvertTo-InstallShieldSuiteConditionResult -State True -ConditionType PrerequisiteOS -Reasons 'The operating-system condition contains no restrictions.'
    }
    Merge-InstallShieldSuiteConditionResult -Type All -Result ([object[]]$Checks)
  }
}

function Get-InstallShieldPrerequisiteInfo {
  <#
  .SYNOPSIS
    Parse one InstallShield setup-prerequisite definition.
  .DESCRIPTION
    A .prq XML file defines prerequisite detection conditions, supported OS
    conditions, payload URLs/checksums, invocation arguments, and reboot codes.
    Parsing the definition does not prove that a particular release embeds or
    selects it; correlate the Id/name with MSI or suite package evidence.
  .PARAMETER Path
    Path to an extracted or official InstallShield .prq XML definition.
  .PARAMETER ConditionEvidence
    Target-state evidence keyed by the EvidenceKey returned for each condition.
    Boolean values represent existence; scalar values represent an existing
    registry, file-version, or package-version value. The host is never read.
  .PARAMETER Architecture
    Optional target architecture used to evaluate operating-system conditions.
  .PARAMETER OSVersion
    Optional target Windows major/minor version.
  .PARAMETER BuildNumber
    Optional target Windows build number.
  .PARAMETER ServicePack
    Optional target service-pack major version.
  .PARAMETER ProductType
    Optional target Windows product type.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [Collections.IDictionary]$ConditionEvidence = @{},
    [ValidateSet('x86', 'x64', 'arm', 'arm64', 'ia64')][string]$Architecture,
    [string]$OSVersion,
    [Nullable[int]]$BuildNumber,
    [Nullable[int]]$ServicePack,
    [ValidateScript({ [string]::IsNullOrEmpty($_) -or $_ -in @('Workstation', 'Server', 'DomainController') })][string]$ProductType
  )

  process {
    $PrerequisitePath = (Get-Item -LiteralPath $Path -Force).FullName
    [xml]$Xml = Get-Content -LiteralPath $PrerequisitePath -Raw
    $Root = $Xml.DocumentElement
    if ($Root.LocalName -ne 'SetupPrereq') { throw "'$PrerequisitePath' is not an InstallShield setup-prerequisite definition." }

    $PropertiesNode = $Root.SelectSingleNode('./properties')
    $ExecuteNode = $Root.SelectSingleNode('./execute')
    $BehaviorNode = $Root.SelectSingleNode('./behavior')
    $Files = foreach ($FileNode in @($Root.SelectNodes('./files/file'))) {
      $SizeParts = @($FileNode.GetAttribute('FileSize') -split ',')
      $Size = 0L
      if ($SizeParts.Count -and -not [long]::TryParse($SizeParts[-1], [ref]$Size)) { $Size = 0 }
      [pscustomobject][ordered]@{
        LocalFile = $FileNode.GetAttribute('LocalFile')
        Url       = $FileNode.GetAttribute('URL')
        Checksum  = $FileNode.GetAttribute('CheckSum')
        Size      = $Size
      }
    }
    $DetectionConditions = foreach ($Node in @($Root.SelectNodes('./conditions/condition'))) {
      ConvertFrom-InstallShieldPrerequisiteCondition -Node $Node
    }
    $OperatingSystemConditions = foreach ($Node in @($Root.SelectNodes('./operatingsystemconditions/operatingsystemcondition'))) {
      ConvertFrom-InstallShieldSuiteCondition -Node $Node
    }
    $RebootCodeInfo = ConvertFrom-InstallShieldIntegerList -Value ($ExecuteNode ? $ExecuteNode.GetAttribute('returncodetoreboot') : $null)
    # The prerequisite editor writes Lua="1" only when "The prerequisite
    # requires administrative privileges" is cleared. The default checked
    # state is represented by omitting Lua from the behavior element.
    $LimitedUserCompatible = if ($BehaviorNode) { $BehaviorNode.GetAttribute('Lua') -eq '1' } else { $null }
    $RequiresAdministrativePrivileges = if ($null -eq $LimitedUserCompatible) { $null } else { -not $LimitedUserCompatible }
    $Dependencies = foreach ($DependencyNode in @($Root.SelectNodes('./dependencies/dependency'))) {
      $DependencyFile = $DependencyNode.GetAttribute('File')
      if (-not [string]::IsNullOrWhiteSpace($DependencyFile)) { $DependencyFile }
    }
    $DetectionConditionAnalyses = foreach ($Condition in @($DetectionConditions)) {
      Resolve-InstallShieldPrerequisiteCondition -Condition $Condition -Evidence $ConditionEvidence
    }
    $OperatingSystemParameters = @{}
    if ($Architecture) { $OperatingSystemParameters.Architecture = $Architecture }
    if ($OSVersion) { $OperatingSystemParameters.OSVersion = $OSVersion }
    if ($null -ne $BuildNumber) { $OperatingSystemParameters.BuildNumber = $BuildNumber }
    if ($null -ne $ServicePack) { $OperatingSystemParameters.ServicePack = $ServicePack }
    if ($ProductType) { $OperatingSystemParameters.ProductType = $ProductType }
    $OperatingSystemConditionAnalyses = foreach ($Condition in @($OperatingSystemConditions)) {
      Resolve-InstallShieldPrerequisiteOperatingSystemCondition -Condition $Condition @OperatingSystemParameters
    }
    # InstallShield runs a prerequisite when every normal condition and any
    # authored OS condition are true. Empty groups impose no restriction.
    $DetectionSet = if (@($DetectionConditionAnalyses).Count) {
      Merge-InstallShieldSuiteConditionResult -Type All -Result ([object[]]@($DetectionConditionAnalyses))
    } else {
      ConvertTo-InstallShieldSuiteConditionResult -State True -ConditionType PrerequisiteConditions -Reasons 'The prerequisite has no normal conditions and therefore always passes this condition group.'
    }
    $OperatingSystemSet = if (@($OperatingSystemConditionAnalyses).Count) {
      Merge-InstallShieldSuiteConditionResult -Type Any -Result ([object[]]@($OperatingSystemConditionAnalyses))
    } else {
      ConvertTo-InstallShieldSuiteConditionResult -State True -ConditionType OperatingSystemConditions -Reasons 'The prerequisite has no operating-system restrictions.'
    }
    $InstallationConditionAnalysis = Merge-InstallShieldSuiteConditionResult -Type All -Result ([object[]]@($DetectionSet, $OperatingSystemSet))

    [pscustomobject][ordered]@{
      Path                             = $PrerequisitePath
      Id                               = $PropertiesNode ? $PropertiesNode.GetAttribute('Id') : $null
      Description                      = $PropertiesNode ? $PropertiesNode.GetAttribute('Description') : $null
      AlternateDefinitionUrl           = $PropertiesNode ? $PropertiesNode.GetAttribute('AltPrqURL') : $null
      Files                            = [object[]]@($Files)
      DetectionConditions              = [object[]]@($DetectionConditions)
      OperatingSystemConditions        = [object[]]@($OperatingSystemConditions)
      DetectionConditionAnalyses       = [object[]]@($DetectionConditionAnalyses)
      OperatingSystemConditionAnalyses = [object[]]@($OperatingSystemConditionAnalyses)
      InstallationConditionAnalysis    = $InstallationConditionAnalysis
      ShouldInstallState               = $InstallationConditionAnalysis.State
      Executable                       = $ExecuteNode ? $ExecuteNode.GetAttribute('file') : $null
      CommandLine                      = $ExecuteNode ? $ExecuteNode.GetAttribute('cmdline') : $null
      SilentCommandLine                = $ExecuteNode ? $ExecuteNode.GetAttribute('cmdlinesilent') : $null
      HasSilentCommandLine             = $ExecuteNode -and -not [string]::IsNullOrWhiteSpace($ExecuteNode.GetAttribute('cmdlinesilent'))
      ReturnCodesToReboot              = [int[]]$RebootCodeInfo.Values
      InvalidReturnCodesToReboot       = [string[]]$RebootCodeInfo.InvalidValues
      RebootBehavior                   = $BehaviorNode ? $BehaviorNode.GetAttribute('Reboot') : $null
      Hidden                           = $BehaviorNode ? $BehaviorNode.GetAttribute('Hidden') -eq '1' : $null
      LimitedUserCompatible            = $LimitedUserCompatible
      RequiresAdministrativePrivileges = $RequiresAdministrativePrivileges
      Dependencies                     = [string[]]@($Dependencies)
    }
  }
}

function Get-InstallShieldAdvancedUiInfo {
  <#
  .SYNOPSIS
    Parse an extracted InstallShield Advanced UI or Suite/Advanced UI catalog.
  .DESCRIPTION
    Setup.xml is authoritative for the outer suite ARP identity and for the
    ordered nested-package execution catalog. Nested MSI ProductCodes do not
    replace the SuiteId when the suite itself owns the visible ARP entry.
  .PARAMETER Path
    Path to the extracted Setup.xml file.
  .PARAMETER ExtractedPath
    Optional root used to resolve catalog file names to extracted files.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$ExtractedPath
  )

  process {
    $SetupXmlPath = (Get-Item -LiteralPath $Path -Force).FullName
    [xml]$Xml = Get-Content -LiteralPath $SetupXmlPath -Raw
    $Root = $Xml.DocumentElement
    # Early Suite/Advanced UI releases encoded a point release in the XML
    # namespace (for example, 2012.2). Preserve that exact token while using
    # its leading year for release-catalog correlation.
    $NamespaceMatch = [regex]::Match($Root.NamespaceURI, '^installshield/(?<Release>\d{4}(?:\.\d+)?)/bootstrap$')
    if ($Root.LocalName -ne 'Setup' -or -not $NamespaceMatch.Success) {
      throw 'Setup.xml is not an InstallShield Advanced UI bootstrap catalog'
    }
    $ReleaseVersion = $NamespaceMatch.Groups['Release'].Value
    $ReleaseYear = [int]$ReleaseVersion.Substring(0, 4)

    $LanguageSelection = $Root.SelectSingleNode("./*[local-name()='LanguageSelection']")
    $DefaultLanguage = if ($LanguageSelection) { $LanguageSelection.GetAttribute('Default') } else { $null }
    $ArpInfo = $Root.SelectSingleNode("./*[local-name()='ARPInfo']")
    $SuiteId = $Root.GetAttribute('SuiteId')
    $ReadArpValue = {
      param([string]$Name)
      $Node = if ($ArpInfo) { $ArpInfo.SelectSingleNode("./*[local-name()='$Name']") } else { $null }
      if (-not $Node) { return $null }
      Resolve-InstallShieldSuiteString -Xml $Xml -Value $Node.InnerText.Trim() -Language $DefaultLanguage
    }

    # SelectionTree is the source-backed relationship between user-visible
    # features and package IDs. A disabled selection control is preserved as
    # authored evidence, but is not interpreted as proof that every parcel runs
    # because the attached condition can still reject the selection.
    $Selections = [Collections.Generic.List[object]]::new()
    foreach ($SelectionNode in @($Root.SelectNodes("./*[local-name()='SelectionTree']/*[local-name()='Selection']"))) {
      $WhenNode = $SelectionNode.SelectSingleNode("./*[local-name()='When']")
      $Selections.Add([pscustomobject][ordered]@{
          Name                 = $SelectionNode.GetAttribute('Name')
          DisplayName          = Resolve-InstallShieldSuiteString -Xml $Xml -Value $SelectionNode.GetAttribute('DisplayName') -Language $DefaultLanguage
          AllowSelectionChange = $SelectionNode.GetAttribute('AllowSelectionChange')
          InstallPackageIds    = [string[]]@($SelectionNode.GetAttribute('Install') -split '\s+' | Where-Object { $_ })
          RemovePackageIds     = [string[]]@($SelectionNode.GetAttribute('Remove') -split '\s+' | Where-Object { $_ })
          Condition            = $WhenNode ? (ConvertFrom-InstallShieldSuiteCondition -Node $WhenNode) : $null
        })
    }

    $Modes = foreach ($ModeNode in @($Root.SelectNodes("./*[local-name()='Mode']/*"))) {
      $WhenNode = $ModeNode.SelectSingleNode("./*[local-name()='When']")
      [pscustomobject][ordered]@{
        Name      = $ModeNode.LocalName
        Condition = $WhenNode ? (ConvertFrom-InstallShieldSuiteCondition -Node $WhenNode) : $null
      }
    }

    $Actions = foreach ($ActionNode in @($Root.SelectNodes("./*[local-name()='Actions']/*"))) {
      $Attributes = [ordered]@{}
      foreach ($Attribute in @($ActionNode.Attributes)) { $Attributes[$Attribute.Name] = $Attribute.Value }
      [pscustomobject][ordered]@{ Type = $ActionNode.LocalName; Id = $ActionNode.GetAttribute('Id'); Attributes = $Attributes }
    }
    $Events = foreach ($EventNode in @($Root.SelectNodes("./*[local-name()='Events']/*"))) {
      foreach ($ActionNode in @($EventNode.SelectNodes("./*[local-name()='Action']"))) {
        $WhenNode = $ActionNode.SelectSingleNode("./*[local-name()='When']")
        [pscustomobject][ordered]@{
          Event     = $EventNode.LocalName
          ActionId  = $ActionNode.GetAttribute('Id')
          Condition = $WhenNode ? (ConvertFrom-InstallShieldSuiteCondition -Node $WhenNode) : $null
        }
      }
    }
    $AbortConditions = foreach ($MessageNode in @($Root.SelectNodes("./*[local-name()='AbortConditions']/*[local-name()='Message']"))) {
      $WhenNode = $MessageNode.SelectSingleNode("./*[local-name()='When']")
      [pscustomobject][ordered]@{
        MessageToken = $MessageNode.GetAttribute('Text')
        Message      = Resolve-InstallShieldSuiteString -Xml $Xml -Value $MessageNode.GetAttribute('Text') -Language $DefaultLanguage
        Condition    = $WhenNode ? (ConvertFrom-InstallShieldSuiteCondition -Node $WhenNode) : $null
      }
    }
    $Transactions = foreach ($TransactionNode in @($Root.SelectNodes("./*[local-name()='Transactions']/* | ./*[local-name()='Parcels']/*[local-name()='Transaction']"))) {
      $Attributes = [ordered]@{}
      foreach ($Attribute in @($TransactionNode.Attributes)) { $Attributes[$Attribute.Name] = $Attribute.Value }
      $WhenNode = $TransactionNode.SelectSingleNode("./*[local-name()='When']")
      [pscustomobject][ordered]@{
        Type       = $TransactionNode.LocalName
        Id         = $TransactionNode.GetAttribute('Id')
        Attributes = $Attributes
        ParcelIds  = [string[]]@($TransactionNode.SelectNodes(".//*[local-name()='ParcelRef']") | ForEach-Object { $_.GetAttribute('Id') } | Where-Object { $_ })
        Condition  = $WhenNode ? (ConvertFrom-InstallShieldSuiteCondition -Node $WhenNode) : $null
      }
    }
    $WindowsFeatures = foreach ($DefinitionNode in @($Root.SelectNodes("./*[local-name()='WindowsFeaturesDefinitions']/*"))) {
      $Mappings = [ordered]@{}
      foreach ($MappingNode in @($DefinitionNode.ChildNodes | Where-Object NodeType -EQ ([Xml.XmlNodeType]::Element))) {
        $Mappings[$MappingNode.LocalName] = [string[]]@($MappingNode.InnerText -split ';' | Where-Object { $_ })
      }
      [pscustomobject][ordered]@{ Name = $DefinitionNode.LocalName; PlatformMappings = $Mappings }
    }

    # Record the exact package target and every operation-specific command line.
    # The physical file can live beneath a GUID folder while Target contains only
    # the basename that the suite launches after staging the parcel.
    $Packages = [Collections.Generic.List[object]]::new()
    foreach ($PackageNode in $Root.SelectNodes("./*[local-name()='Parcels']/*")) {
      # Transactions are ordered catalog entries, but are not installer
      # payloads. They are projected separately so callers do not try to map a
      # transaction boundary to a WinGet NestedInstallerType.
      if ($PackageNode.LocalName -eq 'Transaction') { continue }
      $UiProperties = $PackageNode.SelectSingleNode("./*[local-name()='UIProperties']")
      $PackageIdNode = if ($UiProperties) { $UiProperties.SelectSingleNode("./*[local-name()='Id']") } else { $null }
      $DisplayNameNode = if ($UiProperties) { $UiProperties.SelectSingleNode("./*[local-name()='DisplayName']") } else { $null }
      $PackageId = if ($PackageIdNode) { $PackageIdNode.InnerText.Trim() } else { $null }
      $DisplayNameToken = if ($DisplayNameNode) { $DisplayNameNode.InnerText.Trim() } else { $null }
      $Files = [Collections.Generic.List[object]]::new()
      foreach ($FileNode in $PackageNode.SelectNodes("./*[local-name()='Package']/*[local-name()='Folder']/*[local-name()='File']")) {
        $FolderNode = $FileNode.ParentNode
        $RelativePath = $FileNode.GetAttribute('Name')
        $ResolvedPath = $null
        if ($ExtractedPath -and $RelativePath) {
          $Candidate = Resolve-SafeExtractionPath -DestinationPath $ExtractedPath -RelativePath $RelativePath
          if (Test-Path -LiteralPath $Candidate -PathType Leaf) { $ResolvedPath = $Candidate }
        }
        $Files.Add([pscustomobject][ordered]@{
            RelativePath = $RelativePath
            ResolvedPath = $ResolvedPath
            SourceUrl    = $FolderNode.GetAttribute('Url')
            Stream       = $FolderNode.GetAttribute('Stream')
            Size         = $FileNode.GetAttribute('Size')
            MD5          = $FileNode.GetAttribute('MD5')
          })
      }

      $Operations = [Collections.Generic.List[object]]::new()
      foreach ($OperationNode in $PackageNode.SelectNodes("./*[local-name()='Operation']")) {
        $OperationProperties = [ordered]@{}
        foreach ($PropertyNode in $OperationNode.SelectNodes("./*[local-name()='Property']")) {
          $OperationProperties[$PropertyNode.GetAttribute('Name')] = $PropertyNode.InnerText.Trim()
        }
        $CommandLineNode = $OperationNode.SelectSingleNode("./*[local-name()='CommandLine']")
        $SilentNode = $OperationNode.SelectSingleNode("./*[local-name()='Silent']")
        $RebootCodeInfo = ConvertFrom-InstallShieldIntegerList -Value $OperationProperties['RebootCodes']
        $Operations.Add([pscustomobject][ordered]@{
            Name               = $OperationNode.GetAttribute('Name')
            Target             = $OperationNode.GetAttribute('Target')
            CommandLine        = $CommandLineNode ? $CommandLineNode.InnerText.Trim() : $null
            Silent             = $SilentNode ? $SilentNode.InnerText.Trim() : $null
            ExitBehavior       = $OperationProperties['ExitBehavior']
            RebootRequest      = $OperationProperties['RebootRequest']
            RebootCodes        = [int[]]$RebootCodeInfo.Values
            InvalidRebootCodes = [string[]]$RebootCodeInfo.InvalidValues
            Properties         = $OperationProperties
          })
      }
      $PackageProperties = [ordered]@{}
      foreach ($PropertyNode in $PackageNode.SelectNodes("./*[local-name()='Property']")) {
        $PackageProperties[$PropertyNode.GetAttribute('Name')] = $PropertyNode.InnerText.Trim()
      }
      $DetectionNode = $PackageNode.SelectSingleNode("./*[local-name()='Detect']")
      $EligibilityNode = $PackageNode.SelectSingleNode("./*[local-name()='Eligible']")
      $Platform = $PackageNode.GetAttribute('Platform')
      $Architecture = switch -Regex ($Platform) {
        '^(?i:x64|amd64)$' { 'x64'; break }
        '^(?i:x86|intel)$' { 'x86'; break }
        '^(?i:arm64)$' { 'arm64'; break }
        default { $null }
      }
      $ManifestInstallerType = switch ($PackageNode.LocalName) {
        'Msi' { 'msi' }
        'Exe' { 'exe' }
        'Appx' { 'appx' }
        'AppxBundle' { 'appx' }
        default { $null }
      }
      $PackageFamily = switch ($PackageNode.LocalName) {
        'Msi' { 'Windows Installer Package' }
        'Msp' { 'Windows Installer Patch' }
        'Exe' { 'Executable Package' }
        'IsmMsi' { 'InstallShield Basic MSI Project' }
        'IsmIsp' { 'InstallShield InstallScript Project' }
        'InstallScript' { 'InstallShield InstallScript Package' }
        'Appx' { 'AppX Package' }
        'AppxBundle' { 'AppX Bundle' }
        'WebDeploy' { 'Web Deploy Package' }
        'WinGet' { 'Windows Package Manager Package' }
        { $_ -in @('Prq', 'Prerequisite') } { 'InstallShield Prerequisite'; break }
        default { 'Unknown Suite Package' }
      }
      $Packages.Add([pscustomobject][ordered]@{
          Id                      = $PackageId
          Type                    = $PackageNode.LocalName
          PackageFamily           = $PackageFamily
          DisplayName             = Resolve-InstallShieldSuiteString -Xml $Xml -Value $DisplayNameToken -Language $DefaultLanguage
          ProductCode             = $PackageNode.GetAttribute('ProductCode')
          ProductVersion          = $PackageNode.GetAttribute('ProductVersion')
          PackageCode             = $PackageNode.GetAttribute('PackageCode')
          Platform                = $Platform
          Architecture            = $Architecture
          ManifestInstallerType   = $ManifestInstallerType
          Elevation               = $PackageProperties['Elevation']
          UpgradeType             = $PackageProperties['UpgradeType']
          TransactionMode         = $PackageProperties['TransactionMode']
          Properties              = $PackageProperties
          Files                   = [object[]]$Files
          Operations              = [object[]]$Operations
          DetectionConditionXml   = $DetectionNode ? $DetectionNode.OuterXml : $null
          DetectionCondition      = $DetectionNode ? (ConvertFrom-InstallShieldSuiteCondition -Node $DetectionNode) : $null
          EligibilityConditionXml = $EligibilityNode ? $EligibilityNode.OuterXml : $null
          EligibilityCondition    = $EligibilityNode ? (ConvertFrom-InstallShieldSuiteCondition -Node $EligibilityNode) : $null
          Selections              = [string[]]@($Selections | Where-Object { $PackageId -in $_.InstallPackageIds -or $PackageId -in $_.RemovePackageIds } | ForEach-Object Name)
          # Suite authors can place ARPSYSTEMCOMPONENT in either the ordinary
          # or silent operation arguments. Both routes install the same nested
          # MSI and therefore provide evidence that the suite owns visible ARP.
          HidesNestedArp          = (@($Operations | ForEach-Object { $_.CommandLine; $_.Silent }) -match '(?i)(?:^|\s)ARPSYSTEMCOMPONENT\s*=\s*1(?:\s|$)').Count -gt 0
        })
    }

    # Preserve the physical launch order across both packages and transaction
    # boundaries. Package/transaction detail remains in the focused arrays.
    $CatalogOrder = [Collections.Generic.List[object]]::new()
    $CatalogIndex = 0
    foreach ($CatalogNode in @($Root.SelectNodes("./*[local-name()='Parcels']/*"))) {
      $CatalogIdNode = $CatalogNode.SelectSingleNode("./*[local-name()='UIProperties']/*[local-name()='Id']")
      if (-not $CatalogIdNode) { $CatalogIdNode = $CatalogNode.SelectSingleNode("./*[local-name()='Id']") }
      $CatalogOrder.Add([pscustomobject][ordered]@{
          Order = $CatalogIndex++
          Kind  = $CatalogNode.LocalName -eq 'Transaction' ? 'Transaction' : 'Package'
          Type  = $CatalogNode.LocalName
          Id    = $CatalogIdNode ? $CatalogIdNode.InnerText.Trim() : $CatalogNode.GetAttribute('Id')
        })
    }

    # A suite can author its own install directory and use that value when
    # composing nested package command lines.
    $InstallDirectoryNode = $Root.SelectSingleNode("./*[local-name()='SetProperty' and @Name='INSTALLDIR']")
    $InstallDirectoryExpression = if ($InstallDirectoryNode) { $InstallDirectoryNode.GetAttribute('Value') } else { $null }
    $DefaultInstallLocation = if ($InstallDirectoryExpression) {
      $InstallDirectoryExpression.Replace('[ProgramFiles64Folder]', '%ProgramFiles%\').Replace('[ProgramFilesFolder]', '%ProgramFiles(x86)%\')
    } else {
      $null
    }

    # The mode/downgrade checks reveal the exact hive used by the suite ARP key.
    $SuiteRegistryChecks = @($Root.SelectNodes(".//*[local-name()='RegistryValue']") | Where-Object { $_.GetAttribute('Key') -match [regex]::Escape("\Uninstall\$SuiteId") })
    $SuiteRegistryKeys = @($SuiteRegistryChecks | ForEach-Object { $_.GetAttribute('Key') })
    $Scope = if ($SuiteRegistryKeys -match '^HKLM\\') { 'machine' } elseif ($SuiteRegistryKeys -match '^HKCU\\') { 'user' } else { $null }
    $WritesArp = [bool]($ArpInfo -and $SuiteId)
    $Warnings = [Collections.Generic.List[string]]::new()
    if (-not $WritesArp) { $Warnings.Add('The Advanced UI catalog does not contain both SuiteId and ARPInfo; visible outer ARP ownership is unresolved.') }
    if ($Packages.Count -eq 0) { $Warnings.Add('The Advanced UI catalog contains no package parcels.') }

    # CallInstallScript.Arguments begins with the authored InstallScript
    # function name. Preserve only literal identifiers; dynamic expressions
    # remain unresolved rather than being guessed from nearby strings.
    $InstallScriptEntryPoints = [Collections.Generic.List[string]]::new()
    foreach ($Action in @($Actions | Where-Object Type -EQ 'CallInstallScript')) {
      $Arguments = [string]$Action.Attributes['Arguments']
      $Match = [regex]::Match($Arguments, '^\s*([A-Za-z_][A-Za-z0-9_]*)')
      if ($Match.Success) {
        $Function = $Match.Groups[1].Value
        if ($Function -notin $InstallScriptEntryPoints) { $InstallScriptEntryPoints.Add($Function) }
      } else {
        $Warnings.Add("Advanced UI CallInstallScript action '$($Action.Id)' does not contain a literal function name.")
      }
    }

    $ExecutedPayloads = [Collections.Generic.List[object]]::new()
    foreach ($Package in $Packages) {
      foreach ($Operation in $Package.Operations) {
        if (-not [string]::IsNullOrWhiteSpace($Operation.Target)) {
          $ExecutedPayloads.Add([pscustomobject][ordered]@{
              PackageId       = $Package.Id
              Target          = $Operation.Target
              Arguments       = $Operation.CommandLine
              SilentArguments = $Operation.Silent
            })
        }
      }
    }

    [pscustomobject][ordered]@{
      Path                         = $SetupXmlPath
      InstallerType                = 'exe'
      ProductCode                  = $WritesArp ? $SuiteId : $null
      UpgradeCode                  = $null
      DisplayName                  = & $ReadArpValue 'DisplayName'
      DisplayVersion               = & $ReadArpValue 'Version'
      Publisher                    = & $ReadArpValue 'Publisher'
      Scope                        = $Scope
      DefaultInstallLocation       = $DefaultInstallLocation
      UninstallString              = $null
      QuietUninstallString         = $null
      DisplayIcon                  = & $ReadArpValue 'Icon'
      URLInfoAbout                 = & $ReadArpValue 'URLInfoAbout'
      HelpLink                     = & $ReadArpValue 'HelpLink'
      WritesAppsAndFeaturesEntry   = $WritesArp
      AppsAndFeaturesProductCode   = $WritesArp ? $SuiteId : $null
      AppsAndFeaturesInstallerType = $WritesArp ? 'exe' : $null
      Diagnostics                  = @(ConvertTo-InstallerDiagnostic -InputObject @([object[]]$Warnings) -Source 'InstallShieldAdvancedUI' -Kind Incomplete -Areas Metadata)
      UnresolvedFields             = [string[]]@()
      Family                       = 'InstallShield Advanced UI'
      Variant                      = 'Advanced UI'
      SuiteId                      = $SuiteId
      Namespace                    = $Root.NamespaceURI
      ReleaseVersion               = $ReleaseVersion
      ReleaseYear                  = $ReleaseYear
      DefaultLanguage              = $DefaultLanguage
      Packages                     = [object[]]$Packages
      Selections                   = [object[]]$Selections
      Modes                        = [object[]]@($Modes)
      Actions                      = [object[]]@($Actions)
      InstallScriptEntryPoints     = [string[]]$InstallScriptEntryPoints.ToArray()
      Events                       = [object[]]@($Events)
      AbortConditions              = [object[]]@($AbortConditions)
      Transactions                 = [object[]]@($Transactions)
      CatalogOrder                 = [object[]]$CatalogOrder
      WindowsFeatures              = [object[]]@($WindowsFeatures)
      PackageArchitectures         = [string[]]@($Packages.Architecture | Where-Object { $_ } | Sort-Object -Unique)
      ExecutedPayloads             = [object[]]$ExecutedPayloads
      InstallDirectoryExpression   = $InstallDirectoryExpression
      ParserVersionInfo            = [pscustomobject]@{ Parser = 'Dumplings.PackageModule.InstallShield.AdvancedUI'; ParserMajor = 4; Sources = @('Setup.xml bootstrap catalog', 'ARPInfo', 'Parcels', 'SelectionTree', 'Mode', 'Actions', 'Events', 'Operation', 'Eligibility conditions', 'Nested package dispatch') }
    }
  }
}

Export-ModuleMember -Function *
