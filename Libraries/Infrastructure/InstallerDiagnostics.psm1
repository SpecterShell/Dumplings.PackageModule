# SPDX-License-Identifier: Apache-2.0
# Structured, scenario-aware diagnostics shared by installer parsers and their callers.

function Get-InstallerDiagnosticPropertyValue {
  <#
  .SYNOPSIS
    Read a property from a diagnostic object without relying on StrictMode-sensitive member access.
  .PARAMETER InputObject
    Diagnostic object or dictionary.
  .PARAMETER Name
    Property name to read.
  #>
  param (
    [Parameter(Mandatory)][object]$InputObject,
    [Parameter(Mandatory)][string]$Name
  )

  if ($InputObject -is [Collections.IDictionary]) {
    return $InputObject.Contains($Name) ? $InputObject[$Name] : $null
  }
  $Property = $InputObject.PSObject.Properties[$Name]
  return $null -eq $Property ? $null : $Property.Value
}

function Get-InstallerDiagnosticGeneratedId {
  <#
  .SYNOPSIS
    Generate a stable diagnostic identifier while legacy parser messages are migrated.
  .PARAMETER Source
    Parser or workflow producing the diagnostic.
  .PARAMETER Kind
    Context-neutral diagnostic kind.
  .PARAMETER Message
    Diagnostic message used as the stable hash input.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][string]$Source,
    [Parameter(Mandatory)][string]$Kind,
    [Parameter(Mandatory)][string]$Message
  )

  $Bytes = [Text.Encoding]::UTF8.GetBytes($Message.Trim())
  $Hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).Substring(0, 12)
  $SafeSource = ($Source -replace '[^A-Za-z0-9]+', '.').Trim('.')
  return "${SafeSource}.${Kind}.${Hash}"
}

function New-InstallerDiagnostic {
  <#
  .SYNOPSIS
    Create one context-neutral installer diagnostic.
  .PARAMETER Id
    Stable identifier for the condition, normally Family.ConditionName.
  .PARAMETER Source
    Parser, analyzer, or workflow producing the diagnostic.
  .PARAMETER Message
    Human-readable explanation of the condition.
  .PARAMETER Kind
    Intrinsic condition kind. Final log severity is assigned by the consuming scenario.
  .PARAMETER Areas
    Operations affected by the condition.
  .PARAMETER AffectedFields
    Metadata fields whose evidence is affected.
  .PARAMETER Evidence
    Optional structured evidence retained for programmatic consumers.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]*$')][string]$Id,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Source,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Message,
    [Parameter(Mandatory)][ValidateSet('Information', 'Fallback', 'Incomplete', 'Ambiguous', 'Unsupported', 'Mismatch', 'ManualValidation', 'Risk', 'Invalid')][string]$Kind,
    [Parameter(Mandatory)][ValidateSet('Detection', 'Metadata', 'Extraction', 'Installability', 'Security')][string[]]$Areas,
    [string[]]$AffectedFields = @(),
    [AllowNull()][object]$Evidence
  )

  [pscustomobject][ordered]@{
    PSTypeName     = 'Dumplings.Installer.Diagnostic'
    Id             = $Id
    Source         = $Source
    Message        = $Message.Trim()
    Kind           = $Kind
    Areas          = [string[]]@($Areas | Sort-Object -Unique)
    AffectedFields = [string[]]@($AffectedFields | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
    Evidence       = $Evidence
    Scenario       = $null
    Level          = $null
    IsBlocking     = $null
  }
}

function ConvertTo-InstallerDiagnostic {
  <#
  .SYNOPSIS
    Convert existing messages or diagnostic objects to the structured contract.
  .DESCRIPTION
    This helper lets parser internals compose diagnostics without duplicating validation and supplies
    a deterministic ID for source-backed messages that do not yet have a named condition identifier.
  .PARAMETER InputObject
    Strings or structured diagnostics to normalize.
  .PARAMETER Source
    Source assigned to string inputs.
  .PARAMETER Kind
    Kind assigned to string inputs.
  .PARAMETER Areas
    Areas assigned to string inputs.
  .PARAMETER AffectedFields
    Fields assigned to string inputs.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory, ValueFromPipeline)][AllowNull()][AllowEmptyCollection()][object[]]$InputObject,
    [Parameter(Mandatory)][string]$Source,
    [ValidateSet('Information', 'Fallback', 'Incomplete', 'Ambiguous', 'Unsupported', 'Mismatch', 'ManualValidation', 'Risk', 'Invalid')][string]$Kind = 'Incomplete',
    [ValidateSet('Detection', 'Metadata', 'Extraction', 'Installability', 'Security')][string[]]$Areas = @('Metadata'),
    [string[]]$AffectedFields = @()
  )

  process {
    foreach ($Item in $InputObject) {
      if ($null -eq $Item) { continue }
      $Message = [string](Get-InstallerDiagnosticPropertyValue -InputObject $Item -Name Message)
      $Id = [string](Get-InstallerDiagnosticPropertyValue -InputObject $Item -Name Id)
      if (-not [string]::IsNullOrWhiteSpace($Message) -and -not [string]::IsNullOrWhiteSpace($Id)) {
        $Item
        continue
      }

      $Message = [string]$Item
      if ([string]::IsNullOrWhiteSpace($Message)) { continue }
      New-InstallerDiagnostic -Id (Get-InstallerDiagnosticGeneratedId -Source $Source -Kind $Kind -Message $Message) -Source $Source -Message $Message -Kind $Kind -Areas $Areas -AffectedFields $AffectedFields
    }
  }
}

function Get-InstallerDiagnosticIdentity {
  param ([Parameter(Mandatory)][object]$Diagnostic)

  $Evidence = Get-InstallerDiagnosticPropertyValue -InputObject $Diagnostic -Name Evidence
  $EvidenceJson = $null -eq $Evidence ? '' : (ConvertTo-Json -InputObject $Evidence -Depth 20 -Compress)
  return @(
    Get-InstallerDiagnosticPropertyValue -InputObject $Diagnostic -Name Id
    Get-InstallerDiagnosticPropertyValue -InputObject $Diagnostic -Name Source
    Get-InstallerDiagnosticPropertyValue -InputObject $Diagnostic -Name Message
    @((Get-InstallerDiagnosticPropertyValue -InputObject $Diagnostic -Name AffectedFields) | Sort-Object) -join ','
    $EvidenceJson
  ) -join "`0"
}

function Merge-InstallerDiagnostics {
  <#
  .SYNOPSIS
    Flatten and deduplicate installer diagnostics while preserving first-seen ordering.
  .PARAMETER Diagnostic
    Diagnostic collections to merge.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(ValueFromPipeline)][AllowNull()][object[]]$Diagnostic = @()
  )

  begin {
    $Items = [Collections.Generic.List[object]]::new()
  }
  process {
    foreach ($Entry in @($Diagnostic)) {
      if ($null -eq $Entry) { continue }
      if ($Entry -is [Collections.IEnumerable] -and $Entry -isnot [string] -and -not (Get-InstallerDiagnosticPropertyValue -InputObject $Entry -Name Id)) {
        foreach ($Nested in $Entry) { if ($null -ne $Nested) { $Items.Add($Nested) } }
      } else {
        $Items.Add($Entry)
      }
    }
  }
  end {
    $ByIdentity = [ordered]@{}
    $LevelRank = @{ Verbose = 0; Info = 1; Warning = 2; Error = 3 }
    foreach ($Item in $Items) {
      $Id = [string](Get-InstallerDiagnosticPropertyValue -InputObject $Item -Name Id)
      $Message = [string](Get-InstallerDiagnosticPropertyValue -InputObject $Item -Name Message)
      if ([string]::IsNullOrWhiteSpace($Id) -or [string]::IsNullOrWhiteSpace($Message)) {
        throw 'Installer diagnostics must contain non-empty Id and Message properties.'
      }
      $Identity = Get-InstallerDiagnosticIdentity -Diagnostic $Item
      if (-not $ByIdentity.Contains($Identity)) {
        $ByIdentity[$Identity] = $Item
        continue
      }
      $Existing = $ByIdentity[$Identity]
      $ExistingLevel = [string](Get-InstallerDiagnosticPropertyValue -InputObject $Existing -Name Level)
      $CandidateLevel = [string](Get-InstallerDiagnosticPropertyValue -InputObject $Item -Name Level)
      if ($LevelRank.ContainsKey($CandidateLevel) -and (-not $LevelRank.ContainsKey($ExistingLevel) -or $LevelRank[$CandidateLevel] -gt $LevelRank[$ExistingLevel])) {
        $ByIdentity[$Identity] = $Item
      }
    }
    return [object[]]$ByIdentity.Values
  }
}

function Resolve-InstallerDiagnostic {
  <#
  .SYNOPSIS
    Assign scenario-specific severity and blocking behavior to one installer diagnostic.
  .PARAMETER Diagnostic
    Context-neutral diagnostic returned by a parser or workflow.
  .PARAMETER Scenario
    Workflow consuming the diagnostic.
  .PARAMETER AffectedField
    Fields that the current partial operation is allowed to refresh.
  .PARAMETER ConfirmedFamily
    Indicates that structural evidence already confirmed the parser family.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, ValueFromPipeline)][object]$Diagnostic,
    [Parameter(Mandatory)][ValidateSet('FullAnalysis', 'Detection', 'ManifestAuthoring', 'ManifestUpdate', 'Extraction')][string]$Scenario,
    [string[]]$AffectedField = @(),
    [switch]$ConfirmedFamily
  )

  process {
    $Id = [string](Get-InstallerDiagnosticPropertyValue -InputObject $Diagnostic -Name Id)
    $Source = [string](Get-InstallerDiagnosticPropertyValue -InputObject $Diagnostic -Name Source)
    $Message = [string](Get-InstallerDiagnosticPropertyValue -InputObject $Diagnostic -Name Message)
    if ($Id -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$' -or [string]::IsNullOrWhiteSpace($Source) -or [string]::IsNullOrWhiteSpace($Message)) {
      throw 'Installer diagnostics must contain a valid Id and non-empty Source and Message properties.'
    }
    $Kind = [string](Get-InstallerDiagnosticPropertyValue -InputObject $Diagnostic -Name Kind)
    if ($Kind -notin @('Information', 'Fallback', 'Incomplete', 'Ambiguous', 'Unsupported', 'Mismatch', 'ManualValidation', 'Risk', 'Invalid')) {
      throw "Unsupported installer diagnostic kind '$Kind'."
    }
    $Areas = [string[]]@(Get-InstallerDiagnosticPropertyValue -InputObject $Diagnostic -Name Areas)
    if ($Areas.Count -eq 0 -or @($Areas | Where-Object { $_ -notin @('Detection', 'Metadata', 'Extraction', 'Installability', 'Security') }).Count -gt 0) {
      throw "Installer diagnostic '$Id' contains an unsupported or empty Areas collection."
    }
    $Fields = [string[]]@(Get-InstallerDiagnosticPropertyValue -InputObject $Diagnostic -Name AffectedFields)
    $FieldSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($Field in $AffectedField) { if (-not [string]::IsNullOrWhiteSpace($Field)) { $null = $FieldSet.Add($Field) } }
    $FieldRelevant = @($Fields | Where-Object {
        $DiagnosticField = [string]$_
        if ($FieldSet.Contains($DiagnosticField)) { return $true }
        foreach ($CurrentField in $FieldSet) {
          if ($DiagnosticField.StartsWith("$CurrentField.", [StringComparison]::OrdinalIgnoreCase) -or $CurrentField.StartsWith("$DiagnosticField.", [StringComparison]::OrdinalIgnoreCase)) { return $true }
        }
        return $false
      }).Count -gt 0
    $InstallabilityRelevant = @($Areas | Where-Object { $_ -in @('Installability', 'Security') }).Count -gt 0
    $ExtractionRelevant = $Areas -contains 'Extraction'
    $DetectionRelevant = $Areas -contains 'Detection'

    $Level = 'Verbose'
    $Blocking = $false
    switch ($Scenario) {
      'FullAnalysis' {
        if ($Kind -in @('Information', 'Fallback')) { $Level = 'Info' }
        elseif ($Kind -eq 'Invalid') { $Level = 'Error'; $Blocking = $true }
        else { $Level = 'Warning' }
      }
      'Detection' {
        if ($Kind -eq 'Invalid') { $Level = 'Error'; $Blocking = $true }
        elseif ($Kind -eq 'Mismatch' -and $DetectionRelevant -and $ConfirmedFamily) { $Level = 'Error'; $Blocking = $true }
        elseif ($ConfirmedFamily -and $DetectionRelevant -and $Kind -notin @('Information', 'Fallback')) { $Level = 'Warning' }
      }
      'ManifestAuthoring' {
        if ($Kind -in @('Information', 'Fallback')) { $Level = 'Info' }
        elseif ($Kind -eq 'Invalid' -or ($Kind -eq 'Mismatch' -and $DetectionRelevant) -or ($Kind -eq 'Unsupported' -and $InstallabilityRelevant)) { $Level = 'Error'; $Blocking = $true }
        else { $Level = 'Warning' }
      }
      'ManifestUpdate' {
        if ($Kind -eq 'Invalid' -and $DetectionRelevant) { $Level = 'Error'; $Blocking = $true }
        elseif ($Kind -eq 'Mismatch' -and $DetectionRelevant -and $ConfirmedFamily) { $Level = 'Error'; $Blocking = $true }
        elseif ($InstallabilityRelevant -or ($FieldRelevant -and $Kind -notin @('Information', 'Fallback'))) { $Level = 'Warning' }
      }
      'Extraction' {
        if ($Kind -eq 'Invalid' -and $ExtractionRelevant) { $Level = 'Error'; $Blocking = $true }
        elseif ($ExtractionRelevant -and $Kind -in @('Information', 'Fallback')) { $Level = 'Info' }
        elseif ($ExtractionRelevant) { $Level = 'Warning' }
        elseif ($Areas -contains 'Security') { $Level = 'Warning' }
      }
    }

    [pscustomobject][ordered]@{
      PSTypeName     = 'Dumplings.Installer.ResolvedDiagnostic'
      Id             = $Id
      Source         = $Source
      Message        = $Message
      Kind           = $Kind
      Areas          = $Areas
      AffectedFields = $Fields
      Evidence       = Get-InstallerDiagnosticPropertyValue -InputObject $Diagnostic -Name Evidence
      Scenario       = $Scenario
      Level          = $Level
      IsBlocking     = $Blocking
    }
  }
}

function Resolve-InstallerDiagnostics {
  <#
  .SYNOPSIS
    Resolve and deduplicate a collection of diagnostics for one workflow scenario.
  .PARAMETER Diagnostic
    Context-neutral diagnostics to resolve.
  .PARAMETER Scenario
    Workflow consuming the diagnostics.
  .PARAMETER AffectedField
    Fields refreshed by a partial manifest update.
  .PARAMETER ConfirmedFamily
    Indicates that structural evidence confirmed the parser family.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Diagnostic,
    [Parameter(Mandatory)][ValidateSet('FullAnalysis', 'Detection', 'ManifestAuthoring', 'ManifestUpdate', 'Extraction')][string]$Scenario,
    [string[]]$AffectedField = @(),
    [switch]$ConfirmedFamily
  )

  $Resolved = foreach ($Item in @(Merge-InstallerDiagnostics -Diagnostic $Diagnostic)) {
    Resolve-InstallerDiagnostic -Diagnostic $Item -Scenario $Scenario -AffectedField $AffectedField -ConfirmedFamily:$ConfirmedFamily
  }
  return [object[]]@(Merge-InstallerDiagnostics -Diagnostic $Resolved)
}

function Write-InstallerDiagnostics {
  <#
  .SYNOPSIS
    Resolve installer diagnostics and write each one through a task logger or PowerShell stream.
  .PARAMETER Diagnostic
    Diagnostics to resolve and render.
  .PARAMETER Scenario
    Workflow consuming the diagnostics.
  .PARAMETER AffectedField
    Fields refreshed by a partial manifest update.
  .PARAMETER ConfirmedFamily
    Indicates that structural evidence confirmed the parser family.
  .PARAMETER Logger
    Optional logger whose Invoke method accepts message and level.
  .PARAMETER PassThru
    Return the resolved diagnostics after rendering.
  #>
  param (
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Diagnostic,
    [Parameter(Mandatory)][ValidateSet('FullAnalysis', 'Detection', 'ManifestAuthoring', 'ManifestUpdate', 'Extraction')][string]$Scenario,
    [string[]]$AffectedField = @(),
    [switch]$ConfirmedFamily,
    [ValidateScript({ $null -eq $_ -or (Get-Member -InputObject $_ -Name Invoke -MemberType Method) })]$Logger,
    [switch]$PassThru
  )

  $AlreadyResolved = @($Diagnostic).Count -gt 0 -and @($Diagnostic | Where-Object {
      (Get-InstallerDiagnosticPropertyValue -InputObject $_ -Name Scenario) -cne $Scenario -or
      [string]::IsNullOrWhiteSpace([string](Get-InstallerDiagnosticPropertyValue -InputObject $_ -Name Level))
    }).Count -eq 0
  $Resolved = if ($AlreadyResolved) {
    @(Merge-InstallerDiagnostics -Diagnostic $Diagnostic)
  } else {
    @(Resolve-InstallerDiagnostics -Diagnostic $Diagnostic -Scenario $Scenario -AffectedField $AffectedField -ConfirmedFamily:$ConfirmedFamily)
  }
  foreach ($Item in $Resolved) {
    $Text = "[$($Item.Id)] $($Item.Source): $($Item.Message)"
    if ($Logger) {
      $null = $Logger.Invoke($Text, $Item.Level)
      continue
    }
    switch ($Item.Level) {
      'Error' { Write-Error -Message $Text -ErrorAction Continue }
      'Warning' { Write-Warning -Message $Text }
      'Info' { Write-Information -MessageData $Text }
      default { Write-Verbose -Message $Text }
    }
  }
  if ($PassThru) { return $Resolved }
}

Export-ModuleMember -Function New-InstallerDiagnostic, ConvertTo-InstallerDiagnostic, Merge-InstallerDiagnostics, Resolve-InstallerDiagnostic, Resolve-InstallerDiagnostics, Write-InstallerDiagnostics
