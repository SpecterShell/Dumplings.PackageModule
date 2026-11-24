# SPDX-License-Identifier: Apache-2.0
# Internal CreateInstall implementation. See CreateInstall.psm1 for format sources and the binary layout.
# Pass parsed contexts explicitly and keep caller-owned streams local.

# CreateInstall operations implementation, imported locally by the public facade.
Import-Module (Join-Path $PSScriptRoot 'CreateInstallGentee.psm1') -ErrorAction Stop

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

function Get-CreateInstallProjectVariableEvidence {
  <#
  .SYNOPSIS
    Recover the generated MAINVAR project list from a decoded CreateInstall GE program.
  .PARAMETER Program
    Decoded program returned by Get-CreateInstallGenteeProgram.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][psobject]$Program)

  # CreateInstall initializes g_list as a Gentee buf global. Optimized GE files omit the global
  # name, so candidate offsets come only from integer literals actually referenced by bytecode.
  $Functions = Get-CreateInstallFunctionIndex -Program $Program
  $Buffers = [System.Collections.Generic.List[object]]::new()
  foreach ($Record in @($Program.Records | Where-Object Type -EQ 6)) {
    $Cursor = [pscustomobject]@{ Value = [int]$Record.PayloadOffset }
    $Variable = Read-CreateInstallGenteeVariable -Bytes $Program.Bytes -Cursor $Cursor -Limit $Record.EndOffset
    if ($Cursor.Value -ne $Record.EndOffset) { throw 'A Gentee global record contains trailing data' }
    if ($Variable.Type -eq 12 -and $Variable.HasData -and $Variable.Data.Length -ge 4) {
      $Buffers.Add([pscustomobject]@{ ObjectId = $Record.Id; Data = $Variable.Data })
    }
  }

  $ReferencedOffsets = [System.Collections.Generic.HashSet[uint32]]::new()
  foreach ($Function in $Functions.Values) {
    foreach ($Command in $Function.Commands) {
      if ($Command.Command -in @(25, 26, 27) -and $Command.Operand -is [ValueType]) { $null = $ReferencedOffsets.Add([uint32]$Command.Operand) }
    }
  }

  $Candidates = [System.Collections.Generic.List[object]]::new()
  foreach ($Buffer in $Buffers) {
    foreach ($Offset in $ReferencedOffsets) {
      if ($Offset -gt $Buffer.Data.Length - 4) { continue }
      try { $Rows = @(ConvertFrom-CreateInstallGenteeList -Bytes $Buffer.Data -Offset ([int]$Offset) -FieldCount 2) } catch { continue }
      $Variables = [ordered]@{}
      $Valid = $true
      foreach ($Row in $Rows) {
        $Name = [string]$Row.Fields[0]
        if ([string]::IsNullOrWhiteSpace($Name) -or $Name.Contains([char]0)) { $Valid = $false; break }
        $Variables[$Name] = [string]$Row.Fields[1]
      }
      if (-not $Valid) { continue }
      # These values are consumed directly by common_init and addremove*. Requiring all six
      # separates MAINVAR from command-specific two-column lists without relying on an object ID.
      $RequiredNames = @('progname', 'ver', 'compname', 'setuppath', 'uninstexe', 'silentpar')
      if (@($RequiredNames | Where-Object { -not $Variables.Contains($_) }).Count -eq 0) {
        $Candidates.Add([pscustomobject]@{ BufferObjectId = $Buffer.ObjectId; Offset = [uint32]$Offset; Variables = $Variables; Count = $Rows.Count; BufferData = $Buffer.Data })
      }
    }
  }
  if ($Candidates.Count -eq 0) { throw 'The compiled CreateInstall program does not expose one referenced MAINVAR list' }
  if ($Candidates.Count -gt 1) {
    $Distinct = @($Candidates | Group-Object { ($_.Variables.GetEnumerator() | Sort-Object Key | ForEach-Object { '{0}={1}' -f $_.Key, $_.Value }) -join "`0" })
    if ($Distinct.Count -ne 1) { throw 'The compiled CreateInstall program exposes conflicting MAINVAR lists' }
  }
  return $Candidates[0]
}

function Resolve-CreateInstallMacroValue {
  <#
  .SYNOPSIS
    Resolve deterministic CreateInstall #macro# substitutions to manifest-safe values.
  .PARAMETER Value
    Compiled string expression to expand.
  .PARAMETER Variables
    Case-insensitive MAINVAR key/value dictionary recovered from the GE program.
  .PARAMETER Is32Bit
    Indicates that the CreateInstall process uses the 32-bit Windows folder view.
  #>
  [OutputType([pscustomobject])]
  param (
    [AllowNull()][string]$Value,
    [Parameter(Mandatory)][System.Collections.IDictionary]$Variables,
    [Parameter(Mandatory)][bool]$Is32Bit
  )

  if ($null -eq $Value) { return [pscustomobject]@{ Value = $null; UnresolvedMacros = [string[]]@() } }
  $Known = [System.Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($Entry in $Variables.GetEnumerator()) { $Known[[string]$Entry.Key] = [string]$Entry.Value }
  $Known['progfiles'] = $Is32Bit ? '%ProgramFiles(x86)%' : '%ProgramFiles%'
  $Known['comprogfiles'] = $Is32Bit ? '%CommonProgramFiles(x86)%' : '%CommonProgramFiles%'
  $Known['appdata'] = '%APPDATA%'
  $Known['comappdata'] = '%ProgramData%'
  $Known['windows'] = '%WINDIR%'
  $Known['winpath'] = '%WINDIR%'
  $Known['temp'] = '%TEMP%'
  $Known['temppath'] = '%TEMP%'
  $Known['syspath'] = '%WINDIR%\System32'
  $Known['localpath'] = '%LOCALAPPDATA%'
  $Known['userpath'] = '%USERPROFILE%'
  $Known['progpath'] = '%APPDATA%\Microsoft\Windows\Start Menu\Programs'
  $Known['comprogpath'] = '%ProgramData%\Microsoft\Windows\Start Menu\Programs'
  $Known['start'] = '%APPDATA%\Microsoft\Windows\Start Menu'
  $Known['comstart'] = '%ProgramData%\Microsoft\Windows\Start Menu'
  $Known['startup'] = '%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup'
  $Known['comstartup'] = '%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup'
  $Known['desktop'] = '%USERPROFILE%\Desktop'
  $Known['comdesktop'] = '%PUBLIC%\Desktop'
  $Known['quicklaunch'] = '%APPDATA%\Microsoft\Internet Explorer\Quick Launch'
  $Known['sendto'] = '%APPDATA%\Microsoft\Windows\SendTo'
  $Known['fontpath'] = '%WINDIR%\Fonts'
  $Known['docpath'] = '%USERPROFILE%\Documents'
  $Known['comdocpath'] = '%PUBLIC%\Documents'
  $Known['picpath'] = '%USERPROFILE%\Pictures'
  $Known['compicpath'] = '%PUBLIC%\Pictures'
  $Known['musicpath'] = '%USERPROFILE%\Music'
  $Known['commusicpath'] = '%PUBLIC%\Music'
  $Known['videopath'] = '%USERPROFILE%\Videos'
  $Known['comvideopath'] = '%PUBLIC%\Videos'
  $Known['iefavpath'] = '%USERPROFILE%\Favorites'
  $Known['cookies'] = '%LOCALAPPDATA%\Microsoft\Windows\INetCookies'
  $Known['history'] = '%LOCALAPPDATA%\Microsoft\Windows\History'

  $Resolved = $Value
  for ($Depth = 0; $Depth -lt 16; $Depth++) {
    $Previous = $Resolved
    $Resolved = [regex]::Replace($Previous, '#(?<Name>[^#]+)#', {
        param($Match)
        $Name = $Match.Groups['Name'].Value
        if ($Known.ContainsKey($Name)) { return $Known[$Name] }
        return $Match.Value
      })
    if ($Resolved -ceq $Previous) { break }
  }
  $Unresolved = @([regex]::Matches($Resolved, '#(?<Name>[^#]+)#') | ForEach-Object { $_.Groups['Name'].Value } | Sort-Object -Unique)
  return [pscustomobject]@{ Value = $Resolved; UnresolvedMacros = [string[]]$Unresolved }
}

function Join-CreateInstallMacroPath {
  <#
  .SYNOPSIS
    Join two compiled CreateInstall path operands before deterministic macro expansion.
  .PARAMETER Parent
    Parent path operand.
  .PARAMETER Child
    Optional file-name operand.
  .PARAMETER Variables
    MAINVAR key/value dictionary.
  .PARAMETER Is32Bit
    Indicates the 32-bit Windows folder view.
  #>
  [OutputType([pscustomobject])]
  param (
    [AllowEmptyString()][string]$Parent,
    [AllowEmptyString()][string]$Child,
    [Parameter(Mandatory)][System.Collections.IDictionary]$Variables,
    [Parameter(Mandatory)][bool]$Is32Bit
  )

  $Combined = if ([string]::IsNullOrWhiteSpace($Child)) { $Parent } elseif ([string]::IsNullOrWhiteSpace($Parent)) { $Child } else { $Parent.TrimEnd([char[]]'\/') + '\' + $Child.TrimStart([char[]]'\/') }
  return Resolve-CreateInstallMacroValue -Value $Combined -Variables $Variables -Is32Bit $Is32Bit
}

function Resolve-CreateInstallCondition {
  <#
  .SYNOPSIS
    Resolve the bounded Boolean subset accepted by CreateInstall's ifcondition routine.
  .PARAMETER Expression
    Literal condition string stored in a generated operation list.
  .PARAMETER Variables
    Compiled macro dictionary used by ifcondition for #name# expressions.
  #>
  [OutputType([Nullable[bool]])]
  param (
    [AllowNull()][string]$Expression,
    [Parameter(Mandatory)][System.Collections.IDictionary]$Variables
  )

  if ([string]::IsNullOrWhiteSpace($Expression)) { return $true }
  $Condition = $Expression.Trim()
  $Negated = $Condition.StartsWith('!', [StringComparison]::Ordinal)
  if ($Negated) { $Condition = $Condition.Substring(1) }
  # @function conditions execute arbitrary project code and therefore cannot be evaluated safely.
  if ($Condition.StartsWith('@', [StringComparison]::Ordinal)) { return $null }
  $Name = $Condition.Trim('#')
  if (-not $Variables.Contains($Name)) { return $null }
  $Value = [string]$Variables[$Name]
  $Result = -not [string]::IsNullOrEmpty($Value) -and $Value -cne '0' -and $Value -cne 'false'
  return $Negated ? (-not $Result) : $Result
}

function Get-CreateInstallOperationProfile {
  <#
  .SYNOPSIS
    Return one data-driven CreateInstall operation profile.
  .PARAMETER Id
    Stable route identifier from CreateInstallFormatCatalog.psd1.
  #>
  [OutputType([hashtable])]
  param ([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Id)

  $Profiles = @((Get-CreateInstallCatalogProfile -Section OperationProfiles) | Where-Object Id -CEQ $Id)
  if ($Profiles.Count -ne 1) { throw "The CreateInstall operation profile '$Id' is missing or duplicated" }
  return $Profiles[0]
}

function Find-CreateInstallOperationRoutine {
  <#
  .SYNOPSIS
    Find compiled routines that satisfy one cataloged structural profile.
  .PARAMETER Program
    Decoded GE program returned by Get-CreateInstallGenteeProgram.
  .PARAMETER ProfileId
    Stable operation profile whose parameter, literal, and imported-call constraints are applied.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][psobject]$Program,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ProfileId
  )

  $OperationProfile = Get-CreateInstallOperationProfile -Id $ProfileId
  $Functions = Get-CreateInstallFunctionIndex -Program $Program
  return [object[]]@($Functions.Values | Where-Object {
      $Function = $_
      if ($OperationProfile.ContainsKey('RuntimeParameterCount') -and $Function.ParameterCount -ne [uint32]$OperationProfile.RuntimeParameterCount) { return $false }
      $StringLiterals = if ($Function.PSObject.Properties['StringLiterals']) { [string[]]$Function.StringLiterals } else { [string[]]@() }
      if ($OperationProfile.ContainsKey('RequiredLiteralFragments')) {
        foreach ($Fragment in [string[]]$OperationProfile.RequiredLiteralFragments) {
          if (@($StringLiterals | Where-Object { $_.Contains($Fragment, [StringComparison]::OrdinalIgnoreCase) }).Count -eq 0) { return $false }
        }
      }
      # Some Gentee routines share parameter counts and marker strings. Match the complete literal
      # sequence only for source-backed profiles whose command order is part of the route identity.
      if ($OperationProfile.ContainsKey('ExactStringLiterals')) {
        $ExpectedLiterals = [string[]]$OperationProfile.ExactStringLiterals
        if ($StringLiterals.Count -ne $ExpectedLiterals.Count) { return $false }
        for ($LiteralIndex = 0; $LiteralIndex -lt $ExpectedLiterals.Count; $LiteralIndex++) {
          if ($StringLiterals[$LiteralIndex] -cne $ExpectedLiterals[$LiteralIndex]) { return $false }
        }
      }
      $ExternalNames = if ($Function.PSObject.Properties['ExternalCalls']) { [string[]]@($Function.ExternalCalls.Name) } else { [string[]]@() }
      if ($OperationProfile.ContainsKey('RequiredExternalCalls')) { foreach ($Name in [string[]]$OperationProfile.RequiredExternalCalls) { if ($ExternalNames -inotcontains $Name) { return $false } } }
      if ($OperationProfile.ContainsKey('ForbiddenExternalCalls')) { foreach ($Name in [string[]]$OperationProfile.ForbiddenExternalCalls) { if ($ExternalNames -icontains $Name) { return $false } } }
      return $true
    })
}

function Get-CreateInstallRoutineCallSite {
  <#
  .SYNOPSIS
    Enumerate bounded caller windows ending at calls to selected compiled routines.
  .PARAMETER Program
    Decoded GE program whose function index supplies callers and targets.
  .PARAMETER TargetId
    Compiled routine object identifiers accepted as operation targets.
  .PARAMETER MaximumLookback
    Maximum number of decoded commands retained before each call. The window also starts after the
    preceding call to the same target, preventing one repeated operation from consuming another.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][psobject]$Program,
    [Parameter(Mandatory)][AllowEmptyCollection()][uint32[]]$TargetId,
    [ValidateRange(1, 1024)][int]$MaximumLookback = 192
  )

  if ($TargetId.Count -eq 0) { return @() }
  $Targets = [Collections.Generic.HashSet[uint32]]::new($TargetId)
  $Calls = [Collections.Generic.List[object]]::new()
  foreach ($Function in (Get-CreateInstallFunctionIndex -Program $Program).Values) {
    $PreviousCall = @{}
    for ($CommandIndex = 0; $CommandIndex -lt $Function.Commands.Count; $CommandIndex++) {
      $RoutineId = [uint32]$Function.Commands[$CommandIndex].Command
      if (-not $Targets.Contains($RoutineId)) { continue }
      $Start = [Math]::Max(0, $CommandIndex - $MaximumLookback)
      if ($PreviousCall.ContainsKey($RoutineId)) { $Start = [Math]::Max($Start, [int]$PreviousCall[$RoutineId] + 1) }
      $PreviousCall[$RoutineId] = $CommandIndex
      $Window = if ($Start -lt $CommandIndex) { [object[]]@($Function.Commands[$Start..($CommandIndex - 1)]) } else { [object[]]@() }
      $Calls.Add([pscustomobject]@{ CallerId = [uint32]$Function.Record.Id; RoutineId = $RoutineId; CallOffset = [int]$Function.Commands[$CommandIndex].Offset; Window = $Window })
    }
  }
  return $Calls.ToArray()
}

function Get-CreateInstallScheduledTaskEvidence {
  <#
  .SYNOPSIS
    Recover source-backed CreateInstall scheduled-task creation and deletion operations.
  .PARAMETER Program
    Decoded GE program whose imported citools.dll calls identify the task routines.
  .PARAMETER ProjectVariableEvidence
    MAINVAR variables used to resolve task fields and conditions.
  .PARAMETER Is32Bit
    Indicates the Windows folder view used while resolving CreateInstall macros.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Program,
    [Parameter(Mandatory)][psobject]$ProjectVariableEvidence,
    [Parameter(Mandatory)][bool]$Is32Bit
  )

  $Tasks = [Collections.Generic.List[object]]::new()
  $Diagnostics = [Collections.Generic.List[object]]::new()
  $CreateTargets = [uint32[]]@(Find-CreateInstallOperationRoutine -Program $Program -ProfileId ScheduledTaskCreate13 | ForEach-Object { [uint32]$_.Record.Id })
  foreach ($Call in @(Get-CreateInstallRoutineCallSite -Program $Program -TargetId $CreateTargets)) {
    $Strings = @($Call.Window | Where-Object Command -EQ 34 | Select-Object -Last 12)
    $Integers = @($Call.Window | Where-Object { $_.Command -in @(25, 26, 27) -and $_.Operand -is [ValueType] } | Select-Object -Last 1)
    if ($Strings.Count -ne 12 -or $Integers.Count -ne 1) { continue }
    $TriggerValue = [uint32]$Integers[0].Operand
    $TriggerNames = @{ 0 = 'Once'; 1 = 'Daily'; 2 = 'Weekly'; 6 = 'SystemStart'; 7 = 'Logon' }
    if (-not $TriggerNames.ContainsKey([int]$TriggerValue)) { continue }
    $ConditionExpression = [string]$Strings[11].Operand
    $Condition = Resolve-CreateInstallCondition -Expression $ConditionExpression -Variables $ProjectVariableEvidence.Variables
    if ($Condition -eq $false) { continue }
    $Executable = Join-CreateInstallMacroPath -Parent ([string]$Strings[2].Operand) -Child ([string]$Strings[3].Operand) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
    $WorkingDirectory = Join-CreateInstallMacroPath -Parent ([string]$Strings[5].Operand) -Child ([string]$Strings[6].Operand) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
    $Resolved = foreach ($Index in 0, 1, 4, 7, 8, 9, 10) { Resolve-CreateInstallMacroValue -Value ([string]$Strings[$Index].Operand) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit }
    $Tasks.Add([pscustomobject][ordered]@{
        Operation = 'Create'; CallerId = $Call.CallerId; RoutineId = $Call.RoutineId; CallOffset = $Call.CallOffset
        UserName = $Resolved[0].Value; Name = $Resolved[1].Value; Executable = $Executable.Value; Arguments = $Resolved[2].Value
        WorkingDirectory = $WorkingDirectory.Value; Comment = $Resolved[3].Value; TriggerType = $TriggerNames[[int]$TriggerValue]
        Start = $Resolved[4].Value; Interval = $Resolved[5].Value; Parameters = $Resolved[6].Value
        ConditionExpression = $ConditionExpression; Condition = $Condition
        UnresolvedMacros = [string[]]@($Executable.UnresolvedMacros + $WorkingDirectory.UnresolvedMacros + @($Resolved.UnresolvedMacros) | Sort-Object -Unique)
      })
  }

  $DeleteTargets = [uint32[]]@(Find-CreateInstallOperationRoutine -Program $Program -ProfileId ScheduledTaskDelete2 | ForEach-Object { [uint32]$_.Record.Id })
  foreach ($Call in @(Get-CreateInstallRoutineCallSite -Program $Program -TargetId $DeleteTargets -MaximumLookback 48)) {
    $Strings = @($Call.Window | Where-Object Command -EQ 34 | Select-Object -Last 2)
    if ($Strings.Count -ne 2) { continue }
    $ConditionExpression = [string]$Strings[1].Operand
    $Condition = Resolve-CreateInstallCondition -Expression $ConditionExpression -Variables $ProjectVariableEvidence.Variables
    if ($Condition -eq $false) { continue }
    $Name = Resolve-CreateInstallMacroValue -Value ([string]$Strings[0].Operand) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
    if ([string]::IsNullOrWhiteSpace([string]$Name.Value)) { continue }
    $Tasks.Add([pscustomobject][ordered]@{
        Operation = 'Delete'; CallerId = $Call.CallerId; RoutineId = $Call.RoutineId; CallOffset = $Call.CallOffset
        UserName = $null; Name = $Name.Value; Executable = $null; Arguments = $null; WorkingDirectory = $null; Comment = $null
        TriggerType = $null; Start = $null; Interval = $null; Parameters = $null
        ConditionExpression = $ConditionExpression; Condition = $Condition; UnresolvedMacros = [string[]]$Name.UnresolvedMacros
      })
  }

  $Conditional = @($Tasks | Where-Object { $null -eq $_.Condition -or $_.UnresolvedMacros.Count -gt 0 })
  if ($Conditional.Count) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.ScheduledTask.Conditional' -Source CreateInstall -Message "$($Conditional.Count) CreateInstall scheduled-task operation(s) depend on runtime conditions or macros." -Kind Ambiguous -Areas Metadata, Installability -Evidence $Conditional)) }
  return [pscustomobject]@{ ScheduledTasks = $Tasks.ToArray(); Diagnostics = $Diagnostics.ToArray() }
}

function Get-CreateInstallFileOperationEvidence {
  <#
  .SYNOPSIS
    Recover deterministic direct and list-based CreateInstall file-copy operations.
  .PARAMETER Program
    Decoded GE program containing generated copy call sites.
  .PARAMETER ProjectVariableEvidence
    MAINVAR variables and g_list bytes used to resolve paths and list rows.
  .PARAMETER Is32Bit
    Indicates the Windows folder view used while resolving CreateInstall macros.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Program,
    [Parameter(Mandatory)][psobject]$ProjectVariableEvidence,
    [Parameter(Mandatory)][bool]$Is32Bit
  )

  $Operations = [Collections.Generic.List[object]]::new()
  $Diagnostics = [Collections.Generic.List[object]]::new()
  $DirectTargets = [uint32[]]@(Find-CreateInstallOperationRoutine -Program $Program -ProfileId CopyDirect7 | ForEach-Object { [uint32]$_.Record.Id })
  foreach ($Call in @(Get-CreateInstallRoutineCallSite -Program $Program -TargetId $DirectTargets -MaximumLookback 96)) {
    $Strings = @($Call.Window | Where-Object Command -EQ 34 | Select-Object -Last 5)
    $Integers = @($Call.Window | Where-Object { $_.Command -in @(25, 26, 27) -and $_.Operand -is [ValueType] } | Select-Object -Last 2)
    if ($Strings.Count -ne 5 -or $Integers.Count -ne 2) { continue }
    $ConditionExpression = [string]$Strings[4].Operand
    $Condition = Resolve-CreateInstallCondition -Expression $ConditionExpression -Variables $ProjectVariableEvidence.Variables
    if ($Condition -eq $false) { continue }
    $Source = Join-CreateInstallMacroPath -Parent ([string]$Strings[0].Operand) -Child ([string]$Strings[1].Operand) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
    $Destination = Join-CreateInstallMacroPath -Parent ([string]$Strings[2].Operand) -Child ([string]$Strings[3].Operand) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
    $Operations.Add([pscustomobject][ordered]@{
        Operation = 'Copy'; Route = 'Direct'; CallerId = $Call.CallerId; RoutineId = $Call.RoutineId; CallOffset = $Call.CallOffset; ListOffset = $null; RowIndex = $null
        Source = $Source.Value; Destination = $Destination.Value; SearchFlags = [uint32]$Integers[0].Operand; OverwriteMode = [uint32]$Integers[1].Operand
        ConditionExpression = $ConditionExpression; Condition = $Condition; UnresolvedMacros = [string[]]@($Source.UnresolvedMacros + $Destination.UnresolvedMacros | Sort-Object -Unique)
      })
  }

  $ListTargets = [uint32[]]@(Find-CreateInstallOperationRoutine -Program $Program -ProfileId CopyList7 | ForEach-Object { [uint32]$_.Record.Id })
  foreach ($Call in @(Get-CreateInstallListCallEvidence -Program $Program -ProjectVariableEvidence $ProjectVariableEvidence -TargetId $ListTargets -FieldCount 7)) {
    foreach ($Row in $Call.Rows) {
      $ConditionExpression = [string]$Row.Fields[5]
      $Condition = Resolve-CreateInstallCondition -Expression $ConditionExpression -Variables $ProjectVariableEvidence.Variables
      if ($Condition -eq $false) { continue }
      $Source = Join-CreateInstallMacroPath -Parent ([string]$Row.Fields[0]) -Child ([string]$Row.Fields[1]) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
      $Destination = Join-CreateInstallMacroPath -Parent ([string]$Row.Fields[2]) -Child ([string]$Row.Fields[3]) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
      $Operations.Add([pscustomobject][ordered]@{
          Operation = 'Copy'; Route = 'List'; CallerId = $Call.CallerId; RoutineId = $Call.RoutineId; CallOffset = $Call.CallOffset; ListOffset = $Call.ListOffset; RowIndex = $Row.Index
          Source = $Source.Value; Destination = $Destination.Value; SearchFlags = $null; OverwriteMode = ([string]$Row.Fields[4] -notin '', '0', 'false') ? 1 : 0
          ConditionExpression = $ConditionExpression; Condition = $Condition; UnresolvedMacros = [string[]]@($Source.UnresolvedMacros + $Destination.UnresolvedMacros | Sort-Object -Unique)
        })
    }
  }
  $Conditional = @($Operations | Where-Object { $null -eq $_.Condition -or $_.UnresolvedMacros.Count -gt 0 })
  if ($Conditional.Count) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Copy.Conditional' -Source CreateInstall -Message "$($Conditional.Count) CreateInstall file-copy operation(s) depend on runtime conditions or macros." -Kind Ambiguous -Areas Extraction -Evidence $Conditional)) }
  return [pscustomobject]@{ FileOperations = $Operations.ToArray(); Diagnostics = $Diagnostics.ToArray() }
}

function Get-CreateInstallDownloadEvidence {
  <#
  .SYNOPSIS
    Recover external files downloaded by source-backed CreateInstall download lists.
  .PARAMETER Program
    Decoded GE program containing the downloadfilesex routine and generated calls.
  .PARAMETER ProjectVariableEvidence
    MAINVAR variables and g_list bytes used to resolve URLs, destinations, and conditions.
  .PARAMETER Is32Bit
    Indicates the Windows folder view used while resolving CreateInstall macros.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Program,
    [Parameter(Mandatory)][psobject]$ProjectVariableEvidence,
    [Parameter(Mandatory)][bool]$Is32Bit
  )

  $Downloads = [Collections.Generic.List[object]]::new()
  $Diagnostics = [Collections.Generic.List[object]]::new()
  $Targets = [uint32[]]@(Find-CreateInstallOperationRoutine -Program $Program -ProfileId DownloadList8 | ForEach-Object { [uint32]$_.Record.Id })
  foreach ($Call in @(Get-CreateInstallRoutineCallSite -Program $Program -TargetId $Targets -MaximumLookback 64)) {
    $Strings = @($Call.Window | Where-Object Command -EQ 34 | Select-Object -Last 1)
    $Integers = @($Call.Window | Where-Object { $_.Command -in @(25, 26, 27) -and $_.Operand -is [ValueType] } | Select-Object -Last 2)
    if ($Strings.Count -ne 1 -or $Integers.Count -ne 2 -or [uint32]$Integers[1].Operand -notin 0, 1) { continue }
    $ListOffset = [uint32]$Integers[0].Operand
    try { $Rows = @(ConvertFrom-CreateInstallGenteeList -Bytes $ProjectVariableEvidence.BufferData -Offset ([int]$ListOffset) -FieldCount 8) } catch { continue }
    $BaseUrl = Resolve-CreateInstallMacroValue -Value ([string]$Strings[0].Operand) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
    foreach ($Row in $Rows) {
      $ConditionExpression = [string]$Row.Fields[5]
      $Condition = Resolve-CreateInstallCondition -Expression $ConditionExpression -Variables $ProjectVariableEvidence.Variables
      if ($Condition -eq $false) { continue }
      $UrlPart = Resolve-CreateInstallMacroValue -Value ([string]$Row.Fields[0]) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
      $Url = [string]$UrlPart.Value
      if ($Url -notmatch '^https?://') { $Url = ([string]$BaseUrl.Value).TrimEnd('/') + '/' + $Url.TrimStart('/') }
      $FileName = [string]$Row.Fields[3]
      if ([string]::IsNullOrWhiteSpace($FileName)) {
        $FileName = ($Url -split '/')[-1] -replace '[?:\\]', '_'
      }
      $DestinationDirectory = Join-CreateInstallMacroPath -Parent ([string]$Row.Fields[1]) -Child ([string]$Row.Fields[2]) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
      $Destination = Join-CreateInstallMacroPath -Parent ([string]$DestinationDirectory.Value) -Child $FileName -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
      $OverwriteValue = 0; [void][int]::TryParse([string]$Row.Fields[4], [ref]$OverwriteValue)
      $Downloads.Add([pscustomobject][ordered]@{
          CallerId = $Call.CallerId; RoutineId = $Call.RoutineId; CallOffset = $Call.CallOffset; ListOffset = $ListOffset; RowIndex = $Row.Index
          Url = $Url; Destination = $Destination.Value; OverwriteMode = @('Overwrite', 'OverwriteDifferentSize', 'Skip')[[Math]::Min([Math]::Max($OverwriteValue, 0), 2)]
          ResultVariable = [string]$Row.Fields[6]; UsesTlsSupport = [uint32]$Integers[1].Operand -eq 1
          ConditionExpression = $ConditionExpression; Condition = $Condition
          UnresolvedMacros = [string[]]@($BaseUrl.UnresolvedMacros + $UrlPart.UnresolvedMacros + $Destination.UnresolvedMacros | Sort-Object -Unique)
        })
    }
  }
  if ($Downloads.Count) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Download.ExternalPayload' -Source CreateInstall -Message "CreateInstall downloads $($Downloads.Count) external payload file(s); packaged extraction alone is incomplete." -Kind ManualValidation -Areas Extraction, Installability, Security -Evidence $Downloads.ToArray())) }
  return [pscustomobject]@{ Downloads = $Downloads.ToArray(); Diagnostics = $Diagnostics.ToArray() }
}

function Get-CreateInstallArchiveOperationEvidence {
  <#
  .SYNOPSIS
    Recover source-backed 7z, cabinet, and ZIP decompression operations.
  .PARAMETER Program
    Decoded GE program containing archive routines and generated call sites.
  .PARAMETER ProjectVariableEvidence
    MAINVAR variables used to resolve paths and conditions.
  .PARAMETER Is32Bit
    Indicates the Windows folder view used while resolving CreateInstall macros.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Program,
    [Parameter(Mandatory)][psobject]$ProjectVariableEvidence,
    [Parameter(Mandatory)][bool]$Is32Bit
  )

  $Operations = [Collections.Generic.List[object]]::new()
  $Diagnostics = [Collections.Generic.List[object]]::new()
  $Routes = @(
    [pscustomobject]@{ Profile = 'Decompress7z8'; Format = '7z'; StringCount = 7; ConditionIndex = 4; WildcardIndex = 5; ExcludeIndex = 6; IntegerCount = 1 }
    [pscustomobject]@{ Profile = 'DecompressCab7'; Format = 'Cabinet'; StringCount = 6; ConditionIndex = 4; WildcardIndex = 5; ExcludeIndex = -1; IntegerCount = 1 }
    [pscustomobject]@{ Profile = 'DecompressZip6'; Format = 'ZIP'; StringCount = 5; ConditionIndex = 4; WildcardIndex = -1; ExcludeIndex = -1; IntegerCount = 1 }
  )
  foreach ($Route in $Routes) {
    $Targets = [uint32[]]@(Find-CreateInstallOperationRoutine -Program $Program -ProfileId $Route.Profile | ForEach-Object { [uint32]$_.Record.Id })
    foreach ($Call in @(Get-CreateInstallRoutineCallSite -Program $Program -TargetId $Targets -MaximumLookback 96)) {
      $Strings = @($Call.Window | Where-Object Command -EQ 34 | Select-Object -Last $Route.StringCount)
      $Integers = @($Call.Window | Where-Object { $_.Command -in @(25, 26, 27) -and $_.Operand -is [ValueType] } | Select-Object -Last $Route.IntegerCount)
      if ($Strings.Count -ne $Route.StringCount -or $Integers.Count -ne $Route.IntegerCount) { continue }
      $ConditionExpression = [string]$Strings[$Route.ConditionIndex].Operand
      $Condition = Resolve-CreateInstallCondition -Expression $ConditionExpression -Variables $ProjectVariableEvidence.Variables
      if ($Condition -eq $false) { continue }
      $Source = Join-CreateInstallMacroPath -Parent ([string]$Strings[0].Operand) -Child ([string]$Strings[1].Operand) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
      $Destination = Join-CreateInstallMacroPath -Parent ([string]$Strings[2].Operand) -Child ([string]$Strings[3].Operand) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
      $Operations.Add([pscustomobject][ordered]@{
          Operation = 'Decompress'; Format = $Route.Format; CallerId = $Call.CallerId; RoutineId = $Call.RoutineId; CallOffset = $Call.CallOffset
          Source = $Source.Value; Destination = $Destination.Value
          OverwriteOrFlags = [uint32]$Integers[0].Operand
          IncludeWildcard = $Route.WildcardIndex -ge 0 ? [string]$Strings[$Route.WildcardIndex].Operand : $null
          ExcludeWildcard = $Route.ExcludeIndex -ge 0 ? [string]$Strings[$Route.ExcludeIndex].Operand : $null
          ConditionExpression = $ConditionExpression; Condition = $Condition
          UnresolvedMacros = [string[]]@($Source.UnresolvedMacros + $Destination.UnresolvedMacros | Sort-Object -Unique)
        })
    }
  }
  $Conditional = @($Operations | Where-Object { $null -eq $_.Condition -or $_.UnresolvedMacros.Count -gt 0 })
  if ($Conditional.Count) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.ArchiveOperation.Conditional' -Source CreateInstall -Message "$($Conditional.Count) CreateInstall nested-archive operation(s) depend on runtime conditions or macros." -Kind Ambiguous -Areas Extraction -Evidence $Conditional)) }
  if ($Operations.Count) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.ArchiveOperation.NestedPayload' -Source CreateInstall -Message "CreateInstall expands $($Operations.Count) nested archive(s); their contents are not part of the outer GEA catalog." -Kind Information -Areas Extraction -Evidence $Operations.ToArray())) }
  return [pscustomobject]@{ ArchiveOperations = $Operations.ToArray(); Diagnostics = $Diagnostics.ToArray() }
}

function Get-CreateInstallConfigurationEvidence {
  <#
  .SYNOPSIS
    Recover source-backed CreateInstall INI value writes and deletions.
  .PARAMETER Program
    Decoded GE program whose imported profile APIs distinguish INI operation routes.
  .PARAMETER ProjectVariableEvidence
    MAINVAR variables and g_list bytes used to resolve paths, values, and conditions.
  .PARAMETER Is32Bit
    Indicates the Windows folder view used while resolving CreateInstall macros.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Program,
    [Parameter(Mandatory)][psobject]$ProjectVariableEvidence,
    [Parameter(Mandatory)][bool]$Is32Bit
  )

  $Changes = [Collections.Generic.List[object]]::new()
  $Diagnostics = [Collections.Generic.List[object]]::new()
  foreach ($Route in @(
      [pscustomobject]@{ Profile = 'IniSet6'; Operation = 'Set'; FieldCount = 5; ConditionIndex = 2; ValueIndex = 1 }
      [pscustomobject]@{ Profile = 'IniDelete6'; Operation = 'Delete'; FieldCount = 3; ConditionIndex = 1; ValueIndex = -1 }
    )) {
    $Targets = [uint32[]]@(Find-CreateInstallOperationRoutine -Program $Program -ProfileId $Route.Profile | ForEach-Object { [uint32]$_.Record.Id })
    foreach ($Call in @(Get-CreateInstallRoutineCallSite -Program $Program -TargetId $Targets -MaximumLookback 96)) {
      $Strings = @($Call.Window | Where-Object Command -EQ 34 | Select-Object -Last 3)
      $Integers = @($Call.Window | Where-Object { $_.Command -in @(25, 26, 27) -and $_.Operand -is [ValueType] } | Select-Object -Last 3)
      if ($Strings.Count -ne 3 -or $Integers.Count -ne 3 -or [uint32]$Integers[1].Operand -notin 0, 1 -or [uint32]$Integers[2].Operand -notin 0, 1) { continue }
      $ListOffset = [uint32]$Integers[0].Operand
      try { $Rows = @(ConvertFrom-CreateInstallGenteeList -Bytes $ProjectVariableEvidence.BufferData -Offset ([int]$ListOffset) -FieldCount $Route.FieldCount) } catch { continue }
      $FilePath = Join-CreateInstallMacroPath -Parent ([string]$Strings[0].Operand) -Child ([string]$Strings[1].Operand) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
      $Section = Resolve-CreateInstallMacroValue -Value ([string]$Strings[2].Operand) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
      foreach ($Row in $Rows) {
        $ConditionExpression = [string]$Row.Fields[$Route.ConditionIndex]
        $Condition = Resolve-CreateInstallCondition -Expression $ConditionExpression -Variables $ProjectVariableEvidence.Variables
        if ($Condition -eq $false) { continue }
        $Key = Resolve-CreateInstallMacroValue -Value ([string]$Row.Fields[0]) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
        $Value = $Route.ValueIndex -ge 0 ? (Resolve-CreateInstallMacroValue -Value ([string]$Row.Fields[$Route.ValueIndex]) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit) : $null
        $Changes.Add([pscustomobject][ordered]@{
            Operation = $Route.Operation; CallerId = $Call.CallerId; RoutineId = $Call.RoutineId; CallOffset = $Call.CallOffset; ListOffset = $ListOffset; RowIndex = $Row.Index
            FilePath = $FilePath.Value; Section = $Section.Value; Key = $Key.Value; Value = $null -ne $Value ? $Value.Value : $null
            Utf = [uint32]$Integers[1].Operand -eq 1; WriteBom = [uint32]$Integers[2].Operand -eq 1
            ConditionExpression = $ConditionExpression; Condition = $Condition
            UnresolvedMacros = [string[]]@($FilePath.UnresolvedMacros + $Section.UnresolvedMacros + $Key.UnresolvedMacros + $(if ($null -ne $Value) { $Value.UnresolvedMacros } else { @() }) | Sort-Object -Unique)
          })
      }
    }
  }
  $Conditional = @($Changes | Where-Object { $null -eq $_.Condition -or $_.UnresolvedMacros.Count -gt 0 })
  if ($Conditional.Count) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Configuration.Conditional' -Source CreateInstall -Message "$($Conditional.Count) CreateInstall INI operation(s) depend on runtime conditions or macros." -Kind Ambiguous -Areas Metadata -Evidence $Conditional)) }
  return [pscustomobject]@{ ConfigurationChanges = $Changes.ToArray(); Diagnostics = $Diagnostics.ToArray() }
}

function Get-CreateInstallListCallEvidence {
  <#
  .SYNOPSIS
    Decode source-backed g_list rows passed to one-parameter CreateInstall runtime routines.
  .PARAMETER Program
    Decoded GE program whose cached function index contains the target and caller commands.
  .PARAMETER ProjectVariableEvidence
    MAINVAR evidence containing the initialized g_list byte buffer.
  .PARAMETER TargetId
    Object identifiers of structurally identified one-parameter list routines.
  .PARAMETER FieldCount
    Number of NUL-terminated fields in each source-defined list row.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][psobject]$Program,
    [Parameter(Mandatory)][psobject]$ProjectVariableEvidence,
    [Parameter(Mandatory)][AllowEmptyCollection()][uint32[]]$TargetId,
    [Parameter(Mandatory)][ValidateRange(1, 64)][int]$FieldCount
  )

  if ($TargetId.Count -eq 0) { return @() }
  $Targets = [Collections.Generic.HashSet[uint32]]::new($TargetId)
  $Calls = [Collections.Generic.List[object]]::new()
  foreach ($Function in (Get-CreateInstallFunctionIndex -Program $Program).Values) {
    $Commands = $Function.Commands
    for ($CommandIndex = 1; $CommandIndex -lt $Commands.Count; $CommandIndex++) {
      $RoutineId = [uint32]$Commands[$CommandIndex].Command
      if (-not $Targets.Contains($RoutineId)) { continue }

      # A generated list command passes one integer offset. Limit the backwards search to the
      # current expression and require the nearest integer literal to decode as the expected list.
      $Start = [Math]::Max(0, $CommandIndex - 16)
      $OffsetCommands = @($Commands[$Start..($CommandIndex - 1)] | Where-Object { $_.Command -in @(25, 26, 27) -and $_.Operand -is [ValueType] })
      if ($OffsetCommands.Count -eq 0) { continue }
      $ListOffset = [uint32]$OffsetCommands[-1].Operand
      try { $Rows = @(ConvertFrom-CreateInstallGenteeList -Bytes $ProjectVariableEvidence.BufferData -Offset ([int]$ListOffset) -FieldCount $FieldCount) } catch { continue }
      $Calls.Add([pscustomobject]@{
          CallerId   = [uint32]$Function.Record.Id
          RoutineId  = $RoutineId
          CallOffset = [int]$Commands[$CommandIndex].Offset
          ListOffset = $ListOffset
          Rows       = $Rows
        })
    }
  }
  return $Calls.ToArray()
}

function Get-CreateInstallEnvironmentEvidence {
  <#
  .SYNOPSIS
    Recover deterministic CreateInstall environment-variable set, append, and delete operations.
  .PARAMETER Program
    Decoded GE program returned by Get-CreateInstallGenteeProgram.
  .PARAMETER ProjectVariableEvidence
    MAINVAR variables and g_list bytes used to resolve values and list records.
  .PARAMETER Is32Bit
    Indicates the Windows folder view used while resolving CreateInstall macros.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Program,
    [Parameter(Mandatory)][psobject]$ProjectVariableEvidence,
    [Parameter(Mandatory)][bool]$Is32Bit
  )

  $Functions = Get-CreateInstallFunctionIndex -Program $Program
  # globsets writes a list of complete values. Current globappend and globdel routines have
  # source-backed literal sequences that distinguish the ordinary read/append route from the
  # delete route's additional HKCU registry read. Unknown sequences remain ambiguous.
  $SetTargets = [uint32[]]@($Functions.Values | Where-Object {
      $_.ParameterCount -eq 1 -and $_.LiteralText.Contains('Environment', [StringComparison]::Ordinal) -and -not $_.LiteralText.Contains('g_append', [StringComparison]::Ordinal)
    } | ForEach-Object { [uint32]$_.Record.Id })
  $AppendTargets = [Collections.Generic.HashSet[uint32]]::new([uint32[]]@((Find-CreateInstallOperationRoutine -Program $Program -ProfileId 'EnvironmentAppend4').Record.Id))
  $RemoveTargets = [Collections.Generic.HashSet[uint32]]::new([uint32[]]@((Find-CreateInstallOperationRoutine -Program $Program -ProfileId 'EnvironmentDelete4').Record.Id))
  $MutationTargets = [Collections.Generic.HashSet[uint32]]::new()
  foreach ($Function in $Functions.Values | Where-Object {
      $_.ParameterCount -eq 4 -and $_.LiteralText.Contains('Environment', [StringComparison]::Ordinal) -and $_.LiteralText.Contains('g_append', [StringComparison]::Ordinal)
    }) { $null = $MutationTargets.Add([uint32]$Function.Record.Id) }
  if ($SetTargets.Count -eq 0 -and $MutationTargets.Count -eq 0) { return [pscustomobject]@{ EnvironmentChanges = @(); Diagnostics = @() } }
  $Changes = [Collections.Generic.List[object]]::new()
  $Diagnostics = [Collections.Generic.List[object]]::new()

  $AddChange = {
    param([string]$Operation, [uint32]$CallerId, [uint32]$RoutineId, [int]$CallOffset, [AllowNull()][uint32]$ListOffset, [AllowNull()][int]$RowIndex, [string]$NameExpression, [string]$ValueExpression, [int]$Type, [bool]$OperationIs32Bit, [string]$ConditionExpression)
    $Condition = Resolve-CreateInstallCondition -Expression $ConditionExpression -Variables $ProjectVariableEvidence.Variables
    if ($Condition -eq $false) { return }
    $Name = Resolve-CreateInstallMacroValue -Value $NameExpression -Variables $ProjectVariableEvidence.Variables -Is32Bit $OperationIs32Bit
    $Value = Resolve-CreateInstallMacroValue -Value $ValueExpression -Variables $ProjectVariableEvidence.Variables -Is32Bit $OperationIs32Bit
    $EffectiveType = [Math]::Max(1, $Type)
    $Scopes = [Collections.Generic.List[string]]::new(2)
    if (($EffectiveType -band 1) -ne 0) { $Scopes.Add('machine') }
    if (($EffectiveType -band 2) -ne 0) { $Scopes.Add('user') }
    $Changes.Add([pscustomobject][ordered]@{
        Operation = $Operation; CallerId = $CallerId; RoutineId = $RoutineId; CallOffset = $CallOffset
        ListOffset = $ListOffset; RowIndex = $RowIndex; Name = $Name.Value; Value = $Value.Value
        Scope = $Scopes.Count -eq 2 ? 'both' : ($Scopes.Count -eq 1 ? $Scopes[0] : $null); Scopes = $Scopes.ToArray()
        ConditionExpression = $ConditionExpression; Condition = $Condition
        UnresolvedMacros = [string[]]@($Name.UnresolvedMacros + $Value.UnresolvedMacros | Sort-Object -Unique)
      })
  }

  foreach ($Call in @(Get-CreateInstallListCallEvidence -Program $Program -ProjectVariableEvidence $ProjectVariableEvidence -TargetId $SetTargets -FieldCount 5)) {
    foreach ($Row in $Call.Rows) {
      $Type = 0; [void][int]::TryParse([string]$Row.Fields[2], [ref]$Type)
      & $AddChange 'Set' $Call.CallerId $Call.RoutineId $Call.CallOffset $Call.ListOffset $Row.Index ([string]$Row.Fields[0]) ([string]$Row.Fields[1]) $Type $Is32Bit ([string]$Row.Fields[3])
    }
  }

  if ($MutationTargets.Count -gt 0) {
    foreach ($Function in $Functions.Values) {
      $Commands = $Function.Commands
      for ($CommandIndex = 1; $CommandIndex -lt $Commands.Count; $CommandIndex++) {
        $RoutineId = [uint32]$Commands[$CommandIndex].Command
        if (-not $MutationTargets.Contains($RoutineId)) { continue }
        $Window = @($Commands[[Math]::Max(0, $CommandIndex - 48)..($CommandIndex - 1)])
        $Strings = @($Window | Where-Object Command -EQ 34 | Select-Object -Last 3)
        $Integers = @($Window | Where-Object { $_.Command -in @(25, 26, 27) -and $_.Operand -is [ValueType] } | Select-Object -Last 1)
        if ($Strings.Count -ne 3 -or $Integers.Count -ne 1) { continue }
        $Operation = if ($AppendTargets.Contains($RoutineId)) { 'Append' } elseif ($RemoveTargets.Contains($RoutineId)) { 'Remove' } else { 'AppendOrRemove' }
        & $AddChange $Operation ([uint32]$Function.Record.Id) $RoutineId ([int]$Commands[$CommandIndex].Offset) $null $null ([string]$Strings[0].Operand) ([string]$Strings[1].Operand) ([int][uint32]$Integers[0].Operand) $Is32Bit ([string]$Strings[2].Operand)
      }
    }
  }

  $Conditional = @($Changes | Where-Object { $null -eq $_.Condition -or $_.UnresolvedMacros.Count -gt 0 })
  if ($Conditional.Count) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Environment.Conditional' -Source CreateInstall -Message "$($Conditional.Count) CreateInstall environment-variable operation(s) depend on runtime conditions or macros." -Kind Ambiguous -Areas Metadata -Evidence $Conditional)) }
  $AmbiguousMutations = @($Changes | Where-Object Operation -EQ 'AppendOrRemove')
  if ($AmbiguousMutations.Count) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Environment.AppendDeleteAmbiguous' -Source CreateInstall -Message "$($AmbiguousMutations.Count) CreateInstall environment-variable mutation(s) use an unrecognized compiled routine and may append or remove a value." -Kind Ambiguous -Areas Metadata -Evidence $AmbiguousMutations)) }
  return [pscustomobject]@{ EnvironmentChanges = $Changes.ToArray(); Diagnostics = $Diagnostics.ToArray() }
}

function Get-CreateInstallPrerequisiteEvidence {
  <#
  .SYNOPSIS
    Recover source-backed Visual C++ redistributable checks from compiled CreateInstall commands.
  .PARAMETER Program
    Decoded GE program returned by Get-CreateInstallGenteeProgram.
  .PARAMETER ProjectVariableEvidence
    MAINVAR variables used to resolve conditions and diagnostic text.
  .PARAMETER Is32Bit
    Indicates the Windows folder view used while resolving CreateInstall macros.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Program,
    [Parameter(Mandatory)][psobject]$ProjectVariableEvidence,
    [Parameter(Mandatory)][bool]$Is32Bit
  )

  $Functions = Get-CreateInstallFunctionIndex -Program $Program
  $Targets = [Collections.Generic.HashSet[uint32]]::new([uint32[]]@($Functions.Values | Where-Object {
        $_.ParameterCount -eq 6 -and $_.LiteralText.Contains('SOFTWARE\Classes\Installer\Products\', [StringComparison]::OrdinalIgnoreCase) -and $_.LiteralText.Contains('RuntimeMinimum', [StringComparison]::OrdinalIgnoreCase)
      } | ForEach-Object { [uint32]$_.Record.Id }))
  if ($Targets.Count -eq 0) { return [pscustomobject]@{ PrerequisiteChecks = @(); Diagnostics = @() } }
  $Checks = [Collections.Generic.List[object]]::new()
  $Diagnostics = [Collections.Generic.List[object]]::new()
  $Years = [string[]]@('2005', '2008', '2010', '2012', '2013', '2015', '2017', '2019')

  foreach ($Function in $Functions.Values) {
    $Commands = $Function.Commands
    for ($CommandIndex = 1; $CommandIndex -lt $Commands.Count; $CommandIndex++) {
      $RoutineId = [uint32]$Commands[$CommandIndex].Command
      if (-not $Targets.Contains($RoutineId)) { continue }
      $Strings = @($Commands[[Math]::Max(0, $CommandIndex - 80)..($CommandIndex - 1)] | Where-Object Command -EQ 34 | Select-Object -Last 6)
      if ($Strings.Count -ne 6) { continue }
      $Selection = [string]$Strings[1].Operand
      if ($Selection -notmatch '^[01]{8}$' -or [string]$Strings[0].Operand -notin 'x32', 'x64' -or [string]$Strings[2].Operand -notin 'and', 'or') { continue }
      $ConditionExpression = [string]$Strings[5].Operand
      $Condition = Resolve-CreateInstallCondition -Expression $ConditionExpression -Variables $ProjectVariableEvidence.Variables
      if ($Condition -eq $false) { continue }
      $SelectedYears = [Collections.Generic.List[string]]::new()
      for ($Index = 0; $Index -lt $Selection.Length; $Index++) { if ($Selection[$Index] -eq '1') { $SelectedYears.Add($Years[$Index]) } }
      if ($SelectedYears.Count -eq 0) { continue }
      $DependencyCandidates = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
      $ArchitectureSuffix = [string]$Strings[0].Operand -eq 'x64' ? 'x64' : 'x86'
      foreach ($Year in $SelectedYears) {
        $Identifier = if ([int]$Year -ge 2015) { "Microsoft.VCRedist.2015+.$ArchitectureSuffix" } else { "Microsoft.VCRedist.$Year.$ArchitectureSuffix" }
        $null = $DependencyCandidates.Add($Identifier)
      }
      $Message = Resolve-CreateInstallMacroValue -Value ([string]$Strings[4].Operand) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
      $Checks.Add([pscustomobject][ordered]@{
          Kind = 'VisualCRedistributable'; CallerId = [uint32]$Function.Record.Id; RoutineId = $RoutineId; CallOffset = [int]$Commands[$CommandIndex].Offset
          Architecture = $ArchitectureSuffix; Versions = $SelectedYears.ToArray(); Combination = [string]$Strings[2].Operand; PackageDependencyCandidates = [string[]]@($DependencyCandidates | Sort-Object)
          ResultVariable = [string]$Strings[3].Operand; FailureMessage = $Message.Value; MayAbortInstallation = -not [string]::IsNullOrWhiteSpace([string]$Message.Value)
          ConditionExpression = $ConditionExpression; Condition = $Condition; UnresolvedMacros = [string[]]$Message.UnresolvedMacros
        })
    }
  }

  if ($Checks.Count) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Prerequisite.VisualCpp' -Source CreateInstall -Message "CreateInstall checks $($Checks.Count) Visual C++ redistributable requirement set(s); these are dependency evidence and may control installation." -Kind ManualValidation -Areas Installability -AffectedFields Dependencies -Evidence $Checks.ToArray())) }
  return [pscustomobject]@{ PrerequisiteChecks = $Checks.ToArray(); Diagnostics = $Diagnostics.ToArray() }
}

function Get-CreateInstallServiceEvidence {
  <#
  .SYNOPSIS
    Recover deterministic CreateInstall Windows-service creation calls.
  .PARAMETER Program
    Decoded GE program returned by Get-CreateInstallGenteeProgram.
  .PARAMETER ProjectVariableEvidence
    MAINVAR variables used to resolve service paths and conditions.
  .PARAMETER Is32Bit
    Indicates the Windows folder view used while resolving CreateInstall macros.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Program,
    [Parameter(Mandatory)][psobject]$ProjectVariableEvidence,
    [Parameter(Mandatory)][bool]$Is32Bit
  )

  $Functions = Get-CreateInstallFunctionIndex -Program $Program
  $CreateCoreIds = [Collections.Generic.HashSet[uint32]]::new([uint32[]]@($Functions.Values | Where-Object {
        $_.ParameterCount -eq 6 -and $_.LiteralText.Contains('System\CurrentControlSet\Services\', [StringComparison]::OrdinalIgnoreCase)
      } | ForEach-Object { [uint32]$_.Record.Id }))
  $Targets = [Collections.Generic.HashSet[uint32]]::new([uint32[]]@($Functions.Values | Where-Object {
        $_.ParameterCount -eq 7 -and @($_.Commands | Where-Object { $CreateCoreIds.Contains([uint32]$_.Command) }).Count -gt 0
      } | ForEach-Object { [uint32]$_.Record.Id }))
  $Services = [Collections.Generic.List[object]]::new()
  $Diagnostics = [Collections.Generic.List[object]]::new()

  foreach ($Function in $Functions.Values) {
    $Commands = $Function.Commands
    for ($CommandIndex = 1; $CommandIndex -lt $Commands.Count; $CommandIndex++) {
      $RoutineId = [uint32]$Commands[$CommandIndex].Command
      if (-not $Targets.Contains($RoutineId)) { continue }
      $Window = @($Commands[[Math]::Max(0, $CommandIndex - 96)..($CommandIndex - 1)])
      $Strings = @($Window | Where-Object Command -EQ 34 | Select-Object -Last 6)
      $Integers = @($Window | Where-Object { $_.Command -in @(25, 26, 27) -and $_.Operand -is [ValueType] } | Select-Object -Last 2)
      if ($Strings.Count -ne 6 -or $Integers.Count -ne 2) { continue }
      $StartTypeValue = [uint32]$Integers[0].Operand
      $NoRunValue = [uint32]$Integers[1].Operand
      if ($StartTypeValue -notin 2, 3, 4 -or $NoRunValue -notin 0, 1) { continue }
      $ConditionExpression = [string]$Strings[5].Operand
      $Condition = Resolve-CreateInstallCondition -Expression $ConditionExpression -Variables $ProjectVariableEvidence.Variables
      if ($Condition -eq $false) { continue }
      $Path = Join-CreateInstallMacroPath -Parent ([string]$Strings[0].Operand) -Child ([string]$Strings[1].Operand) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
      $Name = Resolve-CreateInstallMacroValue -Value ([string]$Strings[2].Operand) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
      $DisplayName = Resolve-CreateInstallMacroValue -Value ([string]$Strings[3].Operand) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
      $Description = Resolve-CreateInstallMacroValue -Value ([string]$Strings[4].Operand) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
      $Services.Add([pscustomobject][ordered]@{
          Operation = 'Create'; CallerId = [uint32]$Function.Record.Id; RoutineId = $RoutineId; CallOffset = [int]$Commands[$CommandIndex].Offset
          Name = $Name.Value; DisplayName = $DisplayName.Value; Description = $Description.Value; BinaryPath = $Path.Value
          ServiceType = 'Win32OwnProcess'; StartType = @('Boot', 'System', 'Automatic', 'Manual', 'Disabled')[$StartTypeValue]
          StartAfterInstall = $NoRunValue -eq 0; ConditionExpression = $ConditionExpression; Condition = $Condition
          UnresolvedMacros = [string[]]@($Path.UnresolvedMacros + $Name.UnresolvedMacros + $DisplayName.UnresolvedMacros + $Description.UnresolvedMacros | Sort-Object -Unique)
        })
    }
  }

  # The Start/Stop and Delete project commands are generated inline. Identify their target helpers
  # by exact service-control API imports, then accept only calls from zero-parameter generated event
  # functions with the source-defined condition/name literal pair. Calls between runtime helpers are
  # excluded because their arguments are computed values rather than project fields.
  foreach ($Route in @(
      [pscustomobject]@{ Profile = 'ServiceStart1'; Operation = 'Start' }
      [pscustomobject]@{ Profile = 'ServiceStop1'; Operation = 'Stop' }
      [pscustomobject]@{ Profile = 'ServiceDelete1'; Operation = 'Delete' }
    )) {
    $ActionTargets = [uint32[]]@(Find-CreateInstallOperationRoutine -Program $Program -ProfileId $Route.Profile | ForEach-Object { [uint32]$_.Record.Id })
    foreach ($Call in @(Get-CreateInstallRoutineCallSite -Program $Program -TargetId $ActionTargets -MaximumLookback 48)) {
      if (-not $Functions.ContainsKey([uint32]$Call.CallerId) -or $Functions[[uint32]$Call.CallerId].ParameterCount -ne 0) { continue }
      $Strings = @($Call.Window | Where-Object Command -EQ 34 | Select-Object -Last 2)
      if ($Strings.Count -ne 2) { continue }
      $ConditionExpression = [string]$Strings[0].Operand
      $Condition = Resolve-CreateInstallCondition -Expression $ConditionExpression -Variables $ProjectVariableEvidence.Variables
      if ($Condition -eq $false) { continue }
      $Name = Resolve-CreateInstallMacroValue -Value ([string]$Strings[1].Operand) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
      if ([string]::IsNullOrWhiteSpace([string]$Name.Value)) { continue }
      $Services.Add([pscustomobject][ordered]@{
          Operation = $Route.Operation; CallerId = $Call.CallerId; RoutineId = $Call.RoutineId; CallOffset = $Call.CallOffset
          Name = $Name.Value; DisplayName = $null; Description = $null; BinaryPath = $null; ServiceType = $null; StartType = $null; StartAfterInstall = $null
          ConditionExpression = $ConditionExpression; Condition = $Condition; UnresolvedMacros = [string[]]$Name.UnresolvedMacros
        })
    }
  }
  $Conditional = @($Services | Where-Object { $null -eq $_.Condition -or $_.UnresolvedMacros.Count -gt 0 })
  if ($Conditional.Count) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Service.Conditional' -Source CreateInstall -Message "$($Conditional.Count) CreateInstall service operation(s) depend on runtime conditions or macros." -Kind Ambiguous -Areas Metadata, Installability -Evidence $Conditional)) }
  return [pscustomobject]@{ Services = $Services.ToArray(); Diagnostics = $Diagnostics.ToArray() }
}

function Get-CreateInstallRegistrationEvidence {
  <#
  .SYNOPSIS
    Recover CreateInstall font, COM/ActiveX, type-library, and .NET assembly registrations.
  .PARAMETER Program
    Decoded GE program returned by Get-CreateInstallGenteeProgram.
  .PARAMETER ProjectVariableEvidence
    MAINVAR variables and g_list bytes used to resolve registration rows.
  .PARAMETER Is32Bit
    Indicates the Windows folder view used while resolving CreateInstall macros.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Program,
    [Parameter(Mandatory)][psobject]$ProjectVariableEvidence,
    [Parameter(Mandatory)][bool]$Is32Bit
  )

  $Functions = Get-CreateInstallFunctionIndex -Program $Program
  $RegistrationProfiles = @(
    [pscustomobject]@{ Kind = 'Font'; Marker = 'CurrentVersion\Fonts'; SecondaryMarker = 'Windows NT'; FieldCount = 6 }
    [pscustomobject]@{ Kind = 'Com'; Marker = 'regsvr32.exe'; SecondaryMarker = 'isdllok'; FieldCount = 6 }
    [pscustomobject]@{ Kind = 'DotNetAssembly'; Marker = 'RegAsm.exe'; SecondaryMarker = '/codebase'; FieldCount = 6 }
  )
  $Registrations = [Collections.Generic.List[object]]::new()
  $Diagnostics = [Collections.Generic.List[object]]::new()
  foreach ($RegistrationProfile in $RegistrationProfiles) {
    $Targets = [uint32[]]@($Functions.Values | Where-Object {
        $_.ParameterCount -eq 1 -and $_.LiteralText.Contains($RegistrationProfile.Marker, [StringComparison]::OrdinalIgnoreCase) -and $_.LiteralText.Contains($RegistrationProfile.SecondaryMarker, [StringComparison]::OrdinalIgnoreCase)
      } | ForEach-Object { [uint32]$_.Record.Id })
    foreach ($Call in @(Get-CreateInstallListCallEvidence -Program $Program -ProjectVariableEvidence $ProjectVariableEvidence -TargetId $Targets -FieldCount $RegistrationProfile.FieldCount)) {
      foreach ($Row in $Call.Rows) {
        $ConditionIndex = $RegistrationProfile.Kind -eq 'Font' ? 4 : ($RegistrationProfile.Kind -eq 'Com' ? 3 : 4)
        $ConditionExpression = [string]$Row.Fields[$ConditionIndex]
        $Condition = Resolve-CreateInstallCondition -Expression $ConditionExpression -Variables $ProjectVariableEvidence.Variables
        if ($Condition -eq $false) { continue }
        $Path = Join-CreateInstallMacroPath -Parent ([string]$Row.Fields[0]) -Child ([string]$Row.Fields[1]) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
        $Common = [ordered]@{
          Kind = $RegistrationProfile.Kind; CallerId = $Call.CallerId; RoutineId = $Call.RoutineId; CallOffset = $Call.CallOffset; ListOffset = $Call.ListOffset; RowIndex = $Row.Index
          Path = $Path.Value; ConditionExpression = $ConditionExpression; Condition = $Condition; UnresolvedMacros = [string[]]$Path.UnresolvedMacros
        }
        if ($RegistrationProfile.Kind -eq 'Font') {
          $Common['Name'] = [string]::IsNullOrWhiteSpace([string]$Row.Fields[2]) ? [IO.Path]::GetFileNameWithoutExtension([string]$Row.Fields[1]) : [string]$Row.Fields[2]
          $Common['Permanent'] = [string]$Row.Fields[3] -notin '', '0', 'false'
        } elseif ($RegistrationProfile.Kind -eq 'Com') {
          $Common['RegistrationMethod'] = [string]$Row.Fields[2] -notin '', '0', 'false' ? 'RegSvr32' : ([IO.Path]::GetExtension([string]$Path.Value) -ieq '.tlb' ? 'TypeLibrary' : 'InProcess')
          $Common['ResultVariable'] = [string]$Row.Fields[4]
        } else {
          $FrameworkIndex = 0; [void][int]::TryParse([string]$Row.Fields[2], [ref]$FrameworkIndex)
          $Common['Framework'] = @('', '.NET Framework 2.0/3.0/3.5 x86', '.NET Framework 4.x x86', '.NET Framework 2.0/3.0/3.5 x64', '.NET Framework 4.x x64')[[Math]::Min([Math]::Max($FrameworkIndex, 0), 4)]
          $Common['Arguments'] = [string]$Row.Fields[3]
        }
        $Registrations.Add([pscustomobject]$Common)
      }
    }
  }
  $Conditional = @($Registrations | Where-Object { $null -eq $_.Condition -or $_.UnresolvedMacros.Count -gt 0 })
  if ($Conditional.Count) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Registration.Conditional' -Source CreateInstall -Message "$($Conditional.Count) CreateInstall registration operation(s) depend on runtime conditions or macros." -Kind Ambiguous -Areas Metadata -Evidence $Conditional)) }
  return [pscustomobject]@{ Registrations = $Registrations.ToArray(); Diagnostics = $Diagnostics.ToArray() }
}

function Get-CreateInstallGenteeExpressionEvidence {
  <#
  .SYNOPSIS
    Describe one unresolved CreateInstall condition and the bounded GE function it references.
  .PARAMETER Program
    Decoded GE program containing the function and command records.
  .PARAMETER Variables
    Compiled MAINVAR dictionary used to attach known values to referenced variable names.
  .PARAMETER Is32Bit
    Indicates the shell-folder view used when resolving known CreateInstall macros.
  .PARAMETER Operation
    Installer operation guarded by the expression, such as InstallGroup, Registry, Shortcut, or Run.
  .PARAMETER Expression
    Literal condition passed to CreateInstall's ifcondition routine.
  .PARAMETER CallerId
    GE object identifier of the function that invokes the guarded operation.
  .PARAMETER CallOffset
    GE-program-relative bytecode offset of the guarded operation call.
  .PARAMETER AffectedFields
    Metadata fields whose interpretation can change with the condition result.
  .PARAMETER Context
    Bounded operation-specific values needed to understand what the condition controls.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Program,
    [Parameter(Mandatory)][System.Collections.IDictionary]$Variables,
    [Parameter(Mandatory)][bool]$Is32Bit,
    [Parameter(Mandatory)][string]$Operation,
    [Parameter(Mandatory)][string]$Expression,
    [AllowNull()][Nullable[uint32]]$CallerId,
    [AllowNull()][Nullable[int]]$CallOffset,
    [AllowNull()][string[]]$AffectedFields,
    [AllowNull()][object]$Context
  )

  $Functions = Get-CreateInstallFunctionIndex -Program $Program
  $ConditionText = $Expression.Trim()
  $Negated = $ConditionText.StartsWith('!', [StringComparison]::Ordinal)
  if ($Negated) { $ConditionText = $ConditionText.Substring(1) }
  $IsFunction = $ConditionText.StartsWith('@', [StringComparison]::Ordinal)
  $FunctionName = $IsFunction ? $ConditionText.Substring(1) : $null
  $FunctionMatches = if ($IsFunction) { @($Functions.Values | Where-Object { $_.Record.Name -ceq $FunctionName }) } else { @() }
  $Function = $FunctionMatches.Count -eq 1 ? $FunctionMatches[0] : $null

  # The command list is bounded. It gives an agent enough static evidence to trace
  # small generated if-functions without turning Get-*Info into an unbounded bytecode dump.
  $FunctionEvidence = $null
  $LiteralStrings = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  if ($null -ne $Function) {
    $CommandLimit = 256
    $Commands = [Collections.Generic.List[object]]::new([Math]::Min($Function.Commands.Count, $CommandLimit))
    $CalledFunctions = [Collections.Generic.List[object]]::new()
    $CalledIds = [Collections.Generic.HashSet[uint32]]::new()
    for ($CommandIndex = 0; $CommandIndex -lt [Math]::Min($Function.Commands.Count, $CommandLimit); $CommandIndex++) {
      $Command = $Function.Commands[$CommandIndex]
      $Commands.Add([pscustomobject]@{ Index = $Command.Index; Offset = $Command.Offset; Opcode = $Command.Command; Operand = $Command.Operand })
      if ($Command.Command -eq 34 -and $Command.Operand -is [string]) { $null = $LiteralStrings.Add([string]$Command.Operand) }
      $TargetId = [uint32]$Command.Command
      if ($Functions.ContainsKey($TargetId) -and $CalledIds.Add($TargetId)) {
        $Target = $Functions[$TargetId]
        $CalledFunctions.Add([pscustomobject]@{ ObjectId = $TargetId; Name = $Target.Record.Name; ParameterCount = $Target.ParameterCount })
      }
    }
    $FunctionEvidence = [pscustomobject][ordered]@{
      Name              = $FunctionName
      ObjectId          = [uint32]$Function.Record.Id
      ParameterCount    = [uint32]$Function.ParameterCount
      RecordOffset      = [int]$Function.Record.Offset
      RecordSize        = [int]$Function.Record.Size
      CommandCount      = [int]$Function.Commands.Count
      CommandsTruncated = $Function.Commands.Count -gt $CommandLimit
      LiteralStrings    = [string[]]@($LiteralStrings | Sort-Object)
      CalledFunctions   = $CalledFunctions.ToArray()
      Commands          = $Commands.ToArray()
    }
  }

  # Direct #name# conditions have one exact dependency. For @function conditions, identifier-like
  # string literals are candidate runtime variables because generated predicates commonly call
  # defmacro accessors with names such as oswindows. Candidate status is explicit to avoid assigning
  # semantics to unrelated function literals.
  $VariableNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($Match in [regex]::Matches($Expression, '#(?<Name>[^#]+)#')) { $null = $VariableNames.Add($Match.Groups['Name'].Value) }
  if (-not $IsFunction) {
    $VariableName = $ConditionText.Trim('#')
    if (-not [string]::IsNullOrWhiteSpace($VariableName)) { $null = $VariableNames.Add($VariableName) }
  } else {
    foreach ($Literal in $LiteralStrings) {
      if ($Literal -match '^[A-Za-z_][A-Za-z0-9_.-]*$') { $null = $VariableNames.Add($Literal) }
      foreach ($Match in [regex]::Matches($Literal, '#(?<Name>[^#]+)#')) { $null = $VariableNames.Add($Match.Groups['Name'].Value) }
    }
  }

  # Follow macro references in known project values so the result contains the complete value chain
  # needed to judge a condition, while retaining runtime-only names as unknown evidence.
  $PendingNames = [Collections.Generic.Queue[string]]::new()
  foreach ($VariableName in $VariableNames) { $PendingNames.Enqueue($VariableName) }
  $VisitedNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $VariableEvidence = [Collections.Generic.List[object]]::new()
  while ($PendingNames.Count -gt 0) {
    $VariableName = $PendingNames.Dequeue()
    if (-not $VisitedNames.Add($VariableName)) { continue }
    $Token = Resolve-CreateInstallMacroValue -Value "#$VariableName#" -Variables $Variables -Is32Bit $Is32Bit
    if ($Variables.Contains($VariableName)) {
      $RawValue = [string]$Variables[$VariableName]
      $VariableEvidence.Add([pscustomobject]@{ Name = $VariableName; Source = 'ProjectVariable'; Value = $RawValue; ResolvedValue = $Token.Value; IsDefined = $true })
      foreach ($Match in [regex]::Matches($RawValue, '#(?<Name>[^#]+)#')) { $PendingNames.Enqueue($Match.Groups['Name'].Value) }
    } elseif ($Token.UnresolvedMacros -notcontains $VariableName) {
      $VariableEvidence.Add([pscustomobject]@{ Name = $VariableName; Source = 'KnownMacro'; Value = $null; ResolvedValue = $Token.Value; IsDefined = $true })
    } else {
      $VariableEvidence.Add([pscustomobject]@{ Name = $VariableName; Source = 'RuntimeOrUnknown'; Value = $null; ResolvedValue = $null; IsDefined = $false })
    }
  }

  return [pscustomobject][ordered]@{
    Operation          = $Operation
    Expression         = $Expression
    ExpressionKind     = $IsFunction ? 'FunctionCondition' : 'VariableCondition'
    Negated            = $Negated
    Evaluation         = $null
    RequiresReview     = $true
    CallerId           = $CallerId
    CallOffset         = $CallOffset
    AffectedFields     = [string[]]@($AffectedFields)
    Variables          = @($VariableEvidence | Sort-Object Name)
    ReferencedFunction = $FunctionEvidence
    FunctionFound      = $FunctionMatches.Count -eq 1
    Context            = $Context
  }
}

function Get-CreateInstallShortcutEvidence {
  <#
  .SYNOPSIS
    Recover direct shortcutex calls and compiled shlist table operations.
  .PARAMETER Program
    Decoded GE program returned by Get-CreateInstallGenteeProgram.
  .PARAMETER ProjectVariableEvidence
    MAINVAR variables and g_list bytes used to resolve paths, conditions, and list records.
  .PARAMETER Is32Bit
    Indicates the Windows folder view used by the setup process.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Program,
    [Parameter(Mandatory)][psobject]$ProjectVariableEvidence,
    [Parameter(Mandatory)][bool]$Is32Bit
  )

  $Functions = Get-CreateInstallFunctionIndex -Program $Program
  # shortcutex has eight parameters and delegates to a seven-parameter shortcut helper. shlist has
  # one parameter and names all eight source-backed row fields in its own bytecode. These structural
  # signatures survive stripped function names and avoid relying on link-time object identifiers.
  $CoreIds = [Collections.Generic.HashSet[uint32]]::new()
  foreach ($Function in $Functions.Values) { if ($Function.ParameterCount -eq 7) { $null = $CoreIds.Add([uint32]$Function.Record.Id) } }
  $DirectTargets = [Collections.Generic.HashSet[uint32]]::new()
  foreach ($Function in @($Functions.Values | Where-Object { $_.ParameterCount -eq 8 -and @($_.Commands | Where-Object { $CoreIds.Contains([uint32]$_.Command) }).Count -gt 0 })) { $null = $DirectTargets.Add([uint32]$Function.Record.Id) }
  $ListTargets = [Collections.Generic.HashSet[uint32]]::new()
  foreach ($Function in @($Functions.Values | Where-Object {
        $_.ParameterCount -eq 1 -and $_.LiteralText.Contains('shpath', [StringComparison]::Ordinal) -and $_.LiteralText.Contains('shfile', [StringComparison]::Ordinal) -and $_.LiteralText.Contains('cmdline', [StringComparison]::Ordinal) -and $_.LiteralText.Contains('defwork', [StringComparison]::Ordinal)
      })) { $null = $ListTargets.Add([uint32]$Function.Record.Id) }
  if ($DirectTargets.Count -eq 0 -and $ListTargets.Count -eq 0) { return [pscustomobject]@{ Calls = @(); Diagnostics = @() } }

  $Calls = [Collections.Generic.List[object]]::new()
  $Diagnostics = [Collections.Generic.List[object]]::new()
  foreach ($Function in $Functions.Values) {
    $Commands = $Function.Commands
    for ($CommandIndex = 0; $CommandIndex -lt $Commands.Count; $CommandIndex++) {
      $TargetId = [uint32]$Commands[$CommandIndex].Command
      if ($DirectTargets.Contains($TargetId)) {
        # The command generator starts from ten project fields: shortcut path/name, target
        # path/name, arguments, comment, icon, working path/name, and condition.
        $Start = [Math]::Max(0, $CommandIndex - 96)
        $Window = @($Commands[$Start..($CommandIndex - 1)])
        $Strings = @($Window | Where-Object Command -EQ 34 | Select-Object -Last 10)
        $Integers = @($Window | Where-Object { $_.Command -in @(25, 26, 27) -and $_.Operand -is [ValueType] } | Select-Object -Last 1)
        if ($Strings.Count -ne 10 -or $Integers.Count -ne 1) { continue }
        $ConditionExpression = [string]$Strings[9].Operand
        $Condition = Resolve-CreateInstallCondition -Expression $ConditionExpression -Variables $ProjectVariableEvidence.Variables
        if ($Condition -eq $false) { continue }
        $Shortcut = Join-CreateInstallMacroPath -Parent ([string]$Strings[0].Operand) -Child ([string]$Strings[1].Operand) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
        $Target = Join-CreateInstallMacroPath -Parent ([string]$Strings[2].Operand) -Child ([string]$Strings[3].Operand) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
        $Arguments = Resolve-CreateInstallMacroValue -Value ([string]$Strings[4].Operand) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
        $Comment = Resolve-CreateInstallMacroValue -Value ([string]$Strings[5].Operand) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
        $Icon = Resolve-CreateInstallMacroValue -Value ([string]$Strings[6].Operand) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
        $WorkingDirectory = Join-CreateInstallMacroPath -Parent ([string]$Strings[7].Operand) -Child ([string]$Strings[8].Operand) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
        $ShortcutPath = [string]$Shortcut.Value
        if ([IO.Path]::GetExtension($ShortcutPath) -notin '.lnk', '.pif') { $ShortcutPath += '.lnk' }
        $Calls.Add([pscustomobject][ordered]@{
            Route = 'Direct'; CallerId = $Function.Record.Id; RoutineId = $TargetId; CallOffset = $Commands[$CommandIndex].Offset
            ShortcutPath = $ShortcutPath; TargetPath = $Target.Value; Arguments = $Arguments.Value
            Comment = $Comment.Value; Icon = $Icon.Value; WorkingDirectory = $WorkingDirectory.Value
            ShowCommand = [uint32]$Integers[0].Operand; ConditionExpression = $ConditionExpression; Condition = $Condition
            UnresolvedMacros = [string[]]@($Shortcut.UnresolvedMacros + $Target.UnresolvedMacros + $Arguments.UnresolvedMacros + $Comment.UnresolvedMacros + $WorkingDirectory.UnresolvedMacros + $Icon.UnresolvedMacros | Sort-Object -Unique)
          })
        continue
      }
      if (-not $ListTargets.Contains($TargetId)) { continue }

      # shlist receives one g_list offset. Each row is ten NUL-terminated UTF-8 fields; the final
      # field is retained by the project format but ignored by the source runtime.
      $Start = [Math]::Max(0, $CommandIndex - 16)
      $OffsetCommands = @($Commands[$Start..($CommandIndex - 1)] | Where-Object { $_.Command -in @(25, 26, 27) -and $_.Operand -is [ValueType] })
      if ($OffsetCommands.Count -eq 0) { continue }
      $ListOffset = [uint32]$OffsetCommands[-1].Operand
      try { $Rows = @(ConvertFrom-CreateInstallGenteeList -Bytes $ProjectVariableEvidence.BufferData -Offset ([int]$ListOffset) -FieldCount 10) } catch {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Shortcut.ListMalformed' -Source CreateInstall -Message "A compiled CreateInstall shortcut list is malformed: $($_.Exception.Message)" -Kind Invalid -Areas Metadata -Evidence @{ CallerId = $Function.Record.Id; Offset = $ListOffset }))
        continue
      }
      foreach ($Row in $Rows) {
        $ConditionExpression = [string]$Row.Fields[8]
        $Condition = Resolve-CreateInstallCondition -Expression $ConditionExpression -Variables $ProjectVariableEvidence.Variables
        if ($Condition -eq $false) { continue }
        $Shortcut = Join-CreateInstallMacroPath -Parent ([string]$Row.Fields[0]) -Child ([string]$Row.Fields[1]) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
        $Target = Join-CreateInstallMacroPath -Parent ([string]$Row.Fields[2]) -Child ([string]$Row.Fields[3]) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
        $Arguments = Resolve-CreateInstallMacroValue -Value ([string]$Row.Fields[4]) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
        $Icon = Resolve-CreateInstallMacroValue -Value ([string]$Row.Fields[5]) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
        $WorkingDirectory = Join-CreateInstallMacroPath -Parent ([string]$Row.Fields[6]) -Child ([string]$Row.Fields[7]) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
        $ShortcutPath = [string]$Shortcut.Value
        if ([IO.Path]::GetExtension($ShortcutPath) -notin '.lnk', '.pif') { $ShortcutPath += '.lnk' }
        $Calls.Add([pscustomobject][ordered]@{
            Route = 'List'; CallerId = $Function.Record.Id; RoutineId = $TargetId; CallOffset = $Commands[$CommandIndex].Offset; ListOffset = $ListOffset; RowIndex = $Row.Index
            ShortcutPath = $ShortcutPath; TargetPath = $Target.Value; Arguments = $Arguments.Value
            Comment = ''; ConfiguredComment = [string]$Row.Fields[9]; Icon = $Icon.Value; WorkingDirectory = $WorkingDirectory.Value
            ShowCommand = [uint32]1; ConditionExpression = $ConditionExpression; Condition = $Condition
            UnresolvedMacros = [string[]]@($Shortcut.UnresolvedMacros + $Target.UnresolvedMacros + $Arguments.UnresolvedMacros + $WorkingDirectory.UnresolvedMacros + $Icon.UnresolvedMacros | Sort-Object -Unique)
          })
      }
    }
  }
  $Conditional = @($Calls | Where-Object { $null -eq $_.Condition -or $_.UnresolvedMacros.Count -gt 0 })
  if ($Conditional.Count) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Shortcut.Conditional' -Source CreateInstall -Message "$($Conditional.Count) CreateInstall shortcut operation(s) depend on runtime conditions or macros." -Kind Ambiguous -Areas Metadata -Evidence $Conditional)) }
  return [pscustomobject]@{ Calls = $Calls.ToArray(); Diagnostics = $Diagnostics.ToArray() }
}

function Get-CreateInstallRunEvidence {
  <#
  .SYNOPSIS
    Recover direct CreateInstall Run operations and their nested command lines.
  .PARAMETER Program
    Decoded GE program returned by Get-CreateInstallGenteeProgram.
  .PARAMETER ProjectVariableEvidence
    MAINVAR variables used to resolve deterministic paths and conditions.
  .PARAMETER Is32Bit
    Indicates the Windows folder view used by the setup process.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Program,
    [Parameter(Mandatory)][psobject]$ProjectVariableEvidence,
    [Parameter(Mandatory)][bool]$Is32Bit
  )

  $Functions = Get-CreateInstallFunctionIndex -Program $Program
  # Both source routines have six parameters and publish runret/runok. The MSI route is separated
  # by its complete msiexec command template; link-time IDs and function names are not stable.
  $DirectTargets = [Collections.Generic.HashSet[uint32]]::new()
  $MsiTargets = [Collections.Generic.HashSet[uint32]]::new()
  foreach ($Function in @($Functions.Values | Where-Object {
        $_.ParameterCount -eq 6 -and $_.LiteralText.Contains('runret', [StringComparison]::Ordinal) -and $_.LiteralText.Contains('runok', [StringComparison]::Ordinal) -and
        -not $_.LiteralText.Contains('wscript.exe', [StringComparison]::OrdinalIgnoreCase) -and -not $_.LiteralText.Contains('cscript.exe', [StringComparison]::OrdinalIgnoreCase)
      })) {
    if ($Function.LiteralText.Contains('msiexec.exe', [StringComparison]::OrdinalIgnoreCase)) { $null = $MsiTargets.Add([uint32]$Function.Record.Id) } else { $null = $DirectTargets.Add([uint32]$Function.Record.Id) }
  }
  if ($DirectTargets.Count -eq 0 -and $MsiTargets.Count -eq 0) { return [pscustomobject]@{ Calls = @(); Diagnostics = @() } }
  $Calls = [Collections.Generic.List[object]]::new()
  $Diagnostics = [Collections.Generic.List[object]]::new()

  foreach ($Function in $Functions.Values) {
    $Commands = $Function.Commands
    for ($CommandIndex = 0; $CommandIndex -lt $Commands.Count; $CommandIndex++) {
      if ($CommandIndex -eq 0) { continue }
      $TargetId = [uint32]$Commands[$CommandIndex].Command
      $Segment = @($Commands[[Math]::Max(0, $CommandIndex - 96)..($CommandIndex - 1)])
      if ($DirectTargets.Contains($TargetId)) {
        $Strings = @($Segment | Where-Object Command -EQ 34 | Select-Object -Last 6)
        $Integers = @($Segment | Where-Object { $_.Command -in @(25, 26, 27) -and $_.Operand -is [ValueType] } | Select-Object -Last 2)
        if ($Strings.Count -ne 6 -or $Integers.Count -ne 2) { continue }
        $ConditionExpression = [string]$Strings[5].Operand
        $Condition = Resolve-CreateInstallCondition -Expression $ConditionExpression -Variables $ProjectVariableEvidence.Variables
        if ($Condition -eq $false) { continue }
        $Executable = Join-CreateInstallMacroPath -Parent ([string]$Strings[0].Operand) -Child ([string]$Strings[1].Operand) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
        $Arguments = Resolve-CreateInstallMacroValue -Value ([string]$Strings[2].Operand) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
        $WorkingDirectory = Join-CreateInstallMacroPath -Parent ([string]$Strings[3].Operand) -Child ([string]$Strings[4].Operand) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
        $Calls.Add([pscustomobject][ordered]@{
            Kind = 'Executable'; CallerId = $Function.Record.Id; RoutineId = $TargetId; CallOffset = $Commands[$CommandIndex].Offset
            Executable = $Executable.Value; Arguments = $Arguments.Value; WorkingDirectory = $WorkingDirectory.Value
            Wait = [bool][uint32]$Integers[0].Operand; RunAs = [uint32]$Integers[1].Operand
            ConditionExpression = $ConditionExpression; Condition = $Condition
            UnresolvedMacros = [string[]]@($Executable.UnresolvedMacros + $Arguments.UnresolvedMacros + $WorkingDirectory.UnresolvedMacros | Sort-Object -Unique)
          })
        continue
      }
      if (-not $MsiTargets.Contains($TargetId)) { continue }

      # runmsiex is generated from path/name, five flag inputs, wait, condition, log, and UI mode.
      # The compiler may fold the flag OR expression, so all numeric literals between the MSI name
      # and condition are ORed except the final wait value.
      $Strings = @($Segment | Where-Object Command -EQ 34 | Select-Object -Last 5)
      if ($Strings.Count -ne 5 -or $Strings[1].Index + 1 -gt $Strings[2].Index - 1) { continue }
      $FlagCommands = @($Commands[($Strings[1].Index + 1)..($Strings[2].Index - 1)] | Where-Object { $_.Command -in @(25, 26, 27) -and $_.Operand -is [ValueType] })
      if ($FlagCommands.Count -lt 2) { continue }
      $Wait = [uint32]$FlagCommands[-1].Operand
      $Flags = [uint32]0
      foreach ($FlagCommand in $FlagCommands[0..($FlagCommands.Count - 2)]) { $Flags = $Flags -bor [uint32]$FlagCommand.Operand }
      if (($Flags -band 0xFFFFFFE0) -ne 0 -or $Wait -notin 0, 1) { continue }
      $ConditionExpression = [string]$Strings[2].Operand
      $Condition = Resolve-CreateInstallCondition -Expression $ConditionExpression -Variables $ProjectVariableEvidence.Variables
      if ($Condition -eq $false) { continue }
      $Payload = Join-CreateInstallMacroPath -Parent ([string]$Strings[0].Operand) -Child ([string]$Strings[1].Operand) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
      $Log = Resolve-CreateInstallMacroValue -Value ([string]$Strings[3].Operand) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
      $Interface = Resolve-CreateInstallMacroValue -Value ([string]$Strings[4].Operand) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
      $MsiAction = if (($Flags -band 0x10) -ne 0) { 'Uninstall' } elseif (($Flags -band 0x01) -ne 0) { 'AdministrativeInstall' } else { 'Install' }
      $ArgumentParts = [Collections.Generic.List[string]]::new()
      if (-not [string]::IsNullOrWhiteSpace([string]$Log.Value)) { $ArgumentParts.Add('/l*'); $ArgumentParts.Add('"' + ([string]$Log.Value).Trim('"') + '"') }
      $ArgumentParts.Add($(if ($MsiAction -eq 'Uninstall') { '/x' } elseif ($MsiAction -eq 'AdministrativeInstall') { '/a' } else { '/i' }))
      $ArgumentParts.Add('"' + ([string]$Payload.Value).Trim('"') + '"')
      if (($Flags -band 0x02) -ne 0) { $ArgumentParts.Add('/quiet') }
      if (($Flags -band 0x04) -ne 0) { $ArgumentParts.Add('/passive') }
      if (($Flags -band 0x08) -ne 0) { $ArgumentParts.Add('/norestart') }
      if (-not [string]::IsNullOrWhiteSpace([string]$Interface.Value)) { $ArgumentParts.Add(([string]$Interface.Value).Trim()) }
      $Calls.Add([pscustomobject][ordered]@{
          Kind = 'Msi'; CallerId = $Function.Record.Id; RoutineId = $TargetId; CallOffset = $Commands[$CommandIndex].Offset
          Executable = '%WINDIR%\System32\msiexec.exe'; Arguments = $ArgumentParts -join ' '; WorkingDirectory = $null
          NestedInstallerPath = $Payload.Value; MsiAction = $MsiAction; MsiFlags = $Flags; MsiInterface = $Interface.Value; LogPath = $Log.Value
          Wait = [bool]$Wait; RunAs = $null; ConditionExpression = $ConditionExpression; Condition = $Condition
          UnresolvedMacros = [string[]]@($Payload.UnresolvedMacros + $Log.UnresolvedMacros + $Interface.UnresolvedMacros | Sort-Object -Unique)
        })
    }
  }
  $Conditional = @($Calls | Where-Object { $null -eq $_.Condition -or $_.UnresolvedMacros.Count -gt 0 })
  if ($Conditional.Count) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Run.Conditional' -Source CreateInstall -Message "$($Conditional.Count) CreateInstall child-process operation(s) depend on runtime conditions or macros." -Kind Ambiguous -Areas Installability -Evidence $Conditional)) }
  return [pscustomobject]@{ Calls = $Calls.ToArray(); Diagnostics = $Diagnostics.ToArray() }
}

function Get-CreateInstallExtensionEvidence {
  <#
  .SYNOPSIS
    Recover literal file-association calls emitted by CreateInstall's Extension command.
  .PARAMETER Program
    Decoded GE program returned by Get-CreateInstallGenteeProgram.
  .PARAMETER ProjectVariableEvidence
    MAINVAR evidence and its source g_list buffer.
  .PARAMETER Is32Bit
    Indicates that deterministic folder macros use the 32-bit Windows view.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Program,
    [Parameter(Mandatory)][psobject]$ProjectVariableEvidence,
    [Parameter(Mandatory)][bool]$Is32Bit
  )

  # extension() is identified by the complete group of class-registration strings in the
  # source-backed implementation. Link-time object IDs vary between generated installers.
  $Candidates = @($Program.Records | Where-Object Type -EQ 3 | Where-Object {
      $Text = [Text.Encoding]::ASCII.GetString($Program.Bytes, $_.PayloadOffset, $_.EndOffset - $_.PayloadOffset)
      $Text.Contains('AlwaysShowExt', [StringComparison]::Ordinal) -and
      $Text.Contains('EditFlags', [StringComparison]::Ordinal) -and
      $Text.Contains('UserChoice', [StringComparison]::Ordinal) -and
      $Text.Contains('DefaultIcon', [StringComparison]::Ordinal)
    })
  if ($Candidates.Count -eq 0) { return [pscustomobject]@{ Calls = @(); RegistryWrites = @(); Diagnostics = @() } }
  if ($Candidates.Count -ne 1) { throw 'The compiled CreateInstall program contains multiple candidate Extension routines' }

  $Calls = [System.Collections.Generic.List[object]]::new()
  $RegistryWrites = [System.Collections.Generic.List[object]]::new()
  $Diagnostics = [System.Collections.Generic.List[object]]::new()
  foreach ($Record in @($Program.Records | Where-Object Type -EQ 3)) {
    $Commands = @(Get-CreateInstallGenteeCommand -Program $Program -Record $Record)
    for ($CommandIndex = 0; $CommandIndex -lt $Commands.Count; $CommandIndex++) {
      if ($Commands[$CommandIndex].Command -ne $Candidates[0].Id -or $CommandIndex -eq 0) { continue }
      $Window = @($Commands[([Math]::Max(0, $CommandIndex - 64))..($CommandIndex - 1)])
      $StringCommands = @($Window | Where-Object Command -EQ 34 | Select-Object -Last 4)
      if ($StringCommands.Count -ne 4) { continue }
      if ($StringCommands[-1].Index + 1 -gt $CommandIndex - 1) { continue }
      $OffsetCommands = @($Commands[($StringCommands[-1].Index + 1)..($CommandIndex - 1)] | Where-Object { $_.Command -in @(25, 26, 27) -and $_.Operand -is [ValueType] })
      if ($OffsetCommands.Count -eq 0) { continue }
      $ListOffset = [uint32]$OffsetCommands[-1].Operand
      try { $Rows = @(ConvertFrom-CreateInstallGenteeList -Bytes $ProjectVariableEvidence.BufferData -Offset ([int]$ListOffset) -FieldCount 2) } catch {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Association.ListMalformed' -Source CreateInstall -Message "A compiled CreateInstall file-association list is malformed: $($_.Exception.Message)" -Kind Invalid -Areas Metadata -AffectedFields FileExtensions -Evidence @{ CallerId = $Record.Id; Offset = $ListOffset }))
        continue
      }
      $Variables = [ordered]@{}
      foreach ($Entry in $ProjectVariableEvidence.Variables.GetEnumerator()) { $Variables[$Entry.Key] = $Entry.Value }
      foreach ($Row in $Rows) {
        $Name = [string]$Row.Fields[0]
        if (-not [string]::IsNullOrWhiteSpace($Name) -and -not $Name.Contains(':', [StringComparison]::Ordinal)) { $Variables[$Name] = [string]$Row.Fields[1] }
      }
      $Condition = Resolve-CreateInstallCondition -Expression ([string]$Variables['extif']) -Variables $Variables
      if ($Condition -eq $false) { continue }
      if ($null -eq $Condition) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Association.ConditionDynamic' -Source CreateInstall -Message 'A CreateInstall file association depends on a runtime condition and is retained as conditional evidence.' -Kind Ambiguous -Areas Metadata -AffectedFields FileExtensions -Evidence @{ CallerId = $Record.Id; Expression = [string]$Variables['extif'] }))
      }

      $ExtensionName = ([string]$StringCommands[0].Operand).Trim().TrimStart('.')
      if ($ExtensionName -notmatch '^[A-Za-z0-9][A-Za-z0-9._+-]{0,254}$') {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Association.ExtensionDynamic' -Source CreateInstall -Message "CreateInstall's Extension command has a non-literal extension '$ExtensionName'." -Kind Incomplete -Areas Metadata -AffectedFields FileExtensions -Evidence @{ CallerId = $Record.Id }))
        continue
      }
      $ApplicationResult = Join-CreateInstallMacroPath -Parent ([string]$StringCommands[1].Operand) -Child ([string]$StringCommands[2].Operand) -Variables $Variables -Is32Bit $Is32Bit
      if ($ApplicationResult.UnresolvedMacros.Count -gt 0 -or [string]::IsNullOrWhiteSpace([string]$ApplicationResult.Value)) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.Association.CommandDynamic' -Source CreateInstall -Message "CreateInstall's '.$ExtensionName' association has an unresolved application command." -Kind Incomplete -Areas Metadata -AffectedFields FileExtensions -Evidence @{ CallerId = $Record.Id; Macros = $ApplicationResult.UnresolvedMacros }))
        continue
      }
      $ApplicationPath = [string]$ApplicationResult.Value
      $Parameters = [string]$StringCommands[3].Operand
      if ([string]::IsNullOrWhiteSpace($Parameters)) { $Parameters = '"%1"' }
      $ProgId = [string]$Variables['extfile']
      if ([string]::IsNullOrWhiteSpace($ProgId)) { $ProgId = $ExtensionName + 'file' }
      $Description = [string]$Variables['extdesc']
      if ([string]::IsNullOrWhiteSpace($Description)) { $Description = $ExtensionName.ToUpperInvariant() + ' file' }
      $IconResult = Resolve-CreateInstallMacroValue -Value ([string]$Variables['exticon']) -Variables $Variables -Is32Bit $Is32Bit
      $Icon = if ([string]::IsNullOrWhiteSpace([string]$IconResult.Value)) { $ApplicationPath } elseif ($IconResult.UnresolvedMacros.Count -eq 0) { [string]$IconResult.Value } else { $null }
      $ExtensionKey = ".$ExtensionName"
      $OpenCommand = '"' + $ApplicationPath.Trim('"') + '" ' + $Parameters
      $Evidence = "Gentee extension call in object $($Record.Id)"
      foreach ($Write in @(
          @{ Root = 'HKCR'; Key = $ExtensionKey; Name = ''; Value = $ProgId; Type = 'REG_SZ' },
          @{ Root = 'HKCR'; Key = "$ProgId\DefaultIcon"; Name = ''; Value = $Icon; Type = 'REG_SZ' },
          @{ Root = 'HKCR'; Key = "$ProgId\Shell\Open\command"; Name = ''; Value = $OpenCommand; Type = 'REG_SZ' },
          @{ Root = 'HKCU'; Key = "Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$ExtensionKey\UserChoice"; Name = 'Progid'; Value = $ProgId; Type = 'REG_SZ' },
          @{ Root = 'HKCR'; Key = $ProgId; Name = ''; Value = $Description; Type = 'REG_SZ' },
          @{ Root = 'HKCR'; Key = $ProgId; Name = 'AlwaysShowExt'; Value = ''; Type = 'REG_SZ' },
          @{ Root = 'HKCR'; Key = $ProgId; Name = 'EditFlags'; Value = '00000000'; Type = 'REG_BINARY' }
        )) {
        if ($null -ne $Write.Value) { $RegistryWrites.Add([pscustomobject]@{ Root = $Write.Root; RegistryView = $Is32Bit ? '32-bit' : '64-bit'; Key = $Write.Key; Name = $Write.Name; Value = $Write.Value; Type = $Write.Type; Evidence = $Evidence }) }
      }
      $Calls.Add([pscustomobject]@{ CallerId = $Record.Id; CallOffset = $Commands[$CommandIndex].Offset; Extension = $ExtensionKey; ProgId = $ProgId; Application = $ApplicationPath; Parameters = $Parameters; Description = $Description; DefaultIcon = $Icon; ConditionExpression = [string]$Variables['extif']; Condition = $Condition; ListOffset = $ListOffset })
    }
  }
  return [pscustomobject]@{ Calls = $Calls.ToArray(); RegistryWrites = $RegistryWrites.ToArray(); Diagnostics = $Diagnostics.ToArray() }
}

function Get-CreateInstallInstallFileEvidence {
  <#
  .SYNOPSIS
    Map GEA file groups to their compiled CreateInstall destination paths.
  .PARAMETER Program
    Decoded GE program returned by Get-CreateInstallGenteeProgram.
  .PARAMETER ProjectVariableEvidence
    MAINVAR evidence and its source g_list buffer.
  .PARAMETER Layout
    Validated GEA archive layout whose group identifiers are projected.
  .PARAMETER Is32Bit
    Indicates that deterministic folder macros use the 32-bit Windows view.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Program,
    [Parameter(Mandatory)][psobject]$ProjectVariableEvidence,
    [Parameter(Mandatory)][psobject]$Layout,
    [Parameter(Mandatory)][bool]$Is32Bit
  )

  # Link-time object IDs and function names are unstable. Recover unpackgroup by its five-argument
  # signature and calls to both the one-argument condition evaluator and three-argument unpackfile
  # routine. Requiring both callees excludes unrelated five-argument runtime helpers found in early
  # media. unpackgroupex is the six-argument wrapper that calls the recovered group routine. The
  # generated project may call either route.
  $Functions = Get-CreateInstallFunctionIndex -Program $Program
  $GroupRoutines = @($Functions.Values | Where-Object {
      if ($_.ParameterCount -ne 5 -or $_.Record.Size -ge 512) { return $false }
      $CalledParameterCounts = @($_.Commands | Where-Object { $Functions.ContainsKey([uint32]$_.Command) } | ForEach-Object { $Functions[[uint32]$_.Command].ParameterCount })
      return $CalledParameterCounts -contains 1 -and $CalledParameterCounts -contains 3
    })
  $ExtendedRoutines = @($Functions.Values | Where-Object {
      $_.ParameterCount -eq 6 -and @($_.Commands | Where-Object { $Target = [uint32]$_.Command; $GroupRoutines.Record.Id -contains $Target }).Count -gt 0
    })
  $ProjectCalls = [System.Collections.Generic.HashSet[uint32]]::new()
  foreach ($Function in $Functions.Values) {
    foreach ($Command in $Function.Commands) { if ($Functions.ContainsKey([uint32]$Command.Command)) { $null = $ProjectCalls.Add([uint32]$Command.Command) } }
  }
  $RouteCandidates = @($ExtendedRoutines | Where-Object { $ProjectCalls.Contains([uint32]$_.Record.Id) })
  $RouteId = 'Extended6'
  if ($RouteCandidates.Count -eq 0) {
    $RouteCandidates = @($GroupRoutines | Where-Object { $ProjectCalls.Contains([uint32]$_.Record.Id) })
    $RouteId = 'Direct5'
  }
  if ($RouteCandidates.Count -eq 0) { return [pscustomobject]@{ RouteId = $null; Calls = @(); InstalledFiles = @(); Diagnostics = @() } }
  if ($RouteCandidates.Count -ne 1) { throw 'The compiled CreateInstall program contains multiple candidate install-group routines' }
  $TargetId = [uint32]$RouteCandidates[0].Record.Id

  $Calls = [System.Collections.Generic.List[object]]::new()
  $InstalledFiles = [System.Collections.Generic.List[object]]::new()
  $Diagnostics = [System.Collections.Generic.List[object]]::new()
  $DynamicConditions = [System.Collections.Generic.List[object]]::new()
  foreach ($Function in $Functions.Values) {
    $Commands = $Function.Commands
    $PreviousCallIndex = -1
    for ($CommandIndex = 0; $CommandIndex -lt $Commands.Count; $CommandIndex++) {
      if ($Commands[$CommandIndex].Command -ne $TargetId) { continue }
      $SegmentStart = $PreviousCallIndex + 1
      $PreviousCallIndex = $CommandIndex
      if ($SegmentStart -ge $CommandIndex) { continue }
      $Window = @($Commands[$SegmentStart..($CommandIndex - 1)])
      $StringCommands = @($Window | Where-Object Command -EQ 34 | Select-Object -Last 4)
      if ($StringCommands.Count -ne 4) { continue }
      if ($SegmentStart -gt $StringCommands[0].Index - 1 -or $StringCommands[1].Index + 1 -gt $StringCommands[2].Index - 1) { continue }
      $BeforeDestination = @($Commands[$SegmentStart..($StringCommands[0].Index - 1)] | Where-Object { $_.Command -in @(25, 26, 27) -and $_.Operand -is [ValueType] })
      $BeforeCondition = @($Commands[($StringCommands[1].Index + 1)..($StringCommands[2].Index - 1)] | Where-Object { $_.Command -in @(25, 26, 27) -and $_.Operand -is [ValueType] })
      if ($BeforeDestination.Count -eq 0 -or $BeforeCondition.Count -eq 0) { continue }
      $GroupId = [uint32]$BeforeDestination[-1].Operand
      if ($GroupId -ne 0xFFFF -and -not ($Layout.Entries.GroupId -contains $GroupId)) { continue }
      $OverwriteMode = [uint32]$BeforeCondition[-1].Operand
      $ListOffset = $null
      $Options = @()
      if ($RouteId -eq 'Extended6') {
        if ($StringCommands[3].Index + 1 -gt $CommandIndex - 1) { continue }
        $AfterWildcard = @($Commands[($StringCommands[3].Index + 1)..($CommandIndex - 1)] | Where-Object { $_.Command -in @(25, 26, 27) -and $_.Operand -is [ValueType] })
        if ($AfterWildcard.Count -eq 0) { continue }
        $ListOffset = [uint32]$AfterWildcard[-1].Operand
        if ($ListOffset -ne [uint32]::MaxValue) {
          try { $Options = @(ConvertFrom-CreateInstallGenteeList -Bytes $ProjectVariableEvidence.BufferData -Offset ([int]$ListOffset) -FieldCount 4) } catch {
            $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.InstallGroup.OptionsMalformed' -Source CreateInstall -Message "A compiled CreateInstall install-group option list is malformed: $($_.Exception.Message)" -Kind Invalid -Areas Extraction -Evidence @{ CallerId = $Function.Record.Id; Offset = $ListOffset }))
            continue
          }
        }
      }

      $DestinationExpression = if ([string]::IsNullOrWhiteSpace([string]$StringCommands[0].Operand)) {
        [string]$StringCommands[1].Operand
      } elseif ([string]::IsNullOrWhiteSpace([string]$StringCommands[1].Operand)) {
        [string]$StringCommands[0].Operand
      } else {
        ([string]$StringCommands[0].Operand).TrimEnd([char[]]'\/') + '\' + ([string]$StringCommands[1].Operand).TrimStart([char[]]'\/')
      }
      if ($DestinationExpression.StartsWith('*', [StringComparison]::Ordinal)) { continue }
      $Destination = Resolve-CreateInstallMacroValue -Value $DestinationExpression -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
      $ConditionExpression = [string]$StringCommands[2].Operand
      $Condition = Resolve-CreateInstallCondition -Expression $ConditionExpression -Variables $ProjectVariableEvidence.Variables
      if ($Condition -eq $false) { continue }
      if ($null -eq $Condition) {
        $DynamicConditions.Add([pscustomobject]@{ CallerId = $Function.Record.Id; GroupId = $GroupId; Expression = $ConditionExpression })
      }
      $Wildcard = [string]$StringCommands[3].Operand
      $MatchedEntries = @($Layout.Entries | Where-Object {
          ($GroupId -eq 0xFFFF -or $_.GroupId -eq $GroupId) -and ([string]::IsNullOrWhiteSpace($Wildcard) -or $_.Name -like $Wildcard)
        })
      $Calls.Add([pscustomobject]@{ CallerId = $Function.Record.Id; CallOffset = $Commands[$CommandIndex].Offset; GroupId = $GroupId; DestinationExpression = $DestinationExpression; Destination = $Destination.Value; UnresolvedMacros = $Destination.UnresolvedMacros; OverwriteMode = $OverwriteMode; ConditionExpression = $ConditionExpression; Condition = $Condition; Wildcard = $Wildcard; ListOffset = $ListOffset; Options = $Options })
      foreach ($Entry in $MatchedEntries) {
        $RelativeName = if ([string]::IsNullOrWhiteSpace([string]$Entry.Folder)) { $Entry.Name } else { ([string]$Entry.Folder).TrimEnd([char[]]'\/') + '\' + $Entry.Name }
        $InstalledPath = if ($Destination.UnresolvedMacros.Count -eq 0) { ([string]$Destination.Value).TrimEnd([char[]]'\/') + '\' + $RelativeName.TrimStart([char[]]'\/') } else { $null }
        $InstalledFiles.Add([pscustomobject]@{ ArchiveIndex = $Entry.Index; ArchivePath = $Entry.FullName; GroupId = $Entry.GroupId; InstalledPath = $InstalledPath; Destination = $Destination.Value; Size = $Entry.Size; Crc32 = $Entry.Crc32; IsConditional = $null -eq $Condition; ConditionExpression = $ConditionExpression; OverwriteMode = $OverwriteMode })
      }
    }
  }
  if ($DynamicConditions.Count) {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'CreateInstall.InstallGroup.ConditionDynamic' -Source CreateInstall -Message "$($DynamicConditions.Count) CreateInstall install group(s) depend on runtime conditions; their files are retained as conditional evidence." -Kind Ambiguous -Areas Extraction, Installability -Evidence $DynamicConditions.ToArray()))
  }
  return [pscustomobject]@{ RouteId = $RouteId; RoutineId = $TargetId; Calls = $Calls.ToArray(); InstalledFiles = $InstalledFiles.ToArray(); Diagnostics = $Diagnostics.ToArray() }
}

function Get-CreateInstallRegistryEvidence {
  <#
  .SYNOPSIS
    Recover literal Registry command lists compiled through regsetsex.
  .PARAMETER Program
    Decoded GE program returned by Get-CreateInstallGenteeProgram.
  .PARAMETER ProjectVariableEvidence
    MAINVAR evidence and its source g_list buffer.
  .PARAMETER Is32Bit
    Indicates the default registry view used by the setup process.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Program,
    [Parameter(Mandatory)][psobject]$ProjectVariableEvidence,
    [Parameter(Mandatory)][bool]$Is32Bit
  )

  $RootNames = @{
    ([uint32]2147483648) = 'HKCR'
    ([uint32]2147483649) = 'HKCU'
    ([uint32]2147483650) = 'HKLM'
    ([uint32]2147483651) = 'HKU'
    ([uint32]2147483653) = 'HKCC'
  }
  $TypeNames = @('REG_DWORD', 'REG_SZ', 'REG_BINARY', 'REG_MULTI_SZ', 'REG_EXPAND_SZ')
  $Functions = Get-CreateInstallFunctionIndex -Program $Program
  $Calls = [System.Collections.Generic.List[object]]::new()
  $Writes = [System.Collections.Generic.List[object]]::new()
  $ConditionalWrites = [System.Collections.Generic.List[object]]::new()
  $DynamicConditions = [System.Collections.Generic.List[object]]::new()

  foreach ($Function in $Functions.Values) {
    $Record = $Function.Record
    $Commands = $Function.Commands
    $PreviousTargetIndex = @{}
    for ($CommandIndex = 0; $CommandIndex -lt $Commands.Count; $CommandIndex++) {
      $TargetId = [uint32]$Commands[$CommandIndex].Command
      if (-not $Functions.ContainsKey($TargetId) -or $Functions[$TargetId].ParameterCount -ne 5) { continue }
      $TargetRecord = $Functions[$TargetId].Record
      if ($null -eq $TargetRecord -or $TargetRecord.Size -ge 128) { continue }
      # regsetsex is a small five-argument condition wrapper over regsets. Calls serialize one
      # root constant, one subkey string, list offset, WOW64 flag, and one outer condition string.
      $Start = $PreviousTargetIndex.ContainsKey($TargetId) ? ([int]$PreviousTargetIndex[$TargetId] + 1) : [Math]::Max(0, $CommandIndex - 48)
      $PreviousTargetIndex[$TargetId] = $CommandIndex
      if ($Start -ge $CommandIndex) { continue }
      $Window = @($Commands[$Start..($CommandIndex - 1)])
      $StringCommands = @($Window | Where-Object Command -EQ 34 | Select-Object -Last 2)
      if ($StringCommands.Count -ne 2) { continue }
      if ($Start -gt $StringCommands[0].Index - 1 -or $StringCommands[0].Index + 1 -gt $StringCommands[1].Index - 1) { continue }
      $RootCommands = @($Commands[$Start..($StringCommands[0].Index - 1)] | Where-Object { $_.Command -in @(27, 30) -and $RootNames.ContainsKey([uint32]$_.Operand) })
      $ListCommands = @($Commands[($StringCommands[0].Index + 1)..($StringCommands[1].Index - 1)] | Where-Object { $_.Command -in @(25, 26, 27) -and $_.Operand -is [ValueType] })
      if ($RootCommands.Count -eq 0 -or $ListCommands.Count -lt 2) { continue }
      $RootValue = [uint32]$RootCommands[-1].Operand
      $ListOffset = [uint32]$ListCommands[-2].Operand
      $Wow64 = [bool][uint32]$ListCommands[-1].Operand
      try { $Rows = @(ConvertFrom-CreateInstallGenteeList -Bytes $ProjectVariableEvidence.BufferData -Offset ([int]$ListOffset) -FieldCount 5) } catch { continue }
      if ($Rows.Count -eq 0 -or @($Rows | Where-Object { [string]$_.Fields[1] -notmatch '^[0-4]$' }).Count -gt 0) { continue }

      $Subkey = Resolve-CreateInstallMacroValue -Value ([string]$StringCommands[0].Operand) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
      $OuterExpression = [string]$StringCommands[1].Operand
      $OuterCondition = Resolve-CreateInstallCondition -Expression $OuterExpression -Variables $ProjectVariableEvidence.Variables
      $Call = [pscustomobject]@{ CallerId = $Record.Id; RoutineId = $TargetId; CallOffset = $Commands[$CommandIndex].Offset; Root = $RootNames[$RootValue]; SubkeyExpression = [string]$StringCommands[0].Operand; Subkey = $Subkey.Value; UnresolvedMacros = $Subkey.UnresolvedMacros; ListOffset = $ListOffset; RegistryView = $Wow64 ? '64-bit' : ($Is32Bit ? '32-bit' : '64-bit'); ConditionExpression = $OuterExpression; Condition = $OuterCondition; ValueCount = $Rows.Count }
      $Calls.Add($Call)
      foreach ($Row in $Rows) {
        $RowExpression = [string]$Row.Fields[3]
        $RowCondition = Resolve-CreateInstallCondition -Expression $RowExpression -Variables $ProjectVariableEvidence.Variables
        if ($OuterCondition -eq $false -or $RowCondition -eq $false) { continue }
        $IsConditional = $null -eq $OuterCondition -or $null -eq $RowCondition -or $Subkey.UnresolvedMacros.Count -gt 0
        $NameResult = Resolve-CreateInstallMacroValue -Value ([string]$Row.Fields[0]) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
        $ValueResult = Resolve-CreateInstallMacroValue -Value ([string]$Row.Fields[2]) -Variables $ProjectVariableEvidence.Variables -Is32Bit $Is32Bit
        if ($NameResult.UnresolvedMacros.Count -gt 0 -or $ValueResult.UnresolvedMacros.Count -gt 0) { $IsConditional = $true }
        $TypeCode = [int]$Row.Fields[1]
        $Value = switch ($TypeCode) {
          0 { $Number = 0L; [void][long]::TryParse([string]$ValueResult.Value, [ref]$Number); [uint32]($Number -band [uint32]::MaxValue); break }
          3 { [string[]]@(([string]$ValueResult.Value) -split '\|'); break }
          default { [string]$ValueResult.Value }
        }
        $Write = [pscustomobject]@{ Root = $RootNames[$RootValue]; RegistryView = $Call.RegistryView; Key = [string]$Subkey.Value; Name = [string]$NameResult.Value; Value = $Value; Type = $TypeNames[$TypeCode]; Evidence = "Gentee regsetsex call in object $($Record.Id)"; IsConditional = $IsConditional; ConditionExpression = @($OuterExpression, $RowExpression) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }; UnresolvedKeyMacros = @($Subkey.UnresolvedMacros) }
        if ($IsConditional) {
          $ConditionalWrites.Add($Write)
          $DynamicConditions.Add([pscustomobject]@{ CallerId = $Record.Id; Root = $Write.Root; Key = $Write.Key; Name = $Write.Name; Conditions = $Write.ConditionExpression; UnresolvedKeyMacros = @($Subkey.UnresolvedMacros); UnresolvedMacros = @($Subkey.UnresolvedMacros + $NameResult.UnresolvedMacros + $ValueResult.UnresolvedMacros) })
        } else { $Writes.Add($Write) }
      }
    }
  }

  $Diagnostics = @(
    if ($DynamicConditions.Count) {
      $AffectedFields = [string[]]@($DynamicConditions | ForEach-Object { Get-CreateInstallRegistryAffectedField -Root $_.Root -Key $_.Key -UnresolvedMacros $_.UnresolvedKeyMacros } | Sort-Object -Unique)
      New-InstallerDiagnostic -Id 'CreateInstall.Registry.Conditional' -Source CreateInstall -Message "$($DynamicConditions.Count) CreateInstall registry value(s) depend on runtime conditions or macros and are retained separately from deterministic registry writes." -Kind Ambiguous -Areas Metadata -AffectedFields $AffectedFields -Evidence $DynamicConditions.ToArray()
    }
  )
  return [pscustomobject]@{ Calls = $Calls.ToArray(); RegistryWrites = $Writes.ToArray(); ConditionalRegistryWrites = $ConditionalWrites.ToArray(); Diagnostics = $Diagnostics }
}

function Get-CreateInstallRegistryAffectedField {
  <#
  .SYNOPSIS
    Map a resolved CreateInstall registry destination to parser-managed manifest fields.
  .PARAMETER Root
    Registry root emitted by the compiled regsetsex call.
  .PARAMETER Key
    Resolved registry subkey. A key containing unresolved macros is treated conservatively.
  .PARAMETER UnresolvedMacros
    Macro names that prevented the parser from proving the final subkey.
  #>
  [OutputType([string[]])]
  param (
    [AllowNull()][string]$Root,
    [AllowNull()][string]$Key,
    [AllowNull()][string[]]$UnresolvedMacros
  )

  if (($null -ne $UnresolvedMacros -and $UnresolvedMacros.Count -gt 0) -or [string]::IsNullOrWhiteSpace($Key) -or $Key -match '#[^#]+#') {
    return [string[]]@('ProductCode', 'AppsAndFeaturesEntries', 'Protocols', 'FileExtensions')
  }
  if ($Key -match '(?i)^Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\') {
    return [string[]]@('ProductCode', 'AppsAndFeaturesEntries')
  }
  if ($Root -ceq 'HKCR' -or $Key -match '(?i)^Software\\Classes(?:\\|$)') {
    return [string[]]@('Protocols', 'FileExtensions')
  }
  return [string[]]@()
}

function Get-CreateInstallArpEvidence {
  <#
  .SYNOPSIS
    Reconstruct visible and hidden uninstall entries from deterministic registry writes.
  .PARAMETER RegistryWrite
    Built-in and custom CreateInstall registry writes in execution order.
  #>
  [OutputType([pscustomobject])]
  param ([AllowNull()][object[]]$RegistryWrite)

  $Entries = [System.Collections.Generic.List[object]]::new()
  $VisibleEntries = [System.Collections.Generic.List[object]]::new()
  $AppsAndFeaturesEntries = [System.Collections.Generic.List[object]]::new()
  $ProductCodes = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $Scopes = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $HiddenCodes = [System.Collections.Generic.List[string]]::new()
  $UninstallKeyPattern = '(?i)^Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\(?<Code>[^\\]+)$'
  $Groups = @($RegistryWrite | Where-Object { -not $_.IsConditional -and $_.Key -match $UninstallKeyPattern } | Group-Object Root, RegistryView, Key)
  foreach ($Group in $Groups) {
    $First = $Group.Group[0]
    $Code = [regex]::Match([string]$First.Key, $UninstallKeyPattern).Groups['Code'].Value
    $Values = [ordered]@{}
    foreach ($Write in $Group.Group) { $Values[[string]$Write.Name] = $Write.Value }
    $SystemComponent = 0L
    if ($Values.Contains('SystemComponent')) { [void][long]::TryParse([string]$Values['SystemComponent'], [ref]$SystemComponent) }
    $Visible = $SystemComponent -eq 0 -and -not [string]::IsNullOrWhiteSpace([string]$Values['DisplayName'])
    $Entry = [pscustomobject][ordered]@{
      ProductCode          = $Code
      DisplayName          = $Values['DisplayName']
      DisplayVersion       = $Values['DisplayVersion']
      Publisher            = $Values['Publisher']
      InstallLocation      = $Values['InstallLocation']
      UninstallString      = $Values['UninstallString']
      QuietUninstallString = $Values['QuietUninstallString']
      DisplayIcon          = $Values['DisplayIcon']
      URLInfoAbout         = $Values['URLInfoAbout']
      HelpLink             = $Values['HelpLink']
      SystemComponent      = $SystemComponent
      IsVisible            = $Visible
      RegistryRoot         = $First.Root
      RegistryView         = $First.RegistryView
      RegistryKey          = $First.Key
      Values               = $Values
      Evidence             = [string[]]@($Group.Group.Evidence | Where-Object { $_ } | Select-Object -Unique)
    }
    $Entries.Add($Entry)
    if (-not $Visible) { $HiddenCodes.Add($Code); continue }
    $VisibleEntries.Add($Entry)
    $null = $ProductCodes.Add($Code)
    switch ($First.Root) {
      'HKCU' { $null = $Scopes.Add('user') }
      'HKLM' { $null = $Scopes.Add('machine') }
      'SHCTX' { $null = $Scopes.Add('user'); $null = $Scopes.Add('machine') }
    }
    $ManifestEntry = [ordered]@{ ProductCode = $Code }
    foreach ($Name in 'DisplayName', 'DisplayVersion', 'Publisher') {
      if (-not [string]::IsNullOrWhiteSpace([string]$Entry.$Name)) { $ManifestEntry[$Name] = $Entry.$Name }
    }
    $ManifestEntry['InstallerType'] = 'exe'
    $AppsAndFeaturesEntries.Add([pscustomobject]$ManifestEntry)
  }
  $Diagnostics = @(
    if ($HiddenCodes.Count) { New-InstallerDiagnostic -Id 'CreateInstall.ARP.Hidden' -Source CreateInstall -Message "$($HiddenCodes.Count) CreateInstall uninstall key(s) are hidden or lack DisplayName and are excluded from visible Apps & Features evidence." -Kind Information -Areas Metadata -AffectedFields AppsAndFeaturesEntries -Evidence @($HiddenCodes) }
  )
  return [pscustomobject]@{ Entries = $Entries.ToArray(); VisibleEntries = $VisibleEntries.ToArray(); AppsAndFeaturesEntries = $AppsAndFeaturesEntries.ToArray(); ProductCodes = [string[]]@($ProductCodes); Scopes = [string[]]@($Scopes); Diagnostics = $Diagnostics }
}

function Get-CreateInstallUninstallEvidence {
  <#
  .SYNOPSIS
    Resolve source-verified CreateInstall Add/Remove calls from compiled GE bytecode.
  .PARAMETER Path
    Path to a CreateInstall setup executable. The file is opened read-only and never executed.
  .PARAMETER Program
    Previously decoded GE program. Supplying it avoids reopening and decoding the installer.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, ParameterSetName = 'Path')][string]$Path,
    [Parameter(Mandatory, ParameterSetName = 'Program')][psobject]$Program
  )

  if ($PSCmdlet.ParameterSetName -eq 'Path') { $Program = Get-CreateInstallGenteeProgram -Path $Path }
  $UninstallPath = [Text.Encoding]::ASCII.GetBytes('Software\Microsoft\Windows\CurrentVersion\Uninstall\')
  $PathRoutines = @($Program.Records | Where-Object Type -EQ 3 | Where-Object {
      @(Find-BinaryPattern -Bytes $Program.Bytes -Pattern $UninstallPath -StartOffset $_.PayloadOffset -Length ($_.EndOffset - $_.PayloadOffset) -Maximum 1).Count -eq 1
    })

  # The built-in routine evolved independently of the GEA archive version. Select the most
  # specific source-backed signature rather than guessing from PE ProductVersion.
  $AddRemoveProfile = $null
  $CandidateRoutine = $null
  foreach ($CatalogProfile in (Get-CreateInstallCatalogProfile -Section AddRemoveProfiles)) {
    $ProfileRoutines = @($PathRoutines | Where-Object {
        $RecordText = [Text.Encoding]::ASCII.GetString($Program.Bytes, $_.PayloadOffset, $_.EndOffset - $_.PayloadOffset)
        foreach ($ValueName in $CatalogProfile.RequiredValueNames) {
          if (-not $RecordText.Contains([string]$ValueName, [StringComparison]::Ordinal)) { return $false }
        }
        foreach ($ValueName in @($CatalogProfile.ForbiddenValueNames)) {
          if ($RecordText.Contains([string]$ValueName, [StringComparison]::Ordinal)) { return $false }
        }
        return $true
      })
    if ($ProfileRoutines.Count -gt 1) { throw "The compiled CreateInstall program contains multiple '$($CatalogProfile.Id)' Add/Remove routines" }
    if ($ProfileRoutines.Count -eq 1) {
      $AddRemoveProfile = $CatalogProfile
      $CandidateRoutine = $ProfileRoutines[0]
      break
    }
  }
  if ($null -eq $CandidateRoutine) {
    # Dead-code elimination removes the complete addremove family when the project disables its
    # Add/Remove Programs command. Absence of the source-identifying registry path is therefore a
    # valid no-built-in-ARP state; an unrecognized routine that still contains that path is not.
    if ($PathRoutines.Count -gt 0) { throw 'The compiled CreateInstall program contains an unsupported built-in Add/Remove routine' }
    return [pscustomobject]@{
      Calls       = @()
      ProgramInfo = [pscustomobject]@{
        LauncherOffset = $Program.LauncherOffset; SectionOffset = $Program.SectionOffset; RuntimeSize = $Program.RuntimeSize
        StoredProgramSize = $Program.StoredProgramSize; ProgramSize = $Program.ProgramSize; Packed = $Program.Packed
        VersionMajor = $Program.VersionMajor; VersionMinor = $Program.VersionMinor; ProgramProfile = $Program.ProgramProfile
        ObjectCount = $Program.Records.Count; AddRemoveProfile = $null; AddRemoveRoutine = $null; AddRemoveRoutineId = $null
      }
    }
  }

  $Calls = [System.Collections.Generic.List[object]]::new()
  foreach ($Record in @($Program.Records | Where-Object Type -EQ 3)) {
    $Commands = @(Get-CreateInstallGenteeCommand -Program $Program -Record $Record)
    for ($CommandIndex = 0; $CommandIndex -lt $Commands.Count; $CommandIndex++) {
      if ($Commands[$CommandIndex].Command -ne $CandidateRoutine.Id -or $CommandIndex -eq 0) { continue }

      # Generated project code places literal string arguments immediately before a direct call.
      # Legacy addremove has three strings, addremoveex adds the current-user Boolean, and
      # addremoveext appends a fourth estimated-size string after that Boolean.
      $StringCommands = @($Commands[([Math]::Max(0, $CommandIndex - 64))..($CommandIndex - 1)] | Where-Object Command -EQ 34 | Select-Object -Last ([int]$AddRemoveProfile.StringArgumentCount))
      if ($StringCommands.Count -ne [int]$AddRemoveProfile.StringArgumentCount) { continue }
      $ForCurrentUser = $false
      if ($AddRemoveProfile.HasCurrentUserArgument) {
        $BooleanStart = $StringCommands[2].Index + 1
        $BooleanEnd = if ($AddRemoveProfile.HasEstimatedSizeArgument) { $StringCommands[3].Index - 1 } else { $CommandIndex - 1 }
        if ($BooleanStart -gt $BooleanEnd) { continue }
        $CurrentUserCommands = @($Commands[$BooleanStart..$BooleanEnd] | Where-Object { $_.Command -in @(25, 26, 27) -and $_.Operand -in @(0, 1) })
        if ($CurrentUserCommands.Count -eq 0) { continue }
        $ForCurrentUser = [bool]$CurrentUserCommands[-1].Operand
      }
      $Calls.Add([pscustomobject]@{
          ProfileId             = [string]$AddRemoveProfile.Id
          Routine               = [string]$AddRemoveProfile.Routine
          RoutineId             = [uint32]$CandidateRoutine.Id
          CallerId              = [uint32]$Record.Id
          CallerName            = $Record.Name
          CallOffset            = [int]$Commands[$CommandIndex].Offset
          UninstallKeyName      = [string]$StringCommands[0].Operand
          IconPath              = [string]$StringCommands[1].Operand
          IconFile              = [string]$StringCommands[2].Operand
          ForCurrentUser        = $ForCurrentUser
          EstimatedSizeText     = if ($AddRemoveProfile.HasEstimatedSizeArgument) { [string]$StringCommands[3].Operand } else { $null }
          WritesInstallLocation = [bool]$AddRemoveProfile.WritesInstallLocation
          WritesNoModify        = [bool]$AddRemoveProfile.WritesNoModify
          WritesNoRepair        = [bool]$AddRemoveProfile.WritesNoRepair
          WritesEstimatedSize   = [bool]$AddRemoveProfile.WritesEstimatedSize
        })
    }
  }
  return [pscustomobject]@{
    Calls       = $Calls.ToArray()
    ProgramInfo = [pscustomobject]@{
      LauncherOffset     = $Program.LauncherOffset
      SectionOffset      = $Program.SectionOffset
      RuntimeSize        = $Program.RuntimeSize
      StoredProgramSize  = $Program.StoredProgramSize
      ProgramSize        = $Program.ProgramSize
      Packed             = $Program.Packed
      VersionMajor       = $Program.VersionMajor
      VersionMinor       = $Program.VersionMinor
      ProgramProfile     = $Program.ProgramProfile
      ObjectCount        = $Program.Records.Count
      AddRemoveProfile   = [string]$AddRemoveProfile.Id
      AddRemoveRoutine   = [string]$AddRemoveProfile.Routine
      AddRemoveRoutineId = [uint32]$CandidateRoutine.Id
    }
  }
}

Export-ModuleMember -Function Get-CreateInstallProjectVariableEvidence, Resolve-CreateInstallMacroValue, Join-CreateInstallMacroPath, Resolve-CreateInstallCondition, Get-CreateInstallOperationProfile, Find-CreateInstallOperationRoutine, Get-CreateInstallRoutineCallSite, Get-CreateInstallScheduledTaskEvidence, Get-CreateInstallFileOperationEvidence, Get-CreateInstallDownloadEvidence, Get-CreateInstallArchiveOperationEvidence, Get-CreateInstallConfigurationEvidence, Get-CreateInstallListCallEvidence, Get-CreateInstallEnvironmentEvidence, Get-CreateInstallPrerequisiteEvidence, Get-CreateInstallServiceEvidence, Get-CreateInstallRegistrationEvidence, Get-CreateInstallGenteeExpressionEvidence, Get-CreateInstallShortcutEvidence, Get-CreateInstallRunEvidence, Get-CreateInstallExtensionEvidence, Get-CreateInstallInstallFileEvidence, Get-CreateInstallRegistryEvidence, Get-CreateInstallRegistryAffectedField, Get-CreateInstallArpEvidence, Get-CreateInstallUninstallEvidence
