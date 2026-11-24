# SPDX-License-Identifier: Apache-2.0
# Format source: https://docs.revenera.com/installanywhere/Content/helplibrary/ia_ref_command_line_install_uninstall.htm
# Static InstallAnywhere parser. It reads embedded ZIP/XML project data and
# never starts the installer or its Java launcher.
# Binary structure consumed here:
#
#   native PE launcher -> self-contained ZIP range
#     +-- InstallerData/Execute.zip -> InstallScript.iap_xml
#     +-- IAClasses.zip
#     `-- Resource1.zip and payload entries
#
# The archive base is derived from a matching EOCD and central-directory offset,
# not the first PK local-header marker. Nested ZIPs receive independent bounds,
# safe-path checks, and entry limits. XML product/action records supply metadata.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:InstallAnywhereMaximumArchiveBytes = 2147483648
$Script:InstallAnywhereMaximumEntryBytes = 268435456

# InstallAnywhere archive discovery and project-model decoding.
function Get-InstallAnywhereArchiveData {
  <#
  .SYNOPSIS
    Locate the InstallAnywhere ZIP archive and enumerate its payload names
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)

  $File = Get-Item -LiteralPath $Path -Force

  # Test each independently validated ZIP range because launchers may append
  # signatures or auxiliary archives around the InstallAnywhere payload.
  foreach ($Range in @(Get-EmbeddedZipArchiveRange -Path $Path)) {
    if ($Range.Length -gt $Script:InstallAnywhereMaximumArchiveBytes) { continue }
    $Context = $null
    try {
      $Context = Open-InstallerArchiveRange -Path $File.FullName -Range $Range
      $Entries = @(Get-InstallerArchiveEntry -Archive $Context.Archive | ForEach-Object {
          [pscustomobject]@{ FullName = $_.FullName; Length = $_.Length }
        })
      $Names = @($Entries.FullName)

      # Require InstallAnywhere-specific project/runtime names instead of
      # classifying an arbitrary embedded ZIP by container type alone.
      if ($Names -notcontains 'InstallerData/Execute.zip' -and $Names -notcontains 'InstallerData/IAClasses.zip' -and -not ($Names -match 'InstallScript\.iap_xml$')) { continue }
      return [pscustomobject]@{ SourcePath = $File.FullName; Range = $Range; Entries = $Entries; EntryNames = $Names }
    } catch {
      # Continue to later ranges when a candidate central directory or entry is malformed.
      continue
    } finally {
      if ($Context) { Close-InstallerArchiveRange -Context $Context }
    }
  }
  throw 'The file does not contain a recognized InstallAnywhere embedded ZIP archive'
}

function Get-InstallAnywhereProjectXml {
  <#
  .SYNOPSIS
    Read InstallScript.iap_xml from the outer archive or nested Execute.zip.
  .PARAMETER ArchiveData
    Validated outer ZIP range and catalog returned by Get-InstallAnywhereArchiveData. Nested streams are disposed internally.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)]$ArchiveData)
  $Context = Open-InstallerArchiveRange -Path $ArchiveData.SourcePath -Range $ArchiveData.Range
  try {
    # Newer installers place the project XML inside Execute.zip. Convert the
    # nested entry to a bounded seekable stream before opening its ZIP directory.
    $NestedEntry = Get-InstallerArchiveEntry -Archive $Context.Archive | Where-Object { $_.FullName -ieq 'InstallerData/Execute.zip' } | Select-Object -First 1
    if ($NestedEntry) {
      if ($NestedEntry.Length -gt $Script:InstallAnywhereMaximumEntryBytes) { throw 'The InstallAnywhere Execute.zip entry exceeds the configured size limit' }
      $EntryStream = Open-InstallerArchiveEntry -Entry $NestedEntry
      $SeekableContext = $null
      $ProjectArchive = $null
      try {
        $SeekableContext = New-InstallerSeekableStream -SourceStream $EntryStream -MaximumBytes $Script:InstallAnywhereMaximumEntryBytes
        $ProjectArchive = Get-InstallerArchive -Stream $SeekableContext.Stream
        $ProjectEntry = Get-InstallerArchiveEntry -Archive $ProjectArchive | Where-Object { $_.FullName -ieq 'InstallScript.iap_xml' } | Select-Object -First 1
        if ($ProjectEntry) {
          $ProjectBytes = Read-InstallerArchiveEntryBytes -Entry $ProjectEntry -MaximumBytes ([int]$Script:InstallAnywhereMaximumEntryBytes)
          return [Text.Encoding]::UTF8.GetString($ProjectBytes)
        }
      } finally {
        if ($ProjectArchive) { $ProjectArchive.Dispose() }
        if ($SeekableContext) { $SeekableContext.Dispose() }
        $EntryStream.Dispose()
      }
    }

    # Older generations expose InstallScript.iap_xml directly in the outer archive.
    $ProjectName = $ArchiveData.EntryNames | Where-Object { $_ -match 'InstallScript\.iap_xml$' } | Select-Object -First 1
    if (-not $ProjectName) { return $null }
    $ProjectEntry = Get-InstallerArchiveEntry -Archive $Context.Archive | Where-Object { $_.FullName -ieq $ProjectName } | Select-Object -First 1
    if (-not $ProjectEntry) { return $null }
    if ($ProjectEntry.Length -gt $Script:InstallAnywhereMaximumEntryBytes) { throw "The InstallAnywhere entry '$ProjectName' exceeds the configured size limit" }
    $ProjectBytes = Read-InstallerArchiveEntryBytes -Entry $ProjectEntry -MaximumBytes ([int]$Script:InstallAnywhereMaximumEntryBytes)
    return [Text.Encoding]::UTF8.GetString($ProjectBytes)
  } finally {
    Close-InstallerArchiveRange -Context $Context
  }
}

function Expand-InstallAnywhereInstaller {
  <#
  .SYNOPSIS
    Extract InstallAnywhere outer ZIP payload files without executing the installer
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER DestinationPath
    Destination path for bounded extraction or decoded output; payload-relative names are resolved beneath this path.
  .PARAMETER Name
    Exact name or wildcard used to select format records or payload entries.
  .PARAMETER CollisionAction
    Behavior when an output path already exists or is selected more than once.
  .PARAMETER MaximumExpandedBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  [OutputType([System.IO.FileInfo[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [string]$Name = '*',
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Prompt',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 17179869184
  )
  process {
    $ArchiveData = Get-InstallAnywhereArchiveData -Path $Path
    $Context = Open-InstallerArchiveRange -Path $ArchiveData.SourcePath -Range $ArchiveData.Range
    try {
      if ([string]::IsNullOrWhiteSpace($DestinationPath)) { $DestinationPath = Join-Path ([IO.Path]::GetTempPath()) ("Dumplings-InstallAnywhere-$([guid]::NewGuid().ToString('N'))") }
      $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
      $null = New-Item -Path $DestinationPath -ItemType Directory -Force
      $Selection = Export-InstallerArchiveSelection -Archive $Context.Archive -DestinationPath $DestinationPath `
        -Name $Name -CollisionAction $CollisionAction -MaximumExpandedBytes $MaximumExpandedBytes
      if ($Selection.Files.Count -eq 0) { throw "No InstallAnywhere files matched '$Name'" }
      return $Selection.Files
    } finally { Close-InstallerArchiveRange -Context $Context }
  }
}

function Get-InstallAnywhereObject {
  <#
  .SYNOPSIS
    Select one serialized InstallAnywhere Java bean by its exact class name.
  .PARAMETER Xml
    Parsed InstallScript.iap_xml document.
  .PARAMETER ClassName
    Fully qualified Java class name written in the object's class attribute.
  #>
  [OutputType([System.Xml.XmlElement])]
  param (
    [Parameter(Mandatory)][xml]$Xml,
    [Parameter(Mandatory)][string]$ClassName
  )

  # Property names such as productName and installDir occur in unrelated
  # actions. Restrict every lookup to the bean that owns the documented field.
  return $Xml.SelectSingleNode("//object[@class='$ClassName']")
}

function Get-InstallAnywhereObjectPropertyNode {
  <#
  .SYNOPSIS
    Select a direct property of one serialized InstallAnywhere Java bean.
  .PARAMETER Object
    Java-bean object element whose direct children are inspected.
  .PARAMETER Name
    Exact Java-bean property name to query.
  #>
  [OutputType([System.Xml.XmlElement])]
  param (
    [Parameter(Mandatory)][System.Xml.XmlElement]$Object,
    [Parameter(Mandatory)][string]$Name
  )

  return $Object.SelectSingleNode("./property[@name='$Name']")
}

function Get-InstallAnywhereScalarValue {
  <#
  .SYNOPSIS
    Convert an explicitly serialized primitive property to a PowerShell value.
  .PARAMETER Property
    Property element containing a direct string, Boolean, or numeric child.
  #>
  param ([Parameter(Mandatory)][System.Xml.XmlElement]$Property)

  $ValueNode = $Property.ChildNodes | Where-Object { $_.NodeType -eq [Xml.XmlNodeType]::Element } | Select-Object -First 1
  if (-not $ValueNode) { return $null }
  switch ($ValueNode.Name) {
    'boolean' { return $ValueNode.InnerText.Trim() -ieq 'true' }
    { $_ -in @('byte', 'short', 'int', 'long') } {
      $Parsed = 0L
      if ([long]::TryParse($ValueNode.InnerText.Trim(), [ref]$Parsed)) { return $Parsed }
      return $null
    }
    { $_ -in @('float', 'double') } {
      $Parsed = 0.0
      if ([double]::TryParse($ValueNode.InnerText.Trim(), [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$Parsed)) { return $Parsed }
      return $null
    }
    'string' {
      $Value = $ValueNode.InnerText.Trim()
      if (-not [string]::IsNullOrWhiteSpace($Value)) { return $Value }
      return $null
    }
    default { return $null }
  }
}

function Get-InstallAnywhereObjectPropertyValue {
  <#
  .SYNOPSIS
    Read one direct primitive property from a serialized Java bean.
  .PARAMETER Object
    Java-bean object element whose direct property is read.
  .PARAMETER Name
    Exact Java-bean property name to query.
  #>
  param (
    [Parameter(Mandatory)][System.Xml.XmlElement]$Object,
    [Parameter(Mandatory)][string]$Name
  )

  $Property = Get-InstallAnywhereObjectPropertyNode -Object $Object -Name $Name
  if (-not $Property) { return $null }
  return Get-InstallAnywhereScalarValue -Property $Property
}

function Get-InstallAnywhereUuid {
  <#
  .SYNOPSIS
    Read a UUID serialized by com.zerog.registry.UUID.
  .PARAMETER Object
    Java bean containing the UUID property.
  .PARAMETER Name
    Name of the UUID property.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][System.Xml.XmlElement]$Object,
    [Parameter(Mandatory)][string]$Name
  )

  $Property = Get-InstallAnywhereObjectPropertyNode -Object $Object -Name $Name
  if (-not $Property) { return $null }
  $UuidObject = $Property.SelectSingleNode("./object[@class='com.zerog.registry.UUID']")
  if (-not $UuidObject) { return $null }
  $ValueNode = $UuidObject.SelectSingleNode("./method[@name='update']/string")
  if (-not $ValueNode) { return $null }
  $Value = $ValueNode.InnerText.Trim()
  if ($Value -match '^[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$') { return $Value }
  return $null
}

function Get-InstallAnywhereVersion {
  <#
  .SYNOPSIS
    Assemble the structured InstallAnywhere productVersion components.
  .PARAMETER InstallerInfo
    InstallerInfoData bean containing the structured productVersion property.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][System.Xml.XmlElement]$InstallerInfo)
  $Property = Get-InstallAnywhereObjectPropertyNode -Object $InstallerInfo -Name 'productVersion'
  if (-not $Property) { return $null }

  # InstallAnywhere serializes version components as child bean properties;
  # omit absent trailing components rather than manufacturing zero values.
  $Parts = foreach ($Name in @('major', 'minor', 'revision', 'subRevision')) {
    $Value = $Property.SelectSingleNode(".//property[@name='$Name']/*")
    if ($Value) { $Value.InnerText.Trim() } else { $null }
  }
  $Parts = @($Parts | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
  if ($Parts.Count) { return $Parts -join '.' }
  return $null
}

function Get-InstallAnywhereRegistryWrite {
  <#
  .SYNOPSIS
    Return only literal uninstall registry paths present in project XML.
  .PARAMETER Xml
    Parsed InstallScript.iap_xml document containing SpeedRegistryData records.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][xml]$Xml)

  # SpeedRegistryData is the builder's structured representation of a literal
  # registry write. Do not scan the complete XML for path-like text because
  # comments, rules, and unrelated actions can contain the same strings.
  foreach ($Record in $Xml.SelectNodes("//object[@class='com.zerog.ia.installer.util.SpeedRegistryData']")) {
    $KeyPath = Get-InstallAnywhereObjectPropertyValue -Object $Record -Name 'keyPath'
    if ([string]::IsNullOrWhiteSpace($KeyPath) -or $KeyPath -notmatch '^(?<Root>HKEY_[A-Z_]+|HK[A-Z]+)\\(?<Key>.+)$') { continue }
    [pscustomobject][ordered]@{
      Root  = $Matches.Root
      Key   = $Matches.Key
      Name  = $null
      Value = Get-InstallAnywhereObjectPropertyValue -Object $Record -Name 'data'
      Type  = Get-InstallAnywhereObjectPropertyValue -Object $Record -Name 'dataType'
    }
  }
}

function Get-InstallAnywhereInstallDirectoryExpression {
  <#
  .SYNOPSIS
    Resolve the statically authored Windows installation-directory expression.
  .PARAMETER Installer
    Top-level InstallAnywhere Installer bean.
  .PARAMETER ProductName
    Product name substituted for the literal $PRODUCT_NAME$ variable.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][System.Xml.XmlElement]$Installer,
    [string]$ProductName
  )

  $InstallDirProperty = Get-InstallAnywhereObjectPropertyNode -Object $Installer -Name 'installDir'
  if (-not $InstallDirProperty) { return $null }
  $InstallDir = $InstallDirProperty.SelectSingleNode('./object')
  if (-not $InstallDir) { return $null }
  $WindowsPath = Get-InstallAnywhereObjectPropertyValue -Object $InstallDir -Name 'win32MagicFolderPath'
  if ($WindowsPath -and $ProductName) { $WindowsPath = $WindowsPath.Replace('$PRODUCT_NAME$', $ProductName) }

  # InstallAnywhere references the magic-folder object by objectID/refID. The
  # class is retained on one sibling platform property in serialized projects.
  $WindowsMagicFolder = $InstallDir.SelectSingleNode("./property[@name='win32MagicFolder']/object")
  $MagicFolderClass = if ($WindowsMagicFolder -and $WindowsMagicFolder.HasAttribute('class')) { $WindowsMagicFolder.GetAttribute('class') } else { $null }
  if (-not $MagicFolderClass) {
    $RefId = if ($WindowsMagicFolder -and $WindowsMagicFolder.HasAttribute('refID')) { $WindowsMagicFolder.GetAttribute('refID') } else { $null }
    if ($RefId) {
      $ReferencedMagicFolder = $InstallDir.SelectSingleNode("./property/object[@objectID='$RefId']")
      if ($ReferencedMagicFolder -and $ReferencedMagicFolder.HasAttribute('class')) { $MagicFolderClass = $ReferencedMagicFolder.GetAttribute('class') }
    }
  }
  $Prefix = switch -Regex ($MagicFolderClass) {
    'ProgramsDirMF$' { '%ProgramFiles%'; break }
    'UserHomeDirMF$' { '%UserProfile%'; break }
    'DesktopDirMF$' { '%Desktop%'; break }
    default { $null }
  }
  if ($Prefix -and $WindowsPath) { return Join-Path $Prefix $WindowsPath }
  if ($WindowsPath) { return $WindowsPath }
  return $null
}

function Get-InstallAnywhereStringListProperty {
  <#
  .SYNOPSIS
    Read strings stored in a serialized InstallAnywhere vector property.
  .PARAMETER Object
    Java-bean object containing the direct property.
  .PARAMETER Name
    Exact property name whose nested string elements are returned in order.
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Mandatory)][System.Xml.XmlElement]$Object,
    [Parameter(Mandatory)][string]$Name
  )

  $Property = Get-InstallAnywhereObjectPropertyNode -Object $Object -Name $Name
  if (-not $Property) { return [string[]]@() }
  return [string[]]@($Property.SelectNodes('.//string') | ForEach-Object { $_.InnerText.Trim() } | Where-Object { $_ })
}

# InstallAnywhere condition evaluation.
function Merge-InstallAnywhereRuleState {
  <#
  .SYNOPSIS
    Combine two InstallAnywhere rule states using three-valued Boolean logic.
  .PARAMETER Left
    Left True, False, or Unknown state.
  .PARAMETER Right
    Right True, False, or Unknown state.
  .PARAMETER Operator
    Boolean AND or OR operator.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][ValidateSet('True', 'False', 'Unknown')][string]$Left,
    [Parameter(Mandatory)][ValidateSet('True', 'False', 'Unknown')][string]$Right,
    [Parameter(Mandatory)][ValidateSet('And', 'Or')][string]$Operator
  )

  return Merge-InstallerConditionState -State @($Left, $Right) -Operator ($Operator -eq 'And' ? 'All' : 'Any')
}

function Resolve-InstallAnywhereRuleState {
  <#
  .SYNOPSIS
    Evaluate one serialized InstallAnywhere rule against explicit static facts.
  .PARAMETER Rule
    Rule record from Get-InstallAnywhereInfo.Rules.
  .PARAMETER PlatformName
    Exact target platform descriptor tested by PlatformChk regular expressions.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][object]$Rule,
    [string]$PlatformName
  )

  if ($Rule.Type -ne 'PlatformChk') {
    return [pscustomobject][ordered]@{ State = 'Unknown'; Reason = "Rule '$($Rule.Id)' uses target-state type '$($Rule.Type)'." }
  }
  if ([string]::IsNullOrWhiteSpace($PlatformName)) {
    return [pscustomobject][ordered]@{ State = 'Unknown'; Reason = "Rule '$($Rule.Id)' requires an explicit platform name." }
  }

  $IncludePatterns = [string[]]@($Rule.Properties['installOnPlatformList'])
  $ExcludePatterns = [string[]]@($Rule.Properties['doNotInstallOnPlatformList'])
  try {
    $Excluded = [bool]($ExcludePatterns | Where-Object { [regex]::IsMatch($PlatformName, $_, [Text.RegularExpressions.RegexOptions]::CultureInvariant) } | Select-Object -First 1)
    $Included = [bool]($IncludePatterns | Where-Object { [regex]::IsMatch($PlatformName, $_, [Text.RegularExpressions.RegexOptions]::CultureInvariant) } | Select-Object -First 1)
  } catch {
    return [pscustomobject][ordered]@{ State = 'Unknown'; Reason = "Rule '$($Rule.Id)' contains an invalid platform regular expression: $($_.Exception.Message)" }
  }

  $State = if ($Excluded) { 'False' } elseif ($IncludePatterns.Count -eq 0 -or $Included) { 'True' } else { 'False' }
  [pscustomobject][ordered]@{
    State  = $State
    Reason = "Platform '$PlatformName' was tested against InstallAnywhere rule '$($Rule.Id)'."
  }
}

function Resolve-InstallAnywhereRuleExpression {
  <#
  .SYNOPSIS
    Parse and evaluate an InstallAnywhere Boolean rule expression.
  .DESCRIPTION
    Supports identifiers, true/false literals, !, &&, ||, and parentheses with
    a 256-token and 32-level recursion limit. Unknown rules stay Unknown and no
    Java custom code, variables, registry, files, or host state are evaluated.
  .PARAMETER Expression
    Serialized action rule expression.
  .PARAMETER Rule
    Rule records from Get-InstallAnywhereInfo.Rules.
  .PARAMETER PlatformName
    Optional target platform descriptor used only by PlatformChk rules.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Expression,
    [AllowEmptyCollection()][object[]]$Rule = @(),
    [string]$PlatformName
  )

  # Project platform rules are converted to explicit identifier states once. The shared
  # evaluator then owns tokenization, precedence, bounds, and three-valued Boolean semantics.
  $IdentifierStates = [ordered]@{}
  foreach ($RuleRecord in $Rule) {
    $Identifier = [string]$RuleRecord.Id
    if ([string]::IsNullOrWhiteSpace($Identifier)) { continue }
    $RuleResult = Resolve-InstallAnywhereRuleState -Rule $RuleRecord -PlatformName $PlatformName
    if (-not $IdentifierStates.Contains($Identifier)) {
      $IdentifierStates[$Identifier] = $RuleResult
      continue
    }

    $Existing = $IdentifierStates[$Identifier]
    if ($Existing.State -ne $RuleResult.State) {
      $IdentifierStates[$Identifier] = [pscustomobject]@{
        State   = 'Unknown'
        Reasons = [string[]]@($Existing.Reason, $RuleResult.Reason, "Duplicate rule identifier '$Identifier' resolves to conflicting states.")
      }
    } else {
      $IdentifierStates[$Identifier] = [pscustomobject]@{
        State   = $Existing.State
        Reasons = [string[]]@($Existing.Reason, $RuleResult.Reason | Where-Object { $_ } | Select-Object -Unique)
      }
    }
  }

  $Result = Resolve-InstallerBooleanExpression -Expression $Expression -IdentifierState $IdentifierStates -MaximumTokenCount 256 -MaximumDepth 32
  return [pscustomobject][ordered]@{
    State          = $Result.State
    RuleIds        = [string[]]$Result.Identifiers
    UnknownRuleIds = [string[]]$Result.UnknownIdentifiers
    Reasons        = [string[]]$Result.Reasons
  }
}

function Get-InstallAnywhereActionEligibility {
  <#
  .SYNOPSIS
    Evaluate conditional InstallAnywhere actions for an explicit target platform.
  .PARAMETER Info
    Result from Get-InstallAnywhereInfo.
  .PARAMETER PlatformName
    Target platform descriptor, such as Windows 11 or Linux.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][object]$Info,
    [Parameter(Mandatory)][string]$PlatformName
  )

  process {
    foreach ($Action in @($Info.Actions)) {
      $Result = if ([string]::IsNullOrWhiteSpace([string]$Action.RuleExpression)) {
        [pscustomobject]@{ State = 'True'; RuleIds = [string[]]@(); UnknownRuleIds = [string[]]@(); Reasons = [string[]]@('The action has no rule expression.') }
      } else {
        Resolve-InstallAnywhereRuleExpression -Expression $Action.RuleExpression -Rule ([object[]]$Info.Rules) -PlatformName $PlatformName
      }
      [pscustomobject][ordered]@{
        ObjectId       = $Action.ObjectId
        Type           = $Action.Type
        RuleExpression = $Action.RuleExpression
        State          = $Result.State
        RuleIds        = [string[]]$Result.RuleIds
        UnknownRuleIds = [string[]]$Result.UnknownRuleIds
        Reasons        = [string[]]$Result.Reasons
      }
    }
  }
}

# InstallAnywhere action projection and result composition.
function New-InstallAnywhereAnalysisContext {
  <#
  .SYNOPSIS
    Parse one InstallAnywhere archive and project document for a top-level operation.
  .PARAMETER Path
    Installer path resolved by archive discovery. The XML document is decoded exactly once.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)

  $ArchiveData = Get-InstallAnywhereArchiveData -Path $Path
  $ProjectXml = Get-InstallAnywhereProjectXml -ArchiveData $ArchiveData
  if ([string]::IsNullOrWhiteSpace($ProjectXml)) { throw 'The InstallAnywhere archive does not expose InstallScript.iap_xml' }
  $Xml = [xml]$ProjectXml.TrimStart([char]0xFEFF)
  $Installer = Get-InstallAnywhereObject -Xml $Xml -ClassName 'com.zerog.ia.installer.Installer'
  $InstallerInfo = Get-InstallAnywhereObject -Xml $Xml -ClassName 'com.zerog.ia.installer.util.InstallerInfoData'
  if (-not $InstallerInfo) { throw 'The InstallAnywhere project does not contain InstallerInfoData' }
  $RegistryWrites = @(Get-InstallAnywhereRegistryWrite -Xml $Xml)

  return [pscustomobject][ordered]@{
    ArchiveData             = $ArchiveData
    Xml                     = $Xml
    Installer               = $Installer
    InstallerInfo           = $InstallerInfo
    RegistryWrites          = [object[]]$RegistryWrites
    RegistryAssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite $RegistryWrites
    ActionAndRuleInfo       = Get-InstallAnywhereActionAndRuleInfo -Xml $Xml
  }
}

function Get-InstallAnywhereActionAndRuleInfo {
  <#
  .SYNOPSIS
    Project focused InstallAnywhere action and conditional-rule evidence.
  .DESCRIPTION
    The project serializes all platform actions in one graph. Records with a
    non-empty RuleExpression are therefore conditional evidence, not proof that
    the action runs on Windows. Object references are resolved only within this
    document and custom Java code is never loaded or executed.
  .PARAMETER Xml
    Parsed InstallScript.iap_xml document.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][xml]$Xml)

  $ActionRecords = [Collections.Generic.List[object]]::new()
  $InstalledPayloads = [Collections.Generic.List[object]]::new()
  $ExecutedPayloads = [Collections.Generic.List[object]]::new()
  $Shortcuts = [Collections.Generic.List[object]]::new()
  $Launchers = [Collections.Generic.List[object]]::new()
  $KnownFocusedActions = @('InstallFile', 'InstallDirectory', 'InstallZipfile', 'BOMAction', 'ExecFile', 'CreateShortcut', 'MakeExecutable', 'InstallUninstaller', 'SpeedRegistry', 'RebootAction')

  foreach ($Action in @($Xml.SelectNodes("//object[starts-with(@class, 'com.zerog.ia.installer.actions.')]"))) {
    $Class = $Action.GetAttribute('class')
    $ActionType = $Class.Substring($Class.LastIndexOf('.') + 1)
    $ObjectId = $Action.GetAttribute('objectID')
    $RuleExpression = Get-InstallAnywhereObjectPropertyValue -Object $Action -Name 'ruleExpression'
    $ScalarProperties = [ordered]@{}
    foreach ($Property in @($Action.SelectNodes('./property'))) {
      $Value = Get-InstallAnywhereScalarValue -Property $Property
      if ($null -ne $Value) { $ScalarProperties[$Property.GetAttribute('name')] = $Value }
    }
    $TargetProperty = Get-InstallAnywhereObjectPropertyNode -Object $Action -Name 'targetAction'
    $TargetObject = if ($TargetProperty) { $TargetProperty.SelectSingleNode('./object') } else { $null }
    if ($TargetObject -and $TargetObject.HasAttribute('refID')) {
      $TargetObject = $Xml.SelectSingleNode("//object[@objectID='$($TargetObject.GetAttribute('refID'))']")
    }
    $TargetObjectId = $TargetObject ? $TargetObject.GetAttribute('objectID') : $null
    $TargetClass = $TargetObject ? $TargetObject.GetAttribute('class') : $null
    $TargetName = $TargetObject ? (Get-InstallAnywhereObjectPropertyValue -Object $TargetObject -Name 'destinationName') : $null

    $ActionRecords.Add([pscustomobject][ordered]@{
        Type           = $ActionType
        Class          = $Class
        ObjectId       = $ObjectId
        UninstallPhase = $ScalarProperties['belongsToUninstallPhase']
        RuleExpression = $RuleExpression
        TargetObjectId = $TargetObjectId
        TargetClass    = $TargetClass
        Properties     = $ScalarProperties
      })

    if ($ActionType -in @('InstallFile', 'InstallDirectory', 'InstallZipfile', 'BOMAction')) {
      $InstalledPayloads.Add([pscustomobject][ordered]@{
          Type            = $ActionType
          ObjectId        = $ObjectId
          SourceName      = $ScalarProperties['sourceName']
          SourcePath      = $ScalarProperties['sourcePath']
          DestinationName = $ScalarProperties['destinationName']
          Size            = $ScalarProperties['fileSize'] ?? $ScalarProperties['totalSize']
          RuleExpression  = $RuleExpression
        })
    } elseif ($ActionType -eq 'ExecFile') {
      $ExecutedPayloads.Add([pscustomobject][ordered]@{
          ObjectId        = $ObjectId
          TargetObjectId  = $TargetObjectId
          TargetClass     = $TargetClass
          Target          = $TargetName
          Arguments       = $ScalarProperties['commandLineArgs']
          WaitForProcess  = $ScalarProperties['waitForProcess']
          SuppressConsole = $ScalarProperties['suppressConsoleWindow']
          RuleExpression  = $RuleExpression
        })
    } elseif ($ActionType -eq 'CreateShortcut') {
      $Shortcuts.Add([pscustomobject][ordered]@{
          ObjectId         = $ObjectId
          Name             = $ScalarProperties['destinationName']
          TargetObjectId   = $TargetObjectId
          Target           = $TargetName
          Arguments        = $ScalarProperties['args']
          WorkingDirectory = $ScalarProperties['workingDir']
          RuleExpression   = $RuleExpression
        })
    } elseif ($ActionType -eq 'MakeExecutable') {
      $LaxProperties = [ordered]@{}
      foreach ($LaxProperty in @($Action.SelectNodes("./property[@name='propertyList']//object[@class='com.zerog.ia.installer.util.LAXPropertyData']"))) {
        $Name = Get-InstallAnywhereObjectPropertyValue -Object $LaxProperty -Name 'propertyName'
        if ($Name) { $LaxProperties[$Name] = Get-InstallAnywhereObjectPropertyValue -Object $LaxProperty -Name 'propertyValue' }
      }
      $Launchers.Add([pscustomobject][ordered]@{
          ObjectId       = $ObjectId
          Name           = $ScalarProperties['destinationName']
          MainClass      = $ScalarProperties['mainClass']
          GuiLauncher    = $ScalarProperties['guiLauncher']
          ExecutionLevel = $ScalarProperties['execLevel']
          VmBehavior     = $ScalarProperties['launcherVMBehavior']
          LaxProperties  = $LaxProperties
          RuleExpression = $RuleExpression
        })
    }
  }

  $Rules = foreach ($Rule in @($Xml.SelectNodes("//object[contains(@class, '.installer.rules.')]"))) {
    $Properties = [ordered]@{}
    foreach ($Property in @($Rule.SelectNodes('./property'))) {
      $Name = $Property.GetAttribute('name')
      $Value = Get-InstallAnywhereScalarValue -Property $Property
      if ($null -ne $Value) { $Properties[$Name] = $Value; continue }
      $Values = @(Get-InstallAnywhereStringListProperty -Object $Rule -Name $Name)
      if ($Values.Count) { $Properties[$Name] = [string[]]$Values }
    }
    [pscustomobject][ordered]@{
      Id         = $Properties['ruleId']
      Type       = $Rule.GetAttribute('class').Split('.')[-1]
      Class      = $Rule.GetAttribute('class')
      ObjectId   = $Rule.GetAttribute('objectID')
      Properties = $Properties
    }
  }

  [pscustomobject][ordered]@{
    Actions                  = [object[]]$ActionRecords
    Rules                    = [object[]]@($Rules)
    InstalledPayloads        = [object[]]$InstalledPayloads
    ExecutedPayloads         = [object[]]$ExecutedPayloads
    Shortcuts                = [object[]]$Shortcuts
    Launchers                = [object[]]$Launchers
    ConditionalActionCount   = @($ActionRecords | Where-Object { $_.RuleExpression }).Count
    UnsupportedActionClasses = [string[]]@($ActionRecords | Where-Object Type -NotIn $KnownFocusedActions | ForEach-Object Class | Sort-Object -Unique)
  }
}

function Get-InstallAnywhereInfo {
  <#
  .SYNOPSIS
    Read static product metadata from an InstallAnywhere installer
  .DESCRIPTION
    Parses the embedded InstallAnywhere project XML. Product identity is
    explicit, while built-in uninstall registration may require VM validation.
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process {
    $Context = New-InstallAnywhereAnalysisContext -Path $Path
    $ArchiveData = $Context.ArchiveData
    $Xml = $Context.Xml
    $Installer = $Context.Installer
    $InstallerInfo = $Context.InstallerInfo
    $RegistryWrites = [object[]]$Context.RegistryWrites
    $RegistryAssociationInfo = $Context.RegistryAssociationInfo
    $ExplicitUninstallWrites = @($RegistryWrites | Where-Object { $_.Key -match '(?i)^Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\(?<Code>[^\\]+)' })
    $ExplicitProductCodes = @($ExplicitUninstallWrites | ForEach-Object {
        if ($_.Key -match '(?i)^Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\(?<Code>[^\\]+)') { $Matches.Code }
      } | Sort-Object -Unique)

    # InstallUninstaller creates the Windows ARP entry internally. The embedded
    # runtime builds its uninstall subkey from productName, not productID; the
    # project UUID is written separately as the ProductID registry value.
    $UninstallerActions = @($Xml.SelectNodes("//object[@class='com.zerog.ia.installer.actions.InstallUninstaller']") | Where-Object {
        (Get-InstallAnywhereObjectPropertyValue -Object $_ -Name 'shouldUninstall') -eq $true
      })
    $InstanceDefinitionProperty = if ($Installer) { Get-InstallAnywhereObjectPropertyNode -Object $Installer -Name 'instanceDefinition' } else { $null }
    $InstanceDefinition = if ($InstanceDefinitionProperty) { $InstanceDefinitionProperty.SelectSingleNode('./object') } else { $null }
    $InstanceManagementEnabled = $InstanceDefinition -and (Get-InstallAnywhereObjectPropertyValue -Object $InstanceDefinition -Name 'enableInstanceManagement') -eq $true
    $DisplayName = Get-InstallAnywhereObjectPropertyValue -Object $InstallerInfo -Name 'productName'
    $ProductCode = if ($ExplicitProductCodes.Count -eq 1) {
      $ExplicitProductCodes[0]
    } elseif ($UninstallerActions.Count -and -not $InstanceManagementEnabled) {
      $DisplayName
    } else {
      $null
    }
    $WritesAppsAndFeaturesEntry = if ($ExplicitUninstallWrites.Count -or $UninstallerActions.Count) { $true } else { $null }
    $ExplicitScopes = @(@(
        if ($ExplicitUninstallWrites.Root -match 'HKLM|HKEY_LOCAL_MACHINE') { 'machine' }
        if ($ExplicitUninstallWrites.Root -match 'HKCU|HKEY_CURRENT_USER') { 'user' }
      ) | Select-Object -Unique)
    $Scope = if ($ExplicitScopes.Count -eq 1) {
      $ExplicitScopes[0]
    } else {
      $null
    }

    $Warnings = [Collections.Generic.List[string]]::new()
    if ($ExplicitProductCodes.Count -gt 1) {
      $Warnings.Add('InstallAnywhere contains more than one explicit uninstall key. Select the visible ARP entry using scope and condition evidence.')
    }
    if ($UninstallerActions.Count -and $InstanceManagementEnabled) {
      $Warnings.Add('InstallAnywhere instance management can append a runtime instance number to the product-name uninstall key; the exact ProductCode requires installed-state evidence.')
    }
    if ($UninstallerActions.Count -and -not $Scope) {
      $Warnings.Add('InstallAnywhere chooses the built-in uninstall entry hive at runtime and can fall back from HKLM to HKCU. Validate scope in a VM.')
    }
    if (-not $WritesAppsAndFeaturesEntry) {
      $Warnings.Add('No enabled InstallUninstaller action or explicit uninstall registry write was found. The package may omit ARP registration or delegate it to custom code.')
    }

    $ActionClasses = @($Xml.SelectNodes('//object[starts-with(@class, ''com.zerog.ia.installer.actions.'')]') | ForEach-Object { $_.Attributes['class'].Value } | Sort-Object -Unique)
    $ActionAndRuleInfo = $Context.ActionAndRuleInfo
    if ($ActionAndRuleInfo.UnsupportedActionClasses -match '(?i)CustomCode|CustomAction') {
      $Warnings.Add('InstallAnywhere contains custom-code actions that cannot be interpreted statically and may change files, registry state, or ARP behavior.')
    }
    $UninstallerEvidence = @($UninstallerActions | ForEach-Object {
        [pscustomobject][ordered]@{
          DestinationName = Get-InstallAnywhereObjectPropertyValue -Object $_ -Name 'destinationName'
          ExecutionLevel  = Get-InstallAnywhereObjectPropertyValue -Object $_ -Name 'execLevel'
          ShouldUninstall = $true
        }
      })
    $ProjectProductId = Get-InstallAnywhereUuid -Object $InstallerInfo -Name 'productID'
    $DefaultInstallLocation = if ($Installer) { Get-InstallAnywhereInstallDirectoryExpression -Installer $Installer -ProductName $DisplayName } else { $null }
    $NotUpdateGlobalRegistry = if ($Installer) { Get-InstallAnywhereObjectPropertyValue -Object $Installer -Name 'notUpdateGlobalRegistry' } else { $null }
    [pscustomobject][ordered]@{
      Path                           = $ArchiveData.SourcePath
      InstallerType                  = 'exe'
      ProductCode                    = $ProductCode
      UpgradeCode                    = Get-InstallAnywhereUuid -Object $InstallerInfo -Name 'upgradeCode'
      DisplayName                    = $DisplayName
      DisplayVersion                 = Get-InstallAnywhereVersion -InstallerInfo $InstallerInfo
      Publisher                      = Get-InstallAnywhereObjectPropertyValue -Object $InstallerInfo -Name 'vendorName'
      Scope                          = $Scope
      DefaultInstallLocation         = $DefaultInstallLocation
      WritesAppsAndFeaturesEntry     = $WritesAppsAndFeaturesEntry
      AppsAndFeaturesProductCode     = $WritesAppsAndFeaturesEntry -eq $true ? $ProductCode : $null
      AppsAndFeaturesInstallerType   = $WritesAppsAndFeaturesEntry -eq $true ? 'exe' : $null
      Diagnostics                    = @(ConvertTo-InstallerDiagnostic -InputObject @([object[]]$Warnings) -Source 'InstallAnywhere' -Kind Incomplete -Areas Metadata)
      UnresolvedFields               = [string[]]@(
        if (-not $ProductCode) { 'ProductCode' }
        if (-not $Scope) { 'Scope' }
      )
      Family                         = 'InstallAnywhere'
      PublisherUrl                   = Get-InstallAnywhereObjectPropertyValue -Object $InstallerInfo -Name 'vendorURL'
      ProjectProductId               = $ProjectProductId
      InstanceManagementEnabled      = [bool]$InstanceManagementEnabled
      SupportsSilentUI               = $Installer ? (Get-InstallAnywhereObjectPropertyValue -Object $Installer -Name 'supportsSilentUI') : $null
      SupportsConsoleUI              = $Installer ? (Get-InstallAnywhereObjectPropertyValue -Object $Installer -Name 'supportsConsoleUI') : $null
      ResponseFileEnabled            = $Installer ? (Get-InstallAnywhereObjectPropertyValue -Object $Installer -Name 'responseFileEnabled') : $null
      UpdatesInstallAnywhereRegistry = $null -eq $NotUpdateGlobalRegistry ? $null : -not [bool]$NotUpdateGlobalRegistry
      BuiltInUninstaller             = $UninstallerEvidence
      ActionClasses                  = [string[]]$ActionClasses
      Actions                        = $ActionAndRuleInfo.Actions
      Rules                          = $ActionAndRuleInfo.Rules
      InstalledPayloads              = $ActionAndRuleInfo.InstalledPayloads
      ExecutedPayloads               = $ActionAndRuleInfo.ExecutedPayloads
      Shortcuts                      = $ActionAndRuleInfo.Shortcuts
      Launchers                      = $ActionAndRuleInfo.Launchers
      ConditionalActionCount         = $ActionAndRuleInfo.ConditionalActionCount
      UnsupportedActionClasses       = $ActionAndRuleInfo.UnsupportedActionClasses
      RegistryWrites                 = $RegistryWrites
      RegistryAssociationInfo        = $RegistryAssociationInfo
      Protocols                      = $RegistryAssociationInfo.Protocols
      FileExtensions                 = $RegistryAssociationInfo.FileExtensions
      EmbeddedFiles                  = @($ArchiveData.EntryNames)
      ArchiveRange                   = $ArchiveData.Range
      ParserVersionInfo              = [pscustomobject]@{ Parser = 'Dumplings.PackageModule.InstallAnywhere'; ParserMajor = 3; Sources = @('Validated embedded ZIP archive', 'InstallerData/Execute.zip', 'InstallScript.iap_xml', 'InstallAnywhere InstallUninstaller runtime behavior', 'Structured action and rule graph') }
    }
  }
}

function Test-InstallAnywhereInstaller {
  <#
  .SYNOPSIS
    Test whether a file contains a parseable InstallAnywhere project
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([bool])] param([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { try { $null = Get-InstallAnywhereInfo -Path $Path; $true } catch { $false } }
}

function Read-ProtocolsFromInstallAnywhere {
  <#
  .SYNOPSIS
    Read literal URL protocol names from InstallAnywhere registry evidence
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallAnywhereInfo -Path $Path).Protocols }
}

function Read-FileExtensionsFromInstallAnywhere {
  <#
  .SYNOPSIS
    Read literal file extensions from InstallAnywhere registry evidence
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallAnywhereInfo -Path $Path).FileExtensions }
}

function Read-ProductVersionFromInstallAnywhere {
  <#
  .SYNOPSIS
    Read the explicit InstallAnywhere product version
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallAnywhereInfo -Path $Path).DisplayVersion }
}

function Read-ProductNameFromInstallAnywhere {
  <#
  .SYNOPSIS
    Read the explicit InstallAnywhere product name
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallAnywhereInfo -Path $Path).DisplayName }
}

function Read-PublisherFromInstallAnywhere {
  <#
  .SYNOPSIS
    Read the explicit InstallAnywhere publisher
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallAnywhereInfo -Path $Path).Publisher }
}

function Read-ProductCodeFromInstallAnywhere {
  <#
  .SYNOPSIS
    Read the InstallAnywhere project product identifier
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallAnywhereInfo -Path $Path).ProductCode }
}

Export-ModuleMember -Function Get-InstallAnywhereInfo, Get-InstallAnywhereActionEligibility, Resolve-InstallAnywhereRuleExpression, Expand-InstallAnywhereInstaller, Test-InstallAnywhereInstaller, Read-ProtocolsFromInstallAnywhere, Read-FileExtensionsFromInstallAnywhere, Read-ProductVersionFromInstallAnywhere, Read-ProductNameFromInstallAnywhere, Read-PublisherFromInstallAnywhere, Read-ProductCodeFromInstallAnywhere
