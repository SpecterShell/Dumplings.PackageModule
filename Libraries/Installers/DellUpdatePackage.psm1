# SPDX-License-Identifier: Apache-2.0
# Dell Update Package (DUP) static wrapper analysis, independently derived from
# Command Update 4.1/5.7 and Watchdog 2.0 media. CLI reference:
# https://www.dell.com/support/manuals/en-us/dell-update-packages
#
# PE sections (.rsrc: DUPFramework identity and elevation manifest)
# +-- overlay: ZIP (older media) or 7z (current media)
# |   +-- Mup.xml: selected executable, commands, parameters, inventory
# |   +-- package.xml: SoftwareComponent applicability/release metadata
# |   `-- configured executable and support files
# `-- padding/trailer and optional WIN_CERTIFICATE (outside archive)
#
# 7z signature header, archive-relative offsets, little-endian integers:
# 0x00/6: 37 7A BC AF 27 1C; 0x06/2: version; 0x08/4: start-header CRC;
# 0x0C/8: next-header offset; 0x14/8: next-header size; 0x1C/4: header CRC.
# ZIP local-header magic: 50 4B 03 04. Older DUP central-directory offsets
# can be file-absolute and include the PE stub. Shared archive readers resolve
# these ranges. MUP packagingtype describes the vendor package, not the outer
# container. MUP inventory identities do not necessarily describe visible ARP.

function Read-DellUpdatePackageXml {
  <#
  .SYNOPSIS
    Parse bounded XML without DTDs or external resource resolution.
  .PARAMETER Bytes
    Caller-owned XML bytes, including an optional encoding declaration.
  #>
  param ([Parameter(Mandatory)][byte[]]$Bytes)
  if ($Bytes.Length -gt 4194304) { throw 'Dell package XML exceeds the 4 MiB limit.' }
  $Settings = [Xml.XmlReaderSettings]::new()
  $Settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
  $Settings.XmlResolver = $null
  $Settings.MaxCharactersInDocument = 4194304
  $Stream = [IO.MemoryStream]::new($Bytes, $false)
  try {
    $Reader = [Xml.XmlReader]::Create($Stream, $Settings)
    try {
      $Document = [Xml.XmlDocument]::new()
      $Document.XmlResolver = $null
      $Document.Load($Reader)
      return , $Document
    } finally { $Reader.Dispose() }
  } finally { $Stream.Dispose() }
}

function Get-DellUpdatePackageXmlText {
  <#
  .SYNOPSIS
    Read an optional child without StrictMode-sensitive XML adapters.
  .PARAMETER Node
    Configuration element to inspect.
  .PARAMETER XPath
    Relative XPath using local-name() for versioned Dell namespaces.
  #>
  param ([AllowNull()][Xml.XmlNode]$Node, [Parameter(Mandatory)][string]$XPath)
  if ($null -eq $Node) { return $null }
  $Child = $Node.SelectSingleNode($XPath)
  if ($Child) { return $Child.InnerText.Trim() }
}

function ConvertTo-DellUpdatePackageArgument {
  <#
  .SYNOPSIS
    Render literal MUP vendor options while preserving container quoting.
  .PARAMETER Node
    vendoroption, container, optionvalue, or containervalue XML node.
  .PARAMETER Depth
    Internal recursion bound for nested containers.
  #>
  param ([Parameter(Mandatory)][Xml.XmlNode]$Node, [int]$Depth = 0)
  if ($Depth -gt 8) { throw 'Dell MUP option nesting exceeds the limit.' }
  if ($Node.LocalName -cnotin @('optionvalue', 'containervalue', 'container', 'vendoroption', 'parametermapping')) { throw "Unsupported Dell MUP command element '$($Node.LocalName)'." }
  if ($Node.LocalName -cin @('optionvalue', 'containervalue')) {
    $Token = $Node.GetAttribute('switch') + $Node.InnerText.Trim()
    if ($Node.GetAttribute('requiresvalue') -ieq 'true') {
      $Quote = $Node.GetAttribute('enclose')
      $Token += $Node.GetAttribute('valuedelimiter') + $Quote + '<VALUE>' + $Quote
    }
    return $Token
  }
  if ($Node.LocalName -ceq 'container') {
    $Prefix = $Node.SelectSingleNode("*[local-name()='containervalue']")
    if (-not $Prefix) { throw 'Dell MUP option container has no containervalue.' }
    $Children = @($Node.SelectNodes("*[local-name()!='containervalue']") | ForEach-Object { ConvertTo-DellUpdatePackageArgument -Node $_ -Depth ($Depth + 1) })
    $Quote = $Prefix.GetAttribute('enclose')
    return $Prefix.GetAttribute('switch') + $Prefix.InnerText.Trim() + $Prefix.GetAttribute('valuedelimiter') + $Quote + ($Children -join ' ') + $Quote
  }
  return (@($Node.SelectNodes('*') | ForEach-Object { ConvertTo-DellUpdatePackageArgument -Node $_ -Depth ($Depth + 1) }) -join ' ')
}

function ConvertFrom-DellUpdatePackageConfiguration {
  <#
  .SYNOPSIS
    Decode Mup.xml selection, commands, inventory, and vendor return mappings.
  .PARAMETER Content
    Bounded MUP XML text. Referenced files are never fetched or executed.
  .OUTPUTS
    Configuration facts. VendorReturnCodes belong to the nested executable,
    not the outer DUP process. Inventory remains separate from visible ARP.
  #>
  [CmdletBinding()]
  param ([Parameter(Mandatory)][string]$Content)
  if ($Content.Length -gt 4194304) { throw 'Dell MUP text exceeds the limit.' }
  # A text caller has already decoded the document; normalize its declaration
  # before the secure byte reader so UTF-16 declarations do not corrupt UTF-8.
  $Content = $Content.TrimStart([char]0xFEFF) -replace '^\s*<\?xml[^?]*\?>', ''
  ConvertFrom-DellUpdatePackageXml -Document (Read-DellUpdatePackageXml -Bytes ([Text.Encoding]::UTF8.GetBytes($Content)))
}

function ConvertFrom-DellUpdatePackageXml {
  <#
  .SYNOPSIS
    Project a parsed MUP document without reparsing its bytes.
  .PARAMETER Document
    Validated, bounded XML document.
  #>
  param ([Parameter(Mandatory)][Xml.XmlDocument]$Document)
  $Root = $Document.DocumentElement
  if ($Root.LocalName -cne 'MUPDefinition' -or $Root.NamespaceURI -cne 'http://schemas.dell.com/openmanage/cm/2/0/mupdefinition.xsd') { throw 'The XML is not a supported Dell MUPDefinition.' }
  $Package = $Root.SelectSingleNode("*[local-name()='packageinformation']")
  $Executable = $Root.SelectSingleNode("*[local-name()='executable']")
  if ($Root.SelectNodes("*[local-name()='executable']").Count -ne 1 -or $Executable.SelectNodes("*[local-name()='executablename']").Count -ne 1) { throw 'Dell MUP has no unique configured execution route.' }
  $ExecutableName = Get-DellUpdatePackageXmlText -Node $Executable -XPath "*[local-name()='executablename']"
  if (-not $Package -or [string]::IsNullOrWhiteSpace($ExecutableName)) { throw 'Dell MUP lacks packageinformation or a configured executable.' }
  $null = Resolve-SafeExtractionPath -DestinationPath ([IO.Path]::GetTempPath()) -RelativePath $ExecutableName
  $Behaviors = @(
    foreach ($Node in $Root.SelectNodes("*[local-name()='behaviors']/*[local-name()='behavior']")) {
      $Arguments = $null
      $UnresolvedReason = $null
      try { $Arguments = (@($Node.SelectNodes('*') | ForEach-Object { ConvertTo-DellUpdatePackageArgument -Node $_ }) -join ' ') } catch { $UnresolvedReason = $_.Exception.Message }
      [pscustomobject]@{ Name = $Node.GetAttribute('name'); Arguments = $Arguments; UnresolvedReason = $UnresolvedReason; Xml = $Node.OuterXml }
    }
  )
  $Unattended = @($Behaviors | Where-Object Name -CEQ 'unattended')
  [pscustomobject][ordered]@{
    ProductName                = Get-DellUpdatePackageXmlText -Node $Package -XPath "*[local-name()='name']"
    ProductVersion             = Get-DellUpdatePackageXmlText -Node $Package -XPath "*[local-name()='version']"
    SpecificationVersion       = Get-DellUpdatePackageXmlText -Node $Package -XPath "*[local-name()='mupspecificationversion']"
    InstallerTechnology        = Get-DellUpdatePackageXmlText -Node $Package -XPath "*[local-name()='installertype']"
    PackagingType              = Get-DellUpdatePackageXmlText -Node $Package -XPath "*[local-name()='packagingtype']"
    ReleaseType                = Get-DellUpdatePackageXmlText -Node $Package -XPath "*[local-name()='releasetype']"
    ExecutableName             = $ExecutableName
    ExecutableArchitecture     = $Executable.GetAttribute('architecture')
    ExecutableXml              = $Executable.OuterXml
    SupportedOperatingSystems  = @($Package.SelectNodes("*[local-name()='supportedoperatingsystems']/*") | ForEach-Object { [pscustomobject]@{ Name = $_.GetAttribute('name'); Architecture = $_.GetAttribute('architecture') } })
    Behaviors                  = $Behaviors
    Parameters                 = @($Root.SelectNodes("*[local-name()='parameters']/*") | ForEach-Object {
        $Arguments = $null
        $UnresolvedReason = $null
        try { $Arguments = ConvertTo-DellUpdatePackageArgument -Node $_ } catch { $UnresolvedReason = $_.Exception.Message }
        [pscustomobject]@{ Name = $_.GetAttribute('name'); Arguments = $Arguments; UnresolvedReason = $UnresolvedReason; Xml = $_.OuterXml }
      })
    VendorReturnCodes          = @($Root.SelectNodes("*[local-name()='returncodes']/*") | ForEach-Object { [pscustomobject]@{ Name = $_.GetAttribute('name'); Values = @($_.SelectNodes("*[local-name()='vendorreturncode']") | ForEach-Object InnerText) } })
    Inventory                  = @($Root.SelectNodes("*[local-name()='inventorymetadata']/*") | ForEach-Object OuterXml)
    InventoryUpgradeCodes      = @($Root.SelectNodes("*[local-name()='inventorymetadata']//*[local-name()='upgradecode']") | ForEach-Object InnerText)
    Content                    = @($Package.SelectNodes("*[local-name()='content']/*") | ForEach-Object OuterXml)
    SupportsSilentInstallation = [bool]($Unattended.Count -eq 1 -and $Unattended[0].Arguments -and $Unattended[0].Arguments -notmatch '<VALUE>')
  }
}

function Open-DellUpdatePackage {
  <#
  .SYNOPSIS
    Validate the framework, physical archive, and MUP selection.
  .PARAMETER Path
    Source executable. Returned context owns archive and source streams.
  .PARAMETER MaximumEntries
    Maximum catalog size, including configuration and support files.
  .PARAMETER MaximumExpandedBytes
    Maximum declared aggregate archive output in bytes.
  .OUTPUTS
    Context; release ArchiveContext with Close-InstallerArchiveRange.
  #>
  param ([Parameter(Mandatory)][string]$Path, [int]$MaximumEntries = 16384, [long]$MaximumExpandedBytes = 4294967296)
  $Path = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
  $Stream = [IO.File]::OpenRead($Path)
  try {
    $Layout = Get-PELayout -Stream $Stream
    if (-not $Layout) { throw 'The Dell package is not a valid PE image.' }
    $Version = Get-PEVersionStringTable -Stream $Stream -Layout $Layout
    $Identity = $Version.PSObject.Properties['OriginalFilename']?.Value
    if ([string]$Identity -notmatch '^DUPFramework\.exe[\s\x00]*$') { throw 'The PE does not identify the Dell DUP framework.' }
    $OverlayOffset = 0L
    foreach ($Section in $Layout.Sections) { $OverlayOffset = [Math]::Max($OverlayOffset, [long]$Section.RawOffset + [long]$Section.RawSize) }
    $LogicalEnd = $Stream.Length
    $Certificate = $Layout.DataDirectories.Certificate
    if ($Certificate.Size -gt 0 -and ($Certificate.Offset -lt 0 -or $Certificate.Offset -gt $Stream.Length -or $Certificate.Size -gt $Stream.Length - $Certificate.Offset)) { throw 'The Dell certificate table is outside the file.' }
    if ($Certificate.Size -gt 0 -and $Certificate.Offset -ge $OverlayOffset) { $LogicalEnd = [long]$Certificate.Offset }
    if ($LogicalEnd - $OverlayOffset -lt 32) { throw 'The Dell package has no bounded payload overlay.' }
    $Prefix = Read-BinaryBytes -Stream $Stream -Offset $OverlayOffset -Count 6
  } finally { $Stream.Dispose() }
  if ([Convert]::ToHexString($Prefix) -ceq '377ABCAF271C') {
    $Route = 'SevenZip'
    $Ranges = @(Get-EmbeddedSevenZipArchiveRange -Path $Path -StartOffset $OverlayOffset -MaximumArchives 1)
  } elseif ([Convert]::ToHexString($Prefix).StartsWith('504B0304')) {
    $Route = 'Zip'
    $Ranges = @(Get-EmbeddedZipArchiveRange -Path $Path -MaximumArchives 1)
  } else { throw 'The Dell package overlay is neither a supported ZIP nor a 7z archive.' }
  if ($Ranges.Count -ne 1 -or $Ranges[0].Offset + $Ranges[0].Length -gt $LogicalEnd) { throw 'The Dell archive range is invalid or overlaps the certificate table.' }
  if ($Route -ceq 'SevenZip' -and $Ranges[0].Offset -ne $OverlayOffset) { throw 'The Dell 7z archive does not start at the PE overlay boundary.' }
  $Context = Open-InstallerArchiveRange -Path $Path -Range $Ranges[0]
  try {
    $Entries = [Collections.Generic.List[object]]::new()
    $Names = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $Total = 0L
    foreach ($Entry in Get-InstallerArchiveEntry -Archive $Context.Archive) {
      if ($Entries.Count -ge $MaximumEntries) { throw 'Dell package catalog exceeds the entry limit.' }
      $SafePath = Resolve-SafeExtractionPath -DestinationPath ([IO.Path]::GetTempPath()) -RelativePath $Entry.FullName
      if (-not $Names.Add($SafePath)) { throw 'Dell package catalog contains duplicate paths.' }
      if ($Entry.LinkTarget -or $Entry.IsEncrypted) { throw 'Dell package links or encrypted entries are unsupported.' }
      if ($Entry.Length -lt 0 -or $Entry.Length -gt $MaximumExpandedBytes - $Total) { throw 'Dell package catalog exceeds the expanded-byte limit.' }
      $Total += $Entry.Length
      $Entries.Add($Entry)
    }
    $MupEntries = @($Entries | Where-Object { $_.FullName -ieq 'mup.xml' })
    if ($MupEntries.Count -ne 1) { throw 'Dell package requires exactly one root Mup.xml.' }
    $Mup = Read-DellUpdatePackageXml -Bytes (Read-InstallerArchiveEntryBytes -Entry $MupEntries[0] -MaximumBytes 4194304)
    $Configuration = ConvertFrom-DellUpdatePackageXml -Document $Mup
    $Selected = @($Entries | Where-Object { $_.FullName.Replace('/', '\') -ieq $Configuration.ExecutableName.Replace('/', '\') })
    $PackageEntries = @($Entries | Where-Object { $_.FullName -ieq 'package.xml' })
    $Package = $null
    $Diagnostics = @()
    # Optional release metadata does not define the executable's family. Keep
    # validated MUP/container evidence if this separate document is damaged.
    if ($PackageEntries.Count -eq 1) {
      try {
        $Package = Read-DellUpdatePackageXml -Bytes (Read-InstallerArchiveEntryBytes -Entry $PackageEntries[0] -MaximumBytes 4194304)
        if ($Package.DocumentElement.LocalName -cne 'SoftwareComponent') { throw 'Dell package.xml has an unsupported document root.' }
      } catch {
        $Package = $null
        $Diagnostics = @(New-InstallerDiagnostic -Id 'DellUpdatePackage.PackageMetadata.Invalid' -Source 'Dell Update Package' -Kind Incomplete -Areas Metadata -AffectedFields PackageMetadata, ReleaseNotes -Message "Optional package.xml could not be read: $($_.Exception.Message)")
      }
    }
    return [pscustomobject]@{ Path = $Path; Route = $Route; ArchiveContext = $Context; Entries = $Entries; Selected = $Selected; Configuration = $Configuration; Package = $Package; Diagnostics = $Diagnostics; FrameworkVersion = $Version.PSObject.Properties['FileVersion']?.Value; OuterArchitecture = $Layout.MachineName }
  } catch { Close-InstallerArchiveRange -Context $Context; throw }
}

function Test-DellUpdatePackage {
  <#
  .SYNOPSIS
    Test structural DUP identity without extracting or executing payloads.
  .PARAMETER Path
    Executable to inspect; marker strings or branding alone do not qualify.
  #>
  [OutputType([bool])]
  param ([Parameter(Mandatory, Position = 0)][string]$Path)
  $Context = $null
  try { $Context = Open-DellUpdatePackage -Path $Path; return $true } catch { return $false } finally { if ($Context) { Close-InstallerArchiveRange -Context $Context.ArchiveContext } }
}

function Get-DellUpdatePackageNestedInfo {
  <#
  .SYNOPSIS
    Follow selected MSI, EXE, and configured 7z SFX routes with bounded staging.
  .PARAMETER Path
    Resolved selected payload path. No payload executes.
  .PARAMETER WorkPath
    Owned temporary analysis directory.
  .PARAMETER Budget
    Shared remaining expanded-byte budget across all wrapper layers.
  .PARAMETER Diagnostics
    Caller-owned diagnostic collection.
  .PARAMETER Depth
    Maximum three additional configured 7z wrapper layers.
  .PARAMETER Arguments
    MUP unattended arguments forwarded to static command-line simulation.
  .OUTPUTS
    Family and detached metadata; temporary paths are not valid after analysis.
  #>
  param ([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$WorkPath, [Parameter(Mandatory)]$Budget, [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[object]]$Diagnostics, [int]$Depth = 0, [AllowEmptyString()][string]$Arguments = '')
  if ($Depth -gt 3) { throw 'Dell nested wrapper depth exceeds the limit.' }
  if (Test-DellUpdatePackage -Path $Path) { throw 'Nested Dell packages require separate applicability analysis.' }
  if ([IO.Path]::GetExtension($Path) -ieq '.msi') { return [pscustomobject]@{ Family = 'MSI'; Info = Get-MsiInstallerInfo -Path $Path } }
  $Analysis = Get-InstallerAnalysis -Path $Path -ExtractEmbeddedMsi -CommandLine ('"' + $Path + '" ' + $Arguments)
  $Successful = @($Analysis.ParserResults | Where-Object Success)
  if ($Successful.Count -ne 1) { throw 'The selected Dell payload has no unique supported nested installer parser.' }
  $Result = $Successful[0].Result
  $Metadata = $Result.PSObject.Properties['Metadata']?.Value
  # The analyzer already detached Setup.ini-selected MSI metadata before
  # cleaning its extraction tree. Advanced UI and InstallScript instead retain
  # their own ARP in Metadata; selecting a suite's first MSI loses that identity.
  $Info = $Result.PSObject.Properties['MsiInfo']?.Value ?? $Metadata
  if ($Metadata) { foreach ($Diagnostic in $Metadata.Diagnostics) { $Diagnostics.Add($Diagnostic) } }
  if ($Result.Family -ceq '7z SFX' -and $Info) {
    if ($Depth -ge 3) { throw 'Dell nested 7z wrapper depth exceeds the three-layer limit.' }
    if (@($Info.ExecutedPayloads).Count -ne 1 -or -not $Info.ExecutedPayload) { throw 'The nested 7z wrapper has no unique configured execution route.' }
    if ($Budget.Remaining -le 0) { throw 'Dell nested extraction exceeds the aggregate byte limit.' }
    $Ranges = @(Get-EmbeddedSevenZipArchiveRange -Path $Path -StartOffset $Info.ArchiveOffset -MaximumArchives 1)
    if ($Ranges.Count -ne 1 -or $Ranges[0].Offset -ne $Info.ArchiveOffset) { throw 'The configured nested 7z archive range is invalid.' }
    $Context = Open-InstallerArchiveRange -Path $Path -Range $Ranges[0]
    $Destination = Join-Path $WorkPath "_sfx$Depth"
    try {
      $Selection = Export-InstallerArchiveSelection -Archive $Context.Archive -DestinationPath $Destination -CollisionAction Error -MaximumExpandedBytes $Budget.Remaining -MaximumEntries 16384
      $Budget.Remaining -= $Selection.ExpandedBytes
    } finally { Close-InstallerArchiveRange -Context $Context }
    # Windows launch names are case-insensitive, but staging may live in a
    # case-sensitive directory. Open the actual catalog spelling, not the
    # configured spelling, and never substitute an unconfigured executable.
    $ConfiguredPath = Resolve-SafeExtractionPath -DestinationPath $Destination -RelativePath $Info.ExecutedPayload
    $SelectedFiles = @($Selection.Files | Where-Object { $_.FullName -ieq $ConfiguredPath })
    if ($SelectedFiles.Count -ne 1) { throw 'The configured nested 7z payload has no unique extracted file.' }
    $NextPath = $SelectedFiles[0].FullName
    # The SFX command precedes forwarded caller arguments. Preserve both, and
    # keep every configured wrapper as evidence rather than losing its route.
    $NextArguments = (@($Info.PayloadArguments, $Arguments) | Where-Object { $_ }) -join ' '
    $Step = [pscustomobject]@{ Family = '7z SFX'; Executable = [IO.Path]::GetFileName($Path); SelectedPayload = $Info.ExecutedPayload; Arguments = $NextArguments }
    try {
      $Nested = Get-DellUpdatePackageNestedInfo -Path $NextPath -WorkPath $WorkPath -Budget $Budget -Diagnostics $Diagnostics -Depth ($Depth + 1) -Arguments $NextArguments
    } catch {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'DellUpdatePackage.Nested.Incomplete' -Source 'Dell Update Package' -Kind Incomplete -Areas Metadata -AffectedFields ProductCode, AppsAndFeaturesEntries -Message "The configured SFX child could not be analyzed: $($_.Exception.Message)"))
      return [pscustomobject]@{ Family = '7z SFX'; Info = $null; WrapperInfo = $Info; ExecutionChain = @($Step) }
    }
    $Chain = @($Step) + @($Nested.PSObject.Properties['ExecutionChain']?.Value | Where-Object { $_ })
    $Nested | Add-Member -NotePropertyName ExecutionChain -NotePropertyValue $Chain -Force
    return $Nested
  }
  return [pscustomobject]@{ Family = $Result.Family; Info = $Info; WrapperInfo = $Result.PSObject.Properties['MsiInfo']?.Value ? $Metadata : $null; ExecutionChain = @() }
}

function Get-DellUpdatePackageCommandAffectedField {
  <#
  .SYNOPSIS
    Identify runtime overrides that a nested metadata reader cannot simulate.
  .PARAMETER Arguments
    Literal configured unattended arguments, never executed.
  .PARAMETER Family
    Selected nested family. NSIS already consumes the virtual command line.
  .OUTPUTS
    Canonical fields to preserve as unresolved instead of publishing defaults.
  #>
  param ([AllowEmptyString()][string]$Arguments, [AllowNull()][string]$Family)
  if ($Family -ceq 'NSIS/Nullsoft') { return }
  $PropertyFields = [ordered]@{
    ProductCode        = @('ProductCode', 'AppsAndFeaturesProductCode', 'AppsAndFeaturesEntries')
    ProductName        = @('DisplayName', 'AppsAndFeaturesEntries')
    ProductVersion     = @('DisplayVersion', 'AppsAndFeaturesEntries')
    Manufacturer       = @('Publisher', 'AppsAndFeaturesEntries')
    ARPSYSTEMCOMPONENT = @('WritesAppsAndFeaturesEntry', 'ProductCode', 'AppsAndFeaturesProductCode', 'AppsAndFeaturesEntries', 'DisplayName', 'DisplayVersion', 'Publisher')
    ALLUSERS           = @('Scope')
    MSIINSTALLPERUSER  = @('Scope')
    INSTALLDIR         = @('DefaultInstallLocation')
    INSTALLLOCATION    = @('DefaultInstallLocation')
    TARGETDIR          = @('DefaultInstallLocation')
    TRANSFORMS         = @('ProductCode', 'AppsAndFeaturesProductCode', 'AppsAndFeaturesEntries', 'DisplayName', 'DisplayVersion', 'Publisher', 'Scope', 'DefaultInstallLocation', 'WritesAppsAndFeaturesEntry')
  }
  $Fields = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  foreach ($Property in $PropertyFields.Keys) {
    if ($Arguments -match "(?i)(?<![A-Za-z0-9_])$Property\s*=") { foreach ($Field in $PropertyFields[$Property]) { $null = $Fields.Add($Field) } }
  }
  if ($Arguments -match '(?i)(?:^|\s)/(?:ALLUSERS|CURRENTUSER)(?:\s|$)') { $null = $Fields.Add('Scope') }
  if ($Arguments -match '(?i)(?:^|\s)(?:/D=|/DIR=|--installto(?:\s|=))') { $null = $Fields.Add('DefaultInstallLocation') }
  $Fields | Sort-Object -CaseSensitive
}

function Resolve-DellUpdatePackageCommand {
  <#
  .SYNOPSIS
    Select default MUP arguments or the verbatim /passthrough argument tail.
  .PARAMETER Configuration
    Parsed MUP configuration, retained unchanged as the default command witness.
  .PARAMETER CommandLine
    Virtual outer command line; no executable is launched.
  .OUTPUTS
    Command source, vendor arguments and incompatible outer options. Token
    extents preserve nested quoting instead of reconstructing argv as text.
  #>
  param ([Parameter(Mandatory)]$Configuration, [AllowEmptyString()][string]$CommandLine = '')
  $Unattended = @($Configuration.Behaviors | Where-Object Name -CEQ 'unattended')
  $DefaultArguments = $Unattended.Count -eq 1 ? [string]$Unattended[0].Arguments : ''
  $Tokens = @(Split-BootstrapperCommandLine -CommandLine $CommandLine -IncludeExtent)
  for ($Index = 0; $Index -lt $Tokens.Count; $Index++) {
    if ($Tokens[$Index].Value -ine '/passthrough') { continue }
    # Dell forwards everything after this option. Later /s, /l, or additional
    # /passthrough tokens belong to the vendor; do not parse them as DUP options.
    $Arguments = $CommandLine.Substring($Tokens[$Index].Start + $Tokens[$Index].Length).TrimStart()
    $Conflicts = @(for ($Before = 0; $Before -lt $Index; $Before++) { if ($Tokens[$Before].Value -match '(?i)^/(?:l=|f$|capabilities$)') { $Tokens[$Before].Value } })
    return [pscustomobject]@{ Source = 'Passthrough'; UsesPassthrough = $true; VendorArguments = $Arguments; DefaultVendorArguments = $DefaultArguments; OptionConflicts = $Conflicts }
  }
  [pscustomobject]@{ Source = 'MupUnattended'; UsesPassthrough = $false; VendorArguments = $DefaultArguments; DefaultVendorArguments = $DefaultArguments; OptionConflicts = @() }
}

function Get-DellUpdatePackageInfo {
  <#
  .SYNOPSIS
    Analyze a Dell wrapper and its configured nested installer statically.
  .PARAMETER Path
    DUP executable; neither it nor its payload executes.
  .PARAMETER SkipNestedAnalysis
    Read wrapper configuration/catalog only; ARP remains unresolved.
  .PARAMETER MaximumExpandedBytes
    Aggregate catalog and temporary staging limit in bytes.
  .PARAMETER CommandLine
    Virtual outer command line including the executable. /passthrough replaces
    MUP's default vendor arguments; the remaining text is preserved verbatim.
  .OUTPUTS
    Standard parser envelope plus Configuration, PackageMetadata, PayloadFiles,
    CommandBehavior, ExecutedPayloads, NestedInstallerInfo, NestedWrapperInfo,
    and ExecutionChain. CommandBehavior separates effective vendor arguments
    from MUP defaults and records incompatible outer options.
    PackageArchitecture is OS applicability; NestedPackageArchitecture is the
    selected installer platform. ProductCode and ARP fields come only from the
    selected parser, with unsimulated command overrides reported as unresolved.
  #>
  [CmdletBinding()]
  param ([Parameter(Mandatory, Position = 0, ValueFromPipeline)][string]$Path, [switch]$SkipNestedAnalysis, [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 4294967296, [AllowEmptyString()][string]$CommandLine = '')
  process {
    $Context = Open-DellUpdatePackage -Path $Path -MaximumExpandedBytes $MaximumExpandedBytes
    $TemporaryPath = $null
    try {
      $Configuration = $Context.Configuration
      $Diagnostics = [Collections.Generic.List[object]]::new()
      $Unresolved = [Collections.Generic.List[string]]::new()
      foreach ($Diagnostic in $Context.Diagnostics) {
        $Diagnostics.Add($Diagnostic)
        foreach ($Field in $Diagnostic.AffectedFields) { if (-not $Unresolved.Contains($Field)) { $Unresolved.Add($Field) } }
      }
      $NestedInfo = $null
      $NestedFamily = $null
      $NestedWrapperInfo = $null
      $ExecutionChain = @()
      $Command = Resolve-DellUpdatePackageCommand -Configuration $Configuration -CommandLine $CommandLine
      $Arguments = $Command.VendorArguments
      $PackageMetadata = $Context.Package?.DocumentElement
      if ($Context.Selected.Count -ne 1) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'DellUpdatePackage.Payload.Missing' -Source 'Dell Update Package' -Kind Incomplete -Areas Extraction, Metadata -AffectedFields ProductCode, AppsAndFeaturesEntries -Message 'Mup.xml selects an absent executable; no alternative executable is guessed.' -Evidence $Configuration.ExecutableName))
      } elseif (-not $SkipNestedAnalysis) {
        $TemporaryPath = New-TempFolder
        try {
          # An MSI database is self-contained for static metadata reading. Use
          # its exact entry: wildcard selectors also match same-named sidecars.
          # EXE launchers still need support files such as InstallShield media.
          $SelectedPayload = $Context.Selected[0]
          $NestedPath = Resolve-SafeExtractionPath -DestinationPath $TemporaryPath -RelativePath $SelectedPayload.FullName
          $ExpandedBytes = if ([IO.Path]::GetExtension($SelectedPayload.FullName) -ieq '.msi') {
            (Export-InstallerArchiveEntry -Entry $SelectedPayload -DestinationPath $NestedPath -CollisionAction Error -MaximumBytes $MaximumExpandedBytes).Length
          } else {
            (Export-InstallerArchiveSelection -Archive $Context.ArchiveContext.Archive -DestinationPath $TemporaryPath -CollisionAction Error -MaximumExpandedBytes $MaximumExpandedBytes -MaximumEntries 16384).ExpandedBytes
          }
          $Budget = [pscustomobject]@{ Remaining = $MaximumExpandedBytes - $ExpandedBytes }
          $Nested = Get-DellUpdatePackageNestedInfo -Path $NestedPath -WorkPath $TemporaryPath -Budget $Budget -Diagnostics $Diagnostics -Arguments $Arguments
          $NestedInfo = $Nested.Info
          $NestedFamily = $Nested.Family
          $NestedWrapperInfo = $Nested.PSObject.Properties['WrapperInfo']?.Value
          $ExecutionChain = @($Nested.PSObject.Properties['ExecutionChain']?.Value | Where-Object { $_ })
          if ($NestedInfo) { foreach ($Diagnostic in $NestedInfo.Diagnostics) { $Diagnostics.Add($Diagnostic) } }
        } catch {
          $NestedInfo = $null
          $Diagnostics.Add((New-InstallerDiagnostic -Id 'DellUpdatePackage.Nested.Incomplete' -Source 'Dell Update Package' -Kind Incomplete -Areas Metadata -AffectedFields ProductCode, AppsAndFeaturesEntries, DefaultInstallLocation -Message "The configured nested installer could not be analyzed: $($_.Exception.Message)"))
        }
      }
      if (-not $NestedInfo -or ($null -eq $NestedInfo.PSObject.Properties['WritesAppsAndFeaturesEntry']?.Value -and -not $NestedInfo.PSObject.Properties['ProductCode']?.Value)) {
        $Unresolved.Add('AppsAndFeaturesEntries')
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'DellUpdatePackage.ARP.Unresolved' -Source 'Dell Update Package' -Kind Incomplete -Areas Metadata -AffectedFields ProductCode, AppsAndFeaturesEntries -Message 'Wrapper inventory is not visible ARP evidence. Analyze the configured installer or validate installed state before assigning ProductCode.' -Evidence $Configuration.Inventory))
      }
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'DellUpdatePackage.Applicability' -Source 'Dell Update Package' -Kind ManualValidation -Areas Installability -Message 'Validate the exact command on a suitable test system; platform, operating-system, device and prerequisite checks can affect installation.' -Evidence $Configuration.SupportedOperatingSystems))
      if ($Command.UsesPassthrough) {
        $Unresolved.Add('SupportsSilentInstallation')
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'DellUpdatePackage.Passthrough.UnattendedUnproven' -Source 'Dell Update Package' -Kind ManualValidation -Areas Installability -AffectedFields InstallerSwitches, InstallModes -Message '/passthrough suppresses the wrapper UI but replaces MUP vendor arguments; validate that the supplied vendor command installs unattended.' -Evidence $Command))
        if ($Command.OptionConflicts.Count) {
          $Diagnostics.Add((New-InstallerDiagnostic -Id 'DellUpdatePackage.Passthrough.OptionConflict' -Source 'Dell Update Package' -Kind Invalid -Areas Installability -AffectedFields InstallerSwitches -Message 'The outer /l, /f and /capabilities options cannot be combined with /passthrough; vendor logging must follow /passthrough using vendor syntax.' -Evidence $Command.OptionConflicts))
        }
      } elseif (-not $Configuration.SupportsSilentInstallation) {
        $Unresolved.Add('SupportsSilentInstallation')
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'DellUpdatePackage.Silent.Unresolved' -Source 'Dell Update Package' -Kind Incomplete -Areas Installability -AffectedFields InstallerSwitches -Message 'Mup.xml does not prove an unattended vendor command; outer /s alone does not prove unattended nested installation.'))
      }
      # Replaced MUP commands remain raw configuration evidence, not limitations
      # of the caller's independent passthrough command.
      if (-not $Command.UsesPassthrough) {
        foreach ($Behavior in $Configuration.Behaviors) {
          if ($Behavior.UnresolvedReason) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'DellUpdatePackage.Command.Unsupported' -Source 'Dell Update Package' -Kind Unsupported -Areas Installability -AffectedFields InstallerSwitches -Message $Behavior.UnresolvedReason -Evidence $Behavior.Name)) }
        }
      }
      $Architectures = @($Configuration.SupportedOperatingSystems | ForEach-Object Architecture | Where-Object { $_ -cin @('x86', 'x64', 'arm64') } | Sort-Object -Unique)
      $Fields = [ordered]@{
        Path = $Context.Path; InstallerType = 'exe'; ProductCode = $null; UpgradeCode = $null
        DisplayName = $null; DisplayVersion = $null; Publisher = $null
        Scope = $null; DefaultInstallLocation = $null; WritesAppsAndFeaturesEntry = $null
        AppsAndFeaturesProductCode = $null; AppsAndFeaturesInstallerType = $null
        AppsAndFeaturesEntries = @(); Protocols = @(); FileExtensions = @(); RegistryAssociationInfo = $null
        UninstallString = $null; QuietUninstallString = $null; DisplayIcon = $null
        URLInfoAbout = $null; HelpLink = $null; RegistryView = $null; SystemComponent = $null
      }
      if ($NestedInfo) {
        foreach ($Field in @($NestedInfo.PSObject.Properties['UnresolvedFields']?.Value)) { if ($Field -and -not $Unresolved.Contains($Field)) { $Unresolved.Add($Field) } }
        foreach ($Name in @('ProductCode', 'UpgradeCode', 'DisplayName', 'DisplayVersion', 'Publisher', 'Scope', 'DefaultInstallLocation', 'WritesAppsAndFeaturesEntry', 'AppsAndFeaturesProductCode', 'AppsAndFeaturesInstallerType', 'AppsAndFeaturesEntries', 'Protocols', 'FileExtensions', 'RegistryAssociationInfo', 'UninstallString', 'QuietUninstallString', 'DisplayIcon', 'URLInfoAbout', 'HelpLink', 'RegistryView', 'SystemComponent')) {
          $Property = $NestedInfo.PSObject.Properties[$Name]
          if ($Property -and $null -ne $Property.Value) { $Fields[$Name] = $Property.Value }
        }
        if ($Fields.WritesAppsAndFeaturesEntry -eq $true -and @($Fields.AppsAndFeaturesEntries).Count -eq 0) {
          $Row = [ordered]@{}
          foreach ($Name in @('DisplayName', 'DisplayVersion', 'Publisher', 'ProductCode', 'UpgradeCode')) { if ($Fields[$Name]) { $Row[$Name] = $Fields[$Name] } }
          if ($Fields.AppsAndFeaturesInstallerType) { $Row['InstallerType'] = $Fields.AppsAndFeaturesInstallerType }
          $Fields.AppsAndFeaturesEntries = @($Row)
        }
      }
      # DLL/custom-action effects remain the nested parser's responsibility.
      # Do not let command-line overrides silently reuse its default ARP tuple.
      $EffectiveArguments = $ExecutionChain.Count -gt 0 ? $ExecutionChain[-1].Arguments : $Arguments
      $CommandAffectedFields = @(Get-DellUpdatePackageCommandAffectedField -Arguments $EffectiveArguments -Family $NestedFamily)
      if ($NestedInfo -and $CommandAffectedFields.Count) {
        foreach ($Field in $CommandAffectedFields) {
          if (-not $Unresolved.Contains($Field)) { $Unresolved.Add($Field) }
          if ($Fields.Contains($Field)) { $Fields[$Field] = $Field -ceq 'AppsAndFeaturesEntries' ? @() : $null }
        }
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'DellUpdatePackage.Nested.CommandOverrides' -Source 'Dell Update Package' -Kind ManualValidation -Areas Metadata -AffectedFields $CommandAffectedFields -Message 'Configured vendor arguments can change installed-state fields that this nested parser does not simulate; unmodified payload defaults are retained only as nested evidence.' -Evidence $CommandAffectedFields))
      }
      $Fields['ProductName'] = $Configuration.ProductName
      $Fields['ProductVersion'] = $Configuration.ProductVersion
      $Fields['Family'] = 'Dell Update Package'
      $Fields['ContainerRoute'] = $Context.Route
      $Fields['FrameworkVersion'] = $Context.FrameworkVersion
      $Fields['Configuration'] = $Configuration
      $Fields['CommandBehavior'] = $Command
      $Fields['PackageMetadata'] = ${PackageMetadata}?.OuterXml
      $Fields['ReleaseNotes'] = @(if ($PackageMetadata) { $PackageMetadata.SelectNodes("*[local-name()='RevisionHistory']/*") | ForEach-Object { [pscustomobject]@{ Language = $_.GetAttribute('lang'); Text = $_.InnerText } } })
      $Fields['PayloadFiles'] = @($Context.Entries | ForEach-Object { [pscustomobject]@{ Path = $_.FullName; Length = $_.Length; CompressedSize = $_.CompressedSize } })
      $Fields['ExtractedFiles'] = @()
      $Fields['ExecutedPayloads'] = @([pscustomobject]@{ RelativePath = $Configuration.ExecutableName; Behaviors = $Configuration.Behaviors; Arguments = $Arguments; Architecture = $Configuration.ExecutableArchitecture })
      $Fields['NestedInstallerInfo'] = $NestedInfo
      $Fields['NestedWrapperInfo'] = $NestedWrapperInfo
      $Fields['ExecutionChain'] = $ExecutionChain
      $Fields['NestedFamily'] = $NestedFamily
      $Fields['OuterArchitecture'] = $Context.OuterArchitecture
      $Fields['SupportedArchitectures'] = $Architectures
      $Fields['PackageArchitecture'] = $Architectures.Count -eq 1 ? $Architectures[0] : $null
      # OS applicability and the selected MSI platform are independent: an
      # x64-only DUP can carry an x86 application installer.
      $Fields['NestedPackageArchitecture'] = if ($NestedInfo) { $NestedInfo.PSObject.Properties['PackageArchitecture']?.Value } else { $null }
      $Fields['SupportedScopes'] = @($Fields.Scope | Where-Object { $_ })
      $Fields['CanExpand'] = $true
      $Fields['SupportsSilentInstallation'] = -not $Command.UsesPassthrough -and $Configuration.SupportsSilentInstallation ? $true : $null
      $Fields['InstallModes'] = if ($Command.UsesPassthrough) { @() } elseif ($Configuration.SupportsSilentInstallation) { @('interactive', 'silent') } else { @('interactive') }
      $Fields['InstallerSwitches'] = -not $Command.UsesPassthrough -and $Configuration.SupportsSilentInstallation ? [ordered]@{ Silent = '/s'; SilentWithProgress = '/s'; Log = '/l="<LOGPATH>"' } : [ordered]@{}
      $Fields['RequestedExecutionLevel'] = Get-PERequestedExecutionLevel -Path $Context.Path
      $Fields['ElevationRequirement'] = $Fields.RequestedExecutionLevel -ceq 'requireAdministrator' ? 'elevationRequired' : $null
      $Fields['DocumentedReturnCodes'] = @(
        [pscustomobject]@{ Code = 0; Name = 'SUCCESS' }; [pscustomobject]@{ Code = 1; Name = 'UNSUCCESSFUL' }
        [pscustomobject]@{ Code = 2; Name = 'REBOOT_REQUIRED' }; [pscustomobject]@{ Code = 3; Name = 'DEP_SOFT_ERROR' }
        [pscustomobject]@{ Code = 4; Name = 'DEP_HARD_ERROR' }; [pscustomobject]@{ Code = 5; Name = 'QUAL_HARD_ERROR' }
        [pscustomobject]@{ Code = 6; Name = 'REBOOTING_SYSTEM' }
      )
      $Fields['Diagnostics'] = @(Merge-InstallerDiagnostics -Diagnostic $Diagnostics.ToArray())
      $Fields['UnresolvedFields'] = $Unresolved.ToArray()
      [pscustomobject]$Fields
    } finally {
      Close-InstallerArchiveRange -Context $Context.ArchiveContext
      if ($TemporaryPath) { Remove-Item -LiteralPath $TemporaryPath -Recurse -Force -ErrorAction SilentlyContinue }
    }
  }
}

function Expand-DellUpdatePackage {
  <#
  .SYNOPSIS
    Extract Dell wrapper contents without executing its /e command.
  .PARAMETER Path
    Source Dell executable, resolved before managed file access.
  .PARAMETER DestinationPath
    Output directory; archive paths must stay beneath it.
  .PARAMETER Name
    Optional pattern. Omission expands every physical package file.
  .PARAMETER CollisionAction
    Prompt on collision, or Error, Skip, Overwrite, or Rename. Internal analysis
    uses Error in a newly created temporary directory.
  .PARAMETER MaximumExpandedBytes
    Aggregate output byte limit, enforced during catalog and extraction.
  .PARAMETER MaximumEntries
    Catalog and extraction entry-count limit.
  .OUTPUTS
    FileInfo objects; the nested installer is not itself expanded.
  #>
  [CmdletBinding()]
  [OutputType([IO.FileInfo[]])]
  param (
    [Parameter(Mandatory, Position = 0)][string]$Path,
    [Parameter(Mandatory)][string]$DestinationPath,
    [string]$Name = '*',
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Prompt',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 4294967296,
    [ValidateRange(1, 16384)][int]$MaximumEntries = 16384
  )
  $Context = Open-DellUpdatePackage -Path $Path -MaximumEntries $MaximumEntries -MaximumExpandedBytes $MaximumExpandedBytes
  try {
    (Export-InstallerArchiveSelection -Archive $Context.ArchiveContext.Archive -DestinationPath $DestinationPath -Name $Name -CollisionAction $CollisionAction -MaximumExpandedBytes $MaximumExpandedBytes -MaximumEntries $MaximumEntries).Files
  } finally { Close-InstallerArchiveRange -Context $Context.ArchiveContext }
}

Export-ModuleMember -Function Get-DellUpdatePackageInfo, Test-DellUpdatePackage, Expand-DellUpdatePackage, ConvertFrom-DellUpdatePackageConfiguration
