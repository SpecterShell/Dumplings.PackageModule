# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# Force stop on error
$ErrorActionPreference = 'Stop'

# Node types that will be ignored during traversing
$IgnoredNodes = @('head', 'img', 'script', 'style', 'svg', 'video', '#comment')
# Node types that always start at new line
# https://developer.mozilla.org/docs/Web/HTML/Block-level_elements
$BlockNodes = @('address', 'article', 'aside', 'blockquote', 'dd', 'div', 'dl', 'fieldset', 'figcaption', 'figure', 'footer', 'form', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'header', 'hgroup', 'hr', 'li', 'ol', 'p', 'pre', 'section', 'table', 'tr', 'ul')

Import-Module -Name 'PowerHTML'

function Expand-Node {
  <#
  .SYNOPSIS
    Extract the child nodes from the inline nodes
  .PARAMETER Node
    The HTML Agility Pack nodes that will be expanded
  #>
  param (
    [Parameter(ValueFromPipeline, HelpMessage = 'The nodes list that will be expanded')]
    $Node
  )

  begin {
    $Nodes = @()
  }

  process {
    $Nodes += $Node
  }

  end {
    $ChildNodes = @()

    switch ($Nodes) {
      # Do not add unnecessary nodes to the list
      ({ $_.Name -in $IgnoredNodes }) { continue }
      # Keep and add block nodes to the list
      ({ $_.Name -in $BlockNodes }) { $ChildNodes += $_; continue }
      # Extract the child nodes of the inline nodes and add them to the list
      ({ $_.HasChildNodes }) { $ChildNodes += Expand-Node -Node $_.ChildNodes; continue }
      # In case something went wrong
      default { $ChildNodes += $_; continue }
    }

    return $ChildNodes
  }
}

function Get-HtmlTableRow {
  <#
  .SYNOPSIS
    Collect rows that belong directly to an HTML table.
  .PARAMETER Table
    The HTML table node whose direct rows and row-group rows will be collected.
  #>
  [OutputType([object[]])]
  param (
    [Parameter(Mandatory)]
    [HtmlAgilityPack.HtmlNode]$Table
  )

  $Rows = [System.Collections.Generic.List[object]]::new()
  $GroupId = 0

  foreach ($Child in $Table.ChildNodes) {
    if ($Child.Name -eq 'tr') {
      # Consecutive direct rows form the table's implicit row group.
      $Cells = @($Child.ChildNodes | Where-Object { $_.Name -in @('th', 'td') })
      $Rows.Add([pscustomobject]@{
          Node       = $Child
          Cells      = $Cells
          GroupId    = $GroupId
          IsHeader   = $false
          GroupIndex = 0
          GroupCount = 0
        })
      continue
    }

    if ($Child.Name -notin @('thead', 'tbody', 'tfoot')) {
      continue
    }

    # A new explicit row group also ends an implicit group of direct rows.
    $GroupId++
    foreach ($Row in $Child.ChildNodes) {
      if ($Row.Name -ne 'tr') {
        continue
      }
      $Cells = @($Row.ChildNodes | Where-Object { $_.Name -in @('th', 'td') })
      $Rows.Add([pscustomobject]@{
          Node       = $Row
          Cells      = $Cells
          GroupId    = $GroupId
          IsHeader   = $Child.Name -eq 'thead'
          GroupIndex = 0
          GroupCount = 0
        })
    }
    $GroupId++
  }

  # Record each row's position within its group for bounded rowspan handling.
  foreach ($Group in @($Rows | Group-Object -Property GroupId)) {
    for ($Index = 0; $Index -lt $Group.Count; $Index++) {
      $Group.Group[$Index].GroupIndex = $Index
      $Group.Group[$Index].GroupCount = $Group.Count
    }
  }

  return $Rows.ToArray()
}

function Get-HtmlTableSpan {
  <#
  .SYNOPSIS
    Read and bound an HTML table cell span.
  .PARAMETER Cell
    The table cell containing the span attribute.
  .PARAMETER Name
    The span attribute name, either rowspan or colspan.
  .PARAMETER RemainingRows
    The number of rows left in the current row group, including the anchor row.
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory)]
    [HtmlAgilityPack.HtmlNode]$Cell,

    [Parameter(Mandatory)]
    [ValidateSet('rowspan', 'colspan')]
    [string]$Name,

    [Parameter(Mandatory)]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$RemainingRows
  )

  if (-not $Cell.Attributes.Contains($Name)) {
    return 1
  }

  $Span = 0
  if (-not [int]::TryParse($Cell.Attributes[$Name].Value, [ref]$Span)) {
    return 1
  }

  if ($Name -eq 'rowspan') {
    # HTML defines rowspan=0 as extending to the end of the current row group.
    if ($Span -eq 0) {
      return $RemainingRows
    }
    if ($Span -lt 1) {
      return 1
    }
    return [Math]::Min($Span, $RemainingRows)
  }

  # HTML limits colspan to 1000 columns; invalid values use the default of one.
  if ($Span -lt 1) {
    return 1
  }
  return [Math]::Min($Span, 1000)
}

function ConvertTo-MarkdownTableCellText {
  <#
  .SYNOPSIS
    Convert one HTML table cell into safe Markdown pipe-table text.
  .PARAMETER Cell
    The th or td node to convert.
  .PARAMETER TableSpanMode
    The strategy used to represent merged table cells.
  .PARAMETER HeaderlessTableMode
    The strategy used to select a header for a table without an HTML header row.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)]
    [HtmlAgilityPack.HtmlNode]$Cell,

    [Parameter(Mandatory)]
    [ValidateSet('Repeat', 'Empty', 'AdvancedTableXT')]
    [string]$TableSpanMode,

    [Parameter(Mandatory)]
    [ValidateSet('Empty', 'FirstRow')]
    [string]$HeaderlessTableMode
  )

  $CellText = (Get-TextContent -Node $Cell.ChildNodes -TableSpanMode $TableSpanMode -HeaderlessTableMode $HeaderlessTableMode).Trim()
  $NormalizedText = $CellText -creplace '\r\n?', "`n"
  $ProtectCaret = $TableSpanMode -eq 'AdvancedTableXT' -and $NormalizedText -ceq '^'
  $ProtectDashes = $TableSpanMode -eq 'AdvancedTableXT' -and $NormalizedText -cmatch '^-+$'

  $Lines = foreach ($Line in $NormalizedText -csplit "`n", 0, 'SimpleMatch') {
    # Escape Markdown table delimiters and literal HTML/plugin control syntax.
    $EscapedLine = $Line.Replace('\', '\\').Replace('|', '\|').Replace('<', '\<')
    if ($TableSpanMode -eq 'AdvancedTableXT') {
      $EscapedLine = $EscapedLine.Replace('~', '\~')
    }
    $EscapedLine
  }
  $Result = $Lines -join '<br>'

  if ($ProtectCaret -or $ProtectDashes) {
    $Result = '\' + $Result
  }
  return $Result
}

function Get-TerminalTextWidth {
  <#
  .SYNOPSIS
    Measure the approximate terminal-cell width of Unicode text.
  .PARAMETER Text
    The text whose terminal display width will be measured.
  .DESCRIPTION
    Unicode grapheme clusters are measured as one unit. CJK, full-width, and
    emoji clusters occupy two terminal cells; combining and formatting-only
    clusters occupy none. East Asian ambiguous characters remain single-width.
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory)]
    [AllowEmptyString()]
    [string]$Text
  )

  $Width = 0
  $Enumerator = [System.Globalization.StringInfo]::GetTextElementEnumerator($Text)
  while ($Enumerator.MoveNext()) {
    $Element = $Enumerator.GetTextElement()
    $HasVisibleCharacter = $false
    $IsWide = $false
    $HasEmojiPresentation = $false

    for ($Index = 0; $Index -lt $Element.Length; $Index++) {
      if ([char]::IsHighSurrogate($Element[$Index]) -and $Index + 1 -lt $Element.Length -and [char]::IsLowSurrogate($Element[$Index + 1])) {
        $CodePoint = [char]::ConvertToUtf32($Element[$Index], $Element[$Index + 1])
        $Index++
      } else {
        $CodePoint = [int]$Element[$Index]
      }

      $Category = [System.Globalization.CharUnicodeInfo]::GetUnicodeCategory([char]::ConvertFromUtf32($CodePoint), 0)
      if ($Category -notin @(
          [System.Globalization.UnicodeCategory]::Control,
          [System.Globalization.UnicodeCategory]::Format,
          [System.Globalization.UnicodeCategory]::NonSpacingMark,
          [System.Globalization.UnicodeCategory]::EnclosingMark
        )) {
        $HasVisibleCharacter = $true
      }

      # These ranges cover the wide/full-width characters recognized by common terminals.
      if (
        ($CodePoint -ge 0x1100 -and $CodePoint -le 0x115F) -or
        $CodePoint -in @(0x2329, 0x232A) -or
        ($CodePoint -ge 0x2E80 -and $CodePoint -le 0xA4CF -and $CodePoint -ne 0x303F) -or
        ($CodePoint -ge 0xAC00 -and $CodePoint -le 0xD7A3) -or
        ($CodePoint -ge 0xF900 -and $CodePoint -le 0xFAFF) -or
        ($CodePoint -ge 0xFE10 -and $CodePoint -le 0xFE19) -or
        ($CodePoint -ge 0xFE30 -and $CodePoint -le 0xFE6F) -or
        ($CodePoint -ge 0xFF00 -and $CodePoint -le 0xFF60) -or
        ($CodePoint -ge 0xFFE0 -and $CodePoint -le 0xFFE6) -or
        ($CodePoint -ge 0x20000 -and $CodePoint -le 0x3FFFD)
      ) {
        $IsWide = $true
      }

      # Emoji sequences, flags, keycaps, and emoji-presentation selectors render as one wide cluster.
      if (
        ($CodePoint -ge 0x1F000 -and $CodePoint -le 0x1FAFF) -or
        $CodePoint -in @(0x20E3, 0xFE0F)
      ) {
        $HasEmojiPresentation = $true
      }
    }

    if ($HasVisibleCharacter) {
      $Width += if ($IsWide -or $HasEmojiPresentation) { 2 } else { 1 }
    }
  }
  return $Width
}

function Format-MarkdownTableRow {
  <#
  .SYNOPSIS
    Pad and render one Markdown pipe-table row.
  .PARAMETER Cells
    The already escaped cell strings in column order.
  .PARAMETER ColumnWidths
    The target terminal-cell width for each column.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)]
    [AllowNull()]
    [AllowEmptyCollection()]
    [AllowEmptyString()]
    [string[]]$Cells,

    [Parameter(Mandatory)]
    [int[]]$ColumnWidths
  )

  $PaddedCells = for ($Index = 0; $Index -lt $ColumnWidths.Count; $Index++) {
    $Cell = if ($Index -lt $Cells.Count -and $null -ne $Cells[$Index]) { $Cells[$Index] } else { '' }
    $Padding = [Math]::Max(0, $ColumnWidths[$Index] - (Get-TerminalTextWidth -Text $Cell))
    $Cell + (' ' * $Padding)
  }
  return '| ' + ($PaddedCells -join ' | ') + ' |'
}

function ConvertFrom-HtmlTable {
  <#
  .SYNOPSIS
    Render an HTML table as a rectangular Markdown pipe table.
  .PARAMETER Table
    The HTML table node to render.
  .PARAMETER TableSpanMode
    Repeat, empty, or Advanced Table XT continuation-cell rendering.
  .PARAMETER HeaderlessTableMode
    Empty synthesizes a blank header; FirstRow promotes the first source row.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)]
    [HtmlAgilityPack.HtmlNode]$Table,

    [Parameter(Mandatory)]
    [ValidateSet('Repeat', 'Empty', 'AdvancedTableXT')]
    [string]$TableSpanMode,

    [Parameter(Mandatory)]
    [ValidateSet('Empty', 'FirstRow')]
    [string]$HeaderlessTableMode
  )

  $Rows = @(Get-HtmlTableRow -Table $Table)
  if ($Rows.Count -eq 0 -or -not ($Rows | Where-Object { $_.Cells.Count -gt 0 })) {
    return $null
  }

  # Each occupied slot points to its anchor text and offsets within the span.
  $Grid = @{}
  $ColumnCount = 0
  for ($RowIndex = 0; $RowIndex -lt $Rows.Count; $RowIndex++) {
    $ColumnIndex = 0
    foreach ($Cell in $Rows[$RowIndex].Cells) {
      $RemainingRows = $Rows[$RowIndex].GroupCount - $Rows[$RowIndex].GroupIndex
      $RowSpan = Get-HtmlTableSpan -Cell $Cell -Name rowspan -RemainingRows $RemainingRows
      $ColumnSpan = Get-HtmlTableSpan -Cell $Cell -Name colspan -RemainingRows $RemainingRows

      # Malformed tables can overlap an earlier rowspan. Locate the next complete free range.
      while ($true) {
        $RangeIsFree = $true
        for ($Offset = 0; $Offset -lt $ColumnSpan; $Offset++) {
          if ($Grid.ContainsKey("${RowIndex}:$($ColumnIndex + $Offset)")) {
            $RangeIsFree = $false
            break
          }
        }
        if ($RangeIsFree) {
          break
        }
        $ColumnIndex++
      }

      $AnchorText = ConvertTo-MarkdownTableCellText -Cell $Cell -TableSpanMode $TableSpanMode -HeaderlessTableMode $HeaderlessTableMode
      for ($RowOffset = 0; $RowOffset -lt $RowSpan; $RowOffset++) {
        for ($ColumnOffset = 0; $ColumnOffset -lt $ColumnSpan; $ColumnOffset++) {
          $Grid["$($RowIndex + $RowOffset):$($ColumnIndex + $ColumnOffset)"] = [pscustomobject]@{
            Text         = $AnchorText
            RowOffset    = $RowOffset
            ColumnOffset = $ColumnOffset
          }
        }
      }
      $ColumnIndex += $ColumnSpan
      $ColumnCount = [Math]::Max($ColumnCount, $ColumnIndex)
    }
  }

  if ($ColumnCount -eq 0) {
    return $null
  }

  $RenderedRows = [System.Collections.Generic.List[object]]::new()
  for ($RowIndex = 0; $RowIndex -lt $Rows.Count; $RowIndex++) {
    $RenderedRow = [string[]]::new($ColumnCount)
    for ($ColumnIndex = 0; $ColumnIndex -lt $ColumnCount; $ColumnIndex++) {
      $Slot = $Grid["${RowIndex}:${ColumnIndex}"]
      if ($null -eq $Slot) {
        $RenderedRow[$ColumnIndex] = ''
      } elseif ($Slot.RowOffset -eq 0 -and $Slot.ColumnOffset -eq 0) {
        $RenderedRow[$ColumnIndex] = $Slot.Text
      } elseif ($TableSpanMode -eq 'Repeat') {
        $RenderedRow[$ColumnIndex] = $Slot.Text
      } elseif ($TableSpanMode -eq 'AdvancedTableXT') {
        # A vertical continuation takes precedence for cells covered in both dimensions.
        $RenderedRow[$ColumnIndex] = if ($Slot.RowOffset -gt 0) { '^' } else { '<' }
      } else {
        $RenderedRow[$ColumnIndex] = ''
      }
    }
    $RenderedRows.Add($RenderedRow)
  }

  $FirstRowIsHeader = $Rows[0].IsHeader -or ($Rows[0].Cells.Count -gt 0 -and @($Rows[0].Cells | Where-Object Name -NE 'th').Count -eq 0)
  if ($FirstRowIsHeader -or $HeaderlessTableMode -eq 'FirstRow') {
    $Header = $RenderedRows[0]
    $BodyStart = 1
  } else {
    $Header = [string[]]::new($ColumnCount)
    for ($ColumnIndex = 0; $ColumnIndex -lt $ColumnCount; $ColumnIndex++) {
      $Header[$ColumnIndex] = ''
    }
    $BodyStart = 0
  }

  # Pad by terminal-cell width so CJK and emoji columns remain aligned in plain-text output.
  $ColumnWidths = [int[]]::new($ColumnCount)
  for ($ColumnIndex = 0; $ColumnIndex -lt $ColumnCount; $ColumnIndex++) {
    $ColumnWidths[$ColumnIndex] = [Math]::Max(3, (Get-TerminalTextWidth -Text $Header[$ColumnIndex]))
    for ($RowIndex = $BodyStart; $RowIndex -lt $RenderedRows.Count; $RowIndex++) {
      $ColumnWidths[$ColumnIndex] = [Math]::Max($ColumnWidths[$ColumnIndex], (Get-TerminalTextWidth -Text $RenderedRows[$RowIndex][$ColumnIndex]))
    }
  }

  $Lines = [System.Collections.Generic.List[string]]::new()
  $Lines.Add((Format-MarkdownTableRow -Cells $Header -ColumnWidths $ColumnWidths))
  $DelimiterCells = for ($ColumnIndex = 0; $ColumnIndex -lt $ColumnCount; $ColumnIndex++) { '-' * $ColumnWidths[$ColumnIndex] }
  $Lines.Add((Format-MarkdownTableRow -Cells $DelimiterCells -ColumnWidths $ColumnWidths))
  for ($RowIndex = $BodyStart; $RowIndex -lt $RenderedRows.Count; $RowIndex++) {
    $Lines.Add((Format-MarkdownTableRow -Cells $RenderedRows[$RowIndex] -ColumnWidths $ColumnWidths))
  }

  $Caption = $Table.ChildNodes | Where-Object Name -EQ 'caption' | Select-Object -First 1
  if ($Caption) {
    $CaptionText = (Get-TextContent -Node $Caption.ChildNodes -TableSpanMode $TableSpanMode -HeaderlessTableMode $HeaderlessTableMode).Trim()
    if ($CaptionText) {
      return $CaptionText + "`n`n" + ($Lines -join "`n")
    }
  }
  return $Lines -join "`n"
}

function Get-TextContent {
  <#
  .SYNOPSIS
    Get text content from HTML Agility Pack node(s)
  .PARAMETER Node
    The HTML Agility Pack nodes containing the text
  .PARAMETER TableSpanMode
    How merged HTML table cells are represented. AdvancedTableXT emits the plugin-specific < and ^ merge cells used by Sheets Extended.
  .PARAMETER HeaderlessTableMode
    Whether a table without an HTML header gets an empty Markdown header or promotes its first row.
  .LINK
    https://github.com/niconekoru/obsidan-advanced-table-xt#how-to-use
  .EXAMPLE
    Invoke-WebRequest -Uri 'https://example.com/' | ConvertFrom-Html | Get-TextContent | Format-Text
    ConvertFrom-HTML is a function from the PowerShell module PowerHTML
  .EXAMPLE
    (Invoke-WebRequest -Uri 'https://example.com/' | ConvertFrom-Html).SelectSingleNode('/html/body/div/p[1]') | Get-TextContent | Format-Text
  #>
  [OutputType([string])]
  param (
    [Parameter(ValueFromPipeline, HelpMessage = 'The nodes that containing the text')]
    $Node,

    [Parameter(HelpMessage = 'How rowspan and colspan cells are represented in Markdown tables')]
    [ValidateSet('Repeat', 'Empty', 'AdvancedTableXT')]
    [string]$TableSpanMode = 'Repeat',

    [Parameter(HelpMessage = 'How a Markdown header is created for a headerless HTML table')]
    [ValidateSet('Empty', 'FirstRow')]
    [string]$HeaderlessTableMode = 'Empty',

    [Parameter(DontShow, HelpMessage = 'Disable merging continuous invisible characters')]
    [bool]
    $Raw = $false,

    [Parameter(DontShow, HelpMessage = 'The list info hashtable for internal use')]
    $ListInfo
  )

  begin {
    $Nodes = @()
  }

  process {
    $Nodes += $Node
  }

  end {
    $Content = [System.Text.StringBuilder]::new(2048)
    $Nodes = Expand-Node -Node $Nodes
    # The name of the last node. Leave blank to indicate it is at the beginning of the document/child node
    $LastNodeName = ''
    # Append single whitespace if there are whitespace(s) between visble texts from two text nodes
    $NextWhiteSpace = $false

    switch ($Nodes) {
      ({ $_.Name -eq '#text' }) {
        if ($Raw) {
          # In some elements such as <pre> invisible character is rendered as is
          $NewContent = $_.InnerText
        } else {
          # The browsers merge continuous invisible characters into one whitespace while HtmlAgilityPack doesn't. Do this manually
          $NewContent = $_.InnerText -creplace '\s+', ' '
        }
        if ($LastNodeName -eq '#text') {
          if ([string]::IsNullOrWhiteSpace($NewContent)) {
            $NextWhiteSpace = $true
          } else {
            if ($NewContent -cmatch '^\s+') {
              $NextWhiteSpace = $true
            }
            if ($NextWhiteSpace -eq $true) {
              $Content = $Content.Append(' ')
              $NextWhiteSpace = $false
            }
            $Content = $Content.Append([System.Web.HttpUtility]::HtmlDecode($NewContent.Trim()))
            if ($NewContent -cmatch '\s+$') {
              $NextWhiteSpace = $true
            }
          }
          $LastNodeName = $_.Name
        } else {
          if (-not [string]::IsNullOrWhiteSpace($NewContent)) {
            # Append newline if the last node is a block node
            if ($LastNodeName) {
              $Content = $Content.Append($(if ($LastNodeName -eq 'table') { "`n`n" } else { "`n" }))
            }
            $Content = $Content.Append([System.Web.HttpUtility]::HtmlDecode($NewContent.Trim()))
            if ($NewContent -cmatch '\s+$') {
              $NextWhiteSpace = $true
            }
            $LastNodeName = $_.Name
          }
        }
        continue
      }
      ({ $_.Name -eq 'br' }) {
        # Append additional newline only if the last node is a block element
        if ($LastNodeName -and $LastNodeName -ne '#text') {
          $Content = $Content.Append("`n")
        }
        $NextWhiteSpace = $false
        $LastNodeName = $_.Name
        continue
      }
      ({ $_ -is [HtmlAgilityPack.HtmlNode] }) {
        # Append newline only if there are preceding nodes
        if ($LastNodeName) {
          $Content = $Content.Append($(if ($_.Name -eq 'table' -or $LastNodeName -eq 'table') { "`n`n" } else { "`n" }))
        }
        if ($_.Name -eq 'ul') {
          $Content = $Content.Append((Get-TextContent -Node $_.ChildNodes -TableSpanMode $TableSpanMode -HeaderlessTableMode $HeaderlessTableMode -Raw $Raw -ListInfo @{ Type = 'Unordered'; Number = 1 }))
        } elseif ($_.Name -eq 'ol') {
          if ($_.Attributes.Contains('Start') -and [int]::TryParse($_.Attributes['Start'].Value, [ref]$null)) {
            $Content = $Content.Append((Get-TextContent -Node $_.ChildNodes -TableSpanMode $TableSpanMode -HeaderlessTableMode $HeaderlessTableMode -Raw $Raw -ListInfo @{ Type = 'Ordered'; Number = [int]$_.Attributes['Start'].Value }))
          } else {
            $Content = $Content.Append((Get-TextContent -Node $_.ChildNodes -TableSpanMode $TableSpanMode -HeaderlessTableMode $HeaderlessTableMode -Raw $Raw -ListInfo @{ Type = 'Ordered'; Number = 1 }))
          }
        } elseif ($_.Name -eq 'li') {
          $Prefix = '- '
          if ($ListInfo -and $ListInfo.Type -eq 'Ordered') {
            $Prefix = "$(($ListInfo.Number++)). "
          }
          # Prepend whitespaces to every line, and replace whitespaces in the first line with prefix
          $Content = $Content.Append(((Get-TextContent -Node $_.ChildNodes -TableSpanMode $TableSpanMode -HeaderlessTableMode $HeaderlessTableMode -Raw $Raw -ListInfo $ListInfo) -creplace '(?m)^', (' ' * $Prefix.Length)).Remove(0, $Prefix.Length).Insert(0, $Prefix))
        } elseif ($_.Name -eq 'pre') {
          $Content = $Content.Append((Get-TextContent -Node $_.ChildNodes -TableSpanMode $TableSpanMode -HeaderlessTableMode $HeaderlessTableMode -Raw $true -ListInfo $ListInfo))
        } elseif ($_.Name -eq 'table') {
          $TableContent = ConvertFrom-HtmlTable -Table $_ -TableSpanMode $TableSpanMode -HeaderlessTableMode $HeaderlessTableMode
          if ($null -ne $TableContent) {
            $Content = $Content.Append($TableContent)
          } else {
            # Preserve the old recursive flattening behavior for unusable tables.
            $Content = $Content.Append((Get-TextContent -Node $_.ChildNodes -TableSpanMode $TableSpanMode -HeaderlessTableMode $HeaderlessTableMode -Raw $Raw -ListInfo $ListInfo))
          }
        } else {
          $Content = $Content.Append((Get-TextContent -Node $_.ChildNodes -TableSpanMode $TableSpanMode -HeaderlessTableMode $HeaderlessTableMode -Raw $Raw -ListInfo $ListInfo))
        }
        $NextWhiteSpace = $false
        $LastNodeName = $_.Name
        continue
      }
    }
    return $Content.ToString()
  }
}

function Convert-MarkdownToHtml {
  <#
  .SYNOPSIS
    Convert Markdown content to HTML object
  .PARAMETER Content
    The Markdown content
  .PARAMETER Extensions
    The Markdig Markdown extensions to be added to the pipeline
  #>
  [OutputType([HtmlAgilityPack.HtmlNode])]
  [OutputType([HtmlAgilityPack.HtmlDocument])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory, HelpMessage = 'The Markdown content')]
    [AllowEmptyString()]
    [string]$Content,

    [Parameter(Position = 1, HelpMessage = 'The Markdig Markdown extensions to be added to the pipeline')]
    [ValidateSet('common', 'advanced', 'pipetables', 'gfm-pipetables', 'emphasisextras', 'listextras', 'hardlinebreak', 'footnotes', 'footers', 'citations', 'attributes', 'gridtables', 'abbreviations', 'emojis', 'definitionlists', 'customcontainers', 'figures', 'mathematics', 'bootstrap', 'medialinks', 'smartypants', 'autoidentifiers', 'tasklists', 'diagrams', 'nofollowlinks', 'noopenerlinks', 'noreferrerlinks', 'nohtml', 'yaml', 'nonascii-noescape', 'autolinks', 'globalization')]
    [string[]]$Extensions = @('advanced')
  )

  begin {
    $Pipeline = [Markdig.MarkdownExtensions]::Configure([Markdig.MarkdownPipelineBuilder]::new(), ($Extensions -join '+')).Build()
  }

  process {
    [Markdig.Markdown]::ToHtml($Content, $Pipeline) | ConvertFrom-Html
  }
}

Export-ModuleMember -Function 'Get-TextContent', 'Convert-MarkdownToHtml'
