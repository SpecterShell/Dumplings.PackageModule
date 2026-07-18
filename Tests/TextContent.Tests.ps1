BeforeDiscovery {
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\TextContent.psm1') -Force
}

Describe 'Get-TextContent non-table regressions' {
  It 'preserves paragraphs and inline text' {
    $Actual = '<div><p>Hello <strong>world</strong>.</p><p>Next &amp; final.</p></div>' | ConvertFrom-Html | Get-TextContent
    $Actual | Should -Be "Hello world.`nNext & final."
  }

  It 'preserves ordered and nested lists' {
    $Actual = '<ol start="3"><li>Third<ul><li>Nested</li></ul></li><li>Fourth</li></ol>' | ConvertFrom-Html | Get-TextContent
    $Actual | Should -Be "3. Third`n   - Nested`n4. Fourth"
  }

  It 'preserves preformatted text, line breaks, and entities' {
    ("<pre>line 1`n  line 2</pre>" | ConvertFrom-Html | Get-TextContent) | Should -Be "line 1`n  line 2"
    ('<p>A<br>B &amp; C</p>' | ConvertFrom-Html | Get-TextContent) | Should -Be "A`nB & C"
  }
}

Describe 'Get-TextContent HTML tables' {
  It 'renders an ordinary header and body as a valid rectangular pipe table' {
    $Html = '<table><thead><tr><th>Name</th><th>Value</th></tr></thead><tbody><tr><td>Alpha</td><td>One</td></tr></tbody></table>'
    $Actual = $Html | ConvertFrom-Html | Get-TextContent

    $Actual | Should -Be "| Name  | Value |`n| ----- | ----- |`n| Alpha | One   |"
    $Parsed = $Actual | Convert-MarkdownToHtml -Extensions pipetables
    @($Parsed.SelectNodes('//table//tr')).Count | Should -Be 2
    @($Parsed.SelectNodes('(//table//tr)[1]/*')).Count | Should -Be 2
  }

  It 'synthesizes an empty header for a headerless table by default' {
    $Html = '<table><tr><td>A</td><td>中文</td></tr><tr><td>long</td><td>x</td></tr></table>'
    $Actual = $Html | ConvertFrom-Html | Get-TextContent

    $Actual | Should -Be "|      |      |`n| ---- | ---- |`n| A    | 中文 |`n| long | x    |"
  }

  It 'can promote the first row of a headerless table' {
    $Html = '<table><tr><td>A</td><td>中文</td></tr><tr><td>long</td><td>x</td></tr></table>'
    $Actual = $Html | ConvertFrom-Html | Get-TextContent -HeaderlessTableMode FirstRow

    $Actual | Should -Be "| A    | 中文 |`n| ---- | ---- |`n| long | x    |"
  }

  It 'keeps additional HTML header rows as body rows' {
    $Html = '<table><thead><tr><th>A</th><th>B</th></tr><tr><th>A2</th><th>B2</th></tr></thead><tbody><tr><td>C</td><td>D</td></tr></tbody></table>'
    $Actual = $Html | ConvertFrom-Html | Get-TextContent

    $Actual | Should -Be "| A   | B   |`n| --- | --- |`n| A2  | B2  |`n| C   | D   |"
  }

  It 'requires an all-th first row when the row is outside thead' {
    $Html = '<table><tr><th>A</th><td>B</td></tr><tr><td>C</td><td>D</td></tr></table>'
    $Lines = ($Html | ConvertFrom-Html | Get-TextContent) -split "`n"

    $Lines[0].Trim('| ') | Should -Be ''
    $Lines[2] | Should -Match '\| A\s+\| B\s+\|'
  }

  It 'places a direct caption before the table with a blank boundary' {
    $Html = '<table><caption>Results &amp; notes</caption><tr><th>A</th></tr><tr><td>B</td></tr></table>'
    $Actual = $Html | ConvertFrom-Html | Get-TextContent

    $Actual | Should -Be "Results & notes`n`n| A   |`n| --- |`n| B   |"
  }

  It 'separates tables from surrounding block content' {
    $Html = '<div><p>Before</p><table><tr><th>A</th></tr><tr><td>B</td></tr></table><p>After</p></div>'
    $Actual = $Html | ConvertFrom-Html | Get-TextContent

    $Actual | Should -Be "Before`n`n| A   |`n| --- |`n| B   |`n`nAfter"
  }

  It 'falls back to recursive text extraction for a table without usable rows' {
    $Actual = '<table><caption>Caption only</caption></table>' | ConvertFrom-Html | Get-TextContent

    $Actual | Should -Be 'Caption only'
  }

  It 'repeats rowspan and colspan anchors by default' {
    $Html = '<table><tr><th colspan="2">Head</th><th>X</th></tr><tr><td rowspan="2">A</td><td>B</td><td>C</td></tr><tr><td colspan="2">D</td></tr></table>'
    $Actual = $Html | ConvertFrom-Html | Get-TextContent

    $Actual | Should -Be "| Head | Head | X   |`n| ---- | ---- | --- |`n| A    | B    | C   |`n| A    | D    | D   |"
  }

  It 'can render span continuations as empty cells' {
    $Html = '<table><tr><th colspan="2">Head</th><th>X</th></tr><tr><td rowspan="2">A</td><td>B</td><td>C</td></tr><tr><td colspan="2">D</td></tr></table>'
    $Actual = $Html | ConvertFrom-Html | Get-TextContent -TableSpanMode Empty

    $Actual | Should -Be "| Head |     | X   |`n| ---- | --- | --- |`n| A    | B   | C   |`n|      | D   |     |"
  }

  It 'emits Advanced Table XT horizontal and vertical continuation cells' {
    $Html = '<table><tr><th colspan="2">Head</th><th>X</th></tr><tr><td rowspan="2">A</td><td>B</td><td>C</td></tr><tr><td colspan="2">D</td></tr></table>'
    $Actual = $Html | ConvertFrom-Html | Get-TextContent -TableSpanMode AdvancedTableXT

    $Actual | Should -Be "| Head | <   | X   |`n| ---- | --- | --- |`n| A    | B   | C   |`n| ^    | D   | <   |"
  }

  It 'bounds rowspan zero to its current row group' {
    $Html = '<table><tbody><tr><td rowspan="0">A</td><td>B</td></tr><tr><td>C</td></tr></tbody><tbody><tr><td>D</td><td>E</td></tr></tbody></table>'
    $Actual = $Html | ConvertFrom-Html | Get-TextContent

    $Actual | Should -Be "|     |     |`n| --- | --- |`n| A   | B   |`n| A   | C   |`n| D   | E   |"
  }

  It 'normalizes invalid spans and pads ragged rows without overwriting occupied slots' {
    $Html = '<table><tr><th>A</th><th>B</th><th>C</th></tr><tr><td rowspan="bad" colspan="-2">D</td></tr><tr><td>E</td><td>F</td></tr></table>'
    $Actual = $Html | ConvertFrom-Html | Get-TextContent

    $Actual | Should -Be "| A   | B   | C   |`n| --- | --- | --- |`n| D   |     |     |`n| E   | F   |     |"
  }

  It 'escapes pipes, backslashes, literal angle brackets, and converts cell breaks' {
    $Html = '<table><tr><th>A|B</th><th>C\D</th></tr><tr><td>One<br>Two</td><td>&lt;x&gt; &amp; y</td></tr></table>'
    $Actual = $Html | ConvertFrom-Html | Get-TextContent

    $Actual | Should -Be "| A\|B       | C\\D     |`n| ---------- | -------- |`n| One<br>Two | \<x> & y |"
  }

  It 'protects literal Advanced Table XT control values' {
    $Html = '<table><tr><th colspan="2">&lt;</th></tr><tr><td rowspan="2">^</td><td>~style</td></tr><tr><td>---</td></tr></table>'
    $Actual = $Html | ConvertFrom-Html | Get-TextContent -TableSpanMode AdvancedTableXT

    $Actual | Should -Match '\\\<'
    $Actual | Should -Match '\\\^'
    $Actual | Should -Match '\\~style'
    $Actual | Should -Match '\\---'
  }

  It 'does not collect nested table rows into the parent grid' {
    $Html = '<table><tr><th>Outer</th><th>Value</th></tr><tr><td><strong>A</strong><table><tr><th>N</th></tr><tr><td>X</td></tr></table></td><td>Z</td></tr></table>'
    $Actual = $Html | ConvertFrom-Html | Get-TextContent
    $Parsed = $Actual | Convert-MarkdownToHtml -Extensions pipetables

    @($Parsed.SelectNodes('//table//tr')).Count | Should -Be 2
    @($Parsed.SelectNodes('(//table//tr)[2]/*')).Count | Should -Be 2
  }

  It 'pads columns using CJK and emoji terminal display widths' {
    $Html = '<table><tr><th>名称</th><th>Icon</th></tr><tr><td>A</td><td>😀</td></tr><tr><td>中文测试</td><td>text</td></tr></table>'
    $Actual = $Html | ConvertFrom-Html | Get-TextContent

    $Actual | Should -Be "| 名称     | Icon |`n| -------- | ---- |`n| A        | 😀   |`n| 中文测试 | text |"
  }
}
