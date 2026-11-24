. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

BeforeAll { Import-Module (Join-Path $PSScriptRoot '..\..\Libraries\Data\Conversion.psm1') }

Describe 'Lossless data operations' -Tag Unit {
  It 'preserves nested empty collections, nulls, dates and scriptblocks without mutating the caller' {
    $Block = { 'value' }
    $Original = [ordered]@{ Date = [datetime]'2026-01-02'; Query = $Block; Null = $null; Empty = @(); Nested = @(@(), [ordered]@{ Name = 'Before' }) }
    $Copy = Copy-Object $Original
    $Copy.Keys | Should -Be @('Date', 'Query', 'Null', 'Empty', 'Nested')
    $Copy.Date | Should -BeOfType datetime
    [object]::ReferenceEquals($Copy.Query, $Block) | Should -BeTrue
    $Copy.Contains('Null') | Should -BeTrue
    $Copy.Empty.Count | Should -Be 0
    $Copy.Nested.Count | Should -Be 2
    $Copy.Nested[0].Count | Should -Be 0
    $Copy.Nested[1].Name = 'After'
    $Original.Nested[1].Name | Should -Be 'Before'
  }

  It 'preserves a case-sensitive hashtable and rejects cycles at the depth bound' {
    $Source = [hashtable]::new([StringComparer]::Ordinal)
    $Source['a'] = 1; $Source['A'] = 2
    $Copy = Copy-Object $Source
    $Copy['a'] | Should -Be 1
    $Copy['A'] | Should -Be 2
    $Source['Cycle'] = $Source
    { Copy-Object $Source -Depth 5 } | Should -Throw '*depth limit*'
  }

  It 'does not mistake PSObject-wrapped scalar arguments for property records' {
    $Wrapped = [psobject]'arm'
    Copy-Object $Wrapped | Should -BeExactly 'arm'
    $Copy = Copy-Object ([pscustomobject]@{ Value = $Wrapped })
    $Copy.Value | Should -BeExactly 'arm'
  }

  It 'preserves distinct case-sensitive ordered keys instead of overwriting data' {
    $Source = [Collections.Specialized.OrderedDictionary]::new()
    $Source.Add('Name', 1)
    $Source.Add('name', 2)
    $Copy = Copy-Object $Source
    $Copy.Keys | Should -Be @('Name', 'name')
    $Copy['Name'] | Should -Be 1
    $Copy['name'] | Should -Be 2
  }

  It 'distinguishes casing, missing properties, nulls and ordered arrays' {
    Test-ObjectValueEqual @{ Value = @('a', 'b') } @{ Value = @('a', 'b') } | Should -BeTrue
    Test-ObjectValueEqual @{ Value = @('a', 'b') } @{ Value = @('b', 'a') } | Should -BeFalse
    Test-ObjectValueEqual @{ Value = 'a' } @{ Value = 'A' } | Should -BeFalse
    Test-ObjectValueEqual @{ Value = $null } @{} | Should -BeFalse
    Test-ObjectValueEqual @{ Value = @() } @{ Value = $null } | Should -BeFalse
    Test-ObjectValueEqual @{ Value = 1 } @{ value = 1 } | Should -BeFalse
  }
}
