BeforeDiscovery {
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\YamlSchema.psm1') -Force
}

Describe 'Get-YamlSchemaValidationResult' {
  It 'validates supported scalar, object, and array keywords' {
    $Schema = [ordered]@{
      type                 = 'object'
      required             = @('Name', 'Items')
      properties           = [ordered]@{
        Name  = [ordered]@{ type = 'string'; minLength = 2; maxLength = 8; pattern = '^[A-Z]' }
        Count = [ordered]@{ type = 'integer'; minimum = 1; maximum = 3; format = 'long' }
        Date  = [ordered]@{ type = 'string'; format = 'date' }
        Items = [ordered]@{ type = 'array'; minItems = 1; maxItems = 2; uniqueItems = $true; items = [ordered]@{ enum = @('a', 'b') } }
        Kind  = [ordered]@{ const = 'fixed' }
      }
      additionalProperties = $false
    }

    (Get-YamlSchemaValidationResult -InputObject ([ordered]@{ Name = 'Alpha'; Count = 2L; Date = '2026-07-18'; Items = @('a'); Kind = 'fixed' }) -Schema $Schema).IsValid | Should -BeTrue
    $Result = Get-YamlSchemaValidationResult -InputObject ([ordered]@{ name = 'x'; Count = 4.5; Date = '18-07-2026'; Items = @('a', 'a', 'c'); Kind = 'other'; Extra = 1 }) -Schema $Schema -ValidatePropertyNames
    $Result.IsValid | Should -BeFalse
    $Result.Diagnostics.Reason | Should -Contain PropertyNameCase
    $Result.Diagnostics.Reason | Should -Contain UnknownProperty
    $Result.Diagnostics.Keyword | Should -Contain uniqueItems
    $Result.Diagnostics.Keyword | Should -Contain const
    $Result.Diagnostics.Keyword | Should -Contain format
  }

  It 'supports escaped and nested local references' {
    $Schema = [ordered]@{
      definitions = [ordered]@{
        'a/b~c' = [ordered]@{ type = 'string'; pattern = '^ok$' }
        Wrapper = [ordered]@{ type = 'object'; properties = [ordered]@{ Value = [ordered]@{ '$ref' = '#/definitions/a~1b~0c' } }; required = @('Value') }
      }
      '$ref'      = '#/definitions/Wrapper'
    }
    (Get-YamlSchemaValidationResult -InputObject ([ordered]@{ Value = 'ok' }) -Schema $Schema).IsValid | Should -BeTrue
    (Get-YamlSchemaValidationResult -InputObject ([ordered]@{ Value = 'bad' }) -Schema $Schema).Diagnostics.Keyword | Should -Contain pattern
  }

  It 'reports reference cycles and recursion limits without accessing the network' {
    $Cycle = [ordered]@{ definitions = [ordered]@{ A = [ordered]@{ '$ref' = '#/definitions/A' } }; '$ref' = '#/definitions/A' }
    $CycleResult = Get-YamlSchemaValidationResult -InputObject 'x' -Schema $Cycle
    $CycleResult.IsValid | Should -BeFalse
    $CycleResult.Diagnostics.Reason | Should -Contain Cycle

    { Get-YamlSchemaValue -InputObject @{} -Ref 'https://example.test/schema.json' } | Should -Throw '*disabled*'
    $Deep = [ordered]@{ type = 'object'; properties = [ordered]@{ A = [ordered]@{ type = 'object'; properties = [ordered]@{ B = [ordered]@{ type = 'string' } } } } }
    (Get-YamlSchemaValidationResult -InputObject ([ordered]@{ A = [ordered]@{ B = 'x' } }) -Schema $Deep -MaximumDepth 1).Diagnostics.Reason | Should -Contain MaximumDepth
  }

  It 'implements oneOf and not' {
    $Schema = [ordered]@{ oneOf = @([ordered]@{ const = 'a' }, [ordered]@{ type = 'string' }); not = [ordered]@{ const = 'blocked' } }
    (Get-YamlSchemaValidationResult -InputObject 'a' -Schema $Schema).Diagnostics.Keyword | Should -Contain oneOf
    (Get-YamlSchemaValidationResult -InputObject 'blocked' -Schema $Schema).Diagnostics.Keyword | Should -Contain not
  }
}

Describe 'ConvertTo-SortedYamlObject' {
  It 'orders known keys while preserving unknown keys and every array order' {
    $Schema = [ordered]@{ type = 'object'; properties = [ordered]@{ A = [ordered]@{ type = 'string' }; B = [ordered]@{ type = 'array'; items = [ordered]@{ type = 'string' } } } }
    $InputObject = [ordered]@{ Unknown2 = 2; B = @('z', 'a'); Unknown1 = 1; A = 'first' }
    $Result = ConvertTo-SortedYamlObject -InputObject $InputObject -Schema $Schema
    @($Result.Keys) | Should -Be @('A', 'B', 'Unknown2', 'Unknown1')
    $Result.B | Should -Be @('z', 'a')
  }
}
