. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

# SPDX-License-Identifier: Apache-2.0

BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  $Script:DumplingsModulesRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..'))
  $Script:DumplingsRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModulesRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Data\ProtocolBuffers.psm1') -Force
}

Describe 'ConvertFrom-ProtoBuf' {
  It 'exports only the public converter from the dedicated module' {
    $Module = Get-Module ProtocolBuffers

    @($Module.ExportedFunctions.Keys) | Should -Be @('ConvertFrom-ProtoBuf')
  }

  It 'decodes varint, text, fixed32, and fixed64 wire values' {
    $Content = [byte[]](
      0x08, 0x96, 0x01,
      0x12, 0x03, 0x61, 0x62, 0x63,
      0x1D, 0x78, 0x56, 0x34, 0x12,
      0x21, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01
    )

    $Result = ConvertFrom-ProtoBuf -Content $Content -VarintType UInt64 -Fixed32Type UInt32 -Fixed64Type UInt64

    $Result['1'] | Should -Be 150
    $Result['2'] | Should -Be 'abc'
    $Result['3'] | Should -Be 0x12345678
    $Result['4'] | Should -Be 0x0102030405060708
  }

  It 'preserves repeated values in source order' {
    $Result = ConvertFrom-ProtoBuf -Content ([byte[]](0x08, 0x01, 0x08, 0x02, 0x08, 0x03))

    @($Result['1']) | Should -Be @(1, 2, 3)
  }

  It 'recursively decodes a length-delimited submessage when it is not UTF-8 text' {
    $Result = ConvertFrom-ProtoBuf -Content ([byte[]](0x0A, 0x03, 0x08, 0x96, 0x01)) -VarintType UInt64

    $Result['1']['1'] | Should -Be 150
  }

  It 'accepts file input and resolves the path before opening it' {
    $Path = Join-Path $TestDrive 'message.bin'
    [IO.File]::WriteAllBytes($Path, [byte[]](0x0A, 0x04, 0x74, 0x65, 0x73, 0x74))

    (ConvertFrom-ProtoBuf -Path $Path)['1'] | Should -Be 'test'
  }

  It 'consumes but does not dispose a caller-owned stream' {
    $Stream = [IO.MemoryStream]::new([byte[]](0x08, 0x2A), $false)
    try {
      (ConvertFrom-ProtoBuf -RawContentStream $Stream)['1'] | Should -Be 42
      $Stream.CanRead | Should -BeTrue
      $Stream.Position | Should -Be $Stream.Length
    } finally {
      $Stream.Dispose()
    }
  }

  It 'rejects truncated and unsupported wire values' -ForEach @(
    @{ Content = [byte[]](0x08, 0x80); Message = '*varint is truncated*' }
    @{ Content = [byte[]](0x0D, 0x01); Message = '*fixed32 value is truncated*' }
    @{ Content = [byte[]](0x0A, 0x04, 0x01); Message = '*exceeds the remaining message range*' }
    @{ Content = [byte[]](0x0B); Message = '*wire type 3*' }
  ) {
    { ConvertFrom-ProtoBuf -Content $Content } | Should -Throw $Message
  }
}
