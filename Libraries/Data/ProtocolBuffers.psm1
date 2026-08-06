#Requires -Version 7.4

# SPDX-License-Identifier: Apache-2.0
# Schema-less Protocol Buffers wire-format decoding for package metadata feeds.

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

function Read-ProtocolBufferVarint {
  <#
  .SYNOPSIS
    Read one Protocol Buffers variable-width integer from the current stream position.
  .PARAMETER Stream
    The caller-owned stream. Reading advances its position past the varint.
  .PARAMETER OutputType
    The integer representation returned to the wire-message decoder.
  #>
  param (
    [Parameter(Position = 0, Mandatory)][System.IO.Stream]$Stream,
    [Parameter(Position = 1)][ValidateSet('Int64', 'UInt64', 'Int32', 'UInt32', 'Raw')][string]$OutputType = 'Int64'
  )

  $Buffer = [System.Collections.Generic.List[byte]]::new(10)
  do {
    $Byte = $Stream.ReadByte()
    if ($Byte -lt 0) { throw 'The Protocol Buffers varint is truncated.' }
    if ($Buffer.Count -eq 10) { throw 'The Protocol Buffers varint exceeds the 10-byte uint64 limit.' }
    $Buffer.Add([byte]$Byte)
  } while ($Byte -band 0b10000000u)

  switch ($OutputType) {
    'UInt64' { $Value = [UInt64]0; break }
    'Int64' { $Value = [Int64]0; break }
    'UInt32' { $Value = [UInt32]0; break }
    'Int32' { $Value = [Int32]0; break }
    'Raw' { return $Buffer.ToArray() }
  }

  for ($Index = $Buffer.Count - 1; $Index -ge 0; $Index--) {
    $Value = ($Value -shl 7) -bor ($Buffer[$Index] -band 0b01111111u)
  }
  return $Value
}

function Read-ProtocolBufferFixed64 {
  <#
  .SYNOPSIS
    Read one little-endian 64-bit Protocol Buffers wire value.
  .PARAMETER Stream
    The caller-owned stream. Reading advances its position by eight bytes.
  .PARAMETER OutputType
    The numeric or raw representation returned to the wire-message decoder.
  #>
  param (
    [Parameter(Position = 0, Mandatory)][System.IO.Stream]$Stream,
    [Parameter(Position = 1)][ValidateSet('Int64', 'UInt64', 'Double', 'Raw')][string]$OutputType = 'Int64'
  )

  $Buffer = [byte[]]::new(8)
  $Read = $Stream.ReadAtLeast($Buffer, 8, $false)
  if ($Read -ne 8) { throw 'The Protocol Buffers fixed64 value is truncated.' }

  switch ($OutputType) {
    'UInt64' { return [BitConverter]::ToUInt64($Buffer, 0) }
    'Int64' { return [BitConverter]::ToInt64($Buffer, 0) }
    'Double' { return [BitConverter]::ToDouble($Buffer, 0) }
    'Raw' { return $Buffer }
  }
}

function Read-ProtocolBufferFixed32 {
  <#
  .SYNOPSIS
    Read one little-endian 32-bit Protocol Buffers wire value.
  .PARAMETER Stream
    The caller-owned stream. Reading advances its position by four bytes.
  .PARAMETER OutputType
    The numeric or raw representation returned to the wire-message decoder.
  #>
  param (
    [Parameter(Position = 0, Mandatory)][System.IO.Stream]$Stream,
    [Parameter(Position = 1)][ValidateSet('Int32', 'UInt32', 'Float', 'Raw')][string]$OutputType = 'Int32'
  )

  $Buffer = [byte[]]::new(4)
  $Read = $Stream.ReadAtLeast($Buffer, 4, $false)
  if ($Read -ne 4) { throw 'The Protocol Buffers fixed32 value is truncated.' }

  switch ($OutputType) {
    'UInt32' { return [BitConverter]::ToUInt32($Buffer, 0) }
    'Int32' { return [BitConverter]::ToInt32($Buffer, 0) }
    'Float' { return [BitConverter]::ToSingle($Buffer, 0) }
    'Raw' { return $Buffer }
  }
}

function ConvertFrom-ProtoBuf {
  <#
  .SYNOPSIS
    Convert a schema-less Protocol Buffers message into an ordered dictionary.
  .PARAMETER RawContentStream
    The caller-owned message stream. The function consumes it but does not dispose it.
  .PARAMETER Content
    The complete Protocol Buffers message as a byte array.
  .PARAMETER Path
    The path to a file containing one Protocol Buffers message.
  .PARAMETER VarintType
    The representation used for varint field values.
  .PARAMETER Fixed64Type
    The representation used for fixed64 field values.
  .PARAMETER Fixed32Type
    The representation used for fixed32 field values.
  #>
  [OutputType([System.Collections.Specialized.OrderedDictionary])]
  [CmdletBinding(DefaultParameterSetName = 'Stream')]
  param (
    [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'Stream', Mandatory)][System.IO.Stream]$RawContentStream,
    [Parameter(Position = 0, ParameterSetName = 'Array', Mandatory)][byte[]]$Content,
    [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'File', Mandatory)][string]$Path,
    [Parameter(Position = 1)][ValidateSet('Int64', 'UInt64', 'Int32', 'UInt32', 'Raw')][string]$VarintType = 'Int64',
    [Parameter(Position = 2)][ValidateSet('Int64', 'UInt64', 'Double', 'Raw')][string]$Fixed64Type = 'Int64',
    [Parameter(Position = 3)][ValidateSet('Int32', 'UInt32', 'Float', 'Raw')][string]$Fixed32Type = 'Int32'
  )

  process {
    $OwnsStream = $PSCmdlet.ParameterSetName -ne 'Stream'
    $Stream = switch ($PSCmdlet.ParameterSetName) {
      'Stream' { $RawContentStream }
      'Array' { [IO.MemoryStream]::new($Content, $false) }
      'File' {
        $ResolvedPath = (Get-Item -LiteralPath $Path -Force -ErrorAction Stop).FullName
        [IO.File]::Open($ResolvedPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
      }
    }

    try {
      $Result = [ordered]@{}
      while ($Stream.Position -lt $Stream.Length) {
        $Metadata = Read-ProtocolBufferVarint -Stream $Stream -OutputType UInt64
        $FieldNumber = [string]($Metadata -shr 3)
        $WireType = $Metadata -band 0b00000111u
        if ($FieldNumber -eq '0') { throw 'Protocol Buffers field number zero is invalid.' }
        Write-Verbose -Message "Offset: $($Stream.Position);`tField Number: ${FieldNumber};`tWire Type: ${WireType}"

        $Value = switch ($WireType) {
          0 { Read-ProtocolBufferVarint -Stream $Stream -OutputType $VarintType; break }
          1 { Read-ProtocolBufferFixed64 -Stream $Stream -OutputType $Fixed64Type; break }
          2 {
            $Length = Read-ProtocolBufferVarint -Stream $Stream -OutputType UInt64
            if ($Length -gt [int]::MaxValue -or $Length -gt ($Stream.Length - $Stream.Position)) {
              throw 'The Protocol Buffers length-delimited field exceeds the remaining message range.'
            }
            $Buffer = [byte[]]::new([int]$Length)
            if ($Length -gt 0) { $null = $Stream.ReadAtLeast($Buffer, [int]$Length, $false) }
            try {
              [Text.UTF8Encoding]::new($false, $true).GetString($Buffer)
            } catch {
              try { ConvertFrom-ProtoBuf -Content $Buffer -VarintType $VarintType -Fixed64Type $Fixed64Type -Fixed32Type $Fixed32Type }
              catch { $Buffer }
            }
            break
          }
          5 { Read-ProtocolBufferFixed32 -Stream $Stream -OutputType $Fixed32Type; break }
          default { throw "Unsupported or unknown Protocol Buffers wire type ${WireType}." }
        }

        # Protocol Buffers permits repeated field numbers. Preserve their source order.
        if ($Result.Contains($FieldNumber)) {
          if ($Result[$FieldNumber] -isnot [Collections.Generic.List[object]]) {
            $Result[$FieldNumber] = [Collections.Generic.List[object]]::new(@($Result[$FieldNumber]))
          }
          $Result[$FieldNumber].Add($Value)
        } else {
          $Result[$FieldNumber] = $Value
        }
      }
      return $Result
    } finally {
      if ($OwnsStream) { $Stream.Dispose() }
    }
  }
}

Export-ModuleMember -Function ConvertFrom-ProtoBuf
