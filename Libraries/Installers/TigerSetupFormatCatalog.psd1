# SPDX-License-Identifier: Apache-2.0
# Physical profiles from the MIT upstream footer.rs at a83bdd8 (0.5.2),
# e264bea (0.8.0), and ac77e6a (0.9.0). Offsets are footer-relative bytes.
# Schema field numbers are additive; file batches first become mandatory in 2.
@{
  Profiles = @(
    @{
      Id = 'EngineZip1'; Major = 1; FooterLength = 128; CrcOffset = 116; Schema = 1
      FirstBuilder = '0.5.2'; SourceCommit = 'a83bdd8'; RequiresFileBatches = $false
      Order = @('Engine', 'Metadata', 'Payload'); MetadataHashOffset = 48; EngineHashOffset = -1
      Blocks = @(
        @{ Name = 'Metadata'; OffsetField = 16; LengthField = 24; ExpandedField = -1; HashField = 48; Codec = 'Stored' }
        @{ Name = 'Payload'; OffsetField = 32; LengthField = 40; ExpandedField = -1; HashField = 80; Codec = 'Zip' }
      )
    }
    @{
      Id = 'SplitSolid2'; Major = 2; FooterLength = 256; CrcOffset = 244; Schema = 1
      FirstBuilder = '0.8.0'; SourceCommit = 'e264bea'; RequiresFileBatches = $false
      Order = @('Engine', 'Payload', 'Metadata'); MetadataHashOffset = 144; EngineHashOffset = 112
      Blocks = @(
        @{ Name = 'Engine'; OffsetField = 16; LengthField = 24; ExpandedField = 32; HashField = 80; Codec = 'Zstd' }
        @{ Name = 'Payload'; OffsetField = 56; LengthField = 64; ExpandedField = 72; HashField = 176; Codec = 'Zstd' }
        @{ Name = 'Metadata'; OffsetField = 40; LengthField = 48; ExpandedField = -1; HashField = 144; Codec = 'Stored' }
      )
    }
    @{
      Id = 'CompressedMetadata3'; Major = 3; FooterLength = 320; CrcOffset = 308; Schema = 2
      FirstBuilder = '0.9.0'; SourceCommit = 'ac77e6a'; RequiresFileBatches = $true
      Order = @('Engine', 'Payload', 'Metadata'); MetadataHashOffset = 216; EngineHashOffset = 120
      Blocks = @(
        @{ Name = 'Engine'; OffsetField = 16; LengthField = 24; ExpandedField = 32; HashField = 88; Codec = 'Zstd' }
        @{ Name = 'Payload'; OffsetField = 40; LengthField = 48; ExpandedField = 56; HashField = 152; Codec = 'Zstd' }
        @{ Name = 'Metadata'; OffsetField = 64; LengthField = 72; ExpandedField = 80; HashField = 184; Codec = 'Zstd' }
      )
    }
  )
}
