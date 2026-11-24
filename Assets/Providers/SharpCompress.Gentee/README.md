# SharpCompress Gentee PPMd Provider

`SharpCompress.Gentee.dll` decodes the modified PPMd-I streams in Gentee GEA archives and CreateInstall installers. It uses SharpCompress's PPMd-I object model and exposes `SharpCompress.Compressors.PPMd.Gentee.GenteePpmdDecoder`.

Load the companion assembly alongside the unmodified `Assets\Assemblies\SharpCompress.dll`. SharpCompress has no public custom-codec registration interface. Standard H, H7Z, and I1 decoding remains unchanged.

## Format Differences

GEA modifies the binary-summary QTable, suffix frequency updates, escape-frequency classification, previous-success comparison, model restart behavior, and allocator glue interval. Order-1 records retain the statistical model and start an independent range stream.

Each range stream is bounded by the GEA record's declared compressed size. The decoder requires the exact expanded byte count, a PPMd end marker, and complete consumption of the compressed bytes. A malformed size cannot extend the read into the next record.

## Sources And License

- SharpCompress PPMd-I source is based on SharpCompress 0.39.0 at commit
  `6f3124b386d188baef9dbe15847532d804905650` (MIT).
- Gentee compatibility behavior is based on pyppmd-gentee 1.4.0 at commit
  `a6e4dbcf8b600664c4b8ff47ec090e42588f9f14` and cross-checked against the
  CreateInstall 8.11.2 GEA reader (LGPL-2.1-or-later modifications).

The provider and its complete corresponding source are distributed under `LGPL-2.1-or-later`. See `LICENSE`. PackageModule loads the separate managed assembly only for GEA PPMd records.

## Reproducible Build

From this directory with .NET 8 or later:

```powershell
dotnet build .\Source\SharpCompress.Gentee.csproj -c Release
Copy-Item .\Source\bin\Release\net8.0\SharpCompress.Gentee.dll . -Force
```
