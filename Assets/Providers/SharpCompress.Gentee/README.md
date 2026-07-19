# SharpCompress Gentee PPMd Provider

`SharpCompress.Gentee.dll` is a managed companion provider for the modified
PPMd-I streams used by Gentee GEA archives and CreateInstall installers. It
uses the SharpCompress PPMd-I object model and exposes the provider as
`SharpCompress.Compressors.PPMd.Gentee.GenteePpmdDecoder`.

SharpCompress does not expose a public custom-codec registration interface.
The companion assembly is loaded alongside the unmodified
`Assets\Assemblies\SharpCompress.dll` at runtime; it does not replace or alter
standard H, H7Z, or I1 decoding.

## Format Differences

GEA differs from standard SharpCompress PPMd-I in the binary-summary QTable,
suffix frequency updates, escape-frequency classification, previous-success
comparison, model restart behavior, and the allocator glue interval. Order-1
records retain the statistical model but start an independent range stream.

The provider bounds every range stream to the compressed size declared by the
GEA record. It requires the exact expanded byte count, a PPMd end marker, and
exact compressed-byte consumption. It never reads into the following GEA
record to compensate for a malformed size.

## Sources And License

- SharpCompress PPMd-I source is based on SharpCompress 0.39.0 at commit
  `6f3124b386d188baef9dbe15847532d804905650` (MIT).
- Gentee compatibility behavior is based on pyppmd-gentee 1.4.0 at commit
  `a6e4dbcf8b600664c4b8ff47ec090e42588f9f14` and cross-checked against the
  CreateInstall 8.11.2 GEA reader (LGPL-2.1-or-later modifications).

The combined provider and its complete corresponding source are distributed
under `LGPL-2.1-or-later`; see `LICENSE`. PackageModule loads it as a separate
managed assembly only when a GEA PPMd record is encountered.

## Reproducible Build

From this directory with .NET 8 or later:

```powershell
dotnet build .\Source\SharpCompress.Gentee.csproj -c Release
Copy-Item .\Source\bin\Release\net8.0\SharpCompress.Gentee.dll . -Force
```
