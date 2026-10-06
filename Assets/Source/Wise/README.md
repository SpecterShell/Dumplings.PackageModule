# Wise managed reader assets

`Assets/Assemblies/SabreTools.IO.dll` and `Assets/Assemblies/SabreTools.Serialization.dll` are pinned MIT-licensed dependencies used by `Libraries/Installers/Wise.psm1`.

The Serialization asset was built from SabreTools.Serialization commit `3798dbcb479f42cd607e0ac8a01ed06ba892fbe3`. The local patch removes two unconditional `Console.WriteLine` fallback messages from `SabreTools.Serialization.Readers.WiseScript`. It does not change parsing decisions or public types. Apply `SabreTools.Serialization-no-console.patch` at the repository root with `git apply --ignore-space-change <path-to-patch>`, then build the `SabreTools.Serialization` project for `net8.0`.

Expected asset hashes:

```text
SabreTools.IO.dll             E99F7006FCC01B4CC459B16B09C9DBFF8E9F8D3CCF6532BD097A92FD770ED077
SabreTools.Serialization.dll 6602C7A3C9DD523CFCCDE82254EE647FE639C4505909AAFAA7E6FB37368C1306
```
