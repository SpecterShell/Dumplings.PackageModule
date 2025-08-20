class WinGetManifestRaw {
  [string]$Version
  [string]$Installer
  [System.Collections.Generic.IDictionary[string, string]]$Locale
}

class WinGetManifest {
  [System.Collections.IDictionary]$Version
  [System.Collections.IDictionary]$Installer
  [System.Collections.Generic.IDictionary[string, System.Collections.IDictionary]]$Locale
}
