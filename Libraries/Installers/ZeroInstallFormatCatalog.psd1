# SPDX-License-Identifier: Apache-2.0
# Structural profiles and behavior boundaries derived independently from tagged
# 0install-win and 0install-dotnet sources and official release artifacts.
@{
  CatalogVersion          = 2

  ManagedIdentityProfiles = @(
    @{
      Id                      = 'LegacyGenericBootstrapper'
      TypeNames               = @('ZeroInstall.Bootstrap.BootstrapProcess')
      Encoding                = 'None'
      MinimumRuntimeVersion   = '2.11.0'
      MaximumRuntimeExclusive = '2.11.6'
      ObservedReleases        = '2.11.0-2.11.5'
    }
  )

  ConfigurationProfiles   = @(
    @{
      Id                      = 'EmbeddedConfig3Mode'
      ResourceName            = 'ZeroInstall.EmbeddedConfig.txt'
      Encoding                = 'FixedLines'
      Fields                  = @('app_uri', 'app_name', 'app_mode')
      MinimumRuntimeVersion   = '2.11.6'
      MaximumRuntimeExclusive = '2.21.0'
      ObservedReleases        = '2.11.6-2.20.x'
    }
    @{
      Id                      = 'EmbeddedConfig5Mode'
      ResourceName            = 'ZeroInstall.EmbeddedConfig.txt'
      Encoding                = 'FixedLines'
      Fields                  = @('app_uri', 'app_name', 'app_mode', 'app_args', 'app_fingerprint')
      MinimumRuntimeVersion   = '2.21.0'
      MaximumRuntimeExclusive = '2.22.0'
      ObservedReleases        = '2.21.x'
    }
    @{
      Id                      = 'EmbeddedConfig5Integrate'
      ResourceName            = 'ZeroInstall.EmbeddedConfig.txt'
      Encoding                = 'FixedLines'
      Fields                  = @('app_uri', 'app_name', 'app_fingerprint', 'app_args', 'integrate_args')
      MinimumRuntimeVersion   = '2.22.0'
      MaximumRuntimeExclusive = '2.23.0'
      ObservedReleases        = '2.22.x'
    }
    @{
      Id                      = 'EmbeddedConfig6AppFingerprint'
      ResourceName            = 'ZeroInstall.EmbeddedConfig.txt'
      Encoding                = 'FixedLines'
      Fields                  = @('self_update_uri', 'app_uri', 'app_name', 'app_fingerprint', 'app_args', 'integrate_args')
      MinimumRuntimeVersion   = '2.23.0'
      MaximumRuntimeExclusive = '2.23.1'
      ObservedReleases        = '2.23.0'
    }
    @{
      Id                      = 'EmbeddedConfig6KeyFingerprint'
      ResourceName            = 'ZeroInstall.EmbeddedConfig.txt'
      Encoding                = 'FixedLines'
      Fields                  = @('self_update_uri', 'key_fingerprint', 'app_uri', 'app_name', 'app_args', 'integrate_args')
      MinimumRuntimeVersion   = '2.23.1'
      MaximumRuntimeExclusive = '2.24.1'
      ObservedReleases        = '2.23.1-2.24.0'
    }
    @{
      Id                      = 'EmbeddedConfig7'
      ResourceName            = 'ZeroInstall.EmbeddedConfig.txt'
      Encoding                = 'FixedLines'
      Fields                  = @('self_update_uri', 'key_fingerprint', 'app_uri', 'app_name', 'app_args', 'integrate_args', 'customizable_store_path')
      MinimumRuntimeVersion   = '2.24.1'
      MaximumRuntimeExclusive = '2.24.8'
      ObservedReleases        = '2.24.1-2.24.7'
    }
    @{
      Id                      = 'ConfigIni'
      ResourceName            = 'ZeroInstall.config.ini'
      Encoding                = 'Ini'
      MinimumRuntimeVersion   = '2.24.8'
      MaximumRuntimeExclusive = '2.25.3'
      ObservedReleases        = '2.24.8-2.25.2'
    }
    @{
      Id                    = 'BootstrapConfigIni'
      ResourceName          = 'ZeroInstall.BootstrapConfig.ini'
      Encoding              = 'Ini'
      MinimumRuntimeVersion = '2.25.3'
      ObservedReleases      = '2.25.3-current'
    }
  )

  Features                = @{
    AppSettingsOverrides        = '2.11.8'
    ContentDirectorySwitch      = '2.11.6'
    AppsAndFeaturesRegistration = '2.21.0'
    SilentSwitch                = '2.23.0'
    MachineScopeSwitch          = '2.23.1'
    NoIntegrateSwitch           = '2.23.1'
    PlainArpDisplayName         = '2.23.3'
    PublisherArpValue           = '2.24.0'
    PrepareOfflineSwitch        = '2.23.9'
    RefreshSwitch               = '2.24.0'
    BackgroundSwitch            = '2.24.0'
    VerySilentSwitch            = '2.24.0'
    EmbeddedContent             = '2.24.6'
    WaitSwitch                  = '2.24.7'
    IniConfiguration            = '2.24.8'
    StorePathSwitch             = '2.24.8'
    IntegrateArgsSwitch         = '2.24.8'
    SplitVersionSwitches        = '2.24.6'
    CurrentVersionSwitchNames   = '2.24.8'
    BootstrapConfigResource     = '2.25.3'
    EstimatedRequiredSpace      = '2.25.4'
    ModifyArpCommand            = '2.25.12'
    FeedOverrideSwitches        = '2.27.5'
  }
}
