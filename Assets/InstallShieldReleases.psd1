@{
  # SchemaVersion belongs to the authored InstallShield project database. These
  # mappings are intentionally separate from shipped runtime/media versions.
  Schemas  = @{
    '755' = @(@{ Name = 'InstallShield DevStudio 9'; ProductVersion = '9'; Year = 2003; Confidence = 'PublishedMapping' })
    '761' = @(@{ Name = 'InstallShield 11'; ProductVersion = '11'; Year = 2005; Confidence = 'PublishedMapping' })
    '763' = @(@{ Name = 'InstallShield 11.5'; ProductVersion = '11.5'; Year = 2005; Confidence = 'PublishedMapping' })
    '765' = @(@{ Name = 'InstallShield 12'; ProductVersion = '12'; Year = 2006; Confidence = 'PublishedMapping' })
    '766' = @(@{ Name = 'InstallShield 2008'; ProductVersion = '14'; Year = 2007; Confidence = 'OfficialBuilder' })
    '767' = @(@{ Name = 'InstallShield 2008'; ProductVersion = '14'; Year = 2007; Confidence = 'Reported' })
    '768' = @(@{ Name = 'InstallShield 2009'; ProductVersion = '15'; Year = 2008; Confidence = 'OfficialBuilder' })
    # Both values have been emitted by InstallShield 2010 project revisions.
    '769' = @(@{ Name = 'InstallShield 2010'; ProductVersion = '16'; Year = 2009; Confidence = 'OfficialBuilder' })
    '770' = @(@{ Name = 'InstallShield 2010'; ProductVersion = '16'; Year = 2009; Confidence = 'ReportedAlias' })
    '771' = @(@{ Name = 'InstallShield 2011'; ProductVersion = '17'; Year = 2010; Confidence = 'OfficialBuilder' })
    '772' = @(@{ Name = 'InstallShield 2012'; ProductVersion = '18'; Year = 2011; Confidence = 'PublishedMapping' })
    '773' = @(@{ Name = 'InstallShield 2012 Spring'; ProductVersion = '19'; Year = 2012; Confidence = 'OfficialBuilder' })
    '774' = @(@{ Name = 'InstallShield 2013'; ProductVersion = '20'; Year = 2013; Confidence = 'OfficialBuilder' })
    '775' = @(@{ Name = 'InstallShield 2014'; ProductVersion = '21'; Year = 2014; Confidence = 'PublishedMapping' })
    '776' = @(@{ Name = 'InstallShield 2015'; ProductVersion = '22'; Year = 2015; Confidence = 'OfficialBuilder' })
    '777' = @(@{ Name = 'InstallShield 2016'; ProductVersion = '23'; Year = 2016; Confidence = 'PublishedMapping' })
    '778' = @(@{ Name = 'InstallShield 2018 R1'; ProductVersion = '24'; Year = 2018; Confidence = 'PublishedMapping' })
    '779' = @(@{ Name = 'InstallShield 2018 R2'; ProductVersion = '24'; Year = 2018; Confidence = 'PublishedMapping' })
    '780' = @(@{ Name = 'InstallShield 2019'; ProductVersion = '25'; Year = 2019; Confidence = 'PublishedMapping' })
    '781' = @(@{ Name = 'InstallShield 2019 R2'; ProductVersion = '25'; Year = 2019; Confidence = 'OfficialBuilder'; Specificity = 20 })
    '782' = @(@{ Name = 'InstallShield 2019 R3'; ProductVersion = '25'; Year = 2019; Confidence = 'OfficialBuilder'; Specificity = 20 })
    '783' = @(@{ Name = 'InstallShield 2020 R1'; ProductVersion = '26'; Year = 2020; Confidence = 'OfficialBuilder'; Specificity = 20 })
    '784' = @(
      @{ Name = 'InstallShield 2020 R2'; ProductVersion = '26'; Year = 2020; Confidence = 'ReportedAlias'; Specificity = 20 }
      @{ Name = 'InstallShield 2020 R3'; ProductVersion = '26'; Year = 2020; Confidence = 'ReportedAlias'; Specificity = 20 }
    )
    '785' = @(@{ Name = 'InstallShield 2021 R1'; ProductVersion = '27'; Year = 2021; Confidence = 'OfficialBuilder'; Specificity = 20 })
    '787' = @(@{ Name = 'InstallShield 2022 R2'; ProductVersion = '28'; Year = 2022; Confidence = 'PublishedMapping'; Specificity = 20 })
    '789' = @(@{ Name = 'InstallShield 2023 R2'; ProductVersion = '29'; Year = 2023; Confidence = 'PublishedMapping'; Specificity = 20 })
    '791' = @(@{ Name = 'InstallShield 2025 R1'; ProductVersion = '31'; Year = 2025; Confidence = 'PublishedMapping'; Specificity = 20 })
    '792' = @(@{ Name = 'InstallShield 2026 R1'; ProductVersion = '32'; Year = 2026; Confidence = 'Authoritative'; Specificity = 20 })
  }

  # Product/runtime major versions are weaker evidence than an authored schema.
  # A major can span several service packs, so the resolver preserves candidates.
  Products = @{
    '3'  = @(@{ Name = 'InstallShield 3'; ProductVersion = '3'; Year = 1993 })
    '5'  = @(@{ Name = 'InstallShield 5'; ProductVersion = '5'; Year = 1997 })
    '6'  = @(@{ Name = 'InstallShield Professional 6'; ProductVersion = '6'; Year = 1999 })
    '7'  = @(@{ Name = 'InstallShield Developer 7'; ProductVersion = '7'; Year = 2001 })
    '8'  = @(@{ Name = 'InstallShield Developer 8'; ProductVersion = '8'; Year = 2002 })
    '9'  = @(@{ Name = 'InstallShield DevStudio 9'; ProductVersion = '9'; Year = 2003 })
    '10' = @(@{ Name = 'InstallShield X/10.5'; ProductVersion = '10'; Year = 2004 })
    '11' = @(
      @{ Name = 'InstallShield 11'; ProductVersion = '11'; Year = 2005; VersionPattern = '^11(?:\.0+)?$' }
      @{ Name = 'InstallShield 11.5'; ProductVersion = '11.5'; Year = 2005; VersionPattern = '^11\.5(?:0)?(?:\.|$)' }
    )
    '12' = @(@{ Name = 'InstallShield 12'; ProductVersion = '12'; Year = 2006 })
    '13' = @(@{ Name = 'InstallShield 2007'; ProductVersion = '13'; Year = 2006 })
    '14' = @(@{ Name = 'InstallShield 2008'; ProductVersion = '14'; Year = 2007 })
    '15' = @(@{ Name = 'InstallShield 2009'; ProductVersion = '15'; Year = 2008 })
    '16' = @(@{ Name = 'InstallShield 2010'; ProductVersion = '16'; Year = 2009 })
    '17' = @(@{ Name = 'InstallShield 2011'; ProductVersion = '17'; Year = 2010 })
    '18' = @(@{ Name = 'InstallShield 2012'; ProductVersion = '18'; Year = 2011 })
    '19' = @(@{ Name = 'InstallShield 2012 Spring'; ProductVersion = '19'; Year = 2012 })
    '20' = @(@{ Name = 'InstallShield 2013'; ProductVersion = '20'; Year = 2013 })
    '21' = @(@{ Name = 'InstallShield 2014'; ProductVersion = '21'; Year = 2014 })
    '22' = @(@{ Name = 'InstallShield 2015'; ProductVersion = '22'; Year = 2015 })
    '23' = @(@{ Name = 'InstallShield 2016'; ProductVersion = '23'; Year = 2016 })
    '24' = @(@{ Name = 'InstallShield 2018'; ProductVersion = '24'; Year = 2018 })
    '25' = @(
      @{ Name = 'InstallShield 2019'; ProductVersion = '25'; Year = 2019 }
      @{ Name = 'InstallShield 2019 R2'; ProductVersion = '25'; Year = 2019; Specificity = 20; ProductNamePattern = '(?i)\bInstallShield\s+2019\s+R2\b'; VersionPattern = '^(?:25\.0\.676(?:\.|$)|25\.1(?:\.|$))' }
      @{ Name = 'InstallShield 2019 R3'; ProductVersion = '25'; Year = 2019; Specificity = 20; ProductNamePattern = '(?i)\bInstallShield\s+2019\s+R3\b'; VersionPattern = '^(?:25\.0\.764(?:\.|$)|25\.2(?:\.|$))' }
    )
    '26' = @(
      @{ Name = 'InstallShield 2020'; ProductVersion = '26'; Year = 2020 }
      @{ Name = 'InstallShield 2020 R1'; ProductVersion = '26'; Year = 2020; Specificity = 20; ProductNamePattern = '(?i)\bInstallShield\s+2020\s+R1\b'; VersionPattern = '^(?:26\.0\.546(?:\.|$)|26\.0+(?:\.0+)*$)' }
    )
    '27' = @(
      @{ Name = 'InstallShield 2021'; ProductVersion = '27'; Year = 2021 }
      @{ Name = 'InstallShield 2021 R1'; ProductVersion = '27'; Year = 2021; Specificity = 20; ProductNamePattern = '(?i)\bInstallShield\s+2021\s+R1\b'; VersionPattern = '^(?:27\.0\.58(?:\.|$)|27\.0+(?:\.0+)*$)' }
    )
    '28' = @(@{ Name = 'InstallShield 2022'; ProductVersion = '28'; Year = 2022 })
    '29' = @(@{ Name = 'InstallShield 2023'; ProductVersion = '29'; Year = 2023 })
    '30' = @(@{ Name = 'InstallShield 2024'; ProductVersion = '30'; Year = 2024 })
    '31' = @(
      @{ Name = 'InstallShield 2025'; ProductVersion = '31'; Year = 2025 }
      @{ Name = 'InstallShield 2025 R1'; ProductVersion = '31'; Year = 2025; Specificity = 20; ProductNamePattern = '(?i)\bInstallShield\s+2025\s+R1\b'; VersionPattern = '^(?:31\.0\.24(?:\.|$)|31\.0+(?:\.0+)*$)' }
    )
    '32' = @(
      @{ Name = 'InstallShield 2026'; ProductVersion = '32'; Year = 2026 }
      @{ Name = 'InstallShield 2026 R1'; ProductVersion = '32'; Year = 2026; Specificity = 20; ProductNamePattern = '(?i)\bInstallShield\s+2026\s+R1\b'; VersionPattern = '^(?:32\.0\.68(?:\.|$)|32\.0+(?:\.0+)*$)' }
    )
  }
}
