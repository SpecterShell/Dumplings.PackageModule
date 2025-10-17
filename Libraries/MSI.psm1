# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# Force stop on error
$ErrorActionPreference = 'Stop'

function Import-Assembly {
  <#
  .SYNOPSIS
    Load the Microsoft.Deployment.WindowsInstaller.Package.dll assembly
  #>

  # Check if the assembly is already loaded to prevent double loading
  if (-not ([System.Management.Automation.PSTypeName]'Microsoft.Deployment.WindowsInstaller').Type) {
    if (Test-Path -Path ($Path = Join-Path $PSScriptRoot '..' 'Assets' 'Microsoft.Deployment.WindowsInstaller.dll')) {
      Add-Type -Path $Path
    } else {
      throw 'The Microsoft.Deployment.WindowsInstaller.dll assembly could not be found'
    }
  }
  if (-not ([System.Management.Automation.PSTypeName]'Microsoft.Deployment.WindowsInstaller.Package').Type) {
    if (Test-Path -Path ($Path = Join-Path $PSScriptRoot '..' 'Assets' 'Microsoft.Deployment.WindowsInstaller.Package.dll')) {
      Add-Type -Path $Path
    } else {
      throw 'The Microsoft.Deployment.WindowsInstaller.Package.dll assembly could not be found'
    }
  }
}

Import-Assembly

function Expand-Msp {
  <#
  .SYNOPSIS
    Extract Transforms from the MSP file
  .PARAMETER Path
    The path to the MSP file
  .PARAMETER Database
    The patch package database object
  #>
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the MSP file')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Database', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The patch package database object')]
    [Microsoft.Deployment.WindowsInstaller.Package.PatchPackage]$Database
  )

  process {
    $Database = switch ($PSCmdlet.ParameterSetName) {
      'Path' { [Microsoft.Deployment.WindowsInstaller.Package.PatchPackage]::new((Convert-Path -Path $Path)) }
      'Database' { $Database }
      default { throw 'Invalid parameter set.' }
    }

    try {
      $Transforms = $Database.GetTransforms()
      foreach ($Transform in $Transforms) {
        $File = New-TempFile
        $Database.ExtractTransform($Transform, $File)
        Write-Output -InputObject $File
      }
    } finally {
      switch ($PSCmdlet.ParameterSetName) {
        'Path' { $Database.Close() }
        'Database' { } # Do not close user-provided stream
        default { throw 'Invalid parameter set.' }
      }
    }
  }
}

function Read-MsiProperty {
  <#
  .SYNOPSIS
    Query a value from the MSI file using SQL-like query
  .PARAMETER Path
    The path to the MSI file
  .PARAMETER PatchFile
    Indicate the file is a patch file
  .PARAMETER Database
    The database object
  .PARAMETER TransformPath
    The path to the transform files to be applied
  .PARAMETER PatchPath
    The path to the patch files to be applied
  .PARAMETER Query
    The SQL-like query
  .PARAMETER Field
    The name or number of the field to extract
  #>
  [OutputType([string])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the MSI file')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Path', HelpMessage = 'Indicate the file is a patch file')]
    [switch]$PatchFile,

    [Parameter(ParameterSetName = 'Database', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The database object')]
    [Microsoft.Deployment.WindowsInstaller.Database]$Database,

    [Parameter(HelpMessage = 'The path to the transform file to be applied')]
    [AllowNull()]
    [string]$TransformPath,

    [Parameter(HelpMessage = 'The path to the patch file to be applied')]
    [AllowNull()]
    [string]$PatchPath,

    [Parameter(Mandatory, HelpMessage = 'The SQL-like query')]
    [string]$Query,

    [Parameter(HelpMessage = 'The name or number of the field to extract')]
    $Field = 1
  )

  process {
    $Database = switch ($PSCmdlet.ParameterSetName) {
      'Path' {
        $Path = Convert-Path -Path $Path
        $PatchFile ? [Microsoft.Deployment.WindowsInstaller.Package.PatchPackage]::new($Path) : [Microsoft.Deployment.WindowsInstaller.Package.InstallPackage]::new($Path, 'ReadOnly')
      }
      'Database' { $Database }
      default { throw 'Invalid parameter set.' }
    }

    # Apply the transform if specified
    if ($TransformPath) {
      $TransformPath = Convert-Path -Path $TransformPath
      $Database.ApplyTransform($TransformPath)
    }

    # Apply the patch if specified
    if ($PatchPath) {
      $PatchPath = Convert-Path -Path $PatchPath
      $TransformPaths = Expand-Msp -Path $PatchPath
      foreach ($TransformPath in $TransformPaths) {
        $Database.ApplyTransform($TransformPath)
        Remove-Item -Path $TransformPath -Force -ErrorAction SilentlyContinue
      }
    }

    try {
      $View = $Database.OpenView($Query)
      $View.Execute()
      $Record = $View.Fetch()
      $Record.GetString($Field)
    } finally {
      $Record.Close()
      $View.Close()
      switch ($PSCmdlet.ParameterSetName) {
        'Path' { $Database.Close() }
        'Database' { } # Do not close user-provided stream
        default { throw 'Invalid parameter set.' }
      }
    }
  }
}

function Read-ProductVersionFromMsi {
  <#
  .SYNOPSIS
    Read the ProductVersion property value from the MSI file
  .PARAMETER Path
    The path to the MSI file
  .PARAMETER TransformPath
    The path to the transform file to be applied
  .PARAMETER PatchPath
    The path to the patch files to be applied
  .PARAMETER Database
    The database object
  #>
  [OutputType([string])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the MSI file')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Database', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The database object')]
    [Microsoft.Deployment.WindowsInstaller.Database]$Database,

    [Parameter(HelpMessage = 'The path to the transform file to be applied')]
    [string]$TransformPath,

    [Parameter(HelpMessage = 'The path to the patch file to be applied')]
    [AllowNull()]
    [string]$PatchPath
  )

  process {
    Read-MsiProperty @PSBoundParameters -Query "SELECT Value FROM Property WHERE Property='ProductVersion'"
  }
}

function Read-ProductCodeFromMsi {
  <#
  .SYNOPSIS
    Read the ProductCode property value from the MSI file
  .PARAMETER Path
    The path to the MSI file
  .PARAMETER TransformPath
    The path to the transform files to be applied
  .PARAMETER PatchPath
    The path to the patch files to be applied
  .PARAMETER Database
    The database object
  #>
  [OutputType([string])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the MSI file')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Database', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The database object')]
    [Microsoft.Deployment.WindowsInstaller.Database]$Database,

    [Parameter(HelpMessage = 'The path to the transform file to be applied')]
    [string]$TransformPath,

    [Parameter(HelpMessage = 'The path to the patch file to be applied')]
    [AllowNull()]
    [string]$PatchPath
  )

  process {
    Read-MsiProperty @PSBoundParameters -Query "SELECT Value FROM Property WHERE Property='ProductCode'"
  }
}

function Read-UpgradeCodeFromMsi {
  <#
  .SYNOPSIS
    Read the UpgradeCode property value from the MSI file
  .PARAMETER Path
    The path to the MSI file
  .PARAMETER TransformPath
    The path to the transform files to be applied
  .PARAMETER PatchPath
    The path to the patch files to be applied
  .PARAMETER Database
    The database object
  #>
  [OutputType([string])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the MSI file')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Database', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The database object')]
    [Microsoft.Deployment.WindowsInstaller.Database]$Database,

    [Parameter(HelpMessage = 'The path to the transform file to be applied')]
    [string]$TransformPath,

    [Parameter(HelpMessage = 'The path to the patch file to be applied')]
    [AllowNull()]
    [string]$PatchPath
  )

  process {
    Read-MsiProperty @PSBoundParameters -Query "SELECT Value FROM Property WHERE Property='UpgradeCode'"
  }
}

function Read-ProductNameFromMsi {
  <#
  .SYNOPSIS
    Read the ProductName property value from the MSI file
  .PARAMETER Path
    The path to the MSI file
  .PARAMETER TransformPath
    The path to the transform files to be applied
  .PARAMETER PatchPath
    The path to the patch files to be applied
  .PARAMETER Database
    The database object
  #>
  [OutputType([string])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the MSI file')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Database', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The database object')]
    [Microsoft.Deployment.WindowsInstaller.Database]$Database,

    [Parameter(HelpMessage = 'The path to the transform file to be applied')]
    [string]$TransformPath,

    [Parameter(HelpMessage = 'The path to the patch file to be applied')]
    [AllowNull()]
    [string]$PatchPath
  )

  process {
    Read-MsiProperty @PSBoundParameters -Query "SELECT Value FROM Property WHERE Property='ProductName'"
  }
}

function Read-MsiSummaryInfo {
  <#
  .SYNOPSIS
    Read the summary table of the MSI file
  .PARAMETER Path
    The path to the MSI file
  .PARAMETER PatchFile
    Indicate the file is a patch file
  .PARAMETER Database
    The database object
  #>
  [OutputType([Microsoft.Deployment.WindowsInstaller.SummaryInfo])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the MSI file')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Path', HelpMessage = 'Indicate the file is a patch file')]
    [switch]$PatchFile,

    [Parameter(ParameterSetName = 'Database', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The database object')]
    [Microsoft.Deployment.WindowsInstaller.Database]$Database
  )

  process {
    $Database = switch ($PSCmdlet.ParameterSetName) {
      'Path' {
        $Path = Convert-Path -Path $Path
        $PatchFile ? [Microsoft.Deployment.WindowsInstaller.Package.PatchPackage]::new($Path) : [Microsoft.Deployment.WindowsInstaller.Package.InstallPackage]::new($Path, 'ReadOnly')
      }
      'Database' { $Database }
      default { throw 'Invalid parameter set.' }
    }

    $Database.SummaryInfo

    switch ($PSCmdlet.ParameterSetName) {
      'Path' { $Database.Close() }
      'Database' { } # Do not close user-provided stream
      default { throw 'Invalid parameter set.' }
    }
  }
}
