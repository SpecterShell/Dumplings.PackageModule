# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# Force stop on error
$ErrorActionPreference = 'Stop'

function Get-Assembly {
  <#
  .SYNOPSIS
    Get the WebDriver.dll assembly
  #>
  [OutputType([string])]
  param ()

  if (Test-Path -Path ($Path = Join-Path $PSScriptRoot '..' 'Assets' 'WebDriver.dll')) {
    return (Get-Item -Path $Path -Force).FullName
  } else {
    throw 'The WebDriver.dll assembly could not be found'
  }
}

function Import-Assembly {
  <#
  .SYNOPSIS
    Load the WebDriver.dll assembly
  #>

  # Check if the assembly is already loaded to prevent double loading
  if (-not ([System.Management.Automation.PSTypeName]'OpenQA.Selenium.WebDriver').Type) {
    Add-Type -Path (Get-Assembly)
  }
}

Import-Assembly

#region Edge Driver
[OpenQA.Selenium.Edge.EdgeDriver]$EdgeDriver = $null
[bool]$EdgeDriverLoaded = $false

function Get-EdgeDriverExecutablePath {
  <#
  .SYNOPSIS
    Get the path of the EdgeDriver executable
  #>
  [OutputType([string])]
  param ()

  if (Test-Path -Path Env:\EDGEWEBDRIVER) {
    # https://github.com/actions/runner-images/blob/main/images/win/Windows2022-Readme.md
    if (Test-Path -Path $Env:EDGEWEBDRIVER) {
      return $Env:EDGEWEBDRIVER
    } else {
      throw 'The EDGEWEBDRIVER environment variable is set, but the path is invalid'
    }
  } elseif ($Command = Get-Command -Name 'msedgedriver.exe' -ErrorAction SilentlyContinue) {
    return $Command.Path
  } else {
    throw 'Could not find msedgedriver.exe'
  }
}

function New-EdgeDriver {
  <#
  .SYNOPSIS
    Initialize an EdgeDriver instance
  .PARAMETER Headless
    Initialize the EdgeDriver instance in headless mode
  #>
  [OutputType([OpenQA.Selenium.Edge.EdgeDriver])]
  param (
    [parameter(HelpMessage = 'Initialize the Edge Driver instance in headless mode')]
    [switch]$Headless = $false
  )

  $EdgeOptions = [OpenQA.Selenium.Edge.EdgeOptions]::new()

  # Run Edge in headless mode if specified
  if ($Headless) { $EdgeOptions.AddArgument('--headless=new') }

  # Block image content to speed up page loading and reduce resource consumption
  $EdgeOptions.AddUserProfilePreference('profile.managed_default_content_settings.images', 2)

  $EdgeDriver = [OpenQA.Selenium.Edge.EdgeDriver]::new((Get-EdgeDriverExecutablePath), $EdgeOptions)

  # Resize the window to 1920x1080 to ensure the page is not rendered in mobile layout
  $EdgeDriver.Manage().Window.Size = [System.Drawing.Size]::new(1920, 1080)

  # Block image and video URLs to speed up page loading and reduce resource consumption
  $Dict = [System.Collections.Generic.Dictionary[string, object]]::new()
  $Dict.Add('urls', @('*.jpg*', '*.jpeg*', '*.bmp*', '*.png*', '*.webp*', '*.gif*', '*.svg*', '*.mp4*', '*.webm*', '*.flv*'))
  $null = $EdgeDriver.ExecuteCdpCommand('Network.setBlockedURLs', $Dict)

  # Enable network interception
  $Dict = [System.Collections.Generic.Dictionary[string, object]]::new()
  $null = $EdgeDriver.ExecuteCdpCommand('Network.enable', $Dict)

  return $EdgeDriver
}

function Get-EdgeDriver {
  <#
  .SYNOPSIS
    Initialize and return the managed EdgeDriver instance
  #>
  [OutputType([OpenQA.Selenium.Edge.EdgeDriver])]
  param ()

  if (-not $Script:EdgeDriverLoaded) {
    $Script:EdgeDriver = New-EdgeDriver @args
    $Script:EdgeDriverLoaded = $true
  }
  return $Script:EdgeDriver
}

function Stop-EdgeDriver {
  <#
  .SYNOPSIS
    Stop and dispose the managed EdgeDriver instance
  #>

  if ($Script:EdgeDriverLoaded) {
    $Script:EdgeDriver.Dispose()
    $Script:EdgeDriverLoaded = $false
  }
}
#endregion

#region FirefoxDriver
[OpenQA.Selenium.Firefox.FirefoxDriver]$FirefoxDriver = $null
[bool]$FirefoxDriverLoaded = $false

function Get-FirefoxDriverExecutablePath {
  <#
  .SYNOPSIS
    Get the path of the FirefoxDriver executable
  #>
  [OutputType([string])]
  param ()

  if (Test-Path -Path Env:\GECKOWEBDRIVER) {
    # https://github.com/actions/runner-images/blob/main/images/win/Windows2022-Readme.md
    if (Test-Path -Path $Env:GECKOWEBDRIVER) {
      return $Env:GECKOWEBDRIVER
    } else {
      throw 'The GECKOWEBDRIVER environment variable is set, but the path is invalid'
    }
  } elseif ($Command = Get-Command -Name 'geckodriver.exe' -ErrorAction SilentlyContinue) {
    return $Command.Path
  } else {
    throw 'Could not find msedgedriver.exe'
  }
}

function New-FirefoxDriver {
  <#
  .SYNOPSIS
    Initialize an FirefoxDriver instance
  .PARAMETER Headless
    Initialize the FirefoxDriver instance in headless mode
  #>
  [OutputType([OpenQA.Selenium.Firefox.FirefoxDriver])]
  param (
    [parameter(HelpMessage = 'Initialize the FirefoxDriver instance in headless mode')]
    [switch]$Headless
  )

  $FirefoxOptions = [OpenQA.Selenium.Firefox.FirefoxOptions]::new()

  # Run Firefox in headless mode if specified
  if ($Headless) { $FirefoxOptions.AddArgument('--headless') }

  # Block image content to speed up page loading and reduce resource consumption
  $FirefoxOptions.SetPreference('permissions.default.image', 2)

  $FirefoxDriver = [OpenQA.Selenium.Firefox.FirefoxDriver]::new((Get-FirefoxDriverExecutablePath), $FirefoxOptions)

  # Resize the window to 1920x1080 to ensure the page is not rendered in mobile layout
  $FirefoxDriver.Manage().Window.Size = [System.Drawing.Size]::new(1920, 1080)

  return $FirefoxDriver
}

function Get-FirefoxDriver {
  <#
  .SYNOPSIS
    Initialize and return the managed FirefoxDriver instance
  #>
  [OutputType([OpenQA.Selenium.Firefox.FirefoxDriver])]
  param ()

  if (-not $Script:FirefoxDriverLoaded) {
    $Script:FirefoxDriver = New-FirefoxDriver @args
    $Script:FirefoxDriverLoaded = $true
  }
  return $Script:FirefoxDriver
}

function Stop-FirefoxDriver {
  <#
  .SYNOPSIS
    Stop and dispose the managed FirefoxDriver instance
  #>

  if ($Script:FirefoxDriverLoaded) {
    $Script:FirefoxDriver.Dispose()
    $Script:FirefoxDriverLoaded = $false
  }
}
#endregion

# Stop drivers when the module is unloading
$ExecutionContext.SessionState.Module.OnRemove += {
  Stop-EdgeDriver -ErrorAction Continue
  Stop-FirefoxDriver -ErrorAction Continue
}

Export-ModuleMember -Function New-EdgeDriver, Get-EdgeDriver, Stop-EdgeDriver, New-FirefoxDriver, Get-FirefoxDriver, Stop-FirefoxDriver
