Start-Transcript -Path PSO2NA_PSLOG.log

function Failure {
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory=$true, ValueFromPipeline=$true)]
		[ValidateNotNullOrEmpty()]
		$Error
	)
	$global:result = $Error.Exception.Response.GetResponseStream()
	$global:reader = New-Object System.IO.StreamReader($global:result)
	$global:responseBody = $global:reader.ReadToEnd();
	"Status: A system exception was caught."
	$global:responsebody
	Stop-Transcript
	$null = $global:Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	#exit 254
}

"Checking Windows version..."
$WinVer = [Version](Get-CimInstance Win32_OperatingSystem).version
if ($WinVer.Major -lt 10)
{
	"PSO2NA is only supported on Windows 10. Press any key to exit."
	Stop-Transcript
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	exit 1
}
ElseIf ($WinVer.Build -lt 18362)
{
	"PSO2NA is only supported on Windows 10 (1903+). You need to update your Windows. Press any key to exit."
	Stop-Transcript
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	exit 2
}
"[OK]"
""
""
""
""

Write-Host -NoNewline "Checking for Administrator Role..."
# Get the ID and security principal of the current user account
$myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal=New-Object System.Security.Principal.WindowsPrincipal($myWindowsID)
# Get the security principal for the Administrator role
$adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator
if (-Not $myWindowsPrincipal.IsInRole($adminRole))
{
	"You need to run this PowerShell script using an Administrator account (or with an admin powershell)."
	Stop-Transcript
	Start-Process powershell.exe "-NoLogo","-NoProfile","-ExecutionPolicy","ByPass","-File",('"{0}"' -f $MyInvocation.MyCommand.Path) -Verb RunAs
	exit
	#$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	#exit 3
}
"[OK]"
""
""
""
""

Write-Host -NoNewline "Checking for Developer Mode..."
$DevMode = $true
$RegistryKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock"
if (Test-Path -Path $RegistryKeyPath)
{
	$AppModelUnlock = Get-ItemProperty -Path $RegistryKeyPath
	if (Get-Member -InputObject $AppModelUnlock -Name AllowDevelopmentWithoutDevLicense)
	{
		$RegData = $AppModelUnlock | Select -ExpandProperty AllowDevelopmentWithoutDevLicense
		If ($RegData -eq 1)
		{
			$DevMode = $true
		}
	}
}
If ($DevMode -EQ $false)
{
	"You need to enable Developer mode. Please see https://www.howtogeek.com/292914/what-is-developer-mode-in-windows-10/"
	"Press any key to exit."
	Stop-Transcript
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	exit 4
}
"[OK]"

"Checking PSO2 Tweaker settings..."
$JSONPath = $null
$JSONData = $null
$PSO2NABinFolder = $null
$PSO2NAFolder = $null
$JSONPath = [System.Environment]::ExpandEnvironmentVariables("%APPDATA%\PSO2 Tweaker\settings.json")
If ($JSONPath)
{
	$JSONData = Get-Content -Path $JSONPath -Verbose
}
Else
{
	"Cannot find %APPDATA% folder - Is your Windows properly set up? Press any key to exit."
	Stop-Transcript
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	exit 5
}
If ($JSONData)
{
	$JSONObj = $JSONData | ConvertFrom-Json -Verbose
}
Else
{
	"Cannot read Tweaker Setting JSON - Did you set up the Tweaker yet? Press any key to exit."
	Stop-Transcript
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	exit 6
}
If ($JSONObj)
{
	$PSO2NABinFolder = $JSONObj | Select-Object -ExpandProperty PSO2NABinFolder
}
Else
{
	"Can not convert JSON into PowerShell Object. This shouldn't happen! Press any key to exit."
	Stop-Transcript
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	exit 7
}
If (-Not (Test-Path -Path $PSO2NABinFolder -PathType Container))
{
	"The $($PSO2NABinFolder) folder does not exist. Please check your PSO2 Tweaker settings."
	"Press any key to exit."
	Stop-Transcript
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	exit 16
}
ElseIf ($PSO2NABinFolder)
{
`
	$PSO2NAFolder = $PSO2NABinFolder | Split-Path
}
Else
{
	"Cannot find a PSO2NABinFolder setting - Did you set up PSO2NA through the Tweaker yet? If not, do it. Press any key to exit."
	Stop-Transcript
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	exit 8
}
If (-Not (Test-Path -Path $PSO2NAFolder -PathType Container))
{
	"The $($PSO2NAFolder) folder does not exist. Please check your PSO2 Tweaker settings."
	"Press any key to exit."
	Stop-Transcript
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	exit 17
}
ElseIf ($PSO2NAFolder)
{
	$LeafPath = $PSO2NAFolder | Split-Path -Leaf
	If ($LeafPath -eq "ModifiableWindowsApps")
	{
		"You cannot use the Windows Store copy of PSO2 with this script. Go back to http://arks-layer.com/setup.html and do a fresh install."
		"Press any key to exit."
		Stop-Transcript
		$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
		exit 10
	}
	"Moving instance to $($PSO2NAFolder) Folder"
	Set-Location -Path $PSO2NAFolder -Verbose
}
Else
{
	"Cannot get PSO2NA Folder - Did you follow the instructions? Press any key to exit."
	Stop-Transcript
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	exit 9
}

"Checking if Volume is formated as NTFS..."
$PSO2Vol = @()
$PSO2Vol += Get-Volume -FilePath $PSO2NAFolder | Where-Object -Property FileSystemType -EQ NTFS
If ($PSO2Vol.Count -eq 0)
{
	"Your PSO2NA installation is not on a NTFS drive, please move the PSO2NA installation elsewhere."
	Stop-Transcript
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	exit 15
}


"Checking for appxmanifest.xml..."
$Files = @()
$Files += Get-ChildItem | Where-Object -Property Name -EQ "appxmanifest.xml"
If ($Files.Count -ne 1)
{
	"Cannot find appxmanifest.xml file - Go back to http://arks-layer.com/setup.html and make sure you follow ALL the steps and do a fresh new install."
	Stop-Transcript
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	exit 11
}

$OldPackages = @()
"Looking for a PSO2NA Windows Store installation..."
$OldPackages = Get-AppxPackage -Name "100B7A24.oxyna" -AllUsers | Where-Object -Property SignatureKind -EQ "Store"
If ($OldPackages.Count -gt 0)
{
	"Unregistering the old PSO2 from the Windows Store... (This may take a while, don't panic!)"
	$OldPackages | Remove-AppxPackage -AllUsers -Verbose
}
Else
{
	"No Windows Store PSO2NA installation found. This is OK!"
}

"Checking if we need to install the requirments..."
$NewPackages = @()
$DirectXRuntime = @()
$DirectXRuntime_User = @()
$DirectXRuntime_Good = @()
$DirectXRuntime += Get-AppxPackage -Name "Microsoft.DirectXRuntime" -PackageTypeFilter Framework -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" -AllUsers | Where-Object -Property Architecture -EQ "X64"
$DirectXRuntime_User += Get-AppxPackage -Name "Microsoft.DirectXRuntime" -PackageTypeFilter Framework -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" | Where-Object -Property Architecture -EQ "X64"
$VersionCheck = [Version]"9.29.952.0"
$DirectXRuntime_Good += ([Version]$DirectXRuntime.Version -ge $VersionCheck) -eq $true
$VCLibs = @()
$VCLibs_User = @()
$VCLibs_Good = @()
$VersionCheck = [Version]"14.0.24217.0"
$VCLibs += Get-AppxPackage -Name "Microsoft.VCLibs.140.00.UWPDesktop" -PackageTypeFilter Framework -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" -AllUsers | Where-Object -Property Architecture -EQ "X64"
$DirectXRuntime_User += Get-AppxPackage -Name "Microsoft.VCLibs.140.00.UWPDesktop" -PackageTypeFilter Framework -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" | Where-Object -Property Architecture -EQ "X64"
$VCLibs_Good += ([Version]$VCLibs.Version -ge $VersionCheck) -eq $true

If ($DirectXRuntime_Good.Count -eq 0)
{
	"Downloading DirectX Runtime requirement... (56MB)"
	$URI = "https://download.microsoft.com/download/c/c/2/cc291a37-2ebd-4ac2-ba5f-4c9124733bf1/UAPSignedBinary_Microsoft.DirectX.x64.appx"
	$FileD = "UAPSignedBinary_Microsoft.DirectX.x64.appx"
	Try
	{
		Invoke-WebRequest -Uri $URI -OutFile $FileD  -Verbose -ErrorAction:Stop
	}
	Catch
	{
		$_ | Failure
		exit 12
	}

	"Adding DirectX Runtime requirement to TODO list..."
	$NewPackages += $FilesD
}
ElseIf ($DirectXRuntime_User.Count -eq 0)
{
    $DirectXRuntime | Add-AppxPackage -Verbose -Update
}

If ($VCLibs_Good.Count -eq 0)
{
	"Downloading VCLibs requirement... (7MB)"
	$URI = "https://github.com/Arks-Layer/PSO2WinstoreFix/blob/master/Microsoft.VCLibs.x64.14.00.Desktop.appx?raw=true"
	$FileD = "Microsoft.VCLibs.x64.14.00.Desktop.appx"
	Try
	{
		Invoke-WebRequest -Uri $URI -OutFile $FileD -Verbose -ErrorAction:Stop
	}
	Catch
	{
		$_ | Failure
		exit 13
	}
	"Adding VCLibs requirement to TODO list..."
	$NewPackages += $FilesD
}
ElseIf ($VCLibs_User.Count -eq 0)
{
    $VCLibs | Add-AppxPackage -Verbose -Update
}
If ($NewPackages.Count -gt 0 -and $false)
{
	"Installing requirements... If you see an error about it not being installed becuase of a higher version, that's OK!"
	$NewPackages | Add-AppxPackage -Verbose
	$NewPackages | Remote-Item -Verbose
}

"Registering our new shiny PSO2 with the Windows Store... (This may take a while, don't panic!)"
Try
{
    If ($NewPackages.Count -gt 0)
    {
	    Add-AppxPackage -Register .\appxmanifest.xml -Verbose -ErrorAction Stop -DependencyPath $NewPackages
    }
    Else
    {
        Add-AppxPackage -Register .\appxmanifest.xml -Verbose -ErrorAction Stop
    }
}
Catch
{
	$_ | Failure
	exit 14
}
If ($NewPackages.Count -gt 0)
{
	"Ok, Cleaning up Dependency downloads"
	$NewPackages | Remote-Item -Verbose
}

"Checking needed Apps for runtime"
$GamingServices = @()
$GamingServices += Get-AppxPackage -Name "Microsoft.GamingServices" -PackageTypeFilter Bundle -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
If ($GamingServices.Count -eq 0)
{
	"You Need to Install the Gaming Service App"
	[Diagnostics.Process]::Start("ms-windows-store://pdp?productid=9mwpm2cqnlhn")
}

Stop-Transcript
Write-Host -NoNewLine 'Fixes complete! You can now close this window by pressing any key.';
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
