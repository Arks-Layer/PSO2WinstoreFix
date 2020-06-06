$ErrorActionPreference = "Stop"
Try
{
	Do
	{
		Stop-Transcript
	} While ($true)
}
Catch {}
If ($PSScriptRoot -ne $null)
{
	$ScriptLog = Join-Path -Path $PSScriptRoot -ChildPath "PSO2NA_PSLOG.log"
}
Else
{
	$ScriptLog = Join-Path -Path "." -ChildPath "PSO2NA_PSLOG.log"
}
Start-Transcript -Path $ScriptLog
"Version 2020_06_05_2238" #21
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
Elseif ([System.Environment]::Is64BitOperatingSystem -eq $false)
{
	"PSO2NA is only supported on 64-bit OS. You need to reinstall your Windows OS if you CPU is 64-bit. Press any key to exit."
	Stop-Transcript
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	exit 21
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
$DevMode = $false
$RegistryKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock"
if (Test-Path -Path $RegistryKeyPath)
{
	$AppModelUnlock = Get-ItemProperty -Path $RegistryKeyPath
	if ($AppModelUnlock -ne $null -and ($AppModelUnlock | Get-Member -Name AllowDevelopmentWithoutDevLicense) -ne $null)
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

$SystemVolume = Get-AppxVolume | Where-Object -Property IsSystemVolume -eq $true

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
If ($PSO2NABinFolder -eq $null)
{
	"Old version of the Tweaker config file found, please update Tweaker"
	"Press any key to exit."
	Stop-Transcript
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	exit 20
}
ElseIf (-Not (Test-Path -Path $PSO2NABinFolder -PathType Container))
{
	"The $($PSO2NABinFolder) folder does not exist. Please check your PSO2 Tweaker settings."
	"Press any key to exit."
	Stop-Transcript
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	exit 16
}
ElseIf ($PSO2NABinFolder)
{
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
Try
{
	$BrokenNTFS = $true
	$PSO2Vol += Get-Volume -FilePath $PSO2NAFolder | Where-Object -Property FileSystemType -EQ NTFS
	$BrokenNTFS = $false
}
Catch
{
	#Stop-Transcript
	#$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	#exit 19
}

If ($BrokenNTFS -eq $true)
{
	"Your system's WMI database is broken, please repair it"
}
ElseIf ($PSO2Vol.Count -eq 0)
{
	"Your PSO2NA installation is not on a NTFS drive, please move the PSO2NA installation elsewhere."
	#Stop-Transcript
	#$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	#exit 15
}
Else
{
	"Your PSO2NA installation is on a NTFS drive, Wonderful"
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
	"If this is taking more then 30 minutes, you may have to reboot"
	$OldPackages | Remove-AppxPackage -AllUsers -Verbose
}
Else
{
	"No Windows Store PSO2NA installation found. This is OK!"
}

"Checking if we need to install the requirments..."
$NewPackages = @()

$DirectXRuntime_All = @()
$DirectXRuntime_User = @()
$DirectXRuntime_Good_All = @()
$DirectXRuntime_Good_User = @()

$DirectXRuntime_All += Get-AppxPackage -Name "Microsoft.DirectXRuntime" -PackageTypeFilter Framework -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" -AllUsers | Where-Object -Property Architecture -EQ "X64"
$DirectXRuntime_User += Get-AppxPackage -Name "Microsoft.DirectXRuntime" -PackageTypeFilter Framework -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" | Where-Object -Property Architecture -EQ "X64"
$VersionCheck = [Version]"9.29.952.0"
$DirectXRuntime_Good_All += $DirectXRuntime_All | Where-Object -FilterScript {[Version]$_.Version -ge $VersionCheck}
$DirectXRuntime_Good_User += $DirectXRuntime_User | Where-Object -FilterScript {[Version]$_.Version -ge $VersionCheck}

$VCLibs_All = @()
$VCLibs_User = @()
$VCLibs_Good_All = @()
$VCLibs_Good_User = @()

$VCLibs_All += Get-AppxPackage -Name "Microsoft.VCLibs.140.00.UWPDesktop" -PackageTypeFilter Framework -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" -AllUsers | Where-Object -Property Architecture -EQ "X64"
$VCLibs_User += Get-AppxPackage -Name "Microsoft.VCLibs.140.00.UWPDesktop" -PackageTypeFilter Framework -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" | Where-Object -Property Architecture -EQ "X64"
$VersionCheck = [Version]"14.0.24217.0"
$VCLibs_Good_All += $VCLibs_All | Where-Object -FilterScript {[Version]$_.Version -ge $VersionCheck}
$VCLibs_Good_User += $VCLibs_User | Where-Object -FilterScript {[Version]$_.Version -ge $VersionCheck}

if ($DirectXRuntime_Good_All.Count -gt 0 -and $DirectXRuntime_Good_User.Count -eq 0)
{
	"System already have a good copy of DirectX, trying to install the user profile"
	$NewPackages += $DirectXRuntime_Good_All | Sort-Object -Property Version | Select-Object -First 1
}
ElseIf ($DirectXRuntime_Good_User.Count -eq 0)
{
	"Downloading DirectX Runtime requirement... (56MB)"
	$URI = "https://download.microsoft.com/download/c/c/2/cc291a37-2ebd-4ac2-ba5f-4c9124733bf1/UAPSignedBinary_Microsoft.DirectX.x64.appx"
	$FileD = "UAPSignedBinary_Microsoft.DirectX.x64.appx"
	Try
	{
		If (-Not (Test-Path -Path $FileD -PathType Leaf))
		{
			Invoke-WebRequest -Uri $URI -OutFile $FileD  -Verbose
		}
	}
	Catch
	{
		$_ | Failure
		exit 12
	}

	"Adding DirectX Runtime requirement to TODO list..."
	$NewPackages += Resolve-Path -Path $FileD
}

If ($VCLibs_Good_All.Count -gt 0 -And $VCLibs_Good_User.Count -eq 0 )
{
	"System already have a good copy of VCLibs, trying to install the user profile"
	$NewPackages += $VCLibs_Good_All | Sort-Object -Property Version | Select-Object -First 1
}
Elseif ($VCLibs_Good_User.Count -eq 0)
{
	"Downloading VCLibs requirement... (7MB)"
	$URI = "https://github.com/Arks-Layer/PSO2WinstoreFix/blob/master/Microsoft.VCLibs.x64.14.00.Desktop.appx?raw=true"
	$FileD = "Microsoft.VCLibs.x64.14.00.Desktop.appx"
	Try
	{
		If (-Not (Test-Path -Path $FileD -PathType Leaf))
		{
			Invoke-WebRequest -Uri $URI -OutFile $FileD  -Verbose
		}
	}
	Catch
	{
		$_ | Failure
		exit 13
	}
	"Adding VCLibs requirement to TODO list..."
	$NewPackages += Resolve-Path -Path $FileD
}

If ($NewPackages.Count -gt 0)
{
	"Installing requirements... If you see an error about it not being installed becuase of a higher version, that's OK!"
	$NewPackages | Add-AppxPackage -Verbose -Volume $SystemVolume -ErrorAction Continue
	#$NewPackages | Remove-Item -Verbose
}

$PSO2Packages = @()
$PSO2Packages_Good = @()
$PSO2Packages_Bad = @()
$EmptyFiles = Get-ChildItem -Path $PSO2NABinFolder | Where-Object Length -eq 0
$PSO2Packages += Get-AppxPackage -Name "100B7A24.oxyna" -AllUsers | Where-Object -Property SignatureKind -EQ "None"
$PSO2Packages_Good += $PSO2Packages | Where-Object InstallLocation -eq $PSO2NAFolder  | Where-Object Status -EQ "Ok"
$PSO2Packages_Bad += $PSO2Packages | Where-Object InstallLocation -ne $PSO2NAFolder
$PSO2Packages_Bad += $PSO2Packages | Where-Object Status -ne "Ok"

$XBOXURI = Test-Path -Path "Registry::HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\windows.protocol\ms-xbl-78a72674" -PathType Container
$ForceReinstall = $false
If ($XBOXURI -eq $false)
{
	$ForceReinstall = $true
}

If ($ForceReinstall)
{
	"Bad Install found, forcing reinstalling PSO2"
	Get-AppxPackage -Name "100B7A24.oxyna" -AllUsers | Remove-AppxPackage -Verbose -AllUsers
}
ElseIf ($PSO2Packages_Bad.Count -gt 0)
{
	"Found a old Custom PSO2 Install, removing it"
	$PSO2Packages_Bad | Sort-Object -Unique | Remove-AppxPackage -Verbose -AllUsers
}

If ($EmptyFiles.Count -gt 0)
{
	$JSONObj.PSO2NARemoteVersion = 0
	$JSONObj | ConvertTo-Json | Out-File -FilePath $JSONPath
	"Bad PSO2 files found, Please run a Full File Check in Tweaker"
}
ElseIf ($PSO2Packages_Good.Count -eq 0 -or $ForceReinstall -eq $true) #Try
{
	"Registering our new shiny PSO2 with the Windows Store... (This may take a while, don't panic!)"
	If ($NewPackages.Count -gt 0 -and $false)
	{
		Add-AppxPackage -Register .\appxmanifest.xml -Verbose -DependencyPath $PSO2NAFolder
	}
	Else
	{
		Add-AppxPackage -Register .\appxmanifest.xml -Verbose -ErrorAction Continue
	}
}
Else
{
	"There already a custom PSO2 install"
}
If ($False) #Catch
{
	$_ | Failure
	exit 14
}
If ($NewPackages.Count -gt 0)
{
	#$NewPackages | Remove-Item -Verbose
}

"Checking needed GamingService App for runtime"
$GamingServices_User = @()
$GamingServices_All = @()
$GamingServices_Good_User = @()
$GamingServices_Good_All = @()
$GamingServices_User += Get-AppxPackage -Name "Microsoft.GamingServices" -PackageTypeFilter Bundle -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
$GamingServices_All += Get-AppxPackage -Name "Microsoft.GamingServices" -PackageTypeFilter Bundle -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" -AllUsers
$VersionCheck = [Version]"2.41.10001.0"
$GamingServices_Good_User += $GamingServices_User | Where-Object -FilterScript {[Version]$_.Version -ge $VersionCheck}
$GamingServices_Good_All += $GamingServices_All | Where-Object -FilterScript {[Version]$_.Version -ge $VersionCheck}

Try
{
	$ForceReinstall = $true
	Get-Service | Where-Object Name -In ("GamingServices","GamingServicesNet") | Stop-Service
	$ForceReinstall = $false
}
Catch
{
	"REINSTALL NEEDED, a Reboot may be needed to be done"
}
If ($GamingServices_Good_All.Count -gt 0 -and $GamingServices_Good_User.Count -eq 0)
{
	$GamingServices_Good_All | Sort-Object -Property Version | Select-Object -First 1 | Add-AppxPackage -Verbose -ErrorAction Continue
}
If ($GamingServices_Good.Count -eq 0 -or $ForceReinstall -eq $true)
{
	"Downloading GamingService App... (10MB)"
	$URI = "https://github.com/Arks-Layer/PSO2WinstoreFix/blob/master/Microsoft.GamingServices.x64.2.41.10001.0.appx?raw=true"
	$FileD = "Microsoft.GamingServices.x64.2.41.10001.0.appx"
	Try
	{
		If (-Not (Test-Path -Path $FileD -PathType Leaf))
		{
			Invoke-WebRequest -Uri $URI -OutFile $FileD  -Verbose
		}
	}
	Catch
	{
		$_ | Failure
		exit 18
	}
	If ($ForceReinstall -eq $true)
	{
		"Removing GamingService App"
		$GamingServices_All | Remove-AppxPackage -AllUsers
	}
	"Installing GamingService App"
	Resolve-Path -Path $FileD | Add-AppxPackage -Verbose -ForceApplicationShutdown -ForceUpdateFromAnyVersion -Volume $SystemVolume
	#Resolve-Path -Path $FileD | Remove-Item -Verbose
}
"Please making sure to install the GamingService systemwide"
[Diagnostics.Process]::Start("ms-windows-store://pdp?productid=9mwpm2cqnlhn")

"Stopping the XBox Live Auth Manager Service, this may fail"
Get-Service -Name "XblAuthManager" | Stop-Service
$XBOXIP = Get-AppxPackage -Name "Microsoft.XboxIdentityProvider" -PackageTypeFilter Main -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" -Verbose

If ($XBOXIP -ne $null)
{
	"Looking for the XBOX Identify Provider folder to wipe"
	$PackageF = Join-Path -Path $env:LOCALAPPDATA -ChildPath "Packages" -Verbose
	$XBOXIPFN = $XBOXIP.PackageFamilyName
	$XBOXIPF = Join-Path -Path $PackageF -ChildPath $XBOXIPFN  -Verbose
	$XBOXTBF = Join-Path $XBOXIPF -ChildPath "AC\TokenBroker" -Verbose
	If (Test-Path -Path $XBOXTBF -PathType Container)
	{
		Get-ChildItem $XBOXTBF | Remove-Item -Force -Recurse -ErrorAction Continue
	}
}
Else
{
	"Look like XBOX Identify Provider had been uninstalled, please get it back"
	[Diagnostics.Process]::Start("ms-windows-store://pdp?productid=9wzdncrd1hkw")
}

"Now Double checking the custom PSO2 install"
$CustomPSO2 = @()
$CustomPSO2 += Get-AppxPackage -Name "100B7A24.oxyna" | Where-Object IsDevelopmentMode -eq $true | Where-Object Status -EQ "Ok"
If ($CustomPSO2.Count -eq 0)
{
	 "Can not find custom PSO2 Installtion"
}
ElseIf ($CustomPSO2.Count -eq 1)
{
	"Good, only found one custom PSO2 installs"
}
Else
{
	"Dude? why are there $($CustomPSO2) custom PSO2 installs"
}

Stop-Transcript
Write-Host -NoNewLine 'Script complete! You can now close this window by pressing any key.';
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
