Param(
	[Bool]$ForceReinstall = $false
)

#f there an unhandled error, just stop
If ($host.name -ne 'Windows Powershell ISE Host' -and $false)
{
	$ErrorActionPreference = "Continue"
}
Else
{
	$ErrorActionPreference = "Stop"
}
#Kill all logging
Try
{
	Do
	{
		Stop-Transcript
	} While ($true)
}
Catch {}
#Find the script's folder and add "PSO2NA_PSLOG.log" to end of it
If ($PSScriptRoot -ne $null)
{
	$ScriptLog = Join-Path -Path $PSScriptRoot -ChildPath "PSO2NA_PSLOG.log"
}
Else
{
	$ScriptLog = Join-Path -Path "." -ChildPath "PSO2NA_PSLOG.log"
}
#Start logging
Start-Transcript -Path $ScriptLog
#Version number
"Version 2020_06_08_0254" #28

#All the fun helper functinons
#Crash hander
Function Failure
{
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

#Downloader
Function DownloadMe
{
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory=$true, ValueFromPipeline=$true)]
		[ValidateNotNullOrEmpty()]
		[String]
		$URI,
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]
		$OutFile,
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		$ErrorLevel = 255,
		[Bool]
		$Overwrite = $false
	)
	Try
	{
		If (-Not (Test-Path -Path $OutFile -PathType Leaf) -Or $Overwrite)
		{
			Invoke-WebRequest -Uri $URI -OutFile $OutFile -UserAgent "Arks-Layer pso2_winstore_fix" -Verbose  -ErrorAction Stop
		}
		If (-Not (Test-Path -Path $OutFile -PathType Leaf))
		{
			""
			"Error: Failed to download file, if you want, you can manually download"
			$URI
			exit $ErrorLevel
		}
		Return Resolve-Path -Path $OutFile
	}
	Catch
	{
		$_ | Failure
		exit $ErrorLevel
	}
}

#Package version check
Function PackageVersion
{
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory=$true, ValueFromPipeline=$true)]
		[AllowNull()]
		[Object[]]
		$Packages,
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[Version]
		$Version,
		[String]
		$Architecture = "X64"
	)
	PROCESS
	{
		Return $Packages | Where-Object -Property Architecture -EQ $Architecture | Where-Object -FilterScript {[Version]$_.Version -ge $Version}
	}
}

#Find MutableBackup
Function FindMutableBackup {
	[CmdletBinding()]
	Param
	(
		[String]
		$Package = "100B7A24.oxyna"
	)
	PROCESS
	{
		$AppxVols = Get-AppxVolume -Online -Verbose
		$Mutable = $AppxVols | ForEach-Object {
			$Test = Join-Path $_.PackageStorePath -ChildPath "MutableBackup"
			If (Test-Path $Test -PathType Container)
			{
				Return Resolve-Path -Path $Test -Verbose
            }
		}
		$Backups = $Mutable | ForEach-Object {
            Return Get-ChildItem -Path $_.ProviderPath -Filter "$($Package)*" | Resolve-Path
	    }
		$Backups.ProviderPath
	}
}

Write-Host -NoNewline "Checking Windows version..."
$WinVer = [Version](Get-CimInstance Win32_OperatingSystem).version
if ($WinVer.Major -lt 10)
{
	""
	"Reported Windows Major version $($WinVer.Major)"
	"ERROR: PSO2NA is only supported on Windows 10. Press any key to exit."
	Stop-Transcript
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	exit 1
}
ElseIf ($WinVer.Build -lt 18362)
{
	""
	"Reported Windows Build version $($WinVer.Build)"
	"ERROR: PSO2NA is only supported on Windows 10 (1903+). You need to update your Windows. Press any key to exit."
	Stop-Transcript
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	exit 2
}
Elseif ([System.Environment]::Is64BitOperatingSystem -eq $false)
{
	""
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
	""
	"WARNING: You need to run this PowerShell script using an Administrator account (or with an admin powershell)."
	Stop-Transcript
	Start-Process -FilePath "powershell.exe" -ArgumentList "-NoLogo","-NoProfile","-ExecutionPolicy","ByPass","-File",('"{0}"' -f $MyInvocation.MyCommand.Path) -Verb RunAs
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

"Checking MS Store Setup"
Set-Service -Name "wuauserv" -StartupType Manual -ErrorAction Continue
#Set-Service -Name "BITS" -StartupType AutomaticDelayedStart -ErrorAction Continue
Set-Service -Name "StorSvc" -StartupType Manual -ErrorAction Continue
Get-Service -Name "wuauserv","BITS","StorSvc" | Where-Object Statis -NE "Running" | Start-Service -ErrorAction Continue

$SystemVolume = Get-AppxVolume | Where-Object -Property IsSystemVolume -eq $true

$XBOXIP_User = @()
$XBOXIP_All = @()
$XBOXIP_User += Get-AppxPackage -Name "Microsoft.XboxIdentityProvider" -PackageTypeFilter Main -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" -Verbose
$XBOXIP_All += Get-AppxPackage -Name "Microsoft.XboxIdentityProvider" -PackageTypeFilter Main -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" -AllUsers -Verbose

If ($XBOXIP_All.Count -gt 0 -and $XBOXIP_User.Count -eq 0)
{
	#$XBOXIP_All | Sort-Object -Property Version | Select-Object -First 1 | Add-AppxPackage -Volume $SystemVolume -Verbose
	#$XBOXIP = Get-AppxPackage -Name "Microsoft.XboxIdentityProvider" -PackageTypeFilter Main -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" -Verbose
}
ElseIf ($XBOXIP_All.Count -eq 0)
{
	""
	"ERROR: Look like XBOX Identify Provider had been removed from the OS?"
	""
}
Else
{
	$XBOXIP = Get-AppxPackage -Name "Microsoft.XboxIdentityProvider" -PackageTypeFilter Main -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" -Verbose
}

If ($XBOXIP -ne $null)
{
	"Looking for the XBOX Identify Provider folder to wipe"
	$PackageF = Join-Path -Path $env:LOCALAPPDATA -ChildPath "Packages" -Verbose
	$XBOXIPFN = $XBOXIP.PackageFamilyName
	$XBOXIPF = Join-Path -Path $PackageF -ChildPath $XBOXIPFN  -Verbose
	$XBOXTBF = Join-Path $XBOXIPF -ChildPath "AC\TokenBroker" -Verbose
	If (Test-Path -Path $XBOXTBF -PathType Container)
	{
		$takeownEXE = "C:\Windows\system32\takeown.exe"
		If (Test-Path -Path $takeownEXE)
		{
			Start-Process -FilePath $takeownEXE -ArgumentList "/R","/F",('"{0}"' -f $XBOXTBF) -ErrorAction Continue
		}
		Get-ChildItem $XBOXTBF | Remove-Item -Force -Recurse -ErrorAction Continue
	}
}
Else
{
	""
	"ERROR: Look like XBOX Identify Provider had been uninstalled, please get it back"
	""
	[Diagnostics.Process]::Start("ms-windows-store://pdp?productid=9wzdncrd1hkw")
	Stop-Transcript
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	exit 27
}

"Checking needed GamingService App for runtime"
$GamingServices_User = @()
$GamingServices_Any = @()
$GamingServices_All = @()
$GamingServices_User += Get-AppxPackage -Name "Microsoft.GamingServices" -PackageTypeFilter Main -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" | PackageVersion -Version "2.41.10001.0"
$GamingServices_Any += Get-AppxPackage -Name "Microsoft.GamingServices" -PackageTypeFilter Main -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" -AllUsers
$GamingServices_All += $GamingServices_Any | PackageVersion -Version "2.41.10001.0"

Try
{
	$ForceReinstallGS = $true
	"Checking if we can get the Gaming services working"
	Get-Service | Where-Object Name -In "GamingServices","GamingServicesNet" |  Where-Object Status -NE "Running" | Restart-Service
	"No Errors found"
	$ForceReinstallGS = $false
}
Catch
{
	"There was issues checking the Gaming services, we will try to reinstall the app..."
}

If ($ForceReinstallGS -eq $true -and $GamingServices_All.Count -gt 0)
{
	"Removing Gaming Services app..."
	Get-Service -Name "GamingServices","GamingServicesNet" -ErrorAction Continue | Stop-Service -ErrorAction Continue
	$GamingServices_Any | Remove-AppxPackage -Verbose -PreserveApplicationData:$false
	$GamingServices_Any | Remove-AppxPackage -AllUsers -Verbose
	""
	"ERROR: Gaming Services has been removed, a reboot will be needed to reinstall it"
	Stop-Transcript
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	exit 24
}
ElseIf ($GamingServices_All.Count -gt 0 -and $GamingServices_User.Count -eq 0)
{
	#$GamingServices_All | Sort-Object -Property Version | Select-Object -First 1 | Add-AppxPackage -Volume $SystemVolume -Verbose
}
ElseIf ($GamingServices_User.Count -eq 0 -or $ForceReinstallGS -eq $true)
{
	"Downloading Gaming Services App... (10MB)"
	$URI = "https://github.com/Arks-Layer/PSO2WinstoreFix/blob/master/appx/Microsoft.GamingServices.x64.2.41.10001.0.appx?raw=true"
	$FileD = "Microsoft.GamingServices.x64.2.41.10001.0.appx"
	$Download = $URI | DownloadMe -OutFile $FileD -ErrorLevel 18

	If ($ForceReinstallGS -eq $true)
	{
		"Removing Gaming Services app..."
		$GamingServices_Any | Remove-AppxPackage -PreserveApplicationData:$false
		$GamingServices_Any | Remove-AppxPackage -AllUsers
	}
	"Installing Gaming Services app..."
	Try {
		$BadInstall = $true
		$Download | Add-AppxPackage -Volume $SystemVolume -Verbose -ForceApplicationShutdown -ForceUpdateFromAnyVersion
		$BadInstall = $false
		$ForceReinstallGS = $true
	}
	Catch {}
	$GamingServices_Any += Get-AppxPackage -Name "Microsoft.GamingServices" -PackageTypeFilter Main -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" -AllUsers
	If ($BadInstall -eq $false -and $GamingServices_Any.Count -ne 0)
	{
		""
		"ERROR: Gaming Services installed, please reboot."
		Stop-Transcript
		$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
		exit 25
		#Resolve-Path -Path $FileD | Remove-Item -Verbose
	}
}

If ($GamingServices_User.Count -eq 0 -or $ForceReinstallGS -eq $true)
{
	""
	"ERROR: Please make sure to install the Gaming Services from the MS Store"
	[Diagnostics.Process]::Start("ms-windows-store://pdp?productid=9mwpm2cqnlhn")
	Stop-Transcript
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	exit 26
}

"Restarting XBOX services"
Get-Service -Name "XblAuthManager","XboxNetApiSvc" | Where-Object Statis -NE "Running" | Start-Service

"Finding GameGuard Service"
$npggsvc = @()
$npggsvc += Get-Service | Where-Object Name -eq "npggsvc"
If ($npggsvc.Count -gt 0)
{
	"Found GameGuard Service"
	"Trying to stop it..."
	Try
	{
		$BrokenGG = $true
		$npggsvc | Where-Object Statis -EQ "Running" | Stop-Service -ErrorAction Continue -PassThru | Set-Service -StartupType Manual
		$BrokenGG = $false
	}
	Catch {}
	$npggsvcK = "HKLM:SYSTEM\CurrentControlSet\Services\npggsvc"
	If (-Not (Test-Path -Path $npggsvcK))
	{
		$BrokenGG = $true
	}
	
	If ($BrokenGG)
	{
		#Delete-Service do not exist in Power-Shell 5.1
		& sc.exe delete npggsvc
	}
}

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
	""
	"ERROR: Cannot find %APPDATA% folder - Is your Windows properly set up? Press any key to exit."
	Stop-Transcript
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	exit 5
}
If ($JSONData)
{
	$JSONObj = $JSONData | ConvertFrom-Json -Verbose
	"Tweaker Settings for logging:"
	$JSONObj
}
Else
{
	""
	"ERROR: Cannot read Tweaker Setting JSON - Did you set up the Tweaker yet? Press any key to exit."
	Stop-Transcript
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	exit 6
}
If ($JSONObj)
{
    $PSO2NABinFolder = ""
    try {
		$PSO2NABinFolder = $JSONObj | Select-Object -ExpandProperty PSO2NABinFolder
	}
	catch {}
}
Else
{
	""
	"ERROR: Can not convert JSON into PowerShell Object. This shouldn't happen! Press any key to exit."
	Stop-Transcript
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	exit 7
}
If ($PSO2NABinFolder -eq "")
{
	""
	"ERROR: Old version of the Tweaker config file found, please update Tweaker."
	"Press any key to exit."
	Stop-Transcript
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	exit 20
}
ElseIF ($PSO2NABinFolder -contains "[" -or $PSO2NABinFolder -contains "]")
{
	""
	"ERROR: The $($PSO2NABinFolder) folder have { or ], PowerShell have issues with folder name."
	"Press any key to exit."
	Stop-Transcript
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	exit 28
}
ElseIf ($PSO2NABinFolder -eq $null)
{
	""
	"ERROR: Tweaker NA Setup is not done, please tell me where to install PSO2NA"
	"Press any key to exit."
	Stop-Transcript
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	exit 20
}
ElseIf (-Not (Test-Path -Path "$($PSO2NABinFolder)" -PathType Container))
{
	""
	"ERROR: The $($PSO2NABinFolder) folder does not exist. Please check your PSO2 Tweaker settings."
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
	""
	"ERROR: Cannot find a PSO2NABinFolder setting - Did you set up PSO2NA through the Tweaker yet? If not, do it. Press any key to exit."
	Stop-Transcript
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	exit 8
}
If (-Not (Test-Path -Path $PSO2NAFolder -PathType Container))
{
	""
	"ERROR: The $($PSO2NAFolder) folder does not exist. Please check your PSO2 Tweaker settings."
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
		""
		"ERROR: You cannot use the Windows Store copy of PSO2 with this script. Go back to http://arks-layer.com/setup.html and do a fresh install."
		""
		"WARNING: you just wanted to fix XBOX login mess, you should be fine now"
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
	""
	"ERROR: Cannot get PSO2NA Folder - Did you follow the instructions? Press any key to exit."
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
	"WARNING: Your system's WMI database is broken, please repair it."
}
ElseIf ($PSO2Vol.Count -eq 0)
{
	""
	"WARNING: Your PSO2NA installation is not on a NTFS drive, please move the PSO2NA installation elsewhere."
	#Stop-Transcript
	#$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	#exit 15
}
Else
{
	"Your PSO2NA installation is on a NTFS drive \o/"
}



$MissingFiles = $false
"Checking for appxmanifest.xml..."
If (-Not (Join-Path -Path $PSO2NAFolder -ChildPath "appxmanifest.xml" | Test-Path -PathType Leaf))
{
	$MissingFiles = $true
	"	MISSING"
}
"Checking for MicrosoftGame.config..."
If (-Not (Join-Path -Path $PSO2NAFolder -ChildPath "MicrosoftGame.config" | Test-Path -PathType Leaf))
{
	$MissingFiles = $true
	"	MISSING"
}
"Checking for pso2_bin/pso2.exe file..."
If (-Not (Join-Path -Path $PSO2NABinFolder -ChildPath "pso2.exe" | Test-Path -PathType Leaf))
{
	$MissingFiles = $true
	"	MISSING"
}
"Checking for pso2_bin/Logo.png file..."
If (-Not (Join-Path -Path $PSO2NABinFolder -ChildPath "Logo.png" | Test-Path -PathType Leaf))
{
	$MissingFiles = $true
	"	MISSING"
}
"Checking for pso2_bin/SmallLogo.png file..."
If (-Not (Join-Path -Path $PSO2NABinFolder -ChildPath "SmallLogo.png" | Test-Path -PathType Leaf))
{
	$MissingFiles = $true
	"	MISSING"
}
"Checking for pso2_bin/SplashScreen.png file..."
If (-Not (Join-Path -Path $PSO2NABinFolder -ChildPath "SplashScreen.png" | Test-Path -PathType Leaf))
{
	$MissingFiles = $true
	"	MISSING"
}
"Checking for pso2_bin/vivoxsdk.dll file..."
If (-Not (Join-Path -Path $PSO2NABinFolder -ChildPath "vivoxsdk.dll" | Test-Path -PathType Leaf))
{
	$MissingFiles = $true
	"	MISSING"
}
If ($MissingFiles -eq $true)
{
	""
	"ERROR: Cannot find required files - Go back to http://arks-layer.com/setup.html and make sure you follow ALL the steps and do a fresh new install."
	"If you think you did it right (you probably didn't!), download"
	"https://github.com/Arks-Layer/PSO2WinstoreFix/blob/master/pso2_bin_na_starter.zip"
	"extract it to your PHANTASYSTARONLINE2 folder and DO A FILE CHECK!"
	"(Troubleshooting -> New Method)"
	Stop-Transcript
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	exit 11
}

$OldBackups = @()
"Looking for old PSO2NA MutableBackup folders"
$OldBackups += FindMutableBackup
If ($OldBackups.Count -gt 0)
{
    "Found some MutableBackup folders"
    $OldBackups |fl
	$OldBackups | ForEach-Object -Process {
		$OldBin = $_
		"Going to copy the backup files to your Tweaker copy of PSO2"
		Start-Process -FilePath "C:\Windows\system32\Robocopy.exe" -ArgumentList ('"{0}\"' -f $OldBin),('"{0}\"' -f $PSO2NABinFolder),"/MIR","/XF *.pat","/XO","/MAX:0","/R:0"
		"Press any key to resume"
		$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
		"Deleting old $($OldBin) folder..."
		#Get-ChildItem -Path $OldBin | Remove-Item -Recurse -Force -Confirm:$false -Verbose
	}
}
$OldPackages = @()
"Looking for a PSO2NA Windows Store installation..."
$OldPackages = Get-AppxPackage -Name "100B7A24.oxyna" -AllUsers | Where-Object -Property SignatureKind -EQ "Store"
If ($OldPackages.Count -gt 0)
{
	"Unregistering the old PSO2 from the Windows Store... (This may take a while, don't panic!)"
	"If this takes more then 30 minutes, you may have to reboot."
	$OldBin = $false
	$BadBin = "C:\Program Files\WindowsModifiableApps\pso2_bin"
	$OldBin = Test-Path $BadBin -ErrorAction SilentlyContinue -PathType Container
	If ($OldBin)
	{
		"Found the old MS STORE's pso2_bin folder"
		"Going to copy the MS STORE files to your Tweaker copy of PSO2"
		Start-Process -FilePath "C:\Windows\system32\Robocopy.exe" -ArgumentList ('"{0}\"' -f $OldBin),('"{0}\"' -f $PSO2NABinFolder),"/MIR","/XF *.pat","/XO","/MAX:0","/R:0"
		"Press any key to resume"
		$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');=
		"Deleting old MS STORE's pso2_bin folder..."
		#Get-ChildItem -Path $OldBin | Remove-Item -Recurse -Force -Confirm:$false -Verbose
	}
	$OldPackages | Remove-AppxPackage -AllUsers -Verbose
}
Else
{
	"No Windows Store PSO2NA installation found. This is OK!"
}

"Checking if we need to install the requirements..."
$NewPackages = @()

$DirectXRuntime_All = @()
$DirectXRuntime_User = @()

$DirectXRuntime_All += Get-AppxPackage -Name "Microsoft.DirectXRuntime" -PackageTypeFilter Framework -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" -AllUsers | PackageVersion -Version "9.29.952.0"
$DirectXRuntime_User += Get-AppxPackage -Name "Microsoft.DirectXRuntime" -PackageTypeFilter Framework -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" | PackageVersion -Version "9.29.952.0"

if ($false) #($DirectXRuntime_All.Count -gt 0 -and $DirectXRuntime_User.Count -eq 0)
{
	"System already has a good copy of DirectX, trying to install the user profile..."
	#$DirectXRuntime_All | Sort-Object -Property Version | Select-Object -First 1 | Add-AppxPackage -Volume $SystemVolume -Verbose 
}
ElseIf ($DirectXRuntime_User.Count -eq 0)
{
	"Downloading DirectX Runtime requirement... (56MB)"
	$URI = "https://download.microsoft.com/download/c/c/2/cc291a37-2ebd-4ac2-ba5f-4c9124733bf1/UAPSignedBinary_Microsoft.DirectX.x64.appx"
	$FileD = "UAPSignedBinary_Microsoft.DirectX.x64.appx"
	$NewPackages += $URI | DownloadMe -OutFile $FileD -ErrorLevel 12
}


$VCLibs_All = @()
$VCLibs_User = @()

$VCLibs_All += Get-AppxPackage -Name "Microsoft.VCLibs.140.00.UWPDesktop" -PackageTypeFilter Framework -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" -AllUsers | PackageVersion -Version "14.0.24217.0"
$VCLibs_User += Get-AppxPackage -Name "Microsoft.VCLibs.140.00.UWPDesktop" -PackageTypeFilter Framework -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" | PackageVersion -Version "14.0.24217.0"

If ($false) #($VCLibs_All.Count -gt 0 -And $VCLibs_User.Count -eq 0 )
{
	"System already has a good copy of VCLibs, trying to install the user profile"
	#$VCLibsAll | Sort-Object -Property Version | Select-Object -First 1 | Add-AppxPackage -Volume $SystemVolume-Verbose
}
Elseif ($VCLibs_User.Count -eq 0)
{
	"Downloading VCLibs requirement... (7MB)"
	$URI = "https://github.com/Arks-Layer/PSO2WinstoreFix/blob/master/appx/Microsoft.VCLibs.x64.14.00.Desktop.appx?raw=true"
	$FileD = "Microsoft.VCLibs.x64.14.00.Desktop.appx"
	$NewPackages += $URI | DownloadMe -OutFile $FileD -ErrorLevel 13
}

If ($NewPackages.Count -gt 0)
{
	"Installing requirements... If you see an error about it not being installed becuase of a higher version, that's OK!"
	$NewPackages | Add-AppxPackage -Volume $SystemVolume -Verbose -ErrorAction Continue
	#$NewPackages | Remove-Item -Verbose
}
Else
{
	"Requirements already installed"
}

$PSO2Packages = @()
$PSO2Packages_User+ @()
$PSO2Packages_Good = @()
$PSO2Packages_Bad = @()
$EmptyFiles = Get-ChildItem -Path $PSO2NABinFolder | Where-Object Name -ne "patchlist.txt" | Where-Object Length -eq 0
$PSO2Packages += Get-AppxPackage -Name "100B7A24.oxyna" -AllUser | Where-Object -Property SignatureKind -EQ "None"
$PSO2Packages_User += Get-AppxPackage -Name "100B7A24.oxyna" -AllUser | Where-Object -Property SignatureKind -EQ "None"
$PSO2Packages_Good += $PSO2Packages | Where-Object InstallLocation -eq $PSO2NAFolder  | Where-Object Status -EQ "Ok"
$PSO2Packages_Bad += $PSO2Packages | Where-Object InstallLocation -ne $PSO2NAFolder
$PSO2Packages_Bad += $PSO2Packages | Where-Object Status -ne "Ok"

$XBOXURI = Test-Path -Path "Registry::HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\windows.protocol\ms-xbl-78a72674" -PathType Container
If ($XBOXURI -eq $false -or $PSO2Packages_User.Count -eq 0)
{
	$ForceReinstall = $true
}

If ($ForceReinstall)
{
	"Bad install found, forcing a PSO2 reinstall..."
	Get-AppxPackage -Name "100B7A24.oxyna" -AllUsers | Remove-AppxPackage -Verbose -AllUsers
}
ElseIf ($PSO2Packages_Bad.Count -gt 0)
{
	"Found a old custom PSO2 install, removing it..."
	$PSO2Packages_Bad | Sort-Object -Unique | Remove-AppxPackage -Verbose -AllUsers
}

If ($EmptyFiles.Count -gt 0)
{
	$JSONObj.PSO2NARemoteVersion = 0
	$JSONObj | ConvertTo-Json | Out-File -FilePath $JSONPath
	""
	"ERROR: Bad PSO2 files found, please run a full file check in Tweaker"
	"(Troubleshooting -> New Method)"
	"List of bad files:"
	$EmptyFiles
	""
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
	"There is already a custom PSO2 install?"
	$PSO2Packages_Good
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

"Now double checking the custom PSO2 install..."
$CustomPSO2 = @()
$CustomPSO2 += Get-AppxPackage -Name "100B7A24.oxyna" | Where-Object IsDevelopmentMode -eq $true | Where-Object Status -EQ "Ok"
If ($CustomPSO2.Count -eq 0)
{
	 "Cannot find custom PSO2 installation!"
}
ElseIf ($CustomPSO2.Count -eq 1)
{
	"Good, only found one custom PSO2 install."
}
Else
{
	"What? why are there $($CustomPSO2) custom PSO2 install?!"
}
"Raw PSO2 install status:"
Get-AppxPackage -Name "100B7A24.oxyna"

Stop-Transcript -ErrorAction Continue
Write-Host -NoNewLine 'Script complete! You can now close this window by pressing any key.';
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
