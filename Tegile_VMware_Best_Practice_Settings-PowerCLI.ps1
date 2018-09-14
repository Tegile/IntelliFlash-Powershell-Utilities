<#
.SYNOPSIS
Allows you to check for Tegile Best Practice settings for vSphere NFS & VMFS Datastores

.DESCRIPTION
This script will allow you to connect to vCenter, or a standalone host, and
then will query and offer to apply Best Practice settings for NFS & VMFS Datastores
*Note that if you don't run it with -ReportOnly, SATP rules for VMFS datastores will automatically install/update

Requires PowerShell version 5 or better, and PowerCLI version 6.3 r1 or better
Tested with vSphere 5.5 through 6.7

The script has several optional parameters, which will autocomplete after '-':
	-Version (alias: -ver, -v) | Returns script version
	-ReportOnly (alias: -ro) | Apply no settings just report and generate CSV file
	-DatastorePathCheck | ESX 6.0 or later required. This will check and report all Tegile FC and iSCSI paths supporting VMFS Datastores.
	-RDMPathCheck | ESX 6.0 or later required. This will check and report all paths for any Tegile LUN's supporting RDM's.
	-HostPathCheck | ESX 6.0 or later required. This will check and report the total number of Tegile FC and iSCSI paths for all hosts.
	-CheckIOPS | ESX 6.0 or later required. This will check the current IOPS=XX setting for each Tegile LUN attached.
	-SetIOPS | ESX 6.0 or later required. This will adjust the current IOPS=XX setting for each Tegile LUN attached.
	-SkipMaxVol | Skip the query/application of NFS.MaxVolumes and related settings
	-SkipVAAI | Skip query/installation of NFS VAAI extension
	-SkipNFS | Skip the query/application of all/any NFS best practice settings (implies -SkipMaxVol)
	-SkipBlock | Skip checking/applying Tegile's recommended settings for LUN's / VMFS datastores, which includes SATP rules
		*Note, this also includes disabling VAAI ATS for VMFS Heartbeat. We recommend disabling ATS for VMFS Heartbeat, KB 2113956.
	-SkipATS | Skip disabling VAAI ATS for VMFS Heartbeat. ESXi 5.5u2 or greater is required to disable ATS for VMFS HB, so use this for older releases
	-SkipUpdate | Skip the script version check against the one on s1.tegile.com and subsequent prompt for update if different
	-LegacySATP | Check/Apply legacy ZEBI-FC and ZEBI-ISCSI SATP rules for LUN's created prior to IntelliFlash 3.x
	-AcceptDisclaimer | Accept the disclaimer without being prompted to do so within the script - you accept all responsibility anyway!
	-AutoApply | (alias: -auto) Automatically apply all changes deemed necessary without prompt or check for maintenance mode
	-VCServer (alias: -vCenter) | Specify the IP or FQDN of the vCenter Server or ESXi Host
	-Cluster | Specify a specific cluster (or even a folder) rather than the default which is all hosts and clusters under vCenter
	-User (alias: -u) | Specify the user account for vCenter or Host connectivity
	-Password (alias: -p) | Specify the password for the designated user account

You must specify/verify the vaai plugin version and depot path statically within the script,
just edit with a text editor and look for the variables
	
The vCenter server can optionally be specified statically within the script as well

.EXAMPLE
.\Tegile_VMware_Best_Practice_Settings-PowerCLI.ps1 -Version
Displays the current script version

.EXAMPLE
.\Tegile_VMware_Best_Practice_Settings-PowerCLI.ps1 -ReportOnly -vCenter vc1.tegile.local
Connects to the vCenter server vc1.tegile.local,
and runs in Report Only mode against all hosts (no changes to hosts)

.EXAMPLE
.\Tegile_VMware_Best_Practice_Settings-PowerCLI.ps1 -SkipMaxVol -vCenter vc1.tegile.local -Cluster Production
Connects to the vCenter Server vc1.tegile.local, runs against only hosts in cluster "Production",
and runs in regular mode to apply all changes except NFS.MaxVolumes and related settings

.EXAMPLE
.\Tegile_VMware_Best_Practice_Settings-PowerCLI.ps1 -SkipNFS -vCenter vc1.tegile.local
Connects to the vCenter Server vc1.tegile.local,
and runs in regular mode to apply SATP rules and related settings, but no NFS settings

.EXAMPLE
.\Tegile_VMware_Best_Practice_Settings-PowerCLI.ps1 -SkipBlock -vCenter vc1.tegile.local
Connects to the vCenter Server vc1.tegile.local,
and runs in regular mode to apply all NFS related settings but no SATP rules or disabling of ATS for VMFS Heartbeat

.EXAMPLE
.\Tegile_VMware_Best_Practice_Settings-PowerCLI.ps1 -SetIOPS -SkipNFS -vCenter vc1.tegile.local
Connects to the vCenter Server vc1.tegile.local,
checks all Tegile LUN IOPS=xx setting and updates to what's specified in the script if necessary,
and then also checks/applies all SATP rules, but does not apply any NFS settings

.EXAMPLE
.\Tegile_VMware_Best_Practice_Settings-PowerCLI.ps1 -vCenter vc1.tegile.local -AutoApply
Connects to the vCenter Server vc1.tegile.local,
and runs in automatic mode to apply all settings without prompts for each host (dangerous!)

.LINK
http://www.tegile.com/
#>

[CmdletBinding(ConfirmImpact='Medium')]

	Param(
		[Parameter()]
		[Alias("v")] 
		[Alias("ver")] 
		[Switch]
		$Version,
		[Parameter()]
		[Alias("ro")]
		[Switch]
		$ReportOnly,
		[Parameter()]
		[Switch]
		$SkipMaxVol,
		[Parameter()]
		[Switch]
		$SkipVAAI,
		[Parameter()]
		[Switch]
		$SkipNFS,
		[Parameter()]
		[Switch]
		$SkipBlock,
		[Parameter()]
		[Switch]
		$SkipATS,
		[Parameter()]
		[Switch]
		$SkipUpdate,
		[Parameter()]
		[Switch]
		$LegacySATP,
		[Parameter()]
		[Switch]
		$AcceptDisclaimer,
		[Parameter()]
		[Alias("auto")]
		[Switch]
		$AutoApply,
		[Parameter()]
		[Alias("vCenter")]
		[String]
		$VCServer,
		[Parameter()]
		[String]
		$Cluster,
		[Parameter()]
		[Alias("u")]
		[String]
		$User,
		[Parameter()]
		[Alias("p")]
		[String]
		$Password,
        [Parameter()]
		[Switch]
		$DatastorePathCheck,
        [Parameter()]
		[Switch]
		$RDMPathCheck,
        [Parameter()]
		[Switch]
		$HostPathCheck,
        [Parameter()]
		[Switch]
		$CheckIOPS,
        [Parameter()]
		[Switch]
		$SetIOPS
	)

# This script is supported on a best-effort only
# Script Version:
$MajorVer = 3
$MinorVer = 7
$PatchVer = 1
$BuildVer = 0
$VerMonth = 07
$VerDay = 30
$VerYear = 2018
$Author = "Ben Kendall, Ken Nothnagel, & Tom Crowe, Tegile / WDC Professional Services"

$VerMonthName = (Get-Culture).DateTimeFormat.GetAbbreviatedMonthName($VerMonth)

# Make sure you're on at least PowerShell v5 and have latest PowerCLI. Tested with PowerCLI 6.5.3
# To get latest PowerCLI, first Uninstall any legacy PowerCLI from Add/Remove Programs, and install via PowerShell:
# Find-Module -Name VMware.PowerCLI
# Install-Module -Name VMware.PowerCLI -Scope AllUsers    ## Can also set -Scope to CurrentUser if not running as Administrator
# See: https://blogs.vmware.com/PowerCLI/2017/05/powercli-6-5-1-install-walkthrough.html


# Specify the currrent Tegile NAS VAAI Host Extension (aka "Plugin") version:
$tegilepluginversion = "1.0-15.70"


# Specify the depot path for the Tegile NAS VAAI Host Extension
# Note that you can change to format "file:/path/to/tgl-vaai-nas-plugin.zip" if it's on storage mounted on the host (required if host doesn't have Internet access)
# Example of local file path:  $depotpath = "file:/vmfs/volumes/Datastore01/patches/tgl-vaai-nas-plugin_1.0-15.70---3.7.1.0.zip"
$depotpath = "http://s1.tegile.com/ps/vmware/tgl-vaai-nas-plugin_1.0-15.70---3.7.1.0"


# NFS Settings, Queue Depth is adjustable per your needs, leave the others unless you know what you're doing:
$nfsqueuedepth = 64
$nfsrpctimeout = 30
$nfsheartbeatfreq = 20


# SATP Rule IOPS setting - generally recommended to use value of 1, but 0 may provide better distribution, and 1000 is VMware default:
$iopssetting = 1


# Specify the vCenter Server IP or FQDN if not passing via CLI:
if (!$VCServer) {
$VCServer = "10.10.10.42"
}


# NFS Max Volumes adjustments, note that TcpipHeapMax varies with ESXi version, see list of max values listed under the variables:
# https://kb.vmware.com/kb/2239
# Don't update the below unless you know what you're doing, they're referenced later in the script after determining host version
$nfsmaxvolumes = 256
$nettcpipheapsize = 32
$nettcpipheapmax51 = 128
$nettcpipheapmax55 = 512
$nettcpipheapmax6x = 1536


# The following should be set to "0" to disable use of ATS for VMFS Heartbeat, per VMware KB 2113956:
$tegilevmfshb = 0

### Begin our work

## Only check the version of the script

if ($Version) {
	$VerReport = @()
	$EachVer = New-Object -TypeName PSObject
	$EachVer | Add-Member -Type NoteProperty -Name Vendor -Value "Tegile Systems - a Western Digital brand"
	$EachVer | Add-Member -Type NoteProperty -Name Author -Value $Author
	$EachVer | Add-Member -Type NoteProperty -Name Version -Value "$MajorVer.$MinorVer.$PatchVer.$BuildVer"
	$EachVer | Add-Member -Type NoteProperty -Name Date -Value "$VerMonthName $VerDay, $VerYear"
	$VerReport += $EachVer
	Write-Output $VerReport
	Exit 0
}

# Logging details:
$InvokeTimestamp = Get-Date -UFormat "%Y%m%d%H%M%S"
$scriptpath = Split-Path -parent $MyInvocation.MyCommand.Definition
$scriptname = $MyInvocation.MyCommand | select -ExpandProperty Name
$suffix = "-" + "$InvokeTimestamp" + ".log"
$logfile = $scriptname.Replace(".ps1","$suffix")
$logdir = $scriptpath + "\log"
$logpath = $logdir+"\"+$logfile

Try {
	$logdirexists = Get-Item $logdir -ErrorAction Stop
} Catch {
	New-Item -ItemType directory -Path $logdir | Out-Null
}

Clear
Try {Stop-Transcript | Out-Null} Catch {}
Start-Transcript -path $logpath

# Verify PowerShell Version:
$PSHELLVER = ($PSVersionTable.PSVersion | select Major).Major
if ("$PSHELLVER" -lt "5") {
	Write-Host "`nFound PowerShell version '$PSHELLVER', expecting at least version 5" -foregroundcolor red
	Write-Host "`nYou can download WMF 5.1 which includes PowerShell v5 from:" -foregroundcolor yellow
	Write-Host "https://docs.microsoft.com/en-us/powershell/wmf/5.1/install-configure" -foregroundcolor yellow
	Write-Host "`nExiting the script..." -foregroundcolor red
	Stop-Transcript
	Exit 1
}

# Verify PowerCLI is loaded, if not try to import the module and exit if that fails:
if (!(Get-Module -Name VMware.VimAutomation.Core -ErrorAction SilentlyContinue)) {
	Try {
	Import-Module -Name VMware.VimAutomation.Core -ErrorAction Stop
	}
	Catch {
		Clear
		Write-Host "`nIt appears that you do not have PowerCLI installed, which is required!" -foregroundcolor red
		Write-Host "`nYou can install via:" -foregroundcolor yellow
		Write-Host "Find-Module -Name VMware.PowerCLI" -foregroundcolor yellow
		Write-Host "Install-Module -Name VMware.PowerCLI -Scope AllUsers" -foregroundcolor yellow
		Write-Host "(Can also set -Scope to CurrentUser if not running as Administrator)" -foregroundcolor yellow
		Write-Host "`nExiting the script..." -foregroundcolor red
		Stop-Transcript
		Exit 1
	}
}

if (!$AcceptDisclaimer) {
	# Disclaimer
	$DISCLAIMER = "`nDISCLAIMER`r`n`r`nThis script is provided AS IS without warranty of any kind. Tegile and Western Digital further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose. The entire risk arising out of the use or performance of this script and documentation remains with you. In no event shall Tegile, Western Digital, or anyone else involved in the creation, production, or delivery of this script be liable for any damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use this script or documentation, even if Tegile or Western Digital has been advised of the possibility of such damages.`r`n`r`nThis Script should only be run with the direct supervision of a Tegile/Western Digital Engineer."
	Write-Host $DISCLAIMER
	$title = ""
	$message = "`r`nAccept Disclaimer?`r`n`r`n"
	$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Accept and continue"
	$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Quit now"
	$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
	$ACCEPTED = $host.ui.PromptForChoice($title, $message, $options, 1) 
	if ($ACCEPTED -eq 1) {
		Write-Host "`nYou have not accepted the disclaimer, exiting script...`n" -foregroundcolor red
		Stop-Transcript
		Exit 1
	} else {
		Write-Host "`nYou have accepted the disclaimer, continuing...`n" -foregroundcolor green
		Write-Host "Local Script Version: $MajorVer.$MinorVer.$PatchVer.$BuildVer.$VerYear$VerMonth$VerDay"
	}
} else {
	Write-Host "`nYou specified -AcceptDisclaimer - you're ignoring the Disclaimer and accepting all responsibility anyway!" -foregroundcolor yellow
}
if (!$SkipUpdate) {
	# Check Script Version against the one on s1.tegile.com, offer to update if they're different:
	$url = "http://s1.tegile.com/ps/vmware/Tegile_VMware_Best_Practice_Settings-PowerCLI.ps1"
	$s1vertestscript = "$scriptpath\Tegile_VMware_Best_Practice_Settings-PowerCLI-s1VerTest-$InvokeTimestamp.ps1"
	$Error.Clear()
	Invoke-WebRequest -Uri $url -OutFile "$s1vertestscript"
	If (!$Error){
		# Get version info from local and downloaded scripts to compare, and convert to strings:
		$s1version = Invoke-Expression "& '$s1vertestscript' -version"
		$currentversion = Invoke-Expression "& '$scriptpath\$scriptname' -version"
		$s1version = [Version]$s1version.version
		$currentversion = [Version]$currentversion.version
		if ($currentversion) {
			Write-Debug -Message $currentversion
			} else {
			Write-Debug -Message "Unable to collect local script version"
		}
		if ($s1version) {
			Write-Debug -Message $s1version
			} else {
			Write-Debug -Message "Unable to collect online script version"
		}
		if ($s1version -gt $currentversion) {
			Write-Host "`nYour version of the script is older than '$url'!!!" -foregroundcolor red
			Write-Host "`nThe updated script version on s1.tegile.com is:" -foregroundcolor yellow
			write-host $s1version -foregroundcolor green
			Write-Host "`nYour local script version is:" -foregroundcolor yellow
			write-host $currentversion -foregroundcolor red
			$answer = Read-Host "`nEnter 'y' to update the script, anything else to continue: "
			if ($answer -eq "y") {
				Write-Host "`nReplacing script with updated version as requested, and restarting it with same parameters for you..." -foregroundcolor green
				del "$scriptpath\$scriptname"
				ren "$s1vertestscript" "$scriptname"
				Write-Host "Restarting script in:"
				$i=5
				Do {
					Write-Host $i
					sleep 1
					$i = $i - 1
				} while ($i -ne 0)
				Write-Host "Restarting script..."
				Stop-Transcript
				powershell.exe $MyInvocation.Line
				Exit 0
			} else {
				Write-Host "`nContinuing with current version of script as requested..." -foregroundcolor yellow
				del "$s1vertestscript"
			}
		} else {
			Write-Debug -Message "The online script is not newer than the local script."
			sleep 1
			del "$s1vertestscript"
		}
	} else {
	Write-Host "`nUnable to check for the current script. Verify access to http://s1.tegile.com/ps and try again.`n" -foregroundcolor yellow
	Pause
	}
} else {
	Write-Host "`nSkipping the script version and update check, as requested"
}

# Check to see if PowerCLI is new enough:
$PCLIMAJVER = ((Get-Module -Name VMware.VimAutomation.Core).version).Major
$PCLIMINVER = ((Get-Module -Name VMware.VimAutomation.Core).version).Minor
if ($PCLIMAJVER -lt "6") {
	$PCLIVEROLD = $true
} elseif (($PCLIMAJVER -eq "6") -and ($PCLIMINVER -lt "3")) {
	$PCLIVEROLD = $true
}
if ($PCLIVEROLD) {
	$PCLIFULLVER = "$PCLIMAJVER.$PCLIMINVER"
    Write-Host "`nFound PowerCLI version: $PCLIFULLVER" -foregroundcolor red
	Write-Host "Version 6.3 Release 1 or newer is required" -foregroundcolor red
    Write-Host "`nYou can install latest version via:" -foregroundcolor yellow
    Write-Host "Find-Module -Name VMware.PowerCLI" -foregroundcolor yellow
	Write-Host "Install-Module -Name VMware.PowerCLI -Scope AllUsers" -foregroundcolor yellow
	Write-Host "(Can also set -Scope to CurrentUser if not running as Administrator)" -foregroundcolor yellow
    Write-Host "`nExiting the script..." -foregroundcolor red
    Stop-Transcript
    Exit 1
}

Set-PowerCLIConfiguration -DefaultVIServerMode Single -InvalidCertificateAction Ignore -Scope Session -Confirm:$false | Out-Null

if ($ReportOnly) {
	Write-Host "`nRunning in Report Only mode, will not be applying any changes, as requested"
} elseif ($AutoApply) {
	Write-Host "`nAutomatically applying changes without prompt or maintenance mode check, as requested"
}
if ($SkipMaxVol) {
	Write-Host "`nNot applying NFS.MaxVolumes, Net.TcpipHeapSize, or Net.TcpipHeapMax settings, as requested"
}
if ($SkipVAAI) {
	Write-Host "`nSkipping check/installation of NFS VAAI extension, as requested"
}
if ($SkipNFS) {
	Write-Host "`nNot checking or applying any settings related to NFS, as requested"
}
if ($SkipBlock) {
	Write-Host "`nNot checking or applying any SATP Rules or disabling ATS for VMFS Heartbeat, as requested"
} else {
	if ($LegacySATP) {
		Write-Host "`nChecking/Applying legacy SATP rules, as requested"
	}
}
if ($SkipATS) {
	Write-Host "`nNot checking/disabling VAAI ATS for VMFS Heartbeat, as requested"
}
if ($Cluster) {
	Write-Host "`nLimiting scope to specified cluster: $Cluster"
}

# Disconnect any existing vCenter sessions (thus forcing re-login every time script is run):
# if ((Test-Path Variable:global:DefaultVIServer) -and ($global:DefaultVIServers -ne $null)) {
# 	Disconnect-VIServer $global:DefaultVIServers -Force -Confirm:$false
# }

# Connect to vCenter
Write-Host "`nConnecting to vCenter Server $VCServer...`n"

# First see if we're already connected, and re-use existing session if so:
$SessionID = ($global:DefaultVIServers | Where-Object -FilterScript {$_.name -eq $VCServer}).sessionId
if ($SessionID) {
	Connect-VIServer -Server $VCServer -Session $SessionID -Force -WarningAction SilentlyContinue
} elseif (!$Password) {
	$vccredential = $host.ui.promptforcredential("Need vCenter Credentials", "User Name and Password for vCenter '$VCServer':", "$User", "")
	Connect-VIServer -Server $VCServer -Credential $vccredential -WarningAction SilentlyContinue
} else {
	Connect-VIServer -Server $VCServer -User $User -Password $Password -WarningAction SilentlyContinue
}
if ("$?" -eq "False") {
	Write-Host "`nConnection to vCenter Server $VCServer Failed. Verify Server IP/FQDN and credentials. Exiting...`n" -foregroundcolor red
	Stop-Transcript
	Exit 1
}

# Get list of hosts:
if ($Cluster) {
	$VMHosts = Get-VMHost -Server $VCServer -Location $Cluster -ErrorAction SilentlyContinue
	if (!$VMHosts) {
		Write-Host "`nLooks like an invalid cluster was specified or no hosts present, exiting...`n" -foregroundcolor red
		Exit 1
	}
} else {
	$VMHosts = Get-VMHost -Server $VCServer -ErrorAction SilentlyContinue
	if (!$VMHosts) {
		Write-Host "`nLooks like no hosts present in inventory, exiting...`n" -foregroundcolor red
		Exit 1
	}
}

# Loop through hosts one at at time and apply settings and install Tegile NAS VAAI host extension:
foreach ($VMHost in $VMHosts) {
	
	# Check that host connection state is Connected or Maintenance, not Disconnected or NotResponding
	if (($VMHost.ConnectionState -eq "Disconnected") -or ($VMHost.ConnectionState -eq "NotResponding")) {
		Write-Host "`nHost $VMHost is Disconnected or Not Responding, skipping to next host`n" -foregroundcolor red
		continue
	}
	
	$NFSCHANGES = ""
	$HOSTREPORT = @()
	$esxcli = $VMHost | Get-EsxCli -V2

	$DATASTOREPATHREPORT = @()
	$RDMPATHREPORT = @()
	$HOSTPATHREPORT = @()
	$IOPSREPORT = @()
	$HostVersion = ([version]$VMHost.Version)

	if ($DatastorePathCheck -or $RDMPathCheck -or $HostPathCheck -or $SetIOPS -or $CheckIOPS) {
		if ($HostVersion.Major -lt 6) {
			write-host "Path Validation and IOPS Checks and IOPS Sets only work on ESX 6.0 and later!" -ForegroundColor Red -BackgroundColor Black
		}
	}

	if ($CheckIOPS -and $HostVersion.Major -gt 5) {
		Write-Host "`n`nCollecting all Tegile LUN IOPS Settings for host: $VMHost...`n"
		$LUNIOPSList = (Get-VMHost $VMHost | Get-ScsiLun -LunType disk | Where-Object {$_.Multipathpolicy -like "RoundRobin" -and $_.Vendor -eq "TEGILE"} | Select-Object CanonicalName, MultipathPolicy, CommandsToSwitchPath, Vendor)
		Write-Host "Host,LUN,MultipathPolicy,IOPS,Vendor,Change_Required"
		$IOPColor = "White"
		$IOPChange = "NO"
		foreach ($LUNIOPSetting in $LUNIOPSList) {
			#SET REPORT SETTINGS
			$CNAME = $LUNIOPSetting.CanonicalName
			$CMP = $LUNIOPSetting.MultipathPolicy
			$CIOPS = $LUNIOPSetting.CommandsToSwitchPath
			$CVendor = $LUNIOPSetting.Vendor
			if ($CIOPS -eq $iopssetting) {
				$IOPColor = "Green"
				$IOPChange = "NO"
				} else {
				$IOPColor = "Red"
				$IOPChange = "YES"
			}
			$CurrentIOPCheck = New-Object -TypeName PSObject
					$CurrentIOPCheck | Add-Member -Type NoteProperty -Name "Host" -Value $VMHost
					$CurrentIOPCheck | Add-Member -Type NoteProperty -Name "LUN" -Value $CNAME
					$CurrentIOPCheck | Add-Member -Type NoteProperty -Name "MultipathPolicy" -Value $CMP
					$CurrentIOPCheck | Add-Member -Type NoteProperty -Name "IOPS" -Value $CIOPS
					$CurrentIOPCheck | Add-Member -Type NoteProperty -Name "Vendor" -Value $CVendor
					$CurrentIOPCheck | Add-Member -Type NoteProperty -Name "Change Required" -Value $IOPChange
					$IOPSREPORT += $CurrentIOPCheck
			Write-Host "$VMHost,$CNAME,$CMP,$CIOPS,$CVendor,$IOPChange" -ForegroundColor $IOPColor
		}
		$IOPSREPORT | Export-Csv -NoTypeInformation -Append -Path $logpath.Replace(".log","-IOPSReport.csv")
	}
	if ($SetIOPS -and $HostVersion.Major -gt 5) {
		Write-Host "`n`nSetting all Tegile LUN IOPS Settings for host: $VMHost to $iopssetting...this will take some time...`n"
		$NeedChange = (Get-VMHost $VMHost | Get-ScsiLun -LunType disk | Where-Object {$_.Multipathpolicy -like "RoundRobin" -and $_.Vendor -eq "TEGILE" -and $_.CommandsToSwitchPath -ne $iopssetting})
		if ($NeedChange) {
			Write-Host "Number of LUNs on this host to adjust: "$NeedChange.Count
			$LUNSChanged = 0
			foreach ($ChangeIOPS in $NeedChange) {
				$ChangeReport = ($ChangeIOPS | Set-ScsiLun -CommandsToSwitchPath $iopssetting | Select-Object CanonicalName, MultipathPolicy, CommandsToSwitchPath, Vendor)
				$LUNSChanged++
				Write-Host "The script has set $LUNSChanged : "$ChangeIOPS.CanonicalName
			}
		} else {
			Write-Host "NO IOPS Setting Change Needed" -ForegroundColor Green
		}
		Write-Host "`n`nIOPS Setting complete for host: $VMHost to $iopssetting...collecting list to verify...`n"
		$LUNIOPSList = (Get-VMHost $VMHost | Get-ScsiLun -LunType disk | Where-Object {$_.Multipathpolicy -like "RoundRobin" -and $_.Vendor -eq "TEGILE"} | Select-Object CanonicalName, MultipathPolicy, CommandsToSwitchPath, Vendor)
		Write-Host "Host,LUN,MultipathPolicy,IOPS,Vendor,Change_Required"
		$IOPColor = "White"
		$IOPChange = "NO"
		foreach ($LUNIOPSetting in $LUNIOPSList) {
			#SET REPORT SETTINGS
			$CNAME = $LUNIOPSetting.CanonicalName
			$CMP = $LUNIOPSetting.MultipathPolicy
			$CIOPS = $LUNIOPSetting.CommandsToSwitchPath
			$CVendor = $LUNIOPSetting.Vendor
			if ($CIOPS -eq $iopssetting) {
				$IOPColor = "Green"
				$IOPChange = "NO"
				} else {
				$IOPColor = "Red"
				$IOPChange = "YES"
			}
			$CurrentIOPCheck = New-Object -TypeName PSObject
					$CurrentIOPCheck | Add-Member -Type NoteProperty -Name "Host" -Value $VMHost
					$CurrentIOPCheck | Add-Member -Type NoteProperty -Name "LUN" -Value $CNAME
					$CurrentIOPCheck | Add-Member -Type NoteProperty -Name "MultipathPolicy" -Value $CMP
					$CurrentIOPCheck | Add-Member -Type NoteProperty -Name "IOPS" -Value $CIOPS
					$CurrentIOPCheck | Add-Member -Type NoteProperty -Name "Vendor" -Value $CVendor
					$CurrentIOPCheck | Add-Member -Type NoteProperty -Name "Change Required" -Value $IOPChange
					$IOPSREPORT += $CurrentIOPCheck
			Write-Host "$VMHost,$CNAME,$CMP,$CIOPS,$CVendor,$IOPChange" -ForegroundColor $IOPColor
		}
		$IOPSREPORT | Export-Csv -NoTypeInformation -Append -Path $logpath.Replace(".log","-IOPSReport.csv")
	}

	if ($DatastorePathCheck -and $HostVersion.Major -gt 5) {
		write-host "`n`nChecking datastore / LUN paths...`n`n"

		$datastores = $VMHost | Get-Datastore | Where {$_.type -eq "vmfs"} | Get-View
		$HostTotalPaths = 0
		Write-Host "VMHost,Datastore,PathCount,Vendor"
		foreach ($datastore in $datastores){
			$LUNs = Get-ScsiLun -VmHost $VMHost.Name -CanonicalName $datastore.Info.Vmfs.Extent.DiskName | Where {$_.Vendor -eq "TEGILE" -and $_.VMHost -eq $VMHost}
			foreach ($LUN in $LUNs) {
				$Paths = $LUN | Get-ScsiLunPath
				$pathcount = 0
				foreach ($Path in $Paths) {
					Write-Verbose "$VMHost,$datastore,$LUN,$Path"
					$pathcount++
				}
				$Vendor = $LUN.Vendor
				$DSName = $datastore.Info.Vmfs.Name
				Write-Host "$VMHost,$DSName,$pathcount,$Vendor"
				$HostTotalPaths = $HostTotalPaths + $pathcount
				$currentdatastore = New-Object -TypeName PSObject
				$currentdatastore | Add-Member -Type NoteProperty -Name "Host" -Value $VMHost
				$currentdatastore | Add-Member -Type NoteProperty -Name "Datastore" -Value $DSName
				$currentdatastore | Add-Member -Type NoteProperty -Name "LUN" -Value $LUN
				$currentdatastore | Add-Member -Type NoteProperty -Name "Paths" -Value $pathcount
				$DATASTOREPATHREPORT += $currentdatastore
			}
		}
		Write-Verbose $DATASTOREPATHREPORT.ToString()
		$DATASTOREPATHREPORT | Export-Csv -NoTypeInformation -Append -Path $logpath.Replace(".log","-DatastorePathReport.csv")

		Write-Host "`n`n"
		Write-Host $VMHost.Name" has a total datastore path count of: $HostTotalPaths" -ForegroundColor Green
	}

	if ($RDMPathCheck -and $HostVersion.Major -gt 5) {
		write-host "`n`nChecking RDM / LUN paths...this can take some time...`n`n"
		$RDMs = (Get-VM | Get-HardDisk | Where {$_.DiskType -eq "RawPhysical"} | Select *)
		Write-Host "VMHost,VM,LunID,PathCount,Vendor"
		$HostTotalPaths = 0
		foreach ($RDM in $RDMs) {
			$LUNs = (Get-ScsiLun -CanonicalName $RDM.ScsiCanonicalName -VmHost $VMHost| Where {$_.Vendor -eq "TEGILE" -and $_.VMHost -eq $VMHost})
			$CurrentVM = $RDM.parent
			foreach ($TegileLUN in $LUNs) {
				$Paths = $TegileLUN | Get-ScsiLunPath
				$pathcount = 0
				foreach ($Path in $Paths) {
					Write-Verbose "$VMHost,$CurrentVM,$TegileLUN,$Path"
					$pathcount++
				}
				$Vendor = $TegileLUN.Vendor
				Write-Host "$VMHost,$CurrentVM,$TegileLUN,$pathcount,$Vendor"
				$HostTotalPaths = $HostTotalPaths + $pathcount
				$currentrdm = New-Object -TypeName PSObject
				$currentrdm | Add-Member -Type NoteProperty -Name "Host" -Value $VMHost
				$currentrdm | Add-Member -Type NoteProperty -Name "VM" -Value $CurrentVM
				$currentrdm | Add-Member -Type NoteProperty -Name "LunID" -Value $TegileLUN
				$currentrdm | Add-Member -Type NoteProperty -Name "PathCount" -Value $pathcount
				$RDMPATHREPORT += $currentrdm
			}
		}
		Write-Verbose $RDMPATHREPORT.ToString()
		$RDMPATHREPORT | Export-Csv -NoTypeInformation -Append -Path $logpath.Replace(".log","-RDMPathReport.csv")

		Write-Host "`n`n"
		Write-Host $VMHost.Name" has a total RDM path count of: $HostTotalPaths" -ForegroundColor Green
	}
	if ($HostPathCheck -and $HostVersion.Major -gt 5) {
		$HostRDMPaths = 0
		$HostDataStorePaths = 0
		write-host "`n`nChecking Host RDM paths...this can take some time...`n`n"
		$RDMs = (Get-VM | Get-HardDisk | Where {$_.DiskType -eq "RawPhysical"} | Select *)
		foreach ($RDM in $RDMs){
			$LUNs = (Get-ScsiLun -CanonicalName $RDM.ScsiCanonicalName -VmHost $VMHost | Where {$_.Vendor -eq "TEGILE" -and $_.VMHost -eq $VMHost})
			foreach ($TegileLUN in $LUNs) {
				$Paths = $TegileLUN | Get-ScsiLunPath
				$pathcount = 0
				foreach ($Path in $Paths) {
					$pathcount++
				}
				$HostRDMPaths = $HostRDMPaths + $pathcount
				Write-host "Discovered Host RDM Paths = $HostRDMPaths"
			}
		}

		Write-Host "`n`nChecking datastore paths...`n`n"
		$datastores = $VMHost | Get-Datastore | Where {$_.type -eq "vmfs"} | Get-View
		$HostDatastorePaths = 0
		foreach ($datastore in $datastores){
			$LUNs = Get-ScsiLun -VmHost $VMHost.Name -CanonicalName $datastore.Info.Vmfs.Extent.DiskName | Where {$_.Vendor -eq "TEGILE" -and $_.VMHost -eq $VMHost}
			foreach ($LUN in $LUNs) {
				$Paths = $LUN | Get-ScsiLunPath
				$pathcount = 0
				foreach ($Path in $Paths) {
					$pathcount++
				}
				$HostDatastorePaths = $HostDatastorePaths + $pathcount
				Write-Host "Discovered Datastore Paths = $HostDatastorePaths"
			}
		}

		$HostTotalPathCount = $HostDatastorePaths + $HostRDMPaths

		$HostPathCount = New-Object -TypeName PSObject
		$HostPathCount | Add-Member -Type NoteProperty -Name "Host" -Value $VMHost
		$HostPathCount | Add-Member -Type NoteProperty -Name "Tegile_RDM_Paths" -Value $HostRDMPaths
		$HostPathCount | Add-Member -Type NoteProperty -Name "Tegile_Datastore_Paths" -Value $HostDatastorePaths
		$HostPathCount | Add-Member -Type NoteProperty -Name "Total_Tegile_LUN_Paths" -Value $HostTotalPathCount
		$HOSTPATHREPORT += $HostPathCount
		Write-Verbose $HOSTPATHREPORT.ToString()
		$HOSTPATHREPORT | Export-Csv -NoTypeInformation -Append -Path $logpath.Replace(".log","-HostPathReport.csv")

		Write-Host "`n`n"
		Write-Host $VMHost.Name" has a total path count of: $HostTotalPathCount" -ForegroundColor Green
	}
	
	# Check/Apply NFS Best Practice settings if not overridden by -SkipNFS parameter
	if (!$SkipNFS) {
		Write-Host "`nChecking NFS Advanced Settings on host $VMHost...`n"
		$currentnfsqd = (Get-AdvancedSetting -Entity $VMHost -Name NFS.MaxQueueDepth | Select Entity,Name,Value)
		$currentnfsrpcto = (Get-AdvancedSetting -Entity $VMHost -Name NFS.DeleteRPCTimeout | Select Entity,Name,Value)
		$currentnfshbfreq = (Get-AdvancedSetting -Entity $VMHost -Name NFS.HeartbeatFrequency | Select Entity,Name,Value)
		if (!$SkipMaxVol) {
			$currentnfsmaxvols = (Get-AdvancedSetting -Entity $VMHost -Name NFS.MaxVolumes | Select Entity,Name,Value)
			$currentnetheapsize = (Get-AdvancedSetting -Entity $VMHost -Name Net.TcpipHeapSize | Select Entity,Name,Value)
			$currentnetheapmax = (Get-AdvancedSetting -Entity $VMHost -Name Net.TcpipHeapMax | Select Entity,Name,Value)
		}
		
		if ($currentnfsqd.Value -ne $nfsqueuedepth) {
			$currentval = $currentnfsqd.Value
			Write-Host "NFS.MaxQueueDepth is $currentval, but should be $nfsqueuedepth" -foregroundcolor red
			$changerequired = "Yes"
			$NFSCHANGES += "Get-AdvancedSetting -Entity $VMHost -Name NFS.MaxQueueDepth | Set-AdvancedSetting -Value '$nfsqueuedepth' -confirm:`$false`n"
		} else {
			Write-Host "NFS.MaxQueueDepth is already correctly set to $nfsqueuedepth" -foregroundcolor green
			$changerequired = "No"
		}
		$currentnfsqd | Add-Member -Type NoteProperty -Name "Script Value" -Value $nfsqueuedepth
		$currentnfsqd | Add-Member -Type NoteProperty -Name "Change Required" -Value $changerequired
		$HOSTREPORT += $currentnfsqd
		
		if ($currentnfsrpcto.Value -ne $nfsrpctimeout) {
			$currentval = $currentnfsrpcto.Value
			Write-Host "NFS.DeleteRPCTimeout is $currentval, but should be $nfsrpctimeout" -foregroundcolor red
			$changerequired = "Yes"
			$NFSCHANGES += "Get-AdvancedSetting -Entity $VMHost -Name NFS.DeleteRPCTimeout | Set-AdvancedSetting -Value '$nfsrpctimeout' -confirm:`$false`n"
		} else {
			Write-Host "NFS.DeleteRPCTimeout is already correctly set to $nfsrpctimeout" -foregroundcolor green
			$changerequired = "No"
		}
		$currentnfsrpcto | Add-Member -Type NoteProperty -Name "Script Value" -Value $nfsrpctimeout
		$currentnfsrpcto | Add-Member -Type NoteProperty -Name "Change Required" -Value $changerequired
		$HOSTREPORT += $currentnfsrpcto
		
		if ($currentnfshbfreq.Value -ne $nfsheartbeatfreq) {
		$currentval = $currentnfshbfreq.Value
			Write-Host "NFS.HeartbeatFrequency is $currentval, but should be $nfsheartbeatfreq" -foregroundcolor red
			$changerequired = "Yes"
			$NFSCHANGES += "Get-AdvancedSetting -Entity $VMHost -Name NFS.HeartbeatFrequency | Set-AdvancedSetting -Value '$nfsheartbeatfreq' -confirm:`$false`n"
		} else {
			Write-Host "NFS.HeartbeatFrequency is already correctly set to $nfsheartbeatfreq" -foregroundcolor green
			$changerequired = "No"
		}
		$currentnfshbfreq | Add-Member -Type NoteProperty -Name "Script Value" -Value $nfsheartbeatfreq
		$currentnfshbfreq | Add-Member -Type NoteProperty -Name "Change Required" -Value $changerequired
		$HOSTREPORT += $currentnfshbfreq
		
		if (!$SkipMaxVol) {
			if ($currentnfsmaxvols.Value -ne $nfsmaxvolumes) {
				$currentval = $currentnfsmaxvols.Value
				Write-Host "NFS.MaxVolumes is $currentval, but should be $nfsmaxvolumes" -foregroundcolor red
				$changerequired = "Yes"
				$NFSCHANGES += "Get-AdvancedSetting -Entity $VMHost -Name NFS.MaxVolumes | Set-AdvancedSetting -Value '$nfsmaxvolumes' -confirm:`$false`n"
			} else {
				Write-Host "NFS.MaxVolumes is already correctly set to $nfsmaxvolumes" -foregroundcolor green
				$changerequired = "No"
			}
			$currentnfsmaxvols | Add-Member -Type NoteProperty -Name "Script Value" -Value $nfsmaxvolumes
			$currentnfsmaxvols | Add-Member -Type NoteProperty -Name "Change Required" -Value $changerequired
			$HOSTREPORT += $currentnfsmaxvols
			
			if ($currentnetheapsize.Value -ne $nettcpipheapsize) {
				$currentval = $currentnetheapsize.Value
				Write-Host "Net.TcpipHeapSize is $currentval, but should be $nettcpipheapsize" -foregroundcolor red
				$changerequired = "Yes"
				$NFSCHANGES += "Get-AdvancedSetting -Entity $VMHost -Name Net.TcpipHeapSize | Set-AdvancedSetting -Value '$nettcpipheapsize' -confirm:`$false`n"
			} else {
				Write-Host "Net.TcpipHeapSize is already correctly set to $nettcpipheapsize" -foregroundcolor green
				$changerequired = "No"
			}
			$currentnetheapsize | Add-Member -Type NoteProperty -Name "Script Value" -Value $nettcpipheapsize
			$currentnetheapsize | Add-Member -Type NoteProperty -Name "Change Required" -Value $changerequired
			$HOSTREPORT += $currentnetheapsize
			
			$nettcpipheapmax = ""
			if ($VMHost.Version -eq "5.0.0") {
				$nettcpipheapmax = $nettcpipheapmax51
				Write-Host "Found ESXi version '5.0.0', preferred Net.TcpipHeapMax is $nettcpipheapmax"
			} elseif ($VMHost.Version -eq "5.1.0") {
				$nettcpipheapmax = $nettcpipheapmax51
				Write-Host "Found ESXi version '5.1.0', preferred Net.TcpipHeapMax is $nettcpipheapmax"
			} elseif ($VMHost.Version -eq "5.5.0") {
				$nettcpipheapmax = $nettcpipheapmax55
				Write-Host "Found ESXi version '5.5.0', preferred Net.TcpipHeapMax is $nettcpipheapmax"
			} elseif ($VMHost.Version -eq "6.0.0") {
				$nettcpipheapmax = $nettcpipheapmax6x
				Write-Host "Found ESXi version '6.0.0', preferred Net.TcpipHeapMax is $nettcpipheapmax"
			} elseif ($VMHost.Version -eq "6.5.0") {
				$nettcpipheapmax = $nettcpipheapmax6x
				Write-Host "Found ESXi version '6.5.0', preferred Net.TcpipHeapMax is $nettcpipheapmax"
			} elseif ($VMHost.Version -eq "6.7.0") {
				$nettcpipheapmax = $nettcpipheapmax6x
				Write-Host "Found ESXi version '6.7.0', preferred Net.TcpipHeapMax is $nettcpipheapmax"
			} else {
				Write-Host "`nUnable to determine appropriate Net.TcpipHeapMax setting for ESXi version:" $VMHost.version -foregroundcolor red
			}
			if (($nettcpipheapmax) -and ($currentnetheapmax.Value -ne $nettcpipheapmax)) {
				$currentval = $currentnetheapmax.Value
				Write-Host "Net.TcpipHeapMax is $currentval, but should be $nettcpipheapmax" -foregroundcolor red
				$changerequired = "Yes"
				$NFSCHANGES += "Get-AdvancedSetting -Entity $VMHost -Name Net.TcpipHeapMax | Set-AdvancedSetting -Value '$nettcpipheapmax' -confirm:`$false`n"
			} elseif ($nettcpipheapmax) {
				Write-Host "Net.TcpipHeapMax is already correctly set to $nettcpipheapmax" -foregroundcolor green
				$changerequired = "No"
			} else {
				Write-Host "`nUnknown Net.TcpipHeapMax version for your host version!" -foregroundcolor red
				Write-Host "Please update the script to support your ESXi version(s)`n" -foregroundcolor red
			}
			$currentnetheapmax | Add-Member -Type NoteProperty -Name "Script Value" -Value $nettcpipheapmax
			$currentnetheapmax | Add-Member -Type NoteProperty -Name "Change Required" -Value $changerequired
			$HOSTREPORT += $currentnetheapmax
		}
		
		if (!$SkipVAAI) {
			Write-Host "`nChecking for existing Tegile NAS VAAI Plugin on host $VMHost..."
			$tglplugin = ""
			$tglplugin = $esxcli.software.vib.list.Invoke() | Where-Object {$_.Name -eq "tgl-vaai-nas-diskplugin"}
			$currenttglplugin = New-Object -TypeName PSObject
			$currenttglplugin | Add-Member -Type NoteProperty -Name "Entity" -Value $VMHost
			$currenttglplugin | Add-Member -Type NoteProperty -Name "Name" -Value "Tegile NAS VAAI Plugin"

			if ($tglplugin) { 
				$currenttglplugin | Add-Member -Type NoteProperty -Name "Value" -Value $tglplugin.version
				$currentvaaipluginversion = $tglplugin.version
				if ($tglplugin.version -lt "$tegilepluginversion") {
					Write-Host "`nTegile NAS VAAI Plugin version $currentvaaipluginversion is installed" -foregroundcolor red
					Write-Host "`nThis is out of date and should be upgraded to version $tegilepluginversion" -foregroundcolor red
					$changerequired = "Yes"
					$NFSCHANGES += "`$esxcli.software.vib.install.Invoke(@{depot = `"$depotpath`"})`n"
				} elseif ($tglplugin.version -eq "$tegilepluginversion") {
					Write-Host "`nTegile NAS VAAI Plugin is already up to date with version $currentvaaipluginversion	" -foregroundcolor green
					$changerequired = "No"
				} elseif ($tglplugin.version -gt "$tegilepluginversion") {
					Write-Host "`nTegile NAS VAAI Plugin version $$currentvaaipluginversion is installed" -foregroundcolor red
					Write-Host "`nThis is newer than the version we have in this script: $tegilepluginversion" -foregroundcolor red
					$changerequired = "Maybe"
					}
			} else {
				Write-Host "`nTegile NAS VAAI Plugin is not currently installed, you should install version $tegilepluginversion" -foregroundcolor red
				$changerequired = "Yes"
				$NFSCHANGES += "`$esxcli.software.vib.install.Invoke(@{depot = `"$depotpath`"})`n"
				$currenttglplugin | Add-Member -Type NoteProperty -Name "Value" -Value "missing"
			}
			$currenttglplugin | Add-Member -Type NoteProperty -Name "Script Value" -Value $tegilepluginversion
			$currenttglplugin | Add-Member -Type NoteProperty -Name "Change Required" -Value $changerequired
			$HOSTREPORT += $currenttglplugin
			# Convert Key values to desired strings ("Entity" to "Host", "Setting to "Current Value"):
		}	
		$HOSTREPORT = $HOSTREPORT | Select @{N="Host";E={$_.Entity}},@{N="Setting";E={$_.Name}},@{N="Current Value";E={$_.Value}},"Script Value","Change Required"
	}
	
	# Check/Apply SATP rules and VMFS Heartbeat if not overridden by -SkipBlock (or later -SkipATS) parameter
	# Note that we do this linearly due to the required hash table format for the rules with Get-EsxCli -V2
	# Versus where we easily apply all changes at once as we do later with NFS settings
	if (!$SkipBlock) {
		$iopsparam = "iops=" + $iopssetting
		# Set variables to specify which rules are applied by default - if they don't already exist with correct parameters:
		$tegilealuarule = 1
		$tegilenonaluarule = 1
		if ($LegacySATP) {
			$tegilelegacyiscsi = 1
			$tegilelegacyfc = 1
		} else {
			$tegilelegacyiscsi = 0
			$tegilelegacyfc = 0
		}
		
		# Find any SATP rules with Vendor name "TEGILE":
		Write-Host "`nChecking SATP rules on host $VMHost..."
		$satprules = $esxcli.storage.nmp.satp.rule.list.invoke() | Where-Object {$_.Vendor -eq "TEGILE"} | Select Vendor,Model,Name,DefaultPSP,ClaimOPtions,Description,PSPOptions
		
		if ($satprules) {
			Write-Host "`n`nFound the following existing Tegile IntelliFlash SATP rules`n"
			$satprules
			foreach ($rule in $satprules) {
				Write-Host "`nChecking rule:"
				$rule
				if ($rule.Description -eq "Tegile arrays with ALUA support") {
					Write-Host "`This is the current ALUA rule, used only for IntelliFlash LUN's with ALUA support"
					if (($rule.Name -ne "VMW_SATP_ALUA") -or ($rule.Model -ne "INTELLIFLASH") -or ($rule.DefaultPSP -ne "VMW_PSP_RR") -or ($rule.PSPOptions -ne $iopsparam) -or ($rule.ClaimOptions -ne "tpgs_on")) {
						Write-Host "`nThis rule has one or more invalid settings and should be removed & replaced!" -foregroundcolor red
						$changerequired = "Yes"
						$tegilealuarule = 1
					} else {
						Write-Host "`nThis existing rule looks good" -foregroundcolor green
						$changerequired = "No"
						$tegilealuarule = 0
					}
					$currentsatp = New-Object -TypeName PSObject
					$currentsatp | Add-Member -Type NoteProperty -Name "Host" -Value $VMHost
					$currentsatp | Add-Member -Type NoteProperty -Name "Setting" -Value "Current Tegile SATP ALUA rule"
					$currentsatp | Add-Member -Type NoteProperty -Name "Current Value" -Value $rule
					$currentsatp | Add-Member -Type NoteProperty -Name "Script value" -Value "@{Vendor=TEGILE; Model=INTELLIFLASH; Name=VMW_SATP_ALUA; DefaultPSP=VMW_PSP_RR; ClaimOptions=tpgs_on; Description=Tegile arrays with ALUA support; PSPOptions=$iopsparam}"
					$currentsatp | Add-Member -Type NoteProperty -Name "Change Required" -Value $changerequired
				}
				if ($rule.Description -eq "Tegile arrays without ALUA support") {
					Write-Host "`This is the current Non-ALUA rule, used only for IntelliFlash LUN's without ALUA support"
					if (($rule.Name -ne "VMW_SATP_DEFAULT_AA") -or ($rule.Model -ne "INTELLIFLASH") -or ($rule.DefaultPSP -ne "VMW_PSP_RR") -or ($rule.PSPOptions -ne $iopsparam) -or ($rule.ClaimOptions -ne "tpgs_off")) {
						Write-Host "`nThis rule has one or more invalid settings and should be removed & replaced!" -foregroundcolor red
						$changerequired = "Yes"
						$tegilenonaluarule = 1
					} else {
						Write-Host "`nThe existing rule looks good" -foregroundcolor green
						$changerequired = "No"
						$tegilenonaluarule = 0
					}
					$currentsatp = New-Object -TypeName PSObject
					$currentsatp | Add-Member -Type NoteProperty -Name "Host" -Value $VMHost
					$currentsatp | Add-Member -Type NoteProperty -Name "Setting" -Value "Current Tegile SATP Non-ALUA rule"
					$currentsatp | Add-Member -Type NoteProperty -Name "Current Value" -Value $rule
					$currentsatp | Add-Member -Type NoteProperty -Name "Script value" -Value "@{Vendor=TEGILE; Model=INTELLIFLASH; Name=VMW_SATP_DEFAULT_AA; DefaultPSP=VMW_PSP_RR; ClaimOptions=tpgs_off; Description=Tegile arrays without ALUA support; PSPOptions=$iopsparam}"
					$currentsatp | Add-Member -Type NoteProperty -Name "Change Required" -Value $changerequired
				}
				if ($rule.Description -eq "Tegile Zebi FC") {
					Write-Host "`This is a legacy rule, still required for any FC LUN's created prior to IntelliFlash 3.x"
					if (($rule.Name -ne "VMW_SATP_ALUA") -or ($rule.Model -ne "ZEBI-FC") -or ($rule.DefaultPSP -ne "VMW_PSP_RR") -or ($rule.PSPOptions -ne $iopsparam) -or ($rule.ClaimOptions -ne "tpgs_on")) {
						Write-Host "`nThis rule has one or more invalid settings and should be removed & replaced!" -foregroundcolor red
						$changerequired = "Yes"
						$tegilelegacyfc = 1
					} else {
						Write-Host "`nThis existing rule looks good" -foregroundcolor green
						$changerequired = "No"
						$tegilelegacyfc = 0
					}
					$currentsatp = New-Object -TypeName PSObject
					$currentsatp | Add-Member -Type NoteProperty -Name "Host" -Value $VMHost
					$currentsatp | Add-Member -Type NoteProperty -Name "Setting" -Value "Legacy Tegile SATP FC ALUA rule"
					$currentsatp | Add-Member -Type NoteProperty -Name "Current Value" -Value $rule
					$currentsatp | Add-Member -Type NoteProperty -Name "Script value" -Value "@{Vendor=TEGILE; Model=ZEBI-FC; Name=VMW_SATP_ALUA; DefaultPSP=VMW_PSP_RR; ClaimOptions=tpgs_on; Description=Tegile Zebi FC; PSPOptions=$iopsparam}"
					$currentsatp | Add-Member -Type NoteProperty -Name "Change Required" -Value $changerequired
				}				
				if ($rule.Description -eq "Tegile Zebi iSCSI") {
					Write-Host "`This is a legacy rule, still required for any iSCSI LUN's created prior to IntelliFlash 3.x"
					if (($rule.Name -ne "VMW_SATP_DEFAULT_AA") -or ($rule.Model -ne "ZEBI-ISCSI") -or ($rule.DefaultPSP -ne "VMW_PSP_RR") -or ($rule.PSPOptions -ne $iopsparam) -or ($rule.ClaimOptions)) {
						Write-Host "`nThis rule has one or more invalid settings and should be removed and replaced!" -foregroundcolor red
						$changerequired = "Yes"
						$tegilelegacyiscsi = 1
					} else {
						Write-Host "`nThis existing rule looks good" -foregroundcolor green
						$changerequired = "No"
						$tegilelegacyiscsi = 0
					}
					$currentsatp = New-Object -TypeName PSObject
					$currentsatp | Add-Member -Type NoteProperty -Name "Host" -Value $VMHost
					$currentsatp | Add-Member -Type NoteProperty -Name "Setting" -Value "Legacy Tegile SATP iSCSI Non-ALUA rule"
					$currentsatp | Add-Member -Type NoteProperty -Name "Current Value" -Value $rule
					$currentsatp | Add-Member -Type NoteProperty -Name "Script value" -Value "@{Vendor=TEGILE; Model=ZEBI-ISCSI; Name=VMW_SATP_DEFAULT_AA; DefaultPSP=VMW_PSP_RR; ClaimOptions=; Description=Tegile Zebi iSCSI; PSPOptions=$iopsparam}"
					$currentsatp | Add-Member -Type NoteProperty -Name "Change Required" -Value $changerequired
				}
				# Catching unknown rule with Vendor set as TEGILE:
				if (($rule.Description -ne "Tegile arrays with ALUA support") -and ($rule.Description -ne "Tegile arrays without ALUA support") -and ($rule.Description -ne "Tegile Zebi FC") -and ($rule.Description -ne "Tegile Zebi iSCSI")) {
					Write-Host "`nThis Tegile SATP rule does not have a valid Description property, and will thus be removed!" -foregroundcolor red
					$changerequired = "Yes"
					$currentsatp = New-Object -TypeName PSObject
					$currentsatp | Add-Member -Type NoteProperty -Name "Host" -Value $VMHost
					$currentsatp | Add-Member -Type NoteProperty -Name "Setting" -Value "Unknown SATP rule with Vendor set as TEGILE"
					$currentsatp | Add-Member -Type NoteProperty -Name "Current Value" -Value $rule
					$currentsatp | Add-Member -Type NoteProperty -Name "Script value" -Value "Not Applicable - Unknown current rule to compare to"
					$currentsatp | Add-Member -Type NoteProperty -Name "Change Required" -Value $changerequired
				}
				$HOSTREPORT += $currentsatp
				
				if (($changerequired -eq "Yes") -and (!$ReportOnly)) {
					$satpparams = $esxcli.storage.nmp.satp.rule.remove.createArgs()
					$satpparams.model = $rule.Model
					$satpparams.vendor = $rule.Vendor
					$satpparams.satp = $rule.Name
					$satpparams.psp = $rule.DefaultPSP
					if ($rule.claimoptions -ne "") {$satpparams.claimoption = $rule.ClaimOptions}
					$satpparams.pspoption = $rule.PSPOptions
					$satpremoval = $esxcli.storage.nmp.satp.rule.remove.invoke($satpparams)
					if ($satpremoval -eq $true) {
						Write-Host "Removal of invalid rule successful!" -foregroundcolor green
						Write-Host "If host already has LUN's presented for which this rule applied, a reboot is required!" -foregroundcolor yellow
					} else {
						Write-Host "`nIt seems the removal of the invalid rule did not succeed..." -foregroundcolor red
					}
				} else {
					Write-Host "`nNo changes will be made to this rule" -foregroundcolor green
				}
			}
		}
		# Reporting if any individual rules are missing altogether:
		if ($satprules.Description -notcontains "Tegile arrays with ALUA support") {
			Write-Host "`nThe current ALUA rule is missing" -foregroundcolor red
			$tegilealuarule = "1"
			$changerequired = "Yes"
			$currentsatp = New-Object -TypeName PSObject
			$currentsatp | Add-Member -Type NoteProperty -Name "Host" -Value $VMHost
			$currentsatp | Add-Member -Type NoteProperty -Name "Setting" -Value "Current Tegile SATP ALUA rule"
			$currentsatp | Add-Member -Type NoteProperty -Name "Current Value" -Value "missing"
			$currentsatp | Add-Member -Type NoteProperty -Name "Script value" -Value "@{Vendor=TEGILE; Model=INTELLIFLASH; Name=VMW_SATP_ALUA; DefaultPSP=VMW_PSP_RR; ClaimOptions=tpgs_on; Description=Tegile arrays with ALUA support; PSPOptions=$iopsparam}"
			$currentsatp | Add-Member -Type NoteProperty -Name "Change Required" -Value $changerequired
			$HOSTREPORT += $currentsatp
		}
		if ($satprules.Description -notcontains "Tegile arrays without ALUA support") {
			Write-Host "`nThe current non-ALUA rule is missing" -foregroundcolor red
			$tegilenonaluarule = "1"
			$changerequired = "Yes"
			$currentsatp = New-Object -TypeName PSObject
			$currentsatp | Add-Member -Type NoteProperty -Name "Host" -Value $VMHost
			$currentsatp | Add-Member -Type NoteProperty -Name "Setting" -Value "Current Tegile SATP Non-ALUA rule"
			$currentsatp | Add-Member -Type NoteProperty -Name "Current Value" -Value "missing"
			$currentsatp | Add-Member -Type NoteProperty -Name "Script value" -Value "@{Vendor=TEGILE; Model=INTELLIFLASH; Name=VMW_SATP_DEFAULT_AA; DefaultPSP=VMW_PSP_RR; ClaimOptions=tpgs_off; Description=Tegile arrays without ALUA support; PSPOptions=$iopsparam}"
			$currentsatp | Add-Member -Type NoteProperty -Name "Change Required" -Value $changerequired
			$HOSTREPORT += $currentsatp
		}
		if (($satprules.Description -notcontains "Tegile Zebi FC") -and ($LegacySATP)) {
			Write-Host "`nThe Legacy FC rule is missing" -foregroundcolor red
			$tegilelegacyfc = "1"
			$changerequired = "Yes"
			$currentsatp = New-Object -TypeName PSObject
			$currentsatp | Add-Member -Type NoteProperty -Name "Host" -Value $VMHost
			$currentsatp | Add-Member -Type NoteProperty -Name "Setting" -Value "Legacy Tegile SATP FC ALUA rule"
			$currentsatp | Add-Member -Type NoteProperty -Name "Current Value" -Value "missing"
			$currentsatp | Add-Member -Type NoteProperty -Name "Script value" -Value "@{Vendor=TEGILE; Model=ZEBI-FC; Name=VMW_SATP_ALUA; DefaultPSP=VMW_PSP_RR; ClaimOptions=tpgs_on; Description=Tegile Zebi FC; PSPOptions=$iopsparam}"
			$currentsatp | Add-Member -Type NoteProperty -Name "Change Required" -Value $changerequired
			$HOSTREPORT += $currentsatp
		}
		if (($satprules.Description -notcontains "Tegile Zebi iSCSI") -and ($LegacySATP)) {
			Write-Host "`nThe Legacy iSCSI rule is missing" -foregroundcolor red
			$tegilelegacyiscsi = "1"
			$changerequired = "Yes"
			$currentsatp = New-Object -TypeName PSObject
			$currentsatp | Add-Member -Type NoteProperty -Name "Host" -Value $VMHost
			$currentsatp | Add-Member -Type NoteProperty -Name "Setting" -Value "Legacy Tegile SATP iSCSI Non-ALUA rule"
			$currentsatp | Add-Member -Type NoteProperty -Name "Current Value" -Value "missing"
			$currentsatp | Add-Member -Type NoteProperty -Name "Script value" -Value "@{Vendor=TEGILE; Model=ZEBI-ISCSI; Name=VMW_SATP_DEFAULT_AA; DefaultPSP=VMW_PSP_RR; ClaimOptions=; Description=Tegile Zebi iSCSI; PSPOptions=$iopsparam}"
			$currentsatp | Add-Member -Type NoteProperty -Name "Change Required" -Value $changerequired
			$HOSTREPORT += $currentsatp
		}
		
		# Start applying missing rules:
		if (($tegilealuarule -eq 1) -and (!$ReportOnly)) {
			Write-Host "`n---------------------------------------------------------------------"
			Write-Host "We need to add the modern Tegile IntelliFlash ALUA rule" -foregroundcolor yellow
			Write-Host "Creating new rule to set Round Robin and an IO Operations Limit of $iopssetting..."
			$satpparams = $esxcli.storage.nmp.satp.rule.add.createArgs()
			$satpparams.description = "Tegile arrays with ALUA support"
			$satpparams.model = "INTELLIFLASH"
			$satpparams.vendor = "TEGILE"
			$satpparams.satp = "VMW_SATP_ALUA"
			$satpparams.psp = "VMW_PSP_RR"
			$satpparams.claimoption = "tpgs_on"
			$satpparams.pspoption = $iopsparam
			Write-Host "Adding rule to host $VMHost..."
			$result = $esxcli.storage.nmp.satp.rule.add.invoke($satpparams)
			if ($result -eq $true) {
				Write-Host "Successfully added this rule!" -foregroundcolor green
				Write-Host "If host already has LUN's presented for which this rule applies, a reboot is required!" -foregroundcolor yellow
			} else {
				Write-Host "Something went wrong when adding rule, manual intervention probably required here!" -foregroundcolor red
			}
		}
		if (($tegilenonaluarule -eq 1) -and (!$ReportOnly)) {
			Write-Host "`n---------------------------------------------------------------------"
			Write-Host "We need to add the modern Tegile IntelliFlash Non-ALUA rule" -foregroundcolor yellow
			Write-Host "Creating new rule to set Round Robin and an IO Operations Limit of $iopssetting..."
			$satpparams = $esxcli.storage.nmp.satp.rule.add.createArgs()
			$satpparams.description = "Tegile arrays without ALUA support"
			$satpparams.model = "INTELLIFLASH"
			$satpparams.vendor = "TEGILE"
			$satpparams.satp = "VMW_SATP_DEFAULT_AA"
			$satpparams.psp = "VMW_PSP_RR"
			$satpparams.claimoption = "tpgs_off"
			$satpparams.pspoption = $iopsparam
			Write-Host "Adding rule to host $VMHost..."
			$result = $esxcli.storage.nmp.satp.rule.add.invoke($satpparams)
			if ($result -eq $true) {
				Write-Host "Successfully added this rule!" -foregroundcolor green
				Write-Host "If host already has LUN's presented for which this rule applies, a reboot is required!" -foregroundcolor yellow
			} else {
				Write-Host "Something went wrong when adding rule, manual intervention probably required here!" -foregroundcolor red
			}
		}
		if (($tegilelegacyfc -eq 1) -and (!$ReportOnly)) {
			Write-Host "`n---------------------------------------------------------------------"
			Write-Host "We need to add the legacy Tegile IntelliFlash FC ALUA rule" -foregroundcolor yellow
			Write-Host "Creating new rule to set Round Robin and an IO Operations Limit of $iopssetting..."
			$satpparams = $esxcli.storage.nmp.satp.rule.add.createArgs()
			$satpparams.description = "Tegile Zebi FC"
			$satpparams.model = "ZEBI-FC"
			$satpparams.vendor = "TEGILE"
			$satpparams.satp = "VMW_SATP_ALUA"
			$satpparams.psp = "VMW_PSP_RR"
			$satpparams.claimoption = "tpgs_on"
			$satpparams.pspoption = $iopsparam
			Write-Host "Adding rule to host $VMHost..."
			$result = $esxcli.storage.nmp.satp.rule.add.invoke($satpparams)
			if ($result -eq $true) {
				Write-Host "Successfully added this rule!" -foregroundcolor green
				Write-Host "If host already has LUN's presented for which this rule applies, a reboot is required!" -foregroundcolor yellow
			} else {
				Write-Host "Something went wrong when adding rule, manual intervention probably required here!" -foregroundcolor red
			}
		}
		if (($tegilelegacyiscsi -eq 1) -and (!$ReportOnly)) {
			Write-Host "`n---------------------------------------------------------------------"
			Write-Host "We need to add the legacy Tegile IntelliFlash iSCSI Non-ALUA rule" -foregroundcolor yellow
			Write-Host "Creating new rule to set Round Robin and an IO Operations Limit of $iopssetting..."
			$satpparams = $esxcli.storage.nmp.satp.rule.add.createArgs()
			$satpparams.description = "Tegile Zebi iSCSI"
			$satpparams.model = "ZEBI-ISCSI"
			$satpparams.vendor = "TEGILE"
			$satpparams.satp = "VMW_SATP_DEFAULT_AA"
			$satpparams.psp = "VMW_PSP_RR"
			$satpparams.pspoption = $iopsparam
			Write-Host "Adding rule to host $VMHost..."
			$result = $esxcli.storage.nmp.satp.rule.add.invoke($satpparams)
			if ($result -eq $true) {
				Write-Host "Successfully added this rule!" -foregroundcolor green
				Write-Host "If host already has LUN's presented for which this rule applies, a reboot is required!" -foregroundcolor yellow
			} else {
				Write-Host "Something went wrong when adding rule, manual intervention probably required here!" -foregroundcolor red
			}
		}
		
		if (!$SkipATS) {
			# Check ATS for VMFS Heartbeat setting, disable it if not in ReportOnly mode and it's currently enabled:
			Write-Host "`nChecking to make sure that VMFS Heartbeat is not using ATS..."
			$currentvmfshb = (Get-AdvancedSetting -Entity $VMHost -Name VMFS3.UseATSForHBOnVMFS5 | Select Entity,Name,Value)
			if ($currentvmfshb.Value -ne "$tegilevmfshb") {
				Write-Host "`nVMFS Heartbeat is currently set to use ATS, this needs to be disabled!" -foregroundcolor red
				$changerequired = "Yes"
			} else {
				Write-Host "`nIt looks like VMFS Heartbeat is not set to use ATS which is good!" -foregroundcolor green
				$changerequired = "No"
			}
			# Convert Key values to desired strings ("Entity" to "Host", "Setting to "Current Value"):
			$currentvmfshb = $currentvmfshb | Select @{N="Host";E={$_.Entity}},@{N="Setting";E={$_.Name}},@{N="Current Value";E={$_.Value}}
			$currentvmfshb | Add-Member -Type NoteProperty -Name "Script Value" -Value "$tegilevmfshb"
			$currentvmfshb | Add-Member -Type NoteProperty -Name "Change Required" -Value "$changerequired"
			$HOSTREPORT += $currentvmfshb
			# Apply changes if necessary and allowed:
			if (($changerequired -eq "Yes") -and (!$ReportOnly)) {
				Write-Host "`nDisabling ATS for VMFS Heartbeat..."
				$result = Get-AdvancedSetting -Entity $VMHost -Name VMFS3.UseATSForHBOnVMFS5 | Set-AdvancedSetting -Value $tegilevmfshb -Confirm:$false -WarningAction Ignore
				if ($result.Value -eq "$tegilevmfshb") {
					Write-Host "`nSuccessfully changed ATS for VMFS Heartbeat to '$tegilevmfshb'!" -foregroundcolor green
				} else {
					Write-Host "`nLooks like we failed to change the ATS for VMFS Heartbeat setting, manual intervention required!" -foregroundcolor red
				}
			}
		}
	}
	
	$HOSTREPORT | Export-Csv -NoTypeInformation -Append -Path $logpath.Replace(".log","-Report.csv")
	
	# Apply NFS BP changes if any are needed, as designated by contents of $NFSCHANGES:
	if ((!$ReportOnly) -and ($NFSCHANGES)) {
		Write-Host "`n---------------------------------------------------------------------"
		Write-Host "Host $VMHost needs the following NFS Best Practice changes applied:`n" -foregroundcolor red
		Write-Host "$NFSCHANGES" -foregroundcolor yellow
		if (!$AutoApply) {
			$answer = Read-Host "Please enter 'y' if you want to apply changes, or Enter to skip to next host"
		} else {
			$answer = "y"
		}
		if ($answer -eq "y") {
			if (!$AutoApply) {
				# We're going to apply changes, so make sure host is in Maintenance Mode:
				$VMHostState = (Get-VMHost -Name $VMHost | Where-Object {$_.ConnectionState -eq "Maintenance"}).ConnectionState
				if ($VMHostState -ne "Maintenance") {
					Write-Host "`nHost $VMHost is not in Maintenance Mode, but it should be!" -foregroundcolor red
					Write-Host "`nWe can place $VMHost in Maintenance Mode now if you'd like?`n" -foregroundcolor yellow
					$answerm = Read-Host "Enter 'm' to do so, 's' to skip entering maintenance, anything else to cancel script"
					if ($answerm -eq "m") {
						Write-Host "`nAttempting to put host $VMHost into Maintenance Mode..."
						$maintenance = Set-VMHost -Host $VMHost -State Maintenance
						if ($maintenance.ConnectionState -ne "Maintenance") {
							Write-Host "`nFailed to enter Maintenance Mode, check your host. Exiting script...`n" -foregroundcolor red
							$continue = Read-Host "Enter 'y' to continue anyway, enter to exit"
							if ($continue = "y") {
								Write-Host "`nContinuing and applying changes anyway..."
							} else {
								Stop-Transcript
								Exit 1
							}
						} else {
							Write-Host "`nHost $VMHost successfully entered Maintenance Mode!`n"
						}
					} elseif ($answerm -ne "s") {
						Write-Host "`nExiting script...`n" -foregroundcolor yellow
						Stop-Transcript			
						Exit 1
					} else {
						Write-Host "`nContinuing and applying changes without putting host $VMHost into Maintenance Mode..."
					}
				}
			} else {
				Write-Host "`nAutomatically applying settings due to -AutoApply switch...`n" -foregroundcolor yellow
			}
			Write-Progress -Activity "Applying Best-Practice Settings" -Status "Applying..."
			Invoke-Expression $NFSCHANGES
			Write-Progress -Activity "Applying Best-Practice Settings" -Status "Checking..." -Completed
			Write-Host "`nLook above to make sure changes were applied successfully!" -foregroundcolor yellow
			Write-Host "`nChanges were applied to your host, and it should probably be rebooted now!" -foregroundcolor yellow
			if (!$AutoApply) {
				Write-Host "`nPlease reboot host and then take it out of Maintenance Mode before continuing!`n" -foregroundcolor yellow
				Read-Host "Awaiting your command, press Enter to continue with next host..."
			}
			Write-Host "`nContinuing to next host..."
		} else {
			Write-Host "`nSkipping application of required changes to host $VMHost..."
		}
	} elseif ($ReportOnly) {
		Write-Host "`nReport Only mode, skipping application of any changes and continuing...`n"
	} else {
		Write-Host "`nNo additional changes needed for host $VMHost`n"
	}
	
	Write-Host "`Finished with host $VMHost, continuing...`n"
}
Write-Host "`nCompleted checking/updating all hosts!`n" -foregroundcolor green
Write-Host "`nHost Report and Log files are available in: $logdir`n" -foregroundcolor yellow
Stop-Transcript
