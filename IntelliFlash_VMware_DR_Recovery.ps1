<#
.SYNOPSIS
For quick recovery of VM's in DR site, leveraging IntelliFlash API to clone
 Replica datastores, and PowerCLI to mount them, register, and power-up VM's

.DESCRIPTION
This script will allow you to connect to vCenter, or a standalone host, and your IntelliFlash array, to recover VM's
 from replica snapshots via API calls to clone replica projects, mount datastores, register and optionally power on VM's

*Notice: No support for this is implied or provided. No warranty or liability for any damage or loss due to its use is provided by Western Digitial Corporation or any of its divisions or subsidiaries.

*Important: This script Requires that the Tegile cmdlet be imported and all commands within it available: Import-Module .\Tegile_IntelliFlash_cmdlet.psm1

This has to be run separately for Projects in different IntelliFlash Pools. Know which pool your Projects are in, and thus just run this twice if your DR array is Active/Active.

Does not support "switching replication source" on Reversible replication jobs - only Clones from latest replica snapshot today

Does not support changing Block protocol on target. E.g. if source is Fibre Channel, this only works with target that has/supports Fibre Channel, it cannot change to iSCSI for clones.

Does not support simultaneous iSCSI and FC support. If you'll be cloning Project(s) with LUN's, then for any given run it must be either iSCSI or FC not both.

Along the same lines as the above, if you specify Target/Initiator Groups for the incorrect or mismatched protocol or pool then things will just fail.

Same goes for getting group names and/or NFSServerIP correct for the pool. If you get them wrong you'll get plenty of errors.

Mixing one Block protocol and NFS with the same run is supported, e.g. if you have Generic Projects that contain NFS & iSCSI datasets, or separate Projects for each.

It's also absolutely necessary that none of the Projects/Datasets be already present/mounted as datastores on your target vSphere infrastructure. Duplicates are not accounted for so things will fail.

For either iSCSI or FC, you need to make sure things are all configured and working in advance. E.g. iSCSI initiator discovery IP(s), FC zoning, Target & Initiator group configuration validated, etc.

Same goes for NFS. Just test your setup in advance and if you can mount a datastore of a given protocol successfully the old fashioned way then this script should work.

This makes the assumption that all .vmx files are accurately named the same as the VM display name. Keep your vm folders and files named consistently, and don't rename VM's!

Similarly, this makes the assumption that LUN/Share names match Datastore names precisely, case-sensitive. If they don't, fix them on source first!

This will automatically attempt to register *all* VM's found in *all* cloned/mounted datastores. If you have unwanted VM's still in the datastores, you'll want to clean those up on source first.

All VM Networks from source vSphere environment need to exist on recovery hosts, otherwise Power On will definitely fail and you'll have to manually fix networking before powering on VM's.

Requires PowerShell version 5 or better, and PowerCLI version 10 or better

Tested with vSphere 6.7u1. It will probably work with many earlier versions as well, but like everything else in this script there are no guarantees!

This script has several parameters, which will autocomplete after '-':

	*Mandatory:
	-Projects | Comma-separated list of IntelliFlash Projects which you wish to recover
	-Array | Specify the IP or FQDN of the IntelliFlash array hosting the Replica(s) you wish to clone
	-VCServer | Specify the IP or FQDN of the vCenter Server or ESXi Host
	
	*Optional:
	-NFSServerIP | NFS Server IP for mounting NFS datastores (from IntelliFlash array, see High Availability page and look for IP associated with pool from which you're cloning)
	-NACLHost | Comma-separated list of Host VMkernel IP's or subnet to provide r/w/root NFS access (required for NFS datastores; can specify /24 subnet like: 10.42.42.0, CIDR not yet supported)
	-TargetGroup | Target Group to which to map access for any/all Projects which have LUN's
	-InitiatorGroup | Comma-separated list of Initiator Group(s) to which to map access for any/all Projects which have LUN's
	-Cluster | Specify a specific cluster (or even a folder) rather than the default which is to select first host from all available to use for registering VM's
	-VMHost | Specify a specific ESXi Host to use for registering the VM's, rather than the default which is to use the first host listed
	-PowerOn | Power up the VM's after registering them (which will also automatically answer the moved/copied question with "moved") - Default is to leave Powered Off
	-ScanWait | For Block/VMFS datastores only, this sets the number of seconds to wait between rescan/check for LUN attach/mount. Default is 2 seconds, some environments may need longer for attach/mount to succeed.
	-AcceptDisclaimer | Accept the disclaimer without being prompted to do so within the script - you accept all responsibility anyway!
	-VCUser | Optionally specify the user account for vCenter or Host connectivity
	-VCPassword | Optionally specify the password for the designated user account
	-IFUser | Optionally specify the IntelliFlash user account
	-IFPassword | Optionally specify the IntelliFlash password
	-Version (alias: -ver, -v) | Returns script version

.EXAMPLE
.\IntelliFlash_VMware_DR_Recovery.ps1 -Projects VMware-Prod,VMware-Test -NACLHost 192.168.240.0 -Array 10.42.42.42 -NFSServerIP 192.168.240.42 -VCServer vc1.wdc.local
Connects to the vCenter server vc1.wdc.local, and clones latest replica snapshot of specified projects,
sets NFS NACL's as specified, then mounts all NFS shares from those clones as datastores using server IP specified,
on all hosts, and finally finds and registers all VM's from those datastores.

.EXAMPLE
.\IntelliFlash_VMware_DR_Recovery.ps1 -Projects VMware-Prod,VMware-Test -NACLHost 192.168.240.0 -Array 10.42.42.42 -NFSServerIP 192.168.240.42 -VCServer vc1.wdc.local -Cluster Production -VMHost 10.42.42.44 -PowerOn
Connects to the vCenter server vc1.wdc.local, and clones latest replica snapshot of specified projects,
sets NFS NACL's as specified, then mounts all NFS shares from those clones as datastores using server IP specified,
on only hosts in specified cluster (or host folder), and finds and registers all VM's from those datastores on just
the host specified. Then it powers on all VM's succesffully registered, and answers VM question with "moved".

.EXAMPLE
.\IntelliFlash_VMware_DR_Recovery.ps1 -Array 10.42.42.42 -VCServer vc1.wdc.local -Projects VMware-Prod-NFS,VMware-Prod-iSCSI -NACLHost 192.168.240.101,192.168.240.102 -NFSServerIP 192.168.240.42 -TargetGroup default-pool-a-iscsi-target-group -InitiatorGroup ESX-DR -PowerOn
Similar to previous example, but includes Project with both NFS & iSCSI datasets,
and thus also the associated Target/Initiator groups for which to add mapping

.LINK
http://www.westerndigital.com/
#>

[CmdletBinding(ConfirmImpact='Medium')]

	Param(
		[Parameter(Mandatory=$true)]
		[String]
		$Array,
		[Parameter(Mandatory=$true)]
		[String]
		$VCServer,
		[Parameter(Mandatory=$true)]
		[String[]]
		$Projects,
		[Parameter()]
		[String]
		$NFSServerIP,
		[Parameter()]
		[String[]]
		$NACLHost,
		[Parameter()]
		[String]
		$TargetGroup,
		[Parameter()]
		[String[]]
		$InitiatorGroup,
		[Parameter()]
		[String]
		$VMHost,
		[Parameter()]
		[String]
		$Cluster,
		[Parameter()]
		[Switch]
		$PowerOn,
		[Parameter()]
		[String]
		$ScanWait,
		[Parameter()]
		[String]
		$VCUser,
		[Parameter()]
		[String]
		$VCPassword,
		[Parameter()]
		[String]
		$IFUser,
		[Parameter()]
		[String]
		$IFPassword,
		[Parameter()]
		[Alias("v")] 
		[Alias("ver")] 
		[Switch]
		$Version,
		[Parameter()]
		[Switch]
		$AcceptDisclaimer
	)

# This script is supported on a best-effort only
# Script Version:
$MajorVer = 3
$MinorVer = 7
$PatchVer = 1
$BuildVer = 4
$VerMonth = 02
$VerDay = 13
$VerYear = 2019
$Author = "Ben Kendall, WDC DCS IntelliFlash Professional Services"

$VerMonthName = (Get-Culture).DateTimeFormat.GetAbbreviatedMonthName($VerMonth)

# Make sure you're on at least PowerShell v5 and have latest PowerCLI. Tested with minimum PowerCLI version 6.3 r1.
# To get latest PowerCLI, first Uninstall any legacy PowerCLI from Add/Remove Programs, and install via PowerShell:
# Find-Module -Name VMware.PowerCLI
# Install-Module -Name VMware.PowerCLI -Scope AllUsers    ## Can also set -Scope to CurrentUser if not running as Administrator


### Begin our work

## Only check the version of the script:
if ($Version) {
	$VerReport = @()
	$EachVer = New-Object -TypeName PSObject
	$EachVer | Add-Member -Type NoteProperty -Name Vendor -Value "Western Digital IntelliFlash"
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
	Write-Host "`nExiting the script...`n" -foregroundcolor red
	Stop-Transcript
	Exit 1
}

if (!$AcceptDisclaimer) {
	# Disclaimer
	$DISCLAIMER = "`nDISCLAIMER`r`n`r`nThis script is provided AS IS without warranty of any kind. Western Digital further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose. The entire risk arising out of the use or performance of this script and documentation remains with you. In no event shall Western Digital Corporation, or anyone else involved in the creation, production, or delivery of this script be liable for any damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use this script or documentation, even if Tegile or Western Digital has been advised of the possibility of such damages.`r`n`r`nThis Script should only be run with the direct supervision of a Western Digital Engineer."
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
		Write-Host "`nExiting the script...`n" -foregroundcolor red
		Stop-Transcript
		Exit 1
	}
}

# Verify minimum PowerCLI version:
$PCLIMAJVER = ((Get-Module -Name VMware.VimAutomation.Core).version).Major
$PCLIMINVER = ((Get-Module -Name VMware.VimAutomation.Core).version).Minor
if ($PCLIMAJVER -lt "10") {
	$PCLIVEROLD = $true
} elseif (($PCLIMAJVER -eq "10") -and ($PCLIMINVER -lt "1")) {
	$PCLIVEROLD = $true
}
if ($PCLIVEROLD) {
	$PCLIFULLVER = "$PCLIMAJVER.$PCLIMINVER"
    Write-Host "`nFound PowerCLI version: $PCLIFULLVER" -foregroundcolor red
	Write-Host "Version 10.1 or newer is required" -foregroundcolor red
    Write-Host "`nYou can install latest version via:" -foregroundcolor yellow
    Write-Host "Find-Module -Name VMware.PowerCLI" -foregroundcolor yellow
	Write-Host "Install-Module -Name VMware.PowerCLI -Scope AllUsers" -foregroundcolor yellow
	Write-Host "(Can also set -Scope to CurrentUser if not running as Administrator)" -foregroundcolor yellow
    Write-Host "`nExiting the script...`n" -foregroundcolor red
    Stop-Transcript
    Exit 1
}

# Set some appropriate session options for PowerCLI config:
Set-PowerCLIConfiguration -DefaultVIServerMode Single -InvalidCertificateAction Ignore -ParticipateInCEIP $false -Scope Session -Confirm:$false | Out-Null

# Verify that the IntelliFlash cmdlet is available:
$TegileModule = Get-Module -Name Tegile_IntelliFlash_cmdlet

if (!$TegileModule) {
	Write-Host "`nThe Tegile_IntelliFlash_cmdlet is not loaded, please import it like so:" -foregroundcolor red
	Write-Host "`nImport-Module .\Tegile_IntelliFlash_cmdlet.psm1" -foregroundcolor yellow
	Write-Host "`nExiting the script...`n" -foregroundcolor red
	Stop-Transcript
	Exit 1
}

# Connect to vCenter:
Write-Host "`nConnecting to vCenter or Host $VCServer...`n"
# First see if we're already connected, and re-use existing session if so:
$SessionID = ($global:DefaultVIServers | Where-Object -FilterScript {$_.name -eq $VCServer}).sessionId
if ($SessionID) {
	Connect-VIServer -Server $VCServer -Session $SessionID -Force -WarningAction SilentlyContinue
} elseif (!$Password) {
	$vccredential = $host.ui.promptforcredential("Need vCenter or Host Credentials", "User & Pwd for vCenter or Host '$VCServer':", "$User", "")
	Connect-VIServer -Server $VCServer -Credential $vccredential -WarningAction SilentlyContinue
} else {
	Connect-VIServer -Server $VCServer -User $User -Password $Password -WarningAction SilentlyContinue
}
if ("$?" -eq "False") {
	Write-Host "`nConnection to vCenter Server $VCServer Failed. Verify Server IP/FQDN and credentials. Exiting...`n" -foregroundcolor red
	Stop-Transcript
	Exit 1
}

# Connect to specified IntelliFlash Array after first disconnecting any others:
Write-Host "`nConnecting to Array $Array and disconnecting any others..."
$IFArray = Show-IntelliFlash
foreach ($Arr in $IFArray) {
	if ($Arr.Array -ne $Array) {
		[void](Disconnect-IntelliFlash -Array $Arr.Array)
	}
}
if ($IFArray.Array -eq $Array) {
	Write-Host "`nAlready connected to Array '$Array'" -foregroundcolor green
} else {
	Connect-IntelliFlash -Array $Array -ArrayUserName $IFUser -ArrayPassword $IFPassword
	$IFArray = Show-IntelliFlash
	if ($IFArray.Array -ne $Array) {
		Write-Host "Connection to IntelliFlash appears to have failed, exiting...`n" -foregroundcolor red
		Stop-Transcript
		Exit 1
	} else {
		Write-Host "Successfully connected to array '$Array'" -foregroundcolor green
	}
}

# Report on provided parameters:
Write-Host "`nWe'll be cloning Projects: $Projects"
$Projects = $Projects -split ','

if ($NFSServerIP) {
	Write-Host "`nYou specified NFS Server IP '$NFSServerIP', checking to be sure it exists..."
	$FloatingIP = Get-IntelliFlashFloatingIPList | Where {$_.IPAddress -eq $NFSServerIP}
	if (!$FloatingIP) {
		Write-Host "`nThat IP does not exist as a Floating IP on Array '$Array', exiting!`n" -foregroundcolor red
		Stop-Transcript
		Exit 1
	} else {
		Write-Host "`n'$NFSServerIP' is a valid Floating IP for IntelliFlash pool:" $FloatingIP.PoolName -foregroundcolor green
		if (!$NACLHost) {
			Write-Host "`nYou did not specify -NACLHost, so if appropriate NFS subnet/IP's are not already in properties of cloned Project(s) this will fail" -foregroundcolor yellow
			$answer = Read-Host "`nEnter 'y' to specify -NACLHost now, anything else to just continue"
			if ($answer -eq "y") {
				$NACLHost = Read-Host "`nEnter comma-separated list of IP's for the NFS NACL"
				$NACLHost = $NACLHost -split ','
			} else {
				Write-Host "`nContinuing without -NACLHost..." foregroundcolor yellow
			}
		}
	}
}
if ($NACLHost) {
	Write-Host "`nWe'll be setting r/w/root NFS NACL's for: $NACLHost"
	$NACLHost = $NACLHost -split ','
	if (!$NFSServerIP) {
		Write-Host "`nYou did not enter -NFSServerIP! This is required for NFS Datastores, exiting!`n" -foregroundcolor red
		Stop-Transcript
		Exit 1
	}
}
if ($TargetGroup) {
	if (!$InitiatorGroup) {
		Write-Host "`nYou did not specify -InitiatorGroup, this is required for VMFS Datastores, exiting!`n" -foregroundcolor red
		Stop-Transcript
		Exit 1
	}
	# Verify that Target Group exists:
	$TargetGroupExists = Get-IntelliFlashTargetGroupList | Where {$_.TargetGroup -eq $TargetGroup}
	if ($TargetGroupExists) {
		Write-Host "`nYou specified Target Group: $TargetGroup"
	} else {
		Write-Host "`nTarget Group '$TargetGroup' not found on the array, exiting!`n" -foregroundcolor red
		Stop-Transcript
		Exit 1
	}
}
if ($InitiatorGroup) {
	if (!$TargetGroup) {
		Write-Host "`nYou did not specify -TargetGroup, this is required for VMFS Datastores, exiting!`n" -foregroundcolor red
		Stop-Transcript
		Exit 1
	}
	Write-Host "`nYou specified Intiator Group(s): $InitiatorGroup"
	$InitiatorGroup = $InitiatorGroup -split ','
	# Verify existence of Initiator Group(s):
	foreach ($InitGroup in $InitiatorGroup) {	
		$InitGroupExists = Get-IntelliFlashInitiatorGroupList | Where {$_.InitiatorGroup -eq $InitGroup}
		if (!$InitGroupExists) {
			Write-Host "`nInitiator Group '$InitGroup' not found on the array, exiting!`n" -foregroundcolor red
			Stop-Transcript
			Exit 1
		}
	}
}
if ($VMHost) {
	Write-Host "`nYou specified the following ESXi Host for registering VM's: $VMHost"
}
if ($Cluster) {
	Write-Host "`nYou specified the following cluster or host folder to limit the scope of datastore mounts: $Cluster"
}
if ($PowerOn) {
	Write-Host "`nYou specified PowerOn option, so we will be powering on recovered VM's and answering that they were 'moved'"
}
if ($ScanWait) {
	Write-Host "`nYou specified a ScanWait time of $ScanWait seconds"
} else {
	$ScanWait = "2"
}

# Get details on Replica Projects specified for recovery:
Write-Host "`nGetting details on specified Replica Projects..."
$ProjectsToClone = foreach ($proj in $Projects) {Get-IntelliFlashProjectList -Replica -Array $Array | Where {$_.ProjectName -eq "$proj"}}
if (!$ProjectsToClone) {
	Write-Host "`nNone of your specified Projects appear to exist on this array, exiting...`n"
	Stop-Transcript
	Exit 1
}

# Catch invalid/missing projects from specified list, prompt whether to continue:
foreach ($proj in $Projects) {
	if ($ProjectsToClone.ProjectName -notcontains $proj) {
		Write-Host "`nYour specified Project '$proj' does not seem to exist as a Replica on this array"
		CLV ConfirmContinue -EA SilentlyContinue
		$title = "Continue"
		$message = "Do you want to continue despite the missing/invalid Project?"
		$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Continues Script."
		$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Exits Script."
		$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
		$ConfirmContinue = $host.ui.PromptForChoice($title, $message, $options, 1)
		If ($ConfirmContinue -eq 0) {
			Write-Host "`nContinuing and ignoring the invalid Project above"
		} else {
			Write-Host "`nExiting script...`n" -foregroundcolor red
			Stop-Transcript
			Exit 1
		}
	}
}

# If NFSServerIP was specified, make sure the specified Projects are all for the same pool:
if ($NFSServerIP) {
	foreach ($proj in $ProjectsToClone) {
		if ($proj.PoolName -ne $FloatingIP.PoolName) {
			Write-Host "`nProject" $proj.ProjectName "is in pool" $proj.PoolName -foregroundcolor red
			Write-Host "`nBut the specified NFSServerIP $NFSServerIP is for pool:" $FloatingIP.PoolName -foregroundcolor red
			Write-host "`nExiting!`n" -foregroundcolor red
			Stop-Transcript
			Exit 1
		}
	}
}

# Clone all the Replica projects, using the latest replica snapshot:
Write-Host "`nCloning the Projects...`n"
$clones = @()
foreach ($proj in $ProjectsToClone) {
	$snaps = Get-IntelliFlashSnap -Replica -Array $proj.Array -PoolName $proj.PoolName -ProjectName $proj.ProjectName | Where {$_.SnapName.Substring(0,7) -eq "replica"}
	$snap = $snaps.SnapName | Sort | Select -Last 1
	$clonename = $proj.ProjectName + "-" + $snap
	$thisclone = Add-IntelliFlashClone -Array $proj.Array -PoolName $proj.PoolName -ProjectName $proj.ProjectName -SnapName $snap -CloneName $clonename -Replica -ReplicaKeepGUID -InheritAll
	if ($thisclone.Status -eq "True") {
		$clones += $thisclone
	}
}

if ($clones) {
	Write-Host "`nSuccessfully created the following Project clones:`n" -foregroundcolor green
	foreach ($clone in $clones.CloneName) {
		$clone
	}
} else {
	Write-Host "`nFailed to create clones, exiting...`n" -foregroundcolor red
	Stop-Transcript
	Exit 1
}

# Get list of any Shares in the cloned Projects:
if ($NFSServerIP) {
	Write-Host "`nLooking for Shares in the cloned Projects..."
	$sharestomount = @()
	foreach ($dataset in $clones) {
		$sharestomount += Get-IntelliFlashShareList | Where {$_.ProjectName -eq $dataset.CloneName}
	}

	# Create list of just Projects that have Shares
	$projectswithshares = @()
	foreach ($share in $sharestomount) {
		foreach ($proj in $clones) {
			if (($share.ProjectName -eq $proj.CloneName) -and ($projectswithshares.ProjectName -notcontains $proj.ProjectName)) {
				$projectswithshares += $proj
			}
		}
	}

	Write-Host "`nFound that the following cloned Projects have Shares:`n"
	$projectswithshares.ProjectName
}

# Get list of any LUN's in the cloned Projects:
if ($TargetGroup) {
	Write-Host "`nLooking for LUN's in the cloned Projects..."
	$lunstomount = @()
	foreach ($dataset in $clones) {
		$lunstomount += Get-IntelliFlashLUNList | Where {$_.ProjectName -eq $dataset.CloneName}
	}

	# Create list of just Projects that have LUN's
	$projectswithluns = @()
	foreach ($lun in $lunstomount) {
		foreach ($proj in $clones) {
			if (($lun.ProjectName -eq $proj.CloneName) -and ($projectswithluns.ProjectName -notcontains $proj.ProjectName)) {
				$projectswithluns += $proj
			}
		}
	}

	Write-Host "`nFound that the following cloned Projects have LUN's:`n"
	$projectswithluns.ProjectName
}

if ($sharestomount) {
	Write-Host "`nFound the following Shares in the cloned Projects:`n"
	foreach ($share in $sharestomount) {
		$share
	}
	# Check/Add NACL's to cloned Projects with Shares:
	if ($NACLHost) {
		Write-Host "`nAdding NACL's to cloned Projects with Shares..."
		foreach ($proj in $projectswithshares) {
			$projNACL = Get-IntelliFlashProjectNFSNetworkACL -PoolName $proj.PoolName -ProjectName $proj.CloneName -Array $proj.Array
			foreach ($NACL in $NACLHost) {
				if ($projNACL.NACLHost -notcontains $NACL) {
					Add-IntelliFlashProjectNFSNetworkACL -PoolName $proj.PoolName -ProjectName $proj.CloneName -Array $proj.Array -HostType IP -NACLHost $NACL -AccessMode rw -RootAccessForNFS
				} else {
					Write-Host "`n" $proj.CloneName "already contains NACL '$NACL'" -foregroundcolor yellow
				}
			}
		}
	} else {
		Write-Host "`nGetting existing NACL's on cloned Projects with Shares..."
		foreach ($proj in $projectswithshares) {
			$projNACL = Get-IntelliFlashProjectNFSNetworkACL -PoolName $proj.PoolName -ProjectName $proj.CloneName -Array $proj.Array
			if ($projNACL) {
				Write-Host "`nFound the following NACL for Project" $proj.CloneName ": '$NACL'"
			} else {
				Write-Host "`nProject" $proj.CloneName "contains no NACL! This will thus fail, as you were previously warned!" -foregroundcolor red
			}
		}
	}
}

if ($lunstomount) {
	Write-Host "`nFound the following LUN's in the cloned Projects:`n"
	$luids = @()
	foreach ($lun in $lunstomount) {
		$lun
		$luids += $lun.LUID
	}
	# Add mappings to cloned Projects with LUN's:
	Write-Host "`nAdding Mapping(s) to cloned Projects with LUN's..."
	foreach ($proj in $projectswithluns) {
		foreach ($InitGroup in $InitiatorGroup) {
			Add-IntelliFlashProjectLUNMapping -PoolName $proj.PoolName -ProjectName $proj.CloneName -Array $proj.Array -TargetGroup $TargetGroup -InitiatorGroup $InitGroup
		}
	}
}

# Get list of hosts:
if ($Cluster) {
	$VMHosts = Get-VMHost -Server $VCServer -Location $Cluster -ErrorAction SilentlyContinue | Where {$_.ConnectionState -eq "Connected"} | Sort
	if (!$VMHosts) {
		Write-Host "`nLooks like an invalid cluster was specified or no hosts present or connected, exiting...`n" -foregroundcolor red
		Stop-Transcript
		Exit 1
	}
} else {
	$VMHosts = Get-VMHost -Server $VCServer -ErrorAction SilentlyContinue | Where {$_.ConnectionState -eq "Connected"} | Sort
	if (!$VMHosts) {
		Write-Host "`nLooks like no hosts present in inventory or none connected, exiting...`n" -foregroundcolor red
		Stop-Transcript
		Exit 1
	}
}

# List out the hosts:
Write-Host "`nHosts found:`n"
foreach ($ESXiHost in $VMHosts) {
	$ESXiHost.Name
}

# Set host to use for registering VM's:
if ($VMHost) {
	if (($VMHosts.Name -contains "$VMHost") -and ((Get-VMHost -Name "$VMHost").ConnectionState -eq "Connected")) {
		Write-Host "`nUsing host '$VMHost' for VM registration as you specified`n"
	} else {
		Write-Host "`nYou specified host '$VMHost', but that host is not valid or is disconnected/maintenance/notresponding" -foregroundcolor red
		$VMHost = $VMHosts | Select -First 1
		Write-Host "`nUsing host '$VMHost' for VM registration instead"
	}
} else {
	$VMHost = $VMHosts | Select -First 1
	Write-Host "`nUsing host '$VMHost' for VM registration`n"
}

# Mount all the cloned Datastores:

if ($sharestomount) {
	Write-Host "`nMounting NFS datastores..."
	foreach ($share in $sharestomount) {
		$sharename = $share.ShareName
		foreach ($ESXiHost in $VMHosts) {
			Write-Host "`nMounting '$sharename' on host '$ESXiHost'...`n"
			New-Datastore -Server $VCServer -VMHost $ESXiHost -Name $sharename -Path $share.MountPoint -NfsHost $NFSServerIP -Confirm:$false | out-null
			if ("$?" -eq "False") {
				Write-Host "`nMounting of '$sharename' on host '$ESXiHost' failed!`n" -foregroundcolor red
			} else {
				Write-Host "`nMounting of '$sharename' on host '$ESXiHost' succeeded!`n" -foregroundcolor green
			}
		}
	}
}

# Attach and Mount LUN's:
if ($lunstomount) {
	Write-Host "`nMounting VMFS datastores..."
	foreach ($ESXiHost in $VMHosts) {
		Write-Host "`nRescanning all storage on '$ESXiHost' to find cloned LUN's..."
		[void](Get-VMHostStorage -VMHost $ESXiHost -RescanAllHba -RescanVmfs)
		sleep $ScanWait
	}
	foreach ($ESXiHost in $VMHosts) {
		$intelliflashdatastores = Get-ScsiLun -VMHost $ESXiHost | where {$_.Model -eq "INTELLIFLASH"}
	}
	foreach ($ESXiHost in $VMHosts) {
		$storSys = Get-View $ESXiHost.ExtensionData.ConfigManager.StorageSystem
		foreach ($lun in $intelliflashdatastores.CanonicalName) {
			if ($luids -contains $lun.Substring($_.length+4)) {
				Write-Host "`nAttaching LUN '$lun' on host '$ESXiHost'..."
				try {
					$storSys.AttachScsiLun($lun)
				} catch {
				}
			sleep $ScanWait
			}
		}
	}
	
	# Mounting Unavailable/Inaccessible LUN's (e.g. that didn't automount because of previous manual unmount of previous clones):
	foreach ($ESXiHost in $VMHosts) {
		Write-Host "`nRescanning all storage on '$ESXiHost' to find any attached but unmounted datastores..."
		[void](Get-VMHostStorage -VMHost $ESXiHost -RescanAllHba -RescanVmfs)
		sleep $ScanWait
	}
	$ds = Get-Datastore | Where {$_.State -eq "Unavailable"} | sort
	if ($ds) {
		Write-Host "`nFound the following unmounted datastores:`n"
		$ds.Name
		Write-Host "`nWe'll try to get those mounted now..."
		$dsHostKeys = $ds.extensiondata.host.key.value | sort | get-unique -asstring
		$dsHosts = foreach ($thisKey in $dsHostKeys) {
			($ds.extensiondata.host | ? {$_.key.value -eq $thisKey})[0]
		}
		$allHosts = @()
		foreach ($dsHost in $dsHosts) {
			$hostObj = "" | select keyValue,hostView,storageSys
			$hostObj.hostView = get-view $dsHost.key
			$hostObj.keyValue = $dsHost.key.value
			$hostObj.storageSys = get-view $hostObj.hostView.ConfigManager.StorageSystem
			$allHosts += $hostObj
		}
		foreach ($dsHost in $allHosts) {
			foreach ($d in $ds) {
				Write-Host "`nMounting '$d' on" $dsHost.hostView.Name "..."
				$dsHost.storageSys.MountVmfsVolume($d.ExtensionData.Info.vmfs.uuid)
			}
		}
	}
	foreach ($lunname in $lunstomount.LUNName) {
	Write-Host "`nChecking that cloned VMFS datastores are mounted on '$ESXiHost'..."
		foreach ($ESXiHost in $VMHosts) {
			if (Get-Datastore -Name $lunname -VMHost $ESXiHost -ErrorAction SilentlyContinue) {
				Write-Host "`nVMFS Datastore '$lunname' successfully mounted on host '$ESXiHost'!" -foregroundcolor green
			} else {
				Write-Host "`nVMFS Datastore '$lunname' not mounted on host '$ESXiHost', manual remediation may be necessary!" -foregroundcolor red
			}
		}
	}
}

# Get all the Datastores we'll be browsing for VM's:
$Datastores = @()
foreach ($ds in $sharestomount.ShareName) {
	$Datastores += Get-Datastore $ds -ErrorAction SilentlyContinue
}
foreach ($ds in $lunstomount.LUNName) {
	$Datastores += Get-Datastore $ds -ErrorAction SilentlyContinue
}

# Collect .vmx paths of VM's already registered:
$existingvms = @(Get-VM | %{$_.Extensiondata.LayoutEx.File | where {$_.Name -like "*.vmx"}}).Name

# Register the VM's:
Write-Host "`nBeginning VM registration..."
$registeredvms = @()
foreach ($Datastore in $Datastores) {
	# Gather list of VM's from this datastsore which are not currently registered, by finding all .vmx files and comparing to $existingvms:
	New-PSDrive -Name TgtDS -Location $Datastore -PSProvider VimDatastore -Root '\' | Out-Null
	$unregistered = @(Get-ChildItem -Path TgtDS: -Recurse | where {($_.FolderPath -notmatch ".zfs") -and ($_.Name -like "*.vmx") -and ($existingvms -notcontains $_.DatastoreFullPath)})
	Remove-PSDrive -Name TgtDS

	# Register all .vmx files from $unregistered as VMs
	foreach ($VMXFile in $unregistered) {
		Write-Host "`nRegistering .vmx:" $VMXFile.DatastoreFullPath "..."
		New-VM -VMFilePath $VMXFile.DatastoreFullPath -VMHost $VMHost -RunAsync
		if ("$?" -eq "True") {
			$vm = $VMXFile.DatastoreFullPath -replace "[^/]*/", "" -replace ".vmx", ""
			Write-Host "`nSuccessfully Registered VM: '$vm'" -foregroundcolor green
			$registeredvms += $vm
		} else {
			Write-Host "`nRegistration of the VM '$vm' on host '$VMHost' failed!" -foregroundcolor red
		}
	}
}

Write-Host "`nSuccessfully registered a total of" $registeredvms.Count "VM's from all datastores" -foregroundcolor green

if ($PowerOn) {
	Write-Host "`nAttempting Power-On and answering of VM Moved/Copied Question for the" $registeredvms.Count "registered VM's, this may take a while..." -foregroundcolor yellow
	foreach ($vm in $registeredvms) {
		Write-Host "`nPowering on VM '$vm'..."
		Start-VM -Server $VCServer -VM "$vm" -Confirm:$false -ErrorAction SilentlyContinue 2>&1 3>&1 | out-null
		Get-VMQuestion -Server $VCServer -VM "$vm" | Set-VMQuestion -Option "button.uuid.movedTheVM" -Confirm:$false
		sleep 1
	}
}

Write-Host "`n`nCompleted DR Recovery Script!" -foregroundcolor green
Write-Host "`nPlease go check your vSphere DR inventory to verify everything`n" -foregroundcolor green
Write-Host "`nLog file is available in: $logdir`n" -foregroundcolor yellow
Stop-Transcript
