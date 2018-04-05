<#
.SYNOPSIS
Allows you to leverage Tegile IntelliFlash API and VMware PowerCLI to clone VMFS datastore, and automatically add 2 .vmdk's from it to a VM

.DESCRIPTION
This script will allow you to connect to vCenter & a Tegile IntelliFlash array, and
Then clone an existing VMFS datastore and add .vmdk's out of it to a VM

Requires PowerShell version 5 or better, and PowerCLI version 6.3 r1 or better
Tested with vSphere 5.5 through 6.5

The script has several required parameters, and a few optional, all will autocomplete after '-'
	Required:
	-VCServer (alias: -vCenter) | Specify the IP or FQDN of the vCenter Server or ESXi Host
	-Array | Tegile IntelliFlash array which supports the pool in which the LUN you'll be cloning exists
	-ArrayUser | User name with permissions for API access on the array
	-ArrayPassword | Password for the array user name
	-Datastore	| Exact case-sensitive Name of the VMFS datastore that contains the DB/LOG vmdk's to clone
	-SourceVMname | Name of the original/source virtual machine which has the DB/LOG vmdk's mounted for use to support DB/Log files
	-TargetVMname | Name of the target/new VM which will get the cloned vmdk's added to it's configuration
	-DBvmdk | Exact case-sensitive name of the .vmdk descriptor file for the virtual disk to clone that is supporting the DB files on Source VM
	-LOGvmdk | Exact case-sensitive name of the .vmdk descriptor file for the virtual disk to clone that is supporting the LOG files on Source VM
	-Datacenter | Exact case-sensitive name of the Datacenter within vCenter in which the original/target datastore/VM/files lives

	Optional:
	-VCUser	| Specify the user account for vCenter or Host connectivity
	-VCPassword | Specify the password for the designated VCuser account
	-ClonePrefix	-> if not set, assign to blank string so it's always first part of clone name
	-Cluster | Limit clone mount to specific cluster (or even a folder) rather than the default which is all hosts and clusters under vCenter
	-Version (alias: -ver, -v) | Returns script version
	-AcceptDisclaimer | Accept the disclaimer without being prompted to do so within the script - you accept all responsibility anyway!

.EXAMPLE
.\Tegile_VMFS_DB-LOG_Clone_and_Mount.ps1 -VCServer 10.65.240.25 -VCUser administrator@vsphere.local -Array 10.65.240.184 -ArrayUser admin -ArrayPassword tegile -SourceVMname Win2012R2-ThinDemo -TargetVMname Win2012R2-ThinDemo-clone -Datastore T3100-VMW6-ThinDemoLUN01 -DBvmdk Win2012R2-ThinDemo.vmdk -LOGvmdk Win2012R2-ThinDemo_1.vmdk -Datacenter vSphere-6


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
		[Switch]
		$AcceptDisclaimer,
		[Parameter(Mandatory=$true)]
		[Alias("vCenter")]
		[String]
		$VCServer,
		[Parameter()]
		[String]
		$Cluster,
		[Parameter()]
		[String]
		$VCUser,
		[Parameter()]
		[String]
		$VCPassword,
		[Parameter(Mandatory=$true)]
		[String]
		$Array,
		[Parameter(Mandatory=$true)]
		[String]
		$ArrayUser,
		[Parameter(Mandatory=$true)]
		[String]
		$ArrayPassword,
		[Parameter(Mandatory=$true)]
		[String]
		$Datastore,
		[Parameter(Mandatory=$true)]
		[String]
		$SourceVMname,
		[Parameter(Mandatory=$true)]
		[String]
		$TargetVMname,
		[Parameter(Mandatory=$true)]
		[String]
		$DBvmdk,
		[Parameter(Mandatory=$true)]
		[String]
		$LOGvmdk,
		[Parameter(Mandatory=$true)]
		[String]
		$Datacenter,
		[Parameter()]
		[String]
		$ClonePrefix
	)

# This script is supported on a best-effort only
# Script Version:
$MajorVer = 3
$MinorVer = 7
$PatchVer = 0
$BuildVer = 4
$VerMonth = 1
$VerDay = 17
$VerYear = 2018
$Author = "Ben Kendall & Ken Nothnagel, Tegile / WDC Professional Services"

$VerMonthName = (Get-Culture).DateTimeFormat.GetAbbreviatedMonthName($VerMonth)

# Make sure you're on at least PowerShell v5 and have latest PowerCLI. Tested with PowerCLI 6.5.3
# To get latest PowerCLI, first Uninstall any legacy PowerCLI from Add/Remove Programs, and install via PowerShell:
# Find-Module -Name VMware.PowerCLI
# Install-Module -Name VMware.PowerCLI -Scope AllUsers    ## Can also set -Scope to CurrentUser if not running as Administrator
# See: https://blogs.vmware.com/PowerCLI/2017/05/powercli-6-5-1-install-walkthrough.html

## Set any variables:

if (!$ClonePrefix) {
	$ClonePrefix = ""
}


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

# Check to see if PowerCLI is new enough:
$PCLIMAJVER = ((Get-Module -Name VMware.VimAutomation.Core).version).Major
$PCLIMINVER = ((Get-Module -Name VMware.VimAutomation.Core).version).Minor
if ($PCLIMAJVER -lt "6") {
	$PCLIVEROLD = $true
} elseif (($PCLIMAJVER -ge "6") -and ($PCLIMINVER -lt "3")) {
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

if ($Cluster) {
	Write-Host "`nLimiting scope to specified cluster: $Cluster"
}

# IntelliFlash API Functions:

function Connect-IntelliFlash {
	[CmdletBinding()]
	Param (
		# Array Name or IP
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$Array,
		# Array User
		[Parameter(ValueFromPipelineByPropertyName=$True)]
		[String[]]$ArrayUser,
		# Array Password
		[Parameter(ValueFromPipelineByPropertyName=$True)]
		[String[]]$ArrayPassword
	)
	Begin{
		$ArrayReport = @()
		[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
		[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
		if (!$global:ArrayTable) {
			$global:ArrayTable = @()
			$ArrayCred = @()
			} else {$ArrayCred = $global:ArrayTable}
		$i=0
		If (!$ArrayUser){[String]$CurrentUser}
		If (!$ArrayPassword){[String]$CurrentPassword}
	}
	Process{  
		ForEach ($CurrentArray in $Array){
			If ($ArrayUser){$CurrentUser = $ArrayUser}Else{$CurrentUser = ""}
			If ($ArrayPassword){$CurrentPassword = $ArrayPassword}Else{$CurrentPassword = ""}
			$Check = New-Object Net.Sockets.TcpClient $CurrentArray, 443
			If ($Check.Connected -eq "True") {
				Write-Verbose "`n$CurrentArray appears to be a good Array IP/Name`n"
				Write-Verbose "`nConnecting to IntelliFlash Array '$CurrentArray'...`n"
				$Cred = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select Cred
				$Cred = $Cred.Cred
				If ($Cred){
					Write-Output "$CurrentArray already connected"
					Break
				}
				if (!$Cred -and !$CurrentUser) {
					$ifcredential = $host.ui.promptforcredential("Need IntelliFlash Credentials", "IntelliFlash Array: $CurrentArray", "", "")
						if (!$ifcredential) {Write-Output "`nYou failed to enter credentials!`n"}
					} 
					elseif (!$CurrentPassword) {
						$ifcredential = $host.ui.promptforcredential("Need IntelliFlash Credentials", "IntelliFlash Array: $CurrentArray", "$CurrentUser", "")
						if (!$ifcredential) {Write-Output "`nYou failed to enter credentials!`n"}
					}
				if (!$CurrentUser) {
					$CurrentUser = $ifcredential.username.trimstart('\')
				}
				if (!$CurrentPassword) {
					$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ifcredential.password)
					$CurrentPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
				}

				$auth = "$CurrentUser" + ':' + "$CurrentPassword"
				$encoded = [System.Text.Encoding]::UTF8.GetBytes($auth)
				$encodedpassword = [System.Convert]::ToBase64String($encoded)
				$Cred = @{"Authorization"="Basic $($EncodedPassword)"}
				$CurrentUser = ""
				$CurrentPassword = ""

				$url = "https://$CurrentArray/zebi/api/v1/listSystemProperties"
				$postParams = "[[`"ZEBI_APPLIANCE_MODEL`",`"ZEBI_GUI_VERSION`"]]"
				Write-Debug $postParams
				$ArrayInfo = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
				if (!$?) {
					Write-Output "`nConnection to IntelliFlash Array '$CurrentArray' failed, verify credentials.`n"
					} 
					else
					{
					Write-Verbose "`nIntelliFlash Storage Array Model and Version: $ArrayInfo`n"
					$IntelliFlashVersion = $ArrayInfo[1]
					$EachArray = @()
					CLV EachArray -EA SilentlyContinue
					$Error.Clear()
					$EachArray = New-Object -TypeName PSObject
					$EachArray | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
					$EachArray | Add-Member -Type NoteProperty -Name Cred -Value $Cred
					$EachArray | Add-Member -Type NoteProperty -Name IntelliFlashVersion -Value $IntelliFlashVersion
					$ArrayReport += $EachArray
					}
			}Else{Write-Output "$CurrentArray is a bad Array IP or Name"}
			$i++
		} 
	}
	End{
	If ($ArrayReport){$global:ArrayTable += $ArrayReport}
	Write-Output $global:ArrayTable
	}
}

function Disconnect-IntelliFlash {
	[CmdletBinding()]
	Param (
		[Parameter(ValueFromPipelineByPropertyName=$True)]
		[String[]]$Array,
		[Parameter()]
		[Switch]$All
	)
	Begin {
        If (!$Global:ArrayTable){Write-Output "NO ARRAYS CONNECTED"}
        If ($All){
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            If (!$?){Write-Host "All Arrays Disconnected"}
        }
    }
	Process {
		Write-Verbose "Removing $Array"
        CLV NewCred -EA SilentlyContinue
        $Error.Clear()
        $NewCred = @()
        $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
        CLV ArrayTable -Scope Global -EA SilentlyContinue
        $Error.Clear()
        $Global:ArrayTable = @()
        $Global:ArrayTable += $NewCred
	}
	End {
        If (!$Array -and !$All){Write-Host "Please Specify Arrays to disconnect:" -foregroundcolor "Yellow" -backgroundcolor "Black"}
        Write-Output $Global:ArrayTable
    }
}

function Add-IntelliFlashLUNMapping {
    [CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$Array,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$PoolName,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$ProjectName,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$LUNName,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$InitiatorGroup,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$TargetGroup,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
		[String[]]$LUNNumber,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
		[String[]]$ReadOnlyMapping,
		[Parameter()]
		[String]$ArrayUserName,
		[Parameter()]
		[String]$ArrayPassword
    )
    Begin{
        if (!$global:ArrayTable) {
            If ($Array -and $ArrayUserName -and $ArrayPassword){
                CLV CLINE -EA SilentlyContinue
                $CLINE = @()
                $CLINEReport = New-Object -TypeName PSObject
                $CLINEReport | Add-Member -Type NoteProperty -Name Array -Value $Array
                $CLINEReport | Add-Member -Type NoteProperty -Name ArrayUserName -Value $ArrayUserName
                $CLINEReport | Add-Member -Type NoteProperty -Name ArrayPassword -Value $ArrayPassword
                $CLINE = $CLINEReport
                [void]($CLINE |Connect-IntelliFlash)
                }Else{
                [void](Connect-IntelliFlash)
            }
        }
        #CLV AddMappingReport -EA SilentlyContinue
        $AddMappingReport = @()
        $i=0
    }
    Process{
        ForEach ($CurrentArray in $Array){
            If ($LUNNumber){$CurrentLUNNumber = $LUNNumber[$i]}
            If (!$CurrentLUNNumber){$CurrentLUNNumber = "-1"}
            $Cred = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select Cred
            $Cred = $Cred.Cred
            $IntelliFlashVersion = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select IntelliFlashVersion
            $IntelliFlashVersion = [double]$IntelliFlashVersion.IntelliFlashVersion.Substring(0,3)
            If ($IntelliFlashVersion -lt 3.5){$APIVer = "v1"}else{$APIVer = "v2"}
	        $url = "https://$CurrentArray/zebi/api/$APIVer/createMappingForVolume"
	        $CurrentInitGroup = $InitiatorGroup[$i]
            $CurrentTgtGroup = $TargetGroup[$i]
            $CurrentPool = $PoolName[$i]
            $CurrentProject = $ProjectName[$i]
            $CurrentLUN = $LUNName[$i]
            $DataSetPath = "$CurrentPool/Local/$CurrentProject/$CurrentLUN"
            $postParams = "[`"" + $DataSetPath + "`", " + "`"" + $CurrentInitGroup +"`", " + "`"" + $CurrentTgtGroup + "`", "  + "`"" + $CurrentLUNNumber + "`", "  + "`"" + $ReadOnlyMapping + "`"]"
			Write-Debug $postParams
	        $AddMapping = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
            If ($AddMapping -eq 0){
                $EachMap = New-Object -TypeName PSObject
                $EachMap | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                $EachMap | Add-Member -Type NoteProperty -Name PoolName -Value $CurrentPool
                $EachMap | Add-Member -Type NoteProperty -Name ProjectName -Value $CurrentProject
                $EachMap | Add-Member -Type NoteProperty -Name LUNName -Value $CurrentLUN
                $EachMap | Add-Member -Type NoteProperty -Name InitiatorGroup -Value $CurrentInitGroup
                $EachMap | Add-Member -Type NoteProperty -Name TargetGroup -Value $CurrentTgtGroup
                $EachMap | Add-Member -Type NoteProperty -Name Status -Value "True"
                $EachMap | Add-Member -Type NoteProperty -Name MappingCreated -Value "True"
                $AddMappingReport += $EachMap
                }Else{
                $EachMap = New-Object -TypeName PSObject
                $EachMap | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                $EachMap | Add-Member -Type NoteProperty -Name PoolName -Value $CurrentPool
                $EachMap | Add-Member -Type NoteProperty -Name ProjectName -Value $CurrentProject
                $EachMap | Add-Member -Type NoteProperty -Name LUNName -Value $CurrentLUN
                $EachMap | Add-Member -Type NoteProperty -Name InitiatorGroup -Value $CurrentInitGroup
                $EachMap | Add-Member -Type NoteProperty -Name TargetGroup -Value $CurrentTgtGroup
                $EachMap | Add-Member -Type NoteProperty -Name Status -Value "False"
                $EachMap | Add-Member -Type NoteProperty -Name MappingCreated -Value "False"
                $AddMappingReport += $EachMap
            }
       $i++
       }
    }
    End{
        Write-Output $AddMappingReport
        If ($Array -and $ArrayUserName -and $ArrayPassword){
            $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            $Global:ArrayTable = @()
            $Global:ArrayTable = $NewCred
        }
    }
}

function Get-IntelliFlashPoolList {
	[CmdletBinding()]
	Param (
		[Parameter()]
		[String]$Array,
		[Parameter()]
		[String]$ArrayUserName,
		[Parameter()]
		[String]$ArrayPassword
	)
	Begin{
		if (!$global:ArrayTable) {
			If ($Array -and $ArrayUserName -and $ArrayPassword){
				CLV CLINE -EA SilentlyContinue
				$CLINE = @()
				$CLINEReport = New-Object -TypeName PSObject
				$CLINEReport | Add-Member -Type NoteProperty -Name Array -Value $Array
				$CLINEReport | Add-Member -Type NoteProperty -Name ArrayUserName -Value $ArrayUserName
				$CLINEReport | Add-Member -Type NoteProperty -Name ArrayPassword -Value $ArrayPassword
				$CLINE = $CLINEReport
				[void]($CLINE |Connect-IntelliFlash)
				}Else{
				[void](Connect-IntelliFlash)
			}
			$p=1
		}
	}
	Process{
		CLV ProjectReport -EA SilentlyContinue
		$PoolReport = @()
		ForEach ($Array in $global:ArrayTable.Array){
			Write-progress -activity "Collecting Pools from $Array" -status "Progress:" -percentcomplete ($p/$global:ArrayTable.count*100)
			$Cred = $global:ArrayTable |Where {$_.Array -eq $Array}|select Cred
			$Cred = $Cred.Cred
			$IntelliFlashVersion = $global:ArrayTable |Where {$_.Array -eq $Array}|select IntelliFlashVersion
			$IntelliFlashVersion = [double]$IntelliFlashVersion.IntelliFlashVersion.Substring(0,3)
			If ($IntelliFlashVersion -lt 3.5){$APIVer = "v1"}else{$APIVer = "v2"}
			$url = "https://$Array/zebi/api/$APIVer/listPools"
			$postParams = "[]"
			Write-Debug $postParams
			$pool = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
			if ("$?" -eq "False") {
				Write-Host "`nNo Pools exist on IntelliFlash Array '$Array'.`n"
			} else {
				ForEach ($CurrentPool in $Pool){
					$EachPool = New-Object -TypeName PSObject
					$EachPool | Add-Member -Type NoteProperty -Name Array -Value $Array
					$EachPool | Add-Member -Type NoteProperty -Name PoolName -Value $CurrentPool.name
					$EachPool | Add-Member -Type NoteProperty -Name AvailableSize -Value $CurrentPool.availableSize
					$EachPool | Add-Member -Type NoteProperty -Name AvailableSizeGB -Value ("{0:N2}" -f ($CurrentPool.availableSize/1024/1024/1024))
					$EachPool | Add-Member -Type NoteProperty -Name AvailableSizeTB -Value ("{0:N2}" -f ($CurrentPool.availableSize/1024/1024/1024/1024))
					$EachPool | Add-Member -Type NoteProperty -Name TotalSize -Value $CurrentPool.totalSize
					$EachPool | Add-Member -Type NoteProperty -Name TotalSizeGB -Value ("{0:N2}" -f ($CurrentPool.totalSize/1024/1024/1024))
					$EachPool | Add-Member -Type NoteProperty -Name TotalSizeTB -Value ("{0:N2}" -f ($CurrentPool.totalSize/1024/1024/1024/1024))
					$EachPool | Add-Member -Type NoteProperty -Name APIVer -Value $APIVer
					$PoolReport += $EachPool
				}
			}
		$p++
		}
	}
	End{
		Write-Output $PoolReport
		Write-progress -activity "Collecting Pools from $Array" -Completed
		If ($Array -and $ArrayUserName -and $ArrayPassword){
			$NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
			CLV ArrayTable -Scope Global -EA SilentlyContinue
			$Global:ArrayTable = @()
			$Global:ArrayTable = $NewCred
		}
	}
}

function Get-IntelliFlashProjectList {
	[CmdletBinding()]
	Param (
		[Parameter()]
		[Switch]$Replica,
		[Parameter()]
		[String]$Array,
		[Parameter()]
		[String]$ArrayUserName,
		[Parameter()]
		[String]$ArrayPassword
	)
	Begin{
		if (!$global:ArrayTable) {
			If ($Array -and $ArrayUserName -and $ArrayPassword){
				CLV CLINE -EA SilentlyContinue
				$CLINE = @()
				$CLINEReport = New-Object -TypeName PSObject
				$CLINEReport | Add-Member -Type NoteProperty -Name Array -Value $Array
				$CLINEReport | Add-Member -Type NoteProperty -Name ArrayUserName -Value $ArrayUserName
				$CLINEReport | Add-Member -Type NoteProperty -Name ArrayPassword -Value $ArrayPassword
				$CLINE = $CLINEReport
				[void]($CLINE |Connect-IntelliFlash)
				}Else{
				[void](Connect-IntelliFlash)
			}
		}
		if ($Replica) {$local = "false"} else {$local = "true"}
		#CLV ProjectReport -EA SilentlyContinue
		$ProjectReport = @()
		[void]($PoolReport = Get-IntelliFlashPoolList)
	}
	Process{
		ForEach ($Pool in $PoolReport) {
			$CurrentArray = $Pool.Array
			$Cred = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select Cred
			$Cred = $Cred.Cred
			$APIVer = $Pool.APIVer
			$PoolName = $Pool.PoolName
			Write-Verbose "`nLooking for Projects in '$CurrentArray | $Pool.PoolName | $local'..."
			$url = "https://$CurrentArray/zebi/api/$APIVer/listProjects"
			$postParams = "[`"$poolname`",`"$local`"]"
			Write-Debug $postParams
			$project = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
			ForEach ($proj in $project){
				$EachProj = New-Object -TypeName PSObject
				$EachProj | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
				$EachProj | Add-Member -Type NoteProperty -Name PoolName -Value $proj.poolName
				$EachProj | Add-Member -Type NoteProperty -Name ProjectName -Value $proj.name
				$EachProj | Add-Member -Type NoteProperty -Name LocalProject -Value $proj.local
				$ProjectReport += $EachProj
			}
		}
	}
	End{
		Write-Output $ProjectReport
	}
}

function Get-IntelliFlashLUNList {
	[CmdletBinding()]
	Param (
		[Parameter()]
		[Switch]$Replica,
		[Parameter()]
		[String]$Array,
		[Parameter()]
		[String]$ArrayUser,
		[Parameter()]
		[String]$ArrayPassword
	)
	Begin{
		if (!$global:ArrayTable) {
			If ($Array -and $ArrayUser -and $ArrayPassword){
				CLV CLINE -EA SilentlyContinue
				$CLINE = @()
				$CLINEReport = New-Object -TypeName PSObject
				$CLINEReport | Add-Member -Type NoteProperty -Name Array -Value $Array
				$CLINEReport | Add-Member -Type NoteProperty -Name ArrayUser -Value $ArrayUser
				$CLINEReport | Add-Member -Type NoteProperty -Name ArrayPassword -Value $ArrayPassword
				$CLINE = $CLINEReport
				[void]($CLINE |Connect-IntelliFlash)
				}Else{
				[void](Connect-IntelliFlash)
			}
		}
		if ($Replica) {$local = "false"} else {$local = "true"}
		#CLV LunReport -EA SilentlyContinue
		if ($Replica) {[void]($ProjectList = Get-IntelliFlashProjectList -Replica)}Else{[void]($ProjectList = Get-IntelliFlashProjectList)}
		$LunReport = @()
		$p=1
	}
	Process{
		ForEach ($Project in $ProjectList){
			$CurrentArray = $Project.Array
			$ProjectName = $Project.ProjectName
			$PoolName = $Project.PoolName
			$Cred = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select Cred
			$Cred = $Cred.Cred
			$IntelliFlashVersion = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select IntelliFlashVersion
			$IntelliFlashVersion = [double]$IntelliFlashVersion.IntelliFlashVersion.Substring(0,3)
			If ($IntelliFlashVersion -lt 3.5){$APIVer = "v1"}else{$APIVer = "v2"}
			If (!$ProjectList){Write-progress -id 1 -activity "Collecting LUNs from $CurrentArray/$ProjectName" -status "Progress:" -percentcomplete ($p/$ProjectList.count*100)}
			$url = "https://$CurrentArray/zebi/api/$APIVer/listVolumes"
			$postParams = "[`"$poolname`",`"$projectname`",`"$local`"]"
			Write-Debug $postParams
			$LUNList = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
				ForEach ($LUN in $LUNList) {
					$EachLUN = New-Object -TypeName PSObject
					$EachLUN | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
					$EachLUN | Add-Member -Type NoteProperty -Name PoolName -Value $LUN.poolName
					$EachLUN | Add-Member -Type NoteProperty -Name ProjectName -Value $LUN.projectname
					$EachLUN | Add-Member -Type NoteProperty -Name LUNName -Value $LUN.name
					$EachLUN | Add-Member -Type NoteProperty -Name LUID -Value $LUN.luId
					$EachLUN | Add-Member -Type NoteProperty -Name LUNSize -Value $LUN.volSize
					$EachLUN | Add-Member -Type NoteProperty -Name LUNSizeGB -Value ("{0:N2}" -f ($LUN.volSize/1024/1024/1024))
					$EachLUN | Add-Member -Type NoteProperty -Name LUNSizeTB -Value ("{0:N2}" -f ($LUN.volSize/1024/1024/1024/1024))
					$EachLUN | Add-Member -Type NoteProperty -Name BlockSize -Value $LUN.blockSize
					#$EachLUN | Add-Member -Type NoteProperty -Name ThinProvision -Value $LUN.thinProvision
					#Excluding Thin Provision for now as this property is broken in the API
					$EachLUN | Add-Member -Type NoteProperty -Name Protocol -Value $LUN.Protocol
					$EachLUN | Add-Member -Type NoteProperty -Name FullPath -Value $LUN.datasetPath
					$EachLUN | Add-Member -Type NoteProperty -Name LocalLUN -Value $LUN.local
					$LUNReport += $EachLUN
				}
			}
			$p++
		}
	End{
		Write-Output $LUNReport
		Write-progress -id 1 -activity "Collecting LUNs from $CurrentArray/$ProjectName" -Completed
		If ($Array -and $ArrayUser -and $ArrayPassword){
			$NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
			CLV ArrayTable -Scope Global -EA SilentlyContinue
			$Global:ArrayTable = @()
			$Global:ArrayTable = $NewCred
		}
	}
}

function Get-IntelliFlashSnap {
	[CmdletBinding()]
	Param (
		[Parameter(ValueFromPipelineByPropertyName=$True)]
		[Switch]$Replica,
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String]$Array,
		[Parameter()]
		[String]$ArrayUser,
		[Parameter()]
		[String]$ArrayPassword,
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String]$PoolName,
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String]$ProjectName,
		[Parameter(ValueFromPipelineByPropertyName=$True)]
		[String]$LUNName,
		[Parameter(ValueFromPipelineByPropertyName=$True)]
		[String]$ShareName
	)
	Begin{
		if (!$global:ArrayTable) {
			If ($Array -and $ArrayUser -and $ArrayPassword){
				CLV CLINE -EA SilentlyContinue
				$CLINE = @()
				$CLINEReport = New-Object -TypeName PSObject
				$CLINEReport | Add-Member -Type NoteProperty -Name Array -Value $Array
				$CLINEReport | Add-Member -Type NoteProperty -Name ArrayUser -Value $ArrayUser
				$CLINEReport | Add-Member -Type NoteProperty -Name ArrayPassword -Value $ArrayPassword
				$CLINE = $CLINEReport
				[void]($CLINE |Connect-IntelliFlash)
				}Else{
				[void](Connect-IntelliFlash)
			}
		}
		if ($Replica) {$local = "Replica";$LocalSnap = "False"} else {$local = "Local";$LocalSnap = "True"}
		CLV SnapReport -EA SilentlyContinue
		$SnapReport = @()
		If($ShareName -and $LUNName){
				Write-Host "You have tried to pass both a LUN name and Share name in the same command." -ForegroundColor yellow -BackgroundColor Black
				Write-Host "This is unsupported." -ForegroundColor yellow -BackgroundColor Black
				Break
		}
	}
	Process{
			If ($LUNName){
				$FullPath = "$PoolName/$local/$ProjectName/$LUNName"
				$SnapType = "LUN"
			}
			If ($ShareName){
				$FullPath = "$PoolName/$local/$ProjectName/$ShareName"
				$SnapType = "Share"
			}
			If (!$LUNName -and !$ShareName){
				$FullPath = "$PoolName/$local/$ProjectName"
				$SnapType = "Project"
			}
			$Cred = $global:ArrayTable |Where {$_.Array -eq $Array}|select Cred
			$Cred = $Cred.Cred
			$IntelliFlashVersion = $global:ArrayTable |Where {$_.Array -eq $Array}|select IntelliFlashVersion
			$IntelliFlashVersion = [double]$IntelliFlashVersion.IntelliFlashVersion.Substring(0,3)
			If ($IntelliFlashVersion -lt 3.5){$APIVer = "v1"}else{$APIVer = "v2"}
			$url = "https://$Array/zebi/api/$APIVer/listSnapshots"
			$postParams = "[`"$FullPath`",`".*`"]"
			Write-Debug $postParams
			$SnapList = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
			ForEach ($Snap in $SnapList) {
				$SSPath = "$FullPath@$Snap"
				$EachSnap = New-Object -TypeName PSObject
				$EachSnap | Add-Member -Type NoteProperty -Name Array -Value $Array
				$EachSnap | Add-Member -Type NoteProperty -Name PoolName -Value $PoolName
				$EachSnap | Add-Member -Type NoteProperty -Name ProjectName -Value $ProjectName
				$EachSnap | Add-Member -Type NoteProperty -Name LocalSnap -Value $LocalSnap
				$EachSnap | Add-Member -Type NoteProperty -Name SnapType -Value $SnapType
				$EachSnap | Add-Member -Type NoteProperty -Name SnapName -Value $Snap
				If ($SnapType -eq "Share"){$EachSnap | Add-Member -Type NoteProperty -Name ShareName -Value $ShareName}
				If ($SnapType -eq "LUN"){$EachSnap | Add-Member -Type NoteProperty -Name LUNName -Value $LUNName}
				$EachSnap | Add-Member -Type NoteProperty -Name SnapFullPath -Value $SSPath
				$SnapReport += $EachSnap
			}
	}
	End{
		Write-Output $SnapReport
		If ($Array -and $ArrayUser -and $ArrayPassword){
			$NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
			CLV ArrayTable -Scope Global -EA SilentlyContinue
			$Global:ArrayTable = @()
			$Global:ArrayTable = $NewCred
		}
	}
}

function Add-IntelliFlashClone {
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$Array,
		[Parameter()]
		[String[]]$ArrayUser,
		[Parameter()]
		[String[]]$ArrayPassword,
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$PoolName,
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$ProjectName,
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$SnapName,
		[Parameter(ValueFromPipelineByPropertyName=$True)]
		[String[]]$ShareName,
		[Parameter(ValueFromPipelineByPropertyName=$True)]
		[String[]]$LUNName,
		[Parameter(ValueFromPipelineByPropertyName=$True)]
		[String[]]$CloneName,
		[Parameter(ValueFromPipelineByPropertyName=$True)]
		[Switch[]]$Inherit,
		[Parameter(ValueFromPipelineByPropertyName=$True)]
		[Switch[]]$InheritLUNMappingsFromParentLUN,
		[Parameter(ValueFromPipelineByPropertyName=$True)]
		[Switch[]]$InheritLUNMappingsFromTargetProject,
		[Parameter()]
		[Switch]$InheritAll,
		[Parameter(ValueFromPipelineByPropertyName=$True)]
		[ValidateSet("FC", "iSCSI")]
		[String[]]$Protocol,
		[Parameter()]
		[Switch]$ALLiSCSI
		
	)
	Begin{
		if (!$global:ArrayTable) {
			If ($Array -and $ArrayUser -and $ArrayPassword){
				CLV CLINE -EA SilentlyContinue
				$CLINE = @()
				$CLINEReport = New-Object -TypeName PSObject
				$CLINEReport | Add-Member -Type NoteProperty -Name Array -Value $Array
				$CLINEReport | Add-Member -Type NoteProperty -Name ArrayUser -Value $ArrayUser
				$CLINEReport | Add-Member -Type NoteProperty -Name ArrayPassword -Value $ArrayPassword
				$CLINE = $CLINEReport
				[void]($CLINE |Connect-IntelliFlash)
				}Else{
				[void](Connect-IntelliFlash)
			}
		}
		CLV CreateCloneReport -EA SilentlyContinue
		$CreateCloneReport = @()
		If($ShareName -and $LUNName){
			Write-Host "You have tried to pass both a LUN name and Share name in the same command." -ForegroundColor yellow -BackgroundColor Black
			Write-Host "This is unsupported." -ForegroundColor yellow -BackgroundColor Black
			Break
		}
		If($AlliSCSI -and $Protocol){
			Write-Host "You have tried to define all LUN Clones as iSCSI and the protocol has been sent to this command." -ForegroundColor yellow -BackgroundColor Black
			Write-Host "This is unsupported." -ForegroundColor yellow -BackgroundColor Black
			Break
		}
		$RUNDATETIME = Get-Date -UFormat "%Y%m%d%H%M%S"
	}
	Process{
			ForEach($CurrentArray in $Array){
				$Cred = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select Cred
				$Cred = $Cred.Cred
				$IntelliFlashVersion = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select IntelliFlashVersion
				$IntelliFlashVersion = [double]$IntelliFlashVersion.IntelliFlashVersion.Substring(0,3)
				If ($IntelliFlashVersion -lt 3.5){$APIVer = "v1"}else{$APIVer = "v2"}
				$CSnapName = $SnapName[0]
				$CPoolName = $PoolName[0]
				$CProjectName = $ProjectName[0]
				If ($Inherit){
					If ($Inherit[0]){$CInherit = "true"}Else{$CInherit = "false"}
					}Else{
					If ($InheritAll){$CInherit = "true"}Else{$CInherit = "false"}
				}
				If ($ShareName){
					$CShareName = $ShareName[0]
					$CFullPath = "$CPoolName/Local/$CProjectName/$CShareName@$CSnapName"
					If ($CloneName){$CCloneName = $CloneName[0]}Else{$CCloneName = "$CShareName" + "-" + "$RUNDATETIME"}
					$postParams = "[`"" + $CFullPath + "`", `"" + $CCloneName + "`",`"" + $CInherit + "`"]"
					Write-Debug $postParams
					$SnapType = "Share"
					$url = "https://$CurrentArray/zebi/api/$APIVer/cloneShareSnapshot"
				}
				If ($LUNName){
					$CLUNName = $LUNName[0]
					$CFullPath = "$CPoolName/Local/$CProjectName/$CLUNName@$CSnapName"
					If ($CloneName){$CCloneName = $CloneName[0]}Else{$CCloneName = "$CLUNName" + "-" + "$RUNDATETIME"}
					If ($ALLiSCSI -and !$Protocol){$CProtocol = "true"}
					If (!$ALLiSCSI -and !$Protocol){$CProtocol = "false"}
					If (!$ALLiSCSI -and $Protocol){
						If ($Protocol[0] = "iSCSI"){$CProtocol = "true"}Else{$CProtocol = "false"}
					}
					If ($InheritLUNMappingsFromParentLUN){
						If($InheritLUNMappingsFromParentLUN[0]){$CInheritLUNMappingsFromParentLUN = "true"}Else{$CInheritLUNMappingsFromParentLUN = "false"}
						}Else{
						$CInheritLUNMappingsFromParentLUN = "false"
					}
					If ($InheritLUNMappingsFromTargetProject){
						If($InheritLUNMappingsFromTargetProject[0]){$CInheritLUNMappingsFromTargetProject = "true"}Else{$CInheritLUNMappingsFromTargetProject = "false"}
						}Else{
						$CInheritLUNMappingsFromTargetProject = "false"
					}
					If ($IntelliFlashVersion -lt 3.5){
						$postParams = "[`"" + $CFullPath + "`", `"" + $CCloneName + "`",`"" + $CInheritLUNMappingsFromParentLUN + "`",`"" + $CInheritLUNMappingsFromTargetProject + "`"]"
						Write-Debug $postParams
						}else{
						$postParams = "[`"" + $CFullPath + "`", `"" + $CCloneName + "`",`"" + $CInheritLUNMappingsFromParentLUN + "`",`"" + $CInheritLUNMappingsFromTargetProject + "`",`"" + $CProtocol + "`"]"
						Write-Debug $postParams
					}
					$SnapType = "LUN"
					$url = "https://$CurrentArray/zebi/api/$APIVer/cloneVolumeSnapshot"
				}
				If (!$ShareName -and !$LUNName){
					$CFullPath = "$CPoolName/Local/$CProjectName@$CSnapName"
					If ($CloneName){$CCloneName = $CloneName[0]}Else{$CCloneName = "$CProjectName" + "-" + "$RUNDATETIME"}
					$postParams = "[`"" + $CFullPath + "`", `"" + $CCloneName + "`",`"" + $CInherit + "`"]"
					Write-Debug $postParams
					$SnapType = "Project"
					$url = "https://$CurrentArray/zebi/api/$APIVer/cloneProjectSnapshot"
				}
				$CurrentClone = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
				If($?){$CloneStatus = "True"}Else{$CloneStatus = "False"} 
				$EachClone = New-Object -TypeName PSObject
				$EachClone | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
				$EachClone | Add-Member -Type NoteProperty -Name PoolName -Value $CPoolName
				$EachClone | Add-Member -Type NoteProperty -Name ProjectName -Value $CProjectName
				If ($SnapType -eq "Share"){$EachClone | Add-Member -Type NoteProperty -Name ShareName -Value $CShareName}
				If ($SnapType -eq "LUN"){$EachClone | Add-Member -Type NoteProperty -Name LUNName -Value $CLUNName}
				If ($SnapType -eq "LUN"){$EachClone | Add-Member -Type NoteProperty -Name InheritLUNMappingsFromParentLUN -Value $CInheritLUNMappingsFromParentLUN}
				If ($SnapType -eq "LUN"){$EachClone | Add-Member -Type NoteProperty -Name InheritLUNMappingsFromTargetProject -Value $CInheritLUNMappingsFromTargetProject}
				If ($SnapType -eq "LUN"){$EachClone | Add-Member -Type NoteProperty -Name Protocol -Value $CProtocol}
				$EachClone | Add-Member -Type NoteProperty -Name SnapFullPath -Value $CFullPath
				$EachClone | Add-Member -Type NoteProperty -Name CloneType -Value $SnapType
				$EachClone | Add-Member -Type NoteProperty -Name CloneName -Value $CCloneName
				If ($SnapType -eq "Share"){$EachClone | Add-Member -Type NoteProperty -Name Inherit -Value $CInherit}
				If ($SnapType -eq "Project"){$EachClone | Add-Member -Type NoteProperty -Name Inherit -Value $CInherit}
				$EachClone | Add-Member -Type NoteProperty -Name Status -Value $CloneStatus
				$EachClone | Add-Member -Type NoteProperty -Name CloneCreateStarted -Value $CloneStatus
				$CreateCloneReport += $EachClone
			}
	}
	End{
		Write-Output $CreateCloneReport
		If ($Array -and $ArrayUser -and $ArrayPassword){
			$NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
			CLV ArrayTable -Scope Global -EA SilentlyContinue
			$Global:ArrayTable = @()
			$Global:ArrayTable = $NewCred
		}
	}
}


## Begin doing our thing

# Connect to vCenter
Write-Host "`nConnecting to vCenter Server $VCServer...`n"

# Disconnect any active vCenter Connections:
$SessionID = ($global:DefaultVIServers | Where-Object -FilterScript {$_.name -eq $VCServer}).sessionId
if ($SessionID) {
    Disconnect-VIServer -Server $VCServer
}

If (!$Password -or !$VCUser) {
	$vccredential = $host.ui.promptforcredential("Need vCenter Credentials", "User Name and Password for vCenter '$VCServer':", "$VCUser", "")
	Connect-VIServer -Server $VCServer -Credential $vccredential -WarningAction SilentlyContinue
} else {
	Connect-VIServer -Server $VCServer -User $VCUser -Password $VCPassword -WarningAction SilentlyContinue
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

# Verify Datastore existence, retrieve LUID for it, and verify vmdk's exist in folder "$SourceVMname":
Write-Host "`n`nGet datastore list..."
$DATASTOREDEVICE = Get-Datastore -Server $VCServer -Name $Datastore | Select Name,@{N='CanonicalName';E={$_.ExtensionData.Info.Vmfs.Extent[0].DiskName}}
$DATASTORENAME = ($DATASTOREDEVICE).Name
if ($DATASTORENAME -ne $Datastore) {
	Write-Host "Your Datastore '$Datastore' doesn't seem to exist, exiting" -foregroundcolor red
	Exit 1
} else {
	$DATASTORELUID = ($DATASTOREDEVICE).CanonicalName -Replace ("naa.","")
	Write-Host "Found Datastore '$Datastore', with LUID '$DATASTORELUID'!" -foregroundcolor green
}
Write-Host "`nGet datacenter info..."
$DATACENTERNAME = (Get-Datacenter -Server $VCServer | Where {$_.Name -eq $Datacenter}).Name
if ($DATACENTERNAME -ne $Datacenter) {
	Write-Host "Your Datacenter name '$Datacenter' is wrong, exiting" -foregroundcolor red
	Exit 1
} else {
	Write-Host "Found Datacenter '$Datacenter'!" -foregroundcolor green
}
Write-Host "`nVerify DB - VMDK File Exisits..."
$DBVMDKFILE = Get-ChildItem -Recurse -Path "vmstore:\$DATACENTERNAME\$DATASTORENAME\$SourceVMname\" -Include $DBvmdk | select Name,DatastoreFullPath
$DBVMDKFILENAME = ($DBVMDKFILE).Name
if ($DBVMDKFILENAME -ne $DBvmdk) {
	Write-Host "Your DB vmdk file $DBvmdk doesn't seem to exist on $DATASTORENAME in folder $SourceVMname, exiting" -foregroundcolor red
	Exit 1
} else {
	Write-Host "Found vmdk '$DBvmdk'!" -foregroundcolor green
}
Write-Host "`nVerify LOG - VMDK File Exists..."
$LOGVMDKFILE = Get-ChildItem -Recurse -Path "vmstore:\$DATACENTERNAME\$DATASTORENAME\$SourceVMname\" -Include $LOGvmdk | select Name,DatastoreFullPath
$LOGVMDKFILENAME = ($LOGVMDKFILE).Name
if ($LOGVMDKFILENAME -ne $LOGvmdk) {
	Write-Host "Your LOG vmdk file $LOGvmdk doesn't seem to exist on $DATASTORENAME in folder $SourceVMname, exiting" -foregroundcolor red
	Exit 1
} else {
	Write-Host "Found vmdk '$LOGvmdk'!" -foregroundcolor green
}

# Connect to IntelliFlash array:
Disconnect-IntelliFlash -all
Write-Host "`nConnecting to the IntelliFlash Array..."
Connect-IntelliFlash -Array $Array -ArrayUser $ArrayUser -ArrayPassword $ArrayPassword

# Get LUN with LUID matching the LUN under the designated datastore, then get latest snapshot and clone it:
Write-Host "`nGet IntelliFlash LUN List..."
$DATASTORELUN = Get-IntelliFlashLUNList | Where {$_.LUID -eq $DATASTORELUID}
If (!$DATASTORELUN) {
	Write-Host "Did not find LUN matching '$DATASTORELUID' on array '$Array', exiting!" -foregroundcolor red
	Exit 1
} else {
	Write-Host "Found matching LUN on array:" -foregroundcolor green
	$DATASTORELUNNAME = $DATASTORELUN.LUNName
	Write-Host "`nLooking for latest snapshot..."
	$DATASTORESNAP = $DATASTORELUN | Get-IntelliFlashSnap | Select-Object -First 1
	if (!$DATASTORESNAP) {
		Write-Host "Did not find any snapshots on LUID '$DATASTORELUID', exiting!" -foregroundcolor red
		Exit 1
	} else {
		Write-Host "Found snapshot on LUID '$DATASTORELUID':" -foregroundcolor green
		$DATASTORESNAPNAME = $DATASTORESNAP.SnapName
		$DATASTORESNAPNAME
		$DATASTORECLONENAME = "$ClonePrefix" + "$DATASTORELUNNAME" + "_" + "$TargetVMname" + "_" + "$DATASTORESNAPNAME"
		# Remove any Invalid characters from $DATASTORECLONENAME, it might look a little wrong but this does work:
		$DATASTORECLONENAME = ($DATASTORECLONENAME -Replace (" ","") -Replace ("``|~|!|@|#|\$|%|\^|&|\*|\(|\)|=|\+|\[|\]|\{|\}|\\|/|\?|<|>|`"|'|;|:",""))
		Write-Host "`nCloning snapshot to new LUN: '$DATASTORECLONENAME'"
		$DATASTORECLONE = $DATASTORESNAP | Add-IntelliFlashClone -CloneName "$DATASTORECLONENAME" -InheritLUNMappingsFromTargetProject $true -Protocol $DATASTORELUN.Protocol
		$clonewait = 0
		$NEWDATASTORECLONE = Get-IntelliFlashLUNList | Where {$_.LUNName -eq "$DATASTORECLONENAME"}
		while ($NEWDATASTORECLONE -eq "") {
			$clonewait++
			if ($clonewait -eq 30) {
				Write-Output "`nWaited 30 seconds for Clone '$DATASTORECLONE' to complete and gave up!"
				Write-Output "Status received from the Clone API call was: $DATASTORECLONE"
				Write-Output "Exiting script!`n"
				Exit 1
			}
			Write-Output "Waiting for Clone to complete..."
			sleep 1
            $NEWDATASTORECLONE = Get-IntelliFlashLUNList | Where {$_.LUNName -eq "$DATASTORECLONENAME"}
		}
		$NEWDATASTORECLONELUID = ($NEWDATASTORECLONE).LUID.ToLower()
		If (!$NEWDATASTORECLONELUID) {
			Write-Host "It seems the LUN did not created, or we can't find one that matches $NEWDATASTORECLONE, exiting!" -foregroundcolor red
			Exit 1
		} else {
			Write-Host "Clone completed, it has LUID '$NEWDATASTORECLONELUID'" -foregroundcolor green
		}
	}
}

# Rescan storage, resignature filesystem on LUN with LUID from $DATASTORECLONE, and rename it to $DATASTORECLONENAME
$ESXISERVER = $VMHosts | Select-Object -First 1
$esxcli = $ESXISERVER | Get-EsxCli -V2
Write-Host "`nRescanning storage on '$ESXISERVER'..."
Get-VMHostStorage -VMHost $ESXISERVER -RescanAllHba -RescanVmfs |Out-Null
Write-Host "`nGet the list of datastores that are snapshots..."
$snaps = ($esxcli.storage.vmfs.snapshot.list.Invoke() | Where {$_.VolumeName -eq "$DATASTORENAME"})
if (!$snaps) {
	Write-Host "Did not find any unresolved/snapshot versions of '$DATASTORENAME', exiting!" -foregroundcolor red
	Exit 1
} else {
	Write-Host "Found the following unresolved/snapshot versions of '$DATASTORENAME':"
	$snaps
	Write-Host "`nResignaturing..."
	foreach ($snap in $snaps) {
		$esxcli.storage.vmfs.snapshot.resignature.Invoke(@{volumeuuid = $snap.VMFSUUID}) |Out-Null
		if ($? -eq "True") {
			Write-Host "Resignature appears to have been successful" -foregroundcolor green
            Write-Host "`nRescanning storage on all hosts..."
            foreach ($VMHost in $VMHosts) {
	            Write-Host "Rescanning $VMHost..."
                Get-VMHostStorage -VMHost $VMHost -RescanAllHba -RescanVmfs |out-null
            }
			Write-Host "`nRenaming datastore with LUID '$NEWDATASTORECLONELUID' to '$DATASTORECLONENAME'..."
            Sleep 5
			$DSList = ((Get-View (Get-View (Get-VMHost -Name $ESXISERVER).ID).ConfigManager.StorageSystem).FileSystemVolumeInfo.MountInfo.Volume | Select Name,Extent)
            foreach ($DS in $DSList){
                If ($DS.Extent.DiskName -like "*$NEWDATASTORECLONELUID*"){
                    $DSRenameStatus = (Get-Datastore -Name $DS.Name| Set-Datastore -Name $DATASTORECLONENAME)
                }
            }
            if ($? -eq "True") {
				Write-Host "Rename appears to have completed as well!" -foregroundcolor green
			} else {
				Write-Host "Rename appears to have failed, exiting!" -foregroundcolor red
				Exit 1
			}
		} else {
			Write-Host "Resignature appears to have failed, exiting!" -foregroundcolor red
			Exit 1
		}
	}
}

# Rescan all hosts
Write-Host "`nRescanning storage on all hosts..."
foreach ($VMHost in $VMHosts) {
    Write-Host "Rescanning $VMHost..."
    Get-VMHostStorage -VMHost $VMHost -RescanAllHba -RescanVmfs |out-null
}

# Get the Target VM Details
Write-Host "`nGet VM Details for '$TargetVMname'..."
# Clearing Errors so we can capture any final issues
$Error.Clear()
$TgtVM = (Get-VM $TargetVMname)
if (!$Error) {
    Write-Host "VM details acquired!" -foregroundcolor green
	} else {
	Write-Host "VM query has failed, exiting!" -foregroundcolor red
	Exit 1
}

# Get the new CLONE Path
Write-Host "`nCheck the CLONE DB - VMDK file path..."
$CLONEDBVMDKFILE = Get-ChildItem -Recurse -Path "vmstore:\$DATACENTERNAME\$DATASTORECLONENAME\$SourceVMname\" -Include $DBvmdk | select Name,DatastoreFullPath
Write-Host "Check the CLONE LOG - VMDK file path..."
$CLONELOGVMDKFILE = Get-ChildItem -Recurse -Path "vmstore:\$DATACENTERNAME\$DATASTORECLONENAME\$SourceVMname\" -Include $LOGvmdk | select Name,DatastoreFullPath

# Add vmdk's from clone to TargetVMname
Write-Host "`nAdd the Clone DB VMDK file to the VM..."
New-HardDisk -VM $TgtVM -DiskPath $CLONEDBVMDKFILE.DatastoreFullPath |Out-Null
if (!$Error) {
    Write-Host "New DB Clone - Virtual HD has been added to the VM." -foregroundcolor green
	} else {
	Write-Host "DB Clone - Virtual HD Addition Failed, exiting!" -foregroundcolor red
	Exit 1
}
Write-Host "`nAdd the Clone LOG VMDK file to the VM..."
New-HardDisk -VM $TgtVM -DiskPath $CLONELOGVMDKFILE.DatastoreFullPath |Out-Null
if (!$Error) {
    Write-Host "New LOG Clone - Virtual HD has been added to the VM." -foregroundcolor green
	} else {
	Write-Host "LOG Clone - Virtual HD Addition Failed, exiting!" -foregroundcolor red
	Exit 1
}

Write-Host "`n`nProcess Completed Successfully!`n" -foregroundcolor green
Write-Host "`nLog file is available in: $logdir`n" -foregroundcolor yellow
Stop-Transcript