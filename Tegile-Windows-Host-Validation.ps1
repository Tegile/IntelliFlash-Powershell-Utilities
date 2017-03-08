[CmdletBinding(ConfirmImpact='Medium')]

	Param(
		[Parameter()]
		[switch]
		$iscsi,
		[Parameter()]
		[switch]
		$bfs,
		[Parameter()]
		[switch]
		$nobfs,
		[Parameter()]
		[switch]
		$tdps,
		[Parameter()]
		[Switch]
		$autoapply,
		[Parameter()]
		[Alias("v")] 
		[Alias("ver")] 
		[Switch]
		$Version
	)

    Begin{
		# Variables for Tegile Host Configuration:
		# MPIO Settings:
		$Recommended_PathVerificationState = "Enabled"
		$Recommended_PathVerificationPeriod = "5"
		$Recommended_RetryCount = "100"
		$Recommended_PDORemovePeriod = "180"
		$Recommended_RetryInterval = "1"
		$Recommended_DiskTimeoutValue = "180"
		# iSCSI-Specific Settings:
		$Recommended_MaxRequestHoldTime = "180"
		$Recommended_LinkDownTime = "15"
		$Recommended_BFSiSCSIioSize = "131072"
		$Recommended_NonBFSiSCSIioSize = "65536"
		# End of Tegile Host Configuration Variables

		$MajorVer = 3
		$MinorVer = 5
		$PatchVer = 0
		$BuildVer = 2
		$VerMonth = "December"
		$VerYear = 2016
		$LogReport += $EachLog
		if ($Version){
			$VerReport = @()
			CLV EachVer -EA SilentlyContinue
			CLV VerReport -EA SilentlyContinue
			$EachVer = @()
			$EachVer = New-Object -TypeName PSObject
			$EachVer | Add-Member -Type NoteProperty -Name Vendor -Value "Tegile Systems Inc."
			$EachVer | Add-Member -Type NoteProperty -Name Author -Value "Ken Nothnagel & Ben Kendall, Tegile Professional Services"
			$EachVer | Add-Member -Type NoteProperty -Name Version -Value "$MajorVer.$MinorVer.$PatchVer.$BuildVer"
			$EachVer | Add-Member -Type NoteProperty -Name Major -Value $MajorVer
			$EachVer | Add-Member -Type NoteProperty -Name Minor -Value $MinorVer
			$EachVer | Add-Member -Type NoteProperty -Name Patch -Value $PatchVer
			$EachVer | Add-Member -Type NoteProperty -Name Build -Value $BuildVer
			$VerReport += $EachVer
			Write-Output $VerReport
			Break
		}
		#Check for administrator role.
		If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
			[Security.Principal.WindowsBuiltInRole] "Administrator"))
		{
			Write-Error "You do not have Administrator rights.`nPlease re-run this script as an Administrator!"
			Break
		}
       
		#Check for OS Version.
		$CurrentOSVersion = [version](Get-CimInstance Win32_OperatingSystem).Version
		$Win2012R2Ver = [version]'6.3.9600'
		$OS_Description = (Get-WmiObject Win32_OperatingSystem).Name
		If ($CurrentOSVersion -lt $Win2012R2Ver -or $OS_Description -notlike "*Server 201*"){
			Write-Host "This function is compatible with Windows 2012 R2 and Windows 2016 Only" -BackgroundColor Black -ForegroundColor Yellow; Break
			#CAN DISPLAY ALL RECOMMENDATIONS FOR OTHER OS
		}
		$DISCLAIMER = "DISCLAIMER`r`n`r`nThis script is provided AS IS without warranty of any kind. Tegile further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose. The entire risk arising out of the use or performance of this script and documentation remains with you. In no event shall Tegile, or anyone else involved in the creation, production, or delivery of this script be liable for any damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use this script or documentation, even if Tegile has been advised of the possibility of such damages.`r`n`r`nThis Script should only be run with the direct supervision of a Tegile Engineer."
		$RUNDATETIME = Get-Date -UFormat "%Y%m%d%H%M%S"
		$LOGFILE = "$RUNDATETIME.$env:computername.TEGILE.log"
		$LOG = "$RUNDATETIME.$env:computername.MPIO.tmp"
		$LogReport = @()
		$AUTO = "NO"
		$EachLog = New-Object -TypeName PSObject
		$EachLog | Add-Member -Type NoteProperty -Name StartDate -Value $RUNDATETIME
		$EachLog | Add-Member -Type NoteProperty -Name LogFile -Value $LOGFILE

		if (($autoapply -and (!$bfs -and !$nobfs)) -or ($autoapply -and $bfs -and $nobfs)){write-error "Autoapply requires either -bfs or -nobfs";Break}
		if ($autoapply -and $bfs){$AUTO = "AUTOBFS"}
		if ($autoapply -and $nobfs){$AUTO = "AUTONOBFS"}
	}
	Process{
		$error.clear()
		Clear
		write-host $DISCLAIMER
		if (!$AUTOAPPLY) {
			$title = ""
			$message = "`r`nAccept Disclaimer?`r`n`r`n"
			$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Accept and continue"
			$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Quit now"
			$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
			$ACCEPTED = $host.ui.PromptForChoice($title, $message, $options, 1) 
			if ($ACCEPTED -eq 1){$EachLog | Add-Member -Type NoteProperty -Name Disclaimer -Value "Not-Accepted";$LogReport += $EachLog;Write-Output $LogReport;Break} Else {$EachLog | Add-Member -Type NoteProperty -Name Disclaimer -Value "Accepted"}

			$title = ""
			$message = "`r`nDoes this server boot from SAN over iSCSI?`r`n`r`n"
			$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Sets the recommended iSCSI IO lengths to 128K"
			$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Sets the recommended iSCSI IO lengths to 64K"
			$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
			Clear
			$BFSResponse = $host.ui.PromptForChoice($title, $message, $options, 1) 
			if ($BFSResponse -eq 0) {$iscsiiosize = $Recommended_BFSiSCSIioSize;$bfs = $true} Else {$iscsiiosize = $Recommended_NonBFSiSCSIioSize;$bfs = $false}
			$EachLog | Add-Member -Type NoteProperty -Name AutoApply -Value $AUTO
		} Else {
			if ($AUTO -eq "AUTOBFS"){$iscsiiosize = $Recommended_BFSiSCSIioSize}
			if ($AUTO -eq "AUTONOBFS"){$iscsiiosize = $Recommended_NonBFSiSCSIioSize}
			write-host "Disclaimer is automatically accepted when using -autoapply"
			$EachLog | Add-Member -Type NoteProperty -Name Disclaimer -Value "Auto-Accepted"
			$EachLog | Add-Member -Type NoteProperty -Name AutoApply -Value $AUTO
        }
		$EachLog | Add-Member -Type NoteProperty -Name ISCSI-BFS -Value $BFS
		$EachLog | Add-Member -Type NoteProperty -Name ISCSI-Recommended-MaxTransferLength -Value $iscsiiosize
		$EachLog | Add-Member -Type NoteProperty -Name ISCSI-Recommended-MaxBurstLength -Value $iscsiiosize

		# Check status of MSiSCSI Service and provide or capture option to enable and start it:
		$ISCSISTARTUP = "UNKNOWN"
		$iscsiservice = "UNKNOWN"
		$iscsiservice = (Get-Service -Name MSiSCSI)
		if ($iscsiservice.status -ne "Running"){
			if ($iscsi){
				$ISCSISTARTUP = "YES"
				$EachLog | Add-Member -Type NoteProperty -Name ISCSI-Service_Startup_AutoApply -Value "Applied"
			} ElseIf ($AUTOAPPLY){
				$EachLog | Add-Member -Type NoteProperty -Name ISCSI-Service_Startup_AutoApply -Value "Skipped"				
			} Else {
			$title = ""
			$message = "`r`niSCSI Service isn't running, start it?`r`n`r`n"
			$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Start MSiSCSI Service and set to Automatic Startup"
			$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Leave MSiSCSI Service Off"
			$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
			$STARTISCSI = $host.ui.PromptForChoice($title, $message, $options, 1) 
			if ($STARTISCSI -eq 0){$ISCSISTARTUP = "YES"}
			}
		}

		# Now we'll attempt to start the MSiSCSI Service if determined from above that we should
		if ($ISCSISTARTUP -eq "YES"){
			$error.clear()
			Set-Service -Name MSiSCSI -StartupType Automatic
			if ($error){$EachLog | Add-Member -Type NoteProperty -Name ISCSI-Service_SetStartupType -Value "Failed"} Else {$EachLog | Add-Member -Type NoteProperty -Name ISCSI-Service_SetStartupType -Value "Automatic"}
			Start-Service -Name MSiSCSI
			if ($error){$EachLog | Add-Member -Type NoteProperty -Name ISCSI-Service_StartService -Value "Failed"} Else {$EachLog | Add-Member -Type NoteProperty -Name ISCSI-Service_StartService -Value "Started"}
			$iscsiservice = (Get-Service -Name MSiSCSI)
			if ($iscsiservice.status -ne "Running"){write-host "`r`nMSiSCSI Service Failed to Start" -foregroundcolor red} Else {write-host "`r`nMSiSCSI Service Started"}
		}

		# One last check again to see if MSiSCSI is running or not after previous options to enable it, then proceeding:
		$iscsiservice = (Get-Service -Name MSiSCSI)
		if ($iscsiservice.status -ne "Running"){
			write-host "`r`n`r`nTo check and apply iSCSI settings, MSiSCSI Service needs to be running" -BackgroundColor Black -ForegroundColor Yellow
			$EachLog | Add-Member -Type NoteProperty -Name ISCSI-Service_Status -Value "Stopped"
		} Else {
			$EachLog | Add-Member -Type NoteProperty -Name ISCSI-Service_Status -Value "Running"
			$EachLog | Add-Member -Type NoteProperty -Name ISCSI-Recommended-MaxRequestHoldTime -Value $Recommended_MaxRequestHoldTime
			$EachLog | Add-Member -Type NoteProperty -Name ISCSI-Recommended-LinkDownTime -Value $Recommended_LinkDownTime

			#FIND THE RIGHT REGISTRY KEY FOR ISCSI INITIATOR
			$iscsipath = Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Control\Class\"{4d36e97b-e325-11ce-bfc1-08002be10318}" -Recurse -ErrorAction SilentlyContinue |Get-ItemProperty -name DriverDesc -ErrorAction SilentlyContinue|Where {$_.DriverDesc -like "Microsoft iSCSI Initiator"}|foreach {echo $_.PSPath}
			$iscsipath = "$iscsipath\Parameters"
			$iscsipath_log = "`"$iscsipath`""
			$MTL = (get-item -path $iscsipath |Get-ItemProperty -ErrorAction SilentlyContinue -name MaxTransferLength)
			$MBL = (get-item -path $iscsipath |Get-ItemProperty -ErrorAction SilentlyContinue -name MaxBurstLength)
			$MRHT = (get-item -path $iscsipath |Get-ItemProperty -ErrorAction SilentlyContinue -name MaxRequestHoldTime)
			$LDT = (get-item -path $iscsipath |Get-ItemProperty -ErrorAction SilentlyContinue -name LinkDownTime)

			$MTL = $MTL.MaxTransferLength
			$MBL = $MBL.MaxBurstLength
			$MRHT = $MRHT.MaxRequestHoldTime
			$LDT = $LDT.LinkDownTime
			$EachLog | Add-Member -Type NoteProperty -Name ISCSI-Original-MaxTransferLength -Value $MTL
			$EachLog | Add-Member -Type NoteProperty -Name ISCSI-Original-MaxBurstLength -Value $MBL
			$EachLog | Add-Member -Type NoteProperty -Name ISCSI-Original-MaxRequestHoldtime -Value $MRHT
			$EachLog | Add-Member -Type NoteProperty -Name ISCSI-Original-MaxLinkDownTime -Value $LDT

			#Check for single initiator side IPs per NIC

			$iSCSISession = Get-IscsiSession
			$SameSubnet = "NO"
			ForEach ($Session in $iSCSISession){
				[ipaddress]$CurrentIP = $Session.InitiatorPortalAddress
				$CurrentTarget = $Session.TargetNodeAddress
				ForEach ($Check in $iSCSISession){
					$C1 = $Check.TargetNodeAddress
					[ipaddress]$C2 = $Check.InitiatorPortalAddress
					If ($CurrentTarget -eq $C1){
						If ($CurrentIP){
							$A1 = $CurrentIP.GetAddressBytes()
							$B1 = $C2.GetAddressBytes()
							If (($A1[0] -eq $B1[0]) -and ($A1[1] -eq $B1[1]) -and ($A1[2] -eq $B1[2]) -and ($A1[3] -ne $B1[3])){
								Write-Verbose "These two Initiator IPs seem to be on the same subnet:"
								Write-Verbose $CurrentIP.IPAddressToString
								Write-Verbose $C2.IPAddressToString
								$SameSubnet = "YES"
							}
						} 
					}
				}
			}

			$EachLog | Add-Member -Type NoteProperty -Name ISCSI-MultipleIPsSameSubnet -Value $SameSubnet
			If ($SameSubnet -eq "YES"){Write-Host "This host appears to have multiple iSCSI initiator IPs on the same subnet.`r`nTegile Support recommends adjusting so you have a single initiator side IP on each subnet.`r`nPlease work with Tegile Support or Tegile Professional Services for assistence if needed.`r`n" -ForegroundColor Yellow -BackgroundColor Black}

			#Check for Network Services enabled on iSCSI interfaces
			$NetBindReport = @()
			$iscsiip = Get-IscsiSession|select InitiatorPortalAddress
			$iscsiip = $iscsiip.InitiatorPortalAddress
			$iscsiip = $iscsiip|Sort -Unique
			ForEach ($IP in $iscsiip){
				$IntName = Get-NetIPAddress |Where {$_.IPAddress -eq $IP}|Select InterfaceAlias
				$IscsiBinding = Get-NetAdapterBinding -Name $IntName.InterfaceAlias
				$NetBindEnabled = $IscsiBinding|Where {$_.Enabled -eq "True" -and $_.DisplayName -ne "Internet Protocol Version 4 (TCP/IPv4)"}
				$NetBindReport += $NetBindEnabled
			}
			If ($NetBindReport){
				Write-Host "`r`n`r`nIf the currently connected iSCSI network interfaces ONLY serve iSCSI then the following network services should be disabled on these interfaces:`r`n" -BackgroundColor Black -ForegroundColor Yellow
				$NetBindReport
				$EachLog | Add-Member -Type NoteProperty -Name ISCSI-NetBindingsToRemove -Value "YES"
			} Else {
				$EachLog | Add-Member -Type NoteProperty -Name ISCSI-NetBindingsToRemove -Value "NO"
			}

			#Check for Hotfixes
			Write-Progress -Activity "Checking installed hotfixes"
			$OS_Root = (Get-ChildItem Env:|Where {$_.Name -eq "SystemRoot"})
			$MPIOVer = (Get-WmiObject Win32_PnPSignedDriver| select devicename, driverversion|Where {$_.devicename -eq "Microsoft Multi-Path Bus Driver"})
			$MPIOVer = [version]$MPIOVer.driverversion
			$MSDSMVer = (Get-WmiObject Win32_PnPSignedDriver| select devicename, driverversion|Where {$_.devicename -eq "Microsoft Multi-Path Device Specific Module"})
			$MSDSMVer = [version]$MSDSMVer.driverversion
			$STORPORTPath = $OS_Root.Value + "\System32\drivers\storport.sys"
			$STORPORTVer = [version](Get-Item $STORPORTPath).VersionInfo.ProductVersion
			Write-Progress -Completed -Activity "Checking installed hotfixes"
			If ($MPIOVer -and ($MPIOVer -lt [version]"6.3.9600.18007")){
				Write-Host "KB3078420 is missing. Please download and install : https://support.microsoft.com/en-us/kb/3078420" -BackgroundColor Black -ForegroundColor Yellow
				$EachLog | Add-Member -Type NoteProperty -Name ISCSI-KB3078420-Missing -Value "True"
			} Else {$EachLog | Add-Member -Type NoteProperty -Name ISCSI-KB3078420-Missing -Value "False"}
			If ($MSDSMVer -and ($MSDSMVer -lt [version]"6.3.9600.17809")){
				Write-Host "KB3046101 is missing. Please download and install : https://support.microsoft.com/en-us/kb/3046101" -BackgroundColor Black -ForegroundColor Yellow
				$EachLog | Add-Member -Type NoteProperty -Name ISCSI-KB3046101-Missing -Value "True"
			} Else {$EachLog | Add-Member -Type NoteProperty -Name ISCSI-KB3046101-Missing -Value "False"}
			If ($STORPORTVer -and ($STORPORTVer -lt [version]"6.3.9600.17937")){
				Write-Host "KB3080728 is missing. Please download and install : https://support.microsoft.com/en-us/kb/3080728" -BackgroundColor Black -ForegroundColor Yellow
				$EachLog | Add-Member -Type NoteProperty -Name ISCSI-KB3080728-Missing -Value "True"
			} Else {$EachLog | Add-Member -Type NoteProperty -Name ISCSI-KB3080728-Missing -Value "False"}

			#DISPLAY RECOMMENDATIONS FOR THE ISCSI INITIATOR

			if ($MTL -ne $iscsiiosize) {write-host "`r`nMaxTransferLength is set to $MTL `t`t<== Should be $iscsiiosize" -foregroundcolor red;$CHANGES += "get-item -path ""$iscsipath"" |Set-ItemProperty -ErrorAction SilentlyContinue -name MaxTransferLength -value $iscsiiosize`n"} Else {write-host "`r`nMaxTransferLength is set to $MTL which is good."}
			if ($MBL -ne $iscsiiosize) {write-host "MaxBurstLength is set to $MBL `t`t<== Should be $iscsiiosize" -foregroundcolor red;$CHANGES += "get-item -path ""$iscsipath"" |Set-ItemProperty -ErrorAction SilentlyContinue -name MaxBurstLength -value $iscsiiosize`n"} Else {write-host "MaxBurstLength is set to $MBL which is good."}
			if ($MRHT -ne $Recommended_MaxRequestHoldTime) {write-host "MaxRequestHoldTime is set to $MRHT `t`t<== Should be $Recommended_MaxRequestHoldTime" -foregroundcolor red;$CHANGES += "get-item -path ""$iscsipath"" |Set-ItemProperty -ErrorAction SilentlyContinue -name MaxRequestHoldTime -value $Recommended_MaxRequestHoldTime`n"} Else {write-host "MaxRequestHoldTime is set to $MRHT which is good."}
			if ($LDT -ne $Recommended_LinkDownTime) {write-host "LinkDownTime is set to $LDT `t`t`t<== Should be $Recommended_LinkDownTime`r`n" -foregroundcolor red;$CHANGES += "get-item -path ""$iscsipath"" |Set-ItemProperty -ErrorAction SilentlyContinue -name LinkDownTime -value $Recommended_LinkDownTime`n"} Else {write-host "LinkDownTime is set to $LDT which is good.`r`n"}
		}
		#Check for TDPS
		If ($TDPS){
			$TDPSReg = $()
			$TDPSSearchProgress = 0
			Write-Progress -Activity "Checking the registry for TDPS" -Status "Progress:" -PercentComplete $TDPSSearchProgress
			$TDPSReg = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData" -Recurse |ForEach-Object {
				Get-ItemProperty $_.pspath 
				$TDPSSearchProgress++
				If ($TDPSSearchProgress -eq 99){$TDPSSearchProgress = 1}
				Write-Progress -Activity "Checking the registry for TDPS" -Status "Progress:$_" -percentcomplete ($TDPSSearchProgress)
				} |Where-Object {$_.DisplayName -eq "Tegile Data Protection Services"}
			Write-Progress -Activity "Checking the registry for TDPS" -Completed
			If ($TDPSReg){
				$TDPSCurrentVer = [version]'2.0.0.17'
				$TDPSInstalledVer = [version]$TDPSReg.DisplayVersion

				If ($TDPSInstalledVer -lt $TDPSCurrentVer){
					Write-Host "Your TDPS Version is out of date" -ForegroundColor Yellow -BackgroundColor Black
					Write-Host "TDPS Installed: $TDPSInstalledVer" -ForegroundColor Yellow -BackgroundColor Black
					Write-Host "Current TDPS Version: $TDPSCurrentVer" -ForegroundColor Yellow -BackgroundColor Black
					$EachLog | Add-Member -Type NoteProperty -Name TDPS-Installed -Value "True"
					$EachLog | Add-Member -Type NoteProperty -Name TDPS-Outdated -Value "True"
					$EachLog | Add-Member -Type NoteProperty -Name TDPS-Installed-Version -Value $TDPSInstalledVer
				} Else {
					Write-Verbose "TDPS is up to date"
					Write-Verbose "TDPS installed version: $TDPSInstalledVer"
					$EachLog | Add-Member -Type NoteProperty -Name TDPS-Installed -Value "True"
					$EachLog | Add-Member -Type NoteProperty -Name TDPS-Outdated -Value "False"
					$EachLog | Add-Member -Type NoteProperty -Name TDPS-Installed-Version -Value $TDPSInstalledVer
				}
			} Else {
				$EachLog | Add-Member -Type NoteProperty -Name TDPS-Installed -Value "False"
				Write-host "TDPS Not Installed"
			}
		} Else {
			$EachLog | Add-Member -Type NoteProperty -Name TDPS-Checked -Value "False"
		}
		#Check for PowerShell-V2 Backward Compatibility
		$PS2Engine = Get-WindowsFeature|Where {$_.Name -eq "PowerShell-V2"}
		If($PS2Engine.Installed -eq "True"){
			Write-Verbose "PowerShell-V2 installed"
			$EachLog | Add-Member -Type NoteProperty -Name TDPS-PowerShell-V2-Installed -Value "True"
		} Else {
			Write-host "PowerShell-V2 NOT Installed" -ForegroundColor Yellow -BackgroundColor Black
			Write-host "PowerShell-V2 is required for TDPS"-ForegroundColor Yellow -BackgroundColor Black
			$EachLog | Add-Member -Type NoteProperty -Name TDPS-PowerShell-V2-Installed -Value "False"
		}
		#CHECK IF MPIO IS ENABLED
		$pidintelliflash = "Missing"
		$pidiscsi = "Missing"
		$pidfc = "Missing"
		Write-Progress -Activity "Checking for MPIO" -Status "Checking..."
		$mpioenabled = Get-WindowsOptionalFeature -Online -FeatureName MultiPathIO|Select-Object state
		Write-Progress -Activity "Checking for MPIO" -Status "Checking..." -Completed
		if (!$mpioenabled){$mpioenabled = "Disabled or Missing"} Else {$mpioenabled = $mpioenabled.state}
		If ($mpioenabled -eq "Enabled"){
			$vidpid = Get-MSDSMSupportedHW|where {$_.VendorId -eq "TEGILE"} |ForEach-Object {
				if ($_.ProductId -eq "INTELLIFLASH") {$pidintelliflash = "Good"}
				if ($_.ProductId -eq "ZEBI-ISCSI") {$pidiscsi = "Good"}
				if ($_.ProductId -eq "ZEBI-FC") {$pidfc = "Good"}
			}
			$EachLog | Add-Member -Type NoteProperty -Name SAN-Original-PID-INTELLIFLASH -Value $pidintelliflash
			$EachLog | Add-Member -Type NoteProperty -Name ISCSI-Original-PID-ZEBI-ISCSI -Value $pidiscsi
			$EachLog | Add-Member -Type NoteProperty -Name FC-Original-PID-ZEBI-FC -Value $pidfc

			#CHECK MPIO SETTINGS
			Write-Progress -Activity "Checking MPIO Settings" -Status "Checking..."
			Get-MPIOSetting > .\$LOG
			Write-Progress -Activity "Checking MPIO Settings" -Status "Checking..." -Completed
			$PathVerificationStateTmp = ((get-itemproperty "HKLM:\System\CurrentControlSet\Services\MSDSM\Parameters").PathVerifyEnabled)
			$PathVerificationState = "PathVerificationState     : Disabled"
			If ($PathVerificationStateTmp -eq "1"){$PathVerificationState = "PathVerificationState     : Enabled"}
			$PathVerificationPeriod = (Get-Content .\$LOG)[3]
			$RetryCount = (Get-Content .\$LOG)[5]
			$PDORemovePeriod = (Get-Content .\$LOG)[4]
			$RetryInterval = (Get-Content .\$LOG)[6]
			$DiskTimeoutValue = (Get-Content .\$LOG)[9]
			Remove-Item .\$LOG
			$EachLog | Add-Member -Type NoteProperty -Name SAN-Original-PathVerificationState -Value ($PathVerificationState.Substring(28))
			$EachLog | Add-Member -Type NoteProperty -Name SAN-Original-PathVerificationPeriod -Value ($PathVerificationPeriod.Substring(28))
			$EachLog | Add-Member -Type NoteProperty -Name SAN-Original-RetryCount -Value ($RetryCount.Substring(28))
			$EachLog | Add-Member -Type NoteProperty -Name SAN-Original-PDORemovePeriod -Value ($PDORemovePeriod.Substring(28))
			$EachLog | Add-Member -Type NoteProperty -Name SAN-Original-RetryInterval -Value ($RetryInterval.Substring(28))
			$EachLog | Add-Member -Type NoteProperty -Name SAN-Original-DiskTimeoutValue -Value ($DiskTimeoutValue.Substring(28))

			#CHECK AND MAKE MPIO SETTING RECOMMENDATIONS
			if ($PathVerificationState -ne "PathVerificationState     : Enabled") {write-host "$PathVerificationState `t`t<== Should be Enabled" -foregroundcolor red;$CHANGES += "Set-ItemProperty HKLM:\System\CurrentControlSet\Services\MSDSM\Parameters -name PathVerifyEnabled -value 1`n"} Else {write-host $PathVerificationState}
			if ($PathVerificationPeriod -ne "PathVerificationPeriod    : $Recommended_PathVerificationPeriod") {write-host "$PathVerificationPeriod `t`t`t<== Should be $Recommended_PathVerificationPeriod" -foregroundcolor red;$CHANGES += "Set-MPIOSetting -NewPathVerificationPeriod $Recommended_PathVerificationPeriod`n"} Else {write-host $PathVerificationPeriod}
			if ($RetryCount -ne "RetryCount                : $Recommended_RetryCount") {write-host "$RetryCount `t`t`t<== Should be $Recommended_RetryCount" -foregroundcolor red;$CHANGES += "Set-MPIOSetting -NewRetryCount $Recommended_RetryCount`n"} Else {write-host $RetryCount}
			if ($PDORemovePeriod -ne "PDORemovePeriod           : $Recommended_PDORemovePeriod") {write-host "$PDORemovePeriod `t`t<== Should be $Recommended_PDORemovePeriod" -foregroundcolor red;$CHANGES += "Remove-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\msdsm\Parameters -Name PDORemovePeriod -ErrorAction Ignore;New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\msdsm\Parameters -Name PDORemovePeriod -Value $Recommended_PDORemovePeriod -PropertyType DWord`n"} Else {write-host $PDORemovePeriod}
			if ($RetryInterval -ne "RetryInterval             : $Recommended_RetryInterval") {write-host "$RetryInterval `t`t`t<== Should be $Recommended_RetryInterval" -foregroundcolor red;$CHANGES += "Remove-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\msdsm\Parameters -Name RetryInterval;New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\msdsm\Parameters -Name RetryInterval -Value $Recommended_RetryInterval -PropertyType DWord`n"} Else {write-host $RetryInterval}
			if ($DiskTimeoutValue -ne "DiskTimeoutValue          : $Recommended_DiskTimeoutValue") {write-host "$DiskTimeoutValue `t`t<== Should be $Recommended_DiskTimeoutValue" -foregroundcolor red;$CHANGES += "Remove-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\disk -Name TimeoutValue;New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\disk -Name TimeoutValue -Value $Recommended_DiskTimeoutValue -PropertyType DWord`n"} Else {write-host $DiskTimeoutValue}
			$EachLog | Add-Member -Type NoteProperty -Name SAN-Recommended-PathVerificationState -Value $Recommended_PathVerificationState
			$EachLog | Add-Member -Type NoteProperty -Name SAN-Recommended-PathVerificationPeriod -Value $Recommended_PathVerificationPeriod
			$EachLog | Add-Member -Type NoteProperty -Name SAN-Recommended-RetryCount -Value $Recommended_RetryCount
			$EachLog | Add-Member -Type NoteProperty -Name SAN-Recommended-PDORemovePeriod -Value $Recommended_PDORemovePeriod
			$EachLog | Add-Member -Type NoteProperty -Name SAN-Recommended-RetryInterval -Value $Recommended_RetryInterval
			$EachLog | Add-Member -Type NoteProperty -Name SAN-Recommended-DiskTimeoutValue -Value $Recommended_DiskTimeoutValue
		}
		$EachLog | Add-Member -Type NoteProperty -Name SAN-MPIO -Value $mpioenabled

		#Show MPIO Requirement
		if ($mpioenabled -ne "Enabled") {write-host "`r`nMPIO Enabled = $mpioenabled `t`t`t`t<== MPIO must be enabled" -foregroundcolor red;$CHANGES += "Enable-WindowsOptionalFeature -Online -FeatureName MultiPathIO -NoRestart`n"} Else {write-host "`r`nMPIO Enabled = $mpioenabled"}
		
		#Suggest Tegile VID/PID, and add commands to $CHANGES after first checking if MPIO cmdlet exists
		$mpiocmdlet = (get-command New-MSDSMSupportedHW -ErrorAction SilentlyContinue).Name
		if ($pidintelliflash -eq "Missing") {
			write-host "INTELLIFLASH = $pidintelliflash `t`t`t`t<== The INTELLIFLASH PID should be added" -foregroundcolor red
			if ($mpiocmdlet) {$CHANGES += "New-MSDSMSupportedHW -VendorId ""TEGILE"" -ProductId ""INTELLIFLASH""`n"}
		} Else {
			write-host "INTELLIFLASH = $pidintelliflash"
		}
		if ($pidiscsi -eq "Missing") {
			write-host "ZEBI-ISCSI = $pidiscsi `t`t`t`t<== The ZEBI-ISCSI PID should be added" -foregroundcolor red
			if ($mpiocmdlet) {$CHANGES += "New-MSDSMSupportedHW -VendorId ""TEGILE"" -ProductId ""ZEBI-ISCSI""`n"}
		} Else {
			write-host "ZEBI-ISCSI = $pidiscsi"
		}
		if ($pidfc -eq "Missing") {
			write-host "ZEBI-FC = $pidfc `t`t`t`t<== The ZEBI-FC PID should be added" -foregroundcolor red
			if ($mpiocmdlet) {$CHANGES += "New-MSDSMSupportedHW -VendorId ""TEGILE"" -ProductId ""ZEBI-FC""`n"}
		} Else {
			write-host "ZEBI-FC = $pidfc"
		}

		#################################
		#### SETTING CHECKS IS OVER #####
		#################################

		#ASK TO APPLY TEGILE BEST PRACTICES

		#SHOW THE RECOMMENDED CHANGES

		if (!$CHANGES){
			write-host "`nNo MPIO or iSCSI changes needed.`n"
		}Else{
			write-verbose "`r`nThe following changes are recommended:`r`n`r`n"
			write-verbose $CHANGES
			#ASK TO APPLY ALL SETTINGS
			if (!$AUTOAPPLY) {
				$title = ""
				$message = "`r`nUpdate All Settings with Tegile Best Practices?`r`n`r`n"
				$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes","Yes: Applies all configuration settings above."
				$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "No: will prompt for each change."
				$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
				$APPLYALL = $host.ui.PromptForChoice($title, $message, $options, 1)
			} Else {
				$error.clear()
				If ($Changes){
					Invoke-Expression $CHANGES
					if ($error){
						write-host "`r`n`r`nErrors occurred during setting changes:`r`n$error" -foregroundcolor red
						$EachLog | Add-Member -Type NoteProperty -Name Status -Value "Complete"
						$EachLog | Add-Member -Type NoteProperty -Name Errors -Value "True"
					} Else {
						write-host "`r`n`r`nAll setting changes applied without errors."
						$EachLog | Add-Member -Type NoteProperty -Name Status -Value "Complete"
						$EachLog | Add-Member -Type NoteProperty -Name Errors -Value "False"
					}
					write-host "`r`n`r`nReboot is required to apply all changes. Re-run script after reboot!`r`n`r`n" -foregroundcolor yellow -backgroundcolor black
					$LogReport += $EachLog
					$LogReport > .\$LOGFILE
					$LogSort = Get-Content .\$Logfile -Raw
					$LogSort = $LogSort |Sort
					$LogSort > .\$LOGFILE
					If ($iscsipath_log){Echo "iSCSI Registry Path Used: $iscsipath_log" >> .\$logfile}
					Echo "`r`nThe following commands were applied:`r`n" >> .\$logfile
					$CHANGES > .\$LOG
					$ALLCHANGES = Get-Content .\$LOG
					Remove-Item .\$LOG
					$ALLCHANGES >> $LOGFILE
					break
				}Else{
					write-host "`r`n`r`nNo changes to apply.`r`n`r`n"
					$LogReport += $EachLog
					$LogReport > .\$LOGFILE
					$LogSort = Get-Content .\$Logfile -Raw
					$LogSort = $LogSort |Sort
					$LogSort > .\$LOGFILE
					If ($iscsipath_log){Echo "iSCSI Registry Path Used: $iscsipath_log" >> .\$logfile}
					Echo "`r`nNo changes to apply.`r`n`r`n" >> .\$logfile
					break
				}
			}

			if ($APPLYALL -eq 0){
				$error.clear()
				If($CHANGES){
					Invoke-Expression $CHANGES
					if ($error){write-host "`r`n`r`nErrors occurred during setting changes:`r`n$error" -foregroundcolor red} Else {write-host "`r`n`r`nAll setting changes applied without errors."}
					write-host "`r`n`r`nReboot is required to apply all changes. Re-run script after reboot!`r`n`r`n" -foregroundcolor yellow -backgroundcolor black
					$CHANGES > .\$LOG
					$ALLCHANGES = Get-Content .\$LOG
				}
			} Else {

				#ASK FOR EACH SETTING TO BE APPLIED
				#CREATE ARRAY OUT OF THE CHANGES
				$CHANGES > .\$LOG
				$ALLCHANGES = Get-Content .\$LOG
				Remove-Item .\$LOG
				Foreach ($CHANGE in $($ALLCHANGES | where {$_ -ne ""})){
					$title = "Apply this change?"
					$message = "`r`n$CHANGE`r`n`r`n"
					$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Yes will execute: $CHANGE"
					$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "No: will move on to the next change or exit."
					$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
					$APPLYCHANGE = $host.ui.PromptForChoice($title, $message, $options, 1)
					if ($APPLYCHANGE -eq 0){
						$error.clear()
						Invoke-Expression $CHANGE
						if ($error){write-host "`r`n`r`nErrors occurred executing: `r`n`r`n$CHANGE`r`n" -foregroundcolor red} Else {write-host "`r`nSetting change applied without errors."}
					}
				}
				write-host "`r`n`r`nReboot is required to apply all changes. Re-run script after reboot!`r`n" -foregroundcolor yellow -backgroundcolor black
			}
		}
	}
    End{
        $LogReport += $EachLog
        $LogReport > .\$LOGFILE
        $LogSort = Get-Content .\$Logfile
        $LogSort = $LogSort |Sort
        $LogSort > .\$LOGFILE
        If ($iscsipath_log){Echo "iSCSI Registry Path Used: $iscsipath_log" >> .\$logfile}
        Echo "`r`nThe following commands are recommended:`r`n" >> .\$logfile
        $ALLCHANGES >> $LOGFILE
        Start $LOGFILE
    }
