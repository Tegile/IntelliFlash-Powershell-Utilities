## Tegile IntelliFlash cmdlet module
## Version v3.7.1.3:
## Fixed Add-IntelliFlashProjectLUNMapping ReadOnly parameter
##
## Tegile IntelliFlash cmdlet module
## Version v3.7.1.2:
## Added Get-IntelliFlashProjectNFSNetworkACL
## Added Add-IntelliFlashProjectNFSNetworkACL
## Added Remove-IntelliFlashProjectNFSNetworkACL
##
## Previous Version v3.7.1.1:
## Added support for replica project clones
## Added Remove-IntelliFlashProject
## Added Set-IntelliFlashShareProperty
## Added Add-IntelliFlashProjectLUNMapping
## Get-IntelliFlashReplicationStatus

Function Convert-FromUnixdate {
    [CmdletBinding()]
    Param (
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[string]$UnixDate
    )
    Begin{
    }
    Process{
        [timezone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddSeconds($UnixDate.Substring(0,$UnixDate.Length-3)))
    }
    End{
    }
}
function Connect-IntelliFlash {
    #Requires -Version 4.0
    [CmdletBinding()]
    Param (
		# Array Name or IP
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$Array,
		# Array UserName
		[Parameter(ValueFromPipelineByPropertyName=$True)]
		[String[]]$ArrayUserName,
		# Array Password
		[Parameter(ValueFromPipelineByPropertyName=$True)]
		[String[]]$ArrayPassword
	)
    Begin{
        #If ($Host.Version.Major -lt 4){Write-Host "Please use PowerShell version 4.0 or later" -ForegroundColor Red -BackgroundColor Black;Break}
        $ArrayReport = @()
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
		[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        if (!$global:ArrayTable) {
            $global:ArrayTable = @()
			$ArrayCred = @()
            } else {$ArrayCred = $global:ArrayTable}
        $i=0
        If (!$ArrayUserName){[String]$CurrentUserName}
        If (!$ArrayPassword){[String]$CurrentPassword}
    }
    Process{  
 	    ForEach ($CurrentArray in $Array){
            If ($ArrayUserName){$CurrentUserName = $ArrayUserName}Else{$CurrentUserName = ""}
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
                if (!$Cred -and !$CurrentUserName) {
                    $ifcredential = $host.ui.promptforcredential("Need IntelliFlash Credentials", "IntelliFlash Array: $CurrentArray", "", "")
				        if (!$ifcredential) {Write-Output "`nYou failed to enter credentials!`n"}
			        } 
                    elseif (!$CurrentPassword) {
				        $ifcredential = $host.ui.promptforcredential("Need IntelliFlash Credentials", "IntelliFlash Array: $CurrentArray", "$CurrentUserName", "")
				        if (!$ifcredential) {Write-Output "`nYou failed to enter credentials!`n"}
			        }
                if (!$CurrentUserName) {
				    $CurrentUserName = $ifcredential.username.trimstart('\')
			    }
			    if (!$CurrentPassword) {
				    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ifcredential.password)
				    $CurrentPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
			    }

		    	$auth = "$CurrentUserName" + ':' + "$CurrentPassword"
			    $encoded = [System.Text.Encoding]::UTF8.GetBytes($auth)
			    $encodedpassword = [System.Convert]::ToBase64String($encoded)
			    $Cred = @{"Authorization"="Basic $($EncodedPassword)"}
			    $CurrentUserName = ""
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
function Show-IntelliFlash {
	[CmdletBinding()]
	Param (
	)
	Begin {
        If (!$Global:ArrayTable){
            Write-Output "There are currently no IntelliFlash Arrays Connected"
            Break
        }
    }
	Process {
        Write-Output $Global:ArrayTable
	}
	End {
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
function Get-IntelliFlashNASGroupList {
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
        CLV GroupReport -EA SilentlyContinue
        CLV EachGroup -EA SilentlyContinue
        $GroupReport = @()
        ForEach ($Array in $global:ArrayTable.Array){
            Write-progress -activity "Collecting NAS Groups from $Array" -status "Progress:" -percentcomplete ($p/$global:ArrayTable.count*100)
	        $Cred = $global:ArrayTable |Where {$_.Array -eq $Array}|select Cred
            $Cred = $Cred.Cred
            $IntelliFlashVersion = $global:ArrayTable |Where {$_.Array -eq $Array}|select IntelliFlashVersion
            $IntelliFlashVersion = [double]$IntelliFlashVersion.IntelliFlashVersion.Substring(0,3)
            If ($IntelliFlashVersion -lt 3.5){$APIVer = "v1"}else{$APIVer = "v2"}
	        $url = "https://$Array/zebi/api/$APIVer/listGroups"
	        $postParams = "[]"
			Write-Debug $postParams
	        $Group = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
            if ("$?" -eq "True" -and $Group) {
		        ForEach ($CurrentGroup in $group){
                    $EachGroup = New-Object -TypeName PSObject
                    $EachGroup | Add-Member -Type NoteProperty -Name Array -Value $Array
                    $EachGroup | Add-Member -Type NoteProperty -Name GroupName -Value $CurrentGroup.groupName
                    $EachGroup | Add-Member -Type NoteProperty -Name GroupID -Value $CurrentGroup.groupId
                    $EachGroup | Add-Member -Type NoteProperty -Name GroupUsers -Value $CurrentGroup.userList
                    $EachGroup | Add-Member -Type NoteProperty -Name APIVer -Value $APIVer
                    $GroupReport += $EachGroup
                }
	        }
        $p++
        }
    }
    End{
        Write-Output $GroupReport
        If ($Array -and $ArrayUserName -and $ArrayPassword){
            $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            $Global:ArrayTable = @()
            $Global:ArrayTable = $NewCred
        }
    }   
}
function Get-IntelliFlashNASUserList {
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
        CLV UserReport -EA SilentlyContinue
        CLV EachUser -EA SilentlyContinue
        $UserReport = @()
        ForEach ($Array in $global:ArrayTable.Array){
            Write-progress -activity "Collecting NAS Users from $Array" -status "Progress:" -percentcomplete ($p/$global:ArrayTable.count*100)
	        $Cred = $global:ArrayTable |Where {$_.Array -eq $Array}|select Cred
            $Cred = $Cred.Cred
            $IntelliFlashVersion = $global:ArrayTable |Where {$_.Array -eq $Array}|select IntelliFlashVersion
            $IntelliFlashVersion = [double]$IntelliFlashVersion.IntelliFlashVersion.Substring(0,3)
            If ($IntelliFlashVersion -lt 3.5){$APIVer = "v1"}else{$APIVer = "v2"}
	        $url = "https://$Array/zebi/api/$APIVer/listUsers"
	        $postParams = "[]"
			Write-Debug $postParams
	        $User = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
            if ("$?" -eq "True" -and $User) {
		        ForEach ($CurrentUser in $User){
                    $EachUser = New-Object -TypeName PSObject
                    $EachUser | Add-Member -Type NoteProperty -Name Array -Value $Array
                    $EachUser | Add-Member -Type NoteProperty -Name UserName -Value $CurrentUser.userName
                    $EachUser | Add-Member -Type NoteProperty -Name UserID -Value $CurrentUser.userId
                    $EachUser | Add-Member -Type NoteProperty -Name GroupName -Value $CurrentUser.groupName
                    $EachUser | Add-Member -Type NoteProperty -Name GroupID -Value $CurrentUser.groupId
                    $EachUser | Add-Member -Type NoteProperty -Name APIVer -Value $APIVer
                    $UserReport += $EachUser
                }
	        }
        $p++
        }
    }
    End{
        Write-Output $UserReport
        If ($Array -and $ArrayUserName -and $ArrayPassword){
            $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            $Global:ArrayTable = @()
            $Global:ArrayTable = $NewCred
        }
    }   
}
function Add-IntelliFlashNASGroup {
    [CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$Array,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$GroupName,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$GroupID,
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
        CLV GroupMemberAddReport -EA SilentlyContinue
        $GroupMemberAddReport = @()
        $i=0
    }
    Process{
        ForEach ($CurrentArray in $Array){
	        $Cred = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select Cred
            $Cred = $Cred.Cred
            $IntelliFlashVersion = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select IntelliFlashVersion
            $IntelliFlashVersion = [double]$IntelliFlashVersion.IntelliFlashVersion.Substring(0,3)
            If ($IntelliFlashVersion -lt 3.5){$APIVer = "v1"}else{$APIVer = "v2"}
	        $url = "https://$CurrentArray/zebi/api/$APIVer/createGroup"
	        $CurrentGroupName = $GroupName[$i]
            $CurrentGroupID = $GroupID[$i]
            $postParams = "[`"$CurrentGroupName`",$CurrentGroupID]"
			Write-Debug $postParams
	        $AddGroup = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
            If ($?){
                $EachGroup = New-Object -TypeName PSObject
                $EachGroup | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                $EachGroup | Add-Member -Type NoteProperty -Name InitiatorGroup -Value $CurrentGroupName
                $EachGroup | Add-Member -Type NoteProperty -Name InitiatorGroupMember -Value $CurrentGroupID
                $EachGroup | Add-Member -Type NoteProperty -Name Status -Value "True"
                $EachGroup | Add-Member -Type NoteProperty -Name GroupCreated -Value "True"
                $GroupAddReport += $EachGroup
                }Else{
                $EachGroup = New-Object -TypeName PSObject
                $EachGroup | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                $EachGroup | Add-Member -Type NoteProperty -Name InitiatorGroup -Value $CurrentGroupName
                $EachGroup | Add-Member -Type NoteProperty -Name InitiatorGroupMember -Value $CurrentGroupID
                $EachGroup | Add-Member -Type NoteProperty -Name Status -Value "False"
                $EachGroup | Add-Member -Type NoteProperty -Name GroupCreated -Value "False"
                $GroupAddReport += $EachGroup
            }
       $i++
       }
    }
    End{
        Write-Output $GroupAddReport
        If ($Array -and $ArrayUserName -and $ArrayPassword){
            $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            $Global:ArrayTable = @()
            $Global:ArrayTable = $NewCred
        }
    }
}
function Add-IntelliFlashNASUser {
    [CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$Array,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$UserName,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$UserID,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$GroupName,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$UserPassword,
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
        CLV UserAddReport -EA SilentlyContinue
        $UserAddReport = @()
        $i=0
    }
    Process{
        ForEach ($CurrentArray in $Array){
	        $Cred = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select Cred
            $Cred = $Cred.Cred
            $IntelliFlashVersion = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select IntelliFlashVersion
            $IntelliFlashVersion = [double]$IntelliFlashVersion.IntelliFlashVersion.Substring(0,3)
            If ($IntelliFlashVersion -lt 3.5){$APIVer = "v1"}else{$APIVer = "v2"}
	        $url = "https://$CurrentArray/zebi/api/$APIVer/createUser"
	        $CurrentUserName = $UserName[$i]
            $CurrentUserID = $UserID[$i]
            $CurrentGroupName = $GroupName[$i]
            $CurrentUserPassword = $UserPassword[$i]
            $postParams = "[`"$CurrentUserName`",$CurrentUserID, `"$CurrentGroupName`", `"$CurrentUserPassword`"]"
			Write-Debug $postParams
	        $AddUser = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
            If ($?){
                $EachUser = New-Object -TypeName PSObject
                $EachUser | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                $EachUser | Add-Member -Type NoteProperty -Name UserName -Value $CurrentUserName
                $EachUser | Add-Member -Type NoteProperty -Name UserID -Value $CurrentUserID
                $EachUser | Add-Member -Type NoteProperty -Name GroupName -Value $CurrentGroupName
                $EachUser | Add-Member -Type NoteProperty -Name Password -Value $CurrentUserPassword
                $EachUser | Add-Member -Type NoteProperty -Name Status -Value "True"
                $EachUser | Add-Member -Type NoteProperty -Name GroupCreated -Value "True"
                $UserAddReport += $EachUser
                }Else{
                $EachUser = New-Object -TypeName PSObject
                $EachUser | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                $EachUser | Add-Member -Type NoteProperty -Name UserName -Value $CurrentUserName
                $EachUser | Add-Member -Type NoteProperty -Name UserID -Value $CurrentUserID
                $EachUser | Add-Member -Type NoteProperty -Name GroupName -Value $CurrentGroupName
                $EachUser | Add-Member -Type NoteProperty -Name Password -Value $CurrentUserPassword
                $EachUser | Add-Member -Type NoteProperty -Name Status -Value "False"
                $EachUser | Add-Member -Type NoteProperty -Name GroupCreated -Value "False"
                $UserAddReport += $EachUser
            }
       $i++
       }
    }
    End{
        Write-Output $UserAddReport
        If ($Array -and $ArrayUserName -and $ArrayPassword){
            $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            $Global:ArrayTable = @()
            $Global:ArrayTable = $NewCred
        }
    }
}
function Remove-IntelliFlashNASUser {
    [CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$Array,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$UserName,
		[Parameter()]
        [Switch]$Force,
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
        CLV UserAddReport -EA SilentlyContinue
        $UserRemoveReport = @()
        $i=0
    }
    Process{
        ForEach ($CurrentArray in $Array){
	        $Cred = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select Cred
            $Cred = $Cred.Cred
            $IntelliFlashVersion = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select IntelliFlashVersion
            $IntelliFlashVersion = [double]$IntelliFlashVersion.IntelliFlashVersion.Substring(0,3)
            If ($IntelliFlashVersion -lt 3.5){$APIVer = "v1"}else{$APIVer = "v2"}
	        $url = "https://$CurrentArray/zebi/api/$APIVer/deleteUser"
	        $CurrentUserName = $UserName[$i]
            $postParams = "[`"$CurrentUserName`"]"
			Write-Debug $postParams
	        If ($Force){
                    $DelUser = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
                    If ($?){
                        $EachUser = New-Object -TypeName PSObject
                        $EachUser | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                        $EachUser | Add-Member -Type NoteProperty -Name UserName -Value $CurrentUserName
                        $EachUser | Add-Member -Type NoteProperty -Name Status -Value "True"
                        $EachUser | Add-Member -Type NoteProperty -Name UserRemoved -Value "True"
                        $UserRemoveReport += $EachUser
                        }Else{
                        $EachUser = New-Object -TypeName PSObject
                        $EachUser | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                        $EachUser | Add-Member -Type NoteProperty -Name UserName -Value $CurrentUserName
                        $EachUser | Add-Member -Type NoteProperty -Name Status -Value "False"
                        $EachUser | Add-Member -Type NoteProperty -Name UserRemoved -Value "False"
                        $UserRemoveReport += $EachUser
                    }
                }Else{
                    CLV ConfirmDelete -EA SilentlyContinue
                    $title = "Delete User"
                    $message = "Do you want to delete $CurrentArray : $CurrentUserName ?"
                    $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Deletes User."
                    $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Retains User."
                    $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
                    $ConfirmDelete = $host.ui.PromptForChoice($title, $message, $options, 1)
                    If ($ConfirmDelete -eq 0){
                        $DelUser = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
                            If ($?){
                                $EachUser = New-Object -TypeName PSObject
                                $EachUser | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                                $EachUser | Add-Member -Type NoteProperty -Name UserName -Value $CurrentUserName
                                $EachUser | Add-Member -Type NoteProperty -Name Status -Value "True"
                                $EachUser | Add-Member -Type NoteProperty -Name UserRemoved -Value "True"
                                $UserRemoveReport += $EachUser
                            }Else{
                                $EachUser = New-Object -TypeName PSObject
                                $EachUser | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                                $EachUser | Add-Member -Type NoteProperty -Name UserName -Value $CurrentUserName
                                $EachUser | Add-Member -Type NoteProperty -Name Status -Value "False"
                                $EachUser | Add-Member -Type NoteProperty -Name UserRemoved -Value "False"
                                $UserRemoveReport += $EachUser
                        }
                        }Else{
                            $EachUser = New-Object -TypeName PSObject
                            $EachUser | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                            $EachUser | Add-Member -Type NoteProperty -Name UserName -Value $CurrentUserName
                            $EachUser | Add-Member -Type NoteProperty -Name Status -Value "False"
                            $EachUser | Add-Member -Type NoteProperty -Name UserRemoved -Value "False"
                            $UserRemoveReport += $EachUser
                        }
                    }
       $i++
       }
    }
    End{
        Write-Output $UserRemoveReport
        If ($Array -and $ArrayUserName -and $ArrayPassword){
            $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            $Global:ArrayTable = @()
            $Global:ArrayTable = $NewCred
        }
    }
}
function Remove-IntelliFlashNASGroup {
    [CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$Array,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$GroupName,
		[Parameter()]
        [Switch]$Force,
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
        CLV GroupRemoveReport -EA SilentlyContinue
        $GroupRemoveReport = @()
        $i=0
    }
    Process{
        ForEach ($CurrentArray in $Array){
	        $Cred = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select Cred
            $Cred = $Cred.Cred
            $IntelliFlashVersion = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select IntelliFlashVersion
            $IntelliFlashVersion = [double]$IntelliFlashVersion.IntelliFlashVersion.Substring(0,3)
            If ($IntelliFlashVersion -lt 3.5){$APIVer = "v1"}else{$APIVer = "v2"}
	        $url = "https://$CurrentArray/zebi/api/$APIVer/deleteGroup"
	        $CurrentGroupName = $GroupName[$i]
            $postParams = "[`"$CurrentGroupName`"]"
			Write-Debug $postParams
	        If ($Force){
                    $DelGroup = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
                    If ($?){
                        $EachGroup = New-Object -TypeName PSObject
                        $EachGroup | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                        $EachGroup | Add-Member -Type NoteProperty -Name GroupName -Value $CurrentGroupName
                        $EachGroup | Add-Member -Type NoteProperty -Name Status -Value "True"
                        $EachGroup | Add-Member -Type NoteProperty -Name GroupRemoved -Value "True"
                        $GroupRemoveReport += $EachGroup
                        }Else{
                        $EachGroup = New-Object -TypeName PSObject
                        $EachGroup | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                        $EachGroup | Add-Member -Type NoteProperty -Name UserName -Value $CurrentGroupName
                        $EachGroup | Add-Member -Type NoteProperty -Name Status -Value "False"
                        $EachGroup | Add-Member -Type NoteProperty -Name GroupRemoved -Value "False"
                        $GroupRemoveReport += $EachGroup
                    }
                }Else{
                    CLV ConfirmDelete -EA SilentlyContinue
                    $title = "Delete Group"
                    $message = "Do you want to delete $CurrentArray : $CurrentGroupName ?"
                    $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Deletes Group."
                    $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Retains Group."
                    $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
                    $ConfirmDelete = $host.ui.PromptForChoice($title, $message, $options, 1)
                    If ($ConfirmDelete -eq 0){
                        $DelGroup = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
                            If ($?){
                                $EachGroup = New-Object -TypeName PSObject
                                $EachGroup | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                                $EachGroup | Add-Member -Type NoteProperty -Name UserName -Value $CurrentGroupName
                                $EachGroup | Add-Member -Type NoteProperty -Name Status -Value "True"
                                $EachGroup | Add-Member -Type NoteProperty -Name GroupRemoved -Value "True"
                                $GroupRemoveReport += $EachGroup
                            }Else{
                                $EachGroup = New-Object -TypeName PSObject
                                $EachGroup | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                                $EachGroup | Add-Member -Type NoteProperty -Name UserName -Value $CurrentGroupName
                                $EachGroup | Add-Member -Type NoteProperty -Name Status -Value "False"
                                $EachGroup | Add-Member -Type NoteProperty -Name GroupRemoved -Value "False"
                                $GroupRemoveReport += $EachGroup
                        }
                        }Else{
                            $EachGroup = New-Object -TypeName PSObject
                            $EachGroup | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                            $EachGroup | Add-Member -Type NoteProperty -Name UserName -Value $CurrentGroupName
                            $EachGroup | Add-Member -Type NoteProperty -Name Status -Value "False"
                            $EachGroup | Add-Member -Type NoteProperty -Name GroupRemoved -Value "False"
                            $GroupRemoveReport += $EachGroup
                        }
                    }
       $i++
       }
    }
    End{
        Write-Output $GroupRemoveReport
        If ($Array -and $ArrayUserName -and $ArrayPassword){
            $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            $Global:ArrayTable = @()
            $Global:ArrayTable = $NewCred
        }
    }
}
function Get-IntelliFlashPool {
    [CmdletBinding()]
	Param (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String]$PoolName,
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
        CLV ProjectReport -EA SilentlyContinue
        $PoolReport = @()
        [void]($PoolReport = Get-IntelliFlashPoolList)
    }
    Process{
        Write-Output $PoolReport |Where-Object {$_.PoolName -EQ "$PoolName"}
    }
    End{
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
function Get-IntelliFlashProject {
    [CmdletBinding()]
	Param (
		[Parameter()]
		[Switch]$Replica,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String]$ProjectName,
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
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
    CLV ProjectReport -EA SilentlyContinue
    $ProjectReport = @()
    if ($Replica) {[void]($ProjectReport = Get-IntelliFlashProjectList -Replica)} else {[void]($ProjectReport = Get-IntelliFlashProjectList)}
    }
    Process{
        Write-Output $ProjectReport |Where-Object {$_.ProjectName -EQ "$ProjectName" -and $_.Array -EQ "$Array"}
    }
    End{
        If ($Array -and $ArrayUserName -and $ArrayPassword){
            $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            $Global:ArrayTable = @()
            $Global:ArrayTable = $NewCred
        }
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
        If ($Array -and $ArrayUserName -and $ArrayPassword){
            $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            $Global:ArrayTable = @()
            $Global:ArrayTable = $NewCred
        }
    }
}
function Get-IntelliFlashLUN {
    [CmdletBinding()]
	Param(
		[Parameter()]
		[Switch[]]$Replica,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$LUNName,
  		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$ProjectName,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$Array,
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
    CLV LunReport -EA SilentlyContinue
    $LunReport = @()
    [void]($LUNReport = Get-IntelliFlashLUNList)
    }
    Process{
        Write-Output $LUNReport|Where-Object {$_.LUNName -eq "$LUNName" -and $_.ProjectName -eq "$ProjectName" -and $_.Array -eq "$Array"}
    }
    End{
        If ($Array -and $ArrayUserName -and $ArrayPassword){
            $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            $Global:ArrayTable = @()
            $Global:ArrayTable = $NewCred
        }
    }
}
function Get-IntelliFlashShareList {
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
    CLV ShareReport -EA SilentlyContinue
    if ($Replica){[void]($ProjectList = Get-IntelliFlashProjectList -Replica)}Else{[void]($ProjectList = Get-IntelliFlashProjectList)}
    $ShareReport = @()
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
            $url = "https://$CurrentArray/zebi/api/$APIVer/listShares"
	        $postParams = "[`"$PoolName`",`"$ProjectName`",`"$local`"]"
			Write-Debug $postParams
	        $ShareList = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
            ForEach ($Share in $ShareList) {
                $EachShare = New-Object -TypeName PSObject
                $EachShare | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                $EachShare | Add-Member -Type NoteProperty -Name PoolName -Value $Share.poolName
                $EachShare | Add-Member -Type NoteProperty -Name ProjectName -Value $Share.projectname
                $EachShare | Add-Member -Type NoteProperty -Name ShareName -Value $Share.name
                $EachShare | Add-Member -Type NoteProperty -Name ShareAvailableSize -Value $Share.availableSize
                $EachShare | Add-Member -Type NoteProperty -Name ShareTotalSize -Value $Share.totalSize
                $EachShare | Add-Member -Type NoteProperty -Name ShareAvailableSizeGB -Value ("{0:N2}" -f ($Share.availableSize/1024/1024/1024))
                $EachShare | Add-Member -Type NoteProperty -Name ShareTotalSizeGB -Value ("{0:N2}" -f ($Share.totalSize/1024/1024/1024))
                $EachShare | Add-Member -Type NoteProperty -Name ShareAvailableSizeTB -Value ("{0:N2}" -f ($Share.availableSize/1024/1024/1024/1024))
                $EachShare | Add-Member -Type NoteProperty -Name ShareTotalSizeTB -Value ("{0:N2}" -f ($Share.totalSize/1024/1024/1024/1024))
                $EachShare | Add-Member -Type NoteProperty -Name FullPath -Value $Share.datasetPath
                $MP = $Share.mountpoint
                If (!$MP){$MP = "/export/" + $Share.projectname + "/" + $Share.name}
                $EachShare | Add-Member -Type NoteProperty -Name MountPoint -Value $MP
                $EachShare | Add-Member -Type NoteProperty -Name LocalShare -Value $Share.local
                $ShareReport += $EachShare
            }
        }
    }
    End{
        Write-Output $ShareReport
        If ($Array -and $ArrayUserName -and $ArrayPassword){
            $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            $Global:ArrayTable = @()
            $Global:ArrayTable = $NewCred
        }
    }
}
function Get-IntelliFlashShare {
    [CmdletBinding()]
	Param (
		[Parameter()]
		[Switch]$Replica,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String]$ShareName,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String]$Array,
  		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String]$ProjectName,
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
        CLV ShareReport -EA SilentlyContinue
        $ShareReport = @()
        [void]($ShareReport = Get-IntelliFlashShareList)
    }
    Process{
        Write-Output $ShareReport|Where-Object {$_.ShareName -eq "$ShareName" -and $_.ProjectName -eq "$ProjectName" -and $_.Array -eq $Array} 
    }
    End{
        If ($Array -and $ArrayUserName -and $ArrayPassword){
            $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            $Global:ArrayTable = @()
            $Global:ArrayTable = $NewCred
        }	
    }
}
function Add-IntelliFlashLUN {
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
        [ValidateSet("FC", "iSCSI", ignorecase=$False)]
		[String[]]$Protocol,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
        [ValidateSet("32KB", "64KB")]
		[String[]]$BlockSize,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[decimal[]]$LUNSizeGB,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
		[Switch[]]$DisableThinProvision,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
		[Switch[]]$DisableInheritMappingFromProject,
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
	    $local = "true"
        $LUNReport = @()
    }
    Process{
        ForEach ($ArrayTgt in $global:ArrayTable.Array){
            If ($ArrayTgt -eq $Array){
                If (!$DisableThinProvision) {$TP = "true"} Else{$TP = "false"}
                If (!$DisableInheritMappingFromProject) {$Inherit = "true"} Else{$Inherit = "false"}
                $Cred = $global:ArrayTable |Where {$_.Array -eq $ArrayTgt}|select Cred
                $Cred = $Cred.Cred
                $IntelliFlashVersion = $global:ArrayTable |Where {$_.Array -eq $ArrayTgt}|select IntelliFlashVersion
                $IntelliFlashVersion = [double]$IntelliFlashVersion.IntelliFlashVersion.Substring(0,3)
                If ($IntelliFlashVersion -lt 3.5){$APIVer = "v1"}else{$APIVer = "v2"}
                $LUNSize = [string]$LUNSizeGB
                $LUNSizeGB = [decimal]$LUNSize *1024*1024*1024
                $DataSetPath = "$PoolName/Local/$ProjectName"
                $url = "https://$ArrayTgt/zebi/api/$APIVer/createVolume"
                $postParams = "[{`"blockSize`":`"" + $BlockSize + "`", `"datasetPath`":`"" + $DataSetPath + "`", `"local`":`"true`", `"name`":`"" + $LUNName + "`", `"poolName`":`"" + $PoolName + "`", `"projectName`":`"" + $ProjectName + "`", `"protocol`":`"" + $Protocol + "`", `"thinProvision`":`"" + $TP +"`", `"volSize`":`"" + $LUNSizeGB + "`"}, $Inherit]"
				Write-Debug $postParams
	            $LUNCreate = Invoke-WebRequest -Uri $url -Method Post -ContentType "application/json" -Header $Cred -Body $postParams
                If ($?){
                    $EachLUN = New-Object -TypeName PSObject
                    $EachLUN | Add-Member -Type NoteProperty -Name Array -Value $ArrayTgt
                    $EachLUN | Add-Member -Type NoteProperty -Name PoolName -Value $PoolName[0]
                    $EachLUN | Add-Member -Type NoteProperty -Name ProjectName -Value $ProjectName[0]
                    $EachLUN | Add-Member -Type NoteProperty -Name LUNName -Value $LUNName[0]
                    $EachLUN | Add-Member -Type NoteProperty -Name LUNSizeGB -Value $LUNSize
                    $EachLUN | Add-Member -Type NoteProperty -Name BlockSize -Value $BlockSize[0]
                    $EachLUN | Add-Member -Type NoteProperty -Name Protocol -Value $Protocol[0]
                    $EachLUN | Add-Member -Type NoteProperty -Name FullPath -Value "$DataSetPath/$LUNName"
                    $EachLUN | Add-Member -Type NoteProperty -Name LocalLUN -Value "True"
                    $EachLUN | Add-Member -Type NoteProperty -Name LUNCreationStatus -Value "True"
                    $EachLUN | Add-Member -Type NoteProperty -Name LUNCreation -Value "True"
                    $LUNReport += $EachLUN
                } Else {
                    $EachLUN = New-Object -TypeName PSObject
                    $EachLUN | Add-Member -Type NoteProperty -Name Array -Value $ArrayTgt
                    $EachLUN | Add-Member -Type NoteProperty -Name LUNName -Value $LUNName[0]
                    $EachLUN | Add-Member -Type NoteProperty -Name LUNCreationStatus -Value "False"
                    $EachLUN | Add-Member -Type NoteProperty -Name LUNCreation -Value "False"
                    $LUNReport += $EachLUN
                }
            }
        } 
    }
    End{
        If ($Array -and $ArrayUserName -and $ArrayPassword){
            $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            $Global:ArrayTable = @()
            $Global:ArrayTable = $NewCred
        }
        Write-Output $LUNReport
    }
}
function Add-IntelliFlashLUNSet {
    [CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String]$Array,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String]$PoolName,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String]$ProjectName,
        [Parameter(Mandatory=$true)]
		[String]$LUNSetBaseName,
        [Parameter()]
        [String]$NameDelimiter,
		[Parameter(Mandatory=$true)]
        [int]$StartingNumber,
		[Parameter(Mandatory=$true)]
        [int]$LUNSetQuantity,
        [Parameter(Mandatory=$true)]
        [ValidateSet("FC", "iSCSI", ignorecase=$False)]
		[String]$Protocol,
        [Parameter(Mandatory=$true)]
        [ValidateSet("32KB", "64KB", ignorecase=$False)]
		[String]$BlockSize,
        [Parameter(Mandatory=$true)]
		[decimal]$LUNSizeGB,
        [Parameter()]
		[Switch]$DisableThinProvision,
        [Parameter()]
		[Switch]$DisableInheritMappingFromProject,
		[Parameter()]
		[String]$ArrayUserName,
		[Parameter()]
		[String]$ArrayPassword,
		[Parameter()]
		[Switch]$Force,
		[Parameter()]
		[Switch]$LeadingZeros
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
	    $local = "true"
        $LUNReport = @()
    }
    Process{
        ForEach ($ArrayTgt in $global:ArrayTable.Array){
            If ($ArrayTgt -eq $Array){
                If (!$DisableThinProvision) {$TP = "true"} Else{$TP = "false"}
                If (!$DisableInheritMappingFromProject) {$Inherit = "true"} Else{$Inherit = "false"}
                $Cred = $global:ArrayTable |Where {$_.Array -eq $ArrayTgt}|select Cred
                $Cred = $Cred.Cred
                $IntelliFlashVersion = $global:ArrayTable |Where {$_.Array -eq $ArrayTgt}|select IntelliFlashVersion
                $IntelliFlashVersion = [double]$IntelliFlashVersion.IntelliFlashVersion.Substring(0,3)
                If ($IntelliFlashVersion -lt 3.5){$APIVer = "v1"}else{$APIVer = "v2"}
                $LUNSize = [string]$LUNSizeGB
                $LUNSizeGB = [decimal]$LUNSize *1024*1024*1024
                $DataSetPath = "$PoolName/Local/$ProjectName"
                $url = "https://$ArrayTgt/zebi/api/$APIVer/createVolume"
                
				$i=0
				$LUNFullNameList = @()
				$LUNNames = @()
				$TempName = "TEMP"
				$TempFullNameList = "TEMP"
				While ($i -ne $LUNSetQuantity){
					CLV $TempName -ErrorAction SilentlyContinue
					CLV $TempFullNameList -ErrorAction SilentlyContinue
					$CurrentNumber = $StartingNumber + $i
					If ($LeadingZeros){
						If ($CurrentNumber -lt 10){$CurrentNumber = "00" + $CurrentNumber}
						If ($CurrentNumber -gt 9 -and $CurrentNumber -lt 100){$CurrentNumber = "0" + $CurrentNumber}
					}
					If ($NameDelimiter){$TempName = $LUNSetBaseName + $NameDelimiter + $CurrentNumber}Else {$TempName = $LUNSetBaseName + $CurrentNumber}
					$TempFullNameList = $DataSetPath + "/" + $TempName
					$LUNFullNameList += $TempFullNameList
					$LUNNames += $TempName
					$i++
				}
				Write-Host "`r`nLUNs to be created:"
				$LUNFullNameList
				CLV ConfirmCreate -EA SilentlyContinue
                $title = "Create LUNs?"
                $message = "Do you want to create these LUNs?"
                $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Creates LUN."
                $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Does Nothing."
                $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
                If (!$Force){$ConfirmCreate = $host.ui.PromptForChoice($title, $message, $options, 1)}Else{$ConfirmCreate = 0}
                If ($ConfirmCreate -eq 1){
					Write-Host "`r`nLUN Creation Cancelled"
					break
					} Else {
					Write-Host "`r`nCreating LUNs"
					$p = 1
					ForEach ($LUNName in $LUNNames){
						Write-progress -activity "Creating LUNs" -status "Creating LUN:$LUNName" -percentcomplete ($p/$LUNNames.count*100)
						$postParams = "[{`"blockSize`":`"" + $BlockSize + "`", `"datasetPath`":`"" + $DataSetPath + "`", `"local`":`"true`", `"name`":`"" + $LUNName + "`", `"poolName`":`"" + $PoolName + "`", `"projectName`":`"" + $ProjectName + "`", `"protocol`":`"" + $Protocol + "`", `"thinProvision`":`"" + $TP +"`", `"volSize`":`"" + $LUNSizeGB + "`"}, $Inherit]"
						Write-Debug $postParams
	            		$LUNCreate = Invoke-WebRequest -Uri $url -Method Post -ContentType "application/json" -Header $Cred -Body $postParams
						If ($?){
		                    $EachLUN = New-Object -TypeName PSObject
		                    $EachLUN | Add-Member -Type NoteProperty -Name Array -Value $ArrayTgt
		                    $EachLUN | Add-Member -Type NoteProperty -Name PoolName -Value $PoolName
		                    $EachLUN | Add-Member -Type NoteProperty -Name ProjectName -Value $ProjectName
		                    $EachLUN | Add-Member -Type NoteProperty -Name LUNName -Value $LUNName
		                    $EachLUN | Add-Member -Type NoteProperty -Name LUNSizeGB -Value $LUNSize
		                    $EachLUN | Add-Member -Type NoteProperty -Name BlockSize -Value $BlockSize
		                    $EachLUN | Add-Member -Type NoteProperty -Name Protocol -Value $Protocol
		                    $EachLUN | Add-Member -Type NoteProperty -Name FullPath -Value "$DataSetPath/$LUNName"
		                    $EachLUN | Add-Member -Type NoteProperty -Name LocalLUN -Value "True"
		                    $EachLUN | Add-Member -Type NoteProperty -Name LUNCreationStatus -Value "True"
		                    $EachLUN | Add-Member -Type NoteProperty -Name LUNCreation -Value "True"
		                    $LUNReport += $EachLUN
                		} Else {
		                    $EachLUN = New-Object -TypeName PSObject
		                    $EachLUN | Add-Member -Type NoteProperty -Name Array -Value $ArrayTgt
		                    $EachLUN | Add-Member -Type NoteProperty -Name LUNName -Value $LUNName
		                    $EachLUN | Add-Member -Type NoteProperty -Name LUNCreationStatus -Value "False"
		                    $EachLUN | Add-Member -Type NoteProperty -Name LUNCreation -Value "False"
		                    $LUNReport += $EachLUN
						}
						$p++
					}
				}
            }
        } 
    }
    End{
        If ($Array -and $ArrayUserName -and $ArrayPassword){
            $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            $Global:ArrayTable = @()
            $Global:ArrayTable = $NewCred
        }
        Write-Output $LUNReport
    }
}
function Add-IntelliFlashShare {
    [CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$Array,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$PoolName,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$ProjectName,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$ShareName,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
        [ValidateSet("32KB", "64KB")]
		[String[]]$BlockSize,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
		[string[]]$ShareQuotaGB,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
		[string[]]$ShareReservationGB,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
		[string[]]$ShareMountPoint,
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
        $ShareReport = @()
    }
    Process{
        ForEach ($ArrayTgt in $global:ArrayTable.Array){
            If ($ArrayTgt -eq $Array){
                If (!$ShareQuotaGB) {
                    $SQ = "-1"
                    } Else{
                    $ShareSize = [string]$ShareQuotaGB
                    $SQ = [decimal]$ShareSize *1024*1024*1024
                }
                If (!$ShareReservationGB) {
                    $SR = "-1"
                    } Else{
                    $SRSize = [string]$ShareReservationGB
                    $SR = [decimal]$SRSize *1024*1024*1024
                }
                If (!$ShareMountPoint) {$SMP = ""} Else{$SMP = $ShareMountPoint}
                $Cred = $global:ArrayTable |Where {$_.Array -eq $ArrayTgt}|select Cred
                $Cred = $Cred.Cred
                $IntelliFlashVersion = $global:ArrayTable |Where {$_.Array -eq $ArrayTgt}|select IntelliFlashVersion
                $IntelliFlashVersion = [double]$IntelliFlashVersion.IntelliFlashVersion.Substring(0,3)
                If ($IntelliFlashVersion -lt 3.5){$APIVer = "v1"}else{$APIVer = "v2"}
                $url = "https://$ArrayTgt/zebi/api/$APIVer/createShare"
                $postParams = "[`"" + $PoolName + "`", `"" + $ProjectName + "`", `"" + $ShareName + "`",{`"blockSize`":`"" + $BlockSize + "`", `"quota`": $SQ, `"reservation`": $SR, `"mountPoint`":`"" +  $ShareMountPoint + "`"},[{`"sharePermissionMode`":0,`"sharePermissionEnum`":0,`"groupList`":[{`"groupId`":`"`",`"groupName`":`"`"}]}]]"
				Write-Debug $postParams
                $ShareCreate = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Header $Cred -Body $postParams
                If ($?){
                    $EachShare = New-Object -TypeName PSObject
                    $EachShare | Add-Member -Type NoteProperty -Name Array -Value $ArrayTgt
                    $EachShare | Add-Member -Type NoteProperty -Name PoolName -Value $PoolName[0]
                    $EachShare | Add-Member -Type NoteProperty -Name ProjectName -Value $ProjectName[0]
                    $EachShare | Add-Member -Type NoteProperty -Name ShareName -Value $ShareName[0]
                    $EachShare | Add-Member -Type NoteProperty -Name ShareCreationStatus -Value "True"
                    $EachShare | Add-Member -Type NoteProperty -Name ShareCreated -Value "True"
                    $ShareReport += $EachShare
                } Else {
                    $EachShare = New-Object -TypeName PSObject 
                    $EachShare | Add-Member -Type NoteProperty -Name Array -Value $ArrayTgt
                    $EachShare | Add-Member -Type NoteProperty -Name PoolName -Value $PoolName[0]
                    $EachShare | Add-Member -Type NoteProperty -Name ProjectName -Value $ProjectName[0]
                    $EachShare | Add-Member -Type NoteProperty -Name ShareName -Value $ShareName[0]
                    $EachShare | Add-Member -Type NoteProperty -Name ShareCreationStatus -Value "False"
                    $EachShare | Add-Member -Type NoteProperty -Name ShareCreated -Value "False"
                    $ShareReport += $EachShare
               }
            }
        } 
    }
    End{
        If ($Array -and $ArrayUserName -and $ArrayPassword){
            $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            $Global:ArrayTable = @()
            $Global:ArrayTable = $NewCred
        }
        Write-Output $ShareReport
    }
}
function Add-IntelliFlashShareSet {
    [CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String]$Array,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String]$PoolName,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String]$ProjectName,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String]$ShareSetBaseName,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
        [ValidateSet("32KB", "64KB")]
		[String]$BlockSize,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
		[string]$ShareQuotaGB,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
		[string]$ShareReservationGB,
        [Parameter()]
		[Switch]$Force,
		[Parameter()]
		[Switch]$LeadingZeros,
		[Parameter()]
		[String]$ArrayUserName,
		[Parameter()]
		[String]$ArrayPassword,
		[Parameter(Mandatory=$true)]
        [int]$ShareSetQuantity,
		[Parameter()]
        [String]$NameDelimiter,
		[Parameter(Mandatory=$true)]
        [int]$StartingNumber
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
        $ShareReport = @()
    }
    Process{
        ForEach ($ArrayTgt in $global:ArrayTable.Array){
            If ($ArrayTgt -eq $Array){
                If (!$ShareQuotaGB) {
                    $SQ = "-1"
                    } Else{
                    $ShareSize = [string]$ShareQuotaGB
                    $SQ = [decimal]$ShareSize *1024*1024*1024
                }
                If (!$ShareReservationGB) {
                    $SR = "-1"
                    } Else{
                    $SRSize = [string]$ShareReservationGB
                    $SR = [decimal]$SRSize *1024*1024*1024
                }
                If (!$ShareMountPoint) {$SMP = ""} Else{$SMP = $ShareMountPoint}
                $Cred = $global:ArrayTable |Where {$_.Array -eq $ArrayTgt}|select Cred
                $Cred = $Cred.Cred
                $IntelliFlashVersion = $global:ArrayTable |Where {$_.Array -eq $ArrayTgt}|select IntelliFlashVersion
                $IntelliFlashVersion = [double]$IntelliFlashVersion.IntelliFlashVersion.Substring(0,3)
                If ($IntelliFlashVersion -lt 3.5){$APIVer = "v1"}else{$APIVer = "v2"}
                $url = "https://$ArrayTgt/zebi/api/$APIVer/createShare"
                
				$i=0
				$ShareFullNameList = @()
				$ShareNames = @()
				$TempName = "TEMP"
				$TempFullNameList = "TEMP"
				While ($i -ne $ShareSetQuantity){
					CLV $TempName -ErrorAction SilentlyContinue
					CLV $TempFullNameList -ErrorAction SilentlyContinue
					$CurrentNumber = $StartingNumber + $i
					If ($LeadingZeros){
						If ($CurrentNumber -lt 10){$CurrentNumber = "00" + $CurrentNumber}
						If ($CurrentNumber -gt 9 -and $CurrentNumber -lt 100){$CurrentNumber = "0" + $CurrentNumber}
					}
					If ($NameDelimiter){$TempName = $ShareSetBaseName + $NameDelimiter + $CurrentNumber}Else {$TempName = $ShareSetBaseName + $CurrentNumber}
					$TempFullNameList = $PoolName + "/local/" + $ProjectName + "/" + $TempName
					$ShareFullNameList += $TempFullNameList
					$ShareNames += $TempName
					$i++
				}
				Write-Host "`r`nShares to be created:"
				$ShareFullNameList
				CLV ConfirmCreate -EA SilentlyContinue
                $title = "Create Shares?"
                $message = "Do you want to create these Shares?"
                $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Creates Shares."
                $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Does Nothing."
                $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
                If (!$Force){$ConfirmCreate = $host.ui.PromptForChoice($title, $message, $options, 1)}Else{$ConfirmCreate = 0}
                If ($ConfirmCreate -eq 1){
					Write-Host "`r`nShare Creation Cancelled"
					break
					} Else {
					Write-Host "`r`nCreating Shares"
					$p = 1
					ForEach ($ShareName in $ShareNames){
						Write-progress -activity "Creating Shares" -status "Creating Share:$ShareName" -percentcomplete ($p/$ShareNames.count*100)
						$postParams = "[`"" + $PoolName + "`", `"" + $ProjectName + "`", `"" + $ShareName + "`",{`"blockSize`":`"" + $BlockSize + "`", `"quota`": $SQ, `"reservation`": $SR, `"mountPoint`":`"" +  $ShareMountPoint + "`"},[{`"sharePermissionMode`":0,`"sharePermissionEnum`":0,`"groupList`":[{`"groupId`":`"`",`"groupName`":`"`"}]}]]"
						Write-Debug $postParams
                		$ShareCreate = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Header $Cred -Body $postParams
		                If ($?){
		                    $EachShare = New-Object -TypeName PSObject
		                    $EachShare | Add-Member -Type NoteProperty -Name Array -Value $ArrayTgt
		                    $EachShare | Add-Member -Type NoteProperty -Name PoolName -Value $PoolName
		                    $EachShare | Add-Member -Type NoteProperty -Name ProjectName -Value $ProjectName
		                    $EachShare | Add-Member -Type NoteProperty -Name ShareName -Value $ShareName
		                    $EachShare | Add-Member -Type NoteProperty -Name ShareCreationStatus -Value "True"
		                    $EachShare | Add-Member -Type NoteProperty -Name ShareCreated -Value "True"
		                    $ShareReport += $EachShare
		                } Else {
		                    $EachShare = New-Object -TypeName PSObject 
		                    $EachShare | Add-Member -Type NoteProperty -Name Array -Value $ArrayTgt
		                    $EachShare | Add-Member -Type NoteProperty -Name PoolName -Value $PoolName
		                    $EachShare | Add-Member -Type NoteProperty -Name ProjectName -Value $ProjectName
		                    $EachShare | Add-Member -Type NoteProperty -Name ShareName -Value $ShareName
		                    $EachShare | Add-Member -Type NoteProperty -Name ShareCreationStatus -Value "False"
		                    $EachShare | Add-Member -Type NoteProperty -Name ShareCreated -Value "False"
		                    $ShareReport += $EachShare
               			}
			   		$p++
            		}
        		}
			}
		}
    }
    End{
        If ($Array -and $ArrayUserName -and $ArrayPassword){
            $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            $Global:ArrayTable = @()
            $Global:ArrayTable = $NewCred
        }
        Write-Output $ShareReport
    }
}
function Remove-IntelliFlashLUN {
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
        [Parameter(ValueFromPipelineByPropertyName=$True)]
		[Switch[]]$RecursiveDelete,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
		[Switch]$Force,
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
        $LUNReport = @()
    }
    Process{
        ForEach ($ArrayTgt in $global:ArrayTable.Array){
            If ($ArrayTgt -eq $Array){
                If (!$RecursiveDelete) {$RD = "false"} Else{$RD = "true"}
                $Cred = $global:ArrayTable |Where {$_.Array -eq $ArrayTgt}|select Cred
                $Cred = $Cred.Cred
                $IntelliFlashVersion = $global:ArrayTable |Where {$_.Array -eq $ArrayTgt}|select IntelliFlashVersion
                $IntelliFlashVersion = [double]$IntelliFlashVersion.IntelliFlashVersion.Substring(0,3)
                If ($IntelliFlashVersion -lt 3.5){$APIVer = "v1"}else{$APIVer = "v2"}
                $DataSetPath = "$PoolName/Local/$ProjectName/$LUNName"
                $url = "https://$ArrayTgt/zebi/api/$APIVer/deleteVolume"
                $postParams = "[`"" + $DataSetPath + "`", $RD, true]"
				Write-Debug $postParams
	            If ($Force){
                    $LUNDelete = Invoke-WebRequest -Uri $url -Method Post -ContentType "application/json" -Header $Cred -Body $postParams
                    If ($?){
                        $EachLUN = New-Object -TypeName PSObject
                        $EachLUN | Add-Member -Type NoteProperty -Name Array -Value $ArrayTgt
                        $EachLUN | Add-Member -Type NoteProperty -Name DataSetPath -Value $DataSetPath
                        $EachLUN | Add-Member -Type NoteProperty -Name Status -Value "True"
                        $EachLUN | Add-Member -Type NoteProperty -Name Deleted -Value "True"
                        $LUNReport += $EachLUN
                        } Else {
                        $EachLUN = New-Object -TypeName PSObject
                        $EachLUN | Add-Member -Type NoteProperty -Name Array -Value $ArrayTgt
                        $EachLUN | Add-Member -Type NoteProperty -Name DataSetPath -Value $DataSetPath
                        $EachLUN | Add-Member -Type NoteProperty -Name Status -Value "False"
                        $EachLUN | Add-Member -Type NoteProperty -Name Deleted -Value "False"
                        $LUNReport += $EachLUN
                    }
                }
                    Else{
                    CLV ConfirmDelete -EA SilentlyContinue
                    $title = "Delete LUNs"
                    $message = "Do you want to delete $ArrayTgt : $DataSetPath ?"
                    $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Deletes LUN."
                    $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Retains LUN."
                    $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
                    $ConfirmDelete = $host.ui.PromptForChoice($title, $message, $options, 1)
                    If ($ConfirmDelete -eq 0){
                        $LUNDelete = Invoke-WebRequest -Uri $url -Method Post -ContentType "application/json" -Header $Cred -Body $postParams
                        If ($?){
                            $EachLUN = New-Object -TypeName PSObject
                            $EachLUN | Add-Member -Type NoteProperty -Name Array -Value $ArrayTgt
                            $EachLUN | Add-Member -Type NoteProperty -Name DataSetPath -Value $DataSetPath
                            $EachLUN | Add-Member -Type NoteProperty -Name Status -Value "True"
                            $EachLUN | Add-Member -Type NoteProperty -Name Deleted -Value "True"
                            $LUNReport += $EachLUN
                            } Else {
                            $EachLUN = New-Object -TypeName PSObject
                            $EachLUN | Add-Member -Type NoteProperty -Name Array -Value $ArrayTgt
                            $EachLUN | Add-Member -Type NoteProperty -Name DataSetPath -Value $DataSetPath
                            $EachLUN | Add-Member -Type NoteProperty -Name Status -Value "False"
                            $EachLUN | Add-Member -Type NoteProperty -Name Deleted -Value "False"
                            $LUNReport += $EachLUN
                        }
                        }Else{
                        $EachLUN = New-Object -TypeName PSObject
                        $EachLUN | Add-Member -Type NoteProperty -Name Array -Value $ArrayTgt
                        $EachLUN | Add-Member -Type NoteProperty -Name DataSetPath -Value $DataSetPath
                        $EachLUN | Add-Member -Type NoteProperty -Name Status -Value "False"
                        $EachLUN | Add-Member -Type NoteProperty -Name Deleted -Value "False"
                        $LUNReport += $EachLUN
                    }
                }
            }
        } 
    }
    End{
        If ($Array -and $ArrayUserName -and $ArrayPassword){
            $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            $Global:ArrayTable = @()
            $Global:ArrayTable = $NewCred
        }	
        Write-Output $LUNReport
    }
}
function Remove-IntelliFlashShare {
    [CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$Array,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$PoolName,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$ProjectName,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$ShareName,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
		[Switch[]]$RecursiveDelete,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
		[Switch]$Force,
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
        $ShareReport = @()
    }
    Process{
        ForEach ($ArrayTgt in $global:ArrayTable.Array){
            If ($ArrayTgt -eq $Array){
                If (!$RecursiveDelete) {$RD = "false"} Else{$RD = "true"}
                $Cred = $global:ArrayTable |Where {$_.Array -eq $ArrayTgt}|select Cred
                $Cred = $Cred.Cred
                $IntelliFlashVersion = $global:ArrayTable |Where {$_.Array -eq $ArrayTgt}|select IntelliFlashVersion
                $IntelliFlashVersion = [double]$IntelliFlashVersion.IntelliFlashVersion.Substring(0,3)
                If ($IntelliFlashVersion -lt 3.5){$APIVer = "v1"}else{$APIVer = "v2"}
                $DataSetPath = "$PoolName/Local/$ProjectName/$ShareName"
                $url = "https://$ArrayTgt/zebi/api/$APIVer/deleteShare"
                $postParams = "[`"" + $DataSetPath + "`", $RD, true]"
				Write-Debug $postParams
	            If ($Force){
                    $ShareDelete = Invoke-WebRequest -Uri $url -Method Post -ContentType "application/json" -Header $Cred -Body $postParams
                    If ($?){
                        $EachShare = New-Object -TypeName PSObject
                        $EachShare | Add-Member -Type NoteProperty -Name Array -Value $ArrayTgt
                        $EachShare | Add-Member -Type NoteProperty -Name DataSetPath -Value $DataSetPath
                        $EachShare | Add-Member -Type NoteProperty -Name Status -Value "True"
                        $EachShare | Add-Member -Type NoteProperty -Name Deleted -Value "True"
                        $ShareReport += $EachShare
                        } Else {
                        $EachShare = New-Object -TypeName PSObject
                        $EachShare | Add-Member -Type NoteProperty -Name Array -Value $ArrayTgt
                        $EachShare | Add-Member -Type NoteProperty -Name DataSetPath -Value $DataSetPath
                        $EachShare | Add-Member -Type NoteProperty -Name Status -Value "False"
                        $EachShare | Add-Member -Type NoteProperty -Name Deleted -Value "False"
                        $ShareReport += $EachShare
                    }
                }
                    Else{
                    CLV ConfirmDelete -EA SilentlyContinue
                    $title = "Delete Shares"
                    $message = "Do you want to delete $ArrayTgt : $DataSetPath ?"
                    $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Deletes Share."
                    $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Retains Share."
                    $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
                    $ConfirmDelete = $host.ui.PromptForChoice($title, $message, $options, 1)
                    If ($ConfirmDelete -eq 0){
                        $ShareDelete = Invoke-WebRequest -Uri $url -Method Post -ContentType "application/json" -Header $Cred -Body $postParams
                        If ($?){
                            $EachShare = New-Object -TypeName PSObject
                            $EachShare | Add-Member -Type NoteProperty -Name Array -Value $ArrayTgt
                            $EachShare | Add-Member -Type NoteProperty -Name DataSetPath -Value $DataSetPath
                            $EachShare | Add-Member -Type NoteProperty -Name Status -Value "True"
                            $EachShare | Add-Member -Type NoteProperty -Name Deleted -Value "True"
                            $ShareReport += $EachShare
                            } Else {
                            $EachShare = New-Object -TypeName PSObject
                            $EachShare | Add-Member -Type NoteProperty -Name Array -Value $ArrayTgt
                            $EachShare | Add-Member -Type NoteProperty -Name DataSetPath -Value $DataSetPath
                            $EachShare | Add-Member -Type NoteProperty -Name Status -Value "False"
                            $EachShare | Add-Member -Type NoteProperty -Name Deleted -Value "False"
                            $ShareReport += $EachShare
                        }
                        }Else{
                        $EachShare = New-Object -TypeName PSObject
                        $EachShare | Add-Member -Type NoteProperty -Name Array -Value $ArrayTgt
                        $EachShare | Add-Member -Type NoteProperty -Name DataSetPath -Value $DataSetPath
                        $EachShare | Add-Member -Type NoteProperty -Name Status -Value "False"
                        $EachShare | Add-Member -Type NoteProperty -Name Deleted -Value "False"
                        $ShareReport += $EachShare
                    }
                }
            }
        } 
    }
    End{
        Write-Output $ShareReport
        If ($Array -and $ArrayUserName -and $ArrayPassword){
            $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            $Global:ArrayTable = @()
            $Global:ArrayTable = $NewCred
        }	
    }
}
function Get-IntelliFlashReplicationList {
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
        }
	    $local = "true"
        CLV ProjectReport -EA SilentlyContinue
        CLV RepReport -EA SilentlyContinue
        $ProjectReport = @()
        $RepReport = @()
        [void]($ProjectReport = Get-IntelliFlashProjectList)
        $ReplicationStatusCode = ("Unknown","Started","Restarted","Sending","Completing","Completed","Error","Aborting","Aborted","Abandoning") 
	}
    Process{
        ForEach ($Project in $ProjectReport){
            $CurrentArray = $Project.Array
            $ProjectName = $Project.ProjectName
            $PoolName = $Project.PoolName
            $Cred = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select Cred
            $Cred = $Cred.Cred
            $IntelliFlashVersion = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select IntelliFlashVersion
            $IntelliFlashVersion = [double]$IntelliFlashVersion.IntelliFlashVersion.Substring(0,3)
            If ($IntelliFlashVersion -lt 3.5){$APIVer = "v1"}else{$APIVer = "v2"}
            $url = "https://$CurrentArray/zebi/api/$APIVer/getReplicationConfigList"
	        $postParams = "[`"$PoolName`",`"$ProjectName`"]"
			Write-Debug $postParams
	        $RepSchedule = Invoke-WebRequest -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
            ForEach ($RepStatus in $RepSchedule.Content){
                If ($RepStatus.Length -gt 2){
                    $url = "https://$CurrentArray/zebi/api/$APIVer/getReplicationStatus"
	                $postParams = $RepStatus
                    $RepConfig = $RepStatus | ConvertFrom-Json
                    $CurrentRepStatus = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
                    #$CurrentRepStatus
                    #$RepConfig
                    $EachProjRep = New-Object -TypeName PSObject
                    $EachProjRep | Add-Member -Type NoteProperty -Name SourceArray -Value $CurrentArray
                    $EachProjRep | Add-Member -Type NoteProperty -Name SourcePoolName -Value $Project.PoolName
                    $EachProjRep | Add-Member -Type NoteProperty -Name SourceProjectName -Value $Project.ProjectName
                    $EachProjRep | Add-Member -Type NoteProperty -Name SourceDataSetFullPath -Value $RepConfig.baseDataSetName
                    $EachProjRep | Add-Member -Type NoteProperty -Name ReplicationScope -Value $RepConfig.scopeOption
                    $EachProjRep | Add-Member -Type NoteProperty -Name ReplicationIndex -Value $RepConfig.id
                    $EachProjRep | Add-Member -Type NoteProperty -Name ReplicationGUID -Value $RepConfig.projectGuid
                    $EachProjRep | Add-Member -Type NoteProperty -Name TargetArray -Value $RepConfig.remoteHost
                    $EachProjRep | Add-Member -Type NoteProperty -Name TargetPoolName -Value $RepConfig.remotePoolName
                    $EachProjRep | Add-Member -Type NoteProperty -Name TargetProjectName -Value $RepConfig.remoteProjectName
                    $EachProjRep | Add-Member -Type NoteProperty -Name TargetDataSetFullPath -Value $RepConfig.remoteBaseDataSetName
                    $EachProjRep | Add-Member -Type NoteProperty -Name ReplicationStatusID -Value $CurrentRepStatus.currentStatus
                    $EachProjRep | Add-Member -Type NoteProperty -Name ReplicationStatus -Value $ReplicationStatusCode[$CurrentRepStatus.currentStatus]
                    $EachProjRep | Add-Member -Type NoteProperty -Name ReplicationDataSentMB -Value ("{0:N2}" -f ($CurrentRepStatus.dataSent / 1024 / 1024))
                    $EachProjRep | Add-Member -Type NoteProperty -Name ReplicationSpeedMBps -Value ("{0:N2}" -f ($CurrentRepStatus.sendSpeed / 1024 / 1024))
                    $EachProjRep | Add-Member -Type NoteProperty -Name LastSnapshotName -Value $RepConfig.lastSnapshotName
                    If ($CurrentRepStatus.startTimestamp){
                        $EachProjRep | Add-Member -Type NoteProperty -Name ReplicationStartTimestamp -Value (Convert-FromUnixdate -UnixDate $CurrentRepStatus.startTimestamp)
                        }Else{
                        $EachProjRep | Add-Member -Type NoteProperty -Name ReplicationStartTimestamp -Value "NULL"
                        }
                    If ($CurrentRepStatus.completeTimestamp){
                        $EachProjRep | Add-Member -Type NoteProperty -Name ReplicationCompleteTimestamp -Value (Convert-FromUnixdate -UnixDate $CurrentRepStatus.completeTimestamp)
                        }Else{
                        $EachProjRep | Add-Member -Type NoteProperty -Name ReplicationCompleteTimestamp -Value "NULL"
                        }
                    If ($CurrentRepStatus.updateTimestamp){
                        $EachProjRep | Add-Member -Type NoteProperty -Name ReplicationUpdateTimestamp -Value (Convert-FromUnixdate -UnixDate $CurrentRepStatus.updateTimestamp)
                        }Else{
                        $EachProjRep | Add-Member -Type NoteProperty -Name ReplicationUpdateTimestamp -Value "NULL"
                        }
                    $RepReport += $EachProjRep
                }
            }
        }
    }
    End{
        Write-Output $RepReport
        If ($Array -and $ArrayUserName -and $ArrayPassword){
            $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            $Global:ArrayTable = @()
            $Global:ArrayTable = $NewCred
        }
    }
}
function Start-IntelliFlashReplication {
    [CmdletBinding()]
	Param (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$SourceArray,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$SourcePoolName,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$SourceProjectName,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$TargetProjectName,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$TargetDataSetFullPath,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
		[String[]]$LastSnapshotName,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$ReplicationScope,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$TargetArray,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$SourceDataSetFullPath,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$ReplicationIndex,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$ReplicationGUID,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$TargetPoolName,
		[Parameter()]
		[String]$ArrayUserName,
		[Parameter()]
		[String]$ArrayPassword
    )
    Begin{
        if (!$global:ArrayTable) {
            If ($SourceArray -and $ArrayUserName -and $ArrayPassword){
                CLV CLINE -EA SilentlyContinue
                $CLINE = @()
                $CLINEReport = New-Object -TypeName PSObject
                $CLINEReport | Add-Member -Type NoteProperty -Name Array -Value $SourceArray
                $CLINEReport | Add-Member -Type NoteProperty -Name ArrayUserName -Value $ArrayUserName
                $CLINEReport | Add-Member -Type NoteProperty -Name ArrayPassword -Value $ArrayPassword
                $CLINE = $CLINEReport
                [void]($CLINE |Connect-IntelliFlash)
                }Else{
                [void](Connect-IntelliFlash)
            }
}
        $RepStartReport = @()
    }
	Process{
	    ForEach ($Array in $SourceArray){
            $Cred = $global:ArrayTable |Where {$_.Array -eq $Array}|select Cred
            $Cred = $Cred.Cred
            $IntelliFlashVersion = $global:ArrayTable |Where {$_.Array -eq $Array}|select IntelliFlashVersion
            $IntelliFlashVersion = [double]$IntelliFlashVersion.IntelliFlashVersion.Substring(0,3)
            If ($IntelliFlashVersion -lt 3.5){$APIVer = "v1"}else{$APIVer = "v2"}
            $url = "https://$Array/zebi/api/$APIVer/startReplication"
	        $postParams = "[{`"projectName`":`"" + $SourceProjectName + "`",`"remoteProjectName`":`"" + $TargetProjectName + "`",`"remoteBaseDataSetName`":`"" + $TargetDataSetFullPath + "`",`"poolName`":`"" + $SourcePoolName + "`",`"lastSnapshotName`":`"" + $LastSnapshotName + "`",`"scopeOption`":" + $ReplicationScope + ",`"remoteHost`":`"" + $TargetArray + "`",`"baseDataSetName`":`"" + $SourceDataSetFullPath + "`",`"id`":" + $ReplicationIndex + ",`"projectGuid`":`"" + $ReplicationGUID + "`",`"remotePoolName`":`"" + $TargetPoolName + "`"}]"
			Write-Debug $postParams
	        If (!$LastSnapshotName){$LastSnapshotName -eq ""}
            $StartRep = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
            If ($?){
                $EachRep = New-Object -TypeName PSObject
                $EachRep | Add-Member -Type NoteProperty -Name SourceArray -Value $Array
                $EachRep | Add-Member -Type NoteProperty -Name SourcePoolName -Value $SourcePoolName[0]
                $EachRep | Add-Member -Type NoteProperty -Name SourceProject -Value $SourceProjectName[0]
                $EachRep | Add-Member -Type NoteProperty -Name TargetArray -Value $TargetArray[0]
                $EachRep | Add-Member -Type NoteProperty -Name TargetPoolName -Value $TargetPoolName[0]
                $EachRep | Add-Member -Type NoteProperty -Name TargetProject -Value $TargetProjectName[0]
                $EachRep | Add-Member -Type NoteProperty -Name ReplicationStarted -Value "True"
                $RepStartReport += $EachRep
                }Else{
                $EachRep = New-Object -TypeName PSObject
                $EachRep | Add-Member -Type NoteProperty -Name SourceArray -Value $Array
                $EachRep | Add-Member -Type NoteProperty -Name SourcePoolName -Value $SourcePoolName[0]
                $EachRep | Add-Member -Type NoteProperty -Name SourceProject -Value $SourceProjectName[0]
                $EachRep | Add-Member -Type NoteProperty -Name TargetArray -Value $TargetArray[0]
                $EachRep | Add-Member -Type NoteProperty -Name TargetPoolName -Value $TargetPoolName[0]
                $EachRep | Add-Member -Type NoteProperty -Name TargetProject -Value $TargetProjectName[0]
                $EachRep | Add-Member -Type NoteProperty -Name Status -Value "False"
                $RepStartReport += $EachRep
            }
        }
    }
    End{
        Write-Output $RepStartReport
        If ($SourceArray -and $ArrayUserName -and $ArrayPassword){
            $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            $Global:ArrayTable = @()
            $Global:ArrayTable = $NewCred
        }	
    }
}
function Get-IntelliFlashInitiatorGroupList {
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
        if ($Array){$ReportArray = $Array}
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
        CLV InitReport -EA SilentlyContinue
        $InitReport = @()
    }
    Process{
        ForEach ($Array in $global:ArrayTable.Array){
	        $Cred = $global:ArrayTable |Where {$_.Array -eq $Array}|select Cred
            $Cred = $Cred.Cred
            $IntelliFlashVersion = $global:ArrayTable |Where {$_.Array -eq $Array}|select IntelliFlashVersion
            $IntelliFlashVersion = [double]$IntelliFlashVersion.IntelliFlashVersion.Substring(0,3)
            If ($IntelliFlashVersion -lt 3.5){$APIVer = "v1"}else{$APIVer = "v2"}
	        $url = "https://$Array/zebi/api/$APIVer/listISCSIInitiatorGroups"
	        $postParams = "[]"
			Write-Debug $postParams
	        $iSCSIinit = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
            ForEach ($init in $iSCSIinit){
                    $EachInit = New-Object -TypeName PSObject
                    $EachInit | Add-Member -Type NoteProperty -Name Array -Value $Array
                    $EachInit | Add-Member -Type NoteProperty -Name InitiatorGroup -Value $init
                    $EachInit | Add-Member -Type NoteProperty -Name Protocol -Value "iSCSI"
                    $InitReport += $EachInit
            }
            CLV init -ea SilentlyContinue
            CLV eachinit -ea SilentlyContinue
            $url = "https://$Array/zebi/api/$APIVer/listFCInitiatorGroups"
	        $postParams = "[]"
			Write-Debug $postParams
	        $FCinit = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
            ForEach ($init in $FCinit){
                    $EachInit = New-Object -TypeName PSObject
                    $EachInit | Add-Member -Type NoteProperty -Name Array -Value $Array
                    $EachInit | Add-Member -Type NoteProperty -Name InitiatorGroup -Value $init
                    $EachInit | Add-Member -Type NoteProperty -Name Protocol -Value "FC"
                    $InitReport += $EachInit
            }
	    }
    }
    End{
        If ($ReportArray){Write-Output $InitReport |Where {$_.Array -like $ReportArray}}Else{Write-Output $InitReport}
        If ($Array -and $ArrayUserName -and $ArrayPassword){
            $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            $Global:ArrayTable = @()
            $Global:ArrayTable = $NewCred
        }
    }
}
function Get-IntelliFlashInitiatorGroup {
    [CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$Array,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$InitiatorGroup,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
        [ValidateSet("FC", "iSCSI", "*")]
		[String[]]$Protocol,
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
        CLV InitReport -EA SilentlyContinue
        $InitReport = @()
        [void]($InitReport = Get-IntelliFlashInitiatorGroupList)
    }
    Process{
        Write-Output ($InitReport|where {$_.Array -like $Array -and $_.InitiatorGroup -like $InitiatorGroup -and $_.Protocol -like $Protocol})        
    }
    End{
        If ($Array -and $ArrayUserName -and $ArrayPassword){
            $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            $Global:ArrayTable = @()
            $Global:ArrayTable = $NewCred
        }
    }
}
function Get-IntelliFlashInitiatorGroupMember {
    [CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$Array,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$InitiatorGroup,
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
        CLV InitGroupReport -EA SilentlyContinue
        $InitGroupReport = @()
        $EachInitGroupMember = @()
        $InitGroupMemberReport = @()
    }
    Process{
        [void]($InitGroupReport = Get-IntelliFlashInitiatorGroupList |Where {$_.InitiatorGroup -like $InitiatorGroup -and $_.Array -like $Array})
        ForEach ($EachGroup in $InitGroupReport){
            $CurrentArray = $EachGroup.Array
            $CurrentGroup = $EachGroup.InitiatorGroup
            $Cred = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select Cred
            $Cred = $Cred.Cred
            $IntelliFlashVersion = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select IntelliFlashVersion
            $IntelliFlashVersion = [double]$IntelliFlashVersion.IntelliFlashVersion.Substring(0,3)
            If ($IntelliFlashVersion -lt 3.5){$APIVer = "v1"}else{$APIVer = "v2"}
	        $url = "https://$CurrentArray/zebi/api/$APIVer/listInitiatorsInInitiatorGroup"
	        $postParams = "[`"$CurrentGroup`"]"
			Write-Debug $postParams
	        $initmember = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
            If (!$initmember){
                  $EachInitGroupMember = New-Object -TypeName PSObject
                  $EachInitGroupMember | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                  $EachInitGroupMember | Add-Member -Type NoteProperty -Name InitiatorGroup -Value $CurrentGroup
                  $EachInitGroupMember | Add-Member -Type NoteProperty -Name Status -Value "False"
                  $InitGroupMemberReport += $EachInitGroupMember
                  }Else{
                  ForEach ($init in $initmember){
                      $EachInitGroupMember = New-Object -TypeName PSObject
                      $EachInitGroupMember | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                      $EachInitGroupMember | Add-Member -Type NoteProperty -Name InitiatorGroup -Value $CurrentGroup
                      $EachInitGroupMember | Add-Member -Type NoteProperty -Name InitiatorGroupMember -Value $Init
                      $EachInitGroupMember | Add-Member -Type NoteProperty -Name Status -Value "True"
                      $InitGroupMemberReport += $EachInitGroupMember
                 }
            }
	    }
    }
    End{
        Write-Output $InitGroupMemberReport
        If ($Array -and $ArrayUserName -and $ArrayPassword){
            $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            $Global:ArrayTable = @()
            $Global:ArrayTable = $NewCred
        }	
    }
}
function Get-IntelliFlashTargetGroupList {
    [CmdletBinding()]
	Param (
		[Parameter()]
		[String[]]$Array,
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
        CLV TgtReport -EA SilentlyContinue
        $TgtReport = @()
    }
    Process{
        ForEach ($CurrentArray in $global:ArrayTable){
            $CurrentArray = $CurrentArray.Array
	        $Cred = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select Cred
            $Cred = $Cred.Cred
            $IntelliFlashVersion = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select IntelliFlashVersion
            $IntelliFlashVersion = [double]$IntelliFlashVersion.IntelliFlashVersion.Substring(0,3)
            If ($IntelliFlashVersion -lt 3.5){$APIVer = "v1"}else{$APIVer = "v2"}
	        $url = "https://$CurrentArray/zebi/api/$APIVer/listISCSITargetGroups"
	        $postParams = "[]"
			Write-Debug $postParams
	        $iSCSItgt = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
            ForEach ($tgt in $iSCSItgt){
                    $Eachtgt = New-Object -TypeName PSObject
                    $Eachtgt | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                    $Eachtgt | Add-Member -Type NoteProperty -Name TargetGroup -Value $tgt
                    $Eachtgt | Add-Member -Type NoteProperty -Name Protocol -Value "iSCSI"
                    $TgtReport += $Eachtgt
            }
            CLV tgt -ea SilentlyContinue
            CLV eachtgt -ea SilentlyContinue
            $url = "https://$CurrentArray/zebi/api/$APIVer/listFCTargetGroups"
	        $postParams = "[]"
			Write-Debug $postParams
	        $FCtgt = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
            ForEach ($tgt in $FCtgt){
                    $Eachtgt = New-Object -TypeName PSObject
                    $Eachtgt | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                    $Eachtgt | Add-Member -Type NoteProperty -Name TargetGroup -Value $tgt
                    $Eachtgt | Add-Member -Type NoteProperty -Name Protocol -Value "FC"
                    $TgtReport += $Eachtgt
            }
	    }
    }
    End{
        Write-Output $TgtReport
        If ($Array -and $ArrayUserName -and $ArrayPassword){
            $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            $Global:ArrayTable = @()
            $Global:ArrayTable = $NewCred
        }	
}
}
function Get-IntelliFlashTargetGroup {
    [CmdletBinding()]
	Param (
		[Parameter(ValueFromPipelineByPropertyName=$True)]
		[String[]]$Array,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
		[String[]]$TargetGroup,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [ValidateSet("FC", "iSCSI", "*")]
		[String[]]$Protocol,
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
        CLV TgtReport -EA SilentlyContinue
        $TgtReport = @()
        [void]($TgtReport = Get-IntelliFlashTargetGroupList)
        If (!$Array){$Array = "*"}
        If (!$TargetGroup){$TargetGroup = "*"}
        If (!$Protocol){$Protocol = "*"}
    }
    Process{
        Write-Output ($TgtReport|where {$_.Array -like $Array -and $_.TargetGroup -like $TargetGroup -and $_.Protocol -like $Protocol})
    }
	End{
        If ($Array -and $ArrayUserName -and $ArrayPassword){
            $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            $Global:ArrayTable = @()
            $Global:ArrayTable = $NewCred
        }
    }
}
function Get-IntelliFlashTargetGroupMember {
    [CmdletBinding()]
	Param (
	    [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
	    [String[]]$Array,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
	    [String[]]$TargetGroup,
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
        CLV TgtGroupReport -EA SilentlyContinue
        $TgtGroupReport = @()
        $EachTgtGroupMember = @()
        $TgtGroupMemberReport = @()
        [void]($TgtGroupReport = Get-IntelliFlashTargetGroupList)
        $i=0
    }
    Process{
        ForEach ($CurrentArray in $Array){
            $CurrentArray = $Array[$i]
            $CurrentTargetGroup = $TargetGroup[$i]
            $Cred = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select Cred
            $Cred = $Cred.Cred
            $IntelliFlashVersion = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select IntelliFlashVersion
            $IntelliFlashVersion = [double]$IntelliFlashVersion.IntelliFlashVersion.Substring(0,3)
            If ($IntelliFlashVersion -lt 3.5){$APIVer = "v1"}else{$APIVer = "v2"}
	        $url = "https://$CurrentArray/zebi/api/$APIVer/listTargetsInTargetGroup"
	        $postParams = "[`"$CurrentTargetGroup`"]"
			Write-Debug $postParams
	        $tgtmember = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
            If ($?){
                ForEach ($tgt in $tgtmember){
                    $EachTgtGroupMember = New-Object -TypeName PSObject
                    $EachTgtGroupMember | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                    $EachTgtGroupMember | Add-Member -Type NoteProperty -Name TargetGroup -Value $CurrentTargetGroup
                    $EachTgtGroupMember | Add-Member -Type NoteProperty -Name TargetGroupMember -Value $tgt
                    $EachTgtGroupMember | Add-Member -Type NoteProperty -Name Status -Value "True"
                    $EachTgtGroupMember | Add-Member -Type NoteProperty -Name TargetGroupFound -Value "True"
                    $TgtGroupMemberReport += $EachTgtGroupMember
                }
            }Else{
                ForEach ($tgt in $tgtmember){
                    $EachTgtGroupMember = New-Object -TypeName PSObject
                    $EachTgtGroupMember | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                    $EachTgtGroupMember | Add-Member -Type NoteProperty -Name TargetGroup -Value $CurrentTargetGroup
                    $EachTgtGroupMember | Add-Member -Type NoteProperty -Name Status -Value "False"
                    $EachTgtGroupMember | Add-Member -Type NoteProperty -Name TargetGroupFound -Value "False"
                    $TgtGroupMemberReport += $EachTgtGroupMember
                }
            }
        $i++
        }
	}
    End{
        Write-Output $TgtGroupMemberReport
        If ($Array -and $ArrayUserName -and $ArrayPassword){
            $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            $Global:ArrayTable = @()
            $Global:ArrayTable = $NewCred
        }
    }
}
function Add-IntelliFlashInitiatorGroup {
    [CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$Array,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$InitiatorGroup,
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
        CLV InitGroupCreateReport -EA SilentlyContinue
        $InitGroupCreateReport = @()
        $i=0
    }
    Process{
        ForEach ($CurrentArray in $Array){
            $Cred = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select Cred
            $Cred = $Cred.Cred
            $IntelliFlashVersion = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select IntelliFlashVersion
            $IntelliFlashVersion = [double]$IntelliFlashVersion.IntelliFlashVersion.Substring(0,3)
            If ($IntelliFlashVersion -lt 3.5){$APIVer = "v1"}else{$APIVer = "v2"}
                $url = "https://$CurrentArray/zebi/api/$APIVer/createInitiatorGroup"
                $NewInitGroup = $InitiatorGroup[$i]
                $postParams = "[`"$NewInitGroup`"]"
				Write-Debug $postParams
	            $CreateInit = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
                If ($?){
                    $EachInit = New-Object -TypeName PSObject
                    $EachInit | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                    $EachInit | Add-Member -Type NoteProperty -Name InitiatorGroup -Value $NewInitGroup
                    $EachInit | Add-Member -Type NoteProperty -Name Status -Value "True"
                    $EachInit | Add-Member -Type NoteProperty -Name GroupCreated -Value "True"
                    $InitGroupCreateReport += $EachInit
                    }Else{
                    $EachInit = New-Object -TypeName PSObject
                    $EachInit | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                    $EachInit | Add-Member -Type NoteProperty -Name InitiatorGroup -Value $NewInitGroup
                    $EachInit | Add-Member -Type NoteProperty -Name Status -Value "False"
                    $EachInit | Add-Member -Type NoteProperty -Name GroupCreated -Value "False"
                    $InitGroupCreateReport += $EachInit
                    }
        $i++
        }
    }
    End{
        Write-Output $InitGroupCreateReport
        If ($Array -and $ArrayUserName -and $ArrayPassword){
            $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            $Global:ArrayTable = @()
            $Global:ArrayTable = $NewCred
        }
    }
}
function Add-IntelliFlashInitiatorGroupMember {
    [CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$Array,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$InitiatorGroup,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$InitiatorGroupMember,
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
        CLV InitGroupMemberAddReport -EA SilentlyContinue
        $InitGroupMemberAddReport = @()
        $i=0
    }
    Process{
        ForEach ($CurrentArray in $Array){
	        $Cred = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select Cred
            $Cred = $Cred.Cred
            $IntelliFlashVersion = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select IntelliFlashVersion
            $IntelliFlashVersion = [double]$IntelliFlashVersion.IntelliFlashVersion.Substring(0,3)
            If ($IntelliFlashVersion -lt 3.5){$APIVer = "v1"}else{$APIVer = "v2"}
	        $url = "https://$CurrentArray/zebi/api/$APIVer/addInitiatorToInitiatorGroup"
	        $CurrentInitGroupMember = $InitiatorGroupMember[$i]
            $CurrentInitGroup = $InitiatorGroup[$i]
            $postParams = "[`"$CurrentInitGroupMember`",`"$CurrentInitGroup`"]"
			Write-Debug $postParams
	        $AddInit = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
            If ($?){
                $EachInit = New-Object -TypeName PSObject
                $EachInit | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                $EachInit | Add-Member -Type NoteProperty -Name InitiatorGroup -Value $InitiatorGroup[$i]
                $EachInit | Add-Member -Type NoteProperty -Name InitiatorGroupMember -Value $InitiatorGroupMember[$i]
                $EachInit | Add-Member -Type NoteProperty -Name Status -Value "True"
                $EachInit | Add-Member -Type NoteProperty -Name GroupCreated -Value "True"
                $InitGroupMemberAddReport += $EachInit
                }Else{
                $EachInit = New-Object -TypeName PSObject
                $EachInit | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                $EachInit | Add-Member -Type NoteProperty -Name InitiatorGroup -Value $InitiatorGroup[$i]
                $EachInit | Add-Member -Type NoteProperty -Name InitiatorGroupMember -Value $InitiatorGroupMember[$i]
                $EachInit | Add-Member -Type NoteProperty -Name Status -Value "False"
                $EachInit | Add-Member -Type NoteProperty -Name GroupCreated -Value "False"
                $InitGroupMemberAddReport += $EachInit
            }
       $i++
       }
    }
    End{
        Write-Output $InitGroupMemberAddReport
        If ($Array -and $ArrayUserName -and $ArrayPassword){
            $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            $Global:ArrayTable = @()
            $Global:ArrayTable = $NewCred
        }
    }
}
function Add-IntelliFlashiSCSIInitiator {
    [CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$Array,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$iSCSIInitiatorIQN,
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
        CLV InitGroupMemberAddReport -EA SilentlyContinue
        $InitCreateReport = @()
        $i=0
    }
    Process{
        ForEach ($CurrentArray in $Array){
	        $Cred = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select Cred
            $Cred = $Cred.Cred
            $IntelliFlashVersion = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select IntelliFlashVersion
            $IntelliFlashVersion = [double]$IntelliFlashVersion.IntelliFlashVersion.Substring(0,3)
            If ($IntelliFlashVersion -lt 3.5){$APIVer = "v1"}else{$APIVer = "v2"}
	        $url = "https://$CurrentArray/zebi/api/$APIVer/createIscsiInitiator"
	        $CurrentInit = $iSCSIInitiatorIQN[$i]
            $postParams = "[{`"initiatorName`":`"$CurrentInit`"}]"
			Write-Debug $postParams
	        $AddInit = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
            If ($?){
                $EachInit = New-Object -TypeName PSObject
                $EachInit | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                $EachInit | Add-Member -Type NoteProperty -Name IQN -Value $iSCSIInitiatorIQN[$i]
                $EachInit | Add-Member -Type NoteProperty -Name Status -Value "True"
                $EachInit | Add-Member -Type NoteProperty -Name InitiatorCreated -Value "True"
                $InitCreateReport += $EachInit
                }Else{
                $EachInit = New-Object -TypeName PSObject
                $EachInit | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                $EachInit | Add-Member -Type NoteProperty -Name IQN -Value $iSCSIInitiatorIQN[$i]
                $EachInit | Add-Member -Type NoteProperty -Name Status -Value "False"
                $EachInit | Add-Member -Type NoteProperty -Name InitiatorCreated -Value "False"
                $InitCreateReport += $EachInit
            }
       $i++
       }
    }
    End{
        Write-Output $InitCreateReport
        If ($Array -and $ArrayUserName -and $ArrayPassword){
            $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            $Global:ArrayTable = @()
            $Global:ArrayTable = $NewCred
        }	
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
            $postParams = "[`"" + $DataSetPath + "`", " + "`"" + $CurrentInitGroup +"`", " + "`"" + $CurrentTgtGroup + "`",$CurrentLUNNumber]"
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
function Remove-IntelliFlashLUNMapping {
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
        #CLV RemoveMappingReport -EA SilentlyContinue
        $RemoveMappingReport = @()
        $i=0
    }
    Process{
        ForEach ($CurrentArray in $Array){
            $Cred = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select Cred
            $Cred = $Cred.Cred
            $IntelliFlashVersion = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select IntelliFlashVersion
            $IntelliFlashVersion = [double]$IntelliFlashVersion.IntelliFlashVersion.Substring(0,3)
            If ($IntelliFlashVersion -lt 3.5){$APIVer = "v1"}else{$APIVer = "v2"}
            $url = "https://$CurrentArray/zebi/api/$APIVer/deleteMappingFromVolume"
            $CurrentInitGroup = $InitiatorGroup[$i]
            $CurrentTgtGroup = $TargetGroup[$i]
            $CurrentPool = $PoolName[$i]
            $CurrentProject = $ProjectName[$i]
            $CurrentLUN = $LUNName[$i]
            $DataSetPath = "$CurrentPool/Local/$CurrentProject/$CurrentLUN"
            $postParams = "[`"" + $DataSetPath + "`", " + "`"" + $CurrentInitGroup +"`", " + "`"" + $CurrentTgtGroup + "`"]"
			Write-Debug $postParams
            $RemoveMapping = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
            If ($RemoveMapping -eq 0){
                $EachMap = New-Object -TypeName PSObject
                $EachMap | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                $EachMap | Add-Member -Type NoteProperty -Name PoolName -Value $CurrentPool
                $EachMap | Add-Member -Type NoteProperty -Name ProjectName -Value $CurrentProject
                $EachMap | Add-Member -Type NoteProperty -Name LUNName -Value $CurrentLUN
                $EachMap | Add-Member -Type NoteProperty -Name InitiatorGroup -Value $CurrentInitGroup
                $EachMap | Add-Member -Type NoteProperty -Name TargetGroup -Value $CurrentTgtGroup
                $EachMap | Add-Member -Type NoteProperty -Name Status -Value "True"
                $EachMap | Add-Member -Type NoteProperty -Name MappingDeleted -Value "True"
                $RemoveMappingReport += $EachMap
                }Else{
                $EachMap = New-Object -TypeName PSObject
                $EachMap | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                $EachMap | Add-Member -Type NoteProperty -Name PoolName -Value $CurrentPool
                $EachMap | Add-Member -Type NoteProperty -Name ProjectName -Value $CurrentProject
                $EachMap | Add-Member -Type NoteProperty -Name LUNName -Value $CurrentLUN
                $EachMap | Add-Member -Type NoteProperty -Name InitiatorGroup -Value $CurrentInitGroup
                $EachMap | Add-Member -Type NoteProperty -Name TargetGroup -Value $CurrentTgtGroup
                $EachMap | Add-Member -Type NoteProperty -Name Status -Value "False"
                $EachMap | Add-Member -Type NoteProperty -Name MappingDeleted -Value "False"
                $RemoveMappingReport += $EachMap
                }
        $i++
        }
    }
    End{
        Write-Output $RemoveMappingReport
        If ($Array -and $ArrayUserName -and $ArrayPassword){
            $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            $Global:ArrayTable = @()
            $Global:ArrayTable = $NewCred
        }
    }
}
function Push-IntelliFlashInitiatorConfiguration {
    [CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true)]
		[String]$SourceArray,
        [Parameter(Mandatory=$true)]
		[String]$TargetArray
    )
    Begin{
        $SrcCred = $global:ArrayTable |Where {$_.Array -eq $SourceArray}|select Cred
        $TgtCred = $global:ArrayTable |Where {$_.Array -eq $TargetArray}|select Cred
        if (!$global:ArrayTable -or !$SrcCred -or !$TgtCred) {Write-Output "You must connect to both the source and target IntelliFlash arrays for this function to work properly"}
    }
    Process{
        Write-progress -activity "Cloning Initiator Configuration from $SourceArray to $TargetArray" -status "Progress:" -percentcomplete (0)
        $SrcInitGroup = (Get-IntelliFlashInitiatorGroupList|Where {$_.Array -eq $SourceArray})
        Write-progress -activity "Cloning Initiator Configuration from $SourceArray to $TargetArray" -status "Progress:" -percentcomplete (10)
        $SrcInitGroupMember = (Get-IntelliFlashInitiatorGroupMember -Array $SourceArray -InitiatorGroup "*")
        Write-progress -activity "Cloning Initiator Configuration from $SourceArray to $TargetArray" -status "Progress:" -percentcomplete (20)
        $SrcIscsiInit = $SrcInitGroupMember|Where {$_.InitiatorGroupMember -notlike "wwn.*"}
        ForEach ($NewGroup in $SrcInitGroup){
            $Null = [void](Add-IntelliFlashInitiatorGroup -Array $TargetArray -InitiatorGroup $NewGroup.InitiatorGroup)
        }
        Write-progress -activity "Cloning Initiator Configuration from $SourceArray to $TargetArray" -status "Progress:" -percentcomplete (30)
        ForEach ($NewIscsiInit in $SrcIscsiInit){
            $Null = [void](Add-IntelliFlashiSCSIInitiator -Array $TargetArray -iSCSIInitiatorIQN $NewIscsiInit.InitiatorGroupMember)
        }
        Write-progress -activity "Cloning Initiator Configuration from $SourceArray to $TargetArray" -status "Progress:" -percentcomplete (60)
        ForEach ($NewMember in $SrcInitGroupMember){
            $Null = [void](Add-IntelliFlashInitiatorGroupMember -Array $TargetArray -InitiatorGroup $NewMember.InitiatorGroup -InitiatorGroupMember $NewMember.InitiatorGroupMember)
        }
        Write-progress -activity "Cloning Initiator Configuration from $SourceArray to $TargetArray" -status "Progress:" -percentcomplete (99)
    }
    End{
        Write-Host "-Push complete-"
    }
}
function Get-IntelliFlashSnapList {
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
	if ($Replica) {$local = "Replica";$LocalSnap = "False"} else {$local = "Local";$LocalSnap = "True"}
    CLV SnapReport -EA SilentlyContinue
    if ($Replica)  {[void]($ProjectList = Get-IntelliFlashProjectList -Replica)}Else{[void]($ProjectList = Get-IntelliFlashProjectList)}
    if ($Replica)  {[void]($LUNList = Get-IntelliFlashLUNList -Replica)}Else{[void]($LUNList = Get-IntelliFlashLUNList)}
    if ($Replica)  {[void]($ShareList = Get-IntelliFlashShareList -Replica)}Else{[void]($ShareList = Get-IntelliFlashShareList)}

    $SnapReport = @()
    }
    Process{
        ForEach ($Project in $ProjectList){
            $CurrentArray = $Project.Array
            $ProjectName = $Project.ProjectName
            $PoolName = $Project.PoolName
            $FullPath = "$PoolName/$local/$ProjectName"
            $Cred = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select Cred
            $Cred = $Cred.Cred
            $IntelliFlashVersion = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select IntelliFlashVersion
            $IntelliFlashVersion = [double]$IntelliFlashVersion.IntelliFlashVersion.Substring(0,3)
            If ($IntelliFlashVersion -lt 3.5){$APIVer = "v1"}else{$APIVer = "v2"}
            $url = "https://$CurrentArray/zebi/api/$APIVer/listSnapshots"
	        $postParams = "[`"$FullPath`",`".*`"]"
			Write-Debug $postParams
	        $SnapList = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
            #$postParams
            #$SnapList
            ForEach ($Snap in $SnapList) {
                $SSPath = "$FullPath@$Snap"
                $EachSnap = New-Object -TypeName PSObject
                $EachSnap | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                $EachSnap | Add-Member -Type NoteProperty -Name PoolName -Value $PoolName
                $EachSnap | Add-Member -Type NoteProperty -Name ProjectName -Value $ProjectName
                $EachSnap | Add-Member -Type NoteProperty -Name LocalSnap -Value $LocalSnap
                $EachSnap | Add-Member -Type NoteProperty -Name SnapType -Value "Project"
                $EachSnap | Add-Member -Type NoteProperty -Name SnapName -Value $Snap
                $EachSnap | Add-Member -Type NoteProperty -Name SnapFullPath -Value $SSPath
                $SnapReport += $EachSnap
            }
        }
        ForEach ($LUN in $LUNList){
            $CurrentArray = $LUN.Array
            $ProjectName = $LUN.ProjectName
            $PoolName = $LUN.PoolName
            $LUNName = $LUN.LUNName
            $FullPath = "$PoolName/$local/$ProjectName/$LUNName"
            $Cred = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select Cred
            $Cred = $Cred.Cred
            $IntelliFlashVersion = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select IntelliFlashVersion
            $IntelliFlashVersion = [double]$IntelliFlashVersion.IntelliFlashVersion.Substring(0,3)
            If ($IntelliFlashVersion -lt 3.5){$APIVer = "v1"}else{$APIVer = "v2"}
            $url = "https://$CurrentArray/zebi/api/$APIVer/listSnapshots"
	        $postParams = "[`"$FullPath`",`".*`"]"
			Write-Debug $postParams
	        $SnapList = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
            #$postParams
            #$SnapList
            ForEach ($Snap in $SnapList) {
                $SSPath = "$FullPath@$Snap"
                $EachSnap = New-Object -TypeName PSObject
                $EachSnap | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                $EachSnap | Add-Member -Type NoteProperty -Name PoolName -Value $PoolName
                $EachSnap | Add-Member -Type NoteProperty -Name ProjectName -Value $ProjectName
                $EachSnap | Add-Member -Type NoteProperty -Name LocalSnap -Value $LocalSnap
                $EachSnap | Add-Member -Type NoteProperty -Name SnapType -Value "LUN"
                $EachSnap | Add-Member -Type NoteProperty -Name SnapName -Value $Snap
                $EachSnap | Add-Member -Type NoteProperty -Name LUNName -Value $LUNName
                $EachSnap | Add-Member -Type NoteProperty -Name SnapFullPath -Value $SSPath
                $SnapReport += $EachSnap
            }
        }
        ForEach ($Share in $ShareList){
            $CurrentArray = $Share.Array
            $ProjectName = $Share.ProjectName
            $PoolName = $Share.PoolName
            $ShareName = $Share.ShareName
            $FullPath = "$PoolName/$local/$ProjectName/$ShareName"
            $Cred = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select Cred
            $Cred = $Cred.Cred
            $IntelliFlashVersion = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select IntelliFlashVersion
            $IntelliFlashVersion = [double]$IntelliFlashVersion.IntelliFlashVersion.Substring(0,3)
            If ($IntelliFlashVersion -lt 3.5){$APIVer = "v1"}else{$APIVer = "v2"}
            $url = "https://$CurrentArray/zebi/api/$APIVer/listSnapshots"
	        $postParams = "[`"$FullPath`",`".*`"]"
			Write-Debug $postParams
	        $SnapList = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
            #$postParams
            #$SnapList
            ForEach ($Snap in $SnapList) {
                $SSPath = "$FullPath@$Snap"
                $EachSnap = New-Object -TypeName PSObject
                $EachSnap | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                $EachSnap | Add-Member -Type NoteProperty -Name PoolName -Value $PoolName
                $EachSnap | Add-Member -Type NoteProperty -Name ProjectName -Value $ProjectName
                $EachSnap | Add-Member -Type NoteProperty -Name LocalSnap -Value $LocalSnap
                $EachSnap | Add-Member -Type NoteProperty -Name SnapType -Value "Share"
                $EachSnap | Add-Member -Type NoteProperty -Name SnapName -Value $Snap
                $EachSnap | Add-Member -Type NoteProperty -Name ShareName -Value $ShareName
                $EachSnap | Add-Member -Type NoteProperty -Name SnapFullPath -Value $SSPath
                $SnapReport += $EachSnap
            }
        }
    }
    End{
        Write-Output $SnapReport
        If ($Array -and $ArrayUserName -and $ArrayPassword){
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
		[String]$ArrayUserName,
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
        If ($Array -and $ArrayUserName -and $ArrayPassword){
            $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            $Global:ArrayTable = @()
            $Global:ArrayTable = $NewCred
        }
    }
}
function Add-IntelliFlashLUNSnap {
    [CmdletBinding()]
	Param (
        [Parameter(ValueFromPipelineByPropertyName=$True)]
		[Switch[]]$Quiesce,
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$Array,
		[Parameter()]
		[String[]]$ArrayUserName,
		[Parameter()]
		[String[]]$ArrayPassword,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$PoolName,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$ProjectName,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$LUNName,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$LUID,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$LUNSize,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$BlockSize,
        ##########################################################
        ### Thin Provision Detection is not accurate but the below
        ### can be enabled when that is fixed
        #[Parameter(ValueFromPipelineByPropertyName=$True)]
		#[String]$TP,
        ##########################################################
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
        [ValidateSet("FC", "iSCSI")]
		[String[]]$Protocol,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$FullPath,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
        [ValidateSet("True", "False")]
		[String[]]$LocalLUN,
        [Parameter()]
		[Switch]$QuiesceAll,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
		[String[]]$SnapName
        
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
    #CLV SnapReport -EA SilentlyContinue
    $NewSnapReport = @()
    $RUNDATETIME = Get-Date -UFormat "%Y%m%d%H%M%S"
    }
    Process{
            ForEach($CurrentArray in $Array){
                $Cred = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select Cred
                $Cred = $Cred.Cred
                $IntelliFlashVersion = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select IntelliFlashVersion
                $IntelliFlashVersion = [double]$IntelliFlashVersion.IntelliFlashVersion.Substring(0,3)
                If ($IntelliFlashVersion -lt 3.5){$APIVer = "v1"}else{$APIVer = "v2"}
                $url = "https://$CurrentArray/zebi/api/$APIVer/createVolumeSnapshot"
                $CLUNName = $LUNName[0]
                If ($Quiesce){If ($Quiesce[0] = True){$Q = "true"}Else{$Q = "false"}}
                If ($QuiesceAll){$Q = "true"}
                If (!$Quiesce -and !$QuiesceAll){$Q = "false"}
                If (!$SnapName){$CSnapName = "$CLUNName-$RUNDATETIME"}
                    Else{
                        If (!$SnapName[0]){$CSnapName = "$LUNName-$RUNDATETIME"}
                            Else{
                                $CSnapName = $SnapName[0]
                            }
                }
                $CPoolName = $PoolName[0]
                $CProjectName = $ProjectName[0]
                $CLUID = $LUID[0]
                $CLUNSize = $LUNSize[0]
                $CBlockSize = $BlockSize[0]
                $CProtocol = $Protocol[0]
                $CFullPath = $FullPath[0]
                $postParams = "[`{`"poolName`": `"" + $CPoolName + "`", `"projectName`": `"" + $CProjectName + "`", `"name`": `"" + $CLUNName + "`", `"luId`": `"" + $CLUID + "`", `"volSize`": `"" + $CLUNSize + "`", `"blockSize`": `"" + $CBlockSize + "`", `"thinProvision`": false`, `"protocol`": `"" + $CProtocol + "`", `"datasetPath`": `"" + $CFullPath + "`", `"local`": true`}, `"" + $CSnapName + "`", $Q]"
				Write-Debug $postParams
	            $CurrentSnap = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
                If($?){$SnapStatus = "True"}Else{$SnapStatus = "False"} 
                $EachSnap = New-Object -TypeName PSObject
                $EachSnap | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                $EachSnap | Add-Member -Type NoteProperty -Name PoolName -Value $CPoolName
                $EachSnap | Add-Member -Type NoteProperty -Name ProjectName -Value $CProjectName
                $EachSnap | Add-Member -Type NoteProperty -Name SnapType -Value "LUN"
                $EachSnap | Add-Member -Type NoteProperty -Name SnapName -Value "Manual-V-$CSnapName"
                $EachSnap | Add-Member -Type NoteProperty -Name LUNName -Value $CLUNName
                $EachSnap | Add-Member -Type NoteProperty -Name Quiesce -Value $Q
                $EachSnap | Add-Member -Type NoteProperty -Name Status -Value $SnapStatus
                $EachSnap | Add-Member -Type NoteProperty -Name SnapCreated -Value $SnapStatus
                $NewSnapReport += $EachSnap
            }
    }
    End{
        Write-Output $NewSnapReport
        If ($Array -and $ArrayUserName -and $ArrayPassword){
            $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            $Global:ArrayTable = @()
            $Global:ArrayTable = $NewCred
        }
    }
}
function Add-IntelliFlashShareSnap {
    [CmdletBinding()]
	Param (
        [Parameter(ValueFromPipelineByPropertyName=$True)]
		[Switch[]]$Quiesce,
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$Array,
		[Parameter()]
		[String[]]$ArrayUserName,
		[Parameter()]
		[String[]]$ArrayPassword,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$PoolName,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$ProjectName,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$ShareName,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$ShareAvailableSize,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$ShareTotalSize,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$FullPath,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$MountPoint,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
        [ValidateSet("True", "False")]
		[String[]]$LocalShare,
        [Parameter()]
		[Switch]$QuiesceAll,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
		[String[]]$SnapName
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
    CLV SnapReport -EA SilentlyContinue
    $NewSnapReport = @()
    $RUNDATETIME = Get-Date -UFormat "%Y%m%d%H%M%S"
    }
    Process{
            ForEach($CurrentArray in $Array){
                $Cred = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select Cred
                $Cred = $Cred.Cred
                $IntelliFlashVersion = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select IntelliFlashVersion
                $IntelliFlashVersion = [double]$IntelliFlashVersion.IntelliFlashVersion.Substring(0,3)
                If ($IntelliFlashVersion -lt 3.5){$APIVer = "v1"}else{$APIVer = "v2"}
                $url = "https://$CurrentArray/zebi/api/$APIVer/createShareSnapshot"
                If ($Quiesce){If ($Quiesce[0] = True){$Q = "true"}Else{$Q = "false"}}
                If ($QuiesceAll){$Q = "true"}
                If (!$Quiesce -and !$QuiesceAll){$Q = "false"}
                $CShareName = $ShareName[0]
                If (!$SnapName){$CSnapName = "$CShareName-$RUNDATETIME"}
                    Else{
                        If (!$SnapName[0]){$CSnapName = "$CShareName-$RUNDATETIME"}
                            Else{
                                $CSnapName = $SnapName[0]
                            }
                }
                $CPoolName = $PoolName[0]
                $CProjectName = $ProjectName[0]
                $CShareAvailableSize = $ShareAvailableSize[0]
                $CShareTotalSize = $ShareTotalSize[0]
                $CFullPath = $FullPath[0]
                $CMountPoint = $MountPoint[0]
                $postParams = "[`{`"poolName`": `"" + $CPoolName + "`", `"projectName`": `"" + $CProjectName + "`", `"name`": `"" + $CShareName + "`", `"totalSize`": `"" + $CShareTotalSize + "`", `"availableSize`": `"" + $CShareAvailableSize + "`", `"datasetPath`": `"" + $CFullPath + "`", `"local`": true`}, `"" + $CSnapName + "`", $Q]"
				Write-Debug $postParams
	            $CurrentSnap = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
                If($?){$SnapStatus = "True"}Else{$SnapStatus = "False"} 
                $EachSnap = New-Object -TypeName PSObject
                $EachSnap | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                $EachSnap | Add-Member -Type NoteProperty -Name PoolName -Value $CPoolName
                $EachSnap | Add-Member -Type NoteProperty -Name ProjectName -Value $CProjectName
                $EachSnap | Add-Member -Type NoteProperty -Name SnapType -Value "Share"
                $EachSnap | Add-Member -Type NoteProperty -Name SnapName -Value "Manual-S-$CSnapName"
                $EachSnap | Add-Member -Type NoteProperty -Name ShareName -Value $CShareName
                $EachSnap | Add-Member -Type NoteProperty -Name Quiesce -Value $Q
                $EachSnap | Add-Member -Type NoteProperty -Name Status -Value $SnapStatus
                $EachSnap | Add-Member -Type NoteProperty -Name SnapCreated -Value $SnapStatus
                $NewSnapReport += $EachSnap
            }
    }
    End{
        Write-Output $NewSnapReport
        If ($Array -and $ArrayUserName -and $ArrayPassword){
            $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            $Global:ArrayTable = @()
            $Global:ArrayTable = $NewCred
        }
    }
}
function Add-IntelliFlashProjectSnap {
    [CmdletBinding()]
	Param (
        [Parameter(ValueFromPipelineByPropertyName=$True)]
		[Switch[]]$Quiesce,
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$Array,
		[Parameter()]
		[String[]]$ArrayUserName,
		[Parameter()]
		[String[]]$ArrayPassword,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$PoolName,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$ProjectName,
        [Parameter()]
		[Switch]$QuiesceAll,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
		[String[]]$SnapName
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
    CLV SnapReport -EA SilentlyContinue
    $NewSnapReport = @()
    $RUNDATETIME = Get-Date -UFormat "%Y%m%d%H%M%S"
    }
    Process{
            ForEach($CurrentArray in $Array){
                $Cred = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select Cred
                $Cred = $Cred.Cred
                $IntelliFlashVersion = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select IntelliFlashVersion
                $IntelliFlashVersion = [double]$IntelliFlashVersion.IntelliFlashVersion.Substring(0,3)
                If ($IntelliFlashVersion -lt 3.5){$APIVer = "v1"}else{$APIVer = "v2"}
                $url = "https://$CurrentArray/zebi/api/$APIVer/createProjectSnapshot"
                If ($Quiesce){If ($Quiesce[0] = True){$Q = "true"}Else{$Q = "false"}}
                If ($QuiesceAll){$Q = "true"}
                If (!$Quiesce -and !$QuiesceAll){$Q = "false"}
                $CPoolName = $PoolName[0]
                $CProjectName = $ProjectName[0]
                If (!$SnapName){$CSnapName = "$CProjectName-$RUNDATETIME"}
                    Else{
                        If (!$SnapName[0]){$CSnapName = "$CProjectName-$RUNDATETIME"}
                            Else{
                                $CSnapName = $SnapName[0]
                            }
                }
                $postParams = "[`{`"poolName`": `"" + $CPoolName + "`", `"name`": `"" + $CProjectName + "`", `"local`": true`}, `"" + $CSnapName + "`", $Q]"
				Write-Debug $postParams
	            $CurrentSnap = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
                If($?){$SnapStatus = "True"}Else{$SnapStatus = "False"} 
                $EachSnap = New-Object -TypeName PSObject
                $EachSnap | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                $EachSnap | Add-Member -Type NoteProperty -Name PoolName -Value $CPoolName
                $EachSnap | Add-Member -Type NoteProperty -Name ProjectName -Value $CProjectName
                $EachSnap | Add-Member -Type NoteProperty -Name SnapType -Value "Project"
                $EachSnap | Add-Member -Type NoteProperty -Name SnapName -Value "Manual-P-$CSnapName"
                $EachSnap | Add-Member -Type NoteProperty -Name Quiesce -Value $Q
                $EachSnap | Add-Member -Type NoteProperty -Name Status -Value $SnapStatus
                $EachSnap | Add-Member -Type NoteProperty -Name SnapCreated -Value $SnapStatus
                $NewSnapReport += $EachSnap
            }
    }
    End{
        Write-Output $NewSnapReport
        If ($Array -and $ArrayUserName -and $ArrayPassword){
            $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            $Global:ArrayTable = @()
            $Global:ArrayTable = $NewCred
        }
    }
}
function Get-IntelliFlashSnapStatus {
    [CmdletBinding()]
	Param (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$Array,
		[Parameter()]
		[String[]]$ArrayUserName,
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
		[String[]]$LUNName
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
        CLV SnapStatusReport -EA SilentlyContinue
        $SnapStatusReport = @()
        If($ShareName -and $LUNName){
            Write-Host "You have tried to pass both a LUN name and Share name in the same command." -ForegroundColor yellow -BackgroundColor Black
            Write-Host "This is unsupported." -ForegroundColor yellow -BackgroundColor Black
            Break
        }
        $StatusDescription = ("Success","InProgress","Error")
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
                If ($ShareName){
                    $CShareName = $ShareName[0]
                    $CFullPath = "$CPoolName/Local/$CProjectName/$CShareName"
                    $postParams = "[`"" + $CFullPath + "`", `"" + $CSnapName + "`"]"
					Write-Debug $postParams
                    $SnapType = "Share"
	                $url = "https://$CurrentArray/zebi/api/$APIVer/getShareSnapshotCreationStatus"
                }
                If ($LUNName){
                    $CLUNName = $LUNName[0]
                    $CFullPath = "$CPoolName/Local/$CProjectName/$CLUNName"
                    $postParams = "[`"" + $CFullPath + "`", `"" + $CSnapName + "`"]"
					Write-Debug $postParams
                    $SnapType = "LUN"
	                $url = "https://$CurrentArray/zebi/api/$APIVer/getVolumeSnapshotCreationStatus"
                }
                If (!$ShareName -and !$LUNName){
                    $CFullPath = "$CPoolName/Local/$CProjectName"
                    $postParams = "[`"" + $CFullPath + "`", `"" + $CSnapName + "`"]"
					Write-Debug $postParams
                    $SnapType = "Project"
	                $url = "https://$CurrentArray/zebi/api/$APIVer/getProjectSnapshotCreationStatus"
                }
                $CurrentSnap = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
                $EachSnap = New-Object -TypeName PSObject
                $EachSnap | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                $EachSnap | Add-Member -Type NoteProperty -Name PoolName -Value $CPoolName
                $EachSnap | Add-Member -Type NoteProperty -Name ProjectName -Value $CProjectName
                If ($SnapType -eq "Share"){$EachSnap | Add-Member -Type NoteProperty -Name ShareName -Value $CShareName}
                If ($SnapType -eq "LUN"){$EachSnap | Add-Member -Type NoteProperty -Name LUNName -Value $CLUNName}
                $EachSnap | Add-Member -Type NoteProperty -Name FullPath -Value $CFullPath
                $EachSnap | Add-Member -Type NoteProperty -Name SnapType -Value $SnapType
                $EachSnap | Add-Member -Type NoteProperty -Name SnapName -Value $CSnapName
                $EachSnap | Add-Member -Type NoteProperty -Name Status -Value $CurrentSnap.snapshotProgressStatus
                $EachSnap | Add-Member -Type NoteProperty -Name StatusDescription -Value $StatusDescription[$CurrentSnap.snapshotProgressStatus]
                $SnapStatusReport += $EachSnap
            }
    }
    End{
        Write-Output $SnapStatusReport
        If ($Array -and $ArrayUserName -and $ArrayPassword){
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
		[String[]]$ArrayUserName,
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
		[Switch]$Replica,
        [Parameter()]
		[Switch]$ReplicaKeepGUID,
        [Parameter()]
		[Switch]$ReadOnly,
        [Parameter()]
		[Switch]$ALLiSCSI
        
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
                    If (!$Replica){
                        $CFullPath = "$CPoolName/Local/$CProjectName@$CSnapName"
                        If ($CloneName){$CCloneName = $CloneName[0]}Else{$CCloneName = "$CProjectName" + "-" + "$RUNDATETIME"}
                        $postParams = "[`"" + $CFullPath + "`", `"" + $CCloneName + "`",`"" + $CInherit + "`"]"
					    Write-Debug $postParams
                        $SnapType = "Project"
	                    $url = "https://$CurrentArray/zebi/api/$APIVer/cloneProjectSnapshot"
                    }
                    If ($Replica){
                        $CFullPath = "$CPoolName/Replica/$CProjectName@$CSnapName"
                        If ($CloneName){$CCloneName = $CloneName[0]}Else{$CCloneName = "$CProjectName" + "-" + "$RUNDATETIME"}
                        If ($ReadOnly){$CReadOnly = "true"}Else{$CReadOnly = "false"}
                        If ($ReplicaKeepGUID){$CKeepGUID = "true"}Else{$CKeepGUID = "false"}
                        If ($CKeepGUID){
                            $postParams = "[`"" + $CFullPath + "`", `"" + $CCloneName + "`",`"" + $CReadOnly + "`",`"" + $CInherit + "`",`"" + $CKeepGUID + "`"]"
                            } Else {
                            $postParams = "[`"" + $CFullPath + "`", `"" + $CCloneName + "`",`"" + $CReadOnly + "`",`"" + $CInherit + "`"]"
                        }
					    Write-Debug $postParams
                        $SnapType = "Project"
	                    $url = "https://$CurrentArray/zebi/api/$APIVer/cloneReplicaProjectSnapshot"
                    }
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
        If ($Array -and $ArrayUserName -and $ArrayPassword){
            $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            $Global:ArrayTable = @()
            $Global:ArrayTable = $NewCred
        }
    }
}
function Get-IntelliFlashProjectCloneStatus {
    [CmdletBinding()]
	Param (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$Array,
		[Parameter()]
		[String[]]$ArrayUserName,
		[Parameter()]
		[String[]]$ArrayPassword,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
		[String[]]$PoolName,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
		[String[]]$ProjectName,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$SnapFullPath,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$CloneName
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
        CLV CreateCloneReport -EA SilentlyContinue
        $CreateProjectCloneStatusReport = @()
        $StatusDescription = ("InProgress","Success","Partial","Failure")
    }
    Process{
            ForEach($CurrentArray in $Array){
                $Cred = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select Cred
                $Cred = $Cred.Cred
                $IntelliFlashVersion = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select IntelliFlashVersion
                $IntelliFlashVersion = [double]$IntelliFlashVersion.IntelliFlashVersion.Substring(0,3)
                If ($IntelliFlashVersion -lt 3.5){$APIVer = "v1"}else{$APIVer = "v2"}
                $CFullPath = $SnapFullPath[0]
                $CCloneName = $CloneName[0]
                If($PoolName){$CPoolName = $PoolName[0]}Else{$CPoolName = "N/A"}
                If($ProjectName){$CProjectName = $ProjectName[0]}Else{$CProjectName = "N/A"}
                $postParams = "[`"" + $CFullPath + "`", `"" + $CCloneName + "`"]"
				Write-Debug $postParams
                $url = "https://$CurrentArray/zebi/api/$APIVer/getProjectCloneStatus"
                $CloneStatus = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
                If($CloneStatus){$CStatusReport = $StatusDescription[$CloneStatus.projectCloneState]}Else{$CStatusReport = "Unavailable"}
                $EachClone = New-Object -TypeName PSObject
                $EachClone | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                $EachClone | Add-Member -Type NoteProperty -Name PoolName -Value $CPoolName
                $EachClone | Add-Member -Type NoteProperty -Name ProjectName -Value $CProjectName
                $EachClone | Add-Member -Type NoteProperty -Name SnapFullPath -Value $CFullPath
                $EachClone | Add-Member -Type NoteProperty -Name CloneType -Value "Project"
                $EachClone | Add-Member -Type NoteProperty -Name CloneName -Value $CCloneName
                $EachClone | Add-Member -Type NoteProperty -Name FailedSubClones -Value $CloneStatus.failedSubProjects
                $EachClone | Add-Member -Type NoteProperty -Name TotalClonesCreated -Value $CloneStatus.totalSubProjects
                $EachClone | Add-Member -Type NoteProperty -Name CurrentProjectCloneStatus -Value $CStatusReport
                $CreateProjectCloneStatusReport += $EachClone
            }
    }
    End{
        Write-Output $CreateProjectCloneStatusReport
        If ($Array -and $ArrayUserName -and $ArrayPassword){
            $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            $Global:ArrayTable = @()
            $Global:ArrayTable = $NewCred
        }
    }
}
function Remove-IntelliFlashSnap {
    [CmdletBinding()]
	Param (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$Array,
		[Parameter()]
		[String[]]$ArrayUserName,
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
		[Switch[]]$Recursive,
        [Parameter()]
		[Switch]$RecursiveAll,
        [Parameter()]
		[Switch]$Force,
		[Parameter(ValueFromPipelineByPropertyName=$True)]
		[String[]]$LocalSnap
        
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
        CLV SnapDeleteReport -EA SilentlyContinue
        $SnapDeleteReport = @()
        If($ShareName -and $LUNName){
            Write-Host "You have tried to pass both a LUN name and Share name in the same command." -ForegroundColor yellow -BackgroundColor Black
            Write-Host "This is unsupported." -ForegroundColor yellow -BackgroundColor Black
            Break
        }
        $StatusDescription = ("Success","Partial","Failure")
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
                If($CSnapName -like "*Replica*"){$CLocal = "Replica"}Else{$CLocal = "Local"}
				If($LocalSnap -eq "False"){$CLocal = "Replica"} 
                If ($Recursive){
                    If ($Recursive[0]){$CRecursive = "true"}Else{$CRecursive = "false"}
                    }Else{
                    If ($RecursiveAll){$CRecursive = "true"}Else{$CRecursive = "false"}
                }
                If ($ShareName){
                    $CShareName = $ShareName[0]
                    $CFullPath = "$CPoolName/$CLocal/$CProjectName/$CShareName@$CSnapName"
                    $postParams = "[`"" + $CFullPath + "`",`"" + $CRecursive + "`"]"
					Write-Debug $postParams
                    $SnapType = "Share"
	                $url = "https://$CurrentArray/zebi/api/$APIVer/deleteShareSnapshot"
                }
                If ($LUNName){
                    $CLUNName = $LUNName[0]
                    $CFullPath = "$CPoolName/$CLocal/$CProjectName/$CLUNName@$CSnapName"
                    $postParams = "[`"" + $CFullPath + "`",`"" + $CRecursive + "`"]"
					Write-Debug $postParams
                    $SnapType = "LUN"
	                $url = "https://$CurrentArray/zebi/api/$APIVer/deleteVolumeSnapshot"
                }
                If (!$ShareName -and !$LUNName){
                    $CFullPath = "$CPoolName/$CLocal/$CProjectName@$CSnapName"
                    $postParams = "[`"" + $CFullPath + "`",`"" + $CRecursive + "`"]"
					Write-Debug $postParams
                    $SnapType = "Project"
	                $url = "https://$CurrentArray/zebi/api/$APIVer/deleteProjectSnapshot"
                }
                CLV ConfirmDelete -EA SilentlyContinue
                $title = "Delete Snapshots"
                $message = "Do you want to delete $CurrentArray : $CFullPath ?"
                $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Deletes LUN."
                $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Retains LUN."
                $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
                If (!$Force){$ConfirmDelete = $host.ui.PromptForChoice($title, $message, $options, 1)}Else{$ConfirmDelete = 0}
                If ($ConfirmDelete -eq 0){
                    $CurrentSnapDelete = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
                    If($?){$CurrentSnapDeleteCommandStatus = "True"}Else{$CurrentSnapDeleteCommandStatus = "False"}
                    ForEach($CurrentDelete in $CurrentSnapDelete){
                        $SnapDeleteStatusDescription = $StatusDescription[$CurrentDelete.snapshotDeletionStatus]
                        $EachSnap = New-Object -TypeName PSObject
                        $EachSnap | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                        $EachSnap | Add-Member -Type NoteProperty -Name PoolName -Value $CPoolName
                        $EachSnap | Add-Member -Type NoteProperty -Name ProjectName -Value $CProjectName
                        If ($SnapType -eq "Share"){$EachSnap | Add-Member -Type NoteProperty -Name ShareName -Value $CShareName}
                        If ($SnapType -eq "LUN"){$EachSnap | Add-Member -Type NoteProperty -Name LUNName -Value $CLUNName}
                        $EachSnap | Add-Member -Type NoteProperty -Name SnapName -Value $CSnapName
                        $EachSnap | Add-Member -Type NoteProperty -Name SnapFullPath -Value $CFullPath
                        $EachSnap | Add-Member -Type NoteProperty -Name Recursive -Value $CRecursive
                        $EachSnap | Add-Member -Type NoteProperty -Name DeleteCommandExecuted -Value $CurrentSnapDeleteCommandStatus
                        $EachSnap | Add-Member -Type NoteProperty -Name StatusDescription -Value $SnapDeleteStatusDescription
                        If ($CurrentDelete.deletedList){$EachSnap | Add-Member -Type NoteProperty -Name DeletedSnap -Value $CurrentDelete.deletedList}
                        If ($CurrentDelete.failedToDeleteList){$EachSnap | Add-Member -Type NoteProperty -Name DeletedSnapFailed -Value $CurrentDelete.failedToDeleteList}
                        $SnapDeleteReport += $EachSnap
                    }
                    }Else{
                    $EachSnap = New-Object -TypeName PSObject
                        $EachSnap | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                        $EachSnap | Add-Member -Type NoteProperty -Name PoolName -Value $CPoolName
                        $EachSnap | Add-Member -Type NoteProperty -Name ProjectName -Value $CProjectName
                        If ($SnapType -eq "Share"){$EachSnap | Add-Member -Type NoteProperty -Name ShareName -Value $CShareName}
                        If ($SnapType -eq "LUN"){$EachSnap | Add-Member -Type NoteProperty -Name LUNName -Value $CLUNName}
                        $EachSnap | Add-Member -Type NoteProperty -Name SnapName -Value $CSnapName
                        $EachSnap | Add-Member -Type NoteProperty -Name Recursive -Value $CRecursive
                        $EachSnap | Add-Member -Type NoteProperty -Name SnapFullPath -Value $CFullPath
                        $EachSnap | Add-Member -Type NoteProperty -Name DeleteCommandExecuted -Value "false"
                        $EachSnap | Add-Member -Type NoteProperty -Name StatusDescription -Value "UserAborted"
                        $SnapDeleteReport += $EachSnap
                }
            }
    }
    End{
        Write-Output $SnapDeleteReport
        If ($Array -and $ArrayUserName -and $ArrayPassword){
            $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            $Global:ArrayTable = @()
            $Global:ArrayTable = $NewCred
        }
    }
}
function Push-IntelliFlashNASConfiguration {
    [CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true)]
		[String]$SourceArray,
        [Parameter(Mandatory=$true)]
		[String]$TargetArray,
        [Parameter()]
		[Switch]$Force
    )
    Begin{
        $SrcCred = $global:ArrayTable |Where {$_.Array -eq $SourceArray}|select Cred
        $TgtCred = $global:ArrayTable |Where {$_.Array -eq $TargetArray}|select Cred
        if (!$global:ArrayTable -or !$SrcCred -or !$TgtCred) {Write-Output "You must connect to both the source and target IntelliFlash arrays for this function to work properly"}
    }
    Process{
        Write-progress -activity "Cloning NAS Groups & Users from $SourceArray to $TargetArray" -status "Progress:" -percentcomplete (0)
        $CloneNASGroup = (Get-IntelliFlashNASGroupList|Where {$_.Array -eq $SourceArray})
            ForEach ($NewGroup in $CloneNASGroup){
                $CurrentGroup = $NewGroup.GroupName
                Write-progress -activity "Creating $CurrentGroup on $TargetArray" -status "Progress:" -percentcomplete (0)
                [void](Add-IntelliFlashNASGroup -Array $TargetArray -GroupName $NewGroup.GroupName -GroupID $NewGroup.GroupID)
                Write-progress -activity "Creating $CurrentGroup on $TargetArray" -status "Progress:" -percentcomplete (99)
            }
        Write-progress -activity "Cloning NAS Groups & Users from $SourceArray to $TargetArray" -status "Progress:" -percentcomplete (50)
        $SrcNASUser = (Get-IntelliFlashNASUserList|Where {$_.Array -eq $SourceArray})
        Write-progress -activity "Cloning NAS Groups & Users from $SourceArray to $TargetArray" -status "Progress:" -percentcomplete (75)
        ForEach ($NewUser in $SrcNASUser){
            CLV NewUserPassword -EA SilentlyContinue
            CLV ConfirmPWD -EA SilentlyContinue
            CLV CurrentNewUser -EA SilentlyContinue
            CLV NewUserPassword -EA SilentlyContinue
            $CurrentNewUser = $NewUser.UserName
            Write-progress -activity "Creating $CurrentNewUser on $TargetArray" -status "Progress:" -percentcomplete (0)
            If ($Force){
                $Null = [void](Add-IntelliFlashNASUser -Array $TargetArray -UserName $NewUser.UserName -UserID $NewUser.UserID -GroupName $NewUser.GroupName -UserPassword "TEMP")
                Write-Host "$CurrentNewUser password is set to TEMP on $TargetArray" -BackgroundColor Black -ForegroundColor Yellow
                }Else{
                    $title = "New User Password"
                    $message = "Do you want to set a password for $CurrentNewUser ?"
                    $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Customize Password."
                    $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Use Default Password."
                    $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
                    $ConfirmPWD = $host.ui.PromptForChoice($title, $message, $options, 1)
                    If ($ConfirmPWD -eq 0){
                        $NewUserPassword = Read-Host -Prompt 'Please enter the new password' -AsSecureString
                        $Null = [void](Add-IntelliFlashNASUser -Array $TargetArray -UserName $NewUser.UserName -UserID $NewUser.UserID -GroupName $NewUser.GroupName -UserPassword $NewUserPassword)
                        }Else{
                        $Null = [void](Add-IntelliFlashNASUser -Array $TargetArray -UserName $NewUser.UserName -UserID $NewUser.UserID -GroupName $NewUser.GroupName -UserPassword "TEMP")
                        Write-Host "$CurrentNewUser password is set to TEMP on $TargetArray" -BackgroundColor Black -ForegroundColor Yellow
                        }
            }
            Write-progress -activity "Creating $CurrentNewUser on $TargetArray" -status "Progress:" -percentcomplete (99)   
        }
    }
    End{
        Write-Host "-Push complete-"
    }
}
function Copy-IntelliFlashDataset {
    [CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[String]$Array,
		[Parameter()]
		[String]$ArrayUserName,
		[Parameter()]
		[String]$ArrayPassword,
		[Parameter(Mandatory=$true)]
		[String]$SourcePoolName,
  		[Parameter(Mandatory=$true)]
		[String]$SourceProjectName,
        [Parameter(Mandatory=$true)]
		[String]$SourceDatasetName,
## 		[Parameter()]
##		[String]$SourceSnapshotName,
##---- Source Snapshot will be released with the next version of IntelliFlash OS.
##
##
		[Parameter(Mandatory=$true)]
		[String]$TargetPoolName,
		[Parameter(Mandatory=$true)]
		[String]$TargetProjectName,
		[Parameter(Mandatory=$true)]
		[String]$TargetDatasetName,
		[Parameter(Mandatory=$true)]
		[Single]$NumberOfCopies,
		[Parameter()]
		[Single]$SetStartNumber,
		[Parameter()]
		[String]$TargetArray,
		[Parameter()]
		[Switch]$Force
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
		if ($NumberOfCopies -gt 1 -and !$SetStartNumber) {
			Write-Host "You must set the SetStartNumber if you want more than 1 copy." -BackgroundColor White -ForegroundColor Red
			Pause
			Break 1
		}
		if ($NumberOfCopies -eq 1 ) {
			$SetStartNumber = 0
			$SetEndNumber = 0
		}
		if ($NumberOfCopies -gt 1 ) {
			$SetEndNumber = $SetStartNumber + $NumberOfCopies - 1
		}
		$CopyStartReport = @()
	}
	Process{
        $IntelliFlashVersion = $global:ArrayTable |Where {$_.Array -eq $Array}|select IntelliFlashVersion
        $IntelliFlashVersion = [double]$IntelliFlashVersion.IntelliFlashVersion.Substring(0,3)
        If ($IntelliFlashVersion -lt 3.7){
			Write-Host "The IntelliFlash Array must be 3.7 for the copy command to function." -BackgroundColor White -ForegroundColor Red
			pause
			Break 1
			}Else{
			$APIVer = "v2"
		}
		$Cred = $global:ArrayTable |Where {$_.Array -eq $Array}|select Cred
        $Cred = $Cred.Cred
        $url = "https://$Array/zebi/api/$APIVer/copyDataset"
	    $postParams = "[{`"poolName`":`"" + $SourcePoolName + "`", `"projectName`":`"" + $SourceProjectName + "`", `"snapshot`":`"" + $SourceSnapshotName + "`", `"subProjectName`":`"" + $SourceDatasetName + "`"}, {`"subProjectNameNumberStart`": " + $SetStartNumber + ", `"poolName`":`"" + $TargetPoolName + "`", `"projectName`":`"" + $TargetProjectName + "`", `"subProjectNamePrefix`":`"" + $TargetDatasetName + "`", `"hostName`":`"" + $TargetArray + "`", `"subProjectNameWildcard`":`"`", `"subProjectNameNumberEnd`": " + $SetEndNumber + "}]"
		Write-Debug $postParams
		If (!$Force){
			if (!$TargetArray){$TargetArray = $Array}
			Write-Host "`n`nThe following copies will be created: `n"
			Write-Host "Target Array: $TargetArray"
			Write-Host "Target Pool: $TargetPoolName"
			Write-Host "Target Project: $TargetProjectName`n"
			if ($NumberOfCopies -gt 1){
				$Counter = $SetStartNumber - 1
				Do{
					$Counter++
					$NewDataset = $TargetDatasetName + $Counter.ToString()
					Write-Host "New Dataset: $NewDataset"
					} While ($Counter -ne $SetEndNumber)
				}Else{
				Write-Host "New Dataset: $TargetDatasetName"
			}
	        $title = "Create Copies?"
            $message = "If the target project does not exist, it will be created. Do you want to create the copies above?"
            $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Create Copies."
            $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Abandon Copies."
            $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
            $ConfirmCopy = $host.ui.PromptForChoice($title, $message, $options, 1)
            If ($ConfirmCopy -eq 1){
				Write-Host "`nCopy abandoned by user!`n" -BackgroundColor Black -ForegroundColor Yellow
				break
			}
		}
		
		$DatasetCopy = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams

        if (!$TargetArray){$TargetArray = $SourceArray}
		if (!$SourceSnapshotName){$SourceSnapshotName = "N/A"}
		$EachCopy = New-Object -TypeName PSObject
        $EachCopy | Add-Member -Type NoteProperty -Name SourceArray -Value $Array
        $EachCopy | Add-Member -Type NoteProperty -Name SourcePoolName -Value $SourcePoolName
        $EachCopy | Add-Member -Type NoteProperty -Name SourceProjectName -Value $SourceProjectName
		$EachCopy | Add-Member -Type NoteProperty -Name SourceDatasetName -Value $SourceDatasetName
		$EachCopy | Add-Member -Type NoteProperty -Name SourceSnapshot -Value $SourceSnapshotName
        $EachCopy | Add-Member -Type NoteProperty -Name TargetArray -Value $TargetArray
		$EachCopy | Add-Member -Type NoteProperty -Name TargetPoolName -Value $TargetPoolName
        $EachCopy | Add-Member -Type NoteProperty -Name TargetProjectName -Value $TargetProjectName
		$EachCopy | Add-Member -Type NoteProperty -Name TargetDatasetName -Value $TargetDatasetName
		$EachCopy | Add-Member -Type NoteProperty -Name NumberOfCopies -Value $NumberOfCopies
        $EachCopy | Add-Member -Type NoteProperty -Name CopyGUID -Value $DatasetCopy
        $CopyStartReport += $EachCopy
	}
    End{
        $CopyStartReport
		Write-Host "`n`nTo stop this job, you can run: Stop-IntelliFlashCopy -Array $Array -CopyGUID $DatasetCopy`n`n"
		if (!$global:TegileCopyTable) {$global:TegileCopyTable = @()}
		If ($CopyStartReport){$global:TegileCopyTable += $CopyStartReport}
		If ($Array -and $ArrayUserName -and $ArrayPassword){
            $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            $Global:ArrayTable = @()
            $Global:ArrayTable = $NewCred
        }
    }
}
function Get-IntelliFlashCopyStatus {
    [CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[String]$Array,
		[Parameter()]
		[String]$ArrayUserName,
		[Parameter()]
		[String]$ArrayPassword,
		[Parameter()]
		[String]$CopyGUID,
		[Parameter()]
		[Switch]$All,
		[Parameter()]
		[Switch]$Running
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
		if (!$CopyGUID -and !$global:TegileCopyTable -and !$All -and !$Running) {
			Write-Host "There are no copy jobs saved in your current session. Please specify the Copy GUID you'd like to check. You can also use the -All or -Running switches to check for recent and running copy jobs." -BackgroundColor White -ForegroundColor Red
			Pause
			Break 1
		}
	}
	Process{
        $IntelliFlashVersion = $global:ArrayTable |Where {$_.Array -eq $Array}|select IntelliFlashVersion
		If (!$IntelliFlashVersion){
			Write-Host "You are not connected to $Array. You must connect to the array in order to check for copy status." -BackgroundColor Black -ForegroundColor Red
			Break
		}
        $IntelliFlashVersion = [double]$IntelliFlashVersion.IntelliFlashVersion.Substring(0,3)
        If ($IntelliFlashVersion -lt 3.7){
			Write-Host "The IntelliFlash Array must be 3.7 for the get copy status command to function. $Array will not be checked." -BackgroundColor White -ForegroundColor Red
			Break
			}Else{
			$APIVer = "v2"
		}
		If ($All){
			$Cred = $global:ArrayTable |Where {$_.Array -eq $Array}|select Cred
	        $Cred = $Cred.Cred
	        $url = "https://$Array/zebi/api/$APIVer/listAllCopyOperations"
			$postParams = "[]"
			Write-Debug $postParams	
			$CurrentCopyReport = @()
			$CopyStatus = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
			If (!$CopyStatus){Write-Host "No copy status available."; break}
			ForEach ($GUID in $CopyStatus){
				$postParams = "[`"$GUID`"]"
				Write-Debug $postParams
				$url = "https://$Array/zebi/api/$APIVer/getCopyStatus"
			    $CopyStatus = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
				$EachCopy = New-Object -TypeName PSObject
	        	$EachCopy | Add-Member -Type NoteProperty -Name Status -Value $CopyStatus.status
				$EachCopy | Add-Member -Type NoteProperty -Name ErrorCode -Value $CopyStatus.errorCode
	        	$EachCopy | Add-Member -Type NoteProperty -Name TotalCopiesToCreate -Value $CopyStatus.numberOfCopies
	        	$EachCopy | Add-Member -Type NoteProperty -Name NumberOfCopiesCompleted -Value $CopyStatus.completedCopies
				$EachCopy | Add-Member -Type NoteProperty -Name SourcArray -Value $Array
				$EachCopy | Add-Member -Type NoteProperty -Name CopyList -Value $CopyStatus.allDatasets
				$EachCopy | Add-Member -Type NoteProperty -Name CompletedCopies -Value $CopyStatus.completedDatasets
	        	$EachCopy | Add-Member -Type NoteProperty -Name PendingCopies -Value $CopyStatus.pendingDatasets
				$EachCopy | Add-Member -Type NoteProperty -Name PercentComplete -Value $CopyStatus.percentComplete
	        	$EachCopy | Add-Member -Type NoteProperty -Name CopyStartTime -Value $CopyStatus.startTime
				$EachCopy | Add-Member -Type NoteProperty -Name CopyEndTime -Value $CopyStatus.endTime
				$EachCopy | Add-Member -Type NoteProperty -Name CopyGUID -Value $GUID
				$CurrentCopyReport += $EachCopy
			}
			$CurrentCopyReport
		}
		If ($Running){
			$Cred = $global:ArrayTable |Where {$_.Array -eq $Array}|select Cred
	        $Cred = $Cred.Cred
	        $url = "https://$Array/zebi/api/$APIVer/listRunningCopyOperations"
			$postParams = "[]"
			Write-Debug $postParams	
			$CurrentCopyReport = @()
			$CopyStatus = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
			If (!$CopyStatus){Write-Host "No copy jobs currently running on $Array."}Else{
				ForEach ($GUID in $CopyStatus){
					$postParams = "[`"$GUID`"]"
					Write-Debug $postParams
					$url = "https://$Array/zebi/api/$APIVer/getCopyStatus"
				    $CopyStatus = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
					$EachCopy = New-Object -TypeName PSObject
		        	$EachCopy | Add-Member -Type NoteProperty -Name Status -Value $CopyStatus.status
					$EachCopy | Add-Member -Type NoteProperty -Name ErrorCode -Value $CopyStatus.errorCode
		        	$EachCopy | Add-Member -Type NoteProperty -Name TotalCopiesToCreate -Value $CopyStatus.numberOfCopies
		        	$EachCopy | Add-Member -Type NoteProperty -Name NumberOfCopiesCompleted -Value $CopyStatus.completedCopies
					$EachCopy | Add-Member -Type NoteProperty -Name SourceArray -Value $Array
					$EachCopy | Add-Member -Type NoteProperty -Name CopyList -Value $CopyStatus.allDatasets
					$EachCopy | Add-Member -Type NoteProperty -Name CompletedCopies -Value $CopyStatus.completedDatasets
		        	$EachCopy | Add-Member -Type NoteProperty -Name PendingCopies -Value $CopyStatus.pendingDatasets
					$EachCopy | Add-Member -Type NoteProperty -Name PercentComplete -Value $CopyStatus.percentComplete
		        	$EachCopy | Add-Member -Type NoteProperty -Name CopyStartTime -Value $CopyStatus.startTime
					$EachCopy | Add-Member -Type NoteProperty -Name CopyEndTime -Value $CopyStatus.endTime
					$EachCopy | Add-Member -Type NoteProperty -Name CopyGUID -Value $GUID
					$CurrentCopyReport += $EachCopy
				}
			}
			$CurrentCopyReport
		}
		If (!$All -and !$Running){
			$CopyCheckGUIDs = @()
			$CachedCopyGUIDs = @()
			$CachedCopyGUIDs = $global:TegileCopyTable.CopyGUID
			if ($CopyGUID -and $global:TegileCopyTable) {
				ForEach ($i in $CachedCopyGUIDs){
					$CopyCheckGUIDs += $i
				}
				$CopyCheckGUIDs += $CopyGUID
			}
			if ($CopyGUID -and !$global:TegileCopyTable) {$CopyCheckGUIDs = $CopyGUID}
			if (!$CopyGUID -and $global:TegileCopyTable) {$CopyCheckGUIDs = $global:TegileCopyTable.CopyGUID}
			
			$CopyCheckGUIDs = $CopyCheckGUIDs | Sort | Select -Unique
			$CurrentCopyReport = @()
			$Cred = $global:ArrayTable |Where {$_.Array -eq $Array}|select Cred
	        $Cred = $Cred.Cred
	        $url = "https://$Array/zebi/api/$APIVer/getCopyStatus"
			ForEach ($GUIDReport in $CopyCheckGUIDs){
				$GUID = $GUIDReport
				$postParams = "[`"$GUID`"]"
				Write-Debug $postParams
			    $CopyStatus = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
				$EachCopy = New-Object -TypeName PSObject
		        $EachCopy | Add-Member -Type NoteProperty -Name Status -Value $CopyStatus.status
				$EachCopy | Add-Member -Type NoteProperty -Name ErrorCode -Value $CopyStatus.errorCode
		        $EachCopy | Add-Member -Type NoteProperty -Name TotalCopiesToCreate -Value $CopyStatus.numberOfCopies
		        $EachCopy | Add-Member -Type NoteProperty -Name NumberOfCopiesCompleted -Value $CopyStatus.completedCopies
				$EachCopy | Add-Member -Type NoteProperty -Name CopyList -Value $CopyStatus.allDatasets
				$EachCopy | Add-Member -Type NoteProperty -Name CompletedCopies -Value $CopyStatus.completedDatasets
		        $EachCopy | Add-Member -Type NoteProperty -Name PendingCopies -Value $CopyStatus.pendingDatasets
				$EachCopy | Add-Member -Type NoteProperty -Name PercentComplete -Value $CopyStatus.percentComplete
		        $EachCopy | Add-Member -Type NoteProperty -Name CopyStartTime -Value $CopyStatus.startTime
				$EachCopy | Add-Member -Type NoteProperty -Name CopyEndTime -Value $CopyStatus.endTime
				$EachCopy | Add-Member -Type NoteProperty -Name CopyGUID -Value $GUID
				$CurrentCopyReport += $EachCopy
			}
		$CurrentCopyReport
		}
	}
    End{
		If ($Array -and $ArrayUserName -and $ArrayPassword){
            $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            $Global:ArrayTable = @()
            $Global:ArrayTable = $NewCred
        }
    }
}
function Clear-IntelliFlashCopyStatus {
	[CmdletBinding()]
		Param(
			[Parameter()]
			[Switch]$All,
			[Parameter()]
			[String]$CopyGUID
		)
	if ($All -and $CopyGUID){Write-Host "You must specify a Copy GUID or use the -All switch, not both."; Break 1}
	if (!$global:TegileCopyTable) {Write-Host "There are no copy entries to clear."; Break 1}
	if ($All){
		Write-Host "Clearing the following copy entries: "
		$global:TegileCopyTable.CopyGUID
		clv TegileCopyTable -Scope global
		break 0
	}
	if ($CopyGUID){
		$NewTegileCopyTable =@()
		ForEach	($i in $global:TegileCopyTable){
			If ($i.CopyGUID -ne $CopyGUID){
				$NewTegileCopyTable += $i
				}Else{
				Write-Host $i.CopyGUID has been removed from the cached copy jobs.
			}
		}
	$global:TegileCopyTable = $NewTegileCopyTable
	}
	if (!$CopyGUID -and !$All){
		Write-Host "You must either use the -All switch or the -CopyGuid switch."
	}
}
function Stop-IntelliFlashCopy {
	[CmdletBinding()]
		Param(
			[Parameter(Mandatory=$True)]
			[String]$Array,
			[Parameter()]
			[Switch]$All,
			[Parameter()]
			[String]$CopyGUID,
			[Parameter()]
			[Switch]$Force
		)
	$IntelliFlashVersion = $global:ArrayTable |Where {$_.Array -eq $Array}|select IntelliFlashVersion
		
	If (!$IntelliFlashVersion){
		Write-Host "You are not connected to $Array. You must connect to the array in order to stop a copy." -BackgroundColor Black -ForegroundColor Red
		Break
	}
    $IntelliFlashVersion = [double]$IntelliFlashVersion.IntelliFlashVersion.Substring(0,3)
	If ($IntelliFlashVersion -lt 3.7){
		Write-Host "The IntelliFlash Array must be 3.7 for the abort copy command to function. $Array will not be checked." -BackgroundColor White -ForegroundColor Red
		Break
		}Else{
		$APIVer = "v2"
	}
	
	$Cred = $global:ArrayTable |Where {$_.Array -eq $Array}|select Cred
	$Cred = $Cred.Cred
	if ($All -and $CopyGUID){Write-Host "You must specify a Copy GUID or use the -All switch, not both."; Break}
	if (!$CopyGUID -and !$All){Write-Host "You must either use the -All switch or the -CopyGuid switch."; Break}
	if ($All){
		$CurrentCopyJobs = (Get-IntelliFlashCopyStatus -Array $Array -Running)
		if ($CurrentCopyJobs -eq "No copy jobs currently running."){Write-Host "There are no jobs currently running on $Array";Break}
		if (!$Force){
			$CurrentCopyJobs
			$title = "Stop All Copy Jobs?"
            $message = "Do you want to stop all these copy jobs?"
            $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Stop Copy Jobs."
            $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Allow Copy Jobs to Continue."
            $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
            $ConfirmCopy = $host.ui.PromptForChoice($title, $message, $options, 1)
            If ($ConfirmCopy -eq 1){Write-Host "`nCopy Jobs Will Continue!`n" -BackgroundColor Black -ForegroundColor Yellow;break}
			If ($ConfirmCopy -eq 0){
				foreach ($GUID in $CurrentCopyJobs){
					$StopCopyGUID = $GUID.CopyGUID
					$url = "https://$Array/zebi/api/$APIVer/abortCopy"
					$postParams = "[`"$StopCopyGUID`"]"
					Write-Debug $postParams
		    		$AbortCopy = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
					$AbortCopy
				}
			}
		}Else{
			foreach ($GUID in $CurrentCopyJobs){
				$StopCopyGUID = $GUID.CopyGUID
				$url = "https://$Array/zebi/api/$APIVer/abortCopy"
				$postParams = "[`"$StopCopyGUID`"]"
				Write-Debug $postParams
				Write-Host "Stopping: $StopCopyGUID"
		    	$AbortCopy = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
				$AbortCopy
			}
		}
	}
	if ($CopyGUID){
		$CurrentCopyJobs = (Get-IntelliFlashCopyStatus -Array $Array -Running)
		$CheckGUID = ($CurrentCopyJobs | Where {$_.CopyGUID -like "*$CopyGUID*"})
		If (!$CheckGUID){Write-Host "`n`nThere is no copy job currently running with GUID: $CopyGUID`n`n" -BackgroundColor Black -ForegroundColor Yellow;break}
		if (!$Force){
			$CheckGUID
			$title = "Stop Copy Job?"
            $message = "Do you want to stop the above copy job?"
            $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Stop Copy Job."
            $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Allow Copy Job to Continue."
            $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
            $ConfirmCopy = $host.ui.PromptForChoice($title, $message, $options, 1)
            If ($ConfirmCopy -eq 1){Write-Host "`nCopy Job Will Continue!`n" -BackgroundColor Black -ForegroundColor Yellow;break}
			If ($ConfirmCopy -eq 0){
				$StopCopyGUID = $CheckGUID.CopyGUID
				$url = "https://$Array/zebi/api/$APIVer/abortCopy"
				$postParams = "[`"$StopCopyGUID`"]"
				Write-Debug $postParams
				Write-Host "Stopping: $StopCopyGUID"
		    	$AbortCopy = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
				$AbortCopy
			}
		}Else{
		$StopCopyGUID = $CheckGUID.CopyGUID
		$url = "https://$Array/zebi/api/$APIVer/abortCopy"
		$postParams = "[`"$StopCopyGUID`"]"
		Write-Debug $postParams
		Write-Host "Stopping: $StopCopyGUID"
    	$AbortCopy = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
		$AbortCopy
		}
	}
}
function Get-IntelliFlashCopyList {
    [CmdletBinding()]
	Param (
		[Parameter()]
		[String]$Array,
		[Parameter()]
		[String]$ArrayUserName,
		[Parameter()]
		[String]$ArrayPassword,
		[Parameter()]
		[Switch]$Running
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
        ForEach ($Array in $global:ArrayTable.Array){
            Write-progress -activity "Collecting Copy Jobs from $Array" -status "Progress:" -percentcomplete ($p/$global:ArrayTable.count*100)
	        If ($Running){
				Get-IntelliFlashCopyStatus -Array $Array -Running
				}Else{
				Get-IntelliFlashCopyStatus -Array $Array -All
			}
        $p++
        }
    }
    End{
        Write-progress -activity "Collecting Copy Jobs from $Array" -Completed
        If ($Array -and $ArrayUserName -and $ArrayPassword){
            $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            $Global:ArrayTable = @()
            $Global:ArrayTable = $NewCred
        }
    }   
}
function Remove-IntelliFlashProject {
    [CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$Array,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$PoolName,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$ProjectName,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
		[Switch]$Force,
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
        $LUNReport = @()
    }
    Process{
        ForEach ($ArrayTgt in $global:ArrayTable.Array){
            If ($ArrayTgt -eq $Array){
                $Cred = $global:ArrayTable |Where {$_.Array -eq $ArrayTgt}|select Cred
                $Cred = $Cred.Cred
                $IntelliFlashVersion = $global:ArrayTable |Where {$_.Array -eq $ArrayTgt}|select IntelliFlashVersion
                $IntelliFlashVersion = [double]$IntelliFlashVersion.IntelliFlashVersion.Substring(0,3)
                If ($IntelliFlashVersion -lt 3.5){$APIVer = "v1"}else{$APIVer = "v2"}
                $DataSetPath = "$PoolName/Local/$ProjectName"
                $url = "https://$ArrayTgt/zebi/api/$APIVer/deleteProject"
                $postParams = "[`"" + $DataSetPath + "`"]"
				Write-Debug $postParams
	            If ($Force){
                    $LUNDelete = Invoke-WebRequest -Uri $url -Method Post -ContentType "application/json" -Header $Cred -Body $postParams
                    If ($?){
                        $EachLUN = New-Object -TypeName PSObject
                        $EachLUN | Add-Member -Type NoteProperty -Name Array -Value $ArrayTgt
                        $EachLUN | Add-Member -Type NoteProperty -Name DataSetPath -Value $DataSetPath
                        $EachLUN | Add-Member -Type NoteProperty -Name Status -Value "True"
                        $EachLUN | Add-Member -Type NoteProperty -Name Deleted -Value "True"
                        $LUNReport += $EachLUN
                        } Else {
                        $EachLUN = New-Object -TypeName PSObject
                        $EachLUN | Add-Member -Type NoteProperty -Name Array -Value $ArrayTgt
                        $EachLUN | Add-Member -Type NoteProperty -Name DataSetPath -Value $DataSetPath
                        $EachLUN | Add-Member -Type NoteProperty -Name Status -Value "False"
                        $EachLUN | Add-Member -Type NoteProperty -Name Deleted -Value "False"
                        $LUNReport += $EachLUN
                    }
                }
                    Else{
                    CLV ConfirmDelete -EA SilentlyContinue
                    $title = "Delete Projects"
                    $message = "Do you want to delete $ArrayTgt : $DataSetPath ?"
                    $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Deletes LUN."
                    $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Retains LUN."
                    $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
                    $ConfirmDelete = $host.ui.PromptForChoice($title, $message, $options, 1)
                    If ($ConfirmDelete -eq 0){
                        $LUNDelete = Invoke-WebRequest -Uri $url -Method Post -ContentType "application/json" -Header $Cred -Body $postParams
                        If ($?){
                            $EachLUN = New-Object -TypeName PSObject
                            $EachLUN | Add-Member -Type NoteProperty -Name Array -Value $ArrayTgt
                            $EachLUN | Add-Member -Type NoteProperty -Name DataSetPath -Value $DataSetPath
                            $EachLUN | Add-Member -Type NoteProperty -Name Status -Value "True"
                            $EachLUN | Add-Member -Type NoteProperty -Name Deleted -Value "True"
                            $LUNReport += $EachLUN
                            } Else {
                            $EachLUN = New-Object -TypeName PSObject
                            $EachLUN | Add-Member -Type NoteProperty -Name Array -Value $ArrayTgt
                            $EachLUN | Add-Member -Type NoteProperty -Name DataSetPath -Value $DataSetPath
                            $EachLUN | Add-Member -Type NoteProperty -Name Status -Value "False"
                            $EachLUN | Add-Member -Type NoteProperty -Name Deleted -Value "False"
                            $LUNReport += $EachLUN
                        }
                        }Else{
                        $EachLUN = New-Object -TypeName PSObject
                        $EachLUN | Add-Member -Type NoteProperty -Name Array -Value $ArrayTgt
                        $EachLUN | Add-Member -Type NoteProperty -Name DataSetPath -Value $DataSetPath
                        $EachLUN | Add-Member -Type NoteProperty -Name Status -Value "False"
                        $EachLUN | Add-Member -Type NoteProperty -Name Deleted -Value "False"
                        $LUNReport += $EachLUN
                    }
                }
            }
        } 
    }
    End{
        If ($Array -and $ArrayUserName -and $ArrayPassword){
            $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            $Global:ArrayTable = @()
            $Global:ArrayTable = $NewCred
        }	
        Write-Output $LUNReport
    }
}
function Set-IntelliFlashShareProperty {
    [CmdletBinding()]
	Param (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$Array,
		[Parameter()]
		[String[]]$ArrayUserName,
		[Parameter()]
		[String[]]$ArrayPassword,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$PoolName,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$ProjectName,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$ShareName,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$FullPath,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[Switch[]]$SMBEnabled,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$DisplayName,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[Switch[]]$GuestAccess
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
    CLV SnapReport -EA SilentlyContinue
    $ShareSetReport = @()
    $RUNDATETIME = Get-Date -UFormat "%Y%m%d%H%M%S"
    }
    Process{
            ForEach($CurrentArray in $Array){
                $Cred = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select Cred
                $Cred = $Cred.Cred
                $IntelliFlashVersion = $global:ArrayTable |Where {$_.Array -eq $CurrentArray}|select IntelliFlashVersion
                $IntelliFlashVersion = [double]$IntelliFlashVersion.IntelliFlashVersion.Substring(0,3)
                If ($IntelliFlashVersion -lt 3.5){$APIVer = "v1"}else{$APIVer = "v2"}
                $url = "https://$CurrentArray/zebi/api/$APIVer/setSMBSharingOnShare"
                $CShareName = $ShareName[0]
                $CPoolName = $PoolName[0]
                $CProjectName = $ProjectName[0]
                $CFullPath = $FullPath[0]
                $CSMBEnabled = $SMBEnabled[0]
                $CDisplayName = $DisplayName[0]
                $CGuestAccess = $GuestAccess[0]
                If ($CSMBEnabled){$CSMBEnabled = "true"}Else{$CSMBEnabled = "false"}
                If ($CGuestAccess){$CGuestAccess = "true"}Else{$CGuestAccess = "false"}
                $postParams = "[`"" + $CFullPath + "`", $CSMBEnabled, `"" + $CDisplayName + "`", $CGuestAccess]"
				Write-Debug $postParams
	            $SetShareProperty = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
                If($?){$ShareSetStatus = "True"}Else{$ShareSetStatus = "False"} 
                $EachShareSet = New-Object -TypeName PSObject
                $EachShareSet | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                $EachShareSet | Add-Member -Type NoteProperty -Name PoolName -Value $CPoolName
                $EachShareSet | Add-Member -Type NoteProperty -Name ProjectName -Value $CProjectName
                $EachShareSet | Add-Member -Type NoteProperty -Name ShareName -Value $CShareName
                $EachShareSet | Add-Member -Type NoteProperty -Name SMBEnabled -Value $CSMBEnabled
                $EachShareSet | Add-Member -Type NoteProperty -Name DisplayName -Value $CDisplayName
                $EachShareSet | Add-Member -Type NoteProperty -Name GuestAccess -Value $CGuestAccess
                $EachShareSet | Add-Member -Type NoteProperty -Name SetSuccessful -Value $ShareSetStatus
                $ShareSetReport += $EachShareSet
            }
    }
    End{
        Write-Output $ShareSetReport
        If ($Array -and $ArrayUserName -and $ArrayPassword){
            $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            $Global:ArrayTable = @()
            $Global:ArrayTable = $NewCred
        }
    }
}
function Add-IntelliFlashProjectLUNMapping {
    [CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$Array,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$PoolName,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$ProjectName,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$InitiatorGroup,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$TargetGroup,
        [Parameter()]
        [Switch]$ReadOnlyMapping,
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
	        $url = "https://$CurrentArray/zebi/api/$APIVer/createMappingForProject"
	        $CurrentInitGroup = $InitiatorGroup[$i]
            $CurrentTgtGroup = $TargetGroup[$i]
            $CurrentPool = $PoolName[$i]
            $CurrentProject = $ProjectName[$i]
            If ($ReadOnlyMapping){$CurrentReadOnlyMapping = "true"}Else{$CurrentReadOnlyMapping = "false"}
			$DataSetPath = "$CurrentPool/Local/$CurrentProject"
            $postParams = "[`"" + $DataSetPath + "`", " + "`"" + $CurrentInitGroup +"`", " + "`"" + $CurrentTgtGroup + "`",$CurrentReadOnlyMapping]"
			Write-Debug $postParams
	        $AddMapping = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
            If ($AddMapping -eq 0){
                $EachMap = New-Object -TypeName PSObject
                $EachMap | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                $EachMap | Add-Member -Type NoteProperty -Name PoolName -Value $CurrentPool
                $EachMap | Add-Member -Type NoteProperty -Name ProjectName -Value $CurrentProject
                $EachMap | Add-Member -Type NoteProperty -Name InitiatorGroup -Value $CurrentInitGroup
                $EachMap | Add-Member -Type NoteProperty -Name TargetGroup -Value $CurrentTgtGroup
                $EachMap | Add-Member -Type NoteProperty -Name ReadOnlyMapping -Value $CurrentReadOnlyMapping
                $EachMap | Add-Member -Type NoteProperty -Name Status -Value "True"
                $EachMap | Add-Member -Type NoteProperty -Name MappingCreated -Value "True"
                $AddMappingReport += $EachMap
                }Else{
                $EachMap = New-Object -TypeName PSObject
                $EachMap | Add-Member -Type NoteProperty -Name Array -Value $CurrentArray
                $EachMap | Add-Member -Type NoteProperty -Name PoolName -Value $CurrentPool
                $EachMap | Add-Member -Type NoteProperty -Name ProjectName -Value $CurrentProject
                $EachMap | Add-Member -Type NoteProperty -Name InitiatorGroup -Value $CurrentInitGroup
                $EachMap | Add-Member -Type NoteProperty -Name TargetGroup -Value $CurrentTgtGroup
                $EachMap | Add-Member -Type NoteProperty -Name ReadOnlyMapping -Value $CurrentReadOnlyMapping
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
function Get-IntelliFlashReplicationStatus {
    [CmdletBinding()]
	Param (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$SourceArray,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$SourcePoolName,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$SourceProjectName,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$TargetProjectName,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$TargetDataSetFullPath,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
		[String[]]$LastSnapshotName,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$ReplicationScope,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$TargetArray,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$SourceDataSetFullPath,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$ReplicationIndex,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$ReplicationGUID,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String[]]$TargetPoolName,
		[Parameter()]
		[String]$ArrayUserName,
		[Parameter()]
		[String]$ArrayPassword
    )
    Begin{
        if (!$global:ArrayTable) {
            If ($SourceArray -and $ArrayUserName -and $ArrayPassword){
                CLV CLINE -EA SilentlyContinue
                $CLINE = @()
                $CLINEReport = New-Object -TypeName PSObject
                $CLINEReport | Add-Member -Type NoteProperty -Name Array -Value $SourceArray
                $CLINEReport | Add-Member -Type NoteProperty -Name ArrayUserName -Value $ArrayUserName
                $CLINEReport | Add-Member -Type NoteProperty -Name ArrayPassword -Value $ArrayPassword
                $CLINE = $CLINEReport
                [void]($CLINE |Connect-IntelliFlash)
                }Else{
                [void](Connect-IntelliFlash)
            }
}
        $RepStatusReport = @()
    }
	Process{
	    ForEach ($Array in $SourceArray){
            $Cred = $global:ArrayTable |Where {$_.Array -eq $Array}|select Cred
            $Cred = $Cred.Cred
            $IntelliFlashVersion = $global:ArrayTable |Where {$_.Array -eq $Array}|select IntelliFlashVersion
            $IntelliFlashVersion = [double]$IntelliFlashVersion.IntelliFlashVersion.Substring(0,3)
            If ($IntelliFlashVersion -lt 3.5){$APIVer = "v1"}else{$APIVer = "v2"}
            $url = "https://$Array/zebi/api/$APIVer/getReplicationStatus"
	        $postParams = "[{`"projectName`":`"" + $SourceProjectName + "`",`"remoteProjectName`":`"" + $TargetProjectName + "`",`"remoteBaseDataSetName`":`"" + $TargetDataSetFullPath + "`",`"poolName`":`"" + $SourcePoolName + "`",`"lastSnapshotName`":`"" + $LastSnapshotName + "`",`"scopeOption`":" + $ReplicationScope + ",`"remoteHost`":`"" + $TargetArray + "`",`"baseDataSetName`":`"" + $SourceDataSetFullPath + "`",`"id`":" + $ReplicationIndex + ",`"projectGuid`":`"" + $ReplicationGUID + "`",`"remotePoolName`":`"" + $TargetPoolName + "`"}]"
			Write-Debug $postParams
	        If (!$LastSnapshotName){$LastSnapshotName -eq ""}
            $RepStatus = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
            If ($?){
                $EachRepStatus = New-Object -TypeName PSObject
                $EachRepStatus | Add-Member -Type NoteProperty -Name SourceArray -Value $Array
                $EachRepStatus | Add-Member -Type NoteProperty -Name SourcePoolName -Value $SourcePoolName[0]
                $EachRepStatus | Add-Member -Type NoteProperty -Name SourceProject -Value $SourceProjectName[0]
                $EachRepStatus | Add-Member -Type NoteProperty -Name TargetArray -Value $TargetArray[0]
                $EachRepStatus | Add-Member -Type NoteProperty -Name TargetPoolName -Value $TargetPoolName[0]
                $EachRepStatus | Add-Member -Type NoteProperty -Name TargetProject -Value $TargetProjectName[0]
                $EachRepStatus | Add-Member -Type NoteProperty -Name ReplicationStatus -Value $RepStatus.currentStatus
                $EachRepStatus | Add-Member -Type NoteProperty -Name ReplicationStartTime -Value $RepStatus.startTimestamp
                $EachRepStatus | Add-Member -Type NoteProperty -Name ReplicationCompletedTime -Value $RepStatus.completeTimestamp
                $EachRepStatus | Add-Member -Type NoteProperty -Name ReplicationLastUpdateTime -Value $RepStatus.updateTimestamp
                $EachRepStatus | Add-Member -Type NoteProperty -Name ReplicationDataSent -Value $RepStatus.dataSent
                $EachRepStatus | Add-Member -Type NoteProperty -Name ReplicationCurrentSpeed -Value $RepStatus.sendSpeed
                $EachRepStatus | Add-Member -Type NoteProperty -Name ReplicationJobSize -Value $RepStatus.taskSize
                $EachRepStatus | Add-Member -Type NoteProperty -Name ReplicationComplete -Value $RepStatus.completedTask
                $EachRepStatus | Add-Member -Type NoteProperty -Name GetRepStatusSuccess -Value "True"
                $RepStatusReport += $EachRepStatus
                }Else{
                $EachRepStatus = New-Object -TypeName PSObject
                $EachRepStatus | Add-Member -Type NoteProperty -Name SourceArray -Value $Array
                $EachRepStatus | Add-Member -Type NoteProperty -Name SourcePoolName -Value $SourcePoolName[0]
                $EachRepStatus | Add-Member -Type NoteProperty -Name SourceProject -Value $SourceProjectName[0]
                $EachRepStatus | Add-Member -Type NoteProperty -Name TargetArray -Value $TargetArray[0]
                $EachRepStatus | Add-Member -Type NoteProperty -Name TargetPoolName -Value $TargetPoolName[0]
                $EachRepStatus | Add-Member -Type NoteProperty -Name TargetProject -Value $TargetProjectName[0]
                $EachRepStatus | Add-Member -Type NoteProperty -Name GetRepStatusSuccess -Value "False"
                $RepStatusReport += $EachRepStatus
            }
        }
    }
    End{
        Write-Output $RepStatusReport
        If ($SourceArray -and $ArrayUserName -and $ArrayPassword){
            $NewCred = $global:ArrayTable |Where {$_.Array -ne $Array}
            CLV ArrayTable -Scope Global -EA SilentlyContinue
            $Global:ArrayTable = @()
            $Global:ArrayTable = $NewCred
        }	
    }
}
function Get-IntelliFlashProjectNFSNetworkACL {
    [CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String]$PoolName,
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String]$ProjectName,
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
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
    CLV ProjectNFSNetworkACLReport -EA SilentlyContinue
    $ProjectNFSNetworkACLReport = @()
    }
    Process{
		$Cred = $global:ArrayTable |Where {$_.Array -eq $Array}|select Cred
		$Cred = $Cred.Cred
		$IntelliFlashVersion = $global:ArrayTable |Where {$_.Array -eq $Array}|select IntelliFlashVersion
		$IntelliFlashVersion = [double]$IntelliFlashVersion.IntelliFlashVersion.Substring(0,3)
		If ($IntelliFlashVersion -lt 3.5) {$APIVer = "v1"} else {$APIVer = "v2"}
		$DataSetPath = "$PoolName/Local/$ProjectName"
		Write-Verbose "`nLooking for Network ACL's for Project '$DataSetPath' on Array '$Array'"
		$url = "https://$Array/zebi/api/$APIVer/getNFSNetworkACLsOnProject"
		$postParams = "[`"" + $DataSetPath + "`"]"
		Write-Debug $postParams
		$projectnacl = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
		ForEach ($nacl in $projectnacl){
			$ProjNACL = New-Object -TypeName PSObject
			$ProjNACL | Add-Member -Type NoteProperty -Name Array -Value $Array
			$ProjNACL | Add-Member -Type NoteProperty -Name PoolName -Value $PoolName
			$ProjNACL | Add-Member -Type NoteProperty -Name ProjectName -Value $ProjectName
			$ProjNACL | Add-Member -Type NoteProperty -Name HostType -Value $nacl.hostType
			$ProjNACL | Add-Member -Type NoteProperty -Name NACLHost -Value $nacl.host
			$ProjNACL | Add-Member -Type NoteProperty -Name AccessMode -Value $nacl.accessMode
			$ProjNACL | Add-Member -Type NoteProperty -Name RootAccessForNFS -Value $nacl.rootAccessForNFS
			$ProjectNFSNetworkACLReport += $ProjNACL
		}
    }
    End{
        Write-Output $ProjectNFSNetworkACLReport
    }
}
function Add-IntelliFlashProjectNFSNetworkACL {
    [CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String]$PoolName,
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String]$ProjectName,
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String]$Array,
		[Parameter(Mandatory=$true)]
		[ValidateSet("IP", "FQDN", ignorecase=$False)]
		[String]$HostType,
		[Parameter(Mandatory=$true)]
		[String]$NACLHost,
		[Parameter(Mandatory=$true)]
		[ValidateSet("rw", "ro", ignorecase=$False)]
		[String]$AccessMode,
		[Parameter(Mandatory=$false)]
		[Switch]$RootAccessForNFS,
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
	if ($RootAccessForNFS) {$root = "true"} else {$root = "false"}
    CLV AddProjectNFSNetworkACLReport -EA SilentlyContinue
    $AddProjectNFSNetworkACLReport = @()
    }
    Process{
		$Cred = $global:ArrayTable |Where {$_.Array -eq $Array}|select Cred
		$Cred = $Cred.Cred
		$IntelliFlashVersion = $global:ArrayTable |Where {$_.Array -eq $Array}|select IntelliFlashVersion
		$IntelliFlashVersion = [double]$IntelliFlashVersion.IntelliFlashVersion.Substring(0,3)
		If ($IntelliFlashVersion -lt 3.5) {$APIVer = "v1"} else {$APIVer = "v2"}
		If ($CRootAccessForNFS){$CRootAccessForNFS = "true"} else {$CRootAccessForNFS = "false"}
		$DataSetPath = "$PoolName/Local/$ProjectName"
		Write-Verbose "`nAdding Network ACL's for Project '$DataSetPath' on Array '$Array'"
		$url = "https://$Array/zebi/api/$APIVer/addNFSNetworkACLOnProject"
		$postParams = "[`"" + $DataSetPath + "`", " + "`"" + $HostType +"`", " + "`"" + $NACLHost +"`", " + "`"" + $AccessMode +"`", $root]"
		Write-Debug $postParams
		$AddProjectNACL = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
		If ($AddProjectNACL -eq 0) {
			$AddProjNACL = New-Object -TypeName PSObject
			$AddProjNACL | Add-Member -Type NoteProperty -Name Array -Value $Array
			$AddProjNACL | Add-Member -Type NoteProperty -Name PoolName -Value $PoolName
			$AddProjNACL | Add-Member -Type NoteProperty -Name ProjectName -Value $ProjectName
			$AddProjNACL | Add-Member -Type NoteProperty -Name HostType -Value $HostType
			$AddProjNACL | Add-Member -Type NoteProperty -Name NACLHost -Value $NACLHost
			$AddProjNACL | Add-Member -Type NoteProperty -Name AccessMode -Value $AccessMode
			$AddProjNACL | Add-Member -Type NoteProperty -Name RootAccessForNFS -Value $RootAccessForNFS
			$AddProjNACL | Add-Member -Type NoteProperty -Name Status -Value "True"
			$AddProjNACL | Add-Member -Type NoteProperty -Name NACLadded -Value "True"
			$AddProjectNFSNetworkACLReport += $AddProjNACL
		} else {
			$AddProjNACL = New-Object -TypeName PSObject
			$AddProjNACL | Add-Member -Type NoteProperty -Name Array -Value $Array
			$AddProjNACL | Add-Member -Type NoteProperty -Name PoolName -Value $PoolName
			$AddProjNACL | Add-Member -Type NoteProperty -Name ProjectName -Value $ProjectName
			$AddProjNACL | Add-Member -Type NoteProperty -Name HostType -Value $HostType
			$AddProjNACL | Add-Member -Type NoteProperty -Name NACLHost -Value $NACLHost
			$AddProjNACL | Add-Member -Type NoteProperty -Name AccessMode -Value $AccessMode
			$AddProjNACL | Add-Member -Type NoteProperty -Name RootAccessForNFS -Value $RootAccessForNFS
			$AddProjNACL | Add-Member -Type NoteProperty -Name Status -Value "False"
			$AddProjNACL | Add-Member -Type NoteProperty -Name NACLadded -Value "False"
			$AddProjectNFSNetworkACLReport += $AddProjNACL
		}
    }
    End{
        Write-Output $AddProjectNFSNetworkACLReport
    }
}
function Remove-IntelliFlashProjectNFSNetworkACL {
    [CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String]$PoolName,
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String]$ProjectName,
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String]$Array,
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
		[String]$NACLHost,
		[Parameter()]
        [Switch]$Force,
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
    CLV RemoveProjectNFSNetworkACLReport -EA SilentlyContinue
    $RemoveProjectNFSNetworkACLReport = @()
    }
    Process{
		$Cred = $global:ArrayTable |Where {$_.Array -eq $Array}|select Cred
		$Cred = $Cred.Cred
		$IntelliFlashVersion = $global:ArrayTable |Where {$_.Array -eq $Array}|select IntelliFlashVersion
		$IntelliFlashVersion = [double]$IntelliFlashVersion.IntelliFlashVersion.Substring(0,3)
		If ($IntelliFlashVersion -lt 3.5) {$APIVer = "v1"} else {$APIVer = "v2"}
		$DataSetPath = "$PoolName/Local/$ProjectName"
		$ExistingNACL = Get-IntelliFlashProjectNFSNetworkACL -PoolName $PoolName -ProjectName $ProjectName -Array $Array | Where {($_.NACLHost -eq "$NACLHost")}
		$HostType = $ExistingNACL.HostType
		Write-Verbose "`nRemoving Network ACL's for Project '$DataSetPath' on Array '$Array'"
		$url = "https://$Array/zebi/api/$APIVer/removeNFSNetworkACLOnProject"
		$postParams = "[`"" + $DataSetPath + "`", " + "`"" + $HostType +"`", " + "`"" + $NACLHost +"`"]"
		Write-Debug $postParams
		If ($ExistingNACL) {
			If ($Force) {
				$RemoveProjectNACL = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
				If ($RemoveProjectNACL -eq 0) {
					$RemoveProjNACL = New-Object -TypeName PSObject
					$RemoveProjNACL | Add-Member -Type NoteProperty -Name Array -Value $Array
					$RemoveProjNACL | Add-Member -Type NoteProperty -Name PoolName -Value $PoolName
					$RemoveProjNACL | Add-Member -Type NoteProperty -Name ProjectName -Value $ProjectName
					$RemoveProjNACL | Add-Member -Type NoteProperty -Name HostType -Value $HostType
					$RemoveProjNACL | Add-Member -Type NoteProperty -Name NACLHost -Value $NACLHost
					$RemoveProjNACL | Add-Member -Type NoteProperty -Name Status -Value "True"
					$RemoveProjNACL | Add-Member -Type NoteProperty -Name NACLremoved -Value "True"
					$RemoveProjectNFSNetworkACLReport += $RemoveProjNACL
				} else {
					$RemoveProjNACL = New-Object -TypeName PSObject
					$RemoveProjNACL | Add-Member -Type NoteProperty -Name Array -Value $Array
					$RemoveProjNACL | Add-Member -Type NoteProperty -Name PoolName -Value $PoolName
					$RemoveProjNACL | Add-Member -Type NoteProperty -Name ProjectName -Value $ProjectName
					$RemoveProjNACL | Add-Member -Type NoteProperty -Name HostType -Value $HostType
					$RemoveProjNACL | Add-Member -Type NoteProperty -Name NACLHost -Value $NACLHost
					$RemoveProjNACL | Add-Member -Type NoteProperty -Name Status -Value "False"
					$RemoveProjNACL | Add-Member -Type NoteProperty -Name NACLremoved -Value "False"
					$RemoveProjectNFSNetworkACLReport += $RemoveProjNACL
				}
			} else {
				CLV ConfirmRemove -EA SilentlyContinue
				$title = "Remove NACL"
				$message = "Do you want to delete NACL '$HostType : $NACLHost' from '$DataSetPath' ?"
				$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Removes NACL."
				$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Retains NACL."
				$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
				$ConfirmRemove = $host.ui.PromptForChoice($title, $message, $options, 1)
				If ($ConfirmRemove -eq 0) {
					$RemoveProjectNACL = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers $Cred -Body $postParams
					If ($RemoveProjectNACL -eq 0) {
						$RemoveProjNACL = New-Object -TypeName PSObject
						$RemoveProjNACL | Add-Member -Type NoteProperty -Name Array -Value $Array
						$RemoveProjNACL | Add-Member -Type NoteProperty -Name PoolName -Value $PoolName
						$RemoveProjNACL | Add-Member -Type NoteProperty -Name ProjectName -Value $ProjectName
						$RemoveProjNACL | Add-Member -Type NoteProperty -Name HostType -Value $HostType
						$RemoveProjNACL | Add-Member -Type NoteProperty -Name NACLHost -Value $NACLHost
						$RemoveProjNACL | Add-Member -Type NoteProperty -Name Status -Value "True"
						$RemoveProjNACL | Add-Member -Type NoteProperty -Name NACLremoved -Value "True"
						$RemoveProjectNFSNetworkACLReport += $RemoveProjNACL
					} else {
						$RemoveProjNACL = New-Object -TypeName PSObject
						$RemoveProjNACL | Add-Member -Type NoteProperty -Name Array -Value $Array
						$RemoveProjNACL | Add-Member -Type NoteProperty -Name PoolName -Value $PoolName
						$RemoveProjNACL | Add-Member -Type NoteProperty -Name ProjectName -Value $ProjectName
						$RemoveProjNACL | Add-Member -Type NoteProperty -Name HostType -Value $HostType
						$RemoveProjNACL | Add-Member -Type NoteProperty -Name NACLHost -Value $NACLHost
						$RemoveProjNACL | Add-Member -Type NoteProperty -Name Status -Value "False"
						$RemoveProjNACL | Add-Member -Type NoteProperty -Name NACLremoved -Value "False"
						$RemoveProjectNFSNetworkACLReport += $RemoveProjNACL
					}
				} else {
					$RemoveProjNACL = New-Object -TypeName PSObject
					$RemoveProjNACL | Add-Member -Type NoteProperty -Name Array -Value $Array
					$RemoveProjNACL | Add-Member -Type NoteProperty -Name PoolName -Value $PoolName
					$RemoveProjNACL | Add-Member -Type NoteProperty -Name ProjectName -Value $ProjectName
					$RemoveProjNACL | Add-Member -Type NoteProperty -Name HostType -Value $HostType
					$RemoveProjNACL | Add-Member -Type NoteProperty -Name NACLHost -Value $NACLHost
					$RemoveProjNACL | Add-Member -Type NoteProperty -Name Status -Value "False"
					$RemoveProjNACL | Add-Member -Type NoteProperty -Name NACLremoved -Value "False"
					$RemoveProjectNFSNetworkACLReport += $RemoveProjNACL
				}
			}
		} else {
			Write-Host "`nThe specified NACL does not seem to exist!" -ForegroundColor yellow -BackgroundColor Black
			$RemoveProjNACL = New-Object -TypeName PSObject
			$RemoveProjNACL | Add-Member -Type NoteProperty -Name Array -Value $Array
			$RemoveProjNACL | Add-Member -Type NoteProperty -Name PoolName -Value $PoolName
			$RemoveProjNACL | Add-Member -Type NoteProperty -Name ProjectName -Value $ProjectName
			$RemoveProjNACL | Add-Member -Type NoteProperty -Name HostType -Value $HostType
			$RemoveProjNACL | Add-Member -Type NoteProperty -Name NACLHost -Value $NACLHost
			$RemoveProjNACL | Add-Member -Type NoteProperty -Name Status -Value "False"
			$RemoveProjNACL | Add-Member -Type NoteProperty -Name NACLremoved -Value "False"
			$RemoveProjectNFSNetworkACLReport += $RemoveProjNACL
		}
	}
	End{
		Write-Output $RemoveProjectNFSNetworkACLReport
	}
}