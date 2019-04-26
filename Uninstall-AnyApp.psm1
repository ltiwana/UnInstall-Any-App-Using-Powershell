Get-ADComputer -Filter "name -eq 'c-jutlandhub9'"

Function Uninstall-AnyApp {
    
    [CmdletBinding()] 
    Param (
        [Parameter(Mandatory=$True, Position=1)]
        [string]$AppName,
        [Parameter(Mandatory=$false, Position=2)]
        [string]$SilentSwitch,
        [Parameter(Mandatory=$false, Position=3)]
        [string]$LogLocation = "C:\Windows\Temp"
    )

    Write-Verbose "Checking if Log directory exists: $LogLocation"
    if (!(Test-Path $LogLocation)) {mkdir $LogLocation -Verbose}

    Write-Verbose "Starting log"
    Start-Transcript -Path "$LogLocation\Uninstall-AnyApp_PSLogs$(Get-Date -Format "_yyyy-MM-dd_hh.mm").log" -Verbose
    
    Write-Verbose "Script start time: $(get-date)"

    Function Run-Uninstall {
    
        Param (
            [string]$UninstallString,
            [string]$SilentSwitch,
            [switch]$Quiet
        )

        if ($Quiet) {
    
            Write-Verbose "Quiet Uninstall string: $UninstallString"
            Write-Verbose "Running quiet uninstall command: $("& `""$UninstallString"`" | out-host")"
            #Start-Process -FilePath $UninstallString -Wait
            Invoke-Expression ("& `"" + $UninstallString + "`" | out-host")
            Write-Verbose "Adding 30 seconds delay"
            sleep 30
    
        }

        else {
        
            Write-Verbose ("Running uninstall command: & $UninstallString $SilentSwitch")

            if (!$SilentSwitch) {
                    Write-Warning "Unable to find the quiet uninstall string. Unintall may require user interaction"
                    Write-Warning "Try using the silent switch"
                    Write-Warning "Example: Uninstall-AnyApp -AppName `"$Script:AppName`" -SilentSwitch `"/silent`""
                    #Start-Process -FilePath $UninstallString -Wait
                    Write-Verbose "Trying to Executing following command $("& $UninstallString | out-host")"
                    Invoke-Expression ("& " + $UninstallString + " | out-host")
                    if (!$?) {
                        Write-Warning "$AppName uninstall has failed."
                        Write-Warning "Exit code: $LASTEXITCODE"

                    }
            }

            else {
                Write-Verbose "Silent switch was provided manually"
                Write-Verbose "Trying to Executing following command $("& $UninstallString $SilentSwitch | out-host")"
                Start-Process -FilePath $UninstallString -ArgumentList $SilentSwitch -Wait -PassThru -NoNewWindow
                if (!$?) {
                    Write-Warning "$AppName uninstall has failed."
                    Write-Warning "Exit code: $LASTEXITCODE"

                }                
            }
            

            Write-Verbose "Adding 30 seconds delay"
            sleep 30
    
        }

    }
    Function Clean-UninstallString {
       
        Param (
            [string]$UninstallString
        )

        $UninstallString = $UninstallString -replace "`""
        $UninstallString = $UninstallString -replace "`'"
        $Switches = ($UninstallString -split  "^.*\.exe")[1].Trim()

        $UninstallString -match "^.*\.exe" | Out-Null
        
        $FinalString = ("`"" + ($Matches.Values | Out-String).trim() + "`" " + $Switches)

        return $FinalString
        


    }

    Write-Verbose "Starting the app detection"
    Write-Verbose "Trying to find $AppName in WMI Objects."
    Write-Verbose "This may take sometime, please wait..."

    $FoundApps = Get-WmiObject -Class win32_product -Filter "name like '%$AppName%'" -Verbose

    if ($FoundApps) {
    
        Write-Verbose "$AppName was found in WMI objects"

        if ($FoundApps.count -gt "1") {
            Write-Warning "More than one Apps were found in WMI objects. Please try more specific app name."
            Write-Verbose "Current defined App name: $AppName"
            Write-Verbose "List of apps found: $($FoundApps |fl -Verbose |Out-String)"
        }

        else {

            foreach ($FoundApp in $FoundApps) {

                Write-Verbose ("Starting Uninstall of " + $FoundApp.Name)
	            Write-Verbose ("-" * (("Starting Uninstall of " + $FoundApp.Name)).length )
	            $FoundApp

	            $MSIArgs = ("/x " + $FoundApp.IdentifyingNumber + " /qn /norestart /L*V `"$("$LogLocation\Uninstall-AnyApp_" + $($FoundApp.name -replace " ") +"_uninstall.log")`"")
    
                Write-Verbose "`nRunning uninstall command: Start-Process msiexec.exe -Wait -ArgumentList $MSIArgs -NoNewWindow"

                Write-Verbose ("`nLog file location: $LogLocation\Uninstall-AnyApp_" + $($FoundApp.name -replace " ") +"_uninstall.log")

                Start-Process msiexec.exe -Wait -ArgumentList "$MSIArgs" -NoNewWindow
                if (!$?) {
                    Write-Warning ("$AppName uninstall has failed. Please check the logs under: $LogLocation\Uninstall-AnyApp_" + $($FoundApp.name -replace " ") +"_uninstall.log")
                    Write-Warning "Exit code: $LASTEXITCODE"

                }

                Write-Verbose "Adding 30 seconds delay"
                sleep 30
            }

        }
    }

    else { 

        Write-Warning "$AppName is not found in WMI objects"

        Write-Verbose "Trying to detect $AppName in 64-bit registry"
        $QuietUninstallString64 = (Get-ItemProperty "HKLM:\Software\wow6432node\Microsoft\Windows\CurrentVersion\Uninstall\*$AppName*\" -ErrorAction SilentlyContinue   | select QuietUninstallString).QuietUninstallString 
        if ($QuietUninstallString64 -eq $Null -or !$QuietUninstallString64) { $QuietUninstallString64 = (Get-ItemProperty "HKLM:\Software\wow6432node\Microsoft\Windows\CurrentVersion\Uninstall\*" -Name DisplayName, QuietUninstallString -ErrorAction SilentlyContinue | ?{$_.DisplayName -like "*$AppName*"} | select QuietUninstallString).QuietUninstallString}

        $UninstallString64 = (Get-ItemProperty "HKLM:\Software\wow6432node\Microsoft\Windows\CurrentVersion\Uninstall\*$AppName*\" -ErrorAction SilentlyContinue   | select UninstallString).UninstallString
        if ($UninstallString64 -eq $Null -or !$UninstallString64) { $UninstallString64 = (Get-ItemProperty "HKLM:\Software\wow6432node\Microsoft\Windows\CurrentVersion\Uninstall\*" -Name DisplayName, UninstallString -ErrorAction SilentlyContinue | ?{$_.DisplayName -like "*$AppName*"} | select UninstallString).UninstallString}

        Write-Verbose "Trying to detect $AppName in 32-bit registry"
        $QuietUninstallString32 = (Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*$AppName*\" -ErrorAction SilentlyContinue   | select QuietUninstallString).QuietUninstallString
        if ($QuietUninstallString32 -eq $Null -or !$QuietUninstallString32) { $QuietUninstallString32 = (Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -Name DisplayName, QuietUninstallString -ErrorAction SilentlyContinue | ?{$_.DisplayName -like "*$AppName*"} | select QuietUninstallString).QuietUninstallString}

        $UninstallString32 = (Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*$AppName*\" -ErrorAction SilentlyContinue   | select uninstallstring).UninstallString
        if ($UninstallString32 -eq $Null -or !$UninstallString32) { $UninstallString32 = (Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -Name DisplayName, uninstallstring -ErrorAction SilentlyContinue | ?{$_.DisplayName -like "*$AppName*"} | select uninstallstring).uninstallstring}

        
        if ($QuietUninstallString64 -and $QuietUninstallString64.count -lt "2") {
            Write-Verbose "A 64 bit quiet uninstall string was found"
            $QuietUninstallString64 = Clean-UninstallString $QuietUninstallString64
           
            Run-Uninstall -UninstallString $QuietUninstallString64 -Quiet
        }
        elseif ($QuietUninstallString32 -and $QuietUninstallString32.count -lt "2") {
            Write-Verbose "A 32 bit quiet uninstall string was found"
            $QuietUninstallString32 = Clean-UninstallString $QuietUninstallString32
            Run-Uninstall -UninstallString $QuietUninstallString32 -Quiet
        }
        elseif ($UninstallString64 -and $UninstallString64.count -lt "2") {
            Write-Warning "A 64 bit uninstall string was found."
            $UninstallString64 = Clean-UninstallString $UninstallString64
            Run-Uninstall -UninstallString $UninstallString64 -SilentSwitch $SilentSwitch
        }
        elseif ($UninstallString32 -and $UninstallString32.count -lt "2") {
            Write-Warning "A 32 bit uninstall string was found."
            $UninstallString32 = Clean-UninstallString $UninstallString32
            Run-Uninstall -UninstallString $UninstallString32 -SilentSwitch $SilentSwitch
        }
        Else {
            if ($QuietUninstallString64.count -gt "1" -or $QuietUninstallString32.count -gt "1" -or $UninstallString64.count -gt "1" -or $UninstallString32.count -gt "1") {
                Write-Warning "More than one Apps were found in registry key. Please try more specific app name."
                Write-Verbose "Current defined App name: $AppName"
                
            }
            else {
                Write-Warning "$AppName is not found in 32-bit and 64-bit registry. Please try a different app name"
            }
            
        }

    }

    Stop-Transcript -Verbose

}

