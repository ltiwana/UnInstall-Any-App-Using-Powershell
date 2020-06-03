
Function Uninstall-AnyApp {
    
    [CmdletBinding()] 
    Param (
        [Alias('Name','DisplayName')]
        [Parameter(
            Position=0,
            Mandatory=$true,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true
        )]
        [string[]]$AppName,
        [Parameter(Mandatory=$false, Position=1)]
        [string]$SilentSwitch,
        [Parameter(Mandatory=$false, Position=2)]
        [string]$LogLocation = "C:\Windows\Temp",
        [Alias('QuietUninstallString')]
        [parameter(DontShow, ValueFromPipelineByPropertyName)]
        $QUString,
        [Alias('UninstallString')]
        [parameter(DontShow, ValueFromPipelineByPropertyName)]
        $UString,
        [Alias('IdentifyingNumber')]
        [parameter(DontShow, ValueFromPipelineByPropertyName)]
        $INumber
        
    )
    

    begin {

        Write-Verbose "Checking if Log directory exists: $LogLocation"
        if (!(Test-Path $LogLocation)) {mkdir $LogLocation -Verbose}

        Write-Verbose "Script start time: $(get-date)"

        Function Run-MSIExec {

            param ( 
                $AppName,
                $MSIArgs
            )

            
            Write-Verbose "Running following uninstall command: & MSIExec.exe $MSIArgs"
            & MSIExec.exe @MSIArgs | Out-Host
            if (!$?) {
                Write-Warning "$AppName uninstall has failed."
                Write-Warning "Exit code: $LASTEXITCODE"

            }
            else {
                Write-Verbose "Uninstall finished successfully"
            }

        }

        Function Run-RegUninstall {
    
            Param (
                $AppName,
                $LogLocation,
                $UninstallString,
                $SilentSwitch,
                [switch]$Quiet
            )

            If ($Quiet) {
    
                Write-Verbose "Quiet Uninstall string: $UninstallString"
                Write-Verbose "Running quiet uninstall command: $("& $UninstallString | out-host")"
                Invoke-Expression ("& $UninstallString | out-host")
                if (!$?) {
                    Write-Warning "$AppName uninstall has failed."
                    Write-Warning "Exit code: $LASTEXITCODE"

                }
                else {
                    Write-Verbose "Uninstall finished successfully"
                }
    
            }
            elseif ($UninstallString -match "{[\s\S]*}") {

                Write-Verbose "MSI App Identifier string found"
                $MSIArgs = "/x", "$UninstallString", "/qn", "/norestart", "/L*V", "$LogLocation\Uninstall-AnyApp_$($AppName -replace " ","-")_uninstall.log"
                Run-MSIExec -AppName $AppName -MSIArgs $MSIArgs

            }
            else {
           
                Write-Verbose ("Running uninstall command: & $UninstallString $SilentSwitch")

                if (!$SilentSwitch) {
                        Write-Warning "Unable to find the quiet uninstall string. Unintall may require user interaction"
                        Write-Warning "Try using the silent switch"
                        Write-Warning ("Example: Uninstall-AnyApp -AppName `"" + $AppName + "`" -SilentSwitch `"/silent`"")
                        #Start-Process -FilePath $UninstallString -Wait
                        Write-Verbose "Trying to Executing following command: $("& $UninstallString | out-host")"
                        Invoke-Expression ("&  $UninstallString | out-host")
                        if (!$?) {
                            Write-Warning "$AppName uninstall has failed."
                            Write-Warning "Exit code: $LASTEXITCODE"

                        }
                        else {
                            Write-Verbose "Uninstall finished successfully"
                        }
                }

                else {
                    Write-Verbose "Silent switch was provided manually"
                    #Write-Verbose "Trying to Executing following command: $("Start-Process -FilePath $UninstallString -ArgumentList $SilentSwitch -Wait -PassThru -NoNewWindow | Out-Host")"
                    #Start-Process -FilePath $UninstallString -ArgumentList $SilentSwitch -Wait -PassThru -NoNewWindow | Out-Host
                    Write-Verbose "Trying to Executing following command: $("& $UninstallString $SilentSwitch | out-host")"
                    Invoke-Expression ("&  $UninstallString $SilentSwitch | out-host")
                    if (!$?) {
                        Write-Warning "$AppName uninstall has failed."
                        Write-Warning "Exit code: $LASTEXITCODE"

                    }
                    else {
                        Write-Verbose "Uninstall finished successfully"
                    }
                }
            
            }

        }

        Function Run-MsiUninstall {

            Param (
                $AppName,
                $LogLocation
            )

            Write-Verbose "$AppName is not found in 32-bit and 64-bit registry."

            Write-Verbose "Trying to find $AppName in WMI Objects."
            Write-Verbose "This may take sometime, please wait..."

            $FoundApps = Get-WmiObject -Class win32_product -Filter "name like '%$AppName%'" -Verbose

            if ($FoundApps) {
    
                Write-Verbose "$AppName was found in WMI objects"

                if ($FoundApps.count -gt "1") {
                    Write-Warning "More than one Apps were found in WMI objects. Please try more specific app name."
                    Write-Verbose "Current defined App name: $AppName"
                    Write-Verbose "List of apps found: $($FoundApps |fl -Verbose |Out-String)"
                    Return $FoundApps
                }

                else {

                    foreach ($FoundApp in $FoundApps) {

                        Write-Verbose ("Starting Uninstall of " + $FoundApp.Name)
	                    Write-Verbose ("-" * (("Starting Uninstall of " + $FoundApp.Name)).length )
	                    $FoundApp

	                    $MSIArgs = "/x", "$($FoundApp.IdentifyingNumber)", "/qn", "/norestart", "/L*V", "`"$LogLocation\Uninstall-AnyApp_$($FoundApp.name -replace " ","-")_uninstall.log`""
    
                        #Write-Verbose "`nRunning uninstall command: Start-Process msiexec.exe -Wait -ArgumentList $MSIArgs -NoNewWindow"
                        Write-Verbose "`nRunning uninstall command: & msiexec.exe $MSIArgs)"

                        Run-MSIExec -AppName $AppName -MSIArgs $MSIArgs

                        #Write-Verbose ("`nLog file location: $LogLocation\Uninstall-AnyApp_" + $($FoundApp.name -replace " ","-") +"_uninstall.log")

                        #Start-Process msiexec.exe -Wait -ArgumentList "$MSIArgs" -NoNewWindow -PassThru
	                    #& msiexec.exe  /x  $($FoundApp.IdentifyingNumber) /qn /norestart /L*V $("$LogLocation\Uninstall-AnyApp_" + $($FoundApp.name -replace " ","-") +"_uninstall.log") | Out-Host
                        #Invoke-Expression ("& msiexec.exe $MSIArgs | out-host")
                        #& msiexec.exe $MSIArgs | out-host
                        #if (!$?) {
                        #    Write-Warning ("$AppName uninstall has failed. Please check the logs under: $LogLocation\Uninstall-AnyApp_" + $($FoundApp.name -replace " ","-") +"_uninstall.log")
                        #    Write-Warning "Exit code: $LASTEXITCODE"
                        #
                        #}
                        #else {
                        #    Write-Verbose "Uninstall finished successfully"
                        #}
                    }

                }
            }
            else {
                Write-Warning "$AppName is not found in WMI objects. Please try a different app name!"
                return $null
            }


        }

        Function Clean-UninstallString {
       
            Param (
                [string]$UninstallString
            )

            $UninstallString = $UninstallString -replace "`""
            $UninstallString = $UninstallString -replace "`'"
            if ($UninstallString) {$Switches = ($UninstallString -split  "^.*\.exe")[1].Trim()}

            $UninstallString -match "^.*\.exe" | Out-Null
            $Executable = $Matches.Values
            
            if ($UninstallString -match "msiexec.exe") {
                
                $Switches -match "{[\s\S]*}" | Out-Null
                $FinalString = $Matches.Values

                #$FinalString =   "MSIExec.exe", "/x `"$IdentifyingNumber`" /qn /norestart /L*V `"$LogLocation\Uninstall-AnyApp_" + $($AppName -replace " ","-") + "_uninstall.log`""

            }
            else {
                $FinalString = ("`"" + ($Executable | Out-String).trim() + "`" " + $Switches)
            }

            return $FinalString
        


        }

        Function Get-AppRegKeys {

            param (
                $AppName,
                $RegPath
            )

            Write-Verbose "Looking for app: $AppName in reg key path $RegPath"
            $AppRegKeys = Get-ItemProperty "$RegPath\*" -ErrorAction SilentlyContinue -Name *  | ?{$_.DisplayName -like "*$AppName*"}            

            if ($AppRegKeys -eq $Null -or !$AppRegKeys) {
                $AppRegKeys = Get-ItemProperty "$RegPath\*$AppName*\" -ErrorAction SilentlyContinue -Name *
            }

            Return $AppRegKeys

        }


    }

    Process {

        
        Write-Verbose "Starting log"

        $QuietUninstallString = $QUString
        $UninstallString = $UString
        $IdentifyingNumber = $INumber

        $LogPath = "$LogLocation\Uninstall-AnyApp_$($AppName -replace " ","-" -replace "\*","-")`_PSLogs$(Get-Date -Format "_yyyy-MM-dd_hh.mm").log"

        Start-Transcript -Path $LogPath -Append -Force -Verbose | Out-Host


        Write-Verbose "Starting uninstall of app: $AppName"

        if ($QuietUninstallString) {
            Write-Verbose "QuietUninstallString recieved $QuietUninstallString through pipeline"
            Run-RegUninstall -AppName $AppName -LogLocation $LogLocation -UninstallString $QuietUninstallString -Quiet

        }
        elseif ($IdentifyingNumber) {
            Write-Verbose "IdentifyingNumber recieved $IdentifyingNumber through pipeline"
            Run-RegUninstall -AppName $AppName -LogLocation $LogLocation -UninstallString $IdentifyingNumber
            

        }
        elseif ($UninstallString -match "msiexec.exe") {
            Write-Verbose "UninstallString recieved $UninstallString through pipeline"                
            $IdentifyingNumber = Clean-UninstallString $UninstallString
            Run-RegUninstall -AppName $AppName -LogLocation $LogLocation -UninstallString $IdentifyingNumber
        }
        else {
            
    
            Write-Verbose "Starting the app detection"

            Write-Verbose "Trying to detect $AppName in 64-bit registry"
            $AppName64RegKey = Get-AppRegKeys -AppName $AppName -RegPath "HKLM:\Software\wow6432node\Microsoft\Windows\CurrentVersion\Uninstall"

            Write-Verbose "Trying to detect $AppName in 32-bit registry"
            $AppName32RegKey = Get-AppRegKeys -AppName $AppName -RegPath "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"

            if ($AppName64RegKey.count -gt 1 -or $AppName32RegKey.count -gt 1) {
                Write-Warning "More than one Apps were found in registry key. Please try more specific app name."
                Write-Verbose "Current defined App name: $AppName"
                return $AppName64RegKey, $AppName32RegKey
            
            }
            else {

                if ($AppName64RegKey.QuietUninstallString) {
                
                    Write-Verbose "A 64 bit quiet uninstall string was found"
                    $AppName64RegKey
                    $QuietUninstallString = Clean-UninstallString $AppName64RegKey.QuietUninstallString
                    Run-RegUninstall -AppName $AppName64RegKey.DisplayName -LogLocation $LogLocation -UninstallString $QuietUninstallString -Quiet

                }
                elseif ($AppName32RegKey.QuietUninstallString) {
                
                    Write-Verbose "A 32 bit quiet uninstall string was found"
                    $AppName32RegKey
                    $QuietUninstallString = Clean-UninstallString $AppName32RegKey.QuietUninstallString
                    Run-RegUninstall -AppName $AppName32RegKey.DisplayName -LogLocation $LogLocation -UninstallString $QuietUninstallString -Quiet

                }
                elseif ($AppName64RegKey.UninstallString -match "msiexec.exe") {
                    Write-Verbose "MSI Identifire found in the Uninstall String"
                    $AppName64RegKey
                    $QuietUninstallString = Clean-UninstallString $AppName32RegKey.UninstallString
                    Run-RegUninstall -AppName $AppName64RegKey.DisplayName -LogLocation $LogLocation -UninstallString $QuietUninstallString


                }
                elseif ($AppName32RegKey.UninstallString -match "msiexec.exe") {
                    Write-Verbose "MSI Identifire found in the Uninstall String"
                    $AppName32RegKey
                    $QuietUninstallString = Clean-UninstallString $AppName32RegKey.UninstallString
                    Run-RegUninstall -AppName $AppName32RegKey.DisplayName -LogLocation $LogLocation -UninstallString $QuietUninstallString
                }
                else {
                
                    if ($SilentSwitch -eq $Null -or !$SilentSwitch) {
                        Run-MsiUninstall -AppName $AppName -LogLocation $LogLocation
                    }

                    if ($AppName64RegKey.UninstallString) {

                        Write-Warning "A 64 bit uninstall string was found."
                        $AppName64RegKey
                        $UninstallString = Clean-UninstallString $AppName64RegKey.UninstallString
                        Run-RegUninstall -AppName $AppName64RegKey.DisplayName -LogLocation $LogLocation -UninstallString $UninstallString -SilentSwitch $SilentSwitch

                    }
                    elseif ($AppName32RegKey.UninstallString) {
                        Write-Warning "A 32 bit uninstall string was found."
                        $AppName32RegKey
                        $UninstallString = Clean-UninstallString $AppName32RegKey.UninstallString
                        Run-RegUninstall -AppName $AppName32RegKey.DisplayName -LogLocation $LogLocation -UninstallString $UninstallString -SilentSwitch $SilentSwitch
                    }

                }

            }
        
        }

        Stop-Transcript -Verbose | Out-Host
        
    }
    End {
      
        #
        
    }

}

