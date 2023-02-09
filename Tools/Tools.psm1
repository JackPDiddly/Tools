

#region Function Write-Log


function Write-Log {

    <#
    .Synopsis
       Add an entry to a log file
    .DESCRIPTION
       Write-Log allows an entry to be written to a log file by one or more functions.  Each entry
       is stamped with the date and time, the severity of the message, the function or script which
       called Write-Log, and a supplied message.  The ability to write to a common log file from
       multiple functions allows the logged output from multiple piped functions to be concurrently
       logged.
    .EXAMPLE

    Write-Log -Level INFO -Message "Something happened" -logfile c:\temp\a.log

    This examples shows an information message being written to c:\temp\a.log

    .INPUTS
       The pipeline input can be used for the message to be written to the log
    .OUTPUTS
       - none -
    .NOTES
    Attributions
        Author:      Thomas Karrmann

    Change Log
    Version    Date         Description
    0.1        05-Jun-2018  Development
    1.0                     Initial Publication

    .COMPONENT
       The component this cmdlet belongs to
    .ROLE
       The role this cmdlet belongs to
    .FUNCTIONALITY
       The functionality that best describes this cmdlet
    #>


        [CmdletBinding()]

        Param (

            [Parameter(Mandatory=$False, Position=1)]
            [ValidateSet("INFO","WARN","ERROR","FATAL","DEBUG")]
            [String]
            $Level = "INFO",

            [Parameter(Mandatory=$True, ValueFromPipeline=$true, Position=0)]
            [string]
            $Message,

            [Parameter(Mandatory=$False, Position=2)]
            [string]
            $logfile

        )

        Begin {
            $output = "Begin processing in function $($MyInvocation.Mycommand)" | timestamp
            write-verbose $output
            $output = "Using parameter set $($PSCmdlet.ParameterSetName)" | timestamp
            write-verbose $output
            $output = ($PSBoundParameters | Out-String) | timestamp
            write-verbose $output

        }


        Process {

            $CallStack = Get-PSCallStack

            $Called = " :: Called from $($CallStack[1].FunctionName) at line $($CallStack[1].ScriptLineNumber) :: "

            $Line = "$Level $Called $Message" | timestamp
            If( Test-Path $logfile -PathType Leaf ) {
                Add-Content $logfile -Value $Line
            }
            Else {
                Write-Error "Log file $logfile not found"
                Write-Error $Line
            }
        }


        End {

            $output = "Processing complete in function $($MyInvocation.Mycommand), exiting" | timestamp
            write-verbose $output
        }

    }


    #endregion Function Write-Log




    #region Function Test-Verbose

    function Test-Verbose {

    <#
    .SYNOPSIS
    Tests to see if the cmdlet is running in verbose mode
    .DESCRIPTION
    Tests to see if the cmdlet is running in verbose mode
    .EXAMPLE
    if (test-verbose) {
        # Do something here
    }
    #>

        [CmdletBinding()]

        param()

        process {
            [System.Management.Automation.ActionPreference]::SilentlyContinue -ne $VerbosePreference
        }

    }

    #endregion Fundtion Test-Verbose




    #region Function Test-Connectivity

    function Test-Connectivity {

    <#
    .SYNOPSIS
    Tests connectivity to a remote system
    .DESCRIPTION
    Tests connectivity to a remote system by pinging the system and
    checking for the availability of the C$ administrative share
    .EXAMPLE
    if ( test-connectivity -ComputerName TestServer ) {
        # Perform remote commands here
    }
    .PARAMETER ComputerName
    Name of the remote system to check for connectivity on
    #>

        [CmdletBinding()]

        param(

            [Parameter(Mandatory=$true,
                       ValueFromPipeline=$true,
                       ValueFromPipelineByPropertyName=$false,
                       ValueFromRemainingArguments=$false,
                       Position=0
                       )]
            [String]$ComputerName,

            [Parameter(Mandatory=$false,
                       ValueFromPipeline=$false,
                       ValueFromPipelineByPropertyName=$false,
                       ValueFromRemainingArguments=$false,
                       Position=1
                       )]
            [PSCredential]$Cred = $null

        )

        process {
            if ( Test-Connection -ComputerName $ComputerName -Quiet -Count 1 ) {

    # File System does not support credentials.  Need to determine how to make this work from
    # a non-admin account

                return $true
                if ( $Cred ) {
                    if ( Invoke-Command -ComputerName $ComputerName -Credential $Cred -ScriptBlock { Test-Path -Path "\\$ComputerName\c$" } ) {
    #                if ( Test-Path -Path "\\$ComputerName\c$" -Credential $Cred ) {
                        return $true
                    } else {
                        return $false
                    }
                } else {
                    if ( Test-Path -Path "\\$ComputerName\c$" ) {
                        return $true
                    } else {
                        return $false
                    }
                }
            } else {
                return $false
            }
        }

    }

    #endregion Function Test-Connectivity




    #region Function Archive-Files

    function Archive-Files {

    <#
    .Synopsis
       Archives PowerShell environment, including all scripts and modules to a ZIP file
    .DESCRIPTION
       Archives PowerShell environment, including all scripts and modules to a ZIP file
    .EXAMPLE

    Archive-Files

    This example will archive all PowerShell environment into a ZIP file for archival purposes.

    .INPUTS
       - none -
    .OUTPUTS
       - none -
    .NOTES
    Attributions
        Author:      Thomas Karrmann

    Change Log
    Version    Date         Description
    0.1        05-Jun-2018  Development
    1.0        21-Jan-2019  Initial Publication

    .COMPONENT
       Tools
    .ROLE
       Backup/Archive
    .FUNCTIONALITY
       The functionality that best describes this cmdlet
    #>

        [CmdletBinding()]

        param()

        process {
            $Source1 = "\\ds.ad.ssmhc.com\ssmdfs\agn\UserHome\tkar19186\My Documents\WindowsPowerShell"
            $Source2 = "\\ds.ad.ssmhc.com\ssmdfs\agn\UserHome\tkar19186\My Documents\My Scripts"
            $Destination = "TPK:\temp\PS.zip"
            Compress-Archive -Path $Source1 -DestinationPath $Destination -CompressionLevel Optimal -Force
            Compress-Archive -Path $Source2 -DestinationPath $Destination -CompressionLevel Optimal -Update
        }

    }

    #endregionn Function Archive-Files





    #region Function Deploy-Files

    function Deploy-Files {

    <#
    .SYNOPSIS
    Copies all PowerShell scripts and environment to non-admin computer
    .DESCRIPTION
    Copies all PowerShell scripts and environment to non-admin computer
    .EXAMPLE
    archive-files
    #>

        [CmdletBinding()]

        param()

        process {
            $Source1 = "\\ds.ad.ssmhc.com\ssmdfs\agn\UserHome\tkar19186\My Documents\WindowsPowerShell"
            $Source2 = "\\ds.ad.ssmhc.com\ssmdfs\agn\UserHome\tkar19186\My Documents\My Scripts"
            $Destination1 = "\\ds.ad.ssmhc.com\ssmdfs\agn\UserHome\tkarrm1\My Documents\"
            $Destination2 = "C:\users\tkarrm1\Documents\"
            Copy-Item -Path $Source1 -Destination $Destination1 -Force -Recurse -Verbose
            Copy-Item -Path $Source2 -Destination $Destination1 -Force -Recurse -Verbose
            Copy-Item -Path $Source1 -Destination $Destination2 -Force -Recurse -Verbose
    #		Copy-Item -Path $Source2 -Destination $Destination2 -Force -Recurse -Verbose
        }

    }

    #endregion Function Deploy-Files




    #region Function Set-LogonScripts


    function Set-LogonScripts {


    <#
    .SYNOPSIS
    Changes the logon script of all supplied users to the supplied file
    .DESCRIPTION
    Given a list of users and a valid batch file path, the user accounts are all updated to use
    that script file as their logon script
    .NOTES
    Attributions
        Author:      Thomas Karrmann

    Change Log
    Version    Date         Description
    0.1        09-May-2018  Development
    1.0        10-May-2018  Initial Publication
    .EXAMPLE
    Set-LogonScripts -Users "Burpee" -Script "\\domain.com\NETLOGON\script.bat" -verbose
    Changes user "Burpee" to use the listed logon script
    .EXAMPLE
    Get-ADUser -filter * -properties scriptpath, homedrive, homedirectory |
    where {$_.scriptpath –like “*bat*”} |
    Set-LogonScripts -Script "\\domain.com\NETLOGON\script.bat" -verbose
    Changes all users with existing .BAT logon scripts to use the listed logon script
    .PARAMETER Users
    The users for which to change to logon script
    .PARAMETER Script
    A valid logon script path
    #>



        [CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]

        param (
            [Parameter(Mandatory=$True, ValueFromPipeline=$True, Position = 0,
                        HelpMessage='What users should be affected?')]
            [PSObject[]]$Users,

            [Parameter(Mandatory=$True, ValueFromPipeline=$False, Position = 1,
                        HelpMessage='Logon script to use?')]
            [string]$Script

        )

        Begin {

            $output = "Begin processing in function $($MyInvocation.Mycommand)" | timestamp
            write-verbose $output
            $output = "Using parameter set $($PSCmdlet.ParameterSetName)" | timestamp
            write-verbose $output
            $output = ($PSBoundParameters | Out-String) | timestamp
            write-verbose $output

            if (Test-Path $Script) {
                $output = "Script path validated - continuing" | timestamp
                write-verbose $output
            } else {
                if (Test-Path "\\agn.com\NETLOGON\$Script") {
                    $output = "Script path validated - continuing" | timestamp
                    write-verbose $output
                } else {
                    $output = "Bad script path - exiting" | timestamp
                    write-error $output
                    break
                }
            }
        }

        Process {
            foreach ( $User in $Users ) {
                $U = $User.sAMAccountName
                if ($pscmdlet.ShouldProcess("AD User Account $U", "Set logon script to $Script")) {
                    Set-ADUser -Identity $User.samaccountname -ScriptPath $Script
                }
            }
        }

        End {

            $output = "Processing complete in function $($MyInvocation.Mycommand), exiting" | timestamp
            write-verbose $output
        }

    }

    #endregion Function Set-LogonScripts





    #region Function Backup-DRSysData


    function Backup-DRSysData {


    <#
    .Synopsis
       Exports and assembles DHCP and DNS data for DR offline storage
    .DESCRIPTION
       Exports and assembles DHCP and DNS data for DR offline storage
    .EXAMPLE
       Backup-DRSysData
    .INPUTS
       - None -
    .OUTPUTS
       - None -
    .NOTES
    Attributions
        Author:      Thomas Karrmann

    Change Log
    Version    Date         Description
    0.1        30-May-2018  Development
    1.0        20-May-2018  Initial Publication

    .COMPONENT
       - None -
    .ROLE
       - None -
    .FUNCTIONALITY
       Data export
    #>


        [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Low')]


        Param (
        )


        Begin {

            $output = "Begin processing in function $($MyInvocation.Mycommand)" | timestamp
            write-verbose $output
            $output = "Using parameter set $($PSCmdlet.ParameterSetName)" | timestamp
            write-verbose $output
            $output = ($PSBoundParameters | Out-String) | timestamp
            write-verbose $output

            $DHCPServer = "AGNFDLDC05.agn.com"
            $DHCPLocalFile = "C:\Users\karrmann\Desktop\DHCP"
            $DHCPRemoteFile = "\\agnfdldc05.agn.com\c$\users\karrmann\desktop\DHCP"

            $DRLocation = "S:\Disaster Recovery Data"
            $DHCPLocation = "$DRLocation\DHCP"
            $DNSZoneLocation = "$DRLocation\DNS\Exports\ZoneTemp.csv"
            $DNSExportsLocation = "$DRLocation\DNS\Exports"
            $DNSServer = "AGNFDLDC10P.agn.com"

            $Year = Get-date -Format yyyy
            $Month = Get-Date -Format MM
            $Day = Get-Date -Format dd

        }


        Process {

            $output = "Exporting DHCP Information" | timestamp
            write-verbose $output


            <# if ($pscmdlet.ShouldProcess("DHCP", "Backup Database")) {
                # Backup DHCP Server
                Backup-DhcpServer -ComputerName $DHCPServer -Path $DHCPLocalFile
                Move-Item -Path $DHCPRemoteFile -Destination "$DHCPLocation" -Force # -Recurse
            } #>

            $output = "Exporting DNS Information" | timestamp
            write-verbose $output

            if ($pscmdlet.ShouldProcess("DNS", "Backup Database")) {

                $output = "Gathering DNS Zone List" | timestamp
                write-verbose $output

                # Backup DNS
                # Pulls an environment variable to find the server name, queries it for a list of zones, filters only the primary ones, removes the quotes from the exported .csv file, and saves it to the specified folder.
                Get-DNSServerZone -ComputerName $DNSServer |
                    Where-Object{$_.ZoneType -eq "Primary"} |
                    Select ZoneName | ConvertTo-CSV -NoTypeInformation |
                    ForEach-Object {$_ -replace ‘"‘, ""} |
                    Out-File "$DNSZoneLocation" -Force

                # Imports the zone list
                $ZoneList = Get-Content "$DNSZoneLocation"

                $output = "Processing Zones" | timestamp
                write-verbose $output

                # Starts a loop for each line in the zone list
                ForEach ($line in $ZoneList) {

                    if ( $Line -ne "ZoneName" ) {

                        $output = "Processing Zone $line" | timestamp
                        write-verbose $output

                        $FileName = "${line}_$Year-$Month-$Day.txt"
                        $RemoteFile = "\\$DNSServer\C$\Windows\System32\dns\$FileName"
                        if ( Test-Path $RemoteFile ) {
                            remove-item $RemoteFile -Force
                        }

                        # Exports the zone info with the desired naming scheme
                        Export-DNSServerZone -Name $line -ComputerName $DNSServer -FileName $FileName

                        $output = "Moving Data to Location $DNSExportsLocation" | timestamp
                        write-verbose $output

                        if ( Test-Path $RemoteFile ) {
                            # Moves the export file from the default location to the Exports folder
                            Move-Item $RemoteFile "$DNSExportsLocation\$FileName" -Force
                        } else {
                            Write-Error "File $RemoteFile does not exist.  Zone did not export."
                        }
                    }
                }
            }
        }



        End {

            $output = "Processing complete in function $($MyInvocation.Mycommand), exiting" | timestamp
            write-verbose $output
        }
    }


    #endregion Function Backup-DRSysData




    #region Function Test-EmptyOrNull


    function Test-EmptyOrNull {

    <#
    .Synopsis
       Checks if a string value is empty or null
    .DESCRIPTION
       Takes a command line input string and returns a true if the string is empty or null or returns a false if the string has something in it.

       Also takes an Invert parameter which flops the outputs so that negation in a command line is not needed.

    .EXAMPLE
       Get-ADUser -filter * -properties scriptpath|where { Test-EmptyOrNull -Test $_.scriptpath -Invert }
    .INPUTS
       None
    .OUTPUTS
       Switch indicating True if the input is empty or null
    .NOTES
    Attributions
        Author:      Thomas Karrmann

    Change Log
    Version    Date         Description
    0.1        13-Jun-2018  Development
    1.0                     Initial Publication
    .COMPONENT
       The component this cmdlet belongs to
    .ROLE
       The role this cmdlet belongs to
    .FUNCTIONALITY
       The functionality that best describes this cmdlet
    #>


        [CmdletBinding(SupportsShouldProcess=$false)]
        [Alias()]
        [OutputType([Switch])]

        Param (
            [Parameter(Mandatory=$true,
                       ValueFromPipeline=$false,
                       ValueFromPipelineByPropertyName=$false,
                       ValueFromRemainingArguments=$false,
                       Position=0)]
            [AllowNull()]
            [AllowEmptyString()]
            [String]
            $Test,

            [Parameter(Mandatory=$false,
                ValueFromPipeline=$false,
                ValueFromPipelineByPropertyName=$false,
                ValueFromRemainingArguments=$false,
                Position=1)]
            [Switch]
            $Invert = $false

        )

        Begin {
            $output = "Begin processing in function $($MyInvocation.Mycommand)" | timestamp
            write-verbose $output
            $output = "Using parameter set $($PSCmdlet.ParameterSetName)" | timestamp
            write-verbose $output
            $output = ($PSBoundParameters | Out-String) | timestamp
            write-verbose $output

        }


        Process {
            if ( $Invert ) {
                if ( $Test -eq [DBNull]::Value ) { return $false }
                if ( $Test ) { return $true } else { return $false }
            } else {
                if ( $Test -eq [DBNull]::Value ) { return $true }
                if ( $Test ) { return $false } else { return $true }
            }
        }


        End {

            $output = "Processing complete in function $($MyInvocation.Mycommand), exiting" | timestamp
            write-verbose $output
        }

    }


    #endregion Function Test-EmptyOrNull


    Export-ModuleMember -Function * -Cmdlet * -Variable * -Alias *
