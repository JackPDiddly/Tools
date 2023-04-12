$global:VerbosePreference = "Continue"

$global:testhere = Split-Path -Parent $MyInvocation.MyCommand.Path

$global:Module = "Tools"

$temp = Split-Path $testhere
$global:here = $temp + "\" + $Module

$global:Funtions =  (
                        "Write-Log",
                        "Test-Verbose"
                    )


Describe "Module $Module" {

    Context "Test Module $Module" -Tags @("Module","Unit") {
        It "$Module is valid PowerShell code" {
            $global:path = $here + "\" + $Module + ".psm1"
            $psFile = Get-Content -Path $path -ErrorAction SilentlyContinue
            $errors = $null         #Creates variable so it is ready for next line
            if ( $null -eq $psFile ) {
                $errors = new-object psobject
                Add-Member -InputObject $errors -MemberType NoteProperty -Name "Count" -Value 1
            } else {
                $null = [System.Management.Automation.PSParser]::Tokenize($psFile, [ref]$errors)
            } #If
            $errors.Count | Should -Be 0
        } # It

        It "$Module has a manifest which is valid PowerShell code" {
            $global:path = $here + "\" + $Module + ".psd1"
            $psFile = Get-Content -Path $path -ErrorAction SilentlyContinue
            $errors = $null         #Creates variable so it is ready for next line
            if ( $null -eq $psFile ) {
                $errors = new-object psobject
                Add-Member -InputObject $errors -MemberType NoteProperty -Name "Count" -Value 1
            } else {
                $null = [System.Management.Automation.PSParser]::Tokenize($psFile, [ref]$errors)
            } #If
            $errors.Count | Should -Be 0
        } # It

        It "$Module manifest has the proper GUID" {
            $global:path = $here + "\" + $Module + ".psd1"
            $psFile = Get-Content -Path $path -ErrorAction SilentlyContinue
            if ( $null -eq $psFile ) {
                $results = $false
            } else {
                for ( ($results=$false), ($i=0) ; $i -lt $psFile.Count ; $i++ ) {
                    $Result = [System.Guid]::empty #Reference for the output, required by the method but not useful in powershell
                    if ( $psFile[$i] -like "GUID = *" ) {
                        if ([System.Guid]::TryParse("34823b02-4e79-41ff-908b-3e32fe36e1ef", [System.Management.Automation.PSReference]$Result)) {  # Returns true if successfully parsed, otherwise false.
                            $results = $true
                            break
                        }
                    }
                }
            } #If
            $results| Should -Be $true
        } # It
    } # Context
} # Describe



$Result = [System.Guid]::empty #Reference for the output, required by the method but not useful in powershell
[System.Guid]::TryParse("foo",[System.Management.Automation.PSReference]$Result) # Returns true if successfully parsed and assigns the parsed guid to $Result, otherwise false.

$Result = [System.Guid]::empty #Reference for the output, required by the method but not useful in powershell
[System.Guid]::TryParse("12345678-1234-1234-1234-987654321abc",[System.Management.Automation.PSReference]$Result) # Returns true if successfully parsed, otherwise false.
