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

        It "$Module has a manifest" {
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
    } # Context
} # Describe