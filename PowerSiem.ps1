# Inspired SilentBreakSecurity DSOPS 1 Course - NetSPI
$ErrorActionPreference = "SilentlyContinue"

Function Parse-Event {
    # Credit: https://github.com/RamblingCookieMonster/PowerShell/blob/master/Get-WinEventData.ps1
    param(
        [Parameter(ValueFromPipeline=$true)] $Event
    )

    Process
    {
        foreach($entry in $Event)
        {
            $XML = [xml]$entry.ToXml()
            $X = $XML.Event.EventData.Data
            For( $i=0; $i -lt $X.count; $i++ ){
                $Entry = Add-Member -InputObject $entry -MemberType NoteProperty -Name "$($X[$i].name)" -Value $X[$i].'#text' -Force -Passthru
            }
            $Entry
        }
    }
}

Function Write-Alert ($alerts) {
    Write-Host "Type: $($alerts.Type)"
    $alerts.Remove("Type")
    foreach($alert in $alerts.GetEnumerator()) {
        write-host "$($alert.Name): $($alert.Value)"
    }
    write-host "-----"
}

$LogName = "Microsoft-Windows-Sysmon"

$index =  (Get-WinEvent -Provider "Microsoft-Windows-Sysmon" -max 1).RecordID
while ($true)
{
    Start-Sleep 1

    $NewIndex = (Get-WinEvent -Provider $LogName -max 1).RecordID

    if ($NewIndex -gt $Index) {
        # We Have New Events.
        $logs =  Get-WinEvent -provider $LogName -max ($NewIndex - $index) | sort RecordID
        foreach($log in $logs) {
            $evt = $log | Parse-Event
            if ($evt.id -eq 1) {
                $output = @{}
                $output.add("Type", "Process Create")
                $output.add("PID", $evt.ProcessId)
                $output.add("Image", $evt.Image)
                $output.add("CommandLine", $evt.CommandLine)
                $output.add("CurrentDirectory", $evt.CurrentDirectory)
                $output.add("User", $evt.User)
                $output.add("ParentImage", $evt.ParentImage)
                $output.add("ParentCommandLine", $evt.ParentCommandLine)
                $output.add("ParentUser", $evt.ParentUser)
                write-alert $output
            }
            if ($evt.id -eq 3) {
                $output = @{}
                $output.add("Type", "Network Connection")
                $output.add("Image", $evt.Image)
                $output.add("DestinationIp", $evt.DestinationIp)
                $output.add("DestinationPort", $evt.DestinationPort)                           
                $output.add("DestinationHost", $evt.DestinationHostname)
                write-alert $output
            }
            if ($evt.id -eq 11) {
                $output = @{}
                $output.add("Type", "File Create")
                $output.add("RecordID", $evt.RecordID)
                $output.add("TargetFilename", $evt.TargetFileName)
                $output.add("User", $evt.User)
                $output.add("Process", $evt.Image)
                $output.add("PID", $evt.ProcessID)                
                write-alert $output
            }
            if ($evt.id -eq 23) {
                $output = @{}
                $output.add("Type", "File Delete")
                $output.add("RecordID", $evt.RecordID)
                $output.add("TargetFilename", $evt.TargetFileName)
                $output.add("User", $evt.User)
                $output.add("Process", $evt.Image)
                $output.add("PID", $evt.ProcessID)                
                write-alert $output
            }
            
        }
        $index = $NewIndex
    }
}
