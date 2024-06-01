#start/stop service needs administrative permissions
#return codes:
#2: error within stopUpdateService
#3: error within removing the SoftwareDistribution Folder

function stopUpdateService($started, $service) {
    #stop the update service if it is running. Try 2 times or until the output of Stop-Service shows the service is stopped
    $tried = 0

    while ($started -eq "Running" -and $tried -lt 2) {
        $started = (Stop-Service -Name $service -Force -PassThru).Status
        $tried += 1
        Start-Sleep -Seconds 2
    }

    if ($tried -eq 2) {
        exit 2
    }

}

function startUpdateService($service) {
    $running = $false
    $tried = 0
    while ($running -eq $false -and $tried -lt 2) {
        $started = (Start-Service -Name $service -PassThru).Status

        Start-Sleep -Seconds 2
        
        if ($started -eq "Running") {
            exit 0
        }

        $tried += 1

    }
}

stopUpdateService -started (Get-Service -Name "wuauserv").Status -service "wuauserv"
stopUpdateService -started (Get-Service -Name "bits").Status -service "bits"

if (Test-Path -Path "C:\Windows\SoftwareDistribution") {
    #Remove-Item does not return anything
    Remove-Item -Path "C:\Windows\SoftwareDistribution" -Recurse

    #if folder still exists
    if (Test-Path -Path "C:\Windows\SoftwareDistribution") {
        exit 3
    }
}

startUpdateService -service "wuauserv"
startUpdateService -service "bits"
