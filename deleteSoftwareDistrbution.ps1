#start/stop service needs administrative permissions
#return codes:
#2: error within stopUpdateService
#3: error within removing the SoftwareDistribution Folder
#4: error within renaming the files before deleting them
#5: could not remove lock on file

function Get-FileLockProcess {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$FilePath
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if (! $(Test-Path $FilePath)) {
        Write-Error "The path $FilePath was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    if ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.Platform -eq "Win32NT" -or 
    $($PSVersionTable.PSVersion.Major -le 5 -and $PSVersionTable.PSVersion.Major -ge 3)) {
        $CurrentlyLoadedAssemblies = [System.AppDomain]::CurrentDomain.GetAssemblies()
    
        $AssembliesFullInfo = $CurrentlyLoadedAssemblies | Where-Object {
            $_.GetName().Name -eq "Microsoft.CSharp" -or
            $_.GetName().Name -eq "mscorlib" -or
            $_.GetName().Name -eq "System" -or
            $_.GetName().Name -eq "System.Collections" -or
            $_.GetName().Name -eq "System.Core" -or
            $_.GetName().Name -eq "System.IO" -or
            $_.GetName().Name -eq "System.Linq" -or
            $_.GetName().Name -eq "System.Runtime" -or
            $_.GetName().Name -eq "System.Runtime.Extensions" -or
            $_.GetName().Name -eq "System.Runtime.InteropServices"
        }
        $AssembliesFullInfo = $AssembliesFullInfo | Where-Object {$_.IsDynamic -eq $False}
  
        $ReferencedAssemblies = $AssembliesFullInfo.FullName | Sort-Object | Get-Unique

        $usingStatementsAsString = @"
        using Microsoft.CSharp;
        using System.Collections.Generic;
        using System.Collections;
        using System.IO;
        using System.Linq;
        using System.Runtime.InteropServices;
        using System.Runtime;
        using System;
        using System.Diagnostics;
"@
        
        $TypeDefinition = @"
        $usingStatementsAsString
        
        namespace MyCore.Utils
        {
            static public class FileLockUtil
            {
                [StructLayout(LayoutKind.Sequential)]
                struct RM_UNIQUE_PROCESS
                {
                    public int dwProcessId;
                    public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime;
                }
        
                const int RmRebootReasonNone = 0;
                const int CCH_RM_MAX_APP_NAME = 255;
                const int CCH_RM_MAX_SVC_NAME = 63;
        
                enum RM_APP_TYPE
                {
                    RmUnknownApp = 0,
                    RmMainWindow = 1,
                    RmOtherWindow = 2,
                    RmService = 3,
                    RmExplorer = 4,
                    RmConsole = 5,
                    RmCritical = 1000
                }
        
                [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
                struct RM_PROCESS_INFO
                {
                    public RM_UNIQUE_PROCESS Process;
        
                    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_APP_NAME + 1)]
                    public string strAppName;
        
                    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_SVC_NAME + 1)]
                    public string strServiceShortName;
        
                    public RM_APP_TYPE ApplicationType;
                    public uint AppStatus;
                    public uint TSSessionId;
                    [MarshalAs(UnmanagedType.Bool)]
                    public bool bRestartable;
                }
        
                [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
                static extern int RmRegisterResources(uint pSessionHandle,
                                                    UInt32 nFiles,
                                                    string[] rgsFilenames,
                                                    UInt32 nApplications,
                                                    [In] RM_UNIQUE_PROCESS[] rgApplications,
                                                    UInt32 nServices,
                                                    string[] rgsServiceNames);
        
                [DllImport("rstrtmgr.dll", CharSet = CharSet.Auto)]
                static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, string strSessionKey);
        
                [DllImport("rstrtmgr.dll")]
                static extern int RmEndSession(uint pSessionHandle);
        
                [DllImport("rstrtmgr.dll")]
                static extern int RmGetList(uint dwSessionHandle,
                                            out uint pnProcInfoNeeded,
                                            ref uint pnProcInfo,
                                            [In, Out] RM_PROCESS_INFO[] rgAffectedApps,
                                            ref uint lpdwRebootReasons);
        
                /// <summary>
                /// Find out what process(es) have a lock on the specified file.
                /// </summary>
                /// <param name="path">Path of the file.</param>
                /// <returns>Processes locking the file</returns>
                /// <remarks>See also:
                /// http://msdn.microsoft.com/en-us/library/windows/desktop/aa373661(v=vs.85).aspx
                /// http://wyupdate.googlecode.com/svn-history/r401/trunk/frmFilesInUse.cs (no copyright in code at time of viewing)
                /// 
                /// </remarks>
                static public List<Process> WhoIsLocking(string path)
                {
                    uint handle;
                    string key = Guid.NewGuid().ToString();
                    List<Process> processes = new List<Process>();
        
                    int res = RmStartSession(out handle, 0, key);
                    if (res != 0) throw new Exception("Could not begin restart session.  Unable to determine file locker.");
        
                    try
                    {
                        const int ERROR_MORE_DATA = 234;
                        uint pnProcInfoNeeded = 0,
                            pnProcInfo = 0,
                            lpdwRebootReasons = RmRebootReasonNone;
        
                        string[] resources = new string[] { path }; // Just checking on one resource.
        
                        res = RmRegisterResources(handle, (uint)resources.Length, resources, 0, null, 0, null);
        
                        if (res != 0) throw new Exception("Could not register resource.");                                    
        
                        //Note: there's a race condition here -- the first call to RmGetList() returns
                        //      the total number of process. However, when we call RmGetList() again to get
                        //      the actual processes this number may have increased.
                        res = RmGetList(handle, out pnProcInfoNeeded, ref pnProcInfo, null, ref lpdwRebootReasons);
        
                        if (res == ERROR_MORE_DATA)
                        {
                            // Create an array to store the process results
                            RM_PROCESS_INFO[] processInfo = new RM_PROCESS_INFO[pnProcInfoNeeded];
                            pnProcInfo = pnProcInfoNeeded;
        
                            // Get the list
                            res = RmGetList(handle, out pnProcInfoNeeded, ref pnProcInfo, processInfo, ref lpdwRebootReasons);
                            if (res == 0)
                            {
                                processes = new List<Process>((int)pnProcInfo);
        
                                // Enumerate all of the results and add them to the 
                                // list to be returned
                                for (int i = 0; i < pnProcInfo; i++)
                                {
                                    try
                                    {
                                        processes.Add(Process.GetProcessById(processInfo[i].Process.dwProcessId));
                                    }
                                    // catch the error -- in case the process is no longer running
                                    catch (ArgumentException) { }
                                }
                            }
                            else throw new Exception("Could not list processes locking resource.");                    
                        }
                        else if (res != 0) throw new Exception("Could not list processes locking resource. Failed to get size of result.");                    
                    }
                    finally
                    {
                        RmEndSession(handle);
                    }
        
                    return processes;
                }
            }
        }
"@

        $CheckMyCoreUtilsFileLockUtilLoaded = $CurrentlyLoadedAssemblies | Where-Object {$_.ExportedTypes -like "MyCore.Utils.FileLockUtil*"}
        if ($CheckMyCoreUtilsFileLockUtilLoaded -eq $null) {
            Add-Type -ReferencedAssemblies $ReferencedAssemblies -TypeDefinition $TypeDefinition
        }
        else {
            Write-Verbose "The Namespace MyCore.Utils Class FileLockUtil is already loaded and available!"
        }

        $Result = [MyCore.Utils.FileLockUtil]::WhoIsLocking($FilePath)
    }

    $Result
    
}
function stopUpdateService($started, $service) {
    #stop the update service if it is running. Try 2 times or until the output of Stop-Service shows the service is stopped
    $tried = 0

    while ($started -eq "Running" -and $tried -lt 2) {
        $started = (Stop-Service -Name $service -Force -PassThru -WarningAction:SilentlyContinue).Status
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
        #Supress Warning with -WarningAction: WARNING: Waiting for service 'Background Intelligent Transfer Service (bits)' to start...
        $started = (Start-Service -Name $service -PassThru -WarningAction:SilentlyContinue).Status

        Start-Sleep -Seconds 2
        
        if ($started -eq "Running") {
            break
        }

        $tried += 1

    }
}

function checkFileLocked($file) {

    $locked = $false

    If ([System.IO.File]::Exists($file)) {
        Try {
            $FileStream = [System.IO.File]::Open($file,'Open','Write')
      
            $FileStream.Close()
            $FileStream.Dispose()
      
            
        } Catch [System.UnauthorizedAccessException] {
            $locked = $true
        } Catch {
            $locked = $True
        }
      }

      return $locked

}

function removeLock($file) {
    
    Start-Sleep 10 #wait 10 seconds then if it is still locked, terminate the process locking it

    if (checkFileLocked -file $file) {
        $id = (Get-FileLockProcess -FilePath $file).Id

        Stop-Process -Id $id -Force

        Start-Sleep 2

        $runningProcesses = Get-Process *
        foreach ($process in $runningProcesses) {
            if ($process.Id -eq $id) {
                exit 5
            }
        }
    }
}

#Windows has a problem with deleting files because the names are greater than 260 characters.  
function renameFiles($dir) {
    #recursive function that renames all files within the directory
    $allFiles = (Get-ChildItem -path $dir).Name

    foreach ($name in $allFiles) {
        $full = $dir + "\" + $name
        $isFolder = (Get-Item -Path $full) -is [System.IO.DirectoryInfo]

        if ($isFolder) {
            #recurse
            renameFiles -dir $full
        }

        $new = -join ((65..90) + (97..122) | Get-Random -count 5 | ForEach-Object {[char]$_})

        if (checkFileLocked -file $full) {
            
            removeLock -file $full

        }

        $renamed = Rename-Item -Path $full -NewName $new -Force -PassThru 

        if ($renamed.Name -ne $new) {
            #prevent looping
            exit 4
        }
    }
  
}

stopUpdateService -started (Get-Service -Name "wuauserv").Status -service "wuauserv"
stopUpdateService -started (Get-Service -Name "bits").Status -service "bits"
stopUpdateService -started (Get-Service -Name "cryptsvc").Status -service "cryptsvc"

if (Test-Path -Path "C:\Windows\SoftwareDistribution") {
    
    renameFiles -dir "C:\Windows\SoftwareDistribution"
    
    #Remove-Item does not return anything
    Remove-Item -Path "C:\Windows\SoftwareDistribution" -Recurse

    #if folder still exists
    if (Test-Path -Path "C:\Windows\SoftwareDistribution") {
        exit 3
    }
}

startUpdateService -service "wuauserv"
startUpdateService -service "bits"
startUpdateService -service "cryptsvc"

#some data store files do not get released by an svchost process if an update is currently installing/downloading so go ahead and try to find it and terminate it
