#Requires -Version 5.1
<#
.SYNOPSIS
    A conceptual PowerShell script for system monitoring and control,
    designed for continuous operation with basic self-healing and
    placeholders for advanced features like voice control and self-improvement.

.DESCRIPTION
    This script provides a framework for an interactive system management tool.
    It runs in a continuous loop, accepting commands to monitor system resources,
    control processes, and perform other administrative tasks. It includes
    error handling to allow it to recover from some issues and logs its
    activities and any identified areas for potential improvement.

    Features:
    - Continuous operation loop.
    - Terminal-based command input.
    - System Monitoring: CPU, Memory, Disk, Process status.
    - System Control: Start/Stop processes (example).
    - Logging: Actions, errors, performance metrics.
    - Basic Self-Healing: Try-Catch blocks for error resilience.
    - Conceptual Self-Improvement: Logs data that could be used for manual
      or (in a more advanced system) automated analysis of its own performance
      and reliability.
    - Conceptual Voice Input: Comments on how voice input might be integrated.

.NOTES
    Author: Gemini
    Version: 0.1 (Conceptual Framework)

    Disclaimer: True AI-driven self-improvement and robust voice control are
    highly complex and typically require external AI models and speech engines,
    which are beyond the scope of this standalone script. This script provides
    a foundational structure and ideas.
#>

#region Configuration
$LogFilePath = Join-Path -Path $PSScriptRoot -ChildPath "SystemMonitorLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$ErrorLogPath = Join-Path -Path $PSScriptRoot -ChildPath "SystemMonitorErrorLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$ImprovementLogPath = Join-Path -Path $PSScriptRoot -ChildPath "SystemMonitorImprovementLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

$MaxCpuThreshold = 85 # Percent
$MaxMemoryThreshold = 85 # Percent (Available Memory)
$MinDiskSpaceThresholdGB = 20 # GB

# Store performance and error data for "self-improvement" analysis
$ScriptPerformanceData = @{
    CommandExecutionTimes = @{} # Store average execution time per command
    CommandErrorCounts    = @{}   # Store error counts per command
    LastAnalysisTime      = Get-Date
}
#endregion Configuration

#region Helper Functions
function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [string]$Path = $LogFilePath,
        [switch]$IsError,
        [switch]$IsImprovementSuggestion
    )
    $Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $LogEntry = "$Timestamp - $Message"
    try {
        Add-Content -Path $Path -Value $LogEntry -ErrorAction Stop
        if ($IsError) {
            Write-Host "ERROR: $Message" -ForegroundColor Red
        }
        elseif ($IsImprovementSuggestion) {
            Write-Host "IMPROVEMENT SUGGESTION: $Message" -ForegroundColor Yellow
        }
        else {
            Write-Host $LogEntry -ForegroundColor Cyan
        }
    }
    catch {
        Write-Warning "Failed to write to log file: $Path. Error: $($_.Exception.Message)"
    }
}

function Start-TranscriptIfNecessary {
    if (-not (Get-Transcript)) {
        try {
            Start-Transcript -Path $LogFilePath -Append -Force -ErrorAction Stop
            Write-Log "Transcript started."
        }
        catch {
            Write-Warning "Could not start transcript: $($_.Exception.Message)"
        }
    }
}

function Stop-TranscriptIfRunning {
    if (Get-Transcript) {
        try {
            Stop-Transcript -ErrorAction Stop
            # Write-Log "Transcript stopped." # This might not get logged if transcript just stopped
        }
        catch {
            Write-Warning "Error stopping transcript: $($_.Exception.Message)"
        }
    }
}

#endregion Helper Functions

#region Monitoring Functions
function Get-SystemPerformance {
    Write-Log "Fetching system performance..."
    try {
        $CpuUsage = (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples[0].CookedValue
        $Memory = Get-CimInstance Win32_OperatingSystem
        $TotalMemoryGB = [math]::Round($Memory.TotalVisibleMemorySize / 1MB, 2)
        $FreeMemoryGB = [math]::Round($Memory.FreePhysicalMemory / 1MB, 2)
        $UsedMemoryGB = $TotalMemoryGB - $FreeMemoryGB
        $MemoryUsagePercent = [math]::Round(($UsedMemoryGB / $TotalMemoryGB) * 100, 2)

        Write-Host "CPU Usage: $($CpuUsage)% " -ForegroundColor Green
        Write-Host "Memory Usage: $($UsedMemoryGB)GB / $($TotalMemoryGB)GB ($($MemoryUsagePercent)%)" -ForegroundColor Green

        if ($CpuUsage -gt $MaxCpuThreshold) {
            Write-Log "ALERT: CPU usage ($($CpuUsage)%) exceeds threshold ($($MaxCpuThreshold)%)" -IsError
            # Potential self-healing/control action: Log more details, identify top processes
        }
        if ($MemoryUsagePercent -gt $MaxMemoryThreshold) {
            Write-Log "ALERT: Memory usage ($($MemoryUsagePercent)%) exceeds threshold ($($MaxMemoryThreshold)%)" -IsError
            # Potential self-healing/control action: Log more details, identify top processes
        }
    }
    catch {
        Write-Log "Error getting system performance: $($_.Exception.Message)" -IsError -Path $ErrorLogPath
    }
}

function Get-DiskSpace {
    [CmdletBinding()]
    param (
        [string]$DriveLetter = "C"
    )
    Write-Log "Fetching disk space for drive $DriveLetter..."
    try {
        $Disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$($DriveLetter):'"
        if ($Disk) {
            $FreeSpaceGB = [math]::Round($Disk.FreeSpace / 1GB, 2)
            $TotalSizeGB = [math]::Round($Disk.Size / 1GB, 2)
            $PercentFree = [math]::Round(($FreeSpaceGB / $TotalSizeGB) * 100, 2)
            Write-Host "Disk $($DriveLetter): - Free: $($FreeSpaceGB)GB / Total: $($TotalSizeGB)GB ($($PercentFree)% free)" -ForegroundColor Green

            if ($FreeSpaceGB -lt $MinDiskSpaceThresholdGB) {
                Write-Log "ALERT: Low disk space on drive $DriveLetter ($($FreeSpaceGB)GB) below threshold ($($MinDiskSpaceThresholdGB)GB)" -IsError
                # Potential self-healing/control action: Trigger cleanup script, notify admin
            }
        }
        else {
            Write-Log "Drive $DriveLetter not found." -IsError -Path $ErrorLogPath
        }
    }
    catch {
        Write-Log "Error getting disk space for $DriveLetter: $($_.Exception.Message)" -IsError -Path $ErrorLogPath
    }
}

function Get-ProcessStatus {
    [CmdletBinding()]
    param (
        [string]$ProcessName
    )
    Write-Log "Checking status of process '$ProcessName'..."
    try {
        $Process = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue
        if ($Process) {
            Write-Host "Process '$ProcessName' is RUNNING (PID: $($Process.Id))" -ForegroundColor Green
            return $true
        }
        else {
            Write-Host "Process '$ProcessName' is NOT RUNNING." -ForegroundColor Yellow
            return $false
        }
    }
    catch {
        Write-Log "Error checking process status for '$ProcessName': $($_.Exception.Message)" -IsError -Path $ErrorLogPath
        return $false
    }
}
#endregion Monitoring Functions

#region Control Functions
function Start-MonitoredProcess {
    [CmdletBinding()]
    param (
        [string]$ProcessPath, # Full path to executable
        [string]$Arguments
    )
    Write-Log "Attempting to start process '$ProcessPath'..."
    try {
        if (-not (Test-Path $ProcessPath)) {
            Write-Log "Error: Executable not found at '$ProcessPath'" -IsError -Path $ErrorLogPath
            return
        }
        Start-Process -FilePath $ProcessPath -ArgumentList $Arguments -NoNewWindow
        Write-Log "Process '$ProcessPath' started successfully."
    }
    catch {
        Write-Log "Error starting process '$ProcessPath': $($_.Exception.Message)" -IsError -Path $ErrorLogPath
    }
}

function Stop-MonitoredProcess {
    [CmdletBinding()]
    param (
        [string]$ProcessName
    )
    Write-Log "Attempting to stop process '$ProcessName'..."
    try {
        $Process = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue
        if ($Process) {
            Stop-Process -Name $ProcessName -Force
            Write-Log "Process '$ProcessName' stopped successfully."
        }
        else {
            Write-Log "Process '$ProcessName' not found or already stopped." -IsError -Path $ErrorLogPath
        }
    }
    catch {
        Write-Log "Error stopping process '$ProcessName': $($_.Exception.Message)" -IsError -Path $ErrorLogPath
    }
}
#endregion Control Functions

#region Self-Healing and Improvement Concepts
function AnalyzeScriptPerformanceAndErrors {
    Write-Log "Analyzing script performance and error logs for improvement opportunities..." -Path $ImprovementLogPath

    # Example: Identify commands that frequently error
    foreach ($command in $ScriptPerformanceData.CommandErrorCounts.GetEnumerator() | Sort-Object Value -Descending) {
        if ($command.Value -gt 5) {
            # Arbitrary threshold for "frequent" errors
            $Suggestion = "Command '$($command.Name)' has errored $($command.Value) times. Consider reviewing its implementation or usage."
            Write-Log $Suggestion -IsImprovementSuggestion -Path $ImprovementLogPath
        }
    }

    # Example: Identify slow commands
    foreach ($command in $ScriptPerformanceData.CommandExecutionTimes.GetEnumerator() | Sort-Object Value -Descending) {
        if ($command.Value -gt 1000) {
            # Arbitrary threshold for "slow" in ms
            $Suggestion = "Command '$($command.Name)' has an average execution time of $($command.Value)ms. Consider optimizing."
            Write-Log $Suggestion -IsImprovementSuggestion -Path $ImprovementLogPath
        }
    }

    # This is a very basic example. True self-improvement would involve:
    # - More sophisticated analysis of logs and patterns.
    # - Identifying root causes of errors or inefficiencies.
    # - Potentially A/B testing different approaches for functions.
    # - Dynamically adjusting parameters or logic based on observed system behavior.
    # - For actual code modification: parsing its own script, making changes, testing, and deploying. This is extremely advanced.

    $ScriptPerformanceData.LastAnalysisTime = Get-Date
    Write-Log "Self-analysis complete. Suggestions logged to: $ImprovementLogPath"
}

function RecordCommandMetrics {
    [CmdletBinding()]
    param(
        [string]$CommandName,
        [TimeSpan]$ExecutionTime,
        [bool]$HadError
    )

    # Record execution time
    if (-not $ScriptPerformanceData.CommandExecutionTimes.ContainsKey($CommandName)) {
        $ScriptPerformanceData.CommandExecutionTimes[$CommandName] = @{ Count = 0; TotalTimeMs = 0 }
    }
    $ScriptPerformanceData.CommandExecutionTimes[$CommandName].Count++
    $ScriptPerformanceData.CommandExecutionTimes[$CommandName].TotalTimeMs += $ExecutionTime.TotalMilliseconds
    # Could calculate average on the fly or during analysis

    # Record error
    if ($HadError) {
        if (-not $ScriptPerformanceData.CommandErrorCounts.ContainsKey($CommandName)) {
            $ScriptPerformanceData.CommandErrorCounts[$CommandName] = 0
        }
        $ScriptPerformanceData.CommandErrorCounts[$CommandName]++
    }
}
#endregion Self-Healing and Improvement Concepts

#region Voice Input Placeholder
function Get-VoiceCommand {
    # This is a placeholder. True voice input requires:
    # 1. Windows SAPI (System.Speech assembly):
    #    Add-Type -AssemblyName System.Speech
    #    $recognizer = New-Object System.Speech.Recognition.SpeechRecognitionEngine
    #    $recognizer.LoadGrammar(...) # Define grammar for commands
    #    $recognizer.SetInputToDefaultAudioDevice()
    #    $result = $recognizer.Recognize() # This is synchronous, async is better for continuous listening
    #    if ($result) { return $result.Text }
    #
    # 2. Or, integration with an external voice-to-text service/API.
    #    This would involve sending audio data to an API and receiving text.
    #
    # For now, this function does nothing and commands must be typed.
    Write-Log "Voice input not implemented. Please use terminal." -IsError
    return $null
}
#endregion Voice Input Placeholder

#region Main Script Logic
function Main {
    Start-TranscriptIfNecessary
    Write-Log "System Monitoring and Control Script Initialized."
    Write-Log "Type 'help' for available commands, 'exit' to quit."

    $isRunning = $true
    while ($isRunning) {
        try {
            # --- Input Handling ---
            # Prioritize voice if it were implemented and active.
            # $voiceInput = Get-VoiceCommand
            # $commandInput = if ($voiceInput) { $voiceInput } else { Read-Host "SysControl>" }
            $commandInput = Read-Host "SysControl>"

            if ([string]::IsNullOrWhiteSpace($commandInput)) {
                continue
            }

            $commandStartTime = Get-Date
            $commandParts = $commandInput.Trim() -split '\s+', 2 # Split into command and the rest as arguments
            $command = $commandParts[0].ToLower()
            $arguments = if ($commandParts.Length -gt 1) { $commandParts[1] } else { $null }
            $commandHadError = $false

            # --- Command Processing ---
            switch ($command) {
                "help" {
                    Write-Host @"
Available Commands:
  monitor cpu/mem      - Display current CPU and Memory usage.
  monitor disk [C|D|...] - Display disk space for specified drive (default C).
  monitor process <name> - Check if a process is running.
  control start <path_to_exe> [args] - Start a process.
  control stop <name>    - Stop a process by name.
  analyze self           - Run a basic analysis of script performance/errors for improvement ideas.
  log <message>          - Write a custom message to the main log.
  clear                  - Clear the console.
  exit                   - Exit the script.
"@ -ForegroundColor White
                }
                "monitor" {
                    if ($arguments -match "^(cpu|mem)") { Get-SystemPerformance }
                    elseif ($arguments -match "^disk(?:\s+(\w))?") { Get-DiskSpace -DriveLetter $matches[1] } # Optional drive letter
                    elseif ($arguments -match "^process\s+(.+)") { Get-ProcessStatus -ProcessName $matches[1].Trim() }
                    else { Write-Log "Invalid monitor command. Usage: monitor cpu/mem | disk [drive] | process <name>" -IsError }
                }
                "control" {
                    if ($arguments -match "^start\s+([`"']?)(.+?)\1(?:\s+(.*))?$") {
                        # Handle quoted paths and optional args
                        $exePath = $matches[2].Trim()
                        $exeArgs = if ($matches[3]) { $matches[3].Trim() } else { $null }
                        Start-MonitoredProcess -ProcessPath $exePath -Arguments $exeArgs
                    }
                    elseif ($arguments -match "^stop\s+(.+)") { Stop-MonitoredProcess -ProcessName $matches[1].Trim() }
                    else { Write-Log "Invalid control command. Usage: control start <path> [args] | stop <name>" -IsError }
                }
                "analyze" {
                    if ($arguments -eq "self") { AnalyzeScriptPerformanceAndErrors }
                    else { Write-Log "Invalid analyze command. Usage: analyze self" -IsError }
                }
                "log" {
                    if ($arguments) { Write-Log "USER LOG: $arguments" }
                    else { Write-Log "Usage: log <message_to_log>" -IsError }
                }
                "clear" { Clear-Host }
                "cls" { Clear-Host } # Alias for clear
                "exit" {
                    Write-Log "Exiting script."
                    $isRunning = $false
                }
                default {
                    Write-Log "Unknown command: '$command'. Type 'help' for available commands." -IsError
                    $commandHadError = $true
                }
            } # End Switch

            $commandEndTime = Get-Date
            RecordCommandMetrics -CommandName $command -ExecutionTime ($commandEndTime - $commandStartTime) -HadError $commandHadError

            # --- Periodic Tasks (Example: Self-Analysis) ---
            if ((Get-Date) -gt ($ScriptPerformanceData.LastAnalysisTime.AddHours(1))) {
                # Analyze every hour
                AnalyzeScriptPerformanceAndErrors
            }

        } # End Try for main loop iteration
        catch {
            # This is a basic "self-healing" attempt for the main loop.
            # It logs the error and continues the loop, rather than crashing the script.
            $ErrorMessage = "CRITICAL SCRIPT ERROR in main loop: $($_.Exception.Message) at $($_.InvocationInfo.ScriptLineNumber)"
            Write-Log $ErrorMessage -IsError -Path $ErrorLogPath
            Write-Host $ErrorMessage -ForegroundColor Magenta
            # For more advanced self-healing, it might try to re-initialize certain components
            # or restart a specific failed module if the error is identifiable.
        }
    } # End While $isRunning

    Write-Log "System Monitoring and Control Script Shutting Down."
    Stop-TranscriptIfRunning
}
#endregion Main Script Logic

# --- Script Entry Point ---
# Trap Ctrl+C to ensure clean shutdown
trap [System.Management.Automation.PipelineStoppedException] {
    Write-Log "Ctrl+C detected. Shutting down gracefully..." -ForegroundColor Yellow
    Stop-TranscriptIfRunning
    # Perform any other cleanup here
    exit
}

# Run the main function
Main
