################################################################################
##
## dsp-BreakAD-Logging.psm1
##
## Shared logging functionality for dsp-BreakAD modules
##
## Author: Bob Lyons
## Version: 1.0.0-20251204
##
################################################################################

function Write-Log {
    <#
    .SYNOPSIS
        Writes a log message to both console and log file
    
    .PARAMETER Message
        Message to log
    
    .PARAMETER Level
        Log level (INFO, SUCCESS, WARNING, ERROR)
    #>
    param(
        [string]$Message,
        [ValidateSet('INFO', 'SUCCESS', 'WARNING', 'ERROR')]
        [string]$Level = 'INFO'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Write to console with color
    switch ($Level) {
        'SUCCESS' { Write-Host $logMessage -ForegroundColor Green }
        'WARNING' { Write-Host $logMessage -ForegroundColor Yellow }
        'ERROR' { Write-Host $logMessage -ForegroundColor Red }
        default { Write-Host $logMessage }
    }
    
    # Write to log file if available
    if ($global:LogFile) {
        Add-Content -Path $global:LogFile -Value $logMessage -ErrorAction SilentlyContinue
    }
}

Export-ModuleMember -Function Write-Log