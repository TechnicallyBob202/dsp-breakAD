################################################################################
##
## dsp-BreakAD-Logging.psm1
##
## Shared logging functionality for dsp-breakAD
## Writes to console and structured log files
##
## Author: Bob Lyons (bob@semperis.com)
## Version: 1.0.0
##
################################################################################

# Initialize global log file path (set by main script)
$global:LogFilePath = $null

################################################################################
# Initialize-Logging
################################################################################

function Initialize-Logging {
    <#
    .SYNOPSIS
        Initialize the logging system and create log directory/file
    
    .PARAMETER LogsDirectory
        Path to logs directory (will be created if doesn't exist)
    
    .OUTPUTS
        Full path to log file
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$LogsDirectory
    )
    
    # Create logs directory if it doesn't exist
    if (-not (Test-Path $LogsDirectory)) {
        New-Item -ItemType Directory -Path $LogsDirectory -Force -ErrorAction SilentlyContinue | Out-Null
    }
    
    # Create log file with timestamp
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $logFile = Join-Path $LogsDirectory "dsp-breakAD-$timestamp.log"
    
    # Write header to log file
    $header = @"
================================================================================
dsp-breakAD Execution Log
Started: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Host: $env:COMPUTERNAME
User: $env:USERNAME
Domain: $(Get-ADDomain -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
================================================================================

"@
    
    Add-Content -Path $logFile -Value $header -ErrorAction SilentlyContinue
    
    # Set global log file path
    $global:LogFilePath = $logFile
    
    return $logFile
}

################################################################################
# Write-Log
################################################################################

function Write-Log {
    <#
    .SYNOPSIS
        Write a log message to console and log file
    
    .PARAMETER Message
        The message to log
    
    .PARAMETER Level
        Log level: INFO, SUCCESS, WARNING, ERROR
    
    .PARAMETER NoNewline
        If true, don't add newline after message
    #>
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [AllowEmptyString()]
        [string]$Message,
        
        [ValidateSet('INFO', 'SUCCESS', 'WARNING', 'ERROR')]
        [string]$Level = 'INFO',
        
        [switch]$NoNewline
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Console output with colors
    $color = switch ($Level) {
        'SUCCESS' { 'Green' }
        'WARNING' { 'Yellow' }
        'ERROR' { 'Red' }
        default { 'White' }
    }
    
    if ($NoNewline) {
        Write-Host $logMessage -ForegroundColor $color -NoNewline
    }
    else {
        Write-Host $logMessage -ForegroundColor $color
    }
    
    # File output
    if ($global:LogFilePath -and (Test-Path $global:LogFilePath)) {
        Add-Content -Path $global:LogFilePath -Value $logMessage -ErrorAction SilentlyContinue
    }
}

################################################################################
# Write-LogSection
################################################################################

function Write-LogSection {
    <#
    .SYNOPSIS
        Write a section header to log
    
    .PARAMETER Title
        Section title
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Title
    )
    
    $separator = "=" * 80
    Write-Log $separator -Level INFO
    Write-Log $Title -Level INFO
    Write-Log $separator -Level INFO
}

################################################################################
# Write-LogChange
################################################################################

function Write-LogChange {
    <#
    .SYNOPSIS
        Log an AD change with object, attribute, old value, new value
    
    .PARAMETER Object
        Object being changed (user, group, etc.)
    
    .PARAMETER Attribute
        Attribute name
    
    .PARAMETER OldValue
        Previous value (optional)
    
    .PARAMETER NewValue
        New value
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Object,
        
        [Parameter(Mandatory=$true)]
        [string]$Attribute,
        
        [string]$OldValue = "N/A",
        
        [Parameter(Mandatory=$true)]
        [string]$NewValue
    )
    
    $changeMessage = "CHANGE | Object: $Object | Attribute: $Attribute | Old: $OldValue | New: $NewValue"
    Write-Log $changeMessage -Level INFO
}

################################################################################
# Close-Logging
################################################################################

function Close-Logging {
    <#
    .SYNOPSIS
        Finalize logging and write footer
    #>
    
    $footer = @"

================================================================================
Execution Completed: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Log File: $global:LogFilePath
================================================================================
"@
    
    if ($global:LogFilePath -and (Test-Path $global:LogFilePath)) {
        Add-Content -Path $global:LogFilePath -Value $footer -ErrorAction SilentlyContinue
    }
    
    Write-Log $footer -Level INFO
}

################################################################################
# Export Functions
################################################################################

Export-ModuleMember -Function @(
    'Initialize-Logging',
    'Write-Log',
    'Write-LogSection',
    'Write-LogChange',
    'Close-Logging'
)