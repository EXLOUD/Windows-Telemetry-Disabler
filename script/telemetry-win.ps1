#Requires -RunAsAdministrator
[CmdletBinding()] param()

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

# region --- Safe-colour helper ----------------------------------------------
$script:__supportsColour = try {
    $null -ne $Host.UI.RawUI.ForegroundColor -and $null -ne $Host.PrivateData
} catch { $false }

function Write-HostEx {
    param(
        [Parameter(Mandatory)][string]$Message,
        [System.ConsoleColor]$ForegroundColor = [System.ConsoleColor]::White
    )
    if ($script:__supportsColour) {
        Microsoft.PowerShell.Utility\Write-Host $Message -ForegroundColor $ForegroundColor
    } else {
        Microsoft.PowerShell.Utility\Write-Host $Message
    }
}
# endregion

# Statistics
$script:Stats = @{
    RegistryApplied   = 0
    RegistrySkipped   = 0
    RegistryFailed    = 0
    ServicesDisabled  = 0
    ServicesNotFound  = 0
    ServicesFailed    = 0
    TasksDisabled     = 0
    TasksNotFound     = 0
    TasksFailed       = 0
    FeaturesDisabled  = 0
    FeaturesNotFound  = 0
    FeaturesFailed    = 0
    ItemsRemoved      = 0
    ItemsNotFound     = 0
    ItemsFailed       = 0
}

function Set-RegistryValue {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][object]$Value,
        [string]$Type = 'DWord'
    )

    try {
        if (!(Test-Path $Path)) {
            if ($PSCmdlet.ShouldProcess($Path, 'Create key')) {
                Write-HostEx "  [+] Creating key: $Path" -ForegroundColor Yellow
                New-Item -Path $Path -Force | Out-Null
            }
        }

        $current = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        $currentVal = if ($Name -eq '(Default)') { (Get-Item -LiteralPath $Path).GetValue('') } else { $current.$Name }

        if ($Type -eq 'ExpandString' -and $currentVal -is [string]) {
            $currentVal = [System.Environment]::ExpandEnvironmentVariables($currentVal)
            $desiredVal = [System.Environment]::ExpandEnvironmentVariables($Value)
        } else {
            $desiredVal = $Value
        }

        if ($null -ne $currentVal -and "$currentVal" -eq "$desiredVal") {
            Write-HostEx "  [ SKIP ] Already set: $Name = $desiredVal" -ForegroundColor Gray
            $script:Stats.RegistrySkipped++
            return
        }

        $target = "$Path\$Name"
        if ($PSCmdlet.ShouldProcess($target, "Set $desiredVal (Type=$Type)")) {
            if ($Name -eq '(Default)') {
                # (Default) задається через Set-Item
                Set-Item -LiteralPath $Path -Value $Value -Force
            } else {
                Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
            }
            Write-HostEx "  [ OK ] Applied: $Path\$Name = $desiredVal" -ForegroundColor Green
            $script:Stats.RegistryApplied++
        }
    }
    catch {
        Write-HostEx "  [ ERROR ] Error setting $Name`: $_" -ForegroundColor Red
        $script:Stats.RegistryFailed++
    }
}

function Disable-ServiceSafely {
    param([string]$ServiceName)
    try {
        $svc = Get-Service $ServiceName -ErrorAction Stop

        if ($svc.Status -eq 'Running') {
            Write-HostEx "  [i] Stopping service: $ServiceName" -ForegroundColor Yellow
            Stop-Service $ServiceName -Force -ErrorAction Stop
        }

        if ($svc.StartType -ne 'Disabled') {
            Write-HostEx "  [ OK ] Disabling service: $ServiceName" -ForegroundColor Green
            Set-Service $ServiceName -StartupType Disabled
            $script:Stats.ServicesDisabled++
        } else {
            Write-HostEx "  [ SKIP ] Service already disabled: $ServiceName" -ForegroundColor Gray
        }

        sc.exe delete $ServiceName 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-HostEx "  [ OK ] Service deleted: $ServiceName" -ForegroundColor Green
        } else {
            Write-HostEx "  [i] Service marked for deletion: $ServiceName" -ForegroundColor Cyan
        }
    } catch [Microsoft.PowerShell.Commands.ServiceCommandException] {
        Write-HostEx "  [i] Service not found: $ServiceName" -ForegroundColor DarkYellow
        $script:Stats.ServicesNotFound++
    } catch {
        Write-HostEx "  [ ERROR ] Error with service $ServiceName`: $_" -ForegroundColor Red
    }
}

function Disable-ScheduledTaskSafely {
    param([string]$TaskPath)
    try {
        $task = Get-ScheduledTask -TaskPath "*" -TaskName (Split-Path $TaskPath -Leaf) -ErrorAction Stop |
                Where-Object { $_.TaskPath + $_.TaskName -like "*$TaskPath*" } | Select-Object -First 1

        if ($task) {
            if ($task.State -eq 'Disabled') {
                Write-HostEx "  [ SKIP ] Task already disabled: $TaskPath" -ForegroundColor Gray
            } else {
                schtasks /Change /Disable /TN $TaskPath 2>&1 | Out-Null
                if ($LASTEXITCODE -eq 0) {
                    Write-HostEx "  [ OK ] Task disabled: $TaskPath" -ForegroundColor Green
                    $script:Stats.TasksDisabled++
                } else {
                    Write-HostEx "  [ ERROR ] Error disabling task: $TaskPath" -ForegroundColor Red
                }
            }
        } else {
            Write-HostEx "  [i] Task not found: $TaskPath" -ForegroundColor DarkYellow
            $script:Stats.TasksNotFound++
        }
    } catch {
        Write-HostEx "  [i] Task not found: $TaskPath" -ForegroundColor DarkYellow
        $script:Stats.TasksNotFound++
    }
}

function Disable-WindowsFeature {
    param([string]$FeatureName)
    try {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName $FeatureName -ErrorAction Stop
        if ($feature.State -eq 'Disabled') {
			Write-HostEx "  `n[i] Disabling feature: $FeatureName" -ForegroundColor Yellow
            Write-HostEx "    [SKIP] Feature already disabled: $FeatureName" -ForegroundColor Gray
        } else {
            Write-HostEx "  `n[i] Disabling feature: $FeatureName" -ForegroundColor Yellow
            DISM /Online /Disable-Feature /FeatureName:$FeatureName /NoRestart /Quiet | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-HostEx "  [OK] Feature disabled: $FeatureName" -ForegroundColor Green
                $script:Stats.FeaturesDisabled++
            } else {
                Write-HostEx "    Cannot disable feature - likely already removed from system: $FeatureName" -ForegroundColor Cyan
            }
        }
    } catch {
        Write-HostEx "  [i] Feature not found: $FeatureName" -ForegroundColor DarkYellow
        $script:Stats.FeaturesNotFound++
    }
}

function Remove-ItemSafely
{
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
	param (
		[Parameter(Mandatory, Position = 0)]
		[string]$Path,
		[Parameter(Position = 1)]
		[string]$Description = ""
	)
	
	if (-not (Test-Path $Path))
	{
		Write-HostEx "  [i] Not found: $Description ($Path)" -ForegroundColor DarkYellow
		$script:Stats.ItemsNotFound++
		return
	}
	
	$action = "Remove item(s)"
	if ($Description) { $action += " [$Description]" }
	
	if ($PSCmdlet.ShouldProcess($Path, $action))
	{
		try
		{
			Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop
			Write-HostEx "  [ OK ] Removed: $Description ($Path)" -ForegroundColor Green
			$script:Stats.ItemsRemoved++
		}
		catch
		{
			Write-HostEx "  [ ERROR ] Error removing $Description`: $_" -ForegroundColor Red
		}
	}
}

# ====================  MAIN  ====================

Write-HostEx ("`n" + "="*60) -ForegroundColor Cyan
Write-HostEx " "
Write-HostEx " EEEEEEE  XX    XX  LL        000000    UU     UU  DDDDDD  " -ForegroundColor Cyan
Write-HostEx " EE        XX  XX   LL      OO      OO  UU     UU  DD    DD " -ForegroundColor Cyan
Write-HostEx " EEEEE      XXXX    LL      OO      OO  UU     UU  DD    DD " -ForegroundColor Cyan
Write-HostEx " EE        XX  XX   LL      OO      OO  UU     UU  DD    DD " -ForegroundColor Cyan
Write-HostEx " EEEEEEE  XX    XX  LLLLLLL   000000     UUUUuUU   DDDDDD  " -ForegroundColor Cyan
Write-HostEx " "
Write-HostEx "                         PRESENTS" -ForegroundColor Cyan
Write-HostEx " "
Write-HostEx "                PRIVACY & TELEMETRY KILLER" -ForegroundColor Cyan
Write-HostEx " "
Write-HostEx ("="*60) -ForegroundColor Cyan

# ---------- 1. Registry ----------
Write-HostEx "`n[>] STEP 1: Applying registry policies..." -ForegroundColor Magenta

$reg = @(
    # --- Core telemetry and activity ---
    @{Path='HKCU:\SOFTWARE\Microsoft\Personalization\Settings';                            Name='AcceptedPrivacyPolicy';                        Value=0},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\System';                             Name='EnableActivityFeed';                           Value=0},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\System';                             Name='PublishUserActivities';                        Value=0},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\System';                             Name='UploadUserActivities';                         Value=0},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat';                          Name='AITEnable';                                    Value=0},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat';                          Name='AllowTelemetry';                               Value=0},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat';                          Name='DisableInventory';                             Value=1},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat';                          Name='DisableUAR';                                   Value=1},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection';                     Name='AllowTelemetry';                               Value=0},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection';                     Name='DoNotShowFeedbackNotifications';               Value=1},
	@{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection';                     Name='DisableOneSettingsDownloads';                  Value=1},
    @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection';      Name='Allowtelemetry';                               Value=0},
	@{Path='HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection'; Name ='AllowTelemetry';                       Value=0},
    # @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen';               Name='ConfigureAppInstallControlEnabled';            Value=1},
	# @{Path='HKLM:\SOFTWARE\Policies\Microsoft\MRT'; Name='DontOfferThroughWUAU'; Value=1},
	@{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata'; Name='PreventDeviceMetadataFromNetwork'; Value=1},
	@{Path='HKCU:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name='AllowTelemetry'; Value=0},
	@{Path='HKLM:\SOFTWARE\Microsoft\DataCollection'; Name='AllowTelemetry'; Value=0},
	@{Path='HKLM:\SYSTEM\DriverDatabase\Policies\Settings'; Name='DisableSendGenericDriverNotFoundToWER'; Value=1},
	@{Path='HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows'; Name='CEIPEnable'; Value=0},
	@{Path='HKLM:\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0'; Name='NoActiveHelp'; Value=1},
	@{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name='AllowDesktopAnalyticsProcessing'; Value=0},
	@{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name='AllowUpdateComplianceProcessing'; Value=0},
	@{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name='AllowWUfBCloudProcessing'; Value=0},
	@{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name='LimitDumpCollection'; Value=0},
	@{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name='MaxTelemetryAllowed'; Value=0},
	@{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name='EnableExtendedBooksTelemetry'; Value=0},
	@{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name='LimitDiagnosticLogCollection'; Value=1},
	@{Path='HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection'; Name='AllowTelemetry'; Value=0},
	@{Path='HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection'; Name='AllowDesktopAnalyticsProcessing'; Value=0},
	@{Path='HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection'; Name='AllowUpdateComplianceProcessing'; Value=0},
	@{Path='HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection'; Name='AllowWUfBCloudProcessing'; Value=0},
	@{Path='HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection'; Name='LimitDumpCollection'; Value=0},
	@{Path='HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection'; Name='MaxTelemetryAllowed'; Value=0},
	@{Path='HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection'; Name='EnableExtendedBooksTelemetry'; Value=0},
	@{Path='HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection'; Name='LimitDiagnosticLogCollection'; Value=1},
	@{Path='HKLM:\SOFTWARE\Microsoft\PolicyManager\default\System\AllowTelemetry'; Name='value'; Value=0},
	@{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\StorageSense'; Name='AllowStorageSenseGlobal'; Value=0},
	@{Path='HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl\StorageTelemetry'; Name='DeviceDumpEnabled'; Value=0},
	@{Path='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Tracing\SCM\Regular'; Name='TracingDisabled'; Value=1},
	@{Path='HKLM:\SOFTWARE\Policies\Microsoft\MSDeploy\3'; Name='EnableTelemetry'; Value=0},
	@{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy'; Name='EnableDiagnostics'; Value=0},

    # --- Experimentation on user sys ---
    @{Path='HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\System'; Name='AllowExperimentation'; Value=0},
     
    # --- CDPUserSvc block this curiosity service if y not use Timeline, Virtual Desktops, Your Phone app, Night Light --- 
    # @{Path='HKLM:\SYSTEM\CurrentControlSet\Services\CDPUserSvc'; Name='Start'; Value=4},

    # --- Where y down file ---
    @{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments'; Name='SaveZoneInformation'; Value=1},
	
	# --- EventLog Config ---
	# @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Steps-Recorder'; Name='Enabled'; Value=0},
	# @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Telemetry'; Name='Enabled'; Value=0},
	@{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Inventory'; Name='Enabled'; Value=0},
	@{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Compatibility-Troubleshooter'; Name='Enabled'; Value=0},
	@{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant/Trace'; Name='Enabled'; Value=0},
	@{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant/Compatibility-Infrastructure-Debug'; Name='Enabled'; Value=0},
	@{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant/Analytic'; Name='Enabled'; Value=0},
	@{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant'; Name='Enabled'; Value=0},

    # --- Disable widgets ---
    @{Path='HKCU:\Software\Microsoft\PolicyManager\default\NewsAndInterests\AllowNewsAndInterests';                Name='value';               Value=0},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Dsh';                                                                Name='AllowNewsAndInterests'; Value=0},

    # --- AppCompatFlags ---
    @{Path='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Appraiser';  Name='HaveUploadedForTarget';                        Value=1},
    @{Path='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\AIT';        Name='AITEnable';                                    Value=0},
    @{Path='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\ClientTelemetry'; Name='DontRetryOnError';                        Value=1},
    @{Path='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\ClientTelemetry'; Name='IsCensusDisabled';                        Value=1},
    @{Path='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\ClientTelemetry'; Name='TaskEnableRun';                           Value=0},
    
    # --- MobSync ---
    @{Path='Registry::HKEY_CLASSES_ROOT\CLSID\{1A1F4206-0688-4E7F-BE03-D82EC69DF9A5}\LocalServer32'; Name='(Default)'; Value='%SystemRoot%\System32\mobsync.exe.Disabled'; Type='ExpandString'},
    @{Path='Registry::HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{1A1F4206-0688-4E7F-BE03-D82EC69DF9A5}\LocalServer32'; Name='(Default)'; Value='%SystemRoot%\System32\mobsync.exe.Disabled'; Type='ExpandString'},

    # --- SQMClient ---
    @{Path='HKLM:\SOFTWARE\Microsoft\SQMClient\IE';                                        Name='CEIPEnable';                                     Value=0},
    @{Path='HKLM:\SOFTWARE\Microsoft\SQMClient\IE';                                        Name='SqmLoggerRunning';                               Value=0},
    @{Path='HKLM:\SOFTWARE\Microsoft\SQMClient\Reliability';                               Name='CEIPEnable';                                     Value=0},
    @{Path='HKLM:\SOFTWARE\Microsoft\SQMClient\Reliability';                               Name='SqmLoggerRunning';                               Value=0},
    @{Path='HKLM:\SOFTWARE\Microsoft\SQMClient\Windows';                                   Name='DisableOptinExperience';                         Value=1},
    @{Path='HKLM:\SOFTWARE\Microsoft\SQMClient\Windows';                                   Name='CEIPEnable';                                     Value=0},
    @{Path='HKLM:\SOFTWARE\Microsoft\SQMClient\Windows';                                   Name='SqmLoggerRunning';                               Value=0},

    # --- AutoLoggers ---
    @{Path='HKLM:\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AppModel';                      Name='Start';                                          Value=0},
    @{Path='HKLM:\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener'; Name='Start';                                          Value=0},
	@{Path='HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\CloudExperienceHostOobe';       Name='Start';                                          Value=0},
    @{Path='HKLM:\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\Diagtrack-Listener';            Name='Start';                                          Value=0},
    @{Path='HKLM:\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\Microsoft-Windows-Rdp-Graphics-RdpIdd-Trace'; Name='Start';                            Value=0},
    @{Path='HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Circular Kernel Context Logger'; Name='Start';                                         Value=0},
    @{Path='HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SQMLogger';                      Name='Start';                                         Value=0},
    @{Path='HKLM:\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\NetCore';                      Name='Start';                                          Value=0},
    @{Path='HKLM:\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\RadioMgr';                     Name='Start';                                          Value=0},

    # --- Geolocation ---
    @{Path='HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc';                                Name='Start';                                        Value=4},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors';                 Name='DisableLocation';                              Value=1},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors';                 Name='DisableLocationScripting';                     Value=1},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors';                 Name='DisableWindowsLocationProvider';               Value=1},

    # --- DiagTrack services ---
    @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack';        Name='DiagTrackAuthorization';                       Value=0},
    @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack';        Name='Disabled';                                     Value=1},
    @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack';        Name='DisableAutomaticTelemetryKeywordReporting';    Value=1},
    @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack';        Name='TelemetryServiceDisabled';                     Value=1},
    @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\EventTranscriptKey'; Name='EnableEventTranscript';            Value=0},
    @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\TestHooks'; Name='DisableAsimovUpload';                       Value=1},

    # --- Service start types ---
    @{Path='HKLM:\SYSTEM\CurrentControlSet\Services\DiagTrack';                            Name='Start';                                          Value=4},
    @{Path='HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice';                     Name='Start';                                          Value=4},
    @{Path='HKLM:\SYSTEM\CurrentControlSet\Services\PcaSvc';                               Name='Start';                                          Value=4},
    @{Path='HKLM:\SYSTEM\CurrentControlSet\Services\Telemetry';                            Name='Start';                                          Value=4},
    @{Path='HKLM:\SYSTEM\CurrentControlSet\Services\WpcMonSvc';                            Name='Start';                                          Value=4},

    # --- Windows Search / Cortana ---
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search';                     Name='AllowCortana';                                   Value=0},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search';                     Name='AllowCloudSearch';                               Value=0},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search';                     Name='AllowSearchToUseLocation';                       Value=0},
	@{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search';                     Name='CortanaConsent';                                 Value=0},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search';                     Name='DisableWebSearch';                               Value=1},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search';                     Name='ConnectedSearchUseWeb';                          Value=0},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search';                     Name='AllowCortanaAboveLock';                          Value=0},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search';                     Name='BingSearchEnabled';                              Value=0},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search';                     Name='DisableRemovableDriveIndexing';                  Value=1},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search';                     Name='ConnectedSearchUseWebOverMeteredConnections';    Value=0},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search';                     Name='ConnectedSearchPrivacy';                         Value=3},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search';                     Name='ConnectedSearchSafeSearch';                      Value=3},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search';                     Name='PreventIndexingOutlook';                         Value=1},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search';                     Name='PreventIndexOnBattery';                          Value=1},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search';                     Name='PreventIndexingEmailAttachments';                Value=1},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search';                     Name='PreventRemoteQueries';                           Value=1},
	@{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced';            Name='ShowCopilotButton';                              Value=0},
	@{Path='HKCU:\Software\Policies\Microsoft\Windows\Explorer';                           Name='DisableSearchBoxSuggestions';                    Value=1},
	@{Path='HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot';                     Name='TurnOffWindowsCopilot';                          Value=1},
	@{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot';                     Name='TurnOffWindowsCopilot';                          Value=1},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI';                          Name='DisableAIDataAnalysis';                          Value=1},
    @{Path='HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI';                          Name='DisableAIDataAnalysis';                          Value=1},
    @{Path='HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\WindowsAI';              Name='DisableAIDataAnalysis';                          Value=1},

    # --- Setting Sync & IE ---
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync';                        Name='EnableBackupForWin8Apps';                        Value=0},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Safety\PrivacIE';          Name='DisableLogging';                                 Value=1},
	
	# --- Wi-Fi Sense ---
	@{ Path = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting'; Name = 'Value'; Value = 0 },
	@{ Path = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots'; Name = 'Value'; Value = 0 },
	@{ Path = 'HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config'; Name = 'AutoConnectAllowedOEM'; Value = 0 },
	@{ Path = 'HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config'; Name = 'WiFISenseAllowed'; Value = 0 },

    # --- Input / Handwriting / Speech telemetry ---
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization';                       Name='RestrictImplicitInkCollection';                  Value=1},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization';                       Name='RestrictImplicitTextCollection';                 Value=1},
	@{Path='HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore';               Name='HarvestContacts';                                Value=0},
    @{Path='HKCU:\Software\Microsoft\Personalization\Settings';                            Name='AcceptedPrivacyPolicy';                          Value=0},	
	@{Path='HKCU:\Software\Microsoft\Input';                                               Name='IsInputAppPreloadEnabled';                       Value=0},
    @{Path='HKCU:\Software\Microsoft\Input\Settings';                                      Name='VoiceTypingEnabled';                             Value=0},
    @{Path='HKCU:\Software\Microsoft\Input\TIPC';                                          Name='Enabled';                                        Value=0},
    @{Path='HKCU:\Software\Microsoft\Input\Settings';                                      Name='InsightsEnabled';                                Value=0},	
	@{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput';           Name='AllowLinguisticDataCollection';                  Value=0},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC';                           Name='PreventHandwritingDataSharing';                  Value=1},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports';            Name='PreventHandwritingErrorReports';                 Value=1},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Speech';                                     Name='AllowSpeechModelUpdate';                         Value=0},
	@{Path='HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy';         Name='HasAccepted';                                    Value=0},

    # --- CompactTelR. Block run ---
	@{Path='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe'; Name='Debugger'; Value='%windir%\System32\taskkill.exe'; Type='String'},
	
	# --- Feedback OFF ---
	@{Path='HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0'; Name='NoExplicitFeedback'; Value=1;},
    @{Path='HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0'; Name='NoImplicitFeedback'; Value=1;},
	@{Path='HKLM:\Software\Policies\Microsoft\Assistance\Client\1.0'; Name='NoExplicitFeedback'; Value=1;},
    @{Path='HKLM:\Software\Policies\Microsoft\Assistance\Client\1.0'; Name='NoImplicitFeedback'; Value=1;},
	
    # --- User settings ---
	@{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel'; Name='{20D04FE0-3AEA-1069-A2D8-08002B30309D}'; Value=0},
    @{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo';              Name='Enabled';                                        Value=0},
	@{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo';                    Name='DisabledByGroupPolicy';                          Value=1},
    @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo';              Name='Enabled';                                        Value=0},
    @{Path='HKCU:\Control Panel\International\User Profile';                               Name='HttpAcceptLanguageOptOut';                       Value=1},
    @{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced';            Name='Start_TrackProgs';                               Value=0},
    @{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager';       Name='SubscribedContent-338393Enabled';                Value=0},
    @{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager';       Name='SubscribedContent-353694Enabled';                Value=0},
    @{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager';       Name='SubscribedContent-353696Enabled';                Value=0},
    @{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager';       Name='ContentDeliveryAllowed';                           Value=0},
	@{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager';       Name='OemPreInstalledAppsEnabled';                       Value=0},
	@{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager';       Name='PreInstalledAppsEnabled';                          Value=0},
	@{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager';       Name='PreInstalledAppsEverEnabled';                      Value=0},
	@{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager';       Name='SilentInstalledAppsEnabled';                       Value=0},
	@{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager';       Name='SubscribedContent-310093Enabled';                  Value=0},
	@{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager';       Name='SubscribedContent-314559Enabled';                  Value=0},
	@{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager';       Name='SubscribedContent-338387Enabled';                  Value=0},
	@{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager';       Name='SubscribedContent-338388Enabled';                  Value=0},
	@{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager';       Name='SubscribedContent-338389Enabled';                  Value=0},
	@{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager';       Name='SubscribedContent-353698Enabled';                  Value=0},
	@{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager';       Name='SystemPaneSuggestionsEnabled';                     Value=0},
	@{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy';                      Name='TailoredExperiencesWithDiagnosticDataEnabled';     Value=0},
	@{Path='HKCU:\SOFTWARE\Microsoft\Siuf\Rules';                                          Name='NumberOfSIUFInPeriod';                             Value=0},
	@{Path='HKCU:\SOFTWARE\Microsoft\Siuf\Rules';                                          Name='PeriodInNanoSeconds';                              Value=0},
	@{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced';            Name='LaunchTo';                                         Value=1},
	@{Path='HKCU:\Software\Policies\Microsoft\Windows\CloudContent';                       Name='DisableTailoredExperiencesWithDiagnosticData';     Value=1},
	@{Path='HKCU:\Software\Policies\Microsoft\Windows\CloudContent';  					   Name='DisableWindowsSpotlightWindowsWelcomeExperience'; Value=1},
	@{Path='HKCU:\Software\Policies\Microsoft\Windows\CloudContent';     				   Name='DisableWindowsSpotlightFeatures';                Value=1},
	@{Path='HKCU:\Software\Policies\Microsoft\Windows\CloudContent';     				   Name='DisableWindowsSpotlightOnActionCenter';          Value=1},
	@{Path='HKCU:\Software\Policies\Microsoft\Windows\CloudContent';   					   Name='DisableWindowsSpotlightOnSettings';              Value=1},
	@{Path='HKCU:\Software\Policies\Microsoft\Windows\CloudContent';     			   	   Name='DisableThirdPartySuggestions';                   Value=1},
	@{Path='HKCU:\Software\Policies\Microsoft\Windows\CloudContent';  					   Name='ConfigureWindowsSpotlight';                      Value=2},
	@{Path='HKCU:\Software\Policies\Microsoft\Windows\CloudContent';    				   Name='IncludeEnterpriseSpotlight';                     Value=0},
	@{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced';            Name='HideFileExt';                                    Value=0},
    
    @{Path='HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell'; Name='FolderType'; Value='NotSpecified'; Type='String'},
    @{Path='HKCU:\Control Panel\Accessibility'; Name='DynamicScrollbars'; Value=0},
    @{Path='HKCU:\Control Panel\Desktop'; Name='AutoEndTasks'; Value='1'; Type='String'},
    @{Path='HKCU:\Control Panel\Desktop'; Name='HungAppTimeout'; Value='3000'; Type='String'},
    @{Path='HKCU:\Control Panel\Desktop'; Name='MenuShowDelay'; Value='100'; Type='String'},
    @{Path='HKCU:\Control Panel\Desktop'; Name='WaitToKillAppTimeout'; Value='3000'; Type='String'},
    @{Path='HKCU:\Control Panel\Desktop'; Name='LowLevelHooksTimeout'; Value='3000'; Type='String'},
    @{Path='HKCU:\Control Panel\Desktop'; Name='EnablePerProcessSystemDPI'; Value=1},
    @{Path='HKCU:\Control Panel\Desktop'; Name='JPEGImportQuality'; Value=0x64},
    @{Path='HKCU:\Control Panel\Mouse'; Name='MouseHoverTime'; Value='100'; Type='String'},
    @{Path='HKCU:\Software\Microsoft\Internet Connection Wizard'; Name='Completed'; Value=1},
    @{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize'; Name='StartupDelayInMSec'; Value=0},
    @{Path='HKCU:\Control Panel\Desktop\WindowMetrics'; Name='IconTitleWrap'; Value='0'; Type='String'},
    @{Path='HKCU:\Control Panel\Accessibility\SlateLaunch'; Name='LaunchAT'; Value=0},
    @{Path='HKCU:\Control Panel\Accessibility\SlateLaunch'; Name='ATapp'; Value=''; Type='String'},
    @{Path='HKCU:\Control Panel\Accessibility\StickyKeys'; Name='Flags'; Value='506'; Type='String'},
    @{Path='HKCU:\Control Panel\Keyboard'; Name='InitialKeyboardIndicators'; Value='2'; Type='String'},
    @{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}'; Name='Value'; Value='Allow'; Type='String'},
    @{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C3F}'; Name='Value'; Value='Allow'; Type='String'},
    @{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}'; Name='Value'; Value='Allow'; Type='String'},
    @{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}'; Name='Value'; Value='Deny'; Type='String'},
    @{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}'; Name='Value'; Value='Deny'; Type='String'},
    @{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}'; Name='Value'; Value='Deny'; Type='String'},
    @{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}'; Name='Value'; Value='Deny'; Type='String'},
    @{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}'; Name='Value'; Value='Deny'; Type='String'},
    @{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}'; Name='Value'; Value='Deny'; Type='String'},
    @{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}'; Name='Value'; Value='Deny'; Type='String'},
    @{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled'; Name='Value'; Value='Deny'; Type='String'},
   
    # --- PerfTrack ---
    @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\PerfTrack'; Name='Disabled'; Value=1},
	
	# --- UserProfileEngagement ---
	@{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement'; Name = 'ScoobeSystemSettingEnabled'; Value = 0 },
	
	# --- WindowsInkWorkspace ---
	@{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace'; Name = 'AllowSuggestedAppsInWindowsInkWorkspace'; Value = 0 },

    # --- Internet Explorer settings ---
    @{Path='HKCU:\SOFTWARE\Microsoft\Internet Explorer\Main';                              Name='Search Page';                                    Value='https://www.google.com/'; Type='String'},
    @{Path='HKCU:\SOFTWARE\Microsoft\Internet Explorer\Main';                              Name='Start Page';                                     Value='https://www.google.com/'; Type='String'},
    @{Path='HKCU:\SOFTWARE\Microsoft\Internet Explorer\Main';                              Name='IE10RunOncePerInstallCompleted';                 Value=1},
    @{Path='HKCU:\SOFTWARE\Microsoft\Internet Explorer\Main';                              Name='IE10TourNoShow';                                 Value=1},
    @{Path='HKCU:\SOFTWARE\Microsoft\Internet Explorer\Main';                              Name='IE10TourShown';                                  Value=1},
    @{Path='HKCU:\SOFTWARE\Microsoft\Internet Explorer\Main';                              Name='IE10RecommendedSettingsNo';                      Value=1},
    @{Path='HKCU:\SOFTWARE\Microsoft\Internet Explorer\Main';                              Name='RunOnceComplete';                                Value=1},
    @{Path='HKCU:\SOFTWARE\Microsoft\Internet Explorer\Main';                              Name='RunOnceHasShown';                                Value=1},
    @{Path='HKCU:\SOFTWARE\Microsoft\Internet Explorer\Main';                              Name='AllowWindowReuse';                               Value=0},
    @{Path='HKCU:\SOFTWARE\Microsoft\Internet Explorer\Main';                              Name='DisableFirstRunCustomize';                       Value=1},
    @{Path='HKCU:\SOFTWARE\Microsoft\Internet Explorer\Suggested Sites';                   Name='Enabled';                                        Value=0},
    @{Path='HKCU:\Software\Microsoft\Internet Explorer\Main'; Name='IE10TourShownTime'; Value=([byte[]]@(0x00)); Type='Binary'},
    @{Path='HKCU:\Software\Microsoft\Internet Explorer\Main'; Name='IE10RunOnceCompletionTime'; Value=([byte[]]@(0x00)); Type='Binary'},
    @{Path='HKCU:\Software\Microsoft\Internet Explorer\Main'; Name='IE10RunOnceLastShown_TIMESTAMP'; Value=([byte[]]@(0x00)); Type='Binary'},
    @{Path='HKCU:\Software\Microsoft\Internet Explorer\TabbedBrowsing'; Name='PopupsUseNewWindow'; Value=2},
    @{Path='HKCU:\Software\Microsoft\Internet Explorer\TabbedBrowsing'; Name='NewTabPageShow'; Value=2},
    @{Path='HKCU:\Software\Microsoft\Internet Explorer\TabbedBrowsing'; Name='WarnOnClose'; Value=0},
    @{Path='HKCU:\Software\Microsoft\Internet Explorer\TabbedBrowsing'; Name='ShowTabsWelcome'; Value=0},
    @{Path='HKCU:\Software\Microsoft\Internet Explorer\TabbedBrowsing'; Name='OpenInForeground'; Value=1},
    @{Path='HKCU:\Software\Microsoft\Internet Explorer\ContinuousBrowsing'; Name='Enabled'; Value=1},

    # --- App capability access ---
    @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics';     Name='Value'; Value='Deny';  Type='String'},
    @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments';       Name='Value'; Value='Deny';  Type='String'},
    @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData';       Name='Value'; Value='Deny';  Type='String'},
    @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat';               Name='Value'; Value='Deny';  Type='String'},
    @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts';           Name='Value'; Value='Deny';  Type='String'},
    @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email';             Name='Value'; Value='Deny';  Type='String'},
    @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureProgrammatic'; Name='Value'; Value='Deny'; Type='String'},
    @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureWithoutBorder'; Name='Value'; Value='Deny'; Type='String'},
    @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location';          Name='Value'; Value='Deny';  Type='String'},
    @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone';        Name='Value'; Value='Allow'; Type='String'},
    @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall';         Name='Value'; Value='Deny';  Type='String'},
    @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory';  Name='Value'; Value='Deny';  Type='String'},
    @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios';            Name='Value'; Value='Deny';  Type='String'},
    @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation'; Name='Value'; Value='Deny'; Type='String'},
    @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks';     Name='Value'; Value='Allow'; Type='String'},
    @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener'; Name='Value'; Value='Allow'; Type='String'},
    @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam';            Name='Value'; Value='Allow'; Type='String'},

    # --- Security & hardening ---
    @{Path='HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters';         Name='AutoShareWks';                          Value=0},
    @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer';       Name='NoDriveTypeAutoRun';                    Value=255},
    @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer';       Name='NoAutorun';                             Value=1},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer';                      Name='NoAutoplayfornonVolume';                Value=1},
    @{Path='HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance';                Name='fAllowToGetHelp';                       Value=0},
    @{Path='HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance';                Name='fAllowFullControl';                     Value=0},
    @{Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';                              Name='NoLMHash';                              Value=1},
    @{Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';                              Name='RestrictAnonymous';                     Value=1},
    @{Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';                              Name='LmCompatibilityLevel';                  Value=5},
    @{Path='HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel';           Name='DisableExceptionChainValidation';       Value=0},
    @{Path='HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel';           Name='RestrictAnonymousSAM';                  Value=1},
    @{Path='HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters';         Name='RestrictNullSessAccess';                Value=1},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer';                     Name='AlwaysInstallElevated';                 Value=0},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client';                  Name='AllowBasic';                            Value=0},

    # --- Windows Connect Now ---
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI';                        Name='DisableWcnUi';                Value=1},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars';                Name='DisableFlashConfigRegistrar'; Value=0},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars';                Name='DisableInBand802DOT11Registrar'; Value=0},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars';                Name='DisableUPnPRegistrar';         Value=0},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars';                Name='DisableWPDRegistrar';          Value=0},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars';                Name='EnableRegistrars';             Value=0},
	
	# --- Windows Error Reporting ---
    @{Path='HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting';                Name='Disabled';                              Value=1},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting';       Name='Disabled';                              Value=1},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting';       Name='DontSendAdditionalData';                Value=1},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting';       Name='LoggingDisabled';                       Value=1},
	@{Path='HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Consent';        Name='DefaultConsent';                        Value=0},
    @{Path='HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Consent';        Name='DefaultOverrideBehavior';               Value=1},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting';       Name='DoReport';                              Value=0},
    @{Path='HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting';                Name='ChangeDumpTypeByTelemetryLevel';        Value=0},

    # --- Windows Media Player ---
    @{Path='HKCU:\SOFTWARE\Microsoft\MediaPlayer\Preferences';                         Name='AcceptedPrivacyStatement';              Value=1},
    @{Path='HKCU:\SOFTWARE\Microsoft\MediaPlayer\Preferences';                         Name='AddVideosFromPicturesLibrary';          Value=0},
    @{Path='HKCU:\SOFTWARE\Microsoft\MediaPlayer\Preferences';                         Name='AutoAddMusicToLibrary';                 Value=0},
    @{Path='HKCU:\SOFTWARE\Microsoft\MediaPlayer\Preferences';                         Name='AutoAddVideoToLibrary';                 Value=0},
    @{Path='HKCU:\SOFTWARE\Microsoft\MediaPlayer\Preferences';                         Name='DeleteRemovesFromComputer';             Value=0},
    @{Path='HKCU:\SOFTWARE\Microsoft\MediaPlayer\Preferences';                         Name='DisableLicenseRefresh';                 Value=1},
    @{Path='HKCU:\SOFTWARE\Microsoft\MediaPlayer\Preferences';                         Name='FirstRun';                              Value=0},
    @{Path='HKCU:\SOFTWARE\Microsoft\MediaPlayer\Preferences';                         Name='FlushRatingsToFiles';                   Value=0},
    @{Path='HKCU:\SOFTWARE\Microsoft\MediaPlayer\Preferences';                         Name='LibraryHasBeenRun';                     Value=1},
    @{Path='HKCU:\SOFTWARE\Microsoft\MediaPlayer\Preferences';                         Name='MetadataRetrieval';                     Value=0},
    @{Path='HKCU:\SOFTWARE\Microsoft\MediaPlayer\Preferences';                         Name='SilentAcquisition';                     Value=0},
    @{Path='HKCU:\SOFTWARE\Microsoft\MediaPlayer\Preferences';                         Name='SilentDRMConfiguration';                Value=0},
    @{Path='HKCU:\SOFTWARE\Microsoft\MediaPlayer\Preferences';                         Name='DisableMRU';                            Value=1},
    @{Path='HKCU:\SOFTWARE\Microsoft\MediaPlayer\Preferences';                         Name='UsageTracking';                         Value=0},
    @{Path='HKCU:\SOFTWARE\Microsoft\MediaPlayer\Preferences';                         Name='SendUserGUID';                          Value=0},
    @{Path='HKCU:\SOFTWARE\Microsoft\MediaPlayer\Preferences';                         Name='AskMeAgain';                            Value='No'; Type='String'},
    @{Path='HKCU:\SOFTWARE\Microsoft\MediaPlayer\Preferences';                         Name='StartInMediaGuide';                     Value=0},
    @{Path='HKCU:\SOFTWARE\Microsoft\MediaPlayer\Preferences';                         Name='SnapToVideoV11';                        Value=0},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer';                     Name='GroupPrivacyAcceptance';                Value=1},
    @{Path='HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer';                     Name='PreventCDDVDMetadataRetrieval';         Value=1},
    @{Path='HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer';                     Name='PreventMusicFileMetadataRetrieval';     Value=1},
    @{Path='HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer';                     Name='PreventRadioPresetsRetrieval';          Value=1},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\WMDRM';                                  Name='DisableOnline';                         Value=1}
)

Write-HostEx "Processing $($reg.Count) registry settings..." -ForegroundColor White
$reg | ForEach-Object { Set-RegistryValue @_ }

# ---------- 2. Create Scheduled Task to enforce AllowTelemetry = 0 ----------
Write-HostEx "`n[>] STEP 2: Creating scheduled task to enforce AllowTelemetry = 0..." -ForegroundColor Magenta

$taskName = "AllowTelemetryZero"
$scriptPath = "$env:ProgramData\Scripts\Fix-Telemetry.ps1"

if (!(Test-Path $scriptPath)) {
    $null = New-Item -Path (Split-Path $scriptPath) -ItemType Directory -Force
    @'
$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
$name = 'AllowTelemetry'
$desired = 0
$current = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $name -ErrorAction SilentlyContinue
if ($current -ne $desired) {
    if (!(Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
    Set-ItemProperty -Path $path -Name $name -Type DWord -Value $desired -Force
}
'@ | Set-Content -Path $scriptPath -Encoding UTF8
}

$action = New-ScheduledTaskAction `
          -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
          -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
$trigger  = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet `
            -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries `
            -StartWhenAvailable
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

$existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if (!$existing) {
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal | Out-Null
    Write-HostEx "  [ OK ] Scheduled task '$taskName' created – runs at every startup" -ForegroundColor Green
} else {
    Write-HostEx "  [ SKIP ] Scheduled task '$taskName' already exists" -ForegroundColor Gray
}

# ---------- 3. Services ----------
Write-HostEx "`n[>] STEP 3: Disabling telemetry services..." -ForegroundColor Magenta

$services = @(
    'DiagTrack',
    'dmwappushservice',
    'PcaSvc',
    'wisvc',
    'Telemetry',
    'WpcMonSvc',
    # 'CDPUserSvc',
    'diagnosticshub.standardcollector.service',
    'WMPNetworkSvc'
)

$services | ForEach-Object {
    try {
        $svc = Get-Service $_ -ErrorAction Stop

        if ($svc.Status -eq 'Running') {
            Write-HostEx "  [i] Stopping service: $_" -ForegroundColor Yellow
            Stop-Service $_ -Force -ErrorAction Stop
        }

        if ($svc.StartType -ne 'Disabled') {
            Write-HostEx "  [ OK ] Disabling service: $_" -ForegroundColor Green
            Set-Service $_ -StartupType Disabled -ErrorAction Stop
            $script:Stats.ServicesDisabled++
        } else {
            Write-HostEx "  [ SKIP ] Service already disabled: $_" -ForegroundColor Gray
        }
    } catch [Microsoft.PowerShell.Commands.ServiceCommandException] {
        Write-HostEx "  [i] Service not found: $_" -ForegroundColor DarkYellow
        $script:Stats.ServicesNotFound++
    } catch {
        Write-HostEx "  [ ERROR ] Error with service $_`: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-HostEx "`n[>] STEP 3b: Handling NDU service ..." -ForegroundColor Magenta
try {
    $svc = Get-Service -Name 'ndu' -ErrorAction Stop
    Write-HostEx "  [i] Ndu status: $($svc.Status), start type: $($svc.StartType)" -ForegroundColor Cyan

    # Зупинка, якщо не вимкнена
    if ($svc.Status -eq 'Running') {
        Write-HostEx "  [i] Stopping Ndu (non-blocking)..." -ForegroundColor Yellow
        Stop-Service -Name 'ndu' -Force -NoWait -ErrorAction SilentlyContinue
    } else {
        Write-HostEx "  [ SKIP ] Ndu already stopped" -ForegroundColor Gray
    }

    # Вимкнення, якщо не вимкнена
    if ($svc.StartType -ne 'Disabled') {
        Set-Service -Name 'ndu' -StartupType Disabled -ErrorAction SilentlyContinue
        Write-HostEx "  [ OK ] Ndu startup type set to Disabled" -ForegroundColor Green
    } else {
        Write-HostEx "  [ SKIP ] Ndu startup already Disabled" -ForegroundColor Gray
    }
} catch {
    Write-HostEx "  [i] Ndu service not found or inaccessible" -ForegroundColor DarkYellow
}

# ---------- 3. Scheduled Tasks ----------
Write-HostEx "`n[>] STEP 4: Disabling scheduled tasks..." -ForegroundColor Magenta
$tasks = @(
   # Local .NET compilation - not telemetry
   # '\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319',
   
   # App integrity verification - not telemetry
   # '\Microsoft\Windows\ApplicationData\appuriverifierdaily',
   
   # Application compatibility telemetry
   '\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser',
   '\Microsoft\Windows\Application Experience\ProgramDataUpdater',
   '\Microsoft\Windows\Application Experience\StartupAppTask',
   '\Microsoft\Windows\Application Experience\AITAgent',
   
   # Local compatibility patches - not telemetry
   # '\Microsoft\Windows\Application Experience\PcaPatchDbTask',
   
   # Disk check scheduling - not telemetry
   # '\Microsoft\Windows\Autochk\Proxy',
   
   # Customer Experience Improvement Program (CEIP) - telemetry collection
   '\Microsoft\Windows\Customer Experience Improvement Program\Consolidator',
   '\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask',
   '\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip',
   
   # Device information collection
   '\Microsoft\Windows\Device Information\Device',
   
   # Diagnostics with data transmission
   '\Microsoft\Windows\Diagnosis\Scheduled',

   'Microsoft\Windows\Work Folders\Work Folders Logon Synchronization',
   
   # Local disk cleanup - not telemetry
   # '\Microsoft\Windows\DiskCleanup\SilentCleanup',
   
   # Disk diagnostics with data transmission
   '\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector',
   
   # Local security policy updates - not telemetry
   # '\Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh',
   
   # User feedback collection
   '\Microsoft\Windows\Feedback\Siuf\DmClient',
   '\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload',
   
   # Local file history maintenance - not telemetry
   # '\Microsoft\Windows\FileHistory\File History (maintenance mode)',
   
   # Local experimental features management - not telemetry
   # '\Microsoft\Windows\Flighting\FeatureConfig\ReconcileFeatures',
   
   # Experimental features - telemetry
   '\Microsoft\Windows\Flighting\FeatureConfig\UsageDataFlushing',
   '\Microsoft\Windows\Flighting\FeatureConfig\UsageDataReporting',
   
   # Local settings updates - not telemetry
   # '\Microsoft\Windows\Flighting\OneSettings\RefreshCache',
   
   # Local biometric data cleanup - not telemetry
   # '\Microsoft\Windows\HelloFace\FODCleanupTask',
   
   # Local language settings sync
   '\Microsoft\Windows\International\Synchronize Language Settings',
   
   # Local language components installation - not telemetry
   # '\Microsoft\Windows\LanguageComponentsInstaller\Installation',
   
   # Local performance assessment - not telemetry
   # '\Microsoft\Windows\Maintenance\WinSAT',
   
   # Local maps notifications - not telemetry
   # '\Microsoft\Windows\Maps\MapsToastTask',
   # '\Microsoft\Windows\Maps\MapsUpdateTask',
   
   # Local memory diagnostics - not telemetry
   # '\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents',
   # '\Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic',
   
   # Network information collection
   '\Microsoft\Windows\NetTrace\GatherNetworkInfo',
   
   # Local offline files sync - not telemetry
   # '\Microsoft\Windows\Offline Files\Background Synchronization',
   # '\Microsoft\Windows\Offline Files\Logon Synchronization',
   
   # Software quality metrics
   '\Microsoft\Windows\PI\Sqm-Tasks',
   
   # Power efficiency diagnostics with data transmission
   '\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem',
   
   # Local installation rights check - not telemetry
   # '\Microsoft\Windows\PushToInstall\LoginCheck',
   # '\Microsoft\Windows\PushToInstall\Registration',
   
   # Local registry backup - not telemetry
   # '\Microsoft\Windows\Registry\RegIdleBackup',
   
   # Local retail demo cleanup - not telemetry
   # '\Microsoft\Windows\RetailDemo\CleanupOfflineContent',
   
   # Local setup cleanup - not telemetry
   # '\Microsoft\Windows\Setup\SetupCleanupTask',
   
   # Local parental controls - not telemetry
   # '\Microsoft\Windows\Shell\FamilySafetyMonitor',
   # '\Microsoft\Windows\Shell\FamilySafetyRefreshTask',
   
   # Local search index maintenance - not telemetry
   # '\Microsoft\Windows\Shell\IndexerAutomaticMaintenance',
   
   # Local speech model downloads
   '\Microsoft\Windows\Speech\SpeechModelDownloadTask',
   
   # Local swap file assessment - not telemetry
   # '\Microsoft\Windows\Sysmain\WsSwapAssessmentTask',
   
   # Local system restore - not telemetry
   # '\Microsoft\Windows\SystemRestore\SR',
   
   # Local update notifications - not telemetry
   # '\Microsoft\Windows\UNP\RunUpdateNotificationMgr',
   
   # User profile cloud upload
   '\Microsoft\Windows\User Profile Service\HiveUploadTask',
   
   # Local update remediation - not telemetry
   # '\Microsoft\Windows\WaaSMedic\PerformRemediation',
   
   # Local Edge updates - not telemetry
   # '\MicrosoftEdgeUpdateTaskMachineCore',
   # '\MicrosoftEdgeUpdateTaskMachineUA',
   
      # Error reports transmission
   '\Microsoft\Windows\Windows Error Reporting\QueueReporting'
   
) | Sort-Object -Unique

Write-HostEx "Processing $($tasks.Count) telemetry-related scheduled tasks..." -ForegroundColor White
$tasks | ForEach-Object { Disable-ScheduledTaskSafely $_ }

# ---------- Delete CloudExperienceHost registry entries ----------
Write-HostEx "`n[>] Deleting CloudExperienceHost registry entries..." -ForegroundColor Magenta
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\CloudExperienceHost"

try {
   Write-HostEx "  [i] Checking registry path..." -ForegroundColor Cyan
   if (Test-Path $regPath) {
       Write-HostEx "  [i] Deleting registry entries..." -ForegroundColor Cyan
       Remove-Item -Path $regPath -Recurse -Force -ErrorAction Stop
       Write-HostEx "  [ OK ] CloudExperienceHost registry entries deleted" -ForegroundColor Green
   } else {
       Write-HostEx "  [ SKIP ] CloudExperienceHost registry entries not found" -ForegroundColor Gray
   }
} catch {
   Write-HostEx "  [ ERROR ] Failed to delete CloudExperienceHost registry entries: $_" -ForegroundColor Red
}

# ---------- 5. Physically delete CompatTelRunner ----------
Write-HostEx "`n[>] STEP 5: Physically deleting CompatTelRunner.exe..." -ForegroundColor Magenta

$compatPath = "$env:SystemRoot\System32\CompatTelRunner.exe"
$takeown    = "$env:SystemRoot\System32\takeown.exe"
$icacls     = "$env:SystemRoot\System32\icacls.exe"

if (Test-Path $compatPath) {
    try {
        Write-HostEx "  [i] Taking ownership..." -ForegroundColor Cyan
        & $takeown /F $compatPath > $null 2>&1

        Write-HostEx "  [i] Granting full permissions..." -ForegroundColor Cyan
        & $icacls $compatPath /grant "${env:USERNAME}:F" > $null 2>&1

        Write-HostEx "  [i] Deleting file..." -ForegroundColor Cyan
        Remove-Item -Path $compatPath -Force -ErrorAction Stop

        Write-HostEx "  [ OK ] CompatTelRunner.exe deleted" -ForegroundColor Green
    } catch {
        Write-HostEx "  [ ERROR ] Failed to delete CompatTelRunner.exe: $_" -ForegroundColor Red
    }
} else {
    Write-HostEx "  [ SKIP ] CompatTelRunner.exe not found" -ForegroundColor Gray
}

# ---------- 5. Clean DiagTrack Logs ----------
Write-HostEx "`n[>] STEP 6: Cleaning DiagTrack logs..." -ForegroundColor Magenta
$diagPath = "$env:ProgramData\Microsoft\Diagnosis"
$icacls   = "$env:SystemRoot\System32\icacls.exe"
$takeown  = "$env:SystemRoot\System32\takeown.exe"

if (-not (Test-Path $diagPath)) {
    Write-HostEx "  [INFO] Diagnosis folder not found – skipping." -ForegroundColor Cyan
}

try {
    & $icacls $diagPath /grant:r "*S-1-5-32-544:(OI)(CI)(IO)(F)" /T /C 2>$null | Out-Null
}
catch { Write-HostEx "  [WARN] icacls returned an error: $_" -ForegroundColor Yellow }

try {
    & $takeown /f $diagPath /A /r /d y 2>$null | Out-Null
}
catch { Write-HostEx "  [WARN] takeown returned an error: $_" -ForegroundColor Yellow }

$rbFiles = Get-ChildItem -Path "$diagPath\*.rbs" -Force -ErrorAction SilentlyContinue
if ($rbFiles) {
    try {
        $rbFiles | Remove-Item -Force -ErrorAction Stop
        Write-HostEx "  [ OK ] Removed $($rbFiles.Count) *.rbs file(s)" -ForegroundColor Green
    }
    catch { Write-HostEx "  [WARN] Could not delete *.rbs: $_" -ForegroundColor Yellow }
}
else {
    Write-HostEx "  [INFO] No *.rbs files found – nothing to delete." -ForegroundColor Cyan
}

$etlLogsPath = "$diagPath\ETLLogs"
if (Test-Path $etlLogsPath) {
    $etlItems = Get-ChildItem -Path $etlLogsPath -Force -ErrorAction SilentlyContinue
    if ($etlItems) {
        try {
            Remove-Item -Path "$etlLogsPath\*" -Recurse -Force -ErrorAction Stop
            Write-HostEx "  [ OK ] Cleaned ETLLogs folder ($($etlItems.Count) item(s) removed)" -ForegroundColor Green
        }
        catch { Write-HostEx "  [WARN] Could not clean ETLLogs: $_" -ForegroundColor Yellow }
    }
    else {
        Write-HostEx "  [INFO] ETLLogs folder exists but is empty – nothing to delete." -ForegroundColor Cyan
    }
}
else {
    Write-HostEx "  [INFO] ETLLogs folder does not exist – skipping." -ForegroundColor Cyan
}

Write-HostEx "  [ OK ] Diagnosis folder processed" -ForegroundColor Green

# ---------- 6. Optional Windows Features ----------
Write-HostEx "`n[>] STEP 7: Disabling unnecessary components..." -ForegroundColor Magenta
@(
  # === Critical Security Risk Components - SMB1 and Legacy Protocols ===
  # 'SMB1Protocol',
  # 'SMB1Protocol-Client',
  # 'SMB1Protocol-Server',
  # 'SMB1Protocol-Deprecation',
  # 'FS-SMB1',
  # 'ClientForNFS-Infrastructure',
  # 'ServicesForNFS-ClientOnly',
  # 'ServicesForNFS-ServerAndClient',
	
  # == Insecure Network Protocols and Services ===
  # 'TelnetClient',
  # 'TelnetServer',
  # 'TFTP',
  # 'SimpleTcpip',
  # 'SimpleTCP',
  # 'RasRip',
  # 'RIP',
  # 'SNMP',
  # 'LPR-Print-Server',
  # 'Print-LPDPrintService',
  # 'Printing-Foundation-LPRPortMonitor',
  # 'IIS-FTPServer',
  # 'IIS-FTPSvc',
  # 'IIS-FTPExtensibility'
	
  # === Microsoft Message Queuing (MSMQ) ===
  'MSMQ-Container',
  'MSMQ-Server',
  'MSMQ-Services',
  'MSMQ-Triggers',
  'MSMQ-ADIntegration',
  'MSMQ-HTTP',
  'MSMQ-Multicast',
  'MSMQ-DCOMProxy',

  # === Print and Document Services ===
  # 'Printing-PrintToPDFServices-Features',
  # 'Printing-XPSServices-Features',
  # 'Printing-Foundation-Features',
  # 'Printing-Foundation-InternetPrinting-Client',
  # 'Printing-Foundation-LPDPrintService',
  # 'Printing-Foundation-LPRPortMonitor',
  # 'FaxServicesClientPackage',
  # 'ScanManagementConsole',
  # 'Xps-Foundation-Xps-Viewer',
  # 'Microsoft-Windows-Printing-XPSServices-Package',
  # 'TIFFIFilter',

  # === Remote Access and VPN Components ===
  'RemoteAccess',
  'DirectAccess-VPN',
  'Routing',
  'RasRip', 
  'RasCMAK',
  'RSAT-RemoteAccess',
  'RSAT-RemoteAccess-Mgmt',
  'RSAT-RemoteAccess-PowerShell',
  # === Directory Services and Active Directory Components ===
  'DirectoryServices-ADAM-Client',
  'RSAT-ADDS',
  'RSAT-ADDS-Tools',
  'RSAT-AD-AdminCenter', 
  'RSAT-AD-PowerShell',
  'RSAT-ADLDS',
  'RSAT-DNS-Server',

  # === Enterprise and Server Features (Workstation Hardening) ===
  'DataCenterBridging',
  'MultiPoint-Connector',
  'MultiPoint-Connector-Services',
  'MultiPoint-Tools',
  'HostGuardian',
  'ServerCore-Drivers-General',
  'ServerCore-Drivers-General-WOW64',
  
  # === Hyper-V and Virtualization Components ===
  # P.S. Don't worry - virtual machines like VirtualBox or VMware - work without this component
  'Microsoft-Hyper-V-All',
  'Microsoft-Hyper-V',
  'Microsoft-Hyper-V-Tools-All',
  'Microsoft-Hyper-V-Management-PowerShell',
  'Microsoft-Hyper-V-Hypervisor',
  'Microsoft-Hyper-V-Services',
  'Microsoft-Hyper-V-Management-Clients',
  'HypervisorPlatform',
  'VirtualMachinePlatform',
  'Containers-DisposableClientVM',

  # === Internet Information Services (IIS) ===
  # IIS = Microsoft Web Server (analogue of Apache/Nginx)
  # Used to host websites on Windows Server
  # Supports ASP.NET, PHP and other server technologies
  # Works as a service in the background
  'IIS-WebServerRole',
  'IIS-WebServer',
  'IIS-CommonHttpFeatures',
  'IIS-HttpErrors',
  'IIS-HttpRedirect',
  'IIS-ApplicationDevelopment',
  'IIS-NetFxExtensibility45',
  'IIS-NetFxExtensibility',
  'IIS-ISAPIExtensions',
  'IIS-ISAPIFilter',
  'IIS-ASPNET45',
  'IIS-ASPNET',
  'IIS-CGI',
  'IIS-ServerSideIncludes',
  'IIS-CustomLogging',
  'IIS-LoggingLibraries',
  'IIS-RequestMonitor',
  'IIS-HttpTracing',
  'IIS-BasicAuthentication',
  'IIS-WindowsAuthentication',
  'IIS-DigestAuthentication',
  'IIS-ClientCertificateMappingAuthentication',
  'IIS-IISCertificateMappingAuthentication',
  'IIS-URLAuthorization',
  'IIS-RequestFiltering',
  'IIS-IPSecurity',
  'IIS-Performance',
  'IIS-HttpCompressionStatic',
  'IIS-HttpCompressionDynamic',
  'IIS-WebDAV',
  'IIS-LegacySnapIn',
  'IIS-ManagementConsole',
  'IIS-IIS6ManagementCompatibility',
  'IIS-Metabase',
  'IIS-HostableWebCore',
  'IIS-StaticContent',
  'IIS-DefaultDocument',
  'IIS-DirectoryBrowsing',
  'IIS-ODBC',

  # === Legacy PowerShell and Scripting Components ===
  # If y want write PS scripts - use VS Code with PS syntax and analyzer plugin
  'MicrosoftWindowsPowerShellV2Root',
  'MicrosoftWindowsPowerShellV2',
  'WindowsPowerShellWebAccess',
  'MicrosoftWindowsPowerShellISE',
  'Microsoft.Windows.PowerShell.ISE',
  'MicrosoftWindowsPowerShellV2Engine'

) | ForEach-Object { Disable-WindowsFeature $_ }

# ---------- 7. Disable UWP Background Apps ----------
Write-HostEx "`n[>] STEP 8: Disabling UWP background apps..." -ForegroundColor Magenta
try
{
    $appPrivacyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
    
    $currentValue = Get-ItemProperty -Path $appPrivacyPath -Name "LetAppsRunInBackground" -ErrorAction SilentlyContinue | 
                    Select-Object -ExpandProperty "LetAppsRunInBackground" -ErrorAction SilentlyContinue
    
    if ($currentValue -eq 2)
    {
        Write-HostEx "  [ SKIP ] UWP background apps already disabled via Group Policy" -ForegroundColor Gray
    }
    else
    {
        Write-HostEx "  [i] Disabling UWP background apps..." -ForegroundColor Yellow
        if (-not (Test-Path $appPrivacyPath))
        {
            New-Item -Path $appPrivacyPath -Force | Out-Null
            Write-HostEx "  [+] Creating key: $appPrivacyPath" -ForegroundColor Yellow
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsRunInBackground" -Type DWord -Value 2
        Write-HostEx "  [ OK ] UWP background apps disabled via Group Policy" -ForegroundColor Green
    }
}
catch
{
    Write-HostEx "  [ ERROR ] Error disabling UWP background apps: $_" -ForegroundColor Red
}

# ---------- 8. Optimize Windows for SSD ----------
Write-Host "`n[>] Step 9 : Optimize Windows for SSD..." -ForegroundColor Magenta

$bootDrive = (Get-CimInstance Win32_OperatingSystem).SystemDrive   # C:
$diskIndex = (Get-Partition | Where-Object { $_.DriveLetter -eq $bootDrive.Trim(':') }).DiskNumber
$mediaType = (Get-PhysicalDisk | Where-Object { $_.DeviceId -eq $diskIndex }).MediaType

if ($mediaType -ne 'SSD') {
    Write-Host "  [ SKIP ] OS is on $mediaType disk – SSD optimizations not required." -ForegroundColor Gray
    # return
}

$SYS32    = "$env:SystemRoot\System32"
$FSUTIL   = "$SYS32\fsutil.exe"
$POWERCFG = "$SYS32\powercfg.exe"
$SC       = "$SYS32\sc.exe"
$WEVTUTIL = "$SYS32\wevtutil.exe"

filter Write-Status($msg, $color='White') { Write-Host $msg -ForegroundColor $color }

function Invoke-Safely(
    [scriptblock]$action,
    [string]$ok,
    [string]$skip,
    [string]$errorMsg
) {
    try {
        if (& $action) { Write-Status $skip Gray  }
        else           { Write-Status $ok   Green }
    }
    catch { Write-Status "$errorMsg $_" Red }
}

function Test-RegDWORD($Path, $Name, $Desired) {
    $v = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $Name
    return $v -eq $Desired
}

Write-Status "  [i] Configuring Kernel Paging Executive..." Cyan
Invoke-Safely {
    $memMgmtPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
    $currentValue = Get-ItemProperty -Path $memMgmtPath -Name "DisablePagingExecutive" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "DisablePagingExecutive"
    
    if ($currentValue -eq 1) {
        return $true
    }
    
    Set-ItemProperty -Path $memMgmtPath -Name "DisablePagingExecutive" -Value 1 -Force
    return $false
} "  [ OK ] Kernel Paging Executive disabled" `
  "  [SKIP] Kernel Paging Executive already disabled" `
  "  [ERROR] Kernel Paging Executive:"

Write-Status "  [i] Enabling TRIM..." Cyan
Invoke-Safely `
    { (& $FSUTIL behavior query DisableDeleteNotify) -match '0' } `
    "  [ OK ] TRIM enabled" `
    "  [SKIP] TRIM already enabled" `
    "  [ERROR] TRIM:"

Write-Status "  [i] Disabling Last-Access Timestamp..." Cyan
Invoke-Safely `
    { (& $FSUTIL behavior query DisableLastAccess) -match '1' } `
    "  [ OK ] Last-Access disabled" `
    "  [SKIP] Last-Access already disabled" `
    "  [ERROR] Last-Access:"

Write-Status "  [i] Disabling Hibernation..." Cyan
Invoke-Safely {
    # Check if hibernation is already disabled
    $hibernationStatus = & $POWERCFG /availablesleepstates
    if ($hibernationStatus -notmatch 'Hibernate') {
        return $true  # Already disabled
    }
    
    # Disable hibernation
    & $POWERCFG /hibernate off >$null 2>&1
    
    # Also disable hibernate file
    $hibernateEnabled = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "HibernateEnabled" -ErrorAction SilentlyContinue
    if ($hibernateEnabled -and $hibernateEnabled.HibernateEnabled -ne 0) {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "HibernateEnabled" -Value 0 -Force
    }
    
    return $false
} "  [ OK ] Hibernation disabled" `
  "  [SKIP] Hibernation already disabled" `
  "  [ERROR] Hibernation:"

Write-Status "  [i] Disabling Fast Startup..." Cyan
Invoke-Safely `
    { Test-RegDWORD 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' HiberbootEnabled 0 } `
    "  [ OK ] Fast Startup disabled" `
    "  [SKIP] Fast Startup already off" `
    "  [ERROR] Fast Startup:"

Write-Host "  [i] Disabling Prefetch/Superfetch..." -ForegroundColor Cyan
Invoke-Safely {
    $pf = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters'
    if ((Test-RegDWORD $pf EnablePrefetcher 0) -and (Test-RegDWORD $pf EnableSuperfetch 0)) {
        return $true
    }
    New-Item $pf -Force >$null
    Set-ItemProperty $pf EnablePrefetcher  0 -Force
    Set-ItemProperty $pf EnableSuperfetch  0 -Force
    Set-ItemProperty $pf EnableBoottrace   0 -Force
    return $false
} "  [ OK ] Prefetch/Superfetch disabled" `
  "  [SKIP] Prefetch/Superfetch already off" `
  "  [ERROR] Prefetch/Superfetch:"

Write-Status "  [i] Disabling SysMain..." Cyan
Invoke-Safely {
    $svc = Get-Service SysMain -EA SilentlyContinue
    if (-not $svc) { return $true }
    if ($svc.StartType -eq 'Disabled') { return $true }
    Stop-Service SysMain -Force >$null
    & $SC config SysMain start= disabled >$null
    return $false
} "  [ OK ] SysMain disabled" `
  "  [SKIP] SysMain already off" `
  "  [ERROR] SysMain:"

Write-Status "  [i] Disabling Windows Search..." Cyan
Invoke-Safely {
    $state = (Get-WindowsOptionalFeature -Online -FeatureName SearchEngine-Client-Package -ErrorAction SilentlyContinue).State
    if ($state -eq 'Enabled') {
        Disable-WindowsOptionalFeature -Online -FeatureName SearchEngine-Client-Package -NoRestart -ErrorAction SilentlyContinue >$null
    }

    $svc = Get-Service WSearch -EA SilentlyContinue
    if ($svc) {
        if ($svc.StartType -ne 'Disabled') {
            Stop-Service WSearch -Force >$null
            Set-Service WSearch -StartupType Disabled -ErrorAction SilentlyContinue
        }
    }

    Get-CimInstance Win32_Volume | Where-Object { $_.DriveType -eq 3 -and $_.DriveLetter } | ForEach-Object {
        & "$SYS32\SearchIndexer.exe" /disable "$($_.DriveLetter[0]):\" 2>$null
    }

    return ($state -eq 'Disabled')
} "  [ OK ] Windows Search disabled" `
  "  [SKIP] Windows Search already off" `
  "  [ERROR] Windows Search:"

Write-Status "  [i] Disabling defrag tasks..." Cyan
Get-ScheduledTask | Where-Object {
    $_.TaskName -match 'defrag|optimize|fragment' -and $_.State -ne 'Disabled'
} | ForEach-Object {
    Disable-ScheduledTask -TaskPath $_.TaskPath -TaskName $_.TaskName >$null
    Write-Status "  [+] Disabled task: $($_.TaskName)" Cyan
}

Write-Status "  [i] Event Log configuring..." Cyan
# Вимикати службу не рекомендую для спец. софту та для Steam і йому подібних
# Вимкнути службу : Set-Service -Name "EventLog" -StartupType Disabled -Status Stopped
# Увімкнути службу: Set-Service -Name "EventLog" -StartupType Automatic -Status Running

# Перевірка, чи запущена служба Windows Event Log
$evtSvc = Get-Service -Name 'EventLog' -ErrorAction SilentlyContinue
if (-not $evtSvc -or $evtSvc.Status -ne 'Running') {
    Write-Status "  [SKIP] Windows Event Log service is not running – skipped" Gray
} else {
    # Основні логи
    $criticalLogs = @('Application', 'System', 'Security')
    $otherLogs    = @('Setup', 'Windows PowerShell', 'Microsoft-Windows-PowerShell/Operational')

    foreach ($log in $criticalLogs) {
        try {
            Clear-EventLog -LogName $log
            Limit-EventLog -LogName $log -MaximumSize 64KB
            Write-Status "    [+] $log - cleared and limited to 64KB" Green
        } catch { Write-Status "    [!] Failed: $log" Yellow }
    }

    foreach ($log in $otherLogs) {
        try {
            Clear-EventLog -LogName $log -ErrorAction SilentlyContinue
            Write-Status "    [+] Cleared: $log" Green
        } catch { }
    }

    $logsToDisable = @(
        'Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant',
        'Microsoft-Windows-Application-Experience/Program-Compatibility-Troubleshooter',
        'Microsoft-Windows-Customer Experience Improvement Program/Consolidator'
    )

    foreach ($log in $logsToDisable) {
        try {
            & $WEVTUTIL sl "$log" /e:false 2>$null
            Write-Status "    [-] Disabled: $log" Cyan
        } catch { }
    }
}

Write-Status "  [i] Configuring pagefile..." Cyan
$ramGB = [math]::Round((Get-CimInstance Win32_PhysicalMemory | Measure-Object Capacity -Sum).Sum / 1GB)
$targetMB = [math]::Max(16, [math]::Min(4096, $ramGB * 1024))

$cs = Get-CimInstance Win32_ComputerSystem
if ($cs.AutomaticManagedPagefile) {
    $cs | Set-CimInstance -Property @{ AutomaticManagedPagefile = $false }
}

$page = Get-CimInstance Win32_PageFileSetting -EA SilentlyContinue
if ($page) {
    if ($page.InitialSize -ne $targetMB -or $page.MaximumSize -ne $targetMB) {
        $page.InitialSize = $page.MaximumSize = $targetMB
        $page | Set-CimInstance
    } else {
        Write-Status "  [SKIP] Pagefile already $targetMB MB" Gray
    }
} else {
    New-CimInstance -ClassName Win32_PageFileSetting -Property @{
        Name='C:\pagefile.sys'; InitialSize=$targetMB; MaximumSize=$targetMB
    } -ErrorAction Stop >$null
}
Write-Status "  [ OK ] Pagefile set to $targetMB MB" Green

Write-Host "`n[i] All SSD optimizations ended." -ForegroundColor Cyan

# ---------- 9. Reserved Storage ----------
Write-HostEx "`n[>] STEP 10: Disabling Reserved Storage..." -ForegroundColor Magenta

try {
   $reservedStorageState = Get-WindowsReservedStorageState -ErrorAction SilentlyContinue
   
   if ($reservedStorageState) {
       if ($reservedStorageState.ReservedStorageState -eq "Enabled") {
           Write-HostEx "  [i] Reserved Storage is enabled, disabling..." -ForegroundColor Yellow
           Set-WindowsReservedStorageState -State Disabled -ErrorAction Stop
           Write-HostEx "  [ OK ] Reserved Storage disabled" -ForegroundColor Green
       } else {
           Write-HostEx "  [ SKIP ] Reserved Storage already disabled" -ForegroundColor Gray
       }
   } else {
       Write-HostEx "  [i] Reserved Storage is not supported on this system" -ForegroundColor Yellow
   }
} catch {
   Write-HostEx "  [i] Error disabling Reserved Storage: $($_.Exception.Message)" -ForegroundColor Red
}

# ---------- Epilogue: apply policies ----------
Write-HostEx "`n[>] Finalizing: forcing Group Policy update..." -ForegroundColor Magenta
try {
    Start-Process -FilePath "$env:SystemRoot\System32\gpupdate.exe" -ArgumentList "/force" -Wait -NoNewWindow
    Write-HostEx "  [ OK ] Group Policy refreshed" -ForegroundColor Green
} catch {
    Write-HostEx "  [ WARN ] gpupdate failed: $_" -ForegroundColor Yellow
}

# ---------- 11. Summary ----------
Write-HostEx ("`n" + ("=" * 53)) -ForegroundColor Cyan
Write-HostEx "                   EXECUTION REPORT" -ForegroundColor Cyan
Write-HostEx ("=" * 53) -ForegroundColor Cyan

Write-HostEx ("  Registry:     {0} applied,   {1} skipped,   {2} failed" -f
              $script:Stats.RegistryApplied,
              $script:Stats.RegistrySkipped,
              $script:Stats.RegistryFailed) -ForegroundColor White

Write-HostEx ("  Services:     {0} disabled,  {1} not found, {2} failed" -f
              $script:Stats.ServicesDisabled,
              $script:Stats.ServicesNotFound,
              $script:Stats.ServicesFailed) -ForegroundColor White

Write-HostEx ("  Tasks:        {0} disabled,  {1} not found, {2} failed" -f
              $script:Stats.TasksDisabled,
              $script:Stats.TasksNotFound,
              $script:Stats.TasksFailed) -ForegroundColor White

Write-HostEx ("  Features:     {0} disabled,  {1} not found, {2} failed" -f
              $script:Stats.FeaturesDisabled,
              $script:Stats.FeaturesNotFound,
              $script:Stats.FeaturesFailed) -ForegroundColor White

Write-HostEx ("  Files/Keys:   {0} removed,   {1} not found, {2} failed" -f
              $script:Stats.ItemsRemoved,
              $script:Stats.ItemsNotFound,
              $script:Stats.ItemsFailed) -ForegroundColor White

Write-HostEx "`n[ OK ] All privacy settings have been applied!" -ForegroundColor Green
Write-HostEx "[ ! ] Please restart your computer to apply all changes." -ForegroundColor Yellow
Write-HostEx "`nPress 'Enter' key to exit..."
$null = Read-Host
