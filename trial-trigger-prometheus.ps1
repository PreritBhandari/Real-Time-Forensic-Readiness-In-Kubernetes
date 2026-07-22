param(
    [int]$TrialNumber = 1,
    [int]$MemoryThresholdMi = 1050,
    [string]$PrometheusUrl = "http://localhost:9090"
)

Write-Host "--- Forensic Watchdog: Monitoring for DDoS & Restart Risks ---" -ForegroundColor Cyan

# Added only for repeated-trial reporting.
$resultsFile = Join-Path $PSScriptRoot "Forensic_Experiment_Results.csv"
$monitoringStartTime = Get-Date

# Store the most recent pre-trigger Prometheus samples.
$preTriggerSamples = [System.Collections.Generic.List[object]]::new()

function Get-PrometheusMetrics {
    $memoryQuery = 'container_memory_working_set_bytes{namespace="forensic-lab",pod="cassandra-0",container="cassandra"}'
    $cpuQuery = 'sum(rate(container_cpu_usage_seconds_total{namespace="forensic-lab",pod="cassandra-0",container="cassandra"}[1m])) * 1000'

    try {
        $memoryUrl = "$PrometheusUrl/api/v1/query?query=$([uri]::EscapeDataString($memoryQuery))"
        $cpuUrl = "$PrometheusUrl/api/v1/query?query=$([uri]::EscapeDataString($cpuQuery))"

        $memoryResponse = Invoke-RestMethod -Uri $memoryUrl -TimeoutSec 5
        $cpuResponse = Invoke-RestMethod -Uri $cpuUrl -TimeoutSec 5

        if ($memoryResponse.status -ne "success" -or $memoryResponse.data.result.Count -eq 0) {
            return $null
        }

        $memoryMi = [math]::Round(
            ([double]$memoryResponse.data.result[0].value[1]) / 1MB,
            3
        )

        $cpuMillicores = 0
        if ($cpuResponse.status -eq "success" -and $cpuResponse.data.result.Count -gt 0) {
            $cpuMillicores = [math]::Round(
                [double]$cpuResponse.data.result[0].value[1],
                3
            )
        }

        return [PSCustomObject]@{
            Timestamp     = Get-Date
            CpuMillicores = $cpuMillicores
            MemoryMi      = $memoryMi
        }
    }
    catch {
        return $null
    }
}

while ($true) {
    # THE SENSORS: Prometheus Metrics and Deep Metadata Extraction
    $resourceSample = Get-PrometheusMetrics

    $exitCode = kubectl get pod cassandra-0 -n forensic-lab -o jsonpath='{.status.containerStatuses[0].lastState.terminated.exitCode}' 2>$null
    $reason = kubectl get pod cassandra-0 -n forensic-lab -o jsonpath='{.status.containerStatuses[0].lastState.terminated.reason}' 2>$null

    # Extract RAM value safely
    $ram = 0
    if ($resourceSample) {
        $ram = $resourceSample.MemoryMi
        $preTriggerSamples.Add($resourceSample)

        # Keep only the most recent 10 pre-trigger samples.
        while ($preTriggerSamples.Count -gt 10) {
            $preTriggerSamples.RemoveAt(0)
        }
    }

    # THE TRIGGER: RAM Spike (> threshold) OR OOMKill Fingerprint (137)
    if ($ram -gt $MemoryThresholdMi -or $exitCode -eq 137 -or $reason -eq "OOMKilled") {
        $triggerTime = Get-Date
        $ts = Get-Date -Format "HHmm_ss"
        Write-Host "!!! TRIGGER ACTIVATED at ${ts}: Abnormal Behavior Detected !!!" -ForegroundColor Red

        $incidentDir = "Forensic_Incident_Trial_${TrialNumber}_$ts"
        New-Item -ItemType Directory -Path $incidentDir -Force | Out-Null

        # Baseline immediately before collection.
        $baselineCpu = $null
        $baselineMemory = $null

        if ($preTriggerSamples.Count -gt 0) {
            $baselineCpu = [math]::Round(
                ($preTriggerSamples | Measure-Object CpuMillicores -Average).Average,
                3
            )
            $baselineMemory = [math]::Round(
                ($preTriggerSamples | Measure-Object MemoryMi -Average).Average,
                3
            )
        }

        $collectionStartTime = Get-Date
        $collectionLatencyMs = [math]::Round(
            ($collectionStartTime - $triggerTime).TotalMilliseconds,
            3
        )

        # Added only to quantify collection overhead.
        $collectionSamples = [System.Collections.Generic.List[object]]::new()
        $collectionMonitor = Start-Job -ArgumentList $PrometheusUrl -ScriptBlock {
            param($PrometheusUrl)

            $memoryQuery = 'container_memory_working_set_bytes{namespace="forensic-lab",pod="cassandra-0",container="cassandra"}'
            $cpuQuery = 'sum(rate(container_cpu_usage_seconds_total{namespace="forensic-lab",pod="cassandra-0",container="cassandra"}[1m])) * 1000'

            while ($true) {
                try {
                    $memoryUrl = "$PrometheusUrl/api/v1/query?query=$([uri]::EscapeDataString($memoryQuery))"
                    $cpuUrl = "$PrometheusUrl/api/v1/query?query=$([uri]::EscapeDataString($cpuQuery))"

                    $memoryResponse = Invoke-RestMethod -Uri $memoryUrl -TimeoutSec 5
                    $cpuResponse = Invoke-RestMethod -Uri $cpuUrl -TimeoutSec 5

                    if ($memoryResponse.status -eq "success" -and $memoryResponse.data.result.Count -gt 0) {
                        $memoryMi = [math]::Round(
                            ([double]$memoryResponse.data.result[0].value[1]) / 1MB,
                            3
                        )

                        $cpuMillicores = 0
                        if ($cpuResponse.status -eq "success" -and $cpuResponse.data.result.Count -gt 0) {
                            $cpuMillicores = [math]::Round(
                                [double]$cpuResponse.data.result[0].value[1],
                                3
                            )
                        }

                        [PSCustomObject]@{
                            Timestamp     = Get-Date
                            CpuMillicores = $cpuMillicores
                            MemoryMi      = $memoryMi
                        }
                    }
                }
                catch {}

                Start-Sleep -Seconds 1
            }
        }

        Write-Host "Securing Artifacts and Decoding Audit Logs..." -ForegroundColor Yellow

        kubectl describe pod cassandra-0 -n forensic-lab > "$incidentDir/1_Pod_Status.txt"
        kubectl logs cassandra-0 -n forensic-lab --previous > "$incidentDir/2_Crash_Autopsy.txt" 2>$null

        Write-Host "Converting binary Audit Logs to readable text..." -ForegroundColor Gray
        kubectl exec cassandra-0 -n forensic-lab -- /opt/cassandra/tools/bin/auditlogviewer /var/log/cassandra/audit/ > "$incidentDir/3_Decoded_Malicious_Queries.txt" 2>$null

        kubectl cp forensic-lab/cassandra-0:/etc/cassandra/ "$incidentDir/Config_Backup/" 2>$null
        kubectl cp forensic-lab/cassandra-0:/var/log/cassandra/ "$incidentDir/System_Logs/" 2>$null
        kubectl cp forensic-lab/cassandra-0:/var/lib/cassandra/commitlog/ "$incidentDir/Raw_CommitLogs_Binary/" 2>$null

        $collectionEndTime = Get-Date
        $collectionDurationMs = [math]::Round(
            ($collectionEndTime - $collectionStartTime).TotalMilliseconds,
            3
        )

        Stop-Job $collectionMonitor -ErrorAction SilentlyContinue
        $collectionSamples = @(Receive-Job $collectionMonitor -ErrorAction SilentlyContinue)
        Remove-Job $collectionMonitor -Force -ErrorAction SilentlyContinue

        $collectionCpuMean = $null
        $collectionCpuPeak = $null
        $collectionMemoryMean = $null
        $collectionMemoryPeak = $null

        if ($collectionSamples.Count -gt 0) {
            $collectionCpuMean = [math]::Round(
                ($collectionSamples | Measure-Object CpuMillicores -Average).Average,
                3
            )
            $collectionCpuPeak = [math]::Round(
                ($collectionSamples | Measure-Object CpuMillicores -Maximum).Maximum,
                3
            )
            $collectionMemoryMean = [math]::Round(
                ($collectionSamples | Measure-Object MemoryMi -Average).Average,
                3
            )
            $collectionMemoryPeak = [math]::Round(
                ($collectionSamples | Measure-Object MemoryMi -Maximum).Maximum,
                3
            )
        }

        $cpuOverhead = $null
        $memoryOverhead = $null

        if ($null -ne $baselineCpu -and $null -ne $collectionCpuMean) {
            $cpuOverhead = [math]::Round($collectionCpuMean - $baselineCpu, 3)
        }

        if ($null -ne $baselineMemory -and $null -ne $collectionMemoryMean) {
            $memoryOverhead = [math]::Round($collectionMemoryMean - $baselineMemory, 3)
        }

        # One CSV row is written for each trial.
        [PSCustomObject]@{
            TrialNumber               = $TrialNumber
            TriggerActivated          = $true
            MemoryAtTriggerMi         = $ram
            ExitCode                  = $exitCode
            TerminationReason         = $reason
            MonitoringStartTime       = $monitoringStartTime.ToString("yyyy-MM-dd HH:mm:ss.fff")
            TriggerTime               = $triggerTime.ToString("yyyy-MM-dd HH:mm:ss.fff")
            CollectionStartTime       = $collectionStartTime.ToString("yyyy-MM-dd HH:mm:ss.fff")
            CollectionEndTime         = $collectionEndTime.ToString("yyyy-MM-dd HH:mm:ss.fff")
            TriggerToCollectionMs     = $collectionLatencyMs
            CollectionDurationMs      = $collectionDurationMs
            BaselineCpuMeanMillicores = $baselineCpu
            CollectionCpuMeanMillicores = $collectionCpuMean
            CollectionCpuPeakMillicores = $collectionCpuPeak
            CpuOverheadMillicores     = $cpuOverhead
            BaselineMemoryMeanMi      = $baselineMemory
            CollectionMemoryMeanMi    = $collectionMemoryMean
            CollectionMemoryPeakMi    = $collectionMemoryPeak
            MemoryOverheadMi          = $memoryOverhead
            IncidentDirectory         = $incidentDir
        } | Export-Csv -Path $resultsFile -Append -NoTypeInformation

        Write-Host "SUCCESS: Artifacts secured in $incidentDir" -ForegroundColor Green
        Write-Host "Trigger-to-collection latency: $collectionLatencyMs ms" -ForegroundColor Cyan
        Write-Host "Collection duration: $collectionDurationMs ms" -ForegroundColor Cyan
        Write-Host "CPU overhead: $cpuOverhead millicores" -ForegroundColor Cyan
        Write-Host "Memory overhead: $memoryOverhead Mi" -ForegroundColor Cyan
        Write-Host "Trial result saved to $resultsFile" -ForegroundColor Cyan
        break 
    }

    Start-Sleep -Seconds 2
}
