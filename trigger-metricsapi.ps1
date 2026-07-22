Write-Host "--- Forensic Watchdog: Monitoring for DDoS & Restart Risks ---" -ForegroundColor Cyan

while ($true) {
    # THE SENSORS: Metrics and Deep Metadata Extraction
    $metrics = kubectl top pod cassandra-0 -n forensic-lab --no-headers 2>$null
    
    $exitCode = kubectl get pod cassandra-0 -n forensic-lab -o jsonpath='{.status.containerStatuses[0].lastState.terminated.exitCode}' 2>$null
    $reason = kubectl get pod cassandra-0 -n forensic-lab -o jsonpath='{.status.containerStatuses[0].lastState.terminated.reason}' 2>$null

    # Extract RAM value safely
    $ram = 0
    if ($metrics) { 
        $ram = [int]($metrics.Split(" ", [System.StringSplitOptions]::RemoveEmptyEntries)[2].Replace("Mi","")) 
    }

    # THE TRIGGER: RAM Spike (>1050) OR OOMKill Fingerprint (137)
    if ($ram -gt 1050 -or $exitCode -eq 137 -or $reason -eq "OOMKilled") {
        $ts = Get-Date -Format "HHmm_ss"
        Write-Host "!!! TRIGGER ACTIVATED at ${ts}: Abnormal Behavior Detected !!!" -ForegroundColor Red
        
        $incidentDir = "Forensic_Incident_$ts"
        New-Item -ItemType Directory -Path $incidentDir -Force | Out-Null

        Write-Host "Securing Artifacts and Decoding Audit Logs..." -ForegroundColor Yellow
        
        kubectl describe pod cassandra-0 -n forensic-lab > "$incidentDir/1_Pod_Status.txt"
        kubectl logs cassandra-0 -n forensic-lab --previous > "$incidentDir/2_Crash_Autopsy.txt" 2>$null


        Write-Host "Converting binary Audit Logs to readable text..." -ForegroundColor Gray
        kubectl exec cassandra-0 -n forensic-lab -- /opt/cassandra/tools/bin/auditlogviewer /var/log/cassandra/audit/ > "$incidentDir/3_Decoded_Malicious_Queries.txt" 2>$null
        
        kubectl cp forensic-lab/cassandra-0:/etc/cassandra/ "$incidentDir/Config_Backup/" 2>$null
        kubectl cp forensic-lab/cassandra-0:/var/log/cassandra/ "$incidentDir/System_Logs/" 2>$null
        kubectl cp forensic-lab/cassandra-0:/var/lib/cassandra/commitlog/ "$incidentDir/Raw_CommitLogs_Binary/" 2>$null
        
        Write-Host "SUCCESS: Artifacts secured in $incidentDir" -ForegroundColor Green
        break 
    }
    
    Start-Sleep -Seconds 2
}