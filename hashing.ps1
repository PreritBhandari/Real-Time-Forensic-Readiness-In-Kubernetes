# Generate SHA-256 hashes for all collected artifacts

$incidentDir = "C:\Users\patri\Documents\UofW\Security and Digital Forensics\Final project\Project\Forensic_Incident_Trial_3_1549_00"

$files = Get-ChildItem $incidentDir -Recurse -File |
    Where-Object { $_.Name -ne "SHA256_Hashes.csv" }

$results = foreach ($file in $files) {

    $hash = Get-FileHash $file.FullName -Algorithm SHA256

    [PSCustomObject]@{
        File         = $file.Name
        RelativePath = $file.FullName.Replace($incidentDir + "\", "")
        SHA256       = $hash.Hash
        Timestamp    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
}

$results | Export-Csv "$incidentDir\SHA256_Hashes.csv" -NoTypeInformation