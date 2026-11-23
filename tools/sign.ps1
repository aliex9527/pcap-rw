# Sign one or more PE files with the self-signed pcap-rw code signing certificate.
# Usage:
#   powershell -ExecutionPolicy Bypass -File tools\sign.ps1 dist\pcap-rw.exe
#   powershell -ExecutionPolicy Bypass -File tools\sign.ps1 dist\*.exe -NoTimestamp
#
# The certificate lives in ..\certs (git-ignored). Run make-signing-cert.ps1 once
# to create it. A timestamp server keeps the signature valid after the certificate
# expires; skip it with -NoTimestamp when offline.
#
# Windows PowerShell 5.1 has no -Password parameter on Get-PfxCertificate, so the
# pfx is imported into Cert:\CurrentUser\My (private key persisted) and looked up
# by subject. Repeat runs reuse the imported copy instead of duplicating it.

param(
    [Parameter(Mandatory = $true, ValueFromRemainingArguments = $true)]
    [string[]]$Path,
    [switch]$NoTimestamp
)

$ErrorActionPreference = "Stop"

$repo = Split-Path -Parent $PSScriptRoot
$pfx = Join-Path $repo "certs\pcap-rw-signing.pfx"
$pwFile = Join-Path $repo "certs\.password"

if (-not (Test-Path $pfx)) {
    throw "Certificate not found: $pfx`nRun tools\make-signing-cert.ps1 first."
}
if (-not (Test-Path $pwFile)) {
    throw "Password file not found: $pwFile"
}

$secure = New-Object System.Security.SecureString
foreach ($ch in (Get-Content $pwFile -Raw).Trim().ToCharArray()) {
    $secure.AppendChar($ch)
}

$subject = "CN=aliex9527 pcap-rw, O=aliex9527, C=CN"
$cert = Get-ChildItem Cert:\CurrentUser\My |
    Where-Object { $_.Subject -eq $subject -and $_.HasPrivateKey } |
    Select-Object -First 1

if (-not $cert) {
    $imported = Import-PfxCertificate -FilePath $pfx -CertStoreLocation Cert:\CurrentUser\My -Password $secure
    $cert = Get-Item ("Cert:\CurrentUser\My\" + $imported.Thumbprint)
}

Write-Output ("Cert       : " + $cert.Thumbprint + " (expires " + $cert.NotAfter.ToString("yyyy-MM-dd") + ")")

foreach ($item in $Path) {
    foreach ($file in (Resolve-Path $item)) {
        $target = $file.Path
        if ($NoTimestamp) {
            $result = Set-AuthenticodeSignature -FilePath $target -Certificate $cert -HashAlgorithm SHA256
        } else {
            $result = Set-AuthenticodeSignature -FilePath $target -Certificate $cert -HashAlgorithm SHA256 `
                -TimestampServer "http://timestamp.digicert.com"
        }
        $size = (Get-Item $target).Length
        Write-Output ("Signed : " + $target)
        Write-Output ("  status : " + $result.Status)
        Write-Output ("  size   : " + $size + " bytes")
        if ($result.Status -ne "Valid") {
            Write-Output ("  message: " + $result.StatusMessage)
        }
    }
}
