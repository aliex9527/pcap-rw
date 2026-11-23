# Trust the self-signed pcap-rw code signing certificate on this machine.
# Usage:  powershell -ExecutionPolicy Bypass -File tools\trust-cert.ps1
#
# Adds ..\certs\pcap-rw-signing.cer to the current user's "Trusted Root
# Certification Authorities" and "Trusted Publishers" stores, so that
# Get-AuthenticodeSignature reports Valid and Explorer stops flagging the exe.
#
# Windows shows a security confirmation dialog for the root store - click 是/Yes.
# This only affects the current user; other machines need the same step (or the
# .cer installed once by hand).

$ErrorActionPreference = "Stop"

$repo = Split-Path -Parent $PSScriptRoot
$cer = Join-Path $repo "certs\pcap-rw-signing.cer"

if (-not (Test-Path $cer)) {
    throw "Certificate not found: $cer`nRun tools\make-signing-cert.ps1 first."
}

$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cer)
Write-Output ("Cert: " + $cert.Subject)
Write-Output ("      " + $cert.Thumbprint)

foreach ($storeName in @("Root", "TrustedPublisher")) {
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, "CurrentUser")
    $store.Open("ReadWrite")
    try {
        $existing = $store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
        if ($existing) {
            Write-Output ("  " + $storeName + " : 已存在，跳过")
        } else {
            $store.Add($cert)
            Write-Output ("  " + $storeName + " : 已添加")
        }
    } finally {
        $store.Close()
    }
}

Write-Output ""
Write-Output "现在可以校验已签名文件："
Write-Output "  powershell -Command `"Get-AuthenticodeSignature dist\pcap-rw.exe | Format-List`""
