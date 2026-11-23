# Generate a self-signed Authenticode code signing certificate for pcap-rw.
# Usage:  powershell -ExecutionPolicy Bypass -File tools\make-signing-cert.ps1
#
# Output (all inside ..\certs, which is git-ignored):
#   pcap-rw-signing.pfx  - private key + certificate, protected by a random password
#   pcap-rw-signing.cer  - public certificate only, safe to hand out
#   .password            - the generated password, keep it local
#
# Keep the .pfx private. Anyone with that file plus the password can sign code
# in your name.

$ErrorActionPreference = "Stop"

$repo = Split-Path -Parent $PSScriptRoot
$dir = Join-Path $repo "certs"
New-Item -ItemType Directory -Force -Path $dir | Out-Null

# 24-char password without look-alike characters (0/O, 1/l/I).
$chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$bytes = New-Object byte[] 24
$rng.GetBytes($bytes)
$text = New-Object System.Text.StringBuilder
$secure = New-Object System.Security.SecureString
foreach ($b in $bytes) {
    $ch = $chars[$b % $chars.Length]
    [void]$text.Append($ch)
    $secure.AppendChar($ch)
}
$plain = $text.ToString()
Set-Content -Path (Join-Path $dir ".password") -Value $plain -NoNewline -Encoding ascii

$cert = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject "CN=aliex9527 pcap-rw, O=aliex9527, C=CN" `
    -FriendlyName "pcap-rw code signing" `
    -KeyUsage DigitalSignature `
    -KeyExportPolicy Exportable `
    -KeyLength 3072 `
    -KeyAlgorithm RSA `
    -HashAlgorithm SHA256 `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -NotAfter (Get-Date).AddYears(5)

Export-PfxCertificate -Cert $cert -FilePath (Join-Path $dir "pcap-rw-signing.pfx") -Password $secure | Out-Null
Export-Certificate -Cert $cert -FilePath (Join-Path $dir "pcap-rw-signing.cer") -Type CERT | Out-Null

Write-Output ("Subject    : " + $cert.Subject)
Write-Output ("Thumbprint : " + $cert.Thumbprint)
Write-Output ("Valid      : " + $cert.NotBefore.ToString("yyyy-MM-dd") + " -> " + $cert.NotAfter.ToString("yyyy-MM-dd"))
Write-Output ("Password   : " + (Join-Path $dir ".password"))
Get-ChildItem $dir | Select-Object Name, Length | Format-Table -AutoSize
