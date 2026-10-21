#Requires -Version 7.2
param(
    [Parameter(Mandatory)][string]$Directory,
    [Parameter(Mandatory)][string]$EmergencyAudience,
    [string]$KeyId = 'saml-emergency-encryption',
    [string]$ApplicationPoolIdentity
)
$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'This SAML PoC requires Windows.' }
$folder = [IO.Path]::GetFullPath($Directory)
if (-not [IO.Path]::IsPathFullyQualified($Directory) -or $folder.StartsWith('\\') -or (Test-Path -LiteralPath $folder)) { throw 'Choose a new absolute local directory outside the website and all repositories.' }
$parent = [IO.DirectoryInfo]::new($folder)
while ($null -ne $parent) {
    if (Test-Path -LiteralPath (Join-Path $parent.FullName '.git')) { throw 'Private keys cannot be provisioned into a repository.' }
    $parent = $parent.Parent
}
if ([string]::IsNullOrWhiteSpace($EmergencyAudience) -or [string]::IsNullOrWhiteSpace($KeyId)) { throw 'The audience and key ID are required.' }
$scriptRoot = [IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\') + '\'
if (($folder.TrimEnd('\') + '\').StartsWith($scriptRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'Private keys must be outside the application directory.' }
New-Item -ItemType Directory -Path $folder | Out-Null
$permissions = [Security.AccessControl.DirectorySecurity]::new()
$permissions.SetAccessRuleProtection($true, $false)
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().User
foreach ($principal in @($currentUser, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'), [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))) {
    $permissions.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($principal, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
}
if ($ApplicationPoolIdentity) { $permissions.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($ApplicationPoolIdentity, 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow')) }
Set-Acl -LiteralPath $folder -AclObject $permissions
$rsa = [Security.Cryptography.RSA]::Create(2048)
try {
    $purpose = [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes('SamlSample.Emergency.EncryptionKey.v1|' + $EmergencyAudience))
    $privateBytes = [Text.Encoding]::UTF8.GetBytes($rsa.ToXmlString($true))
    [IO.File]::WriteAllBytes((Join-Path $folder 'decryption-key.bin'), [Security.Cryptography.ProtectedData]::Protect($privateBytes, $purpose, [Security.Cryptography.DataProtectionScope]::LocalMachine))
    $key = $rsa.ExportParameters($false)
    $modulus = [Convert]::ToBase64String($key.Modulus).TrimEnd('=').Replace('+','-').Replace('/','_')
    $exponent = [Convert]::ToBase64String($key.Exponent).TrimEnd('=').Replace('+','-').Replace('/','_')
    $public = [ordered]@{ kty='RSA'; kid=$KeyId; alg='RSA-OAEP'; use='enc'; n=$modulus; e=$exponent }
    [IO.File]::WriteAllText((Join-Path $folder 'encryption-public.jwk.json'), ($public | ConvertTo-Json))
} finally { $rsa.Dispose() }
'Created the protected SAML decryption key and public JWK outside source control.'
