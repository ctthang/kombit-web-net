#Requires -Version 5.1
<##
.SYNOPSIS
Adds a stable machineKey to a deployed SAML sample Web.config.
.DESCRIPTION
Stop the application pool before running. Existing explicit or encrypted keys are
preserved. Keys are never printed or placed on the clipboard. Keep the generated
backup outside source control. Replacing a key invalidates cookies and protected
emergency state; -ReplaceExisting is only for a coordinated reset.
##>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)][string]$WebConfigPath,
    [switch]$ReplaceExisting
)
$ErrorActionPreference = 'Stop'
$path = (Resolve-Path -LiteralPath $WebConfigPath).ProviderPath
if ([IO.Path]::GetFileName($path) -ine 'web.config') { throw 'Select the deployed Web.config file.' }
$directory = [IO.DirectoryInfo]::new([IO.Path]::GetDirectoryName($path))
while ($null -ne $directory) {
    if (Test-Path -LiteralPath (Join-Path $directory.FullName '.git')) { throw 'Generate machine keys only in a deployed website, outside source control.' }
    $directory = $directory.Parent
}
$document = [xml]::new()
$document.PreserveWhitespace = $true
$document.Load($path)
if ($document.DocumentElement.Name -ne 'configuration') { throw 'Not an application configuration file.' }
$systemWeb = $document.SelectSingleNode('/configuration/system.web')
if ($null -eq $systemWeb) {
    $systemWeb = $document.CreateElement('system.web')
    [void]$document.DocumentElement.AppendChild($systemWeb)
}
$existing = $systemWeb.SelectSingleNode('machineKey')
if ($null -ne $existing) {
    if ($existing.HasAttribute('configSource')) { throw 'The machineKey uses configSource. Update its external configuration file separately.' }
    $explicit = $existing.HasAttribute('configProtectionProvider') -or (
        $existing.GetAttribute('validationKey') -match '^[0-9a-fA-F]{40,128}$' -and
        $existing.GetAttribute('decryptionKey') -match '^[0-9a-fA-F]{32,64}$')
    if ($explicit -and !$ReplaceExisting) { Write-Output 'Existing machine key preserved. No changes made.'; return }
}
if (!$PSCmdlet.ShouldProcess($path, 'Back up Web.config and install a new stable machine key')) { return }
$backup = $path + '.machinekey-' + [DateTime]::UtcNow.ToString('yyyyMMddHHmmssfff') + '-' + [guid]::NewGuid().ToString('N') + '.config'
Copy-Item -LiteralPath $path -Destination $backup
Set-Acl -LiteralPath $backup -AclObject (Get-Acl -LiteralPath $path)
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
$validationBytes = New-Object byte[] 64
$decryptionBytes = New-Object byte[] 32
try {
    $rng.GetBytes($validationBytes)
    $rng.GetBytes($decryptionBytes)
    $machineKey = $document.CreateElement('machineKey')
    $machineKey.SetAttribute('validationKey', [BitConverter]::ToString($validationBytes).Replace('-', ''))
    $machineKey.SetAttribute('decryptionKey', [BitConverter]::ToString($decryptionBytes).Replace('-', ''))
    $machineKey.SetAttribute('validation', 'HMACSHA256')
    $machineKey.SetAttribute('decryption', 'AES')
    if ($null -eq $existing) { [void]$systemWeb.AppendChild($machineKey) }
    else { [void]$systemWeb.ReplaceChild($machineKey, $existing) }
    try { $document.Save($path) }
    catch { Copy-Item -LiteralPath $backup -Destination $path -Force; throw }
    Write-Output "Machine key installed. Backup: $backup"
} finally {
    [Array]::Clear($validationBytes, 0, $validationBytes.Length)
    [Array]::Clear($decryptionBytes, 0, $decryptionBytes.Length)
    $rng.Dispose()
}
