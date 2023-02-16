# Set PowerShell execution policy to RemoteSigned for the current user
$ExecutionPolicy = Get-ExecutionPolicy -Scope CurrentUser
if ($ExecutionPolicy -eq "RemoteSigned") {
    Write-Verbose "Execution policy is already set to RemoteSigned for the current user, skipping..." -Verbose
}
else {
    Write-Verbose "Setting execution policy to RemoteSigned for the current user..." -Verbose
    Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
}

# Install chocolatey
if ([bool](Get-Command -Name 'choco' -ErrorAction SilentlyContinue)) {
    Write-Verbose "Chocolatey is already installed, skip installation." -Verbose
}
else {
    Write-Verbose "Installing Chocolatey..." -Verbose
    Set-ExecutionPolicy Bypass -Scope Process -Force; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
}

# Install OpenSSH Server
if ([bool](Get-Service -Name sshd -ErrorAction SilentlyContinue)) {
    Write-Verbose "OpenSSH is already installed, skip installation." -Verbose
}
else {
    Write-Verbose "Installing OpenSSH..." -Verbose
    $openSSHpackages = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*' | Select-Object -ExpandProperty Name

    foreach ($package in $openSSHpackages) {
        Add-WindowsCapability -Online -Name $package
    }

    # Start the sshd service
    Write-Verbose "Starting OpenSSH service..." -Verbose
    Start-Service sshd
    Set-Service -Name sshd -StartupType 'Automatic'

    # Confirm the Firewall rule is configured. It should be created automatically by setup. Run the following to verify
    Write-Verbose "Confirm the Firewall rule is configured..." -Verbose
    if (!(Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue | Select-Object Name, Enabled)) {
        Write-Output "Firewall Rule 'OpenSSH-Server-In-TCP' does not exist, creating it..."
        New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' `
            -DisplayName 'OpenSSH Server (sshd)' `
            -Enabled True `
            -Direction Inbound `
            -Protocol TCP `
            -Action Allow `
            -LocalPort 22
    }
    else {
        Write-Output "Firewall rule 'OpenSSH-Server-In-TCP' has been created and exists."
    }
}

$username = "provision"
if(Get-LocalUser $username -ErrorAction ignore){
    Write-Verbose "$username user already exists" -Verbose
}
else{
    $Password = Read-Host -AsSecureString -Prompt "Password? "
    New-LocalUser $username -Password $Password -Description "provision account used by alariotech"
    Add-LocalGroupMember -Group "Administrators" -Member $username
}

# Set various known paths
$openSSHZip = Join-Path $env:TEMP 'OpenSSH.zip'
$openSSHInstallDir = Join-Path $env:ProgramFiles 'OpenSSH'
$openSSHInstallScript = Join-Path $openSSHInstallDir 'install-sshd.ps1'
$openSSHDownloadKeyScript = Join-Path $openSSHInstallDir 'download-key-pair.ps1'
$openSSHDaemon = Join-Path $openSSHInstallDir 'sshd.exe'
$openSSHDaemonConfig = [io.path]::combine($env:ProgramData, 'ssh', 'sshd_config')


$keyDownloadScript = @'

$openSSHAuthorizedKeys = 'c:\ProgramData\ssh\administrators_authorized_keys'

$keyUrl = "https://raw.githubusercontent.com/MichaelMcNeil/ansible-windows/master/id_rsa.pub"
$keyReq = [System.Net.WebRequest]::Create($keyUrl)
$keyResp = $keyReq.GetResponse()
$keyRespStream = $keyResp.getResponseStream()
$streamReader = New-Object System.IO.StreamReader $keyRespStream
$keyMaterial | Out-File -Append -FilePath $openSSHAuthorizedKeys -Encoding ASCII


# $pubkey = "$env:temp\id_rsa.pub"
# (New-Object -TypeName System.Net.WebClient).DownloadFile($url, $pubkey)
# $authorizedKey = Get-Content -Path $env:temp\id_rsa.pub
# Add-Content -Force -Path $env:ProgramData\ssh\administrators_authorized_keys -Value '$authorizedKey'

#Ensure Access Control
$acl = Get-ACL -Path $openSSHAuthorizedKeys
$acl.SetAccessRuleProtection($True, $True)
Set-Acl -Path $openSSHAuthorizedKeys -AclObject $acl

$acl = Get-ACL -Path $openSSHAuthorizedKeys
$ar = New-Object System.Security.AccessControl.FileSystemAccessRule( `
"NT Authority\Authenticated Users", "ReadAndExecute", "Allow")
$acl.RemoveAccessRule($ar)
$ar = New-Object System.Security.AccessControl.FileSystemAccessRule( `
"BUILTIN\Administrators", "FullControl", "Allow")
$acl.RemoveAccessRule($ar)
$ar = New-Object System.Security.AccessControl.FileSystemAccessRule( `
"BUILTIN\Users", "FullControl", "Allow")
$acl.RemoveAccessRule($ar)
Set-Acl -Path $openSSHAuthorizedKeys -AclObject $acl


Disable-ScheduledTask -TaskName "Download Key Pair"

$sshdConfigContent = @"
# Modified sshd_config, created by Packer provisioner

PasswordAuthentication yes
PubKeyAuthentication yes
PidFile __PROGRAMDATA__/ssh/logs/sshd.pid
AuthorizedKeysFile __PROGRAMDATA__/ssh/authorized_keys
AllowUsers Administrator

Subsystem       sftp    sftp-server.exe
"@

Set-Content -Path C:\ProgramData\ssh\sshd_config `
    -Value $sshdConfigContent

'@

$keyDownloadScript | Out-File $openSSHDownloadKeyScript

# Create Task - Ensure the name matches the verbatim version above
$taskName = "Download Key Pair"
$principal = New-ScheduledTaskPrincipal `
    -UserID "NT AUTHORITY\SYSTEM" `
    -LogonType ServiceAccount `
    -RunLevel Highest
$action = New-ScheduledTaskAction -Execute 'Powershell.exe' `
  -Argument "-NoProfile -File ""$openSSHDownloadKeyScript"""
$trigger =  New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -TaskName $taskName `
    -Description $taskName
Disable-ScheduledTask -TaskName $taskName

# Run the install script, terminate if it fails
& Powershell.exe -ExecutionPolicy Bypass -File $openSSHDownloadKeyScript
if ($LASTEXITCODE -ne 0) {
	throw("Failed to download key pair")
}


# icacls $env:ProgramData\ssh\administrators_authorized_keys /inheritance:r /grant "Administrators:F" /grant "SYSTEM:F"
