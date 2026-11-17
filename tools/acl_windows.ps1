param([Parameter(Mandatory=$true)][string]$RuntimePath,
      [Parameter(Mandatory=$true)][string]$ServiceAccount)
$ErrorActionPreference = 'Stop'
$target = (Resolve-Path -LiteralPath $RuntimePath).Path
if ($target -eq [System.IO.Path]::GetPathRoot($target) -or
    -not (Test-Path -LiteralPath (Join-Path $target 'server.json')) -or
    -not (Test-Path -LiteralPath (Join-Path $target 'data'))) {
    throw 'Specify a provisioned project runtime directory, never a drive root.'
}
# Explicit opt-in deployment command. No accounts are created, and only this directory is changed.
$identity = New-Object System.Security.Principal.NTAccount($ServiceAccount)
$sid = $identity.Translate([System.Security.Principal.SecurityIdentifier])
$acl = Get-Acl -LiteralPath $target
$acl.SetAccessRuleProtection($true, $false)
foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRuleSpecific($rule) }
$inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
$propagation = [System.Security.AccessControl.PropagationFlags]::None
$allow = [System.Security.AccessControl.AccessControlType]::Allow
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sid,'Modify',$inherit,$propagation,$allow)))
foreach ($known in @('S-1-5-18','S-1-5-32-544')) {
    $knownSid = New-Object System.Security.Principal.SecurityIdentifier($known)
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($knownSid,'FullControl',$inherit,$propagation,$allow)))
}
Set-Acl -LiteralPath $target -AclObject $acl
Get-Acl -LiteralPath $target | Format-List
