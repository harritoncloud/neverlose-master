param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9.-]+$')]
    [string]$ServerHost,

    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$SshUser = "root",

    [string]$KeyPath = (Join-Path $env:USERPROFILE ".ssh\neverlose_auth_ed25519")
)

$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = "Discord bot token"
$form.StartPosition = "CenterScreen"
$form.ClientSize = New-Object System.Drawing.Size(500, 145)
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox = $false
$form.MinimizeBox = $false
$form.TopMost = $true

$label = New-Object System.Windows.Forms.Label
$label.AutoSize = $true
$label.Location = New-Object System.Drawing.Point(18, 18)
$label.Text = "Paste the Discord bot token. It will not be stored on this PC."
$form.Controls.Add($label)

$tokenBox = New-Object System.Windows.Forms.TextBox
$tokenBox.Location = New-Object System.Drawing.Point(20, 47)
$tokenBox.Size = New-Object System.Drawing.Size(458, 24)
$tokenBox.UseSystemPasswordChar = $true
$tokenBox.ShortcutsEnabled = $true
$form.Controls.Add($tokenBox)

$submit = New-Object System.Windows.Forms.Button
$submit.Location = New-Object System.Drawing.Point(298, 93)
$submit.Size = New-Object System.Drawing.Size(86, 30)
$submit.Text = "Connect"
$submit.DialogResult = [System.Windows.Forms.DialogResult]::OK
$form.AcceptButton = $submit
$form.Controls.Add($submit)

$cancel = New-Object System.Windows.Forms.Button
$cancel.Location = New-Object System.Drawing.Point(392, 93)
$cancel.Size = New-Object System.Drawing.Size(86, 30)
$cancel.Text = "Cancel"
$cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$form.CancelButton = $cancel
$form.Controls.Add($cancel)

$form.Add_Shown({ $tokenBox.Focus() })
if ($form.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
    exit 0
}

$token = $tokenBox.Text.Trim()
$tokenBox.Clear()
$form.Dispose()

if ($token.Length -lt 40 -or $token.Length -gt 256 -or $token -match "\s") {
    [System.Windows.Forms.MessageBox]::Show(
        "The token format is invalid.",
        "Discord setup",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
    exit 1
}

if (-not (Test-Path -LiteralPath $KeyPath)) {
    throw "SSH key is missing: $KeyPath"
}

$destination = "$SshUser@$ServerHost"
$startInfo = New-Object System.Diagnostics.ProcessStartInfo
$startInfo.FileName = (Get-Command ssh.exe).Source
$startInfo.Arguments = '-i "' + $KeyPath + '" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes ' + $destination + ' "/usr/local/sbin/nl-auth-register-discord"'
$startInfo.UseShellExecute = $false
$startInfo.CreateNoWindow = $true
$startInfo.RedirectStandardInput = $true
$startInfo.RedirectStandardOutput = $true
$startInfo.RedirectStandardError = $true

$process = New-Object System.Diagnostics.Process
$process.StartInfo = $startInfo
$null = $process.Start()
$process.StandardInput.Write($token + "`n")
$process.StandardInput.Close()
$token = $null

$stdout = $process.StandardOutput.ReadToEnd()
$stderr = $process.StandardError.ReadToEnd()
$process.WaitForExit()

if ($process.ExitCode -eq 0) {
    [System.Windows.Forms.MessageBox]::Show(
        "Discord commands were registered successfully.",
        "Discord setup",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
    ) | Out-Null
    exit 0
}

$details = ($stderr + "`n" + $stdout).Trim()
if ($details.Length -gt 600) {
    $details = $details.Substring(0, 600)
}
[System.Windows.Forms.MessageBox]::Show(
    "Discord setup failed.`n`n$details",
    "Discord setup",
    [System.Windows.Forms.MessageBoxButtons]::OK,
    [System.Windows.Forms.MessageBoxIcon]::Error
) | Out-Null
exit 1
