# secret-dialog-windows.ps1 — native Windows dialog (WinForms): hidden field + eye button to reveal.
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File secret-dialog-windows.ps1 -Title T -Message M [-Visible 1] [-Timeout 300]
# stdout: the typed text (no trailing newline). exit 0 ok · 2 cancelled · 3 timed out · 4 empty
# UNTESTED by the author on real Windows — please open an issue with results.
param(
  [string]$Title = "Secret",
  [string]$Message = "",
  [string]$Visible = "0",
  [int]$Timeout = 300
)
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$form = New-Object System.Windows.Forms.Form
$form.Text = $Title
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox = $false; $form.MinimizeBox = $false
$form.TopMost = $true
$form.ClientSize = New-Object System.Drawing.Size(440, 170)
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9)

$label = New-Object System.Windows.Forms.Label
$label.Text = $Message
$label.Location = New-Object System.Drawing.Point(12, 12)
$label.Size = New-Object System.Drawing.Size(416, 60)
$form.Controls.Add($label)

$box = New-Object System.Windows.Forms.TextBox
$box.Location = New-Object System.Drawing.Point(12, 80)
$box.Size = New-Object System.Drawing.Size(370, 24)
$box.Font = New-Object System.Drawing.Font("Consolas", 10)
$box.UseSystemPasswordChar = ($Visible -ne "1")
$form.Controls.Add($box)

$eye = New-Object System.Windows.Forms.Button
$eye.Location = New-Object System.Drawing.Point(388, 79)
$eye.Size = New-Object System.Drawing.Size(40, 26)
$eye.Text = if ($Visible -eq "1") { "hide" } else { "show" }
$eye.Add_Click({
  $box.UseSystemPasswordChar = -not $box.UseSystemPasswordChar
  $eye.Text = if ($box.UseSystemPasswordChar) { "show" } else { "hide" }
  $hint.Text = if ($box.UseSystemPasswordChar) { "Hidden field. Click show to check what you pasted." } else { "VISIBLE. Click hide to mask it again." }
  $box.Focus()
})
$form.Controls.Add($eye)

$hint = New-Object System.Windows.Forms.Label
$hint.Text = "Hidden field. Click show to check what you pasted."
$hint.ForeColor = [System.Drawing.Color]::Gray
$hint.Location = New-Object System.Drawing.Point(12, 108)
$hint.Size = New-Object System.Drawing.Size(416, 18)
$form.Controls.Add($hint)

$ok = New-Object System.Windows.Forms.Button
$ok.Text = "OK"; $ok.DialogResult = "OK"
$ok.Location = New-Object System.Drawing.Point(266, 134); $ok.Size = New-Object System.Drawing.Size(78, 26)
$form.Controls.Add($ok); $form.AcceptButton = $ok

$cancel = New-Object System.Windows.Forms.Button
$cancel.Text = "Cancel"; $cancel.DialogResult = "Cancel"
$cancel.Location = New-Object System.Drawing.Point(350, 134); $cancel.Size = New-Object System.Drawing.Size(78, 26)
$form.Controls.Add($cancel); $form.CancelButton = $cancel

$script:timedOut = $false
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = [Math]::Max(1, $Timeout) * 1000
$timer.Add_Tick({ $script:timedOut = $true; $timer.Stop(); $form.DialogResult = "Cancel"; $form.Close() })
$timer.Start()

$form.Add_Shown({ $form.Activate(); $box.Focus() })
$result = $form.ShowDialog()
$timer.Stop()

if ($script:timedOut) { exit 3 }
if ($result -ne [System.Windows.Forms.DialogResult]::OK) { exit 2 }
if ([string]::IsNullOrEmpty($box.Text)) { exit 4 }
[Console]::Out.Write($box.Text)
exit 0
