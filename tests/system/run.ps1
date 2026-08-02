[CmdletBinding(DefaultParameterSetName = 'Scenario')]
param(
    [Parameter(ParameterSetName = 'List')]
    [switch]$List,
    [Parameter(ParameterSetName = 'Validate')]
    [switch]$ValidateAll,
    [Parameter(ParameterSetName = 'Scenario', Mandatory = $true)]
    [string]$Scenario,
    [Parameter(ParameterSetName = 'Scenario')]
    [string]$Inventory,
    [Parameter(ParameterSetName = 'Scenario')]
    [switch]$Execute,
    [Parameter(ParameterSetName = 'Scenario')]
    [ValidateSet('simulated')]
    [string]$Backend = 'simulated',
    [Parameter(ParameterSetName = 'Scenario')]
    [string[]]$AllowTarget,
    [Parameter(ParameterSetName = 'Scenario')]
    [string]$ConfirmLabId,
    [switch]$Json
)

$ErrorActionPreference = 'Stop'
$Runner = Join-Path $PSScriptRoot 'runner.py'
$Arguments = @($Runner)
if ($List) { $Arguments += '--list' }
elseif ($ValidateAll) { $Arguments += '--validate-all' }
else {
    $Arguments += @('--scenario', $Scenario)
    if ($Inventory) { $Arguments += @('--inventory', (Resolve-Path $Inventory).Path) }
    if ($Execute) {
        $Arguments += @('--execute', '--backend', $Backend)
        foreach ($Target in $AllowTarget) { $Arguments += @('--allow-target', $Target) }
        if ($ConfirmLabId) { $Arguments += @('--confirm-lab-id', $ConfirmLabId) }
    }
}
if ($Json) { $Arguments += '--json' }

if ($env:MESHLAKE_PYTHON) {
    if (-not (Test-Path -LiteralPath $env:MESHLAKE_PYTHON -PathType Leaf)) {
        throw 'MESHLAKE_PYTHON does not name an executable file'
    }
    & $env:MESHLAKE_PYTHON @Arguments
} elseif ($Py = Get-Command py -ErrorAction SilentlyContinue) {
    & $Py.Source -3 @Arguments
} elseif ($Python = Get-Command python -ErrorAction SilentlyContinue) {
    & $Python.Source @Arguments
} else {
    throw 'Python 3 is required; set MESHLAKE_PYTHON or install the Windows Python Launcher'
}
exit $LASTEXITCODE
