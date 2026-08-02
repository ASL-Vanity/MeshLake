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
    [switch]$Json
)

$ErrorActionPreference = 'Stop'
$Runner = Join-Path $PSScriptRoot 'runner.py'
$Python = Get-Command python -ErrorAction SilentlyContinue
$Arguments = @($Runner)
if ($List) { $Arguments += '--list' }
elseif ($ValidateAll) { $Arguments += '--validate-all' }
else {
    $Arguments += @('--scenario', $Scenario)
    if ($Inventory) { $Arguments += @('--inventory', (Resolve-Path $Inventory).Path) }
}
if ($Json) { $Arguments += '--json' }

if ($Python) {
    & $Python.Source @Arguments
} else {
    $Py = Get-Command py -ErrorAction Stop
    & $Py.Source -3 @Arguments
}
exit $LASTEXITCODE
