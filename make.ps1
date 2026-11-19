<#
    Точечная замена `make` для dev-машины Windows: `.\make.ps1 lint`, `.\make.ps1 test`,
    `.\make.ps1 revision -m "текст"`. Реальная логика — в scripts/dev.py, как и в Makefile,
    чтобы поведение на Windows, Linux и в CI не расходилось.
#>
param(
    [Parameter(Position = 0)]
    [string]$Command = 'help',
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Rest = @()
)

$ErrorActionPreference = 'Stop'
$py = if (Get-Command python -ErrorAction SilentlyContinue) { 'python' } else { 'py' }
$verbMap = @{
    'dev'            = 'dev'
    'lint'           = 'lint'
    'fmt'            = 'fmt'
    'typecheck'      = 'typecheck'
    'test'           = 'test'
    'test-live'      = 'test-live'
    'e2e'            = 'e2e'
    'migrate'        = 'migrate'
    'revision'       = 'revision'
    'seed-dev'       = 'seed-dev'
    'history-load'   = 'history-load'
    'backtest'       = 'backtest'
    'deploy-check'   = 'deploy-check'
    'backup'         = 'backup'
    'restore-verify' = 'restore-verify'
    'deploy'         = 'deploy'
    'ci-local'       = 'ci-local'
    'clean'          = 'clean'
    'help'           = '--list'
}
if (-not $verbMap.ContainsKey($Command)) {
    Write-Host "Неизвестная команда: $Command" -ForegroundColor Red
    & $py scripts/dev.py --list
    exit 2
}
& $py scripts/dev.py $verbMap[$Command] @Rest
exit $LASTEXITCODE
