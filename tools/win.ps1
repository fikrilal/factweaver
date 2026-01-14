<#
Agent-only: invoked by `tools/agent/win` (bash) to run Windows commands from a WSL agent context.

Contract:
- Sets working directory to repo root (Windows path)
- Executes the provided command with arguments
- Exits with the child process exit code
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($args.Count -lt 1) {
  Write-Error 'Usage: win.ps1 <command> [args...]'
  exit 2
}

$repoRoot = Resolve-Path $PSScriptRoot
for ($i = 0; $i -lt 6; $i++) {
  $hasGit = Test-Path (Join-Path $repoRoot '.git') -PathType Any
  $hasMarkers = (Test-Path (Join-Path $repoRoot 'README.md') -PathType Leaf) -and (Test-Path (Join-Path $repoRoot '.gitignore') -PathType Leaf)
  if ($hasGit -or $hasMarkers) {
    break
  }

  $parent = Split-Path -Parent $repoRoot
  if (-not $parent -or $parent -eq $repoRoot) {
    break
  }
  $repoRoot = $parent
}
Set-Location $repoRoot

$command = $args[0]
$commandArgs = @()
if ($args.Count -gt 1) {
  $commandArgs = $args[1..($args.Count - 1)]
}

& $command @commandArgs
exit $LASTEXITCODE
