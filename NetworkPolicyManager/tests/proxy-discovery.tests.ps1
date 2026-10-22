[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$manager = Get-ChildItem (Split-Path -Parent $PSScriptRoot) -File -Filter '*.ps1' |
    Sort-Object Length -Descending | Select-Object -First 1
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($manager.FullName, [ref]$tokens, [ref]$errors)
if (@($errors).Count -gt 0) { throw 'Manager syntax check failed.' }
$definition = @($ast.FindAll({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-ProxyTokens'
}, $true))
if ($definition.Count -ne 1) { throw 'Expected exactly one Get-ProxyTokens function.' }
. ([scriptblock]::Create($definition[0].Extent.Text))

# Read-only in-memory registry fixture; do not execute the manager startup.
function Get-ItemProperty { param($LiteralPath) $script:Settings }
$script:Settings = [pscustomobject]@{}
if (@(Get-ProxyTokens).Count -ne 0) { throw 'Missing ProxyOverride must mean no bypass tokens.' }
$script:Settings = [pscustomobject]@{ ProxyOverride = '' }
if (@(Get-ProxyTokens).Count -ne 0) { throw 'Empty ProxyOverride must mean no bypass tokens.' }
$script:Settings = [pscustomobject]@{ ProxyOverride = '127.0.0.1;192.0.2.1;;' }
$actual = @(Get-ProxyTokens)
if ($actual.Count -ne 2 -or $actual[0] -ne '127.0.0.1' -or $actual[1] -ne '192.0.2.1') {
    throw 'Configured bypass tokens must be preserved.'
}
'PROXY_DISCOVERY_TESTS_OK cases=3 registry_writes=0'
