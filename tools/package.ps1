param([string]$Output = 'site-defense.zip')

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$source = Join-Path $root 'site-defense'
$destination = [IO.Path]::GetFullPath($Output)
$parent = [IO.Path]::GetDirectoryName($destination)
[IO.Directory]::CreateDirectory($parent) | Out-Null
$temporary = Join-Path $parent ('.site-defense-' + [Guid]::NewGuid().ToString('N') + '.zip')
try {
    Compress-Archive -LiteralPath $source -DestinationPath $temporary -CompressionLevel Optimal
    [IO.File]::Move($temporary, $destination, $true)
} finally {
    if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary }
}
Get-Item -LiteralPath $destination | Select-Object FullName, Length

