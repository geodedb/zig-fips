# SPDX-License-Identifier: Apache-2.0
param([Parameter(Mandatory = $true)][string[]] $Steps)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/ci-native.ps1"
& "$PSScriptRoot/test_ci_native.ps1"
$vcpkgCommit = 'e456309491fd875487bf02b8a0dca76c1b1b00cc'
$vcpkgDir = Join-Path $PWD '.ci-tools/vcpkg'
if (-not (Test-Path "$vcpkgDir/.git")) {
    New-Item -ItemType Directory -Path $vcpkgDir -Force | Out-Null
    Invoke-CiNative git @('init', $vcpkgDir)
    Invoke-CiNative git @('-C', $vcpkgDir, 'remote', 'add', 'origin', 'https://github.com/microsoft/vcpkg.git')
    Invoke-CiNative git @('-C', $vcpkgDir, 'fetch', '--depth=1', 'origin', $vcpkgCommit)
    Invoke-CiNative git @('-C', $vcpkgDir, 'checkout', '--detach', $vcpkgCommit)
}
$actualCommit = @(Invoke-CiNative git @('-C', $vcpkgDir, 'rev-parse', 'HEAD'))
if ($actualCommit.Count -ne 1 -or $actualCommit[0] -ne $vcpkgCommit) {
    throw 'Cached vcpkg checkout does not match the pinned commit'
}
Invoke-CiNative "$vcpkgDir/bootstrap-vcpkg.bat" @('-disableMetrics')
$env:VCPKG_DEFAULT_BINARY_CACHE = Join-Path $PWD '.ci-tools/vcpkg-cache'
New-Item -ItemType Directory -Path $env:VCPKG_DEFAULT_BINARY_CACHE -Force | Out-Null
$installRoot = Join-Path $PWD '.ci-tools/vcpkg-installed'
Invoke-CiNative "$vcpkgDir/vcpkg.exe" @('install', '--triplet=x64-windows', '--host-triplet=x64-windows', "--x-manifest-root=$PWD/ci/windows", "--x-install-root=$installRoot", '--disable-metrics')
$prefix = Join-Path $installRoot 'x64-windows'
# Interop tests use OPENSSL_PREFIX/bin/openssl and OPENSSL_PREFIX/ssl.
# Normalize vcpkg's tools layout to that same prefix contract.
$env:OPENSSL_PREFIX = $prefix
$openssl = Join-Path $prefix 'bin/openssl.exe'
Copy-Item -LiteralPath (Join-Path $prefix 'tools/openssl/openssl.exe') -Destination $openssl -Force
$env:Path = "$prefix\bin;$env:Path"
$version = @(Invoke-CiNative $openssl @('version')) -join "`n"
if ($version -notmatch '^OpenSSL 3\.6\.5\s') { throw "Unexpected OpenSSL version: $version" }
$modules = @(Get-ChildItem -LiteralPath $prefix -Filter fips.dll -Recurse | Where-Object { $_.FullName -notmatch '\\debug\\' })
if ($modules.Count -ne 1) { throw 'Expected exactly one release FIPS provider DLL' }
$env:OPENSSL_MODULES = $modules[0].DirectoryName
$configDir = Join-Path $prefix 'ssl'
New-Item -ItemType Directory -Path $configDir -Force | Out-Null
$moduleConfig = Join-Path $configDir 'fipsmodule.cnf'
Invoke-CiNative $openssl @('fipsinstall', '-module', $modules[0].FullName, '-out', $moduleConfig)
$env:OPENSSL_CONF = Join-Path $configDir 'openssl.cnf'
$includePath = $moduleConfig.Replace('\', '/')
[System.IO.File]::WriteAllText($env:OPENSSL_CONF, @"
config_diagnostics = 1
openssl_conf = openssl_init
.include "$includePath"
[openssl_init]
providers = provider_sect
alg_section = algorithm_sect
[provider_sect]
fips = fips_sect
base = base_sect
[base_sect]
activate = 1
[algorithm_sect]
default_properties = fips=yes
"@)
$providers = @(Invoke-CiNative $openssl @('list', '-providers')) -join "`n"
Write-Host $providers
if ($providers -notmatch '(?ms)^  fips\r?\n(?:(?!^  \S).)*?^\s+status: active\s*$') {
    throw 'FIPS provider is not active'
}
foreach ($check in @(@('-kem-algorithms', 'ML-KEM-768'), @('-signature-algorithms', 'ML-DSA-65'), @('-signature-algorithms', 'SLH-DSA-SHA2-128s'))) {
    $algorithms = @(Invoke-CiNative $openssl @('list', $check[0])) -join "`n"
    if ($algorithms -notmatch [regex]::Escape($check[1])) { throw "Missing algorithm $($check[1])" }
}
Invoke-CiNative zig (@('build') + $Steps + @("-Dopenssl_path=$prefix", '--summary', 'all')) | Tee-Object -FilePath test-output.txt
