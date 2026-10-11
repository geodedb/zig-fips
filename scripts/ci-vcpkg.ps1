# SPDX-License-Identifier: Apache-2.0
. "$PSScriptRoot/ci-native.ps1"

function Initialize-CiVcpkgCheckout {
    param(
        [Parameter(Mandatory = $true)][string] $CheckoutPath,
        [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')][string] $Commit,
        [string] $RepositoryUrl = 'https://github.com/microsoft/vcpkg.git'
    )
    if (-not (Test-Path "$CheckoutPath/.git")) {
        New-Item -ItemType Directory -Path $CheckoutPath -Force | Out-Null
        Invoke-CiNative git @('init', $CheckoutPath)
        Invoke-CiNative git @('-C', $CheckoutPath, 'remote', 'add', 'origin', $RepositoryUrl)
        # Versioned ports refer to historical tree objects, not just HEAD's tree.
        Invoke-CiNative git @('-C', $CheckoutPath, 'fetch', '--no-tags', 'origin', $Commit)
        Invoke-CiNative git @('-C', $CheckoutPath, 'checkout', '--detach', $Commit)
    }
    $actualCommit = @(Invoke-CiNative git @('-C', $CheckoutPath, 'rev-parse', 'HEAD'))
    if ($actualCommit.Count -ne 1 -or $actualCommit[0] -ne $Commit) {
        throw 'Cached vcpkg checkout does not match the pinned commit'
    }
    $actualRemote = @(Invoke-CiNative git @('-C', $CheckoutPath, 'remote', 'get-url', 'origin'))
    if ($actualRemote.Count -ne 1 -or $actualRemote[0] -ne $RepositoryUrl) {
        throw 'Cached vcpkg origin does not match the expected repository'
    }
    $shallow = @(Invoke-CiNative git @('-C', $CheckoutPath, 'rev-parse', '--is-shallow-repository'))
    if ($shallow.Count -eq 1 -and $shallow[0] -eq 'true') {
        Invoke-CiNative git @('-C', $CheckoutPath, 'fetch', '--unshallow', '--no-tags', 'origin', $Commit)
        $shallow = @(Invoke-CiNative git @('-C', $CheckoutPath, 'rev-parse', '--is-shallow-repository'))
    }
    if ($shallow.Count -ne 1 -or $shallow[0] -ne 'false') {
        throw 'vcpkg requires complete history to resolve pinned port versions'
    }
}
