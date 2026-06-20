<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2024-2026 CodePros -->

# GAP-0020 — Zig 0.16 module-dedup bug + the canonical avoidance rule

## Symptom

Zig 0.16 errors at build time with:

```text
error: file 'src/policy.zig' exists in modules 'build_options' and 'build_options0'
```

(or `...exists in modules 'ffi' and 'fips'`) when the **same source file**
is reachable through **two different module roots**. The most common
trigger is materializing the `build_options` module **twice** (two
`b.addOptions()` instances, each `.createModule()`d) where both option
modules transitively reach a shared file (e.g. `policy.zig`, or the
package's own root). Zig assigns the second instance a synthesized name
(`build_options0`) and then refuses the duplicate file membership.

This bug previously forced `concurrency`'s otel seam to be hardcoded
`pub const enabled = false;` (see
`concurrency/src/observability.zig`), disabling the seam entirely.

## Reproduction (in this repo)

`zig build test -Drepro_dedup=true -Dopenssl_path=/usr/local/ssl`
creates TWO separate `b.addOptions()` instances, both `.createModule()`d,
and roots a test that reaches the SAME file graph through both — Zig then
emits the `file ... exists in modules` error. The default build
(`-Drepro_dedup=false`) never wires the bad shape, so the package builds
clean.

We also hit the *same class* of error during Task 8 when an interop test
imported BOTH the `fips` module (which roots `ffi.zig`) AND a separate
standalone `ffi` module (also rooting `ffi.zig`):
`file 'src/provider.zig' exists in modules 'ffi' and 'fips'`. The fix was
the same principle — reach `ffi.zig` through ONE root only
(`fips.ffi.c`).

## The canonical rule

> **Materialize exactly ONE `build_options` module** via
> `b.addOptions()` + `.createModule()` and pass that single
> `*std.Build.Module` to **every** compile unit (lib, tests, check,
> examples) and to the lazy `fips` dependency. **Never** call
> `.createModule()` on a second options instance reachable from the same
> file graph, and **never** root the same source file under two different
> module names.

This is captured as the copy-paste wiring in
`templates/build_fips_snippet.zig` and documented in
`docs/SEAM_CONTRACT.md` §3.

## Proof point

`concurrency`'s otel seam is **re-enabled** on top of this rule:
`concurrency/src/observability.zig` now reads
`pub const enabled: bool = @import("build_options").with_otel;` (the
GAP-0020 workaround removed), and `concurrency/build.zig` already
materializes a single `build_options_mod` (lines 35-37) threaded into the
module, both seam tests, the lib, and the check step. Both
`-Dwith_otel=false` (default) and `-Dwith_otel=true` build green with no
`file exists in modules` error — proving the single-instance wiring fixes
the bug.
