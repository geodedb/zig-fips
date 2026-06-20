// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
//
// ANTI-PATTERN (do NOT copy). Reference for GAP-0020. This is the shape
// that triggers `error: file '...' exists in modules 'build_options' and
// 'build_options0'` in Zig 0.16.
//
//   // BAD: two separate options instances, both createModule()'d, both
//   // reachable from the same file graph.
//   const opts_a = b.addOptions();
//   opts_a.addOption(bool, "fips", fips);
//   const mod_a = opts_a.createModule();       // build_options
//
//   const opts_b = b.addOptions();             // <-- SECOND INSTANCE
//   opts_b.addOption(bool, "fips", fips);
//   const mod_b = opts_b.createModule();       // build_options0  (BAD)
//
//   unit_a.root_module.addImport("build_options", mod_a);
//   unit_b.root_module.addImport("build_options", mod_b); // same file graph
//
// CORRECT: one instance, threaded everywhere. See build_fips_snippet.zig.
