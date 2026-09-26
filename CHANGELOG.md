# Changelog

## Unreleased

### Fixed

- Resolve current-function analysis from interior addresses and detached basic blocks, and report
  addresses outside recovered functions instead of silently analyzing an empty function set.
- Detect loops in large control-flow graphs without exhausting Python's recursion limit.
- Preserve zero base, function, basic-block, and instruction addresses when reading r2 JSON.
- Stop emitting `offset` features for frame, RIP-relative, and absolute memory operands, and
  `number`/`offset` features for `add`/`sub` stack adjustments.
- Stop reporting `peb access` for segment offsets that merely begin with `0x30`/`0x60`.
- Read operand details from `aoj`, since radare2 6.2's `pdfj` omits `opex`; `number`, `offset`,
  operand, and `nzxor` features previously never fired on real binaries.
- Stop emitting `number` features for call and jump targets.
- Drop the empty-module `.name` API/import variant for ELF and Mach-O imports.

### Added

- Initial radare2-backed capa static feature extractor.
- Native `r2capa` core command wrapper and r2pipe worker.
- ResultDocument JSON, verbose rendering, current-function filtering, feature export, and r2 flags.
- Regression, formatting, typing, packaging, and native-plugin CI.
- Animated terminal demo, contribution guidance, and private vulnerability reporting policy.
