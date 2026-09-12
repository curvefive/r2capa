# Changelog

## Unreleased

### Fixed

- Resolve current-function analysis from interior addresses and detached basic blocks, and report
  addresses outside recovered functions instead of silently analyzing an empty function set.
- Detect loops in large control-flow graphs without exhausting Python's recursion limit.
- Preserve zero base, function, basic-block, and instruction addresses when reading r2 JSON.

### Added

- Initial radare2-backed capa static feature extractor.
- Native `r2capa` core command wrapper and r2pipe worker.
- ResultDocument JSON, verbose rendering, current-function filtering, feature export, and r2 flags.
- Regression, formatting, typing, packaging, and native-plugin CI.
- Animated terminal demo, contribution guidance, and private vulnerability reporting policy.
