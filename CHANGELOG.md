# Changelog

All notable changes to **Tamp.Syft** are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [SemVer](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.2] — 2026-09-27

### Fixed

- **Absolute directory sources now scan correctly under Windows junctions/symlinks** ([#5](https://github.com/tamp-build/tamp-syft/issues/5)). syft 1.x's directory resolver fails on an absolute path whose root traverses a reparse point (e.g. a repo mapped under `C:\repos`) — `could not evaluate root … symlinks: The system cannot find the path specified` — producing a **0-byte SBOM + exit 1**. `syft scan` now emits a `dir:` source with an absolute path **relative to the working directory**, which syft resolves fine. Only rewrites relativizable `dir:` sources; relative sources, other-drive paths, other schemes, and image refs are untouched. A relative source (`dir:.`) always worked and is unchanged.

### Changed

- **Documented that `Quiet` (`-q`) also hides syft's failure diagnostics.** syft has no errors-only log level, so a failed scan under `SetQuiet(true)` exits non-zero with no message (just a 0-byte SBOM). The XML doc now says so and points at running without `Quiet` (Tamp's per-target capture then surfaces syft's stderr on non-zero exit).

## [0.1.1] — 2026-09-27

### Added

- Package now ships XML documentation files (`.xml`) alongside the assembly, so consumers get IntelliSense and API docs. (Mirrors [tamp-build/tamp#3](https://github.com/tamp-build/tamp/pull/50).)


## [0.1.0] - 2026-05-13

### Added

- Initial release. Wraps [anchore/syft](https://github.com/anchore/syft) v1.44.0
  — the leading OSS SBOM generator. Filed under TAM-194. Addresses DasBook
  wishlist #6 (build attestation / SBOM) for the "what's inside the artifact"
  side. Pairs with the forthcoming Tamp.GitHubAttest (TAM-195) for the SLSA
  build-provenance side.

#### Primary verb

- **`Syft.Scan(...)`** — `syft scan [SOURCE]`. Generate an SBOM for:
  - Directories (`SetDirectorySource(path)` → `dir:<path>`)
  - Files including built artifacts like MSIX (`SetFileSource(path)` → `file:<path>`)
  - Container images via Docker daemon (`SetImageSource(ref)`) or directly from
    a registry (`SetRegistrySource(ref)` → `registry:<ref>`)
  - Docker / OCI archive tarballs on disk
- Multi-output supported in one invocation — `AddOutputCycloneDxJson(file)` +
  `AddOutputSpdxJson(file)` + `AddOutputSyftJson(file)` + `AddOutputPurls(file)`
  emit all four formats from a single scan.
- Source metadata stamping: `SetSourceName`, `SetSourceVersion`,
  `SetSourceSupplier` — what gets written into the SBOM's top-level
  identification fields.
- Cataloger control: `AddSelectCataloger("+cargo")`, `-npm`, etc.
  `AddOverrideDefaultCataloger(...)` to replace the default set entirely.
- Layer scope for image scans: `SetScope("squashed" | "all-layers" |
  "deep-squashed")` — validated at `ToCommandPlan` time.
- Glob exclusions (`AddExclude("**/node_modules/**")`), platform override for
  image scans (`SetPlatform("linux/arm64")`), parallelism (`SetParallelism(n)` —
  validated ≥1), enrichment (`AddEnrich("javascript")`), base-path symlink
  containment.

#### Format conversion

- **`Syft.Convert(...)`** — `syft convert [SOURCE-SBOM] -o [FORMAT]`. Convert
  between syft-json, CycloneDX (JSON/XML), and SPDX (JSON/tag-value). Source
  via `SetSourceSbom(path)` or `ReadFromStdin()` (passes `-`). Template-format
  conversion supported via `SetTemplatePath(path)`.

#### Attestation

- **`Syft.Attest(...)`** — `syft attest [IMAGE]`. Generate an in-toto SBOM
  attestation for a container image and upload alongside the image in the
  registry. `SetKey(path)` for the cosign signing key.
  **`SetKeyPassword(Secret)`** accepts a `Tamp.Core.Secret` and routes it via
  the `COSIGN_PASSWORD` environment variable (cosign's canonical password
  channel), NOT via command-line flag — value never appears in the arg list,
  and is masked in `CommandPlan.Secrets`.

#### Diagnostic / escape hatch

- `Syft.Version(...)` — version stamp.
- `Syft.CatalogerList(...)` — print available catalogers + their config (useful
  during onboarding to see which ecosystems syft will detect in a given repo
  shape).
- `Syft.Raw(...)` — escape hatch for verbs not yet typed.

#### Shared knobs

- Verbosity: `SetVerbosity(1)` → `-v`, `SetVerbosity(2)` → `-vv`. Range
  validated 0-2.
- Quiet mode: `SetQuiet()` → `-q`.
- Config files: `AddConfigFile(path)` → `-c <path>`. Profiles:
  `AddProfile(name)` → `--profile <name>`.

### Validation

- `Scan` requires a source (`SetDirectorySource` / `SetFileSource` /
  `SetImageSource` / `SetRegistrySource` / `SetSource`).
- `Convert` requires both a source SBOM and at least one output format.
- `Attest` requires both an image reference and at least one output format.
- `Scope` validated against {squashed, all-layers, deep-squashed}.
- `Parallelism` validated ≥1.
- `Verbosity` validated in [0, 2].

### Tests

- 40 unit tests covering positive verb-shape paths plus negative cases
  (missing required args, invalid scope, out-of-range parallelism, out-of-range
  verbosity, password-never-on-command-line for attest, multi-output emission,
  all 7 output-format helpers, all 4 source-scheme helpers).

### Requires

- **Tamp.Core ≥ 1.6.0** (public `Secret.Reveal()` + TAMP004 analyzer; no
  per-satellite IVT needed).

### Notes

- Sixth non-.NET-ish satellite, second under the post-1.6.0 regime. No
  `Tamp.Core/AssemblyInfo.cs` change required — TAMP004 recognizes the
  `*Settings` class shape as approved for `Secret.Reveal()`.

- Dogfood-validated: scanned the `tamp-build/tamp` repo with syft 1.44.0 and
  produced a clean CycloneDX 1.6 SBOM with 108 components across nuget (18),
  github (8), maven (8), and test-tooling ecosystems before shipping the
  wrapper. The wrapper's command-line construction was sanity-checked against
  the same shape of invocation.
