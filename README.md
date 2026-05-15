# Tamp.Syft

> Wrapper for [anchore/syft](https://github.com/anchore/syft) — the leading OSS SBOM generator. Auto-detects 20+ package ecosystems (Rust, npm, .NET, Go, Java, Python, PHP, …) and emits CycloneDX (JSON/XML) or SPDX (JSON/tag-value) for directories, files, and container images.

| Package | Status |
|---|---|
| `Tamp.Syft` | 0.1.0 (initial) |

## Why this exists

Microsoft Store cert pressure, federal supply-chain hygiene requirements (SLSA, CycloneDX), and increasingly common "ship me an SBOM with your release" asks from enterprise buyers all converge on the same need: every release artifact should ship with a Software Bill of Materials.

The OSS ecosystem has converged on **syft** as the canonical generator — Apache 2.0, single Go binary, no online dependencies, handles polyglot repos (Rust + Node + .NET + container images all in one scan). It's the recommended tool from Anchore, Microsoft's [Secure Supply Chain Consumption Framework (S2C2F)](https://github.com/ossf/s2c2f) reference, and is what GitHub's own [`anchore/sbom-action`](https://github.com/anchore/sbom-action) uses under the hood.

`Tamp.Syft` makes SBOM generation a typed step in the Tamp build graph:

- `Syft.Scan(...)` for directories, files, or container images — multi-output supported (CycloneDX + SPDX from one invocation)
- `Syft.Convert(...)` for format conversion (Syft↔SPDX↔CycloneDX)
- `Syft.Attest(...)` for in-toto SBOM attestations uploaded to container registries (pairs with cosign for signing)
- `Syft.CatalogerList(...)` for inspecting which package ecosystems syft will detect

## Install

```bash
dotnet add package Tamp.Syft
```

Multi-targets net8 / net9 / net10. Requires `Tamp.Core` ≥ **1.6.0**.

## Tool installation

syft is a single Go binary:

- **macOS / Linux:** `brew install syft` (or [anchore's install script](https://github.com/anchore/syft/blob/main/install.sh))
- **Windows:** download release `.zip` from [github.com/anchore/syft/releases](https://github.com/anchore/syft/releases), put on PATH
- **GitHub Actions:** [`anchore/sbom-action`](https://github.com/anchore/sbom-action) installs + invokes syft in one step (this wrapper covers the same flag surface for cases where you want the SBOM step to live in your Tamp `Build.cs` rather than YAML)

Pin a specific version in CI — syft's verb shape has been stable, but pinning is the canonical move.

## Quick start — scan a polyglot repo for CycloneDX + SPDX SBOMs

```csharp
using Tamp;
using Tamp.Syft;

class Build : TampBuild
{
    public static int Main(string[] args) => Execute<Build>(args);

    [Parameter] readonly string Version = "1.0.6";

    [FromPath("syft")] readonly Tool SyftTool = null!;

    AbsolutePath Artifacts => RootDirectory / "artifacts";

    Target Sbom => _ => _
        .Description("[Compliance] Generate CycloneDX + SPDX SBOM for the repo")
        .Executes(() =>
        {
            Artifacts.CreateDirectory();
            return Syft.Scan(SyftTool, s => s
                .SetDirectorySource(RootDirectory)
                .SetSourceName("DasBook")
                .SetSourceVersion(Version)
                .SetSourceSupplier("Brewing Coder Software LLC")
                .AddOutputCycloneDxJson(Artifacts / $"DasBook-{Version}.cdx.json")
                .AddOutputSpdxJson(Artifacts / $"DasBook-{Version}.spdx.json")
                .AddExcludes("**/node_modules/**", "**/target/**", "**/bin/**", "**/obj/**", "**/.git/**")
                .SetQuiet());
        });
}
```

Run `dotnet tamp Sbom --version 1.0.6` and you get `DasBook-1.0.6.cdx.json` + `DasBook-1.0.6.spdx.json` in `artifacts/`. Attach to the GitHub release, ship to Partner Center compliance, or upload alongside the MSIX.

## What syft finds

Tested on the [`tamp-build/tamp`](https://github.com/tamp-build/tamp) repo (this project's own dogfood scan):

```
BOM format: CycloneDX v1.6 | components: 108 | tools: syft
ecosystems detected: 18 nuget, 8 github, 8 maven (+ test-tooling)
```

For a Tauri-based desktop project like DasBook, expect a similar mix — Rust crates (Cargo.lock), npm packages (package-lock.json), .NET dependencies (packages.lock.json), and embedded transitive build tooling.

## Verb surface

### `syft scan`

| Setter | Effect |
|---|---|
| `SetDirectorySource(path)` | `dir:<path>` — scan a directory tree |
| `SetFileSource(path)` | `file:<path>` — scan a single file (jar, msix, container archive) |
| `SetImageSource(image)` | bare image ref — uses Docker daemon, falls back to registry |
| `SetRegistrySource(image)` | `registry:<image>` — pull directly from registry, no daemon |
| `SetDockerArchiveSource(path)` / `SetOciArchiveSource(path)` | tar-on-disk variants |
| `AddOutputCycloneDxJson(file?)` | `-o cyclonedx-json[=file]` |
| `AddOutputCycloneDxXml(file?)` | `-o cyclonedx-xml[=file]` |
| `AddOutputSpdxJson(file?)` | `-o spdx-json[=file]` |
| `AddOutputSpdxTagValue(file?)` | `-o spdx-tag-value[=file]` |
| `AddOutputSyftJson(file?)` | `-o syft-json[=file]` — native format, lossless |
| `AddOutputGitHubJson(file?)` | `-o github-json[=file]` — for `dependency-graph` API submission |
| `AddOutputPurls(file?)` | `-o purls[=file]` — flat package-URL list |
| `AddOutput(spec)` | escape hatch for arbitrary `format=path` tokens |
| `AddExclude(glob)` | `--exclude` |
| `AddSelectCataloger(spec)` | `--select-catalogers +foo` / `-foo` |
| `SetScope("squashed"\|"all-layers"\|"deep-squashed")` | image-layer selection (validated) |
| `SetSourceName(name)` / `SetSourceVersion(v)` / `SetSourceSupplier(s)` | metadata stamping |
| `SetPlatform("linux/arm64")` | image platform |
| `SetParallelism(n)` | cataloger worker count (validated ≥1) |
| `AddEnrich("javascript"\|"python"\|...)` | online + local enrichment |
| `SetBasePath(path)` | symlink containment root |

### `syft convert`

| Setter | Effect |
|---|---|
| `SetSourceSbom(path)` / `ReadFromStdin()` | input SBOM (or `-` for stdin) |
| `AddOutputCycloneDxJson(...)` / `AddOutputSpdxJson(...)` / `AddOutput(...)` | output format(s) |
| `SetTemplatePath(path)` | for the `template=file.txt` output format |

### `syft attest`

| Setter | Effect |
|---|---|
| `SetImage(ref)` | container image to attest |
| `AddOutputCycloneDxJson(...)` / `AddOutputSpdxJson(...)` | predicate format |
| `SetKey(path)` | cosign-style signing key path |
| `SetKeyPassword(Secret)` | `Secret`-typed, routed via `COSIGN_PASSWORD` env var (cosign convention) — masked in `CommandPlan.Secrets`, never on the command line |

### Other

- `Syft.Version(tool)` — diagnostic
- `Syft.CatalogerList(tool)` — print available catalogers + config
- `Syft.Raw(tool, ...)` — escape hatch

## Secrets handling

`SyftAttestSettings.SetKeyPassword(Secret)` accepts a `Tamp.Core.Secret` and routes it via the `COSIGN_PASSWORD` environment variable — cosign's canonical password channel — not via command-line flag. Even with the env-var route the `Secret` is registered in `CommandPlan.Secrets` so Tamp's process trace masks it in printed output.

Built against Tamp.Core 1.6.0 — TAMP004 analyzer recognizes `SyftAttestSettings` as an approved Reveal context via the standard `*Settings` heuristic. No per-satellite `InternalsVisibleTo` entry required.

## Pairs with

- **[`Tamp.Cargo`](https://github.com/tamp-build/tamp-cargo)** + **[`Tamp.Tauri.V2`](https://github.com/tamp-build/tamp-tauri)** — Rust + Tauri toolchain whose dependency tree gets cataloged
- **[`Tamp.Msix`](https://github.com/tamp-build/tamp-msix)** — point `syft scan file:DasBook.msix` at a built MSIX to enumerate what's inside the package
- **[`Tamp.MicrosoftStoreCli`](https://github.com/tamp-build/tamp-msstore-cli)** — generate the SBOM at pack time, attach to the Partner Center submission
- **Tamp.GitHubAttest** (forthcoming, TAM-195) — the SLSA build-provenance side; SBOM (this package) is "what's inside", provenance is "how/where it was built"

## Releasing

Releases follow the [Tamp dogfood pattern](MAINTAINERS.md).

## Settings authoring style

Examples above use the fluent `Set*`-chain shape. Every wrapper verb also accepts a `new XxxSettings { ... }` object-init form — both produce identical `CommandPlan`s. The fluent shape stays canonical in docs and the `tamp init` template; opt into object-init scaffolding via `tamp init --settings-style=init`.

See [Build Script Authoring → Two authoring styles](https://github.com/tamp-build/tamp/wiki/Build-Script-Authoring#two-authoring-styles-for-wrapper-calls-120) on the wiki for the side-by-side comparison.

## License

MIT. See [LICENSE](LICENSE).
