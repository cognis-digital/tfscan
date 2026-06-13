<a name="top"></a>
<div align="center">

<img src="https://capsule-render.vercel.app/api?type=rect&color=0:6b46c1,100:2b6cb0&height=120&section=header&text=TFSCAN&fontSize=48&fontColor=ffffff&fontAlignY=58" width="100%" alt="TFSCAN"/>

# TFSCAN

### Scan Terraform plans/configs for misconfigurations

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=18&duration=3500&pause=1000&color=6B46C1&center=true&vCenter=true&width=720&lines=Scan+Terraform+plansconfigs+for+misconfigurations;Self-hostable+%C2%B7+MCP-native+%C2%B7+CI-ready+%C2%B7+polyglot" width="720"/>

[![PyPI](https://img.shields.io/pypi/v/cognis-tfscan.svg?color=6b46c1)](https://pypi.org/project/cognis-tfscan/) [![CI](https://github.com/cognis-digital/tfscan/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/tfscan/actions) [![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE) [![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital)

*Part of the Cognis Neural Suite.*

</div>

```bash
pip install cognis-tfscan
tfscan scan .            # → prioritized findings in seconds
```

## Usage — step by step

1. **Install** the CLI (console script `tfscan`):
   ```bash
   pip install cognis-tfscan
   ```
2. **Scan Terraform** — `scan` walks a file or directory of `.tf` / `.tf.json` / plan files for misconfigurations:
   ```bash
   tfscan scan ./infra
   ```
3. **Filter by severity / change format** — restrict noise and emit JSON or a shareable HTML report:
   ```bash
   tfscan scan ./infra --min-severity HIGH
   tfscan scan ./infra --format html -o report.html
   ```
4. **Read the output** — each finding carries `severity`, `check_id`, the `resource`, `file:line`, and a `remediation`. Exit codes: `0` clean, `1` findings present, `2` scan error:
   ```bash
   tfscan scan ./infra --format json | jq '.findings[] | {check_id, severity, resource_name}'
   ```
5. **Automate in CI** — block merges that introduce HIGH/CRITICAL misconfigs:
   ```yaml
   - run: pip install cognis-tfscan
   - run: tfscan scan ./infra --min-severity HIGH  # nonzero exit fails the job
   ```

## Contents

- [Why tfscan?](#why) · [Features](#features) · [Quick start](#quick-start) · [Example](#example) · [Architecture](#architecture) · [AI stack](#ai-stack) · [How it compares](#how-it-compares) · [Integrations](#integrations) · [Install anywhere](#install-anywhere) · [Related](#related) · [Contributing](#contributing)

<a name="why"></a>
## Why tfscan?

Scan Terraform plans/configs for misconfigurations — without standing up heavyweight infrastructure.

`tfscan` is single-purpose, scriptable, and self-hostable: point it at a target, get prioritized results in the format your workflow already speaks (table · JSON · SARIF), gate CI on it, and let agents drive it over MCP.

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="features"></a>
## Features

- ✅ Parse Hcl
- ✅ Parse Plan Json
- ✅ Load Checks
- ✅ Scan Text
- ✅ Scan Path
- ✅ Runs on Linux/macOS/Windows · Docker · devcontainer
- ✅ Ports in Python, JavaScript, Go, and Rust (`ports/`)

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="quick-start"></a>
## Quick start

```bash
pip install cognis-tfscan
tfscan --version
tfscan scan .                       # scan current project
tfscan scan . --format json         # machine-readable
tfscan scan . --fail-on high        # CI gate (non-zero exit)
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="example"></a>
## Example

```text
$ tfscan scan .
  [HIGH    ] TFS-001  example finding             (./src/app.py)
  [MEDIUM  ] TFS-002  another signal              (./config.yaml)

  2 findings · risk score 5 · 38ms
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="architecture"></a>
## Architecture

```mermaid
flowchart LR
  IN[target / manifest] --> P[tfscan<br/>checks + rules]
  P --> OUT[findings (JSON / SARIF)]
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="ai-stack"></a>
## Use it from any AI stack

`tfscan` is interoperable with every popular way of using AI:

- **MCP server** — `tfscan mcp` (Claude Desktop, Cursor, Cognis.Studio, [uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet))
- **OpenAI-compatible / JSON** — pipe `tfscan scan . --format json` into any agent or LLM
- **LangChain · CrewAI · AutoGen · LlamaIndex** — wrap the CLI/JSON as a tool in one line
- **CI / scripts** — exit codes + SARIF for non-AI pipelines

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="how-it-compares"></a>
## How it compares

| | **Cognis tfscan** | typical tools |
|---|:---:|:---:|
| Self-hostable, no account | ✅ | varies |
| Single command, zero config | ✅ | ⚠️ |
| JSON + SARIF for CI | ✅ | varies |
| MCP-native (AI agents) | ✅ | ❌ |
| Polyglot ports (JS/Go/Rust) | ✅ | ❌ |
| Open license | ✅ COCL | varies |
<div align="right"><a href="#top">↑ back to top</a></div>

<a name="integrations"></a>
## Integrations

Pipes into your stack: **SARIF** for code-scanning, **JSON** for anything, an **MCP server** (`tfscan mcp`) for AI agents, and a webhook forwarder for SIEM/Slack/Jira. See [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md).

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="install-anywhere"></a>
## Install — every way, every platform

```bash
pip install "git+https://github.com/cognis-digital/tfscan.git"    # pip (works today)
pipx install "git+https://github.com/cognis-digital/tfscan.git"   # isolated CLI
uv tool install "git+https://github.com/cognis-digital/tfscan.git" # uv
pip install cognis-tfscan                                          # PyPI (when published)
docker run --rm ghcr.io/cognis-digital/tfscan:latest --help        # Docker
brew install cognis-digital/tap/tfscan                             # Homebrew tap
curl -fsSL https://raw.githubusercontent.com/cognis-digital/tfscan/main/install.sh | sh
```

| Linux | macOS | Windows | Docker | Cloud |
|---|---|---|---|---|
| `scripts/setup-linux.sh` | `scripts/setup-macos.sh` | `scripts/setup-windows.ps1` | `docker run ghcr.io/cognis-digital/tfscan` | [DEPLOY.md](docs/DEPLOY.md) (AWS/Azure/GCP/k8s) |

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="related"></a>
## Related Cognis tools


**Explore the suite →** [🗂️ all 170+ tools](https://github.com/cognis-digital/cognis-neural-suite) · [⭐ awesome-cognis](https://github.com/cognis-digital/awesome-cognis) · [🔗 cognis-sources](https://github.com/cognis-digital/cognis-sources) · [🤖 uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet) · [🧠 engram](https://github.com/cognis-digital/engram)

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="contributing"></a>
## Contributing

PRs, new rules, and demo scenarios are welcome under the collaboration-pull model — see [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

> ### ⭐ If `tfscan` saved you time, **star it** — it genuinely helps others find it.

## Interoperability

`{}` composes with the 300+ tool Cognis suite — JSON in/out and a shared
OpenAI-compatible `/v1` backbone. See **[INTEROP.md](INTEROP.md)** for the
suite map, composition patterns, and reference stacks.

## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** — free for personal, internal-evaluation, research, and educational use; **commercial / production use requires a license** (licensing@cognis.digital). See [LICENSE](LICENSE).

---

<div align="center"><sub><b><a href="https://cognis.digital">Cognis Digital</a></b> · one of 170+ tools in the <a href="https://github.com/cognis-digital/cognis-neural-suite">Cognis Neural Suite</a> · <i>Making Tomorrow Better Today</i></sub></div>
