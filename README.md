# Zypheron

A local-first security CLI for **authorized** work: recon, scanning, and AI-assisted operator workflows.

Go CLI plus an optional Python AI runtime. Sessions and loot live under `~/.zypheron`. This repo is the open-source CLI (`v2.0.0`), not a hosted SaaS product.

> Authorized testing and research only. You need explicit permission (or you own the systems). See [SECURITY.md](SECURITY.md) and [LICENSE](LICENSE).

---

<table>
<tr>
<td width="33%" valign="top">

**Status**

v2.0.0 · OSS release candidate

Local / self-hosted path. Not enterprise SaaS.

</td>
<td width="33%" valign="top">

**Prefer**

`bash scripts/install/setup-hybrid.sh`

`zypheron doctor` before first scan

TUI: `zypheron` or `zypheron tui`

</td>
<td width="33%" valign="top">

**Do not claim**

Public apt/brew/AUR feeds are live

`dork` / `autopent` / `update` commands

Ungated autonomous exploitation

</td>
</tr>
</table>

---

## Pieces

<table>
<tr>
<td width="50%" valign="top">

**CLI** (`zypheron-go/`)

Go 1.24+. Cobra commands, TUI, tool orchestration. Binary installs to `~/.local/bin/zypheron`.

</td>
<td width="50%" valign="top">

**AI runtime** (`zypheron-ai/`)

Python 3.9+. Chat, scan analysis, recon planning. Providers: Claude, OpenAI, Gemini, DeepSeek, Grok, Kimi, Ollama.

</td>
</tr>
<tr>
<td width="50%" valign="top">

**Optional API** (`zypheron-api/`)

FastAPI service for the local/self-hosted path. Teams endpoints may still return `501`.

</td>
<td width="50%" valign="top">

**On disk**

`~/.zypheron` — config, history, logs, cache, memory. External scanners (nmap, nuclei, …) are called if present.

</td>
</tr>
</table>

---

## How to use

<table>
<tr>
<td width="50%" valign="top">

**1 · Install**

```bash
git clone https://github.com/KKingZero/Zypheron-CLI.git
cd Zypheron-CLI
bash scripts/install/setup-hybrid.sh
```

Builds the CLI, Python deps, and shell completion. Skip extra scanners with `ZYPHERON_INSTALL_TOOLS=none`.

</td>
<td width="50%" valign="top">

**2 · Check the box**

```bash
export PATH="$HOME/.local/bin:$PATH"
zypheron --version          # 2.0.0
zypheron doctor
zypheron tools check
```

If `zypheron` is missing, add `~/.local/bin` to `PATH`.

</td>
</tr>
<tr>
<td width="50%" valign="top">

**3 · First-time setup**

```bash
zypheron setup
zypheron config set-key anthropic   # or openai / grok / …
zypheron ai status
```

Hosted models need a key. Local path: Ollama running, then pick it in the TUI.

</td>
<td width="50%" valign="top">

**4 · Daily loop**

```bash
zypheron                        # TUI
zypheron scan scanme.nmap.org
zypheron recon example.com
zypheron chat "How would you approach this target?"
```

`scan` wraps nmap / masscan / nikto / nuclei. `recon` can plan with AI (`--no-ai` to skip).

</td>
</tr>
<tr>
<td width="50%" valign="top">

**5 · Heavier work**

```bash
zypheron ad --target 10.10.10.1 --domain corp.local --mode enum
zypheron cloud --provider aws --target <account>
zypheron exploit --c2 sliver --guided
zypheron workflow list
```

AD and exploit steps ask for operator approval. `exploit --safe-mode` is on by default.

</td>
<td width="50%" valign="top">

**6 · Tools and C2 (opt-in)**

```bash
sudo bash scripts/install/install-tools.sh    # Debian/Kali
# install-tools-arch.sh · install-tools-rpm.sh
sudo bash scripts/install/install-c2.sh       # Sliver / Empire, interactive
```

Havoc is not installed by the script. Empire needs `EMPIRE_HOST` / `EMPIRE_USER` / `EMPIRE_PASS`.

</td>
</tr>
</table>

Other installs: release binary (`curl -sSfL https://download.zypheron.net/install.sh | bash`) and `.deb` / `.rpm` from tagged releases. Public apt / Homebrew / AUR / DNF repos are **not** published yet. Details: [docs/INSTALL.md](docs/INSTALL.md).

---

## What the CLI actually has

From `zypheron --help` (v2.0.0):

<table>
<tr>
<td width="50%" valign="top">

**Everyday**

`scan` `recon` `osint` `fuzz` `chat` `ai` `doctor` `tools` `setup` `config` `tui`

</td>
<td width="50%" valign="top">

**Operator**

`ad` `cloud` `exploit` `bruteforce` `bounty` `mitre` `workflow` `session` `report` `findings` `approvals`

</td>
</tr>
<tr>
<td width="50%" valign="top">

**Environment**

`kali` `plugin` `cluster` `scheduler` `scope` `status` `login` / `logout` (desktop pairing) `install-deps`

</td>
<td width="50%" valign="top">

**Not in this build**

`dork`, `autopent`, `update` — older docs mentioned them; they are not commands today.

</td>
</tr>
</table>

```bash
zypheron scan example.com
zypheron scan https://example.com --web
zypheron recon example.com --no-ai
zypheron chat --interactive
zypheron tools install-all --critical-only --yes
```

Run `zypheron <command> --help` for flags. Many flows need the matching local tool (`nmap`, `nuclei`, BloodHound, Prowler, …).

---

## Honest gaps

| Area | Today |
| --- | --- |
| Package repos | Artifacts exist on tags; apt/brew/AUR/DNF feeds are not live |
| Chat | Non-streaming path. Streaming protocol is deferred |
| Autopent | Not a top-level command. Exploitation stays approval-gated |
| Teams API | Some enterprise endpoints return `501` |
| Hosted product | Billing / dashboard polish is out of OSS RC scope |
| C2 | Sliver / Empire via `install-c2.sh` + `exploit --guided`. Havoc is manual |

---

## Requirements

- Go **1.24+** (source builds)
- Python **3.9+** (AI engine)
- Linux, macOS, or WSL — Kali-class box recommended for AD / exploit / C2

---

## Docs

| | |
| --- | --- |
| First run | [docs/QUICKSTART.md](docs/QUICKSTART.md) · [docs/SETUP_AND_USE.md](docs/SETUP_AND_USE.md) |
| Install | [docs/INSTALL.md](docs/INSTALL.md) |
| Commands / AI | [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md) · [docs/AI_GUIDE.md](docs/AI_GUIDE.md) |
| Build / test | [docs/BUILD_AND_TEST.md](docs/BUILD_AND_TEST.md) · `./scripts/run_all_tests.sh --ci` |
| Changelog | [docs/CHANGELOG.md](docs/CHANGELOG.md) |

---

[MIT](LICENSE)
