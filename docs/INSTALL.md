# Installing ReconForge and its tools

```bash
./install.sh            # app + tools + PATH (macOS, Ubuntu/Debian, Kali)
```

| Step | macOS | Ubuntu / Debian / Kali |
|---|---|---|
| Base packages | Homebrew: python@3.12, node, libpcap (Homebrew itself must already be installed) | apt: python3, venv, pip, git, curl, unzip, build-essential, libpcap-dev, nodejs, npm (uses `sudo`) |
| Go ≥ 1.22 | `brew install go` | latest official tarball into `~/.local/go` |
| ProjectDiscovery tools, tomnomnom tools, gau, puredns, github-subdomains | `go install` into `~/go/bin` | same |
| amass, gitleaks, trufflehog | Homebrew | apt (amass) or `go install` |
| nmap, sslscan, massdns | Homebrew | apt; massdns is built from source if no package exists |
| findomain | Homebrew | official release binary |
| whatweb | built from the official repository with Homebrew Ruby (it is not in Homebrew) | apt |
| waymore | pip into the app's `.venv` | same |
| retire | npm into `~/.local/share/reconforge/npm` | same |
| Chrome/Chromium | reuse Google Chrome; otherwise `brew install --cask chromium` | apt chromium |

How it works:
- **Reuse first.** Before installing anything, the installer looks for a working binary on PATH and
  in `~/go/bin`, `~/.local/bin`, Homebrew, `/usr/local/bin`, `/usr/bin` and `/snap/bin`. Binaries
  whose version banner does not match the expected program are ignored. For example, the Python
  `httpx` HTTP client is skipped in favour of ProjectDiscovery httpx.
- **Recorded paths.** `reconforge tools --detect` writes `~/.reconforge/tool-paths.yaml`
  (`RECONFORGE_HOME` overrides the location). On startup, ReconForge uses these absolute paths unless
  your config sets an explicit `tools.<name>.path`. It also appends the tool directories to `PATH`
  for child processes (for example, shuffledns calling massdns).
- **Shell PATH.** A block between `# >>> reconforge >>>` and `# <<< reconforge <<<` is added to
  `~/.zshrc` / `~/.bashrc`. Delete that block to undo it.
- **Failures don't stop the install.** If one tool fails to install, the rest still continue and the
  summary lists the failure with a log path. ReconForge's built-in engines cover DNS, HTTP, TLS,
  ports, crawling and fingerprinting without any external tool.
- **Nuclei templates are only downloaded.** The template update fetches templates, but only those
  listed in `nuclei.reviewed_templates` are ever executed.

Windows is not supported yet.
