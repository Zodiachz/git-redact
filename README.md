# git-redact

**Commit your files with the secrets stripped out. Get them back on checkout.**

`git-redact` is a git filter. When you `git add` a file, every secret in it (API keys, bot tokens, database passwords, private keys…) is replaced by a placeholder in what git stores. The file on your disk does not change. The real values go to a small vault outside the repository, so a checkout on your machine puts them back, and a clone anywhere else only ever sees `REDACTED-3f9a1c0b7d2e`.

```js
// what you edit and run                          // what gets committed and pushed
const bot = new Client({                          const bot = new Client({
  token: "MTE5ODk…real…token",                      token: "REDACTED-3f9a1c0b7d2e",
});                                               });
const db = "postgres://app:Hunter2x9@db/app";     const db = "postgres://app:REDACTED-81c4e02a9f6b@db/app";
```

![python](https://img.shields.io/badge/python-3.8%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![dependencies](https://img.shields.io/badge/dependencies-0-brightgreen?style=flat-square)
![platforms](https://img.shields.io/badge/linux%20%7C%20macOS%20%7C%20windows-grey?style=flat-square)
![license](https://img.shields.io/badge/license-MIT-blue?style=flat-square)

## Why

Secrets end up hardcoded: a quick bot, a legacy script, a config that was never meant to leave the server. The usual answers are to block the commit ([gitleaks](https://github.com/gitleaks/gitleaks), [git-secrets](https://github.com/awslabs/git-secrets)) or to encrypt the whole file ([git-crypt](https://github.com/AGWA/git-crypt), [SOPS](https://github.com/getsops/sops)). Sometimes you just want to **version the code as it is**, readable and diffable on GitHub, without the secret in it and without refactoring first.

| | blocks the commit | file readable in the repo | secret restored on checkout |
|---|:-:|:-:|:-:|
| gitleaks, git-secrets | ✅ | ✅ | — |
| git-crypt, SOPS | — | ❌ encrypted | ✅ with the key |
| **git-redact** | optional (`check`) | ✅ | ✅ from your vault |

## Install

One file, Python 3.8+ standard library only.

```bash
curl -fsSL https://raw.githubusercontent.com/Zodiachz/git-redact/main/git-redact -o ~/.local/bin/git-redact
chmod +x ~/.local/bin/git-redact        # any folder on your PATH; `git redact …` then works
```

On Windows, put it anywhere and call `python path\to\git-redact init` once. The filter is registered with absolute paths, so git finds it afterwards.

## Quick start

```bash
cd my-repo
git redact init                    # filter every text file (or: git redact init '*.js' '*.py' config/*)
git redact diff                    # preview: file:line, rule, first characters of each secret
git add --renormalize . && git add .gitattributes
git commit -m "Redact secrets"
git redact hook                    # optional: refuse commits that still contain a secret
```

`init` writes `* filter=redact` to `.gitattributes` and registers the filter in `.git/config`. Binary files and files over 20 MB go through untouched.

> **Already committed secrets stay in your history.** git-redact protects what you commit from now on. Rotate anything that was pushed before, or rewrite history with [git filter-repo](https://github.com/newren/git-filter-repo).

## What it detects

`git redact rules` lists them. Built in:

| Rule | Example |
|---|---|
| `private-key` | body of `-----BEGIN … PRIVATE KEY-----` blocks |
| `github-token` `gitlab-token` | `ghp_…`, `github_pat_…`, `glpat-…` |
| `discord-bot-token` `discord-webhook` | bot tokens, `discord.com/api/webhooks/<id>/<token>` |
| `slack-token` `slack-webhook` | `xoxb-…`, `hooks.slack.com/services/…` |
| `telegram-bot-token` | `123456789:AA…` |
| `aws-access-key-id` `aws-secret-key` | `AKIA…`, `aws_secret_access_key = …` |
| `google-api-key` `stripe-key` `openai-key` `anthropic-key` `sendgrid-key` `npm-token` `pypi-token` | provider key formats |
| `jwt` | `eyJ….eyJ….…` |
| `url-password` | `postgres://user:PASSWORD@host`, `redis://:PASSWORD@host` |
| `secret-assignment` | `API_KEY = "…"`, `"password": "…"`, `const secretHex = '…'` |
| `secret-line` | `DB_PASSWORD=…`, `token: …` (unquoted, whole line) |

The two generic rules skip what is obviously not a secret: `process.env.X`, `${VAR}`, `{{ template }}`, `config.apiKey`, `changeme`, `your-key-here`, version numbers, `0x` addresses, single-case words, plain endpoints like `https://api.example.com/token`.

## Configuration

### Your own `.env` values

```bash
git config --add redact.envFile .env            # repeatable, relative to the repo root
```

Every value of a secret-looking key (`*_TOKEN`, `*_SECRET`, `*PASSWORD*`, `*_KEY`, `DATABASE_URL`, …) or any long random value in that file is redacted wherever it appears in committed files, even inside a string no rule would recognise. `NODE_ENV=production` or `PORT=3000` are left alone.

### A list of literal secrets

```bash
git config redact.secretsFile ~/.config/git-redact/extra-secrets.txt   # one value per line, keep it outside the repo
```

### `.gitredact` in the repository

```text
# custom rule: name + Python regex (group "s" = the part to redact, else the whole match)
rule internal-key  \bINT-(?P<s>[A-Z0-9]{24})\b
# never redact this value (a public test key, a false positive)
allow pk_test_51H8example
# turn a built-in rule off
disable jwt
```

### Other settings

| git config | Default | |
|---|---|---|
| `redact.vault` | `~/.config/git-redact` | vault folder; `off` = no vault, bare `REDACTED` placeholders |
| `redact.disable` | | rule name to turn off (repeatable) |
| `redact.maxBytes` | `20971520` | larger files are not filtered |

The environment variable `GIT_REDACT_VAULT` overrides `redact.vault` (`off` works too).

## Commands

| Command | |
|---|---|
| `git redact init [patterns…] [--no-vault]` | register the filter, add patterns to `.gitattributes` (default `*`) |
| `git redact diff [paths…]` | secrets in the working tree, and whether each file is covered by the filter |
| `git redact check` | scan the staged files; exit 1 on any secret. Use it in a pre-commit hook |
| `git redact check --rev HEAD` | scan a commit, e.g. in CI |
| `git redact hook` | install `.git/hooks/pre-commit` running `check` |
| `git redact rules` | list the active rules |

Masked output only ever shows the first 4 characters and the length of a secret.

## How it works

```
git add  ──► clean filter ──► secret → REDACTED-<id> in the blob; the value → vault/secrets/<id>
checkout ──► smudge filter ──► REDACTED-<id> → value from the vault (unknown ids stay as they are)
```

- **Ids** are `HMAC-SHA256(vault key, secret)`, truncated to 12 hex characters. The key is random and never leaves your machine, so an id says nothing about the secret, and the same secret always gets the same id (diffs stay stable).
- **The vault** is `~/.config/git-redact/key` plus one file per secret in `secrets/`, created with mode `0600`. Copy that folder to another machine to restore the secrets there.
- **One process per git command.** git-redact speaks git's [long-running filter protocol](https://git-scm.com/docs/gitattributes#_long_running_filter_process), so `git add` on a whole repository starts Python once, not once per file. Measured on a 576-file, 14 MB Node.js/Go repository: 3.0 s, against 15 s with a per-file filter.
- **Idempotent.** Placeholders are never redacted again, and cleaning a clean file changes nothing, so `git status` stays quiet.

## Good to know

- `git diff` compares your file with the redacted blob *after* cleaning it, so it never shows the secret either.
- Teammates without your vault see placeholders. Share secrets through your usual channel (a `.env`, a secrets manager); git-redact only keeps them out of git.
- Editing a file on GitHub keeps its placeholders; when you pull, your vault fills them back in.
- A placeholder shows *where* a secret lives. That is the point, but it is information.

## Development

```bash
python -m unittest discover -s tests -v
```

The tests build a throwaway repository and exercise the real git round trip: add, commit, checkout, `reset --hard`, clone, process vs per-file mode, binary files, the pre-commit hook. CI runs them on Linux, macOS and Windows with Python 3.8 and 3.12.

## License

[MIT](LICENSE)
