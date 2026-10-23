# emudhra-ca-remediation

An agent skill for remediating systems exposed to the October 2026 eMudhra/emSign intermediate CA compromise. It helps your agent find every system you run or software you ship that trusts the compromised intermediates, patch it, and verify that the deployed artifact rejects them. [`SKILL.md`](skills/emudhra-ca-remediation/SKILL.md) is the entry point.

> [!TIP]
> You only need to run this once, so instead of installing it consider running just once:
> ```sh
> npx skills use fractional-ai/emudhra-ca-remediation@emudhra-ca-remediation --agent claude-code
> ```
> Or just point your agent to this repo, it can figure out what to do.

## Install

**Patch the client you install with first.** `npx` and `git` fetch over the same kind of TLS client this skill is about, so on an unpatched Node, prefer `git clone`.

With [skills](https://github.com/vercel-labs/skills) (Claude Code, Codex, Cursor, OpenCode and others):

```bash
npx skills add fractional-ai/emudhra-ca-remediation
```

As a Claude Code plugin:

```
/plugin marketplace add fractional-ai/emudhra-ca-remediation
/plugin install emudhra-ca-remediation@emudhra-ca-remediation
```

Or by hand:

```bash
git clone https://github.com/fractional-ai/emudhra-ca-remediation
cp -r emudhra-ca-remediation/skills/emudhra-ca-remediation ~/.claude/skills/
```

## Requirements and tests

The scripts need Python 3.8+ (PyYAML for YAML files) and POSIX sh. Run the tests with `python3 tests/test_scripts.py`.

## Status

Versions and dates are a snapshot from 2026-10-23. Run `check_advisory.py` first, every time, to see what has changed since: https://emudhra.we-have-a-problem.com/

This is shared as is and maintained on a best-effort basis. Issues about anything the skill gets wrong or misses are welcome.

## License

MIT. See [LICENSE](LICENSE).

Copyright (c) 2026 Ode with Anthropic
