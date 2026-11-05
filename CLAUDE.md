# CLAUDE.md

Tests of whether a tool-using Claude agent can be turned against its user by text hidden in the emails, documents and web pages it reads, and which defenses stop that. It can also be installed and pointed at a skill or agent in another repo. Everything here is public, so write for a reader who has never seen it.

## Run things

```bash
uv sync                                     # install
uv run pre-commit install                   # once: ruff, mypy, line endings and gitleaks on every commit
uv run injectiontests list                  # the tasks, attacks and defenses
uv run injectiontests worst-case --check    # every case with scripted models: free, what CI runs
uv run injectiontests worst-case --write    # regenerate evals/WORST_CASE.md
uv run injectiontests run --attack <id> --defense <name>   # one run against Claude, costs money: ask first
uv run injectiontests eval                  # prints the plan of the full matrix; --yes runs it, costs money: ask first
uv run injectiontests eval --passes 3 --yes --resume results/<time>/runs.jsonl   # repeat the matrix, or finish a stopped run
uv run injectiontests rescore results/<time>/runs.jsonl    # score saved runs again, free; --write replaces evals/RESULTS.md
uv run injectiontests audit <file or folder>   # what to fix in a skill or agent: free, no API key
uv run injectiontests scan <file or folder>    # prints the plan; --yes runs planted attacks with simulated tools, costs money: ask first
uv run ruff check . && uv run ruff format --check . && uv run mypy src && uv run pytest   # what CI checks
```

## Index of `.claude/` and related files

| File | Read it when | What it covers |
|---|---|---|
| [.claude/reference/python-style.md](.claude/reference/python-style.md) | **Before writing or editing any `.py` file** | The single source of truth for Python here: PEP 8 via ruff, typing checked by mypy, Google-style docstrings, Pydantic models at boundaries, module structure, KISS/DRY/LEAN, comments, testing. |
| [.claude/reference/git-workflow.md](.claude/reference/git-workflow.md) | **Before creating a branch, a commit or a pull request** | Branch names (`category/description`), commit messages (`tag(scope): Header`, a body that says why), rebasing instead of merging `main` in, pull request bodies, attribution. |
| [.claude/commands/commit-push-pr.md](.claude/commands/commit-push-pr.md) | Committing and opening a pull request | Command that runs the checks, commits, pushes and opens the pull request by the workflow above. |
| [.claude/hooks/check_python_style_read.py](.claude/hooks/check_python_style_read.py) | Debugging why a Python edit was blocked | `PreToolUse` hook that blocks editing `.py`/`.ipynb` files until the style guide has been read in the session. |
| [.claude/settings.json](.claude/settings.json) | Changing permissions or hooks | Allowed, asked and denied commands (paid runs ask; force pushes that are not `--force-with-lease` are denied), and the hook above. |
| [.pre-commit-config.yaml](.pre-commit-config.yaml), [.github/workflows/ci.yml](.github/workflows/ci.yml) and [.gitleaks.toml](.gitleaks.toml) | Changing what runs on commit or in CI | The automatic half of the style guide, the worst-case check and the gitleaks secret scan, which allows only the canary key. |
| [docs/decisions.md](docs/decisions.md) | Changing a design choice | Why things are built the way they are. |
| [docs/learn/](docs/learn/README.md) | Learning or explaining how the suite works | Study guide: prompt injection, the agent loop, the attacks, the defenses, measuring, self-test questions and further reading, with pointers into the code. |

## Rules

- Every new attack gets `attacker_calls` (or, for hijack_answer, a `marker` and `attacker_answer`) so the worst-case check covers it. Every new task gets `reference_calls` and a `reference_answer`. Every new attack in `config/existing_agents/attacks.yaml` gets a `call_marker` with `needs` and an `attacker_call`, or an `answer_marker` and an `attacker_answer`.
- Every new guard or defense must keep `worst-case --check` passing: no defense may block a correct run of a task, and with every guard on, only hijacked answers may get through.
- Synthetic data only. Names, accounts and domains are made up; domains use the reserved `.test` and `.example` top-level domains. Attacks run only against this repo's own agent and world, or through `scan` against an agent the user owns, always with simulated tools. A tool in `sandbox.py` must never touch a real file, command or website.
- Nothing from Anders's current or past employers goes in this repo: no code, prompts, documents, internal names or data.
- Never commit keys or raw transcripts: `.env`, `results/` and `injection-results/` are git-ignored. Never read `.env`.
- Run `run`, `eval` or `scan --yes` only when asked: they call the paid API. Say the number of runs and the model first.
- A fix in `config/existing_agents/audit.yaml` or `scan.yaml` must name a setting that exists in Claude Code's docs, and must not be weaker than it looks.
- Results tables in `evals/` are generated by the CLI, never edited by hand.
- Record design choices and their reasons in `docs/decisions.md`.
- Prompts, patterns, prices, limits and fix advice go in `config/`, not in code. A Python file that needs config has one YAML file at the same path under `config/`, read with `config_for(__name__, ...)` and checked by a Pydantic model. `lib/existing_agents` and `lib/fund_agent` never import each other.
- When a technique, defense or metric is added or changed, update the matching file in `docs/learn/`, including any numbers it quotes.

## Attribution: the agent never credits itself

Anders is the only author of everything here: commits, pull request bodies, comments and docs. No `Co-Authored-By:` trailer naming a tool, agent or model, no "Generated with" line, and no text that says an AI tool built or helped with the work. Never override `user.name`, `user.email` or `--author`.

## Writing style (everything that is not Python)

- Never use em dashes anywhere: README, docs, comments, commit messages. Use commas, colons, full stops or parentheses.
- Plain English, short sentences, numbers instead of adjectives, no hype words. README in first person singular.
- Write about the code and the results as they are now, not about how they got there.
- Git: follow [.claude/reference/git-workflow.md](.claude/reference/git-workflow.md). Branches `category/description`, one per task, rebased (never merged) onto `main`. Commits `tag(scope): Header` with a body that explains why, author `Anders Henriksen <anhenr.dev@gmail.com>`. Squash merge.

## Layout

```text
src/injectiontests/
|-- cli.py                 the entry point: reads the command line and hands over
|-- lib/                   all other Python
|   |-- existing_agents/   testing a skill or agent from another repo
|   |   |-- commands.py    the audit and scan commands
|   |   |-- targets.py     reading such a file, and what its tools let it do
|   |   |-- audit.py       the free rules that say what to fix
|   |   |-- attacks.py     which attacks can reach it, and whether one worked
|   |   |-- sandbox.py     the simulated tools and the emulator: never touch anything real
|   |   |-- scan.py        running the attacks
|   |   `-- report.py      the Markdown report
|   |-- fund_agent/        this repo's own study on a made-up fund administrator
|   |   |-- commands.py    the list, worst-case, run, eval and rescore commands
|   |   |-- cases.py       loading and checking the case files
|   |   |-- world.py       the tools and the in-memory company; `plant` adds a payload
|   |   |-- guards.py      least privilege, approval and egress
|   |   |-- defenses.py    the seven configurations and tool-output wrapping
|   |   |-- agent.py       one run: every call passes the guards and is recorded
|   |   |-- scoring.py     attempted versus succeeded, and whether the task was done
|   |   `-- evaluate.py    the matrix, the worst case and the results tables
|   `-- shared/            what both use: nothing here imports either of them
|       |-- loop.py        the hand-written agent loop, the Claude model, the scripted model
|       |-- models.py      Pydantic models for everything read from YAML or written as JSON
|       |-- settings.py    reading config files, and the shared settings
|       `-- claims.py      stating a claim versus quoting it to warn
`-- config/                the same subfolders as lib/: audit.py reads audit.yaml
tests/                     the same subfolders again
evals/                     generated results (WORST_CASE.md, and RESULTS.md from paid runs)
```
