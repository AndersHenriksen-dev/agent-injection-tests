# 7. Further reading

## The problem

- Perez and Ribeiro (2022), "Ignore Previous Prompt: Attack Techniques For Language Models", arXiv:2211.09527. Early systematic look at direct prompt injection.
- Greshake et al. (2023), "Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection", arXiv:2302.12173. The paper that named indirect injection and showed it against real applications.
- Simon Willison (2025), "The lethal trifecta for AI agents: private data, untrusted content, and external communication", simonwillison.net. The three legs from [file 1](01-prompt-injection.md), and why removing one leg is the reliable fix.
- OWASP Top 10 for Large Language Model Applications, entry LLM01 "Prompt Injection". A practitioner's checklist of attack and mitigation types.

## Measuring agents under attack

- Zhan et al. (2024), "InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated Large Language Model Agents", arXiv:2403.02691. A benchmark of attacks planted in tool output, like the cases here.
- Debenedetti et al. (2024), "AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents", arXiv:2406.13352. Tasks, attacks and defenses in simulated environments, measuring both security and utility, the same two axes as this repo.

## Defenses

- Hines et al. (2024), "Defending Against Indirect Prompt Injection Attacks With Spotlighting", arXiv:2403.14720. Delimiting, datamarking and encoding untrusted input; the `spotlight` defense here is the delimiting variant.
- Debenedetti et al. (2025), "Defeating Prompt Injections by Design", arXiv:2503.18813. CaMeL: separate the control flow, fixed from the user's request, from the untrusted data flow.
- Beurer-Kellner et al. (2025), "Design Patterns for Securing LLM Agents against Prompt Injections". Patterns such as plan-then-execute and limiting what untrusted data can influence.

## The API features used here

The Claude API documentation at platform.claude.com/docs, on tool use (tool definitions, `tool_use` and `tool_result` blocks, strict tools), extended and adaptive thinking and effort, prompt caching, and stop reasons including refusals.

## This repository

- [decisions.md](../decisions.md) for why each choice was made.
- [evals/WORST_CASE.md](../../evals/WORST_CASE.md) for the generated worst-case results.
