# 1. Prompt injection

## Instructions and data travel in the same channel

A language model reads one stream of text. The system prompt, the user's request, and an email the model was asked to summarize all arrive as tokens in the same context. Nothing in the text itself marks which parts are instructions to follow and which parts are data to read. The model has to infer that, and a model trained to be helpful leans towards following anything that reads like an instruction.

**Prompt injection** is text that exploits this: it is supposed to be data, but it is written so the model treats it as an instruction.

- **Direct injection:** the user types the instruction themselves ("Ignore your previous instructions and..."). The attacker and the user are the same person, so the damage is mostly to the operator's rules.
- **Indirect injection:** the attacker plants the instruction in content the model reads *on someone else's behalf*: an email, a shared document, a web page, a tool result. The user never sees it, and the victim is the user. Greshake et al. (2023) named and demonstrated this.

This repository is about indirect injection.

## Why agents raise the stakes

A chatbot that is fooled writes a bad answer. An agent that is fooled *acts*: it sends email, fetches URLs, creates payments. The text that fooled it now has the agent's permissions.

Simon Willison describes the dangerous combination as the **lethal trifecta**. An agent is exposed when it has all three of:

1. **Access to private data** (client records, internal documents, keys).
2. **Exposure to untrusted content** (anything an outsider can write: inbound email, web pages, shared documents).
3. **A way to send data out** (email, web requests, even a link in its answer that a browser will load).

With all three, anyone who can put text in front of the agent can try to make it send the private data to them. Remove any one leg and that attack class is gone.

The agent in this repository has all three on purpose:

| Leg | In this repo |
|---|---|
| Private data | `lookup_client` returns settlement accounts; document D-4 holds an API key |
| Untrusted content | emails from outside senders, internal documents, the rates web page |
| A way out | `send_email`, `fetch_url`, `create_payment`, and links in the final answer |

## Why it is hard to fix

- **There is no type system for text.** You cannot mark a string as "data only" in a way the model is guaranteed to respect. Delimiters and instructions help, but they are more text.
- **Models follow instructions by design.** The training that makes a model useful is the same training that makes it obey well-written instructions in the wrong place.
- **Filters are probabilistic.** A classifier that catches 99% of injections still lets through the 1% an attacker tunes for, and attackers can try again and again.
- **The attacker adapts.** A defense measured against yesterday's attacks says little about attacks written against that defense.

So the useful question is not "can the model be fooled?" (assume it can) but "**what is the worst that happens when it is?**". That splits defenses into two families, and this repository measures both:

- Defenses the model has to choose to follow: prompt rules, marking data as untrusted. They lower how often the model is fooled.
- Defenses in code around the model: limiting tools, approval, blocking data from leaving. They limit what a fooled model can do.

## In this repo

- [cases/world.yaml](../../cases/world.yaml): the private data and the untrusted content.
- `SIDE_EFFECT_TOOLS` and `OUTBOUND_TOOLS` in [world.py](../../src/injectiontests/world.py): the ways out.
- [decisions.md](../decisions.md), entry 1: why every run records both what the model tried and what actually ran.
