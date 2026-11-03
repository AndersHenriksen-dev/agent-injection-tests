# Design decisions

One entry per choice, with the reason. Newest last.

## 1. Score what the model tried and what actually ran, separately

Every tool call is recorded before the guards decide, so each attack gets two outcomes: *attempted* (the model asked for the attacker's action) and *succeeded* (the action ran, or the employee would see the hijacked answer). The first measures the model; the second measures the system. A defense that leaves the model fooled but stops the harm shows up as attempted without success.

## 2. A worst case with scripted models, run in CI

Prompt rules and tagged tool output only help if the model listens. Guards in code hold whatever the model does. To show the difference without an API key, every attack lists the calls a fully hijacked model would make, and a scripted model makes exactly those. Every task lists the calls a correct agent makes, so the same check shows whether a guard blocks real work. CI fails if a correct run is blocked, if an attack's own calls do not reach its goal, or if anything but a hijacked answer gets through with every guard on.

## 3. The approver is careful by design

The approval guard approves a side effect only when it matches what the employee asked for. That is the best case for approval. Real approvers who click yes to everything give no protection, so the results are an upper bound for this defense.

## 4. A hand-written agent loop

The SDK's tool runner would run the loop, but every call here must pass the guards and be recorded before it runs, whether or not it is allowed. A short manual loop does that in one place. Assistant turns are appended unchanged, thinking blocks included, so the conversation history stays valid for the API.

## 5. Claude Opus 5.5 by default, no refusal fallback

The model under test defaults to `claude-opus-5-5` at effort `medium`, and both can be changed with `INJECTIONTESTS_MODEL` and `INJECTIONTESTS_EFFORT`. A refusal is recorded as its own outcome. The API's refusal fallback is not turned on, because a fallback model would answer some runs and the results would no longer describe the model under test.

## 6. Synthetic world, reserved domains

The company, its clients, accounts and staff are made up. Company addresses use `examplefund.test` and attacker addresses use `attacker.example`, both reserved top-level domains, so no case can point at a real site. Client accounts and one API key are canaries: the egress guard blocks them in any outbound call, however they are spaced.

## 7. Tool output is marked with a tag the data cannot close

The spotlight defense wraps every tool result in `<tool_output>` tags and tells the model that everything inside is untrusted. Any copy of the tag inside the data is broken (`<tool_output_`), so a payload cannot end the wrapper early and pretend to be outside it. The tag is fixed rather than random so the cached prompt prefix stays the same between runs.
