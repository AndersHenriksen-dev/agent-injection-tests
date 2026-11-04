# Learning guide

A study guide to the ideas behind this repository and to what the code actually does. Read the files in order once; afterwards each one works as a reference. Every file ends with where to find its ideas in the code.

| # | File | What it covers |
|---|---|---|
| 1 | [Prompt injection](01-prompt-injection.md) | What it is, why tool-using agents raise the stakes, and why it is hard to fix |
| 2 | [The agent](02-the-agent.md) | Tool use in the Messages API, the agent loop in this repo step by step, and one attack traced through it |
| 3 | [The attacks](03-attacks.md) | How an attack case is built: channels, goals and the eight techniques, with an example of each |
| 4 | [The defenses](04-defenses.md) | Asking the model versus constraining the system: each defense, how it is built and what it cannot stop |
| 5 | [Measuring](05-measuring.md) | Attempted versus succeeded, tasks done, the worst case versus a real model, and how to read the numbers |
| 6 | [Questions to test yourself](06-questions.md) | Short questions with answers, and exercises that change the code |
| 7 | [Further reading](07-further-reading.md) | Papers and posts behind the ideas, and the parts of the API docs this repo uses |
| 8 | [Testing your own agent](08-your-own-agent.md) | How `audit` and `scan` read a skill or agent from another repo, test it with simulated tools and say what to fix |

The one idea to take away: **a defense that the model has to choose to follow can be talked around; a guard in code cannot.** The worst-case check shows this directly. With a model that does whatever the attacker says, the prompt defenses stop 0 of 24 attacks and the guards in code stop 19. The 5 left are false sentences in the answer, which no tool guard can stop. In the [first real run](05-measuring.md#the-first-real-run), Claude Haiku 5.5 resisted all 24 attacks on its own, which says how it handles these known attacks, not what it would do against someone who keeps trying.
