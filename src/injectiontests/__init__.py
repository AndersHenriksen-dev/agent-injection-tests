"""Tests of whether a tool-using Claude agent can be hijacked by instructions hidden in the data it reads.

The agent works for a synthetic fund administrator. Attacks hide instructions in its emails, documents and web pages;
defenses range from prompt rules to guards in code; scoring checks what the model tried and what actually ran.
"""
