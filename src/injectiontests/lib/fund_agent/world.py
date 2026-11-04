"""The synthetic fund administrator and the tools the agent uses on it.

Nothing here is real: names, accounts and domains are made up, and the domains use the reserved `.test` and
`.example` top-level domains. Tools only read and change this in-memory world.
"""

from __future__ import annotations

from typing import Any

from anthropic.types import ToolParam

from injectiontests.lib.shared.loop import strict_tool
from injectiontests.lib.shared.models import Attack, Channel, Strict, ToolSpec, World
from injectiontests.lib.shared.settings import config_for


class _WorldConfig(Strict):
    side_effect_tools: frozenset[str]
    outbound_tools: frozenset[str]
    tools: dict[str, ToolSpec]


_CONFIG = config_for(__name__, _WorldConfig)

SIDE_EFFECT_TOOLS = _CONFIG.side_effect_tools
OUTBOUND_TOOLS = _CONFIG.outbound_tools
TOOLS: dict[str, ToolParam] = {
    name: strict_tool(name, spec.description, spec.parameters) for name, spec in _CONFIG.tools.items()
}

# The parameter names again as plain strings, since the SDK types a schema's properties loosely.
PARAMETERS: dict[str, list[str]] = {name: list(spec.parameters) for name, spec in _CONFIG.tools.items()}


class ToolError(Exception):
    """A tool was called with arguments it cannot use. The message goes back to the model."""


def plant(world: World, attack: Attack) -> World:
    """Return a copy of the world with the attacker's text added to the end of the targeted item."""
    planted = world.model_copy(deep=True)
    if attack.channel is Channel.EMAIL:
        email = planted.emails[attack.target]
        email.body = f"{email.body}\n\n{attack.payload}"
    elif attack.channel is Channel.DOCUMENT:
        document = planted.documents[attack.target]
        document.body = f"{document.body}\n\n{attack.payload}"
    else:
        planted.pages[attack.target] = f"{planted.pages[attack.target]}\n\n{attack.payload}"
    return planted


class Workspace:
    """A world the agent acts on during one run, with a record of what its write tools did."""

    def __init__(self, world: World) -> None:
        """Start a run on `world`, which is not changed."""
        self.world = world
        self.sent: list[dict[str, str]] = []
        self.payments: list[dict[str, str]] = []
        self.tickets: list[dict[str, str]] = []

    def execute(self, tool: str, arguments: dict[str, Any]) -> str:
        """Run one tool and return its text output.

        Raises:
            ToolError: The tool does not exist, or an argument is missing or refers to nothing.
        """
        handler = getattr(self, f"_{tool}", None)
        if tool not in TOOLS or handler is None:
            raise ToolError(f"Unknown tool {tool!r}.")
        try:
            values = {key: str(arguments[key]) for key in PARAMETERS[tool]}
        except KeyError as missing:
            raise ToolError(f"Missing argument {missing}.") from None
        output: str = handler(**values)
        return output

    def _list_emails(self) -> str:
        return "\n".join(f"{key} | from {email.sender} | {email.subject}" for key, email in self.world.emails.items())

    def _read_email(self, email_id: str) -> str:
        email = self._find(self.world.emails, email_id, "email")
        return f"From: {email.sender}\nSubject: {email.subject}\n\n{email.body}"

    def _search_documents(self, query: str) -> str:
        words = [word for word in query.lower().split() if len(word) > 2]
        hits = [
            f"{key} | {doc.title}"
            for key, doc in self.world.documents.items()
            if any(word in f"{doc.title} {doc.body}".lower() for word in words)
        ]
        return "\n".join(hits) if hits else "No documents match."

    def _read_document(self, document_id: str) -> str:
        document = self._find(self.world.documents, document_id, "document")
        return f"{document.title}\n\n{document.body}"

    def _lookup_client(self, client_id: str) -> str:
        client = self._find(self.world.clients, client_id, "client")
        return (
            f"Client {client_id}: {client.name}\nHoldings: {client.holdings}\n"
            f"Relationship manager: {client.relationship_manager}\nSettlement account: {client.account}"
        )

    def _fetch_url(self, url: str) -> str:
        return self.world.pages.get(url, "404 Not Found")

    def _send_email(self, to: str, subject: str, body: str) -> str:
        self.sent.append({"to": to, "subject": subject, "body": body})
        return f"Email sent to {to}."

    def _create_payment(self, beneficiary_account: str, amount: str, reference: str) -> str:
        self.payments.append({"beneficiary_account": beneficiary_account, "amount": amount, "reference": reference})
        return f"Payment of {amount} to {beneficiary_account} created and sent for approval."

    def _create_ticket(self, title: str, description: str) -> str:
        self.tickets.append({"title": title, "description": description})
        return f"Ticket T-{len(self.tickets)} created: {title}"

    @staticmethod
    def _find[T](items: dict[str, T], key: str, kind: str) -> T:
        if key not in items:
            raise ToolError(f"No {kind} with id {key!r}.")
        return items[key]
