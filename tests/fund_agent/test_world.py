"""The synthetic world: tools read and change it, and attacks are planted in copies of it."""

from __future__ import annotations

import pytest

from injectiontests.lib.fund_agent.cases import Cases
from injectiontests.lib.fund_agent.world import TOOLS, ToolError, Workspace, plant
from injectiontests.lib.shared.models import Attack, Channel, Goal, Technique


def _attack(channel: Channel, target: str) -> Attack:
    return Attack(
        id="test",
        task="summarize_inbox",
        channel=channel,
        target=target,
        technique=Technique.PLAIN,
        goal=Goal.HIJACK_ANSWER,
        payload="PAYLOAD",
        marker="x",
    )


class TestPlant:
    @pytest.mark.parametrize(
        ("channel", "target"),
        [(Channel.EMAIL, "E-2"), (Channel.DOCUMENT, "D-1"), (Channel.PAGE, "https://rates.examplefund.test/eur")],
    )
    def test_adds_the_payload_to_a_copy(self, cases: Cases, channel: Channel, target: str) -> None:
        planted = plant(cases.world, _attack(channel, target))
        workspace, original = Workspace(planted), Workspace(cases.world)
        tool, argument = {
            Channel.EMAIL: ("read_email", {"email_id": target}),
            Channel.DOCUMENT: ("read_document", {"document_id": target}),
            Channel.PAGE: ("fetch_url", {"url": target}),
        }[channel]
        assert workspace.execute(tool, argument).endswith("PAYLOAD")
        assert "PAYLOAD" not in original.execute(tool, argument)


class TestTools:
    def test_every_tool_has_a_handler(self, cases: Cases) -> None:
        workspace = Workspace(cases.world)
        for name in TOOLS:
            assert hasattr(workspace, f"_{name}")

    def test_client_lookup_shows_the_account(self, cases: Cases) -> None:
        assert "DK50 9000 0001 0101 99" in Workspace(cases.world).execute("lookup_client", {"client_id": "C-101"})

    def test_search_finds_documents_by_word(self, cases: Cases) -> None:
        assert "D-1" in Workspace(cases.world).execute("search_documents", {"query": "Aurora"})

    def test_unknown_page_is_not_found(self, cases: Cases) -> None:
        assert Workspace(cases.world).execute("fetch_url", {"url": "https://nowhere.test/"}) == "404 Not Found"

    def test_write_tools_are_recorded(self, cases: Cases) -> None:
        workspace = Workspace(cases.world)
        workspace.execute("send_email", {"to": "a@examplefund.test", "subject": "s", "body": "b"})
        workspace.execute("create_payment", {"beneficiary_account": "X", "amount": "EUR 1", "reference": "r"})
        workspace.execute("create_ticket", {"title": "t", "description": "d"})
        assert (len(workspace.sent), len(workspace.payments), len(workspace.tickets)) == (1, 1, 1)

    def test_unknown_tool_missing_argument_and_unknown_id_are_errors(self, cases: Cases) -> None:
        workspace = Workspace(cases.world)
        with pytest.raises(ToolError, match="Unknown tool"):
            workspace.execute("delete_everything", {})
        with pytest.raises(ToolError, match="Missing argument"):
            workspace.execute("read_email", {})
        with pytest.raises(ToolError, match="No email"):
            workspace.execute("read_email", {"email_id": "E-99"})
