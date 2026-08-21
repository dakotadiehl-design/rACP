import asyncio
import unittest
from pathlib import Path

from acp.remote import RemoteAuthority, RemoteHost, sample_layout
from acp.session import Session
from acp.testkit import default_caps, identity, linked_transports
from acp.types import Endpoint, Role

from acp_workbench.engine import WorkbenchEngine
from acp_workbench.models import ConnectionConfig, ConnectionState
from acp_workbench.scenarios import ScenarioRunner, load_scenario

NODE_ID = "0193f8d8-4c4e-7d8b-a2ab-0000000000b0"
SHOW_ID = "0193f8d8-4c4e-7d8b-a2ab-000000000050"
LAYOUT_ID = "0193f8d8-4c4e-7d8b-a2ab-0000000000a0"


class ACPFixture:
    def __init__(self, *, inline_surface=True):
        self.tasks = []
        self.sessions = []
        self.hosts = []
        self.authorities = []
        self.inline_surface = inline_surface

    async def transport(self, _config):
        client_transport, server_transport = linked_transports()
        # The reference authority uses a Conductor identity because the registry
        # permits it to publish both navigation state and generic state deltas.
        # This never launches or connects to the Prism executable.
        server_identity = identity(Role.CONDUCTOR, "fixture-authority")
        authority = RemoteAuthority(source=Endpoint(server_identity.node_id), show_id=SHOW_ID)
        authority.set_layout(sample_layout(show_id=SHOW_ID, layout_id=LAYOUT_ID))
        authority.authorize(
            NODE_ID,
            ["remote.operator", "remote.busker", "remote.show_navigation", "remote.admin"],
        )
        server = Session(
            server_transport,
            server_identity,
            is_server=True,
            allow_plaintext=True,
            profiles=["core", "remote", "aurora.remote.prism.v1"],
        )
        host = RemoteHost(authority, inline_surface=self.inline_surface)
        self.sessions.append(server)
        self.hosts.append(host)
        self.authorities.append(authority)

        async def serve():
            await server.handshake(default_caps())
            await host.start()
            await host.serve(server)

        self.tasks.append(asyncio.create_task(serve()))
        return client_transport

    async def close(self):
        for host in self.hosts:
            await host.close()
        for session in self.sessions:
            await session.goodbye()
        for task in self.tasks:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, ConnectionError):
                pass


class EngineIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.fixture = ACPFixture()
        self.engine = WorkbenchEngine(transport_factory=self.fixture.transport)
        self.config = ConnectionConfig(
            target="ws://127.0.0.1:27421/acp",
            node_id=NODE_ID,
            allow_plaintext=True,
            show_id=SHOW_ID,
            layout_id=LAYOUT_ID,
        )

    async def asyncTearDown(self):
        await self.engine.close()
        await self.fixture.close()

    async def test_connect_sync_and_authoritative_go(self):
        connection = await self.engine.connect(self.config)
        self.assertEqual(connection.state, ConnectionState.READY)
        self.assertTrue(connection.profile.actions())
        self.assertIn("control.blackout", connection.profile.view)
        blackout = next(action for action in connection.profile.actions() if action.id == "blackout")
        self.assertTrue(blackout.enabled)
        self.assertTrue(blackout.available)
        before = dict(connection.profile.view)
        envelope = await self.engine.navigate("default", "go")
        after = self.engine.history[-1].sequence
        ack = await self.engine.wait_for(
            lambda event: event.kind == "envelope.in"
            and event.data["envelope"]["type"] == "command.ack"
            and event.data["envelope"].get("correlation_id") == envelope.message_id,
            after_sequence=after,
            timeout=2,
        )
        state = await self.engine.wait_for(
            lambda event: event.kind == "envelope.in"
            and event.sequence > ack.sequence
            and event.data["envelope"]["type"] in {"remote.navigation.state", "state.delta"},
            after_sequence=ack.sequence,
            timeout=2,
        )
        self.assertGreater(state.sequence, ack.sequence)
        self.assertNotEqual(connection.profile.view, before)

    async def test_terminal_ack_clears_pending_by_correlation(self):
        connection = await self.engine.connect(self.config)
        envelope = await self.engine.invoke("default", "look_recall")
        invocation = str(envelope.payload["invocation_id"])
        self.assertIn(invocation, connection.profile.client.pending)
        await self.engine.wait_for(
            lambda event: event.kind == "envelope.in"
            and event.data["envelope"]["type"] == "command.ack"
            and event.data["envelope"].get("correlation_id") == envelope.message_id,
            timeout=2,
        )
        self.assertNotIn(invocation, connection.profile.client.pending)

    async def test_chunked_surface_transfer(self):
        fixture = ACPFixture(inline_surface=False)
        engine = WorkbenchEngine(transport_factory=fixture.transport)
        try:
            connection = await engine.connect(self.config)
            self.assertEqual(connection.state, ConnectionState.READY)
            self.assertIsNotNone(connection.profile.client.layout)
            self.assertTrue(any(event.kind == "envelope.in" and event.data["envelope"]["type"] == "resource.chunk"
                                for event in engine.history))
            self.assertTrue(any(event.kind == "envelope.out" and event.data["envelope"]["type"] == "resource.accept"
                                for event in engine.history))
        finally:
            await engine.close()
            await fixture.close()

    async def test_graceful_disconnect_sends_momentary_end(self):
        connection = await self.engine.connect(self.config)
        envelope = await self.engine.invoke(
            "default",
            "fog_burst",
            1.0,
            interaction="momentary_begin",
        )
        await self.engine.wait_for(
            lambda event: event.kind == "envelope.in"
            and event.data["envelope"]["type"] == "command.ack"
            and event.data["envelope"].get("correlation_id") == envelope.message_id,
            timeout=2,
        )
        self.assertTrue(connection.profile.client.leases)
        await self.engine.disconnect("default", graceful=True)
        await asyncio.sleep(0)
        self.assertFalse(self.fixture.authorities[0].effect_active("fog_burst"))
        self.assertTrue(any(
            event.kind == "envelope.out"
            and event.data["envelope"]["type"] == "remote.control.invoke"
            and event.data["envelope"]["payload"].get("interaction") == "momentary_end"
            for event in self.engine.history
        ))

    async def test_command_ack_does_not_mutate_confirmed_view(self):
        connection = await self.engine.connect(self.config)
        before = dict(connection.profile.view)
        envelope = connection.profile.envelope_for_action("look_recall")
        invocation = str(envelope.payload["invocation_id"])
        from acp.envelope import make_envelope
        from acp.types import QoS

        ack = make_envelope(
            type="command.ack",
            source=Endpoint(self.fixture.sessions[0].local.node_id),
            qos=QoS.RELIABLE,
            payload={
                "status": "applied",
                "result": {"invocation_id": invocation, "control_id": "look_recall", "value": "Rock"},
            },
        )
        connection.profile.handle(ack)
        self.assertEqual(connection.profile.view, before)

    async def test_canonical_delta_updates_remote_view(self):
        connection = await self.engine.connect(self.config)
        from acp.envelope import make_envelope

        delta = make_envelope(
            type="state.delta",
            source=Endpoint(self.fixture.sessions[0].local.node_id),
            payload={
                "authority_epoch": 7,
                "base_revision": 1,
                "revision": 2,
                "changes": [{
                    "resource": "prism.cue",
                    "revision": 2,
                    "confidence": "confirmed",
                    "value": {"current_cue_id": "cue-1", "next_cue_id": "cue-2"},
                }],
            },
        )
        connection.profile.handle(delta)
        self.assertEqual(connection.profile.view["prism.cue"]["current_cue_id"], "cue-1")
        self.assertEqual(connection.profile._authority_epoch, 7)

    async def test_cue_fire_uses_published_target_and_preconditions(self):
        connection = await self.engine.connect(self.config)
        current = "02530c92-934b-4c84-b91b-5c5b877a2d74"
        next_cue = "b4e8ea4b-9c61-4dd3-bc79-9326f6f5fe1b"
        connection.profile.client.view["prism.cue"] = {
            "current_cue_id": current,
            "next_cue_id": next_cue,
        }
        connection.profile._authority_epoch = 9

        envelope = connection.profile.envelope_for_action("cue_fire")

        self.assertEqual(envelope.payload["value"], next_cue)
        self.assertEqual(envelope.payload["delivery"], "live_ephemeral")
        self.assertEqual(envelope.payload["preconditions"], [
            {"op": "equals", "field": "authority_epoch", "value": 9},
            {"op": "equals", "field": "current_cue_id", "value": current},
        ])

    async def test_grand_master_uses_set_freshness_and_epoch(self):
        connection = await self.engine.connect(self.config)
        connection.profile._authority_epoch = 12

        envelope = connection.profile.envelope_for_action("grand_master", 0.42)

        self.assertEqual(envelope.payload["interaction"], "set")
        self.assertEqual(envelope.payload["value"], 0.42)
        self.assertEqual(envelope.payload["delivery"], "live_ephemeral")
        self.assertIn("issued_at", envelope.payload)
        self.assertIn("expires_at", envelope.payload)
        self.assertEqual(envelope.payload["preconditions"], [
            {"op": "equals", "field": "authority_epoch", "value": 12},
        ])

        with self.assertRaises(ValueError):
            connection.profile.envelope_for_action("grand_master", float("nan"))
        with self.assertRaises(ValueError):
            connection.profile.envelope_for_action("grand_master", 1.01)

    async def test_explicit_blackout_uses_freshness_and_epoch(self):
        connection = await self.engine.connect(self.config)
        connection.profile._authority_epoch = 14

        for action in ("blackout_on", "blackout_off"):
            envelope = connection.profile.envelope_for_action(action)
            self.assertEqual(envelope.payload["interaction"], "activate")
            self.assertEqual(envelope.payload["delivery"], "live_ephemeral")
            self.assertIn("issued_at", envelope.payload)
            self.assertIn("expires_at", envelope.payload)
            self.assertEqual(envelope.payload["preconditions"], [
                {"op": "equals", "field": "authority_epoch", "value": 14},
            ])

    async def test_bundled_scenarios_against_reference_fixture(self):
        runner = ScenarioRunner(self.engine)
        root = Path(__file__).parents[1] / "scenarios" / "remote-prism"
        for path in sorted(root.glob("*.json")):
            with self.subTest(path=path.name):
                result = await runner.run(load_scenario(path), self.config)
                self.assertTrue(result.passed, result.error)


if __name__ == "__main__":
    unittest.main()
