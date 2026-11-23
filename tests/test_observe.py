"""observe(): sent, on the wire, received, reply on the wire, each kept separate.

The capture is replaced by a fake whose report the test controls, so every
combination of a healthy, incomplete or broken instrument is exercised. The
point: a fact the instrument cannot vouch for is ``None``, never ``False``.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from nse import stimuli
from nse.core import probe_packets, sniffer
from nse.models.stimulus import Endpoint, Receipt, ReceiptLog, StimulusResult

PROBE = "abcdefabcdefabcdefabcdef"


def _result(**fields: Any) -> StimulusResult:
    base: dict[str, Any] = {
        "kind": "udp_round_trip",
        "transport": "udp",
        "family": 4,
        "probe_id": PROBE,
        "destination": Endpoint(address="10.0.1.1", port=9999),
        "source": Endpoint(address="10.0.1.2", port=40000),
        "payload": probe_packets.marker(PROBE),
        "outcome": "answered",
        "reply": probe_packets.marker(PROBE),
        "reply_source": Endpoint(address="10.0.1.1", port=9999),
    }
    base.update(fields)
    return StimulusResult(**base)


REQUEST = Ether(
    bytes(
        Ether()
        / IP(src="10.0.1.2", dst="10.0.1.1")
        / UDP(sport=40000, dport=9999)
        / Raw(probe_packets.marker(PROBE))
    )
)
REPLY = Ether(
    bytes(
        Ether()
        / IP(src="10.0.1.1", dst="10.0.1.2")
        / UDP(sport=9999, dport=40000)
        / Raw(probe_packets.marker(PROBE))
    )
)


class FakeStimulus:
    def __init__(self, result: StimulusResult) -> None:
        self.result = result
        self.calls: list[dict[str, Any]] = []

    async def run(self, sandbox: Any, **options: Any) -> StimulusResult:
        self.calls.append(options)
        return self.result


class FakeReceiver:
    def __init__(self, log: ReceiptLog) -> None:
        self._log = log

    def log(self) -> ReceiptLog:
        return self._log


def _receipt(probe_id: str | None = PROBE) -> Receipt:
    return Receipt(
        seq=1,
        transport="udp",
        kind="datagram",
        family=4,
        source=Endpoint(address="10.0.1.2", port=40000),
        destination=Endpoint(address="10.0.1.1", port=9999),
        monotonic=1.0,
        wall=1.0,
        size=34,
        data=b"",
        response="echo",
        probe_id=probe_id,
    )


@pytest.fixture
def capture(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """Replace PCAPAsserter; the test sets what the capture saw and reports."""
    state = SimpleNamespace(
        packets=[], healthy=True, complete=True, created=[], stopped=0, started=0, reported=0
    )

    class FakeAsserter:
        def __init__(self, iface: str, filter: str | None = None, *, netns: Any = None) -> None:
            state.created.append({"iface": iface, "filter": filter, "netns": netns})

        async def start(self) -> None:
            state.started += 1

        async def stop_report(self) -> Any:
            state.reported += 1
            return SimpleNamespace(
                instrument_healthy=state.healthy,
                window_complete=state.complete,
                iface="vhr-x",
                packets_observed=len(state.packets),
            )

        async def stop(self) -> list[Any]:
            state.stopped += 1
            return list(state.packets)

    monkeypatch.setattr(sniffer, "PCAPAsserter", FakeAsserter)
    return state


SANDBOX = SimpleNamespace(ext_iface="vhr-x", ext_netns="nsh_x")


@pytest.mark.asyncio
async def test_every_fact_true_when_everything_was_seen(capture: SimpleNamespace) -> None:
    capture.packets = [REQUEST, REPLY]
    receiver = FakeReceiver(ReceiptLog(receipts=(_receipt(),), complete=True))
    stimulus = FakeStimulus(_result())
    seen = await stimuli.observe(SANDBOX, stimulus, receiver=receiver, settle=0)  # type: ignore[arg-type]
    assert (seen.sent, seen.on_wire, seen.received, seen.reply_on_wire) == (True,) * 4
    assert seen.requests == (REQUEST,)
    assert seen.replies == (REPLY,)
    assert seen.receipts == (_receipt(),)
    assert seen.contradictions() == []
    assert capture.created == [{"iface": "vhr-x", "filter": None, "netns": "nsh_x"}]
    assert "on the wire: yes" in seen.describe()


@pytest.mark.asyncio
async def test_an_absence_in_a_complete_capture_is_false(capture: SimpleNamespace) -> None:
    receiver = FakeReceiver(ReceiptLog(complete=True))
    seen = await stimuli.observe(
        SANDBOX,
        FakeStimulus(_result(outcome="refused", stage="send", errno=1, reply=None)),  # type: ignore[arg-type]
        receiver=receiver,  # type: ignore[arg-type]
        settle=0,
    )
    assert (seen.sent, seen.on_wire, seen.received, seen.reply_on_wire) == (False,) * 4


@pytest.mark.parametrize(
    ("healthy", "complete"), [(True, None), (True, False), (False, True), (False, None)]
)
@pytest.mark.asyncio
async def test_an_absence_the_capture_cannot_vouch_for_is_unknown(
    capture: SimpleNamespace, healthy: bool, complete: bool | None
) -> None:
    capture.healthy, capture.complete = healthy, complete
    capture.packets = [REQUEST] if healthy else []
    seen = await stimuli.observe(SANDBOX, FakeStimulus(_result()), settle=0)  # type: ignore[arg-type]
    assert seen.on_wire is (True if healthy else None)  # what was seen still counts
    assert seen.reply_on_wire is None
    assert seen.received is None
    assert seen.receipts is None
    assert capture.stopped == (1 if healthy else 0)  # a broken capture's list is never read
    assert "unknown" in seen.describe()


@pytest.mark.asyncio
async def test_an_incomplete_receiver_log_cannot_say_not_received(
    capture: SimpleNamespace,
) -> None:
    receiver = FakeReceiver(ReceiptLog(complete=False, problems=("gap",)))
    seen = await stimuli.observe(SANDBOX, FakeStimulus(_result()), receiver=receiver, settle=0)  # type: ignore[arg-type]
    assert seen.received is None
    found = FakeReceiver(ReceiptLog(receipts=(_receipt(),), complete=False))
    seen = await stimuli.observe(SANDBOX, FakeStimulus(_result()), receiver=found, settle=0)  # type: ignore[arg-type]
    assert seen.received is True  # what is in the log was received


@pytest.mark.asyncio
async def test_a_blind_capture_contradicts_the_receiver(capture: SimpleNamespace) -> None:
    """The deliberately blind setup: the receiver got it, the capture saw nothing."""
    receiver = FakeReceiver(ReceiptLog(receipts=(_receipt(),), complete=True))
    seen = await stimuli.observe(SANDBOX, FakeStimulus(_result()), receiver=receiver, settle=0)  # type: ignore[arg-type]
    assert seen.on_wire is False
    assert seen.received is True
    problems = seen.contradictions()
    assert len(problems) == 2
    assert "blind to this path" in problems[0]
    assert "blind to the return path" in problems[1]
    assert "CONTRADICTION" in seen.describe()


@pytest.mark.parametrize(
    ("outcome", "stage", "contradiction"),
    [
        ("could_not_run", "socket", True),
        ("refused", "send", True),
        ("refused", "connect", False),  # a TCP RST follows a SYN that did leave
        ("refused", "receive", False),  # an ICMP error follows a datagram that did leave
    ],
)
@pytest.mark.asyncio
async def test_a_packet_on_the_wire_contradicts_a_probe_that_produced_none(
    capture: SimpleNamespace, outcome: Any, stage: Any, contradiction: bool
) -> None:
    capture.packets = [REQUEST]
    result = _result(outcome=outcome, stage=stage, reply=None, reply_source=None)
    seen = await stimuli.observe(SANDBOX, FakeStimulus(result), settle=0)  # type: ignore[arg-type]
    assert bool(seen.contradictions()) is contradiction


@pytest.mark.asyncio
async def test_observe_passes_identity_and_capture_options(capture: SimpleNamespace) -> None:
    from nse.models.process import ProcessIdentity

    stimulus = FakeStimulus(_result())
    identity = ProcessIdentity(uid=1000, gid=1000)
    await stimuli.observe(
        SANDBOX,
        stimulus,  # type: ignore[arg-type]
        identity=identity,
        iface="other",
        netns=None,
        capture_filter="udp",
        python="/usr/bin/python3",
        settle=0,
    )
    assert stimulus.calls == [{"identity": identity, "python": "/usr/bin/python3"}]
    assert capture.created == [{"iface": "other", "filter": "udp", "netns": None}]


@pytest.mark.asyncio
async def test_the_capture_is_stopped_even_if_the_stimulus_raises(
    capture: SimpleNamespace,
) -> None:
    class Exploding:
        async def run(self, sandbox: Any, **options: Any) -> StimulusResult:
            raise RuntimeError("boom")

    with pytest.raises(RuntimeError, match="boom"):
        await stimuli.observe(SANDBOX, Exploding(), settle=0)  # type: ignore[arg-type]
    assert capture.started == 1
    assert capture.reported == 1  # the capture thread does not outlive the failure


def test_result_descriptions_name_the_failure() -> None:
    result = _result(outcome="could_not_run", stage="socket", error="EPERM: x", reason="why")
    assert result.describe().endswith("could_not_run at socket (EPERM: x): why")
    assert str(Endpoint(address="::1", port=5)) == "[::1]:5"
    assert str(Endpoint(address="10.0.0.1", port=5)) == "10.0.0.1:5"


def test_one_capture_can_hold_a_probe_and_its_control() -> None:
    """Two stimuli in one window: each finds only its own packets."""
    other = "0123456789abcdef01234567"
    control = _result(probe_id=other, source=Endpoint(address="10.0.1.2", port=40001))
    control_request = Ether(
        bytes(
            Ether()
            / IP(src="10.0.1.2", dst="10.0.1.1")
            / UDP(sport=40001, dport=9999)
            / Raw(probe_packets.marker(other))
        )
    )
    window = [REQUEST, control_request, REPLY]
    assert stimuli.requests_in(_result(), window) == [REQUEST]
    assert stimuli.requests_in(control, window) == [control_request]
    assert stimuli.replies_in(_result(), window) == [REPLY]
    assert stimuli.replies_in(control, window) == []


# --------------------------------------------------------------------------- one window, a canary

CANARY = "cafecafecafecafecafecafe"


def _canary_result(**fields: Any) -> StimulusResult:
    base: dict[str, Any] = {
        "kind": "udp",
        "probe_id": CANARY,
        "destination": Endpoint(address="10.0.1.1", port=7777),
        "payload": probe_packets.marker(CANARY),
        "outcome": "sent",
        "reply": None,
        "reply_source": None,
    }
    base.update(fields)
    return _result(**base)


CANARY_PACKET = Ether(
    bytes(
        Ether()
        / IP(src="10.0.1.2", dst="10.0.1.1")
        / UDP(sport=40001, dport=7777)
        / Raw(probe_packets.marker(CANARY))
    )
)


@pytest.mark.asyncio
async def test_a_seen_canary_lets_an_absence_be_false(capture: SimpleNamespace) -> None:
    capture.packets = [CANARY_PACKET]
    canary = FakeStimulus(_canary_result())
    stimulus = FakeStimulus(_result(outcome="sent", reply=None))
    seen = await stimuli.observe(SANDBOX, stimulus, canary=canary, settle=0)  # type: ignore[arg-type]
    assert seen.on_wire is False
    assert seen.canary is not None
    assert seen.canary.on_wire is True
    assert "canary: seen" in seen.describe()


@pytest.mark.asyncio
async def test_an_unseen_canary_makes_every_absence_unknown(capture: SimpleNamespace) -> None:
    capture.packets = [REQUEST]  # the capture saw the stimulus but not the canary
    stimulus = FakeStimulus(_result(outcome="sent", reply=None))
    canary = FakeStimulus(_canary_result())
    window = await stimuli.observe_window(
        SANDBOX,  # type: ignore[arg-type]
        [
            stimulus,
            FakeStimulus(
                _result(
                    probe_id="1" * 24,
                    outcome="sent",
                    source=Endpoint(address="10.0.1.2", port=40002),
                )
            ),
        ],  # type: ignore[list-item]
        canary=canary,  # type: ignore[arg-type]
        identity=None,
        settle=0,
    )
    assert window.canary_seen is False
    assert not window.vouched
    assert not window.conclusive
    assert window[0].on_wire is True  # what was seen still counts
    assert window[1].on_wire is None  # but no absence is vouched for
    assert window[1].reply_on_wire is None
    assert len(window) == 2
    assert [o.result.probe_id for o in window] == [PROBE, "1" * 24]
    assert "canary: NOT seen" in window[1].describe()
    assert "vouched False" in window.describe()


@pytest.mark.asyncio
async def test_the_canary_runs_last_with_its_own_identity(capture: SimpleNamespace) -> None:
    order: list[str] = []

    class Recording(FakeStimulus):
        def __init__(self, name: str, result: StimulusResult) -> None:
            super().__init__(result)
            self.name = name

        async def run(self, sandbox: Any, **options: Any) -> StimulusResult:
            order.append(self.name)
            return await super().run(sandbox, **options)

    first, second = Recording("a", _result()), Recording("b", _result(probe_id="2" * 24))
    canary = Recording("canary", _canary_result())
    identity, other = object(), object()
    await stimuli.observe_window(
        SANDBOX,  # type: ignore[arg-type]
        [first, second],  # type: ignore[list-item]
        canary=canary,  # type: ignore[arg-type]
        identity=identity,  # type: ignore[arg-type]
        canary_identity=other,  # type: ignore[arg-type]
        settle=0,
    )
    assert order == ["a", "b", "canary"]
    assert first.calls[0]["identity"] is identity
    assert canary.calls[0]["identity"] is other
    assert capture.started == capture.reported == 1  # one window for all of them

    default = Recording("canary", _canary_result())
    await stimuli.observe(SANDBOX, first, canary=default, identity=identity, settle=0)  # type: ignore[arg-type]
    assert default.calls[0]["identity"] is identity


@pytest.mark.asyncio
async def test_a_window_collects_every_contradiction(capture: SimpleNamespace) -> None:
    receiver = FakeReceiver(ReceiptLog(receipts=(_receipt(),), complete=True))
    capture.packets = [CANARY_PACKET]
    window = await stimuli.observe_window(
        SANDBOX,  # type: ignore[arg-type]
        [FakeStimulus(_result())],  # type: ignore[list-item]
        canary=FakeStimulus(_canary_result()),  # type: ignore[arg-type]
        receiver=receiver,  # type: ignore[arg-type]
        settle=0,
    )
    assert window.vouched
    assert window.contradictions()[0].startswith(f"udp_round_trip {PROBE}: the receiver")
    assert not window.conclusive
    with pytest.raises(ValueError, match="at least one"):
        await stimuli.observe_window(SANDBOX, [], settle=0)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_without_a_canary_a_window_is_vouched_by_the_capture_alone(
    capture: SimpleNamespace,
) -> None:
    window = await stimuli.observe_window(
        SANDBOX,  # type: ignore[arg-type]
        [FakeStimulus(_result(outcome="sent", reply=None))],  # type: ignore[list-item]
        settle=0,
    )
    assert window.canary is None
    assert window.canary_seen is None
    assert window.vouched
    assert window.conclusive
    assert window[0].on_wire is False


DNAT_REQUEST = Ether(
    bytes(
        Ether()
        / IP(src="10.0.1.2", dst="192.0.2.9")
        / UDP(sport=40000, dport=5353)
        / Raw(probe_packets.marker(PROBE))
    )
)
DNAT_REPLY = Ether(
    bytes(
        Ether()
        / IP(src="192.0.2.9", dst="10.0.1.2")
        / UDP(sport=5353, dport=40000)
        / Raw(probe_packets.marker(PROBE))
    )
)


@pytest.mark.asyncio
async def test_nat_recognises_a_probe_whose_destination_was_rewritten(
    capture: SimpleNamespace,
) -> None:
    capture.packets = [DNAT_REQUEST, DNAT_REPLY]
    stimulus = FakeStimulus(_result())
    strict = await stimuli.observe(SANDBOX, stimulus, settle=0)  # type: ignore[arg-type]
    assert strict.on_wire is False  # 2.4.0 behaviour: the destination must match
    rewritten = await stimuli.observe(SANDBOX, stimulus, settle=0, nat=True)  # type: ignore[arg-type]
    assert rewritten.requests == (DNAT_REQUEST,)
    assert rewritten.replies == (DNAT_REPLY,)
    assert rewritten.requests[0][IP].dst == "192.0.2.9"  # where it really went
