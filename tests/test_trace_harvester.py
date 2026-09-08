# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""
Unit tests for the trace harvester: the module that decides what the oracle saw.

The read loop is driven with a fake subprocess so every terminal state can be
provoked without root: a clean stop, a monitor that dies on its own, a deadline
that expires, and a crash. Each one used to be reported through the same
sentinel, making them indistinguishable to the caller.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from nse.core.trace_harvester import (
    HarvestState,
    TraceHarvester,
)
from nse.models.trace_event import TraceEvent

pytestmark = pytest.mark.asyncio


class FakeStdout:
    """An asyncio.StreamReader stand-in that yields prepared lines then blocks."""

    def __init__(self, lines: list[bytes], hang_after: bool = False) -> None:
        self._lines = list(lines)
        self._hang_after = hang_after

    async def readline(self) -> bytes:
        if self._lines:
            return self._lines.pop(0)
        if self._hang_after:
            await asyncio.sleep(3600)
        return b""  # EOF


class FakeProc:
    def __init__(self, stdout: Any) -> None:
        self.stdout = stdout
        self.returncode: int | None = None
        self.terminated = False

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = -15


async def start_with(
    lines: list[bytes], hang_after: bool = False, timeout: float = 5.0
) -> tuple[TraceHarvester, asyncio.Queue[TraceEvent | None], FakeProc]:
    """Start a harvester whose `nft monitor trace` is a canned stream."""
    proc = FakeProc(FakeStdout(lines, hang_after=hang_after))
    queue: asyncio.Queue[TraceEvent | None] = asyncio.Queue()
    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
        harvester = TraceHarvester()
        await harvester.start(netns_name="nse_test", queue=queue, timeout=timeout)
    return harvester, queue, proc


async def drain(queue: asyncio.Queue[TraceEvent | None]) -> list[TraceEvent]:
    events: list[TraceEvent] = []
    while True:
        item = await asyncio.wait_for(queue.get(), timeout=2.0)
        if item is None:
            return events
        events.append(item)


ACCEPT_STREAM = [
    b'trace id aaaa ip filter input packet: iif "veth0"\n',
    b"trace id aaaa ip filter input verdict accept\n",
]


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


async def test_parses_a_stream_and_ends_cleanly() -> None:
    harvester, queue, _ = await start_with(ACCEPT_STREAM)
    events = await drain(queue)
    assert [e.type for e in events] == ["hook", "verdict"]
    assert harvester.seen_trace_ids == ["aaaa"]
    assert harvester.unparsed_trace_lines == 0


async def test_on_event_callback_receives_every_event() -> None:
    seen: list[TraceEvent] = []
    proc = FakeProc(FakeStdout(ACCEPT_STREAM))
    queue: asyncio.Queue[TraceEvent | None] = asyncio.Queue()
    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
        harvester = TraceHarvester()
        await harvester.start(netns_name="nse_test", queue=queue, timeout=5.0, on_event=seen.append)
    await drain(queue)
    assert len(seen) == 2
    assert harvester.state is HarvestState.CLEAN_EOF


async def test_wait_ready_returns_true_once_the_loop_runs() -> None:
    harvester, queue, _ = await start_with(ACCEPT_STREAM)
    assert await harvester.wait_ready(timeout=1.0) is True
    await drain(queue)


async def test_wait_for_event_is_true_only_after_a_real_event() -> None:
    """
    The property the old readiness probe did not have: this waits for the kernel
    to actually deliver something, not for a coroutine to be scheduled.
    """
    harvester, _, _ = await start_with(ACCEPT_STREAM, hang_after=True, timeout=5.0)
    assert await harvester.wait_for_event(timeout=1.0) is True
    await harvester.aclose()


async def test_wait_for_event_is_false_when_nothing_arrives() -> None:
    harvester, _, _ = await start_with([], hang_after=True, timeout=5.0)
    assert await harvester.wait_for_event(timeout=0.2) is False
    await harvester.aclose()


async def test_arm_event_signal_requires_a_new_event() -> None:
    harvester, _, _ = await start_with(ACCEPT_STREAM, hang_after=True)
    assert await harvester.wait_for_event(timeout=1.0) is True
    harvester.arm_event_signal()
    assert await harvester.wait_for_event(timeout=0.2) is False
    await harvester.aclose()


# ---------------------------------------------------------------------------
# Terminal states — each used to look identical to the caller
# ---------------------------------------------------------------------------


async def test_state_is_stopped_when_we_asked_it_to_stop() -> None:
    harvester, _, proc = await start_with([], hang_after=True, timeout=10.0)
    await harvester.wait_ready(timeout=1.0)
    state = await harvester.aclose(timeout=1.0)
    assert state is HarvestState.STOPPED
    assert proc.terminated is True
    assert harvester.health_errors() == []


async def test_state_is_clean_eof_when_the_monitor_dies_on_its_own() -> None:
    """`nft monitor trace` exiting by itself means the oracle went blind."""
    harvester, queue, _ = await start_with([])
    await drain(queue)
    assert harvester.state is HarvestState.CLEAN_EOF
    assert any("exited on its own" in p for p in harvester.health_errors())


async def test_state_is_timeout_when_the_deadline_expires() -> None:
    harvester, queue, _ = await start_with([], hang_after=True, timeout=0.2)
    await drain(queue)
    assert harvester.state is HarvestState.TIMEOUT
    assert any("timed out" in p for p in harvester.health_errors())


async def test_state_is_error_when_the_read_loop_raises() -> None:
    proc = FakeProc(MagicMock())
    proc.stdout.readline = AsyncMock(side_effect=OSError("pipe went away"))
    queue: asyncio.Queue[TraceEvent | None] = asyncio.Queue()
    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
        harvester = TraceHarvester()
        await harvester.start(netns_name="nse_test", queue=queue, timeout=5.0)
    await drain(queue)
    assert harvester.state is HarvestState.ERROR
    assert isinstance(harvester.error, OSError)
    assert any("crashed" in p for p in harvester.health_errors())


async def test_not_started_is_reported_as_a_health_error() -> None:
    harvester = TraceHarvester()
    assert harvester.state is HarvestState.NOT_STARTED
    assert any("never started" in p for p in harvester.health_errors())


# ---------------------------------------------------------------------------
# Deadline
# ---------------------------------------------------------------------------


async def test_extend_deadline_keeps_the_loop_alive() -> None:
    """
    A fixed deadline used to expire mid-injection on long packet sequences,
    truncating the verdict stream with no error.
    """
    harvester, _, _ = await start_with([], hang_after=True, timeout=0.3)
    await harvester.wait_ready(timeout=1.0)
    for _ in range(4):
        harvester.extend_deadline(0.3)
        await asyncio.sleep(0.15)
    assert harvester.state is HarvestState.RUNNING
    assert await harvester.aclose(timeout=1.0) is HarvestState.STOPPED


async def test_extend_deadline_never_moves_the_deadline_backwards() -> None:
    harvester, _, _ = await start_with([], hang_after=True, timeout=10.0)
    await harvester.wait_ready(timeout=1.0)
    far = harvester._deadline
    harvester.extend_deadline(0.01)
    assert harvester._deadline == far
    await harvester.aclose()


# ---------------------------------------------------------------------------
# Unparsed lines — a format change must be loud
# ---------------------------------------------------------------------------


async def test_unparsed_trace_lines_are_counted_and_reported() -> None:
    stream = [
        b"trace id bbbb ip filter input somethingnobodyparsed 42\n",
        b"trace id bbbb ip filter input alsoweird\n",
    ]
    harvester, queue, _ = await start_with(stream)
    await drain(queue)
    assert harvester.unparsed_trace_lines == 2
    problems = harvester.health_errors()
    assert any("could not be parsed" in p for p in problems)
    assert any("somethingnobodyparsed" in p for p in problems)


async def test_non_trace_noise_is_not_an_oracle_error() -> None:
    stream = [b"some banner from nft\n", *ACCEPT_STREAM]
    harvester, queue, _ = await start_with(stream)
    await drain(queue)
    assert harvester.unparsed_other_lines == 1
    assert harvester.unparsed_trace_lines == 0
    assert not any("could not be parsed" in p for p in harvester.health_errors())


async def test_blank_lines_are_ignored() -> None:
    harvester, queue, _ = await start_with([b"\n", b"   \n", *ACCEPT_STREAM])
    events = await drain(queue)
    assert len(events) == 2
    assert harvester.unparsed_other_lines == 0


async def test_force_blind_makes_every_line_unparsed(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    NSE_FORCE_BLIND simulates a kernel format change. The harvester must notice,
    not shrug: this is what the blindness meta-test in CI relies on.
    """
    monkeypatch.setenv("NSE_FORCE_BLIND", "1")
    harvester, queue, _ = await start_with(ACCEPT_STREAM)
    events = await drain(queue)
    assert events == []
    assert harvester.unparsed_trace_lines == 2
    assert harvester.health_errors()


# ---------------------------------------------------------------------------
# Remaining lifecycle paths
# ---------------------------------------------------------------------------


async def test_wait_ready_times_out_when_the_loop_never_runs() -> None:
    harvester = TraceHarvester()
    assert await harvester.wait_ready(timeout=0.05) is False


async def test_start_uses_nsenter_in_containers() -> None:
    proc = FakeProc(FakeStdout([], hang_after=True))
    queue: asyncio.Queue[TraceEvent | None] = asyncio.Queue()
    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)) as spawn:
        harvester = TraceHarvester()
        await harvester.start(netns_name="nse_x", queue=queue, timeout=5.0, use_nsenter=True)
        await harvester.aclose()
    assert spawn.call_args[0][0] == "nsenter"


async def test_start_uses_ip_netns_exec_by_default() -> None:
    proc = FakeProc(FakeStdout([], hang_after=True))
    queue: asyncio.Queue[TraceEvent | None] = asyncio.Queue()
    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)) as spawn:
        harvester = TraceHarvester()
        await harvester.start(netns_name="nse_x", queue=queue, timeout=5.0)
        await harvester.aclose()
    assert spawn.call_args[0][:4] == ("ip", "netns", "exec", "nse_x")


async def test_aclose_cancels_a_read_loop_that_will_not_finish() -> None:
    """A monitor whose stdout never closes must not hang the whole run."""

    class NeverCloses:
        async def readline(self) -> bytes:
            await asyncio.sleep(3600)
            return b""

    proc = FakeProc(NeverCloses())
    proc.terminate = lambda: None  # type: ignore[method-assign]
    queue: asyncio.Queue[TraceEvent | None] = asyncio.Queue()
    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
        harvester = TraceHarvester()
        await harvester.start(netns_name="nse_x", queue=queue, timeout=60.0)
        await harvester.wait_ready(timeout=1.0)
        state = await harvester.aclose(timeout=0.2)
    assert state is HarvestState.STOPPED


async def test_aclose_is_idempotent() -> None:
    harvester, _, _ = await start_with([], hang_after=True)
    await harvester.wait_ready(timeout=1.0)
    assert await harvester.aclose(timeout=1.0) is HarvestState.STOPPED
    assert await harvester.aclose(timeout=1.0) is HarvestState.STOPPED


async def test_stop_on_an_unstarted_harvester_is_safe() -> None:
    TraceHarvester().stop()


async def test_seen_trace_ids_are_deduplicated_in_order() -> None:
    stream = [
        b"trace id aaaa ip filter input packet: iif veth0\n",
        b"trace id aaaa ip filter input verdict accept\n",
        b"trace id bbbb ip filter input packet: iif veth0\n",
        b"trace id aaaa ip filter output verdict accept\n",
    ]
    harvester, queue, _ = await start_with(stream)
    await drain(queue)
    assert harvester.seen_trace_ids == ["aaaa", "bbbb"]


async def test_unparsed_samples_are_capped() -> None:
    stream = [f"trace id cccc ip filter input weird{i}\n".encode() for i in range(12)]
    harvester, queue, _ = await start_with(stream)
    await drain(queue)
    assert harvester.unparsed_trace_lines == 12
    assert len(harvester.unparsed_samples) == 5
