"""Cancellation cannot race a worker that is still mutating the topology."""

from __future__ import annotations

import asyncio
import threading

import pytest

from nse.core.async_work import finish_work, run_blocking


@pytest.mark.asyncio
@pytest.mark.parametrize("worker_fails", [False, True])
async def test_repeated_cancellation_waits_for_the_worker(worker_fails: bool) -> None:
    entered, release = threading.Event(), threading.Event()
    loop = asyncio.get_running_loop()
    arrived = asyncio.Event()
    finished = []

    def worker() -> None:
        entered.set()
        loop.call_soon_threadsafe(arrived.set)
        assert release.wait(5)
        finished.append("worker finished")
        if worker_fails:
            raise RuntimeError("late failure")

    task = asyncio.create_task(run_blocking(worker))
    await asyncio.wait_for(arrived.wait(), 5)
    try:
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()
        await asyncio.sleep(0)
        assert entered.is_set()
        assert not task.done()
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 5)
    assert finished == ["worker finished"]


@pytest.mark.asyncio
async def test_worker_result_and_failure_propagate() -> None:
    assert await run_blocking(lambda *, value: value, value=42) == 42

    def fail() -> None:
        raise ValueError("worker error")

    with pytest.raises(ValueError, match="worker error"):
        await run_blocking(fail)


@pytest.mark.asyncio
async def test_work_that_cancels_itself_is_not_retried() -> None:
    async def cancel() -> None:
        raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await finish_work(cancel())
