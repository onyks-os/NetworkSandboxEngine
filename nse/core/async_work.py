"""Finish work already dispatched to a thread before propagating cancellation."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from functools import partial
from typing import ParamSpec, TypeVar

P = ParamSpec("P")
T = TypeVar("T")


async def finish_work(work: Awaitable[T]) -> T:
    task = asyncio.ensure_future(work)
    cancelled = False
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            if task.cancelled():
                raise
            cancelled = True
        except Exception:
            if not cancelled:
                raise
    if cancelled:
        # Retrieve any worker exception as well: the caller's finally block
        # will clean its registered resources before cancellation leaves it.
        if not task.cancelled():
            task.exception()
        raise asyncio.CancelledError
    return task.result()


async def run_blocking(function: Callable[P, T], *args: P.args, **kwargs: P.kwargs) -> T:
    return await finish_work(
        asyncio.get_running_loop().run_in_executor(None, partial(function, *args, **kwargs))
    )
