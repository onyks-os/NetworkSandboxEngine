# How-To: In-Process Integration with FastAPI & Web Applications

NSE v2.0.0 uses a single-process root architecture. This guide explains how to integrate NSE into a FastAPI or Svelte full-stack web application.

---

## FastAPI Lifespan & State Integration

Store the `NetnsController` instance in FastAPI `app.state` and clean up namespaces during application shutdown:

```python
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request
from nse.core.netns_controller import NetnsController, TestRun
from nse.core.pipeline import run_test_pipeline
from nse.models.test_request import TestRequest

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize controller and run startup sweep for orphan netns/veth links
    app.state.controller = NetnsController()
    app.state.runs = {}
    app.state.tasks = {}
    yield
    # Teardown pending tasks & clean remaining namespaces
    for task in app.state.tasks.values():
        if not task.done():
            task.cancel()
    app.state.controller.cleanup_all()

app = FastAPI(title="NSE Web Service", lifespan=lifespan)
```

---

## Non-Blocking Execution in Route Handlers

Enqueue test runs using `asyncio.create_task()`:

```python
@app.post("/api/test")
async def submit_test(request: TestRequest, req: Request):
    test_id = uuid.uuid4().hex[:12]
    controller: NetnsController = req.app.state.controller
    
    run = TestRun(test_id=test_id, netns_name=f"nse_{test_id}", request=request)
    req.app.state.runs[test_id] = run
    
    # Launch pipeline task in-process asynchronously
    task = asyncio.create_task(
        run_test_pipeline(request=request, controller=controller, run=run)
    )
    req.app.state.tasks[test_id] = task
    
    return {"test_id": test_id}
```

---

## WebSocket Event Streaming

Stream live `TraceEvent` objects to the browser:

```python
from fastapi import WebSocket, APIRouter

@app.websocket("/ws/{test_id}")
async def trace_stream(websocket: WebSocket, test_id: str):
    await websocket.accept()
    run: TestRun = websocket.app.state.runs.get(test_id)
    
    try:
        while True:
            event = await run.event_queue.get()
            if event is None:
                await websocket.send_json({"type": "done"})
                break
            await websocket.send_text(event.model_dump_json())
    finally:
        with contextlib.suppress(RuntimeError):
            await websocket.close()
```
