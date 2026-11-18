# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""
ExperimentReport: everything needed to reconstruct one NSE run from a CI artifact.

The report is split by reproducibility:

* ``input`` and ``environment`` are what was asked and where it ran. Two runs of
  the same request on the same host produce the same values here.
* ``result`` is what the run established: outcome, oracle status, the verdict
  per stimulus, errors by stage, and anything teardown left behind.
* ``observations`` is the evidence: trace events, canary attempts, processes,
  captures. It contains kernel trace ids, which differ on every run.
* ``run`` holds what is specific to this execution: identifiers, namespace and
  interface names, timestamps and phase durations.

The report states what NSE measured. It holds no expectation: whether those
verdicts are the right ones is the caller's judgement (the CLI records its own
next to it).
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterable
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, computed_field

from nse.models.artifacts import ArtifactEntry, artifact_entry, write_text_atomic
from nse.models.capture_report import CaptureReport
from nse.models.process import ProcessResult
from nse.models.test_request import TestRequest
from nse.models.trace_event import TraceEvent

SCHEMA = "nse.experiment-report"
SCHEMA_VERSION = 1

Outcome = Literal[
    "completed",  # every stage ran and the oracle confirmed it was observing throughout
    "rules_invalid",  # the ruleset was rejected before anything was measured
    "setup_failure",  # topology, listeners or monitor could not be prepared
    "instrument_failure",  # the oracle was blind, truncated or unhealthy: no evidence
    "execution_failure",  # injecting or collecting failed after the oracle was ready
    "timeout",  # the run exceeded the caller's deadline and was stopped
]
Stage = Literal[
    "setup", "listeners", "rules", "monitor", "readiness", "injection", "liveness", "collection",
    "teardown",
]  # fmt: skip
CanaryStatus = Literal["observed", "missed", "not_reached"]


def canonical_json(data: Any) -> str:
    """JSON with sorted keys and no insignificant whitespace: stable across runs."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


class ExperimentInput(BaseModel):
    """The request exactly as run, with content hashes to compare runs by."""

    model_config = ConfigDict(frozen=True)

    request: TestRequest
    rules_sha256: str = Field(description="SHA-256 of the ruleset text.")
    request_sha256: str = Field(description="SHA-256 of the canonical JSON of the request.")

    @classmethod
    def of(cls, request: TestRequest) -> ExperimentInput:
        return cls(
            request=request,
            rules_sha256=sha256_text(request.rules),
            request_sha256=sha256_text(canonical_json(request.model_dump(mode="json"))),
        )


class Environment(BaseModel):
    """Software and kernel the run used. ``None`` means unavailable, never guessed."""

    model_config = ConfigDict(frozen=True)

    nse: str
    python: str
    python_implementation: str
    dependencies: dict[str, str | None] = Field(description="Installed versions by package.")
    kernel: str = Field(description="uname release.")
    machine: str
    tools: dict[str, str | None] = Field(description="First line of each tool's version output.")
    use_nsenter: bool
    in_container: bool


class StageError(BaseModel):
    """An error, the stage it happened in, and its type."""

    model_config = ConfigDict(frozen=True)

    stage: Stage
    kind: str = Field(description="Exception class, or 'oracle' for an instrument check.")
    message: str


class PositiveControl(BaseModel):
    """A check the caller ran to show the instrument could see what was asserted."""

    model_config = ConfigDict(frozen=True)

    name: str
    passed: bool
    detail: str = ""


class OracleStatus(BaseModel):
    model_config = ConfigDict(frozen=True)

    readiness: CanaryStatus
    liveness: CanaryStatus
    errors: list[str] = Field(default_factory=list, description="Oracle errors, in order.")


class StimulusResult(BaseModel):
    """The verdicts observed for one requested packet."""

    model_config = ConfigDict(frozen=True)

    index: int = Field(description="Position in request.packets.")
    verdicts: list[str] = Field(
        description="Verdict of each trace attributed to this packet. Identical packets "
        "cannot be told apart and share their traces."
    )


class ExperimentResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    outcome: Outcome
    oracle: OracleStatus
    verdicts: list[str] = Field(
        description="One verdict per observed stimulus, in order: what the CLI compares."
    )
    stimuli: list[StimulusResult]
    errors: list[StageError] = Field(default_factory=list)
    teardown_complete: bool = Field(
        description="Teardown raised no error and left no resource of this run behind."
    )
    residual_resources: list[str] = Field(
        default_factory=list, description="Resources of this run still recorded after teardown."
    )
    controls: list[PositiveControl] = Field(default_factory=list)


class CanaryObservation(BaseModel):
    model_config = ConfigDict(frozen=True)

    status: CanaryStatus
    attempts: int
    trace_ids: list[str] = Field(default_factory=list)


class StimulusObservation(BaseModel):
    model_config = ConfigDict(frozen=True)

    index: int
    injected_at: float | None = Field(description="Unix time of injection; None if never sent.")
    trace_ids: list[str]


class Observations(BaseModel):
    model_config = ConfigDict(frozen=True)

    events: list[TraceEvent] = Field(description="Trace, conntrack and error events, no canaries.")
    canary_events: list[TraceEvent] = Field(default_factory=list)
    canaries: dict[str, CanaryObservation]
    stimuli: list[StimulusObservation]
    processes: list[ProcessResult] = Field(
        default_factory=list, description="NSE-managed processes, e.g. mock listeners."
    )
    captures: list[CaptureReport] = Field(default_factory=list)


class RunInfo(BaseModel):
    model_config = ConfigDict(frozen=True)

    test_id: str
    ownership_id: str
    namespaces: dict[str, str] = Field(description="Role -> namespace name.")
    interfaces: dict[str, str] = Field(description="Role -> interface name.")
    started_at: float
    ended_at: float
    phases: dict[str, float] = Field(description="Seconds spent per stage.")


class ExperimentReport(BaseModel):
    """The complete, serialisable record of one experiment. See the module docstring."""

    model_config = ConfigDict(frozen=True, populate_by_name=True)

    schema_name: str = Field(default=SCHEMA, alias="schema")
    schema_version: int = SCHEMA_VERSION
    input: ExperimentInput
    environment: Environment
    result: ExperimentResult
    observations: Observations
    run: RunInfo
    artifacts: list[ArtifactEntry] = Field(default_factory=list)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def measurement_valid(self) -> bool:
        """The run is evidence: it completed, cleaned up, and every attached
        instrument and positive control was sound. Says nothing about whether
        the verdicts are the expected ones."""
        return (
            self.result.outcome == "completed"
            and self.result.teardown_complete
            and all(control.passed for control in self.result.controls)
            and all(capture.instrument_healthy for capture in self.observations.captures)
        )

    def attach(
        self,
        *,
        captures: Iterable[CaptureReport] = (),
        controls: Iterable[PositiveControl] = (),
    ) -> ExperimentReport:
        """A copy with the caller's capture reports and positive controls linked in.

        Files the captures produced are hashed into :attr:`artifacts` now, so
        the report pins their content even if they change later.
        """
        captures, controls = list(captures), list(controls)
        artifacts = list(self.artifacts)
        known = {entry.path for entry in artifacts}
        for capture in captures:
            for path in capture.artifacts:
                if os.path.abspath(path) not in known and os.path.isfile(path):
                    entry = artifact_entry(path)
                    artifacts.append(entry)
                    known.add(entry.path)
        return self.model_copy(
            update={
                "observations": self.observations.model_copy(
                    update={"captures": [*self.observations.captures, *captures]}
                ),
                "result": self.result.model_copy(
                    update={"controls": [*self.result.controls, *controls]}
                ),
                "artifacts": artifacts,
            }
        )

    def to_json(self) -> str:
        """Indented JSON with sorted keys, so two reports diff cleanly."""
        data = self.model_dump(mode="json", by_alias=True)
        return json.dumps(data, sort_keys=True, indent=2, ensure_ascii=False) + "\n"

    def write(self, path: str | os.PathLike[str]) -> ArtifactEntry:
        """Write :meth:`to_json` atomically to *path*; return its hash entry."""
        return write_text_atomic(path, self.to_json())
