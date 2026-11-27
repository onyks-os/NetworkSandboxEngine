# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""Network Sandbox Engine: deterministic nftables testing in ephemeral netns."""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _version

from .core.netns_controller import NetnsController
from .core.process import IdentityError, ManagedProcess, ProcessExitedError, ProcessStartError
from .core.sniffer import CaptureError, CaptureStartError, CaptureStateError, PCAPAsserter
from .models.capture_report import (
    Beacon,
    BeaconSighting,
    CaptureLimits,
    CaptureReport,
    SenderClock,
)
from .models.clock import BootClock, ClockMap, MappedTime
from .models.experiment_report import ExperimentReport, PositiveControl
from .models.process import EffectiveIdentity, ProcessIdentity, ProcessResult
from .models.stimulus import Endpoint, Receipt, ReceiptLog, StimulusResult
from .models.stream import Correlation, Fate, Gap, StreamAttempt, StreamLog
from .receivers import Receiver, ReceiverSpec, ReceiverStartError
from .stimuli import Observation, Stimulus, Window, observe, observe_window
from .streams import RunningStream, StimulusStream, StreamStartError, correlate

try:
    # Read the version from installed metadata rather than restating it here.
    # A hardcoded literal drifts from pyproject.toml silently: this constant
    # still said 2.0.0 while the package was being built as 2.1.0.
    __version__ = _version("network-sandbox-engine")
except PackageNotFoundError:  # pragma: no cover - running from a bare checkout
    __version__ = "0.0.0.dev0"

__all__ = [
    "Beacon",
    "BeaconSighting",
    "BootClock",
    "CaptureError",
    "CaptureLimits",
    "CaptureReport",
    "CaptureStartError",
    "CaptureStateError",
    "ClockMap",
    "Correlation",
    "EffectiveIdentity",
    "Endpoint",
    "ExperimentReport",
    "Fate",
    "Gap",
    "IdentityError",
    "ManagedProcess",
    "MappedTime",
    "NetnsController",
    "Observation",
    "PCAPAsserter",
    "PositiveControl",
    "ProcessExitedError",
    "ProcessIdentity",
    "ProcessResult",
    "ProcessStartError",
    "Receipt",
    "ReceiptLog",
    "Receiver",
    "ReceiverSpec",
    "ReceiverStartError",
    "RunningStream",
    "SenderClock",
    "Stimulus",
    "StimulusResult",
    "StimulusStream",
    "StreamAttempt",
    "StreamLog",
    "StreamStartError",
    "Window",
    "__version__",
    "correlate",
    "observe",
    "observe_window",
]
