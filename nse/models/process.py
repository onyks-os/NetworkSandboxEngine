# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""
Identity and results of application processes run inside a namespace.

:class:`ProcessIdentity` is what the caller asks for; :class:`EffectiveIdentity`
is what the kernel reported for the process itself, read before the application
was allowed to start; :class:`ProcessResult` is how the process ended.
"""

from __future__ import annotations

import subprocess
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator, model_validator

#: Linux capability names by bit number (include/uapi/linux/capability.h).
CAPABILITIES: tuple[str, ...] = (
    "chown",
    "dac_override",
    "dac_read_search",
    "fowner",
    "fsetid",
    "kill",
    "setgid",
    "setuid",
    "setpcap",
    "linux_immutable",
    "net_bind_service",
    "net_broadcast",
    "net_admin",
    "net_raw",
    "ipc_lock",
    "ipc_owner",
    "sys_module",
    "sys_rawio",
    "sys_chroot",
    "sys_ptrace",
    "sys_pacct",
    "sys_admin",
    "sys_boot",
    "sys_nice",
    "sys_resource",
    "sys_time",
    "sys_tty_config",
    "mknod",
    "lease",
    "audit_write",
    "audit_control",
    "setfcap",
    "mac_override",
    "mac_admin",
    "syslog",
    "wake_alarm",
    "block_suspend",
    "audit_read",
    "perfmon",
    "bpf",
    "checkpoint_restore",
)

Termination = Literal[
    "exited",  # the process ended on its own
    "timeout",  # wait(timeout) expired; NSE stopped the process
    "cancelled",  # the awaiting task was cancelled; NSE stopped the process
    "terminated",  # terminate() was called while the process was running
]


def capability_names(mask: int) -> tuple[str, ...]:
    """Names of the capabilities set in a /proc ``Cap*`` bit mask."""
    return tuple(
        CAPABILITIES[bit] if bit < len(CAPABILITIES) else f"cap_{bit}"
        for bit in range(mask.bit_length())
        if mask >> bit & 1
    )


class ProcessIdentity(BaseModel):
    """The identity a process must run with. Every field defaults to "unchanged".

    The namespace is always entered with NSE's privileges first; the identity is
    applied afterwards, before the application starts, and verified. If any part
    cannot be applied the process is not started: there is no fallback to root.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    uid: int | None = Field(default=None, ge=0, description="Real, effective and saved UID.")
    gid: int | None = Field(
        default=None,
        ge=0,
        description="Real, effective and saved GID. Required with a non-root uid, so a "
        "process never keeps the root group by omission.",
    )
    groups: tuple[int, ...] | None = Field(
        default=None,
        description="Supplementary groups. None keeps them unless uid or gid is set, in "
        "which case they are cleared; () clears them explicitly.",
    )
    # set is accepted for convenience; the validator always stores a frozenset.
    capabilities: frozenset[str] | set[str] | None = Field(
        default=None,
        description="Exactly the capabilities the process keeps: effective, permitted, "
        "ambient and bounding set. None leaves the kernel default: all for root, none "
        "for any other uid. Names as in capabilities(7), with or without 'CAP_'.",
    )
    no_new_privileges: bool = Field(
        default=False, description="Set no_new_privs: setuid binaries cannot gain privileges."
    )

    @field_validator("groups")
    @classmethod
    def _valid_groups(cls, groups: tuple[int, ...] | None) -> tuple[int, ...] | None:
        if groups is not None and any(group < 0 for group in groups):
            raise ValueError("group ids must be non-negative")
        return None if groups is None else tuple(sorted(set(groups)))

    @field_validator("capabilities", mode="before")
    @classmethod
    def _normalise_capabilities(cls, value: object) -> object:
        if value is None:
            return None
        if isinstance(value, str):
            raise ValueError("capabilities must be a collection of names, not one string")
        names = set()
        for raw in value:  # type: ignore[attr-defined]
            if not isinstance(raw, str):
                raise ValueError(f"capability {raw!r} is not a name")
            name = raw.lower().removeprefix("cap_")
            if name not in CAPABILITIES:
                raise ValueError(f"unknown capability {raw!r}")
            names.add(name)
        return frozenset(names)

    @model_validator(mode="after")
    def _gid_with_uid(self) -> ProcessIdentity:
        if self.uid not in (None, 0) and self.gid is None:
            raise ValueError("a non-root uid needs an explicit gid")
        return self

    @property
    def requested(self) -> bool:
        """True when anything differs from "unchanged"."""
        return self != ProcessIdentity()

    @property
    def effective_groups(self) -> tuple[int, ...] | None:
        """The supplementary groups the process must end up with, if determined."""
        if self.groups is not None:
            return self.groups
        if self.uid is not None or self.gid is not None:
            return ()
        return None


class EffectiveIdentity(BaseModel):
    """The identity the kernel reported for the process, before the application ran."""

    model_config = ConfigDict(frozen=True)

    uids: tuple[int, int, int, int] = Field(description="Real, effective, saved, filesystem.")
    gids: tuple[int, int, int, int] = Field(description="Real, effective, saved, filesystem.")
    groups: tuple[int, ...]
    capabilities_effective: tuple[str, ...]
    capabilities_permitted: tuple[str, ...]
    capabilities_inheritable: tuple[str, ...]
    capabilities_ambient: tuple[str, ...]
    capabilities_bounding: tuple[str, ...]
    no_new_privileges: bool

    @classmethod
    def from_status(cls, text: str) -> EffectiveIdentity:
        """Parse ``/proc/<pid>/status``; raise ``ValueError`` if a field is missing."""
        fields: dict[str, str] = {}
        for line in text.splitlines():
            key, _, value = line.partition(":")
            fields[key.strip()] = value.strip()

        def ids(key: str) -> tuple[int, int, int, int]:
            values = tuple(int(part) for part in fields[key].split())
            if len(values) != 4:
                raise ValueError(f"{key}: expected 4 ids, got {fields[key]!r}")
            return values

        def caps(key: str) -> tuple[str, ...]:
            return capability_names(int(fields[key], 16))

        try:
            return cls(
                uids=ids("Uid"),
                gids=ids("Gid"),
                groups=tuple(sorted(int(g) for g in fields["Groups"].split())),
                capabilities_effective=caps("CapEff"),
                capabilities_permitted=caps("CapPrm"),
                capabilities_inheritable=caps("CapInh"),
                capabilities_ambient=caps("CapAmb"),
                capabilities_bounding=caps("CapBnd"),
                no_new_privileges=fields.get("NoNewPrivs", "0") == "1",
            )
        except KeyError as missing:
            raise ValueError(f"process status lacks {missing}") from None

    def mismatches(self, requested: ProcessIdentity) -> list[str]:
        """Every way this identity differs from *requested*; empty when it matches."""
        problems = []
        if requested.uid is not None and set(self.uids) != {requested.uid}:
            problems.append(f"uids {self.uids} != {requested.uid}")
        if requested.gid is not None and set(self.gids) != {requested.gid}:
            problems.append(f"gids {self.gids} != {requested.gid}")
        groups = requested.effective_groups
        if groups is not None and self.groups != groups:
            problems.append(f"groups {self.groups} != {groups}")
        if requested.capabilities is not None:
            wanted = tuple(sorted(requested.capabilities, key=CAPABILITIES.index))
            for label, actual in (
                ("effective", self.capabilities_effective),
                ("permitted", self.capabilities_permitted),
                ("ambient", self.capabilities_ambient),
                ("bounding", self.capabilities_bounding),
            ):
                if actual != wanted:
                    problems.append(f"{label} capabilities {actual} != {wanted}")
        elif 0 not in self.uids and (self.capabilities_effective or self.capabilities_permitted):
            # A non-root process asked for no capabilities must not hold any.
            problems.append(f"non-root process holds capabilities {self.capabilities_permitted}")
        if requested.no_new_privileges and not self.no_new_privileges:
            problems.append("no_new_privs is not set")
        return problems


class ProcessResult(BaseModel):
    """How a managed process ended, with its verified identity and its output."""

    model_config = ConfigDict(frozen=True, ser_json_bytes="base64")

    argv: list[str] = Field(description="The application's argv, as requested.")
    command: list[str] = Field(description="The full command line, launch chain included.")
    pid: int
    identity: EffectiveIdentity
    termination: Termination
    returncode: int = Field(description="Exit status; negative for a signal, as in subprocess.")
    started_at: float = Field(description="Unix time the application was allowed to start.")
    ended_at: float
    stdout: bytes | None = Field(default=None, description="Captured stdout, up to the limit.")
    stderr: bytes | None = Field(default=None, description="Captured stderr, up to the limit.")
    stdout_path: str | None = Field(default=None, description="File stdout was written to.")
    stderr_path: str | None = Field(default=None, description="File stderr was written to.")
    stdout_dropped: int = Field(default=0, description="Captured bytes discarded at the limit.")
    stderr_dropped: int = Field(default=0, description="Captured bytes discarded at the limit.")
    output_complete: bool = Field(
        default=True,
        description="False when a captured stream was still held open (e.g. by a "
        "descendant) after the process ended, so reading it was abandoned.",
    )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def ok(self) -> bool:
        """The process ended on its own with status 0."""
        return self.termination == "exited" and self.returncode == 0

    def check(self) -> ProcessResult:
        """Return self if :attr:`ok`; otherwise raise ``subprocess.CalledProcessError``."""
        if not self.ok:
            raise subprocess.CalledProcessError(
                self.returncode, self.argv, output=self.stdout, stderr=self.stderr
            )
        return self
