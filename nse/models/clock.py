# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""
Placing a sender's clock on a capture's clock, from clocked beacons.

A stream that runs elsewhere, in a VM for instance, logs its attempts on that
machine's clocks. A capture written by someone else, for instance QEMU, has
its own. A clocked beacon is seen in the capture at a known capture time, and
it carries the sender's ``CLOCK_BOOTTIME`` read just before and just after it
was sent. Each beacon gives the offset between the two clocks to within that
before/after bracket. :class:`ClockMap` combines them, one boot at a time.

``CLOCK_BOOTTIME`` is used rather than ``CLOCK_MONOTONIC`` because it keeps
counting while the machine is suspended, as the capturing host's clock does.
A reboot starts both clocks again, so a mapping is only valid for the boot
its beacons came from.

The map never guesses. A time is mapped only when the boot has a mapping and
the time lies between that boot's first and last beacon; anything else is
``None``. In particular, a boot with a single beacon maps only the instant
of that beacon.
"""

from __future__ import annotations

from collections.abc import Iterable

from pydantic import BaseModel, ConfigDict, Field

from nse.models.capture_report import BeaconSighting


class MappedTime(BaseModel):
    """A time on the capture's clock, and how far from the truth it may be."""

    model_config = ConfigDict(frozen=True)

    time: float = Field(description="Seconds on the capture's clock.")
    uncertainty: float = Field(ge=0, description="The truth is within this many seconds.")


class BootClock(BaseModel):
    """The offset from one boot's CLOCK_BOOTTIME to the capture's clock."""

    model_config = ConfigDict(frozen=True)

    boot_id: str
    offset: float = Field(description="capture time = boottime + offset.")
    uncertainty: float = Field(
        ge=0,
        description="The widest before/after bracket of a beacon, plus the spread between "
        "the offsets the beacons give.",
    )
    beacons: int = Field(ge=1, description="Bracketed beacons this offset rests on.")
    first_boottime: float = Field(description="CLOCK_BOOTTIME just before the first beacon.")
    last_boottime: float = Field(description="CLOCK_BOOTTIME just after the last beacon.")

    def covers(self, boottime: float) -> bool:
        """*boottime* lies between this boot's first and last beacon."""
        return self.first_boottime <= boottime <= self.last_boottime


class ClockMap(BaseModel):
    """Offsets from each sender boot's clock to the capture's clock."""

    model_config = ConfigDict(frozen=True)

    boots: tuple[BootClock, ...] = ()
    problems: tuple[str, ...] = Field(
        default=(), description="Beacons that could not be used, and boots mapped only weakly."
    )

    @classmethod
    def from_beacons(cls, sightings: Iterable[BeaconSighting]) -> ClockMap:
        """The map the clocked beacons among *sightings* support.

        A beacon is used only when its follow-up was seen too, so that its
        sending time is bracketed. For each boot, the offset is the midpoint of
        the range the beacons give, and its uncertainty is the widest bracket
        plus the spread of the beacons' offsets.
        """
        problems: list[str] = []
        by_boot: dict[str, list[tuple[float, float, float]]] = {}
        for sighting in sightings:
            clock = sighting.clock
            if clock is None:
                problems.append(f"beacon {sighting.label!r} carries no clock")
                continue
            if clock.boottime_after is None:
                problems.append(
                    f"beacon {sighting.label!r}: its follow-up was not seen, so its sending "
                    "time is not bracketed"
                )
                continue
            before, after = clock.boottime_before, clock.boottime_after
            if after < before:
                problems.append(f"beacon {sighting.label!r}: its clock ran backwards")
                continue
            by_boot.setdefault(clock.boot_id, []).append((sighting.seen_at, before, after))
        boots = []
        for boot_id, beacons in by_boot.items():
            offsets = [seen - (before + after) / 2 for seen, before, after in beacons]
            bracket = max(after - before for _, before, after in beacons)
            spread = max(offsets) - min(offsets)
            if len(beacons) == 1:
                problems.append(
                    f"boot {boot_id[:8]}: a single beacon, so the map covers only its instant"
                )
            boots.append(
                BootClock(
                    boot_id=boot_id,
                    offset=(max(offsets) + min(offsets)) / 2,
                    uncertainty=bracket + spread,
                    beacons=len(beacons),
                    first_boottime=min(before for _, before, _ in beacons),
                    last_boottime=max(after for _, _, after in beacons),
                )
            )
        return cls(boots=tuple(boots), problems=tuple(problems))

    def boot(self, boot_id: str | None) -> BootClock | None:
        """The mapping for *boot_id*, or None."""
        for boot in self.boots:
            if boot.boot_id == boot_id:
                return boot
        return None

    def to_capture(self, boot_id: str | None, boottime: float | None) -> MappedTime | None:
        """*boottime* of boot *boot_id* on the capture's clock; None if it cannot be placed."""
        boot = self.boot(boot_id)
        if boot is None or boottime is None or not boot.covers(boottime):
            return None
        return MappedTime(time=boottime + boot.offset, uncertainty=boot.uncertainty)
