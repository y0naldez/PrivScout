from __future__ import annotations

from collections.abc import Callable


ProgressCallback = Callable[[str, str, int | None, int | None], None]


def report(
    callback: ProgressCallback | None,
    source: str,
    phase: str,
    completed: int | None = None,
    total: int | None = None,
) -> None:
    if callback is not None:
        callback(source, phase, completed, total)

