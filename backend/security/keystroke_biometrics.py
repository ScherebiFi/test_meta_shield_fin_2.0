from __future__ import annotations

import statistics


def similarity(reference_intervals: list[float], observed_intervals: list[float]) -> float:
    if len(reference_intervals) < 3 or len(observed_intervals) < 3:
        return 0.0
    reference_mean = statistics.fmean(reference_intervals)
    observed_mean = statistics.fmean(observed_intervals)
    if reference_mean <= 0 or observed_mean <= 0:
        return 0.0
    relative_difference = abs(reference_mean - observed_mean) / reference_mean
    return round(max(0.0, min(1.0, 1.0 - relative_difference)), 4)