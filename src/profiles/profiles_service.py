import math


def welford_update(mean: float, m2: float, n: int, new_value: float) -> tuple[float, float, int]:
    """
    Welford's online algorithm — update running mean and M2 with one new observation.

    Returns (new_mean, new_m2, new_n).

    Variance  = M2 / n          (population)
    Std dev   = sqrt(M2 / n)
    """
    n      += 1
    delta   = new_value - mean
    mean   += delta / n
    delta2  = new_value - mean
    m2     += delta * delta2
    return mean, m2, n


def safe_z_score(value: float, mean: float, m2: float, n: int) -> float:
    """
    Compute a z-score from Welford state.
    Returns 0.0 when there are fewer than 2 observations or std is negligible.
    """
    if n < 2:
        return 0.0
    std = math.sqrt(m2 / n)
    if std < 1e-9:
        return 0.0
    return (value - mean) / std


def normalize_z(z: float) -> float:
    """Clamp |z| to [0, 1]. |z| >= 3 maps to 1.0 (maximum deviation)."""
    return min(abs(z) / 3.0, 1.0)
