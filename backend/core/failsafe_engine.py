from backend.db.database import get_state, set_state


def is_enabled() -> bool:
    return get_state("failsafe_enabled", "false") == "true"


def set_enabled(enabled: bool) -> bool:
    set_state("failsafe_enabled", "true" if enabled else "false")
    return enabled