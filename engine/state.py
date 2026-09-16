from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Set, Optional
import threading


@dataclass
class MandateRollingState:
    mandate_id: str
    spent_this_month: float = 0.0
    count_this_month: int = 0
    used_nonces: Set[str] = field(default_factory=set)
    last_attempt_at: Optional[str] = None
    last_settled_at: Optional[str] = None


class MandateStateManager:
    """
    Thread-safe manager for rolling counters, budget depletion, and replay-protection nonces.
    """

    def __init__(self):
        self._states: Dict[str, MandateRollingState] = {}
        self._all_nonces: Set[str] = set()
        self._lock = threading.RLock()


    def get_state(self, mandate_id: str) -> MandateRollingState:
        with self._lock:
            if mandate_id not in self._states:
                self._states[mandate_id] = MandateRollingState(mandate_id=mandate_id)
            return self._states[mandate_id]

    def get_or_create_state(self, mandate_id: str) -> MandateRollingState:
        return self.get_state(mandate_id)

    def is_nonce_used(self, mandate_id: str, nonce: str) -> bool:
        with self._lock:
            if mandate_id not in self._states:
                return nonce in self._all_nonces
            return nonce in self._states[mandate_id].used_nonces or nonce in self._all_nonces

    def validate_nonce(self, nonce: str, mandate_id: Optional[str] = None) -> bool:
        """Returns True if nonce is fresh (not used before), False if it is a replay."""
        with self._lock:
            if nonce in self._all_nonces:
                return False
            if mandate_id and mandate_id in self._states and nonce in self._states[mandate_id].used_nonces:
                return False
            self._all_nonces.add(nonce)
            if mandate_id:
                if mandate_id not in self._states:
                    self._states[mandate_id] = MandateRollingState(mandate_id=mandate_id)
                self._states[mandate_id].used_nonces.add(nonce)
            return True

    def record_attempt(self, mandate_id: str, nonce: str) -> None:
        with self._lock:
            state = self.get_state(mandate_id)
            state.used_nonces.add(nonce)
            self._all_nonces.add(nonce)
            state.last_attempt_at = datetime.now(timezone.utc).isoformat()

    def record_successful_purchase(self, mandate_id: str, amount: float) -> None:
        with self._lock:
            state = self.get_state(mandate_id)
            state.spent_this_month += amount
            state.count_this_month += 1
            state.last_settled_at = datetime.now(timezone.utc).isoformat()

    def record_usage(self, mandate_id: str, amount: float, nonce: str) -> None:
        self.record_attempt(mandate_id, nonce)
        self.record_successful_purchase(mandate_id, amount)

    def reset_state(self, mandate_id: str) -> None:
        with self._lock:
            self._states[mandate_id] = MandateRollingState(mandate_id=mandate_id)


# Global singleton instance
state_manager = MandateStateManager()
