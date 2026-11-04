from __future__ import annotations

import unittest

from oc_rig.domain import (
    DispatchState,
    InvalidStateTransition,
    OperationState,
    require_transition,
)


class StateTransitionTests(unittest.TestCase):
    def test_valid_operation_transition(self) -> None:
        require_transition(OperationState.PENDING, OperationState.RUNNING)
        require_transition(OperationState.RUNNING, OperationState.WAITING)
        require_transition(OperationState.WAITING, OperationState.SUCCEEDED)

    def test_terminal_state_cannot_transition(self) -> None:
        with self.assertRaisesRegex(InvalidStateTransition, "succeeded -> running"):
            require_transition(OperationState.SUCCEEDED, OperationState.RUNNING)

    def test_state_families_cannot_be_mixed(self) -> None:
        with self.assertRaisesRegex(InvalidStateTransition, "OperationState"):
            require_transition(OperationState.PENDING, DispatchState.DISPATCHING)


if __name__ == "__main__":
    unittest.main()
