"""Live three-SDK enrollment state/provider boundary interoperability gate."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT / "python/src"))

from acp.security_enrollment import (  # noqa: E402
    CandidateEnrollment,
    CommissionerEnrollment,
    CommissionerState,
    EnrollmentLimits,
)
from acp.security_models import EnrollmentAttemptID, EnrollmentID, SecuritySuite  # noqa: E402


class Confirmation:
    def receive_peer_share(self, share: bytes) -> bytes:
        return share

    def verify_confirmation(self, value: bytes) -> bool:
        return value == b"valid"


def python_pair() -> dict[str, str]:
    enrollment = EnrollmentID("50617283-94a5-4b6c-9a4b-5c6d7e8f90a1")
    attempt = EnrollmentAttemptID("60718293-a4b5-4c6d-aa5b-6c7d8e9fa0b1")
    candidate = CandidateEnrollment(enrollment, frozenset({SecuritySuite.RAW128}), EnrollmentLimits(2), 0)
    candidate.begin(attempt, SecuritySuite.RAW128, 1)
    candidate.process_peer_share(attempt, Confirmation(), b"share", 2)
    candidate.verify_key_confirmation(attempt, Confirmation(), b"valid", 2)
    candidate.await_approval(attempt, 3)
    candidate.credential_staged(attempt, 4)
    candidate.durable_install_verified(attempt, 5)
    candidate.complete(attempt, 6)
    commissioner = CommissionerEnrollment(enrollment, attempt, 100)
    for expected, target in [
        (CommissionerState.IDLE, CommissionerState.CANDIDATE_SELECTED),
        (CommissionerState.CANDIDATE_SELECTED, CommissionerState.SECRET_ACQUIRED),
        (CommissionerState.SECRET_ACQUIRED, CommissionerState.NEGOTIATING),
        (CommissionerState.NEGOTIATING, CommissionerState.KEY_CONFIRMED),
        (CommissionerState.KEY_CONFIRMED, CommissionerState.AWAITING_OPERATOR_APPROVAL),
        (CommissionerState.AWAITING_OPERATOR_APPROVAL, CommissionerState.ISSUING_CREDENTIAL),
        (CommissionerState.ISSUING_CREDENTIAL, CommissionerState.AWAITING_INSTALL_RECEIPT),
    ]:
        commissioner.transition(expected, target, 1)
    commissioner.complete_after_verified_install(6, hmac_valid=True, proof_valid=True)
    return {"candidate": candidate.state.value, "commissioner": commissioner.state.value}


def run(command: list[str], cwd: Path) -> dict[str, str]:
    result = subprocess.run(command, cwd=cwd, check=True, text=True, capture_output=True, timeout=180)
    return json.loads(result.stdout.strip().splitlines()[-1])


def main() -> None:
    expected = {"candidate": "enrolled", "commissioner": "complete"}
    rust = run(["cargo", "run", "--quiet", "-p", "acp-security", "--example", "enrollment_fixture"], ROOT / "rust")
    swift = run(["swift", "run", "--quiet", "acp-enrollment-fixture"], ROOT)
    assert python_pair() == rust == swift == expected
    print("security enrollment interop ok: python rust swift")


if __name__ == "__main__":
    main()
