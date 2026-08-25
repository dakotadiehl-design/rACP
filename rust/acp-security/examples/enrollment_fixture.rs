use acp_security::*;
use std::collections::HashSet;

struct Confirmation;
impl Spake2PlusOperation for Confirmation {
    fn receive_peer_share(&mut self, share: &[u8]) -> Result<Vec<u8>, SecurityErrorCode> {
        Ok(share.to_vec())
    }
    fn verify_confirmation(&mut self, value: &[u8]) -> Result<(), SecurityErrorCode> {
        if value == b"valid" {
            Ok(())
        } else {
            Err(SecurityErrorCode::AuthenticationFailed)
        }
    }
}
fn main() -> Result<(), SecurityErrorCode> {
    let enrollment = EnrollmentId::parse("50617283-94a5-4b6c-9a4b-5c6d7e8f90a1")?;
    let attempt = EnrollmentAttemptId::parse("60718293-a4b5-4c6d-aa5b-6c7d8e9fa0b1")?;
    let mut candidate = CandidateEnrollment::new(
        enrollment.clone(),
        HashSet::from([SecuritySuite::Raw128]),
        EnrollmentLimits::for_profile(SecurityProfile::Full),
        0,
    );
    candidate.begin(attempt.clone(), SecuritySuite::Raw128, 1)?;
    candidate.process_peer_share(&attempt, &mut Confirmation, b"share", 2)?;
    candidate.verify_key_confirmation(&attempt, &mut Confirmation, b"valid", 2)?;
    candidate.await_approval(&attempt, 3)?;
    candidate.credential_staged(&attempt, 4)?;
    candidate.durable_install_verified(&attempt, 5)?;
    candidate.complete(&attempt, 6)?;
    let mut commissioner = CommissionerEnrollment::new(enrollment, attempt, 100);
    for (from, to) in [
        (
            CommissionerEnrollmentState::Idle,
            CommissionerEnrollmentState::CandidateSelected,
        ),
        (
            CommissionerEnrollmentState::CandidateSelected,
            CommissionerEnrollmentState::SecretAcquired,
        ),
        (
            CommissionerEnrollmentState::SecretAcquired,
            CommissionerEnrollmentState::Negotiating,
        ),
        (
            CommissionerEnrollmentState::Negotiating,
            CommissionerEnrollmentState::KeyConfirmed,
        ),
        (
            CommissionerEnrollmentState::KeyConfirmed,
            CommissionerEnrollmentState::AwaitingOperatorApproval,
        ),
        (
            CommissionerEnrollmentState::AwaitingOperatorApproval,
            CommissionerEnrollmentState::IssuingCredential,
        ),
        (
            CommissionerEnrollmentState::IssuingCredential,
            CommissionerEnrollmentState::AwaitingInstallReceipt,
        ),
    ] {
        commissioner.transition(from, to, 1)?;
    }
    commissioner.complete_verified_install(6, true, true)?;
    println!("{{\"candidate\":\"enrolled\",\"commissioner\":\"complete\"}}");
    Ok(())
}
