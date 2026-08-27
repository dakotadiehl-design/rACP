#ifndef AURORA_ACP_SPAKE2_H
#define AURORA_ACP_SPAKE2_H

#include <stddef.h>
#include <stdint.h>

#if defined(__GNUC__)
#define ACP_SPAKE2_EXPORT __attribute__((visibility("default")))
#else
#define ACP_SPAKE2_EXPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define ACP_SPAKE2_SCALAR_BYTES 32u
#define ACP_SPAKE2_PROVER_SECRET_BYTES 64u
#define ACP_SPAKE2_SHARE_BYTES 65u
#define ACP_SPAKE2_REGISTRATION_RECORD_BYTES 97u
#define ACP_SPAKE2_VERIFIER_RESPONSE_BYTES 97u
#define ACP_SPAKE2_CONFIRMATION_BYTES 32u
#define ACP_SPAKE2_SHARED_SECRET_BYTES 32u
#define ACP_SPAKE2_MAX_IDENTITY_BYTES 255u
#define ACP_SPAKE2_MAX_CONTEXT_BYTES 4096u

typedef struct acp_spake2_context acp_spake2_context;

typedef enum acp_spake2_status {
    ACP_SPAKE2_SUCCESS = 0,
    ACP_SPAKE2_INVALID_ARGUMENT = 1,
    ACP_SPAKE2_INVALID_CREDENTIAL = 2,
    ACP_SPAKE2_INVALID_PEER_MESSAGE = 3,
    ACP_SPAKE2_CONFIRMATION_FAILED = 4,
    ACP_SPAKE2_INVALID_STATE = 5,
    ACP_SPAKE2_RANDOM_FAILED = 6,
    ACP_SPAKE2_INTERNAL_FAILED = 7
} acp_spake2_status;

ACP_SPAKE2_EXPORT acp_spake2_status acp_spake2_create_registration_record(
    const uint8_t* prover_secret, size_t prover_secret_len,
    uint8_t* record, size_t record_len);

ACP_SPAKE2_EXPORT acp_spake2_status acp_spake2_prover_create(
    const uint8_t* prover_secret, size_t prover_secret_len,
    const uint8_t* prover_identity, size_t prover_identity_len,
    const uint8_t* verifier_identity, size_t verifier_identity_len,
    const uint8_t* context, size_t context_len,
    acp_spake2_context** out_context);

ACP_SPAKE2_EXPORT acp_spake2_status acp_spake2_verifier_create(
    const uint8_t* record, size_t record_len,
    const uint8_t* prover_identity, size_t prover_identity_len,
    const uint8_t* verifier_identity, size_t verifier_identity_len,
    const uint8_t* context, size_t context_len,
    acp_spake2_context** out_context);

ACP_SPAKE2_EXPORT acp_spake2_status acp_spake2_prover_generate_share(
    acp_spake2_context* context,
    uint8_t* share, size_t share_len);

ACP_SPAKE2_EXPORT acp_spake2_status acp_spake2_verifier_process_share(
    acp_spake2_context* context,
    const uint8_t* prover_share, size_t prover_share_len,
    uint8_t* response, size_t response_len);

/* Atomically verifies confirmV, emits confirmP, consumes K_shared, and
 * terminalizes the prover context. There is intentionally no secret getter. */
ACP_SPAKE2_EXPORT acp_spake2_status acp_spake2_prover_process_response_and_consume_key(
    acp_spake2_context* context,
    const uint8_t* response, size_t response_len,
    uint8_t* confirmation, size_t confirmation_len,
    uint8_t* shared_secret, size_t shared_secret_len);

/* Atomically verifies confirmP, consumes K_shared, and terminalizes the
 * verifier context. There is intentionally no skip-confirmation operation. */
ACP_SPAKE2_EXPORT acp_spake2_status acp_spake2_verifier_verify_confirmation_and_consume_key(
    acp_spake2_context* context,
    const uint8_t* confirmation, size_t confirmation_len,
    uint8_t* shared_secret, size_t shared_secret_len);

ACP_SPAKE2_EXPORT void acp_spake2_destroy(acp_spake2_context** context);

#ifdef __cplusplus
}
#endif
#endif
