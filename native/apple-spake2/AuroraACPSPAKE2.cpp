#include "AuroraACPSPAKE2.h"

#include <botan/ec_scalar.h>
#include <botan/exceptn.h>
#include <botan/spake2p.h>
#include <botan/system_rng.h>
#include <botan/rng.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <memory>
#include <new>
#include <span>
#include <vector>

namespace {

enum class Role { prover, verifier };
enum class State { created, share_ready, confirmation_pending, consumed, failed };

void secure_wipe(void* value, size_t length) {
   volatile uint8_t* bytes = static_cast<volatile uint8_t*>(value);
   while(length-- > 0) { *bytes++ = 0; }
}

template <size_t N>
void wipe(std::array<uint8_t, N>& value) { secure_wipe(value.data(), value.size()); }

bool valid_span(const uint8_t* value, size_t length, size_t maximum) {
   return length <= maximum && (length == 0 || value != nullptr);
}

bool overlaps(const uint8_t* a, size_t a_len, const uint8_t* b, size_t b_len) {
   if(a == nullptr || b == nullptr || a_len == 0 || b_len == 0) { return false; }
   const auto a0 = reinterpret_cast<uintptr_t>(a);
   const auto b0 = reinterpret_cast<uintptr_t>(b);
   return a0 < b0 + b_len && b0 < a0 + a_len;
}

#if defined(ACP_SPAKE2_TESTING)
class FixedRNG final : public Botan::RandomNumberGenerator {
   public:
      void set(std::span<const uint8_t> value) { m_value.assign(value.begin(), value.end()); }
      bool is_seeded() const override { return !m_value.empty(); }
      bool accepts_input() const override { return false; }
      void clear() override { m_value.clear(); }
      std::string name() const override { return "ACP-test-only-fixed-RNG"; }
   private:
      void fill_bytes_with_input(std::span<uint8_t> output, std::span<const uint8_t>) override {
         if(m_value.empty()) { throw Botan::PRNG_Unseeded(name()); }
         for(size_t i = 0; i != output.size(); ++i) { output[i] = m_value[i % m_value.size()]; }
      }
      std::vector<uint8_t> m_value;
};
thread_local FixedRNG test_rng;
Botan::RandomNumberGenerator& provider_rng() { return test_rng; }
#else
Botan::RandomNumberGenerator& provider_rng() { return Botan::system_rng(); }
#endif

Botan::SPAKE2p::ProverSecret parse_secret(const uint8_t* bytes) {
   const auto params = Botan::SPAKE2p::SystemParameters::rfc9383_p256_sha256();
   auto w0 = Botan::EC_Scalar::deserialize(params.group(), {bytes, ACP_SPAKE2_SCALAR_BYTES});
   auto w1 = Botan::EC_Scalar::deserialize(params.group(), {bytes + ACP_SPAKE2_SCALAR_BYTES, ACP_SPAKE2_SCALAR_BYTES});
   if(!w0 || !w1 || w0->serialize() != std::vector<uint8_t>(bytes, bytes + ACP_SPAKE2_SCALAR_BYTES) ||
      w1->serialize() != std::vector<uint8_t>(bytes + ACP_SPAKE2_SCALAR_BYTES,
                                             bytes + ACP_SPAKE2_PROVER_SECRET_BYTES)) {
      throw Botan::Decoding_Error("invalid ACP scalar");
   }
   return Botan::SPAKE2p::ProverSecret::from_prehashed(std::move(*w0), std::move(*w1));
}

}  // namespace

struct acp_spake2_context {
   Role role;
   State state = State::created;
   Botan::SPAKE2p::SystemParameters params = Botan::SPAKE2p::SystemParameters::rfc9383_p256_sha256();
   std::unique_ptr<Botan::SPAKE2p::ProverContext> prover;
   std::unique_ptr<Botan::SPAKE2p::VerifierContext> verifier;

   explicit acp_spake2_context(Role selected) : role(selected) {}
   void fail() {
      state = State::failed;
      prover.reset();
      verifier.reset();
   }
};

namespace {

acp_spake2_status validate_common(const uint8_t* prover_id, size_t prover_id_len,
                                  const uint8_t* verifier_id, size_t verifier_id_len,
                                  const uint8_t* context, size_t context_len,
                                  acp_spake2_context** output) {
   if(output == nullptr || *output != nullptr ||
      !valid_span(prover_id, prover_id_len, ACP_SPAKE2_MAX_IDENTITY_BYTES) ||
      !valid_span(verifier_id, verifier_id_len, ACP_SPAKE2_MAX_IDENTITY_BYTES) ||
      !valid_span(context, context_len, ACP_SPAKE2_MAX_CONTEXT_BYTES)) {
      return ACP_SPAKE2_INVALID_ARGUMENT;
   }
   return ACP_SPAKE2_SUCCESS;
}

template <typename Action>
acp_spake2_status transition(acp_spake2_context* context, Role role, State expected,
                             acp_spake2_status failure, Action action) {
   if(context == nullptr || context->role != role || context->state != expected) {
      if(context != nullptr) { context->fail(); }
      return ACP_SPAKE2_INVALID_STATE;
   }
   try {
      action();
      return ACP_SPAKE2_SUCCESS;
   } catch(const Botan::PRNG_Unseeded&) {
      context->fail();
      return ACP_SPAKE2_RANDOM_FAILED;
   } catch(...) {
      context->fail();
      return failure;
   }
}

}  // namespace

extern "C" acp_spake2_status acp_spake2_create_registration_record(
   const uint8_t* prover_secret, size_t prover_secret_len,
   uint8_t* record, size_t record_len) {
   if(prover_secret == nullptr || prover_secret_len != ACP_SPAKE2_PROVER_SECRET_BYTES ||
      record == nullptr || record_len != ACP_SPAKE2_REGISTRATION_RECORD_BYTES ||
      overlaps(prover_secret, ACP_SPAKE2_PROVER_SECRET_BYTES, record, ACP_SPAKE2_REGISTRATION_RECORD_BYTES)) {
      if(record != nullptr && record_len == ACP_SPAKE2_REGISTRATION_RECORD_BYTES) {
         secure_wipe(record, record_len);
      }
      return ACP_SPAKE2_INVALID_ARGUMENT;
   }
   try {
      auto secret = parse_secret(prover_secret);
      auto serialized = secret.registration_record(provider_rng()).serialize();
      if(serialized.size() != ACP_SPAKE2_REGISTRATION_RECORD_BYTES) { return ACP_SPAKE2_INTERNAL_FAILED; }
      std::copy(serialized.begin(), serialized.end(), record);
      return ACP_SPAKE2_SUCCESS;
   } catch(const Botan::PRNG_Unseeded&) {
      secure_wipe(record, record_len);
      return ACP_SPAKE2_RANDOM_FAILED;
   } catch(...) {
      secure_wipe(record, record_len);
      return ACP_SPAKE2_INVALID_CREDENTIAL;
   }
}

extern "C" acp_spake2_status acp_spake2_prover_create(
   const uint8_t* prover_secret, size_t prover_secret_len,
   const uint8_t* prover_id, size_t prover_id_len,
   const uint8_t* verifier_id, size_t verifier_id_len,
   const uint8_t* context, size_t context_len,
   acp_spake2_context** output) {
   const auto checked = validate_common(prover_id, prover_id_len, verifier_id, verifier_id_len,
                                        context, context_len, output);
   if(checked != ACP_SPAKE2_SUCCESS) { return checked; }
   if(prover_secret == nullptr || prover_secret_len != ACP_SPAKE2_PROVER_SECRET_BYTES) {
      return ACP_SPAKE2_INVALID_ARGUMENT;
   }
   try {
      auto handle = std::make_unique<acp_spake2_context>(Role::prover);
      auto secret = parse_secret(prover_secret);
      handle->prover = std::make_unique<Botan::SPAKE2p::ProverContext>(
         handle->params, secret, std::span(prover_id, prover_id_len),
         std::span(verifier_id, verifier_id_len), std::span(context, context_len));
      *output = handle.release();
      return ACP_SPAKE2_SUCCESS;
   } catch(...) {
      return ACP_SPAKE2_INVALID_CREDENTIAL;
   }
}

extern "C" acp_spake2_status acp_spake2_verifier_create(
   const uint8_t* record, size_t record_len,
   const uint8_t* prover_id, size_t prover_id_len,
   const uint8_t* verifier_id, size_t verifier_id_len,
   const uint8_t* context, size_t context_len,
   acp_spake2_context** output) {
   const auto checked = validate_common(prover_id, prover_id_len, verifier_id, verifier_id_len,
                                        context, context_len, output);
   if(checked != ACP_SPAKE2_SUCCESS) { return checked; }
   if(record == nullptr || record_len != ACP_SPAKE2_REGISTRATION_RECORD_BYTES) {
      return ACP_SPAKE2_INVALID_ARGUMENT;
   }
   try {
      auto handle = std::make_unique<acp_spake2_context>(Role::verifier);
      auto parsed = Botan::SPAKE2p::RegistrationRecord::deserialize(
         handle->params, {record, ACP_SPAKE2_REGISTRATION_RECORD_BYTES});
      const auto canonical = parsed.serialize();
      if(canonical.size() != ACP_SPAKE2_REGISTRATION_RECORD_BYTES ||
         !std::equal(canonical.begin(), canonical.end(), record)) {
         return ACP_SPAKE2_INVALID_CREDENTIAL;
      }
      handle->verifier = std::make_unique<Botan::SPAKE2p::VerifierContext>(
         handle->params, parsed, std::span(prover_id, prover_id_len),
         std::span(verifier_id, verifier_id_len), std::span(context, context_len));
      *output = handle.release();
      return ACP_SPAKE2_SUCCESS;
   } catch(...) {
      return ACP_SPAKE2_INVALID_CREDENTIAL;
   }
}

extern "C" acp_spake2_status acp_spake2_prover_generate_share(
   acp_spake2_context* context, uint8_t* share, size_t share_len) {
   if(share == nullptr || share_len != ACP_SPAKE2_SHARE_BYTES) {
      if(context) context->fail(); return ACP_SPAKE2_INVALID_ARGUMENT;
   }
   const auto status = transition(context, Role::prover, State::created, ACP_SPAKE2_INTERNAL_FAILED, [&] {
      auto message = context->prover->generate_message(provider_rng());
      if(message.size() != ACP_SPAKE2_SHARE_BYTES) { throw Botan::Internal_Error("share size"); }
      std::copy(message.begin(), message.end(), share);
      context->state = State::confirmation_pending;
   });
   if(status != ACP_SPAKE2_SUCCESS) { secure_wipe(share, share_len); }
   return status;
}

extern "C" acp_spake2_status acp_spake2_verifier_process_share(
   acp_spake2_context* context, const uint8_t* share, size_t share_len,
   uint8_t* response, size_t response_len) {
   if(share == nullptr || share_len != ACP_SPAKE2_SHARE_BYTES || response == nullptr ||
      response_len != ACP_SPAKE2_VERIFIER_RESPONSE_BYTES || overlaps(share, ACP_SPAKE2_SHARE_BYTES,
                                                          response, ACP_SPAKE2_VERIFIER_RESPONSE_BYTES)) {
      if(context) context->fail();
      return ACP_SPAKE2_INVALID_ARGUMENT;
   }
   const auto status = transition(context, Role::verifier, State::created, ACP_SPAKE2_INVALID_PEER_MESSAGE, [&] {
      auto message = context->verifier->process_message({share, ACP_SPAKE2_SHARE_BYTES}, provider_rng());
      if(message.size() != ACP_SPAKE2_VERIFIER_RESPONSE_BYTES) { throw Botan::Internal_Error("response size"); }
      std::copy(message.begin(), message.end(), response);
      context->state = State::confirmation_pending;
   });
   if(status != ACP_SPAKE2_SUCCESS) { secure_wipe(response, response_len); }
   return status;
}

extern "C" acp_spake2_status acp_spake2_prover_process_response_and_consume_key(
   acp_spake2_context* context, const uint8_t* response, size_t response_len,
   uint8_t* confirmation, size_t confirmation_len,
   uint8_t* shared_secret, size_t shared_secret_len) {
   if(response == nullptr || response_len != ACP_SPAKE2_VERIFIER_RESPONSE_BYTES ||
      confirmation == nullptr || confirmation_len != ACP_SPAKE2_CONFIRMATION_BYTES ||
      shared_secret == nullptr || shared_secret_len != ACP_SPAKE2_SHARED_SECRET_BYTES ||
      overlaps(response, ACP_SPAKE2_VERIFIER_RESPONSE_BYTES, confirmation, ACP_SPAKE2_CONFIRMATION_BYTES) ||
      overlaps(response, ACP_SPAKE2_VERIFIER_RESPONSE_BYTES, shared_secret, ACP_SPAKE2_SHARED_SECRET_BYTES) ||
      overlaps(confirmation, ACP_SPAKE2_CONFIRMATION_BYTES, shared_secret, ACP_SPAKE2_SHARED_SECRET_BYTES)) {
      if(context) context->fail();
      return ACP_SPAKE2_INVALID_ARGUMENT;
   }
   std::array<uint8_t, ACP_SPAKE2_SHARED_SECRET_BYTES> staged_secret{};
   const auto status = transition(context, Role::prover, State::confirmation_pending,
                                  ACP_SPAKE2_CONFIRMATION_FAILED, [&] {
      auto confirm = context->prover->process_message({response, ACP_SPAKE2_VERIFIER_RESPONSE_BYTES}, provider_rng());
      auto secret = context->prover->shared_secret();
      if(confirm.size() != ACP_SPAKE2_CONFIRMATION_BYTES || secret.size() != staged_secret.size()) {
         throw Botan::Internal_Error("output size");
      }
      std::copy(confirm.begin(), confirm.end(), confirmation);
      std::copy(secret.begin(), secret.end(), staged_secret.begin());
      context->prover.reset();
      context->state = State::consumed;
   });
   if(status == ACP_SPAKE2_SUCCESS) { std::copy(staged_secret.begin(), staged_secret.end(), shared_secret); }
   else { secure_wipe(confirmation, ACP_SPAKE2_CONFIRMATION_BYTES); secure_wipe(shared_secret, ACP_SPAKE2_SHARED_SECRET_BYTES); }
   wipe(staged_secret);
   return status;
}

extern "C" acp_spake2_status acp_spake2_verifier_verify_confirmation_and_consume_key(
   acp_spake2_context* context, const uint8_t* confirmation, size_t confirmation_len,
   uint8_t* shared_secret, size_t shared_secret_len) {
   if(confirmation == nullptr || confirmation_len != ACP_SPAKE2_CONFIRMATION_BYTES ||
      shared_secret == nullptr || shared_secret_len != ACP_SPAKE2_SHARED_SECRET_BYTES ||
      overlaps(confirmation, ACP_SPAKE2_CONFIRMATION_BYTES, shared_secret, ACP_SPAKE2_SHARED_SECRET_BYTES)) {
      if(context) context->fail();
      return ACP_SPAKE2_INVALID_ARGUMENT;
   }
   std::array<uint8_t, ACP_SPAKE2_SHARED_SECRET_BYTES> staged_secret{};
   const auto status = transition(context, Role::verifier, State::confirmation_pending,
                                  ACP_SPAKE2_CONFIRMATION_FAILED, [&] {
      context->verifier->verify_confirmation({confirmation, ACP_SPAKE2_CONFIRMATION_BYTES});
      auto secret = context->verifier->shared_secret();
      if(secret.size() != staged_secret.size()) { throw Botan::Internal_Error("secret size"); }
      std::copy(secret.begin(), secret.end(), staged_secret.begin());
      context->verifier.reset();
      context->state = State::consumed;
   });
   if(status == ACP_SPAKE2_SUCCESS) { std::copy(staged_secret.begin(), staged_secret.end(), shared_secret); }
   else { secure_wipe(shared_secret, ACP_SPAKE2_SHARED_SECRET_BYTES); }
   wipe(staged_secret);
   return status;
}

extern "C" void acp_spake2_destroy(acp_spake2_context** context) {
   if(context == nullptr || *context == nullptr) { return; }
   (*context)->fail();
   delete *context;
   *context = nullptr;
}

#if defined(ACP_SPAKE2_TESTING)
extern "C" void acp_spake2_test_set_rng(const uint8_t* value, size_t value_len) {
   test_rng.set({value, value_len});
}
#endif
