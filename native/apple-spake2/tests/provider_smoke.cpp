#include "AuroraACPSPAKE2.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <string>

namespace {
std::array<uint8_t, ACP_SPAKE2_PROVER_SECRET_BYTES> hex_secret(const std::string& text) {
   std::array<uint8_t, ACP_SPAKE2_PROVER_SECRET_BYTES> output{};
   for(size_t i = 0; i != output.size(); ++i) {
      output[i] = static_cast<uint8_t>(std::stoul(text.substr(i * 2, 2), nullptr, 16));
   }
   return output;
}

bool passed(acp_spake2_status status) { return status == ACP_SPAKE2_SUCCESS; }
bool require(bool condition, const char* label) {
   if(!condition) { std::cerr << "FAIL: " << label << "\n"; }
   return condition;
}
}

int main() {
   // Frozen RFC 9383 Appendix C w0 || w1.
   const auto secret = hex_secret(
      "bb8e1bbcf3c48f62c08db243652ae55d3e5586053fca77102994f23ad95491b3"
      "7e945f34d78785b8a3ef44d0df5a1a97d6b3b460409a345ca7830387a74b1dba");
   const std::array<uint8_t, 6> prover_id = {'c','l','i','e','n','t'};
   const std::array<uint8_t, 6> verifier_id = {'s','e','r','v','e','r'};
   const std::string context_text = "SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256 Test Vectors";
   const auto* context_bytes = reinterpret_cast<const uint8_t*>(context_text.data());

   std::array<uint8_t, ACP_SPAKE2_REGISTRATION_RECORD_BYTES> record{};
   if(!require(passed(acp_spake2_create_registration_record(secret.data(), secret.size(), record.data(), record.size())), "registration")) { return 1; }

   acp_spake2_context* prover = nullptr;
   acp_spake2_context* verifier = nullptr;
   if(!passed(acp_spake2_prover_create(secret.data(), secret.size(), prover_id.data(), prover_id.size(),
                                       verifier_id.data(), verifier_id.size(), context_bytes,
                                       context_text.size(), &prover)) ||
      !passed(acp_spake2_verifier_create(record.data(), record.size(), prover_id.data(), prover_id.size(),
                                         verifier_id.data(), verifier_id.size(), context_bytes,
                                         context_text.size(), &verifier))) { std::cerr << "FAIL: create\n"; return 1; }

   std::array<uint8_t, ACP_SPAKE2_SHARE_BYTES> share{};
   std::array<uint8_t, ACP_SPAKE2_VERIFIER_RESPONSE_BYTES> response{};
   std::array<uint8_t, ACP_SPAKE2_CONFIRMATION_BYTES> confirmation{};
   std::array<uint8_t, ACP_SPAKE2_SHARED_SECRET_BYTES> prover_key{};
   std::array<uint8_t, ACP_SPAKE2_SHARED_SECRET_BYTES> verifier_key{};

   // Secret extraction is absent from the ABI. The only key-producing calls
   // below also process/verify peer confirmation and terminalize the context.
   if(!passed(acp_spake2_prover_generate_share(prover, share.data(), share.size())) ||
      !passed(acp_spake2_verifier_process_share(verifier, share.data(), share.size(), response.data(), response.size())) ||
      !passed(acp_spake2_prover_process_response_and_consume_key(
         prover, response.data(), response.size(), confirmation.data(), confirmation.size(), prover_key.data(), prover_key.size())) ||
      !passed(acp_spake2_verifier_verify_confirmation_and_consume_key(
         verifier, confirmation.data(), confirmation.size(), verifier_key.data(), verifier_key.size())) ||
      prover_key != verifier_key) { std::cerr << "FAIL: exchange\n"; return 1; }

   // Both success paths are one-shot and terminal.
   if(acp_spake2_prover_generate_share(prover, share.data(), share.size()) != ACP_SPAKE2_INVALID_STATE ||
      acp_spake2_verifier_verify_confirmation_and_consume_key(
         verifier, confirmation.data(), confirmation.size(), verifier_key.data(), verifier_key.size()) != ACP_SPAKE2_INVALID_STATE) { std::cerr << "FAIL: terminal\n"; return 1; }
   acp_spake2_destroy(&prover);
   acp_spake2_destroy(&verifier);
   if(prover != nullptr || verifier != nullptr) { std::cerr << "FAIL: destroy\n"; return 1; }

   // Explicit capacities reject truncated and zero-writable outputs and make
   // the affected context terminal. Offset buffers with exact capacity work.
   std::array<uint8_t, ACP_SPAKE2_REGISTRATION_RECORD_BYTES + 1> offset_record{};
   if(acp_spake2_create_registration_record(secret.data(), secret.size(),
                                             offset_record.data() + 1,
                                             ACP_SPAKE2_REGISTRATION_RECORD_BYTES) != ACP_SPAKE2_SUCCESS) return 1;
   acp_spake2_context* capacity = nullptr;
   if(acp_spake2_prover_create(secret.data(), secret.size(), nullptr, 0, nullptr, 0, nullptr, 0,
                               &capacity) != ACP_SPAKE2_SUCCESS) return 1;
   if(acp_spake2_prover_generate_share(capacity, share.data(), 0) != ACP_SPAKE2_INVALID_ARGUMENT ||
      acp_spake2_prover_generate_share(capacity, share.data(), share.size()) != ACP_SPAKE2_INVALID_STATE) return 1;
   acp_spake2_destroy(&capacity);

   acp_spake2_context* malformed_share = nullptr;
   if(acp_spake2_verifier_create(offset_record.data() + 1, ACP_SPAKE2_REGISTRATION_RECORD_BYTES,
                                  nullptr, 0, nullptr, 0, nullptr, 0, &malformed_share) != ACP_SPAKE2_SUCCESS) return 1;
   std::array<uint8_t, ACP_SPAKE2_SHARE_BYTES> invalid_point{};
   if(acp_spake2_verifier_process_share(malformed_share, invalid_point.data(), invalid_point.size(),
                                        response.data(), response.size()) != ACP_SPAKE2_INVALID_PEER_MESSAGE ||
      acp_spake2_verifier_process_share(malformed_share, share.data(), share.size(),
                                        response.data(), response.size()) != ACP_SPAKE2_INVALID_STATE) return 1;
   acp_spake2_destroy(&malformed_share);

   // Non-canonical/zero scalars and malformed records fail before Botan PAKE state.
   auto zero = secret;
   std::fill(zero.begin(), zero.begin() + ACP_SPAKE2_SCALAR_BYTES, 0);
   acp_spake2_context* invalid = nullptr;
   if(acp_spake2_prover_create(zero.data(), zero.size(), nullptr, 0, nullptr, 0, nullptr, 0, &invalid) !=
      ACP_SPAKE2_INVALID_CREDENTIAL || invalid != nullptr) { std::cerr << "FAIL: scalar\n"; return 1; }
   std::fill(record.begin() + ACP_SPAKE2_SCALAR_BYTES, record.end(), 0);
   if(acp_spake2_verifier_create(record.data(), record.size(), nullptr, 0, nullptr, 0, nullptr, 0, &invalid) !=
      ACP_SPAKE2_INVALID_CREDENTIAL || invalid != nullptr) { std::cerr << "FAIL: record\n"; return 1; }

   std::cout << "PASS: restricted provider confirmation-gated key agreement\n";
   return 0;
}
