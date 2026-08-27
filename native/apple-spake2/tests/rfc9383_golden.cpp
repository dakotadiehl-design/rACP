#include "AuroraACPSPAKE2.h"

#include <array>
#include <cstdint>
#include <iostream>
#include <string>

extern "C" void acp_spake2_test_set_rng(const uint8_t*, size_t);

template <size_t N>
std::array<uint8_t, N> from_hex(const std::string& text) {
   std::array<uint8_t, N> output{};
   for(size_t i = 0; i != N; ++i) {
      output[i] = static_cast<uint8_t>(std::stoul(text.substr(i * 2, 2), nullptr, 16));
   }
   return output;
}

int main() {
   const auto secret = from_hex<64>(
      "bb8e1bbcf3c48f62c08db243652ae55d3e5586053fca77102994f23ad95491b3"
      "7e945f34d78785b8a3ef44d0df5a1a97d6b3b460409a345ca7830387a74b1dba");
   const auto x = from_hex<32>("d1232c8e8693d02368976c174e2088851b8365d0d79a9eee709c6a05a2fad539");
   const auto y = from_hex<32>("717a72348a182085109c8d3917d6c43d59b224dc6a7fc4f0483232fa6516d8b3");
   const auto expected_share = from_hex<65>(
      "04ef3bd051bf78a2234ec0df197f7828060fe9856503579bb1733009042c15c0"
      "c1de127727f418b5966afadfdd95a6e4591d171056b333dab97a79c7193e341727");
   const auto expected_response = from_hex<97>(
      "04c0f65da0d11927bdf5d560c69e1d7d939a05b0e88291887d679fcadea75810"
      "fb5cc1ca7494db39e82ff2f50665255d76173e09986ab46742c798a9a68437b048"
      "9747bcc4f8fe9f63defee53ac9b07876d907d55047e6ff2def2e7529089d3e68");
   const auto expected_confirmation = from_hex<32>(
      "926cc713504b9b4d76c9162ded04b5493e89109f6d89462cd33adc46fda27527");
   const auto expected_key = from_hex<32>(
      "0c5f8ccd1413423a54f6c1fb26ff01534a87f893779c6e68666d772bfd91f3e7");
   const std::array<uint8_t, 6> prover_id = {'c','l','i','e','n','t'};
   const std::array<uint8_t, 6> verifier_id = {'s','e','r','v','e','r'};
   const std::string context = "SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256 Test Vectors";

   std::array<uint8_t, 97> record{}, response{};
   std::array<uint8_t, 65> share{};
   std::array<uint8_t, 32> confirmation{}, prover_key{}, verifier_key{};
   acp_spake2_context *prover = nullptr, *verifier = nullptr;
   acp_spake2_test_set_rng(y.data(), y.size());
   if(acp_spake2_create_registration_record(secret.data(), secret.size(), record.data(), record.size()) ||
      acp_spake2_prover_create(secret.data(), secret.size(), prover_id.data(), prover_id.size(),
         verifier_id.data(), verifier_id.size(), reinterpret_cast<const uint8_t*>(context.data()), context.size(), &prover) ||
      acp_spake2_verifier_create(record.data(), record.size(), prover_id.data(), prover_id.size(),
         verifier_id.data(), verifier_id.size(), reinterpret_cast<const uint8_t*>(context.data()), context.size(), &verifier)) return 1;
   acp_spake2_test_set_rng(x.data(), x.size());
   if(acp_spake2_prover_generate_share(prover, share.data(), share.size()) || share != expected_share) return 1;
   acp_spake2_test_set_rng(y.data(), y.size());
   if(acp_spake2_verifier_process_share(verifier, share.data(), share.size(), response.data(), response.size()) ||
      response != expected_response) return 1;
   acp_spake2_test_set_rng(x.data(), x.size());
   if(acp_spake2_prover_process_response_and_consume_key(prover, response.data(), response.size(),
         confirmation.data(), confirmation.size(), prover_key.data(), prover_key.size()) ||
      confirmation != expected_confirmation || prover_key != expected_key) return 1;
   if(acp_spake2_verifier_verify_confirmation_and_consume_key(verifier, confirmation.data(), confirmation.size(),
         verifier_key.data(), verifier_key.size()) || verifier_key != expected_key) return 1;
   acp_spake2_destroy(&prover); acp_spake2_destroy(&verifier);
   std::cout << "PASS: RFC 9383 Appendix C byte-for-byte through restricted ABI\n";
   return 0;
}
