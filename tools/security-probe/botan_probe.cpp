#include <botan/auto_rng.h>
#include <botan/ec_scalar.h>
#include <botan/hash.h>
#include <botan/kdf.h>
#include <botan/mac.h>
#include <botan/spake2p.h>

#include <algorithm>
#include <cstdint>
#include <exception>
#include <iostream>
#include <span>
#include <string>
#include <vector>

namespace {

std::vector<uint8_t> from_hex(const std::string& text) {
   std::vector<uint8_t> output;
   output.reserve(text.size() / 2);
   for(size_t i = 0; i < text.size(); i += 2) {
      output.push_back(static_cast<uint8_t>(std::stoul(text.substr(i, 2), nullptr, 16)));
   }
   return output;
}

bool expect_throw(auto&& operation) {
   try {
      operation();
      return false;
   } catch(const std::exception&) {
      return true;
   }
}

class FixedRNG final : public Botan::RandomNumberGenerator {
   public:
      explicit FixedRNG(std::vector<uint8_t> value) : m_value(std::move(value)) {}
      bool is_seeded() const override { return true; }
      bool accepts_input() const override { return false; }
      void clear() override {}
      std::string name() const override { return "ACP-M0-FixedRNG"; }

   private:
      void fill_bytes_with_input(std::span<uint8_t> output, std::span<const uint8_t>) override {
         for(size_t i = 0; i != output.size(); ++i) {
            output[i] = m_value[i % m_value.size()];
         }
      }
      std::vector<uint8_t> m_value;
};

}  // namespace

int main(int argc, char** argv) {
   if(argc != 4) {
      std::cerr << "usage: botan_probe W0_HEX W1_HEX CONTEXT_HEX\n";
      return 2;
   }

   try {
      const auto parameters = Botan::SPAKE2p::SystemParameters::rfc9383_p256_sha256();

      auto hash = Botan::HashFunction::create_or_throw("SHA-256");
      const std::vector<uint8_t> abc = {'a', 'b', 'c'};
      hash->update(abc);
      const bool sha256_pass = hash->final_stdvec() ==
                               from_hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
      auto mac = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");
      mac->set_key(std::vector<uint8_t>(20, 0x0b));
      const std::vector<uint8_t> hi_there = {'H', 'i', ' ', 'T', 'h', 'e', 'r', 'e'};
      mac->update(hi_there);
      const bool hmac_pass =
         mac->final_stdvec() == from_hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
      auto kdf = Botan::KDF::create_or_throw("HKDF(SHA-256)");
      const auto hkdf_output = kdf->derive_key<std::vector<uint8_t>>(
         42,
         std::vector<uint8_t>(22, 0x0b),
         from_hex("000102030405060708090a0b0c"),
         from_hex("f0f1f2f3f4f5f6f7f8f9"));
      const bool hkdf_pass = hkdf_output == from_hex(
                                                "3cb25f25faacd57a90434f64d0362f2a"
                                                "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                                                "34007208d5b887185865");

      const auto rfc_w0 = Botan::EC_Scalar::deserialize(
         parameters.group(), from_hex("bb8e1bbcf3c48f62c08db243652ae55d3e5586053fca77102994f23ad95491b3"));
      const auto rfc_w1 = Botan::EC_Scalar::deserialize(
         parameters.group(), from_hex("7e945f34d78785b8a3ef44d0df5a1a97d6b3b460409a345ca7830387a74b1dba"));
      if(!rfc_w0 || !rfc_w1) {
         throw std::runtime_error("RFC scalar deserialization failed");
      }
      const std::vector<uint8_t> rfc_prover_id = {'c', 'l', 'i', 'e', 'n', 't'};
      const std::vector<uint8_t> rfc_verifier_id = {'s', 'e', 'r', 'v', 'e', 'r'};
      const std::string rfc_context_string = "SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256 Test Vectors";
      const std::vector<uint8_t> rfc_context(rfc_context_string.begin(), rfc_context_string.end());
      const auto rfc_secret = Botan::SPAKE2p::ProverSecret::from_prehashed(*rfc_w0, *rfc_w1);
      FixedRNG rfc_x_rng(from_hex("d1232c8e8693d02368976c174e2088851b8365d0d79a9eee709c6a05a2fad539"));
      FixedRNG rfc_y_rng(from_hex("717a72348a182085109c8d3917d6c43d59b224dc6a7fc4f0483232fa6516d8b3"));
      const auto rfc_record = rfc_secret.registration_record(rfc_y_rng);
      Botan::SPAKE2p::ProverContext rfc_prover(
         parameters, rfc_secret, rfc_prover_id, rfc_verifier_id, rfc_context);
      Botan::SPAKE2p::VerifierContext rfc_verifier(
         parameters, rfc_record, rfc_prover_id, rfc_verifier_id, rfc_context);
      const auto rfc_share_p = rfc_prover.generate_message(rfc_x_rng);
      const auto rfc_response = rfc_verifier.process_message(rfc_share_p, rfc_y_rng);
      const auto rfc_confirm_p = rfc_prover.process_message(rfc_response, rfc_x_rng);
      rfc_verifier.verify_confirmation(rfc_confirm_p);
      const auto rfc_shared = rfc_prover.shared_secret();
      const auto rfc_shared_expected =
         from_hex("0c5f8ccd1413423a54f6c1fb26ff01534a87f893779c6e68666d772bfd91f3e7");
      const bool rfc_pass =
         rfc_share_p == from_hex(
                           "04ef3bd051bf78a2234ec0df197f7828060fe9856503579bb1733009042c15c0"
                           "c1de127727f418b5966afadfdd95a6e4591d171056b333dab97a79c7193e341727") &&
         std::vector<uint8_t>(rfc_response.begin(), rfc_response.begin() + 65) ==
            from_hex(
               "04c0f65da0d11927bdf5d560c69e1d7d939a05b0e88291887d679fcadea75810"
               "fb5cc1ca7494db39e82ff2f50665255d76173e09986ab46742c798a9a68437b048") &&
         std::vector<uint8_t>(rfc_response.begin() + 65, rfc_response.end()) ==
            from_hex("9747bcc4f8fe9f63defee53ac9b07876d907d55047e6ff2def2e7529089d3e68") &&
         rfc_confirm_p == from_hex("926cc713504b9b4d76c9162ded04b5493e89109f6d89462cd33adc46fda27527") &&
         std::equal(rfc_shared.begin(), rfc_shared.end(), rfc_shared_expected.begin(), rfc_shared_expected.end());
      const auto w0_bytes = from_hex(argv[1]);
      const auto w1_bytes = from_hex(argv[2]);
      const auto context = from_hex(argv[3]);
      const auto w0 = Botan::EC_Scalar::deserialize(parameters.group(), w0_bytes);
      const auto w1 = Botan::EC_Scalar::deserialize(parameters.group(), w1_bytes);
      if(!w0 || !w1) {
         throw std::runtime_error("ACP scalar deserialization failed");
      }

      const std::vector<uint8_t> prover_id = from_hex("00112233445546778899aabbccddeeff");
      const std::vector<uint8_t> verifier_id = from_hex("10213243546547689a0b1c2d3e4f5061");
      const auto secret = Botan::SPAKE2p::ProverSecret::from_prehashed(*w0, *w1);
      Botan::AutoSeeded_RNG rng;
      const auto record = secret.registration_record(rng);
      Botan::SPAKE2p::ProverContext prover(parameters, secret, prover_id, verifier_id, context);
      Botan::SPAKE2p::VerifierContext verifier(parameters, record, prover_id, verifier_id, context);

      const auto share_p = prover.generate_message(rng);
      const bool prover_secret_before_confirmation_rejected = expect_throw([&] { (void)prover.shared_secret(); });
      const auto verifier_message = verifier.process_message(share_p, rng);
      const bool verifier_secret_before_confirmation_rejected = expect_throw([&] { (void)verifier.shared_secret(); });
      const auto confirm_p = prover.process_message(verifier_message, rng);
      verifier.verify_confirmation(confirm_p);
      const auto prover_shared = prover.shared_secret();
      const auto verifier_shared = verifier.shared_secret();

      auto corrupted = confirm_p;
      corrupted[0] ^= 1;
      Botan::SPAKE2p::VerifierContext negative_verifier(parameters, record, prover_id, verifier_id, context);
      const auto negative_response = negative_verifier.process_message(share_p, rng);
      (void)negative_response;
      const bool bad_confirmation_rejected = expect_throw([&] { negative_verifier.verify_confirmation(corrupted); });

      const bool pass = sha256_pass && hmac_pass && hkdf_pass && rfc_pass && parameters.share_size() == 65 &&
                        parameters.confirmation_size() == 32 && share_p.size() == 65 &&
                        verifier_message.size() == 97 && confirm_p.size() == 32 && prover_shared.size() == 32 &&
                        std::equal(prover_shared.begin(), prover_shared.end(), verifier_shared.begin(), verifier_shared.end()) &&
                        prover_secret_before_confirmation_rejected && verifier_secret_before_confirmation_rejected &&
                        bad_confirmation_rejected;
      std::cout << "{\"spake2p\":" << (pass ? "true" : "false")
                << ",\"sha256\":" << (sha256_pass ? "true" : "false")
                << ",\"hmac_sha256\":" << (hmac_pass ? "true" : "false")
                << ",\"hkdf_sha256\":" << (hkdf_pass ? "true" : "false")
                << ",\"rfc9383_appendix_c\":" << (rfc_pass ? "true" : "false")
                << ",\"share_size\":" << share_p.size() << ",\"verifier_message_size\":" << verifier_message.size()
                << ",\"confirm_size\":" << confirm_p.size()
                << ",\"shared_size\":" << prover_shared.size()
                << ",\"pre_confirmation_rejected\":"
                << ((prover_secret_before_confirmation_rejected && verifier_secret_before_confirmation_rejected) ? "true" : "false")
                << ",\"bad_confirmation_rejected\":" << (bad_confirmation_rejected ? "true" : "false") << "}\n";
      return pass ? 0 : 1;
   } catch(const std::exception& error) {
      std::cerr << error.what() << "\n";
      return 1;
   }
}
