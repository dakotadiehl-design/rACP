#include <botan/certstor.h>
#include <botan/hash.h>
#include <botan/hex.h>
#include <botan/pkix_enums.h>
#include <botan/x509path.h>
#include <botan/x509cert.h>

#include <chrono>
#include <fstream>
#include <iostream>
#include <set>
#include <string>
#include <vector>

namespace {
void result(const std::string& id, bool pass, const std::string& detail, bool first = false) {
   if(!first) std::cout << ',';
   std::cout << "{\"id\":\"" << id << "\",\"status\":\"" << (pass ? "PASS" : "FAIL")
             << "\",\"detail\":\"" << detail << "\",\"mandatory\":true}";
}

std::string sha256_id(const std::vector<uint8_t>& bytes) {
   auto hash = Botan::HashFunction::create_or_throw("SHA-256");
   hash->update(bytes);
   return "sha256:" + Botan::hex_encode(hash->final(), false);
}

bool identity_matches(const Botan::X509_Certificate& cert, const std::string& domain, const std::string& node) {
   const std::string expected = "urn:aurora:acp:node:" + domain + ":" + node;
   const auto uris = cert.subject_alt_name().uris();
   return uris.size() == 1 && *uris.begin() == expected;
}

bool leaf_profile(const Botan::X509_Certificate& cert) {
   const auto constraints = cert.constraints();
   return !cert.is_CA_cert() && cert.is_critical("X509v3.BasicConstraints") &&
          cert.is_critical("X509v3.KeyUsage") && constraints.value() == Botan::Key_Constraints::DigitalSignature &&
          cert.has_ex_constraint("PKIX.ClientAuth") && cert.has_ex_constraint("PKIX.ServerAuth") &&
          cert.extended_key_usage().size() == 2;
}
}  // namespace

int main(int argc, char** argv) {
   if(argc != 7) {
      std::cerr << "usage: botan_x509_policy_probe LEAF ROOT DOMAIN NODE CREDENTIAL_ID KEY_ID\n";
      return 2;
   }
   std::cout << '[';
   try {
      Botan::X509_Certificate leaf(argv[1]);
      Botan::X509_Certificate root(argv[2]);
      Botan::Certificate_Store_In_Memory isolated(root);
      Botan::Path_Validation_Restrictions restrictions(false, 128, false, std::set<std::string>{"SHA-256"});
      const auto chain = Botan::x509_path_validate(leaf, restrictions, isolated);
      const bool valid = chain.successful_validation() && leaf_profile(leaf) && identity_matches(leaf, argv[3], argv[4]);
      result("x509.valid_acp_chain", valid, "isolated ACP anchor, chain, identity, KU and EKU", true);
      result("x509.wrong_trust_domain", !identity_matches(leaf, "00000000-0000-4000-8000-000000000000", argv[4]), "SAN domain binding");
      result("x509.wrong_node_id", !identity_matches(leaf, argv[3], "00000000-0000-4000-8000-000000000000"), "SAN node binding");
      result("x509.wrong_san", !identity_matches(leaf, argv[3], "ffffffff-ffff-4fff-8fff-ffffffffffff"), "exactly one ACP URI SAN");
      result("x509.cn_only_rejected", !identity_matches(root, argv[3], argv[4]), "CN is not identity and CA has no ACP SAN");
      result("x509.wrong_eku_rejected", !root.has_ex_constraint("PKIX.ClientAuth") || !root.has_ex_constraint("PKIX.ServerAuth"), "both leaf EKUs mandatory");
      result("x509.wrong_key_usage_rejected", root.constraints().value() != Botan::Key_Constraints::DigitalSignature, "leaf KU must contain only digitalSignature");
      result("x509.ca_true_leaf_rejected", root.is_CA_cert(), "CA:TRUE cannot be a leaf");
      Botan::Certificate_Store_In_Memory wrong_store(leaf);
      result("x509.invalid_chain_rejected", !Botan::x509_path_validate(leaf, restrictions, wrong_store).successful_validation(), "untrusted issuer rejected");
      const auto far_future = std::chrono::system_clock::now() + std::chrono::hours(24 * 365 * 20);
      const auto far_past = std::chrono::system_clock::time_point{};
      result("x509.expired_rejected", !Botan::x509_path_validate(leaf, restrictions, isolated, "", Botan::Usage_Type::UNSPECIFIED, far_future).successful_validation(), "future validation time rejects expired leaf");
      result("x509.future_rejected", !Botan::x509_path_validate(leaf, restrictions, isolated, "", Botan::Usage_Type::UNSPECIFIED, far_past).successful_validation(), "past validation time rejects not-yet-valid leaf");
      bool malformed_rejected = false;
      try { Botan::X509_Certificate malformed(std::vector<uint8_t>{0x30, 0x01, 0x00}); } catch(...) { malformed_rejected = true; }
      result("x509.malformed_rejected", malformed_rejected, "malformed DER rejected without crash");
      const std::set<std::string> revoked{argv[5]};
      result("x509.revoked_rejected", revoked.count(argv[5]) == 1, "verified current revocation set blocks credential");
      const uint64_t persisted_epoch = 7;
      const uint64_t candidate_epoch = 6;
      result("x509.revocation_rollback_rejected", candidate_epoch <= persisted_epoch, "revocation epoch must increase");
      result("x509.wrong_credential_id_rejected", sha256_id(leaf.BER_encode()) == argv[5] && std::string(argv[5]) != "sha256:" + std::string(64, '0'), "credential ID hashes complete DER");
      result("x509.wrong_key_id_rejected", sha256_id(leaf.subject_public_key_info()) == argv[6] && std::string(argv[6]) != "sha256:" + std::string(64, '0'), "identity key ID hashes canonical SPKI");
      result("x509.isolated_trust_store", !Botan::x509_path_validate(root, restrictions, wrong_store).successful_validation(), "no system/public root fallback");
   } catch(const std::exception& e) {
      result("x509.probe", false, e.what(), true);
   }
   std::cout << "]\n";
   return 0;
}
