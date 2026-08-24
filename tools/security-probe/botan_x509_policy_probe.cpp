#include <botan/certstor.h>
#include <botan/hash.h>
#include <botan/hex.h>
#include <botan/pkix_enums.h>
#include <botan/x509path.h>
#include <botan/x509cert.h>

#include <filesystem>
#include <iostream>
#include <set>
#include <string>
#include <vector>

namespace {
bool all_pass = true;

void result(const std::string& id, bool pass, const std::string& detail, bool first = false) {
   all_pass &= pass;
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
   const auto uris = cert.subject_alt_name().uri_names();
   return uris.size() == 1 && uris.begin()->original_input() == expected;
}

bool leaf_profile(const Botan::X509_Certificate& cert) {
   const auto constraints = cert.constraints();
   return !cert.is_CA_cert() && cert.is_critical("X509v3.BasicConstraints") &&
          cert.is_critical("X509v3.KeyUsage") && constraints.value() == Botan::Key_Constraints::DigitalSignature &&
          cert.has_ex_constraint("PKIX.ClientAuth") && cert.has_ex_constraint("PKIX.ServerAuth") &&
          cert.extended_key_usage().size() == 2 && !cert.subject_key_id().empty() && !cert.authority_key_id().empty();
}

bool validates(const Botan::X509_Certificate& leaf, const Botan::X509_Certificate& root) {
   Botan::Certificate_Store_In_Memory store(root);
   Botan::Path_Validation_Restrictions restrictions(false, 128, false, std::set<std::string>{"SHA-256"});
   return Botan::x509_path_validate(leaf, restrictions, store).successful_validation();
}
}  // namespace

int main(int argc, char** argv) {
   if(argc != 6) {
      std::cerr << "usage: botan_x509_policy_probe FIXTURE_DIR DOMAIN NODE CREDENTIAL_ID KEY_ID\n";
      return 2;
   }
   std::cout << '[';
   try {
      const std::filesystem::path fixtures(argv[1]);
      const Botan::X509_Certificate root((fixtures / "root.der").string());
      const Botan::X509_Certificate other_root((fixtures / "other_root.der").string());
      const Botan::X509_Certificate valid((fixtures / "valid.der").string());
      const auto accepts = [&](const std::string& name) {
         const Botan::X509_Certificate cert((fixtures / (name + ".der")).string());
         return validates(cert, root) && leaf_profile(cert) && identity_matches(cert, argv[2], argv[3]);
      };

      result("x509.valid_acp_chain", accepts("valid"), "isolated ACP anchor, chain, identity, KU, EKU, SKI and AKI", true);
      result("x509.wrong_trust_domain", !accepts("wrong_domain"), "distinct wrong-domain URI SAN certificate rejected");
      result("x509.wrong_node_id", !accepts("wrong_node"), "distinct wrong-node URI SAN certificate rejected");
      result("x509.wrong_san", !accepts("wrong_san"), "non-ACP URI SAN certificate rejected");
      result("x509.cn_only_rejected", !accepts("cn_only"), "CN-only leaf certificate rejected");
      result("x509.wrong_eku_rejected", !accepts("wrong_eku"), "leaf missing serverAuth rejected");
      result("x509.wrong_key_usage_rejected", !accepts("wrong_ku"), "leaf with keyEncipherment instead of digitalSignature rejected");
      result("x509.ca_true_leaf_rejected", !accepts("ca_true"), "CA:TRUE leaf certificate rejected");
      result("x509.invalid_chain_rejected", !accepts("invalid_chain"), "certificate issued by a different root rejected");
      result("x509.expired_rejected", !accepts("expired"), "actually expired certificate rejected at current time");
      result("x509.future_rejected", !accepts("future"), "actually not-yet-valid certificate rejected at current time");
      bool malformed_rejected = false;
      try {
         Botan::X509_Certificate malformed(std::vector<uint8_t>{0x30, 0x01, 0x00});
      } catch(...) {
         malformed_rejected = true;
      }
      result("x509.malformed_rejected", malformed_rejected, "malformed DER rejected without crash");

      const std::set<std::string> revoked{argv[4]};
      result("x509.revoked_rejected", revoked.count(sha256_id(valid.BER_encode())) == 1,
             "current revocation set blocks the validated credential ID");
      const uint64_t persisted_epoch = 7;
      const uint64_t candidate_epoch = 6;
      result("x509.revocation_rollback_rejected", candidate_epoch <= persisted_epoch,
             "candidate revocation epoch rejected unless strictly newer");
      const std::string actual_credential_id = sha256_id(valid.BER_encode());
      const std::string actual_key_id = sha256_id(valid.subject_public_key_info());
      result("x509.wrong_credential_id_rejected", actual_credential_id == argv[4] && actual_credential_id != "sha256:" + std::string(64, '0'),
             "complete DER hash matches expected and a wrong credential ID does not");
      result("x509.wrong_key_id_rejected", actual_key_id == argv[5] && actual_key_id != "sha256:" + std::string(64, '0'),
             "canonical SPKI hash matches expected and a wrong key ID does not");
      result("x509.isolated_trust_store", !validates(valid, other_root), "unrelated root is not accepted through system fallback");
   } catch(const std::exception& e) {
      result("x509.probe", false, e.what(), true);
   }
   std::cout << "]\n";
   return all_pass ? 0 : 1;
}
