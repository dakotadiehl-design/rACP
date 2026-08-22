#include <botan/auto_rng.h>
#include <botan/certstor.h>
#include <botan/credentials_manager.h>
#include <botan/data_src.h>
#include <botan/pkcs8.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_client.h>
#include <botan/tls_policy.h>
#include <botan/tls_server.h>
#include <botan/tls_session.h>
#include <botan/tls_session_manager_noop.h>
#include <botan/x509cert.h>

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace {

class ACPPolicy final : public Botan::TLS::Policy {
   public:
      bool allow_tls12() const override { return false; }
      bool allow_tls13() const override { return true; }
      bool require_cert_revocation_info() const override { return false; }
      bool require_client_certificate_authentication() const override { return true; }
      bool request_client_certificate_authentication() const override { return true; }
      size_t new_session_tickets_upon_handshake_success() const override { return 0; }
};

class Credentials final : public Botan::Credentials_Manager {
   public:
      Credentials(const std::string& leaf_path, const std::string& root_path, const std::string& key_path) :
            m_leaf(leaf_path), m_root(root_path), m_store(m_root) {
         Botan::DataSource_Stream key_source(key_path);
         m_key = std::shared_ptr<Botan::Private_Key>(Botan::PKCS8::load_key(key_source).release());
      }

      std::vector<Botan::Certificate_Store*> trusted_certificate_authorities(const std::string&,
                                                                              const std::string&) override {
         return {&m_store};
      }

      std::vector<Botan::X509_Certificate> find_cert_chain(
         const std::vector<std::string>&,
         const std::vector<Botan::AlgorithmIdentifier>&,
         const std::vector<Botan::X509_DN>&,
         const std::string&,
         const std::string&) override {
         return {m_leaf};
      }

      std::shared_ptr<Botan::Private_Key> private_key_for(const Botan::X509_Certificate&,
                                                          const std::string&,
                                                          const std::string&) override {
         return m_key;
      }

   private:
      Botan::X509_Certificate m_leaf;
      Botan::X509_Certificate m_root;
      Botan::Certificate_Store_In_Memory m_store;
      std::shared_ptr<Botan::Private_Key> m_key;
};

class Callbacks final : public Botan::TLS::Callbacks {
   public:
      void tls_emit_data(std::span<const uint8_t> data) override { outgoing.insert(outgoing.end(), data.begin(), data.end()); }
      void tls_record_received(uint64_t, std::span<const uint8_t> data) override {
         application_data.insert(application_data.end(), data.begin(), data.end());
      }
      void tls_alert(Botan::TLS::Alert) override {}
      void tls_verify_cert_chain(
         const std::vector<Botan::X509_Certificate>& cert_chain,
         const std::vector<std::optional<Botan::OCSP::Response>>& ocsp_responses,
         const std::vector<Botan::Certificate_Store*>& trusted_roots,
         Botan::Usage_Type usage,
         std::string_view hostname,
         const Botan::TLS::Policy& policy) override {
         Botan::TLS::Callbacks::tls_verify_cert_chain(
            cert_chain, ocsp_responses, trusted_roots, usage, hostname, policy);
         verified_certificate_count = cert_chain.size();
      }
      void tls_session_established(const Botan::TLS::Session_Summary& summary) override {
         established = true;
         peer_certificate_count = summary.peer_certs().size();
      }

      std::vector<uint8_t> take() {
         std::vector<uint8_t> result;
         result.swap(outgoing);
         return result;
      }

      std::vector<uint8_t> outgoing;
      std::vector<uint8_t> application_data;
      bool established = false;
      size_t peer_certificate_count = 0;
      size_t verified_certificate_count = 0;
};

void pump(Botan::TLS::Client& client,
          Botan::TLS::Server& server,
          const std::shared_ptr<Callbacks>& client_callbacks,
          const std::shared_ptr<Callbacks>& server_callbacks) {
   for(size_t round = 0; round != 100; ++round) {
      const auto to_server = client_callbacks->take();
      if(!to_server.empty()) {
         server.from_peer(to_server);
      }
      const auto to_client = server_callbacks->take();
      if(!to_client.empty()) {
         client.from_peer(to_client);
      }
      if(client.is_active() && server.is_active() && client_callbacks->outgoing.empty() &&
         server_callbacks->outgoing.empty()) {
         return;
      }
   }
   throw std::runtime_error("TLS in-memory handshake did not quiesce");
}

}  // namespace

int main(int argc, char** argv) {
   if(argc != 4) {
      std::cerr << "usage: botan_tls_probe LEAF ROOT PRIVATE_KEY\n";
      return 2;
   }
   try {
      auto credentials = std::make_shared<Credentials>(argv[1], argv[2], argv[3]);
      auto policy = std::make_shared<ACPPolicy>();
      auto sessions = std::make_shared<Botan::TLS::Session_Manager_Noop>();
      auto client_rng = std::make_shared<Botan::AutoSeeded_RNG>();
      auto server_rng = std::make_shared<Botan::AutoSeeded_RNG>();
      auto client_callbacks = std::make_shared<Callbacks>();
      auto server_callbacks = std::make_shared<Callbacks>();
      Botan::TLS::Server server(server_callbacks, sessions, credentials, policy, server_rng);
      Botan::TLS::Client client(client_callbacks,
                                sessions,
                                credentials,
                                policy,
                                client_rng,
                                Botan::TLS::Server_Information(),
                                Botan::TLS::Protocol_Version::TLS_V13);
      pump(client, server, client_callbacks, server_callbacks);
      const auto client_chain = client.peer_cert_chain();
      const auto server_chain = server.peer_cert_chain();
      const std::string label = "EXPORTER-Aurora-ACP-1.2-HELLO";
      const std::string context(32, '\xA5');
      const auto client_exporter = client.key_material_export(label, context, 32).bits_of();
      const auto server_exporter = server.key_material_export(label, context, 32).bits_of();
      const bool exporter_equal = client_exporter == server_exporter;
      const bool pass = client.is_active() && server.is_active() && client_callbacks->established &&
                        server_callbacks->established && client_callbacks->verified_certificate_count >= 1 &&
                        server_callbacks->verified_certificate_count >= 1 &&
                        exporter_equal && client_exporter.size() == 32;
      std::cout << "{\"tls13\":" << (pass ? "true" : "false")
                << ",\"client_peer_certificates\":" << client_chain.size()
                << ",\"server_peer_certificates\":" << server_chain.size()
                << ",\"client_summary_peer_certificates\":" << client_callbacks->peer_certificate_count
                << ",\"server_summary_peer_certificates\":" << server_callbacks->peer_certificate_count
                << ",\"client_verified_certificates\":" << client_callbacks->verified_certificate_count
                << ",\"server_verified_certificates\":" << server_callbacks->verified_certificate_count
                << ",\"exporter_equal\":" << (exporter_equal ? "true" : "false")
                << ",\"exporter_length\":" << client_exporter.size()
                << ",\"policy_requires_client_auth\":"
                << (policy->require_client_certificate_authentication() ? "true" : "false")
                << ",\"session_manager\":\"noop\",\"tickets_issued\":0}\n";
      return pass ? 0 : 1;
   } catch(const std::exception& error) {
      std::cerr << error.what() << "\n";
      return 1;
   }
}
