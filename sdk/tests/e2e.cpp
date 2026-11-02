#include "secureauth/client.hpp"
#include <cstdlib>
#include <iostream>
#include <stdexcept>
using namespace secureauth;
void check(bool value) { if (!value) throw std::runtime_error("TLS integration test failed"); }

// Synthetic Windows SID-format strings — unique per "machine" so tests stay isolated.
static const std::string kSidAlice = "S-1-5-21-1111111111-2222222222-3333333333-1001";
static const std::string kSidOther = "S-1-5-21-1111111111-2222222222-3333333333-9999";

int main(int argc, char** argv) {
    if (argc != 3) return 2;
    auto tls = std::make_shared<CurlTransport>(argv[2]);
    // SID is required for Initialize() and Login() — pass kSidAlice as hardware.
    Client client(argv[1], kSidAlice, tls);
    check(client.Initialize());
    const std::string password = "correct horse battery staple";
    // Login before registration must fail (wrong credentials / no hardware binding yet).
    check(!client.Login("alice", "incorrect password").success);
    check(!client.DownloadFile("protected-file").success);
    // Register without a license key — sends hardware_id in body automatically.
    check(!client.Register("alice", password).success);   // alice may already exist; that's OK
    check(client.GetState() == State::Unauthenticated);
    check(client.Register("cpp-created", password).success);
    check(client.GetState() == State::Unauthenticated);
    // Login with correct credentials + matching SID.
    check(client.Login("alice", password).success);
    check(client.IsSessionValid());
    auto variable = client.GetVariable("premium_feature");
    check(variable.success && variable.value == "enabled");
    check(!client.GetVariable("secret").success);
    check(!client.DownloadFile("secret-file").success);
    auto file = client.DownloadFile("protected-file");
    check(file.success && std::string(file.bytes.begin(), file.bytes.end()) == std::string("private\0payload", 15));
    check(client.RefreshSession().success);
    check(client.IsSessionValid());
    check(client.Logout().success);
    check(!client.GetVariable("premium_feature").success);
    // A different SID should be rejected (hardware_mismatch) after alice is bound.
    Client wrong_sid(argv[1], kSidOther, tls);
    check(wrong_sid.Initialize());
    check(!wrong_sid.Login("alice", password).success);   // bound to kSidAlice, not kSidOther
    // An untrusted self-signed server must be rejected by the default transport.
    Client untrusted(argv[1], kSidAlice);
    check(untrusted.Initialize());
    check(untrusted.Login("alice", password).error == Error::NetworkFailure);
    std::cout << "C++ SDK to FastAPI TLS integration passed\n";
}
