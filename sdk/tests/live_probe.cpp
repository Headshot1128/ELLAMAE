#include "secureauth/client.hpp"
#include <iostream>
#include <stdexcept>

// A syntactically valid Windows SID for testing (not tied to any real account).
static const std::string kTestSid = "S-1-5-21-0000000001-0000000001-0000000001-1000";

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    const std::string base = argv[1];
    // SID is required — Initialize() rejects an empty hardware string.
    secureauth::Client client(base, kTestSid);
    if (!client.Initialize()) throw std::runtime_error("Invalid HTTPS origin or hardware ID");
    const auto result = client.Login("sdk-live-probe-unknown", "not a real account password");
    if (result.success || result.error != secureauth::Error::AuthenticationFailed)
        throw std::runtime_error("Expected server authentication rejection over trusted TLS");
    secureauth::CurlTransport transport;
    for (const auto* path : {"/v1/variables/premium_feature", "/v1/files/protected-file/content"}) {
        const auto response = transport.Send("GET", base + path, "", "", "");
        if (!response.network_ok || response.status != 401)
            throw std::runtime_error("Unauthenticated resource was not rejected with HTTP 401");
    }
    std::cout << "Live C++ HTTPS: certificate verified; invalid login and unauthenticated variable/file access rejected.\n";
}
