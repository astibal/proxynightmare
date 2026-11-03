#pragma once

#include <chrono>
#include <cstddef>
#include <filesystem>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace pn {

struct SourceLocation {
    std::filesystem::path file;
    std::size_t line{};
};

class ParseError : public std::runtime_error {
public:
    ParseError(SourceLocation where, const std::string& message);
    [[nodiscard]] const SourceLocation& where() const noexcept { return where_; }
private:
    SourceLocation where_;
};

enum class Role { server, client };
enum class Transport { tcp, udp, tls, quic };
enum class Op {
    listen,
    connect,
    receive_eot,
    close,
    transmit,
    drain,
    await_tx,
    await_rx,
    set_sndbuf,
    set_rcvbuf,
    half_close_write,
    half_close_read,
    sleep,
    abort,
    reconnect,
    next_stream,
    handshake,
    hello,
    encrypted_extensions,
    certificate,
    certificate_request,
    certificate_verify,
    finished,
    new_session_ticket,
    key_update,
    change_cipher_spec,
    close_notify
};

struct Step {
    Role role{};
    Op op{};
    std::string argument;
    std::optional<std::size_t> size;
    SourceLocation where;
};

struct Condition {
    std::string metric;
    std::string comparison;
    std::string expected;
    SourceLocation where;
};

struct PassOutcome {
    std::vector<Condition> conditions;
    std::string description;
};

struct Test {
    std::map<std::string, std::string> metadata;
    std::chrono::milliseconds timeout{10000};
    Transport transport{Transport::tcp};
    std::string server_target;
    std::string client_target;
    std::vector<Step> steps;
    PassOutcome pass_outcome;
    std::string fail_outcome;
    std::string timeout_outcome;
};

[[nodiscard]] Test parse(const std::string& text,
                         const std::filesystem::path& source = "<input>");
[[nodiscard]] std::string role_name(Role role);
[[nodiscard]] std::string op_name(Op op);
[[nodiscard]] std::string transport_name(Transport transport);

} // namespace pn
