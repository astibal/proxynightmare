#include "pn/dsl.hpp"

#include <charconv>
#include <cctype>
#include <sstream>

namespace pn {
namespace {

std::string trim(std::string value) {
    auto space = [](unsigned char ch) { return std::isspace(ch) != 0; };
    while (!value.empty() && space(value.front())) value.erase(value.begin());
    while (!value.empty() && space(value.back())) value.pop_back();
    return value;
}

std::vector<std::string> words(const std::string& line, const SourceLocation& where) {
    std::vector<std::string> out;
    for (std::size_t i = 0; i < line.size();) {
        while (i < line.size() && std::isspace(static_cast<unsigned char>(line[i]))) ++i;
        if (i == line.size() || line[i] == '#') break;
        std::string token;
        if (line[i] == '"') {
            ++i;
            bool closed = false;
            while (i < line.size()) {
                char ch = line[i++];
                if (ch == '"') { closed = true; break; }
                if (ch == '\\') {
                    if (i == line.size()) throw ParseError(where, "unfinished escape");
                    const char escaped = line[i++];
                    switch (escaped) {
                        case 'n': token.push_back('\n'); break;
                        case 'r': token.push_back('\r'); break;
                        case 't': token.push_back('\t'); break;
                        case '\\': token.push_back('\\'); break;
                        case '"': token.push_back('"'); break;
                        default: throw ParseError(where, "unknown escape sequence");
                    }
                } else token.push_back(ch);
            }
            if (!closed) throw ParseError(where, "unterminated quoted string");
        } else {
            while (i < line.size() && !std::isspace(static_cast<unsigned char>(line[i]))) {
                if (line[i] == '#') break;
                token.push_back(line[i++]);
            }
        }
        if (!token.empty()) out.push_back(std::move(token));
    }
    return out;
}

std::chrono::milliseconds duration(const std::string& value, const SourceLocation& where) {
    std::size_t suffix = 0;
    while (suffix < value.size() && std::isdigit(static_cast<unsigned char>(value[suffix]))) ++suffix;
    if (suffix == 0) throw ParseError(where, "duration must start with a number");
    long long count{};
    const auto result = std::from_chars(value.data(), value.data() + suffix, count);
    if (result.ec != std::errc{} || count <= 0) throw ParseError(where, "invalid duration");
    const auto unit = value.substr(suffix);
    if (unit == "ms") return std::chrono::milliseconds(count);
    if (unit == "s") return std::chrono::seconds(count);
    if (unit == "m") return std::chrono::minutes(count);
    throw ParseError(where, "duration unit must be ms, s, or m");
}

Role to_role(const std::string& value, const SourceLocation& where) {
    if (value == "server") return Role::server;
    if (value == "client") return Role::client;
    throw ParseError(where, "expected server or client");
}

Op to_op(const std::string& value, const SourceLocation& where) {
    if (value == "listen") return Op::listen;
    if (value == "connect") return Op::connect;
    if (value == "receive-eot") return Op::receive_eot;
    if (value == "close") return Op::close;
    if (value == "transmit") return Op::transmit;
    if (value == "drain") return Op::drain;
    if (value == "await-tx") return Op::await_tx;
    if (value == "await-rx") return Op::await_rx;
    if (value == "set-sndbuf") return Op::set_sndbuf;
    if (value == "set-rcvbuf") return Op::set_rcvbuf;
    if (value == "half-close-write") return Op::half_close_write;
    if (value == "write-eot") return Op::half_close_write;
    if (value == "half-close-read") return Op::half_close_read;
    if (value == "sleep") return Op::sleep;
    if (value == "abort") return Op::abort;
    if (value == "reconnect") return Op::reconnect;
    if (value == "next-stream") return Op::next_stream;
    if (value == "handshake") return Op::handshake;
    if (value == "hello") return Op::hello;
    if (value == "encrypted-extensions") return Op::encrypted_extensions;
    if (value == "certificate") return Op::certificate;
    if (value == "certificate-request") return Op::certificate_request;
    if (value == "certificate-verify") return Op::certificate_verify;
    if (value == "finished") return Op::finished;
    if (value == "new-session-ticket") return Op::new_session_ticket;
    if (value == "key-update") return Op::key_update;
    if (value == "change-cipher-spec") return Op::change_cipher_spec;
    if (value == "close-notify") return Op::close_notify;
    throw ParseError(where, "unknown operation '" + value + "'");
}

} // namespace

ParseError::ParseError(SourceLocation where, const std::string& message)
    : std::runtime_error(where.file.string() + ":" + std::to_string(where.line) + ": " + message),
      where_(std::move(where)) {}

Test parse(const std::string& text, const std::filesystem::path& source) {
    enum class Section { start, preamble, body, final, done } section = Section::start;
    Test test;
    bool saw_preamble = false;
    bool saw_begin = false;
    bool parsing_pass = false;
    std::istringstream input(text);
    std::string line;
    std::size_t line_number = 0;
    while (std::getline(input, line)) {
        ++line_number;
        SourceLocation where{source, line_number};
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        const auto token = words(line, where);
        if (token.empty()) continue;

        if (section == Section::start) {
            if (token.size() != 1 || token[0] != "preamble")
                throw ParseError(where, "test must start with preamble");
            section = Section::preamble;
            saw_preamble = true;
            continue;
        }
        if (section == Section::preamble) {
            if (token.size() == 3 && token[0] == "begin" && token[1] == "using") {
                if (token[2] == "tcp") test.transport = Transport::tcp;
                else if (token[2] == "udp") test.transport = Transport::udp;
                else if (token[2] == "tls") test.transport = Transport::tls;
                else if (token[2] == "quic") test.transport = Transport::quic;
                else throw ParseError(where, "transport must be tcp, udp, tls, or quic");
                section = Section::body;
                saw_begin = true;
                continue;
            }
            if (token.size() != 2) throw ParseError(where, "metadata is: key \"value\"");
            if (token[0] == "timeout") test.timeout = duration(token[1], where);
            else test.metadata[token[0]] = token[1];
            continue;
        }
        if (section == Section::body) {
            if (token.size() == 1 && token[0] == "end") {
                section = Section::final;
                continue;
            }
            const Role role = to_role(token[0], where);
            if (token.size() >= 2 && token[1] == "at") {
                if (token.size() != 3) throw ParseError(where, "role declaration is: role at target");
                auto& target = role == Role::server ? test.server_target : test.client_target;
                if (!target.empty()) throw ParseError(where, "role target declared twice");
                target = token[2];
                continue;
            }
            if (token.size() < 2) throw ParseError(where, "missing operation");
            Step step{role, to_op(token[1], where), {}, std::nullopt, where};
            switch (step.op) {
                case Op::listen:
                case Op::connect:
                    if (token.size() != 3) throw ParseError(where, "operation requires one argument");
                    step.argument = token[2];
                    break;
                case Op::transmit:
                case Op::drain: {
                    if (token.size() < 5 || token[3] != "stamp-every")
                        throw ParseError(where, "stream is: transmit|drain SIZE stamp-every SIZE [chunk SIZE] [delay DURATION]");
                    for (std::size_t i = 2; i < token.size(); ++i) {
                        if (i != 2) step.argument.push_back(' ');
                        step.argument += token[i];
                    }
                    break;
                }
                case Op::set_sndbuf:
                case Op::set_rcvbuf:
                case Op::sleep:
                    if (token.size() != 3) throw ParseError(where, "operation requires one argument");
                    step.argument = token[2];
                    break;
                default:
                    if (token.size() != 2) throw ParseError(where, "operation takes no argument");
            }
            test.steps.push_back(std::move(step));
            continue;
        }
        if (section == Section::final) {
            if (token.size() == 1 && token[0] == "end") {
                section = Section::done;
                continue;
            }
            if (token[0] == "outcome") {
                parsing_pass = false;
                if (token.size() == 2 && token[1] == "pass") parsing_pass = true;
                else if (token.size() == 3 && token[1] == "fail") test.fail_outcome = token[2];
                else if (token.size() == 3 && token[1] == "timeout") test.timeout_outcome = token[2];
                else throw ParseError(where, "use outcome pass, outcome fail \"text\", or outcome timeout \"text\"");
                continue;
            }
            if (!parsing_pass) throw ParseError(where, "content must belong to outcome pass");
            if (token[0] == "describe") {
                if (token.size() != 2) throw ParseError(where, "describe requires one quoted string");
                test.pass_outcome.description = token[1];
                continue;
            }
            if ((token[0] == "when" || token[0] == "and") && token.size() == 4) {
                if (token[2] != "==" && token[2] != "!=")
                    throw ParseError(where, "outcome comparison must be == or !=");
                test.pass_outcome.conditions.push_back({token[1], token[2], token[3], where});
                continue;
            }
            throw ParseError(where, "pass clause is: when|and METRIC ==|!= VALUE, or describe \"text\"");
        }
        throw ParseError(where, "content after final end");
    }
    SourceLocation eof{source, line_number + 1};
    if (!saw_preamble || !saw_begin) throw ParseError(eof, "incomplete test header");
    if (section != Section::done) throw ParseError(eof, "test must end with final outcome block and end");
    if (test.server_target.empty() || test.client_target.empty())
        throw ParseError(eof, "both server and client must have an at declaration");
    if (!test.metadata.contains("name"))
        throw ParseError(eof, "preamble requires name metadata");
    if (test.pass_outcome.conditions.empty() || test.pass_outcome.description.empty())
        throw ParseError(eof, "outcome pass requires conditions and a description");
    if (test.timeout_outcome.empty()) throw ParseError(eof, "outcome timeout is required");
    if (test.steps.empty()) throw ParseError(eof, "test has no steps");
    for (const auto& step : test.steps) {
        const bool is_tls_phase = step.op == Op::handshake ||
                                  (step.op >= Op::hello && step.op <= Op::close_notify);
        if (step.op == Op::handshake && test.transport != Transport::tls && test.transport != Transport::quic)
            throw ParseError(step.where, "handshake requires begin using tls or quic");
        if (step.op != Op::handshake && is_tls_phase && test.transport != Transport::tls)
            throw ParseError(step.where, op_name(step.op) + " requires begin using tls");
        if (step.op == Op::reconnect && test.transport != Transport::udp)
            throw ParseError(step.where, "reconnect requires begin using udp");
        if (step.op == Op::next_stream && test.transport != Transport::quic)
            throw ParseError(step.where, "next-stream requires begin using quic");
    }
    return test;
}

std::string role_name(Role role) { return role == Role::server ? "server" : "client"; }

std::string op_name(Op op) {
    switch (op) {
        case Op::listen: return "listen";
        case Op::connect: return "connect";
        case Op::receive_eot: return "receive-eot";
        case Op::close: return "close";
        case Op::transmit: return "transmit";
        case Op::drain: return "drain";
        case Op::await_tx: return "await-tx";
        case Op::await_rx: return "await-rx";
        case Op::set_sndbuf: return "set-sndbuf";
        case Op::set_rcvbuf: return "set-rcvbuf";
        case Op::half_close_write: return "half-close-write";
        case Op::half_close_read: return "half-close-read";
        case Op::sleep: return "sleep";
        case Op::abort: return "abort";
        case Op::reconnect: return "reconnect";
        case Op::next_stream: return "next-stream";
        case Op::handshake: return "handshake";
        case Op::hello: return "hello";
        case Op::encrypted_extensions: return "encrypted-extensions";
        case Op::certificate: return "certificate";
        case Op::certificate_request: return "certificate-request";
        case Op::certificate_verify: return "certificate-verify";
        case Op::finished: return "finished";
        case Op::new_session_ticket: return "new-session-ticket";
        case Op::key_update: return "key-update";
        case Op::change_cipher_spec: return "change-cipher-spec";
        case Op::close_notify: return "close-notify";
    }
    return "unknown";
}

std::string transport_name(Transport transport) {
    switch (transport) {
        case Transport::tcp: return "tcp";
        case Transport::udp: return "udp";
        case Transport::tls: return "tls";
        case Transport::quic: return "quic";
    }
    return "unknown";
}

} // namespace pn
