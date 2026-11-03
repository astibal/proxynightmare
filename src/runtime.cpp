#include "pn/runtime.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <future>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/quic.h>
#include <openssl/x509.h>

#include <array>
#include <charconv>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <unordered_map>
#include <vector>
#include <thread>

namespace pn {
namespace {

using Clock = std::chrono::steady_clock;

std::string hex_encode(const std::string& value) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(value.size() * 2);
    for (unsigned char ch : value) {
        out.push_back(digits[ch >> 4]);
        out.push_back(digits[ch & 15]);
    }
    return out;
}

std::string hex_decode(const std::string& value) {
    if (value.size() % 2 != 0) throw std::runtime_error("invalid hex payload");
    auto nibble = [](char ch) -> int {
        if (ch >= '0' && ch <= '9') return ch - '0';
        if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
        if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
        throw std::runtime_error("invalid hex payload");
    };
    std::string out(value.size() / 2, '\0');
    for (std::size_t i = 0; i < out.size(); ++i)
        out[i] = static_cast<char>((nibble(value[2 * i]) << 4) | nibble(value[2 * i + 1]));
    return out;
}

void write_all(int fd, const std::string& data) {
    std::size_t offset = 0;
    while (offset < data.size()) {
        const ssize_t count = ::write(fd, data.data() + offset, data.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) throw std::runtime_error("agent pipe write failed: " + std::string(std::strerror(errno)));
        offset += static_cast<std::size_t>(count);
    }
}

struct Response { std::string kind; std::string payload; };

class AgentProcess {
public:
    AgentProcess(const std::string& target, const RunOptions& options) {
        int to_child[2]{};
        int from_child[2]{};
        if (::pipe(to_child) != 0 || ::pipe(from_child) != 0)
            throw std::runtime_error("cannot create agent pipes");
        pid_ = ::fork();
        if (pid_ < 0) throw std::runtime_error("cannot fork agent");
        if (pid_ == 0) {
            ::dup2(to_child[0], STDIN_FILENO);
            ::dup2(from_child[1], STDOUT_FILENO);
            ::close(to_child[0]); ::close(to_child[1]);
            ::close(from_child[0]); ::close(from_child[1]);
            if (target == "local") {
                ::execlp(options.local_executable.c_str(), options.local_executable.c_str(), "--agent", nullptr);
            } else if (target.starts_with("netns:")) {
                const auto name = target.substr(6);
                const auto valid = !name.empty() && std::all_of(name.begin(), name.end(), [](unsigned char ch) {
                    return std::isalnum(ch) || ch == '_' || ch == '.' || ch == '-';
                });
                if (!valid) _exit(126);
                ::execlp("ip", "ip", "netns", "exec", name.c_str(),
                         options.local_executable.c_str(), "--agent", nullptr);
            } else {
                ::execlp(options.ssh.c_str(), options.ssh.c_str(), "-T", target.c_str(),
                         options.remote_executable.c_str(), "--agent", nullptr);
            }
            _exit(127);
        }
        ::close(to_child[0]);
        ::close(from_child[1]);
        input_ = to_child[1];
        output_ = from_child[0];
    }

    AgentProcess(const AgentProcess&) = delete;
    AgentProcess& operator=(const AgentProcess&) = delete;

    ~AgentProcess() {
        if (input_ >= 0) ::close(input_);
        if (output_ >= 0) ::close(output_);
        if (pid_ > 0) {
            int status{};
            if (::waitpid(pid_, &status, WNOHANG) == 0) {
                ::kill(pid_, SIGTERM);
                ::waitpid(pid_, &status, 0);
            }
        }
    }

    Response request(const std::string& command, const std::string& argument,
                     Clock::time_point deadline) {
        write_all(input_, command + "\t" + hex_encode(argument) + "\n");
        std::string line;
        for (;;) {
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now());
            if (remaining.count() <= 0) throw std::runtime_error("TIMEOUT");
            pollfd descriptor{output_, POLLIN | POLLHUP, 0};
            const int timeout = static_cast<int>(std::min<long long>(remaining.count(), 1000));
            const int ready = ::poll(&descriptor, 1, timeout);
            if (ready < 0 && errno == EINTR) continue;
            if (ready < 0) throw std::runtime_error("agent poll failed");
            if (ready == 0) continue;
            char ch{};
            const ssize_t count = ::read(output_, &ch, 1);
            if (count == 0) throw std::runtime_error("agent exited unexpectedly");
            if (count < 0 && errno == EINTR) continue;
            if (count < 0) throw std::runtime_error("agent pipe read failed");
            if (ch == '\n') break;
            line.push_back(ch);
        }
        const auto tab = line.find('\t');
        const std::string kind = line.substr(0, tab);
        const std::string payload = tab == std::string::npos ? std::string{} : hex_decode(line.substr(tab + 1));
        return {kind, payload};
    }

private:
    pid_t pid_{-1};
    int input_{-1};
    int output_{-1};
};

std::pair<std::string, std::string> split_endpoint(const std::string& endpoint) {
    if (!endpoint.empty() && endpoint.front() == '[') {
        const auto close = endpoint.find(']');
        if (close == std::string::npos || close + 2 > endpoint.size() || endpoint[close + 1] != ':')
            throw std::runtime_error("endpoint must be [IPv6]:port");
        return {endpoint.substr(1, close - 1), endpoint.substr(close + 2)};
    }
    const auto colon = endpoint.rfind(':');
    if (colon == std::string::npos) throw std::runtime_error("endpoint must be host:port");
    return {endpoint.substr(0, colon), endpoint.substr(colon + 1)};
}

int make_socket(const std::string& endpoint, bool passive, int socket_type = SOCK_STREAM) {
    const auto [host, port] = split_endpoint(endpoint);
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = socket_type;
    hints.ai_flags = passive ? AI_PASSIVE : 0;
    addrinfo* addresses = nullptr;
    const int lookup = ::getaddrinfo(host.empty() ? nullptr : host.c_str(), port.c_str(), &hints, &addresses);
    if (lookup != 0) throw std::runtime_error(::gai_strerror(lookup));
    std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> guard(addresses, freeaddrinfo);
    int fd = -1;
    for (auto* address = addresses; address != nullptr; address = address->ai_next) {
        fd = ::socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (fd < 0) continue;
        if (passive) {
            int yes = 1;
            ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
            if (::bind(fd, address->ai_addr, address->ai_addrlen) == 0) {
                if (socket_type == SOCK_DGRAM || ::listen(fd, 1) == 0) return fd;
            }
        } else if (::connect(fd, address->ai_addr, address->ai_addrlen) == 0) return fd;
        ::close(fd);
        fd = -1;
    }
    throw std::runtime_error(std::string(passive ? "listen" : "connect") + " failed: " + std::strerror(errno));
}

bool tls_operation(Op op) {
    return op >= Op::hello && op <= Op::close_notify;
}

std::string recv_exact(int fd, std::size_t wanted);
void send_all(int fd, const std::string& data);

std::string ssl_errors() {
    std::string result;
    for (unsigned long code; (code = ERR_get_error()) != 0;) {
        if (!result.empty()) result += "; ";
        result += ERR_error_string(code, nullptr);
    }
    return result.empty() ? "unknown OpenSSL error" : result;
}

std::string tls_event_name(int content_type, const void* buffer, std::size_t length) {
    const auto* bytes = static_cast<const unsigned char*>(buffer);
    if (content_type == SSL3_RT_HANDSHAKE && length > 0) {
        switch (bytes[0]) {
            case SSL3_MT_CLIENT_HELLO: return "client-hello";
            case SSL3_MT_SERVER_HELLO: return "server-hello";
            case SSL3_MT_NEWSESSION_TICKET: return "new-session-ticket";
            case SSL3_MT_ENCRYPTED_EXTENSIONS: return "encrypted-extensions";
            case SSL3_MT_CERTIFICATE: return "certificate";
            case SSL3_MT_CERTIFICATE_REQUEST: return "certificate-request";
            case SSL3_MT_CERTIFICATE_VERIFY: return "certificate-verify";
            case SSL3_MT_FINISHED: return "finished";
            case SSL3_MT_KEY_UPDATE: return "key-update";
            default: return {};
        }
    }
    if (content_type == SSL3_RT_CHANGE_CIPHER_SPEC) return "change-cipher-spec";
    if (content_type == SSL3_RT_ALERT && length >= 2 && bytes[1] == SSL_AD_CLOSE_NOTIFY)
        return "close-notify";
    return {};
}

class TlsEngine {
public:
    explicit TlsEngine(bool client) : client_(client) {
        ctx_ = SSL_CTX_new(TLS_method());
        if (!ctx_) throw std::runtime_error(ssl_errors());
        SSL_CTX_set_min_proto_version(ctx_, TLS1_3_VERSION);
        SSL_CTX_set_max_proto_version(ctx_, TLS1_3_VERSION);
        if (!client_) {
            SSL_CTX_set_num_tickets(ctx_, 1);
            install_certificate();
        }
        ssl_ = SSL_new(ctx_);
        if (!ssl_) throw std::runtime_error(ssl_errors());
        BIO* read_bio = BIO_new(BIO_s_mem());
        BIO* write_bio = BIO_new(BIO_s_mem());
        if (!read_bio || !write_bio) throw std::runtime_error(ssl_errors());
        SSL_set_bio(ssl_, read_bio, write_bio);
        if (client_) {
            SSL_set_connect_state(ssl_);
            SSL_set_verify(ssl_, SSL_VERIFY_NONE, nullptr);
        } else SSL_set_accept_state(ssl_);
        SSL_set_msg_callback(ssl_, &TlsEngine::message_callback);
        SSL_set_msg_callback_arg(ssl_, this);
    }

    ~TlsEngine() {
        if (ssl_) SSL_free(ssl_);
        if (ctx_) SSL_CTX_free(ctx_);
    }

    TlsEngine(const TlsEngine&) = delete;
    TlsEngine& operator=(const TlsEngine&) = delete;

    void send_phase(int fd, const std::string& expected) {
        if (expected == "close-notify") {
            const int result = SSL_shutdown(ssl_);
            if (result < 0) check_ssl_result(result);
            drain_records();
        } else if (expected == "key-update" && out_events_.empty()) {
            if (SSL_key_update(ssl_, SSL_KEY_UPDATE_NOT_REQUESTED) != 1)
                throw std::runtime_error("cannot schedule TLS KeyUpdate: " + ssl_errors());
            drive();
        } else {
            drive();
        }
        if (out_events_.empty() || out_events_.front() != expected)
            throw std::runtime_error("OpenSSL next outbound phase is " +
                (out_events_.empty() ? std::string("<none>") : out_events_.front()) + ", not " + expected);
        out_events_.pop_front();
        if (!out_records_.empty()) {
            send_all(fd, out_records_.front());
            out_records_.pop_front();
        }
    }

    void receive_phase(int fd, const std::string& expected) {
        while (in_events_.empty()) {
            const auto header = recv_exact(fd, 5);
            const auto length = (static_cast<unsigned char>(header[3]) << 8) |
                                static_cast<unsigned char>(header[4]);
            const auto record = header + recv_exact(fd, length);
            if (BIO_write(SSL_get_rbio(ssl_), record.data(), static_cast<int>(record.size())) <= 0)
                throw std::runtime_error(ssl_errors());
            if (complete()) {
                char byte{};
                std::size_t read_bytes{};
                const int result = SSL_read_ex(ssl_, &byte, 1, &read_bytes);
                if (result != 1) {
                    const int error = SSL_get_error(ssl_, result);
                    if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_ZERO_RETURN)
                        throw std::runtime_error("TLS post-handshake processing failed: " + ssl_errors());
                }
                drain_records();
            } else drive();
        }
        if (in_events_.front() != expected)
            throw std::runtime_error("OpenSSL received " + in_events_.front() + ", expected " + expected);
        in_events_.pop_front();
    }

    [[nodiscard]] bool complete() const { return SSL_is_init_finished(ssl_) == 1; }

    void handshake(int fd) {
        while (!complete()) {
            ERR_clear_error();
            const int result = SSL_do_handshake(ssl_);
            const int error = result == 1 ? SSL_ERROR_NONE : SSL_get_error(ssl_, result);
            drain_records();
            flush_records(fd);
            if (complete()) break;
            if (error == SSL_ERROR_WANT_WRITE) continue;
            if (error != SSL_ERROR_WANT_READ)
                throw std::runtime_error("TLS handshake failed: " + ssl_errors());
            const auto header = recv_exact(fd, 5);
            const auto length = (static_cast<unsigned char>(header[3]) << 8) |
                                static_cast<unsigned char>(header[4]);
            const auto record = header + recv_exact(fd, length);
            if (BIO_write(SSL_get_rbio(ssl_), record.data(), static_cast<int>(record.size())) <= 0)
                throw std::runtime_error(ssl_errors());
        }
        // Autonomous mode consumes the complete handshake as one operation;
        // its per-phase trace events must not leak into later post-handshake
        // operations such as KeyUpdate or close_notify.
        in_events_.clear();
        out_events_.clear();
    }

    void write_application(int fd, const std::string& data) {
        std::lock_guard lock(io_mutex_);
        if (!complete()) throw std::runtime_error("TLS application write before handshake completion");
        std::size_t written{};
        if (SSL_write_ex(ssl_, data.data(), data.size(), &written) != 1 || written != data.size())
            throw std::runtime_error("TLS application write failed: " + ssl_errors());
        drain_records();
        flush_records(fd);
    }

    std::string read_application(int fd, std::size_t wanted) {
        if (!complete()) throw std::runtime_error("TLS application read before handshake completion");
        std::string result(wanted, '\0');
        std::size_t offset = 0;
        while (offset < wanted) {
            bool need_record = false;
            {
                std::lock_guard lock(io_mutex_);
                std::size_t received{};
                const int ok = SSL_read_ex(ssl_, result.data() + offset, wanted - offset, &received);
                if (ok == 1) offset += received;
                else {
                    const int error = SSL_get_error(ssl_, ok);
                    if (error == SSL_ERROR_WANT_READ) need_record = true;
                    else if (error == SSL_ERROR_ZERO_RETURN)
                        throw std::runtime_error("TLS close_notify before expected application bytes");
                    else throw std::runtime_error("TLS application read failed: " + ssl_errors());
                }
                drain_records();
                flush_records(fd);
            }
            if (need_record) {
                const auto header = recv_exact(fd, 5);
                const auto length = (static_cast<unsigned char>(header[3]) << 8) |
                                    static_cast<unsigned char>(header[4]);
                const auto record = header + recv_exact(fd, length);
                std::lock_guard lock(io_mutex_);
                if (BIO_write(SSL_get_rbio(ssl_), record.data(), static_cast<int>(record.size())) <= 0)
                    throw std::runtime_error(ssl_errors());
            }
        }
        return result;
    }

private:
    static void message_callback(int write_p, int, int content_type, const void* buffer,
                                 std::size_t length, SSL*, void* argument) {
        auto& self = *static_cast<TlsEngine*>(argument);
        auto event = tls_event_name(content_type, buffer, length);
        if (event.empty()) return;
        (write_p ? self.out_events_ : self.in_events_).push_back(std::move(event));
    }

    void install_certificate() {
        EVP_PKEY* key = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "prime256v1");
        if (!key) throw std::runtime_error(ssl_errors());
        X509* cert = X509_new();
        if (!cert) { EVP_PKEY_free(key); throw std::runtime_error(ssl_errors()); }
        X509_set_version(cert, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
        X509_gmtime_adj(X509_get_notBefore(cert), -60);
        X509_gmtime_adj(X509_get_notAfter(cert), 3600);
        X509_set_pubkey(cert, key);
        X509_NAME* name = X509_get_subject_name(cert);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char*>("ProxyNightmare"), -1, -1, 0);
        X509_set_issuer_name(cert, name);
        const bool ok = X509_sign(cert, key, EVP_sha256()) > 0 &&
                        SSL_CTX_use_certificate(ctx_, cert) == 1 &&
                        SSL_CTX_use_PrivateKey(ctx_, key) == 1;
        X509_free(cert);
        EVP_PKEY_free(key);
        if (!ok) throw std::runtime_error(ssl_errors());
    }

    void check_ssl_result(int result) {
        const int error = SSL_get_error(ssl_, result);
        if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
            throw std::runtime_error("TLS handshake failed: " + ssl_errors());
    }

    void drive() {
        const int result = SSL_do_handshake(ssl_);
        if (result != 1) check_ssl_result(result);
        drain_records();
    }

    void drain_records() {
        BIO* bio = SSL_get_wbio(ssl_);
        while (BIO_ctrl_pending(bio) >= 5) {
            std::array<char, 5> header{};
            if (BIO_read(bio, header.data(), 5) != 5) throw std::runtime_error("short TLS record header");
            const auto length = (static_cast<unsigned char>(header[3]) << 8) |
                                static_cast<unsigned char>(header[4]);
            std::string record(header.data(), header.size());
            std::string body(length, '\0');
            if (length && BIO_read(bio, body.data(), length) != length)
                throw std::runtime_error("short TLS record body");
            record += body;
            out_records_.push_back(std::move(record));
        }
    }

    void flush_records(int fd) {
        while (!out_records_.empty()) {
            send_all(fd, out_records_.front());
            out_records_.pop_front();
        }
    }

    bool client_{};
    SSL_CTX* ctx_{};
    SSL* ssl_{};
    std::deque<std::string> in_events_;
    std::deque<std::string> out_events_;
    std::deque<std::string> out_records_;
    std::mutex io_mutex_;
};

class QuicEngine {
public:
    QuicEngine(bool client, int fd) : client_(client), fd_(fd) {
        const int flags = ::fcntl(fd_, F_GETFL, 0);
        if (flags < 0 || ::fcntl(fd_, F_SETFL, flags | O_NONBLOCK) != 0)
            throw std::runtime_error("cannot make QUIC UDP socket nonblocking");
        ctx_ = SSL_CTX_new(client ? OSSL_QUIC_client_thread_method() : OSSL_QUIC_server_method());
        if (!ctx_) throw std::runtime_error(ssl_errors());
        if (client_) start_client();
        else start_server();
    }

    ~QuicEngine() {
        if (connection_) {
            SSL_SHUTDOWN_EX_ARGS args{OSSL_QUIC_ERR_NO_ERROR, "PN shutdown"};
            SSL_shutdown_ex(connection_, SSL_SHUTDOWN_FLAG_RAPID, &args, sizeof(args));
        }
        if (accept_thread_.joinable()) accept_thread_.join();
        if (tx_stream_) SSL_free(tx_stream_);
        if (rx_stream_ && rx_stream_ != tx_stream_) SSL_free(rx_stream_);
        if (connection_) SSL_free(connection_);
        if (listener_) SSL_free(listener_);
        if (ctx_) SSL_CTX_free(ctx_);
    }

    QuicEngine(const QuicEngine&) = delete;
    QuicEngine& operator=(const QuicEngine&) = delete;

    void handshake() { (void)get_connection(); }
    [[nodiscard]] int fd() const { return fd_; }

    void write(const std::string& data) {
        SSL* connection = get_connection();
        std::lock_guard lock(stream_mutex_);
        if (!tx_stream_) {
            tx_stream_ = SSL_new_stream(connection, 0);
            if (!tx_stream_) throw std::runtime_error("cannot create QUIC stream: " + ssl_errors());
        }
        std::size_t written{};
        if (SSL_write_ex(tx_stream_, data.data(), data.size(), &written) != 1 || written != data.size())
            throw std::runtime_error("QUIC stream write failed: " + ssl_errors());
    }

    std::string read(std::size_t wanted) {
        SSL* connection = get_connection();
        {
            std::lock_guard lock(stream_mutex_);
            if (!rx_stream_) {
                rx_stream_ = SSL_accept_stream(connection, 0);
                if (!rx_stream_) throw std::runtime_error("cannot accept QUIC stream: " + ssl_errors());
            }
        }
        std::string data(wanted, '\0');
        std::size_t offset = 0;
        while (offset < wanted) {
            std::size_t received{};
            if (SSL_read_ex(rx_stream_, data.data() + offset, wanted - offset, &received) != 1)
                throw std::runtime_error("QUIC stream ended before expected bytes: " + ssl_errors());
            offset += received;
        }
        return data;
    }

    void conclude_write() {
        std::lock_guard lock(stream_mutex_);
        if (tx_stream_ && SSL_stream_conclude(tx_stream_, 0) != 1)
            throw std::runtime_error("cannot conclude QUIC stream: " + ssl_errors());
    }

    void reset_read() {
        std::lock_guard lock(stream_mutex_);
        if (rx_stream_) {
            SSL_STREAM_RESET_ARGS args{0x100};
            if (SSL_stream_reset(rx_stream_, &args, sizeof(args)) != 1)
                throw std::runtime_error("cannot reset QUIC stream: " + ssl_errors());
        }
    }

    void receive_eot() {
        SSL* connection = get_connection();
        {
            std::lock_guard lock(stream_mutex_);
            if (!rx_stream_) {
                rx_stream_ = SSL_accept_stream(connection, 0);
                if (!rx_stream_) throw std::runtime_error("cannot accept QUIC stream: " + ssl_errors());
            }
        }
        char byte{};
        std::size_t received{};
        const int result = SSL_read_ex(rx_stream_, &byte, 1, &received);
        if (result == 1 || received != 0 || SSL_get_stream_read_state(rx_stream_) != SSL_STREAM_STATE_FINISHED)
            throw std::runtime_error("expected QUIC stream FIN");
    }

    void next_stream() {
        std::lock_guard lock(stream_mutex_);
        if (tx_stream_) { SSL_free(tx_stream_); tx_stream_ = nullptr; }
        if (rx_stream_) { SSL_free(rx_stream_); rx_stream_ = nullptr; }
    }

    void close() {
        SSL* connection = get_connection();
        SSL_SHUTDOWN_EX_ARGS args{OSSL_QUIC_ERR_NO_ERROR, "PN close"};
        if (SSL_shutdown_ex(connection, SSL_SHUTDOWN_FLAG_RAPID, &args, sizeof(args)) < 0)
            throw std::runtime_error("QUIC connection close failed: " + ssl_errors());
    }

private:
    static int select_alpn(SSL*, const unsigned char** out, unsigned char* out_len,
                           const unsigned char* input, unsigned int input_len, void*) {
        static const unsigned char supported[] = {4, 'p', 'n', '/', '1'};
        unsigned char* selected = nullptr;
        if (SSL_select_next_proto(&selected, out_len, supported, sizeof(supported), input, input_len)
            != OPENSSL_NPN_NEGOTIATED)
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        *out = selected;
        return SSL_TLSEXT_ERR_OK;
    }

    void install_certificate() {
        EVP_PKEY* key = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "prime256v1");
        if (!key) throw std::runtime_error(ssl_errors());
        X509* cert = X509_new();
        if (!cert) { EVP_PKEY_free(key); throw std::runtime_error(ssl_errors()); }
        X509_set_version(cert, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(cert), 2);
        X509_gmtime_adj(X509_get_notBefore(cert), -60);
        X509_gmtime_adj(X509_get_notAfter(cert), 3600);
        X509_set_pubkey(cert, key);
        X509_NAME* name = X509_get_subject_name(cert);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char*>("ProxyNightmare QUIC"), -1, -1, 0);
        X509_set_issuer_name(cert, name);
        const bool ok = X509_sign(cert, key, EVP_sha256()) > 0 &&
                        SSL_CTX_use_certificate(ctx_, cert) == 1 &&
                        SSL_CTX_use_PrivateKey(ctx_, key) == 1;
        X509_free(cert);
        EVP_PKEY_free(key);
        if (!ok) throw std::runtime_error(ssl_errors());
    }

    void start_client() {
        connection_ = SSL_new(ctx_);
        if (!connection_) throw std::runtime_error(ssl_errors());
        static const unsigned char alpn[] = {4, 'p', 'n', '/', '1'};
        SSL_set_verify(connection_, SSL_VERIFY_NONE, nullptr);
        if (SSL_set_alpn_protos(connection_, alpn, sizeof(alpn)) != 0 ||
            SSL_set_default_stream_mode(connection_, SSL_DEFAULT_STREAM_MODE_NONE) != 1 ||
            SSL_set_fd(connection_, fd_) != 1 || SSL_set_blocking_mode(connection_, 1) != 1 ||
            SSL_connect(connection_) != 1)
            throw std::runtime_error("QUIC client handshake failed: " + ssl_errors());
    }

    void start_server() {
        install_certificate();
        SSL_CTX_set_alpn_select_cb(ctx_, &QuicEngine::select_alpn, nullptr);
        listener_ = SSL_new_listener(ctx_, 0);
        if (!listener_ || SSL_set_fd(listener_, fd_) != 1 || SSL_set_blocking_mode(listener_, 1) != 1)
            throw std::runtime_error("cannot create QUIC listener: " + ssl_errors());
        accept_thread_ = std::thread([this] {
            SSL* accepted = SSL_accept_connection(listener_, 0);
            std::lock_guard lock(connection_mutex_);
            if (!accepted) accept_error_ = "QUIC accept failed: " + ssl_errors();
            else {
                SSL_set_blocking_mode(accepted, 1);
                SSL_set_incoming_stream_policy(accepted, SSL_INCOMING_STREAM_POLICY_ACCEPT, 0);
                if (SSL_accept(accepted) != 1) {
                    accept_error_ = "QUIC server handshake failed: " + ssl_errors();
                    SSL_free(accepted);
                } else connection_ = accepted;
            }
            connection_ready_.notify_all();
        });
    }

    SSL* get_connection() {
        if (client_) return connection_;
        std::unique_lock lock(connection_mutex_);
        connection_ready_.wait(lock, [this] { return connection_ || !accept_error_.empty(); });
        if (!accept_error_.empty()) throw std::runtime_error(accept_error_);
        return connection_;
    }

    bool client_{};
    int fd_{};
    SSL_CTX* ctx_{};
    SSL* listener_{};
    SSL* connection_{};
    SSL* tx_stream_{};
    SSL* rx_stream_{};
    std::thread accept_thread_;
    std::mutex connection_mutex_;
    std::condition_variable connection_ready_;
    std::string accept_error_;
    std::mutex stream_mutex_;
};

std::string tls_phase(Op op, Role sender) {
    if (op == Op::hello) return sender == Role::client ? "client-hello" : "server-hello";
    return op_name(op);
}

std::string recv_exact(int fd, std::size_t wanted) {
    std::string data;
    data.resize(wanted);
    std::size_t offset = 0;
    while (offset < wanted) {
        const ssize_t count = ::recv(fd, data.data() + offset, wanted - offset, 0);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) throw std::runtime_error("receive failed: " + std::string(std::strerror(errno)));
        if (count == 0) throw std::runtime_error("peer closed before requested bytes arrived");
        offset += static_cast<std::size_t>(count);
    }
    return data;
}

void send_all(int fd, const std::string& data) {
    std::size_t offset = 0;
    while (offset < data.size()) {
        const ssize_t count = ::send(fd, data.data() + offset, data.size() - offset, MSG_NOSIGNAL);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) throw std::runtime_error("send failed: " + std::string(std::strerror(errno)));
        offset += static_cast<std::size_t>(count);
    }
}

std::uint64_t parse_quantity(const std::string& text, bool duration_value = false) {
    std::size_t split = 0;
    while (split < text.size() && std::isdigit(static_cast<unsigned char>(text[split]))) ++split;
    if (split == 0) throw std::runtime_error("quantity must start with a number: " + text);
    std::uint64_t value{};
    const auto parsed = std::from_chars(text.data(), text.data() + split, value);
    if (parsed.ec != std::errc{} || value == 0) throw std::runtime_error("invalid quantity: " + text);
    const auto suffix = text.substr(split);
    if (duration_value) {
        if (suffix == "ms") return value;
        if (suffix == "s") return value * 1000;
        if (suffix == "us") return (value + 999) / 1000;
        throw std::runtime_error("delay unit must be us, ms, or s");
    }
    if (suffix.empty() || suffix == "B") return value;
    if (suffix == "KiB") return value * 1024;
    if (suffix == "MiB") return value * 1024 * 1024;
    if (suffix == "GiB") return value * 1024 * 1024 * 1024;
    throw std::runtime_error("size unit must be B, KiB, MiB, or GiB");
}

struct StreamSpec {
    std::uint64_t total{};
    std::uint64_t stamp_every{};
    std::size_t chunk{16384};
    std::chrono::milliseconds delay{0};
};

StreamSpec parse_stream_spec(const std::string& text) {
    std::istringstream input(text);
    std::vector<std::string> token;
    for (std::string part; input >> part;) token.push_back(part);
    if (token.size() < 3 || token[1] != "stamp-every") throw std::runtime_error("invalid stream specification");
    StreamSpec spec;
    spec.total = parse_quantity(token[0]);
    spec.stamp_every = parse_quantity(token[2]);
    if (spec.stamp_every < 32 || spec.stamp_every > 64 * 1024 * 1024)
        throw std::runtime_error("stamp-every must be between 32B and 64MiB");
    for (std::size_t i = 3; i < token.size();) {
        if (i + 1 >= token.size()) throw std::runtime_error("incomplete stream option");
        if (token[i] == "chunk") spec.chunk = static_cast<std::size_t>(parse_quantity(token[i + 1]));
        else if (token[i] == "delay") spec.delay = std::chrono::milliseconds(parse_quantity(token[i + 1], true));
        else throw std::runtime_error("unknown stream option: " + token[i]);
        i += 2;
    }
    if (spec.chunk == 0 || spec.chunk > 64 * 1024 * 1024) throw std::runtime_error("chunk is too large");
    return spec;
}

void put_u64(std::string& data, std::size_t at, std::uint64_t value) {
    for (int i = 7; i >= 0; --i) data[at + static_cast<std::size_t>(7 - i)] = static_cast<char>(value >> (i * 8));
}

std::uint64_t get_u64(const std::string& data, std::size_t at) {
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < 8; ++i) value = (value << 8) | static_cast<unsigned char>(data[at + i]);
    return value;
}

constexpr std::uint64_t stamp_salt = 0x504e5354414d5031ULL;

std::string make_block(std::uint64_t offset, std::size_t size) {
    std::string block(size, '\0');
    for (std::size_t i = 0; i < size; ++i)
        block[i] = static_cast<char>(((offset + i) * 1315423911ULL + 0x5a) & 0xff);
    if (size >= 32) {
        std::memcpy(block.data(), "PNSTAMP1", 8);
        const auto now = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
        put_u64(block, 8, offset);
        put_u64(block, 16, now);
        put_u64(block, 24, offset ^ now ^ stamp_salt);
    }
    return block;
}

std::uint64_t validate_block(const std::string& block, std::uint64_t offset) {
    if (block.size() < 32 || block.compare(0, 8, "PNSTAMP1") != 0)
        throw std::runtime_error("missing timestamp at offset " + std::to_string(offset));
    const auto marked_offset = get_u64(block, 8);
    const auto timestamp = get_u64(block, 16);
    const auto checksum = get_u64(block, 24);
    if (marked_offset != offset || checksum != (offset ^ timestamp ^ stamp_salt))
        throw std::runtime_error("corrupt timestamp at offset " + std::to_string(offset));
    for (std::size_t i = 32; i < block.size(); ++i) {
        const char expected = static_cast<char>(((offset + i) * 1315423911ULL + 0x5a) & 0xff);
        if (block[i] != expected) throw std::runtime_error("payload corruption at offset " + std::to_string(offset + i));
    }
    return timestamp;
}

} // namespace

RunResult run(const Test& test, const RunOptions& options, std::ostream& log) {
    std::signal(SIGPIPE, SIG_IGN);
    try {
        AgentProcess server(test.server_target, options);
        AgentProcess client(test.client_target, options);
        std::unordered_map<Role, AgentProcess*> agents{{Role::server, &server}, {Role::client, &client}};
        std::unordered_map<Role, bool> closed{{Role::server, false}, {Role::client, false}};
        std::unordered_map<std::string, std::string> metrics;
        auto failed = [&](const std::string& detail, std::size_t steps) {
            const auto message = test.fail_outcome.empty() ? detail : test.fail_outcome + ": " + detail;
            return RunResult{FinishReason::failed, message, steps};
        };
        const auto deadline = Clock::now() + test.timeout;
        std::size_t completed = 0;
        for (auto* agent : {&server, &client}) {
            const auto configured = agent->request("transport", transport_name(test.transport), deadline);
            if (configured.kind != "OK") return failed("cannot configure transport: " + configured.payload, completed);
        }
        for (const auto& step : test.steps) {
            if (Clock::now() >= deadline) return {FinishReason::timeout, test.timeout_outcome, completed};
            if (options.trace) log << "[" << role_name(step.role) << "] " << op_name(step.op) << "\n";
            std::string argument = step.argument;
            Response response;
            try {
                if (step.op == Op::handshake) {
                    if (test.transport != Transport::tls && test.transport != Transport::quic)
                        return failed("handshake requires begin using tls or quic", completed);
                    const auto command = test.transport == Transport::quic ? "quic-handshake" : "tls-handshake";
                    auto server_handshake = std::async(std::launch::async, [&] {
                        return server.request(command, "server", deadline);
                    });
                    auto client_handshake = std::async(std::launch::async, [&] {
                        return client.request(command, "client", deadline);
                    });
                    const auto server_response = server_handshake.get();
                    const auto client_response = client_handshake.get();
                    if (server_response.kind != "OK") response = server_response;
                    else response = client_response;
                    const std::string metric = test.transport == Transport::quic ? "quic.handshake" : "tls.handshake";
                    if (server_response.kind == "OK") metrics[std::string("server.") + metric] = "complete";
                    if (client_response.kind == "OK") metrics[std::string("client.") + metric] = "complete";
                } else if (tls_operation(step.op)) {
                    if (test.transport != Transport::tls)
                        return failed(op_name(step.op) + " requires begin using tls", completed);
                    const auto phase = tls_phase(step.op, step.role);
                    response = agents.at(step.role)->request("tls-send", phase, deadline);
                    if (response.kind == "OK") {
                        const Role peer = step.role == Role::server ? Role::client : Role::server;
                        response = agents.at(peer)->request("tls-receive", phase, deadline);
                        if (response.kind == "OK") {
                            metrics[role_name(peer) + ".tls." + phase] = "received";
                            std::istringstream fields(response.payload);
                            for (std::string field; fields >> field;) {
                                const auto equals = field.find('=');
                                if (equals != std::string::npos)
                                    metrics[role_name(peer) + "." + field.substr(0, equals)] = field.substr(equals + 1);
                            }
                        }
                    }
                } else {
                    response = agents.at(step.role)->request(op_name(step.op), argument, deadline);
                }
            } catch (const std::runtime_error& error) {
                if (std::string(error.what()) == "TIMEOUT")
                    return {FinishReason::timeout, test.timeout_outcome, completed};
                throw;
            }
            if (response.kind == "ERR")
                return failed(role_name(step.role) + ": " + response.payload, completed);
            if (response.kind == "EOF") closed[step.role] = true;
            else if (response.kind != "OK")
                return failed("invalid response from " + role_name(step.role) + " agent", completed);
            if (step.op == Op::await_rx) {
                std::istringstream fields(response.payload);
                for (std::string field; fields >> field;) {
                    const auto equals = field.find('=');
                    if (equals != std::string::npos)
                        metrics[role_name(step.role) + "." + field.substr(0, equals)] = field.substr(equals + 1);
                }
            }
            if (options.trace && !response.payload.empty())
                log << "  " << response.payload << "\n";
            if (step.op == Op::receive_eot && response.kind != "EOF")
                return failed(role_name(step.role) + ": expected end of stream", completed);
            if (step.op == Op::receive_eot) metrics[role_name(step.role) + ".rx.eot"] = "received";
            if (step.op == Op::close) closed[step.role] = true;
            ++completed;
        }
        for (const auto& condition : test.pass_outcome.conditions) {
            const auto found = metrics.find(condition.metric);
            if (found == metrics.end()) return failed("pass metric unavailable: " + condition.metric, completed);
            std::string expected = condition.expected;
            if (condition.metric.ends_with(".bytes")) expected = std::to_string(parse_quantity(expected));
            const bool equal = found->second == expected;
            if ((condition.comparison == "==" && !equal) || (condition.comparison == "!=" && equal))
                return failed(condition.metric + " is " + found->second + ", expected " +
                              condition.comparison + " " + expected, completed);
        }
        return {FinishReason::pass, test.pass_outcome.description, completed};
    } catch (const std::exception& error) {
        const auto message = test.fail_outcome.empty() ? error.what() : test.fail_outcome + ": " + error.what();
        return {FinishReason::failed, message, 0};
    }
}

int run_agent(std::istream& input, std::ostream& output) {
    std::signal(SIGPIPE, SIG_IGN);
    int listener = -1;
    int socket = -1;
    Transport transport = Transport::tcp;
    std::string connect_endpoint;
    std::unique_ptr<TlsEngine> tls;
    std::unique_ptr<QuicEngine> quic;
    std::mutex socket_mutex;
    std::condition_variable socket_ready;
    bool accepting = false;
    auto ensure_socket = [&]() -> int {
        std::unique_lock lock(socket_mutex);
        if (socket >= 0) return socket;
        if (transport == Transport::udp && listener >= 0) return listener;
        if (listener < 0) throw std::runtime_error("no connected socket");
        if (accepting) {
            socket_ready.wait(lock, [&] { return !accepting; });
            if (socket < 0) throw std::runtime_error("accept failed");
            return socket;
        }
        accepting = true;
        const int listen_fd = listener;
        lock.unlock();
        int accepted;
        do { accepted = ::accept(listen_fd, nullptr, nullptr); } while (accepted < 0 && errno == EINTR);
        lock.lock();
        socket = accepted;
        accepting = false;
        socket_ready.notify_all();
        if (socket < 0) throw std::runtime_error("accept failed: " + std::string(std::strerror(errno)));
        return socket;
    };
    struct Job {
        std::thread thread;
        std::string error;
        std::string stats;
        bool active{false};
    } tx, rx;
    auto await_job = [](Job& job) {
        if (!job.active) throw std::runtime_error("no active stream job");
        if (job.thread.joinable()) job.thread.join();
        job.active = false;
        if (!job.error.empty()) throw std::runtime_error(job.error);
        return job.stats;
    };
    std::string line;
    while (std::getline(input, line)) {
        const auto tab = line.find('\t');
        const std::string command = line.substr(0, tab);
        try {
            const std::string argument = tab == std::string::npos ? std::string{} : hex_decode(line.substr(tab + 1));
            std::string payload;
            std::string kind = "OK";
            if (command == "transport") {
                if (listener >= 0 || socket >= 0) throw std::runtime_error("transport must be selected before sockets");
                if (argument == "tcp") transport = Transport::tcp;
                else if (argument == "udp") transport = Transport::udp;
                else if (argument == "tls") transport = Transport::tls;
                else if (argument == "quic") transport = Transport::quic;
                else throw std::runtime_error("unknown transport: " + argument);
            } else if (command == "listen") {
                if (listener >= 0 || socket >= 0) throw std::runtime_error("socket already configured");
                listener = make_socket(argument, true,
                    (transport == Transport::udp || transport == Transport::quic) ? SOCK_DGRAM : SOCK_STREAM);
                if (transport == Transport::quic) {
                    quic = std::make_unique<QuicEngine>(false, listener);
                    listener = -1;
                }
            } else if (command == "connect") {
                if (listener >= 0 || socket >= 0) throw std::runtime_error("socket already configured");
                connect_endpoint = argument;
                socket = make_socket(argument, false,
                    (transport == Transport::udp || transport == Transport::quic) ? SOCK_DGRAM : SOCK_STREAM);
                if (transport == Transport::quic) {
                    quic = std::make_unique<QuicEngine>(true, socket);
                    socket = -1;
                }
            } else if (command == "receive-eot") {
                if (transport == Transport::udp) payload = "noop: UDP has no EOT";
                else if (transport == Transport::quic) quic->receive_eot();
                else {
                    char byte{};
                    ssize_t count;
                    const int fd = ensure_socket();
                    do { count = ::recv(fd, &byte, 1, 0); } while (count < 0 && errno == EINTR);
                    if (count < 0) throw std::runtime_error("receive failed");
                    if (count > 0) throw std::runtime_error("received data while expecting EOT");
                }
                kind = "EOF";
            } else if (command == "transmit") {
                if (tx.active) throw std::runtime_error("transmit already active");
                const auto spec = parse_stream_spec(argument);
                tx.active = true; tx.error.clear(); tx.stats.clear();
                tx.thread = std::thread([&, spec] {
                    try {
                        const int fd = transport == Transport::quic ? quic->fd() : ensure_socket();
                        const auto started = Clock::now();
                        if (transport == Transport::udp && spec.chunk > 65507)
                            throw std::runtime_error("UDP chunk exceeds maximum datagram payload");
                        for (std::uint64_t offset = 0; offset < spec.total; offset += spec.stamp_every) {
                            const auto block_size = static_cast<std::size_t>(std::min<std::uint64_t>(spec.stamp_every, spec.total - offset));
                            auto block = make_block(offset, block_size);
                            for (std::size_t sent = 0; sent < block.size();) {
                                const auto amount = std::min(spec.chunk, block.size() - sent);
                                const auto bytes = block.substr(sent, amount);
                                if (transport == Transport::quic) {
                                    if (!quic) throw std::runtime_error("QUIC stream used before connect");
                                    quic->write(bytes);
                                } else if (transport == Transport::tls) {
                                    if (!tls) throw std::runtime_error("TLS stream used before handshake");
                                    tls->write_application(fd, bytes);
                                } else send_all(fd, bytes);
                                sent += amount;
                                if (spec.delay.count() > 0) std::this_thread::sleep_for(spec.delay);
                            }
                        }
                        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - started).count();
                        tx.stats = std::to_string(spec.total) + " bytes sent in " + std::to_string(elapsed) + " ms";
                    } catch (const std::exception& error) { tx.error = error.what(); }
                });
            } else if (command == "drain") {
                if (rx.active) throw std::runtime_error("drain already active");
                const auto spec = parse_stream_spec(argument);
                rx.active = true; rx.error.clear(); rx.stats.clear();
                rx.thread = std::thread([&, spec] {
                    try {
                        const int fd = transport == Transport::quic ? quic->fd() : ensure_socket();
                        const auto started = Clock::now();
                        std::int64_t latency_min = std::numeric_limits<std::int64_t>::max();
                        std::int64_t latency_max = std::numeric_limits<std::int64_t>::min();
                        long double latency_sum = 0;
                        std::uint64_t stamps = 0;
                        std::string udp_data;
                        if (transport == Transport::udp) {
                            if (spec.total > 256 * 1024 * 1024ULL) throw std::runtime_error("UDP drain limit is 256MiB");
                            udp_data.reserve(static_cast<std::size_t>(spec.total));
                            while (udp_data.size() < spec.total) {
                                std::array<char, 65536> datagram{};
                                sockaddr_storage peer{};
                                socklen_t peer_size = sizeof(peer);
                                const auto count = ::recvfrom(fd, datagram.data(), datagram.size(), 0,
                                                              reinterpret_cast<sockaddr*>(&peer), &peer_size);
                                if (count < 0 && errno == EINTR) continue;
                                if (count < 0) throw std::runtime_error("UDP receive failed: " + std::string(std::strerror(errno)));
                                if (count == 0) throw std::runtime_error("empty UDP datagram in generated stream");
                                if (udp_data.empty() && socket < 0 &&
                                    ::connect(fd, reinterpret_cast<sockaddr*>(&peer), peer_size) != 0)
                                    throw std::runtime_error("cannot select UDP peer");
                                udp_data.append(datagram.data(), static_cast<std::size_t>(count));
                                if (udp_data.size() > spec.total) throw std::runtime_error("UDP stream exceeded expected byte count");
                            }
                        }
                        for (std::uint64_t offset = 0; offset < spec.total; offset += spec.stamp_every) {
                            const auto block_size = static_cast<std::size_t>(std::min<std::uint64_t>(spec.stamp_every, spec.total - offset));
                            const auto block = transport == Transport::udp
                                ? udp_data.substr(static_cast<std::size_t>(offset), block_size)
                                : transport == Transport::quic
                                    ? (quic ? quic->read(block_size)
                                            : throw std::runtime_error("QUIC stream used before connect"))
                                : transport == Transport::tls
                                    ? (tls ? tls->read_application(fd, block_size)
                                           : throw std::runtime_error("TLS stream used before handshake"))
                                    : recv_exact(fd, block_size);
                            const auto timestamp = validate_block(block, offset);
                            const auto now = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                std::chrono::system_clock::now().time_since_epoch()).count());
                            const auto latency = static_cast<std::int64_t>(now - timestamp);
                            latency_min = std::min(latency_min, latency);
                            latency_max = std::max(latency_max, latency);
                            latency_sum += static_cast<long double>(latency);
                            ++stamps;
                        }
                        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - started).count();
                        const auto average_us = static_cast<long long>((latency_sum / stamps) / 1000.0L);
                        rx.stats = "rx.bytes=" + std::to_string(spec.total) + " rx.stamps=" + std::to_string(stamps) +
                            " rx.integrity=valid rx.elapsed-ms=" + std::to_string(elapsed) +
                            " rx.clock-delta-us=" + std::to_string(latency_min / 1000) + "/" +
                            std::to_string(average_us) + "/" + std::to_string(latency_max / 1000);
                    } catch (const std::exception& error) { rx.error = error.what(); }
                });
            } else if (command == "await-tx") {
                payload = await_job(tx);
            } else if (command == "await-rx") {
                payload = await_job(rx);
            } else if (command == "set-sndbuf" || command == "set-rcvbuf") {
                const int value = static_cast<int>(parse_quantity(argument));
                const int option = command == "set-sndbuf" ? SO_SNDBUF : SO_RCVBUF;
                const int fd = transport == Transport::quic ? quic->fd() : ensure_socket();
                if (::setsockopt(fd, SOL_SOCKET, option, &value, sizeof(value)) != 0)
                    throw std::runtime_error("setsockopt failed: " + std::string(std::strerror(errno)));
            } else if (command == "half-close-write" || command == "half-close-read") {
                if (transport == Transport::udp) payload = "noop: UDP has no half-close";
                else if (transport == Transport::quic) {
                    if (command == "half-close-write") quic->conclude_write();
                    else throw std::runtime_error("QUIC STOP_SENDING is not exposed by OpenSSL 3.5");
                }
                else {
                    const int how = command == "half-close-write" ? SHUT_WR : SHUT_RD;
                    if (::shutdown(ensure_socket(), how) != 0) throw std::runtime_error("shutdown failed");
                }
            } else if (command == "reconnect") {
                if (transport != Transport::udp) throw std::runtime_error("reconnect is UDP-only");
                if (socket >= 0) {
                    ::close(socket);
                    socket = make_socket(connect_endpoint, false, SOCK_DGRAM);
                } else if (listener >= 0) {
                    sockaddr address{};
                    address.sa_family = AF_UNSPEC;
                    if (::connect(listener, &address, sizeof(address)) != 0 && errno != EAFNOSUPPORT)
                        throw std::runtime_error("cannot forget UDP peer");
                }
            } else if (command == "next-stream") {
                if (transport != Transport::quic || !quic) throw std::runtime_error("next-stream is QUIC-only");
                quic->next_stream();
            } else if (command == "tls-send") {
                if (transport != Transport::tls) throw std::runtime_error("TLS phase used outside TLS transport");
                if (!tls) tls = std::make_unique<TlsEngine>(argument == "client-hello");
                tls->send_phase(ensure_socket(), argument);
                payload = "tls." + argument + "=sent tls.handshake=" + (tls->complete() ? "complete" : "pending");
            } else if (command == "tls-receive") {
                if (transport != Transport::tls) throw std::runtime_error("TLS phase used outside TLS transport");
                if (!tls) tls = std::make_unique<TlsEngine>(argument == "server-hello");
                tls->receive_phase(ensure_socket(), argument);
                payload = "tls." + argument + "=received tls.handshake=" + (tls->complete() ? "complete" : "pending");
            } else if (command == "tls-handshake") {
                if (transport != Transport::tls) throw std::runtime_error("TLS handshake used outside TLS transport");
                if (!tls) tls = std::make_unique<TlsEngine>(argument == "client");
                tls->handshake(ensure_socket());
                payload = "tls.handshake=complete";
            } else if (command == "quic-handshake") {
                if (transport != Transport::quic || !quic) throw std::runtime_error("QUIC endpoint is not configured");
                quic->handshake();
                payload = "quic.handshake=complete";
            } else if (command == "sleep") {
                std::this_thread::sleep_for(std::chrono::milliseconds(parse_quantity(argument, true)));
            } else if (command == "abort") {
                if (transport == Transport::quic) {
                    quic->close();
                    payload = "quic.connection=aborted";
                } else {
                const int fd = ensure_socket();
                linger reset{1, 0};
                ::setsockopt(fd, SOL_SOCKET, SO_LINGER, &reset, sizeof(reset));
                ::close(fd);
                std::lock_guard lock(socket_mutex);
                socket = -1;
                }
            } else if (command == "close") {
                if (tx.active) (void)await_job(tx);
                if (rx.active) (void)await_job(rx);
                if (quic) quic->close();
                if (socket >= 0) { ::close(socket); socket = -1; }
                if (listener >= 0) { ::close(listener); listener = -1; }
            } else throw std::runtime_error("unknown command: " + command);
            output << kind << '\t' << hex_encode(payload) << '\n' << std::flush;
        } catch (const std::exception& error) {
            output << "ERR\t" << hex_encode(error.what()) << '\n' << std::flush;
        }
    }
    if (tx.thread.joinable()) tx.thread.join();
    if (rx.thread.joinable()) rx.thread.join();
    if (socket >= 0) ::close(socket);
    if (listener >= 0) ::close(listener);
    return 0;
}

std::string finish_reason_name(FinishReason reason) {
    switch (reason) {
        case FinishReason::pass: return "pass";
        case FinishReason::timeout: return "timeout";
        case FinishReason::failed: return "failed";
    }
    return "unknown";
}

} // namespace pn
