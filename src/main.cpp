#include "pn/dsl.hpp"
#include "pn/runtime.hpp"

#include <fstream>
#include <iostream>
#include <sstream>

namespace {
void usage(std::ostream& out) {
    out << "ProxyNightmare 0.1\nusage:\n"
           "  pn run TEST.pn [--trace] [--ssh PATH] [--remote-pn PATH]\n"
           "  pn check TEST.pn\n  pn --agent\n";
}
std::string read_file(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("cannot open " + path);
    std::ostringstream buffer; buffer << input.rdbuf(); return buffer.str();
}
} // namespace

int main(int argc, char** argv) {
    if (argc == 2 && std::string(argv[1]) == "--agent") return pn::run_agent(std::cin, std::cout);
    if (argc < 3) { usage(std::cerr); return 2; }
    const std::string command = argv[1], path = argv[2];
    if (command != "run" && command != "check") { usage(std::cerr); return 2; }
    try {
        const auto test = pn::parse(read_file(path), path);
        if (command == "check") {
            std::cout << "ok: " << test.steps.size() << " steps, timeout " << test.timeout.count() << " ms\n";
            return 0;
        }
        pn::RunOptions options; options.local_executable = argv[0];
        for (int i = 3; i < argc; ++i) {
            const std::string option = argv[i];
            if (option == "--trace") options.trace = true;
            else if ((option == "--ssh" || option == "--remote-pn") && i + 1 < argc) {
                const std::string value = argv[++i];
                if (option == "--ssh") options.ssh = value; else options.remote_executable = value;
            } else throw std::runtime_error("unknown or incomplete option: " + option);
        }
        const auto result = pn::run(test, options, std::cerr);
        std::cout << pn::finish_reason_name(result.reason) << ": " << result.message
                  << " (" << result.completed_steps << "/" << test.steps.size() << " steps)\n";
        return result.reason == pn::FinishReason::pass ? 0 : 1;
    } catch (const std::exception& error) {
        std::cerr << "pn: " << error.what() << '\n'; return 2;
    }
}
