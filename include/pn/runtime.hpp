#pragma once

#include "pn/dsl.hpp"

#include <iosfwd>
#include <string>

namespace pn {

struct RunOptions {
    std::string local_executable{"pn"};
    std::string remote_executable{"pn"};
    std::string ssh{"ssh"};
    bool trace{false};
};

enum class FinishReason { pass, timeout, failed };

struct RunResult {
    FinishReason reason{FinishReason::failed};
    std::string message;
    std::size_t completed_steps{};
};

[[nodiscard]] RunResult run(const Test& test, const RunOptions& options,
                            std::ostream& log);
int run_agent(std::istream& input, std::ostream& output);
[[nodiscard]] std::string finish_reason_name(FinishReason reason);

} // namespace pn
