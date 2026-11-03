#include "pn/dsl.hpp"
#include <cassert>
#include <iostream>

namespace {
const char* scenario = R"PN(
preamble
name "local smoke test"
owner "PN"
timeout 2s
begin using tcp
server at local
client at local
server listen "127.0.0.1:39191"
client connect "127.0.0.1:39191"
server drain 64KiB stamp-every 1KiB
client transmit 64KiB stamp-every 1KiB chunk 257B
client await-tx
client half-close-write
server await-rx
server receive-eot
server close
client close
end
outcome pass
when server.rx.bytes == 64KiB
describe "stream passed"
outcome fail "stream failed"
outcome timeout "proxy left the flow open"
end
)PN";
void parser_test() {
    const auto test = pn::parse(scenario, "test.pn");
    assert(test.metadata.at("name") == "local smoke test");
    assert(test.server_target == "local");
    assert(test.transport == pn::Transport::tcp);
    assert(test.steps.size() == 10);
    assert(test.timeout == std::chrono::seconds(2));
}
void validation_test() {
    bool failed = false;
    try { (void)pn::parse("preamble\nbegin\nend\nend\n", "bad.pn"); }
    catch (const pn::ParseError&) { failed = true; }
    assert(failed);
}
} // namespace
int main() { parser_test(); validation_test(); std::cout << "all tests passed\n"; }
