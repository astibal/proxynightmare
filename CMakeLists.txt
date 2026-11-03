cmake_minimum_required(VERSION 3.20)
project(ProxyNightmare VERSION 0.1.0 LANGUAGES CXX)
find_package(OpenSSL 3.5 REQUIRED COMPONENTS SSL Crypto)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(pnlib
    src/dsl.cpp
    src/runtime.cpp
)
target_include_directories(pnlib PUBLIC include)
target_link_libraries(pnlib PUBLIC OpenSSL::SSL OpenSSL::Crypto)
target_compile_options(pnlib PRIVATE -Wall -Wextra -Wpedantic)

add_executable(pn src/main.cpp)
target_link_libraries(pn PRIVATE pnlib)
install(TARGETS pn RUNTIME DESTINATION bin)

enable_testing()
add_executable(pn_tests tests/tests.cpp)
target_link_libraries(pn_tests PRIVATE pnlib)
add_test(NAME pn_tests COMMAND pn_tests)
add_test(NAME pn_local_smoke
    COMMAND pn run ${CMAKE_CURRENT_SOURCE_DIR}/docs/examples/local_smoke.pn)
add_test(NAME pn_buffer_torture
    COMMAND pn run ${CMAKE_CURRENT_SOURCE_DIR}/docs/examples/buffer_torture.pn)
add_test(NAME pn_udp_churn
    COMMAND pn run ${CMAKE_CURRENT_SOURCE_DIR}/docs/examples/udp_churn.pn)
add_test(NAME pn_tls_client_hello_eot
    COMMAND pn run ${CMAKE_CURRENT_SOURCE_DIR}/docs/examples/tls_client_hello_eot.pn)
add_test(NAME pn_tls_full_handshake
    COMMAND pn run ${CMAKE_CURRENT_SOURCE_DIR}/docs/examples/tls_full_handshake.pn)
add_test(NAME pn_tls_encrypted_stream
    COMMAND pn run ${CMAKE_CURRENT_SOURCE_DIR}/docs/examples/tls_encrypted_stream.pn)
add_test(NAME pn_tls_autonomous_handshake
    COMMAND pn run ${CMAKE_CURRENT_SOURCE_DIR}/docs/examples/tls_autonomous_handshake.pn)
add_test(NAME pn_quic_stream_torture
    COMMAND pn run ${CMAKE_CURRENT_SOURCE_DIR}/docs/examples/quic_stream_torture.pn)
add_test(NAME pn_quic_stream_churn
    COMMAND pn run ${CMAKE_CURRENT_SOURCE_DIR}/docs/examples/quic_stream_churn.pn)
