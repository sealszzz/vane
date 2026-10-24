cmake_minimum_required(VERSION 3.28)

# VERSION is the only product-version source. CMake, binaries, packages, tags,
# and release assets derive their version from this file.
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/VERSION")
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VANE_VERSION_STRING)
string(STRIP "${VANE_VERSION_STRING}" VANE_VERSION_STRING)
if(NOT VANE_VERSION_STRING MATCHES "^[0-9]+\\.[0-9]+\\.[0-9]+$")
  message(FATAL_ERROR
    "VERSION must contain exactly one numeric x.y.z value: '${VANE_VERSION_STRING}'")
endif()

project(vane VERSION "${VANE_VERSION_STRING}" LANGUAGES C)

include(CheckCCompilerFlag)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)


option(VANE_BUILD_TESTS "Build tests" ON)
option(VANE_SANITIZE "Enable ASan and UBSan" OFF)
option(VANE_NATIVE "Tune for the build host" OFF)
set(VANE_CPU_TARGET "" CACHE STRING
    "Release CPU target: baseline, x86-64-v3, armv8-a, or native")
option(VANE_WERROR "Treat project warnings as errors" ON)
option(VANE_STATIC_JSONC "Link json-c statically" OFF)
set(VANE_CRYPTO_ROOT "" CACHE PATH "OpenSSL-compatible crypto prefix (for example AWS-LC install prefix)")
set(VANE_JSONC_ROOT "" CACHE PATH "json-c install prefix")
set(VANE_GIT_COMMIT "$ENV{VANE_GIT_COMMIT}" CACHE STRING "Build commit metadata")
set(VANE_BUILD_TIME "$ENV{VANE_BUILD_TIME}" CACHE STRING "Build time metadata")
if(NOT VANE_GIT_COMMIT)
  set(VANE_GIT_COMMIT "unknown")
endif()
if(NOT VANE_BUILD_TIME)
  string(TIMESTAMP VANE_BUILD_TIME "%Y-%m-%dT%H:%M:%SZ" UTC)
endif()

if(VANE_NATIVE)
  set(VANE_CPU_TARGET "native" CACHE STRING
      "Release CPU target: baseline, x86-64-v3, armv8-a, or native" FORCE)
elseif(NOT VANE_CPU_TARGET)
  if(CMAKE_BUILD_TYPE STREQUAL "Release" AND
     CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$")
    set(VANE_CPU_TARGET "x86-64-v3" CACHE STRING
        "Release CPU target: baseline, x86-64-v3, armv8-a, or native" FORCE)
  else()
    set(VANE_CPU_TARGET "baseline" CACHE STRING
        "Release CPU target: baseline, x86-64-v3, armv8-a, or native" FORCE)
  endif()
endif()
if(NOT VANE_CPU_TARGET MATCHES "^[0-9A-Za-z_.+-]+$")
  message(FATAL_ERROR "VANE_CPU_TARGET contains invalid characters")
endif()
if(NOT VANE_CPU_TARGET STREQUAL "baseline")
  check_c_compiler_flag("-march=${VANE_CPU_TARGET}" VANE_CPU_TARGET_SUPPORTED)
  if(NOT VANE_CPU_TARGET_SUPPORTED)
    message(FATAL_ERROR
      "compiler does not support -march=${VANE_CPU_TARGET}")
  endif()
endif()

if(VANE_CRYPTO_ROOT)
  set(OPENSSL_ROOT_DIR "${VANE_CRYPTO_ROOT}")
  find_library(VANE_CRYPTO_LIBRARY NAMES crypto
    PATHS "${VANE_CRYPTO_ROOT}/lib" "${VANE_CRYPTO_ROOT}/lib64"
    NO_DEFAULT_PATH
    NO_CMAKE_FIND_ROOT_PATH
    REQUIRED)
  set(OPENSSL_CRYPTO_LIBRARY "${VANE_CRYPTO_LIBRARY}" CACHE FILEPATH "" FORCE)
  set(OPENSSL_INCLUDE_DIR "${VANE_CRYPTO_ROOT}/include" CACHE PATH "" FORCE)
  set(OPENSSL_USE_STATIC_LIBS FALSE)
endif()

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)

if(VANE_JSONC_ROOT)
  find_path(VANE_JSONC_INCLUDE_DIR NAMES json-c/json.h
    PATHS "${VANE_JSONC_ROOT}/include"
    NO_DEFAULT_PATH
    NO_CMAKE_FIND_ROOT_PATH
    REQUIRED)
else()
  find_path(VANE_JSONC_INCLUDE_DIR NAMES json-c/json.h REQUIRED)
endif()
if(VANE_STATIC_JSONC)
  set(_VANE_LIBRARY_SUFFIXES "${CMAKE_FIND_LIBRARY_SUFFIXES}")
  set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
endif()
if(VANE_JSONC_ROOT)
  find_library(VANE_JSONC_LIBRARY NAMES json-c
    PATHS "${VANE_JSONC_ROOT}/lib" "${VANE_JSONC_ROOT}/lib64"
    NO_DEFAULT_PATH NO_CMAKE_FIND_ROOT_PATH REQUIRED)
else()
  find_library(VANE_JSONC_LIBRARY NAMES json-c REQUIRED)
endif()
if(VANE_STATIC_JSONC)
  set(CMAKE_FIND_LIBRARY_SUFFIXES "${_VANE_LIBRARY_SUFFIXES}")
endif()
add_library(vane_jsonc UNKNOWN IMPORTED)
set_target_properties(vane_jsonc PROPERTIES
  IMPORTED_LOCATION "${VANE_JSONC_LIBRARY}"
  INTERFACE_INCLUDE_DIRECTORIES "${VANE_JSONC_INCLUDE_DIR}")
set(VANE_JSONC_TARGET vane_jsonc m)

set(VANE_WARNINGS
  -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow
  -Wformat=2 -Wundef -Wstrict-prototypes -Wmissing-prototypes
  -Wmissing-declarations -Wcast-align -Wpointer-arith -Wwrite-strings
)
if(VANE_WERROR)
  list(APPEND VANE_WARNINGS -Werror)
endif()

add_library(vane_project_options INTERFACE)
target_compile_options(vane_project_options INTERFACE
  ${VANE_WARNINGS}
  -fstack-protector-strong
)
if(VANE_SANITIZE)
  target_compile_options(vane_project_options INTERFACE
    -fsanitize=address,undefined
    -fno-omit-frame-pointer
  )
  target_link_options(vane_project_options INTERFACE
    -fsanitize=address,undefined
  )
endif()
if(CMAKE_BUILD_TYPE STREQUAL "Release")
  target_compile_options(vane_project_options INTERFACE
    -O3
    -flto
    -fno-plt
    -fPIE
    -ffunction-sections
    -fdata-sections
    -D_FORTIFY_SOURCE=3
  )
  target_link_options(vane_project_options INTERFACE -flto)
endif()
if(NOT VANE_CPU_TARGET STREQUAL "baseline")
  target_compile_options(vane_project_options INTERFACE
    "-march=${VANE_CPU_TARGET}")
endif()

function(vane_apply_project_options target)
  target_link_libraries(${target} PRIVATE vane_project_options)
endfunction()

set(VANE_CORE_SOURCES
  src/core/address.c
  src/core/config.c
  src/core/json_validate.c
  src/core/log.c
  src/core/route.c
  src/core/runtime.c
  src/core/system.c
  src/core/version.c
)
set(VANE_PROTOCOL_SOURCES
  src/protocol/proxy_protocol.c
  src/protocol/quic_parser.c
  src/protocol/tls_parser.c
)
set(VANE_NET_SOURCES
  src/net/linux_net.c
  src/net/tcp_worker.c
  src/net/udp_flow.c
  src/net/udp_probe.c
  src/net/udp_receive.c
  src/net/udp_send.c
  src/net/udp_worker.c
)

add_library(vane_core STATIC
  ${VANE_CORE_SOURCES}
  ${VANE_PROTOCOL_SOURCES}
  ${VANE_NET_SOURCES}
)
target_include_directories(vane_core
  PUBLIC include
  PRIVATE src/core src/net
)
target_compile_definitions(vane_core PRIVATE
  _GNU_SOURCE _FILE_OFFSET_BITS=64
  VANE_VERSION_STRING="${VANE_VERSION_STRING}"
  VANE_GIT_COMMIT="${VANE_GIT_COMMIT}"
  VANE_BUILD_TIME="${VANE_BUILD_TIME}"
  VANE_CPU_TARGET_STRING="${VANE_CPU_TARGET}"
)
vane_apply_project_options(vane_core)
target_link_libraries(vane_core PUBLIC
  Threads::Threads
  OpenSSL::Crypto
  ${VANE_JSONC_TARGET}
)

add_executable(vane src/main.c)
target_compile_definitions(vane PRIVATE _GNU_SOURCE _FILE_OFFSET_BITS=64)
vane_apply_project_options(vane)
if(CMAKE_BUILD_TYPE STREQUAL "Release")
  target_link_options(vane PRIVATE -pie -Wl,-z,relro -Wl,-z,now
    -Wl,-z,noexecstack -Wl,--as-needed -Wl,--gc-sections)
  if(VANE_CPU_TARGET STREQUAL "x86-64-v3")
    target_link_options(vane PRIVATE -Wl,-z,x86-64-v3)
  endif()
endif()
target_link_libraries(vane PRIVATE vane_core)

add_executable(vane_udp_offload_probe tools/udp_offload_probe.c)
target_compile_definitions(vane_udp_offload_probe PRIVATE _GNU_SOURCE _FILE_OFFSET_BITS=64)
vane_apply_project_options(vane_udp_offload_probe)
if(CMAKE_BUILD_TYPE STREQUAL "Release")
  target_link_options(vane_udp_offload_probe PRIVATE -pie -Wl,-z,relro -Wl,-z,now
    -Wl,-z,noexecstack -Wl,--as-needed -Wl,--gc-sections)
  if(VANE_CPU_TARGET STREQUAL "x86-64-v3")
    target_link_options(vane_udp_offload_probe PRIVATE -Wl,-z,x86-64-v3)
  endif()
endif()

add_executable(vane_probe_bench EXCLUDE_FROM_ALL tools/probe_bench.c)
target_compile_definitions(vane_probe_bench PRIVATE _GNU_SOURCE)
vane_apply_project_options(vane_probe_bench)
target_compile_options(vane_probe_bench PRIVATE -UNDEBUG)
target_link_libraries(vane_probe_bench PRIVATE vane_core)

install(TARGETS vane RUNTIME DESTINATION bin)
install(FILES configs/vane.json DESTINATION share/vane)
install(FILES VERSION README.md SECURITY.md CHANGELOG.md BUILDING.md LICENSE
              THIRD_PARTY_NOTICES.md
              docs/ARCHITECTURE.md docs/CONFIG.md docs/FEATURES.md
        DESTINATION share/doc/vane)

if(VANE_BUILD_TESTS)
  enable_testing()
  foreach(test_name IN ITEMS config linux_net tls_parser proxy_protocol route quic_parser parser_robustness udp_flow udp_send udp_receive_error startup_notify)
    add_executable(test_${test_name} tests/unit/test_${test_name}.c)
    target_compile_definitions(test_${test_name} PRIVATE
      _GNU_SOURCE _FILE_OFFSET_BITS=64
      VANE_TEST_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures")
    vane_apply_project_options(test_${test_name})
    target_compile_options(test_${test_name} PRIVATE -UNDEBUG)
    if(test_name MATCHES "^udp_" OR test_name STREQUAL "startup_notify")
      target_include_directories(test_${test_name} PRIVATE src/net)
    endif()
    target_link_libraries(test_${test_name} PRIVATE vane_core)
    if(test_name STREQUAL "udp_send")
      target_link_options(test_${test_name} PRIVATE
        -Wl,--wrap=sendmmsg -Wl,--wrap=sendmsg)
    endif()
    if(test_name STREQUAL "startup_notify")
      target_link_options(test_${test_name} PRIVATE
        -Wl,--wrap=socket -Wl,--wrap=sendto)
    endif()
    if(test_name STREQUAL "udp_receive_error")
      target_link_options(test_${test_name} PRIVATE -Wl,--wrap=recvmsg)
    endif()
    add_test(NAME ${test_name} COMMAND test_${test_name})
  endforeach()
  add_test(NAME sample_config
    COMMAND vane --check ${CMAKE_CURRENT_SOURCE_DIR}/configs/vane.json)
  add_test(NAME udp_offload COMMAND vane_udp_offload_probe)
  set_tests_properties(udp_offload PROPERTIES SKIP_RETURN_CODE 77)
  find_package(Python3 COMPONENTS Interpreter)
  if(Python3_Interpreter_FOUND AND NOT CMAKE_CROSSCOMPILING)
    add_test(NAME integration_smoke
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/integration_smoke.py
              $<TARGET_FILE:vane>)
    set_tests_properties(integration_smoke PROPERTIES TIMEOUT 20)
    add_test(NAME udp_diagnostics
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/udp_diagnostics.py
              $<TARGET_FILE:vane>)
    set_tests_properties(udp_diagnostics PROPERTIES TIMEOUT 10)
    add_test(NAME tcp_half_close
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/tcp_half_close.py
              $<TARGET_FILE:vane>)
    set_tests_properties(tcp_half_close PROPERTIES TIMEOUT 15)
    add_test(NAME tcp_backpressure
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/tcp_backpressure.py
              $<TARGET_FILE:vane>)
    set_tests_properties(tcp_backpressure PROPERTIES TIMEOUT 20)
    add_test(NAME maintenance_regressions
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/maintenance_regressions.py
              $<TARGET_FILE:vane>)
    set_tests_properties(maintenance_regressions PROPERTIES TIMEOUT 25)
    add_test(NAME installer_regressions
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/installer_regressions.py
              $<TARGET_FILE:vane>)
    set_tests_properties(installer_regressions PROPERTIES TIMEOUT 60)
    add_test(NAME uninstaller_regressions
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/uninstaller_regressions.py)
    set_tests_properties(uninstaller_regressions PROPERTIES TIMEOUT 20)
  endif()
  if(VANE_SANITIZE)
    set_tests_properties(config linux_net tls_parser proxy_protocol route quic_parser parser_robustness udp_flow udp_send udp_receive_error startup_notify sample_config udp_offload
      PROPERTIES ENVIRONMENT "ASAN_OPTIONS=detect_leaks=0:halt_on_error=1;UBSAN_OPTIONS=halt_on_error=1")
    if(Python3_Interpreter_FOUND AND NOT CMAKE_CROSSCOMPILING)
      set_tests_properties(integration_smoke udp_diagnostics tcp_half_close tcp_backpressure maintenance_regressions installer_regressions uninstaller_regressions
        PROPERTIES ENVIRONMENT "ASAN_OPTIONS=detect_leaks=0:halt_on_error=1;UBSAN_OPTIONS=halt_on_error=1")
    endif()
  endif()
endif()
