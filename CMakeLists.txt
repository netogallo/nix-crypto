cmake_minimum_required (VERSION 3.9)
project (nix-crypto)
set (nix-plugins_VERSION_MAJOR 0)
set (nix-plugins_VERSION_MINOR 1)
set (nix-plugins_VERSION_PATCH 0)

find_package(PkgConfig)

pkg_check_modules(NIX REQUIRED nix-cmd>=2.28 nix-expr>=2.28 nix-main>=2.28 nix-store>=2.28)

find_path(BOOST_INCLUDE_DIR boost/format.hpp)
if(BOOST_INCLUDE_DIR STREQUAL "BOOST_INCLUDE_DIR-NOTFOUND")
  message(FATAL_ERROR "Could not find Boost formatting library.")
endif()
include_directories(${BOOST_INCLUDE_DIR})

if(APPLE)
  set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} -flat_namespace -undefined suppress")
endif()

add_library(libnix_crypto SHARED IMPORTED)

# TODO: only when developing
set_target_properties(libnix_crypto PROPERTIES
    IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/nix-crypto/target/debug/libnix_crypto.so"
    INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/nix-crypto/include"
)

add_library(nix-crypto MODULE src/nix_crypto.cc)
target_include_directories(nix-crypto PUBLIC ${CMAKE_CURRENT_BINARY_DIR})
target_include_directories(nix-crypto PUBLIC ${NIX_INCLUDE_DIRS})
target_compile_options(nix-crypto PUBLIC ${NIX_CFLAGS_OTHER})
target_link_libraries(nix-crypto PUBLIC libnix_crypto)

install(TARGETS nix-crypto DESTINATION lib/nix/plugins)

