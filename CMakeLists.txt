cmake_minimum_required(VERSION 3.20)
project(tema1)

set(CMAKE_CXX_STANDARD 20)

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

add_executable(KM KM.cpp common.cpp common.h)
target_link_libraries(KM OpenSSL::Crypto)
add_executable(nodeA nodeA.cpp common.cpp common.h)
target_link_libraries(nodeA OpenSSL::Crypto)
add_executable(nodeB nodeB.cpp common.cpp common.h)
target_link_libraries(nodeB OpenSSL::Crypto)
