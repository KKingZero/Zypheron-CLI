cmake_minimum_required(VERSION 3.20)
project(cobra-packet-manipulator)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find packages
find_package(Threads REQUIRED)
find_package(Protobuf CONFIG REQUIRED)
find_package(gRPC CONFIG REQUIRED)

# Proto files
set(PROTO_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../proto")
set(PROTO_FILES
    ${PROTO_PATH}/packet.proto
    ${PROTO_PATH}/common.proto
)

# Generate proto sources
set(PROTO_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/proto")
file(MAKE_DIRECTORY ${PROTO_BINARY_DIR})

protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${PROTO_FILES})
grpc_generate_cpp(GRPC_SRCS GRPC_HDRS ${PROTO_BINARY_DIR} ${PROTO_FILES})

# Include directories
include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${PROTO_BINARY_DIR})
include_directories(src)

# Source files
set(SOURCES
    src/main.cpp
    src/packet_service.cpp
    src/packet_crafter.cpp
    src/packet_analyzer.cpp
    ${PROTO_SRCS}
    ${GRPC_SRCS}
)

# Executable
add_executable(packet-manipulator ${SOURCES})

# Link libraries
target_link_libraries(packet-manipulator
    PRIVATE
        Threads::Threads
        protobuf::libprotobuf
        gRPC::grpc++
        pcap
        ${CMAKE_DL_LIBS}
)

# Platform specific
if(WIN32)
    target_link_libraries(packet-manipulator PRIVATE ws2_32 iphlpapi)
endif()

# Install
install(TARGETS packet-manipulator DESTINATION bin) 