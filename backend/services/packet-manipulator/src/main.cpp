#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <functional>

#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>
#include <grpcpp/ext/proto_server_reflection_plugin.h>

#include "packet.grpc.pb.h"
#include "packet_service.h"

#ifdef _WIN32
    #include <windows.h>
#else
    #include <unistd.h>
#endif

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;

class PacketManipulatorServiceImpl final : public cobra::packet::PacketManipulator::Service {
private:
    std::unique_ptr<PacketService> packet_service_;
    std::chrono::steady_clock::time_point start_time_;

public:
    PacketManipulatorServiceImpl() 
        : packet_service_(std::make_unique<PacketService>()),
          start_time_(std::chrono::steady_clock::now()) {
        std::cout << "PacketManipulator service initialized" << std::endl;
    }

    Status HealthCheck(ServerContext* context, 
                      const cobra::HealthCheckRequest* request,
                      cobra::HealthCheckResponse* response) override {
        response->set_status("healthy");
        response->set_service_name("COBRA AI Packet Manipulator");
        response->set_version("1.0.0");
        
        auto now = std::chrono::steady_clock::now();
        auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now - start_time_).count();
        response->set_uptime_seconds(uptime);
        
        return Status::OK;
    }

    Status CraftPacket(ServerContext* context,
                      const cobra::packet::CraftPacketRequest* request,
                      cobra::packet::CraftPacketResponse* response) override {
        try {
            auto packet_data = packet_service_->CraftPacket(*request);
            
            response->mutable_status()->set_success(true);
            response->mutable_status()->set_message("Packet crafted successfully");
            response->set_packet_data(packet_data);
            response->set_packet_size(packet_data.size());
            response->set_packet_hex(BytesToHex(packet_data));
            
            return Status::OK;
        } catch (const std::exception& e) {
            response->mutable_status()->set_success(false);
            response->mutable_status()->set_message(e.what());
            return Status::OK;
        }
    }

    Status AnalyzePacket(ServerContext* context,
                        const cobra::packet::AnalyzePacketRequest* request,
                        cobra::packet::AnalyzePacketResponse* response) override {
        try {
            auto packet_info = packet_service_->AnalyzePacket(request->packet_data());
            
            response->mutable_status()->set_success(true);
            response->mutable_status()->set_message("Packet analyzed successfully");
            response->mutable_info()->CopyFrom(packet_info);
            
            return Status::OK;
        } catch (const std::exception& e) {
            response->mutable_status()->set_success(false);
            response->mutable_status()->set_message(e.what());
            return Status::OK;
        }
    }

    Status SendPacket(ServerContext* context,
                     const cobra::packet::SendPacketRequest* request,
                     cobra::packet::SendPacketResponse* response) override {
        try {
            auto result = packet_service_->SendPacket(*request);
            
            response->mutable_status()->set_success(result.success);
            response->mutable_status()->set_message(result.message);
            response->set_packets_sent(result.packets_sent);
            
            for (const auto& error : result.errors) {
                response->add_errors(error);
            }
            
            return Status::OK;
        } catch (const std::exception& e) {
            response->mutable_status()->set_success(false);
            response->mutable_status()->set_message(e.what());
            return Status::OK;
        }
    }

    Status CapturePackets(ServerContext* context,
                         const cobra::packet::CapturePacketsRequest* request,
                         grpc::ServerWriter<cobra::packet::PacketInfo>* writer) override {
        try {
            packet_service_->CapturePackets(*request, 
                [writer](const cobra::packet::PacketInfo& packet) {
                    writer->Write(packet);
                });
            return Status::OK;
        } catch (const std::exception& e) {
            return Status(grpc::StatusCode::INTERNAL, e.what());
        }
    }

private:
    std::string BytesToHex(const std::string& bytes) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (unsigned char c : bytes) {
            ss << std::setw(2) << static_cast<int>(c);
        }
        return ss.str();
    }
};

void RunServer() {
    std::string server_address("0.0.0.0:8003");
    PacketManipulatorServiceImpl service;

    grpc::EnableDefaultHealthCheckService(true);
    grpc::reflection::InitProtoReflectionServerBuilderPlugin();
    
    ServerBuilder builder;
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);
    
    std::unique_ptr<Server> server(builder.BuildAndStart());
    std::cout << "🔧 C++ Packet Manipulator listening on " << server_address << std::endl;
    
    server->Wait();
}

int main(int argc, char** argv) {
    std::cout << "Starting COBRA AI Packet Manipulator Service..." << std::endl;
    
    // Check for root/admin privileges (required for raw sockets)
    #ifdef _WIN32
        if (!IsUserAnAdmin()) {
            std::cerr << "Warning: This service requires administrator privileges for full functionality" << std::endl;
        }
    #else
        if (geteuid() != 0) {
            std::cerr << "Warning: This service requires root privileges for full functionality" << std::endl;
        }
    #endif
    
    RunServer();
    return 0;
} 