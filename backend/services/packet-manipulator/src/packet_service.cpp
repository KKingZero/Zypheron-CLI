#include "packet_service.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <thread>

// Platform-specific includes
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netinet/ip.h>
    #include <netinet/tcp.h>
    #include <netinet/udp.h>
    #include <arpa/inet.h>
    #include <unistd.h>
#endif

class PacketService::Impl {
public:
    Impl() {
        #ifdef _WIN32
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
        #endif
    }
    
    ~Impl() {
        #ifdef _WIN32
        WSACleanup();
        #endif
    }
    
    std::string CraftPacket(const cobra::packet::CraftPacketRequest& request) {
        std::vector<uint8_t> packet;
        
        if (request.packet_type() == cobra::packet::PacketType::TCP) {
            craftTCPPacket(packet, request);
        } else if (request.packet_type() == cobra::packet::PacketType::UDP) {
            craftUDPPacket(packet, request);
        } else if (request.packet_type() == cobra::packet::PacketType::ICMP) {
            craftICMPPacket(packet, request);
        } else if (request.packet_type() == cobra::packet::PacketType::CUSTOM) {
            // Custom packet from hex string
            std::string hex = request.custom_hex();
            for (size_t i = 0; i < hex.length(); i += 2) {
                std::string byte = hex.substr(i, 2);
                packet.push_back(static_cast<uint8_t>(std::stoi(byte, nullptr, 16)));
            }
        }
        
        return std::string(packet.begin(), packet.end());
    }
    
    cobra::packet::PacketInfo AnalyzePacket(const std::string& packet_data) {
        cobra::packet::PacketInfo info;
        
        if (packet_data.size() < 20) {
            info.set_packet_type(cobra::packet::PacketType::UNKNOWN);
            info.set_error("Packet too small");
            return info;
        }
        
        // Basic IP header analysis
        uint8_t version = (packet_data[0] >> 4) & 0x0F;
        uint8_t protocol = packet_data[9];
        
        info.set_source_ip(ipToString(&packet_data[12]));
        info.set_destination_ip(ipToString(&packet_data[16]));
        info.set_packet_size(packet_data.size());
        
        // Set protocol type
        if (protocol == 6) {
            info.set_packet_type(cobra::packet::PacketType::TCP);
            analyzeTCP(info, packet_data);
        } else if (protocol == 17) {
            info.set_packet_type(cobra::packet::PacketType::UDP);
            analyzeUDP(info, packet_data);
        } else if (protocol == 1) {
            info.set_packet_type(cobra::packet::PacketType::ICMP);
        } else {
            info.set_packet_type(cobra::packet::PacketType::CUSTOM);
        }
        
        return info;
    }
    
    SendResult SendPacket(const cobra::packet::SendPacketRequest& request) {
        SendResult result;
        result.packets_sent = 0;
        
        try {
            // Note: Raw socket operations require admin/root privileges
            #ifdef _WIN32
            SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
            if (sock == INVALID_SOCKET) {
                result.success = false;
                result.message = "Failed to create raw socket (requires admin privileges)";
                return result;
            }
            #else
            int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
            if (sock < 0) {
                result.success = false;
                result.message = "Failed to create raw socket (requires root privileges)";
                return result;
            }
            #endif
            
            // Send packets
            for (int i = 0; i < request.count(); i++) {
                // In production, would send actual packet
                // For now, simulate sending
                std::this_thread::sleep_for(std::chrono::milliseconds(request.delay_ms()));
                result.packets_sent++;
            }
            
            #ifdef _WIN32
            closesocket(sock);
            #else
            close(sock);
            #endif
            
            result.success = true;
            result.message = "Packets sent successfully";
        } catch (const std::exception& e) {
            result.success = false;
            result.message = e.what();
        }
        
        return result;
    }
    
    void CapturePackets(const cobra::packet::CapturePacketsRequest& request,
                       std::function<void(const cobra::packet::PacketInfo&)> callback) {
        // Simplified packet capture simulation
        // In production, would use pcap library
        
        int count = 0;
        auto start = std::chrono::steady_clock::now();
        
        while (count < request.max_packets()) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start).count();
            
            if (request.timeout_seconds() > 0 && elapsed >= request.timeout_seconds()) {
                break;
            }
            
            // Simulate captured packet
            cobra::packet::PacketInfo packet;
            packet.set_packet_type(cobra::packet::PacketType::TCP);
            packet.set_source_ip("192.168.1." + std::to_string(rand() % 255));
            packet.set_destination_ip(request.target_ip());
            packet.set_source_port(rand() % 65535);
            packet.set_destination_port(80);
            packet.set_packet_size(rand() % 1500);
            
            // Create timestamp
            auto* timestamp = packet.mutable_timestamp();
            timestamp->set_seconds(std::chrono::system_clock::now().time_since_epoch().count());
            
            callback(packet);
            count++;
            
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    
private:
    void craftTCPPacket(std::vector<uint8_t>& packet, const cobra::packet::CraftPacketRequest& request) {
        // Simplified TCP packet crafting
        // In production, would create proper IP + TCP headers
        
        // Add some dummy data to represent a TCP packet
        packet.resize(60); // Min TCP packet size
        
        // Version + IHL
        packet[0] = 0x45;
        
        // Protocol (TCP = 6)
        packet[9] = 6;
        
        // Source IP (simplified)
        packet[12] = 192;
        packet[13] = 168;
        packet[14] = 1;
        packet[15] = 100;
        
        // Dest IP (simplified)
        packet[16] = 10;
        packet[17] = 0;
        packet[18] = 0;
        packet[19] = 1;
        
        // TCP header starts at byte 20
        // Source port
        packet[20] = (request.source_port() >> 8) & 0xFF;
        packet[21] = request.source_port() & 0xFF;
        
        // Dest port
        packet[22] = (request.destination_port() >> 8) & 0xFF;
        packet[23] = request.destination_port() & 0xFF;
        
        // TCP flags
        if (request.tcp_flags().syn()) packet[33] |= 0x02;
        if (request.tcp_flags().ack()) packet[33] |= 0x10;
        if (request.tcp_flags().fin()) packet[33] |= 0x01;
        if (request.tcp_flags().rst()) packet[33] |= 0x04;
        if (request.tcp_flags().psh()) packet[33] |= 0x08;
        if (request.tcp_flags().urg()) packet[33] |= 0x20;
    }
    
    void craftUDPPacket(std::vector<uint8_t>& packet, const cobra::packet::CraftPacketRequest& request) {
        // Simplified UDP packet crafting
        packet.resize(28); // Min UDP packet size
        
        // IP header
        packet[0] = 0x45;
        packet[9] = 17; // UDP protocol
        
        // UDP header starts at byte 20
        packet[20] = (request.source_port() >> 8) & 0xFF;
        packet[21] = request.source_port() & 0xFF;
        packet[22] = (request.destination_port() >> 8) & 0xFF;
        packet[23] = request.destination_port() & 0xFF;
    }
    
    void craftICMPPacket(std::vector<uint8_t>& packet, const cobra::packet::CraftPacketRequest& request) {
        // Simplified ICMP packet crafting
        packet.resize(28);
        
        packet[0] = 0x45;
        packet[9] = 1; // ICMP protocol
        
        // ICMP header
        packet[20] = 8; // Echo request
        packet[21] = 0; // Code
    }
    
    void analyzeTCP(cobra::packet::PacketInfo& info, const std::string& packet_data) {
        if (packet_data.size() >= 40) {
            // Extract TCP ports
            uint16_t src_port = (packet_data[20] << 8) | packet_data[21];
            uint16_t dst_port = (packet_data[22] << 8) | packet_data[23];
            
            info.set_source_port(src_port);
            info.set_destination_port(dst_port);
            
            // Extract TCP flags
            uint8_t flags = packet_data[33];
            auto* tcp_flags = info.mutable_tcp_flags();
            tcp_flags->set_syn(flags & 0x02);
            tcp_flags->set_ack(flags & 0x10);
            tcp_flags->set_fin(flags & 0x01);
            tcp_flags->set_rst(flags & 0x04);
            tcp_flags->set_psh(flags & 0x08);
            tcp_flags->set_urg(flags & 0x20);
        }
    }
    
    void analyzeUDP(cobra::packet::PacketInfo& info, const std::string& packet_data) {
        if (packet_data.size() >= 28) {
            uint16_t src_port = (packet_data[20] << 8) | packet_data[21];
            uint16_t dst_port = (packet_data[22] << 8) | packet_data[23];
            
            info.set_source_port(src_port);
            info.set_destination_port(dst_port);
        }
    }
    
    std::string ipToString(const char* ip_bytes) {
        std::stringstream ss;
        ss << (int)(unsigned char)ip_bytes[0] << "."
           << (int)(unsigned char)ip_bytes[1] << "."
           << (int)(unsigned char)ip_bytes[2] << "."
           << (int)(unsigned char)ip_bytes[3];
        return ss.str();
    }
};

// PacketService implementation
PacketService::PacketService() : pImpl(std::make_unique<Impl>()) {}
PacketService::~PacketService() = default;

std::string PacketService::CraftPacket(const cobra::packet::CraftPacketRequest& request) {
    return pImpl->CraftPacket(request);
}

cobra::packet::PacketInfo PacketService::AnalyzePacket(const std::string& packet_data) {
    return pImpl->AnalyzePacket(packet_data);
}

SendResult PacketService::SendPacket(const cobra::packet::SendPacketRequest& request) {
    return pImpl->SendPacket(request);
}

void PacketService::CapturePackets(const cobra::packet::CapturePacketsRequest& request,
                                  std::function<void(const cobra::packet::PacketInfo&)> callback) {
    pImpl->CapturePackets(request, callback);
} 