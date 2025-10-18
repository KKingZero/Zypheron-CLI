#ifndef PACKET_SERVICE_H
#define PACKET_SERVICE_H

#include <string>
#include <vector>
#include <memory>
#include "packet.pb.h"

struct SendResult {
    bool success;
    std::string message;
    int packets_sent;
    std::vector<std::string> errors;
};

class PacketService {
public:
    PacketService();
    ~PacketService();
    
    std::string CraftPacket(const cobra::packet::CraftPacketRequest& request);
    cobra::packet::PacketInfo AnalyzePacket(const std::string& packet_data);
    SendResult SendPacket(const cobra::packet::SendPacketRequest& request);
    void CapturePackets(const cobra::packet::CapturePacketsRequest& request,
                       std::function<void(const cobra::packet::PacketInfo&)> callback);
    
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

#endif // PACKET_SERVICE_H 