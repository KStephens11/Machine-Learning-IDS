#include <iostream>
#include <deque>
#include <mutex>

#include <nanobind/nanobind.h>
#include <nanobind/stl/vector.h>
#include <nanobind/stl/string.h>

#include <PcapLiveDeviceList.h>
#include <PcapLiveDevice.h>
#include <Packet.h>
#include <EthLayer.h>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <TcpLayer.h>
#include <UdpLayer.h>

namespace nb = nanobind;

struct PacketData
{   
    double timetamp;
    uint8_t protocol = -1;
    std::string src_ip{};
    std::string dst_ip{};
    uint16_t src_port = -1;
    uint16_t dst_port = -1;

    uint16_t win_size = 0;

    uint16_t transport_header_size = 0;
    uint16_t transport_payload_size = 0;

    uint16_t ether_header_size = 0;
    uint16_t ether_payload_size = 0;

    uint16_t ip_header_size = 0;
    uint16_t ip_payload_size = 0;

    uint16_t packet_size = 0;

    uint16_t syn_flag = 0;
    uint16_t ack_flag = 0;
    uint16_t fin_flag = 0;
    uint16_t rst_flag = 0;
    uint16_t psh_flag = 0;
    uint16_t urg_flag = 0;
    uint16_t ece_flag = 0;
    uint16_t cwr_flag = 0;
};

std::deque<PacketData> packets;

pcpp::PcapLiveDevice* device = nullptr;

std::mutex packetsMutex;

static void onPacketArrival(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie)
{
    PacketData data;

    data.timetamp = packet->getPacketTimeStamp().tv_sec + packet->getPacketTimeStamp().tv_nsec / 1e9; //1bil
    data.packet_size = packet->getRawDataLen();

    pcpp::Packet parsedPacket(packet);

    if (auto ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>())
    {
        data.protocol = ipLayer->getIPv4Header()->protocol;
        data.src_ip = ipLayer->getSrcIPAddress().toString();
        data.dst_ip = ipLayer->getDstIPAddress().toString();

        data.ip_header_size = ipLayer->getHeaderLen();
        data.ip_payload_size = ipLayer->getLayerPayloadSize();
    }
    else if (auto ipLayer = parsedPacket.getLayerOfType<pcpp::IPv6Layer>())
    {   
        data.protocol = ipLayer->getIPv6Header()->nextHeader;
        data.src_ip = ipLayer->getSrcIPAddress().toString();
        data.dst_ip = ipLayer->getDstIPAddress().toString();

        data.ip_header_size = ipLayer->getHeaderLen();
        data.ip_payload_size = ipLayer->getLayerPayloadSize();
    }
    if ((data.protocol == 17 || data.protocol == 6) && (data.src_ip != "" || data.dst_ip != ""))
    {

        if (auto etherLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>())
        {
            data.ether_header_size = etherLayer->getHeaderLen();
            data.ether_payload_size = etherLayer->getLayerPayloadSize();
        }

        if (auto tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>())
        {
            data.src_port = tcpLayer->getSrcPort();
            data.dst_port = tcpLayer->getDstPort();
            data.win_size = tcpLayer->getTcpHeader()->windowSize;

            data.transport_header_size = tcpLayer->getHeaderLen();
            data.transport_payload_size = tcpLayer->getLayerPayloadSize();

            data.syn_flag = tcpLayer->getTcpHeader()->synFlag;
            data.ack_flag = tcpLayer->getTcpHeader()->ackFlag;
            data.fin_flag = tcpLayer->getTcpHeader()->finFlag;
            data.rst_flag = tcpLayer->getTcpHeader()->rstFlag;
            data.psh_flag = tcpLayer->getTcpHeader()->pshFlag;
            data.urg_flag = tcpLayer->getTcpHeader()->urgFlag;
            data.ece_flag = tcpLayer->getTcpHeader()->eceFlag;
            data.cwr_flag = tcpLayer->getTcpHeader()->cwrFlag;
            
        }
        else if (auto udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>())
        {
            data.src_port = udpLayer->getSrcPort();
            data.dst_port = udpLayer->getDstPort();

            data.transport_header_size = udpLayer->getHeaderLen();
            data.transport_payload_size = udpLayer->getLayerPayloadSize();

        }

        std::lock_guard<std::mutex> lock(packetsMutex);
        packets.push_back(data);
    }
}

void start(const std::string& interface_ip)
{
    device = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interface_ip);
    if (!device)
    {
        std::cerr << "Cannot find device with IPv4 address '" << interface_ip << "'" << std::endl;
        return;
    }

    if (!device->open())
    {
        std::cerr << "Cannot open device" << std::endl;
        return;
    }

    device->startCapture(onPacketArrival, nullptr);
}

void stop()
{
    if (device)
    {
        device->stopCapture();
        device->close();
        device = nullptr;
    }
}

bool has_next()
{
    return !packets.empty();
}

PacketData get_packet()
{   

    std::lock_guard<std::mutex> lock(packetsMutex);

    if (!packets.empty())
    {
        PacketData packet = packets.front();
        packets.pop_front();
        return packet;
    }
    else
    {
        return PacketData{};
    }
}

NB_MODULE(packet_capture, module)
{
    module.def("start", &start);
    module.def("stop", &stop);
    module.def("has_next", &has_next);
    module.def("get_packet", &get_packet);

    nb::class_<PacketData>(module, "PacketData")
        .def_ro("timestamp", &PacketData::timetamp)
        .def_ro("protocol", &PacketData::protocol)

        .def_ro("src_ip", &PacketData::src_ip)
        .def_ro("dst_ip", &PacketData::dst_ip)
        .def_ro("src_port", &PacketData::src_port)
        .def_ro("dst_port", &PacketData::dst_port)

        .def_ro("win_size", &PacketData::win_size)

        .def_ro("ether_payload_size", &PacketData::ether_payload_size)
        .def_ro("ether_header_size", &PacketData::ether_payload_size)

        .def_ro("ip_header_size", &PacketData::ip_header_size)
        .def_ro("ip_payload_size", &PacketData::ip_payload_size)

        .def_ro("transport_header_size", &PacketData::transport_header_size)
        .def_ro("transport_payload_size", &PacketData::transport_payload_size)
        
        .def_ro("packet_size", &PacketData::packet_size)

        .def_ro("syn_flag", &PacketData::syn_flag)
        .def_ro("ack_flag", &PacketData::ack_flag)
        .def_ro("fin_flag", &PacketData::fin_flag)
        .def_ro("rst_flag", &PacketData::rst_flag)
        .def_ro("psh_flag", &PacketData::psh_flag)
        .def_ro("urg_flag", &PacketData::urg_flag)
        .def_ro("ece_flag", &PacketData::ece_flag)
        .def_ro("cwr_flag", &PacketData::cwr_flag);
}
