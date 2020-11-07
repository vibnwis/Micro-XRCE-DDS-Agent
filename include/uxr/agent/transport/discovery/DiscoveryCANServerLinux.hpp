/*
 * DiscoveryCANServerLinux.hpp
 *
 *  Created on: Nov 7, 2020
 *      Author: wiki-ros
 */

#ifndef INCLUDE_UXR_AGENT_TRANSPORT_DISCOVERY_DISCOVERYCANSERVERLINUX_HPP_
#define INCLUDE_UXR_AGENT_TRANSPORT_DISCOVERY_DISCOVERYCANSERVERLINUX_HPP_

#include <uxr/agent/transport/discovery/DiscoveryServer.hpp>
#include <uxr/agent/message/Packet.hpp>

#include <thread>
#include <atomic>
#include <sys/poll.h>
#include <type_traits>

namespace eprosima {
namespace uxr {

template<typename EndPoint>
class DiscoveryCANServerLinux : public DiscoveryServer<EndPoint>
{
public:
	DiscoveryCANServerLinux(
            const Processor<EndPoint>& processor);

    ~DiscoveryCANServerLinux() override = default;

private:
    bool init(
            uint16_t discovery_port) final;

    bool close() final;

    bool recv_message(
            InputPacket<IPv4EndPoint>& input_packet, int timeout) final ;

    bool send_message(
            OutputPacket<IPv4EndPoint>&& output_packet) final;

private:
    struct pollfd poll_fd_;
    uint8_t buffer_[128];
};

} // namespace uxr
} // namespace eprosima



#endif /* INCLUDE_UXR_AGENT_TRANSPORT_DISCOVERY_DISCOVERYCANSERVERLINUX_HPP_ */
