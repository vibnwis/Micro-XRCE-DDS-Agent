/*
 * CAN2Agent.hpp
 *
 *  Created on: Nov 13, 2020
 *      Author: wiki-ros
 */

#ifndef INCLUDE_UXR_AGENT_TRANSPORT_CAN_CAN2AGENTLINUX_HPP_
#define INCLUDE_UXR_AGENT_TRANSPORT_CAN_CAN2AGENTLINUX_HPP_

#include <uxr/agent/transport/Server.hpp>
#include <uxr/agent/transport/endpoint/CAN2EndPoint.hpp>

#include "socketcan_cpp.hpp"

#include <cstdint>
#include <cstddef>
#include <sys/poll.h>
#include <unordered_map>

namespace eprosima {
namespace uxr {

extern template class Server<CAN2EndPoint>; // Explicit instantiation declaration.
class CAN2Agent : public Server<CAN2EndPoint>
{
public:
	CAN2Agent(
		    uint16_t id,
			const char * dev,
			uint8_t len,
		    Middleware::Kind middleware_kind);

    ~CAN2Agent() final;

private:
    bool init() final;

    bool fini() final;


    bool recv_message(
            InputPacket<CAN2EndPoint>& input_packet,
            int timeout,
            TransportRc& transport_rc) final;

    bool send_message(
            OutputPacket<CAN2EndPoint> output_packet,
            TransportRc& transport_rc) final;

    bool handle_error(
            TransportRc transport_rc) final;

private:
    struct pollfd poll_fd_;
    uint8_t buffer_[SERVER_BUFFER_SIZE];
    uint16_t id_;
    uint8_t len_;
    const char * dev_;
    SocketCan socket_can_;
};

} // namespace uxr
} // namespace eprosima




#endif /* INCLUDE_UXR_AGENT_TRANSPORT_CAN_CAN2AGENTLINUX_HPP_ */
