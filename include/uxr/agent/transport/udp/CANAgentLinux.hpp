// Copyright 2019 Proyectos y Sistemas de Mantenimiento SL (eProsima).
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/*
 * CANAgentLinux.hpp
 *
 *  Created on: Nov 5, 2020
 *      Author: wiki-ros
 */

#ifndef INCLUDE_UXR_AGENT_TRANSPORT_UDP_CANAGENTLINUX_HPP_
#define INCLUDE_UXR_AGENT_TRANSPORT_UDP_CANAGENTLINUX_HPP_


#include <uxr/agent/transport/Server.hpp>
//#include <uxr/agent/transport/endpoint/IPv4EndPoint.hpp>
#include <uxr/agent/transport/endpoint/CANEndPoint.hpp>
#ifdef UAGENT_DISCOVERY_PROFILE
#include <uxr/agent/transport/discovery/DiscoveryCANServerLinux.hpp>
#endif
#ifdef UAGENT_P2P_PROFILE
#include <uxr/agent/transport/p2p/AgentDiscovererLinux.hpp>
#endif

#include <cstdint>
#include <cstddef>
#include <sys/poll.h>
#include <unordered_map>

namespace eprosima {
namespace uxr {

extern template class Server<CANEndPoint>; // Explicit instantiation declaration.

class CANAgent : public Server<CANEndPoint>
{
public:
	CANAgent(
            uint16_t port,
            Middleware::Kind middleware_kind);

    ~CANAgent() final;

private:
    bool init() final;

    bool fini() final;

#ifdef UAGENT_DISCOVERY_PROFILE
    bool init_discovery(uint16_t discovery_port) final;

    bool fini_discovery() final;
#endif

#ifdef UAGENT_P2P_PROFILE
    bool init_p2p(uint16_t p2p_port) final;

    bool fini_p2p() final;
#endif

    bool recv_message(
            InputPacket<CANEndPoint>& input_packet,
            int timeout,
            TransportRc& transport_rc) final;

    bool send_message(
            OutputPacket<CANEndPoint> output_packet,
            TransportRc& transport_rc) final;

    bool handle_error(
            TransportRc transport_rc) final;

private:
    struct pollfd poll_fd_;
    uint8_t buffer_[SERVER_BUFFER_SIZE];
    uint16_t agent_port_;
#ifdef UAGENT_DISCOVERY_PROFILE
    DiscoveryCANServerLinux<CANEndPoint> discovery_server_;
#endif
#ifdef UAGENT_P2P_PROFILE
    AgentDiscovererLinux agent_discoverer_;
#endif
};

} // namespace uxr
} // namespace eprosima


#endif /* INCLUDE_UXR_AGENT_TRANSPORT_UDP_CANAGENTLINUX_HPP_ */
