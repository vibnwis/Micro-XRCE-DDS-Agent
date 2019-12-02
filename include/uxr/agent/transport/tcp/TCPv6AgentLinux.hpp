// Copyright 2018 Proyectos y Sistemas de Mantenimiento SL (eProsima).
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

#ifndef UXR_AGENT_TRANSPORT_TCPv6_AGENT_HPP_
#define UXR_AGENT_TRANSPORT_TCPv6_AGENT_HPP_

#include <uxr/agent/transport/tcp/TCPServerBase.hpp>
#include <uxr/agent/transport/Server.hpp>
#ifdef UAGENT_DISCOVERY_PROFILE
#include <uxr/agent/transport/discovery/DiscoveryServerLinux.hpp>
#endif
#ifdef UAGENT_P2P_PROFILE
#include <uxr/agent/transport/p2p/AgentDiscovererLinux.hpp>
#endif

#include <netinet/in.h>
#include <sys/poll.h>
#include <array>
#include <list>
#include <set>

namespace eprosima {
namespace uxr {

struct TCPv6ConnectionLinux : public TCPv6Connection
{
    struct pollfd* poll_fd;
};

extern template class Server<IPv6EndPoint>;

class TCPv6Agent : public Server<IPv6EndPoint>, public TCPServerBase<TCPv6ConnectionLinux>
{
public:
    TCPv6Agent(
            uint16_t agent_port,
            Middleware::Kind middleware_kind);

    ~TCPv6Agent() final;

private:
    bool init() final;

    bool close() final;

#ifdef UAGENT_DISCOVERY_PROFILE
    bool init_discovery(uint16_t discovery_port) final;

    bool close_discovery() final;
#endif

#ifdef UAGENT_P2P_PROFILE
    bool init_p2p(uint16_t p2p_port) final;

    bool close_p2p() final;
#endif

    bool recv_message(
            InputPacket<IPv6EndPoint>& input_packet,
            int timeout) final;

    bool send_message(
            OutputPacket<IPv6EndPoint> output_packet) final;

    int get_error() final;

    bool read_message(
            int timeout);

    bool open_connection(
            int fd,
            struct sockaddr_in6& sockaddr);

    bool close_connection(
            TCPv6ConnectionLinux& connection);

    bool connection_available();

    void listener_loop();

    static void init_input_buffer(
            TCPInputBuffer& buffer);

    static void sigpipe_handler(int fd) { (void)fd; }

    size_t recv_data(
            TCPv6ConnectionLinux& connection,
            uint8_t* buffer,
            size_t len,
            uint8_t& errcode) final;

    size_t send_data(
            TCPv6ConnectionLinux& connection,
            uint8_t* buffer,
            size_t len,
            uint8_t& errcode) final;

private:
    std::array<TCPv6ConnectionLinux, TCP_MAX_CONNECTIONS> connections_;
    std::set<uint32_t> active_connections_;
    std::list<uint32_t> free_connections_;
    std::map<IPv6EndPoint, uint32_t> endpoint_to_connection_map_;
    std::mutex connections_mtx_;
    struct pollfd listener_poll_;
    std::array<struct pollfd, TCP_MAX_CONNECTIONS> poll_fds_;
    uint8_t buffer_[UINT16_MAX];
    uint16_t agent_port_;
    std::thread listener_thread_;
    std::atomic<bool> running_cond_;
    std::queue<InputPacket<IPv6EndPoint>> messages_queue_;
#ifdef UAGENT_DISCOVERY_PROFILE
    DiscoveryServerLinux<IPv6EndPoint> discovery_server_;
#endif
#ifdef UAGENT_P2P_PROFILE
    AgentDiscovererLinux agent_discoverer_;
#endif
};

} // namespace uxr
} // namespace eprosima

#endif // UXR_AGENT_TRANSPORT_TCPv6_AGENT_HPP_
