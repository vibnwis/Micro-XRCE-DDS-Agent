// Copyright 2017-present Proyectos y Sistemas de Mantenimiento SL (eProsima).
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

#ifndef UXR_AGENT_TRANSPORT_UTIL_INTERFACELINUX_HPP_
#define UXR_AGENT_TRANSPORT_UTIL_INTERFACELINUX_HPP_

#include <uxr/agent/transport/util/Interface.hpp>
#include <uxr/agent/transport/endpoint/IPv4EndPoint.hpp>
#include <uxr/agent/transport/endpoint/IPv6EndPoint.hpp>
#include <uxr/agent/logger/Logger.hpp>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ifaddrs.h>

namespace eprosima {
namespace uxr {
namespace util {

template<>
inline
InterfacesContainer get_transport_interfaces<IPv4EndPoint>(
    uint16_t agent_port)
{
    InterfacesContainer interfaces{};
    struct ifaddrs* ifaddr;
    struct ifaddrs* ptr;

    interfaces.clear();
    if (-1 != getifaddrs(&ifaddr))
    {
        for (ptr = ifaddr; ptr != nullptr; ptr = ptr->ifa_next)
        {
            if (AF_INET == ptr->ifa_addr->sa_family)
            {
                dds::xrce::TransportAddressMedium address_medium;
                address_medium.port(agent_port);
                const sockaddr_in* addr = reinterpret_cast<sockaddr_in*>(ptr->ifa_addr);
                std::memcpy(
                    address_medium.address().data(),
                    &addr->sin_addr.s_addr,
                    address_medium.address().size());
                dds::xrce::TransportAddress address;
                address.medium_locator(address_medium);
                interfaces.emplace(ptr->ifa_name, address);

                UXR_AGENT_LOG_TRACE(
                    UXR_DECORATE_WHITE("interface found"),
                    "address: {}",
                    address
                );
            }
        }
    }
    freeifaddrs(ifaddr);
    return interfaces;
}

template<>
inline
InterfacesContainer get_transport_interfaces<IPv6EndPoint>(
    uint16_t agent_port)
{
    InterfacesContainer interfaces{};
    struct ifaddrs* ifaddr;
    struct ifaddrs* ptr;

    interfaces.clear();
    if (-1 != getifaddrs(&ifaddr))
    {
        for (ptr = ifaddr; ptr != nullptr; ptr = ptr->ifa_next)
        {
            if (AF_INET6 == ptr->ifa_addr->sa_family)
            {
                dds::xrce::TransportAddressLarge address_large;
                address_large.port(agent_port);
                struct sockaddr_in6* addr = reinterpret_cast<sockaddr_in6*>(ptr->ifa_addr);
                std::memcpy(
                    address_large.address().data(),
                    &addr->sin6_addr.s6_addr,
                    address_large.address().size());
                dds::xrce::TransportAddress address;
                address.large_locator() = address_large;

                UXR_AGENT_LOG_TRACE(
                    UXR_DECORATE_WHITE("interface found"),
                    "address: {}",
                    address
                );
            }
        }
    }
    freeifaddrs(ifaddr);
    return interfaces;
}

} // namespace util
} // namespace uxr
} // namespace eprosima

#endif // UXR_AGENT_TRANSPORT_UTIL_INTERFACELINUX_HPP_