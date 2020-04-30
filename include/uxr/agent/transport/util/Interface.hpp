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

#ifndef UXR__AGENT__TRANSPORT__UTIL__INTERFACE_HPP_
#define UXR__AGENT__TRANSPORT__UTIL__INTERFACE_HPP_

#include <uxr/agent/types/XRCETypes.hpp>

#include <iostream>

namespace eprosima {
namespace uxr {
namespace util {

using Interface = std::pair<std::string, dds::xrce::TransportAddress>;
using InterfacesContainer = std::map<Interface::first_type, Interface::second_type>;

template<typename E>
InterfacesContainer get_transport_interfaces(
    uint16_t agent_port);

} // namespace util
} // namespace uxr
} // namespace eprosima

inline
std::ostream & operator<<(std::ostream & os, dds::xrce::TransportAddressMedium const & address)
{
    os << int(address.address().at(0)) << "."
       << int(address.address().at(1)) << "."
       << int(address.address().at(2)) << "."
       << int(address.address().at(3)) << ":"
       << address.port();
    return os;
}

inline
std::ostream & operator<<(std::ostream & os, dds::xrce::TransportAddressLarge const & address)
{
    os << std::hex << "["
       << int(address.address().at(0))
       << int(address.address().at(1))
       << ":"
       << int(address.address().at(2))
       << int(address.address().at(3))
       << ":"
       << int(address.address().at(4))
       << int(address.address().at(5))
       << ":"
       << int(address.address().at(6))
       << int(address.address().at(7))
       << ":"
       << int(address.address().at(8))
       << int(address.address().at(9))
       << ":"
       << int(address.address().at(10))
       << int(address.address().at(11))
       << ":"
       << int(address.address().at(12))
       << int(address.address().at(13))
       << ":"
       << int(address.address().at(14))
       << int(address.address().at(15))
       << "]:" << std::dec
       << address.port();
    return os;
}

inline
std::ostream & operator<<(std::ostream & os, dds::xrce::TransportAddress const & address)
{
    switch (address._d())
    {
        case dds::xrce::ADDRESS_FORMAT_MEDIUM:
            os << address.medium_locator();
            break;
        case dds::xrce::ADDRESS_FORMAT_LARGE:
            os << address.large_locator();
            break;
        default:
            break;
    } 
    return os;
}

#endif // UXR__AGENT__TRANSPORT__UTIL__INTERFACE_HPP_