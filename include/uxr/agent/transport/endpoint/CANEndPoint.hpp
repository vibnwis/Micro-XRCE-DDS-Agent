
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
 * CANEndPoint.hpp
 *
 *  Created on: Nov 6, 2020
 *      Author: wiki-ros
 */

#ifndef INCLUDE_UXR_AGENT_TRANSPORT_ENDPOINT_CANENDPOINT_HPP_
#define INCLUDE_UXR_AGENT_TRANSPORT_ENDPOINT_CANENDPOINT_HPP_


#include <uxr/agent/transport/endpoint/EndPoint.hpp>

#include <stdint.h>
#include <iostream>

namespace eprosima {
namespace uxr {

class CANEndPoint
{
public:
	CANEndPoint() = default;

	CANEndPoint(
            uint32_t addr,
            uint16_t port)
        : addr_(addr)
        , port_(port)
    {}

    ~CANEndPoint() = default;

    bool operator<(const CANEndPoint& other) const
    {
        return (addr_ < other.addr_) || ((addr_ == other.addr_) && (port_ < other.port_));
    }

   friend std::ostream& operator<<(std::ostream& os, const CANEndPoint& endpoint)
   {
       os << int(uint8_t(endpoint.addr_)) << "."
          << int(uint8_t(endpoint.addr_ >> 8)) << "."
          << int(uint8_t(endpoint.addr_ >> 16)) << "."
          << int(uint8_t(endpoint.addr_ >> 24)) << ":"
          << endpoint.get_port();
       return os;
   }

    uint32_t get_addr() const { return addr_; }
 
    uint16_t get_port() const { return port_; }
    
    void set_port(uint16_t can_id){
    	port_ = 0x0FFF & can_id;
    }
    
    void set_len(uint8_t len){
        	len_ = len;
    }
    
    uint8_t get_len(){
           return len_;
    }
    
    uint8_t get_data(uint8_t *in_data) { 
    	memcpy(in_data, data_, len_);		// len = port & 0x0007
    	return len_; 
    }
    
    uint8_t set_data(uint8_t *in_data) {
    	
    	memcpy(data_, in_data, len_);		// len = port & 0x0007
    	return len_;
    }

private:
    uint32_t addr_;
    uint16_t port_;
    uint8_t data_[8];
    uint8_t len_;
};


} // namespace uxr
} // namespace eprosima



#endif /* INCLUDE_UXR_AGENT_TRANSPORT_ENDPOINT_CANENDPOINT_HPP_ */
