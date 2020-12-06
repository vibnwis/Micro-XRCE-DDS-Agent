/*
 * CAN2AgentLinux.cpp
 *
 *  Created on: Nov 13, 2020
 *      Author: wiki-ros
 */

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
#include <uxr/agent/types/MessageHeader.hpp>
#include <uxr/agent/types/SubMessageHeader.hpp>

#include <uxr/agent/transport/can/CAN2AgentLinux.hpp>
#include <uxr/agent/transport/can/socketcan_cpp.hpp>
#include <uxr/agent/transport/util/InterfaceLinux.hpp>
#include <uxr/agent/utils/Conversion.hpp>
#include <uxr/agent/logger/Logger.hpp>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <cerrno>

namespace eprosima {
namespace uxr {

#define CAN2_TRANSPORT_ACTIVE


CAN2Agent::CAN2Agent(
 //       uint16_t id,
		const std::string dev,
//const char * dev,
        Middleware::Kind middleware_kind)
    : Server<CAN2EndPoint>{middleware_kind}
    , poll_fd_{-1, 0, 0}
    , buffer_{0}
    , dev_{dev}
{}


CAN2Agent::~CAN2Agent()
{
    try
    {
        stop();
    }
    catch (std::exception& e)
    {
        UXR_AGENT_LOG_CRITICAL(
            UXR_DECORATE_RED("CAN2 error stopping server"),
            "exception: {}",
            e.what());
    }
}

bool CAN2Agent::init()
{
    bool rv = false;

    //SocketCan socket_can;
    int32_t read_timeout_ms = 1000;							// 1000ms
    //poll_fd_.fd = socket_can.open("can0"); 	// != scpp::STATUS_OK)
    poll_fd_.fd = socket_can_.open(dev_,read_timeout_ms, MODE_CAN_MTU); 	// != scpp::STATUS_OK)

    
    if (-1 == poll_fd_.fd)					// STATUS_OP_FAILED = -1
    {
        UXR_AGENT_LOG_ERROR(
            UXR_DECORATE_RED("CAN2 socket error"),
            "dev_: {}, errno: {}",
			dev_, errno);
    }
    else {
    	rv = true;
    }

    return rv;
}

bool CAN2Agent::fini()
{
    if (-1 == poll_fd_.fd)
    {
        return false;
    }

    bool rv = false;

    if (0 == socket_can_.close())
    {
        poll_fd_.fd = -1;
        rv = true;
        UXR_AGENT_LOG_INFO(
            UXR_DECORATE_GREEN("CAN2 server stopped"),
            "dev_: {}",
			dev_);
    }
    else
    {
        UXR_AGENT_LOG_ERROR(
            UXR_DECORATE_RED("CAN2 : socket error"),
            "dev_: {}, errno: {}",
			dev_, errno);
    }

    return rv;
}


bool CAN2Agent::recv_message(
        InputPacket<CAN2EndPoint>& input_packet,
        int timeout,
        TransportRc& transport_rc)
{
    bool rv = false;
    SocketCanStatus can_status = STATUS_CAN_OP_ERROR;
    struct CanFrame can_msg;
    int i = 0;

    if (socket_can_.read(can_msg) != STATUS_OK)
    {
    	printf("*** CAN2 - read error *** \n");
    	transport_rc = TransportRc::server_error;
    }
    else
    {
    	printf("len %d byte, id: %d ", can_msg.len, can_msg.id);
    	for (i=0; i < can_msg.len; i++)
    	{
    		printf("data[%d]: %02x ", i, can_msg.data[i]);
    	}

    	printf("\n");
    	input_packet.source.set_id(can_msg.id);
    	input_packet.source.set_len(can_msg.len);
    	input_packet.source.set_data(can_msg.data, can_msg.len);

      	rv = true;
       	UXR_AGENT_LOG_MESSAGE(
      			UXR_DECORATE_YELLOW("[** <<CAN2>> **]"),
    			can_msg.id = 0x120,
				input_packet.message->get_buf(),
				input_packet.message->get_len());

     }



    return rv;
}

bool CAN2Agent::send_message(
        OutputPacket<CAN2EndPoint> output_packet,
        TransportRc& transport_rc)
{
    bool rv = false;
    SocketCanStatus can_status = STATUS_CAN_OP_ERROR;
    struct CanFrame can_msg;
    uint8_t count =0;
#if 1
    can_msg.id = output_packet.destination.get_id();
    can_msg.len = output_packet.destination.get_len();
    
    while (output_packet.destination.get_data(can_msg.data) != can_msg.len )
    {
    	   printf("output_packet length and read data length mismatche\n");
    	   
    	   
    	   if (count++ > 8)
    	   {
    		   printf("output packet reading exceeded %d times \n", count);
    		   transport_rc = TransportRc::server_error;    	   
    		   break;
    	   }
    }
    

    if (count <= 8)
    {
    	printf("output packet reading count %d \n", count);
    		
    	if (STATUS_OK != (can_status = socket_can_.write(can_msg)))
    	{
    	
    		printf("something went wrong on socket write, error code : %d \n", int32_t(can_status));
    		transport_rc = TransportRc::server_error;
    	}
    	else
    	{
    		rv = true;
    		UXR_AGENT_LOG_MESSAGE(
   				UXR_DECORATE_YELLOW("[** <<CAN2>> **]"),
				can_msg.id,
				can_msg.data,
				can_msg.len);

    		printf("Message was written to the socket \n");

   		}
    }
#endif
    return rv;
}

bool CAN2Agent::handle_error(
        TransportRc /*transport_rc*/)
{
    return fini() && init();
}

} // namespace uxr
} // namespace eprosima







