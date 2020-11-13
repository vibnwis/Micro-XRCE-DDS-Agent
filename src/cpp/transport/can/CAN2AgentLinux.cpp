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

#define CAN_TRANSPORT_ACTIVE


CAN2Agent::CAN2Agent(
        uint16_t id,
		const char * dev,
		uint8_t len,
        Middleware::Kind middleware_kind)
    : Server<CAN2EndPoint>{middleware_kind}
    , poll_fd_{-1, 0, 0}
    , buffer_{0}
    , dev_{dev}
    , len_{len}
    , id_{id}
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
            UXR_DECORATE_RED("error stopping server"),
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
            UXR_DECORATE_RED("CAN socket error"),
            "dev_: {}, errno: {}",
			dev_, errno);
    }

    return rv;
}

bool CAN2Agent::fini()
{
    if (-1 == poll_fd_.fd)
    {
        return true;
    }

    bool rv = false;

    if (0 == socket_can_.close())
    {
        poll_fd_.fd = -1;
        rv = true;
        UXR_AGENT_LOG_INFO(
            UXR_DECORATE_GREEN("CAN server stopped"),
            "dev_: {}",
			dev_);
    }
    else
    {
        UXR_AGENT_LOG_ERROR(
            UXR_DECORATE_RED("socket error"),
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
    	printf("*** CAN - read error *** \n");
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
    	
  //  	input_packet.message->set_id((uint16_t)can_msg.id);
  //  	input_packet.set_id(can_msg.id);
  //  	input_packet.id = can_msg.id;

    //	InputMessage imesg(can_msg.data, size_t(can_msg.len));

      //  input_packet.message.reset();

    //	uint32_t addr = client_addr.sin_addr.s_addr;
   // 	uint16_t port = client_addr.sin_port;

   // 	input_packet.source = CANEndPoint(addr, port);
   // 	            rv = true;

 //   	input_packet.message->set_port((uint16_t)can_msg.id);
 //   	input_packet.message->set_len((uint8_t)can_msg.len);
 //   	input_packet.message->set_data (can_msg.data);

      	rv = true;
       	UXR_AGENT_LOG_MESSAGE(
      			UXR_DECORATE_YELLOW("[** <<CAN>> **]"),
    			can_msg.id = 0x120,
				input_packet.message->get_buf(),
				input_packet.message->get_len());

     }

//    struct sockaddr_in client_addr{};
//    socklen_t client_addr_len = sizeof(struct sockaddr_in);

#if 0
    int poll_rv = poll(&poll_fd_, 1, timeout);
    if (0 < poll_rv)
    {
        ssize_t bytes_received =
                recvfrom(poll_fd_.fd,
                         buffer_,
                         sizeof(buffer_),
                         0,
                         reinterpret_cast<struct sockaddr*>(&client_addr),
                         &client_addr_len);
        if (-1 != bytes_received)
        {
            input_packet.message.reset(new InputMessage(buffer_, size_t(bytes_received)));
            uint32_t addr = client_addr.sin_addr.s_addr;
            uint16_t port = client_addr.sin_port;
            input_packet.source = CANEndPoint(addr, port);
            rv = true;

            uint32_t raw_client_key = 0u;
            Server<CANEndPoint>::get_client_key(input_packet.source, raw_client_key);
            UXR_AGENT_LOG_MESSAGE(
                UXR_DECORATE_YELLOW("[==>> UDP <<==]"),
                raw_client_key,
                input_packet.message->get_addr(),
                input_packet.message->get_port());
        }
        else
        {
            transport_rc = TransportRc::server_error;
        }
    }
    else
    {
        transport_rc = (0 == poll_rv) ? TransportRc::timeout_error : TransportRc::server_error;
    }
#endif

    return rv;
}

bool CAN2Agent::send_message(
        OutputPacket<CAN2EndPoint> output_packet,
        TransportRc& transport_rc)
{
    bool rv = false;
    SocketCanStatus can_status = STATUS_CAN_OP_ERROR;
    struct CanFrame can_msg;


 //   struct sockaddr_in client_addr{};

    can_msg.id = 0x120;
    can_msg.len = output_packet.message->get_len();

    memcpy(can_msg.data, output_packet.message->get_buf(), can_msg.len + 1);


    if (STATUS_OK != (can_status = socket_can_.write(can_msg)))
    {
    	printf("something went wrong on socket write, error code : %d \n", int32_t(can_status));
    	transport_rc = TransportRc::server_error;
    }
    else
    {
    	rv = true;
    	UXR_AGENT_LOG_MESSAGE(
   			UXR_DECORATE_YELLOW("[** <<CAN>> **]"),
			can_msg.id = 0x120,
			output_packet.message->get_buf(),
   	        output_packet.message->get_len());

    	printf("Message was written to the socket \n");

   }

#if 0
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = output_packet.destination.get_port();
    client_addr.sin_addr.s_addr = output_packet.destination.get_addr();

    ssize_t bytes_sent =
        sendto(
            poll_fd_.fd,
            output_packet.message->get_buf(),
            output_packet.message->get_len(),
            0,
            reinterpret_cast<struct sockaddr*>(&client_addr),
            sizeof(client_addr));
    if (-1 != bytes_sent)
    {
        if (size_t(bytes_sent) == output_packet.message->get_len())
        {
            rv = true;
            uint32_t raw_client_key = 0u;
            Server<CANEndPoint>::get_client_key(output_packet.destination, raw_client_key);
            UXR_AGENT_LOG_MESSAGE(
                UXR_DECORATE_YELLOW("[** <<UDP>> **]"),
                raw_client_key,
                output_packet.message->get_buf(),
                output_packet.message->get_len());
        }
    }
    else
    {
        transport_rc = TransportRc::server_error;
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







