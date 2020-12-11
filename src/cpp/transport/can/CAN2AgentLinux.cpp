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
    int32_t read_timeout_ms = 1000;
    int ret_val = 0;
    // 1000ms
    //poll_fd_.fd = socket_can.open("can0"); 	// != scpp::STATUS_OK)
    ret_val = socket_can_.open(dev_,read_timeout_ms, MODE_CAN_MTU); 	// != scpp::STATUS_OK)

    poll_fd_.fd = ret_val;
    if (-1 != ret_val)					// STATUS_OP_FAILED = -1
    {
    	rv = true;
    	return rv;
    }

#ifdef SW_UXR_AGENT_ON
        UXR_AGENT_LOG_ERROR(
            UXR_DECORATE_RED("CAN2 socket error"),
            "dev_: {}, errno: {}",
			dev_, errno);
#endif

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
#ifdef SW_UXR_AGENT_ON
        UXR_AGENT_LOG_INFO(
            UXR_DECORATE_GREEN("CAN2 server stopped"),
            "dev_: {}",
			dev_);
#endif
    }
    else
    {
#ifdef SW_UXR_AGENT_ON
        UXR_AGENT_LOG_ERROR(
            UXR_DECORATE_RED("CAN2 : socket error"),
            "dev_: {}, errno: {}",
			dev_, errno);
#endif
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
    printf("CAN2Agent::recv_message() entered \n");

    memset(&can_msg, 0, sizeof(struct CanFrame));

    if (socket_can_.read(can_msg) != STATUS_OK)
    {
    	printf("*** CAN2 - read error *** \n");
#ifdef SW_UXR_AGENT_ON
    	transport_rc = TransportRc::server_error;
#endif
    	return rv;
    }
    else
    {

    	memset(buffer_, 0, CAN2ENDPOINT_BUFFER_SIZE);
    	memcpy(buffer_, can_msg.data, can_msg.len);		//only frame's payload

    	input_packet.message.reset(new InputMessage(buffer_, can_msg.len));
    	input_packet.source = CAN2EndPoint(can_msg.id, can_msg.len);
    	rv = true;



    	uint32_t raw_client_key = 0u;
    	Server<CAN2EndPoint>::get_client_key(input_packet.source, raw_client_key);
    	UXR_AGENT_LOG_MESSAGE(
    			UXR_DECORATE_YELLOW("[==>> CAN2 <<==]"),
    	        raw_client_key,
    	        input_packet.message->get_buf(),
    	        input_packet.message->get_len());

    	printf("len %d byte, id: %d ", can_msg.len, can_msg.id);
    	for (i=0; i < can_msg.len; i++)
    	{
    		printf("data[%d]: %02x ", i, can_msg.data[i]);
    	}

    	printf("\n");

    	printf("write frame_id to source of input_packet \n");
    //	input_packet.source.set_id(can_msg.id);

    	printf("write frame_len to source of input_packet \n");
    //	input_packet.source.set_len(can_msg.len);

    	printf("write frame_data to source of input_packet \n");
    	input_packet.source.set_data(can_msg.data, can_msg.len);
     }


    printf("CAN2Agent::recv_message() exited \n");
    return rv;
}

bool CAN2Agent::send_message(
        OutputPacket<CAN2EndPoint> output_packet,
        TransportRc& transport_rc)
{
    bool rv = false;
    SocketCanStatus can_status = STATUS_CAN_OP_ERROR;
    struct CanFrame can_msg;
    uint8_t data_size = 0;
    int i = 0;

    printf("CAN2Agent::send_message() entered \n");

    can_msg.id = output_packet.destination.get_id();
    printf("CAN2Agent::send_message() copied id %d", can_msg.id);

    can_msg.len = output_packet.destination.get_len();
    printf("CAN2Agent::send_message() copied len %d", can_msg.len);

    data_size = output_packet.destination.get_data(can_msg.data);

    if ( data_size != can_msg.len )
    {
    	   printf("output_packet length and read data length mis-matchex\n");
    	   printf("can2 data length is %d but the number bytes read are %d \n",can_msg.len, data_size);

    	   transport_rc = TransportRc::server_error;
    }
    else
    {
    	if (STATUS_OK != (can_status = socket_can_.write(can_msg)))
    	{
    		printf("something went wrong on socket write, error code : %d \n", int32_t(can_status));
    		transport_rc = TransportRc::server_error;
    	}
    	else
    	{
    		rv = true;
    		uint32_t raw_client_key = 0u;
    		Server<CAN2EndPoint>::get_client_key(output_packet.destination, raw_client_key);
    		UXR_AGENT_LOG_MESSAGE(
    				UXR_DECORATE_YELLOW("[** CAN2 send_message()**]"),
    		        raw_client_key,
    		        output_packet.message->get_buf(),
    		        output_packet.message->get_len());

    		printf("Message was written to the socket \n");

   		}
    }

    printf("CAN2Agent::send_message() exited \n");
    return rv;
}

bool CAN2Agent::handle_error(
        TransportRc /*transport_rc*/)
{
    return fini() && init();
}

} // namespace uxr
} // namespace eprosima







