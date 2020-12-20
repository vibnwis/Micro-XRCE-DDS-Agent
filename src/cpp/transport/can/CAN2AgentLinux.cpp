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
    , can2_messages {0}
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

    initCAN2Message();

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
 //   SocketCanStatus can_status = STATUS_CAN_OP_ERROR;
    struct CanFrame can_msg;
    uint32_t i = 0;
    uint32_t id, length, msg_len = 0;
    uint8_t fr_num = 0;
    uint8_t arr[2048];

    printf("CAN2Agent::recv_message() entered \n");

    memset(&can_msg.data, 0, CAN2ENDPOINT_BUFFER_SIZE);
    can_msg.id = 0;
    can_msg.len = 0;
    can_msg.flags = 0;

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

    	// ----
    	if (0 < can_msg.len)   // a CAN frame is obtained
    	    {
    	    	fr_num = can_msg.data[0];
    	    	length = can_msg.len;
    	    	id = can_msg.id;
    	    	memcpy(arr, can_msg.data, length);

    	    	printf ("\n\r inFrame id=0x%x, fr_num=%d  length=%d\n\r", id, fr_num, length);
    	    	msg_len = processInFrame(id, arr, fr_num, length);

    	    	printf ("\n\r msg_len %d \n\r", msg_len);
    	    	if (msg_len) {
    	        	printf ("\n\r< CAN2 concatenated frames \n\r");
    	        	for (i=0; i<msg_len; i++) {
    	        		if (!(i%8))
    	        		    printf ("\n\r");
    	        		printf("[%d]=0x%x ", i, arr[i]);
    	        	}
    	        	printf ("\n\rCAN2 concatenated frames > \n\r");

    	        	memset(buffer_, 0, msg_len);  		//clear first
    	            memcpy(buffer_, arr, msg_len);		//only frame's payload

    	            resetIDMessage(id);

    	            input_packet.message.reset(new InputMessage(buffer_, msg_len));
    	            input_packet.source = CAN2EndPoint(id, msg_len);
    	            input_packet.source.set_data(arr, msg_len);

    	            uint32_t raw_client_key = 0u;
    	            Server<CAN2EndPoint>::get_client_key(input_packet.source, raw_client_key);
    	            UXR_AGENT_LOG_MESSAGE(
    	            	UXR_DECORATE_YELLOW("[==>> uAgent CAN2 <<==]"),
    	            	raw_client_key,
    	            	input_packet.message->get_buf(),
    	            	input_packet.message->get_len());

    	            printf("len %d byte, id: 0x%x \n", msg_len, id);
    	            for (i=0; i < msg_len; i++)
   	            	{
    	            	printf("data[%d]: 0x%x ", i, (int)arr[i]);
    	            	if (((i+1) % 8) == 0)
    	            		printf("\n");
   	            	}

   	            	printf("\n");

   	            	printf("write frame_id 0x%x to source of input_packet \n", id);
    	            //	input_packet.source.set_id(can_msg.id);

   	            	printf("write message_len %d to source of input_packet \n", msg_len);
    	            //	input_packet.source.set_len(can_msg.len);

   	            //	printf("write frame_data to source of input_packet \n");

    	        	rv = true;

    	        }
    	    }
    	//---




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
    uint32_t packet_data_size = 0;
    uint8_t f_num = 0;
    uint32_t quotient = 0;
    uint32_t remainder = 0;
    size_t index = 0;
    size_t to_write, frame_size;
    uint8_t fr_data[2048];
    uint32_t fr_id;
    uint32_t fr_len;
    size_t max_frame_data_size = CAN_MAX_DATA_SIZE-1;

    printf("CAN2Agent::send_message() entered \n");

    fr_id = output_packet.destination.get_id();
    printf("CAN2Agent::send_message() copied id %d", fr_id);

    fr_len = output_packet.destination.get_len();
    printf("CAN2Agent::send_message() copied len %d", fr_len);

    packet_data_size = output_packet.destination.get_data(fr_data);

    if ( packet_data_size != fr_len )
    {
    	   printf("output_packet length and read data length mis-matchex\n");
    	   printf("can2 data length is %d but the number bytes read are %d \n",fr_len, packet_data_size);

    	   transport_rc = TransportRc::server_error;
    }
    else
    {
    	//---

    	if (fr_len <= 0)
    	{
    		printf("output_packet length zero \n");
    		transport_rc = TransportRc::server_error;
    		return rv;
    	}

    	/* calculate number of smaller CAN frames */
    	if (fr_len <= max_frame_data_size)
    	{
    		f_num = 1;
    	}
    	else {
    		quotient = fr_len / max_frame_data_size;
    		remainder = fr_len % max_frame_data_size;

    		if (!remainder)
    			f_num = quotient;
    		else
    			f_num = quotient + 1;
    	}

    	while(fr_len > 0){

    		// decide the data length
    		to_write = (fr_len <= max_frame_data_size) ? fr_len : max_frame_data_size;

    		can_msg.data[0] = --f_num; //stores the frame number in the first byte of a frame can_msg.data[0]

    		memcpy(&can_msg.data[1], &fr_data[index], to_write); // can_msg.data[1..7] store data

    		frame_size = to_write + 1; //however, CAN frame size remain to_write + 1
    		can_msg.len = frame_size;
    		can_msg.id = fr_id;

    		fr_len -= to_write;   // deduct to_write from fr_len
    		index += to_write;    // add to the index

    		if (STATUS_OK != (can_status = socket_can_.write(can_msg)))
    		{
    		 	printf("something went wrong on socket write, error code : %d \n", int32_t(can_status));
    		    transport_rc = TransportRc::server_error;
    		    break;
    		 }

    		printf("Frame %d was written to the CANSocket.\n", f_num);
    		//sent_status |= STATUS_OK;
    		if (!f_num)
			{
    		 	rv = true;
    		 	uint32_t raw_client_key = 0u;
    		 	Server<CAN2EndPoint>::get_client_key(output_packet.destination, raw_client_key);
    		   		UXR_AGENT_LOG_MESSAGE(
    		 		UXR_DECORATE_YELLOW("[** CAN2 send_message()**]"),
    		        raw_client_key,
    		        output_packet.message->get_buf(),
    		    	output_packet.message->get_len());
			}
    	}
    }

    printf("CAN2Agent::send_message() exited \n");
    return rv;
}

// CAN Messaging start
void CAN2Agent::initCAN2Message(void){
	int i;

	for (i=0; i<CAN2_MAX_ID_SIZE; i++){
		memset(&can2_messages[i], 0x0, sizeof(struct CAN2_Messaging_t));
	}
}

uint8_t CAN2Agent::isIDRegistered (uint32_t id) {
	int i;
	uint8_t idx = 0xFF;

	for (i = 0; i < CAN2_MAX_ID_SIZE; i++) {
		if (id == can2_messages[i].id) {
			idx = i;
			break;
		}
	}
	return idx;
}

uint8_t CAN2Agent::registerID(uint32_t id, uint8_t *fr, uint8_t fr_num, uint8_t len) {
	uint8_t i;
	uint8_t idx = 0xFF;

	idx = isIDRegistered(id);
	if (idx == 0xFF) { //has not registered
		for (i = 0; i < CAN2_MAX_ID_SIZE; i++) {
			if (0x0 == can2_messages[i].id) {
				can2_messages[i].id = id;
				can2_messages[i].fr_num = fr_num;
				can2_messages[i].length = 0;
				can2_messages[i].index = fr_num;
				addFrame(fr, len, i);
				idx = i;
				break;
			}
		}
	}
	else {
		addFrame(fr, len, idx);
	}
	return idx;
}


bool CAN2Agent::resetIDMessage(uint32_t id) {
	bool rv = false;
	uint8_t idx = 0xFF;

	idx =isIDRegistered(id);
	if (idx != 0xFF) {
		memset(&can2_messages[idx], 0x0, sizeof(struct CAN2_Messaging_t));
		rv = true;
	}
	return rv;
}

bool CAN2Agent::resetIDXMessage(uint8_t idx) {
	bool rv = false;
	if (idx != 0xFF) {
		memset(&can2_messages[idx], 0x0, sizeof(struct CAN2_Messaging_t));
		rv = true;
	}
	return rv;
}

uint8_t CAN2Agent::addFrame(uint8_t *fr, uint8_t len, uint8_t idx) {

	can2_messages[idx].index--;
	memcpy(&can2_messages[idx].buf[can2_messages[idx].length], &fr[1] ,len-1);
	can2_messages[idx].length += len-1;

	return len-1;
}

size_t CAN2Agent::retrieveFullMesg(uint8_t *msg, uint8_t idx) {

	size_t rv = can2_messages[idx].length;
	memcpy(msg, &can2_messages[idx].buf[0], can2_messages[idx].length);
	memset(&can2_messages[idx], 0x0, sizeof(struct CAN2_Messaging_t));

	return rv;
}

size_t CAN2Agent::IsLastFrame(uint8_t idx, uint8_t *msg, uint8_t fr_num){
	size_t msg_len = 0;

	if (!fr_num){
		msg_len = can2_messages[idx].length;
		memcpy(msg, &can2_messages[idx].buf[0], can2_messages[idx].length);
		//memset(&can2_messages[idx], 0x0, sizeof(struct CAN2_Messaging_t));
	}

	return msg_len;
}


uint32_t CAN2Agent::processInFrame(uint32_t id, uint8_t *fr, uint8_t fr_num, uint32_t len) {

	uint8_t idx = 0xFF;
	uint32_t msg_len = 0;

	idx = registerID(id, fr, fr_num, len);  //fr bring data in

	msg_len = IsLastFrame(idx, fr, fr_num); //fr bring data out

	return msg_len;
}

// CAN Messaging end

bool CAN2Agent::handle_error(
        TransportRc /*transport_rc*/)
{
    return fini() && init();
}

} // namespace uxr
} // namespace eprosima







