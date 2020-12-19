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

#define  	CAN2_MAX_ID_SIZE 			2
#define     CAN1_FRAME_SIZE				12		// For simplicity, the CAN frame of std_ID(4 bytes) + DLC(4bytes) + data(4 bytes)
#define  	CAN_MAX_DATA_SIZE 			8
#define     XRCE_CAN2_MAX_FRAME			255
#define	    XRCE_CAN2_MTU			    CAN_MAX_DATA_SIZE * XRCE_CAN2_MAX_FRAME

typedef struct CAN2_Messaging_t
{
	  size_t length; 	///< Maximum number of items in the buffer
	  size_t fr_num;    ///< Number of frame in the buffer
	  size_t id; 		///< Data Buffer
	  size_t index;     ///< Buffer Index
	  uint8_t buf[XRCE_CAN2_MTU];     ///< Tail Index
} CAN2_Messaging_t;


extern template class Server<CAN2EndPoint>; // Explicit instantiation declaration.
class CAN2Agent : public Server<CAN2EndPoint>
{
public:
	CAN2Agent(
//		    uint16_t id,
//			const char * dev,
			const std::string dev,
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

    void initCAN2Message(void);
    uint8_t isIDRegistered (uint32_t id);
    uint8_t registerID(uint32_t id, uint8_t *fr, uint8_t fr_num, uint8_t len);
    bool resetIDMessage(uint32_t id);
    bool resetIDXMessage(uint8_t idx);
    uint8_t addFrame(uint8_t *fr, uint8_t len, uint8_t idx);
    size_t retrieveFullMesg(uint8_t *msg, uint8_t idx);
    size_t IsLastFrame(uint8_t idx, uint8_t *msg, uint8_t fr_num);
    uint32_t processInFrame(uint32_t id, uint8_t *fr, uint8_t fr_num, uint32_t len);

private:
    struct pollfd poll_fd_;
    //uint8_t buffer_[SERVER_BUFFER_SIZE];
    uint8_t buffer_[CAN2ENDPOINT_BUFFER_SIZE];
    uint32_t id_;
    uint32_t len_;
    //const char * dev_;
    const std::string dev_;
    SocketCan socket_can_;
    CAN2_Messaging_t can2_messages[CAN2_MAX_ID_SIZE];
};

} // namespace uxr
} // namespace eprosima




#endif /* INCLUDE_UXR_AGENT_TRANSPORT_CAN_CAN2AGENTLINUX_HPP_ */
