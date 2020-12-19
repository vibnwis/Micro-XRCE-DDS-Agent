#ifndef INCLUDE_UXR_AGENT_TRANSPORT_SOCKETCAN_CPP_HPP_
#define INCLUDE_UXR_AGENT_TRANSPORT_SOCKETCAN_CPP_HPP_

#pragma once

#include <string>
//#include <socketcan_cpp/socketcan_cpp_export.h>

#define HAVE_SOCKETCAN_HEADERS

#ifndef HAVE_SOCKETCAN_HEADERS
#define CAN_MTU                   0
#define CANFD_MTU                 1
#else
#include <linux/can.h>
#endif


/*
 * For reference only
 * Struct can_frame:
 *
 *	canid_t 	can_id
 *		32 bit CAN_ID + EFF/RTR/ERR flags
 *
 *	uint8_t 	can_dlc
 *		frame payload length in byte (0 . More...
 *
 *	uint8_t 	__pad
 *		padding
 *
 *	uint8_t 	__res0
 *		reserved / padding
 *
 *	uint8_t 	__res1
 *		reserved / padding
 *
 *	uint8_t 	data [CAN_MAX_DLEN]
 *		Frame data.
 *		CAN_MAX_DLEN = 8
 *
 */

namespace eprosima {
namespace uxr {

/* linux/can.h
 * #define CAN_MTU   (sizeof(struct can_frame))   == 16  => 'legacy' CAN frame
 * #define CANFD_MTU (sizeof(struct canfd_frame)) == 72  => CAN FD frame
 */

enum SocketMode
{
        MODE_CAN_MTU = CAN_MTU,
        MODE_CANFD_MTU = CANFD_MTU
};

struct CanFrame
{
        uint32_t id = 0;
        uint32_t len = 0;
        uint8_t flags = 0;
        uint8_t data[2048];

};

enum SocketCanStatus
{
        STATUS_OK = 1 << 0,
        STATUS_SOCKET_CREATE_ERROR = 1 << 2,
        STATUS_INTERFACE_NAME_TO_IDX_ERROR = 1 << 3,
        STATUS_MTU_ERROR = 1 << 4, /// maximum transfer unit
        STATUS_CANFD_NOT_SUPPORTED = 1 << 5, /// Flexible data-rate is not supported on this interface
        STATUS_ENABLE_FD_SUPPORT_ERROR = 1 << 6, /// Error on enabling fexible-data-rate support
        STATUS_WRITE_ERROR = 1 << 7,
        STATUS_READ_ERROR = 1 << 8,
        STATUS_BIND_ERROR = 1 << 9,
		STATUS_CAN_OP_ERROR = -1
};

class SocketCan
    {
    public:
         SocketCan();
         SocketCan(const SocketCan &) = delete;
         SocketCan & operator=(const SocketCan &) = delete;
         SocketCanStatus open(const std::string & can_interface, int32_t read_timeout_ms = 3, SocketMode mode = MODE_CAN_MTU);
         SocketCanStatus write(const CanFrame & msg);
         SocketCanStatus read(CanFrame & msg);
         SocketCanStatus close();
         const std::string & interfaceName() const;
         ~SocketCan();

    private:
        int s = -1;
        int32_t m_read_timeout_ms = 3;
        std::string m_interface;
        SocketMode m_socket_mode;
        struct can_frame cframe;
    };

} // namespace uxr
} // namespace eprosima

#endif  // INCLUDE_UXR_AGENT_TRANSPORT_SOCKETCAN_CPP_HPP_
