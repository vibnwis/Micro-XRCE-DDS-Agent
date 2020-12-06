#include "../../../../include/uxr/agent/transport/can/socketcan_cpp.hpp"
//#include "../include/socketcan_cpp/socketcan_cpp.hpp"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_SOCKETCAN_HEADERS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <linux/can/raw.h>
/* CAN DLC to real data length conversion helpers */
static const unsigned char dlc2len[] = {0, 1, 2, 3, 4, 5, 6, 7,
					8, 12, 16, 20, 24, 32, 48, 64};

/* get data length from can_dlc with sanitized can_dlc */
unsigned char can_dlc2len(unsigned char can_dlc)
{
	return dlc2len[can_dlc & 0x0F];
}

static const unsigned char len2dlc[] = {0, 1, 2, 3, 4, 5, 6, 7, 8,		/* 0 - 8 */
					9, 9, 9, 9,				/* 9 - 12 */
					10, 10, 10, 10,				/* 13 - 16 */
					11, 11, 11, 11,				/* 17 - 20 */
					12, 12, 12, 12,				/* 21 - 24 */
					13, 13, 13, 13, 13, 13, 13, 13,		/* 25 - 32 */
					14, 14, 14, 14, 14, 14, 14, 14,		/* 33 - 40 */
					14, 14, 14, 14, 14, 14, 14, 14,		/* 41 - 48 */
					15, 15, 15, 15, 15, 15, 15, 15,		/* 49 - 56 */
					15, 15, 15, 15, 15, 15, 15, 15};	/* 57 - 64 */

/* map the sanitized data length to an appropriate data length code */
unsigned char can_len2dlc(unsigned char len)
{
	if (len > 64)
		return 0xF;

	return len2dlc[len];
}

#endif

namespace eprosima {
namespace uxr {

SocketCan::SocketCan()
{}

SocketCanStatus SocketCan::open(const std::string & can_interface, int32_t read_timeout_ms, SocketMode mode)
{
        m_interface = can_interface;
        m_socket_mode = mode;
        m_read_timeout_ms = read_timeout_ms;

        char buf[100];


        /* open socket */
        if ((s = socket(PF_CAN, SOCK_RAW, CAN_RAW)) < 0)
        {
            perror("socketcan ");
            return STATUS_SOCKET_CREATE_ERROR;
        }


        //int enable_canfd = 1; //Lim for time being not supporting CAN_FD

        struct ifreq ifr;

        strncpy(ifr.ifr_name, can_interface.c_str(), IFNAMSIZ - 1);
        ifr.ifr_name[IFNAMSIZ - 1] = '\0';


/*
 * retrieve index of the interface name
 */
        ifr.ifr_ifindex = if_nametoindex(ifr.ifr_name);
        /*
         * index of the interface name
         */
        if (!ifr.ifr_ifindex) {
            perror("if_nametoindex");
            printf("Interface name %s",ifr.ifr_name);
            return STATUS_INTERFACE_NAME_TO_IDX_ERROR;
        }

        /*
         * retrieve the interface index for the interface name (can0, can1, vcan0 etc) we wish to use.
         */

        if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) {
            perror("SIOCGIFINDEX");
            return STATUS_CAN_OP_ERROR;
        }

        /*
        	const int timestamping_flags = (SOF_TIMESTAMPING_SOFTWARE | \
            	SOF_TIMESTAMPING_RX_SOFTWARE | \
            	SOF_TIMESTAMPING_RAW_HARDWARE);

        	if (setsockopt(m_socket, SOL_SOCKET, SO_TIMESTAMPING,
            	&timestamping_flags, sizeof(timestamping_flags)) < 0) {
            	perror("setsockopt SO_TIMESTAMPING is not supported by your Linux kernel");
        }
        */

        /*
         * The owner - disable default receive filter on this RAW socket
         * This is obsolete as we do not read from the socket at all, but for
         * this reason we can remove the receive list in the Kernel to save a
         * little (really a very little!) CPU usage.
         *
         * */

        /*
         #define CAN_SFF_MASK 0x000007FFU / * Standard frame format (SFF) * /
 	 	 #define CAN_EFF_MASK 0x1FFFFFFFU / * Extended frame format (EFF) * /
 	 	 #define CAN_ERR_MASK 0x1FFFFFFFU / * Ignore EFF, RTR, ERR flags * /
         */

        /* 12 Nov 20 Lim - Re-open the default receive filter on this RAW socket */
        //setsockopt(m_socket, SOL_CAN_RAW, CAN_RAW_FILTER, NULL, 0);  // Disable frame reception
        /*
         * A filter matches, when  <received_can_id> & mask == can_id & mask
         */


#if 0
        struct can_filter rfilter[2];
        rfilter[0].can_id   = 0x128;
        rfilter[0].can_mask = CAN_SFF_MASK;
        rfilter[1].can_id   = 0x120; 	//x120-x123
        rfilter[1].can_mask = 0x1FC;  	//001-1111-1100 eg, 0x120-0x123
#else
        /* accept all frames */
        struct can_filter rfilter[1];
        rfilter[0].can_id   = CAN_SFF_MASK;
        rfilter[0].can_mask = 0x0;   	// can_mask = 0, all frames pass through
#endif
        setsockopt(s, SOL_CAN_RAW, CAN_RAW_FILTER, &rfilter, sizeof(rfilter));


// LINUX
        struct sockaddr_can addr;

        memset(&addr, 0, sizeof(addr));
        addr.can_family = AF_CAN;
        addr.can_ifindex = ifr.ifr_ifindex;


        if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("Socket CAN2 bind");
            return STATUS_BIND_ERROR;
        }

        sprintf(buf,"%s \n", ifr.ifr_name);
        printf("SocketCAN for interface %s succeeded\n",buf);

        return STATUS_OK;
}


/* linux/can.h
 * Classic CAN frame of Socket CAN
 * struct can_frame {
 * 	u32 can_id;
 * 	u8  can_dlc;
 * 	u8  data[8];
 * 	}
 *
 */

SocketCanStatus SocketCan::write(const CanFrame & msg)
{

		char buf[100];
        struct can_frame frame;
        memset(&frame, 0, sizeof(frame)); /* init CAN FD frame, e.g. LEN = 0 */
        //convert CanFrame to canfd_frame
        frame.can_id = msg.id;
        frame.can_dlc = msg.len;
        //frame.flags = msg.flags;


        /*
         * Use sprintf to fill-up frame.data
         */

        // sprintf(frame.data, "Hello");

        /*
         * User memcpy to fill-up frame i.e. msg.data
         */
        memcpy(frame.data, msg.data, msg.len);

        m_socket_mode = MODE_CAN_MTU;

        /* send frame */
        if (::write(s, &frame, int(sizeof(struct can_frame))) != int(sizeof(struct can_frame))) {
            perror("CAN2 write error");
            return STATUS_WRITE_ERROR;
        }

        sprintf(buf,"%s \n", msg.data);
        printf("SocketCAN: Write() %s \n",buf);

        return STATUS_OK;
}


SocketCanStatus SocketCan::read(CanFrame & msg)
{

        struct can_frame frame;
        char buf[100];

        // Read in a CAN frame
        auto num_bytes = ::read(s, &frame, int(sizeof(struct can_frame)));
        if (num_bytes < 0 ) 	//  old implementation (num_bytes != CAN_MTU && num_bytes != CANFD_MTU)
        {
            perror("CAN2 read error");
            return STATUS_READ_ERROR;
        }

        msg.id = frame.can_id;
        msg.len = frame.can_dlc;
        //msg.flags = frame.flags;
        memcpy(msg.data, frame.data, frame.can_dlc);

        sprintf(buf,"%s \n", msg.data);
        printf("SocketCAN: Read() %s \n",buf);

        return STATUS_OK;
}

SocketCanStatus SocketCan::close()
{
		printf("SocketCAN:close()\n");
        ::close(s);
        return STATUS_OK;
}

const std::string & SocketCan::interfaceName() const
{
        return m_interface;
}

SocketCan::~SocketCan()
{
		printf("Socketcan_cpp class de-init\n");
        close();
}

}
}
