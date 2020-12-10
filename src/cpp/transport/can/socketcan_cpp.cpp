#include "../../../../include/uxr/agent/transport/can/socketcan_cpp.hpp"
//#include "../include/socketcan_cpp/socketcan_cpp.hpp"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <boost/thread/thread.hpp>
#include <chrono>
#include <thread>

#ifdef HAVE_SOCKETCAN_HEADERS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <linux/can.h>
#include <linux/can/raw.h>
#include <linux/can/error.h>
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
{
}

SocketCanStatus SocketCan::open(const std::string & can_interface, int32_t read_timeout_ms, SocketMode mode)
{
        m_interface = can_interface;
        m_socket_mode = mode;
        m_read_timeout_ms = read_timeout_ms;

        char buf[100];

        int size_c_frame = sizeof (cframe);
        printf("can_frame is %d bytes", size_c_frame);
        memset(&cframe, 0x0,size_c_frame);

        /* open socket */
        if ((s = socket(PF_CAN, SOCK_RAW, CAN_RAW)) < 0)
        {
            perror("socketcan ");
            return STATUS_SOCKET_CREATE_ERROR;
        }


        int mtu, enable_canfd = 1; //Lim for time being not supporting CAN_FD

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

        /* Check if it is required to set as FD CAN */
        if (mode == MODE_CANFD_MTU)
        {
        	/*
        	 * retrieve the interface index for the interface name (can0, can1, vcan0 etc) we wish to use.
        	 */

        	if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) {
        		perror("SIOCGIFINDEX");
        		return STATUS_CAN_OP_ERROR;
        	}

        	 mtu = ifr.ifr_mtu;

        	if (mtu != CANFD_MTU) {

        		printf("CAN Classic  mode");
        		return STATUS_CANFD_NOT_SUPPORTED;
        	}

        	printf("CD CAN mode");
        	/* By default it is CAN classic.
        	 *interface is ok - try to switch the socket into CAN FD mode
        	 */

        	if (setsockopt(s, SOL_CAN_RAW, CAN_RAW_FD_FRAMES,
        	           &enable_canfd, sizeof(enable_canfd)))
        	{

        	        return STATUS_ENABLE_FD_SUPPORT_ERROR;
        	}


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
        /* filter incoming frames */
        struct can_filter rfilter[1];
        rfilter[0].can_id   = CAN_SFF_MASK;
        rfilter[0].can_mask = 0x123;   	// can_mask = 0, all frames pass through
#endif
        setsockopt(s, SOL_CAN_RAW, CAN_RAW_FILTER, &rfilter, sizeof(rfilter));

#if 0
        struct timeval timeout;

        timeout.tv_sec = 0;
        timeout.tv_usec = 1000; //m_read_timeout_ms *1000;

       // timeout.tv_usec = m_read_timeout_ms * 10;  // Not init'ing this can cause strange errors
       // if(setsockopt(s, SOL_SOCKET, SO_RCVTIMEO|SO_SNDTIMEO, (const char*)&timeout,sizeof(struct timeval)) < 0) {
        if(setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout,sizeof(timeout)) < 0) {
        	perror("Setting timeout failed");
        	return STATUS_SOCKET_CREATE_ERROR;
        }
        printf("\nSocketCAN init Timeout %d succeeded\n",timeout.tv_usec);
#endif

// LINUX
        struct sockaddr_can addr;

        memset(&addr, 0, sizeof(addr));
        addr.can_family = AF_CAN;
        addr.can_ifindex = ifr.ifr_ifindex;


        if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("Socket CAN2 bind");
            return STATUS_BIND_ERROR;
        }

        printf("SocketCAN  bind() succeeded\n");

        int error = 0;
        socklen_t len = sizeof (error);
        int retval = getsockopt (s, SOL_SOCKET, SO_ERROR, &error, &len);
        if (retval != 0) {
            /* there was a problem getting the error code */
            printf("Error getting socket error code: %s\n", strerror(retval));
            perror("Setting timeout failed");
            return STATUS_SOCKET_CREATE_ERROR;
        }
        printf("SocketCAN  getsockopt() succeeded\n");

        if (error != 0) {
           /* socket has a non zero error status */
        	printf("Socket error: %s\n", strerror(error));
            return STATUS_SOCKET_CREATE_ERROR;
        }
        printf("SocketCAN  error none\n");
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
		int i=0;
       // struct can_frame frame;
        memset(&cframe, 0, sizeof(struct can_frame)); /* init CAN FD frame, e.g. LEN = 0 */
        //convert CanFrame to canfd_frame
        cframe.can_id = msg.id;
        cframe.can_dlc = msg.len;
        //frame.flags = msg.flags;


        /*
         * Use sprintf to fill-up frame.data
         */

        // sprintf(frame.data, "Hello");

        /*
         * User memcpy to fill-up frame i.e. msg.data
         */
        memcpy(cframe.data, msg.data, msg.len);


        sprintf(buf,"%s \n", msg.data);
        printf("SocketCAN: write() frame.can_dlc= %d, frame.can_id = %d\n", cframe.can_dlc,cframe.can_id);
        for (i=0; i< cframe.can_dlc; i++)
        {
        	printf("data[%d]", buf[i]);
        }

        printf("\nSocketCAN: Write() ended\n");


        m_socket_mode = MODE_CAN_MTU;

        /* send frame */
        if (::write(s, &cframe, int(sizeof(struct can_frame))) != int(sizeof(struct can_frame))) {
            perror("CAN2 write error");
            return STATUS_WRITE_ERROR;
        }

        sprintf(buf,"%s \n", msg.data);
        printf("SocketCAN: Write() %s \n",buf);

        return STATUS_OK;
}


SocketCanStatus SocketCan::read(CanFrame & msg)
{

	   // struct canfd_frame frame;
    //    struct can_frame frame;  //include/linux/can.h
    //    struct can_frame * p_frame = NULL;
	    memset(&cframe, 0, sizeof(struct can_frame)); /* init CAN FD frame, e.g. LEN = 0 */
        char buf[100];
        int i= 0;
        unsigned int microseconds;

        if (s < 0) {
        	printf("SocketCAN:: handler error %d \n", s);
        	return STATUS_SOCKET_CREATE_ERROR;
        }

        printf("SocketCAN:: handler %d \n", s);
        int error = 0;
        socklen_t len = sizeof (error);
        int retval = getsockopt (s, SOL_SOCKET, SO_ERROR, &error, &len);
        if (retval != 0)
        {
        	/* there was a problem getting the error code */
            printf("Error getting socket error code: %s\n", strerror(retval));
            return STATUS_SOCKET_CREATE_ERROR;
        }
        printf("SocketCAN::read  getsockopt() succeeded len = %d\n", len);


        // Read in a CAN frame

     //   memset(&frame, 0, sizeof(struct can_frame));

     //   p_frame = (struct can_frame *)malloc(sizeof(struct can_frame));

        if(!sizeof(cframe))
        {
        	printf("SocketCAN:: read() frame size error\n");
        	return STATUS_READ_ERROR;
        }

        printf("SocketCAN:: Read() - A Frame memory space is ready and about to read from CAN interface can0\n");
       // struct canfd_frame cfd;
        //auto num_bytes = 0;
        int num_bytes = 0;
        	can_err_mask_t err_mask = ( CAN_ERR_TX_TIMEOUT | CAN_ERR_BUSOFF );
        	setsockopt(s, SOL_CAN_RAW, CAN_RAW_ERR_FILTER, &err_mask, sizeof(err_mask));


        	num_bytes = ::read(s, &cframe, int(sizeof(struct can_frame)));
        	//num_bytes = ::read(s, &frame, int(sizeof(struct can_frame)));

        	if (num_bytes == 0) {
                printf("Read() returns values = %d and data length of %d\n", num_bytes, cframe.can_dlc);
                /* cfd.flags is undefined */
        	}
        	else if (num_bytes < 8)
        	{
        		printf("ead() returns values = %d and data length of %d\n", num_bytes, cframe.can_dlc);
        	}
        	else if (num_bytes > 16)
        	{
        		printf("Read() returns values = %d and data length of %d\n", num_bytes, cframe.can_dlc);
                fprintf(stderr, "read: invalid CAN frame\n");
                return STATUS_READ_ERROR;
        	}
            else
            {
            	printf("Read() returns values = %d and data length of %d\n", num_bytes, cframe.can_dlc);
        //    	break;
            }

        	//waits 2 seconds
        //	std::this_thread::sleep_for(std::chrono::seconds(1));
        //	std::this_thread::sleep_for(std::chrono::milliseconds(1000));



    //    printf("SocketCAN:: Read() - read from CAN interface can0 completed with num_bytes %d\n", num_bytes);
        if (num_bytes < 0 ) 	//  old implementation (num_bytes != CAN_MTU && num_bytes != CANFD_MTU)
        {
            perror("CAN2 read error");
            return STATUS_READ_ERROR;
        }

        /* paranoid check ...
        if (num_bytes < sizeof(struct can_frame)) {
            fprintf(stderr, "read: incomplete CAN frame\n");
            return STATUS_READ_ERROR;
        }
        */


        if (cframe.can_id & CAN_EFF_FLAG) {
        	printf("SocketCAN: Read() Extended frame.flags = %d \n", cframe.can_id);
        }
        else {
        	printf("SocketCAN: Read() Classis frame.flags = %d \n", cframe.can_id);
        }

        if (cframe.can_id & CAN_ERR_FLAG) {
               	printf("SocketCAN: Read() Error frame.flags = %d \n", cframe.can_id);
        }
        else {
               	printf("SocketCAN: Read() Non-Error frame.flags = %d \n", cframe.can_id);
        }

        msg.id = cframe.can_id;
        msg.len = cframe.can_dlc;
        //msg.flags = frame.flags;
        memcpy(msg.data, cframe.data, cframe.can_dlc);

        //sprintf(buf,"%s \n", msg.data);
        printf("SocketCAN: Read() frame.can_dlc= %d, frame.can_id = %d\n", cframe.can_dlc,cframe.can_id);
        for (i=0; i< cframe.can_dlc; i++)
        {
        	printf("data[%d]", msg.data[i]);
        }

        printf("\nSocketCAN: Read() ended\n");

       // free(p_frame);

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
