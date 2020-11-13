/*
 * CAN2EndPoint.hpp
 *
 *  Created on: Nov 13, 2020
 *      Author: wiki-ros
 */

#ifndef INCLUDE_UXR_AGENT_TRANSPORT_ENDPOINT_CAN2ENDPOINT_HPP_
#define INCLUDE_UXR_AGENT_TRANSPORT_ENDPOINT_CAN2ENDPOINT_HPP_



#include <uxr/agent/transport/endpoint/EndPoint.hpp>

#include <stdint.h>
#include <iostream>

namespace eprosima {
namespace uxr {

class CAN2EndPoint: public EndPoint
{
public:
	CAN2EndPoint() = default;

	CAN2EndPoint(
            uint16_t id,
            uint8_t len
			)
        : id_(id)
        , len_(len)
		, buf_{0}
    {}

    ~CAN2EndPoint() = default;
    


    bool operator<(const CAN2EndPoint& other) const
    {
        return (id_ < other.id_) ;
    }
    
    std::ostream& print(std::ostream& os) const final
    {
        return os << int(id_);
    }
    
 
    uint16_t get_id() const { return id_; }
    
    void set_id(uint16_t can_id) {
    	id_ = 0x0FFF & can_id;
    }
    
    void set_len(uint8_t len){
        	len_ = len;
    }
    
    uint8_t get_len() const{
           return len_;
    }
    
    uint8_t get_data(uint8_t *in_data) { 
    	memcpy(in_data, buf_, len_);		// len = port & 0x0007
    	return len_; 
    }
    
    uint8_t set_data(uint8_t *in_data, uint8_t len) {	
    	len_ = len;
    	memcpy(buf_, in_data, len_);		// len = port & 0x0007
    	return len_;
    }
    

private:
    uint16_t id_;
    uint8_t len_;
    uint8_t buf_[8];
    
};


} // namespace uxr
} // namespace eprosima



#endif /* INCLUDE_UXR_AGENT_TRANSPORT_ENDPOINT_CAN2ENDPOINT_HPP_ */
