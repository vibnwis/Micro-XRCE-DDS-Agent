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

#ifndef UXR_AGENT_TRANSPORT_TCP_TCPSERVERBASE_HPP_
#define UXR_AGENT_TRANSPORT_TCP_TCPSERVERBASE_HPP_

#include <uxr/agent/transport/tcp/TCPConnection.hpp>

#include <cstdint>
#include <cstddef>

namespace eprosima {
namespace uxr {

template<typename Connection>
class TCPServerBase
{
private:
    virtual size_t recv_data(
            Connection& connection,
            uint8_t* buffer,
            size_t len,
            uint8_t& errcode) = 0;

    virtual size_t send_data(
            Connection& connection,
            uint8_t* buffer,
            size_t len,
            uint8_t& errcode) = 0;

protected:
    uint16_t read_data(
            Connection& connection,
            bool& error);
};

template<typename Connection>
inline uint16_t TCPServerBase<Connection>::read_data(
        Connection& connection,
        bool& read_error)
{
    uint16_t rv = 0;
    read_error = false;
    bool exit_flag = false;

    while(!exit_flag)
    {
        switch (connection.input_buffer.state)
        {
            case TCP_BUFFER_EMPTY:
            {
                connection.input_buffer.position = 0;
                uint8_t size_buf[2];
                uint8_t errcode = 0;
                size_t bytes_received = recv_data(connection, size_buf, 2, errcode);
                if (0 < bytes_received)
                {
                    connection.input_buffer.msg_size = 0;
                    if (2 == bytes_received)
                    {
                        connection.input_buffer.msg_size = uint16_t((uint16_t(size_buf[1]) << 8) | size_buf[0]);
                        if (connection.input_buffer.msg_size != 0)
                        {
                            connection.input_buffer.state = TCP_SIZE_READ;
                        }
                    }
                    else
                    {
                        connection.input_buffer.msg_size = uint16_t(size_buf[0]);
                        connection.input_buffer.state = TCP_SIZE_INCOMPLETE;
                    }
                }
                else
                {
                    read_error = (0 < errcode);
                    exit_flag = true;
                }
                break;
            }
            case TCP_SIZE_INCOMPLETE:
            {
                uint8_t size_msb;
                uint8_t errcode = 0;
                size_t bytes_received = recv_data(connection, &size_msb, 1, errcode);
                if (0 < bytes_received)
                {
                    connection.input_buffer.msg_size = uint16_t((uint16_t(size_msb) << 8) | connection.input_buffer.msg_size);
                    if (connection.input_buffer.msg_size != 0)
                    {
                        connection.input_buffer.state = TCP_SIZE_READ;
                    }
                    else
                    {
                        connection.input_buffer.state = TCP_BUFFER_EMPTY;
                    }
                }
                else
                {
                    read_error = (0 < errcode);
                    exit_flag = true;
                }
                break;
            }
            case TCP_SIZE_READ:
            {
                connection.input_buffer.buffer.resize(connection.input_buffer.msg_size);
                uint8_t errcode = 0;
                size_t bytes_received =
                        recv_data(connection,
                                  connection.input_buffer.buffer.data(),
                                  connection.input_buffer.buffer.size(),
                                  errcode);
                if (0 < bytes_received)
                {
                    if (uint16_t(bytes_received) == connection.input_buffer.msg_size)
                    {
                        connection.input_buffer.state = TCP_MESSAGE_AVAILABLE;
                    }
                    else
                    {
                        connection.input_buffer.position = uint16_t(bytes_received);
                        connection.input_buffer.state = TCP_MESSAGE_INCOMPLETE;
                        exit_flag = true;
                    }
                }
                else
                {
                    read_error = (0 < errcode);
                    exit_flag = true;
                }
                break;
            }
            case TCP_MESSAGE_INCOMPLETE:
            {
                uint8_t errcode = 0;
                size_t bytes_received =
                        recv_data(connection,
                                  connection.input_buffer.buffer.data() + connection.input_buffer.position,
                                  connection.input_buffer.buffer.size() - connection.input_buffer.position,
                                  errcode);
                if (0 < bytes_received)
                {
                    connection.input_buffer.position += uint16_t(bytes_received);
                    if (connection.input_buffer.position == connection.input_buffer.msg_size)
                    {
                        connection.input_buffer.state = TCP_MESSAGE_AVAILABLE;
                    }
                    else
                    {
                        exit_flag = true;
                    }
                }
                else
                {
                    read_error = (0 < errcode);
                    exit_flag = true;
                }
                break;
            }
            case TCP_MESSAGE_AVAILABLE:
            {
                rv = connection.input_buffer.msg_size;
                connection.input_buffer.state = TCP_BUFFER_EMPTY;
                exit_flag = true;
                break;
            }
        }
    }

    return rv;
}

} // namespace uxr
} // namespace eprosima

#endif // UXR_AGENT_TRANSPORT_TCP_TCPSERVERBASE_HPP_
