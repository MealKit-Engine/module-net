#pragma once

#include "mealkit/platform/Socket.h"

#include <memory>

namespace mealkit::net {

// Packet transport layer. The lockstep session uses only this interface.
//   UdpTransport   : IP/port directly (LAN, development, same-PC tests)
//   platform relay : online::Service::createTransport() (Steam ID + Steam relay etc., mealkit/online/Online.h)
class Transport {
public:
    virtual ~Transport() = default;
    virtual bool send(const Address& to, const void* data, u32 size) = 0;
    virtual i32 receive(Address& from, void* buffer, u32 capacity) = 0; // -1 if there's nothing to receive
};

class UdpTransport final : public Transport {
public:
    bool open(u16 port, bool loopbackOnly) { return m_socket.open(port, loopbackOnly); }
    u16 localPort() const { return m_socket.localPort(); }
    bool send(const Address& to, const void* data, u32 size) override { return m_socket.sendTo(to, data, size); }
    i32 receive(Address& from, void* buffer, u32 capacity) override {
        return m_socket.receiveFrom(from, buffer, capacity);
    }

private:
    UdpSocket m_socket;
};

} // namespace mealkit::net
