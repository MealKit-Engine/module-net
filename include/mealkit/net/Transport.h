#pragma once

#include "mealkit/net/Socket.h"

#include <memory>

namespace mealkit::net {

// 패킷 전송 계층. 락스텝 세션은 이 인터페이스만 쓴다.
//   UdpTransport   : IP/포트 직접 (LAN, 개발, 같은 PC 테스트)
//   Steam 전송     : Steam ID + Steam 릴레이 (mealkit/platform/Steam.h, SDK가 있을 때)
class Transport {
public:
    virtual ~Transport() = default;
    virtual bool send(const Address& to, const void* data, u32 size) = 0;
    virtual i32 receive(Address& from, void* buffer, u32 capacity) = 0; // 받을 것이 없으면 -1
};

class UdpTransport final : public Transport {
public:
    bool open(u16 port, bool loopbackOnly) { return m_socket.open(port, loopbackOnly); }
    u16 localPort() const { return m_socket.localPort(); }
    bool send(const Address& to, const void* data, u32 size) override { return m_socket.sendTo(to, data, size); }
    i32 receive(Address& from, void* buffer, u32 capacity) override { return m_socket.receiveFrom(from, buffer, capacity); }

private:
    UdpSocket m_socket;
};

} // namespace mealkit::net
