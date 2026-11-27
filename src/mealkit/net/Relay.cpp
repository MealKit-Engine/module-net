#include "mealkit/net/Relay.h"

#include "mealkit/core/Log.h"
#include "mealkit/platform/WebSocket.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <vector>

namespace mealkit::net {
namespace {

constexpr u32 kPeerIdBytes = sizeof(u64); // little endian, like every CPU the engine builds for
constexpr size_t kMaxWaiting = 1024;      // packets nobody reads yet (before the session opens)

} // namespace

// The socket to one room. The room and the transport share it
struct RelayLink {
    struct Packet {
        u64 from;
        std::vector<u8> data;
    };

    WebSocket socket;
    std::string request; // sent once the socket is open
    RelayRoom::State state = RelayRoom::State::Connecting;
    u64 code = 0, selfId = 0, ownerId = 0;
    std::deque<Packet> packets;
    std::vector<u8> message;

    void readLine(const std::string& line) {
        unsigned long long a = 0, b = 0, c = 0;
        if (std::sscanf(line.c_str(), "room %llu %llu %llu", &a, &b, &c) == 3) {
            code = a;
            selfId = b;
            ownerId = c;
            state = RelayRoom::State::InRoom;
            MEALKIT_INFO("Relay: in room %llu", a);
        } else if (std::sscanf(line.c_str(), "owner %llu", &a) == 1) {
            ownerId = a;
        } else if (line.rfind("error ", 0) == 0) {
            MEALKIT_WARN("Relay: %s", line.c_str() + 6);
            state = RelayRoom::State::Failed;
        }
    }

    void pump() {
        if (!request.empty() && socket.state() == WebSocket::State::Open && socket.sendText(request)) request.clear();
        bool isText = false;
        while (socket.receive(message, isText)) {
            if (isText) {
                readLine(std::string(message.begin(), message.end()));
            } else if (message.size() >= kPeerIdBytes && packets.size() < kMaxWaiting) {
                Packet p;
                std::memcpy(&p.from, message.data(), kPeerIdBytes);
                p.data.assign(message.begin() + kPeerIdBytes, message.end());
                packets.push_back(std::move(p));
            }
        }
        if (state != RelayRoom::State::Failed && socket.state() == WebSocket::State::Closed) {
            MEALKIT_WARN("Relay: the connection to the relay server closed");
            state = RelayRoom::State::Failed;
        }
    }
};

namespace {

class RelayTransport final : public Transport {
public:
    explicit RelayTransport(std::shared_ptr<RelayLink> link) : m_link(std::move(link)) {}

    bool send(const Address& to, const void* data, u32 size) override {
        if (!to.userId) return false;
        m_packet.resize(kPeerIdBytes + size);
        std::memcpy(m_packet.data(), &to.userId, kPeerIdBytes);
        std::memcpy(m_packet.data() + kPeerIdBytes, data, size);
        return m_link->socket.sendBinary(m_packet.data(), static_cast<u32>(m_packet.size()));
    }

    i32 receive(Address& from, void* buffer, u32 capacity) override {
        if (m_link->packets.empty()) m_link->pump();
        while (!m_link->packets.empty()) {
            const RelayLink::Packet p = std::move(m_link->packets.front());
            m_link->packets.pop_front();
            if (p.data.size() > capacity) continue;
            from = {};
            from.userId = p.from;
            if (!p.data.empty()) std::memcpy(buffer, p.data.data(), p.data.size());
            return static_cast<i32>(p.data.size());
        }
        return -1;
    }

private:
    std::shared_ptr<RelayLink> m_link;
    std::vector<u8> m_packet;
};

} // namespace

bool parseRoomCode(const std::string& text, u64& code) {
    if (text.empty() || text.size() > 12 || text.find_first_not_of("0123456789") != std::string::npos) return false;
    code = std::strtoull(text.c_str(), nullptr, 10);
    return code != 0;
}

void RelayRoom::open(const std::string& url, const std::string& request) {
    m_link = std::make_shared<RelayLink>();
    m_link->request = request;
    m_failed = false;
    if (!m_link->socket.open(url)) {
        m_link.reset();
        m_failed = true;
    }
}

void RelayRoom::create(const std::string& url, const std::string& game) { open(url, "host " + game); }

void RelayRoom::join(const std::string& url, u64 code, const std::string& game) {
    open(url, "join " + std::to_string(code) + " " + game);
}

void RelayRoom::leave() {
    m_link.reset();
    m_failed = false;
}

void RelayRoom::update() {
    if (m_link) m_link->pump();
}

RelayRoom::State RelayRoom::state() const {
    if (m_link) return m_link->state;
    return m_failed ? State::Failed : State::None;
}

u64 RelayRoom::code() const { return state() == State::InRoom ? m_link->code : 0; }
bool RelayRoom::isOwner() const { return state() == State::InRoom && m_link->ownerId == m_link->selfId; }

Address RelayRoom::ownerAddress() const {
    Address address;
    if (m_link) address.userId = m_link->ownerId;
    return address;
}

void RelayRoom::setOwner(u64 userId) {
    if (!isOwner() || userId == 0 || userId == m_link->selfId) return;
    if (m_link->socket.sendText("owner " + std::to_string(userId))) m_link->ownerId = userId;
}

std::unique_ptr<Transport> RelayRoom::createTransport() {
    if (!m_link) return nullptr;
    return std::make_unique<RelayTransport>(m_link);
}

} // namespace mealkit::net
