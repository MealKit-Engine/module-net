#include "mealkit/net/Rooms.h"

#include "mealkit/core/Log.h"
#include "mealkit/net/Lockstep.h"

#include <algorithm>
#include <cstring>

namespace mealkit::net {
namespace {

constexpr u32 kRoomMagic = 0x4D524B4Du; // "MKRM"
constexpr u8 kRoomVersion = 2;

void putText(std::vector<u8>& out, const std::string& s) {
    const std::string t = clampUtf8(s, 64);
    out.push_back(static_cast<u8>(t.size()));
    out.insert(out.end(), t.begin(), t.end());
}

template <class T>
void putValue(std::vector<u8>& out, const T& v) {
    const u8* p = reinterpret_cast<const u8*>(&v);
    out.insert(out.end(), p, p + sizeof(T));
}

struct RoomReader {
    const u8* data;
    u32 size, pos = 0;
    bool ok = true;
    template <class T>
    T get() {
        T v{};
        if (pos + sizeof(T) > size) {
            ok = false;
            return v;
        }
        std::memcpy(&v, data + pos, sizeof(T));
        pos += sizeof(T);
        return v;
    }
    std::string text() {
        const u8 n = get<u8>();
        if (!ok || pos + n > size) {
            ok = false;
            return {};
        }
        std::string s(reinterpret_cast<const char*>(data + pos), n);
        pos += n;
        return s;
    }
};

} // namespace

bool RoomAnnouncer::open(bool broadcast) {
    close();
    if (!startup()) return false;
    m_started = true;
    m_broadcast = broadcast;
    if (!m_socket.open(0, !broadcast) || (broadcast && !m_socket.enableBroadcast())) {
        MEALKIT_WARN("LAN rooms: cannot open the announce socket");
        close();
        return false;
    }
    m_next = 0.0;
    return true;
}

void RoomAnnouncer::close() {
    m_socket.close();
    if (m_started) cleanup();
    m_started = false;
}

void RoomAnnouncer::update(f64 now, const RoomAnnouncement& room) {
    if (!isOpen() || now < m_next) return;
    m_next = now + kRoomAnnounceInterval;
    std::vector<u8> packet;
    putValue(packet, kRoomMagic);
    putValue(packet, kRoomVersion);
    putValue(packet, room.simVersion);
    putValue(packet, room.contentHash);
    putValue(packet, room.port);
    putValue(packet, room.players);
    putValue(packet, room.maxPlayers);
    putText(packet, room.game);
    putText(packet, room.hostName);
    putText(packet, room.version);
    putText(packet, room.group);
    putText(packet, room.platform);
    putValue(packet, static_cast<u8>(room.crossplay ? 1 : 0));
    const u32 size = static_cast<u32>(packet.size());
    if (m_broadcast) m_socket.sendTo({kBroadcastIp, kRoomPort}, packet.data(), size);
    m_socket.sendTo({kLoopbackIp, kRoomPort}, packet.data(), size); // same PC (environments where broadcasts don't loop back)
}

bool RoomFinder::open(const std::string& game) {
    close();
    if (!startup()) return false;
    m_started = true;
    m_game = game;
    m_rooms.clear();
    if (!m_socket.openShared(kRoomPort)) {
        MEALKIT_WARN("LAN rooms: cannot listen on UDP port %u", kRoomPort);
        close();
        return false;
    }
    return true;
}

void RoomFinder::close() {
    m_socket.close();
    if (m_started) cleanup();
    m_started = false;
}

void RoomFinder::update(f64 now) {
    u8 buffer[512];
    Address from;
    i32 received;
    while (isOpen() && (received = m_socket.receiveFrom(from, buffer, sizeof(buffer))) >= 0) {
        RoomReader r{buffer, static_cast<u32>(received)};
        if (r.get<u32>() != kRoomMagic || r.get<u8>() != kRoomVersion) continue;
        Room room;
        room.simVersion = r.get<u64>();
        room.contentHash = r.get<u64>();
        room.port = r.get<u16>();
        room.players = r.get<u8>();
        room.maxPlayers = r.get<u8>();
        room.game = r.text();
        room.hostName = r.text();
        room.version = r.text();
        room.group = r.text();
        room.platform = r.text();
        room.crossplay = r.get<u8>() != 0;
        if (!r.ok || room.game != m_game) continue;
        room.address = {from.ip, room.port};
        room.lastSeen = now;
        // The same room arrives twice via broadcast and 127.0.0.1: for a room on the same PC, keep the LAN address
        auto same = [&](const Room& e) {
            return e.port == room.port && e.hostName == room.hostName && e.contentHash == room.contentHash &&
                   (e.address.ip == room.address.ip || e.address.ip == kLoopbackIp || room.address.ip == kLoopbackIp);
        };
        auto at = std::find_if(m_rooms.begin(), m_rooms.end(), same);
        if (at == m_rooms.end()) {
            m_rooms.push_back(room);
        } else {
            const bool keepAddress = room.address.ip == kLoopbackIp && at->address.ip != kLoopbackIp;
            const Address kept = at->address;
            *at = room;
            if (keepAddress) at->address = kept;
        }
    }
    m_rooms.erase(std::remove_if(m_rooms.begin(), m_rooms.end(), [&](const Room& e) { return now - e.lastSeen > kRoomTimeout; }),
                  m_rooms.end());
}

} // namespace mealkit::net
