#pragma once

#include "mealkit/core/Types.h"
#include "mealkit/net/Socket.h"

#include <string>
#include <vector>

// LAN room search (ROADMAP stage 1 "LAN room search"): join on the same router without sharing an IP.
//   During the lobby, the host sends room announcements (game name, build/content hash, player count, port, host name) every second to the whole network (broadcast)
//   and to 127.0.0.1 (same-PC tests). The join menu listens on kRoomPort shared with others (multiple games on the same PC) and collects only rooms of the same game name.
//   Outside matches, so unrelated to determinism. Uses only platform layer sockets.
namespace mealkit::net {

inline constexpr u16 kRoomPort = 27199; // room announcement port (separate from game ports, shared by all games and filtered by game name)
inline constexpr f64 kRoomAnnounceInterval = 1.0;
inline constexpr f64 kRoomTimeout = 3.5; // removed from the list after this long without announcements

struct RoomAnnouncement {
    std::string game;     // game name (project name)
    std::string hostName; // host name
    u64 simVersion = 0;   // simulation version (game::BuildInfo, net::buildId if 0)
    std::string version;  // game version (display only)
    std::string group;    // determinism group (net::determinismGroup)
    u64 contentHash = 0;
    u16 port = 0;         // lockstep session port
    u8 players = 0, maxPlayers = 0;
};

struct Room : RoomAnnouncement {
    Address address; // IP that sent the announcement + session port (passed to join as is)
    f64 lastSeen = 0.0;
};

class RoomAnnouncer {
public:
    // If broadcast is false, sends only to 127.0.0.1 (rooms opened only on 127.0.0.1: same-PC tests)
    bool open(bool broadcast = true);
    void close();
    bool isOpen() const { return m_socket.isOpen(); }
    // Every frame: sends once every kRoomAnnounceInterval
    void update(f64 now, const RoomAnnouncement& room);

private:
    UdpSocket m_socket;
    f64 m_next = 0.0;
    bool m_started = false;
    bool m_broadcast = true;
};

class RoomFinder {
public:
    bool open(const std::string& game);
    void close();
    bool isOpen() const { return m_socket.isOpen(); }
    // Every frame: collects received announcements and removes stale rooms
    void update(f64 now);
    const std::vector<Room>& rooms() const { return m_rooms; }

private:
    UdpSocket m_socket;
    std::string m_game;
    std::vector<Room> m_rooms;
    bool m_started = false;
};

} // namespace mealkit::net
