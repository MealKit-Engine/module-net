#pragma once

#include "mealkit/core/Types.h"
#include "mealkit/net/Socket.h"

#include <string>
#include <vector>

// LAN 방 찾기 (ROADMAP 1단계 "LAN 방 찾기"): 같은 공유기에서 IP를 알려 주지 않고 참가한다.
//   호스트는 로비 동안 1초마다 방 알림(게임 이름, 빌드·콘텐츠 해시, 인원, 포트, 방장 이름)을 같은 네트워크 전체(브로드캐스트)와
//   127.0.0.1(같은 PC 시험)로 보낸다. 참가 메뉴는 kRoomPort를 여럿이 같이 듣고(같은 PC의 여러 게임), 같은 게임 이름의 방만 모은다.
//   매치 밖이라 결정론과 무관하다. 플랫폼 계층의 소켓만 쓴다.
namespace mealkit::net {

inline constexpr u16 kRoomPort = 27199; // 방 알림 포트 (게임 포트와 따로, 모든 게임이 같이 쓰고 게임 이름으로 거른다)
inline constexpr f64 kRoomAnnounceInterval = 1.0;
inline constexpr f64 kRoomTimeout = 3.5; // 이만큼 알림이 없으면 목록에서 뺀다

struct RoomAnnouncement {
    std::string game;     // 게임 이름 (프로젝트 이름)
    std::string hostName; // 방장 이름
    u64 simVersion = 0;   // 시뮬레이션 버전 (game::BuildInfo, 0이면 net::buildId)
    std::string version;  // 게임 버전 (보이기만)
    std::string group;    // 결정론 그룹 (net::determinismGroup)
    u64 contentHash = 0;
    u16 port = 0;         // 락스텝 세션 포트
    u8 players = 0, maxPlayers = 0;
};

struct Room : RoomAnnouncement {
    Address address; // 알림을 보낸 IP + 세션 포트 (join에 그대로)
    f64 lastSeen = 0.0;
};

class RoomAnnouncer {
public:
    // broadcast가 false면 127.0.0.1로만 보낸다 (127.0.0.1에만 연 방: 같은 PC 시험)
    bool open(bool broadcast = true);
    void close();
    bool isOpen() const { return m_socket.isOpen(); }
    // 매 프레임: kRoomAnnounceInterval마다 한 번 보낸다
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
    // 매 프레임: 받은 알림을 모으고 오래된 방을 뺀다
    void update(f64 now);
    const std::vector<Room>& rooms() const { return m_rooms; }

private:
    UdpSocket m_socket;
    std::string m_game;
    std::vector<Room> m_rooms;
    bool m_started = false;
};

} // namespace mealkit::net
