#pragma once

#include "aster/core/Types.h"
#include "aster/net/Transport.h"

#include <memory>

// 결정론적 락스텝 세션.
//
// 모든 피어가 같은 시뮬레이션을 돌리고, 네트워크로는 틱별 플레이어 입력만 주고받는다.
// 대역폭은 오브젝트 수와 무관하다. 호스트는 플레이어이자 중계자다:
//   1. 각 피어는 틱 T를 실행할 때 자기 입력을 T + inputDelay 틱용으로 제출한다.
//   2. 호스트는 모든 플레이어의 입력이 모인 틱을 확정(finalize)하고 묶음(bundle)으로 배포한다.
//   3. 확정된 틱만 실행할 수 있다. 입력이 늦으면 시뮬레이션이 잠시 멈추고, 렌더링은 계속된다.
// 패킷 손실은 재전송 대신 중복 전송으로 처리한다(확인받지 못한 입력을 매 패킷에 다시 싣는다).
// 피어는 실행한 틱의 상태 해시를 보고하고, 호스트가 비교해 디싱크를 감지한다.
namespace aster::net {

inline constexpr u32 kMaxPlayers = 8;
inline constexpr u32 kInputBytes = 8;   // 게임이 정의하는 플레이어 입력 크기 (틱당)
inline constexpr u32 kTickWindow = 256; // 동시에 다룰 수 있는 틱 범위 (30Hz 기준 약 8.5초)

struct PlayerInput {
    u8 bytes[kInputBytes] = {};
};

struct TickInputs {
    PlayerInput players[kMaxPlayers];
};

enum class SessionState : u8 {
    Idle,       // 시작 전
    Connecting, // 클라이언트: 호스트에 접속 중
    Lobby,      // 매치 시작 대기
    Running,    // 시뮬레이션 진행 중
    Ended,      // 종료 (endReason 참고)
};

struct SessionStats {
    f32 rttMs = 0.0f;       // 클라이언트: 호스트 왕복 시간
    u32 sentBytesPerSec = 0;
    u32 recvBytesPerSec = 0;
};

class LockstepSession {
public:
    LockstepSession();
    ~LockstepSession();
    LockstepSession(const LockstepSession&) = delete;
    LockstepSession& operator=(const LockstepSession&) = delete;

    // 게임 데이터(씬 등)의 해시. host/join 전에 설정하면 다른 데이터를 가진 피어의 접속을 거부한다.
    void setContentHash(u64 hash);

    // 혼자 플레이: 네트워크 없이 같은 코드 경로를 쓴다.
    bool startOffline(u64 seed, u32 matchData);
    // loopbackOnly: 같은 PC 테스트용 (방화벽 확인 창이 뜨지 않는다)
    bool host(u16 port, u32 maxPlayers, u32 inputDelay, bool loopbackOnly = false);
    bool join(const Address& hostAddress);
    // 다른 전송 계층(Steam 등)으로 방 만들기/참가
    bool hostWith(std::unique_ptr<Transport> transport, u32 maxPlayers, u32 inputDelay);
    bool joinWith(std::unique_ptr<Transport> transport, const Address& hostAddress);
    // 호스트 전용: 로비 → 진행. seed와 matchData(게임이 정하는 매치 설정값)를 모두에게 보낸다.
    void startMatch(u64 seed, u32 matchData);
    // 매 프레임 호출: 패킷 수신, 확정, 송신.
    void update(f64 now);
    void shutdown();

    SessionState state() const;
    const char* endReason() const;
    bool isHost() const;
    u8 localPlayer() const;
    u32 playerCount() const;      // 매치 참가 인원 (Running 이후 확정)
    u32 lobbyPlayerCount() const; // 로비 인원
    u64 seed() const;
    u32 matchData() const;
    u32 inputDelay() const;

    bool canExecute(u32 tick) const;
    const TickInputs& inputs(u32 tick) const;
    // 틱 T를 실행한 직후 호출한다.
    void tickExecuted(u32 tick, u64 stateHash);
    // 로컬 입력을 (실행한 틱 + inputDelay) 틱용으로 제출한다.
    void submitLocalInput(u32 tick, const PlayerInput& input);

    bool desynced() const;
    u32 desyncTick() const;
    const SessionStats& stats() const;

private:
    struct Impl;
    Impl* m;
};

} // namespace aster::net
