#pragma once

#include "mealkit/core/Types.h"
#include "mealkit/net/Transport.h"

#include <memory>
#include <string>
#include <vector>

// 결정론적 락스텝 세션.
//
// 모든 피어가 같은 시뮬레이션을 돌리고, 네트워크로는 틱별 플레이어 입력만 주고받는다.
// 대역폭은 오브젝트 수와 무관하다. 호스트는 플레이어이자 중계자다:
//   1. 각 피어는 틱 T를 실행할 때 자기 입력을 T + inputDelay 틱용으로 제출한다.
//   2. 호스트는 모든 플레이어의 입력이 모인 틱을 확정(finalize)하고 묶음(bundle)으로 배포한다.
//   3. 확정된 틱만 실행할 수 있다. 입력이 늦으면 시뮬레이션이 잠시 멈추고, 렌더링은 계속된다.
// 패킷 손실은 재전송 대신 중복 전송으로 처리한다(확인받지 못한 입력을 매 패킷에 다시 싣는다).
// 피어는 실행한 틱의 상태 해시를 보고하고, 호스트가 비교해 디싱크를 감지한다.
// 확정 명령(submitCommand): 가끔 있는 크기가 제각각인 명령(치트, 입력 지연 변경 등). 피어가 보내면 호스트가 확정하는 틱에 붙여
// 그 틱의 입력과 함께 배포한다(입력과 같은 중복 전송, 클라이언트 → 호스트는 확인받을 때까지 다시 싣는다). 틱당 kCommandBytesPerTick까지,
// 넘치면 다음 틱. 한 틱 안의 순서는 플레이어 번호 → 보낸 순서. 게임은 mealkit/sim/Commands.h로 타입을 붙여 쓴다.
//
// 세션 한 번에 매치를 여러 번 한다: 로비 → startMatch → 매치(Running) → returnToLobby → 로비 → ... (화면 흐름, game::MatchService).
// 로비에서는 사람마다 이름·준비·로드아웃을 호스트가 모아 모두에게 보여 준다. 채팅은 틱 밖 메시지라 입력 기록에 들어가지 않는다.
namespace mealkit::net {

inline constexpr u32 kMaxPlayers = 8;
inline constexpr u32 kInputBytes = 8;   // 게임이 정의하는 플레이어 입력 크기 (틱당)
inline constexpr u32 kTickWindow = 256; // 동시에 다룰 수 있는 틱 범위 (30Hz 기준 약 8.5초)
inline constexpr u32 kMaxCommandBytes = 200;     // 명령 하나의 최대 크기
inline constexpr u32 kCommandBytesPerTick = 256; // 한 틱에 싣는 명령 (명령마다 머리 2바이트 포함)
inline constexpr u32 kMaxLoadoutBytes = 128;     // 플레이어 한 명의 매치 시작 데이터 (시작 패킷 하나에 8명이 들어가게)
inline constexpr u32 kMaxNameBytes = 24;         // 로비에 보이는 플레이어 이름 (UTF-8, 넘으면 글자 단위로 자른다)
inline constexpr u32 kMaxChatBytes = 120;        // 채팅 한 줄 (UTF-8)
inline constexpr u32 kChatLogSize = 50;          // chatLog()가 남기는 줄 수
inline constexpr f64 kChatInterval = 0.5;        // 내 채팅 한 줄 사이 최소 간격 (초)

struct PlayerInput {
    u8 bytes[kInputBytes] = {};
};

struct TickInputs {
    PlayerInput players[kMaxPlayers];
    u16 commandBytes = 0;                     // commands에 쓴 바이트
    u8 commands[kCommandBytesPerTick] = {};   // [플레이어 u8][크기 u8][내용] 반복 (forEachCommand로 읽는다)
};

// 이 틱의 확정 명령: f(플레이어, 내용, 크기)
template <class F>
void forEachCommand(const TickInputs& in, F&& f) {
    u32 i = 0;
    while (i + 2 <= in.commandBytes) {
        const u8 player = in.commands[i];
        const u32 size = in.commands[i + 1];
        if (i + 2 + size > in.commandBytes) break;
        f(player, in.commands + i + 2, size);
        i += 2 + size;
    }
}

enum class SessionState : u8 {
    Idle,       // 시작 전
    Connecting, // 클라이언트: 호스트에 접속 중
    Lobby,      // 매치 시작 대기
    Running,    // 시뮬레이션 진행 중
    Ended,      // 종료 (endReason 참고)
};

struct SessionStats {
    f32 rttMs = 0.0f; // 클라이언트: 호스트 왕복 시간
    u32 sentBytesPerSec = 0;
    u32 recvBytesPerSec = 0;
};

// 로비에 있는 사람 하나 (호스트가 모아 로비 신호로 나눠 준다)
struct LobbyMember {
    u8 player = 0;  // 플레이어 번호 (호스트 0). 매치를 시작하면 빈 번호 없이 다시 매긴다
    std::string name;
    bool ready = false;
    bool host = false;
    std::vector<u8> loadout; // 그 사람이 고른 매치 시작 데이터 (game::readLobbyLoadout으로 읽는다)
};

struct ChatMessage {
    u32 serial = 0; // 이 세션에서 받은 순서 (1부터): 화면이 새 줄을 알아본다
    u8 player = 0;
    std::string name; // 보낼 때의 이름
    std::string text;
};

// 실행 파일마다 다른 값 (같은 빌드끼리만 접속한다: 결정론은 같은 기계어 코드를 전제로 한다)
u32 buildId();

class LockstepSession {
public:
    LockstepSession();
    ~LockstepSession();
    LockstepSession(const LockstepSession&) = delete;
    LockstepSession& operator=(const LockstepSession&) = delete;

    // 게임 데이터(씬 등)의 해시. host/join 전에 설정하면 다른 데이터를 가진 피어의 접속을 거부한다.
    void setContentHash(u64 hash);
    u64 contentHash() const;
    // 호스트: 실행 파일이 다른 피어도 받는다. 컴파일러 비교 시험 전용(mp_test -ClientExe). 디싱크가 날 수 있다.
    void setAcceptOtherBuilds(bool accept);

    // 혼자 플레이: 네트워크 없이 같은 코드 경로를 쓴다. startOffline은 바로 매치, openOffline은 로비부터(startMatch로 시작)
    bool startOffline(u64 seed, u32 matchData);
    bool openOffline();
    // loopbackOnly: 같은 PC 테스트용 (방화벽 확인 창이 뜨지 않는다)
    bool host(u16 port, u32 maxPlayers, u32 inputDelay, bool loopbackOnly = false);
    bool join(const Address& hostAddress);
    // 다른 전송 계층(Steam 등)으로 방 만들기/참가
    bool hostWith(std::unique_ptr<Transport> transport, u32 maxPlayers, u32 inputDelay);
    bool joinWith(std::unique_ptr<Transport> transport, const Address& hostAddress);
    // 매치 시작 데이터 (플레이어별 로드아웃, mealkit/game/Loadout.h): 매치 전에 정한다. 클라이언트는 로비 신호(1초마다)에 실어 보내고,
    // 호스트가 startMatch 때 모든 플레이어 것을 확정해 시작 패킷으로 배포한다. 크기는 kMaxLoadoutBytes까지 (넘으면 false)
    bool setLocalLoadout(const void* data, u32 size);
    // 확정된 로드아웃 (Running 이후, 플레이어 번호마다. 보내지 않았으면 비어 있다)
    const std::vector<u8>& loadout(u32 player) const;
    // 로비에 보이는 내 이름(kMaxNameBytes까지)과 준비. 클라이언트는 로비 신호에 실어 보낸다 (바뀌면 바로)
    void setLocalName(const std::string& name);
    const std::string& localName() const;
    void setLocalReady(bool ready);
    bool localReady() const;
    // 로비에 있는 사람 (플레이어 번호 순, 호스트 포함). 매치 중에는 시작할 때의 목록
    const std::vector<LobbyMember>& lobbyMembers() const;
    // 호스트 전용: 로비 → 진행. seed와 matchData(게임이 정하는 매치 설정값)를 모두에게 보낸다.
    void startMatch(u64 seed, u32 matchData);
    // 호스트 전용: 진행 → 로비 (결과 화면 뒤). 클라이언트도 로비로 돌아가고 모두의 준비가 풀린다. 다음 startMatch가 새 매치다
    void returnToLobby();
    u32 matchIndex() const; // 시작한 매치 수 (첫 매치가 1)
    // 매 프레임 호출: 패킷 수신, 확정, 송신.
    void update(f64 now);
    void shutdown();
    // 세션을 닫고(상대에게 알린다) 처음(Idle)으로 돌아간다. 콘텐츠 해시·빌드 설정·이름은 남는다 (메뉴로 나가기)
    void reset();

    SessionState state() const;
    const char* endReason() const;
    bool isHost() const;
    bool isOffline() const;
    u8 localPlayer() const;
    u32 playerCount() const;      // 매치 참가 인원 (Running 이후 확정)
    u32 lobbyPlayerCount() const; // 로비 인원
    u32 maxPlayers() const;
    u64 seed() const;
    u32 matchData() const;
    u32 inputDelay() const;

    bool canExecute(u32 tick) const;
    const TickInputs& inputs(u32 tick) const;
    // 틱 T를 실행한 직후 호출한다.
    void tickExecuted(u32 tick, u64 stateHash);
    // 로컬 입력을 (실행한 틱 + inputDelay) 틱용으로 제출한다.
    void submitLocalInput(u32 tick, const PlayerInput& input);
    // 확정 명령을 보낸다 (Running일 때만, 크기 1..kMaxCommandBytes). 호스트가 다음에 확정하는 틱에 들어간다. 대기열이 차면 false.
    bool submitCommand(const void* data, u32 size);

    // 채팅 (로비·매치 중, 틱 밖): 한 줄(kMaxChatBytes까지 자른다)을 보낸다. 호스트가 모두에게 순서대로 나눠 주고, 확인받을 때까지 다시 보낸다.
    // 빈 줄이거나 kChatInterval보다 빨리 보내면 false. 입력 기록·리플레이에 들어가지 않는다
    bool sendChat(const std::string& text);
    const std::vector<ChatMessage>& chatLog() const; // 받은 순서, 마지막 kChatLogSize 줄 (내 것 포함)

    bool desynced() const;
    u32 desyncTick() const;
    const SessionStats& stats() const;

private:
    struct Impl;
    Impl* m;
};

// UTF-8 문자열을 maxBytes 이하로 글자 단위로 자른다 (이름, 채팅)
std::string clampUtf8(const std::string& text, u32 maxBytes);

} // namespace mealkit::net
