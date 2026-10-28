#pragma once

#include "mealkit/core/Types.h"
#include "mealkit/net/Conditions.h"
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
//
// 중간 참가·재접속: 매치 중에 누가 끊기면 매치는 계속되고 그 슬롯의 입력은 빈 입력이 된다. 다시 들어오면(같은 세션 토큰이나 이름)
// 그 슬롯을, 처음 들어온 사람은 빈 슬롯을 받는다. 호스트는 게임(game::Simulation)에게 지금 틱의 월드 스냅샷을 받아(snapshotWanted →
// provideSnapshot) LZ4로 압축해 나눠 보내고, 들어온 사람은 그 틱부터 확정된 입력으로 빨리 감아 따라잡는다(catchingUp). 다른 사람은 멈추지 않는다.
// 접속·끊김은 엔진 확정 명령(kPresenceCommand)으로 모두 같은 틱에 시뮬레이션에 알린다(sim::readPresence).
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
// 엔진 확정 명령 이름 (명령 타입 = 이름의 fnv1a): 플레이어 접속·끊김. 내용 [접속 u8][로드아웃 바이트], 보낸 플레이어 = 그 슬롯
inline constexpr const char* kPresenceCommand = "mealkit.net.Presence";

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
    u32 pingMs = 0; // 호스트와의 왕복 시간 (호스트가 잰다, 호스트 자신은 0)
    std::vector<u8> loadout; // 그 사람이 고른 매치 시작 데이터 (game::readLobbyLoadout으로 읽는다)
};

struct ChatMessage {
    u32 serial = 0; // 이 세션에서 받은 순서 (1부터): 화면이 새 줄을 알아본다
    u8 player = 0;
    std::string name; // 보낼 때의 이름
    std::string text;
};

// 입력 지연 자동 조절 (호스트): 매치 시작 때 로비에서 잰 왕복 시간으로 정하고, 매치 중에는 엔진 확정 명령으로 모두 같은 틱부터 1틱씩 바꾼다
struct AutoDelay {
    bool enabled = false;
    f32 tickMs = 1000.0f / 30.0f; // 한 틱의 길이 (프로젝트 틱레이트)
    u32 minTicks = 2;             // 같은 공유기에서도 이보다 짧게 하지 않는다
    u32 maxTicks = 8;             // 이보다 먼 상대는 멈칫거린다 (로비가 경고한다)
};

// 이 왕복 시간(ms)에 맞는 입력 지연 (틱): 가장 먼 상대의 입력이 호스트를 거쳐 모두에게 닿을 시간 + 흔들림 여유 + 한 틱
u32 delayForRtt(f32 rttMs, const AutoDelay& autoDelay);

// 실행 파일마다 다른 값 (시뮬레이션 버전을 모를 때 대신 쓴다)
u32 buildId();
// 결정론 그룹: 컴파일러와 CPU ("msvc-x64", "clang-x64", "clang-arm64" ...). 플랫폼 사이 결정론을 확인하기 전까지(5단계)
// 그룹이 다른 피어는 받지 않는다
const char* determinismGroup();

// 콘텐츠 해시 구성 (거부 이유를 알려 주려고 따로 비교한다): game::MatchData::contentParts의 순서
enum class ContentPart : u8 { Scene, Models, Tuning, Project, Tables, Count };

// 접속 거부 이유 (클라이언트, rejectInfo())
enum class RejectReason : u8 { None, Version, Platform, Content, Full, InProgress };
struct RejectInfo {
    RejectReason reason = RejectReason::None;
    u32 contentMask = 0;     // Content: 다른 구성 (비트 = ContentPart)
    std::string hostVersion; // Version: 방장의 게임 버전
    std::string hostGroup;   // Platform: 방장의 결정론 그룹
};

class LockstepSession {
public:
    LockstepSession();
    ~LockstepSession();
    LockstepSession(const LockstepSession&) = delete;
    LockstepSession& operator=(const LockstepSession&) = delete;

    // 게임 데이터(씬 등)의 해시. host/join 전에 설정하면 다른 데이터를 가진 피어의 접속을 거부한다.
    void setContentHash(u64 hash);
    u64 contentHash() const;
    // 해시 구성 (ContentPart 순서, Count개): 거부할 때 무엇이 다른지 알려 준다
    void setContentParts(const u64* parts);
    // 이 빌드의 시뮬레이션 버전과 게임 버전 (game::BuildInfo). 시뮬레이션 버전이 다른 피어는 받지 않는다 (0이면 buildId)
    void setBuild(u64 simVersion, const std::string& gameVersion);
    // 클라이언트: 호스트가 접속을 거부한 이유 (Ended 뒤)
    const RejectInfo& rejectInfo() const;
    // 호스트: 실행 파일이 다른 피어도 받는다. 컴파일러 비교 시험 전용(mp_test -ClientExe). 디싱크가 날 수 있다.
    void setAcceptOtherBuilds(bool accept);
    // 네트워크 상태 흉내 (지연·흔들림·손실, mealkit/net/Conditions.h): host/join 전에. 시험용
    void setConditions(const NetConditions& conditions);
    // 호스트: 입력 지연 자동 조절 (host의 inputDelay는 처음 값). 매치 중 바꾼 값은 inputDelay()
    void setAutoDelay(const AutoDelay& autoDelay);
    // 호스트, 매치 중: 입력 지연을 이 값으로 바꾸는 엔진 명령을 보낸다 (모두 같은 틱부터). 시험·게임 설정용
    bool requestInputDelay(u32 ticks);

    // 혼자 플레이: 네트워크 없이 같은 코드 경로를 쓴다. startOffline은 바로 매치, openOffline은 로비부터(startMatch로 시작)
    bool startOffline(u64 seed, u32 matchData);
    bool openOffline();
    // 기록된 매치를 다시 돌린다 (네트워크 없음, Idle에서만). 바로 Running이 되고 canExecute는 기록된 틱까지만 참이다.
    // 내 입력·명령은 버린다. hashes가 있으면 tickExecuted에서 비교해 처음 다른 틱을 디싱크로 알린다 (desynced/desyncTick)
    bool startReplay(u64 seed, u32 matchData, const std::vector<std::vector<u8>>& loadouts,
                     std::vector<TickInputs> inputs, std::vector<u64> hashes);
    bool isReplay() const;
    u32 replayTicks() const; // 기록된 틱 수 (리플레이가 아니면 0)
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
    // 매치 중 접속해 있는 플레이어 (비트 = 플레이어 번호, 실행한 틱 기준: 접속·끊김 명령을 실행하면 바뀐다)
    u32 connectedMask() const;

    // 중간 참가 (호스트): 들어오는 사람에게 보낼 스냅샷이 필요하다. 게임이 틱 사이에 provideSnapshot(다음에 실행할 틱, 바이트)으로 준다
    bool snapshotWanted() const;
    void provideSnapshot(u32 tick, const std::vector<u8>& bytes);
    // 중간 참가 (클라이언트): Running이 된 첫 틱 (처음부터 시작했으면 0). 스냅샷 바이트는 게임이 한 번 가져간다
    u32 joinTick() const;
    bool takeJoinSnapshot(std::vector<u8>& out);
    // 들어온 뒤 확정된 틱을 따라잡는 중: 게임은 한 프레임에 많이 돌리고, 내 입력은 따라잡은 뒤부터 보낸다
    bool catchingUp() const;
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
    // 플레이어별 호스트와의 왕복 시간 (ms, 호스트가 로비·매치 동안 재서 모두에게 나눠 준다. 호스트는 0)
    u32 pingMs(u32 player) const;
    // 매치가 이 플레이어들의 입력을 기다리며 멈춰 있다 (비트 = 플레이어 번호, 0.15초 넘게 멈췄을 때만).
    // 클라이언트는 호스트가 알려 준 값, 호스트의 묶음이 0.3초 넘게 오지 않으면 호스트(비트 0)
    u32 waitingFor() const;

private:
    struct Impl;
    Impl* m;
};

// UTF-8 문자열을 maxBytes 이하로 글자 단위로 자른다 (이름, 채팅)
std::string clampUtf8(const std::string& text, u32 maxBytes);

} // namespace mealkit::net
