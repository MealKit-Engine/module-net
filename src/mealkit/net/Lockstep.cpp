#include "mealkit/net/Lockstep.h"

#include "mealkit/core/Compress.h"
#include "mealkit/core/Hash.h"
#include "mealkit/core/Log.h"
#include "mealkit/core/Profile.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <deque>
#include <memory>
#include <random>
#include <string>
#include <vector>

namespace mealkit::net {
namespace {

constexpr u32 kMagic = 0x52545341u; // "ASTR"
constexpr u32 kMaxPacket = 1200;    // 인터넷 경로에서 쪼개지지 않는 안전한 크기
constexpr f64 kKeepAliveInterval = 1.0 / 30.0;
constexpr f64 kLobbyInterval = 0.5;
constexpr f64 kConnectInterval = 0.25;
constexpr f64 kStartResendInterval = 0.1;
constexpr f64 kChatResendInterval = 0.1;
constexpr f64 kTimeout = 10.0;
constexpr f64 kStallReport = 0.15;     // 이만큼 확정이 멈추면 누구를 기다리는지 알린다
constexpr f64 kHostSilence = 0.3;      // 클라이언트: 호스트 묶음이 이만큼 없으면 호스트를 기다린다
constexpr f64 kDelayCheckInterval = 1.0; // 호스트: 입력 지연을 다시 볼 간격
constexpr f64 kDelayChangeInterval = 3.0; // 호스트: 입력 지연을 바꾼 뒤 다음 변경까지
const u32 kDelayCommandType = static_cast<u32>(fnv1a("mealkit.net.InputDelay")); // 엔진 확정 명령 (게임 명령과 겹치지 않는 이름)
const u32 kPresenceCommandType = static_cast<u32>(fnv1a(kPresenceCommand)); // 접속·끊김 (Lockstep.h)
constexpr u32 kSnapshotChunk = 1100;      // 스냅샷 패킷 하나의 데이터 (머리를 더해 kMaxPacket 안)
constexpr u32 kSnapshotWindow = 32 * kSnapshotChunk; // 확인받지 않고 보내 두는 양
constexpr f64 kSnapshotResend = 0.25;     // 확인이 이만큼 나아가지 않으면 확인받은 곳부터 다시
constexpr u32 kCaughtUpTicks = 2;
constexpr f64 kStaleConnection = 1.0;     // 호스트: 이만큼 소식이 없는 연결은 같은 이름의 재접속이 대신한다         // 클라이언트: 확정된 끝에서 이만큼 안이면 따라잡았다
constexpr u32 kMaxTicksPerPacket = 32;
constexpr u32 kNoTick = 0xFFFFFFFFu;
constexpr u32 kMaxPendingCommands = 256; // 호스트: 틱을 기다리는 명령
constexpr u32 kMaxOutCommands = 64;      // 클라이언트: 호스트가 확인하지 않은 명령
constexpr u32 kMaxOutChat = 16;          // 클라이언트: 호스트가 확인하지 않은 채팅
constexpr u32 kMaxRelayLog = 64;         // 호스트: 아직 모두가 확인하지 않은 채팅
// 호스트 이전 (docs/DECISIONS.md 2026-10-28)
constexpr f64 kSuccessionInterval = 1.0; // 호스트: 승계 목록을 보내는 간격
constexpr f64 kHostLost = 3.0;           // 클라이언트: 매치가 흐르는 중 호스트가 이만큼 조용하면 승계자에게 넘어간다 (로비·로딩은 kTimeout)
constexpr f64 kMigrateHold = 1.0;        // 새 호스트: 다른 피어의 더 앞선 확정 틱을 기다리는 시간 (그동안 스스로 확정하지 않는다)
constexpr f64 kTickRequestInterval = 0.1;
constexpr f64 kUpdateGap = 0.5;          // 클라이언트: update 사이가 이보다 길면 (내가 멈춰 있었다) 그동안은 침묵으로 세지 않는다
constexpr u32 kUnknownSeq = 0xFFFFFFFFu; // 새 호스트: 이 피어의 명령·채팅 번호를 아직 모른다 (처음 받은 것부터)

enum class Packet : u8 {
    ConnectRequest = 1,
    ConnectAccept,
    ConnectReject,
    Lobby,
    Start,
    Input,
    Bundle,
    Disconnect,
    Chat,      // 클라이언트 → 호스트: 보낼 채팅 + 받은 채팅 확인
    ChatRelay, // 호스트 → 클라이언트: 모두의 채팅 + 보낸 채팅 확인
    Roster,    // 호스트 → 클라이언트: 매치 중 명단 (로비 신호와 같은 모양: 이름·핑, 로비로 돌아가지는 않는다)
    Snapshot,    // 호스트 → 중간 참가: 압축한 월드 스냅샷 조각 [매치][위치 u32][크기 u16][바이트]
    SnapshotAck, // 중간 참가 → 호스트: 처음부터 이어서 받은 바이트 수
    Succession,  // 호스트 → 클라이언트: 승계 목록 [수 u8]{번호 u8, 연결 u8, 토큰 u64, 이름, ip u32, 포트 u16, steamId u64} (호스트 자신 먼저)
    Handoff,     // 호스트 → 클라이언트: 호스트가 나간다, 승계 목록대로 넘어가라 (Disconnect 대신)
    TickRequest, // 새 호스트 → 클라이언트: [매치][이 틱부터] 네가 가진 확정 틱을 보내라
    TickFill,    // 클라이언트 → 새 호스트: [매치][첫 틱 u32][수 u8] 틱마다 kMaxPlayers × 입력 + 명령
};
using Reject = RejectReason;

constexpr u8 kMemberReady = 1;
constexpr u8 kMemberHost = 2;

u32 toMs(f64 seconds) { return static_cast<u32>(seconds * 1000.0) + 1; } // 0은 "없음"

const char* rejectText(Reject r) {
    switch (r) {
    case Reject::Version: return "Host runs a different game version";
    case Reject::Platform: return "Host runs a build for another platform or compiler";
    case Reject::Full: return "Session is full";
    case Reject::InProgress: return "Match already in progress";
    case Reject::Content: return "Host uses different game data";
    case Reject::None: break;
    }
    return "Connection rejected";
}

struct Writer {
    u8 data[kMaxPacket];
    u32 size = 0;
    bool ok = true;

    template <class T>
    void put(const T& v) {
        bytes(&v, sizeof(T));
    }
    void bytes(const void* p, u32 n) {
        if (size + n > kMaxPacket) {
            ok = false;
            return;
        }
        std::memcpy(data + size, p, n);
        size += n;
    }
    void text(const std::string& s) { // u8 길이 + 바이트 (255바이트까지)
        const u32 n = std::min<u32>(static_cast<u32>(s.size()), 255);
        put(static_cast<u8>(n));
        bytes(s.data(), n);
    }
};

struct Reader {
    const u8* data;
    u32 size;
    u32 pos = 0;
    bool ok = true;

    Reader(const u8* d, u32 s) : data(d), size(s) {}
    template <class T>
    T get() {
        T v{};
        bytes(&v, sizeof(T));
        return v;
    }
    void bytes(void* out, u32 n) {
        if (pos + n > size) {
            ok = false;
            std::memset(out, 0, n);
            return;
        }
        std::memcpy(out, data + pos, n);
        pos += n;
    }
    std::string text(u32 maxBytes) {
        const u8 n = get<u8>();
        std::string s(n, '\0');
        bytes(s.data(), n);
        return ok ? clampUtf8(s, maxBytes) : std::string();
    }
};

void header(Writer& w, Packet type) {
    w.put(kMagic);
    w.put(static_cast<u8>(type));
}

struct HashEntry {
    u32 tick = kNoTick;
    u64 hash = 0;
};

struct Slot {
    u32 tick = kNoTick;
    u32 mask = 0; // 입력이 도착한 플레이어 비트
    bool complete = false;
    TickInputs inputs{};
};

struct Peer {
    Address address;
    u8 playerId = 0;
    f64 lastRecv = -1.0;
    f64 lastSend = -1.0;
    f64 lastControlSend = -1.0; // 접속 요청 / 로비 / 시작 패킷
    f64 lastChatSend = -1.0;
    bool started = false;       // 호스트: 이 클라이언트가 시작을 확인했는가
    u32 inputNext = 0;          // 호스트: 이 클라이언트에게서 연속으로 받은 입력의 다음 틱
    u32 bundleNext = 0;         // 호스트: 이 클라이언트가 아직 못 받은 첫 확정 틱
    u32 echoTime = 0;           // RTT 측정용으로 되돌려 줄 상대 시각
    u32 commandNext = 0;        // 호스트: 이 클라이언트에게서 받은 명령의 다음 번호
    f32 rttMs = 0.0f;           // 호스트: 이 클라이언트와의 왕복 시간 (지수 평균)
    u32 hostEcho = 0;           // 클라이언트: 호스트가 보낸 시각 (되돌려 줘서 호스트가 왕복 시간을 잰다)
    std::vector<u8> loadout;    // 호스트: 로비에서 받은 이 클라이언트의 매치 시작 데이터
    std::string name;           // 호스트: 로비 이름
    bool ready = false;         // 호스트: 로비 준비
    u32 chatNext = 0;           // 호스트: 이 클라이언트에게서 받은 채팅의 다음 번호
    u32 relayNext = 0;          // 호스트: 이 클라이언트가 확인한 중계 채팅의 다음 번호
    bool chatAckDirty = false;  // 호스트: 받은 채팅을 확인해 줘야 한다
    u64 token = 0;              // 호스트: 이 클라이언트의 세션 토큰 (재접속 때 같은 슬롯을 찾는다)
    // 호스트, 중간 참가: 스냅샷을 받는 중(late && !started)이거나 확정된 틱을 따라잡는 중(catchUp)
    bool late = false;
    bool catchUp = false;
    std::shared_ptr<const std::vector<u8>> snapshot; // 압축한 스냅샷 (provideSnapshot 뒤)
    u32 snapshotTick = kNoTick;
    u32 snapshotRaw = 0;        // 압축 전 크기
    u32 snapshotCount = 0;      // 스냅샷 틱의 참가 인원·접속 (시작 패킷에 싣는다)
    u32 snapshotConnected = 0;
    u32 snapshotAcked = 0, snapshotSent = 0;
    f64 snapshotProgress = 0.0;
    HashEntry reported[kTickWindow];
    // 새 호스트: 호스트 이전 뒤 이 피어에게서 소식을 들었다, 그 피어가 가진 확정 틱의 끝
    bool heard = true;
    u32 clientFinal = 0;
};

// 승계 목록 한 줄 (호스트 이전)
struct Successor {
    u8 player = 0;
    bool connected = true;
    u64 token = 0;
    std::string name;
    Address address;
};

// 호스트: 매치 중에 끊긴 사람 (다시 들어오면 같은 슬롯)
struct Departed {
    u8 playerId = 0;
    u64 token = 0;
    std::string name;
};

struct Command {
    u32 seq = 0;   // 클라이언트: 보낸 순서 번호
    u8 player = 0; // 호스트: 보낸 플레이어
    u8 size = 0;
    u8 data[kMaxCommandBytes];
};

struct OutChat { // 클라이언트: 호스트가 확인하지 않은 내 채팅
    u32 seq = 0;
    std::string text;
};

struct RelayChat { // 호스트: 모두에게 나눠 주는 채팅 (번호 순)
    u32 index = 0;
    u8 player = 0;
    std::string name;
    std::string text;
};

} // namespace

const char* determinismGroup() {
#if defined(__clang__)
#define MEALKIT_GROUP_COMPILER "clang"
#elif defined(_MSC_VER)
#define MEALKIT_GROUP_COMPILER "msvc"
#elif defined(__GNUC__)
#define MEALKIT_GROUP_COMPILER "gcc"
#else
#define MEALKIT_GROUP_COMPILER "other"
#endif
#if defined(_M_X64) || defined(__x86_64__)
    return MEALKIT_GROUP_COMPILER "-x64";
#elif defined(_M_ARM64) || defined(__aarch64__)
    return MEALKIT_GROUP_COMPILER "-arm64";
#else
    return MEALKIT_GROUP_COMPILER "-other";
#endif
}

u32 buildId() {
    static const u32 id = static_cast<u32>(fnv1a(__DATE__ " " __TIME__));
    return id;
}

std::string clampUtf8(const std::string& text, u32 maxBytes) {
    if (text.size() <= maxBytes) return text;
    size_t end = maxBytes;
    while (end > 0 && (static_cast<u8>(text[end]) & 0xC0) == 0x80) --end; // 글자 중간에서 자르지 않는다
    return text.substr(0, end);
}

struct LockstepSession::Impl {
    SessionState state = SessionState::Idle;
    std::string endReason;
    bool host = false;
    bool offline = false;
    bool replay = false;               // startReplay: 입력은 replayInputs에서
    std::vector<TickInputs> replayInputs;
    std::vector<u64> replayHashes;     // replayInputs[t]를 실행한 뒤의 해시 (비어 있으면 비교하지 않는다)
    bool netStarted = false;
    std::unique_ptr<Transport> transport;
    std::vector<Peer> peers; // 호스트: 클라이언트들 (플레이어 번호 순) / 클라이언트: [0] = 호스트

    u32 maxPlayers = 1;
    u32 playerCount = 1;
    u32 lobbyCount = 0;
    u8 localPlayer = 0;
    u64 seed = 0;
    u32 matchData = 0;
    u32 inputDelay = 3;
    u64 contentHash = 0;
    u64 contentParts[static_cast<u32>(ContentPart::Count)] = {};
    u64 simVersion = 0;      // 0이면 buildId()
    std::string gameVersion;
    RejectInfo rejectInfo;   // 클라이언트: 거부당한 이유
    bool acceptOtherBuilds = false;
    NetConditions conditions;
    AutoDelay autoDelay;
    f64 lastDelayCheck = 0.0, lastDelayChange = 0.0;
    bool delayChangePending = false; // 호스트: 보낸 지연 변경 명령이 아직 실행되지 않았다
    PlayerInput lastLocalInput;      // 지연이 늘 때 빈 틱을 채운다
    u32 matchIndex = 0; // 시작한 매치 수 (호스트가 정하고 시작·로비 패킷으로 알린다)

    Slot slots[kTickWindow];
    u32 finalNext = 0;    // 확정된 틱의 끝 (이 틱부터 미확정)
    u32 executedNext = 0; // 다음에 실행할 틱

    PlayerInput localInputs[kTickWindow]; // 클라이언트: 호스트가 확인하기 전까지 보관
    std::deque<Command> outCommands;      // 클라이언트: 호스트가 확인하기 전까지 보관 (매 입력 패킷에 다시 싣는다)
    u32 nextCommandSeq = 0;
    std::vector<Command> pendingCommands; // 호스트: 받은 순서, 다음에 확정하는 틱에 싣는다
    std::vector<u8> localLoadout;
    std::vector<u8> loadouts[kMaxPlayers]; // 확정된 매치 시작 데이터
    u32 localSubmittedNext = 0;
    u32 hostInputAckNext = 0;

    // 왕복 시간·멈춤 (플레이어용 네트워크 표시, 입력 지연 자동 조절)
    u32 playerPing[kMaxPlayers] = {};
    u32 waitMask = 0;
    f64 lastFinalize = 0.0; // 호스트: finalNext가 마지막으로 나아간 시각
    f64 lastBundle = 0.0;   // 클라이언트: 마지막 묶음 수신

    // 로비
    std::string localName;
    bool localReady = false;
    std::vector<LobbyMember> members; // 호스트: update마다 다시 만든다 / 클라이언트: 로비 신호에서
    std::vector<f64> memberSeen;      // 클라이언트: members마다 마지막으로 받은 시각 (나간 사람을 지운다)
    u32 memberCursor = 0;             // 호스트: 로비 신호에 다 들어가지 않으면 다음 신호는 여기부터

    // 채팅
    std::vector<ChatMessage> chatLog;
    u32 chatSerial = 0;
    f64 lastLocalChat = -1e9;
    std::deque<OutChat> outChat;   // 클라이언트
    u32 nextChatSeq = 0;           // 클라이언트
    u32 relayExpected = 0;         // 클라이언트: 다음에 받을 중계 번호
    bool relayStarted = false;     // 클라이언트: 첫 중계 패킷을 받았다
    bool relayAckDirty = false;    // 클라이언트
    f64 lastChatSend = -1.0;       // 클라이언트
    std::deque<RelayChat> relayLog; // 호스트
    u32 relayEnd = 0;               // 호스트: 다음 중계 번호

    // 중간 참가·재접속
    u64 localToken = 0;                 // 이 세션 객체의 토큰 (reset 뒤에도 남는다)
    u32 connected = 0;                  // 실행한 틱 기준 접속 비트
    u32 requiredFrom[kMaxPlayers] = {}; // 호스트: 이 틱부터 이 플레이어의 입력을 기다린다 (kNoTick: 기다리지 않는다, 빈 입력)
    u32 width = 1;                      // 호스트: 묶음에 싣는 플레이어 수 (쓴 적 있는 가장 큰 번호 + 1)
    std::vector<Departed> departed;     // 호스트
    bool snapshotWanted = false;        // 호스트: 게임에게 스냅샷을 달라고 한다
    std::deque<TickInputs> joinLog;     // 호스트: 따라잡는 사람에게 보낼 확정 틱 (링 버퍼에서 밀려난 것까지)
    u32 joinLogBase = 0;
    bool joinLogging = false;
    bool late = false;                  // 클라이언트: 매치 중에 들어왔다
    u32 joinTick = 0;                   // 클라이언트: 스냅샷의 틱 (처음부터면 0)
    u32 joinRaw = 0, joinCompressed = 0;
    std::vector<u8> joinBuffer;         // 클라이언트: 받는 중인 압축 스냅샷 (전체 크기, 조각은 순서 없이 채운다)
    std::vector<bool> joinChunks;       // 클라이언트: 받은 조각
    u32 joinPrefix = 0;                 // 클라이언트: 처음부터 빠짐없이 받은 바이트 (호스트에게 확인)
    std::vector<u8> joinSnapshot;       // 클라이언트: 푼 스냅샷 (게임이 가져간다)
    bool catchingUp = false;            // 클라이언트

    // 호스트 이전
    u8 hostPlayer = 0;                  // 지금 호스트의 플레이어 번호
    std::vector<Successor> successors;  // 클라이언트: 호스트가 마지막으로 보낸 승계 목록 (호스트 자신 포함, 보낸 순서)
    f64 lastSuccession = -1.0;          // 호스트
    f64 migrateHold = 0.0;              // 새 호스트: 이 시각까지 앞선 확정 틱을 기다린다 (0 = 끝)
    f64 lastTickRequest = -1.0;         // 새 호스트
    f64 lastUpdate = -1.0;              // 클라이언트: 지난 update 시각
    bool matchFlowing = false;          // 클라이언트: 이번 매치에서 묶음에 틱이 실려 왔다 (짧은 호스트 판정을 쓴다)
    u32 migrations = 0;

    HashEntry hashes[kTickWindow];
    u32 latestHashTick = kNoTick;
    u64 latestHash = 0;
    bool desynced = false;
    u32 desyncTick = 0;

    f64 now = 0.0;
    bool sendPending = false;
    SessionStats stats;
    f64 statsWindowStart = 0.0;
    u64 sentBytes = 0;
    u64 recvBytes = 0;

    u32 allMask() const { return (1u << playerCount) - 1u; }
    // 호스트: 이 틱을 확정하려면 입력이 있어야 하는 플레이어 (끊긴 사람·아직 따라잡는 사람은 빈 입력)
    u32 needMask(u32 tick) const {
        u32 mask = 0;
        for (u32 player = 0; player < kMaxPlayers; ++player)
            if (requiredFrom[player] <= tick) mask |= 1u << player;
        return mask;
    }
    Slot& slot(u32 tick) { return slots[tick % kTickWindow]; }
    const Slot& slot(u32 tick) const { return slots[tick % kTickWindow]; }
    u8 matchByte() const { return static_cast<u8>(matchIndex); } // 입력·묶음 패킷: 지난 매치의 늦은 패킷을 버린다

    Slot& claim(u32 tick) {
        Slot& s = slot(tick);
        if (s.tick != tick) {
            s = Slot{};
            s.tick = tick;
        }
        return s;
    }

    // 아직 필요한 가장 오래된 틱. 링 버퍼가 이보다 kTickWindow 이상 앞서면 덮어쓰게 되므로 받지 않는다.
    u32 windowLow() const {
        u32 low = executedNext;
        if (host)
            for (const Peer& p : peers)
                if (!(p.late && !p.started) && !p.catchUp) low = std::min(low, p.bundleNext); // 들어오는 사람은 joinLog에서 받는다
        return low;
    }
    bool inWindow(u32 tick) const { return tick + 1 < windowLow() + kTickWindow; }

    void beginRunning() {
        for (Slot& s : slots) s = Slot{};
        for (HashEntry& h : hashes) h = HashEntry{};
        // 처음 inputDelay 틱은 모두 빈 입력으로 확정된 상태에서 시작한다.
        for (u32 t = 0; t < inputDelay; ++t) {
            Slot& s = claim(t);
            s.mask = allMask();
            s.complete = true;
        }
        finalNext = inputDelay;
        for (u32 player = 0; player < kMaxPlayers; ++player) requiredFrom[player] = player < playerCount ? 0 : kNoTick;
        width = playerCount;
        connected = allMask();
        departed.clear();
        joinLog.clear();
        joinLogging = false;
        snapshotWanted = false;
        lastFinalize = lastBundle = now;
        waitMask = 0;
        executedNext = 0;
        localSubmittedNext = inputDelay;
        hostInputAckNext = inputDelay;
        latestHashTick = kNoTick;
        desynced = false;
        desyncTick = 0;
        outCommands.clear();
        pendingCommands.clear();
        nextCommandSeq = 0;
        delayChangePending = false;
        lastDelayChange = lastDelayCheck = now;
        lastLocalInput = {};
        matchFlowing = false;
        migrateHold = 0.0;
        lastSuccession = -1.0; // 매치 번호로 다시 매긴 목록을 바로 보낸다
        state = SessionState::Running;
    }

    u32 desiredDelay() const {
        f32 worst = 0.0f;
        for (const Peer& p : peers) worst = std::max(worst, p.rttMs);
        return delayForRtt(worst, autoDelay);
    }

    // 호스트: 매치 중 왕복 시간이 바뀌면 지연을 바꾸는 엔진 명령을 보낸다 (늘릴 때는 필요한 만큼 바로, 줄일 때는 2틱 넘게 남을 때 1틱씩)
    void adjustDelay() {
        if (!autoDelay.enabled || offline || delayChangePending || now - lastDelayCheck < kDelayCheckInterval) return;
        lastDelayCheck = now;
        if (now - lastDelayChange < kDelayChangeInterval) return;
        const u32 want = desiredDelay();
        u32 next = inputDelay;
        if (want > inputDelay) next = want; // 늘릴 때는 한 번에 (멈칫거림이 바로 사라진다)
        else if (want + 2 <= inputDelay) next = inputDelay - 1;
        if (next == inputDelay) return;
        if (queueDelay(next)) lastDelayChange = now;
    }

    bool queueDelay(u32 next) {
        if (!host || state != SessionState::Running || pendingCommands.size() >= kMaxPendingCommands) return false;
        Command c;
        c.player = localPlayer;
        c.size = 5;
        std::memcpy(c.data, &kDelayCommandType, 4);
        c.data[4] = static_cast<u8>(std::clamp(next, 1u, 30u));
        pendingCommands.push_back(c);
        delayChangePending = true;
        return true;
    }

    // 모든 피어가 같은 틱(지연 명령이 든 틱)을 실행한 직후 바꾼다. 다음 제출은 (tick + 새 지연)
    void applyDelay(u32 tick, u32 next) {
        next = std::clamp(next, 1u, 30u);
        if (next == inputDelay) return;
        MEALKIT_INFO("Input delay %u -> %u ticks from tick %u", inputDelay, next, tick);
        // 늘면 (tick-1+예전)과 (tick+새) 사이가 빈다: 마지막 내 입력으로 채운다 (줄면 겹치는 틱은 submitLocalInput이 건너뛴다)
        for (u32 t = tick + inputDelay; t < tick + next; ++t) {
            if (host) {
                Slot& s = claim(t);
                const u32 bit = 1u << localPlayer;
                if (!(s.mask & bit)) {
                    s.inputs.players[localPlayer] = lastLocalInput;
                    s.mask |= bit;
                }
            } else {
                localInputs[t % kTickWindow] = lastLocalInput;
                localSubmittedNext = std::max(localSubmittedNext, t + 1);
            }
        }
        inputDelay = next;
        delayChangePending = false;
        if (host) finalize();
        else sendPending = true;
    }

    void rttSample(Peer& p, u32 echo) {
        if (!echo) return;
        const f32 sample = static_cast<f32>(toMs(now) - echo);
        p.rttMs = p.rttMs == 0.0f ? sample : p.rttMs * 0.8f + sample * 0.2f;
    }

    bool finalize() {
        const u32 before = finalNext;
        for (;;) {
            Slot& s = slot(finalNext);
            if (s.tick != finalNext) break;
            if (!s.complete) {
                if (host && holding()) break; // 새 호스트: 앞선 확정 틱이 올 수 있다 (스스로 정하면 갈라진다)
                const u32 need = host ? needMask(finalNext) : allMask();
                if ((s.mask & need) != need) break;
                if (host) packCommands(s.inputs);
                s.complete = true;
            }
            if (host && joinLogging && joinLogBase + joinLog.size() == finalNext) joinLog.push_back(s.inputs);
            ++finalNext;
        }
        if (finalNext != before) lastFinalize = now;
        return finalNext != before;
    }

    // 새 호스트: 다른 피어가 더 앞선 확정 틱을 가졌을 수 있다. 모두에게서 소식을 듣고 그 틱을 다 받거나 kMigrateHold가 지나면 끝
    bool holding() {
        if (migrateHold == 0.0) return false;
        bool wait = false;
        for (const Peer& p : peers) wait = wait || !p.heard || p.clientFinal > finalNext;
        if (!wait || now >= migrateHold) {
            migrateHold = 0.0;
            MEALKIT_INFO("Host migration: continuing from tick %u", finalNext);
            return false;
        }
        return true;
    }

    // 호스트: 기다리던 명령을 이 틱에 싣는다. 플레이어 번호 → 받은 순서, 넘치면 그 플레이어의 나머지는 다음 틱 (순서 유지)
    void packCommands(TickInputs& in) {
        in.commandBytes = 0;
        if (pendingCommands.empty()) return;
        std::vector<bool> taken(pendingCommands.size(), false);
        for (u32 player = 0; player < kMaxPlayers; ++player) {
            for (size_t i = 0; i < pendingCommands.size(); ++i) {
                const Command& c = pendingCommands[i];
                if (c.player != player) continue;
                if (in.commandBytes + 2u + c.size > kCommandBytesPerTick) break;
                in.commands[in.commandBytes] = c.player;
                in.commands[in.commandBytes + 1] = c.size;
                std::memcpy(in.commands + in.commandBytes + 2, c.data, c.size);
                in.commandBytes = static_cast<u16>(in.commandBytes + 2u + c.size);
                taken[i] = true;
            }
        }
        size_t keep = 0;
        for (size_t i = 0; i < pendingCommands.size(); ++i)
            if (!taken[i]) pendingCommands[keep++] = pendingCommands[i];
        pendingCommands.resize(keep);
    }

    // 호스트: 접속·끊김 엔진 명령 (보낸 플레이어 = 그 슬롯). 모두 같은 틱에 applyPresence와 시뮬레이션이 처리한다
    void queuePresence(u8 player, bool isConnected, const std::vector<u8>& loadout) {
        Command c;
        c.player = player;
        std::memcpy(c.data, &kPresenceCommandType, 4);
        c.data[4] = isConnected ? 1 : 0;
        const u32 n = std::min<u32>(static_cast<u32>(loadout.size()), kMaxCommandBytes - 5);
        if (n) std::memcpy(c.data + 5, loadout.data(), n);
        c.size = static_cast<u8>(5 + n);
        pendingCommands.push_back(c);
    }

    void applyPresence(u8 player, bool isConnected, const u8* loadout, u32 size) {
        if (player >= kMaxPlayers) return;
        if (isConnected) {
            connected |= 1u << player;
            playerCount = std::max(playerCount, player + 1u);
            if (size) loadouts[player].assign(loadout, loadout + std::min(size, kMaxLoadoutBytes));
        } else {
            connected &= ~(1u << player);
        }
        if (host) width = std::max(width, playerCount);
    }

    // 확정된 틱의 입력: 링 버퍼, 이미 밀려났으면 joinLog
    const TickInputs* finalized(u32 tick) const {
        const Slot& s = slot(tick);
        if (s.tick == tick && s.complete) return &s.inputs;
        if (tick >= joinLogBase && tick - joinLogBase < joinLog.size()) return &joinLog[tick - joinLogBase];
        return nullptr;
    }

    // 호스트, 매치 중: 끊긴 사람은 빼고 계속한다 (그 슬롯은 빈 입력, 다시 들어오면 같은 슬롯)
    void dropPeer(size_t index, const char* why) {
        const Peer& p = peers[index];
        MEALKIT_WARN("Player %u %s - the match goes on without them", p.playerId, why);
        requiredFrom[p.playerId] = kNoTick;
        departed.push_back({p.playerId, p.token, p.name});
        queuePresence(p.playerId, false, {});
        peers.erase(peers.begin() + static_cast<std::ptrdiff_t>(index));
        if (finalize()) sendPending = true;
    }

    void send(const Address& to, const Writer& w) {
        if (!w.ok) return;
        if (transport) transport->send(to, w.data, w.size);
        sentBytes += w.size;
    }

    void end(const char* reason) {
        if (state == SessionState::Ended) return;
        MEALKIT_WARN("Session ended: %s", reason);
        endReason = reason;
        Writer w;
        header(w, Packet::Disconnect);
        for (const Peer& p : peers) {
            send(p.address, w);
            send(p.address, w);
        }
        state = SessionState::Ended;
    }

    void flagDesync(u32 tick, u32 player, u64 hostHash, u64 peerHash) {
        if (desynced) return;
        desynced = true;
        desyncTick = tick;
        MEALKIT_ERROR("DESYNC at tick %u: host %016llx vs player %u %016llx", tick,
                      static_cast<unsigned long long>(hostHash), player, static_cast<unsigned long long>(peerHash));
    }

    Peer* findPeer(const Address& a) {
        for (Peer& p : peers)
            if (p.address == a) return &p;
        return nullptr;
    }

    std::string displayName(const std::string& name, u8 player) const {
        return name.empty() ? "P" + std::to_string(player + 1) : name;
    }

    void addChat(u8 player, const std::string& name, const std::string& text) {
        ChatMessage entry;
        entry.serial = ++chatSerial;
        entry.player = player;
        entry.name = name;
        entry.text = text;
        chatLog.push_back(std::move(entry));
        if (chatLog.size() > kChatLogSize) chatLog.erase(chatLog.begin());
    }

    // ---------------- 호스트 ----------------

    // 비어 있는 가장 작은 플레이어 번호 (로비에서 나간 사람의 번호를 다시 쓴다)
    u8 freePlayerId() const {
        for (u8 id = 0; id < kMaxPlayers; ++id) {
            bool used = id == localPlayer;
            for (const Peer& p : peers) used = used || p.playerId == id;
            for (const Departed& d : departed) used = used || d.playerId == id;
            if (!used) return id;
        }
        return 0;
    }

    void rebuildMembers() {
        members.clear();
        LobbyMember self;
        self.player = localPlayer; // 이어받은 호스트는 0이 아닐 수 있다
        self.name = displayName(localName, localPlayer);
        self.ready = true; // 호스트는 시작하는 사람
        self.host = true;
        self.loadout = localLoadout;
        members.push_back(std::move(self));
        for (const Peer& p : peers) {
            LobbyMember entry;
            entry.player = p.playerId;
            entry.name = displayName(p.name, p.playerId);
            entry.ready = p.ready;
            entry.pingMs = static_cast<u32>(p.rttMs + 0.5f);
            entry.loadout = p.loadout;
            members.push_back(std::move(entry));
        }
        std::sort(members.begin(), members.end(), [](const LobbyMember& a, const LobbyMember& b) { return a.player < b.player; });
    }

    void sendAccept(const Peer& p) {
        Writer w;
        header(w, Packet::ConnectAccept);
        w.put(p.playerId);
        w.put(static_cast<u8>(maxPlayers));
        w.put(static_cast<u8>(state == SessionState::Running ? 1 : 0)); // 매치 중: 로비로 가지 않고 스냅샷을 기다린다
        send(p.address, w);
    }

    u64 mySimVersion() const { return simVersion ? simVersion : buildId(); }

    void sendReject(const Address& to, Reject reason, u32 contentMask = 0) {
        Writer w;
        header(w, Packet::ConnectReject);
        w.put(static_cast<u8>(reason));
        w.put(contentMask);
        w.text(gameVersion);
        w.text(determinismGroup());
        send(to, w);
    }

    // 로비 신호: 인원 + 사람마다 (번호, 준비, 이름, 로드아웃). 다 들어가지 않으면 다음 신호가 이어서 싣는다
    void sendLobby(const Peer& p, Packet type = Packet::Lobby) {
        Writer w;
        header(w, type);
        w.put(static_cast<u8>(members.size()));
        w.put(static_cast<u8>(maxPlayers));
        w.put(matchIndex);
        w.put(toMs(now)); // 클라이언트가 접속 요청에 되돌려 준다 (로비에서도 왕복 시간)
        const u32 countAt = w.size;
        w.put(static_cast<u8>(0));
        u8 written = 0;
        for (u32 k = 0; k < members.size(); ++k) {
            const LobbyMember& entry = members[(memberCursor + k) % members.size()];
            const u32 need = 6 + static_cast<u32>(entry.name.size()) + static_cast<u32>(entry.loadout.size()) + 1;
            if (w.size + need > kMaxPacket) break;
            w.put(entry.player);
            w.put(static_cast<u16>(std::min<u32>(entry.pingMs, 0xFFFF)));
            w.put(static_cast<u8>((entry.ready ? kMemberReady : 0) | (entry.host ? kMemberHost : 0)));
            w.text(entry.name);
            w.put(static_cast<u8>(entry.loadout.size()));
            w.bytes(entry.loadout.data(), static_cast<u32>(entry.loadout.size()));
            ++written;
        }
        w.data[countAt] = written;
        send(p.address, w);
    }

    void sendStart(const Peer& p) {
        Writer w;
        header(w, Packet::Start);
        const u32 count = p.late ? p.snapshotCount : playerCount;
        w.put(p.playerId);
        w.put(static_cast<u8>(count));
        w.put(static_cast<u8>(inputDelay));
        w.put(seed);
        w.put(matchData);
        w.put(matchIndex);
        for (u32 i = 0; i < count; ++i) {
            w.put(static_cast<u8>(loadouts[i].size()));
            w.bytes(loadouts[i].data(), static_cast<u32>(loadouts[i].size()));
        }
        w.put(static_cast<u8>(p.late ? 1 : 0));
        if (p.late) { // 중간 참가: 스냅샷의 틱·크기, 그 틱의 접속
            w.put(p.snapshotTick);
            w.put(p.snapshotRaw);
            w.put(static_cast<u32>(p.snapshot->size()));
            w.put(p.snapshotConnected);
        }
        send(p.address, w);
    }

    void sendBundle(Peer& p) {
        Writer w;
        header(w, Packet::Bundle);
        w.put(matchByte());
        w.put(p.inputNext);
        w.put(p.echoTime);
        w.put(static_cast<u8>(desynced ? 1 : 0));
        w.put(desyncTick);
        w.put(p.commandNext);
        w.put(toMs(now));
        w.put(static_cast<u8>(waitMask));
        w.put(static_cast<u8>(width));
        for (u32 player = 0; player < width; ++player) w.put(static_cast<u16>(std::min<u32>(playerPing[player], 0xFFFF)));
        const u32 first = p.bundleNext;
        const u32 perTick = width * kInputBytes + 2; // + 명령 바이트 수
        const u32 available = finalNext > first ? std::min(finalNext - first, kMaxTicksPerPacket) : 0;
        u32 count = 0, bytes = w.size + 4 + 1;
        while (count < available) { // 명령이 있는 틱은 커서 패킷에 들어가는 만큼만
            const TickInputs* in = finalized(first + count);
            if (!in || bytes + perTick + in->commandBytes > kMaxPacket) break;
            bytes += perTick + in->commandBytes;
            ++count;
        }
        w.put(first);
        w.put(static_cast<u8>(count));
        for (u32 i = 0; i < count; ++i) {
            const TickInputs& in = *finalized(first + i);
            for (u32 player = 0; player < width; ++player) w.bytes(in.players[player].bytes, kInputBytes);
            w.put(in.commandBytes);
            w.bytes(in.commands, in.commandBytes);
        }
        send(p.address, w);
        p.lastSend = now;
    }

    // 호스트 → 클라이언트: 아직 확인받지 못한 중계 채팅 + 받은 채팅 확인
    void sendChatRelay(Peer& p) {
        Writer w;
        header(w, Packet::ChatRelay);
        w.put(p.chatNext);
        const u32 first = std::max(p.relayNext, relayLog.empty() ? relayEnd : relayLog.front().index);
        w.put(first);
        const u32 countAt = w.size;
        w.put(static_cast<u8>(0));
        u8 count = 0;
        for (const RelayChat& c : relayLog) {
            if (c.index < first) continue;
            if (w.size + 3 + c.name.size() + c.text.size() > kMaxPacket || count == 255) break;
            w.put(c.player);
            w.text(c.name);
            w.text(c.text);
            ++count;
        }
        w.data[countAt] = count;
        send(p.address, w);
        p.lastChatSend = now;
        p.chatAckDirty = false;
    }

    void relayChat(u8 player, const std::string& name, const std::string& text) {
        RelayChat c;
        c.index = relayEnd++;
        c.player = player;
        c.name = name;
        c.text = text;
        relayLog.push_back(std::move(c));
        addChat(player, name, text);
        // 모두가 확인한 줄은 버린다 (너무 많이 밀리면 오래된 줄부터)
        u32 low = relayEnd;
        for (const Peer& p : peers) low = std::min(low, p.relayNext);
        while (!relayLog.empty() && (relayLog.front().index < low || relayLog.size() > kMaxRelayLog)) relayLog.pop_front();
    }

    void hostChat() {
        for (Peer& p : peers) {
            const bool unsent = p.relayNext < relayEnd;
            if ((unsent || p.chatAckDirty) && now - p.lastChatSend >= kChatResendInterval) sendChatRelay(p);
        }
    }

    // 매치 중 접속: 끊긴 사람(같은 토큰, 아니면 같은 이름)은 그 슬롯, 아니면 빈 슬롯. 스냅샷은 게임에게 달라고 하고 다음 update부터 보낸다
    Peer* acceptLate(const Address& from, u64 token, const std::string& name, const std::vector<u8>& loadout) {
        // 같은 사람이 새 주소로 (네트워크가 바뀌었다, 또는 끊김을 알리지 못하고 나갔다가 다시 켰다): 예전 연결을 끊은 셈 친다.
        // 토큰이 같거나, 같은 이름인데 예전 연결이 조용하다
        for (size_t i = 0; i < peers.size(); ++i)
            if ((token != 0 && peers[i].token == token) ||
                (!name.empty() && peers[i].name == name && now - peers[i].lastRecv > kStaleConnection)) {
                dropPeer(i, "reconnected");
                break;
            }
        size_t found = departed.size();
        for (size_t i = 0; i < departed.size() && found == departed.size(); ++i)
            if (token != 0 && departed[i].token == token) found = i;
        for (size_t i = 0; i < departed.size() && found == departed.size(); ++i)
            if (!name.empty() && departed[i].name == name) found = i;
        u8 id = 0;
        if (found < departed.size()) {
            id = departed[found].playerId;
            departed.erase(departed.begin() + static_cast<std::ptrdiff_t>(found));
        } else {
            if (1 + peers.size() + departed.size() >= maxPlayers) {
                sendReject(from, Reject::Full);
                return nullptr;
            }
            id = freePlayerId();
        }
        const bool rejoin = id < playerCount;
        Peer p;
        p.address = from;
        p.playerId = id;
        p.lastRecv = now;
        p.relayNext = relayEnd;
        p.token = token;
        p.name = name;
        p.loadout = loadout;
        p.late = true;
        peers.push_back(std::move(p));
        std::sort(peers.begin(), peers.end(), [](const Peer& a, const Peer& b) { return a.playerId < b.playerId; });
        width = std::max(width, id + 1u);
        queuePresence(id, true, loadout);
        snapshotWanted = true;
        MEALKIT_INFO("Player %u %s the match from %s (tick %u)", id, rejoin ? "rejoined" : "joined", from.toString().c_str(),
                     executedNext);
        return findPeer(from);
    }

    // 호스트 → 중간 참가: 확인받지 않은 스냅샷 조각을 창 크기만큼. 확인이 멈추면 확인받은 곳부터 다시
    void sendSnapshot(Peer& p) {
        const std::vector<u8>& data = *p.snapshot;
        const u32 size = static_cast<u32>(data.size());
        if (p.snapshotAcked >= size) return;
        if (now - p.snapshotProgress > kSnapshotResend) {
            p.snapshotSent = p.snapshotAcked;
            p.snapshotProgress = now;
        }
        while (p.snapshotSent < size && p.snapshotSent - p.snapshotAcked < kSnapshotWindow) {
            const u32 n = std::min(kSnapshotChunk, size - p.snapshotSent);
            Writer w;
            header(w, Packet::Snapshot);
            w.put(matchByte());
            w.put(p.snapshotSent);
            w.put(static_cast<u16>(n));
            w.bytes(data.data() + p.snapshotSent, n);
            send(p.address, w);
            p.snapshotSent += n;
        }
    }

    void hostReceive(const Address& from, Reader& r, Packet type) {
        Peer* peer = findPeer(from);
        if (peer) peer->lastRecv = now;

        switch (type) {
        case Packet::ConnectRequest: {
            const u64 build = r.get<u64>();
            const std::string group = r.text(32);
            const std::string version = r.text(64);
            const u64 content = r.get<u64>();
            u64 parts[static_cast<u32>(ContentPart::Count)] = {};
            for (u64& part : parts) part = r.get<u64>();
            const u8 loadoutSize = r.get<u8>();
            std::vector<u8> loadout(std::min<u32>(loadoutSize, kMaxLoadoutBytes));
            r.bytes(loadout.data(), static_cast<u32>(loadout.size()));
            const u8 flags = r.get<u8>();
            std::string name = r.text(kMaxNameBytes);
            const u32 hostEcho = r.get<u32>();
            const u64 token = r.get<u64>();
            if (!r.ok) return;
            // 같은 시뮬레이션이어야 한다: 결정론 그룹(컴파일러·CPU) → 시뮬레이션 버전(게임 버전 + 시뮬레이션 소스) → 게임 데이터
            if (group != determinismGroup() || build != mySimVersion()) {
                if (!acceptOtherBuilds) {
                    sendReject(from, group != determinismGroup() ? Reject::Platform : Reject::Version);
                    return;
                }
                if (!peer) MEALKIT_WARN("Accepting a peer with a different build (%s %s, test option)", group.c_str(), version.c_str());
            }
            if (content != contentHash) {
                u32 mask = 0;
                for (u32 i = 0; i < static_cast<u32>(ContentPart::Count); ++i)
                    if (parts[i] != contentParts[i]) mask |= 1u << i;
                sendReject(from, Reject::Content, mask);
                return;
            }
            if (!peer && state == SessionState::Running) {
                peer = acceptLate(from, token, name, loadout);
                if (!peer) return;
            }
            if (!peer) {
                if (state != SessionState::Lobby) {
                    sendReject(from, Reject::InProgress);
                    return;
                }
                if (1 + peers.size() >= maxPlayers) {
                    sendReject(from, Reject::Full);
                    return;
                }
                Peer p;
                p.address = from;
                p.playerId = freePlayerId();
                p.lastRecv = now;
                p.relayNext = relayEnd; // 들어오기 전의 채팅은 보내지 않는다
                p.token = token;
                peers.push_back(p);
                std::sort(peers.begin(), peers.end(), [](const Peer& a, const Peer& b) { return a.playerId < b.playerId; });
                peer = findPeer(from);
                MEALKIT_INFO("Player joined from %s (%zu/%u)", from.toString().c_str(), peers.size() + 1, maxPlayers);
            }
            rttSample(*peer, hostEcho);
            if (state == SessionState::Lobby) { // 로비 신호마다 새 값
                peer->loadout = std::move(loadout);
                peer->name = std::move(name);
                peer->ready = (flags & kMemberReady) != 0;
            }
            sendAccept(*peer);
            break;
        }
        case Packet::Input: {
            if (!peer || state != SessionState::Running) return;
            if (r.get<u8>() != matchByte()) return; // 지난 매치의 늦은 패킷
            peer->started = true;
            const u32 bundleNext = r.get<u32>();
            const u32 echo = r.get<u32>();
            const u32 hashTick = r.get<u32>();
            const u64 hash = r.get<u64>();
            const u32 hostEcho = r.get<u32>();
            const u32 first = r.get<u32>();
            const u8 count = r.get<u8>();
            if (!r.ok) return;
            rttSample(*peer, hostEcho);
            if (!peer->heard) peer->bundleNext = std::min(bundleNext, finalNext); // 호스트 이전 뒤 처음: 이 피어가 가진 끝부터 보낸다
            peer->heard = true;
            peer->clientFinal = bundleNext;
            if (requiredFrom[peer->playerId] == kNoTick && count > 0) { // 중간 참가·재접속: 따라잡고 처음 낸 입력부터 기다린다
                requiredFrom[peer->playerId] = std::max(first, finalNext);
                peer->inputNext = requiredFrom[peer->playerId];
                MEALKIT_INFO("Player %u is caught up: inputs from tick %u", peer->playerId, peer->inputNext);
            }

            peer->bundleNext = std::max(peer->bundleNext, std::min(bundleNext, finalNext));
            peer->echoTime = echo;
            const u32 bit = 1u << peer->playerId;
            for (u32 i = 0; i < count; ++i) {
                PlayerInput input;
                r.bytes(input.bytes, kInputBytes);
                if (!r.ok) break;
                const u32 t = first + i;
                if (t < peer->inputNext || !inWindow(t)) continue;
                Slot& s = claim(t);
                if (!(s.mask & bit)) {
                    s.inputs.players[peer->playerId] = input;
                    s.mask |= bit;
                }
            }
            for (;;) {
                const Slot& s = slot(peer->inputNext);
                if (s.tick != peer->inputNext || !(s.mask & bit)) break;
                ++peer->inputNext;
            }
            const u32 commandFirst = r.get<u32>();
            const u8 commandCount = r.get<u8>();
            if (r.ok && peer->commandNext == kUnknownSeq) peer->commandNext = commandFirst; // 호스트 이전 뒤 처음
            for (u32 i = 0; r.ok && i < commandCount; ++i) {
                Command c;
                c.size = r.get<u8>();
                if (c.size == 0 || c.size > kMaxCommandBytes) break;
                r.bytes(c.data, c.size);
                if (!r.ok) break;
                const u32 seq = commandFirst + i;
                if (seq < peer->commandNext) continue; // 이미 받은 것 (다시 실린 것)
                if (seq > peer->commandNext || pendingCommands.size() >= kMaxPendingCommands) break;
                c.player = peer->playerId;
                pendingCommands.push_back(c);
                ++peer->commandNext;
            }
            if (hashTick != kNoTick) {
                peer->reported[hashTick % kTickWindow] = {hashTick, hash};
                const HashEntry& own = hashes[hashTick % kTickWindow];
                if (own.tick == hashTick && own.hash != hash) flagDesync(hashTick, peer->playerId, own.hash, hash);
            }
            if (finalize()) sendPending = true;
            break;
        }
        case Packet::Chat: {
            if (!peer) return;
            const u32 relayAck = r.get<u32>();
            const u32 firstSeq = r.get<u32>();
            const u8 count = r.get<u8>();
            if (!r.ok) return;
            peer->relayNext = std::max(peer->relayNext, std::min(relayAck, relayEnd));
            if (peer->chatNext == kUnknownSeq) peer->chatNext = firstSeq; // 호스트 이전 뒤 처음
            for (u32 i = 0; i < count; ++i) {
                const std::string text = r.text(kMaxChatBytes);
                if (!r.ok) break;
                const u32 seq = firstSeq + i;
                if (seq < peer->chatNext) continue; // 이미 받은 것
                if (seq > peer->chatNext) break;
                ++peer->chatNext;
                peer->chatAckDirty = true;
                if (!text.empty()) relayChat(peer->playerId, displayName(peer->name, peer->playerId), text);
            }
            break;
        }
        case Packet::TickFill: { // 호스트 이전: 옛 호스트가 확정했지만 내가 받지 못한 틱
            if (!peer || state != SessionState::Running || r.get<u8>() != matchByte()) return;
            const u32 first = r.get<u32>();
            const u8 count = r.get<u8>();
            for (u32 i = 0; r.ok && i < count; ++i) {
                TickInputs in{};
                for (u32 player = 0; player < kMaxPlayers; ++player) r.bytes(in.players[player].bytes, kInputBytes);
                in.commandBytes = r.get<u16>();
                if (in.commandBytes > kCommandBytesPerTick) break;
                r.bytes(in.commands, in.commandBytes);
                if (!r.ok) break;
                const u32 t = first + i;
                if (t < finalNext || !inWindow(t)) continue;
                Slot& s = claim(t);
                s.inputs = in; // 옛 호스트가 정한 것이 맞다 (내가 채운 내 입력도 같은 값이다)
                s.mask = ~0u;
                s.complete = true;
            }
            lastTickRequest = -1.0;
            if (finalize()) sendPending = true;
            break;
        }
        case Packet::SnapshotAck: {
            const u32 received = r.get<u32>();
            if (!peer || !r.ok || !peer->snapshot) return;
            const u32 acked = std::min(received, static_cast<u32>(peer->snapshot->size()));
            if (acked > peer->snapshotAcked) {
                peer->snapshotAcked = acked;
                peer->snapshotSent = std::max(peer->snapshotSent, acked);
                peer->snapshotProgress = now;
            }
            break;
        }
        case Packet::Disconnect: {
            if (!peer) return;
            if (state == SessionState::Running) {
                dropPeer(static_cast<size_t>(peer - peers.data()), "left");
            } else {
                MEALKIT_INFO("Player left the lobby (%s)", from.toString().c_str());
                peers.erase(peers.begin() + (peer - peers.data()));
            }
            break;
        }
        default: break;
        }
    }

    // 호스트 → 클라이언트: 승계 목록 (나, 그다음 연결된 클라이언트와 매치 중 끊긴 사람, 슬롯 순). 다 들어가지 않으면 앞쪽만
    void sendSuccession() {
        Writer w;
        header(w, Packet::Succession);
        const u32 countAt = w.size;
        w.put(static_cast<u8>(0));
        u8 count = 0;
        auto entry = [&](u8 player, bool isConnected, u64 token, const std::string& name, const Address& a) {
            if (w.size + 1 + 1 + 8 + 1 + name.size() + 4 + 2 + 8 > kMaxPacket) return;
            w.put(player);
            w.put(static_cast<u8>(isConnected ? 1 : 0));
            w.put(token);
            w.text(name);
            w.put(a.ip);
            w.put(a.port);
            w.put(a.steamId);
            ++count;
        };
        entry(localPlayer, true, localToken, localName, Address{});
        for (const Peer& p : peers) entry(p.playerId, true, p.token, p.name, p.address);
        for (const Departed& d : departed) entry(d.playerId, false, d.token, d.name, Address{});
        w.data[countAt] = count;
        for (const Peer& p : peers) send(p.address, w);
        lastSuccession = now;
    }

    // 새 호스트: 가장 앞선 확정 틱을 가진 피어에게 모자란 틱을 달라고 한다
    void requestTicks() {
        if (migrateHold == 0.0 || now - lastTickRequest < kTickRequestInterval) return;
        const Peer* best = nullptr;
        for (const Peer& p : peers)
            if (p.heard && p.clientFinal > finalNext && (!best || p.clientFinal > best->clientFinal)) best = &p;
        if (!best) return;
        Writer w;
        header(w, Packet::TickRequest);
        w.put(matchByte());
        w.put(finalNext);
        send(best->address, w);
        lastTickRequest = now;
    }

    void hostUpdate() {
        rebuildMembers();
        if (!peers.empty() && now - lastSuccession >= kSuccessionInterval) sendSuccession();
        if (state == SessionState::Lobby) {
            bool sentLobby = false;
            for (size_t i = 0; i < peers.size();) {
                if (now - peers[i].lastRecv > kTimeout) {
                    MEALKIT_INFO("Lobby: %s timed out", peers[i].address.toString().c_str());
                    peers.erase(peers.begin() + static_cast<std::ptrdiff_t>(i));
                    continue;
                }
                if (now - peers[i].lastControlSend >= kLobbyInterval) {
                    sendLobby(peers[i]);
                    peers[i].lastControlSend = now;
                    sentLobby = true;
                }
                ++i;
            }
            if (sentLobby && !members.empty()) memberCursor = (memberCursor + 1) % static_cast<u32>(members.size());
            hostChat();
            return;
        }
        if (state != SessionState::Running) return;
        requestTicks();
        if (holding()) lastFinalize = now; // 기다리는 동안은 멈춤으로 알리지 않는다
        else if (finalize()) sendPending = true;
        adjustDelay();
        playerPing[localPlayer] = 0;
        for (const Peer& p : peers)
            if (p.playerId < kMaxPlayers) playerPing[p.playerId] = static_cast<u32>(p.rttMs + 0.5f);
        waitMask = 0;
        if (now - lastFinalize > kStallReport) { // 확정이 멈췄다: 이 틱의 입력이 오지 않은 플레이어
            const Slot& s = slot(finalNext);
            waitMask = needMask(finalNext) & ~(s.tick == finalNext ? s.mask : 0u);
        }
        for (size_t i = 0; i < peers.size();) {
            if (now - peers[i].lastRecv > kTimeout) dropPeer(i, "timed out");
            else ++i;
        }
        bool logNeeded = false;
        for (Peer& p : peers) {
            if (p.late && !p.started) { // 중간 참가: 스냅샷이 준비되면 시작 패킷과 스냅샷 조각
                if (p.snapshot) {
                    if (now - p.lastControlSend >= kStartResendInterval) {
                        sendStart(p);
                        p.lastControlSend = now;
                    }
                    sendSnapshot(p);
                }
                logNeeded = true;
                continue;
            }
            if (p.catchUp && finalNext - p.bundleNext < kTickWindow / 2) p.catchUp = false; // 이제 링 버퍼에 있다
            logNeeded = logNeeded || p.catchUp;
            if (!p.started && now - p.lastControlSend >= kStartResendInterval) {
                sendStart(p);
                p.lastControlSend = now;
            } else if (p.started && now - p.lastControlSend >= kLobbyInterval) { // 매치 중 명단 (로비 신호 전에 시작한 사람도 이름을 안다)
                sendLobby(p, Packet::Roster);
                p.lastControlSend = now;
            }
            if (sendPending || now - p.lastSend >= kKeepAliveInterval) sendBundle(p);
        }
        trimJoinLog(logNeeded);
        sendPending = false;
        hostChat();
    }

    // 따라잡는 사람이 모두 받은 틱은 버린다. 아무도 없으면 그만 남긴다
    void trimJoinLog(bool needed) {
        if (!needed) {
            joinLog.clear();
            joinLogging = false;
            return;
        }
        u32 low = finalNext;
        for (const Peer& p : peers)
            if ((p.late && !p.started && p.snapshot) || p.catchUp) low = std::min(low, p.bundleNext);
        while (!joinLog.empty() && joinLogBase < low) {
            joinLog.pop_front();
            ++joinLogBase;
        }
    }

    // ---------------- 클라이언트 ----------------

    void sendConnect() {
        Writer w;
        header(w, Packet::ConnectRequest);
        w.put(mySimVersion());
        w.text(determinismGroup());
        w.text(gameVersion);
        w.put(contentHash);
        for (u64 part : contentParts) w.put(part);
        w.put(static_cast<u8>(localLoadout.size()));
        w.bytes(localLoadout.data(), static_cast<u32>(localLoadout.size()));
        w.put(static_cast<u8>(localReady ? kMemberReady : 0));
        w.text(localName);
        w.put(peers[0].hostEcho);
        w.put(localToken);
        send(peers[0].address, w);
    }

    void sendInput() {
        Peer& h = peers[0];
        Writer w;
        header(w, Packet::Input);
        w.put(matchByte());
        w.put(finalNext);
        w.put(toMs(now));
        w.put(latestHashTick);
        w.put(latestHash);
        w.put(h.hostEcho);
        const u32 first = hostInputAckNext;
        u32 count = localSubmittedNext > first ? localSubmittedNext - first : 0;
        count = std::min(count, kMaxTicksPerPacket);
        w.put(first);
        w.put(static_cast<u8>(count));
        for (u32 i = 0; i < count; ++i) w.bytes(localInputs[(first + i) % kTickWindow].bytes, kInputBytes);
        u32 commands = 0, bytes = w.size + 4 + 1;
        while (commands < outCommands.size() && commands < 255 && bytes + 1 + outCommands[commands].size <= kMaxPacket)
            bytes += 1 + outCommands[commands++].size;
        w.put(outCommands.empty() ? nextCommandSeq : outCommands.front().seq);
        w.put(static_cast<u8>(commands));
        for (u32 i = 0; i < commands; ++i) {
            w.put(outCommands[i].size);
            w.bytes(outCommands[i].data, outCommands[i].size);
        }
        send(h.address, w);
        h.lastSend = now;
    }

    // 클라이언트 → 호스트: 확인받지 못한 내 채팅 + 받은 중계 확인
    void clientChat() {
        if ((outChat.empty() && !relayAckDirty) || now - lastChatSend < kChatResendInterval) return;
        Writer w;
        header(w, Packet::Chat);
        w.put(relayExpected);
        w.put(outChat.empty() ? nextChatSeq : outChat.front().seq);
        const u32 countAt = w.size;
        w.put(static_cast<u8>(0));
        u8 count = 0;
        for (const OutChat& c : outChat) {
            if (w.size + 1 + c.text.size() > kMaxPacket) break;
            w.text(c.text);
            ++count;
        }
        w.data[countAt] = count;
        send(peers[0].address, w);
        lastChatSend = now;
        relayAckDirty = false;
    }

    // 호스트가 로비로 돌아갔다 (결과 화면 뒤): 매치를 끝내고 다시 준비를 고른다
    void enterLobbyFromMatch() {
        state = SessionState::Lobby;
        localReady = false;
        if (!peers.empty()) peers[0].lastControlSend = -1.0; // 로비 신호를 바로 보낸다
        MEALKIT_INFO("Back to the lobby (match %u ended)", matchIndex);
    }

    // ---------------- 호스트 이전 ----------------

    // 승계 목록에서 다음 호스트: 지금 호스트를 뺀 첫 연결자
    const Successor* nextHost() const {
        for (const Successor& e : successors)
            if (e.connected && e.player != hostPlayer) return &e;
        return nullptr;
    }

    bool canMigrate() const {
        return !offline && !replay && !late && !catchingUp &&
               (state == SessionState::Lobby || state == SessionState::Running) && nextHost() != nullptr;
    }

    // 호스트가 나갔다·조용하다: 승계 목록의 다음 사람에게 붙거나 내가 호스트가 된다
    void migrate(const char* why) {
        if (!canMigrate()) {
            end("Connection to the host was lost");
            return;
        }
        for (Successor& e : successors)
            if (e.player == hostPlayer) e.connected = false; // 옛 호스트: 끊긴 사람 (같은 토큰으로 다시 들어오면 그 슬롯)
        const Successor next = *nextHost();
        ++migrations;
        MEALKIT_WARN("Host player %u %s - player %u takes over the session (tick %u)", hostPlayer, why, next.player, finalNext);
        const u8 oldHost = hostPlayer;
        hostPlayer = next.player;
        relayStarted = false; // 새 호스트의 중계 번호는 0부터
        if (next.player == localPlayer) {
            becomeHost(oldHost);
            return;
        }
        Peer& h = peers[0];
        h = Peer{};
        h.address = next.address;
        h.lastRecv = now;
        lastBundle = now;
        matchFlowing = false; // 새 호스트가 틱을 보내기 시작할 때까지는 긴 판정
        if (state == SessionState::Running) {
            hostInputAckNext = std::min(hostInputAckNext, finalNext); // 옛 호스트가 받고 확정하지 못한 내 입력은 다시 보낸다
            sendInput();
        } else {
            sendConnect();
        }
    }

    void becomeHost(u8 oldHost) {
        host = true;
        std::vector<Peer> next;
        departed.clear();
        for (const Successor& e : successors) {
            if (e.player == localPlayer) continue;
            if (!e.connected) {
                departed.push_back({e.player, e.token, e.name});
                continue;
            }
            Peer p;
            p.address = e.address;
            p.playerId = e.player;
            p.token = e.token;
            p.name = e.name;
            p.lastRecv = now;
            p.started = state == SessionState::Running;
            p.inputNext = p.bundleNext = finalNext;
            p.commandNext = p.chatNext = kUnknownSeq;
            p.heard = false;
            for (const LobbyMember& member : members)
                if (member.player == e.player) p.loadout = member.loadout;
            next.push_back(std::move(p));
        }
        peers = std::move(next);
        relayLog.clear();
        relayEnd = 0;
        pendingCommands.clear();
        if (state == SessionState::Running) {
            // 앞으로 기다릴 입력: 목록의 연결자와 나. 그 밖(옛 호스트, 목록 뒤에 들어온 사람)은 빈 입력 (다시 들어오면 그 슬롯)
            for (u32 player = 0; player < kMaxPlayers; ++player) requiredFrom[player] = kNoTick;
            requiredFrom[localPlayer] = finalNext;
            for (const Peer& p : peers) requiredFrom[p.playerId] = finalNext;
            width = playerCount;
            for (u32 player = 0; player < kMaxPlayers; ++player)
                if (requiredFrom[player] != kNoTick) width = std::max(width, player + 1);
            // 내가 낸 입력 중 아직 확정되지 않은 것
            for (u32 t = finalNext; t < localSubmittedNext; ++t) {
                Slot& pending = claim(t);
                pending.inputs.players[localPlayer] = localInputs[t % kTickWindow];
                pending.mask |= 1u << localPlayer;
            }
            for (u32 player = 0; player < kMaxPlayers; ++player)
                if (requiredFrom[player] == kNoTick && (connected & (1u << player)))
                    queuePresence(static_cast<u8>(player), false, {});
            joinLog.clear();
            joinLogging = false;
            snapshotWanted = false;
            delayChangePending = false;
            migrateHold = now + kMigrateHold;
            lastTickRequest = -1.0;
            lastFinalize = now;
        }
        rebuildMembers();
        sendSuccession();
        MEALKIT_INFO("This peer is the host now (player %u, %zu client(s), old host %u)", localPlayer, peers.size(), oldHost);
    }

    // 클라이언트 → 새 호스트: 가진 확정 틱 (from부터, 패킷에 들어가는 만큼)
    void sendTickFill(u32 from) {
        if (from >= finalNext) return;
        Writer w;
        header(w, Packet::TickFill);
        w.put(matchByte());
        w.put(from);
        const u32 countAt = w.size;
        w.put(static_cast<u8>(0));
        u8 count = 0;
        for (u32 t = from; t < finalNext && count < kMaxTicksPerPacket; ++t) {
            const Slot& s = slot(t);
            if (s.tick != t || !s.complete) break;
            if (w.size + kMaxPlayers * kInputBytes + 2 + s.inputs.commandBytes > kMaxPacket) break;
            for (u32 player = 0; player < kMaxPlayers; ++player) w.bytes(s.inputs.players[player].bytes, kInputBytes);
            w.put(s.inputs.commandBytes);
            w.bytes(s.inputs.commands, s.inputs.commandBytes);
            ++count;
        }
        w.data[countAt] = count;
        send(peers[0].address, w);
    }

    void clientReceive(const Address& from, Reader& r, Packet type) {
        if (!(from == peers[0].address)) {
            // 승계자가 먼저 호스트가 되어 보낸다 (Handoff를 놓쳤다): 바로 넘어간다
            const Successor* next = nextHost();
            const bool fromHost = type == Packet::Bundle || type == Packet::Succession || type == Packet::TickRequest ||
                                  type == Packet::Lobby || type == Packet::Roster;
            if (!fromHost || !next || next->player == localPlayer || !(next->address == from) || !canMigrate()) return;
            migrate("was replaced");
            if (host || !(from == peers[0].address)) return;
        }
        Peer& h = peers[0];
        h.lastRecv = now;

        switch (type) {
        case Packet::ConnectAccept: {
            const u8 id = r.get<u8>();
            const u8 maxP = r.get<u8>();
            const u8 inMatch = r.get<u8>();
            if (!r.ok) return;
            if (state == SessionState::Connecting && inMatch) { // 매치 중: 스냅샷을 받을 때까지 접속 중으로 남는다
                if (!late) MEALKIT_INFO("Connected to %s - the match is running, waiting for its snapshot", from.toString().c_str());
                late = true;
                localPlayer = id;
                maxPlayers = maxP;
                break;
            }
            if (state == SessionState::Connecting) {
                state = SessionState::Lobby;
                MEALKIT_INFO("Connected to %s - waiting for the host to start", from.toString().c_str());
            }
            if (state == SessionState::Lobby) localPlayer = id;
            maxPlayers = maxP;
            break;
        }
        case Packet::ConnectReject: {
            rejectInfo.reason = static_cast<Reject>(r.get<u8>());
            rejectInfo.contentMask = r.get<u32>();
            rejectInfo.hostVersion = r.text(64);
            rejectInfo.hostGroup = r.text(32);
            std::string reason = rejectText(rejectInfo.reason);
            if (rejectInfo.reason == Reject::Version) reason += " (yours " + gameVersion + ", host " + rejectInfo.hostVersion + ")";
            if (rejectInfo.reason == Reject::Platform) reason += " (yours " + std::string(determinismGroup()) + ", host " + rejectInfo.hostGroup + ")";
            end(reason.c_str());
            break;
        }
        case Packet::Lobby:
        case Packet::Roster: {
            const u8 count = r.get<u8>();
            const u8 maxP = r.get<u8>();
            const u32 hostMatch = r.get<u32>();
            const u32 hostTime = r.get<u32>();
            const u8 entries = r.get<u8>();
            if (!r.ok) return;
            h.hostEcho = hostTime;
            if (type == Packet::Roster) { // 매치 중 명단: 이 매치의 것만
                if (state != SessionState::Running || hostMatch != matchIndex) return;
            } else {
                if (state == SessionState::Running) {
                    if (hostMatch < matchIndex) return; // 매치 시작 전에 보낸 늦은 신호
                    enterLobbyFromMatch();
                }
                if (state != SessionState::Lobby) return;
                matchIndex = std::max(matchIndex, hostMatch);
            }
            lobbyCount = count;
            maxPlayers = maxP;
            for (u32 i = 0; i < entries; ++i) {
                LobbyMember entry;
                entry.player = r.get<u8>();
                entry.pingMs = r.get<u16>();
                const u8 flags = r.get<u8>();
                entry.name = r.text(kMaxNameBytes);
                const u8 size = r.get<u8>();
                entry.loadout.resize(std::min<u32>(size, kMaxLoadoutBytes));
                r.bytes(entry.loadout.data(), static_cast<u32>(entry.loadout.size()));
                if (!r.ok) break;
                entry.ready = (flags & kMemberReady) != 0;
                entry.host = (flags & kMemberHost) != 0;
                size_t at = 0;
                while (at < members.size() && members[at].player != entry.player) ++at;
                if (at == members.size()) {
                    members.push_back({});
                    memberSeen.push_back(0.0);
                }
                members[at] = std::move(entry);
                memberSeen[at] = now;
            }
            // 나간 사람: 로비 신호 몇 번 동안 다시 오지 않은 사람을 지운다 (신호마다 일부만 실릴 수 있다)
            for (size_t i = 0; i < members.size();) {
                if (now - memberSeen[i] > kLobbyInterval * 4.0) {
                    members.erase(members.begin() + static_cast<std::ptrdiff_t>(i));
                    memberSeen.erase(memberSeen.begin() + static_cast<std::ptrdiff_t>(i));
                } else {
                    ++i;
                }
            }
            for (size_t i = 1; i < members.size(); ++i) // 플레이어 번호 순 (삽입 정렬, 같이 옮긴다)
                for (size_t j = i; j > 0 && members[j - 1].player > members[j].player; --j) {
                    std::swap(members[j - 1], members[j]);
                    std::swap(memberSeen[j - 1], memberSeen[j]);
                }
            break;
        }
        case Packet::Start: {
            const u8 id = r.get<u8>();
            const u8 count = r.get<u8>();
            const u8 delay = r.get<u8>();
            const u64 matchSeed = r.get<u64>();
            const u32 data = r.get<u32>();
            const u32 index = r.get<u32>();
            if (!r.ok || state == SessionState::Running || state == SessionState::Ended) return;
            if (index <= matchIndex && matchIndex != 0) return; // 지난 매치의 늦은 시작 패킷
            if (count == 0 || count > kMaxPlayers || id >= kMaxPlayers || delay == 0) return;
            std::vector<u8> startLoadouts[kMaxPlayers];
            for (u32 i = 0; i < count; ++i) {
                const u8 size = r.get<u8>();
                startLoadouts[i].resize(std::min<u32>(size, kMaxLoadoutBytes));
                r.bytes(startLoadouts[i].data(), static_cast<u32>(startLoadouts[i].size()));
            }
            const u8 lateStart = r.get<u8>();
            if (!r.ok || (!lateStart && id >= count)) return;
            for (u32 i = 0; i < kMaxPlayers; ++i) loadouts[i] = std::move(startLoadouts[i]);
            if (lateStart) { // 중간 참가: 스냅샷 조각을 기다린다 (다 받으면 startLate)
                const u32 snapshotTick = r.get<u32>();
                const u32 raw = r.get<u32>();
                const u32 compressed = r.get<u32>();
                const u32 connectedAt = r.get<u32>();
                if (!r.ok || state != SessionState::Connecting || joinCompressed != 0 || compressed == 0) return;
                localPlayer = id;
                playerCount = count;
                inputDelay = delay;
                seed = matchSeed;
                matchData = data;
                matchIndex = index;
                joinTick = snapshotTick;
                joinRaw = raw;
                joinCompressed = compressed;
                joinBuffer.assign(compressed, 0);
                joinChunks.assign((compressed + kSnapshotChunk - 1) / kSnapshotChunk, false);
                joinPrefix = 0;
                connected = connectedAt;
                MEALKIT_INFO("Joining the running match at tick %u: snapshot %u bytes (%u compressed)", snapshotTick, raw,
                             compressed);
                break;
            }
            localPlayer = id;
            playerCount = count;
            inputDelay = delay;
            seed = matchSeed;
            matchData = data;
            matchIndex = index;
            for (size_t i = 0; i < members.size(); ++i) members[i].player = static_cast<u8>(i); // 호스트처럼 빈 번호 없이
            beginRunning();
            MEALKIT_INFO("Match started: player %u of %u, input delay %u ticks", id, count, delay);
            sendInput(); // 시작 확인
            break;
        }
        case Packet::Bundle: {
            if (state != SessionState::Running) return;
            if (r.get<u8>() != matchByte()) return; // 지난 매치의 늦은 패킷
            const u32 inputAckNext = r.get<u32>();
            const u32 echo = r.get<u32>();
            const u8 flags = r.get<u8>();
            const u32 hostDesyncTick = r.get<u32>();
            const u32 commandAck = r.get<u32>();
            const u32 hostTime = r.get<u32>();
            const u8 hostWait = r.get<u8>();
            const u8 players = r.get<u8>(); // 호스트가 싣는 플레이어 수 (중간 참가로 늘 수 있다)
            if (!r.ok || players == 0 || players > kMaxPlayers) return;
            u32 pings[kMaxPlayers] = {};
            for (u32 player = 0; player < players; ++player) pings[player] = r.get<u16>();
            const u32 first = r.get<u32>();
            const u8 count = r.get<u8>();
            if (!r.ok) return;
            h.hostEcho = hostTime;
            waitMask = hostWait;
            lastBundle = now;
            if (count > 0) matchFlowing = true;
            for (u32 player = 0; player < players; ++player) playerPing[player] = pings[player];

            hostInputAckNext = std::max(hostInputAckNext, std::min(inputAckNext, localSubmittedNext));
            while (!outCommands.empty() && outCommands.front().seq < commandAck) outCommands.pop_front();
            if (echo) {
                const f32 sample = static_cast<f32>(toMs(now) - echo);
                stats.rttMs = stats.rttMs == 0.0f ? sample : stats.rttMs * 0.9f + sample * 0.1f;
            }
            if ((flags & 1) && !desynced) {
                desynced = true;
                desyncTick = hostDesyncTick;
                MEALKIT_ERROR("DESYNC reported by host at tick %u", hostDesyncTick);
            }
            for (u32 i = 0; i < count; ++i) {
                TickInputs in{};
                for (u32 player = 0; player < players; ++player) r.bytes(in.players[player].bytes, kInputBytes);
                in.commandBytes = r.get<u16>();
                if (in.commandBytes > kCommandBytesPerTick) break;
                r.bytes(in.commands, in.commandBytes);
                if (!r.ok) break;
                const u32 t = first + i;
                if (t < finalNext || !inWindow(t)) continue;
                Slot& s = claim(t);
                if (!s.complete) {
                    s.inputs = in;
                    s.mask = allMask();
                    s.complete = true;
                }
            }
            finalize();
            break;
        }
        case Packet::ChatRelay: {
            const u32 chatAck = r.get<u32>();
            const u32 first = r.get<u32>();
            const u8 count = r.get<u8>();
            if (!r.ok) return;
            while (!outChat.empty() && outChat.front().seq < chatAck) outChat.pop_front();
            if (!relayStarted) { // 처음 받은 묶음부터 (들어오기 전의 채팅은 없다)
                relayStarted = true;
                relayExpected = first;
            }
            for (u32 i = 0; i < count; ++i) {
                const u8 player = r.get<u8>();
                const std::string name = r.text(kMaxNameBytes);
                const std::string text = r.text(kMaxChatBytes);
                if (!r.ok) break;
                const u32 index = first + i;
                if (index < relayExpected) continue;
                if (index > relayExpected) break; // 빠진 것이 있다: 다시 올 때까지 기다린다
                ++relayExpected;
                addChat(player, name, text);
            }
            relayAckDirty = true;
            break;
        }
        case Packet::Snapshot: {
            const u8 match = r.get<u8>();
            const u32 offset = r.get<u32>();
            const u16 size = r.get<u16>();
            if (!r.ok || state != SessionState::Connecting || joinCompressed == 0 || match != matchByte()) return;
            const u32 chunk = offset / kSnapshotChunk; // 순서가 바뀌어 와도 받아 둔다 (빠진 것은 호스트가 다시 보낸다)
            if (offset % kSnapshotChunk != 0 || chunk >= joinChunks.size() ||
                size != std::min(kSnapshotChunk, joinCompressed - offset))
                return;
            if (!joinChunks[chunk]) {
                r.bytes(joinBuffer.data() + offset, size);
                if (!r.ok) return;
                joinChunks[chunk] = true;
                while (joinPrefix < joinCompressed && joinChunks[joinPrefix / kSnapshotChunk])
                    joinPrefix = std::min(joinPrefix + kSnapshotChunk, joinCompressed);
            }
            Writer w;
            header(w, Packet::SnapshotAck);
            w.put(joinPrefix);
            send(h.address, w);
            if (joinPrefix == joinCompressed) startLate();
            break;
        }
        case Packet::Disconnect: end("Host closed the session"); break;
        case Packet::Handoff: migrate("left"); break;
        case Packet::Succession: {
            const u8 count = r.get<u8>();
            std::vector<Successor> list;
            for (u32 i = 0; r.ok && i < count; ++i) {
                Successor e;
                e.player = r.get<u8>();
                e.connected = r.get<u8>() != 0;
                e.token = r.get<u64>();
                e.name = r.text(kMaxNameBytes);
                e.address.ip = r.get<u32>();
                e.address.port = r.get<u16>();
                e.address.steamId = r.get<u64>();
                if (r.ok) list.push_back(std::move(e));
            }
            if (!r.ok || list.empty()) return;
            hostPlayer = list[0].player; // 호스트 자신이 먼저
            list[0].address = h.address;
            successors = std::move(list);
            break;
        }
        case Packet::TickRequest: {
            if (state != SessionState::Running || r.get<u8>() != matchByte()) return;
            const u32 fromTick = r.get<u32>();
            if (r.ok) sendTickFill(fromTick);
            break;
        }
        default: break;
        }
    }

    // 스냅샷을 다 받았다: 그 틱부터 확정된 입력을 받아 따라잡는다 (게임은 takeJoinSnapshot으로 월드를 불러온다)
    void startLate() {
        if (!decompressBytes(joinBuffer.data(), static_cast<u32>(joinBuffer.size()), joinRaw, joinSnapshot)) {
            end("The match snapshot from the host was damaged");
            return;
        }
        joinBuffer = {};
        joinChunks = {};
        const u32 connectedAt = connected;
        const u32 count = playerCount;
        beginRunning();
        for (Slot& s : slots) s = Slot{};
        connected = connectedAt;
        playerCount = count;
        finalNext = executedNext = joinTick;
        localSubmittedNext = hostInputAckNext = joinTick;
        catchingUp = true;
        MEALKIT_INFO("Match snapshot received: catching up from tick %u as player %u", joinTick, localPlayer);
        sendInput(); // 시작 확인 (호스트가 묶음을 보내기 시작한다)
    }

    void clientUpdate() {
        Peer& h = peers[0];
        if (h.lastRecv < 0.0) h.lastRecv = now;
        if (lastUpdate >= 0.0 && now - lastUpdate > kUpdateGap) { // 내가 멈춰 있었다 (로딩): 그동안은 호스트 침묵으로 세지 않는다
            h.lastRecv += now - lastUpdate;
            lastBundle += now - lastUpdate;
        }
        lastUpdate = now;
        if (state == SessionState::Connecting) {
            if (now - h.lastControlSend >= kConnectInterval) {
                sendConnect();
                h.lastControlSend = now;
            }
            if (now - h.lastRecv > kTimeout) end("Could not reach the host");
            return;
        }
        // 호스트가 조용하다: 매치가 흐르는 중이면 짧게, 로비·로딩(호스트가 몇 초 멈출 수 있다)은 길게. 승계 목록의 다음 사람에게 넘어간다
        const f64 lost = state == SessionState::Running && matchFlowing ? kHostLost : kTimeout;
        if (now - h.lastRecv > lost) {
            migrate("timed out");
            if (host || state == SessionState::Ended) return;
        }
        if (state == SessionState::Lobby) {
            if (now - h.lastControlSend >= 1.0) { // 로비 유지 신호 (로드아웃·이름·준비)
                sendConnect();
                h.lastControlSend = now;
            }
            clientChat();
            return;
        }
        if (state == SessionState::Running && now - lastBundle > kHostSilence) waitMask |= 1u << hostPlayer; // 호스트에게서 아무것도 오지 않는다
        if (state == SessionState::Running && (sendPending || now - h.lastSend >= kKeepAliveInterval)) {
            sendInput();
            sendPending = false;
        }
        clientChat();
    }
};

namespace {
u64 newToken() {
    std::random_device device;
    const u64 token = (static_cast<u64>(device()) << 32) ^ device();
    return token ? token : 1;
}
} // namespace

LockstepSession::LockstepSession() : m(new Impl()) { m->localToken = newToken(); }

LockstepSession::~LockstepSession() {
    shutdown();
    delete m;
}

void LockstepSession::setContentHash(u64 hash) { m->contentHash = hash; }
void LockstepSession::setContentParts(const u64* parts) {
    for (u32 i = 0; i < static_cast<u32>(ContentPart::Count); ++i) m->contentParts[i] = parts[i];
}
void LockstepSession::setBuild(u64 simVersion, const std::string& gameVersion) {
    m->simVersion = simVersion;
    m->gameVersion = gameVersion;
}
const RejectInfo& LockstepSession::rejectInfo() const { return m->rejectInfo; }
u64 LockstepSession::contentHash() const { return m->contentHash; }
void LockstepSession::setAcceptOtherBuilds(bool accept) { m->acceptOtherBuilds = accept; }
void LockstepSession::setConditions(const NetConditions& conditions) { m->conditions = conditions; }
void LockstepSession::setAutoDelay(const AutoDelay& autoDelay) { m->autoDelay = autoDelay; }
bool LockstepSession::requestInputDelay(u32 ticks) { return m->queueDelay(ticks); }

u32 delayForRtt(f32 rttMs, const AutoDelay& a) {
    const f32 tickMs = a.tickMs > 0.0f ? a.tickMs : 1000.0f / 30.0f;
    const f32 needMs = rttMs * 1.25f + tickMs; // 왕복(호스트를 거친 가장 먼 길) + 흔들림 여유 + 처리 한 틱
    const u32 ticks = static_cast<u32>(std::ceil(needMs / tickMs));
    return std::clamp(ticks, std::max(1u, a.minTicks), std::max(a.minTicks, a.maxTicks));
}

bool LockstepSession::openOffline() {
    if (m->state != SessionState::Idle) return false;
    m->offline = true;
    m->host = true;
    m->maxPlayers = 1;
    m->playerCount = 1;
    m->localPlayer = 0;
    m->inputDelay = 1;
    m->state = SessionState::Lobby;
    m->rebuildMembers();
    return true;
}

bool LockstepSession::startOffline(u64 seed, u32 matchData) {
    if (!openOffline()) return false;
    startMatch(seed, matchData);
    return true;
}

bool LockstepSession::startReplay(u64 seed, u32 matchData, const std::vector<std::vector<u8>>& loadouts,
                                  std::vector<TickInputs> inputs, std::vector<u64> hashes) {
    if (m->state != SessionState::Idle) return false;
    const u32 players = std::clamp(static_cast<u32>(loadouts.size()), 1u, kMaxPlayers);
    m->offline = true;
    m->host = true;
    m->replay = true;
    m->maxPlayers = m->playerCount = players;
    m->localPlayer = 0;
    m->inputDelay = 1;
    m->seed = seed;
    m->matchData = matchData;
    for (std::vector<u8>& l : m->loadouts) l.clear();
    for (u32 i = 0; i < players && i < loadouts.size(); ++i)
        m->loadouts[i].assign(loadouts[i].begin(),
                              loadouts[i].begin() + std::min<size_t>(loadouts[i].size(), kMaxLoadoutBytes));
    m->replayInputs = std::move(inputs);
    m->replayHashes = std::move(hashes);
    m->rebuildMembers();
    ++m->matchIndex;
    m->beginRunning();
    MEALKIT_INFO("Replaying a match: %u tick(s), %u player(s), seed %016llx", static_cast<u32>(m->replayInputs.size()),
                 players, static_cast<unsigned long long>(seed));
    return true;
}

bool LockstepSession::isReplay() const { return m->replay; }
u32 LockstepSession::replayTicks() const { return m->replay ? static_cast<u32>(m->replayInputs.size()) : 0; }

bool LockstepSession::host(u16 port, u32 maxPlayers, u32 inputDelay, bool loopbackOnly) {
    if (m->state != SessionState::Idle) return false;
    if (!startup()) return false;
    m->netStarted = true;
    auto udp = std::make_unique<UdpTransport>();
    if (!udp->open(port, loopbackOnly)) return false;
    MEALKIT_INFO("Hosting on UDP port %u", udp->localPort());
    return hostWith(std::move(udp), maxPlayers, inputDelay);
}

bool LockstepSession::join(const Address& hostAddress) {
    if (m->state != SessionState::Idle) return false;
    if (!startup()) return false;
    m->netStarted = true;
    auto udp = std::make_unique<UdpTransport>();
    if (!udp->open(0, hostAddress.ip == kLoopbackIp)) return false;
    return joinWith(std::move(udp), hostAddress);
}

bool LockstepSession::hostWith(std::unique_ptr<Transport> transport, u32 maxPlayers, u32 inputDelay) {
    if (m->state != SessionState::Idle || !transport) return false;
    m->transport = withConditions(std::move(transport), m->conditions);
    m->host = true;
    m->maxPlayers = std::clamp(maxPlayers, 1u, kMaxPlayers);
    m->inputDelay = std::clamp(inputDelay, 1u, 30u);
    m->playerCount = 1;
    m->localPlayer = 0;
    m->state = SessionState::Lobby;
    m->rebuildMembers();
    MEALKIT_INFO("Session open: max %u players, input delay %u ticks", m->maxPlayers, m->inputDelay);
    return true;
}

bool LockstepSession::joinWith(std::unique_ptr<Transport> transport, const Address& hostAddress) {
    if (m->state != SessionState::Idle || !transport) return false;
    m->transport = withConditions(std::move(transport), m->conditions);
    m->host = false;
    m->peers.assign(1, Peer{});
    m->peers[0].address = hostAddress;
    m->state = SessionState::Connecting;
    MEALKIT_INFO("Connecting to %s ...", hostAddress.toString().c_str());
    return true;
}

bool LockstepSession::setLocalLoadout(const void* data, u32 size) {
    if (size > kMaxLoadoutBytes || m->state == SessionState::Running || m->state == SessionState::Ended) return false;
    const u8* bytes = static_cast<const u8*>(data);
    const std::vector<u8> next(bytes, bytes + size);
    if (next == m->localLoadout) return true;
    m->localLoadout = next;
    if (!m->host && !m->peers.empty()) m->peers[0].lastControlSend = -1.0; // 로비에 있으면 바로 다시 보낸다
    return true;
}

const std::vector<u8>& LockstepSession::loadout(u32 player) const {
    static const std::vector<u8> none;
    return player < kMaxPlayers ? m->loadouts[player] : none;
}

void LockstepSession::setLocalName(const std::string& name) {
    const std::string clamped = clampUtf8(name, kMaxNameBytes);
    if (clamped == m->localName) return;
    m->localName = clamped;
    if (!m->host && !m->peers.empty()) m->peers[0].lastControlSend = -1.0;
}

const std::string& LockstepSession::localName() const { return m->localName; }

void LockstepSession::setLocalReady(bool ready) {
    if (ready == m->localReady) return;
    m->localReady = ready;
    if (!m->host && !m->peers.empty()) m->peers[0].lastControlSend = -1.0;
}

bool LockstepSession::localReady() const { return m->localReady; }
const std::vector<LobbyMember>& LockstepSession::lobbyMembers() const { return m->members; }

void LockstepSession::startMatch(u64 seed, u32 matchData) {
    if (!m->host || m->state != SessionState::Lobby) return;
    m->localPlayer = m->hostPlayer = 0; // 이어받은 호스트도 새 매치에서는 0번
    m->rebuildMembers(); // 시작할 때의 목록 (매치 중에 보인다)
    m->playerCount = 1 + static_cast<u32>(m->peers.size());
    for (std::vector<u8>& l : m->loadouts) l.clear();
    m->loadouts[0] = m->localLoadout;
    // 빈 번호 없이 다시 매긴다 (로비에서 나간 사람이 있으면 번호가 비어 있다)
    for (size_t i = 0; i < m->peers.size(); ++i) m->loadouts[i + 1] = m->peers[i].loadout;
    for (size_t i = 0; i < m->members.size(); ++i) m->members[i].player = static_cast<u8>(i);
    m->seed = seed;
    m->matchData = matchData;
    if (m->autoDelay.enabled && !m->offline) { // 로비에서 잰 왕복 시간으로
        m->inputDelay = m->desiredDelay();
        MEALKIT_INFO("Input delay %u ticks (automatic, worst round trip %.0f ms)", m->inputDelay,
                     m->peers.empty() ? 0.0 : static_cast<f64>(std::max_element(m->peers.begin(), m->peers.end(), [](const Peer& a, const Peer& b) {
                                                   return a.rttMs < b.rttMs;
                                               })->rttMs));
    }
    ++m->matchIndex;
    for (size_t i = 0; i < m->peers.size(); ++i) {
        Peer& p = m->peers[i];
        p.playerId = static_cast<u8>(i + 1);
        p.started = false;
        p.lastControlSend = -1.0;
        p.inputNext = m->inputDelay;
        p.bundleNext = m->inputDelay;
        p.echoTime = 0;
        p.commandNext = 0;
        p.late = p.catchUp = false;
        p.snapshot.reset();
        for (HashEntry& e : p.reported) e = HashEntry{};
    }
    m->beginRunning();
    MEALKIT_INFO("Match %u started with %u player(s), seed %016llx", m->matchIndex, m->playerCount,
                 static_cast<unsigned long long>(seed));
}

void LockstepSession::returnToLobby() {
    if (!m->host || m->state != SessionState::Running) return;
    m->state = SessionState::Lobby;
    m->localReady = false;
    for (Peer& p : m->peers) {
        p.ready = false;
        p.started = false;
        p.lastControlSend = -1.0; // 로비 신호를 바로 보낸다 (클라이언트는 이것을 받고 로비로)
    }
    m->rebuildMembers();
    MEALKIT_INFO("Back to the lobby after match %u", m->matchIndex);
}

u32 LockstepSession::matchIndex() const { return m->matchIndex; }

void LockstepSession::update(f64 now) {
    MEALKIT_ZONE("Network");
    m->now = now;
    if (m->offline) {
        m->rebuildMembers();
        return;
    }
    if (m->state == SessionState::Idle || m->state == SessionState::Ended) return;

    u8 buffer[1500];
    Address from;
    i32 received;
    while (m->transport && (received = m->transport->receive(from, buffer, sizeof(buffer))) >= 0) {
        m->recvBytes += static_cast<u64>(received);
        Reader r(buffer, static_cast<u32>(received));
        if (r.get<u32>() != kMagic || !r.ok) continue;
        const Packet type = static_cast<Packet>(r.get<u8>());
        if (m->host) m->hostReceive(from, r, type);
        else m->clientReceive(from, r, type);
        if (m->state == SessionState::Ended) return;
    }

    if (m->host) m->hostUpdate();
    else m->clientUpdate();

    const f64 window = now - m->statsWindowStart;
    if (window >= 1.0) {
        m->stats.sentBytesPerSec = static_cast<u32>(static_cast<f64>(m->sentBytes) / window);
        m->stats.recvBytesPerSec = static_cast<u32>(static_cast<f64>(m->recvBytes) / window);
        m->sentBytes = m->recvBytes = 0;
        m->statsWindowStart = now;
    }
}

void LockstepSession::shutdown() {
    if (m->state == SessionState::Connecting || m->state == SessionState::Lobby || m->state == SessionState::Running) {
        // 호스트가 나간다: 남은 사람은 승계 목록대로 이어 간다 (호스트 이전). 끝내는 것은 end()의 Disconnect
        const bool handoff = m->host && !m->offline && !m->peers.empty() && m->state != SessionState::Connecting;
        if (handoff) m->sendSuccession(); // 마지막 목록 (Handoff보다 먼저 닿게)
        Writer w;
        header(w, handoff ? Packet::Handoff : Packet::Disconnect);
        for (const Peer& p : m->peers) {
            m->send(p.address, w);
            m->send(p.address, w);
        }
        m->state = SessionState::Ended;
        m->endReason = "Session closed";
    }
    m->transport.reset();
    if (m->netStarted) {
        cleanup();
        m->netStarted = false;
    }
}

void LockstepSession::reset() {
    shutdown();
    Impl* fresh = new Impl();
    fresh->contentHash = m->contentHash;
    fresh->acceptOtherBuilds = m->acceptOtherBuilds;
    fresh->conditions = m->conditions;
    std::copy(std::begin(m->contentParts), std::end(m->contentParts), std::begin(fresh->contentParts));
    fresh->simVersion = m->simVersion;
    fresh->gameVersion = m->gameVersion;
    fresh->autoDelay = m->autoDelay;
    fresh->localName = m->localName;
    fresh->localLoadout = m->localLoadout;
    fresh->localToken = m->localToken; // 같은 사람: 다시 들어가면 예전 슬롯
    delete m;
    m = fresh;
}

SessionState LockstepSession::state() const { return m->state; }
const char* LockstepSession::endReason() const { return m->endReason.c_str(); }
bool LockstepSession::isHost() const { return m->host; }
bool LockstepSession::isOffline() const { return m->offline; }
u8 LockstepSession::localPlayer() const { return m->localPlayer; }
u32 LockstepSession::playerCount() const { return m->playerCount; }
u32 LockstepSession::lobbyPlayerCount() const {
    return m->host ? 1 + static_cast<u32>(m->peers.size()) : m->lobbyCount;
}
u32 LockstepSession::maxPlayers() const { return m->maxPlayers; }
u64 LockstepSession::seed() const { return m->seed; }
u32 LockstepSession::matchData() const { return m->matchData; }
u32 LockstepSession::inputDelay() const { return m->inputDelay; }

bool LockstepSession::canExecute(u32 tick) const {
    if (m->replay) return m->state == SessionState::Running && tick < m->replayInputs.size();
    const Slot& s = m->slot(tick);
    return m->state == SessionState::Running && s.tick == tick && s.complete;
}

const TickInputs& LockstepSession::inputs(u32 tick) const {
    if (m->replay) return m->replayInputs[tick];
    return m->slot(tick).inputs;
}

void LockstepSession::tickExecuted(u32 tick, u64 stateHash) {
    m->executedNext = tick + 1;
    if (m->replay) {
        m->latestHashTick = tick;
        m->latestHash = stateHash;
        if (tick < m->replayHashes.size() && m->replayHashes[tick] != stateHash && !m->desynced) {
            m->desynced = true;
            m->desyncTick = tick;
            MEALKIT_ERROR("Replay diverged at tick %u: state hash %016llx, recorded %016llx (different build or data?)",
                          tick, static_cast<unsigned long long>(stateHash),
                          static_cast<unsigned long long>(m->replayHashes[tick]));
        }
        return;
    }
    forEachCommand(m->slot(tick).inputs, [&](u8 player, const u8* data, u32 size) { // 엔진 명령: 입력 지연 변경, 접속·끊김
        u32 type = 0;
        if (size >= 5) std::memcpy(&type, data, 4);
        if (size == 5 && type == kDelayCommandType) m->applyDelay(tick, data[4]);
        if (size >= 5 && type == kPresenceCommandType) m->applyPresence(player, data[4] != 0, data + 5, size - 5);
    });
    if (m->catchingUp && tick + 1 + kCaughtUpTicks >= m->finalNext) { // 따라잡았다: 다음 내 입력부터 보낸다
        m->catchingUp = false;
        m->localSubmittedNext = m->hostInputAckNext = tick + m->inputDelay;
        MEALKIT_INFO("Caught up with the match at tick %u", tick);
    }
    m->hashes[tick % kTickWindow] = {tick, stateHash};
    m->latestHashTick = tick;
    m->latestHash = stateHash;
    if (m->host) {
        for (const Peer& p : m->peers) {
            const HashEntry& e = p.reported[tick % kTickWindow];
            if (e.tick == tick && e.hash != stateHash) m->flagDesync(tick, p.playerId, stateHash, e.hash);
        }
    }
}

void LockstepSession::submitLocalInput(u32 tick, const PlayerInput& input) {
    if (m->state != SessionState::Running || m->replay || m->catchingUp) return;
    m->lastLocalInput = input;
    if (m->host) {
        if (tick < m->finalNext) return; // 지연이 줄어 이미 낸 틱 (확정된 것은 바꾸지 않는다)
        Slot& s = m->claim(tick);
        if (s.mask & (1u << m->localPlayer)) return;
        s.inputs.players[m->localPlayer] = input;
        s.mask |= 1u << m->localPlayer;
        if (m->finalize() && !m->offline) {
            for (Peer& p : m->peers) m->sendBundle(p); // 확정되면 바로 배포 (지연 최소화)
        }
    } else {
        if (tick < m->localSubmittedNext) return; // 지연이 줄어 이미 낸 틱
        m->localInputs[tick % kTickWindow] = input;
        m->localSubmittedNext = std::max(m->localSubmittedNext, tick + 1);
        m->sendInput();
    }
}

u32 LockstepSession::connectedMask() const { return m->connected; }

u32 LockstepSession::hostMigrations() const { return m->migrations; }

Address LockstepSession::hostAddress() const { return m->host || m->peers.empty() ? Address{} : m->peers[0].address; }

Address LockstepSession::successorAddress() const {
    // 플레이어 번호 순의 첫 클라이언트 (승계 목록의 다음 사람)
    return !m->host || m->peers.empty() ? Address{} : m->peers[0].address;
}

bool LockstepSession::snapshotWanted() const { return m->host && m->state == SessionState::Running && m->snapshotWanted; }

void LockstepSession::provideSnapshot(u32 tick, const std::vector<u8>& bytes) {
    if (!snapshotWanted() || tick != m->executedNext || tick > m->finalNext) return;
    m->snapshotWanted = false;
    auto compressed = std::make_shared<const std::vector<u8>>(compressBytes(bytes.data(), static_cast<u32>(bytes.size())));
    if (compressed->empty()) {
        MEALKIT_ERROR("Could not compress the join snapshot");
        return;
    }
    // 따라잡을 확정 틱: 스냅샷 틱부터 (링 버퍼에 아직 있다)
    if (!m->joinLogging || tick < m->joinLogBase) {
        m->joinLog.clear();
        m->joinLogBase = tick;
        for (u32 t = tick; t < m->finalNext; ++t) m->joinLog.push_back(m->slot(t).inputs);
        m->joinLogging = true;
    }
    for (Peer& p : m->peers) {
        if (!p.late || p.started || p.snapshot) continue;
        p.snapshot = compressed;
        p.snapshotTick = tick;
        p.snapshotRaw = static_cast<u32>(bytes.size());
        p.snapshotCount = m->playerCount;
        p.snapshotConnected = m->connected;
        p.snapshotAcked = p.snapshotSent = 0;
        p.snapshotProgress = m->now;
        p.bundleNext = tick;
        p.inputNext = 0;
        p.commandNext = 0;
        p.echoTime = 0;
        p.catchUp = true;
        p.lastControlSend = -1.0;
        for (HashEntry& e : p.reported) e = HashEntry{};
    }
    MEALKIT_INFO("Join snapshot at tick %u: %zu bytes, %zu compressed", tick, bytes.size(), compressed->size());
}

u32 LockstepSession::joinTick() const { return m->joinTick; }

bool LockstepSession::takeJoinSnapshot(std::vector<u8>& out) {
    if (m->joinSnapshot.empty()) return false;
    out = std::move(m->joinSnapshot);
    m->joinSnapshot = {};
    return true;
}

bool LockstepSession::catchingUp() const { return m->catchingUp; }

bool LockstepSession::submitCommand(const void* data, u32 size) {
    if (m->state != SessionState::Running || m->replay || size == 0 || size > kMaxCommandBytes) return false;
    Command c;
    c.size = static_cast<u8>(size);
    std::memcpy(c.data, data, size);
    if (m->host) {
        if (m->pendingCommands.size() >= kMaxPendingCommands) return false;
        c.player = m->localPlayer;
        m->pendingCommands.push_back(c);
    } else {
        if (m->outCommands.size() >= kMaxOutCommands) return false;
        c.seq = m->nextCommandSeq++;
        m->outCommands.push_back(c);
        m->sendPending = true;
    }
    return true;
}

bool LockstepSession::sendChat(const std::string& text) {
    if (m->state != SessionState::Lobby && m->state != SessionState::Running) return false;
    const std::string line = clampUtf8(text, kMaxChatBytes);
    if (line.empty() || m->now - m->lastLocalChat < kChatInterval) return false;
    m->lastLocalChat = m->now;
    const std::string name = m->displayName(m->localName, m->localPlayer);
    if (m->host) { // 혼자 플레이도 여기 (자기 로그에만)
        m->relayChat(m->localPlayer, name, line);
        return true;
    }
    if (m->outChat.size() >= kMaxOutChat) return false;
    m->outChat.push_back({m->nextChatSeq++, line});
    m->lastChatSend = -1.0; // 바로 보낸다
    return true;
}

const std::vector<ChatMessage>& LockstepSession::chatLog() const { return m->chatLog; }

bool LockstepSession::desynced() const { return m->desynced; }
u32 LockstepSession::desyncTick() const { return m->desyncTick; }
const SessionStats& LockstepSession::stats() const { return m->stats; }

u32 LockstepSession::pingMs(u32 player) const {
    if (player >= kMaxPlayers) return 0;
    if (m->state == SessionState::Running) return m->playerPing[player];
    for (const LobbyMember& member : m->members)
        if (member.player == player) return member.pingMs;
    return 0;
}

u32 LockstepSession::waitingFor() const { return m->state == SessionState::Running ? m->waitMask : 0u; }

} // namespace mealkit::net
