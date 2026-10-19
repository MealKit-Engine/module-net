#include "mealkit/net/Lockstep.h"

#include "mealkit/core/Hash.h"
#include "mealkit/core/Log.h"
#include "mealkit/core/Profile.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <deque>
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
constexpr u32 kMaxTicksPerPacket = 32;
constexpr u32 kNoTick = 0xFFFFFFFFu;
constexpr u32 kMaxPendingCommands = 256; // 호스트: 틱을 기다리는 명령
constexpr u32 kMaxOutCommands = 64;      // 클라이언트: 호스트가 확인하지 않은 명령
constexpr u32 kMaxOutChat = 16;          // 클라이언트: 호스트가 확인하지 않은 채팅
constexpr u32 kMaxRelayLog = 64;         // 호스트: 아직 모두가 확인하지 않은 채팅

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
};
enum class Reject : u8 { BuildMismatch = 1, Full, InProgress, ContentMismatch };

constexpr u8 kMemberReady = 1;
constexpr u8 kMemberHost = 2;

u32 toMs(f64 seconds) { return static_cast<u32>(seconds * 1000.0) + 1; } // 0은 "없음"

const char* rejectText(Reject r) {
    switch (r) {
    case Reject::BuildMismatch: return "Host runs a different build (all players need the same executable)";
    case Reject::Full: return "Session is full";
    case Reject::InProgress: return "Match already in progress";
    case Reject::ContentMismatch: return "Host uses different game data (scene file differs)";
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
    HashEntry reported[kTickWindow];
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
    bool acceptOtherBuilds = false;
    NetConditions conditions;
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
            for (const Peer& p : peers) low = std::min(low, p.bundleNext);
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
        state = SessionState::Running;
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
                if ((s.mask & allMask()) != allMask()) break;
                if (host) packCommands(s.inputs);
                s.complete = true;
            }
            ++finalNext;
        }
        if (finalNext != before) lastFinalize = now;
        return finalNext != before;
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
        for (u8 id = 1; id < kMaxPlayers; ++id) {
            bool used = false;
            for (const Peer& p : peers) used = used || p.playerId == id;
            if (!used) return id;
        }
        return 0;
    }

    void rebuildMembers() {
        members.clear();
        LobbyMember self;
        self.player = 0;
        self.name = displayName(localName, 0);
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
        send(p.address, w);
    }

    void sendReject(const Address& to, Reject reason) {
        Writer w;
        header(w, Packet::ConnectReject);
        w.put(static_cast<u8>(reason));
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
        w.put(p.playerId);
        w.put(static_cast<u8>(playerCount));
        w.put(static_cast<u8>(inputDelay));
        w.put(seed);
        w.put(matchData);
        w.put(matchIndex);
        for (u32 i = 0; i < playerCount; ++i) {
            w.put(static_cast<u8>(loadouts[i].size()));
            w.bytes(loadouts[i].data(), static_cast<u32>(loadouts[i].size()));
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
        for (u32 player = 0; player < playerCount; ++player) w.put(static_cast<u16>(std::min<u32>(playerPing[player], 0xFFFF)));
        const u32 first = p.bundleNext;
        const u32 perTick = playerCount * kInputBytes + 2; // + 명령 바이트 수
        const u32 available = finalNext > first ? std::min(finalNext - first, kMaxTicksPerPacket) : 0;
        u32 count = 0, bytes = w.size + 4 + 2;
        while (count < available) { // 명령이 있는 틱은 커서 패킷에 들어가는 만큼만
            const u32 need = perTick + slot(first + count).inputs.commandBytes;
            if (bytes + need > kMaxPacket) break;
            bytes += need;
            ++count;
        }
        w.put(first);
        w.put(static_cast<u8>(count));
        w.put(static_cast<u8>(playerCount));
        for (u32 i = 0; i < count; ++i) {
            const Slot& s = slot(first + i);
            MEALKIT_ASSERT(s.tick == first + i && s.complete);
            for (u32 player = 0; player < playerCount; ++player) w.bytes(s.inputs.players[player].bytes, kInputBytes);
            w.put(s.inputs.commandBytes);
            w.bytes(s.inputs.commands, s.inputs.commandBytes);
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

    void hostReceive(const Address& from, Reader& r, Packet type) {
        Peer* peer = findPeer(from);
        if (peer) peer->lastRecv = now;

        switch (type) {
        case Packet::ConnectRequest: {
            const u32 build = r.get<u32>();
            const u64 content = r.get<u64>();
            const u8 loadoutSize = r.get<u8>();
            std::vector<u8> loadout(std::min<u32>(loadoutSize, kMaxLoadoutBytes));
            r.bytes(loadout.data(), static_cast<u32>(loadout.size()));
            const u8 flags = r.get<u8>();
            std::string name = r.text(kMaxNameBytes);
            const u32 hostEcho = r.get<u32>();
            if (!r.ok) return;
            if (build != buildId()) {
                if (!acceptOtherBuilds) {
                    sendReject(from, Reject::BuildMismatch);
                    return;
                }
                if (!peer) MEALKIT_WARN("Accepting a peer with a different build (%08X, test option)", build);
            }
            if (content != contentHash) {
                sendReject(from, Reject::ContentMismatch);
                return;
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
        case Packet::Disconnect: {
            if (!peer) return;
            if (state == SessionState::Running) {
                char reason[64];
                snprintf(reason, sizeof(reason), "Player %u left the match", peer->playerId);
                end(reason);
            } else {
                MEALKIT_INFO("Player left the lobby (%s)", from.toString().c_str());
                peers.erase(peers.begin() + (peer - peers.data()));
            }
            break;
        }
        default: break;
        }
    }

    void hostUpdate() {
        rebuildMembers();
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
        playerPing[0] = 0;
        for (const Peer& p : peers)
            if (p.playerId < kMaxPlayers) playerPing[p.playerId] = static_cast<u32>(p.rttMs + 0.5f);
        waitMask = 0;
        if (now - lastFinalize > kStallReport) { // 확정이 멈췄다: 이 틱의 입력이 오지 않은 플레이어
            const Slot& s = slot(finalNext);
            waitMask = allMask() & ~(s.tick == finalNext ? s.mask : 0u);
        }
        for (Peer& p : peers) {
            if (now - p.lastRecv > kTimeout) {
                char reason[64];
                snprintf(reason, sizeof(reason), "Player %u timed out", p.playerId);
                end(reason);
                return;
            }
            if (!p.started && now - p.lastControlSend >= kStartResendInterval) {
                sendStart(p);
                p.lastControlSend = now;
            } else if (p.started && now - p.lastControlSend >= kLobbyInterval) { // 매치 중 명단 (로비 신호 전에 시작한 사람도 이름을 안다)
                sendLobby(p, Packet::Roster);
                p.lastControlSend = now;
            }
            if (sendPending || now - p.lastSend >= kKeepAliveInterval) sendBundle(p);
        }
        sendPending = false;
        hostChat();
    }

    // ---------------- 클라이언트 ----------------

    void sendConnect() {
        Writer w;
        header(w, Packet::ConnectRequest);
        w.put(buildId());
        w.put(contentHash);
        w.put(static_cast<u8>(localLoadout.size()));
        w.bytes(localLoadout.data(), static_cast<u32>(localLoadout.size()));
        w.put(static_cast<u8>(localReady ? kMemberReady : 0));
        w.text(localName);
        w.put(peers[0].hostEcho);
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

    void clientReceive(const Address& from, Reader& r, Packet type) {
        Peer& h = peers[0];
        if (!(from == h.address)) return;
        h.lastRecv = now;

        switch (type) {
        case Packet::ConnectAccept: {
            const u8 id = r.get<u8>();
            const u8 maxP = r.get<u8>();
            if (!r.ok) return;
            if (state == SessionState::Connecting) {
                state = SessionState::Lobby;
                MEALKIT_INFO("Connected to %s - waiting for the host to start", from.toString().c_str());
            }
            if (state == SessionState::Lobby) localPlayer = id;
            maxPlayers = maxP;
            break;
        }
        case Packet::ConnectReject: end(rejectText(static_cast<Reject>(r.get<u8>()))); break;
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
            if (count == 0 || count > kMaxPlayers || id >= count || delay == 0) return;
            for (u32 i = 0; i < count; ++i) {
                const u8 size = r.get<u8>();
                loadouts[i].resize(std::min<u32>(size, kMaxLoadoutBytes));
                r.bytes(loadouts[i].data(), static_cast<u32>(loadouts[i].size()));
            }
            if (!r.ok) return;
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
            u32 pings[kMaxPlayers] = {};
            for (u32 player = 0; player < playerCount; ++player) pings[player] = r.get<u16>();
            const u32 first = r.get<u32>();
            const u8 count = r.get<u8>();
            const u8 players = r.get<u8>();
            if (!r.ok || players != playerCount) return;
            h.hostEcho = hostTime;
            waitMask = hostWait;
            lastBundle = now;
            for (u32 player = 0; player < playerCount; ++player) playerPing[player] = pings[player];

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
        case Packet::Disconnect: end("Host closed the session"); break;
        default: break;
        }
    }

    void clientUpdate() {
        Peer& h = peers[0];
        if (h.lastRecv < 0.0) h.lastRecv = now;
        if (state == SessionState::Connecting) {
            if (now - h.lastControlSend >= kConnectInterval) {
                sendConnect();
                h.lastControlSend = now;
            }
            if (now - h.lastRecv > kTimeout) end("Could not reach the host");
            return;
        }
        if (now - h.lastRecv > kTimeout) {
            end("Connection to the host was lost");
            return;
        }
        if (state == SessionState::Lobby) {
            if (now - h.lastControlSend >= 1.0) { // 로비 유지 신호 (로드아웃·이름·준비)
                sendConnect();
                h.lastControlSend = now;
            }
            clientChat();
            return;
        }
        if (state == SessionState::Running && now - lastBundle > kHostSilence) waitMask |= 1u; // 호스트에게서 아무것도 오지 않는다
        if (state == SessionState::Running && (sendPending || now - h.lastSend >= kKeepAliveInterval)) {
            sendInput();
            sendPending = false;
        }
        clientChat();
    }
};

LockstepSession::LockstepSession() : m(new Impl()) {}

LockstepSession::~LockstepSession() {
    shutdown();
    delete m;
}

void LockstepSession::setContentHash(u64 hash) { m->contentHash = hash; }
u64 LockstepSession::contentHash() const { return m->contentHash; }
void LockstepSession::setAcceptOtherBuilds(bool accept) { m->acceptOtherBuilds = accept; }
void LockstepSession::setConditions(const NetConditions& conditions) { m->conditions = conditions; }

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
    m->rebuildMembers(); // 시작할 때의 목록 (매치 중에 보인다)
    m->playerCount = 1 + static_cast<u32>(m->peers.size());
    for (std::vector<u8>& l : m->loadouts) l.clear();
    m->loadouts[0] = m->localLoadout;
    // 빈 번호 없이 다시 매긴다 (로비에서 나간 사람이 있으면 번호가 비어 있다)
    for (size_t i = 0; i < m->peers.size(); ++i) m->loadouts[i + 1] = m->peers[i].loadout;
    for (size_t i = 0; i < m->members.size(); ++i) m->members[i].player = static_cast<u8>(i);
    m->seed = seed;
    m->matchData = matchData;
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
        Writer w;
        header(w, Packet::Disconnect);
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
    fresh->localName = m->localName;
    fresh->localLoadout = m->localLoadout;
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
    const Slot& s = m->slot(tick);
    return m->state == SessionState::Running && s.tick == tick && s.complete;
}

const TickInputs& LockstepSession::inputs(u32 tick) const { return m->slot(tick).inputs; }

void LockstepSession::tickExecuted(u32 tick, u64 stateHash) {
    m->executedNext = tick + 1;
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
    if (m->state != SessionState::Running) return;
    if (m->host) {
        Slot& s = m->claim(tick);
        s.inputs.players[m->localPlayer] = input;
        s.mask |= 1u << m->localPlayer;
        if (m->finalize() && !m->offline) {
            for (Peer& p : m->peers) m->sendBundle(p); // 확정되면 바로 배포 (지연 최소화)
        }
    } else {
        m->localInputs[tick % kTickWindow] = input;
        m->localSubmittedNext = std::max(m->localSubmittedNext, tick + 1);
        m->sendInput();
    }
}

bool LockstepSession::submitCommand(const void* data, u32 size) {
    if (m->state != SessionState::Running || size == 0 || size > kMaxCommandBytes) return false;
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
