#include "mealkit/net/Lockstep.h"

#include "mealkit/core/Hash.h"
#include "mealkit/core/Log.h"
#include "mealkit/core/Profile.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
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
constexpr f64 kTimeout = 10.0;
constexpr u32 kMaxTicksPerPacket = 32;
constexpr u32 kNoTick = 0xFFFFFFFFu;

enum class Packet : u8 { ConnectRequest = 1, ConnectAccept, ConnectReject, Lobby, Start, Input, Bundle, Disconnect };
enum class Reject : u8 { BuildMismatch = 1, Full, InProgress, ContentMismatch };

// 같은 실행 파일끼리만 접속한다: 결정론은 같은 기계어 코드를 전제로 한다.
u32 buildId() {
    static const u32 id = static_cast<u32>(fnv1a(__DATE__ " " __TIME__));
    return id;
}

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
    void put(const T& v) { bytes(&v, sizeof(T)); }
    void bytes(const void* p, u32 n) {
        if (size + n > kMaxPacket) {
            ok = false;
            return;
        }
        std::memcpy(data + size, p, n);
        size += n;
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
    bool started = false;       // 호스트: 이 클라이언트가 시작을 확인했는가
    u32 inputNext = 0;          // 호스트: 이 클라이언트에게서 연속으로 받은 입력의 다음 틱
    u32 bundleNext = 0;         // 호스트: 이 클라이언트가 아직 못 받은 첫 확정 틱
    u32 echoTime = 0;           // RTT 측정용으로 되돌려 줄 상대 시각
    HashEntry reported[kTickWindow];
};

} // namespace

struct LockstepSession::Impl {
    SessionState state = SessionState::Idle;
    std::string endReason;
    bool host = false;
    bool offline = false;
    bool netStarted = false;
    std::unique_ptr<Transport> transport;
    std::vector<Peer> peers; // 호스트: 클라이언트들 / 클라이언트: [0] = 호스트

    u32 maxPlayers = 1;
    u32 playerCount = 1;
    u32 lobbyCount = 0;
    u8 localPlayer = 0;
    u64 seed = 0;
    u32 matchData = 0;
    u32 inputDelay = 3;
    u64 contentHash = 0;

    Slot slots[kTickWindow];
    u32 finalNext = 0;    // 확정된 틱의 끝 (이 틱부터 미확정)
    u32 executedNext = 0; // 다음에 실행할 틱

    PlayerInput localInputs[kTickWindow]; // 클라이언트: 호스트가 확인하기 전까지 보관
    u32 localSubmittedNext = 0;
    u32 hostInputAckNext = 0;

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
        executedNext = 0;
        localSubmittedNext = inputDelay;
        hostInputAckNext = inputDelay;
        latestHashTick = kNoTick;
        desynced = false;
        state = SessionState::Running;
    }

    bool finalize() {
        const u32 before = finalNext;
        for (;;) {
            Slot& s = slot(finalNext);
            if (s.tick != finalNext) break;
            if (!s.complete) {
                if ((s.mask & allMask()) != allMask()) break;
                s.complete = true;
            }
            ++finalNext;
        }
        return finalNext != before;
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

    // ---------------- 호스트 ----------------

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

    void sendLobby(const Peer& p) {
        Writer w;
        header(w, Packet::Lobby);
        w.put(static_cast<u8>(1 + peers.size()));
        w.put(static_cast<u8>(maxPlayers));
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
        send(p.address, w);
    }

    void sendBundle(Peer& p) {
        Writer w;
        header(w, Packet::Bundle);
        w.put(p.inputNext);
        w.put(p.echoTime);
        w.put(static_cast<u8>(desynced ? 1 : 0));
        w.put(desyncTick);
        const u32 first = p.bundleNext;
        const u32 perTick = playerCount * kInputBytes;
        u32 count = finalNext > first ? finalNext - first : 0;
        count = std::min(count, kMaxTicksPerPacket);
        count = std::min(count, (kMaxPacket - 40) / perTick);
        w.put(first);
        w.put(static_cast<u8>(count));
        w.put(static_cast<u8>(playerCount));
        for (u32 i = 0; i < count; ++i) {
            const Slot& s = slot(first + i);
            MEALKIT_ASSERT(s.tick == first + i && s.complete);
            for (u32 player = 0; player < playerCount; ++player) w.bytes(s.inputs.players[player].bytes, kInputBytes);
        }
        send(p.address, w);
        p.lastSend = now;
    }

    void hostReceive(const Address& from, Reader& r, Packet type) {
        Peer* peer = findPeer(from);
        if (peer) peer->lastRecv = now;

        switch (type) {
        case Packet::ConnectRequest: {
            const u32 build = r.get<u32>();
            const u64 content = r.get<u64>();
            if (!r.ok) return;
            if (build != buildId()) {
                sendReject(from, Reject::BuildMismatch);
                return;
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
                p.playerId = static_cast<u8>(1 + peers.size());
                p.lastRecv = now;
                peers.push_back(p);
                peer = &peers.back();
                MEALKIT_INFO("Player joined from %s (%zu/%u)", from.toString().c_str(), peers.size() + 1, maxPlayers);
            }
            sendAccept(*peer);
            break;
        }
        case Packet::Input: {
            if (!peer || state != SessionState::Running) return;
            peer->started = true;
            const u32 bundleNext = r.get<u32>();
            const u32 echo = r.get<u32>();
            const u32 hashTick = r.get<u32>();
            const u64 hash = r.get<u64>();
            const u32 first = r.get<u32>();
            const u8 count = r.get<u8>();
            if (!r.ok) return;

            peer->bundleNext = std::max(peer->bundleNext, std::min(bundleNext, finalNext));
            peer->echoTime = echo;
            const u32 bit = 1u << peer->playerId;
            for (u32 i = 0; i < count; ++i) {
                PlayerInput input;
                r.bytes(input.bytes, kInputBytes);
                if (!r.ok) break;
                const u32 t = first + i;
                if (t < peer->inputNext) continue;
                if (!inWindow(t)) break;
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
            if (hashTick != kNoTick) {
                peer->reported[hashTick % kTickWindow] = {hashTick, hash};
                const HashEntry& own = hashes[hashTick % kTickWindow];
                if (own.tick == hashTick && own.hash != hash) flagDesync(hashTick, peer->playerId, own.hash, hash);
            }
            if (finalize()) sendPending = true;
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
        default:
            break;
        }
    }

    void hostUpdate() {
        if (state == SessionState::Lobby) {
            for (size_t i = 0; i < peers.size();) {
                if (now - peers[i].lastRecv > kTimeout) {
                    MEALKIT_INFO("Lobby: %s timed out", peers[i].address.toString().c_str());
                    peers.erase(peers.begin() + static_cast<std::ptrdiff_t>(i));
                    continue;
                }
                if (now - peers[i].lastControlSend >= kLobbyInterval) {
                    sendLobby(peers[i]);
                    peers[i].lastControlSend = now;
                }
                ++i;
            }
            return;
        }
        if (state != SessionState::Running) return;
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
            }
            if (sendPending || now - p.lastSend >= kKeepAliveInterval) sendBundle(p);
        }
        sendPending = false;
    }

    // ---------------- 클라이언트 ----------------

    void sendConnect() {
        Writer w;
        header(w, Packet::ConnectRequest);
        w.put(buildId());
        w.put(contentHash);
        send(peers[0].address, w);
    }

    void sendInput() {
        Peer& h = peers[0];
        Writer w;
        header(w, Packet::Input);
        w.put(finalNext);
        w.put(toMs(now));
        w.put(latestHashTick);
        w.put(latestHash);
        const u32 first = hostInputAckNext;
        u32 count = localSubmittedNext > first ? localSubmittedNext - first : 0;
        count = std::min(count, kMaxTicksPerPacket);
        w.put(first);
        w.put(static_cast<u8>(count));
        for (u32 i = 0; i < count; ++i) w.bytes(localInputs[(first + i) % kTickWindow].bytes, kInputBytes);
        send(h.address, w);
        h.lastSend = now;
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
            localPlayer = id;
            maxPlayers = maxP;
            break;
        }
        case Packet::ConnectReject:
            end(rejectText(static_cast<Reject>(r.get<u8>())));
            break;
        case Packet::Lobby:
            lobbyCount = r.get<u8>();
            maxPlayers = r.get<u8>();
            break;
        case Packet::Start: {
            const u8 id = r.get<u8>();
            const u8 count = r.get<u8>();
            const u8 delay = r.get<u8>();
            const u64 matchSeed = r.get<u64>();
            const u32 data = r.get<u32>();
            if (!r.ok || state == SessionState::Running || state == SessionState::Ended) return;
            if (count == 0 || count > kMaxPlayers || id >= count || delay == 0) return;
            localPlayer = id;
            playerCount = count;
            inputDelay = delay;
            seed = matchSeed;
            matchData = data;
            beginRunning();
            MEALKIT_INFO("Match started: player %u of %u, input delay %u ticks", id, count, delay);
            sendInput(); // 시작 확인
            break;
        }
        case Packet::Bundle: {
            if (state != SessionState::Running) return;
            const u32 inputAckNext = r.get<u32>();
            const u32 echo = r.get<u32>();
            const u8 flags = r.get<u8>();
            const u32 hostDesyncTick = r.get<u32>();
            const u32 first = r.get<u32>();
            const u8 count = r.get<u8>();
            const u8 players = r.get<u8>();
            if (!r.ok || players != playerCount) return;

            hostInputAckNext = std::max(hostInputAckNext, std::min(inputAckNext, localSubmittedNext));
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
        case Packet::Disconnect:
            end("Host closed the session");
            break;
        default:
            break;
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
            if (now - h.lastControlSend >= 1.0) { // 로비 유지 신호
                sendConnect();
                h.lastControlSend = now;
            }
            return;
        }
        if (state == SessionState::Running && (sendPending || now - h.lastSend >= kKeepAliveInterval)) {
            sendInput();
            sendPending = false;
        }
    }
};

LockstepSession::LockstepSession() : m(new Impl()) {}

LockstepSession::~LockstepSession() {
    shutdown();
    delete m;
}

void LockstepSession::setContentHash(u64 hash) { m->contentHash = hash; }

bool LockstepSession::startOffline(u64 seed, u32 matchData) {
    if (m->state != SessionState::Idle) return false;
    m->offline = true;
    m->host = true;
    m->maxPlayers = 1;
    m->playerCount = 1;
    m->localPlayer = 0;
    m->inputDelay = 1;
    m->seed = seed;
    m->matchData = matchData;
    m->beginRunning();
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
    if (!udp->open(0, hostAddress.ip == 0x7F000001u)) return false;
    return joinWith(std::move(udp), hostAddress);
}

bool LockstepSession::hostWith(std::unique_ptr<Transport> transport, u32 maxPlayers, u32 inputDelay) {
    if (m->state != SessionState::Idle || !transport) return false;
    m->transport = std::move(transport);
    m->host = true;
    m->maxPlayers = std::clamp(maxPlayers, 1u, kMaxPlayers);
    m->inputDelay = std::clamp(inputDelay, 1u, 30u);
    m->playerCount = 1;
    m->localPlayer = 0;
    m->state = SessionState::Lobby;
    MEALKIT_INFO("Session open: max %u players, input delay %u ticks", m->maxPlayers, m->inputDelay);
    return true;
}

bool LockstepSession::joinWith(std::unique_ptr<Transport> transport, const Address& hostAddress) {
    if (m->state != SessionState::Idle || !transport) return false;
    m->transport = std::move(transport);
    m->host = false;
    m->peers.assign(1, Peer{});
    m->peers[0].address = hostAddress;
    m->state = SessionState::Connecting;
    MEALKIT_INFO("Connecting to %s ...", hostAddress.toString().c_str());
    return true;
}

void LockstepSession::startMatch(u64 seed, u32 matchData) {
    if (!m->host || m->state != SessionState::Lobby) return;
    m->playerCount = 1 + static_cast<u32>(m->peers.size());
    m->seed = seed;
    m->matchData = matchData;
    for (size_t i = 0; i < m->peers.size(); ++i) {
        Peer& p = m->peers[i];
        p.playerId = static_cast<u8>(i + 1);
        p.started = false;
        p.lastControlSend = -1.0;
        p.inputNext = m->inputDelay;
        p.bundleNext = m->inputDelay;
        p.echoTime = 0;
        for (HashEntry& e : p.reported) e = HashEntry{};
    }
    m->beginRunning();
    MEALKIT_INFO("Match started with %u player(s), seed %016llx", m->playerCount,
               static_cast<unsigned long long>(seed));
}

void LockstepSession::update(f64 now) {
    MEALKIT_ZONE("Network");
    m->now = now;
    if (m->offline || m->state == SessionState::Idle || m->state == SessionState::Ended) return;

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
    if (m->state == SessionState::Connecting || m->state == SessionState::Lobby ||
        m->state == SessionState::Running) {
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

SessionState LockstepSession::state() const { return m->state; }
const char* LockstepSession::endReason() const { return m->endReason.c_str(); }
bool LockstepSession::isHost() const { return m->host; }
u8 LockstepSession::localPlayer() const { return m->localPlayer; }
u32 LockstepSession::playerCount() const { return m->playerCount; }
u32 LockstepSession::lobbyPlayerCount() const {
    return m->host ? 1 + static_cast<u32>(m->peers.size()) : m->lobbyCount;
}
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

bool LockstepSession::desynced() const { return m->desynced; }
u32 LockstepSession::desyncTick() const { return m->desyncTick; }
const SessionStats& LockstepSession::stats() const { return m->stats; }

} // namespace mealkit::net
