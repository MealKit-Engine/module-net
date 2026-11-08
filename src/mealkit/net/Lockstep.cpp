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
constexpr u32 kMaxPacket = 1170;    // size that doesn't fragment on internet paths, and the EOS P2P limit (EOS_P2P_MAX_PACKET_SIZE)
constexpr f64 kKeepAliveInterval = 1.0 / 30.0;
constexpr f64 kLobbyInterval = 0.5;
constexpr f64 kConnectInterval = 0.25;
constexpr f64 kStartResendInterval = 0.1;
constexpr f64 kChatResendInterval = 0.1;
constexpr f64 kTimeout = 10.0;
constexpr f64 kStallReport = 0.15;     // when confirmation stalls this long, report who we're waiting for
constexpr f64 kHostSilence = 0.3;      // client: if no host bundle for this long, wait for the host
constexpr f64 kDelayCheckInterval = 1.0; // host: interval for rechecking input delay
constexpr f64 kDelayChangeInterval = 3.0; // host: after changing input delay, until the next change
const u32 kDelayCommandType = static_cast<u32>(fnv1a("mealkit.net.InputDelay")); // engine confirmed command (a name that doesn't collide with game commands)
const u32 kPresenceCommandType = static_cast<u32>(fnv1a(kPresenceCommand)); // connect/disconnect (Lockstep.h)
constexpr u32 kSnapshotChunk = 1100;      // data per snapshot packet (within kMaxPacket with the header)
constexpr u32 kSnapshotWindow = 32 * kSnapshotChunk; // amount sent ahead without acknowledgement
constexpr f64 kSnapshotResend = 0.25;     // if acknowledgement doesn't advance for this long, resend from the acknowledged point
constexpr u32 kCaughtUpTicks = 2;
constexpr f64 kStaleConnection = 1.0;     // host: a connection silent this long is replaced by a reconnect with the same name         // client: caught up when within this of the confirmed end
constexpr u32 kMaxTicksPerPacket = 32;
constexpr u32 kNoTick = 0xFFFFFFFFu;
constexpr u32 kMaxPendingCommands = 256; // host: commands waiting for a tick
constexpr u32 kMaxOutCommands = 64;      // client: commands not yet acknowledged by the host
constexpr u32 kMaxOutChat = 16;          // client: chat not yet acknowledged by the host
constexpr u32 kMaxRelayLog = 64;         // host: chat not yet acknowledged by everyone
// Host migration (docs/DECISIONS.md 2026-10-28)
constexpr f64 kSuccessionInterval = 1.0; // host: interval for sending the succession list
constexpr f64 kHostLost = 3.0;           // client: if the host is silent this long while the match is flowing, hand over to the successor (lobby/loading use kTimeout)
constexpr f64 kMigrateHold = 1.0;        // new host: time to wait for other peers' further confirmed ticks (doesn't confirm on its own meanwhile)
constexpr f64 kTickRequestInterval = 0.1;
constexpr f64 kUpdateGap = 0.5;          // client: if the gap between updates is longer than this (I was stalled), that time isn't counted as silence
constexpr u32 kUnknownSeq = 0xFFFFFFFFu; // new host: this peer's command/chat numbers aren't known yet (start from the first received)

enum class Packet : u8 {
    ConnectRequest = 1,
    ConnectAccept,
    ConnectReject,
    Lobby,
    Start,
    Input,
    Bundle,
    Disconnect,
    Chat,      // client → host: chat to send + acknowledgement of received chat
    ChatRelay, // host → client: everyone's chat + acknowledgement of sent chat
    Roster,    // host → client: roster during the match (same shape as the lobby signal: name/ping, doesn't return to the lobby)
    Snapshot,    // host → late joiner: compressed world snapshot chunk [match][offset u32][size u16][bytes]
    SnapshotAck, // late joiner → host: number of bytes received contiguously from the start
    Succession,  // host → client: succession list [count u8]{index u8, connected u8, token u64, name, ip u32, port u16, user id u64} (host itself first)
    Handoff,     // host → client: the host is leaving, hand over per the succession list (instead of Disconnect)
    TickRequest, // new host → client: [match][from this tick] send me the confirmed ticks you have
    TickFill,    // client → new host: [match][first tick u32][count u8] per tick kMaxPlayers × input + commands
};
using Reject = RejectReason;

constexpr u8 kMemberReady = 1;
constexpr u8 kMemberHost = 2;
constexpr u8 kMemberInputShift = 2; // bits 2..3: InputKind
constexpr u8 kMemberInputMask = 3;

u8 inputBits(InputKind kind) { return static_cast<u8>(static_cast<u8>(kind) << kMemberInputShift); }
InputKind inputOf(u8 flags) {
    const u8 v = (flags >> kMemberInputShift) & kMemberInputMask;
    return v <= static_cast<u8>(InputKind::Touch) ? static_cast<InputKind>(v) : InputKind::KeyboardMouse;
}

u32 toMs(f64 seconds) { return static_cast<u32>(seconds * 1000.0) + 1; } // 0 means "none"

const char* rejectText(Reject r) {
    switch (r) {
    case Reject::Version: return "Host runs a different game version";
    case Reject::Platform: return "Host runs a build for another platform or compiler";
    case Reject::Full: return "Session is full";
    case Reject::InProgress: return "Match already in progress";
    case Reject::Content: return "Host uses different game data";
    case Reject::Input: return "Host only takes players with its input kind";
    case Reject::Crossplay: return "Crossplay is off and the host runs another operating system";
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
    void text(const std::string& s) { // u8 length + bytes (up to 255 bytes)
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
    u32 mask = 0; // bits of players whose input arrived
    bool complete = false;
    TickInputs inputs{};
};

struct Peer {
    Address address;
    u8 playerId = 0;
    f64 lastRecv = -1.0;
    f64 lastSend = -1.0;
    f64 lastControlSend = -1.0; // join request / lobby / start packets
    f64 lastChatSend = -1.0;
    bool started = false;       // host: whether this client acknowledged the start
    u32 inputNext = 0;          // host: next tick of inputs received contiguously from this client
    u32 bundleNext = 0;         // host: first confirmed tick this client hasn't received yet
    u32 echoTime = 0;           // the peer's time to echo back for RTT measurement
    u32 commandNext = 0;        // host: next number of commands received from this client
    f32 rttMs = 0.0f;           // host: round-trip time with this client (exponential average)
    u32 hostEcho = 0;           // client: time sent by the host (echoed back so the host measures the round trip)
    std::vector<u8> loadout;    // host: this client's match start data received in the lobby
    std::string name;           // host: lobby name
    bool ready = false;         // host: lobby ready
    InputKind input = InputKind::KeyboardMouse; // host: input device sent in the lobby signal
    u32 chatNext = 0;           // host: next number of chat received from this client
    u32 relayNext = 0;          // host: next number of relayed chat this client acknowledged
    bool chatAckDirty = false;  // host: needs to acknowledge received chat
    u64 token = 0;              // host: this client's session token (finds the same slot on reconnect)
    // Host, late join: receiving the snapshot (late && !started) or catching up on confirmed ticks (catchUp)
    bool late = false;
    bool catchUp = false;
    std::shared_ptr<const std::vector<u8>> snapshot; // compressed snapshot (after provideSnapshot)
    u32 snapshotTick = kNoTick;
    u32 snapshotRaw = 0;        // size before compression
    u32 snapshotCount = 0;      // player count/connections at the snapshot tick (carried in the start packet)
    u32 snapshotConnected = 0;
    u32 snapshotAcked = 0, snapshotSent = 0;
    f64 snapshotProgress = 0.0;
    HashEntry reported[kTickWindow];
    // New host: heard from this peer after host migration; the end of the confirmed ticks that peer has
    bool heard = true;
    u32 clientFinal = 0;
};

// One line of the succession list (host migration)
struct Successor {
    u8 player = 0;
    bool connected = true;
    u64 token = 0;
    std::string name;
    Address address;
};

// Host: someone who disconnected mid-match (gets the same slot on rejoin)
struct Departed {
    u8 playerId = 0;
    u64 token = 0;
    std::string name;
};

struct Command {
    u32 seq = 0;   // client: send sequence number
    u8 player = 0; // host: player who sent it
    u8 size = 0;
    u8 data[kMaxCommandBytes];
};

struct OutChat { // client: my chat not yet acknowledged by the host
    u32 seq = 0;
    std::string text;
};

struct RelayChat { // host: chat distributed to everyone (in number order)
    u32 index = 0;
    u8 player = 0;
    std::string name;
    std::string text;
};

} // namespace

const char* platformName() {
#if defined(__ANDROID__)
    return "android";
#elif defined(__EMSCRIPTEN__)
    return "web";
#elif defined(__APPLE__)
    return "macos";
#elif defined(__linux__)
    return "linux";
#elif defined(_WIN32)
    return "windows";
#else
    return "other";
#endif
}

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

struct LockstepSession::Impl {
    SessionState state = SessionState::Idle;
    std::string endReason;
    bool host = false;
    bool offline = false;
    bool replay = false;               // startReplay: inputs come from replayInputs
    std::vector<TickInputs> replayInputs;
    std::vector<u64> replayHashes;     // hashes after running replayInputs[t] (not compared if empty)
    bool netStarted = false;
    std::unique_ptr<Transport> transport;
    std::vector<Peer> peers; // host: clients (in player index order) / client: [0] = host

    u32 maxPlayers = 1;
    u32 playerCount = 1;
    u32 lobbyCount = 0;
    u8 localPlayer = 0;
    u64 seed = 0;
    u32 matchData = 0;
    u32 inputDelay = 3;
    u64 contentHash = 0;
    u64 contentParts[static_cast<u32>(ContentPart::Count)] = {};
    u64 simVersion = 0;      // buildId() if 0
    std::string gameVersion;
    RejectInfo rejectInfo;   // client: why we were rejected
    bool acceptOtherBuilds = false;
    NetConditions conditions;
    AutoDelay autoDelay;
    f64 lastDelayCheck = 0.0, lastDelayChange = 0.0;
    bool delayChangePending = false; // host: the delay change command sent hasn't executed yet
    PlayerInput lastLocalInput;      // fills empty ticks when the delay grows
    u32 matchIndex = 0; // number of matches started (decided by the host, announced via start/lobby packets)

    Slot slots[kTickWindow];
    u32 finalNext = 0;    // end of confirmed ticks (unconfirmed from this tick)
    u32 executedNext = 0; // next tick to run

    PlayerInput localInputs[kTickWindow]; // client: kept until the host acknowledges
    std::deque<Command> outCommands;      // client: kept until the host acknowledges (re-sent in every input packet)
    u32 nextCommandSeq = 0;
    std::vector<Command> pendingCommands; // host: in received order, put in the next confirmed tick
    std::vector<u8> localLoadout;
    std::vector<u8> loadouts[kMaxPlayers]; // confirmed match start data
    u32 localSubmittedNext = 0;
    u32 hostInputAckNext = 0;

    // Round-trip time/stalls (network display for players, automatic input delay adjustment)
    u32 playerPing[kMaxPlayers] = {};
    u32 waitMask = 0;
    f64 lastFinalize = 0.0; // host: time finalNext last advanced
    f64 lastBundle = 0.0;   // client: last bundle received

    // Lobby
    std::string localName;
    bool localReady = false;
    InputKind localInput = InputKind::KeyboardMouse;
    bool sameInputOnly = false; // host: reject joiners with another input kind
    bool crossplay = true;      // false: peers on another OS are rejected
    std::vector<LobbyMember> members; // host: rebuilt every update / client: from lobby signals
    std::vector<f64> memberSeen;      // client: last receive time per member (removes people who left)
    u32 memberCursor = 0;             // host: if not everything fits in a lobby signal, the next signal starts here

    // Chat
    std::vector<ChatMessage> chatLog;
    u32 chatSerial = 0;
    f64 lastLocalChat = -1e9;
    std::deque<OutChat> outChat;   // client
    u32 nextChatSeq = 0;           // client
    u32 relayExpected = 0;         // client: next relay number to receive
    bool relayStarted = false;     // client: received the first relay packet
    bool relayAckDirty = false;    // client
    f64 lastChatSend = -1.0;       // client
    std::deque<RelayChat> relayLog; // host
    u32 relayEnd = 0;               // host: next relay number

    // Late join/reconnect
    u64 localToken = 0;                 // this session object's token (survives reset)
    u32 connected = 0;                  // connection bits as of executed ticks
    u32 requiredFrom[kMaxPlayers] = {}; // host: waits for this player's input from this tick (kNoTick: doesn't wait, empty input)
    u32 width = 1;                      // host: number of players carried in bundles (highest index ever used + 1)
    std::vector<Departed> departed;     // host
    bool snapshotWanted = false;        // host: asks the game for a snapshot
    std::deque<TickInputs> joinLog;     // host: confirmed ticks to send to catching-up players (including those pushed out of the ring buffer)
    u32 joinLogBase = 0;
    bool joinLogging = false;
    bool late = false;                  // client: joined mid-match
    u32 joinTick = 0;                   // client: the snapshot's tick (0 if from the start)
    u32 joinRaw = 0, joinCompressed = 0;
    std::vector<u8> joinBuffer;         // client: compressed snapshot being received (full size, chunks filled out of order)
    std::vector<bool> joinChunks;       // client: received chunks
    u32 joinPrefix = 0;                 // client: bytes received without gaps from the start (acknowledged to the host)
    std::vector<u8> joinSnapshot;       // client: decompressed snapshot (taken by the game)
    bool catchingUp = false;            // client

    // Host migration
    u8 hostPlayer = 0;                  // current host's player index
    std::vector<Successor> successors;  // client: the succession list last sent by the host (including the host, in send order)
    f64 lastSuccession = -1.0;          // host
    f64 migrateHold = 0.0;              // new host: waits until this time for further confirmed ticks (0 = done)
    f64 lastTickRequest = -1.0;         // new host
    f64 lastUpdate = -1.0;              // client: time of the last update
    bool matchFlowing = false;          // client: ticks have arrived in bundles this match (use the short host timeout)
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
    // Host: players whose input is needed to confirm this tick (disconnected or still catching up players get empty input)
    u32 needMask(u32 tick) const {
        u32 mask = 0;
        for (u32 player = 0; player < kMaxPlayers; ++player)
            if (requiredFrom[player] <= tick) mask |= 1u << player;
        return mask;
    }
    Slot& slot(u32 tick) { return slots[tick % kTickWindow]; }
    const Slot& slot(u32 tick) const { return slots[tick % kTickWindow]; }
    u8 matchByte() const { return static_cast<u8>(matchIndex); } // input/bundle packets: drops late packets from the previous match

    Slot& claim(u32 tick) {
        Slot& s = slot(tick);
        if (s.tick != tick) {
            s = Slot{};
            s.tick = tick;
        }
        return s;
    }

    // Oldest tick still needed. If the ring buffer gets kTickWindow or more ahead of it, it would overwrite, so don't accept.
    u32 windowLow() const {
        u32 low = executedNext;
        if (host)
            for (const Peer& p : peers)
                if (!(p.late && !p.started) && !p.catchUp) low = std::min(low, p.bundleNext); // joiners receive from joinLog
        return low;
    }
    bool inWindow(u32 tick) const { return tick + 1 < windowLow() + kTickWindow; }

    void beginRunning() {
        for (Slot& s : slots) s = Slot{};
        for (HashEntry& h : hashes) h = HashEntry{};
        // Starts with the first inputDelay ticks all confirmed with empty input.
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
        lastSuccession = -1.0; // send the list renumbered by match right away
        state = SessionState::Running;
    }

    u32 desiredDelay() const {
        f32 worst = 0.0f;
        for (const Peer& p : peers) worst = std::max(worst, p.rttMs);
        return delayForRtt(worst, autoDelay);
    }

    // Host: when round-trip time changes mid-match, sends an engine command that changes the delay (increase as much as needed at once, decrease by 1 tick when more than 2 ticks remain)
    void adjustDelay() {
        if (!autoDelay.enabled || offline || delayChangePending || now - lastDelayCheck < kDelayCheckInterval) return;
        lastDelayCheck = now;
        if (now - lastDelayChange < kDelayChangeInterval) return;
        const u32 want = desiredDelay();
        u32 next = inputDelay;
        if (want > inputDelay) next = want; // increases happen at once (stutter disappears immediately)
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

    // Changed right after all peers run the same tick (the tick containing the delay command). The next submission is (tick + new delay)
    void applyDelay(u32 tick, u32 next) {
        next = std::clamp(next, 1u, 30u);
        if (next == inputDelay) return;
        MEALKIT_INFO("Input delay %u -> %u ticks from tick %u", inputDelay, next, tick);
        // When it grows, the gap between (tick-1+old) and (tick+new) is empty: filled with my last input (when it shrinks, submitLocalInput skips overlapping ticks)
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
                if (host && holding()) break; // new host: further confirmed ticks may arrive (deciding on its own would diverge)
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

    // New host: other peers may have further confirmed ticks. Done once heard from everyone and all those ticks received, or kMigrateHold elapses
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

    // Host: puts waiting commands in this tick. Player index → received order; on overflow that player's rest go to the next tick (order kept)
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

    // Host: connect/disconnect engine command (sending player = that slot). Everyone processes it with applyPresence and the simulation at the same tick
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

    // Inputs of a confirmed tick: ring buffer, or joinLog if already pushed out
    const TickInputs* finalized(u32 tick) const {
        const Slot& s = slot(tick);
        if (s.tick == tick && s.complete) return &s.inputs;
        if (tick >= joinLogBase && tick - joinLogBase < joinLog.size()) return &joinLog[tick - joinLogBase];
        return nullptr;
    }

    // Host, mid-match: continues without disconnected players (their slot gets empty input, same slot on rejoin)
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

    // ---------------- Host ----------------

    // Smallest empty player index (reuses the index of someone who left the lobby)
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
        self.player = localPlayer; // a successor host may not be 0
        self.name = displayName(localName, localPlayer);
        self.ready = true; // the host is the one who starts
        self.host = true;
        self.input = localInput;
        self.loadout = localLoadout;
        members.push_back(std::move(self));
        for (const Peer& p : peers) {
            LobbyMember entry;
            entry.player = p.playerId;
            entry.name = displayName(p.name, p.playerId);
            entry.ready = p.ready;
            entry.input = p.input;
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
        w.put(static_cast<u8>(state == SessionState::Running ? 1 : 0)); // mid-match: don't go to the lobby, wait for the snapshot
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
        w.text(platformName());
        w.put(static_cast<u8>(localInput));
        send(to, w);
    }

    // Lobby signal: count + per person (index, ready, name, loadout). If not everything fits, the next signal continues
    void sendLobby(const Peer& p, Packet type = Packet::Lobby) {
        Writer w;
        header(w, type);
        w.put(static_cast<u8>(members.size()));
        w.put(static_cast<u8>(maxPlayers));
        w.put(matchIndex);
        w.put(toMs(now)); // the client echoes it back in its join request (round-trip time in the lobby too)
        const u32 countAt = w.size;
        w.put(static_cast<u8>(0));
        u8 written = 0;
        for (u32 k = 0; k < members.size(); ++k) {
            const LobbyMember& entry = members[(memberCursor + k) % members.size()];
            const u32 need = 6 + static_cast<u32>(entry.name.size()) + static_cast<u32>(entry.loadout.size()) + 1;
            if (w.size + need > kMaxPacket) break;
            w.put(entry.player);
            w.put(static_cast<u16>(std::min<u32>(entry.pingMs, 0xFFFF)));
            w.put(static_cast<u8>((entry.ready ? kMemberReady : 0) | (entry.host ? kMemberHost : 0) | inputBits(entry.input)));
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
        if (p.late) { // late join: snapshot tick/size, connections at that tick
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
        const u32 perTick = width * kInputBytes + 2; // + command byte count
        const u32 available = finalNext > first ? std::min(finalNext - first, kMaxTicksPerPacket) : 0;
        u32 count = 0, bytes = w.size + 4 + 1;
        while (count < available) { // ticks with commands are large, so only as many as fit in the packet
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

    // Host → client: relayed chat not yet acknowledged + acknowledgement of received chat
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
        // Lines acknowledged by everyone are dropped (if it backs up too much, oldest first)
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

    // Mid-match join: disconnected players (same token, otherwise same name) get their slot, otherwise an empty slot. Ask the game for a snapshot and send from the next update
    Peer* acceptLate(const Address& from, u64 token, const std::string& name, const std::vector<u8>& loadout) {
        // The same person from a new address (network changed, or quit without announcing and restarted): treated as the old connection disconnecting.
        // Same token, or same name with a quiet old connection
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

    // Host → late joiner: unacknowledged snapshot chunks up to the window size. If acknowledgement stalls, resend from the acknowledged point
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
            const std::string platform = r.text(16);
            const bool peerCrossplay = r.get<u8>() != 0;
            if (!r.ok) return;
            // Must be the same simulation: determinism group (compiler/CPU) → simulation version (game version + simulation source) → game data
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
            if (platform != platformName() && (!crossplay || !peerCrossplay)) {
                sendReject(from, Reject::Crossplay);
                return;
            }
            if (!peer && sameInputOnly && inputOf(flags) != localInput) { // new joiners only: switching devices in the room doesn't kick
                sendReject(from, Reject::Input);
                return;
            }
            if (!peer && state == SessionState::Running) {
                peer = acceptLate(from, token, name, loadout);
                if (!peer) return;
                peer->input = inputOf(flags);
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
                p.relayNext = relayEnd; // chat from before joining isn't sent
                p.token = token;
                peers.push_back(p);
                std::sort(peers.begin(), peers.end(), [](const Peer& a, const Peer& b) { return a.playerId < b.playerId; });
                peer = findPeer(from);
                MEALKIT_INFO("Player joined from %s (%zu/%u)", from.toString().c_str(), peers.size() + 1, maxPlayers);
            }
            rttSample(*peer, hostEcho);
            if (state == SessionState::Lobby) { // new values every lobby signal
                peer->loadout = std::move(loadout);
                peer->name = std::move(name);
                peer->ready = (flags & kMemberReady) != 0;
                peer->input = inputOf(flags);
            }
            sendAccept(*peer);
            break;
        }
        case Packet::Input: {
            if (!peer || state != SessionState::Running) return;
            if (r.get<u8>() != matchByte()) return; // late packet from the previous match
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
            if (!peer->heard) peer->bundleNext = std::min(bundleNext, finalNext); // first time after host migration: send from the end this peer has
            peer->heard = true;
            peer->clientFinal = bundleNext;
            if (requiredFrom[peer->playerId] == kNoTick && count > 0) { // late join/reconnect: wait from the first input sent after catching up
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
            if (r.ok && peer->commandNext == kUnknownSeq) peer->commandNext = commandFirst; // first time after host migration
            for (u32 i = 0; r.ok && i < commandCount; ++i) {
                Command c;
                c.size = r.get<u8>();
                if (c.size == 0 || c.size > kMaxCommandBytes) break;
                r.bytes(c.data, c.size);
                if (!r.ok) break;
                const u32 seq = commandFirst + i;
                if (seq < peer->commandNext) continue; // already received (re-sent)
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
            if (peer->chatNext == kUnknownSeq) peer->chatNext = firstSeq; // first time after host migration
            for (u32 i = 0; i < count; ++i) {
                const std::string text = r.text(kMaxChatBytes);
                if (!r.ok) break;
                const u32 seq = firstSeq + i;
                if (seq < peer->chatNext) continue; // already received
                if (seq > peer->chatNext) break;
                ++peer->chatNext;
                peer->chatAckDirty = true;
                if (!text.empty()) relayChat(peer->playerId, displayName(peer->name, peer->playerId), text);
            }
            break;
        }
        case Packet::TickFill: { // host migration: ticks the old host confirmed but I didn't receive
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
                s.inputs = in; // what the old host decided is correct (my own input I filled in is the same value)
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

    // Host → client: succession list (me, then connected clients and players disconnected mid-match, in slot order). If not everything fits, only the front part
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
            w.put(a.userId);
            ++count;
        };
        entry(localPlayer, true, localToken, localName, Address{});
        for (const Peer& p : peers) entry(p.playerId, true, p.token, p.name, p.address);
        for (const Departed& d : departed) entry(d.playerId, false, d.token, d.name, Address{});
        w.data[countAt] = count;
        for (const Peer& p : peers) send(p.address, w);
        lastSuccession = now;
    }

    // New host: asks the peer with the furthest confirmed tick for the missing ticks
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
        if (holding()) lastFinalize = now; // while waiting, it isn't reported as a stall
        else if (finalize()) sendPending = true;
        adjustDelay();
        playerPing[localPlayer] = 0;
        for (const Peer& p : peers)
            if (p.playerId < kMaxPlayers) playerPing[p.playerId] = static_cast<u32>(p.rttMs + 0.5f);
        waitMask = 0;
        if (now - lastFinalize > kStallReport) { // confirmation stalled: players whose input for this tick hasn't arrived
            const Slot& s = slot(finalNext);
            waitMask = needMask(finalNext) & ~(s.tick == finalNext ? s.mask : 0u);
        }
        for (size_t i = 0; i < peers.size();) {
            if (now - peers[i].lastRecv > kTimeout) dropPeer(i, "timed out");
            else ++i;
        }
        bool logNeeded = false;
        for (Peer& p : peers) {
            if (p.late && !p.started) { // late join: once the snapshot is ready, start packet and snapshot chunks
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
            if (p.catchUp && finalNext - p.bundleNext < kTickWindow / 2) p.catchUp = false; // now within the ring buffer
            logNeeded = logNeeded || p.catchUp;
            if (!p.started && now - p.lastControlSend >= kStartResendInterval) {
                sendStart(p);
                p.lastControlSend = now;
            } else if (p.started && now - p.lastControlSend >= kLobbyInterval) { // roster during the match (so people who started before a lobby signal know names too)
                sendLobby(p, Packet::Roster);
                p.lastControlSend = now;
            }
            if (sendPending || now - p.lastSend >= kKeepAliveInterval) sendBundle(p);
        }
        trimJoinLog(logNeeded);
        sendPending = false;
        hostChat();
    }

    // Ticks all catching-up players received are dropped. If nobody is catching up, stop keeping them
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

    // ---------------- Client ----------------

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
        w.put(static_cast<u8>((localReady ? kMemberReady : 0) | inputBits(localInput)));
        w.text(localName);
        w.put(peers[0].hostEcho);
        w.put(localToken);
        w.text(platformName());
        w.put(static_cast<u8>(crossplay ? 1 : 0));
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

    // Client → host: my unacknowledged chat + acknowledgement of received relays
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

    // The host went back to the lobby (after the results screen): end the match and choose ready again
    void enterLobbyFromMatch() {
        state = SessionState::Lobby;
        localReady = false;
        if (!peers.empty()) peers[0].lastControlSend = -1.0; // send the lobby signal right away
        MEALKIT_INFO("Back to the lobby (match %u ended)", matchIndex);
    }

    // ---------------- Host migration ----------------

    // Next host from the succession list: the first connected one excluding the current host
    const Successor* nextHost() const {
        for (const Successor& e : successors)
            if (e.connected && e.player != hostPlayer) return &e;
        return nullptr;
    }

    bool canMigrate() const {
        return !offline && !replay && !late && !catchingUp &&
               (state == SessionState::Lobby || state == SessionState::Running) && nextHost() != nullptr;
    }

    // The host left/went silent: attach to the next person on the succession list or become the host myself
    void migrate(const char* why) {
        if (!canMigrate()) {
            end("Connection to the host was lost");
            return;
        }
        for (Successor& e : successors)
            if (e.player == hostPlayer) e.connected = false; // old host: a disconnected player (gets that slot if rejoining with the same token)
        const Successor next = *nextHost();
        ++migrations;
        MEALKIT_WARN("Host player %u %s - player %u takes over the session (tick %u)", hostPlayer, why, next.player, finalNext);
        const u8 oldHost = hostPlayer;
        hostPlayer = next.player;
        relayStarted = false; // the new host's relay numbers start from 0
        if (next.player == localPlayer) {
            becomeHost(oldHost);
            return;
        }
        Peer& h = peers[0];
        h = Peer{};
        h.address = next.address;
        h.lastRecv = now;
        lastBundle = now;
        matchFlowing = false; // long timeout until the new host starts sending ticks
        if (state == SessionState::Running) {
            hostInputAckNext = std::min(hostInputAckNext, finalNext); // my inputs the old host received but didn't confirm are resent
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
                if (member.player == e.player) {
                    p.loadout = member.loadout;
                    p.input = member.input;
                }
            next.push_back(std::move(p));
        }
        peers = std::move(next);
        relayLog.clear();
        relayEnd = 0;
        pendingCommands.clear();
        if (state == SessionState::Running) {
            // Inputs to wait for from now on: connected players on the list and me. Others (old host, people who joined after the list) get empty input (same slot on rejoin)
            for (u32 player = 0; player < kMaxPlayers; ++player) requiredFrom[player] = kNoTick;
            requiredFrom[localPlayer] = finalNext;
            for (const Peer& p : peers) requiredFrom[p.playerId] = finalNext;
            width = playerCount;
            for (u32 player = 0; player < kMaxPlayers; ++player)
                if (requiredFrom[player] != kNoTick) width = std::max(width, player + 1);
            // My submitted inputs not yet confirmed
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

    // Client → new host: confirmed ticks I have (from from, as many as fit in the packet)
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
            // The successor became host first and is sending (I missed the Handoff): switch over immediately
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
            if (state == SessionState::Connecting && inMatch) { // mid-match: stays connecting until the snapshot is received
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
            rejectInfo.hostPlatform = r.text(16);
            rejectInfo.hostInput = static_cast<InputKind>(std::min<u8>(r.get<u8>(), static_cast<u8>(InputKind::Touch)));
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
            if (type == Packet::Roster) { // roster during the match: only this match's
                if (state != SessionState::Running || hostMatch != matchIndex) return;
            } else {
                if (state == SessionState::Running) {
                    if (hostMatch < matchIndex) return; // late signal sent before the match started
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
                entry.input = inputOf(flags);
                size_t at = 0;
                while (at < members.size() && members[at].player != entry.player) ++at;
                if (at == members.size()) {
                    members.push_back({});
                    memberSeen.push_back(0.0);
                }
                members[at] = std::move(entry);
                memberSeen[at] = now;
            }
            // People who left: remove those who haven't come back for a few lobby signals (each signal may carry only some)
            for (size_t i = 0; i < members.size();) {
                if (now - memberSeen[i] > kLobbyInterval * 4.0) {
                    members.erase(members.begin() + static_cast<std::ptrdiff_t>(i));
                    memberSeen.erase(memberSeen.begin() + static_cast<std::ptrdiff_t>(i));
                } else {
                    ++i;
                }
            }
            for (size_t i = 1; i < members.size(); ++i) // in player index order (insertion sort, moved together)
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
            if (index <= matchIndex && matchIndex != 0) return; // late start packet from a previous match
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
            if (lateStart) { // late join: wait for snapshot chunks (startLate once all are received)
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
            for (size_t i = 0; i < members.size(); ++i) members[i].player = static_cast<u8>(i); // no gaps in indices, like the host
            beginRunning();
            MEALKIT_INFO("Match started: player %u of %u, input delay %u ticks", id, count, delay);
            sendInput(); // acknowledge the start
            break;
        }
        case Packet::Bundle: {
            if (state != SessionState::Running) return;
            if (r.get<u8>() != matchByte()) return; // late packet from the previous match
            const u32 inputAckNext = r.get<u32>();
            const u32 echo = r.get<u32>();
            const u8 flags = r.get<u8>();
            const u32 hostDesyncTick = r.get<u32>();
            const u32 commandAck = r.get<u32>();
            const u32 hostTime = r.get<u32>();
            const u8 hostWait = r.get<u8>();
            const u8 players = r.get<u8>(); // number of players the host carries (can grow with late joins)
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
            if (!relayStarted) { // from the first bundle received (no chat from before joining)
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
                if (index > relayExpected) break; // something is missing: wait until it comes again
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
            const u32 chunk = offset / kSnapshotChunk; // kept even if out of order (the host resends missing ones)
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
                e.address.userId = r.get<u64>();
                if (r.ok) list.push_back(std::move(e));
            }
            if (!r.ok || list.empty()) return;
            hostPlayer = list[0].player; // the host itself first
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

    // The whole snapshot is received: catch up with confirmed inputs from that tick (the game loads the world via takeJoinSnapshot)
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
        sendInput(); // acknowledge the start (the host starts sending bundles)
    }

    void clientUpdate() {
        Peer& h = peers[0];
        if (h.lastRecv < 0.0) h.lastRecv = now;
        if (lastUpdate >= 0.0 && now - lastUpdate > kUpdateGap) { // I was stalled (loading): that time isn't counted as host silence
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
        // The host is silent: short timeout while the match flows, long in lobby/loading (the host may stall for seconds). Hand over to the next person on the succession list
        const f64 lost = state == SessionState::Running && matchFlowing ? kHostLost : kTimeout;
        if (now - h.lastRecv > lost) {
            migrate("timed out");
            if (host || state == SessionState::Ended) return;
        }
        if (state == SessionState::Lobby) {
            if (now - h.lastControlSend >= 1.0) { // lobby keepalive signal (loadout/name/ready)
                sendConnect();
                h.lastControlSend = now;
            }
            clientChat();
            return;
        }
        if (state == SessionState::Running && now - lastBundle > kHostSilence) waitMask |= 1u << hostPlayer; // nothing is coming from the host
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
    const f32 needMs = rttMs * 1.25f + tickMs; // round trip (the longest path via the host) + jitter margin + one processing tick
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
    if (!m->host && !m->peers.empty()) m->peers[0].lastControlSend = -1.0; // if in the lobby, resend right away
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

void LockstepSession::setLocalInputKind(InputKind kind) {
    if (kind == m->localInput) return;
    m->localInput = kind;
    if (!m->host && !m->peers.empty()) m->peers[0].lastControlSend = -1.0;
}

InputKind LockstepSession::localInputKind() const { return m->localInput; }
void LockstepSession::setSameInputOnly(bool sameOnly) { m->sameInputOnly = sameOnly; }
void LockstepSession::setCrossplay(bool allowed) {
    if (allowed == m->crossplay) return;
    m->crossplay = allowed;
    if (!m->host && !m->peers.empty()) m->peers[0].lastControlSend = -1.0;
}
bool LockstepSession::crossplay() const { return m->crossplay; }

const std::vector<LobbyMember>& LockstepSession::lobbyMembers() const { return m->members; }

void LockstepSession::startMatch(u64 seed, u32 matchData) {
    if (!m->host || m->state != SessionState::Lobby) return;
    m->localPlayer = m->hostPlayer = 0; // a successor host is also index 0 in a new match
    m->rebuildMembers(); // list at start (shown during the match)
    m->playerCount = 1 + static_cast<u32>(m->peers.size());
    for (std::vector<u8>& l : m->loadouts) l.clear();
    m->loadouts[0] = m->localLoadout;
    // Renumber without gaps (indices are empty if someone left the lobby)
    for (size_t i = 0; i < m->peers.size(); ++i) m->loadouts[i + 1] = m->peers[i].loadout;
    for (size_t i = 0; i < m->members.size(); ++i) m->members[i].player = static_cast<u8>(i);
    m->seed = seed;
    m->matchData = matchData;
    if (m->autoDelay.enabled && !m->offline) { // from round-trip times measured in the lobby
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
        p.lastControlSend = -1.0; // send the lobby signal right away (clients go to the lobby on receiving it)
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
        // The host is leaving: the rest continue per the succession list (host migration). Ending is end()'s Disconnect
        const bool handoff = m->host && !m->offline && !m->peers.empty() && m->state != SessionState::Connecting;
        if (handoff) m->sendSuccession(); // the final list (so it arrives before the Handoff)
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
    fresh->localToken = m->localToken; // same person: rejoining gets the old slot
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
    forEachCommand(m->slot(tick).inputs, [&](u8 player, const u8* data, u32 size) { // engine commands: input delay change, connect/disconnect
        u32 type = 0;
        if (size >= 5) std::memcpy(&type, data, 4);
        if (size == 5 && type == kDelayCommandType) m->applyDelay(tick, data[4]);
        if (size >= 5 && type == kPresenceCommandType) m->applyPresence(player, data[4] != 0, data + 5, size - 5);
    });
    if (m->catchingUp && tick + 1 + kCaughtUpTicks >= m->finalNext) { // caught up: send from my next input
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
        if (tick < m->finalNext) return; // a tick already submitted because the delay shrank (confirmed ones aren't changed)
        Slot& s = m->claim(tick);
        if (s.mask & (1u << m->localPlayer)) return;
        s.inputs.players[m->localPlayer] = input;
        s.mask |= 1u << m->localPlayer;
        if (m->finalize() && !m->offline) {
            for (Peer& p : m->peers) m->sendBundle(p); // distribute as soon as confirmed (minimizes delay)
        }
    } else {
        if (tick < m->localSubmittedNext) return; // a tick already submitted because the delay shrank
        m->localInputs[tick % kTickWindow] = input;
        m->localSubmittedNext = std::max(m->localSubmittedNext, tick + 1);
        m->sendInput();
    }
}

u32 LockstepSession::connectedMask() const { return m->connected; }

u32 LockstepSession::hostMigrations() const { return m->migrations; }

Address LockstepSession::hostAddress() const { return m->host || m->peers.empty() ? Address{} : m->peers[0].address; }

Address LockstepSession::successorAddress() const {
    // First client in player index order (the next person on the succession list)
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
    // Confirmed ticks to catch up on: from the snapshot tick (still in the ring buffer)
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
    if (m->host) { // solo play also comes here (only into its own log)
        m->relayChat(m->localPlayer, name, line);
        return true;
    }
    if (m->outChat.size() >= kMaxOutChat) return false;
    m->outChat.push_back({m->nextChatSeq++, line});
    m->lastChatSend = -1.0; // send right away
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
