#pragma once

#include "mealkit/core/Types.h"
#include "mealkit/net/Conditions.h"
#include "mealkit/net/Transport.h"

#include <memory>
#include <string>
#include <vector>

// Deterministic lockstep session.
//
// All peers run the same simulation, and only per-tick player inputs are exchanged over the network.
// Bandwidth is independent of object count. The host is both a player and a relay:
//   1. When running tick T, each peer submits its input for tick T + inputDelay.
//   2. The host finalizes ticks for which all players' inputs have arrived and distributes them as bundles.
//   3. Only confirmed ticks can run. If input is late, the simulation pauses briefly while rendering continues.
// Packet loss is handled by redundant sending instead of retransmission (unacknowledged inputs are re-sent in every packet).
// Peers report the state hash of executed ticks, and the host compares them to detect desyncs.
// Confirmed commands (submitCommand): occasional commands of varying size (cheats, input delay changes, etc.). When a peer sends one, the host attaches it to the tick it confirms
// and distributes it with that tick's inputs (same redundant sending as inputs; client → host re-sends until acknowledged). Up to kCommandBytesPerTick per tick,
// overflow goes to the next tick. Order within a tick is player index → send order. Games use typed commands via mealkit/sim/Commands.h.
//
// One session runs multiple matches: lobby → startMatch → match (Running) → returnToLobby → lobby → ... (screen flow, game::MatchService).
// In the lobby, the host collects each person's name/ready/loadout and shows them to everyone. Chat is an out-of-tick message, so it isn't in input recordings.
//
// Late join/reconnect: if someone disconnects mid-match the match continues and that slot's input becomes empty. On rejoin (same session token or name)
// they get that slot; first-time joiners get an empty slot. The host gets a world snapshot of the current tick from the game (game::Simulation) (snapshotWanted →
// provideSnapshot), compresses it with LZ4, and sends it in pieces; the joiner fast-forwards from that tick with confirmed inputs to catch up (catchingUp). Others don't pause.
// Connects/disconnects are announced to the simulation at the same tick for everyone via the engine confirmed command (kPresenceCommand) (sim::readPresence).
//
// Host migration: the host sends the succession list (itself, clients, disconnected players: index/token/name/address) every second. When the host leaves (Handoff) or
// is silent for 3 seconds while the match flows (10 seconds in lobby/loading), the first connected one on the list excluding the old host becomes host, and the rest reconnect to its address.
// The new host spends 1 second receiving other peers' further confirmed ticks (TickRequest/TickFill), appends them, then continues confirming; the old host's slot gets a disconnect Presence.
// Direct UDP is only guaranteed on LAN since clients have never connected to each other (Steam/EOS use account ids, so anywhere).
namespace mealkit::net {

inline constexpr u32 kMaxPlayers = 8;
inline constexpr u32 kInputBytes = 8;   // player input size defined by the game (per tick)
inline constexpr u32 kTickWindow = 256; // range of ticks that can be handled at once (about 8.5 seconds at 30Hz)
inline constexpr u32 kMaxCommandBytes = 200;     // max size of one command
inline constexpr u32 kCommandBytesPerTick = 256; // commands carried per tick (including a 2-byte header per command)
inline constexpr u32 kMaxLoadoutBytes = 128;     // match start data per player (so 8 players fit in one start packet)
inline constexpr u32 kMaxNameBytes = 24;         // player name shown in the lobby (UTF-8, cut by character if longer)
inline constexpr u32 kMaxChatBytes = 120;        // one chat line (UTF-8)
inline constexpr u32 kChatLogSize = 50;          // number of lines chatLog() keeps
inline constexpr f64 kChatInterval = 0.5;        // minimum interval between my chat lines (seconds)
// Engine confirmed command name (command type = fnv1a of the name): player connect/disconnect. Contents [connected u8][loadout bytes], sending player = that slot
inline constexpr const char* kPresenceCommand = "mealkit.net.Presence";

struct PlayerInput {
    u8 bytes[kInputBytes] = {};
};

struct TickInputs {
    PlayerInput players[kMaxPlayers];
    u16 commandBytes = 0;                     // bytes used in commands
    u8 commands[kCommandBytesPerTick] = {};   // repeated [player u8][size u8][contents] (read with forEachCommand)
};

// This tick's confirmed commands: f(player, contents, size)
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
    Idle,       // before start
    Connecting, // client: connecting to the host
    Lobby,      // waiting for match start
    Running,    // simulation in progress
    Ended,      // ended (see endReason)
};

struct SessionStats {
    f32 rttMs = 0.0f; // client: round-trip time to the host
    u32 sentBytesPerSec = 0;
    u32 recvBytesPerSec = 0;
};

// One person in the lobby (collected by the host and distributed via lobby signals)
// Device a player plays with (shown in the lobby; crossplay matches mix platforms). Information only: the simulation sees quantized input
enum class InputKind : u8 { KeyboardMouse, Gamepad, Touch };
const char* inputKindName(InputKind kind); // "keyboard/mouse", "gamepad", "touch" (English, logs)

struct LobbyMember {
    u8 player = 0;  // player index (host 0). Renumbered without gaps when the match starts
    std::string name;
    bool ready = false;
    bool host = false;
    InputKind input = InputKind::KeyboardMouse;
    u32 pingMs = 0; // round-trip time to the host (measured by the host, 0 for the host itself)
    std::vector<u8> loadout; // match start data that person picked (read with game::readLobbyLoadout)
};

struct ChatMessage {
    u32 serial = 0; // order received in this session (from 1): lets the screen recognize new lines
    u8 player = 0;
    std::string name; // name at send time
    std::string text;
};

// Automatic input delay adjustment (host): set at match start from round-trip times measured in the lobby, and changed 1 tick at a time mid-match from the same tick for everyone via an engine confirmed command
struct AutoDelay {
    bool enabled = false;
    f32 tickMs = 1000.0f / 30.0f; // length of one tick (project tick rate)
    u32 minTicks = 2;             // never shorter than this, even on the same router
    u32 maxTicks = 8;             // peers farther than this stutter (the lobby warns)
};

// Input delay (ticks) for this round-trip time (ms): time for the farthest peer's input to reach everyone via the host + jitter margin + one tick
u32 delayForRtt(f32 rttMs, const AutoDelay& autoDelay);

// Value that differs per executable (used instead when the simulation version is unknown)
u32 buildId();
// Determinism group: compiler and CPU ("msvc-x64", "clang-x64", "clang-arm64" ...). Until cross-platform determinism is verified (stage 5)
// peers in a different group are rejected
const char* determinismGroup();
// Operating system ("windows", "linux", "macos", ...): players who turn crossplay off only meet peers of the same one
const char* platformName();

// Content hash components (compared separately to report rejection reasons): order of game::MatchData::contentParts
enum class ContentPart : u8 { Scene, Models, Tuning, Project, Tables, Count };

// Connection rejection reason (client, rejectInfo())
// Input: the host only takes players with its own input kind (setSameInputOnly). Crossplay: another OS and one side turned crossplay off
enum class RejectReason : u8 { None, Version, Platform, Content, Full, InProgress, Input, Crossplay };
struct RejectInfo {
    RejectReason reason = RejectReason::None;
    u32 contentMask = 0;     // Content: differing components (bit = ContentPart)
    std::string hostVersion; // Version: the host's game version
    std::string hostGroup;   // Platform: the host's determinism group
    std::string hostPlatform; // Crossplay: the host's OS (platformName)
    InputKind hostInput = InputKind::KeyboardMouse; // Input: the host's input kind
};

class LockstepSession {
public:
    LockstepSession();
    ~LockstepSession();
    LockstepSession(const LockstepSession&) = delete;
    LockstepSession& operator=(const LockstepSession&) = delete;

    // Hash of game data (scene etc.). Set before host/join to reject connections from peers with different data.
    void setContentHash(u64 hash);
    u64 contentHash() const;
    // Hash components (ContentPart order, Count items): tells what differs on rejection
    void setContentParts(const u64* parts);
    // This build's simulation version and game version (game::BuildInfo). Peers with a different simulation version are rejected (buildId if 0)
    void setBuild(u64 simVersion, const std::string& gameVersion);
    // Client: why the host rejected the connection (after Ended)
    const RejectInfo& rejectInfo() const;
    // Host: accept peers with different executables too. Only for compiler comparison tests (mp_test -ClientExe). Desyncs may happen.
    void setAcceptOtherBuilds(bool accept);
    // Host: reject joiners whose input kind differs from the host's (project setting mixInputKinds off). Players already in the room stay
    void setSameInputOnly(bool sameOnly);
    // Player setting: false = only peers on the same OS (platformName). Either side turning it off is enough to reject
    void setCrossplay(bool allowed);
    bool crossplay() const;
    // Network condition simulation (delay/jitter/loss, mealkit/net/Conditions.h): before host/join. For tests
    void setConditions(const NetConditions& conditions);
    // Host: automatic input delay adjustment (host's inputDelay is the initial value). The value changed mid-match is inputDelay()
    void setAutoDelay(const AutoDelay& autoDelay);
    // Host, mid-match: sends an engine command changing input delay to this value (from the same tick for everyone). For tests/game settings
    bool requestInputDelay(u32 ticks);

    // Solo play: uses the same code path without a network. startOffline goes straight to the match, openOffline starts at the lobby (start with startMatch)
    bool startOffline(u64 seed, u32 matchData);
    bool openOffline();
    // Reruns a recorded match (no network, only from Idle). Becomes Running immediately and canExecute is true only up to the recorded ticks.
    // My inputs/commands are discarded. If hashes are given, they're compared in tickExecuted and the first differing tick is reported as a desync (desynced/desyncTick)
    bool startReplay(u64 seed, u32 matchData, const std::vector<std::vector<u8>>& loadouts,
                     std::vector<TickInputs> inputs, std::vector<u64> hashes);
    bool isReplay() const;
    u32 replayTicks() const; // number of recorded ticks (0 if not a replay)
    // loopbackOnly: for same-PC tests (no firewall prompt)
    bool host(u16 port, u32 maxPlayers, u32 inputDelay, bool loopbackOnly = false);
    bool join(const Address& hostAddress);
    // Create/join a room over another transport (Steam etc.)
    bool hostWith(std::unique_ptr<Transport> transport, u32 maxPlayers, u32 inputDelay);
    bool joinWith(std::unique_ptr<Transport> transport, const Address& hostAddress);
    // Match start data (per-player loadout, mealkit/game/Loadout.h): decided before the match. Clients send it in lobby signals (every second),
    // and the host confirms everyone's at startMatch and distributes it in the start packet. Size up to kMaxLoadoutBytes (false if over)
    bool setLocalLoadout(const void* data, u32 size);
    // Confirmed loadouts (after Running, per player index. Empty if not sent)
    const std::vector<u8>& loadout(u32 player) const;
    // My name shown in the lobby (up to kMaxNameBytes) and ready. Clients send them in lobby signals (immediately when changed)
    void setLocalName(const std::string& name);
    const std::string& localName() const;
    void setLocalReady(bool ready);
    bool localReady() const;
    // My input device (sent in lobby signals, immediately when changed; the host's roster carries everyone's)
    void setLocalInputKind(InputKind kind);
    InputKind localInputKind() const;
    // People in the lobby (player index order, including the host). During a match, the list at start
    const std::vector<LobbyMember>& lobbyMembers() const;
    // Host only: lobby → running. Sends seed and matchData (match setting decided by the game) to everyone.
    void startMatch(u64 seed, u32 matchData);
    // Host only: running → lobby (after the results screen). Clients also return to the lobby and everyone's ready is cleared. The next startMatch is a new match
    void returnToLobby();
    u32 matchIndex() const; // number of matches started (the first match is 1)
    // Call every frame: receive packets, confirm, send.
    void update(f64 now);
    void shutdown();
    // Closes the session (notifying peers) and returns to the start (Idle). Content hash, build settings, and name remain (leaving to the menu)
    void reset();

    SessionState state() const;
    const char* endReason() const;
    bool isHost() const;
    bool isOffline() const;
    u8 localPlayer() const;
    u32 playerCount() const;      // match player count (confirmed after Running)
    u32 lobbyPlayerCount() const; // lobby player count
    u32 maxPlayers() const;
    u64 seed() const;
    u32 matchData() const;
    u32 inputDelay() const;

    bool canExecute(u32 tick) const;
    const TickInputs& inputs(u32 tick) const;
    // Call right after running tick T.
    void tickExecuted(u32 tick, u64 stateHash);
    // Players connected during the match (bit = player index, as of executed ticks: changes when connect/disconnect commands execute)
    u32 connectedMask() const;
    // Host migration: when the host leaves (Handoff) or is silent for 3 seconds mid-match, the next person on the succession list takes over as host (isHost() changes).
    // hostAddress: the current host when a client (account id for Steam), successorAddress: the next host when host (to match the lobby owner)
    u32 hostMigrations() const;
    Address hostAddress() const;
    Address successorAddress() const;

    // Late join (host): a snapshot is needed for the joiner. The game provides it between ticks with provideSnapshot(next tick to run, bytes)
    bool snapshotWanted() const;
    void provideSnapshot(u32 tick, const std::vector<u8>& bytes);
    // Late join (client): the first tick of Running (0 if started from the beginning). The game takes the snapshot bytes once
    u32 joinTick() const;
    bool takeJoinSnapshot(std::vector<u8>& out);
    // Catching up on confirmed ticks after joining: the game runs many per frame, and my input is sent only after catching up
    bool catchingUp() const;
    // Submits local input for tick (executed tick + inputDelay).
    void submitLocalInput(u32 tick, const PlayerInput& input);
    // Sends a confirmed command (only when Running, size 1..kMaxCommandBytes). It goes into the next tick the host confirms. false if the queue is full.
    bool submitCommand(const void* data, u32 size);

    // Chat (lobby/mid-match, outside ticks): sends one line (cut to kMaxChatBytes). The host distributes to everyone in order, resending until acknowledged.
    // false for empty lines or sending faster than kChatInterval. Not included in input recordings/replays
    bool sendChat(const std::string& text);
    const std::vector<ChatMessage>& chatLog() const; // in received order, the last kChatLogSize lines (including mine)

    bool desynced() const;
    u32 desyncTick() const;
    const SessionStats& stats() const;
    // Per-player round-trip time to the host (ms, measured by the host during lobby/match and distributed to everyone. 0 for the host)
    u32 pingMs(u32 player) const;
    // The match is stalled waiting for these players' inputs (bit = player index, only when stalled over 0.15 s).
    // Clients get the value the host reported; if the host's bundles haven't come for over 0.3 s, the host (bit 0)
    u32 waitingFor() const;

private:
    struct Impl;
    Impl* m;
};

// Cuts a UTF-8 string to at most maxBytes on character boundaries (names, chat)
std::string clampUtf8(const std::string& text, u32 maxBytes);

} // namespace mealkit::net
