#pragma once

#include "mealkit/core/Types.h"
#include "mealkit/net/Conditions.h"
#include "mealkit/net/Transport.h"
#include "mealkit/session/Session.h"

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

// Shared types live in the session module (mealkit/session/Session.h); these names keep engine-side net code unchanged
using session::ChatMessage;
using session::clampUtf8;
using session::ContentPart;
using session::forEachCommand;
using session::InputKind;
using session::inputKindName;
using session::kChatInterval;
using session::kChatLogSize;
using session::kCommandBytesPerTick;
using session::kInputBytes;
using session::kMaxChatBytes;
using session::kMaxCommandBytes;
using session::kMaxLoadoutBytes;
using session::kMaxNameBytes;
using session::kMaxPlayers;
using session::kPresenceCommand;
using session::kTickWindow;
using session::LobbyMember;
using session::PlayerInput;
using session::RejectInfo;
using session::RejectReason;
using session::SessionState;
using session::SessionStats;
using session::TickInputs;

using session::AutoDelay;
using session::buildId;
using session::delayForRtt;
using session::determinismGroup;
using session::platformName;

class LockstepSession final : public session::Session {
public:
    LockstepSession();
    ~LockstepSession();
    LockstepSession(const LockstepSession&) = delete;
    LockstepSession& operator=(const LockstepSession&) = delete;

    // Hash of game data (scene etc.). Set before host/join to reject connections from peers with different data.
    void setContentHash(u64 hash);
    u64 contentHash() const override;
    // Hash components (ContentPart order, Count items): tells what differs on rejection
    void setContentParts(const u64* parts);
    // This build's simulation version and game version (game::BuildInfo). Peers with a different simulation version are rejected (buildId if 0)
    void setBuild(u64 simVersion, const std::string& gameVersion);
    // Client: why the host rejected the connection (after Ended)
    const RejectInfo& rejectInfo() const override;
    // Host: accept peers with different executables too. Only for compiler comparison tests (mp_test -ClientExe). Desyncs may happen.
    void setAcceptOtherBuilds(bool accept);
    // Host: reject joiners whose input kind differs from the host's (project setting mixInputKinds off). Players already in the room stay
    void setSameInputOnly(bool sameOnly);
    // Player setting: false = only peers on the same OS (platformName). Either side turning it off is enough to reject
    void setCrossplay(bool allowed);
    bool crossplay() const override;
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
    bool isReplay() const override;
    u32 replayTicks() const override; // number of recorded ticks (0 if not a replay)
    // loopbackOnly: for same-PC tests (no firewall prompt)
    bool host(u16 port, u32 maxPlayers, u32 inputDelay, bool loopbackOnly = false);
    bool join(const Address& hostAddress);
    // Create/join a room over another transport (Steam etc.)
    bool hostWith(std::unique_ptr<Transport> transport, u32 maxPlayers, u32 inputDelay);
    bool joinWith(std::unique_ptr<Transport> transport, const Address& hostAddress);
    // Match start data (per-player loadout, mealkit/game/Loadout.h): decided before the match. Clients send it in lobby signals (every second),
    // and the host confirms everyone's at startMatch and distributes it in the start packet. Size up to kMaxLoadoutBytes (false if over)
    bool setLocalLoadout(const void* data, u32 size) override;
    // Confirmed loadouts (after Running, per player index. Empty if not sent)
    const std::vector<u8>& loadout(u32 player) const override;
    // My name shown in the lobby (up to kMaxNameBytes) and ready. Clients send them in lobby signals (immediately when changed)
    void setLocalName(const std::string& name) override;
    const std::string& localName() const override;
    void setLocalReady(bool ready) override;
    bool localReady() const override;
    // My input device (sent in lobby signals, immediately when changed; the host's roster carries everyone's)
    void setLocalInputKind(InputKind kind) override;
    InputKind localInputKind() const override;
    // People in the lobby (player index order, including the host). During a match, the list at start
    const std::vector<LobbyMember>& lobbyMembers() const override;
    // Host only: lobby → running. Sends seed and matchData (match setting decided by the game) to everyone.
    void startMatch(u64 seed, u32 matchData) override;
    // Host only: running → lobby (after the results screen). Clients also return to the lobby and everyone's ready is cleared. The next startMatch is a new match
    void returnToLobby() override;
    u32 matchIndex() const override; // number of matches started (the first match is 1)
    // Call every frame: receive packets, confirm, send.
    void update(f64 now);
    void shutdown();
    // Closes the session (notifying peers) and returns to the start (Idle). Content hash, build settings, and name remain (leaving to the menu)
    void reset();

    SessionState state() const override;
    const char* endReason() const override;
    bool isHost() const override;
    bool isOffline() const override;
    u8 localPlayer() const override;
    u32 playerCount() const override;      // match player count (confirmed after Running)
    u32 lobbyPlayerCount() const override; // lobby player count
    u32 maxPlayers() const override;
    u64 seed() const override;
    u32 matchData() const override;
    u32 inputDelay() const override;

    bool canExecute(u32 tick) const override;
    const TickInputs& inputs(u32 tick) const override;
    // Call right after running tick T.
    void tickExecuted(u32 tick, u64 stateHash) override;
    // Players connected during the match (bit = player index, as of executed ticks: changes when connect/disconnect commands execute)
    u32 connectedMask() const override;
    // Host migration: when the host leaves (Handoff) or is silent for 3 seconds mid-match, the next person on the succession list takes over as host (isHost() changes).
    // hostAddress: the current host when a client (account id for Steam), successorAddress: the next host when host (to match the lobby owner)
    u32 hostMigrations() const override;
    Address hostAddress() const;
    Address successorAddress() const;

    // Late join (host): a snapshot is needed for the joiner. The game provides it between ticks with provideSnapshot(next tick to run, bytes)
    bool snapshotWanted() const override;
    void provideSnapshot(u32 tick, const std::vector<u8>& bytes) override;
    // Late join (client): the first tick of Running (0 if started from the beginning). The game takes the snapshot bytes once
    u32 joinTick() const override;
    bool takeJoinSnapshot(std::vector<u8>& out) override;
    // Catching up on confirmed ticks after joining: the game runs many per frame, and my input is sent only after catching up
    bool catchingUp() const override;
    // Submits local input for tick (executed tick + inputDelay).
    void submitLocalInput(u32 tick, const PlayerInput& input) override;
    // Sends a confirmed command (only when Running, size 1..kMaxCommandBytes). It goes into the next tick the host confirms. false if the queue is full.
    bool submitCommand(const void* data, u32 size) override;

    // Chat (lobby/mid-match, outside ticks): sends one line (cut to kMaxChatBytes). The host distributes to everyone in order, resending until acknowledged.
    // false for empty lines or sending faster than kChatInterval. Not included in input recordings/replays
    bool sendChat(const std::string& text) override;
    const std::vector<ChatMessage>& chatLog() const override; // in received order, the last kChatLogSize lines (including mine)

    bool desynced() const override;
    u32 desyncTick() const override;
    const SessionStats& stats() const override;
    // Per-player round-trip time to the host (ms, measured by the host during lobby/match and distributed to everyone. 0 for the host)
    u32 pingMs(u32 player) const override;
    // The match is stalled waiting for these players' inputs (bit = player index, only when stalled over 0.15 s).
    // Clients get the value the host reported; if the host's bundles haven't come for over 0.3 s, the host (bit 0)
    u32 waitingFor() const override;

private:
    struct Impl;
    Impl* m;
};

} // namespace mealkit::net
