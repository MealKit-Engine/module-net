#pragma once

#include "mealkit/net/Transport.h"

#include <memory>
#include <string>

// Rooms on a relay server (the engine's tools/relay.py, protocol there): how browser builds play together (a browser has no UDP),
// and how desktop builds play with them. Players connect over a WebSocket and the relay passes lockstep packets between the
// members of a room. A room has a code the relay chose and an owner, the lockstep host (handed on when the host leaves).
// Nothing blocks: call update until state is InRoom, then open the session with createTransport (host: LockstepSession::hostWith
// when isOwner, others joinWith(transport, ownerAddress())). There are no accounts or invites; players give each other the code.
namespace mealkit::net {

struct RelayLink;

// true for what players type to enter a room: digits only. A desktop build, where [join] also takes addresses, asks for
// the six digits a relay chooses
bool parseRoomCode(const std::string& text, u64& code);

class RelayRoom {
public:
    enum class State : u8 { None, Connecting, InRoom, Failed };

    // url: "ws://host:port" or "wss://..." (browser only). Rooms are only shared between the same game
    void create(const std::string& url, const std::string& game);
    void join(const std::string& url, u64 code, const std::string& game);
    void leave(); // the connection closes once the transport is gone too (a leaving host's handoff still goes out)
    void update();
    State state() const;
    u64 code() const; // 0 until InRoom
    bool isOwner() const;
    Address ownerAddress() const;
    void setOwner(u64 userId); // owner only: matches the new owner the relay picks with the lockstep successor
    std::unique_ptr<Transport> createTransport();

private:
    void open(const std::string& url, const std::string& request);
    std::shared_ptr<RelayLink> m_link;
    bool m_failed = false; // the socket couldn't even be created
};

} // namespace mealkit::net
