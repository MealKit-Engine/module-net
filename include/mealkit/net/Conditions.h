#pragma once

#include "mealkit/core/Types.h"
#include "mealkit/net/Transport.h"

#include <memory>

// Network condition simulation (ROADMAP stage 1 "Simulating network conditions"): creates distant peers, jittery connections, and packet loss in same-PC tests.
//   --net-lag <ms>      increases the round-trip time of this process's connections (half on send, half on receive)
//   --net-jitter <ms>   jitters each packet's delay by 0..jitter ms more (order can change, like the real internet)
//   --net-loss <%>      drops each sent and received packet with this probability (takes the same retransmit/duplicate send paths as real loss)
// It's a wrapper over the transport layer (UDP, Steam), so the lockstep session is unchanged. Unrelated to determinism (only delivery timing changes).
namespace mealkit::net {

struct NetConditions {
    f32 lagMs = 0.0f;
    f32 jitterMs = 0.0f;
    f32 lossPercent = 0.0f;
    bool active() const { return lagMs > 0.0f || jitterMs > 0.0f || lossPercent > 0.0f; }
};

// If conditions are inactive, returns inner as is
std::unique_ptr<Transport> withConditions(std::unique_ptr<Transport> inner, const NetConditions& conditions);

} // namespace mealkit::net
