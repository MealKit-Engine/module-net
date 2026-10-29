#include "mealkit/net/Conditions.h"

#include "mealkit/core/Clock.h"
#include "mealkit/core/Log.h"
#include "mealkit/core/Random.h"

#include <algorithm>
#include <cstring>
#include <vector>

namespace mealkit::net {
namespace {

struct Delayed {
    f64 due = 0.0;
    Address address;
    std::vector<u8> data;
};

class ConditionedTransport final : public Transport {
public:
    ConditionedTransport(std::unique_ptr<Transport> inner, const NetConditions& c)
        : m_inner(std::move(inner)), m_c(c), m_rng(static_cast<u64>(nowSeconds() * 1000003.0)) {
        MEALKIT_INFO("Network conditions: +%.0f ms round trip, %.0f ms jitter, %.1f%% loss", c.lagMs, c.jitterMs, c.lossPercent);
    }

    bool send(const Address& to, const void* data, u32 size) override {
        flushOut();
        if (drop()) return true; // as if sent (UDP can't know anyway)
        m_out.push_back({nowSeconds() + delay(), to, {static_cast<const u8*>(data), static_cast<const u8*>(data) + size}});
        flushOut();
        return true;
    }

    i32 receive(Address& from, void* buffer, u32 capacity) override {
        flushOut();
        u8 packet[2048];
        Address source;
        i32 n;
        while ((n = m_inner->receive(source, packet, sizeof(packet))) >= 0) // everything received goes to the delay queue
            if (!drop()) m_in.push_back({nowSeconds() + delay(), source, {packet, packet + n}});
        const f64 now = nowSeconds();
        auto due = std::min_element(m_in.begin(), m_in.end(), [](const Delayed& a, const Delayed& b) { return a.due < b.due; });
        if (due == m_in.end() || due->due > now) return -1;
        const u32 size = std::min<u32>(capacity, static_cast<u32>(due->data.size()));
        std::memcpy(buffer, due->data.data(), size);
        from = due->address;
        m_in.erase(due);
        return static_cast<i32>(size);
    }

private:
    bool drop() { return m_c.lossPercent > 0.0f && m_rng.next01() * 100.0f < m_c.lossPercent; }
    // One-way delay (seconds): half the round trip + jitter
    f64 delay() { return (m_c.lagMs * 0.5f + m_rng.next01() * m_c.jitterMs) / 1000.0; }

    void flushOut() {
        const f64 now = nowSeconds();
        for (size_t i = 0; i < m_out.size();) {
            if (m_out[i].due <= now) {
                m_inner->send(m_out[i].address, m_out[i].data.data(), static_cast<u32>(m_out[i].data.size()));
                m_out.erase(m_out.begin() + static_cast<std::ptrdiff_t>(i));
            } else {
                ++i;
            }
        }
    }

    std::unique_ptr<Transport> m_inner;
    NetConditions m_c;
    Pcg32 m_rng; // outside the simulation (only changes delivery timing)
    std::vector<Delayed> m_out, m_in;
};

} // namespace

std::unique_ptr<Transport> withConditions(std::unique_ptr<Transport> inner, const NetConditions& conditions) {
    if (!inner || !conditions.active()) return inner;
    return std::make_unique<ConditionedTransport>(std::move(inner), conditions);
}

} // namespace mealkit::net
