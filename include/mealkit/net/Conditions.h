#pragma once

#include "mealkit/core/Types.h"
#include "mealkit/net/Transport.h"

#include <memory>

// 네트워크 상태 흉내 (ROADMAP 1단계 "네트워크 상태 흉내 내기"): 같은 PC 시험에서 먼 상대·흔들리는 연결·패킷 손실을 만든다.
//   --net-lag <ms>      이 프로세스 연결의 왕복 시간을 늘린다 (보낼 때와 받을 때 반씩)
//   --net-jitter <ms>   패킷마다 지연을 0..jitter ms 더 흔든다 (순서가 바뀔 수 있다, 실제 인터넷처럼)
//   --net-loss <%>      보내고 받는 패킷마다 이 확률로 버린다 (실제 손실과 같은 재전송·중복 전송 길을 탄다)
// 전송 계층(UDP, Steam) 위의 래퍼라 락스텝 세션은 바뀌지 않는다. 결정론과 무관하다 (전달 시점만 바뀐다).
namespace mealkit::net {

struct NetConditions {
    f32 lagMs = 0.0f;
    f32 jitterMs = 0.0f;
    f32 lossPercent = 0.0f;
    bool active() const { return lagMs > 0.0f || jitterMs > 0.0f || lossPercent > 0.0f; }
};

// conditions가 비활성이면 inner를 그대로 돌려준다
std::unique_ptr<Transport> withConditions(std::unique_ptr<Transport> inner, const NetConditions& conditions);

} // namespace mealkit::net
