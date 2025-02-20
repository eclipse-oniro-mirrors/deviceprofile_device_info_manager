/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_DP_SESSION_KEY_MANAGER_H
#define OHOS_DP_SESSION_KEY_MANAGER_H

#include <string>
#include <random>
#include <chrono>
#include <cstdint>

#include "distributed_device_profile_constants.h"
#include "single_instance.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class SessionKeyManager {
    DECLARE_SINGLE_INSTANCE(SessionKeyManager);
public:
    int32_t PutSessionKey(uint32_t userId, const std::vector<uint8_t>& sessionKey, int32_t& sessionKeyId);
    int32_t GetSessionKey(uint32_t userId, int32_t sessionKeyId, std::vector<uint8_t>& sessionKey);
    int32_t UpdateSessionKey(uint32_t userId, int32_t sessionKeyId, const std::vector<uint8_t>& sessionKey);
    int32_t DeleteSessionKey(uint32_t userId, int32_t sessionKeyId);

private:
    void GeneratedSessionKeyId(uint32_t userId, int32_t& sessionKeyId);
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // OHOS_DP_SESSION_KEY_MANAGER_H
