/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_DP_LOCAL_SWITCH_PROFILE_MOCK_H
#define OHOS_DP_LOCAL_SWITCH_PROFILE_MOCK_H

#include <string>

#include "gmock/gmock.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace TestMock {
class LocalSwitchProfileMock {
public:
    MOCK_METHOD(std::string, GetLocalNetworkId, ());
    MOCK_METHOD(std::string, GetLocalUdid, ());
};

class ScopedLocalSwitchProfileMock final {
public:
    explicit ScopedLocalSwitchProfileMock(LocalSwitchProfileMock &mock);
    ~ScopedLocalSwitchProfileMock();
    ScopedLocalSwitchProfileMock(const ScopedLocalSwitchProfileMock &) = delete;
    ScopedLocalSwitchProfileMock &operator=(const ScopedLocalSwitchProfileMock &) = delete;
    static LocalSwitchProfileMock *Current();

private:
    LocalSwitchProfileMock *const previous_;
    static thread_local LocalSwitchProfileMock *current_;
};
}  // namespace TestMock
}  // namespace DistributedDeviceProfile
}  // namespace OHOS
#endif  // OHOS_DP_LOCAL_SWITCH_PROFILE_MOCK_H
