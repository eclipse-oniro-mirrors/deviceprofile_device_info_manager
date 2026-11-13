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

#include "local_switch_profile_mock.h"

#include "distributed_device_profile_errors.h"
#include "profile_cache.h"
#include "switch_adapter.h"

namespace OHOS {
namespace DistributedDeviceProfile {
// Only linked into RefreshLocalSwitchProfileTest, which excludes the service SO.
IMPLEMENT_SINGLE_INSTANCE(ProfileCache);
IMPLEMENT_SINGLE_INSTANCE(SwitchAdapter);

namespace TestMock {
thread_local LocalSwitchProfileMock* ScopedLocalSwitchProfileMock::current_ = nullptr;

ScopedLocalSwitchProfileMock::ScopedLocalSwitchProfileMock(LocalSwitchProfileMock& mock) : previous_(current_)
{
    current_ = &mock;
}

ScopedLocalSwitchProfileMock::~ScopedLocalSwitchProfileMock()
{
    current_ = previous_;
}

LocalSwitchProfileMock* ScopedLocalSwitchProfileMock::Current()
{
    return current_;
}

}  // namespace TestMock

std::string ProfileCache::GetLocalNetworkId()
{
    auto* mock = TestMock::ScopedLocalSwitchProfileMock::Current();
    if (mock == nullptr) {
        ADD_FAILURE() << "Local identity Mock is not installed";
        return {};
    }
    return mock->GetLocalNetworkId();
}

std::string ProfileCache::GetLocalUdid()
{
    auto* mock = TestMock::ScopedLocalSwitchProfileMock::Current();
    if (mock == nullptr) {
        ADD_FAILURE() << "Local identity Mock is not installed";
        return {};
    }
    return mock->GetLocalUdid();
}

int32_t SwitchAdapter::GetSwitch(const std::string& appId, const std::string& networkId, uint32_t& value,
                                 uint32_t& switchLength)
{
    ADD_FAILURE() << "Invalid parameters must not reach the database";
    return DP_GET_KV_DB_FAIL;
}

int32_t ProfileCache::GetServiceNameByPos(int32_t pos,
                                          const std::unordered_map<std::string, SwitchFlag>& switchServiceMap,
                                          std::string& serviceName)
{
    ADD_FAILURE() << "Invalid parameters must not query the switch cache";
    return DP_INVALID_PARAMS;
}

int32_t ProfileCache::AddCharProfile(const CharacteristicProfile& charProfile)
{
    ADD_FAILURE() << "Invalid parameters must not update profiles";
    return DP_INVALID_PARAMS;
}

void ProfileCache::SetCurSwitch(uint32_t newSwitch)
{
    ADD_FAILURE() << "Invalid parameters must not update the local switch";
}

uint32_t ProfileCache::GetSwitch()
{
    ADD_FAILURE() << "Invalid parameters must not read the local switch";
    return 0;
}
}  // namespace DistributedDeviceProfile
}  // namespace OHOS
