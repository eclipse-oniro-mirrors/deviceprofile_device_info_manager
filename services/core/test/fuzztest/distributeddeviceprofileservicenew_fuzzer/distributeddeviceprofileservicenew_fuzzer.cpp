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

#include <cstddef>
#include <cstdint>
#include <string>
#include <memory>
#include <fuzzer/FuzzedDataProvider.h>

#include "distributed_device_profile_service_new.h"
#include "service_info_profile_new.h"

namespace OHOS {
namespace DistributedDeviceProfile {

void PutServiceInfoProfileNewFuzzTest(const uint8_t* data, size_t size)
{
    int32_t maxDataSize = sizeof(int32_t) * 2  + sizeof(int64_t) * 2 + sizeof(int8_t) + 1;
    if (!data || size < maxDataSize) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    ServiceInfoProfileNew profile;
    profile.SetRegServiceId(fdp.ConsumeIntegral<int32_t>());
    profile.SetDeviceId(fdp.ConsumeRandomLengthString());
    profile.SetUserId(fdp.ConsumeIntegral<int32_t>());
    profile.SetTokenId(fdp.ConsumeIntegral<int64_t>());
    profile.SetSerPubState(fdp.ConsumeIntegral<int8_t>());
    profile.SetServiceId(fdp.ConsumeIntegral<int64_t>());
    profile.SetServiceType(fdp.ConsumeRandomLengthString());
    profile.SetServiceName(fdp.ConsumeRandomLengthString());
    profile.SetServiceDisplayName(fdp.ConsumeRandomLengthString());

    DistributedDeviceProfileServiceNew::GetInstance().PutServiceInfoProfile(profile);
}

void DeleteServiceInfoProfileNewFuzzTest(const uint8_t* data, size_t size)
{
    int32_t maxDataSize = sizeof(int32_t) * 2 + 1;
    if (!data || size < maxDataSize) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t regServiceId = fdp.ConsumeIntegral<int32_t>();
    int32_t userId = fdp.ConsumeIntegral<int32_t>();

    DistributedDeviceProfileServiceNew::GetInstance().DeleteServiceInfoProfile(regServiceId, userId);
}

void GetServiceInfoProfileByServiceIdFuzzTest(const uint8_t* data, size_t size)
{
    int32_t maxDataSize = sizeof(int64_t) * 2 + 1;
    if (!data || size < maxDataSize) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t serviceId = fdp.ConsumeIntegral<int64_t>();
    ServiceInfoProfileNew profile;

    profile.SetServiceId(fdp.ConsumeIntegral<int64_t>());
    profile.SetServiceType(fdp.ConsumeRandomLengthString());
    DistributedDeviceProfileServiceNew::GetInstance().GetServiceInfoProfileByServiceId(serviceId, profile);
}

void GetServiceInfoProfileByTokenIdFuzzTest(const uint8_t* data, size_t size)
{
    int32_t maxDataSize = sizeof(int64_t) * 2 + 1;
    if (!data || size < maxDataSize) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t tokenId = fdp.ConsumeIntegral<int64_t>();
    ServiceInfoProfileNew profile;

    profile.SetServiceId(fdp.ConsumeIntegral<int64_t>());
    profile.SetServiceType(fdp.ConsumeRandomLengthString());
    DistributedDeviceProfileServiceNew::GetInstance().GetServiceInfoProfileByTokenId(tokenId, profile);
}
} // namespace DistributedDeviceProfile
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedDeviceProfile::PutServiceInfoProfileNewFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::DeleteServiceInfoProfileNewFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::GetServiceInfoProfileByServiceIdFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::GetServiceInfoProfileByTokenIdFuzzTest(data, size);
    return 0;
}