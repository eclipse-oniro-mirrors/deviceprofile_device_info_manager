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
#include <fuzzer/FuzzedDataProvider.h>
#include "distributed_device_profile_client.h"
#include "service_info_profile_new.h"

namespace OHOS {
namespace DistributedDeviceProfile {

void PutServiceInfoProfileNewFuzzTest(FuzzedDataProvider &fdp)
{
    ServiceInfoProfileNew profile;

    profile.SetServiceId(fdp.ConsumeIntegral<int64_t>());
    profile.SetServiceType(fdp.ConsumeRandomLengthString());
    DistributedDeviceProfileClient::GetInstance().PutServiceInfoProfile(profile);
}

void DeleteServiceInfoProfileNewFuzzTest(FuzzedDataProvider &fdp)
{
    int32_t regServiceId = fdp.ConsumeIntegral<int32_t>();
    int32_t userId = fdp.ConsumeIntegral<int32_t>();
    DistributedDeviceProfileClient::GetInstance().DeleteServiceInfoProfile(regServiceId, userId);
}

void GetServiceInfoProfileByServiceIdFuzzTest(FuzzedDataProvider &fdp)
{
    int32_t serviceId = fdp.ConsumeIntegral<int64_t>();
    ServiceInfoProfileNew profile;

    profile.SetServiceId(fdp.ConsumeIntegral<int64_t>());
    profile.SetServiceType(fdp.ConsumeRandomLengthString());
    DistributedDeviceProfileClient::GetInstance().GetServiceInfoProfileByServiceId(serviceId, profile);
}

void GetServiceInfoProfileByTokenIdFuzzTest(FuzzedDataProvider &fdp)
{
    int32_t tokenId = fdp.ConsumeIntegral<int64_t>();
    ServiceInfoProfileNew profile;

    profile.SetServiceId(fdp.ConsumeIntegral<int64_t>());
    profile.SetServiceType(fdp.ConsumeRandomLengthString());
    DistributedDeviceProfileClient::GetInstance().GetServiceInfoProfileByTokenId(tokenId, profile);
}
} // namespace DistributedDeviceProfile
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    size_t maxDataSize = sizeof(int64_t) * 2;
    if (!data || size < maxDataSize) {
        return 0;
    }
    FuzzedDataProvider fdp(data, size);
    OHOS::DistributedDeviceProfile::PutServiceInfoProfileNewFuzzTest(fdp);
    OHOS::DistributedDeviceProfile::DeleteServiceInfoProfileNewFuzzTest(fdp);
    OHOS::DistributedDeviceProfile::GetServiceInfoProfileByServiceIdFuzzTest(fdp);
    OHOS::DistributedDeviceProfile::GetServiceInfoProfileByTokenIdFuzzTest(fdp);
    return 0;
}