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

#include "service_info_profile_new_fuzzer.h"
#include <cstddef>
#include <cstdint>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include "service_info_profile_new.h"
#include "dp_parcel.h"

namespace OHOS {
namespace DistributedDeviceProfile {

void MarshallingFuzzTest(const uint8_t* data, size_t size)
{
    const size_t minDataSize = sizeof(int64_t) * 2 + 1;
    if (data == nullptr || (size < minDataSize)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    ServiceInfoProfileNew profile;
    profile.SetServiceId(fdp.ConsumeIntegral<int64_t>());
    profile.SetServiceType(fdp.ConsumeRandomLengthString());
    OHOS::MessageParcel parcel;
    profile.Marshalling(parcel);
}

void UnMarshallingFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    OHOS::MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    ServiceInfoProfileNew profile;
    profile.UnMarshalling(parcel);
}

void DumpFuzzTest(const uint8_t* data, size_t size)
{
    const size_t minDataSize = sizeof(int64_t) * 2 + 1;
    if (data == nullptr || (size < minDataSize)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    ServiceInfoProfileNew profile;
    profile.SetServiceId(fdp.ConsumeIntegral<int64_t>());
    profile.SetServiceType(fdp.ConsumeRandomLengthString());
    profile.dump();
}

} // namespace DistributedDeviceProfile
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedDeviceProfile::MarshallingFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::UnMarshallingFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::DumpFuzzTest(data, size);
    return 0;
}