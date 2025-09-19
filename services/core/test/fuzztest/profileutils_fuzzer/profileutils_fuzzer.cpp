/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "profileutils_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include <cstdlib>
#include <fcntl.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <sys/types.h>
#include "sys/stat.h"

#include "distributed_device_profile_constants.h"
#include "profile_utils.h"
#include "service_info_profile_new.h"

namespace OHOS {
namespace DistributedDeviceProfile {

void GetProfileTypeFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int64_t) + 1 )) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    std::string dbKey = fdp.ConsumeRandomLengthString();
    ProfileUtils::GetProfileType(dbKey);
}

void StartsWithFuzzTest(const uint8_t* data, size_t size)
{
    const int32_t minSize = sizeof(int64_t) * 2 + 1;
    if ((data == nullptr) || (size < minSize)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    std::string str = fdp.ConsumeRandomLengthString();
    std::string prefix = fdp.ConsumeRandomLengthString();
    ProfileUtils::StartsWith(str, prefix);
}

void SplitStringFuzzTest(const uint8_t* data, size_t size)
{
    const int32_t minSize = sizeof(int64_t) * 3 + 1;
    if ((data == nullptr) || (size < minSize)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    std::string str = fdp.ConsumeRandomLengthString();
    std::string splits = fdp.ConsumeRandomLengthString();
    std::vector<std::string> res;
    std::string strs = fdp.ConsumeRandomLengthString();
    res.push_back(strs);
    ProfileUtils::SplitString(str, splits, res);
}

void IsKeyValidFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int64_t) + 1 )) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    std::string dbKey = fdp.ConsumeRandomLengthString();
    ProfileUtils::IsKeyValid(dbKey);
}

void GenerateDeviceProfileKeyFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int64_t) + 1 )) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    std::string deviceId = fdp.ConsumeRandomLengthString();
    ProfileUtils::GenerateDeviceProfileKey(deviceId);
}

void GenerateServiceProfileKeyFuzzTest(const uint8_t* data, size_t size)
{
    const int32_t minSize = sizeof(int64_t) * 2 + 1;
    if ((data == nullptr) || (size < minSize)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    std::string deviceId = fdp.ConsumeRandomLengthString();
    std::string serviceName = fdp.ConsumeRandomLengthString();
    ProfileUtils::GenerateServiceProfileKey(deviceId, serviceName);
}

void GenerateCharProfileKeyFuzzTest(const uint8_t* data, size_t size)
{
    const int32_t minSize = sizeof(int64_t) * 3 + 1;
    if ((data == nullptr) || (size < minSize)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    std::string deviceId = fdp.ConsumeRandomLengthString();
    std::string serviceName = fdp.ConsumeRandomLengthString();
    std::string charKey = fdp.ConsumeRandomLengthString();
    ProfileUtils::GenerateCharProfileKey(deviceId, serviceName, charKey);
}

void GenerateDBKeyFuzzTest(const uint8_t* data, size_t size)
{
    const int32_t minSize = sizeof(int64_t) * 2 + 1;
    if ((data == nullptr) || (size < minSize)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    std::string profileProperty = fdp.ConsumeRandomLengthString();
    std::string profileKey = fdp.ConsumeRandomLengthString();

    ProfileUtils::GenerateDBKey(profileKey, profileProperty);
}

void ServiceInfoProfileToEntriesFuzzTest(const uint8_t* data, size_t size)
{
    const int32_t minSize = sizeof(int64_t) * 2 + 1;
    if ((data == nullptr) || (size < minSize)) {
        return;
    }
    ServiceInfoProfileNew profile;
    FuzzedDataProvider fdp(data, size);
    std::string key = fdp.ConsumeRandomLengthString();
    std::string value = fdp.ConsumeRandomLengthString();
    std::map<std::string, std::string> values = {{key, value}};

    ProfileUtils::ServiceInfoProfileToEntries(profile, values);
}

void GenerateServiceDBKeyFuzzTest(const uint8_t* data, size_t size)
{
    const int32_t minSize = sizeof(int64_t) * 2 + sizeof(int32_t) + 1;
    if ((data == nullptr) || (size < minSize)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    std::string regServiceId = fdp.ConsumeRandomLengthString();
    std::string trailInfo = fdp.ConsumeRandomLengthString();
    int32_t userId = fdp.ConsumeIntegral<int32_t>();

    ProfileUtils::GenerateServiceDBKey(regServiceId, trailInfo, userId);
}

void GenerateServiceInfoProfilekeysFuzzTest(const uint8_t* data, size_t size)
{
    const int32_t minSize = sizeof(int64_t) * 2 + sizeof(int32_t) + 1;
    if ((data == nullptr) || (size < minSize)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    std::string regServiceId = fdp.ConsumeRandomLengthString();
    std::vector<std::string> res;
    std::string strs = fdp.ConsumeRandomLengthString();
    res.push_back(strs);
    int32_t userId = fdp.ConsumeIntegral<int32_t>();

    ProfileUtils::GenerateServiceInfoProfilekeys(regServiceId, res, userId);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedDeviceProfile::GetProfileTypeFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::StartsWithFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::SplitStringFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::IsKeyValidFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::GenerateDeviceProfileKeyFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::GenerateServiceProfileKeyFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::GenerateCharProfileKeyFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::GenerateDBKeyFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::ServiceInfoProfileToEntriesFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::GenerateServiceDBKeyFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::GenerateServiceInfoProfilekeysFuzzTest(data, size);
    return 0;
}
