/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <string>
#include <sys/types.h>
#include "sys/stat.h"

#include "distributed_device_profile_constants.h"
#include "profile_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {

void GetProfileTypeFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    std::string dbKey(reinterpret_cast<const char*>(data), size);
    ProfileUtils::GetProfileType(dbKey);
}

void StartsWithFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    std::string str(reinterpret_cast<const char*>(data), size);
    std::string prefix(reinterpret_cast<const char*>(data), size);
    ProfileUtils::StartsWith(str, prefix);
}

void SplitStringFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    std::string str(reinterpret_cast<const char*>(data), size);
    std::string splits(reinterpret_cast<const char*>(data), size);
    std::vector<std::string> res;
    std::string strs(reinterpret_cast<const char*>(data), size);
    res.push_back(strs);
    ProfileUtils::SplitString(str, splits, res);
}

void IsKeyValidFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    std::string dbKey(reinterpret_cast<const char*>(data), size);
    ProfileUtils::IsKeyValid(dbKey);
}

void GenerateDeviceProfileKeyFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    std::string deviceId(reinterpret_cast<const char*>(data), size);
    ProfileUtils::GenerateDeviceProfileKey(deviceId);
}

void GenerateServiceProfileKeyFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    std::string deviceId(reinterpret_cast<const char*>(data), size);
    std::string serviceName(reinterpret_cast<const char*>(data), size);
    ProfileUtils::GenerateServiceProfileKey(deviceId, serviceName);
}

void GenerateCharProfileKeyFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    std::string deviceId(reinterpret_cast<const char*>(data), size);
    std::string serviceName(reinterpret_cast<const char*>(data), size);
    std::string charKey(reinterpret_cast<const char*>(data), size);
    ProfileUtils::GenerateCharProfileKey(deviceId, serviceName, charKey);
}

void GenerateDBKeyFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    std::string profileProperty(reinterpret_cast<const char*>(data), size);
    std::string profileKey(reinterpret_cast<const char*>(data), size);

    ProfileUtils::GenerateDBKey(profileKey, profileProperty);
}

void GetUdidByNetworkIdFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    std::string networkId(reinterpret_cast<const char*>(data), size);
    std::string udid(reinterpret_cast<const char*>(data), size);
    ProfileUtils::GetUdidByNetworkId(networkId, udid);
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
    OHOS::DistributedDeviceProfile::GetUdidByNetworkIdFuzzTest(data, size);

    return 0;
}
