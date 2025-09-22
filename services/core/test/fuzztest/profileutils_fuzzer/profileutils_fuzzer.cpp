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

#include <fuzzer/FuzzedDataProvider.h>

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

void ProfileUtilsFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int64_t))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    std::string dbKey = fdp.ConsumeRandomLengthString();
    std::string str = fdp.ConsumeRandomLengthString();
    std::string prefix = fdp.ConsumeRandomLengthString();
    std::string splits = fdp.ConsumeRandomLengthString();
    std::vector<std::string> res;
    std::string deviceId = fdp.ConsumeRandomLengthString();
    std::string serviceName = fdp.ConsumeRandomLengthString();
    std::string charKey = fdp.ConsumeRandomLengthString();
    std::string profileProperty = fdp.ConsumeRandomLengthString();
    std::string profileKey = fdp.ConsumeRandomLengthString();

    ProfileUtils::GetProfileType(dbKey);
    ProfileUtils::StartsWith(str, prefix);
    ProfileUtils::IsKeyValid(dbKey);
    ProfileUtils::GenerateDeviceProfileKey(deviceId);
    ProfileUtils::GenerateServiceProfileKey(deviceId, serviceName);
    ProfileUtils::GenerateCharProfileKey(deviceId, serviceName, charKey);
    ProfileUtils::GenerateDBKey(profileKey, profileProperty);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedDeviceProfile::ProfileUtilsFuzzTest(data, size);
    return 0;
}
