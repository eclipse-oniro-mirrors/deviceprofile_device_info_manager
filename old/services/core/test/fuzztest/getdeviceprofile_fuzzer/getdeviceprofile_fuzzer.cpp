/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "getdeviceprofile_fuzzer.h"

#include "device_profile_storage_manager.h"

#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include <cstdlib>
#include <fcntl.h>
#include <string>

namespace OHOS {
namespace DeviceProfile {
namespace {
    constexpr int32_t TEST_LEVEL = 8;
    constexpr int32_t TIME = 3;
}

void FuzzGetDeviceProfile(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    DeviceProfileStorageManager::GetInstance().Init();
    sleep(TIME);

    ServiceCharacteristicProfile profile;
    std::string serviceId(reinterpret_cast<const char*>(data), size);
    std::string serviceType(reinterpret_cast<const char*>(data), size);
    profile.SetServiceId(serviceId);
    profile.SetServiceType(serviceType);
    nlohmann::json j;
    j["testVersion"] = "3.0.0";
    j["testApiLevel"] = TEST_LEVEL;
    profile.SetCharacteristicProfileJson(j.dump());
    DeviceProfileStorageManager::GetInstance().GetDeviceProfile("", serviceId, profile);

    DeviceProfileStorageManager::GetInstance().DeleteDeviceProfile(serviceId);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DeviceProfile::FuzzGetDeviceProfile(data, size);
    return 0;
}

