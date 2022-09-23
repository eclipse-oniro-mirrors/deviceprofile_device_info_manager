/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "device_profile_fuzzer.h"

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

void FuzzStorageDeviceProfile(const uint8_t* data, size_t size)
{
    DeviceProfileStorageManager::GetInstance().Init();
    sleep(TIME);
}

void FuzzPutDeviceProfile(const uint8_t* data, size_t size)
{
    ServiceCharacteristicProfile profile;
    std::string serviceId(reinterpret_cast<const char*>(data), size);
    std::string serviceType(reinterpret_cast<const char*>(data), size);

    profile.SetServiceId(serviceId);
    profile.SetServiceType(serviceType);
    nlohmann::json j;
    j["testVersion"] = "3.0.0";
    j["testApiLevel"] = TEST_LEVEL;
    profile.SetCharacteristicProfileJson(j.dump());
    DeviceProfileStorageManager::GetInstance().PutDeviceProfile(profile);
}

void FuzzGetDeviceProfile(const uint8_t* data, size_t size)
{
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
}

void FuzzDeleteDeviceProfile(const uint8_t* data, size_t size)
{
    std::string serviceId(reinterpret_cast<const char*>(data), size);
    DeviceProfileStorageManager::GetInstance().DeleteDeviceProfile(serviceId);
}

void FuzzRemoveUnBoundDeviceProfile(const uint8_t* data, size_t size)
{
    std::string udid(reinterpret_cast<const char*>(data), size);
    DeviceProfileStorageManager::GetInstance().RemoveUnBoundDeviceProfile(udid);
}

void FuzzDumpLocalProfile(const uint8_t* data, size_t size)
{
    std::string result(reinterpret_cast<const char*>(data), size);
    DeviceProfileStorageManager::GetInstance().DumpLocalProfile(result);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    constexpr int32_t minSize = 0;
    constexpr int32_t maxSize = 100;
    if (size <= minSize || size > maxSize || data == nullptr) {
        return 0;
    }
    OHOS::DeviceProfile::FuzzStorageDeviceProfile(data, size);
    OHOS::DeviceProfile::FuzzPutDeviceProfile(data, size);
    OHOS::DeviceProfile::FuzzGetDeviceProfile(data, size);
    OHOS::DeviceProfile::FuzzDeleteDeviceProfile(data, size);
    OHOS::DeviceProfile::FuzzRemoveUnBoundDeviceProfile(data, size);
    OHOS::DeviceProfile::FuzzDumpLocalProfile(data, size);
    return 0;
}

