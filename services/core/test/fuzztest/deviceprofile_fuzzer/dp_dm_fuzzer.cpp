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

#include "dp_device_manager.h"

#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include <cstdlib>
#include <fcntl.h>
#include <string>

namespace OHOS {
namespace DeviceProfile {
void FuzzDeviceManager(const uint8_t* data, size_t size)
{
    DpDeviceManager::GetInstance().Init();
    DpDeviceManager::GetInstance().ConnectDeviceManager();
}

void FuzzDeviceManagerGetUdidByNetworkId(const uint8_t* data, size_t size)
{
    std::string udid;
    std::string networkId(reinterpret_cast<const char*>(data), size);
    DpDeviceManager::GetInstance().GetUdidByNetworkId(networkId, udid);
}

void FuzzDeviceManagerGetUuidByNetworkId(const uint8_t* data, size_t size)
{
    std::string uuid;
    std::string udid;
    std::string networkId(reinterpret_cast<const char*>(data), size);
    DpDeviceManager::GetInstance().GetLocalDeviceUdid(udid);
    DpDeviceManager::GetInstance().GetUuidByNetworkId(networkId, uuid);
}

void FuzzDeviceManagerRemoveDeviceIdsByUdid(const uint8_t* data, size_t size)
{
    std::string udid(reinterpret_cast<const char*>(data), size);
    DpDeviceManager::GetInstance().RemoveDeviceIdsByUdid(udid);
}

void FuzzDeviceManagerTransformDeviceId(const uint8_t* data, size_t size)
{
    std::string queryUdid;
    std::string udid(reinterpret_cast<const char*>(data), size);
    DpDeviceManager::GetInstance().TransformDeviceId(udid, queryUdid, DeviceIdType::UDID);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DeviceProfile::FuzzDeviceManager(data, size);
    OHOS::DeviceProfile::FuzzDeviceManagerGetUdidByNetworkId(data, size);
    OHOS::DeviceProfile::FuzzDeviceManagerGetUuidByNetworkId(data, size);
    OHOS::DeviceProfile::FuzzDeviceManagerRemoveDeviceIdsByUdid(data, size);
    OHOS::DeviceProfile::FuzzDeviceManagerTransformDeviceId(data, size);
    return 0;
}

