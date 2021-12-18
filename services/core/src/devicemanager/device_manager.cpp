/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "device_manager.h"

#include "parameter.h"

#include "device_profile_log.h"

namespace OHOS {
namespace DeviceProfile {
namespace {
const std::string TAG = "DeviceManager";

constexpr int32_t DEVICE_ID_SIZE = 65;
}

IMPLEMENT_SINGLE_INSTANCE(DeviceManager);

bool DeviceManager::Init()
{
    return true;
}

void DeviceManager::GetLocalDeviceUdid(std::string& udid)
{
    char localDeviceId[DEVICE_ID_SIZE] = {0};
    GetDevUdid(localDeviceId, DEVICE_ID_SIZE);
    udid = localDeviceId;
}
bool DeviceManager::TransformDeviceId(const std::string& fromDeviceId,
    std::string& toDeviceId, DeviceIdType toType)
{
    return false;
}
} // namespace DeviceProfile
} // namespace OHOS
