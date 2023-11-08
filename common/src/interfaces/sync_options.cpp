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

#include "sync_options.h"
#include "macro_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "SyncOptions";
}

std::vector<std::string> SyncOptions::GetDeviceList() const
{
    return syncDeviceIds_;
}

void SyncOptions::AddDevice(const std::string& deviceId)
{
    syncDeviceIds_.emplace_back(deviceId);
}

SyncMode SyncOptions::GetSyncMode() const
{
    return syncMode_;
}

void SyncOptions::SetSyncMode(SyncMode mode)
{
    syncMode_ = mode;
}

bool SyncOptions::Marshalling(MessageParcel& parcel) const
{
    WRITE_HELPER_RET(parcel, Int32, static_cast<int32_t>(syncMode_), false);
    WRITE_HELPER_RET(parcel, Int32, static_cast<int32_t>(syncDeviceIds_.size()), false);
    for (const auto& deviceId : syncDeviceIds_) {
        WRITE_HELPER_RET(parcel, String, deviceId, false);
    }
    return true;
}

bool SyncOptions::UnMarshalling(MessageParcel& parcel)
{
    int32_t mode = 0;
    READ_HELPER_RET(parcel, Int32, mode, false);
    syncMode_ = static_cast<SyncMode>(mode);
    int32_t size = 0;
    READ_HELPER_RET(parcel, Int32, size, false);
    if (size > MAX_DEVICE_SIZE) {
        return false;
    }
    for (int32_t i = 0; i < size; i++) {
        std::string deviceId;
        READ_HELPER_RET(parcel, String, deviceId, false);
        syncDeviceIds_.emplace_back(deviceId);
    }
    return true;
}

void SyncOptions::dump() const
{
    nlohmann::json json;
    json[SYNC_MODE] = static_cast<int32_t>(syncMode_);
    std::vector<std::string> syncDeviceList;
    for (const std::string& deviceId : syncDeviceIds_) {
        syncDeviceList.push_back(deviceId);
    }
    json[SYNC_DEVICE_IDS] = syncDeviceList;
    HILOGI("dump %s!", json.dump().c_str());
}
} // namespace DistributedDeviceProfile
} // namespace OHOS