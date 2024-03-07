/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "dp_sync_options.h"
#include "cJSON.h"
#include "macro_utils.h"
#include "profile_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "DpSyncOptions";
}

std::vector<std::string> DpSyncOptions::GetDeviceList() const
{
    return syncDeviceIds_;
}

void DpSyncOptions::AddDevice(const std::string& deviceId)
{
    syncDeviceIds_.emplace_back(deviceId);
}

SyncMode DpSyncOptions::GetSyncMode() const
{
    return syncMode_;
}

void DpSyncOptions::SetSyncMode(SyncMode mode)
{
    syncMode_ = mode;
}

bool DpSyncOptions::Marshalling(MessageParcel& parcel) const
{
    WRITE_HELPER_RET(parcel, Int32, static_cast<int32_t>(syncMode_), false);
    WRITE_HELPER_RET(parcel, Int32, static_cast<int32_t>(syncDeviceIds_.size()), false);
    for (const auto& deviceId : syncDeviceIds_) {
        WRITE_HELPER_RET(parcel, String, deviceId, false);
    }
    return true;
}

bool DpSyncOptions::UnMarshalling(MessageParcel& parcel)
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

std::string DpSyncOptions::dump() const
{
    cJSON* json = cJSON_CreateObject();
    if(!cJSON_IsObject(json)) {
        cJSON_Delete(json);
        return EMPTY_STRING;
    }
    cJSON_AddNumberToObject(json, SYNC_MODE.c_str(), static_cast<int64_t>(syncMode_));
    cJSON* jsonArr = cJSON_CreateArray();
     if(!cJSON_IsArray(jsonArr)) {
        cJSON_Delete(jsonArr);
    } else {
        for (const auto& deviceId : syncDeviceIds_) {
            cJSON_AddItemToArray(jsonArr, cJSON_CreateString(deviceId.c_str()));
        }
        cJSON_AddItemToObject(json, SYNC_DEVICE_IDS.c_str(), jsonArr);
    }
    char* jsonChars = cJSON_PrintUnformatted(json);
    if (jsonChars == NULL) {
        cJSON_Delete(json);
        HILOGE("cJSON formatted to string failed!");
        return EMPTY_STRING;
    }
    std::string jsonStr = jsonChars;
    cJSON_Delete(json);
    free(jsonChars);
    return jsonStr;
}
} // namespace DistributedDeviceProfile
} // namespace OHOS