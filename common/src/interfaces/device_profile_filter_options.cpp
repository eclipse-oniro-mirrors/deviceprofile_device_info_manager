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

#include "device_profile_filter_options.h"
#include "cJSON.h"
#include "distributed_device_profile_constants.h"
#include "macro_utils.h"
#include "profile_utils.h"
#include "ipc_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "DeviceProfileFilterOptions";
}
int32_t DeviceProfileFilterOptions::GetUserId() const
{
    return userId_;
}

void DeviceProfileFilterOptions::SetUserId(int32_t userId)
{
    userId_ = userId;
}

std::string DeviceProfileFilterOptions::GetAccountId() const
{
    return accountId_;
}

void DeviceProfileFilterOptions::SetAccountId(std::string accountId)
{
    accountId_ = accountId;
}

std::vector<std::string> DeviceProfileFilterOptions::GetDeviceIds() const
{
    return deviceIds_;
}

void DeviceProfileFilterOptions::SetDeviceIds(std::vector<std::string> deviceIds)
{
    deviceIds_ = deviceIds;
}

std::vector<std::string> DeviceProfileFilterOptions::GetWiseDeviceIds() const
{
    return wiseDeviceIds_;
}

void DeviceProfileFilterOptions::SetWiseDeviceIds(std::vector<std::string> wiseDeviceIds)
{
    wiseDeviceIds_ = wiseDeviceIds;
}

std::vector<int32_t> DeviceProfileFilterOptions::GetDeviceProfileIds() const
{
    return deviceProfileIds_;
}

void DeviceProfileFilterOptions::SetDeviceProfileIds(std::vector<int32_t> deviceProfileIds)
{
    deviceProfileIds_ = deviceProfileIds;
}

bool DeviceProfileFilterOptions::Marshalling(MessageParcel& parcel) const
{
    WRITE_HELPER_RET(parcel, Int32, userId_, false);
    WRITE_HELPER_RET(parcel, String, accountId_, false);
    IpcUtils::Marshalling(parcel, deviceIds_);
    IpcUtils::Marshalling(parcel, wiseDeviceIds_);
    IpcUtils::Marshalling(parcel, deviceProfileIds_);
    return true;
}

bool DeviceProfileFilterOptions::UnMarshalling(MessageParcel& parcel)
{
    READ_HELPER_RET(parcel, Int32, userId_, false);
    READ_HELPER_RET(parcel, String, accountId_, false);
    IpcUtils::UnMarshalling(parcel, deviceIds_);
    IpcUtils::UnMarshalling(parcel, wiseDeviceIds_);
    IpcUtils::UnMarshalling(parcel, deviceProfileIds_);
    return true;
}

std::string DeviceProfileFilterOptions::dump() const
{
    cJSON* json = cJSON_CreateObject();
    if (!cJSON_IsObject(json)) {
        cJSON_Delete(json);
        return EMPTY_STRING;
    }
    cJSON_AddStringToObject(json, USERID.c_str(), ProfileUtils::GetAnonyInt32(userId_).c_str());
    cJSON_AddStringToObject(json, ACCOUNTID.c_str(), ProfileUtils::GetAnonyString(accountId_).c_str());
    cJSON* jsonArr = cJSON_CreateArray();
    if (!cJSON_IsArray(jsonArr)) {
        cJSON_Delete(jsonArr);
    } else {
        for (const auto &deviceId : deviceIds_) {
            cJSON* jsonArrItem = cJSON_CreateString(ProfileUtils::GetAnonyString(deviceId).c_str());
            if (jsonArrItem == NULL) {
                continue;
            }
            if (!cJSON_AddItemToArray(jsonArr, jsonArrItem)) {
                cJSON_Delete(jsonArrItem);
                continue;
            }
        }
        if (!cJSON_AddItemToObject(json, DEVICE_ID.c_str(), jsonArr)) {
            HILOGE("cJSON formatted to string failed!");
            cJSON_Delete(jsonArr);
        }
    }
    char* jsonChars = cJSON_PrintUnformatted(json);
    if (jsonChars == NULL) {
        cJSON_Delete(json);
        HILOGE("cJSON formatted to string failed!");
        return EMPTY_STRING;
    }
    std::string jsonStr = jsonChars;
    cJSON_Delete(json);
    cJSON_free(jsonChars);
    return jsonStr;
}
} // namespace DistributedDeviceProfile
} // namespace OHOS