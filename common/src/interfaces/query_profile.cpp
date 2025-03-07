/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "query_profile.h"
#include "cJSON.h"
#include "distributed_device_profile_constants.h"
#include "macro_utils.h"
#include "profile_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "QueryProfile";
}

QueryProfile::QueryProfile()
    : accesserDeviceId_(""),
    accesserUserId_(-1),
    accesserTokenId_(-1),
    accesseeDeviceId_(""),
    accesseeUserId_(-1),
    accesseeTokenId_(-1)
    
{}

std::string QueryProfile::GetAccesserDeviceId() const
{
    return accesserDeviceId_;
}

void QueryProfile::SetAccesserDeviceId(const std::string& accesserDeviceId)
{
    accesserDeviceId_ = accesserDeviceId;
}

int64_t QueryProfile::GetAccesserTokenId() const
{
    return accesserTokenId_;
}

void QueryProfile::SetAccesserTokenId(int64_t accesserTokenId)
{
    accesserTokenId_ = accesserTokenId;
}

int32_t QueryProfile::GetAccesserUserId() const
{
    return accesserUserId_;
}

void QueryProfile::SetAccesserUserId(int32_t accesserUserId)
{
    accesserUserId_ = accesserUserId;
}

std::string QueryProfile::GetAccesseeDeviceId() const
{
    return accesseeDeviceId_;
}

void QueryProfile::SetAccesseeDeviceId(const std::string& accesseeDeviceId)
{
    accesseeDeviceId_ = accesseeDeviceId;
}

int64_t QueryProfile::GetAccesseeTokenId() const
{
    return accesseeTokenId_;
}

void QueryProfile::SetAccesseeTokenId(int64_t accesseeTokenId)
{
    accesseeTokenId_ = accesseeTokenId;
}

int32_t QueryProfile::GetAccesseeUserId() const
{
    return accesseeUserId_;
}

void QueryProfile::SetAccesseeUserId(int32_t accesseeUserId)
{
    accesseeUserId_ = accesseeUserId;
}

bool QueryProfile::Marshalling(MessageParcel& parcel) const
{
    WRITE_HELPER_RET(parcel, String, accesserDeviceId_, false);
    WRITE_HELPER_RET(parcel, Int32, accesserUserId_, false);
    WRITE_HELPER_RET(parcel, Int64, accesserTokenId_, false);
    WRITE_HELPER_RET(parcel, String, accesseeDeviceId_, false);
    WRITE_HELPER_RET(parcel, Int32, accesseeUserId_, false);
    WRITE_HELPER_RET(parcel, Int64, accesseeTokenId_, false);
    return true;
}

bool QueryProfile::UnMarshalling(MessageParcel& parcel)
{
    READ_HELPER_RET(parcel, String, accesserDeviceId_, false);
    READ_HELPER_RET(parcel, Int32, accesserUserId_, false);
    READ_HELPER_RET(parcel, Int64, accesserTokenId_, false);
    READ_HELPER_RET(parcel, String, accesseeDeviceId_, false);
    READ_HELPER_RET(parcel, Int32, accesseeUserId_, false);
    READ_HELPER_RET(parcel, Int64, accesseeTokenId_, false);
    return true;
}

std::string QueryProfile::dump() const
{
    cJSON* json = cJSON_CreateObject();
    if (!cJSON_IsObject(json)) {
        cJSON_Delete(json);
        return EMPTY_STRING;
    }
    cJSON_AddStringToObject(json, ACCESSER_DEVICE_ID.c_str(), ProfileUtils::GetAnonyString(accesserDeviceId_).c_str());
    cJSON_AddStringToObject(json, ACCESSER_USER_ID.c_str(),
        ProfileUtils::GetAnonyString(std::to_string(accesserUserId_)).c_str());
    cJSON_AddNumberToObject(json, ACCESSER_TOKEN_ID.c_str(), accesserTokenId_);
    cJSON_AddStringToObject(json, ACCESSEE_DEVICE_ID.c_str(), ProfileUtils::GetAnonyString(accesseeDeviceId_).c_str());
    cJSON_AddStringToObject(json, ACCESSEE_USER_ID.c_str(),
        ProfileUtils::GetAnonyString(std::to_string(accesseeUserId_)).c_str());
    cJSON_AddNumberToObject(json, ACCESSEE_TOKEN_ID.c_str(), accesseeTokenId_);
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