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

#include "accessee.h"
#include "cJSON.h"
#include "distributed_device_profile_constants.h"
#include "macro_utils.h"
#include "profile_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "Accessee";
}
Accessee::Accessee()
    : accesseeId_(0),
    accesseeDeviceId_(""),
    accesseeUserId_(-1),
    accesseeAccountId_(""),
    accesseeTokenId_(-1),
    accesseeBundleName_(""),
    accesseeHapSignature_(""),
    accesseeBindLevel_(static_cast<uint32_t>(BindLevel::MIN))
{
}

int64_t Accessee::GetAccesseeId()
{
    return accesseeId_;
}

void Accessee::SetAccesseeId(int64_t accesseeId)
{
    accesseeId_ = accesseeId;
}

std::string Accessee::GetAccesseeDeviceId() const
{
    return accesseeDeviceId_;
}

void Accessee::SetAccesseeDeviceId(const std::string& accesseeDeviceId)
{
    accesseeDeviceId_ = accesseeDeviceId;
}

int32_t Accessee::GetAccesseeUserId() const
{
    return accesseeUserId_;
}

void Accessee::SetAccesseeUserId(int32_t accesseeUserId)
{
    accesseeUserId_ = accesseeUserId;
}

std::string Accessee::GetAccesseeAccountId() const
{
    return accesseeAccountId_;
}

void Accessee::SetAccesseeAccountId(const std::string& accesseeAccountId)
{
    accesseeAccountId_ = accesseeAccountId;
}

int64_t Accessee::GetAccesseeTokenId() const
{
    return accesseeTokenId_;
}

void Accessee::SetAccesseeTokenId(int64_t accesseeTokenId)
{
    accesseeTokenId_ = accesseeTokenId;
}

std::string Accessee::GetAccesseeBundleName() const
{
    return accesseeBundleName_;
}

void Accessee::SetAccesseeBundleName(const std::string& accesseeBundleName)
{
    accesseeBundleName_ = accesseeBundleName;
}

std::string Accessee::GetAccesseeHapSignature() const
{
    return accesseeHapSignature_;
}

void Accessee::SetAccesseeHapSignature(const std::string& accesseeHapSignature)
{
    accesseeHapSignature_ = accesseeHapSignature;
}

uint32_t Accessee::GetAccesseeBindLevel() const
{
    return accesseeBindLevel_;
}

void Accessee::SetAccesseeBindLevel(uint32_t accesseeBindLevel)
{
    accesseeBindLevel_ = accesseeBindLevel;
}

bool Accessee::Marshalling(MessageParcel& parcel) const
{
    WRITE_HELPER_RET(parcel, Int64, accesseeId_, false);
    WRITE_HELPER_RET(parcel, String, accesseeDeviceId_, false);
    WRITE_HELPER_RET(parcel, Int32, accesseeUserId_, false);
    WRITE_HELPER_RET(parcel, String, accesseeAccountId_, false);
    WRITE_HELPER_RET(parcel, Int64, accesseeTokenId_, false);
    WRITE_HELPER_RET(parcel, String, accesseeBundleName_, false);
    WRITE_HELPER_RET(parcel, String, accesseeHapSignature_, false);
    WRITE_HELPER_RET(parcel, Uint32, accesseeBindLevel_, false);
    return true;
}

bool Accessee::UnMarshalling(MessageParcel& parcel)
{
    READ_HELPER_RET(parcel, Int64, accesseeId_, false);
    READ_HELPER_RET(parcel, String, accesseeDeviceId_, false);
    READ_HELPER_RET(parcel, Int32, accesseeUserId_, false);
    READ_HELPER_RET(parcel, String, accesseeAccountId_, false);
    READ_HELPER_RET(parcel, Int64, accesseeTokenId_, false);
    READ_HELPER_RET(parcel, String, accesseeBundleName_, false);
    READ_HELPER_RET(parcel, String, accesseeHapSignature_, false);
    READ_HELPER_RET(parcel, Uint32, accesseeBindLevel_, false);
    return true;
}

std::string Accessee::dump() const
{
    cJSON* json = cJSON_CreateObject();
    if (!cJSON_IsObject(json)) {
        cJSON_Delete(json);
        return EMPTY_STRING;
    }
    cJSON_AddNumberToObject(json, ACCESSEE_ID.c_str(), accesseeId_);
    cJSON_AddStringToObject(json, ACCESSEE_DEVICE_ID.c_str(),
        ProfileUtils::GetAnonyString(accesseeDeviceId_).c_str());
    cJSON_AddNumberToObject(json, ACCESSEE_USER_ID.c_str(),
        ProfileUtils::GetAnonyString(std::to_string(accesseeUserId_)).c_str());
    cJSON_AddStringToObject(json, ACCESSEE_ACCOUNT_ID.c_str(),
        ProfileUtils::GetAnonyString(accesseeAccountId_).c_str());
    cJSON_AddNumberToObject(json, ACCESSEE_TOKEN_ID.c_str(), accesseeTokenId_);
    cJSON_AddStringToObject(json, ACCESSEE_BUNDLE_NAME.c_str(), accesseeBundleName_.c_str());
    cJSON_AddStringToObject(json, ACCESSEE_HAP_SIGNATURE.c_str(), accesseeHapSignature_.c_str());
    cJSON_AddNumberToObject(json, ACCESSEE_BIND_LEVEL.c_str(), accesseeBindLevel_);
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