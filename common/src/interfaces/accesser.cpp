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

#include "accesser.h"
#include "cJSON.h"
#include "distributed_device_profile_constants.h"
#include "macro_utils.h"
#include "profile_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "Accesser";
}
Accesser::Accesser()
    : accesserId_(0),
    accesserDeviceId_(""),
    accesserUserId_(-1),
    accesserAccountId_(""),
    accesserTokenId_(-1),
    accesserBundleName_(""),
    accesserHapSignature_(""),
    accesserBindLevel_(static_cast<uint32_t>(BindLevel::MIN))
{
}

int64_t Accesser::GetAccesserId()
{
    return accesserId_;
}

void Accesser::SetAccesserId(int64_t accesserId)
{
    accesserId_ = accesserId;
}

std::string Accesser::GetAccesserDeviceId() const
{
    return accesserDeviceId_;
}

void Accesser::SetAccesserDeviceId(const std::string& accesserDeviceId)
{
    accesserDeviceId_ = accesserDeviceId;
}

int32_t Accesser::GetAccesserUserId() const
{
    return accesserUserId_;
}

void Accesser::SetAccesserUserId(int32_t accesserUserId)
{
    accesserUserId_ = accesserUserId;
}

std::string Accesser::GetAccesserAccountId() const
{
    return accesserAccountId_;
}

void Accesser::SetAccesserAccountId(const std::string& accesserAccountId)
{
    accesserAccountId_ = accesserAccountId;
}

int64_t Accesser::GetAccesserTokenId() const
{
    return accesserTokenId_;
}

void Accesser::SetAccesserTokenId(int64_t accesserTokenId)
{
    accesserTokenId_ = accesserTokenId;
}

std::string Accesser::GetAccesserBundleName() const
{
    return accesserBundleName_;
}

void Accesser::SetAccesserBundleName(const std::string& accesserBundleName)
{
    accesserBundleName_ = accesserBundleName;
}

std::string Accesser::GetAccesserHapSignature() const
{
    return accesserHapSignature_;
}

void Accesser::SetAccesserHapSignature(const std::string& accesserHapSignature)
{
    accesserHapSignature_ = accesserHapSignature;
}

uint32_t Accesser::GetAccesserBindLevel() const
{
    return accesserBindLevel_;
}

void Accesser::SetAccesserBindLevel(uint32_t accesserBindLevel)
{
    accesserBindLevel_ = accesserBindLevel;
}

bool Accesser::Marshalling(MessageParcel& parcel) const
{
    WRITE_HELPER_RET(parcel, Int64, accesserId_, false);
    WRITE_HELPER_RET(parcel, String, accesserDeviceId_, false);
    WRITE_HELPER_RET(parcel, Int32, accesserUserId_, false);
    WRITE_HELPER_RET(parcel, String, accesserAccountId_, false);
    WRITE_HELPER_RET(parcel, Int64, accesserTokenId_, false);
    WRITE_HELPER_RET(parcel, String, accesserBundleName_, false);
    WRITE_HELPER_RET(parcel, String, accesserHapSignature_, false);
    WRITE_HELPER_RET(parcel, Uint32, accesserBindLevel_, false);
    return true;
}

bool Accesser::UnMarshalling(MessageParcel& parcel)
{
    READ_HELPER_RET(parcel, Int64, accesserId_, false);
    READ_HELPER_RET(parcel, String, accesserDeviceId_, false);
    READ_HELPER_RET(parcel, Int32, accesserUserId_, false);
    READ_HELPER_RET(parcel, String, accesserAccountId_, false);
    READ_HELPER_RET(parcel, Int64, accesserTokenId_, false);
    READ_HELPER_RET(parcel, String, accesserBundleName_, false);
    READ_HELPER_RET(parcel, String, accesserHapSignature_, false);
    READ_HELPER_RET(parcel, Uint32, accesserBindLevel_, false);
    return true;
}

std::string Accesser::dump() const
{
    cJSON* json = cJSON_CreateObject();
    if (!cJSON_IsObject(json)) {
        cJSON_Delete(json);
        return EMPTY_STRING;
    }
    cJSON_AddNumberToObject(json, ACCESSER_ID.c_str(), accesserId_);
    cJSON_AddStringToObject(json, ACCESSER_DEVICE_ID.c_str(),
        ProfileUtils::GetAnonyString(accesserDeviceId_).c_str());
    cJSON_AddNumberToObject(json, ACCESSER_USER_ID.c_str(),
        ProfileUtils::GetAnonyString(std::to_string(accesserUserId_)).c_str());
    cJSON_AddStringToObject(json, ACCESSER_ACCOUNT_ID.c_str(),
        ProfileUtils::GetAnonyString(accesserAccountId_).c_str());
    cJSON_AddNumberToObject(json, ACCESSER_TOKEN_ID.c_str(), accesserTokenId_);
    cJSON_AddStringToObject(json, ACCESSER_BUNDLE_NAME.c_str(), accesserBundleName_.c_str());
    cJSON_AddStringToObject(json, ACCESSER_HAP_SIGNATURE.c_str(), accesserHapSignature_.c_str());
    cJSON_AddNumberToObject(json, ACCESSER_BIND_LEVEL.c_str(), accesserBindLevel_);
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