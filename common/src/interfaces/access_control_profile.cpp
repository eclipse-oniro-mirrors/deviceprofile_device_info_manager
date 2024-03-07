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

#include "access_control_profile.h"
#include <cstdint>
#include <string>
#include "cJSON.h"
#include "distributed_device_profile_constants.h"
#include "macro_utils.h"
#include "profile_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "AccessControlProfile";
}
AccessControlProfile::AccessControlProfile()
    : accessControlId_(0),
    accesserId_(0),
    accesseeId_(0),
    sessionKey_(""),
    bindType_(static_cast<uint32_t>(BindType::MIN)),
    authenticationType_(static_cast<uint32_t>(AuthenticationType::MIN)),
    bindLevel_(static_cast<uint32_t>(BindLevel::MIN)),
    status_(static_cast<int32_t>(Status::MIN)),
    validPeriod_(-1),
    lastAuthTime_(-1),
    trustDeviceId_(""),
    deviceIdType_((uint32_t)DeviceIdType::MIN),
    deviceIdHash_(""),
    accesser_({}),
    accessee_({})
{
}

int64_t AccessControlProfile::GetAccessControlId() const
{
    return accessControlId_;
}

void AccessControlProfile::SetAccessControlId(int64_t accessControlId)
{
    accessControlId_ = accessControlId;
}

int64_t AccessControlProfile::GetAccesserId() const
{
    return accesserId_;
}

void AccessControlProfile::SetAccesserId(int64_t accesserId)
{
    accesserId_ = accesserId;
}

int64_t AccessControlProfile::GetAccesseeId() const
{
    return accesseeId_;
}

void AccessControlProfile::SetAccesseeId(int64_t accesseeId)
{
    accesseeId_ = accesseeId;
}

std::string AccessControlProfile::GetSessionKey() const
{
    return sessionKey_;
}

void AccessControlProfile::SetSessionKey(const std::string &sessionKey)
{
    sessionKey_ = sessionKey;
}

std::string AccessControlProfile::GetTrustDeviceId() const
{
    return trustDeviceId_;
}

void AccessControlProfile::SetTrustDeviceId(const std::string &trustDeviceId)
{
    trustDeviceId_ = trustDeviceId;
}

uint32_t AccessControlProfile::GetBindType() const
{
    return bindType_;
}

void AccessControlProfile::SetBindType(uint32_t bindType)
{
    bindType_ = bindType;
}

uint32_t AccessControlProfile::GetAuthenticationType() const
{
    return authenticationType_;
}

void AccessControlProfile::SetAuthenticationType(uint32_t authenticationType)
{
    authenticationType_ = authenticationType;
}

int32_t AccessControlProfile::GetStatus() const
{
    return status_;
}

void AccessControlProfile::SetStatus(int32_t status)
{
    status_ = status;
}

int32_t AccessControlProfile::GetValidPeriod() const
{
    return validPeriod_;
}

void AccessControlProfile::SetValidPeriod(int32_t validPeriod)
{
    validPeriod_ = validPeriod;
}

int32_t AccessControlProfile::GetLastAuthTime() const
{
    return lastAuthTime_;
}

void AccessControlProfile::SetLastAuthTime(int32_t lastAuthTime)
{
    lastAuthTime_ = lastAuthTime;
}

Accesser AccessControlProfile::GetAccesser() const
{
    return accesser_;
}

void AccessControlProfile::SetAccesser(const Accesser &accesser)
{
    // impl deep clone
    accesser_ = accesser;
}

Accessee AccessControlProfile::GetAccessee() const
{
    return accessee_;
}

void AccessControlProfile::SetAccessee(const Accessee &accessee)
{
    // impl deep clone
    accessee_ = accessee;
}

uint32_t AccessControlProfile::GetBindLevel() const
{
    return bindLevel_;
}

void AccessControlProfile::SetBindLevel(uint32_t bindLevel)
{
    bindLevel_ = bindLevel;
}

uint32_t AccessControlProfile::GetDeviceIdType() const
{
    return deviceIdType_;
}

void AccessControlProfile::SetDeviceIdType(uint32_t deviceIdType)
{
    deviceIdType_ = deviceIdType;
}

std::string AccessControlProfile::GetDeviceIdHash() const
{
    return deviceIdHash_;
}

void AccessControlProfile::SetDeviceIdHash(const std::string& deviceIdHash)
{
    deviceIdHash_ = deviceIdHash;
}

bool AccessControlProfile::Marshalling(MessageParcel& parcel) const
{
    WRITE_HELPER_RET(parcel, Int64, accessControlId_, false);
    WRITE_HELPER_RET(parcel, Int64, accesserId_, false);
    WRITE_HELPER_RET(parcel, Int64, accesseeId_, false);
    WRITE_HELPER_RET(parcel, String, sessionKey_, false);
    WRITE_HELPER_RET(parcel, Uint32, bindType_, false);
    WRITE_HELPER_RET(parcel, Uint32, authenticationType_, false);
    WRITE_HELPER_RET(parcel, Uint32, bindLevel_, false);
    WRITE_HELPER_RET(parcel, Int32, status_, false);
    WRITE_HELPER_RET(parcel, Int32, validPeriod_, false);
    WRITE_HELPER_RET(parcel, Int32, lastAuthTime_, false);
    WRITE_HELPER_RET(parcel, String, trustDeviceId_, false);
    WRITE_HELPER_RET(parcel, Uint32, deviceIdType_, false);
    WRITE_HELPER_RET(parcel, String, deviceIdHash_, false);
    accesser_.Marshalling(parcel);
    accessee_.Marshalling(parcel);
    return true;
}

bool AccessControlProfile::UnMarshalling(MessageParcel& parcel)
{
    READ_HELPER_RET(parcel, Int64, accessControlId_, false);
    READ_HELPER_RET(parcel, Int64, accesserId_, false);
    READ_HELPER_RET(parcel, Int64, accesseeId_, false);
    READ_HELPER_RET(parcel, String, sessionKey_, false);
    READ_HELPER_RET(parcel, Uint32, bindType_, false);
    READ_HELPER_RET(parcel, Uint32, authenticationType_, false);
    READ_HELPER_RET(parcel, Uint32, bindLevel_, false);
    READ_HELPER_RET(parcel, Int32, status_, false);
    READ_HELPER_RET(parcel, Int32, validPeriod_, false);
    READ_HELPER_RET(parcel, Int32, lastAuthTime_, false);
    READ_HELPER_RET(parcel, String, trustDeviceId_, false);
    READ_HELPER_RET(parcel, Uint32, deviceIdType_, false);
    READ_HELPER_RET(parcel, String, deviceIdHash_, false);
    accesser_.UnMarshalling(parcel);
    accessee_.UnMarshalling(parcel);
    return true;
}

std::string AccessControlProfile::dump() const
{
    cJSON* json = cJSON_CreateObject();
    if(!cJSON_IsObject(json)) {
        cJSON_Delete(json);
        return EMPTY_STRING;
    }
    cJSON_AddNumberToObject(json, ACCESS_CONTROL_ID.c_str(), accessControlId_);
    cJSON_AddNumberToObject(json, ACCESSER_ID.c_str(), accesserId_);
    cJSON_AddNumberToObject(json, ACCESSEE_ID.c_str(), accesseeId_);
    cJSON_AddStringToObject(json, SESSION_KEY.c_str(), sessionKey_.c_str());
    cJSON_AddNumberToObject(json, BIND_TYPE.c_str(), bindType_);
    cJSON_AddNumberToObject(json, AUTHENTICATION_TYPE.c_str(), authenticationType_);
    cJSON_AddNumberToObject(json, BIND_LEVEL.c_str(), bindLevel_);
    cJSON_AddNumberToObject(json, STATUS.c_str(), status_);
    cJSON_AddNumberToObject(json, VALID_PERIOD.c_str(), validPeriod_);
    cJSON_AddNumberToObject(json, LAST_AUTH_TIME.c_str(), lastAuthTime_);
    cJSON_AddStringToObject(json, TRUST_DEVICE_ID.c_str(), ProfileUtils::GetAnonyString(trustDeviceId_).c_str());
    cJSON_AddNumberToObject(json, DEVICE_ID_TYPE.c_str(), deviceIdType_);
    cJSON_AddStringToObject(json, DEVICE_ID_HASH.c_str(), deviceIdHash_.c_str());
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