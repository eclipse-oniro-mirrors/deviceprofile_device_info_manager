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

#include "access_control_profile.h"
#include <cstdint>
#include <string>
#include "macro_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "AccessControlProfile";
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

int AccessControlProfile::GetBindType() const
{
    return bindType_;
}

void AccessControlProfile::SetBindType(int bindType)
{
    bindType_ = bindType;
}

int AccessControlProfile::GetAuthenticationType() const
{
    return authenticationType_;
}

void AccessControlProfile::SetAuthenticationType(int authenticationType)
{
    authenticationType_ = authenticationType;
}

int AccessControlProfile::GetStatus() const
{
    return status_;
}

void AccessControlProfile::SetStatus(int status)
{
    status_ = status;
}

int AccessControlProfile::GetValidPeriod() const
{
    return validPeriod_;
}

void AccessControlProfile::SetValidPeriod(int validPeriod)
{
    validPeriod_ = validPeriod;
}

int AccessControlProfile::GetLastAuthTime() const
{
    return lastAuthTime_;
}

void AccessControlProfile::SetLastAuthTime(int lastAuthTime)
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

int32_t AccessControlProfile::GetBindLevel() const
{
    return bindLevel_;
}

void AccessControlProfile::SetBindLevel(int32_t bindLevel)
{
    bindLevel_ = bindLevel;
}

int32_t AccessControlProfile::GetDeviceIdType() const
{
    return deviceIdType_;
}

void AccessControlProfile::SetDeviceIdType(int32_t deviceIdType)
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

void AccessControlProfile::dump() const
{
    nlohmann::json json;
    json[ACCESS_CONTROL_ID] = accessControlId_;
    json[ACCESSER_ID] = accesserId_;
    json[ACCESSEE_ID] = accesseeId_;
    json[SESSION_KEY] = sessionKey_;
    json[BIND_TYPE] = bindType_;
    json[AUTHENTICATION_TYPE] = authenticationType_;
    json[BIND_LEVEL] = bindLevel_;
    json[STATUS] = status_;
    json[VALID_PERIOD] = validPeriod_;
    json[LAST_AUTH_TIME] = lastAuthTime_;
    json[TRUST_DEVICE_ID] = ProfileUtils::GetAnonyString(trustDeviceId_);;
    json[DEVICE_ID_TYPE] = deviceIdType_;
    json[DEVICE_ID_HASH] = deviceIdHash_;
    HILOGI("dump %s!", json.dump().c_str());
}
} // namespace DistributedDeviceProfile
} // namespace OHOS