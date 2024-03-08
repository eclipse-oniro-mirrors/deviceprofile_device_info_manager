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

#include "dp_subscribe_info.h"
#include "cJSON.h"
#include "distributed_device_profile_constants.h"
#include "ipc_utils.h"
#include "macro_utils.h"
#include "profile_change_listener_stub.h"
#include "profile_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "SubscribeInfo";
}
SubscribeInfo::SubscribeInfo(int32_t saId, const std::string& subscribeKey,
    std::unordered_set<ProfileChangeType> subscribeChangeTypes, sptr<IProfileChangeListener> profileChangeListener)
{
    HILOGI("constructor!");
    this->saId_ = saId;
    this->subscribeKey_ = subscribeKey;
    this->subscribeChangeTypes_ = subscribeChangeTypes;
    if (profileChangeListener == nullptr) {
        HILOGI("constructor!");
        return;
    }
    if (profileChangeListener->AsObject() == nullptr) {
        HILOGI("constructor!");
        return;
    }
    this->listener_ = profileChangeListener->AsObject();
}

SubscribeInfo::SubscribeInfo()
{
    HILOGI("destructor!");
}

SubscribeInfo::~SubscribeInfo()
{
    HILOGI("destructor!");
}

int32_t SubscribeInfo::GetSaId() const
{
    return saId_;
}

void SubscribeInfo::SetSaId(int32_t saId)
{
    saId_ = saId;
}

void SubscribeInfo::SetSubscribeKey(const std::string& deviceId, const std::string& deviceAttribute)
{
    subscribeKey_ = DEV_PREFIX + SEPARATOR + deviceId + SEPARATOR + deviceAttribute;
}

void SubscribeInfo::SetSubscribeKey(const std::string& deviceId, const std::string& serviceName,
    const std::string& serviceAttribute)
{
    subscribeKey_ = SVR_PREFIX + SEPARATOR + deviceId + SEPARATOR + serviceName + SEPARATOR + serviceAttribute;
}
void SubscribeInfo::SetSubscribeKey(const std::string& deviceId, const std::string& serviceName,
    const std::string& characteristicKey, const std::string& characteristicAttribute)
{
    subscribeKey_ = CHAR_PREFIX + SEPARATOR + deviceId + SEPARATOR + serviceName + SEPARATOR + characteristicKey +
        SEPARATOR + characteristicAttribute;
}

std::string SubscribeInfo::GetSubscribeKey() const
{
    return subscribeKey_;
}

void SubscribeInfo::SetSubscribeKey(const std::string& subscribeKey)
{
    subscribeKey_ = subscribeKey;
}

sptr<IRemoteObject> SubscribeInfo::GetListener() const
{
    return listener_;
}

std::unordered_set<ProfileChangeType> SubscribeInfo::GetProfileChangeTypes() const
{
    return subscribeChangeTypes_;
}

void SubscribeInfo::AddProfileChangeType(ProfileChangeType profileChangeType)
{
    if (profileChangeType <= PROFILE_CHANGE_TYPE_MIN || profileChangeType >= PROFILE_CHANGE_TYPE_MAX) {
        return;
    }
    if (subscribeChangeTypes_.size() > MAX_SUBSCRIBE_CHANGE_SIZE) {
        return;
    }
    subscribeChangeTypes_.emplace(profileChangeType);
}

void SubscribeInfo::SetListener(sptr<IProfileChangeListener> listener)
{
    if (listener == nullptr) {
        HILOGE("listener is null!");
        return;
    }
    if (listener->AsObject() == nullptr) {
        HILOGE("listener cast fail!");
        return;
    }
    listener_ = listener->AsObject();
}

bool SubscribeInfo::Marshalling(MessageParcel& parcel) const
{
    WRITE_HELPER_RET(parcel, Int32, saId_, false);
    WRITE_HELPER_RET(parcel, String, subscribeKey_, false);
    IpcUtils::Marshalling(parcel, subscribeChangeTypes_);
    WRITE_HELPER_RET(parcel, RemoteObject, listener_, false);
    return true;
}

bool SubscribeInfo::UnMarshalling(MessageParcel& parcel)
{
    READ_HELPER_RET(parcel, Int32, saId_, false);
    READ_HELPER_RET(parcel, String, subscribeKey_, false);
    IpcUtils::UnMarshalling(parcel, subscribeChangeTypes_);
    listener_ = parcel.ReadRemoteObject();
    if (listener_ == nullptr) {
        HILOGE("read remoteObject failed!");
        return false;
    }
    return true;
}

std::string SubscribeInfo::dump() const
{
    cJSON* json = cJSON_CreateObject();
    if (!cJSON_IsObject(json)) {
        cJSON_Delete(json);
        return EMPTY_STRING;
    }
    cJSON_AddNumberToObject(json, SA_ID.c_str(), saId_);
    cJSON_AddStringToObject(json, SUBSCRIBE_KEY.c_str(), subscribeKey_.c_str());
    cJSON* jsonArr = cJSON_CreateArray();
    if (!cJSON_IsArray(jsonArr)) {
        cJSON_Delete(jsonArr);
    } else {
        for (const auto &subChangeType : subscribeChangeTypes_) {
            cJSON_AddItemToArray(jsonArr, cJSON_CreateNumber(static_cast<int32_t>(subChangeType)));
        }
        cJSON_AddItemToObject(json, SUBSCRIBE_CHANGE_TYPES.c_str(), jsonArr);
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

