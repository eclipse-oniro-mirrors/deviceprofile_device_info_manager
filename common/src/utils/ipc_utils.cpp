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

#include "ipc_utils.h"
#include "dp_subscribe_info.h"
#include "macro_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "IpcUtils";
}
bool IpcUtils::Marshalling(MessageParcel& parcel, const std::vector<TrustDeviceProfile>& trustDeviceProfiles)
{
    if (trustDeviceProfiles.empty() || trustDeviceProfiles.size() > MAX_PROFILE_SIZE) {
        HILOGE("profile size is invalid!size : %{public}zu", trustDeviceProfiles.size());
        return false;
    }
    uint32_t size = trustDeviceProfiles.size();
    WRITE_HELPER_RET(parcel, Uint32, size, false);
    for (const auto& profile : trustDeviceProfiles) {
        if (!profile.Marshalling(parcel)) {
            HILOGE("profile Marshalling fail!");
            return false;
        }
    }
    return true;
}

bool IpcUtils::Marshalling(MessageParcel& parcel, const std::vector<AccessControlProfile>& aclProfiles)
{
    if (aclProfiles.empty() || aclProfiles.size() > MAX_PROFILE_SIZE) {
        HILOGE("profile size is invalid!size : %{public}zu", aclProfiles.size());
        return false;
    }
    uint32_t size = aclProfiles.size();
    WRITE_HELPER_RET(parcel, Uint32, size, false);
    for (const auto& profile : aclProfiles) {
        if (!profile.Marshalling(parcel)) {
            HILOGE("profile Marshalling fail!");
            return false;
        }
    }
    return true;
}

bool IpcUtils::Marshalling(MessageParcel& parcel, const std::vector<ServiceProfile>& serviceProfiles)
{
    if (serviceProfiles.empty() || serviceProfiles.size() > MAX_PROFILE_SIZE) {
        HILOGE("profile size is invalid!size : %{public}zu", serviceProfiles.size());
        return false;
    }
    uint32_t size = serviceProfiles.size();
    WRITE_HELPER_RET(parcel, Uint32, size, false);
    for (const auto& profile : serviceProfiles) {
        if (!profile.Marshalling(parcel)) {
            HILOGE("profile Marshalling fail!");
            return false;
        }
    }
    return true;
}

bool IpcUtils::Marshalling(MessageParcel& parcel, const std::vector<CharacteristicProfile>& charProfiles)
{
    if (charProfiles.empty() || charProfiles.size() > MAX_PROFILE_SIZE) {
        HILOGE("profile size is invalid!size : %{public}zu", charProfiles.size());
        return false;
    }
    uint32_t size = charProfiles.size();
    WRITE_HELPER_RET(parcel, Uint32, size, false);
    for (const auto& profile : charProfiles) {
        profile.Marshalling(parcel);
    }
    return true;
}

bool IpcUtils::Marshalling(MessageParcel& parcel, const std::map<std::string, std::string>& params)
{
    if (params.size() == 0 || params.size() > MAX_PARAM_SIZE) {
        HILOGE("Params size is invalid!size : %{public}zu", params.size());
        return false;
    }
    uint32_t size = params.size();
    WRITE_HELPER_RET(parcel, Uint32, size, false);
    for (const auto& item : params) {
        WRITE_HELPER_RET(parcel, String, item.first + SEPARATOR + item.second, false);
    }
    return true;
}

bool IpcUtils::Marshalling(MessageParcel& parcel, const std::map<std::string,
    OHOS::DistributedDeviceProfile::SubscribeInfo>& listenerMap)
{
    if (listenerMap.size() == 0 || listenerMap.size() > MAX_LISTENER_SIZE) {
        HILOGE("listenerMap size is invalid!size : %{public}zu", listenerMap.size());
        return false;
    }
    uint32_t size = listenerMap.size();
    WRITE_HELPER_RET(parcel, Uint32, size, false);
    for (const auto& item : listenerMap) {
        OHOS::DistributedDeviceProfile::SubscribeInfo subscribeInfo = item.second;
        if (!subscribeInfo.Marshalling(parcel)) {
            HILOGE("subscribeInfo Marshalling fail!");
            return false;
        }
    }
    return true;
}

bool IpcUtils::Marshalling(MessageParcel& parcel, const std::unordered_set<ProfileChangeType>& changeTypes)
{
    if (changeTypes.size() == 0 || changeTypes.size() > MAX_SUBSCRIBE_CHANGE_SIZE) {
        HILOGE("listenerMap size is invalid!size : %{public}zu", changeTypes.size());
        return false;
    }
    uint32_t size = changeTypes.size();
    WRITE_HELPER_RET(parcel, Uint32, size, false);
    for (ProfileChangeType item : changeTypes) {
        WRITE_HELPER_RET(parcel, Int32, static_cast<int32_t>(item), false);
    }
    return true;
}

bool IpcUtils::UnMarshalling(MessageParcel& parcel, std::vector<TrustDeviceProfile>& trustDeviceProfiles)
{
    uint32_t size = parcel.ReadUint32();
    if (size == 0 || size > MAX_PROFILE_SIZE) {
        HILOGE("Profile size is invalid!size : %{public}u", size);
        return false;
    }
    for (uint32_t i = 0; i < size; i++) {
        TrustDeviceProfile trustDeviceProfile;
        if (!trustDeviceProfile.UnMarshalling(parcel)) {
            HILOGE("Profile UnMarshalling fail!");
            return false;
        }
        trustDeviceProfiles.emplace_back(trustDeviceProfile);
    }
    return true;
}

bool IpcUtils::UnMarshalling(MessageParcel& parcel, std::vector<AccessControlProfile>& aclProfiles)
{
    uint32_t size = parcel.ReadUint32();
    if (size == 0 || size > MAX_PROFILE_SIZE) {
        HILOGE("Profile size is invalid!size : %{public}u", size);
        return false;
    }
    for (uint32_t i = 0; i < size; i++) {
        AccessControlProfile aclProfile;
        if (!aclProfile.UnMarshalling(parcel)) {
            HILOGE("Profile UnMarshalling fail!");
            return false;
        }
        aclProfiles.emplace_back(aclProfile);
    }
    return true;
}

bool IpcUtils::UnMarshalling(MessageParcel& parcel, std::vector<ServiceProfile>& serviceProfiles)
{
    uint32_t size = parcel.ReadUint32();
    if (size == 0 || size > MAX_PROFILE_SIZE) {
        HILOGE("Profile size is invalid!size : %{public}u", size);
        return false;
    }
    for (uint32_t i = 0; i < size; i++) {
        ServiceProfile serviceProfile;
        if (!serviceProfile.UnMarshalling(parcel)) {
            HILOGE("Profile UnMarshalling fail!");
            return false;
        }
        serviceProfiles.emplace_back(serviceProfile);
    }
    return true;
}

bool IpcUtils::UnMarshalling(MessageParcel& parcel, std::vector<CharacteristicProfile>& charProfiles)
{
    uint32_t size = parcel.ReadUint32();
    if (size == 0 || size > MAX_PROFILE_SIZE) {
        HILOGE("Profile size is invalid!size : %{public}u", size);
        return false;
    }
    for (uint32_t i = 0; i < size; i++) {
        CharacteristicProfile charProfile;
        if (!charProfile.UnMarshalling(parcel)) {
            HILOGE("Profile UnMarshalling fail!");
            return false;
        }
        charProfiles.emplace_back(charProfile);
    }
    return true;
}

bool IpcUtils::UnMarshalling(MessageParcel& parcel, std::map<std::string, std::string>& params)
{
    uint32_t size = parcel.ReadUint32();
    if (size == 0 || size > MAX_PARAM_SIZE) {
        HILOGE("Params size is invalid!size : %{public}u", size);
        return false;
    }
    for (uint32_t i = 0; i < size; i++) {
        std::string item = "";
        READ_HELPER_RET(parcel, String, item, false);
        std::string::size_type position = item.find(SEPARATOR);
        if (position == item.npos) {
            HILOGE("Not found the separator!");
            continue;
        }
        std::string key = item.substr(0, position);
        std::string value = item.substr(position + 1);
        HILOGI("the key is %{public}s, value is %{public}s", key.c_str(), value.c_str());
        params[key] = value;
    }
    return true;
}

bool IpcUtils::UnMarshalling(MessageParcel& parcel, std::map<std::string,
    OHOS::DistributedDeviceProfile::SubscribeInfo>& listenerMap)
{
    uint32_t size = parcel.ReadUint32();
    if (size == 0 || size > MAX_LISTENER_SIZE) {
        HILOGE("Params size is invalid!size : %{public}u", size);
        return false;
    }
    for (uint32_t i = 0; i < size; i++) {
        OHOS::DistributedDeviceProfile::SubscribeInfo subscribeInfo;
        if (!subscribeInfo.UnMarshalling(parcel)) {
            HILOGE("subscribeInfo UnMarshalling fail!");
            return false;
        }
        listenerMap[subscribeInfo.GetSubscribeKey() + SEPARATOR + std::to_string(subscribeInfo.GetSaId())] =
            subscribeInfo;
    }
    return true;
}

bool IpcUtils::UnMarshalling(MessageParcel& parcel, std::unordered_set<ProfileChangeType>& changeTypes)
{
    uint32_t size = parcel.ReadUint32();
    if (size == 0 || size > MAX_SUBSCRIBE_CHANGE_SIZE) {
        HILOGE("Params size is invalid!size : %{public}u", size);
        return false;
    }
    for (uint32_t i = 0; i < size; i++) {
        uint32_t num = parcel.ReadUint32();
        if (num <= ProfileChangeType::PROFILE_CHANGE_TYPE_MIN || num >= ProfileChangeType::PROFILE_CHANGE_TYPE_MAX) {
            HILOGE("The value is invalid!");
            return false;
        }
        changeTypes.emplace(static_cast<ProfileChangeType>(num));
    }
    return true;
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
