/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License")
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

#include "subscribe_profile_manager.h"

#include "distributed_device_profile_errors.h"
#include "dp_radar_helper.h"
#include "profile_utils.h"
#include "profile_cache.h"

namespace OHOS {
namespace DistributedDeviceProfile {
IMPLEMENT_SINGLE_INSTANCE(SubscribeProfileManager);
namespace {
    const std::string TAG = "SubscribeProfileManager";
}

int32_t SubscribeProfileManager::Init()
{
    HILOGI("call!");
    {
        std::lock_guard<std::mutex> lockGuard(funcsMutex_);
        funcsMap_[ProfileType::DEVICE_PROFILE * ChangeType::ADD] =
            &SubscribeProfileManager::NotifyDeviceProfileAdd;
        funcsMap_[ProfileType::DEVICE_PROFILE * ChangeType::UPDATE] =
            &SubscribeProfileManager::NotifyDeviceProfileUpdate;
        funcsMap_[ProfileType::DEVICE_PROFILE * ChangeType::DELETE] =
            &SubscribeProfileManager::NotifyDeviceProfileDelete;
        funcsMap_[ProfileType::SERVICE_PROFILE * ChangeType::ADD] =
            &SubscribeProfileManager::NotifyServiceProfileAdd;
        funcsMap_[ProfileType::SERVICE_PROFILE * ChangeType::UPDATE] =
            &SubscribeProfileManager::NotifyServiceProfileUpdate;
        funcsMap_[ProfileType::SERVICE_PROFILE * ChangeType::DELETE] =
            &SubscribeProfileManager::NotifyServiceProfileDelete;
        funcsMap_[ProfileType::CHAR_PROFILE * ChangeType::ADD] =
            &SubscribeProfileManager::NotifyCharProfileAdd;
        funcsMap_[ProfileType::CHAR_PROFILE * ChangeType::UPDATE] =
            &SubscribeProfileManager::NotifyCharProfileUpdate;
        funcsMap_[ProfileType::CHAR_PROFILE * ChangeType::DELETE] =
            &SubscribeProfileManager::NotifyCharProfileDelete;
    }
    return DP_SUCCESS;
}

int32_t SubscribeProfileManager::UnInit()
{
    HILOGI("call!");
    {
        std::lock_guard<std::mutex> lockGuard(subscribeMutex_);
        subscribeInfoMap_.clear();
    }
    {
        std::lock_guard<std::mutex> lockGuard(funcsMutex_);
        funcsMap_.clear();
    }
    return DP_SUCCESS;
}

int32_t SubscribeProfileManager::NotifyProfileChange(ProfileType profileType, ChangeType changeType,
    const std::string& dbKey, const std::string& dbValue)
{
    int32_t code = static_cast<int32_t>(profileType) * static_cast<int32_t>(changeType);
    if (funcsMap_.find(code) == funcsMap_.end()) {
        HILOGE("Params is invalid!");
        return DP_INVALID_PARAMS;
    }
    DpRadarHelper::GetInstance().ReportNotifyProfileChange(code);
    return (this->*(funcsMap_[code]))(dbKey, dbValue);
}

int32_t SubscribeProfileManager::NotifyTrustDeviceProfileAdd(const TrustDeviceProfile& trustDeviceProfile)
{
    HILOGI("NotifyTrustDeviceProfileAdd : %{public}s!", trustDeviceProfile.dump().c_str());
    auto subscriberInfos = GetSubscribeInfos(SUBSCRIBE_TRUST_DEVICE_PROFILE);
    for (const auto& subscriberInfo : subscriberInfos) {
        sptr<IProfileChangeListener> listenerProxy = iface_cast<IProfileChangeListener>(subscriberInfo.GetListener());
        if (listenerProxy == nullptr) {
            HILOGE("Cast to IProfileChangeListener failed!");
            continue;
        }
        if (subscriberInfo.GetProfileChangeTypes().count(ProfileChangeType::TRUST_DEVICE_PROFILE_ADD) != 0) {
            listenerProxy->OnTrustDeviceProfileAdd(trustDeviceProfile);
        }
    }
    return DP_SUCCESS;
}

int32_t SubscribeProfileManager::NotifyTrustDeviceProfileUpdate(const TrustDeviceProfile& oldDeviceProfile,
    const TrustDeviceProfile& newDeviceProfile)
{
    HILOGI("NotifyTrustDeviceProfileUpdate : %{public}s!", newDeviceProfile.dump().c_str());
    auto subscriberInfos = GetSubscribeInfos(SUBSCRIBE_TRUST_DEVICE_PROFILE);
    for (const auto& subscriberInfo : subscriberInfos) {
        sptr<IProfileChangeListener> listenerProxy = iface_cast<IProfileChangeListener>(subscriberInfo.GetListener());
        if (listenerProxy == nullptr) {
            HILOGE("Cast to IProfileChangeListener failed!");
            continue;
        }
        if (subscriberInfo.GetProfileChangeTypes().count(ProfileChangeType::TRUST_DEVICE_PROFILE_UPDATE) != 0) {
            listenerProxy->OnTrustDeviceProfileUpdate(oldDeviceProfile, newDeviceProfile);
        }
    }
    return DP_SUCCESS;
}

int32_t SubscribeProfileManager::NotifyTrustDeviceProfileDelete(const TrustDeviceProfile& trustDeviceProfile)
{
    HILOGI("NotifyTrustDeviceProfileDelete : %{public}s!", trustDeviceProfile.dump().c_str());
    auto subscriberInfos = GetSubscribeInfos(SUBSCRIBE_TRUST_DEVICE_PROFILE);
    for (const auto& subscriberInfo : subscriberInfos) {
        sptr<IProfileChangeListener> listenerProxy = iface_cast<IProfileChangeListener>(subscriberInfo.GetListener());
        if (listenerProxy == nullptr) {
            HILOGE("Cast to IProfileChangeListener failed!");
            continue;
        }
        if (subscriberInfo.GetProfileChangeTypes().count(ProfileChangeType::TRUST_DEVICE_PROFILE_DELETE) != 0) {
            listenerProxy->OnTrustDeviceProfileDelete(trustDeviceProfile);
        }
    }
    return DP_SUCCESS;
}

int32_t SubscribeProfileManager::SubscribeDeviceProfile(const SubscribeInfo& subscribeInfo)
{
    HILOGI("SubscribeDeviceProfile, saId: %{public}d!, subscribeKey: %{public}s", subscribeInfo.GetSaId(),
        ProfileUtils::GetAnonyString(subscribeInfo.GetSubscribeKey()).c_str());
    {
        std::lock_guard<std::mutex> lock(subscribeMutex_);
        if (subscribeInfoMap_.size() > MAX_LISTENER_SIZE) {
            HILOGE("SubscribeInfoMap size is invalid!size: %{public}zu!", subscribeInfoMap_.size());
            return DP_EXCEED_MAX_SIZE_FAIL;
        }
        if (subscribeInfoMap_[subscribeInfo.GetSubscribeKey()].size() > MAX_LISTENER_SIZE) {
            HILOGE("SubscribeInfoMap size is invalid!size: %{public}zu!",
                subscribeInfoMap_[subscribeInfo.GetSubscribeKey()].size());
            return DP_EXCEED_MAX_SIZE_FAIL;
        }
        if (subscribeInfoMap_[subscribeInfo.GetSubscribeKey()].find(subscribeInfo) !=
            subscribeInfoMap_[subscribeInfo.GetSubscribeKey()].end()) {
            HILOGI("this sa subscribeInfo is exist");
            subscribeInfoMap_[subscribeInfo.GetSubscribeKey()].erase(subscribeInfo);
        }
        subscribeInfoMap_[subscribeInfo.GetSubscribeKey()].emplace(subscribeInfo);
    }
    return DP_SUCCESS;
}

int32_t SubscribeProfileManager::SubscribeDeviceProfile(std::map<std::string, SubscribeInfo> subscribeInfos)
{
    HILOGI("call!");
    for (auto item : subscribeInfos) {
        SubscribeDeviceProfile(item.second);
    }
    return DP_SUCCESS;
}

int32_t SubscribeProfileManager::UnSubscribeDeviceProfile(const SubscribeInfo& subscribeInfo)
{
    HILOGI("UnSubscribeDeviceProfile, saId: %{public}d!, subscribeKey: %{public}s", subscribeInfo.GetSaId(),
        ProfileUtils::GetAnonyString(subscribeInfo.GetSubscribeKey()).c_str());
    {
        std::lock_guard<std::mutex> lock(subscribeMutex_);
        subscribeInfoMap_[subscribeInfo.GetSubscribeKey()].erase(subscribeInfo);
    }
    return DP_SUCCESS;
}

int32_t SubscribeProfileManager::NotifyDeviceProfileAdd(const std::string& dbKey, const std::string& dbValue)
{
    std::map<std::string, std::string> values;
    values[dbKey] = dbValue;
    DeviceProfile deviceProfile;
    deviceProfile.SetDeviceId(ProfileUtils::GetDeviceIdByDBKey(dbKey));
    ProfileUtils::EntriesToDeviceProfile(values, deviceProfile);
    HILOGI("NotifyDeviceProfileAdd : %{public}s!", deviceProfile.AnnoymizeDump().c_str());
    auto subscriberInfos = GetSubscribeInfos(dbKey);
    for (const auto& subscriberInfo : subscriberInfos) {
        sptr<IProfileChangeListener> listenerProxy = iface_cast<IProfileChangeListener>(subscriberInfo.GetListener());
        if (listenerProxy == nullptr) {
            HILOGE("Cast to IProfileChangeListener failed!");
            continue;
        }
        if (subscriberInfo.GetProfileChangeTypes().count(ProfileChangeType::DEVICE_PROFILE_ADD) != 0) {
            listenerProxy->OnDeviceProfileAdd(deviceProfile);
        }
    }
    return DP_SUCCESS;
}

int32_t SubscribeProfileManager::NotifyDeviceProfileUpdate(const std::string& dbKey, const std::string& dbValue)
{
    std::map<std::string, std::string> values;
    values[dbKey] = dbValue;
    DeviceProfile newDeviceProfile;
    newDeviceProfile.SetDeviceId(ProfileUtils::GetDeviceIdByDBKey(dbKey));
    ProfileUtils::EntriesToDeviceProfile(values, newDeviceProfile);
    HILOGI("NotifyDeviceProfileUpdate : %{public}s!", newDeviceProfile.AnnoymizeDump().c_str());
    DeviceProfile oldDeviceProfile;
    ProfileCache::GetInstance().GetDeviceProfile(ProfileUtils::GetDeviceIdByDBKey(dbKey), oldDeviceProfile);
    auto subscriberInfos = GetSubscribeInfos(dbKey);
    for (const auto& subscriberInfo : subscriberInfos) {
        sptr<IProfileChangeListener> listenerProxy = iface_cast<IProfileChangeListener>(subscriberInfo.GetListener());
        if (listenerProxy == nullptr) {
            HILOGE("Cast to IProfileChangeListener failed!");
            continue;
        }
        if (subscriberInfo.GetProfileChangeTypes().count(ProfileChangeType::DEVICE_PROFILE_UPDATE) != 0) {
            listenerProxy->OnDeviceProfileUpdate(oldDeviceProfile, newDeviceProfile);
        }
    }
    return DP_SUCCESS;
}

int32_t SubscribeProfileManager::NotifyDeviceProfileDelete(const std::string& dbKey, const std::string& dbValue)
{
    std::map<std::string, std::string> values;
    values[dbKey] = dbValue;
    DeviceProfile deviceProfile;
    deviceProfile.SetDeviceId(ProfileUtils::GetDeviceIdByDBKey(dbKey));
    ProfileUtils::EntriesToDeviceProfile(values, deviceProfile);
    HILOGI("NotifyDeviceProfileDelete : %{public}s!", deviceProfile.AnnoymizeDump().c_str());
    auto subscriberInfos = GetSubscribeInfos(dbKey);
    for (const auto& subscriberInfo : subscriberInfos) {
        sptr<IProfileChangeListener> listenerProxy = iface_cast<IProfileChangeListener>(subscriberInfo.GetListener());
        if (listenerProxy == nullptr) {
            HILOGE("Cast to IProfileChangeListener failed!");
            continue;
        }
        if (subscriberInfo.GetProfileChangeTypes().count(ProfileChangeType::DEVICE_PROFILE_DELETE) != 0) {
            listenerProxy->OnDeviceProfileDelete(deviceProfile);
        }
    }
    return DP_SUCCESS;
}

int32_t SubscribeProfileManager::NotifyServiceProfileAdd(const std::string& dbKey, const std::string& dbValue)
{
    std::map<std::string, std::string> values;
    values[dbKey] = dbValue;
    ServiceProfile serviceProfile;
    serviceProfile.SetDeviceId(ProfileUtils::GetDeviceIdByDBKey(dbKey));
    serviceProfile.SetServiceName(ProfileUtils::GetServiceNameByDBKey(dbKey));
    ProfileUtils::EntriesToServiceProfile(values, serviceProfile);
    HILOGI("NotifyServiceProfileAdd : %{public}s!", serviceProfile.dump().c_str());
    auto subscriberInfos = GetSubscribeInfos(dbKey);
    for (const auto& subscriberInfo : subscriberInfos) {
        sptr<IProfileChangeListener> listenerProxy = iface_cast<IProfileChangeListener>(subscriberInfo.GetListener());
        if (listenerProxy == nullptr) {
            HILOGE("Cast to IProfileChangeListener failed!");
            continue;
        }
        if (subscriberInfo.GetProfileChangeTypes().count(ProfileChangeType::SERVICE_PROFILE_ADD) != 0) {
            listenerProxy->OnServiceProfileAdd(serviceProfile);
        }
    }
    return DP_SUCCESS;
}

int32_t SubscribeProfileManager::NotifyServiceProfileUpdate(const std::string& dbKey, const std::string& dbValue)
{
    std::map<std::string, std::string> values;
    values[dbKey] = dbValue;
    ServiceProfile newServiceProfile;
    newServiceProfile.SetDeviceId(ProfileUtils::GetDeviceIdByDBKey(dbKey));
    newServiceProfile.SetServiceName(ProfileUtils::GetServiceNameByDBKey(dbKey));
    ProfileUtils::EntriesToServiceProfile(values, newServiceProfile);
    HILOGI("NotifyServiceProfileUpdate : %{public}s!", newServiceProfile.dump().c_str());
    auto subscriberInfos = GetSubscribeInfos(dbKey);
    ServiceProfile oldServiceProfile;
    ProfileCache::GetInstance().GetServiceProfile(ProfileUtils::GetDeviceIdByDBKey(dbKey),
        ProfileUtils::GetServiceNameByDBKey(dbKey), oldServiceProfile);
    for (const auto& subscriberInfo : subscriberInfos) {
        sptr<IProfileChangeListener> listenerProxy = iface_cast<IProfileChangeListener>(subscriberInfo.GetListener());
        if (listenerProxy == nullptr) {
            HILOGE("Cast to IProfileChangeListener failed!");
            continue;
        }
        if (subscriberInfo.GetProfileChangeTypes().count(ProfileChangeType::SERVICE_PROFILE_UPDATE) != 0) {
            listenerProxy->OnServiceProfileUpdate(oldServiceProfile, newServiceProfile);
        }
    }
    return DP_SUCCESS;
}

int32_t SubscribeProfileManager::NotifyServiceProfileDelete(const std::string& dbKey, const std::string& dbValue)
{
    std::map<std::string, std::string> values;
    values[dbKey] = dbValue;
    ServiceProfile serviceProfile;
    serviceProfile.SetDeviceId(ProfileUtils::GetDeviceIdByDBKey(dbKey));
    serviceProfile.SetServiceName(ProfileUtils::GetServiceNameByDBKey(dbKey));
    ProfileUtils::EntriesToServiceProfile(values, serviceProfile);
    HILOGI("NotifyServiceProfileDelete : %{public}s!", serviceProfile.dump().c_str());
    auto subscriberInfos = GetSubscribeInfos(dbKey);
    for (const auto& subscriberInfo : subscriberInfos) {
        sptr<IProfileChangeListener> listenerProxy = iface_cast<IProfileChangeListener>(subscriberInfo.GetListener());
        if (listenerProxy == nullptr) {
            HILOGE("Cast to IProfileChangeListener failed!");
            continue;
        }
        if (subscriberInfo.GetProfileChangeTypes().count(ProfileChangeType::SERVICE_PROFILE_DELETE) != 0) {
            listenerProxy->OnServiceProfileDelete(serviceProfile);
        }
    }
    return DP_SUCCESS;
}

int32_t SubscribeProfileManager::NotifyCharProfileAdd(const std::string& dbKey, const std::string& dbValue)
{
    std::map<std::string, std::string> values;
    values[dbKey] = dbValue;
    CharacteristicProfile charProfile;
    charProfile.SetDeviceId(ProfileUtils::GetDeviceIdByDBKey(dbKey));
    charProfile.SetServiceName(ProfileUtils::GetServiceNameByDBKey(dbKey));
    charProfile.SetCharacteristicKey(ProfileUtils::GetCharKeyByDBKey(dbKey));
    ProfileUtils::EntriesToCharProfile(values, charProfile);
    HILOGI("NotifyCharProfileAdd : %{public}s!", charProfile.dump().c_str());
    auto subscriberInfos = GetSubscribeInfos(dbKey);
    for (const auto& subscriberInfo : subscriberInfos) {
        sptr<IProfileChangeListener> listenerProxy = iface_cast<IProfileChangeListener>(subscriberInfo.GetListener());
        if (listenerProxy == nullptr) {
            HILOGE("Cast to IProfileChangeListener failed!");
            continue;
        }
        if (subscriberInfo.GetProfileChangeTypes().count(ProfileChangeType::CHAR_PROFILE_ADD) != 0) {
            listenerProxy->OnCharacteristicProfileAdd(charProfile);
        }
    }
    return DP_SUCCESS;
}

int32_t SubscribeProfileManager::NotifyCharProfileUpdate(const std::string& dbKey, const std::string& dbValue)
{
    std::map<std::string, std::string> values;
    values[dbKey] = dbValue;
    CharacteristicProfile newCharProfile;
    newCharProfile.SetDeviceId(ProfileUtils::GetDeviceIdByDBKey(dbKey));
    newCharProfile.SetServiceName(ProfileUtils::GetServiceNameByDBKey(dbKey));
    newCharProfile.SetCharacteristicKey(ProfileUtils::GetCharKeyByDBKey(dbKey));
    ProfileUtils::EntriesToCharProfile(values, newCharProfile);
    HILOGI("NotifyCharProfileUpdate : %{public}s!", newCharProfile.dump().c_str());
    auto subscriberInfos = GetSubscribeInfos(dbKey);
    CharacteristicProfile oldCharProfile;
    ProfileCache::GetInstance().GetCharacteristicProfile(ProfileUtils::GetDeviceIdByDBKey(dbKey),
        ProfileUtils::GetServiceNameByDBKey(dbKey), ProfileUtils::GetCharKeyByDBKey(dbKey), oldCharProfile);
    for (const auto& subscriberInfo : subscriberInfos) {
        sptr<IProfileChangeListener> listenerProxy = iface_cast<IProfileChangeListener>(subscriberInfo.GetListener());
        if (listenerProxy == nullptr) {
            HILOGE("Cast to IProfileChangeListener failed!");
            continue;
        }
        if (subscriberInfo.GetProfileChangeTypes().count(ProfileChangeType::CHAR_PROFILE_UPDATE) != 0) {
            listenerProxy->OnCharacteristicProfileUpdate(oldCharProfile, newCharProfile);
        }
    }
    return DP_SUCCESS;
}

int32_t SubscribeProfileManager::NotifyCharProfileDelete(const std::string& dbKey, const std::string& dbValue)
{
    std::map<std::string, std::string> values;
    values[dbKey] = dbValue;
    CharacteristicProfile charProfile;
    charProfile.SetDeviceId(ProfileUtils::GetDeviceIdByDBKey(dbKey));
    charProfile.SetServiceName(ProfileUtils::GetServiceNameByDBKey(dbKey));
    charProfile.SetCharacteristicKey(ProfileUtils::GetCharKeyByDBKey(dbKey));
    ProfileUtils::EntriesToCharProfile(values, charProfile);
    HILOGI("NotifyCharProfileDelete : %{public}s!", charProfile.dump().c_str());
    auto subscriberInfos = GetSubscribeInfos(dbKey);
    for (const auto& subscriberInfo : subscriberInfos) {
        sptr<IProfileChangeListener> listenerProxy = iface_cast<IProfileChangeListener>(subscriberInfo.GetListener());
        if (listenerProxy == nullptr) {
            HILOGE("Cast to IProfileChangeListener failed!");
            continue;
        }
        if (subscriberInfo.GetProfileChangeTypes().count(ProfileChangeType::CHAR_PROFILE_DELETE) != 0) {
            listenerProxy->OnCharacteristicProfileDelete(charProfile);
        }
    }
    return DP_SUCCESS;
}
std::unordered_set<SubscribeInfo, SubscribeHash, SubscribeCompare> SubscribeProfileManager::GetSubscribeInfos(
    const std::string& dbKey)
{
    {
        std::lock_guard<std::mutex> lock(subscribeMutex_);
        if (subscribeInfoMap_.find(dbKey) == subscribeInfoMap_.end()) {
            HILOGE("This dbKey is not subscribed, dbKey: %{public}s", ProfileUtils::GetAnonyString(dbKey).c_str());
            return {};
        }
        return subscribeInfoMap_[dbKey];
    }
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
