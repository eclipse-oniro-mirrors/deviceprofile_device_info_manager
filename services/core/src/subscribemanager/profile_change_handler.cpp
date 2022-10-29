/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "profile_change_handler.h"

#include <cinttypes>

#include "datetime_ex.h"
#include "string_ex.h"

#include "authority_manager.h"
#include "device_profile_errors.h"
#include "device_profile_log.h"
#include "device_profile_storage_manager.h"
#include "device_profile_utils.h"
#include "profile_change_notification.h"

namespace OHOS {
namespace DeviceProfile {
using namespace OHOS::DistributedKv;

namespace {
const std::string TAG = "ProfileChangeHandler";

constexpr int32_t NUM_KEY_FILEDS = 3;
constexpr int32_t DEVICE_ID_SIZE = 64;
}

struct ProfileKey {
    std::string udid;
    std::string serviceId;
    KeyType type {KeyType::UNKNOWN};

    static std::unique_ptr<ProfileKey> Parse(const std::string& entryKey);
};

std::unique_ptr<ProfileKey> ProfileKey::Parse(const std::string& entryKey)
{
    std::vector<std::string> vec;
    SplitStr(entryKey, "/", vec);
    if (vec.size() != NUM_KEY_FILEDS) {
        HILOGE("parse key failed");
        return nullptr;
    }

    int32_t index = 0;
    auto profileKey = std::make_unique<ProfileKey>();
    profileKey->udid = std::move(vec[index++]);
    if (profileKey->udid.size() != DEVICE_ID_SIZE) {
        HILOGE("parse udid failed");
        return nullptr;
    }
    int32_t type = 0;
    if (!StrToInt(vec[index++], type)) {
        HILOGE("parse type failed");
        return nullptr;
    }
    profileKey->type = static_cast<KeyType>(type);
    profileKey->serviceId = std::move(vec[index]);
    return profileKey;
}

void ProfileChangeHandler::OnChange(const ChangeNotification& changeNotification)
{
    std::vector<ProfileEntry> profileEntries;
    const auto& insertedEntries = changeNotification.GetInsertEntries();
    const auto& updatedEntries = changeNotification.GetUpdateEntries();
    const auto& deletedEntries = changeNotification.GetDeleteEntries();
    int32_t numEntries = insertedEntries.size() + updatedEntries.size() + deletedEntries.size();
    profileEntries.reserve(numEntries);
    HILOGI("numEntries = %{public}d", numEntries);

    int64_t begin = GetTickCount();
    Service2Index service2Index;
    Entry entry;
    if (!insertedEntries.empty()) {
        entry = insertedEntries.front();
        ConvertEntry(insertedEntries, ProfileChangeType::INSERTED, profileEntries, service2Index);
    }
    if (!updatedEntries.empty()) {
        entry = updatedEntries.front();
        ConvertEntry(updatedEntries, ProfileChangeType::UPDATED, profileEntries, service2Index);
    }
    if (!deletedEntries.empty()) {
        entry = deletedEntries.front();
        ConvertEntry(deletedEntries, ProfileChangeType::DELETED, profileEntries, service2Index);
    }
    HILOGI("convert entry elapsedTime is %{public}" PRId64 " ms", GetTickCount() - begin);

    std::string udid;
    auto profileKey = ProfileKey::Parse(entry.key.ToString());
    if (profileKey == nullptr) {
        HILOGE("bad profile entry");
        return;
    }
    udid = std::move(profileKey->udid);
    HILOGI("udid = %{public}s", DeviceProfileUtils::AnonymizeDeviceId(udid).c_str());
    std::string localUdid;
    // won't fail
    DpDeviceManager::GetInstance().GetLocalDeviceUdid(localUdid);

    std::string networkId;
    if (!DpDeviceManager::GetInstance().TransformDeviceId(udid, networkId,
        DeviceIdType::NETWORKID)) {
        HILOGE("transform to networkid failed");
    }

    ProfileChangeNotification notification(profileEntries, networkId, localUdid == udid);
    auto notifyTask = [this, notification = std::move(notification),
        service2Index = std::move(service2Index)]() {
        NotifyProfileChanged(notification, service2Index);
    };
    std::lock_guard<std::mutex> autoLock(notifierLock_);
    if (eventHandler_ != nullptr && !eventHandler_->PostTask(notifyTask)) {
        HILOGI("post task failed");
    }
}

void ProfileChangeHandler::ConvertEntry(const std::vector<Entry>& entries,
    ProfileChangeType changeType, std::vector<ProfileEntry>& profileEntries,
    Service2Index& service2Index)
{
    for (const auto& entry : entries) {
        auto profileKey = ProfileKey::Parse(entry.key.ToString());
        if (profileKey == nullptr || profileKey->type != KeyType::SERVICE) {
            HILOGW("profileKey is invalid");
            continue;
        }

        std::string trimmedKey = std::move(profileKey->serviceId);
        HILOGI("key = %{public}s, state = %{public}u", trimmedKey.c_str(),
            static_cast<uint8_t>(changeType));
        service2Index.emplace(trimmedKey, profileEntries.size());
        profileEntries.emplace_back(std::move(trimmedKey), entry.value.ToString(), changeType);
        HILOGD("value = %{public}s, state = %{public}u",
            entry.value.ToString().c_str(), static_cast<uint8_t>(changeType));
    }
}

void ProfileChangeHandler::NotifyProfileChanged(const ProfileChangeNotification& changeNotification,
    const Service2Index& service2Index)
{
    HILOGD("called");
    std::lock_guard<std::mutex> autoLock(notifierLock_);
    HILOGI("subscribers size = %{public}zu", profileEventSubscribeInfos_.size());
    for (const auto& [notifier, subscribeInfo] : profileEventSubscribeInfos_) {
        sptr<IProfileEventNotifier> profileEventNotifier = iface_cast<IProfileEventNotifier>(notifier);
        if (profileEventNotifier == nullptr) {
            HILOGE("cast to IProfileEventNotifier failed");
            continue;
        }

        FilterInfo filterInfo;
        FilterChangedProfileLocked(subscribeInfo, changeNotification, service2Index, filterInfo);
        int64_t begin = GetTickCount();
        NotifyProfileChangedLocked(changeNotification, filterInfo, profileEventNotifier);
        HILOGI("notify elapsedTime is %{public}" PRId64 " ms", GetTickCount() - begin);
    }
}

void ProfileChangeHandler::NotifyProfileChangedLocked(const ProfileChangeNotification& changeNotification,
    const FilterInfo& filterInfo, const sptr<IProfileEventNotifier>& profileEventNotifier)
{
    if (!filterInfo.filtered) {
        HILOGD("not filtered");
        profileEventNotifier->OnProfileChanged(changeNotification);
        return;
    }

    const auto& indexes = filterInfo.indexes;
    // filtered but not found satisfied service
    size_t size = indexes.size();
    if (size == 0) {
        return;
    }

    std::vector<ProfileEntry> filteredEntries;
    filteredEntries.reserve(size);
    const auto& profileEntries = changeNotification.GetProfileEntries();
    for (auto index : indexes) {
        filteredEntries.emplace_back(profileEntries[index]);
    }
    HILOGI("filtered with %{public}zu entries", size);
    bool isLocal = changeNotification.IsLocal();
    std::string deviceId = changeNotification.GetDeviceId();
    ProfileChangeNotification filteredNotification(filteredEntries, deviceId, isLocal);
    profileEventNotifier->OnProfileChanged(filteredNotification);
}

void ProfileChangeHandler::FilterChangedProfileLocked(const SubscribeInfo& subscribeInfo,
    const ProfileChangeNotification& changeNotification,
    const Service2Index& service2Index, FilterInfo& filterInfo)
{
    const auto& extraInfo = subscribeInfo.extraInfo;

    // currently only support specific deviceId
    std::string deviceId = extraInfo["deviceId"];
    if (!deviceId.empty()) {
        filterInfo.filtered = true;
        std::string networkId;
        if (!DpDeviceManager::GetInstance().TransformDeviceId(deviceId, networkId,
            DeviceIdType::NETWORKID)) {
            HILOGE("transform to networkid failed");
            return;
        }
        if (networkId != changeNotification.GetDeviceId()) {
            return;
        }
    }

    const auto& serviceIdsJson = extraInfo["serviceIds"];
    auto& indexes = filterInfo.indexes;
    if (serviceIdsJson.empty()) {
        return;
    }
    filterInfo.filtered = true;
    for (const auto& serviceIdJson : serviceIdsJson) {
        std::string serviceId = serviceIdJson;
        HILOGI("serviceId = %{public}s", serviceId.c_str());
        auto iter = service2Index.find(serviceId);
        if (iter != service2Index.end()) {
            indexes.insert(iter->second);
        }
    }
}

int32_t ProfileChangeHandler::Register()
{
    HILOGI("called");
    return DeviceProfileStorageManager::GetInstance().SubscribeKvStore(shared_from_this());
}

int32_t ProfileChangeHandler::Unregister()
{
    HILOGI("called");
    return DeviceProfileStorageManager::GetInstance().UnSubscribeKvStore(shared_from_this());
}

int32_t ProfileChangeHandler::Subscribe(const SubscribeInfo& subscribeInfo,
    const sptr<IRemoteObject>& profileEventNotifier)
{
    const auto& extraInfo = subscribeInfo.extraInfo;
    const auto& serviceIdsJson = extraInfo["serviceIds"];
    std::vector<std::string> serviceIds;
    for (const auto& serviceIdJson : serviceIdsJson) {
        std::string serviceId = serviceIdJson;
        HILOGI("serviceId = %{public}s", serviceId.c_str());
        serviceIds.emplace_back(std::move(serviceId));
    }

    if (!AuthorityManager::GetInstance().CheckServicesAuthority(AuthValue::AUTH_R,
        serviceIds)) {
        return ERR_DP_PERMISSION_DENIED;
    }
    return ProfileEventHandler::Subscribe(subscribeInfo, profileEventNotifier);
}
} // namespace DeviceProfile
} // namespace OHOS
