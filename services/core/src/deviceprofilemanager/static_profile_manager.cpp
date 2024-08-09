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

#include <mutex>
#include <memory>
#include <algorithm>
#include <dlfcn.h>
#include <vector>

#include "static_profile_manager.h"

#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"
#include "kv_data_change_listener.h"
#include "kv_store_death_recipient.h"
#include "kv_sync_completed_listener.h"
#include "kv_adapter.h"
#include "profile_cache.h"
#include "profile_control_utils.h"
#include "profile_utils.h"
#include "static_capability_loader.h"

namespace OHOS {
namespace DistributedDeviceProfile {
IMPLEMENT_SINGLE_INSTANCE(StaticProfileManager);
namespace {
    const std::string TAG = "StaticProfileManager";
    const std::string APP_ID = "distributed_device_profile_service";
    const std::string STORE_ID = "dp_kv_static_store";
}

int32_t StaticProfileManager::Init()
{
    HILOGI("call!");
    int32_t initResult = DP_MANAGER_INIT_FAIL;
    {
        std::lock_guard<std::mutex> lock(staticStoreMutex_);
        staticProfileStore_ = std::make_shared<KVAdapter>(APP_ID, STORE_ID,
            std::make_shared<KvDataChangeListener>(STORE_ID),
            std::make_shared<KvSyncCompletedListener>(STORE_ID), std::make_shared<KvDeathRecipient>(STORE_ID),
            DistributedKv::TYPE_STATICS);
        initResult = staticProfileStore_->Init();
    }
    HILOGI("Init finish, res: %{public}d", initResult);
    return initResult;
}

int32_t StaticProfileManager::UnInit()
{
    HILOGI("call!");
    {
        std::lock_guard<std::mutex> lock(staticStoreMutex_);
        if (staticProfileStore_ == nullptr) {
            HILOGE("staticProfileStore_ is nullptr!");
            return DP_NULLPTR;
        }
        staticProfileStore_->UnInit();
        staticProfileStore_ = nullptr;
    }
    return DP_SUCCESS;
}

int32_t StaticProfileManager::ReInit()
{
    HILOGI("call!");
    UnInit();
    return Init();
}

int32_t StaticProfileManager::PutCharacteristicProfile(const CharacteristicProfile& charProfile)
{
    HILOGD("call!");
    int32_t putResult = DP_PUT_CHARACTERISTIC_CACHE_ERR;
    {
        std::lock_guard<std::mutex> lock(staticStoreMutex_);
        putResult = ProfileControlUtils::PutCharacteristicProfile(staticProfileStore_, charProfile);
    }
    HILOGI("PutCharacteristicProfile result: %{public}d!", putResult);
    return putResult;
}

int32_t StaticProfileManager::GetCharacteristicProfile(const std::string& deviceId, const std::string& serviceName,
    const std::string& characteristicKey, CharacteristicProfile& charProfile)
{
    HILOGD("call!");
    if (!ProfileUtils::IsKeyValid(deviceId) || !ProfileUtils::IsKeyValid(serviceName) ||
        !ProfileUtils::IsKeyValid(characteristicKey)) {
        HILOGE("Params are invalid!");
        return DP_INVALID_PARAMS;
    }
    HILOGD("deviceId: %{public}s, serviceName: %{public}s, charKey: %{public}s!",
        ProfileUtils::GetAnonyString(deviceId).c_str(), serviceName.c_str(), characteristicKey.c_str());
    if (ProfileCache::GetInstance().GetStaticCharacteristicProfile(deviceId, serviceName, characteristicKey,
        charProfile) == DP_SUCCESS) {
        HILOGI("profile: %{public}s!", charProfile.dump().c_str());
        return DP_SUCCESS;
    }
    CharacteristicProfile staticCapabilityProfile;
    int32_t getResult = DP_GET_KV_DB_FAIL;
    {
        std::lock_guard<std::mutex> lock(staticStoreMutex_);
        getResult = ProfileControlUtils::GetCharacteristicProfile(staticProfileStore_, deviceId,
            STATIC_CAPABILITY_SVR_ID, STATIC_CAPABILITY_CHAR_ID, staticCapabilityProfile);
    }
    if (getResult != DP_SUCCESS) {
        HILOGE("GetCharacteristicProfile fail, reason: %{public}d!", getResult);
        return getResult;
    }
    HILOGI("profile : %{public}s", staticCapabilityProfile.dump().c_str());
    std::unordered_map<std::string, CharacteristicProfile> staticInfoProfiles;
    int generateProfileResult = GenerateStaticInfoProfile(staticCapabilityProfile, staticInfoProfiles);
    if (generateProfileResult != DP_SUCCESS) {
        HILOGE("GenerateStaticInfoProfile fail, reason: %{public}d!", generateProfileResult);
        return generateProfileResult;
    }
    std::string charProfileKey = ProfileUtils::GenerateCharProfileKey(deviceId, serviceName, characteristicKey);
    if (staticInfoProfiles.find(charProfileKey) == staticInfoProfiles.end()) {
        HILOGE("charKey not exist, deviceId: %{public}s, serviceName: %{public}s, characteristicKey: %{public}s",
            ProfileUtils::GetAnonyString(deviceId).c_str(), serviceName.c_str(), characteristicKey.c_str());
        return DP_NOT_FOUND_FAIL;
    }
    charProfile = staticInfoProfiles[charProfileKey];
    ProfileCache::GetInstance().AddStaticCharProfileBatch(staticInfoProfiles);
    return DP_SUCCESS;
}

int32_t StaticProfileManager::GetAllCharacteristicProfile(
    std::vector<CharacteristicProfile>& staticCapabilityProfiles)
{
    HILOGD("call!");
    int32_t getAllResult = DP_GET_KV_DB_FAIL;
    {
        std::lock_guard<std::mutex> lock(staticStoreMutex_);
        getAllResult = ProfileControlUtils::GetAllCharacteristicProfile(staticProfileStore_, staticCapabilityProfiles);
    }
    if (getAllResult != DP_SUCCESS) {
        HILOGE("GetAllCharacteristicProfile fail, reason: %{public}d!", getAllResult);
        return getAllResult;
    }
    return DP_SUCCESS;
}

int32_t StaticProfileManager::GenerateStaticInfoProfile(const CharacteristicProfile& staticCapabilityProfile,
    std::unordered_map<std::string, CharacteristicProfile>& staticInfoProfiles)
{
    HILOGD("call!");
    std::string charValue = staticCapabilityProfile.GetCharacteristicValue();
    cJSON* charValueJson = cJSON_Parse(charValue.c_str());
    if (!cJSON_IsObject(charValueJson)) {
        HILOGE("cJSON_Parse fail! charValue : %{public}s", charValue.c_str());
        cJSON_Delete(charValueJson);
        return DP_PARSE_STATIC_CAP_FAIL;
    }
    cJSON* staticCapabilityVersionItem = cJSON_GetObjectItemCaseSensitive(charValueJson,
        STATIC_CAPABILITY_VERSION.c_str());
    if (!cJSON_IsString(staticCapabilityVersionItem) || (staticCapabilityVersionItem->valuestring == NULL)) {
        HILOGE("staticCapabilityVersion is invalid!");
        cJSON_Delete(charValueJson);
        return DP_PARSE_STATIC_CAP_FAIL;
    }
    std::string staticCapabilityVersion = staticCapabilityVersionItem->valuestring;
    cJSON* staticCapabilityValueItem = cJSON_GetObjectItemCaseSensitive(charValueJson, STATIC_CAPABILITY_VALUE.c_str());
    if (!cJSON_IsString(staticCapabilityValueItem) || (staticCapabilityValueItem->valuestring == NULL)) {
        HILOGE("staticCapabilityValue is invalid!");
        cJSON_Delete(charValueJson);
        return DP_PARSE_STATIC_CAP_FAIL;
    }
    std::string staticCapabilityValue = staticCapabilityValueItem->valuestring;
    cJSON_Delete(charValueJson);
    StaticCapabilityLoader::GetInstance().LoadStaticProfiles(staticCapabilityProfile.GetDeviceId(),
        staticCapabilityValue, staticCapabilityVersion, staticInfoProfiles);
    return DP_SUCCESS;
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
