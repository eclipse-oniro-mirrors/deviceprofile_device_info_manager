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

#include "device_profile_manager.h"

#include <algorithm>
#include <dlfcn.h>
#include <list>
#include <thread>

#include "dm_constants.h"

#include "content_sensor_manager_utils.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"
#include "kv_adapter.h"
#include "permission_manager.h"
#include "profile_utils.h"
#include "profile_cache.h"
#include "profile_control_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {
constexpr const char *LIB_DP_ADAPTER_NAME = "libdeviceprofileadapter.z.so";
IMPLEMENT_SINGLE_INSTANCE(DeviceProfileManager);
namespace {
    const std::string APP_ID = "distributed_device_profile_service";
    const std::string STORE_ID = "dp_kv_store";
    const std::string TAG = "DeviceProfileManager";
    const std::string DP_MANAGER_HANDLER = "dp_manager_handler";
    const int32_t DEFAULT_OS_TYPE = 10;
}

int32_t DeviceProfileManager::Init()
{
    HILOGI("call!");
    int32_t initResult = DP_MANAGER_INIT_FAIL;
    {
        std::lock_guard<std::mutex> lock(dynamicStoreMutex_);
        deviceProfileStore_ = std::make_shared<KVAdapter>(APP_ID, STORE_ID, std::make_shared<KvDataChangeListener>(),
            std::make_shared<KvSyncCompletedListener>(), std::make_shared<KvDeathRecipient>(STORE_ID),
            DistributedKv::TYPE_DYNAMICAL);
        initResult = deviceProfileStore_->Init();
        if (initResult != DP_SUCCESS) {
            HILOGE("deviceProfileStore init failed");
            return initResult;
        }
        std::string localDeviceId = ContentSensorManagerUtils::GetInstance().ObtainLocalUdid();
        std::string dbKeyPrefix = ProfileUtils::GenerateDeviceProfileKey(localDeviceId);
        std::map<std::string, std::string> values;
        int32_t status = deviceProfileStore_->GetByPrefix(dbKeyPrefix, values);
        if (status == DP_SUCCESS) {
            isFirst_.store(values.empty());
        }
    }
    LoadDpSyncAdapter();
    HILOGI("Init finish, res: %{public}d", initResult);
    return initResult;
}

int32_t DeviceProfileManager::UnInit()
{
    HILOGI("call!");
    {
        std::lock_guard<std::mutex> lock(dynamicStoreMutex_);
        if (deviceProfileStore_ == nullptr) {
            HILOGE("deviceProfileStore_ is nullptr");
            return DP_KV_DB_PTR_NULL;
        }
        deviceProfileStore_->UnInit();
        deviceProfileStore_ = nullptr;
    }
    {
        std::lock_guard<std::mutex> lock(putTempCacheMutex_);
        putTempCache_.clear();
    }
    UnloadDpSyncAdapter();
    return DP_SUCCESS;
}

int32_t DeviceProfileManager::ReInit()
{
    HILOGI("call!");
    UnInit();
    return Init();
}

int32_t DeviceProfileManager::PutDeviceProfile(const DeviceProfile& deviceProfile)
{
    HILOGI("call! deviceProfile: %{public}s", deviceProfile.AnnoymizeDump().c_str());
    if (!ProfileUtils::IsDevProfileValid(deviceProfile)) {
        HILOGE("the profile is invalid! deviceProfile: %{public}s", deviceProfile.AnnoymizeDump().c_str());
        return DP_INVALID_PARAMS;
    }
    std::map<std::string, std::string> entries;
    ProfileUtils::DeviceProfileToEntries(deviceProfile, entries);
    if (isFirst_.load()) {
        AddToPutTempCache(entries);
        return DP_SUCCESS;
    }
    {
        std::lock_guard<std::mutex> lock(dynamicStoreMutex_);
        if (deviceProfileStore_ == nullptr) {
            HILOGE("deviceProfileStore is nullptr!");
            return DP_KV_DB_PTR_NULL;
        }
        if (deviceProfileStore_->PutBatch(entries) != DP_SUCCESS) {
            HILOGE("PutDeviceProfile fail! deviceProfile: %{public}s", deviceProfile.AnnoymizeDump().c_str());
            return DP_PUT_KV_DB_FAIL;
        }
    }
    HILOGI("PutDeviceProfile success");
    return DP_SUCCESS;
}

int32_t DeviceProfileManager::PutServiceProfile(const ServiceProfile& serviceProfile)
{
    HILOGI("call! serviceProfile: %{public}s", serviceProfile.dump().c_str());
    if (!ProfileUtils::IsSvrProfileValid(serviceProfile)) {
        HILOGE("the profile is invalid!");
        return DP_INVALID_PARAMS;
    }
    std::map<std::string, std::string> entries;
    ProfileUtils::ServiceProfileToEntries(serviceProfile, entries);
    if (isFirst_.load()) {
        AddToPutTempCache(entries);
        return DP_SUCCESS;
    }
    {
        std::lock_guard<std::mutex> lock(dynamicStoreMutex_);
        if (deviceProfileStore_ == nullptr) {
            HILOGE("deviceProfileStore is nullptr!");
            return DP_KV_DB_PTR_NULL;
        }
        if (deviceProfileStore_->PutBatch(entries) != DP_SUCCESS) {
            HILOGE("PutServiceProfile fail! serviceProfile: %{public}s", serviceProfile.dump().c_str());
            return DP_PUT_KV_DB_FAIL;
        }
    }
    HILOGI("PutServiceProfile success");
    return DP_SUCCESS;
}

int32_t DeviceProfileManager::PutServiceProfileBatch(const std::vector<ServiceProfile>& serviceProfiles)
{
    HILOGI("call!");
    std::map<std::string, std::string> entries;
    for (const auto& serviceProfile : serviceProfiles) {
        if (!ProfileUtils::IsSvrProfileValid(serviceProfile)) {
            HILOGE("the profile is invalid! serviceProfile:%{public}s", serviceProfile.dump().c_str());
            continue;
        }
        ProfileUtils::ServiceProfileToEntries(serviceProfile, entries);
    }
    if (isFirst_.load()) {
        AddToPutTempCache(entries);
        return DP_SUCCESS;
    }
    {
        std::lock_guard<std::mutex> lock(dynamicStoreMutex_);
        if (deviceProfileStore_ == nullptr) {
            HILOGE("deviceProfileStore is nullptr!");
            return DP_KV_DB_PTR_NULL;
        }
        if (deviceProfileStore_->PutBatch(entries) != DP_SUCCESS) {
            HILOGE("PutServiceProfileBatch fail!");
            return DP_PUT_KV_DB_FAIL;
        }
    }
    HILOGI("PutServiceProfileBatch success");
    return DP_SUCCESS;
}

int32_t DeviceProfileManager::PutCharacteristicProfile(const CharacteristicProfile& charProfile)
{
    HILOGI("call! charProfile: %{public}s", charProfile.dump().c_str());
    if (!ProfileUtils::IsCharProfileValid(charProfile)) {
        HILOGE("the profile is invalid!");
        return DP_INVALID_PARAMS;
    }
    std::map<std::string, std::string> entries;
    ProfileUtils::CharacteristicProfileToEntries(charProfile, entries);
    if (isFirst_.load()) {
        AddToPutTempCache(entries);
        return DP_SUCCESS;
    }
    {
        std::lock_guard<std::mutex> lock(dynamicStoreMutex_);
        if (deviceProfileStore_ == nullptr) {
            HILOGE("deviceProfileStore is nullptr!");
            return DP_KV_DB_PTR_NULL;
        }
        if (deviceProfileStore_->PutBatch(entries) != DP_SUCCESS) {
            HILOGE("PutCharacteristicProfile fail! charProfile: %{public}s", charProfile.dump().c_str());
            return DP_PUT_KV_DB_FAIL;
        }
    }
    HILOGI("PutCharacteristicProfile success");
    return DP_SUCCESS;
}

int32_t DeviceProfileManager::PutCharacteristicProfileBatch(const std::vector<CharacteristicProfile>& charProfiles)
{
    HILOGI("call!");
    std::map<std::string, std::string> entries;
    for (const auto& charProfile : charProfiles) {
        if (!ProfileUtils::IsCharProfileValid(charProfile)) {
            HILOGE("the profile is invalid! charProfile:%{public}s", charProfile.dump().c_str());
            continue;
        }
        ProfileUtils::CharacteristicProfileToEntries(charProfile, entries);
    }
    if (isFirst_.load()) {
        AddToPutTempCache(entries);
        return DP_SUCCESS;
    }
    {
        std::lock_guard<std::mutex> lock(dynamicStoreMutex_);
        if (deviceProfileStore_ == nullptr) {
            HILOGE("deviceProfileStore is nullptr!");
            return DP_KV_DB_PTR_NULL;
        }
        if (deviceProfileStore_->PutBatch(entries) != DP_SUCCESS) {
            HILOGE("PutCharacteristicProfileBatch fail!");
            return DP_PUT_KV_DB_FAIL;
        }
    }
    HILOGI("PutCharacteristicProfileBatch success");
    return DP_SUCCESS;
}

int32_t DeviceProfileManager::GetDeviceProfile(const std::string& deviceId, DeviceProfile& deviceProfile)
{
    HILOGI("call!");
    int32_t res = 0;
    {
        std::lock_guard<std::mutex> lock(dynamicStoreMutex_);
        res = ProfileControlUtils::GetDeviceProfile(deviceProfileStore_, deviceId, deviceProfile);
    }
    if (res != DP_SUCCESS) {
        HILOGE("GetDeviceProfile fail, reason: %{public}d!", res);
        return res;
    }
    HILOGI("GetDeviceProfile success");
    return DP_SUCCESS;
}

int32_t DeviceProfileManager::GetServiceProfile(const std::string& deviceId, const std::string& serviceName,
    ServiceProfile& serviceProfile)
{
    HILOGI("call!");
    int32_t res = 0;
    {
        std::lock_guard<std::mutex> lock(dynamicStoreMutex_);
        res = ProfileControlUtils::GetServiceProfile(deviceProfileStore_, deviceId, serviceName,
            serviceProfile);
    }
    if (res != DP_SUCCESS) {
        HILOGE("GetServiceProfile fail, reason: %{public}d!", res);
        return res;
    }
    HILOGI("GetServiceProfile success");
    return DP_SUCCESS;
}

int32_t DeviceProfileManager::GetCharacteristicProfile(const std::string& deviceId, const std::string& serviceName,
    const std::string& characteristicKey, CharacteristicProfile& charProfile)
{
    HILOGI("call!");
    int32_t res = 0;
    {
        std::lock_guard<std::mutex> lock(dynamicStoreMutex_);
        res = ProfileControlUtils::GetCharacteristicProfile(deviceProfileStore_, deviceId, serviceName,
            characteristicKey, charProfile);
    }
    if (res != DP_SUCCESS) {
        HILOGE("GetCharacteristicProfile fail, reason: %{public}d!", res);
        return res;
    }
    HILOGI("GetCharacteristicProfile success");
    return DP_SUCCESS;
}

int32_t DeviceProfileManager::DeleteServiceProfile(const std::string& deviceId, const std::string& serviceName)
{
    HILOGI("call!");
    int32_t res = 0;
    {
        std::lock_guard<std::mutex> lock(dynamicStoreMutex_);
        res = ProfileControlUtils::DeleteServiceProfile(deviceProfileStore_, deviceId, serviceName);
    }
    if (res != DP_SUCCESS) {
        HILOGE("DeleteServiceProfile fail, reason: %{public}d!", res);
        return res;
    }
    HILOGI("DeleteServiceProfile success");
    return DP_SUCCESS;
}

int32_t DeviceProfileManager::DeleteCharacteristicProfile(const std::string& deviceId, const std::string& serviceName,
    const std::string& characteristicKey)
{
    HILOGI("call!");
    int32_t res = 0;
    {
        std::lock_guard<std::mutex> lock(dynamicStoreMutex_);
        res = ProfileControlUtils::DeleteCharacteristicProfile(deviceProfileStore_, deviceId, serviceName,
            characteristicKey);
    }
    if (res != DP_SUCCESS) {
        HILOGE("DeleteCharacteristicProfile fail, reason: %{public}d!", res);
        return res;
    }
    HILOGI("DeleteCharacteristicProfile success");
    return DP_SUCCESS;
}

int32_t DeviceProfileManager::GetAllDeviceProfile(std::vector<DeviceProfile>& deviceProfiles)
{
    HILOGI("call!");
    int32_t res = 0;
    {
        std::lock_guard<std::mutex> lock(dynamicStoreMutex_);
        res = ProfileControlUtils::GetAllDeviceProfile(deviceProfileStore_, deviceProfiles);
    }
    if (res != DP_SUCCESS) {
        HILOGE("GetAllDeviceProfile fail, reason: %{public}d!", res);
        return res;
    }
    HILOGI("GetAllDeviceProfile success");
    return DP_SUCCESS;
}

int32_t DeviceProfileManager::GetAllServiceProfile(std::vector<ServiceProfile>& serviceProfiles)
{
    HILOGI("call!");
    int32_t res = 0;
    {
        std::lock_guard<std::mutex> lock(dynamicStoreMutex_);
        res = ProfileControlUtils::GetAllServiceProfile(deviceProfileStore_, serviceProfiles);
    }
    if (res != DP_SUCCESS) {
        HILOGE("serviceProfiles fail, reason: %{public}d!", res);
        return res;
    }
    HILOGI("serviceProfiles success");
    return DP_SUCCESS;
}

int32_t DeviceProfileManager::GetAllCharacteristicProfile(std::vector<CharacteristicProfile>& charProfiles)
{
    HILOGI("call!");
    int32_t res = 0;
    {
        std::lock_guard<std::mutex> lock(dynamicStoreMutex_);
        res = ProfileControlUtils::GetAllCharacteristicProfile(deviceProfileStore_, charProfiles);
    }
    if (res != DP_SUCCESS) {
        HILOGE("GetAllCharacteristicProfile fail, reason: %{public}d!", res);
        return res;
    }
    HILOGI("GetAllCharacteristicProfile success");
    return DP_SUCCESS;
}

int32_t DeviceProfileManager::SyncDeviceProfile(const DistributedDeviceProfile::DpSyncOptions &syncOptions,
    sptr<IRemoteObject> syncCompletedCallback)
{
    HILOGI("call!");
    if (syncCompletedCallback == nullptr) {
        HILOGE("Params is invalid!");
        return DP_INVALID_PARAMS;
    }
    HILOGI("SyncDeviceProfile start!");
    std::vector<std::string> onlineDevices = ProfileUtils::FilterOnlineDevices(syncOptions.GetDeviceList());
    if (onlineDevices.empty()) {
        HILOGE("Params is invalid!");
        return DP_INVALID_PARAMS;
    }
    std::vector<std::string> openHarmonyDevices;
    for (auto it = onlineDevices.begin(); it != onlineDevices.end(); it++) {
        std::string deviceId = *it;
        if (RunloadedFunction(deviceId, syncCompletedCallback) != DP_SUCCESS) {
            openHarmonyDevices.push_back(deviceId);
        }
    }
    if (openHarmonyDevices.empty()) {
        return DP_SUCCESS;
    }
    std::string callerDescriptor = PermissionManager::GetInstance().GetCallerProcName();
    ProfileCache::GetInstance().AddSyncListener(callerDescriptor, syncCompletedCallback);
    {
        std::lock_guard<std::mutex> lock(dynamicStoreMutex_);
        if (deviceProfileStore_ == nullptr) {
            HILOGE("deviceProfileStore_ is nullptr");
            return DP_KV_DB_PTR_NULL;
        }
        int32_t syncResult = deviceProfileStore_->Sync(openHarmonyDevices, syncOptions.GetSyncMode());
        if (syncResult != DP_SUCCESS) {
            HILOGI("SyncDeviceProfile fail, res: %{public}d!", syncResult);
            return DP_SYNC_DEVICE_FAIL;
        }
    }
    HILOGI("SyncDeviceProfile success, caller: %{public}s!", callerDescriptor.c_str());
    return DP_SUCCESS;
}

bool DeviceProfileManager::LoadDpSyncAdapter()
{
    HILOGI("DeviceProfileManager::LoadDpSyncAdapter start.");
    std::lock_guard<std::mutex> lock(isAdapterLoadLock_);
    if (isAdapterSoLoaded_ && (dpSyncAdapter_ != nullptr)) {
        return true;
    }
    char path[PATH_MAX + 1] = {0x00};
    std::string soName = std::string(LIB_LOAD_PATH) + std::string(LIB_DP_ADAPTER_NAME);
    if ((soName.length() == 0) || (soName.length() > PATH_MAX) || (realpath(soName.c_str(), path) == nullptr)) {
        HILOGI("File %{public}s canonicalization failed", soName.c_str());
        return false;
    }
    void *so_handle = dlopen(path, RTLD_NOW);
    if (so_handle == nullptr) {
        HILOGI("load dp sync adapter so %{public}s failed", soName.c_str());
        return false;
    }
    dlerror();
    auto func = (CreateDPSyncAdapterFuncPtr)dlsym(so_handle, "CreateDPSyncAdaptertObject");
    if (dlerror() != nullptr || func == nullptr) {
        dlclose(so_handle);
        HILOGI("Create object function is not exist.");
        return false;
    }
    auto adapter = func();
    if (adapter = nullptr) {
        dlclose(so_handle);
        HILOGI("adapter is nullptr");
        return false;
    }
    dpSyncAdapter_ = std::shared_ptr<IDPSyncAdapter>(adapter);
    if (dpSyncAdapter_->Initialize() != DP_SUCCESS) {
        dlclose(so_handle);
        dpSyncAdapter_ = nullptr;
        isAdapterSoLoaded_ = false;
        HILOGI("dp sync adapter init failed");
        return false;
    }
    isAdapterSoLoaded_ = true;
    HILOGI("DeviceProfileManager::LoadDpSyncAdapter sucess");
    return true;
}

void DeviceProfileManager::UnloadDpSyncAdapter()
{
    HILOGI("DeviceProfileManager::UnloadDpSyncAdapter start.");
    std::lock_guard<std::mutex> lock(isAdapterLoadLock_);
    if (dpSyncAdapter_ != nullptr) {
        dpSyncAdapter_->Release();
    }
    dpSyncAdapter_ = nullptr;
    char path[PATH_MAX + 1] = {0x00};
    std::string soPathName = std::string(LIB_LOAD_PATH) + std::string(LIB_DP_ADAPTER_NAME);
    if ((soPathName.length() == 0) || (soPathName.length() > PATH_MAX) ||
        (realpath(soPathName.c_str(), path) == nullptr)) {
        HILOGI("File %{public}s canonicalization failed", soPathName.c_str());
        return;
    }
    void *so_handle = dlopen(path, RTLD_NOW | RTLD_NOLOAD);
    if (so_handle != nullptr) {
        HILOGI("dp sync adapter so_handle is not nullptr.");
        dlclose(so_handle);
        isAdapterSoLoaded_ = false;
    }
}

int32_t DeviceProfileManager::RunloadedFunction(std::string deviceId, sptr<IRemoteObject> syncCompletedCallback)
{
    if (!LoadDpSyncAdapter()) {
        HILOGE("dp service adapter load failed.");
        return DP_LOAD_SYNC_ADAPTER_FAILED;
    }
    if (dpSyncAdapter_ == nullptr) {
        HILOGE("dpSyncAdapter_ is nullptr");
        return DP_NULLPTR;
    }
    if (dpSyncAdapter_->Initialize() != DP_SUCCESS) {
        HILOGE("dp service adapter initialize failed.");
        return DP_LOAD_SYNC_ADAPTER_FAILED;
    }
    if (dpSyncAdapter_->DetectRemoteDPVersion(deviceId) != DP_SUCCESS) {
        HILOGE("dp service adapter detect remote version failed.");
        return DP_LOAD_SYNC_ADAPTER_FAILED;
    }
    const std::list<std::string> deviceIdList = { deviceId };
    if (dpSyncAdapter_->SyncProfile(deviceIdList, syncCompletedCallback) != DP_SUCCESS) {
        HILOGE("dp service adapter sync profile failed.");
        return DP_LOAD_SYNC_ADAPTER_FAILED;
    }
    HILOGD("dp service adapter sync profile success.");
    return DP_SUCCESS;
}

int32_t DeviceProfileManager::DeviceOnlineAutoSync(const std::string& peerNetworkId)
{
    HILOGI("call! peerNetworkId=%{public}s", ProfileUtils::GetAnonyString(peerNetworkId).c_str());
    std::vector<std::string> deviceList{peerNetworkId};
    std::vector<std::string> onlineDevices = ProfileUtils::FilterOnlineDevices(deviceList);
    if (onlineDevices.empty() ||
        std::find(onlineDevices.begin(), onlineDevices.end(), peerNetworkId) == onlineDevices.end()) {
        HILOGE("Params is invalid! peerNetworkId=%{public}s", ProfileUtils::GetAnonyString(peerNetworkId).c_str());
        return DP_INVALID_PARAMS;
    }
    int32_t errCode = RunloadedFunction(peerNetworkId, nullptr);
    if (errCode != DP_SUCCESS) {
        HILOGE("sync profile failed.errCode=%{public}d,peerNetworkId=%{public}s", errCode,
            ProfileUtils::GetAnonyString(peerNetworkId).c_str());
    }
    return errCode;
}

std::vector<DistributedKv::Entry> DeviceProfileManager::GetEntriesByKeys(const std::vector<std::string>& keys)
{
    HILOGI("call!");
    std::vector<DistributedKv::Entry> entries;
    if (keys.empty()) {
        HILOGE("keys empty.");
        return entries;
    }
    {
        std::lock_guard<std::mutex> lock(dynamicStoreMutex_);
        if (deviceProfileStore_ == nullptr) {
            HILOGE("dynamicProfileStore is nullptr!");
            return entries;
        }
        for (const auto& key : keys) {
            std::string value;
            if (deviceProfileStore_->Get(key, value) != DP_SUCCESS) {
                continue;
            }
            DistributedKv::Entry entry;
            DistributedKv::Key kvKey(key);
            entry.key = kvKey;
            entry.value = value;
            entries.emplace_back(entry);
        }
    }
    return entries;
}

void DeviceProfileManager::AddToPutTempCache(const std::map<std::string, std::string>& values)
{
    if (values.empty()) {
        HILOGW("values empty!");
        return;
    }
    HILOGI("values.size : %{public}zu", values.size());
    {
        std::lock_guard<std::mutex> lock(putTempCacheMutex_);
        for (const auto& [key, value] : values) {
            putTempCache_[key] = value;
        }
    }
}

int32_t DeviceProfileManager::SavePutTempCache(std::map<std::string, std::string>& entries)
{
    HILOGI("business entries.size : %{public}zu", entries.size());
    {
        std::lock_guard<std::mutex> lock(putTempCacheMutex_);
        if (!putTempCache_.empty()) {
            for (const auto& [key, value] : putTempCache_) {
                entries[key] = value;
            }
        }
    }
    if (entries.empty()) {
        HILOGW("all entries empty!");
        isFirst_.store(false);
        {
            std::lock_guard<std::mutex> lock(putTempCacheMutex_);
            putTempCache_.clear();
        }
        return DP_SUCCESS;
    }
    HILOGI("all entries.size : %{public}zu", entries.size());
    int32_t ret = DP_SUCCESS;
    {
        std::lock_guard<std::mutex> lock(dynamicStoreMutex_);
        if (deviceProfileStore_ == nullptr) {
            HILOGE("deviceProfileStore is nullptr!");
            return DP_GET_KV_DB_FAIL;
        }
        ret = deviceProfileStore_->PutBatch(entries);
        if (ret != DP_SUCCESS) {
            HILOGE("PutBatch fail! ret:%{public}d", ret);
            return ret;
        }
    }
    isFirst_.store(false);
    {
        std::lock_guard<std::mutex> lock(putTempCacheMutex_);
        putTempCache_.clear();
    }
    HILOGI("put all entries success");
    return ret;
}

bool DeviceProfileManager::IsFirstInitDB()
{
    return isFirst_.load();
}

void DeviceProfileManager::ResetFirst()
{
    isFirst_.store(false);
}

void DeviceProfileManager::ClearDataOnDeviceOnline(const std::string& networkId, const std::string& extraData)
{
    HILOGI("networkId:%{public}s", ProfileUtils::GetAnonyString(networkId).c_str());
    if (networkId.empty() || extraData.empty()) {
        HILOGE("networkId or extraData is empty!");
        return;
    }
    auto clearDataTask = [this, networkId, extraData]() {
        cJSON* extraDataJson = cJSON_Parse(extraData.c_str());
        if (extraDataJson == NULL) {
            HILOGE("extraData parse failed");
            return;
        }
        int32_t osType = DEFAULT_OS_TYPE;
        cJSON* osTypeJson = cJSON_GetObjectItem(extraDataJson, DistributedHardware::PARAM_KEY_OS_TYPE);
        if (cJSON_IsNumber(osTypeJson)) {
            osType = static_cast<int32_t>(osTypeJson->valueint);
        }
        cJSON_Delete(extraDataJson);
        if (osType != DEFAULT_OS_TYPE) {
            return;
        }
        std::string deviceId;
        if (!ProfileUtils::GetUdidByNetworkId(networkId, deviceId) || deviceId.empty()) {
            HILOGE("GetUdidByNetworkId failed");
            return;
        }
        DeviceProfile deviceProfile;
        if (GetDeviceProfile(deviceId, deviceProfile) != DP_SUCCESS || osType == deviceProfile.GetOsType()) {
            return;
        }
        std::string key = ProfileUtils::GenerateDBKey(ProfileUtils::GenerateDeviceProfileKey(deviceId), OS_TYPE);
        std::string value = std::to_string(osType);
        {
            std::lock_guard<std::mutex> lock(dynamicStoreMutex_);
            if (deviceProfileStore_ == nullptr) {
                HILOGE("dynamicProfileStore is nullptr!");
                return;
            }
            if (deviceProfileStore_->Put(key, value) != DP_SUCCESS) {
                HILOGE("Put failed!");
                return;
            }
        }
    };
    std::thread(clearDataTask).detach();
}
} // namespace DeviceProfile
} // namespace OHOS