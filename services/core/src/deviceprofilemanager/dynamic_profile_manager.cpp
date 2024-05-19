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

#include "dynamic_profile_manager.h"

#include <mutex>
#include <memory>
#include <algorithm>
#include <dlfcn.h>
#include <vector>
#include <list>

#include "kv_adapter.h"
#include "content_sensor_manager_utils.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"
#include "profile_utils.h"
#include "profile_cache.h"
#include "profile_control_utils.h"
#include "permission_manager.h"

namespace OHOS {
namespace DistributedDeviceProfile {
constexpr const char *LIB_DP_ADAPTER_NAME = "libdeviceprofileadapter.z.so";
IMPLEMENT_SINGLE_INSTANCE(DynamicProfileManager);
namespace {
    const std::string APP_ID = "distributed_device_profile_service";
    const std::string STORE_ID = "dp_kv_store";
    const std::string TAG = "DynamicProfileManager";
    const std::string DP_MANAGER_HANDLER = "dp_manager_handler";
}

int32_t DynamicProfileManager::Init()
{
    HILOGI("call!");
    int32_t initResult = DP_MANAGER_INIT_FAIL;
    {
        std::lock_guard<std::mutex> lock(dynamicStoreMutex_);
        dynamicProfileStore_ = std::make_shared<KVAdapter>(APP_ID, STORE_ID, std::make_shared<KvDataChangeListener>(),
            std::make_shared<KvSyncCompletedListener>(), std::make_shared<KvDeathRecipient>(),
            DistributedKv::TYPE_DYNAMICAL);
        initResult = dynamicProfileStore_->Init();
    }
    LoadDpSyncAdapter();
    HILOGI("Init finish, res: %d", initResult);
    return initResult;
}

int32_t DynamicProfileManager::UnInit()
{
    HILOGI("call!");
    {
        std::lock_guard<std::mutex> lock(dynamicStoreMutex_);
        dynamicProfileStore_->UnInit();
        dynamicProfileStore_ = nullptr;
    }
    UnloadDpSyncAdapter();
    return DP_SUCCESS;
}

int32_t DynamicProfileManager::ReInit()
{
    HILOGI("call!");
    UnInit();
    return Init();
}

int32_t DynamicProfileManager::PutDeviceProfile(const DeviceProfile& deviceProfile)
{
    HILOGI("call!");
    int32_t res;
    {
        std::lock_guard<std::mutex> lock(dynamicStoreMutex_);
        res = ProfileControlUtils::PutDeviceProfile(dynamicProfileStore_, deviceProfile);
    }
    if (res != DP_SUCCESS) {
        HILOGE("PutDeviceProfile fail, reason: %{public}d!", res);
        return res;
    }
    HILOGI("PutDeviceProfile success");
    return DP_SUCCESS;
}

int32_t DynamicProfileManager::PutServiceProfile(const ServiceProfile& serviceProfile)
{
    HILOGI("call!");
    int32_t res;
    {
        std::lock_guard<std::mutex> lock(dynamicStoreMutex_);
        res = ProfileControlUtils::PutServiceProfile(dynamicProfileStore_, serviceProfile);
    }
    if (res != DP_SUCCESS) {
        HILOGE("PutServiceProfile fail, reason: %{public}d!", res);
        return res;
    }
    HILOGI("PutServiceProfile success");
    return DP_SUCCESS;
}

int32_t DynamicProfileManager::PutServiceProfileBatch(const std::vector<ServiceProfile>& serviceProfiles)
{
    HILOGI("call!");
    int32_t res;
    {
        std::lock_guard<std::mutex> lock(dynamicStoreMutex_);
        res = ProfileControlUtils::PutServiceProfileBatch(dynamicProfileStore_, serviceProfiles);
    }
    if (res != DP_SUCCESS) {
        HILOGE("PutServiceProfileBatch fail, reason: %{public}d!", res);
        return res;
    }
    HILOGI("PutServiceProfileBatch success");
    return DP_SUCCESS;
}

int32_t DynamicProfileManager::PutCharacteristicProfile(const CharacteristicProfile& charProfile)
{
    HILOGI("call!");
    int32_t res;
    {
        std::lock_guard<std::mutex> lock(dynamicStoreMutex_);
        res = ProfileControlUtils::PutCharacteristicProfile(dynamicProfileStore_, charProfile);
    }
    if (res != DP_SUCCESS) {
        HILOGE("PutCharacteristicProfile fail, reason: %{public}d!", res);
        return res;
    }
    HILOGI("PutCharacteristicProfile success");
    return DP_SUCCESS;
}

int32_t DynamicProfileManager::PutCharacteristicProfileBatch(const std::vector<CharacteristicProfile>& charProfiles)
{
    HILOGI("call!");
    int32_t res;
    {
        std::lock_guard<std::mutex> lock(dynamicStoreMutex_);
        res = ProfileControlUtils::PutCharacteristicProfileBatch(dynamicProfileStore_, charProfiles);
    }
    if (res != DP_SUCCESS) {
        HILOGE("PutCharacteristicProfileBatch fail, reason: %{public}d!", res);
        return res;
    }
    HILOGI("PutCharacteristicProfileBatch success");
    return DP_SUCCESS;
}

int32_t DynamicProfileManager::GetDeviceProfile(const std::string& deviceId, DeviceProfile& deviceProfile)
{
    HILOGI("call!");
    int32_t res;
    {
        std::lock_guard<std::mutex> lock(dynamicStoreMutex_);
        res = ProfileControlUtils::GetDeviceProfile(dynamicProfileStore_, deviceId, deviceProfile);
    }
    if (res != DP_SUCCESS) {
        HILOGE("GetDeviceProfile fail, reason: %{public}d!", res);
        return res;
    }
    HILOGI("GetDeviceProfile success");
    return DP_SUCCESS;
}

int32_t DynamicProfileManager::GetServiceProfile(const std::string& deviceId, const std::string& serviceName,
    ServiceProfile& serviceProfile)
{
    HILOGI("call!");
    int32_t res;
    {
        std::lock_guard<std::mutex> lock(dynamicStoreMutex_);
        res = ProfileControlUtils::GetServiceProfile(dynamicProfileStore_, deviceId, serviceName,
            serviceProfile);
    }
    if (res != DP_SUCCESS) {
        HILOGE("GetServiceProfile fail, reason: %{public}d!", res);
        return res;
    }
    HILOGI("GetServiceProfile success");
    return DP_SUCCESS;
}

int32_t DynamicProfileManager::GetCharacteristicProfile(const std::string& deviceId, const std::string& serviceName,
    const std::string& characteristicKey, CharacteristicProfile& charProfile)
{
    HILOGI("call!");
    int32_t res;
    {
        std::lock_guard<std::mutex> lock(dynamicStoreMutex_);
        res = ProfileControlUtils::GetCharacteristicProfile(dynamicProfileStore_, deviceId, serviceName,
            characteristicKey, charProfile);
    }
    if (res != DP_SUCCESS) {
        HILOGE("GetCharacteristicProfile fail, reason: %{public}d!", res);
        return res;
    }
    HILOGI("GetCharacteristicProfile success");
    return DP_SUCCESS;
}

int32_t DynamicProfileManager::DeleteServiceProfile(const std::string& deviceId, const std::string& serviceName)
{
    HILOGI("call!");
    int32_t res;
    {
        std::lock_guard<std::mutex> lock(dynamicStoreMutex_);
        res = ProfileControlUtils::DeleteServiceProfile(dynamicProfileStore_, deviceId, serviceName);
    }
    if (res != DP_SUCCESS) {
        HILOGE("DeleteServiceProfile fail, reason: %{public}d!", res);
        return res;
    }
    HILOGI("DeleteServiceProfile success");
    return DP_SUCCESS;
}

int32_t DynamicProfileManager::DeleteCharacteristicProfile(const std::string& deviceId, const std::string& serviceName,
    const std::string& characteristicKey)
{
    HILOGI("call!");
    int32_t res;
    {
        std::lock_guard<std::mutex> lock(dynamicStoreMutex_);
        res = ProfileControlUtils::DeleteCharacteristicProfile(dynamicProfileStore_, deviceId, serviceName,
            characteristicKey);
    }
    if (res != DP_SUCCESS) {
        HILOGE("DeleteCharacteristicProfile fail, reason: %{public}d!", res);
        return res;
    }
    HILOGI("DeleteCharacteristicProfile success");
    return DP_SUCCESS;
}

int32_t DynamicProfileManager::GetAllDeviceProfile(std::vector<DeviceProfile>& deviceProfiles)
{
    HILOGI("call!");
    int32_t res;
    {
        std::lock_guard<std::mutex> lock(dynamicStoreMutex_);
        res = ProfileControlUtils::GetAllDeviceProfile(dynamicProfileStore_, deviceProfiles);
    }
    if (res != DP_SUCCESS) {
        HILOGE("GetAllDeviceProfile fail, reason: %{public}d!", res);
        return res;
    }
    HILOGI("GetAllDeviceProfile success");
    return DP_SUCCESS;
}

int32_t DynamicProfileManager::GetAllServiceProfile(std::vector<ServiceProfile>& serviceProfiles)
{
    HILOGI("call!");
    int32_t res;
    {
        std::lock_guard<std::mutex> lock(dynamicStoreMutex_);
        res = ProfileControlUtils::GetAllServiceProfile(dynamicProfileStore_, serviceProfiles);
    }
    if (res != DP_SUCCESS) {
        HILOGE("serviceProfiles fail, reason: %{public}d!", res);
        return res;
    }
    HILOGI("serviceProfiles success");
    return DP_SUCCESS;
}

int32_t DynamicProfileManager::GetAllCharacteristicProfile(std::vector<CharacteristicProfile>& charProfiles)
{
    HILOGI("call!");
    int32_t res;
    {
        std::lock_guard<std::mutex> lock(dynamicStoreMutex_);
        res = ProfileControlUtils::GetAllCharacteristicProfile(dynamicProfileStore_, charProfiles);
    }
    if (res != DP_SUCCESS) {
        HILOGE("GetAllCharacteristicProfile fail, reason: %{public}d!", res);
        return res;
    }
    HILOGI("GetAllCharacteristicProfile success");
    return DP_SUCCESS;
}

int32_t DynamicProfileManager::SyncDeviceProfile(const DistributedDeviceProfile::DpSyncOptions &syncOptions,
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
        int32_t syncResult = dynamicProfileStore_->Sync(openHarmonyDevices, syncOptions.GetSyncMode());
        if (syncResult != DP_SUCCESS) {
            HILOGI("SyncDeviceProfile fail, res: %d!", syncResult);
            return DP_SYNC_DEVICE_FAIL;
        }
    }
    HILOGI("SyncDeviceProfile success, caller: %s!", callerDescriptor.c_str());
    return DP_SUCCESS;
}

bool DynamicProfileManager::LoadDpSyncAdapter()
{
    HILOGI("DynamicProfileManager::LoadDpSyncAdapter start.");
    std::lock_guard<std::mutex> lock(isAdapterLoadLock_);
    if (isAdapterSoLoaded_ && (dpSyncAdapter_ != nullptr)) {
        return true;
    }
    char path[PATH_MAX + 1] = {0x00};
    std::string soName = std::string(LIB_LOAD_PATH) + std::string(LIB_DP_ADAPTER_NAME);
    if ((soName.length() == 0) || (soName.length() > PATH_MAX) || (realpath(soName.c_str(), path) == nullptr)) {
        HILOGI("File %s canonicalization failed", soName.c_str());
        return false;
    }
    void *so_handle = dlopen(path, RTLD_NOW);
    if (so_handle == nullptr) {
        HILOGI("load dp sync adapter so %s failed", soName.c_str());
        return false;
    }
    dlerror();
    auto func = (CreateDPSyncAdapterFuncPtr)dlsym(so_handle, "CreateDPSyncAdaptertObject");
    if (dlerror() != nullptr || func == nullptr) {
        dlclose(so_handle);
        HILOGI("Create object function is not exist.");
        return false;
    }
    dpSyncAdapter_ = std::shared_ptr<IDPSyncAdapter>(func());
    if (dpSyncAdapter_->Initialize() != DP_SUCCESS) {
        dlclose(so_handle);
        dpSyncAdapter_ = nullptr;
        isAdapterSoLoaded_ = false;
        HILOGI("dp sync adapter init failed");
        return false;
    }
    isAdapterSoLoaded_ = true;
    HILOGI("DynamicProfileManager::LoadDpSyncAdapter sucess");
    return true;
}

void DynamicProfileManager::UnloadDpSyncAdapter()
{
    HILOGI("DynamicProfileManager::UnloadDpSyncAdapter start.");
    std::lock_guard<std::mutex> lock(isAdapterLoadLock_);
    if (dpSyncAdapter_ != nullptr) {
        dpSyncAdapter_->Release();
    }
    dpSyncAdapter_ = nullptr;
    char path[PATH_MAX + 1] = {0x00};
    std::string soPathName = std::string(LIB_LOAD_PATH) + std::string(LIB_DP_ADAPTER_NAME);
    if ((soPathName.length() == 0) || (soPathName.length() > PATH_MAX) ||
        (realpath(soPathName.c_str(), path) == nullptr)) {
        HILOGI("File %s canonicalization failed", soPathName.c_str());
        return;
    }
    void *so_handle = dlopen(path, RTLD_NOW | RTLD_NOLOAD);
    if (so_handle != nullptr) {
        HILOGI("dp sync adapter so_handle is not nullptr.");
        dlclose(so_handle);
        isAdapterSoLoaded_ = false;
    }
}

int32_t DynamicProfileManager::RunloadedFunction(std::string deviceId, sptr<IRemoteObject> syncCompletedCallback)
{
    if (!LoadDpSyncAdapter()) {
        HILOGE("dp service adapter load failed.");
        return DP_LOAD_SYNC_ADAPTER_FAILED;
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

int32_t DynamicProfileManager::DeviceOnlineAutoSync(const std::string& peerNetworkId)
{
    HILOGI("call! peerNetworkId=%{public}s", ProfileUtils::GetAnonyString(peerNetworkId).c_str());
    std::vector<std::string> deviceList{peerNetworkId};
    std::vector<std::string> onlineDevices = ProfileUtils::FilterOnlineDevices(deviceList);
    if (onlineDevices.empty()
        || std::find(onlineDevices.begin(), onlineDevices.end(), peerNetworkId) == onlineDevices.end()) {
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

std::vector<DistributedKv::Entry> DynamicProfileManager::GetEntriesByKeys(const std::vector<std::string>& keys)
{
    HILOGI("call!");
    std::vector<DistributedKv::Entry> entries;
    if (keys.empty()) {
        HILOGE("keys empty.");
        return entries;
    }
    {
        std::lock_guard<std::mutex> lock(dpStoreMutex_);
        if (dynamicProfileStore_ == nullptr) {
            HILOGE("dynamicProfileStore is nullptr!");
            return entries;
        }
        for (const auto& key : keys) {
            std::string value;
            if (dynamicProfileStore_->Get(key, value) != DP_SUCCESS) {
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
} // namespace DeviceProfile
} // namespace OHOS