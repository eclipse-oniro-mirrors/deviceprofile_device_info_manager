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

#include "device_profile_storage_manager.h"

#include <chrono>
#include <thread>

#include "device_manager.h"
#include "device_profile_errors.h"
#include "device_profile_log.h"

#include "ipc_object_proxy.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace DeviceProfile {
using namespace std::chrono_literals;
using namespace OHOS::DistributedKv;

namespace {
const std::string TAG = "DeviceProfileStorageManager";

const std::string SERVICE_TYPE = "type";
const std::string SERVICES = "services";
constexpr int32_t RETRY_TIMES_WAIT_KV_DATA = 30;
}

IMPLEMENT_SINGLE_INSTANCE(DeviceProfileStorageManager);

bool DeviceProfileStorageManager::Init()
{
    if (!inited_) {
        DeviceManager::GetInstance().GetLocalDeviceUdid(localUdid_);
        if (localUdid_.empty()) {
            HILOGE("get local udid failed");
            return false;
        }
        onlineSyncTbl_ = std::make_unique<OnlineSyncTable>();
        if (onlineSyncTbl_ == nullptr) {
            return false;
        }

        kvStoreDeathRecipient_ = sptr<IRemoteObject::DeathRecipient>(new KvStoreDeathRecipient());
        auto runner = AppExecFwk::EventRunner::Create("dpstorage");
        storageHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
        if (storageHandler_ == nullptr) {
            return false;
        }
        inited_ = true;
    }

    auto waitTask = [this]() {
        if (!WaitKvDataService()) {
            std::lock_guard<std::mutex> autoLock(serviceLock_);
            profileItems_.clear();
            kvDataServiceFailed_ = true;
            return;
        }
        auto callback = std::bind(&DeviceProfileStorageManager::OnKvStoreInitDone, this);
        onlineSyncTbl_->RegisterKvStoreInitCallback(callback);
        onlineSyncTbl_->Init();
    };
    if (!storageHandler_->PostTask(waitTask)) {
        HILOGE("post task failed");
        return false;
    }
    HILOGI("init succeeded");
    return true;
}

bool DeviceProfileStorageManager::WaitKvDataService()
{
    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrProxy == nullptr) {
        HILOGE("get samgrProxy failed");
        return false;
    }
    int32_t retryTimes = RETRY_TIMES_WAIT_KV_DATA;
    do {
        auto kvDataSvr = samgrProxy->CheckSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID);
        if (kvDataSvr != nullptr) {
            IPCObjectProxy* proxy = reinterpret_cast<IPCObjectProxy*>(kvDataSvr.GetRefPtr());
            if (proxy != nullptr && !proxy->IsObjectDead()) {
                HILOGI("get service succeed");
                proxy->AddDeathRecipient(kvStoreDeathRecipient_);
                return true;
            }
        }
        HILOGD("waiting for service...");
        std::this_thread::sleep_for(1s);
        if (--retryTimes <= 0) {
            HILOGE("waiting service timeout(30)s");
            return false;
        }
    } while (true);
    return false;
}

std::string DeviceProfileStorageManager::GenerateKey(const std::string& udid,
    const std::string& key, KeyType keyType)
{
    std::string tmp;
    tmp.append(udid).append("/").append(std::to_string(keyType)).append("/").append(key);
    return tmp;
}

int32_t DeviceProfileStorageManager::PutDeviceProfile(const ServiceCharacteristicProfile& profile)
{
    if (kvDataServiceFailed_ || onlineSyncTbl_->GetInitStatus() == StorageInitStatus::INIT_FAILED) {
        HILOGE("kvstore init failed");
        return ERR_DP_INIT_DB_FAILED;
    }

    std::vector<std::string> keys;
    std::vector<std::string> values;
    std::string serviceId = profile.GetServiceId();
    keys.emplace_back(GenerateKey(localUdid_, serviceId, KeyType::SERVICE));
    values.emplace_back(profile.GetCharacteristicProfileJson());
    std::unique_lock<std::mutex> autoLock(serviceLock_);
    if (servicesJson_[serviceId] == nullptr) {
        nlohmann::json j;
        j[SERVICE_TYPE] = profile.GetServiceType();
        servicesJson_[serviceId] = j;
        keys.emplace_back(GenerateKey(localUdid_, SERVICES, KeyType::SERVICE_LIST));
        values.emplace_back(servicesJson_.dump());
    }

    int32_t errCode = ERR_OK;
    if (onlineSyncTbl_->GetInitStatus() == StorageInitStatus::INIT_SUCCEED) {
        autoLock.unlock();
        if (keys.size() > 1) {
            errCode = onlineSyncTbl_->PutDeviceProfileBatch(keys, values);
        } else {
            errCode = onlineSyncTbl_->PutDeviceProfile(keys[0], values[0]);
        }
    } else {
        for (size_t i = 0; i < keys.size(); i++) {
            profileItems_[keys[i]] = values[i];
        }
    }
    return errCode;
}

void DeviceProfileStorageManager::RestoreServiceItemLocked(const std::string& value)
{
    auto restoreItems = nlohmann::json::parse(value, nullptr, false);
    if (restoreItems.is_discarded()) {
        HILOGE("parse error");
        return;
    }
    for (const auto& [key, value] : servicesJson_.items()) {
        restoreItems[key] = value;
    }
    servicesJson_ = std::move(restoreItems);
}

void DeviceProfileStorageManager::FlushProfileItems()
{
    std::string services;
    std::string servicesKey = GenerateKey(localUdid_, SERVICES, KeyType::SERVICE_LIST);
    int32_t errCode = onlineSyncTbl_->GetDeviceProfile(servicesKey, services);
    std::unique_lock<std::mutex> autoLock(serviceLock_);
    if (errCode == ERR_OK) {
        RestoreServiceItemLocked(services);
    }

    std::vector<std::string> keys;
    std::vector<std::string> values;
    size_t itemSize = profileItems_.size();
    HILOGI("profile item size = %{public}zu", itemSize);
    if (itemSize == 0) {
        return;
    }
    keys.reserve(itemSize);
    values.reserve(itemSize);
    // update service list to avoid overwriting the value in db storage
    profileItems_[servicesKey] = servicesJson_.dump();
    for (const auto& [key, value] : profileItems_) {
        keys.emplace_back(key);
        values.emplace_back(value);
        HILOGD("key = %{public}s, value = %{public}s", key.c_str(), value.c_str());
    }
    profileItems_.clear();
    autoLock.unlock();

    errCode = onlineSyncTbl_->PutDeviceProfileBatch(keys, values);
    if (errCode != ERR_OK) {
        HILOGE("put failed, errCode = %{public}d", errCode);
    }
}

void DeviceProfileStorageManager::OnKvStoreInitDone()
{
    FlushProfileItems();
}

} // namespace DeviceProfile
} // namespace OHOS
