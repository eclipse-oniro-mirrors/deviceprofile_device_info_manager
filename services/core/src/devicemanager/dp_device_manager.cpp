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

#include "dp_device_manager.h"

#include <chrono>
#include <thread>

#include <unistd.h>

#include "parameter.h"

#include "device_profile_log.h"
#include "device_profile_utils.h"
#include "ipc_object_proxy.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace DeviceProfile {
using namespace std::chrono_literals;
using namespace DistributedHardware;

namespace {
const std::string TAG = "DpDeviceManager";

constexpr int32_t RETRY_TIMES = 30;
constexpr uint8_t MAX_DEVICE_TYPE = 3;
constexpr int32_t DEVICE_ID_SIZE = 65;
constexpr int32_t MAX_TIMES_CONNECT_DEVICEMANAGER = 10;
const std::string PKG_NAME = "DBinderBus_" + std::to_string(getpid());
}

IMPLEMENT_SINGLE_INSTANCE(DpDeviceManager);

bool DpDeviceManager::Init()
{
    initCallback_ = std::make_shared<DeviceInitCallBack>();
    stateCallback_ = std::make_shared<DpDeviceStateCallback>();
    auto runner = AppExecFwk::EventRunner::Create("devmgr");
    devMgrHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    if (devMgrHandler_ == nullptr) {
        return false;
    }
    if (!ConnectDeviceManager()) {
        return false;
    }
    return true;
}

void DpDeviceManager::DeviceInitCallBack::OnRemoteDied()
{
    HILOGI("DeviceInitCallBack OnRemoteDied");
    DpDeviceManager::GetInstance().Init();
}

void DpDeviceManager::DpDeviceStateCallback::OnDeviceOnline(const DmDeviceInfo &deviceInfo)
{
    HILOGI("online called");
    auto dpDeviceInfo = std::make_shared<DeviceInfo>(
        deviceInfo.deviceName, deviceInfo.deviceId, deviceInfo.deviceTypeId);
    DpDeviceManager::GetInstance().OnNodeOnline(dpDeviceInfo);
}

void DpDeviceManager::DpDeviceStateCallback::OnDeviceOffline(const DmDeviceInfo &deviceInfo)
{
    HILOGI("offline called");
    std::string deviceId = deviceInfo.deviceId;
    DpDeviceManager::GetInstance().OnNodeOffline(deviceId);
}

void DpDeviceManager::DpDeviceStateCallback::OnDeviceChanged(const DmDeviceInfo &deviceInfo)
{
    HILOGD("called");
}

void DpDeviceManager::DpDeviceStateCallback::OnDeviceReady(const DmDeviceInfo &deviceInfo)
{
    HILOGD("called");
}

void DpDeviceManager::OnNodeOnline(const std::shared_ptr<DeviceInfo> deviceInfo)
{
    auto onlineNotifyTask = [this, deviceInfo = deviceInfo]() {
        HILOGI("online networkId = %{public}s",
            DeviceProfileUtils::AnonymizeDeviceId(deviceInfo->GetDeviceId()).c_str());
        RemoveExpiredDeviceIds(deviceInfo->GetDeviceId());
        AddDeviceIds(deviceInfo->GetDeviceId());
        {
            std::string deviceId = deviceInfo->GetDeviceId();
            std::lock_guard<std::mutex> autoLock(deviceLock_);
            remoteDeviceInfoMap_[deviceId] = deviceInfo;
        }
    };
    if (!devMgrHandler_->PostTask(onlineNotifyTask)) {
        HILOGE("post task failed");
        return;
    }
}

void DpDeviceManager::OnNodeOffline(const std::string& deviceId)
{
    auto offlineNotifyTask = [this, deviceId = std::move(deviceId)]() {
        HILOGI("offline networkId = %{public}s",
            DeviceProfileUtils::AnonymizeDeviceId(deviceId).c_str());
        std::lock_guard<std::mutex> autoLock(deviceLock_);
        remoteDeviceInfoMap_.erase(deviceId);
    };
    if (!devMgrHandler_->PostTask(offlineNotifyTask)) {
        HILOGE("post task failed");
        return;
    }
}

bool DpDeviceManager::WaitForDnetworkReady()
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        HILOGE("WaitForDnetworkReady failed to get samgr!");
        return false;
    }
    int32_t retryTimeout = RETRY_TIMES;
    do {
        auto dnetworkDm = samgr->CheckSystemAbility(DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID);
        auto dnetworkSoftBus = samgr->CheckSystemAbility(SOFTBUS_SERVER_SA_ID);
        if (dnetworkDm != nullptr && dnetworkSoftBus != nullptr) {
            IPCObjectProxy* dmProxy = reinterpret_cast<IPCObjectProxy*>(dnetworkDm.GetRefPtr());
            IPCObjectProxy* sbProxy = reinterpret_cast<IPCObjectProxy*>(dnetworkSoftBus.GetRefPtr());
            // make sure the proxy is not dead
            if (dmProxy != nullptr && !dmProxy->IsObjectDead() && sbProxy != nullptr && !sbProxy->IsObjectDead()) {
                return true;
            }
        }
        HILOGI("Waiting for dnentwork service...");
        std::this_thread::sleep_for(1s);
        if (--retryTimeout <= 0) {
            HILOGI("Waiting for dnentwork service timeout(30)s");
            return false;
        }
    } while (true);
    return false;
}

bool DpDeviceManager::ConnectDeviceManager()
{
    HILOGI("ConnectDeviceManager");
    bool isReady = WaitForDnetworkReady();
    if (!isReady) {
        HILOGE("ConnectDeviceManager wait Dnetwork failed!");
        return false;
    }

    auto registerTask = [this]() {
        HILOGD("register task...");
        int32_t retryTimes = 0;
        int32_t errCode = ERR_OK;
        while (retryTimes++ < MAX_TIMES_CONNECT_DEVICEMANAGER) {
            int32_t ret = DeviceManager::GetInstance().InitDeviceManager(PKG_NAME, initCallback_);
            if (ret != 0) {
                HILOGE("init device manager failed, ret:%{public}d", ret);
                std::this_thread::sleep_for(1s);
                continue;
            }
            errCode = DeviceManager::GetInstance().RegisterDevStateCallback(
                PKG_NAME, "", stateCallback_);
            if (errCode == ERR_OK) {
                break;
            }
            HILOGE("register errCode = %{public}d, retrying...", errCode);

            errCode = DeviceManager::GetInstance().UnRegisterDevStateCallback(PKG_NAME);
            HILOGI("unregister errCode = %{public}d", errCode);
            std::this_thread::sleep_for(1s);
        }

        if (errCode == ERR_OK) {
            AddLocalDeviceIds();
            RecoverDevicesIfNeeded();
        }
        HILOGI("register %{public}s", (errCode == ERR_OK) ? "success" : "timeout");
    };
    if (!devMgrHandler_->PostTask(registerTask)) {
        HILOGE("post task failed");
        return false;
    }
    return true;
}

void DpDeviceManager::RecoverDevicesIfNeeded()
{
    HILOGI("called");
    std::vector<DmDeviceInfo> deviceList;
    if (DeviceManager::GetInstance().GetTrustedDeviceList(PKG_NAME, "", deviceList) != ERR_OK) {
        HILOGE("get all node info failed");
        return;
    }
    for (DmDeviceInfo dmDeviceInfo : deviceList) {
        std::string networkId = dmDeviceInfo.networkId;
        HILOGI("deviceId %{public}s found",
            DeviceProfileUtils::AnonymizeDeviceId(networkId).c_str());
        AddDeviceIds(networkId);
        {
            auto deviceInfo = std::make_shared<DeviceInfo>(
                dmDeviceInfo.deviceName, networkId, dmDeviceInfo.deviceTypeId);
            std::lock_guard<std::mutex> autoLock(deviceLock_);
            remoteDeviceInfoMap_.emplace(std::move(networkId), deviceInfo);
        }
    }
}

void DpDeviceManager::AddLocalDeviceIds()
{
    HILOGI("called");
    DmDeviceInfo dmInfo;
    int32_t errCode = DeviceManager::GetInstance().GetLocalDeviceInfo(PKG_NAME, dmInfo);
    if (errCode != ERR_OK) {
        HILOGW("errCode = %{public}d", errCode);
        std::string udid;
        GetLocalDeviceUdid(udid);
        std::vector<std::string> deviceIds = {"", std::move(udid), ""};
        std::lock_guard<std::mutex> autoLock(deviceLock_);
        deviceIdsList_.emplace_back(std::move(deviceIds));
    } else {
        AddDeviceIds(dmInfo.networkId);
    }
}

void DpDeviceManager::AddDeviceIds(const std::string& networkId)
{
    HILOGI("called");
    std::string udid;
    if (GetUdidByNetworkId(networkId, udid)) {
        HILOGI("udid %{public}s", DeviceProfileUtils::AnonymizeDeviceId(udid).c_str());
    }
    std::string uuid;
    if (GetUuidByNetworkId(networkId, uuid)) {
        HILOGI("uuid %{public}s", DeviceProfileUtils::AnonymizeDeviceId(uuid).c_str());
    }
    std::vector<std::string> deviceIds = {networkId, std::move(udid), std::move(uuid)};
    std::lock_guard<std::mutex> autoLock(deviceLock_);
    deviceIdsList_.emplace_back(std::move(deviceIds));
}

void DpDeviceManager::RemoveExpiredDeviceIds(const std::string& networkId)
{
    HILOGI("called");
    std::string udid;
    if (!GetUdidByNetworkId(networkId, udid)) {
        return;
    }
    if (udid.empty()) {
        return;
    }
    RemoveDeviceIdsByUdid(udid);
}

void DpDeviceManager::RemoveDeviceIds(const std::string& networkId)
{
    HILOGI("called");
    std::lock_guard<std::mutex> autoLock(deviceLock_);
    auto iter = std::find_if(deviceIdsList_.begin(), deviceIdsList_.end(), [&networkId](const auto& deviceIds) {
        return deviceIds[static_cast<uint8_t>(DeviceIdType::NETWORKID)] == networkId;
    });
    if (iter != deviceIdsList_.end()) {
        deviceIdsList_.erase(iter);
    }
    return;
}

void DpDeviceManager::RemoveDeviceIdsByUdid(const std::string& udid)
{
    HILOGI("called");
    std::lock_guard<std::mutex> autoLock(deviceLock_);
    auto iter = std::find_if(deviceIdsList_.begin(), deviceIdsList_.end(), [&udid](const auto& deviceIds) {
        return deviceIds[static_cast<uint8_t>(DeviceIdType::UDID)] == udid;
    });
    if (iter != deviceIdsList_.end()) {
        deviceIdsList_.erase(iter);
        HILOGI("remove device udid %{public}s", DeviceProfileUtils::AnonymizeDeviceId(udid).c_str());
    }
    return;
}

bool DpDeviceManager::DisconnectDeviceManager()
{
    int32_t errCode = DeviceManager::GetInstance().UnRegisterDevStateCallback(PKG_NAME);
    if (errCode != ERR_OK) {
        HILOGE("remove failed, errCode = %{public}d", errCode);
        return false;
    }
    return true;
}

void DpDeviceManager::GetLocalDeviceUdid(std::string& udid)
{
    char localDeviceId[DEVICE_ID_SIZE] = {0};
    GetDevUdid(localDeviceId, DEVICE_ID_SIZE);
    udid = localDeviceId;
}

bool DpDeviceManager::GetUdidByNetworkId(const std::string& networkId, std::string& udid)
{
    return ((DeviceManager::GetInstance().GetUdidByNetworkId(
        PKG_NAME, networkId, udid) == 0) ? true : false);
}

bool DpDeviceManager::GetUuidByNetworkId(const std::string& networkId, std::string& uuid)
{
    return ((DeviceManager::GetInstance().GetUuidByNetworkId(
        PKG_NAME, networkId, uuid) == 0) ? true : false);
}

bool DpDeviceManager::TransformDeviceId(const std::string& fromDeviceId,
    std::string& toDeviceId, DeviceIdType toType)
{
    if (fromDeviceId.empty()) {
        HILOGW("empty device id");
        return false;
    }

    uint8_t idx = static_cast<uint8_t>(toType);
    if (idx > MAX_DEVICE_TYPE - 1) {
        return false;
    }

    toDeviceId = "";
    std::lock_guard<std::mutex> autoLock(deviceLock_);
    for (const auto& deviceIds : deviceIdsList_) {
        auto iter = std::find(deviceIds.begin(), deviceIds.end(), fromDeviceId);
        if (iter != deviceIds.end()) {
            toDeviceId = deviceIds[idx];
            return !toDeviceId.empty();
        }
    }
    return false;
}

void DpDeviceManager::GetDeviceIdList(std::list<std::string>& deviceIdList)
{
    deviceIdList.clear();
    std::lock_guard<std::mutex> autoLock(deviceLock_);
    for (const auto& [_, deviceInfo] : remoteDeviceInfoMap_) {
        deviceIdList.emplace_back(deviceInfo->GetDeviceId());
    }
}

void DpDeviceManager::GetDeviceList(std::list<std::shared_ptr<DeviceInfo>>& deviceList)
{
    deviceList.clear();
    std::lock_guard<std::mutex> autoLock(deviceLock_);
    for (const auto& [_, deviceInfo] : remoteDeviceInfoMap_) {
        deviceList.emplace_back(deviceInfo);
    }
}
} // namespace DeviceProfile
} // namespace OHOS
