/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#include "device_profile_manager.h"
#include "device_profile_utils.h"
#include "distributed_device_profile_service.h"
#include "dm_constants.h"
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
const int32_t DEFAULT_OS_TYPE = 10;
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

void DpDeviceManager::GetTrustedDeviceList()
{
    std::vector<DmDeviceInfo> deviceList;
    int32_t ret = DeviceManager::GetInstance().GetTrustedDeviceList(PKG_NAME, "", deviceList);
    if (ret != ERR_OK) {
        HILOGE("GetTrustedDeviceList Failed!");
        return;
    }
    if (deviceList.empty()) {
        HILOGI("deviceList is empty!");
        return;
    }
    for (const DmDeviceInfo& dmDeviceInfo : deviceList) {
        auto dpDeviceInfo = std::make_shared<DeviceInfo>(
            dmDeviceInfo.deviceName, dmDeviceInfo.networkId, dmDeviceInfo.deviceTypeId);
        DpDeviceManager::GetInstance().OnNodeOnline(dpDeviceInfo);
    }
    DistributedDeviceProfileService::GetInstance().DeviceOnline();
}

void DpDeviceManager::DpDeviceStateCallback::OnDeviceOnline(const DmDeviceInfo &deviceInfo)
{
    HILOGI("online called");
    auto dpDeviceInfo = std::make_shared<DeviceInfo>(
        deviceInfo.deviceName, deviceInfo.networkId, deviceInfo.deviceTypeId);
    DpDeviceManager::GetInstance().OnNodeOnline(dpDeviceInfo);
    DistributedDeviceProfileService::GetInstance().DeviceOnline();
    DpDeviceManager::GetInstance().AutoSync(deviceInfo);
}

void DpDeviceManager::DpDeviceStateCallback::OnDeviceOffline(const DmDeviceInfo &deviceInfo)
{
    HILOGI("offline called");
    std::string networkId = deviceInfo.networkId;
    DpDeviceManager::GetInstance().OnNodeOffline(networkId);
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
            DeviceProfileUtils::AnonymizeDeviceId(deviceInfo->GetNetworkId()).c_str());
        RemoveExpiredDeviceIds(deviceInfo->GetNetworkId());
        AddDeviceIds(deviceInfo->GetNetworkId());
        {
            std::string networkId = deviceInfo->GetNetworkId();
            std::lock_guard<std::mutex> autoLock(deviceLock_);
            remoteDeviceInfoMap_[networkId] = deviceInfo;
        }
    };
    if (!devMgrHandler_->PostTask(onlineNotifyTask)) {
        HILOGE("post task failed");
        return;
    }
}

void DpDeviceManager::OnNodeOffline(const std::string& networkId)
{
    auto offlineNotifyTask = [this, networkId = std::move(networkId)]() {
        HILOGI("offline networkId = %{public}s", DeviceProfileUtils::AnonymizeDeviceId(networkId).c_str());
        std::lock_guard<std::mutex> autoLock(deviceLock_);
        remoteDeviceInfoMap_.erase(networkId);
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
                DpDeviceManager::GetInstance().GetTrustedDeviceList();
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
        HILOGI("deviceId %{public}s found", DeviceProfileUtils::AnonymizeDeviceId(networkId).c_str());
        AddDeviceIds(networkId);
        {
            auto deviceInfo = std::make_shared<DeviceInfo>(
                dmDeviceInfo.deviceName, dmDeviceInfo.networkId, dmDeviceInfo.deviceTypeId);
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
        deviceIdList.emplace_back(deviceInfo->GetNetworkId());
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

void DpDeviceManager::AutoSync(const DistributedHardware::DmDeviceInfo &deviceInfo)
{
    HILOGI("call! networdId=%{public}s", DeviceProfileUtils::AnonymizeDeviceId(deviceInfo.networkId).c_str());
    if (deviceInfo.extraData.empty()) {
        HILOGE("extraData is empty!");
        return;
    }
    auto autoSyncTask = [deviceInfo]() {
        auto extraData = nlohmann::json::parse(deviceInfo.extraData, nullptr, false);
        if (extraData.is_discarded()) {
            HILOGE("extraData parse failed");
            return;
        }
        int32_t osType = DEFAULT_OS_TYPE;
        if (extraData.contains(DistributedHardware::PARAM_KEY_OS_TYPE)
            && extraData[DistributedHardware::PARAM_KEY_OS_TYPE].is_number_integer()) {
            osType = extraData[DistributedHardware::PARAM_KEY_OS_TYPE].get<int32_t>();
        }
        HILOGI("osType=%{public}d", osType);
        if (osType != DEFAULT_OS_TYPE) {
            int32_t errCode = DistributedDeviceProfile::DeviceProfileManager::GetInstance()
                .DeviceOnlineAutoSync(deviceInfo.networkId);
            HILOGI("DeviceOnlineAutoSync errCode=%{public}d, networdId=%{public}s", errCode,
                DeviceProfileUtils::AnonymizeDeviceId(deviceInfo.networkId).c_str());
        }
    };
    std::thread(autoSyncTask).detach();
}
} // namespace DeviceProfile
} // namespace OHOS
