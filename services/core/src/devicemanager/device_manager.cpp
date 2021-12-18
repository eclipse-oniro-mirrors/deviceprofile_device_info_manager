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

#include "device_manager.h"

#include <chrono>
#include <thread>

#include <unistd.h>

#include "parameter.h"

#include "device_profile_log.h"
#include "device_profile_storage_manager.h"
#include "device_profile_utils.h"

namespace OHOS {
namespace DeviceProfile {
using namespace std::chrono_literals;

namespace {
const std::string TAG = "DeviceManager";

constexpr uint8_t MAX_DEVICE_TYPE = 3;
constexpr int32_t DEVICE_ID_SIZE = 65;
constexpr int32_t MAX_TIMES_CONNECT_SOFTBUS = 10;
const std::string PKG_NAME = "DBinderBus_" + std::to_string(getpid());
}

IMPLEMENT_SINGLE_INSTANCE(DeviceManager);

bool DeviceManager::Init()
{
    nodeStateCb_.events = EVENT_NODE_STATE_MASK;
    nodeStateCb_.onNodeOnline = OnNodeOnlineAdapter;
    nodeStateCb_.onNodeOffline = OnNodeOfflineAdapter;
    nodeStateCb_.onNodeBasicInfoChanged = OnNodeBasicInfoChangedAdapter;

    auto runner = AppExecFwk::EventRunner::Create("devmgr");
    devMgrHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    if (devMgrHandler_ == nullptr) {
        return false;
    }
    if (!ConnectSoftbus()) {
        return false;
    }
    return true;
}

void DeviceManager::OnNodeOnlineAdapter(NodeBasicInfo* info)
{
    if (info == nullptr) {
        HILOGE("null info");
        return;
    }
    HILOGI("networkId = %{public}s", DeviceProfileUtils::AnonymizeDeviceId(info->networkId).c_str());
    auto deviceInfo = std::make_shared<DeviceInfo>(
        info->deviceName, info->networkId, info->deviceTypeId);
    DeviceManager::GetInstance().OnNodeOnline(deviceInfo);
}

void DeviceManager::OnNodeOfflineAdapter(NodeBasicInfo* info)
{
    if (info == nullptr) {
        HILOGE("null info");
        return;
    }

    std::string deviceId = info->networkId;
    DeviceManager::GetInstance().OnNodeOffline(deviceId);
}

void DeviceManager::OnNodeBasicInfoChangedAdapter(NodeBasicInfoType type,
    NodeBasicInfo* info)
{
    std::string deviceId = info->networkId;
    DeviceManager::GetInstance().OnNodeBasicInfoChanged(deviceId, type);
}

void DeviceManager::OnNodeOnline(const std::shared_ptr<DeviceInfo> deviceInfo)
{
    auto onlineNotifyTask = [this, deviceInfo = deviceInfo]() {
        HILOGI("online networkId = %{public}s",
            DeviceProfileUtils::AnonymizeDeviceId(deviceInfo->GetDeviceId()).c_str());
        AddDeviceIds(deviceInfo->GetDeviceId());
        std::string deviceId = deviceInfo->GetDeviceId();
        std::lock_guard<std::mutex> autoLock(deviceLock_);
        remoteDeviceInfoMap_[deviceId] = deviceInfo;
    };
    if (!devMgrHandler_->PostTask(onlineNotifyTask)) {
        HILOGE("post task failed");
        return;
    }
}

void DeviceManager::OnNodeOffline(const std::string& deviceId)
{
    auto offlineNotifyTask = [this, deviceId = std::move(deviceId)]() {
        HILOGI("offline networkId = %{public}s",
            DeviceProfileUtils::AnonymizeDeviceId(deviceId).c_str());
        RemoveDeviceIds(deviceId);
        std::lock_guard<std::mutex> autoLock(deviceLock_);
        remoteDeviceInfoMap_.erase(deviceId);
    };
    if (!devMgrHandler_->PostTask(offlineNotifyTask)) {
        HILOGE("post task failed");
        return;
    }
}

void DeviceManager::OnNodeBasicInfoChanged(const std::string& deviceId,
    NodeBasicInfoType type)
{
    HILOGD("called");
}

bool DeviceManager::ConnectSoftbus()
{
    auto registerTask = [this]() {
        HILOGD("register task...");
        int32_t retryTimes = 0;
        int32_t errCode = ERR_OK;
        while (retryTimes++ < MAX_TIMES_CONNECT_SOFTBUS) {
            errCode = RegNodeDeviceStateCb(PKG_NAME.c_str(), &nodeStateCb_);
            if (errCode == ERR_OK) {
                break;
            }
            HILOGE("register errCode = %{public}d, retrying...", errCode);

            errCode = UnregNodeDeviceStateCb(&nodeStateCb_);
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

void DeviceManager::RecoverDevicesIfNeeded()
{
    HILOGI("called");
    NodeBasicInfo* info = nullptr;
    int32_t numInfos = 0;
    if (GetAllNodeDeviceInfo(PKG_NAME.c_str(), &info, &numInfos) != ERR_OK) {
        FreeNodeInfo(info);
        HILOGE("get all node info failed");
        return;
    }
    for (int32_t i = 0; i < numInfos; i++) {
        NodeBasicInfo* nodeBasicInfo = info + i;
        std::string networkId = nodeBasicInfo->networkId;
        HILOGI("deviceId %{public}s found",
            DeviceProfileUtils::AnonymizeDeviceId(networkId).c_str());
        AddDeviceIds(networkId);
        {
            auto deviceInfo = std::make_shared<DeviceInfo>(
                nodeBasicInfo->deviceName, networkId, nodeBasicInfo->deviceTypeId);
            std::lock_guard<std::mutex> autoLock(deviceLock_);
            remoteDeviceInfoMap_.emplace(std::move(networkId), deviceInfo);
        }
    }
    FreeNodeInfo(info);
}

void DeviceManager::AddLocalDeviceIds()
{
    HILOGI("called");
    auto info = GetLocalBasicInfo();
    if (info != nullptr) {
        AddDeviceIds(info->networkId);
    } else {
        std::string udid;
        GetLocalDeviceUdid(udid);
        std::vector<std::string> deviceIds = {"", std::move(udid), ""};
        std::lock_guard<std::mutex> autoLock(deviceLock_);
        deviceIdsList_.emplace_back(std::move(deviceIds));
    }
}

void DeviceManager::AddDeviceIds(const std::string& networkId)
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

void DeviceManager::RemoveDeviceIds(const std::string& networkId)
{
    HILOGI("called");
    std::lock_guard<std::mutex> autoLock(deviceLock_);
    for (auto iter = deviceIdsList_.begin(); iter != deviceIdsList_.end(); iter++) {
        if ((*iter)[static_cast<uint8_t>(DeviceIdType::NETWORKID)] == networkId) {
            deviceIdsList_.erase(iter);
            return;
        }
    }
}

void DeviceManager::DisconnectSoftbus()
{
    int32_t errCode = UnregNodeDeviceStateCb(&nodeStateCb_);
    if (errCode != ERR_OK) {
        HILOGE("remove failed, errCode = %{public}d", errCode);
    }
}

void DeviceManager::GetLocalDeviceUdid(std::string& udid)
{
    char localDeviceId[DEVICE_ID_SIZE] = {0};
    GetDevUdid(localDeviceId, DEVICE_ID_SIZE);
    udid = localDeviceId;
}

std::unique_ptr<NodeBasicInfo> DeviceManager::GetLocalBasicInfo()
{
    auto info = std::make_unique<NodeBasicInfo>();
    int32_t errCode = GetLocalNodeDeviceInfo(PKG_NAME.c_str(), info.get());
    if (errCode != ERR_OK) {
        HILOGE("errCode = %{public}d", errCode);
        return nullptr;
    }
    return info;
}

bool DeviceManager::GetUdidByNetworkId(const std::string& networkId, std::string& udid)
{
    return GetUuidOrUdidByNetworkId(networkId, NodeDeivceInfoKey::NODE_KEY_UDID, udid);
}

bool DeviceManager::GetUuidByNetworkId(const std::string& networkId, std::string& uuid)
{
    return GetUuidOrUdidByNetworkId(networkId, NodeDeivceInfoKey::NODE_KEY_UUID, uuid);
}

bool DeviceManager::GetUuidOrUdidByNetworkId(const std::string& networkId,
    NodeDeivceInfoKey keyType, std::string& uuidOrUdid)
{
    if (networkId.empty()) {
        return false;
    }

    char id[DEVICE_ID_SIZE] = {0};
    int32_t errCode = GetNodeKeyInfo(PKG_NAME.c_str(), networkId.c_str(), keyType,
        reinterpret_cast<uint8_t*>(id), DEVICE_ID_SIZE);
    if (errCode != ERR_OK) {
        HILOGE("get udid failed, errCode = %{public}d", errCode);
        return false;
    }
    uuidOrUdid = id;
    return true;
}

bool DeviceManager::TransformDeviceId(const std::string& fromDeviceId,
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
} // namespace DeviceProfile
} // namespace OHOS
