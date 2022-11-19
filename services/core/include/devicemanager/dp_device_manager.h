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

#ifndef OHOS_DEVICE_PROFILE_DEVICE_MANAGER_H
#define OHOS_DEVICE_PROFILE_DEVICE_MANAGER_H

#include <mutex>
#include <list>
#include <string>

#include "event_handler.h"
#include "single_instance.h"
#include "device_info.h"
#include "device_manager.h"

namespace OHOS {
namespace DeviceProfile {
enum class DeviceIdType : uint8_t {
    NETWORKID = 0,
    UDID = 1,
    UUID = 2
};

class DpDeviceManager {
    DECLARE_SINGLE_INSTANCE(DpDeviceManager);

public:
    bool Init();
    void GetLocalDeviceUdid(std::string& udid);
    bool GetUdidByNetworkId(const std::string& networkId, std::string& udid);
    bool GetUuidByNetworkId(const std::string& networkId, std::string& uuid);
    bool DisconnectDeviceManager();
    bool ConnectDeviceManager();
    bool TransformDeviceId(const std::string& fromDeviceId, std::string& toDeviceId,
        DeviceIdType toType);
    void GetDeviceIdList(std::list<std::string>& deviceIdList);
    void GetDeviceList(std::list<std::shared_ptr<DeviceInfo>>& deviceList);
    void RemoveDeviceIdsByUdid(const std::string& udid);

private:
    bool WaitForDnetworkReady();
    void OnNodeOnline(const std::shared_ptr<DeviceInfo> deviceInfo);
    void OnNodeOffline(const std::string& deviceId);
    void AddLocalDeviceIds();
    void AddDeviceIds(const std::string& networkId);
    void RemoveDeviceIds(const std::string& networkId);
    void RemoveExpiredDeviceIds(const std::string& networkId);
    void RecoverDevicesIfNeeded();

private:
    std::mutex deviceLock_;
    std::shared_ptr<AppExecFwk::EventHandler> devMgrHandler_;
    std::shared_ptr<DistributedHardware::DeviceStateCallback> stateCallback_;
    std::shared_ptr<DistributedHardware::DmInitCallback> initCallback_;
    std::map<std::string, std::shared_ptr<DeviceInfo>> remoteDeviceInfoMap_;
    std::list<std::vector<std::string>> deviceIdsList_;

class DeviceInitCallBack : public DistributedHardware::DmInitCallback {
    void OnRemoteDied() override;
};

class DpDeviceStateCallback : public DistributedHardware::DeviceStateCallback {
    void OnDeviceOnline(const DistributedHardware::DmDeviceInfo &deviceInfo) override;
    void OnDeviceOffline(const DistributedHardware::DmDeviceInfo &deviceInfo) override;
    void OnDeviceChanged(const DistributedHardware::DmDeviceInfo &deviceInfo) override;
    void OnDeviceReady(const DistributedHardware::DmDeviceInfo &deviceInfo) override;
};
};
} // namespace DeviceProfile
} // namespace OHOS
#endif // OHOS_DEVICE_PROFILE_DEVICE_MANAGER_H
