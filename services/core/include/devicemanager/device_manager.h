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
#include "softbus_bus_center.h"

namespace OHOS {
namespace DeviceProfile {
enum DeviceIdType : uint8_t {
    NETWORKID = 0,
    UDID = 1,
    UUID = 2
};

class DeviceManager {
    DECLARE_SINGLE_INSTANCE(DeviceManager);
public:
    bool Init();
    std::unique_ptr<NodeBasicInfo> GetLocalBasicInfo();
    void GetLocalDeviceUdid(std::string& udid);
    bool GetUdidByNetworkId(const std::string& networkId, std::string& udid);
    bool GetUuidByNetworkId(const std::string& networkId, std::string& uuid);
    void DisconnectSoftbus();
    bool ConnectSoftbus();
    bool TransformDeviceId(const std::string& fromDeviceId, std::string& toDeviceId,
        DeviceIdType toType);
    void GetDeviceIdList(std::list<std::string>& deviceIdList);
    void GetDeviceList(std::list<std::shared_ptr<DeviceInfo>>& deviceList);

private:
    static void OnNodeOnlineAdapter(NodeBasicInfo* info);
    static void OnNodeOfflineAdapter(NodeBasicInfo* info);
    static void OnNodeBasicInfoChangedAdapter(NodeBasicInfoType type, NodeBasicInfo* info);

    bool GetUuidOrUdidByNetworkId(const std::string& nodeId, NodeDeivceInfoKey keyType,
        std::string& uuidOrUdid);
    void OnNodeOnline(const std::shared_ptr<DeviceInfo> deviceInfo);
    void OnNodeOffline(const std::string& deviceId);
    void OnNodeBasicInfoChanged(const std::string& deviceId, NodeBasicInfoType type);
    void AddLocalDeviceIds();
    void AddDeviceIds(const std::string& networkId);
    void RemoveDeviceIds(const std::string& networkId);
    void RecoverDevicesIfNeeded();

private:
    INodeStateCb nodeStateCb_;
    std::mutex deviceLock_;
    std::shared_ptr<AppExecFwk::EventHandler> devMgrHandler_;
    std::map<std::string, std::shared_ptr<DeviceInfo>> remoteDeviceInfoMap_;
    std::list<std::vector<std::string>> deviceIdsList_;
};
} // namespace DeviceProfile
} // namespace OHOS
#endif // OHOS_DEVICE_PROFILE_DEVICE_MANAGER_H
