/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_DP_DATA_CHANGE_LISTENER_H
#define OHOS_DP_DATA_CHANGE_LISTENER_H

#include <cstdint>
#include <map>
#include <mutex>
#include <vector>

#include "kvstore_observer.h"

#include "distributed_device_profile_enums.h"
#include "single_instance.h"
#include "trusted_device_info.h"
#include "service_info.h"
#include "user_info.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class KvDataChangeListener : public DistributedKv::KvStoreObserver {
public:
    KvDataChangeListener(const std::string& storeId);
    ~KvDataChangeListener();

    void OnChange(const DistributedKv::ChangeNotification& changeNotification) override;
    void OnChange(const DistributedKv::DataOrigin& origin, Keys&& keys) override;
    void OnSwitchChange(const DistributedKv::SwitchNotification &notification) override;
    static int32_t EntriesToUserInfo(const std::string& key, UserInfo& userInfo, ServiceInfo& serviceInfo);

private:
    void HandleAddChange(const std::vector<DistributedKv::Entry> &insertRecords);
    void HandleUpdateChange(const std::vector<DistributedKv::Entry> &updateRecords);
    void HandleDeleteChange(const std::vector<DistributedKv::Entry> &deleteRecords);
    std::vector<DistributedKv::Entry> ConvertCloudChangeDataToEntries(const std::vector<std::string> &keys);
    void FilterEntries(const std::vector<DistributedKv::Entry>& records,
        std::map<std::string, std::string>& entriesMap, bool isDelete);
    void ConvertRecordsToMap(const std::vector<DistributedKv::Entry>& records,
        std::map<std::string, std::string>& entriesMap);
    void ProcessChangeOp(const std::vector<std::string>& keyList, ChangeOp op);
    void ProcessInsertOrUpdate(const std::vector<std::string>& keyList, const std::string& localUdid,
        std::vector<ServiceInfo>& serviceInfos);
    void ProcessDelete(const std::vector<std::string>& keyList, const std::string& localUdid,
        std::vector<ServiceInfo>& serviceInfos);
private:
    std::string storeId_;
};

class SwitchUpdater {
    DECLARE_SINGLE_INSTANCE(SwitchUpdater);
public:
    void OnDeviceOnline(const TrustedDeviceInfo& deviceInfo);
    void HandleSwitchUpdateChange(const std::string& netWorkId, uint32_t switchValue);
    void AddSwitchCacheMap(const std::string& netWorkId, uint32_t switchValue);
    void EraseSwitchCacheMap(const std::string& netWorkId);

private:
    int32_t GenerateSwitchNotify(const std::string& udid, const std::string& serviceName,
        const std::string& characteristicProfileKey, const std::string& characteristicProfileValue,
        ChangeType changeType);

    std::mutex switchCacheMapMutex_;
    std::map<std::string, uint32_t> switchCacheMap_;
};
} // namespace DeviceProfile
} // namespace OHOS
#endif // OHOS_DP_DATA_CHANGE_LISTENER_H
