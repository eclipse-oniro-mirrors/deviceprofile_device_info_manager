/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef OHOS_DP_SETTINGS_DATA_CONNECTOR_H
#define OHOS_DP_SETTINGS_DATA_CONNECTOR_H
 
#include <string>
#include <cstdint>
#include <memory>
#include <mutex>

#include "datashare_helper.h"

#include "single_instance.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class SettingsDataManager {
    DECLARE_SINGLE_INSTANCE(SettingsDataManager);
public:
    int32_t Init();
    int32_t UnInit();
 
    int32_t GetUserDefinedDeviceName(int32_t userId, std::string &deviceName);
    int32_t SetUserDefinedDeviceName(const std::string &deviceName, int32_t userId);
    int32_t GetDisplayDeviceName(int32_t userId, std::string &deviceName);
    int32_t SetDisplayDeviceName(const std::string &deviceName, int32_t userId);
    int32_t GetDeviceName(std::string &deviceName);
private:
    int32_t GetValue(const std::string &tableName, int32_t userId, const std::string &key, std::string &value);
    int32_t SetValue(const std::string &tableName, int32_t userId, const std::string &key, const std::string &value);
 
    std::string GetProxyUriStr(const std::string &tableName, int32_t userId);
    std::shared_ptr<DataShare::DataShareHelper> CreateDataShareHelper(const std::string &proxyUri);
    Uri MakeUri(const std::string &proxyUri, const std::string &key);
    bool ReleaseDataShareHelper(std::shared_ptr<DataShare::DataShareHelper> helper);
 
    sptr<IRemoteObject> GetRemoteObj();
 
private:
    std::mutex remoteObjMtx_;
    sptr<IRemoteObject> remoteObj_;
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // OHOS_DP_SETTINGS_DATA_CONNECTOR_H
