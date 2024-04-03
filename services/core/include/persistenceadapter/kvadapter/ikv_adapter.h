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

#ifndef OHOS_DP_IKV_ADAPTER_H
#define OHOS_DP_IKV_ADAPTER_H

#include <string>
#include <map>
#include <vector>
#include "distributed_device_profile_enums.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class IKVAdapter {
public:
    IKVAdapter() = default;
    virtual ~IKVAdapter() = default;
    virtual int32_t Init() = 0;
    virtual int32_t UnInit() = 0;
    virtual int32_t Put(const std::string& key, const std::string& value) = 0;
    virtual int32_t PutBatch(const std::map<std::string, std::string>& values) = 0;
    virtual int32_t Delete(const std::string& key) = 0;
    virtual int32_t DeleteByPrefix(const std::string& keyPrefix) = 0;
    virtual int32_t Get(const std::string& key, std::string& value) = 0;
    virtual int32_t Get(const std::string& key, std::string& value, const std::string& udid) = 0;
    virtual int32_t GetByPrefix(const std::string& keyPrefix, std::map<std::string, std::string>& values) = 0;
    virtual int32_t GetByPrefix(const std::string& keyPrefix, std::map<std::string, std::string>& values,
        const std::string& udid) = 0;
    virtual int32_t Sync(const std::vector<std::string>& deviceList, SyncMode syncMode) = 0;
};
} // namespace DeviceProfile
} // namespace OHOS
#endif // OHOS_DP_IKV_ADAPTER_H
