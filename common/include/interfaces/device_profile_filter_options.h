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

#ifndef OHOS_DP_DEVICE_PROFILE_FILTER_OPTIONS_H
#define OHOS_DP_DEVICE_PROFILE_FILTER_OPTIONS_H

#include <string>
#include "distributed_device_profile_enums.h"
#include "dp_parcel.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class DeviceProfileFilterOptions : public DpParcel {
public:
    DeviceProfileFilterOptions()
        : userId_(-1),
        accountId_("")
    {}
    ~DeviceProfileFilterOptions() = default;

    int32_t GetUserId() const;
    void SetUserId(int32_t userId);
    std::string GetAccountId() const;
    void SetAccountId(std::string accountId);
    std::vector<std::string> GetDeviceIds() const;
    void SetDeviceIds(std::vector<std::string> deviceIds);
    void AddDeviceIds(std::string deviceId);
    std::vector<std::string> GetWiseDeviceIds() const;
    void SetWiseDeviceIds(std::vector<std::string> wiseDeviceIds);
    void AddWiseDeviceIds(std::string wiseDeviceId);
    std::vector<int32_t> GetDeviceProfileIds() const;
    void SetDeviceProfileIds(std::vector<int32_t> deviceProfileIds);
    void AddDeviceProfileIds(int32_t deviceProfileId);
    bool Marshalling(MessageParcel& parcel) const override;
    bool UnMarshalling(MessageParcel& parcel) override;
    std::string dump() const override;

private:
    int32_t userId_;
    std::string accountId_;
    std::vector<std::string> deviceIds_;
    std::vector<std::string> wiseDeviceIds_;
    std::vector<int32_t> deviceProfileIds_;
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // OHOS_DP_DEVICE_PROFILE_FILTER_OPTIONS_H
