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

#ifndef OHOS_DP_SERVICE_PROFILE_FILTER_OPTIONS_H
#define OHOS_DP_SERVICE_PROFILE_FILTER_OPTIONS_H

#include <cstdint>
#include <string>
#include <vector>

#include "distributed_device_profile_constants.h"
#include "dp_parcel.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class ServiceProfileFilterOptions : public DpParcel {
public:
    ServiceProfileFilterOptions(int32_t userId, std::string& accountId, std::string& deviceId,
        const std::vector<std::string>& wiseDeviceIds, const std::vector<std::string>& serviceIds,
        const std::vector<int32_t>& serviceProfileIds, const std::vector<int32_t>& deviceProfileIds);
    ServiceProfileFilterOptions();
    ~ServiceProfileFilterOptions();
    
    int32_t GetUserId() const;
    void SetUserId(int32_t userId);
    const std::string& GetAccountId() const;
    void SetAccountId(const std::string& accountId);
    const std::string& GetDeviceId() const;
    void SetDeviceId(const std::string& deviceId);
    const std::vector<std::string>& GetWiseDeviceIds() const;
    void SetWiseDeviceIds(const std::vector<std::string>& wiseDeviceIds);
    void AddWiseDeviceIds(const std::string& wiseDeviceId);
    const std::vector<std::string>& GetServiceIds() const;
    void SetServiceIds(const std::vector<std::string>& serviceIds);
    void AddServiceIds(const std::string& serviceId);
    const std::vector<int32_t>& GetServiceProfileIds() const; 
    void SetServiceProfileIds(const std::vector<int32_t>& serviceProfileIds);
    void AddServiceProfileIds(int32_t serviceProfileId);
    const std::vector<int32_t>& GetDeviceProfileIds() const;
    void SetDeviceProfileIds(const std::vector<int32_t>& deviceProfileIds);
    void AddDeviceProfileIds(int32_t deviceProfileId);
    bool IsEmpty() const;
    bool Marshalling(MessageParcel& parcel) const override;
    bool UnMarshalling(MessageParcel& parcel) override;
    std::string dump() const override;

    bool operator==(const ServiceProfileFilterOptions& rhs) const;

private:
    int32_t userId_ = DEFAULT_USER_ID;
    std::string accountId_ = "";
    std::string deviceId_ = "";
    std::vector<std::string> wiseDeviceIds_;
    std::vector<std::string> serviceIds_;
    std::vector<int32_t> serviceProfileIds_;
    std::vector<int32_t> deviceProfileIds_;
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif //OHOS_DP_SERVICE_PROFILE_FILTER_OPTIONS_H
