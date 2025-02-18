/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_DP_SERVICE_INFO_UNIQUE_KEY_H
#define OHOS_DP_SERVICE_INFO_UNIQUE_KEY_H

#include <cstdint>
#include <string>

#include "distributed_device_profile_constants.h"
#include "dp_parcel.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class ServiceInfoUniqueKey : public DpParcel {
public:
    ServiceInfoUniqueKey(const std::string& deviceId, const int32_t userId, const std::string& tokenId,
        const int64_t serviceId)
        : deviceId_(deviceId),
        userId_(userId),
        tokenId_(tokenId),
        serviceId_(serviceId)
    {}
    ServiceInfoUniqueKey(const std::string& deviceId, const int32_t userId, const std::string& bundleName)
        : deviceId_(deviceId),
        userId_(userId),
        bundleName_(bundleName)
    {}
    ServiceInfoUniqueKey();
    ~ServiceInfoUniqueKey();

    std::string GetDeviceId() const;
    void SetDeviceId(const std::string& deviceId);
    int32_t GetUserId() const;
    void SetUserId(const int32_t userId);
    std::string GetTokenId() const;
    void SetTokenId(const std::string& tokenId);
    int64_t GetServiceId() const;
    void SetServiceId(const int64_t serviceId);
    std::string GetBundleName() const;
    void SetBundleName(const std::string& bundleName);

    bool Marshalling(MessageParcel& parcel) const override;
    bool UnMarshalling(MessageParcel& parcel) override;
    std::string dump() const override;

private:
    std::string deviceId_ = "";
    int32_t userId_ = DEFAULT_USER_ID;
    std::string tokenId_ = "";
    int64_t serviceId_ = DEFAULT_SERVICE_ID;
    std::string bundleName_ = "";
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif //OHOS_DP_SERVICE_INFO_UNIQUE_KEY_H
