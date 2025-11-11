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

#ifndef OHOS_DP_SERVICE_INFO_H
#define OHOS_DP_SERVICE_INFO_H

#include <cstdint>
#include <string>

#include "distributed_device_profile_constants.h"
#include "dp_parcel.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class ServiceInfoProfileNew : public DpParcel {
public:
    ServiceInfoProfileNew()
        : regServiceId_(0),
        deviceId_(""),
        userId_(-1),
        tokenId_(0),
        servicePubState_(0),
        serviceId_(0),
        serviceType_(""),
        serviceName_(""),
        serviceDisplayName_("")
        {};

    ~ServiceInfoProfileNew();

    int32_t GetRegServiceId() const;
    void SetRegServiceId(int32_t regServiceIdValue);
    std::string GetDeviceId() const;
    void SetDeviceId(const std::string &deviceIdValue);

    int32_t GetUserId() const;
    void SetUserId(int32_t userIdValue);

    int64_t GetTokenId() const;
    void SetTokenId(int64_t tokenIdValue);

    int8_t GetSerPubState() const;
    void SetSerPubState(int8_t SerPubStateValue);

    int64_t GetServiceId() const;
    void SetServiceId(int64_t serviceIdValue);

    std::string GetServiceType() const;
    void SetServiceType(const std::string &serviceTypeValue);

    std::string GetServiceName() const;
    void SetServiceName(const std::string &serviceNameValue);

    std::string GetServiceDisplayName() const;
    void SetServiceDisplayName(const std::string &serviceDisplayNameValue);

    bool Marshalling(MessageParcel& parcel) const override;
    bool UnMarshalling(MessageParcel& parcel) override;
    std::string dump() const override;

private:
    int32_t regServiceId_;
    std::string deviceId_;
    int32_t userId_;
    int64_t tokenId_;
    int8_t servicePubState_;
    int64_t serviceId_;
    std::string serviceType_;
    std::string serviceName_;
    std::string serviceDisplayName_;
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif //OHOS_DP_SERVICE_INFO_H