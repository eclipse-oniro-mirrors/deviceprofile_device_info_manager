/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "user_info.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class ServiceInfo : public DpParcel {
public:
    ServiceInfo()
        : udid_(""), userId_(DEFAULT_USER_ID), displayId_(DEFAULT_DISPLAY_ID),
        serviceOwnerTokenId_(DEFAULT_SERVICE_OWNER_TOKENID), serviceOwnerPkgName_(""),
        serviceRegisterTokenId_(DEFAULT_SERVICE_REGISTER_TOKENID), serviceId_(DEFAULT_SERVICE_ID),
        timeStamp_(DEFAULT_TIMESTAMP), publishState_(DEFAULT_PUBLISH_STATE), serviceType_(""), serviceName_(""),
        serviceDisplayName_(""), customData_(""), serviceCode_(""), dataLen_(0), extraData_(""),
        version_(""), description_(""){};

    ~ServiceInfo();

    const std::string& GetUdid() const;
    void SetUdid(const std::string& udid);
    int32_t GetUserId() const;
    void SetUserId(int32_t userId);
    int64_t GetDisplayId() const;
    void SetDisplayId(int64_t displayId);
    int32_t GetServiceOwnerTokenId() const;
    void SetServiceOwnerTokenId(int32_t serviceOwnerTokenId);
    const std::string& GetServiceOwnerPkgName() const;
    void SetServiceOwnerPkgName(const std::string& serviceOwnerPkgName);
    int32_t GetServiceRegisterTokenId() const;
    void SetServiceRegisterTokenId(int32_t serviceRegisterTokenId);
    int64_t GetServiceId() const;
    void SetServiceId(int64_t serviceId);
    int64_t GetTimeStamp() const;
    void SetTimeStamp(int64_t timeStamp);
    int8_t GetPublishState() const;
    void SetPublishState(int8_t publishState);
    const std::string& GetServiceType() const;
    void SetServiceType(const std::string& serviceType);
    const std::string& GetServiceName() const;
    void SetServiceName(const std::string& serviceName);
    const std::string& GetServiceDisplayName() const;
    void SetServiceDisplayName(const std::string& serviceDisplayName);

    const std::string& GetCustomData() const;
    void SetCustomData(const std::string& customData);
    const std::string& GetServiceCode() const;
    void SetServiceCode(const std::string& serviceCode);
    uint32_t GetDataLen() const;
    void SetDataLen(uint32_t dataLen);
    const std::string& GetExtraData() const;
    void SetExtraData(const std::string& extraData);
    const std::string& GetVersion() const;
    void SetVersion(const std::string& version);
    const std::string& GetDescription() const;
    void SetDescription(const std::string& description);

    bool Marshalling(MessageParcel& parcel) const override;
    bool UnMarshalling(MessageParcel& parcel) override;
    std::string dump() const override;

    bool operator<(const ServiceInfo& other) const
    {
        return (udid_ < other.udid_) ||
            (udid_ == other.udid_ && userId_ < other.userId_) ||
            (udid_ == other.udid_ && userId_ == other.userId_ && serviceId_ < other.serviceId_);
    }

    bool operator==(const ServiceInfo& other) const
    {
        return (udid_ == other.udid_) && (userId_ == other.userId_) && (serviceId_ == other.serviceId_);
    }

private:
    std::string udid_;
    int32_t userId_;
    int64_t displayId_;
    int32_t serviceOwnerTokenId_;
    std::string serviceOwnerPkgName_;
    int32_t serviceRegisterTokenId_;
    int64_t serviceId_;
    int64_t timeStamp_;
    int8_t publishState_;
    std::string serviceType_;
    std::string serviceName_;
    std::string serviceDisplayName_;
    std::string customData_;
    std::string serviceCode_;
    uint32_t dataLen_;
    std::string extraData_;
    std::string version_;
    std::string description_;
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif //OHOS_DP_SERVICE_INFO_H