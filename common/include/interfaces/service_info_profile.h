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

#ifndef OHOS_DP_SERVICE_INFO_PROFILE_H
#define OHOS_DP_SERVICE_INFO_PROFILE_H

#include <cstdint>
#include <string>

#include "distributed_device_profile_constants.h"
#include "dp_parcel.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class ServiceInfoProfile : public DpParcel {
public:
    ServiceInfoProfile(const std::string& deviceId, const int32_t userId, const std::string& networkId,
        const std::string& tokenId, const int64_t serviceId, const std::string& serviceType,
        const std::string& serviceName, const std::string& serviceDisplayName, const std::string& customData,
        const int32_t customDataLen, const std::string& bundleName, const std::string& moduleName,
        const std::string abilityName, const int32_t authBoxType, const int32_t authType, const int32_t pinExchangeType,
        const std::string& pinCode, const std::string& description, const std::string& serviceDicoveryScope,
        const std::string& extraInfo)
        : deviceId_(deviceId),
        userId_(userId),
        networkId_(networkId),
        tokenId_(tokenId),
        serviceId_(serviceId),
        serviceType_(serviceType),
        serviceName_(serviceName),
        serviceDisplayName_(serviceDisplayName),
        customData_(customData),
        customDataLen_(customDataLen),
        bundleName_(bundleName),
        moduleName_(moduleName),
        abilityName_(abilityName),
        authBoxType_(authBoxType),
        authType_(authType),
        pinExchangeType_(pinExchangeType),
        pinCode_(pinCode),
        description_(description),
        serviceDicoveryScope_(serviceDicoveryScope),
        extraInfo_(extraInfo)
    {}
    ServiceInfoProfile();
    ~ServiceInfoProfile();

    std::string GetDeviceId() const;
    void SetDeviceId(const std::string& deviceId);
    int32_t GetUserId() const;
    void SetUserId(const int32_t userId);
    std::string GetNetworkId() const;
    void SetNetworkId(const std::string& networkId);
    std::string GetTokenId() const;
    void SetTokenId(const std::string& tokenId);
    int64_t GetServiceId() const;
    void SetServiceId(const int64_t serviceId);
    std::string GetServiceType() const;
    void SetServiceType(const std::string& serviceType);
    std::string GetServiceName() const;
    void SetServiceName(const std::string& serviceName);
    std::string GetServiceDisplayName() const;
    void SetServiceDisplayName(const std::string& serviceDisplayName);
    std::string GetCustomData() const;
    void SetCustomData(const std::string& customData);
    int32_t GetCustomDataLen() const;
    void SetCustomDataLen(const int32_t customDataLen);
    std::string GetBundleName() const;
    void SetBundleName(const std::string& bundleName);
    std::string GetModuleName() const;
    void SetModuleName(const std::string& moduleName);
    std::string GetAbilityName() const;
    void SetAbilityName(const std::string& abilityName);
    int32_t GetAuthBoxType() const;
    void SetAuthBoxType(const int32_t authBoxType);
    int32_t GetAuthType() const;
    void SetAuthType(const int32_t authType);
    int32_t GetPinExchangeType() const;
    void SetPinExchangeType(const int32_t pinExchangeType);
    std::string GetPinCode() const;
    void SetPinCode(const std::string& pinCode);
    std::string GetDescription() const;
    void SetDescription(const std::string& description);
    std::string GetServiceDicoveryScope() const;
    void SetServiceDicoveryScope(const std::string& serviceDicoveryScope);
    std::string GetExtraInfo() const;
    void SetExtraInfo(const std::string& extraInfo);

    bool Marshalling(MessageParcel& parcel) const override;
    bool UnMarshalling(MessageParcel& parcel) override;
    std::string dump() const override;

private:
    std::string deviceId_ = "";
    int32_t userId_ = DEFAULT_USER_ID;
    std::string networkId_ = "";
    std::string tokenId_ = "";
    int64_t serviceId_ = DEFAULT_SERVICE_ID;
    std::string serviceType_ = "";
    std::string serviceName_ = "";
    std::string serviceDisplayName_ = "";
    std::string customData_ = "";
    int32_t customDataLen_ = 0;
    std::string bundleName_ = "";
    std::string moduleName_ = "";
    std::string abilityName_ = "";
    int32_t authBoxType_ = 0;
    int32_t authType_ = 0;
    int32_t pinExchangeType_ = 0;
    std::string pinCode_ = "";
    std::string description_ = "";
    std::string serviceDicoveryScope_ = "";
    std::string extraInfo_ = "";
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif //OHOS_DP_SERVICE_INFO_PROFILE_H
