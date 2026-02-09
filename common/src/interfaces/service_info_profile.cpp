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

#include "service_info_profile.h"

#include "cJSON.h"

#include "distributed_device_profile_constants.h"
#include "macro_utils.h"
#include "profile_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "ServiceInfoProfile";
}

ServiceInfoProfile::ServiceInfoProfile()
{
}

ServiceInfoProfile::~ServiceInfoProfile()
{
}

std::string  ServiceInfoProfile::GetDeviceId() const
{
    return deviceId_;
}

void ServiceInfoProfile::SetDeviceId(const std::string& deviceId)
{
    deviceId_ = deviceId;
}

int32_t ServiceInfoProfile::GetUserId() const
{
    return userId_;
}

void ServiceInfoProfile::SetUserId(const int32_t userId)
{
    userId_ = userId;
}

std::string ServiceInfoProfile::GetNetworkId() const
{
    return networkId_;
}

void ServiceInfoProfile::SetNetworkId(const std::string& networkId)
{
    networkId_ = networkId;
}

std::string ServiceInfoProfile::GetTokenId() const
{
    return tokenId_;
}

void ServiceInfoProfile::SetTokenId(const std::string& tokenId)
{
    tokenId_ = tokenId;
}

int64_t ServiceInfoProfile::GetServiceId() const
{
    return serviceId_;
}

void ServiceInfoProfile::SetServiceId(const int64_t serviceId)
{
    serviceId_ = serviceId;
}

std::string ServiceInfoProfile::GetServiceType() const
{
    return serviceType_;
}

void ServiceInfoProfile::SetServiceType(const std::string& serviceType)
{
    serviceType_ = serviceType;
}

std::string ServiceInfoProfile::GetServiceName() const
{
    return serviceName_;
}

void ServiceInfoProfile::SetServiceName(const std::string& serviceName)
{
    serviceName_ = serviceName;
}

std::string ServiceInfoProfile::GetServiceDisplayName() const
{
    return serviceDisplayName_;
}

void ServiceInfoProfile::SetServiceDisplayName(const std::string& serviceDisplayName)
{
    serviceDisplayName_ = serviceDisplayName;
}

std::string ServiceInfoProfile::GetCustomData() const
{
    return customData_;
}

void ServiceInfoProfile::SetCustomData(const std::string& customData)
{
    customData_ = customData;
}

int32_t ServiceInfoProfile::GetCustomDataLen() const
{
    return customDataLen_;
}

void ServiceInfoProfile::SetCustomDataLen(const int32_t customDataLen)
{
    customDataLen_ = customDataLen;
}

std::string ServiceInfoProfile::GetBundleName() const
{
    return bundleName_;
}

void ServiceInfoProfile::SetBundleName(const std::string& bundleName)
{
    bundleName_ = bundleName;
}

std::string ServiceInfoProfile::GetModuleName() const
{
    return moduleName_;
}

void ServiceInfoProfile::SetModuleName(const std::string& moduleName)
{
    moduleName_ = moduleName;
}

std::string ServiceInfoProfile::GetAbilityName() const
{
    return abilityName_;
}

void ServiceInfoProfile::SetAbilityName(const std::string& abilityName)
{
    abilityName_ = abilityName;
}
  
int32_t ServiceInfoProfile::GetAuthBoxType() const
{
    return authBoxType_;
}

void ServiceInfoProfile::SetAuthBoxType(const int32_t authBoxType)
{
    authBoxType_ = authBoxType;
}

int32_t ServiceInfoProfile::GetAuthType() const
{
    return authType_;
}

void ServiceInfoProfile::SetAuthType(const int32_t authType)
{
    authType_ = authType;
}

int32_t ServiceInfoProfile::GetPinExchangeType() const
{
    return pinExchangeType_;
}

void ServiceInfoProfile::SetPinExchangeType(const int32_t pinExchangeType)
{
    pinExchangeType_ = pinExchangeType;
}

std::string ServiceInfoProfile::GetPinCode() const
{
    return pinCode_;
}

void ServiceInfoProfile::SetPinCode(const std::string& pinCode)
{
    pinCode_ = pinCode;
}

std::string ServiceInfoProfile::GetDescription() const
{
    return description_;
}

void ServiceInfoProfile::SetDescription(const std::string& description)
{
    description_ = description;
}

std::string ServiceInfoProfile::GetServiceDicoveryScope() const
{
    return serviceDicoveryScope_;
}

void ServiceInfoProfile::SetServiceDicoveryScope(const std::string& serviceDicoveryScope)
{
    serviceDicoveryScope_ = serviceDicoveryScope;
}

std::string ServiceInfoProfile::GetExtraInfo() const
{
    return extraInfo_;
}

void ServiceInfoProfile::SetExtraInfo(const std::string& extraInfo)
{
    extraInfo_ = extraInfo;
}
//delete start
bool ServiceInfoProfile::Marshalling(MessageParcel& parcel) const
{
    WRITE_HELPER_RET(parcel, String, deviceId_, false);
    WRITE_HELPER_RET(parcel, Int32, userId_, false);
    WRITE_HELPER_RET(parcel, String, networkId_, false);
    WRITE_HELPER_RET(parcel, String, tokenId_, false);
    WRITE_HELPER_RET(parcel, Int64, serviceId_, false);
    WRITE_HELPER_RET(parcel, String, serviceType_, false);
    WRITE_HELPER_RET(parcel, String, serviceName_, false);
    WRITE_HELPER_RET(parcel, String, serviceDisplayName_, false);
    WRITE_HELPER_RET(parcel, String, customData_, false);
    WRITE_HELPER_RET(parcel, Int32, customDataLen_, false);
    WRITE_HELPER_RET(parcel, String, bundleName_, false);
    WRITE_HELPER_RET(parcel, String, moduleName_, false);
    WRITE_HELPER_RET(parcel, String, abilityName_, false);
    WRITE_HELPER_RET(parcel, Int32, authBoxType_, false);
    WRITE_HELPER_RET(parcel, Int32, authType_, false);
    WRITE_HELPER_RET(parcel, Int32, pinExchangeType_, false);
    WRITE_HELPER_RET(parcel, String, pinCode_, false);
    WRITE_HELPER_RET(parcel, String, description_, false);
    WRITE_HELPER_RET(parcel, String, serviceDicoveryScope_, false);
    WRITE_HELPER_RET(parcel, String, extraInfo_, false);
    return true;
}

bool ServiceInfoProfile::UnMarshalling(MessageParcel& parcel)
{
    READ_HELPER_RET(parcel, String, deviceId_, false);
    READ_HELPER_RET(parcel, Int32, userId_, false);
    READ_HELPER_RET(parcel, String, networkId_, false);
    READ_HELPER_RET(parcel, String, tokenId_, false);
    READ_HELPER_RET(parcel, Int64, serviceId_, false);
    READ_HELPER_RET(parcel, String, serviceType_, false);
    READ_HELPER_RET(parcel, String, serviceName_, false);
    READ_HELPER_RET(parcel, String, serviceDisplayName_, false);
    READ_HELPER_RET(parcel, String, customData_, false);
    READ_HELPER_RET(parcel, Int32, customDataLen_, false);
    READ_HELPER_RET(parcel, String, bundleName_, false);
    READ_HELPER_RET(parcel, String, moduleName_, false);
    READ_HELPER_RET(parcel, String, abilityName_, false);
    READ_HELPER_RET(parcel, Int32, authBoxType_, false);
    READ_HELPER_RET(parcel, Int32, authType_, false);
    READ_HELPER_RET(parcel, Int32, pinExchangeType_, false);
    READ_HELPER_RET(parcel, String, pinCode_, false);
    READ_HELPER_RET(parcel, String, description_, false);
    READ_HELPER_RET(parcel, String, serviceDicoveryScope_, false);
    READ_HELPER_RET(parcel, String, extraInfo_, false);
    return true;
}
//delete end

std::string ServiceInfoProfile::dump() const
{
    return "";
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
