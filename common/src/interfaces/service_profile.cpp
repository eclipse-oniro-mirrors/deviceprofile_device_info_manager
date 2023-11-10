/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "service_profile.h"
#include "macro_utils.h"
#include "distributed_device_profile_constants.h"
#include "nlohmann/json.hpp"
#include "profile_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "ServiceProfile";
}

ServiceProfile::ServiceProfile(const std::string& deviceId, const std::string& serviceName, const std::string& serviceType)
    : deviceId_(deviceId), serviceName_(serviceName), serviceType_(serviceType)
{
    HILOGI("constructor!");
}
ServiceProfile::ServiceProfile()
{
    HILOGI("constructor!");
}

ServiceProfile::~ServiceProfile()
{
    HILOGI("destructor");
}

std::string ServiceProfile::GetDeviceId() const
{
    return deviceId_;
}

void ServiceProfile::SetDeviceId(const std::string& deviceId)
{
    deviceId_ = deviceId;
}

std::string ServiceProfile::GetServiceName() const
{
    return serviceName_;
}

void ServiceProfile::SetServiceName(const std::string& serviceName)
{
    serviceName_ = serviceName;
}

std::string ServiceProfile::GetServiceType() const
{
    return serviceType_;
}

void ServiceProfile::SetServiceType(const std::string& serviceType)
{
    serviceType_ = serviceType;
}

bool ServiceProfile::Marshalling(MessageParcel& parcel) const
{
    WRITE_HELPER_RET(parcel, String, deviceId_, false);
    WRITE_HELPER_RET(parcel, String, serviceName_, false);
    WRITE_HELPER_RET(parcel, String, serviceType_, false);
    return true;
}

bool ServiceProfile::UnMarshalling(MessageParcel& parcel)
{
    READ_HELPER_RET(parcel, String, deviceId_, false);
    READ_HELPER_RET(parcel, String, serviceName_, false);
    READ_HELPER_RET(parcel, String, serviceType_, false);
    return true;
}

bool ServiceProfile::operator!=(const ServiceProfile& serviceProfile) const
{
    bool isNotEqual = (deviceId_ != serviceProfile.GetDeviceId() || serviceName_ != serviceProfile.GetServiceName() ||
        serviceType_ != serviceProfile.GetServiceType());
    if (isNotEqual) {
        return true;
    } else {
        return false;
    }
}

std::string ServiceProfile::dump() const
{
    nlohmann::json json;
    json[DEVICE_ID] = ProfileUtils::GetAnonyString(deviceId_);
    json[SERVICE_NAME] = serviceName_;
    json[SERVICE_TYPE] = serviceType_;
    return json.dump();
}
} // namespace DistributedDeviceProfile
} // namespace OHOS