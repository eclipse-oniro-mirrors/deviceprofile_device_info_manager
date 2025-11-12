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

#include "service_info_unique_key.h"

#include "cJSON.h"

#include "distributed_device_profile_constants.h"
#include "macro_utils.h"
#include "profile_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "ServiceInfoUniqueKey";
}
ServiceInfoUniqueKey::ServiceInfoUniqueKey()
{
}
ServiceInfoUniqueKey::~ServiceInfoUniqueKey()
{
}
std::string ServiceInfoUniqueKey::GetDeviceId() const
{
    return deviceId_;
}

void ServiceInfoUniqueKey::SetDeviceId(const std::string& deviceId)
{
    deviceId_ = deviceId;
}

int32_t ServiceInfoUniqueKey::GetUserId() const
{
    return userId_;
}

void ServiceInfoUniqueKey::SetUserId(const int32_t userId)
{
    userId_ = userId;
}

std::string ServiceInfoUniqueKey::GetTokenId() const
{
    return tokenId_;
}

void ServiceInfoUniqueKey::SetTokenId(const std::string& tokenId)
{
    tokenId_ = tokenId;
}

int64_t ServiceInfoUniqueKey::GetServiceId() const
{
    return serviceId_;
}

void ServiceInfoUniqueKey::SetServiceId(const int64_t serviceId)
{
    serviceId_ = serviceId;
}

std::string ServiceInfoUniqueKey::GetBundleName() const
{
    return bundleName_;
}

void ServiceInfoUniqueKey::SetBundleName(const std::string& bundleName)
{
    bundleName_ = bundleName;
}

bool ServiceInfoUniqueKey::operator<(const ServiceInfoUniqueKey& rhs) const
{
    return serviceId_ < rhs.serviceId_;
}

bool ServiceInfoUniqueKey::Marshalling(MessageParcel& parcel) const
{
    WRITE_HELPER_RET(parcel, String, deviceId_, false);
    WRITE_HELPER_RET(parcel, Int32, userId_, false);
    WRITE_HELPER_RET(parcel, String, tokenId_, false);
    WRITE_HELPER_RET(parcel, Int64, serviceId_, false);
    WRITE_HELPER_RET(parcel, String, bundleName_, false);
    return true;
}

bool ServiceInfoUniqueKey::UnMarshalling(MessageParcel& parcel)
{
    READ_HELPER_RET(parcel, String, deviceId_, false);
    READ_HELPER_RET(parcel, Int32, userId_, false);
    READ_HELPER_RET(parcel, String, tokenId_, false);
    READ_HELPER_RET(parcel, Int64, serviceId_, false);
    READ_HELPER_RET(parcel, String, bundleName_, false);
    return true;
}

std::string ServiceInfoUniqueKey::dump() const
{
    return "";
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
