/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "service_characteristic_profile.h"

#include <iosfwd>
#include <string>

#include "device_profile_log.h"
#include "parcel.h"
#include "parcel_helper.h"

namespace OHOS {
namespace DeviceProfile {
namespace {
const std::string TAG = "ServiceCharacteristicProfile";
}

void ServiceCharacteristicProfile::SetServiceId(const std::string& serviceId)
{
    serviceId_ = serviceId;
}

void ServiceCharacteristicProfile::SetServiceType(const std::string& serviceType)
{
    serviceType_ = serviceType;
}

void ServiceCharacteristicProfile::SetServiceProfileJson(const std::string& profileJson)
{
    serviceProfileJson_ = profileJson;
}

void ServiceCharacteristicProfile::SetCharacteristicProfileJson(const std::string& profileJson)
{
    characteristicProfileJson_ = profileJson;
}

const std::string& ServiceCharacteristicProfile::GetServiceId() const
{
    return serviceId_;
}

const std::string& ServiceCharacteristicProfile::GetServiceType() const
{
    return serviceType_;
}

const std::string& ServiceCharacteristicProfile::GetServiceProfileJson() const
{
    return serviceProfileJson_;
}

const std::string& ServiceCharacteristicProfile::GetCharacteristicProfileJson() const
{
    return characteristicProfileJson_;
}

bool ServiceCharacteristicProfile::Marshalling(Parcel& parcel) const
{
    PARCEL_WRITE_HELPER_RET(parcel, String, serviceId_, false);
    PARCEL_WRITE_HELPER_RET(parcel, String, serviceType_, false);
    PARCEL_WRITE_HELPER_RET(parcel, String, characteristicProfileJson_, false);
    PARCEL_WRITE_HELPER_RET(parcel, String, serviceProfileJson_, false);
    return true;
}

bool ServiceCharacteristicProfile::Unmarshalling(Parcel& parcel)
{
    PARCEL_READ_HELPER_RET(parcel, String, serviceId_, false);
    PARCEL_READ_HELPER_RET(parcel, String, serviceType_, false);
    PARCEL_READ_HELPER_RET(parcel, String, characteristicProfileJson_, false);
    PARCEL_READ_HELPER_RET(parcel, String, serviceProfileJson_, false);
    return true;
}
} // namespace DeviceProfile
} // namespace OHOS
