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

#include "local_service_info.h"

#include "cJSON.h"

#include "macro_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "LocalServiceInfo";
}

LocalServiceInfo::LocalServiceInfo()
{
}

LocalServiceInfo::~LocalServiceInfo()
{
}

std::string LocalServiceInfo::GetBundleName() const
{
    return bundleName_;
}

void LocalServiceInfo::SetBundleName(const std::string& bundleName)
{
    bundleName_ = bundleName;
}
  
int32_t LocalServiceInfo::GetAuthBoxType() const
{
    return authBoxType_;
}

void LocalServiceInfo::SetAuthBoxType(const int32_t authBoxType)
{
    authBoxType_ = authBoxType;
}

int32_t LocalServiceInfo::GetAuthType() const
{
    return authType_;
}

void LocalServiceInfo::SetAuthType(const int32_t authType)
{
    authType_ = authType;
}

int32_t LocalServiceInfo::GetPinExchangeType() const
{
    return pinExchangeType_;
}

void LocalServiceInfo::SetPinExchangeType(const int32_t pinExchangeType)
{
    pinExchangeType_ = pinExchangeType;
}

std::string LocalServiceInfo::GetPinCode() const
{
    return pinCode_;
}

void LocalServiceInfo::SetPinCode(const std::string& pinCode)
{
    pinCode_ = pinCode;
}

std::string LocalServiceInfo::GetDescription() const
{
    return description_;
}

void LocalServiceInfo::SetDescription(const std::string& description)
{
    description_ = description;
}

std::string LocalServiceInfo::GetExtraInfo() const
{
    return extraInfo_;
}

void LocalServiceInfo::SetExtraInfo(const std::string& extraInfo)
{
    extraInfo_ = extraInfo;
}

bool LocalServiceInfo::Marshalling(MessageParcel& parcel) const
{
    WRITE_HELPER_RET(parcel, String, bundleName_, false);
    WRITE_HELPER_RET(parcel, Int32, authBoxType_, false);
    WRITE_HELPER_RET(parcel, Int32, authType_, false);
    WRITE_HELPER_RET(parcel, Int32, pinExchangeType_, false);
    WRITE_HELPER_RET(parcel, String, pinCode_, false);
    WRITE_HELPER_RET(parcel, String, description_, false);
    WRITE_HELPER_RET(parcel, String, extraInfo_, false);
    return true;
}

bool LocalServiceInfo::UnMarshalling(MessageParcel& parcel)
{
    READ_HELPER_RET(parcel, String, bundleName_, false);
    READ_HELPER_RET(parcel, Int32, authBoxType_, false);
    READ_HELPER_RET(parcel, Int32, authType_, false);
    READ_HELPER_RET(parcel, Int32, pinExchangeType_, false);
    READ_HELPER_RET(parcel, String, pinCode_, false);
    READ_HELPER_RET(parcel, String, description_, false);
    READ_HELPER_RET(parcel, String, extraInfo_, false);
    return true;
}

std::string LocalServiceInfo::dump() const
{
    return "";
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
