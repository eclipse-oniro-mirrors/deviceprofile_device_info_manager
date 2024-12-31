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

#include "service_profile_filter_opotions.h"

#include "cJSON.h"

#include "distributed_device_profile_constants.h"
#include "ipc_utils.h"
#include "macro_utils.h"
#include "profile_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "ServiceProfileFilterOptions";
}
ServiceProfileFilterOptions::ServiceProfileFilterOptions(int32_t userId, std::string& accountId,
    std::string& deviceId, const std::vector<std::string>& wiseDeviceIds,
    const std::vector<std::string>& serviceIds,const std::vector<int32_t>& serviceProfileIds,
    const std::vector<int32_t>& deviceProfileIds)
    : userId_(userId), accountId_(accountId), deviceId_(deviceId), wiseDeviceIds_(wiseDeviceIds),
    serviceIds_(serviceIds), serviceProfileIds_(serviceProfileIds), deviceProfileIds_(deviceProfileIds)
{
}

ServiceProfileFilterOptions::ServiceProfileFilterOptions()
{
}

ServiceProfileFilterOptions::~ServiceProfileFilterOptions()
{
}

int32_t ServiceProfileFilterOptions::GetUserId() const
{
    return userId_;
}

void ServiceProfileFilterOptions::SetUserId(int32_t userId)
{
    userId_ = userId;
}

const std::string& ServiceProfileFilterOptions::GetAccountId() const
{
    return accountId_;
}

void ServiceProfileFilterOptions::SetAccountId(const std::string& accountId)
{
    accountId_ = accountId;
}

const std::string& ServiceProfileFilterOptions::GetDeviceId() const
{
    return deviceId_;
}

void ServiceProfileFilterOptions::SetDeviceId(const std::string& deviceId)
{
    deviceId_ = deviceId;
}

const std::vector<std::string>& ServiceProfileFilterOptions::GetWiseDeviceIds() const
{
    return wiseDeviceIds_;
}

void ServiceProfileFilterOptions::SetWiseDeviceIds(const std::vector<std::string>& wiseDeviceIds)
{
    wiseDeviceIds_ = wiseDeviceIds;
}

const std::vector<std::string>& ServiceProfileFilterOptions::GetServiceIds() const
{
    return serviceIds_;
}

void ServiceProfileFilterOptions::SetServiceIds(const std::vector<std::string>& serviceIds)
{
    serviceIds_ = serviceIds;
}

const std::vector<int32_t>& ServiceProfileFilterOptions::GetServiceProfileIds() const
{
    return serviceProfileIds_;
}

void ServiceProfileFilterOptions::SetServiceProfileIds(const std::vector<int32_t>& serviceProfileIds)
{
    serviceProfileIds_ = serviceProfileIds;
}

const std::vector<int32_t>& ServiceProfileFilterOptions::GetDeviceProfileIds() const
{
    return deviceProfileIds_;
}

void ServiceProfileFilterOptions::SetDeviceProfileIds(const std::vector<int32_t>& deviceProfileIds)
{
    deviceProfileIds_ = deviceProfileIds;
}

bool ServiceProfileFilterOptions::Marshalling(MessageParcel& parcel) const
{
    WRITE_HELPER_RET(parcel, Int32, userId_, false);
    WRITE_HELPER_RET(parcel, String, accountId_, false);
    WRITE_HELPER_RET(parcel, String, deviceId_, false);
    if (!IpcUtils::Marshalling(parcel, wiseDeviceIds_)) {
        HILOGE("dp write parcel fail");
        return false;
    }
    if (!IpcUtils::Marshalling(parcel, serviceIds_)) {
        HILOGE("dp write parcel fail");
        return false;
    }
    if (!IpcUtils::Marshalling(parcel, serviceProfileIds_)) {
        HILOGE("dp write parcel fail");
        return false;
    }
    if (!IpcUtils::Marshalling(parcel, deviceProfileIds_)) {
        HILOGE("dp write parcel fail");
        return false;
    }
    return true;
}

bool ServiceProfileFilterOptions::UnMarshalling(MessageParcel& parcel)
{
    READ_HELPER_RET(parcel, Int32, userId_, false);
    READ_HELPER_RET(parcel, String, accountId_, false);
    READ_HELPER_RET(parcel, String, deviceId_, false);
    if (!IpcUtils::UnMarshalling(parcel, wiseDeviceIds_)) {
        HILOGE("dp read parcel fail");
        return false;
    }
    if (!IpcUtils::UnMarshalling(parcel, serviceIds_)) {
        HILOGE("dp read parcel fail");
        return false;
    }
    if (!IpcUtils::UnMarshalling(parcel, serviceProfileIds_)) {
        HILOGE("dp read parcel fail");
        return false;
    }
    if (!IpcUtils::UnMarshalling(parcel, deviceProfileIds_)) {
        HILOGE("dp read parcel fail");
        return false;
    }
    return true;
}

bool ServiceProfileFilterOptions::IsEmpty() const
{
    return deviceId_.empty() && wiseDeviceIds_.empty() && serviceIds_.empty() && userId_ == DEFAULT_USER_ID &&
        serviceProfileIds_.empty() && accountId_.empty() && deviceProfileIds_.empty();
}

void ServiceProfileFilterOptions::AddWiseDeviceIds(const std::string& wiseDeviceId)
{
    wiseDeviceIds_.emplace_back(wiseDeviceId);
}

void ServiceProfileFilterOptions::AddServiceIds(const std::string& serviceId)
{
    serviceIds_.emplace_back(serviceId);
}

void ServiceProfileFilterOptions::AddServiceProfileIds(int32_t serviceProfileId)
{
    serviceProfileIds_.emplace_back(serviceProfileId);
}

void ServiceProfileFilterOptions::AddDeviceProfileIds(int32_t deviceProfileId)
{
    deviceProfileIds_.emplace_back(deviceProfileId);
}

std::string ServiceProfileFilterOptions::dump() const
{
    return "";
}

} // namespace DistributedDeviceProfile
} // namespace OHOS
