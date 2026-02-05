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

#include "service_info.h"
#include "cJSON.h"
#include "distributed_device_profile_constants.h"
#include "macro_utils.h"
#include "profile_utils.h"
#include <cstdint>

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "ServiceInfo";
}

ServiceInfo::~ServiceInfo()
{
}

const std::string& ServiceInfo::GetUdid() const
{
    return udid_;
}

void ServiceInfo::SetUdid(const std::string& udid)
{
    udid_ = udid;
}

int32_t ServiceInfo::GetUserId() const
{
    return userId_;
}

void ServiceInfo::SetUserId(int32_t userId)
{
    userId_ = userId;
}
int64_t ServiceInfo::GetDisplayId() const
{
    return displayId_;
}
void ServiceInfo::SetDisplayId(int64_t displayId)
{
    displayId_ = displayId;
}

int32_t ServiceInfo::GetServiceOwnerTokenId() const
{
    return serviceOwnerTokenId_;
}

void ServiceInfo::SetServiceOwnerTokenId(int32_t serviceOwnerTokenId)
{
    serviceOwnerTokenId_ = serviceOwnerTokenId;
}

const std::string& ServiceInfo::GetServiceOwnerPkgName() const
{
    return serviceOwnerPkgName_;
}

void ServiceInfo::SetServiceOwnerPkgName(const std::string& serviceOwnerPkgName)
{
    serviceOwnerPkgName_ = serviceOwnerPkgName;
}

int32_t ServiceInfo::GetServiceRegisterTokenId() const
{
    return serviceRegisterTokenId_;
}

void ServiceInfo::SetServiceRegisterTokenId(int32_t serviceRegisterTokenId)
{
    serviceRegisterTokenId_ = serviceRegisterTokenId;
}

int64_t ServiceInfo::GetServiceId() const
{
    return serviceId_;
}

void ServiceInfo::SetServiceId(int64_t serviceId)
{
    serviceId_ = serviceId;
}

int64_t ServiceInfo::GetTimeStamp() const
{
    return timeStamp_;
}

void ServiceInfo::SetTimeStamp(int64_t timeStamp)
{
    timeStamp_ = timeStamp;
}

int8_t ServiceInfo::GetPublishState() const
{
    return publishState_;
}

void ServiceInfo::SetPublishState(int8_t publishState)
{
    publishState_ = publishState;
}

const std::string& ServiceInfo::GetServiceType() const
{
    return serviceType_;
}

void ServiceInfo::SetServiceType(const std::string& serviceType)
{
    serviceType_ = serviceType;
}

const std::string& ServiceInfo::GetServiceName() const
{
    return serviceName_;
}

void ServiceInfo::SetServiceName(const std::string& serviceName)
{
    serviceName_ = serviceName;
}

const std::string& ServiceInfo::GetServiceDisplayName() const
{
    return serviceDisplayName_;
}

void ServiceInfo::SetServiceDisplayName(const std::string& serviceDisplayName)
{
    serviceDisplayName_ = serviceDisplayName;
}

const std::string& ServiceInfo::GetCustomData() const
{
    return customData_;
}

void ServiceInfo::SetCustomData(const std::string& customData)
{
    customData_ = customData;
}

const std::string& ServiceInfo::GetServiceCode() const
{
    return serviceCode_;
}

void ServiceInfo::SetServiceCode(const std::string& serviceCode)
{
    serviceCode_ = serviceCode;
}

uint32_t ServiceInfo::GetDataLen() const
{
    return dataLen_;
}

void ServiceInfo::SetDataLen(uint32_t dataLen)
{
    dataLen_ = dataLen;
}

const std::string& ServiceInfo::GetExtraData() const
{
    return extraData_;
}

void ServiceInfo::SetExtraData(const std::string& extraData)
{
    extraData_ = extraData;
}

const std::string& ServiceInfo::GetVersion() const
{
    return version_;
}

void ServiceInfo::SetVersion(const std::string& version)
{
    version_ = version;
}
const std::string& ServiceInfo::GetDescription() const
{
    return description_;
}
void ServiceInfo::SetDescription(const std::string& description)
{
    description_ = description;
}

bool ServiceInfo::Marshalling(MessageParcel& parcel) const
{
    WRITE_HELPER(parcel, String, udid_);
    WRITE_HELPER(parcel, Int32, userId_);
    WRITE_HELPER(parcel, Int64, displayId_);
    WRITE_HELPER(parcel, Int32, serviceOwnerTokenId_);
    WRITE_HELPER(parcel, String, serviceOwnerPkgName_);
    WRITE_HELPER(parcel, Int32, serviceRegisterTokenId_);
    WRITE_HELPER(parcel, Int64, serviceId_);
    WRITE_HELPER(parcel, Int64, timeStamp_);
    WRITE_HELPER(parcel, Int8, publishState_);
    WRITE_HELPER(parcel, String, serviceType_);
    WRITE_HELPER(parcel, String, serviceName_);
    WRITE_HELPER(parcel, String, serviceDisplayName_);
    WRITE_HELPER(parcel, String, customData_);
    WRITE_HELPER(parcel, String, serviceCode_);
    WRITE_HELPER(parcel, Uint32, dataLen_);
    WRITE_HELPER(parcel, String, extraData_);
    WRITE_HELPER(parcel, String, version_);
    WRITE_HELPER(parcel, String, description_);

    return true;
}

bool ServiceInfo::UnMarshalling(MessageParcel& parcel)
{
    READ_HELPER_RET(parcel, String, udid_, false);
    READ_HELPER_RET(parcel, Int32, userId_, false);
    READ_HELPER_RET(parcel, Int64, displayId_, false);
    READ_HELPER_RET(parcel, Int32, serviceOwnerTokenId_, false);
    READ_HELPER_RET(parcel, String, serviceOwnerPkgName_, false);
    READ_HELPER_RET(parcel, Int32, serviceRegisterTokenId_, false);
    READ_HELPER_RET(parcel, Int64, serviceId_, false);
    READ_HELPER_RET(parcel, Int64, timeStamp_, false);
    READ_HELPER_RET(parcel, Int8, publishState_, false);
    READ_HELPER_RET(parcel, String, serviceType_, false);
    READ_HELPER_RET(parcel, String, serviceName_, false);
    READ_HELPER_RET(parcel, String, serviceDisplayName_, false);
    READ_HELPER_RET(parcel, String, customData_, false);
    READ_HELPER_RET(parcel, String, serviceCode_, false);
    READ_HELPER_RET(parcel, Uint32, dataLen_, false);
    READ_HELPER_RET(parcel, String, extraData_, false);
    READ_HELPER_RET(parcel, String, version_, false);
    READ_HELPER_RET(parcel, String, description_, false);

    return true;
}

std::string ServiceInfo::dump() const
{
    cJSON* json = cJSON_CreateObject();
    if (!cJSON_IsObject(json)) {
        cJSON_Delete(json);
        return EMPTY_STRING;
    }

    cJSON_AddStringToObject(json, UD_ID.c_str(), ProfileUtils::GetAnonyString(udid_.c_str()).c_str());
    cJSON_AddNumberToObject(json, USERID.c_str(), userId_);
    cJSON_AddStringToObject(json, DISPLAYID.c_str(), std::to_string(displayId_).c_str());
    cJSON_AddNumberToObject(json, SERVICE_OWNER_TOKEN_ID.c_str(), serviceOwnerTokenId_);
    cJSON_AddStringToObject(
        json, SERVICE_OWNER_PKG_NAME.c_str(), ProfileUtils::GetAnonyString(serviceOwnerPkgName_.c_str()).c_str());
    cJSON_AddNumberToObject(json, SERVICE_REGISTER_TOKEN_ID.c_str(), serviceRegisterTokenId_);
    cJSON_AddStringToObject(json, SERVICEID.c_str(), ProfileUtils::GetAnonyString(std::to_string(serviceId_)).c_str());
    cJSON_AddStringToObject(json, TIME_STAMP.c_str(), std::to_string(timeStamp_).c_str());
    cJSON_AddNumberToObject(json, PUBLISH_STATE.c_str(), publishState_);
    cJSON_AddStringToObject(json, SERVICE_TYPE.c_str(), serviceType_.c_str());
    cJSON_AddStringToObject(json, SERVICE_NAME.c_str(), serviceName_.c_str());
    cJSON_AddStringToObject(
        json, SERVICE_DISPLAY_NAME.c_str(), ProfileUtils::GetAnonyString(serviceDisplayName_.c_str()).c_str());
    cJSON_AddStringToObject(json, CUSTOM_DATA.c_str(), ProfileUtils::GetAnonyString(customData_.c_str()).c_str());
    cJSON_AddStringToObject(json, SERVICE_CODE.c_str(), serviceCode_.c_str());
    cJSON_AddNumberToObject(json, DATA_LEN.c_str(), dataLen_);
    cJSON_AddStringToObject(json, EXTRA_DATA.c_str(), ProfileUtils::GetAnonyString(extraData_.c_str()).c_str());
    cJSON_AddStringToObject(json, VERSION.c_str(), version_.c_str());
    cJSON_AddStringToObject(json, DESCRIPTION.c_str(), description_.c_str());

    char* jsonChars = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    if (jsonChars == NULL) {
        HILOGE("cJSON formatted to string failed!");
        return EMPTY_STRING;
    }
    std::string jsonStr = jsonChars;
    cJSON_free(jsonChars);
    return jsonStr;
}
} // namespace DistributedDeviceProfile
} // namespace OHOS