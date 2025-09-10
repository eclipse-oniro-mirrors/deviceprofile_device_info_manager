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
 
#include "service_info_profile_new.h"
#include "cJSON.h"
#include "distributed_device_profile_constants.h"
#include "macro_utils.h"
#include "profile_utils.h"
 
namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "ServiceInfoProfileNew";
}
 
ServiceInfoProfileNew::~ServiceInfoProfileNew()
{
}
 
int64_t ServiceInfoProfileNew::GetServiceId() const
{
    return serviceId_;
}
 
void ServiceInfoProfileNew::SetServiceId(const int64_t serviceId)
{
    serviceId_ = serviceId;
}
 
std::string ServiceInfoProfileNew::GetServiceType() const
{
    return serviceType_;
}
 
void ServiceInfoProfileNew::SetServiceType(const std::string& serviceType)
{
    serviceType_ = serviceType;
}

std::string ServiceInfoProfileNew::GetServiceName() const
{
    return serviceName_;
}
 
void ServiceInfoProfileNew::SetServiceName(const std::string &serviceName)
{
    serviceName_ = serviceName;
}
 
std::string ServiceInfoProfileNew::GetServiceDisplayName() const
{
    return serviceDisplayName_;
}
 
void ServiceInfoProfileNew::SetServiceDisplayName(const std::string &serviceDisplayName)
{
    serviceDisplayName_ = serviceDisplayName;
}
 
int32_t ServiceInfoProfileNew::GetRegServiceId() const
{
    return regServiceId_;
}
 
void ServiceInfoProfileNew::SetRegServiceId(const int32_t &regServiceId)
{
    regServiceId_ = regServiceId;
}
 
int8_t ServiceInfoProfileNew::GetSerPubState() const
{
    return servicePubState_;
}
 
void ServiceInfoProfileNew::SetSerPubState(const int8_t &serPubState)
{
    servicePubState_ = serPubState;
}
 
std::string ServiceInfoProfileNew::GetDeviceId() const
{
    return deviceId_;
}

void ServiceInfoProfileNew::SetDeviceId(const std::string &deviceId)
{
    deviceId_ = deviceId;
}

int32_t ServiceInfoProfileNew::GetUserId() const
{
    return userId_;
}
void ServiceInfoProfileNew::SetUserId(const int32_t &userId)
{
    userId_ = userId;
}
 
int64_t ServiceInfoProfileNew::GetTokenId() const
{
    return tokenId_;
}
void ServiceInfoProfileNew::SetTokenId(const int64_t &tokenId)
{
    tokenId_ = tokenId;
}
 
bool ServiceInfoProfileNew::Marshalling(MessageParcel& parcel) const
{
    WRITE_HELPER(parcel, Int32, regServiceId_);
    WRITE_HELPER(parcel, String, deviceId_);
    WRITE_HELPER(parcel, Int32, userId_);
    WRITE_HELPER(parcel, Int64, tokenId_);
    WRITE_HELPER(parcel, Int8, servicePubState_);
    WRITE_HELPER(parcel, Int64, serviceId_);
    WRITE_HELPER(parcel, String, serviceType_);
    WRITE_HELPER(parcel, String, serviceName_);
    WRITE_HELPER(parcel, String, serviceDisplayName_);
 
    return true;
}
 
bool ServiceInfoProfileNew::UnMarshalling(MessageParcel& parcel)
{
    READ_HELPER_RET(parcel, Int32, regServiceId_, false);
    READ_HELPER_RET(parcel, String, deviceId_, false);
    READ_HELPER_RET(parcel, Int32, userId_, false);
    READ_HELPER_RET(parcel, Int64, tokenId_, false);
    READ_HELPER_RET(parcel, Int8, servicePubState_, false);
    READ_HELPER_RET(parcel, Int64, serviceId_, false);
    READ_HELPER_RET(parcel, String, serviceType_, false);
    READ_HELPER_RET(parcel, String, serviceName_, false);
    READ_HELPER_RET(parcel, String, serviceDisplayName_, false);
 
    return true;
}
 
std::string ServiceInfoProfileNew::dump() const
{
    cJSON* json = cJSON_CreateObject();
    if (!cJSON_IsObject(json)) {
        cJSON_Delete(json);
        return EMPTY_STRING;
    }
    cJSON_AddStringToObject(json, DEVICE_ID.c_str(), ProfileUtils::GetAnonyString(deviceId_).c_str());
 
    cJSON_AddStringToObject(json, USERID.c_str(), std::to_string(userId_).c_str());
 
    cJSON_AddStringToObject(json, TOKENID.c_str(), std::to_string(tokenId_).c_str());
 
    cJSON_AddStringToObject(json, PUBLISH_STATE.c_str(), std::to_string(servicePubState_).c_str());
 
    cJSON_AddStringToObject(json, SISERVICE_ID.c_str(), std::to_string(serviceId_).c_str());
 
    cJSON_AddStringToObject(json, SERVICE_TYPE.c_str(), serviceType_.c_str());
 
    cJSON_AddStringToObject(json, SERVICE_NAME.c_str(), serviceName_.c_str());
    
    cJSON_AddStringToObject(json, SERVICE_DISPLAY_NAME.c_str(),
        ProfileUtils::GetAnonyString(serviceDisplayName_).c_str());
        char* jsonChars = cJSON_PrintUnformatted(json);
    if (jsonChars == NULL) {
        cJSON_Delete(json);
        HILOGE("cJSON formatted to string failed!");
        return EMPTY_STRING;
    }
    std::string jsonStr = jsonChars;
    cJSON_Delete(json);
    cJSON_free(jsonChars);
    return jsonStr;
}
} // namespace DistributedDeviceProfile
} // namespace OHOS