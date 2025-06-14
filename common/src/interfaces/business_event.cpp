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

#include "business_event.h"
#include "cJSON.h"
#include "distributed_device_profile_constants.h"
#include "macro_utils.h"
#include "profile_utils.h"
 
namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "BusinessEvent";
}

BusinessEvent::BusinessEvent()
{
}

BusinessEvent::~BusinessEvent()
{
}

std::string BusinessEvent::GetBusinessKey() const
{
    return businessKey_;
}

void BusinessEvent::SetBusinessKey(const std::string& businessKey)
{
    businessKey_ = businessKey;
}

std::string BusinessEvent::GetBusinessValue() const
{
    return businessValue_;
}

void BusinessEvent::SetBusinessValue(const std::string& businessValue)
{
    businessValue_ = businessValue;
}

bool BusinessEvent::Marshalling(MessageParcel& parcel) const
{
    WRITE_HELPER(parcel, String, businessKey_);
    WRITE_HELPER(parcel, String, businessValue_);
    return true;
}

bool BusinessEvent::UnMarshalling(MessageParcel& parcel)
{
    businessKey_ = parcel.ReadString();
    businessValue_ = parcel.ReadString();
    return true;
}

std::string BusinessEvent::dump() const
{
    cJSON* json = cJSON_CreateObject();
    if (!cJSON_IsObject(json)) {
        cJSON_Delete(json);
        return EMPTY_STRING;
    }
    cJSON_AddStringToObject(json, BUSINESS_KEY.c_str(), businessKey_.c_str());
    cJSON_AddStringToObject(json, BUSINESS_VALUE.c_str(), businessValue_.c_str());
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
 