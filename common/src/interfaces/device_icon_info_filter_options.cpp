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

#include "device_icon_info_filter_options.h"

#include "cJSON.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_log.h"
#include "ipc_utils.h"
#include "macro_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "DeviceIconInfoFilterOptions";
    const std::string PRODUCT_IDS = "productIds";
}

std::vector<std::string> DeviceIconInfoFilterOptions::GetProductIds() const
{
    return productIds_;
}

void DeviceIconInfoFilterOptions::SetProductIds(const std::vector<std::string>& productIds)
{
    productIds_ = productIds;
}

std::string DeviceIconInfoFilterOptions::GetInternalModel() const
{
    return internalModel_;
}

void DeviceIconInfoFilterOptions::SetInternalModel(const std::string& internalModel)
{
    internalModel_ = internalModel;
}

std::string DeviceIconInfoFilterOptions::GetSubProductId() const
{
    return subProductId_;
}

void DeviceIconInfoFilterOptions::SetSubProductId(const std::string& subProductId)
{
    subProductId_ = subProductId;
}

std::string DeviceIconInfoFilterOptions::GetImageType() const
{
    return imageType_;
}

void DeviceIconInfoFilterOptions::SetImageType(const std::string& imageType)
{
    imageType_ = imageType;
}

std::string DeviceIconInfoFilterOptions::GetSpecName() const
{
    return specName_;
}

void DeviceIconInfoFilterOptions::SetSpecName(const std::string& specName)
{
    specName_ = specName;
}

bool DeviceIconInfoFilterOptions::Marshalling(MessageParcel& parcel) const
{
    IpcUtils::Marshalling(parcel, productIds_);
    WRITE_HELPER_RET(parcel, String, internalModel_, false);
    WRITE_HELPER_RET(parcel, String, subProductId_, false);
    WRITE_HELPER_RET(parcel, String, imageType_, false);
    WRITE_HELPER_RET(parcel, String, specName_, false);
    return true;
}

bool DeviceIconInfoFilterOptions::UnMarshalling(MessageParcel& parcel)
{
    IpcUtils::UnMarshalling(parcel, productIds_);
    READ_HELPER_RET(parcel, String, internalModel_, false);
    READ_HELPER_RET(parcel, String, subProductId_, false);
    READ_HELPER_RET(parcel, String, imageType_, false);
    READ_HELPER_RET(parcel, String, specName_, false);
    return true;
}

std::string DeviceIconInfoFilterOptions::dump() const
{
    cJSON* json = cJSON_CreateObject();
    if (json == NULL) {
        HILOGE("cJSON CreateObject failed!");
        return EMPTY_STRING;
    }
    cJSON* prodIdsJson = cJSON_CreateArray();
    if (prodIdsJson == NULL) {
        cJSON_Delete(json);
        HILOGE("cJSON CreateArray failed!");
        return EMPTY_STRING;
    }
    for (const auto& value : productIds_) {
        cJSON* arrItem = cJSON_CreateString(value.c_str());
        if (arrItem == NULL) {
            HILOGW("cJSON CreateString failed!");
            continue;
        }
        if (!cJSON_AddItemToArray(prodIdsJson, arrItem)) {
            cJSON_Delete(arrItem);
            HILOGW("Add item to array failed!");
            continue;
        }
    }
    if (!cJSON_AddItemToObject(json, PRODUCT_IDS.c_str(), prodIdsJson)) {
        cJSON_Delete(prodIdsJson);
        HILOGW("Add json array to Object failed!");
    }
    cJSON_AddStringToObject(json, INTERNAL_MODEL.c_str(), internalModel_.c_str());
    cJSON_AddStringToObject(json, SUB_PRODUCT_ID.c_str(), subProductId_.c_str());
    cJSON_AddStringToObject(json, IMAGE_TYPE.c_str(), imageType_.c_str());
    cJSON_AddStringToObject(json, SPEC_NAME.c_str(), specName_.c_str());
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
