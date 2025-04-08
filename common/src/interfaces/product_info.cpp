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

#include "product_info.h"

#include "cJSON.h"
#include "distributed_device_profile_constants.h"
#include "macro_utils.h"
#include "profile_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "ProductInfo";
}

std::string ProductInfo::GetProductId() const
{
    return productId_;
}

void ProductInfo::SetProductId(const std::string& productId)
{
    this->productId_ = productId;
}

std::string ProductInfo::GetModel() const
{
    return model_;
}

void ProductInfo::SetModel(const std::string& model)
{
    this->model_ = model;
}

std::string ProductInfo::GetProductName() const
{
    return productName_;
}

void ProductInfo::SetProductName(const std::string& productName)
{
    this->productName_ = productName;
}

std::string ProductInfo::GetProductShortName() const
{
    return productShortName_;
}

void ProductInfo::SetProductShortName(const std::string& productShortName)
{
    this->productShortName_ = productShortName;
}

std::string ProductInfo::GetImageVersion() const
{
    return imageVersion_;
}

void ProductInfo::SetImageVersion(const std::string& imageVersion)
{
    this->imageVersion_ = imageVersion;
}


bool ProductInfo::Marshalling(MessageParcel& parcel) const
{
    WRITE_HELPER_RET(parcel, String, productId_, false);
    WRITE_HELPER_RET(parcel, String, model_, false);
    WRITE_HELPER_RET(parcel, String, productName_, false);
    WRITE_HELPER_RET(parcel, String, productShortName_, false);
    WRITE_HELPER_RET(parcel, String, imageVersion_, false);
    return true;
}

bool ProductInfo::UnMarshalling(MessageParcel& parcel)
{
    READ_HELPER_RET(parcel, String, productId_, false);
    READ_HELPER_RET(parcel, String, model_, false);
    READ_HELPER_RET(parcel, String, productName_, false);
    READ_HELPER_RET(parcel, String, productShortName_, false);
    READ_HELPER_RET(parcel, String, imageVersion_, false);
    return true;
}

bool ProductInfo::operator!=(const ProductInfo& other) const
{
    bool isNotEqual = (productId_ != other.GetProductId() || model_ != other.GetModel() ||
        productName_ != other.GetProductName() || productShortName_ != other.GetProductShortName() ||
        imageVersion_ != other.GetImageVersion());
    if (isNotEqual) {
        return true;
    } else {
        return false;
    }
}

std::string ProductInfo::dump() const
{
    cJSON* json = cJSON_CreateObject();
    if (json == NULL) {
        return EMPTY_STRING;
    }
    cJSON_AddStringToObject(json, PRODUCT_ID.c_str(), productId_.c_str());
    cJSON_AddStringToObject(json, DEVICE_MODEL.c_str(), model_.c_str());
    cJSON_AddStringToObject(json, PRODUCT_NAME.c_str(), GetAnonyProductName(productName_).c_str());
    cJSON_AddStringToObject(json, PRODUCT_SHORT_NAME.c_str(), GetAnonyProductName(productShortName_).c_str());
    cJSON_AddStringToObject(json, IMAGE_VERSION.c_str(), imageVersion_.c_str());
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

std::string ProductInfo::GetAnonyProductName(const std::string& productName) const
{
    cJSON* json = cJSON_Parse(productName.c_str());
    if (!cJSON_IsObject(json)) {
        HILOGW("cJSON_Parse productName fail!");
        cJSON_Delete(json);
        return EMPTY_STRING;
    }
    cJSON* item = json->child;
    while (item != NULL) {
        if (cJSON_IsString(item)) {
            cJSON_SetValuestring(item, ProfileUtils::GetAnonyString(item->valuestring).c_str());
        }
        item = item->next;
    }
    char* jsonChars = cJSON_PrintUnformatted(json);
    if (jsonChars == NULL) {
        cJSON_Delete(json);
        HILOGE("cJSON formatted to string failed!");
        return EMPTY_STRING;
    }
    std::string jsonStr = jsonChars;
    cJSON_free(jsonChars);
    cJSON_Delete(json);
    return jsonStr;
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
