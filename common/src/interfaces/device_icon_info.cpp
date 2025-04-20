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

#include "device_icon_info.h"

#include "cJSON.h"
#include "distributed_device_profile_constants.h"
#include "ipc_utils.h"
#include "macro_utils.h"
#include "profile_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "DeviceIconInfo";
    const std::string DEVICE_ICON_WISE_VERSION = "wiseVersion";
    const std::string DEVICE_ICON_SIZE = "iconSize";
}

int32_t DeviceIconInfo::GetId() const
{
    return id_;
}

void DeviceIconInfo::SetId(const int32_t id)
{
    this->id_ = id;
}

std::string DeviceIconInfo::GetProductId() const
{
    return productId_;
}

void DeviceIconInfo::SetProductId(const std::string& productId)
{
    this->productId_ = productId;
}

std::string DeviceIconInfo::GetInternalModel() const
{
    return internalModel_;
}

void DeviceIconInfo::SetInternalModel(const std::string& internalModel)
{
    internalModel_ = internalModel;
}

std::string DeviceIconInfo::GetSubProductId() const
{
    return subProductId_;
}

void DeviceIconInfo::SetSubProductId(const std::string& subProductId)
{
    this->subProductId_ = subProductId;
}

std::string DeviceIconInfo::GetImageType() const
{
    return imageType_;
}

void DeviceIconInfo::SetImageType(const std::string& imageType)
{
    this->imageType_ = imageType;
}

std::string DeviceIconInfo::GetSpecName() const
{
    return specName_;
}

void DeviceIconInfo::SetSpecName(const std::string& specName)
{
    this->specName_ = specName;
}

std::string DeviceIconInfo::GetVersion() const
{
    return version_;
}

void DeviceIconInfo::SetVersion(const std::string& version)
{
    version_ = version;
}

std::string DeviceIconInfo::GetWiseVersion() const
{
    return wiseVersion_;
}

void DeviceIconInfo::SetWiseVersion(const std::string& wiseVersion)
{
    wiseVersion_ = wiseVersion;
}

std::string DeviceIconInfo::GetUrl() const
{
    return url_;
}

void DeviceIconInfo::SetUrl(const std::string& url)
{
    url_ = url;
}

std::vector<uint8_t> DeviceIconInfo::GetIcon() const
{
    return icon_;
}

void DeviceIconInfo::SetIcon(const std::vector<uint8_t>& icon)
{
    this->icon_ = icon;
}

bool DeviceIconInfo::Marshalling(MessageParcel& parcel) const
{
    WRITE_HELPER_RET(parcel, String, productId_, false);
    WRITE_HELPER_RET(parcel, String, internalModel_, false);
    WRITE_HELPER_RET(parcel, String, subProductId_, false);
    WRITE_HELPER_RET(parcel, String, imageType_, false);
    WRITE_HELPER_RET(parcel, String, specName_, false);
    WRITE_HELPER_RET(parcel, String, version_, false);
    WRITE_HELPER_RET(parcel, String, wiseVersion_, false);
    WRITE_HELPER_RET(parcel, String, url_, false);
    IpcUtils::Marshalling(parcel, icon_);
    return true;
}

bool DeviceIconInfo::UnMarshalling(MessageParcel& parcel)
{
    READ_HELPER_RET(parcel, String, productId_, false);
    READ_HELPER_RET(parcel, String, internalModel_, false);
    READ_HELPER_RET(parcel, String, subProductId_, false);
    READ_HELPER_RET(parcel, String, imageType_, false);
    READ_HELPER_RET(parcel, String, specName_, false);
    READ_HELPER_RET(parcel, String, version_, false);
    READ_HELPER_RET(parcel, String, wiseVersion_, false);
    READ_HELPER_RET(parcel, String, url_, false);
    IpcUtils::UnMarshalling(parcel, icon_);
    return true;
}

bool DeviceIconInfo::operator!=(const DeviceIconInfo& other) const
{
    bool isNotEqual = (id_ != other.GetId() || productId_ != other.GetProductId() ||
        internalModel_ != other.GetInternalModel() ||
        subProductId_ != other.GetSubProductId() || imageType_ != other.GetImageType() ||
        specName_ != other.GetSpecName() || version_ != other.GetVersion() || wiseVersion_ != other.GetWiseVersion() ||
        url_ != other.GetUrl() || icon_ != other.GetIcon());
    if (isNotEqual) {
        return true;
    } else {
        return false;
    }
}

std::string DeviceIconInfo::dump() const
{
    cJSON* json = cJSON_CreateObject();
    if (json == NULL) {
        return EMPTY_STRING;
    }
    cJSON_AddNumberToObject(json, ID.c_str(), id_);
    cJSON_AddStringToObject(json, PRODUCT_ID.c_str(), productId_.c_str());
    cJSON_AddStringToObject(json, INTERNAL_MODEL.c_str(), internalModel_.c_str());
    cJSON_AddStringToObject(json, SUB_PRODUCT_ID.c_str(), subProductId_.c_str());
    cJSON_AddStringToObject(json, IMAGE_TYPE.c_str(), imageType_.c_str());
    cJSON_AddStringToObject(json, SPEC_NAME.c_str(), specName_.c_str());
    cJSON_AddStringToObject(json, SPEC_NAME.c_str(), specName_.c_str());
    cJSON_AddStringToObject(json, DEVICE_ICON_VERSION.c_str(), version_.c_str());
    cJSON_AddStringToObject(json, DEVICE_ICON_WISE_VERSION.c_str(), wiseVersion_.c_str());
    cJSON_AddStringToObject(json, DEVICE_ICON_URL.c_str(), ProfileUtils::GetAnonyString(url_).c_str());
    cJSON_AddNumberToObject(json, DEVICE_ICON_SIZE.c_str(), icon_.size());
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
