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

#include "profile_data_manager.h"

#include "device_profile_manager.h"
#include "device_icon_info_dao.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"
#include "multi_user_manager.h"
#include "product_info_dao.h"
#include "profile_cache.h"
#include "profile_utils.h"
#include "settings_data_manager.h"
#include "content_sensor_manager_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {
IMPLEMENT_SINGLE_INSTANCE(ProfileDataManager)

namespace {
const std::string TAG = "ProfileDataManager";
}

int32_t ProfileDataManager::Init()
{
    if (DeviceProfileDao::GetInstance().Init() != DP_SUCCESS) {
        HILOGE("DeviceProfileDao init failed");
        return DP_DEVICE_PROFILE_DAO_INIT_FAIL;
    }
    if (ProductInfoDao::GetInstance().Init() != DP_SUCCESS) {
        HILOGE("ProductInfoDao init failed");
        return DP_PRODUCT_INFO_DAO_INIT_FAIL;
    }
    if (DeviceIconInfoDao::GetInstance().Init() != DP_SUCCESS) {
        HILOGE("DeviceIconInfoDao init failed");
        return DP_DEVICE_ICON_INFO_DAO_INIT_FAIL;
    }
    if (SettingsDataManager::GetInstance().Init() != DP_SUCCESS) {
        HILOGE("SettingsDataManager init failed");
        return DP_SETTINGSDATA_MANAGER_INIT_FAIL;
    }
    return DP_SUCCESS;
}

int32_t ProfileDataManager::UnInit()
{
    if (DeviceProfileDao::GetInstance().UnInit() != DP_SUCCESS) {
        HILOGE("DeviceProfileDao unInit failed");
        return DP_DEVICE_PROFILE_DAO_UNINIT_FAIL;
    }
    if (ProductInfoDao::GetInstance().UnInit() != DP_SUCCESS) {
        HILOGE("ProductInfoDao unInit failed");
        return DP_PRODUCT_INFO_DAO_UNINIT_FAIL;
    }
    if (DeviceIconInfoDao::GetInstance().UnInit() != DP_SUCCESS) {
        HILOGE("DeviceIconInfoDao unInit failed");
        return DP_DEVICE_ICON_INFO_DAO_UNINIT_FAIL;
    }
    if (SettingsDataManager::GetInstance().UnInit() != DP_SUCCESS) {
        HILOGE("SettingsDataManager unInit failed");
        return DP_SETTINGSDATA_MANAGER_UNINIT_FAIL;
    }
    return 0;
}
    
int32_t ProfileDataManager::PutDeviceProfile(DeviceProfile deviceProfile)
{
    if (deviceProfile.GetDeviceId().empty() || ProfileDataManager::FilterInvaildSymbol(deviceProfile.GetDeviceId())) {
        HILOGE("deviceId invaild,deviceId=%{public}s",
            ProfileUtils::GetAnonyString(deviceProfile.GetDeviceId()).c_str());
        return DP_INVALID_PARAMS;
    }
    deviceProfile.SetUserId(MultiUserManager::GetInstance().GetCurrentForegroundUserID());
    deviceProfile.SetAccountId(ProfileCache::GetInstance().GetLocalAccountId());
    DeviceProfileFilterOptions filterOptions;
    filterOptions.AddDeviceIds(deviceProfile.GetDeviceId());
    filterOptions.SetUserId(deviceProfile.GetUserId());
    std::vector<DeviceProfile> oldDeviceProfiles;
    int32_t ret = RET_INIT;
    ret = DeviceProfileDao::GetInstance().GetDeviceProfiles(filterOptions, oldDeviceProfiles);
    if ((ret != DP_SUCCESS) && (ret != DP_NOT_FIND_DATA)) {
        HILOGE("GetDeviceProfiles failed,ret=%{public}d", ret);
        return ret;
    }
    if (oldDeviceProfiles.empty()) {
        HILOGI("oldDeviceProfiles is mepty");
        deviceProfile.SetId(DEFAULT_ID);
    } else {
        DeviceProfile oldDeviceProfile = oldDeviceProfiles[0];
        deviceProfile.SetId(oldDeviceProfile.GetId());
    }
    if (deviceProfile.GetId() <= 0) {
        ret = DeviceProfileDao::GetInstance().PutDeviceProfile(deviceProfile);
    } else {
        ret = DeviceProfileDao::GetInstance().UpdateDeviceProfile(deviceProfile);
    }
    if (ret != DP_SUCCESS) {
        HILOGE("PutDeviceProfile failed,ret=%{public}d", ret);
        return ret;
    }
    return DP_SUCCESS;
}

bool ProfileDataManager::FilterInvaildSymbol(std::string str)
{
    if (str.length() == 0 || str.length() > MAX_STRING_LEN) {
        return false;
    }
    size_t found = str.find(SEPARATOR);
    if (found == std::string::npos) {
        return false;
    }
    size_t foundSlashes = str.find(SLASHES);
    if (foundSlashes == std::string::npos) {
        return false;
    }
    return true;
}

int32_t ProfileDataManager::PutDeviceProfileBatch(std::vector<DeviceProfile>& deviceProfiles)
{
    if (deviceProfiles.empty()) {
        HILOGE("deviceProfiles is empty");
        return DP_INVALID_PARAM;
    }
    int32_t ret = RET_INIT;
    for (auto deviceProfile : deviceProfiles) {
        int32_t putRet = PutDeviceProfile(deviceProfile);
        if (ret != DP_SUCCESS) {
            ret = putRet;
        }
    }
    if (ret != DP_SUCCESS) {
        HILOGE("PutDeviceProfiles failed,ret=%{public}d", ret);
        return ret;
    }
    return DP_SUCCESS;
}

int32_t ProfileDataManager::GetDeviceProfiles(DeviceProfileFilterOptions& options,
    std::vector<DeviceProfile>& deviceProfiles)
{
    int32_t localUserId = MultiUserManager::GetInstance().GetCurrentForegroundUserID();
    options.SetUserId(localUserId);
    int32_t ret = DeviceProfileDao::GetInstance().GetDeviceProfiles(options, deviceProfiles);
    if (ret != DP_SUCCESS) {
        HILOGE("GetDeviceProfile failed,ret=%{public}d", ret);
        return ret;
    }
    if (deviceProfiles.empty()) {
        HILOGE("GetDeviceProfile failed,deviceProfiles is empty");
        return DP_DEVICE_PROFILE_NOT_FOUND;
    }
    return DP_SUCCESS;
}

int32_t ProfileDataManager::GetDeviceIconInfos(const DeviceIconInfoFilterOptions& filterOptions,
    std::vector<DeviceIconInfo>& deviceIconInfos)
{
    if (filterOptions.GetProductIds().empty() || filterOptions.GetSubProductId().empty() ||
        filterOptions.GetImageType().empty() || filterOptions.GetSpecName().empty()) {
        HILOGE("Invalid parameter");
        return DP_INVALID_PARAM;
    }
    int32_t ret = DeviceIconInfoDao::GetInstance().GetDeviceIconInfos(filterOptions, deviceIconInfos);
    if (ret != DP_SUCCESS) {
        HILOGE("GetDeviceIconInfos failed,ret=%{public}d", ret);
        return ret;
    }
    return DP_SUCCESS;
}

int32_t ProfileDataManager::PutDeviceIconInfoBatch(const std::vector<DeviceIconInfo>& deviceIconInfos)
{
    if (deviceIconInfos.empty()) {
        HILOGE("ProductInfos is empty");
        return DP_INVALID_PARAM;
    }
    for (auto &deviceIconInfo : deviceIconInfos) {
        int32_t ret = PutDeviceIconInfo(deviceIconInfo);
        if (ret != DP_SUCCESS) {
            HILOGE("PutDeviceIconInfo is failed,ret=%{public}d", ret);
            return ret;
        }
    }
    return DP_SUCCESS;
}

int32_t ProfileDataManager::PutDeviceIconInfo(const DeviceIconInfo& deviceIconInfo)
{
    DeviceIconInfoFilterOptions filterOptions;
    std::vector<std::string> productIds;
    productIds.emplace_back(deviceIconInfo.GetProductId());
    filterOptions.SetProductIds(productIds);
    filterOptions.SetSubProductId(deviceIconInfo.GetSubProductId());
    filterOptions.SetImageType(deviceIconInfo.GetImageType());
    filterOptions.SetSpecName(deviceIconInfo.GetSpecName());
    std::vector<DeviceIconInfo> deviceIconInfos;
    int32_t ret = DeviceIconInfoDao::GetInstance().GetDeviceIconInfos(filterOptions, deviceIconInfos);
    if ((ret != DP_SUCCESS) && (ret != DP_NOT_FIND_DATA)) {
        HILOGE("GetDeviceIconInfos failed,ret=%{public}d", ret);
        return ret;
    }
    if (deviceIconInfos.empty()) {
        ret = DeviceIconInfoDao::GetInstance().PutDeviceIconInfo(deviceIconInfo);
    } else {
        DeviceIconInfo updateDeviceIconInfo = deviceIconInfo;
        updateDeviceIconInfo.SetId(deviceIconInfos[0].GetId());
        ret = DeviceIconInfoDao::GetInstance().UpdateDeviceIconInfo(updateDeviceIconInfo);
    }
    if (ret != DP_SUCCESS) {
        HILOGE("PutDeviceIconInfo failed,ret=%{public}d", ret);
        return ret;
    }
    return DP_SUCCESS;
}

int32_t ProfileDataManager::PutProductInfoBatch(const std::vector<ProductInfo>& productInfos)
{
    if (productInfos.empty()) {
        HILOGE("ProductInfos is empty");
        return DP_INVALID_PARAM;
    }
    for (auto &productInfo : productInfos) {
        int32_t ret = PutProductInfo(productInfo);
        if (ret != DP_SUCCESS) {
            HILOGE("PutProductInfo is failed,ret=%{public}d", ret);
            return ret;
        }
    }
    return DP_SUCCESS;
}

int32_t ProfileDataManager::PutProductInfo(const ProductInfo& productInfo)
{
    if (productInfo.GetProductId().empty()) {
        HILOGE("ProductId is nullptr");
        return DP_INVALID_PARAM;
    }
    std::vector<std::string> productIds;
    productIds.emplace_back(productInfo.GetProductId());
    std::vector<ProductInfo> productInfos;
    int32_t ret = ProductInfoDao::GetInstance().GetProductInfos(productIds, productInfos);
    if ((ret != DP_SUCCESS) && (ret != DP_NOT_FIND_DATA)) {
        HILOGE("GetProductInfos failed,ret=%{public}d", ret);
        return ret;
    }
    if (productInfos.empty()) {
        ret = ProductInfoDao::GetInstance().PutProductInfo(productInfo);
    } else {
        ret = ProductInfoDao::GetInstance().UpdateProductInfo(productInfo);
    }
    if (ret != DP_SUCCESS) {
        HILOGE("PutProductInfo failed,ret=%{public}d", ret);
        return ret;
    }
    return DP_SUCCESS;
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
