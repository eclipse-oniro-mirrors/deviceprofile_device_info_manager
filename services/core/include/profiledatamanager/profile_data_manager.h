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

#ifndef OHOS_DP_PROFILE_DATA_MANAGER_H
#define OHOS_DP_PROFILE_DATA_MANAGER_H

#include <cstdint>

#include "kvstore_observer.h"

#include "device_icon_info.h"
#include "device_icon_info_filter_options.h"
#include "device_profile.h"
#include "device_profile_dao.h"
#include "product_info.h"
#include "single_instance.h"
namespace OHOS {
namespace DistributedDeviceProfile {
class ProfileDataManager {
    DECLARE_SINGLE_INSTANCE(ProfileDataManager);
public:
    int32_t Init();
    int32_t UnInit();

    int32_t PutDeviceProfileBatch(std::vector<DeviceProfile>& deviceProfiles);
    int32_t DeleteDeviceProfileBatch(std::vector<DeviceProfile>& deviceProfiles);
    int32_t GetDeviceProfiles(DeviceProfileFilterOptions& options,
        std::vector<DeviceProfile>& deviceProfiles);
    int32_t PutProductInfoBatch(const std::vector<ProductInfo>& productInfos);
    int32_t PutDeviceIconInfoBatch(const std::vector<DeviceIconInfo>& deviceIconInfos);
    int32_t GetDeviceIconInfos(const DeviceIconInfoFilterOptions& filterOptions,
        std::vector<DeviceIconInfo>& deviceIconInfos);

    int32_t PutDeviceProfile(DeviceProfile deviceProfile);
private:
    bool FilterInvaildSymbol(std::string str);
    int32_t PutDeviceIconInfo(const DeviceIconInfo& deviceIconInfo);
    int32_t PutProductInfo(const ProductInfo& productInfo);
};
} // DistributedDeviceProfile
} // OHOS
#endif // OHOS_DP_PROFILE_DATA_MANAGER_H
