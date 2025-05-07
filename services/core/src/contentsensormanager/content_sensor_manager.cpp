/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "content_sensor_manager.h"

#include <list>
#include <vector>
#include <memory>
#include <thread>
#include "collaboration_info_collector.h"
#include "collector.h"
#include "content_sensor_manager_utils.h"
#include "device_profile_filter_options.h"
#include "device_profile_manager.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"
#include "dms_info_collector.h"
#include "multi_user_manager.h"
#include "pasteboard_info_collector.h"
#include "profile_data_manager.h"
#include "profile_cache.h"
#include "switch_status_collector.h"
#include "syscap_info_collector.h"
#include "system_info_collector.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "ContentSensorManager";
}

IMPLEMENT_SINGLE_INSTANCE(ContentSensorManager);

int32_t ContentSensorManager::Init()
{
    HILOGI("call!");
    return Collect();
}

int32_t ContentSensorManager::UnInit()
{
    HILOGI("ContentSensorManager UnInit");
    return DP_SUCCESS;
}

int32_t ContentSensorManager::Collect()
{
    auto csTask = [this]() {
        HILOGI("ContentSensorManager Collect");
        std::list<std::shared_ptr<Collector>> taskList;
        taskList.push_back(std::make_shared<SystemInfoCollector>());
        taskList.push_back(std::make_shared<SyscapInfoCollector>());
        taskList.push_back(std::make_shared<DmsInfoCollector>());
        taskList.push_back(std::make_shared<CollaborationInfoCollector>());
        taskList.push_back(std::make_shared<PasteboardInfoCollector>());
        taskList.push_back(std::make_shared<SwitchStatusCollector>());
        DeviceProfile deviceProfile;
        std::vector<ServiceProfile> svrProfileList;
        std::vector<CharacteristicProfile> charProfileList;
        for (const auto& task : taskList) {
            task->ConvertToProfile(deviceProfile);
            task->ConvertToProfile(svrProfileList);
            task->ConvertToProfile(charProfileList);
        }
        deviceProfile.SetDeviceId(ContentSensorManagerUtils::GetInstance().ObtainLocalUdid());
        DeviceProfileManager::GetInstance().PutDeviceProfile(deviceProfile);
        CollectInfoToProfileData(deviceProfile);
        if (!svrProfileList.empty()) {
            DeviceProfileManager::GetInstance().PutServiceProfileBatch(svrProfileList);
        } else {
            HILOGI("svrProfileList is empty");
        }
        if (!charProfileList.empty()) {
            DeviceProfileManager::GetInstance().PutCharacteristicProfileBatch(charProfileList);
        } else {
            HILOGI("charProfileList is empty");
        }
    };
    std::thread csTaskThread(csTask);
    if (!csTaskThread.joinable()) {
        HILOGE("csTaskThread joinable is false");
        return DP_CONTENT_SENSOR_MANAGER_INIT_FAIL;
    }
    csTaskThread.join();
    return DP_SUCCESS;
}

int32_t ContentSensorManager::CollectInfoToProfileData(DeviceProfile& collectProfile)
{
    int32_t userID = MultiUserManager::GetInstance().GetCurrentForegroundUserID();
    if (userID == DEFAULT_USER_ID) {
        userID = U_100;
    }
    collectProfile.SetUserId(userID);
    collectProfile.SetAccountId(ProfileCache::GetInstance().GetLocalAccountId());
    DeviceProfileFilterOptions devFilterOptions;
    devFilterOptions.AddDeviceIds(collectProfile.GetDeviceId());
    devFilterOptions.SetUserId(collectProfile.GetUserId());
    std::vector<DeviceProfile> oldDeviceProfiles;
    int32_t ret = DeviceProfileDao::GetInstance().GetDeviceProfiles(devFilterOptions, oldDeviceProfiles);
    if ((ret != DP_SUCCESS) && (ret != DP_NOT_FIND_DATA)) {
        HILOGE("GetDeviceProfiles failed,ret=%{public}d", ret);
        return ret;
    }
    if (!oldDeviceProfiles.empty()) {
        DeviceProfile oldDeviceProfile = oldDeviceProfiles[0];
        collectProfile.SetWiseDeviceId(oldDeviceProfile.GetWiseDeviceId());
        collectProfile.SetWiseUserId(oldDeviceProfile.GetWiseUserId());
        collectProfile.SetSetupType(oldDeviceProfile.GetSetupType());
        collectProfile.SetRegisterTime(oldDeviceProfile.GetRegisterTime());
        collectProfile.SetModifyTime(oldDeviceProfile.GetModifyTime());
        collectProfile.SetShareTime(oldDeviceProfile.GetShareTime());
        collectProfile.SetInternalModel(oldDeviceProfile.GetInternalModel());
        if (collectProfile.GetAccountId().empty()) {
            collectProfile.SetAccountId(oldDeviceProfile.GetAccountId());
        }
        std::string marketName = ContentSensorManagerUtils::GetInstance().ObtainMarketName();
        if (!oldDeviceProfile.GetDeviceName().empty() && oldDeviceProfile.GetDeviceName() != marketName &&
            collectProfile.GetDeviceName() == collectProfile.GetProductName()) {
            collectProfile.SetDeviceName(oldDeviceProfile.GetDeviceName());
        }
    }
    ret = ProfileDataManager::GetInstance().PutDeviceProfile(collectProfile);
    if (ret != DP_SUCCESS) {
        HILOGE("PutDeviceProfile failed,ret=%{public}d", ret);
        return ret;
    }
    return DP_SUCCESS;
}
} // namespace DeviceProfile
} // namespace OHOS
