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

#ifndef OHOS_DP_PROFILE_SWITCH_STATUS_TASK_H
#define OHOS_DP_PROFILE_SWITCH_STATUS_TASK_H

#include <string>
#include "cJSON.h"
#include "collector.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class SwitchStatusCollector : public Collector {
public:
    bool ConvertToProfile(std::vector<CharacteristicProfile>& charProfileList) override;
private:
    int32_t LoadJsonFile(const std::string& filePath, std::string& fileContent);
    int32_t GenerateSwitchProfiles(const cJSON* const staticInfoJson,
        std::vector<CharacteristicProfile> &charProfileList);
    void AddSwitchStatusToDB(std::vector<CharacteristicProfile>& charProfileList);
};
} // namespace DeviceProfile
} // namespace OHOS
#endif // OHOS_DP_PROFILE_SWITCH_STATUS_TASK_H