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

#ifndef OHOS_DP_CONTENT_SENSOR_MANAGER_UTILS_H
#define OHOS_DP_CONTENT_SENSOR_MANAGER_UTILS_H

#include <atomic>
#include <mutex>
#include <string>
#include "single_instance.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class ContentSensorManagerUtils {
DECLARE_SINGLE_INSTANCE(ContentSensorManagerUtils);
public:
    std::string ObtainProductModel();
    std::string ObtainDeviceType();
    std::string ObtainManufacture();
    std::string ObtainSerial();
    std::string ObtainMarketName();
    std::string ObtainOsFullName();
    std::string ObtainDisplayVersion();
    std::string ObtainLocalUdid();
    std::string ObtainProductId();
    void ObtainDeviceDataSyncMode();
    bool IsDeviceE2ESync();

private:
    std::string deviceModel_ = "";
    std::string deviceType_ = "";
    std::string manufacture_ = "";
    std::string serial_ = "";
    std::string marketName_ = "";
    std::string osFullName_ = "";
    std::string displayVersion_ = "";
    std::string localUdid_ = "";
    std::string productId_ = "";
    std::atomic<bool> isDeviceE2ESync_ {false};
    std::mutex csMutex_;
};
}
}
#endif // OHOS_DP_MANAGER_CONTENT_SENSOR_MANAGER_UTILS_H
