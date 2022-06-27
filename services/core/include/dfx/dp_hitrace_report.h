/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_DEVICEPROFILE_HITRACE_REPORT_H
#define OHOS_DEVICEPROFILE_HITRACE_REPORT_H

#include <string>

#include "hitrace_meter.h"

namespace OHOS {
namespace DeviceProfile {
namespace {
    const std::string DP_DEVICE_PUT_TRACE = "DP_DEVICE_PUT";
    const std::string DP_DEVICE_GET_TRACE = "DP_DEVICE_GET";
    const std::string DP_DEVICE_DELETE_TRACE = "DP_DEVICE_DELETE";
    const std::string DP_DEVICE_SYNC_TRACE = "DP_DEVICE_SYNC";
    const std::string DP_DEVICE_SUB_TRACE = "DP_DEVICE_SUB";
    const std::string DP_CONTENT_SENSOR_TRACE = "DP_CONTENT_SENSOR";
}
} // namespace DeviceProfile
} // namespace OHOS

#endif /* OHOS_DEVICEPROFILE_HITRACE_REPORT_H */