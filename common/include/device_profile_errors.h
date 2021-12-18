/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_DEVICE_PROFILE_ERRORS_H
#define OHOS_DEVICE_PROFILE_ERRORS_H

#include "errors.h"

namespace OHOS {
namespace DeviceProfile {
enum {
    DEVICE_PROFILE_MODULE_DDP = 0,
};

constexpr ErrCode DEVICE_PROFILE_ERR_OFFSET = ErrCodeOffset(SUBSYS_DEVICEPROFILE, DEVICE_PROFILE_MODULE_DDP);

enum {
    // DEVICE_PROFILE_ERR_OFFSET(98566143)
    ERR_DP_INVALID_PARAMS = 98566144,
    ERR_DP_INTERFACE_CHECK_FAILED = 98566145,
    ERR_DP_GET_LOCAL_UDID_FAILED = 98566146,
    ERR_DP_GET_SERVICE_FAILED = 98566147,
    ERR_DP_INIT_DB_FAILED = 98566148,
};
} // namespace DeviceProfile
} // namespace OHOS
#endif // OHOS_DEVICE_PROFILE_ERRORS_H
