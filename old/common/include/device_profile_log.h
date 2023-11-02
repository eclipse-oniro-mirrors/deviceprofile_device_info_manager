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

#ifndef OHOS_DEVICE_PROFILE_LOG_H
#define OHOS_DEVICE_PROFILE_LOG_H

#include "hilog/log.h"

namespace OHOS {
namespace DeviceProfile {
static constexpr OHOS::HiviewDFX::HiLogLabel DP_LOG_LABEL = {
    LOG_CORE,
    0xD004400,
    "Device_Profile"
};

#ifdef HILOGF
#undef HILOGF
#endif
#ifdef HILOGE
#undef HILOGE
#endif
#ifdef HILOGW
#undef HILOGW
#endif
#ifdef HILOGI
#undef HILOGI
#endif
#ifdef HILOGD
#undef HILOGD
#endif

#define DP_LOG(level, fmt, ...) \
    HiviewDFX::HiLog::level(DP_LOG_LABEL, "%{public}s::%{public}s " fmt, TAG.c_str(), __FUNCTION__, ##__VA_ARGS__)

#define HILOGF(fmt, ...) DP_LOG(Fatal, fmt, ##__VA_ARGS__)
#define HILOGE(fmt, ...) DP_LOG(Error, fmt, ##__VA_ARGS__)
#define HILOGW(fmt, ...) DP_LOG(Warn,  fmt, ##__VA_ARGS__)
#define HILOGI(fmt, ...) DP_LOG(Info,  fmt, ##__VA_ARGS__)
#define HILOGD(fmt, ...) DP_LOG(Debug, fmt, ##__VA_ARGS__)
} // namespace DeviceProfile
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_DP_DATA_CHANGE_LISTENER_H
