/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_DP_DEVICE_PROFILE_LOG_H
#define OHOS_DP_DEVICE_PROFILE_LOG_H

#ifndef LOG_TAG
#define LOG_TAG "DHDP"
#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD004400
#endif
#include "hilog/log.h"
#include "log_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {

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

#define HILOGF(fmt, ...) HILOG_FATAL(LOG_CORE, "[%{public}d] %{public}s::%{public}s " fmt, LogUtils::LogCounter(), \
    TAG.c_str(), __FUNCTION__, ##__VA_ARGS__)
#define HILOGE(fmt, ...) HILOG_ERROR(LOG_CORE, "[%{public}d] %{public}s::%{public}s " fmt, LogUtils::LogCounter(), \
    TAG.c_str(), __FUNCTION__, ##__VA_ARGS__)
#define HILOGW(fmt, ...) HILOG_WARN(LOG_CORE, "[%{public}d] %{public}s::%{public}s " fmt, LogUtils::LogCounter(), \
    TAG.c_str(), __FUNCTION__, ##__VA_ARGS__)
#define HILOGI(fmt, ...) HILOG_INFO(LOG_CORE, "[%{public}d] %{public}s::%{public}s " fmt, LogUtils::LogCounter(), \
    TAG.c_str(), __FUNCTION__, ##__VA_ARGS__)
#define HILOGD(fmt, ...) HILOG_DEBUG(LOG_CORE, "[%{public}d] %{public}s::%{public}s " fmt, LogUtils::LogCounter(), \
    TAG.c_str(), __FUNCTION__, ##__VA_ARGS__)
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // OHOS_DP_DEVICE_PROFILE_LOG_H
