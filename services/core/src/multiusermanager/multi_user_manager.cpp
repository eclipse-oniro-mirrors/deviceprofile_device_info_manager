/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "multi_user_manager.h"

#include "device_profile_manager.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"
#include "profile_utils.h"

#include "account_info.h"
#include "ohos_account_kits.h"
#include "os_account_manager.h"

namespace OHOS {
namespace DistributedDeviceProfile {
IMPLEMENT_SINGLE_INSTANCE(MultiUserManager);

namespace {
    const std::string TAG = "MultiUserManager";
}

int32_t MultiUserManager::Init()
{
    HILOGI("Init");
    int32_t foregroundId = DEFAULT_USER_ID;
    int32_t res = OHOS::AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(foregroundId);
    if (res != DP_SUCCESS || foregroundId == DEFAULT_USER_ID) {
        HILOGE("GetForegroundId failed, res: %{public}d", res);
    }
    HILOGI("current foregroundId = %{public}d", foregroundId);
    SetCurrentForegroundUserID(foregroundId);

    return DP_SUCCESS;
}

int32_t MultiUserManager::UnInit()
{
    return DP_SUCCESS;
}

void MultiUserManager::SetCurrentForegroundUserID(int32_t userId)
{
    std::lock_guard<std::mutex> lock(foregroundUserIdLock_);
    DeviceProfileManager::GetInstance().OnUserChange(foregroundUserId_, userId);
    foregroundUserId_ = userId;
}

int32_t MultiUserManager::GetCurrentForegroundUserID()
{
    std::lock_guard<std::mutex> lock(foregroundUserIdLock_);
    if (foregroundUserId_ == DEFAULT_USER_ID) {
        GetForegroundUserIDFromOs(foregroundUserId_);
    }
    return foregroundUserId_;
}

int32_t MultiUserManager::GetForegroundUserIDFromOs(int32_t& foregroundId)
{
    foregroundId = DEFAULT_USER_ID;
    int32_t res = OHOS::AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(foregroundId);
    if (res != DP_SUCCESS || foregroundId == DEFAULT_USER_ID) {
        HILOGE("GetForegroundId failed, res:%{public}d", res);
        return DP_GET_FOREGROUND_ID_FAIL;
    }
    HILOGI("GetForegroundUserIDFromOs foregroundId = %{public}d", foregroundId);
    return DP_SUCCESS;
}

std::string MultiUserManager::GetOhosAccountId()
{
#if (defined(__LITEOS_M__) || defined(LITE_DEVICE))
    return "";
#elif DP_OS_ACCOUNT_PART_EXISTS
    AccountSA::OhosAccountInfo accountInfo;
    ErrCode ret = OHOS::AccountSA::OhosAccountKits::GetInstance().GetOhosAccountInfo(accountInfo);
    if (ret != 0 || accountInfo.uid_ == "") {
        HILOGE("GetOhosAccountId error ret: %{public}d", ret);
        return "";
    }
    return accountInfo.uid_;
#else
    return "";
#endif
}

std::string MultiUserManager::GetOhosAccountIdByUserId(int32_t userId)
{
#if (defined(__LITEOS_M__) || defined(LITE_DEVICE))
    (void)userId;
    return "";
#elif DP_OS_ACCOUNT_PART_EXISTS
    AccountSA::OhosAccountInfo accountInfo;
    ErrCode ret = OHOS::AccountSA::OhosAccountKits::GetInstance().GetOsAccountDistributedInfo(userId, accountInfo);
    if (ret != 0 || accountInfo.uid_ == "") {
        HILOGE("error ret: %{public}d", ret);
        return "";
    }
    return accountInfo.uid_;
#else
    (void)userId;
    return "";
#endif
}

} // namespace DistributedHardware
} // namespace OHOS
