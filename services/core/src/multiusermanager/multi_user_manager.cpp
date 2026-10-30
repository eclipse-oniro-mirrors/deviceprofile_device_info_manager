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

#include "dp_account_query.h"

namespace OHOS {
namespace DistributedDeviceProfile {
IMPLEMENT_SINGLE_INSTANCE(MultiUserManager);

namespace {
    constexpr char TAG[] = "MultiUserManager";
    const std::string OHOS_ANONYMOUS_UID = "ohosAnonymousUid";
}

int32_t MultiUserManager::Init()
{
    HILOGI("Init");
    int32_t foregroundId = DEFAULT_USER_ID;
    int32_t res = DpAccountQuery::Connect().GetForegroundUserId(foregroundId);
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
    int32_t res = DpAccountQuery::Connect().GetForegroundUserId(foregroundId);
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
    std::string accountUid;
    int32_t ret = DpAccountQuery::Connect().GetAccountUid(accountUid);
    if (ret != 0 || accountUid == "") {
        HILOGE("GetOhosAccountId error ret: %{public}d", ret);
        return "";
    }
    return accountUid;
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
    std::string accountUid;
    int32_t ret = DpAccountQuery::Connect().GetAccountUid(userId, accountUid);
    if (ret != 0 || accountUid == "" || accountUid == OHOS_ANONYMOUS_UID) {
        HILOGE("error ret: %{public}d", ret);
        return "";
    }
    return accountUid;
#else
    (void)userId;
    return "";
#endif
}

bool MultiUserManager::CurrentIsEnterpriseSpace()
{
    bool enterprise = false;
    auto ret = DpAccountQuery::Connect().IsEnterpriseUser(GetCurrentForegroundUserID(), enterprise);
    if (ret != DP_SUCCESS) {
        HILOGE("GetOsAccountDomainInfo failed");
        return false;
    }
    return enterprise;
}

} // namespace DistributedHardware
} // namespace OHOS
