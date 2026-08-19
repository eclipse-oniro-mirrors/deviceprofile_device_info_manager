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

#include "permission_manager.h"

#include <string>

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "securec.h"

#include "dp_radar_helper.h"
#include "distributed_device_profile_log.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_errors.h"
#include "macro_utils.h"
#include "profile_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace OHOS::Security::AccessToken;

namespace {
    const std::string TAG = "PermissionManager";
    constexpr uint32_t INVALID_TOKEN_ID = 0;
    const std::string DP_SERVICE_ACCESS_PERMISSION = "ohos.permission.ACCESS_SERVICE_DP";
    const std::string DP_SERVICE_SYNC_PERMISSION = "ohos.permission.SYNC_PROFILE_DP";
}

IMPLEMENT_SINGLE_INSTANCE(PermissionManager);

int32_t PermissionManager::Init()
{
    HILOGI("init succeeded");
    return DP_SUCCESS;
}

int32_t PermissionManager::UnInit()
{
    HILOGI("UnInit succeeded");
    return DP_SUCCESS;
}

bool PermissionManager::IsCallerTrust(const std::string& interfaceName)
{
    int32_t stageRes = static_cast<int32_t>(StageRes::STAGE_FAIL);
    auto tokenID = IPCSkeleton::GetCallingTokenID();
    if (tokenID == INVALID_TOKEN_ID) {
        HILOGW("invalid token id");
        DpRadarHelper::GetInstance().ReportSaCheckAuth(stageRes);
        return false;
    }
    ATokenTypeEnum tokenType = AccessTokenKit::GetTokenTypeFlag(tokenID);
    if (tokenType != ATokenTypeEnum::TOKEN_NATIVE) {
        HILOGE("TokenType is not native");
        DpRadarHelper::GetInstance().ReportSaCheckAuth(stageRes);
        return false;
    }
    stageRes = static_cast<int32_t>(StageRes::STAGE_SUCC);
    DpRadarHelper::GetInstance().ReportSaCheckAuth(stageRes);
    HILOGD("interface %{public}s check passed", interfaceName.c_str());
    return true;
}

bool PermissionManager::CheckCallerPermission()
{
    int32_t stageRes = static_cast<int32_t>(StageRes::STAGE_FAIL);
    auto tokenID = IPCSkeleton::GetCallingTokenID();
    if (tokenID == INVALID_TOKEN_ID) {
        HILOGW("invalid token id");
        DpRadarHelper::GetInstance().ReportSaCheckAuth(stageRes);
        return false;
    }
    ATokenTypeEnum tokenType = AccessTokenKit::GetTokenTypeFlag(tokenID);
    if (tokenType != ATokenTypeEnum::TOKEN_NATIVE) {
        HILOGE("TokenType is not native");
        DpRadarHelper::GetInstance().ReportSaCheckAuth(stageRes);
        return false;
    }
    std::string callProcName = GetCallerProcName();
    int32_t ret = AccessTokenKit::VerifyAccessToken(tokenID, DP_SERVICE_ACCESS_PERMISSION);
    if (ret != PermissionState::PERMISSION_GRANTED) {
        HILOGE("failed callProc %{public}s!", callProcName.c_str());
        DpRadarHelper::GetInstance().ReportSaCheckAuth(stageRes);
        return false;
    }
    stageRes = static_cast<int32_t>(StageRes::STAGE_SUCC);
    DpRadarHelper::GetInstance().ReportSaCheckAuth(stageRes);
    return true;
}

bool PermissionManager::CheckCallerSyncPermission()
{
    int32_t stageRes = static_cast<int32_t>(StageRes::STAGE_FAIL);
    auto tokenID = IPCSkeleton::GetCallingTokenID();
    if (tokenID == INVALID_TOKEN_ID) {
        HILOGW("invalid token id");
        DpRadarHelper::GetInstance().ReportSaCheckAuth(stageRes);
        return false;
    }
    ATokenTypeEnum tokenType = AccessTokenKit::GetTokenTypeFlag(tokenID);
    if (tokenType != ATokenTypeEnum::TOKEN_NATIVE) {
        HILOGE("TokenType is not native");
        DpRadarHelper::GetInstance().ReportSaCheckAuth(stageRes);
        return false;
    }
    std::string callProcName = GetCallerProcName();
    int32_t ret = AccessTokenKit::VerifyAccessToken(tokenID, DP_SERVICE_SYNC_PERMISSION);
    if (ret != PermissionState::PERMISSION_GRANTED) {
        HILOGE("failed callProc %{public}s!", callProcName.c_str());
        DpRadarHelper::GetInstance().ReportSaCheckAuth(stageRes);
        return false;
    }
    stageRes = static_cast<int32_t>(StageRes::STAGE_SUCC);
    DpRadarHelper::GetInstance().ReportSaCheckAuth(stageRes);
    HILOGI("success callProc %{public}s!", callProcName.c_str());
    return true;
}

std::string PermissionManager::GetCallerProcName()
{
    NativeTokenInfo nativeTokenInfo;
    auto tokenID = IPCSkeleton::GetCallingTokenID();
    auto errCode = AccessTokenKit::GetNativeTokenInfo(tokenID, nativeTokenInfo);
    std::string procName;
    if (errCode == EOK) {
        procName = std::move(nativeTokenInfo.processName);
        HILOGD("procName:%{public}s", procName.c_str());
    }
    return procName;
}
} // namespace DeviceProfile
} // namespace OHOS
