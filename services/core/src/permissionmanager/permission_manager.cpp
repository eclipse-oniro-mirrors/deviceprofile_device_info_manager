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

#include "permission_manager.h"

#include <fstream>
#include <string>
#include <unordered_set>

#include "accesstoken_kit.h"
#include "file_ex.h"
#include "ipc_skeleton.h"
#include "securec.h"
#include "nlohmann/json.hpp"

#include "distributed_device_profile_log.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_errors.h"
#include "macro_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace OHOS::Security::AccessToken;

namespace {
    const std::string TAG = "PermissionManager";
    constexpr uint32_t INVALID_TOKEN_ID = 0;
    const std::string INTERFACES = "interfacesAuthority";
    const std::string SERVICES = "servicesAuthority";
    const std::string SERVICES_ALL = "all";
    const std::string SERVICES_SPECIFIC = "specific";
    const std::string SERVICES_PREFIX = "prefix";
    const std::string PERMISSION_JSON_PATH = "/system/etc/deviceprofile/permission.json";
}

IMPLEMENT_SINGLE_INSTANCE(PermissionManager);

int32_t PermissionManager::Init()
{
    HILOGI("call!");
    if (!LoadPermissionCfg(PERMISSION_JSON_PATH)) {
        return false;
    }
    HILOGI("init succeeded");
    return DP_SUCCESS;
}

int32_t PermissionManager::UnInit()
{
    HILOGI("UnInit");
    return DP_SUCCESS;
}

int32_t PermissionManager::LoadPermissionCfg(const std::string& filePath)
{
    char path[PATH_MAX + 1] = {0x00};
    if (filePath.length() == 0 || filePath.length() > PATH_MAX || realpath(filePath.c_str(), path) == nullptr) {
        HILOGE("File canonicalization failed");
        return DP_PARSE_PERMISSION_JSON_FAIL;
    }
    std::ifstream ifs(path);
    if (!ifs.is_open()) {
        HILOGE("load json file failed");
        return DP_PARSE_PERMISSION_JSON_FAIL;
    }
    nlohmann::json permissionJson = nlohmann::json::parse(ifs, nullptr, false);
    if (permissionJson.is_discarded()) {
        HILOGE("Permission json parse failed!");
        ifs.close();
        return DP_PARSE_PERMISSION_JSON_FAIL;
    }
    int32_t parseResult = ParsePermissionJson(permissionJson);
    HILOGI("permission json load result %d!", parseResult);
    ifs.close();
    return parseResult;
}


int32_t PermissionManager::ParsePermissionJson(const nlohmann::json& permissionJson)
{
    if (permissionJson.size() == 0 || permissionJson.size() > MAX_INTERFACE_SIZE) {
        HILOGE("Permission json size is invalid!");
        return DP_PARSE_PERMISSION_JSON_FAIL;
    }
    {
        std::lock_guard<std::mutex> lockGuard(permissionMutex_);
        SET_PERMISSION_MAP(permissionMap_, permissionJson, PUT_ACCESS_CONTROL_PROFILE);
        SET_PERMISSION_MAP(permissionMap_, permissionJson, UPDATE_ACCESS_CONTROL_PROFILE);
        SET_PERMISSION_MAP(permissionMap_, permissionJson, GET_ACCESS_CONTROL_PROFILE);
        SET_PERMISSION_MAP(permissionMap_, permissionJson, GET_ALL_ACCESS_CONTROL_PROFILE);
        SET_PERMISSION_MAP(permissionMap_, permissionJson, DELETE_ACCESS_CONTROL_PROFILE);
        SET_PERMISSION_MAP(permissionMap_, permissionJson, GET_TRUST_DEVICE_PROFILE);
        SET_PERMISSION_MAP(permissionMap_, permissionJson, GET_ALL_TRUST_DEVICE_PROFILE);
        SET_PERMISSION_MAP(permissionMap_, permissionJson, PUT_SERVICE_PROFILE);
        SET_PERMISSION_MAP(permissionMap_, permissionJson, PUT_SERVICE_PROFILE_BATCH);
        SET_PERMISSION_MAP(permissionMap_, permissionJson, PUT_CHARACTERISTIC_PROFILE);
        SET_PERMISSION_MAP(permissionMap_, permissionJson, PUT_CHARACTERISTIC_PROFILE_BATCH);
        SET_PERMISSION_MAP(permissionMap_, permissionJson, GET_DEVICE_PROFILE);
        SET_PERMISSION_MAP(permissionMap_, permissionJson, GET_SERVICE_PROFILE);
        SET_PERMISSION_MAP(permissionMap_, permissionJson, GET_CHARACTERISTIC_PROFILE);
        SET_PERMISSION_MAP(permissionMap_, permissionJson, DELETE_SERVICE_PROFILE);
        SET_PERMISSION_MAP(permissionMap_, permissionJson, DELETE_CHARACTERISTIC_PROFILE);
        SET_PERMISSION_MAP(permissionMap_, permissionJson, SUBSCRIBE_DEVICE_PROFILE);
        SET_PERMISSION_MAP(permissionMap_, permissionJson, UNSUBSCRIBE_DEVICE_PROFILE);
        SET_PERMISSION_MAP(permissionMap_, permissionJson, SYNC_DEVICE_PROFILE);
    }
    HILOGI("permission json %{public}s parse success!", permissionJson.dump().c_str());
    return DP_SUCCESS;
}

bool PermissionManager::CheckInterfacePermission(const std::string& interfaceName)
{
    std::string callProcName = GetCallerProcName();
    std::unordered_set<std::string> permittedProcNames;
    {
        std::lock_guard<std::mutex> lockGuard(permissionMutex_);
        permittedProcNames = permissionMap_[interfaceName];
    }
    bool checkResult =  (permittedProcNames.count(callProcName) != 0 || permittedProcNames.count(ALL_PROC) != 0);
    HILOGI("Permission success interface %{public}s callProc %{public}s!", interfaceName.c_str(), callProcName.c_str());
    return checkResult;
}

bool PermissionManager::IsCallerTrust(const std::string& interfaceName)
{
    auto tokenID = IPCSkeleton::GetCallingTokenID();
    if (tokenID == INVALID_TOKEN_ID) {
        HILOGW("invalid token id");
        return false;
    }
    ATokenTypeEnum tokenType = AccessTokenKit::GetTokenTypeFlag(tokenID);
    HILOGD("tokenID:%{public}u, tokenType:%{public}d", tokenID, tokenType);
    // currently only support native trusted caller
    if (tokenType != ATokenTypeEnum::TOKEN_NATIVE) {
        HILOGE("TokenType is not native");
        return false;
    }
    if (!CheckInterfacePermission(interfaceName)) {
        HILOGE("This caller cannot call this interface, interfaceName: %s", interfaceName.c_str());
        return false;
    }
    return true;
}

std::string PermissionManager::GetCallerProcName()
{
    // called after CheckCallerTrust, and keep same policy with CheckCallerTrust
    NativeTokenInfo nativeTokenInfo;
    auto tokenID = IPCSkeleton::GetCallingTokenID();
    auto errCode = AccessTokenKit::GetNativeTokenInfo(tokenID, nativeTokenInfo);
    HILOGI("get token info errCode = %{public}d", errCode);
    std::string procName;
    if (errCode == EOK) {
        procName = std::move(nativeTokenInfo.processName);
        HILOGI("procName:%{public}s", procName.c_str());
    }
    return procName;
}
} // namespace DeviceProfile
} // namespace OHOS
