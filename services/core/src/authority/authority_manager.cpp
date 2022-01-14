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

#include "authority_manager.h"

#include <fstream>

#include "file_ex.h"
#include "ipc_skeleton.h"
#include "securec.h"

#include "device_profile_log.h"

namespace OHOS {
namespace DeviceProfile {
namespace {
const std::string TAG = "AuthorityManager";

constexpr int32_t BUF_SIZE = 256;
constexpr int32_t ROOT_UID = 0;
constexpr int32_t SYSTEM_UID = 1000;
const std::string INTERFACES = "interfacesAuthority";
const std::string SERVICES = "servicesAuthority";
const std::string SERVICES_ALL = "all";
const std::string SERVICES_SPECIFIC = "specific";
const std::string SERVICES_PREFIX = "prefix";
const std::string AUTHORITY_JSON_PATH = "/system/etc/deviceprofile/authority.json";
}

IMPLEMENT_SINGLE_INSTANCE(AuthorityManager);

bool AuthorityManager::Init()
{
    if (!LoadAuthorityCfg(AUTHORITY_JSON_PATH)) {
        return false;
    }
    InitSupportedInterfaces();
    ValidateAuthorityCfg();
    HILOGI("init succeeded");
    return true;
}

void AuthorityManager::InitSupportedInterfaces()
{
    supportedInterfaces_ = { "sync" };
}

bool AuthorityManager::LoadAuthorityCfg(const std::string& filePath)
{
    std::ifstream ifs(filePath.c_str());
    if (!ifs.good()) {
        HILOGE("load json file failed");
        return false;
    }
    authJson_ = nlohmann::json::parse(ifs, nullptr, false);
    if (authJson_.is_discarded()) {
        HILOGE("parse failed");
        return false;
    }
    HILOGD("authority json %{public}s", authJson_.dump().c_str());
    return true;
}

void AuthorityManager::ValidateAuthorityCfg()
{
    for (auto iter = authJson_.begin(); iter != authJson_.end();) {
        if (!ValidateProcess(iter.value())) {
            HILOGE("authority for proc %{public}s is invalid, deleted", iter.key().c_str());
            authJson_.erase(iter++);
        } else {
            iter++;
        }
    }
}

bool AuthorityManager::ValidateProcess(nlohmann::json& processJson)
{
    for (auto& [key, value] : processJson.items()) {
        if (key != INTERFACES && key != SERVICES) {
            HILOGE("invalid key:%{public}s under proc", key.c_str());
            return false;
        }
        if (key == INTERFACES && !ValidateInterfaces(value)) {
            return false;
        }
        if (key == SERVICES && !ValidateServices(value)) {
            return false;
        }
    }
    return true;
}

bool AuthorityManager::ValidateInterfaces(nlohmann::json& interfacesJson)
{
    if (interfacesJson.empty()) {
        return false;
    }

    for (auto& [key, value] : interfacesJson.items()) {
        if (supportedInterfaces_.find(key) == supportedInterfaces_.end()) {
            return false;
        }
        // value should be type of object, e.g. "sync": {}
        if (!value.is_object()) {
            return false;
        }
    }
    return true;
}

bool AuthorityManager::ValidateServices(nlohmann::json& servicesJson)
{
    if (servicesJson.empty()) {
        return false;
    }

    if (servicesJson.contains(SERVICES_ALL)) {
        // currently only read permission is allowed being with SERVICES_ALL
        if (!ValidateService(servicesJson[SERVICES_ALL], true)) {
            return false;
        }
    }

    if (servicesJson.contains(SERVICES_SPECIFIC) &&
        !ValidateServicesHelper(servicesJson[SERVICES_SPECIFIC])) {
        return false;
    }
    if (servicesJson.contains(SERVICES_PREFIX) &&
        !ValidateServicesHelper(servicesJson[SERVICES_PREFIX])) {
        return false;
    }
    return true;
}

bool AuthorityManager::ValidateServicesHelper(nlohmann::json& servicesJson)
{
    for (auto& [key, value] : servicesJson.items()) {
        if (!ValidateService(value, false)) {
            HILOGW("service:%{public}s is invalid, deleted", key.c_str());
            return false;
        }
    }
    return true;
}

bool AuthorityManager::ValidateService(const nlohmann::json& authValJson, bool readOnly)
{
    if (!authValJson.is_number_unsigned()) {
        HILOGE("not number type");
        return false;
    }
    auto authVal = authValJson.get<uint32_t>();
    // single AUTH_W is meaningless and disallowed
    if (authVal != AuthValue::AUTH_RW &&
        authVal != AuthValue::AUTH_R) {
        HILOGE("invalid auth value");
        return false;
    }
    if (readOnly && authVal != AuthValue::AUTH_R) {
        HILOGE("read only");
        return false;
    }
    return true;
}

bool AuthorityManager::CheckInterfaceAuthority(const std::string& ifaceName)
{
    std::string procName = GetCallingProcName();
    if (!authJson_.contains(procName)) {
        HILOGE("can't find entry for proc:%{public}s", procName.c_str());
        return false;
    }

    auto& interfacesJson = authJson_[procName][INTERFACES];
    if (interfacesJson == nullptr) {
        HILOGE("can't find interfaces entry");
        return false;
    }

    if (!interfacesJson.contains(ifaceName)) {
        HILOGE("%{public}s is disallowed for %{public}s", ifaceName.c_str(),
            procName.c_str());
        return false;
    }
    return true;
}

bool AuthorityManager::CheckServiceAuthority(AuthValue authVal,
    const std::string& serviceId)
{
    return CheckServicesAuthority(authVal, { serviceId });
}

bool AuthorityManager::CheckServicesAuthority(AuthValue authVal,
    const std::vector<std::string>& serviceIds)
{
    bool hasEmpty = std::any_of(serviceIds.begin(), serviceIds.end(),
        [](const auto& serviceId) { return serviceId.empty(); });
    if (hasEmpty) {
        HILOGE("empty serviceId");
        return false;
    }

    std::string procName = GetCallingProcName();
    if (!authJson_.contains(procName)) {
        HILOGE("can't find entry for proc:%{public}s", procName.c_str());
        return false;
    }
    auto& servicesJson = authJson_[procName][SERVICES];
    if (servicesJson == nullptr) {
        HILOGE("can't find services entry");
        return false;
    }

    if (!CheckServicesAuth(servicesJson, authVal, serviceIds)) {
        return false;
    }
    return true;
}

bool AuthorityManager::CheckServicesAuth(const nlohmann::json& servicesJson,
    AuthValue authVal, const std::vector<std::string>& serviceIds)
{
    bool isReadWithAll = (authVal == AuthValue::AUTH_R) && servicesJson.contains(SERVICES_ALL);
    if (serviceIds.empty()) {
        // in case where no serviceIds provided, which means all services; but
        // SERVICES_ALL is only allowed with AUTH_R
        return isReadWithAll;
    }
    if (isReadWithAll) {
        HILOGI("check pass, SERVICES_ALL with read");
        return true;
    }

    const auto& specificSvcsJson = servicesJson.contains(SERVICES_SPECIFIC) ?
        servicesJson[SERVICES_SPECIFIC] : nlohmann::json {};
    const auto& prefixSvcsJson = servicesJson.contains(SERVICES_PREFIX) ?
        servicesJson[SERVICES_PREFIX] : nlohmann::json {};
    if (specificSvcsJson == nullptr && prefixSvcsJson == nullptr) {
        HILOGE("check failed, no specific and prefix service");
        return false;
    }
    for (const auto& serviceId : serviceIds) {
        if ((specificSvcsJson != nullptr) &&
            CheckSpecificServiceAuth(specificSvcsJson, serviceId, authVal)) {
            continue;
        }
        if ((prefixSvcsJson != nullptr) &&
            CheckPrefixServiceAuth(prefixSvcsJson, serviceId, authVal)) {
            continue;
        }
        HILOGE("denied to access service:%{public}s", serviceId.c_str());
        return false;
    }
    HILOGI("check pass, authorities statisfied");
    return true;
}

bool AuthorityManager::CheckSpecificServiceAuth(const nlohmann::json& specificSvcsJson,
    const std::string& serviceId, AuthValue authVal)
{
    if (!specificSvcsJson.contains(serviceId)) {
        return false;
    }
    auto& authValJson = specificSvcsJson[serviceId];
    return ((authValJson.get<uint32_t>() & authVal) != 0);
}

bool AuthorityManager::CheckPrefixServiceAuth(const nlohmann::json& prefixSvcsJson,
    const std::string& serviceId, AuthValue authVal)
{
    for (auto& [prefixSvcId, authValJson] : prefixSvcsJson.items()) {
        if ((serviceId.compare(0, prefixSvcId.size(), prefixSvcId) == 0)) {
            HILOGI("service:%{public}s, prefix:%{public}s", serviceId.c_str(), prefixSvcId.c_str());
            return ((authValJson.get<uint32_t>() & authVal) != 0);
        }
    }
    return false;
}

bool AuthorityManager::CheckCallerTrust()
{
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    HILOGI("calling uid is %{public}d", callingUid);
    return (callingUid == SYSTEM_UID || callingUid == ROOT_UID);
}

std::string AuthorityManager::GetCallingProcName()
{
    char buf[BUF_SIZE] = {0};
    int32_t pid = IPCSkeleton::GetCallingPid();
    HILOGI("pid = %{public}d", pid);
    (void)snprintf_s(buf, BUF_SIZE, BUF_SIZE - 1, "/proc/%d/cmdline", pid);

    std::string procName;
    if (!LoadStringFromFile(std::string(buf, strlen(buf)), procName)) {
        HILOGE("load string failed");
        return procName;
    }
    auto pos = procName.find_last_not_of(" \n\r\t");
    if (pos != std::string::npos) {
        procName.erase(pos + 1);
    }

    pos = procName.find_last_of("/");
    if (pos != std::string::npos) {
        procName = procName.substr(pos + 1);
    }
    HILOGI("calling proc is %{public}s", procName.c_str());
    return procName.c_str();
}
} // namespace DeviceProfile
} // namespace OHOS