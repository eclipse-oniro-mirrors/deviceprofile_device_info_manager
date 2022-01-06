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

#ifndef OHOS_DISTRIBUTED_DEVICE_PROFILE_AUTHORITY_MANAGER_H
#define OHOS_DISTRIBUTED_DEVICE_PROFILE_AUTHORITY_MANAGER_H

#include <string>
#include <unordered_set>

#include "single_instance.h"

#include "nlohmann/json.hpp"

namespace OHOS {
namespace DeviceProfile {
enum AuthValue : uint16_t {
    // 0000 0000 0000 0001, the authority of read
    AUTH_R = 0x0001,
    // 0000 0000 0000 0010, the authority of write
    AUTH_W = 0x0002,
    // 0000 0000 0000 0011, the authority of both read and write
    AUTH_RW = 0x0003
};

class AuthorityManager {
    DECLARE_SINGLE_INSTANCE(AuthorityManager);

public:
    bool Init();

    bool CheckCallerTrust();
    bool CheckInterfaceAuthority(const std::string& ifaceName);
    bool CheckServiceAuthority(AuthValue authVal, const std::string& serviceId);
    bool CheckServicesAuthority(AuthValue authVal, const std::vector<std::string>& serviceIds);

private:
    bool LoadAuthorityCfg(const std::string& filePath);
    void InitSupportedInterfaces();

    void ValidateAuthorityCfg();
    bool ValidateProcess(nlohmann::json& processJson);
    bool ValidateInterfaces(nlohmann::json& interfacesJson);
    bool ValidateServices(nlohmann::json& servicesJson);
    bool ValidateServicesHelper(nlohmann::json& servicesJson);
    bool ValidateService(const nlohmann::json& authValJson, bool readOnly);

    bool CheckServicesAuth(const nlohmann::json& servicesJson, AuthValue authVal,
        const std::vector<std::string>& serviceIds);
    bool CheckPrefixServiceAuth(const nlohmann::json& prefixSvcsJson,
       const std::string& serviceId, AuthValue authVal);
    bool CheckSpecificServiceAuth(const nlohmann::json& specificSvcsJson,
       const std::string& serviceId, AuthValue authVal);

    std::string GetCallingProcName();

private:
    nlohmann::json authJson_;
    std::unordered_set<std::string> supportedInterfaces_;
};
} // namespace DeviceProfile
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_DEVICE_PROFILE_AUTHORITY_MANAGER_H