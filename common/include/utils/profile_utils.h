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

#ifndef OHOS_DP_PROFILE_UTILS_H
#define OHOS_DP_PROFILE_UTILS_H

#include <list>
#include <string>
#include <vector>
#include <map>
#include "trust_device_profile.h"
#include "access_control_profile.h"
#include "device_profile.h"
#include "service_profile.h"
#include "characteristic_profile.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_enums.h"
#include "values_bucket.h"

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace OHOS::NativeRdb;

class ProfileUtils {
public:
    static std::string GetAnonyString(const std::string& value);
    static std::vector<std::string> GetOnlineDevices();
    static std::string GetLocalUdidFromDM();
    static std::vector<std::string> FilterOnlineDevices(const std::vector<std::string>& deviceList);
    static ProfileType GetProfileType(const std::string& key);
    static bool StartsWith(const std::string& str, const std::string prefix);
    static bool IsKeyValid(const std::string& key);
    static std::string GenerateDeviceProfileKey(const std::string& deviceId);
    static std::string GenerateServiceProfileKey(const std::string& deviceId, const std::string& serviceName);
    static std::string GenerateCharProfileKey(const std::string& deviceId, const std::string& serviceName,
        const std::string& charKey);
    static int32_t TrustDeviceProfileToEntries(const TrustDeviceProfile& profile, ValuesBucket& values);
    static int32_t AccessControlProfileToEntries(const AccessControlProfile& profile, ValuesBucket& values);
    static int32_t AccesserToEntries(const AccessControlProfile& aclProfile, ValuesBucket& values);
    static int32_t AccesseeToEntries(const AccessControlProfile& aclProfile, ValuesBucket& values);
    static int32_t DeviceProfileToEntries(const DeviceProfile& profile, std::map<std::string, std::string>& values);
    static int32_t ServiceProfileToEntries(const ServiceProfile& profile, std::map<std::string, std::string>& values);
    static int32_t CharacteristicProfileToEntries(const CharacteristicProfile& profile,
        std::map<std::string, std::string>& values);
    static int32_t EntriesToTrustDeviceProfile(const ValuesBucket& values, TrustDeviceProfile& profile);
    static int32_t EntriesToAccessControlProfile(const ValuesBucket& values, AccessControlProfile& profile);
    static int32_t EntriesToAccesser(const ValuesBucket& values, Accesser& accesser);
    static int32_t EntriesToAccessee(const ValuesBucket& values, Accessee& accessee);
    static int32_t EntriesToDeviceProfile(std::map<std::string, std::string> values, DeviceProfile& profile);
    static int32_t EntriesToServiceProfile(std::map<std::string, std::string> values, ServiceProfile& profile);
    static int32_t EntriesToCharProfile(std::map<std::string, std::string> values, CharacteristicProfile& profile);
    static std::string GenerateDBKey(const std::string& profileKey, const std::string& profileProperty);
    static std::string GetProfileKey(const std::string& dbKey);
    static std::string GetDeviceIdByDBKey(const std::string& dbKey);
    static std::string GetServiceNameByDBKey(const std::string& dbKey);
    static std::string GetCharKeyByDBKey(const std::string& dbKey);
    static int32_t SplitString(const std::string& str, const std::string& splits, std::vector<std::string>& res);
    static std::string GetProfileProperty(const std::string& dbKey);
    static std::map<std::string, std::string> GetProfilePropertiesMap(std::map<std::string, std::string> dbEntries);
    static std::string toString(const std::u16string& str16);
    static bool IsPropertyValid(const std::map<std::string, std::string>& propertyMap, const std::string& property,
        int32_t maxValue);
    static bool IsPropertyValid(const std::map<std::string, std::string>& propertyMap, const std::string& property,
        int32_t minValue, int32_t maxValue);
    static bool IsPropertyValid(const std::map<std::string, std::string>& propertyMap, const std::string& property,
        uint32_t minValue, uint32_t maxValue);
    static bool IsPropertyValid(const std::map<std::string, std::string>& propertyMap, const std::string& property,
        int64_t minValue, int64_t maxValue);
    static bool GetIntValue(const ValuesBucket& values, const std::string& property, int32_t& value);
    static bool GetStringValue(const ValuesBucket& values, const std::string& property, std::string& value);
    static bool GetLongValue(const ValuesBucket& values, const std::string& property, int64_t& value);
    static bool GetUdidByNetworkId(const std::string& networkId, std::string& udid);
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // OHOS_DP_PROFILE_UTILS_H
