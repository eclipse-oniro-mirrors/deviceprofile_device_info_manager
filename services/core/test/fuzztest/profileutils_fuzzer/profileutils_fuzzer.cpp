/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "profileutils_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include <cstdlib>
#include <fcntl.h>
#include <string>
#include <sys/types.h>
#include "sys/stat.h"

#include "profile_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {

namespace {
    const int32_t AERUSERID = 11;
    const int32_t USERIDS = 22;
    const int32_t AERTOKENID = 111;
    const int32_t TOKENIDS = 222;
    const int32_t AUTHTIME = 5;
}

void GetProfileTypeFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    std::string dbKey(reinterpret_cast<const char*>(data), size);
    ProfileUtils::GetProfileType(dbKey);
}

void StartsWithFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    std::string str(reinterpret_cast<const char*>(data), size);
    std::string prefix(reinterpret_cast<const char*>(data), size);
    ProfileUtils::StartsWith(str, prefix);
}

void GetDeviceIdByDBKeyFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    std::string dbKey = "";
    ProfileUtils::GetDeviceIdByDBKey(dbKey);
}

void GetCharKeyByDBKeyFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    std::string dbKey = "char#";
    ProfileUtils::GetCharKeyByDBKey(dbKey);
}

void SplitStringFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    std::string str(reinterpret_cast<const char*>(data), size);
    std::string splits(reinterpret_cast<const char*>(data), size);
    std::vector<std::string> res;
    std::string strs(reinterpret_cast<const char*>(data), size);
    res.push_back(strs);
    ProfileUtils::SplitString(str, splits, res);
}

void IsKeyValidFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    std::string dbKey(reinterpret_cast<const char*>(data), size);
    ProfileUtils::IsKeyValid(dbKey);
}

void GenerateDeviceProfileKeyFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    std::string deviceId(reinterpret_cast<const char*>(data), size);
    ProfileUtils::GenerateDeviceProfileKey(deviceId);
}

void GenerateServiceProfileKeyFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    std::string deviceId(reinterpret_cast<const char*>(data), size);
    std::string serviceName(reinterpret_cast<const char*>(data), size);
    ProfileUtils::GenerateServiceProfileKey(deviceId, serviceName);
}

void GenerateCharProfileKeyFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    std::string deviceId(reinterpret_cast<const char*>(data), size);
    std::string serviceName(reinterpret_cast<const char*>(data), size);
    std::string charKey(reinterpret_cast<const char*>(data), size);
    ProfileUtils::GenerateCharProfileKey(deviceId, serviceName, charKey);
}

void TrustDeviceProfileToEntriesFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    TrustDeviceProfile profile;
    profile.SetDeviceId("deviceId");
    profile.SetDeviceIdHash("deviceIdHash");
    profile.SetDeviceIdType(1);
    profile.SetStatus(1);
    
    ValuesBucket values;
    ProfileUtils::TrustDeviceProfileToEntries(profile, values);
}

void AccessControlProfileToEntriesFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    Accesser accesser;
    accesser.SetAccesserDeviceId("acer1");
    accesser.SetAccesserUserId(AERUSERID);
    accesser.SetAccesserAccountId("a1");
    accesser.SetAccesserTokenId(AERTOKENID);
    accesser.SetAccesserBundleName("b1");
    accesser.SetAccesserHapSignature("h1");
    accesser.SetAccesserBindLevel(1);
    
    Accessee accessee;
    accessee.SetAccesseeDeviceId("acee1");
    accessee.SetAccesseeUserId(USERIDS);
    accessee.SetAccesseeAccountId("a1");
    accessee.SetAccesseeTokenId(TOKENIDS);
    accessee.SetAccesseeBundleName("bb1");
    accessee.SetAccesseeHapSignature("h1");
    accessee.SetAccesseeBindLevel(1);

    AccessControlProfile profile;
    profile.SetTrustDeviceId("123456");
    profile.SetSessionKey("key1");
    profile.SetBindType(1);
    profile.SetAuthenticationType(1);
    profile.SetDeviceIdType(1);
    profile.SetDeviceIdHash("abcd");
    profile.SetStatus(0);
    profile.SetValidPeriod(1);
    profile.SetLastAuthTime(AUTHTIME);
    profile.SetBindLevel(0);
    
    profile.SetAccesser(accesser);
    profile.SetAccessee(accessee);

    ValuesBucket values;
    ProfileUtils::AccessControlProfileToEntries(profile, values);
}

void EntriesToAccesserFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    ValuesBucket values;
    Accesser profile;
    int32_t intValue = 1;
    int64_t longValue = 1;
    std::string strValue = "strValue";
    
    values.PutLong(ACCESSER_ID, longValue);
    values.PutString(ACCESSER_DEVICE_ID, strValue);
    values.PutInt(ACCESSER_USER_ID, intValue);
    values.PutString(ACCESSER_ACCOUNT_ID, strValue);
    values.PutLong(ACCESSER_TOKEN_ID, longValue);
    values.PutString(ACCESSER_BUNDLE_NAME, strValue);
    values.PutInt(ACCESSER_BIND_LEVEL, intValue);

    ProfileUtils::EntriesToAccesser(values, profile);
}

void EntriesToDeviceProfileFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    DeviceProfile deviceProfile;
    deviceProfile.SetDeviceId("anything");
    deviceProfile.SetOsApiLevel(1);
    deviceProfile.SetOsVersion("anything");
    deviceProfile.SetOsType(1);
    
    std::map<std::string, std::string> entries;
    ProfileUtils::DeviceProfileToEntries(deviceProfile, entries);
    DeviceProfile outDeviceProfile;
    ProfileUtils::EntriesToDeviceProfile(entries, outDeviceProfile);
}

void EntriesToServiceProfileFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    ServiceProfile serviceProfile;
    serviceProfile.SetDeviceId("deviceId");
    serviceProfile.SetServiceName("serviceName");
    serviceProfile.SetServiceType("serviceType");
    
    std::map<std::string, std::string> entries;
    ProfileUtils::ServiceProfileToEntries(serviceProfile, entries);
    ServiceProfile outServiceProfile;
    ProfileUtils::EntriesToServiceProfile(entries, outServiceProfile);
}

void EntriesToCharProfileFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    std::map<std::string, std::string> values;
    CharacteristicProfile profile;

    ProfileUtils::EntriesToCharProfile(values, profile);
}

void GenerateDBKeyFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    std::string profileProperty(reinterpret_cast<const char*>(data), size);
    std::string profileKey(reinterpret_cast<const char*>(data), size);

    ProfileUtils::GenerateDBKey(profileKey, profileProperty);
}

void GetProfilePropertyFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    std::string dbKey = "profileKey#profileProperty";
    ProfileUtils::GetProfileProperty(dbKey);
}

void GetProfilePropertiesMapFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    DeviceProfile profile;
    std::map<std::string, std::string> values;
    values["key"] = "value";
    ProfileUtils::GetProfilePropertiesMap(values);
}

void ToStringFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    std::u16string str16 = u"abc";
    ProfileUtils::toString(str16);
}

void IsPropertyValidFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    std::map<std::string, std::string> propertyMap;
    std::string property = "property";
    int32_t maxValue = 1;
    ProfileUtils::IsPropertyValid(propertyMap, property, maxValue);
    
    int32_t minValue = 0;
    ProfileUtils::IsPropertyValid(propertyMap, property, minValue, maxValue);

    uint32_t u32MinValue = 0;
    uint32_t u32MaxValue = 1;
    ProfileUtils::IsPropertyValid(propertyMap, property, u32MinValue, u32MaxValue);

    int64_t i64MinValue = 0;
    int64_t i64MaxValue = 1;
    ProfileUtils::IsPropertyValid(propertyMap, property, i64MinValue, i64MaxValue);
}

void GetIntValueFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    ValuesBucket values;
    std::string property = "property";
    int32_t value = 0;
    ProfileUtils::GetIntValue(values, property, value);
}

void GetStringValueFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    ValuesBucket values;
    std::string strValue = "strValue";
    std::string property = "property";
    values.PutString(property, strValue);
    std::string outValue = "";
    ProfileUtils::GetStringValue(values, property, outValue);
}

void GetLongValueFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    ValuesBucket values;
    int64_t longValue = 1;
    std::string property = "property";
    values.PutLong(property, longValue);
    int64_t outValue = 0;
    ProfileUtils::GetLongValue(values, property, outValue);
}

void GetUdidByNetworkIdFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    std::string networkId(reinterpret_cast<const char*>(data), size);
    std::string udid(reinterpret_cast<const char*>(data), size);
    ProfileUtils::GetUdidByNetworkId(networkId, udid);
}

void GetDbKeyByProfileFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    CharacteristicProfile charProfile;
    ProfileUtils::GetDbKeyByProfile(charProfile);

    charProfile.SetDeviceId("deviceId");
    charProfile.SetServiceName("serviceName");
    charProfile.SetCharacteristicKey("characteristicKey");
    charProfile.SetCharacteristicValue("characteristicValue");
    ProfileUtils::GetDbKeyByProfile(charProfile);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedDeviceProfile::GetProfileTypeFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::StartsWithFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::GetDeviceIdByDBKeyFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::GetCharKeyByDBKeyFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::SplitStringFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::IsKeyValidFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::GenerateDeviceProfileKeyFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::GenerateServiceProfileKeyFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::GenerateCharProfileKeyFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::TrustDeviceProfileToEntriesFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::AccessControlProfileToEntriesFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::EntriesToAccesserFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::EntriesToDeviceProfileFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::EntriesToCharProfileFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::GenerateDBKeyFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::GetProfilePropertyFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::GetProfilePropertiesMapFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::ToStringFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::IsPropertyValidFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::GetIntValueFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::GetStringValueFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::GetLongValueFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::GetUdidByNetworkIdFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::GetDbKeyByProfileFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::EntriesToServiceProfileFuzzTest(data, size);

    return 0;
}