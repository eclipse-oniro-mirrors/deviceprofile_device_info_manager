/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <string>
#include <algorithm>
#include <locale>
#include <codecvt>
#include "profile_utils.h"
#include "distributed_device_profile_log.h"
#include "distributed_device_profile_errors.h"
#include "device_manager.h"
#include "nlohmann/json.hpp"

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace OHOS::DistributedHardware;

namespace {
    const std::string TAG = "ProfileUtils";
}

std::string ProfileUtils::GetAnonyString(const std::string& value)
{
    constexpr size_t INT32_SHORT_ID_LENGTH = 20;
    constexpr size_t INT32_PLAINTEXT_LENGTH = 4;
    constexpr size_t INT32_MIN_ID_LENGTH = 3;
    std::string res;
    std::string tmpStr("******");
    size_t strLen = value.length();
    if (strLen < INT32_MIN_ID_LENGTH) {
        return tmpStr;
    }

    if (strLen <= INT32_SHORT_ID_LENGTH) {
        res += value[0];
        res += tmpStr;
        res += value[strLen - 1];
    } else {
        res.append(value, 0, INT32_PLAINTEXT_LENGTH);
        res += tmpStr;
        res.append(value, strLen - INT32_PLAINTEXT_LENGTH, INT32_PLAINTEXT_LENGTH);
    }
    return res;
}

std::vector<std::string> ProfileUtils::GetOnlineDevices()
{
    std::vector<std::string> targetDevices;
    std::vector<DmDeviceInfo> allOnlineDeviceInfos;
    int32_t result = DeviceManager::GetInstance().GetTrustedDeviceList(PKG_NAME, "", allOnlineDeviceInfos);
    if (result != DP_SUCCESS || allOnlineDeviceInfos.empty()) {
        HILOGE("GetTrustedDeviceList Failed!");
        return {};
    }
    for (const DmDeviceInfo& dmDeviceInfo : allOnlineDeviceInfos) {
        targetDevices.push_back(dmDeviceInfo.networkId);
    }
    return targetDevices;
}

std::vector<std::string> ProfileUtils::FilterOnlineDevices(const std::vector<std::string>& deviceList)
{
    if (deviceList.size() == 0 || deviceList.size() > MAX_DEVICE_SIZE) {
        HILOGE("This deviceList size is invalid, size: %{public}zu!", deviceList.size());
        return {};
    }
    std::vector<DmDeviceInfo> allOnlineDeviceInfos;
    int32_t result = DeviceManager::GetInstance().GetTrustedDeviceList(PKG_NAME, "", allOnlineDeviceInfos);
    if (result != DP_SUCCESS || allOnlineDeviceInfos.empty()) {
        HILOGE("GetTrustedDeviceList Failed!");
        return {};
    }
    std::vector<std::string> targetDevices;
    for (const DmDeviceInfo& dmDeviceInfo : allOnlineDeviceInfos) {
        if (std::find(deviceList.begin(), deviceList.end(), dmDeviceInfo.networkId) == deviceList.end()) {
            HILOGE("This device is not online, networkId: %s!",
                   ProfileUtils::GetAnonyString(dmDeviceInfo.networkId).c_str());
            continue;
        }
        targetDevices.push_back(dmDeviceInfo.networkId);
    }
    return targetDevices;
}

ProfileType ProfileUtils::GetProfileType(const std::string& key)
{
    if (key.length() == 0 || key.length() > MAX_STRING_LEN) {
        HILOGE("This key is invalid, value: %s!", key.c_str());
        return ProfileType::PROFILE_TYPE_MIN;
    }
    ProfileType profileType = ProfileType::PROFILE_TYPE_MIN;
    if (StartsWith(key, DEV_PREFIX)) {
        profileType = ProfileType::DEVICE_PROFILE;
    }
    if (StartsWith(key, SVR_PREFIX)) {
        profileType = ProfileType::SERVICE_PROFILE;
    }
    if (StartsWith(key, CHAR_PREFIX)) {
        profileType = ProfileType::CHAR_PROFILE;
    }
    return profileType;
}

bool ProfileUtils::StartsWith(const std::string& str, const std::string prefix)
{
    return (str.find(prefix, 0) == 0);
}

std::string ProfileUtils::GetProfileKey(const std::string& dbKey)
{
    if (dbKey.length() == 0 || dbKey.length() > MAX_STRING_LEN) {
        return "";
    }
    std::size_t pos = dbKey.find_last_of("#");
    return dbKey.substr(0, pos);
}

std::string ProfileUtils::GetDeviceIdByDBKey(const std::string& dbKey)
{
    if (dbKey.length() == 0 || dbKey.length() > MAX_STRING_LEN) {
        return "";
    }
    std::vector<std::string> res;
    if (SplitString(dbKey, SEPARATOR, res) != DP_SUCCESS) {
        return "";
    }
    if (res.size() < NUM_1) {
        return "";
    }
    return res[NUM_1];
}

std::string ProfileUtils::GetServiceNameByDBKey(const std::string& dbKey)
{
    if (dbKey.length() == 0 || dbKey.length() > MAX_STRING_LEN) {
        return "";
    }
    std::vector<std::string> res;
    if (SplitString(dbKey, SEPARATOR, res) != DP_SUCCESS) {
        return "";
    }
    if (res.size() < NUM_2) {
        return "";
    }
    return res[NUM_2];
}

std::string ProfileUtils::GetCharKeyByDBKey(const std::string& dbKey)
{
    if (dbKey.length() == 0 || dbKey.length() > MAX_STRING_LEN) {
        return "";
    }
    std::vector<std::string> res;
    if (SplitString(dbKey, SEPARATOR, res) != DP_SUCCESS) {
        return "";
    }
    if (res.size() < NUM_3) {
        return "";
    }
    return res[NUM_3];
}

int32_t ProfileUtils::SplitString(const std::string& str, const std::string& splits, std::vector<std::string>& res)
{
    if (str == "") {
        return DP_INVALID_PARAMS;
    }
    std::string strs = str + splits;
    size_t pos = strs.find(splits);
    int step = splits.size();

    while (pos != strs.npos)
    {
        std::string temp = strs.substr(0, pos);
        res.push_back(temp);
        strs = strs.substr(pos + step, strs.size());
        pos = strs.find(splits);
    }
    return DP_SUCCESS;
}

bool ProfileUtils::IsKeyValid(const std::string& key)
{
    if (key.length() == 0 || key.length() > MAX_STRING_LEN) {
        return false;
    }
    for (auto item : key) {
        if (item == '#') {
            return false;
        }
    }
    return true;
}

std::string ProfileUtils::GenerateDeviceProfileKey(const std::string& deviceId)
{
    return DEV_PREFIX + SEPARATOR + deviceId;
}

std::string ProfileUtils::GenerateServiceProfileKey(const std::string& deviceId, const std::string& serviceName)
{
    return DEV_PREFIX + SEPARATOR + deviceId + SEPARATOR + serviceName;
}

std::string ProfileUtils::GenerateCharProfileKey(const std::string& deviceId, const std::string& serviceName,
    const std::string& charKey)
{
    return DEV_PREFIX + SEPARATOR + deviceId + SEPARATOR + serviceName + SEPARATOR + charKey;
}

int32_t ProfileUtils::TrustDeviceProfileToEntries(const TrustDeviceProfile& profile, ValuesBucket& values)
{
    values.PutString(DEVICE_ID, profile.GetDeviceId());
    values.PutInt(DEVICE_ID_TYPE, profile.GetDeviceIdType());
    values.PutString(DEVICE_ID_HASH, profile.GetDeviceIdHash());
    values.PutInt(STATUS, profile.GetStatus());
    return DP_SUCCESS;
}

int32_t ProfileUtils::AccessControlProfileToEntries(const AccessControlProfile& profile, ValuesBucket& values)
{
    values.PutLong(ACCESS_CONTROL_ID, profile.GetAccessControlId());
    values.PutLong(ACCESSER_ID, profile.GetAccesserId());
    values.PutLong(ACCESSEE_ID, profile.GetAccesseeId());
    values.PutString(TRUST_DEVICE_ID, profile.GetTrustDeviceId());
    values.PutInt(AUTHENTICATION_TYPE, profile.GetAuthenticationType());
    values.PutInt(DEVICE_ID_TYPE, profile.GetDeviceIdType());
    values.PutString(DEVICE_ID_HASH, profile.GetDeviceIdHash());
    values.PutInt(BIND_TYPE, profile.GetBindType());
    values.PutString(SESSION_KEY, profile.GetSessionKey());
    values.PutInt(LAST_AUTH_TIME, profile.GetLastAuthTime());
    values.PutInt(VALID_PERIOD, profile.GetValidPeriod());
    values.PutInt(STATUS, profile.GetStatus());
    values.PutInt(BIND_LEVEL, profile.GetBindLevel());
    return DP_SUCCESS;
}

int32_t ProfileUtils::AccesserToEntries(const AccessControlProfile& aclProfile, ValuesBucket& values)
{
    Accesser accesser = aclProfile.GetAccesser();
    values.PutLong(ACCESSER_ID, accesser.GetAccesserId());
    values.PutString(ACCESSER_DEVICE_ID, accesser.GetAccesserDeviceId());
    values.PutInt(ACCESSER_USER_ID, accesser.GetAccesserUserId());
    values.PutString(ACCESSER_ACCOUNT_ID, accesser.GetAccesserAccountId());
    values.PutLong(ACCESSER_TOKEN_ID, accesser.GetAccesserTokenId());
    values.PutString(ACCESSER_BUNDLE_NAME, accesser.GetAccesserBundleName());
    values.PutString(ACCESSER_HAP_SIGNATURE, accesser.GetAccesserHapSignature());
    values.PutInt(ACCESSER_BIND_LEVEL, accesser.GetAccesserBindLevel());
    return DP_SUCCESS;
}

int32_t ProfileUtils::AccesseeToEntries(const AccessControlProfile& aclProfile, ValuesBucket& values)
{
    Accessee accessee = aclProfile.GetAccessee();
    values.PutLong(ACCESSEE_ID, accessee.GetAccesseeId());
    values.PutString(ACCESSEE_DEVICE_ID, accessee.GetAccesseeDeviceId());
    values.PutInt(ACCESSEE_USER_ID, accessee.GetAccesseeUserId());
    values.PutString(ACCESSEE_ACCOUNT_ID, accessee.GetAccesseeAccountId());
    values.PutLong(ACCESSEE_TOKEN_ID, accessee.GetAccesseeTokenId());
    values.PutString(ACCESSEE_BUNDLE_NAME, accessee.GetAccesseeBundleName());
    values.PutString(ACCESSER_HAP_SIGNATURE, accessee.GetAccesseeHapSignature());
    values.PutInt(ACCESSEE_BIND_LEVEL, accessee.GetAccesseeBindLevel());
    return DP_SUCCESS;
}

int32_t ProfileUtils::DeviceProfileToEntries(const DeviceProfile& profile, std::map<std::string, std::string>& values)
{
    std::string deviceProfileKey = GenerateDeviceProfileKey(profile.GetDeviceId());
    values[GenerateDBKey(deviceProfileKey, DEVICE_ID)] = profile.GetDeviceId();
    values[GenerateDBKey(deviceProfileKey, DEVICE_TYPE_ID)] = std::to_string(profile.GetDeviceTypeId());
    values[GenerateDBKey(deviceProfileKey, DEVICE_TYPE_NAME)] = profile.GetDeviceTypeName();
    values[GenerateDBKey(deviceProfileKey, DEVICE_NAME)] = profile.GetDeviceName();
    values[GenerateDBKey(deviceProfileKey, MANUFACTURE_NAME)] = profile.GetManufactureName();
    values[GenerateDBKey(deviceProfileKey, DEVICE_MODEL)] = profile.GetDeviceModel();
    values[GenerateDBKey(deviceProfileKey, SERIAL_NUMBER_ID)] = profile.GetSerialNumberId();
    values[GenerateDBKey(deviceProfileKey, STORAGE_CAPACITY)] = std::to_string(profile.GetStorageCapability());
    values[GenerateDBKey(deviceProfileKey, OS_SYS_CAPACITY)] = profile.GetOsSysCap();
    values[GenerateDBKey(deviceProfileKey, OS_API_LEVEL)] = std::to_string(profile.GetOsApiLevel());
    values[GenerateDBKey(deviceProfileKey, OS_VERSION)] = profile.GetOsVersion();
    values[GenerateDBKey(deviceProfileKey, OS_TYPE)] = std::to_string(profile.GetOsType());
    return DP_SUCCESS;
}

int32_t ProfileUtils::ServiceProfileToEntries(const ServiceProfile& profile, std::map<std::string, std::string>& values)
{
    std::string serviceProfileKey = GenerateServiceProfileKey(profile.GetDeviceId(), profile.GetServiceName());
    values[GenerateDBKey(serviceProfileKey, SERVICE_NAME)] = profile.GetServiceName();
    values[GenerateDBKey(serviceProfileKey, SERVICE_TYPE)] = profile.GetServiceType();
    return DP_SUCCESS;
}

int32_t ProfileUtils::CharacteristicProfileToEntries(const CharacteristicProfile& profile,
                                                     std::map<std::string, std::string>& values)
{
    std::string charProfileKey = GenerateCharProfileKey(profile.GetDeviceId(), profile.GetServiceName(),
        profile.GetCharacteristicKey());
    values[GenerateDBKey(charProfileKey, CHARACTERISTIC_KEY)] = profile.GetCharacteristicKey();
    values[GenerateDBKey(charProfileKey, CHARACTERISTIC_VALUE)] = profile.GetCharacteristicValue();
    return DP_SUCCESS;
}

int32_t ProfileUtils::EntriesToTrustDeviceProfile(const ValuesBucket& values, TrustDeviceProfile& profile)
{
    ValueObject valueObject;
    std::string strValue = "";
    int32_t intValue = 0;
    if (values.GetObject(DEVICE_ID, valueObject) && valueObject.GetString(strValue)) {
        profile.SetDeviceId(strValue);
    }
    if (values.GetObject(DEVICE_ID_HASH, valueObject) && valueObject.GetString(strValue)) {
        profile.SetDeviceIdHash(strValue);
    }
    if (values.GetObject(DEVICE_TYPE_ID, valueObject) && valueObject.GetInt(intValue)) {
        profile.SetDeviceIdType(intValue);
    }
    if (values.GetObject(STATUS, valueObject) && valueObject.GetInt(intValue)) {
        profile.SetStatus(intValue);
    }
    return DP_SUCCESS;
}

int32_t ProfileUtils::EntriesToAccessControlProfile(const ValuesBucket& values, AccessControlProfile& profile)
{
    ValueObject valueObject;
    std::string strValue = "";
    int32_t intValue = 0;
    int64_t int64Value = 0;

    if (values.GetObject(ACCESS_CONTROL_ID, valueObject) && valueObject.GetLong(int64Value)) {
        profile.SetAccessControlId(int64Value);
    }
    if (values.GetObject(ACCESSER_ID, valueObject) && valueObject.GetLong(int64Value)) {
        profile.SetAccesserId(int64Value);
    }
    if (values.GetObject(ACCESSEE_ID, valueObject) && valueObject.GetLong(int64Value)) {
        profile.SetAccesseeId(int64Value);
    }
    if (values.GetObject(SESSION_KEY, valueObject) && valueObject.GetString(strValue)) {
        profile.SetSessionKey(strValue);
    }
    if (values.GetObject(BIND_TYPE, valueObject) && valueObject.GetInt(intValue)) {
        profile.SetBindType(intValue);
    }
    if (values.GetObject(AUTHENTICATION_TYPE, valueObject) && valueObject.GetInt(intValue)) {
        profile.SetAuthenticationType(intValue);
    }
    if (values.GetObject(BIND_LEVEL, valueObject) && valueObject.GetInt(intValue)) {
        profile.SetBindLevel(intValue);
    }
    if (values.GetObject(STATUS, valueObject) && valueObject.GetInt(intValue)) {
        profile.SetStatus(intValue);
    }
    if (values.GetObject(VALID_PERIOD, valueObject) && valueObject.GetInt(intValue)) {
        profile.SetValidPeriod(intValue);
    }
    if (values.GetObject(LAST_AUTH_TIME, valueObject) && valueObject.GetInt(intValue)) {
        profile.SetLastAuthTime(intValue);
    }
    if (values.GetObject(TRUST_DEVICE_ID, valueObject) && valueObject.GetString(strValue)) {
        profile.SetTrustDeviceId(strValue);
    }
    if (values.GetObject(DEVICE_TYPE_ID, valueObject) && valueObject.GetInt(intValue)) {
        profile.SetDeviceIdType(intValue);
    }
    if (values.GetObject(DEVICE_ID_HASH, valueObject) && valueObject.GetString(strValue)) {
        profile.SetDeviceIdHash(strValue);
    }
    Accesser accesser;
    EntriesToAccesser(values, accesser);
    profile.SetAccesser(accesser);
    Accessee accessee;
    EntriesToAccessee(values, accessee);
    profile.SetAccessee(accessee);
    return DP_SUCCESS;
}

int32_t ProfileUtils::EntriesToAccesser(const ValuesBucket& values, Accesser& accesser)
{
    ValueObject valueObject;
    std::string strValue = "";
    int32_t intValue = 0;
    int64_t int64Value = 0;
    if (values.GetObject(ACCESSER_ID, valueObject) && valueObject.GetLong(int64Value)) {
        accesser.SetAccesserId(int64Value);
    }
    if (values.GetObject(ACCESSER_DEVICE_ID, valueObject) && valueObject.GetString(strValue)) {
        accesser.SetAccesserDeviceId(strValue);
    }
    if (values.GetObject(ACCESSER_USER_ID, valueObject) && valueObject.GetInt(intValue)) {
        accesser.SetAccesserUserId(intValue);
    }
    if (values.GetObject(ACCESSER_ACCOUNT_ID, valueObject) && valueObject.GetString(strValue)) {
        accesser.SetAccesserAccountId(strValue);
    }
    if (values.GetObject(ACCESSER_TOKEN_ID, valueObject) && valueObject.GetLong(int64Value)) {
        accesser.SetAccesserTokenId(int64Value);
    }
    if (values.GetObject(ACCESSER_BUNDLE_NAME, valueObject) && valueObject.GetString(strValue)) {
        accesser.SetAccesserBundleName(strValue);
    }
    if (values.GetObject(ACCESSER_BIND_LEVEL, valueObject) && valueObject.GetInt(intValue)) {
        accesser.SetAccesserBindLevel(intValue);
    }
    return DP_SUCCESS;
}

int32_t ProfileUtils::EntriesToAccessee(const ValuesBucket& values, Accessee& accessee)
{
    ValueObject valueObject;
    std::string strValue = "";
    int32_t intValue = 0;
    int64_t int64Value = 0;
    if (values.GetObject(ACCESSEE_ID, valueObject) && valueObject.GetLong(int64Value)) {
        accessee.SetAccesseeId(int64Value);
    }
    if (values.GetObject(ACCESSER_DEVICE_ID, valueObject) && valueObject.GetString(strValue)) {
        accessee.SetAccesseeDeviceId(strValue);
    }
    if (values.GetObject(ACCESSER_USER_ID, valueObject) && valueObject.GetInt(intValue)) {
        accessee.SetAccesseeUserId(intValue);
    }
    if (values.GetObject(ACCESSER_ACCOUNT_ID, valueObject) && valueObject.GetString(strValue)) {
        accessee.SetAccesseeAccountId(strValue);
    }
    if (values.GetObject(ACCESSER_TOKEN_ID, valueObject) && valueObject.GetLong(int64Value)) {
        accessee.SetAccesseeTokenId(int64Value);
    }
    if (values.GetObject(ACCESSER_BUNDLE_NAME, valueObject) && valueObject.GetString(strValue)) {
        accessee.SetAccesseeBundleName(strValue);
    }
    if (values.GetObject(ACCESSER_BIND_LEVEL, valueObject) && valueObject.GetInt(intValue)) {
        accessee.SetAccesseeBindLevel(intValue);
    }
    return DP_SUCCESS;
}

int32_t ProfileUtils::EntriesToDeviceProfile(std::map<std::string, std::string> values, DeviceProfile& profile)
{
    if (values.empty() || values.size() > MAX_DB_RECORD_SIZE) {
        HILOGI("Entries size is invalid!");
        return DP_INVALID_PARAMS;
    }
    auto propertiesMap = GetProfilePropertiesMap(values);
    if (propertiesMap.count(DEVICE_ID) != 0 && 0 < propertiesMap[DEVICE_ID].length() &&
        propertiesMap[DEVICE_ID].length() < MAX_STRING_LEN) {
        profile.SetDeviceId(propertiesMap[DEVICE_ID]);
    }
    uint32_t deviceTypeId = std::atoi(propertiesMap[DEVICE_TYPE_ID].c_str());
    if (propertiesMap.count(DEVICE_TYPE_ID) != 0 && static_cast<uint32_t>(DeviceIdType::MIN) < deviceTypeId &&
        deviceTypeId < static_cast<uint32_t>(DeviceIdType::MAX)) {
        profile.SetDeviceTypeId(deviceTypeId);
    }
    if (propertiesMap.count(DEVICE_TYPE_NAME) != 0 && 0 < propertiesMap[DEVICE_TYPE_NAME].length() &&
        propertiesMap[DEVICE_TYPE_NAME].length() < MAX_STRING_LEN) {
        profile.SetDeviceTypeName(propertiesMap[DEVICE_TYPE_NAME]);
    }
    if (propertiesMap.count(DEVICE_NAME) != 0 && 0 < propertiesMap[DEVICE_NAME].length() &&
        propertiesMap[DEVICE_NAME].length() < MAX_STRING_LEN) {
        profile.SetDeviceName(propertiesMap[DEVICE_NAME]);
    }
    if (propertiesMap.count(MANUFACTURE_NAME) != 0 && 0 < propertiesMap[MANUFACTURE_NAME].length() &&
        propertiesMap[MANUFACTURE_NAME].length() < MAX_STRING_LEN) {
        profile.SetManufactureName(propertiesMap[MANUFACTURE_NAME]);
    }
    if (propertiesMap.count(DEVICE_MODEL) != 0 && 0 < propertiesMap[DEVICE_MODEL].length() &&
        propertiesMap[DEVICE_MODEL].length() < MAX_STRING_LEN) {
        profile.SetDeviceModel(propertiesMap[DEVICE_MODEL]);
    }
    if (propertiesMap.count(SERIAL_NUMBER_ID) != 0 && 0 < propertiesMap[SERIAL_NUMBER_ID].length() &&
        propertiesMap[SERIAL_NUMBER_ID].length() < MAX_STRING_LEN) {
        profile.SetSerialNumberId(propertiesMap[SERIAL_NUMBER_ID]);
    }
    int64_t storageCapability = std::atoi(propertiesMap[DEVICE_TYPE_ID].c_str());
    if (propertiesMap.count(STORAGE_CAPACITY) != 0 && 0 < storageCapability && storageCapability < MAX_STORAGE_LEN) {
        profile.SetStorageCapability(storageCapability);
    }
    if (propertiesMap.count(OS_SYS_CAPACITY) != 0 && 0 < propertiesMap[OS_SYS_CAPACITY].length() &&
        propertiesMap[OS_SYS_CAPACITY].length() < MAX_STRING_LEN) {
        profile.SetOsSysCap(propertiesMap[OS_SYS_CAPACITY]);
    }
    int32_t osApiLevel = std::atoi(propertiesMap[OS_API_LEVEL].c_str());
    if (propertiesMap.count(OS_API_LEVEL) != 0 && 0 < osApiLevel && osApiLevel < MAX_OS_API_LEVEL) {
        profile.SetOsApiLevel(osApiLevel);
    }
    if (propertiesMap.count(OS_VERSION) != 0 && 0 < propertiesMap[OS_VERSION].length() &&
        propertiesMap[OS_VERSION].length() < MAX_STRING_LEN) {
        profile.SetOsVersion(propertiesMap[OS_VERSION]);
    }
    int32_t osType = std::atoi(propertiesMap[OS_TYPE].c_str());
    if (propertiesMap.count(OS_TYPE) != 0 && 0 < osType && osType < MAX_OS_TYPE) {
        profile.SetOsType(osType);
    }
    return DP_SUCCESS;
}

int32_t ProfileUtils::EntriesToServiceProfile(std::map<std::string, std::string> values, ServiceProfile& profile)
{
    if (values.empty() || values.size() > MAX_DB_RECORD_SIZE) {
        HILOGI("Entries size is invalid!");
        return DP_INVALID_PARAMS;
    }
    auto iter = values.begin();
    profile.SetDeviceId(GetDeviceIdByDBKey(iter->first));
    auto propertiesMap = GetProfilePropertiesMap(values);
    if (propertiesMap.count(SERVICE_NAME) != 0 && 0 < values[SERVICE_NAME].length() &&
        values[SERVICE_NAME].length() < MAX_STRING_LEN) {
        profile.SetServiceName(propertiesMap[SERVICE_NAME]);
    }
    if (propertiesMap.count(SERVICE_TYPE) != 0 && 0 < propertiesMap[SERVICE_TYPE].length() &&
        propertiesMap[SERVICE_TYPE].length() < MAX_STRING_LEN) {
        profile.SetServiceType(propertiesMap[SERVICE_TYPE]);
    }
    return DP_SUCCESS;
}

int32_t ProfileUtils::EntriesToCharProfile(std::map<std::string, std::string> values, CharacteristicProfile& profile)
{
    if (values.empty() || values.size() > MAX_DB_RECORD_SIZE) {
        HILOGI("Entries size is invalid!");
        return DP_INVALID_PARAMS;
    }
    auto iter = values.begin();
    profile.SetDeviceId(GetDeviceIdByDBKey(iter->first));
    profile.SetServiceName(GetServiceNameByDBKey(iter->first));
    auto propertiesMap = GetProfilePropertiesMap(values);
    if (values.count(CHARACTERISTIC_KEY) != 0 && 0 < values[CHARACTERISTIC_KEY].length() &&
        values[CHARACTERISTIC_KEY].length() < MAX_STRING_LEN) {
        profile.SetCharacteristicKey(propertiesMap[CHARACTERISTIC_KEY]);
    }
    if (values.count(CHARACTERISTIC_VALUE) != 0 && 0 < values[CHARACTERISTIC_VALUE].length() &&
        values[CHARACTERISTIC_VALUE].length() < MAX_STRING_LEN) {
        profile.SetCharacteristicValue(propertiesMap[CHARACTERISTIC_VALUE]);
    }
    return DP_SUCCESS;
}

std::string ProfileUtils::GenerateDBKey(const std::string& profileKey, const std::string& profileProperty)
{
    return profileKey + SEPARATOR + profileProperty;
}

std::string ProfileUtils::GetProfileProperty(const std::string& dbKey)
{
    if (dbKey.length() == 0 || dbKey.length() > MAX_STRING_LEN) {
        return "";
    }
    std::size_t pos = dbKey.find_last_of("#");
    return dbKey.substr(pos + 1);
}

std::map<std::string, std::string> ProfileUtils::GetProfilePropertiesMap(std::map<std::string, std::string> dbEntries)
{
    std::map<std::string, std::string> propertiesMap;
    for (const auto& item : dbEntries) {
        std::string profileProperty = GetProfileProperty(item.first);
        if (profileProperty.empty()) {
            HILOGE("GetProfileProperty fail, %s!", item.first.c_str());
            continue;
        }
        propertiesMap[profileProperty] = item.second;
    }
    return propertiesMap;
}

std::string ProfileUtils::toString(const std::u16string& str16)
{
    return std::wstring_convert< std::codecvt_utf8_utf16<char16_t>, char16_t >{}.to_bytes(str16);
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
