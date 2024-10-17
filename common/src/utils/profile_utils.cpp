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

#include "profile_utils.h"

#include <codecvt>
#include <locale>
#include <regex>
#include <unordered_set>

#include "cJSON.h"
#include "device_manager.h"
#include "dm_constants.h"
#include "rdb_errno.h"

#include "content_sensor_manager_utils.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_enums.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace OHOS::DistributedHardware;

namespace {
    const std::string TAG = "ProfileUtils";
    const std::unordered_set<std::string> NEED_ADD_OH_SUFFIX_DEV_PROFILES { OS_TYPE, OS_VERSION };
    const std::unordered_set<std::string> NEED_ADD_OH_SUFFIX_SVR_NAMES { "DistributeModemService",
        "multiScreenAssistantService", "appInfo" };
}

std::string ProfileUtils::GetDbKeyAnonyString(const std::string& dbKey)
{
    constexpr size_t DEVICE_ID_INDEX = 1;
    std::vector<std::string> splitKeys;
    if (ProfileUtils::SplitString(dbKey, SEPARATOR, splitKeys) != DP_SUCCESS ||
        splitKeys.size() <= DEVICE_ID_INDEX) {
        return GetAnonyString(dbKey);
    }
    for (size_t i = DEVICE_ID_INDEX; i < splitKeys.size(); i++) {
        splitKeys[i] = GetAnonyString(splitKeys[i]);
    }
    return JoinString(splitKeys, SEPARATOR);
}

std::string ProfileUtils::GetAnonyString(const std::string& value)
{
    constexpr size_t INT32_SHORT_ID_LENGTH = 10;
    constexpr size_t INT32_PLAINTEXT_LENGTH = 4;
    constexpr size_t INT32_MIN_ID_LENGTH = 3;
    std::string res;
    std::string tmpStr("***");
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
    int32_t result = DeviceManager::GetInstance().GetTrustedDeviceList(DP_PKG_NAME, "", allOnlineDeviceInfos);
    if (result != DP_SUCCESS || allOnlineDeviceInfos.empty()) {
        HILOGE("GetTrustedDeviceList Failed!");
        return {};
    }
    for (const DmDeviceInfo& dmDeviceInfo : allOnlineDeviceInfos) {
        targetDevices.push_back(dmDeviceInfo.networkId);
    }
    return targetDevices;
}

std::string ProfileUtils::GetLocalUdidFromDM()
{
    std::string udid = "";
    if (DeviceManager::GetInstance().GetLocalDeviceId(DP_PKG_NAME, udid) != DP_SUCCESS) {
        HILOGE("Get local udid fail from DM!");
        return "";
    }
    return udid;
}

bool ProfileUtils::FilterAndGroupOnlineDevices(const std::vector<std::string>& deviceList,
    std::vector<std::string>& ohBasedDevices, std::vector<std::string>& notOHBasedDevices)
{
    if (deviceList.size() == 0 || deviceList.size() > MAX_DEVICE_SIZE) {
        HILOGE("This deviceList size is invalid, size: %{public}zu!", deviceList.size());
        return false;
    }
    std::vector<DmDeviceInfo> allOnlineDeviceInfos;
    int32_t result = DeviceManager::GetInstance().GetTrustedDeviceList(DP_PKG_NAME, "", allOnlineDeviceInfos);
    if (result != DP_SUCCESS || allOnlineDeviceInfos.empty()) {
        HILOGE("GetTrustedDeviceList Failed!");
        return false;
    }
    for (const DmDeviceInfo& dmDeviceInfo : allOnlineDeviceInfos) {
        if (std::find(deviceList.begin(), deviceList.end(), dmDeviceInfo.networkId) == deviceList.end()) {
            continue;
        }
        if (dmDeviceInfo.extraData.empty()) {
            HILOGW("extraData is empty! networkId:%{public}s", GetAnonyString(dmDeviceInfo.networkId).c_str());
            continue;
        }
        if (IsOHBasedDevice(dmDeviceInfo.extraData)) {
            ohBasedDevices.push_back(dmDeviceInfo.networkId);
        } else {
            notOHBasedDevices.push_back(dmDeviceInfo.networkId);
        }
    }
    return true;
}

bool ProfileUtils::IsOHBasedDevice(const std::string& extraData)
{
    if (extraData.empty()) {
        HILOGE("extraData is empty!");
        return false;
    }
    cJSON* extraDataJson = cJSON_Parse(extraData.c_str());
    if (extraDataJson == NULL) {
        HILOGE("extraData parse failed");
        return false;
    }
    int32_t osType = OHOS_TYPE_UNKNOWN;
    cJSON* osTypeJson = cJSON_GetObjectItem(extraDataJson, DistributedHardware::PARAM_KEY_OS_TYPE);
    if (cJSON_IsNumber(osTypeJson)) {
        osType = static_cast<int32_t>(osTypeJson->valueint);
    }
    cJSON_Delete(extraDataJson);
    return osType == OHOS_TYPE;
}

bool ProfileUtils::IsP2p(const int32_t authForm)
{
    if (authForm == static_cast<int32_t>(DistributedHardware::DmAuthForm::INVALID_TYPE) ||
        authForm == static_cast<int32_t>(DistributedHardware::DmAuthForm::IDENTICAL_ACCOUNT)) {
        HILOGD("authForm: %{public}d!", authForm);
        return false;
    }
    return true;
}

ProfileType ProfileUtils::GetProfileType(const std::string& key)
{
    if (key.length() == 0 || key.length() > MAX_STRING_LEN) {
        HILOGE("This key is invalid, value: %{public}s!", GetAnonyString(key).c_str());
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

bool ProfileUtils::StartsWith(const std::string& str, const std::string& prefix)
{
    return (str.find(prefix, 0) == 0);
}

bool ProfileUtils::EndsWith(const std::string& str, const std::string& suffix)
{
    if (str.length() < suffix.length()) {
        return false;
    }
    return str.substr(str.length() - suffix.length()).compare(suffix) == 0;
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

std::string ProfileUtils::GetNonOhSuffixServiceNameByDBKey(const std::string& dbKey)
{
    std::string serviceName = GetServiceNameByDBKey(dbKey);
    if (serviceName.empty()) {
        return "";
    }
    return CheckAndRemoveOhSuffix(serviceName);
}

bool ProfileUtils::IsNeedAddOhSuffix(const std::string& profileName, bool isSvr)
{
    if (profileName.length() == 0 || profileName.length() > MAX_STRING_LEN) {
        return false;
    }
    if (isSvr && NEED_ADD_OH_SUFFIX_SVR_NAMES.count(profileName) > 0) {
        return true;
    }
    if (!isSvr && NEED_ADD_OH_SUFFIX_DEV_PROFILES.count(profileName) > 0) {
        return true;
    }
    return false;
}

std::string ProfileUtils::CheckAndAddOhSuffix(const std::string& profileName, bool isSvr)
{
    std::string str = profileName;
    if (IsNeedAddOhSuffix(str, isSvr)) {
        str = str + OH_PROFILE_SUFFIX;
    }
    return str;
}

std::string ProfileUtils::CheckAndRemoveOhSuffix(const std::string& profileName)
{
    std::string str = profileName;
    if (EndsWith(str, OH_PROFILE_SUFFIX)) {
        str = str.erase(str.length() - OH_PROFILE_SUFFIX.length());
    }
    return str;
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
    int32_t step = splits.size();

    while (pos != strs.npos) {
        std::string temp = strs.substr(0, pos);
        res.push_back(temp);
        strs = strs.substr(pos + step, strs.size());
        pos = strs.find(splits);
    }
    return DP_SUCCESS;
}

std::string ProfileUtils::JoinString(const std::vector<std::string>& strs, const std::string& delimiter)
{
    std::string res = EMPTY_STRING;
    if (strs.empty()) {
        return res;
    }
    for (size_t i = 0; i < strs.size(); i++) {
        res += strs[i];
        if (i != strs.size() - 1) {
            res += delimiter;
        }
    }
    return res;
}

bool ProfileUtils::IsKeyValid(const std::string& key)
{
    if (key.length() == 0 || key.length() > MAX_STRING_LEN) {
        return false;
    }
    size_t found = key.find(SEPARATOR);
    if (found != std::string::npos) {
        return false;
    }
    return true;
}

bool ProfileUtils::IsLocalUdid(const std::string& udid)
{
    if (udid.length() == 0 || udid.length() > MAX_STRING_LEN) {
        return false;
    }
    std::string localUdid = ContentSensorManagerUtils::GetInstance().ObtainLocalUdid();
    return localUdid == udid;
}

bool ProfileUtils::IsDevProfileValid(const DeviceProfile& devProfile)
{
    return IsKeyValid(devProfile.GetDeviceId()) && IsLocalUdid(devProfile.GetDeviceId());
}

bool ProfileUtils::IsSvrProfileValid(const ServiceProfile& svrProfile)
{
    return IsKeyValid(svrProfile.GetDeviceId()) && IsLocalUdid(svrProfile.GetDeviceId()) &&
        IsKeyValid(svrProfile.GetServiceName());
}

bool ProfileUtils::IsCharProfileValid(const CharacteristicProfile& charProfile)
{
    return IsKeyValid(charProfile.GetDeviceId()) && IsLocalUdid(charProfile.GetDeviceId()) &&
        IsKeyValid(charProfile.GetServiceName()) && IsKeyValid(charProfile.GetCharacteristicKey());
}

bool ProfileUtils::IsDeviceProfileValid(const DeviceProfile& devProfile)
{
    if (devProfile.GetOsVersion().empty() || devProfile.GetOsType() == MIN_OS_TYPE) {
        return false;
    }
    return true;
}

bool ProfileUtils::IsServiceProfileValid(const ServiceProfile& svrProfile)
{
    if (svrProfile.GetServiceName().empty() || svrProfile.GetServiceType().empty()) {
        return false;
    }
    return true;
}

bool ProfileUtils::IsCharacteristicProfileValid(const CharacteristicProfile& charProfile)
{
    if (charProfile.GetCharacteristicKey().empty() || charProfile.GetCharacteristicValue().empty()) {
        return false;
    }
    return true;
}

std::string ProfileUtils::GenerateDeviceProfileKey(const std::string& deviceId)
{
    return DEV_PREFIX + SEPARATOR + deviceId;
}

std::string ProfileUtils::GenerateServiceProfileKey(const std::string& deviceId, const std::string& serviceName)
{
    return SVR_PREFIX + SEPARATOR + deviceId + SEPARATOR + serviceName;
}

std::string ProfileUtils::GenerateCharProfileKey(const std::string& deviceId, const std::string& serviceName,
    const std::string& charKey)
{
    return CHAR_PREFIX + SEPARATOR + deviceId + SEPARATOR + serviceName + SEPARATOR + charKey;
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
    values.PutString(ACCESSEE_HAP_SIGNATURE, accessee.GetAccesseeHapSignature());
    values.PutInt(ACCESSEE_BIND_LEVEL, accessee.GetAccesseeBindLevel());
    return DP_SUCCESS;
}

int32_t ProfileUtils::DeviceProfileToEntries(const DeviceProfile& profile, std::map<std::string, std::string>& values)
{
    std::string deviceProfileKey = GenerateDeviceProfileKey(profile.GetDeviceId());
    values[GenerateDBKey(deviceProfileKey, OS_SYS_CAPACITY)] = profile.GetOsSysCap();
    values[GenerateDBKey(deviceProfileKey, OS_VERSION)] = profile.GetOsVersion();
    values[GenerateDBKey(deviceProfileKey, OS_TYPE)] = std::to_string(profile.GetOsType());
    values[GenerateDBKey(deviceProfileKey, OS_VERSION + OH_PROFILE_SUFFIX)] = profile.GetOsVersion();
    values[GenerateDBKey(deviceProfileKey, OS_TYPE + OH_PROFILE_SUFFIX)] = std::to_string(profile.GetOsType());
    return DP_SUCCESS;
}

int32_t ProfileUtils::ServiceProfileToEntries(const ServiceProfile& profile, std::map<std::string, std::string>& values)
{
    std::string serviceName = CheckAndAddOhSuffix(profile.GetServiceName(), true);
    std::string serviceProfileKey = GenerateServiceProfileKey(profile.GetDeviceId(), serviceName);
    // value not need add OH suffix
    values[GenerateDBKey(serviceProfileKey, SERVICE_NAME)] = profile.GetServiceName();
    values[GenerateDBKey(serviceProfileKey, SERVICE_TYPE)] = profile.GetServiceType();
    return DP_SUCCESS;
}

int32_t ProfileUtils::CharacteristicProfileToEntries(const CharacteristicProfile& profile,
                                                     std::map<std::string, std::string>& values)
{
    std::string serviceName = CheckAndAddOhSuffix(profile.GetServiceName(), true);
    std::string charProfileKey = GenerateCharProfileKey(profile.GetDeviceId(), serviceName,
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
    if (values.GetObject(DEVICE_ID, valueObject) && valueObject.GetString(strValue) == NativeRdb::E_OK) {
        profile.SetDeviceId(strValue);
    }
    if (values.GetObject(DEVICE_ID_HASH, valueObject) && valueObject.GetString(strValue) == NativeRdb::E_OK) {
        profile.SetDeviceIdHash(strValue);
    }
    if (values.GetObject(DEVICE_TYPE_ID, valueObject) && valueObject.GetInt(intValue) == NativeRdb::E_OK) {
        profile.SetDeviceIdType(intValue);
    }
    if (values.GetObject(STATUS, valueObject) && valueObject.GetInt(intValue) == NativeRdb::E_OK) {
        profile.SetStatus(intValue);
    }
    return DP_SUCCESS;
}

int32_t ProfileUtils::EntriesToAccessControlProfile(const ValuesBucket& values, AccessControlProfile& profile)
{
    std::string strValue = "";
    int32_t intValue = 0;
    int64_t int64Value = 0;
    if (GetLongValue(values, ACCESS_CONTROL_ID, int64Value)) {
        profile.SetAccessControlId(int64Value);
    }
    if (GetLongValue(values, ACCESSER_ID, int64Value)) {
        profile.SetAccesserId(int64Value);
    }
    if (GetLongValue(values, ACCESSEE_ID, int64Value)) {
        profile.SetAccesseeId(int64Value);
    }
    if (GetStringValue(values, SESSION_KEY, strValue)) {
        profile.SetSessionKey(strValue);
    }
    if (GetIntValue(values, BIND_TYPE, intValue)) {
        profile.SetBindType(intValue);
    }
    if (GetIntValue(values, AUTHENTICATION_TYPE, intValue)) {
        profile.SetAuthenticationType(intValue);
    }
    if (GetIntValue(values, BIND_LEVEL, intValue)) {
        profile.SetBindLevel(intValue);
    }
    if (GetIntValue(values, STATUS, intValue)) {
        profile.SetStatus(intValue);
    }
    if (GetIntValue(values, VALID_PERIOD, intValue)) {
        profile.SetValidPeriod(intValue);
    }
    if (GetIntValue(values, LAST_AUTH_TIME, intValue)) {
        profile.SetLastAuthTime(intValue);
    }
    if (GetStringValue(values, TRUST_DEVICE_ID, strValue)) {
        profile.SetTrustDeviceId(strValue);
    }
    if (GetIntValue(values, DEVICE_TYPE_ID, intValue)) {
        profile.SetDeviceIdType(intValue);
    }
    if (GetStringValue(values, DEVICE_ID_HASH, strValue)) {
        profile.SetDeviceIdHash(strValue);
    }
    return DP_SUCCESS;
}

int32_t ProfileUtils::EntriesToAccesser(const ValuesBucket& values, Accesser& accesser)
{
    ValueObject valueObject;
    std::string strValue = "";
    int32_t intValue = 0;
    int64_t int64Value = 0;
    if (values.GetObject(ACCESSER_ID, valueObject) && valueObject.GetLong(int64Value) == NativeRdb::E_OK) {
        accesser.SetAccesserId(int64Value);
    }
    if (values.GetObject(ACCESSER_DEVICE_ID, valueObject) && valueObject.GetString(strValue) == NativeRdb::E_OK) {
        accesser.SetAccesserDeviceId(strValue);
    }
    if (values.GetObject(ACCESSER_USER_ID, valueObject) && valueObject.GetInt(intValue) == NativeRdb::E_OK) {
        accesser.SetAccesserUserId(intValue);
    }
    if (values.GetObject(ACCESSER_ACCOUNT_ID, valueObject) && valueObject.GetString(strValue) == NativeRdb::E_OK) {
        accesser.SetAccesserAccountId(strValue);
    }
    if (values.GetObject(ACCESSER_TOKEN_ID, valueObject) && valueObject.GetLong(int64Value) == NativeRdb::E_OK) {
        accesser.SetAccesserTokenId(int64Value);
    }
    if (values.GetObject(ACCESSER_BUNDLE_NAME, valueObject) && valueObject.GetString(strValue) == NativeRdb::E_OK) {
        accesser.SetAccesserBundleName(strValue);
    }
    if (values.GetObject(ACCESSER_BIND_LEVEL, valueObject) && valueObject.GetInt(intValue) == NativeRdb::E_OK) {
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
    if (values.GetObject(ACCESSEE_ID, valueObject) && valueObject.GetLong(int64Value) == NativeRdb::E_OK) {
        accessee.SetAccesseeId(int64Value);
    }
    if (values.GetObject(ACCESSEE_DEVICE_ID, valueObject) && valueObject.GetString(strValue) == NativeRdb::E_OK) {
        accessee.SetAccesseeDeviceId(strValue);
    }
    if (values.GetObject(ACCESSEE_USER_ID, valueObject) && valueObject.GetInt(intValue) == NativeRdb::E_OK) {
        accessee.SetAccesseeUserId(intValue);
    }
    if (values.GetObject(ACCESSEE_ACCOUNT_ID, valueObject) && valueObject.GetString(strValue) == NativeRdb::E_OK) {
        accessee.SetAccesseeAccountId(strValue);
    }
    if (values.GetObject(ACCESSEE_TOKEN_ID, valueObject) && valueObject.GetLong(int64Value) == NativeRdb::E_OK) {
        accessee.SetAccesseeTokenId(int64Value);
    }
    if (values.GetObject(ACCESSEE_BUNDLE_NAME, valueObject) && valueObject.GetString(strValue) == NativeRdb::E_OK) {
        accessee.SetAccesseeBundleName(strValue);
    }
    if (values.GetObject(ACCESSEE_BIND_LEVEL, valueObject) && valueObject.GetInt(intValue) == NativeRdb::E_OK) {
        accessee.SetAccesseeBindLevel(intValue);
    }
    return DP_SUCCESS;
}

int32_t ProfileUtils::EntriesToDeviceProfile(std::map<std::string, std::string> values, DeviceProfile& profile)
{
    if (values.empty() || values.size() > MAX_DB_RECORD_SIZE) {
        HILOGI("Entries size is invalid!size: %{public}zu!", values.size());
        return DP_INVALID_PARAMS;
    }
    auto propertiesMap = GetProfilePropertiesMap(values);
    if (IsPropertyValid(propertiesMap, OS_SYS_CAPACITY, MAX_STRING_LEN)) {
        profile.SetOsSysCap(propertiesMap[OS_SYS_CAPACITY]);
    }
    if (IsPropertyValid(propertiesMap, OS_VERSION, MAX_STRING_LEN)) {
        profile.SetOsVersion(propertiesMap[OS_VERSION]);
    }
    if (IsPropertyValid(propertiesMap, OS_VERSION + OH_PROFILE_SUFFIX, MAX_STRING_LEN)) {
        profile.SetOsVersion(propertiesMap[OS_VERSION + OH_PROFILE_SUFFIX]);
    }
    if (IsPropertyValid(propertiesMap, OS_TYPE, MIN_OS_TYPE, MAX_OS_TYPE)) {
        int32_t osType = std::atoi(propertiesMap[OS_TYPE].c_str());
        profile.SetOsType(osType);
    }
    if (IsPropertyValid(propertiesMap, OS_TYPE + OH_PROFILE_SUFFIX, MIN_OS_TYPE, MAX_OS_TYPE)) {
        int32_t osType = std::atoi(propertiesMap[OS_TYPE + OH_PROFILE_SUFFIX].c_str());
        profile.SetOsType(osType);
    }
    return DP_SUCCESS;
}

int32_t ProfileUtils::EntriesToServiceProfile(std::map<std::string, std::string> values, ServiceProfile& profile)
{
    if (values.empty() || values.size() > MAX_DB_RECORD_SIZE) {
        HILOGI("Entries size is invalid!size: %{public}zu!", values.size());
        return DP_INVALID_PARAMS;
    }
    auto iter = values.begin();
    profile.SetDeviceId(GetDeviceIdByDBKey(iter->first));
    auto propertiesMap = GetProfilePropertiesMap(values);
    if (propertiesMap.count(SERVICE_NAME) != 0 && 0 < propertiesMap[SERVICE_NAME].length() &&
        propertiesMap[SERVICE_NAME].length() < MAX_STRING_LEN) {
        profile.SetServiceName(CheckAndRemoveOhSuffix(propertiesMap[SERVICE_NAME]));
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
        HILOGI("Entries size is invalid!size : %{public}zu", values.size());
        return DP_INVALID_PARAMS;
    }
    auto iter = values.begin();
    profile.SetDeviceId(GetDeviceIdByDBKey(iter->first));
    profile.SetServiceName(GetNonOhSuffixServiceNameByDBKey(iter->first));
    auto propertiesMap = GetProfilePropertiesMap(values);
    if (propertiesMap.count(CHARACTERISTIC_KEY) != 0 && 0 < propertiesMap[CHARACTERISTIC_KEY].length() &&
        propertiesMap[CHARACTERISTIC_KEY].length() < MAX_STRING_LEN) {
        profile.SetCharacteristicKey(propertiesMap[CHARACTERISTIC_KEY]);
    }
    if (propertiesMap.count(CHARACTERISTIC_VALUE) != 0 && 0 < propertiesMap[CHARACTERISTIC_VALUE].length() &&
        propertiesMap[CHARACTERISTIC_VALUE].length() < MAX_STRING_LEN) {
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
    if (pos == std::string::npos) {
        return "";
    }
    return dbKey.substr(pos + 1);
}

std::map<std::string, std::string> ProfileUtils::GetProfilePropertiesMap(std::map<std::string, std::string> dbEntries)
{
    std::map<std::string, std::string> propertiesMap;
    for (const auto& item : dbEntries) {
        std::string profileProperty = GetProfileProperty(item.first);
        if (profileProperty.empty()) {
            HILOGE("GetProfileProperty fail, %{public}s!", GetDbKeyAnonyString(item.first).c_str());
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

bool ProfileUtils::IsPropertyValid(const std::map<std::string, std::string>& propertyMap, const std::string& property,
    int32_t maxValue)
{
    if (propertyMap.count(property) != 0 && 0 < propertyMap.at(property).length() &&
        (static_cast<int32_t>(propertyMap.at(property).length())) < maxValue) {
        return true;
    }
    HILOGE("property is valid, property : %{public}s", property.c_str());
    return false;
}

bool ProfileUtils::IsPropertyValid(const std::map<std::string, std::string>& propertyMap, const std::string& property,
    int32_t minValue, int32_t maxValue)
{
    if (property.empty() || propertyMap.find(property) == propertyMap.end()) {
        HILOGE("property is valid, property : %{public}s", property.c_str());
        return false;
    }
    std::string propertyValue = propertyMap.at(property);
    if (!IsNumStr(propertyValue)) {
        HILOGE("%{public}s is not numeric string", GetAnonyString(propertyValue).c_str());
        return false;
    }
    if (minValue < std::atoi(propertyValue.c_str()) && std::atoi(propertyValue.c_str()) < maxValue) {
        return true;
    }
    return false;
}

bool ProfileUtils::IsNumStr(const std::string& inString)
{
    if (inString.empty()) {
        HILOGE("inString is empty");
        return false;
    }
    std::regex isNumStrRule(IS_NUMSTRING_RULES);
    return std::regex_match(inString, isNumStrRule);
}

bool ProfileUtils::GetIntValue(const ValuesBucket& values, const std::string& property, int32_t& value)
{
    ValueObject valueObject;
    if (values.GetObject(property, valueObject) && valueObject.GetInt(value) == NativeRdb::E_OK) {
        return true;
    }
    return false;
}

bool ProfileUtils::GetStringValue(const ValuesBucket& values, const std::string& property, std::string& value)
{
    ValueObject valueObject;
    if (values.GetObject(property, valueObject) && valueObject.GetString(value) == NativeRdb::E_OK) {
        return true;
    }
    return false;
}

bool ProfileUtils::GetLongValue(const ValuesBucket& values, const std::string& property, int64_t& value)
{
    ValueObject valueObject;
    if (values.GetObject(property, valueObject) && valueObject.GetLong(value) == NativeRdb::E_OK) {
        return true;
    }
    return false;
}

bool ProfileUtils::GetUdidByNetworkId(const std::string& networkId, std::string& udid)
{
    return ((DeviceManager::GetInstance().GetUdidByNetworkId(DP_PKG_NAME, networkId, udid) == 0) ? true : false);
}

bool ProfileUtils::GetUuidByNetworkId(const std::string& networkId, std::string& uuid)
{
    return ((DeviceManager::GetInstance().GetUuidByNetworkId(DP_PKG_NAME, networkId, uuid) == 0) ? true : false);
}

std::string ProfileUtils::GetDbKeyByProfile(const CharacteristicProfile& profile)
{
    if (profile.GetDeviceId().empty() ||
        profile.GetServiceName().empty() ||
        profile.GetCharacteristicKey().empty()) {
        HILOGE("GetDbKeyByProfile fail");
        return "";
    }
    std::string serviceName = CheckAndAddOhSuffix(profile.GetServiceName(), true);
    std::string dbKey = CHAR_PREFIX + SEPARATOR + profile.GetDeviceId() + SEPARATOR + serviceName +
        SEPARATOR + profile.GetCharacteristicKey() + SEPARATOR + CHARACTERISTIC_VALUE;
    return dbKey;
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
