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

#include "profile_utils.h"

#include <codecvt>
#include <locale>
#include <regex>
#include <unordered_set>

#include "dm_device_info.h"
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

std::string ProfileUtils::GetAnonyInt32(const int32_t value)
{
    std::string tempString = std::to_string(value);
    size_t length = tempString.length();
    if (length == 0x01) {
        tempString[0] = '*';
        return tempString;
    }
    for (size_t i = 1; i < length - 1; i++) {
        tempString[i] = '*';
    }
    return tempString;
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
    if (pos == std::string::npos) {
        return "";
    }
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

bool ProfileUtils::IsSvrInfoProfileValid(const ServiceInfoProfileNew& serInfoProfile)
{
    return IsKeyValid(serInfoProfile.GetDeviceId()) && IsKeyValid(serInfoProfile.GetServiceName());
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

std::string ProfileUtils::GenerateServiceInfoProfileKey(const std::string& regServiceId)
{
    return SERVICE_INFO + SEPARATOR + regServiceId;
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
    values.PutLong(LAST_AUTH_TIME, profile.GetLastAuthTime());
    values.PutLong(VALID_PERIOD, profile.GetValidPeriod());
    values.PutInt(STATUS, profile.GetStatus());
    values.PutInt(BIND_LEVEL, profile.GetBindLevel());
    values.PutString(EXTRA_DATA, profile.GetExtraData());
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
    values.PutString(ACCESSER_DEVICE_NAME, accesser.GetAccesserDeviceName());
    values.PutString(ACCESSER_SERVICE_NAME, accesser.GetAccesserServiceName());
    values.PutInt(ACCESSER_CREDENTIAL_ID, accesser.GetAccesserCredentialId());
    values.PutString(ACCESSER_CREDENTIAL_ID_STR, accesser.GetAccesserCredentialIdStr());
    values.PutInt(ACCESSER_STATUS, accesser.GetAccesserStatus());
    values.PutInt(ACCESSER_SESSION_KEY_ID, accesser.GetAccesserSessionKeyId());
    values.PutLong(ACCESSER_SESSION_KEY_TIMESTAMP, accesser.GetAccesserSKTimeStamp());
    values.PutString(ACCESSER_EXTRA_DATA, accesser.GetAccesserExtraData());
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
    values.PutString(ACCESSEE_DEVICE_NAME, accessee.GetAccesseeDeviceName());
    values.PutString(ACCESSEE_SERVICE_NAME, accessee.GetAccesseeServiceName());
    values.PutInt(ACCESSEE_CREDENTIAL_ID, accessee.GetAccesseeCredentialId());
    values.PutString(ACCESSEE_CREDENTIAL_ID_STR, accessee.GetAccesseeCredentialIdStr());
    values.PutInt(ACCESSEE_STATUS, accessee.GetAccesseeStatus());
    values.PutInt(ACCESSEE_SESSION_KEY_ID, accessee.GetAccesseeSessionKeyId());
    values.PutLong(ACCESSEE_SESSION_KEY_TIMESTAMP, accessee.GetAccesseeSKTimeStamp());
    values.PutString(ACCESSEE_EXTRA_DATA, accessee.GetAccesseeExtraData());
    return DP_SUCCESS;
}

int32_t ProfileUtils::DeviceProfileToEntries(const DeviceProfile& profile, std::map<std::string, std::string>& values,
    bool isMultiUser)
{
    std::string deviceProfileKey = GenerateDeviceProfileKey(profile.GetDeviceId());
    if (isMultiUser) {
        values[GenerateDBKey(deviceProfileKey, OS_SYS_CAPACITY, profile.GetUserId())] = profile.GetOsSysCap();
        values[GenerateDBKey(deviceProfileKey, OS_VERSION, profile.GetUserId())] = profile.GetOsVersion();
        values[GenerateDBKey(deviceProfileKey, OS_TYPE, profile.GetUserId())] = std::to_string(profile.GetOsType());
        values[GenerateDBKey(deviceProfileKey, OS_VERSION + OH_PROFILE_SUFFIX, profile.GetUserId())] =
            profile.GetOsVersion();
        values[GenerateDBKey(deviceProfileKey, OS_TYPE + OH_PROFILE_SUFFIX, profile.GetUserId())] =
            std::to_string(profile.GetOsType());
    } else {
        values[GenerateDBKey(deviceProfileKey, OS_SYS_CAPACITY)] = profile.GetOsSysCap();
        values[GenerateDBKey(deviceProfileKey, OS_VERSION)] = profile.GetOsVersion();
        values[GenerateDBKey(deviceProfileKey, OS_TYPE)] = std::to_string(profile.GetOsType());
        values[GenerateDBKey(deviceProfileKey, OS_VERSION + OH_PROFILE_SUFFIX)] = profile.GetOsVersion();
        values[GenerateDBKey(deviceProfileKey, OS_TYPE + OH_PROFILE_SUFFIX)] = std::to_string(profile.GetOsType());
    }
    return DP_SUCCESS;
}

int32_t ProfileUtils::ServiceProfileToEntries(const ServiceProfile& profile, std::map<std::string,
    std::string>& values, bool isMultiUser)
{
    std::string serviceName = CheckAndAddOhSuffix(profile.GetServiceName(), true);
    std::string serviceProfileKey = GenerateServiceProfileKey(profile.GetDeviceId(), serviceName);
    // value not need add OH suffix
    if (isMultiUser) {
        values[GenerateDBKey(serviceProfileKey, SERVICE_NAME, profile.GetUserId())] = profile.GetServiceName();
        values[GenerateDBKey(serviceProfileKey, SERVICE_TYPE, profile.GetUserId())] = profile.GetServiceType();
    } else {
        values[GenerateDBKey(serviceProfileKey, SERVICE_NAME)] = profile.GetServiceName();
        values[GenerateDBKey(serviceProfileKey, SERVICE_TYPE)] = profile.GetServiceType();
    }
    return DP_SUCCESS;
}

int32_t ProfileUtils::ServiceInfoProfileToEntries(const ServiceInfoProfileNew& profile, std::map<std::string,
    std::string>& values)
{
    int32_t userIdValue = profile.GetUserId();
    std::string regServiceId = std::to_string(profile.GetRegServiceId());
    values[GenerateServiceDBKey(regServiceId, DEVICE_ID, userIdValue)] = profile.GetDeviceId();
    values[GenerateServiceDBKey(regServiceId, USERID, userIdValue)] = std::to_string(profile.GetUserId());
    values[GenerateServiceDBKey(regServiceId, TOKENID, userIdValue)] = std::to_string(profile.GetTokenId());
    values[GenerateServiceDBKey(regServiceId, PUBLISH_STATE, userIdValue)] =
        std::to_string(profile.GetSerPubState());
    values[GenerateServiceDBKey(regServiceId, SERVICEID, userIdValue)] =
        std::to_string(profile.GetServiceId());
    values[GenerateServiceDBKey(regServiceId, SERVICE_TYPE, userIdValue)] = profile.GetServiceType();
    values[GenerateServiceDBKey(regServiceId, SERVICE_NAME, userIdValue)] = profile.GetServiceName();
    values[GenerateServiceDBKey(regServiceId, SERVICE_DISPLAY_NAME, userIdValue)] =
         profile.GetServiceDisplayName();
 
    return DP_SUCCESS;
}

int32_t ProfileUtils::CharacteristicProfileToEntries(const CharacteristicProfile& profile,
    std::map<std::string, std::string>& values, bool isMultiUser)
{
    std::string serviceName = CheckAndAddOhSuffix(profile.GetServiceName(), true);
    std::string charProfileKey = GenerateCharProfileKey(profile.GetDeviceId(), serviceName,
        profile.GetCharacteristicKey());
    if (isMultiUser) {
        values[GenerateDBKey(charProfileKey, CHARACTERISTIC_KEY, profile.GetUserId())] =
            profile.GetCharacteristicKey();
        values[GenerateDBKey(charProfileKey, CHARACTERISTIC_VALUE, profile.GetUserId())] =
            profile.GetCharacteristicValue();
    } else {
        values[GenerateDBKey(charProfileKey, CHARACTERISTIC_KEY)] = profile.GetCharacteristicKey();
        values[GenerateDBKey(charProfileKey, CHARACTERISTIC_VALUE)] = profile.GetCharacteristicValue();
    }
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
    if (GetLongValue(values, VALID_PERIOD, int64Value)) {
        profile.SetValidPeriod(int64Value);
    }
    if (GetLongValue(values, LAST_AUTH_TIME, int64Value)) {
        profile.SetLastAuthTime(int64Value);
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
    if (GetStringValue(values, EXTRA_DATA, strValue)) {
        profile.SetExtraData(strValue);
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
    EntriesToAccesserExt(values, accesser);
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
    EntriesToAccesseeExt(values, accessee);
    return DP_SUCCESS;
}

int32_t ProfileUtils::EntriesToAccesserExt(const ValuesBucket &values, Accesser &accesser)
{
    ValueObject valueObject;
    std::string strValue = "";
    int32_t intValue = 0;
    int64_t int64Value = 0;
    if (values.GetObject(ACCESSER_DEVICE_NAME, valueObject) && valueObject.GetString(strValue) == NativeRdb::E_OK) {
        accesser.SetAccesserDeviceName(strValue);
    }
    if (values.GetObject(ACCESSER_SERVICE_NAME, valueObject) && valueObject.GetString(strValue) == NativeRdb::E_OK) {
        accesser.SetAccesserServiceName(strValue);
    }
    if (values.GetObject(ACCESSER_CREDENTIAL_ID, valueObject) && valueObject.GetInt(intValue) == NativeRdb::E_OK) {
        accesser.SetAccesserCredentialId(intValue);
    }
    if (values.GetObject(ACCESSER_CREDENTIAL_ID_STR, valueObject) &&
        valueObject.GetString(strValue) == NativeRdb::E_OK) {
        accesser.SetAccesserCredentialIdStr(strValue);
    }
    if (values.GetObject(ACCESSER_STATUS, valueObject) && valueObject.GetInt(intValue) == NativeRdb::E_OK) {
        accesser.SetAccesserStatus(intValue);
    }
    if (values.GetObject(ACCESSER_SESSION_KEY_ID, valueObject) && valueObject.GetInt(intValue) == NativeRdb::E_OK) {
        accesser.SetAccesserSessionKeyId(intValue);
    }
    if (values.GetObject(ACCESSER_SESSION_KEY_TIMESTAMP, valueObject) &&
        valueObject.GetLong(int64Value) == NativeRdb::E_OK) {
        accesser.SetAccesserSKTimeStamp(int64Value);
    }
    if (values.GetObject(ACCESSER_EXTRA_DATA, valueObject) && valueObject.GetString(strValue) == NativeRdb::E_OK) {
        accesser.SetAccesserExtraData(strValue);
    }
    return DP_SUCCESS;
}

int32_t ProfileUtils::EntriesToAccesseeExt(const ValuesBucket &values, Accessee &accessee)
{
    ValueObject valueObject;
    std::string strValue = "";
    int32_t intValue = 0;
    int64_t int64Value = 0;
    if (values.GetObject(ACCESSEE_DEVICE_NAME, valueObject) && valueObject.GetString(strValue) == NativeRdb::E_OK) {
        accessee.SetAccesseeDeviceName(strValue);
    }
    if (values.GetObject(ACCESSEE_SERVICE_NAME, valueObject) && valueObject.GetString(strValue) == NativeRdb::E_OK) {
        accessee.SetAccesseeServiceName(strValue);
    }
    if (values.GetObject(ACCESSEE_CREDENTIAL_ID, valueObject) && valueObject.GetInt(intValue) == NativeRdb::E_OK) {
        accessee.SetAccesseeCredentialId(intValue);
    }
    if (values.GetObject(ACCESSEE_CREDENTIAL_ID_STR, valueObject) &&
        valueObject.GetString(strValue) == NativeRdb::E_OK) {
        accessee.SetAccesseeCredentialIdStr(strValue);
    }
    if (values.GetObject(ACCESSEE_STATUS, valueObject) && valueObject.GetInt(intValue) == NativeRdb::E_OK) {
        accessee.SetAccesseeStatus(intValue);
    }
    if (values.GetObject(ACCESSEE_SESSION_KEY_ID, valueObject) && valueObject.GetInt(intValue) == NativeRdb::E_OK) {
        accessee.SetAccesseeSessionKeyId(intValue);
    }
    if (values.GetObject(ACCESSEE_SESSION_KEY_TIMESTAMP, valueObject) &&
        valueObject.GetLong(int64Value) == NativeRdb::E_OK) {
        accessee.SetAccesseeSKTimeStamp(int64Value);
    }
    if (values.GetObject(ACCESSEE_EXTRA_DATA, valueObject) && valueObject.GetString(strValue) == NativeRdb::E_OK) {
        accessee.SetAccesseeExtraData(strValue);
    }
    return DP_SUCCESS;
}

int32_t ProfileUtils::EntriesToDeviceProfile(std::map<std::string, std::string> values, DeviceProfile& profile)
{
    if (values.empty() || values.size() > MAX_DB_RECORD_SIZE) {
        HILOGI("Entries size is invalid!size: %{public}zu!", values.size());
        return DP_INVALID_PARAMS;
    }
    auto propertiesMap = GetProfilePropertiesMap(values, profile.GetUserId());
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
    auto propertiesMap = GetProfilePropertiesMap(values, profile.GetUserId());
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
    auto propertiesMap = GetProfilePropertiesMap(values, profile.GetUserId());
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

std::string ProfileUtils::GenerateDBKey(const std::string& profileKey, const std::string& profileProperty,
    int32_t userId)
{
    std::string DBKey = "";
    if (userId != DEFAULT_USER_ID) {
        DBKey = profileKey + SEPARATOR + profileProperty + SEPARATOR + std::to_string(userId);
    } else {
        DBKey = profileKey + SEPARATOR + profileProperty;
    }
    return DBKey;
}

std::string ProfileUtils::GenerateServiceDBKey(const std::string& regServiceId, const std::string& trailInfo,
    int32_t userId)
{
    std::string strUserId = std::to_string(userId);
    std::string DBKey = "";
    DBKey = "serviceInfo" + SEPARATOR + regServiceId + SEPARATOR + strUserId + SEPARATOR + trailInfo;
    return DBKey;
}

std::string ProfileUtils::GetProfileProperty(const std::string& dbKey, int32_t userId)
{
    if (dbKey.length() == 0 || dbKey.length() > MAX_STRING_LEN) {
        return "";
    }
    int32_t getUserId = GetUserIdFromDbKey(dbKey);
    std::vector<std::string> splitKeys;
    if (SplitString(dbKey, SEPARATOR, splitKeys) != DP_SUCCESS || splitKeys.size() < NUM_3) {
        HILOGE("GetProfileProperty SplitString fail");
        return "";
    }

    if (splitKeys[0] == DEV_PREFIX) {
        if (userId != DEFAULT_USER_ID && getUserId == DEFAULT_USER_ID) {
            return splitKeys[NUM_2];
        }
        return (userId == getUserId) ? splitKeys[NUM_2] : "";
    }
    if (splitKeys[0] == SVR_PREFIX && splitKeys.size() >= NUM_4) {
        if (userId != DEFAULT_USER_ID && getUserId == DEFAULT_USER_ID) {
            return splitKeys[NUM_3];
        }
        return (userId == getUserId) ? splitKeys[NUM_3] : "";
    }
    if (splitKeys[0] == CHAR_PREFIX && splitKeys.size() >= NUM_5) {
        if (userId != DEFAULT_USER_ID && getUserId == DEFAULT_USER_ID) {
            return splitKeys[NUM_4];
        }
        return (userId == getUserId) ? splitKeys[NUM_4] : "";
    }

    HILOGE("dbKey has wrong prefix");
    return "";
}

std::map<std::string, std::string> ProfileUtils::GetProfilePropertiesMap(std::map<std::string, std::string> dbEntries,
    int32_t userId)
{
    std::map<std::string, std::string> propertiesWithoutUserId;
    std::map<std::string, std::string> propertiesWithUserId;
    if (userId <= 0 && userId != DEFAULT_USER_ID) {
        HILOGE("userId is invalid, userId: %{public}s", GetAnonyInt32(userId).c_str());
        return propertiesWithoutUserId;
    }
    for (const auto& item : dbEntries) {
        std::string profileProperty = GetProfileProperty(item.first, userId);
        if (profileProperty.empty()) {
            HILOGE("GetProfileProperty fail, %{public}s!", GetDbKeyAnonyString(item.first).c_str());
            continue;
        }
        if (GetUserIdFromDbKey(item.first) == DEFAULT_USER_ID) {
            propertiesWithoutUserId[profileProperty] = item.second;
            continue;
        }
        propertiesWithUserId[profileProperty] = item.second;
    }

    if (userId != DEFAULT_USER_ID && !propertiesWithUserId.empty()) {
        HILOGI("GetProfile with multi-user");
        return propertiesWithUserId;
    }

    //1. Get profile without multi-user;
    //2. Get profile with multi-user, but remote device without multi-user;
    //3. Get profile with multi-user, but can't find in DB;
    return propertiesWithoutUserId;
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

bool ProfileUtils::IsPropertyValidInt64(const std::map<std::string,
    std::string>& propertyMap, const std::string& property)
{
    if (property.empty() || propertyMap.find(property) == propertyMap.end()) {
        return false;
    }
    std::string propertyValue = propertyMap.at(property);
    if (!IsNumStr(propertyValue)) {
        HILOGE("%{public}s is not numeric string", GetAnonyString(propertyValue).c_str());
        return false;
    }
    if (INT64_MIN < std::atoll(propertyValue.c_str()) && std::atoll(propertyValue.c_str()) < INT64_MAX) {
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

int32_t ProfileUtils::GetUserIdFromDbKey(const std::string& dbKey)
{
    int32_t userId = DEFAULT_USER_ID;
    std::vector<std::string> splitKeys;
    if (SplitString(dbKey, SEPARATOR, splitKeys) != DP_SUCCESS || splitKeys.size() < NUM_3) {
        HILOGE("SplitString fail");
        return userId;
    }
    if (splitKeys[0] == DEV_PREFIX && splitKeys.size() > NUM_3 && IsNumStr(splitKeys[NUM_3])) {
        userId = std::atoi(splitKeys[NUM_3].c_str());
    }
    if (splitKeys[0] == SVR_PREFIX && splitKeys.size() > NUM_4 && IsNumStr(splitKeys[NUM_4])) {
        userId = std::atoi(splitKeys[NUM_4].c_str());
    }
    if (splitKeys[0] == CHAR_PREFIX && splitKeys.size() > NUM_5 && IsNumStr(splitKeys[NUM_5])) {
        userId = std::atoi(splitKeys[NUM_5].c_str());
    }
    return userId;
}

std::string ProfileUtils::RemoveUserIdFromDbKey(const std::string& dbKey)
{
    std::vector<std::string> splitKeys;
    if (SplitString(dbKey, SEPARATOR, splitKeys) != DP_SUCCESS || splitKeys.size() < NUM_3) {
        HILOGE("SplitString fail");
        return EMPTY_STRING;
    }
    if (splitKeys[0] == DEV_PREFIX && splitKeys.size() > NUM_3 && IsNumStr(splitKeys[NUM_3])) {
        splitKeys.erase(splitKeys.begin() + NUM_3);
    }
    if (splitKeys[0] == SVR_PREFIX && splitKeys.size() > NUM_4 && IsNumStr(splitKeys[NUM_4])) {
        splitKeys.erase(splitKeys.begin() + NUM_4);
    }
    if (splitKeys[0] == CHAR_PREFIX && splitKeys.size() > NUM_5 && IsNumStr(splitKeys[NUM_5])) {
        splitKeys.erase(splitKeys.begin() + NUM_5);
    }
    std::string dbKeyWithoutUserId = JoinString(splitKeys, SEPARATOR);
    if (dbKeyWithoutUserId.empty()) {
        HILOGE("JoinString fail");
        return EMPTY_STRING;
    }
    return dbKeyWithoutUserId;
}

int32_t ProfileUtils::GenerateServiceDBkeys(const std::string& deviceId, const std::string& serviceName,
    std::vector<std::string>& dbKeys, bool isMultiUser, int32_t userId)
{
    std::string localServiceName = CheckAndAddOhSuffix(serviceName, true);
    std::string serviceProfileKey = GenerateServiceProfileKey(deviceId, localServiceName);
    // value not need add OH suffix
    if (isMultiUser) {
        dbKeys.emplace_back(GenerateDBKey(serviceProfileKey, SERVICE_NAME, userId));
        dbKeys.emplace_back(GenerateDBKey(serviceProfileKey, SERVICE_TYPE, userId));
    } else {
        dbKeys.emplace_back(GenerateDBKey(serviceProfileKey, SERVICE_NAME));
        dbKeys.emplace_back(GenerateDBKey(serviceProfileKey, SERVICE_TYPE));
    }
    return DP_SUCCESS;
}

int32_t ProfileUtils::GenerateServiceInfoProfilekeys(const std::string& regServiceId, std::vector<std::string>& dbKeys,
    int32_t userId)
{
    std::string serviceProfileKey = GenerateServiceInfoProfileKey(regServiceId);
    dbKeys.emplace_back(GenerateDBKey(serviceProfileKey, DEVICE_ID, userId));
    dbKeys.emplace_back(GenerateDBKey(serviceProfileKey, RDB_USER_ID, userId));
    dbKeys.emplace_back(GenerateDBKey(serviceProfileKey, TOKENID, userId));
    dbKeys.emplace_back(GenerateDBKey(serviceProfileKey, PUBLISH_STATE, userId));
    dbKeys.emplace_back(GenerateDBKey(serviceProfileKey, SERVICE_PROFILE_SERVICE_ID, userId));
    dbKeys.emplace_back(GenerateDBKey(serviceProfileKey, SERVICE_TYPE, userId));
    dbKeys.emplace_back(GenerateDBKey(serviceProfileKey, SERVICE_NAME, userId));
    dbKeys.emplace_back(GenerateDBKey(serviceProfileKey, SERVICE_DISPLAY_NAME, userId));
 
    return DP_SUCCESS;
}

int32_t ProfileUtils::GenerateCharacteristicDBkeys(const std::string& deviceId, const std::string& serviceName,
    const std::string& characteristicKey, std::vector<std::string>& dbKeys, bool isMultiUser, int32_t userId)
{
    std::string localServiceName = CheckAndAddOhSuffix(serviceName, true);
    std::string charProfileKey = GenerateCharProfileKey(deviceId, localServiceName, characteristicKey);
    if (isMultiUser) {
        dbKeys.emplace_back(GenerateDBKey(charProfileKey, CHARACTERISTIC_KEY, userId));
        dbKeys.emplace_back(GenerateDBKey(charProfileKey, CHARACTERISTIC_VALUE, userId));
    } else {
        dbKeys.emplace_back(GenerateDBKey(charProfileKey, CHARACTERISTIC_KEY));
        dbKeys.emplace_back(GenerateDBKey(charProfileKey, CHARACTERISTIC_VALUE));
    }
    return DP_SUCCESS;
}

int32_t ProfileUtils::ConvertToTrustDeviceProfile(
    const AccessControlProfile& accessControlProfile, TrustDeviceProfile& trustDeviceProfile)
{
    trustDeviceProfile.SetDeviceId(accessControlProfile.GetTrustDeviceId());
    trustDeviceProfile.SetDeviceIdType(accessControlProfile.GetDeviceIdType());
    trustDeviceProfile.SetDeviceIdHash(accessControlProfile.GetDeviceIdHash());
    trustDeviceProfile.SetStatus(accessControlProfile.GetStatus());
    trustDeviceProfile.SetBindType(accessControlProfile.GetBindType());
    std::string peerDeviceId = accessControlProfile.GetTrustDeviceId();
    int32_t peerUserId = accessControlProfile.GetAccesser().GetAccesserUserId();
    int32_t localUserId = accessControlProfile.GetAccessee().GetAccesseeUserId();
    if (accessControlProfile.GetAccessee().GetAccesseeDeviceId() == peerDeviceId) {
        peerUserId = accessControlProfile.GetAccessee().GetAccesseeUserId();
        localUserId = accessControlProfile.GetAccesser().GetAccesserUserId();
    }
    trustDeviceProfile.SetPeerUserId(peerUserId);
    trustDeviceProfile.SetLocalUserId(localUserId);
    return DP_SUCCESS;
}

int32_t ProfileUtils::ConvertToAccessControlProfiles(std::shared_ptr<ResultSet> resultSet,
    std::shared_ptr<ResultSet> accesserResultSet, std::shared_ptr<ResultSet> accesseeResultSet,
    std::vector<AccessControlProfile>& profile)
{
    if (accesserResultSet == nullptr) {
        HILOGE("accesserResultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    if (accesseeResultSet == nullptr) {
        HILOGE("accesseeResultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    Accesser accesser;
    accesserResultSet->GoToNextRow();
    ConvertToAccesser(accesserResultSet, accesser);
    Accessee accessee;
    accesseeResultSet->GoToNextRow();
    ConvertToAccessee(accesseeResultSet, accessee);
    if (resultSet == nullptr) {
        HILOGE("resultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    AccessControlProfile accessControlProfile;
    ConvertToAccessControlProfile(resultSet, accessControlProfile);

    accessControlProfile.SetAccesser(accesser);
    accessControlProfile.SetAccessee(accessee);
    profile.push_back(accessControlProfile);
    return DP_SUCCESS;
}

int32_t ProfileUtils::ConvertToTrustDeviceProfile(
    std::shared_ptr<ResultSet> trustResultSet, TrustDeviceProfile& trustDeviceProfile)
{
    if (trustResultSet == nullptr) {
        HILOGE("trustResultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    RowEntity rowEntity;
    if (trustResultSet->GetRow(rowEntity) != DP_SUCCESS) {
        HILOGE("get trustResultSet failed");
        return DP_GET_RESULTSET_FAIL;
    }
    std::string deviceId = rowEntity.Get(DEVICE_ID);
    int32_t deviceIdType = rowEntity.Get(DEVICE_ID_TYPE);
    std::string deviceIdHash = rowEntity.Get(DEVICE_ID_HASH);
    int32_t status = rowEntity.Get(STATUS);

    trustDeviceProfile.SetDeviceId(deviceId);
    trustDeviceProfile.SetDeviceIdType(deviceIdType);
    trustDeviceProfile.SetDeviceIdHash(deviceIdHash);
    trustDeviceProfile.SetStatus(status);
    return DP_SUCCESS;
}

int32_t ProfileUtils::ConvertToAccesser(std::shared_ptr<ResultSet> accesserResultSet,
    Accesser& accesser)
{
    if (accesserResultSet == nullptr) {
        HILOGE("accesserResultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    RowEntity rowEntity;
    if (accesserResultSet->GetRow(rowEntity) != DP_SUCCESS) {
        HILOGE("get accesserResultSet failed");
        return DP_GET_RESULTSET_FAIL;
    }
    int64_t accesserId = rowEntity.Get(ACCESSER_ID);
    std::string accesserDeviceId = rowEntity.Get(ACCESSER_DEVICE_ID);
    int32_t accesserUserId = rowEntity.Get(ACCESSER_USER_ID);
    std::string accesserAccountId = rowEntity.Get(ACCESSER_ACCOUNT_ID);
    int64_t accesserTokenId = rowEntity.Get(ACCESSER_TOKEN_ID);
    std::string accesserBundleName = rowEntity.Get(ACCESSER_BUNDLE_NAME);
    std::string accesserHapSignature = rowEntity.Get(ACCESSER_HAP_SIGNATURE);
    int32_t accesserBindLevel = rowEntity.Get(ACCESSER_BIND_LEVEL);
    std::string accesserDeviceName = rowEntity.Get(ACCESSER_DEVICE_NAME);
    std::string accesserServiceName = rowEntity.Get(ACCESSER_SERVICE_NAME);
    int32_t accesserCredentialId = rowEntity.Get(ACCESSER_CREDENTIAL_ID);
    std::string accesserCredentialIdStr = rowEntity.Get(ACCESSER_CREDENTIAL_ID_STR);
    int32_t accesserStatus = rowEntity.Get(ACCESSER_STATUS);
    int32_t accesserSessionKeyId = rowEntity.Get(ACCESSER_SESSION_KEY_ID);
    int64_t accesserSKTimeStamp = rowEntity.Get(ACCESSER_SESSION_KEY_TIMESTAMP);
    std::string accesserExtraData = rowEntity.Get(ACCESSER_EXTRA_DATA);

    accesser.SetAccesserId(accesserId);
    accesser.SetAccesserDeviceId(accesserDeviceId);
    accesser.SetAccesserUserId(accesserUserId);
    accesser.SetAccesserAccountId(accesserAccountId);
    accesser.SetAccesserTokenId(accesserTokenId);
    accesser.SetAccesserBundleName(accesserBundleName);
    accesser.SetAccesserHapSignature(accesserHapSignature);
    accesser.SetAccesserBindLevel(accesserBindLevel);
    accesser.SetAccesserDeviceName(accesserDeviceName);
    accesser.SetAccesserServiceName(accesserServiceName);
    accesser.SetAccesserCredentialId(accesserCredentialId);
    accesser.SetAccesserCredentialIdStr(accesserCredentialIdStr);
    accesser.SetAccesserStatus(accesserStatus);
    accesser.SetAccesserSessionKeyId(accesserSessionKeyId);
    accesser.SetAccesserSKTimeStamp(accesserSKTimeStamp);
    accesser.SetAccesserExtraData(accesserExtraData);
    return DP_SUCCESS;
}

int32_t ProfileUtils::ConvertToAccessee(std::shared_ptr<ResultSet> accesseeResultSet,
    Accessee& accessee)
{
    if (accesseeResultSet == nullptr) {
        HILOGE("accesseeResultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    RowEntity rowEntity;
    if (accesseeResultSet->GetRow(rowEntity) != DP_SUCCESS) {
        HILOGE("get accesseeResultSet failed");
        return DP_GET_RESULTSET_FAIL;
    }
    int64_t accesseeId = rowEntity.Get(ACCESSEE_ID);
    std::string accesseeDeviceId = rowEntity.Get(ACCESSEE_DEVICE_ID);
    int32_t accesseeUserId = rowEntity.Get(ACCESSEE_USER_ID);
    std::string accesseeAccountId = rowEntity.Get(ACCESSEE_ACCOUNT_ID);
    int64_t accesseeTokenId = rowEntity.Get(ACCESSEE_TOKEN_ID);
    std::string accesseeBundleName = rowEntity.Get(ACCESSEE_BUNDLE_NAME);
    std::string accesseeHapSignature = rowEntity.Get(ACCESSEE_HAP_SIGNATURE);
    int32_t accesseeBindLevel = rowEntity.Get(ACCESSEE_BIND_LEVEL);
    std::string accesseeDeviceName = rowEntity.Get(ACCESSEE_DEVICE_NAME);
    std::string accesseeServiceName = rowEntity.Get(ACCESSEE_SERVICE_NAME);
    int32_t accesseeCredentialId = rowEntity.Get(ACCESSEE_CREDENTIAL_ID);
    std::string accesseeCredentialIdStr = rowEntity.Get(ACCESSEE_CREDENTIAL_ID_STR);
    int32_t accesseeStatus = rowEntity.Get(ACCESSEE_STATUS);
    int32_t accesseeSessionKeyId = rowEntity.Get(ACCESSEE_SESSION_KEY_ID);
    int64_t accesseeSKTimeStamp = rowEntity.Get(ACCESSEE_SESSION_KEY_TIMESTAMP);
    std::string accesseeExtraData = rowEntity.Get(ACCESSEE_EXTRA_DATA);

    accessee.SetAccesseeId(accesseeId);
    accessee.SetAccesseeDeviceId(accesseeDeviceId);
    accessee.SetAccesseeUserId(accesseeUserId);
    accessee.SetAccesseeAccountId(accesseeAccountId);
    accessee.SetAccesseeTokenId(accesseeTokenId);
    accessee.SetAccesseeBundleName(accesseeBundleName);
    accessee.SetAccesseeHapSignature(accesseeHapSignature);
    accessee.SetAccesseeBindLevel(accesseeBindLevel);
    accessee.SetAccesseeDeviceName(accesseeDeviceName);
    accessee.SetAccesseeServiceName(accesseeServiceName);
    accessee.SetAccesseeCredentialId(accesseeCredentialId);
    accessee.SetAccesseeCredentialIdStr(accesseeCredentialIdStr);
    accessee.SetAccesseeStatus(accesseeStatus);
    accessee.SetAccesseeSessionKeyId(accesseeSessionKeyId);
    accessee.SetAccesseeSKTimeStamp(accesseeSKTimeStamp);
    accessee.SetAccesseeExtraData(accesseeExtraData);
    return DP_SUCCESS;
}

int32_t ProfileUtils::ConvertToAccessControlProfile(
    std::shared_ptr<ResultSet> accessControlResultSet, AccessControlProfile& accessControlProfile)
{
    if (accessControlResultSet == nullptr) {
        HILOGE("accessControlResultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    RowEntity rowEntity;
    if (accessControlResultSet->GetRow(rowEntity) != DP_SUCCESS) {
        HILOGE("get accessControlResultSet failed");
        return DP_GET_RESULTSET_FAIL;
    }
    int64_t accessControlId = rowEntity.Get(ACCESS_CONTROL_ID);
    int64_t accesserId = rowEntity.Get(ACCESSER_ID);
    int64_t accesseeId = rowEntity.Get(ACCESSEE_ID);
    std::string trustDeviceId = rowEntity.Get(TRUST_DEVICE_ID);
    std::string sessionKey = rowEntity.Get(SESSION_KEY);
    int32_t bindType = rowEntity.Get(BIND_TYPE);
    int32_t authenticationType = rowEntity.Get(AUTHENTICATION_TYPE);
    int32_t deviceIdType = rowEntity.Get(DEVICE_ID_TYPE);
    std::string deviceIdHash = rowEntity.Get(DEVICE_ID_HASH);
    int32_t status = rowEntity.Get(STATUS);
    int64_t validPeriod = rowEntity.Get(VALID_PERIOD);
    int64_t lastAuthTime = rowEntity.Get(LAST_AUTH_TIME);
    int32_t bindLevel = rowEntity.Get(BIND_LEVEL);
    std::string extraData = rowEntity.Get(EXTRA_DATA);

    accessControlProfile.SetAccessControlId(accessControlId);
    accessControlProfile.SetAccesserId(accesserId);
    accessControlProfile.SetAccesseeId(accesseeId);
    accessControlProfile.SetTrustDeviceId(trustDeviceId);
    accessControlProfile.SetSessionKey(sessionKey);
    accessControlProfile.SetBindType(bindType);
    accessControlProfile.SetAuthenticationType(authenticationType);
    accessControlProfile.SetDeviceIdType(deviceIdType);
    accessControlProfile.SetDeviceIdHash(deviceIdHash);
    accessControlProfile.SetStatus(status);
    accessControlProfile.SetValidPeriod(validPeriod);
    accessControlProfile.SetLastAuthTime(lastAuthTime);
    accessControlProfile.SetBindLevel(bindLevel);
    accessControlProfile.SetExtraData(extraData);
    return DP_SUCCESS;
}

bool ProfileUtils::IsExistColumn(RdbStore& store, const std::string &tabName, const std::string &colName,
    const std::string &colType, int32_t &errCode)
{
    std::vector<ValueObject> args {tabName, colName, colType};
    std::shared_ptr<ResultSet> resultSet = nullptr;
    resultSet = store.QuerySql(TABLE_EXIST_COLUMN_SQL, args);
    if (resultSet == nullptr) {
        HILOGE("resultSet is nullptr");
        errCode = DP_GET_RESULTSET_FAIL;
        return false;
    }
    int32_t rowCount = ROWCOUNT_INIT;
    if (resultSet->GetRowCount(rowCount) != DP_SUCCESS) {
        HILOGE("GetRowCount failed");
        resultSet->Close();
        errCode = DP_GET_RESULTSET_FAIL;
        return false;
    }
    if (rowCount == 0) {
        HILOGE("by condition not find data");
        resultSet->Close();
        errCode = DP_NOT_FIND_DATA;
        return false;
    }
    if (resultSet->GoToNextRow() != DP_SUCCESS) {
        HILOGE("GoToNextRow failed");
        resultSet->Close();
        errCode = DP_GET_RESULTSET_FAIL;
        return false;
    }
    RowEntity rowEntity;
    if (resultSet->GetRow(rowEntity) != DP_SUCCESS) {
        HILOGE("GetRow failed");
        resultSet->Close();
        errCode = DP_GET_RESULTSET_FAIL;
        return false;
    }
    int32_t result = rowEntity.Get(RESULT);
    if (result != 0 && result != 1) {
        HILOGE("select exists sql failed");
        resultSet->Close();
        errCode = DP_INVALID_SQL_RESULT;
        return false;
    }
    resultSet->Close();
    errCode = DP_SUCCESS;
    return result == 1;
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
