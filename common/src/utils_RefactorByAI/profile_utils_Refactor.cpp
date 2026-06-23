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
#include "cJSON.h"

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace OHOS::DistributedHardware;

namespace {
    const std::string TAG = "ProfileUtils";
    const std::unordered_set<std::string> NEED_ADD_OH_SUFFIX_DEV_PROFILES { OS_TYPE, OS_VERSION };
    const std::unordered_set<std::string> NEED_ADD_OH_SUFFIX_SVR_NAMES { "DistributeModemService",
        "multiScreenAssistantService", "appInfo" };
}

static void SecureClearString(std::string& str)
{
    if (!str.empty()) {
        volatile char* ptr = &str[0];
        for (size_t i = 0; i < str.size(); ++i) {
            ptr[i] = '\0';
        }
        str.clear();
    }
}

static void SecureClearCString(char* cstr)
{
    if (cstr != nullptr) {
        size_t len = strlen(cstr);
        volatile char* ptr = cstr;
        for (size_t i = 0; i < len; ++i) {
            ptr[i] = '\0';
        }
    }
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
//LCOV_EXCL_START
bool ProfileUtils::IsSvrInfoValid(const ServiceInfo& serviceInfo)
{
    if (serviceInfo.GetServiceOwnerPkgName().empty() ||serviceInfo.GetServiceType().empty() ||
        serviceInfo.GetServiceName().empty() || serviceInfo.GetServiceDisplayName().empty() ||
        serviceInfo.GetCustomData().empty() || serviceInfo.GetServiceCode().empty() ||
        serviceInfo.GetVersion().empty() ||
        serviceInfo.GetDescription().empty()) {
            HILOGE("Invalid parameters exist in serviceInfo.");
        return false;
    }

    if (serviceInfo.GetUserId() == DEFAULT_USER_ID || serviceInfo.GetDisplayId() == DEFAULT_DISPLAY_ID ||
        serviceInfo.GetServiceOwnerTokenId() == DEFAULT_SERVICE_OWNER_TOKENID ||
        serviceInfo.GetServiceRegisterTokenId() == DEFAULT_SERVICE_REGISTER_TOKENID ||
        serviceInfo.GetServiceId() == DEFAULT_SERVICE_ID || serviceInfo.GetTimeStamp() == DEFAULT_TIMESTAMP ||
        serviceInfo.GetPublishState() == DEFAULT_PUBLISH_STATE || serviceInfo.GetDataLen() == 0) {
        HILOGE("Invalid parameters exist in serviceInfo.");
        return false;
    }
    return IsKeyValid(serviceInfo.GetUdid());
}
//LCOV_EXCL_STOP
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
//LCOV_EXCL_START
int32_t ProfileUtils::ServiceInfoToEntries(const ServiceInfo& profile, std::map<std::string,
    std::string>& values)
{
    std::string DBKey = "serInfo" + SEPARATOR + profile.GetUdid() + SEPARATOR + std::to_string(profile.GetUserId()) +
                        SEPARATOR + std::to_string(profile.GetServiceId());
    cJSON* jsonObj = cJSON_CreateObject();
    if (jsonObj == nullptr) {
        HILOGE("Create cJSON object failed!");
        return DP_INVALID_PARAMS;
    }
    cJSON_AddStringToObject(jsonObj, UD_ID.c_str(), profile.GetUdid().c_str());
    cJSON_AddNumberToObject(jsonObj, USER_ID.c_str(), profile.GetUserId());
    cJSON_AddStringToObject(jsonObj, DISPLAYID.c_str(), std::to_string(profile.GetDisplayId()).c_str());
    cJSON_AddNumberToObject(jsonObj, SERVICE_OWNER_TOKEN_ID.c_str(), profile.GetServiceOwnerTokenId());
    cJSON_AddStringToObject(jsonObj, SERVICE_OWNER_PKG_NAME.c_str(), profile.GetServiceOwnerPkgName().c_str());
    cJSON_AddNumberToObject(jsonObj, SERVICE_REGISTER_TOKEN_ID.c_str(), profile.GetServiceRegisterTokenId());
    cJSON_AddStringToObject(jsonObj, SERVICEID.c_str(), std::to_string(profile.GetServiceId()).c_str());
    cJSON_AddStringToObject(jsonObj, TIME_STAMP.c_str(), std::to_string(profile.GetTimeStamp()).c_str());
    cJSON_AddNumberToObject(jsonObj, PUBLISH_STATE.c_str(), profile.GetPublishState());
    cJSON_AddStringToObject(jsonObj, SERVICE_TYPE.c_str(), profile.GetServiceType().c_str());
    cJSON_AddStringToObject(jsonObj, SERVICE_NAME.c_str(), profile.GetServiceName().c_str());
    cJSON_AddStringToObject(jsonObj, SERVICE_DISPLAY_NAME.c_str(), profile.GetServiceDisplayName().c_str());
    cJSON_AddStringToObject(jsonObj, CUSTOM_DATA.c_str(), profile.GetCustomData().c_str());
    cJSON_AddStringToObject(jsonObj, SERVICE_CODE.c_str(), profile.GetServiceCode().c_str());
    cJSON_AddNumberToObject(jsonObj, DATA_LEN.c_str(), profile.GetDataLen());
    cJSON_AddStringToObject(jsonObj, EXTRA_DATA.c_str(), profile.GetExtraData().c_str());
    cJSON_AddStringToObject(jsonObj, VERSION.c_str(), profile.GetVersion().c_str());
    cJSON_AddStringToObject(jsonObj, DESCRIPTION.c_str(), profile.GetDescription().c_str());

    char* jsonStr = cJSON_PrintUnformatted(jsonObj);
    if (jsonStr == nullptr) {
        cJSON_Delete(jsonObj);
        HILOGE("Convert cJSON to string failed!");
        return DP_INVALID_PARAMS;
    }
    values[DBKey] = jsonStr;
    SecureClearCString(jsonStr);
    cJSON_free(jsonStr);
    cJSON_Delete(jsonObj);
    return DP_SUCCESS;
}
//LCOV_EXCL_STOP
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
        SecureClearString(strValue);
    }
    if (values.GetObject(DEVICE_ID_HASH, valueObject) && valueObject.GetString(strValue) == NativeRdb::E_OK) {
        profile.SetDeviceIdHash(strValue);
        SecureClearString(strValue);
    }
    if (values.GetObject(DEVICE_TYPE_ID, valueObject) && valueObject.GetInt(intValue) == NativeRdb::E_OK) {
        profile.SetDeviceIdType(intValue);
    }
    if (values.GetObject(STATUS, valueObject) && valueObject.GetInt(intValue) == NativeRdb::E_OK) {
        profile.SetStatus(intValue);
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
        SecureClearString(strValue);
    }
    if (values.GetObject(ACCESSER_USER_ID, valueObject) && valueObject.GetInt(intValue) == NativeRdb::E_OK) {
        accesser.SetAccesserUserId(intValue);
    }
    if (values.GetObject(ACCESSER_ACCOUNT_ID, valueObject) && valueObject.GetString(strValue) == NativeRdb::E_OK) {
        accesser.SetAccesserAccountId(strValue);
        SecureClearString(strValue);
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
        SecureClearString(strValue);
    }
    if (values.GetObject(ACCESSEE_USER_ID, valueObject) && valueObject.GetInt(intValue) == NativeRdb::E_OK) {
        accessee.SetAccesseeUserId(intValue);
    }
    if (values.GetObject(ACCESSEE_ACCOUNT_ID, valueObject) && valueObject.GetString(strValue) == NativeRdb::E_OK) {
        accessee.SetAccesseeAccountId(strValue);
        SecureClearString(strValue);
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
} // namespace DistributedDeviceProfile
} // namespace OHOS