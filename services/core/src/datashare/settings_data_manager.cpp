/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "settings_data_manager.h"

#include "iservice_registry.h"
#include "system_ability_definition.h"

#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"

namespace OHOS {
namespace DistributedDeviceProfile {
IMPLEMENT_SINGLE_INSTANCE(SettingsDataManager)
namespace {
const std::string TAG = "SettingsDataManager";
constexpr int32_t USERID_HELPER_NUMBER = 100;
const std::string SETTING_URI_PROXY = "datashare:///com.ohos.settingsdata/entry/settingsdata/";
const std::string SETTINGS_DATA_EXT_URI = "datashare:///com.ohos.settingsdata.DataAbility";
const std::string URI_PROXY_SUFFIX = "?Proxy=true";
const std::string SETTINGSDATA_GLOBAL = "SETTINGSDATA";
const std::string SETTINGS_GENERAL_DEVICE_NAME = "settings.general.device_name";
const std::string SETTINGSDATA_SYSTEM = "USER_SETTINGSDATA_";
const std::string SETTINGSDATA_SECURE = "USER_SETTINGSDATA_SECURE_";
const std::string SETTINGS_GENERAL_DISPLAY_DEVICE_NAME = "settings.general.display_device_name";
const std::string SETTINGS_GENERAL_USER_DEFINED_DEVICE_NAME = "settings.general.user_defined_device_name";
 
const std::string SETTING_COLUMN_VALUE = "VALUE";
const std::string SETTING_COLUMN_KEYWORD = "KEYWORD";
}
 
int32_t SettingsDataManager::Init()
{
    GetRemoteObj();
    return DP_SUCCESS;
}
 
int32_t SettingsDataManager::UnInit()
{
    std::lock_guard<std::mutex> lock(remoteObjMtx_);
    remoteObj_ = nullptr;
    return DP_SUCCESS;
}
 
int32_t SettingsDataManager::GetUserDefinedDeviceName(int32_t userId, std::string &deviceName)
{
    return GetValue(SETTINGSDATA_SECURE, userId, SETTINGS_GENERAL_USER_DEFINED_DEVICE_NAME, deviceName);
}
 
int32_t SettingsDataManager::SetUserDefinedDeviceName(const std::string &deviceName, int32_t userId)
{
    return SetValue(SETTINGSDATA_SECURE, userId, SETTINGS_GENERAL_USER_DEFINED_DEVICE_NAME, deviceName);
}
 
int32_t SettingsDataManager::GetDisplayDeviceName(int32_t userId, std::string &deviceName)
{
    return GetValue(SETTINGSDATA_SECURE, userId, SETTINGS_GENERAL_DISPLAY_DEVICE_NAME, deviceName);
}
 
int32_t SettingsDataManager::SetDisplayDeviceName(const std::string &deviceName, int32_t userId)
{
    return SetValue(SETTINGSDATA_SECURE, userId, SETTINGS_GENERAL_DISPLAY_DEVICE_NAME, deviceName);
}
 
int32_t SettingsDataManager::GetDeviceName(std::string &deviceName)
{
    return GetValue(SETTINGSDATA_GLOBAL, 0, SETTINGS_GENERAL_DEVICE_NAME, deviceName);
}
 
sptr<IRemoteObject> SettingsDataManager::GetRemoteObj()
{
    std::lock_guard<std::mutex> lock(remoteObjMtx_);
    if (remoteObj_ != nullptr) {
        return remoteObj_;
    }
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        HILOGE("get sa manager return nullptr");
        return nullptr;
    }
    auto remoteObj = samgr->GetSystemAbility(DISTRIBUTED_DEVICE_PROFILE_SA_ID  );
    if (remoteObj == nullptr) {
        HILOGE("get system ability failed, id=%{public}d", DISTRIBUTED_DEVICE_PROFILE_SA_ID  );
        return nullptr;
    }
    remoteObj_ = remoteObj;
    return remoteObj_;
}
 
int32_t SettingsDataManager::GetValue(const std::string &tableName, int32_t userId,
    const std::string &key, std::string &value)
{
    std::string proxyUri = GetProxyUriStr(tableName, userId);
    auto helper = CreateDataShareHelper(proxyUri);
    if (helper == nullptr) {
        HILOGE("helper is nullptr");
        return DP_NULLPTR;
    }
    std::vector<std::string> columns = { SETTING_COLUMN_VALUE };
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SETTING_COLUMN_KEYWORD, key);
    Uri uri = MakeUri(proxyUri, key);
    auto resultSet = helper->Query(uri, predicates, columns);
    ReleaseDataShareHelper(helper);
    if (resultSet == nullptr) {
        HILOGE("Query failed key=%{public}s", key.c_str());
        return DP_NULLPTR;
    }
    int32_t count;
    resultSet->GetRowCount(count);
    if (count == 0) {
        HILOGW("no value, key=%{public}s", key.c_str());
        resultSet->Close();
        return DP_SUCCESS;
    }
    int32_t index = 0;
    resultSet->GoToRow(index);
    int32_t ret = resultSet->GetString(index, value);
    if (ret != DataShare::E_OK) {
        HILOGE("get value failed, ret=%{public}d", ret);
        resultSet->Close();
        return ret;
    }
    resultSet->Close();
    return DP_SUCCESS;
}
 
int32_t SettingsDataManager::SetValue(const std::string &tableName, int32_t userId,
    const std::string &key, const std::string &value)
{
    std::string proxyUri = GetProxyUriStr(tableName, userId);
    auto helper = CreateDataShareHelper(proxyUri);
    if (helper == nullptr) {
        HILOGE("helper is nullptr");
        return DP_NULLPTR;
    }
 
    DataShare::DataShareValuesBucket val;
    val.Put(SETTING_COLUMN_KEYWORD, key);
    val.Put(SETTING_COLUMN_VALUE, value);
    Uri uri = MakeUri(proxyUri, key);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SETTING_COLUMN_KEYWORD, key);
    int ret = helper->Update(uri, predicates, val);
    if (ret <= 0) {
        HILOGW("Update failed, ret=%{public}d", ret);
        ret = helper->Insert(uri, val);
    }
    ReleaseDataShareHelper(helper);
    if (ret <= 0) {
        HILOGE("set value failed, ret=%{public}d", ret);
        return ret;
    }
    return ret;
}
 
std::shared_ptr<DataShare::DataShareHelper> SettingsDataManager::CreateDataShareHelper(const std::string &proxyUri)
{
    auto [ret, helper] = DataShare::DataShareHelper::Create(GetRemoteObj(), proxyUri, SETTINGS_DATA_EXT_URI);
    if (ret != 0) {
        HILOGE("create helper failed ret %{public}d", ret);
        return nullptr;
    }
    return helper;
}
 
std::string SettingsDataManager::GetProxyUriStr(const std::string &tableName, int32_t userId)
{
    if (userId < USERID_HELPER_NUMBER) {
        userId = USERID_HELPER_NUMBER;
    }
    if (tableName == SETTINGSDATA_GLOBAL) {
        return SETTING_URI_PROXY + SETTINGSDATA_GLOBAL + URI_PROXY_SUFFIX;
    } else {
        return SETTING_URI_PROXY + tableName + std::to_string(userId) + URI_PROXY_SUFFIX;
    }
}
 
Uri SettingsDataManager::MakeUri(const std::string &proxyUri, const std::string &key)
{
    Uri uri(proxyUri + "&key=" + key);
    return uri;
}
 
bool SettingsDataManager::ReleaseDataShareHelper(std::shared_ptr<DataShare::DataShareHelper> helper)
{
    if (helper == nullptr) {
        HILOGE("helper is nullptr");
        return false;
    }
    if (!helper->Release()) {
        HILOGE("release helper fail");
        return false;
    }
    return true;
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
