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

#include "dp_services_constants.h"
#include "content_sensor_manager_utils.h"
#include "characteristic_profile.h"
#include "characteristic_profile_filter_option.h"
#include "characteristic_profile_dao.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"
#include "device_profile_manager.h"
#include "profile_utils.h"
#include "profile_cache.h"
#include "subscribe_profile_manager.h"

namespace OHOS {
namespace DistributedDeviceProfile {
IMPLEMENT_SINGLE_INSTANCE(CharacteristicProfileDao);
namespace {
    const std::string TAG = "CharacteristicProfileDao";
}

int32_t CharacteristicProfileDao::Init()
{
    int32_t ret;
    if (!ProfileDataRdbAdapter::GetInstance().IsInit()) {
        ret = ProfileDataRdbAdapter::GetInstance().Init();
        if (ret != DP_SUCCESS) {
            HILOGE("ProfileDataRdbAdapter Init failed");
            return DP_INIT_DB_FAILED;
        }
    }
    CreateTable();
    CreateIndex();
    HILOGI("end!");
    return DP_SUCCESS;
}

int32_t CharacteristicProfileDao::UnInit()
{
    if (!ProfileDataRdbAdapter::GetInstance().IsInit()) {
        HILOGE("ProfileDataRdbAdapter is UnInit");
        return DP_SUCCESS;
    }
    int32_t ret = ProfileDataRdbAdapter::GetInstance().UnInit();
    if (ret != DP_SUCCESS) {
        HILOGE("ProfileDataRdbAdapter UnInit failed");
        return DP_UNINIT_FAIL;
    }
    HILOGI("end!");
    return DP_SUCCESS;
}

int32_t CharacteristicProfileDao::PutCharacteristicProfile(CharacteristicProfile& charProfile)
{
    ValuesBucket values;
    int32_t result = CharProfileToEntries(charProfile, values);
    if (result != DP_SUCCESS) {
        HILOGE("charProfile invalid params");
        return DP_INVALID_PARAMS;
    }
    int64_t rowId = ROWID_INIT;
    int32_t ret = RET_INIT;
    ret = ProfileDataRdbAdapter::GetInstance().Put(rowId, CHARACTERISTIC_PROFILE_TABLE, values);
    if (ret != DP_SUCCESS) {
        HILOGE("characteristic_profile insert failed");
        return DP_PUT_CHARACTERISTIC_PROFILE_FAIL;
    }
    if (SetCharacteristicProfileId(charProfile) != DP_SUCCESS) {
        HILOGE("SetCharacteristicProfileId fail");
        return DP_PUT_CHARACTERISTIC_PROFILE_FAIL;
    }
    SubscribeProfileManager::GetInstance().NotifyCharProfileAdd(charProfile);
    std::string localUdid = ContentSensorManagerUtils::GetInstance().ObtainLocalUdid();
    if (localUdid == charProfile.GetDeviceId()) {
        DeviceProfileManager::GetInstance().PutCharacteristicProfile(charProfile);
    }
    HILOGI("end!");
    return DP_SUCCESS;
}

int32_t CharacteristicProfileDao::GetCharacteristicProfiles(const CharacteristicProfileFilterOption &filterOptions,
    std::vector<CharacteristicProfile> &charProfiles)
{
    std::string sql;
    std::vector<ValueObject> condition;
    if (filterOptions.GetUserId() <= 0 && filterOptions.GetAccountld().empty() &&
        filterOptions.GetDeviceIds().empty() && filterOptions.GetWiseDeviceId() .empty() &&
        filterOptions.GetServiceId().empty() && filterOptions.GetCharacteristicKey().empty() &&
        filterOptions.GetCharacteristicProfileIds().empty() && filterOptions.GetServiceProfileId() <= 0) {
        HILOGE("filterOptions is empty");
        return DP_INVALID_PARAMS;
    }
    CreateQuerySqlAndCondition(filterOptions, sql, condition);
    std::shared_ptr<ResultSet> resultSet = ProfileDataRdbAdapter::GetInstance().Get(sql, condition);
    if (resultSet == nullptr) {
        HILOGE("resultSet is nullptr");
        return DP_GET_CHARACTERISTIC_PROFILE_FAIL;
    }
    int32_t rowCount = ROWCOUNT_INIT;
    resultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        HILOGE("by condition not find data");
        resultSet->Close();
        return DP_NOT_FIND_DATA;
    }
    while (resultSet->GoToNextRow() == DP_SUCCESS) {
        CharacteristicProfile charProfile;
        ConvertToCharProfile(resultSet, charProfile);
        charProfiles.push_back(charProfile);
    }
    resultSet->Close();
    if (charProfiles.empty()) {
        return DP_NOT_FIND_DATA;
    }
    HILOGI("end!");
    return DP_SUCCESS;
}

int32_t CharacteristicProfileDao::DeleteCharacteristicProfile(const CharacteristicProfile &charProfiles)
{
    if (charProfiles.GetDeviceId().empty() || charProfiles.GetServiceProfileId() <= 0 ||
        charProfiles.GetServiceId().empty() || charProfiles.GetCharacteristicKey().empty() ||
        charProfiles.GetCharacteristicValue().empty()) {
        HILOGE("charProfile invalid params");
        return DP_INVALID_PARAMS;
    }
    int32_t deleteRows = DELETEROWS_INIT;
    int32_t ret = ProfileDataRdbAdapter::GetInstance().Delete(deleteRows, CHARACTERISTIC_PROFILE_TABLE,
        ID_EQUAL_CONDITION, std::vector<ValueObject>{ ValueObject(charProfiles.GetId()) });
    if (ret != DP_SUCCESS) {
        HILOGE("delete characteristicprofile_profile data failed");
        return DP_DELETE_CHARACTERISTIC_PROFILE_FAIL;
    }
    SubscribeProfileManager::GetInstance().NotifyCharProfileDelete(charProfiles);
    std::string localUdid = ProfileCache::GetInstance().GetLocalUdid();
    if (localUdid == charProfiles.GetDeviceId()) {
        DeviceProfileManager::GetInstance().DeleteCharacteristicProfile(charProfiles.GetDeviceId(),
            charProfiles.GetServiceName(), charProfiles.GetCharacteristicKey(), true, charProfiles.GetUserId());
    }
    HILOGI("end!");
    return DP_SUCCESS;
}

int32_t CharacteristicProfileDao::UpdateCharacteristicProfile(const CharacteristicProfile &oldProfile,
    const CharacteristicProfile &newProfile)
{
    ValuesBucket values;
    int32_t result = CharProfileToEntries(newProfile, values);
    if (result != DP_SUCCESS) {
        HILOGE("charProfile invalid params");
        return DP_INVALID_PARAMS;
    }
    int32_t changeRowCnt = CHANGEROWCNT_INIT;
    int32_t ret = ProfileDataRdbAdapter::GetInstance().Update(
        changeRowCnt, CHARACTERISTIC_PROFILE_TABLE, values, ID_EQUAL_CONDITION,
        std::vector<ValueObject>{ ValueObject(newProfile.GetId()) });
    if (ret != DP_SUCCESS) {
        HILOGE("Update characteristicprofile_profile table failed");
        return DP_UPDATE_TRUST_DEVICE_PROFILE_FAIL;
    }
    SubscribeProfileManager::GetInstance().NotifyCharProfileUpdate(oldProfile, newProfile);
    std::string localUdid = ContentSensorManagerUtils::GetInstance().ObtainLocalUdid();
    if (localUdid == newProfile.GetDeviceId()) {
        DeviceProfileManager::GetInstance().PutCharacteristicProfile(newProfile);
    }
    HILOGI("end!");
    return DP_SUCCESS;
}

int32_t CharacteristicProfileDao::CreateTable()
{
    int32_t ret = ProfileDataRdbAdapter::GetInstance().CreateTable(CREATE_CHARACTERISTIC_PROFILE_TABLE_SQL);
    if (ret != DP_SUCCESS) {
        HILOGE("characteristicprofile_profile create failed");
        return DP_CREATE_TABLE_FAIL;
    }
    return DP_SUCCESS;
}

int32_t CharacteristicProfileDao::CreateIndex()
{
    int32_t ret = ProfileDataRdbAdapter::GetInstance().
        CreateTable(CREATE_CHARACTERISTIC_PROFILE_TABLE_INDEX_SQL_CHARACTERISTIC_KEY);
    if (ret != DP_SUCCESS) {
        HILOGE("characteristicprofile_profile unique index create failed");
        return DP_CREATE_UNIQUE_INDEX_FAIL;
    }
    ret = ProfileDataRdbAdapter::GetInstance().
        CreateTable(CREATE_CHARACTERISTIC_PROFILE_TABLE_INDEX_SQL_SERVICE_PROFILE_ID);
    if (ret != DP_SUCCESS) {
        HILOGE("characteristicprofile_profile unique index create failed");
        return DP_CREATE_UNIQUE_INDEX_FAIL;
    }
    return DP_SUCCESS;
}

void CharacteristicProfileDao::CreateQuerySqlAndCondition(const CharacteristicProfileFilterOption& filterOptions,
    std::string& sql, std::vector<ValueObject>& condition)
{
    sql = SELECT_CHARACTERISTIC_PROFILE_TABLE;
    if (!filterOptions.GetCharacteristicProfileIds().empty()) {
        sql += "cp.id IN(";
        std::vector<int32_t> characteristicProfileIds = filterOptions.GetCharacteristicProfileIds();
        for (auto deviceProfileId : characteristicProfileIds) {
            sql += "?,";
            condition.emplace_back(ValueObject(deviceProfileId));
        }
        sql.erase(sql.end() - 1);
        sql += ") AND ";
    }
    if (!filterOptions.GetCharacteristicKey().empty()) {
        sql += "cp.characteristicKey = ? AND ";
        condition.emplace_back(ValueObject(filterOptions.GetCharacteristicKey()));
    }
    if (filterOptions.GetServiceProfileId() != 0) {
        sql += "cp.serviceProfileId = ? AND ";
        condition.emplace_back(ValueObject(filterOptions.GetServiceProfileId()));
    }
    if (!filterOptions.GetServiceId().empty()) {
        sql += "sp.serviceId = ? AND ";
        condition.emplace_back(ValueObject(filterOptions.GetServiceId()));
    }
    if (!filterOptions.GetDeviceIds().empty()) {
        sql += "sp.deviceId = ? AND ";
        condition.emplace_back(ValueObject(filterOptions.GetDeviceIds()));
    }
    if (filterOptions.GetUserId() != 0) {
        sql += "dp.deviceId = ? AND ";
        condition.emplace_back(ValueObject(filterOptions.GetUserId()));
    }
    if (!filterOptions.GetAccountld().empty()) {
        sql += "dp.deviceId = ? AND ";
        condition.emplace_back(ValueObject(filterOptions.GetAccountld()));
    }
    if (!filterOptions.GetWiseDeviceId().empty()) {
        sql += "dp.deviceId = ? AND ";
        condition.emplace_back(ValueObject(filterOptions.GetWiseDeviceId()));
    }
    if (sql.empty()) {
        return;
    }
    sql.erase(sql.end() - AND_LENGTH);
    return;
}

int32_t CharacteristicProfileDao::CharProfileToEntries(const CharacteristicProfile& charProfile, ValuesBucket& values)
{
    if (charProfile.GetDeviceId().empty() || charProfile.GetServiceProfileId() <= 0 ||
        charProfile.GetServiceId().empty() || charProfile.GetCharacteristicKey().empty() ||
        charProfile.GetCharacteristicValue().empty()) {
        return DP_INVALID_PARAMS;
    }
    values.PutInt(SERVICE_PROFILE_ID, charProfile.GetServiceProfileId());
    values.PutString(CHARACTERISTIC_KEY, charProfile.GetCharacteristicKey());
    values.PutString(CHARACTERISTIC_VALUE, charProfile.GetCharacteristicValue());
    return DP_SUCCESS;
}

int32_t CharacteristicProfileDao::ConvertToCharProfile(
    std::shared_ptr<ResultSet> resultSet, CharacteristicProfile& charProfile)
{
    if (resultSet == nullptr) {
        HILOGE("resultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    RowEntity rowEntity;
    if (resultSet->GetRow(rowEntity) != DP_SUCCESS) {
        HILOGE("get resultSet failed");
        return DP_GET_RESULTSET_FAIL;
    }
    charProfile.SetId(rowEntity.Get(ID));
    charProfile.SetServiceProfileId(rowEntity.Get(SERVICE_PROFILE_ID));
    charProfile.SetDeviceId(rowEntity.Get(DEVICE_ID));
    charProfile.SetServiceId(rowEntity.Get(SERVICE_PROFILE_SERVICE_ID));
    charProfile.SetCharacteristicKey(rowEntity.Get(CHARACTERISTIC_KEY));
    charProfile.SetCharacteristicValue(rowEntity.Get(CHARACTERISTIC_VALUE));
    return DP_SUCCESS;
}

int32_t CharacteristicProfileDao::SetCharacteristicProfileId(CharacteristicProfile& charProfile)
{
    std::shared_ptr<ResultSet> resultSet = ProfileDataRdbAdapter::GetInstance().Get(
        SELECT_CHARACTERISTIC_PROFILE_TABLE_MAX_ID, std::vector<ValueObject> {
            charProfile.GetServiceProfileId(), charProfile.GetCharacteristicKey(),
            charProfile.GetCharacteristicValue()});
    if (resultSet == nullptr) {
        HILOGE("resultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    while (resultSet->GoToNextRow() == DP_SUCCESS) {
        int32_t columnIndex = COLUMNINDEX_INIT;
        int32_t id = DEVICE_PROFILE_ID_INIT;
        resultSet->GetColumnIndex(ID, columnIndex);
        resultSet->GetInt(columnIndex, id);
        charProfile.SetId(id);
    }
    resultSet->Close();
    return DP_SUCCESS;
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
