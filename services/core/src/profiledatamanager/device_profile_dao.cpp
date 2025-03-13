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

#include "device_profile_dao.h"
#include "content_sensor_manager_utils.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"
#include "device_profile_manager.h"
#include "dp_services_constants.h"
#include "profile_utils.h"
#include "subscribe_profile_manager.h"

namespace OHOS {
namespace DistributedDeviceProfile {
IMPLEMENT_SINGLE_INSTANCE(DeviceProfileDao);
namespace {
    const std::string TAG = "DeviceProfileDao";
}

int32_t DeviceProfileDao::Init()
{
    std::lock_guard<std::mutex> lock(rdbMutex_);
    int32_t ret = RET_INIT;
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

int32_t DeviceProfileDao::UnInit()
{
    std::lock_guard<std::mutex> lock(rdbMutex_);
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

int32_t DeviceProfileDao::PutDeviceProfile(const DeviceProfile& deviceProfile)
{
    ValuesBucket values;
    DeviceProfileToEntries(deviceProfile, values);
    int64_t rowId = ROWID_INIT;
    int32_t ret = RET_INIT;
    {
        std::lock_guard<std::mutex> lock(rdbMutex_);
        ret = ProfileDataRdbAdapter::GetInstance().Put(rowId, DEVICE_PROFILE_TABLE, values);
        if (ret != DP_SUCCESS) {
            HILOGE("device_profile insert failed");
            return DP_PUT_TRUST_DEVICE_PROFILE_FAIL;
        }
    }
    std::shared_ptr<ResultSet> resultSet = ProfileDataRdbAdapter::GetInstance().Get(
        SELECT_DEVICE_PROFILE_TABLE_WHERE_DEVID_USERID,
        std::vector<ValueObject>{ ValueObject(deviceProfile.GetDeviceId()),
        ValueObject(deviceProfile.GetUserId())});
    if (resultSet == nullptr) {
        HILOGE("resultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    DeviceProfile profile(deviceProfile);
    while (resultSet->GoToNextRow() == DP_SUCCESS) {
        int32_t columnIndex = COLUMNINDEX_INIT;
        int32_t id = DEVICE_PROFILE_ID_INIT;
        resultSet->GetColumnIndex(ID, columnIndex);
        resultSet->GetInt(columnIndex, id);
        profile.SetId(id);
    }
    resultSet->Close();
    HILOGI("end!");
    return DP_SUCCESS;
}

int32_t DeviceProfileDao::GetDeviceProfiles(const DeviceProfileFilterOptions &filterOptions,
    std::vector<DeviceProfile> &deviceProfiles)
{
    std::string sql;
    std::vector<ValueObject> condition;
    CreateQuerySqlAndCondition(filterOptions, sql, condition);
    std::shared_ptr<ResultSet> resultSet = ProfileDataRdbAdapter::GetInstance().Get(sql, condition);
    if (resultSet == nullptr) {
        HILOGE("resultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = ROWCOUNT_INIT;
    resultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        HILOGE("by condition not find data");
        resultSet->Close();
        return DP_NOT_FIND_DATA;
    }
    while (resultSet->GoToNextRow() == DP_SUCCESS) {
        DeviceProfile deviceProfile;
        ConvertToDeviceProfile(resultSet, deviceProfile);
        deviceProfiles.emplace_back(deviceProfile);
    }
    resultSet->Close();
    if (deviceProfiles.empty()) {
        return DP_NOT_FIND_DATA;
    }
    HILOGI("end!");
    return DP_SUCCESS;
}

int32_t DeviceProfileDao::DeleteDeviceProfile(const DeviceProfile &deviceProfile)
{
    {
        std::lock_guard<std::mutex> lock(rdbMutex_);
        int32_t deleteRows = DELETEROWS_INIT;
        int32_t ret = ProfileDataRdbAdapter::GetInstance().Delete(deleteRows, DEVICE_PROFILE_TABLE, ID_EQUAL_CONDITION,
            std::vector<ValueObject>{ ValueObject(deviceProfile.GetId()) });
        if (ret != DP_SUCCESS) {
            HILOGE("delete device_profile data failed, ret=%{public}d", ret);
            return DP_DELETE_TRUST_DEVICE_PROFILE_FAIL;
        }
    }
    HILOGI("end!");
    return DP_SUCCESS;
}

int32_t DeviceProfileDao::UpdateDeviceProfile(const DeviceProfile &newProfile)
{
    ValuesBucket values;
    DeviceProfileToEntries(newProfile, values);
    int32_t changeRowCnt = CHANGEROWCNT_INIT;
    {
        std::lock_guard<std::mutex> lock(rdbMutex_);
        int32_t ret = ProfileDataRdbAdapter::GetInstance().Update(
            changeRowCnt, DEVICE_PROFILE_TABLE, values, ID_EQUAL_CONDITION,
            std::vector<ValueObject>{ ValueObject(newProfile.GetId()) });
        if (ret != DP_SUCCESS) {
            HILOGE("Update device_profile table failed");
            return DP_UPDATE_TRUST_DEVICE_PROFILE_FAIL;
        }
    }
    HILOGI("end!");
    return DP_SUCCESS;
}

int32_t DeviceProfileDao::CreateTable()
{
    int32_t ret = ProfileDataRdbAdapter::GetInstance().CreateTable(CREATE_DEVICE_PROFILE_TABLE_SQL);
    if (ret != DP_SUCCESS) {
        HILOGE("device_profile create failed");
        return DP_CREATE_TABLE_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DeviceProfileDao::CreateIndex()
{
    int32_t ret = ProfileDataRdbAdapter::GetInstance().CreateTable(CREATE_DEVICE_PROFILE_TABLE_UNIQUE_INDEX_SQL);
    if (ret != DP_SUCCESS) {
        HILOGE("device_profile unique index create failed");
        return DP_CREATE_UNIQUE_INDEX_FAIL;
    }
    ret = ProfileDataRdbAdapter::GetInstance().CreateTable(CREATE_DEVICE_PROFILE_WISE_DEVICEID_INDEX_SQL);
    if (ret != DP_SUCCESS) {
        HILOGE("device_profile wiseDeviceId index create failed");
        return DP_CREATE_INDEX_FAIL;
    }
    return DP_SUCCESS;
}

void DeviceProfileDao::CreateQuerySqlAndCondition(const DeviceProfileFilterOptions &filterOptions,
    std::string &sql, std::vector<ValueObject> &condition)
{
    sql = SELECT_DEVICE_PROFILE_TABLE;
    bool matchCondition = false;
    if (!filterOptions.GetDeviceProfileIds().empty()) {
        sql += "id IN(";
        GenerateSqlAndCondition(filterOptions.GetDeviceProfileIds(), sql, condition);
        matchCondition = true;
    }
    if (!filterOptions.GetDeviceIds().empty()) {
        sql += "deviceId IN(";
        GenerateSqlAndCondition(filterOptions.GetDeviceIds(), sql, condition);
        matchCondition = true;
    }
    if (filterOptions.GetUserId() != DEFAULT_USER_ID) {
        sql += "userId = ? AND ";
        condition.emplace_back(ValueObject(filterOptions.GetUserId()));
        matchCondition = true;
    }
    if (!filterOptions.GetAccountId().empty()) {
        sql += "accountId = ? AND ";
        condition.emplace_back(ValueObject(filterOptions.GetAccountId()));
        matchCondition = true;
    }
    if (!filterOptions.GetWiseDeviceIds().empty()) {
        sql += "wiseDeviceId IN(";
        GenerateSqlAndCondition(filterOptions.GetWiseDeviceIds(), sql, condition);
        matchCondition = true;
    }
    if (matchCondition) {
        sql.erase(sql.end() - AND_LENGTH, sql.end());
        return;
    }
    sql.erase(sql.end() - WHERE_LENGTH, sql.end());
    return;
}

int32_t DeviceProfileDao::DeviceProfileToEntries(const DeviceProfile &deviceProfile, ValuesBucket &values)
{
    values.PutString(DEVICE_ID, deviceProfile.GetDeviceId());
    values.PutString(DEVICE_MODEL, deviceProfile.GetDeviceModel());
    values.PutString(DEV_TYPE, deviceProfile.GetDevType());
    values.PutString(MANU, deviceProfile.GetManu());
    values.PutString(SN, deviceProfile.GetSn());
    values.PutString(PRODUCT_ID, deviceProfile.GetProductId());
    values.PutString(PRODUCT_NAME, deviceProfile.GetProductName());
    values.PutString(SUB_PRODUCT_ID, deviceProfile.GetSubProductId());
    values.PutString(HIV, deviceProfile.GetHiv());
    values.PutString(MAC, deviceProfile.GetMac());
    values.PutString(FWV, deviceProfile.GetFwv());
    values.PutString(HWV, deviceProfile.GetHwv());
    values.PutString(SWV, deviceProfile.GetSwv());
    values.PutInt(PROT_TYPE, deviceProfile.GetProtType());
    values.PutString(DEVICE_NAME, deviceProfile.GetDeviceName());
    values.PutString(WISE_USER_ID, deviceProfile.GetWiseUserId());
    values.PutString(WISE_DEVICE_ID, deviceProfile.GetWiseDeviceId());
    values.PutString(REGISTER_TIME, deviceProfile.GetRegisterTime());
    values.PutString(INTERNAL_MODEL, deviceProfile.GetInternalModel());
    values.PutString(MODIFY_TIME, deviceProfile.GetModifyTime());
    values.PutString(SHARE_TIME, deviceProfile.GetShareTime());
    values.PutInt(USERID, deviceProfile.GetUserId());
    values.PutString(ACCOUNTID, deviceProfile.GetAccountId());
    values.PutString(BLE_MAC, deviceProfile.GetBleMac());
    values.PutString(BR_MAC, deviceProfile.GetBrMac());
    values.PutString(SLE_MAC, deviceProfile.GetSleMac());
    values.PutInt(SETUP_TYPE, deviceProfile.GetSetupType());
    return DP_SUCCESS;
}

int32_t DeviceProfileDao::ConvertToDeviceProfile(
    std::shared_ptr<ResultSet> resultSet, DeviceProfile& deviceProfile)
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
    deviceProfile.SetId(rowEntity.Get(ID));
    deviceProfile.SetDeviceId(rowEntity.Get(DEVICE_ID));
    deviceProfile.SetDeviceModel(rowEntity.Get(DEVICE_MODEL));
    deviceProfile.SetDevType(rowEntity.Get(DEV_TYPE));
    deviceProfile.SetManu(rowEntity.Get(MANU));
    deviceProfile.SetSn(rowEntity.Get(SN));
    deviceProfile.SetProductId(rowEntity.Get(PRODUCT_ID));
    deviceProfile.SetProductName(rowEntity.Get(PRODUCT_NAME));
    deviceProfile.SetSubProductId(rowEntity.Get(SUB_PRODUCT_ID));
    deviceProfile.SetHiv(rowEntity.Get(HIV));
    deviceProfile.SetMac(rowEntity.Get(MAC));
    deviceProfile.SetFwv(rowEntity.Get(FWV));
    deviceProfile.SetHwv(rowEntity.Get(HWV));
    deviceProfile.SetSwv(rowEntity.Get(SWV));
    deviceProfile.SetProtType(rowEntity.Get(PROT_TYPE));
    deviceProfile.SetDeviceName(rowEntity.Get(DEVICE_NAME));
    deviceProfile.SetWiseUserId(rowEntity.Get(WISE_USER_ID));
    deviceProfile.SetWiseDeviceId(rowEntity.Get(WISE_DEVICE_ID));
    deviceProfile.SetRegisterTime(rowEntity.Get(REGISTER_TIME));
    deviceProfile.SetInternalModel(rowEntity.Get(INTERNAL_MODEL));
    deviceProfile.SetModifyTime(rowEntity.Get(MODIFY_TIME));
    deviceProfile.SetShareTime(rowEntity.Get(SHARE_TIME));
    deviceProfile.SetUserId(rowEntity.Get(USERID));
    deviceProfile.SetAccountId(rowEntity.Get(ACCOUNTID));
    deviceProfile.SetBleMac(rowEntity.Get(BLE_MAC));
    deviceProfile.SetBrMac(rowEntity.Get(BR_MAC));
    deviceProfile.SetSleMac(rowEntity.Get(SLE_MAC));
    deviceProfile.SetSetupType(rowEntity.Get(SETUP_TYPE));
    return DP_SUCCESS;
}

void DeviceProfileDao::GenerateSqlAndCondition(const std::vector<int32_t> &params,
    std::string &sql, std::vector<ValueObject> &condition)
{
    for (auto param : params) {
        sql += "?,";
        condition.emplace_back(ValueObject(param));
    }
    sql.erase(sql.end() - 1, sql.end());
    sql += ") AND ";
    return;
}

void DeviceProfileDao::GenerateSqlAndCondition(const std::vector<std::string> &params,
    std::string &sql, std::vector<ValueObject> &condition)
{
    for (auto param : params) {
        sql += "?,";
        condition.emplace_back(ValueObject(param));
    }
    sql.erase(sql.end() - 1, sql.end());
    sql += ") AND ";
    return;
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
