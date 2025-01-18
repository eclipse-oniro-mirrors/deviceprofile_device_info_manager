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

#include "device_icon_info_dao.h"

#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"
#include "dp_services_constants.h"
#include "profile_data_rdb_adapter.h"

namespace OHOS {
namespace DistributedDeviceProfile {
IMPLEMENT_SINGLE_INSTANCE(DeviceIconInfoDao);
namespace {
    const std::string TAG = "DeviceIconInfoDao";
}

int32_t DeviceIconInfoDao::Init()
{
    std::lock_guard<std::mutex> lock(rdbMutex_);
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

int32_t DeviceIconInfoDao::UnInit()
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

int32_t DeviceIconInfoDao::PutDeviceIconInfo(const DeviceIconInfo& deviceIconInfo)
{
    ValuesBucket values;
    DeviceIconInfoToEntries(deviceIconInfo, values);
    int64_t rowId = ROWID_INIT;
    int32_t ret = RET_INIT;
    {
        std::lock_guard<std::mutex> lock(rdbMutex_);
        ret = ProfileDataRdbAdapter::GetInstance().Put(rowId, DEVICE_ICON_INFO_TABLE, values);
        if (ret != DP_SUCCESS) {
            HILOGE("%{public}s insert failed", DEVICE_ICON_INFO_TABLE.c_str());
            return DP_PUT_DEVICE_ICON_INFO_FAIL;
        }
    }
    HILOGI("end!");
    return DP_SUCCESS;
}

int32_t DeviceIconInfoDao::GetDeviceIconInfos(const DeviceIconInfoFilterOptions& filterOptions,
    std::vector<DeviceIconInfo>& deviceIconInfos)
{
    std::string sql;
    std::vector<ValueObject> condition;
    if (!CreateQuerySqlAndCondition(filterOptions, sql, condition)) {
        HILOGE("invalid params:%{public}s", filterOptions.dump().c_str());
        return DP_INVALID_PARAMS;
    }
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
        DeviceIconInfo deviceIconInfo;
        ConvertToDeviceIconInfo(resultSet, deviceIconInfo);
        deviceIconInfos.emplace_back(deviceIconInfo);
    }
    resultSet->Close();
    if (deviceIconInfos.empty()) {
        return DP_NOT_FIND_DATA;
    }
    HILOGI("end!");
    return DP_SUCCESS;
}

int32_t DeviceIconInfoDao::DeleteDeviceIconInfo(const DeviceIconInfo& deviceIconInfo)
{
    {
        std::lock_guard<std::mutex> lock(rdbMutex_);
        int32_t deleteRows = DELETEROWS_INIT;
        int32_t ret = ProfileDataRdbAdapter::GetInstance().Delete(deleteRows, DEVICE_ICON_INFO_TABLE,
            ID_EQUAL_CONDITION, std::vector<ValueObject>{ ValueObject(deviceIconInfo.GetId()) });
        if (ret != DP_SUCCESS) {
            HILOGE("delete %{public}s data failed", DEVICE_ICON_INFO_TABLE.c_str());
            return DP_DEL_DEVICE_ICON_INFO_FAIL;
        }
    }
    HILOGI("end!");
    return DP_SUCCESS;
}

int32_t DeviceIconInfoDao::UpdateDeviceIconInfo(const DeviceIconInfo& deviceIconInfo)
{
    ValuesBucket values;
    DeviceIconInfoToEntries(deviceIconInfo, values);
    int32_t changeRowCnt = CHANGEROWCNT_INIT;
    {
        std::lock_guard<std::mutex> lock(rdbMutex_);
        int32_t ret = ProfileDataRdbAdapter::GetInstance().Update(changeRowCnt, DEVICE_ICON_INFO_TABLE, values,
            ID_EQUAL_CONDITION, std::vector<ValueObject>{ ValueObject(deviceIconInfo.GetId()) });
        if (ret != DP_SUCCESS) {
            HILOGE("Update %{public}s table failed", DEVICE_ICON_INFO_TABLE.c_str());
            return DP_UPDATE_DEVICE_ICON_INFO_FAIL;
        }
    }
    HILOGI("end!");
    return DP_SUCCESS;
}

int32_t DeviceIconInfoDao::CreateTable()
{
    int32_t ret = ProfileDataRdbAdapter::GetInstance().CreateTable(CREATE_DEVICE_ICON_INFO_TABLE_SQL);
    if (ret != DP_SUCCESS) {
        HILOGE("%{public}s create failed", DEVICE_ICON_INFO_TABLE.c_str());
        return DP_CREATE_TABLE_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DeviceIconInfoDao::CreateIndex()
{
    int32_t ret = ProfileDataRdbAdapter::GetInstance().CreateTable(CREATE_DEVICE_ICON_INFO_TABLE_UNIQUE_INDEX_SQL);
    if (ret != DP_SUCCESS) {
        HILOGE("%{public}s unique index create failed", DEVICE_ICON_INFO_TABLE.c_str());
        return DP_CREATE_UNIQUE_INDEX_FAIL;
    }
    return DP_SUCCESS;
}

bool DeviceIconInfoDao::CreateQuerySqlAndCondition(const DeviceIconInfoFilterOptions& filterOptions,
    std::string& sql, std::vector<ValueObject>& condition)
{
    sql = SELECT_DEVICE_ICON_INFO_TABLE;
    bool flag = false;
    if (!filterOptions.GetProductIds().empty()) {
        sql += "a." + PRODUCT_ID + " IN(";
        for (const auto& prodId : filterOptions.GetProductIds()) {
            sql += "?,";
            condition.emplace_back(ValueObject(prodId));
        }
        sql.erase(sql.end() - 1, sql.end());
        sql += ") AND ";
        flag = true;
    }
    if (!filterOptions.GetSubProductId().empty()) {
        sql += "a." + SUB_PRODUCT_ID + " = ? AND ";
        condition.emplace_back(ValueObject(filterOptions.GetSubProductId()));
        flag = true;
    }
    if (!filterOptions.GetImageType().empty()) {
        sql += "a." + IMAGE_TYPE + " = ? AND ";
        condition.emplace_back(ValueObject(filterOptions.GetImageType()));
        flag = true;
    }
    if (!filterOptions.GetSpecName().empty()) {
        sql += "a." + SPEC_NAME + " = ? AND ";
        condition.emplace_back(ValueObject(filterOptions.GetSpecName()));
        flag = true;
    }
    if (flag) {
        sql.erase(sql.end() - NUM_4, sql.end());
        return flag;
    }
    return flag;
}

int32_t DeviceIconInfoDao::DeviceIconInfoToEntries(const DeviceIconInfo& deviceIconInfo, ValuesBucket& values)
{
    values.PutString(PRODUCT_ID, deviceIconInfo.GetProductId());
    values.PutString(SUB_PRODUCT_ID, deviceIconInfo.GetSubProductId());
    values.PutString(IMAGE_TYPE, deviceIconInfo.GetImageType());
    values.PutString(SPEC_NAME, deviceIconInfo.GetSpecName());
    values.PutString(DEVICE_ICON_VERSION, deviceIconInfo.GetVersion());
    values.PutString(DEVICE_ICON_URL, deviceIconInfo.GetUrl());
    values.PutBlob(DEVICE_ICON, deviceIconInfo.GetIcon());
    return DP_SUCCESS;
}

int32_t DeviceIconInfoDao::ConvertToDeviceIconInfo(std::shared_ptr<ResultSet> resultSet, DeviceIconInfo& deviceIconInfo)
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
    deviceIconInfo.SetId(rowEntity.Get(ID));
    deviceIconInfo.SetProductId(rowEntity.Get(PRODUCT_ID));
    deviceIconInfo.SetSubProductId(rowEntity.Get(SUB_PRODUCT_ID));
    deviceIconInfo.SetImageType(rowEntity.Get(IMAGE_TYPE));
    deviceIconInfo.SetSpecName(rowEntity.Get(SPEC_NAME));
    deviceIconInfo.SetVersion(rowEntity.Get(DEVICE_ICON_VERSION));
    deviceIconInfo.SetWiseVersion(rowEntity.Get(IMAGE_VERSION));
    deviceIconInfo.SetUrl(rowEntity.Get(DEVICE_ICON_URL));
    deviceIconInfo.SetIcon(rowEntity.Get(DEVICE_ICON));
    return DP_SUCCESS;
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
