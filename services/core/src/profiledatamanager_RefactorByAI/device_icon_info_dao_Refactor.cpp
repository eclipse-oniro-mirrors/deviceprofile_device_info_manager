/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "device_icon_info_dao_Refactor.h"

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
    // [原则7] 限制IN条件最大元素数，防止构造超大SQL导致资源耗尽
    constexpr uint32_t MAX_IN_QUERY_SIZE = 500;

    // [原则12] RAII守卫，保证结果集在任何退出路径都被关闭，避免资源泄漏
    class ResultSetGuard {
    public:
        explicit ResultSetGuard(std::shared_ptr<ResultSet> resultSet) : resultSet_(std::move(resultSet)) {}
        ~ResultSetGuard()
        {
            if (resultSet_ != nullptr) {
                resultSet_->Close();
            }
        }
        // 禁止拷贝，防止多次Close
        ResultSetGuard(const ResultSetGuard&) = delete;
        ResultSetGuard& operator=(const ResultSetGuard&) = delete;
    private:
        std::shared_ptr<ResultSet> resultSet_;
    };
}

int32_t DeviceIconInfoDao::Init()
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
    // [原则12] 校验建表/建索引返回值，失败时提前返回，避免数据库处于不一致状态
    ret = CreateTable();
    if (ret != DP_SUCCESS) {
        HILOGE("CreateTable failed, ret:%{public}d", ret);
        return ret;
    }
    ret = CreateIndex();
    if (ret != DP_SUCCESS) {
        HILOGE("CreateIndex failed, ret:%{public}d", ret);
        return ret;
    }
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
    // [原则3] 校验入库数据合法性，主键字段（productId、internalModel）不可为空或超长
    if (!IsValidDeviceIconInfo(deviceIconInfo)) {
        HILOGE("invalid deviceIconInfo params");
        return DP_INVALID_PARAMS;
    }
    HILOGI("deviceIconInfo:%{public}s", deviceIconInfo.dump().c_str());
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
    // [原则12] 使用RAII守卫，确保结果集在任何路径下（包括提前返回）都被正确关闭
    ResultSetGuard guard(resultSet);
    int32_t rowCount = ROWCOUNT_INIT;
    resultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        HILOGE("by condition not find data");
        return DP_NOT_FIND_DATA;
    }
    while (resultSet->GoToNextRow() == DP_SUCCESS) {
        DeviceIconInfo deviceIconInfo;
        ConvertToDeviceIconInfo(resultSet, deviceIconInfo);
        deviceIconInfos.emplace_back(deviceIconInfo);
    }
    if (deviceIconInfos.empty()) {
        return DP_NOT_FIND_DATA;
    }
    return DP_SUCCESS;
}

int32_t DeviceIconInfoDao::DeleteDeviceIconInfo(const DeviceIconInfo& deviceIconInfo)
{
    // [原则3] 校验id合法性，id<=0时不应执行删除，防止误删或无效操作
    if (deviceIconInfo.GetId() <= 0) {
        HILOGE("invalid id:%{public}d", deviceIconInfo.GetId());
        return DP_INVALID_PARAMS;
    }
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
    return DP_SUCCESS;
}

int32_t DeviceIconInfoDao::UpdateDeviceIconInfo(const DeviceIconInfo& deviceIconInfo)
{
    // [原则3] 校验数据合法性：id必须有效（>0），主键字段不可为空或超长
    if (!IsValidDeviceIconInfo(deviceIconInfo) || deviceIconInfo.GetId() <= 0) {
        HILOGE("invalid deviceIconInfo params, id:%{public}d", deviceIconInfo.GetId());
        return DP_INVALID_PARAMS;
    }
    HILOGI("deviceIconInfo:%{public}s", deviceIconInfo.dump().c_str());
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
    const auto& productIds = filterOptions.GetProductIds();
    // [原则7] 限制IN条件元素数量，防止超大SQL导致资源耗尽或超出SQLite占位符上限（默认999）
    if (productIds.size() > MAX_IN_QUERY_SIZE) {
        HILOGE("productIds size too large:%{public}zu", productIds.size());
        return false;
    }
    if (!productIds.empty()) {
        sql += "a." + PRODUCT_ID + " IN(";
        for (const auto& prodId : productIds) {
            sql += "?,";
            condition.emplace_back(ValueObject(prodId));
        }
        sql.erase(sql.end() - 1, sql.end());
        sql += ") AND ";
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
        sql += "a." + SUB_PRODUCT_ID + " = ? AND ";
        condition.emplace_back(ValueObject(filterOptions.GetSubProductId()));
        sql += "a." + INTERNAL_MODEL + " = ? ORDER By a.id LIMIT 1 ";
        condition.emplace_back(ValueObject(filterOptions.GetInternalModel()));
    }
    return flag;
}

int32_t DeviceIconInfoDao::DeviceIconInfoToEntries(const DeviceIconInfo& deviceIconInfo, ValuesBucket& values)
{
    values.PutString(PRODUCT_ID, deviceIconInfo.GetProductId());
    values.PutString(INTERNAL_MODEL, deviceIconInfo.GetInternalModel());
    values.PutString(SUB_PRODUCT_ID, deviceIconInfo.GetSubProductId());
    values.PutString(IMAGE_TYPE, deviceIconInfo.GetImageType());
    values.PutString(SPEC_NAME, deviceIconInfo.GetSpecName());
    values.PutString(DEVICE_ICON_VERSION, deviceIconInfo.GetVersion());
    values.PutString(DEVICE_ICON_URL, deviceIconInfo.GetUrl());
    if (!deviceIconInfo.GetIcon().empty()) {
        values.PutBlob(DEVICE_ICON, deviceIconInfo.GetIcon());
    }
    values.PutLong(MODIFY_TIME, deviceIconInfo.GetModifyTime());
    return DP_SUCCESS;
}

int32_t DeviceIconInfoDao::ConvertToDeviceIconInfo(std::shared_ptr<ResultSet> resultSet, DeviceIconInfo& deviceIconInfo)
{
    if (resultSet == nullptr) {
        HILOGE("resultSet is nullptr.");
        return DP_GET_RESULTSET_FAIL;
    }
    RowEntity rowEntity;
    if (resultSet->GetRow(rowEntity) != DP_SUCCESS) {
        HILOGE("get resultSet failed");
        return DP_GET_RESULTSET_FAIL;
    }
    deviceIconInfo.SetId(rowEntity.Get(ID));
    deviceIconInfo.SetProductId(rowEntity.Get(PRODUCT_ID));
    deviceIconInfo.SetInternalModel(rowEntity.Get(INTERNAL_MODEL));
    deviceIconInfo.SetSubProductId(rowEntity.Get(SUB_PRODUCT_ID));
    deviceIconInfo.SetImageType(rowEntity.Get(IMAGE_TYPE));
    deviceIconInfo.SetSpecName(rowEntity.Get(SPEC_NAME));
    deviceIconInfo.SetVersion(rowEntity.Get(DEVICE_ICON_VERSION));
    deviceIconInfo.SetWiseVersion(rowEntity.Get(IMAGE_VERSION));
    deviceIconInfo.SetUrl(rowEntity.Get(DEVICE_ICON_URL));
    deviceIconInfo.SetIcon(rowEntity.Get(DEVICE_ICON));
    deviceIconInfo.SetModifyTime(rowEntity.Get(MODIFY_TIME));
    return DP_SUCCESS;
}

// [原则3] 校验DeviceIconInfo的合法性：主键字段（productId、internalModel）必填，各字段不超长
bool DeviceIconInfoDao::IsValidDeviceIconInfo(const DeviceIconInfo& deviceIconInfo) const
{
    if (deviceIconInfo.GetProductId().empty() || deviceIconInfo.GetProductId().size() > MAX_STRING_LEN) {
        HILOGE("productId is invalid");
        return false;
    }
    if (deviceIconInfo.GetInternalModel().empty() || deviceIconInfo.GetInternalModel().size() > MAX_STRING_LEN) {
        HILOGE("internalModel is invalid");
        return false;
    }
    if (deviceIconInfo.GetSubProductId().size() > MAX_STRING_LEN) {
        HILOGE("subProductId exceeds max length");
        return false;
    }
    if (deviceIconInfo.GetImageType().size() > MAX_STRING_LEN) {
        HILOGE("imageType exceeds max length");
        return false;
    }
    if (deviceIconInfo.GetSpecName().size() > MAX_STRING_LEN) {
        HILOGE("specName exceeds max length");
        return false;
    }
    return true;
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
