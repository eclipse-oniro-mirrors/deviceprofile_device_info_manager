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

#include "device_profile_dao_Refactor.h"
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
        ResultSetGuard(const ResultSetGuard&) = delete;
        ResultSetGuard& operator=(const ResultSetGuard&) = delete;
    private:
        std::shared_ptr<ResultSet> resultSet_;
    };
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
    // [原则3] 校验入库数据合法性，deviceId不可为空或超长
    if (!IsValidDeviceProfile(deviceProfile)) {
        HILOGE("invalid deviceProfile params");
        return DP_INVALID_PARAMS;
    }
    ValuesBucket values;
    DeviceProfileToEntries(deviceProfile, values);
    int64_t rowId = ROWID_INIT;
    int32_t ret = RET_INIT;
    {
        std::lock_guard<std::mutex> lock(rdbMutex_);
        ret = ProfileDataRdbAdapter::GetInstance().Put(rowId, DEVICE_PROFILE_TABLE, values);
        if (ret != DP_SUCCESS) {
            HILOGE("deviceprofile insert failed");
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
    // [原则12] 使用RAII守卫，确保结果集在任何路径下都被正确关闭
    ResultSetGuard guard(resultSet);
    DeviceProfile profile(deviceProfile);
    while (resultSet->GoToNextRow() == DP_SUCCESS) {
        int32_t columnIndex = COLUMNINDEX_INIT;
        int32_t id = DEVICE_PROFILE_ID_INIT;
        resultSet->GetColumnIndex(ID, columnIndex);
        resultSet->GetInt(columnIndex, id);
        profile.SetId(id);
    }
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
    // [原则12] 使用RAII守卫，确保结果集在任何路径下都被正确关闭
    ResultSetGuard guard(resultSet);
    int32_t rowCount = ROWCOUNT_INIT;
    resultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        return DP_NOT_FIND_DATA;
    }
    while (resultSet->GoToNextRow() == DP_SUCCESS) {
        DeviceProfile deviceProfile;
        ConvertToDeviceProfile(resultSet, deviceProfile);
        deviceProfiles.emplace_back(deviceProfile);
    }
    if (deviceProfiles.empty()) {
        return DP_NOT_FIND_DATA;
    }
    return DP_SUCCESS;
}

int32_t DeviceProfileDao::DeleteDeviceProfile(const DeviceProfile &deviceProfile)
{
    // [原则3] 校验id合法性，id<=0时不应执行删除，防止误删或无效操作
    if (deviceProfile.GetId() <= 0) {
        HILOGE("invalid id:%{public}d", deviceProfile.GetId());
        return DP_INVALID_PARAMS;
    }
    {
        std::lock_guard<std::mutex> lock(rdbMutex_);
        int32_t deleteRows = DELETEROWS_INIT;
        int32_t ret = ProfileDataRdbAdapter::GetInstance().Delete(deleteRows, DEVICE_PROFILE_TABLE, ID_EQUAL_CONDITION,
            std::vector<ValueObject>{ ValueObject(deviceProfile.GetId()) });
        if (ret != DP_SUCCESS) {
            HILOGE("delete deviceprofile data failed, ret=%{public}d", ret);
            return DP_DELETE_TRUST_DEVICE_PROFILE_FAIL;
        }
    }
    return DP_SUCCESS;
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
