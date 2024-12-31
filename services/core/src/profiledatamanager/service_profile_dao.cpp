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

#include "service_profile_dao.h"

#include <memory>

#include "content_sensor_manager_utils.h"
#include "device_profile_manager.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"
#include "dp_services_constants.h"
#include "profile_cache.h"
#include "profile_data_rdb_adapter.h"
#include "subscribe_profile_manager.h"

namespace OHOS {
namespace DistributedDeviceProfile {
IMPLEMENT_SINGLE_INSTANCE(ServiceProfileDao);
namespace {
const std::string TAG = "DistributedDeviceProfile";
}

int32_t ServiceProfileDao::Init()
{
    if (!ProfileDataRdbAdapter::GetInstance().IsInit()) {
        if (ProfileDataRdbAdapter::GetInstance().Init() != DP_SUCCESS) {
            HILOGE("ProfileDataRdbAdapter Init failed");
            return DP_INIT_DB_FAILED;
        }
    }
    CreateTable();
    CreateIndex();
    HILOGI("end!");
    return DP_SUCCESS;
}

int32_t ServiceProfileDao::UnInit()
{
    if (!ProfileDataRdbAdapter::GetInstance().IsInit()) {
        HILOGE("ProfileDataRdbAdapter is UnInit");
        return DP_SUCCESS;
    }
    if (ProfileDataRdbAdapter::GetInstance().UnInit() != DP_SUCCESS) {
        HILOGE("ProfileDataRdbAdapter UnInit failed");
        return DP_UNINIT_FAIL;
    }
    HILOGI("end!");
    return DP_SUCCESS;
}

int32_t ServiceProfileDao::PutServiceProfile(ServiceProfile& serviceProfile)
{
    if (serviceProfile.GetDeviceId().empty() || serviceProfile.GetServiceName().empty() ||
        serviceProfile.GetServiceType().empty() || serviceProfile.GetDeviceProfileId() == DEFAULT_DEVICE_PROFILE_ID) {
        HILOGE("serviceProfile params is invalid!");
        return DP_INVALID_PARAMS;
    }
    ValuesBucket values;
    ServiceProfileToEntries(serviceProfile, values);
    int64_t rowId = ROWID_INIT;
    if (ProfileDataRdbAdapter::GetInstance().Put(rowId, SERVICE_PROFILE_TABLE, values) != DP_SUCCESS) {
        HILOGE("service_profile insert failed");
        return DP_RDB_PUT_SERVICE_PROFILE_FAIL;
    }
    if (SetServiceProfileId(serviceProfile) != DP_SUCCESS) {
        HILOGE("SetServiceProfileId fail");
        return DP_RDB_SET_SERVICE_PROFILE_ID_FAIL;
    }
    SubscribeProfileManager::GetInstance().NotifyServiceProfileAdd(serviceProfile);
    std::string localUdid = ProfileCache::GetInstance().GetLocalUdid();
    if (localUdid == serviceProfile.GetDeviceId()) {
        DeviceProfileManager::GetInstance().PutServiceProfile(serviceProfile);
    }
    HILOGI("end!");
    return DP_SUCCESS;
}

int32_t ServiceProfileDao::DeleteServiceProfile(const ServiceProfile& serviceProfile)
{
    if (serviceProfile.GetDeviceId().empty() || serviceProfile.GetServiceName().empty() ||
        serviceProfile.GetServiceType().empty() || serviceProfile.GetId() == DEFAULT_SERVICE_PROFILE_ID) {
        HILOGE("serviceProfile params is invalid!");
        return DP_INVALID_PARAMS;
    }
    int32_t deleteRows = DELETEROWS_INIT;
    int32_t ret = ProfileDataRdbAdapter::GetInstance().Delete(deleteRows, SERVICE_PROFILE_TABLE, ID_EQUAL_CONDITION,
        std::vector<ValueObject>{ ValueObject(serviceProfile.GetId()) });
    if (ret != DP_SUCCESS) {
        HILOGE("delete service_profile data failed");
        return DP_RDB_DELETE_SERVICE_PROFILE_FAIL;
    }
    SubscribeProfileManager::GetInstance().NotifyServiceProfileDelete(serviceProfile);
    std::string localUdid = ProfileCache::GetInstance().GetLocalUdid();
    if (localUdid == serviceProfile.GetDeviceId()) {
        DeviceProfileManager::GetInstance().DeleteServiceProfile(serviceProfile.GetDeviceId(),
            serviceProfile.GetServiceName(), true, serviceProfile.GetUserId());
    }
    HILOGI("end!");
    return DP_SUCCESS;
}

int32_t ServiceProfileDao::UpdateServiceProfile(const ServiceProfile& serviceProfile)
{
    if (serviceProfile.GetDeviceId().empty() || serviceProfile.GetServiceName().empty() ||
        serviceProfile.GetServiceType().empty() || serviceProfile.GetId() == DEFAULT_SERVICE_PROFILE_ID) {
        HILOGE("serviceProfile params is invalid!");
        return DP_INVALID_PARAMS;
    }
    ValuesBucket values;
    ServiceProfileToEntries(serviceProfile, values);
    int32_t changeRowCnt = CHANGEROWCNT_INIT;
    int32_t ret = ProfileDataRdbAdapter::GetInstance().Update(
        changeRowCnt, SERVICE_PROFILE_TABLE, values, ID_EQUAL_CONDITION,
        std::vector<ValueObject>{ ValueObject(serviceProfile.GetId()) });
    if (ret != DP_SUCCESS) {
        HILOGE("Update service_profile table failed");
        return DP_UPDATE_TRUST_DEVICE_PROFILE_FAIL;
    }
    SubscribeProfileManager::GetInstance().NotifyServiceProfileUpdate(serviceProfile);
    std::string localUdid = ContentSensorManagerUtils::GetInstance().ObtainLocalUdid();
    if (localUdid == serviceProfile.GetDeviceId()) {
        DeviceProfileManager::GetInstance().PutServiceProfile(serviceProfile);
    }
    HILOGI("end!");
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfile::ServiceProfileDao::GetServiceProfiles(
    const ServiceProfileFilterOptions& filterOptions, std::vector<ServiceProfile>& serviceProfiles)
{
    if (filterOptions.IsEmpty()) {
        HILOGE("filterOptions is empty!");
        return DP_INVALID_PARAMS;
    }
    std::vector<ValueObject> condition;
    std::string sql = "";
    if (CreateQuerySqlAndCondition(filterOptions, sql, condition) != DP_SUCCESS) {
        HILOGE("CreateQuerySqlAndCondition failed!");
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
        ServiceProfile serviceProfile;
        ConvertToServiceProfile(resultSet, serviceProfile);
        serviceProfiles.emplace_back(serviceProfile);
    }
    resultSet->Close();
    if (serviceProfiles.empty()) {
        return DP_NOT_FIND_DATA;
    }
    HILOGI("end!");
    return DP_SUCCESS;
}

int32_t ServiceProfileDao::CreateTable()
{
    int32_t ret = ProfileDataRdbAdapter::GetInstance().CreateTable(CREATE_SERVICE_PROFILE_TABLE_SQL);
    if (ret != DP_SUCCESS) {
        HILOGE("service_profile create failed");
        return DP_CREATE_TABLE_FAIL;
    }
    return DP_SUCCESS;
}

int32_t ServiceProfileDao::CreateIndex()
{
    int32_t ret = ProfileDataRdbAdapter::GetInstance().CreateTable(CREATE_SERVICE_PROFILE_TABLE_INDEX_SERVICEID_SQL);
    if (ret != DP_SUCCESS) {
        HILOGE("service_profile index create failed");
        return DP_CREATE_UNIQUE_INDEX_FAIL;
    }
    ret = ProfileDataRdbAdapter::GetInstance().CreateTable(CREATE_SERVICE_PROFILE_TABLE_INDEX_DEVICEPROFILEID_SQL);
    if (ret != DP_SUCCESS) {
        HILOGE("service_profile index create failed");
        return DP_CREATE_UNIQUE_INDEX_FAIL;
    }
    return DP_SUCCESS;
}

int32_t ServiceProfileDao::ConvertToServiceProfile(std::shared_ptr<ResultSet> resultSet,
    ServiceProfile& serviceProfile)
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
    serviceProfile.SetId(rowEntity.Get(ID));
    serviceProfile.SetDeviceProfileId(rowEntity.Get(SERVICE_PROFILE_DEVICE_PROFILE_ID));
    serviceProfile.SetDeviceId(rowEntity.Get(DEVICE_ID));
    serviceProfile.SetServiceName(rowEntity.Get(SERVICE_PROFILE_SERVICE_ID));
    serviceProfile.SetServiceType(rowEntity.Get(SERVICE_TYPE));
    serviceProfile.SetUserId(rowEntity.Get(RDB_USER_ID));
    return DP_SUCCESS;
}

int32_t ServiceProfileDao::CreateQuerySqlAndCondition(const ServiceProfileFilterOptions& filterOptions,
    std::string& sql, std::vector<ValueObject>& condition)
{
    std::string whereSql = "";
    CreateComplexQuerySqlAndCondition(filterOptions, whereSql, condition);
    CreateBaseQuerySqlAndCondition(filterOptions, whereSql, condition);
    if (whereSql.empty()) {
        HILOGE("whereSql is empty!");
        return DP_INVALID_PARAMS;
    }
    whereSql.erase(whereSql.end() - NUM_3, whereSql.end());
    sql = SELECT_SERVICE_PROGILES + whereSql;
    return DP_SUCCESS;
}

void ServiceProfileDao::CreateComplexQuerySqlAndCondition(const ServiceProfileFilterOptions& filterOptions,
    std::string& whereSql, std::vector<ValueObject>& condition)
{
    // whereSql append service_profile.id
    if (!filterOptions.GetServiceProfileIds().empty()) {
        whereSql += "service_profile.id IN (";
        for (auto& id : filterOptions.GetServiceProfileIds()) {
            whereSql += "?,";
            condition.emplace_back(ValueObject(id));
        }
        whereSql.erase(whereSql.end() - 1, whereSql.end());
        whereSql += ") AND";
    }
    // whereSql append service_profile.serviceId
    if (!filterOptions.GetServiceIds().empty()) {
        whereSql += "service_profile.serviceId IN (";
        for (auto& serviceId : filterOptions.GetServiceIds()) {
            whereSql += "?,";
            condition.emplace_back(ValueObject(serviceId));
        }
        whereSql.erase(whereSql.end() - 1, whereSql.end());
        whereSql += ") AND";
    }
    // whereSql append service_profile.deviceProfileId
    if (!filterOptions.GetDeviceProfileIds().empty()) {
        whereSql += "service_profile.deviceProfileId IN (";
        for (auto& deviceProfileId : filterOptions.GetDeviceProfileIds()) {
            whereSql += "?,";
            condition.emplace_back(ValueObject(deviceProfileId));
        }
        whereSql.erase(whereSql.end() - 1, whereSql.end());
        whereSql += ") AND";
    }
}

void ServiceProfileDao::CreateBaseQuerySqlAndCondition(const ServiceProfileFilterOptions& filterOptions,
    std::string& whereSql, std::vector<ValueObject>& condition)
{
    // whereSql append device_profile.userId
    if (filterOptions.GetUserId() != DEFAULT_USER_ID) {
        whereSql += "device_profile.userId=? AND";
        condition.emplace_back(ValueObject(filterOptions.GetUserId()));
    }
    // whereSql append device_profile.accountId
    if (!filterOptions.GetAccountId().empty()) {
        whereSql += "device_profile.accountId=? AND";
        condition.emplace_back(ValueObject(filterOptions.GetAccountId()));
    }
    // whereSql append device_profile.deviceId
    if (!filterOptions.GetDeviceId().empty()) {
        whereSql += "device_profile.deviceId=? AND";
        condition.emplace_back(ValueObject(filterOptions.GetDeviceId()));
    }
    // whereSql append device_profile.wiseDeviceId
    if (!filterOptions.GetWiseDeviceIds().empty()) {
        whereSql += "device_profile.wiseDeviceId IN (";
        for (auto& wiseDeviceId : filterOptions.GetWiseDeviceIds()) {
            whereSql += "?,";
            condition.emplace_back(ValueObject(wiseDeviceId));
        }
        whereSql.erase(whereSql.end() - 1, whereSql.end());
        whereSql += ") AND";
    }
}

void ServiceProfileDao::ServiceProfileToEntries(const ServiceProfile& serviceProfile, ValuesBucket& values)
{
    values.PutInt(SERVICE_PROFILE_DEVICE_PROFILE_ID, serviceProfile.GetDeviceProfileId());
    values.PutString(SERVICE_PROFILE_SERVICE_ID, serviceProfile.GetServiceName());
    values.PutString(SERVICE_PROFILE_SERVICE_TYPE, serviceProfile.GetServiceType());
}

int32_t ServiceProfileDao::SetServiceProfileId(ServiceProfile& serviceProfile)
{
    std::shared_ptr<ResultSet> resultSet = ProfileDataRdbAdapter::GetInstance().Get(
        SELECT_SERVICE_PROFILE_TABLE_WHERE_DEVID_SERID_SERTYPE, std::vector<ValueObject>{
        serviceProfile.GetDeviceProfileId(), serviceProfile.GetServiceName(), serviceProfile.GetServiceType()});
    if (resultSet == nullptr) {
        HILOGE("resultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    while (resultSet->GoToNextRow() == DP_SUCCESS) {
        int32_t columnIndex = COLUMNINDEX_INIT;
        int32_t id = DEVICE_PROFILE_ID_INIT;
        resultSet->GetColumnIndex(ID, columnIndex);
        resultSet->GetInt(columnIndex, id);
        serviceProfile.SetId(id);
    }
    resultSet->Close();
    return DP_SUCCESS;
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
