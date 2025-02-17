/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "service_info_profile_manager.h"

#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"
#include "dp_services_constants.h"

namespace OHOS {
namespace DistributedDeviceProfile {
IMPLEMENT_SINGLE_INSTANCE(ServiceInfoProfileManager)

namespace {
const std::string TAG = "ServiceInfoProfileManager";
}

int32_t ServiceInfoProfileManager::Init()
{
    int32_t ret = ServiceInfoRdbAdapter::GetInstance().Init();
    if (ret != DP_SUCCESS) {
        HILOGE("ServiceInfoRdbAdapter Init failed");
        return DP_INIT_DB_FAILED;
    }
    CreateTable();
    CreateIndex();
    HILOGI("end!");
    return DP_SUCCESS;
}

int32_t ServiceInfoProfileManager::UnInit()
{
    int32_t ret = ServiceInfoRdbAdapter::GetInstance().UnInit();
    if (ret != DP_SUCCESS) {
        HILOGE("ServiceInfoRdbAdapter UnInit failed");
        return DP_UNINIT_FAIL;
    }
    return DP_SUCCESS;
}

int32_t ServiceInfoProfileManager::CreateTable()
{
    int32_t ret = ServiceInfoRdbAdapter::GetInstance().CreateTable(CREATE_SERVICE_INFO_PROFILE_TABLE_SQL);
    if (ret != DP_SUCCESS) {
        HILOGE("service_info_profile create failed");
        return DP_CREATE_TABLE_FAIL;
    }
    return DP_SUCCESS;
}

int32_t ServiceInfoProfileManager::CreateIndex()
{
    int32_t ret = ServiceInfoRdbAdapter::GetInstance().CreateTable(
        CREATE_SERVICE_INFO_PROFILE_TABLE_UNIQUE_INDEX_SQL);
    if (ret != DP_SUCCESS) {
        HILOGE("service_info_profile unique index create failed");
        return DP_CREATE_UNIQUE_INDEX_FAIL;
    }
    return DP_SUCCESS;
}

int32_t ServiceInfoProfileManager::PutServiceInfoProfile(const ServiceInfoProfile& serviceInfoProfile)
{
    if (serviceInfoProfile.GetDeviceId().empty() || serviceInfoProfile.GetUserId() == DEFAULT_USER_ID ||
        serviceInfoProfile.GetTokenId().empty() || serviceInfoProfile.GetServiceId() == DEFAULT_USER_ID) {
        HILOGE("Invalid parameter");
        return DP_INVALID_PARAM;
    }
    ValuesBucket values;
    ServiceInfoProfileToEntries(serviceInfoProfile, values);
    int64_t rowId = ROWID_INIT;
    int32_t ret = RET_INIT;
    ServiceInfoUniqueKey key;
    ServiceInfoProfile oldSerInfo;
    key.SetDeviceId(serviceInfoProfile.GetDeviceId());
    key.SetUserId(serviceInfoProfile.GetUserId());
    key.SetTokenId(serviceInfoProfile.GetTokenId());
    key.SetServiceId(serviceInfoProfile.GetServiceId());
    int32_t getRet = GetServiceInfoProfileByUniqueKey(key, oldSerInfo);
    if (getRet == DP_SUCCESS) {
        HILOGI("serviceInfoProfile already exit");
        return DP_SUCCESS;
    }
    ret = ServiceInfoRdbAdapter::GetInstance().Put(rowId, SERVICE_INFO_PROFILE_TABLE, values);
    if (ret != DP_SUCCESS) {
        HILOGE("%{public}s insert failed", SERVICE_INFO_PROFILE_TABLE.c_str());
        return DP_PUT_SERVICE_INFO_PROFILE_FAIL;
    }
    HILOGI("end!");
    return DP_SUCCESS;
}

int32_t ServiceInfoProfileManager::DeleteServiceInfoProfile(const ServiceInfoUniqueKey& key)
{
    if (key.GetDeviceId().empty() || key.GetUserId() == DEFAULT_USER_ID ||
        key.GetTokenId().empty() || key.GetServiceId() == DEFAULT_SERVICE_ID) {
        HILOGE("Invalid parameter");
        return DP_INVALID_PARAM;
    }
    ServiceInfoProfile oldServiceInfo;
    int32_t getRet = GetServiceInfoProfileByUniqueKey(key, oldServiceInfo);
    if (getRet == DP_NOT_FIND_DATA) {
        HILOGI("ServiceInfoProfile not exit, doesn't need delete");
        return DP_SUCCESS;
    }
    if (getRet != DP_SUCCESS) {
        HILOGE("GetServiceInfoProfile filed");
        return getRet;
    }
    int32_t deleteRows = DELETEROWS_INIT;
    int32_t ret = ServiceInfoRdbAdapter::GetInstance().Delete(deleteRows, SERVICE_INFO_PROFILE_TABLE,
        SERVICE_INFO_PROFILE_UNIQUE_INDEX_EQUAL_CONDITION,
        std::vector<ValueObject>{ValueObject(key.GetDeviceId()), ValueObject(key.GetUserId()),
        ValueObject(key.GetTokenId()), ValueObject(key.GetServiceId())});
    if (ret != DP_SUCCESS) {
        HILOGE("delete %{public}s data failed", SERVICE_INFO_PROFILE_TABLE.c_str());
        return DP_DELETE_SERVICE_INFO_PROFILE_FAIL;
    }
    HILOGI("end!");
    return DP_SUCCESS;
}

int32_t ServiceInfoProfileManager::UpdateServiceInfoProfile(const ServiceInfoProfile& serviceInfoProfile)
{
    if (serviceInfoProfile.GetDeviceId().empty() || serviceInfoProfile.GetUserId() == DEFAULT_USER_ID ||
        serviceInfoProfile.GetTokenId().empty() || serviceInfoProfile.GetServiceId() == DEFAULT_SERVICE_ID) {
        HILOGE("Invalid parameter");
        return DP_INVALID_PARAM;
    }
    ServiceInfoUniqueKey key;
    ServiceInfoProfile serInfo;
    key.SetDeviceId(serviceInfoProfile.GetDeviceId());
    key.SetUserId(serviceInfoProfile.GetUserId());
    key.SetTokenId(serviceInfoProfile.GetTokenId());
    key.SetServiceId(serviceInfoProfile.GetServiceId());
    int32_t getRet = GetServiceInfoProfileByUniqueKey(key, serInfo);
    if (getRet == DP_NOT_FIND_DATA) {
        HILOGE("serviceInfoProfile not exit, can't update");
        return getRet;
    }
    if (getRet != DP_SUCCESS) {
        HILOGI("GetServiceInfoProfileByUniqueKey failed");
        return getRet;
    }
    ValuesBucket values;
    ServiceInfoProfileToEntries(serviceInfoProfile, values);
    int32_t changeRowCnt = CHANGEROWCNT_INIT;
    int32_t ret = ServiceInfoRdbAdapter::GetInstance().Update(changeRowCnt, SERVICE_INFO_PROFILE_TABLE, values,
        SERVICE_INFO_PROFILE_UNIQUE_INDEX_EQUAL_CONDITION,
        std::vector<ValueObject>{ValueObject(serviceInfoProfile.GetDeviceId()),
        ValueObject(serviceInfoProfile.GetUserId()),
        ValueObject(serviceInfoProfile.GetTokenId()),
        ValueObject(serviceInfoProfile.GetServiceId())});
    if (ret != DP_SUCCESS) {
        HILOGE("Update %{public}s table failed", SERVICE_INFO_PROFILE_TABLE.c_str());
        return DP_UPDATE_SERVICE_INFO_PROFILE_FAIL;
    }
    HILOGI("end!");
    return DP_SUCCESS;
}

int32_t ServiceInfoProfileManager::GetServiceInfoProfileByUniqueKey(const ServiceInfoUniqueKey& key,
    ServiceInfoProfile& serviceInfoProfile)
{
    if (key.GetDeviceId().empty() || key.GetUserId() == DEFAULT_USER_ID ||
        key.GetTokenId().empty() || key.GetServiceId() == DEFAULT_SERVICE_ID) {
        HILOGE("Invalid parameter");
        return DP_INVALID_PARAM;
    }
    std::vector<ValueObject> condition;
    condition.emplace_back(ValueObject(key.GetDeviceId()));
    condition.emplace_back(ValueObject(key.GetUserId()));
    condition.emplace_back(ValueObject(key.GetTokenId()));
    condition.emplace_back(ValueObject(key.GetServiceId()));
    std::shared_ptr<ResultSet> resultSet = ServiceInfoRdbAdapter::GetInstance().Get(
        SELECT_SERVICE_INFO_PROFILE_TABLE_WHERE_DEVID_USERID_TOKENID_SERVICEID, condition);
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
    int32_t ret = resultSet->GoToNextRow();
    if (ret != DP_SUCCESS) {
        HILOGE("get ServiceInfoProfileResult failed");
        resultSet->Close();
        return DP_NOT_FIND_DATA;
    }
    ConvertToServiceInfo(resultSet, serviceInfoProfile);
    resultSet->Close();
    HILOGI("end!");
    return DP_SUCCESS;
}

int32_t ServiceInfoProfileManager::GetServiceInfoProfileListByTokenId(const ServiceInfoUniqueKey& key,
    std::vector<ServiceInfoProfile>& serviceInfoProfiles)
{
    if (key.GetDeviceId().empty() || key.GetUserId() == DEFAULT_USER_ID || key.GetTokenId().empty()) {
        HILOGE("Invalid parameter");
        return DP_INVALID_PARAM;
    }
    std::vector<ValueObject> condition;
    condition.emplace_back(ValueObject(key.GetDeviceId()));
    condition.emplace_back(ValueObject(key.GetUserId()));
    condition.emplace_back(ValueObject(key.GetTokenId()));
    std::shared_ptr<ResultSet> resultSet = ServiceInfoRdbAdapter::GetInstance().Get(
        SELECT_SERVICE_INFO_PROFILE_TABLE_WHERE_DEVID_USERID_TOKENID, condition);
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
        ServiceInfoProfile serviceInfoProfile;
        ConvertToServiceInfo(resultSet, serviceInfoProfile);
        serviceInfoProfiles.emplace_back(serviceInfoProfile);
    }
    resultSet->Close();
    if (serviceInfoProfiles.empty()) {
        return DP_NOT_FIND_DATA;
    }
    HILOGI("end!");
    return DP_SUCCESS;
}

int32_t ServiceInfoProfileManager::GetAllServiceInfoProfileList(std::vector<ServiceInfoProfile>& serviceInfoProfiles)
{
    std::vector<ValueObject> condition;
    std::shared_ptr<ResultSet> resultSet = ServiceInfoRdbAdapter::GetInstance().Get(
        SELECT_SERVICE_INFO_PROFILE_ALL, condition);
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
        ServiceInfoProfile serviceInfoProfile;
        ConvertToServiceInfo(resultSet, serviceInfoProfile);
        serviceInfoProfiles.emplace_back(serviceInfoProfile);
    }
    resultSet->Close();
    if (serviceInfoProfiles.empty()) {
        return DP_NOT_FIND_DATA;
    }
    HILOGI("end!");
    return DP_SUCCESS;
}

int32_t ServiceInfoProfileManager::GetServiceInfoProfileListByBundleName(const ServiceInfoUniqueKey& key,
    std::vector<ServiceInfoProfile>& serviceInfoProfiles)
{
    if (key.GetDeviceId().empty() || key.GetUserId() == DEFAULT_USER_ID || key.GetBundleName().empty()) {
        HILOGE("Invalid parameter");
        return DP_INVALID_PARAM;
    }
    std::vector<ValueObject> condition;
    condition.emplace_back(ValueObject(key.GetDeviceId()));
    condition.emplace_back(ValueObject(key.GetUserId()));
    condition.emplace_back(ValueObject(key.GetBundleName()));
    std::shared_ptr<ResultSet> resultSet = ServiceInfoRdbAdapter::GetInstance().Get(
        SELECT_SERVICE_INFO_PROFILE_TABLE_WHERE_DEVID_USERID_BUNDLENAME, condition);
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
        ServiceInfoProfile serviceInfoProfile;
        ConvertToServiceInfo(resultSet, serviceInfoProfile);
        serviceInfoProfiles.emplace_back(serviceInfoProfile);
    }
    resultSet->Close();
    if (serviceInfoProfiles.empty()) {
        return DP_NOT_FIND_DATA;
    }
    HILOGI("end!");
    return DP_SUCCESS;
}

int32_t ServiceInfoProfileManager::ConvertToServiceInfo(std::shared_ptr<ResultSet> resultSet,
    ServiceInfoProfile& serviceInfo)
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
    serviceInfo.SetDeviceId(rowEntity.Get(DEVICE_ID));
    serviceInfo.SetUserId(rowEntity.Get(USERID));
    serviceInfo.SetNetworkId(rowEntity.Get(SRNETWORK_ID));
    serviceInfo.SetTokenId(rowEntity.Get(TOKENID));
    serviceInfo.SetServiceId(rowEntity.Get(SISERVICE_ID));
    serviceInfo.SetServiceType(rowEntity.Get(SERVICE_TYPE));
    serviceInfo.SetServiceName(rowEntity.Get(SERVICE_NAME));
    serviceInfo.SetServiceDisplayName(rowEntity.Get(SERVICE_DISPLAY_NAME));
    serviceInfo.SetCustomData(rowEntity.Get(CUSTOM_DATA));
    serviceInfo.SetCustomDataLen(rowEntity.Get(CUSTOM_DATA_LEN));
    serviceInfo.SetBundleName(rowEntity.Get(BUNDLE_NAME));
    serviceInfo.SetModuleName(rowEntity.Get(MODULE_NAME));
    serviceInfo.SetAbilityName(rowEntity.Get(ABILITY_NAME));
    serviceInfo.SetAuthBoxType(rowEntity.Get(AUTH_BOX_TYPE));
    serviceInfo.SetAuthType(rowEntity.Get(AUTH_TYPE));
    serviceInfo.SetPinExchangeType(rowEntity.Get(PIN_EXCHANGE_TYPE));
    serviceInfo.SetPinCode(rowEntity.Get(PINCODE));
    serviceInfo.SetDescription(rowEntity.Get(DESCRIPTION));
    serviceInfo.SetServiceDicoveryScope(rowEntity.Get(SERVICE_DISCOVERY_SCOPE));
    serviceInfo.SetExtraInfo(rowEntity.Get(EXTRAINFO));
    return DP_SUCCESS;
}

int32_t ServiceInfoProfileManager::ServiceInfoProfileToEntries(const ServiceInfoProfile& serviceInfo,
    ValuesBucket& values)
{
    values.PutString(DEVICE_ID, serviceInfo.GetDeviceId());
    values.PutInt(USERID, serviceInfo.GetUserId());
    values.PutString(SRNETWORK_ID, serviceInfo.GetNetworkId());
    values.PutString(TOKENID, serviceInfo.GetTokenId());
    values.PutLong(SISERVICE_ID, serviceInfo.GetServiceId());
    values.PutString(SERVICE_TYPE, serviceInfo.GetServiceType());
    values.PutString(SERVICE_NAME, serviceInfo.GetServiceName());
    values.PutString(SERVICE_DISPLAY_NAME, serviceInfo.GetServiceDisplayName());
    values.PutString(CUSTOM_DATA, serviceInfo.GetCustomData());
    values.PutInt(CUSTOM_DATA_LEN, serviceInfo.GetCustomDataLen());
    values.PutString(BUNDLE_NAME, serviceInfo.GetBundleName());
    values.PutString(MODULE_NAME, serviceInfo.GetModuleName());
    values.PutString(ABILITY_NAME, serviceInfo.GetAbilityName());
    values.PutInt(AUTH_BOX_TYPE, serviceInfo.GetAuthBoxType());
    values.PutInt(AUTH_TYPE, serviceInfo.GetAuthType());
    values.PutInt(PIN_EXCHANGE_TYPE, serviceInfo.GetPinExchangeType());
    values.PutString(PINCODE, serviceInfo.GetPinCode());
    values.PutString(DESCRIPTION, serviceInfo.GetDescription());
    values.PutString(SERVICE_DISCOVERY_SCOPE, serviceInfo.GetServiceDicoveryScope());
    values.PutString(EXTRAINFO, serviceInfo.GetExtraInfo());
    return DP_SUCCESS;
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
