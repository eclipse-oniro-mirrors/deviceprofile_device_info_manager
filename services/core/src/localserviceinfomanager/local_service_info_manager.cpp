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

#include "local_service_info_manager.h"

#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"
#include "dp_services_constants.h"
#include "local_service_info.h"
#include "local_service_info_rdb_adapter.h"

namespace OHOS {
namespace DistributedDeviceProfile {
IMPLEMENT_SINGLE_INSTANCE(LocalServiceInfoManager)

namespace {
const std::string TAG = "LocalServiceInfoManager";
}

int32_t LocalServiceInfoManager::Init()
{
    int32_t ret = LocalServiceInfoRdbAdapter::GetInstance().Init();
    if (ret != DP_SUCCESS) {
        HILOGE("LocalServiceInfoRdbAdapter Init failed");
        return DP_INIT_DB_FAILED;
    }
    CreateTable();
    CreateIndex();
    HILOGI("end!");
    return DP_SUCCESS;
}

int32_t LocalServiceInfoManager::UnInit()
{
    int32_t ret = LocalServiceInfoRdbAdapter::GetInstance().UnInit();
    if (ret != DP_SUCCESS) {
        HILOGE("LocalServiceInfoRdbAdapter UnInit failed");
        return DP_UNINIT_FAIL;
    }
    return DP_SUCCESS;
}

int32_t LocalServiceInfoManager::CreateTable()
{
    int32_t ret = LocalServiceInfoRdbAdapter::GetInstance().CreateTable(CREATE_LOCAL_SERVICE_INFO_TABLE_SQL);
    if (ret != DP_SUCCESS) {
        HILOGE("local_service_Info create failed");
        return DP_CREATE_TABLE_FAIL;
    }
    return DP_SUCCESS;
}

int32_t LocalServiceInfoManager::CreateIndex()
{
    int32_t ret = LocalServiceInfoRdbAdapter::GetInstance().CreateTable(
        CREATE_LOCAL_SERVICE_INFO_TABLE_UNIQUE_INDEX_SQL);
    if (ret != DP_SUCCESS) {
        HILOGE("local_service_Info unique index create failed");
        return DP_CREATE_UNIQUE_INDEX_FAIL;
    }
    return DP_SUCCESS;
}

int32_t LocalServiceInfoManager::PutLocalServiceInfo(const LocalServiceInfo& localServiceInfo)
{
    if (localServiceInfo.GetBundleName().empty() || localServiceInfo.GetPinExchangeType() == 0) {
        HILOGE("Invalid parameter");
        return DP_INVALID_PARAM;
    }
    ValuesBucket values;
    LocalServiceInfoToEntries(localServiceInfo, values);
    int64_t rowId = ROWID_INIT;
    int32_t ret = RET_INIT;
    std::string bundleName = localServiceInfo.GetBundleName();
    int32_t pinExchangeType = localServiceInfo.GetPinExchangeType();
    LocalServiceInfo oldBusInfo;
    int32_t getRet = GetLocalServiceInfoByBundleAndPinType(bundleName, pinExchangeType, oldBusInfo);
    if (getRet == DP_SUCCESS) {
        HILOGI("localserviceInfo already exit");
        return DP_LOCAL_SERVICE_INFO_EXISTS;
    }
    ret = LocalServiceInfoRdbAdapter::GetInstance().Put(rowId, LOCAL_SERVICE_INFO_TABLE, values);
    if (ret != DP_SUCCESS) {
        HILOGE("%{public}s insert failed", LOCAL_SERVICE_INFO_TABLE.c_str());
        return DP_PUT_LOCAL_SERVICE_INFO_FAIL;
    }
    HILOGI("end!");
    return DP_SUCCESS;
}

int32_t LocalServiceInfoManager::DeleteLocalServiceInfo(const std::string& bundleName, int32_t pinExchangeType)
{
    if (bundleName.empty() || pinExchangeType == 0) {
        HILOGE("Invalid parameter");
        return DP_INVALID_PARAM;
    }
    LocalServiceInfo oldBusInfo;
    int32_t getRet = GetLocalServiceInfoByBundleAndPinType(bundleName, pinExchangeType, oldBusInfo);
    if (getRet == DP_NOT_FIND_DATA) {
        HILOGI("LocalServiceInfo not exit, doesn't need delete");
        return DP_SUCCESS;
    }
    if (getRet != DP_SUCCESS) {
        HILOGE("GetLocalServiceInfo filed");
        return getRet;
    }
    int32_t deleteRows = DELETEROWS_INIT;
    int32_t ret = LocalServiceInfoRdbAdapter::GetInstance().Delete(deleteRows, LOCAL_SERVICE_INFO_TABLE,
        LOCAL_SERVICE_INFO_UNIQUE_INDEX_EQUAL_CONDITION,
        std::vector<ValueObject>{ValueObject(bundleName), ValueObject(pinExchangeType)});
    if (ret != DP_SUCCESS) {
        HILOGE("delete %{public}s data failed", LOCAL_SERVICE_INFO_TABLE.c_str());
        return DP_DELETE_LOCAL_SERVICE_INFO_FAIL;
    }
    HILOGI("end!");
    return DP_SUCCESS;
}

int32_t LocalServiceInfoManager::UpdateLocalServiceInfo(const LocalServiceInfo& localServiceInfo)
{
    if (localServiceInfo.GetBundleName().empty() || localServiceInfo.GetPinExchangeType() == 0) {
        HILOGE("Invalid parameter");
        return DP_INVALID_PARAM;
    }
    LocalServiceInfo serInfo;
    std::string bundleName = localServiceInfo.GetBundleName();
    int32_t pinExchangeType = localServiceInfo.GetPinExchangeType();
    int32_t getRet = GetLocalServiceInfoByBundleAndPinType(bundleName, pinExchangeType, serInfo);
    if (getRet == DP_NOT_FIND_DATA) {
        HILOGE("localserviceInfo not exit, can't update");
        return getRet;
    }
    if (getRet != DP_SUCCESS) {
        HILOGI("GetLocalServiceInfoByBundleAndPinType failed");
        return getRet;
    }
    ValuesBucket values;
    LocalServiceInfoToEntries(localServiceInfo, values);
    int32_t changeRowCnt = CHANGEROWCNT_INIT;
    int32_t ret = LocalServiceInfoRdbAdapter::GetInstance().Update(changeRowCnt, LOCAL_SERVICE_INFO_TABLE, values,
        LOCAL_SERVICE_INFO_UNIQUE_INDEX_EQUAL_CONDITION,
        std::vector<ValueObject>{ValueObject(bundleName), ValueObject(pinExchangeType)});
    if (ret != DP_SUCCESS) {
        HILOGE("Update %{public}s table failed", LOCAL_SERVICE_INFO_TABLE.c_str());
        return DP_UPDATE_LOCAL_SERVICE_INFO_FAIL;
    }
    HILOGI("end!");
    return DP_SUCCESS;
}

int32_t LocalServiceInfoManager::GetLocalServiceInfoByBundleAndPinType(const std::string& bundleName,
    int32_t pinExchangeType, LocalServiceInfo& localServiceInfo)
{
    if (bundleName.empty() || pinExchangeType == 0) {
        HILOGE("Invalid parameter");
        return DP_INVALID_PARAM;
    }
    std::vector<ValueObject> condition;
    condition.emplace_back(ValueObject(bundleName));
    condition.emplace_back(ValueObject(pinExchangeType));
    std::shared_ptr<ResultSet> resultSet = LocalServiceInfoRdbAdapter::GetInstance().Get(
        SELECT_LOCAL_SERVICE_INFO_WHERE_BUNDLENAME_PINEXCHANGETYPE, condition);
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
        HILOGE("get localserviceInfo failed");
        resultSet->Close();
        return DP_NOT_FIND_DATA;
    }
    ConvertToLocalServiceInfo(resultSet, localServiceInfo);
    resultSet->Close();
    HILOGI("end!");
    return DP_SUCCESS;
}

int32_t LocalServiceInfoManager::ConvertToLocalServiceInfo(std::shared_ptr<ResultSet> resultSet,
    LocalServiceInfo& LocalServiceInfo)
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
    LocalServiceInfo.SetBundleName(rowEntity.Get(BUNDLE_NAME));
    LocalServiceInfo.SetAuthBoxType(rowEntity.Get(AUTH_BOX_TYPE));
    LocalServiceInfo.SetAuthType(rowEntity.Get(AUTH_TYPE));
    LocalServiceInfo.SetPinExchangeType(rowEntity.Get(PIN_EXCHANGE_TYPE));
    LocalServiceInfo.SetPinCode(rowEntity.Get(PINCODE));
    LocalServiceInfo.SetDescription(rowEntity.Get(DESCRIPTION));
    LocalServiceInfo.SetExtraInfo(rowEntity.Get(EXTRAINFO));
    return DP_SUCCESS;
}

int32_t LocalServiceInfoManager::LocalServiceInfoToEntries(const LocalServiceInfo& LocalServiceInfo,
    ValuesBucket& values)
{
    values.PutString(BUNDLE_NAME, LocalServiceInfo.GetBundleName());
    values.PutInt(AUTH_BOX_TYPE, LocalServiceInfo.GetAuthBoxType());
    values.PutInt(AUTH_TYPE, LocalServiceInfo.GetAuthType());
    values.PutInt(PIN_EXCHANGE_TYPE, LocalServiceInfo.GetPinExchangeType());
    values.PutString(PINCODE, LocalServiceInfo.GetPinCode());
    values.PutString(DESCRIPTION, LocalServiceInfo.GetDescription());
    values.PutString(EXTRAINFO, LocalServiceInfo.GetExtraInfo());
    return DP_SUCCESS;
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
