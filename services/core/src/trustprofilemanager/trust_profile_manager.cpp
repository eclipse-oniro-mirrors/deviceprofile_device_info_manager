/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "trust_profile_manager.h"
#include "subscribe_profile_manager.h"
#include "distributed_device_profile_log.h"
#include "rdb_adapter.h"
#include "profile_utils.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_errors.h"
#include "accesser.h"
#include "accessee.h"


namespace OHOS {
namespace DistributedDeviceProfile {
IMPLEMENT_SINGLE_INSTANCE(TrustProfileManager);
namespace {
    const std::string TAG = "TrustProfileManager";
}

int32_t TrustProfileManager::Init()
{
    {
        std::lock_guard<std::mutex> lock(rdbMutex_);
        rdbStore_ = std::make_shared<RdbAdapter>();
        if (rdbStore_ == nullptr) {
            HILOGE("Init::rdbStore_ create failed");
            return DP_INIT_DB_FAILED;
        }
        int32_t ret = rdbStore_->Init();
        if (ret != DP_SUCCESS) {
            HILOGE("Init::rdbStore_ Init failed");
            return DP_INIT_DB_FAILED;
        }
    }
    this->CreateTable();
    this->CreateUniqueIndex();
    return DP_SUCCESS;
}

int32_t TrustProfileManager::UnInit()
{
    {
        std::lock_guard<std::mutex> lock(rdbMutex_);
        if (rdbStore_ == nullptr) {
            HILOGE("UnInit::rdbStore_ is nullptr");
            return DP_GET_RDBSTORE_FAIL;
        }
        int32_t ret = rdbStore_->UnInit();
        if (ret != DP_SUCCESS) {
            HILOGE("UnInit::rdbStore_ Uninit failed");
            return DP_UNINIT_FAIL;
        }
        rdbStore_ = nullptr;
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::PutTrustDeviceProfile(const TrustDeviceProfile& profile)
{
    ValuesBucket values;
    ProfileUtils::TrustDeviceProfileToEntries(profile, values);

    int64_t id = INIT_VALUE_64;
    int32_t ret = INIT_VALUE_32;
    {
        std::lock_guard<std::mutex> lock(rdbMutex_);
        if (rdbStore_ == nullptr) {
            HILOGE("PutTrustDeviceProfile::rdbStore_ is nullptr");
            return DP_GET_RDBSTORE_FAIL;
        }
        ret = rdbStore_->Put(id, TRUST_DEVICE_TABLE, values);
        if (ret != DP_SUCCESS) {
            HILOGE("PutTrustDeviceProfile::trust_device_table insert failed");
            return DP_PUT_TRUST_DEVICE_PROFILE_FAIL;
        }
    }
    ret = SubscribeProfileManager::GetInstance().NotifyTrustDeviceProfileAdd(profile);
    if (ret != DP_SUCCESS) {
        HILOGE("PutTrustDeviceProfile::NotifyTrustDeviceProfileAdd failed");
        return DP_NOTIFY_TRUST_DEVICE_FAIL;
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::PutAccessControlProfile(const AccessControlProfile& profile)
{
    AccessControlProfile accessControlProfile(profile);
    this->SetAclId(accessControlProfile);
    this->PutAccesserProfile(accessControlProfile);
    this->PutAccesseeProfile(accessControlProfile);

    ValuesBucket values;
    ProfileUtils::AccessControlProfileToEntries(accessControlProfile, values);
    int64_t rowId = INIT_VALUE_64;
    int32_t ret = INIT_VALUE_32;
    {
        std::lock_guard<std::mutex> lock(rdbMutex_);
        ret = rdbStore_ ->Put(rowId, ACCESS_CONTROL_TABLE, values);
        values.Clear();
        if (ret != DP_SUCCESS) {
            HILOGE("PutAccessControlProfile::access_control_table insert failed");
            return DP_PUT_ACL_PROFILE_FAIL;
        }
    }
    TrustDeviceProfile trustProfile;
    this->AccessControlProfileToTrustDeviceProfile(profile, trustProfile);
    std::string trustDeviceId = accessControlProfile.GetTrustDeviceId();
    std::shared_ptr<ResultSet> resultSet =
        GetResultSet(SELECT_TRUST_DEVICE_TABLE_WHERE_DEVICEID,
        std::vector<ValueObject>{ ValueObject(trustDeviceId) });
    if (resultSet == nullptr) {
        HILOGE("PutAccessControlProfile::get resultSet failed");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = INIT_VALUE_32;
    resultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        this->PutTrustDeviceProfile(trustProfile);
        return DP_SUCCESS;
    }
    int32_t trustDeviceStatus = INIT_VALUE_32;
    ret = this->GetResultStatus(trustDeviceId, trustDeviceStatus);
    if (ret != DP_SUCCESS) {
        HILOGE("UpdateAccessControlProfile::GetResultStatus failed");
        return DP_GET_RESULTSET_FAIL;
    }
    trustProfile.SetStatus(trustDeviceStatus);
    ret = this->UpdateTrustDeviceProfile(trustProfile);
    resultSet->Close();
    if (ret != DP_SUCCESS) {
        HILOGE("PutAccessControlProfile::UpdateTrustDeviceProfile failed");
        return DP_UPDATE_TRUST_DEVICE_PROFILE_FAIL;
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::UpdateTrustDeviceProfile(const TrustDeviceProfile& profile)
{
    if (rdbStore_ == nullptr) {
        HILOGE("UpdateTrustDeviceProfile::rdbStore_ is nullptr");
        return DP_GET_RDBSTORE_FAIL;
    }
    std::string deviceId = profile.GetDeviceId();
    std::shared_ptr<ResultSet> resultSet =
        GetResultSet(SELECT_TRUST_DEVICE_TABLE_WHERE_DEVICEID,
        std::vector<ValueObject>{ ValueObject(deviceId) });
    if (resultSet == nullptr) {
        HILOGE("UpdateTrustDeviceProfile::deviceId not find");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = INIT_VALUE_32;
    resultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        HILOGE("UpdateTrustDeviceProfile::deviceId not find");
        return DP_NOT_FIND_DATA;
    }
    int32_t ret = resultSet->GoToFirstRow();
    if (ret != DP_SUCCESS) {
        HILOGE("UpdateTrustDeviceProfile::deviceId not find");
        return DP_NOT_FIND_DATA;
    }
    TrustDeviceProfile oldProfile;
    this->TrustResultSetToTrustDeviceProfile(resultSet, oldProfile);
    ValuesBucket values;
    ProfileUtils::TrustDeviceProfileToEntries(profile, values);
    int32_t rowCnt = INIT_VALUE_32;
    {
        std::lock_guard<std::mutex> lock(rdbMutex_);
        ret = rdbStore_->Update(rowCnt, TRUST_DEVICE_TABLE, values, "deviceId = ?",
            std::vector<ValueObject>{ ValueObject(profile.GetDeviceId()) });
        if (ret != DP_SUCCESS) {
            HILOGE("UpdateTrustDeviceProfile::StatusUpdateNotify failed");
            return DP_UPDATE_TRUST_DEVICE_PROFILE_FAIL;
        }
    }
    this->UpdateTrustDeviceProfileNotify(oldProfile, profile);
    resultSet->Close();
    return DP_SUCCESS;
}

int32_t TrustProfileManager::UpdateAccessControlProfile(const AccessControlProfile& profile)
{
    if (rdbStore_ == nullptr) {
        HILOGE("UpdateAccessControlProfile::rdbStore_ is nullptr");
        return DP_GET_RDBSTORE_FAIL;
    }
    int32_t ret = this->UpdateAclCheck(profile);
    if (ret != DP_SUCCESS) {
        HILOGE("UpdateAccessControlProfile::UpdateAclCheck faild");
        return ret;
    }
    this->UpdateAccesserProfile(profile.GetAccesserId(), profile);
    this->UpdateAccesseeProfile(profile.GetAccesseeId(), profile);
    ValuesBucket values;
    ProfileUtils::AccessControlProfileToEntries(profile, values);
    int32_t rowCnt = INIT_VALUE_32;
    {
        std::lock_guard<std::mutex> lock(rdbMutex_);
        ret = rdbStore_->Update(rowCnt, ACCESS_CONTROL_TABLE, values, "accessControlId = ?",
            std::vector<ValueObject>{ ValueObject(profile.GetAccessControlId()) });
        if (ret != DP_SUCCESS) {
            HILOGE("UpdateAccessControlProfile::update access_control_table failed");
            return DP_UPDATE_ACL_PROFILE_FAIL;
        }
    }
    int32_t trustDeviceStatus = 0;
    ret = this->GetResultStatus(profile.GetTrustDeviceId(), trustDeviceStatus);
    if (ret != DP_SUCCESS) {
        HILOGE("UpdateAccessControlProfile::GetResultStatus failed");
        return DP_GET_RESULTSET_FAIL;
    }
    TrustDeviceProfile trustProfile;
    this->AccessControlProfileToTrustDeviceProfile(profile, trustProfile);
    trustProfile.SetStatus(trustDeviceStatus);
    ret = this->UpdateTrustDeviceProfile(trustProfile);
    if (ret != DP_SUCCESS) {
        HILOGE("UpdateAccessControlProfile::UpdateTrustDeviceProfile failed");
        return DP_UPDATE_TRUST_DEVICE_PROFILE_FAIL;
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetTrustDeviceProfile(const std::string& deviceId, TrustDeviceProfile& profile)
{
    if (rdbStore_ == nullptr) {
        HILOGE("GetTrustDeviceProfile::rdbStore_ is nullptr");
        return DP_GET_RDBSTORE_FAIL;
    }
    std::shared_ptr<ResultSet> resultSet = GetResultSet(SELECT_TRUST_DEVICE_TABLE_WHERE_DEVICEID,
        std::vector<ValueObject>{ ValueObject(deviceId) });
    if (resultSet == nullptr) {
        HILOGE("GetTrustDeviceProfile::get result failed");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = INIT_VALUE_32;
    resultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        HILOGE("GetTrustDeviceProfile::accessControlId not find");
        return DP_NOT_FIND_DATA;
    }
    int32_t ret = resultSet->GoToFirstRow();
    if (ret != DP_SUCCESS) {
        HILOGE("GetTrustDeviceProfile::not find trust device data");
        return DP_NOT_FIND_DATA;
    }
    this->TrustResultSetToTrustDeviceProfile(resultSet, profile);
    resultSet->Close();
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetAllTrustDeviceProfile(std::vector<TrustDeviceProfile>& profile)
{
    if (rdbStore_ == nullptr) {
        HILOGE("GetAllTrustDeviceProfile::rdbStore_ is nullptr");
        return DP_GET_RDBSTORE_FAIL;
    }
    std::shared_ptr<ResultSet> resultSet =
        GetResultSet(SELECT_TRUST_DEVICE_TABLE, std::vector<ValueObject> {});
    if (resultSet == nullptr) {
        HILOGE("GetAllTrustDeviceProfile::get result failed");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = INIT_VALUE_32;
    resultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        HILOGE("GetAllTrustDeviceProfile::accessControlId not find");
        return DP_NOT_FIND_DATA;
    }
    while (resultSet->GoToNextRow() == DP_SUCCESS) {
        TrustDeviceProfile trustProfile;
        this->TrustResultSetToTrustDeviceProfile(resultSet, trustProfile);
        profile.push_back(trustProfile);
    }
    resultSet->Close();
    if (profile.empty()) {
        return DP_NOT_FIND_DATA;
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetAccessControlProfile(int32_t userId, const std::string& bundleName,
    int32_t bindType, int32_t status, std::vector<AccessControlProfile>& profile)
{
    if (rdbStore_ == nullptr) {
        HILOGE("GetAccessControlProfile::rdbStore_ is nullptr");
        return DP_GET_RDBSTORE_FAIL;
    }
    std::shared_ptr<ResultSet> resultSet =
        GetResultSet(SELECT_ACCESS_CONTROL_TABLE_WHERE_BINDTYPE_AND_STATUS,
        std::vector<ValueObject>{ ValueObject(bindType), ValueObject(status) });
    if (resultSet == nullptr) {
        HILOGE("GetAccessControlProfile::resultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = INIT_VALUE_32;
    resultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        HILOGE("GetAccessControlProfile::bindType not find");
        return DP_NOT_FIND_DATA;
    }
    int32_t ret = this->GetAccessControlProfileOnUserIdAndBundleName(resultSet, userId, bundleName, profile);
    if (ret != DP_SUCCESS) {
        HILOGE("GetAccessControlProfile::GetAccessControlProfileOnUserIdAndBundleName faild");
        return DP_NOT_FIND_DATA;
    }
    resultSet->Close();
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetAccessControlProfile(int32_t userId, const std::string& bundleName,
    const std::string& trustDeviceId, int32_t status, std::vector<AccessControlProfile>& profile)
{
    if (rdbStore_ == nullptr) {
        HILOGE("GetAccessControlProfile::rdbStore_ is nullptr");
        return DP_GET_RDBSTORE_FAIL;
    }
    std::shared_ptr<ResultSet> resultSet =
        GetResultSet(SELECT_ACCESS_CONTROL_TABLE_WHERE_TRUSTDEVICEID_AND_STATUS,
        std::vector<ValueObject>{ ValueObject(trustDeviceId), ValueObject(status) });
    if (resultSet == nullptr) {
        HILOGE("GetAccessControlProfile::bindType not find");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = INIT_VALUE_32;
    resultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        HILOGE("GetAccessControlProfile::accessControlId not find");
        return DP_NOT_FIND_DATA;
    }
    int32_t ret = this->GetAccessControlProfileOnUserIdAndBundleName(resultSet, userId, bundleName, profile);
    if (ret != DP_SUCCESS) {
        HILOGE("GetAccessControlProfile::GetAccessControlProfileOnUserIdAndBundleName faild");
        return ret;
    }
    resultSet->Close();
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetAccessControlProfileOnTokenAndDevice(int32_t accesserTokenId,
    const std::string& accesseeDeviceId, std::vector<AccessControlProfile>& profile)
{
    if (rdbStore_ == nullptr) {
        HILOGE("GetAccessControlProfile::rdbStore_ is nullptr");
        return DP_GET_RDBSTORE_FAIL;
    }
    std::shared_ptr<ResultSet> resultSet =
        GetResultSet(SELECT_ACCESS_CONTROL_TABLE, std::vector<ValueObject> {});
    if (resultSet == nullptr) {
        HILOGE("GetAccessControlProfile::access_control_table no data");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = INIT_VALUE_32;
    resultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        HILOGE("GetAccessControlProfile::access_control_table no data");
        return DP_NOT_FIND_DATA;
    }
    int32_t ret = this->GetAccessControlProfileOnTokenIdAndDeviceId(
        resultSet, accesserTokenId, accesseeDeviceId, profile);
    if (ret != DP_SUCCESS) {
        HILOGE("GetAccessControlProfile::GetAccessControlProfileOnUserIdAndAccountId faild");
        return ret;
    }
    resultSet->Close();
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetAccessControlProfile(int32_t userId,
    const std::string& accountId, std::vector<AccessControlProfile>& profile)
{
    if (rdbStore_ == nullptr) {
        HILOGE("GetAccessControlProfile::rdbStore_ is nullptr");
        return DP_GET_RDBSTORE_FAIL;
    }
    std::shared_ptr<ResultSet> resultSet =
        GetResultSet(SELECT_ACCESS_CONTROL_TABLE, std::vector<ValueObject> {});
    if (resultSet == nullptr) {
        HILOGE("GetAccessControlProfile::access_control_table no data");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = INIT_VALUE_32;
    resultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        HILOGE("GetAccessControlProfile::access_control_table no data");
        return DP_NOT_FIND_DATA;
    }
    int32_t ret = this->GetAccessControlProfileOnUserIdAndAccountId(
        resultSet, userId, accountId, profile);
    if (ret != DP_SUCCESS) {
        HILOGE("GetAccessControlProfile::GetAccessControlProfileOnUserIdAndAccountId faild");
        return ret;
    }
    resultSet->Close();
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetAllAccessControlProfile(std::vector<AccessControlProfile>& profile)
{
    if (rdbStore_ == nullptr) {
        HILOGE("GetAllAccessControlProfile::rdbStore_ is nullptr");
        return DP_GET_RDBSTORE_FAIL;
    }
    std::shared_ptr<ResultSet> resultSet =
        GetResultSet(SELECT_ACCESS_CONTROL_TABLE, std::vector<ValueObject> {});
    if (resultSet == nullptr) {
        HILOGE("GetAllAccessControlProfile::bindType not find");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = INIT_VALUE_32;
    resultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        HILOGE("GetAllAccessControlProfile::no data");
        return DP_NOT_FIND_DATA;
    }
    int32_t ret = INIT_VALUE_32;
    while (resultSet->GoToNextRow() == DP_SUCCESS) {
        int32_t columnIndex = INIT_VALUE_32;
        int64_t accesserId = INIT_VALUE_64;
        ret = resultSet->GetColumnIndex("accesserId", columnIndex);
        ret = resultSet->GetLong(columnIndex, accesserId);
        int64_t accesseeId = INIT_VALUE_64;
        ret = resultSet->GetColumnIndex("accesseeId", columnIndex);
        ret = resultSet->GetLong(columnIndex, accesseeId);
        ret = this->GetAccesserAndAccesseeAndAccessControl(
            resultSet, accesserId, accesseeId, profile);
        if (ret != DP_SUCCESS) {
            HILOGE("GetAllAccessControlProfile::faild");
            return ret;
        }
    }
    resultSet->Close();
    if (profile.empty()) {
        return DP_NOT_FIND_DATA;
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetAccessControlProfile(const std::string& bundleName,
    int32_t bindType, int32_t status, std::vector<AccessControlProfile>& profile)
{
    if (rdbStore_ == nullptr) {
        HILOGE("GetAccessControlProfile::rdbStore_ is nullptr");
        return DP_GET_RDBSTORE_FAIL;
    }
    std::shared_ptr<ResultSet> resultSet =
        GetResultSet(SELECT_ACCESS_CONTROL_TABLE_WHERE_BINDTYPE_AND_STATUS,
        std::vector<ValueObject>{ ValueObject(bindType), ValueObject(status) });
    if (resultSet == nullptr) {
        HILOGE("GetAccessControlProfile::resultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = INIT_VALUE_32;
    resultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        HILOGE("GetAccessControlProfile::bindType not find");
        return DP_NOT_FIND_DATA;
    }
    int32_t ret = this->GetAccessControlProfileOnBundleName(
        resultSet, bundleName, profile);
    if (ret != DP_SUCCESS) {
        HILOGE("GetAccessControlProfile::GetAccessControlProfileOnBundleName faild");
        return ret;
    }
    resultSet->Close();
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetAccessControlProfile(const std::string& bundleName,
    const std::string& trustDeviceId, int32_t status, std::vector<AccessControlProfile>& profile)
{
    if (rdbStore_ == nullptr) {
        HILOGE("GetAccessControlProfile::rdbStore_ is nullptr");
        return DP_GET_RDBSTORE_FAIL;
    }
    std::shared_ptr<ResultSet> resultSet =
        GetResultSet(SELECT_ACCESS_CONTROL_TABLE_WHERE_TRUSTDEVICEID_AND_STATUS,
        std::vector<ValueObject>{ ValueObject(trustDeviceId), ValueObject(status) });
    if (resultSet == nullptr) {
        HILOGE("GetAccessControlProfile::resultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = INIT_VALUE_32;
    resultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        HILOGE("GetAccessControlProfile::bindType not find");
        return DP_NOT_FIND_DATA;
    }
    int32_t ret = this->GetAccessControlProfileOnBundleName(resultSet, bundleName, profile);
    if (ret != DP_SUCCESS) {
        HILOGE("GetAccessControlProfile::GetAccessControlProfileOnBundleName faild");
        return ret;
    }
    resultSet->Close();
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetAccessControlProfile(std::map<std::string, std::string> params,
    std::vector<AccessControlProfile>& profile)
{
    if (params.find("userId") != params.end() && params.find("bundleName") != params.end()
        && params.find("bindType") != params.end() && params.find("status") != params.end()) {
        if (this->GetAclOnUserAndBundleAndBindAndStauts(params, profile) != DP_SUCCESS) {
            HILOGE("GetAccessControlProfile::params not find");
            return DP_GET_ACL_PROFILE_FAIL;
        }
        return DP_SUCCESS;
    }
    if (params.find("userId") != params.end() && params.find("bundleName") != params.end()
        && params.find("trustDeviceId") != params.end() && params.find("status") != params.end()) {
        if (this->GetAclOnUserAndBundleAndDeviceIdAndStauts(params, profile) != DP_SUCCESS) {
            HILOGE("GetAccessControlProfile::params not find");
            return DP_GET_ACL_PROFILE_FAIL;
        }
        return DP_SUCCESS;
    }
    if (params.find("bundleName") != params.end() && params.find("trustDeviceId") != params.end()
        && params.find("status") != params.end()) {
        if (this->GetAclOnBundleAndDeviceIdAndStauts(params, profile) != DP_SUCCESS) {
            HILOGE("GetAccessControlProfile::params not find");
            return DP_GET_ACL_PROFILE_FAIL;
        }
        return DP_SUCCESS;
    }
    if (params.find("bundleName") != params.end() && params.find("bindType") != params.end()
        && params.find("status") != params.end()) {
        if (this->GetAclOnBundleAndBindAndStauts(params, profile) != DP_SUCCESS) {
            HILOGE("GetAccessControlProfile::params not find");
            return DP_GET_ACL_PROFILE_FAIL;
        }
        return DP_SUCCESS;
    }
    if (params.find("userId") != params.end() && params.find("accountId") != params.end()) {
        if (this->GetAclOnUserAndAccount(params, profile) != DP_SUCCESS) {
            HILOGE("GetAccessControlProfile::params not find");
            return DP_GET_ACL_PROFILE_FAIL;
        }
        return DP_SUCCESS;
    }
    if (params.find("accesserTokenId") != params.end() && params.find("accesseeDeviceId") != params.end()) {
        if (this->GetAclOnTokenIdAndDeviceId(params, profile) != DP_SUCCESS) {
            HILOGE("GetAccessControlProfile::params not find");
            return DP_GET_ACL_PROFILE_FAIL;
        }
        return DP_SUCCESS;
    }
    HILOGE("params is error");
    return DP_GET_ACL_PROFILE_FAIL;
}

int32_t TrustProfileManager::DeleteTrustDeviceProfile(const std::string& deviceId)
{
    if (rdbStore_ == nullptr) {
        HILOGE("DeleteTrustDeviceProfile::rdbStore_ is nullptr");
        return DP_GET_RDBSTORE_FAIL;
    }
    std::shared_ptr<ResultSet> resultSet =
        GetResultSet(SELECT_TRUST_DEVICE_TABLE_WHERE_DEVICEID,
        std::vector<ValueObject>{ ValueObject(deviceId) });
    if (resultSet == nullptr) {
        HILOGE("DeleteTrustDeviceProfile::get result failed");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = INIT_VALUE_32;
    resultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        HILOGE("DeleteTrustDeviceProfile::no data");
        return DP_NOT_FIND_DATA;
    }
    int32_t ret = resultSet->GoToFirstRow();
    if (ret != DP_SUCCESS) {
        HILOGE("DeleteTrustDeviceProfile::deviceId not find");
        return DP_NOT_FIND_DATA;
    }
    TrustDeviceProfile profile;
    this->TrustResultSetToTrustDeviceProfile(resultSet, profile);

    int32_t deleteRows = INIT_VALUE_32;
    {
        std::lock_guard<std::mutex> lock(rdbMutex_);
        ret = rdbStore_->Delete(deleteRows, TRUST_DEVICE_TABLE, "deviceId = ?",
            std::vector<ValueObject>{ ValueObject(deviceId) });
        if (ret != DP_SUCCESS) {
            HILOGE("DeleteTrustDeviceProfile::delete trust_device_table data failed");
            return DP_DELETE_TRUST_DEVICE_PROFILE_FAIL;
        }
    }
    ret = SubscribeProfileManager::GetInstance().NotifyTrustDeviceProfileDelete(profile);
    if (ret != DP_SUCCESS) {
        HILOGE("DeleteTrustDeviceProfile::ProfileDelete failed");
        return DP_NOTIFY_TRUST_DEVICE_FAIL;
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::DeleteAccessControlProfile(int64_t accessControlId)
{
    if (rdbStore_ == nullptr) {
        HILOGE("DeleteAccessControlProfile::rdbStore_ is nullptr");
        return DP_GET_RDBSTORE_FAIL;
    }
    std::shared_ptr<ResultSet> resultSet =
        GetResultSet(SELECT_ACCESS_CONTROL_TABLE_WHERE_ACCESSCONTROLID,
        std::vector<ValueObject>{ ValueObject(accessControlId) });
    if (resultSet == nullptr) {
        HILOGE("DeleteAccessControlProfile::get result failed");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = INIT_VALUE_32;
    resultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        HILOGE("DeleteAccessControlProfile::no data");
        return DP_NOT_FIND_DATA;
    }
    int32_t ret = this->DeleteAccessControlProfileCheck(resultSet);
    if (ret != DP_SUCCESS) {
        HILOGE("DeleteAccessControlProfile::DeleteAccessControlProfileCheck failed");
        return ret;
    }
    resultSet->Close();
    return DP_SUCCESS;
}

int32_t TrustProfileManager::CreateTable()
{
    std::lock_guard<std::mutex> lock(rdbMutex_);
    int32_t ret = rdbStore_->CreateTable(CREATE_TURST_DEVICE_TABLE_SQL);
    if (ret != DP_SUCCESS) {
        HILOGE("CreateTable::trust_device_table create failed");
        return DP_CREATE_TABLE_FAIL;
    }
    ret = rdbStore_->CreateTable(CREATE_ACCESS_CONTROL_TABLE_SQL);
    if (ret != DP_SUCCESS) {
        HILOGE("CreateTable::access_control_table create failed");
        return DP_CREATE_TABLE_FAIL;
    }
    ret = rdbStore_->CreateTable(CREATE_ACCESSER_TABLE_SQL);
    if (ret != DP_SUCCESS) {
        HILOGE("CreateTable::accesser_table create failed");
        return DP_CREATE_TABLE_FAIL;
    }
    ret = rdbStore_->CreateTable(CREATE_ACCESSEE_TABLE_SQL);
    if (ret != DP_SUCCESS) {
        HILOGE("CreateTable::accessee_table create failed");
        return DP_CREATE_TABLE_FAIL;
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::CreateUniqueIndex()
{
    std::lock_guard<std::mutex> lock(rdbMutex_);
    int32_t ret = rdbStore_->CreateTable(CREATE_TURST_DEVICE_TABLE_UNIQUE_INDEX_SQL);
    if (ret != DP_SUCCESS) {
        HILOGE("CreateUniqueIndex::trust_device_table unique index create failed");
        return DP_CREATE_UNIQUE_INDEX_FAIL;
    }
    ret = rdbStore_->CreateTable(CREATE_ACCESS_CONTROL_TABLE_UNIQUE_INDEX_SQL);
    if (ret != DP_SUCCESS) {
        HILOGE("CreateUniqueIndex::access_control_table unique index create failed");
        return DP_CREATE_UNIQUE_INDEX_FAIL;
    }
    ret = rdbStore_->CreateTable(CREATE_ACCESSER_TABLE_UNIQUE_INDEX_SQL);
    if (ret != DP_SUCCESS) {
        HILOGE("CreateUniqueIndex::accesser_table unique index create failed");
        return DP_CREATE_UNIQUE_INDEX_FAIL;
    }
    ret = rdbStore_->CreateTable(CREATE_ACCESSEE_TABLE_UNIQUE_INDEX_SQL);
    if (ret != DP_SUCCESS) {
        HILOGE("CreateUniqueIndex::accessee_table unique index create failed");
        return DP_CREATE_UNIQUE_INDEX_FAIL;
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::AccessControlProfileToTrustDeviceProfile(
    const AccessControlProfile& accessControlProfile, TrustDeviceProfile& trustDeviceProfile)
{
    trustDeviceProfile.SetDeviceId(accessControlProfile.GetTrustDeviceId());
    trustDeviceProfile.SetDeviceIdType(accessControlProfile.GetDeviceIdType());
    trustDeviceProfile.SetDeviceIdHash(accessControlProfile.GetDeviceIdHash());
    trustDeviceProfile.SetStatus(accessControlProfile.GetStatus());
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetAccessControlProfileOnUserIdAndBundleName(std::shared_ptr<ResultSet> resultSet,
    int32_t userId, const std::string& bundleName, std::vector<AccessControlProfile>& profile)
{
    while (resultSet->GoToNextRow() == DP_SUCCESS) {
        int32_t  columnIndex = INIT_VALUE_32;
        int64_t accesserId = INIT_VALUE_64;
        int32_t ret = resultSet->GetColumnIndex("accesserId", columnIndex);
        ret = resultSet->GetLong(columnIndex, accesserId);
        int64_t accesseeId = INIT_VALUE_64;
        ret = resultSet->GetColumnIndex("accesseeId", columnIndex);
        ret = resultSet->GetLong(columnIndex, accesseeId);
        int32_t bindType = INIT_VALUE_32;
        ret = resultSet->GetColumnIndex("bindType", columnIndex);
        ret = resultSet->GetInt(columnIndex, bindType);
        int32_t bindLevel = INIT_VALUE_32;
        ret = resultSet->GetColumnIndex("bindLevel", columnIndex);
        ret = resultSet->GetInt(columnIndex, bindLevel);
        if (bindType == static_cast<int32_t>(BindType::SAME_ACCOUNT) &&
            bindLevel == static_cast<int32_t>(BindLevel::DEVICE)) {
            ret = this->GetAclVectorOnUserId(resultSet, accesserId,
                accesseeId, userId, profile);
            if (ret != DP_SUCCESS) {
                HILOGE("GetAccessControlProfileOnUserIdAndBundleName::GetAclVectorOnUserId failed");
                return ret;
            }
        } else {
            ret = this->GetAclVectorOnUserIdAndBundleName(resultSet, accesserId,
                accesseeId, userId, bundleName, profile);
            if (ret != DP_SUCCESS) {
                HILOGE("GetAccessControlProfileOnUserIdAndBundleName::GetAclVectorOnUserId failed");
                return ret;
            }
        }
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetAccessControlProfileOnUserIdAndAccountId(std::shared_ptr<ResultSet> resultSet,
    int32_t userId, const std::string& accountId, std::vector<AccessControlProfile>& profile)
{
    while (resultSet->GoToNextRow() == DP_SUCCESS) {
        int32_t columnIndex = INIT_VALUE_32;
        int64_t accesserId = INIT_VALUE_64;
        int32_t ret = resultSet->GetColumnIndex("accesserId", columnIndex);
        ret = resultSet->GetLong(columnIndex, accesserId);
        int64_t accesseeId = INIT_VALUE_64;
        ret = resultSet->GetColumnIndex("accesseeId", columnIndex);
        ret = resultSet->GetLong(columnIndex, accesseeId);

        std::shared_ptr<ResultSet> accesserResultSet =
            GetResultSet(SELECT_ACCESSER_TABLE_WHERE_ACCESSERID_AND_ACCESSERUSERID_ACCESSERACCOUNTID,
            std::vector<ValueObject>{ ValueObject(accesserId), ValueObject(userId), ValueObject(accountId) });
        if (accesserResultSet == nullptr) {
            HILOGE("GetAccessControlProfileOnUserIdAndAccountId::get accesserResultSet failed");
            return DP_GET_RESULTSET_FAIL;
        }
        int32_t rowCount = INIT_VALUE_32;
        accesserResultSet->GetRowCount(rowCount);
        if (rowCount != 0) {
            std::shared_ptr<ResultSet> accesseeResultSet =
                GetResultSet(SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID,
                std::vector<ValueObject>{ ValueObject(accesseeId) });
            this->GetVectorAccessControlProfile(resultSet, accesserResultSet, accesseeResultSet, profile);
            accesserResultSet->Close();
            accesseeResultSet->Close();
            continue;
        }
        accesserResultSet->Close();

        std::shared_ptr<ResultSet> accesseeResultSet =
            GetResultSet(SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID_AND_ACCESSEEUSEEID_ACCESSEEACCOUNTID,
            std::vector<ValueObject>{ ValueObject(accesseeId), ValueObject(userId), ValueObject(accountId) });
        if (accesseeResultSet == nullptr) {
            HILOGE("GetAccessControlProfileOnUserIdAndAccountId::get accesseeResultSet failed");
            return DP_GET_RESULTSET_FAIL;
        }
        accesseeResultSet->GetRowCount(rowCount);
        if (rowCount != 0) {
            accesserResultSet = GetResultSet(SELECT_ACCESSER_TABLE_WHERE_ACCESSERID,
                std::vector<ValueObject>{ ValueObject(accesserId) });
            this->GetVectorAccessControlProfile(resultSet, accesserResultSet, accesseeResultSet, profile);
            accesseeResultSet->Close();
            accesserResultSet->Close();
        }
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetAccessControlProfileOnTokenIdAndDeviceId(std::shared_ptr<ResultSet> resultSet,
    int32_t accesserTokenId, const std::string& accesseeDeviceId, std::vector<AccessControlProfile>& profile)
{
    while (resultSet->GoToNextRow() == DP_SUCCESS) {
        int32_t columnIndex = INIT_VALUE_32;
        int64_t accesserId = INIT_VALUE_64;
        int32_t ret = resultSet->GetColumnIndex("accesserId", columnIndex);
        ret = resultSet->GetLong(columnIndex, accesserId);
        int64_t accesseeId = INIT_VALUE_64;
        ret = resultSet->GetColumnIndex("accesseeId", columnIndex);
        ret = resultSet->GetLong(columnIndex, accesseeId);

        std::shared_ptr<ResultSet> accesserResultSet =
            GetResultSet(SELECT_ACCESSER_TABLE_WHERE_ACCESSERID_AND_ACCESSERTOKENID,
            std::vector<ValueObject>{ ValueObject(accesserId), ValueObject(accesserTokenId) });
        if (accesserResultSet == nullptr) {
            HILOGE("GetAccessControlProfileOnTokenIdAndDeviceId::get accesserResultSet failed");
            return DP_GET_RESULTSET_FAIL;
        }
        int32_t rowCount = INIT_VALUE_32;
        accesserResultSet->GetRowCount(rowCount);
        if (rowCount != 0) {
            std::shared_ptr<ResultSet> accesseeResultSet =
                GetResultSet(SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID_AND_ACCESSEEDEVICEID,
                std::vector<ValueObject>{ ValueObject(accesseeId), ValueObject(accesseeDeviceId) });
            if (accesseeResultSet == nullptr) {
                HILOGE("GetAccessControlProfileOnTokenIdAndDeviceId::get accesseeResultSet failed");
                return DP_GET_RESULTSET_FAIL;
            }
            accesseeResultSet->GetRowCount(rowCount);
            if (rowCount != 0) {
                this->GetVectorAccessControlProfile(resultSet, accesserResultSet, accesseeResultSet, profile);
                accesserResultSet->Close();
                accesseeResultSet->Close();
            }
        }
        accesserResultSet->Close();
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetAccessControlProfileOnBundleName(std::shared_ptr<ResultSet> resultSet,
    const std::string& bundleName, std::vector<AccessControlProfile>& profile)
{
    while (resultSet->GoToNextRow() == DP_SUCCESS) {
        int32_t columnIndex = INIT_VALUE_32;
        int64_t accesserId = INIT_VALUE_64;
        int32_t ret = resultSet->GetColumnIndex("accesserId", columnIndex);
        ret = resultSet->GetLong(columnIndex, accesserId);
        int64_t accesseeId = INIT_VALUE_64;
        ret = resultSet->GetColumnIndex("accesseeId", columnIndex);
        ret = resultSet->GetLong(columnIndex, accesseeId);
        int32_t bindType = INIT_VALUE_32;
        ret = resultSet->GetColumnIndex("bindType", columnIndex);
        ret = resultSet->GetInt(columnIndex, bindType);
        int32_t bindLevel = INIT_VALUE_32;
        ret = resultSet->GetColumnIndex("bindLevel", columnIndex);
        ret = resultSet->GetInt(columnIndex, bindLevel);
        if (bindType == static_cast<int32_t> (BindType::SAME_ACCOUNT) &&
            bindLevel == static_cast<int32_t> (BindLevel::DEVICE)) {
            ret = this->GetAccesserAndAccesseeAndAccessControl(resultSet, accesserId, accesseeId, profile);
            if (ret != DP_SUCCESS) {
                HILOGE("GetAccessControlProfileOnBundleName::GetAccesserAndAccesseeAndAccessControl failed");
                return ret;
            }
        } else {
            ret = this->GetAclVectorOnBundleName(resultSet, accesserId, accesseeId, bundleName, profile);
            if (ret != DP_SUCCESS) {
                HILOGE("GetAccessControlProfileOnBundleName::GetAclVectorOnBundleName failed");
                return ret;
            }
        }
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetVectorAccessControlProfile(std::shared_ptr<ResultSet> resultSet,
    std::shared_ptr<ResultSet> accesserResultSet, std::shared_ptr<ResultSet> accesseeResultSet,
    std::vector<AccessControlProfile>& profile)
{
    Accesser accesser;
    accesserResultSet->GoToNextRow();
    this->AccesserResultSetToAccesser(accesserResultSet, accesser);
    Accessee accessee;
    accesseeResultSet->GoToNextRow();
    this->AccesseeResultSetToAccessee(accesseeResultSet, accessee);
    AccessControlProfile accessControlProfile;
    this->AccessControlResultSetToAccessControlProfile(resultSet, accessControlProfile);

    accessControlProfile.SetAccesser(accesser);
    accessControlProfile.SetAccessee(accessee);
    profile.push_back(accessControlProfile);
    return DP_SUCCESS;
}

int32_t TrustProfileManager::PutAccesserProfile(const AccessControlProfile& profile)
{
    if (rdbStore_ == nullptr) {
        HILOGE("PutAccesserProfile::rdbStore_ is nullptr");
        return DP_GET_RDBSTORE_FAIL;
    }
    ValuesBucket values;
    ProfileUtils::AccesserToEntries(profile, values);
    int64_t rowId = INIT_VALUE_64;
    {
        std::lock_guard<std::mutex> lock(rdbMutex_);
        int32_t ret = rdbStore_->Put(rowId, ACCESSER_TABLE, values);
        if (ret != DP_SUCCESS) {
            HILOGE("PutAccesserProfile::accesser_table insert failed");
            return DP_PUT_ACCESSER_PROFILE_FAIL;
        }
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::PutAccesseeProfile(const AccessControlProfile& profile)
{
    if (rdbStore_ == nullptr) {
        HILOGE("PutAccesseeProfile::rdbStore_ is nullptr");
        return DP_GET_RDBSTORE_FAIL;
    }
    ValuesBucket values;
    ProfileUtils::AccesseeToEntries(profile, values);
    int64_t rowId = INIT_VALUE_64;
    {
        std::lock_guard<std::mutex> lock(rdbMutex_);
        int32_t ret = rdbStore_->Put(rowId, ACCESSEE_TABLE, values);
        if (ret != DP_SUCCESS) {
            HILOGE("PutAccesseeProfile::accessee_table insert failed");
            return DP_PUT_ACCESSEE_PROFILE_FAIL;
        }
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::SetAccessControlId(AccessControlProfile& profile)
{
    if (rdbStore_ == nullptr) {
        HILOGE("SetAccessControlId::rdbStore_ is nullptr");
        return DP_GET_RDBSTORE_FAIL;
    }
    std::shared_ptr<ResultSet> resultSet =
        GetResultSet(SELECT_ACCESS_CONTROL_TABLE, std::vector<ValueObject> {});
    if (resultSet == nullptr) {
        HILOGE("SetAccessControlId::resultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = INIT_VALUE_32;
    resultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        profile.SetAccessControlId(1);
        return DP_SUCCESS;
    }
    int64_t accessControlId = INIT_VALUE_64;
    int32_t columnIndex = INIT_VALUE_32;
    resultSet->GoToLastRow();
    resultSet->GetColumnIndex("accessControlId", columnIndex);
    resultSet->GetLong(columnIndex, accessControlId);
    resultSet->Close();
    profile.SetAccessControlId(accessControlId+1);
    return DP_SUCCESS;
}

int32_t TrustProfileManager::SetAccesserId(AccessControlProfile& profile)
{
    if (rdbStore_ == nullptr) {
        HILOGE("SetAccesserId::rdbStore_ is nullptr");
        return DP_GET_RDBSTORE_FAIL;
    }
    Accesser accesser = profile.GetAccesser();
    std::shared_ptr<ResultSet> resultSet =
        GetResultSet(SELECT_ACCESSER_TABLE_WHERE_ALL, std::vector<ValueObject>{
        ValueObject(accesser.GetAccesserDeviceId()), ValueObject(accesser.GetAccesserUserId()),
        ValueObject(accesser.GetAccesserAccountId()), ValueObject(accesser.GetAccesserTokenId()),
        ValueObject(accesser.GetAccesserBundleName()), ValueObject(accesser.GetAccesserHapSignature()),
        ValueObject(accesser.GetAccesserBindLevel())});
    if (resultSet == nullptr) {
        HILOGE("SetAccesserId::resultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = INIT_VALUE_32;
    int64_t accesserId = INIT_VALUE_64;
    int32_t columnIndex = INIT_VALUE_32;
    resultSet->GetRowCount(rowCount);
    if (rowCount != 0) {
        resultSet->GoToFirstRow();
        resultSet->GetColumnIndex("accesserId", columnIndex);
        resultSet->GetLong(columnIndex, accesserId);
        profile.SetAccesserId(accesserId);
        resultSet->Close();
        return DP_SUCCESS;
    }
    resultSet->Close();
    resultSet = GetResultSet(SELECT_ACCESSER_TABLE, std::vector<ValueObject> {});
    if (resultSet == nullptr) {
        HILOGE("SetAccesserId::resultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    resultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        profile.GetAccesser().SetAccesserId(1);
        profile.SetAccesserId(1);
        return DP_SUCCESS;
    }
    resultSet->GoToLastRow();
    resultSet->GetColumnIndex("accesserId", columnIndex);
    resultSet->GetLong(columnIndex, accesserId);
    resultSet->Close();
    accesserId = accesserId + 1;
    profile.SetAccesserId(accesserId);
    return DP_SUCCESS;
}

int32_t TrustProfileManager::SetAccesseeId(AccessControlProfile& profile)
{
    if (rdbStore_ == nullptr) {
        HILOGE("SetAccesseeId::rdbStore_ is nullptr");
        return DP_GET_RDBSTORE_FAIL;
    }
    Accessee accessee = profile.GetAccessee();
    std::shared_ptr<ResultSet> resultSet =
        GetResultSet(SELECT_ACCESSEE_TABLE_WHERE_ALL, std::vector<ValueObject>{
        ValueObject(accessee.GetAccesseeDeviceId()), ValueObject(accessee.GetAccesseeUserId()),
        ValueObject(accessee.GetAccesseeAccountId()), ValueObject(accessee.GetAccesseeTokenId()),
        ValueObject(accessee.GetAccesseeBundleName()), ValueObject(accessee.GetAccesseeHapSignature()),
        ValueObject(accessee.GetAccesseeBindLevel())});
    if (resultSet == nullptr) {
        HILOGE("SetAccesserId::resultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = INIT_VALUE_32;
    int64_t accesseeId = INIT_VALUE_64;
    int32_t columnIndex = INIT_VALUE_32;
    resultSet->GetRowCount(rowCount);
    if (rowCount != 0) {
        resultSet->GoToFirstRow();
        resultSet->GetColumnIndex("accesseeId", columnIndex);
        resultSet->GetLong(columnIndex, accesseeId);
        profile.SetAccesseeId(accesseeId);
        resultSet->Close();
        return DP_SUCCESS;
    }
    resultSet->Close();
    resultSet =
        GetResultSet(SELECT_ACCESSEE_TABLE, std::vector<ValueObject> {});
    if (resultSet == nullptr) {
        HILOGE("SetAccesseeId::resultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    resultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        profile.GetAccessee().SetAccesseeId(1);
        profile.SetAccesseeId(1);
        return DP_SUCCESS;
    }
    resultSet->GoToLastRow();
    resultSet->GetColumnIndex("accesseeId", columnIndex);
    resultSet->GetLong(columnIndex, accesseeId);
    resultSet->Close();
    accesseeId = accesseeId + 1;
    profile.SetAccesseeId(accesseeId);
    return DP_SUCCESS;
}

int32_t TrustProfileManager::UpdateAccesserProfile(int64_t accesserId, const AccessControlProfile& profile)
{
    ValuesBucket values;
    ProfileUtils::AccesserToEntries(profile, values);
    if (rdbStore_ == nullptr) {
        HILOGE("UpdateAccesserProfile::rdbStore_ is nullptr");
        return DP_GET_RDBSTORE_FAIL;
    }
    int32_t changeRowId = INIT_VALUE_32;
    {
        std::lock_guard<std::mutex> lock(rdbMutex_);
        int32_t ret = rdbStore_->
			Update(changeRowId, ACCESSER_TABLE, values, "accesserId = ? ",
            std::vector<ValueObject> {ValueObject(accesserId)});
        if (ret != DP_SUCCESS) {
            HILOGE("UpdateAccesserProfile::accesser_table update failed");
            return DP_UPDATE_ACCESSER_PROFILE_FAIL;
        }
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::UpdateAccesseeProfile(int64_t accesseeId, const AccessControlProfile& profile)
{
    ValuesBucket values;
    ProfileUtils::AccesseeToEntries(profile, values);
    if (rdbStore_ == nullptr) {
        HILOGE("UpdateAccesseeProfile::rdbStore_ is nullptr");
        return DP_GET_RDBSTORE_FAIL;
    }
    int32_t changeRowId = INIT_VALUE_32;
    {
        std::lock_guard<std::mutex> lock(rdbMutex_);
        int32_t ret = rdbStore_->
			Update(changeRowId, ACCESSEE_TABLE, values, "accesseeId = ? ",
            std::vector<ValueObject>{ ValueObject(accesseeId) });
        if (ret != DP_SUCCESS) {
            HILOGE("UpdateAccesseeProfile::accessee_table update failed");
            return DP_UPDATE_ACCESSEE_PROFILE_FAIL;
        }
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::UpdateTrustDeviceProfileNotify(const TrustDeviceProfile& oldProfile,
    const TrustDeviceProfile &newProfile)
{
    int32_t ret = INIT_VALUE_32;
    if (oldProfile.GetStatus() == 1 && newProfile.GetStatus() == 0) {
        ret = SubscribeProfileManager::GetInstance().NotifyTrustDeviceProfileDelete(newProfile);
        if (ret != DP_SUCCESS) {
            HILOGE("UpdateTrustDeviceProfileNotify::NotifyTrustDeviceProfileDelete failed");
            return DP_NOTIFY_TRUST_DEVICE_FAIL;
        }
    }
    if (oldProfile.GetStatus() == 0 && newProfile.GetStatus() == 1) {
        ret = SubscribeProfileManager::GetInstance().NotifyTrustDeviceProfileAdd(newProfile);
        if (ret != DP_SUCCESS) {
            HILOGE("UpdateTrustDeviceProfileNotify::NotifyTrustDeviceProfileAdd failed");
            return DP_NOTIFY_TRUST_DEVICE_FAIL;
        }
    }
    if (oldProfile.GetDeviceId() != newProfile.GetDeviceId() ||
        oldProfile.GetDeviceIdHash() != newProfile.GetDeviceIdHash() ||
        oldProfile.GetDeviceIdType() != newProfile.GetDeviceIdType()) {
        ret = SubscribeProfileManager::GetInstance().NotifyTrustDeviceProfileUpdate(oldProfile, newProfile);
        if (ret != DP_SUCCESS) {
            HILOGE("UpdateTrustDeviceProfileNotify::NotifyTrustDeviceProfileUpdate failed");
            return DP_NOTIFY_TRUST_DEVICE_FAIL;
        }
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetResultStatus(const std::string& trustDeviceId, int32_t& trustDeviceStatus)
{
    if (rdbStore_ == nullptr) {
        HILOGE("GetResultStatus::rdbStore_ is nullptr");
        return DP_GET_RDBSTORE_FAIL;
    }
    std::shared_ptr<ResultSet> resultSet =
        GetResultSet(SELECT_ACCESS_CONTROL_TABLE_WHERE_TRUSTDEVICEID,
        std::vector<ValueObject>{ ValueObject(trustDeviceId) });
    if (resultSet == nullptr) {
        HILOGE("GetResultStatus::resultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = INIT_VALUE_32;
    resultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        HILOGE("GetResultStatus::trustDeviceId not find");
        return DP_NOT_FIND_DATA;
    }
    int32_t columnIndex = INIT_VALUE_32;
    int32_t ret = INIT_VALUE_32;
    trustDeviceStatus = 0;
    while (resultSet->GoToNextRow() == DP_SUCCESS) {
        int32_t status = INIT_VALUE_32;
        ret = resultSet->GetColumnIndex("status", columnIndex);
        ret = resultSet->GetInt(columnIndex, status);
        if (status == 1) {
            trustDeviceStatus = 1;
            break;
        }
    }
    resultSet->Close();
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetAccesserAndAccesseeAndAccessControl(std::shared_ptr<ResultSet> resultSet,
    int64_t accesserId, int64_t accesseeId, std::vector<AccessControlProfile>& profile)
{
    std::shared_ptr<ResultSet> accesserResultSet =
        GetResultSet(SELECT_ACCESSER_TABLE_WHERE_ACCESSERID,
        std::vector<ValueObject>{ ValueObject(accesserId) });
    if (accesserResultSet == nullptr) {
        HILOGE("GetAccesserAndAccesseeAndAccessControl::accesserResultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = INIT_VALUE_32;
    accesserResultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        HILOGE("GetAccesserAndAccesseeAndAccessControl::not find data");
        return DP_NOT_FIND_DATA;
    }
    std::shared_ptr<ResultSet> accesseeResultSet =
        GetResultSet(SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID,
        std::vector<ValueObject>{ ValueObject(accesseeId) });
    if (accesseeResultSet == nullptr) {
        HILOGE("GetAccesserAndAccesseeAndAccessControl::accesseeResultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    accesseeResultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        HILOGE("GetAccesserAndAccesseeAndAccessControl::not find data");
        return DP_NOT_FIND_DATA;
    }
    this->GetVectorAccessControlProfile(resultSet, accesserResultSet, accesseeResultSet, profile);
    accesserResultSet->Close();
    accesseeResultSet->Close();
    return DP_SUCCESS;
}

int32_t TrustProfileManager::DeleteAccessControlProfileCheck(std::shared_ptr<ResultSet> resultSet)
{
    int32_t ret = resultSet->GoToNextRow();
    if (ret != DP_SUCCESS) {
        HILOGE("DeleteAccessControlProfileCheck::get AccessControlProfileResult failed");
        return DP_NOT_FIND_DATA;
    }
    AccessControlProfile profile;
    this->AccessControlResultSetToAccessControlProfile(resultSet, profile);
    resultSet->Close();

    ret = this->DeleteAccesseeCheck(profile.GetAccesseeId());
    if (ret != DP_SUCCESS) {
        HILOGE("DeleteAccessControlProfileCheck::DeleteAccesseeCheck failed");
        return ret;
    }
    ret = this->DeleteAccesserCheck(profile.GetAccesserId());
    if (ret != DP_SUCCESS) {
        HILOGE("DeleteAccessControlProfileCheck::DeleteAccesserCheck failed");
        return ret;
    }
    {
        std::lock_guard<std::mutex> lock(rdbMutex_);
        int32_t deleteRows = INIT_VALUE_32;
        ret = rdbStore_->Delete(deleteRows, ACCESS_CONTROL_TABLE, "accessControlId = ?",
            std::vector<ValueObject>{ ValueObject(profile.GetAccessControlId()) });
        if (ret != DP_SUCCESS) {
            HILOGE("DeleteAccessControlProfile::delete access_control_table failed");
            return DP_DELETE_ACCESS_CONTROL_PROFILE_FAIL;
        }
    }
    ret = this->DeleteTrustDeviceCheck(profile);
    if (ret != DP_SUCCESS) {
        HILOGE("DeleteAccessControlProfileCheck::DeleteTrustDeviceCheck failed");
        return ret;
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::TrustResultSetToTrustDeviceProfile(
    std::shared_ptr<ResultSet> trustResultSet, TrustDeviceProfile& trustDeviceProfile)
{
    int32_t columnIndex = INIT_VALUE_32;
    std::string deviceId;
    trustResultSet->GetColumnIndex("deviceId", columnIndex);
    trustResultSet->GetString(columnIndex, deviceId);
    trustDeviceProfile.SetDeviceId(deviceId);

    int32_t deviceIdType = INIT_VALUE_32;
    trustResultSet->GetColumnIndex("deviceIdType", columnIndex);
    trustResultSet->GetInt(columnIndex, deviceIdType);
    trustDeviceProfile.SetDeviceIdType(deviceIdType);

    std::string deviceIdHash;
    trustResultSet->GetColumnIndex("deviceIdHash", columnIndex);
    trustResultSet->GetString(columnIndex, deviceIdHash);
    trustDeviceProfile.SetDeviceIdHash(deviceIdHash);

    int32_t status = INIT_VALUE_32;
    trustResultSet->GetColumnIndex("status", columnIndex);
    trustResultSet->GetInt(columnIndex, status);
    trustDeviceProfile.SetStatus(status);
    return DP_SUCCESS;
}

int32_t TrustProfileManager::AccesserResultSetToAccesser(std::shared_ptr<ResultSet> accesserResultSet,
    Accesser& accesser)
{
    int32_t columnIndex = INIT_VALUE_32;
    int64_t accesserId = INIT_VALUE_64;
    accesserResultSet->GetColumnIndex("accesserId", columnIndex);
    accesserResultSet->GetLong(columnIndex, accesserId);
    accesser.SetAccesserId(accesserId);

    std::string accesserDeviceId;
    accesserResultSet->GetColumnIndex("accesserDeviceId", columnIndex);
    accesserResultSet->GetString(columnIndex, accesserDeviceId);
    accesser.SetAccesserDeviceId(accesserDeviceId);

    int32_t accesserUserId = INIT_VALUE_32;
    accesserResultSet->GetColumnIndex("accesserUserId", columnIndex);
    accesserResultSet->GetInt(columnIndex, accesserUserId);
    accesser.SetAccesserUserId(accesserUserId);

    std::string accesserAccountId;
    accesserResultSet->GetColumnIndex("accesserAccountId", columnIndex);
    accesserResultSet->GetString(columnIndex, accesserAccountId);
    accesser.SetAccesserAccountId(accesserAccountId);

    int64_t accesserTokenId = INIT_VALUE_64;
    accesserResultSet->GetColumnIndex("accesserTokenId", columnIndex);
    accesserResultSet->GetLong(columnIndex, accesserTokenId);
    accesser.SetAccesserTokenId(accesserTokenId);

    std::string accesserBundleName;
    accesserResultSet->GetColumnIndex("accesserBundleName", columnIndex);
    accesserResultSet->GetString(columnIndex, accesserBundleName);
    accesser.SetAccesserBundleName(accesserBundleName);

    std::string accesserHapSignature;
    accesserResultSet->GetColumnIndex("accesserHapSignature", columnIndex);
    accesserResultSet->GetString(columnIndex, accesserHapSignature);
    accesser.SetAccesserHapSignature(accesserHapSignature);

    int32_t accesserBindLevel = INIT_VALUE_32;
    accesserResultSet->GetColumnIndex("accesserBindLevel", columnIndex);
    accesserResultSet->GetInt(columnIndex, accesserBindLevel);
    accesser.SetAccesserBindLevel(accesserBindLevel);
    return DP_SUCCESS;
}

int32_t TrustProfileManager::AccesseeResultSetToAccessee(std::shared_ptr<ResultSet> accesseeResultSet,
    Accessee& accessee)
{
    int32_t columnIndex = INIT_VALUE_32;
    int64_t accesseeId = INIT_VALUE_64;
    accesseeResultSet->GetColumnIndex("accesseeId", columnIndex);
    accesseeResultSet->GetLong(columnIndex, accesseeId);
    accessee.SetAccesseeId(accesseeId);

    std::string accesseeDeviceId;
    accesseeResultSet->GetColumnIndex("accesseeDeviceId", columnIndex);
    accesseeResultSet->GetString(columnIndex, accesseeDeviceId);
    accessee.SetAccesseeDeviceId(accesseeDeviceId);

    int32_t accesseeUserId = INIT_VALUE_32;
    accesseeResultSet->GetColumnIndex("accesserUserId", columnIndex);
    accesseeResultSet->GetInt(columnIndex, accesseeUserId);
    accessee.SetAccesseeUserId(accesseeUserId);

    std::string accesseeAccountId;
    accesseeResultSet->GetColumnIndex("accesseeAccountId", columnIndex);
    accesseeResultSet->GetString(columnIndex, accesseeAccountId);
    accessee.SetAccesseeAccountId(accesseeAccountId);

    int64_t accesseeTokenId = INIT_VALUE_64;
    accesseeResultSet->GetColumnIndex("accesseeTokenId", columnIndex);
    accesseeResultSet->GetLong(columnIndex, accesseeTokenId);
    accessee.SetAccesseeTokenId(accesseeTokenId);

    std::string accesseeBundleName;
    accesseeResultSet->GetColumnIndex("accesseeBundleName", columnIndex);
    accesseeResultSet->GetString(columnIndex, accesseeBundleName);
    accessee.SetAccesseeBundleName(accesseeBundleName);

    std::string accesseeHapSignature;
    accesseeResultSet->GetColumnIndex("accesseeHapSignature", columnIndex);
    accesseeResultSet->GetString(columnIndex, accesseeHapSignature);
    accessee.SetAccesseeHapSignature(accesseeHapSignature);

    int32_t accesseeBindLevel = INIT_VALUE_32;
    accesseeResultSet->GetColumnIndex("accesseeBindLevel", columnIndex);
    accesseeResultSet->GetInt(columnIndex, accesseeBindLevel);
    accessee.SetAccesseeBindLevel(accesseeBindLevel);
    return DP_SUCCESS;
}

int32_t TrustProfileManager::AccessControlResultSetToAccessControlProfile(
    std::shared_ptr<ResultSet> accessControlResultSet, AccessControlProfile& accessControlProfile)
{
    int32_t columnIndex = INIT_VALUE_32;
    int64_t accessControlId = INIT_VALUE_64;
    accessControlResultSet->GetColumnIndex("accessControlId", columnIndex);
    accessControlResultSet->GetLong(columnIndex, accessControlId);
    accessControlProfile.SetAccessControlId(accessControlId);

    int64_t accesserId = INIT_VALUE_64;
    accessControlResultSet->GetColumnIndex("accesserId", columnIndex);
    accessControlResultSet->GetLong(columnIndex, accesserId);
    accessControlProfile.SetAccesserId(accesserId);

    int64_t accesseeId = INIT_VALUE_64;
    accessControlResultSet->GetColumnIndex("accesseeId", columnIndex);
    accessControlResultSet->GetLong(columnIndex, accesseeId);
    accessControlProfile.SetAccesseeId(accesseeId);

    std::string trustDeviceId;
    accessControlResultSet->GetColumnIndex("trustDeviceId", columnIndex);
    accessControlResultSet->GetString(columnIndex, trustDeviceId);
    accessControlProfile.SetTrustDeviceId(trustDeviceId);
    
    std::string sessionKey;
    accessControlResultSet->GetColumnIndex("sessionKey", columnIndex);
    accessControlResultSet->GetString(columnIndex, sessionKey);
    accessControlProfile.SetSessionKey(sessionKey);

    int32_t bindType = INIT_VALUE_32;
    accessControlResultSet->GetColumnIndex("bindType", columnIndex);
    accessControlResultSet->GetInt(columnIndex, bindType);
    accessControlProfile.SetBindType(bindType);

    int32_t authenticationType = INIT_VALUE_32;
    accessControlResultSet->GetColumnIndex("authenticationType", columnIndex);
    accessControlResultSet->GetInt(columnIndex, authenticationType);
    accessControlProfile.SetAuthenticationType(authenticationType);

    int32_t deviceIdType = INIT_VALUE_32;
    accessControlResultSet->GetColumnIndex("deviceIdType", columnIndex);
    accessControlResultSet->GetInt(columnIndex, deviceIdType);
    accessControlProfile.SetDeviceIdType(deviceIdType);

    std::string deviceIdHash;
    accessControlResultSet->GetColumnIndex("deviceIdHash", columnIndex);
    accessControlResultSet->GetString(columnIndex, deviceIdHash);
    accessControlProfile.SetDeviceIdHash(deviceIdHash);

    int32_t status = INIT_VALUE_32;
    accessControlResultSet->GetColumnIndex("status", columnIndex);
    accessControlResultSet->GetInt(columnIndex, status);
    accessControlProfile.SetStatus(status);

    int32_t validPeriod = INIT_VALUE_32;
    accessControlResultSet->GetColumnIndex("validPeriod", columnIndex);
    accessControlResultSet->GetInt(columnIndex, validPeriod);
    accessControlProfile.SetValidPeriod(validPeriod);

    int32_t lastAuthTime = INIT_VALUE_32;
    accessControlResultSet->GetColumnIndex("lastAuthTime", columnIndex);
    accessControlResultSet->GetInt(columnIndex, lastAuthTime);
    accessControlProfile.SetLastAuthTime(lastAuthTime);

    int32_t bindLevel = INIT_VALUE_32;
    accessControlResultSet->GetColumnIndex("bindLevel", columnIndex);
    accessControlResultSet->GetInt(columnIndex, bindLevel);
    accessControlProfile.SetBindLevel(bindLevel);
    return DP_SUCCESS;
}

std::shared_ptr<ResultSet> TrustProfileManager::GetResultSet(
    const std::string& sql, std::vector<ValueObject> condition)
{
    if (sql.empty() || sql.length() > MAX_STRING_LEN) {
        HILOGE("sql is invalid");
    }
    if (condition.empty() || condition.size() > MAX_PARAM_SIZE) {
        HILOGE("condition is invalid");
    }
    std::lock_guard<std::mutex> lock(rdbMutex_);
    return rdbStore_->Get(sql, condition);
}

int32_t TrustProfileManager::SetAclId(AccessControlProfile& accessControlProfile)
{
    this->SetAccessControlId(accessControlProfile);
    this->SetAccesserId(accessControlProfile);
    this->SetAccesseeId(accessControlProfile);
    Accesser accesser(accessControlProfile.GetAccesser());
    accesser.SetAccesserId(accessControlProfile.GetAccesserId());
    accessControlProfile.SetAccesser(accesser);

    Accessee accessee(accessControlProfile.GetAccessee());
    accessee.SetAccesseeId(accessControlProfile.GetAccesseeId());
    accessControlProfile.SetAccessee(accessee);
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetAclOnUserAndBundleAndDeviceIdAndStauts(
    std::map<std::string, std::string> params, std::vector<AccessControlProfile>& profile)
{
    auto iter = params.find("userId");
    int32_t userId = std::atoi(iter->second.c_str());
    std::string bundleName = params.find("bundleName")->second;
    std::string trustDeviceId = params.find("trustDeviceId")->second;
    iter = params.find("status");
    int32_t status = std::atoi(iter->second.c_str());
    int32_t ret = this->GetAccessControlProfile(userId, bundleName, trustDeviceId, status, profile);
    if (ret != DP_SUCCESS) {
        HILOGE("GetAccessControlProfile::params not find");
        return ret;
    }
    if (profile.empty()) {
        return DP_NOT_FIND_DATA;
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetAclOnUserAndBundleAndBindAndStauts(std::map<std::string, std::string> params,
    std::vector<AccessControlProfile>& profile)
{
    auto iter = params.find("userId");
    int32_t userId = std::atoi(iter->second.c_str());
    std::string bundleName = params.find("bundleName")->second;
    iter = params.find("bindType");
    int32_t bindType = std::atoi(iter->second.c_str());
    iter = params.find("status");
    int32_t status = std::atoi(iter->second.c_str());
    int32_t ret = this->GetAccessControlProfile(userId, bundleName, bindType, status, profile);
    if (ret != DP_SUCCESS) {
        HILOGE("GetAccessControlProfile::faild");
        return ret;
    }
    if (profile.empty()) {
        return DP_NOT_FIND_DATA;
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetAclOnBundleAndBindAndStauts(std::map<std::string, std::string> params,
    std::vector<AccessControlProfile>& profile)
{
    std::string bundleName = params.find("bundleName")->second;
    auto iter = params.find("bindType");
    int32_t bindType = std::atoi(iter->second.c_str());
    iter = params.find("status");
    int32_t status = std::atoi(iter->second.c_str());
    int32_t ret = this->GetAccessControlProfile(bundleName, bindType, status, profile);
    if (ret != DP_SUCCESS) {
        HILOGE("GetAccessControlProfile::params not find");
        return ret;
    }
    if (profile.empty()) {
        return DP_NOT_FIND_DATA;
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetAclOnBundleAndDeviceIdAndStauts(std::map<std::string, std::string> params,
    std::vector<AccessControlProfile>& profile)
{
    std::string bundleName = params.find("bundleName")->second;
    std::string trustDeviceId = params.find("trustDeviceId")->second;
    auto iter = params.find("status");
    int32_t status = std::atoi(iter->second.c_str());
    int32_t ret = this->GetAccessControlProfile(bundleName, trustDeviceId, status, profile);
    if (ret != DP_SUCCESS) {
        HILOGE("GetAccessControlProfile::params not find");
        return ret;
    }
    if (profile.empty()) {
        return DP_NOT_FIND_DATA;
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetAclOnUserAndAccount(std::map<std::string, std::string> params,
    std::vector<AccessControlProfile>& profile)
{
    auto iter = params.find("userId");
    int32_t userId = std::atoi(iter->second.c_str());
    std::string accountId = params.find("accountId")->second;
    int32_t ret = this->GetAccessControlProfile(userId, accountId, profile);
    if (ret != DP_SUCCESS) {
        HILOGE("GetAccessControlProfile::params not find");
        return ret;
    }
    if (profile.empty()) {
        return DP_NOT_FIND_DATA;
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetAclVectorOnUserIdAndBundleName(std::shared_ptr<ResultSet> resultSet,
    int64_t accesserId, int64_t accesseeId, int32_t userId, const std::string& bundleName,
    std::vector<AccessControlProfile>& profile)
{
    std::shared_ptr<ResultSet> accesserResultSet =
        GetResultSet(SELECT_ACCESSER_TABLE_WHERE_ACCESSERID_AND_ACCESSERUSERID_ACCESSERBUNDLENAME,
        std::vector<ValueObject>{ ValueObject(accesserId), ValueObject(userId), ValueObject(bundleName) });
    if (accesserResultSet == nullptr) {
        HILOGE("GetAccessControlProfileOnUserIdAndBundleName::get accesserResultSet failed");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = INIT_VALUE_32;
    accesserResultSet->GetRowCount(rowCount);
    if (rowCount != 0) {
        std::shared_ptr<ResultSet> accesseeResultSet =
            GetResultSet(SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID,
            std::vector<ValueObject>{ ValueObject(accesseeId) });
        this->GetVectorAccessControlProfile(resultSet, accesserResultSet, accesseeResultSet, profile);
        accesserResultSet->Close();
        accesseeResultSet->Close();
        return DP_SUCCESS;
    }
    accesserResultSet->Close();

    std::shared_ptr<ResultSet> accesseeResultSet =
        GetResultSet(SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID_AND_ACCESSEEUSEEID_ACCESSEEBUNDLENAME,
        std::vector<ValueObject>{ ValueObject(accesseeId), ValueObject(userId), ValueObject(bundleName) });
    if (accesseeResultSet == nullptr) {
        HILOGE("GetAccessControlProfileOnUserIdAndBundleName::get accesseeResultSet failed");
        return DP_GET_RESULTSET_FAIL;
    }
    accesseeResultSet->GetRowCount(rowCount);
    if (rowCount != 0) {
        accesserResultSet = GetResultSet(SELECT_ACCESSER_TABLE_WHERE_ACCESSERID,
            std::vector<ValueObject>{ ValueObject(accesserId) });
        this->GetVectorAccessControlProfile(resultSet, accesserResultSet, accesseeResultSet, profile);
        accesseeResultSet->Close();
        accesserResultSet->Close();
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetAclVectorOnUserId(std::shared_ptr<ResultSet> resultSet, int64_t accesserId,
    int64_t accesseeId, int32_t userId, std::vector<AccessControlProfile>& profile)
{
    std::shared_ptr<ResultSet> accesserResultSet =
        GetResultSet(SELECT_ACCESSER_TABLE_WHERE_ACCESSERID_AND_ACCESSERUSERID,
        std::vector<ValueObject>{ ValueObject(accesserId), ValueObject(userId) });
    if (accesserResultSet == nullptr) {
        HILOGE("GetAccessControlProfileOnUserIdAndBundleName::get accesserResultSet failed");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = INIT_VALUE_32;
    accesserResultSet->GetRowCount(rowCount);
    if (rowCount != 0) {
        std::shared_ptr<ResultSet> accesseeResultSet =
            GetResultSet(SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID,
            std::vector<ValueObject>{ ValueObject(accesseeId) });
        this->GetVectorAccessControlProfile(resultSet, accesserResultSet, accesseeResultSet, profile);
        accesserResultSet->Close();
        accesseeResultSet->Close();
        return DP_SUCCESS;
    }
    accesserResultSet->Close();

    std::shared_ptr<ResultSet> accesseeResultSet =
        GetResultSet(SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID_AND_ACCESSEEUSERID,
        std::vector<ValueObject>{ ValueObject(accesseeId), ValueObject(userId) });
    if (accesseeResultSet == nullptr) {
        HILOGE("GetAccessControlProfileOnUserIdAndBundleName::get accesseeResultSet failed");
        return DP_GET_RESULTSET_FAIL;
    }
    accesseeResultSet->GetRowCount(rowCount);
    if (rowCount != 0) {
        accesserResultSet = GetResultSet(SELECT_ACCESSER_TABLE_WHERE_ACCESSERID,
            std::vector<ValueObject>{ ValueObject(accesserId) });
        this->GetVectorAccessControlProfile(resultSet, accesserResultSet, accesseeResultSet, profile);
        accesseeResultSet->Close();
        accesserResultSet->Close();
    }
    if (profile.empty()) {
        HILOGE("GetAccessControlProfileOnTokenIdAndDeviceId::not find data");
        return DP_GET_ACL_PROFILE_FAIL;
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetAclVectorOnBundleName(std::shared_ptr<ResultSet> resultSet, int64_t accesserId,
    int64_t accesseeId, const std::string& bundleName, std::vector<AccessControlProfile>& profile)
{
    std::shared_ptr<ResultSet> accesserResultSet =
        GetResultSet(SELECT_ACCESSER_TABLE_WHERE_ACCESSERID_AND_ACCESSERBUNDLENAME,
        std::vector<ValueObject>{ ValueObject(accesserId), ValueObject(bundleName) });
    if (accesserResultSet == nullptr) {
        HILOGE("GetAccessControlProfileOnUserIdAndTokenId::get result failed");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = INIT_VALUE_32;
    accesserResultSet->GetRowCount(rowCount);
    if (rowCount != 0) {
        std::shared_ptr<ResultSet> accesseeResultSet =
            GetResultSet(SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID,
            std::vector<ValueObject>{ ValueObject(accesseeId) });
        this->GetVectorAccessControlProfile(resultSet, accesserResultSet, accesseeResultSet, profile);
        accesserResultSet->Close();
        accesseeResultSet->Close();
        return DP_SUCCESS;
    }
    accesserResultSet->Close();

    std::shared_ptr<ResultSet> accesseeResultSet =
        GetResultSet(SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID_AND_ACCESSEEBUNDLENAME,
        std::vector<ValueObject>{ ValueObject(accesseeId), ValueObject(bundleName) });
    if (accesseeResultSet == nullptr) {
        HILOGE("GetAccessControlProfileOnUserIdAndTokenId::get accesseeResultSet failed");
        return DP_GET_RESULTSET_FAIL;
    }
    accesseeResultSet->GetRowCount(rowCount);
    if (rowCount != 0) {
        accesserResultSet = GetResultSet(SELECT_ACCESSER_TABLE_WHERE_ACCESSERID,
            std::vector<ValueObject>{ ValueObject(accesserId) });
        this->GetVectorAccessControlProfile(resultSet, accesserResultSet, accesseeResultSet, profile);
        accesseeResultSet->Close();
        accesserResultSet->Close();
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::DeleteAccesserCheck(int64_t accesserId)
{
    int32_t deleteRows = INIT_VALUE_32;
    std::shared_ptr<ResultSet> resultSet =
        GetResultSet(SELECT_ACCESS_CONTROL_TABLE_WHERE_ACCESSERID,
        std::vector<ValueObject>{ ValueObject(accesserId) });
    if (resultSet == nullptr) {
        HILOGE("DeleteAccesseeCheck::accesserId not find");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = INIT_VALUE_32;
    resultSet->GetRowCount(rowCount);
    resultSet->Close();
    if (rowCount == 1) {
        std::lock_guard<std::mutex> lock(rdbMutex_);
        int32_t ret = rdbStore_->
            Delete(deleteRows, ACCESSER_TABLE, "accesserId = ?",
            std::vector<ValueObject>{ ValueObject(accesserId) });
        if (ret != DP_SUCCESS) {
            HILOGE("DeleteAccesseeCheck::delete accesser_table accesserId failed");
            return DP_DELETE_ACCESSER_PROFILE_FAIL;
        }
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::UpdateAclCheck(const AccessControlProfile& profile)
{
    if (rdbStore_ == nullptr) {
        HILOGE("UpdateAccessControlProfile::rdbStore_ is nullptr");
        return DP_GET_RDBSTORE_FAIL;
    }
    std::shared_ptr<ResultSet> resultSet =
        GetResultSet(SELECT_ACCESS_CONTROL_TABLE_WHERE_ACCESSCONTROLID,
        std::vector<ValueObject>{ ValueObject(profile.GetAccessControlId()) });
    if (resultSet == nullptr) {
        HILOGE("UpdateAccessControlProfile::resultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = INIT_VALUE_32;
    resultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        HILOGE("UpdateAccessControlProfile::accessControlId not find");
        return DP_NOT_FIND_DATA;
    }
    resultSet->GoToNextRow();
    AccessControlProfile oldProfile;
    this->AccessControlResultSetToAccessControlProfile(resultSet, oldProfile);
    resultSet->Close();
    if (oldProfile.GetAccesseeId() != profile.GetAccessee().GetAccesseeId() ||
        oldProfile.GetAccesserId() != profile.GetAccesser().GetAccesserId() ||
        oldProfile.GetAccesserId() != profile.GetAccesserId() ||
        oldProfile.GetAccesseeId() != profile.GetAccesseeId()) {
        HILOGE("UpdateAclCheck:Can't Update not allowed attribute");
        return DP_UPDATE_ACL_NOT_ALLOW;
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::DeleteAccesseeCheck(int64_t accesseeId)
{
    int32_t deleteRows = INIT_VALUE_32;
    std::shared_ptr<ResultSet> resultSet =
        GetResultSet(SELECT_ACCESS_CONTROL_TABLE_WHERE_ACCESSEEID,
        std::vector<ValueObject>{ ValueObject(accesseeId) });
    if (resultSet == nullptr) {
        HILOGE("DeleteAccesseeCheck::accesseeId not find");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = INIT_VALUE_32;
    resultSet->GetRowCount(rowCount);
    resultSet->Close();
    if (rowCount == 1) {
        std::lock_guard<std::mutex> lock(rdbMutex_);
        int32_t ret = rdbStore_->
            Delete(deleteRows, ACCESSEE_TABLE, "accesseeId = ?",
            std::vector<ValueObject> {ValueObject(accesseeId)});
        if (ret != DP_SUCCESS) {
            HILOGE("DeleteAccessControlProfileCheck::delete accessee_table accesseeId failed");
            return DP_DELETE_ACCESSEE_PROFILE_FAIL;
        }
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::DeleteTrustDeviceCheck(const AccessControlProfile& profile)
{
    std::shared_ptr<ResultSet> resultSet =
        GetResultSet(SELECT_ACCESS_CONTROL_TABLE_WHERE_TRUSTDEVICEID,
        std::vector<ValueObject>{ ValueObject(profile.GetTrustDeviceId()) });
    if (resultSet == nullptr) {
        HILOGE("DeleteTrustDeviceCheck::trustDeviceId not find");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = INIT_VALUE_32;
    resultSet->GetRowCount(rowCount);
    int32_t ret = INIT_VALUE_32;
    if (rowCount == 0) {
        ret = this->DeleteTrustDeviceProfile(profile.GetTrustDeviceId());
        if (ret != DP_SUCCESS) {
            HILOGE("DeleteTrustDeviceCheck::DeleteTrustDeviceProfile failed");
            return DP_DELETE_TRUST_DEVICE_PROFILE_FAIL;
        }
    } else {
        int32_t status = INIT_VALUE_32;
        this->GetResultStatus(profile.GetTrustDeviceId(), status);
        TrustDeviceProfile trustDeviceProfile;
        trustDeviceProfile.SetDeviceId(profile.GetTrustDeviceId());
        trustDeviceProfile.SetDeviceIdType(profile.GetDeviceIdType());
        trustDeviceProfile.SetDeviceIdHash(profile.GetDeviceIdHash());
        trustDeviceProfile.SetStatus(status);
        ret = this->UpdateTrustDeviceProfile(trustDeviceProfile);
        if (ret != DP_SUCCESS) {
            HILOGE("DeleteTrustDeviceCheck::UpdateTrustDeviceProfile failed");
            return DP_UPDATE_TRUST_DEVICE_PROFILE_FAIL;
        }
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetAclOnTokenIdAndDeviceId(std::map<std::string, std::string> params,
    std::vector<AccessControlProfile>& profile)
{
    auto iter = params.find("accesserTokenId");
    int32_t accesserTokenId = std::atoi(iter->second.c_str());
    std::string accesseeDeviceId = params.find("accesseeDeviceId")->second;
    int32_t ret = this->GetAccessControlProfileOnTokenAndDevice(accesserTokenId, accesseeDeviceId, profile);
    if (ret != DP_SUCCESS) {
        HILOGE("GetAccessControlProfile::params not find");
        return ret;
    }
    if (profile.empty()) {
        return DP_NOT_FIND_DATA;
    }
    return DP_SUCCESS;
}
} // namespace DistributedDeviceProfile
} // namespace OHOS