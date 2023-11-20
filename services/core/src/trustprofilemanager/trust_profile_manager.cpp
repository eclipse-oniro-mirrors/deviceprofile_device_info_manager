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
        rdbStore_ = std::make_shared<RdbAdapter> ();
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

    int64_t id;
    int32_t ret;
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
    int64_t rowId;
    int32_t ret;
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
    std::shared_ptr<ResultSet> resultSet = rdbStore_->
        Get(SELECT_TRUST_DEVICE_TABLE_WHERE_DEVICEID, std::vector<ValueObject>{ValueObject(trustDeviceId)});
    if (resultSet == nullptr) {
        HILOGE("PutAccessControlProfile::get resultSet failed");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount;
    resultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        this->PutTrustDeviceProfile(trustProfile);
        return DP_SUCCESS;
    }
    int32_t trustDeviceStatus;
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
    std::shared_ptr<ResultSet> resultSet = rdbStore_->
        Get(SELECT_TRUST_DEVICE_TABLE_WHERE_DEVICEID, std::vector<ValueObject>{ValueObject(deviceId)});
    if (resultSet == nullptr) {
        HILOGE("UpdateTrustDeviceProfile::deviceId not find");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount;
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
    if (profile.GetDeviceId() == oldProfile.GetDeviceId() &&
        profile.GetDeviceIdHash() == oldProfile.GetDeviceIdHash() &&
        profile.GetDeviceIdType() == oldProfile.GetDeviceIdType() &&
        profile.GetStatus() == oldProfile.GetStatus()) {
        HILOGI("UpdateTrustDeviceProfile::data not have change");
        return DP_SUCCESS;
    }
    ValuesBucket values;
    ProfileUtils::TrustDeviceProfileToEntries(profile, values);
    int32_t rowCnt;
    {
        std::lock_guard<std::mutex> lock(rdbMutex_);
        ret = rdbStore_->Update(rowCnt, TRUST_DEVICE_TABLE, values, "deviceId = ?",
            std::vector<ValueObject>{ValueObject(profile.GetDeviceId())});
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
    int32_t rowCnt;
    {
        std::lock_guard<std::mutex> lock(rdbMutex_);
        ret = rdbStore_->Update(rowCnt, ACCESS_CONTROL_TABLE, values, "accessControlId = ?",
            std::vector<ValueObject> {ValueObject(profile.GetAccessControlId())});
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
    if (ret != DP_SUCCESS)
    {
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
    std::shared_ptr<ResultSet> resultSet = rdbStore_->
        Get(SELECT_TRUST_DEVICE_TABLE_WHERE_DEVICEID, std::vector<ValueObject>{ValueObject(deviceId)});
    if (resultSet == nullptr) {
        HILOGE("GetTrustDeviceProfile::get result failed");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount;
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
    std::shared_ptr<ResultSet> resultSet = rdbStore_->Get(SELECT_TRUST_DEVICE_TABLE);
    if (resultSet == nullptr) {
        HILOGE("GetAllTrustDeviceProfile::get result failed");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount;
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
    std::shared_ptr<ResultSet> resultSet = rdbStore_->Get(SELECT_ACCESS_CONTROL_TABLE_WHERE_BINDTYPE_AND_STATUS,
        std::vector<ValueObject>{ValueObject(bindType), ValueObject(status)});
    if (resultSet == nullptr) {
        HILOGE("GetAccessControlProfile::resultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount;
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
    if (profile.empty()) {
        return DP_NOT_FIND_DATA;
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetAccessControlProfile(int32_t userId, const std::string& bundleName,
    const std::string& trustDeviceId, int32_t status, std::vector<AccessControlProfile>& profile)
{
    if (rdbStore_ == nullptr) {
        HILOGE("GetAccessControlProfile::rdbStore_ is nullptr");
        return DP_GET_RDBSTORE_FAIL;
    }
    std::shared_ptr<ResultSet> resultSet = rdbStore_->
        Get(SELECT_ACCESS_CONTROL_TABLE_WHERE_TRUSTDEVICEID_AND_STATUS,
        std::vector<ValueObject>{ValueObject(trustDeviceId), ValueObject(status)});
    if (resultSet == nullptr) {
        HILOGE("GetAccessControlProfile::bindType not find");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount;
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
    if (profile.empty()) {
        return DP_NOT_FIND_DATA;
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetAllAccessControlProfile(std::vector<AccessControlProfile>& profile)
{
    if (rdbStore_ == nullptr) {
        HILOGE("GetAllAccessControlProfile::rdbStore_ is nullptr");
        return DP_GET_RDBSTORE_FAIL;
    }
    std::shared_ptr<ResultSet> accessControlResultSet = rdbStore_->
        Get(SELECT_ACCESS_CONTROL_TABLE, std::vector<ValueObject>{});
    if (accessControlResultSet == nullptr) {
        HILOGE("GetAllAccessControlProfile::bindType not find");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount;
    accessControlResultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        HILOGE("GetAllAccessControlProfile::no data");
        return DP_NOT_FIND_DATA;
    }
    int32_t ret = this->GetAccesserAndAccesseeAndAccessControl(accessControlResultSet, profile);
    if (ret != DP_SUCCESS) {
        HILOGE("GetAllAccessControlProfile::faild");
        return ret;
    }
    accessControlResultSet->Close();
    if (profile.empty()) {
        return DP_NOT_FIND_DATA;
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetAccessControlProfile(const std::string &bundleName,
    int32_t bindType, int32_t status, std::vector<AccessControlProfile> &profile)
{
    if (rdbStore_ == nullptr) {
        HILOGE("GetAccessControlProfile::rdbStore_ is nullptr");
        return DP_GET_RDBSTORE_FAIL;
    }
    std::shared_ptr<ResultSet> resultSet = rdbStore_->Get(SELECT_ACCESS_CONTROL_TABLE_WHERE_BINDTYPE_AND_STATUS,
        std::vector<ValueObject>{ValueObject(bindType), ValueObject(status)});
    if (resultSet == nullptr) {
        HILOGE("GetAccessControlProfile::resultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount;
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
    if (profile.empty()) {
        return DP_NOT_FIND_DATA;
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetAccessControlProfile(const std::string &bundleName,
    const std::string &trustDeviceId, int32_t status, std::vector<AccessControlProfile> &profile)
{
    if (rdbStore_ == nullptr) {
        HILOGE("GetAccessControlProfile::rdbStore_ is nullptr");
        return DP_GET_RDBSTORE_FAIL;
    }
    std::shared_ptr<ResultSet> resultSet = rdbStore_->Get(SELECT_ACCESS_CONTROL_TABLE_WHERE_TRUSTDEVICEID_AND_STATUS,
        std::vector<ValueObject>{ValueObject(trustDeviceId), ValueObject(status)});
    if (resultSet == nullptr) {
        HILOGE("GetAccessControlProfile::resultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount;
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
    if (profile.empty()) {
        return DP_NOT_FIND_DATA;
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetAccessControlProfile(std::map<std::string, 
    std::string> params, std::vector<AccessControlProfile>& profile)
{
    if (params.find("userId") != params.end() && params.find("bundleName") != params.end() &&
        params.find("bindType") != params.end() && params.find("status") != params.end()) {
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
    if (params.find("userId") != params.end() && params.find("bundleName") != params.end() &&
        params.find("trustDeviceId") != params.end() && params.find("status") != params.end()) {
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
    if (params.find("bundleName") != params.end() && params.find("trustDeviceId") != params.end() &&
        params.find("status") != params.end()) {
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
    if (params.find("bundleName") != params.end() && params.find("bindType") != params.end() &&
        params.find("status") != params.end()) {
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
    HILOGE("params is error");
    return DP_GET_ACL_PROFILE_FAIL;
}

int32_t TrustProfileManager::DeleteTrustDeviceProfile(const std::string& deviceId)
{
    if (rdbStore_ == nullptr) {
        HILOGE("DeleteTrustDeviceProfile::rdbStore_ is nullptr");
        return DP_GET_RDBSTORE_FAIL;
    }
    std::shared_ptr<ResultSet> resultSet = rdbStore_->
        Get(SELECT_TRUST_DEVICE_TABLE_WHERE_DEVICEID, std::vector<ValueObject>{ValueObject(deviceId)});
    if (resultSet == nullptr) {
        HILOGE("DeleteTrustDeviceProfile::get result failed");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount;
    int32_t ret;
    resultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        HILOGE("DeleteTrustDeviceProfile::no data");
        return DP_NOT_FIND_DATA;
    }
    ret = resultSet->GoToFirstRow();
    if (ret != DP_SUCCESS) {
        HILOGE("DeleteTrustDeviceProfile::deviceId not find");
        return DP_NOT_FIND_DATA;
    }
    TrustDeviceProfile profile;
    this->TrustResultSetToTrustDeviceProfile(resultSet, profile);

    int32_t deleteRows;
    {
        std::lock_guard<std::mutex> lock(rdbMutex_);
        ret = rdbStore_->Delete(deleteRows,TRUST_DEVICE_TABLE, "deviceId = ?",
            std::vector<ValueObject>{ValueObject(deviceId)});
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
    std::shared_ptr<ResultSet> resultSet = rdbStore_->
        Get(SELECT_ACCESS_CONTROL_TABLE_WHERE_ACCESSCONTROLID, std::vector<ValueObject>{ValueObject(accessControlId)});
    if (resultSet == nullptr) {
        HILOGE("DeleteAccessControlProfile::get result failed");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount;
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
    const AccessControlProfile &accessControlProfile, TrustDeviceProfile &trustDeviceProfile)
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
    int32_t rowCount;
    int64_t accesserId;
    int64_t accesseeId;
    int32_t bindType;
    int32_t bindLevel;
    int32_t  columnIndex;
    int32_t ret;
    while (resultSet->GoToNextRow() == DP_SUCCESS) {
        ret = resultSet->GetColumnIndex("accesserId", columnIndex);
        ret = resultSet->GetLong(columnIndex, accesserId);
        ret = resultSet->GetColumnIndex("accesseeId", columnIndex);
        ret = resultSet->GetLong(columnIndex, accesseeId);
        ret = resultSet->GetColumnIndex("bindType", columnIndex);
        ret = resultSet->GetInt(columnIndex, bindType);
        ret = resultSet->GetColumnIndex("bindLevel", columnIndex);
        ret = resultSet->GetInt(columnIndex, bindLevel);
        if (bindType == static_cast<int32_t>(BindType::SAME_ACCOUNT) &&
            bindLevel == static_cast<int32_t>(BindLevel::DEVICE)) {
            std::shared_ptr<ResultSet> accesserResultSet = rdbStore_->
                Get(SELECT_ACCESSER_TABLE_WHERE_ACCESSERID_AND_ACCESSERUSERID,
                    std::vector<ValueObject>{ValueObject(accesserId), ValueObject(userId)});
            if (accesserResultSet == nullptr) {
                HILOGE("GetAccessControlProfileOnUserIdAndBundleName::get accesserResultSet failed");
                return DP_GET_RESULTSET_FAIL;
            }
            accesserResultSet->GetRowCount(rowCount);
            if (rowCount != 0) {
                std::shared_ptr<ResultSet> accesseeResultSet = rdbStore_->
                    Get(SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID, std::vector<ValueObject>{ValueObject(accesseeId)});
                this->GetVectorAccessControlProfile(resultSet, accesserResultSet, accesseeResultSet, profile);
                accesserResultSet->Close();
                accesseeResultSet->Close();
                continue;
            }
            accesserResultSet->Close();

            std::shared_ptr<ResultSet> accesseeResultSet = rdbStore_->
                Get(SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID_AND_ACCESSEEUSERID,
                std::vector<ValueObject>{ValueObject(accesseeId), ValueObject(userId)});
            if (accesseeResultSet == nullptr) {
                HILOGE("GetAccessControlProfileOnUserIdAndBundleName::get accesseeResultSet failed");
                return DP_GET_RESULTSET_FAIL;
            }
            accesseeResultSet->GetRowCount(rowCount);
            if (rowCount != 0) {
                accesserResultSet = rdbStore_->
                    Get(SELECT_ACCESSER_TABLE_WHERE_ACCESSERID, std::vector<ValueObject>{ValueObject(accesserId)});
                this->GetVectorAccessControlProfile(resultSet, accesserResultSet, accesseeResultSet, profile);
                accesseeResultSet->Close();
                accesserResultSet->Close();
            }
        } else {
            std::shared_ptr<ResultSet> accesserResultSet = rdbStore_->
                Get(SELECT_ACCESSER_TABLE_WHERE_ACCESSERID_AND_ACCESSERUSERID_ACCESSERBUNDLENAME,
                std::vector<ValueObject>{ValueObject(accesserId), ValueObject(userId), ValueObject(bundleName)});
            if (accesserResultSet == nullptr) {
                HILOGE("GetAccessControlProfileOnUserIdAndBundleName::get accesserResultSet failed");
                return DP_GET_RESULTSET_FAIL;
            }
            accesserResultSet->GetRowCount(rowCount);
            if (rowCount != 0) {
                std::shared_ptr<ResultSet> accesseeResultSet = rdbStore_->
                    Get(SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID, std::vector<ValueObject>{ValueObject(accesseeId)});
                this->GetVectorAccessControlProfile(resultSet, accesserResultSet, accesseeResultSet, profile);
                accesserResultSet->Close();
                continue;
            }
            accesserResultSet->Close();

            std::shared_ptr<ResultSet> accesseeResultSet = rdbStore_->
                Get(SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID_AND_ACCESSEEUSEEID_ACCESSEEBUNDLENAME,
                std::vector<ValueObject>{ValueObject(accesseeId), ValueObject(userId), ValueObject(bundleName)});
            if (accesseeResultSet == nullptr) {
                HILOGE("GetAccessControlProfileOnUserIdAndBundleName::get accesseeResultSet failed");
                return DP_GET_RESULTSET_FAIL;
            }
            accesseeResultSet->GetRowCount(rowCount);
            if (rowCount != 0) {
                accesserResultSet = rdbStore_->
                    Get(SELECT_ACCESSER_TABLE_WHERE_ACCESSERID, std::vector<ValueObject>{ValueObject(accesserId)});
                this->GetVectorAccessControlProfile(resultSet, accesserResultSet, accesseeResultSet, profile);
                accesseeResultSet->Close();
                accesserResultSet->Close();
            }
        }
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetAccessControlProfileOnBundleName(std::shared_ptr<ResultSet> resultSet,
    const std::string &bundleName, std::vector<AccessControlProfile> &profile)
{
    int32_t rowCount;
    int64_t accesserId;
    int64_t accesseeId;
    int32_t bindType;
    int32_t bindLevel;
    int32_t columnIndex;
    int32_t ret;
    while (resultSet->GoToNextRow() == DP_SUCCESS) {
        ret = resultSet->GetColumnIndex("accesserId", columnIndex);
        ret = resultSet->GetLong(columnIndex, accesserId);
        ret = resultSet->GetColumnIndex("accesseeId", columnIndex);
        ret = resultSet->GetLong(columnIndex, accesseeId);
        ret = resultSet->GetColumnIndex("bindType", columnIndex);
        ret = resultSet->GetInt(columnIndex, bindType);
        ret = resultSet->GetColumnIndex("bindLevel", columnIndex);
        ret = resultSet->GetInt(columnIndex, bindLevel);
        if (bindType == static_cast<int32_t>(BindType::SAME_ACCOUNT) &&
            bindLevel == static_cast<int32_t>(BindLevel::DEVICE)) {
            std::shared_ptr<ResultSet> accesserResultSet = rdbStore_->
                Get(SELECT_ACCESSER_TABLE_WHERE_ACCESSERID, std::vector<ValueObject>{ValueObject(accesserId)});
            if (accesserResultSet == nullptr) {
                HILOGE("GetAccesserAndAccesseeAndAccessControl::accesserResultSet is nullptr");
                return DP_GET_RESULTSET_FAIL;
            }
            accesserResultSet->GetRowCount(rowCount);
            if (rowCount == 0) {
                HILOGE("GetAccesserAndAccesseeAndAccessControl::not find accesserId");
                return DP_NOT_FIND_DATA;
            }
            std::shared_ptr<ResultSet> accesseeResultSet = rdbStore_->
                Get(SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID, std::vector<ValueObject>{ValueObject(accesseeId)});
            if (accesseeResultSet == nullptr) {
                HILOGE("GetAccesserAndAccesseeAndAccessControl::accesseeResultSet is nullptr");
                return DP_GET_RESULTSET_FAIL;
            }
            accesseeResultSet->GetRowCount(rowCount);
            if (rowCount == 0) {
                HILOGE("GetAccesserAndAccesseeAndAccessControl::not find accesseeId");
                return DP_NOT_FIND_DATA;
            }
            this->GetVectorAccessControlProfile(resultSet, accesserResultSet, accesseeResultSet, profile);
            accesserResultSet->Close();
            accesseeResultSet->Close();
        } else {
            std::shared_ptr<ResultSet> accesserResultSet = rdbStore_->
                Get(SELECT_ACCESSER_TABLE_WHERE_ACCESSERID_AND_ACCESSERBUNDLENAME,
                std::vector<ValueObject>{ValueObject(accesserId), ValueObject(bundleName)});
            if (accesserResultSet == nullptr) {
                HILOGE("GetAccessControlProfileOnUserIdAndTokenId::get result failed");
                return DP_GET_RESULTSET_FAIL;
            }
            accesserResultSet->GetRowCount(rowCount);
            if (rowCount != 0) {
                std::shared_ptr<ResultSet> accesseeResultSet = rdbStore_->
                    Get(SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID, std::vector<ValueObject>{ValueObject(accesseeId)});
                this->GetVectorAccessControlProfile(resultSet, accesserResultSet, accesseeResultSet, profile);
                accesserResultSet->Close();
                continue;
            }
            accesserResultSet->Close();

            std::shared_ptr<ResultSet> accesseeResultSet = rdbStore_->
                Get(SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID_AND_ACCESSEEBUNDLENAME,
                std::vector<ValueObject>{ValueObject(accesseeId), ValueObject(bundleName)});
            if (accesseeResultSet == nullptr) {
                HILOGE("GetAccessControlProfileOnUserIdAndTokenId::get accesseeResultSet failed");
                return DP_GET_RESULTSET_FAIL;
            }
            accesseeResultSet->GetRowCount(rowCount);
            if (rowCount != 0) {
                accesserResultSet = rdbStore_->
                    Get(SELECT_ACCESSER_TABLE_WHERE_ACCESSERID, std::vector<ValueObject>{ValueObject(accesserId)});
                this->GetVectorAccessControlProfile(resultSet, accesserResultSet, accesseeResultSet, profile);
                accesseeResultSet->Close();
                accesserResultSet->Close();
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
    int64_t rowId;
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
    int64_t rowId;
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

int32_t TrustProfileManager::SetAccessControlId(AccessControlProfile &profile)
{
    if (rdbStore_ == nullptr) {
        HILOGE("SetAccessControlId::rdbStore_ is nullptr");
        return DP_GET_RDBSTORE_FAIL;
    }
    std::shared_ptr<ResultSet> resultSet = rdbStore_->
		Get(SELECT_ACCESS_CONTROL_TABLE, std::vector<ValueObject>{});
    if (resultSet == nullptr) {
        HILOGE("SetAccessControlId::resultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount;
    resultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        profile.SetAccessControlId(1);
        return DP_SUCCESS;
    }
    int64_t accessControlId;
    int32_t columnIndex;
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
	std::shared_ptr<ResultSet> resultSet = rdbStore_->Get(SELECT_ACCESSER_TABLE_WHERE_ALL,
        std::vector<ValueObject>{ValueObject(accesser.GetAccesserDeviceId()),
        ValueObject(accesser.GetAccesserUserId()), ValueObject(accesser.GetAccesserAccountId()),
        ValueObject(accesser.GetAccesserTokenId()), ValueObject(accesser.GetAccesserBundleName()),
        ValueObject(accesser.GetAccesserHapSignature()), ValueObject(accesser.GetAccesserBindLevel())});
    if (resultSet == nullptr) {
        HILOGE("SetAccesserId::resultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount;
    int64_t accesserId;
    int32_t columnIndex;
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
    resultSet = rdbStore_->Get(SELECT_ACCESSER_TABLE, std::vector<ValueObject> {});
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

int32_t TrustProfileManager::SetAccesseeId(AccessControlProfile &profile)
{
    if (rdbStore_ == nullptr) {
        HILOGE("SetAccesseeId::rdbStore_ is nullptr");
        return DP_GET_RDBSTORE_FAIL;
    }
    Accessee accessee = profile.GetAccessee();
	std::shared_ptr<ResultSet> resultSet = rdbStore_->Get(SELECT_ACCESSEE_TABLE_WHERE_ALL,
        std::vector<ValueObject> {ValueObject(accessee.GetAccesseeDeviceId()), 
        ValueObject(accessee.GetAccesseeUserId()), ValueObject(accessee.GetAccesseeAccountId()),
        ValueObject(accessee.GetAccesseeTokenId()), ValueObject(accessee.GetAccesseeBundleName()),
        ValueObject(accessee.GetAccesseeHapSignature()), ValueObject(accessee.GetAccesseeBindLevel())});
    if (resultSet == nullptr) {
        HILOGE("SetAccesserId::resultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount;
    int64_t accesseeId;
    int32_t columnIndex;
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
    resultSet = rdbStore_->
		Get(SELECT_ACCESSEE_TABLE, std::vector<ValueObject> {});
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
        HILOGE("PutAccesserProfile::rdbStore_ is nullptr");
        return DP_GET_RDBSTORE_FAIL;
    }
    int32_t changeRowId;
    {
        std::lock_guard<std::mutex> lock(rdbMutex_);
        int32_t ret = rdbStore_->Update(changeRowId, ACCESSER_TABLE, values, "accesserId = ? ",
            std::vector<ValueObject>{ValueObject(accesserId)});
        if (ret != DP_SUCCESS) {
            HILOGE("PutAccesserProfile::accesser_table update failed");
            return DP_UPDATE_ACCESSER_PROFILE_FAIL;
        }
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::UpdateAccesseeProfile(int64_t accesseeId, const AccessControlProfile &profile)
{
    ValuesBucket values;
    ProfileUtils::AccesseeToEntries(profile, values);
    if (rdbStore_ == nullptr) {
        HILOGE("UpdateAccesseeProfile::rdbStore_ is nullptr");
        return DP_GET_RDBSTORE_FAIL;
    }
    int32_t changeRowId;
    {
        std::lock_guard<std::mutex> lock(rdbMutex_);
        int32_t ret = rdbStore_->Update(changeRowId, ACCESSEE_TABLE, values, "accesseeId = ? ",
            std::vector<ValueObject>{ValueObject(accesseeId)});
        if (ret != DP_SUCCESS) {
            HILOGE("UpdateAccesseeProfile::accessee_table update failed");
            return DP_UPDATE_ACCESSEE_PROFILE_FAIL;
        }
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::UpdateTrustDeviceProfileNotify(const TrustDeviceProfile &oldProfile,
    const TrustDeviceProfile &newProfile)
{
    int32_t ret;
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
        ret = SubscribeProfileManager::GetInstance().NotifyTrustDeviceProfileUpdate(oldProfile,newProfile);
        if (ret != DP_SUCCESS) {
            HILOGE("UpdateTrustDeviceProfileNotify::NotifyTrustDeviceProfileUpdate failed");
            return DP_NOTIFY_TRUST_DEVICE_FAIL;
        }
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetResultStatus(const std::string &trustDeviceId, int32_t& trustDeviceStatus)
{
    if (rdbStore_ == nullptr) {
        HILOGE("GetResultStatus::rdbStore_ is nullptr");
        return DP_GET_RDBSTORE_FAIL;
    }
    std::shared_ptr<ResultSet> resultSet = rdbStore_->
        Get(SELECT_ACCESS_CONTROL_TABLE_WHERE_TRUSTDEVICEID, std::vector<ValueObject>{ValueObject(trustDeviceId)});
    if (resultSet == nullptr) {
        HILOGE("GetResultStatus::resultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount;
    resultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        HILOGE("GetResultStatus::trustDeviceId not find");
        return DP_NOT_FIND_DATA;
    }
    int32_t columnIndex;
    int32_t ret;
    trustDeviceStatus = 0;
    while (resultSet->GoToNextRow() == DP_SUCCESS) {
        int32_t status;
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

int32_t TrustProfileManager::GetAccesserAndAccesseeAndAccessControl(
    std::shared_ptr<ResultSet> resultSet, std::vector<AccessControlProfile> &profile)
{
    int32_t rowCount;
    int64_t accesserId;
    int64_t accesseeId;
    int32_t columnIndex;
    int32_t ret;
    while (resultSet->GoToNextRow() == DP_SUCCESS) {
        ret = resultSet->GetColumnIndex("accesserId", columnIndex);
        ret = resultSet->GetLong(columnIndex, accesserId);
        
        ret = resultSet->GetColumnIndex("accesseeId", columnIndex);
        ret = resultSet->GetLong(columnIndex, accesseeId);
        std::shared_ptr<ResultSet> accesserResultSet = rdbStore_->
            Get(SELECT_ACCESSER_TABLE_WHERE_ACCESSERID, std::vector<ValueObject>{ValueObject(accesserId)});
        if (accesserResultSet == nullptr) {
            HILOGE("GetAccesserAndAccesseeAndAccessControl::accesserResultSet is nullptr");
            return DP_GET_RESULTSET_FAIL;
        }
        accesserResultSet->GetRowCount(rowCount);
        if (rowCount == 0) {
            HILOGE("GetAccesserAndAccesseeAndAccessControl::not find data");
            return DP_NOT_FIND_DATA;
        }
        std::shared_ptr<ResultSet> accesseeResultSet = rdbStore_->
            Get(SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID, std::vector<ValueObject>{ValueObject(accesseeId)});
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
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::DeleteAccessControlProfileCheck(std::shared_ptr<ResultSet> resultSet)
{
    int32_t ret = resultSet->GoToNextRow();
    if (ret != DP_SUCCESS) {
        HILOGE("DeleteAccessControlProfileCheck::get result failed");
        return DP_NOT_FIND_DATA;
    }
    int32_t rowCount;
    int32_t columnIndex;
    int64_t accessControlId;
    int64_t accesserId;
    int64_t accesseeId;
    std::string trustDeviceId;
    int32_t deviceIdType;
    std::string deviceIdHash;
 
    ret = resultSet->GetColumnIndex("accessControlId", columnIndex);
    ret = resultSet->GetLong(columnIndex, accessControlId);

    ret = resultSet->GetColumnIndex("accesserId", columnIndex);
    ret = resultSet->GetLong(columnIndex, accesserId);

    ret = resultSet->GetColumnIndex("accesseeId", columnIndex);
    ret = resultSet->GetLong(columnIndex, accesseeId);

    ret = resultSet->GetColumnIndex("trustDeviceId", columnIndex);
    ret = resultSet->GetString(columnIndex, trustDeviceId);

    ret = resultSet->GetColumnIndex("deviceIdType", columnIndex);
    ret = resultSet->GetInt(columnIndex, deviceIdType);

    ret = resultSet->GetColumnIndex("deviceIdHash", columnIndex);
    ret = resultSet->GetString(columnIndex, deviceIdHash);

    resultSet->Close();

    int32_t deleteRows;
    resultSet = rdbStore_->
        Get(SELECT_ACCESS_CONTROL_TABLE_WHERE_ACCESSEEID, std::vector<ValueObject>{ValueObject(accesseeId)});
    if (resultSet == nullptr) {
        HILOGE("DeleteAccessControlProfileCheck::accessControlResultSet not find");
        return DP_GET_RESULTSET_FAIL;
    }
    resultSet->GetRowCount(rowCount);
    resultSet->Close();
    if (rowCount == 1) {
        std::lock_guard<std::mutex> lock(rdbMutex_);
        ret = rdbStore_->
            Delete(deleteRows, ACCESSEE_TABLE, "accesseeId = ?", std::vector<ValueObject>{ValueObject(accesseeId)});
        if (ret != DP_SUCCESS)
        {
            HILOGE("DeleteAccessControlProfileCheck::delete accessee_table accesseeId failed");
            return DP_DELETE_ACCESSEE_PROFILE_FAIL;
        }
    }

    resultSet = rdbStore_->
        Get(SELECT_ACCESS_CONTROL_TABLE_WHERE_ACCESSERID, std::vector<ValueObject>{ValueObject(accesserId)});
    if (resultSet == nullptr) {
        HILOGE("DeleteAccessControlProfileCheck::accesserId not find");
        return DP_GET_RESULTSET_FAIL;
    }
    resultSet->GetRowCount(rowCount);
    resultSet->Close();
    if (rowCount == 1) {
        std::lock_guard<std::mutex> lock(rdbMutex_);
        ret = rdbStore_->
            Delete(deleteRows, ACCESSER_TABLE, "accesserId = ?", std::vector<ValueObject>{ValueObject(accesserId)});
        if (ret != DP_SUCCESS) {
            HILOGE("DeleteAccessControlProfileCheck::delete accesser_table accesserId failed");
            return DP_DELETE_ACCESSER_PROFILE_FAIL;
        }
    }

    {
        std::lock_guard<std::mutex> lock(rdbMutex_);
        ret = rdbStore_->Delete(deleteRows, ACCESS_CONTROL_TABLE, "accessControlId = ?",
            std::vector<ValueObject>{ValueObject(accessControlId)});
        if (ret != DP_SUCCESS) {
            HILOGE("DeleteAccessControlProfile::delete accesser_table accesserId failed");
            return DP_DELETE_ACCESS_CONTROL_PROFILE_FAIL;
        }
    }

    resultSet = rdbStore_->
        Get(SELECT_ACCESS_CONTROL_TABLE_WHERE_TRUSTDEVICEID, std::vector<ValueObject>{ValueObject(trustDeviceId)});
    if (resultSet == nullptr) {
        HILOGE("DeleteAccessControlProfileCheck::trustDeviceId not find");
        return DP_GET_RESULTSET_FAIL;
    }
    resultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        this->DeleteTrustDeviceProfile(trustDeviceId);
    } else {
        int32_t status;
        this->GetResultStatus(trustDeviceId, status);
        TrustDeviceProfile trustDeviceProfile;
        trustDeviceProfile.SetDeviceId(trustDeviceId);
        trustDeviceProfile.SetDeviceIdType(deviceIdType);
        trustDeviceProfile.SetDeviceIdHash(deviceIdHash);
        trustDeviceProfile.SetStatus(status);
        this->UpdateTrustDeviceProfile(trustDeviceProfile);
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::TrustResultSetToTrustDeviceProfile(
    std::shared_ptr<ResultSet> trustResultSet, TrustDeviceProfile& trustDeviceProfile)
{
    int32_t ret;
    int32_t columnIndex;
    std::string deviceId;
    ret = trustResultSet->GetColumnIndex("deviceId", columnIndex);
    ret = trustResultSet->GetString(columnIndex, deviceId);
    trustDeviceProfile.SetDeviceId(deviceId);

    int32_t deviceIdType;
    ret = trustResultSet->GetColumnIndex("deviceIdType", columnIndex);
    ret = trustResultSet->GetInt(columnIndex, deviceIdType);
    trustDeviceProfile.SetDeviceIdType(deviceIdType);

    std::string deviceIdHash;
    ret = trustResultSet->GetColumnIndex("deviceIdHash", columnIndex);
    ret = trustResultSet->GetString(columnIndex, deviceIdHash);
    trustDeviceProfile.SetDeviceIdHash(deviceIdHash);

    int32_t status;
    ret = trustResultSet->GetColumnIndex("status", columnIndex);
    ret = trustResultSet->GetInt(columnIndex, status);
    trustDeviceProfile.SetStatus(status);
    return DP_SUCCESS;
}

int32_t TrustProfileManager::AccesserResultSetToAccesser(std::shared_ptr<ResultSet> accesserResultSet,
    Accesser& accesser)
{
    int32_t ret;
    int32_t columnIndex;
    int64_t accesserId;
    ret = accesserResultSet->GetColumnIndex("accesserId", columnIndex);
    ret = accesserResultSet->GetLong(columnIndex, accesserId);
    accesser.SetAccesserId(accesserId);

    std::string accesserDeviceId;
    ret = accesserResultSet->GetColumnIndex("accesserDeviceId", columnIndex);
    ret = accesserResultSet->GetString(columnIndex, accesserDeviceId);
    accesser.SetAccesserDeviceId(accesserDeviceId);

    int32_t accesserUserId;
    ret = accesserResultSet->GetColumnIndex("accesserUserId", columnIndex);
    ret = accesserResultSet->GetInt(columnIndex, accesserUserId);
    accesser.SetAccesserUserId(accesserUserId);

    std::string accesserAccountId;
    ret = accesserResultSet->GetColumnIndex("accesserAccountId", columnIndex);
    ret = accesserResultSet->GetString(columnIndex, accesserAccountId);
    accesser.SetAccesserAccountId(accesserAccountId);

    int64_t accesserTokenId;
    ret = accesserResultSet->GetColumnIndex("accesserTokenId", columnIndex);
    ret = accesserResultSet->GetLong(columnIndex, accesserTokenId);
    accesser.SetAccesserTokenId(accesserTokenId);

    std::string accesserBundleName;
    ret = accesserResultSet->GetColumnIndex("accesserBundleName", columnIndex);
    ret = accesserResultSet->GetString(columnIndex, accesserBundleName);
    accesser.SetAccesserBundleName(accesserBundleName);

    std::string accesserHapSignature;
    ret = accesserResultSet->GetColumnIndex("accesserHapSignature", columnIndex);
    ret = accesserResultSet->GetString(columnIndex, accesserHapSignature);
    accesser.SetAccesserHapSignature(accesserHapSignature);

    int32_t accesserBindLevel;
    ret = accesserResultSet->GetColumnIndex("accesserBindLevel", columnIndex);
    ret = accesserResultSet->GetInt(columnIndex, accesserBindLevel);
    accesser.SetAccesserBindLevel(accesserBindLevel);
    return DP_SUCCESS;
}

int32_t TrustProfileManager::AccesseeResultSetToAccessee(std::shared_ptr<ResultSet> accesseeResultSet,
    Accessee& accessee)
{
    int32_t columnIndex;
    int64_t accesseeId;
    int32_t ret;
    ret = accesseeResultSet->GetColumnIndex("accesseeId", columnIndex);
    ret = accesseeResultSet->GetLong(columnIndex, accesseeId);
    accessee.SetAccesseeId(accesseeId);

    std::string accesseeDeviceId;
    ret = accesseeResultSet->GetColumnIndex("accesseeDeviceId", columnIndex);
    ret = accesseeResultSet->GetString(columnIndex, accesseeDeviceId);
    accessee.SetAccesseeDeviceId(accesseeDeviceId);

    int32_t accesseeUserId;
    ret = accesseeResultSet->GetColumnIndex("accesserUserId", columnIndex);
    ret = accesseeResultSet->GetInt(columnIndex, accesseeUserId);
    accessee.SetAccesseeUserId(accesseeUserId);

    std::string accesseeAccountId;
    ret = accesseeResultSet->GetColumnIndex("accesseeAccountId", columnIndex);
    ret = accesseeResultSet->GetString(columnIndex, accesseeAccountId);
    accessee.SetAccesseeAccountId(accesseeAccountId);

    int64_t accesseeTokenId;
    ret = accesseeResultSet->GetColumnIndex("accesseeTokenId", columnIndex);
    ret = accesseeResultSet->GetLong(columnIndex, accesseeTokenId);
    accessee.SetAccesseeTokenId(accesseeTokenId);

    std::string accesseeBundleName;
    ret = accesseeResultSet->GetColumnIndex("accesseeBundleName", columnIndex);
    ret = accesseeResultSet->GetString(columnIndex, accesseeBundleName);
    accessee.SetAccesseeBundleName(accesseeBundleName);

    std::string accesseeHapSignature;
    ret = accesseeResultSet->GetColumnIndex("accesseeHapSignature", columnIndex);
    ret = accesseeResultSet->GetString(columnIndex, accesseeHapSignature);
    accessee.SetAccesseeHapSignature(accesseeHapSignature);

    int32_t accesseeBindLevel;
    ret = accesseeResultSet->GetColumnIndex("accesseeBindLevel", columnIndex);
    ret = accesseeResultSet->GetInt(columnIndex, accesseeBindLevel);
    accessee.SetAccesseeBindLevel(accesseeBindLevel);
    return DP_SUCCESS;
}

int32_t TrustProfileManager::AccessControlResultSetToAccessControlProfile(
    std::shared_ptr<ResultSet> accessControlResultSet, AccessControlProfile& accessControlProfile)
{
    int32_t columnIndex;
    int32_t ret;
    int64_t accessControlId;
    ret = accessControlResultSet->GetColumnIndex("accessControlId", columnIndex);
    ret = accessControlResultSet->GetLong(columnIndex, accessControlId);
    accessControlProfile.SetAccessControlId(accessControlId);

    int64_t accesserId;
    ret = accessControlResultSet->GetColumnIndex("accesserId", columnIndex);
    ret = accessControlResultSet->GetLong(columnIndex, accesserId);
    accessControlProfile.SetAccesserId(accesserId);

    int64_t accesseeId;
    ret = accessControlResultSet->GetColumnIndex("accesseeId", columnIndex);
    ret = accessControlResultSet->GetLong(columnIndex, accesseeId);
    accessControlProfile.SetAccesseeId(accesseeId);

    std::string trustDeviceId;
    ret = accessControlResultSet->GetColumnIndex("trustDeviceId", columnIndex);
    ret = accessControlResultSet->GetString(columnIndex, trustDeviceId);
    accessControlProfile.SetTrustDeviceId(trustDeviceId);
    
    std::string sessionKey;
    ret = accessControlResultSet->GetColumnIndex("sessionKey", columnIndex);
    ret = accessControlResultSet->GetString(columnIndex, sessionKey);
    accessControlProfile.SetSessionKey(sessionKey);

    int32_t bindType;
    ret = accessControlResultSet->GetColumnIndex("bindType", columnIndex);
    ret = accessControlResultSet->GetInt(columnIndex, bindType);
    accessControlProfile.SetBindType(bindType);

    int32_t authenticationType;
    ret = accessControlResultSet->GetColumnIndex("authenticationType", columnIndex);
    ret = accessControlResultSet->GetInt(columnIndex, authenticationType);
    accessControlProfile.SetAuthenticationType(authenticationType);

    int32_t deviceIdType;
    ret = accessControlResultSet->GetColumnIndex("deviceIdType", columnIndex);
    ret = accessControlResultSet->GetInt(columnIndex, deviceIdType);
    accessControlProfile.SetDeviceIdType(deviceIdType);

    std::string deviceIdHash;
    ret = accessControlResultSet->GetColumnIndex("deviceIdHash", columnIndex);
    ret = accessControlResultSet->GetString(columnIndex, deviceIdHash);
    accessControlProfile.SetDeviceIdHash(deviceIdHash);

    int32_t status;
    ret = accessControlResultSet->GetColumnIndex("status", columnIndex);
    ret = accessControlResultSet->GetInt(columnIndex, status);
    accessControlProfile.SetStatus(status);

    int32_t validPeriod;
    ret = accessControlResultSet->GetColumnIndex("validPeriod", columnIndex);
    ret = accessControlResultSet->GetInt(columnIndex, validPeriod);
    accessControlProfile.SetValidPeriod(validPeriod);

    int32_t lastAuthTime;
    ret = accessControlResultSet->GetColumnIndex("lastAuthTime", columnIndex);
    ret = accessControlResultSet->GetInt(columnIndex, lastAuthTime);
    accessControlProfile.SetLastAuthTime(lastAuthTime);

    int32_t bindLevel;
    ret = accessControlResultSet->GetColumnIndex("bindLevel", columnIndex);
    ret = accessControlResultSet->GetInt(columnIndex, bindLevel);
    accessControlProfile.SetBindLevel(bindLevel);
    return DP_SUCCESS;
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

int32_t TrustProfileManager::UpdateAclCheck(const AccessControlProfile& profile)
{
    if (rdbStore_ == nullptr) {
        HILOGE("UpdateAccessControlProfile::rdbStore_ is nullptr");
        return DP_GET_RDBSTORE_FAIL;
    }
    std::shared_ptr<ResultSet> resultSet = rdbStore_->
		Get(SELECT_ACCESS_CONTROL_TABLE_WHERE_ACCESSCONTROLID,
        std::vector<ValueObject> {ValueObject(profile.GetAccessControlId())});
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
} // namespace DistributedDeviceProfile
} // namespace OHOS