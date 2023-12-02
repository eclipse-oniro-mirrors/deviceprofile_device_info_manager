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

    int64_t rowId = ROWID_INIT;
    int32_t ret = RET_INIT;
    {
        std::lock_guard<std::mutex> lock(rdbMutex_);
        if (rdbStore_ == nullptr) {
            HILOGE("PutTrustDeviceProfile::rdbStore_ is nullptr");
            return DP_GET_RDBSTORE_FAIL;
        }
        ret = rdbStore_->Put(rowId, TRUST_DEVICE_TABLE, values);
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
    this->SetAccessControlProfileId(accessControlProfile);
    this->PutAccesserProfile(accessControlProfile);
    this->PutAccesseeProfile(accessControlProfile);

    ValuesBucket values;
    ProfileUtils::AccessControlProfileToEntries(accessControlProfile, values);
    int64_t rowId = ROWID_INIT;
    int32_t ret = RET_INIT;
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
    this->ConvertToTrustDeviceProfile(profile, trustProfile);
    std::string trustDeviceId = accessControlProfile.GetTrustDeviceId();
    std::shared_ptr<ResultSet> resultSet =
        GetResultSet(SELECT_TRUST_DEVICE_TABLE_WHERE_DEVICEID,
        std::vector<ValueObject>{ ValueObject(trustDeviceId) });
    if (resultSet == nullptr) {
        HILOGE("PutAccessControlProfile::get resultSet failed");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = ROWCOUNT_INIT;
    resultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        this->PutTrustDeviceProfile(trustProfile);
        return DP_SUCCESS;
    }
    int32_t status = STATUS_INIT;
    ret = this->GetResultStatus(trustDeviceId, status);
    if (ret != DP_SUCCESS) {
        HILOGE("UpdateAccessControlProfile::GetResultStatus failed");
        return DP_GET_RESULTSET_FAIL;
    }
    trustProfile.SetStatus(status);
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
    std::string deviceId = profile.GetDeviceId();
    std::shared_ptr<ResultSet> resultSet =
        GetResultSet(SELECT_TRUST_DEVICE_TABLE_WHERE_DEVICEID,
        std::vector<ValueObject>{ ValueObject(deviceId) });
    if (resultSet == nullptr) {
        HILOGE("UpdateTrustDeviceProfile::resultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = ROWCOUNT_INIT;
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
    this->ConvertToTrustDeviceProfile(resultSet, oldProfile);
    ValuesBucket values;
    ProfileUtils::TrustDeviceProfileToEntries(profile, values);
    int32_t changeRowCnt = CHANGEROWCNT_INIT;
    {
        std::lock_guard<std::mutex> lock(rdbMutex_);
        if (rdbStore_ == nullptr) {
            HILOGE("UpdateTrustDeviceProfile::rdbStore_ is nullptr");
            return DP_GET_RDBSTORE_FAIL;
        }
        ret = rdbStore_->Update(changeRowCnt, TRUST_DEVICE_TABLE, values, DEVICEID_EQUAL_CONDITION,
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
    int32_t ret = this->UpdateAclCheck(profile);
    if (ret != DP_SUCCESS) {
        HILOGE("UpdateAccessControlProfile::UpdateAclCheck faild");
        return ret;
    }
    this->UpdateAccesserProfile(profile.GetAccesserId(), profile);
    this->UpdateAccesseeProfile(profile.GetAccesseeId(), profile);
    ValuesBucket values;
    ProfileUtils::AccessControlProfileToEntries(profile, values);
    int32_t changeRowCnt = CHANGEROWCNT_INIT;
    {
        std::lock_guard<std::mutex> lock(rdbMutex_);
        if (rdbStore_ == nullptr) {
            HILOGE("UpdateAccessControlProfile::rdbStore_ is nullptr");
            return DP_GET_RDBSTORE_FAIL;
        }
        ret = rdbStore_->Update(changeRowCnt, ACCESS_CONTROL_TABLE, values, ACCESSCONTROLID_EQUAL_CONDITION,
            std::vector<ValueObject>{ ValueObject(profile.GetAccessControlId()) });
        if (ret != DP_SUCCESS) {
            HILOGE("UpdateAccessControlProfile::update access_control_table failed");
            return DP_UPDATE_ACL_PROFILE_FAIL;
        }
    }
    int32_t status = STATUS_INIT;
    ret = this->GetResultStatus(profile.GetTrustDeviceId(), status);
    if (ret != DP_SUCCESS) {
        HILOGE("UpdateAccessControlProfile::GetResultStatus failed");
        return DP_GET_RESULTSET_FAIL;
    }
    TrustDeviceProfile trustProfile;
    this->ConvertToTrustDeviceProfile(profile, trustProfile);
    trustProfile.SetStatus(status);
    ret = this->UpdateTrustDeviceProfile(trustProfile);
    if (ret != DP_SUCCESS) {
        HILOGE("UpdateAccessControlProfile::UpdateTrustDeviceProfile failed");
        return DP_UPDATE_TRUST_DEVICE_PROFILE_FAIL;
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetTrustDeviceProfile(const std::string& deviceId, TrustDeviceProfile& profile)
{
    std::shared_ptr<ResultSet> resultSet = GetResultSet(SELECT_TRUST_DEVICE_TABLE_WHERE_DEVICEID,
        std::vector<ValueObject>{ ValueObject(deviceId) });
    if (resultSet == nullptr) {
        HILOGE("GetTrustDeviceProfile::get result failed");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = ROWCOUNT_INIT;
    resultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        HILOGE("GetTrustDeviceProfile::deviceId not find");
        return DP_NOT_FIND_DATA;
    }
    int32_t ret = resultSet->GoToFirstRow();
    if (ret != DP_SUCCESS) {
        HILOGE("GetTrustDeviceProfile::not find trust device data");
        return DP_NOT_FIND_DATA;
    }
    this->ConvertToTrustDeviceProfile(resultSet, profile);
    resultSet->Close();
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetAllTrustDeviceProfile(std::vector<TrustDeviceProfile>& profile)
{
    std::shared_ptr<ResultSet> resultSet =
        GetResultSet(SELECT_TRUST_DEVICE_TABLE, std::vector<ValueObject> {});
    if (resultSet == nullptr) {
        HILOGE("GetAllTrustDeviceProfile::get result failed");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = ROWCOUNT_INIT;
    resultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        HILOGE("GetAllTrustDeviceProfile::trustDevice no data");
        return DP_NOT_FIND_DATA;
    }
    while (resultSet->GoToNextRow() == DP_SUCCESS) {
        TrustDeviceProfile trustProfile;
        this->ConvertToTrustDeviceProfile(resultSet, trustProfile);
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
    if (bundleName.size() > MAX_STRING_LEN) {
        HILOGE("GetAccessControlProfile::bundleName is invalid");
        return DP_INVALID_PARAMS;
    }
    std::shared_ptr<ResultSet> resultSet =
        GetResultSet(SELECT_ACCESS_CONTROL_TABLE_WHERE_BINDTYPE_AND_STATUS,
        std::vector<ValueObject>{ ValueObject(bindType), ValueObject(status) });
    if (resultSet == nullptr) {
        HILOGE("GetAccessControlProfile::resultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = ROWCOUNT_INIT;
    resultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        HILOGE("GetAccessControlProfile::bindType not find");
        return DP_NOT_FIND_DATA;
    }
    int32_t ret = this->GetAclProfileByUserIdAndBundleName(resultSet, userId, bundleName, profile);
    if (ret != DP_SUCCESS) {
        HILOGE("GetAccessControlProfile::GetAclProfileByUserIdAndBundleName faild");
        return DP_NOT_FIND_DATA;
    }
    if (profile.empty()) {
        HILOGE("GetAccessControlProfile::by userId bundleName bindType status not find data");
        return DP_NOT_FIND_DATA;
    }
    resultSet->Close();
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetAccessControlProfile(int32_t userId, const std::string& bundleName,
    const std::string& trustDeviceId, int32_t status, std::vector<AccessControlProfile>& profile)
{
    if (bundleName.size() > MAX_STRING_LEN || trustDeviceId.size() > MAX_STRING_LEN) {
        HILOGE("GetAccessControlProfile::bundleName or trustDeviceId is invalid");
        return DP_INVALID_PARAMS;
    }
    std::shared_ptr<ResultSet> resultSet =
        GetResultSet(SELECT_ACCESS_CONTROL_TABLE_WHERE_TRUSTDEVICEID_AND_STATUS,
        std::vector<ValueObject>{ ValueObject(trustDeviceId), ValueObject(status) });
    if (resultSet == nullptr) {
        HILOGE("GetAccessControlProfile::resultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = ROWCOUNT_INIT;
    resultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        HILOGE("GetAccessControlProfile::parmas not find");
        return DP_NOT_FIND_DATA;
    }
    int32_t ret = this->GetAclProfileByUserIdAndBundleName(resultSet, userId, bundleName, profile);
    if (ret != DP_SUCCESS) {
        HILOGE("GetAccessControlProfile::GetAclProfileByUserIdAndBundleName faild");
        return ret;
    }
    if (profile.empty()) {
        HILOGE("GetAccessControlProfile::by userId bundleName trustDeviceId status not find data");
        return DP_NOT_FIND_DATA;
    }
    resultSet->Close();
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetAccessControlProfileByTokenId(int32_t accesserTokenId,
    const std::string& accesseeDeviceId, std::vector<AccessControlProfile>& profile)
{
    if (accesseeDeviceId.size() > MAX_STRING_LEN) {
        HILOGE("GetAccessControlProfile::accesseeDeviceId or trustDeviceId is invalid");
        return DP_INVALID_PARAMS;
    }
    std::shared_ptr<ResultSet> resultSet =
        GetResultSet(SELECT_ACCESS_CONTROL_TABLE, std::vector<ValueObject> {});
    if (resultSet == nullptr) {
        HILOGE("GetAccessControlProfile::access_control_table no data");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = ROWCOUNT_INIT;
    resultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        HILOGE("GetAccessControlProfile::access_control_table no data");
        return DP_NOT_FIND_DATA;
    }
    int32_t ret = this->GetAclProfileByTokenIdAndDeviceId(
        resultSet, accesserTokenId, accesseeDeviceId, profile);
    if (ret != DP_SUCCESS) {
        HILOGE("GetAccessControlProfile::GetAccessControlProfileByTokenId faild");
        return ret;
    }
    if (profile.empty()) {
        HILOGE("GetAccessControlProfile::by accesserTokenId accesseeDeviceId not find data");
        return DP_NOT_FIND_DATA;
    }
    resultSet->Close();
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetAccessControlProfile(int32_t userId,
    const std::string& accountId, std::vector<AccessControlProfile>& profile)
{
    if (accountId.size() > MAX_STRING_LEN) {
        HILOGE("GetAccessControlProfile::accountId or trustDeviceId is invalid");
        return DP_INVALID_PARAMS;
    }
    std::shared_ptr<ResultSet> resultSet =
        GetResultSet(SELECT_ACCESS_CONTROL_TABLE, std::vector<ValueObject> {});
    if (resultSet == nullptr) {
        HILOGE("GetAccessControlProfile::access_control_table no data");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = ROWCOUNT_INIT;
    resultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        HILOGE("GetAccessControlProfile::access_control_table no data");
        return DP_NOT_FIND_DATA;
    }
    int32_t ret = this->GetAclProfileByUserIdAndAccountId(
        resultSet, userId, accountId, profile);
    if (ret != DP_SUCCESS) {
        HILOGE("GetAccessControlProfile::GetAccessControlProfile faild");
        return ret;
    }
    if (profile.empty()) {
        HILOGE("GetAccessControlProfile::by userId accountId not find data");
        return DP_NOT_FIND_DATA;
    }
    resultSet->Close();
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetAllAccessControlProfile(std::vector<AccessControlProfile>& profile)
{
    std::shared_ptr<ResultSet> resultSet =
        GetResultSet(SELECT_ACCESS_CONTROL_TABLE, std::vector<ValueObject> {});
    if (resultSet == nullptr) {
        HILOGE("GetAllAccessControlProfile::bindType not find");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = ROWCOUNT_INIT;
    resultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        HILOGE("GetAllAccessControlProfile::no data");
        return DP_NOT_FIND_DATA;
    }
    while (resultSet->GoToNextRow() == DP_SUCCESS) {
        int32_t columnIndex = COLUMNINDEX_INIT;
        int64_t accesserId = ACCESSERID_INIT;
        resultSet->GetColumnIndex(ACCESSER_ID, columnIndex);
        resultSet->GetLong(columnIndex, accesserId);
        int64_t accesseeId = ACCESSEEID_INIT;
        resultSet->GetColumnIndex(ACCESSEE_ID, columnIndex);
        resultSet->GetLong(columnIndex, accesseeId);
        int32_t ret = this->GetAccessControlProfile(resultSet, accesserId, accesseeId, profile);
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
    if (bundleName.size() > MAX_STRING_LEN) {
        HILOGE("GetAccessControlProfile::bundleName is invalid");
        return DP_INVALID_PARAMS;
    }
    std::shared_ptr<ResultSet> resultSet =
        GetResultSet(SELECT_ACCESS_CONTROL_TABLE_WHERE_BINDTYPE_AND_STATUS,
        std::vector<ValueObject>{ ValueObject(bindType), ValueObject(status) });
    if (resultSet == nullptr) {
        HILOGE("GetAccessControlProfile::resultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = ROWCOUNT_INIT;
    resultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        HILOGE("GetAccessControlProfile::bindType not find");
        return DP_NOT_FIND_DATA;
    }
    int32_t ret = this->GetAclProfileByBundleName(resultSet, bundleName, profile);
    if (ret != DP_SUCCESS) {
        HILOGE("GetAccessControlProfile::GetAclProfileByBundleName faild");
        return ret;
    }
    if (profile.empty()) {
        HILOGE("GetAccessControlProfile::by bundleName bindType status not find data");
        return DP_NOT_FIND_DATA;
    }
    resultSet->Close();
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetAccessControlProfile(const std::string& bundleName,
    const std::string& trustDeviceId, int32_t status, std::vector<AccessControlProfile>& profile)
{
    if (bundleName.size() > MAX_STRING_LEN || trustDeviceId.size() > MAX_STRING_LEN) {
        HILOGE("GetAccessControlProfile::bundleName or trustDeviceId is invalid");
        return DP_INVALID_PARAMS;
    }
    std::shared_ptr<ResultSet> resultSet =
        GetResultSet(SELECT_ACCESS_CONTROL_TABLE_WHERE_TRUSTDEVICEID_AND_STATUS,
        std::vector<ValueObject>{ ValueObject(trustDeviceId), ValueObject(status) });
    if (resultSet == nullptr) {
        HILOGE("GetAccessControlProfile::resultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = ROWCOUNT_INIT;
    resultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        HILOGE("GetAccessControlProfile::bindType not find");
        return DP_NOT_FIND_DATA;
    }
    int32_t ret = this->GetAclProfileByBundleName(resultSet, bundleName, profile);
    if (ret != DP_SUCCESS) {
        HILOGE("GetAccessControlProfile::GetAclProfileByBundleName faild");
        return ret;
    }
    if (profile.empty()) {
        HILOGE("GetAccessControlProfile::by bundleName trustDeviceId status not find data");
        return DP_NOT_FIND_DATA;
    }
    resultSet->Close();
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetAccessControlProfile(const std::map<std::string, std::string>& params,
    std::vector<AccessControlProfile>& profile)
{
    if (params.find("userId") != params.end() && params.find("bundleName") != params.end()
            && params.find("bindType") != params.end() && params.find("status") != params.end()) {
        int32_t ret = this->GetAccessControlProfile(std::atoi(params.find("userId")->second.c_str()),
            params.find("bundleName")->second, std::atoi(params.find("bindType")->second.c_str()),
            std::atoi(params.find("status")->second.c_str()), profile);
        return ret;
    }
    if (params.find("userId") != params.end() && params.find("bundleName") != params.end()
            && params.find("trustDeviceId") != params.end() && params.find("status") != params.end()) {
        int32_t ret = this->GetAccessControlProfile(std::atoi(params.find("userId")->second.c_str()),
            params.find("bundleName")->second, params.find("trustDeviceId")->second,
            std::atoi(params.find("status")->second.c_str()), profile);
        return ret;
    }
    if (params.find("bundleName") != params.end() && params.find("trustDeviceId") != params.end()
        && params.find("status") != params.end()) {
        int32_t ret = this->GetAccessControlProfile(params.find("bundleName")->second,
            params.find("trustDeviceId")->second, std::atoi(params.find("status")->second.c_str()), profile);
        return ret;
    }
    if (params.find("bundleName") != params.end() && params.find("bindType") != params.end()
        && params.find("status") != params.end()) {
        int32_t ret = this->GetAccessControlProfile(params.find("bundleName")->second,
            std::atoi(params.find("bindType")->second.c_str()),
            std::atoi(params.find("status")->second.c_str()), profile);
        return ret;
    }
    if (params.find("userId") != params.end() && params.find("accountId") != params.end()) {
        int32_t ret = this->GetAccessControlProfile(std::atoi(params.find("userId")->second.c_str()),
            params.find("accountId")->second, profile);
        return ret;
    }
    if (params.find("accesserTokenId") != params.end() && params.find("accesseeDeviceId") != params.end()) {
        int32_t ret = this->GetAccessControlProfileByTokenId(
            std::atoi(params.find("accesserTokenId")->second.c_str()),
            params.find("accesseeDeviceId")->second, profile);
        return ret;
    }
    HILOGE("params is error");
    return DP_GET_ACL_PROFILE_FAIL;
}

int32_t TrustProfileManager::DeleteTrustDeviceProfile(const std::string& deviceId)
{
    std::shared_ptr<ResultSet> resultSet =
        GetResultSet(SELECT_TRUST_DEVICE_TABLE_WHERE_DEVICEID,
        std::vector<ValueObject>{ ValueObject(deviceId) });
    if (resultSet == nullptr) {
        HILOGE("DeleteTrustDeviceProfile::get result failed");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = ROWCOUNT_INIT;
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
    this->ConvertToTrustDeviceProfile(resultSet, profile);
    {
        std::lock_guard<std::mutex> lock(rdbMutex_);
        if (rdbStore_ == nullptr) {
            HILOGE("DeleteTrustDeviceProfile::rdbStore_ is nullptr");
            return DP_GET_RDBSTORE_FAIL;
        }
        int32_t deleteRows = DELETEROWS_INIT;
        ret = rdbStore_->Delete(deleteRows, TRUST_DEVICE_TABLE, DEVICEID_EQUAL_CONDITION,
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
    std::shared_ptr<ResultSet> resultSet =
        GetResultSet(SELECT_ACCESS_CONTROL_TABLE_WHERE_ACCESSCONTROLID,
        std::vector<ValueObject>{ ValueObject(accessControlId) });
    if (resultSet == nullptr) {
        HILOGE("DeleteAccessControlProfile::get result failed");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = ROWCOUNT_INIT;
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

int32_t TrustProfileManager::ConvertToTrustDeviceProfile(
    const AccessControlProfile& accessControlProfile, TrustDeviceProfile& trustDeviceProfile)
{
    trustDeviceProfile.SetDeviceId(accessControlProfile.GetTrustDeviceId());
    trustDeviceProfile.SetDeviceIdType(accessControlProfile.GetDeviceIdType());
    trustDeviceProfile.SetDeviceIdHash(accessControlProfile.GetDeviceIdHash());
    trustDeviceProfile.SetStatus(accessControlProfile.GetStatus());
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetAclProfileByUserIdAndBundleName(std::shared_ptr<ResultSet> resultSet,
    int32_t userId, const std::string& bundleName, std::vector<AccessControlProfile>& profile)
{
    while (resultSet->GoToNextRow() == DP_SUCCESS) {
        int32_t columnIndex = COLUMNINDEX_INIT;
        int64_t accesserId = ACCESSERID_INIT;
        resultSet->GetColumnIndex(ACCESSER_ID, columnIndex);
        resultSet->GetLong(columnIndex, accesserId);
        int64_t accesseeId = ACCESSEEID_INIT;
        resultSet->GetColumnIndex(ACCESSEE_ID, columnIndex);
        resultSet->GetLong(columnIndex, accesseeId);
        int32_t bindType = BINDTYPE_INIT;
        resultSet->GetColumnIndex(BIND_TYPE, columnIndex);
        resultSet->GetInt(columnIndex, bindType);
        int32_t bindLevel = BINDLEVEL_INIT;
        resultSet->GetColumnIndex(BIND_LEVEL, columnIndex);
        resultSet->GetInt(columnIndex, bindLevel);
        if (bindType == static_cast<int32_t>(BindType::SAME_ACCOUNT) &&
            bindLevel == static_cast<int32_t>(BindLevel::DEVICE)) {
            int32_t ret = this->GetAccessControlProfiles(resultSet, accesserId, accesseeId, userId, profile);
            if (ret != DP_SUCCESS) {
                HILOGE("GetAclProfileByUserIdAndBundleName::GetAccessControlProfiles failed");
                return ret;
            }
        } else {
            int32_t ret = this->GetAccessControlProfiles(resultSet, accesserId,
                accesseeId, userId, bundleName, profile);
            if (ret != DP_SUCCESS) {
                HILOGE("GetAclProfileByUserIdAndBundleName::GetAccessControlProfiles failed");
                return ret;
            }
        }
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetAclProfileByUserIdAndAccountId(std::shared_ptr<ResultSet> resultSet,
    int32_t userId, const std::string& accountId, std::vector<AccessControlProfile>& profile)
{
    while (resultSet->GoToNextRow() == DP_SUCCESS) {
        int32_t columnIndex = COLUMNINDEX_INIT;
        int64_t accesserId = ACCESSERID_INIT;
        resultSet->GetColumnIndex(ACCESSER_ID, columnIndex);
        resultSet->GetLong(columnIndex, accesserId);
        int64_t accesseeId = ACCESSEEID_INIT;
        resultSet->GetColumnIndex(ACCESSEE_ID, columnIndex);
        resultSet->GetLong(columnIndex, accesseeId);

        std::shared_ptr<ResultSet> accesserResultSet =
            GetResultSet(SELECT_ACCESSER_TABLE_WHERE_ACCESSERID_AND_ACCESSERUSERID_ACCESSERACCOUNTID,
            std::vector<ValueObject>{ ValueObject(accesserId), ValueObject(userId), ValueObject(accountId) });
        if (accesserResultSet == nullptr) {
            HILOGE("GetAclProfileByUserIdAndAccountId::get accesserResultSet failed");
            return DP_GET_RESULTSET_FAIL;
        }
        int32_t rowCount = ROWCOUNT_INIT;
        accesserResultSet->GetRowCount(rowCount);
        if (rowCount != 0) {
            std::shared_ptr<ResultSet> accesseeResultSet =
                GetResultSet(SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID,
                std::vector<ValueObject>{ ValueObject(accesseeId) });
            this->ConvertToAccessControlProfiles(resultSet, accesserResultSet, accesseeResultSet, profile);
            accesserResultSet->Close();
            accesseeResultSet->Close();
            continue;
        }
        accesserResultSet->Close();

        std::shared_ptr<ResultSet> accesseeResultSet =
            GetResultSet(SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID_AND_ACCESSEEUSEEID_ACCESSEEACCOUNTID,
            std::vector<ValueObject>{ ValueObject(accesseeId), ValueObject(userId), ValueObject(accountId) });
        if (accesseeResultSet == nullptr) {
            HILOGE("GetAclProfileByUserIdAndAccountId::get accesseeResultSet failed");
            return DP_GET_RESULTSET_FAIL;
        }
        accesseeResultSet->GetRowCount(rowCount);
        if (rowCount != 0) {
            accesserResultSet = GetResultSet(SELECT_ACCESSER_TABLE_WHERE_ACCESSERID,
                std::vector<ValueObject>{ ValueObject(accesserId) });
            this->ConvertToAccessControlProfiles(resultSet, accesserResultSet, accesseeResultSet, profile);
            accesseeResultSet->Close();
            accesserResultSet->Close();
        }
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetAclProfileByTokenIdAndDeviceId(std::shared_ptr<ResultSet> resultSet,
    int32_t accesserTokenId, const std::string& accesseeDeviceId, std::vector<AccessControlProfile>& profile)
{
    while (resultSet->GoToNextRow() == DP_SUCCESS) {
        int32_t columnIndex = COLUMNINDEX_INIT;
        int64_t accesserId = ACCESSERID_INIT;
        resultSet->GetColumnIndex(ACCESSER_ID, columnIndex);
        resultSet->GetLong(columnIndex, accesserId);
        int64_t accesseeId = ACCESSEEID_INIT;
        resultSet->GetColumnIndex(ACCESSEE_ID, columnIndex);
        resultSet->GetLong(columnIndex, accesseeId);

        std::shared_ptr<ResultSet> accesserResultSet =
            GetResultSet(SELECT_ACCESSER_TABLE_WHERE_ACCESSERID_AND_ACCESSERTOKENID,
            std::vector<ValueObject>{ ValueObject(accesserId), ValueObject(accesserTokenId) });
        if (accesserResultSet == nullptr) {
            HILOGE("GetAclProfileByTokenIdAndDeviceId::get accesserResultSet failed");
            return DP_GET_RESULTSET_FAIL;
        }
        int32_t rowCount = ROWCOUNT_INIT;
        accesserResultSet->GetRowCount(rowCount);
        if (rowCount != 0) {
            std::shared_ptr<ResultSet> accesseeResultSet =
                GetResultSet(SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID_AND_ACCESSEEDEVICEID,
                std::vector<ValueObject>{ ValueObject(accesseeId), ValueObject(accesseeDeviceId) });
            if (accesseeResultSet == nullptr) {
                HILOGE("GetAclProfileByTokenIdAndDeviceId::get accesseeResultSet failed");
                return DP_GET_RESULTSET_FAIL;
            }
            accesseeResultSet->GetRowCount(rowCount);
            if (rowCount != 0) {
                this->ConvertToAccessControlProfiles(resultSet, accesserResultSet, accesseeResultSet, profile);
                accesserResultSet->Close();
                accesseeResultSet->Close();
            }
        }
        accesserResultSet->Close();
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetAclProfileByBundleName(std::shared_ptr<ResultSet> resultSet,
    const std::string& bundleName, std::vector<AccessControlProfile>& profile)
{
    while (resultSet->GoToNextRow() == DP_SUCCESS) {
        int32_t columnIndex = COLUMNINDEX_INIT;
        int64_t accesserId = ACCESSERID_INIT;
        resultSet->GetColumnIndex(ACCESSER_ID, columnIndex);
        resultSet->GetLong(columnIndex, accesserId);
        int64_t accesseeId = ACCESSEEID_INIT;
        resultSet->GetColumnIndex(ACCESSEE_ID, columnIndex);
        resultSet->GetLong(columnIndex, accesseeId);
        int32_t bindType = BINDTYPE_INIT;
        resultSet->GetColumnIndex(BIND_TYPE, columnIndex);
        resultSet->GetInt(columnIndex, bindType);
        int32_t bindLevel = BINDLEVEL_INIT;
        resultSet->GetColumnIndex(BIND_LEVEL, columnIndex);
        resultSet->GetInt(columnIndex, bindLevel);
        if (bindType == static_cast<int32_t> (BindType::SAME_ACCOUNT) &&
            bindLevel == static_cast<int32_t> (BindLevel::DEVICE)) {
            int32_t ret = this->GetAccessControlProfile(resultSet, accesserId, accesseeId, profile);
            if (ret != DP_SUCCESS) {
                HILOGE("GetAclProfileByBundleName::GetAccessControlProfile failed");
                return ret;
            }
        } else {
            int32_t ret = this->GetAccessControlProfiles(resultSet, accesserId, accesseeId, bundleName, profile);
            if (ret != DP_SUCCESS) {
                HILOGE("GetAclProfileByBundleName::GetAccessControlProfiles failed");
                return ret;
            }
        }
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::ConvertToAccessControlProfiles(std::shared_ptr<ResultSet> resultSet,
    std::shared_ptr<ResultSet> accesserResultSet, std::shared_ptr<ResultSet> accesseeResultSet,
    std::vector<AccessControlProfile>& profile)
{
    Accesser accesser;
    accesserResultSet->GoToNextRow();
    this->ConvertToAccesser(accesserResultSet, accesser);
    Accessee accessee;
    accesseeResultSet->GoToNextRow();
    this->ConvertToAccessee(accesseeResultSet, accessee);
    AccessControlProfile accessControlProfile;
    this->ConvertToAccessControlProfile(resultSet, accessControlProfile);

    accessControlProfile.SetAccesser(accesser);
    accessControlProfile.SetAccessee(accessee);
    profile.push_back(accessControlProfile);
    return DP_SUCCESS;
}

int32_t TrustProfileManager::PutAccesserProfile(const AccessControlProfile& profile)
{
    ValuesBucket values;
    ProfileUtils::AccesserToEntries(profile, values);
    int64_t rowId = ROWID_INIT;
    {
        std::lock_guard<std::mutex> lock(rdbMutex_);
        if (rdbStore_ == nullptr) {
            HILOGE("PutAccesserProfile::rdbStore_ is nullptr");
            return DP_GET_RDBSTORE_FAIL;
        }
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
    ValuesBucket values;
    ProfileUtils::AccesseeToEntries(profile, values);
    int64_t rowId = ROWID_INIT;
    {
        std::lock_guard<std::mutex> lock(rdbMutex_);
        if (rdbStore_ == nullptr) {
            HILOGE("PutAccesserProfile::rdbStore_ is nullptr");
            return DP_GET_RDBSTORE_FAIL;
        }
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
    int32_t rowCount = ROWCOUNT_INIT;
    resultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        profile.SetAccessControlId(1);
        return DP_SUCCESS;
    }
    int64_t accessControlId = ACCESSCONTROLID_INIT;
    int32_t columnIndex = COLUMNINDEX_INIT;
    resultSet->GoToLastRow();
    resultSet->GetColumnIndex(ACCESS_CONTROL_ID, columnIndex);
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
        ValueObject(static_cast<int32_t>(accesser.GetAccesserBindLevel()))});
    if (resultSet == nullptr) {
        HILOGE("SetAccesserId::resultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = ROWCOUNT_INIT;
    int64_t accesserId = ACCESSERID_INIT;
    int32_t columnIndex = COLUMNINDEX_INIT;
    resultSet->GetRowCount(rowCount);
    if (rowCount != 0) {
        resultSet->GoToFirstRow();
        resultSet->GetColumnIndex(ACCESSER_ID, columnIndex);
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
    resultSet->GetColumnIndex(ACCESSER_ID, columnIndex);
    resultSet->GetLong(columnIndex, accesserId);
    resultSet->Close();
    accesserId = accesserId + 1;
    profile.SetAccesserId(accesserId);
    return DP_SUCCESS;
}

int32_t TrustProfileManager::SetAccesseeId(AccessControlProfile& profile)
{
    Accessee accessee = profile.GetAccessee();
    std::shared_ptr<ResultSet> resultSet =
        GetResultSet(SELECT_ACCESSEE_TABLE_WHERE_ALL, std::vector<ValueObject>{
        ValueObject(accessee.GetAccesseeDeviceId()), ValueObject(accessee.GetAccesseeUserId()),
        ValueObject(accessee.GetAccesseeAccountId()), ValueObject(accessee.GetAccesseeTokenId()),
        ValueObject(accessee.GetAccesseeBundleName()), ValueObject(accessee.GetAccesseeHapSignature()),
        ValueObject(static_cast<int32_t>(accessee.GetAccesseeBindLevel()))});
    if (resultSet == nullptr) {
        HILOGE("SetAccesserId::resultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = ROWCOUNT_INIT;
    int64_t accesseeId = ACCESSEEID_INIT;
    int32_t columnIndex = COLUMNINDEX_INIT;
    resultSet->GetRowCount(rowCount);
    if (rowCount != 0) {
        resultSet->GoToFirstRow();
        resultSet->GetColumnIndex(ACCESSEE_ID, columnIndex);
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
    resultSet->GetColumnIndex(ACCESSEE_ID, columnIndex);
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
    int32_t changeRowCnt = CHANGEROWCNT_INIT;
    {
        std::lock_guard<std::mutex> lock(rdbMutex_);
        if (rdbStore_ == nullptr) {
            HILOGE("UpdateAccesserProfile::rdbStore_ is nullptr");
            return DP_GET_RDBSTORE_FAIL;
        }
        int32_t ret = rdbStore_->Update(changeRowCnt, ACCESSER_TABLE, values, ACCESSERID_EQUAL_CONDITION,
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
    int32_t changeRowCnt = CHANGEROWCNT_INIT;
    {
        std::lock_guard<std::mutex> lock(rdbMutex_);
        if (rdbStore_ == nullptr) {
            HILOGE("UpdateAccesseeProfile::rdbStore_ is nullptr");
            return DP_GET_RDBSTORE_FAIL;
        }
        int32_t ret = rdbStore_->Update(changeRowCnt, ACCESSEE_TABLE, values, ACCESSEEID_EQUAL_CONDITION,
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
    if (oldProfile.GetStatus() == 1 && newProfile.GetStatus() == 0) {
        int32_t ret = SubscribeProfileManager::GetInstance().NotifyTrustDeviceProfileDelete(newProfile);
        if (ret != DP_SUCCESS) {
            HILOGE("UpdateTrustDeviceProfileNotify::NotifyTrustDeviceProfileDelete failed");
            return DP_NOTIFY_TRUST_DEVICE_FAIL;
        }
    }
    if (oldProfile.GetStatus() == 0 && newProfile.GetStatus() == 1) {
        int32_t ret = SubscribeProfileManager::GetInstance().NotifyTrustDeviceProfileAdd(newProfile);
        if (ret != DP_SUCCESS) {
            HILOGE("UpdateTrustDeviceProfileNotify::NotifyTrustDeviceProfileAdd failed");
            return DP_NOTIFY_TRUST_DEVICE_FAIL;
        }
    }
    if (oldProfile.GetDeviceId() != newProfile.GetDeviceId() ||
        oldProfile.GetDeviceIdHash() != newProfile.GetDeviceIdHash() ||
        oldProfile.GetDeviceIdType() != newProfile.GetDeviceIdType()) {
        int32_t ret = SubscribeProfileManager::GetInstance().NotifyTrustDeviceProfileUpdate(oldProfile, newProfile);
        if (ret != DP_SUCCESS) {
            HILOGE("UpdateTrustDeviceProfileNotify::NotifyTrustDeviceProfileUpdate failed");
            return DP_NOTIFY_TRUST_DEVICE_FAIL;
        }
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetResultStatus(const std::string& trustDeviceId, int32_t& trustDeviceStatus)
{
    std::shared_ptr<ResultSet> resultSet =
        GetResultSet(SELECT_ACCESS_CONTROL_TABLE_WHERE_TRUSTDEVICEID,
        std::vector<ValueObject>{ ValueObject(trustDeviceId) });
    if (resultSet == nullptr) {
        HILOGE("GetResultStatus::resultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = ROWCOUNT_INIT;
    resultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        HILOGE("GetResultStatus::trustDeviceId not find");
        return DP_NOT_FIND_DATA;
    }
    int32_t columnIndex = COLUMNINDEX_INIT;
    trustDeviceStatus = 0;
    while (resultSet->GoToNextRow() == DP_SUCCESS) {
        int32_t status = STATUS_INIT;
        resultSet->GetColumnIndex(STATUS, columnIndex);
        resultSet->GetInt(columnIndex, status);
        if (status == 1) {
            trustDeviceStatus = 1;
            break;
        }
    }
    resultSet->Close();
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetAccessControlProfile(std::shared_ptr<ResultSet> resultSet,
    int64_t accesserId, int64_t accesseeId, std::vector<AccessControlProfile>& profile)
{
    std::shared_ptr<ResultSet> accesserResultSet =
        GetResultSet(SELECT_ACCESSER_TABLE_WHERE_ACCESSERID,
        std::vector<ValueObject>{ ValueObject(accesserId) });
    if (accesserResultSet == nullptr) {
        HILOGE("GetAccessControlProfile::accesserResultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = ROWCOUNT_INIT;
    accesserResultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        HILOGE("GetAccessControlProfile::not find data");
        return DP_NOT_FIND_DATA;
    }
    std::shared_ptr<ResultSet> accesseeResultSet =
        GetResultSet(SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID,
        std::vector<ValueObject>{ ValueObject(accesseeId) });
    if (accesseeResultSet == nullptr) {
        HILOGE("GetAccessControlProfile::accesseeResultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    accesseeResultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        HILOGE("GetAccessControlProfile::not find data");
        return DP_NOT_FIND_DATA;
    }
    this->ConvertToAccessControlProfiles(resultSet, accesserResultSet, accesseeResultSet, profile);
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
    this->ConvertToAccessControlProfile(resultSet, profile);
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
        if (rdbStore_ == nullptr) {
            HILOGE("DeleteAccessControlProfileCheck::rdbStore_ is nullptr");
            return DP_GET_RDBSTORE_FAIL;
        }
        int32_t deleteRows = DELETEROWS_INIT;
        ret = rdbStore_->Delete(deleteRows, ACCESS_CONTROL_TABLE, ACCESSCONTROLID_EQUAL_CONDITION,
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

int32_t TrustProfileManager::ConvertToTrustDeviceProfile(
    std::shared_ptr<ResultSet> trustResultSet, TrustDeviceProfile& trustDeviceProfile)
{
    RowEntity rowEntity;
    if (trustResultSet->GetRow(rowEntity) != DP_SUCCESS) {
        HILOGE("ConvertToTrustDeviceProfile::get trustResultSet failed");
        return DP_GET_RESULTSET_FAIL;
    }
    std::string deviceId = rowEntity.Get(DEVICE_ID);
    int32_t deviceIdType = rowEntity.Get(DEVICE_ID_TYPE);
    std::string deviceIdHash = rowEntity.Get(DEVICE_ID_HASH);
    int32_t status = rowEntity.Get(STATUS);

    trustDeviceProfile.SetDeviceId(deviceId);
    trustDeviceProfile.SetDeviceIdType(deviceIdType);
    trustDeviceProfile.SetDeviceIdHash(deviceIdHash);
    trustDeviceProfile.SetStatus(status);
    return DP_SUCCESS;
}

int32_t TrustProfileManager::ConvertToAccesser(std::shared_ptr<ResultSet> accesserResultSet,
    Accesser& accesser)
{
    RowEntity rowEntity;
    if (accesserResultSet->GetRow(rowEntity) != DP_SUCCESS) {
        HILOGE("ConvertToAccesser::get accesserResultSet failed");
        return DP_GET_RESULTSET_FAIL;
    }
    int64_t accesserId = rowEntity.Get(ACCESSER_ID);
    std::string accesserDeviceId = rowEntity.Get(ACCESSER_DEVICE_ID);
    int32_t accesserUserId = rowEntity.Get(ACCESSER_USER_ID);
    std::string accesserAccountId = rowEntity.Get(ACCESSER_ACCOUNT_ID);
    int64_t accesserTokenId = rowEntity.Get(ACCESSER_TOKEN_ID);
    std::string accesserBundleName = rowEntity.Get(ACCESSER_BUNDLE_NAME);
    std::string accesserHapSignature = rowEntity.Get(ACCESSER_HAP_SIGNATURE);
    int32_t accesserBindLevel = rowEntity.Get(ACCESSER_BIND_LEVEL);

    accesser.SetAccesserId(accesserId);
    accesser.SetAccesserDeviceId(accesserDeviceId);
    accesser.SetAccesserUserId(accesserUserId);
    accesser.SetAccesserAccountId(accesserAccountId);
    accesser.SetAccesserTokenId(accesserTokenId);
    accesser.SetAccesserBundleName(accesserBundleName);
    accesser.SetAccesserHapSignature(accesserHapSignature);
    accesser.SetAccesserBindLevel(accesserBindLevel);
    return DP_SUCCESS;
}

int32_t TrustProfileManager::ConvertToAccessee(std::shared_ptr<ResultSet> accesseeResultSet,
    Accessee& accessee)
{
    RowEntity rowEntity;
    if (accesseeResultSet->GetRow(rowEntity) != DP_SUCCESS) {
        HILOGE("ConvertToAccessee::get accesseeResultSet failed");
        return DP_GET_RESULTSET_FAIL;
    }
    int64_t accesseeId = rowEntity.Get(ACCESSEE_ID);
    std::string accesseeDeviceId = rowEntity.Get(ACCESSEE_DEVICE_ID);
    int32_t accesseeUserId = rowEntity.Get(ACCESSEE_USER_ID);
    std::string accesseeAccountId = rowEntity.Get(ACCESSEE_ACCOUNT_ID);
    int64_t accesseeTokenId = rowEntity.Get(ACCESSEE_TOKEN_ID);
    std::string accesseeBundleName = rowEntity.Get(ACCESSEE_BUNDLE_NAME);
    std::string accesseeHapSignature = rowEntity.Get(ACCESSEE_HAP_SIGNATURE);
    int32_t accesseeBindLevel = rowEntity.Get(ACCESSEE_BIND_LEVEL);

    accessee.SetAccesseeId(accesseeId);
    accessee.SetAccesseeDeviceId(accesseeDeviceId);
    accessee.SetAccesseeUserId(accesseeUserId);
    accessee.SetAccesseeAccountId(accesseeAccountId);
    accessee.SetAccesseeTokenId(accesseeTokenId);
    accessee.SetAccesseeBundleName(accesseeBundleName);
    accessee.SetAccesseeHapSignature(accesseeHapSignature);
    accessee.SetAccesseeBindLevel(accesseeBindLevel);
    return DP_SUCCESS;
}

int32_t TrustProfileManager::ConvertToAccessControlProfile(
    std::shared_ptr<ResultSet> accessControlResultSet, AccessControlProfile& accessControlProfile)
{
    RowEntity rowEntity;
    if (accessControlResultSet->GetRow(rowEntity) != DP_SUCCESS) {
        HILOGE("ConvertToAccessControlProfile::get accessControlResultSet failed");
        return DP_GET_RESULTSET_FAIL;
    }
    int64_t accessControlId = rowEntity.Get(ACCESS_CONTROL_ID);
    int64_t accesserId = rowEntity.Get(ACCESSER_ID);
    int64_t accesseeId = rowEntity.Get(ACCESSEE_ID);
    std::string trustDeviceId = rowEntity.Get(TRUST_DEVICE_ID);
    std::string sessionKey = rowEntity.Get(SESSION_KEY);
    int32_t bindType = rowEntity.Get(BIND_TYPE);
    int32_t authenticationType = rowEntity.Get(AUTHENTICATION_TYPE);
    int32_t deviceIdType = rowEntity.Get(DEVICE_ID_TYPE);
    std::string deviceIdHash = rowEntity.Get(DEVICE_ID_HASH);
    int32_t status = rowEntity.Get(STATUS);
    int32_t validPeriod = rowEntity.Get(VALID_PERIOD);
    int32_t lastAuthTime = rowEntity.Get(LAST_AUTH_TIME);
    int32_t bindLevel = rowEntity.Get(BIND_LEVEL);

    accessControlProfile.SetAccessControlId(accessControlId);
    accessControlProfile.SetAccesserId(accesserId);
    accessControlProfile.SetAccesseeId(accesseeId);
    accessControlProfile.SetTrustDeviceId(trustDeviceId);
    accessControlProfile.SetSessionKey(sessionKey);
    accessControlProfile.SetBindType(bindType);
    accessControlProfile.SetAuthenticationType(authenticationType);
    accessControlProfile.SetDeviceIdType(deviceIdType);
    accessControlProfile.SetDeviceIdHash(deviceIdHash);
    accessControlProfile.SetStatus(status);
    accessControlProfile.SetValidPeriod(validPeriod);
    accessControlProfile.SetLastAuthTime(lastAuthTime);
    accessControlProfile.SetBindLevel(bindLevel);
    return DP_SUCCESS;
}

std::shared_ptr<ResultSet> TrustProfileManager::GetResultSet(
    const std::string& sql, std::vector<ValueObject> condition)
{
    if (sql.empty() || sql.length() > MAX_STRING_LEN) {
        HILOGE("sql is invalid");
        return nullptr;
    }
    if (condition.size() > MAX_PARAM_SIZE) {
        HILOGE("condition is invalid");
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(rdbMutex_);
    if (rdbStore_ == nullptr) {
        HILOGE("GetResultSet::rdbStore_ is nullptr");
        return nullptr;
    }
    return rdbStore_->Get(sql, condition);
}

int32_t TrustProfileManager::SetAccessControlProfileId(AccessControlProfile& accessControlProfile)
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

int32_t TrustProfileManager::GetAccessControlProfiles(std::shared_ptr<ResultSet> resultSet,
    int64_t accesserId, int64_t accesseeId, int32_t userId, const std::string& bundleName,
    std::vector<AccessControlProfile>& profile)
{
    std::shared_ptr<ResultSet> accesserResultSet =
        GetResultSet(SELECT_ACCESSER_TABLE_WHERE_ACCESSERID_AND_ACCESSERUSERID_ACCESSERBUNDLENAME,
        std::vector<ValueObject>{ ValueObject(accesserId), ValueObject(userId), ValueObject(bundleName) });
    if (accesserResultSet == nullptr) {
        HILOGE("GetAccessControlProfiles::get accesserResultSet failed");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = ROWCOUNT_INIT;
    accesserResultSet->GetRowCount(rowCount);
    if (rowCount != 0) {
        std::shared_ptr<ResultSet> accesseeResultSet =
            GetResultSet(SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID,
            std::vector<ValueObject>{ ValueObject(accesseeId) });
        this->ConvertToAccessControlProfiles(resultSet, accesserResultSet, accesseeResultSet, profile);
        accesserResultSet->Close();
        accesseeResultSet->Close();
        return DP_SUCCESS;
    }
    accesserResultSet->Close();

    std::shared_ptr<ResultSet> accesseeResultSet =
        GetResultSet(SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID_AND_ACCESSEEUSEEID_ACCESSEEBUNDLENAME,
        std::vector<ValueObject>{ ValueObject(accesseeId), ValueObject(userId), ValueObject(bundleName) });
    if (accesseeResultSet == nullptr) {
        HILOGE("GetAccessControlProfiles::get accesseeResultSet failed");
        return DP_GET_RESULTSET_FAIL;
    }
    accesseeResultSet->GetRowCount(rowCount);
    if (rowCount != 0) {
        accesserResultSet = GetResultSet(SELECT_ACCESSER_TABLE_WHERE_ACCESSERID,
            std::vector<ValueObject>{ ValueObject(accesserId) });
        this->ConvertToAccessControlProfiles(resultSet, accesserResultSet, accesseeResultSet, profile);
        accesseeResultSet->Close();
        accesserResultSet->Close();
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetAccessControlProfiles(std::shared_ptr<ResultSet> resultSet, int64_t accesserId,
    int64_t accesseeId, int32_t userId, std::vector<AccessControlProfile>& profile)
{
    std::shared_ptr<ResultSet> accesserResultSet =
        GetResultSet(SELECT_ACCESSER_TABLE_WHERE_ACCESSERID_AND_ACCESSERUSERID,
        std::vector<ValueObject>{ ValueObject(accesserId), ValueObject(userId) });
    if (accesserResultSet == nullptr) {
        HILOGE("GetAccessControlProfiles::get accesserResultSet failed");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = ROWCOUNT_INIT;
    accesserResultSet->GetRowCount(rowCount);
    if (rowCount != 0) {
        std::shared_ptr<ResultSet> accesseeResultSet =
            GetResultSet(SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID,
            std::vector<ValueObject>{ ValueObject(accesseeId) });
        this->ConvertToAccessControlProfiles(resultSet, accesserResultSet, accesseeResultSet, profile);
        accesserResultSet->Close();
        accesseeResultSet->Close();
        return DP_SUCCESS;
    }
    accesserResultSet->Close();

    std::shared_ptr<ResultSet> accesseeResultSet =
        GetResultSet(SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID_AND_ACCESSEEUSERID,
        std::vector<ValueObject>{ ValueObject(accesseeId), ValueObject(userId) });
    if (accesseeResultSet == nullptr) {
        HILOGE("GetAccessControlProfiles::get accesseeResultSet failed");
        return DP_GET_RESULTSET_FAIL;
    }
    accesseeResultSet->GetRowCount(rowCount);
    if (rowCount != 0) {
        accesserResultSet = GetResultSet(SELECT_ACCESSER_TABLE_WHERE_ACCESSERID,
            std::vector<ValueObject>{ ValueObject(accesserId) });
        this->ConvertToAccessControlProfiles(resultSet, accesserResultSet, accesseeResultSet, profile);
        accesseeResultSet->Close();
        accesserResultSet->Close();
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::GetAccessControlProfiles(std::shared_ptr<ResultSet> resultSet, int64_t accesserId,
    int64_t accesseeId, const std::string& bundleName, std::vector<AccessControlProfile>& profile)
{
    std::shared_ptr<ResultSet> accesserResultSet =
        GetResultSet(SELECT_ACCESSER_TABLE_WHERE_ACCESSERID_AND_ACCESSERBUNDLENAME,
        std::vector<ValueObject>{ ValueObject(accesserId), ValueObject(bundleName) });
    if (accesserResultSet == nullptr) {
        HILOGE("GetAccessControlProfileOnUserIdAndTokenId::get result failed");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = ROWCOUNT_INIT;
    accesserResultSet->GetRowCount(rowCount);
    if (rowCount != 0) {
        std::shared_ptr<ResultSet> accesseeResultSet =
            GetResultSet(SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID,
            std::vector<ValueObject>{ ValueObject(accesseeId) });
        this->ConvertToAccessControlProfiles(resultSet, accesserResultSet, accesseeResultSet, profile);
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
        this->ConvertToAccessControlProfiles(resultSet, accesserResultSet, accesseeResultSet, profile);
        accesseeResultSet->Close();
        accesserResultSet->Close();
    }
    return DP_SUCCESS;
}

int32_t TrustProfileManager::DeleteAccesserCheck(int64_t accesserId)
{
    std::shared_ptr<ResultSet> resultSet =
        GetResultSet(SELECT_ACCESS_CONTROL_TABLE_WHERE_ACCESSERID,
        std::vector<ValueObject>{ ValueObject(accesserId) });
    if (resultSet == nullptr) {
        HILOGE("DeleteAccesseeCheck::accesserId not find");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = ROWCOUNT_INIT;
    resultSet->GetRowCount(rowCount);
    resultSet->Close();
    if (rowCount == DELETE_ACCESSER_CONDITION) {
        std::lock_guard<std::mutex> lock(rdbMutex_);
        if (rdbStore_ == nullptr) {
            HILOGE("DeleteAccesserCheck::rdbStore_ is nullptr");
            return DP_GET_RDBSTORE_FAIL;
        }
        int32_t deleteRows = DELETEROWS_INIT;
        int32_t ret = rdbStore_->Delete(deleteRows, ACCESSER_TABLE, ACCESSERID_EQUAL_CONDITION,
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
    std::shared_ptr<ResultSet> resultSet =
        GetResultSet(SELECT_ACCESS_CONTROL_TABLE_WHERE_ACCESSCONTROLID,
        std::vector<ValueObject>{ ValueObject(profile.GetAccessControlId()) });
    if (resultSet == nullptr) {
        HILOGE("UpdateAccessControlProfile::resultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = ROWCOUNT_INIT;
    resultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        HILOGE("UpdateAccessControlProfile::accessControlId not find");
        return DP_NOT_FIND_DATA;
    }
    resultSet->GoToNextRow();
    AccessControlProfile oldProfile;
    this->ConvertToAccessControlProfile(resultSet, oldProfile);
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
    std::shared_ptr<ResultSet> resultSet =
        GetResultSet(SELECT_ACCESS_CONTROL_TABLE_WHERE_ACCESSEEID,
        std::vector<ValueObject>{ ValueObject(accesseeId) });
    if (resultSet == nullptr) {
        HILOGE("DeleteAccesseeCheck::accesseeId not find");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = ROWCOUNT_INIT;
    resultSet->GetRowCount(rowCount);
    resultSet->Close();
    if (rowCount == DELETE_ACCESSEE_CONDITION) {
        std::lock_guard<std::mutex> lock(rdbMutex_);
        if (rdbStore_ == nullptr) {
            HILOGE("DeleteAccesseeCheck::rdbStore_ is nullptr");
            return DP_GET_RDBSTORE_FAIL;
        }
        int32_t deleteRows = DELETEROWS_INIT;
        int32_t ret = rdbStore_->Delete(deleteRows, ACCESSEE_TABLE, ACCESSEEID_EQUAL_CONDITION,
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
    int32_t rowCount = ROWCOUNT_INIT;
    resultSet->GetRowCount(rowCount);
    int32_t ret = RET_INIT;
    if (rowCount == DELETE_TRUST_CONDITION) {
        ret = this->DeleteTrustDeviceProfile(profile.GetTrustDeviceId());
        if (ret != DP_SUCCESS) {
            HILOGE("DeleteTrustDeviceCheck::DeleteTrustDeviceProfile failed");
            return DP_DELETE_TRUST_DEVICE_PROFILE_FAIL;
        }
    } else {
        int32_t status = STATUS_INIT;
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

} // namespace DistributedDeviceProfile
} // namespace OHOS