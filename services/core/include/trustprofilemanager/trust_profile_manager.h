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

#ifndef OHOS_DP_TRUST_PROFILE_MANAGER_H
#define OHOS_DP_TRUST_PROFILE_MANAGER_H


#include <map>
#include <string>
#include <memory>
#include <mutex>
#include <vector>

#include "irdb_adapter.h"
#include "access_control_profile.h"
#include "trust_device_profile.h"
#include "values_bucket.h"
#include "single_instance.h"


namespace OHOS {
namespace DistributedDeviceProfile {
using namespace OHOS::NativeRdb;

class TrustProfileManager {
    DECLARE_SINGLE_INSTANCE(TrustProfileManager);

public:
    int32_t Init();
    int32_t UnInit();
    int32_t PutTrustDeviceProfile(const TrustDeviceProfile& profile);
    int32_t PutAccessControlProfile(const AccessControlProfile& profile);
    int32_t UpdateTrustDeviceProfile(const TrustDeviceProfile& profile);
    int32_t UpdateAccessControlProfile(const AccessControlProfile& profile);
    int32_t GetTrustDeviceProfile(const std::string& deviceId, TrustDeviceProfile& profile);
    int32_t GetAllTrustDeviceProfile(std::vector<TrustDeviceProfile>& profile);
    int32_t GetAllAccessControlProfile(std::vector<AccessControlProfile>& profile);
    int32_t GetAccessControlProfile(const std::string& bundleName, int32_t bindType,
        int32_t status, std::vector<AccessControlProfile>& profile);
    int32_t GetAccessControlProfile(const std::string& bundleName,
        const std::string& trustDeviceId, int32_t status, std::vector<AccessControlProfile>& profile);
    int32_t GetAccessControlProfile(int32_t userId, const std::string& bundleName,
        int32_t bindType, int32_t status, std::vector<AccessControlProfile>& profile);
    int32_t GetAccessControlProfile(int32_t userId, const std::string& bundleName,
        const std::string& trustDeviceId, int32_t status, std::vector<AccessControlProfile>& profile);
    int32_t GetAccessControlProfile(int32_t userId, const std::string& accountId,
        std::vector<AccessControlProfile>& profile);
    int32_t GetAccessControlProfileOnTokenAndDevice(int32_t accesserTokenId, const std::string& accesseeDeviceId,
        std::vector<AccessControlProfile>& profile);
    int32_t GetAccessControlProfile(std::map<std::string, std::string> params,
        std::vector<AccessControlProfile>& profile);
    int32_t DeleteTrustDeviceProfile(const std::string& deviceId);
    int32_t DeleteAccessControlProfile(int64_t accessControlId);
private:
    int32_t CreateTable();
    int32_t CreateUniqueIndex();
    int32_t AccessControlProfileToTrustDeviceProfile(const AccessControlProfile& accessControlProfile,
        TrustDeviceProfile& trustDeviceProfile);
    int32_t GetAccessControlProfileOnUserIdAndBundleName(std::shared_ptr<ResultSet> resultSet,
        int32_t userId, const std::string& bundleName, std::vector<AccessControlProfile>& profile);
    int32_t GetAccessControlProfileOnUserIdAndAccountId(std::shared_ptr<ResultSet> resultSet,
        int32_t userId, const std::string& accountId, std::vector<AccessControlProfile>& profile);
    int32_t GetAccessControlProfileOnTokenIdAndDeviceId(std::shared_ptr<ResultSet> resultSet,
        int32_t accesserTokenId, const std::string& accesseeDeviceId, std::vector<AccessControlProfile>& profile);
    int32_t GetAccessControlProfileOnBundleName(std::shared_ptr<ResultSet> resultSet,
        const std::string& bundleName, std::vector<AccessControlProfile>& profile);
    int32_t GetVectorAccessControlProfile(std::shared_ptr<ResultSet> resultSet,
        std::shared_ptr<ResultSet> accesserResultSet, std::shared_ptr<ResultSet> accesseeResultSet,
        std::vector<AccessControlProfile>& profile);
    int32_t PutAccesserProfile(const AccessControlProfile& profile);
    int32_t PutAccesseeProfile(const AccessControlProfile& profile);
    int32_t SetAccessControlId(AccessControlProfile& profile);
    int32_t SetAccesserId(AccessControlProfile& profile);
    int32_t SetAccesseeId(AccessControlProfile& profile);
    int32_t UpdateAccesserProfile(int64_t accesserId, const AccessControlProfile& profile);
    int32_t UpdateAccesseeProfile(int64_t accesseeId, const AccessControlProfile& profile);
    int32_t UpdateTrustDeviceProfileNotify(const TrustDeviceProfile& oldProfile,
        const TrustDeviceProfile& newProfile);
    int32_t GetResultStatus(const std::string& trustDeviceId, int32_t& trustDeviceStatus);
    int32_t GetAccesserAndAccesseeAndAccessControl(std::shared_ptr<ResultSet> resultSet,
        int64_t accesserId, int64_t accesseeId, std::vector<AccessControlProfile>& profile);
    int32_t DeleteAccessControlProfileCheck(std::shared_ptr<ResultSet> resultSet);
    int32_t TrustResultSetToTrustDeviceProfile(std::shared_ptr<ResultSet> trustResultSet,
        TrustDeviceProfile& trustDeviceProfile);
    int32_t AccesserResultSetToAccesser(std::shared_ptr<ResultSet> accesserResultSet, Accesser& accesser);
    int32_t AccesseeResultSetToAccessee(std::shared_ptr<ResultSet> accesseeResultSet, Accessee& accessee);
    int32_t AccessControlResultSetToAccessControlProfile(std::shared_ptr<ResultSet> accessControlResultSet,
        AccessControlProfile& accessControlProfile);
    std::shared_ptr<ResultSet> GetResultSet(const std::string& sql, std::vector<ValueObject> condition);
    int32_t SetAclId(AccessControlProfile& accessControlProfile);
    int32_t GetAclOnUserAndBundleAndBindAndStauts(std::map<std::string, std::string> params,
        std::vector<AccessControlProfile>& profile);
    int32_t GetAclOnUserAndBundleAndDeviceIdAndStauts(std::map<std::string, std::string> params,
        std::vector<AccessControlProfile>& profile);
    int32_t GetAclOnBundleAndBindAndStauts(std::map<std::string, std::string> params,
        std::vector<AccessControlProfile>& profile);
    int32_t GetAclOnBundleAndDeviceIdAndStauts(std::map<std::string, std::string> params,
        std::vector<AccessControlProfile>& profile);
    int32_t GetAclOnUserAndAccount(std::map<std::string, std::string> params,
        std::vector<AccessControlProfile>& profile);
    int32_t GetAclVectorOnUserId(std::shared_ptr<ResultSet> resultSet, int64_t accesserId,
        int64_t accesseeId, int32_t userId, std::vector<AccessControlProfile>& profile);
    int32_t GetAclVectorOnUserIdAndBundleName(std::shared_ptr<ResultSet> resultSet,
        int64_t accesserId, int64_t accesseeId, int32_t userId, const std::string& bundleName,
        std::vector<AccessControlProfile>& profile);
    int32_t GetAclVectorOnBundleName(std::shared_ptr<ResultSet> resultSet, int64_t accesserId,
        int64_t accesseeId, const std::string& bundleName, std::vector<AccessControlProfile>& profile);
    int32_t DeleteAccesserCheck(int64_t accesserId);
    int32_t DeleteAccesseeCheck(int64_t accesseeId);
    int32_t DeleteTrustDeviceCheck(const AccessControlProfile& profile);
    int32_t UpdateAclCheck(const AccessControlProfile& profile);
    int32_t GetAclOnTokenIdAndDeviceId(std::map<std::string, std::string> params,
        std::vector<AccessControlProfile>& profile);
private:
    std::shared_ptr<IRdbAdapter> rdbStore_;
    std::mutex rdbMutex_;
};

} // namespace DistributedDeviceProfile
} // namespace OHOS

#endif //OHOS_DP_TRUST_PROFILE_MANAGER_H
