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

#ifndef OHOS_DP_PROFILE_DATA_RDB_ADAPTER_H
#define OHOS_DP_PROFILE_DATA_RDB_ADAPTER_H


#include <set>
#include "dp_services_constants.h"
#include "irdb_adapter.h"
#include "rdb_open_callback.h"
#include "single_instance.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class ProfileDataRdbAdapter : public IRdbAdapter {
    DECLARE_SINGLE_INSTANCE(ProfileDataRdbAdapter);
public:
    int32_t Init() override;
    int32_t UnInit() override;
    int32_t Put(int64_t& outRowId, const std::string& table, const ValuesBucket& Values) override;
    int32_t Delete(int32_t& deleteRows, const std::string& table, const std::string& whereClause,
        const std::vector<ValueObject>& bindArgs = {}) override;
    int32_t Update(int32_t& changedRows, const std::string& table, const ValuesBucket& values,
        const std::string& whereClause, const std::vector<ValueObject>& bindArgs = {}) override;
    int32_t CreateTable(const std::string& sql) override;
    std::shared_ptr <ResultSet> Get(const std::string& sql, const std::vector<ValueObject>& args = {}) override;
    int32_t GetRDBPtr();
    bool IsInit();

private:
    std::shared_ptr<RdbStore> store_ = nullptr;
    std::mutex ProfileDataRdbAdapterMtx_;
};

class ProfileDataOpenCallback : public NativeRdb::RdbOpenCallback {
public:
    int32_t OnCreate(RdbStore& store) override;
    int32_t OnUpgrade(RdbStore& store, int oldVersion, int newVersion) override;
private:
    int32_t CheckAndAlterTable(RdbStore& store, const RdbTableAlterInfo& info);
    int32_t UpdateFromVer1To2(RdbStore& store);
    int32_t UpdateToVer3(RdbStore& store);
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // OHOS_DP_PROFILE_DATA_RDB_ADAPTER_H
