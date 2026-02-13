/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_DP_RDB_ADAPTER_H
#define OHOS_DP_RDB_ADAPTER_H


#include <set>
#include "irdb_adapter.h"
#include "rdb_open_callback.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class RdbAdapter : public IRdbAdapter {
public:
    RdbAdapter();
    ~RdbAdapter();
    int32_t Init() override;
    int32_t UnInit() override;
    int32_t Put(int64_t& outRowId, const std::string& table, const ValuesBucket& Values) override;
    int32_t Delete(int32_t& deleteRows, const std::string& table, const std::string& whereClause,
        const std::vector<ValueObject>& bindArgs = {}) override;
    int32_t Update(int32_t& changedRows, const std::string& table, const ValuesBucket& values,
        const std::string& whereClause, const std::vector<ValueObject>& bindArgs = {}) override;
    int32_t CreateTable(const std::string& sql) override;
    std::shared_ptr <ResultSet> Get(const std::string& sql, const std::vector<ValueObject>& args = {}) override;

private:
    int32_t GetRDBPtr(std::shared_ptr<RdbStore>& store, int32_t DBVersion, const std::string& path);
    int32_t ConnectDB(std::shared_ptr<RdbStore>& store, int32_t DBVersion, const std::string& path);
    int32_t MigrateDatabase();
    int32_t CheckMigrateDB();
    std::shared_ptr<RdbStore> store_ = nullptr;
    std::mutex rdbAdapterMtx_;
    std::mutex InitMtx_;
    std::shared_ptr<RdbStore> preMigStore_ = nullptr;
    std::shared_ptr<RdbStore> postMigStore_ = nullptr;
};

class OpenCallback : public NativeRdb::RdbOpenCallback {
public:
    int32_t OnCreate(RdbStore& store) override;
    int32_t OnUpgrade(RdbStore& store, int oldVersion, int newVersion) override;
    int32_t CreateTable(RdbStore& store);
    int32_t CreateUniqueIndex(RdbStore& store);
    int32_t UpgradeVersionOneToTwo(RdbStore& store);
    int32_t UpgradeVersionTwoToThree(RdbStore& store);
    int32_t AddAcerColumnOneToTwo(RdbStore& store);
    int32_t AddAceeColumnOneToTwo(RdbStore& store);
    int32_t AddAclColumnTwoToThree(RdbStore& store);
    int32_t AddAcerColumnTwoToThree(RdbStore& store);
    int32_t AddAceeColumnTwoToThree(RdbStore& store);
    int32_t DropAndRebuildIndex(RdbStore& store);

private:
    std::mutex rdbStoreMtx_;
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // OHOS_DP_RDB_ADAPTER_H
