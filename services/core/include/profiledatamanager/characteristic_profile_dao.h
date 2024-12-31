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

#ifndef OHOS_DP_CHARACTERISTIC_PROFILE_DAO_H
#define OHOS_DP_CHARACTERISTIC_PROFILE_DAO_H


#include <map>
#include <string>
#include <memory>
#include <mutex>
#include <vector>

#include "characteristic_profile.h"
#include "characteristic_profile_filter_option.h"
#include "profile_data_rdb_adapter.h"
#include "single_instance.h"
#include "values_bucket.h"

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace OHOS::NativeRdb;

class CharacteristicProfileDao {
    DECLARE_SINGLE_INSTANCE(CharacteristicProfileDao);
public:
    int32_t Init();
    int32_t UnInit();
    int32_t PutCharacteristicProfile(CharacteristicProfile& charProfile);
    int32_t GetCharacteristicProfiles(const CharacteristicProfileFilterOption& filterOptions,
        std::vector<CharacteristicProfile>& deviceProfiles);
    int32_t DeleteCharacteristicProfile(const CharacteristicProfile& charProfile);
    int32_t UpdateCharacteristicProfile(const CharacteristicProfile& oldProfile,
        const CharacteristicProfile& newProfile);

private:
    void CreateQuerySqlAndCondition(const CharacteristicProfileFilterOption& filterOptions,
        std::string& sql, std::vector<ValueObject>& condition);
    int32_t CharProfileToEntries(const CharacteristicProfile& charProfile, ValuesBucket& values);
    int32_t ConvertToCharProfile(std::shared_ptr<ResultSet> resultSet, CharacteristicProfile& charProfile);
    int32_t CreateTable();
    int32_t CreateIndex();
    int32_t SetCharacteristicProfileId(CharacteristicProfile& charProfile);
};
}
}
#endif // OHOS_DP_CHARACTERISTIC_PROFILE_DAO_H
