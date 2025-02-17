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

#ifndef OHOS_DP_SERVICES_CONSTANTS_H
#define OHOS_DP_SERVICES_CONSTANTS_H

#include <unordered_set>
#include <string>
#include <unistd.h>

namespace OHOS {
namespace DistributedDeviceProfile {
/* DeviceProfileDao */
constexpr int32_t AND_LENGTH = 5;
constexpr int32_t WHERE_LENGTH = 7;
extern const std::string PROFILE_DATA_RDB_PATH;
extern const std::string PROFILE_DATA_DATABASE_NAME;
extern const std::string SERVICE_INFO_PROFILE_RDB_PATH;
extern const std::string SERVICE_INFO_PROFILE_DATABASE_NAME;
extern const std::string ID_EQUAL_CONDITION;
extern const std::string SELECT_DEVICE_PROFILE_TABLE;
extern const std::string SELECT_DEVICE_PROFILE_TABLE_WHERE_DEVID_USERID;
extern const std::string CREATE_DEVICE_PROFILE_TABLE_SQL;
extern const std::string CREATE_DEVICE_PROFILE_TABLE_UNIQUE_INDEX_SQL;
extern const std::string CREATE_DEVICE_PROFILE_WISE_DEVICEID_INDEX_SQL;
// DeviceIconInfoDao
extern const std::string CREATE_DEVICE_ICON_INFO_TABLE_SQL ;
extern const std::string CREATE_DEVICE_ICON_INFO_TABLE_UNIQUE_INDEX_SQL;
extern const std::string SELECT_DEVICE_ICON_INFO_TABLE;
// ProductInfoDao
extern const std::string CREATE_PRODUCT_INFO_TABLE_SQL;
extern const std::string SELECT_PRODUCT_INFO_TABLE;
/* ServiceProfileDao */
extern const std::string SELECT_SERVICE_PROGILES;
extern const std::string CREATE_SERVICE_PROFILE_TABLE_SQL;
extern const std::string CREATE_SERVICE_PROFILE_TABLE_INDEX_SERVICEID_SQL;
extern const std::string CREATE_SERVICE_PROFILE_TABLE_INDEX_DEVICEPROFILEID_SQL;
extern const std::string SELECT_SERVICE_PROFILE_TABLE_WHERE_DEVID_SERID_SERTYPE;
// CharacteristicProfileDao
extern const std::string SELECT_CHARACTERISTIC_PROFILE_TABLE;
extern const std::string CREATE_CHARACTERISTIC_PROFILE_TABLE_SQL;
extern const std::string CREATE_CHARACTERISTIC_PROFILE_TABLE_INDEX_SQL_CHARACTERISTIC_KEY;
extern const std::string CREATE_CHARACTERISTIC_PROFILE_TABLE_INDEX_SQL_SERVICE_PROFILE_ID;
extern const std::string SELECT_CHARACTERISTIC_PROFILE_TABLE_MAX_ID;
// ServiceInfoProfile
extern const std::string SERVICE_INFO_PROFILE_TABLE;
extern const std::string CREATE_SERVICE_INFO_PROFILE_TABLE_SQL;
extern const std::string CREATE_SERVICE_INFO_PROFILE_TABLE_UNIQUE_INDEX_SQL;
extern const std::string SELECT_SERVICE_INFO_PROFILE_ALL;
extern const std::string SERVICE_INFO_PROFILE_UNIQUE_INDEX_EQUAL_CONDITION;
extern const std::string SELECT_SERVICE_INFO_PROFILE_TABLE_WHERE_DEVID_USERID_TOKENID_SERVICEID;
extern const std::string SELECT_SERVICE_INFO_PROFILE_TABLE_WHERE_DEVID_USERID_TOKENID;
extern const std::string SELECT_SERVICE_INFO_PROFILE_TABLE_WHERE_DEVID_USERID_BUNDLENAME;
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // OHOS_DP_SERVICES_CONSTANTS_H
