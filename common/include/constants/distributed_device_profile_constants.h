/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_DP_DISTRIBUTED_DEVICE_PROFILE_CONSTANTS_H
#define OHOS_DP_DISTRIBUTED_DEVICE_PROFILE_CONSTANTS_H

#include <unordered_set>
#include <string>
#include <unistd.h>

#ifdef __LP64__
constexpr const char* LIB_LOAD_PATH = "/system/lib64/";
#else
constexpr const char* LIB_LOAD_PATH = "/system/lib/";
#endif

namespace OHOS {
namespace DistributedDeviceProfile {
/* DeviceProfile Attribute */
const std::string DEVICE_ID = "deviceId";
const std::string DEVICE_TYPE_ID = "deviceTypeId";
const std::string DEVICE_TYPE_NAME = "deviceTypeName";
const std::string DEVICE_NAME = "deviceIdName";
const std::string MANUFACTURE_NAME = "manufactureName";
const std::string DEVICE_MODEL = "deviceModel";
const std::string STORAGE_CAPACITY = "storageCapacity";
const std::string OS_SYS_CAPACITY = "osSysCapacity";
const std::string OS_API_LEVEL = "osApiLevel";
const std::string OS_VERSION = "osVersion";
const std::string OS_TYPE = "osType";
/* ServiceProfile Attribute */
const std::string SERVICE_NAME = "serviceName";
const std::string SERVICE_TYPE = "serviceType";
/* CharacteristicProfile Attribute */
const std::string CHARACTERISTIC_KEY = "characteristicKey";
const std::string CHARACTERISTIC_VALUE = "characteristicValue";
/* TrustDeviceProfile Attribute */
const std::string SUBSCRIBE_TRUST_DEVICE_PROFILE = "trust_device_profile";
const std::string DEVICE_ID_TYPE = "deviceIdType";
const std::string DEVICE_ID_HASH = "deviceIdHash";
/* AccessControlProfile Attribute */
const std::string ACCESS_CONTROL_ID = "accessControlId";
const std::string ACCESSER_ID = "accesserId";
const std::string ACCESSEE_ID = "accesseeId";
const std::string TRUST_DEVICE_ID = "trustDeviceId";
const std::string SESSION_KEY = "sessionKey";
const std::string BIND_TYPE = "bindType";
const std::string AUTHENTICATION_TYPE = "authenticationType";
const std::string BIND_LEVEL = "bindLevel";
const std::string STATUS = "status";
const std::string VALID_PERIOD = "validPeriod";
const std::string LAST_AUTH_TIME = "lastAuthTime";
/* Accesser Attribute */
const std::string ACCESSER_DEVICE_ID = "accesserDeviceId";
const std::string ACCESSER_USER_ID = "accesserUserId";
const std::string ACCESSER_ACCOUNT_ID = "accesserAccountId";
const std::string ACCESSER_TOKEN_ID = "accesserTokenId";
const std::string ACCESSER_BUNDLE_NAME = "accesserBundleName";
const std::string ACCESSER_HAP_SIGNATURE = "accesserHapSignature";
const std::string ACCESSER_BIND_LEVEL = "accesserBindLevel";
/* Accessee Attribute */
const std::string ACCESSEE_DEVICE_ID = "accesseeDeviceId";
const std::string ACCESSEE_USER_ID = "accesseeUserId";
const std::string ACCESSEE_ACCOUNT_ID = "accesseeAccountId";
const std::string ACCESSEE_TOKEN_ID = "accesseeTokenId";
const std::string ACCESSEE_BUNDLE_NAME = "accesseeBundleName";
const std::string ACCESSEE_HAP_SIGNATURE = "accesseeHapSignature";
const std::string ACCESSEE_BIND_LEVEL = "accesseeBindLevel";
/* subscribe info */
const std::string SA_ID = "saId";
const std::string SUBSCRIBE_KEY = "subscribeKey";
const std::string SUBSCRIBE_CHANGE_TYPES = "subscribeChangeTypes";
/* syncOptions */
const std::string SYNC_MODE = "syncMode";
const std::string SYNC_DEVICE_IDS = "syncDevices";
/* Interface Name */
const std::string PUT_ACCESS_CONTROL_PROFILE = "PutAccessControlProfile";
const std::string UPDATE_ACCESS_CONTROL_PROFILE = "UpdateAccessControlProfile";
const std::string GET_ACCESS_CONTROL_PROFILE = "GetAccessControlProfile";
const std::string DELETE_ACCESS_CONTROL_PROFILE = "DeleteAccessControlProfile";
const std::string GET_TRUST_DEVICE_PROFILE = "GetTrustDeviceProfile";
const std::string GET_ALL_TRUST_DEVICE_PROFILE = "GetAllTrustDeviceProfile";
const std::string GET_ALL_ACCESS_CONTROL_PROFILE = "GetAllAccessControlProfile";
const std::string PUT_SERVICE_PROFILE = "PutServiceProfile";
const std::string PUT_SERVICE_PROFILE_BATCH = "PutServiceProfileBatch";
const std::string PUT_CHARACTERISTIC_PROFILE = "PutCharacteristicProfile";
const std::string PUT_CHARACTERISTIC_PROFILE_BATCH = "PutCharacteristicProfileBatch";
const std::string GET_DEVICE_PROFILE = "GetDeviceProfile";
const std::string GET_SERVICE_PROFILE = "GetServiceProfile";
const std::string GET_CHARACTERISTIC_PROFILE = "GetCharacteristicProfile";
const std::string DELETE_SERVICE_PROFILE = "DeleteServiceProfile";
const std::string DELETE_CHARACTERISTIC_PROFILE = "DeleteCharacteristicProfile";
const std::string SUBSCRIBE_DEVICE_PROFILE = "SubscribeDeviceProfile";
const std::string UNSUBSCRIBE_DEVICE_PROFILE = "UnSubscribeDeviceProfile";
const std::string SYNC_DEVICE_PROFILE = "SyncDeviceProfile";
/* Common constants */
constexpr int32_t MIN_STRING_LEN = 0;
constexpr int32_t MAX_STRING_LEN = 4096;
constexpr int64_t MIN_STORAGE_KB = 0;
constexpr int64_t MAX_STORAGE_KB = 5368709120;
constexpr int32_t MIN_OS_API_LEVEL = 0;
constexpr int32_t MAX_OS_API_LEVEL = 10000;
constexpr int32_t MIN_OS_TYPE = 0;
constexpr int32_t MAX_OS_TYPE = 10000;
constexpr int32_t MAX_PARAM_SIZE = 20;
constexpr int32_t MAX_PROFILE_SIZE = 10000;
constexpr int32_t MAX_DEVICE_SIZE = 1000;
constexpr int32_t MAX_SERVICE_SIZE = 1000;
constexpr int32_t MAX_CHAR_SIZE = 1000;
constexpr int32_t MAX_DB_SIZE = 1000;
constexpr int32_t MAX_LISTENER_SIZE = 100;
constexpr int32_t MAX_EVENT_HANDLER_SIZE = 50;
constexpr int32_t MAX_DB_RECORD_SIZE = 10000;
constexpr int32_t MAX_SUBSCRIBE_CHANGE_SIZE = 3;
constexpr int32_t MAX_INTERFACE_SIZE = 20;
constexpr int32_t MAX_SUBSCRIBE_INFO_SIZE = 500;
constexpr int32_t MAX_SYNC_RESULTS_SIZE = 50;
const std::string SEPARATOR = "#";
const std::string DEV_PREFIX = "dev";
const std::string SVR_PREFIX = "svr";
const std::string CHAR_PREFIX = "char";
const std::string USER_ID = "user_id";
const std::string TOKEN_ID = "token_id";
const std::string PKG_NAME = "DBinderBus_" + std::to_string(getpid());
const std::string ALL_PROC = "all";
constexpr int32_t NUM_1 = 1;
constexpr int32_t NUM_2 = 2;
constexpr int32_t NUM_3 = 3;
/* rdb constants */
const std::string RDB_PATH = "/data/service/el1/public/database/distributed_device_profile_service/";
const std::string DATABASE_NAME = "dp_rdb.db";
constexpr int32_t RDB_VERSION = 1;
constexpr int32_t RDB_INIT_MAX_TIMES = 30;
constexpr int32_t RDB_INIT_INTERVAL_TIME = 100000;
/* TrustProfile Manager */
const std::string USERID = "userId";
const std::string BUNDLENAME = "bundleName";
const std::string TOKENID = "tokenId";
const std::string ACCOUNTID = "accountId";
const std::string DEVICEID_EQUAL_CONDITION = "deviceId = ?";
const std::string ACCESSCONTROLID_EQUAL_CONDITION = "accessControlId = ?";
const std::string ACCESSERID_EQUAL_CONDITION = "accesserId = ? ";
const std::string ACCESSEEID_EQUAL_CONDITION = "accesseeId = ? ";
constexpr int32_t ROWCNT_INIT = -1;
constexpr int32_t RET_INIT = -1;
constexpr int32_t ROWCOUNT_INIT = -1;
constexpr int32_t CHANGEROWCNT_INIT = -1;
constexpr int32_t COLUMNINDEX_INIT = -1;
constexpr int32_t STATUS_INIT = 0;
constexpr int32_t BINDTYPE_INIT = -1;
constexpr int32_t BINDLEVEL_INIT = -1;
constexpr int32_t DELETEROWS_INIT = -1;
constexpr int32_t DELETE_ACCESSER_CONDITION = 1;
constexpr int32_t DELETE_ACCESSEE_CONDITION = 1;
constexpr int32_t DELETE_TRUST_CONDITION = 0;
constexpr int64_t ROWID_INIT = -1;
constexpr int64_t ACCESSERID_INIT = -1;
constexpr int64_t ACCESSEEID_INIT = -1;
constexpr int64_t ACCESSCONTROLID_INIT = -1;
const std::string CREATE_TURST_DEVICE_TABLE_SQL = "CREATE TABLE IF NOT EXISTS trust_device_table\
(\
    deviceId        TEXT PRIMARY KEY,\
    deviceIdType    INTEGER,\
    deviceIdHash    TEXT,\
    status          INTEGER);";
const std::string CREATE_ACCESS_CONTROL_TABLE_SQL = "CREATE TABLE IF NOT EXISTS access_control_table\
(\
    accessControlId    INTEGER PRIMARY KEY,\
    accesserId         INTEGER,\
    accesseeId         INTEGER,\
    trustDeviceId      TEXT,\
    sessionKey         TEXT,\
    bindType           INTEGER,\
    authenticationType INTEGER,\
    deviceIdType       INTEGER,\
    deviceIdHash       TEXT,\
    status             INTEGER,\
    validPeriod        INTEGER,\
    lastAuthTime       INTEGER,\
    bindLevel          INTEGER);";
const std::string CREATE_ACCESSER_TABLE_SQL = "CREATE TABLE IF NOT EXISTS accesser_table\
(\
    accesserId           INTEGER PRIMARY KEY,\
    accesserDeviceId     TEXT,\
    accesserUserId       INTEGER,\
    accesserAccountId    TEXT,\
    accesserTokenId      INTEGER,\
    accesserBundleName   TEXT,\
    accesserHapSignature TEXT,\
    accesserBindLevel    INTEGER\
);";
const std::string CREATE_ACCESSEE_TABLE_SQL = "CREATE TABLE IF NOT EXISTS accessee_table\
(\
    accesseeId           INTEGER PRIMARY KEY,\
    accesseeDeviceId     TEXT,\
    accesseeUserId       INTEGER,\
    accesseeAccountId    TEXT,\
    accesseeTokenId      INTEGER,\
    accesseeBundleName   TEXT,\
    accesseeHapSignature TEXT,\
    accesseeBindLevel    INTEGER\
);";
const std::string CREATE_TURST_DEVICE_TABLE_UNIQUE_INDEX_SQL =
"CREATE UNIQUE INDEX if not exists unique_trust_device_table ON trust_device_table \
(\
    deviceId,\
    deviceIdType,\
    deviceIdHash,\
    status);";
const std::string CREATE_ACCESS_CONTROL_TABLE_UNIQUE_INDEX_SQL =
"CREATE UNIQUE INDEX if not exists unique_access_control_table ON access_control_table \
(\
    accesserId,\
    accesseeId,\
    trustDeviceId,\
    sessionKey,\
    bindType,\
    authenticationType,\
    deviceIdType,\
    deviceIdHash,\
    status,\
    validPeriod,\
    lastAuthTime,\
    bindLevel);";
const std::string CREATE_ACCESSER_TABLE_UNIQUE_INDEX_SQL =
"CREATE UNIQUE INDEX if not exists unique_accesser_table ON accesser_table \
(\
    accesserDeviceId,\
    accesserUserId,\
    accesserAccountId,\
    accesserTokenId,\
    accesserBundleName,\
    accesserHapSignature,\
    accesserBindLevel);";
const std::string CREATE_ACCESSEE_TABLE_UNIQUE_INDEX_SQL =
"CREATE UNIQUE INDEX if not exists unique_accessee_table ON accessee_table \
(\
    accesseeDeviceId,\
    accesseeUserId,\
    accesseeAccountId,\
    accesseeTokenId,\
    accesseeBundleName,\
    accesseeHapSignature,\
    accesseeBindLevel);";
const std::string TRUST_DEVICE_TABLE = "trust_device_table";
const std::string ACCESS_CONTROL_TABLE = "access_control_table";
const std::string ACCESSER_TABLE = "accesser_table";
const std::string ACCESSEE_TABLE = "accessee_table";
const std::string SELECT_TRUST_DEVICE_TABLE = "SELECT * FROM trust_device_table";
const std::string SELECT_TRUST_DEVICE_TABLE_WHERE_DEVICEID =
    "SELECT * FROM trust_device_table WHERE deviceId = ?";
const std::string SELECT_ACCESS_CONTROL_TABLE_WHERE_ACCESSCONTROLID =
    "SELECT * FROM access_control_table WHERE accessControlId = ?";
const std::string SELECT_ACCESS_CONTROL_TABLE_WHERE_ACCESSEEID =
    "SELECT * FROM access_control_table WHERE accesseeId = ? ";
const std::string SELECT_ACCESS_CONTROL_TABLE_WHERE_ACCESSERID =
    "SELECT * FROM access_control_table WHERE accesserId = ? ";
const std::string SELECT_ACCESS_CONTROL_TABLE_WHERE_BINDTYPE_AND_STATUS =
    "SELECT * FROM access_control_table WHERE bindType = ? and status = ? ";
const std::string SELECT_ACCESS_CONTROL_TABLE = "SELECT * FROM access_control_table";
const std::string SELECT_ACCESS_CONTROL_TABLE_WHERE_TRUSTDEVICEID =
    "SELECT * FROM access_control_table WHERE trustDeviceId = ? ";
const std::string SELECT_ACCESS_CONTROL_TABLE_WHERE_TRUSTDEVICEID_AND_STATUS =
    "SELECT * FROM access_control_table WHERE trustDeviceId = ? and status = ?";
const std::string SELECT_ACCESS_CONTROL_TABLE_WHERE_STATUS =
    "SELECT * FROM access_control_table WHERE status = ?";
const std::string SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID = "SELECT * FROM accessee_table WHERE accesseeId = ? ";
const std::string SELECT_ACCESSER_TABLE_WHERE_ACCESSERID = "SELECT * FROM accesser_table WHERE accesserId = ? ";
const std::string SELECT_ACCESSER_TABLE_WHERE_ACCESSERID_AND_ACCESSERUSERID_ACCESSERTOKENID =
    "SELECT * FROM accesser_table WHERE accesserId = ? and accesserUserId = ? and accesserTokenId = ?";
const std::string SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID_AND_ACCESSEEUSEEID_ACCESSEETOKENID =
    "SELECT * FROM accessee_table WHERE accesseeId = ? and accesseeUserId = ? and accesseeTokenId = ?";
const std::string SELECT_ACCESSER_TABLE_WHERE_ACCESSERID_AND_ACCESSERUSERID_ACCESSERBUNDLENAME =
    "SELECT * FROM accesser_table WHERE accesserId = ? and accesserUserId = ? and accesserBundleName = ?";
const std::string SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID_AND_ACCESSEEUSEEID_ACCESSEEBUNDLENAME =
    "SELECT * FROM accessee_table WHERE accesseeId = ? and accesseeUserId = ? and accesseeBundleName = ?";
const std::string SELECT_ACCESSER_TABLE_WHERE_ACCESSERID_AND_ACCESSERUSERID_ACCESSERACCOUNTID =
    "SELECT * FROM accesser_table WHERE accesserId = ? and accesserUserId = ? and accesserAccountId = ?";
const std::string SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID_AND_ACCESSEEUSEEID_ACCESSEEACCOUNTID =
    "SELECT * FROM accessee_table WHERE accesseeId = ? and accesseeUserId = ? and accesseeAccountId = ?";
const std::string SELECT_ACCESSER_TABLE_WHERE_ACCESSERID_AND_ACCESSERUSERID =
    "SELECT * FROM accesser_table WHERE accesserId = ? and accesserUserId = ? ";
const std::string SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID_AND_ACCESSEEUSERID =
    "SELECT * FROM accessee_table WHERE accesseeId = ? and accesseeUserId = ? ";
const std::string SELECT_ACCESSER_TABLE_WHERE_ACCESSERID_AND_DEVICEID_AND_ACCESSERTOKENID =
    "SELECT * FROM accesser_table WHERE accesserId = ? and accesserDeviceId = ? and accesserTokenId = ? ";
const std::string SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID_AND_DEVICEID_AND_ACCESSEETOKENID =
    "SELECT * FROM accessee_table WHERE accesseeId = ? and accesseeDeviceId = ? and accesseeTokenId = ? ";
const std::string SELECT_ACCESSER_TABLE_WHERE_ACCESSERID_AND_ACCESSERDEVICEID =
    "SELECT * FROM accesser_table WHERE accesserId = ? and accesserDeviceId = ? ";
const std::string SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID_AND_ACCESSEEDEVICEID =
    "SELECT * FROM accessee_table WHERE accesseeId = ? and accesseeDeviceId = ? ";
const std::string SELECT_ACCESSER_TABLE_WHERE_ACCESSERID_AND_ACCESSERBUNDLENAME =
    "SELECT * FROM accesser_table WHERE accesserId = ? and accesserBundleName = ? ";
const std::string SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID_AND_ACCESSEEBUNDLENAME =
    "SELECT * FROM accessee_table WHERE accesseeId = ? and accesseeBundleName = ? ";
const std::string SELECT_ACCESSEE_TABLE = "SELECT * FROM accessee_table ";
const std::string SELECT_ACCESSER_TABLE = "SELECT * FROM accesser_table ";
const std::string SELECT_ACCESS_CONTROL_TABLE_WHERE_ALL =
    "SELECT * FROM access_control_table WHERE accesserId = ? and accesseeId = ? and trustDeviceId = ? and \
    sessionKey = ? and bindType = ? and authenticationType = ? and deviceIdType = ? and deviceIdHash = ? \
    and status = ? and validPeriod = ? and lastAuthTime = ? and bindLevel = ? ";
const std::string SELECT_ACCESSER_TABLE_WHERE_ALL =
    "SELECT * FROM accesser_table WHERE accesserDeviceId = ? and accesserUserId = ? and accesserAccountId = ? and \
    accesserTokenId = ? and accesserBundleName = ? and accesserHapSignature = ? and accesserBindLevel = ? ";
const std::string SELECT_ACCESSEE_TABLE_WHERE_ALL =
    "SELECT * FROM accessee_table WHERE accesseeDeviceId = ? and accesseeUserId = ? and accesseeAccountId = ? and \
    accesseeTokenId = ? and accesseeBundleName = ? and accesseeHapSignature = ? and accesseeBindLevel = ? ";
/* SubscribeTrustInfoManager */
const std::string SUBSCRIBE_TRUST_INFO_TABLE = "subscribe_trust_info_table";
const std::string CREATE_SUBSCRIBE_TRUST_INFO_TABLE_SQL =
    "CREATE TABLE IF NOT EXISTS subscribe_trust_info_table\
    (\
        saId                 INTEGER PRIMARY KEY,\
        subscribeTable       TEXT,\
    );";
const std::string CREATE_SUBSCRIBE_TRUST_INFO_TABLE_UNIQUE_INDEX_SQL =
    "CREATE UNIQUE INDEX if not exists unique_subscribe_trust_info_table ON subscribe_trust_info_table \
    (said,\
    subscribeTable);";
const std::string TRUST_DEVICE_DELETE = "TrustDeviceDelete";
const std::string TRUST_DEVICE_ADD = "TrustDeviceAdd";
const std::string TRUST_DEVICE_UPDATE = "TrustDeviceUpdate";
/* event handler factory */
const std::string UNLOAD_DP_SA_HANDLER = "unload_dp_sa_handler";
const std::string KV_DEATH_HANDLER = "kv_store_death_handler";
const std::string ON_SYNC_HANDLER = "kv_sync_completed_handler";
const std::string AUTO_SYNC_HANDLER = "auto_sync_handler";
const std::string EMPTY_STRING = "";
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // OHOS_DP_DISTRIBUTED_DEVICE_PROFILE_CONSTANTS_H
