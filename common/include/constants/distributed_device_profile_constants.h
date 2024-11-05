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
constexpr const char* DMS_LIB_LOAD_PATH = "/system/lib64/platformsdk/";
#else
constexpr const char* LIB_LOAD_PATH = "/system/lib/";
constexpr const char* DMS_LIB_LOAD_PATH = "/system/lib/platformsdk/";
#endif

namespace OHOS {
namespace DistributedDeviceProfile {
/* DeviceProfile Attribute */
extern const std::string DEVICE_ID;
extern const std::string DEVICE_TYPE_ID;
extern const std::string DEVICE_TYPE_NAME;
extern const std::string DEVICE_NAME;
extern const std::string MANUFACTURE_NAME;
extern const std::string DEVICE_MODEL;
extern const std::string STORAGE_CAPACITY;
extern const std::string OS_SYS_CAPACITY;
extern const std::string OS_API_LEVEL;
extern const std::string OS_VERSION;
extern const std::string OS_TYPE;
extern const std::string OH_PROFILE_SUFFIX;
/* ServiceProfile Attribute */
extern const std::string SERVICE_NAME;
extern const std::string SERVICE_TYPE;
/* CharacteristicProfile Attribute */
extern const std::string CHARACTERISTIC_KEY;
extern const std::string CHARACTERISTIC_VALUE;
/* TrustDeviceProfile Attribute */
extern const std::string SUBSCRIBE_TRUST_DEVICE_PROFILE;
extern const std::string DEVICE_ID_TYPE;
extern const std::string DEVICE_ID_HASH;
/* AccessControlProfile Attribute */
extern const std::string ACCESS_CONTROL_ID;
extern const std::string ACCESSER_ID;
extern const std::string ACCESSEE_ID;
extern const std::string TRUST_DEVICE_ID;
extern const std::string SESSION_KEY;
extern const std::string BIND_TYPE;
extern const std::string AUTHENTICATION_TYPE;
extern const std::string BIND_LEVEL;
extern const std::string STATUS;
extern const std::string VALID_PERIOD;
extern const std::string LAST_AUTH_TIME;
/* Accesser Attribute */
extern const std::string ACCESSER_DEVICE_ID;
extern const std::string ACCESSER_USER_ID;
extern const std::string ACCESSER_ACCOUNT_ID;
extern const std::string ACCESSER_TOKEN_ID;
extern const std::string ACCESSER_BUNDLE_NAME;
extern const std::string ACCESSER_HAP_SIGNATURE;
extern const std::string ACCESSER_BIND_LEVEL;
/* Accessee Attribute */
extern const std::string ACCESSEE_DEVICE_ID;
extern const std::string ACCESSEE_USER_ID;
extern const std::string ACCESSEE_ACCOUNT_ID;
extern const std::string ACCESSEE_TOKEN_ID;
extern const std::string ACCESSEE_BUNDLE_NAME;
extern const std::string ACCESSEE_HAP_SIGNATURE;
extern const std::string ACCESSEE_BIND_LEVEL;
/* subscribe info */
extern const std::string SA_ID;
extern const std::string SUBSCRIBE_KEY;
extern const std::string SUBSCRIBE_CHANGE_TYPES;
/* syncOptions */
extern const std::string SYNC_MODE;
extern const std::string SYNC_DEVICE_IDS;
/* Interface Name */
extern const std::string PUT_ACCESS_CONTROL_PROFILE;
extern const std::string UPDATE_ACCESS_CONTROL_PROFILE;
extern const std::string GET_ACCESS_CONTROL_PROFILE;
extern const std::string DELETE_ACCESS_CONTROL_PROFILE;
extern const std::string GET_TRUST_DEVICE_PROFILE;
extern const std::string GET_ALL_TRUST_DEVICE_PROFILE;
extern const std::string GET_ALL_ACCESS_CONTROL_PROFILE;
extern const std::string PUT_SERVICE_PROFILE;
extern const std::string PUT_SERVICE_PROFILE_BATCH;
extern const std::string PUT_CHARACTERISTIC_PROFILE;
extern const std::string PUT_CHARACTERISTIC_PROFILE_BATCH;
extern const std::string GET_DEVICE_PROFILE;
extern const std::string GET_SERVICE_PROFILE;
extern const std::string GET_CHARACTERISTIC_PROFILE;
extern const std::string DELETE_SERVICE_PROFILE;
extern const std::string DELETE_CHARACTERISTIC_PROFILE;
extern const std::string SUBSCRIBE_DEVICE_PROFILE;
extern const std::string UNSUBSCRIBE_DEVICE_PROFILE;
extern const std::string SYNC_DEVICE_PROFILE;
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
constexpr int32_t MAX_STATIC_CAPABILITY_SIZE = 100;
extern const std::string SEPARATOR;
extern const std::string DEV_PREFIX;
extern const std::string SVR_PREFIX;
extern const std::string CHAR_PREFIX;
extern const std::string USER_ID;
extern const std::string TOKEN_ID;
extern const std::string ALL_PROC;
constexpr int32_t NUM_1 = 1;
constexpr int32_t NUM_2 = 2;
constexpr int32_t NUM_3 = 3;
constexpr uint32_t NUM_1U = 1;
constexpr uint32_t NUM_8U = 8;
constexpr uint16_t CUR_SWITCH_LEN = 3;
extern const std::string DP_PKG_NAME;
extern const std::string IS_NUMSTRING_RULES;
constexpr int32_t OHOS_TYPE = 10;
constexpr int32_t OHOS_TYPE_UNKNOWN = -1;
/* rdb constants */
extern const std::string RDB_PATH;
extern const std::string DATABASE_NAME;
constexpr int32_t RDB_VERSION = 1;
constexpr int32_t RDB_INIT_MAX_TIMES = 30;
constexpr int32_t RDB_INIT_INTERVAL_TIME = 100000;
/* TrustProfile Manager */
extern const std::string USERID;
extern const std::string BUNDLENAME;
extern const std::string TOKENID;
extern const std::string ACCOUNTID;
extern const std::string DEVICEID_EQUAL_CONDITION;
extern const std::string ACCESSCONTROLID_EQUAL_CONDITION;
extern const std::string ACCESSERID_EQUAL_CONDITION;
extern const std::string ACCESSEEID_EQUAL_CONDITION;
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
constexpr int32_t MAX_SAID = 16777215;
constexpr int64_t ROWID_INIT = -1;
constexpr int64_t ACCESSERID_INIT = -1;
constexpr int64_t ACCESSEEID_INIT = -1;
constexpr int64_t ACCESSCONTROLID_INIT = -1;
extern const std::string CREATE_TURST_DEVICE_TABLE_SQL;
extern const std::string CREATE_ACCESS_CONTROL_TABLE_SQL;
extern const std::string CREATE_ACCESSER_TABLE_SQL;
extern const std::string CREATE_ACCESSEE_TABLE_SQL;
extern const std::string CREATE_TURST_DEVICE_TABLE_UNIQUE_INDEX_SQL;
extern const std::string CREATE_ACCESS_CONTROL_TABLE_UNIQUE_INDEX_SQL;
extern const std::string CREATE_ACCESSER_TABLE_UNIQUE_INDEX_SQL;
extern const std::string CREATE_ACCESSEE_TABLE_UNIQUE_INDEX_SQL;
extern const std::string TRUST_DEVICE_TABLE;
extern const std::string ACCESS_CONTROL_TABLE;
extern const std::string ACCESSER_TABLE;
extern const std::string ACCESSEE_TABLE;
extern const std::string SELECT_TRUST_DEVICE_TABLE;
extern const std::string SELECT_TRUST_DEVICE_TABLE_WHERE_DEVICEID;
extern const std::string SELECT_ACCESS_CONTROL_TABLE_WHERE_ACCESSCONTROLID;
extern const std::string SELECT_ACCESS_CONTROL_TABLE_WHERE_ACCESSEEID;
extern const std::string SELECT_ACCESS_CONTROL_TABLE_WHERE_ACCESSERID;
extern const std::string SELECT_ACCESS_CONTROL_TABLE_WHERE_BINDTYPE_AND_STATUS;
extern const std::string SELECT_ACCESS_CONTROL_TABLE;
extern const std::string SELECT_ACCESS_CONTROL_TABLE_WHERE_TRUSTDEVICEID;
extern const std::string SELECT_ACCESS_CONTROL_TABLE_WHERE_TRUSTDEVICEID_AND_STATUS;
extern const std::string SELECT_ACCESS_CONTROL_TABLE_WHERE_STATUS;
extern const std::string SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID;
extern const std::string SELECT_ACCESSER_TABLE_WHERE_ACCESSERID;
extern const std::string SELECT_ACCESSER_TABLE_WHERE_ACCESSERID_AND_ACCESSERUSERID_ACCESSERTOKENID;
extern const std::string SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID_AND_ACCESSEEUSEEID_ACCESSEETOKENID;
extern const std::string SELECT_ACCESSER_TABLE_WHERE_ACCESSERID_AND_ACCESSERUSERID_ACCESSERBUNDLENAME;
extern const std::string SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID_AND_ACCESSEEUSEEID_ACCESSEEBUNDLENAME;
extern const std::string SELECT_ACCESSER_TABLE_WHERE_ACCESSERID_AND_ACCESSERUSERID_ACCESSERACCOUNTID;
extern const std::string SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID_AND_ACCESSEEUSEEID_ACCESSEEACCOUNTID;
extern const std::string SELECT_ACCESSER_TABLE_WHERE_ACCESSERID_AND_ACCESSERUSERID;
extern const std::string SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID_AND_ACCESSEEUSERID;
extern const std::string SELECT_ACCESSER_TABLE_WHERE_ACCESSERID_AND_DEVICEID_AND_ACCESSERTOKENID;
extern const std::string SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID_AND_DEVICEID_AND_ACCESSEETOKENID;
extern const std::string SELECT_ACCESSER_TABLE_WHERE_ACCESSERID_AND_ACCESSERDEVICEID;
extern const std::string SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID_AND_ACCESSEEDEVICEID;
extern const std::string SELECT_ACCESSER_TABLE_WHERE_ACCESSERID_AND_ACCESSERBUNDLENAME;
extern const std::string SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID_AND_ACCESSEEBUNDLENAME;
extern const std::string SELECT_ACCESSEE_TABLE;
extern const std::string SELECT_ACCESSER_TABLE;
extern const std::string SELECT_ACCESS_CONTROL_TABLE_WHERE_ALL;
extern const std::string SELECT_ACCESSER_TABLE_WHERE_ALL;
extern const std::string SELECT_ACCESSEE_TABLE_WHERE_ALL;
/* SubscribeTrustInfoManager */
extern const std::string SUBSCRIBE_TRUST_INFO_TABLE;
extern const std::string CREATE_SUBSCRIBE_TRUST_INFO_TABLE_SQL;
extern const std::string CREATE_SUBSCRIBE_TRUST_INFO_TABLE_UNIQUE_INDEX_SQL;
extern const std::string TRUST_DEVICE_DELETE;
extern const std::string TRUST_DEVICE_ADD;
extern const std::string TRUST_DEVICE_UPDATE;
/* event handler factory */
extern const std::string DP_HANDLER;
extern const std::string EMPTY_STRING;
/* switch attribute */
extern const std::string SWITCH_CAPABILITY_PATH;
extern const std::string SWITCH_CALLERS;
extern const std::string SWITCH_SERVICE_NAMES;
extern const std::string SWITCH_STATUS;
extern const std::string SWITCH_ON;
extern const std::string SWITCH_OFF;
extern const std::string SWITCH_OPERATE_PUT;
extern const std::string SWITCH_OPERATE_GET;
/* static attribute */
extern const std::string STATIC_CAPABILITY_SVR_ID;
extern const std::string STATIC_CAPABILITY_CHAR_ID;
extern const std::string STATIC_CAPABILITY_PATH;
extern const std::string STATIC_INFO_PATH;
extern const std::string STATIC_CAPABILITY_ATTRIBUTE;
extern const std::string STATIC_INFO;
extern const std::string DEFAULT_STATIC_VAL;
extern const std::string STATIC_CHARACTERISTIC_KEY;
extern const std::string STATIC_CAPABILITY_VERSION;
extern const std::string STATIC_CAPABILITY_VALUE;
extern const std::string DP_VERSION;
extern const std::string ABILITIES;
extern const std::string ABILITY_KEY;
extern const std::string ABILITY_VALUE;
constexpr char NOT_SUPPORT_STATIC_VAL = '0';
constexpr char SUPPORT_STATIC_VAL = '1';
extern const std::string STATIC_CAP_HANDLER_NAME;
extern const std::string STATIC_CAP_HANDLER_LOC;
extern const std::string DMS_HANDLER_LOC;
extern const std::string STATIC_VERSION_RULES;
constexpr uint32_t SWITCH_LENGTH_MAX = 24;
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // OHOS_DP_DISTRIBUTED_DEVICE_PROFILE_CONSTANTS_H
