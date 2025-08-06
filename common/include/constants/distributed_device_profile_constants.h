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
extern const std::string TYPE;
extern const std::string OH_PROFILE_SUFFIX;
extern const std::string ID;
extern const std::string DEV_TYPE;
extern const std::string MANU;
extern const std::string SN;
extern const std::string PRODUCT_ID;
extern const std::string PRODUCT_NAME;
extern const std::string SUB_PRODUCT_ID;
extern const std::string HIV;
extern const std::string MAC;
extern const std::string BLE_MAC;
extern const std::string BR_MAC;
extern const std::string SLE_MAC;
extern const std::string FWV;
extern const std::string HWV;
extern const std::string SWV;
extern const std::string PROT_TYPE;
extern const std::string SETUP_TYPE;
extern const std::string WISE_USER_ID;
extern const std::string WISE_DEVICE_ID;
extern const std::string ROOM_NAME;
extern const std::string REGISTER_TIME;
extern const std::string MODIFY_TIME;
extern const std::string SHARE_TIME;
extern const std::string PRODUCTOR_INFO_VERSION;
extern const std::string INTERNAL_MODEL;
extern const std::string DEVICE_PROFILE_TABLE;
extern const std::string DEVICE_ICON_INFO_TABLE;
extern const std::string PRODUCT_INFO_TABLE;
extern const std::string SYSTEM;
extern const std::string RDB_TYPE_TEXT;
extern const std::string RESULT;
/* ServiceProfile Attribute */
extern const std::string SERVICE_NAME;
extern const std::string SERVICE_PROFILE_SERVICE_ID;
extern const std::string SERVICE_TYPE;
extern const std::string SERVICE_PROFILE_TABLE;
extern const std::string RDB_USER_ID;
extern const std::string SERVICE_PROFILE_DEVICE_PROFILE_ID;
extern const std::string SERVICE_PROFILE_SERVICE_TYPE;
/* CharacteristicProfile Attribute */
extern const std::string SERVICE_PROFILE_ID;
extern const std::string CHARACTERISTIC_PROFILE_TABLE;
extern const std::string CHARACTERISTIC_KEY;
extern const std::string CHARACTERISTIC_VALUE;
/* ProductInfo Attribute */
extern const std::string PRODUCT_NAME;
extern const std::string PRODUCT_SHORT_NAME;
extern const std::string IMAGE_VERSION;
/* DeviceIconInfo Attribute */
extern const std::string IMAGE_TYPE;
extern const std::string SPEC_NAME;
extern const std::string DEVICE_ICON;
extern const std::string DEVICE_ICON_VERSION;
extern const std::string DEVICE_ICON_URL;
 /* ServiceInfoProfile Attribute */
extern const std::string SRNETWORK_ID;
extern const std::string SISERVICE_ID;
extern const std::string SERVICE_DISPLAY_NAME;
extern const std::string CUSTOM_DATA;
extern const std::string CUSTOM_DATA_LEN;
extern const std::string BUNDLE_NAME;
extern const std::string MODULE_NAME;
extern const std::string ABILITY_NAME;
extern const std::string AUTH_BOX_TYPE;
extern const std::string AUTH_TYPE;
extern const std::string PIN_EXCHANGE_TYPE;
extern const std::string PINCODE;
extern const std::string DESCRIPTION;
extern const std::string SERVICE_DISCOVERY_SCOPE;
extern const std::string EXTRAINFO;
extern const std::string PUT_SERVICE_INFO_PROFILE;
extern const std::string DELETE_SERVICE_INFO_PROFILE;
extern const std::string UPDATE_SERVICE_INFO_PROFILE;
extern const std::string GET_SERVICE_INFO_PROFILE_BY_UNIQUE_KEY;
extern const std::string GET_SERVICE_INFO_PROFILE_LIST_BY_TOKEN_ID;
extern const std::string GET_ALL_SERVICE_INFO_PROFILE_LIST;
extern const std::string GET_SERVICE_INFO_PROFILE_LIST_BY_BUNDLE_NAME;
/* LocalServiceInfo Attribute */
extern const std::string PUT_LOCAL_SERVICE_INFO;
extern const std::string UPDATE_LOCAL_SERVICE_INFO;
extern const std::string GET_LOCAL_SERVICE_INFO_BY_BINDLE_AND_PINTYPE;
extern const std::string DELETE_LOCAL_SERVICE_INFO;
/* TrustDeviceProfile Attribute */
extern const std::string SUBSCRIBE_TRUST_DEVICE_PROFILE;
extern const std::string DEVICE_ID_TYPE;
extern const std::string DEVICE_ID_HASH;
extern const std::string PEER_USER_ID;
extern const std::string LOCAL_USER_ID;
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
extern const std::string EXTRA_DATA;
/* Accesser Attribute */
extern const std::string ACCESSER_DEVICE_ID;
extern const std::string ACCESSER_USER_ID;
extern const std::string ACCESSER_ACCOUNT_ID;
extern const std::string ACCESSER_TOKEN_ID;
extern const std::string ACCESSER_BUNDLE_NAME;
extern const std::string ACCESSER_HAP_SIGNATURE;
extern const std::string ACCESSER_BIND_LEVEL;
extern const std::string ACCESSER_DEVICE_NAME;
extern const std::string ACCESSER_SERVICE_NAME;
extern const std::string ACCESSER_CREDENTIAL_ID;
extern const std::string ACCESSER_CREDENTIAL_ID_STR;
extern const std::string ACCESSER_STATUS;
extern const std::string ACCESSER_SESSION_KEY_ID;
extern const std::string ACCESSER_SESSION_KEY_TIMESTAMP;
extern const std::string ACCESSER_EXTRA_DATA;
/* Accessee Attribute */
extern const std::string ACCESSEE_DEVICE_ID;
extern const std::string ACCESSEE_USER_ID;
extern const std::string ACCESSEE_ACCOUNT_ID;
extern const std::string ACCESSEE_TOKEN_ID;
extern const std::string ACCESSEE_BUNDLE_NAME;
extern const std::string ACCESSEE_HAP_SIGNATURE;
extern const std::string ACCESSEE_BIND_LEVEL;
extern const std::string ACCESSEE_DEVICE_NAME;
extern const std::string ACCESSEE_SERVICE_NAME;
extern const std::string ACCESSEE_CREDENTIAL_ID;
extern const std::string ACCESSEE_CREDENTIAL_ID_STR;
extern const std::string ACCESSEE_STATUS;
extern const std::string ACCESSEE_SESSION_KEY_ID;
extern const std::string ACCESSEE_SESSION_KEY_TIMESTAMP;
extern const std::string ACCESSEE_EXTRA_DATA;
/* subscribe info */
extern const std::string SA_ID;
extern const std::string SUBSCRIBE_KEY;
extern const std::string SUBSCRIBE_CHANGE_TYPES;
/* syncOptions */
extern const std::string SYNC_MODE;
extern const std::string SYNC_DEVICE_IDS;
/* Interface Name */
extern const std::string PUT_SESSION_KEY;
extern const std::string GET_SESSION_KEY;
extern const std::string UPDATE_SESSION_KEY;
extern const std::string DELETE_SESSION_KEY;
extern const std::string PUT_ACCESS_CONTROL_PROFILE;
extern const std::string UPDATE_ACCESS_CONTROL_PROFILE;
extern const std::string GET_ACCESS_CONTROL_PROFILE;
extern const std::string DELETE_ACCESS_CONTROL_PROFILE;
extern const std::string GET_TRUST_DEVICE_PROFILE;
extern const std::string GET_ALL_TRUST_DEVICE_PROFILE;
extern const std::string GET_ALL_ACCESS_CONTROL_PROFILE;
extern const std::string GET_ALL_ACL_INCLUDE_LNN_ACL;
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
extern const std::string PUT_ALL_TRUSTED_DEVICES;
extern const std::string PUT_DEVICE_PROFILE_BATCH;
extern const std::string DELETE_DEVICE_PROFILE_BATCH;
extern const std::string GET_DEVICE_PROFILES;
extern const std::string PUT_PRODUCT_INFO_BATCH;
extern const std::string PUT_DEVICE_ICON_INFO_BATCH;
extern const std::string GET_DEVICE_ICON_INFOS;
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
constexpr int32_t MAX_DUMP_ARGS_SIZE = 1000;
constexpr int32_t MAX_LISTENER_SIZE = 100;
constexpr int32_t MAX_EVENT_HANDLER_SIZE = 50;
constexpr int32_t MAX_DB_RECORD_SIZE = 10000;
constexpr int32_t MAX_SUBSCRIBE_CHANGE_SIZE = 6;
constexpr int32_t MAX_INTERFACE_SIZE = 60;
constexpr int32_t MAX_SUBSCRIBE_INFO_SIZE = 500;
constexpr int32_t MAX_SYNC_RESULTS_SIZE = 50;
constexpr int32_t MAX_STATIC_CAPABILITY_SIZE = 100;
constexpr int32_t MAX_ID_SIZE = 1000;
constexpr int32_t MAX_ICON_SIZE = 4*1024*1024;
constexpr int32_t MIN_USER_ID = 0;
constexpr int32_t MAX_USER_ID = 100000;
constexpr uint32_t MAX_TRUSTED_DEVICE_SIZE = 1000;
constexpr int32_t MAX_SESSIONKEY_SIZE = 8*1024;
constexpr int32_t COUNTER_INIT = 0;
constexpr int32_t COUNTER_MAX = 999999;
constexpr int32_t US_100000 = 100000;
constexpr int32_t US_200000 = 200000;
constexpr int32_t US_300000 = 300000;
constexpr int32_t US_400000 = 400000;
constexpr int32_t US_500000 = 500000;
extern const std::string IS_MULTI_USER;
extern const std::string SEPARATOR;
extern const std::string SLASHES;
extern const std::string DEV_PREFIX;
extern const std::string SVR_PREFIX;
extern const std::string CHAR_PREFIX;
extern const std::string USER_ID;
extern const std::string TOKEN_ID;
extern const std::string DEVICE_PROFILE_ID;
extern const std::string ALL_PROC;
extern const std::string TYPE_UNKNOWN;
extern const std::string TYPE_PHONE;
extern const std::string TYPE_PAD;
extern const std::string TYPE_TV;
extern const std::string TYPE_CAR;
extern const std::string TYPE_WATCH;
extern const std::string TYPE_PC;
extern const std::string TYPE_2IN1;
extern const std::string HIV_VERSION;
extern const std::string INVALID_PINCODE;
constexpr int32_t NUM_1 = 1;
constexpr int32_t NUM_2 = 2;
constexpr int32_t NUM_3 = 3;
constexpr int32_t NUM_4 = 4;
constexpr int32_t NUM_5 = 5;
constexpr int32_t NUM_6 = 6;
constexpr int32_t NUM_16 = 16;
constexpr int32_t DEFAULT_USER_ID = -1;
constexpr int32_t DEFAULT_USER_ID_EXTRA = 0;
constexpr int32_t U_100 = 100;
constexpr int64_t DEFAULT_SERVICE_ID = -1;
constexpr int32_t DEFAULT_ID = -1;
constexpr int32_t DEFAULT_SERVICE_PROFILE_ID = -1;
constexpr int32_t DEFAULT_DEVICE_PROFILE_ID = -1;
constexpr int32_t DEFAULT_AUTH_BOX_TYPE = -1;
constexpr int32_t DEFAULT_AUTH_TYPE = -1;
constexpr int32_t DEFAULT_PIN_EXCHANGE_TYPE = -1;
constexpr uint32_t NUM_1U = 1;
constexpr uint32_t NUM_8U = 8;
constexpr uint16_t CUR_SWITCH_LEN = 5;
extern const std::string DP_PKG_NAME;
extern const std::string IS_NUMSTRING_RULES;
constexpr int32_t OHOS_TYPE = 10;
constexpr int32_t OHOS_TYPE_UNKNOWN = -1;
/* rdb constants */
extern const std::string RDB_PATH;
extern const std::string DATABASE_NAME;
constexpr int32_t RDB_VERSION = 1;
constexpr int32_t RDB_VERSION_5_1 = 2;
constexpr int32_t RDB_VERSION_5_1_2 = 3;
constexpr int32_t RDB_INIT_MAX_TIMES = 30;
constexpr int32_t RDB_INIT_INTERVAL_TIME = 100000;
/* TrustProfile Manager */
extern const std::string USERID;
extern const std::string BUNDLENAME;
extern const std::string TOKENID;
extern const std::string ACCOUNTID;
extern const std::string PRODUCTID;
extern const std::string DEVICEID_EQUAL_CONDITION;
extern const std::string ACCESSCONTROLID_EQUAL_CONDITION;
extern const std::string ACCESSERID_EQUAL_CONDITION;
extern const std::string ACCESSEEID_EQUAL_CONDITION;
extern const std::string IS_LNN_ACL;
extern const std::string LNN_ACL_TRUE;
extern const std::string BUSINESS_KEY;
extern const std::string BUSINESS_VALUE;

constexpr int32_t ROWCNT_INIT = -1;
constexpr int32_t RET_INIT = -1;
constexpr int32_t ROWCOUNT_INIT = -1;
constexpr int32_t CHANGEROWCNT_INIT = -1;
constexpr int32_t CHANGEROWCNT_INIT_ID = -1;
constexpr int32_t COLUMNINDEX_INIT = -1;
constexpr int32_t STATUS_INIT = 0;
constexpr int32_t STATUS_ACTIVE = 1;
constexpr int32_t STATUS_INACTIVE = 0;
constexpr int32_t BINDTYPE_INIT = -1;
constexpr int32_t BINDLEVEL_INIT = -1;
constexpr int32_t DELETEROWS_INIT = -1;
constexpr int32_t DELETE_ACCESSER_CONDITION = 1;
constexpr int32_t DELETE_ACCESSEE_CONDITION = 1;
constexpr int32_t DELETE_TRUST_CONDITION = 0;
constexpr int32_t MAX_SAID = 16777215;
constexpr int64_t ROWID_INIT = -1;
constexpr int64_t DEVICE_PROFILE_ID_INIT = -1;
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
extern const std::string PRAGMA_ACCESSEE_TABLE;
extern const std::string DROP_OLD_UNIQUE_INDEX_ON_ACER;
extern const std::string DROP_OLD_UNIQUE_INDEX_ON_ACEE;
extern const std::string ALTER_TABLE_ACCESS_CONTROL_ADD_COLUMN_EXTRA_DATA;
extern const std::string ALTER_TABLE_ACER_ADD_COLUMN_ACER_DEVICE_NAME;
extern const std::string ALTER_TABLE_ACER_ADD_COLUMN_ACER_SERVICE_NAME;
extern const std::string ALTER_TABLE_ACER_ADD_COLUMN_ACER_CREDENTIAL_ID;
extern const std::string ALTER_TABLE_ACER_ADD_COLUMN_ACER_CREDENTIAL_ID_STR;
extern const std::string ALTER_TABLE_ACER_ADD_COLUMN_ACER_STATUS;
extern const std::string ALTER_TABLE_ACER_ADD_COLUMN_ACER_SESSION_KEY_ID;
extern const std::string ALTER_TABLE_ACER_ADD_COLUMN_ACER_SESSION_KEY_TIMESTAMP;
extern const std::string ALTER_TABLE_ACER_ADD_COLUMN_ACER_EXTRA_DATA;
extern const std::string ALTER_TABLE_ACEE_ADD_COLUMN_ACEE_DEVICE_NAME;
extern const std::string ALTER_TABLE_ACEE_ADD_COLUMN_ACEE_SERVICE_NAME;
extern const std::string ALTER_TABLE_ACEE_ADD_COLUMN_ACEE_CREDENTIAL_ID;
extern const std::string ALTER_TABLE_ACEE_ADD_COLUMN_ACEE_CREDENTIAL_ID_STR;
extern const std::string ALTER_TABLE_ACEE_ADD_COLUMN_ACEE_STATUS;
extern const std::string ALTER_TABLE_ACEE_ADD_COLUMN_ACEE_SESSION_KEY_ID;
extern const std::string ALTER_TABLE_ACEE_ADD_COLUMN_ACEE_SESSION_KEY_TIMESTAMP;
extern const std::string ALTER_TABLE_ACEE_ADD_COLUMN_ACEE_EXTRA_DATA;
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
extern const std::string SELECT_ACCESSER_TABLE_WHERE_ACCESSERID_AND_ACCESSERTOKENID;
extern const std::string SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID_AND_ACCESSEETOKENID;
extern const std::string SELECT_ACCESSER_TABLE_WHERE_ACCESSERID_AND_DEVICEID_AND_ACCESSERTOKENID;
extern const std::string SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID_AND_DEVICEID_AND_ACCESSEETOKENID;
extern const std::string SELECT_ACCESSER_TABLE_WHERE_ACCESSERID_AND_DEVICEID_AND_USERID;
extern const std::string SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID_AND_DEVICEID_AND_USERID;
extern const std::string SELECT_ACCESSER_TABLE_WHERE_ACCESSERID_AND_ACCESSERDEVICEID;
extern const std::string SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID_AND_ACCESSEEDEVICEID;
extern const std::string SELECT_ACCESSER_TABLE_WHERE_ACCESSERID_AND_ACCESSERBUNDLENAME;
extern const std::string SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID_AND_ACCESSEEBUNDLENAME;
extern const std::string SELECT_ACCESSEE_TABLE;
extern const std::string SELECT_ACCESSER_TABLE;
extern const std::string SELECT_ACCESS_CONTROL_TABLE_WHERE_ALL_EXCEPT_STATUS;
extern const std::string SELECT_ACCESSER_TABLE_WHERE_ALL;
extern const std::string SELECT_ACCESSEE_TABLE_WHERE_ALL;
extern const std::string SELECT_ACCESSER_TABLE_WHERE_ACCESSERDEVICEID_AND_ACCESSERUSERID;
extern const std::string SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEDEVICEID_AND_ACCESSEEUSERID;
extern const std::string SELECT_ACCESS_CONTROL_TABLE_WHERE_ACCESSERID_AND_ACCESSEEID;
extern const std::string TABLE_EXIST_COLUMN_SQL;
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
