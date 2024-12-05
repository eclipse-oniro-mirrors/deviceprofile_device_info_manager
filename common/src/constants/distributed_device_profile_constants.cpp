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

#include "distributed_device_profile_constants.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "DeviceProfileConstants";
}
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
const std::string OH_PROFILE_SUFFIX = "_OH";
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
const std::string PEER_USER_ID = "peerUserId";
const std::string LOCAL_USER_ID = "localUserId";
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
const std::string PUT_ALL_TRUSTED_DEVICES = "PutAllTrustedDevices";
/* Common constants */
const std::string IS_MULTI_USER = "is_multi_user";
const std::string SEPARATOR = "#";
const std::string DEV_PREFIX = "dev";
const std::string SVR_PREFIX = "svr";
const std::string CHAR_PREFIX = "char";
const std::string USER_ID = "user_id";
const std::string TOKEN_ID = "token_id";
const std::string ALL_PROC = "all";
const std::string DP_PKG_NAME = "ohos.deviceprofile";
const std::string IS_NUMSTRING_RULES = "^[-+]?[0-9]+$";
/* rdb constants */
const std::string RDB_PATH = "/data/service/el1/public/database/distributed_device_profile_service/";
const std::string DATABASE_NAME = "dp_rdb.db";
/* TrustProfile Manager */
const std::string USERID = "userId";
const std::string BUNDLENAME = "bundleName";
const std::string TOKENID = "tokenId";
const std::string ACCOUNTID = "accountId";
const std::string DEVICEID_EQUAL_CONDITION = "deviceId = ?";
const std::string ACCESSCONTROLID_EQUAL_CONDITION = "accessControlId = ?";
const std::string ACCESSERID_EQUAL_CONDITION = "accesserId = ? ";
const std::string ACCESSEEID_EQUAL_CONDITION = "accesseeId = ? ";
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
const std::string SELECT_ACCESSER_TABLE_WHERE_ACCESSERID_AND_ACCESSERTOKENID =
    "SELECT * FROM accesser_table WHERE accesserId = ? and accesserTokenId = ? ";
const std::string SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID_AND_ACCESSEETOKENID =
    "SELECT * FROM accessee_table WHERE accesseeId = ? and accesseeTokenId = ? ";
const std::string SELECT_ACCESSER_TABLE_WHERE_ACCESSERID_AND_DEVICEID_AND_ACCESSERTOKENID =
    "SELECT * FROM accesser_table WHERE accesserId = ? and accesserDeviceId = ? and accesserTokenId = ? ";
const std::string SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID_AND_DEVICEID_AND_ACCESSEETOKENID =
    "SELECT * FROM accessee_table WHERE accesseeId = ? and accesseeDeviceId = ? and accesseeTokenId = ? ";
const std::string SELECT_ACCESSER_TABLE_WHERE_ACCESSERID_AND_DEVICEID_AND_USERID =
    "SELECT * FROM accesser_table WHERE accesserId = ? and accesserDeviceId = ? and accesserUserId = ? ";
const std::string SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEID_AND_DEVICEID_AND_USERID =
    "SELECT * FROM accessee_table WHERE accesseeId = ? and accesseeDeviceId = ? and accesseeUserId = ? ";
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
const std::string SELECT_ACCESS_CONTROL_TABLE_WHERE_ALL_EXCEPT_STATUS =
    "SELECT * FROM access_control_table WHERE accesserId = ? and accesseeId = ? and trustDeviceId = ? and \
    sessionKey = ? and bindType = ? and authenticationType = ? and deviceIdType = ? and deviceIdHash = ? \
    and validPeriod = ? and lastAuthTime = ? and bindLevel = ? ";
const std::string SELECT_ACCESSER_TABLE_WHERE_ALL =
    "SELECT * FROM accesser_table WHERE accesserDeviceId = ? and accesserUserId = ? and accesserAccountId = ? and \
    accesserTokenId = ? and accesserBundleName = ? and accesserHapSignature = ? and accesserBindLevel = ? ";
const std::string SELECT_ACCESSEE_TABLE_WHERE_ALL =
    "SELECT * FROM accessee_table WHERE accesseeDeviceId = ? and accesseeUserId = ? and accesseeAccountId = ? and \
    accesseeTokenId = ? and accesseeBundleName = ? and accesseeHapSignature = ? and accesseeBindLevel = ? ";
const std::string SELECT_ACCESSER_TABLE_WHERE_ACCESSERDEVICEID_AND_ACCESSERUSERID =
    "SELECT * FROM accesser_table WHERE accesserDeviceId = ? and accesserUserId = ? ";
const std::string SELECT_ACCESSEE_TABLE_WHERE_ACCESSEEDEVICEID_AND_ACCESSEEUSERID =
    "SELECT * FROM accessee_table WHERE accesseeDeviceId = ? and accesseeUserId = ? ";
const std::string SELECT_ACCESS_CONTROL_TABLE_WHERE_ACCESSERID_AND_ACCESSEEID =
    "SELECT * FROM access_control_table WHERE accesserId = ? and accesseeId = ? ";
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
const std::string DP_HANDLER = "dp_handler";
const std::string EMPTY_STRING = "";
/* switch attribute */
const std::string SWITCH_CAPABILITY_PATH = "etc/deviceprofile/dp_switch_status_cfg.json";
const std::string SWITCH_CALLERS = "DP_Callers";
const std::string SWITCH_SERVICE_NAMES = "name";
const std::string SWITCH_STATUS = "SwitchStatus";
const std::string SWITCH_ON = "1";
const std::string SWITCH_OFF = "0";
const std::string SWITCH_OPERATE_PUT = "PutSwitch";
const std::string SWITCH_OPERATE_GET = "GetSwitch";
/* static attribute */
const std::string STATIC_CAPABILITY_SVR_ID = "static_cap_svr_id";
const std::string STATIC_CAPABILITY_CHAR_ID = "static_capability";
const std::string STATIC_CAPABILITY_PATH = "etc/deviceprofile/dp_static_capability_cfg.json";
const std::string STATIC_INFO_PATH = "etc/deviceprofile/dp_static_info_cfg.json";
const std::string STATIC_CAPABILITY_ATTRIBUTE = "static_capability";
const std::string STATIC_INFO = "static_info";
const std::string DEFAULT_STATIC_VAL = "0";
const std::string STATIC_CHARACTERISTIC_KEY = "static_capability";
const std::string STATIC_CAPABILITY_VERSION = "staticCapabilityVersion";
const std::string STATIC_CAPABILITY_VALUE = "staticCapabilityValue";
const std::string DP_VERSION = "DPVersion";
const std::string ABILITIES = "abilities";
const std::string ABILITY_KEY = "abilityKey";
const std::string ABILITY_VALUE = "abilityValue";
const std::string STATIC_CAP_HANDLER_NAME = "service_name";
const std::string STATIC_CAP_HANDLER_LOC = "handler_loc";
const std::string DMS_HANDLER_LOC = "libdistributed_sdk.z.so";
const std::string STATIC_VERSION_RULES = "^(\\d+\\.){3}\\d+$";
} // namespace DistributedDeviceProfile
} // namespace OHOS
