/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
const std::string DEVICE_NAME = "deviceName";
const std::string MANUFACTURE_NAME = "manufactureName";
const std::string DEVICE_MODEL = "model";
const std::string STORAGE_CAPACITY = "storageCapacity";
const std::string OS_SYS_CAPACITY = "osSysCapacity";
const std::string OS_API_LEVEL = "osApiLevel";
const std::string OS_VERSION = "osVersion";
const std::string OS_TYPE = "osType";
const std::string TYPE = "type";
const std::string OH_PROFILE_SUFFIX = "_OH";
const std::string ID = "id";
const std::string DEV_TYPE = "devType";
const std::string MANU = "manu";
const std::string SN = "sn";
const std::string PRODUCT_ID = "productId";
const std::string SUB_PRODUCT_ID = "subProductId";
const std::string HIV = "hiv";
const std::string MAC = "mac";
const std::string BLE_MAC = "bleMac";
const std::string BR_MAC = "brMac";
const std::string SLE_MAC = "sleMac";
const std::string FWV = "fwv";
const std::string HWV = "hwv";
const std::string SWV = "swv";
const std::string PROT_TYPE = "protType";
const std::string SETUP_TYPE = "setupType";
const std::string WISE_USER_ID = "wiseUserId";
const std::string WISE_DEVICE_ID = "wiseDeviceId";
const std::string ROOM_NAME = "roomName";
const std::string REGISTER_TIME = "registerTime";
const std::string MODIFY_TIME = "modifyTime";
const std::string SHARE_TIME = "shareTime";
const std::string PRODUCTOR_INFO_VERSION = "productorInfoVersion";
const std::string INTERNAL_MODEL = "internalModel";
const std::string DEVICE_PROFILE_TABLE = "device_profile";
const std::string DEVICE_ICON_INFO_TABLE = "device_icon_info";
const std::string PRODUCT_INFO_TABLE = "product_info";
const std::string SYSTEM = "system";
/* ServiceProfile Attribute */
const std::string SERVICE_NAME = "serviceName";
const std::string SERVICE_PROFILE_SERVICE_ID = "serviceId";
const std::string SERVICE_TYPE = "serviceType";
const std::string SERVICE_PROFILE_TABLE = "service_profile";
const std::string RDB_USER_ID = "userId";
const std::string SERVICE_PROFILE_DEVICE_PROFILE_ID = "deviceProfileId";
const std::string SERVICE_PROFILE_SERVICE_TYPE = "serviceType";
/* CharacteristicProfile Attribute */
const std::string SERVICE_PROFILE_ID = "serviceProfileId";
const std::string CHARACTERISTIC_PROFILE_TABLE = "characteristic_profile";
const std::string CHARACTERISTIC_KEY = "characteristicKey";
const std::string CHARACTERISTIC_VALUE = "characteristicValue";
/* ProductInfo Attribute */
const std::string PRODUCT_NAME = "productName";
const std::string PRODUCT_SHORT_NAME = "productShortName";
const std::string IMAGE_VERSION = "imageVersion";
/* DeviceIconInfo Attribute */
const std::string IMAGE_TYPE = "imageType";
const std::string SPEC_NAME = "specName";
const std::string DEVICE_ICON = "icon";
const std::string DEVICE_ICON_VERSION = "version";
const std::string DEVICE_ICON_URL = "url";
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
const std::string EXTRA_DATA = "extraData";
/* Accesser Attribute */
const std::string ACCESSER_DEVICE_ID = "accesserDeviceId";
const std::string ACCESSER_USER_ID = "accesserUserId";
const std::string ACCESSER_ACCOUNT_ID = "accesserAccountId";
const std::string ACCESSER_TOKEN_ID = "accesserTokenId";
const std::string ACCESSER_BUNDLE_NAME = "accesserBundleName";
const std::string ACCESSER_HAP_SIGNATURE = "accesserHapSignature";
const std::string ACCESSER_BIND_LEVEL = "accesserBindLevel";
const std::string ACCESSER_DEVICE_NAME = "accesserDeviceName";
const std::string ACCESSER_SERVICE_NAME = "accesserServiceName";
const std::string ACCESSER_CREDENTIAL_ID = "accesserCredentialId";
const std::string ACCESSER_CREDENTIAL_ID_STR = "accesserCredentialIdStr";
const std::string ACCESSER_STATUS = "accesserStatus";
const std::string ACCESSER_SESSION_KEY_ID = "accesserSessionKeyId";
const std::string ACCESSER_SESSION_KEY_TIMESTAMP = "accesserSKTimeStamp";
const std::string ACCESSER_EXTRA_DATA = "accesserExtraData";
/* Accessee Attribute */
const std::string ACCESSEE_DEVICE_ID = "accesseeDeviceId";
const std::string ACCESSEE_USER_ID = "accesseeUserId";
const std::string ACCESSEE_ACCOUNT_ID = "accesseeAccountId";
const std::string ACCESSEE_TOKEN_ID = "accesseeTokenId";
const std::string ACCESSEE_BUNDLE_NAME = "accesseeBundleName";
const std::string ACCESSEE_HAP_SIGNATURE = "accesseeHapSignature";
const std::string ACCESSEE_BIND_LEVEL = "accesseeBindLevel";
const std::string ACCESSEE_DEVICE_NAME = "accesseeDeviceName";
const std::string ACCESSEE_SERVICE_NAME = "accesseeServiceName";
const std::string ACCESSEE_CREDENTIAL_ID = "accesseeCredentialId";
const std::string ACCESSEE_CREDENTIAL_ID_STR = "accesseeCredentialIdStr";
const std::string ACCESSEE_STATUS = "accesseeStatus";
const std::string ACCESSEE_SESSION_KEY_ID = "accesseeSessionKeyId";
const std::string ACCESSEE_SESSION_KEY_TIMESTAMP = "accesseeSKTimeStamp";
const std::string ACCESSEE_EXTRA_DATA = "accesseeExtraData";
/* subscribe info */
const std::string SA_ID = "saId";
const std::string SUBSCRIBE_KEY = "subscribeKey";
const std::string SUBSCRIBE_CHANGE_TYPES = "subscribeChangeTypes";
/* syncOptions */
const std::string SYNC_MODE = "syncMode";
const std::string SYNC_DEVICE_IDS = "syncDevices";
/* ServiceInfoProfile Attribute */
const std::string SRNETWORK_ID = "networkId";
const std::string SISERVICE_ID = "serviceId";
const std::string SERVICE_DISPLAY_NAME = "serviceDisplayName";
const std::string CUSTOM_DATA = "customData";
const std::string CUSTOM_DATA_LEN = "customDataLen";
const std::string BUNDLE_NAME = "bundleName";
const std::string MODULE_NAME = "moduleName";
const std::string ABILITY_NAME = "abilityName";
const std::string AUTH_BOX_TYPE = "authBoxType";
const std::string AUTH_TYPE = "authType";
const std::string PIN_EXCHANGE_TYPE = "pinExchangeType";
const std::string PINCODE = "pinCode";
const std::string DESCRIPTION = "description";
const std::string SERVICE_DISCOVERY_SCOPE = "serviceDicoveryScope";
const std::string EXTRAINFO = "extraInfo";
const std::string PUT_SERVICE_INFO_PROFILE = "PutServiceInfoProfile";
const std::string DELETE_SERVICE_INFO_PROFILE = "DeleteServiceInfoProfile";
const std::string UPDATE_SERVICE_INFO_PROFILE = "UpdateServiceInfoProfile";
const std::string GET_SERVICE_INFO_PROFILE_BY_UNIQUE_KEY = "GetServiceInfoProfileByUniqueKey";
const std::string GET_SERVICE_INFO_PROFILE_LIST_BY_TOKEN_ID = "GetServiceInfoProfileListByTokenId";
const std::string GET_ALL_SERVICE_INFO_PROFILE_LIST = "GetAllServiceInfoProfileList";
const std::string GET_SERVICE_INFO_PROFILE_LIST_BY_BUNDLE_NAME = "GetServiceInfoProfileListByBundleName";
/* LocalServiceInfo Attribute */
const std::string PUT_LOCAL_SERVICE_INFO = "PutLocalServiceInfo";
const std::string UPDATE_LOCAL_SERVICE_INFO = "UpdateLocalServiceInfo";
const std::string GET_LOCAL_SERVICE_INFO_BY_BINDLE_AND_PINTYPE = "GetLocalServiceInfoByBundleAndPinType";
const std::string DELETE_LOCAL_SERVICE_INFO = "DeleteLocalServiceInfo";
/* Interface Name */
const std::string PUT_SESSION_KEY = "PutSessionKey";
const std::string GET_SESSION_KEY = "GetSessionKey";
const std::string UPDATE_SESSION_KEY = "UpdateSessionKey";
const std::string DELETE_SESSION_KEY = "DeleteSessionKey";
const std::string PUT_ACCESS_CONTROL_PROFILE = "PutAccessControlProfile";
const std::string UPDATE_ACCESS_CONTROL_PROFILE = "UpdateAccessControlProfile";
const std::string GET_ACCESS_CONTROL_PROFILE = "GetAccessControlProfile";
const std::string DELETE_ACCESS_CONTROL_PROFILE = "DeleteAccessControlProfile";
const std::string GET_TRUST_DEVICE_PROFILE = "GetTrustDeviceProfile";
const std::string GET_ALL_TRUST_DEVICE_PROFILE = "GetAllTrustDeviceProfile";
const std::string GET_ALL_ACCESS_CONTROL_PROFILE = "GetAllAccessControlProfile";
const std::string GET_ALL_ACL_INCLUDE_LNN_ACL = "GetAllAclIncludeLnnAcl";
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
const std::string PUT_DEVICE_PROFILE_BATCH = "PutDeviceProfileBatch";
const std::string DELETE_DEVICE_PROFILE_BATCH = "DeleteDeviceProfileBatch";
const std::string GET_DEVICE_PROFILES = "GetDeviceProfiles";
const std::string PUT_PRODUCT_INFO_BATCH = "PutProductInfoBatch";
const std::string PUT_DEVICE_ICON_INFO_BATCH = "PutDeviceIconInfoBatch";
const std::string GET_DEVICE_ICON_INFOS = "GetDeviceIconInfos";
/* Common constants */
const std::string IS_MULTI_USER = "is_multi_user";
const std::string SEPARATOR = "#";
const std::string SLASHES = "/";
const std::string DEV_PREFIX = "dev";
const std::string SVR_PREFIX = "svr";
const std::string CHAR_PREFIX = "char";
const std::string USER_ID = "user_id";
const std::string DEVICE_PROFILE_ID = "deviceProfile_id";
const std::string TOKEN_ID = "token_id";
const std::string ALL_PROC = "all";
const std::string TYPE_UNKNOWN = "default";
const std::string TYPE_PHONE = "phone";
const std::string TYPE_PAD = "tablet";
const std::string TYPE_TV = "tv";
const std::string TYPE_CAR = "car";
const std::string TYPE_WATCH = "wearable";
const std::string TYPE_PC = "pc";
const std::string TYPE_2IN1 = "2in1";
const std::string HIV_VERSION = "1.0";
const std::string INVALID_PINCODE = "******";
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
const std::string PRODUCTID = "productId";
const std::string DEVICEID_EQUAL_CONDITION = "deviceId = ?";
const std::string ACCESSCONTROLID_EQUAL_CONDITION = "accessControlId = ?";
const std::string ACCESSERID_EQUAL_CONDITION = "accesserId = ? ";
const std::string ACCESSEEID_EQUAL_CONDITION = "accesseeId = ? ";
const std::string IS_LNN_ACL = "IsLnnAcl";
const std::string LNN_ACL_TRUE = "true";
const std::string BUSINESS_KEY = "businessKey";
const std::string BUSINESS_VALUE = "businessValue";

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
    bindLevel          INTEGER,\
    extraData          TEXT);";
const std::string CREATE_ACCESSER_TABLE_SQL = "CREATE TABLE IF NOT EXISTS accesser_table\
(\
    accesserId               INTEGER PRIMARY KEY,\
    accesserDeviceId         TEXT,\
    accesserUserId           INTEGER,\
    accesserAccountId        TEXT,\
    accesserTokenId          INTEGER,\
    accesserBundleName       TEXT,\
    accesserHapSignature     TEXT,\
    accesserBindLevel        INTEGER,\
    accesserDeviceName       TEXT,\
    accesserServiceName      TEXT,\
    accesserCredentialId     INTEGER,\
    accesserCredentialIdStr  TEXT,\
    accesserStatus           INTEGER,\
    accesserSessionKeyId     INTEGER,\
    accesserSKTimeStamp      INTEGER,\
    accesserExtraData        TEXT);";
const std::string CREATE_ACCESSEE_TABLE_SQL = "CREATE TABLE IF NOT EXISTS accessee_table\
(\
    accesseeId               INTEGER PRIMARY KEY,\
    accesseeDeviceId         TEXT,\
    accesseeUserId           INTEGER,\
    accesseeAccountId        TEXT,\
    accesseeTokenId          INTEGER,\
    accesseeBundleName       TEXT,\
    accesseeHapSignature     TEXT,\
    accesseeBindLevel        INTEGER,\
    accesseeDeviceName       TEXT,\
    accesseeServiceName      TEXT,\
    accesseeCredentialId     INTEGER,\
    accesseeCredentialIdStr  TEXT,\
    accesseeStatus           INTEGER,\
    accesseeSessionKeyId     INTEGER,\
    accesseeSKTimeStamp      INTEGER,\
    accesseeExtraData        TEXT);";
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
    accesserBindLevel,\
    accesserDeviceName,\
    accesserServiceName,\
    accesserCredentialIdStr,\
    accesserStatus,\
    accesserSessionKeyId);";
const std::string CREATE_ACCESSEE_TABLE_UNIQUE_INDEX_SQL =
"CREATE UNIQUE INDEX if not exists unique_accessee_table ON accessee_table \
(\
    accesseeDeviceId,\
    accesseeUserId,\
    accesseeAccountId,\
    accesseeTokenId,\
    accesseeBundleName,\
    accesseeHapSignature,\
    accesseeBindLevel,\
    accesseeDeviceName,\
    accesseeServiceName,\
    accesseeCredentialIdStr,\
    accesseeStatus,\
    accesseeSessionKeyId);";
const std::string PRAGMA_ACCESSEE_TABLE = "PRAGMA table_info(accessee_table)";
const std::string DROP_OLD_UNIQUE_INDEX_ON_ACER = "DROP INDEX unique_accesser_table";
const std::string DROP_OLD_UNIQUE_INDEX_ON_ACEE = "DROP INDEX unique_accessee_table";
const std::string ALTER_TABLE_ACCESS_CONTROL_ADD_COLUMN_EXTRA_DATA =
    "ALTER TABLE access_control_table ADD COLUMN extraData TEXT DEFAULT ''";;
const std::string ALTER_TABLE_ACER_ADD_COLUMN_ACER_DEVICE_NAME =
    "ALTER TABLE accesser_table ADD COLUMN accesserDeviceName TEXT DEFAULT ''";
const std::string ALTER_TABLE_ACER_ADD_COLUMN_ACER_SERVICE_NAME =
    "ALTER TABLE accesser_table ADD COLUMN accesserServiceName TEXT DEFAULT ''";
const std::string ALTER_TABLE_ACER_ADD_COLUMN_ACER_CREDENTIAL_ID =
    "ALTER TABLE accesser_table ADD COLUMN accesserCredentialId INTERGER DEFAULT -1";
const std::string ALTER_TABLE_ACER_ADD_COLUMN_ACER_CREDENTIAL_ID_STR =
    "ALTER TABLE accesser_table ADD COLUMN accesserCredentialIdStr TEXT DEFAULT ''";
const std::string ALTER_TABLE_ACER_ADD_COLUMN_ACER_STATUS =
    "ALTER TABLE accesser_table ADD COLUMN accesserStatus INTERGER DEFAULT -1";
const std::string ALTER_TABLE_ACER_ADD_COLUMN_ACER_SESSION_KEY_ID =
    "ALTER TABLE accesser_table ADD COLUMN accesserSessionKeyId INTERGER DEFAULT -1";
const std::string ALTER_TABLE_ACER_ADD_COLUMN_ACER_SESSION_KEY_TIMESTAMP =
    "ALTER TABLE accesser_table ADD COLUMN accesserSKTimeStamp INTERGER DEFAULT -1";
const std::string ALTER_TABLE_ACER_ADD_COLUMN_ACER_EXTRA_DATA =
    "ALTER TABLE accesser_table ADD COLUMN accesserExtraData TEXT DEFAULT ''";
const std::string ALTER_TABLE_ACEE_ADD_COLUMN_ACEE_DEVICE_NAME =
    "ALTER TABLE accessee_table ADD COLUMN accesseeDeviceName TEXT DEFAULT ''";
const std::string ALTER_TABLE_ACEE_ADD_COLUMN_ACEE_SERVICE_NAME =
    "ALTER TABLE accessee_table ADD COLUMN accesseeServiceName TEXT DEFAULT ''";
const std::string ALTER_TABLE_ACEE_ADD_COLUMN_ACEE_CREDENTIAL_ID =
    "ALTER TABLE accessee_table ADD COLUMN accesseeCredentialId INTERGER DEFAULT -1";
const std::string ALTER_TABLE_ACEE_ADD_COLUMN_ACEE_CREDENTIAL_ID_STR =
    "ALTER TABLE accessee_table ADD COLUMN accesseeCredentialIdStr TEXT DEFAULT ''";
const std::string ALTER_TABLE_ACEE_ADD_COLUMN_ACEE_STATUS =
    "ALTER TABLE accessee_table ADD COLUMN accesseeStatus INTERGER DEFAULT -1";
const std::string ALTER_TABLE_ACEE_ADD_COLUMN_ACEE_SESSION_KEY_ID =
    "ALTER TABLE accessee_table ADD COLUMN accesseeSessionKeyId INTERGER DEFAULT -1";
const std::string ALTER_TABLE_ACEE_ADD_COLUMN_ACEE_SESSION_KEY_TIMESTAMP =
    "ALTER TABLE accessee_table ADD COLUMN accesseeSKTimeStamp INTERGER DEFAULT -1";
const std::string ALTER_TABLE_ACEE_ADD_COLUMN_ACEE_EXTRA_DATA =
    "ALTER TABLE accessee_table ADD COLUMN accesseeExtraData TEXT DEFAULT ''";
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
    accesserTokenId = ? and accesserBundleName = ? and accesserHapSignature = ? and accesserBindLevel = ? and \
    accesserDeviceName = ? and accesserServiceName = ? and accesserCredentialIdStr = ? and accesserStatus = ? and \
    accesserSessionKeyId = ? ";
const std::string SELECT_ACCESSEE_TABLE_WHERE_ALL =
    "SELECT * FROM accessee_table WHERE accesseeDeviceId = ? and accesseeUserId = ? and accesseeAccountId = ? and \
    accesseeTokenId = ? and accesseeBundleName = ? and accesseeHapSignature = ? and accesseeBindLevel = ? and \
    accesseeDeviceName = ? and accesseeServiceName = ? and accesseeCredentialIdStr = ? and accesseeStatus = ? and \
    accesseeSessionKeyId = ? ";
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
