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

#include "dp_services_constants.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "DpServicesConstants";
}
/* DeviceProfileDao */
const std::string PROFILE_DATA_RDB_PATH = "/data/service/el1/public/database/distributed_device_profile_service/";
const std::string PROFILE_DATA_DATABASE_NAME = "profile_data.db";
const std::string SERVICE_INFO_PROFILE_RDB_PATH =
    "/data/service/el1/public/database/distributed_device_profile_service/";
const std::string SERVICE_INFO_PROFILE_DATABASE_NAME = "service_info_store.db";
const std::string ID_EQUAL_CONDITION = "id = ?";
const std::string SELECT_DEVICE_PROFILE_TABLE = "SELECT * FROM device_profile WHERE ";
const std::string SELECT_DEVICE_PROFILE_TABLE_WHERE_DEVID_USERID =
    "SELECT * FROM device_profile WHERE deviceId = ? AND userId = ?";
const std::string CREATE_DEVICE_PROFILE_TABLE_SQL =
    "CREATE TABLE IF NOT EXISTS device_profile (\n"
    "    id                 INTEGER PRIMARY KEY AUTOINCREMENT,\n"
    "    deviceId           TEXT    NOT NULL,\n"
    "    userId             INTEGER,\n"
    "    accountId          TEXT,\n"
    "    productId          TEXT,\n"
    "    subProductId       TEXT,\n"
    "    model              TEXT,\n"
    "    devType            TEXT,\n"
    "    deviceName         TEXT,\n"
    "    manu               TEXT,\n"
    "    sn                 TEXT,\n"
    "    hiv                TEXT,\n"
    "    mac                TEXT,\n"
    "    bleMac             TEXT,\n"
    "    brMac              TEXT,\n"
    "    sleMac             TEXT,\n"
    "    fwv                TEXT,\n"
    "    hwv                TEXT,\n"
    "    swv                TEXT,\n"
    "    protType           INTEGER,\n"
    "    setupType          INTEGER,\n"
    "    wiseUserId         TEXT,\n"
    "    wiseDeviceId       TEXT,\n"
    "    registerTime       TEXT,\n"
    "    modifyTime         TEXT,\n"
    "    shareTime          TEXT,\n"
    "    internalModel      TEXT,\n"
    "    productName        TEXT\n"
    ")";
const std::string CREATE_DEVICE_PROFILE_TABLE_UNIQUE_INDEX_SQL =
    "CREATE UNIQUE INDEX IF NOT EXISTS unique_device_profile  ON device_profile (deviceId, userId)";
const std::string CREATE_DEVICE_PROFILE_WISE_DEVICEID_INDEX_SQL =
    "CREATE INDEX IF NOT EXISTS index_wiseDeviceId  ON device_profile (wiseDeviceId)";
const std::string ALTER_TABLE_DP_RENAME_COLUMN_INTERNAL_MODEL_SQL =
    "ALTER TABLE device_profile RENAME COLUMN innerModel TO internalModel";
const std::string ALTER_TABLE_DP_ADD_COLUMN_PRODUCT_NAME_SQL = "ALTER TABLE device_profile ADD COLUMN productName TEXT";
// DeviceIconInfoDao
const std::string CREATE_DEVICE_ICON_INFO_TABLE_SQL = "CREATE TABLE IF NOT EXISTS device_icon_info\
    (id           INTEGER PRIMARY KEY AUTOINCREMENT,\
    productId     TEXT,\
    subProductId  TEXT,\
    imageType     TEXT,\
    specName      TEXT,\
    version       TEXT,\
    url           TEXT,\
    icon          blob,\
    internalModel    TEXT);";
const std::string CREATE_DEVICE_ICON_INFO_TABLE_UNIQUE_INDEX_SQL = "CREATE UNIQUE INDEX if not exists \
    unique_device_icon_info ON device_icon_info (productId, subProductId, imageType, specName);";
const std::string ALTER_TABLE_DEVICE_ICON_INFO_ADD_COLUMN_INTENAL_MODEL_SQL =
    "ALTER TABLE device_icon_info ADD COLUMN internalModel TEXT";
const std::string SELECT_DEVICE_ICON_INFO_TABLE = "SELECT a.*,b.imageVersion FROM device_icon_info a \
    LEFT JOIN product_info b ON a.productId = b.productId \
    WHERE ";
// ProductInfoDao
const std::string CREATE_PRODUCT_INFO_TABLE_SQL = "CREATE TABLE IF NOT EXISTS product_info \
    (productId          TEXT PRIMARY KEY,\
    model               TEXT,\
    productName         TEXT,\
    productShortName    TEXT,\
    imageVersion        TEXT);";
const std::string SELECT_PRODUCT_INFO_TABLE = "SELECT * FROM product_info WHERE ";
/* ServiceProfileDao */
const std::string SELECT_SERVICE_PROGILES =
    "SELECT sp.*, dp.deviceId, dp.userId FROM service_profile sp \
    LEFT JOIN device_profile dp ON dp.id=sp.deviceProfileId WHERE ";
const std::string  CREATE_SERVICE_PROFILE_TABLE_SQL =
    "CREATE TABLE IF NOT EXISTS service_profile (\n"
    "                                               id              INTEGER PRIMARY KEY AUTOINCREMENT,\n"
    "                                               deviceProfileId INTEGER NOT NULL,\n"
    "                                               serviceId       TEXT    NOT NULL,\n"
    "                                               serviceType     TEXT,\n"
    "                                               FOREIGN KEY (\n"
    "                                                            deviceProfileId\n"
    "                                                   )\n"
    "                                                   REFERENCES device_profile (id)\n"
    ")";
const std::string  CREATE_SERVICE_PROFILE_TABLE_INDEX_SERVICEID_SQL =
    "CREATE INDEX if not exists serviceId_idx ON service_profile (serviceId)";
const std::string  CREATE_SERVICE_PROFILE_TABLE_INDEX_DEVICEPROFILEID_SQL =
    "CREATE INDEX if not exists deviceProfileId_idx ON service_profile (deviceProfileId)";
const std::string  SELECT_SERVICE_PROFILE_TABLE_WHERE_DEVID_SERID_SERTYPE =
    "SELECT * FROM service_profile WHERE deviceProfileId = ? AND serviceId = ? AND serviceType = ?";
// CharateristicProfileDao
const std::string SELECT_CHARACTERISTIC_PROFILE_TABLE_MAX_ID =
    "SELECT * FROM characteristic_profile WHERE serviceProfileId = ? AND characteristicKey = ? \
    AND characteristicValue = ?";
const std::string SELECT_CHARACTERISTIC_PROFILE_TABLE = "SELECT cp.*,sp.serviceId,dp.deviceId,dp.userId\
    from characteristic_profile cp\
    left join service_profile sp on cp.serviceProfileId=sp.id\
    left join device_profile dp on dp.id=sp.deviceProfileId WHERE ";
const std::string CREATE_CHARACTERISTIC_PROFILE_TABLE_SQL = "CREATE TABLE IF NOT EXISTS characteristic_profile (\
        id                  INTEGER PRIMARY KEY AUTOINCREMENT,\
        serviceProfileId    INTEGER NOT NULL,\
        characteristicKey   TEXT    NOT NULL,\
        characteristicValue TEXT    NOT NULL,\
        FOREIGN KEY (serviceProfileId)\
        REFERENCES service_profile (id)\
    );";
const std::string CREATE_CHARACTERISTIC_PROFILE_TABLE_INDEX_SQL_CHARACTERISTIC_KEY =
    "CREATE INDEX IF NOT EXISTS index_characteristicKey  ON characteristic_profile (characteristicKey)";
const std::string CREATE_CHARACTERISTIC_PROFILE_TABLE_INDEX_SQL_SERVICE_PROFILE_ID =
    "CREATE INDEX IF NOT EXISTS index_serviceProfileId  ON characteristic_profile (serviceProfileId)";
// ServiceInfoProfile
const std::string SERVICE_INFO_PROFILE_TABLE = "service_info_profile";
const std::string CREATE_SERVICE_INFO_PROFILE_TABLE_SQL =
    "CREATE TABLE IF NOT EXISTS service_info_profile (\n"
    "    deviceId TEXT,\n"
    "    userId INTEGER,\n"
    "    networkId TEXT,\n"
    "    tokenId TEXT,\n"
    "    serviceId INTEGER,\n"
    "    serviceType TEXT,\n"
    "    serviceName TEXT,\n"
    "    serviceDisplayName TEXT,\n"
    "    customData TEXT,\n"
    "    customDataLen INTEGER,\n"
    "    bundleName TEXT,\n"
    "    moduleName TEXT,\n"
    "    abilityName TEXT,\n"
    "    authBoxType INTEGER,\n"
    "    authType INTEGER,\n"
    "    pinExchangeType INTEGER,\n"
    "    pinCode TEXT,\n"
    "    description TEXT,\n"
    "    serviceDicoveryScope TEXT,\n"
    "    extraInfo TEXT\n"
    ")";
const std::string CREATE_SERVICE_INFO_PROFILE_TABLE_UNIQUE_INDEX_SQL =
    "CREATE UNIQUE INDEX IF NOT EXISTS unique_service_info_profile ON service_info_profile "
    "(deviceId, userId, tokenId, serviceId)";
const std::string SERVICE_INFO_PROFILE_UNIQUE_INDEX_EQUAL_CONDITION =
    "deviceId = ? AND userId = ? AND tokenId = ? AND serviceId = ?";
const std::string SELECT_SERVICE_INFO_PROFILE_ALL =
    "SELECT * FROM service_info_profile;";
const std::string SELECT_SERVICE_INFO_PROFILE_TABLE_WHERE_DEVID_USERID_TOKENID_SERVICEID =
    "SELECT * FROM service_info_profile WHERE deviceId = ? AND userId = ? AND tokenId = ? AND serviceId = ?";
const std::string SELECT_SERVICE_INFO_PROFILE_TABLE_WHERE_DEVID_USERID_TOKENID =
    "SELECT * FROM service_info_profile WHERE deviceId = ? AND userId = ? AND tokenId = ?";
const std::string SELECT_SERVICE_INFO_PROFILE_TABLE_WHERE_DEVID_USERID_BUNDLENAME =
    "SELECT * FROM service_info_profile WHERE deviceId = ? AND userId = ? AND bundleName = ?";
// LocalServiceInfo
const std::string LOCAL_SERVICE_INFO_RDB_PATH =
    "/data/service/el1/public/database/distributed_device_profile_service/";
const std::string LOCAL_SERVICE_INFO_DATABASE_NAME = "local_service_info_store.db";
const std::string LOCAL_SERVICE_INFO_TABLE = "local_service_info";
const std::string CREATE_LOCAL_SERVICE_INFO_TABLE_UNIQUE_INDEX_SQL =
    "CREATE UNIQUE INDEX IF NOT EXISTS unique_local_service_info ON local_service_info "
    "(bundleName, pinExchangeType)";
const std::string CREATE_LOCAL_SERVICE_INFO_TABLE_SQL =
    "CREATE TABLE IF NOT EXISTS local_service_info (\n"
    "    bundleName TEXT,\n"
    "    authBoxType INTEGER,\n"
    "    authType INTEGER,\n"
    "    pinExchangeType INTEGER,\n"
    "    pinCode TEXT,\n"
    "    description TEXT,\n"
    "    extraInfo TEXT\n"
    ")";
const std::string LOCAL_SERVICE_INFO_UNIQUE_INDEX_EQUAL_CONDITION =
    "bundleName = ? AND pinExchangeType = ?";
const std::string SELECT_LOCAL_SERVICE_INFO_WHERE_BUNDLENAME_PINEXCHANGETYPE =
    "SELECT * FROM local_service_info WHERE bundleName = ? AND pinExchangeType = ?";
} // namespace DistributedDeviceProfile
} // namespace OHOS
