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
const std::string PROFILE_DATA_RDB_PATH = "/data/service/el2/public/database/distributed_device_profile_service/";
const std::string PROFILE_DATA_DATABASE_NAME = "profile_data.db";
const std::string ID_EQUAL_CONDITION = "id = ?";
const std::string SELECT_DEVICE_PROFILE_TABLE = "SELECT * FROM device_profile WHERE ";
const std::string SELECT_DEVICE_PROFILE_TABLE_WHERE_DEVID_USERID_ACCOUNTID =
    "SELECT * FROM device_profile WHERE deviceId = ? AND udid = ? AND accountId = ?";
const std::string CREATE_DEVICE_PROFILE_TABLE_SQL = "CREATE TABLE IF NOT EXISTS device_profile\
(\
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,\
    deviceId                TEXT,\
    model                   TEXT,\
    devType                 TEXT,\
    manu                    TEXT,\
    sn                      TEXT,\
    productId               TEXT,\
    subProductId            TEXT,\
    hiv                     TEXT,\
    mac                     TEXT,\
    fwv                     TEXT,\
    hwv                     TEXT,\
    swv                     TEXT,\
    protType                INTEGER,\
    userId                  INTEGER,\
    accountId               TEXT,\
    wiseUserId              TEXT,\
    deviceName              TEXT,\
    wiseDeviceId            TEXT,\
    roomName                TEXT,\
    registerTime            TEXT,\
    modifyTime              INTEGER,\
    shareTime               TEXT,\
    productInfoVersion      TEXT,);";
const std::string CREATE_DEVICE_PROFILE_TABLE_UNIQUE_INDEX_SQL =
"CREATE UNIQUE INDEX if not exists unique_device_profile ON device_profile\
(\
    deviceId,\
    userId,\
    accountId,\
    productId);";
// DeviceIconInfoDao
const std::string CREATE_DEVICE_ICON_INFO_TABLE_SQL = "CREATE TABLE IF NOT EXISTS device_icon_info\
(id           INTEGER PRIMARY KEY AUTOINCREMENT,\
productId     TEXT,\
subProductId  TEXT,\
imageType     TEXT,\
specName      TEXT,\
version       TEXT,\
url           TEXT,\
icon          blob);";
const std::string CREATE_DEVICE_ICON_INFO_TABLE_UNIQUE_INDEX_SQL = "CREATE UNIQUE INDEX if not exists \
unique_device_icon_info ON device_icon_info (productId, subProductId, imageType, specName);";
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
    "CREATE INDEX characteristicKey_idx  ON characteristic_profile (characteristicKey);";
const std::string CREATE_CHARACTERISTIC_PROFILE_TABLE_INDEX_SQL_SERVICE_PROFILE_ID =
    "CREATE INDEX IF NOT EXISTS index_serviceProfileId  ON characteristic_profile (serviceProfileId);";
} // namespace DistributedDeviceProfile
} // namespace OHOS
