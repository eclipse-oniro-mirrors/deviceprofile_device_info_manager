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

#include "content_sensor_manager_utils.h"

#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>

#include "cJSON.h"
#include "config_policy_utils.h"
#include "parameter.h"
#include "parameters.h"
#include "softbus_bus_center.h"
#include "softbus_error_code.h"

#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "ContentSensorManagerUtils";
    const char* SYS_SETTINGS_DATA_SYNC = "persist.distributed_scene.sys_settings_data_sync";
    const char* ENTERPRISE_SPACE_ENABLE_PARAM = "persist.space_mgr_service.enterprise_space_enable";
    const char* PRODUCT_ID_KEY = "const.distributed_collaboration.productId";
    const char* UNDEFINED_VALUE = "undefined";
    const char* SYNC_TYPE_E2E = "1";
    const char* MANUFACTURER_KEY = "const.product.manufacturer";
    constexpr int32_t DEVICE_UUID_LENGTH = 65;
    constexpr int32_t SYS_SETTINGS_DATA_SYNC_PARAM_LEN = 128;
    constexpr int32_t PROT_TYPE_WIFI_ONLY = 1;
    constexpr int32_t PROT_TYPE_MOBILIE_NETWORK_AND_WIFI = 18;
    constexpr const char* WIFI_ONLY_DEVICE_TREE_PROC_NODE_NAME = "/proc/device-tree/singleap_wifionly/is_wifionly";
    constexpr const char* WIFI_ONLY_FLAG_VALUE = "1";
    constexpr int32_t WIFI_ONLY_FLAG_VALUE_MAX_LEN = 8;
    const char* OHOS_BOOT_BACKCOLOR = "ohos.boot.backcolor";
    constexpr const char* SUB_PROD_ID_CONFIG = "etc/CollaborationFwk/sub_prodId_config.json";
    constexpr int32_t MAX_SUB_PROD_ID_SIZE = 500;
    constexpr size_t MAX_CONFIG_FILE_SIZE = 4 * 1024 * 1024;
    const std::string MANU_NAME = "485541574549";
    const std::string MANU_CODE = "001";
}
IMPLEMENT_SINGLE_INSTANCE(ContentSensorManagerUtils);
std::string ContentSensorManagerUtils::ObtainProductModel()
{
    HILOGI("called!");
    std::lock_guard<std::mutex> lock(csMutex_);
    if (!deviceModel_.empty()) {
        return deviceModel_;
    }
    const char* productModelTemp = GetProductModel();
    if (productModelTemp == nullptr) {
        HILOGE("get productModel failed!");
        return "";
    }
    deviceModel_ = productModelTemp;
    free((char*)productModelTemp);
    return deviceModel_;
}

std::string ContentSensorManagerUtils::ObtainDeviceType()
{
    HILOGI("called!");
    std::lock_guard<std::mutex> lock(csMutex_);
    if (!deviceType_.empty()) {
        return deviceType_;
    }
    const char* deviceTypeTemp = GetDeviceType();
    if (deviceTypeTemp == nullptr) {
        HILOGE("get deviceType failed!");
        return "";
    }
    deviceType_ = deviceTypeTemp;
    free((char*)deviceTypeTemp);
    return deviceType_;
}

std::string ContentSensorManagerUtils::ObtainDeviceTypeId()
{
    {
        std::lock_guard<std::mutex> lock(csMutex_);
        if (!deviceTypeId_.empty()) {
            return deviceTypeId_;
        }
    }
    NodeBasicInfo nodeBasicInfo;
    int32_t ret = GetLocalNodeDeviceInfo(DP_PKG_NAME.c_str(), &nodeBasicInfo);
    if (ret != SOFTBUS_OK) {
        HILOGE("GetLocalNodeDeviceInfo from dsofbus fail, ret=%{public}d", ret);
        return "";
    }
    uint16_t deviceTypeId = nodeBasicInfo.deviceTypeId;
    std::stringstream strDeviceTypeId;
    strDeviceTypeId << std::uppercase << std::setw(NUM_3) << std::setfill('0') << std::hex << deviceTypeId;
    std::lock_guard<std::mutex> lock(csMutex_);
    deviceTypeId_ = strDeviceTypeId.str();
    return deviceTypeId_;
}

std::string ContentSensorManagerUtils::ObtainManufacture()
{
    HILOGI("called!");
    std::lock_guard<std::mutex> lock(csMutex_);
    if (!manufacture_.empty()) {
        return manufacture_;
    }
    std::string manufactureTemp = system::GetParameter(MANUFACTURER_KEY, "");
    HILOGI("get manufacture from system, manufacture = %{public}s", manufactureTemp.c_str());
    if (manufactureTemp == DecodeHexStr(MANU_NAME)) {
        manufactureTemp = MANU_CODE;
    }
    if (manufactureTemp.empty()) {
        HILOGE("get manufacture failed!");
        return "";
    }
    manufacture_ = manufactureTemp;
    return manufacture_;
}

std::string ContentSensorManagerUtils::ObtainSerial()
{
    HILOGI("called!");
    std::lock_guard<std::mutex> lock(csMutex_);
    if (!serial_.empty()) {
        return serial_;
    }
    const char* serialTemp = GetSerial();
    if (serialTemp == nullptr) {
        HILOGE("get serial failed!");
        return "";
    }
    serial_ = serialTemp;
    free((char*)serialTemp);
    return serial_;
}

std::string ContentSensorManagerUtils::ObtainMarketName()
{
    HILOGI("called!");
    std::lock_guard<std::mutex> lock(csMutex_);
    if (!marketName_.empty()) {
        return marketName_;
    }
    const char* marketNameTemp = GetMarketName();
    if (marketNameTemp == nullptr) {
        HILOGE("get marketName failed!");
        return "";
    }
    marketName_ = marketNameTemp;
    free((char*)marketNameTemp);
    return marketName_;
}

std::string ContentSensorManagerUtils::ObtainOsFullName()
{
    HILOGI("called!");
    std::lock_guard<std::mutex> lock(csMutex_);
    if (!osFullName_.empty()) {
        return osFullName_;
    }
    const char* osFullNameTemp = GetOSFullName();
    if (osFullNameTemp == nullptr) {
        HILOGE("get osFullName failed!");
        return "";
    }
    osFullName_ = osFullNameTemp;
    free((char*)osFullNameTemp);
    return osFullName_;
}

std::string ContentSensorManagerUtils::ObtainDisplayVersion()
{
    HILOGI("called!");
    std::lock_guard<std::mutex> lock(csMutex_);
    if (!displayVersion_.empty()) {
        return displayVersion_;
    }
    const char* displayVersionTemp = GetDisplayVersion();
    if (displayVersionTemp == nullptr) {
        HILOGE("get displayVersion failed!");
        return "";
    }
    displayVersion_ = displayVersionTemp;
    free((char*)displayVersionTemp);
    return displayVersion_;
}

std::string ContentSensorManagerUtils::ObtainLocalUdid()
{
    std::lock_guard<std::mutex> lock(csMutex_);
    if (!localUdid_.empty()) {
        return localUdid_;
    }
    HILOGD("GetDevUdid");
    char localUdidTemp[DEVICE_UUID_LENGTH] = {0};
    GetDevUdid(localUdidTemp, DEVICE_UUID_LENGTH);
    localUdid_ = localUdidTemp;
    return localUdid_;
}

std::string ContentSensorManagerUtils::ObtainProductId()
{
    HILOGI("called!");
    std::lock_guard<std::mutex> lock(csMutex_);
    if (!productId_.empty()) {
        return productId_;
    }
    std::string productIdTemp = system::GetParameter(PRODUCT_ID_KEY, "");
    if (productIdTemp.empty()) {
        HILOGE("get productId failed!");
        return "";
    }
    productId_ = productIdTemp;
    if (productId_.size() > NUM_1) {
        productId_.pop_back();
    }
    return productId_;
}

void ContentSensorManagerUtils::ObtainDeviceDataSyncMode()
{
    char isE2EDeviceParam[SYS_SETTINGS_DATA_SYNC_PARAM_LEN + 1] = {0};
    int ret = GetParameter(SYS_SETTINGS_DATA_SYNC, UNDEFINED_VALUE, isE2EDeviceParam,
        SYS_SETTINGS_DATA_SYNC_PARAM_LEN);
    if (ret > 0 && strncmp(isE2EDeviceParam, SYNC_TYPE_E2E, strlen(SYNC_TYPE_E2E)) == 0) {
        isDeviceE2ESync_.store(true);
        HILOGI("Determining the e2e device succeeded.");
        return;
    }
    HILOGW("Determining is not e2e device");
}

bool ContentSensorManagerUtils::IsDeviceE2ESync()
{
    return isDeviceE2ESync_.load();
}

int32_t ContentSensorManagerUtils::GetProtType()
{
    std::lock_guard<std::mutex> lock(csMutex_);
    if (protType_ > 0) {
        return protType_;
    }
    if (IsWifiOnly()) {
        protType_ = PROT_TYPE_WIFI_ONLY;
    } else {
        protType_ = PROT_TYPE_MOBILIE_NETWORK_AND_WIFI;
    }
    HILOGI("protType:%{public}d", protType_);
    return protType_;
}

bool ContentSensorManagerUtils::IsWifiOnly()
{
    char buf[WIFI_ONLY_FLAG_VALUE_MAX_LEN] = {0};
    FILE *fp = nullptr;
    if ((fp = fopen(WIFI_ONLY_DEVICE_TREE_PROC_NODE_NAME, "r")) == nullptr) {
        HILOGE("open wifi only device tree proc node fail");
        return false;
    }
    if (fgets(buf, WIFI_ONLY_FLAG_VALUE_MAX_LEN, fp) == nullptr) {
        HILOGE("fgets return nullptr");
        if (fclose(fp) != 0) {
            HILOGE("Close file failed");
        }
        return false;
    }
    if (strcmp(buf, WIFI_ONLY_FLAG_VALUE)) {
        HILOGE("buf not equal WIFI_ONLY_FLAG_VALUE");
        if (fclose(fp) != 0) {
            HILOGE("Close file failed");
        }
        return false;
    }
    if (fclose(fp) != 0) {
        HILOGE("Close file failed");
    }
    return true;
}

std::string ContentSensorManagerUtils::GetSubProductId()
{
    std::string backcolor = GetBackcolor();
    std::map<std::string, std::string> subProdIdMap = GetSubProdIdMap();
    if (backcolor.empty() || subProdIdMap.empty() || subProdIdMap.find(backcolor) == subProdIdMap.end()) {
        HILOGE("subProdIdMap not found backcolor: %{public}s", backcolor.c_str());
        return EMPTY_STRING;
    }
    std::string subProdId = subProdIdMap[backcolor];
    HILOGI("backcolor: %{public}s, subProdId: %{public}s", backcolor.c_str(), subProdId.c_str());
    return subProdId;
}

std::string ContentSensorManagerUtils::GetBackcolor()
{
    std::lock_guard<std::mutex> lock(csMutex_);
    if (!backcolor_.empty()) {
        return backcolor_;
    }
    std::string temp = system::GetParameter(OHOS_BOOT_BACKCOLOR, "");
    if (temp.empty()) {
        HILOGE("get backcolor failed!");
        return "";
    }
    backcolor_ = temp;
    return backcolor_;
}

int32_t ContentSensorManagerUtils::LoadJsonFile(const std::string &filePath, std::string &fileContent)
{
    if (filePath.empty() || filePath.size() > MAX_STRING_LEN) {
        HILOGE("filePath is invalid!");
        return DP_INVALID_PARAM;
    }
    char buf[MAX_PATH_LEN] = {0};
    char *srcPath = GetOneCfgFile(filePath.c_str(), buf, MAX_PATH_LEN);
    if (srcPath == nullptr) {
        HILOGE("srcPath is invalid!");
        return DP_LOAD_JSON_FILE_FAIL;
    }
    char targetPath[PATH_MAX + 1] = {0x00};
    if (strlen(srcPath) == 0 || strlen(srcPath) > PATH_MAX || realpath(srcPath, targetPath) == nullptr) {
        HILOGE("File canonicalization failed!");
        return DP_LOAD_JSON_FILE_FAIL;
    }
    std::ifstream ifs(targetPath);
    if (!ifs.is_open()) {
        HILOGE("load json file failed");
        return DP_LOAD_JSON_FILE_FAIL;
    }
    ifs.seekg(0, std::ios::end);
    size_t fileSize = ifs.tellg();
    ifs.seekg(0, std::ios::beg);
    if (fileSize > MAX_CONFIG_FILE_SIZE) {
        HILOGE("config file too large: %zu", fileSize);
        ifs.close();
        return DP_LOAD_JSON_FILE_FAIL;
    }
    fileContent.reserve(fileSize);
    fileContent.assign(std::istreambuf_iterator<char>{ifs}, std::istreambuf_iterator<char>{});
    ifs.close();
    return DP_SUCCESS;
}

std::map<std::string, std::string> ContentSensorManagerUtils::GetSubProdIdMap()
{
    std::lock_guard<std::mutex> lock(csMutex_);
    if (!subProdIdMap_.empty()) {
        return subProdIdMap_;
    }
    std::string fileContent;
    if (LoadJsonFile(SUB_PROD_ID_CONFIG, fileContent) != DP_SUCCESS || fileContent.empty()) {
        HILOGE("load subProdId config failed");
        return {};
    }
    cJSON* jsonArr = cJSON_Parse(fileContent.c_str());
    if (!cJSON_IsArray(jsonArr)) {
        HILOGW("cJSON_Parse subProdId config fail!");
        cJSON_Delete(jsonArr);
        return {};
    }
    cJSON *item = NULL;
    cJSON_ArrayForEach(item, jsonArr) {
        if (!cJSON_IsObject(item)) {
            HILOGE("Item is not object!");
            continue;
        }
        if (!cJSON_IsString(item->child)) {
            HILOGE("first child is not string!");
            continue;
        }
        if (subProdIdMap_.size() > MAX_SUB_PROD_ID_SIZE) {
            HILOGE("subProdIdMap_ size more than limit");
            break;
        }
        subProdIdMap_[item->child->string] = item->child->valuestring;
    }
    cJSON_Delete(jsonArr);
    return subProdIdMap_;
}

std::string ContentSensorManagerUtils::DecodeHexStr(const std::string &str)
{
    if (str.empty() || str.length() % NUM_2 != 0) {
        HILOGE("str.length:%{public}zu is not an even number.", str.length());
        return EMPTY_STRING;
    }
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < str.length(); i += NUM_2) {
        std::string byteStr = str.substr(i, NUM_2);
        long result = strtol(byteStr.c_str(), nullptr, NUM_16);
        if (result == LONG_MIN || result == LONG_MAX) {
            HILOGE("decode hexstring error.");
            return EMPTY_STRING;
        }
        uint8_t byte = (uint8_t)result;
        bytes.push_back(byte);
    }
    if (bytes.empty()) {
        HILOGE("bytes is empty");
        return EMPTY_STRING;
    }
    return std::string(bytes.begin(), bytes.end());
}

bool ContentSensorManagerUtils::IsEnterpriseSpaceEnable()
{
    return system::GetBoolParameter(ENTERPRISE_SPACE_ENABLE_PARAM, false);
}


} // namespace DistributedDeviceProfile
} // namespace OHOS
