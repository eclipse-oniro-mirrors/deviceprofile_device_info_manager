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

#include <cstring>
#include "content_sensor_manager_utils.h"
#include "parameter.h"
#include "distributed_device_profile_log.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "ContentSensorManagerUtils";
    const char* SYS_SETTINGS_DATA_SYNC = "persist.distributed_scene.sys_settings_data_sync";
    const char* UNDEFINED_VALUE = "undefined";
    const char* SYNC_TYPE_E2E = "1";
    constexpr int32_t DEVICE_UUID_LENGTH = 65;
    constexpr int32_t IT_BOOK_PARAM_LEN = 128;
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

std::string ContentSensorManagerUtils::ObtainManufacture()
{
    HILOGI("called!");
    std::lock_guard<std::mutex> lock(csMutex_);
    if (!manufacture_.empty()) {
        return manufacture_;
    }
    const char* manufactureTemp = GetManufacture();
    if (manufactureTemp == nullptr) {
        HILOGE("get manufacture failed!");
        return "";
    }
    manufacture_ = manufactureTemp;
    free((char*)manufactureTemp);
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

void ContentSensorManagerUtils::ObtainDeviceDataSyncMode()
{
    char isITBookparam[IT_BOOK_PARAM_LEN + 1] = {0};
    int ret = GetParameter(SYS_SETTINGS_DATA_SYNC, UNDEFINED_VALUE, isITBookparam, IT_BOOK_PARAM_LEN);
    if (ret > 0 && strncmp(isITBookparam, SYNC_TYPE_E2E, strlen(SYNC_TYPE_E2E)) == 0) {
        isDeviceE2ESync_.store(true);
        HILOGI("Determining the e2e device succeeded.");
        return;
    }
    HILOGW("Determining not is e2e device");
}

bool ContentSensorManagerUtils::IsDeviceE2ESync()
{
    return isDeviceE2ESync_.load();
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
