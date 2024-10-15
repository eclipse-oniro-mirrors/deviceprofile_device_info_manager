/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "dp_command.h"

#include <functional>
#include <getopt.h>
#include <istream>
#include <list>
#include <map>
#include <memory>
#include <sstream>
#include <streambuf>
#include <string>
#include <type_traits>
#include <unistd.h>

#include "device_profile_log.h"
#include "distributed_device_profile_client.h"
#include "iprofile_event_notifier.h"
#include "nlohmann/json.hpp"
#include "nlohmann/json_fwd.hpp"
#include "profile_event.h"
#include "service_characteristic_profile.h"
#include "softbus_bus_center.h"
#include "subscribe_info.h"
#include "sync_options.h"

namespace OHOS {
namespace DeviceProfile {
namespace {
const std::string TAG = "DpShellCommand";
const std::string DP_TOOL_NAME = "dp";
const std::string DP_HELP_MSG = "usage: dp <command> <options>\n"
                             "These are common dp commands list:\n"
                             "  help         list available commands\n"
                             "  getDevice    list all devices\n"
                             "  query        query device info with options\n"
                             "  put          put device info with options\n"
                             "  sync         sync device info with options\n"
                             "  delete       delete device info with options\n"
                             "  subscribe    subscribe device info with options\n";
const std::string HELP_MSG_QUERY =
    "usage: dp query <options>\n"
    "options list:\n"
    "  -h, --help                               list available commands\n"
    "  -d  <device-id>                          query device info by a device id\n"
    "  -s  <service-id>                         query device info by a service id\n";
const std::string HELP_MSG_SYNC =
    "usage: dp sync <options>\n"
    "options list:\n"
    "  -h, --help                               list available commands\n"
    "  -d  <device-ids>                         sync device info by a device ids\n"
    "  -m  <mode>                               sync device info by mode\n";
const std::string HELP_MSG_PUT =
    "usage: dp put <options>\n"
    "options list:\n"
    "  -h, --help                               list available commands\n"
    "  -s  <service-id>                         put device info by service id\n"
    "  -t  <service-type>                       put device info by service type\n";
const std::string HELP_MSG_SUBSCRIBE =
    "usage: dp subscribe <options>\n"
    "options list:\n"
    "  -h, --help                               list available commands\n"
    "  -s  <service-ids>                        subscribe device info by service ids\n"
    "  -d  <device-id>                          subscribe device info by device id\n";
const std::string HELP_MSG_DELETE =
    "usage: dp delete <options>\n"
    "options list:\n"
    "  -h, --help                               list available commands\n"
    "  -s  <service-id>                        service id to delete\n";
constexpr int32_t API_LEVEL = 7;
constexpr int32_t SYNC_SLEEP_TIME = 10;
constexpr int32_t BASE = 10;
constexpr int32_t SUBSCRIBE_SLEEP_TIME = 120;
const std::string SHORT_OPTIONS = "hd:s:m:t:";
const struct option LONG_OPTIONS[] = {
    {"help", no_argument, nullptr, 'h'},
    {"device-id", required_argument, nullptr, 'd'},
    {"service-id", required_argument, nullptr, 's'},
    {"mode", required_argument, nullptr, 'm'},
    {"service-type", required_argument, nullptr, 't'},
    {nullptr, nullptr, nullptr, nullptr},
};
}

DpShellCommand::DpShellCommand(int argc, char *argv[]) : ShellCommand(argc, argv, DP_TOOL_NAME)
{
}

ErrCode DpShellCommand::init()
{
    return ERR_OK;
}

ErrCode DpShellCommand::CreateCommandMap()
{
    commandMap_ = {
        {"help", std::bind(&DpShellCommand::HelpCommand, this)},
        {"getDevice", std::bind(&DpShellCommand::GetDeviceCommand, this)},
        {"query", std::bind(&DpShellCommand::QueryCommand, this)},
        {"put", std::bind(&DpShellCommand::PutCommand, this)},
        {"delete", std::bind(&DpShellCommand::DeleteCommand, this)},
        {"sync", std::bind(&DpShellCommand::SyncCommand, this)},
        {"subscribe", std::bind(&DpShellCommand::SubscribeCommand, this)},
    };
    return ERR_OK;
}

ErrCode DpShellCommand::CreateMessageMap()
{
    messageMap_ = {};
    return ERR_OK;
}

ErrCode DpShellCommand::HelpCommand()
{
    resultReceiver_.append(DP_HELP_MSG);
    return ERR_OK;
}

ErrCode DpShellCommand::GetDeviceCommand()
{
    resultReceiver_.append("[remote device list]\n");
    NodeBasicInfo *info = nullptr;
    int32_t infoNum = 0;
    int32_t ret = GetAllNodeDeviceInfo("dp", &info, &infoNum);
    if (ret != ERR_OK) {
        resultReceiver_.append("get remote device list error\n");
        return ret;
    }
    for (int32_t i = 0; i < infoNum; i++) {
        resultReceiver_.append("networkId: " + std::string(info->networkId)
            + " deviceName:" + std::string(info->deviceName) + "\n");
        info++;
    }

    resultReceiver_.append("[local device list]\n");
    NodeBasicInfo localInfo;
    ret = GetLocalNodeDeviceInfo("dp", &localInfo);
    if (ret != ERR_OK) {
        resultReceiver_.append("get local device error\n");
        return ret;
    }
    resultReceiver_.append("networkId: " + std::string(localInfo.networkId)
        + " deviceName:" + std::string(localInfo.deviceName) + "\n");
    return ERR_OK;
}

ErrCode DpShellCommand::QueryCommand()
{
    int32_t result = ERR_OK;
    std::string serviceType;
    std::string deviceId;
    std::string serviceId;
    while (true) {
        int option = getopt_long(argc_, argv_, SHORT_OPTIONS.c_str(), LONG_OPTIONS, nullptr);
        HILOGI("option: %{public}d, optopt: %{public}d, optind: %{public}d", option, optopt, optind);
        if (optind < 0 || optind > argc_) {
            return OHOS::ERR_INVALID_VALUE;
        }

        if (option == -1) {
            break;
        }
        result = HandleNormalOption(option, deviceId, serviceId, serviceType);
    }

    if (result == ERR_OK) {
        ServiceCharacteristicProfile profile;
        DistributedDeviceProfileClient::GetInstance().GetDeviceProfile(deviceId, serviceId, profile);
        std::string jsonData = profile.GetCharacteristicProfileJson();
        resultReceiver_.append("ServiceId:" + profile.GetServiceId() + "\n");
        resultReceiver_.append("ServiceType:" + profile.GetServiceType() + "\n");
        resultReceiver_.append("jsonData:" + jsonData + "\n");
    } else {
        resultReceiver_.append(HELP_MSG_QUERY);
    }
    return result;
}

ErrCode DpShellCommand::PutCommand()
{
    int32_t result = ERR_OK;
    std::string serviceType;
    std::string serviceId;
    std::string deviceId;
    while (true) {
        int option = getopt_long(argc_, argv_, SHORT_OPTIONS.c_str(), LONG_OPTIONS, nullptr);
        HILOGI("option: %{public}d, optopt: %{public}d, optind: %{public}d", option, optopt, optind);
        if (optind < 0 || optind > argc_) {
            return OHOS::ERR_INVALID_VALUE;
        }
        if (option == -1) {
            break;
        }
        result = HandleNormalOption(option, deviceId, serviceId, serviceType);
    }

    if (result == ERR_OK) {
        ServiceCharacteristicProfile profile;
        profile.SetServiceId(serviceId);
        profile.SetServiceType(serviceType);
        nlohmann::json j;
        j["testVersion"] = "3.0.0";
        j["testApiLevel"] = API_LEVEL;
        profile.SetCharacteristicProfileJson(j.dump());
        DistributedDeviceProfileClient::GetInstance().PutDeviceProfile(profile);
    } else {
        resultReceiver_.append(HELP_MSG_PUT);
    }
    return result;
}

ErrCode DpShellCommand::DeleteCommand()
{
    int32_t result = ERR_OK;
    std::string serviceType;
    std::string deviceId;
    std::string serviceId;

    while (true) {
        int option = getopt_long(argc_, argv_, SHORT_OPTIONS.c_str(), LONG_OPTIONS, nullptr);
        HILOGI("option: %{public}d, optopt: %{public}d, optind: %{public}d", option, optopt, optind);
        if (optind < 0 || optind > argc_) {
            return OHOS::ERR_INVALID_VALUE;
        }

        if (option == -1) {
            break;
        }
        result = HandleNormalOption(option, deviceId, serviceId, serviceType);
    }

    if (result == ERR_OK) {
        DistributedDeviceProfileClient::GetInstance().DeleteDeviceProfile(serviceId);
    } else {
        resultReceiver_.append(HELP_MSG_DELETE);
    }
    return result;
}

ErrCode DpShellCommand::SyncCommand()
{
    int32_t result = ERR_OK;
    std::list<std::string> deviceIds;
    std::string modeStr;
    while (true) {
        int option = getopt_long(argc_, argv_, SHORT_OPTIONS.c_str(), LONG_OPTIONS, nullptr);
        HILOGI("option: %{public}d, optopt: %{public}d, optind: %{public}d", option, optopt, optind);
        if (optind < 0 || optind > argc_) {
            return OHOS::ERR_INVALID_VALUE;
        }

        if (option == -1) {
            break;
        }
        result = HandleSyncOption(option, modeStr, deviceIds);
    }

    if (result == ERR_OK) {
        SyncOptions syncOption;
        int64_t mode = strtol(modeStr.c_str(), nullptr, BASE);
        syncOption.SetSyncMode((OHOS::DeviceProfile::SyncMode)mode);
        for (const auto& deviceId : deviceIds) {
            syncOption.AddDevice(deviceId);
        }
        DistributedDeviceProfileClient::GetInstance().SyncDeviceProfile(syncOption,
            std::make_shared<ProfileEventCallback>());
        sleep(SYNC_SLEEP_TIME);
        HILOGI("sync end");
    } else {
        resultReceiver_.append(HELP_MSG_SYNC);
    }
    return result;
}

ErrCode DpShellCommand::SubscribeCommand()
{
    int32_t result = ERR_OK;
    std::list<std::string> serviceIds;
    std::string deviceId;
    while (true) {
        int option = getopt_long(argc_, argv_, SHORT_OPTIONS.c_str(), LONG_OPTIONS, nullptr);
        HILOGI("option: %{public}d, optopt: %{public}d, optind: %{public}d", option, optopt, optind);
        if (optind < 0 || optind > argc_) {
            return OHOS::ERR_INVALID_VALUE;
        }

        if (option == -1) {
            break;
        }
        result = HandleSubscribeOption(option, deviceId, serviceIds);
    }

    if (result == ERR_OK) {
        auto callback = std::make_shared<ProfileEventCallback>();
        std::list<SubscribeInfo> subscribeInfos;
        ExtraInfo extraInfo;
        extraInfo["deviceId"] = deviceId;
        extraInfo["serviceIds"] = serviceIds;

        SubscribeInfo info1;
        info1.profileEvent = ProfileEvent::EVENT_PROFILE_CHANGED;
        info1.extraInfo = std::move(extraInfo);
        subscribeInfos.emplace_back(info1);

        SubscribeInfo info2;
        info2.profileEvent = ProfileEvent::EVENT_SYNC_COMPLETED;
        subscribeInfos.emplace_back(info2);

        std::list<ProfileEvent> failedEvents;
        DistributedDeviceProfileClient::GetInstance().SubscribeProfileEvents(subscribeInfos, callback, failedEvents);
        sleep(SUBSCRIBE_SLEEP_TIME);
        std::list<ProfileEvent> profileEvents;
        profileEvents.emplace_back(ProfileEvent::EVENT_PROFILE_CHANGED);
        failedEvents.clear();
        DistributedDeviceProfileClient::GetInstance().UnsubscribeProfileEvents(profileEvents, callback, failedEvents);
        sleep(SYNC_SLEEP_TIME);
    } else {
        resultReceiver_.append(HELP_MSG_SUBSCRIBE);
    }
    return result;
}

int32_t DpShellCommand::HandleNormalOption(int option, std::string& deviceId,
    std::string& serviceId, std::string& serviceType)
{
    HILOGI("%{public}s start, option: %{public}d", __func__, option);
    int32_t result = ERR_OK;
    switch (option) {
        case 'h': {
            HILOGI("'dp query' %{public}s", argv_[optind - 1]);
            result = OHOS::ERR_INVALID_VALUE;
            break;
        }
        case 'd': {
            if (optarg == nullptr) {
                resultReceiver_.append("error: option, requires a value\n");
                result = OHOS::ERR_INVALID_VALUE;
                break;
            }
            deviceId = optarg;
            break;
        }
        case 's': {
            if (optarg == nullptr) {
                resultReceiver_.append("error: option, requires a value\n");
                result = OHOS::ERR_INVALID_VALUE;
                break;
            }
            serviceId = optarg;
            break;
        }
        case 't': {
            if (optarg == nullptr) {
                resultReceiver_.append("error: option, requires a value\n");
                result = OHOS::ERR_INVALID_VALUE;
                break;
            }
            serviceType = optarg;
            break;
        }
        default: {
            result = OHOS::ERR_INVALID_VALUE;
            HILOGE("'dp query' invalid option.");
            break;
        }
    }
    return result;
}

int32_t DpShellCommand::HandleSyncOption(int option, std::string& mode, std::list<std::string>& deviceIds)
{
    HILOGI("%{public}s start, option: %{public}d", __func__, option);
    int32_t result = ERR_OK;
    switch (option) {
        case 'h': {
            HILOGI("'dp sync' %{public}s", argv_[optind - 1]);
            result = OHOS::ERR_INVALID_VALUE;
            break;
        }
        case 'd': {
            if (optarg == nullptr) {
                resultReceiver_.append("error: option, requires a value\n");
                result = OHOS::ERR_INVALID_VALUE;
                break;
            }
            std::stringstream input(optarg);
            std::string temp;
            while (std::getline(input, temp, ' ')) {
                deviceIds.push_back(temp);
            }
            break;
        }
        case 'm': {
            if (optarg == nullptr) {
                resultReceiver_.append("error: option, requires a value\n");
                result = OHOS::ERR_INVALID_VALUE;
                break;
            }
            mode = optarg;
            break;
        }
        default: {
            result = OHOS::ERR_INVALID_VALUE;
            HILOGE("'dp sync' invalid option.");
            break;
        }
    }
    return result;
}

int32_t DpShellCommand::HandleSubscribeOption(int option, std::string& deviceId,
    std::list<std::string>& serviceIds)
{
    HILOGI("%{public}s start, option: %{public}d", __func__, option);
    int32_t result = ERR_OK;
    switch (option) {
        case 'h': {
            HILOGI("'dp subscribe' %{public}s", argv_[optind - 1]);
            result = OHOS::ERR_INVALID_VALUE;
            break;
        }
        case 's': {
            if (optarg == nullptr) {
                resultReceiver_.append("error: option, requires a value\n");
                result = OHOS::ERR_INVALID_VALUE;
                break;
            }
            std::stringstream input(optarg);
            std::string temp;
            while (std::getline(input, temp, ' ')) {
                serviceIds.push_back(temp);
            }
            break;
        }
        case 'd': {
            if (optarg == nullptr) {
                resultReceiver_.append("error: option, requires a value\n");
                result = OHOS::ERR_INVALID_VALUE;
                break;
            }
            deviceId = optarg;
            break;
        }
        default: {
            result = OHOS::ERR_INVALID_VALUE;
            HILOGE("'dp subscribe' invalid option.");
            break;
        }
    }
    return result;
}

void ProfileEventCallback::OnSyncCompleted(const SyncResult& syncResults)
{
    HILOGI("OnSyncCompleted");
}

void ProfileEventCallback::OnProfileChanged(const ProfileChangeNotification& changeNotification)
{
    HILOGI("OnProfileChanged");
}
}  // namespace DeviceProfile
}  // namespace OHOS