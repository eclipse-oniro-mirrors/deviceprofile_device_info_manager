/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef DEVICE_PROFILE_DP_COMMAND_H
#define DEVICE_PROFILE_DP_COMMAND_H

#include "shell_command.h"

#include <list>

#include "device_profile_log.h"
#include "iprofile_event_callback.h"

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
}  // namespace

class DpShellCommand : public OHOS::DeviceProfile::ShellCommand {
public:
    DpShellCommand(int argc, char *argv[]);
    ~DpShellCommand() override {}

private:
    ErrCode CreateCommandMap() override;
    ErrCode CreateMessageMap() override;
    ErrCode init() override;

    ErrCode HelpCommand();
    ErrCode GetDeviceCommand();
    ErrCode QueryCommand();
    ErrCode PutCommand();
    ErrCode DeleteCommand();
    ErrCode SyncCommand();
    ErrCode SubscribeCommand();

    int32_t HandleUnknownOption(char optopt);
    int32_t HandleNormalOption(int option, std::string& deviceId,
        std::string& serviceId, std::string& serviceType);
    int32_t HandleSyncOption(int option, std::string& mode,
        std::list<std::string>& deviceIds);
    int32_t HandleSubscribeOption(int option, std::string& deviceId,
        std::list<std::string>& serviceIds);
};

class ProfileEventCallback : public IProfileEventCallback {
public:
    void OnSyncCompleted(const SyncResult& syncResults) override
    {
        HILOGI("OnSyncCompleted");
    }

    void OnProfileChanged(const ProfileChangeNotification& changeNotification) override
    {
        HILOGI("OnProfileChanged");
    }
};
}  // namespace DeviceProfile
}  // namespace OHOS

#endif  // DEVICE_PROFILE_DP_COMMAND_H