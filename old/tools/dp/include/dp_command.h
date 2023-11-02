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

#include <iosfwd>
#include <list>
#include <stdint.h>

#include "device_profile_log.h"
#include "errors.h"
#include "iprofile_event_callback.h"
#include "shell_command.h"

namespace OHOS {
namespace DeviceProfile {
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
    void OnSyncCompleted(const SyncResult& syncResults) override;
    void OnProfileChanged(const ProfileChangeNotification& changeNotification) override;
};
}  // namespace DeviceProfile
}  // namespace OHOS

#endif  // DEVICE_PROFILE_DP_COMMAND_H