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

#include "shell_command.h"

#include <errors.h>
#include <functional>
#include <getopt.h>
#include <map>
#include <string>
#include <vector>

#include "device_profile_log.h"

namespace OHOS {
namespace DeviceProfile {
namespace {
const std::string TAG = "ShellCommand";

const std::string HELP_MSG_NO_OPTION = "error: you must specify an option at least.";
}

ShellCommand::ShellCommand(int argc, char *argv[], std::string name)
{
    opterr = 0;
    argc_ = argc;
    argv_ = argv;
    name_ = name;

    if (argc < MIN_ARGUMENT_NUMBER) {
        cmd_ = "help";
        return;
    }
    cmd_ = argv[1];
    for (int i = 2; i < argc; i++) {
        argList_.push_back(argv[i]);
    }
}

ErrCode ShellCommand::OnCommand()
{
    int result = ERR_OK;

    auto respond = commandMap_[cmd_];
    if (respond == nullptr) {
        resultReceiver_.append(GetCommandErrorMsg());
        respond = commandMap_["help"];
    }

    if (init() == ERR_OK) {
        respond();
    } else {
        result = OHOS::ERR_INVALID_VALUE;
    }

    return result;
}

std::string ShellCommand::ExecCommand()
{
    int result = CreateCommandMap();
    if (result != ERR_OK) {
        HILOGE("failed to create command map.\n");
    }

    result = CreateMessageMap();
    if (result != ERR_OK) {
        HILOGE("failed to create message map.\n");
    }

    result = OnCommand();
    if (result != ERR_OK) {
        HILOGE("failed to execute your command.\n");
        resultReceiver_ = "error: failed to execute your command.\n";
    }

    return resultReceiver_;
}

std::string ShellCommand::GetCommandErrorMsg() const
{
    std::string commandErrorMsg =
        name_ + ": '" + cmd_ + "' is not a valid " + name_ + " command. See '" + name_ + " help'.\n";
    return commandErrorMsg;
}

std::string ShellCommand::GetUnknownOptionMsg(std::string &unknownOption) const
{
    std::string result = "";

    if (optind < 0 || optind > argc_) {
        return result;
    }

    result.append("error: unknown option");
    result.append(".\n");
    return result;
}

std::string ShellCommand::GetMessageFromCode(int32_t code) const
{
    HILOGI("[%{public}s(%{public}s)] enter", __FILE__, __FUNCTION__);
    HILOGI("code = %{public}d", code);

    std::string result = "";
    if (messageMap_.find(code) != messageMap_.end()) {
        std::string message = messageMap_.at(code);
        if (message.size() != 0) {
            result.append(message + "\n");
        }
    }
    HILOGI("result = %{public}s", result.c_str());
    return result;
}
}  // namespace DeviceProfile
}  // namespace OHOS