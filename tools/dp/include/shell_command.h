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

#ifndef DEVICE_PROFILE_SHELL_COMMAND_H
#define DEVICE_PROFILE_SHELL_COMMAND_H

#include <cstdint>
#include <functional>
#include <iosfwd>
#include <map>
#include <stdint.h>
#include <string>
#include <vector>

#include "errors.h"

namespace OHOS {
namespace DeviceProfile {
class ShellCommand {
public:
    ShellCommand(int argc, char *argv[], std::string name);
    virtual ~ShellCommand()  = default;

    ErrCode OnCommand();
    std::string ExecCommand();
    std::string GetCommandErrorMsg() const;
    std::string GetUnknownOptionMsg(std::string &unknownOption) const;
    std::string GetMessageFromCode(int32_t code) const;

    virtual ErrCode CreateCommandMap() = 0;
    virtual ErrCode CreateMessageMap() = 0;
    virtual ErrCode init() = 0;

protected:
    static constexpr int MIN_ARGUMENT_NUMBER = 2;

    int argc_;
    char **argv_;

    std::string cmd_;
    std::vector<std::string> argList_;

    std::string name_;
    std::map<std::string, std::function<int()>> commandMap_;
    std::map<int32_t, std::string> messageMap_;

    std::string resultReceiver_ = "";
};
}  // namespace DeviceProfile
}  // namespace OHOS

#endif  // DEVICE_PROFILE_SHELL_COMMAND_H