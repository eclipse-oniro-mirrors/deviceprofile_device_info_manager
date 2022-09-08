/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "device_profile_dumper.h"

#include "device_profile_log.h"
#include "device_profile_storage_manager.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace DeviceProfile {
namespace {
constexpr size_t MIN_ARGS_SIZE = 1;
const std::string ARGS_HELP = "-h";
const std::string TAG = "DeviceProfileDumper";
constexpr int32_t UID_HIDUMPER = 1212;
}

bool DeviceProfileDumper::DumpDefault(std::string& result)
{
    result.append("DeviceProfile Dump:\n");
    DeviceProfileStorageManager::GetInstance().DumpLocalProfile(result);
    return true;
}

bool DeviceProfileDumper::Dump(const std::vector<std::string>& args, std::string& result)
{
    result.clear();
    if (!CanDump()) {
        result.append("Dump failed, not allowed");
        return false;
    }

    if (args.size() < MIN_ARGS_SIZE) {
        return DumpDefault(result);
    }

    if (args.size() == MIN_ARGS_SIZE) {
        // -h
        if (args[0] == ARGS_HELP) {
            ShowHelp(result);
            return true;
        }
    }
    IllegalInput(result);
    return false;
}

void DeviceProfileDumper::ShowHelp(std::string& result)
{
    result.append("DeviceProfile Dump options:\n")
        .append("  [-h] [cmd]...\n");
}

void DeviceProfileDumper::IllegalInput(std::string& result)
{
    result.append("The arguments are illegal and you can enter '-h' for help.\n");
}

bool DeviceProfileDumper::CanDump()
{
    auto callingUid = IPCSkeleton::GetCallingUid();
    HILOGI("calling uid = %u", callingUid);
    if (callingUid != UID_HIDUMPER) {
        return false;
    }
    return true;
}
} // namespace DeviceProfile
} // namespace OHOS