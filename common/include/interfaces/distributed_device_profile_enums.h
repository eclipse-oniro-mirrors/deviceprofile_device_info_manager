/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_DP_DISTRIBUTED_DEVICE_PROFILE_ENUMS_H
#define OHOS_DP_DISTRIBUTED_DEVICE_PROFILE_ENUMS_H

#include <string>
#include <unordered_map>

namespace OHOS {
namespace DistributedDeviceProfile {
enum class DeviceIdType : uint32_t {
    MIN = 0,
    UDID = 1,
    UUID = 2,
    SN = 3,
    MAX = 4
};
enum class AuthenticationType : uint32_t {
    MIN = 0,
    TEMPORARY = 1,
    PERMANENT = 2,
    MAX = 3
};
enum class BindType : uint32_t {
    MIN = 0,
    SAME_ACCOUNT = 1,
    SHARE = 2,
    SAME_GROUP = 3,
    POINT_TO_POINT = 256,
    COMPATIBLE = 512,
    DIFF_ACCOUNT = 1282,
    MAX = 1283
};
enum class BindLevel : uint32_t {
    MIN = 0,
    USER = 1,
    SERVICE = 2,
    APP = 3,
    MAX = 4
};
enum class Status : int32_t {
    MIN = -1,
    INACTIVE = 0,
    ACTIVE = 1,
    MAX = 2
};
enum class QueryType : int32_t {
    MIN = -1,
    ACER_AND_ACEE_TOKENID = 0,
    ACER_TOKENID = 1,
    MAX = 2
};
enum SyncStatus {
    SUCCEEDED = 0,
    FAILED = 1,
};
enum class SyncMode : int64_t {
    MIN = -1,
    PULL = 0,
    PUSH = 1,
    PUSH_PULL = 2,
    MAX = 3,
};
enum ProfileType {
    PROFILE_TYPE_MIN = 0x00,
    TRUST_DEVICE_PROFILE = 0x10,
    ACCESS_CONTROL_PROFILE = 0x20,
    DEVICE_PROFILE = 0x30,
    SERVICE_PROFILE = 0x40,
    CHAR_PROFILE = 0x50,
    PROFILE_TYPE_MAX = 0x60
};
enum ChangeType {
    CHANGE_TYPE_MIN = 0,
    ADD = 1,
    UPDATE = 2,
    DELETE = 3,
    CHANGE_TYPE_MAX = 4
};
enum ProfileChangeType {
    PROFILE_CHANGE_TYPE_MIN = 0,
    TRUST_DEVICE_PROFILE_ADD = 1,
    TRUST_DEVICE_PROFILE_UPDATE = 2,
    TRUST_DEVICE_PROFILE_DELETE = 3,
    DEVICE_PROFILE_ADD = 4,
    DEVICE_PROFILE_UPDATE = 5,
    DEVICE_PROFILE_DELETE = 6,
    SERVICE_PROFILE_ADD = 7,
    SERVICE_PROFILE_UPDATE = 8,
    SERVICE_PROFILE_DELETE = 9,
    CHAR_PROFILE_ADD = 10,
    CHAR_PROFILE_UPDATE = 11,
    CHAR_PROFILE_DELETE = 12,
    TRUST_DEVICE_PROFILE_ACTIVE = 13,
    TRUST_DEVICE_PROFILE_INACTIVE = 14,
    PROFILE_CHANGE_TYPE_MAX = 15
};
enum StaticCapabilityFlag {
    CAPABILITY_FLAG_MIN = -1,
    CAPABILITY_FLAG_DMS = 0,
    CAPABILITY_FLAG_PASTE_BOARD = 1,
    CAPABILITY_FLAG_DISTRIBUTED_FILE_DAEMON = 2,
    CAPABILITY_FLAG_MAX = 3,
};
enum class SwitchFlag : int32_t {
    SWITCH_FLAG_MIN = -1,
    SWITCH_FLAG_KEY_MOUSE_EDGE_CROSSING = 0,
    SWITCH_FLAG_KEY_DISTRIBUTED_PASTEBOARD = 1,
    SWITCH_FLAG_DCSHARESWITCH = 2,
    SWITCH_FLAG_WIFI_DISPLAY_SERVICE = 3,
    SWITCH_FLAG_DISTRIBUTED_SUPER_MANAGER = 4,
    SWITCH_FLAG_MAX = 5
};
const std::unordered_map<std::string, SwitchFlag> SWITCH_SERVICE_MAP = {
    { "SwitchStatus_Key_Mouse_Edge_Crossing", SwitchFlag::SWITCH_FLAG_KEY_MOUSE_EDGE_CROSSING },
    { "SwitchStatus_Key_Distributed_Pasteboard", SwitchFlag::SWITCH_FLAG_KEY_DISTRIBUTED_PASTEBOARD },
    { "SwitchStatus_DcShareSwitch", SwitchFlag::SWITCH_FLAG_DCSHARESWITCH },
    { "SwitchStatus_Wifi_Display_Service", SwitchFlag::SWITCH_FLAG_WIFI_DISPLAY_SERVICE },
    { "SwitchStatus_Distributed_Super_Manager", SwitchFlag::SWITCH_FLAG_DISTRIBUTED_SUPER_MANAGER }
};
const std::unordered_map<std::string, StaticCapabilityFlag> CAPABILITY_FLAG_MAP = {
    { "dmsfwk_svr_id", StaticCapabilityFlag::CAPABILITY_FLAG_DMS },
    { "pasteboardService", StaticCapabilityFlag::CAPABILITY_FLAG_PASTE_BOARD },
    { "distributedfiledaemon", StaticCapabilityFlag::CAPABILITY_FLAG_DISTRIBUTED_FILE_DAEMON }
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // OHOS_DP_DISTRIBUTED_DEVICE_PROFILE_ENUMS_H
