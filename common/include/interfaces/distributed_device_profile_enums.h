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

#ifndef OHOS_DP_DISTRIBUTED_DEVICE_PROFILE_ENUMS_H
#define OHOS_DP_DISTRIBUTED_DEVICE_PROFILE_ENUMS_H

#include <unordered_map>

namespace OHOS {
namespace DistributedDeviceProfile {
enum class DPInterfaceCode : uint32_t {
    MIN = 0,
    PUT_ACL_PROFILE = 7, // new ipc code
    UPDATE_ACL_PROFILE = 8,
    GET_TRUST_DEVICE_PROFILE = 9,
    GET_ALL_TRUST_DEVICE_PROFILE = 10,
    GET_ACL_PROFILE = 11,
    GET_ALL_ACL_PROFILE = 12,
    DELETE_ACL_PROFILE = 13,
    PUT_SERVICE_PROFILE = 14,
    PUT_SERVICE_PROFILE_BATCH = 15,
    PUT_CHAR_PROFILE = 16,
    PUT_CHAR_PROFILE_BATCH = 17,
    GET_DEVICE_PROFILE_NEW = 18,
    GET_SERVICE_PROFILE = 19,
    GET_CHAR_PROFILE = 20,
    DEL_SERVICE_PROFILE = 21,
    DEL_CHAR_PROFILE = 22,
    SUBSCRIBE_DEVICE_PROFILE = 23,
    UNSUBSCRIBE_DEVICE_PROFILE = 24,
    SYNC_DEVICE_PROFILE_NEW = 25,
    SEND_SUBSCRIBE_INFOS = 26,
    ON_SYNC_COMPLETED = 27,
    ON_TRUST_DEVICE_PROFILE_ADD = 28,
    ON_TRUST_DEVICE_PROFILE_UPDATE = 29,
    ON_TRUST_DEVICE_PROFILE_DELETE = 30,
    ON_DEVICE_PROFILE_ADD = 31,
    ON_DEVICE_PROFILE_UPDATE = 32,
    ON_DEVICE_PROFILE_DELETE = 33,
    ON_SERVICE_PROFILE_ADD = 34,
    ON_SERVICE_PROFILE_UPDATE = 35,
    ON_SERVICE_PROFILE_DELETE = 36,
    ON_CHAR_PROFILE_ADD = 37,
    ON_CHAR_PROFILE_UPDATE = 38,
    ON_CHAR_PROFILE_DELETE = 39,
    ON_DEVICE_PROFILE_INITED = 40,
    SUBSCRIBE_DEVICE_PROFILE_INITED = 41,
    UNSUBSCRIBE_DEVICE_PROFILE_INITED = 42,
    ON_TRUST_DEVICE_PROFILE_ACTIVE = 43,
    ON_TRUST_DEVICE_PROFILE_INACTIVE = 44,
    PUT_ALL_TRUSTED_DEVICES = 45,
    MAX = 46
};

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
    POINT_TO_POINT = 256,
    COMPATIBLE = 512,
    DIFF_ACCOUNT = 1282,
    MAX = 1283
};
enum class BindLevel : uint32_t {
    MIN = 0,
    DEVICE = 1,
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
    CAPABILITY_FLAG_COLLABORATION_FWK = 2,
    CAPABILITY_FLAG_DEVICE_STATUS = 3,
    CAPABILITY_FLAG_MAX = 4,
};
enum class SwitchFlag : int32_t {
    SWITCH_FLAG_MIN = -1,
    SWITCH_FLAG_KEY_MOUSE_EDGE_CROSSING = 0,
    SWITCH_FLAG_KEY_DISTRIBUTED_PASTEBOARD = 1,
    SWITCH_FLAG_DCSHARESWITCH = 2,
    SWITCH_FLAG_MAX = 3
};
const std::unordered_map<std::string, SwitchFlag> SWITCH_SERVICE_MAP = {
    { "SwitchStatus_Key_Mouse_Edge_Crossing", SwitchFlag::SWITCH_FLAG_KEY_MOUSE_EDGE_CROSSING },
    { "SwitchStatus_Key_Distributed_Pasteboard", SwitchFlag::SWITCH_FLAG_KEY_DISTRIBUTED_PASTEBOARD },
    { "SwitchStatus_DcShareSwitch", SwitchFlag::SWITCH_FLAG_DCSHARESWITCH }
};
const std::unordered_map<std::string, StaticCapabilityFlag> CAPABILITY_FLAG_MAP = {
    { "dmsfwk_svr_id", StaticCapabilityFlag::CAPABILITY_FLAG_DMS },
    { "pasteboardService", StaticCapabilityFlag::CAPABILITY_FLAG_PASTE_BOARD },
    { "collaborationFwk", StaticCapabilityFlag::CAPABILITY_FLAG_COLLABORATION_FWK },
    { "deviceStatus", StaticCapabilityFlag::CAPABILITY_FLAG_DEVICE_STATUS },
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // OHOS_DP_DISTRIBUTED_DEVICE_PROFILE_ENUMS_H
