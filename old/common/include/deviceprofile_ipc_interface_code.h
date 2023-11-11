/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_DEVICE_PROFILE_IPC_INTERFACE_CODE_H
#define OHOS_DEVICE_PROFILE_IPC_INTERFACE_CODE_H

#include <cstdint>

/* SAID: 6001 */
namespace OHOS {
namespace DeviceProfile {
enum class IDeviceProfileInterfaceCode : uint32_t {
    PUT_DEVICE_PROFILE = 1,
    GET_DEVICE_PROFILE = 2,
    DELETE_DEVICE_PROFILE = 3,
    SUBSCRIBE_PROFILE_EVENT = 4,
    UNSUBSCRIBE_PROFILE_EVENT = 5,
    SYNC_DEVICE_PROFILE = 6,
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
};
} // namespace DeviceProfile
} // namespace OHOS
#endif
