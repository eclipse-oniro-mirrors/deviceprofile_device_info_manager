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

#ifndef OHOS_DP_DEVICE_PROFILE_PARCEL_HELPER_H
#define OHOS_DP_DEVICE_PROFILE_PARCEL_HELPER_H

#include "ipc_types.h"
#include "distributed_device_profile_log.h"

namespace OHOS {
namespace DistributedDeviceProfile {
#define WRITE_HELPER(parcel, type, value) \
    do { \
        bool ret = (parcel).Write##type((value)); \
        if (!ret) { \
            HILOGE("write value failed!"); \
            return ERR_FLATTEN_OBJECT; \
        } \
    } while (0)

#define WRITE_HELPER_NORET(parcel, type, value) \
    do { \
        bool ret = (parcel).Write##type((value)); \
        if (!ret) { \
            HILOGE("write value failed!"); \
            return; \
        } \
    } while (0)

#define WRITE_HELPER_RET(parcel, type, value, failRet) \
    do { \
        bool ret = (parcel).Write##type((value)); \
        if (!ret) { \
            HILOGE("write value failed!"); \
            return failRet; \
        } \
    } while (0)

#define READ_HELPER(parcel, type, out) \
    do { \
        bool ret = (parcel).Read##type((out)); \
        if (!ret) { \
            HILOGE("read value failed!"); \
            return ERR_FLATTEN_OBJECT; \
        } \
    } while (0)

#define READ_HELPER_RET(parcel, type, out, failRet) \
    do { \
        bool ret = (parcel).Read##type((out)); \
        if (!ret) { \
            HILOGE("read value failed!"); \
            return failRet; \
        } \
    } while (0)

#define SEND_REQUEST(remote, code, data, reply) \
    do { \
        MessageOption option; \
        int32_t errCode = (remote)->SendRequest((code), (data), (reply), option); \
        if (errCode != DP_SUCCESS) { \
            HILOGE("transact failed, errCode = %{public}d", errCode); \
            return errCode; \
        } \
        int32_t ret = (reply).ReadInt32(); \
        if (ret != DP_SUCCESS) { \
            HILOGE("dp method call fail, errCode = %{public}d", ret); \
            return ret; \
        } \
    } while (0)

#define GET_REMOTE_OBJECT(remote) \
    do { \
        (remote) = Remote(); \
        if ((remote) == nullptr) { \
            HILOGE("RemoteObject is nullptr!"); \
            return DP_IPC_REMOTE_OBJECT_NULLPTR; \
        } \
    } while (0)

#define WRITE_INTERFACE_TOKEN(data) \
    do { \
        if (!(data).WriteInterfaceToken(IDistributedDeviceProfile::GetDescriptor())) { \
            HILOGE("Write interface token failed!"); \
            return ERR_FLATTEN_OBJECT; \
        } \
    } while (0)

#define WRITE_CHANGE_LISTENER_TOKEN(data) \
    do { \
        if (!(data).WriteInterfaceToken(IProfileChangeListener::GetDescriptor())) { \
            HILOGE("Write interface token failed!"); \
            return ERR_FLATTEN_OBJECT; \
        } \
    } while (0)

#define WRITE_SYNC_CALLBACK_TOKEN(data) \
    do { \
        if (!(data).WriteInterfaceToken(ISyncCompletedCallback::GetDescriptor())) { \
            HILOGE("Write interface token failed!"); \
            return ERR_FLATTEN_OBJECT; \
        } \
    } while (0)
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // OHOS_DP_DEVICE_PROFILE_PARCEL_HELPER_H
