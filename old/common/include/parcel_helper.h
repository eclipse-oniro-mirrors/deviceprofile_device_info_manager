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

#ifndef OHOS_DEVICE_PROFILE_PARCEL_HELPER_H
#define OHOS_DEVICE_PROFILE_PARCEL_HELPER_H

#include "ipc_types.h"
#include "device_profile_log.h"

namespace OHOS {
namespace DeviceProfile {
#define PARCEL_WRITE_HELPER(parcel, type, value) \
    do { \
        bool ret = parcel.Write##type((value)); \
        if (!ret) { \
            HILOGE("write value failed!"); \
            return ERR_FLATTEN_OBJECT; \
        } \
    } while (0)

#define PARCEL_WRITE_HELPER_NORET(parcel, type, value) \
    do { \
        bool ret = parcel.Write##type((value)); \
        if (!ret) { \
            HILOGE("write value failed!"); \
            return; \
        } \
    } while (0)

#define PARCEL_WRITE_HELPER_RET(parcel, type, value, failRet) \
    do { \
        bool ret = parcel.Write##type((value)); \
        if (!ret) { \
            HILOGE("write value failed!"); \
            return failRet; \
        } \
    } while (0)

#define PARCEL_READ_HELPER(parcel, type, out) \
    do { \
        bool ret = parcel.Read##type((out)); \
        if (!ret) { \
            HILOGE("read value failed!"); \
            return ERR_FLATTEN_OBJECT; \
        } \
    } while (0)

#define PARCEL_READ_HELPER_RET(parcel, type, out, failRet) \
    do { \
        bool ret = parcel.Read##type((out)); \
        if (!ret) { \
            HILOGE("read value failed!"); \
            return failRet; \
        } \
    } while (0)

#define PARCEL_READ_HELPER_NORET(parcel, type, out) \
    do { \
        bool ret = parcel.Read##type((out)); \
        if (!ret) { \
            HILOGW("read value failed!"); \
        } \
    } while (0)

#define PARCEL_WRITE_REPLY_NOERROR(reply, type, result) \
    do { \
        bool ret = reply.Write##type(result); \
        if (!ret) { \
            HILOGW("write reply failed!"); \
        } \
        return ERR_OK; \
    } while (0)

#define PARCEL_TRANSACT_SYNC_RET_INT(remote, code, data, reply) \
    do { \
        MessageOption option; \
        int32_t errCode = remote->SendRequest(code, data, reply, option); \
        if (errCode != ERR_OK) { \
            HILOGE("transact failed, errCode = %{public}d", errCode); \
            return errCode; \
        } \
        HILOGI("transact succeeded"); \
        return ERR_OK; \
    } while (0)

#define PARCEL_TRANSACT_SYNC_NORET(remote, code, data, reply) \
    do { \
        MessageOption option; \
        int32_t errCode = remote->SendRequest(code, data, reply, option); \
        if (errCode != ERR_OK) { \
            HILOGE("transact failed, errCode = %{public}d", errCode); \
            return; \
        } \
        HILOGI("transact succeeded"); \
    } while (0)
} // namespace DeviceProfile
} // namespace OHOS
#endif // OHOS_DEVICE_PROFILE_PARCEL_HELPER_H
