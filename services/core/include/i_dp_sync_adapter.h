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

#ifndef OH_DISTRIBUTED_DEVICE_I_DP_SYNC_ADAPTER_H
#define OH_DISTRIBUTED_DEVICE_I_DP_SYNC_ADAPTER_H

#include "i_sync_completed_callback.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class IDPSyncListener {
public:
    virtual ~IDPSyncListener() = default;
    virtual void SyncCompleted(const SyncResult& syncResults) = 0;
};
class IDPSyncAdapter {
public:
    virtual ~IDPSyncAdapter() = default;
    virtual int32_t Initialize() = 0;
    virtual int32_t Release() = 0;
    virtual int32_t DetectRemoteDPVersion(const std::string& peerDevId) = 0;
    virtual int32_t SyncProfile(const std::list<std::string>& deviceIdList,
        const sptr<IRemoteObject>& syncCompletedCallback) = 0;
};
using CreateDPSyncAdapterFuncPtr = IDPSyncAdapter *(*)(void);
} // namespace DeviceProfile
} // namespace OHOS
#endif // DEFAULT_DP_SYNC_ADAPTER_H