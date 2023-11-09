/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_DP_DISTRIBUTED_DEVICE_PROFILE_STUB_H
#define OHOS_DP_DISTRIBUTED_DEVICE_PROFILE_STUB_H

#include <map>

#include "iremote_stub.h"
#include "distributed_device_profile_errors.h"
#include "ipc_utils.h"
#include "i_distributed_device_profile.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class DistributedDeviceProfileStubNew : public IRemoteStub<IDistributedDeviceProfile> {
public:
    DistributedDeviceProfileStubNew();
    ~DistributedDeviceProfileStubNew();

    int32_t OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override;

    int32_t PutAccessControlProfileInner(MessageParcel& data, MessageParcel& reply);
    int32_t UpdateAccessControlProfileInner(MessageParcel& data, MessageParcel& reply);
    int32_t GetTrustDeviceProfileInner(MessageParcel& data, MessageParcel& reply);
    int32_t GetAllTrustDeviceProfileInner(MessageParcel& data, MessageParcel& reply);
    int32_t GetAccessControlProfileInner(MessageParcel& data, MessageParcel& reply);
    int32_t GetAllAccessControlProfileInner(MessageParcel& data, MessageParcel& reply);
    int32_t DeleteAccessControlProfileInner(MessageParcel& data, MessageParcel& reply);
    int32_t PutServiceProfileInner(MessageParcel& data, MessageParcel& reply);
    int32_t PutServiceProfileBatchInner(MessageParcel& data, MessageParcel& reply);
    int32_t PutCharacteristicProfileInner(MessageParcel& data, MessageParcel& reply);
    int32_t PutCharacteristicProfileBatchInner(MessageParcel& data, MessageParcel& reply);
    int32_t GetDeviceProfileInner(MessageParcel& data, MessageParcel& reply);
    int32_t GetServiceProfileInner(MessageParcel& data, MessageParcel& reply);
    int32_t GetCharacteristicProfileInner(MessageParcel& data, MessageParcel& reply);
    int32_t DeleteServiceProfileInner(MessageParcel& data, MessageParcel& reply);
    int32_t DeleteCharacteristicProfileInner(MessageParcel& data, MessageParcel& reply);
    int32_t SubscribeDeviceProfileInner(MessageParcel& data, MessageParcel& reply);
    int32_t UnSubscribeDeviceProfileInner(MessageParcel& data, MessageParcel& reply);
    int32_t SyncDeviceProfileInner(MessageParcel& data, MessageParcel& reply);
    int32_t SendSubscribeInfosInner(MessageParcel& data, MessageParcel& reply);

private:
    using Func = int32_t(DistributedDeviceProfileStubNew::*)(MessageParcel& data, MessageParcel& reply);
    bool IsInterfaceTokenValid(MessageParcel& data);

private:
    std::map<uint32_t, Func> funcsMap_;
    std::mutex funcsMutex_;
};
} // namespace DeviceProfile
} // namespace OHOS
#endif // OHOS_DP_DISTRIBUTED_DEVICE_PROFILE_STUB_H