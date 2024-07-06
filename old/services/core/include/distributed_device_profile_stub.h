/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_DISTRIBUTED_DEVICE_PROFILE_STUB_H
#define OHOS_DISTRIBUTED_DEVICE_PROFILE_STUB_H

#include "idistributed_device_profile.h"

#include <map>

#include "iremote_stub.h"

namespace OHOS {
namespace DeviceProfile {
class DistributedDeviceProfileStub : public IRemoteStub<IDistributedDeviceProfile> {
public:
    DistributedDeviceProfileStub();
    ~DistributedDeviceProfileStub() = default;

    int32_t OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply,
        MessageOption& option) override;

    int32_t PutDeviceProfileInner(MessageParcel& data, MessageParcel& reply);
    int32_t DeleteDeviceProfileInner(MessageParcel& data, MessageParcel& reply);
    int32_t GetDeviceProfileInner(MessageParcel& data, MessageParcel& reply);
    int32_t SubscribeProfileEventInner(MessageParcel& data, MessageParcel& reply);
    int32_t UnsubscribeProfileEventInner(MessageParcel& data, MessageParcel& reply);
    int32_t SyncDeviceProfileInner(MessageParcel& data, MessageParcel& reply);
    // new stub interface
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
    int32_t GetDeviceProfileNewInner(MessageParcel& data, MessageParcel& reply);
    int32_t GetServiceProfileInner(MessageParcel& data, MessageParcel& reply);
    int32_t GetCharacteristicProfileInner(MessageParcel& data, MessageParcel& reply);
    int32_t DeleteServiceProfileInner(MessageParcel& data, MessageParcel& reply);
    int32_t DeleteCharacteristicProfileInner(MessageParcel& data, MessageParcel& reply);
    int32_t SubscribeDeviceProfileInner(MessageParcel& data, MessageParcel& reply);
    int32_t UnSubscribeDeviceProfileInner(MessageParcel& data, MessageParcel& reply);
    int32_t SyncDeviceProfileNewInner(MessageParcel& data, MessageParcel& reply);
    int32_t SendSubscribeInfosInner(MessageParcel& data, MessageParcel& reply);
    virtual void DelayUnloadTask()
    {
        return;
    }

private:
    using Func = int32_t(DistributedDeviceProfileStub::*)(MessageParcel& data, MessageParcel& reply);

    bool EnforceInterfaceToken(MessageParcel& data);

    void InitNewIpcInterface();

    void InitAclAndSubscribe();

    int32_t NotifyAclEventInner(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option);

    int32_t NotifyOldEventInner(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option);

    int32_t NotifyNewEventInner(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option);

private:
    std::map<uint32_t, Func> funcsMap_;
    std::vector<uint32_t> aclAndSubscribeFuncs_;
};
} // namespace DeviceProfile
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_DEVICE_PROFILE_STUB_H