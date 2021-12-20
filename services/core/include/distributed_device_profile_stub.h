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

private:
    using Func = int32_t(DistributedDeviceProfileStub::*)(MessageParcel& data, MessageParcel& reply);

    bool EnforceInterfaceToken(MessageParcel& data);

private:
    std::map<uint32_t, Func> funcsMap_;
};
} // namespace DeviceProfile
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_DEVICE_PROFILE_STUB_H