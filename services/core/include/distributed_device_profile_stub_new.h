/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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
#include <unordered_set>

#include "iremote_stub.h"

#include "distributed_device_profile_errors.h"
#include "i_distributed_device_profile.h"
#include "ipc_utils.h"

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
    int32_t GetAllAclIncludeLnnAclInner(MessageParcel& data, MessageParcel& reply);
    int32_t DeleteAccessControlProfileInner(MessageParcel& data, MessageParcel& reply);
    int32_t PutSessionKeyInner(MessageParcel& data, MessageParcel& reply);
    int32_t GetSessionKeyInner(MessageParcel& data, MessageParcel& reply);
    int32_t UpdateSessionKeyInner(MessageParcel& data, MessageParcel& reply);
    int32_t PutDeviceProfileBatchInner(MessageParcel& data, MessageParcel& reply);
    int32_t DeleteSessionKeyInner(MessageParcel& data, MessageParcel& reply);
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
    int32_t SyncStaticProfileInner(MessageParcel& data, MessageParcel& reply);
    int32_t SendSubscribeInfosInner(MessageParcel& data, MessageParcel& reply);
    int32_t SubscribeDeviceProfileInitedInner(MessageParcel& data, MessageParcel& reply);
    int32_t UnSubscribeDeviceProfileInitedInner(MessageParcel& data, MessageParcel& reply);
    int32_t PutAllTrustedDevicesInner(MessageParcel& data, MessageParcel& reply);
    int32_t PutLocalServiceInfoInner(MessageParcel& data, MessageParcel& reply);
    int32_t UpdateLocalServiceInfoInner(MessageParcel& data, MessageParcel& reply);
    int32_t GetLocalServiceInfoByBundleAndPinTypeInner(MessageParcel& data, MessageParcel& reply);
    int32_t DeleteLocalServiceInfoInner(MessageParcel& data, MessageParcel& reply);
    int32_t GetDeviceProfilesInner(MessageParcel& data, MessageParcel& reply);
    int32_t DeleteDeviceProfileBatchInner(MessageParcel& data, MessageParcel& reply);
    int32_t PutProductInfoBatchInner(MessageParcel& data, MessageParcel& reply);
    int32_t PutDeviceIconInfoBatchInner(MessageParcel& data, MessageParcel& reply);
    int32_t GetDeviceIconInfosInner(MessageParcel& data, MessageParcel& reply);
    int32_t PutServiceInfoProfileInner(MessageParcel& data, MessageParcel& reply);
    int32_t DeleteServiceInfoProfileInner(MessageParcel& data, MessageParcel& reply);
    int32_t UpdateServiceInfoProfileInner(MessageParcel& data, MessageParcel& reply);
    int32_t GetServiceInfoProfileByUniqueKeyInner(MessageParcel& data, MessageParcel& reply);
    int32_t GetServiceInfoProfileListByTokenIdInner(MessageParcel& data, MessageParcel& reply);
    int32_t GetAllServiceInfoProfileListInner(MessageParcel& data, MessageParcel& reply);
    int32_t GetServiceInfoProfileListByBundleNameInner(MessageParcel& data, MessageParcel& reply);
    int32_t SubscribePinCodeInvalidInner(MessageParcel& data, MessageParcel& reply);
    int32_t UnSubscribePinCodeInvalidInner(MessageParcel& data, MessageParcel& reply);
    virtual void DelayUnloadTask() = 0;
    virtual bool IsInited() = 0;
    int32_t RegisterBusinessCallbackInner(MessageParcel& data, MessageParcel& reply);
    int32_t UnRegisterBusinessCallbackInner(MessageParcel& data, MessageParcel& reply);
    int32_t PutBusinessEventInner(MessageParcel& data, MessageParcel& reply);
    int32_t GetBusinessEventInner(MessageParcel& data, MessageParcel& reply);

private:
    using Func = int32_t(DistributedDeviceProfileStubNew::*)(MessageParcel& data, MessageParcel& reply);
    bool IsInterfaceTokenValid(MessageParcel& data);
    void InitAclAndSubscribe();
    int32_t NotifyEventInner(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option);
    int32_t NotifyAclEventInner(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option);
    int32_t NotifyProfileDataEventInner(uint32_t code, MessageParcel& data,
        MessageParcel& reply, MessageOption& option);
    int32_t NotifyLocalServiceEventInner(uint32_t code, MessageParcel& data, MessageParcel& reply,
        MessageOption& option);
private:
    std::unordered_set<uint32_t> aclAndSubscribeFuncs_;
};
} // namespace DeviceProfile
} // namespace OHOS
#endif // OHOS_DP_DISTRIBUTED_DEVICE_PROFILE_STUB_H
