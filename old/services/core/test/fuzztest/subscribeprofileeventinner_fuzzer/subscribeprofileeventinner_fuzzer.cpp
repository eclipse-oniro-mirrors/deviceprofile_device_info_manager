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

#include "subscribeprofileeventinner_fuzzer.h"

#include "distributed_device_profile_stub.h"

#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include <cstdlib>
#include <fcntl.h>
#include <string>
#include <iostream>
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

namespace OHOS {
namespace DeviceProfile {
class DistributedDeviceProfileStubTest : public DistributedDeviceProfileStub {
public:
public:
    DistributedDeviceProfileStubTest() = default;
    ~DistributedDeviceProfileStubTest() = default;
    int32_t PutDeviceProfile(const ServiceCharacteristicProfile& profile)
    {
        (void)profile;
        return 0;
    }
    int32_t GetDeviceProfile(const std::string& udid, const std::string& serviceId,
        ServiceCharacteristicProfile& profile)
    {
        (void)udid;
        (void)serviceId;
        (void)profile;
        return 0;
    }
    int32_t DeleteDeviceProfile(const std::string& serviceId)
    {
        (void)serviceId;
        return 0;
    }
    int32_t SubscribeProfileEvents(const std::list<SubscribeInfo>& subscribeInfos,
        const sptr<IRemoteObject>& profileEventNotifier, std::list<ProfileEvent>& failedEvents)
    {
        (void)subscribeInfos;
        (void)profileEventNotifier;
        (void)failedEvents;
        return 0;
    }
    int32_t UnsubscribeProfileEvents(const std::list<ProfileEvent>& profileEvents,
        const sptr<IRemoteObject>& profileEventNotifier, std::list<ProfileEvent>& failedEvents)
    {
        (void)profileEvents;
        (void)profileEventNotifier;
        (void)failedEvents;
        return 0;
    }
    int32_t SyncDeviceProfile(const SyncOptions& syncOptions, const sptr<IRemoteObject>& profileEventNotifier)
    {
        (void)syncOptions;
        (void)profileEventNotifier;
        return 0;
    }
};

void MockPermission(const char* processName)
{
    const int32_t PERMS_NUM = 2;
    const char *perms[PERMS_NUM] = {
        "ohos.permission.DISTRIBUTED_DATASYNC",
        "ohos.permission.DISTRIBUTED_SOFTBUS_CENTER"
    };
    uint64_t tokenId;
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = PERMS_NUM,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .processName = processName,
        .aplStr = "system_core",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

void FuzzDumpLocalProfile(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(uint32_t))) {
        return;
    }
    uint32_t numSubscribeInfos = *(reinterpret_cast<const uint32_t*>(data));
    MessageParcel messageData;
    MessageParcel reply;
    messageData.WriteUint32(numSubscribeInfos);
    std::shared_ptr<DistributedDeviceProfileStub> deviceProfileStub =
        std::make_shared<DistributedDeviceProfileStubTest>();
    deviceProfileStub->SubscribeProfileEventInner(messageData, reply);
    deviceProfileStub->UnsubscribeProfileEventInner(messageData, reply);
}

void PutAccessControlProfileInnerTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    MockPermission("deviceprofile");
    std::string udid(reinterpret_cast<const char*>(data), size);
    std::string serviceId(reinterpret_cast<const char*>(data), size);
    MessageParcel messageData;
    messageData.WriteString(udid);
    messageData.WriteString(serviceId);
    MessageParcel reply;
    std::shared_ptr<DistributedDeviceProfileStub> deviceProfilePutStub =
        std::make_shared<DistributedDeviceProfileStubTest>();
    deviceProfilePutStub->PutAccessControlProfileInner(messageData, reply);
    deviceProfilePutStub->GetAccessControlProfileInner(messageData, reply);
}

void GetTrustDeviceProfileInnerTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    MockPermission("deviceprofile");
    std::string deviceId(reinterpret_cast<const char*>(data), size);
    MessageParcel messageData;
    messageData.WriteString(deviceId);
    MessageParcel reply;
    std::shared_ptr<DistributedDeviceProfileStub> deviceProfileGetStub =
        std::make_shared<DistributedDeviceProfileStubTest>();
    deviceProfileGetStub->PutAccessControlProfileInner(messageData, reply);
    deviceProfileGetStub->GetTrustDeviceProfileInner(messageData, reply);
    deviceProfileGetStub->GetAllTrustDeviceProfileInner(messageData, reply);
}

void UpdateAccessControlProfileInnerTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    MockPermission("deviceprofile");
    std::string udid(reinterpret_cast<const char*>(data), size);
    std::string serviceId(reinterpret_cast<const char*>(data), size);
    MessageParcel messageData;
    messageData.WriteString(udid);
    messageData.WriteString(serviceId);
    MessageParcel reply;
    std::shared_ptr<DistributedDeviceProfileStub> deviceProfileUpdateStub =
        std::make_shared<DistributedDeviceProfileStubTest>();
    deviceProfileUpdateStub->PutAccessControlProfileInner(messageData, reply);
    deviceProfileUpdateStub->UpdateAccessControlProfileInner(messageData, reply);
}

void GetAllAccessControlProfileInnerTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    MockPermission("deviceprofile");
    std::string udid(reinterpret_cast<const char*>(data), size);
    std::string serviceId(reinterpret_cast<const char*>(data), size);
    MessageParcel messageData;
    messageData.WriteString(udid);
    messageData.WriteString(serviceId);
    MessageParcel reply;
    std::shared_ptr<DistributedDeviceProfileStub> deviceProfileGetAllStub =
        std::make_shared<DistributedDeviceProfileStubTest>();
    deviceProfileGetAllStub->PutAccessControlProfileInner(messageData, reply);
    deviceProfileGetAllStub->GetAllAccessControlProfileInner(messageData, reply);
}

void DeleteAccessControlProfileInnerTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    MockPermission("deviceprofile");
    std::string udid(reinterpret_cast<const char*>(data), size);
    std::string serviceId(reinterpret_cast<const char*>(data), size);
    MessageParcel messageData;
    messageData.WriteString(udid);
    messageData.WriteString(serviceId);
    MessageParcel reply;
    std::shared_ptr<DistributedDeviceProfileStub> deviceProfileDeleteStub =
        std::make_shared<DistributedDeviceProfileStubTest>();
    deviceProfileDeleteStub->PutAccessControlProfileInner(messageData, reply);
    deviceProfileDeleteStub->GetAllAccessControlProfileInner(messageData, reply);
    deviceProfileDeleteStub->DeleteAccessControlProfileInner(messageData, reply);
}

void PutServiceProfileInnerTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    MockPermission("deviceprofile");
    std::string udid(reinterpret_cast<const char*>(data), size);
    std::string serviceId(reinterpret_cast<const char*>(data), size);
    MessageParcel messageData;
    messageData.WriteString(udid);
    messageData.WriteString(serviceId);
    MessageParcel reply;
    std::shared_ptr<DistributedDeviceProfileStub> deviceProfilePutSerStub =
        std::make_shared<DistributedDeviceProfileStubTest>();
    deviceProfilePutSerStub->PutServiceProfileInner(messageData, reply);
    deviceProfilePutSerStub->GetServiceProfileInner(messageData, reply);
}

void PutServiceProfileBatchInnerTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    MockPermission("deviceprofile");
    std::string udid(reinterpret_cast<const char*>(data), size);
    std::string serviceId(reinterpret_cast<const char*>(data), size);
    MessageParcel messageData;
    messageData.WriteString(udid);
    messageData.WriteString(serviceId);
    MessageParcel reply;
    std::shared_ptr<DistributedDeviceProfileStub> deviceProfilePutSerStub =
        std::make_shared<DistributedDeviceProfileStubTest>();
    deviceProfilePutSerStub->PutServiceProfileBatchInner(messageData, reply);
    deviceProfilePutSerStub->GetServiceProfileInner(messageData, reply);
}

void PutCharacteristicProfileInnerTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    MockPermission("deviceprofile");
    std::string udid(reinterpret_cast<const char*>(data), size);
    std::string serviceId(reinterpret_cast<const char*>(data), size);
    MessageParcel messageData;
    messageData.WriteString(udid);
    messageData.WriteString(serviceId);
    MessageParcel reply;
    std::shared_ptr<DistributedDeviceProfileStub> deviceProfilePutStub =
        std::make_shared<DistributedDeviceProfileStubTest>();
    deviceProfilePutStub->PutCharacteristicProfileInner(messageData, reply);
    deviceProfilePutStub->GetCharacteristicProfileInner(messageData, reply);
}

void PutCharacteristicProfileBatchInnerTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    MockPermission("deviceprofile");
    std::string udid(reinterpret_cast<const char*>(data), size);
    std::string serviceId(reinterpret_cast<const char*>(data), size);
    MessageParcel messageData;
    messageData.WriteString(udid);
    messageData.WriteString(serviceId);
    MessageParcel reply;
    std::shared_ptr<DistributedDeviceProfileStub> deviceProfileStub =
        std::make_shared<DistributedDeviceProfileStubTest>();
    deviceProfileStub->PutCharacteristicProfileBatchInner(messageData, reply);
    deviceProfileStub->GetCharacteristicProfileInner(messageData, reply);
}

void DeleteCharacteristicProfileInnerTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    MockPermission("deviceprofile");
    std::string udid(reinterpret_cast<const char*>(data), size);
    std::string serviceId(reinterpret_cast<const char*>(data), size);
    MessageParcel messageData;
    messageData.WriteString(udid);
    messageData.WriteString(serviceId);
    MessageParcel reply;
    std::shared_ptr<DistributedDeviceProfileStub> deviceProfileStub =
        std::make_shared<DistributedDeviceProfileStubTest>();
    deviceProfileStub->PutCharacteristicProfileBatchInner(messageData, reply);
    deviceProfileStub->DeleteCharacteristicProfileInner(messageData, reply);
}

void DeleteServiceProfileInnerTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    MockPermission("deviceprofile");
    std::string udid(reinterpret_cast<const char*>(data), size);
    std::string serviceId(reinterpret_cast<const char*>(data), size);
    MessageParcel messageData;
    messageData.WriteString(udid);
    messageData.WriteString(serviceId);
    MessageParcel reply;
    std::shared_ptr<DistributedDeviceProfileStub> deviceProfileDeleteSerStub =
        std::make_shared<DistributedDeviceProfileStubTest>();
    deviceProfileDeleteSerStub->PutServiceProfileBatchInner(messageData, reply);
    deviceProfileDeleteSerStub->DeleteServiceProfileInner(messageData, reply);
}

void SubscribeDeviceProfileInnerTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    MockPermission("deviceprofile");
    std::string udid(reinterpret_cast<const char*>(data), size);
    std::string serviceId(reinterpret_cast<const char*>(data), size);
    MessageParcel messageData;
    messageData.WriteString(udid);
    messageData.WriteString(serviceId);
    MessageParcel reply;
    std::shared_ptr<DistributedDeviceProfileStub> deviceProfileSubStub =
        std::make_shared<DistributedDeviceProfileStubTest>();
    deviceProfileSubStub->SubscribeDeviceProfileInner(messageData, reply);
    deviceProfileSubStub->UnSubscribeDeviceProfileInner(messageData, reply);
}

void SyncDeviceProfileNewInnerTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    MockPermission("deviceprofile");
    std::string udid(reinterpret_cast<const char*>(data), size);
    std::string serviceId(reinterpret_cast<const char*>(data), size);
    MessageParcel messageData;
    messageData.WriteString(udid);
    messageData.WriteString(serviceId);
    MessageParcel reply;
    std::shared_ptr<DistributedDeviceProfileStub> deviceProfileSyncStub =
        std::make_shared<DistributedDeviceProfileStubTest>();
    deviceProfileSyncStub->SyncDeviceProfileNewInner(messageData, reply);
    deviceProfileSyncStub->SendSubscribeInfosInner(messageData, reply);
}
} // namespace DeviceProfile
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DeviceProfile::FuzzDumpLocalProfile(data, size);
    OHOS::DeviceProfile::PutAccessControlProfileInnerTest(data, size);
    OHOS::DeviceProfile::GetTrustDeviceProfileInnerTest(data, size);
    OHOS::DeviceProfile::UpdateAccessControlProfileInnerTest(data, size);
    OHOS::DeviceProfile::GetAllAccessControlProfileInnerTest(data, size);
    OHOS::DeviceProfile::DeleteAccessControlProfileInnerTest(data, size);
    OHOS::DeviceProfile::PutServiceProfileBatchInnerTest(data, size);
    OHOS::DeviceProfile::PutServiceProfileInnerTest(data, size);
    OHOS::DeviceProfile::PutCharacteristicProfileInnerTest(data, size);
    OHOS::DeviceProfile::PutCharacteristicProfileBatchInnerTest(data, size);
    OHOS::DeviceProfile::DeleteCharacteristicProfileInnerTest(data, size);
    OHOS::DeviceProfile::DeleteServiceProfileInnerTest(data, size);
    OHOS::DeviceProfile::SyncDeviceProfileNewInnerTest(data, size);
    OHOS::DeviceProfile::SubscribeDeviceProfileInnerTest(data, size);
    return 0;
}
