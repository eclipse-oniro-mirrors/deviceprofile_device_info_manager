/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include <string>
#include <vector>
#define private   public
#define protected public
#include "gtest/gtest.h"
#include "refbase.h"
#include "business_callback_stub.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"
#include "distributed_device_profile_enums.h"
#include "dp_inited_callback_stub.h"
#include "dp_inited_callback_proxy.h"
#include "device_profile.h"
#include "service_profile.h"
#include "dp_subscribe_info.h"
#include "i_sync_completed_callback.h"
#include "characteristic_profile.h"
#include "distributed_device_profile_client.h"
#include "pincode_invalid_callback_stub.h"
#include "trusted_device_info.h"
#undef private
#undef protected

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace testing::ext;
using namespace std;

class DistributedDeviceProfileClientKvTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DistributedDeviceProfileClientKvTest::SetUpTestCase(void) {
}

void DistributedDeviceProfileClientKvTest::TearDownTestCase(void) {
}

void DistributedDeviceProfileClientKvTest::SetUp() {
}

void DistributedDeviceProfileClientKvTest::TearDown() {
}

class SubscribeDPChangeListener : public ProfileChangeListenerStub {
public:
    SubscribeDPChangeListener()
    {
    }
    ~SubscribeDPChangeListener()
    {
    }
    int32_t OnTrustDeviceProfileAdd(const TrustDeviceProfile &profile)
    {
        return 0;
    }
    int32_t OnTrustDeviceProfileDelete(const TrustDeviceProfile &profile)
    {
        return 0;
    }
    int32_t OnTrustDeviceProfileUpdate(const TrustDeviceProfile &oldProfile, const TrustDeviceProfile &newProfile)
    {
        return 0;
    }
    int32_t OnDeviceProfileAdd(const DeviceProfile &profile)
    {
        return 0;
    }
    int32_t OnDeviceProfileDelete(const DeviceProfile &profile)
    {
        return 0;
    }
    int32_t OnDeviceProfileUpdate(const DeviceProfile &oldProfile, const DeviceProfile &newProfile)
    {
        return 0;
    }
    int32_t OnServiceProfileAdd(const ServiceProfile &profile)
    {
        return 0;
    }
    int32_t OnServiceProfileDelete(const ServiceProfile &profile)
    {
        return 0;
    }
    int32_t OnServiceProfileUpdate(const ServiceProfile &oldProfile, const ServiceProfile &newProfile)
    {
        return 0;
    }
    int32_t OnCharacteristicProfileAdd(const CharacteristicProfile &profile)
    {
        return 0;
    }
    int32_t OnCharacteristicProfileDelete(const CharacteristicProfile &profile)
    {
        return 0;
    }
    int32_t OnCharacteristicProfileUpdate(const CharacteristicProfile &oldProfile,
                                          const CharacteristicProfile &newProfile)
    {
        return 0;
    }
};

class DpInitedCallback : public DpInitedCallbackStub {
public:
    DpInitedCallback()
    {
    }
    ~DpInitedCallback()
    {
    }
    int32_t OnDpInited()
    {
        return 0;
    }
};

class MockDpInitedCallbackStub : public DpInitedCallbackStub {
public:
    int32_t OnDpInited()
    {
        return 0;
    }
};

class PinCodeInvalidCallback : public PinCodeInvalidCallbackStub {
public:
    PinCodeInvalidCallback()
    {
    }
    ~PinCodeInvalidCallback()
    {
    }
    int32_t OnPincodeInvalid(const LocalServiceInfo& localServiceInfo)
    {
        (void)localServiceInfo;
        return DP_SUCCESS;
    }
};

class BusinessCallback : public BusinessCallbackStub {
public:
    BusinessCallback()
    {
    }
    ~BusinessCallback()
    {
    }
    int32_t OnBusinessEvent(const BusinessEventExt &event)
    {
        (void)event;
        return DP_SUCCESS;
    }
};

/**
 * @tc.name:PutServiceProfile001
 * @tc.desc: PutServiceProfile success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, PutServiceProfile001, TestSize.Level1)
{
    ServiceProfile serviceProfile;
    serviceProfile.SetDeviceId("deviceId");
    serviceProfile.SetServiceName("serviceName");
    serviceProfile.SetServiceType("serviceType");
    DistributedDeviceProfileClient::GetInstance().ReleaseResource();
    int32_t errCode = DistributedDeviceProfileClient::GetInstance().PutServiceProfile(serviceProfile);
    EXPECT_EQ(errCode, DP_PERMISSION_DENIED);
}

/**
 * @tc.name:PutServiceProfileBatch001
 * @tc.desc: PutServiceProfileBatch success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, PutServiceProfileBatch001, TestSize.Level1)
{
    vector<ServiceProfile> serviceProfiles;
    
    ServiceProfile serviceProfile1;
    serviceProfile1.SetDeviceId("deviceId1");
    serviceProfile1.SetServiceName("serviceName1");
    serviceProfile1.SetServiceType("serviceType1");
    ServiceProfile serviceProfile2;
    serviceProfile2.SetDeviceId("deviceId2");
    serviceProfile2.SetServiceName("serviceName2");
    serviceProfile2.SetServiceType("serviceType2");
    serviceProfiles.push_back(serviceProfile1);
    serviceProfiles.push_back(serviceProfile2);
    
    int32_t errCode = DistributedDeviceProfileClient::GetInstance().PutServiceProfileBatch(serviceProfiles);
    EXPECT_EQ(errCode, DP_PERMISSION_DENIED);
}

/**
 * @tc.name:PutServiceProfileBatch002
 * @tc.desc: PutServiceProfileBatch failed, ServiceProfiles size is invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, PutServiceProfileBatch002, TestSize.Level1)
{
    vector<ServiceProfile> serviceProfiles;
    
    int32_t errCode = DistributedDeviceProfileClient::GetInstance().PutServiceProfileBatch(serviceProfiles);
    EXPECT_EQ(errCode, DP_INVALID_PARAMS);
}

/**
 * @tc.name:PutCharacteristicProfile001
 * @tc.desc: PutCharacteristicProfile success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, PutCharacteristicProfile001, TestSize.Level1)
{
    CharacteristicProfile charProfile;
    charProfile.SetDeviceId("deviceId");
    charProfile.SetServiceName("serviceName");
    charProfile.SetCharacteristicKey("characteristicKey");
    charProfile.SetCharacteristicValue("characteristicValue");
    
    int32_t errCode = DistributedDeviceProfileClient::GetInstance().PutCharacteristicProfile(charProfile);
    EXPECT_EQ(errCode, DP_PERMISSION_DENIED);
}

/**
 * @tc.name:PutCharacteristicProfileBatch001
 * @tc.desc: PutCharacteristicProfileBatch success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, PutCharacteristicProfileBatch001, TestSize.Level1)
{
    vector<CharacteristicProfile> charProfiles;
    
    CharacteristicProfile charProfile1;
    charProfile1.SetDeviceId("deviceId1");
    charProfile1.SetServiceName("serviceName1");
    charProfile1.SetCharacteristicKey("characteristicKey1");
    charProfile1.SetCharacteristicValue("characteristicValue1");
    CharacteristicProfile charProfile2;
    charProfile2.SetDeviceId("deviceId2");
    charProfile2.SetServiceName("serviceName2");
    charProfile2.SetCharacteristicKey("characteristicKey2");
    charProfile2.SetCharacteristicValue("characteristicValue2");
    charProfiles.push_back(charProfile1);
    charProfiles.push_back(charProfile2);

    int32_t errCode = DistributedDeviceProfileClient::GetInstance().PutCharacteristicProfileBatch(charProfiles);
    EXPECT_EQ(errCode, DP_PERMISSION_DENIED);
}

/**
 * @tc.name:PutCharacteristicProfileBatch002
 * @tc.desc: PutCharacteristicProfileBatch failed, CharacteristicProfiles size is invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, PutCharacteristicProfileBatch002, TestSize.Level1)
{
    vector<CharacteristicProfile> charProfiles;
    
    int32_t errCode = DistributedDeviceProfileClient::GetInstance().PutCharacteristicProfileBatch(charProfiles);
    EXPECT_EQ(errCode, DP_INVALID_PARAMS);
}

/**
 * @tc.name: GetDeviceProfile001
 * @tc.desc: GetDeviceProfile success, DeviceProfile Set and Get
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, GetDeviceProfile001, TestSize.Level1)
{
    string deviceId = "deviceId";
    DeviceProfile deviceProfile;
    
    int32_t errCode = DistributedDeviceProfileClient::GetInstance().GetDeviceProfile(deviceId, deviceProfile);
    EXPECT_NE(errCode, DP_SUCCESS);

    DeviceProfile deviceProfile1;
    deviceProfile1.SetDeviceId("anything");
    deviceProfile1.SetDeviceName("anything");
    deviceProfile1.SetManufactureName("anything");
    deviceProfile1.SetDeviceModel("anything");
    deviceProfile1.SetStorageCapability(1);
    deviceProfile1.SetOsSysCap("anything");
    deviceProfile1.SetOsApiLevel(1);
    deviceProfile1.SetOsVersion("anything");
    deviceProfile1.SetOsType(1);

    deviceProfile1.GetDeviceId();
    deviceProfile1.GetDeviceName();
    deviceProfile1.GetManufactureName();
    deviceProfile1.GetDeviceModel();
    deviceProfile1.GetStorageCapability();
    deviceProfile1.GetOsSysCap();
    deviceProfile1.GetOsApiLevel();
    deviceProfile1.GetOsVersion();
    deviceProfile1.GetOsType();
}

/**
 * @tc.name: GetServiceProfile001
 * @tc.desc: GetServiceProfile success, ServiceProfile Get
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, GetServiceProfile001, TestSize.Level1)
{
    string deviceId = "deviceId";
    string serviceName = "serviceName";
    ServiceProfile serviceProfile;
    
    int32_t errCode = DistributedDeviceProfileClient::GetInstance().GetServiceProfile(
        deviceId, serviceName, serviceProfile);
    EXPECT_NE(errCode, DP_SUCCESS);
}

/**
 * @tc.name: GetCharacteristicProfile001
 * @tc.desc: GetCharacteristicProfile success, CharacteristicProfile Get
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, GetCharacteristicProfile001, TestSize.Level1)
{
    string deviceId = "deviceId";
    string serviceName = "serviceName";
    string characteristicKey = "characteristicKey";
    CharacteristicProfile characteristicProfile;
    
    int32_t errCode = DistributedDeviceProfileClient::GetInstance().GetCharacteristicProfile(
            deviceId, serviceName, characteristicKey, characteristicProfile);
    EXPECT_NE(errCode, DP_SUCCESS);

    characteristicProfile.GetDeviceId();
    characteristicProfile.GetServiceName();
    characteristicProfile.GetCharacteristicKey();
}

/**
 * @tc.name: DeleteServiceProfile001
 * @tc.desc: DeleteServiceProfile success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, DeleteServiceProfile001, TestSize.Level1)
{
    int32_t errCode = DistributedDeviceProfileClient::GetInstance().DeleteServiceProfile(
            "deviceId", "serviceName", false, DEFAULT_USER_ID);
    EXPECT_NE(errCode, DP_SUCCESS);
}

/**
 * @tc.name: DeleteCharacteristicProfile001
 * @tc.desc: DeleteCharacteristicProfile success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, DeleteCharacteristicProfile001, TestSize.Level1)
{
    int32_t errCode = DistributedDeviceProfileClient::GetInstance().DeleteCharacteristicProfile(
            "deviceId", "serviceName", "characteristicKey", false, DEFAULT_USER_ID);
    EXPECT_NE(errCode, DP_SUCCESS);
}

/**
 * @tc.name: SubscribeDeviceProfile001
 * @tc.desc: SubscribeDeviceProfile success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, SubscribeDeviceProfile001, TestSize.Level1)
{
    string subscribeKey = "subscribeKey";
    int32_t saId = 4801;
    unordered_set<ProfileChangeType> subscribeTypes = {
        ProfileChangeType::SERVICE_PROFILE_ADD,
        ProfileChangeType::SERVICE_PROFILE_UPDATE,
        ProfileChangeType::SERVICE_PROFILE_DELETE
    };
    OHOS::sptr<IProfileChangeListener> subscribeDPChangeListener =
        OHOS::sptr<ProfileChangeListenerStub>(new SubscribeDPChangeListener);
    SubscribeInfo subscribeInfo(saId, subscribeKey, subscribeTypes, subscribeDPChangeListener);
    
    int32_t errCode = DistributedDeviceProfileClient::GetInstance().SubscribeDeviceProfile(subscribeInfo);
    EXPECT_EQ(errCode, DP_PERMISSION_DENIED);
}

/**
 * @tc.name: UnSubscribeDeviceProfile001
 * @tc.desc: UnSubscribeDeviceProfile success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, UnSubscribeDeviceProfile001, TestSize.Level1)
{
    string subscribeKey = "subscribeKey";
    int32_t saId = 4801;
    unordered_set<ProfileChangeType> subscribeTypes = {
            ProfileChangeType::SERVICE_PROFILE_ADD,
            ProfileChangeType::SERVICE_PROFILE_UPDATE,
            ProfileChangeType::SERVICE_PROFILE_DELETE
    };
    OHOS::sptr<IProfileChangeListener> subscribeDPChangeListener =
        OHOS::sptr<ProfileChangeListenerStub>(new SubscribeDPChangeListener);
    SubscribeInfo subscribeInfo(saId, subscribeKey, subscribeTypes, subscribeDPChangeListener);
    
    int32_t errCode = DistributedDeviceProfileClient::GetInstance().UnSubscribeDeviceProfile(subscribeInfo);
    EXPECT_EQ(errCode, DP_PERMISSION_DENIED);
}

/**
 * @tc.name: SyncDeviceProfile001
 * @tc.desc: SyncDeviceProfile failed, SyncCb is nullptr!
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, SyncDeviceProfile001, TestSize.Level1)
{
    DistributedDeviceProfile::DpSyncOptions syncOptions;
    OHOS::sptr<ISyncCompletedCallback> syncCb = nullptr;
    
    syncOptions.AddDevice("deviceId1");
    syncOptions.AddDevice("deviceId2");
    syncOptions.SetSyncMode(SyncMode::MIN);
    
    int32_t errCode = DistributedDeviceProfileClient::GetInstance().SyncDeviceProfile(syncOptions, syncCb);
    EXPECT_EQ(errCode, DP_SYNC_DEVICE_FAIL);
}

/**
 * @tc.name: OnServiceDied001
 * @tc.desc: OnServiceDied
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, OnServiceDied001, TestSize.Level1)
{
    OHOS::wptr<OHOS::IRemoteObject> remsotes = nullptr;
    DistributedDeviceProfileClient::DeviceProfileDeathRecipient deathRecipient;
    deathRecipient.OnRemoteDied(remsotes);

    OHOS::sptr<OHOS::IRemoteObject> remote = nullptr;
    DistributedDeviceProfileClient::GetInstance().OnServiceDied(remote);
    EXPECT_EQ(nullptr, DistributedDeviceProfileClient::GetInstance().dpProxy_);
}

/**
 * @tc.name: SubscribeDeviceProfileInited_001
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, SubscribeDeviceProfileInited_001, TestSize.Level1)
{
    OHOS::sptr<IDpInitedCallback> initedCb = sptr<IDpInitedCallback>(new DpInitedCallback());
    int32_t ret = DistributedDeviceProfileClient::GetInstance().SubscribeDeviceProfileInited(1000, initedCb);
    EXPECT_EQ(ret, DP_PERMISSION_DENIED);
}

/**
 * @tc.name: SubscribeDeviceProfileInited_002
 * @tc.desc: saId < 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, SubscribeDeviceProfileInited_002, TestSize.Level1)
{
    OHOS::sptr<IDpInitedCallback> initedCb = sptr<IDpInitedCallback>(new DpInitedCallback());
    int32_t ret = DistributedDeviceProfileClient::GetInstance().SubscribeDeviceProfileInited(-1, initedCb);
    EXPECT_EQ(ret, DP_INVALID_PARAM);
}

/**
 * @tc.name: SubscribeDeviceProfileInited_003
 * @tc.desc: saId > MAX_SAID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, SubscribeDeviceProfileInited_003, TestSize.Level1)
{
    OHOS::sptr<IDpInitedCallback> initedCb = sptr<IDpInitedCallback>(new DpInitedCallback());
    int32_t ret = DistributedDeviceProfileClient::GetInstance().SubscribeDeviceProfileInited(MAX_SAID + 1, initedCb);
    EXPECT_EQ(ret, DP_INVALID_PARAM);
}

/**
 * @tc.name: SubscribeDeviceProfileInited_004
 * @tc.desc: initedCb == nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, SubscribeDeviceProfileInited_004, TestSize.Level1)
{
    OHOS::sptr<IDpInitedCallback> initedCb = nullptr;
    int32_t ret = DistributedDeviceProfileClient::GetInstance().SubscribeDeviceProfileInited(MAX_SAID + 1, initedCb);
    EXPECT_EQ(ret, DP_INVALID_PARAM);
}

/**
 * @tc.name: UnSubscribeDeviceProfileInited_001
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, UnSubscribeDeviceProfileInited_001, TestSize.Level1)
{
    OHOS::sptr<IDpInitedCallback> initedCb = sptr<IDpInitedCallback>(new DpInitedCallback());
    DistributedDeviceProfileClient::GetInstance().dpInitedCallback_ = initedCb;
    int32_t ret = DistributedDeviceProfileClient::GetInstance().UnSubscribeDeviceProfileInited(1000);
    EXPECT_EQ(ret, DP_PERMISSION_DENIED);
}

/**
 * @tc.name: UnSubscribeDeviceProfileInited_002
 * @tc.desc: dpInitedCallback_ == nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, UnSubscribeDeviceProfileInited_002, TestSize.Level1)
{
    DistributedDeviceProfileClient::GetInstance().dpInitedCallback_ = nullptr;
    int32_t ret = DistributedDeviceProfileClient::GetInstance().UnSubscribeDeviceProfileInited(1000);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/**
 * @tc.name: UnSubscribeDeviceProfileInited_003
 * @tc.desc: saId < 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, UnSubscribeDeviceProfileInited_003, TestSize.Level1)
{
    OHOS::sptr<IDpInitedCallback> initedCb = sptr<IDpInitedCallback>(new DpInitedCallback());
    DistributedDeviceProfileClient::GetInstance().dpInitedCallback_ = initedCb;
    int32_t ret = DistributedDeviceProfileClient::GetInstance().UnSubscribeDeviceProfileInited(-1);
    EXPECT_EQ(ret, DP_INVALID_PARAM);
}

/**
 * @tc.name: UnSubscribeDeviceProfileInited_004
 * @tc.desc: saId > MAX_SAID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, UnSubscribeDeviceProfileInited_004, TestSize.Level1)
{
    OHOS::sptr<IDpInitedCallback> initedCb = sptr<IDpInitedCallback>(new DpInitedCallback());
    DistributedDeviceProfileClient::GetInstance().dpInitedCallback_ = initedCb;
    int32_t ret = DistributedDeviceProfileClient::GetInstance().UnSubscribeDeviceProfileInited(MAX_SAID + 1);
    EXPECT_EQ(ret, DP_INVALID_PARAM);
}

/**
 * @tc.name: DpinitedCallback001
 * @tc.desc: DP_SUCCESS
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, DpinitedCallback001, TestSize.Level1)
{
    std::shared_ptr<DpInitedCallbackStub> DpinitedCallbackStub_ = std::make_shared<MockDpInitedCallbackStub>();
    MessageParcel data;
    MessageParcel reply;
    DpInitedCallbackProxy proxy(nullptr);
    proxy.OnDpInited();
    int32_t ret = DpinitedCallbackStub_->OnDpInitedInner(data, reply);
    EXPECT_EQ(DP_SUCCESS, ret);
}

/**
 * @tc.name: OnRemoteRequest_001
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, OnRemoteRequest_001, TestSize.Level0)
{
    std::shared_ptr<DpInitedCallbackStub> DpinitedCallbackStub_ = std::make_shared<MockDpInitedCallbackStub>();
    uint32_t code = static_cast<uint32_t>(DPInterfaceCode::ON_DEVICE_PROFILE_INITED);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = DpinitedCallbackStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(DP_INTERFACE_CHECK_FAILED, ret);
}

/**
 * @tc.name: PutAllTrustedDevices_001
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, PutAllTrustedDevices_001, TestSize.Level0)
{
    std::vector<TrustedDeviceInfo> deviceInfos;
    int32_t errCode = DistributedDeviceProfileClient::GetInstance().PutAllTrustedDevices(deviceInfos);
    EXPECT_EQ(errCode, DP_INVALID_PARAMS);
}

/**
 * @tc.name: PutAllTrustedDevices_002
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, PutAllTrustedDevices_002, TestSize.Level0)
{
    TrustedDeviceInfo deviceInfo;
    std::vector<TrustedDeviceInfo> deviceInfos { deviceInfo };
    int32_t errCode = DistributedDeviceProfileClient::GetInstance().PutAllTrustedDevices(deviceInfos);
    EXPECT_EQ(errCode, DP_PERMISSION_DENIED);
}

/**
 * @tc.name: PutDeviceProfileBatch_001
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, PutDeviceProfileBatch_001, TestSize.Level0)
{
    std::vector<DeviceProfile> deviceProfiles;
    int32_t errCode = DistributedDeviceProfileClient::GetInstance().PutDeviceProfileBatch(deviceProfiles);
    EXPECT_EQ(errCode, DP_WRITE_PARCEL_FAIL);
}

/**
 * @tc.name: GetDeviceProfiles_001
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, GetDeviceProfiles_001, TestSize.Level0)
{
    std::vector<DeviceProfile> deviceProfiles;
    DeviceProfileFilterOptions options;
    int32_t errCode = DistributedDeviceProfileClient::GetInstance().GetDeviceProfiles(options, deviceProfiles);
    EXPECT_EQ(errCode, DP_PERMISSION_DENIED);
}

/**
 * @tc.name: DeleteDeviceProfileBatch_001
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, DeleteDeviceProfileBatch_001, TestSize.Level0)
{
    std::vector<DeviceProfile> deviceProfiles;
    int32_t errCode = DistributedDeviceProfileClient::GetInstance().DeleteDeviceProfileBatch(deviceProfiles);
    EXPECT_EQ(errCode, DP_WRITE_PARCEL_FAIL);
}

/**
 * @tc.name: PutDeviceIconInfoBatch_001
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, PutDeviceIconInfoBatch_001, TestSize.Level0)
{
    std::vector<DeviceIconInfo> deviceIconInfos;
    int32_t errCode = DistributedDeviceProfileClient::GetInstance().PutDeviceIconInfoBatch(deviceIconInfos);
    EXPECT_NE(errCode, DP_SUCCESS);
}

/**
 * @tc.name: GetDeviceIconInfos_001
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, GetDeviceIconInfos_001, TestSize.Level0)
{
    DeviceIconInfoFilterOptions filterOptions;
    std::vector<DeviceIconInfo> deviceIconInfos;
    int32_t errCode = DistributedDeviceProfileClient::GetInstance().GetDeviceIconInfos(filterOptions, deviceIconInfos);
    EXPECT_EQ(errCode, DP_PERMISSION_DENIED);
}

/**
 * @tc.name: SubscribePinCodeInvalid_001
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, SubscribePinCodeInvalid_001, TestSize.Level0)
{
    std::string bundleName = "";
    int32_t pinExchangeType = 5;
    sptr<IPincodeInvalidCallback> pinCodeCallback;
    int32_t errCode = DistributedDeviceProfileClient::GetInstance().SubscribePinCodeInvalid(bundleName,
        pinExchangeType, pinCodeCallback);
    EXPECT_EQ(errCode, DP_INVALID_PARAM);
}

/**
 * @tc.name: SubscribePinCodeInvalid_003
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, SubscribePinCodeInvalid_003, TestSize.Level1)
{
    OHOS::sptr<IPincodeInvalidCallback> pincodeInvalidCb = sptr<IPincodeInvalidCallback>(new PinCodeInvalidCallback());
    std::string bundleName = "bundleName";
    int32_t pinExchangeType = 1;
    int32_t ret = DistributedDeviceProfileClient::GetInstance().SubscribePinCodeInvalid(bundleName, pinExchangeType,
        pincodeInvalidCb);
    EXPECT_EQ(ret, DP_PERMISSION_DENIED);
}

/**
 * @tc.name: UnSubscribePinCodeInvalid_001
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, UnSubscribePinCodeInvalid_001, TestSize.Level1)
{
    OHOS::sptr<IPincodeInvalidCallback> pincodeInvalidCb = sptr<IPincodeInvalidCallback>(new PinCodeInvalidCallback());
    std::string bundleName = "bundleName";
    int32_t pinExchangeType = 1;
    DistributedDeviceProfileClient::GetInstance().pinCodeCallback_ = pincodeInvalidCb;
    int32_t ret = DistributedDeviceProfileClient::GetInstance().UnSubscribePinCodeInvalid(bundleName, pinExchangeType);
    EXPECT_EQ(ret, DP_PERMISSION_DENIED);
}

/**
 * @tc.name: PutServiceInfoProfile_001
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, PutServiceInfoProfile_001, TestSize.Level0)
{
    ServiceInfoProfile serviceInfoProfile;
    int32_t errCode = DistributedDeviceProfileClient::GetInstance().PutServiceInfoProfile(serviceInfoProfile);
    EXPECT_NE(errCode, DP_SUCCESS);
}

/**
 * @tc.name: DeleteServiceInfoProfile_001
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, DeleteServiceInfoProfile_001, TestSize.Level0)
{
    ServiceInfoUniqueKey key;
    int32_t errCode = DistributedDeviceProfileClient::GetInstance().DeleteServiceInfoProfile(key);
    EXPECT_NE(errCode, DP_SUCCESS);
}

/**
 * @tc.name: UpdateServiceInfoProfile_001
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, UpdateServiceInfoProfile_001, TestSize.Level0)
{
    ServiceInfoProfile serviceInfoProfile;
    int32_t errCode = DistributedDeviceProfileClient::GetInstance().UpdateServiceInfoProfile(serviceInfoProfile);
    EXPECT_NE(errCode, DP_SUCCESS);
}


/**
 * @tc.name: GetServiceInfoProfileByUniqueKey_001
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, GetServiceInfoProfileByUniqueKey_001, TestSize.Level0)
{
    ServiceInfoUniqueKey key;
    ServiceInfoProfile serviceInfoProfile;
    int32_t errCode = DistributedDeviceProfileClient::GetInstance().GetServiceInfoProfileByUniqueKey(key,
        serviceInfoProfile);
    EXPECT_NE(errCode, DP_SUCCESS);
}

/**
 * @tc.name: GetServiceInfoProfileListByTokenId_001
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, GetServiceInfoProfileListByTokenId_001, TestSize.Level0)
{
    ServiceInfoUniqueKey key;
    std::vector<ServiceInfoProfile> serviceInfoProfiles;
    int32_t errCode =
        DistributedDeviceProfileClient::GetInstance().GetServiceInfoProfileListByTokenId(key, serviceInfoProfiles);
    EXPECT_NE(errCode, DP_SUCCESS);
}

/**
 * @tc.name: GetAllServiceInfoProfileList_001
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, GetAllServiceInfoProfileList_001, TestSize.Level0)
{
    std::vector<ServiceInfoProfile> serviceInfoProfiles;
    int32_t errCode = DistributedDeviceProfileClient::GetInstance().GetAllServiceInfoProfileList(serviceInfoProfiles);
    EXPECT_NE(errCode, DP_SUCCESS);
}

/**
 * @tc.name: GetServiceInfoProfileListByBundleName_001
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, GetServiceInfoProfileListByBundleName_001, TestSize.Level0)
{
    ServiceInfoUniqueKey key;
    std::vector<ServiceInfoProfile> serviceInfoProfiles;
    int32_t errCode =
        DistributedDeviceProfileClient::GetInstance().GetServiceInfoProfileListByBundleName(key, serviceInfoProfiles);
    EXPECT_NE(errCode, DP_SUCCESS);
}

/**
 * @tc.name: PutProductInfoBatch_001
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, PutProductInfoBatch_001, TestSize.Level1)
{
    std::vector<ProductInfo> productInfos;
    int32_t errCode =
        DistributedDeviceProfileClient::GetInstance().PutProductInfoBatch(productInfos);
    EXPECT_NE(errCode, DP_SUCCESS);
}

/**
 * @tc.name: PutLocalServiceInfo_001
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, PutLocalServiceInfo_001, TestSize.Level1)
{
    LocalServiceInfo localServiceInfo;
    int32_t errCode =
        DistributedDeviceProfileClient::GetInstance().PutLocalServiceInfo(localServiceInfo);
    EXPECT_NE(errCode, DP_SUCCESS);
}

/**
 * @tc.name: UpdateLocalServiceInfo_001
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, UpdateLocalServiceInfo_001, TestSize.Level1)
{
    LocalServiceInfo localServiceInfo;
    int32_t errCode =
        DistributedDeviceProfileClient::GetInstance().UpdateLocalServiceInfo(localServiceInfo);
    EXPECT_NE(errCode, DP_SUCCESS);
}

/**
 * @tc.name: GetLocalServiceInfoByBundleAndPinType_001
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, GetLocalServiceInfoByBundleAndPinType_001, TestSize.Level1)
{
    std::string bundleName = "bundleName";
    int32_t pinExchangeType = 0;
    LocalServiceInfo localServiceInfo;
    int32_t errCode = DistributedDeviceProfileClient::GetInstance().
        GetLocalServiceInfoByBundleAndPinType(bundleName, pinExchangeType, localServiceInfo);
    EXPECT_NE(errCode, DP_SUCCESS);
}

/**
 * @tc.name: DeleteLocalServiceInfo_001
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, DeleteLocalServiceInfo_001, TestSize.Level1)
{
    std::string bundleName = "bundleName";
    int32_t pinExchangeType = 0;
    int32_t errCode = DistributedDeviceProfileClient::GetInstance().
        DeleteLocalServiceInfo(bundleName, pinExchangeType);
    EXPECT_NE(errCode, DP_SUCCESS);
}

HWTEST_F(DistributedDeviceProfileClientKvTest, SubscribePinCodeInvalid_002, TestSize.Level1)
{
    OHOS::sptr<IPincodeInvalidCallback> pincodeInvalidCb = sptr<IPincodeInvalidCallback>(new PinCodeInvalidCallback());
    std::string bundleName = "bundleName";
    int32_t pinExchangeType = 1;
    int32_t ret = DistributedDeviceProfileClient::GetInstance().SubscribePinCodeInvalid(bundleName, pinExchangeType,
        pincodeInvalidCb);
    EXPECT_EQ(ret, DP_PERMISSION_DENIED);
}

HWTEST_F(DistributedDeviceProfileClientKvTest, RegisterBusinessCallback_001, TestSize.Level1)
{
    std::string saId = "validSaId";
    std::string businessKey = "validBusinessKey";
    sptr<IBusinessCallback> businessCallback = sptr<IBusinessCallback>(new BusinessCallback());

    int32_t ret = DistributedDeviceProfileClient::GetInstance().
        RegisterBusinessCallback(saId, businessKey, businessCallback);
    EXPECT_NE(ret, DP_SUCCESS);
}

HWTEST_F(DistributedDeviceProfileClientKvTest, RegisterBusinessCallback_002, TestSize.Level1)
{
    std::string saId = "";
    std::string businessKey = "validBusinessKey";
    sptr<IBusinessCallback> businessCallback = sptr<IBusinessCallback>(new BusinessCallback());

    int32_t ret = DistributedDeviceProfileClient::GetInstance().
        RegisterBusinessCallback(saId, businessKey, businessCallback);
    EXPECT_EQ(ret, DP_INVALID_PARAM);
}

HWTEST_F(DistributedDeviceProfileClientKvTest, RegisterBusinessCallback_003, TestSize.Level1)
{
    std::string saId = "validSaId";
    std::string businessKey = "";
    sptr<IBusinessCallback> businessCallback = sptr<IBusinessCallback>(new BusinessCallback());

    int32_t ret = DistributedDeviceProfileClient::GetInstance().
        RegisterBusinessCallback(saId, businessKey, businessCallback);
    EXPECT_EQ(ret, DP_INVALID_PARAM);
}

HWTEST_F(DistributedDeviceProfileClientKvTest, RegisterBusinessCallback_004, TestSize.Level1)
{
    std::string saId = "validSaId";
    std::string businessKey = "validBusinessKey";
    sptr<IBusinessCallback> businessCallback = nullptr;

    int32_t ret = DistributedDeviceProfileClient::GetInstance().
        RegisterBusinessCallback(saId, businessKey, businessCallback);
    EXPECT_EQ(ret, DP_INVALID_PARAM);
}

HWTEST_F(DistributedDeviceProfileClientKvTest, RegisterBusinessCallback_005, TestSize.Level1)
{
    std::string saId = "validSaId";
    std::string businessKey = "validBusinessKey";
    sptr<IBusinessCallback> businessCallback = sptr<IBusinessCallback>(new BusinessCallback());

    DistributedDeviceProfileClient::GetInstance().dpProxy_ = nullptr;

    int32_t ret = DistributedDeviceProfileClient::GetInstance().
        RegisterBusinessCallback(saId, businessKey, businessCallback);
    EXPECT_NE(ret, DP_SUCCESS);

    DistributedDeviceProfileClient::GetInstance().dpProxy_ =
        DistributedDeviceProfileClient::GetInstance().GetDeviceProfileService();
    EXPECT_NE(DistributedDeviceProfileClient::GetInstance().dpProxy_, nullptr);
}

HWTEST_F(DistributedDeviceProfileClientKvTest, RegisterBusinessCallback_006, TestSize.Level1)
{
    std::string saId = "validSaId";
    std::string businessKey = "validBusinessKey";
    sptr<IBusinessCallback> businessCallback = sptr<IBusinessCallback>(new BusinessCallback());

    sptr<IRemoteObject> innerBusinessCallback = nullptr;

    int32_t ret = DistributedDeviceProfileClient::GetInstance().
        RegisterBusinessCallback(saId, businessKey, businessCallback);
    EXPECT_NE(ret, DP_SUCCESS);
}

HWTEST_F(DistributedDeviceProfileClientKvTest, UnRegisterBusinessCallback_001, TestSize.Level1)
{
    std::string saId = "validSaId";
    std::string businessKey = "validBusinessKey";
    sptr<IBusinessCallback> businessCallback = sptr<IBusinessCallback>(new BusinessCallback());
    DistributedDeviceProfileClient::GetInstance().businessCallback_ = businessCallback;

    int32_t ret = DistributedDeviceProfileClient::GetInstance().UnRegisterBusinessCallback(saId, businessKey);
    EXPECT_NE(ret, DP_SUCCESS);
}

HWTEST_F(DistributedDeviceProfileClientKvTest, UnRegisterBusinessCallback_002, TestSize.Level1)
{
    std::string saId = "validSaId";
    std::string businessKey = "validBusinessKey";
    DistributedDeviceProfileClient::GetInstance().businessCallback_ = nullptr;

    int32_t ret = DistributedDeviceProfileClient::GetInstance().UnRegisterBusinessCallback(saId, businessKey);
    EXPECT_EQ(ret, DP_SUCCESS);

    sptr<IBusinessCallback> businessCallback = sptr<IBusinessCallback>(new BusinessCallback());
    ret = DistributedDeviceProfileClient::GetInstance().RegisterBusinessCallback(saId, businessKey, businessCallback);
    EXPECT_NE(ret, DP_SUCCESS);
    EXPECT_EQ(DistributedDeviceProfileClient::GetInstance().businessCallback_, nullptr);
}

HWTEST_F(DistributedDeviceProfileClientKvTest, UnRegisterBusinessCallback_003, TestSize.Level1)
{
    std::string saId = "";
    std::string businessKey = "validBusinessKey";
    sptr<IBusinessCallback> businessCallback = sptr<IBusinessCallback>(new BusinessCallback());
    DistributedDeviceProfileClient::GetInstance().businessCallback_ = businessCallback;

    int32_t ret = DistributedDeviceProfileClient::GetInstance().UnRegisterBusinessCallback(saId, businessKey);
    EXPECT_EQ(ret, DP_INVALID_PARAM);
}

HWTEST_F(DistributedDeviceProfileClientKvTest, UnRegisterBusinessCallback_004, TestSize.Level1)
{
    std::string saId = "validSaId";
    std::string businessKey = "";
    sptr<IBusinessCallback> businessCallback = sptr<IBusinessCallback>(new BusinessCallback());
    DistributedDeviceProfileClient::GetInstance().businessCallback_ = businessCallback;

    int32_t ret = DistributedDeviceProfileClient::GetInstance().UnRegisterBusinessCallback(saId, businessKey);
    EXPECT_EQ(ret, DP_INVALID_PARAM);
}

HWTEST_F(DistributedDeviceProfileClientKvTest, UnRegisterBusinessCallback_005, TestSize.Level1)
{
    std::string saId = "validSaId";
    std::string businessKey = "validBusinessKey";
    sptr<IBusinessCallback> businessCallback = sptr<IBusinessCallback>(new BusinessCallback());
    DistributedDeviceProfileClient::GetInstance().businessCallback_ = businessCallback;

    DistributedDeviceProfileClient::GetInstance().dpProxy_ = nullptr;

    int32_t ret = DistributedDeviceProfileClient::GetInstance().UnRegisterBusinessCallback(saId, businessKey);
    EXPECT_NE(ret, DP_SUCCESS);

    DistributedDeviceProfileClient::GetInstance().dpProxy_ =
        DistributedDeviceProfileClient::GetInstance().GetDeviceProfileService();
    EXPECT_NE(DistributedDeviceProfileClient::GetInstance().dpProxy_, nullptr);
}

HWTEST_F(DistributedDeviceProfileClientKvTest, PutBusinessEvent_001, TestSize.Level1)
{
    DistributedDeviceProfileClient::GetInstance().dpProxy_ = nullptr;

    BusinessEvent event;
    event.SetBusinessKey("business_id_cast+_reject_event");
    event.SetBusinessValue("validValue");

    int32_t ret = DistributedDeviceProfileClient::GetInstance().PutBusinessEvent(event);
    EXPECT_NE(ret, DP_SUCCESS);

    DistributedDeviceProfileClient::GetInstance().dpProxy_ =
        DistributedDeviceProfileClient::GetInstance().GetDeviceProfileService();
    EXPECT_NE(DistributedDeviceProfileClient::GetInstance().dpProxy_, nullptr);
}

HWTEST_F(DistributedDeviceProfileClientKvTest, PutBusinessEvent_002, TestSize.Level1)
{
    BusinessEvent event;
    event.SetBusinessKey("business_id_cast+_reject_event");
    event.SetBusinessValue("validValue");

    int32_t ret = DistributedDeviceProfileClient::GetInstance().PutBusinessEvent(event);
    EXPECT_NE(ret, DP_SUCCESS);
}

HWTEST_F(DistributedDeviceProfileClientKvTest, GetBusinessEvent_001, TestSize.Level1)
{
    DistributedDeviceProfileClient::GetInstance().dpProxy_ = nullptr;

    BusinessEvent event;
    event.SetBusinessKey("business_id_cast+_reject_event");

    int32_t ret = DistributedDeviceProfileClient::GetInstance().GetBusinessEvent(event);
    EXPECT_NE(ret, DP_SUCCESS);

    DistributedDeviceProfileClient::GetInstance().dpProxy_ =
        DistributedDeviceProfileClient::GetInstance().GetDeviceProfileService();
    EXPECT_NE(DistributedDeviceProfileClient::GetInstance().dpProxy_, nullptr);
}

HWTEST_F(DistributedDeviceProfileClientKvTest, GetBusinessEvent_002, TestSize.Level1)
{
    BusinessEvent event;
    event.SetBusinessKey("business_id_cast+_reject_event");

    int32_t ret = DistributedDeviceProfileClient::GetInstance().GetBusinessEvent(event);
    EXPECT_NE(ret, DP_SUCCESS);
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
