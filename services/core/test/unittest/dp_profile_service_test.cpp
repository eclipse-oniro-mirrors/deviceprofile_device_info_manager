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

#include <gtest/gtest.h>
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

#define private   public
#define protected public
#include "distributed_device_profile_service_new.h"
#include "system_ability_definition.h"
#include "profile_cache.h"
#include "distributed_device_profile_errors.h"
#include "trust_profile_manager.h"
#include "permission_manager.h"
#include "subscribe_profile_manager.h"
#include "event_handler_factory.h"
#include "distributed_device_profile_constants.h"
#include "dp_inited_callback_stub.h"
#include "i_dp_inited_callback.h"
#undef private
#undef protected


namespace OHOS {
namespace DistributedDeviceProfile {
using namespace testing;
using namespace testing::ext;
namespace {
const std::string PERMISSION_JSON_PATH = "/system/etc/deviceprofile/permission.json";
const int32_t PERMS_NUM = 2;
}
class DpProfileServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void DpProfileServiceTest::SetUpTestCase()
{
}

void DpProfileServiceTest::TearDownTestCase()
{
}

void DpProfileServiceTest::SetUp()
{
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
        .processName = "deviceprofile",
        .aplStr = "system_core",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

void DpProfileServiceTest::TearDown()
{
}

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

HWTEST_F(DpProfileServiceTest, Init_001, TestSize.Level1)
{
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().Init();
    EXPECT_EQ(DP_SUCCESS, ret);
}

HWTEST_F(DpProfileServiceTest, UnInit_001, TestSize.Level1)
{
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().UnInit();
    EXPECT_EQ(DP_DEVICE_PROFILE_MANAGER_UNINIT_FAIL, ret);
}

HWTEST_F(DpProfileServiceTest, CreateUnloadHandler_001, TestSize.Level1)
{
    DistributedDeviceProfileServiceNew::GetInstance().unloadHandler_ = nullptr;
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().CreateUnloadHandler();
    EXPECT_EQ(DP_SUCCESS, ret);
    
    ret = DistributedDeviceProfileServiceNew::GetInstance().DestroyUnloadHandler();
    EXPECT_EQ(DP_SUCCESS, ret);
    
    EventHandlerFactory::GetInstance().Init();
    ret = DistributedDeviceProfileServiceNew::GetInstance().CreateUnloadHandler();
    EXPECT_EQ(DP_SUCCESS, ret);
    
    ret = DistributedDeviceProfileServiceNew::GetInstance().DestroyUnloadHandler();
    EXPECT_EQ(DP_SUCCESS, ret);
}

HWTEST_F(DpProfileServiceTest, PutAccessControlProfile_001, TestSize.Level1)
{
    AccessControlProfile accessControlProfile;
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().PutAccessControlProfile(accessControlProfile);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
    DistributedDeviceProfileServiceNew::GetInstance().DelayUnloadTask();
}

HWTEST_F(DpProfileServiceTest, UpdateAccessControlProfile_001, TestSize.Level1)
{
    AccessControlProfile accessControlProfile;
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().UpdateAccessControlProfile(accessControlProfile);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
}

HWTEST_F(DpProfileServiceTest, PutProductInfoBatch_001, TestSize.Level1)
{
    std::vector<ProductInfo> productInfos;
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().PutProductInfoBatch(productInfos);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
}

HWTEST_F(DpProfileServiceTest, PutDeviceIconInfoBatch_001, TestSize.Level1)
{
    std::vector<DeviceIconInfo> deviceIconInfos;
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().PutDeviceIconInfoBatch(deviceIconInfos);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
}

HWTEST_F(DpProfileServiceTest, GetDeviceIconInfos_001, TestSize.Level1)
{
    DeviceIconInfoFilterOptions filterOptions;
    std::vector<DeviceIconInfo> deviceIconInfos;
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().GetDeviceIconInfos(filterOptions, deviceIconInfos);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
}

HWTEST_F(DpProfileServiceTest, DeleteDeviceProfileBatch_001, TestSize.Level1)
{
    std::vector<DeviceProfile> deviceProfiles;
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().DeleteDeviceProfileBatch(deviceProfiles);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
}

HWTEST_F(DpProfileServiceTest, GetTrustDeviceProfile_001, TestSize.Level1)
{
    std::string devid;
    TrustDeviceProfile trustDeviceProfile;
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().GetTrustDeviceProfile(devid, trustDeviceProfile);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
}

HWTEST_F(DpProfileServiceTest, GetAllTrustDeviceProfile_001, TestSize.Level1)
{
    std::vector<TrustDeviceProfile> trustDeviceProfiles;
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().GetAllTrustDeviceProfile(trustDeviceProfiles);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
}

HWTEST_F(DpProfileServiceTest, GetAccessControlProfile_001, TestSize.Level1)
{
    std::map<std::string, std::string> queryParams;
    std::vector<AccessControlProfile> accessControlProfiles;
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().GetAccessControlProfile(queryParams,
        accessControlProfiles);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
}

HWTEST_F(DpProfileServiceTest, GetAllAccessControlProfile_001, TestSize.Level1)
{
    std::vector<AccessControlProfile> accessControlProfiles;
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().GetAllAccessControlProfile(accessControlProfiles);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
}

HWTEST_F(DpProfileServiceTest, DeleteAccessControlProfile_001, TestSize.Level1)
{
    int32_t accessControlId = 0;
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().DeleteAccessControlProfile(accessControlId);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
}

HWTEST_F(DpProfileServiceTest, PutSessionKey_001, TestSize.Level1)
{
    uint32_t userId = 0;
    std::vector<uint8_t> sessionKey;
    int32_t sessionKeyId = 0;
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().PutSessionKey(userId, sessionKey, sessionKeyId);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
}

HWTEST_F(DpProfileServiceTest, GetSessionKey_001, TestSize.Level1)
{
    uint32_t userId = 0;
    std::vector<uint8_t> sessionKey;
    int32_t sessionKeyId = 0;
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().GetSessionKey(userId, sessionKeyId, sessionKey);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
}

HWTEST_F(DpProfileServiceTest, UpdateSessionKey_001, TestSize.Level1)
{
    uint32_t userId = 0;
    std::vector<uint8_t> sessionKey;
    int32_t sessionKeyId = 0;
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().UpdateSessionKey(userId, sessionKeyId, sessionKey);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
}

HWTEST_F(DpProfileServiceTest, DeleteSessionKey_001, TestSize.Level1)
{
    uint32_t userId = 0;
    int32_t sessionKeyId = 0;
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().DeleteSessionKey(userId, sessionKeyId);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
}

HWTEST_F(DpProfileServiceTest, PutServiceProfile_001, TestSize.Level1)
{
    std::string devid = "";
    std::string serName = "serName_test";
    std::string serviceType = "serviceType_test";
    ServiceProfile serviceProfile(devid, serName, serviceType);
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().PutServiceProfile(serviceProfile);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
}

HWTEST_F(DpProfileServiceTest, PutServiceProfileBatch_001, TestSize.Level1)
{
    std::vector<ServiceProfile> serviceProfiles;
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().PutServiceProfileBatch(serviceProfiles);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
}

HWTEST_F(DpProfileServiceTest, PutCharacteristicProfile_001, TestSize.Level1)
{
    CharacteristicProfile charProfile;
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().PutCharacteristicProfile(charProfile);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
}

HWTEST_F(DpProfileServiceTest, PutServiceInfoProfile_001, TestSize.Level1)
{
    ServiceInfoProfile serviceInfoProfile;
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().PutServiceInfoProfile(serviceInfoProfile);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
}

HWTEST_F(DpProfileServiceTest, DeleteServiceInfoProfile_001, TestSize.Level1)
{
    ServiceInfoUniqueKey key;
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().DeleteServiceInfoProfile(key);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
}

HWTEST_F(DpProfileServiceTest, UpdateServiceInfoProfile_001, TestSize.Level1)
{
    ServiceInfoProfile serviceInfoProfile;
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().UpdateServiceInfoProfile(serviceInfoProfile);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
}

HWTEST_F(DpProfileServiceTest, GetServiceInfoProfileByUniqueKey_001, TestSize.Level1)
{
    ServiceInfoUniqueKey key;
    ServiceInfoProfile serviceInfoProfile;
    int32_t ret =
        DistributedDeviceProfileServiceNew::GetInstance().GetServiceInfoProfileByUniqueKey(key, serviceInfoProfile);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
}

HWTEST_F(DpProfileServiceTest, GetServiceInfoProfileListByTokenId_001, TestSize.Level1)
{
    ServiceInfoUniqueKey key;
    std::vector<ServiceInfoProfile> serviceInfoProfiles;
    int32_t ret =
        DistributedDeviceProfileServiceNew::GetInstance().GetServiceInfoProfileListByTokenId(key, serviceInfoProfiles);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
}

HWTEST_F(DpProfileServiceTest, GetAllServiceInfoProfileList_001, TestSize.Level1)
{
    std::vector<ServiceInfoProfile> serviceInfoProfiles;
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().GetAllServiceInfoProfileList(serviceInfoProfiles);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
}

HWTEST_F(DpProfileServiceTest, GetServiceInfoProfileListByBundleName_001, TestSize.Level1)
{
    ServiceInfoUniqueKey key;
    std::vector<ServiceInfoProfile> serviceInfoProfiles;
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().GetServiceInfoProfileListByBundleName(
        key, serviceInfoProfiles);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
}

HWTEST_F(DpProfileServiceTest, PutCharacteristicProfileBatch_001, TestSize.Level1)
{
    std::string devid = "";
    std::string serName = "serName_test";
    std::string charKey = "charKey_test";
    std::string characteristicValue = "characteristicValue_test";
    CharacteristicProfile charProfile(devid, serName, charKey, characteristicValue);
    std::vector<CharacteristicProfile> charProfiles;
    charProfiles.push_back(charProfile);
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().PutCharacteristicProfileBatch(charProfiles);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
}

HWTEST_F(DpProfileServiceTest, GetDeviceProfile_001, TestSize.Level1)
{
    std::string devid = "";
    DeviceProfile deviceProfile;
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().GetDeviceProfile(devid, deviceProfile);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
}

HWTEST_F(DpProfileServiceTest, GetDeviceProfiles_001, TestSize.Level1)
{
    DeviceProfileFilterOptions options;
    std::vector<DeviceProfile> deviceProfiles;
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().GetDeviceProfiles(options, deviceProfiles);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
}

HWTEST_F(DpProfileServiceTest, GetServiceProfile_001, TestSize.Level1)
{
    std::string devid = "";
    std::string serName = "";
    ServiceProfile serviceProfile;
    int32_t ret =
            DistributedDeviceProfileServiceNew::GetInstance().GetServiceProfile(devid, serName, serviceProfile);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
}

HWTEST_F(DpProfileServiceTest, GetCharacteristicProfile_001, TestSize.Level1)
{
    std::string devid = "";
    std::string serName = "";
    std::string charKey = "";
    CharacteristicProfile charProfile;
    int32_t ret =
            DistributedDeviceProfileServiceNew::GetInstance().GetCharacteristicProfile(devid,
                                                                                       serName, charKey, charProfile);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
}

HWTEST_F(DpProfileServiceTest, DeleteServiceProfile_001, TestSize.Level1)
{
    std::string devid = "";
    std::string serName = "";
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().DeleteServiceProfile(devid, serName);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
}

HWTEST_F(DpProfileServiceTest, DeleteCharacteristicProfile_001, TestSize.Level1)
{
    std::string devid = "";
    std::string serName = "";
    std::string charKey = "";
    int32_t ret =
            DistributedDeviceProfileServiceNew::GetInstance().DeleteCharacteristicProfile(devid, serName, charKey);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
}

HWTEST_F(DpProfileServiceTest, PutLocalServiceInfo_001, TestSize.Level1)
{
    LocalServiceInfo localServiceInfo;
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().PutLocalServiceInfo(localServiceInfo);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
}

HWTEST_F(DpProfileServiceTest, UpdateLocalServiceInfo_001, TestSize.Level1)
{
    LocalServiceInfo localServiceInfo;
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().UpdateLocalServiceInfo(localServiceInfo);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
}

HWTEST_F(DpProfileServiceTest, GetLocalServiceInfoByBundleAndPinType_001, TestSize.Level1)
{
    std::string bundleName;
    int32_t pinExchangeType = 0;
    LocalServiceInfo localServiceInfo;
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().GetLocalServiceInfoByBundleAndPinType(
        bundleName, pinExchangeType, localServiceInfo);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
}

HWTEST_F(DpProfileServiceTest, DeleteLocalServiceInfo_001, TestSize.Level1)
{
    std::string bundleName;
    int32_t pinExchangeType = 0;
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().DeleteLocalServiceInfo(bundleName, pinExchangeType);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
}

HWTEST_F(DpProfileServiceTest, SubscribeDeviceProfile_001, TestSize.Level1)
{
    SubscribeInfo subscriberInfo;
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().SubscribeDeviceProfile(subscriberInfo);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
}

HWTEST_F(DpProfileServiceTest, UnSubscribeDeviceProfile_001, TestSize.Level1)
{
    SubscribeInfo subscriberInfo;
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().UnSubscribeDeviceProfile(subscriberInfo);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
}

HWTEST_F(DpProfileServiceTest, SyncDeviceProfile_001, TestSize.Level1)
{
    DistributedDeviceProfile::DpSyncOptions syncOptions;
    sptr<IRemoteObject> syncCallback = nullptr;
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().SyncDeviceProfile(syncOptions, syncCallback);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
}

HWTEST_F(DpProfileServiceTest, Dump_001, TestSize.Level1)
{
    int32_t fd = -1;
    std::vector<std::u16string> args;
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().Dump(fd, args);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
}

HWTEST_F(DpProfileServiceTest, SubscribeDeviceProfileInited_001, TestSize.Level1)
{
    int32_t saId = 1000;
    OHOS::sptr<IRemoteObject> initedCb = sptr<IRemoteObject>(new DpInitedCallback());
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().SubscribeDeviceProfileInited(saId, initedCb);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
}

HWTEST_F(DpProfileServiceTest, UnSubscribeDeviceProfileInited_001, TestSize.Level1)
{
    int32_t saId = 1000;
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().UnSubscribeDeviceProfileInited(saId);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
}

HWTEST_F(DpProfileServiceTest, SubscribePinCodeInvalid_001, TestSize.Level1)
{
    SystemAbilityOnDemandReason startReason;
    DistributedDeviceProfileServiceNew::GetInstance().OnStart(startReason);
    DistributedDeviceProfileServiceNew::GetInstance().OnStop();
    std::string bundleName;
    int32_t pinExchangeType = 0;
    sptr<IRemoteObject> pinCodeCallback;
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().SubscribePinCodeInvalid(
        bundleName, pinExchangeType, pinCodeCallback);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
}

HWTEST_F(DpProfileServiceTest, UnSubscribePinCodeInvalid_001, TestSize.Level1)
{
    std::string bundleName;
    int32_t pinExchangeType = 0;
    int32_t ret =
        DistributedDeviceProfileServiceNew::GetInstance().UnSubscribePinCodeInvalid(bundleName, pinExchangeType);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
}

HWTEST_F(DpProfileServiceTest, NotifyPinCodeInvalid_001, TestSize.Level1)
{
    LocalServiceInfo localServiceInfo;
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().NotifyPinCodeInvalid(localServiceInfo);
    EXPECT_EQ(DP_SUCCESS, ret);
}

HWTEST_F(DpProfileServiceTest, NotifyPinCodeInvalid_002, TestSize.Level1)
{
    LocalServiceInfo localServiceInfo;
    localServiceInfo.SetBundleName("aaa");
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().NotifyPinCodeInvalid(localServiceInfo);
    EXPECT_EQ(0, ret);
}

HWTEST_F(DpProfileServiceTest, PutAllTrustedDevices_001, TestSize.Level1)
{
    std::vector<TrustedDeviceInfo> deviceInfos;
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().PutAllTrustedDevices(deviceInfos);
    EXPECT_EQ(DP_PERMISSION_DENIED, ret);
}

HWTEST_F(DpProfileServiceTest, UnInitNext_001, TestSize.Level1)
{
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().UnInitNext();
    EXPECT_EQ(DP_SUCCESS, ret);
}
}
}
