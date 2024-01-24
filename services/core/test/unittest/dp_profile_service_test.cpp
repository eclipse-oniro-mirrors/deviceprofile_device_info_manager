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

#include <gtest/gtest.h>

#define private   public
#define protected public
#include "distributed_device_profile_service_new.h"
#include "system_ability_definition.h"
#include "profile_cache.h"
#include "distributed_device_profile_errors.h"
#include "trust_profile_manager.h"
#include "device_profile_manager.h"
#include "permission_manager.h"
#include "subscribe_profile_manager.h"
#include "event_handler_factory.h"
#include "distributed_device_profile_constants.h"
#undef private
#undef protected


namespace OHOS {
namespace DistributedDeviceProfile {
using namespace testing;
using namespace testing::ext;
namespace {
const std::string PERMISSION_JSON_PATH = "/system/etc/deviceprofile/permission.json";
}

class DpProfileServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void DpProfileServiceTest::SetUpTestCase() {
}

void DpProfileServiceTest::TearDownTestCase() {
}

void DpProfileServiceTest::SetUp() {
}

void DpProfileServiceTest::TearDown() {
}

HWTEST_F(DpProfileServiceTest, Init_001, TestSize.Level1)
{
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().Init();
    EXPECT_EQ(DP_SUCCESS, ret);
}

HWTEST_F(DpProfileServiceTest, UnInit_001, TestSize.Level1)
{
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().UnInit();
    EXPECT_EQ(DP_SUCCESS, ret);
}

HWTEST_F(DpProfileServiceTest, CreateUnloadHandler_001, TestSize.Level1)
{
    DistributedDeviceProfileServiceNew::GetInstance().unloadHandler_ = nullptr;
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().CreateUnloadHandler();
    EXPECT_EQ(DP_UNLOAD_HANDLER_NULLPTR, ret);
    
    ret = DistributedDeviceProfileServiceNew::GetInstance().DestroyUnloadHandler();
    EXPECT_EQ(DP_UNLOAD_HANDLER_NULLPTR, ret);
    
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
}

HWTEST_F(DpProfileServiceTest, UpdateAccessControlProfile_001, TestSize.Level1)
{
    AccessControlProfile accessControlProfile;
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().UpdateAccessControlProfile(accessControlProfile);
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
    int32_t ret =
            DistributedDeviceProfileServiceNew::GetInstance().GetAccessControlProfile(queryParams, accessControlProfiles);
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
    SyncOptions syncOptions;
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
}
}
