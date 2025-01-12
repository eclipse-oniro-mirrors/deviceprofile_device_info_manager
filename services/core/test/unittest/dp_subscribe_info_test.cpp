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
#include <sys/stat.h>
#include <sys/types.h>
#include <string>
#include <vector>
#include <iostream>

#include "profile_utils.h"
#include "trust_profile_manager.h"
#include "dp_subscribe_info.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_log.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_client.h"

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace testing::ext;
using namespace std;
namespace {
    const std::string TAG = "DPSubscribeInfoTest";
}
class DPSubscribeInfoTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    class SubscribeDPChangeListener : public ProfileChangeListenerStub {
    public:
        SubscribeDPChangeListener()
        {
            cout << "SubscribeDPChangeListener constructor" << endl;
        }
        ~SubscribeDPChangeListener()
        {
            cout << "SubscribeDPChangeListener destructor" << endl;
        }
        int32_t OnTrustDeviceProfileAdd(const TrustDeviceProfile& profile)
        {
            cout << "OnTrustDeviceProfileAdd" << profile.dump() <<endl;
            return 0;
        }
        int32_t OnTrustDeviceProfileDelete(const TrustDeviceProfile& profile)
        {
            cout << "OnTrustDeviceProfileDelete" << profile.dump() <<endl;
            return 0;
        }
        int32_t OnTrustDeviceProfileUpdate(const TrustDeviceProfile& oldProfile, const TrustDeviceProfile& newProfile)
        {
            cout << "OnTrustDeviceProfileUpdate: oldProfile " << oldProfile.dump() <<endl;
            cout << "OnTrustDeviceProfileUpdate: newProfile " << newProfile.dump() <<endl;
            return 0;
        }
        int32_t OnTrustDeviceProfileActive(const TrustDeviceProfile& profile)
        {
            cout << "OnTrustDeviceProfileActive" << profile.dump() <<endl;
            return 0;
        }
        int32_t OnTrustDeviceProfileInactive(const TrustDeviceProfile& profile)
        {
            cout << "OnTrustDeviceProfileInactive" << profile.dump() <<endl;
            return 0;
        }
        int32_t OnDeviceProfileAdd(const DeviceProfile& profile)
        {
            return 0;
        }
        int32_t OnDeviceProfileDelete(const DeviceProfile& profile)
        {
            return 0;
        }
        int32_t OnDeviceProfileUpdate(const DeviceProfile& oldProfile, const DeviceProfile& newProfile)
        {
            return 0;
        }
        int32_t OnServiceProfileAdd(const ServiceProfile& profile)
        {
            return 0;
        }
        int32_t OnServiceProfileDelete(const ServiceProfile& profile)
        {
            return 0;
        }
        int32_t OnServiceProfileUpdate(const ServiceProfile& oldProfile, const ServiceProfile& newProfile)
        {
            return 0;
        }
        int32_t OnCharacteristicProfileAdd(const CharacteristicProfile& profile)
        {
            return 0;
        }
        int32_t OnCharacteristicProfileDelete(const CharacteristicProfile& profile)
        {
            return 0;
        }
        int32_t OnCharacteristicProfileUpdate(const CharacteristicProfile& oldProfile,
            const CharacteristicProfile& newProfile)
        {
            return 0;
        }
    };
};

void DPSubscribeInfoTest::SetUpTestCase()
{
}

void DPSubscribeInfoTest::TearDownTestCase()
{
}

void DPSubscribeInfoTest::SetUp()
{
}

void DPSubscribeInfoTest::TearDown()
{
}

/*
 * @tc.name: Get_001
 * @tc.desc: Normal testCase of DPSubscribeInfoTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(DPSubscribeInfoTest, Get_001, TestSize.Level1)
{
    uint32_t saId = 4801;
    std::string subscribeKey = "trust_device_profile";
    std::unordered_set<ProfileChangeType> subscribeTypes = {ProfileChangeType::TRUST_DEVICE_PROFILE_ADD,
        ProfileChangeType::TRUST_DEVICE_PROFILE_UPDATE, ProfileChangeType::TRUST_DEVICE_PROFILE_DELETE};
    OHOS::sptr<IProfileChangeListener> subscribeDPChangeListener =
        sptr<IProfileChangeListener>(new DPSubscribeInfoTest::SubscribeDPChangeListener);
    SubscribeInfo subscribeInfo(saId, subscribeKey, subscribeTypes, subscribeDPChangeListener);
    uint32_t id = subscribeInfo.GetSaId();
    subscribeKey = subscribeInfo.GetSubscribeKey();
    subscribeTypes = subscribeInfo.GetProfileChangeTypes();
    subscribeInfo.GetListener();
    EXPECT_EQ(id, saId);
}

/*
 * @tc.name: Set_001
 * @tc.desc: Normal testCase of DPSubscribeInfoTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(DPSubscribeInfoTest, Set_001, TestSize.Level1)
{
    uint32_t saId = 4801;
    std::string subscribekey = "trust_device_profile";
    OHOS::sptr<IProfileChangeListener> subscribeDPChangeListener = nullptr;
    SubscribeInfo subscribeInfo;
    subscribeInfo.SetSaId(saId);
    subscribeInfo.SetSubscribeKey(subscribekey);
    subscribeInfo.SetListener(subscribeDPChangeListener);
    subscribeInfo.dump();
    EXPECT_EQ(subscribeInfo.saId_, saId);
}

/*
 * @tc.name: Set_002
 * @tc.desc: Normal testCase of DPSubscribeInfoTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(DPSubscribeInfoTest, Set_002, TestSize.Level1)
{
    SubscribeInfo subscribeInfo;
    std::string deviceId = "";
    std::string deviceAttribute = "";
    subscribeInfo.SetSubscribeKey(deviceId, deviceAttribute);
    std::string serviceName = "";
    std::string serviceAttribute = "";
    subscribeInfo.SetSubscribeKey(deviceId, serviceName, serviceAttribute);
    std::string characteristicKey = "";
    std::string characteristicAttribute = "";
    subscribeInfo.SetSubscribeKey(deviceId, serviceName, characteristicKey, characteristicAttribute);
    std::string subscribeKey = CHAR_PREFIX + SEPARATOR + deviceId + SEPARATOR + serviceName + SEPARATOR+
        characteristicKey + SEPARATOR + characteristicAttribute;
    EXPECT_EQ(subscribeInfo.subscribeKey_, subscribeKey);

    subscribeInfo.AddProfileChangeType(ProfileChangeType::TRUST_DEVICE_PROFILE_ADD);
}

/*
 * @tc.name: Marshalling_001
 * @tc.desc: Normal testCase of DPSubscribeInfoTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(DPSubscribeInfoTest, Marshalling_001, TestSize.Level1)
{
    SubscribeInfo subscribeInfo;
    SubscribeInfo subscribeInfo_2;
    SubscribeCompare cmp;
    cmp(subscribeInfo, subscribeInfo_2);
    SubscribeHash hash;
    hash(subscribeInfo_2);
    subscribeInfo.SetListener(nullptr);
    OHOS::MessageParcel parcel;
    TrustDeviceProfile profile;
    AccessControlProfile aclProfile;
    Accesser accesser;
    Accessee accessee;
    accesser.Marshalling(parcel);
    accesser.UnMarshalling(parcel);
    accessee.Marshalling(parcel);
    accessee.UnMarshalling(parcel);
    aclProfile.Marshalling(parcel);
    aclProfile.UnMarshalling(parcel);
    profile.Marshalling(parcel);
    profile.UnMarshalling(parcel);
    bool ret = subscribeInfo.Marshalling(parcel);
    EXPECT_EQ(ret, false);
    ret = subscribeInfo.UnMarshalling(parcel);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: Stub_001
 * @tc.desc: Normal testCase of DPSubscribeInfoTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(DPSubscribeInfoTest, Stub_001, TestSize.Level1)
{
    uint32_t saId = 4801;
    std::string subscribeKey = "trust_device_profile";
    std::unordered_set<ProfileChangeType> subscribeTypes = {ProfileChangeType::TRUST_DEVICE_PROFILE_ADD,
        ProfileChangeType::TRUST_DEVICE_PROFILE_UPDATE, ProfileChangeType::TRUST_DEVICE_PROFILE_DELETE};
    OHOS::sptr<IProfileChangeListener> subscribeDPChangeListener =
        sptr<IProfileChangeListener>(new DPSubscribeInfoTest::SubscribeDPChangeListener);
    SubscribeInfo subscribeInfo(saId, subscribeKey, subscribeTypes, subscribeDPChangeListener);
    OHOS::sptr<IProfileChangeListener> proxy = OHOS::iface_cast<IProfileChangeListener>(subscribeInfo.GetListener());
    TrustDeviceProfile oldTrustProfile;
    TrustDeviceProfile newTrustProfile;
    ASSERT_NE(proxy, nullptr);
    int32_t ret = proxy->OnTrustDeviceProfileAdd(oldTrustProfile);
    EXPECT_EQ(ret, DP_SUCCESS);
    ret = proxy->OnTrustDeviceProfileDelete(oldTrustProfile);
    EXPECT_EQ(ret, DP_SUCCESS);
    ret = proxy->OnTrustDeviceProfileUpdate(oldTrustProfile, newTrustProfile);
    EXPECT_EQ(ret, DP_SUCCESS);

    DeviceProfile oldDeviceProfile;
    DeviceProfile newDeviceProfile;
    ret = proxy->OnDeviceProfileAdd(oldDeviceProfile);
    EXPECT_EQ(ret, DP_SUCCESS);
    ret = proxy->OnDeviceProfileDelete(oldDeviceProfile);
    EXPECT_EQ(ret, DP_SUCCESS);
    ret = proxy->OnDeviceProfileUpdate(oldDeviceProfile, newDeviceProfile);
    EXPECT_EQ(ret, DP_SUCCESS);

    ServiceProfile oldServiceProfile;
    ServiceProfile newServiceProfile;
    ret = proxy->OnServiceProfileAdd(oldServiceProfile);
    EXPECT_EQ(ret, DP_SUCCESS);
    ret = proxy->OnServiceProfileDelete(oldServiceProfile);
    EXPECT_EQ(ret, DP_SUCCESS);
    ret = proxy->OnServiceProfileUpdate(oldServiceProfile, newServiceProfile);
    EXPECT_EQ(ret, DP_SUCCESS);

    CharacteristicProfile oldChaProfile;
    CharacteristicProfile newChaProfile;
    ret = proxy->OnCharacteristicProfileAdd(oldChaProfile);
    EXPECT_EQ(ret, DP_SUCCESS);
    ret = proxy->OnCharacteristicProfileDelete(oldChaProfile);
    EXPECT_EQ(ret, DP_SUCCESS);
    ret = proxy->OnCharacteristicProfileUpdate(oldChaProfile, newChaProfile);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/*
 * @tc.name: Stub_002
 * @tc.desc: Normal testCase of DPSubscribeInfoTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(DPSubscribeInfoTest, Stub_002, TestSize.Level1)
{
    uint32_t saId = 4801;
    std::string subscribeKey = "trust_device_profile";
    std::unordered_set<ProfileChangeType> subscribeTypes = {ProfileChangeType::TRUST_DEVICE_PROFILE_ACTIVE,
        ProfileChangeType::TRUST_DEVICE_PROFILE_INACTIVE};
    OHOS::sptr<IProfileChangeListener> subscribeDPChangeListener =
        sptr<IProfileChangeListener>(new DPSubscribeInfoTest::SubscribeDPChangeListener);
    SubscribeInfo subscribeInfo(saId, subscribeKey, subscribeTypes, subscribeDPChangeListener);
    OHOS::sptr<IProfileChangeListener> proxy = OHOS::iface_cast<IProfileChangeListener>(subscribeInfo.GetListener());
    TrustDeviceProfile profile;
    profile.SetPeerUserId(1001);
    profile.GetPeerUserId();
    ASSERT_NE(proxy, nullptr);
    int32_t ret = proxy->OnTrustDeviceProfileActive(profile);
    EXPECT_EQ(ret, DP_SUCCESS);
    ret = proxy->OnTrustDeviceProfileInactive(profile);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/*
 * @tc.name: IProfileChangeListener_001
 * @tc.desc: Normal testCase of DPSubscribeInfoTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(DPSubscribeInfoTest, IProfileChangeListener_001, TestSize.Level1)
{
    OHOS::sptr<IProfileChangeListener> subscribeDPChangeListener =
	    new(std::nothrow) DPSubscribeInfoTest::SubscribeDPChangeListener;
    TrustDeviceProfile profile;
    profile.SetPeerUserId(1001);
    int32_t ret = subscribeDPChangeListener->OnTrustDeviceProfileActive(profile);
    EXPECT_EQ(ret, DP_SUCCESS);
    ret = subscribeDPChangeListener->OnTrustDeviceProfileInactive(profile);
    EXPECT_EQ(ret, DP_SUCCESS);
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
