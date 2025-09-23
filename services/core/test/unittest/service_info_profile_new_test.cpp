/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
 
#include "dp_parcel.h"
#include "distributed_device_profile_constants.h"
#include "service_info_profile_new.h"
 
namespace OHOS {
namespace DistributedDeviceProfile {
using namespace testing::ext;
using namespace std;

class ServiceInfoProfileNewTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}

    ServiceInfoProfileNew CreateDefaultProfile()
    {
        ServiceInfoProfileNew profile;
        return profile;
    }
};

/**
 * @tc.name: MarshallingTest
 * @tc.desc: Verify Marshalling function
 */
HWTEST_F(ServiceInfoProfileNewTest, Marshalling_001, TestSize.Level1)
{
    auto profile = CreateDefaultProfile();
    OHOS::MessageParcel parcel;
    
    bool result = profile.Marshalling(parcel);
    EXPECT_TRUE(result);
    
    EXPECT_GE(parcel.GetDataSize(), 0);
}
 
/**
 * @tc.name: UnMarshallingTest
 * @tc.desc: Verify UnMarshalling function
 */
HWTEST_F(ServiceInfoProfileNewTest, UnMarshalling_001, TestSize.Level1)
{
    auto profile = CreateDefaultProfile();
    OHOS::MessageParcel parcel;
    ASSERT_TRUE(profile.Marshalling(parcel));
    
    ServiceInfoProfileNew newProfile;
    EXPECT_TRUE(newProfile.UnMarshalling(parcel));
    
    EXPECT_EQ(newProfile.GetServiceId(), 0);
    EXPECT_EQ(newProfile.GetServiceType(), "");
}
 
/**
 * @tc.name: DumpTest
 * @tc.desc: Verify dump function
 */
HWTEST_F(ServiceInfoProfileNewTest, Dump_001, TestSize.Level1)
{
    auto profile = CreateDefaultProfile();
    profile.SetServiceId(123456);
    profile.SetServiceType("typeA");
    string jsonStr = profile.dump();
    
    EXPECT_FALSE(jsonStr.empty());
 
    EXPECT_NE(jsonStr.find("123456"), string::npos);
    EXPECT_NE(jsonStr.find("typeA"), string::npos);
}
 
/**
 * @tc.name: MarshallingEmptyTest
 * @tc.desc: Verify Marshalling with empty profile
 */
HWTEST_F(ServiceInfoProfileNewTest, Marshalling_002, TestSize.Level1)
{
    ServiceInfoProfileNew emptyProfile;
    OHOS::MessageParcel parcel;
    
    bool result = emptyProfile.Marshalling(parcel);
    EXPECT_TRUE(result);
}
 
/**
 * @tc.name: UnMarshallingInvalidTest
 * @tc.desc: Verify UnMarshalling with invalid parcel
 */
HWTEST_F(ServiceInfoProfileNewTest, UnMarshalling_002, TestSize.Level1)
{
    OHOS::MessageParcel invalidParcel;
    ServiceInfoProfileNew profile;
    
    EXPECT_FALSE(profile.UnMarshalling(invalidParcel));
}
 
/**
 * @tc.name: DumpEmptyTest
 * @tc.desc: Verify dump with empty profile
 */
HWTEST_F(ServiceInfoProfileNewTest, Dump_002, TestSize.Level1)
{
    ServiceInfoProfileNew emptyProfile;
    string jsonStr = emptyProfile.dump();

    EXPECT_FALSE(jsonStr.empty());
    EXPECT_NE(jsonStr.find("\"\""), string::npos);
}

HWTEST_F(ServiceInfoProfileNewTest, SetAndGetRegServiceId_001, TestSize.Level1)
{
    ServiceInfoProfileNew newprofile;
    int32_t ServiceId = 123;
    newprofile.SetRegServiceId(ServiceId);
 
    int32_t ret = newprofile.GetRegServiceId();
    EXPECT_EQ(ServiceId, ret);
}
 
HWTEST_F(ServiceInfoProfileNewTest, SetAndGetDeviceId_001, TestSize.Level1)
{
    ServiceInfoProfileNew newprofile;
    std::string deviceId = "MK11";
    newprofile.SetDeviceId(deviceId);
 
    std::string ret = newprofile.GetDeviceId();
    EXPECT_EQ(deviceId, ret);
}

HWTEST_F(ServiceInfoProfileNewTest, SetAndGetUserId_001, TestSize.Level1)
{
    ServiceInfoProfileNew newprofile;
    int32_t userId = 10023;
    newprofile.SetUserId(userId);
 
    int32_t ret = newprofile.GetUserId();
    EXPECT_EQ(userId, ret);
}

HWTEST_F(ServiceInfoProfileNewTest, SetAndGetTokenId_001, TestSize.Level1)
{
    ServiceInfoProfileNew newprofile;
    int64_t tokenId = 11223344;
    newprofile.SetTokenId(tokenId);
 
    int64_t ret = newprofile.GetTokenId();
    EXPECT_EQ(tokenId, ret);
}

HWTEST_F(ServiceInfoProfileNewTest, SetAndGetSerPubState_001, TestSize.Level1)
{
    ServiceInfoProfileNew newprofile;
    int8_t serPubState = 20;
    newprofile.SetSerPubState(serPubState);
 
    int8_t ret = newprofile.GetSerPubState();
    EXPECT_EQ(serPubState, ret);
}

HWTEST_F(ServiceInfoProfileNewTest, SetAndGetServiceId_001, TestSize.Level1)
{
    ServiceInfoProfileNew newprofile;
    int64_t deviceId = 10203;
    newprofile.SetServiceId(deviceId);
    
    int64_t ret = newprofile.GetServiceId();
    EXPECT_EQ(deviceId, ret);
}

HWTEST_F(ServiceInfoProfileNewTest, SetAndGetServiceType_001, TestSize.Level1)
{
    ServiceInfoProfileNew newprofile;
    std::string ServiceType = "On";
    newprofile.SetServiceType(ServiceType);
 
    std::string ret = newprofile.GetServiceType();
    EXPECT_EQ(ServiceType, ret);
}

HWTEST_F(ServiceInfoProfileNewTest, SetAndGetServiceName_001, TestSize.Level1)
{
    ServiceInfoProfileNew newprofile;
    std::string ServiceName = "ohos";
    newprofile.SetServiceName(ServiceName);
 
    std::string ret = newprofile.GetServiceName();
    EXPECT_EQ(ServiceName, ret);
}

HWTEST_F(ServiceInfoProfileNewTest, SetAndGetServiceDisplayName_001, TestSize.Level1)
{
    ServiceInfoProfileNew newprofile;
    std::string serviceDisplayName = "ohosname";
    newprofile.SetServiceDisplayName(serviceDisplayName);
 
    std::string ret = newprofile.GetServiceDisplayName();
    EXPECT_EQ(serviceDisplayName, ret);
}
} // namespace DistributedDeviceProfile
} // namespace OHOSUser());