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

#define private   public
#define protected public
#include <string>
#include <vector>
#include "gtest/gtest.h"
#include "refbase.h"
#include "rdb_errno.h"
#include "profile_utils.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_enums.h"
#undef private
#undef protected

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace std;

class ProfileUtilsTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ProfileUtilsTest::SetUpTestCase(void) {
}

void ProfileUtilsTest::TearDownTestCase(void) {
}

void ProfileUtilsTest::SetUp() {
}

void ProfileUtilsTest::TearDown() {
}

/**
 * @tc.name: GetAnonyString001
 * @tc.desc: GetAnonyString failed, length < 3.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, GetAnonyString001, TestSize.Level1)
{
    string len2 = "ab";
    string res = ProfileUtils::GetAnonyString(len2);
    EXPECT_EQ("******", res);
}

/**
 * @tc.name: GetAnonyString002
 * @tc.desc: GetAnonyString succeed, 3 <= length <= 20.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, GetAnonyString002, TestSize.Level1)
{
    string len5 = "abcde";
    string res = ProfileUtils::GetAnonyString(len5);
    EXPECT_EQ("a******e", res);
}

/**
 * @tc.name: GetAnonyString003
 * @tc.desc: GetAnonyString succeed, length > 20.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, GetAnonyString003, TestSize.Level1)
{
    string len22 = "abcdefghijklmnopqrstuv";
    string res = ProfileUtils::GetAnonyString(len22);
    EXPECT_EQ("abcd******stuv", res);
}

/**
 * @tc.name: GetOnlineDevices001
 * @tc.desc: GetOnlineDevices succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, GetOnlineDevices001, TestSize.Level1)
{
    vector<string> res = ProfileUtils::GetOnlineDevices();
    EXPECT_EQ(0, res.size());
}

/**
 * @tc.name: FilterOnlineDevices001
 * @tc.desc: FilterOnlineDevices failed, deviceList.size() == 0.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, FilterOnlineDevices001, TestSize.Level1)
{
    vector<string> deviceList;
    vector<string> res = ProfileUtils::FilterOnlineDevices(deviceList);
    EXPECT_EQ(0, res.size());
}

/**
 * @tc.name: FilterOnlineDevices002
 * @tc.desc: FilterOnlineDevices failed, deviceList.size() > 1000.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, FilterOnlineDevices002, TestSize.Level1)
{
    vector<string> deviceList;
    for (int32_t i = 0; i < 1005; i++) {
    deviceList.emplace_back("deviceId");
    }
    vector<string> res = ProfileUtils::FilterOnlineDevices(deviceList);
    EXPECT_EQ(0, res.size());
}

/**
 * @tc.name: GetProfileType001
 * @tc.desc: GetProfileType succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, GetProfileType001, TestSize.Level1)
{
    string minkey = "";
    ProfileType res = ProfileUtils::GetProfileType(minkey);
    EXPECT_EQ(ProfileType::PROFILE_TYPE_MIN, res);

    string maxKey = "";
    for (int32_t i = 0; i < 5000; i++) {
        maxKey += 'a';
    }
    res = ProfileUtils::GetProfileType(maxKey);
    EXPECT_EQ(ProfileType::PROFILE_TYPE_MIN, res);
    
    string devKey = "dev111";
    res = ProfileUtils::GetProfileType(devKey);
    EXPECT_EQ(ProfileType::DEVICE_PROFILE, res);
    
    string serKet = "svr111";
    res = ProfileUtils::GetProfileType(serKet);
    EXPECT_EQ(ProfileType::SERVICE_PROFILE, res);
    
    string charKey = "char111";
    res = ProfileUtils::GetProfileType(charKey);
    EXPECT_EQ(ProfileType::CHAR_PROFILE, res);
    
    string lastKey = "other";
    res = ProfileUtils::GetProfileType(lastKey);
    EXPECT_EQ(ProfileType::PROFILE_TYPE_MIN, res);
}

/**
 * @tc.name: StartsWith001
 * @tc.desc: StartsWith succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, StartsWith001, TestSize.Level1)
{
    string str = "abcdefg";
    string prefix = "abc";
    bool res = ProfileUtils::StartsWith(str, prefix);
    EXPECT_EQ(true, res);
}

/**
 * @tc.name: IsKeyValid001
 * @tc.desc: IsKeyValid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, IsKeyValid001, TestSize.Level1)
{
    string key = "abc";
    bool res = ProfileUtils::IsKeyValid(key);
    EXPECT_EQ(true, res);
    
    key = "";
    res = ProfileUtils::IsKeyValid(key);
    EXPECT_EQ(false, res);

    key = "";
    for (int32_t i = 0; i < 5000; i++) {
        key += 'a';
    }
    res = ProfileUtils::IsKeyValid(key);
    EXPECT_EQ(false, res);

    key = "abc#";
    res = ProfileUtils::IsKeyValid(key);
    EXPECT_EQ(false, res);
}

/**
 * @tc.name: GenerateDeviceProfileKey001
 * @tc.desc: GenerateDeviceProfileKey.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, GenerateDeviceProfileKey001, TestSize.Level1)
{
    string deviceId = "111";
    string res = ProfileUtils::GenerateDeviceProfileKey(deviceId);
    EXPECT_EQ("dev#111", res);
}

/**
 * @tc.name: GenerateServiceProfileKey001
 * @tc.desc: GenerateServiceProfileKey.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, GenerateServiceProfileKey001, TestSize.Level1)
{
    string deviceId = "111";
    string serviceName = "222";
    string res = ProfileUtils::GenerateServiceProfileKey(deviceId, serviceName);
    EXPECT_EQ("svr#111#222", res);
}

/**
 * @tc.name: GenerateCharProfileKey001
 * @tc.desc: GenerateCharProfileKey.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, GenerateCharProfileKey001, TestSize.Level1)
{
    string deviceId = "111";
    string serviceName = "222";
    string charKey = "333";
    string res = ProfileUtils::GenerateCharProfileKey(deviceId, serviceName, charKey);
    EXPECT_EQ("char#111#222#333", res);
}

/**
 * @tc.name: TrustDeviceProfileTranslateEntries001
 * @tc.desc: TrustDeviceProfileToEntries and EntriesToTrustDeviceProfile.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, TrustDeviceProfileTranslateEntries001, TestSize.Level1)
{
    TrustDeviceProfile profile;
    profile.SetDeviceId("deviceId");
    profile.SetDeviceIdHash("deviceIdHash");
    profile.SetDeviceIdType(1);
    profile.SetStatus(1);
    
    ValuesBucket values;
    ValueObject valueObject;
    string strValue = "";
    int32_t res1 = ProfileUtils::TrustDeviceProfileToEntries(profile, values);
    EXPECT_EQ(DP_SUCCESS, res1);
    values.GetObject(DEVICE_ID, valueObject);
    valueObject.GetString(strValue);
    EXPECT_EQ("deviceId", strValue);

    TrustDeviceProfile outProfile;
    int32_t res2 = ProfileUtils::EntriesToTrustDeviceProfile(values, outProfile);
    EXPECT_EQ(DP_SUCCESS, res2);
    EXPECT_EQ("deviceId", outProfile.GetDeviceId());
}

/**
 * @tc.name: AccessControlProfileTranslateEntries001
 * @tc.desc: AccessControlProfileToEntries and EntriesToAccessControlProfile.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, AccessControlProfileTranslateEntries001, TestSize.Level1)
{
    Accesser accesser;
    accesser.SetAccesserDeviceId("acer1");
    accesser.SetAccesserUserId(11);
    accesser.SetAccesserAccountId("a1");
    accesser.SetAccesserTokenId(111);
    accesser.SetAccesserBundleName("b1");
    accesser.SetAccesserHapSignature("h1");
    accesser.SetAccesserBindLevel(1);
    
    Accessee accessee;
    accessee.SetAccesseeDeviceId("acee1");
    accessee.SetAccesseeUserId(22);
    accessee.SetAccesseeAccountId("a1");
    accessee.SetAccesseeTokenId(222);
    accessee.SetAccesseeBundleName("bb1");
    accessee.SetAccesseeHapSignature("h1");
    accessee.SetAccesseeBindLevel(1);

    AccessControlProfile profile;
    profile.SetTrustDeviceId("123456");
    profile.SetSessionKey("key1");
    profile.SetBindType(1);
    profile.SetAuthenticationType(1);
    profile.SetDeviceIdType(1);
    profile.SetDeviceIdHash("abcd");
    profile.SetStatus(0);
    profile.SetValidPeriod(1);
    profile.SetLastAuthTime(5);
    profile.SetBindLevel(0);
    
    profile.SetAccesser(accesser);
    profile.SetAccessee(accessee);

    ValuesBucket values;
    ValueObject valueObject;
    string strValue = "";
    int32_t res1 = ProfileUtils::AccessControlProfileToEntries(profile, values);
    EXPECT_EQ(DP_SUCCESS, res1);
    values.GetObject(TRUST_DEVICE_ID, valueObject);
    valueObject.GetString(strValue);
    EXPECT_EQ("123456", strValue);
    
    AccessControlProfile outProfile;
    int32_t res2 = ProfileUtils::EntriesToAccessControlProfile(values, outProfile);
    EXPECT_EQ(DP_SUCCESS, res2);
    EXPECT_EQ("123456", outProfile.GetTrustDeviceId());
}

/**
 * @tc.name: AccesserTranslateEntries001
 * @tc.desc: AccesserToEntries and EntriesToAccesser.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, AccesserTranslateEntries001, TestSize.Level1)
{
    Accesser accesser;
    accesser.SetAccesserDeviceId("acer1");
    accesser.SetAccesserUserId(11);
    accesser.SetAccesserAccountId("a1");
    accesser.SetAccesserTokenId(111);
    accesser.SetAccesserBundleName("b1");
    accesser.SetAccesserHapSignature("h1");
    accesser.SetAccesserBindLevel(1);
    
    Accessee accessee;
    accessee.SetAccesseeDeviceId("acee1");
    accessee.SetAccesseeUserId(22);
    accessee.SetAccesseeAccountId("a1");
    accessee.SetAccesseeTokenId(222);
    accessee.SetAccesseeBundleName("bb1");
    accessee.SetAccesseeHapSignature("h1");
    accessee.SetAccesseeBindLevel(1);

    AccessControlProfile profile;
    profile.SetTrustDeviceId("123456");
    profile.SetSessionKey("key1");
    profile.SetBindType(1);
    profile.SetAuthenticationType(1);
    profile.SetDeviceIdType(1);
    profile.SetDeviceIdHash("abcd");
    profile.SetStatus(0);
    profile.SetValidPeriod(1);
    profile.SetLastAuthTime(5);
    profile.SetBindLevel(0);
    
    profile.SetAccesser(accesser);
    profile.SetAccessee(accessee);
    
    ValuesBucket values;
    ValueObject valueObject;
    string strValue = "";
    int32_t res1 = ProfileUtils::AccesserToEntries(profile, values);
    EXPECT_EQ(DP_SUCCESS, res1);
    values.GetObject(ACCESSER_DEVICE_ID, valueObject);
    valueObject.GetString(strValue);
    EXPECT_EQ("acer1", strValue);

    Accesser outAccesser;
    int32_t res2 = ProfileUtils::EntriesToAccesser(values, outAccesser);
    EXPECT_EQ(DP_SUCCESS, res2);
    EXPECT_EQ("acer1", outAccesser.GetAccesserDeviceId());
}

/**
 * @tc.name: AccesseeTranslateEntries001
 * @tc.desc: AccesseeToEntries and EntriesToAccessee.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, AccesseeTranslateEntries001, TestSize.Level1)
{
    Accesser accesser;
    accesser.SetAccesserDeviceId("acer1");
    accesser.SetAccesserUserId(11);
    accesser.SetAccesserAccountId("a1");
    accesser.SetAccesserTokenId(111);
    accesser.SetAccesserBundleName("b1");
    accesser.SetAccesserHapSignature("h1");
    accesser.SetAccesserBindLevel(1);
    
    Accessee accessee;
    accessee.SetAccesseeDeviceId("acee1");
    accessee.SetAccesseeUserId(22);
    accessee.SetAccesseeAccountId("a1");
    accessee.SetAccesseeTokenId(222);
    accessee.SetAccesseeBundleName("bb1");
    accessee.SetAccesseeHapSignature("h1");
    accessee.SetAccesseeBindLevel(1);

    AccessControlProfile profile;
    profile.SetTrustDeviceId("123456");
    profile.SetSessionKey("key1");
    profile.SetBindType(1);
    profile.SetAuthenticationType(1);
    profile.SetDeviceIdType(1);
    profile.SetDeviceIdHash("abcd");
    profile.SetStatus(0);
    profile.SetValidPeriod(1);
    profile.SetLastAuthTime(5);
    profile.SetBindLevel(0);

    profile.SetAccesser(accesser);
    profile.SetAccessee(accessee);
    
    ValuesBucket values;
    ValueObject valueObject;
    string strValue = "";
    int32_t res1 = ProfileUtils::AccesseeToEntries(profile, values);
    EXPECT_EQ(DP_SUCCESS, res1);
    values.GetObject(ACCESSEE_DEVICE_ID, valueObject);
    valueObject.GetString(strValue);
    EXPECT_EQ("acee1", strValue);
    
    Accessee outAccessee;
    int32_t res2 = ProfileUtils::EntriesToAccessee(values, outAccessee);
    EXPECT_EQ(DP_SUCCESS, res2);
    EXPECT_EQ("acee1", outAccessee.GetAccesseeDeviceId());
}

/**
 * @tc.name: DeviceProfileTranslateEntries001
 * @tc.desc: DeviceProfileToEntries and EntriesToDeviceProfile.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, DeviceProfileTranslateEntries001, TestSize.Level1)
{
    DeviceProfile deviceProfile;
    deviceProfile.SetDeviceId("anything");
    deviceProfile.SetOsApiLevel(1);
    deviceProfile.SetOsVersion("anything");
    deviceProfile.SetOsType(1);
    
    map<string, string> entries;
    int32_t res1 = ProfileUtils::DeviceProfileToEntries(deviceProfile, entries);
    EXPECT_EQ(DP_SUCCESS, res1);
    
    DeviceProfile outDeviceProfile;
    int32_t res2 = ProfileUtils::EntriesToDeviceProfile(entries, outDeviceProfile);
    EXPECT_EQ(DP_SUCCESS, res2);
}

/**
 * @tc.name: ServiceProfileTranslateEntries001
 * @tc.desc: ServiceProfileToEntries and EntriesToServiceProfile.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, ServiceProfileTranslateEntries001, TestSize.Level1)
{
    ServiceProfile serviceProfile;
    serviceProfile.SetDeviceId("deviceId");
    serviceProfile.SetServiceName("serviceName");
    serviceProfile.SetServiceType("serviceType");
    
    map<string, string> entries;
    int32_t res1 = ProfileUtils::ServiceProfileToEntries(serviceProfile, entries);
    EXPECT_EQ(DP_SUCCESS, res1);
    
    ServiceProfile outServiceProfile;
    int32_t res2 = ProfileUtils::EntriesToServiceProfile(entries, outServiceProfile);
    EXPECT_EQ(DP_SUCCESS, res2);
    EXPECT_EQ("deviceId", outServiceProfile.GetDeviceId());
}

/**
 * @tc.name: CharacteristicProfileTranslateEntries001
 * @tc.desc: CharacteristicProfileToEntries and EntriesToCharProfile.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, CharacteristicProfileTranslateEntries001, TestSize.Level1)
{
    CharacteristicProfile charProfile;
    charProfile.SetDeviceId("deviceId");
    charProfile.SetServiceName("serviceName");
    charProfile.SetCharacteristicKey("characteristicKey");
    charProfile.SetCharacteristicValue("characteristicValue");
    
    map<string, string> entries;
    int32_t res1 = ProfileUtils::CharacteristicProfileToEntries(charProfile, entries);
    EXPECT_EQ(DP_SUCCESS, res1);
    
    CharacteristicProfile outCharProfile;
    int32_t res2 = ProfileUtils::EntriesToCharProfile(entries, outCharProfile);
    EXPECT_EQ(DP_SUCCESS, res2);
    EXPECT_EQ("deviceId", outCharProfile.GetDeviceId());
}

/**
 * @tc.name: EntriesToDeviceProfile001
 * @tc.desc: EntriesToDeviceProfile failed, Entries size is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, EntriesToDeviceProfile001, TestSize.Level1)
{
    map<string, string> entries;
    DeviceProfile deviceProfile;
    int32_t res = ProfileUtils::EntriesToDeviceProfile(entries, deviceProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, res);
}

/**
 * @tc.name: EntriesToServiceProfile001
 * @tc.desc: EntriesToServiceProfile failed, Entries size is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, EntriesToServiceProfile001, TestSize.Level1)
{
    map<string, string> entries;
    ServiceProfile serviceProfile;
    int32_t res = ProfileUtils::EntriesToServiceProfile(entries, serviceProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, res);
}

/**
 * @tc.name: EntriesToCharProfile001
 * @tc.desc: EntriesToCharProfile failed, Entries size is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, EntriesToCharProfile001, TestSize.Level1)
{
    map<string, string> entries;
    CharacteristicProfile charProfile;
    int32_t res = ProfileUtils::EntriesToCharProfile(entries, charProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, res);
}

/**
 * @tc.name: SplitString001
 * @tc.desc: SplitString failed, str == "".
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, SplitString001, TestSize.Level1)
{
    string str = "";
    string splits = "#";
    vector<string> res;
    int32_t ret = ProfileUtils::SplitString(str, splits, res);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
}

/**
 * @tc.name: SplitString002
 * @tc.desc: SplitString succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, SplitString002, TestSize.Level1)
{
    string str = "a#b#c";
    string splits = "#";
    vector<string> res;
    int32_t ret = ProfileUtils::SplitString(str, splits, res);
    EXPECT_EQ(DP_SUCCESS, ret);
    EXPECT_EQ(3, res.size());
}

/**
 * @tc.name: GenerateDBKey001
 * @tc.desc: GenerateDBKey succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, GenerateDBKey001, TestSize.Level1)
{
    string profileKey = "profileKey";
    string profileProperty = "profileProperty";
    string res = ProfileUtils::GenerateDBKey(profileKey, profileProperty);
    EXPECT_EQ("profileKey#profileProperty", res);
}

/**
 * @tc.name: GetProfileKey001
 * @tc.desc: GetProfileKey succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, GetProfileKey001, TestSize.Level1)
{
    string dbKey = "profileKey#profileProperty";
    string res = ProfileUtils::GetProfileKey(dbKey);
    EXPECT_EQ("profileKey", res);
}

/**
 * @tc.name: GetProfileKey002
 * @tc.desc: GetProfileKey failed , dbKey.length() == 0.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, GetProfileKey002, TestSize.Level1)
{
    string dbKey = "";
    string res = ProfileUtils::GetProfileKey(dbKey);
    EXPECT_EQ(0, res.length());
}

/**
 * @tc.name: GetProfileKey003
 * @tc.desc: GetProfileKey failed , dbKey.length() > 4096.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, GetProfileKey003, TestSize.Level1)
{
    string dbKey = "";
    for (int32_t i = 0; i < 5000; i++) {
        dbKey += 'a';
    }
    string res = ProfileUtils::GetProfileKey(dbKey);
    EXPECT_EQ(0, res.length());
}

/**
 * @tc.name: GetProfileProperty001
 * @tc.desc: GetProfileProperty succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, GetProfileProperty001, TestSize.Level1)
{
    string dbKey = "profileKey#profileProperty";
    string res = ProfileUtils::GetProfileProperty(dbKey);
    EXPECT_EQ("profileProperty", res);
}

/**
 * @tc.name: GetProfileProperty002
 * @tc.desc: GetProfileProperty failed , dbKey.length() == 0.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, GetProfileProperty002, TestSize.Level1)
{
    string dbKey = "";
    string res = ProfileUtils::GetProfileProperty(dbKey);
    EXPECT_EQ(0, res.length());
}

/**
 * @tc.name: GetProfileProperty003
 * @tc.desc: GetProfileProperty failed , dbKey.length() > 4096.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, GetProfileProperty003, TestSize.Level1)
{
    string dbKey = "";
    for (int32_t i = 0; i < 5000; i++) {
        dbKey += 'a';
    }
    string res = ProfileUtils::GetProfileProperty(dbKey);
    EXPECT_EQ(0, res.length());
}

/**
 * @tc.name: GetDeviceIdByDBKey001
 * @tc.desc: GetDeviceIdByDBKey succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, GetDeviceIdByDBKey001, TestSize.Level1)
{
    string dbKey = "dev#111";
    string res = ProfileUtils::GetDeviceIdByDBKey(dbKey);
    EXPECT_EQ("111", res);
}

/**
 * @tc.name: GetDeviceIdByDBKey002
 * @tc.desc: GetDeviceIdByDBKey failed , dbKey.length() == 0.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, GetDeviceIdByDBKey002, TestSize.Level1)
{
    string dbKey = "";
    string res = ProfileUtils::GetDeviceIdByDBKey(dbKey);
    EXPECT_EQ(0, res.length());
}

/**
 * @tc.name: GetDeviceIdByDBKey003
 * @tc.desc: GetDeviceIdByDBKey failed , res.size() < 1.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, GetDeviceIdByDBKey003, TestSize.Level1)
{
    string dbKey = "#";
    string res = ProfileUtils::GetDeviceIdByDBKey(dbKey);
    EXPECT_EQ(0, res.length());
}

/**
 * @tc.name: GetDeviceIdByDBKey004
 * @tc.desc: GetDeviceIdByDBKey failed , dbKey.length() > 4096.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, GetDeviceIdByDBKey004, TestSize.Level1)
{
    string dbKey = "";
    for (int32_t i = 0; i < 5000; i++) {
        dbKey += 'a';
    }
    string res = ProfileUtils::GetDeviceIdByDBKey(dbKey);
    EXPECT_EQ(0, res.length());
}

/**
 * @tc.name: GetServiceNameByDBKey001
 * @tc.desc: GetServiceNameByDBKey succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, GetServiceNameByDBKey001, TestSize.Level1)
{
    string dbKey = "ser#111#222";
    string res = ProfileUtils::GetServiceNameByDBKey(dbKey);
    EXPECT_EQ("222", res);
}

/**
 * @tc.name: GetServiceNameByDBKey002
 * @tc.desc: GetServiceNameByDBKey failed , dbKey.length() == 0.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, GetServiceNameByDBKey002, TestSize.Level1)
{
    string dbKey = "";
    string res = ProfileUtils::GetServiceNameByDBKey(dbKey);
    EXPECT_EQ(0, res.length());
}

/**
 * @tc.name: GetServiceNameByDBKey003
 * @tc.desc: GetServiceNameByDBKey failed , dbKey.length() > 4096.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, GetServiceNameByDBKey003, TestSize.Level1)
{
    string dbKey = "";
        for (int32_t i = 0; i < 5000; i++) {
    dbKey += 'a';
    }
    string res = ProfileUtils::GetServiceNameByDBKey(dbKey);
    EXPECT_EQ(0, res.length());
}

/**
 * @tc.name: GetServiceNameByDBKey004
 * @tc.desc: GetDeviceIdByDBKey failed , res.size() < 2.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, GetServiceNameByDBKey004, TestSize.Level1)
{
    string dbKey = "ser";
    string res = ProfileUtils::GetServiceNameByDBKey(dbKey);
    EXPECT_EQ(0, res.length());
}

/**
 * @tc.name: GetCharKeyByDBKey001
 * @tc.desc: GetCharKeyByDBKey succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, GetCharKeyByDBKey001, TestSize.Level1)
{
    string dbKey = "char#111#222#333";
    string res = ProfileUtils::GetCharKeyByDBKey(dbKey);
    EXPECT_EQ("333", res);
}

/**
 * @tc.name: GetCharKeyByDBKey002
 * @tc.desc: GetCharKeyByDBKey failed , dbKey.length() == 0.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, GetCharKeyByDBKey002, TestSize.Level1)
{
    string dbKey = "";
    string res = ProfileUtils::GetCharKeyByDBKey(dbKey);
    EXPECT_EQ(0, res.length());
}

/**
 * @tc.name: GetCharKeyByDBKey003
 * @tc.desc: GetCharKeyByDBKey failed , res.size() < 3.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, GetCharKeyByDBKey003, TestSize.Level1)
{
    string dbKey = "char#";
    string res = ProfileUtils::GetCharKeyByDBKey(dbKey);
    EXPECT_EQ(0, res.length());
}

/**
 * @tc.name: GetCharKeyByDBKey004
 * @tc.desc: GetCharKeyByDBKey failed , dbKey.length() > 4096.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, GetCharKeyByDBKey004, TestSize.Level1)
{
    string dbKey = "";
        for (int32_t i = 0; i < 5000; i++) {
    dbKey += 'a';
    }
    string res = ProfileUtils::GetCharKeyByDBKey(dbKey);
    EXPECT_EQ(0, res.length());
}

/**
 * @tc.name: toString001
 * @tc.desc: toString succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, toString001, TestSize.Level1)
{
    u16string str16 = u"abc";
    string res = ProfileUtils::toString(str16);
    EXPECT_EQ("abc", res);
}

/**
 * @tc.name: IsPropertyValid001
 * @tc.desc: IsPropertyValid failed, propertyMap.size() == 0.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, IsPropertyValid001, TestSize.Level1)
{
    map<string, string> propertyMap;
    string property = "property";
    int32_t maxValue = 1;
    bool res1 = ProfileUtils::IsPropertyValid(propertyMap, property, maxValue);
    EXPECT_EQ(false, res1);
    
    int32_t minValue = 0;
    bool res2 = ProfileUtils::IsPropertyValid(propertyMap, property, minValue, maxValue);
    EXPECT_EQ(false, res2);
}

/**
 * @tc.name: IsPropertyValid002
 * @tc.desc: IsPropertyValid overload 1.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, IsPropertyValid002, TestSize.Level1)
{
    map<string, string> propertyMap;
    string property = "property";
    string value = "value";
    propertyMap[property] = value;
    int32_t maxValue = 10;
    bool res1 = ProfileUtils::IsPropertyValid(propertyMap, property, maxValue);
    EXPECT_EQ(true, res1);
    
    maxValue = 0;
    bool res2 = ProfileUtils::IsPropertyValid(propertyMap, property, maxValue);
    EXPECT_EQ(false, res2);
    
    value = "";
    propertyMap[property] = value;
    bool res3 = ProfileUtils::IsPropertyValid(propertyMap, property, maxValue);
    EXPECT_EQ(false, res3);
    
    propertyMap.erase(property);
    bool res4 = ProfileUtils::IsPropertyValid(propertyMap, property, maxValue);
    EXPECT_EQ(false, res4);
}

/**
 * @tc.name: IsPropertyValid003
 * @tc.desc: IsPropertyValid overload 2.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, IsPropertyValid003, TestSize.Level1)
{
    map<string, string> propertyMap;
    string property = "property";
    string value = "5";
    propertyMap[property] = value;
    int32_t maxValue = 10;
    int32_t minValue = 0;
    bool res1 = ProfileUtils::IsPropertyValid(propertyMap, property, minValue, maxValue);
    EXPECT_EQ(true, res1);
    
    maxValue = 0;
    bool res2 = ProfileUtils::IsPropertyValid(propertyMap, property, minValue, maxValue);
    EXPECT_EQ(false, res2);
    
    value = "0";
    propertyMap[property] = value;
    bool res3 = ProfileUtils::IsPropertyValid(propertyMap, property, minValue, maxValue);
    EXPECT_EQ(false, res3);
    
    propertyMap.erase(property);
    bool res4 = ProfileUtils::IsPropertyValid(propertyMap, property, minValue, maxValue);
    EXPECT_EQ(false, res4);
}

/**
 * @tc.name: GetIntValue001
 * @tc.desc: GetIntValue failed, ValuesBucket is empty.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, GetIntValue001, TestSize.Level1)
{
    ValuesBucket values;
    string property = "property";
    int32_t value = 0;
    bool res = ProfileUtils::GetIntValue(values, property, value);
    EXPECT_EQ(false, res);
}

/**
 * @tc.name: GetIntValue002
 * @tc.desc: GetIntValue all.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, GetIntValue002, TestSize.Level1)
{
    ValuesBucket values;
    int32_t intValue = 1;
    string property = "property";
    values.PutInt(property, intValue);
    int32_t outValue = 0;
    bool res1 = ProfileUtils::GetIntValue(values, property, outValue);
    EXPECT_EQ(true, res1);
    
    string strValue = "strValue";
    values.Clear();
    values.PutString(property, strValue);
    bool res2 = ProfileUtils::GetIntValue(values, property, outValue);
    EXPECT_EQ(false, res2);
    
    values.Clear();
    bool res3 = ProfileUtils::GetIntValue(values, property, outValue);
    EXPECT_EQ(false, res3);
}

/**
 * @tc.name: GetStringValue001
 * @tc.desc: GetStringValue failed, ValuesBucket is empty.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, GetStringValue001, TestSize.Level1)
{
    ValuesBucket values;
    string property = "property";
    string value = "";
    bool res = ProfileUtils::GetStringValue(values, property, value);
    EXPECT_EQ(false, res);
}

/**
 * @tc.name: GetStringValue002
 * @tc.desc: GetStringValue all.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, GetStringValue002, TestSize.Level1)
{
    ValuesBucket values;
    string strValue = "strValue";
    string property = "property";
    values.PutString(property, strValue);
    string outValue = "";
    bool res1 = ProfileUtils::GetStringValue(values, property, outValue);
    EXPECT_EQ(true, res1);
    
    values.Clear();
    values.PutNull(property);
    bool res2 = ProfileUtils::GetStringValue(values, property, outValue);
    EXPECT_EQ(false, res2);
    
    values.Clear();
    bool res3 = ProfileUtils::GetStringValue(values, property, outValue);
    EXPECT_EQ(false, res3);
}

/**
 * @tc.name: GetLongValue001
 * @tc.desc: GetLongValue failed, ValuesBucket is empty.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, GetLongValue001, TestSize.Level1)
{
    ValuesBucket values;
    string property = "property";
    int64_t value = 0;
    bool res = ProfileUtils::GetLongValue(values, property, value);
    EXPECT_EQ(false, res);
}

/**
 * @tc.name: GetLongValue002
 * @tc.desc: GetLongValue all.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, GetLongValue002, TestSize.Level1)
{
    ValuesBucket values;
    int64_t longValue = 1;
    string strValue = "strValue";
    string property = "property";
    values.PutLong(property, longValue);
    int64_t outValue = 0;
    bool res1 = ProfileUtils::GetLongValue(values, property, outValue);
    EXPECT_EQ(true, res1);
    
    values.Clear();
    values.PutString(property, strValue);
    bool res2 = ProfileUtils::GetLongValue(values, property, outValue);
    EXPECT_EQ(false, res2);
    
    values.Clear();
    bool res3 = ProfileUtils::GetLongValue(values, property, outValue);
    EXPECT_EQ(false, res3);
}

/**
 * @tc.name: EntriesToTrustDeviceProfile001
 * @tc.desc: EntriesToTrustDeviceProfile all.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, EntriesToTrustDeviceProfile001, TestSize.Level1)
{
    ValuesBucket values;
    TrustDeviceProfile profile;
    int32_t intValue = 1;
    string strValue = "strValue";
    
    values.PutString(DEVICE_ID, strValue);
    values.PutString(DEVICE_ID_HASH, strValue);
    values.PutInt(DEVICE_TYPE_ID, intValue);
    values.PutInt(STATUS, intValue);
    int32_t ret1 = ProfileUtils::EntriesToTrustDeviceProfile(values, profile);
    EXPECT_EQ(DP_SUCCESS, ret1);

    values.Delete(STATUS);
    values.PutNull(STATUS);
    ProfileUtils::EntriesToTrustDeviceProfile(values, profile);
    values.Delete(STATUS);
    ProfileUtils::EntriesToTrustDeviceProfile(values, profile);

    values.Delete(DEVICE_TYPE_ID);
    values.PutNull(DEVICE_TYPE_ID);
    ProfileUtils::EntriesToTrustDeviceProfile(values, profile);
    values.Delete(DEVICE_TYPE_ID);
    ProfileUtils::EntriesToTrustDeviceProfile(values, profile);

    values.Delete(DEVICE_ID_HASH);
    values.PutNull(DEVICE_ID_HASH);
    ProfileUtils::EntriesToTrustDeviceProfile(values, profile);
    values.Delete(DEVICE_ID_HASH);
    ProfileUtils::EntriesToTrustDeviceProfile(values, profile);

    values.Delete(DEVICE_ID);
    values.PutNull(DEVICE_ID);
    ProfileUtils::EntriesToTrustDeviceProfile(values, profile);
    values.Delete(DEVICE_ID);
    ProfileUtils::EntriesToTrustDeviceProfile(values, profile);
}

/**
 * @tc.name: EntriesToAccessControlProfile001
 * @tc.desc: EntriesToAccessControlProfile all failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, EntriesToAccessControlProfile001, TestSize.Level1)
{
    ValuesBucket values;
    AccessControlProfile profile;
    ProfileUtils::EntriesToAccessControlProfile(values, profile);
    string strValue = "";
    bool ret = ProfileUtils::GetStringValue(values, SESSION_KEY, strValue);
    EXPECT_EQ(false, ret);
}

/**
 * @tc.name: EntriesToAccesser001
 * @tc.desc: EntriesToAccesser all .
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, EntriesToAccesser001, TestSize.Level1)
{
    ValuesBucket values;
    ValueObject valueObject;
    Accesser profile;
    int32_t intValue = 1;
    int64_t longValue = 1;
    string strValue = "strValue";
    
    values.PutLong(ACCESSER_ID, longValue);
    values.PutString(ACCESSER_DEVICE_ID, strValue);
    values.PutInt(ACCESSER_USER_ID, intValue);
    values.PutString(ACCESSER_ACCOUNT_ID, strValue);
    values.PutLong(ACCESSER_TOKEN_ID, longValue);
    values.PutString(ACCESSER_BUNDLE_NAME, strValue);
    values.PutInt(ACCESSER_BIND_LEVEL, intValue);

    ProfileUtils::EntriesToAccesser(values, profile);
    EXPECT_EQ("strValue", profile.GetAccesserBundleName());
    
    values.Clear();
    values.PutNull(ACCESSER_ID);
    values.PutNull(ACCESSER_DEVICE_ID);
    values.PutNull(ACCESSER_USER_ID);
    values.PutNull(ACCESSER_ACCOUNT_ID);
    values.PutNull(ACCESSER_TOKEN_ID);
    values.PutNull(ACCESSER_BUNDLE_NAME);
    values.PutNull(ACCESSER_BIND_LEVEL);
    EXPECT_EQ(true, values.GetObject(ACCESSER_ACCOUNT_ID, valueObject));
    EXPECT_EQ(false, valueObject.GetString(strValue) == E_OK);
    ProfileUtils::EntriesToAccesser(values, profile);

    values.Clear();
    EXPECT_EQ(false, values.GetObject(ACCESSER_ACCOUNT_ID, valueObject));
    ProfileUtils::EntriesToAccesser(values, profile);
}

/**
 * @tc.name: EntriesToAccessee001
 * @tc.desc: EntriesToAccessee all .
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, EntriesToAccessee001, TestSize.Level1)
{
    ValuesBucket values;
    ValueObject valueObject;
    Accessee profile;
    int32_t intValue = 1;
    int64_t longValue = 1;
    string strValue = "strValue";
    
    values.PutLong(ACCESSEE_ID, longValue);
    values.PutString(ACCESSEE_DEVICE_ID, strValue);
    values.PutInt(ACCESSEE_USER_ID, intValue);
    values.PutString(ACCESSEE_ACCOUNT_ID, strValue);
    values.PutLong(ACCESSEE_TOKEN_ID, longValue);
    values.PutString(ACCESSEE_BUNDLE_NAME, strValue);
    values.PutInt(ACCESSEE_BIND_LEVEL, intValue);
    
    ProfileUtils::EntriesToAccessee(values, profile);
    EXPECT_EQ("strValue", profile.GetAccesseeBundleName());

    values.Clear();
    values.PutNull(ACCESSEE_ID);
    values.PutNull(ACCESSEE_DEVICE_ID);
    values.PutNull(ACCESSEE_USER_ID);
    values.PutNull(ACCESSEE_ACCOUNT_ID);
    values.PutNull(ACCESSEE_TOKEN_ID);
    values.PutNull(ACCESSEE_BUNDLE_NAME);
    values.PutNull(ACCESSEE_BIND_LEVEL);
    EXPECT_EQ(true, values.GetObject(ACCESSEE_ACCOUNT_ID, valueObject));
    EXPECT_EQ(false, valueObject.GetString(strValue) == E_OK);
    ProfileUtils::EntriesToAccessee(values, profile);
    
    values.Clear();
    EXPECT_EQ(false, values.GetObject(ACCESSEE_ACCOUNT_ID, valueObject));
    ProfileUtils::EntriesToAccessee(values, profile);
}

/**
 * @tc.name: EntriesToDeviceProfile002
 * @tc.desc: EntriesToDeviceProfile failed all.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, EntriesToDeviceProfile002, TestSize.Level1)
{
    DeviceProfile profile;
    map<string, string> values;
    values["key"] = "value";
    auto propertiesMap = ProfileUtils::GetProfilePropertiesMap(values);
    bool ret1 = ProfileUtils::IsPropertyValid(propertiesMap, DEVICE_NAME, MAX_STRING_LEN);
    EXPECT_EQ(false, ret1);
    ProfileUtils::EntriesToDeviceProfile(values, profile);

    for (int32_t i = 0; i < MAX_DB_RECORD_SIZE + 5; i++) {
        values[to_string(i)] = "value";
    }
    int32_t ret2 = ProfileUtils::EntriesToDeviceProfile(values, profile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret2);
}

/**
 * @tc.name: EntriesToServiceProfile002
 * @tc.desc: EntriesToServiceProfile all.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, EntriesToServiceProfile002, TestSize.Level1)
{
    map<string, string> values;
    ServiceProfile profile;
    string strValye = "";
    values[SERVICE_NAME] = "serviceName";
    values[SERVICE_TYPE] = "serviceType";

    int32_t ret1 = ProfileUtils::EntriesToServiceProfile(values, profile);
    EXPECT_EQ(DP_SUCCESS, ret1);
    EXPECT_EQ("", profile.GetServiceName());

    for (int32_t i = 0; i < MAX_STRING_LEN + 5; i++) {
        strValye += "a";
    }
    values[SERVICE_NAME] = strValye;
    values[SERVICE_TYPE] = strValye;
    auto propertiesMap = ProfileUtils::GetProfilePropertiesMap(values);
    EXPECT_EQ(false, propertiesMap.count(SERVICE_TYPE) != 0);
    EXPECT_EQ(false, 0 < propertiesMap[SERVICE_TYPE].length());
    EXPECT_EQ(true, propertiesMap[SERVICE_TYPE].length() < MAX_STRING_LEN);
    ProfileUtils::EntriesToServiceProfile(values, profile);

    values[SERVICE_NAME] = "";
    values[SERVICE_TYPE] = "";
    propertiesMap = ProfileUtils::GetProfilePropertiesMap(values);
    EXPECT_EQ(false, propertiesMap.count(SERVICE_TYPE) != 0);
    EXPECT_EQ(false, 0 < propertiesMap[SERVICE_TYPE].length());
    ProfileUtils::EntriesToServiceProfile(values, profile);
    
    values.erase(SERVICE_NAME);
    values.erase(SERVICE_TYPE);
    propertiesMap = ProfileUtils::GetProfilePropertiesMap(values);
    EXPECT_EQ(false, propertiesMap.count(SERVICE_TYPE) != 0);
    ProfileUtils::EntriesToServiceProfile(values, profile);

    for (int32_t i = 0; i < MAX_DB_RECORD_SIZE + 5; i++) {
        values[to_string(i)] = "value";
    }
    int32_t ret2 = ProfileUtils::EntriesToServiceProfile(values, profile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret2);
}

/**
 * @tc.name: EntriesToCharProfile002
 * @tc.desc: EntriesToCharProfile all.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileUtilsTest, EntriesToCharProfile002, TestSize.Level1)
{
    map<string, string> values;
    CharacteristicProfile profile;
    string strValye = "";
    values[CHARACTERISTIC_KEY] = "characteristicKey";
    values[CHARACTERISTIC_VALUE] = "characteristicValue";
    
    int32_t ret1 = ProfileUtils::EntriesToCharProfile(values, profile);
    EXPECT_EQ(DP_SUCCESS, ret1);
    EXPECT_EQ("", profile.GetCharacteristicKey());

    for (int32_t i = 0; i < MAX_STRING_LEN + 5; i++) {
        strValye += "a";
    }
    values[CHARACTERISTIC_KEY] = strValye;
    values[CHARACTERISTIC_VALUE] = strValye;
    EXPECT_EQ(true, values.count(CHARACTERISTIC_KEY) != 0);
    EXPECT_EQ(true, 0 < values[CHARACTERISTIC_KEY].length());
    EXPECT_EQ(false, values[CHARACTERISTIC_KEY].length() < MAX_STRING_LEN);
    ProfileUtils::EntriesToCharProfile(values, profile);

    values[CHARACTERISTIC_KEY] = "";
    values[CHARACTERISTIC_VALUE] = "";
    EXPECT_EQ(true, values.count(CHARACTERISTIC_KEY) != 0);
    EXPECT_EQ(false, 0 < values[CHARACTERISTIC_KEY].length());
    ProfileUtils::EntriesToCharProfile(values, profile);

    values.erase(CHARACTERISTIC_KEY);
    values.erase(CHARACTERISTIC_VALUE);
    EXPECT_EQ(false, values.count(CHARACTERISTIC_KEY) != 0);
    ProfileUtils::EntriesToCharProfile(values, profile);

    for (int32_t i = 0; i < MAX_DB_RECORD_SIZE + 5; i++) {
        values[to_string(i)] = "value";
    }
    int32_t ret2 = ProfileUtils::EntriesToCharProfile(values, profile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret2);
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
