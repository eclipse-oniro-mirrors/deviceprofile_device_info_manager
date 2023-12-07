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

#define private   public
#define protected public
#include <string>
#include <vector>
#include "gtest/gtest.h"
#include "refbase.h"
#include "profile_utils.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_enums.h"
#undef private
#undef protected

using namespace testing::ext;
using namespace OHOS::DistributedDeviceProfile;
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
    int32_t res2 = res2 = ProfileUtils::EntriesToTrustDeviceProfile(values, outProfile);
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
    deviceProfile.SetDeviceTypeName("anything");
    deviceProfile.SetDeviceTypeId(0);
    deviceProfile.SetDeviceName("anything");
    deviceProfile.SetManufactureName("anything");
    deviceProfile.SetDeviceModel("anything");
    deviceProfile.SetSerialNumberId("anything");
    deviceProfile.SetStorageCapability(1);
    deviceProfile.SetOsSysCap("anything");
    deviceProfile.SetOsApiLevel(1);
    deviceProfile.SetOsVersion("anything");
    deviceProfile.SetOsType(1);
    
    map<string, string> entries;
    int32_t res1 = ProfileUtils::DeviceProfileToEntries(deviceProfile, entries);
    EXPECT_EQ(DP_SUCCESS, res1);
    
    DeviceProfile outDeviceProfile;
    int32_t res2 = ProfileUtils::EntriesToDeviceProfile(entries, outDeviceProfile);
    EXPECT_EQ(DP_SUCCESS, res2);
    EXPECT_EQ("anything", outDeviceProfile.GetDeviceId());
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
    
    uint32_t u32MinValue = 0;
    uint32_t u32MaxValue = 1;
    bool res3 = ProfileUtils::IsPropertyValid(propertyMap, property, u32MinValue, u32MaxValue);
    EXPECT_EQ(false, res3);
    
    int64_t i64MinValue = 0;
    int64_t i64MaxValue = 1;
    bool res4 = ProfileUtils::IsPropertyValid(propertyMap, property, i64MinValue, i64MaxValue);
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
