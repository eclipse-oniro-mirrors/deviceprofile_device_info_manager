/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"

#include "utils.h"

#define protected public
#define private public
#include "authority_manager.h"
#include "trust_group_manager.h"
#undef private
#undef protected
#include "device_profile_errors.h"

namespace OHOS {
namespace DeviceProfile {
using namespace testing;
using namespace testing::ext;

namespace {
const std::string AUTHORITY_JSON_PATH = "/system/etc/deviceprofile/authority.json";
const std::string TEST_DEVICEID = "1111111111111111111111111";
const std::string TEST_TRUST_GROUP =
    "{\"groupId\":\"id\",\"groupType\":0,\"groupName\":\"name\",\"groupOwner\":\"test\",\"groupVisibility\":1}";
const std::string INVALID_AUTHORITY_STR =
    "{\"fakeProcess1\":{\"servicesAuthority\":{\"all\":3}},\"fakeProcess2\":{\"servicesAuthority\":{\"all\":true}}}";
const std::string VALID_AUTHORITY_STR = "{\"hdcd\":{\"servicesAuthority\":{\"all\":1,\"specific\":" \
    "{\"storage\":3,\"system\":3},\"prefix\":{\"cameraRear\":3}},\"interfacesAuthority\":{\"sync\":{}}}}";
}

class ProfileAuthorityTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    static bool LoadAuthorityCfg(const std::string& filePath);
    static bool LoadAuthorityByStr(const std::string& jsonStr);
    void SetUp();
    void TearDown();
};

void ProfileAuthorityTest::SetUpTestCase()
{
}

void ProfileAuthorityTest::TearDownTestCase()
{
}

void ProfileAuthorityTest::SetUp()
{
}

void ProfileAuthorityTest::TearDown()
{
}

bool ProfileAuthorityTest::LoadAuthorityCfg(const std::string& filePath)
{
    if (!AuthorityManager::GetInstance().LoadAuthorityCfg(filePath)) {
        DTEST_LOG << "not found " << filePath << std::endl;
        return false;
    }
    AuthorityManager::GetInstance().InitSupportedInterfaces();
    AuthorityManager::GetInstance().ValidateAuthorityCfg();
    return true;
}

bool ProfileAuthorityTest::LoadAuthorityByStr(const std::string& jsonStr)
{
    AuthorityManager::GetInstance().authJson_ =
        nlohmann::json::parse(jsonStr.c_str(), nullptr, false);
    if (AuthorityManager::GetInstance().authJson_.is_discarded()) {
        return false;
    }

    AuthorityManager::GetInstance().InitSupportedInterfaces();
    AuthorityManager::GetInstance().ValidateAuthorityCfg();
    return true;
}

/**
 * @tc.name: PrecheckAuthority_001
 * @tc.desc: precheck an authority json with invalid config
 * @tc.type: FUNC
 * @tc.require: I4OH94
 */
HWTEST_F(ProfileAuthorityTest, PrecheckAuthority_001, TestSize.Level2)
{
    if (!LoadAuthorityByStr(INVALID_AUTHORITY_STR)) {
        return;
    }

    EXPECT_EQ(AuthorityManager::GetInstance().authJson_.dump(), R"({})");
}

/**
 * @tc.name: CheckAuthority_002
 * @tc.desc: check authority of a fake serviceId
 * @tc.type: FUNC
 * @tc.require: I4OH94
 */
HWTEST_F(ProfileAuthorityTest, CheckAuthority_002, TestSize.Level2)
{
    if (!LoadAuthorityByStr(VALID_AUTHORITY_STR)) {
        return;
    }

    EXPECT_EQ(false, AuthorityManager::GetInstance().CheckServiceAuthority(AuthValue::AUTH_W,
        "fakeServiceId"));
}

/**
 * @tc.name: CheckAuthority_003
 * @tc.desc: check authority of specific serviceId with diff auth value
 * @tc.type: FUNC
 * @tc.require: I4OH94
 */
HWTEST_F(ProfileAuthorityTest, CheckAuthority_003, TestSize.Level2)
{
    if (!LoadAuthorityByStr(VALID_AUTHORITY_STR)) {
        return;
    }

    EXPECT_EQ(true, AuthorityManager::GetInstance().CheckServiceAuthority(AuthValue::AUTH_R, "storage"));
    EXPECT_EQ(true, AuthorityManager::GetInstance().CheckServiceAuthority(AuthValue::AUTH_W, "storage"));
}

/**
 * @tc.name: CheckAuthority_004
 * @tc.desc: check authority of an empty serviceId
 * @tc.type: FUNC
 * @tc.require: I4OH94
 */
HWTEST_F(ProfileAuthorityTest, CheckAuthority_004, TestSize.Level2)
{
    if (!LoadAuthorityByStr(VALID_AUTHORITY_STR)) {
        return;
    }

    EXPECT_EQ(false, AuthorityManager::GetInstance().CheckServiceAuthority(AuthValue::AUTH_R,
        ""));
    EXPECT_EQ(false, AuthorityManager::GetInstance().CheckServicesAuthority(AuthValue::AUTH_R,
        {"system", ""}));
}

/**
 * @tc.name: CheckAuthority_005
 * @tc.desc: check authority of all with diff auth value
 * @tc.type: FUNC
 * @tc.require: I4OH94
 */
HWTEST_F(ProfileAuthorityTest, CheckAuthority_005, TestSize.Level2)
{
    if (!LoadAuthorityByStr(VALID_AUTHORITY_STR)) {
        return;
    }

    EXPECT_EQ(true, AuthorityManager::GetInstance().CheckServicesAuthority(AuthValue::AUTH_R, {}));
    EXPECT_EQ(false, AuthorityManager::GetInstance().CheckServicesAuthority(AuthValue::AUTH_W, {}));
}

/**
 * @tc.name: CheckAuthority_006
 * @tc.desc: check authority of serviceIds with same prefix
 * @tc.type: FUNC
 * @tc.require: I4OH94
 */
HWTEST_F(ProfileAuthorityTest, CheckAuthority_006, TestSize.Level2)
{
    if (!LoadAuthorityByStr(VALID_AUTHORITY_STR)) {
        return;
    }

    EXPECT_EQ(true, AuthorityManager::GetInstance().CheckServiceAuthority(AuthValue::AUTH_R,
        "cameraRear1"));
    EXPECT_EQ(true, AuthorityManager::GetInstance().CheckServiceAuthority(AuthValue::AUTH_W,
        "cameraRear1"));

    EXPECT_EQ(true, AuthorityManager::GetInstance().CheckServiceAuthority(AuthValue::AUTH_R,
        "cameraRear2"));
    EXPECT_EQ(true, AuthorityManager::GetInstance().CheckServiceAuthority(AuthValue::AUTH_W,
        "cameraRear2"));
}

/**
 * @tc.name: CheckAuthority_007
 * @tc.desc: check authority of multiple serviceIds
 * @tc.type: FUNC
 * @tc.require: I4OH94
 */
HWTEST_F(ProfileAuthorityTest, CheckAuthority_007, TestSize.Level2)
{
    if (!LoadAuthorityByStr(VALID_AUTHORITY_STR)) {
        return;
    }

    EXPECT_EQ(true, AuthorityManager::GetInstance().CheckServicesAuthority(AuthValue::AUTH_W,
        {"cameraRear1", "cameraRear2", "cameraRear3"}));
    EXPECT_EQ(true, AuthorityManager::GetInstance().CheckServicesAuthority(AuthValue::AUTH_W,
        {"storage", "system"}));
    EXPECT_EQ(true, AuthorityManager::GetInstance().CheckServicesAuthority(AuthValue::AUTH_W,
        {"cameraRear1", "cameraRear2", "cameraRear3", "storage", "system"}));
}

/**
 * @tc.name: CheckAuthority_008
 * @tc.desc: check authority of interfaces
 * @tc.type: FUNC
 * @tc.require: I4OH94
 */
HWTEST_F(ProfileAuthorityTest, CheckAuthority_008, TestSize.Level2)
{
    if (!LoadAuthorityByStr(VALID_AUTHORITY_STR)) {
        return;
    }

    EXPECT_EQ(true, AuthorityManager::GetInstance().CheckInterfaceAuthority("sync"));
    EXPECT_EQ(false, AuthorityManager::GetInstance().CheckInterfaceAuthority("fakeInterface"));
    EXPECT_EQ(false, AuthorityManager::GetInstance().CheckInterfaceAuthority(""));
}

/**
 * @tc.name: CheckAuthority_009
 * @tc.desc: check authority of interfaces
 * @tc.type: FUNC
 * @tc.require: I4OH94
 */
HWTEST_F(ProfileAuthorityTest, CheckAuthority_009, TestSize.Level2)
{
    if (!LoadAuthorityCfg(AUTHORITY_JSON_PATH)) {
        return;
    }

    EXPECT_EQ(false, AuthorityManager::GetInstance().CheckServiceAuthority(AuthValue::AUTH_R, "syscap"));
}

/**
 * @tc.name: Init_001
 * @tc.desc: precheck an authority json with invalid config
 * @tc.type: FUNC
 * @tc.require: I4OH94
 */
HWTEST_F(ProfileAuthorityTest, Init_001, TestSize.Level2)
{
    EXPECT_EQ(true, AuthorityManager::GetInstance().Init());
}

/**
 * @tc.name: CheckDeviceId_001
 * @tc.desc: check device id of interfaces
 * @tc.type: FUNC
 * @tc.require: I4OH93
 */
HWTEST_F(ProfileAuthorityTest, CheckDeviceId_001, TestSize.Level2)
{
    EXPECT_EQ(false, TrustGroupManager::GetInstance().CheckDeviceId(""));
    EXPECT_EQ(true, TrustGroupManager::GetInstance().CheckDeviceId(TEST_DEVICEID));
}

/**
 * @tc.name: InitHichainService_001
 * @tc.desc: init hichain service of interfaces
 * @tc.type: FUNC
 * @tc.require: I4OH93
 */
HWTEST_F(ProfileAuthorityTest, InitHichainService_001, TestSize.Level2)
{
    TrustGroupManager::GetInstance().OnDeviceUnBoundAdapter("", "");
    EXPECT_EQ(true, TrustGroupManager::GetInstance().InitHichainService());
}

/**
 * @tc.name: CheckTrustGroup_001
 * @tc.desc: check trust group of interfaces
 * @tc.type: FUNC
 * @tc.require: I4OH93
 */
HWTEST_F(ProfileAuthorityTest, CheckTrustGroup_001, TestSize.Level2)
{
    GroupInfo groupInfo;
    nlohmann::json jsonObject = nlohmann::json::parse(TEST_TRUST_GROUP, nullptr, false);
    if (jsonObject.is_discarded()) {
        return;
    }
    from_json(jsonObject, groupInfo);
    EXPECT_EQ(false, TrustGroupManager::GetInstance().CheckTrustGroup(""));
}
}
}