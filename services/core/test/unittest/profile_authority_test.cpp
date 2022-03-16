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
#undef private
#undef protected
#include "device_profile_errors.h"

namespace OHOS {
namespace DeviceProfile {
using namespace testing;
using namespace testing::ext;

namespace {
const std::string AUTHORITY_JSON_DIR = "/data/test/resource/deviceprofile/authority/";
const std::string INVALID_AUTHORITY = AUTHORITY_JSON_DIR + "invalid_authority.json";
const std::string VALID_AUTHORITY = AUTHORITY_JSON_DIR + "valid_authority.json";
}

class ProfileAuthorityTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    static bool LoadAuthorityCfg(const std::string& filePath);
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

/**
 * @tc.name: PrecheckAuthority_001
 * @tc.desc: precheck an authority json with invalid config
 * @tc.type: FUNC
 */
HWTEST_F(ProfileAuthorityTest, PrecheckAuthority_001, TestSize.Level0)
{
    if (!LoadAuthorityCfg(INVALID_AUTHORITY)) {
        return;
    }

    EXPECT_EQ(AuthorityManager::GetInstance().authJson_.dump(), R"({})");
}

/**
 * @tc.name: CheckAuthority_002
 * @tc.desc: check authority of a fake serviceId
 * @tc.type: FUNC
 */
HWTEST_F(ProfileAuthorityTest, CheckAuthority_002, TestSize.Level0)
{
    if (!LoadAuthorityCfg(VALID_AUTHORITY)) {
        return;
    }

    EXPECT_FALSE(AuthorityManager::GetInstance().CheckServiceAuthority(AuthValue::AUTH_W,
        "fakeServiceId"));
}

/**
 * @tc.name: CheckAuthority_003
 * @tc.desc: check authority of specific serviceId with diff auth value
 * @tc.type: FUNC
 */
HWTEST_F(ProfileAuthorityTest, CheckAuthority_003, TestSize.Level0)
{
    if (!LoadAuthorityCfg(VALID_AUTHORITY)) {
        return;
    }

    EXPECT_TRUE(AuthorityManager::GetInstance().CheckServiceAuthority(AuthValue::AUTH_R,
        "storage"));
    EXPECT_TRUE(AuthorityManager::GetInstance().CheckServiceAuthority(AuthValue::AUTH_W,
        "storage"));
}

/**
 * @tc.name: CheckAuthority_004
 * @tc.desc: check authority of an empty serviceId
 * @tc.type: FUNC
 */
HWTEST_F(ProfileAuthorityTest, CheckAuthority_004, TestSize.Level0)
{
    if (!LoadAuthorityCfg(VALID_AUTHORITY)) {
        return;
    }

    EXPECT_FALSE(AuthorityManager::GetInstance().CheckServiceAuthority(AuthValue::AUTH_R,
        ""));
    EXPECT_FALSE(AuthorityManager::GetInstance().CheckServicesAuthority(AuthValue::AUTH_R,
        {"system", ""}));
}

/**
 * @tc.name: CheckAuthority_005
 * @tc.desc: check authority of all with diff auth value
 * @tc.type: FUNC
 */
HWTEST_F(ProfileAuthorityTest, CheckAuthority_005, TestSize.Level0)
{
    if (!LoadAuthorityCfg(VALID_AUTHORITY)) {
        return;
    }

    EXPECT_TRUE(AuthorityManager::GetInstance().CheckServicesAuthority(AuthValue::AUTH_R, {}));
    EXPECT_FALSE(AuthorityManager::GetInstance().CheckServicesAuthority(AuthValue::AUTH_W, {}));
}

/**
 * @tc.name: CheckAuthority_006
 * @tc.desc: check authority of serviceIds with same prefix
 * @tc.type: FUNC
 */
HWTEST_F(ProfileAuthorityTest, CheckAuthority_006, TestSize.Level0)
{
    if (!LoadAuthorityCfg(VALID_AUTHORITY)) {
        return;
    }

    EXPECT_TRUE(AuthorityManager::GetInstance().CheckServiceAuthority(AuthValue::AUTH_R,
        "cameraRear1"));
    EXPECT_TRUE(AuthorityManager::GetInstance().CheckServiceAuthority(AuthValue::AUTH_W,
        "cameraRear1"));

    EXPECT_TRUE(AuthorityManager::GetInstance().CheckServiceAuthority(AuthValue::AUTH_R,
        "cameraRear2"));
    EXPECT_TRUE(AuthorityManager::GetInstance().CheckServiceAuthority(AuthValue::AUTH_W,
        "cameraRear2"));
}

/**
 * @tc.name: CheckAuthority_007
 * @tc.desc: check authority of multiple serviceIds
 * @tc.type: FUNC
 */
HWTEST_F(ProfileAuthorityTest, CheckAuthority_007, TestSize.Level0)
{
    if (!LoadAuthorityCfg(VALID_AUTHORITY)) {
        return;
    }

    EXPECT_TRUE(AuthorityManager::GetInstance().CheckServicesAuthority(AuthValue::AUTH_W,
        {"cameraRear1", "cameraRear2", "cameraRear3"}));
    EXPECT_TRUE(AuthorityManager::GetInstance().CheckServicesAuthority(AuthValue::AUTH_W,
        {"storage", "system"}));
    EXPECT_TRUE(AuthorityManager::GetInstance().CheckServicesAuthority(AuthValue::AUTH_W,
        {"cameraRear1", "cameraRear2", "cameraRear3", "storage", "system"}));
}

/**
 * @tc.name: CheckAuthority_008
 * @tc.desc: check authority of interfaces
 * @tc.type: FUNC
 */
HWTEST_F(ProfileAuthorityTest, CheckAuthority_008, TestSize.Level0)
{
    if (!LoadAuthorityCfg(VALID_AUTHORITY)) {
        return;
    }

    EXPECT_TRUE(AuthorityManager::GetInstance().CheckInterfaceAuthority("sync"));
    EXPECT_FALSE(AuthorityManager::GetInstance().CheckInterfaceAuthority("fakeInterface"));
    EXPECT_FALSE(AuthorityManager::GetInstance().CheckInterfaceAuthority(""));
}
}
}
