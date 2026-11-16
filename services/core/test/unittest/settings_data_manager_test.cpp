/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "settings_data_manager.h"

#include <memory>
#include <string>

#include "distributed_device_profile_errors.h"
#include "gtest/gtest.h"

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace testing::ext;
namespace {
constexpr int32_t MIN_USER_ID = 100;
constexpr int32_t INVALID_USER_ID = -1;
constexpr int32_t OTHER_USER_ID = 101;
const std::string URI_ROOT = "datashare:///com.ohos.settingsdata/entry/settingsdata/";
}  // namespace
class SettingsDataManagerFileTest : public testing::Test {};

/**
 * @tc.name: GlobalTableDoesNotAppendUserId_001
 * @tc.desc: Verify that global table does not append user id.
 * @tc.type: FUNC
 */
HWTEST_F(SettingsDataManagerFileTest, GlobalTableDoesNotAppendUserId_001, TestSize.Level1)
{
    auto &manager = SettingsDataManager::GetInstance();
    const auto first = manager.GetProxyUriStr("SETTINGSDATA", MIN_USER_ID);
    const auto second = manager.GetProxyUriStr("SETTINGSDATA", OTHER_USER_ID);
    EXPECT_EQ(first, URI_ROOT + "SETTINGSDATA?Proxy=true");
    EXPECT_EQ(second, first);
}

/**
 * @tc.name: SecureTableSeparatesUsers_001
 * @tc.desc: Verify that secure table separates users.
 * @tc.type: FUNC
 */
HWTEST_F(SettingsDataManagerFileTest, SecureTableSeparatesUsers_001, TestSize.Level1)
{
    auto &manager = SettingsDataManager::GetInstance();
    const auto first = manager.GetProxyUriStr("USER_SETTINGSDATA_SECURE_", MIN_USER_ID);
    const auto second = manager.GetProxyUriStr("USER_SETTINGSDATA_SECURE_", OTHER_USER_ID);
    EXPECT_EQ(first, URI_ROOT + "USER_SETTINGSDATA_SECURE_100?Proxy=true");
    EXPECT_EQ(second, URI_ROOT + "USER_SETTINGSDATA_SECURE_101?Proxy=true");
    EXPECT_NE(first, second);
}

/**
 * @tc.name: LowUserIdsNormalizeToFirstApplicationUser_001
 * @tc.desc: Verify that low user ids normalize to first application user.
 * @tc.type: FUNC
 */
HWTEST_F(SettingsDataManagerFileTest, LowUserIdsNormalizeToFirstApplicationUser_001, TestSize.Level1)
{
    auto &manager = SettingsDataManager::GetInstance();
    const auto expected = manager.GetProxyUriStr("USER_SETTINGSDATA_", MIN_USER_ID);
    EXPECT_EQ(manager.GetProxyUriStr("USER_SETTINGSDATA_", INVALID_USER_ID), expected);
    EXPECT_EQ(manager.GetProxyUriStr("USER_SETTINGSDATA_", 0), expected);
    EXPECT_EQ(manager.GetProxyUriStr("USER_SETTINGSDATA_", MIN_USER_ID - 1), expected);
    EXPECT_EQ(expected, URI_ROOT + "USER_SETTINGSDATA_100?Proxy=true");
}

/**
 * @tc.name: MakeUriRetainsProxyAndAddsKey_001
 * @tc.desc: Verify that make uri retains proxy and adds key.
 * @tc.type: FUNC
 */
HWTEST_F(SettingsDataManagerFileTest, MakeUriRetainsProxyAndAddsKey_001, TestSize.Level1)
{
    auto &manager = SettingsDataManager::GetInstance();
    const std::string proxy = manager.GetProxyUriStr("SETTINGSDATA", MIN_USER_ID);
    const std::string key = "settings.general.device_name";
    Uri uri = manager.MakeUri(proxy, key);
    EXPECT_EQ(uri.ToString(), proxy + "&key=" + key);
    EXPECT_EQ(uri.GetScheme(), "datashare");
}

/**
 * @tc.name: EmptyProxyAndNullHelperAreRejectedLocally_002
 * @tc.desc: Verify that empty proxy and null helper are rejected locally.
 * @tc.type: FUNC
 */
HWTEST_F(SettingsDataManagerFileTest, EmptyProxyAndNullHelperAreRejectedLocally_002, TestSize.Level1)
{
    auto &manager = SettingsDataManager::GetInstance();
    EXPECT_EQ(manager.CreateDataShareHelper(""), nullptr);
    EXPECT_FALSE(manager.ReleaseDataShareHelper(nullptr));
    EXPECT_EQ(manager.UnInit(), DP_SUCCESS);
    EXPECT_EQ(manager.remoteObj_, nullptr);
}

/**
 * @tc.name: UnInitIsIdempotent_001
 * @tc.desc: Verify that un init is idempotent.
 * @tc.type: FUNC
 */
HWTEST_F(SettingsDataManagerFileTest, UnInitIsIdempotent_001, TestSize.Level1)
{
    auto &manager = SettingsDataManager::GetInstance();
    EXPECT_EQ(manager.UnInit(), DP_SUCCESS);
    EXPECT_EQ(manager.UnInit(), DP_SUCCESS);
    EXPECT_EQ(manager.remoteObj_, nullptr);
}
}  // namespace DistributedDeviceProfile
}  // namespace OHOS
