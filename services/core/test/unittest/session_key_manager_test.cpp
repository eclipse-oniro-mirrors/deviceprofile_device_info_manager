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
#include <string>
#include <vector>
#include "distributed_device_profile_client.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_errors.h"

#include "session_key_manager.h"

using namespace testing::ext;
namespace OHOS {
namespace DistributedDeviceProfile {
using namespace std;
namespace {
const std::string TAG = "SessionKeyManagerTest";
int32_t g_sessionKeyId = 0;
}

class SessionKeyManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void SessionKeyManagerTest::SetUpTestCase()
{
}

void SessionKeyManagerTest::TearDownTestCase()
{
}

void SessionKeyManagerTest::SetUp()
{
}

void SessionKeyManagerTest::TearDown()
{
}

/*
 * @tc.name: PutSessionKey001
 * @tc.desc: PutSessionKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SessionKeyManagerTest, PutSessionKey001, TestSize.Level1)
{
    uint32_t userId = 100;
    std::vector<uint8_t> sessionKey;
    sessionKey.emplace_back(1);
    sessionKey.emplace_back(2);
    sessionKey.emplace_back(3);
    sessionKey.emplace_back(4);
    sessionKey.emplace_back(5);
    int32_t ret = OHOS::DistributedDeviceProfile::DistributedDeviceProfileClient::
        GetInstance().PutSessionKey(userId, sessionKey, g_sessionKeyId);
    EXPECT_NE(ret, DP_SUCCESS);
}

/*
 * @tc.name: PutSessionKey002
 * @tc.desc: PutSessionKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SessionKeyManagerTest, PutSessionKey002, TestSize.Level1)
{
    uint32_t userId = 100;
    std::vector<uint8_t> sessionKey;
    sessionKey.emplace_back(1);
    sessionKey.emplace_back(2);
    sessionKey.emplace_back(3);
    sessionKey.emplace_back(4);
    sessionKey.emplace_back(5);
    int32_t ret = SessionKeyManager::GetInstance().PutSessionKey(userId, sessionKey, g_sessionKeyId);
    EXPECT_NE(ret, DP_SUCCESS);
}

/*
 * @tc.name: PutSessionKey003
 * @tc.desc: PutSessionKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SessionKeyManagerTest, PutSessionKey003, TestSize.Level1)
{
    uint32_t userId = 0;
    std::vector<uint8_t> sessionKey;
    sessionKey.emplace_back(1);
    sessionKey.emplace_back(2);
    sessionKey.emplace_back(3);
    sessionKey.emplace_back(4);
    sessionKey.emplace_back(5);
    int32_t ret = SessionKeyManager::GetInstance().PutSessionKey(userId, sessionKey, g_sessionKeyId);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/*
 * @tc.name: GetSessionKey001
 * @tc.desc: GetSessionKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SessionKeyManagerTest, GetSessionKey001, TestSize.Level1)
{
    uint32_t userId = 100;
    std::vector<uint8_t> sessionKey;
    int32_t ret = OHOS::DistributedDeviceProfile::DistributedDeviceProfileClient::
        GetInstance().GetSessionKey(userId, g_sessionKeyId, sessionKey);
    EXPECT_NE(ret, DP_SUCCESS);
}

/*
 * @tc.name: GetSessionKey004
 * @tc.desc: GetSessionKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SessionKeyManagerTest, GetSessionKey004, TestSize.Level1)
{
    uint32_t userId = 100;
    std::vector<uint8_t> sessionKey;
    int32_t ret = SessionKeyManager::GetInstance().GetSessionKey(userId, g_sessionKeyId, sessionKey);
    EXPECT_NE(ret, DP_SUCCESS);
}

/*
 * @tc.name: UpdateSessionKey001
 * @tc.desc: UpdateSessionKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SessionKeyManagerTest, UpdateSessionKey001, TestSize.Level1)
{
    uint32_t userId = 100;
    std::vector<uint8_t> sessionKey;
    sessionKey.emplace_back(6);
    sessionKey.emplace_back(7);
    sessionKey.emplace_back(8);
    sessionKey.emplace_back(9);
    sessionKey.emplace_back(10);
    int32_t ret = OHOS::DistributedDeviceProfile::DistributedDeviceProfileClient::
        GetInstance().UpdateSessionKey(userId, g_sessionKeyId, sessionKey);
    EXPECT_NE(ret, DP_SUCCESS);
}

/*
 * @tc.name: UpdateSessionKey002
 * @tc.desc: UpdateSessionKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SessionKeyManagerTest, UpdateSessionKey002, TestSize.Level1)
{
    uint32_t userId = 100;
    std::vector<uint8_t> sessionKey;
    sessionKey.emplace_back(6);
    sessionKey.emplace_back(7);
    sessionKey.emplace_back(8);
    sessionKey.emplace_back(9);
    sessionKey.emplace_back(10);
    int32_t ret = SessionKeyManager::GetInstance().UpdateSessionKey(userId, g_sessionKeyId, sessionKey);
    EXPECT_NE(ret, DP_SUCCESS);
}

/*
 * @tc.name: UpdateSessionKey003
 * @tc.desc: UpdateSessionKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SessionKeyManagerTest, UpdateSessionKey003, TestSize.Level1)
{
    uint32_t userId = 0;
    std::vector<uint8_t> sessionKey;
    sessionKey.emplace_back(6);
    sessionKey.emplace_back(7);
    sessionKey.emplace_back(8);
    sessionKey.emplace_back(9);
    sessionKey.emplace_back(10);
    int32_t ret = SessionKeyManager::GetInstance().UpdateSessionKey(userId, g_sessionKeyId, sessionKey);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/*
 * @tc.name: GetSessionKey002
 * @tc.desc: GetSessionKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SessionKeyManagerTest, GetSessionKey002, TestSize.Level1)
{
    uint32_t userId = 100;
    std::vector<uint8_t> sessionKey;
    int32_t ret = OHOS::DistributedDeviceProfile::DistributedDeviceProfileClient::
        GetInstance().GetSessionKey(userId, g_sessionKeyId, sessionKey);
    EXPECT_NE(ret, DP_SUCCESS);
}

/*
 * @tc.name: GetSessionKey005
 * @tc.desc: GetSessionKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SessionKeyManagerTest, GetSessionKey005, TestSize.Level1)
{
    uint32_t userId = 100;
    std::vector<uint8_t> sessionKey;
    int32_t ret = SessionKeyManager::GetInstance().GetSessionKey(userId, g_sessionKeyId, sessionKey);
    EXPECT_NE(ret, DP_SUCCESS);
}

/*
 * @tc.name: DeleteSessionKey001
 * @tc.desc: DeleteSessionKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SessionKeyManagerTest, DeleteSessionKey001, TestSize.Level1)
{
    uint32_t userId = 100;
    int32_t ret = OHOS::DistributedDeviceProfile::DistributedDeviceProfileClient::
        GetInstance().DeleteSessionKey(userId, g_sessionKeyId);
    EXPECT_NE(ret, DP_SUCCESS);
}

/*
 * @tc.name: DeleteSessionKey002
 * @tc.desc: DeleteSessionKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SessionKeyManagerTest, DeleteSessionKey002, TestSize.Level1)
{
    uint32_t userId = 100;
    int32_t ret = SessionKeyManager::GetInstance().DeleteSessionKey(userId, g_sessionKeyId);
    EXPECT_NE(ret, DP_SUCCESS);
}

/*
 * @tc.name: DeleteSessionKey003
 * @tc.desc: DeleteSessionKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SessionKeyManagerTest, DeleteSessionKey003, TestSize.Level1)
{
    uint32_t userId = 0;
    int32_t ret = SessionKeyManager::GetInstance().DeleteSessionKey(userId, g_sessionKeyId);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/*
 * @tc.name: GetSessionKey003
 * @tc.desc: GetSessionKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SessionKeyManagerTest, GetSessionKey003, TestSize.Level1)
{
    uint32_t userId = 100;
    std::vector<uint8_t> sessionKey;
    int32_t ret = OHOS::DistributedDeviceProfile::DistributedDeviceProfileClient::
        GetInstance().GetSessionKey(userId, g_sessionKeyId, sessionKey);
    EXPECT_NE(ret, DP_SUCCESS);
}

/*
 * @tc.name: GetSessionKey006
 * @tc.desc: GetSessionKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SessionKeyManagerTest, GetSessionKey006, TestSize.Level1)
{
    uint32_t userId = 100;
    std::vector<uint8_t> sessionKey;
    int32_t ret = SessionKeyManager::GetInstance().GetSessionKey(userId, g_sessionKeyId, sessionKey);
    EXPECT_NE(ret, DP_SUCCESS);
}

/*
 * @tc.name: GetSessionKey007
 * @tc.desc: GetSessionKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SessionKeyManagerTest, GetSessionKey007, TestSize.Level1)
{
    uint32_t userId = 0;
    std::vector<uint8_t> sessionKey;
    int32_t ret = SessionKeyManager::GetInstance().GetSessionKey(userId, g_sessionKeyId, sessionKey);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}
}
}
