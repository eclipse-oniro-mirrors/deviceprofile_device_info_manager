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
#include <iostream>

#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_log.h"
#include "distributed_device_profile_errors.h"

#include "business_callback_stub.h"
#include "distributed_device_profile_client.h"
#include "business_event_manager.h"

using namespace testing::ext;
namespace OHOS {
namespace DistributedDeviceProfile {
using namespace std;
namespace {
    const std::string TAG = "BusinessEventManagerTest";
}
class BusinessEventManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void BusinessEventManagerTest::SetUpTestCase()
{}

void BusinessEventManagerTest::TearDownTestCase()
{}

void BusinessEventManagerTest::SetUp()
{}

void BusinessEventManagerTest::TearDown()
{}

/*
* @tc.name: Init001
* @tc.desc: Init
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BusinessEventManagerTest, Init001, TestSize.Level1)
{
    int32_t result = BusinessEventManager::GetInstance().Init();
    EXPECT_EQ(result, DP_SUCCESS);
}

/*
* @tc.name: PutBusinessEvent001
* @tc.desc: Init
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BusinessEventManagerTest, PutBusinessEvent001, TestSize.Level1)
{
    BusinessEvent businessEvent;
    businessEvent.SetBusinessKey("");
    businessEvent.SetBusinessValue("testValue");
    int32_t result = BusinessEventManager::GetInstance().PutBusinessEvent(businessEvent);
    EXPECT_EQ(result, DP_INVALID_PARAM);
}

/*
* @tc.name: PutBusinessEvent002
* @tc.desc: Init
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BusinessEventManagerTest, PutBusinessEvent002, TestSize.Level1)
{
    BusinessEvent businessEvent;
    businessEvent.SetBusinessKey("business_id_cast+_reject_event");
    businessEvent.SetBusinessValue("");
    int32_t result = BusinessEventManager::GetInstance().PutBusinessEvent(businessEvent);
    EXPECT_EQ(result, DP_INVALID_PARAM);
}

/*
* @tc.name: PutBusinessEvent003
* @tc.desc: Init
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BusinessEventManagerTest, PutBusinessEvent003, TestSize.Level1)
{
    BusinessEvent businessEvent;
    businessEvent.SetBusinessKey("");
    businessEvent.SetBusinessValue("");
    int32_t result = BusinessEventManager::GetInstance().PutBusinessEvent(businessEvent);
    EXPECT_EQ(result, DP_INVALID_PARAM);
}

/*
* @tc.name: PutBusinessEvent004
* @tc.desc: Init
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BusinessEventManagerTest, PutBusinessEvent004, TestSize.Level1)
{
    BusinessEvent businessEvent;
    businessEvent.SetBusinessKey("businessKey");
    businessEvent.SetBusinessValue("testValue");
    int32_t result = BusinessEventManager::GetInstance().PutBusinessEvent(businessEvent);
    EXPECT_EQ(result, DP_INVALID_PARAM);
}


/*
* @tc.name: PutBusinessEvent005
* @tc.desc: Init
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BusinessEventManagerTest, PutBusinessEvent005, TestSize.Level1)
{
    BusinessEvent businessEvent;
    businessEvent.SetBusinessKey("business_id_cast+_disturbance_event");
    businessEvent.SetBusinessValue("testValue");
    int32_t result = BusinessEventManager::GetInstance().PutBusinessEvent(businessEvent);
    EXPECT_EQ(result, DP_SUCCESS);
}

/*
* @tc.name: GetBusinessEvent001
* @tc.desc: Init
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BusinessEventManagerTest, GetBusinessEvent001, TestSize.Level1)
{
    BusinessEvent businessEvent;
    businessEvent.SetBusinessKey("");
    int32_t result = BusinessEventManager::GetInstance().GetBusinessEvent(businessEvent);
    EXPECT_EQ(result, DP_INVALID_PARAM);
}

/*
* @tc.name: GetBusinessEvent002
* @tc.desc: Init
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BusinessEventManagerTest, GetBusinessEvent002, TestSize.Level1)
{
    BusinessEvent businessEvent;
    businessEvent.SetBusinessKey("businessKey");
    int32_t result = BusinessEventManager::GetInstance().GetBusinessEvent(businessEvent);
    EXPECT_EQ(result, DP_INVALID_PARAM);
}

/*
* @tc.name: GetBusinessEvent003
* @tc.desc: Init
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BusinessEventManagerTest, GetBusinessEvent003, TestSize.Level1)
{
    BusinessEvent businessEvent;
    businessEvent.SetBusinessKey("business_id_cast+_disturbance_event");
    int32_t result = BusinessEventManager::GetInstance().GetBusinessEvent(businessEvent);
    EXPECT_EQ(result, DP_SUCCESS);
}

/*
* @tc.name: UnInit001
* @tc.desc: Init
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BusinessEventManagerTest, UnInit001, TestSize.Level1)
{
    int32_t result = BusinessEventManager::GetInstance().UnInit();
    EXPECT_EQ(result, DP_SUCCESS);
}
}  // namespace DistributedDeviceProfile
}  // namespace OHOS