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

#include <string>
#include <vector>
#include "gtest/gtest.h"
#include "event_handler_factory.h"
#include "distributed_device_profile_constants.h"

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace testing::ext;
using namespace std;

class EventHandlerFactoryTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void EventHandlerFactoryTest::SetUpTestCase(void) {
}

void EventHandlerFactoryTest::TearDownTestCase(void) {
}

void EventHandlerFactoryTest::SetUp() {
}

void EventHandlerFactoryTest::TearDown() {
}

/**
 * @tc.name: CreateEventHandler001
 * @tc.desc: CreateEventHandler succeed and failed, handlerName is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventHandlerFactoryTest, CreateEventHandler001, TestSize.Level1)
{
    auto eventHandler = EventHandlerFactory::GetInstance().GetEventHandler();
    EXPECT_EQ(nullptr, eventHandler);
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
