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
#include <memory>
#include "gtest/gtest.h"
#include "sync_options.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_enums.h"
#undef private
#undef protected

using namespace testing::ext;
using namespace OHOS::DistributedDeviceProfile;
using namespace std;

namespace {
    shared_ptr<SyncOptions> syncPtr = make_shared<SyncOptions>();
}

class SyncOptionsTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void SyncOptionsTest::SetUpTestCase(void) {
}

void SyncOptionsTest::TearDownTestCase(void) {
}

void SyncOptionsTest::SetUp() {
}

void SyncOptionsTest::TearDown() {
}

/**
 * @tc.name: AddGetDevice001
 * @tc.desc: AddDevice and GetDeviceList succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SyncOptionsTest, AddGetDevice001, TestSize.Level1)
{
    syncPtr->AddDevice("device1");
    syncPtr->AddDevice("device2");
    syncPtr->AddDevice("device3");
    EXPECT_EQ(3, syncPtr->GetDeviceList().size());
}

/**
 * @tc.name: SetGetSyncMode001
 * @tc.desc: SetSyncMode and GetSyncMode succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SyncOptionsTest, SetGetSyncMode001, TestSize.Level1)
{
    syncPtr->SetSyncMode(SyncMode::PULL);
    EXPECT_EQ(SyncMode::PULL, syncPtr->GetSyncMode());
}
