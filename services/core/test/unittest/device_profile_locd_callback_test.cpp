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

#include <gtest/gtest.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string>
#include <vector>
#include <iostream>

#define private public
#define protected public
#include "device_profile_load_callback.h"
#include "distributed_device_profile_log.h"
#include "distributed_device_profile_errors.h"
#undef private
#undef protected

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace testing::ext;
using namespace std;
namespace {
    const std::string TAG = "DeviceProfileLoadCallbackTest";
}
class DeviceProfileLoadCallbackTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void DeviceProfileLoadCallbackTest::SetUpTestCase()
{
}

void DeviceProfileLoadCallbackTest::TearDownTestCase()
{
}

void DeviceProfileLoadCallbackTest::SetUp()
{
}

void DeviceProfileLoadCallbackTest::TearDown()
{
}

/*
 * @tc.name: OnLoadSystemAbilitySuccess_001
 * @tc.desc: Normal testCase of OnLoadSystemAbilitySuccess for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(DeviceProfileLoadCallbackTest, OnLoadSystemAbilitySuccess_001, TestSize.Level1)
{
    int32_t systemAbilityId = 0;
    const OHOS::sptr<OHOS::IRemoteObject> remoteObject = nullptr;
    DeviceProfileLoadCallback callBack;
    EXPECT_NO_FATAL_FAILURE(callBack.OnLoadSystemAbilitySuccess(systemAbilityId, remoteObject));
}

/*
 * @tc.name: OnLoadSystemAbilityFail_001
 * @tc.desc: Normal testCase of OnLoadSystemAbilityFail for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(DeviceProfileLoadCallbackTest, OnLoadSystemAbilityFail_001, TestSize.Level1)
{
    int32_t systemAbilityId = 0;
    DeviceProfileLoadCallback callBack;
    callBack.OnLoadSystemAbilityFail(systemAbilityId);
    EXPECT_NO_FATAL_FAILURE(callBack.OnLoadSystemAbilityFail(systemAbilityId));
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
