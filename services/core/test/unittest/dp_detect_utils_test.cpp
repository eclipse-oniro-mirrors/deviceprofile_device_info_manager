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

#include "dp_detect_utils.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_log.h"
#include "distributed_device_profile_errors.h"


using namespace testing::ext;
using namespace OHOS::DistributedDeviceProfile;
using namespace std;
namespace {
    const std::string TAG = "DPDetectUtilsTest";
}
class DPDetectUtilsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void DPDetectUtilsTest::SetUpTestCase()
{
}

void DPDetectUtilsTest::TearDownTestCase()
{
}

void DPDetectUtilsTest::SetUp()
{
}

void DPDetectUtilsTest::TearDown()
{
}

/*
 * @tc.name: DetectRemoteDPVersion_001
 * @tc.desc: Normal testCase of DPDetectUtilsTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(DPDetectUtilsTest, DetectRemoteDPVersion_001, TestSize.Level1)
{
    int32_t ret = DPDetectVersion::DetectRemoteDPVersion("12345");
    EXPECT_EQ(ret, DP_CREATE_SESSION_FAILED);
    std::string peerDevId;
    ret = DPDetectVersion::DetectRemoteDPVersion(peerDevId);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}