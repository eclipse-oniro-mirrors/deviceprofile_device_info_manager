/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "parameter.h"
#include "content_sensor_manager_utils.h"


using namespace testing::ext;
namespace OHOS {
namespace DistributedDeviceProfile {
using namespace std;
namespace {
    const std::string TAG = "ContentSensorManagerUtilsTest";
}
class ContentSensorManagerUtilsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ContentSensorManagerUtilsTest::SetUpTestCase()
{
}

void ContentSensorManagerUtilsTest::TearDownTestCase()
{
}

void ContentSensorManagerUtilsTest::SetUp()
{
}

void ContentSensorManagerUtilsTest::TearDown()
{
}

/*
 * @tc.name: ObtainProductModel001
 * @tc.desc: ObtainProductModel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ContentSensorManagerUtilsTest, ObtainProductModel001, TestSize.Level1)
{
    std::string str = "123456";
    DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().deviceModel_ = str;
    std::string result = DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().ObtainProductModel();
    EXPECT_EQ(result, str);
}

/*
 * @tc.name: ObtainDeviceType001
 * @tc.desc: ObtainDeviceType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ContentSensorManagerUtilsTest, ObtainDeviceType001, TestSize.Level1)
{
    std::string str = "123456";
    DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().deviceType_ = str;
    std::string result = DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().ObtainDeviceType();
    EXPECT_EQ(result, str);
}

/*
 * @tc.name: ObtainManufacture001
 * @tc.desc: ObtainManufacture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ContentSensorManagerUtilsTest, ObtainManufacture001, TestSize.Level1)
{
    std::string str = "123456";
    DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().manufacture_ = str;
    std::string result = DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().ObtainManufacture();
    EXPECT_EQ(result, str);
}

/*
 * @tc.name: ObtainSerial001
 * @tc.desc: ObtainSerial
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ContentSensorManagerUtilsTest, ObtainSerial001, TestSize.Level1)
{
    std::string str = "123456";
    DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().serial_ = str;
    std::string result = DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().ObtainSerial();
    EXPECT_EQ(result, str);
}


/*
 * @tc.name: ObtainMarketName001
 * @tc.desc: ObtainMarketName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ContentSensorManagerUtilsTest, ObtainMarketName001, TestSize.Level1)
{
    std::string str = "123456";
    DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().serial_ = str;
    std::string result = DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().ObtainMarketName();
    EXPECT_NE(result, str);
}

/*
 * @tc.name: ObtainOsFullName001
 * @tc.desc: ObtainOsFullName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ContentSensorManagerUtilsTest, ObtainOsFullName001, TestSize.Level1)
{
    std::string str = "123456";
    DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().osFullName_ = str;
    std::string result = DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().ObtainOsFullName();
    EXPECT_EQ(result, str);
}

/*
 * @tc.name: ObtainDisplayVersion001
 * @tc.desc: ObtainDisplayVersion
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ContentSensorManagerUtilsTest, ObtainDisplayVersion001, TestSize.Level1)
{
    std::string str = "123456";
    DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().displayVersion_ = str;
    std::string result = DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().ObtainDisplayVersion();
    EXPECT_EQ(result, str);
}

/*
 * @tc.name: ObtainLocalUdid001
 * @tc.desc: ObtainLocalUdid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ContentSensorManagerUtilsTest, ObtainLocalUdid001, TestSize.Level1)
{
    std::string str = "123456";
    DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().localUdid_ = str;
    std::string result = DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().ObtainLocalUdid();
    EXPECT_EQ(result, str);
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
