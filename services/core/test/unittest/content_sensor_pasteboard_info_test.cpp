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

#define private public
#define protected public

#include "pasteboard_info_collector.h"

#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace DistributedDeviceProfile {
using namespace std;
namespace {
    const std::string TAG = "ContentSensorPasteboardInfoTest";
}
class ContentSensorPasteboardInfoTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ContentSensorPasteboardInfoTest::SetUpTestCase()
{
}

void ContentSensorPasteboardInfoTest::TearDownTestCase()
{
}

void ContentSensorPasteboardInfoTest::SetUp()
{
}

void ContentSensorPasteboardInfoTest::TearDown()
{
}

/*
 * @tc.name: ConvertToProfile001
 * @tc.desc: ConvertToProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ContentSensorPasteboardInfoTest, ConvertToProfile001, TestSize.Level1)
{
    PasteboardInfoCollector pasteboardInfoCollector;
    std::vector<ServiceProfile> svrProfileList;
    bool result = pasteboardInfoCollector.ConvertToProfile(svrProfileList);
    EXPECT_EQ(result, true);
}

/*
 * @tc.name: ConvertToProfile002
 * @tc.desc: ConvertToProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ContentSensorPasteboardInfoTest, ConvertToProfile002, TestSize.Level1)
{
    PasteboardInfoCollector pasteboardInfoCollector;
    std::vector<CharacteristicProfile> charProfileList;
    bool result = pasteboardInfoCollector.ConvertToProfile(charProfileList);
    EXPECT_EQ(result, true);
}
}
}
