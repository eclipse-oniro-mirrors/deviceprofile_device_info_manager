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
#include "gtest/gtest.h"
#include "device_profile_dumper.h"
#undef private
#undef protected

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace testing;
using namespace testing::ext;

class DpDumperTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void DpDumperTest::SetUpTestCase() {
}

void DpDumperTest::TearDownTestCase() {
}

void DpDumperTest::SetUp() {
}

void DpDumperTest::TearDown() {
}

HWTEST_F(DpDumperTest, Dump_001, TestSize.Level1)
{
    std::vector<std::string> args;
    std::string result;
    auto dumper = std::make_shared<DeviceProfileDumper>();
    bool ret = dumper->Dump(args, result);
    EXPECT_EQ(false, ret);
}

HWTEST_F(DpDumperTest, Dump_002, TestSize.Level1)
{
    setuid(1212);
    std::string result;
    std::vector<std::string> args;
    auto dumper = std::make_shared<DeviceProfileDumper>();
    bool ret = dumper->Dump(args, result);
    EXPECT_EQ(true, ret);
}

HWTEST_F(DpDumperTest, Dump_003, TestSize.Level1)
{
    setuid(1212);
    std::string result;
    std::vector<std::string> args;
    args.emplace_back("-h");
    auto dumper = std::make_shared<DeviceProfileDumper>();
    bool ret = dumper->Dump(args, result);
    EXPECT_EQ(true, ret);
}

HWTEST_F(DpDumperTest, Dump_004, TestSize.Level1)
{
    setuid(1212);
    std::string result;
    std::vector<std::string> args;
    args.emplace_back("-g");
    auto dumper = std::make_shared<DeviceProfileDumper>();
    bool ret = dumper->Dump(args, result);
    EXPECT_EQ(false, ret);
}
}
}
