/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include <memory>

#define private public
#define protected public
#include "device_profile_dumper.h"
#undef private
#undef protected
#include "utils.h"

namespace OHOS {
namespace DeviceProfile {
using namespace testing;
using namespace testing::ext;

class DeviceProfileDFXTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};


void DeviceProfileDFXTest::SetUpTestCase()
{
    DTEST_LOG << "SetUpTestCase" << std::endl;
}

void DeviceProfileDFXTest::TearDownTestCase()
{
    DTEST_LOG << "TearDownTestCase" << std::endl;
}

void DeviceProfileDFXTest::SetUp()
{
    DTEST_LOG << "SetUp" << std::endl;
}

void DeviceProfileDFXTest::TearDown()
{
    DTEST_LOG << "TearDown" << std::endl;
}

/**
 * @tc.name: DumpDefault_001
 * @tc.desc: dfx dump default
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(DeviceProfileDFXTest, DumpDefault_001, TestSize.Level3)
{
    auto dumper = std::make_shared<DeviceProfileDumper>();
    std::string msg;
    dumper->ShowHelp(msg);
    dumper->IllegalInput(msg);
    auto result = dumper->DumpDefault(msg);
    EXPECT_EQ(true, result);
}

/**
 * @tc.name: CanDump_002
 * @tc.desc: CanDump
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(DeviceProfileDFXTest, CanDump_002, TestSize.Level3)
{
    auto dumper = std::make_shared<DeviceProfileDumper>();
    auto result = dumper->CanDump();
    EXPECT_EQ(false, result);
}

/**
 * @tc.name: Dump_002
 * @tc.desc: Dump
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(DeviceProfileDFXTest, Dump_003, TestSize.Level3)
{
    auto dumper = std::make_shared<DeviceProfileDumper>();
    std::string msg;
    const std::vector<std::string> args;
    auto result = dumper->Dump(args, msg);
    EXPECT_EQ(false, result);
}
}
}