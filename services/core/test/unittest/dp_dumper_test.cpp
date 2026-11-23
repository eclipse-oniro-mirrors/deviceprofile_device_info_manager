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

#include <unistd.h>

#include <memory>

#include "ipc_skeleton_mock.h"

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace testing;
using namespace testing::ext;

namespace {
constexpr uid_t UID_HIDUMPER = 1212;
constexpr uid_t UID_SYSTEM = 1000;
constexpr uid_t UID_ROOT = 0;
constexpr uid_t UID_APP = 10001;
const std::string DUMP_DENIED = "Dump failed, not allowed";
const std::string DUMP_DEFAULT_PREFIX = "DeviceProfile Dump:";
const std::string DUMP_HELP_PREFIX = "DeviceProfile Dump options:";
const std::string DUMP_HELP_ITEM = "[-h] [cmd]...";
const std::string DUMP_ILLEGAL = "The arguments are illegal";
} // namespace

class DpDumperTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    std::shared_ptr<IPCSkeletonMock> skeleton_ = nullptr;
};

void DpDumperTest::SetUpTestCase()
{
}

void DpDumperTest::TearDownTestCase()
{
}

void DpDumperTest::SetUp()
{
    skeleton_ = std::static_pointer_cast<IPCSkeletonMock>(IPCSkeletonInterface::GetOrCreateIPCSkeleton());
}

void DpDumperTest::TearDown()
{
    IPCSkeletonInterface::ReleaseIPCSkeleton();
    skeleton_ = nullptr;
}

HWTEST_F(DpDumperTest, Dump_001, TestSize.Level1)
{
    ASSERT_NE(skeleton_, nullptr);
    EXPECT_CALL(*skeleton_, GetCallingAppUid()).Times(1).WillOnce(Return(UID_SYSTEM));
    std::vector<std::string> args;
    std::string result;
    auto dumper = std::make_shared<DeviceProfileDumper>();
    bool ret = dumper->Dump(args, result);
    EXPECT_EQ(false, ret);
    EXPECT_EQ(DUMP_DENIED, result);
}

HWTEST_F(DpDumperTest, Dump_002, TestSize.Level1)
{
    ASSERT_NE(skeleton_, nullptr);
    EXPECT_CALL(*skeleton_, GetCallingAppUid()).Times(1).WillOnce(Return(UID_HIDUMPER));
    std::string result;
    std::vector<std::string> args;
    auto dumper = std::make_shared<DeviceProfileDumper>();
    bool ret = dumper->Dump(args, result);
    EXPECT_EQ(true, ret);
}

HWTEST_F(DpDumperTest, Dump_003, TestSize.Level1)
{
    ASSERT_NE(skeleton_, nullptr);
    EXPECT_CALL(*skeleton_, GetCallingAppUid()).Times(1).WillOnce(Return(UID_HIDUMPER));
    std::string result;
    std::vector<std::string> args;
    args.emplace_back("-h");
    auto dumper = std::make_shared<DeviceProfileDumper>();
    bool ret = dumper->Dump(args, result);
    EXPECT_EQ(true, ret);
}

HWTEST_F(DpDumperTest, Dump_004, TestSize.Level1)
{
    ASSERT_NE(skeleton_, nullptr);
    EXPECT_CALL(*skeleton_, GetCallingAppUid()).Times(1).WillOnce(Return(UID_HIDUMPER));
    std::string result;
    std::vector<std::string> args;
    args.emplace_back("-g");
    auto dumper = std::make_shared<DeviceProfileDumper>();
    bool ret = dumper->Dump(args, result);
    EXPECT_EQ(false, ret);
}

/**
 * @tc.name: Dump_005
 * @tc.desc: After uid rectification to GetCallingAppUid, non-hidumper callers are rejected and no
 *           dump content is returned.
 * @tc.type: FUNC
 */
HWTEST_F(DpDumperTest, Dump_005, TestSize.Level1)
{
    ASSERT_NE(skeleton_, nullptr);
    EXPECT_CALL(*skeleton_, GetCallingAppUid()).Times(1).WillOnce(Return(UID_SYSTEM));
    std::string result = "dirty content";
    std::vector<std::string> args;
    auto dumper = std::make_shared<DeviceProfileDumper>();
    bool ret = dumper->Dump(args, result);
    EXPECT_EQ(false, ret);
    EXPECT_EQ(DUMP_DENIED, result);
}

/**
 * @tc.name: Dump_006
 * @tc.desc: root (uid=0) is not hidumper and is not allowed to dump.
 * @tc.type: FUNC
 */
HWTEST_F(DpDumperTest, Dump_006, TestSize.Level1)
{
    ASSERT_NE(skeleton_, nullptr);
    EXPECT_CALL(*skeleton_, GetCallingAppUid()).Times(1).WillOnce(Return(UID_ROOT));
    std::string result;
    std::vector<std::string> args;
    auto dumper = std::make_shared<DeviceProfileDumper>();
    bool ret = dumper->Dump(args, result);
    EXPECT_EQ(false, ret);
    EXPECT_EQ(DUMP_DENIED, result);
}

/**
 * @tc.name: Dump_007
 * @tc.desc: A normal application with uid (10001) is not allowed to dump; its uid is not mistaken for hidumper's 1212.
 * @tc.type: FUNC
 */
HWTEST_F(DpDumperTest, Dump_007, TestSize.Level1)
{
    ASSERT_NE(skeleton_, nullptr);
    EXPECT_CALL(*skeleton_, GetCallingAppUid()).Times(1).WillOnce(Return(UID_APP));
    std::string result;
    std::vector<std::string> args;
    args.emplace_back("-h");
    auto dumper = std::make_shared<DeviceProfileDumper>();
    bool ret = dumper->Dump(args, result);
    EXPECT_EQ(false, ret);
    EXPECT_EQ(DUMP_DENIED, result);
}

/**
 * @tc.name: Dump_008
 * @tc.desc: hidumper calls the default dump branch and the returned content starts with a fixed prefix.
 * @tc.type: FUNC
 */
HWTEST_F(DpDumperTest, Dump_008, TestSize.Level1)
{
    ASSERT_NE(skeleton_, nullptr);
    EXPECT_CALL(*skeleton_, GetCallingAppUid()).Times(1).WillOnce(Return(UID_HIDUMPER));
    std::string result;
    std::vector<std::string> args;
    auto dumper = std::make_shared<DeviceProfileDumper>();
    bool ret = dumper->Dump(args, result);
    EXPECT_EQ(true, ret);
    EXPECT_EQ(0, result.rfind(DUMP_DEFAULT_PREFIX, 0));
}

/**
 * @tc.name: Dump_009
 * @tc.desc: hidumper calls "-help" and the help information is returned.
 * @tc.type: FUNC
 */
HWTEST_F(DpDumperTest, Dump_009, TestSize.Level1)
{
    ASSERT_NE(skeleton_, nullptr);
    EXPECT_CALL(*skeleton_, GetCallingAppUid()).Times(1).WillOnce(Return(UID_HIDUMPER));
    std::string result;
    std::vector<std::string> args;
    args.emplace_back("-help");
    auto dumper = std::make_shared<DeviceProfileDumper>();
    bool ret = dumper->Dump(args, result);
    EXPECT_EQ(true, ret);
    EXPECT_EQ(0, result.rfind(DUMP_HELP_PREFIX, 0));
    EXPECT_NE(std::string::npos, result.find(DUMP_HELP_ITEM));
}

/**
 * @tc.name: Dump_010
 * @tc.desc: When hidumper passes an illegal argument, an illegal-argument message is returned and no
 *           help content is returned.
 * @tc.type: FUNC
 */
HWTEST_F(DpDumperTest, Dump_010, TestSize.Level1)
{
    ASSERT_NE(skeleton_, nullptr);
    EXPECT_CALL(*skeleton_, GetCallingAppUid()).Times(1).WillOnce(Return(UID_HIDUMPER));
    std::string result;
    std::vector<std::string> args;
    args.emplace_back("-invalid");
    args.emplace_back("extra");
    auto dumper = std::make_shared<DeviceProfileDumper>();
    bool ret = dumper->Dump(args, result);
    EXPECT_EQ(false, ret);
    EXPECT_NE(std::string::npos, result.find(DUMP_ILLEGAL));
    EXPECT_EQ(std::string::npos, result.find(DUMP_HELP_PREFIX));
}

/**
 * @tc.name: Dump_011
 * @tc.desc: Permission check precedes argument parsing; a non-hidumper caller cannot get help even with "-h".
 * @tc.type: FUNC
 */
HWTEST_F(DpDumperTest, Dump_011, TestSize.Level1)
{
    ASSERT_NE(skeleton_, nullptr);
    EXPECT_CALL(*skeleton_, GetCallingAppUid()).Times(1).WillOnce(Return(UID_SYSTEM));
    std::string result;
    std::vector<std::string> args;
    args.emplace_back("-h");
    auto dumper = std::make_shared<DeviceProfileDumper>();
    bool ret = dumper->Dump(args, result);
    EXPECT_EQ(false, ret);
    EXPECT_EQ(DUMP_DENIED, result);
    EXPECT_EQ(std::string::npos, result.find(DUMP_HELP_ITEM));
}

/**
 * @tc.name: Dump_012
 * @tc.desc: The Dump entry clears the caller-provided result to avoid carrying over content from the previous dump.
 * @tc.type: FUNC
 */
HWTEST_F(DpDumperTest, Dump_012, TestSize.Level1)
{
    ASSERT_NE(skeleton_, nullptr);
    EXPECT_CALL(*skeleton_, GetCallingAppUid()).Times(1).WillOnce(Return(UID_HIDUMPER));
    std::string result = "dirty content";
    std::vector<std::string> args;
    auto dumper = std::make_shared<DeviceProfileDumper>();
    bool ret = dumper->Dump(args, result);
    EXPECT_EQ(true, ret);
    EXPECT_EQ(std::string::npos, result.find("dirty content"));
}

/**
 * @tc.name: Dump_013
 * @tc.desc: When hidumper passes "-h", it is equivalent to "-help" and returns the help information.
 * @tc.type: FUNC
 */
HWTEST_F(DpDumperTest, Dump_013, TestSize.Level1)
{
    ASSERT_NE(skeleton_, nullptr);
    EXPECT_CALL(*skeleton_, GetCallingAppUid()).Times(1).WillOnce(Return(UID_HIDUMPER));
    std::string result;
    std::vector<std::string> args;
    args.emplace_back("-h");
    auto dumper = std::make_shared<DeviceProfileDumper>();
    bool ret = dumper->Dump(args, result);
    EXPECT_EQ(true, ret);
    EXPECT_EQ(0, result.rfind(DUMP_HELP_PREFIX, 0));
    EXPECT_NE(std::string::npos, result.find(DUMP_HELP_ITEM));
}

/**
 * @tc.name: Dump_014
 * @tc.desc: When hidumper passes multiple arguments ("-h extra"), it does not enter the help branch and
 *           returns an illegal-argument message.
 * @tc.type: FUNC
 */
HWTEST_F(DpDumperTest, Dump_014, TestSize.Level1)
{
    ASSERT_NE(skeleton_, nullptr);
    EXPECT_CALL(*skeleton_, GetCallingAppUid()).Times(1).WillOnce(Return(UID_HIDUMPER));
    std::string result;
    std::vector<std::string> args;
    args.emplace_back("-h");
    args.emplace_back("extra");
    auto dumper = std::make_shared<DeviceProfileDumper>();
    bool ret = dumper->Dump(args, result);
    EXPECT_EQ(false, ret);
    EXPECT_NE(std::string::npos, result.find(DUMP_ILLEGAL));
    EXPECT_EQ(std::string::npos, result.find(DUMP_HELP_PREFIX));
}

/**
 * @tc.name: Dump_015
 * @tc.desc: When hidumper passes an empty string argument, it is neither "-h" nor "-help", and an
 *           illegal-argument message is returned.
 * @tc.type: FUNC
 */
HWTEST_F(DpDumperTest, Dump_015, TestSize.Level1)
{
    ASSERT_NE(skeleton_, nullptr);
    EXPECT_CALL(*skeleton_, GetCallingAppUid()).Times(1).WillOnce(Return(UID_HIDUMPER));
    std::string result;
    std::vector<std::string> args;
    args.emplace_back("");
    auto dumper = std::make_shared<DeviceProfileDumper>();
    bool ret = dumper->Dump(args, result);
    EXPECT_EQ(false, ret);
    EXPECT_NE(std::string::npos, result.find(DUMP_ILLEGAL));
    EXPECT_EQ(std::string::npos, result.find(DUMP_HELP_PREFIX));
}

/**
 * @tc.name: Dump_016
 * @tc.desc: When hidumper passes "-H" with the wrong case, it does not match "-h", and an illegal-argument
 *           message is returned.
 * @tc.type: FUNC
 */
HWTEST_F(DpDumperTest, Dump_016, TestSize.Level1)
{
    ASSERT_NE(skeleton_, nullptr);
    EXPECT_CALL(*skeleton_, GetCallingAppUid()).Times(1).WillOnce(Return(UID_HIDUMPER));
    std::string result;
    std::vector<std::string> args;
    args.emplace_back("-H");
    auto dumper = std::make_shared<DeviceProfileDumper>();
    bool ret = dumper->Dump(args, result);
    EXPECT_EQ(false, ret);
    EXPECT_NE(std::string::npos, result.find(DUMP_ILLEGAL));
    EXPECT_EQ(std::string::npos, result.find(DUMP_HELP_PREFIX));
}
}
}
