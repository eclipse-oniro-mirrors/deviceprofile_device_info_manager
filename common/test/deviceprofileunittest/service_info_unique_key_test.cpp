/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "service_info_unique_key.h"

#include <limits>

#include "gtest/gtest.h"

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace testing::ext;
namespace {
constexpr int32_t TEST_USER = 100;
constexpr int64_t LOW_SERVICE = 1;
constexpr int64_t HIGH_SERVICE = std::numeric_limits<int64_t>::max();
}  // namespace

class ServiceInfoUniqueKeyFileTest : public testing::Test {};

/**
 * @tc.name: DefaultsAndBundleConstructor_001
 * @tc.desc: Verify that defaults and bundle constructor.
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoUniqueKeyFileTest, DefaultsAndBundleConstructor_001, TestSize.Level1)
{
    ServiceInfoUniqueKey empty;
    EXPECT_EQ(empty.GetUserId(), DEFAULT_USER_ID);
    EXPECT_EQ(empty.GetServiceId(), DEFAULT_SERVICE_ID);
    EXPECT_TRUE(empty.GetDeviceId().empty());
    EXPECT_TRUE(empty.GetTokenId().empty());
    EXPECT_TRUE(empty.GetBundleName().empty());
    ServiceInfoUniqueKey key("synthetic-device", TEST_USER, "test.bundle");
    EXPECT_EQ(key.GetDeviceId(), "synthetic-device");
    EXPECT_EQ(key.GetUserId(), TEST_USER);
    EXPECT_EQ(key.GetBundleName(), "test.bundle");
    EXPECT_EQ(key.GetServiceId(), DEFAULT_SERVICE_ID);
}

/**
 * @tc.name: ParcelPreservesEveryField_001
 * @tc.desc: Verify that parcel preserves every field.
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoUniqueKeyFileTest, ParcelPreservesEveryField_001, TestSize.Level1)
{
    ServiceInfoUniqueKey input("synthetic-device", TEST_USER, "test-token", HIGH_SERVICE);
    input.SetBundleName("test.bundle");
    MessageParcel parcel;
    ASSERT_TRUE(input.Marshalling(parcel));
    ServiceInfoUniqueKey output;
    ASSERT_TRUE(output.UnMarshalling(parcel));
    EXPECT_EQ(output.GetDeviceId(), input.GetDeviceId());
    EXPECT_EQ(output.GetUserId(), TEST_USER);
    EXPECT_EQ(output.GetTokenId(), "test-token");
    EXPECT_EQ(output.GetServiceId(), HIGH_SERVICE);
    EXPECT_EQ(output.GetBundleName(), "test.bundle");
}

/**
 * @tc.name: SettersReplacePreviousFields_001
 * @tc.desc: Verify that setters replace previous fields.
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoUniqueKeyFileTest, SettersReplacePreviousFields_001, TestSize.Level1)
{
    ServiceInfoUniqueKey key("old-device", TEST_USER, "old-token", LOW_SERVICE);
    key.SetDeviceId("new-device");
    key.SetUserId(DEFAULT_USER_ID);
    key.SetTokenId("new-token");
    key.SetServiceId(HIGH_SERVICE);
    key.SetBundleName("new.bundle");
    EXPECT_EQ(key.GetDeviceId(), "new-device");
    EXPECT_EQ(key.GetUserId(), DEFAULT_USER_ID);
    EXPECT_EQ(key.GetTokenId(), "new-token");
    EXPECT_EQ(key.GetServiceId(), HIGH_SERVICE);
    EXPECT_EQ(key.GetBundleName(), "new.bundle");
}

/**
 * @tc.name: OrderingUsesServiceIdOnly_001
 * @tc.desc: Verify that ordering uses service id only.
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoUniqueKeyFileTest, OrderingUsesServiceIdOnly_001, TestSize.Level1)
{
    ServiceInfoUniqueKey low("device-a", TEST_USER, "token-a", LOW_SERVICE);
    ServiceInfoUniqueKey high("device-b", TEST_USER, "token-b", HIGH_SERVICE);
    ServiceInfoUniqueKey equal("device-c", DEFAULT_USER_ID, "token-c", LOW_SERVICE);
    EXPECT_TRUE(low < high);
    EXPECT_FALSE(high < low);
    EXPECT_FALSE(low < equal);
    EXPECT_FALSE(equal < low);
    EXPECT_FALSE(low < low);
}

/**
 * @tc.name: EmptyAndTruncatedParcelsAreRejected_003
 * @tc.desc: Verify that empty and truncated parcels are rejected.
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoUniqueKeyFileTest, EmptyAndTruncatedParcelsAreRejected_003, TestSize.Level1)
{
    ServiceInfoUniqueKey key;
    MessageParcel empty;
    EXPECT_FALSE(key.UnMarshalling(empty));
    MessageParcel truncated;
    ASSERT_TRUE(truncated.WriteString("device"));
    ASSERT_TRUE(truncated.WriteInt32(TEST_USER));
    ASSERT_TRUE(truncated.WriteString("token"));
    ASSERT_TRUE(truncated.WriteInt64(HIGH_SERVICE));
    EXPECT_FALSE(key.UnMarshalling(truncated));
    EXPECT_TRUE(key.GetBundleName().empty());
}
}  // namespace DistributedDeviceProfile
}  // namespace OHOS
