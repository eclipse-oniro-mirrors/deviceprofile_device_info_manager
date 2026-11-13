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

#include "query_profile.h"

#include <limits>
#include <memory>

#include "cJSON.h"
#include "gtest/gtest.h"
#include "profile_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace testing::ext;
namespace {
constexpr int32_t UNSET_ID = -1;
constexpr int32_t ACCESSER_USER = 100;
constexpr int32_t ACCESSEE_USER = 101;
constexpr int64_t ACCESSER_TOKEN = std::numeric_limits<int64_t>::max();
constexpr int64_t ACCESSEE_TOKEN = std::numeric_limits<int64_t>::min();
}  // namespace

class QueryProfileFileTest : public testing::Test {};

/**
 * @tc.name: DefaultFieldsAreUnset_001
 * @tc.desc: Verify that default fields are unset.
 * @tc.type: FUNC
 */
HWTEST_F(QueryProfileFileTest, DefaultFieldsAreUnset_001, TestSize.Level1)
{
    QueryProfile profile;
    EXPECT_TRUE(profile.GetAccesserDeviceId().empty());
    EXPECT_TRUE(profile.GetAccesserAccountId().empty());
    EXPECT_TRUE(profile.GetAccesseeDeviceId().empty());
    EXPECT_TRUE(profile.GetAccesseeAccountId().empty());
    EXPECT_EQ(profile.GetAccesserUserId(), UNSET_ID);
    EXPECT_EQ(profile.GetAccesseeUserId(), UNSET_ID);
    EXPECT_EQ(profile.GetAccesserTokenId(), UNSET_ID);
    EXPECT_EQ(profile.GetAccesseeTokenId(), UNSET_ID);
}

/**
 * @tc.name: ParcelRoundTripPreservesBothSidesAndWideTokens_001
 * @tc.desc: Verify that parcel round trip preserves both sides and wide tokens.
 * @tc.type: FUNC
 */
HWTEST_F(QueryProfileFileTest, ParcelRoundTripPreservesBothSidesAndWideTokens_001, TestSize.Level1)
{
    QueryProfile input;
    input.SetAccesserDeviceId("synthetic-accesser-device");
    input.SetAccesserAccountId("synthetic-accesser-account");
    input.SetAccesserUserId(ACCESSER_USER);
    input.SetAccesserTokenId(ACCESSER_TOKEN);
    input.SetAccesseeDeviceId("synthetic-accessee-device");
    input.SetAccesseeAccountId("synthetic-accessee-account");
    input.SetAccesseeUserId(ACCESSEE_USER);
    input.SetAccesseeTokenId(ACCESSEE_TOKEN);
    MessageParcel parcel;
    ASSERT_TRUE(input.Marshalling(parcel));
    QueryProfile output;
    ASSERT_TRUE(output.UnMarshalling(parcel));
    EXPECT_EQ(output.GetAccesserDeviceId(), input.GetAccesserDeviceId());
    EXPECT_EQ(output.GetAccesserAccountId(), input.GetAccesserAccountId());
    EXPECT_EQ(output.GetAccesserUserId(), ACCESSER_USER);
    EXPECT_EQ(output.GetAccesserTokenId(), ACCESSER_TOKEN);
    EXPECT_EQ(output.GetAccesseeDeviceId(), input.GetAccesseeDeviceId());
    EXPECT_EQ(output.GetAccesseeAccountId(), input.GetAccesseeAccountId());
    EXPECT_EQ(output.GetAccesseeUserId(), ACCESSEE_USER);
    EXPECT_EQ(output.GetAccesseeTokenId(), ACCESSEE_TOKEN);
}

/**
 * @tc.name: DefaultProfileCanRoundTrip_001
 * @tc.desc: Verify that default profile can round trip.
 * @tc.type: FUNC
 */
HWTEST_F(QueryProfileFileTest, DefaultProfileCanRoundTrip_001, TestSize.Level1)
{
    QueryProfile input;
    MessageParcel parcel;
    ASSERT_TRUE(input.Marshalling(parcel));
    QueryProfile output;
    ASSERT_TRUE(output.UnMarshalling(parcel));
    EXPECT_EQ(output.GetAccesserTokenId(), UNSET_ID);
    EXPECT_EQ(output.GetAccesseeUserId(), UNSET_ID);
    EXPECT_TRUE(output.GetAccesserDeviceId().empty());
    EXPECT_TRUE(output.GetAccesseeAccountId().empty());
}

/**
 * @tc.name: EmptyParcelIsRejected_002
 * @tc.desc: Verify that empty parcel is rejected.
 * @tc.type: FUNC
 */
HWTEST_F(QueryProfileFileTest, EmptyParcelIsRejected_002, TestSize.Level1)
{
    QueryProfile profile;
    profile.SetAccesserUserId(ACCESSER_USER);
    MessageParcel parcel;
    EXPECT_FALSE(profile.UnMarshalling(parcel));
    EXPECT_EQ(profile.GetAccesserUserId(), ACCESSER_USER);
}

/**
 * @tc.name: ParcelMissingFinalTokenIsRejected_002
 * @tc.desc: Verify that parcel missing final token is rejected.
 * @tc.type: FUNC
 */
HWTEST_F(QueryProfileFileTest, ParcelMissingFinalTokenIsRejected_002, TestSize.Level1)
{
    MessageParcel parcel;
    ASSERT_TRUE(parcel.WriteString("accesser"));
    ASSERT_TRUE(parcel.WriteInt32(ACCESSER_USER));
    ASSERT_TRUE(parcel.WriteString("account-a"));
    ASSERT_TRUE(parcel.WriteInt64(ACCESSER_TOKEN));
    ASSERT_TRUE(parcel.WriteString("accessee"));
    ASSERT_TRUE(parcel.WriteInt32(ACCESSEE_USER));
    ASSERT_TRUE(parcel.WriteString("account-b"));
    QueryProfile profile;
    EXPECT_FALSE(profile.UnMarshalling(parcel));
    EXPECT_EQ(profile.GetAccesseeTokenId(), UNSET_ID);
}

/**
 * @tc.name: DumpAnonymizesDeviceAndAccountIdentifiers_001
 * @tc.desc: Verify that dump anonymizes device and account identifiers.
 * @tc.type: FUNC
 */
HWTEST_F(QueryProfileFileTest, DumpAnonymizesDeviceAndAccountIdentifiers_001, TestSize.Level1)
{
    QueryProfile profile;
    const std::string deviceId = "synthetic-device-123456789";
    const std::string accountId = "synthetic-account-987654321";
    profile.SetAccesserDeviceId(deviceId);
    profile.SetAccesseeAccountId(accountId);
    const std::string dump = profile.dump();
    std::unique_ptr<cJSON, decltype(&cJSON_Delete)> json(cJSON_Parse(dump.c_str()), cJSON_Delete);
    ASSERT_NE(json, nullptr);
    const cJSON *device = cJSON_GetObjectItemCaseSensitive(json.get(), "accesserDeviceId");
    const cJSON *account = cJSON_GetObjectItemCaseSensitive(json.get(), "accesseeAccountId");
    ASSERT_NE(device, nullptr);
    ASSERT_TRUE(cJSON_IsString(device));
    ASSERT_NE(account, nullptr);
    ASSERT_TRUE(cJSON_IsString(account));
    EXPECT_STREQ(device->valuestring, ProfileUtils::GetAnonyString(deviceId).c_str());
    EXPECT_STREQ(account->valuestring, ProfileUtils::GetAnonyString(accountId).c_str());
    EXPECT_EQ(dump.find(deviceId), std::string::npos);
    EXPECT_EQ(dump.find(accountId), std::string::npos);
}
}  // namespace DistributedDeviceProfile
}  // namespace OHOS
