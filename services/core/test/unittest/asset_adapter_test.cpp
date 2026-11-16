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

#include "asset_adapter.h"

#include "distributed_device_profile_errors.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace {
class AssetApiMock {
public:
    MOCK_METHOD(int32_t, Add, (const AssetAttr *, uint32_t));
    MOCK_METHOD(int32_t, Update, (const AssetAttr *, uint32_t, const AssetAttr *, uint32_t));
    MOCK_METHOD(int32_t, Query, (const AssetAttr *, uint32_t, AssetResultSet *));
    MOCK_METHOD(int32_t, Remove, (const AssetAttr *, uint32_t));
    MOCK_METHOD(AssetAttr *, Parse, (const AssetResult *, AssetTag));
    MOCK_METHOD(void, Free, (AssetResultSet *));
};
AssetApiMock *g_assetApi = nullptr;
constexpr uint32_t ATTRIBUTE_COUNT = 1;
}  // namespace

// The real adapter is compiled into this test. Only its external C API is replaced.
extern "C" int32_t AssetAdd(const AssetAttr *attributes, uint32_t count)
{
    if (g_assetApi == nullptr) {
        ADD_FAILURE() << "Asset API mock is not installed";
        return SEC_ASSET_INVALID_ARGUMENT;
    }
    return g_assetApi->Add(attributes, count);
}
extern "C" int32_t AssetUpdate(const AssetAttr *query, uint32_t queryCount, const AssetAttr *attributes, uint32_t count)
{
    if (g_assetApi == nullptr) {
        ADD_FAILURE() << "Asset API mock is not installed";
        return SEC_ASSET_INVALID_ARGUMENT;
    }
    return g_assetApi->Update(query, queryCount, attributes, count);
}
extern "C" int32_t AssetQuery(const AssetAttr *query, uint32_t count, AssetResultSet *result)
{
    if (g_assetApi == nullptr) {
        ADD_FAILURE() << "Asset API mock is not installed";
        return SEC_ASSET_INVALID_ARGUMENT;
    }
    return g_assetApi->Query(query, count, result);
}
extern "C" int32_t AssetRemove(const AssetAttr *query, uint32_t count)
{
    if (g_assetApi == nullptr) {
        ADD_FAILURE() << "Asset API mock is not installed";
        return SEC_ASSET_INVALID_ARGUMENT;
    }
    return g_assetApi->Remove(query, count);
}
extern "C" AssetAttr *AssetParseAttr(const AssetResult *result, AssetTag tag)
{
    if (g_assetApi == nullptr) {
        ADD_FAILURE() << "Asset API mock is not installed";
        return nullptr;
    }
    return g_assetApi->Parse(result, tag);
}
extern "C" void AssetFreeResultSet(AssetResultSet *result)
{
    if (g_assetApi == nullptr) {
        ADD_FAILURE() << "Asset API mock is not installed";
        return;
    }
    g_assetApi->Free(result);
}

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace testing;
using namespace testing::ext;
class AssetAdapterFileTest : public testing::Test {
public:
    void SetUp() override
    {
        g_assetApi = &mock_;
    }
    void TearDown() override
    {
        g_assetApi = nullptr;
    }

protected:
    StrictMock<AssetApiMock> mock_;
    AssetAttr attribute_{};
    AssetResultSet result_{};
};

/**
 * @tc.name: PutForwardsAttributesAndMapsSuccess_001
 * @tc.desc: Verify that put forwards attributes and maps success.
 * @tc.type: FUNC
 */
HWTEST_F(AssetAdapterFileTest, PutForwardsAttributesAndMapsSuccess_001, TestSize.Level1)
{
    EXPECT_CALL(mock_, Add(&attribute_, ATTRIBUTE_COUNT)).WillOnce(Return(SEC_ASSET_SUCCESS));
    EXPECT_EQ(AssetAdapter::GetInstance().PutAsset(&attribute_, ATTRIBUTE_COUNT), DP_SUCCESS);
}

/**
 * @tc.name: PutDistinguishesDuplicateFromOtherErrors_002
 * @tc.desc: Verify that put distinguishes duplicate from other errors.
 * @tc.type: FUNC
 */
HWTEST_F(AssetAdapterFileTest, PutDistinguishesDuplicateFromOtherErrors_002, TestSize.Level1)
{
    EXPECT_CALL(mock_, Add(&attribute_, ATTRIBUTE_COUNT))
        .WillOnce(Return(SEC_ASSET_DUPLICATED))
        .WillOnce(Return(SEC_ASSET_INVALID_ARGUMENT));
    EXPECT_EQ(AssetAdapter::GetInstance().PutAsset(&attribute_, ATTRIBUTE_COUNT), DP_ASSET_DUPLICATED);
    EXPECT_EQ(AssetAdapter::GetInstance().PutAsset(&attribute_, ATTRIBUTE_COUNT), DP_PUT_ASSET_ERROR);
}

/**
 * @tc.name: UpdateForwardsQueryAndNewAttributes_001
 * @tc.desc: Verify that update forwards query and new attributes.
 * @tc.type: FUNC
 */
HWTEST_F(AssetAdapterFileTest, UpdateForwardsQueryAndNewAttributes_001, TestSize.Level1)
{
    AssetAttr replacement{};
    EXPECT_CALL(mock_, Update(&attribute_, ATTRIBUTE_COUNT, &replacement, ATTRIBUTE_COUNT))
        .WillOnce(Return(SEC_ASSET_SUCCESS));
    EXPECT_EQ(AssetAdapter::GetInstance().UpdateAsset(&attribute_, ATTRIBUTE_COUNT, &replacement, ATTRIBUTE_COUNT),
              DP_SUCCESS);
}

/**
 * @tc.name: UpdateDistinguishesMissingAssetAndFailure_002
 * @tc.desc: Verify that update distinguishes missing asset and failure.
 * @tc.type: FUNC
 */
HWTEST_F(AssetAdapterFileTest, UpdateDistinguishesMissingAssetAndFailure_002, TestSize.Level1)
{
    EXPECT_CALL(mock_, Update(&attribute_, ATTRIBUTE_COUNT, &attribute_, ATTRIBUTE_COUNT))
        .WillOnce(Return(SEC_ASSET_NOT_FOUND))
        .WillOnce(Return(SEC_ASSET_INVALID_ARGUMENT));
    EXPECT_EQ(AssetAdapter::GetInstance().UpdateAsset(&attribute_, ATTRIBUTE_COUNT, &attribute_, ATTRIBUTE_COUNT),
              DP_GET_ASSET_NOT_FIND);
    EXPECT_EQ(AssetAdapter::GetInstance().UpdateAsset(&attribute_, ATTRIBUTE_COUNT, &attribute_, ATTRIBUTE_COUNT),
              DP_UPDATE_ASSET_ERROR);
}

/**
 * @tc.name: SuccessfulQueryRetainsResultUntilExplicitFree_001
 * @tc.desc: Verify that successful query retains result until explicit free.
 * @tc.type: FUNC
 */
HWTEST_F(AssetAdapterFileTest, SuccessfulQueryRetainsResultUntilExplicitFree_001, TestSize.Level1)
{
    InSequence order;
    EXPECT_CALL(mock_, Query(&attribute_, ATTRIBUTE_COUNT, &result_)).WillOnce(Return(SEC_ASSET_SUCCESS));
    EXPECT_CALL(mock_, Free(&result_)).Times(1);
    EXPECT_EQ(AssetAdapter::GetInstance().GetAsset(&attribute_, ATTRIBUTE_COUNT, &result_), DP_SUCCESS);
    AssetAdapter::GetInstance().FreeResultSet(&result_);
}

/**
 * @tc.name: MissingAssetDoesNotFreeAnUnallocatedResult_002
 * @tc.desc: Verify that missing asset does not free an unallocated result.
 * @tc.type: FUNC
 */
HWTEST_F(AssetAdapterFileTest, MissingAssetDoesNotFreeAnUnallocatedResult_002, TestSize.Level1)
{
    EXPECT_CALL(mock_, Query(&attribute_, ATTRIBUTE_COUNT, &result_)).WillOnce(Return(SEC_ASSET_NOT_FOUND));
    EXPECT_CALL(mock_, Free(_)).Times(0);
    EXPECT_EQ(AssetAdapter::GetInstance().GetAsset(&attribute_, ATTRIBUTE_COUNT, &result_), DP_GET_ASSET_NOT_FIND);
}

/**
 * @tc.name: FailedQueryFreesResultExactlyOnce_002
 * @tc.desc: Verify that failed query frees result exactly once.
 * @tc.type: FUNC
 */
HWTEST_F(AssetAdapterFileTest, FailedQueryFreesResultExactlyOnce_002, TestSize.Level1)
{
    InSequence order;
    EXPECT_CALL(mock_, Query(&attribute_, ATTRIBUTE_COUNT, &result_)).WillOnce(Return(SEC_ASSET_INVALID_ARGUMENT));
    EXPECT_CALL(mock_, Free(&result_)).Times(1);
    EXPECT_EQ(AssetAdapter::GetInstance().GetAsset(&attribute_, ATTRIBUTE_COUNT, &result_), DP_GET_ASSET_ERROE);
}

/**
 * @tc.name: DeleteMapsBackendResult_002
 * @tc.desc: Verify that delete maps backend result.
 * @tc.type: FUNC
 */
HWTEST_F(AssetAdapterFileTest, DeleteMapsBackendResult_002, TestSize.Level1)
{
    EXPECT_CALL(mock_, Remove(&attribute_, ATTRIBUTE_COUNT))
        .WillOnce(Return(SEC_ASSET_SUCCESS))
        .WillOnce(Return(SEC_ASSET_NOT_FOUND));
    EXPECT_EQ(AssetAdapter::GetInstance().DeleteAsset(&attribute_, ATTRIBUTE_COUNT), DP_SUCCESS);
    EXPECT_EQ(AssetAdapter::GetInstance().DeleteAsset(&attribute_, ATTRIBUTE_COUNT), DP_DELETE_ASSET_ERROR);
}

/**
 * @tc.name: ParseReturnsTheBackendAttributeWithoutCopying_001
 * @tc.desc: Verify that parse returns the backend attribute without copying.
 * @tc.type: FUNC
 */
HWTEST_F(AssetAdapterFileTest, ParseReturnsTheBackendAttributeWithoutCopying_001, TestSize.Level1)
{
    AssetResult result{};
    EXPECT_CALL(mock_, Parse(&result, SEC_ASSET_TAG_ALIAS)).WillOnce(Return(&attribute_));
    EXPECT_EQ(AssetAdapter::GetInstance().ParseAttr(&result, SEC_ASSET_TAG_ALIAS), &attribute_);
}

/**
 * @tc.name: ParsePropagatesMissingAttribute_002
 * @tc.desc: Verify that parse propagates missing attribute.
 * @tc.type: FUNC
 */
HWTEST_F(AssetAdapterFileTest, ParsePropagatesMissingAttribute_002, TestSize.Level1)
{
    AssetResult result{};
    EXPECT_CALL(mock_, Parse(&result, SEC_ASSET_TAG_ALIAS)).WillOnce(Return(nullptr));
    EXPECT_EQ(AssetAdapter::GetInstance().ParseAttr(&result, SEC_ASSET_TAG_ALIAS), nullptr);
}
}  // namespace DistributedDeviceProfile
}  // namespace OHOS
