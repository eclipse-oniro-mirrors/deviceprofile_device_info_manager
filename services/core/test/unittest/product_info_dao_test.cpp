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
 #include <string>
 #include <vector>
 #include <iostream>
 
 #include "distributed_device_profile_constants.h"
 #include "distributed_device_profile_log.h"
 #include "distributed_device_profile_errors.h"
 
 #include "product_info_dao.h"
 #include "product_info.h"
 
 using namespace testing::ext;
 namespace OHOS {
 namespace DistributedDeviceProfile {
 using namespace std;
 namespace {
 const std::string TAG = "ProductInfoDaoTest";
 }
 class ProductInfoDaoTest : public testing::Test {
 public:
     static void SetUpTestCase();
     static void TearDownTestCase();
     void SetUp();
     void TearDown();
 };
 
 void ProductInfoDaoTest::SetUpTestCase()
 {}
 
 void ProductInfoDaoTest::TearDownTestCase()
 {}
 
 void ProductInfoDaoTest::SetUp()
 {}
 
 void ProductInfoDaoTest::TearDown()
 {}
 
 /*
  * @tc.name: Init001
  * @tc.desc: Init
  * @tc.type: FUNC
  * @tc.require:
  */
 HWTEST_F(ProductInfoDaoTest, Init001, TestSize.Level1)
 {
     int32_t result = ProductInfoDao::GetInstance().Init();
     EXPECT_EQ(result, DP_SUCCESS);
 }
 
 /*
  * @tc.name: UnInit001
  * @tc.desc: UnInit
  * @tc.type: FUNC
  * @tc.require:
  */
 HWTEST_F(ProductInfoDaoTest, UnInit001, TestSize.Level1)
 {
     ProductInfoDao::GetInstance().Init();
     int32_t result = ProductInfoDao::GetInstance().UnInit();
     EXPECT_EQ(result, DP_SUCCESS);
 }
 
 /*
  * @tc.name: PutProductInfo001
  * @tc.desc: PutProductInfo
  * @tc.type: FUNC
  * @tc.require:
  */
 HWTEST_F(ProductInfoDaoTest, PutProductInfo001, TestSize.Level1)
 {
     ProductInfoDao::GetInstance().Init();
     ProductInfo productInfo;
     int32_t result = ProductInfoDao::GetInstance().PutProductInfo(productInfo);
     EXPECT_EQ(result, DP_SUCCESS);
     ProductInfoDao::GetInstance().DeleteProductInfo(productInfo);
     ProductInfoDao::GetInstance().UnInit();
 }
 
 /*
  * @tc.name: GetProductInfos001
  * @tc.desc: GetProductInfos
  * @tc.type: FUNC
  * @tc.require:
  */
 HWTEST_F(ProductInfoDaoTest, GetProductInfos001, TestSize.Level1)
 {
     ProductInfoDao::GetInstance().Init();
     std::vector<std::string> productIds;
     std::vector<ProductInfo> productInfos;
     int32_t result = ProductInfoDao::GetInstance().GetProductInfos(productIds, productInfos);
     EXPECT_EQ(result, DP_INVALID_PARAMS);
     ProductInfoDao::GetInstance().UnInit();
 }
 
 /*
  * @tc.name: GetProductInfos002
  * @tc.desc: GetProductInfos
  * @tc.type: FUNC
  * @tc.require:
  */
 HWTEST_F(ProductInfoDaoTest, GetProductInfos002, TestSize.Level1)
 {
     ProductInfoDao::GetInstance().Init();
     std::vector<std::string> productIds;
     productIds.emplace_back("11111");
     std::vector<ProductInfo> productInfos;
     ProfileDataRdbAdapter::GetInstance().store_ = nullptr;
     int32_t result = ProductInfoDao::GetInstance().GetProductInfos(productIds, productInfos);
     EXPECT_EQ(result, DP_GET_RESULTSET_FAIL);
     ProductInfoDao::GetInstance().UnInit();
 }
 
 /*
  * @tc.name: GetProductInfos003
  * @tc.desc: GetProductInfos
  * @tc.type: FUNC
  * @tc.require:
  */
 HWTEST_F(ProductInfoDaoTest, GetProductInfos003, TestSize.Level1)
 {
     ProductInfoDao::GetInstance().Init();
     ProductInfo productInfo;
     productInfo.SetProductId("11111");
     ProductInfoDao::GetInstance().PutProductInfo(productInfo);
     std::vector<std::string> productIds;
     productIds.emplace_back("11111");
     std::vector<ProductInfo> productInfos;
     int32_t result = ProductInfoDao::GetInstance().GetProductInfos(productIds, productInfos);
     EXPECT_EQ(result, DP_SUCCESS);
     ProductInfoDao::GetInstance().DeleteProductInfo(productInfo);
     ProductInfoDao::GetInstance().UnInit();
 }
 
 /*
  * @tc.name: DeleteProductInfo001
  * @tc.desc: DeleteProductInfo
  * @tc.type: FUNC
  * @tc.require:
  */
 HWTEST_F(ProductInfoDaoTest, DeleteProductInfo001, TestSize.Level1)
 {
     ProductInfoDao::GetInstance().Init();
     ProductInfo productInfo;
     productInfo.SetProductId("11111");
     ProductInfoDao::GetInstance().PutProductInfo(productInfo);
     int32_t result = ProductInfoDao::GetInstance().DeleteProductInfo(productInfo);
     EXPECT_EQ(result, DP_SUCCESS);
     ProductInfoDao::GetInstance().UnInit();
 }
 
 /*
  * @tc.name: DeleteProductInfo002
  * @tc.desc: DeleteProductInfo
  * @tc.type: FUNC
  * @tc.require:
  */
 HWTEST_F(ProductInfoDaoTest, DeleteProductInfo002, TestSize.Level1)
 {
     ProductInfoDao::GetInstance().UnInit();
     ProductInfo productInfo;
     int32_t result = ProductInfoDao::GetInstance().DeleteProductInfo(productInfo);
     EXPECT_EQ(result, DP_DEL_PRODUCT_INFO_FAIL);
     ProductInfoDao::GetInstance().UnInit();
 }
 
 /*
  * @tc.name: UpdateProductInfo001
  * @tc.desc: UpdateProductInfo
  * @tc.type: FUNC
  * @tc.require:
  */
 HWTEST_F(ProductInfoDaoTest, UpdateProductInfo001, TestSize.Level1)
 {
     ProductInfoDao::GetInstance().Init();
     ProductInfo productInfo;
     int32_t result = ProductInfoDao::GetInstance().UpdateProductInfo(productInfo);
     EXPECT_EQ(result, DP_SUCCESS);
     ProductInfoDao::GetInstance().UnInit();
 }
 
 /*
  * @tc.name: UpdateProductInfo001
  * @tc.desc: UpdateProductInfo
  * @tc.type: FUNC
  * @tc.require:
  */
 HWTEST_F(ProductInfoDaoTest, UpdateProductInfo002, TestSize.Level1)
 {
     ProductInfoDao::GetInstance().UnInit();
     ProductInfo productInfo;
     int32_t result = ProductInfoDao::GetInstance().UpdateProductInfo(productInfo);
     EXPECT_EQ(result, DP_UPDATE_PRODUCT_INFO_FAIL);
 }
 
 /*
  * @tc.name: CreateTable001
  * @tc.desc: CreateTable
  * @tc.type: FUNC
  * @tc.require:
  */
 HWTEST_F(ProductInfoDaoTest, CreateTable001, TestSize.Level1)
 {
     ProductInfoDao::GetInstance().Init();
     int32_t result = ProductInfoDao::GetInstance().CreateTable();
     EXPECT_EQ(result, DP_SUCCESS);
     ProductInfoDao::GetInstance().UnInit();
 }
 
 /*
  * @tc.name: CreateTable002
  * @tc.desc: CreateTable
  * @tc.type: FUNC
  * @tc.require:
  */
 HWTEST_F(ProductInfoDaoTest, CreateTable002, TestSize.Level1)
 {
     ProductInfoDao::GetInstance().UnInit();
     int32_t result = ProductInfoDao::GetInstance().CreateTable();
     EXPECT_EQ(result, DP_CREATE_TABLE_FAIL);
 }
 
 /*
  * @tc.name: CreateIndex001
  * @tc.desc: CreateIndex
  * @tc.type: FUNC
  * @tc.require:
  */
 HWTEST_F(ProductInfoDaoTest, CreateIndex001, TestSize.Level1)
 {
     ProductInfoDao::GetInstance().Init();
     int32_t result = ProductInfoDao::GetInstance().CreateIndex();
     EXPECT_EQ(result, DP_SUCCESS);
     ProductInfoDao::GetInstance().UnInit();
 }
 
 /*
  * @tc.name: CreateQuerySqlAndCondition001
  * @tc.desc: CreateQuerySqlAndCondition
  * @tc.type: FUNC
  * @tc.require:
  */
 HWTEST_F(ProductInfoDaoTest, CreateQuerySqlAndCondition001, TestSize.Level1)
 {
     ProductInfoDao::GetInstance().Init();
     std::vector<std::string> productIds;
     std::string sql = "";
     std::vector<ValueObject> condition;
     bool result = ProductInfoDao::GetInstance().CreateQuerySqlAndCondition(productIds, sql, condition);
     EXPECT_EQ(result, false);
     ProductInfoDao::GetInstance().UnInit();
 }
 
 /*
  * @tc.name: CreateQuerySqlAndCondition002
  * @tc.desc: CreateQuerySqlAndCondition
  * @tc.type: FUNC
  * @tc.require:
  */
 HWTEST_F(ProductInfoDaoTest, CreateQuerySqlAndCondition002, TestSize.Level1)
 {
     ProductInfoDao::GetInstance().Init();
     std::vector<std::string> productIds;
     productIds.emplace_back("11111");
     std::string sql = "";
     std::vector<ValueObject> condition;
     bool result = ProductInfoDao::GetInstance().CreateQuerySqlAndCondition(productIds, sql, condition);
     EXPECT_EQ(result, true);
     ProductInfoDao::GetInstance().UnInit();
 }
 
 /*
  * @tc.name: ProductInfoToEntries001
  * @tc.desc: ProductInfoToEntries
  * @tc.type: FUNC
  * @tc.require:
  */
 HWTEST_F(ProductInfoDaoTest, ProductInfoToEntries001, TestSize.Level1)
 {
     ProductInfoDao::GetInstance().Init();
     ProductInfo productInfo;
     ValuesBucket values;
     int32_t result = ProductInfoDao::GetInstance().ProductInfoToEntries(productInfo, values);
     EXPECT_EQ(result, DP_SUCCESS);
     ProductInfoDao::GetInstance().UnInit();
 }
 
 /*
  * @tc.name: ConvertToProductInfo001
  * @tc.desc: ProductInfoToEntries
  * @tc.type: FUNC
  * @tc.require:
  */
 HWTEST_F(ProductInfoDaoTest, ConvertToProductInfo001, TestSize.Level1)
 {
     ProductInfoDao::GetInstance().Init();
     std::shared_ptr<ResultSet> resultSet = nullptr;
     ProductInfo productInfo;
     int32_t result = ProductInfoDao::GetInstance().ConvertToProductInfo(resultSet, productInfo);
     EXPECT_EQ(result, DP_GET_RESULTSET_FAIL);
     ProductInfoDao::GetInstance().UnInit();
 }
 
 /*
  * @tc.name: ConvertToProductInfo002
  * @tc.desc: ProductInfoToEntries
  * @tc.type: FUNC
  * @tc.require:
  */
 HWTEST_F(ProductInfoDaoTest, ConvertToProductInfo002, TestSize.Level1)
 {
     ProductInfoDao::GetInstance().Init();
     std::vector<std::string> productIds;
     productIds.emplace_back("11111");
     std::string sql;
     std::vector<ValueObject> condition;
     ProductInfoDao::GetInstance().CreateQuerySqlAndCondition(productIds, sql, condition);
     std::shared_ptr<ResultSet> resultSet = ProfileDataRdbAdapter::GetInstance().Get(sql, condition);
     ProductInfo productInfo;
     int32_t result = ProductInfoDao::GetInstance().ConvertToProductInfo(resultSet, productInfo);
     EXPECT_EQ(result, DP_GET_RESULTSET_FAIL);
     ProductInfoDao::GetInstance().UnInit();
 }
 }  // namespace DistributedDeviceProfile
 }  // namespace OHOS