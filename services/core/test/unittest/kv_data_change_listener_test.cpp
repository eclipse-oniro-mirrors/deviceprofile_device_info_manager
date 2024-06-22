/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#include "kvstore_observer.h"
#define private public
#define protected public

#include "kv_data_change_listener.h"

#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace DistributedDeviceProfile {
using namespace std;
namespace {
    const std::string TAG = "KvDataChangeListenerTest";
}
class KvDataChangeListenerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void KvDataChangeListenerTest::SetUpTestCase()
{
}

void KvDataChangeListenerTest::TearDownTestCase()
{
}

void KvDataChangeListenerTest::SetUp()
{
}

void KvDataChangeListenerTest::TearDown()
{
}

/*
 * @tc.name: OnChange001
 * @tc.desc: OnChange
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KvDataChangeListenerTest, OnChange001, TestSize.Level1)
{
    std::vector<DistributedKv::Entry> insertEntries, UpdateEntries, deleteEntries;
    std::string deviceId;
    bool isClear = true;
    DistributedKv::ChangeNotification changeNotification_(std::move(insertEntries), std::move(insertEntries),
        std::move(insertEntries), deviceId, isClear);
    KvDataChangeListener KvDataChangeListener_;
    KvDataChangeListener_.OnChange(changeNotification_);
    EXPECT_NE("deviceId", deviceId);
}

/*
 * @tc.name: OnChange002
 * @tc.desc: OnChange
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KvDataChangeListenerTest, OnChange002, TestSize.Level1)
{
    DistributedKv::DataOrigin origin;
    origin.id = {};
    origin.store = "";
    KvDataChangeListener::Keys keys;
    keys[KvDataChangeListener::OP_INSERT] = {};
    keys[KvDataChangeListener::OP_UPDATE] = {};
    keys[KvDataChangeListener::OP_DELETE] = {};
    KvDataChangeListener KvDataChangeListener_;
    KvDataChangeListener_.OnChange(origin, std::move(keys));
    EXPECT_NE("deviceId", deviceId);
}

/*
 * @tc.name: HandleAddChange001
 * @tc.desc: HandleAddChange
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KvDataChangeListenerTest, HandleAddChange001, TestSize.Level1)
{   
    std::vector<std::string> vec;
    vec.push_back("deviceId");
    std::vector<DistributedKv::Entry> insertRecords;
    std::shared_ptr<KvDataChangeListener> KvDataChangeListener_;
    KvDataChangeListener_->HandleAddChange(insertRecords);
    EXPECT_NE(vec, insertRecords);
}

/*
 * @tc.name: HandleUpdateChange001
 * @tc.desc: HandleUpdateChange
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KvDataChangeListenerTest, HandleUpdateChange001, TestSize.Level1)
{
    std::vector<std::string> vec;
    vec.push_back("deviceId");
    std::vector<DistributedKv::Entry> updateRecords;
    std::shared_ptr<KvDataChangeListener> KvDataChangeListener_;
    KvDataChangeListener_->HandleUpdateChange(updateRecords);
    EXPECT_NE(vec, updateRecords);
}

/*
 * @tc.name: HandleDeleteChange001
 * @tc.desc: HandleDeleteChange
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KvDataChangeListenerTest, HandleDeleteChange001, TestSize.Level1)
{
    std::vector<std::string> vec;
    vec.push_back("deviceId");
    std::vector<DistributedKv::Entry> deleteRecords;
    std::shared_ptr<KvDataChangeListener> KvDataChangeListener_;
    KvDataChangeListener_->HandleDeleteChange(deleteRecords);
    EXPECT_NE(vec, deleteRecords);
}
}
}
