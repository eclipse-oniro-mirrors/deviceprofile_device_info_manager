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
#define private public
#define protected public

#include "kv_store_death_recipient.h"

#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace DistributedDeviceProfile {
using namespace std;
namespace {
    const std::string TAG = "KvStoreDeathRecipientTest";
}
class KvStoreDeathRecipientTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void KvStoreDeathRecipientTest::SetUpTestCase()
{
}

void KvStoreDeathRecipientTest::TearDownTestCase()
{
}

void KvStoreDeathRecipientTest::SetUp()
{
}

void KvStoreDeathRecipientTest::TearDown()
{
}

/*
 * @tc.name: OnRemoteDied001
 * @tc.desc: OnRemoteDied
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KvStoreDeathRecipientTest, OnRemoteDied001, TestSize.Level1)
{
    std::shared_ptr<KvDeathRecipient> KvDeathRecipient_;
    KvDeathRecipient_->OnRemoteDied();
}
}
}
