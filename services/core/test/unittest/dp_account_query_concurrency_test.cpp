/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <atomic>
#include <thread>
#include <vector>

#include "gtest/gtest.h"
#include "account_error_no.h"
#include "account_info.h"
#include "domain_account_common.h"
#include "dp_account_query.h"
#include "iaccount.h"
#include "ios_account.h"
#include "ipc_object_stub.h"

using namespace OHOS;
using namespace OHOS::AccountSA;
using namespace OHOS::DistributedDeviceProfile;
namespace {
constexpr int32_t TEST_USER_ID = 100;
constexpr int32_t SENTINEL_USER_ID = -1;
constexpr int32_t QUERY_THREAD_COUNT = 8;
constexpr int32_t QUERIES_PER_THREAD = 16;
constexpr int32_t REQUESTS_PER_QUERY_GROUP = 6;

class ConcurrentAccountService final : public IPCObjectStub {
public:
    explicit ConcurrentAccountService(bool failQuery) : failQuery_(failQuery) {}

    int32_t OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override
    {
        ++requests_;
        const auto token = data.ReadInterfaceToken();
        if (token == IAccount::GetDescriptor() &&
            code == static_cast<uint32_t>(IAccountIpcCode::COMMAND_GET_OS_ACCOUNT_SERVICE)) {
            return reply.WriteInt32(ERR_OK) && reply.WriteRemoteObject(this) ? ERR_OK : ERR_INVALID_DATA;
        }
        if (failQuery_) {
            return ERR_INVALID_DATA;
        }
        if (token == IAccount::GetDescriptor()) {
            return ReplyAccount(code, data, reply);
        }
        if (token == IOsAccount::GetDescriptor()) {
            return ReplyOsAccount(code, data, reply);
        }
        return ERR_INVALID_VALUE;
    }

    int32_t RequestCount() const
    {
        return requests_.load();
    }

private:
    int32_t ReplyAccount(uint32_t code, MessageParcel& data, MessageParcel& reply) const
    {
        int32_t userId = TEST_USER_ID;
        if (code == static_cast<uint32_t>(IAccountIpcCode::COMMAND_GET_OS_ACCOUNT_DISTRIBUTED_INFO)) {
            if (!data.ReadInt32(userId)) {
                return ERR_INVALID_DATA;
            }
        } else if (code != static_cast<uint32_t>(IAccountIpcCode::COMMAND_GET_OHOS_ACCOUNT_INFO)) {
            return ERR_INVALID_VALUE;
        }
        OhosAccountInfo info;
        info.uid_ = "synthetic-" + std::to_string(userId);
        return reply.WriteInt32(ERR_OK) && reply.WriteParcelable(&info) ? ERR_OK : ERR_INVALID_DATA;
    }

    int32_t ReplyOsAccount(uint32_t code, MessageParcel& data, MessageParcel& reply) const
    {
        if (code == static_cast<uint32_t>(IOsAccountIpcCode::COMMAND_GET_FOREGROUND_OS_ACCOUNT_LOCAL_ID_OUT_INT)) {
            return reply.WriteInt32(ERR_OK) && reply.WriteInt32(TEST_USER_ID) ? ERR_OK : ERR_INVALID_DATA;
        }
        if (code != static_cast<uint32_t>(IOsAccountIpcCode::COMMAND_GET_OS_ACCOUNT_DOMAIN_INFO)) {
            return ERR_INVALID_VALUE;
        }
        int32_t userId;
        if (!data.ReadInt32(userId)) {
            return ERR_INVALID_DATA;
        }
        DomainAccountInfo info;
        if (userId != TEST_USER_ID) {
            info.accountName_ = "synthetic-domain";
        }
        return reply.WriteInt32(ERR_OK) && reply.WriteParcelable(&info) ? ERR_OK : ERR_INVALID_DATA;
    }

    const bool failQuery_;
    std::atomic<int32_t> requests_ {0};
};

bool CheckQueries(const DpAccountQuery& query, int32_t userId, bool failQuery)
{
    const int32_t uidError = failQuery ? ERR_INVALID_DATA : ERR_OK;
    const int32_t osError = failQuery ? ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR : ERR_OK;
    const std::string sentinel = "synthetic-sentinel";
    std::string uid = sentinel;
    bool valid = query.GetAccountUid(userId, uid) == uidError;
    valid = (uid == (failQuery ? sentinel : "synthetic-" + std::to_string(userId))) && valid;
    uid = sentinel;
    valid = (query.GetAccountUid(uid) == uidError) && valid;
    valid = (uid == (failQuery ? sentinel : "synthetic-" + std::to_string(TEST_USER_ID))) && valid;
    int32_t foreground = SENTINEL_USER_ID;
    valid = (query.GetForegroundUserId(foreground) == osError) && valid;
    valid = (foreground == (failQuery ? SENTINEL_USER_ID : TEST_USER_ID)) && valid;
    bool enterprise = false;
    valid = (query.IsEnterpriseUser(userId, enterprise) == osError) && valid;
    return (enterprise == (!failQuery && userId != TEST_USER_ID)) && valid;
}

int32_t RunConcurrentQueries(const DpAccountQuery& query, bool failQuery)
{
    std::atomic<int32_t> failures {0};
    std::vector<std::thread> threads;
    for (int32_t n = 0; n < QUERY_THREAD_COUNT; ++n) {
        threads.emplace_back([&query, &failures, failQuery, n] {
            for (int32_t i = 0; i < QUERIES_PER_THREAD; ++i) {
                if (!CheckQueries(query, TEST_USER_ID + n, failQuery)) {
                    ++failures;
                }
            }
        });
    }
    for (auto& thread : threads) {
        thread.join();
    }
    return failures.load();
}

/**
 * @tc.name: SharedAdapterKeepsConcurrentQueryResultsSeparate
 * @tc.desc: All four query methods share one adapter and one remote without mixing replies.
 * @tc.type: FUNC
 */
TEST(DpAccountQueryConcurrencyTest, SharedAdapterKeepsConcurrentQueryResultsSeparate)
{
    sptr<ConcurrentAccountService> remote = new ConcurrentAccountService(false);
    const DpAccountQuery query(remote);
    const int32_t failures = RunConcurrentQueries(query, false);
    EXPECT_EQ(failures, 0);
    EXPECT_EQ(remote->RequestCount(), QUERY_THREAD_COUNT * QUERIES_PER_THREAD * REQUESTS_PER_QUERY_GROUP);
}

/**
 * @tc.name: SharedAdapterKeepsOutputsOnConcurrentTransportErrors
 * @tc.desc: Concurrent IPC failures preserve each caller's output and original error mapping.
 * @tc.type: FUNC
 */
TEST(DpAccountQueryConcurrencyTest, SharedAdapterKeepsOutputsOnConcurrentTransportErrors)
{
    sptr<ConcurrentAccountService> remote = new ConcurrentAccountService(true);
    const DpAccountQuery query(remote);
    const int32_t failures = RunConcurrentQueries(query, true);
    EXPECT_EQ(failures, 0);
    EXPECT_EQ(remote->RequestCount(), QUERY_THREAD_COUNT * QUERIES_PER_THREAD * REQUESTS_PER_QUERY_GROUP);
}
} // namespace
