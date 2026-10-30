/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <functional>
#include <thread>
#include <vector>
#include "gtest/gtest.h"
#include "account_error_no.h"
#include "account_info.h"
#include "iaccount.h"
#include "domain_account_common.h"
#include "dp_account_query.h"
#include "ipc_object_stub.h"
#include "ios_account.h"

using namespace OHOS;
using namespace OHOS::AccountSA;
using namespace OHOS::DistributedDeviceProfile;
namespace {
int32_t Convert(int32_t code)
{
    if (code == ERR_INVALID_VALUE) return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    if (code == ERR_INVALID_DATA) return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    return code;
}

class ReplyService final : public IPCObjectStub {
public:
    std::function<void(MessageParcel&)> body;
    int32_t transport = ERR_OK;
    int32_t serviceResult = ERR_OK;
    uint32_t expectedCode = 0;
    int32_t expectedId = 100;
    bool expectsId = false;
    bool osQuery = false;
    bool omitStatus = false;
    bool omitHandshakeStatus = false;
    int requests = 0;
    int handshakes = 0;
    int OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override
    {
        auto token = data.ReadInterfaceToken();
        if (token == IAccount::GetDescriptor() &&
            code == static_cast<uint32_t>(IAccountIpcCode::COMMAND_GET_OS_ACCOUNT_SERVICE)) {
            EXPECT_EQ(option.GetFlags(), MessageOption::TF_IMAGE);
            ++handshakes;
            if (!omitHandshakeStatus) reply.WriteInt32(ERR_OK);
            reply.WriteRemoteObject(this);
            return ERR_OK;
        }
        ++requests;
        EXPECT_EQ(token, osQuery ? IOsAccount::GetDescriptor() : IAccount::GetDescriptor());
        EXPECT_EQ(code, expectedCode);
        EXPECT_EQ(option.GetFlags(), MessageOption::TF_SYNC);
        if (expectsId) EXPECT_EQ(data.ReadInt32(), expectedId);
        EXPECT_EQ(data.GetReadableBytes(), 0U);
        if (transport != ERR_OK) return transport;
        if (!omitStatus) reply.WriteInt32(serviceResult);
        if (body) body(reply);
        return ERR_OK;
    }
};

void CompareUid(const std::function<void(MessageParcel&)>& body, bool byUser,
    int32_t serviceResult = ERR_OK, int32_t transport = ERR_OK, int32_t id = 100)
{
    sptr<ReplyService> remote = new ReplyService;
    remote->body = body;
    remote->expectedCode = static_cast<uint32_t>(byUser ? IAccountIpcCode::COMMAND_GET_OS_ACCOUNT_DISTRIBUTED_INFO :
        IAccountIpcCode::COMMAND_GET_OHOS_ACCOUNT_INFO);
    remote->expectsId = byUser;
    remote->expectedId = id;
    remote->serviceResult = serviceResult;
    remote->transport = transport;
    OhosAccountInfo info;
    // Independent public sequenceable oracle. Private generated proxy symbols
    // are hidden; real SDK calls are compared separately on the device.
    MessageParcel oracle;
    oracle.WriteInt32(serviceResult);
    if (body) body(oracle);
    int32_t oldCode = transport != ERR_OK ? transport : oracle.ReadInt32();
    if (oldCode == ERR_OK) {
        std::unique_ptr<OhosAccountInfo> decoded(oracle.ReadParcelable<OhosAccountInfo>());
        if (decoded) {
            info = *decoded;
        } else {
            // The adapter must reject malformed replies, even though the old
            // generated proxy silently retained an empty output on this path.
            oldCode = ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
        }
    }
    std::string uid;
    DpAccountQuery candidate(remote);
    int32_t newCode = byUser ? candidate.GetAccountUid(id, uid) : candidate.GetAccountUid(uid);
    EXPECT_EQ(oldCode, newCode);
    // Identity values in this suite are synthetic, never real account information.
    EXPECT_EQ(info.uid_, uid);
    EXPECT_EQ(remote->requests, 1);
}

void CompareDomain(const std::function<void(MessageParcel&)>& body, int32_t error = ERR_OK)
{
    sptr<ReplyService> remote = new ReplyService;
    remote->body = body;
    remote->expectedCode = static_cast<uint32_t>(IOsAccountIpcCode::COMMAND_GET_OS_ACCOUNT_DOMAIN_INFO);
    remote->expectsId = true; remote->osQuery = true; remote->serviceResult = error;
    DomainAccountInfo info;
    MessageParcel oracle;
    if (body) body(oracle);
    int32_t oldCode = Convert(error);
    if (error == ERR_OK) {
        std::unique_ptr<DomainAccountInfo> decoded(oracle.ReadParcelable<DomainAccountInfo>());
        if (decoded) {
            info = *decoded;
        } else {
            oldCode = ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
        }
    }
    bool enterprise = false;
    int32_t newCode = DpAccountQuery(remote).IsEnterpriseUser(100, enterprise);
    EXPECT_EQ(oldCode, newCode);
    EXPECT_EQ(!info.accountName_.empty(), enterprise);
    EXPECT_EQ(remote->handshakes, 1);
}

TEST(DpAccountQueryTest, UidUsesOriginalSequenceableForAllFields)
{
    for (const auto& uid : {std::string(), std::string("ohosAnonymousUid"), std::string("synthetic-uid"),
        std::string("a\0b", 3), std::string("虚构用户")}) {
        for (bool byUser : {false, true}) {
            OhosAccountInfo info;
            info.name_ = "synthetic-name"; info.uid_ = uid; info.rawUid_ = "raw";
            info.nickname_ = "test"; info.avatar_ = std::string("x\0y", 3); info.scalableData_ = "{}";
            CompareUid([&info](MessageParcel& reply) { ASSERT_TRUE(reply.WriteParcelable(&info)); }, byUser);
        }
    }
}

TEST(DpAccountQueryTest, LargeAvatarRetainsOriginalLimitAndRawDataHandling)
{
    for (size_t size : {size_t(0), size_t(128 * 1024 + 1), size_t(10 * 1024 * 1024)}) {
        OhosAccountInfo info; info.uid_ = "synthetic"; info.avatar_ = std::string(size, 'x');
        CompareUid([&info](MessageParcel& reply) { ASSERT_TRUE(reply.WriteParcelable(&info)); }, true);
    }
}

TEST(DpAccountQueryTest, TruncatedUidSequenceableReturnsReadError)
{
    OhosAccountInfo info;
    info.name_ = "name"; info.uid_ = "synthetic-uid"; info.nickname_ = "nick"; info.avatar_ = "icon";
    MessageParcel full; ASSERT_TRUE(full.WriteParcelable(&info));
    const auto* bytes = reinterpret_cast<const uint8_t*>(full.GetData());
    for (size_t cut = 0; cut <= full.GetDataSize(); ++cut) {
        CompareUid([&](MessageParcel& reply) { if (cut) ASSERT_TRUE(reply.WriteBuffer(bytes, cut)); }, false);
    }
}

TEST(DpAccountQueryTest, InvalidAvatarAndNullParcelableKeepUidEmpty)
{
    CompareUid([](MessageParcel& reply) { reply.WriteInt32(0); }, false);
    for (int32_t size : {-1, 0, 10 * 1024 * 1024 + 2}) {
        CompareUid([size](MessageParcel& reply) {
            reply.WriteInt32(1); reply.WriteString16(u"name"); reply.WriteString16(u"must-not-escape");
            reply.WriteString16(u"raw"); reply.WriteInt32(0); reply.WriteString16(u"nick"); reply.WriteInt32(size);
        }, true);
    }
}

TEST(DpAccountQueryTest, AccountErrorsAndNegativeIdsMatchOriginalProxy)
{
    for (int32_t error : std::vector<int32_t>{ERR_INVALID_VALUE, ERR_INVALID_DATA, -1, 1234}) {
        CompareUid({}, false, error);
        CompareUid({}, true, ERR_OK, error, -1);
    }
}

TEST(DpAccountQueryTest, DomainFieldsMatchOriginalAndTruncationReturnsReadError)
{
    for (const auto& name : {std::string(), std::string("enterprise"), std::string("x\0y", 3)}) {
        DomainAccountInfo info;
        info.accountName_ = name; info.domain_ = "synthetic.invalid"; info.accountId_ = "test";
        CompareDomain([&info](MessageParcel& reply) { ASSERT_TRUE(reply.WriteParcelable(&info)); });
        MessageParcel full; ASSERT_TRUE(full.WriteParcelable(&info));
        const auto* bytes = reinterpret_cast<const uint8_t*>(full.GetData());
        for (size_t cut = 0; cut <= full.GetDataSize(); ++cut) {
            CompareDomain([&](MessageParcel& reply) { if (cut) ASSERT_TRUE(reply.WriteBuffer(bytes, cut)); });
        }
    }
    CompareDomain({}, ERR_INVALID_VALUE);
    CompareDomain({}, ERR_INVALID_DATA);
}

TEST(DpAccountQueryTest, ForegroundUsesOriginalReplyAndErrorConversion)
{
    for (int32_t value : {0, 100, 101, 2000000000}) {
        for (int32_t error : std::vector<int32_t>{ERR_OK, ERR_INVALID_VALUE, ERR_INVALID_DATA}) {
            sptr<ReplyService> remote = new ReplyService;
            remote->osQuery = true; remote->expectedCode = static_cast<uint32_t>(
                IOsAccountIpcCode::COMMAND_GET_FOREGROUND_OS_ACCOUNT_LOCAL_ID_OUT_INT);
            remote->body = [value](MessageParcel& reply) { reply.WriteInt32(value); };
            remote->serviceResult = error;
            int32_t oldId = -1, newId = -1;
            if (error == ERR_OK) oldId = value;
            EXPECT_EQ(Convert(error), DpAccountQuery(remote).GetForegroundUserId(newId));
            EXPECT_EQ(oldId, newId);
        }
    }
}

TEST(DpAccountQueryTest, MissingServiceAndInvalidDomainUserReturnOriginalErrors)
{
    DpAccountQuery query(nullptr); int32_t id = -1; std::string uid; bool enterprise = false;
    EXPECT_EQ(query.GetForegroundUserId(id), ERR_ACCOUNT_COMMON_GET_PROXY);
    EXPECT_EQ(query.GetAccountUid(uid), ERR_ACCOUNT_COMMON_GET_PROXY);
    EXPECT_EQ(query.GetAccountUid(100, uid), ERR_ACCOUNT_COMMON_GET_PROXY);
    EXPECT_EQ(query.IsEnterpriseUser(-1, enterprise), ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
    EXPECT_EQ(query.IsEnterpriseUser(100, enterprise), ERR_ACCOUNT_COMMON_GET_PROXY);
    EXPECT_EQ(id, -1); EXPECT_TRUE(uid.empty()); EXPECT_FALSE(enterprise);
}

TEST(DpAccountQueryTest, ConcurrentQueriesKeepEachUserSeparate)
{
    std::vector<std::thread> threads;
    for (int n = 0; n < 8; ++n) {
        threads.emplace_back([n] {
            for (int i = 0; i < 16; ++i) {
                OhosAccountInfo info; info.uid_ = "synthetic-" + std::to_string(n);
                CompareUid([&info](MessageParcel& reply) { reply.WriteParcelable(&info); }, true, ERR_OK, ERR_OK, 100 + n);
            }
        });
    }
    for (auto& thread : threads) thread.join();
}

TEST(DpAccountQueryTest, MissingStatusOrForegroundValueCannotBecomeUserZero)
{
    for (bool omitStatus : {false, true}) {
        sptr<ReplyService> remote = new ReplyService;
        remote->osQuery = true;
        remote->omitStatus = omitStatus;
        remote->expectedCode = static_cast<uint32_t>(
            IOsAccountIpcCode::COMMAND_GET_FOREGROUND_OS_ACCOUNT_LOCAL_ID_OUT_INT);
        int32_t userId = 123;
        EXPECT_EQ(DpAccountQuery(remote).GetForegroundUserId(userId), ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR);
        EXPECT_EQ(userId, 123);
    }
}

TEST(DpAccountQueryTest, MalformedIdentityRepliesDoNotOverwriteCallerOutputs)
{
    for (bool omitStatus : {false, true}) {
        sptr<ReplyService> remote = new ReplyService;
        remote->omitStatus = omitStatus;
        remote->expectedCode = static_cast<uint32_t>(IAccountIpcCode::COMMAND_GET_OHOS_ACCOUNT_INFO);
        std::string uid = "synthetic-sentinel";
        EXPECT_EQ(DpAccountQuery(remote).GetAccountUid(uid), ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR);
        EXPECT_EQ(uid, "synthetic-sentinel");
        remote->expectedCode = static_cast<uint32_t>(IOsAccountIpcCode::COMMAND_GET_OS_ACCOUNT_DOMAIN_INFO);
        remote->osQuery = true;
        remote->expectsId = true;
        bool enterprise = true;
        EXPECT_EQ(DpAccountQuery(remote).IsEnterpriseUser(100, enterprise), ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR);
        EXPECT_TRUE(enterprise);
    }
}

TEST(DpAccountQueryTest, MissingHandshakeStatusDoesNotAcceptRemote)
{
    sptr<ReplyService> remote = new ReplyService;
    remote->omitHandshakeStatus = true;
    int32_t userId = 123;
    EXPECT_EQ(DpAccountQuery(remote).GetForegroundUserId(userId), ERR_ACCOUNT_COMMON_GET_PROXY);
    EXPECT_EQ(userId, 123);
    EXPECT_EQ(remote->requests, 0);
}
} // namespace
