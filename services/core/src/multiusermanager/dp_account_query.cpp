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

#include "dp_account_query.h"

#include "account_error_no.h"
#include "iaccount.h"
#include "ios_account.h"
#include "iservice_registry.h"
#include "message_option.h"
#include "message_parcel.h"
#include "string_ex.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace OHOS::AccountSA;
namespace {
constexpr int32_t AVATAR_MAX_SIZE = 10 * 1024 * 1024;

int32_t ConvertAccountError(int32_t result)
{
    if (result == ERR_INVALID_VALUE) {
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (result == ERR_INVALID_DATA) {
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    return result;
}

// Match the existing sequenceable's complete wire validation. Unused fields are
// temporary; UID is committed only after every field has been read successfully.
bool ReadAccountUid(MessageParcel& reply, std::string& uid)
{
    int32_t present = 0;
    if (!reply.ReadInt32(present) || present == 0) {
        return false;
    }
    std::u16string scratch;
    std::u16string parsedUid;
    int32_t status;
    int32_t avatarSize;
    if (!reply.ReadString16(scratch) || !reply.ReadString16(parsedUid) ||
        !reply.ReadString16(scratch) || !reply.ReadInt32(status) ||
        !reply.ReadString16(scratch) || !reply.ReadInt32(avatarSize)) {
        return false;
    }
    if (avatarSize < 1 || avatarSize > AVATAR_MAX_SIZE + 1 || reply.ReadRawData(avatarSize) == nullptr ||
        !reply.ReadString16(scratch)) {
        return false;
    }
    uid = Str16ToStr8(parsedUid);
    return true;
}

bool ReadEnterprise(MessageParcel& reply, bool& enterprise)
{
    int32_t present = 0;
    if (!reply.ReadInt32(present) || present == 0) {
        return false;
    }
    std::string accountName;
    std::string scratch;
    bool authenticated;
    if (!reply.ReadString(accountName) || !reply.ReadString(scratch) || !reply.ReadString(scratch) ||
        !reply.ReadBool(authenticated) || !reply.ReadString(scratch) || !reply.ReadString(scratch)) {
        return false;
    }
    enterprise = !accountName.empty();
    return true;
}
}

DpAccountQuery DpAccountQuery::Connect()
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    return DpAccountQuery(samgr == nullptr ? nullptr : samgr->GetSystemAbility(SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN));
}

sptr<IRemoteObject> DpAccountQuery::GetOsAccountService() const
{
    if (account_ == nullptr) {
        return nullptr;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_IMAGE);
    if (!data.WriteInterfaceToken(IAccount::GetDescriptor())) {
        return nullptr;
    }
    int32_t ret = account_->SendRequest(static_cast<uint32_t>(IAccountIpcCode::COMMAND_GET_OS_ACCOUNT_SERVICE),
        data, reply, option);
    int32_t status = ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    if (ret != ERR_OK || !reply.ReadInt32(status) || status != ERR_OK) {
        return nullptr;
    }
    return reply.ReadRemoteObject();
}

int32_t DpAccountQuery::GetForegroundUserId(int32_t& userId) const
{
    auto remote = GetOsAccountService();
    if (remote == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    if (!data.WriteInterfaceToken(IOsAccount::GetDescriptor())) {
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    int32_t ret = remote->SendRequest(
        static_cast<uint32_t>(IOsAccountIpcCode::COMMAND_GET_FOREGROUND_OS_ACCOUNT_LOCAL_ID_OUT_INT),
        data, reply, option);
    if (ret != ERR_OK) {
        return ConvertAccountError(ret);
    }
    if (!reply.ReadInt32(ret)) {
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    if (ret != ERR_OK) {
        return ConvertAccountError(ret);
    }
    int32_t parsedId;
    if (!reply.ReadInt32(parsedId)) {
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    userId = parsedId;
    return ERR_OK;
}

int32_t DpAccountQuery::GetAccountUid(std::string& uid) const
{
    return GetAccountUidInner(false, 0, uid);
}

int32_t DpAccountQuery::GetAccountUid(int32_t userId, std::string& uid) const
{
    return GetAccountUidInner(true, userId, uid);
}

int32_t DpAccountQuery::GetAccountUidInner(bool byUser, int32_t userId, std::string& uid) const
{
    if (account_ == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    if (!data.WriteInterfaceToken(IAccount::GetDescriptor())) {
        return ERR_INVALID_VALUE;
    }
    if (byUser && !data.WriteInt32(userId)) {
        return ERR_INVALID_DATA;
    }
    auto code = byUser ? IAccountIpcCode::COMMAND_GET_OS_ACCOUNT_DISTRIBUTED_INFO :
        IAccountIpcCode::COMMAND_GET_OHOS_ACCOUNT_INFO;
    int32_t ret = account_->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (ret != ERR_OK) {
        return ret;
    }
    if (!reply.ReadInt32(ret)) {
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    if (ret != ERR_OK) {
        return ret;
    }
    return ReadAccountUid(reply, uid) ? ERR_OK : ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
}

int32_t DpAccountQuery::IsEnterpriseUser(int32_t userId, bool& enterprise) const
{
    if (userId < 0) {
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    auto remote = GetOsAccountService();
    if (remote == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    if (!data.WriteInterfaceToken(IOsAccount::GetDescriptor())) {
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(IOsAccountIpcCode::COMMAND_GET_OS_ACCOUNT_DOMAIN_INFO),
        data, reply, option);
    if (ret != ERR_OK) {
        return ConvertAccountError(ret);
    }
    if (!reply.ReadInt32(ret)) {
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    if (ret != ERR_OK) {
        return ConvertAccountError(ret);
    }
    return ReadEnterprise(reply, enterprise) ? ERR_OK : ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
