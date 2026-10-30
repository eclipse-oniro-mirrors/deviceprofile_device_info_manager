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

#ifndef OHOS_DP_ACCOUNT_QUERY_H
#define OHOS_DP_ACCOUNT_QUERY_H

#include <string>
#include "iremote_object.h"

namespace OHOS {
namespace DistributedDeviceProfile {
// DP-private, synchronous read-only adapter. Never retains account data or callbacks.
class DpAccountQuery final {
public:
    explicit DpAccountQuery(const sptr<IRemoteObject>& account) : account_(account) {}
    static DpAccountQuery Connect();
    int32_t GetForegroundUserId(int32_t& userId) const;
    int32_t GetAccountUid(std::string& uid) const;
    int32_t GetAccountUid(int32_t userId, std::string& uid) const;
    int32_t IsEnterpriseUser(int32_t userId, bool& enterprise) const;
private:
    sptr<IRemoteObject> GetOsAccountService() const;
    int32_t GetAccountUidInner(bool byUser, int32_t userId, std::string& uid) const;
    sptr<IRemoteObject> account_;
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // OHOS_DP_ACCOUNT_QUERY_H
