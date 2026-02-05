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

#ifndef OHOS_DP_SERVICE_INFO_CHANGE_CALLBACK_STUB_H
#define OHOS_DP_SERVICE_INFO_CHANGE_CALLBACK_STUB_H

#include <map>
#include <memory>
#include <mutex>
#include "i_service_info_change_callback.h"
#include "iremote_stub.h"
#include "message_parcel.h"
#include "refbase.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class ServiceInfoChangeCallbackStub : public IRemoteStub<IServiceInfoChangeCallback> {
public:
    ServiceInfoChangeCallbackStub();
    ~ServiceInfoChangeCallbackStub();
    virtual int32_t OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply,
        MessageOption& option) override;
    int32_t OnServiceInfoInsertInner(MessageParcel& data, MessageParcel& reply);
    int32_t OnServiceInfoUpdateInner(MessageParcel& data, MessageParcel& reply);
    int32_t OnServiceInfoDeleteInner(MessageParcel& data, MessageParcel& reply);

private:
    using Func = int32_t(ServiceInfoChangeCallbackStub::*)(MessageParcel& data, MessageParcel& reply);
    bool IsInterfaceToken(MessageParcel& data);

private:
    std::map<int32_t, Func> funcsMap_;
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // OHOS_DP_SERVICE_INFO_CHANGE_CALLBACK_STUB_H