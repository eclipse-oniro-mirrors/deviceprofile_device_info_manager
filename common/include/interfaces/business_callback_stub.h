/*
* Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_BUSINESS_CALLBACK_STUB_H
#define OHOS_BUSINESS_CALLBACK_STUB_H

#include <mutex>

#include "distributed_device_profile_enums.h"
#include "distributed_device_profile_errors.h"
#include "i_business_callback.h"
#include "iremote_stub.h"
#include "message_parcel.h"
#include "refbase.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class BusinessCallbackStub : public IRemoteStub<IBusinessCallback> {
public:
    BusinessCallbackStub();
    ~BusinessCallbackStub();

    virtual int32_t OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply,
        MessageOption& option) override;

private:
    int32_t OnBusinessEventInner(MessageParcel& data, MessageParcel& reply);
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // OHOS_BUSINESS_CALLBCK_STUB_H
