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

#ifndef OHOS_DP_IBUSINESS_CALLBACK_H
#define OHOS_DP_IBUSINESS_CALLBACK_H

#include "business_event.h"
#include "iremote_broker.h"

namespace OHOS {
namespace DistributedDeviceProfile {

class IBusinessCallback : public OHOS::IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.DeviceProfile.IBusinessCallback");
    IBusinessCallback() = default;
    virtual ~IBusinessCallback() = default;

    virtual int32_t OnBusinessEvent(const BusinessEvent& event) = 0;
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // OHOS_DP_IBUSINESS_CALLBACK_H