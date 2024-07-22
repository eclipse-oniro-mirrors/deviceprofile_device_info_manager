/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_DP_I_DP_INITED_CALLBCK_H
#define OHOS_DP_I_DP_INITED_CALLBCK_H

#include "iremote_broker.h"
#include "distributed_device_profile_enums.h"

namespace OHOS {
namespace DistributedDeviceProfile {

class IDpInitedCallback : public OHOS::IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.DeviceProfile.IDpInitedCallback");
    IDpInitedCallback() = default;
    virtual ~IDpInitedCallback() = default;
    virtual int32_t OnDpInited() = 0;
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // OHOS_DP_I_DP_INITED_CALLBCK_H
