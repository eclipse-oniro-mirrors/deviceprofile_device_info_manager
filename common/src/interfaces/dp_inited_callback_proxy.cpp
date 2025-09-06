/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "dp_inited_callback_proxy.h"
#include "macro_utils.h"
#include "distributed_device_profile_errors.h"
#include "dp_ipc_interface_code.h"
#include "i_distributed_device_profile.h"
#include "message_parcel.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "DpInitedCallbackProxy";
}

int32_t DpInitedCallbackProxy::OnDpInited()
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    if (!data.WriteInterfaceToken(IDpInitedCallback::GetDescriptor())) {
        HILOGE("write descriptor failed");
        return ERR_FLATTEN_OBJECT;
    }
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DpIpcInterfaceCode::ON_DEVICE_PROFILE_INITED), data, reply);
    return DP_SUCCESS;
}
} // namespace DistributedDeviceProfile
} // namespace OHOS

