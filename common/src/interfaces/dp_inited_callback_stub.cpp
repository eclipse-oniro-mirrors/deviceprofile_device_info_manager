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

#include "distributed_device_profile_log.h"
#include "ipc_utils.h"
#include "message_parcel.h"
#include "dp_inited_callback_stub.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "DpInitedCallbackStub";
}

DpInitedCallbackStub::DpInitedCallbackStub()
{
    HILOGI("constructor!");
}

DpInitedCallbackStub::~DpInitedCallbackStub()
{
    HILOGI("destruct!");
}

int32_t DpInitedCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel& data,
    MessageParcel& reply, MessageOption& option)
{
    HILOGI("Code = %{public}u", code);
    std::u16string descriptor = DpInitedCallbackStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        HILOGE("Check descriptor failed");
        return DP_INTERFACE_CHECK_FAILED;
    }
    if (code != static_cast<uint32_t>(DPInterfaceCode::ON_DEVICE_PROFILE_INITED)) {
        HILOGW("Unknown request code, code = %{public}u", code);
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return OnDpInitedInner(data, reply);
}

int32_t DpInitedCallbackStub::OnDpInitedInner(MessageParcel& data, MessageParcel& reply)
{
    (void)data;
    HILOGI("called");
    int32_t ret = OnDpInited();
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
