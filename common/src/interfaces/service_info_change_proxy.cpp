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

#include "service_info_change_proxy.h"

#include "ipc_utils.h"

#include "macro_utils.h"
#include "distributed_device_profile_errors.h"
#include "dp_ipc_interface_code.h"
#include "i_distributed_device_profile.h"
#include "message_parcel.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "ServiceInfoChangeCallbackProxy";
}
int32_t ServiceInfoChangeCallbackProxy::OnServiceInfoInsert(const std::vector<ServiceInfo>& serviceInfos)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_SERINFO_CHANGE_LISTENER_TOKEN(data);
    if (!IpcUtils::Marshalling(data, serviceInfos)) {
        HILOGE("Marshalling failed");
        return ERR_FLATTEN_OBJECT;
    }
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DpIpcInterfaceCode::ON_SERVICE_INFO_INSERT), data, reply);
    return DP_SUCCESS;
}

int32_t ServiceInfoChangeCallbackProxy::OnServiceInfoUpdate(const std::vector<ServiceInfo>& serviceInfos)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_SERINFO_CHANGE_LISTENER_TOKEN(data);
    if (!IpcUtils::Marshalling(data, serviceInfos)) {
        HILOGE("Marshalling failed");
        return ERR_FLATTEN_OBJECT;
    }
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DpIpcInterfaceCode::ON_SERVICE_INFO_UPDATE), data, reply);
    return DP_SUCCESS;
}

int32_t ServiceInfoChangeCallbackProxy::OnServiceInfoDelete(const std::vector<ServiceInfo>& serviceInfos)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_SERINFO_CHANGE_LISTENER_TOKEN(data);
    if (!IpcUtils::Marshalling(data, serviceInfos)) {
        HILOGE("Marshalling failed");
        return ERR_FLATTEN_OBJECT;
    }
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DpIpcInterfaceCode::ON_SERVICE_INFO_DELETE), data, reply);
    return DP_SUCCESS;
}
} // namespace DistributedDeviceProfile
} // namespace OHOS