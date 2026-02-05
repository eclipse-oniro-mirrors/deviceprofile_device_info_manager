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

#include "service_info_change_stub.h"

#include "message_parcel.h"
#include "ipc_utils.h"

#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"
#include "dp_ipc_interface_code.h"
#include "service_info.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "ServiceInfoChangeCallbackStub";
}
ServiceInfoChangeCallbackStub::ServiceInfoChangeCallbackStub()
{
    HILOGI("construct!");
    funcsMap_[static_cast<uint32_t>(DpIpcInterfaceCode::ON_SERVICE_INFO_INSERT)] =
        &ServiceInfoChangeCallbackStub::OnServiceInfoInsertInner;
    funcsMap_[static_cast<uint32_t>(DpIpcInterfaceCode::ON_SERVICE_INFO_UPDATE)] =
        &ServiceInfoChangeCallbackStub::OnServiceInfoUpdateInner;
    funcsMap_[static_cast<uint32_t>(DpIpcInterfaceCode::ON_SERVICE_INFO_DELETE)] =
        &ServiceInfoChangeCallbackStub::OnServiceInfoDeleteInner;
}

ServiceInfoChangeCallbackStub::~ServiceInfoChangeCallbackStub()
{
    HILOGI("destruct!");
}

bool ServiceInfoChangeCallbackStub::IsInterfaceToken(MessageParcel& data)
{
    return data.ReadInterfaceToken() == IServiceInfoChangeCallback::GetDescriptor();
}

int32_t ServiceInfoChangeCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel& data,
    MessageParcel& reply, MessageOption& option)
{
    HILOGI("code = %{public}u, flags = %{public}d", code, option.GetFlags());

    if (!IsInterfaceToken(data)) {
        HILOGE("check interface token failed");
        return DP_INTERFACE_CHECK_FAILED;
    }
    switch (code) {
        case static_cast<uint32_t>(DpIpcInterfaceCode::ON_SERVICE_INFO_INSERT):
            return ServiceInfoChangeCallbackStub::OnServiceInfoInsertInner(data, reply);
        case static_cast<uint32_t>(DpIpcInterfaceCode::ON_SERVICE_INFO_UPDATE):
            return ServiceInfoChangeCallbackStub::OnServiceInfoUpdateInner(data, reply);
        case static_cast<uint32_t>(DpIpcInterfaceCode::ON_SERVICE_INFO_DELETE):
            return ServiceInfoChangeCallbackStub::OnServiceInfoDeleteInner(data, reply);
        default:
            HILOGW("unknown request code, please check, code = %{public}u", code);
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

int32_t ServiceInfoChangeCallbackStub::OnServiceInfoInsertInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    std::vector<ServiceInfo> serviceInfos;
    if (!IpcUtils::UnMarshalling(data, serviceInfos)) {
        HILOGE("UnMarshalling failed");
        return ERR_FLATTEN_OBJECT;
    }
    int32_t ret = OnServiceInfoInsert(serviceInfos);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t ServiceInfoChangeCallbackStub::OnServiceInfoUpdateInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    std::vector<ServiceInfo> serviceInfos;
    if (!IpcUtils::UnMarshalling(data, serviceInfos)) {
        HILOGE("UnMarshalling failed");
        return ERR_FLATTEN_OBJECT;
    }
    int32_t ret = OnServiceInfoUpdate(serviceInfos);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t ServiceInfoChangeCallbackStub::OnServiceInfoDeleteInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    std::vector<ServiceInfo> serviceInfos;
    if (!IpcUtils::UnMarshalling(data, serviceInfos)) {
        HILOGE("UnMarshalling failed");
        return ERR_FLATTEN_OBJECT;
    }
    int32_t ret = OnServiceInfoDelete(serviceInfos);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

} // namespace DistributedDeviceProfile
} // namespace OHOS