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
 
#ifndef OHOS_DP_SERVICE_INFO_CHANGE_CALLBACK_PROXY_H
#define OHOS_DP_SERVICE_INFO_CHANGE_CALLBACK_PROXY_H
 
#include "i_service_info_change_callback.h"
#include "iremote_broker.h"
#include "iremote_proxy.h"
#include "refbase.h"
 
namespace OHOS {
namespace DistributedDeviceProfile {
class ServiceInfoChangeCallbackProxy : public IRemoteProxy<IServiceInfoChangeCallback> {
public:
    explicit ServiceInfoChangeCallbackProxy(const sptr<IRemoteObject>& impl)
        : IRemoteProxy<IServiceInfoChangeCallback>(impl) {}
    ~ServiceInfoChangeCallbackProxy() = default;
    int32_t OnServiceInfoInsert(const std::vector<ServiceInfo>& serviceInfos) override;
    int32_t OnServiceInfoUpdate(const std::vector<ServiceInfo>& serviceInfos) override;
    int32_t OnServiceInfoDelete(const std::vector<ServiceInfo>& serviceInfos) override;

private:
    static inline BrokerDelegator<ServiceInfoChangeCallbackProxy> delegator_;
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // OHOS_DP_SERVICE_INFO_CHANGE_CALLBACK_PROXY_H