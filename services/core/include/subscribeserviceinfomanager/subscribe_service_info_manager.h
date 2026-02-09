/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * limitations under the License.
 */

#ifndef OHOS_DP_SUBSCRIBE_SERVICE_INFO_MANAGER_H
#define OHOS_DP_SUBSCRIBE_SERVICE_INFO_MANAGER_H
#include <string>
#include <map>
#include <mutex>
#include "single_instance.h"
#include "distributed_device_profile_enums.h"
#include "dp_subscribe_info.h"
#include "service_info.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class SubscribeServiceInfoManager {
    DECLARE_SINGLE_INSTANCE(SubscribeServiceInfoManager);

public:
    int32_t Init();
    int32_t UnInit();
    int32_t SubscribeServiceInfo(int32_t saId, sptr<IRemoteObject> listener);
    int32_t NotifyServiceInfoAdd(const std::vector<ServiceInfo>& serviceInfos);
    int32_t NotifyServiceInfoUpdate(const std::vector<ServiceInfo>& serviceInfos);
    int32_t NotifyServiceInfoDelete(const std::vector<ServiceInfo>& serviceInfos);

private:
    std::mutex serviceInfoMutex_;
    std::map<int32_t, sptr<IRemoteObject>> serviceInfoMap_;
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // OHOS_DP_SUBSCRIBE_SERVICE_INFO_MANAGER_H