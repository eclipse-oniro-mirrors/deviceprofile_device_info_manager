/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_DP_PARCEL_H
#define OHOS_DP_PARCEL_H

#include <string>
#include "message_parcel.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class DpParcel {
public:
    DpParcel() = default;
    virtual ~DpParcel() = default;
    virtual bool Marshalling(MessageParcel& parcel) const = 0;
    virtual bool UnMarshalling(MessageParcel& parcel) = 0;
    virtual std::string dump() const = 0;
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // OHOS_DP_PARCEL_H
