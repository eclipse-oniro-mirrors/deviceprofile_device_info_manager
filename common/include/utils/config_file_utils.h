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

#ifndef OHOS_DP_CONFIG_FILE_UTILS_H
#define OHOS_DP_CONFIG_FILE_UTILS_H

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>

namespace OHOS {
namespace DistributedDeviceProfile {
constexpr size_t CONFIG_FILE_UNLIMITED = std::numeric_limits<size_t>::max();
// Resolve the original product configuration path and read its bytes.
int32_t LoadConfigFile(const std::string& filePath, std::string& fileContent,
    size_t maxSize = CONFIG_FILE_UNLIMITED);
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // OHOS_DP_CONFIG_FILE_UTILS_H
