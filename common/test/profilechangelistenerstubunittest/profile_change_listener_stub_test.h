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

#ifndef PROFILE_CHANGE_LISTENNER_STUB_TEST_H
#define PROFILE_CHANGE_LISTENNER_STUB_TEST_H

#include <gtest/gtest.h>

#include "characteristic_profile.h"
#include "profile_change_listener_stub.h"
#include "service_profile.h"
#include "trust_device_profile.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class ProfileChangeListenerStubTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    virtual void SetUp();
    virtual void TearDown();

    std::shared_ptr<ProfileChangeListenerStub> listenerStub_ = nullptr;
};

class MockProfileChangeListenerStub : public ProfileChangeListenerStub {
public:
    int32_t OnTrustDeviceProfileAdd(const TrustDeviceProfile& profile) override;
    int32_t OnTrustDeviceProfileDelete(const TrustDeviceProfile& profile) override;
    int32_t OnTrustDeviceProfileUpdate(const TrustDeviceProfile& oldProfile,
        const TrustDeviceProfile& newProfile) override;
    int32_t OnTrustDeviceProfileInactive(const TrustDeviceProfile& profile) override;
    int32_t OnTrustDeviceProfileActive(const TrustDeviceProfile& profile) override;
    int32_t OnDeviceProfileAdd(const DeviceProfile& profile) override;
    int32_t OnDeviceProfileDelete(const DeviceProfile& profile) override;
    int32_t OnDeviceProfileUpdate(const DeviceProfile& oldProfile, const DeviceProfile& newProfile) override;
    int32_t OnServiceProfileAdd(const ServiceProfile& profile) override;
    int32_t OnServiceProfileDelete(const ServiceProfile& profile) override;
    int32_t OnServiceProfileUpdate(const ServiceProfile& oldProfile, const ServiceProfile& newProfile) override;
    int32_t OnCharacteristicProfileAdd(const CharacteristicProfile& profile) override;
    int32_t OnCharacteristicProfileDelete(const CharacteristicProfile& profile) override;
    int32_t OnCharacteristicProfileUpdate(const CharacteristicProfile& oldProfile,
        const CharacteristicProfile& newProfile) override;
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // PROFILE_CHANGE_LISTENNER_STUB_TEST_H