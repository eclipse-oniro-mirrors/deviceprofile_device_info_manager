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

#include <gtest/gtest.h>

#include "profile_cache.h"
#include "profile_utils.h"
#include "device_profile_manager.h"

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace testing;
using namespace testing::ext;

class ProfileCacheTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ProfileCacheTest::SetUpTestCase() {
}

void ProfileCacheTest::TearDownTestCase() {
}

void ProfileCacheTest::SetUp() {
}

void ProfileCacheTest::TearDown() {
}

HWTEST_F(ProfileCacheTest, AddDeviceProfile_001, TestSize.Level2)
{
    DeviceProfile deviceProfile;
    int32_t ret = ProfileCache::GetInstance().AddDeviceProfile(deviceProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    std::string devId = "dp_devId";
    deviceProfile.SetDeviceId(devId);
    ret = ProfileCache::GetInstance().AddDeviceProfile(deviceProfile);
    EXPECT_EQ(DP_SUCCESS, ret);
    
    for (int i = 1; i < MAX_DEVICE_SIZE + 1; ++i) {
        ProfileCache::GetInstance().deviceProfileMap_[std::to_string(i)] = deviceProfile;
    }
    ret = ProfileCache::GetInstance().AddDeviceProfile(deviceProfile);
    EXPECT_EQ(DP_EXCEED_MAX_SIZE_FAIL, ret);
}

HWTEST_F(ProfileCacheTest, AddServiceProfile_001, TestSize.Level2)
{
    ServiceProfile serviceProfile;
    int32_t ret = ProfileCache::GetInstance().AddServiceProfile(serviceProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    std::string devId = "dp_devId";
    serviceProfile.SetDeviceId(devId);
    ret = ProfileCache::GetInstance().AddServiceProfile(serviceProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    std::string serName = "dp_serName";
    serviceProfile.SetServiceName(serName);
    ret = ProfileCache::GetInstance().AddServiceProfile(serviceProfile);
    EXPECT_EQ(DP_SUCCESS, ret);
    
    devId = "";
    serviceProfile.SetDeviceId(devId);
    ret = ProfileCache::GetInstance().AddServiceProfile(serviceProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    for (int i = 1; i < MAX_DEVICE_SIZE + 1; ++i) {
        ProfileCache::GetInstance().serviceProfileMap_[std::to_string(i)] = serviceProfile;
    }
    ret = ProfileCache::GetInstance().AddServiceProfile(serviceProfile);
    EXPECT_EQ(DP_EXCEED_MAX_SIZE_FAIL, ret);
}

HWTEST_F(ProfileCacheTest, AddCharProfile_001, TestSize.Level2)
{
    CharacteristicProfile charProfile;
    int32_t ret = ProfileCache::GetInstance().AddCharProfile(charProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    std::string devId = "dp_devId";
    charProfile.SetDeviceId(devId);
    ret = ProfileCache::GetInstance().AddCharProfile(charProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    std::string serName = "dp_serName";
    charProfile.SetServiceName(serName);
    ret = ProfileCache::GetInstance().AddCharProfile(charProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    std::string charKey = "dp_charKey";
    charProfile.SetCharacteristicKey(charKey);
    ret = ProfileCache::GetInstance().AddCharProfile(charProfile);
    EXPECT_EQ(DP_SUCCESS, ret);
    
    devId = "";
    charProfile.SetDeviceId(devId);
    ret = ProfileCache::GetInstance().AddCharProfile(charProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    serName = "";
    charProfile.SetServiceName(serName);
    ret = ProfileCache::GetInstance().AddCharProfile(charProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    devId = "dp_devId";
    charProfile.SetDeviceId(devId);
    ret = ProfileCache::GetInstance().AddCharProfile(charProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    for (int i = 1; i < MAX_DEVICE_SIZE + 1; ++i) {
        ProfileCache::GetInstance().charProfileMap_[std::to_string(i)] = charProfile;
    }
    ret = ProfileCache::GetInstance().AddCharProfile(charProfile);
    EXPECT_EQ(DP_EXCEED_MAX_SIZE_FAIL, ret);
}

HWTEST_F(ProfileCacheTest, GetDeviceProfile_001, TestSize.Level2)
{
    std::string devId = "";
    DeviceProfile deviceProfile;
    int32_t ret = ProfileCache::GetInstance().GetDeviceProfile(devId, deviceProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    devId = "dp_devId";
    ret = ProfileCache::GetInstance().GetDeviceProfile(devId, deviceProfile);
    EXPECT_EQ(DP_SUCCESS, ret);
    
    ProfileCache::GetInstance().deviceProfileMap_.clear();
    ret = ProfileCache::GetInstance().GetDeviceProfile(devId, deviceProfile);
    EXPECT_EQ(DP_NOT_FOUND_FAIL, ret);
}

HWTEST_F(ProfileCacheTest, GetServiceProfile_001, TestSize.Level2)
{
    std::string devId = "";
    std::string serName = "";
    ServiceProfile serviceProfile;
    int32_t ret = ProfileCache::GetInstance().GetServiceProfile(devId, serName, serviceProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    devId = "dp_devId";
    ret = ProfileCache::GetInstance().GetServiceProfile(devId, serName, serviceProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    serName = "dp_serName";
    ret = ProfileCache::GetInstance().GetServiceProfile(devId, serName, serviceProfile);
    EXPECT_EQ(DP_SUCCESS, ret);
    
    devId = "";
    ret = ProfileCache::GetInstance().GetServiceProfile(devId, serName, serviceProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    ProfileCache::GetInstance().serviceProfileMap_.clear();
    ret = ProfileCache::GetInstance().GetServiceProfile(devId, serName, serviceProfile);
    EXPECT_EQ(DP_NOT_FOUND_FAIL, ret);
}

HWTEST_F(ProfileCacheTest, GetCharacteristicProfile_001, TestSize.Level2)
{
    std::string devId = "";
    std::string serName = "";
    std::string charKey = "";
    CharacteristicProfile charProfile;
    int32_t ret = ProfileCache::GetInstance().GetCharacteristicProfile(devId, serName, charKey, charProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    devId = "dp_devId";
    ret = ProfileCache::GetInstance().GetCharacteristicProfile(devId, serName, charKey, charProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    serName = "dp_serName";
    ret = ProfileCache::GetInstance().GetCharacteristicProfile(devId, serName, charKey, charProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    charKey = "dp_charKey";
    ret = ProfileCache::GetInstance().GetCharacteristicProfile(devId, serName, charKey, charProfile);
    EXPECT_EQ(DP_SUCCESS, ret);
    
    devId = "";
    ret = ProfileCache::GetInstance().GetCharacteristicProfile(devId, serName, charKey, charProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    serName = "";
    ret = ProfileCache::GetInstance().GetCharacteristicProfile(devId, serName, charKey, charProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    devId = "dp_devId";
    ret = ProfileCache::GetInstance().GetCharacteristicProfile(devId, serName, charKey, charProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    ProfileCache::GetInstance().charProfileMap_.clear();
    ret = ProfileCache::GetInstance().GetCharacteristicProfile(devId, serName, charKey, charProfile);
    EXPECT_EQ(DP_NOT_FOUND_FAIL, ret);
}

HWTEST_F(ProfileCacheTest, DeleteDeviceProfile_001, TestSize.Level2)
{
    std::string devId = "";
    int32_t ret = ProfileCache::GetInstance().DeleteDeviceProfile(devId);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    devId = "dp_devId";
    ret = ProfileCache::GetInstance().DeleteDeviceProfile(devId);
    EXPECT_EQ(DP_SUCCESS, ret);
}

HWTEST_F(ProfileCacheTest, DeleteServiceProfile_001, TestSize.Level2)
{
    std::string devId = "";
    std::string serName = "";
    int32_t ret = ProfileCache::GetInstance().DeleteServiceProfile(devId, serName);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    devId = "dp_devId";
    ret = ProfileCache::GetInstance().DeleteServiceProfile(devId, serName);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    serName = "dp_serName";
    ret = ProfileCache::GetInstance().DeleteServiceProfile(devId, serName);
    EXPECT_EQ(DP_SUCCESS, ret);
    
    devId = "";
    ret = ProfileCache::GetInstance().DeleteServiceProfile(devId, serName);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
}

HWTEST_F(ProfileCacheTest, DeleteCharProfile_001, TestSize.Level2)
{
    std::string devId = "";
    std::string serName = "";
    std::string charKey = "";
    int32_t ret = ProfileCache::GetInstance().DeleteCharProfile(devId, serName, charKey);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    devId = "dp_devId";
    ret = ProfileCache::GetInstance().DeleteCharProfile(devId, serName, charKey);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    serName = "dp_serName";
    ret = ProfileCache::GetInstance().DeleteCharProfile(devId, serName, charKey);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    charKey = "dp_charKey";
    ret = ProfileCache::GetInstance().DeleteCharProfile(devId, serName, charKey);
    EXPECT_EQ(DP_SUCCESS, ret);
    
    devId = "";
    ret = ProfileCache::GetInstance().DeleteCharProfile(devId, serName, charKey);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    serName = "";
    ret = ProfileCache::GetInstance().DeleteCharProfile(devId, serName, charKey);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);

    devId = "dp_devId";
    ret = ProfileCache::GetInstance().DeleteCharProfile(devId, serName, charKey);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
}

HWTEST_F(ProfileCacheTest, IsDeviceProfileExist_001, TestSize.Level2)
{
    DeviceProfile deviceProfile;
    bool ret = ProfileCache::GetInstance().IsDeviceProfileExist(deviceProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    std::string devId = "dp_devId";
    deviceProfile.SetDeviceId(devId);
    ret = ProfileCache::GetInstance().IsDeviceProfileExist(deviceProfile);
    EXPECT_EQ(false, ret);
    
    std::string deviceProfileKey = ProfileUtils::GenerateDeviceProfileKey(devId);
    ProfileCache::GetInstance().deviceProfileMap_[deviceProfileKey] = deviceProfile;
    ret = ProfileCache::GetInstance().IsDeviceProfileExist(deviceProfile);
    EXPECT_EQ(true, ret);
}

HWTEST_F(ProfileCacheTest, IsServiceProfileExist_001, TestSize.Level2)
{
    ServiceProfile serviceProfile;
    bool ret = ProfileCache::GetInstance().IsServiceProfileExist(serviceProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    std::string devId = "dp_devId";
    serviceProfile.SetDeviceId(devId);
    ret = ProfileCache::GetInstance().IsServiceProfileExist(serviceProfile);
    EXPECT_EQ(false, ret);
    
    devId = "";
    std::string serName = "dp_serName";
    serviceProfile.SetDeviceId(devId);
    serviceProfile.SetServiceName(serName);
    ret = ProfileCache::GetInstance().IsServiceProfileExist(serviceProfile);
    EXPECT_EQ(false, ret);
    
    devId = "dp_devId";
    serviceProfile.SetDeviceId(devId);
    ret = ProfileCache::GetInstance().IsServiceProfileExist(serviceProfile);
    EXPECT_EQ(false, ret);
    
    std::string serviceProfileKey = ProfileUtils::GenerateDeviceProfileKey(devId);
    ProfileCache::GetInstance().serviceProfileMap_[serviceProfileKey] = serviceProfile;
    ret = ProfileCache::GetInstance().IsServiceProfileExist(serviceProfile);
    EXPECT_EQ(true, ret);
}

HWTEST_F(ProfileCacheTest, IsCharProfileExist_001, TestSize.Level2)
{
    CharacteristicProfile charProfile;
    bool ret = ProfileCache::GetInstance().IsCharProfileExist(charProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    std::string devId = "dp_devId";
    charProfile.SetDeviceId(devId);
    ret = ProfileCache::GetInstance().IsCharProfileExist(charProfile);
    EXPECT_EQ(false, ret);
    
    std::string serName = "dp_serName";
    charProfile.SetServiceName(serName);
    ret = ProfileCache::GetInstance().IsCharProfileExist(charProfile);
    EXPECT_EQ(false, ret);
    
    devId = "";
    charProfile.SetDeviceId(devId);
    std::string charKey = "dp_charKey";
    charProfile.SetCharacteristicKey(charKey);
    ret = ProfileCache::GetInstance().IsCharProfileExist(charProfile);
    EXPECT_EQ(false, ret);
    
    serName = "";
    charProfile.SetServiceName(serName);
    ret = ProfileCache::GetInstance().IsCharProfileExist(charProfile);
    EXPECT_EQ(false, ret);

    devId = "dp_devId";
    charProfile.SetDeviceId(devId);
    ret = ProfileCache::GetInstance().IsCharProfileExist(charProfile);
    EXPECT_EQ(false, ret);
    
    std::string charProfileKey = ProfileUtils::GenerateDeviceProfileKey(devId);
    ProfileCache::GetInstance().charProfileMap_[charProfileKey] = charProfile;
    ret = ProfileCache::GetInstance().IsCharProfileExist(charProfile);
    EXPECT_EQ(true, ret);
}

HWTEST_F(ProfileCacheTest, RefreshDeviceProfileCache_001, TestSize.Level2)
{
    std::vector<DeviceProfile> deviceProfiles;
    int32_t ret = ProfileCache::GetInstance().RefreshDeviceProfileCache(deviceProfiles);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    DeviceProfile deviceProfile;
    std::string devId = "dp_devId";
    deviceProfile.SetDeviceId(devId);
    deviceProfiles.push_back(deviceProfile);
    ret = ProfileCache::GetInstance().RefreshDeviceProfileCache(deviceProfiles);
    EXPECT_EQ(DP_SUCCESS, ret);
}

HWTEST_F(ProfileCacheTest, RefreshServiceProfileCache_001, TestSize.Level2)
{
    std::vector<ServiceProfile> serviceProfiles;
    int32_t ret = ProfileCache::GetInstance().RefreshServiceProfileCache(serviceProfiles);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    ServiceProfile serviceProfile;
    std::string devId = "dp_devId";
    std::string serName = "dp_serName";
    serviceProfile.SetDeviceId(devId);
    serviceProfile.SetServiceName(serName);
    serviceProfiles.push_back(serviceProfile);
    ret = ProfileCache::GetInstance().RefreshServiceProfileCache(serviceProfiles);
    EXPECT_EQ(DP_SUCCESS, ret);
}

HWTEST_F(ProfileCacheTest, RefreshCharProfileCache_001, TestSize.Level2)
{
    std::vector<CharacteristicProfile> characteristicProfiles;
    int32_t ret = ProfileCache::GetInstance().RefreshCharProfileCache(characteristicProfiles);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    CharacteristicProfile characteristicProfile;
    std::string devId = "dp_devId";
    std::string serName = "dp_serName";
    std::string charKey = "dp_charKey";
    characteristicProfile.SetDeviceId(devId);
    characteristicProfile.SetServiceName(serName);
    characteristicProfile.SetCharacteristicKey(charKey);
    characteristicProfiles.push_back(characteristicProfile);
    ret = ProfileCache::GetInstance().RefreshCharProfileCache(characteristicProfiles);
    EXPECT_EQ(DP_SUCCESS, ret);
}
}
}
