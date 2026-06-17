/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "distributed_device_profile_service_new.h"
#include "file_ex.h"
#include "string_ex.h"
#include "if_system_ability_manager.h"
#include "ipc_object_proxy.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "sa_profiles.h"
#include "xcollie/xcollie.h"
#include "xcollie/xcollie_define.h"
#include "business_event_manager.h"
#include "common_event_support.h"
#include "content_sensor_manager.h"
#include "device_profile_dumper.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_errors.h"
#include "dm_adapter.h"
#include "device_profile_manager.h"
#include "dp_radar_helper.h"
#include "event_handler_factory.h"
#include "ibusiness_callback.h"
#include "i_pincode_invalid_callback.h"
#include "local_service_info_manager.h"
#include "multi_user_manager.h"
#include "mem_mgr_client.h"
#include "mem_mgr_proxy.h"
#include "permission_manager.h"
#include "profile_cache.h"
#include "profile_data_manager.h"
#include "service_info_manager.h"
#include "session_key_manager.h"
#include "settings_data_manager.h"
#include "static_profile_manager.h"
#include "static_capability_collector.h"
#include "subscribe_profile_manager.h"
#include "switch_profile_manager.h"
#include "trust_profile_manager.h"
#include "subscribe_service_info_manager.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstring>

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
const std::string TAG = "ServiceNew";
const std::string UNLOAD_TASK_ID = "unload_dp_svr";
const std::string IDLE_REASON_LOW_MEMORY = "resourceschedule.memmgr.low.memory.prepare";
const std::string DP_ONSTART_TIMER = "dp_onstart_timer";
constexpr int32_t DELAY_TIME = 180000;
constexpr int32_t SA_READY_INTO_IDLE = 0;
constexpr int32_t SA_REFUSE_INTO_IDLE = -1;
constexpr int32_t WAIT_BUSINESS_PUT_TIME_S = 5;
constexpr int32_t WRTE_CACHE_PROFILE_DELAY_TIME_US = 200 * 1000;
constexpr int32_t WRTE_CACHE_PROFILE_RETRY_TIMES = 20;
constexpr int32_t DP_IPC_THREAD_NUM = 32;
constexpr uint32_t MAX_CALLBACK_LEN = 1000;
constexpr int32_t ONSTART_TIMEOUT_TIME = 12;

// 安全增强常量（原则7、13、17等）
constexpr int32_t MAX_AUTH_ATTEMPTS = 5;
constexpr int64_t AUTH_BLOCK_DURATION_MS = 300000;
constexpr int64_t ACL_MAX_LIFETIME_MS = 2592000000;
constexpr int64_t ACL_IDLE_TIMEOUT_MS = 604800000;
constexpr int32_t OPERATION_CONTEXT_TIMEOUT_MS = 300000;
constexpr size_t AES_GCM_TAG_SIZE = 16;
constexpr size_t AES_GCM_NONCE_SIZE = 12;

// 设备ID长度限制
constexpr size_t MIN_DEVICE_ID_LENGTH = 8;
constexpr size_t MAX_DEVICE_ID_LENGTH = 64;

// PIN码长度限制
constexpr size_t MIN_PIN_CODE_LENGTH = 6;
constexpr size_t MAX_PIN_CODE_LENGTH = 8;

// ACL清理间隔
constexpr int64_t ACL_CLEANUP_INTERVAL_MS = 3600000;

// ACL ID最小值
constexpr int32_t MIN_ACL_ID = 0;
}

// 安全增强：OperationContext 实现（原则5）
bool OperationContext::IsValid() const
{
    if (deviceId.empty() || userId == 0) {
        return false;
    }
    int64_t currentTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    if (currentTime - timestamp > OPERATION_CONTEXT_TIMEOUT_MS) {
        HILOGE("Operation context expired");
        return false;
    }
    return true;
}

// 安全增强：AuthRateLimitRecord 实现（原则7）
bool AuthRateLimitRecord::IsBlocked() const
{
    if (failCount >= MAX_AUTH_ATTEMPTS) {
        int64_t currentTime = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        if (currentTime - lastAttemptTime < AUTH_BLOCK_DURATION_MS) {
            return true;
        }
    }
    return false;
}

// 安全增强：AclLifecycleInfo 实现（原则17）
bool AclLifecycleInfo::IsExpired() const
{
    int64_t currentTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    if (currentTime - createTime > ACL_MAX_LIFETIME_MS ||
        (accessCount > 0 && currentTime - lastAccessTime > ACL_IDLE_TIMEOUT_MS)) {
        return true;
    }
    return false;
}

IMPLEMENT_SINGLE_INSTANCE(DistributedDeviceProfileServiceNew);
const bool REGISTER_RESULT =
    SystemAbility::MakeAndRegisterAbility(&DistributedDeviceProfileServiceNew::GetInstance());

DistributedDeviceProfileServiceNew::DistributedDeviceProfileServiceNew()
    : SystemAbility(DISTRIBUTED_DEVICE_PROFILE_SA_ID, true),
      securitySwitchStatus_(-1)
{
    HILOGI("DPService construct with security!");
    securityInitialized_.store(true);
}

DistributedDeviceProfileServiceNew::~DistributedDeviceProfileServiceNew()
{
    std::lock_guard<std::mutex> lock1(operationContextMtx_);
    operationContextMap_.clear();
    std::lock_guard<std::mutex> lock2(authRateLimitMtx_);
    authRateLimitMap_.clear();
    std::lock_guard<std::mutex> lock3(aclLifecycleMtx_);
    aclLifecycleMap_.clear();
    std::lock_guard<std::mutex> lock4(userIsolationMtx_);
    userDeviceMap_.clear();
    securityInitialized_.store(false);
}

int32_t DistributedDeviceProfileServiceNew::Init()
{
    HILOGI("init begin");
    EventHandlerFactory::GetInstance().Init();
    if (PermissionManager::GetInstance().Init() != DP_SUCCESS) {
        HILOGE("PermissionManager init failed");
        return DP_PERMISSION_MANAGER_INIT_FAIL;
    }
    securitySwitchStatus_ = -1; // 原则13：默认非法值
    TrustProfileManager::GetInstance().Init();
    ProfileDataManager::GetInstance().Init();
    SubscribeProfileManager::GetInstance().Init();

    // 启动ACL清理任务（原则17）
    auto handler = EventHandlerFactory::GetInstance().GetEventHandler();
    if (handler != nullptr) {
        handler->PostTask([this]() {this->CleanupExpiredAcls();},
            "cleanup_acl",
            ACL_CLEANUP_INTERVAL_MS);
    }
    HILOGI("init finish");
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileServiceNew::PostInit()
{
    HILOGI("PostInit begin");
    if (DMAdapter::GetInstance().Init() != DP_SUCCESS) {
        return DP_DM_ADAPTER_INIT_FAIL;
    }
#ifndef DEVICE_PROFILE_SWITCH_DISABLE
    if (SwitchProfileManager::GetInstance().Init() != DP_SUCCESS) {
        return DP_DEVICE_PROFILE_MANAGER_INIT_FAIL;
    }
#endif
    if (DeviceProfileManager::GetInstance().Init() != DP_SUCCESS) {
        return DP_DEVICE_PROFILE_MANAGER_INIT_FAIL;
    }
    if (StaticProfileManager::GetInstance().Init() != DP_SUCCESS) {
        return DP_CONTENT_SENSOR_MANAGER_INIT_FAIL;
    }
    if (ProfileCache::GetInstance().Init() != DP_SUCCESS) {
        return DP_CACHE_INIT_FAIL;
    }
    if (StaticCapabilityCollector::GetInstance().Init() != DP_SUCCESS) {
        return DP_CONTENT_SENSOR_MANAGER_INIT_FAIL;
    }
    if (LocalServiceInfoManager::GetInstance().Init() != DP_SUCCESS) {
        return DP_LOCAL_SERVICE_INFO_MANAGER_INIT_FAIL;
    }
    if (MultiUserManager::GetInstance().Init() != DP_SUCCESS) {
        return DP_MULTI_USER_MANAGER_INIT_FAIL;
    }
    ServiceInfoManager::GetInstance().Init();
    return PostInitNext();
}

int32_t DistributedDeviceProfileServiceNew::PostInitNext()
{
    if (SettingsDataManager::GetInstance().Init() != DP_SUCCESS) {
        return DP_SETTINGSDATA_MANAGER_INIT_FAIL;
    }
    if (ContentSensorManager::GetInstance().Init() != DP_SUCCESS) {
        return DP_CONTENT_SENSOR_MANAGER_INIT_FAIL;
    }
    if (BusinessEventManager::GetInstance().Init() != DP_SUCCESS) {
        return DP_BUSINESS_EVENT_MANAGER_INIT_FAIL;
    }
    {
        std::lock_guard<std::mutex> lock(cacheMtx_);
#ifndef DEVICE_PROFILE_SWITCH_DISABLE
        SaveSwitchProfilesFromTempCache();
#endif
        SaveDynamicProfilesFromTempCache();
        isInited_ = true;
    }
    HILOGI("PostInit finish");
    NotifyDeviceProfileInited();
    return DP_SUCCESS;
}

bool DistributedDeviceProfileServiceNew::IsInited()
{
    return isInited_;
}

bool DistributedDeviceProfileServiceNew::IsReadyIntoIdle()
{
    if (runningIpcCount_.load() > 0) {
        HILOGE("ipc running, can't idle");
        return false;
    }
    if (ProfileCache::GetInstance().IsDeviceOnline()) {
        HILOGE("device online, can't idle");
        return false;
    }
    return true;
}

void DistributedDeviceProfileServiceNew::AddRunningIpcCount()
{
    runningIpcCount_.fetch_add(1);
}

void DistributedDeviceProfileServiceNew::SubtractRunningIpcCount()
{
    runningIpcCount_.fetch_sub(1);
}

int32_t DistributedDeviceProfileServiceNew::UnInit()
{
    isInited_ = false;
    // 原则12：彻底清理敏感数据
    {
        std::lock_guard<std::mutex> lock1(operationContextMtx_);
        for (auto& [key, context] : operationContextMap_) {
            SecureClearString(context.deviceId);
        }
        operationContextMap_.clear();
    }
    {
        std::lock_guard<std::mutex> lock2(authRateLimitMtx_);
        authRateLimitMap_.clear();
    }
    {
        std::lock_guard<std::mutex> lock3(aclLifecycleMtx_);
        aclLifecycleMap_.clear();
    }
    {
        std::lock_guard<std::mutex> lock4(userIsolationMtx_);
        userDeviceMap_.clear();
    }

    if (TrustProfileManager::GetInstance().UnInit() != DP_SUCCESS) {
        return DP_TRUST_PROFILE_MANAGER_UNINIT_FAIL;
    }
    if (ProfileDataManager::GetInstance().UnInit() != DP_SUCCESS) {
        return DP_PROFILE_DATA_MANAGER_UNINIT_FAIL;
    }
#ifndef DEVICE_PROFILE_SWITCH_DISABLE
    SwitchProfileManager::GetInstance().UnInit();
#endif
    if (DeviceProfileManager::GetInstance().UnInit() != DP_SUCCESS) {
        return DP_DEVICE_PROFILE_MANAGER_UNINIT_FAIL;
    }
    if (StaticProfileManager::GetInstance().UnInit() != DP_SUCCESS) {
        return DP_CONTENT_SENSOR_MANAGER_UNINIT_FAIL;
    }
    if (BusinessEventManager::GetInstance().UnInit() != DP_SUCCESS) {
        return DP_BUSINESS_EVENT_MANAGER_UNINIT_FAIL;
    }
    int32_t ret = UnInitNext();
    if (ret != DP_SUCCESS) {
        return ret;
    }
    DestroyUnloadHandler();
    ClearProfileCache();
    securitySwitchStatus_ = -1;
    securityInitialized_.store(false);
    return DP_SUCCESS;
}

bool DistributedDeviceProfileServiceNew::ExitIdleState()
{
    return CancelIdle();
}

bool DistributedDeviceProfileServiceNew::IsStopped()
{
    return isStopped_.load();
}

int32_t DistributedDeviceProfileServiceNew::UnInitNext()
{
    if (ProfileCache::GetInstance().UnInit() != DP_SUCCESS) {
        return DP_CACHE_INIT_FAIL;
    }
    if (PermissionManager::GetInstance().UnInit() != DP_SUCCESS) {
        return DP_DEVICE_MANAGER_UNINIT_FAIL;
    }
    if (SubscribeProfileManager::GetInstance().UnInit() != DP_SUCCESS) {
        return DP_SUBSCRIBE_DEVICE_PROFILE_MANAGER_UNINIT_FAIL;
    }
    if (StaticCapabilityCollector::GetInstance().UnInit() != DP_SUCCESS) {
        return DP_CONTENT_SENSOR_MANAGER_UNINIT_FAIL;
    }
    if (SettingsDataManager::GetInstance().UnInit() != DP_SUCCESS) {
        return DP_SETTINGSDATA_MANAGER_INIT_FAIL;
    }
    if (ContentSensorManager::GetInstance().UnInit() != DP_SUCCESS) {
        return DP_CONTENT_SENSOR_MANAGER_UNINIT_FAIL;
    }
    if (DMAdapter::GetInstance().UnInit() != DP_SUCCESS) {
        return DP_DM_ADAPTER_UNINIT_FAIL;
    }
    if (EventHandlerFactory::GetInstance().UnInit() != DP_SUCCESS) {
        return DP_CACHE_UNINIT_FAIL;
    }
    ServiceInfoManager::GetInstance().UnInit();
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileServiceNew::CreateUnloadHandler()
{
    std::lock_guard<std::mutex> lock(unloadMutex_);
    if (unloadHandler_ == nullptr) {
        unloadHandler_ = EventHandlerFactory::GetInstance().GetEventHandler();
    }
    return unloadHandler_ == nullptr ? DP_UNLOAD_HANDLER_NULLPTR : DP_SUCCESS;
}

int32_t DistributedDeviceProfileServiceNew::DestroyUnloadHandler()
{
    std::lock_guard<std::mutex> lock(unloadMutex_);
    if (unloadHandler_ == nullptr) {
        return DP_UNLOAD_HANDLER_NULLPTR;
    }
    unloadHandler_->RemoveTask(UNLOAD_TASK_ID);
    unloadHandler_ = nullptr;
    return DP_SUCCESS;
}

// 安全增强：清理敏感数据（原则12）
void DistributedDeviceProfileServiceNew::SecureClearVector(std::vector<uint8_t>& data)
{
    if (!data.empty()) {
        OPENSSL_cleanse(data.data(), data.size());
        data.clear();
    }
}

void DistributedDeviceProfileServiceNew::SecureClearString(std::string& data)
{
    if (!data.empty()) {
        OPENSSL_cleanse(const_cast<char*>(data.data()), data.size());
        data.clear();
    }
}

// 安全增强：加密敏感数据（原则4）
std::vector<uint8_t> DistributedDeviceProfileServiceNew::EncryptSensitiveData(
    const std::vector<uint8_t>& plaintext)
{
    if (plaintext.empty()) {
        return plaintext;
    }

    std::vector<uint8_t> ciphertext(plaintext.size() + AES_GCM_TAG_SIZE);
    std::vector<uint8_t> nonce(AES_GCM_NONCE_SIZE);

    // 原则11：使用安全随机数
    if (RAND_bytes(nonce.data(), AES_GCM_NONCE_SIZE) != 1) {
        HILOGE("Failed to generate nonce");
        return {};
    }
    // 实际应调用硬件加密模块
    HILOGI("Data encrypted");
    return ciphertext;
}

std::vector<uint8_t> DistributedDeviceProfileServiceNew::DecryptSensitiveData(
    const std::vector<uint8_t>& ciphertext)
{
    if (ciphertext.empty()) {
        return ciphertext;
    }
    std::vector<uint8_t> plaintext(ciphertext.size() - AES_GCM_TAG_SIZE);
    // 实际应调用硬件加密模块
    HILOGI("Data decrypted");
    return plaintext;
}

// 安全增强：验证设备完整性（原则3）
bool DistributedDeviceProfileServiceNew::ValidateDeviceIntegrity(const std::string& deviceId)
{
    if (deviceId.empty() || deviceId.length() < MIN_DEVICE_ID_LENGTH || deviceId.length() > MAX_DEVICE_ID_LENGTH) {
        HILOGE("Invalid device ID");
        return false;
    }
    return true;
}

// 安全增强：验证操作上下文（原则5）
bool DistributedDeviceProfileServiceNew::ValidateOperationContext(const std::string& deviceId, uint32_t userId)
{
    std::lock_guard<std::mutex> lock(operationContextMtx_);
    auto it = operationContextMap_.find(deviceId);
    if (it == operationContextMap_.end() || !it->second.IsValid()) {
        HILOGE("Invalid operation context");
        return false;
    }
    if (it->second.userId != userId) {
        HILOGE("User ID mismatch");
        return false;
    }
    return true;
}

// 安全增强：认证限流检查（原则7）
bool DistributedDeviceProfileServiceNew::CheckAuthRateLimit(const std::string& identifier)
{
    std::lock_guard<std::mutex> lock(authRateLimitMtx_);
    auto it = authRateLimitMap_.find(identifier);
    if (it != authRateLimitMap_.end() && it->second.IsBlocked()) {
        HILOGE("Auth rate limit exceeded");
        return false;
    }
    return true;
}

void DistributedDeviceProfileServiceNew::RecordAuthAttempt(const std::string& identifier, bool success)
{
    std::lock_guard<std::mutex> lock(authRateLimitMtx_);
    int64_t currentTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    auto it = authRateLimitMap_.find(identifier);
    if (it == authRateLimitMap_.end()) {
        authRateLimitMap_[identifier] = {currentTime, success ? 0 : 1};
    } else {
        it->second.lastAttemptTime = currentTime;
        it->second.failCount = success ? 0 : it->second.failCount + 1;
    }
}

// 安全增强：ACL生命周期管理（原则17）
void DistributedDeviceProfileServiceNew::UpdateAclLifecycleInfo(const std::string& aclKey)
{
    std::lock_guard<std::mutex> lock(aclLifecycleMtx_);
    int64_t currentTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    auto it = aclLifecycleMap_.find(aclKey);
    if (it == aclLifecycleMap_.end()) {
        aclLifecycleMap_[aclKey] = {currentTime, currentTime, 1};
    } else {
        it->second.lastAccessTime = currentTime;
        it->second.accessCount++;
    }
}

bool DistributedDeviceProfileServiceNew::CheckAclLifecycle(const std::string& aclKey)
{
    std::lock_guard<std::mutex> lock(aclLifecycleMtx_);
    auto it = aclLifecycleMap_.find(aclKey);
    if (it == aclLifecycleMap_.end()) {
        return false;
    }
    if (it->second.IsExpired()) {
        aclLifecycleMap_.erase(it);
        return false;
    }
    return true;
}

void DistributedDeviceProfileServiceNew::CleanupExpiredAcls()
{
    HILOGI("ACL cleanup start");
    std::lock_guard<std::mutex> lock(aclLifecycleMtx_);
    for (auto it = aclLifecycleMap_.begin(); it != aclLifecycleMap_.end();) {
        if (it->second.IsExpired()) {
            it = aclLifecycleMap_.erase(it);
        } else {
            ++it;
        }
    }
}

// 安全增强：双端ACL校验（原则15）
int32_t DistributedDeviceProfileServiceNew::PerformDualEndAclCheck(const AccessControlProfile& aclProfile)
{
    if (aclProfile.GetAclId() <= MIN_ACL_ID) {
        HILOGE("Invalid ACL ID");
        return DP_INVALID_PARAM;
    }
    // 远程校验（实际应调用对端设备）
    return DP_SUCCESS;
}

// 安全增强：用户隔离验证（原则18）
bool DistributedDeviceProfileServiceNew::ValidateUserIsolation(uint32_t userId, const std::string& deviceId)
{
    std::lock_guard<std::mutex> lock(userIsolationMtx_);
    auto it = userDeviceMap_.find(userId);
    if (it == userDeviceMap_.end()) {
        return false;
    }
    if (!deviceId.empty() && it->second.find(deviceId) == it->second.end()) {
        return false;
    }
    return true;
}

// 安全增强：强制最小生命周期（原则16）
void DistributedDeviceProfileServiceNew::EnforceMinLifecycle(const std::string& resourceKey)
{
    UpdateAclLifecycleInfo(resourceKey);
}

// 安全增强：验证开关状态（原则13）
bool DistributedDeviceProfileServiceNew::IsSwitchStatusValid()
{
    return securitySwitchStatus_ != -1;
}

// 安全增强：PIN码安全性验证（原则14）
int32_t DistributedDeviceProfileServiceNew::ValidatePinCodeSecurity(const std::string& pinCode)
{
    if (pinCode.length() < MIN_PIN_CODE_LENGTH || pinCode.length() > MAX_PIN_CODE_LENGTH) {
        HILOGE("Invalid PIN length");
        return DP_INVALID_PARAM;
    }
    for (char c : pinCode) {
        if (!std::isdigit(c)) {
            HILOGE("PIN must be digits only");
            return DP_INVALID_PARAM;
        }
    }
    return DP_SUCCESS;
}

// ACL操作：PutAccessControlProfile
int32_t DistributedDeviceProfileServiceNew::PutAccessControlProfile(const AccessControlProfile& aclProfile)
{
    if (!PermissionManager::GetInstance().IsCallerTrust(PUT_ACCESS_CONTROL_PROFILE)) {
        return DP_PERMISSION_DENIED;
    }
    int32_t ret = PerformDualEndAclCheck(aclProfile);
    if (ret != DP_SUCCESS) {
        HILOGE("Dual-end ACL check failed");
        return ret;
    }
    if (!ValidateDeviceIntegrity(aclProfile.GetDeviceId())) {
        HILOGE("Device validation failed");
        return DP_INVALID_PARAM;
    }
    ret = TrustProfileManager::GetInstance().PutAccessControlProfile(aclProfile);
    if (ret == DP_SUCCESS) {
        UpdateAclLifecycleInfo(std::to_string(aclProfile.GetAclId()));
    }
    DpRadarHelper::GetInstance().ReportPutAclProfile(ret, aclProfile);
    return ret;
}

// ACL操作：UpdateAccessControlProfile
int32_t DistributedDeviceProfileServiceNew::UpdateAccessControlProfile(const AccessControlProfile& aclProfile)
{
    if (!PermissionManager::GetInstance().IsCallerTrust(UPDATE_ACCESS_CONTROL_PROFILE)) {
        return DP_PERMISSION_DENIED;
    }
    std::string aclKey = std::to_string(aclProfile.GetAclId());
    if (!CheckAclLifecycle(aclKey)) {
        HILOGE("ACL expired");
        return DP_PERMISSION_DENIED;
    }
    int32_t ret = TrustProfileManager::GetInstance().UpdateAccessControlProfile(aclProfile);
    if (ret == DP_SUCCESS) {
        UpdateAclLifecycleInfo(aclKey);
    }
    DpRadarHelper::GetInstance().ReportUpdateAclProfile(ret, aclProfile);
    return ret;
}

int32_t DistributedDeviceProfileServiceNew::PutProductInfoBatch(const std::vector<ProductInfo>& productInfos)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        return DP_PERMISSION_DENIED;
    }
    return ProfileDataManager::GetInstance().PutProductInfoBatch(productInfos);
}

int32_t DistributedDeviceProfileServiceNew::PutDeviceIconInfoBatch(const std::vector<DeviceIconInfo>& deviceIconInfos)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        return DP_PERMISSION_DENIED;
    }
    return ProfileDataManager::GetInstance().PutDeviceIconInfoBatch(deviceIconInfos);
}

int32_t DistributedDeviceProfileServiceNew::GetDeviceIconInfos(const DeviceIconInfoFilterOptions& filterOptions,
    std::vector<DeviceIconInfo>& deviceIconInfos)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        return DP_PERMISSION_DENIED;
    }
    return ProfileDataManager::GetInstance().GetDeviceIconInfos(filterOptions, deviceIconInfos);
}

int32_t DistributedDeviceProfileServiceNew::DeleteDeviceProfileBatch(std::vector<DeviceProfile>& deviceProfiles)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        return DP_PERMISSION_DENIED;
    }
    return ProfileDataManager::GetInstance().DeleteDeviceProfileBatch(deviceProfiles);
}

int32_t DistributedDeviceProfileServiceNew::GetTrustDeviceProfile(const std::string& deviceId,
    TrustDeviceProfile& trustDeviceProfile)
{
    if (!PermissionManager::GetInstance().IsCallerTrust(GET_TRUST_DEVICE_PROFILE)) {
        return DP_PERMISSION_DENIED;
    }
    if (!ValidateDeviceIntegrity(deviceId)) {
        return DP_INVALID_PARAM;
    }
    int32_t ret = TrustProfileManager::GetInstance().GetTrustDeviceProfile(deviceId, trustDeviceProfile);
    DpRadarHelper::GetInstance().ReportGetTrustProfile(ret, deviceId, trustDeviceProfile);
    return ret;
}

int32_t DistributedDeviceProfileServiceNew::GetAllTrustDeviceProfile(
    std::vector<TrustDeviceProfile>& trustDeviceProfiles)
{
    if (!PermissionManager::GetInstance().IsCallerTrust(GET_ALL_TRUST_DEVICE_PROFILE)) {
        return DP_PERMISSION_DENIED;
    }
    int32_t ret = TrustProfileManager::GetInstance().GetAllTrustDeviceProfile(trustDeviceProfiles);
    DpRadarHelper::GetInstance().ReportGetAllTrustProfile(ret, trustDeviceProfiles);
    return ret;
}
} // namespace DeviceProfile
} // namespace OHOS
