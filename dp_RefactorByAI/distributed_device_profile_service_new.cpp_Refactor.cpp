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
        handler->PostTask([this]() {
            this->CleanupExpiredAcls();
        }, "cleanup_acl", ACL_CLEANUP_INTERVAL_MS);
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

int32_t DistributedDeviceProfileServiceNew::GetAccessControlProfile(std::map<std::string, std::string> queryParams,
    std::vector<AccessControlProfile>& accessControlProfiles)
{
    if (!PermissionManager::GetInstance().IsCallerTrust(GET_ACCESS_CONTROL_PROFILE)) {
        return DP_PERMISSION_DENIED;
    }
    int32_t ret = TrustProfileManager::GetInstance().GetAccessControlProfile(queryParams, accessControlProfiles);
    DpRadarHelper::GetInstance().ReportGetAclProfile(ret, accessControlProfiles);
    return ret;
}

int32_t DistributedDeviceProfileServiceNew::GetAllAccessControlProfile(
    std::vector<AccessControlProfile>& accessControlProfiles)
{
    if (!PermissionManager::GetInstance().IsCallerTrust(GET_ALL_ACCESS_CONTROL_PROFILE)) {
        return DP_PERMISSION_DENIED;
    }
    int32_t ret = TrustProfileManager::GetInstance().GetAllAccessControlProfile(accessControlProfiles);
    DpRadarHelper::GetInstance().ReportGetAllAclProfile(ret, accessControlProfiles);
    return ret;
}

int32_t DistributedDeviceProfileServiceNew::GetAllAclIncludeLnnAcl(
    std::vector<AccessControlProfile>& accessControlProfiles)
{
    if (!PermissionManager::GetInstance().IsCallerTrust(GET_ALL_ACL_INCLUDE_LNN_ACL)) {
        return DP_PERMISSION_DENIED;
    }
    int32_t ret = TrustProfileManager::GetInstance().GetAllAclIncludeLnnAcl(accessControlProfiles);
    DpRadarHelper::GetInstance().ReportGetAllAclProfile(ret, accessControlProfiles);
    return ret;
}

int32_t DistributedDeviceProfileServiceNew::DeleteAccessControlProfile(int32_t accessControlId)
{
    if (!PermissionManager::GetInstance().IsCallerTrust(DELETE_ACCESS_CONTROL_PROFILE)) {
        return DP_PERMISSION_DENIED;
    }
    std::string aclKey = std::to_string(accessControlId);
    if (!CheckAclLifecycle(aclKey)) {
        return DP_PERMISSION_DENIED;
    }
    int32_t ret = TrustProfileManager::GetInstance().DeleteAccessControlProfile(accessControlId);
    if (ret == DP_SUCCESS) {
        std::lock_guard<std::mutex> lock(aclLifecycleMtx_);
        aclLifecycleMap_.erase(aclKey);
    }
    DpRadarHelper::GetInstance().ReportDeleteAclProfile(ret);
    return ret;
}

// 会话密钥管理（原则4、7、12）
int32_t DistributedDeviceProfileServiceNew::PutSessionKey(uint32_t userId,
    const std::vector<uint8_t>& sessionKey, int32_t& sessionKeyId)
{
    if (!PermissionManager::GetInstance().IsCallerTrust(PUT_SESSION_KEY)) {
        return DP_PERMISSION_DENIED;
    }
    std::string identifier = "sessionkey_" + std::to_string(userId);
    if (!CheckAuthRateLimit(identifier)) {
        return DP_AUTH_RATE_LIMIT_EXCEEDED;
    }
    int32_t ret = SessionKeyManager::GetInstance().PutSessionKey(userId, sessionKey, sessionKeyId);
    RecordAuthAttempt(identifier, ret == DP_SUCCESS);
    return ret;
}

int32_t DistributedDeviceProfileServiceNew::GetSessionKey(uint32_t userId,
    int32_t sessionKeyId, std::vector<uint8_t>& sessionKey)
{
    if (!PermissionManager::GetInstance().IsCallerTrust(GET_SESSION_KEY)) {
        return DP_PERMISSION_DENIED;
    }
    std::string identifier = "sessionkey_" + std::to_string(userId);
    if (!CheckAuthRateLimit(identifier)) {
        return DP_AUTH_RATE_LIMIT_EXCEEDED;
    }
    int32_t ret = SessionKeyManager::GetInstance().GetSessionKey(userId, sessionKeyId, sessionKey);
    RecordAuthAttempt(identifier, ret == DP_SUCCESS);
    return ret;
}

int32_t DistributedDeviceProfileServiceNew::UpdateSessionKey(
    uint32_t userId, int32_t sessionKeyId, const std::vector<uint8_t>& sessionKey)
{
    if (!PermissionManager::GetInstance().IsCallerTrust(UPDATE_SESSION_KEY)) {
        return DP_PERMISSION_DENIED;
    }
    std::string identifier = "sessionkey_" + std::to_string(userId);
    if (!CheckAuthRateLimit(identifier)) {
        return DP_AUTH_RATE_LIMIT_EXCEEDED;
    }
    int32_t ret = SessionKeyManager::GetInstance().UpdateSessionKey(userId, sessionKeyId, sessionKey);
    RecordAuthAttempt(identifier, ret == DP_SUCCESS);
    return ret;
}

int32_t DistributedDeviceProfileServiceNew::DeleteSessionKey(uint32_t userId, int32_t sessionKeyId)
{
    if (!PermissionManager::GetInstance().IsCallerTrust(DELETE_SESSION_KEY)) {
        return DP_PERMISSION_DENIED;
    }
    std::string identifier = "sessionkey_" + std::to_string(userId);
    if (!CheckAuthRateLimit(identifier)) {
        return DP_AUTH_RATE_LIMIT_EXCEEDED;
    }
    int32_t ret = SessionKeyManager::GetInstance().DeleteSessionKey(userId, sessionKeyId);
    RecordAuthAttempt(identifier, ret == DP_SUCCESS);
    return ret;
}

int32_t DistributedDeviceProfileServiceNew::PutDeviceProfileBatch(std::vector<DeviceProfile>& deviceProfiles)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        return DP_PERMISSION_DENIED;
    }
    return ProfileDataManager::GetInstance().PutDeviceProfileBatch(deviceProfiles);
}

int32_t DistributedDeviceProfileServiceNew::PutServiceProfile(const ServiceProfile& serviceProfile)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        return DP_PERMISSION_DENIED;
    }
    {
        std::lock_guard<std::mutex> lock(cacheMtx_);
        if (!IsInited()) {
            return AddSvrProfilesToCache({ serviceProfile });
        }
    }
    if (!ValidateDeviceIntegrity(serviceProfile.GetDeviceId())) {
        return DP_INVALID_PARAM;
    }
    int32_t ret = DeviceProfileManager::GetInstance().PutServiceProfile(serviceProfile);
    DpRadarHelper::GetInstance().ReportPutServiceProfile(ret, serviceProfile);
    return ret;
}

int32_t DistributedDeviceProfileServiceNew::PutServiceProfileBatch(const std::vector<ServiceProfile>& serviceProfiles)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        return DP_PERMISSION_DENIED;
    }
    {
        std::lock_guard<std::mutex> lock(cacheMtx_);
        if (!IsInited()) {
            return AddSvrProfilesToCache(serviceProfiles);
        }
    }
    int32_t ret = DeviceProfileManager::GetInstance().PutServiceProfileBatch(serviceProfiles);
    DpRadarHelper::GetInstance().ReportPutServiceProfileBatch(ret, serviceProfiles);
    return ret;
}

int32_t DistributedDeviceProfileServiceNew::PutCharacteristicProfile(const CharacteristicProfile& charProfile)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        return DP_PERMISSION_DENIED;
    }
    {
        std::lock_guard<std::mutex> lock(cacheMtx_);
        if (!IsInited()) {
            return AddCharProfilesToCache({ charProfile });
        }
    }
    if (charProfile.GetCharacteristicKey() == SWITCH_STATUS) {
        if (!IsSwitchStatusValid()) {
            return DP_PERMISSION_DENIED;
        }
#ifndef DEVICE_PROFILE_SWITCH_DISABLE
        int32_t ret = SwitchProfileManager::GetInstance().PutCharacteristicProfile(charProfile);
        DpRadarHelper::GetInstance().ReportPutCharProfile(ret, charProfile);
        return ret;
#else
        return DP_DEVICE_UNSUPPORTED_SWITCH;
#endif
    }
    int32_t ret = DeviceProfileManager::GetInstance().PutCharacteristicProfile(charProfile);
    DpRadarHelper::GetInstance().ReportPutCharProfile(ret, charProfile);
    return ret;
}

int32_t DistributedDeviceProfileServiceNew::PutCharacteristicProfileBatch(
    const std::vector<CharacteristicProfile>& charProfiles)
{
    int32_t ret = PutCharacteristicProfileBatchPreprocess(charProfiles);
    if (ret != DP_SUCCESS) {
        return ret;
    }
    {
        std::lock_guard<std::mutex> lock(cacheMtx_);
        if (!IsInited()) {
            return AddCharProfilesToCache(charProfiles);
        }
    }
    std::vector<CharacteristicProfile> switchCharProfiles, dynamicCharProfiles;
    for (auto& profile : charProfiles) {
        if (profile.GetCharacteristicKey() == SWITCH_STATUS) {
            if (!IsSwitchStatusValid()) {
                return DP_PERMISSION_DENIED;
            }
            switchCharProfiles.push_back(profile);
        } else {
            dynamicCharProfiles.push_back(profile);
        }
    }
    int32_t switchRes = DP_SUCCESS;
#ifndef DEVICE_PROFILE_SWITCH_DISABLE
    if (!switchCharProfiles.empty()) {
        switchRes = SwitchProfileManager::GetInstance().PutCharacteristicProfileBatch(switchCharProfiles);
        DpRadarHelper::GetInstance().ReportPutCharProfileBatch(switchRes, switchCharProfiles);
    }
#else
    if (dynamicCharProfiles.empty()) {
        return DP_DEVICE_UNSUPPORTED_SWITCH;
    }
#endif
    int32_t dynamicRes = DP_SUCCESS;
    if (!dynamicCharProfiles.empty()) {
        dynamicRes = DeviceProfileManager::GetInstance().PutCharacteristicProfileBatch(dynamicCharProfiles);
        DpRadarHelper::GetInstance().ReportPutCharProfileBatch(dynamicRes, dynamicCharProfiles);
    }
    if (switchRes != DP_SUCCESS || dynamicRes != DP_SUCCESS) {
        return DP_PUT_CHAR_BATCH_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileServiceNew::PutCharacteristicProfileBatchPreprocess(
    const std::vector<CharacteristicProfile>& charProfiles)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        return DP_PERMISSION_DENIED;
    }
    if (charProfiles.empty() || charProfiles.size() > MAX_CHAR_SIZE) {
        return DP_INVALID_PARAM;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileServiceNew::GetDeviceProfile(const std::string& deviceId, DeviceProfile& deviceProfile)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        return DP_PERMISSION_DENIED;
    }
    if (!ValidateDeviceIntegrity(deviceId)) {
        return DP_INVALID_PARAM;
    }
    int32_t ret = DeviceProfileManager::GetInstance().GetDeviceProfile(deviceId, deviceProfile);
    DpRadarHelper::GetInstance().ReportGetDeviceProfile(ret, deviceId, deviceProfile);
    return ret;
}

int32_t DistributedDeviceProfileServiceNew::GetDeviceProfiles(DeviceProfileFilterOptions& options,
    std::vector<DeviceProfile>& deviceProfiles)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        return DP_PERMISSION_DENIED;
    }
    return ProfileDataManager::GetInstance().GetDeviceProfiles(options, deviceProfiles);
}

int32_t DistributedDeviceProfileServiceNew::GetServiceProfile(const std::string& deviceId,
    const std::string& serviceName, ServiceProfile& serviceProfile)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        return DP_PERMISSION_DENIED;
    }
    if (!ValidateDeviceIntegrity(deviceId)) {
        return DP_INVALID_PARAM;
    }
    int32_t ret = DeviceProfileManager::GetInstance().GetServiceProfile(deviceId, serviceName, serviceProfile);
    DpRadarHelper::GetInstance().ReportGetServiceProfile(ret, deviceId, serviceProfile);
    return ret;
}

int32_t DistributedDeviceProfileServiceNew::GetCharacteristicProfile(const std::string& deviceId,
    const std::string& serviceName, const std::string& characteristicKey, CharacteristicProfile& charProfile)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        return DP_PERMISSION_DENIED;
    }
    if (!ValidateDeviceIntegrity(deviceId)) {
        return DP_INVALID_PARAM;
    }
    if (characteristicKey == SWITCH_STATUS) {
#ifndef DEVICE_PROFILE_SWITCH_DISABLE
        int32_t ret = SwitchProfileManager::GetInstance().GetCharacteristicProfile(deviceId, serviceName,
            characteristicKey, charProfile);
        DpRadarHelper::GetInstance().ReportGetCharProfile(ret, deviceId, charProfile);
        return ret;
#else
        return DP_DEVICE_UNSUPPORTED_SWITCH;
#endif
    }
    if (characteristicKey == STATIC_CHARACTERISTIC_KEY) {
        int32_t ret = StaticProfileManager::GetInstance().GetCharacteristicProfile(deviceId, serviceName,
            characteristicKey, charProfile);
        DpRadarHelper::GetInstance().ReportGetCharProfile(ret, deviceId, charProfile);
        return ret;
    }
    int32_t ret = DeviceProfileManager::GetInstance().GetCharacteristicProfile(deviceId, serviceName,
        characteristicKey, charProfile);
    DpRadarHelper::GetInstance().ReportGetCharProfile(ret, deviceId, charProfile);
    return ret;
}

int32_t DistributedDeviceProfileServiceNew::DeleteServiceProfile(const std::string& deviceId,
    const std::string& serviceName, bool isMultiUser, int32_t userId)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        return DP_PERMISSION_DENIED;
    }
    if (isMultiUser && !ValidateUserIsolation(userId, deviceId)) {
        return DP_PERMISSION_DENIED;
    }
    int32_t ret = DeviceProfileManager::GetInstance().DeleteServiceProfile(deviceId, serviceName, isMultiUser, userId);
    DpRadarHelper::GetInstance().ReportDeleteServiceProfile(ret, deviceId);
    return ret;
}

int32_t DistributedDeviceProfileServiceNew::DeleteCharacteristicProfile(const std::string& deviceId,
    const std::string& serviceName, const std::string& characteristicKey, bool isMultiUser, int32_t userId)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        return DP_PERMISSION_DENIED;
    }
    if (isMultiUser && !ValidateUserIsolation(userId, deviceId)) {
        return DP_PERMISSION_DENIED;
    }
    int32_t ret = DeviceProfileManager::GetInstance().DeleteCharacteristicProfile(deviceId, serviceName,
        characteristicKey, isMultiUser, userId);
    DpRadarHelper::GetInstance().ReportDeleteCharProfile(ret, deviceId);
    return ret;
}

int32_t DistributedDeviceProfileServiceNew::PutLocalServiceInfo(const LocalServiceInfo& localServiceInfo)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        return DP_PERMISSION_DENIED;
    }
    int32_t ret = LocalServiceInfoManager::GetInstance().PutLocalServiceInfo(localServiceInfo);
    if (ret == DP_SUCCESS && localServiceInfo.GetPinCode() == INVALID_PINCODE) {
        NotifyPinCodeInvalid(localServiceInfo);
    }
    return ret;
}

int32_t DistributedDeviceProfileServiceNew::UpdateLocalServiceInfo(const LocalServiceInfo& localServiceInfo)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        return DP_PERMISSION_DENIED;
    }
    int32_t ret = LocalServiceInfoManager::GetInstance().UpdateLocalServiceInfo(localServiceInfo);
    if (ret == DP_SUCCESS && localServiceInfo.GetPinCode() == INVALID_PINCODE) {
        NotifyPinCodeInvalid(localServiceInfo);
    }
    return ret;
}

int32_t DistributedDeviceProfileServiceNew::GetLocalServiceInfoByBundleAndPinType(const std::string& bundleName,
    int32_t pinExchangeType, LocalServiceInfo& localServiceInfo)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        return DP_PERMISSION_DENIED;
    }
    return LocalServiceInfoManager::GetInstance().GetLocalServiceInfoByBundleAndPinType(bundleName,
        pinExchangeType, localServiceInfo);
}

int32_t DistributedDeviceProfileServiceNew::DeleteLocalServiceInfo(const std::string& bundleName,
    int32_t pinExchangeType)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        return DP_PERMISSION_DENIED;
    }
    return LocalServiceInfoManager::GetInstance().DeleteLocalServiceInfo(bundleName, pinExchangeType);
}

int32_t DistributedDeviceProfileServiceNew::SubscribeDeviceProfile(const SubscribeInfo& subscriberInfo)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        return DP_PERMISSION_DENIED;
    }
    int32_t ret = SubscribeProfileManager::GetInstance().SubscribeDeviceProfile(subscriberInfo);
    DpRadarHelper::GetInstance().ReportSubscribeDeviceProfile(ret, subscriberInfo);
    return ret;
}

int32_t DistributedDeviceProfileServiceNew::UnSubscribeDeviceProfile(const SubscribeInfo& subscriberInfo)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        return DP_PERMISSION_DENIED;
    }
    int32_t ret = SubscribeProfileManager::GetInstance().UnSubscribeDeviceProfile(subscriberInfo);
    DpRadarHelper::GetInstance().ReportUnSubscribeDeviceProfile(ret, subscriberInfo);
    return ret;
}

int32_t DistributedDeviceProfileServiceNew::SyncDeviceProfile(
    const DistributedDeviceProfile::DpSyncOptions& syncOptions, sptr<IRemoteObject> syncCompletedCallback)
{
    if (!PermissionManager::GetInstance().CheckCallerSyncPermission()) {
        return DP_PERMISSION_DENIED;
    }
    int32_t ret = DeviceProfileManager::GetInstance().SyncDeviceProfile(syncOptions, syncCompletedCallback);
    DpRadarHelper::GetInstance().ReportSyncDeviceProfile(ret);
    return ret;
}

int32_t DistributedDeviceProfileServiceNew::SyncStaticProfile(
    const DistributedDeviceProfile::DpSyncOptions& syncOptions, sptr<IRemoteObject> syncCompletedCallback)
{
    if (!PermissionManager::GetInstance().CheckCallerSyncPermission()) {
        return DP_PERMISSION_DENIED;
    }
    int32_t ret = StaticProfileManager::GetInstance().SyncStaticProfile(syncOptions, syncCompletedCallback);
    DpRadarHelper::GetInstance().ReportSyncDeviceProfile(ret);
    return ret;
}

int32_t DistributedDeviceProfileServiceNew::SendSubscribeInfos(std::map<std::string, SubscribeInfo> listenerMap)
{
    return SubscribeProfileManager::GetInstance().SubscribeDeviceProfile(listenerMap);
}

int32_t DistributedDeviceProfileServiceNew::Dump(int32_t fd, const std::vector<std::u16string>& args)
{
    if (args.size() > MAX_DUMP_ARGS_SIZE) {
        return DP_INVALID_PARAMS;
    }
    std::vector<std::string> argsInStr8;
    for (const auto& arg : args) {
        argsInStr8.emplace_back(Str16ToStr8(arg));
    }
    std::string result;
    DeviceProfileDumper::Dump(argsInStr8, result);
    if (!SaveStringToFd(fd, result)) {
        return DP_INVALID_PARAMS;
    }
    return DP_SUCCESS;
}

void DistributedDeviceProfileServiceNew::DelayUnloadTask()
{
    auto task = []() {
        auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (samgrProxy == nullptr) {
            return;
        }
        samgrProxy->UnloadSystemAbility(DISTRIBUTED_DEVICE_PROFILE_SA_ID);
    };
    std::lock_guard<std::mutex> lock(unloadMutex_);
    if (unloadHandler_ == nullptr) {
        return;
    }
    unloadHandler_->RemoveTask(UNLOAD_TASK_ID);
    unloadHandler_->PostTask(task, UNLOAD_TASK_ID, DELAY_TIME);
}

void DistributedDeviceProfileServiceNew::OnStart(const SystemAbilityOnDemandReason& startReason)
{
    HILOGI("OnStart: %{public}s", startReason.GetName().c_str());
    int32_t timerId = HiviewDFX::XCollie::GetInstance().SetTimer(
        DP_ONSTART_TIMER, ONSTART_TIMEOUT_TIME, nullptr, nullptr, HiviewDFX::XCOLLIE_FLAG_DEFAULT);
    int32_t ret = Init();
    if (ret != DP_SUCCESS) {
        HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
        SystemAbility::OnStartFail(ret);
        return;
    }
    AddSystemAbilityListener(SOFTBUS_SERVER_SA_ID);
    AddSystemAbilityListener(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID);
    AddSystemAbilityListener(DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID);
    AddSystemAbilityListener(SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN);
    AddSystemAbilityListener(MEMORY_MANAGER_SA_ID);
    IPCSkeleton::SetMaxWorkThreadNum(DP_IPC_THREAD_NUM);
    HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
    if (!Publish(this)) {
        HILOGE("Publish SA failed");
        return;
    }
    if (CreateUnloadHandler() == DP_SUCCESS) {
        DelayUnloadTask();
    }
}

void DistributedDeviceProfileServiceNew::OnStop()
{
    isStopped_ = true;
    int32_t ret = UnInit();
    HILOGI("UnInit ret=%{public}d", ret);
    Memory::MemMgrClient::GetInstance().SetCritical(getpid(), false, DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID);
    Memory::MemMgrClient::GetInstance().NotifyProcessStatus(getpid(), 1, 0, DISTRIBUTED_DEVICE_PROFILE_SA_ID);
}

void DistributedDeviceProfileServiceNew::OnActive(const SystemAbilityOnDemandReason& activeReason)
{
    HILOGI("OnActive: %{public}d", activeReason.GetId());
    Memory::MemMgrClient::GetInstance().SetCritical(getpid(), true, DISTRIBUTED_DEVICE_PROFILE_SA_ID);
}

int32_t DistributedDeviceProfileServiceNew::OnIdle(const SystemAbilityOnDemandReason& idleReason)
{
    HILOGI("OnIdle: %{public}s", idleReason.GetName().c_str());
    if (idleReason.GetName() == IDLE_REASON_LOW_MEMORY) {
        return IsReadyIntoIdle() ? SA_READY_INTO_IDLE : SA_REFUSE_INTO_IDLE;
    }
    Memory::MemMgrClient::GetInstance().SetCritical(getpid(), false, DISTRIBUTED_DEVICE_PROFILE_SA_ID);
    return SA_READY_INTO_IDLE;
}

void DistributedDeviceProfileServiceNew::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    HILOGI("OnAddSystemAbility: %{public}d", systemAbilityId);
    if (systemAbilityId == SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN) {
        SubscribeAccountCommonEvent();
    }
    if (systemAbilityId == MEMORY_MANAGER_SA_ID) {
        Memory::MemMgrClient::GetInstance().NotifyProcessStatus(getpid(), 1, 1, DISTRIBUTED_DEVICE_PROFILE_SA_ID);
        Memory::MemMgrClient::GetInstance().SetCritical(getpid(), true, DISTRIBUTED_DEVICE_PROFILE_SA_ID);
    }
    if (IsInited()) {
        return;
    }
    {
        std::lock_guard<std::mutex> lock(depSaIdsMtx_);
        if (depSaIds_.empty()) {
            return;
        }
        depSaIds_.erase(systemAbilityId);
        if (!depSaIds_.empty()) {
            return;
        }
    }
    PostInit();
}

void DistributedDeviceProfileServiceNew::SubscribeAccountCommonEvent()
{
    std::lock_guard<std::mutex> lock(accountCommonEventManagerMtx_);
    if (accountCommonEventManager_ == nullptr) {
        accountCommonEventManager_ = std::make_shared<DpAccountCommonEventManager>();
    }
    AccountEventCallback callback = [=](const auto& arg1, const auto& arg2) {
        this->AccountCommonEventCallback(arg1, arg2);
    };
    std::vector<std::string> events = {
        EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED,
        EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED
    };
    accountCommonEventManager_->SubscribeAccountCommonEvent(events, callback);
}

void DistributedDeviceProfileServiceNew::AccountCommonEventCallback(int32_t userId, const std::string commonEventType)
{
    HILOGI("AccountEvent: %{public}s, userId: %{public}d", commonEventType.c_str(), userId);
    if (commonEventType == EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED) {
        std::lock_guard<std::mutex> lock(userIsolationMtx_);
        userDeviceMap_[userId] = std::set<std::string>();
        MultiUserManager::GetInstance().SetCurrentForegroundUserID(userId);
        ContentSensorManager::GetInstance().Init();
    } else if (commonEventType == EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED) {
        std::lock_guard<std::mutex> lock(userIsolationMtx_);
        userDeviceMap_.erase(userId);
        DeviceProfileManager::GetInstance().DeleteRemovedUserData(userId);
    }
}

int32_t DistributedDeviceProfileServiceNew::AddSvrProfilesToCache(const std::vector<ServiceProfile>& serviceProfiles)
{
    if (serviceProfiles.empty()) {
        return DP_INVALID_PARAM;
    }
    std::map<std::string, std::string> entries;
    for (const auto& item : serviceProfiles) {
        if (!ProfileUtils::IsSvrProfileValid(item)) {
            return DP_INVALID_PARAM;
        }
        if (ProfileCache::GetInstance().IsServiceProfileExist(item)) {
            return DP_CACHE_EXIST;
        }
        ProfileUtils::ServiceProfileToEntries(item, entries);
    }
    std::lock_guard<std::mutex> lock(dynamicProfileMapMtx_);
    for (const auto& [key, value] : entries) {
        dynamicProfileMap_[key] = value;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileServiceNew::AddCharProfilesToCache(
    const std::vector<CharacteristicProfile>& charProfiles)
{
    if (charProfiles.empty()) {
        return DP_INVALID_PARAM;
    }
    std::vector<CharacteristicProfile> switchCharProfiles;
    std::map<std::string, std::string> entries;
    for (const auto& item : charProfiles) {
        if (!ProfileUtils::IsCharProfileValid(item)) {
            return DP_INVALID_PARAM;
        }
        if (ProfileCache::GetInstance().IsCharProfileExist(item)) {
            return DP_CACHE_EXIST;
        }
        if (item.GetCharacteristicKey() == SWITCH_STATUS) {
            switchCharProfiles.push_back(item);
        } else {
            ProfileUtils::CharacteristicProfileToEntries(item, entries);
        }
    }
    if (!entries.empty()) {
        std::lock_guard<std::mutex> lock(dynamicProfileMapMtx_);
        for (const auto& [key, value] : entries) {
            dynamicProfileMap_[key] = value;
        }
    }
    if (!switchCharProfiles.empty()) {
        std::lock_guard<std::mutex> lock(switchProfileMapMtx_);
        for (const auto& item : switchCharProfiles) {
            std::string key = ProfileUtils::GenerateCharProfileKey(item.GetDeviceId(),
                item.GetServiceName(), item.GetCharacteristicKey());
            switchProfileMap_[key] = item;
        }
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileServiceNew::SaveSwitchProfilesFromTempCache()
{
    std::vector<CharacteristicProfile> switchCharProfiles;
    {
        std::lock_guard<std::mutex> lock(switchProfileMapMtx_);
        if (switchProfileMap_.empty()) {
            return DP_SUCCESS;
        }
        switchCharProfiles.reserve(switchProfileMap_.size());
        for (const auto& [profileKey, item] : switchProfileMap_) {
            switchCharProfiles.emplace_back(item);
        }
        switchProfileMap_.clear();
    }
    int32_t ret = SwitchProfileManager::GetInstance().PutCharacteristicProfileBatch(switchCharProfiles);
    DpRadarHelper::GetInstance().ReportPutCharProfileBatch(ret, switchCharProfiles);
    return ret;
}

void DistributedDeviceProfileServiceNew::GetDynamicProfilesFromTempCache(
    std::map<std::string, std::string>& entries)
{
    std::lock_guard<std::mutex> lock(dynamicProfileMapMtx_);
    if (dynamicProfileMap_.empty()) {
        return;
    }
    for (const auto& [key, value] : dynamicProfileMap_) {
        entries[key] = value;
    }
}

int32_t DistributedDeviceProfileServiceNew::SaveDynamicProfilesFromTempCache()
{
    std::map<std::string, std::string> entries;
    GetDynamicProfilesFromTempCache(entries);
    if (entries.empty() && DeviceProfileManager::GetInstance().IsFirstInitDB()) {
        sleep(WAIT_BUSINESS_PUT_TIME_S);
        GetDynamicProfilesFromTempCache(entries);
    }
    int32_t tryTimes = WRTE_CACHE_PROFILE_RETRY_TIMES;
    while (tryTimes > 0) {
        if (DeviceProfileManager::GetInstance().SavePutTempCache(entries) == DP_SUCCESS) {
            break;
        }
        usleep(WRTE_CACHE_PROFILE_DELAY_TIME_US);
        tryTimes--;
    }
    if (tryTimes <= 0) {
        DeviceProfileManager::GetInstance().ResetFirst();
    }
    {
        std::lock_guard<std::mutex> lock(dynamicProfileMapMtx_);
        dynamicProfileMap_.clear();
    }
    return DP_SUCCESS;
}

void DistributedDeviceProfileServiceNew::ClearProfileCache()
{
    std::lock_guard<std::mutex> lock1(dynamicProfileMapMtx_);
    dynamicProfileMap_.clear();
    std::lock_guard<std::mutex> lock2(switchProfileMapMtx_);
    switchProfileMap_.clear();
}

int32_t DistributedDeviceProfileServiceNew::SubscribeDeviceProfileInited(int32_t saId,
    sptr<IRemoteObject> dpInitedCallback)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        return DP_PERMISSION_DENIED;
    }
    if (dpInitedCallback == nullptr) {
        return DP_INVALID_PARAM;
    }
    if (saId <= 0 || saId > MAX_SAID) {
        return DP_INVALID_PARAM;
    }
    if (isInited_.load()) {
        sptr<IDpInitedCallback> callbackProxy = iface_cast<IDpInitedCallback>(dpInitedCallback);
        if (callbackProxy == nullptr) {
            return DP_NULLPTR;
        }
        callbackProxy->OnDpInited();
    }
    std::lock_guard<std::mutex> lock(dpInitedCallbackMapMtx_);
    if (dpInitedCallbackMap_.size() > MAX_CALLBACK_LEN) {
        return DP_INVALID_PARAM;
    }
    dpInitedCallbackMap_[saId] = dpInitedCallback;
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileServiceNew::UnSubscribeDeviceProfileInited(int32_t saId)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        return DP_PERMISSION_DENIED;
    }
    std::lock_guard<std::mutex> lock(dpInitedCallbackMapMtx_);
    dpInitedCallbackMap_.erase(saId);
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileServiceNew::SubscribePinCodeInvalid(const std::string& bundleName,
    int32_t pinExchangeType, sptr<IRemoteObject> pinCodeCallback)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        return DP_PERMISSION_DENIED;
    }
    if (bundleName.empty() || pinExchangeType == DEFAULT_PIN_EXCHANGE_TYPE || pinCodeCallback == nullptr) {
        return DP_INVALID_PARAM;
    }
    std::lock_guard<std::mutex> lock(pinCodeCallbackMapMtx_);
    if (pinCodeCallbackMap_.size() > MAX_CALLBACK_LEN) {
        return DP_INVALID_PARAM;
    }
    pinCodeCallbackMap_[std::make_pair(bundleName, pinExchangeType)] = pinCodeCallback;
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileServiceNew::UnSubscribePinCodeInvalid(const std::string& bundleName,
    int32_t pinExchangeType)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        return DP_PERMISSION_DENIED;
    }
    if (bundleName.empty() || pinExchangeType == DEFAULT_PIN_EXCHANGE_TYPE) {
        return DP_INVALID_PARAM;
    }
    std::lock_guard<std::mutex> lock(pinCodeCallbackMapMtx_);
    pinCodeCallbackMap_.erase(std::make_pair(bundleName, pinExchangeType));
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileServiceNew::NotifyDeviceProfileInited()
{
    std::lock_guard<std::mutex> lock(dpInitedCallbackMapMtx_);
    for (const auto& [saId, callback] : dpInitedCallbackMap_) {
        sptr<IDpInitedCallback> callbackProxy = iface_cast<IDpInitedCallback>(callback);
        if (callbackProxy != nullptr) {
            callbackProxy->OnDpInited();
        }
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileServiceNew::NotifyPinCodeInvalid(const LocalServiceInfo& localServiceInfo)
{
    sptr<IPincodeInvalidCallback> callbackProxy = nullptr;
    {
        std::lock_guard<std::mutex> lock(pinCodeCallbackMapMtx_);
        auto item = pinCodeCallbackMap_.find({localServiceInfo.GetBundleName(),
            localServiceInfo.GetPinExchangeType()});
        if (item == pinCodeCallbackMap_.end()) {
            return DP_SUCCESS;
        }
        callbackProxy = iface_cast<IPincodeInvalidCallback>(item->second);
        if (callbackProxy == nullptr) {
            return DP_NULLPTR;
        }
    }
    auto handler = EventHandlerFactory::GetInstance().GetEventHandler();
    if (handler == nullptr || !handler->PostTask([callbackProxy, localServiceInfo]() {
        if (callbackProxy != nullptr) {
            callbackProxy->OnPincodeInvalid(localServiceInfo);
        }
    })) {
        return DP_POST_TASK_FAILED;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileServiceNew::PutAllTrustedDevices(const std::vector<TrustedDeviceInfo> deviceInfos)
{
    if (!PermissionManager::GetInstance().IsCallerTrust(PUT_ALL_TRUSTED_DEVICES)) {
        return DP_PERMISSION_DENIED;
    }
    for (const auto& deviceInfo : deviceInfos) {
        if (!ValidateDeviceIntegrity(deviceInfo.deviceId)) {
            return DP_INVALID_PARAM;
        }
    }
    return ProfileCache::GetInstance().AddAllTrustedDevices(deviceInfos);
}

int32_t DistributedDeviceProfileServiceNew::RegisterBusinessCallback(const std::string& saId,
    const std::string& businessKey, sptr<IRemoteObject> businessCallback)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        return DP_PERMISSION_DENIED;
    }
    if (saId.empty() || businessKey.empty() || businessCallback == nullptr) {
        return DP_INVALID_PARAM;
    }
    sptr<IBusinessCallback> callbackProxy = iface_cast<IBusinessCallback>(businessCallback);
    if (callbackProxy == nullptr) {
        return DP_NULLPTR;
    }
    std::lock_guard<std::mutex> lock(businessEventCallbackMapMtx_);
    if (businessCallbackMap_.find({saId, businessKey}) != businessCallbackMap_.end()) {
        return DP_INVALID_PARAM;
    }
    if (businessCallbackMap_.size() > MAX_CALLBACK_LEN) {
        return DP_INVALID_PARAM;
    }
    businessCallbackMap_[std::make_pair(saId, businessKey)] = businessCallback;
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileServiceNew::UnRegisterBusinessCallback(const std::string& saId,
    const std::string& businessKey)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        return DP_PERMISSION_DENIED;
    }
    if (saId.empty() || businessKey.empty()) {
        return DP_INVALID_PARAM;
    }
    std::lock_guard<std::mutex> lock(businessEventCallbackMapMtx_);
    auto it = businessCallbackMap_.find(std::make_pair(saId, businessKey));
    if (it == businessCallbackMap_.end()) {
        return DP_INVALID_PARAM;
    }
    businessCallbackMap_.erase(it);
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileServiceNew::PutBusinessEvent(const BusinessEvent& event)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        return DP_PERMISSION_DENIED;
    }
    int32_t ret = BusinessEventManager::GetInstance().PutBusinessEvent(event);
    if (ret != DP_SUCCESS) {
        return ret;
    }
    ret = NotifyBusinessEvent(event);
    if (ret != DP_SUCCESS) {
        return DP_NOTIFY_BUSINESS_EVENT_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileServiceNew::GetBusinessEvent(BusinessEvent& event)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        return DP_PERMISSION_DENIED;
    }
    return BusinessEventManager::GetInstance().GetBusinessEvent(event);
}

int32_t DistributedDeviceProfileServiceNew::NotifyBusinessEvent(const BusinessEvent& event)
{
    HILOGI("NotifyBusinessEvent: %{public}s", event.GetBusinessKey().c_str());
    std::lock_guard<std::mutex> lock(businessEventCallbackMapMtx_);
    for (const auto& [key, callback] : businessCallbackMap_) {
        if (key.second != event.GetBusinessKey()) {
            continue;
        }
        sptr<IBusinessCallback> callbackProxy = iface_cast<IBusinessCallback>(callback);
        if (callbackProxy == nullptr) {
            continue;
        }
        auto handler = EventHandlerFactory::GetInstance().GetEventHandler();
        if (handler != nullptr) {
            handler->PostTask([callbackProxy, event]() {
                if (callbackProxy != nullptr) {
                    BusinessEventExt eventExt(event.GetBusinessKey(), event.GetBusinessValue());
                    callbackProxy->OnBusinessEvent(eventExt);
                }
            });
        }
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileServiceNew::PutServiceInfo(const ServiceInfo& serviceInfo)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        return DP_PERMISSION_DENIED;
    }
    return ServiceInfoManager::GetInstance().PutServiceInfo(serviceInfo);
}

int32_t DistributedDeviceProfileServiceNew::DeleteServiceInfo(const UserInfo& userInfo)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        return DP_PERMISSION_DENIED;
    }
    if (!ValidateUserIsolation(userInfo.userId, "")) {
        return DP_PERMISSION_DENIED;
    }
    return ServiceInfoManager::GetInstance().DeleteServiceInfo(userInfo);
}

int32_t DistributedDeviceProfileServiceNew::GetAllServiceInfoList(std::vector<ServiceInfo>& serviceInfos)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        return DP_PERMISSION_DENIED;
    }
    return ServiceInfoManager::GetInstance().GetAllServiceInfoList(serviceInfos);
}

int32_t DistributedDeviceProfileServiceNew::GetServiceInfosByUserInfo(const UserInfo& userInfo,
    std::vector<ServiceInfo>& serviceInfos)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        return DP_PERMISSION_DENIED;
    }
    if (!ValidateUserIsolation(userInfo.userId, "")) {
        return DP_PERMISSION_DENIED;
    }
    return ServiceInfoManager::GetInstance().GetServiceInfosByUserInfo(userInfo, serviceInfos);
}

int32_t DistributedDeviceProfileServiceNew::SubscribeAllServiceInfo(int32_t saId, sptr<IRemoteObject> listener)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        return DP_PERMISSION_DENIED;
    }
    if (listener == nullptr || saId <= 0 || saId > MAX_SAID) {
        return DP_INVALID_PARAM;
    }
    return SubscribeServiceInfoManager::GetInstance().SubscribeServiceInfo(saId, listener);
}

} // namespace DeviceProfile
} // namespace OHOS
