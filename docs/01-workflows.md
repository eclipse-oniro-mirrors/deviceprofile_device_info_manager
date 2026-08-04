# deviceprofile_device_info_manager 工作流规则

> 本文件记录必须按序执行的关键工作流。每条工作流给出前置条件、严格时序（含 `Class::Method()` 锚点与源码路径）与违反后果。
> 背景知识见 `knowledge/`：架构与生命周期见 `service-architecture.md`，画像数据与存储见 `profile-data-and-storage.md`，信任与访问控制见 `trust-acl-access-control.md`，同步与订阅通知见 `sync-subscription-notification.md`。

## 1. SA 启动 / 上线时序

**前置：** SA Framework 调用 `OnStart(reason)`；触发条件为设备上线事件或 `usual.event.BOOT_COMPLETED`。5 个依赖 SA 必须就绪后才进入 `PostInit`。

**严格时序：**

1. `DistributedDeviceProfileServiceNew::OnStart(reason)` — `services/core/src/distributed_device_profile_service_new.cpp:955`
2. `XCollie::SetTimer(DP_ONSTART_TIMER, 12s, ...)` — `:958`
3. `Init()`：`EventHandlerFactory::Init()` → `PermissionManager::Init()` → `TrustProfileManager::Init()` → `ProfileDataManager::Init()` → `SubscribeProfileManager::Init()` — `:104`
4. `AddSystemAbilityListener(SOFTBUS_SERVER_SA_ID)` / `DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID` / `DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID`(4802) / `SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN` / `MEMORY_MANAGER_SA_ID` — `:967-971`
5. `IPCSkeleton::SetMaxWorkThreadNum(32)` — `:972`
6. `CancelTimer(onStartTimerId)` — `:973`
7. `Publish(this)` — `:974`
8. `CreateUnloadHandler()` + `DelayUnloadTask()`（180s） — `:978-981`
9. 依赖 SA 逐个上线 → `OnAddSystemAbility` → `depSaIds_.erase(saId)`；账户 SA 上线→`SubscribeAccountCommonEvent()`；内存 SA 上线→`SetCritical(true)` — `:1014`
10. `depSaIds_` 为空 → `PostInit()`：`DMAdapter::Init()` → `SwitchProfileManager::Init()`(`#ifndef DEVICE_PROFILE_SWITCH_DISABLE`) → `DeviceProfileManager::Init()` → `StaticProfileManager::Init()` → `ProfileCache::Init()` → `StaticCapabilityCollector::Init()` → `LocalServiceInfoManager::Init()` → `MultiUserManager::Init()` → `ServiceInfoManager::Init()` — `:139`
11. `PostInitNext()`：`SettingsDataManager::Init()` → `ContentSensorManager::Init()` → `BusinessEventManager::Init()` → `SaveSwitchProfilesFromTempCache()` → `SaveDynamicProfilesFromTempCache()` → `isInited_ = true` → `NotifyDeviceProfileInited()` — `:184`

**违反后果：** 在 `PostInit` 完成前（`isInited_!=true`）调用非 `aclAndSubscribeFuncs_` 的读取类接口，Stub 返回 `DP_LOAD_SERVICE_ERR`(98566160)，客户端触发重试。在 `OnStart` 与 `PostInitNext` 之间 KV Store 未就绪时写入的数据由临时缓存暂存，若未刷新（`SaveDynamicProfilesFromTempCache`）会丢失。若 `depSaIds_` 未清空即强行调用 `PostInit`，`PostInit` 不会触发（依赖集合非空）。

## 2. SA 关停 / 下线时序

**前置：** `OnStop` 由框架触发（设备下线、低内存 `resourceschedule.memmgr.low.memory.prepare=true`、或卸载超时）。

**严格时序：**

1. `OnStop()` → `isStopped_ = true` — `services/core/src/distributed_device_profile_service_new.cpp:984`
2. `UnInit()`：`TrustProfileManager::UnInit()` → `ProfileDataManager::UnInit()` → `SwitchProfileManager::UnInit()` → `DeviceProfileManager::UnInit()` → `StaticProfileManager::UnInit()` → `BusinessEventManager::UnInit()`（与 `Init` 逆序） — `:241`
3. `UnInitNext()`：`ProfileCache::UnInit()` → `PermissionManager::UnInit()` → `SubscribeProfileManager::UnInit()` → `StaticCapabilityCollector::UnInit()` → `SettingsDataManager::UnInit()` → `ContentSensorManager::UnInit()` → `DMAdapter::UnInit()` → `EventHandlerFactory::UnInit()` → `ServiceInfoManager::UnInit()` — `:295`
4. `DestroyUnloadHandler()` + `ClearProfileCache()` — `:316`
5. `MemMgrClient::SetCritical(getpid(), false, ...)` + `NotifyProcessStatus(getpid(), 1, 0, ...)` — `:984`

**违反后果：** `UnInit` 顺序与 `Init` 相反；不逆序会导致悬空访问或锁失效。`OnStop` 后 IPC 入口被 `IsStopped()` 拦截返回 `DP_SERVICE_STOPPED`(98566331)。

## 3. PutDeviceProfile（核心 CRUD 写入）

**前置：** 客户端经 SDK 调用；服务层 `ServiceNew` 已就绪；KV Store 经 `KVAdapter` 可访问。

**严格时序：**

1. `DistributedDeviceProfileProxy::PutDeviceProfile` → `SEND_REQUEST(PUT_DEVICE_PROFILE_BATCH=46 之单条/批次)` — `interfaces/innerkits/core/src/distributed_device_profile_proxy.cpp`
2. Stub `OnRemoteRequest` → `PutDeviceProfileInner` — `services/core/src/distributed_device_profile_stub_new.cpp`
3. `PermissionManager::CheckCallerPermission()` — `services/core/src/distributed_device_profile_service_new.cpp`
4. `DeviceProfileManager::PutDeviceProfile` — `services/core/src/deviceprofilemanager/device_profile_manager.cpp:109`
5. `ProfileUtils::IsDevProfileValid` 字段校验 — 同上
6. `ProfileUtils::DeviceProfileToEntries`（多用户生成专属键） — 同上
7. `DeviceProfileManager::IsFirstInitDB` 判定 — `:748`
8. 首次未初始化 → `AddToPutTempCache`（临时缓存，待 `SaveDynamicProfilesFromTempCache` 刷新） — `:686`；否则 → `KVAdapter::PutBatch(entries)` — 同上
9. 写路径通知 `SubscribeProfileManager::NotifyProfileChange` — 同上

**违反后果：** 多用户校验失败返回 `DP_GET_LOCAL_PROFILE_IS_NOT_FOREGROUND_ID`(98566279)；缓存已存在返回 `DP_CACHE_EXIST`(98566164)；临时缓存未刷新则数据丢失。

## 4. GetDeviceProfile（缓存优先读取）

**严格时序：**

1. `DistributedDeviceProfileProxy::GetDeviceProfile`（序列化 `isMultiUser`+`userId`）→ `SEND_REQUEST(GET_DEVICE_PROFILE_NEW=18)` — `distributed_device_profile_proxy.cpp`
2. Stub → `GetDeviceProfileInner` → `PermissionManager::CheckCallerPermission()` — `distributed_device_profile_service_new.cpp`
3. `DeviceProfileManager::GetDeviceProfile` — `device_profile_manager.cpp:298`
4. `IsMultiUserValid` 前台用户校验 — `:1126`
5. `ProfileControlUtils::GetDeviceProfile` — `services/core/src/utils/profile_control_utils.cpp:224`
6. `ProfileCache::GetDeviceProfile(deviceId)` 缓存查找 — 同上
7. 命中→返回 `DP_SUCCESS`；未命中→`KVAdapter::GetByPrefix("DEV/udid")` → `ProfileUtils::EntriesToDeviceProfile` — 同上

**违反后果：** 非前台用户读返回 `DP_GET_LOCAL_PROFILE_IS_NOT_FOREGROUND_ID`(98566279)；服务未初始化返回 `DP_LOAD_SERVICE_ERR`(98566160)。

## 5. PutCharacteristicProfile（路由分发）

**严格时序：**

1. Stub → `PutCharacteristicProfileInner` → `CheckCallerPermission()` — `distributed_device_profile_service_new.cpp:600`
2. 未初始化 → `AddCharProfilesToCache`（服务层临时缓存） — `:1114`
3. 已初始化 → 按 `characteristicKey` 路由：`SWITCH_STATUS` → `SwitchProfileManager::PutCharacteristicProfile`（经 `SwitchAdapter::PutSwitch`）；静态能力仅 Get；默认动态 → `DeviceProfileManager::PutCharacteristicProfile` — `device_profile_manager.cpp:222`

**违反后果：** 路由判定错误会导致开关状态写入动态存储或反之，数据不一致。

## 6. PutAccessControlProfile（ACL 四表级联写入）

**前置：** 调用方在 `PUT_ACCESS_CONTROL_PROFILE` 受信列表（`IsCallerTrust`）；本地 RDB 可访问；4 表已建。

**严格时序：**

1. `PutAccessControlProfileInner` → `PermissionManager::IsCallerTrust(PUT_ACCESS_CONTROL_PROFILE)` — `distributed_device_profile_service_new.cpp:362`
2. `TrustProfileManager::PutAccessControlProfile` — `trust_profile_manager.cpp:111`
3. `CheckDeviceIdAndUserIdExists` 扫描匹配 — `:2010`
4. `SetAccessControlProfileId` 分配 ID — `:1619`
5. `PutAccesserProfile`（INSERT 或 NOOP） — `:1183`
6. `PutAccesseeProfile`（INSERT 或 NOOP） — `:1226`
7. `IsAclExists` 重复检测 — `:1947`
8. INSERT `access_control_table`
9. `PutAclCheck` trust 级联检查 — `:1906`
10. 不存在 → INSERT `trust_device_table` + `NotifyTrustDeviceProfileAdd`；已存在 → `GetResultStatus` 聚合 UPDATE — `:1450`
11. `DpAclAdd(accessControlId, trustDeviceId, bindType)` 通知 DM

**违反后果：** 更新 ACL 不可变字段（`accesserId`/`accesseeId`）返回 `DP_UPDATE_ACL_NOT_ALLOW`(98566249)；重复 ACL 返回 `DP_DATA_EXISTS`(98566253)；不受信调用方返回 `DP_PERMISSION_DENIED`(98566155)。

## 7. DeleteAccessControlProfile（四级级联删除）

**前置：** 存在待删 ACL 记录。

**严格时序（级联顺序：accessee → accesser → ACL → trust_device，依赖 COUNT 引用计数）：**

1. `DeleteAccessControlProfileInner` — `distributed_device_profile_service_new.cpp:489`
2. `TrustProfileManager::DeleteAccessControlProfile` → SELECT 待删 — `trust_profile_manager.cpp:741`
3. `DeleteAccessControlProfileCheck` 级联入口 — `:1564`
4. `DeleteAccesseeCheck`（COUNT==1 才删 accessee_table） — `:2089`
5. `DeleteAccesserCheck`（COUNT==1 才删 accesser_table） — `:1840`
6. DELETE `access_control_table` WHERE accessControlId
7. `DeleteTrustDeviceCheck` — `:2127`
8. `CheckDeviceIdAndUserIdExists` 复查 — `:2010`
9. 无引用且非 LNN → `NotifyTrustDeviceProfileDelete` + DELETE/UPDATE `trust_device_table` — `:1450`

**违反后果：** 跳过级联会导致 accesser/accessee/trust_device 残留孤儿行；改错 COUNT 语义会误删 trust_device。

## 8. SyncDeviceProfile（OH KV 同步 + 非 OH Adapter）

**前置：** 调用方持 `SYNC_PROFILE_DP` 权限；OH 设备经 KV 内置同步，非 OH 设备需 `libdeviceprofileadapter.z.so` 插件。

**严格时序：**

1. `SyncDeviceProfileInner` → `PermissionManager::CheckCallerSyncPermission()` — `distributed_device_profile_service_new.cpp:874`
2. `DeviceProfileManager::SyncDeviceProfile` — `device_profile_manager.cpp:489`
3. `ProfileCache::FilterAndGroupOnlineDevices(..., ohBased, notOHBased)` — 同上
4. **OH 路径：** `AddSyncListener(callerDescriptor, syncCompletedCallback)` → `KVAdapter::Sync(ohBasedDevices, syncMode)` — `:510`、`:517`
5. 异步完成 → `KvSyncCompletedListener::SyncCompleted` → `NotifySyncCompleted` → `GetSyncListeners` → `OnSyncCompleted` → `RemoveSyncListeners` — `services/core/src/deviceprofilemanager/listener/kv_sync_completed_listener.cpp:63`/`:94`
6. **非 OH 路径：** `SyncWithNotOHBasedDevice` → `LoadDpSyncAdapter` — `device_profile_manager.cpp:603`/`:534`
7. `dlopen("libdeviceprofileadapter.z.so")` → `CreateDPSyncAdapterObject` → `Initialize()` — `:534`
8. 逐设备 `IDPSyncAdapter::SyncProfile(peerUdid, peerNetId, callback, isP2p)` — 同上
9. 失败 → `SyncWithNotOHBasedDeviceFailed` → `OnSyncCompleted` — `:625`
10. `UnloadDpSyncAdapter` — `:582`

**违反后果：** 两组设备都空（全离线）返回 `DP_INVALID_PARAMS`(98566144)；适配器 `.so` 缺失返回 `DP_LOAD_SYNC_ADAPTER_FAILED`(98566248)。

## 9. 设备上线 E2E 同步（始终 PUSH_PULL）

**前置：** `DMAdapter` 收到 `OnDeviceOnline`；`DmDeviceInfo.extraData` JSON 含 osVersion/osType/udid/uuid 四字段可解析。

**严格时序：**

1. `DmDeviceStateCallback::OnDeviceOnline(DmDeviceInfo)` — `services/core/src/dm_adapter/dm_adapter.cpp:100`
2. `ConvertToTrustedDeviceInfo`（解析 extraData JSON） — 同上
3. 解析失败（extraData 空/JSON 失败/字段缺失） → 直接返回，不再继续
4. `ProfileCache::OnNodeOnline(trustedDeviceInfo)`（加入 `onlineDevMap_`） — `services/core/src/utils/profile_cache.cpp`
5. 新线程（detach）执行 `DeviceProfileManager::OnDeviceOnline` + `SwitchUpdater::OnDeviceOnline` — `dm_adapter.cpp:110-115`
6. `FixDataOnDeviceOnline` → `FixLocalData` → `FixRemoteDataWhenPeerIsNonOH`/`FixRemoteDataWhenPeerIsOHBase` — `device_profile_manager.cpp:769`/`:950`/`:980`/`:1016`
7. `NotifyNotOHBaseOnline` → `dpSyncAdapter_->NotOHBaseDeviceOnline` — `:873`
8. `IsDeviceE2ESync` 判定 — `:1203`
9. `E2ESyncDynamicProfile` → `deviceProfileStore_->Sync({networkId}, PUSH_PULL)` — `:916`
10. `StaticProfileManager::E2ESyncStaticProfile` — 同上
11. `FixDiffProfiles` — `:1037`

**违反后果：** E2E 若改非 `PUSH_PULL` 会导致对端缺数据；`extraData` 解析失败则上线流程中断、不触发 E2E。

## 10. 设备下线

**严格时序：**

1. `DmDeviceStateCallback::OnDeviceOffline(DmDeviceInfo)` — `dm_adapter.cpp:118`
2. `networkId = deviceInfo.networkId` — 同上
3. `ProfileCache::OnNodeOffline(networkId)` 擦除 `onlineDevMap_` — `profile_cache.cpp`

**违反后果：** 无。下线路径**不触发级联数据清理**，已断开设备的残留数据继续保留在存储中。

## 11. SubscribeDeviceProfile 与变更通知链

**前置：** 订阅者经 SDK 注册；`ServiceNew` 处理 IPC；KV Store 变更经 `KvDataChangeListener` 驱动通知。

**严格时序：**

1. `SubscribeDeviceProfileInner` → `CheckCallerPermission()` — `services/core/src/subscribeprofilemanager/subscribe_profile_manager.cpp`
2. `SubscribeProfileManager::SubscribeDeviceProfile` — 同上
3. 加锁 `subscribeMutex_`；`subscribeInfoMap_.size() > MAX_LISTENER_SIZE(100)` → `DP_EXCEED_MAX_SIZE_FAIL` — 同上
4. 擦除旧条目再 emplace — 同上

数据变更驱动通知：

5. `KvDataChangeListener::OnChange` — `services/core/src/deviceprofilemanager/listener/kv_data_change_listener.cpp`
6. `HandleAddChange`/`HandleUpdateChange`/`HandleDeleteChange` + `FilterEntries`（去重+OH 后缀清理） — 同上
7. `GetProfileType(dbKey)` 解析类型 — 同上
8. `NotifyProfileChange`：`code = profileType * changeType` → `DpRadarHelper::ReportNotifyProfileChange(code)` — `subscribe_profile_manager.cpp`
9. 按 code 调 `NotifyDeviceProfileAdd/Update/Delete` 等 — 同上
10. `DBKeyToSubcribeKey` → `GetSubscribeInfos(subscribeKey)` — 同上
11. `profileChangeTypes` 过滤 → `iface_cast<IProfileChangeListener>` → `OnDeviceProfileAdd` 等 IPC 回调 — 同上

**违反后果：** 超限返回 `DP_EXCEED_MAX_SIZE_FAIL`；OH 后缀键不一致导致通知漏投。

## 12. 内容采集启动

**前置：** `PostInitNext` 调用 `ContentSensorManager::Init()`；静态能力配置文件可读；工作线程阻塞 join。

**严格时序：**

1. `ContentSensorManager::Init()` / `Collect()` — `services/core/src/contentsensormanager/content_sensor_manager.cpp`
2. `std::thread(csTask)`（阻塞 join） — 同上
3. 6 采集器依次 `ConvertToProfile`：`SystemInfoCollector` → `SyscapInfoCollector` → `DmsInfoCollector` → `CollaborationInfoCollector` → `PasteboardInfoCollector` → `SwitchStatusCollector`(`#ifndef DEVICE_PROFILE_SWITCH_DISABLE`) — `services/core/src/contentsensormanager/*_info_collector.cpp`
4. 设 localUDID
5. `DeviceProfileManager::PutDeviceProfile(deviceProfile)` 写 KV — 同上
6. `ContentSensorManager::CollectInfoToProfileData`（经 `ProfileDataManager::PutDeviceProfile`）写 RDB
7. `DeviceProfileManager::PutServiceProfileBatch` + `PutCharacteristicProfileBatch` — 同上

**违反后果：** 线程不可加入返回 `DP_CONTENT_SENSOR_MANAGER_INIT_FAIL`(98566179)；采集数据空/JSON 无效返回 `DP_STATIC_COLLECT_FAIL`(98566254)。

## 13. 静态能力采集（插件 dlopen/dlsym）

**严格时序：**

1. `StaticCapabilityCollector::CollectStaticCapability` — `services/core/src/staticcapabilitycollector/static_capability_collector.cpp`
2. `StaticCapabilityLoader::LoadStaticCapability` → `LoadJsonFile(STATIC_CAPABILITY_PATH)` — `services/core/src/staticcapabilityloader/static_capability_loader.cpp`
3. `InitStaticCapability(size)`（全 '0'） — 同上
4. 遍历处理器 `dlopen`/`dlsym("GetStaticCapabilityCollector")`/`dlclose` — 同上
5. `LoadStaticInfo` → `GetLatestStaticInfoJson`（取数组末项） — 同上
6. `GenerateStaticProfiles`（按 `HasStaticCapability` 过滤） — 同上
7. `AddStaticInfoToCache` — `static_capability_collector.cpp`
8. `StaticProfileManager::PutCharacteristicProfile(staticCapabilityProfile)` 写库 — 同上

**违反后果：** 版本不匹配则该版本静态信息不返回；加载失败返回 `DP_LOAD_STATIC_CAP_FAIL`(98566255)。

## 14. PutServiceInfo（双层 KV）

**前置：** 双层 KV（本地 `dp_kv_store_service_info_profile` + 同步 store）已初始化；`KvDeathRecipient` 已注册。

**严格时序：**

1. `PutServiceInfoInner` → `CheckCallerPermission()` — `services/core/src/distributed_device_profile_service_new.cpp`
2. `ServiceInfoManager::PutServiceInfo` — `services/core/src/serviceinfo_manager/service_info_manager.cpp`
3. `IsSvrInfoValid`（字符串+数字+`IsNumStr`） — 同上
4. `ServiceInfoToEntries` 序列化 — 同上
5. 加锁 `storeMutex_` → `serviceInfoKvAdapter_->PutBatch(entries)` 写本地 KV — 同上
6. `GetDevUdid()` — 同上
7. 非本地 UDID → 跳过同步存储写入（远程设备自负责）；本地 UDID → 加锁 `syncStoreMutex_` → `syncServiceInfoKvAdapter_->PutBatch(entries)` 写同步 KV — 同上

**违反后果：** 字段非法返回 `DP_INVALID_PARAMS`；非本地 UDID 仅写本地存储，对端不同步。

## 15. PutLocalServiceInfo 与 PinCode 失效通知

**前置：** `local_service_info` RDB 表已建。

**严格时序：**

1. `PutLocalServiceInfoInner` — `distributed_device_profile_service_new.cpp`
2. 参数校验：`bundleName` 空 或 `pinExchangeType==0` → `DP_INVALID_PARAM` — 同上
3. `LocalServiceInfoManager::PutLocalServiceInfo` — `services/core/src/localserviceinfomanager/local_service_info_manager.cpp`
4. `GetLocalServiceInfoByBundleAndPinType` 重复检测 → 重复返回 `DP_LOCAL_SERVICE_INFO_EXISTS`(98566325) — 同上
5. `LocalServiceInfoToEntries` → RDB `Put(rowId, LOCAL_SERVICE_INFO_TABLE, values)` — 同上
6. `pinCode == PINCODE_INVALID` → `NotifyPinCodeInvalid` — `distributed_device_profile_service_new.cpp`
7. 加锁 `pinCodeCallbackMapMtx_` 查 `{bundleName, pinExchangeType}` — 同上
8. `EventHandler->PostTask(OnPincodeInvalid)` 异步派发 — 同上

**违反后果：** 重复返回 `DP_LOCAL_SERVICE_INFO_EXISTS`(98566325)；更新不存在的记录返回 `DP_NOT_FIND_DATA`(98566221)。

## 16. PutSessionKey（Asset 加密存储）

**前置：** 调用方在 `PUT_SESSION_KEY` 受信列表；Asset 可访问性 `SEC_ASSET_ACCESSIBILITY_DEVICE_FIRST_UNLOCKED`。

**严格时序：**

1. `PutSessionKeyInner` → `PermissionManager::IsCallerTrust(PUT_SESSION_KEY)` → 不受信返回 `DP_PERMISSION_DENIED`(98566155) — `distributed_device_profile_service_new.cpp`
2. `SessionKeyManager::PutSessionKey` — `services/core/src/sessionkeymanager/session_key_manager.cpp`
3. 参数校验：`userId==0` 或 sessionKey 空或 `size > MAX_SESSIONKEY_SIZE(8192)` → `DP_INVALID_PARAMS`(98566144) — 同上
4. `GeneratedSessionKeyId`（随机 int32_t，`GetSessionKey` 碰撞检测循环） — 同上
5. 构建 Asset 属性数组 `[ALIAS, USER_ID, SECRET, ACCESSIBILITY]` — 同上
6. `AssetAdapter::PutAsset(attr, count)` — `services/core/src/persistenceadapter/assetadapter/asset_adapter.cpp`
7. 返回 `DP_SUCCESS` + sessionKeyId

**违反后果：** Asset 查询返回 null/无效返回 `DP_GET_ASSET_ERROE`(98566319)；超长返回 `DP_INVALID_PARAMS`(98566144)。

## 17. PutBusinessEvent 与回调派发

**严格时序：**

1. `PutBusinessEventInner` → `CheckCallerPermission()` — `distributed_device_profile_service_new.cpp`
2. `BusinessEventManager::PutBusinessEvent` — `services/core/src/businesseventmanager/business_event_manager.cpp`
3. `IsValidKey` 白名单校验（仅 `DP_REJECT_KEY`/`DP_DISTURBANCE_KEY`）→ 不在白名单返回 `DP_INVALID_PARAM`(98566245) — 同上
4. 加锁 `dynamicStoreMutex_` → `BusinessEventAdapter::Put(key, value)` — 同上
5. `ServiceNew::NotifyBusinessEvent` → 转 `BusinessEventExt` — `distributed_device_profile_service_new.cpp`
6. 加锁 `businessEventCallbackMapMtx_` 遍历匹配 businessKey — 同上
7. `iface_cast<IBusinessCallback>` → `EventHandler::PostTask` → `OnBusinessEvent(eventExt)` 异步派发 — 同上

**违反后果：** 业务密钥不在白名单返回 `DP_INVALID_PARAM`(98566245)；`businessEventCallbackMap_` 无死亡接收者，已失效条目残留至显式注销。
