# 内部 API 参考 -- 管理器契约

> DeviceProfile 服务进程内部各管理器模块之间的契约文档。
> 这些不是公开 API；它们是同一进程内的 C++ 私有方法调用。

## 1. 管理器初始化顺序

服务入口 `DistributedDeviceProfileServiceNew` 负责编排所有管理器的初始化。`Init()` 方法在 `OnStart()` 期间调用，`PostInit()` 在依赖 SA 上线后执行。

### Init 顺序（同步执行，必须依次成功）

| 步骤 | 管理器 | 方法 | 依赖项 | 说明 |
|---|---|---|---|---|
| 1 | `PermissionManager` | `Init()` | 无 | 通过 `GetCfgFiles` 从系统配置路径加载 `permission.json` |
| 2 | `MultiUserManager` | `Init()` | 无 | 从 OS Account 获取当前前台用户 ID |
| 3 | `ProfileCache` | `Init()` | 无 | 从 SoftBus 获取本地 UDID/UUID/networkId |
| 4 | `EventHandleFactory` | `Init()` | 无 | 创建 FFRT 事件处理器用于异步任务调度 |
| 5 | `ProfileDataManager` | `Init()` | 无 | 初始化 RDB 适配器用于设备画像、产品信息、图标信息 |
| 6 | `DMAdapter` | `Init()` | 无 | 向 DeviceManager 注册 `DmDeviceStateCallback` 和 `DmInitCallback` |
| 7 | `BusinessEventManager` | `Init()` | 无 | 初始化 BusinessEventAdapter KV 存储 |
| 8 | `ServiceInfoManager` | `Init()` | 无 | 初始化双层 KV 存储（本地 + 同步） |
| 9 | `SubscribeServiceInfoManager` | `Init()` | 无 | 初始化内存中的订阅映射表 |
| 10 | `LocalServiceInfoManager` | `Init()` | 无 | 为本地服务信息创建 RDB 表 |
| 11 | `DeviceProfileManager` | `Init()` | 无 | 初始化主 KV 存储 + 监听器（数据变更、同步完成、远端死亡） |
| 12 | `TrustProfileManager` | `Init()` | 无 | 创建信任设备 + 访问控制画像的 RDB 表 |
| 13 | `SubscribeProfileManager` | `Init()` | 无 | 初始化画像变更分发的订阅映射表 |

### PostInit 顺序（异步执行，在依赖 SA 上线后）

`PostInit()` 通过 `SystemAbilityStatusChangeListener` 等待依赖 SA（SoftBus 4002、KV Data 3340、DeviceManager 3202、OS Account、Memory Manager）上线。

| 步骤 | 操作 | 依赖项 |
|---|---|---|
| 1 | `ProfileDataManager::Init()` 二次检查 | SA 上线确认 |
| 2 | `ContentSensorManager::Init()` + `Collect()` | DeviceManager（获取本地设备信息） |
| 3 | `MultiUserManager::GetForegroundUserIDFromOs()` | OS Account SA |
| 4 | `TrustProfileManager::IsAceeCreIdExistToAceeTable()` | RDB（Schema 迁移检查） |
| 5 | `ProfileCache::RefreshProfileCache()` | KV 存储数据加载完成 |
| 6 | `StaticCapabilityCollector::Init()` | 内容采集完成 |
| 7 | `DeviceProfileManager::IsFirstInitDB()` | KV 存储初始设置检查 |
| 8 | `NotifyDeviceProfileInited()` | 通知所有订阅者 |

### UnInit 顺序（与 Init 顺序相反）

| 步骤 | 管理器 | 方法 |
|---|---|---|
| 1 | `StaticCapabilityCollector` | `UnInit()` |
| 2 | `DeviceProfileManager` | `UnInit()` |
| 3 | `SubscribeProfileManager` | `UnInit()` |
| 4 | `TrustProfileManager` | `UnInit()` |
| 5 | `LocalServiceInfoManager` | `UnInit()` |
| 6 | `ServiceInfoManager` | `UnInit()` |
| 7 | `BusinessEventManager` | `UnInit()` |
| 8 | `ContentSensorManager` | `UnInit()` |
| 9 | `DMAdapter` | `UnInit()` |
| 10 | `ProfileDataManager` | `UnInit()` |
| 11 | `ProfileCache` | `UnInit()` |
| 12 | `MultiUserManager` | `UnInit()` |
| 13 | `PermissionManager` | `UnInit()` |

---

## 2. 跨管理器调用模式

### 2.1 DeviceProfileManager

`DeviceProfileManager` 是基于 KV 存储的中心画像管理器。它将键生成/序列化工作委托给 `ProfileControlUtils`，将存储操作委托给 `KVAdapter`。它还维护 `putTempCache_` 映射表用于延迟持久化。

```
DeviceProfileManager
  ├── ProfileCache（读路径：优先缓存查找）
  │     ├── GetDeviceProfile(deviceId) -> 查询 deviceProfileMap_
  │     ├── GetServiceProfile(deviceId, serviceName) -> 查询 serviceProfileMap_
  │     ├── GetCharacteristicProfile(deviceId, serviceName, charKey) -> 查询 charProfileMap_
  │     ├── AddDeviceProfile(...) -> 写入 deviceProfileMap_
  │     ├── AddServiceProfile(...) -> 写入 serviceProfileMap_
  │     └── AddCharProfile(...) -> 写入 charProfileMap_
  ├── ProfileControlUtils（静态方法：键构造 + KV 序列化）
  │     ├── PutDeviceProfile(kvStore, profile) -> 生成键, Put(k,v)
  │     ├── PutServiceProfile(kvStore, profile) -> 生成键, Put(k,v)
  │     ├── PutServiceProfileBatch(kvStore, profiles) -> PutBatch(entries)
  │     ├── PutCharacteristicProfile(kvStore, profile) -> 生成键, Put(k,v)
  │     ├── PutCharacteristicProfileBatch(kvStore, profiles) -> PutBatch(entries)
  │     ├── GetDeviceProfile(kvStore, deviceId, out) -> GetByPrefix + 反序列化
  │     ├── GetServiceProfile(kvStore, deviceId, serviceName, out) -> Get + 反序列化
  │     ├── GetCharacteristicProfile(kvStore, deviceId, serviceName, charKey, out) -> Get
  │     ├── DeleteServiceProfile(kvStore, deviceId, serviceName, ...) -> Delete
  │     ├── DeleteCharacteristicProfile(kvStore, deviceId, serviceName, charKey, ...) -> Delete
  │     ├── GetAllDeviceProfile(kvStore, out) -> GetByPrefix
  │     ├── GetAllServiceProfile(kvStore, out) -> GetByPrefix
  │     └── GetAllCharacteristicProfile(kvStore, out) -> GetByPrefix
  ├── KVAdapter（IKVAdapter 实现，包装 DistributedKvDataManager）
  │     ├── Init() -> GetKvStorePtr() -> kvDataMgr_.GetSingleKvStore()
  │     ├── Put(key, value) -> kvStorePtr_->Put(key, value)
  │     ├── PutBatch(values) -> kvStorePtr_->PutBatch(values)
  │     ├── Get(key, out) -> kvStorePtr_->Get(key, out)
  │     ├── GetByPrefix(prefix, out) -> kvStorePtr_->GetEntries(prefix, out)
  │     ├── Delete(key) -> kvStorePtr_->Delete(key)
  │     ├── DeleteByPrefix(prefix) -> kvStorePtr_->DeleteBatch(keys)
  │     ├── DeleteBatch(keys) -> kvStorePtr_->DeleteBatch(keys)
  │     ├── Sync(deviceList, mode) -> kvStorePtr_->Sync(deviceList, mode)
  │     └── RemoveDeviceData(uuid) -> kvStorePtr_->RemoveDeviceData(uuid)
  ├── KvDataChangeListener（DistributedKv::KvStoreObserver）
  │     └── OnChange(changeNotification) -> 将 ADD/UPDATE/DELETE 分发给 SubscribeProfileManager
  ├── KvSyncCompletedListener（DistributedKv::KvStoreSyncCallback）
  │     └── SyncCompleted(map) -> 向注册的回调报告同步结果
  └── SubscribeProfileManager（写路径：画像变更通知）
        └── NotifyProfileChange(profileType, changeType, dbKey, dbValue) -> 分发给订阅者
```

**`PutDeviceProfile` 内部调用流程（单条，通过 PutServiceProfileBatch 路径）：**

```
DistributedDeviceProfileServiceNew::PutServiceProfile(profile)
  -> DeviceProfileManager::PutServiceProfile(profile)
    -> ProfileControlUtils::PutServiceProfile(kvStore, profile)
       [生成键："SERVICE_PROFILE/udid/serviceName/userId"]
       -> kvStore->Put(key, value)
    -> ProfileCache::AddServiceProfile(profile)
```

**`GetDeviceProfile` 内部调用流程：**

```
DistributedDeviceProfileServiceNew::GetDeviceProfile(deviceId, out)
  -> 如果画像有 userId/isMultiUser：
       -> ProfileCache::GetDeviceProfile(deviceId, out)
          [查询 deviceProfileMap_]
          [未命中：调用 KV profileController_->GetByPrefix，然后反序列化]
       -> 如果缓存命中：直接返回
     否则：
       -> DeviceProfileManager::GetDeviceProfile(deviceId, out)
          -> ProfileControlUtils::GetDeviceProfile(kvStore, deviceId, out)
```

### 2.2 TrustProfileManager

`TrustProfileManager` 在 RDB 中管理信任和 ACL 画像。发生变更时通知 `SubscribeProfileManager`。

```
TrustProfileManager
  ├── RdbAdapter（IRdbAdapter 实现）
  │     ├── Init() -> ConnectDB(store, DBVersion, path)
  │     ├── Put(outRowId, table, values) -> store_->Insert(outRowId, table, values)
  │     ├── Delete(deleteRows, table, whereClause, args) -> store_->Delete(...)
  │     ├── Update(changedRows, table, values, whereClause, args) -> store_->Update(...)
  │     ├── CreateTable(sql) -> store_->ExecuteSql(sql)
  │     └── Get(sql, args) -> store_->QuerySql(sql, args)
  └── SubscribeProfileManager（通知）
        ├── NotifyTrustDeviceProfileAdd(profile)
        ├── NotifyTrustDeviceProfileUpdate(oldProfile, newProfile)
        ├── NotifyTrustDeviceProfileDelete(profile)
        ├── NotifyTrustDeviceProfileActive(profile)
        └── NotifyTrustDeviceProfileInactive(profile)
```

**ACL CRUD 内部流程：**

```
PutAccessControlProfile(aclProfile):
  TrustProfileManager::PutAccessControlProfile(profile)
    -> PutAclCheck(profile)  // 验证唯一性
    -> SetAccessControlId(profile)  // 自动生成唯一 ID
    -> SetAccesserId(profile)      // 自动生成访问者 ID
    -> SetAccesseeId(profile)      // 自动生成被访问者 ID
    -> PutAccesserProfile(profile) // INSERT 到 accesser 表
    -> PutAccesseeProfile(profile) // INSERT 到 accessee 表
    -> rdbStore_->Put(aclRowId, "acl_table", aclValues)  // INSERT 到 acl 表
    -> NotifyTrustDeviceProfileAdd(...)

UpdateAccessControlProfile(aclProfile):
  TrustProfileManager::UpdateAccessControlProfile(profile)
    -> UpdateAclCheck(profile, oldProfile)  // 验证并获取旧数据
    -> UpdateAccesserProfile(profile)       // UPDATE accesser 表
    -> UpdateAccesseeProfile(profile)       // UPDATE accessee 表
    -> rdbStore_->Update(changedRows, "acl_table", values, where, args)
    -> NotifyCheck(profile, oldProfile)     // 判断发出 ADD/UPDATE 通知

DeleteAccessControlProfile(accessControlId):
  TrustProfileManager::DeleteAccessControlProfile(accessControlId)
    -> rdbStore_->Get("SELECT ... WHERE accessControlId = ...")
    -> DeleteAccessControlProfileCheck(profile)
    -> rdbStore_->Delete(deleteRows, "acl_table", where)
    -> DeleteAccesserCheck(accesserId) -> rdbStore_->Delete("accesser_table", ...)
    -> DeleteAccesseeCheck(accesseeId) -> rdbStore_->Delete("accessee_table", ...)
    -> DeleteTrustDeviceCheck(profile) // 级联操作：如果该设备无其他 ACL 引用，删除信任关系
```

### 2.3 SubscribeProfileManager

`SubscribeProfileManager` 是通知中心。它接收来自 `KvDataChangeListener`、`TrustProfileManager` 和开关更新器的变更事件，并通过 IPC 将这些事件分发给已注册的订阅者。

```
SubscribeProfileManager
  ├── subscribeInfoMap_（内存中）：map<subscribeKey, set<SubscribeInfo>>
  ├── funcsMap_（内存中）：map<ProfileType, dispatchFunc>
  ├── 接收来源：
  │     ├── KvDataChangeListener::OnChange() -> 调用 NotifyProfileChange(type, change, key, value)
  │     ├── TrustProfileManager -> NotifyTrustDeviceProfile*()
  │     └── DeviceProfileManager -> NotifyProfileChange()
  └── 分发至：
        └── IProfileChangeListener（每个订阅者的 IPC 代理实例）
              ├── OnTrustDeviceProfileAdd(profile)
              ├── OnTrustDeviceProfileDelete(profile)
              ├── OnTrustDeviceProfileUpdate(old, new)
              ├── OnTrustDeviceProfileActive(profile)
              ├── OnTrustDeviceProfileInactive(profile)
              ├── OnDeviceProfileAdd(profile)
              ├── OnDeviceProfileDelete(profile)
              ├── OnDeviceProfileUpdate(old, new)
              ├── OnServiceProfileAdd(profile)
              ├── OnServiceProfileDelete(profile)
              ├── OnServiceProfileUpdate(old, new)
              ├── OnCharacteristicProfileAdd(profile)
              ├── OnCharacteristicProfileDelete(profile)
              └── OnCharacteristicProfileUpdate(old, new)
```

**从 KV 数据变更到订阅者通知的分发流程：**

```
KvDataChangeListener::OnChange(changeNotification)
  -> HandleAddChange(insertRecords)     -> NotifyProfileChange(type, ADD, ...)
  -> HandleUpdateChange(updateRecords)  -> NotifyProfileChange(type, UPDATE, ...)
  -> HandleDeleteChange(deleteRecords)  -> NotifyProfileChange(type, DELETE, ...)

NotifyProfileChange(profileType, changeType, dbKey, dbValue):
  -> funcsMap_[profileType] -> 调用对应的处理函数
     （例如 PROFILE_TYPE_DEVICE -> NotifyDeviceProfileAdd/Update/Delete）
  -> subscribeInfoMap_[subscribeKey] -> 对每个匹配的 SubscribeInfo：
     -> IProfileChangeListener->OnDeviceProfileAdd(profile) [IPC]
```

### 2.4 ContentSensorManager

`ContentSensorManager` 在启动时采集本地设备能力数据，并喂入 `DeviceProfileManager` 和 `ProfileDataManager`。

```
ContentSensorManager
  ├── Collect() -> 编排所有采集器
  │     ├── SystemInfoCollector::Collect(deviceProfile)
  │     ├── SyscapInfoCollector::Collect(deviceProfile)
  │     ├── DmsInfoCollector::Collect(deviceProfile)
  │     ├── PasteboardInfoCollector::Collect(deviceProfile)
  │     ├── CollaborationInfoCollector::Collect(deviceProfile)
  │     └── SwitchStatusCollector::Collect(deviceProfile, switchValue)
  └── CollectInfoToProfileData(collectProfile)
        └── DeviceProfileManager::PutDeviceProfile(collectProfile)  // 写入 KV 存储
```

### 2.5 ServiceInfoManager

`ServiceInfoManager` 在双层 KV 存储配置中管理服务信息记录。它有两个 KV 适配器：本地存储（`ServiceInfoKvAdapter`）和同步存储（`KVAdapter`）。

```
ServiceInfoManager
  ├── ServiceInfoKvAdapter（本地 KV 存储）
  │     ├── Put(key, value) -> localStore_->Put(...)
  │     ├── Get(key, out) -> localStore_->Get(...)
  │     ├── GetByPrefix(prefix, out) -> localStore_->GetEntries(...)
  │     ├── Delete(keys) -> localStore_->DeleteBatch(...)
  │     └── Sync(deviceList, mode) -> localStore_->Sync(...)
  ├── KVAdapter（同步 KV 存储——用于跨设备同步）
  │     ├── 相同的 IKVAdapter 接口，不同的 store ID
  │     └── Sync(deviceList, mode) -> syncStore_->Sync(...)
  └── SubscribeServiceInfoManager（通知）
        ├── SubscribeServiceInfo(saId, listener)
        ├── NotifyServiceInfoAdd(infos)
        ├── NotifyServiceInfoUpdate(infos)
        └── NotifyServiceInfoDelete(infos)
```

**ServiceInfo 写路径：**

```
PutServiceInfo(serviceInfo):
  -> ServiceInfoManager::PutServiceInfo(serviceInfo)
     -> 通过 cJSON 将 serviceInfo 序列化为 JSON
     -> serviceInfoKvAdapter_->Put(key, jsonString)    // 本地存储
     -> syncServiceInfoKvAdapter_->Put(key, jsonString) // 同步存储
     -> SubscribeServiceInfoManager::NotifyServiceInfoAdd(...)
```

### 2.6 DpAccountCommonEventManager

`DpAccountCommonEventManager` 订阅 OS 账户的公共事件，并将其转发给 `DeviceProfileManager`。

```
DpAccountCommonEventManager
  ├── SubscribeAccountCommonEvent(eventNameVec, callback)
  │     -> CommonEventManager::SubscribeCommonEvent(subscriber)
  └── OnReceiveEvent 回调 -> 调用 AccountEventCallback(userId, eventType)
        └── DistributedDeviceProfileServiceNew::AccountCommonEventCallback(userId, eventType)
              └── DeviceProfileManager::OnUserChange(lastUserId, curUserId)
                    -> 切换 KV 存储用户上下文
                    -> 修复用户变更相关数据
```

---

## 3. 关键内部数据流

### 3.1 画像创建路径（以 PutServiceProfile 为例）

```
外部调用者（通过 IPC）
  └── DistributedDeviceProfileServiceNew::PutServiceProfile(profile)
        └── PermissionManager::IsCallerTrust("PutServiceProfile")
              ├── GetCallerProcName() -> 与 permissionMap_ 比对
              └── 返回 true/false
        └── DeviceProfileManager::PutServiceProfile(profile)
              ├── ProfileControlUtils::PutServiceProfile(kvStore, profile)
              │     ├── GenerateKVKey(profile)  // "SERVICE_PROFILE/udid/serviceName/userId"
              │     ├── 通过 ParcelToJson 将画像序列化为 JSON
              │     └── kvStore->Put(key, json)
              └── ProfileCache::AddServiceProfile(profile)
                    └── serviceProfileMap_[key] = profile
        └── [KV 数据变更监听器异步触发]
              └── KvDataChangeListener::OnChange(notification)
                    └── SubscribeProfileManager::NotifyProfileChange(SERVICE_PROFILE, ADD, key, value)
                          └── 对每个匹配的订阅者：
                                └── IProfileChangeListener::OnServiceProfileAdd(profile) [IPC]
```

### 3.2 画像读取路径（以 GetDeviceProfile 为例）

```
外部调用者（通过 IPC）
  └── DistributedDeviceProfileServiceNew::GetDeviceProfile(deviceId, out)
        └── [检查画像是否有 userId/isMultiUser？]
              ├── [是] ProfileCache::GetDeviceProfile(deviceId, out)
              │     └── deviceProfileMap_.find(key) -> 返回缓存数据
              │     └── [未命中] ProfileControlUtils::GetDeviceProfile(kvStore, deviceId, out)
              │           └── kvStore->GetByPrefix(prefix, values)
              │           └── JsonToParcel(value, profile) -> 反序列化
              └── [否] DeviceProfileManager::GetDeviceProfile(deviceId, out)
                    └── ProfileControlUtils::GetDeviceProfile(kvStore, deviceId, out)
```

### 3.3 设备上线路径

```
DMAdapter::DmDeviceStateCallback::OnDeviceOnline(dmDeviceInfo)
  └── ConvertToTrustedDeviceInfo(dmDeviceInfo, trustedDeviceInfo)
  └── ProfileCache::OnNodeOnline(trustedDeviceInfo)
        └── onlineDevMap_[networkId] = trustedDeviceInfo
  └── DeviceProfileManager::OnDeviceOnline(trustedDeviceInfo)
        ├── FixDataOnDeviceOnline(deviceInfo)  // 修补本地/临时数据
        ├── NotifyNotOHBaseOnline(deviceInfo)  // 非 OH 设备通知
        └── E2ESyncDynamicProfile(deviceInfo)  // 触发 PUSH_PULL 同步
              └── kvStore->Sync({peerUdid}, SyncMode::PUSH_PULL)
```

### 3.4 设备离线路径

```
DMAdapter::DmDeviceStateCallback::OnDeviceOffline(dmDeviceInfo)
  └── ProfileCache::OnNodeOffline(peerNetworkId)
        └── onlineDevMap_.erase(networkId)
  └── [清理离线设备的缓存数据]
```

---

## 4. 内部事件分发

### 4.1 KV 数据变更监听器到订阅管理器

```
DistributedKv::KvStoreObserver::OnChange(ChangeNotification)
  └── KvDataChangeListener::OnChange(notification)
        ├── 提取 insertRecords、updateRecords、deleteRecords
        ├── HandleAddChange(insertRecords)
        │     └── 对每条记录：
        │           ├── 从键中解析 ProfileType
        │           ├── 将 JSON 反序列化为画像对象
        │           └── SubscribeProfileManager::NotifyProfileChange(type, ADD, key, value)
        ├── HandleUpdateChange(updateRecords)
        │     └── [相同流程，变更类型为 UPDATE]
        └── HandleDeleteChange(deleteRecords)
              └── [相同流程，变更类型为 DELETE]

SubscribeProfileManager::NotifyProfileChange(type, change, key, value)
  └── funcsMap_[type](key, value)  // 通过函数指针表分发
        └── GetSubscribeInfos(dbKey)
              └── subscribeInfoMap_.find(matchingSubcribeKey)
        └── 对每个匹配的 SubscribeInfo：
              └── listener_->SendRequest(IPC_CODE, data, reply)
                    └── ProfileChangeListenerProxy::OnDeviceProfileAdd(...)
```

### 4.2 ServiceInfo 变更到订阅管理器

```
KvDataChangeListener::OnChange(notification) [针对 service info KV 存储]
  └── HandleAddChange / HandleUpdateChange / HandleDeleteChange
        └── ConvertKVEntriesToServiceInfos
        └── SubscribeServiceInfoManager::NotifyServiceInfoAdd(infos)
              └── 对 serviceInfoMap_ 中的每个订阅者：
                    └── IServiceInfoChangeCallback::OnServiceInfoAdd(infos) [IPC]
```

### 4.3 业务事件回调链

```
PutBusinessEvent(event):
  └── BusinessEventManager::PutBusinessEvent(event)
        └── businessEventAdapter_->Put(key, value)  // 持久化到 KV 存储
        └── DistributedDeviceProfileServiceNew::NotifyBusinessEvent(event)
              └── businessCallbackMap_.find({saId, businessKey})
                    └── 对每个匹配的回调：
                          └── IBusinessCallback::OnBusinessEvent(event) [IPC]
```

---

## 5. 临时缓存到持久化流程

`DistributedDeviceProfileServiceNew` 维护一个 `dynamicProfileMap_`，用于在持久化之前保存临时画像数据。这用于在 KV 存储完全就绪前、早期初始化阶段提交的服务画像和特性画像。

### 流程

```
DistributedDeviceProfileServiceNew::PutServiceProfile(profile)
  └── 如果 !isInited_：
        └── dynamicProfileMap_[key] = jsonValue  // 临时存储
  └── PostInit() 完成后：
        └── SaveDynamicProfilesFromTempCache()
              └── GetDynamicProfilesFromTempCache(entries)
              └── DeviceProfileManager::SavePutTempCache(entries)
                    └── putTempCache_.insert(entries)
                    └── [批量刷新]
                    └── kvStore->PutBatch(values)
                    └── putTempCache_.clear()

DistributedDeviceProfileServiceNew::PutCharacteristicProfile(profile)
  └── 如果 !isInited_：
        └── PutCharacteristicProfileBatchPreprocess(profiles)
              └── 开关画像：switchProfileMap_[key] = profile
              └── 动态画像：dynamicProfileMap_[key] = jsonValue
  └── PostInit() 后：
        └── SaveSwitchProfilesFromTempCache()
              └── 遍历 switchProfileMap_
              └── ProfileControlUtils::PutSwitchCharacteristicProfileBatch(...)
                    └── switchAdapter->PutBatch(values)
        └── SaveDynamicProfilesFromTempCache() [与服务画像流程相同]
```

### 关键数据结构

| 数据结构 | 所属者 | 用途 |
|---|---|---|
| `dynamicProfileMap_` | `DistributedDeviceProfileServiceNew` | 初始化完成前动态画像的临时存储。Map\<string, string\>（键 -> JSON）。由 `dynamicProfileMapMtx_` 保护。 |
| `switchProfileMap_` | `DistributedDeviceProfileServiceNew` | 开关特性画像的临时存储。Map\<string, CharacteristicProfile\>。由 `switchProfileMapMtx_` 保护。 |
| `putTempCache_` | `DeviceProfileManager` | KV 批量写入的累积缓冲区。Map\<string, string\>。由 `putTempCacheMutex_` 保护。 |
| `deviceProfileMap_` | `ProfileCache` | 设备画像的内存缓存。Map\<string, DeviceProfile\>。由 `deviceProfileMutex_` 保护。 |
| `serviceProfileMap_` | `ProfileCache` | 服务画像的内存缓存。由 `serviceProfileMutex_` 保护。 |
| `charProfileMap_` | `ProfileCache` | 特性画像的内存缓存。由 `charProfileMutex_` 保护。 |
| `onlineDevMap_` | `ProfileCache` | 当前在线设备的映射表（networkId -> TrustedDeviceInfo）。由 `onlineDeviceLock_` 保护。 |
| `subscribeInfoMap_` | `SubscribeProfileManager` | subscribeKey -> SubscribeInfo 集合的映射表。由 `subscribeMutex_` 保护。 |
| `businessCallbackMap_` | `DistributedDeviceProfileServiceNew` | (saId, businessKey) -> 回调的映射表。由 `businessEventCallbackMapMtx_` 保护。 |
| `dpInitedCallbackMap_` | `DistributedDeviceProfileServiceNew` | saId -> 初始化完成通知回调的映射表。由 `dpInitedCallbackMapMtx_` 保护。 |
| `pinCodeCallbackMap_` | `DistributedDeviceProfileServiceNew` | (bundleName, pinExchangeType) -> 回调的映射表。由 `pinCodeCallbackMapMtx_` 保护。 |

---

## 6. 线程安全模型

所有管理器类都使用 `DECLARE_SINGLE_INSTANCE`（单实例模式）。线程安全通过以下机制保证：

- **每个数据结构一个互斥锁：** 每个映射表都有自己的互斥锁（例如 `deviceProfileMutex_`、`serviceProfileMutex_`、`subscribeMutex_`）。
- **KV 存储互斥锁：** `DeviceProfileManager` 中的 `dynamicStoreMutex_` 序列化 KV I/O。
- **RDB 互斥锁：** `TrustProfileManager` 中的 `aclMutex_` 和 `rdbMutex_` 序列化 ACL 操作。
- **原子标志：** `isInited_`（atomic\<bool\>）在大多数管理器中用作生命周期守卫。
- **EventHandler：** `EventHandleFactory` 创建 FFRT 事件处理器用于异步任务（例如静态能力采集）。

### 加锁顺序（防止死锁）

1. 权限检查（不持有锁）
2. `ProfileCache` 锁（内部缓存映射表）
3. 管理器级锁（例如 `dynamicProfileMapMtx_`、`aclMutex_`）
4. KV/RDB 适配器锁（最低层级）

---

## 参见

- `docs/05-interfaces/01-external-api.md` -- 公开 API 参考（50 个 API）
- `docs/05-interfaces/03-dependency-api.md` -- 外部模块依赖
- `services/core/include/deviceprofilemanager/device_profile_manager.h` -- 主画像管理器
- `services/core/include/trustprofilemanager/trust_profile_manager.h` -- 信任/ACL 管理器
- `services/core/include/subscribeprofilemanager/subscribe_profile_manager.h` -- 订阅管理器
