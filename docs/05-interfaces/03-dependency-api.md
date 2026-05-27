# 外部依赖 API 参考

> DeviceProfile 调用的所有外部 API（而非其自身提供的 API）。
> 本文档记录 DP 的"出站"API 面——即 DP 依赖的其他 OpenHarmony 子系统的接口。

## 依赖概览

来自 `bundle.json` 的 `deps.components` 和 `services/core/BUILD.gn` 的 `external_deps`：

| 模块 | GN 依赖 (external_deps) | 对 DP 的作用 |
|---|---|---|
| DeviceManager | `device_manager:devicemanagersdk` | 设备状态回调（上线/离线/变更/就绪）、初始化回调 |
| KV Store | `kv_store:distributeddata_inner` | 分布式画像数据存储，跨设备同步 |
| RDB | `relational_store:native_rdb` | 结构化画像存储（SQLite） |
| Asset | `asset:asset_sdk` | 硬件加密的会话密钥存储 |
| SAMGR | `samgr:samgr_common`、`samgr:samgr_proxy` | 系统能力管理，IPC 代理创建 |
| SoftBus | `dsoftbus`（通过 `dmsfwk:common_sdk`） | 本地设备信息（networkId、UDID、UUID） |
| IPC | `ipc:ipc_core` | 进程间通信（IRemoteBroker、Parcel） |
| Access Token | `access_token:libaccesstoken_sdk` | 调用者身份验证 |
| Common Event Service | `common_event_service:cesfwk_core`、`cesfwk_innerkits` | 账户公共事件订阅 |
| OS Account | `os_account:libaccountkits`、`os_account:os_account_innerkits` | 多用户支持（前台用户、账户 ID） |
| HiSysEvent | `hisysevent:libhisysevent` | 系统事件日志和雷达上报 |
| HiLog | `hilog:libhilog` | 调试/追踪日志，域 0xD004400 |
| cJSON | `cJSON:cjson` | JSON 解析与构建 |
| nlohmann::json | `json`（third_party） | JSON 序列化（nlohmann/json） |
| Config Policy | `config_policy:configpolicy_util` | 平台配置文件查找 |
| DataShare | `data_share:datashare_consumer` | 设置数据访问 |
| device_auth | `device_auth:deviceauth_sdk` | 设备认证集成 |
| SysCap Codec | `syscap_codec:syscap_interface_shared` | 系统能力编解码 |
| FFRT | `ffrt:libffrt` | 并发任务运行时（异步事件处理） |
| EventHandler | `eventhandler:libeventhandler` | 延时/卸载任务的事件循环 |
| Hitrace | `hitrace:hitrace_meter` | 分布式追踪标记 |
| HiCollie | `hicollie:libhicollie` | 看门狗/卡顿检测 |
| Init | `init:libbegetutil` | 启动阶段工具 |
| C Utils | `c_utils:utils` | 系统工具函数 |
| SAFWK | `safwk:system_ability_fwk` | 系统能力框架 |
| DMSFwk | `dmsfwk:common_sdk` | 分布式管理服务框架 |
| Memory Manager | `memmgr:memmgrclient` | 内存压力管理 |
| SELinux | `selinux_adapter`（组件） | 安全标签强制执行 |

---

## 1. DeviceManager

**模块：** `DistributedHardware::DeviceManager`
**GN 依赖：** `device_manager:devicemanagersdk`
**适配器：** `DMAdapter`（`services/core/src/dm_adapter/dm_adapter.cpp`）

### 调用的 API

| API | 签名 | 用途 |
|---|---|---|
| `InitDeviceManager` | `int32_t InitDeviceManager(const std::string& pkgName, std::shared_ptr<DmInitCallback> callback)` | 初始化与 DM 服务的连接 |
| `UnInitDeviceManager` | `int32_t UnInitDeviceManager(const std::string& pkgName)` | 断开 DM 连接 |
| `RegisterDevStateCallback` | `int32_t RegisterDevStateCallback(const std::string& pkgName, const std::string& extra, std::shared_ptr<DeviceStateCallback> callback)` | 注册设备上线/离线/变更/就绪事件 |
| `UnRegisterDevStateCallback` | `int32_t UnRegisterDevStateCallback(const std::string& pkgName)` | 取消注册设备状态回调 |
| `GetUuidByNetworkId` | `int32_t GetUuidByNetworkId(const std::string& pkgName, const std::string& netWorkId, std::string& uuid)` | 将 networkId 解析为 UUID |

### DP 实现的回调接口

```cpp
// DeviceStateCallback -- DMAdapter::DmDeviceStateCallback
void OnDeviceOnline(const DmDeviceInfo& deviceInfo) override;
void OnDeviceOffline(const DmDeviceInfo& deviceInfo) override;
void OnDeviceChanged(const DmDeviceInfo& deviceInfo) override;
void OnDeviceReady(const DmDeviceInfo& deviceInfo) override;

// DmInitCallback -- DMAdapter::DpDmInitCallback
void OnRemoteDied() override;  // DM 死亡时重新初始化
```

### 约束条件

| 约束项 | 详情 |
|---|---|
| 初始化顺序 | DM 必须在 DP 的本地信息可用之后（ProfileCache 已获取本地 UDID/UUID）进行初始化。 |
| 线程安全 | 回调在 DM 的线程上到达；DMAdapter 将其转发到 EventHandler 处理。 |
| 包名 | DP 以 `"deviceprofile"` 身份向 DM 注册。 |
| DA 重初始化 | DM 服务死亡时，`DpDmInitCallback::OnRemoteDied()` 触发重初始化，重试延迟 3 秒。 |

### 错误处理

- DM 初始化失败：通过 HiLog 记录日志，服务进入降级模式（无设备上线/离线事件）。
- 设备状态回调错误：记录为警告；单个回调失败不影响其他回调。
- `GetUuidByNetworkId` 失败：UUID 查询可能返回空；调用者优雅处理。

---

## 2. KV Store（distributeddata_inner）

**模块：** `DistributedKv`
**GN 依赖：** `kv_store:distributeddata_inner`
**适配器：** `KVAdapter`、`ServiceInfoKvAdapter`、`BusinessEventAdapter`

### 调用的 API

| API | 签名 | 用途 |
|---|---|---|
| `DistributedKvDataManager::GetSingleKvStore` | `Status GetSingleKvStore(const Options& options, const AppId& appId, const StoreId& storeId, std::shared_ptr<SingleKvStore>& kvStore)` | 打开或创建 KV 存储 |
| `SingleKvStore::Put` | `Status Put(const Key& key, const Value& value)` | 插入/更新单个键值对 |
| `SingleKvStore::PutBatch` | `Status PutBatch(const std::vector<Entry>& entries)` | 批量插入/更新 |
| `SingleKvStore::Get` | `Status Get(const Key& key, Value& value)` | 获取单个值 |
| `SingleKvStore::GetEntries` | `Status GetEntries(const Key& prefix, std::vector<Entry>& entries)` | 按键前缀获取条目 |
| `SingleKvStore::Delete` | `Status Delete(const Key& key)` | 删除单个键 |
| `SingleKvStore::DeleteBatch` | `Status DeleteBatch(const std::vector<Key>& keys)` | 批量删除 |
| `SingleKvStore::Sync` | `Status Sync(const std::vector<std::string>& deviceIds, SyncMode mode)` | 与远程设备同步数据 |
| `SingleKvStore::RegisterDataChangeListener` | `Status RegisterDataChangeListener(std::shared_ptr<KvStoreObserver> observer)` | 注册数据变更通知 |
| `SingleKvStore::UnRegisterDataChangeListener` | `Status UnRegisterDataChangeListener(std::shared_ptr<KvStoreObserver> observer)` | 取消注册数据变更监听器 |
| `SingleKvStore::RegisterSyncCallback` | `Status RegisterSyncCallback(std::shared_ptr<KvStoreSyncCallback> callback)` | 注册同步完成回调 |
| `SingleKvStore::RemoveDeviceData` | `Status RemoveDeviceData(const std::string& deviceId)` | 移除指定设备的所有数据 |
| `DistributedKvDataManager::CloseKvStore` | `Status CloseKvStore(const AppId& appId, const StoreId& storeId)` | 关闭 KV 存储 |
| `DistributedKvDataManager::DeleteKvStore` | `Status DeleteKvStore(const AppId& appId, const StoreId& storeId)` | 彻底删除 KV 存储 |

### KV 存储实例

| 存储 | 适配器 | AppId | DataType | 用途 |
|---|---|---|---|---|
| 动态画像 | `KVAdapter`（通过 `DeviceProfileManager`） | `"device_profile"` | `TYPE_DYNAMICS` | 设备/服务/特性画像 |
| 服务信息（本地） | `ServiceInfoKvAdapter` | `"service_info"` | `TYPE_STATICS` | 服务信息记录（本地） |
| 服务信息（同步） | `KVAdapter`（通过 `ServiceInfoManager`） | `"service_info_sync"` | `TYPE_STATICS` | 服务信息记录（同步） |
| 业务事件 | `BusinessEventAdapter` | `"business_event"` | `TYPE_STATICS` | 业务事件键值对 |

### 回调接口

```cpp
// KvDataChangeListener 实现 DistributedKv::KvStoreObserver
void OnChange(const ChangeNotification& changeNotification) override;
void OnChange(const DataOrigin& origin, Keys&& keys) override;
void OnSwitchChange(const SwitchNotification& notification) override;

// KvSyncCompletedListener 实现 DistributedKv::KvStoreSyncCallback
void SyncCompleted(const std::map<std::string, Status>& results) override;

// KvStoreDeathRecipient 实现 DistributedKv::KvStoreDeathRecipient
void OnRemoteDied() override;
```

### 约束条件

| 约束项 | 详情 |
|---|---|
| 初始化顺序 | KV 存储要求 `DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID`（SAID 3340）在线。DP 在 `PostInit()` 中等待它上线。 |
| 线程安全 | `KvStoreObserver::OnChange` 可能在任意线程上被调用。DP 的实现通过 EventHandler 分发。 |
| DataType | DYNAMICS = 可跨设备同步；STATICS = 仅本地（应用级别）。 |
| SyncMode | PULL=0、PUSH=1、PUSH_PULL=2。同步是异步的；完成情况通过 `KvStoreSyncCallback` 报告。 |

### 错误处理

- `GetSingleKvStore` 返回 `Status` 枚举值。DP 在存储未就绪时重试。
- 所有 KV 操作均检查返回状态；失败时通过 HiLog 记录日志并附带 store ID。
- 当 `KvStoreDeathRecipient::OnRemoteDied()` 触发时，DP 重新初始化受影响的 KV 存储适配器。
- 数据变更监听器注册失败不是致命错误（基于订阅的通知将不可用，但存储功能仍正常）。

---

## 3. RDB（native_rdb）

**模块：** `OHOS::NativeRdb`
**GN 依赖：** `relational_store:native_rdb`
**适配器：** `RdbAdapter`、`LocalServiceInfoRdbAdapter`、`ProfileDataRdbAdapter`

### 调用的 API

| API | 签名 | 用途 |
|---|---|---|
| `RdbHelper::GetRdbStore` | `static std::shared_ptr<RdbStore> GetRdbStore(const RdbStoreConfig& config, int version, RdbOpenCallback& openCallback, int& errCode)` | 打开或创建 RDB 存储（SQLite 数据库） |
| `RdbStore::Insert` | `int Insert(int64_t& outRowId, const std::string& table, const ValuesBucket& initialValues)` | 插入一行 |
| `RdbStore::Update` | `int Update(int& changedRows, const std::string& table, const ValuesBucket& values, const std::string& whereClause, const std::vector<ValueObject>& bindArgs)` | 更新匹配的行 |
| `RdbStore::Delete` | `int Delete(int& deletedRows, const std::string& table, const std::string& whereClause, const std::vector<ValueObject>& bindArgs)` | 删除匹配的行 |
| `RdbStore::QuerySql` | `std::shared_ptr<ResultSet> QuerySql(const std::string& sql, const std::vector<ValueObject>& bindArgs)` | 执行原始 SQL 查询 |
| `RdbStore::ExecuteSql` | `int ExecuteSql(const std::string& sql)` | 执行 DDL（CREATE TABLE、CREATE INDEX 等） |
| `ResultSet::GoToNextRow` | `int GoToNextRow()` | 移动游标 |
| `ResultSet::GetString` | `int GetString(int columnIndex, std::string& value)` | 读取字符串列 |
| `ResultSet::GetInt` | `int GetInt(int columnIndex, int& value)` | 读取整型列 |
| `ResultSet::GetLong` | `int GetLong(int columnIndex, int64_t& value)` | 读取 int64 列 |
| `ResultSet::GetBlob` | `int GetBlob(int columnIndex, std::vector<uint8_t>& value)` | 读取二进制列 |
| `ValuesBucket::PutString` | `void PutString(const std::string& columnName, const std::string& value)` | 在 bucket 中设置字符串值 |
| `ValuesBucket::PutInt` | `void PutInt(const std::string& columnName, int value)` | 在 bucket 中设置整型值 |
| `ValuesBucket::PutLong` | `void PutLong(const std::string& columnName, int64_t value)` | 在 bucket 中设置 int64 值 |
| `ValuesBucket::PutBlob` | `void PutBlob(const std::string& columnName, const std::vector<uint8_t>& value)` | 在 bucket 中设置二进制值 |

### RDB 适配器实现

| 适配器 | 数据库版本 | 表 | 用途 |
|---|---|---|---|
| `RdbAdapter` | 3（从 v1->v2->v3 迁移） | `trust_device_profile`、`access_control_profile`、`accesser`、`accessee` | 信任和 ACL 管理 |
| `LocalServiceInfoRdbAdapter` | 1 | `local_service_info` | 本地服务 pin 码数据 |
| `ProfileDataRdbAdapter` | 3（从 v1->v2->v3 迁移） | `device_profile`、`product_info`、`device_icon_info` | 设备画像、产品信息、图标 |

### 约束条件

| 约束项 | 详情 |
|---|---|
| 文件路径 | 默认 RDB 路径：`/data/service/el1/public/deviceprofile/` |
| Schema 迁移 | `RdbOpenCallback::OnCreate` 创建表；`OnUpgrade` 处理 Schema 迁移（v1->v2 新增列；v2->v3 新增列 + 重建索引）。 |
| 线程安全 | RDB 存储不是线程安全的。每个适配器都有自己的互斥锁（`rdbAdapterMtx_`、`LocalServiceInfoRdbAdapterMtx_`）。 |
| 数据库重建 | 如果数据库文件损坏，`GetRDBPtr` 会删除并重建存储。 |

### 错误处理

- 插入：唯一约束违反返回 `E_SQLITE_CONSTRAINT`（视为 DP_ALREADY_EXISTS）。
- 更新/删除：无匹配时返回 0 行变更（视为 DP_NOT_FOUND）。
- 查询：错误时返回 null `ResultSet`；迭代前检查。
- 数据库迁移：如果迁移失败，删除并重建数据库。

---

## 4. Asset SDK

**模块：** Asset（硬件加密存储）
**GN 依赖：** `asset:asset_sdk`
**适配器：** `AssetAdapter`（`services/core/src/persistenceadapter/assetadapter/asset_adapter.cpp`）

### 调用的 API

| API | 签名 | 用途 |
|---|---|---|
| `OH_Asset_Add` | `int32_t OH_Asset_Add(const AssetAttr* attrs, uint32_t attrCnt)` | 存储加密资产 |
| `OH_Asset_Update` | `int32_t OH_Asset_Update(const AssetAttr* query, uint32_t queryCnt, const AssetAttr* attrsToUpdate, uint32_t updateCnt)` | 更新已有资产 |
| `OH_Asset_Query` | `int32_t OH_Asset_Query(const AssetAttr* query, uint32_t queryCnt, AssetResultSet* resultSet)` | 查询资产 |
| `OH_Asset_Remove` | `int32_t OH_Asset_Remove(const AssetAttr* query, uint32_t queryCnt)` | 删除资产 |
| `OH_Asset_ParseAttr` | `AssetAttr* OH_Asset_ParseAttr(const AssetResult* result, AssetTag tag)` | 从查询结果中提取属性 |

### 使用的 Asset 标签

| 标签 | 用途 |
|---|---|
| `ASSET_TAG_ALIAS` | 会话密钥别名（唯一标识符） |
| `ASSET_TAG_SECRET` | 会话密钥值（敏感数据，静态加密） |
| `ASSET_TAG_ACCESSIBILITY` | 访问控制（设备级、用户级） |
| `ASSET_TAG_DATA_LABEL_CRITICAL_1` | DP 数据自定义标签 |
| `ASSET_TAG_DATA_LABEL_CRITICAL_2` | 辅助标签 |

### 约束条件

| 约束项 | 详情 |
|---|---|
| 安全级别 | 硬件级加密（如可用则使用 TEE/安全元件）。 |
| 初始化顺序 | Asset 必须在使用 SessionKeyManager 之前初始化。无需显式初始化 API；首次 `Asset_Add` 即完成初始化。 |
| 线程安全 | Asset API 在 HAL 级别是线程安全的。适配器无需额外加锁调用。 |
| 数据局部性 | Asset 数据仅限本地设备（不支持跨设备同步）。 |

### 错误处理

- 如果会话密钥不存在，`OH_Asset_Query` 返回 `ASSET_NOT_FOUND`（视为 DP_NOT_FOUND）。
- Asset 操作返回非零码视为 DP_DB_ERR。
- 缺失标签时 `AssetAdapter::ParseAttr` 返回 nullptr；调用者优雅处理。

---

## 5. SAMGR（系统能力管理器）

**模块：** `OHOS::SystemAbility`
**GN 依赖：** `samgr:samgr_common`、`samgr:samgr_proxy`

### 调用的 API

| API | 签名 | 用途 |
|---|---|---|
| `SystemAbilityManagerClient::GetSystemAbilityManager` | `sptr<ISystemAbilityManager> GetSystemAbilityManager()` | 获取 SA 管理器代理 |
| `ISystemAbilityManager::GetSystemAbility` | `sptr<IRemoteObject> GetSystemAbility(int32_t systemAbilityId)` | 通过 ID 获取远程 SA |
| `ISystemAbilityManager::AddSystemAbilityListener` | `int32_t AddSystemAbilityListener(int32_t systemAbilityId, sptr<ISystemAbilityStatusChange> listener)` | 注册 SA 生命周期事件 |
| `ISystemAbilityManager::CheckSystemAbility` | `sptr<IRemoteObject> CheckSystemAbility(int32_t systemAbilityId)` | 检查 SA 是否可用 |
| `ISystemAbilityManager::UnloadSystemAbility` | `int32_t UnloadSystemAbility(int32_t systemAbilityId)` | 请求 SA 卸载 |
| `SystemAbility::Publish` | `bool Publish(sptr<IRemoteObject> systemAbility)` | 以 SA 6001 身份发布自身 |
| `SystemAbility::OnStart` | `void OnStart(const SystemAbilityOnDemandReason& reason)` | SA 启动回调（覆写） |
| `SystemAbility::OnStop` | `void OnStop()` | SA 停止回调（覆写） |
| `SystemAbility::OnIdle` | `int32_t OnIdle(const SystemAbilityOnDemandReason& reason)` | SA 空闲回调（覆写） |
| `SystemAbility::OnAddSystemAbility` | `void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)` | 依赖 SA 上线回调 |

### SAID 依赖项（DP 在 PostInit 前等待这些 SA）

| SAID | SA 名称 | 用途 |
|---|---|---|
| 4002 | SoftBus Server | 本地设备信息（networkId、UDID） |
| 3340 | Distributed KV Data Service | KV 存储操作 |
| 3202 | Device Manager | 设备状态回调 |
| 1000 | Account System Ability（起始） | 多用户信息 |
| 3201 | Memory Manager | 内存可见性 |

### 约束条件

| 约束项 | 详情 |
|---|---|
| 按需启动 | DP（SA 6001）由设备上线和 `usual.event.BOOT_COMPLETED` 触发按需启动。 |
| 空闲卸载 | 所有 SA 依赖监听器断开连接且没有进行中的 IPC 调用后，DP 卸载自身。 |
| 初始化顺序 | `OnStart` -> `Init()`（管理器）-> 等待依赖 -> `PostInit()` -> 通知订阅者。 |

### 错误处理

- `GetSystemAbility` 返回 null：SA 依赖尚未启动。DP 通过 `AddSystemAbilityListener` 订阅并在 SA 上线时重试。
- `Publish` 失败：致命错误。DP 无法作为服务运行；通过 HiLog 记录错误。

---

## 6. SoftBus

**模块：** `DSoftBus`
**GN 依赖：** `dsoftbus`（通过 `dmsfwk:common_sdk`）

### 调用的 API

| API | 签名 | 用途 |
|---|---|---|
| `GetLocalNodeDeviceInfo` | `int32_t GetLocalNodeDeviceInfo(const std::string& nodeName, NodeDeviceInfo& deviceInfo)` | 获取本地设备网络信息（networkId、UDID、UUID） |

### DP 中的使用方式

由 `ProfileCache::Init()` 用于填充：
- `localNetworkId_` -- 本地 SoftBus 网络标识符
- `localUuid_` -- 本地设备 UUID
- 本地 UDID（通过 SoftBus 或 DM）

### 约束条件

| 约束项 | 详情 |
|---|---|
| 初始化顺序 | 必须在 DM 初始化之后调用。DM 提供包括 networkId 在内的设备信息。 |
| 线程安全 | 在 Init() 期间调用一次；结果在生命周期内缓存。 |
| SA 依赖 | 要求 SoftBus SA（4002）在线。 |

### 错误处理

- `GetLocalNodeDeviceInfo` 失败：DP 无法确定本地身份；初始化失败并记录错误日志。
- 调用后 networkId 或 UDID 为空：DP 进入降级状态并记录警告。

---

## 7. IPC（进程间通信）

**模块：** `OHOS::IRemoteBroker`、`OHOS::MessageParcel`
**GN 依赖：** `ipc:ipc_core`

### 调用的 API

| API | 签名 | 用途 |
|---|---|---|
| `IRemoteBroker::AsObject` | `sptr<IRemoteObject> AsObject()` | 获取远程对象引用 |
| `IRemoteStub::SendRequest` | `int SendRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)` | 发送 IPC 请求 |
| `IRemoteProxy::SendRequest` | `int SendRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)` | 分发 IPC 请求 |
| `MessageParcel::WriteInt32` | `bool WriteInt32(int32_t value)` | 序列化 int32 |
| `MessageParcel::WriteString` | `bool WriteString(const std::string& value)` | 序列化字符串 |
| `MessageParcel::WriteUint32` | `bool WriteUint32(uint32_t value)` | 序列化 uint32 |
| `MessageParcel::WriteInt64` | `bool WriteInt64(int64_t value)` | 序列化 int64 |
| `MessageParcel::WriteBool` | `bool WriteBool(bool value)` | 序列化布尔值 |
| `MessageParcel::WriteParcelable` | `bool WriteParcelable(const Parcelable* object)` | 序列化 Parcelable 对象 |
| `MessageParcel::WriteRemoteObject` | `bool WriteRemoteObject(const sptr<IRemoteObject>& object)` | 序列化远程对象引用 |
| `MessageParcel::ReadInt32` | `bool ReadInt32(int32_t& value)` | 反序列化 int32 |
| `MessageParcel::ReadString` | `bool ReadString(std::string& value)` | 反序列化字符串 |
| `MessageParcel::ReadParcelable` | `template<typename T> T* ReadParcelable()` | 反序列化 Parcelable 对象 |
| `MessageParcel::ReadRemoteObject` | `sptr<IRemoteObject> ReadRemoteObject()` | 反序列化远程对象引用 |
| `IRemoteObject::AddDeathRecipient` | `bool AddDeathRecipient(const sptr<DeathRecipient>& recipient)` | 注册死亡回调 |
| `IRemoteObject::RemoveDeathRecipient` | `bool RemoveDeathRecipient(const sptr<DeathRecipient>& recipient)` | 取消注册死亡回调 |
| `DeathRecipient::OnRemoteDied` | `void OnRemoteDied(const wptr<IRemoteObject>& object)` | 处理远程进程死亡 |
| `DECLARE_INTERFACE_DESCRIPTOR` | 宏 | 定义接口描述符字符串 |
| `DECLARE_SYSTEM_ABILITY` | 宏 | 注册为系统能力 |
| `DECLARE_SINGLE_INSTANCE` | 宏 | 单实例访问器 |

### 使用的 IPC 回调接口

| 接口 | 描述符 | 用途 |
|---|---|---|
| `IProfileChangeListener` | `OHOS.DeviceProfile.IProfileListener` | 画像变更通知回调 |
| `ISyncCompletedCallback` | （隐式） | 同步完成通知 |
| `IDpInitedCallback` | （隐式） | 初始化完成通知 |
| `IPinCodeInvalidCallback` | （隐式） | PIN 码无效通知 |
| `IServiceInfoChangeCallback` | （隐式） | 服务信息变更通知 |
| `IBusinessCallback` | （IDL 生成） | 业务事件通知 |

### 约束条件

| 约束项 | 详情 |
|---|---|
| 线程安全 | `SendRequest` 可能阻塞。DP 在 EventHandler 线程而非主循环中调用 IPC。 |
| 死亡处理 | DP 在订阅者代理上注册 `DeathRecipient`。订阅者死亡时，清理其订阅信息。 |
| 同步模式 | IPC 调用使用同步模式。回复预计在超时时间内返回。 |
| Parcel 所有权 | ReadParcelable 返回堆分配对象；调用者必须释放。 |

### 错误处理

- `SendRequest` 返回非零：视为 DP_IPC_ERR，记录为警告。
- `AddDeathRecipient` 失败：订阅仍已注册；清理将在下次通知失败时进行。
- 读/写失败：`Marshalling/UnMarshalling` 返回 false；调用者返回 DP_IPC_ERR。

---

## 8. Access Token

**模块：** `OHOS::Security::AccessToken`
**GN 依赖：** `access_token:libaccesstoken_sdk`

### 调用的 API

| API | 签名 | 用途 |
|---|---|---|
| `GetNativeTokenInfo` | `AccessTokenID GetNativeTokenInfo(pid_t callingPid, NativeTokenInfo& nativeTokenInfo)` | 获取调用者的访问令牌信息（进程名） |
| `VerifyNativeToken` | `int VerifyNativeToken(const AccessTokenID& tokenId, const std::string& permissionName)` | 验证原生令牌权限 |
| `CheckPermission` | `int CheckPermission(const AccessTokenID& tokenId, const std::string& permissionName)` | 检查令牌 ID 的权限 |

### PermissionManager 中的使用方式

```cpp
bool PermissionManager::IsCallerTrust(const std::string& interfaceName) {
    std::string procName = GetCallerProcName();
    return permissionMap_[interfaceName].count(procName) > 0 ||
           permissionMap_[interfaceName].count("all") > 0;
}

std::string PermissionManager::GetCallerProcName() {
    // 从 IPC 调用 PID 获取原生令牌信息
    // 从令牌信息中提取进程名
    return procName;
}
```

### 约束条件

| 约束项 | 详情 |
|---|---|
| IPC 上下文 | 调用 PID 从 IPC 上下文中提取（非显式传入）。对并发 IPC 调用是线程安全的。 |
| 配置文件 | `permissionMap_` 在启动时从 `permission/permission.json` 初始化。 |

### 错误处理

- 无法获取令牌信息：进程名为空；权限被拒绝。
- `CheckPermission` 失败：返回非零；视为权限不足。

---

## 9. Common Event Service

**模块：** `OHOS::EventFwk`
**GN 依赖：** `common_event_service:cesfwk_core`、`common_event_service:cesfwk_innerkits`

### 调用的 API

| API | 签名 | 用途 |
|---|---|---|
| `CommonEventManager::SubscribeCommonEvent` | `bool SubscribeCommonEvent(const std::shared_ptr<CommonEventSubscriber>& subscriber)` | 订阅公共事件 |
| `CommonEventManager::UnSubscribeCommonEvent` | `bool UnSubscribeCommonEvent(const std::shared_ptr<CommonEventSubscriber>& subscriber)` | 取消订阅公共事件 |

### 订阅的事件

| 事件 | 用途 |
|---|---|
| `usual.event.USER_SWITCHED` | 检测前台用户变更 |
| `usual.event.USER_REMOVED` | 清理已删除用户的数据 |
| 账户相关事件 | 多用户账户生命周期 |

### 实现

`DpAccountCommonEventManager` 创建 `DpAccountEventSubscriber`（继承 `CommonEventSubscriber`）并将其注册到 CommonEvent 服务。订阅者的 `OnReceiveEvent` 回调到 `DistributedDeviceProfileServiceNew::AccountCommonEventCallback`，处理：
- `USER_SWITCHED`：`DeviceProfileManager::OnUserChange(lastUserId, curUserId)`——切换 KV 存储上下文，修复用户变更相关数据。
- `USER_REMOVED`：`DeviceProfileManager::DeleteRemovedUserData(userId)`——清理已删除用户的所有画像数据。

### 约束条件

| 约束项 | 详情 |
|---|---|
| 初始化顺序 | 在 PostInit 之后订阅（账户 SA 必须在线）。 |
| 线程安全 | `OnReceiveEvent` 可能在任意线程上被调用。DP 通过 EventHandler 处理。 |
| SA 依赖 | 要求 CommonEvent SA 存活；DP 监控 SA 状态并在 `OnAddSystemAbility` 时重试订阅。 |

### 错误处理

- `SubscribeCommonEvent` 失败：事件将不会被接收；DP 无法自动检测用户变更。记录为错误。
- 事件处理器为空：跳过回调调用并记录警告。

---

## 10. OS Account

**模块：** `OHOS::AccountSA`
**GN 依赖：** `os_account:libaccountkits`、`os_account:os_account_innerkits`

### 调用的 API

| API | 签名 | 用途 |
|---|---|---|
| `GetForegroundOsAccountInfo` | `int32_t GetForegroundOsAccountInfo(OsAccountInfo& info)` | 获取当前前台账户信息 |
| `GetOsAccountInfoById` | `int32_t GetOsAccountInfoById(int id, OsAccountInfo& info)` | 通过用户 ID 获取账户信息 |
| `GetOhosAccountId` | `std::string GetOhosAccountId()` | 获取当前 Ohos 账户 ID |
| `GetOhosAccountIdByUserId` | `std::string GetOhosAccountIdByUserId(int32_t userId)` | 通过用户 ID 获取 Ohos 账户 ID |

### DP 中的使用方式

- `MultiUserManager::GetCurrentForegroundUserID()`——在启动时查询前台用户。
- `MultiUserManager::GetOhosAccountId()`——获取 Ohos 账户 ID 用于多用户画像键构造。
- 画像键包含 `userId` 或 `accountId` 以实现多用户数据隔离。

### 约束条件

| 约束项 | 详情 |
|---|---|
| 初始化顺序 | 在 PostInit 期间调用，此时 OS Account SA 已在线。 |
| 特性标志 | 多用户特性受 `-DDP_OS_ACCOUNT_PART_EXISTS` 编译标志控制。 |
| 线程安全 | OS Account API 是线程安全的。 |

### 错误处理

- `GetForegroundOsAccountInfo` 失败：使用 `DEFAULT_USER_ID`（-1）作为回退值。
- `GetOhosAccountId` 失败：返回空字符串；画像键中省略账户 ID。

---

## 11. HiSysEvent

**模块：** `OHOS::HiviewDFX::HiSysEvent`
**GN 依赖：** `hisysevent:libhisysevent`

### 调用的 API

| API | 签名 | 用途 |
|---|---|---|
| `HiSysEventWrite` | `int HiSysEventWrite(const std::string& domain, const std::string& eventName, HiSysEvent::EventType type, ...)` | 向 HiView 写入系统事件 |

### 事件定义（来自 `hisysevent.yaml`）

| 事件 | 类型 | 用途 |
|---|---|---|
| `DP_SYNC_COMPLETED` | STATISTIC | 同步操作结果上报 |
| `DP_SYNC_FAILED` | FAULT | 同步失败上报 |
| `DP_DB_EXCEPTION` | FAULT | 数据库异常上报 |

### 约束条件

| 约束项 | 详情 |
|---|---|
| 域 | DP 使用域 `DEVICE_PROFILE` 进行 HiSysEvent 上报。 |
| 频率限制 | FAULT 事件有频率限制以避免日志泛滥。 |
| 初始化顺序 | 可早期使用；无需显式初始化。 |

### 错误处理

- `HiSysEventWrite` 失败：静默忽略（尽力而为的日志记录）。

---

## 12. HiLog

**模块：** `OHOS::HiviewDFX::HiLog`
**GN 依赖：** `hilog:libhilog`

### 调用的 API

| 宏 | 签名 | 用途 |
|---|---|---|
| `HILOGD` | 调试级日志 | 详细调试追踪 |
| `HILOGI` | 信息级日志 | 信息性消息 |
| `HILOGW` | 警告级日志 | 警告条件 |
| `HILOGE` | 错误级日志 | 错误条件 |
| `HILOGF` | 致命级日志 | 致命条件 |

### 域

| 常量 | 值 |
|---|---|
| `DHDP` / `0xD004400` | DeviceProfile HiLog 域 |

### 常用日志模式

```cpp
HILOGI("DeviceProfileManager Init start");
HILOGE("failed to get kvStore, error: %{public}d", status);
HILOGW("profile not found, deviceId: %{public}s", deviceId.c_str());
```

### 约束条件

| 约束项 | 详情 |
|---|---|
| 安全性 | 日志中不得包含个人隐私数据（按 PR 检查清单要求："禁止在日志中出现 PII"）。数据转储使用 `AnnoymizeDump()`。 |
| 格式 | 对字符串参数使用 `%{public}s` 以避免在发布版本中隐私屏蔽。 |

---

## 13. cJSON / nlohmann::json

**模块：** cJSON（C 库）、nlohmann::json（C++ 库）
**GN 依赖：** `cJSON:cjson`、`json`（third_party）

### 调用的 cJSON API

| API | 用途 |
|---|---|
| `cJSON_Parse` | 将 JSON 字符串解析为树 |
| `cJSON_Print` | 将树序列化为字符串 |
| `cJSON_PrintUnformatted` | 无空格序列化 |
| `cJSON_Delete` | 释放解析后的树 |
| `cJSON_GetObjectItem` | 访问对象字段 |
| `cJSON_GetObjectItemCaseSensitive` | 区分大小写的字段访问 |
| `cJSON_CreateObject` | 创建空 JSON 对象 |
| `cJSON_AddStringToObject` | 向对象添加字符串字段 |
| `cJSON_AddNumberToObject` | 向对象添加数字字段 |
| `cJSON_CreateArray` | 创建空 JSON 数组 |
| `cJSON_AddItemToArray` | 向数组添加项 |
| `cJSON_IsString` | 类型检查 |
| `cJSON_IsNumber` | 类型检查 |
| `cJSON_IsTrue` / `cJSON_IsFalse` | 布尔值检查 |

### nlohmann::json 使用方式

```cpp
// 通过 nlohmann::json::parse() 和 .dump() 进行画像序列化
nlohmann::json jsonObj = nlohmann::json::parse(jsonStr);
std::string value = jsonObj["field"];
std::string output = jsonObj.dump();
```

### 约束条件

| 约束项 | 详情 |
|---|---|
| 内存 | 每个 cJSON 树都必须调用 cJSON_Delete。PR 检查清单明确要求进行 cJSON 清理。 |
| 线程安全 | 两个库对独立的 JSON 树是线程安全的。 |

### 错误处理

- `cJSON_Parse` 返回 NULL：JSON 无效；记录日志并返回 DP_INVALID_PARAMETER。
- `cJSON_GetObjectItem` 返回 NULL：字段缺失；按字段默认值处理。

---

## 14. Config Policy

**模块：** ConfigPolicy
**GN 依赖：** `config_policy:configpolicy_util`

### 调用的 API

| API | 签名 | 用途 |
|---|---|---|
| `GetCfgFiles` | `int32_t GetCfgFiles(const char* pathSuffix, std::vector<std::string>& filePaths)` | 查找配置文件路径 |

### 使用方式

```cpp
// PermissionManager::Init()
std::vector<std::string> filePaths;
GetCfgFiles("deviceprofile/permission.json", filePaths);
// filePaths 包含所有配置层级中 permission.json 的路径
LoadPermissionCfg(filePaths[0]);  // 加载第一个匹配的文件
```

### 约束条件

| 约束项 | 详情 |
|---|---|
| 搜索顺序 | 依次搜索系统配置、厂商配置、产品配置等。按优先级排序返回所有匹配结果。 |
| 文件存在性 | 如果未找到文件，向量为空。DP 回退到默认（空权限映射表）。 |

### 错误处理

- 未找到配置文件：`permissionMap_` 保持为空；所有权限检查失败（API 调用被拒）。记录错误。

---

## 15. DataShare

**模块：** `OHOS::DataShare`
**GN 依赖：** `data_share:datashare_consumer`

### 调用的 API

| API | 签名 | 用途 |
|---|---|---|
| `DataShareHelper::Creator` | `static std::shared_ptr<DataShareHelper> Creator(const std::string& uri, const DataShareHelperOptions& options)` | 创建 DataShare 访问辅助器 |
| `DataShareHelper::Query` | `std::shared_ptr<DataShareResultSet> Query(Uri& uri, std::vector<std::string>& columns, DataSharePredicates& predicates)` | 查询设置数据 |
| `DataShareHelper::Insert` | `int Insert(Uri& uri, DataShareValuesBucket& values)` | 插入设置条目 |
| `DataShareHelper::Update` | `int Update(Uri& uri, DataShareValuesBucket& values, DataSharePredicates& predicates)` | 更新设置条目 |

### 使用方式

`SettingsDataManager` 使用 DataShare 读写系统设置（例如设备画像开关状态）。通过指向 Settings 数据提供者的 DataShare URI 进行访问。

### 约束条件

| 约束项 | 详情 |
|---|---|
| 特性标志 | 由 `device_info_manager_supported_switch` 特性标志控制。 |
| URI 格式 | Settings URI 遵循 OpenHarmony DataShare 约定。 |
| 线程安全 | DataShare 辅助器必须在单个线程中使用。 |

### 错误处理

- `Creator` 失败（null 辅助器）：设置访问不可用；开关使用默认值。
- Query 返回 null：视为空结果集。

---

## 总结：初始化顺序约束

以下外部模块必须按此顺序就绪，DP 才能正确启动：

```
1. SAMGR（本地）           -- 始终可用
2. IPC（本地）             -- 始终可用
3. HiLog（本地）           -- 始终可用
4. Config Policy           -- 文件系统必须已挂载
5. OS Account SA（1000）   -- 多用户初始化所需
6. SoftBus SA（4002）      -- 本地设备身份标识所需
7. KV Store SA（3340）     -- 画像存储所需
8. DeviceManager SA（3202） -- 设备状态回调所需
9. CommonEvent SA          -- 账户事件订阅所需
10. Memory Manager SA（3201） -- 内存协调所需
```

DP 在 `PostInit()` 中通过 `SystemAbilityStatusChangeListener` 等待所有依赖 SA（4002、3340、3202、1000、3201）上线后，才完成初始化。

---

## 参见

- `bundle.json` -- 组件依赖声明
- `services/core/BUILD.gn` -- 编译期 external_deps
- `docs/05-interfaces/01-external-api.md` -- DP 自身的公开 API 参考
- `docs/05-interfaces/02-internal-api.md` -- 内部管理器契约
