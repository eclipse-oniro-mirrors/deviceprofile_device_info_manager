# 服务架构知识

> 本文只记录 DP 服务的分层结构、SA 6001 生命周期骨架、Manager 职责矩阵与 IPC 派发机制。
> 画像数据结构与存储后端见 `profile-data-and-storage.md`；信任与访问控制见 `trust-acl-access-control.md`；同步与订阅通知见 `sync-subscription-notification.md`。
> 上述各流程的**严格时序**（先做什么后做什么）见 `../01-workflows.md`，本文只给背景。

## 1. 模块定位

`deviceprofile_device_info_manager`（部件名 `@ohos/device_info_manager`，subsystem `deviceprofile`）是 OpenHarmony 分布式设备画像的**集中式存储与同步管理层**。它以系统服务 `SAID 6001`、进程名 `deviceprofile` 运行，对外提供设备/服务/特征画像的存取、信任关系与访问控制管理、跨设备同步、变更订阅，并以 KV / RDB / Asset 三种后端持久化。

**它是：** 一个持久化画像仓库 + 一个数据同步引擎 + 一个变更通知中心。
**它不是：** 通信传输层（委托 SoftBus 与 DeviceManager）、认证授权服务（认证由 device_auth 处理）、编排引擎（只供数据，不做编排决策）。

优先按这些目录定位问题：

| 目录 | 作用 |
|------|------|
| `services/core/` | 服务核心层：SA 生命周期（`DistributedDeviceProfileServiceNew`）、所有业务 Manager、持久化适配器、内容采集器、DFX |
| `common/` | 共享层：所有 `DpParcel` 数据结构、IPC broker/stub/proxy、常量与枚举、日志宏 |
| `interfaces/innerkits/core/` | 客户端 SDK 层：`DistributedDeviceProfileClient` 单例、`DistributedDeviceProfileProxy`、SA 装载回调 |
| `permission/permission.json` | 调用方进程 → 可调用接口 的白名单（权限模型唯一数据源） |

## 2. 四层架构

由外向内：Client SDK → IPC Transport → Service Core → Storage Backends。

| 层 | 职责 | 代表类 | 关键路径 |
|----|------|--------|---------|
| Client SDK | 外部 API 入口；提供 IPC 代理；监听 SA 生命周期；对瞬时错误自动重试 | `DistributedDeviceProfileClient`、`DistributedDeviceProfileProxy`、`DeviceProfileLoadCallback` | `interfaces/innerkits/core/include/`、`src/` |
| IPC Transport | 定义 `IDistributedDeviceProfile` 远程 broker；Stub `OnRemoteRequest` 派发；回调 proxy/stub | `IDistributedDeviceProfile`、`DistributedDeviceProfileStubNew`、各回调 Stub/Proxy | `services/core/include/distributed_device_profile_stub_new.h`、`common/include/interfaces/` |
| Service Core | 18+ Manager 业务逻辑；权限校验；持久化编排；事件通知；内容采集；多用户隔离 | `DistributedDeviceProfileServiceNew` + 各 Manager + 适配器 + 采集器 | `services/core/src/`、`services/core/include/` |
| Storage Backends | KV 分布式存储 / RDB(SQLite) / Asset 加密存储 | `KvAdapter`、`RdbAdapter`、`AssetAdapter` 及各专用适配器 | `services/core/src/persistenceadapter/`、`services/core/include/persistenceadapter/` |

## 3. SA 6001 生命周期骨架（阶段表）

> 严格调用顺序与违反后果见 `../01-workflows.md` 第 1 节。本表只列阶段与代码锚点。

| 阶段 | 操作 | 代码锚点 | 源码路径 |
|------|------|----------|----------|
| 注册 | `SystemAbility::MakeAndRegisterAbility(&GetInstance())` | `DistributedDeviceProfileServiceNew` 构造 | `services/core/src/distributed_device_profile_service_new.cpp:84` |
| 启动 | `OnStart(reason)` → `Init()` → 注册 5 依赖 SA 监听 + `Publish(this)` + 延迟卸载 | `OnStart` / `Init` | `services/core/src/distributed_device_profile_service_new.cpp:955` / `:104` |
| 依赖就绪 | `OnAddSystemAbility` 逐个 `depSaIds_.erase(saId)`，账户 SA 上线订阅账户事件，内存 SA 上线设临界 | `OnAddSystemAbility` | `services/core/src/distributed_device_profile_service_new.cpp:1014` |
| 后初始化 | 依赖全就绪 → `PostInit()` 初始化 9 个 Manager → `PostInitNext()` 初始化 3 个 Manager + 刷临时缓存 + `isInited_=true` + `NotifyDeviceProfileInited()` | `PostInit` / `PostInitNext` | `services/core/src/distributed_device_profile_service_new.cpp:139` / `:184` |
| 空闲/活跃 | 低内存事件 → `OnIdle` → `SetCritical(false)`；IPC 唤醒 → `OnActive` → `SetCritical(true)` | `OnIdle` / `OnActive` | `services/core/src/distributed_device_profile_service_new.cpp:1002` / `:995` |
| 关停 | `OnStop()` → `isStopped_=true` + `UnInit()` + `UnInitNext()`（逆序）+ `SetCritical(false)` + `DestroyUnloadHandler()` + `ClearProfileCache()` | `OnStop` / `UnInit` / `UnInitNext` | `services/core/src/distributed_device_profile_service_new.cpp:984` / `:241` / `:295` |

`depSaIds_`（5 个必须先就绪的依赖 SA）：`SOFTBUS_SERVER_SA_ID`、`DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID`、`DISTRIBUTED_HARDWARE_DEVICEMAGER_SA_ID`(4802)、`SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN`、`MEMORY_MANAGER_SA_ID`。定义于 `services/core/include/distributed_device_profile_service_new.h:169`。

## 4. IPC 派发机制（`DistributedDeviceProfileStubNew::OnRemoteRequest`）

入口网关顺序（`services/core/src/distributed_device_profile_stub_new.cpp`）：

| 顺序 | 操作 | 失败返回 |
|------|------|----------|
| 1 | `IsStopped()` 为真 | `DP_SERVICE_STOPPED`(98566331) |
| 2 | `ExitIdleState()` 失败 | `DP_SERVICE_ON_IDLE`(98566330) |
| 3 | `AddRunningIpcCount()` + `DelayUnloadTask()`（纯虚，Service 实现） | — |
| 4 | `IsInterfaceTokenValid(data)` | `DP_INTERFACE_CHECK_FAILED`(98566145) |
| 5 | 若接口码 ∈ `aclAndSubscribeFuncs_`（36 个码）→ `NotifyAclEventInner`（**绕过 IsInited 检查**） | — |
| 6 | 否则 `!IsInited()` | `DP_LOAD_SERVICE_ERR`(98566160) |
| 7 | `NotifyEventInner` 链式 fallthrough 派发到各 `*Inner` 处理函数 | 序列化失败 `DP_READ_PARCEL_FAIL`(98566236) / `DP_WRITE_PARCEL_FAIL`(98566235) |
| 末 | `SubtractRunningIpcCount()` | — |

`aclAndSubscribeFuncs_`（绕过初始化检查、可在 `PostInit` 完成前调用的 36 个接口码）：`7,8,9,10,11,12,13,66,23,24,26,14,15,16,17,41,42,45,46,47,51,48,49,50,55,56,57,58,60,61,77,52,53,54,73,78`。含义：信任/会话密钥/订阅/画像写入类接口允许在服务未完成初始化时调用（数据先落临时缓存，见 `../01-workflows.md` 第 1 节临时缓存机制）。

## 5. Manager 职责矩阵

| 类 | 职责 | 源码路径(src) | 头文件路径(include) |
|----|------|----------------|---------------------|
| `DistributedDeviceProfileServiceNew` | SA 生命周期；Manager 初始化/销毁编排；`depSaIds_` 跟踪；临时缓存刷新；按需启停与延迟卸载 | `services/core/src/distributed_device_profile_service_new.cpp` | `services/core/include/distributed_device_profile_service_new.h` |
| `DistributedDeviceProfileStubNew` | IPC Stub `OnRemoteRequest` 派发；接口码路由 | `services/core/src/distributed_device_profile_stub_new.cpp` | `services/core/include/distributed_device_profile_stub_new.h` |
| `PermissionManager` | 调用方身份校验；按 `permission.json` 比对 caller 进程名 | `services/core/src/permissionmanager/permission_manager.cpp` | `services/core/include/permissionmanager/permission_manager.h` |
| `TrustProfileManager` | `TrustDeviceProfile`/`AccessControlProfile` CRUD；4 表 RDB；级联删除；LNN 过滤 | `services/core/src/trustprofilemanager/trust_profile_manager.cpp` | `services/core/include/trustprofilemanager/trust_profile_manager.h` |
| `DeviceProfileManager` | 动态 `DeviceProfile`/`ServiceProfile`/`CharacteristicProfile` CRUD；KV 监听器；同步编排；临时缓存 | `services/core/src/deviceprofilemanager/device_profile_manager.cpp` | `services/core/include/deviceprofilemanager/device_profile_manager.h` |
| `StaticProfileManager` | 静态能力画像（JSON 加载的不可变能力）；受 `DEVICE_PROFILE_STATIC_DISABLE` 控制 | `services/core/src/deviceprofilemanager/static_profile_manager.cpp` | `services/core/include/deviceprofilemanager/static_profile_manager.h` |
| `SwitchProfileManager` | 分布式开关状态；KV 同步；受 `DEVICE_PROFILE_SWITCH_DISABLE` 控制 | `services/core/src/deviceprofilemanager/switch_profile_manager.cpp` | `services/core/include/deviceprofilemanager/switch_profile_manager.h` |
| `SubscribeProfileManager` | 画像变更订阅分发；`funcsMap_` 按类型派发；`(saId,subscribeKey)` 去重 | `services/core/src/subscribeprofilemanager/subscribe_profile_manager.cpp` | `services/core/include/subscribeprofilemanager/subscribe_profile_manager.h` |
| `SubscribeServiceInfoManager` | ServiceInfo 变更通知分发（insert/update/delete） | `services/core/src/subscribeserviceinfomanager/subscribe_service_info_manager.cpp` | `services/core/include/subscribeserviceinfomanager/subscribe_service_info_manager.h` |
| `ContentSensorManager` | 编排 6 个采集器；写入 KV 与 RDB | `services/core/src/contentsensormanager/content_sensor_manager.cpp` | `services/core/include/contentsensormanager/content_sensor_manager.h` |
| `ServiceInfoManager` | `ServiceInfo` CRUD；双层 KV（本地+同步） | `services/core/src/serviceinfo_manager/service_info_manager.cpp` | `services/core/include/serviceinfo_manager/service_info_manager.h` |
| `LocalServiceInfoManager` | `LocalServiceInfo` CRUD（RDB）；PIN 管理；触发 `NotifyPinCodeInvalid` | `services/core/src/localserviceinfomanager/local_service_info_manager.cpp` | `services/core/include/localserviceinfomanager/local_service_info_manager.h` |
| `SessionKeyManager` | 会话密钥 CRUD（Asset 加密存储） | `services/core/src/sessionkeymanager/session_key_manager.cpp` | `services/core/include/sessionkeymanager/session_key_manager.h` |
| `BusinessEventManager` | 业务事件注册/存储/回调通知 | `services/core/src/businesseventmanager/business_event_manager.cpp` | `services/core/include/businesseventmanager/business_event_manager.h` |
| `ProfileDataManager` | 结构化画像 RDB 批量管理（设备/产品/图标，经 DAO） | `services/core/src/profiledatamanager/profile_data_manager.cpp` | `services/core/include/profiledatamanager/profile_data_manager.h` |
| `MultiUserManager` | 多用户隔离；前台用户 ID；用户切换/删除公共事件 | `services/core/src/multiusermanager/multi_user_manager.cpp` | `services/core/include/multiusermanager/multi_user_manager.h` |
| `DMAdapter` | DeviceManager 集成；上线/下线事件消费；E2E 同步触发；离线清理 | `services/core/src/dm_adapter/dm_adapter.cpp` | `services/core/include/dm_adapter/dm_adapter.h` |
| `StaticCapabilityCollector` | 启动采集静态能力；动态 `.so` 插件加载 | `services/core/src/staticcapabilitycollector/static_capability_collector.cpp` | `services/core/include/staticcapabilitycollector/static_capability_collector.h` |
| `StaticCapabilityLoader` | 从 `LIB_LOAD_PATH` 加载静态能力/信息 JSON 与插件 | `services/core/src/staticcapabilityloader/static_capability_loader.cpp` | `services/core/include/staticcapabilityloader/static_capability_loader.h` |
| `SettingsDataManager` | DataShare 设置数据（设备名）读写 | `services/core/src/datashare/settings_data_manager.cpp` | `services/core/include/data_share/settings_data_manager.h` |
| `ProfileCache` | 内存热路径缓存；在线设备映射；空闲判定 | `services/core/src/utils/profile_cache.cpp` | `services/core/include/utils/profile_cache.h` |
| `ProfileControlUtils` | 画像控制流工具（静态） | `services/core/src/utils/profile_control_utils.cpp` | `services/core/include/utils/profile_control_utils.h` |
| `EventHandlerFactory` | 命名事件处理器（FFRT）管理 | `services/core/src/utils/event_handler_factory.cpp` | `services/core/include/utils/event_handler_factory.h` |
| `DeviceProfileDumper` | `hidumper -s 6001` 诊断输出 | `services/core/src/dfx/device_profile_dumper.cpp` | `services/core/include/dfx/device_profile_dumper.h` |

持久化适配器子层：

| 类 | 后端 | 路径(src) |
|----|------|-----------|
| `KvAdapter`/`IKvAdapter` | KV | `services/core/src/persistenceadapter/kvadapter/kv_adapter.cpp` |
| `ServiceInfoKvAdapter` | KV（本地权威） | `.../kvadapter/service_info_kv_adapter.cpp` |
| `BusinessEventAdapter` | KV（本地） | `.../kvadapter/business_event_adapter.cpp` |
| `SwitchAdapter` | KV（开关） | `.../kvadapter/switch_adapter.cpp` |
| `RdbAdapter`/`IRdbAdapter` | RDB | `services/core/src/persistenceadapter/rdbadapter/rdb_adapter.cpp` |
| `ProfileDataRdbAdapter` | RDB（结构化画像） | `.../rdbadapter/profile_data_rdb_adapter.cpp` |
| `ServiceInfoRdbAdapter` | RDB（service_info_profile） | `.../rdbadapter/service_info_rdb_adapter.cpp` |
| `LocalServiceInfoRdbAdapter` | RDB（local_service_info） | `.../rdbadapter/local_service_info_rdb_adapter.cpp` |
| `AssetAdapter` | Asset（会话密钥） | `services/core/src/persistenceadapter/assetadapter/asset_adapter.cpp` |

KV 监听器（`services/core/src/deviceprofilemanager/listener/`）：`KvDataChangeListener`（数据变更）、`KvSyncCompletedListener`（同步完成）、`KvStoreDeathRecipient`（KV 死亡恢复 4 个 store）、`SyncSubscriberDeathRecipient`（订阅者死亡）。

## 6. 单例与卸载机制

| 机制 | 说明 | 锚点 |
|------|------|------|
| 单例 | `IMPLEMENT_SINGLE_INSTANCE` + `DECLARE_SINGLE_INSTANCE`；**未使用** `DelayedSpSingleton` | `service_new.cpp:84-86`、`service_new.h:42-43` |
| 注册 | `SystemAbility::MakeAndRegisterAbility(&GetInstance())` 于构造期 | `service_new.cpp:84` |
| 启动看门狗 | `XCollie::SetTimer(DP_ONSTART_TIMER, ONSTART_TIMEOUT_TIME=12, ...)`；成功后 `CancelTimer` | `service_new.cpp:958`、`:973` |
| IPC 线程数 | `IPCSkeleton::SetMaxWorkThreadNum(DP_IPC_THREAD_NUM=32)` | `service_new.cpp:972` |
| 延迟卸载 | `CreateUnloadHandler()` + `DelayUnloadTask()`，`DELAY_TIME=180000`(180s) | `service_new.cpp:978-981` |
| 卸载守卫 | `OnIdle` 低内存时返回 `SA_READY_INTO_IDLE` 并 `SetCritical(false)`；`OnActive` 唤醒并 `SetCritical(true)` | `service_new.cpp:1002`、`:995` |

## 7. SA Profile 与进程配置

`sa_profile/6001.json`（注意：仓库内为 `.json`，无 `.xml`）：

| 字段 | 值 |
|------|----|
| process | `deviceprofile` |
| name (SAID) | `6001` |
| libpath | `libdistributed_device_profile_svr.z.so` |
| run-on-create | `false` |
| distributed | `false` |
| dump-level | `1` |
| recycle-strategy | `low-memory` |
| start-on-demand | deviceonline `on`；commonevent `usual.event.BOOT_COMPLETED` |
| stop-on-demand | deviceonline `off`；param `resourceschedule.memmgr.low.memory.prepare`=`true` |

进程配置 `etc/init/deviceprofile.cfg`（手表形态见 `etc/init/watch/deviceprofile.cfg`，额外 `importance:-20`）：

| 项 | 值 |
|----|----|
| path | `["/system/bin/sa_main","/system/profile/deviceprofile.json"]` |
| uid / gid | `dms` / `["dms","shell"]` |
| ondemand | `true` |
| secon | `u:r:distributedsche:s0` |
| on-start job | `service:deviceprofile`（mkdir 4 个数据库目录） |
| 权限 | `DISTRIBUTED_DATASYNC`、`ACCESS_SERVICE_DM`、`MANAGE_LOCAL_ACCOUNTS`、`MANAGE_SECURE_SETTINGS`、`MONITOR_DEVICE_NETWORK_STATE`、`INTERACT_ACROSS_LOCAL_ACCOUNTS`、`GET_DOMAIN_ACCOUNTS` |
| permission_acls | `ohos.permission.MONITOR_DEVICE_NETWORK_STATE` |

mkdir 目录：`/data/service/el1/public/database`、`.../distributed_device_profile_service`、`.../acl_db`、`.../ddps_adapter`（见 `deviceprofile.cfg:2-10`）。

## 8. 常见误用

| 误用 | 后果 | 修正 |
|------|------|------|
| 在 `PostInit` 完成前（`isInited_!=true`）调用非 `aclAndSubscribeFuncs_` 的接口 | Stub 返回 `DP_LOAD_SERVICE_ERR`(98566160)，客户端触发重试 | 仅信任/会话密钥/订阅/画像写入接口可在未完成初始化时调用（数据落临时缓存）；读取类接口须等服务就绪 |
| 直接 `new` Manager 而非走 `GetInstance()` 单例 | 多实例导致状态不一致、锁失效 | 一律使用 `XxxManager::GetInstance()` |
| 在 `OnStop` 后仍持有 Manager 引用调用其方法 | 行为未定义，`isStopped_=true` 后 IPC 返回 `DP_SERVICE_STOPPED`(98566331) | 依赖 SA 生命周期，不要跨停服调用 |
| 修改接口码但未同步 Stub 派发表与 Proxy `SEND_REQUEST` 码 | IPC 路由错配，调用落到 default 分支返回失败 | 见 `AGENTS.md` 接口码约束，四端同步修改 |
| 误用 `DelayedSpSingleton` 推测单例行为 | 代码未使用该模式，推测会误导调试 | 单例为 `IMPLEMENT_SINGLE_INSTANCE`，按实际代码理解 |

## 9. 反模式 / 修改前检查

- 新增 Manager 必须在 `Init()`/`PostInit()`/`PostInitNext()` 之一注册并在 `UnInit()`/`UnInitNext()` 逆序反初始化；未注册则不会被初始化。
- 新增 IPC 接口码必须同步：`dp_ipc_interface_code.h` 枚举、`DistributedDeviceProfileStubNew` 派发表、`DistributedDeviceProfileProxy` 的 `SEND_REQUEST`、`permission.json`（若需鉴权）、回调 stub/proxy（若是回调方向）、测试与 mock。任一缺失即路由或鉴权失败。
- 不允许绕过 `PermissionManager::IsCallerTrust`/`CheckCallerPermission` 直接实现外部可达接口；受保护接口无白名单条目时全部被拒。
- 不允许在 Manager 析构后访问其单例；`UnInit` 顺序必须与 `Init` 相反，避免悬空。
- 修改 `depSaIds_` 集合须同步 `OnAddSystemAbility` 的处理分支，否则依赖 SA 上线无法触发 `PostInit`。

## 10. 测试指引

- SA 生命周期与 Stub 派发：`services/core/test/unittest/dp_profile_service_test.cpp`、`distributed_device_profile_stub_new_test.cpp`（目标 `dp_profile_service_new_test`、`distributed_device_profile_stub_new_test`）。
- 各 Manager：`trust_profile_manager_test.cpp`、`device_profile_manager_*_test.cpp`、`subscribe_profile_manager_test.cpp`、`session_key_manager_test.cpp`、`business_event_manager_test.cpp`、`permission_manager_test.cpp`、`multi_user_manager_test.cpp`、`static_capability_collector_test.cpp`/`static_capability_loader_test.cpp`。
- DM 适配：`dm_adapter_test.cpp`（目标 `dp_dm_adapter_test`）。
- Dumper：`dp_dumper_new_test.cpp`（目标 `dp_dumper_new_test`）。
- 完整测试目标清单与构建命令见 `../03-build-test.md`。
