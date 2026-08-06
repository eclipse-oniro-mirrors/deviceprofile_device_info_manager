# 同步与订阅通知知识

> 本文只记录 DP 的跨设备同步（OH KV 同步 / 非 OH DP Sync Adapter / E2E 同步）、订阅与变更通知链、回调 proxy/stub 机制。
> 服务分层与 SA 生命周期见 `service-architecture.md`；画像数据结构与存储后端见 `profile-data-and-storage.md`；信任与访问控制见 `trust-acl-access-control.md`。
> 同步与订阅的**严格时序**见 `../01-workflows.md` 第 6-8 节。

## 1. 同步路径总览

| 路径 | 触发 | 对端 | 机制 | 关键类 |
|------|------|------|------|--------|
| OH KV 同步 | `SyncDeviceProfile` API | OH 设备 | `KVAdapter::Sync(devices, mode)` 内置分布式复制 | `DeviceProfileManager`、`KvSyncCompletedListener` |
| 非 OH Adapter 同步 | `SyncDeviceProfile` API | 非 OH 设备 | `dlopen("libdeviceprofileadapter.z.so")` + `IDPSyncAdapter` 插件 | `DeviceProfileManager::SyncWithNotOHBasedDevice` |
| E2E 自动同步 | 设备上线（`DMAdapter::OnDeviceOnline`） | OH 设备 | `deviceProfileStore_->Sync({networkId}, PUSH_PULL)` | `DeviceProfileManager::E2ESyncDynamicProfile` |
| 静态同步 | `SyncStaticProfile` API | — | `StaticProfileManager` | `StaticProfileManager` |

`IDPSyncAdapter` 接口定义于 `common/include/interfaces/i_dp_sync_adapter.h`。加载失败返回 `DP_LOAD_SYNC_ADAPTER_FAILED`(98566248)。

## 2. SyncDeviceProfile 阶段表

> 严格时序与违反后果见 `../01-workflows.md` 第 6 节。

| 阶段 | 操作 | 代码锚点 | 源码路径 |
|------|------|----------|----------|
| 入口 | `SyncDeviceProfile(syncOptions, callback)` (Svc) | `:831` | `.../distributed_device_profile_service_new.cpp` |
| 同步权限 | `PermissionManager::CheckCallerSyncPermission()`（需 `SYNC_PROFILE_DP`） | 同上 | 同上 |
| 路由 | `DeviceProfileManager::SyncDeviceProfile` | `:489` | `device_profile_manager.cpp` |
| 分组在线设备 | `ProfileCache::FilterAndGroupOnlineDevices(..., ohBased, notOHBased)` | 同上 | 同上 |
| OH：注册监听 | `ProfileCache::AddSyncListener(callerDescriptor, syncCompletedCallback)` | 同上 | 同上 |
| OH：KV 同步 | `KVAdapter::Sync(ohBasedDevices, syncMode)` | `:517` | 同上 |
| OH：完成回调 | `KvSyncCompletedListener::SyncCompleted` → `NotifySyncCompleted` | `:63`/`:94` | `.../listener/kv_sync_completed_listener.cpp` |
| OH：分发+清理 | `GetSyncListeners` → `OnSyncCompleted` → `RemoveSyncListeners` | 同上 | 同上 |
| 非 OH：加载适配器 | `SyncWithNotOHBasedDevice` → `LoadDpSyncAdapter` | `:603`/`:534` | `device_profile_manager.cpp` |
| 非 OH：dlopen | `dlopen("libdeviceprofileadapter.z.so")` → `CreateDPSyncAdapterObject` → `Initialize()` | `:534` | 同上 |
| 非 OH：逐设备同步 | `IDPSyncAdapter::SyncProfile(peerUdid, peerNetId, callback, isP2p)` | 同上 | 同上 |
| 非 OH：失败回调 | `SyncWithNotOHBasedDeviceFailed` → `OnSyncCompleted` | `:625` | 同上 |
| 非 OH：卸载 | `UnloadDpSyncAdapter` | `:582` | 同上 |

## 3. 设备上线 E2E 同步阶段表

> 严格时序见 `../01-workflows.md` 第 7 节。E2E **始终用 `PUSH_PULL`**。

| 阶段 | 操作 | 代码锚点 | 源码路径 |
|------|------|----------|----------|
| 上线回调 | `DeviceProfileManager::OnDeviceOnline(trustedDeviceInfo)` | `:758` | `device_profile_manager.cpp` |
| 数据修复 | `FixDataOnDeviceOnline(deviceInfo)` | `:769` | 同上 |
| 修本地 | `FixLocalData` | `:950` | 同上 |
| 修非 OH 远程 | `FixRemoteDataWhenPeerIsNonOH` | `:980` | 同上 |
| 修 OH 远程 | `FixRemoteDataWhenPeerIsOHBase` | `:1016` | 同上 |
| 通知非 OH | `NotifyNotOHBaseOnline` | `:873` | 同上 |
| E2E 判定 | `IsDeviceE2ESync` | `:1203` | 同上 |
| 动态 E2E | `E2ESyncDynamicProfile` → `deviceProfileStore_->Sync({networkId}, PUSH_PULL)` | `:916` | 同上 |
| 静态 E2E | `StaticProfileManager::E2ESyncStaticProfile` | 同上 | 同上 |
| 差异修复 | `FixDiffProfiles` | `:1037` | 同上 |

## 4. 订阅与变更通知链

| 容量/约束 | 值 | 锚点 |
|-----------|----|------|
| 订阅最大数 | `MAX_LISTENER_SIZE = 100` | `subscribe_profile_manager.cpp` |
| 初始化回调最大数 | `MAX_CALLBACK_LEN = 1000` | `distributed_device_profile_service_new.cpp` |
| 单订阅最大变更类型 | `MAX_SUBSCRIBE_CHANGE_SIZE = 6` | `dp_subscribe_info.h` |
| 订阅去重键 | `(saId, subscribeKey)`（`SubscribeCompare`/`SubscribeHash`） | 同上 |
| 超限返回 | 订阅超 `MAX_LISTENER_SIZE` → `DP_EXCEED_MAX_SIZE_FAIL`；回调超 `MAX_CALLBACK_LEN` → `DP_INVALID_PARAM` | 同上 |

数据变更驱动通知链（KV 变更 → 分发）：

| 步骤 | 操作 | 代码锚点 | 源码路径 |
|------|------|----------|----------|
| KV 变更 | `KvDataChangeListener::OnChange` | — | `.../listener/kv_data_change_listener.cpp` |
| 分类 | `HandleAddChange`/`HandleUpdateChange`/`HandleDeleteChange` | 同上 | 同上 |
| 去重+OH 后缀清理 | `FilterEntries(records, entries, isDelete)` | 同上 | 同上 |
| 解析类型 | `GetProfileType(dbKey)` | 同上 | 同上 |
| 复合码+雷达 | `NotifyProfileChange`：`code = profileType * changeType` → `DpRadarHelper::ReportNotifyProfileChange(code)` | — | `subscribe_profile_manager.cpp` |
| 按 code 分发 | `NotifyDeviceProfileAdd/Update/Delete` 等 | 同上 | 同上 |
| DB 键转订阅键 | `DBKeyToSubcribeKey` | 同上 | 同上 |
| 查订阅者 | `GetSubscribeInfos(subscribeKey)` | 同上 | 同上 |
| 类型过滤+IPC 回调 | `iface_cast<IProfileChangeListener>` → `OnDeviceProfileAdd` 等 | 同上 | 同上 |

> 注意：用 OH 后缀键注册的订阅者只能匹配到完全相同的 DB 键；键后缀标准化方向性不一致会导致通知漏投。

`SubscribeDeviceProfileInited`：`isInited_==true` 时立即回调 `OnDpInited()`；否则存入 `dpInitedCallbackMap_[saId]`，待 `PostInitNext` 完成后 `NotifyDeviceProfileInited()` 遍历回调。

## 5. 回调 proxy/stub 机制

| 回调接口 | Stub | Proxy | 头文件 |
|----------|------|-------|--------|
| `IProfileChangeListener` | `ProfileChangeListenerStub` | `ProfileChangeListenerProxy` | `common/include/interfaces/profile_change_listener_stub.h`/`_proxy.h` |
| `ISyncCompletedCallback` | `SyncCompletedCallbackStub` | `SyncCompletedCallbackProxy` | `common/include/interfaces/sync_completed_callback_stub.h`/`_proxy.h` |
| `IDpInitedCallback` | `DpInitedCallbackStub` | `DpInitedCallbackProxy` | 同目录 |
| `IPinCodeInvalidCallback` | `PincodeInvalidCallbackStub` | `PincodeInvalidCallbackProxy` | 同目录 |
| `IServiceInfoChangeCallback` | `ServiceInfoChangeStub` | `ServiceInfoChangeProxy` | 同目录 |
| `IBusinessCallback` | `BusinessCallbackStub` | `BusinessCallbackProxy` | 经 `common/BUILD.gn` 的 `idl_gen_interface("dp_business_callback_interfaces")` IDL 生成 |

回调方向码（`ON_*` 段：27-40,43,44,59,67,74-76,79-84）不由主 Stub `OnRemoteRequest` 派发，而由对应回调 Stub 处理。主 Stub 只派发 51 个外部 API 码（见 `service-architecture.md` 第 4 节）。

`ProfileChangeType` 枚举值映射到 IPC 通知码 28-44（值见 `profile-data-and-storage.md` 第 5 节）。

## 6. 常见误用

| 误用 | 后果 | 修正 |
|------|------|------|
| E2E 同步用非 `PUSH_PULL` 模式 | 双端数据不一致 | `E2ESyncDynamicProfile` 固定 `PUSH_PULL`，不可改 |
| 两组设备都为空（全离线）同步 | 返回 `DP_INVALID_PARAMS`(98566144) | 同步前确认目标在线 |
| 非 OH 适配器 `.so` 缺失或 `dlopen` 失败 | 返回 `DP_LOAD_SYNC_ADAPTER_FAILED`(98566248) | 确认 `libdeviceprofileadapter.z.so` 在 `LIB_LOAD_PATH`（如 `/system/lib64/`） |
| 订阅数超 100 | 返回 `DP_EXCEED_MAX_SIZE_FAIL` | 控制订阅数量，及时 `UnSubscribe` |
| 用 OH 后缀键注册但 DB 键后缀不一致 | 通知漏投 | 订阅键与 DB 键后缀标准化方向须一致 |
| `businessEventCallbackMap_` 不注销 | 已失效条目残留（无死亡接收者清理） | 显式 `UnRegisterBusinessCallback` |
| 业务事件回调重复注册/超限 | 返回 `DP_INVALID_PARAM`(98566245) | 先注销再注册 |
| 期望 `OnDeviceOffline` 触发数据清理 | 残留数据保留 | 下线路径不级联清理，已断开设备数据继续保留在存储中 |

## 7. 反模式 / 修改前检查

- 新增同步路径必须同步：`FilterAndGroupOnlineDevices` 分组逻辑、`AddSyncListener`/`RemoveSyncListeners` 监听管理、`KvSyncCompletedListener::SyncCompleted` 回调分发。漏改导致同步完成回调丢失。
- 修改 E2E 同步模式必须保持 `PUSH_PULL`；改单方向会导致对端缺数据。
- 新增订阅变更类型必须同步：`ProfileChangeType` 枚举、`funcsMap_` 分发表、`DBKeyToSubcribeKey`、`Notify*` 方法、回调 stub/proxy 的 IPC 码、测试。漏改即通知不触发或路由错配。
- 新增回调接口必须经 `idl_gen_interface` 生成 stub/proxy 并注册死亡接收者（除业务事件外）；不生成则无法跨进程回调。
- 不允许在 `SyncCompleted` 回调中阻塞或重入同步；可能死锁或重入导致状态错乱。
- 修改 `IDPSyncAdapter` 接口须同步适配器插件 `.so` 的 ABI；不一致导致 `dlopen` 后调用崩溃。

## 8. 测试指引

- 同步：`kv_sync_completed_listener_test.cpp`、`sync_subscriber_death_recipient_test.cpp`、`sync_options_new_test.cpp`、`sync_completed_callback_test.cpp`。
- 订阅：`subscribe_profile_manager_test.cpp`、`subscribe_profile_manager_new_test.cpp`、`DPSubscribeInfoTest`、`ProfileChangeListenerProxyTest`。
- KV 监听/死亡：`kv_store_death_recipient_test.cpp`、`kv_data_change_listener`（经 manager 测试覆盖）。
- DM/E2E：`dm_adapter_test.cpp`（`dp_dm_adapter_test`）、`device_profile_manager_*_test.cpp`。
- 业务事件：`business_event_manager_test.cpp`、`business_event_adapter_test`、`businesseventmanager_fuzzer`。
- 完整清单与命令见 `../03-build-test.md`。
