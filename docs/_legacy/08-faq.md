# 08 - 常见问题 (FAQ)

> DeviceProfile 模块常见问题 | 最后更新: 2025-05-21

---

## 概述

### Q: DP 模块和 DM 模块有什么区别？

**A:** DeviceProfile (DP, SAID 6001) 是**数据管理层**，负责设备画像的持久化存储、查询、跨设备同步和变更通知。DeviceManager (DM, SAID 4802) 是**设备连接层**，负责设备发现、认证、连接管理和在线/离线状态跟踪。

DP 是 DM 的下游消费者：DM 通知 DP 设备上线/下线，DP 据此触发数据同步和缓存更新。DP 的数据权威来源是自身存储，DM 告知 DP"有设备上线了"但 DP 自己管理画像数据。

### Q: 为什么有些 API 对所有进程开放，有些只对 device_manager 开放？

**A:** 这是由 `permission/permission.json` 控制的安全策略。分为两级：

- **`"all"` 级别**（所有进程可调用）：`PutServiceProfile`、`GetDeviceProfile`、`SubscribeDeviceProfile` 等 Profile CRUD 和订阅操作。这些是通用数据读/写接口，任何系统服务都有权使用。
- **白名单级别**（仅特定进程）：`PutAccessControlProfile`、`PutSessionKey` 等信任关系和安全敏感操作。这些仅开放给 `device_manager`、`softbus_server`、`iShare` 等可信系统服务。

设计原则：Profile 数据读写是基础能力开放给所有系统服务；信任关系管理需要统一入口防止 ACL 数据被非授权修改，因此只对特定服务开放。

### Q: DeviceProfile 的数据存储在哪里？如何查看？

**A:** 数据分散在三种存储后端：

| 存储 | 路径/方式 | 查看方法 |
|------|---------|---------|
| **KV Store** | `/data/service/el1/public/database/distributed_device_profile_service/` | 通过 distributeddata 工具查询，或通过 `hdc shell` 检查 KV 目录 |
| **RDB (SQLite)** | RDB 管理的数据库文件（由 `native_rdb` 框架定位） | 使用 rdb 调试工具或 SQLite CLI 查询表结构 |
| **Asset** | Asset SDK 加密存储（硬件级加密） | 只能通过 Asset SDK API 读取，无法直接查看原始文件 |

运行时排查建议使用 hidumper 或日志查看数据序列化内容：
```bash
hdc shell hidumper -s 6001  # SA Dump
hdc shell hilog -T DHDP -e "dump\|entries\|profile"  # 日志中的数据 dump
```

---

## Profile 管理

### Q: PutDeviceProfile 和 PutServiceProfile 的区别？

**A:** 

- **PutDeviceProfile:** 写入设备级别的 Profile（如设备类型、OS 版本、制造商），粒度是「某台设备是什么样的」。
- **PutServiceProfile:** 写入服务级别的 Profile（如某设备上运行的某服务的名称和版本），粒度是「某设备上的某个服务具备什么特征」。
- **PutCharacteristicProfile:** 写入特征级别的 Profile（如某设备上某服务的某个具体特征值，如蓝牙 MAC 地址），是最细粒度的数据。

三者形成 **Device > Service > Characteristic** 的三级模型，层级越低越具体。

### Q: ServiceProfile 和 ServiceInfo 应该用哪个？

**A:** 

| 维度 | ServiceProfile | ServiceInfo |
|------|---------------|-------------|
| **用途** | 描述设备上某服务的通用能力画像（serviceName, serviceType） | 描述 DM 管理的服务交互信息（deviceId, bundleName, tokenId, authBoxType 等） |
| **存储** | RDB (ServiceProfile 表) + KV store | 双 KV store（本地 + 同步） |
| **调用者** | 任意系统服务（`"all"` 级别） | 仅 device_manager |
| **同步** | 随 Profile 同步 | 有独立的 ServiceInfo 同步机制 |
| **典型用法** | "这台手机的蓝牙服务版本是 5.0" | "设备 A 的这些服务可以通过 DM 交互" |

若描述设备上服务的**能力属性**用 ServiceProfile；若描述 DM 层面的**服务交互信息**用 ServiceInfo。

### Q: 为什么 DeleteServiceProfile 只允许删除本地设备的 Profile？

**A:** `DeleteServiceProfile` 接受 deviceId 参数，但业务逻辑上只应删除**本地设备**上发布的 ServiceProfile。原因：

1. **数据所有权:** 每个设备是其自身 ServiceProfile 的权威来源。远程设备的 ServiceProfile 应通过同步获取而不应被本地删除。
2. **同步一致性:** 如果允许删除远程设备的 ServiceProfile，本地删除操作不会自动同步到远程设备，导致数据不一致。
3. **安全边界:** 防止恶意或错误代码破坏其他设备的画像数据。

---

## 同步

### Q: DP 的跨设备同步是如何触发的？

**A:** 同步触发路径有多种：

| 触发方式 | 场景 | 同步模式 |
|---------|------|---------|
| **设备上线自动同步** | DMAdapter 检测到设备上线 -> 触发 E2E PUSH_PULL sync | PUSH_PULL (双向) |
| **手动调用 SyncDeviceProfile** | 应用/服务通过 SDK 调用 `SyncDeviceProfile(syncOptions, callback)` | 取决于 syncMode 参数 (PULL/PUSH/PUSH_PULL) |
| **KV 自动同步** | DistributedKv 框架的自动增量同步（OH 设备之间） | 增量 sync |
| **静态能力同步** | `SyncStaticProfile` 用于同步设备的静态能力信息 | PUSH_PULL |

OH 设备之间使用 DistributedKv 内置同步；非 OH 设备通过 `dp_sync_adapter` 插件同步。

### Q: 为什么同步失败？（排查检查点列表）

**A:** 按以下检查点逐项排查：

1. **设备在线状态:** 目标设备是否在线？检查 `ProfileCache::IsDeviceOnline()`
2. **SyncMode 正确性:** PUSH_PULL (2) 是完整双向同步，PUSH (1) 只推不拉
3. **KV 存储健康:** KV death 是否触发过？检查 `DP_SYNC_FAILED` 雷达事件
4. **权限校验:** 是否有 `CheckCallerSyncPermission` 返回 `DP_PERMISSION_DENIED`？
5. **网络状态:** SoftBus 是否正常？检查分布式网络连接
6. **错误码:** 对应分析 `DP_SYNC_DEVICE_FAIL`、`DP_KV_SYNC_FAIL`、`DP_SYNC_PROFILE_FAILED` 的具体触发点
7. **Sync adapter:** 非 OH 设备同步需确认 `dp_sync_adapter.so` 可动态加载

查询同步日志:
```bash
hdc shell hilog -T DHDP -e "SyncDeviceProfile\|DP_SYNC\|SyncCompleted\|E2E"
```

### Q: OH 设备和非 OH 设备同步有什么区别？

**A:** 

| 维度 | OH 设备 | 非 OH 设备 |
|------|--------|-----------|
| **同步机制** | DistributedKv 内置同步 | dp_sync_adapter 动态库（dlopen 加载） |
| **协议** | KV store 的 PUSH/PULL/PUSH_PULL | 适配器定义的私有协议 |
| **依赖** | 无额外依赖（KV 框架自带） | 需要 `dp_sync_adapter.so` 存在 |
| **错误码** | `DP_KV_SYNC_FAIL` | `DP_LOAD_SYNC_ADAPTER_FAILED` / `DP_RUN_LOADED_FUNCTION_FAILED` |
| **触发方式** | `SyncDeviceProfile` / 自动 E2E | 同左，但底层走适配器 |
| **局限性** | 只能同步到分布式 KV 网络内的设备 | 适配器可用性决定能否同步 |

---

## 订阅

### Q: 如何订阅某个设备 Profile 的变更？

**A:** 通过 `SubscribeDeviceProfile` API，传入 `SubscribeInfo` 指定订阅范围：

```cpp
SubscribeInfo subscriberInfo;
subscriberInfo.SetSaId(saId);                    // 订阅者 SAID
subscriberInfo.SetDeviceId(deviceId);            // 要监听的设备（可选，空字符串 = 所有设备）
subscriberInfo.SetServiceName(serviceName);      // 要监听的服务（可选）
subscriberInfo.SetCharacteristicKey(charKey);    // 要监听的特征键（可选）

DistributedDeviceProfileClient::GetInstance().SubscribeDeviceProfile(subscriberInfo);
```

订阅成功后，当匹配的 Profile 发生增/删/改时，订阅者会通过 `ProfileChangeListener` 回调收到通知。

回调实现：
```cpp
class MyProfileListener : public ProfileChangeListenerStub {
    void OnProfileChange(const ProfileChangeNotification& notification) override {
        // 处理变更通知
    }
};
```

### Q: 订阅后收不到通知怎么办？

**A:** 按以下步骤排查：

1. **确认订阅成功:** `SubscribeDeviceProfile` 是否返回 `DP_SUCCESS` (0)？检查 `DP_SUBSCRIBE_FAILED` (98566151) 错误
2. **检查订阅上限:** 全局回调数是否超过 1000？错误码 `DP_SUBSCRIBE_LIMIT_EXCEEDED` (98566152)
3. **确认 SubscribeInfo 匹配:** 订阅时指定的 deviceId/serviceName/characteristicKey 是否覆盖了实际变更的 Profile？空的 deviceId 才匹配所有设备
4. **验证回调存活:** 回调 Proxy 是否因订阅者 SA 死亡而失效？检查 `SyncSubscriberDeathRecipient`
5. **确认变更已发生:** 对应的 Put/Update/Delete 操作是否真的执行成功？
6. **检查 Profile 类型计算:** 通知分发使用 `ProfileType * ChangeType` 编码，确认编码匹配

### Q: 为什么有 1000 个订阅上限？

**A:** `MAX_CALLBACK_LEN = 1000` 是全局回调数量上限，同时在多处使用：

- `dpInitedCallbackMap_`（初始化完成通知）
- `pinCodeCallbackMap_`（PinCode 失效通知）
- `businessCallbackMap_`（业务事件通知）
- SubscribeProfileManager 内部订阅列表

设置上限的原因：
1. **IPC 内存保护:** 每个回调持有一个 `sptr<IRemoteObject>`，1000 个回调意味着最多 1000 个 IPC 代理对象，防止内存过度占用
2. **通知分发性能:** 每次 Profile 变更需要遍历所有匹配的回调，上限防止遍历开销过大致使响应延迟
3. **SA 生命周期管理:** 回调过多时 DeathRecipient 管理复杂度上升

返回 `DP_SUBSCRIBE_LIMIT_EXCEEDED` 时，订阅者应等待或合并订阅减少注册数。

---

## 信任与 ACL

### Q: AccessControlProfile 中的 Accesser 和 Accessee 是什么意思？

**A:** ACL 描述的是一个**方向性信任关系**：

| 字段 | 含义 | 示例 |
|------|------|------|
| **Accesser** | 访问发起方（谁发起了这个信任关系） | 手机 A 主动信任并访问平板 B |
| **Accessee** | 访问接受方（被信任的目标） | 平板 B 接受了手机 A 的访问请求 |

所以一个 ACL 记录表达了"Accesser 有权访问 Accessee 的哪些资源"。这两个字段共同描述了一个完整的**单方向**信任关系。双向信任需要两条 ACL 记录（A->B 和 B->A）。

### Q: LNN ACL 和用户绑定的 ACL 有什么不同？

**A:** 

| 维度 | LNN ACL | 用户绑定 ACL |
|------|--------|------------|
| **创建方式** | 局域网设备自动发现时由 LNN 协议自动生成 | 用户主动配对/绑定设备时创建 |
| **生命周期** | 局域网断开时可能被清理 | 持续到用户手动解绑 |
| **可见性** | `GetAllAccessControlProfile()` 不返回；仅 `GetAllAclIncludeLnnAcl()` 可查询 | `GetAllAccessControlProfile()` 返回 |
| **查询权限** | 仅 device_manager 和 softbus_server | device_manager 和 softbus_server |
| **extraData 标记** | JSON 中包含 LNN 来源标记 | 无标记或包含用户绑定信息 |

设计意图：LNN ACL 是基础设施层优化（快速局域网重连），不应暴露给应用层。

---

## 故障排查

### Q: 服务频繁重启怎么办？

**A:** 按以下步骤诊断：

1. **检查启动日志:** 查找 `OnStart` 和 `Init` 相关的 ERROR 级别日志
   ```bash
   hdc shell hilog -T DHDP -e "init failed\|OnStart\|OnStop"
   ```
2. **检查 Crash 堆栈:** 查找 `DFX` / `faultlog` 相关崩溃日志
3. **查看依赖 SA 状态:** 确认 5 个核心依赖 SA 是否正常运行（softbus, kv, dm, account, memmgr）
4. **检查内存压力:** 低内存触发 SA 卸载属于正常行为；如果频繁发生，考虑系统内存配置
5. **检查 Idle 卸载是否正常:** `DelayUnloadTask` 在 180s 后卸载；如果 `runningIpcCount_` 未正确递减，SA 可能永远不进入 idle 又反复重启
6. **检查 OnStartFail 回调:** `SystemAbility::OnStartFail(initRet)` 是否被调用？

### Q: Profile 数据丢失如何排查？

**A:** 

1. **确认数据写入路径:** 
   - 写入时是否在 `isInited_ = false` 期间？如果是，检查 temp cache 是否成功 flush（日志中 `SaveDynamicProfilesFromTempCache` 和 retry 次数）
   - 如果 20 次重试全部失败，缓存数据确实会丢失（调用了 `ResetFirst()`）
2. **检查 KV 存储:** 使用 `hilog -T DHDP | grep "PutKv\|DelKv"` 查看 KV 操作日志
3. **检查 RDB 存储:** 查找 `RDBADAPTER_PUT_FAIL` / `RDBADAPTER_DELETE_FAIL` 错误
4. **检查多用户上下文:** 当前 foreground user 是否匹配数据所属用户？
5. **检查设备离线清理:** 设备离线时是否有误删除了本地数据？
6. **检查 KV 服务健康:** `KvDeathRecipient::OnRemoteDied` 是否触发了 ReInit 丢失数据？

### Q: 多用户场景下 Profile 数据访问异常？

**A:** 

1. **确认当前前台用户:** `MultiUserManager::GetCurrentForegroundUserID()` 是否正确？
2. **确认 Key 格式:** 是否包含正确的 `#userId` 后缀？
3. **确认用户切换事件:** `COMMON_EVENT_USER_SWITCHED` 是否被正确接收和处理？
4. **确认用户删除级联:** 如果用户被删除，`DeleteRemovedUserData` 是否成功？失败的日志中包含错误原因
5. **多用户特有错误码:**
   - `DP_GET_FOREGROUND_ID_FAIL` (98566277): 获取前台用户 ID 失败
   - `DP_GET_LOCAL_PROFILE_IS_NOT_FOREGROUND_ID` (98566279): 查询了非前台用户的数据
   - `DP_GET_USER_ID_IS_NOT_TRUSTED` (98566280): 请求的用户 ID 不被信任

### Q: PutServiceProfile 返回 DP_CACHE_EXIST 怎么处理？

**A:** `DP_CACHE_EXIST` (98566164) 表示 temp cache 中已存在相同的 Profile（在服务初始化未完成期间写入后被再次写入）。处理方式：

1. **短等待后重试:** 等待服务完全初始化（建议 10s）后重新调用
2. **检查是否真的重复:** 同一个 deviceId + serviceName 的 ServiceProfile 只能写入一次
3. **如需覆盖:** 先 DeleteServiceProfile 再 PutServiceProfile（但注意 DeleteServiceProfile 的限制）
4. **避免写入时机:** 不要在系统启动早期密集写入 Profile，等待 `usual.event.BOOT_COMPLETED` 后再操作

### Q: GetDeviceProfile 返回 DP_NOT_FIND_DATA 但设备确实在线？

**A:** 

1. **检查设备是否为 LNN 发现:** LNN 发现的设备可能有信任关系但没有 DeviceProfile 数据（DeviceProfile 需要显式 Put）
2. **检查 KV 同步状态:** 如果是远程设备，DeviceProfile 是否已从远程同步到本地？
3. **检查缓存:** `ProfileCache` 中是否有该设备的缓存条目？
4. **区分 NOT_FIND_DATA 和 NOT_FOUND_FAIL:** 前者 (98566221) 来自 RDB 查询，后者 (98566202) 来自 KV 查询 -- 定位查询路径
5. **确认 deviceId 格式:** 是否使用了正确的 UDID/UUID 格式？
