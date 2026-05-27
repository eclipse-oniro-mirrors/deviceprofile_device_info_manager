# 07 - 设计决策 (ADR)

> DeviceProfile 模块架构决策记录 | 最后更新: 2025-05-21

---

## ADR-001：三层架构 (SDK / Common / Service)

- **日期:** 2023 年（初始架构）
- **状态:** 已采纳，生产环境中

### 背景

DeviceProfile 模块服务两种不同的消费者模式：(a) 外部 OpenHarmony 服务通过 IPC 调用 `deviceprofile` 进程 (SA 6001)；(b) 内部业务逻辑操作共享数据结构。最初的设计考虑将 IPC 传输和业务逻辑合并到单一层中。

### 决策

采用严格的三层分离：

1. **SDK 层** (`interfaces/innerkits/core/`) -- 客户端代理 (`DistributedDeviceProfileClient` + `DistributedDeviceProfileProxy`)，封装 IPC 传输。对外暴露单例 API (`GetInstance()`)，具有 SA 生命周期感知的重连能力，通过 `DeathRecipient` 和 `SystemAbilityStatusChangeStub` 实现。

2. **Common 层** (`common/`) -- 共享数据模型 (`DeviceProfile`、`ServiceProfile`、`CharacteristicProfile`、`AccessControlProfile` 等) 和 IPC 样板代码 (proxy/stub 对)。同时包含客户端和服务端共用的常量（错误码、枚举、日志宏）。

3. **Service 层** (`services/core/`) -- 业务逻辑管理器（16+ 个专门的管理器）、持久化适配器（KV store、RDB、Asset）、内容采集器和订阅管理。实现 SA 6001 生命周期。

### 备选方案

| 备选方案 | 拒绝原因 |
|------------|-----------------|
| 单体单层设计 | 无法在客户端和服务端之间共享数据模型而不产生代码重复；IPC 协议变更需要客户端和服务端协同重新构建 |
| 轻量客户端 + 厚重的 common 库 | 将 DAO 逻辑放在共享层中，会向 SDK 消费者暴露内部存储细节 |

### 影响

- **正面:** SDK 和服务端共享单一数据模型定义；IPC 关注点与业务逻辑隔离；SDK 可在 SA 死亡后重连，而消费者无感知。
- **负面:** 新增一个外部 API 需要在 3 层中修改（SDK proxy、common IPC stubs、service 实现）— 每个新方法大约涉及 6 个文件。
- **负面:** Common 层不能引用 service 头文件，导致需要在各 `constants/` 文件夹之间复制常量/接口定义。

---

## ADR-002：三存储后端 (KV + RDB + Asset)

- **日期:** 2023-2024
- **状态:** 已采纳，生产环境中

### 背景

DeviceProfile 必须满足三种根本不同的存储需求：
- Profile 数据在 OH 设备之间的分布式同步
- 结构化关系查询（设备图标信息、产品信息、ACL 关系）
- 高度敏感数据的加密存储（会话密钥）

### 决策

使用三种独立的存储后端，各自针对其用途进行优化：

| 后端 | 技术 | 主要用例 | 选用原因 |
|---------|-----------|-----------------|-----|
| **KV Store** | `distributeddata_inner` (DistributedKv) | Device/Service/Characteristic profiles、ServiceInfo、Business events | 内置跨 OH 设备分布式同步；键值访问模式与 profile 数据匹配 |
| **RDB** | `native_rdb` (SQLite) | Trust devices、ACL profiles、product info、device icon info、ServiceProfile、LocalServiceInfo | 关系完整性；高效的多条件查询（如"所有 Accesser=UDID 的 ACL"）；外键级联删除 |
| **Asset** | `asset_sdk`（硬件级加密） | Session keys | 安全敏感密钥需要硬件级加密；即使获取 root 权限也无法提取密钥 |

### 备选方案

| 备选方案 | 拒绝原因 |
|------------|-----------------|
| 全部使用单一 SQLite | 无分布式同步能力；profile 数据必须在 OH 设备之间同步 |
| 全部使用 KV store | 无法高效按 Accesser/Accessee 关系查询 ACL；无关系模式约束 |
| 移除 Asset，在 RDB 中加密 | Asset SDK 提供硬件级密钥存储，这是 SQLite 中软件级加密所无法比拟的 |

### 影响

- **正面:** 每个后端针对其访问模式进行了优化；KV store 提供零配置跨设备同步；Asset 确保会话密钥安全。
- **负面:** 必须管理三个独立的 init/uninit 生命周期；KV store 死亡恢复与 RDB 健康检查分离；跨后端一致性没有事务性的保证。
- **负面:** 后端之间的数据迁移非常复杂（需要应用层协调）。

---

## ADR-003：ServiceInfo 双层 KV 存储

- **日期:** 2024
- **状态:** 已采纳，生产环境中

### 背景

ServiceInfo 数据（由 device_manager 发布的服务元数据）需要两种不同的一致性模型：
- 一个**本地权威存储**，用于本地设备发布的数据
- 一个**同步存储**，在 OH 设备之间复制 ServiceInfo 以支持分布式发现

### 决策

将 ServiceInfo 拆分为两个 KV store 层：

| 层 | Store ID | 用途 |
|-------|---------|---------|
| **本地存储** | `dp_kv_store_service_info_profile` | 本地权威 ServiceInfo；仅由本地 device_manager 修改 |
| **同步存储** | （启用了同步的 KV） | 复制的 ServiceInfo，用于分布式查询；变更通过 KV 同步传播 |

`ServiceInfoKvAdapter` 管理本地 store；启用了同步的 store 使用 KV 内置的分布式同步机制。

### 备选方案

| 备选方案 | 拒绝原因 |
|------------|-----------------|
| 使用带过滤的单一同步 store | 无法保证本地数据的唯一权威性；本地写入和远程同步之间的竞态条件可能覆盖本地数据 |
| 对 ServiceInfo 使用 RDB | 失去自动分布式同步能力；需要自定义同步协议 |

### 影响

- **正面:** 本地权威性得到保护；同步存储支持分布式服务发现而无需自定义协议。
- **负面:** 两个 store 需要仔细的 key/namespace 管理；`KvDeathRecipient` 必须在 KV 死亡时恢复两个 store。

---

## ADR-004：首次初始化窗口的临时缓存

- **日期:** 2024
- **状态:** 已采纳，生产环境中

### 背景

DP 服务在 SA 发布到 `samgr` 后立即开始接受 `PutServiceProfile` / `PutCharacteristicProfile` API 调用。然而，KV store 和 RDB 在 `PostInit()` 完成后才就绪 — 而这要等到全部 5 个依赖 SA 都上报在线之后。这就产生了一个长达数秒的窗口期，在此期间的写入操作没有可用的存储后端。

### 决策

实现一个临时内存缓存，在初始化窗口期间吸收写入，然后在 `isInited_` 变为 true 后刷新到存储：

1. **缓存吸收:** 在 `IsInited()` 之前调用的 `PutServiceProfile` 和 `PutCharacteristicProfile` 进入临时缓存 (`dynamicProfileMap_`、`switchProfileMap_`)，而不是进入 KV/RDB。
2. **重复检测:** `IsServiceProfileExist()` / `IsCharProfileExist()` 同时检查临时缓存和持久化存储；重复项返回 `DP_CACHE_EXIST`。
3. **5 秒宽限期:** 如果在 `PostInit()` 期间运行 `SaveDynamicProfilesFromTempCache()` 时临时缓存为空，系统会休眠 `WAIT_BUSINESS_PUT_TIME_S`（5秒）以允许延迟的客户端填充缓存。
4. **带退避的重试:** 最多重试 `WRTE_CACHE_PROFILE_RETRY_TIMES`（20）次，每次重试间隔 `WRTE_CACHE_PROFILE_DELAY_TIME_US`（200ms）。
5. **失败恢复:** 如果全部 20 次重试均失败，调用 `ResetFirst()` 并接受数据丢失（原始客户端 API 调用在缓存接受时已返回 `DP_SUCCESS`）。

```cpp
// 关键参数（来源：distributed_device_profile_service_new.cpp）
constexpr int32_t WAIT_BUSINESS_PUT_TIME_S = 5;         // 5s 宽限期
constexpr int32_t WRTE_CACHE_PROFILE_DELAY_TIME_US = 200 * 1000; // 200ms 重试延迟
constexpr int32_t WRTE_CACHE_PROFILE_RETRY_TIMES = 20;  // 20 次重试
```

### 备选方案

| 备选方案 | 拒绝原因 |
|------------|-----------------|
| 在 PostInit 完成前阻塞所有 API 调用 | 对客户端造成不可接受的延迟；会导致依赖服务的初始化级联延迟 |
| 在 PostInit 前拒绝 API 调用 | 迫使客户端实现重试逻辑；许多调用者是有严格启动顺序的系统服务 |
| 同步启动依赖项 | 会破坏 SA 按需启动模型；如果依赖项也是按需的，可能导致死锁 |

### 影响

- **正面:** 客户端在启动期间体验到零延迟写入；无需客户端重试。
- **负面:** 在 5s + 重试窗口期间写入缓存的数据，如果进程在刷新完成前崩溃，存在数据丢失风险。
- **负面:** 跨临时缓存和持久化存储的重复检测给缓存管理增加了复杂性。

---

## ADR-005：DP 同步适配器作为动态库

- **日期:** 2024-2025
- **状态:** 已采纳，生产环境中

### 背景

OpenHarmony 设备通过 DistributedKv 内置的同步机制同步 profile 数据。然而，非 OH 设备（旧版 HarmonyOS、使用自定义同步协议的 IoT 设备）需要不同的同步传输方式。对非 OH 同步代码的硬编译时依赖是不可取的，原因是：
- 大多数 OH 设备永远不会需要非 OH 同步
- 非 OH 同步库可能并非在所有构建环境中都可用
- 基于插件的可扩展性允许针对特定设备的同步适配器

### 决策

对 DP 同步适配器使用基于 `dlopen` 的动态加载：

```cpp
// 来源：dp_services_constants / dp_sync_adapter 接口
// 适配器 .so 在需要非 OH 同步时通过 dlopen() 在运行时加载
// 错误：DP_LOAD_SYNC_ADAPTER_FAILED (98566248)
// 错误：DP_RUN_LOADED_FUNCTION_FAILED (98566247)
```

同步适配器是一个可选的 `.so` 文件。DP 服务在请求非 OH 设备同步时尝试加载它。如果 `.so` 不存在，非 OH 同步就不可用 — 服务继续正常运行 OH 设备同步。

### 备选方案

| 备选方案 | 拒绝原因 |
|------------|-----------------|
| 硬编译时依赖 | 适配器不可用时构建失败；对永远不需要它的设备增加二进制的体积 |
| 为非 OH 同步使用独立的服务进程 | 进程开销翻倍；生命周期协调复杂 |
| 使用 stub 回退的静态链接 | Stub 仍然需要链接时符号解析；未能解决构建可用性问题 |

### 影响

- **正面:** OH 和非 OH 同步路径清晰分离；对可选组件无构建时依赖。
- **负面:** 必须优雅处理 `dlopen` 失败模式（错误 `DP_LOAD_SYNC_ADAPTER_FAILED`、`DP_RUN_LOADED_FUNCTION_FAILED`）。
- **负面:** DP 服务与适配器 `.so` 之间的版本兼容性仅在运行时强制。

---

## ADR-006：按需启动与延迟卸载

- **日期:** 2023-2024
- **状态:** 已采纳，生产环境中

### 背景

作为一个系统服务，DeviceProfile 在没有分布式操作活跃时不应消耗资源。然而，频繁的启动/停止周期会降低响应速度。设计必须在资源效率和响应速度之间取得平衡。

### 决策

实现三阶段生命周期：

**阶段 1 -- 按需启动:**
SA 在 `sa_profile/6001.json` 中注册了 `OnDemandReason`。仅在以下情况启动：
- 设备上线（由 device_manager 触发）
- `usual.event.BOOT_COMPLETED` 触发（确保启动后可用）
- 其他服务通过 samgr 显式加载 SA 6001

**阶段 2 -- 空闲检测:**
SA 评估 `IsReadyIntoIdle()`，仅在以下条件满足时返回 true：
- `runningIpcCount_` 为零（无活跃 IPC 调用）
- 当前无设备在线（`ProfileCache::IsDeviceOnline()` 返回 false）

**阶段 3 -- 延迟卸载:**
启动后，`DelayUnloadTask()` 投递一个 180 秒定时器（`DELAY_TIME = 180000ms`）：
```cpp
constexpr int32_t DELAY_TIME = 180000; // 180 秒
unloadHandler_->PostTask(task, UNLOAD_TASK_ID, DELAY_TIME);
```
当定时器触发时，SA 通过 `samgrProxy->UnloadSystemAbility()` 卸载自身。

**保活机制:** 在 IPC 调用期间，`AddRunningIpcCount()` 原子递增计数器；`SubtractRunningIpcCount()` 递减。只要 IPC 处于活跃状态，空闲进入就会被拒绝。

### 备选方案

| 备选方案 | 拒绝原因 |
|------------|-----------------|
| 始终运行 | 在没有分布式操作活跃时浪费内存（~32 IPC 线程、KV store、RDB 连接） |
| 空闲时立即退出 | 频繁启动/停止会因 SA 初始化开销而降低客户端响应速度 |
| 固定时长轮询 | 无法及时响应设备上线事件 |

### 影响

- **正面:** 内存高效；SA 仅在需要时运行，并为突发性使用提供 3 分钟宽限期。
- **负面:** 空闲卸载后的首次 IPC 调用会产生完整的 SA 启动延迟（~秒级）。
- **负面:** `runningIpcCount_` 跟踪要求在所有 IPC 入口点仔细配对 increment/decrement。

---

## ADR-007：LNN ACL 分离

- **日期:** 2024
- **状态:** 已采纳，生产环境中

### 背景

DP 中的 AccessControlProfile 有两种不同的来源：
1. **用户绑定 ACL** — 当用户显式将两台设备绑定（如通过账户配对或 NFC 触碰）时，由 device_manager 或 softbus 创建
2. **LNN ACL** — 当两台设备在同一局域网内互相发现时，由本地网络协商（Local Network Negotiation）协议自动生成

用户绑定 ACL 应当对应用程序可见和可查询。LNN ACL 是基础设施层的产物，不应出现在应用查询中，但仍需对系统级调用者（如 device_manager）可访问。

### 决策

将两种 ACL 类型存储在同一 RDB 表中，但通过 JSON `extraData` 标志模式区分：

- LNN ACL 的 `extraData` 中包含一个标志，标记其为 LNN 来源
- `GetAllAccessControlProfile()` 过滤掉 LNN ACL — 仅返回用户绑定 ACL
- `GetAllAclIncludeLnnAcl()` 返回两种类型 — 通过 `permission.json` 限制为 `device_manager` 和 `softbus_server`

```json
// permission.json
"GetAllAccessControlProfile": ["device_manager", "softbus_server"],
"GetAllAclIncludeLnnAcl": ["device_manager", "softbus_server"]
```

### 备选方案

| 备选方案 | 拒绝原因 |
|------------|-----------------|
| 为 LNN ACL 使用单独的 RDB 表 | 需要对每个表使用不同的查询逻辑；使级联删除复杂化 |
| 在应用层过滤 | 每个应用都必须了解 LNN 过滤规则；无法强制执行 |
| 不需要时删除 LNN ACL | LNN ACL 支持快速重连；删除它们会导致重复的发现开销 |

### 影响

- **正面:** LNN ACL 不会泄露到应用查询中；系统服务保留完整访问权限。
- **负面:** 基于 `extraData` 标志的过滤是约定式的，非法模式强制 — 如果新代码路径忘记设置标志，LNN ACL 可能泄露。
- **负面:** `GetAllAccessControlProfile` 的 RDB 查询必须始终附加过滤条件。

---

## ADR-008：多用户 Profile 隔离

- **日期:** 2024
- **状态:** 已采纳，生产环境中

### 背景

OpenHarmony 支持单设备上多个 OS 账户（用户）。每个用户可能拥有不同的信任关系、服务画像和特征画像。用户 A 的数据不能对用户 B 可见，除非显式共享。

### 决策

实现三种机制用于多用户隔离：

**1. 带 #userId 后缀的 Key 标注:**
Profile 数据的 KV store key 以 `#<userId>` 作为后缀，以按用户分区数据：
```
Key 格式: <deviceId>#<serviceName>#<charKey>#<userId>
```
这确保 KV store 在 key 级别进行命名空间隔离 — 每个用户的数据存储在不同的 KV key 下。

**2. 前台用户提升:**
`MultiUserManager` 通过 `COMMON_EVENT_USER_SWITCHED` 跟踪当前前台用户。在用户切换时，前台用户的 profile 数据成为查询的"活跃"数据集。`GetCurrentForegroundUserID()` 返回活跃的用户上下文。

**3. 删除用户级联:**
当 `COMMON_EVENT_USER_REMOVED` 触发时，`DeviceProfileManager::DeleteRemovedUserData(userId)` 级联删除与该用户关联的所有 KV 条目、RDB 行和 Asset 记录：
```cpp
if (commonEventType == EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED) {
    DeviceProfileManager::GetInstance().DeleteRemovedUserData(userId);
}
```

### 备选方案

| 备选方案 | 拒绝原因 |
|------------|-----------------|
| 每个用户使用独立的 KV store | KV store 数量随用户线性增长；KV 服务可能限制 store 数量 |
| 单一 store 不做隔离 | 隐私违规；用户 A 可以读取用户 B 的信任关系 |
| 仅在查询时过滤 | 单一 store 中存储所有用户数据的成本；级联删除变得复杂 |

### 影响

- **正面:** 存储层强隔离；级联删除确保无孤儿数据。
- **负面:** Key 格式是约定式的；如果新代码路径省略 `#userId`，数据会在用户之间泄露。
- **负面:** `COMMON_EVENT_USER_SWITCHED` / `COMMON_EVENT_USER_REMOVED` 的投递延迟可能导致短暂的过期用户上下文窗口。
