# 06 - 调试与故障排查

> DeviceProfile 模块调试与故障排查指南 | 最后更新: 2025-05-21

---

## 1. 日志配置

### 日志域与标签

| 属性 | 值 | 说明 |
|------|-----|------|
| **日志域** | `0xD004400` | HiLog 系统日志域，定义为 `LOG_DOMAIN 0xD004400` |
| **日志标签** | `DHDP` | 统一日志标签，定义为 `LOG_TAG "DHDP"` |
| **日志头文件** | `common/include/utils/distributed_device_profile_log.h` | 日志宏定义位置 |

### 日志级别说明

所有日志宏均自动追加 `TAG` 和 `__FUNCTION__` 信息，格式为 `TAG::FunctionName message`。

| 宏 | HiLog 级别 | 使用场景 |
|----|------------|---------|
| `HILOGF(fmt, ...)` | FATAL | 不可恢复的致命错误 |
| `HILOGE(fmt, ...)` | ERROR | 初始化失败、DB 操作失败、权限拒绝等错误 |
| `HILOGW(fmt, ...)` | WARN | 可恢复异常：缓存重复、重试失败、数据过期 |
| `HILOGI(fmt, ...)` | INFO | 关键路径节点：服务启动、初始化完成、同步触发 |
| `HILOGD(fmt, ...)` | DEBUG | 详细调试信息：Call 进入/退出、参数 dump |

### 如何启用 DEBUG 日志

由于编译时使用 `-O2` 优化，且代码中大量使用 `HILOGD` 宏，DEBUG 日志的可见性取决于系统日志级别配置：

```bash
# 方法 1: 通过 hdc shell 设置日志级别
hdc shell hilog -b D -D 0xD004400

# 方法 2: 临时关闭日志限流查看完整日志
hdc shell hilog -Q off

# 方法 3: 实时过滤 DHDP 标签日志
hdc shell hilog -T DHDP

# 方法 4: 导出日志到文件分析
hdc shell hilog -T DHDP > dp_debug.log
```

**注意:** `HILOGD` 宏使用 `LOG_CORE` 域，在 release 构建中需要确保系统 Hilog 级别设置为 DEBUG 或更低。

---

## 2. HiSysEvent（雷达）事件

### 事件定义（来源：`hisysevent.yaml`）

| 事件名称 | 类型 | 级别 | 标签 | 说明 |
|------------|------|-------|-----|-------------|
| `DP_SYNC_EVENT` | BEHAVIOR | MINOR | `deviceProfileSyn` | 设备画像同步活动日志 |
| `DP_SYNC_FAILED` | FAULT | CRITICAL | -- | 设备画像同步失败，携带 `FAULT_CODE` |

### DP_SYNC_EVENT（BEHAVIOR，MINOR）

记录所有设备画像同步活动，用于正常行为的审计和统计。

```
域名: DEVICE_PROFILE
类型: BEHAVIOR
级别: MINOR
标签: deviceProfileSyn
描述: 设备画像同步
```

### DP_SYNC_FAILED（FAULT，CRITICAL）

同步失败时触发，包含故障码用于故障定位。

```
域名: DEVICE_PROFILE
类型: FAULT
级别: CRITICAL
描述: 设备画像同步失败
字段:
  FAULT_CODE: INT32 - 故障码（对应 DP 错误码）
```

### 雷达辅助实现

**源码位置:** `radar/src/dp_radar_helper.cpp`

`DpRadarHelper` 是单例类（`IMPLEMENT_SINGLE_INSTANCE`），在关键业务操作点通过 `HiSysEventWrite` 上报雷达事件。主要上报点：

| 方法 | 触发点 | 业务场景 | 阶段 |
|--------|--------------|----------|-------|
| `ReportCheckDpSa` | SA 可用性检查 | `DP_GET_SA` | `DP_CHECK_SA` |
| `ReportLoadDpSa` | 加载 SA | `DP_GET_SA` | `DP_LOAD_SA` |
| `ReportLoadDpSaCb` | SA 加载回调 | `DP_GET_SA` | `DP_LOAD_SA` |
| `ReportSaCheckAuth` | 调用者权限校验 | `DP_GET_SA` | `DP_SA_CHACK_AUTH` |
| `ReportPutAclProfile` | 写入 ACL Profile | `DP_PUT_ACL_PROFILE` | `DP_PROFILE_OPERATE` |
| `ReportUpdateAclProfile` | 更新 ACL Profile | `DP_UPDATE_ACL_PROFILE` | `DP_PROFILE_OPERATE` |
| `ReportGetTrustProfile` | 查询信任设备 | `DP_GET_TRUST_PROFILE` | `DP_PROFILE_OPERATE` |
| `ReportGetAllTrustProfile` | 查询所有信任设备 | `DP_GET_ALL_TRUST_PROFILE` | `DP_PROFILE_OPERATE` |
| `ReportGetAclProfile` | 查询 ACL Profile | `DP_GET_ACL_PROFILE` | `DP_PROFILE_OPERATE` |
| `ReportGetAllAclProfile` | 查询所有 ACL Profile | `DP_GET_ALL_ACL_PROFILE` | `DP_PROFILE_OPERATE` |
| `ReportDeleteAclProfile` | 删除 ACL Profile | `DP_DELETE_ACL_PROFILE` | `DP_PROFILE_OPERATE` |
| `ReportPutServiceProfile` | 写入 ServiceProfile | `DP_PUT_SERVICE_PROFILE` | `DP_PROFILE_OPERATE` |
| `ReportPutCharProfile` | 写入 CharacteristicProfile | `DP_PUT_CHAR_PROFILE` | `DP_PROFILE_OPERATE` |
| `ReportGetDeviceProfile` | 查询 DeviceProfile | `DP_GET_DEVICE_PROFILE` | `DP_PROFILE_OPERATE` |
| `ReportGetServiceProfile` | 查询 ServiceProfile | `DP_GET_SERVICE_PROFILE` | `DP_PROFILE_OPERATE` |
| `ReportGetCharProfile` | 查询 CharacteristicProfile | `DP_GET_CHAR_PROFILE` | `DP_PROFILE_OPERATE` |
| `ReportDeleteServiceProfile` | 删除 ServiceProfile | `DP_DELETE_SERVICE_PROFILE` | `DP_PROFILE_OPERATE` |
| `ReportDeleteCharProfile` | 删除 CharacteristicProfile | `DP_DELETE_CHAR_PROFILE` | `DP_PROFILE_OPERATE` |
| `ReportSubscribeDeviceProfile` | 订阅 Profile 变更 | `DP_SUBSCRIBE_DEVICE_PROFILE` | `DP_PROFILE_OPERATE` |
| `ReportUnSubscribeDeviceProfile` | 取消订阅 | `DP_UNSUNBSCRIBE_DEVICE_PROFILE` | `DP_PROFILE_OPERATE` |
| `ReportSyncDeviceProfile` | 同步操作 | `DP_SYNC_DEVICE_PROFILE` | `DP_PROFILE_OPERATE` |
| `ReportNotifyProfileChange` | 通知 Profile 变更 | `DP_SYNC_DEVICE_PROFILE` | `DP_NOTIFY_PROFILE_CHANGE` |

**查询雷达事件:**

```bash
# 查询 DEVICE_PROFILE 域的所有雷达事件
hdc shell hisysevent -d DEVICE_PROFILE

# 查询特定事件
hdc shell hisysevent -d DEVICE_PROFILE -n DP_SYNC_FAILED

# 查询最近的 CRITICAL 级别事件
hdc shell hisysevent -l CRITICAL -d DEVICE_PROFILE
```

---

## 3. Dump 支持

### DeviceProfileDumper

**源码位置:** `services/core/src/dfx/device_profile_dumper.cpp`

`DeviceProfileDumper` 提供 SA Dump 功能，通过 `hidumper` 命令触发。当前实现执行基本的安全检查后输出模块信息。

**权限控制:** 仅允许 `hidumper` 进程（UID=1212）调用：
```cpp
bool DeviceProfileDumper::CanDump() {
    auto callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid != UID_HIDUMPER) {
        return false;
    }
    return true;
}
```

**触发方式:**

```bash
# 通过 hidumper 触发 SA dump（SAID = 6001）
hdc shell hidumper -s 6001

# 查看帮助
hdc shell hidumper -s 6001 -h
```

**当前支持的参数:**
- 无参数: 执行默认 Dump，输出 "DeviceProfile Dump:" 基本信息
- `-h` / `-help`: 显示帮助信息
- 其他参数: 返回 `IllegalInput` 提示

> **提示:** 若需要更详细的 Dump（如缓存状态、KV 存储内容），需要在 `DumpDefault` 方法中扩展实现。代码中预留了 `DeviceProfileStorageManager::DumpLocalProfile` 的注释调用。

---

## 4. 按症状排查

| 症状 | 排查步骤 | 关键检查点 |
|------|---------|-----------|
| **服务无法启动** | 1. 检查 `OnStart` 日志中 `Init()` 返回的错误码<br>2. 确认 5 个 SA 依赖是否就绪：softbus_server (SAID)、distributed_kv_data、device_manager (4802)、os_account、memmgr<br>3. 检查 `hisysevent -d DEVICE_PROFILE` 中 `DP_CHECK_SA` / `DP_LOAD_SA` 阶段的状态<br>4. 检查 SA profile 配置 `sa_profile/6001.json` | SA 依赖项 (softbus, kv, dm, account, memmgr)，OnStart 错误码 (`DP_INIT_DB_FAILED`，各 manager 初始化失败) |
| **Profile 同步失败** | 1. 确认 syncMode 设置正确 (PUSH_PULL=2 是完整同步)<br>2. 检查目标设备是否在线 (`ProfileCache::IsDeviceOnline()`)<br>3. 查看 `DP_SYNC_FAILED` 雷达事件获取 fault_code<br>4. 检查 KV 存储健康状态：`hdc shell hilog -T DHDP \| grep "KvStore"`<br>5. 验证 KV death listener 是否触发过 reinit | 同步模式，设备在线状态，`DP_SYNC_FAILED` 雷达事件，KV 存储健康 |
| **数据未找到** | 1. 确认错误码是否为 `DP_NOT_FIND_DATA` (98566221)<br>2. 检查 ProfileCache 中是否有该数据<br>3. 检查 KV / RDB 对应表中是否存在数据<br>4. 多用户场景：确认当前 foreground user ID 是否匹配数据所属用户 | `DP_NOT_FIND_DATA`，缓存查找，KV 存储，RDB 表，多用户上下文 |
| **权限拒绝** | 1. 检查 `permission/permission.json` 中调用方法对应的允许进程列表<br>2. 区分两种权限检查路径：`IsCallerTrust`（特定方法白名单）vs `CheckCallerPermission`（通用调用者校验）<br>3. 确认调用者进程名是否在许可列表中（如 `device_manager`、`softbus_server`） | `permission.json`，进程名称，`IsCallerTrust` vs `CheckCallerPermission` |
| **KV 存储死亡** | 1. 检查日志中 `KvDeathRecipient::OnRemoteDied` 触发记录<br>2. 确认 reInit 任务是否成功 Post (storeId 匹配)<br>3. 四类 store 各自独立恢复：`dp_kv_store`(dynamic) -> DeviceProfileManager::ReInit, `dp_kv_static_store` -> StaticProfileManager::ReInit, `dp_kv_store_business` -> DeviceProfileManager::ReInit, `dp_kv_store_service_info_profile` -> ServiceInfoManager::ReInit<br>4. 如果 reInit 持续失败，检查 KV 服务本身是否异常 | `KvDeathRecipient`，`OnRemoteDied` 日志，reInit 任务成功，store ID 匹配 |
| **RDB 操作失败** | 1. 检查 `DP_RDBADAPTER_TABLE_NOT_EXIST` (98566215) — 需执行建表<br>2. 检查 `DP_CREATE_TABLE_FAIL` (98566226) — 确认 SQL 语句和权限<br>3. 如果有 `DP_PRE_MIGRATION_DB_*` 错误 — 检查旧版本数据库迁移状态<br>4. 检查 RDB store 指针是否为空 (`DP_RDB_DB_PTR_NULL`) | 表是否存在，schema 迁移状态 (`DP_PRE_MIGRATION_DB_*`)，RDB store 指针 |
| **Profile 写入返回 DP_CACHE_EXIST** | 1. `DP_CACHE_EXIST` (98566164) 表示 temp cache 中已存在相同 profile<br>2. 发生在服务初始化未完成期间 (PostInit 进行中)<br>3. 检查 `IsServiceProfileExist` / `IsCharProfileExist` 日志<br>4. 如确需覆盖：等待服务完全初始化后重试（缓存 flush 后自动清除） | temp cache 重复检测，`IsServiceProfileExist`，等待 `isInited_` |
| **订阅不生效** | 1. 确认未超过 1000 个回调上限 (`MAX_CALLBACK_LEN`)<br>2. 检查 subscribe key 格式（saId, deviceId, serviceName, characteristicKey 组合）<br>3. 确认订阅时未返回 `DP_SUBSCRIBE_LIMIT_EXCEEDED` (98566152)<br>4. 检查 `DP_SUBSCRIBE_FAILED` (98566151) 和对应日志<br>5. 验证回调 proxy 是否存在（未因 SA 死亡而失效） | 订阅上限 (1000)，subscribe key 格式，`DP_SUBSCRIBE_LIMIT_EXCEEDED`，回调 proxy 存活状态 |
| **空闲卸载未触发** | 1. 检查 `runningIpcCount_` 计数器：若有未完成的 IPC 调用则拒绝进入 idle<br>2. 检查 `IsDeviceOnline()` 状态：有在线设备时拒绝空闲<br>3. 检查日志中 `IsReadyIntoIdle` 的返回值<br>4. 180s 延迟注销在 `DelayUnloadTask()` 中触发 (`DELAY_TIME = 180000ms`)<br>5. 低内存场景下由 `IDLE_REASON_LOW_MEMORY` 触发额外检查 | `runningIpcCount_`，在线设备数，`IsReadyIntoIdle()`，180s 定时器 |

---

## 5. 错误码速查

错误码基址: `98566143` (DEVICE_PROFILE_ERR_OFFSET)

### 成功
| 错误码 | 名称 | 说明 |
|------|------|-------------|
| 0 | `DP_SUCCESS` | 操作成功 |

### 参数错误 (44-45)
| 错误码 | 名称 | 说明 |
|------|------|-------------|
| 98566144 | `DP_INVALID_PARAMS` | 参数无效 |
| 98566145 | `DP_INTERFACE_CHECK_FAILED` | 接口校验失败 |

### 设备错误 (46-47)
| 错误码 | 名称 | 说明 |
|------|------|-------------|
| 98566146 | `DP_GET_LOCAL_UDID_FAILED` | 获取本地 UDID 失败 |
| 98566147 | `DP_GET_SERVICE_FAILED` | 获取服务失败 |

### 数据库初始化错误 (48, 57)
| 错误码 | 名称 | 说明 |
|------|------|-------------|
| 98566148 | `DP_INIT_DB_FAILED` | 数据库初始化失败 |
| 98566157 | `DP_NOT_INIT_DB` | 数据库未初始化 |

### 缓存错误 (61-65, 73, 80)
| 错误码 | 名称 | 说明 |
|------|------|-------------|
| 98566161 | `DP_PUT_DEVICE_CACHE_ERR` | 写入设备缓存失败 |
| 98566162 | `DP_PUT_SERVICE_CACHE_ERR` | 写入服务缓存失败 |
| 98566163 | `DP_PUT_CHARACTERISTIC_CACHE_ERR` | 写入特征缓存失败 |
| 98566164 | `DP_CACHE_EXIST` | 缓存已存在（重复插入） |
| 98566165 | `DP_CACHE_NOT_EXIST` | 缓存不存在 |
| 98566173 | `DP_CACHE_INIT_FAIL` | 缓存初始化失败 |
| 98566180 | `DP_CACHE_UNINIT_FAIL` | 缓存反初始化失败 |

### KV 存储错误 (89-99, 01-04)
| 错误码 | 名称 | 说明 |
|------|------|-------------|
| 98566189 | `DP_KV_DB_PTR_NULL` | KV 数据库指针为空 |
| 98566190 | `DP_KV_DB_INIT_FAIL` | KV 数据库初始化失败 |
| 98566191 | `DP_REGISTER_KV_DATA_LISTENER_FAILED` | 注册 KV 数据监听器失败 |
| 98566192 | `DP_UNREGISTER_KV_DATA_LISTENER_FAILED` | 注销 KV 数据监听器失败 |
| 98566193 | `DP_REGISTER_KV_SYNC_LISTENER_FAILED` | 注册 KV 同步监听器失败 |
| 98566194 | `DP_UNREGISTER_KV_SYNC_LISTENER_FAILED` | 注销 KV 同步监听器失败 |
| 98566195 | `DP_REGISTER_KV_DEATH_LISTENER_FAILED` | 注册 KV 死亡监听器失败 |
| 98566196 | `DP_UNREGISTER_KV_DEATH_LISTENER_FAILED` | 注销 KV 死亡监听器失败 |
| 98566197 | `DP_PUT_KV_DB_FAIL` | KV 写入失败 |
| 98566198 | `DP_DEL_KV_DB_FAIL` | KV 删除失败 |
| 98566199 | `DP_GET_KV_DB_FAIL` | KV 读取失败 |
| 98566200 | `DP_MANAGER_INIT_FAIL` | Manager 初始化失败 |
| 98566201 | `DP_EXCEED_MAX_SIZE_FAIL` | 超出最大尺寸限制 |
| 98566202 | `DP_NOT_FOUND_FAIL` | 未找到数据 |
| 98566203 | `DP_SYNC_DEVICE_FAIL` | 同步设备失败 |
| 98566204 | `DP_KV_SYNC_FAIL` | KV 同步失败 |

### RDB 错误 (09-15)
| 错误码 | 名称 | 说明 |
|------|------|-------------|
| 98566209 | `DP_RDBADAPTER_PUT_FAIL` | RDB 写入失败 |
| 98566210 | `DP_RDBADAPTER_DELETE_FAIL` | RDB 删除失败 |
| 98566211 | `DP_RDBADAPTER_UPDATE_FAIL` | RDB 更新失败 |
| 98566212 | `DP_RDBADAPTER_CREATE_TABLE_FAIL` | RDB 建表失败 |
| 98566213 | `DP_RDBADAPTER_INIT_FAIL` | RDB 适配器初始化失败 |
| 98566214 | `DP_GET_RDBSTORE_FAIL` | 获取 RDB Store 失败 |
| 98566215 | `DP_RDBADAPTER_TABLE_NOT_EXIST` | RDB 表不存在 |

### 信任/ACL 错误 (18-32)
| 错误码 | 名称 | 说明 |
|------|------|-------------|
| 98566218 | `DP_PUT_TRUST_DEVICE_PROFILE_FAIL` | 写入信任设备画像失败 |
| 98566219 | `DP_NOTIFY_TRUST_DEVICE_FAIL` | 通知信任设备失败 |
| 98566220 | `DP_GET_RESULTSET_FAIL` | 获取 ResultSet 失败 |
| 98566221 | `DP_NOT_FIND_DATA` | 未找到数据 |
| 98566222 | `DP_NOTIFY_STATUS_UPDATE_FAIL` | 状态更新通知失败 |
| 98566223 | `DP_RESULTSET_TO_VALUES_FAIL` | ResultSet 转 Values 失败 |
| 98566224 | `DP_DELETE_TRUST_DEVICE_PROFILE_FAIL` | 删除信任设备画像失败 |
| 98566225 | `DP_DELETE_ACCESS_CONTROL_PROFILE_FAIL` | 删除 ACL Profile 失败 |
| 98566226 | `DP_CREATE_TABLE_FAIL` | 建表失败 |
| 98566227 | `DP_CREATE_UNIQUE_INDEX_FAIL` | 创建唯一索引失败 |
| 98566228 | `DP_PUT_ACCESSER_PROFILE_FAIL` | 写入 Accesser Profile 失败 |
| 98566229 | `DP_PUT_ACCESSEE_PROFILE_FAIL` | 写入 Accessee Profile 失败 |
| 98566230 | `DP_UPDATE_TRUST_DEVICE_PROFILE_FAIL` | 更新信任设备画像失败 |
| 98566231 | `DP_DELETE_ACCESSER_PROFILE_FAIL` | 删除 Accesser Profile 失败 |
| 98566232 | `DP_DELETE_ACCESSEE_PROFILE_FAIL` | 删除 Accessee Profile 失败 |

### IPC 错误 (34-38)
| 错误码 | 名称 | 说明 |
|------|------|-------------|
| 98566234 | `DP_GET_PROXY_FAIL` | 获取 Proxy 失败 |
| 98566235 | `DP_WRITE_PARCEL_FAIL` | 写入 Parcel 失败 |
| 98566236 | `DP_READ_PARCEL_FAIL` | 读取 Parcel 失败 |
| 98566237 | `DP_UNLOAD_SA_FAIL` | 卸载 SA 失败 |
| 98566238 | `DP_IPC_REMOTE_OBJECT_NULLPTR` | IPC 远程对象为空 |

### 同步错误 (40-48)
| 错误码 | 名称 | 说明 |
|------|------|-------------|
| 98566240 | `DP_SYNC_INIT_FAILED` | 同步初始化失败 |
| 98566241 | `DP_SYNC_PROFILE_FAILED` | 同步 Profile 失败 |
| 98566242 | `DP_UNSUPPORTED_METHOD` | 不支持的方法 |
| 98566243 | `DP_NO_MEMORY` | 内存不足 |
| 98566244 | `DP_SESSION_ERROR` | 会话错误 |
| 98566245 | `DP_INVALID_PARAM` | 参数无效 |
| 98566246 | `DP_CREATE_SESSION_FAILED` | 创建会话失败 |
| 98566247 | `DP_RUN_LOADED_FUNCTION_FAILED` | 运行已加载函数失败 |
| 98566248 | `DP_LOAD_SYNC_ADAPTER_FAILED` | 加载同步适配器失败 |

### 静态能力错误 (54-60)
| 错误码 | 名称 | 说明 |
|------|------|-------------|
| 98566254 | `DP_STATIC_COLLECT_FAIL` | 静态能力采集失败 |
| 98566255 | `DP_LOAD_STATIC_CAP_FAIL` | 加载静态能力失败 |
| 98566256 | `DP_LOAD_STATIC_INFO_FAIL` | 加载静态信息失败 |
| 98566257 | `DP_GET_STATIC_CAP_FAIL` | 获取静态能力失败 |
| 98566258 | `DP_GET_STATIC_INFO_FAIL` | 获取静态信息失败 |
| 98566259 | `DP_PARSE_STATIC_CAP_FAIL` | 解析静态能力失败 |
| 98566260 | `DP_PARSE_STATIC_INFO_FAIL` | 解析静态信息失败 |

### Switch 管理错误 (62-72)
| 错误码 | 名称 | 说明 |
|------|------|-------------|
| 98566262 | `DP_SET_SWITCH_CHARPROFILE_FAIL` | 设置 Switch 特征画像失败 |
| 98566263 | `DP_NOTIFYSWITCHUPDATE_FAIL` | 通知 Switch 更新失败 |
| 98566264 | `DP_PUT_CHAR_BATCH_FAIL` | 批量写入特征画像失败 |
| 98566265 | `DP_GET_SWITCH_FAIL` | 获取 Switch 状态失败 |
| 98566266 | `DP_GET_NETWORKID_BY_UDID_FAIL` | UDID 转 NetworkID 失败 |
| 98566267 | `DP_GET_UDID_BY_NETWORKID_FAIL` | NetworkID 转 UDID 失败 |
| 98566268 | `DP_GET_SERVICENAME_BY_POS_FAIL` | 通过位置获取服务名失败 |
| 98566269 | `DP_GENERATE_SWITCH_NOTIFY_FAIL` | 生成 Switch 通知失败 |
| 98566270 | `DP_LOAD_SWITCH_JSON_FAIL` | 加载 Switch JSON 失败 |
| 98566271 | `DP_GET_SWITCH_INFO_FAIL` | 获取 Switch 信息失败 |
| 98566272 | `DP_INIT_SWITCH_PROFILE_MANAGER_FAIL` | 初始化 SwitchProfileManager 失败 |

### 多用户错误 (77-82)
| 错误码 | 名称 | 说明 |
|------|------|-------------|
| 98566277 | `DP_GET_FOREGROUND_ID_FAIL` | 获取前台用户 ID 失败 |
| 98566278 | `DP_GET_MULTI_USER_PROFILE_PARAMS_INVALID` | 多用户 Profile 参数无效 |
| 98566279 | `DP_GET_LOCAL_PROFILE_IS_NOT_FOREGROUND_ID` | 本地 Profile 非前台用户 |
| 98566280 | `DP_GET_USER_ID_IS_NOT_TRUSTED` | 用户 ID 不受信任 |
| 98566281 | `DP_MULTI_USER_MANAGER_INIT_FAIL` | 多用户管理器初始化失败 |
| 98566282 | `DP_MULTI_USER_MANAGER_UNINIT_FAIL` | 多用户管理器反初始化失败 |

### Profile 数据错误 (84-08)
| 错误码 | 名称 | 说明 |
|------|------|-------------|
| 98566284 | `DP_PUT_DEVICE_ICON_INFO_FAIL` | 写入设备图标信息失败 |
| 98566286 | `DP_DEL_DEVICE_ICON_INFO_FAIL` | 删除设备图标信息失败 |
| 98566287 | `DP_UPDATE_DEVICE_ICON_INFO_FAIL` | 更新设备图标信息失败 |
| 98566288 | `DP_PUT_PRODUCT_INFO_FAIL` | 写入产品信息失败 |
| 98566289 | `DP_DEL_PRODUCT_INFO_FAIL` | 删除产品信息失败 |
| 98566290 | `DP_UPDATE_PRODUCT_INFO_FAIL` | 更新产品信息失败 |
| 98566291 | `DP_RDB_PUT_SERVICE_PROFILE_FAIL` | RDB 写入 ServiceProfile 失败 |
| 98566292 | `DP_RDB_DELETE_SERVICE_PROFILE_FAIL` | RDB 删除 ServiceProfile 失败 |
| 98566293 | `DP_RDB_UPDATE_SERVICE_PROFILE_FAIL` | RDB 更新 ServiceProfile 失败 |
| 98566294 | `DP_RDB_GET_SERVICE_PROFILE_FAIL` | RDB 读取 ServiceProfile 失败 |
| 98566295 | `DP_RDB_SET_SERVICE_PROFILE_ID_FAIL` | RDB 设置 ServiceProfile ID 失败 |
| 98566296 | `DP_DEVICE_PROFILE_NOT_FOUND` | DeviceProfile 未找到 |
| 98566297 | `DP_SERVICE_PROFILE_NOT_FOUND` | ServiceProfile 未找到 |
| 98566298 | `DP_DEVICE_PROFILE_DAO_INIT_FAIL` | DeviceProfile DAO 初始化失败 |
| 98566299 | `DP_SERVICE_PROFILE_DAO_INIT_FAIL` | ServiceProfile DAO 初始化失败 |
| 98566300 | `DP_CHAR_PROFILE_DAO_INIT_FAIL` | CharacteristicProfile DAO 初始化失败 |
| 98566301 | `DP_PRODUCT_INFO_DAO_INIT_FAIL` | ProductInfo DAO 初始化失败 |
| 98566302 | `DP_DEVICE_ICON_INFO_DAO_INIT_FAIL` | DeviceIconInfo DAO 初始化失败 |
| 98566303 | `DP_DEVICE_PROFILE_DAO_UNINIT_FAIL` | DeviceProfile DAO 反初始化失败 |
| 98566304 | `DP_SERVICE_PROFILE_DAO_UNINIT_FAIL` | ServiceProfile DAO 反初始化失败 |
| 98566305 | `DP_CHAR_PROFILE_DAO_UNINIT_FAIL` | CharacteristicProfile DAO 反初始化失败 |
| 98566306 | `DP_PRODUCT_INFO_DAO_UNINIT_FAIL` | ProductInfo DAO 反初始化失败 |
| 98566307 | `DP_DEVICE_ICON_INFO_DAO_UNINIT_FAIL` | DeviceIconInfo DAO 反初始化失败 |
| 98566308 | `DP_CREATE_INDEX_FAIL` | 创建索引失败 |

### Asset 错误 (16-22)
| 错误码 | 名称 | 说明 |
|------|------|-------------|
| 98566316 | `DP_ASSET_DUPLICATED` | Asset 数据重复 |
| 98566317 | `DP_PUT_ASSET_ERROR` | Asset 写入失败 |
| 98566318 | `DP_UPDATE_ASSET_ERROR` | Asset 更新失败 |
| 98566319 | `DP_GET_ASSET_ERROE` | Asset 读取失败 |
| 98566320 | `DP_GET_ASSET_NOT_FIND` | Asset 数据未找到 |
| 98566321 | `DP_DELETE_ASSET_ERROR` | Asset 删除失败 |
| 98566322 | `DP_PARSE_ASSET_ERROR` | Asset 数据解析失败 |

### 业务/服务错误 (32-37)
| 错误码 | 名称 | 说明 |
|------|------|-------------|
| 98566332 | `DP_BUSINESS_EVENT_MANAGER_INIT_FAIL` | 业务事件管理器初始化失败 |
| 98566333 | `DP_BUSINESS_EVENT_MANAGER_UNINIT_FAIL` | 业务事件管理器反初始化失败 |
| 98566334 | `DP_PUT_BUSINESS_EVENT_FAIL` | 写入业务事件失败 |
| 98566335 | `DP_GET_BUSINESS_EVENT_FAIL` | 获取业务事件失败 |
| 98566336 | `DP_NOTIFY_BUSINESS_EVENT_FAIL` | 通知业务事件失败 |
| 98566337 | `DP_INVALID_SQL_RESULT` | SQL 查询结果无效 |

### 服务生命周期错误 (30-31, 39-42)
| 错误码 | 名称 | 说明 |
|------|------|-------------|
| 98566330 | `DP_SERVICE_ON_IDLE` | 服务进入空闲 |
| 98566331 | `DP_SERVICE_STOPPED` | 服务已停止 |
| 98566339 | `DP_PRE_MIGRATION_DB_AVAILABLE` | 迁移前数据库可用 |
| 98566340 | `DP_PRE_MIGRATION_DB_UNAVAILABLE` | 迁移前数据库不可用 |
| 98566341 | `DP_NOT_NEED_MIGRATION` | 无需迁移 |
| 98566342 | `DP_NOT_SUPPORT` | 不支持的操作 |

---

## 6. 依赖模块健康检查

DP 服务依赖以下 5 个核心 SA，启动时通过 `AddSystemAbilityListener` 注册监听。所有依赖 SA 就绪后才执行 `PostInit()`。

| 序号 | SA 模块 | SAID 常量 | 作用 | 健康检查命令 |
|---|---------|--------------|------|------------|
| 1 | **softbus_server** | `SOFTBUS_SERVER_SA_ID` | 设备发现和网络通信 | `hdc shell hidumper -s <saId>` + 检查业务日志 |
| 2 | **distributed_kv_data** | `DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID` | 分布式 KV 存储（Profile 跨设备同步基础） | 检查 KV store 初始化日志: `hilog -T DHDP \| grep "Init KvStorePtr"` |
| 3 | **device_manager** | `DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID` (4802) | 设备状态管理和上线/下线事件 | `hdc shell hidumper -s 4802` |
| 4 | **os_account** | `SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN` | 多用户管理、用户切换/删除事件 | 检查用户事件日志: `hilog -T DHDP \| grep "CommonEventType"` |
| 5 | **memmgr** | `MEMORY_MANAGER_SA_ID` | 内存管理，低内存事件触发 SA 卸载 | `hdc shell hidumper -s <saId>` + 检查 `SetCritical` 日志 |

**快速健康检查脚本:**

```bash
# 检查 DP 服务进程是否存在
hdc shell ps -ef | grep deviceprofile

# 检查 DP SA 是否已注册 (SAID 6001)
hdc shell hidumper -l | grep 6001

# 检查 DV 数据变化监听器日志
hdc shell hilog -T DHDP -e "RegisterDataChangeListener\|UnRegisterDataChangeListener"

# 检查 KV 死亡恢复日志
hdc shell hilog -T DHDP -e "OnRemoteDied\|ReInit"

# 检查同步行为
hdc shell hilog -T DHDP -e "SyncDeviceProfile\|DP_SYNC"
```

**关键健康指标:**
- `PostInit finish` 日志出现 -> 所有依赖就绪，服务完全初始化
- `isInited_ = true` -> Cache 已 flush，服务进入正常运行状态
- KV store 初始化耗时（日志中 `Init KvStorePtr Success, spend X ms`）若超过 6s (30次 x 200ms)，说明 KV 服务异常
- `DepSaIds_` map 为空 -> 所有依赖 SA 已上线
