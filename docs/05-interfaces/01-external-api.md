# 外部 API 参考 -- IDistributedDeviceProfile

> `IDistributedDeviceProfile` 中定义的全部 50 个公开 API 的完整参考文档。
> API 级别：System API | SAID：6001 | 接口描述符：`OHOS.DeviceProfile.IDistributedDeviceProfile`

## API 分类概览

| 类别 | API 数量 | 存储后端 |
|---|---|---|
| A. 信任与访问控制 | 8 | RDB（SQLite） |
| B. 会话密钥 | 4 | Asset（加密存储） |
| C. 设备画像 | 4 | KV Store / RDB |
| D. 服务画像 | 4 | KV Store |
| E. 特性画像 | 4 | KV Store |
| F. 画像变更订阅 | 6 | 内存映射表 -> IPC 回调 |
| G. 画像同步 | 3 | KV Sync / DP Sync Adapter |
| H. 信任设备管理 | 1 | 内存映射表 -> KV + RDB |
| I. 产品信息与设备图标 | 3 | RDB |
| J. 本地服务信息 | 4 | RDB |
| K. 业务事件 | 4 | KV Store（BusinessEventAdapter） |
| L. 服务信息 | 5 | KV Store（双层：本地 + 同步） |

## 通用返回码

所有 API 均返回 `int32_t`。以下错误码在整个模块中使用（偏移量 `98566143`）：

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 操作成功 |
| 98566144 | DP_PERMISSION_DENIED | 调用者缺少访问此 API 的权限 |
| 98566145 | DP_INVALID_PARAMETER | 输入参数无效或超出范围 |
| 98566146 | DP_NOT_FOUND | 请求的资源不存在 |
| 98566147 | DP_ALREADY_EXISTS | 资源已存在（插入冲突） |
| 98566148 | DP_LOAD_SERVICE_ERR | 服务 SA 未加载或未运行 |
| 98566149 | DP_SERVICE_STOPPED | 服务已停止 |
| 98566150 | DP_IPC_ERR | IPC 序列化或传输失败 |
| 98566151 | DP_DB_ERR | 数据库操作失败 |
| 98566152 | DP_KV_ERR | KV 存储操作失败 |
| 98566153 | DP_SYNC_ERR | 画像同步失败 |

---

## A. 信任与访问控制（8 个 API）

这些 API 管理信任设备关系和访问控制画像。数据通过 `TrustProfileManager` / `RdbAdapter` 存储在 RDB（SQLite）中。访问限于 `device_manager` 和 `softbus_server` 进程。

### A1. PutAccessControlProfile

**功能描述：** 创建一个新的访问控制画像，定义访问者（发起方）与被访问者（目标方）之间的信任关系。画像包含认证类型、绑定类型、绑定级别、会话密钥和有效期。会同时在 `accesser` 和 `accessee` 两张 RDB 表中插入记录。

**签名：**
```cpp
virtual int32_t PutAccessControlProfile(const AccessControlProfile& aclProfile) = 0;
```

**API 级别：** System API

**权限：** `["device_manager", "softbus_server"]`——仅允许这些调用者进程。

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `aclProfile` | `const AccessControlProfile&` | 输入 | 要创建的访问控制画像 | 必须包含有效的访问者设备 ID、被访问者设备 ID、绑定类型、认证类型、绑定级别。参见下方 AccessControlProfile 字段。 |

**AccessControlProfile 关键字段：**

| 字段 | 类型 | 说明 |
|---|---|---|
| accessControlId | int64_t | 自动分配的唯一 ID |
| accesserId | int64_t | 自动分配的访问者记录 ID |
| accesseeId | int64_t | 自动分配的被访问者记录 ID |
| trustDeviceId | string | 信任设备唯一标识符 |
| sessionKey | string | 会话密钥字符串 |
| bindType | uint32_t | SAME_ACCOUNT=1, SHARE=2, POINT_TO_POINT=256, COMPATIBLE=512, DIFF_ACCOUNT=1282 |
| authenticationType | uint32_t | TEMPORARY=1, PERMANENT=2 |
| bindLevel | uint32_t | USER=1, SERVICE=2, APP=3 |
| status | int32_t | INACTIVE=0, ACTIVE=1 |
| validPeriod | int64_t | 有效期时长（秒） |
| lastAuthTime | int64_t | 上次认证时间戳 |
| deviceIdType | uint32_t | UDID=1, UUID=2, SN=3 |
| deviceIdHash | string | 设备标识符哈希值 |
| extraData | string | 扩展数据字段 |
| accesser | Accesser | 访问者详情（设备、用户、Bundle 信息） |
| accessee | Accessee | 被访问者详情（设备、用户、Bundle 信息） |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | ACL 画像创建成功 |
| 98566144 | DP_PERMISSION_DENIED | 调用者不在允许的进程列表中 |
| 98566145 | DP_INVALID_PARAMETER | aclProfile 中含有空字段或无效字段 |
| 98566151 | DP_DB_ERR | RDB 插入失败 |
| 98566147 | DP_ALREADY_EXISTS | ACL 关系已存在 |

**示例：**
```cpp
#include "distributed_device_profile_client.h"
#include "access_control_profile.h"
#include "accesser.h"
#include "accessee.h"

using namespace OHOS::DistributedDeviceProfile;

// 构建 ACL 画像对象
AccessControlProfile aclProfile;
aclProfile.SetTrustDeviceId("device_udid_12345");
aclProfile.SetBindType(static_cast<uint32_t>(BindType::POINT_TO_POINT));
aclProfile.SetAuthenticationType(static_cast<uint32_t>(AuthenticationType::PERMANENT));
aclProfile.SetBindLevel(static_cast<uint32_t>(BindLevel::APP));
aclProfile.SetStatus(static_cast<int32_t>(Status::ACTIVE));
aclProfile.SetValidPeriod(86400);  // 有效期 24 小时
aclProfile.SetDeviceIdType(static_cast<uint32_t>(DeviceIdType::UDID));

// 设置访问者信息
Accesser accesser;
accesser.SetAccesserDeviceId("local_device_udid");
accesser.SetAccesserUserId(100);
accesser.SetAccesserBundleName("com.example.app");
aclProfile.SetAccesser(accesser);

// 设置被访问者信息
Accessee accessee;
accessee.SetAccesseeDeviceId("device_udid_12345");
accessee.SetAccesseeUserId(100);
accessee.SetAccesseeBundleName("com.example.service");
aclProfile.SetAccessee(accessee);

// 通过客户端单例调用 API
auto& client = DistributedDeviceProfileClient::GetInstance();
int32_t ret = client.PutAccessControlProfile(aclProfile);
if (ret == DP_SUCCESS) {
    // ACL 画像创建成功
}
```

---

### A2. UpdateAccessControlProfile

**功能描述：** 更新已有的访问控制画像。传入的 `aclProfile` 必须包含之前 `PutAccessControlProfile` 调用返回的有效 `accessControlId`。会同时更新 accesser 和 accessee 表。如果状态或绑定级别发生变化，会触发信任设备画像更新通知。

**签名：**
```cpp
virtual int32_t UpdateAccessControlProfile(const AccessControlProfile& aclProfile) = 0;
```

**API 级别：** System API

**权限：** `["device_manager", "softbus_server"]`

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `aclProfile` | `const AccessControlProfile&` | 输入 | 包含更新字段的 ACL 画像 | 必须包含有效的 `accessControlId`，指向一个已存在的画像 |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 画像更新成功 |
| 98566144 | DP_PERMISSION_DENIED | 调用者不被允许 |
| 98566145 | DP_INVALID_PARAMETER | 字段无效 |
| 98566146 | DP_NOT_FOUND | 未找到对应 accessControlId 的画像 |
| 98566151 | DP_DB_ERR | RDB 更新失败 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
// 获取已有画像，然后修改字段
AccessControlProfile updatedProfile = /* 获取已有画像 */;
updatedProfile.SetStatus(static_cast<int32_t>(Status::INACTIVE));  // 设为非活跃
updatedProfile.SetValidPeriod(3600);  // 有效期改为 1 小时
int32_t ret = client.UpdateAccessControlProfile(updatedProfile);
```

---

### A3. GetTrustDeviceProfile

**功能描述：** 通过设备 ID 获取单个信任设备画像。信任设备画像代表与远程设备的信任关系摘要，包含状态、绑定类型和用户映射信息。

**签名：**
```cpp
virtual int32_t GetTrustDeviceProfile(const std::string& deviceId, TrustDeviceProfile& trustDeviceProfile) = 0;
```

**API 级别：** System API

**权限：** `["device_manager", "softbus_server"]`

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `deviceId` | `const std::string&` | 输入 | 设备标识符（UDID/UUID） | 非空字符串 |
| `trustDeviceProfile` | `TrustDeviceProfile&` | 输出 | 获取到的信任设备画像 | 成功时填充 |

**TrustDeviceProfile 字段：**

| 字段 | 类型 | 说明 |
|---|---|---|
| deviceId | string | 设备唯一标识符 |
| deviceIdType | uint32_t | UDID=1, UUID=2, SN=3 |
| deviceIdHash | string | 设备 ID 哈希值 |
| status | int32_t | INACTIVE=0, ACTIVE=1 |
| bindType | uint32_t | 信任关系绑定类型 |
| peerUserId | int32_t | 对端设备用户 ID（未知时为 -1） |
| localUserId | int32_t | 本地用户 ID |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 画像获取成功 |
| 98566144 | DP_PERMISSION_DENIED | 调用者不被允许 |
| 98566146 | DP_NOT_FOUND | 设备 ID 不在信任表中 |
| 98566151 | DP_DB_ERR | RDB 查询失败 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
TrustDeviceProfile trustProfile;
int32_t ret = client.GetTrustDeviceProfile("device_udid_12345", trustProfile);
if (ret == DP_SUCCESS) {
    // 判断设备状态
    std::string status = (trustProfile.GetStatus() == static_cast<int32_t>(Status::ACTIVE)) ? "ACTIVE" : "INACTIVE";
}
```

---

### A4. GetAllTrustDeviceProfile

**功能描述：** 获取本地 RDB 中存储的所有信任设备画像。返回所有已建立信任关系的设备的完整列表。

**签名：**
```cpp
virtual int32_t GetAllTrustDeviceProfile(std::vector<TrustDeviceProfile>& trustDeviceProfiles) = 0;
```

**API 级别：** System API

**权限：** `["device_manager", "softbus_server"]`

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `trustDeviceProfiles` | `std::vector<TrustDeviceProfile>&` | 输出 | 全部信任设备画像的向量 | 成功时清空并填充 |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 所有画像获取成功 |
| 98566144 | DP_PERMISSION_DENIED | 调用者不被允许 |
| 98566151 | DP_DB_ERR | RDB 查询失败 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
std::vector<TrustDeviceProfile> trustProfiles;
int32_t ret = client.GetAllTrustDeviceProfile(trustProfiles);
if (ret == DP_SUCCESS) {
    for (auto& profile : trustProfiles) {
        // 遍历处理每个信任设备
    }
}
```

---

### A5. GetAccessControlProfile

**功能描述：** 使用灵活的键值查询参数查询访问控制画像。支持的查询键包括 `tokenId`、`userId`、`bundleName`、`trustDeviceId`、`bindType`、`status`、`accountId`。根据提供的参数组合，可按正向（按访问者）或反向（按被访问者）进行过滤。

**签名：**
```cpp
virtual int32_t GetAccessControlProfile(std::map<std::string, std::string> queryParams,
    std::vector<AccessControlProfile>& accessControlProfiles) = 0;
```

**API 级别：** System API

**权限：** `["device_manager", "softbus_server", "iShare"]`

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `queryParams` | `std::map<std::string, std::string>` | 输入 | 键值查询过滤参数 | 见下方支持的查询键 |
| `accessControlProfiles` | `std::vector<AccessControlProfile>&` | 输出 | 匹配的 ACL 画像列表 | 成功时填充 |

**支持的查询键：**

| 键 | 说明 |
|---|---|
| `tokenId` | 访问者或被访问者的令牌 ID |
| `userId` | 访问者用户 ID |
| `bundleName` | 访问者 Bundle 名称 |
| `trustDeviceId` | 信任设备标识符 |
| `bindType` | 绑定类型（1/2/256/512/1282） |
| `status` | 画像状态（0/1） |
| `accountId` | 访问者账户 ID |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 查询完成，结果已返回 |
| 98566144 | DP_PERMISSION_DENIED | 调用者不被允许 |
| 98566145 | DP_INVALID_PARAMETER | 查询参数无效 |
| 98566146 | DP_NOT_FOUND | 无匹配画像 |
| 98566151 | DP_DB_ERR | RDB 查询失败 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
// 按 bundleName 和 status 查询
std::map<std::string, std::string> queryParams;
queryParams["bundleName"] = "com.example.app";
queryParams["status"] = "1";  // 仅查询活跃的
std::vector<AccessControlProfile> aclProfiles;
int32_t ret = client.GetAccessControlProfile(queryParams, aclProfiles);
```

---

### A6. GetAllAccessControlProfile

**功能描述：** 获取本地 RDB 中存储的所有访问控制画像。包括所有 ACL 关系，无论状态或绑定类型如何，但不包括 LNN（Local Network Negotiation，局域网协商）自动生成的 ACL。

**签名：**
```cpp
virtual int32_t GetAllAccessControlProfile(std::vector<AccessControlProfile>& accessControlProfiles) = 0;
```

**API 级别：** System API

**权限：** `["device_manager", "softbus_server"]`

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `accessControlProfiles` | `std::vector<AccessControlProfile>&` | 输出 | 所有 ACL 画像（不含 LNN） | 清空并重新填充 |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 所有画像获取成功 |
| 98566144 | DP_PERMISSION_DENIED | 调用者不被允许 |
| 98566151 | DP_DB_ERR | RDB 查询失败 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
std::vector<AccessControlProfile> aclProfiles;
int32_t ret = client.GetAllAccessControlProfile(aclProfiles);
```

---

### A7. GetAllAclIncludeLnnAcl

**功能描述：** 获取所有访问控制画像，包括 LNN（局域网协商）自动生成的 ACL。与 `GetAllAccessControlProfile` 不同，此 API 还返回基于局域网发现的临时信任关系。

**签名：**
```cpp
virtual int32_t GetAllAclIncludeLnnAcl(std::vector<AccessControlProfile>& accessControlProfiles) = 0;
```

**API 级别：** System API

**权限：** `["device_manager", "softbus_server"]`

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `accessControlProfiles` | `std::vector<AccessControlProfile>&` | 输出 | 所有 ACL 画像（含 LNN） | 清空并重新填充 |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 所有画像获取成功 |
| 98566144 | DP_PERMISSION_DENIED | 调用者不被允许 |
| 98566151 | DP_DB_ERR | RDB 查询失败 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
std::vector<AccessControlProfile> allAclProfiles;
int32_t ret = client.GetAllAclIncludeLnnAcl(allAclProfiles);
```

---

### A8. DeleteAccessControlProfile

**功能描述：** 通过唯一 ID 删除访问控制画像。此操作会级联执行：如果无其他 ACL 引用了对应的信任设备，则关联的信任设备画像也会一并删除。accesser 和 accessee 表中的记录也将被移除。

**签名：**
```cpp
virtual int32_t DeleteAccessControlProfile(int32_t accessControlId) = 0;
```

**API 级别：** System API

**权限：** `["device_manager", "softbus_server"]`

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `accessControlId` | `int32_t` | 输入 | 要删除的访问控制画像 ID | 必须指向一个已存在的画像 |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 画像及相关记录已删除 |
| 98566144 | DP_PERMISSION_DENIED | 调用者不被允许 |
| 98566146 | DP_NOT_FOUND | accessControlId 不存在 |
| 98566151 | DP_DB_ERR | RDB 删除失败 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
int32_t ret = client.DeleteAccessControlProfile(1001);
```

---

## B. 会话密钥（4 个 API）

会话密钥通过 `SessionKeyManager` 存储在 Asset 加密存储后端中。访问限于 `device_manager` 和 `softbus_server`。

### B1. PutSessionKey

**功能描述：** 在 Asset 加密存储中为指定用户存储一个新的会话密钥。系统自动生成并返回唯一的会话密钥 ID。密钥以 Asset 二进制大对象形式持久化，附带包括用户 ID 和会话密钥 ID 在内的属性，用于索引查找。

**签名：**
```cpp
virtual int32_t PutSessionKey(uint32_t userId, const std::vector<uint8_t>& sessionKey, int32_t& sessionKeyId) = 0;
```

**API 级别：** System API

**权限：** `["device_manager", "softbus_server"]`

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `userId` | `uint32_t` | 输入 | OS 账户用户 ID | 必须是有效的已存在用户 |
| `sessionKey` | `const std::vector<uint8_t>&` | 输入 | 原始会话密钥字节 | 非空，通常 32-256 字节 |
| `sessionKeyId` | `int32_t&` | 输出 | 自动生成的唯一会话密钥 ID | 成功时填充 |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 密钥已存储，ID 已返回 |
| 98566144 | DP_PERMISSION_DENIED | 调用者不被允许 |
| 98566145 | DP_INVALID_PARAMETER | 密钥为空或 userId 无效 |
| 98566151 | DP_DB_ERR | Asset 存储操作失败 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
// 准备密钥字节
std::vector<uint8_t> key = {0x01, 0x02, 0x03, 0x04, /* ... 密钥字节 ... */};
int32_t sessionKeyId = 0;
int32_t ret = client.PutSessionKey(100, key, sessionKeyId);
if (ret == DP_SUCCESS) {
    // sessionKeyId 现在包含已存储密钥的标识符
}
```

---

### B2. GetSessionKey

**功能描述：** 使用用户 ID 和会话密钥 ID 作为查找键，从 Asset 加密存储中获取之前存储的会话密钥。

**签名：**
```cpp
virtual int32_t GetSessionKey(uint32_t userId, int32_t sessionKeyId, std::vector<uint8_t>& sessionKey) = 0;
```

**API 级别：** System API

**权限：** `["device_manager", "softbus_server"]`

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `userId` | `uint32_t` | 输入 | OS 账户用户 ID | 必须与存储记录匹配 |
| `sessionKeyId` | `int32_t` | 输入 | PutSessionKey 返回的会话密钥 ID | 必须在存储中存在 |
| `sessionKey` | `std::vector<uint8_t>&` | 输出 | 获取到的会话密钥字节 | 成功时填充 |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 密钥获取成功 |
| 98566144 | DP_PERMISSION_DENIED | 调用者不被允许 |
| 98566146 | DP_NOT_FOUND | 未找到匹配 userId + sessionKeyId 的密钥 |
| 98566151 | DP_DB_ERR | Asset 读取失败 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
std::vector<uint8_t> retrievedKey;
int32_t ret = client.GetSessionKey(100, 42, retrievedKey);
if (ret == DP_SUCCESS) {
    // 使用 retrievedKey
}
```

---

### B3. UpdateSessionKey

**功能描述：** 更新 Asset 加密存储中的已有会话密钥。以新的密钥字节替换已有条目（由 userId + sessionKeyId 标识）。

**签名：**
```cpp
virtual int32_t UpdateSessionKey(uint32_t userId, int32_t sessionKeyId, const std::vector<uint8_t>& sessionKey) = 0;
```

**API 级别：** System API

**权限：** `["device_manager", "softbus_server"]`

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `userId` | `uint32_t` | 输入 | OS 账户用户 ID | 必须与已有记录匹配 |
| `sessionKeyId` | `int32_t` | 输入 | 要更新的会话密钥 ID | 必须存在 |
| `sessionKey` | `const std::vector<uint8_t>&` | 输入 | 新的会话密钥字节 | 非空 |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 密钥已更新 |
| 98566144 | DP_PERMISSION_DENIED | 调用者不被允许 |
| 98566146 | DP_NOT_FOUND | 未找到匹配记录 |
| 98566151 | DP_DB_ERR | Asset 更新失败 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
std::vector<uint8_t> newKey = {0xAA, 0xBB, 0xCC, 0xDD};
int32_t ret = client.UpdateSessionKey(100, 42, newKey);
```

---

### B4. DeleteSessionKey

**功能描述：** 从 Asset 加密存储中删除会话密钥。

**签名：**
```cpp
virtual int32_t DeleteSessionKey(uint32_t userId, int32_t sessionKeyId) = 0;
```

**API 级别：** System API

**权限：** `["device_manager", "softbus_server"]`

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `userId` | `uint32_t` | 输入 | OS 账户用户 ID | 必须与存储记录匹配 |
| `sessionKeyId` | `int32_t` | 输入 | 要删除的会话密钥 ID | 必须存在 |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 密钥已删除 |
| 98566144 | DP_PERMISSION_DENIED | 调用者不被允许 |
| 98566146 | DP_NOT_FOUND | 未找到匹配记录 |
| 98566151 | DP_DB_ERR | Asset 删除失败 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
int32_t ret = client.DeleteSessionKey(100, 42);
```

---

## C. 设备画像（4 个 API）

设备画像描述设备的硬件和系统能力。动态画像存储在 KV Store 中，批量导入画像存储在 RDB 中。`PutDeviceProfileBatch` 限于 `device_manager`；读取/删除操作具有更广泛的访问权限。

### C1. PutDeviceProfileBatch

**功能描述：** 通过 `ProfileDataManager` 将多个设备画像批量插入 RDB。每个画像经校验后插入 `device_profile` 表。通常用于批量导入设备数据（例如产品信息数据库）。

**签名：**
```cpp
virtual int32_t PutDeviceProfileBatch(std::vector<DeviceProfile>& deviceProfiles) = 0;
```

**API 级别：** System API

**权限：** `["device_manager"]`

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `deviceProfiles` | `std::vector<DeviceProfile>&` | 输入 | 要插入的设备画像向量 | 不能为空；每个画像必须有有效的 `deviceId` |

**DeviceProfile 关键字段：**

| 字段 | 类型 | 说明 |
|---|---|---|
| deviceId | string | 设备唯一标识符 |
| deviceName | string | 设备可读名称 |
| deviceModel | string | 设备型号字符串 |
| manufactureName | string | 制造商名称 |
| storageCapability | int64_t | 存储容量（字节） |
| osSysCap | string | 系统能力编解码字符串 |
| osApiLevel | int32_t | OS API 级别 |
| osVersion | string | OS 版本字符串 |
| osType | int32_t | OS 类型标识符 |
| devType | string | 设备类型（手机/平板/电视等） |
| manu | string | 制造商代码 |
| sn | string | 序列号 |
| productId | string | 产品标识符 |
| productName | string | 产品名称 |
| internalModel | string | 内部型号代码 |
| isMultiUser | bool | 多用户支持标志 |
| userId | int32_t | 关联的用户 ID |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 所有画像插入成功 |
| 98566144 | DP_PERMISSION_DENIED | 调用者不是 device_manager |
| 98566145 | DP_INVALID_PARAMETER | 向量为空或字段无效 |
| 98566151 | DP_DB_ERR | RDB 插入失败 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
std::vector<DeviceProfile> profiles;

// 构建第一个设备画像
DeviceProfile profile1;
profile1.SetDeviceId("device_udid_001");
profile1.SetDeviceName("Phone A");
profile1.SetDeviceModel("P60");
profile1.SetOsType(1);
profile1.SetOsVersion("5.0.0");
profiles.push_back(profile1);

// 构建第二个设备画像
DeviceProfile profile2;
profile2.SetDeviceId("device_udid_002");
profile2.SetDeviceName("Tablet B");
profile2.SetDeviceModel("MatePad");
profiles.push_back(profile2);

int32_t ret = client.PutDeviceProfileBatch(profiles);
```

---

### C2. GetDeviceProfile

**功能描述：** 通过设备 ID 获取指定设备的设备画像。首先检查内存中的 `ProfileCache`，未命中时回退到 KV Store 查询。

**签名：**
```cpp
virtual int32_t GetDeviceProfile(const std::string& deviceId, DeviceProfile& deviceProfile) = 0;
```

**API 级别：** System API

**权限：** `["all"]`——任意进程均可访问。

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `deviceId` | `std::string&` | 输入 | 设备标识符 | 非空，有效的 UDID/UUID |
| `deviceProfile` | `DeviceProfile&` | 输出 | 获取到的设备画像 | 成功时填充 |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 画像获取成功 |
| 98566146 | DP_NOT_FOUND | 设备未找到 |
| 98566152 | DP_KV_ERR | KV Store 读取失败 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
DeviceProfile profile;
int32_t ret = client.GetDeviceProfile("device_udid_001", profile);
if (ret == DP_SUCCESS) {
    std::string name = profile.GetDeviceName();   // 获取设备名称
    std::string model = profile.GetDeviceModel();  // 获取设备型号
}
```

---

### C3. GetDeviceProfiles

**功能描述：** 使用过滤选项从 RDB 中查询多个设备画像。过滤条件可包括设备 ID 列表、智慧设备 ID 列表、设备画像 ID 列表、用户 ID 和账户 ID。

**签名：**
```cpp
virtual int32_t GetDeviceProfiles(DeviceProfileFilterOptions& options,
    std::vector<DeviceProfile>& deviceProfiles) = 0;
```

**API 级别：** System API

**权限：** `["device_manager"]`

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `options` | `DeviceProfileFilterOptions&` | 输入 | 过滤条件 | 至少应提供一个过滤字段 |
| `deviceProfiles` | `std::vector<DeviceProfile>&` | 输出 | 匹配的设备画像 | 成功时填充 |

**DeviceProfileFilterOptions 字段：**

| 字段 | 类型 | 说明 |
|---|---|---|
| userId | int32_t | 按用户 ID 过滤（-1 表示全部） |
| accountId | string | 按账户 ID 过滤 |
| deviceIds | vector\<string\> | 按设备 ID 列表过滤 |
| wiseDeviceIds | vector\<string\> | 按智慧设备 ID 列表过滤 |
| deviceProfileIds | vector\<int32_t\> | 按设备画像主键 ID 过滤 |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 画像获取成功 |
| 98566144 | DP_PERMISSION_DENIED | 调用者不是 device_manager |
| 98566145 | DP_INVALID_PARAMETER | 无有效过滤条件 |
| 98566146 | DP_NOT_FOUND | 无匹配画像 |
| 98566151 | DP_DB_ERR | RDB 查询失败 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
// 按 userId 过滤查询
DeviceProfileFilterOptions options;
options.SetUserId(100);
std::vector<DeviceProfile> profiles;
int32_t ret = client.GetDeviceProfiles(options, profiles);
```

---

### C4. DeleteDeviceProfileBatch

**功能描述：** 批量删除设备画像。输入向量中的每个画像必须包含要删除画像的 `deviceId`。从 RDB 的 `device_profile` 表中移除对应行。

**签名：**
```cpp
virtual int32_t DeleteDeviceProfileBatch(std::vector<DeviceProfile>& deviceProfiles) = 0;
```

**API 级别：** System API

**权限：** `["device_manager"]`

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `deviceProfiles` | `std::vector<DeviceProfile>&` | 输入 | 要删除的设备画像（通过 deviceId 标识） | 非空；每个画像必须有有效的 deviceId |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 画像已删除 |
| 98566144 | DP_PERMISSION_DENIED | 调用者不是 device_manager |
| 98566145 | DP_INVALID_PARAMETER | 向量为空或缺少 deviceId |
| 98566151 | DP_DB_ERR | RDB 删除失败 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
// 构建待删除设备画像列表
std::vector<DeviceProfile> toDelete;
DeviceProfile delItem;
delItem.SetDeviceId("device_udid_001");
toDelete.push_back(delItem);
int32_t ret = client.DeleteDeviceProfileBatch(toDelete);
```

---

## D. 服务画像（4 个 API）

服务画像描述设备上运行的服务（以 deviceId + serviceName 为复合键）。通过 `DeviceProfileManager` 和 `ProfileControlUtils` 存储在 KV Store 中。所有操作对所有进程开放。

### D1. PutServiceProfile

**功能描述：** 在 KV Store 中创建或覆盖服务画像。服务画像用于标识特定设备上具有指定服务类型的命名服务。

**签名：**
```cpp
virtual int32_t PutServiceProfile(const ServiceProfile& serviceProfile) = 0;
```

**API 级别：** System API

**权限：** `["all"]`

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `serviceProfile` | `const ServiceProfile&` | 输入 | 要存储的服务画像 | 必须具有非空的 deviceId、serviceName、serviceType |

**ServiceProfile 字段：**

| 字段 | 类型 | 说明 |
|---|---|---|
| deviceId | string | 宿主设备标识符 |
| serviceName | string | 服务名称 |
| serviceType | string | 服务类型字符串 |
| isMultiUser | bool | 多用户支持 |
| userId | int32_t | 关联的用户 ID（默认：-1） |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 服务画像已存储 |
| 98566145 | DP_INVALID_PARAMETER | 缺少必填字段 |
| 98566152 | DP_KV_ERR | KV Store 写入失败 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
// 构建服务画像
ServiceProfile svcProfile;
svcProfile.SetDeviceId("device_udid_001");
svcProfile.SetServiceName("com.example.myservice");
svcProfile.SetServiceType("dataService");
int32_t ret = client.PutServiceProfile(svcProfile);
```

---

### D2. PutServiceProfileBatch

**功能描述：** 在单个 KV Store 事务中通过 `PutBatch` 批量存储多个服务画像。

**签名：**
```cpp
virtual int32_t PutServiceProfileBatch(const std::vector<ServiceProfile>& serviceProfiles) = 0;
```

**API 级别：** System API

**权限：** `["all"]`

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `serviceProfiles` | `const std::vector<ServiceProfile>&` | 输入 | 服务画像向量 | 非空；每个画像必须有有效字段 |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 所有画像已存储 |
| 98566145 | DP_INVALID_PARAMETER | 向量为空或无效 |
| 98566152 | DP_KV_ERR | KV 批量写入失败 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
std::vector<ServiceProfile> profiles;
ServiceProfile svc1;
svc1.SetDeviceId("device_udid_001");
svc1.SetServiceName("musicService");
svc1.SetServiceType("media");
profiles.push_back(svc1);
// ... 添加更多服务画像
int32_t ret = client.PutServiceProfileBatch(profiles);
```

---

### D3. GetServiceProfile

**功能描述：** 通过设备 ID 和服务名称获取服务画像。首先检查内存缓存，未命中时查询 KV Store。

**签名：**
```cpp
virtual int32_t GetServiceProfile(const std::string& deviceId, const std::string& serviceName,
    ServiceProfile& serviceProfile) = 0;
```

**API 级别：** System API

**权限：** `["all"]`

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `deviceId` | `const std::string&` | 输入 | 设备标识符 | 非空 |
| `serviceName` | `const std::string&` | 输入 | 服务名称 | 非空 |
| `serviceProfile` | `ServiceProfile&` | 输出 | 获取到的服务画像 | 成功时填充 |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 画像获取成功 |
| 98566146 | DP_NOT_FOUND | 未找到匹配画像 |
| 98566152 | DP_KV_ERR | KV 读取失败 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
ServiceProfile svcProfile;
int32_t ret = client.GetServiceProfile("device_udid_001", "com.example.myservice", svcProfile);
```

---

### D4. DeleteServiceProfile

**功能描述：** 通过设备 ID 和服务名称从 KV Store 中删除服务画像。可选的多用户参数允许针对特定用户的画像进行操作。

**签名：**
```cpp
virtual int32_t DeleteServiceProfile(const std::string& deviceId, const std::string& serviceName,
    bool isMultiUser = false, int32_t userId = DEFAULT_USER_ID) = 0;
```

**API 级别：** System API

**权限：** `["all"]`

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `deviceId` | `const std::string&` | 输入 | 设备标识符 | 非空 |
| `serviceName` | `const std::string&` | 输入 | 服务名称 | 非空 |
| `isMultiUser` | `bool` | 输入 | 是否使用多用户键变体 | 默认：false |
| `userId` | `int32_t` | 输入 | 多用户变体的用户 ID | 默认：-1（DEFAULT_USER_ID） |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 画像已删除 |
| 98566146 | DP_NOT_FOUND | 未找到匹配画像 |
| 98566152 | DP_KV_ERR | KV 删除失败 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
int32_t ret = client.DeleteServiceProfile("device_udid_001", "com.example.myservice");
```

---

## E. 特性画像（4 个 API）

特性画像表示服务的键值属性（以 deviceId + serviceName + characteristicKey 为复合键）。存储在 KV Store 中。所有操作对所有进程开放。

### E1. PutCharacteristicProfile

**功能描述：** 存储一条与设备服务相关联的特性画像（键值对）。开关特性（例如剪贴板、跨设备拖拽）会路由到开关 KV 适配器。

**签名：**
```cpp
virtual int32_t PutCharacteristicProfile(const CharacteristicProfile& charProfile) = 0;
```

**API 级别：** System API

**权限：** `["all"]`

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `charProfile` | `const CharacteristicProfile&` | 输入 | 要存储的特性画像 | 必须具有非空的 deviceId、serviceName、characteristicKey、characteristicValue |

**CharacteristicProfile 字段：**

| 字段 | 类型 | 说明 |
|---|---|---|
| deviceId | string | 宿主设备标识符 |
| serviceName | string | 服务名称 |
| characteristicKey | string | 特性属性键 |
| characteristicValue | string | 特性属性值 |
| isMultiUser | bool | 多用户支持 |
| userId | int32_t | 关联的用户 ID |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 画像已存储 |
| 98566145 | DP_INVALID_PARAMETER | 缺少必填字段 |
| 98566152 | DP_KV_ERR | KV 写入失败 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
// 构建特性画像：记录服务版本号
CharacteristicProfile charProfile;
charProfile.SetDeviceId("device_udid_001");
charProfile.SetServiceName("com.example.myservice");
charProfile.SetCharacteristicKey("version");
charProfile.SetCharacteristicValue("2.0.1");
int32_t ret = client.PutCharacteristicProfile(charProfile);
```

---

### E2. PutCharacteristicProfileBatch

**功能描述：** 在单个 KV Store 批量事务中批量存储多个特性画像。开关特性会被分离出来并路由到开关 KV 适配器。

**签名：**
```cpp
virtual int32_t PutCharacteristicProfileBatch(const std::vector<CharacteristicProfile>& charProfiles) = 0;
```

**API 级别：** System API

**权限：** `["all"]`

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `charProfiles` | `const std::vector<CharacteristicProfile>&` | 输入 | 要存储的特性画像列表 | 非空；每个画像均有效 |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 所有画像已存储 |
| 98566145 | DP_INVALID_PARAMETER | 向量为空 |
| 98566152 | DP_KV_ERR | KV 批量写入失败 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
std::vector<CharacteristicProfile> charProfiles;
CharacteristicProfile cp1;
cp1.SetDeviceId("device_udid_001");
cp1.SetServiceName("myService");
cp1.SetCharacteristicKey("status");
cp1.SetCharacteristicValue("idle");
charProfiles.push_back(cp1);
int32_t ret = client.PutCharacteristicProfileBatch(charProfiles);
```

---

### E3. GetCharacteristicProfile

**功能描述：** 通过设备、服务和特性键获取特性画像。

**签名：**
```cpp
virtual int32_t GetCharacteristicProfile(const std::string& deviceId, const std::string& serviceName,
    const std::string& characteristicId, CharacteristicProfile& charProfile) = 0;
```

**API 级别：** System API

**权限：** `["all"]`

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `deviceId` | `const std::string&` | 输入 | 设备标识符 | 非空 |
| `serviceName` | `const std::string&` | 输入 | 服务名称 | 非空 |
| `characteristicId` | `const std::string&` | 输入 | 要查找的特性键 | 非空 |
| `charProfile` | `CharacteristicProfile&` | 输出 | 获取到的特性画像 | 成功时填充 |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 画像获取成功 |
| 98566146 | DP_NOT_FOUND | 未找到匹配画像 |
| 98566152 | DP_KV_ERR | KV 读取失败 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
CharacteristicProfile charProfile;
int32_t ret = client.GetCharacteristicProfile("device_udid_001", "myService", "version", charProfile);
```

---

### E4. DeleteCharacteristicProfile

**功能描述：** 通过设备、服务和特性键从 KV Store 中删除特性画像。

**签名：**
```cpp
virtual int32_t DeleteCharacteristicProfile(const std::string& deviceId, const std::string& serviceName,
    const std::string& characteristicId, bool isMultiUser = false, int32_t userId = DEFAULT_USER_ID) = 0;
```

**API 级别：** System API

**权限：** `["all"]`

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `deviceId` | `const std::string&` | 输入 | 设备标识符 | 非空 |
| `serviceName` | `const std::string&` | 输入 | 服务名称 | 非空 |
| `characteristicId` | `const std::string&` | 输入 | 要删除的特性键 | 非空 |
| `isMultiUser` | `bool` | 输入 | 多用户变体 | 默认：false |
| `userId` | `int32_t` | 输入 | 多用户的用户 ID | 默认：-1 |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 画像已删除 |
| 98566146 | DP_NOT_FOUND | 未找到匹配画像 |
| 98566152 | DP_KV_ERR | KV 删除失败 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
int32_t ret = client.DeleteCharacteristicProfile("device_udid_001", "myService", "version");
```

---

## F. 画像变更订阅（6 个 API）

这些 API 管理画像变更事件的订阅。订阅信息由 `SubscribeProfileManager` 在内存中维护，变更事件通过 IPC 回调分发给已注册的 `IProfileChangeListener` 代理。

### F1. SubscribeDeviceProfile

**功能描述：** 注册画像变更事件订阅。`SubscribeInfo` 指定了订阅的 SA、要匹配的画像键模式、要监听的变更类型（添加/更新/删除）以及接收回调的 IPC 监听器对象。

**签名：**
```cpp
virtual int32_t SubscribeDeviceProfile(const SubscribeInfo& subscribeInfo) = 0;
```

**API 级别：** System API

**权限：** `["all"]`

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `subscribeInfo` | `const SubscribeInfo&` | 输入 | 订阅规格说明 | 必须包含有效的 saId、subscribeKey、listener 以及至少一个 ProfileChangeType |

**SubscribeInfo 字段：**

| 字段 | 类型 | 说明 |
|---|---|---|
| saId | int32_t | 订阅的 System Ability ID |
| subscribeKey | string | 匹配画像变更的模式键 |
| subscribeChangeTypes | unordered_set\<ProfileChangeType\> | 要监听的事件类型 |
| listener | sptr\<IRemoteObject\> | IPC 回调代理 |

**ProfileChangeType 取值：**

| 枚举 | 值 |
|---|---|
| TRUST_DEVICE_PROFILE_ADD | 1 |
| TRUST_DEVICE_PROFILE_UPDATE | 2 |
| TRUST_DEVICE_PROFILE_DELETE | 3 |
| DEVICE_PROFILE_ADD | 4 |
| DEVICE_PROFILE_UPDATE | 5 |
| DEVICE_PROFILE_DELETE | 6 |
| SERVICE_PROFILE_ADD | 7 |
| SERVICE_PROFILE_UPDATE | 8 |
| SERVICE_PROFILE_DELETE | 9 |
| CHAR_PROFILE_ADD | 10 |
| CHAR_PROFILE_UPDATE | 11 |
| CHAR_PROFILE_DELETE | 12 |
| TRUST_DEVICE_PROFILE_ACTIVE | 13 |
| TRUST_DEVICE_PROFILE_INACTIVE | 14 |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 订阅已注册 |
| 98566145 | DP_INVALID_PARAMETER | SubscribeInfo 无效 |
| 98566147 | DP_ALREADY_EXISTS | 相同的订阅已注册 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
// 构建订阅信息，监听设备画像的添加和更新事件
SubscribeInfo subscribeInfo;
subscribeInfo.SetSaId(6002);
subscribeInfo.SetSubscribeKey("device_udid_001", "serviceName", "charKey", 100);
subscribeInfo.AddProfileChangeType(ProfileChangeType::DEVICE_PROFILE_ADD);
subscribeInfo.AddProfileChangeType(ProfileChangeType::DEVICE_PROFILE_UPDATE);
subscribeInfo.SetListener(myProfileChangeListener);
int32_t ret = client.SubscribeDeviceProfile(subscribeInfo);
```

---

### F2. UnSubscribeDeviceProfile

**功能描述：** 移除之前注册的画像变更订阅，通过匹配的 saId 和 subscribeKey 来标识。

**签名：**
```cpp
virtual int32_t UnSubscribeDeviceProfile(const SubscribeInfo& subscribeInfo) = 0;
```

**API 级别：** System API

**权限：** `["all"]`

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `subscribeInfo` | `const SubscribeInfo&` | 输入 | 要移除的订阅 | 必须与之前注册的订阅匹配（通过 saId + subscribeKey） |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 订阅已移除 |
| 98566146 | DP_NOT_FOUND | 未找到匹配的订阅 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
SubscribeInfo subscribeInfo;
subscribeInfo.SetSaId(6002);
subscribeInfo.SetSubscribeKey("device_udid_001", "serviceName", "charKey", 100);
int32_t ret = client.UnSubscribeDeviceProfile(subscribeInfo);
```

---

### F3. SubscribeDeviceProfileInited

**功能描述：** 注册一个回调，当 DeviceProfile 服务完成初始化后接收通知。服务完成 `PostInit()` 后，所有已注册的回调都会收到服务就绪的通知。通常由依赖 SA 使用，它们需要等待 DP 完全运行后才能发出 API 调用。

**签名：**
```cpp
virtual int32_t SubscribeDeviceProfileInited(int32_t saId, sptr<IRemoteObject> dpInitedCallback) = 0;
```

**API 级别：** System API

**权限：** permission.json 中未指定（开放访问）。

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `saId` | `int32_t` | 输入 | 订阅的 SA ID | 有效的正数 System Ability ID |
| `dpInitedCallback` | `sptr<IRemoteObject>` | 输入 | 实现 `IDpInitedCallback` 的 IPC 回调代理 | 非空 |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 回调已注册 |
| 98566145 | DP_INVALID_PARAMETER | 回调为空 |
| 98566147 | DP_ALREADY_EXISTS | 相同的 saId 已注册 |
| 98566150 | DP_IPC_ERR | IPC 代理创建失败 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
sptr<DpInitedCallbackProxy> callback = new DpInitedCallbackProxy(myRemoteCallback);
int32_t ret = client.SubscribeDeviceProfileInited(6002, callback->AsObject());
```

---

### F4. UnSubscribeDeviceProfileInited

**功能描述：** 移除指定 SA ID 之前注册的初始化完成回调。

**签名：**
```cpp
virtual int32_t UnSubscribeDeviceProfileInited(int32_t saId) = 0;
```

**API 级别：** System API

**权限：** 未指定（开放访问）。

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `saId` | `int32_t` | 输入 | 要取消注册的 SA ID | 必须已在此之前注册 |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 回调已取消注册 |
| 98566146 | DP_NOT_FOUND | 未找到匹配的注册 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
int32_t ret = client.UnSubscribeDeviceProfileInited(6002);
```

---

### F5. SubscribePinCodeInvalid

**功能描述：** 注册一个回调，当与特定 Bundle 和 Pin 交换类型关联的 PIN 码失效时接收通知。当本地服务的 PIN 码被更新或关联的 ACL 被删除时，`LocalServiceInfoManager` 会触发该通知。

**签名：**
```cpp
virtual int32_t SubscribePinCodeInvalid(const std::string& bundleName, int32_t pinExchangeType,
    sptr<IRemoteObject> pinCodeCallback) = 0;
```

**API 级别：** System API

**权限：** 未指定（开放访问）。

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `bundleName` | `const std::string&` | 输入 | 要监听的 Bundle 名称 | 非空 |
| `pinExchangeType` | `int32_t` | 输入 | Pin 交换类型标识符 | 有效的类型值 |
| `pinCodeCallback` | `sptr<IRemoteObject>` | 输入 | 实现 `IPinCodeInvalidCallback` 的 IPC 回调代理 | 非空 |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 回调已注册 |
| 98566145 | DP_INVALID_PARAMETER | bundleName 无效或回调为空 |
| 98566147 | DP_ALREADY_EXISTS | 相同的 bundleName + pinExchangeType 已注册 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
sptr<PinCodeInvalidCallbackProxy> callback = new PinCodeInvalidCallbackProxy(myRemoteCallback);
int32_t ret = client.SubscribePinCodeInvalid("com.example.app", 1, callback->AsObject());
```

---

### F6. UnSubscribePinCodeInvalid

**功能描述：** 移除指定 Bundle 和 Pin 交换类型之前注册的 PIN 码失效回调。

**签名：**
```cpp
virtual int32_t UnSubscribePinCodeInvalid(const std::string& bundleName, int32_t pinExchangeType) = 0;
```

**API 级别：** System API

**权限：** 未指定（开放访问）。

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `bundleName` | `const std::string&` | 输入 | 之前注册的 Bundle 名称 | 非空 |
| `pinExchangeType` | `int32_t` | 输入 | 之前注册的 Pin 交换类型 | - |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 回调已取消注册 |
| 98566146 | DP_NOT_FOUND | 未找到匹配的注册 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
int32_t ret = client.UnSubscribePinCodeInvalid("com.example.app", 1);
```

---

## G. 画像同步（3 个 API）

画像同步将本地画像推送到远程设备并从远程设备拉取画像。存在两种同步模式：OH-to-OH（通过 KV Store 端到端同步）和 OH-to-nonOH（通过 DP Sync Adapter 动态库）。

### G1. SyncDeviceProfile

**功能描述：** 触发与指定远程设备的画像同步。基于 OH 的设备直接通过 KV Store 的 `Sync()` 进行同步。非 OH 设备通过 DP Sync Adapter 动态库同步。所有同步操作完成（或失败）后调用 `syncCompletedCallback`。

**签名：**
```cpp
virtual int32_t SyncDeviceProfile(const DistributedDeviceProfile::DpSyncOptions& syncOptions,
    sptr<IRemoteObject> syncCompletedCallback) = 0;
```

**API 级别：** System API

**权限：** `["all"]`

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `syncOptions` | `const DpSyncOptions&` | 输入 | 同步配置：设备列表和同步模式 | 必须包含至少一个设备和有效的 SyncMode |
| `syncCompletedCallback` | `sptr<IRemoteObject>` | 输入 | 同步完成通知的 IPC 回调 | 非空（实现 `ISyncCompletedCallback`） |

**DpSyncOptions 字段：**

| 字段 | 类型 | 说明 |
|---|---|---|
| syncMode | SyncMode | PULL=0, PUSH=1, PUSH_PULL=2 |
| syncDeviceIds | vector\<string\> | 目标设备 ID 列表 |

**SyncMode 取值：**

| 值 | 枚举 | 说明 |
|---|---|---|
| 0 | PULL | 从远程设备拉取画像 |
| 1 | PUSH | 将本地画像推送到远程设备 |
| 2 | PUSH_PULL | 双向同步 |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 同步已启动 |
| 98566145 | DP_INVALID_PARAMETER | 设备列表为空 |
| 98566153 | DP_SYNC_ERR | 所有同步操作均失败 |
| 98566148 | DP_LOAD_SERVICE_ERR | DP Sync Adapter 库加载失败 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
// 配置双向同步到两个远程设备
DpSyncOptions syncOptions;
syncOptions.SetSyncMode(SyncMode::PUSH_PULL);
syncOptions.AddDevice("remote_udid_001");
syncOptions.AddDevice("remote_udid_002");
sptr<SyncCompletedCallbackProxy> callback = new SyncCompletedCallbackProxy(myRemoteCallback);
int32_t ret = client.SyncDeviceProfile(syncOptions, callback->AsObject());
```

---

### G2. SyncStaticProfile

**功能描述：** 触发与远程设备的静态设备画像（硬件能力、系统特性）同步。与同步动态画像的 `SyncDeviceProfile` 不同，此 API 仅同步设备启动时采集的静态能力数据。

**签名：**
```cpp
virtual int32_t SyncStaticProfile(const DistributedDeviceProfile::DpSyncOptions& syncOptions,
    sptr<IRemoteObject> syncCompletedCallback) = 0;
```

**API 级别：** System API

**权限：** 未指定（开放访问）。

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `syncOptions` | `const DpSyncOptions&` | 输入 | 同步配置 | 与 SyncDeviceProfile 相同 |
| `syncCompletedCallback` | `sptr<IRemoteObject>` | 输入 | 完成回调 | 非空 |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 静态同步已启动 |
| 98566145 | DP_INVALID_PARAMETER | 设备列表为空 |
| 98566153 | DP_SYNC_ERR | 同步失败 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
// 推送模式同步静态画像
DpSyncOptions syncOptions;
syncOptions.SetSyncMode(SyncMode::PUSH);
syncOptions.AddDevice("remote_udid_001");
sptr<SyncCompletedCallbackProxy> callback = new SyncCompletedCallbackProxy(myRemoteCallback);
int32_t ret = client.SyncStaticProfile(syncOptions, callback->AsObject());
```

---

### G3. SendSubscribeInfos

**功能描述：** 将本地订阅信息发送给 `SubscribeProfileManager` 用于跨设备转发。这使远程设备能够了解本地订阅者感兴趣哪些画像变更，从而远程端可以仅推送相关的变更。在同步订阅者连接时内部使用。

**签名：**
```cpp
virtual int32_t SendSubscribeInfos(std::map<std::string, SubscribeInfo> listenerMap) = 0;
```

**API 级别：** System API

**权限：** 未指定（开放访问）。

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `listenerMap` | `std::map<std::string, SubscribeInfo>` | 输入 | subscribe key 到 SubscribeInfo 的映射表 | 至少包含一个条目 |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 订阅信息已转发 |
| 98566145 | DP_INVALID_PARAMETER | 映射表为空 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
std::map<std::string, SubscribeInfo> listenerMap;
SubscribeInfo subInfo;
subInfo.SetSaId(6002);
subInfo.SetSubscribeKey("device_udid_001", 100);
subInfo.AddProfileChangeType(ProfileChangeType::SERVICE_PROFILE_ADD);
listenerMap["key_1"] = subInfo;
int32_t ret = client.SendSubscribeInfos(listenerMap);
```

---

## H. 信任设备管理（1 个 API）

### H1. PutAllTrustedDevices

**功能描述：** 在单个操作中批量注册所有信任设备。每个 `TrustedDeviceInfo` 描述一个设备，包含其网络 ID、认证形式、设备类型、OS 版本、UDID 和 UUID。设备被添加到 `ProfileCache` 的在线设备映射表中，并为每个未知设备在 RDB 中创建信任画像。

**签名：**
```cpp
virtual int32_t PutAllTrustedDevices(const std::vector<TrustedDeviceInfo> deviceInfos) = 0;
```

**API 级别：** System API

**权限：** `["device_manager"]`

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `deviceInfos` | `const std::vector<TrustedDeviceInfo>` | 输入 | 要注册的信任设备信息向量 | 非空；每个设备必须有有效的 networkId 和 udid |

**TrustedDeviceInfo 字段：**

| 字段 | 类型 | 说明 |
|---|---|---|
| networkId | string | SoftBus 网络 ID |
| authForm | int32_t | 认证形式类型 |
| deviceTypeId | uint16_t | 设备类型标识符 |
| osVersion | string | OS 版本字符串 |
| osType | int32_t | OS 类型代码 |
| udid | string | 设备唯一标识符 |
| uuid | string | 通用唯一标识符 |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 所有设备已注册 |
| 98566144 | DP_PERMISSION_DENIED | 调用者不是 device_manager |
| 98566145 | DP_INVALID_PARAMETER | 向量为空或缺少 UDID |
| 98566151 | DP_DB_ERR | 部分设备的 RDB 插入失败 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
std::vector<TrustedDeviceInfo> deviceInfos;

// 构建一个信任设备信息
TrustedDeviceInfo device1;
device1.SetNetworkId("net_001");
device1.SetAuthForm(1);
device1.SetUdid("udid_001");
device1.SetUuid("uuid_001");
device1.SetOsType(1);
device1.SetOsVersion("5.0.0");
deviceInfos.push_back(device1);

int32_t ret = client.PutAllTrustedDevices(deviceInfos);
```

---

## I. 产品信息与设备图标（3 个 API）

这些 API 管理 RDB 中的产品元数据和设备图标信息。限于 `device_manager`。

### I1. PutProductInfoBatch

**功能描述：** 将产品信息记录批量插入 RDB 的 `product_info` 表。每个 `ProductInfo` 将产品 ID 映射到其型号、名称、简称和图片版本。

**签名：**
```cpp
virtual int32_t PutProductInfoBatch(const std::vector<ProductInfo>& productInfos) = 0;
```

**API 级别：** System API

**权限：** `["device_manager"]`

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `productInfos` | `const std::vector<ProductInfo>&` | 输入 | 要插入的产品信息记录 | 非空；每条记录必须有 productId |

**ProductInfo 字段：**

| 字段 | 类型 | 说明 |
|---|---|---|
| productId | string | 产品标识符（主键） |
| model | string | 产品型号字符串 |
| productName | string | 产品显示名称 |
| productShortName | string | 产品简称 |
| imageVersion | string | 关联的图片版本 |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 所有记录已插入 |
| 98566144 | DP_PERMISSION_DENIED | 调用者不是 device_manager |
| 98566145 | DP_INVALID_PARAMETER | 记录为空或无效 |
| 98566151 | DP_DB_ERR | RDB 插入失败 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
std::vector<ProductInfo> productInfos;
ProductInfo pi;
pi.SetProductId("P60_Pro");
pi.SetModel("P60Pro");
pi.SetProductName("Phone P60 Pro");
pi.SetProductShortName("P60P");
pi.SetImageVersion("v1");
productInfos.push_back(pi);
int32_t ret = client.PutProductInfoBatch(productInfos);
```

---

### I2. PutDeviceIconInfoBatch

**功能描述：** 将设备图标信息批量插入 RDB。每个 `DeviceIconInfo` 将产品/设备标识映射到图标图片（以二进制数据形式）、URL 以及如图片类型、规格名称和版本等元数据。

**签名：**
```cpp
virtual int32_t PutDeviceIconInfoBatch(const std::vector<DeviceIconInfo>& deviceIconInfos) = 0;
```

**API 级别：** System API

**权限：** `["device_manager"]`

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `deviceIconInfos` | `const std::vector<DeviceIconInfo>&` | 输入 | 要插入的设备图标记录 | 非空；productId + internalModel + subProductId + imageType + specName 构成唯一键 |

**DeviceIconInfo 字段：**

| 字段 | 类型 | 说明 |
|---|---|---|
| id | int32_t | 自动分配的主键 |
| productId | string | 产品标识符 |
| internalModel | string | 内部型号代码 |
| subProductId | string | 子产品标识符 |
| imageType | string | 图片类型（如 "phone"、"tablet"） |
| specName | string | 规格名称 |
| version | string | 图标版本 |
| wiseVersion | string | Wise 平台版本 |
| url | string | 图标图片 URL |
| icon | vector\<uint8_t\> | 图标二进制数据 |
| modifyTime | int64_t | 最后修改时间戳 |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 所有图标已插入 |
| 98566144 | DP_PERMISSION_DENIED | 调用者不是 device_manager |
| 98566145 | DP_INVALID_PARAMETER | 记录为空或无效 |
| 98566151 | DP_DB_ERR | RDB 插入失败 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
std::vector<DeviceIconInfo> icons;
DeviceIconInfo icon;
icon.SetProductId("P60_Pro");
icon.SetInternalModel("LNA-AL00");
icon.SetSubProductId("default");
icon.SetImageType("phone");
icon.SetSpecName("large");
icon.SetVersion("1.0.0");
icon.SetUrl("https://example.com/icon.png");
// icon.SetIcon(iconBinaryData);  // 设置图标二进制数据
icons.push_back(icon);
int32_t ret = client.PutDeviceIconInfoBatch(icons);
```

---

### I3. GetDeviceIconInfos

**功能描述：** 使用过滤选项查询设备图标信息。过滤条件可包括产品 ID 列表、内部型号、子产品 ID、图片类型或规格名称。

**签名：**
```cpp
virtual int32_t GetDeviceIconInfos(const DeviceIconInfoFilterOptions& filterOptions,
    std::vector<DeviceIconInfo>& deviceIconInfos) = 0;
```

**API 级别：** System API

**权限：** `["device_manager"]`

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `filterOptions` | `const DeviceIconInfoFilterOptions&` | 输入 | 过滤条件 | 至少设置一个过滤字段 |
| `deviceIconInfos` | `std::vector<DeviceIconInfo>&` | 输出 | 匹配的设备图标记录 | 成功时填充 |

**DeviceIconInfoFilterOptions 字段：**

| 字段 | 类型 | 说明 |
|---|---|---|
| productIds | vector\<string\> | 按产品 ID 列表过滤 |
| internalModel | string | 按内部型号过滤 |
| subProductId | string | 按子产品 ID 过滤 |
| imageType | string | 按图片类型过滤 |
| specName | string | 按规格名称过滤 |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 图标获取成功 |
| 98566144 | DP_PERMISSION_DENIED | 调用者不是 device_manager |
| 98566146 | DP_NOT_FOUND | 未找到匹配的图标 |
| 98566151 | DP_DB_ERR | RDB 查询失败 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
// 按内部型号和图片类型过滤查询图标
DeviceIconInfoFilterOptions filterOpts;
filterOpts.SetInternalModel("LNA-AL00");
filterOpts.SetImageType("phone");
std::vector<DeviceIconInfo> icons;
int32_t ret = client.GetDeviceIconInfos(filterOpts, icons);
```

---

## J. 本地服务信息（4 个 API）

本地服务信息管理 RDB 中启用了 PIN 码认证的本地服务注册。限于 `device_manager`。

### J1. PutLocalServiceInfo

**功能描述：** 注册带有 PIN 码认证元数据的本地服务。数据存储在 `local_service_info` RDB 表中。PIN 码与 Bundle 名称、认证盒类型、认证类型和 PIN 交换类型关联。

**签名：**
```cpp
virtual int32_t PutLocalServiceInfo(const LocalServiceInfo& localServiceInfo) = 0;
```

**API 级别：** System API

**权限：** `["device_manager"]`

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `localServiceInfo` | `const LocalServiceInfo&` | 输入 | 要注册的本地服务信息 | 必须具有非空的 bundleName；有效的 authBoxType、authType、pinExchangeType |

**LocalServiceInfo 字段：**

| 字段 | 类型 | 说明 |
|---|---|---|
| bundleName | string | Bundle 名称（唯一键组成部分） |
| authBoxType | int32_t | 认证盒类型 |
| authType | int32_t | 认证类型 |
| pinExchangeType | int32_t | PIN 交换类型（唯一键组成部分） |
| pinCode | string | PIN 码值 |
| description | string | 服务描述 |
| extraInfo | string | 额外信息 |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 本地服务信息已创建 |
| 98566144 | DP_PERMISSION_DENIED | 调用者不是 device_manager |
| 98566145 | DP_INVALID_PARAMETER | 缺少必填字段 |
| 98566147 | DP_ALREADY_EXISTS | 相同的 bundleName + pinExchangeType 已存在 |
| 98566151 | DP_DB_ERR | RDB 插入失败 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
// 注册一个本地服务
LocalServiceInfo localInfo;
localInfo.SetBundleName("com.example.app");
localInfo.SetAuthBoxType(1);
localInfo.SetAuthType(2);
localInfo.SetPinExchangeType(1);
localInfo.SetPinCode("123456");
localInfo.SetDescription("My local service");
localInfo.SetExtraInfo("{}");
int32_t ret = client.PutLocalServiceInfo(localInfo);
```

---

### J2. UpdateLocalServiceInfo

**功能描述：** 更新已有的本地服务信息记录。`bundleName` 和 `pinExchangeType` 标识要更新的记录。如果 PIN 码被修改，已注册的 `PinCodeInvalidCallback` 订阅者会收到通知。

**签名：**
```cpp
virtual int32_t UpdateLocalServiceInfo(const LocalServiceInfo& localServiceInfo) = 0;
```

**API 级别：** System API

**权限：** `["device_manager"]`

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `localServiceInfo` | `const LocalServiceInfo&` | 输入 | 更新后的本地服务信息 | 必须匹配已有的 bundleName + pinExchangeType |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 记录已更新 |
| 98566144 | DP_PERMISSION_DENIED | 调用者不是 device_manager |
| 98566146 | DP_NOT_FOUND | 无已有记录匹配 |
| 98566151 | DP_DB_ERR | RDB 更新失败 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
// 更新已有本地服务的 PIN 码
LocalServiceInfo updatedInfo;
updatedInfo.SetBundleName("com.example.app");
updatedInfo.SetPinExchangeType(1);
updatedInfo.SetPinCode("654321");  // 新的 PIN 码
updatedInfo.SetDescription("Updated description");
int32_t ret = client.UpdateLocalServiceInfo(updatedInfo);
```

---

### J3. GetLocalServiceInfoByBundleAndPinType

**功能描述：** 通过复合键（Bundle 名称和 PIN 交换类型）获取本地服务信息记录。

**签名：**
```cpp
virtual int32_t GetLocalServiceInfoByBundleAndPinType(const std::string& bundleName,
    int32_t pinExchangeType, LocalServiceInfo& localServiceInfo) = 0;
```

**API 级别：** System API

**权限：** `["device_manager"]`

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `bundleName` | `const std::string&` | 输入 | 要查找的 Bundle 名称 | 非空 |
| `pinExchangeType` | `int32_t` | 输入 | PIN 交换类型 | 有效的类型值 |
| `localServiceInfo` | `LocalServiceInfo&` | 输出 | 获取到的本地服务信息 | 成功时填充 |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 记录获取成功 |
| 98566144 | DP_PERMISSION_DENIED | 调用者不是 device_manager |
| 98566146 | DP_NOT_FOUND | 未找到匹配记录 |
| 98566151 | DP_DB_ERR | RDB 查询失败 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
LocalServiceInfo result;
int32_t ret = client.GetLocalServiceInfoByBundleAndPinType("com.example.app", 1, result);
if (ret == DP_SUCCESS) {
    std::string pinCode = result.GetPinCode();  // 获取 PIN 码
}
```

---

### J4. DeleteLocalServiceInfo

**功能描述：** 通过 Bundle 名称和 PIN 交换类型删除本地服务信息记录。

**签名：**
```cpp
virtual int32_t DeleteLocalServiceInfo(const std::string& bundleName, int32_t pinExchangeType) = 0;
```

**API 级别：** System API

**权限：** `["device_manager"]`

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `bundleName` | `const std::string&` | 输入 | 要删除记录的 Bundle 名称 | 非空 |
| `pinExchangeType` | `int32_t` | 输入 | 要删除记录的 PIN 交换类型 | - |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 记录已删除 |
| 98566144 | DP_PERMISSION_DENIED | 调用者不是 device_manager |
| 98566146 | DP_NOT_FOUND | 未找到匹配记录 |
| 98566151 | DP_DB_ERR | RDB 删除失败 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
int32_t ret = client.DeleteLocalServiceInfo("com.example.app", 1);
```

---

## K. 业务事件（4 个 API）

业务事件是通过 `BusinessEventAdapter` 存储在 KV Store 中的键值对，用于在系统服务之间传递结构化事件数据。开放访问（不在 permission.json 中）。

### K1. RegisterBusinessCallback

**功能描述：** 注册业务事件通知的回调。当调用 `PutBusinessEvent` 时传入匹配的 `businessKey`，该 key 的所有已注册回调都会被调用。回调代理实现 `IBusinessCallback`。

**签名：**
```cpp
virtual int32_t RegisterBusinessCallback(const std::string& saId, const std::string& businessKey,
    sptr<IRemoteObject> businessCallback) = 0;
```

**API 级别：** System API

**权限：** 未指定（开放访问）。

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `saId` | `const std::string&` | 输入 | 订阅的 SA 标识符字符串 | 非空 |
| `businessKey` | `const std::string&` | 输入 | 要监听的业务事件键 | 非空 |
| `businessCallback` | `sptr<IRemoteObject>` | 输入 | IPC 回调代理 | 非空，实现 IBusinessCallback |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 回调已注册 |
| 98566145 | DP_INVALID_PARAMETER | saId/businessKey 为空或回调为空 |
| 98566147 | DP_ALREADY_EXISTS | 相同的 saId + businessKey 已注册 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
sptr<IRemoteObject> callback = myBusinessCallbackProxy->AsObject();
int32_t ret = client.RegisterBusinessCallback("6002", "event.user.login", callback);
```

---

### K2. UnRegisterBusinessCallback

**功能描述：** 移除之前注册的业务事件回调。

**签名：**
```cpp
virtual int32_t UnRegisterBusinessCallback(const std::string& saId, const std::string& businessKey) = 0;
```

**API 级别：** System API

**权限：** 未指定（开放访问）。

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `saId` | `const std::string&` | 输入 | 之前注册的 SA ID | 非空 |
| `businessKey` | `const std::string&` | 输入 | 之前注册的业务键 | 非空 |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 回调已取消注册 |
| 98566146 | DP_NOT_FOUND | 未找到匹配的注册 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
int32_t ret = client.UnRegisterBusinessCallback("6002", "event.user.login");
```

---

### K3. PutBusinessEvent

**功能描述：** 在 KV Store 中存储业务事件（键值对），并通知所有匹配该事件 `businessKey` 的已注册回调。事件被持久化后可通过 `GetBusinessEvent` 获取。

**签名：**
```cpp
virtual int32_t PutBusinessEvent(const BusinessEvent& event) = 0;
```

**API 级别：** System API

**权限：** 未指定（开放访问）。

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `event` | `const BusinessEvent&` | 输入 | 包含键和值的业务事件 | businessKey 非空；value 长度 <= MAX_BUSINESS_EVENT_VALUE_LEN |

**BusinessEvent 字段：**

| 字段 | 类型 | 说明 |
|---|---|---|
| businessKey | string | 事件键标识符 |
| businessValue | string | 事件值载荷（JSON 或字符串） |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 事件已存储，回调已通知 |
| 98566145 | DP_INVALID_PARAMETER | businessKey 为空或 value 过长 |
| 98566152 | DP_KV_ERR | KV Store 写入失败 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
// 发布一个用户登录业务事件
BusinessEvent event;
event.SetBusinessKey("event.user.login");
event.SetBusinessValue("{\"userId\": 100, \"timestamp\": 1700000000}");
int32_t ret = client.PutBusinessEvent(event);
```

---

### K4. GetBusinessEvent

**功能描述：** 从 KV Store 获取业务事件的最新值。输入的 `event` 必须指定 `businessKey`；成功时 `businessValue` 被填充。

**签名：**
```cpp
virtual int32_t GetBusinessEvent(BusinessEvent& event) = 0;
```

**API 级别：** System API

**权限：** 未指定（开放访问）。

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `event` | `BusinessEvent&` | 输入/输出 | 输入：指定要查找的 businessKey；输出：填充 value | 必须设置 businessKey |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 事件获取成功 |
| 98566146 | DP_NOT_FOUND | 未找到对应 businessKey 的事件 |
| 98566152 | DP_KV_ERR | KV 读取失败 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
// 查询用户登录事件的最新值
BusinessEvent event;
event.SetBusinessKey("event.user.login");
int32_t ret = client.GetBusinessEvent(event);
if (ret == DP_SUCCESS) {
    std::string value = event.GetBusinessValue();
}
```

---

## L. 服务信息（5 个 API）

ServiceInfo 在双层 KV 存储配置（本地存储 + 同步存储）中管理服务发布元数据。限于 `device_manager`。

### L1. PutServiceInfo

**功能描述：** 将服务信息记录发布到 KV Store。服务信息包含设备 UDID、用户 ID、服务拥有者令牌、服务 ID、发布状态、服务类型/名称、自定义数据和版本。同时存储在本地服务 KV Store 和同步服务 KV Store 中，以实现跨设备可用。

**签名：**
```cpp
virtual int32_t PutServiceInfo(const ServiceInfo& serviceInfo) = 0;
```

**API 级别：** System API

**权限：** `["device_manager"]`

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `serviceInfo` | `const ServiceInfo&` | 输入 | 要发布的服务信息记录 | 必须具有有效的 udid、userId、serviceId、serviceType、serviceName |

**ServiceInfo 字段：**

| 字段 | 类型 | 说明 |
|---|---|---|
| udid | string | 宿主设备 UDID |
| userId | int32_t | 用户 ID |
| displayId | int64_t | 显示标识符 |
| serviceOwnerTokenId | int32_t | 服务拥有者访问令牌 ID |
| serviceOwnerPkgName | string | 服务拥有者包名 |
| serviceRegisterTokenId | int32_t | 服务注册访问令牌 ID |
| serviceId | int64_t | 唯一服务标识符 |
| timeStamp | int64_t | 发布时间戳 |
| publishState | int8_t | 发布状态标志 |
| serviceType | string | 服务类型字符串 |
| serviceName | string | 服务名称字符串 |
| serviceDisplayName | string | 服务显示名称 |
| customData | string | 自定义数据载荷 |
| serviceCode | string | 服务代码标识符 |
| dataLen | uint32_t | 数据载荷长度 |
| extraData | string | 额外数据字段 |
| version | string | 服务版本 |
| description | string | 服务描述 |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 服务信息已发布 |
| 98566144 | DP_PERMISSION_DENIED | 调用者不是 device_manager |
| 98566145 | DP_INVALID_PARAMETER | 缺少必填字段 |
| 98566152 | DP_KV_ERR | KV 写入失败 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
// 发布一个打印机服务
ServiceInfo svcInfo;
svcInfo.SetUdid("device_udid_001");
svcInfo.SetUserId(100);
svcInfo.SetServiceId(1001);
svcInfo.SetServiceType("printer");
svcInfo.SetServiceName("com.hp.printer");
svcInfo.SetServiceDisplayName("HP Printer Service");
svcInfo.SetPublishState(1);
svcInfo.SetVersion("1.0.0");
int32_t ret = client.PutServiceInfo(svcInfo);
```

---

### L2. DeleteServiceInfo

**功能描述：** 删除匹配指定用户信息条件（UDID、userId，可选的 serviceId）的服务信息记录。匹配的记录会从本地和同步两个 KV Store 中移除。

**签名：**
```cpp
virtual int32_t DeleteServiceInfo(const UserInfo& userInfo) = 0;
```

**API 级别：** System API

**权限：** `["device_manager"]`

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `userInfo` | `const UserInfo&` | 输入 | 删除的过滤条件 | 必须具有有效的 udid 和 userId |

**UserInfo 字段：**

| 字段 | 类型 | 说明 |
|---|---|---|
| udid | string | 设备 UDID |
| userId | int32_t | 用户 ID |
| serviceId | int64_t | 可选的服务 ID 过滤（DEFAULT_SERVICE_ID = 匹配全部） |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 匹配的服务信息已删除 |
| 98566144 | DP_PERMISSION_DENIED | 调用者不是 device_manager |
| 98566146 | DP_NOT_FOUND | 未找到匹配记录 |
| 98566152 | DP_KV_ERR | KV 删除操作失败 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
// 删除指定用户在该设备上的所有服务信息
UserInfo userInfo;
userInfo.udid = "device_udid_001";
userInfo.userId = 100;
int32_t ret = client.DeleteServiceInfo(userInfo);
```

---

### L3. GetAllServiceInfoList

**功能描述：** 从本地 KV Store 获取所有已发布服务信息记录的完整列表。

**签名：**
```cpp
virtual int32_t GetAllServiceInfoList(std::vector<ServiceInfo>& serviceInfos) = 0;
```

**API 级别：** System API

**权限：** `["device_manager"]`

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `serviceInfos` | `std::vector<ServiceInfo>&` | 输出 | 所有服务信息记录 | 清空并重新填充（可能为空） |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 列表已获取（可能为空） |
| 98566144 | DP_PERMISSION_DENIED | 调用者不是 device_manager |
| 98566152 | DP_KV_ERR | KV 读取操作失败 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
std::vector<ServiceInfo> serviceInfos;
int32_t ret = client.GetAllServiceInfoList(serviceInfos);
if (ret == DP_SUCCESS) {
    for (auto& info : serviceInfos) {
        // 遍历处理每条服务信息
    }
}
```

---

### L4. GetServiceInfosByUserInfo

**功能描述：** 按用户信息条件（UDID、userId，可选的 serviceId）过滤查询服务信息记录。匹配的记录从同步 KV Store 中获取。

**签名：**
```cpp
virtual int32_t GetServiceInfosByUserInfo(const UserInfo& userInfo,
    std::vector<ServiceInfo>& serviceInfos) = 0;
```

**API 级别：** System API

**权限：** `["device_manager"]`

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `userInfo` | `const UserInfo&` | 输入 | 查询过滤条件 | 必须具有有效的 udid 和 userId |
| `serviceInfos` | `std::vector<ServiceInfo>&` | 输出 | 匹配的服务信息记录 | 成功时填充 |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 记录获取成功 |
| 98566144 | DP_PERMISSION_DENIED | 调用者不是 device_manager |
| 98566146 | DP_NOT_FOUND | 未找到匹配记录 |
| 98566152 | DP_KV_ERR | KV 读取失败 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
// 查询指定用户在该设备上的所有服务信息
UserInfo userInfo;
userInfo.udid = "device_udid_001";
userInfo.userId = 100;
std::vector<ServiceInfo> results;
int32_t ret = client.GetServiceInfosByUserInfo(userInfo, results);
```

---

### L5. SubscribeAllServiceInfo

**功能描述：** 订阅服务信息变更事件（添加/更新/删除）。每当服务信息记录被创建、修改或移除时，通过 IPC 调用监听器。由 `SubscribeServiceInfoManager` 管理。

**签名：**
```cpp
virtual int32_t SubscribeAllServiceInfo(int32_t saId, sptr<IRemoteObject> listener) = 0;
```

**API 级别：** System API

**权限：** 未指定（开放访问）。

**参数详情：**

| 参数名 | 类型 | 输入/输出 | 含义 | 约束条件 |
|---|---|---|---|---|
| `saId` | `int32_t` | 输入 | 订阅的 SA ID | 有效的正数 SA ID |
| `listener` | `sptr<IRemoteObject>` | 输入 | 实现 `IServiceInfoChangeCallback` 的 IPC 监听器代理 | 非空 |

**返回值：**

| 错误码 | 常量名 | 含义 |
|---|---|---|
| 0 | DP_SUCCESS | 订阅已注册 |
| 98566145 | DP_INVALID_PARAMETER | 监听器为空 |
| 98566147 | DP_ALREADY_EXISTS | 相同的 saId 已订阅 |
| 98566150 | DP_IPC_ERR | IPC 代理错误 |

**示例：**
```cpp
auto& client = DistributedDeviceProfileClient::GetInstance();
sptr<ServiceInfoChangeProxy> listener = new ServiceInfoChangeProxy(myRemoteObject);
int32_t ret = client.SubscribeAllServiceInfo(6002, listener->AsObject());
```

---

## 权限汇总

| API 分组 | 允许的调用者进程 |
|---|---|
| 信任与访问控制（A1-A8） | `device_manager`、`softbus_server`（A5 还允许 `iShare`） |
| 会话密钥（B1-B4） | `device_manager`、`softbus_server` |
| 设备画像（C1-C4） | C1,C3,C4：`device_manager`；C2：`all` |
| 服务画像（D1-D4） | `all` |
| 特性画像（E1-E4） | `all` |
| 画像变更订阅（F1-F6） | F1,F2：`all`；F3-F6：开放 |
| 画像同步（G1-G3） | G1：`all`；G2,G3：开放 |
| 信任设备管理（H1） | `device_manager` |
| 产品信息与图标（I1-I3） | `device_manager` |
| 本地服务信息（J1-J4） | `device_manager` |
| 业务事件（K1-K4） | 开放（不在 permission.json 中） |
| 服务信息（L1-L5） | L1-L4：`device_manager`；L5：开放 |

## 客户端 SDK 使用模式

所有外部 API 调用均通过 `DistributedDeviceProfileClient::GetInstance()` 执行，它封装了到 SA 6001 的 IPC 通信：

```cpp
#include "distributed_device_profile_client.h"
using namespace OHOS::DistributedDeviceProfile;

auto& client = DistributedDeviceProfileClient::GetInstance();
int32_t ret = client.PutDeviceProfile(...);

// 客户端自动处理：
// 1. SA 生命周期（通过 DeathRecipient 自动重连）
// 2. DP_SERVICE_STOPPED / DP_LOAD_SERVICE_ERR 时自动重试
// 3. IPC 序列化/反序列化
```

## 错误处理模式

```cpp
int32_t ret = client.SomeApi(...);
switch (ret) {
    case DP_SUCCESS:        // 0：操作成功
        break;
    case DP_PERMISSION_DENIED: // 检查调用进程权限
        break;
    case DP_NOT_FOUND:      // 资源不存在
        break;
    case DP_INVALID_PARAMETER: // 修正输入后重试
        break;
    default:                // DP_DB_ERR、DP_KV_ERR、DP_IPC_ERR 等
        break;
}
```

## 参见

- `docs/05-interfaces/02-internal-api.md` -- 内部管理器契约
- `docs/05-interfaces/03-dependency-api.md` -- 外部模块依赖
- `docs/04-workflows/` -- 各 API 分组的工作流文档
- `common/include/interfaces/i_distributed_device_profile.h` -- 接口源码
- `permission/permission.json` -- 权限配置
