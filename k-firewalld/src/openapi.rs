//! OpenAPI 3.1 规范（REST API 文档），供 Scalar UI 渲染。
//!
//! 端点与 `api.rs` 的路由一一对应；文档 UI 见 `/docs`，规范本体见 `/openapi.json`。

use serde_json::{json, Value};

/// 构建 OpenAPI 3.1 文档。
pub fn openapi_doc() -> Value {
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "k-firewall REST API",
            "version": "0.1.0",
            "description": "k-firewall daemon 的运行时管理接口：状态、统计、封禁、Suricata 规则与预过滤状态、会话、系统信息。"
        },
        "servers": [
            { "url": "/", "description": "Unix socket 或 TCP（daemon.http_addr）" }
        ],
        "paths": {
            "/api/v1/auth/verify": {
                "get": {
                    "summary": "校验当前请求的认证状态（API Key 是否正确）",
                    "operationId": "authVerify",
                    "security": [{ "ApiKeyAuth": [] }],
                    "responses": {
                        "200": { "description": "OK", "content": { "application/json": { "schema": { "type": "object", "properties": { "valid": { "type": "boolean" }, "auth_enabled": { "type": "boolean" } } } } } },
                        "401": { "description": "未认证" }
                    }
                }
            },
            "/api/v1/operational/sessions": {
                "get": {
                    "summary": "查询连接跟踪会话（Conntrack；支持过滤 / 排序 / 分页）",
                    "operationId": "getSessions",
                    "security": [{ "ApiKeyAuth": [] }],
                    "parameters": [
                        { "name": "family", "in": "query", "required": false, "schema": { "type": "string", "enum": ["ipv4", "ipv6"] } },
                        { "name": "proto", "in": "query", "required": false, "schema": { "type": "string", "enum": ["tcp", "udp", "icmp", "icmp6"] } },
                        { "name": "src_ip", "in": "query", "required": false, "schema": { "type": "string" } },
                        { "name": "dst_ip", "in": "query", "required": false, "schema": { "type": "string" } },
                        { "name": "src_port", "in": "query", "required": false, "schema": { "type": "integer" } },
                        { "name": "dst_port", "in": "query", "required": false, "schema": { "type": "integer" } },
                        { "name": "src_cidr", "in": "query", "required": false, "schema": { "type": "string", "description": "源地址 CIDR（如 192.168.10.0/24，无前缀按 /32）" } },
                        { "name": "dst_cidr", "in": "query", "required": false, "schema": { "type": "string", "description": "目的地址 CIDR" } },
                        { "name": "app_proto", "in": "query", "required": false, "schema": { "type": "string" } },
                        { "name": "tls_sni", "in": "query", "required": false, "schema": { "type": "string" } },
                        { "name": "http_host", "in": "query", "required": false, "schema": { "type": "string" } },
                        { "name": "dns_query", "in": "query", "required": false, "schema": { "type": "string" } },
                        { "name": "state", "in": "query", "required": false, "schema": { "type": "string" } },
                        { "name": "q", "in": "query", "required": false, "schema": { "type": "string", "description": "全局关键字：同时匹配 SNI / Host / DNS / app_info / IP" } },
                        { "name": "sort", "in": "query", "required": false, "schema": { "type": "string", "enum": ["state", "packets", "bytes", "last_seen"], "default": "last_seen" } },
                        { "name": "page", "in": "query", "required": false, "schema": { "type": "integer", "default": 1 } },
                        { "name": "limit", "in": "query", "required": false, "schema": { "type": "integer", "default": 100 } }
                    ],
                    "responses": { "200": { "description": "OK", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SessionsOut" } } } } }
                },
                "delete": {
                    "summary": "按过滤器删除会话（空过滤器 = 清空全部）",
                    "operationId": "deleteSessions",
                    "security": [{ "ApiKeyAuth": [] }],
                    "requestBody": { "required": false, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SessionDeleteRequest" } } } },
                    "responses": { "200": { "description": "OK", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SessionsDeleteOut" } } } } }
                }
            },
            "/api/v1/operational/sessions/{session_id}": {
                "delete": {
                    "summary": "按 session_id 精确切断单个会话",
                    "operationId": "deleteSessionById",
                    "security": [{ "ApiKeyAuth": [] }],
                    "parameters": [{ "name": "session_id", "in": "path", "required": true, "schema": { "type": "string", "description": "会话稳定 ID（GET /sessions 返回的 session_id）" } }],
                    "responses": {
                        "200": { "description": "OK", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SessionsDeleteOut" } } } },
                        "404": { "description": "会话不存在" }
                    }
                }
            },
            "/api/v1/operational/events": {
                "get": {
                    "summary": "SSE 事件流（连接跟踪 / 封禁 / 规则变更通知）",
                    "operationId": "getOperationalEvents",
                    "security": [{ "ApiKeyAuth": [] }],
                    "responses": {
                        "200": { "description": "OK（text/event-stream，持续推送）", "content": { "text/event-stream": { "schema": { "type": "string" } } } }
                    }
                }
            },
            "/api/v1/operational/blocklist": {
                "get": {
                    "summary": "导出封禁列表",
                    "operationId": "getBlocklist",
                    "security": [{ "ApiKeyAuth": [] }],
                    "responses": { "200": { "description": "OK", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/BlocklistOut" } } } } }
                },
                "post": {
                    "summary": "封禁一个 IP（可选限时 + 原因）",
                    "operationId": "addBlocklistEntry",
                    "security": [{ "ApiKeyAuth": [] }],
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/BlockRequest" } } } },
                    "responses": { "200": { "description": "OK", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/BlocklistOut" } } } } }
                }
            },
            "/api/v1/operational/blocklist/{ip}": {
                "delete": {
                    "summary": "解除封禁",
                    "operationId": "deleteBlocklistEntry",
                    "security": [{ "ApiKeyAuth": [] }],
                    "parameters": [{ "name": "ip", "in": "path", "required": true, "schema": { "type": "string" } }],
                    "responses": { "200": { "description": "OK", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/BlocklistOut" } } } } }
                }
            },
            "/api/v1/operational/stats": {
                "get": {
                    "summary": "流量统计（packets/passed/dropped/blocked）",
                    "operationId": "getStatsV1",
                    "security": [{ "ApiKeyAuth": [] }],
                    "responses": { "200": { "description": "OK", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/StatsOut" } } } } }
                }
            },
            "/api/v1/operational/stats/interfaces": {
                "get": {
                    "summary": "每物理网卡 sysfs 收发统计",
                    "operationId": "getInterfaceStats",
                    "security": [{ "ApiKeyAuth": [] }],
                    "responses": { "200": { "description": "OK", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/InterfaceStatsOut" } } } } }
                }
            },
            "/api/v1/system/info": {
                "get": {
                    "summary": "系统信息（版本、接口、运行时长等）",
                    "operationId": "getSystemInfo",
                    "security": [{ "ApiKeyAuth": [] }],
                    "responses": { "200": { "description": "OK", "content": { "application/json": { "schema": { "type": "object", "properties": { "name": { "type": "string" }, "version": { "type": "string" }, "iface": { "type": "string" }, "uptime_secs": { "type": "integer", "format": "int64" }, "rule_count": { "type": "integer", "format": "int64" }, "blocked_count": { "type": "integer", "format": "int64" }, "auth_enabled": { "type": "boolean" }, "kernel": { "type": "string" } } } } } } }
                }
            },
            "/api/v1/system/interfaces": {
                "get": {
                    "summary": "逻辑接口信息（只读：角色/模式/NAT/地址/链路状态）",
                    "operationId": "getInterfaces",
                    "security": [{ "ApiKeyAuth": [] }],
                    "responses": { "200": { "description": "OK", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/InterfacesOut" } } } } }
                }
            },
            "/api/v1/system/config": {
                "get": {
                    "summary": "备份当前配置文件（text/plain YAML）",
                    "operationId": "getSystemConfig",
                    "security": [{ "ApiKeyAuth": [] }],
                    "responses": {
                        "200": { "description": "OK", "content": { "text/plain": { "schema": { "type": "string" } } } },
                        "404": { "description": "未跟踪配置路径" }
                    }
                },
                "post": {
                    "summary": "恢复配置文件（YAML 文本；校验通过后写入，需重启生效）",
                    "operationId": "postSystemConfig",
                    "security": [{ "ApiKeyAuth": [] }],
                    "requestBody": { "required": true, "content": { "text/plain": { "schema": { "type": "string" } } } },
                    "responses": {
                        "200": { "description": "OK", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ConfigRestoreOut" } } } },
                        "400": { "description": "配置非法" }
                    }
                }
            },
            "/api/v1/system/config/validate": {
                "post": {
                    "summary": "校验 YAML 配置（不落盘）",
                    "operationId": "postSystemConfigValidate",
                    "security": [{ "ApiKeyAuth": [] }],
                    "requestBody": { "required": true, "content": { "text/plain": { "schema": { "type": "string" } } } },
                    "responses": { "200": { "description": "OK", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ConfigValidateOut" } } } } }
                }
            },
            "/api/v1/system/config/diff": {
                "post": {
                    "summary": "与当前落盘配置做 YAML 顶层键语义差异",
                    "operationId": "postSystemConfigDiff",
                    "security": [{ "ApiKeyAuth": [] }],
                    "requestBody": { "required": true, "content": { "text/plain": { "schema": { "type": "string" } } } },
                    "responses": { "200": { "description": "OK", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ConfigDiffOut" } } } } }
                }
            },
            "/api/v1/system/reload": {
                "post": {
                    "summary": "重新加载磁盘配置（校验 + 热生效 Suricata 预过滤开关；XDP/接口变更需重启）",
                    "operationId": "postSystemReload",
                    "security": [{ "ApiKeyAuth": [] }],
                    "responses": {
                        "200": { "description": "OK", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ConfigRestoreOut" } } } },
                        "400": { "description": "配置非法" }
                    }
                }
            },
            "/api/v1/suricata/rules": {
                "get": {
                    "summary": "列出 Suricata 规则（分页 + 可选 ?q= 文本过滤；含 enabled/prefilter）",
                    "operationId": "listSuricataRules",
                    "security": [{ "ApiKeyAuth": [] }],
                    "parameters": [
                        { "name": "page", "in": "query", "required": false, "schema": { "type": "integer", "default": 1 } },
                        { "name": "limit", "in": "query", "required": false, "schema": { "type": "integer", "default": 100 } },
                        { "name": "q", "in": "query", "required": false, "schema": { "type": "string" } }
                    ],
                    "responses": { "200": { "description": "OK", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SuricataRuleListOut" } } } } }
                },
                "post": {
                    "summary": "新增一条 Suricata 规则（只填规则文本；解析 L4 头部生成 eBPF 预过滤，全文持久化）",
                    "operationId": "addSuricataRule",
                    "security": [{ "ApiKeyAuth": [] }],
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SuricataRuleRequest" } } } },
                    "responses": {
                        "200": { "description": "OK", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SuricataRuleOut" } } } },
                        "400": { "description": "规则非法或已存在", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Error" } } } }
                    }
                },
                "delete": {
                    "summary": "批量删除规则（body 传 ids 数组）",
                    "operationId": "deleteSuricataRules",
                    "security": [{ "ApiKeyAuth": [] }],
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SuricataRuleDeleteRequest" } } } },
                    "responses": { "200": { "description": "OK", "content": { "application/json": { "schema": { "type": "object", "properties": { "removed": { "type": "integer" }, "rules": { "type": "array", "items": { "$ref": "#/components/schemas/SuricataRuleOut" } } } } } } } }
                }
            },
            "/api/v1/suricata/prefilter/stats": {
                "get": {
                    "summary": "规则头预过滤状态与 4 张 LPM 表容量",
                    "operationId": "getSuricataPrefilterStats",
                    "security": [{ "ApiKeyAuth": [] }],
                    "responses": { "200": { "description": "OK", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SuricataPrefilterStats" } } } } }
                }
            },
            "/api/v1/suricata/rules/import": {
                "post": {
                    "summary": "批量导入 Suricata 规则（逐条处理，失败条目返回原因）",
                    "operationId": "importSuricataRules",
                    "security": [{ "ApiKeyAuth": [] }],
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SuricataRuleImportRequest" } } } },
                    "responses": { "200": { "description": "OK", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SuricataRuleImportOut" } } } } }
                }
            },
            "/api/v1/suricata/rules/export": {
                "get": {
                    "summary": "导出全部 Suricata 规则（text/plain，一行一条，可直接存为 .rules 文件）",
                    "operationId": "exportSuricataRules",
                    "security": [{ "ApiKeyAuth": [] }],
                    "responses": { "200": { "description": "OK", "content": { "text/plain": { "schema": { "type": "string" } } } } }
                }
            },
            "/api/v1/suricata/rules/{id}": {
                "delete": {
                    "summary": "按 id 删除一条 Suricata 规则（同步更新 eBPF 预过滤表）",
                    "operationId": "deleteSuricataRule",
                    "security": [{ "ApiKeyAuth": [] }],
                    "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "integer", "format": "int64" } }],
                    "responses": { "200": { "description": "OK", "content": { "application/json": { "schema": { "type": "array", "items": { "$ref": "#/components/schemas/SuricataRuleOut" } } } } } }
                },
                "patch": {
                    "summary": "启停规则（body 可只带 enabled）",
                    "operationId": "patchSuricataRule",
                    "security": [{ "ApiKeyAuth": [] }],
                    "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "integer", "format": "int64" } }],
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SuricataRulePatchRequest" } } } },
                    "responses": {
                        "200": { "description": "OK", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SuricataRuleOut" } } } },
                        "400": { "description": "规则不存在或请求非法" }
                    }
                },
                "put": {
                    "summary": "原地替换规则文本（重新解析头部并同步预过滤）",
                    "operationId": "updateSuricataRule",
                    "security": [{ "ApiKeyAuth": [] }],
                    "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "integer", "format": "int64" } }],
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SuricataRuleUpdateRequest" } } } },
                    "responses": {
                        "200": { "description": "OK", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SuricataRuleOut" } } } },
                        "400": { "description": "规则不存在或文本非法" }
                    }
                }
            },
            "/status": {
                "get": {
                    "summary": "运行状态",
                    "operationId": "getStatus",
                    "responses": { "200": { "description": "OK", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Status" } } } } }
                }
            },
            "/stats": {
                "get": {
                    "summary": "流量统计（packets/passed/dropped/blocked）",
                    "operationId": "getStats",
                    "responses": { "200": { "description": "OK", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/StatsOut" } } } } }
                }
            },
            "/blocked": {
                "get": {
                    "summary": "当前封禁的源 IP 列表",
                    "operationId": "getBlocked",
                    "responses": { "200": { "description": "OK", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/BlockedOut" } } } } }
                }
            },
            "/block": {
                "post": {
                    "summary": "封禁一个源 IP（可限时）",
                    "operationId": "block",
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/BlockRequest" } } } },
                    "responses": { "200": { "description": "OK", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Status" } } } } }
                }
            },
            "/unblock": {
                "post": {
                    "summary": "解除封禁",
                    "operationId": "unblock",
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/BlockRequest" } } } },
                    "responses": { "200": { "description": "OK", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Status" } } } } }
                }
            },
            "/metrics": {
                "get": {
                    "summary": "Prometheus 指标（text/plain；未认证）",
                    "operationId": "metrics",
                    "responses": { "200": { "description": "OK", "content": { "text/plain": { "schema": { "type": "string" } } } } }
                }
            }
        },
        "components": {
            "securitySchemes": {
                "ApiKeyAuth": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-API-Key",
                    "description": "Bearer token（daemon.api_keys 中配置的 API Key）。亦可使用 `Authorization: Bearer <key>`。"
                }
            },
            "schemas": {
                "Status": {
                    "type": "object",
                    "properties": {
                        "iface": { "type": "string", "description": "主接口" },
                        "attached": { "type": "boolean" },
                        "rule_count": { "type": "integer", "format": "int64" },
                        "blocked_count": { "type": "integer", "format": "int64" },
                        "uptime_secs": { "type": "integer", "format": "int64" }
                    }
                },
                "StatsOut": {
                    "type": "object",
                    "properties": {
                        "packets": { "type": "integer", "format": "int64" },
                        "passed": { "type": "integer", "format": "int64" },
                        "dropped": { "type": "integer", "format": "int64" },
                        "blocked": { "type": "integer", "format": "int64" }
                    }
                },
                "BlockedOut": {
                    "type": "object",
                    "properties": {
                        "entries": { "type": "array", "items": { "$ref": "#/components/schemas/BlockedEntryOut" } }
                    }
                },
                "BlockedEntryOut": {
                    "type": "object",
                    "properties": {
                        "ip": { "type": "string" },
                        "reason": { "type": "string" },
                        "added_unix": { "type": "integer", "format": "int64" },
                        "expire_unix": { "type": "integer", "format": "int64", "nullable": true }
                    }
                },
                "BlockRequest": {
                    "type": "object",
                    "required": ["ip"],
                    "properties": {
                        "ip": { "type": "string" },
                        "seconds": { "type": "integer", "format": "int64", "nullable": true, "description": "封禁秒数；空 = 永久" },
                        "reason": { "type": "string", "nullable": true }
                    }
                },
                "SessionOut": {
                    "type": "object",
                    "properties": {
                        "session_id": { "type": "string", "description": "会话稳定标识（五元组十六进制），供 DELETE /operational/sessions/{session_id} 精确切断" },
                        "family": { "type": "string", "enum": ["ipv4", "ipv6"] },
                        "proto": { "type": "string" },
                        "src_ip": { "type": "string" },
                        "src_port": { "type": "integer", "format": "int32" },
                        "dst_ip": { "type": "string" },
                        "dst_port": { "type": "integer", "format": "int32" },
                        "state": { "type": "string", "description": "SYN_SENT / ESTABLISHED / UDP / ICMP / ..." },
                        "is_nat": { "type": "boolean" },
                        "packets": { "type": "integer", "format": "int64" },
                        "pkts_orig": { "type": "integer", "format": "int64", "description": "原始方向（键方向）包数" },
                        "pkts_repl": { "type": "integer", "format": "int64", "description": "反向包数" },
                        "bytes_orig": { "type": "integer", "format": "int64", "description": "原始方向（键方向）字节数（整帧含 L2 头）" },
                        "bytes_repl": { "type": "integer", "format": "int64", "description": "反向字节数（整帧含 L2 头）" },
                        "last_seen_ns": { "type": "integer", "format": "int64", "description": "最近活跃时刻（CLOCK_MONOTONIC，ns）" },
                        "idle_secs": { "type": "integer", "format": "int64", "description": "距上次活跃的空闲秒数" },
                        "expire_in_secs": { "type": "integer", "format": "int64", "description": "距被超时回收的剩余秒数（未配置超时的状态为 null）", "nullable": true },
                        "last_seen_unix": { "type": "integer", "format": "int64", "description": "最近活跃的 Unix 时间戳（秒）" },
                        "app_proto": { "type": "string", "description": "Suricata 检测的应用层协议（http/tls/dns/ssh...）", "nullable": true },
                        "tls_fingerprint": { "type": "string", "description": "TLS 指纹（JA3/JA3S）", "nullable": true },
                        "tls_sni": { "type": "string", "description": "TLS SNI", "nullable": true },
                        "http_host": { "type": "string", "nullable": true },
                        "http_user_agent": { "type": "string", "nullable": true },
                        "dns_query": { "type": "string", "nullable": true },
                        "app_info": { "type": "string", "description": "Wireshark 风格会话概要（如 GET /path 200、TLSv1.3、DNS query）", "nullable": true }
                    }
                },
                "SessionsOut": {
                    "type": "object",
                    "properties": {
                        "total": { "type": "integer", "format": "int64" },
                        "entries": { "type": "array", "items": { "$ref": "#/components/schemas/SessionOut" } }
                    }
                },
                "BlocklistOut": {
                    "type": "object",
                    "properties": {
                        "entries": { "type": "array", "items": { "$ref": "#/components/schemas/BlocklistEntryOut" } }
                    }
                },
                "BlocklistEntryOut": {
                    "type": "object",
                    "properties": {
                        "ip": { "type": "string" },
                        "reason": { "type": "string" },
                        "added_unix": { "type": "integer", "format": "int64" },
                        "expire_unix": { "type": "integer", "format": "int64", "nullable": true }
                    }
                },
                "SuricataRuleOut": {
                    "type": "object",
                    "properties": {
                        "id": { "type": "integer", "format": "int64" },
                        "suricata_str": { "type": "string", "description": "原始 Suricata 规则文本" },
                        "enabled": { "type": "boolean", "description": "是否启用（false=临时关闭，不参与预过滤）" },
                        "prefilter": { "type": "boolean", "description": "是否成功下发为 eBPF 预过滤条目" },
                        "prefilter_note": { "type": "string", "nullable": true, "description": "预过滤下发失败原因（IPv6/变量/取反等）" }
                    }
                },
                "SuricataRuleRequest": {
                    "type": "object",
                    "required": ["rule"],
                    "properties": { "rule": { "type": "string" } }
                },
                "SuricataRulePatchRequest": {
                    "type": "object",
                    "description": "PATCH：仅启用/禁用。",
                    "properties": {
                        "enabled": { "type": "boolean", "nullable": true }
                    }
                },
                "SuricataRuleUpdateRequest": {
                    "type": "object",
                    "required": ["rule"],
                    "properties": { "rule": { "type": "string" } }
                },
                "SuricataRuleDeleteRequest": {
                    "type": "object",
                    "required": ["ids"],
                    "properties": { "ids": { "type": "array", "items": { "type": "integer", "format": "int64" } } }
                },
                "SuricataRuleImportRequest": {
                    "type": "object",
                    "required": ["rules"],
                    "properties": { "rules": { "type": "array", "items": { "type": "string" } } }
                },
                "SuricataRuleImportOut": {
                    "type": "object",
                    "properties": {
                        "total": { "type": "integer", "format": "int64" },
                        "added": { "type": "integer", "format": "int64" },
                        "failed": { "type": "integer", "format": "int64" },
                        "errors": { "type": "array", "items": { "type": "object", "properties": { "line": { "type": "integer", "format": "int64" }, "error": { "type": "string" } } } },
                        "rules": { "type": "array", "items": { "$ref": "#/components/schemas/SuricataRuleOut" } }
                    }
                },
                "SuricataRuleListOut": {
                    "type": "object",
                    "properties": {
                        "total": { "type": "integer", "format": "int64", "description": "分页前总条数" },
                        "entries": { "type": "array", "items": { "$ref": "#/components/schemas/SuricataRuleOut" } }
                    }
                },
                "SuricataPrefilterStats": {
                    "type": "object",
                    "properties": {
                        "enabled": { "type": "boolean" },
                        "tuples_total": { "type": "integer", "format": "int64" },
                        "dst": { "type": "integer", "format": "int64" },
                        "dst_any": { "type": "integer", "format": "int64" },
                        "src": { "type": "integer", "format": "int64" },
                        "src_any": { "type": "integer", "format": "int64" }
                    }
                },
                "SessionDeleteRequest": {
                    "type": "object",
                    "properties": {
                        "family": { "type": "string", "enum": ["ipv4", "ipv6"], "nullable": true },
                        "proto": { "type": "string", "enum": ["tcp", "udp", "icmp", "icmp6"], "nullable": true },
                        "src_ip": { "type": "string", "nullable": true },
                        "dst_ip": { "type": "string", "nullable": true },
                        "src_port": { "type": "integer", "format": "int32", "nullable": true },
                        "dst_port": { "type": "integer", "format": "int32", "nullable": true },
                        "src_cidr": { "type": "string", "nullable": true, "description": "源地址 CIDR（如 192.168.10.0/24，无前缀按 /32）" },
                        "dst_cidr": { "type": "string", "nullable": true, "description": "目的地址 CIDR" }
                    }
                },
                "SessionsDeleteOut": {
                    "type": "object",
                    "properties": { "removed": { "type": "integer", "format": "int64" } }
                },
                "InterfaceInfo": {
                    "type": "object",
                    "properties": {
                        "name": { "type": "string" },
                        "role": { "type": "string", "enum": ["wan", "lan", "inline"] },
                        "mode": { "type": "string", "enum": ["route", "transparent", "hybrid"] },
                        "nat": { "type": "string", "enum": ["none", "masquerade"] },
                        "address": { "type": "string", "nullable": true },
                        "netmask": { "type": "string", "nullable": true },
                        "ifindex": { "type": "integer", "format": "int64" },
                        "mac": { "type": "string", "nullable": true },
                        "carrier": { "type": "boolean" }
                    }
                },
                "InterfacesOut": {
                    "type": "object",
                    "properties": { "entries": { "type": "array", "items": { "$ref": "#/components/schemas/InterfaceInfo" } } }
                },
                "InterfaceStats": {
                    "type": "object",
                    "properties": {
                        "name": { "type": "string" },
                        "rx_packets": { "type": "integer", "format": "int64" },
                        "rx_bytes": { "type": "integer", "format": "int64" },
                        "rx_dropped": { "type": "integer", "format": "int64" },
                        "tx_packets": { "type": "integer", "format": "int64" },
                        "tx_bytes": { "type": "integer", "format": "int64" },
                        "tx_dropped": { "type": "integer", "format": "int64" }
                    }
                },
                "InterfaceStatsOut": {
                    "type": "object",
                    "properties": { "entries": { "type": "array", "items": { "$ref": "#/components/schemas/InterfaceStats" } } }
                },
                "ConfigRestoreOut": {
                    "type": "object",
                    "properties": {
                        "accepted": { "type": "boolean" },
                        "message": { "type": "string" }
                    }
                },
                "ConfigValidateOut": {
                    "type": "object",
                    "properties": {
                        "valid": { "type": "boolean" },
                        "errors": { "type": "array", "items": { "type": "string" } }
                    }
                },
                "ConfigDiffOut": {
                    "type": "object",
                    "properties": {
                        "valid": { "type": "boolean" },
                        "changed_keys": { "type": "array", "items": { "type": "string" } },
                        "summary": { "type": "array", "items": { "type": "string" } }
                    }
                },
                "Envelope": {
                    "type": "object",
                    "description": "统一响应信封（/api/v1 所有响应）：code=HTTP 状态码，message=状态说明，data=业务数据",
                    "properties": {
                        "code": { "type": "integer", "format": "int64" },
                        "message": { "type": "string" },
                        "data": {}
                    }
                },
                "Error": {
                    "type": "object",
                    "properties": { "error": { "type": "string" } }
                }
            }
        }
    })
}
