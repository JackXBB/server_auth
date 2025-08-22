项目概述

一个安全、可扩展的服务器用户身份验证机制，基于 Flask + SQLite 构建。
支持身份认证机制（短期访问令牌 + 长期刷新令牌）、密码管理和角色权限控制。

核心功能

👤 用户认证：注册、登录及基于令牌的访问控制

🔑 访问令牌 & 刷新令牌：安全短期访问 + 可撤销长期刷新令牌

🔒 角色权限：区分普通用户与管理员，限制敏感接口访问

🔐 密码管理：Bcrypt 加密、修改密码、忘记密码流程（邮箱发放重置令牌）

👥 用户管理：管理员查看所有用户、更新信息、软删除账户

⚙️ 搜索 & 分页：动态筛选和分页处理



项目架构

API 层 (app.py)：处理 HTTP 请求，调用服务层，无业务逻辑或数据库操作

服务层 (services.py)：核心业务逻辑，数据验证，协调数据库访问层

数据库访问层 (repositories.py)：提供统一接口

| 方法   | 接口                 | 描述                   |
| :--- | :----------------- | :----------------------- |
| POST | `/register`        | 注册用户                   |
| POST | `/login`           | 登录，返回访问令牌 & 刷新令牌 |
| POST | `/refresh`         | 使用刷新令牌获取新令牌       |
| POST | `/logout`          | 撤销刷新令牌，注销用户       |
| POST | `/forgot-password` | 发起密码重置               | 
| POST | `/reset-password`  | 使用重置令牌修改密码        |



| 方法     | 接口                          | 描述                         |
| :----- | :-------------------------- | :------------------------- |
| GET    | `/users`                    | **管理员专用**：分页获取所有用户，支持筛选    |
| GET    | `/logs`                    | **管理员专用**：分页获取所有用户活动日志，支持筛选    |
| GET    | `/users/{user_id}`          | 获取用户资料，普通用户仅能查看自己，管理员可查看所有 |
| GET    | `/users/{user_id}/logs`          | 获取用户活动日志，普通用户仅能查看自己，管理员可查看所有 |
| PUT    | `/users/{user_id}`          | 更新用户资料，普通用户仅能修改自己，管理员可修改所有 |
| PUT    | `/users/{user_id}/password` | 修改自身密码                     |
| DELETE | `/users/{user_id}`          | **管理员专用**：禁用账户（软删除）        |

命令行示例:
curl -X POST http://localhost:5000/reset-password \
  -H "Content-Type: application/json" \
  -d '{"token":"83AgInn_0_5VZZpFs-7jE7aSCNM3VAMC3P-XAcfhm6U","new_password":"abc123456"}'

## Acknowledgements
本项目基于 [User-Management-API](https://github.com/m-arifin-ilham/User-Management-API) 开发。
