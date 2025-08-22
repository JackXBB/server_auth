from repo import UserRepository, AuthRepository,LogRepository # 引入用户库和认证库接口
from datetime import datetime, timezone, timedelta
import re  # 用于正则表达式验证
import jwt
import secrets
from flask_bcrypt import Bcrypt  # 用于密码哈希加密

# --- 服务层 ---
# 这些类包含“业务逻辑”（要做什么）
# 它们依赖于抽象数据库（UserRepository, AuthRepository,LogRepository），而不是具体的数据库实现。


class UserService:
    def __init__(
        self,
        user_repo: UserRepository,
        auth_repo: AuthRepository,
        bcrypt_instance: Bcrypt,
    ):
        self.user_repo = user_repo
        self.auth_repo = auth_repo
        self.bcrypt = bcrypt_instance  # 通过依赖注入传入 bcrypt 实例

    def register_user(
        self, username, email, password, first_name, last_name, role="user"
    ):
        """注册新用户，包含基本验证"""
        # 校验必填字段
        if not username or not email or not password:
            raise ValueError("用户名、邮箱和密码是必填项")

        # 用户名规则：3-20 个字母或数字
        if not (3 <= len(username) <= 20) or not username.isalnum():
            raise ValueError("用户名必须是 3-20 位字母或数字组合")

        # 邮箱格式校验
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            raise ValueError("邮箱格式无效")

        # 密码规则：至少 8 位，包含字母和数字
        if not (
            len(password) >= 8
            and any(char.isdigit() for char in password)
            and any(char.isalpha() for char in password)
        ):
            raise ValueError("密码必须至少 8 位，且包含字母和数字")

        # 角色限制：只能是 user 或 admin
        if role not in ["user", "admin"]:
            raise ValueError("角色无效")

        # 生成密码哈希
        password_hash = self.bcrypt.generate_password_hash(password).decode("utf-8")

        try:
            # 保存到数据库
            user_id = self.user_repo.add_user(
                username, email, password_hash, first_name, last_name, role
            )
            return {"message": "用户注册成功", "user_id": user_id}
        except ValueError as e:
            raise ValueError(str(e))  # 抛出给 API 层处理

    def get_user_profile(self, user_id):
        """获取用户资料（去掉敏感信息）"""
        user = self.user_repo.find_user_by_id(user_id)
        if user:
            user.pop("password_hash", None)  # 去掉密码哈希
            return user
        return None

    def update_user_profile(self, target_user_id, update_data):
        """更新用户资料"""
        user = self.user_repo.find_user_by_id(target_user_id)
        if not user:
            raise ValueError("用户未找到")

        # 校验角色
        if "role" in update_data and update_data["role"] not in ["user", "admin"]:
            raise ValueError("角色无效")

        # 校验名字
        if "first_name" in update_data and not isinstance(update_data["first_name"], str):
            raise ValueError("姓必须是字符串")
        if "last_name" in update_data and not isinstance(update_data["last_name"], str):
            raise ValueError("名必须是字符串")

        # 如果没传新值，就用原有的
        first_name = update_data.get("first_name", user["first_name"])
        last_name = update_data.get("last_name", user["last_name"])
        role = update_data.get("role", user["role"])
        is_active = update_data.get("is_active", user["is_active"])

        # 更新用户信息
        updated_user = self.user_repo.update_user_profile(
            target_user_id, first_name, last_name, role, is_active
        )
        if updated_user:
            updated_user.pop("password_hash", None)  # 移除敏感信息
        return updated_user

    def change_user_password(self, user_id, old_password, new_password):
        """修改用户密码"""
        if not old_password or not new_password:
            raise ValueError("旧密码和新密码不能为空")

        # 校验新密码
        if not (
            len(new_password) >= 8
            and any(char.isdigit() for char in new_password)
            and any(char.isalpha() for char in new_password)
        ):
            raise ValueError("新密码必须至少 8 位，且包含字母和数字")

        # 查询旧密码哈希
        user = self.user_repo.find_password_hash_by_id(user_id)
        if not user:
            raise ValueError("用户未找到")

        # 验证旧密码是否正确
        if not self.bcrypt.check_password_hash(user["password_hash"], old_password):
            raise ValueError("旧密码错误")

        # 生成新密码哈希并更新
        hashed_new_password = self.bcrypt.generate_password_hash(new_password).decode("utf-8")
        self.user_repo.update_user_password_hash(user_id, hashed_new_password)
        return {"message": "密码修改成功"}

    def deactivate_user(self, user_id):
        """删除用户（软删除）"""
        user_exists = self.user_repo.find_user_by_id(user_id)
        if not user_exists:
            raise ValueError("用户未找到")

        success = self.user_repo.deactivate_user(user_id)
        if not success:
            raise RuntimeError("删除用户失败")

        # 停用用户时，撤销其所有刷新令牌
        self.auth_repo.revoke_user_refresh_tokens(user_id, datetime.now(timezone.utc))
        return {"message": "用户已删除"}

    def get_all_users(self, search_params, page, limit, include_inactive=False):
        """获取用户列表，带分页和筛选"""
        if page < 1:
            raise ValueError("页码必须 >= 1")
        if limit < 1:
            raise ValueError("每页数量必须 >= 1")

        # 校验 is_active 参数
        search_is_active = search_params.get("is_active")
        if search_is_active is not None:
            try:
                active_int = int(search_is_active)
                if active_int not in [0, 1]:
                    raise ValueError("'is_active' 必须是 0 或 1")
            except ValueError:
                raise ValueError("'is_active' 必须是数字 0 或 1")

        offset = (page - 1) * limit

        # 获取用户数据
        users = self.user_repo.get_all_users_paginated(
            search_params, limit, offset, include_inactive
        )
        total_users = self.user_repo.get_users_count(search_params, include_inactive)

        total_pages = (total_users + limit - 1) // limit  # 计算总页数

        # 移除敏感字段
        for user in users:
            user.pop("password_hash", None)

        return {
            "data": users,
            "pagination": {
                "total_items": total_users,
                "total_pages": total_pages,
                "current_page": page,
                "items_per_page": limit,
                "next_page": page + 1 if page < total_pages else None,
                "prev_page": page - 1 if page > 1 else None,
            },
        }

class AuthService:
    def __init__(
        self,
        user_repo: UserRepository,
        auth_repo: AuthRepository,
        bcrypt_instance: Bcrypt,
        jwt_secret_key: str,
        jwt_algorithm: str,
        access_token_expire_minutes: int,
        refresh_token_expire_days: int,
        log_service,
    ):
        # 依赖注入：用户仓库、认证仓库、Bcrypt 实例，以及 JWT 相关配置
        self.user_repo = user_repo
        self.auth_repo = auth_repo
        self.bcrypt = bcrypt_instance
        self.jwt_secret_key = jwt_secret_key
        self.jwt_algorithm = jwt_algorithm
        self.access_token_expire_minutes = access_token_expire_minutes
        self.refresh_token_expire_days = refresh_token_expire_days
        self.log_service = log_service  # 初始化日志服务

    def login_user(self, username_or_email, password, ip_address, user_agent):
        """用户登录：验证用户名/邮箱 + 密码，返回 access_token 和 refresh_token"""
        if not username_or_email or not password:
            raise ValueError("必须提供用户名/邮箱和密码")

        # 根据用户名或邮箱查找用户
        user = self.user_repo.find_user_by_username_or_email(username_or_email)
        if not user or not self.bcrypt.check_password_hash(
            user["password_hash"], password
        ):
            raise ValueError("账号不存在、密码错误或账号已被禁用")

        # 生成新的 access_token 和 refresh_token
        access_token = self._generate_access_token(
            user["id"], user["username"], user["role"]
        )
        refresh_token = self._generate_refresh_token(user["id"])
        
        # 记录登录日志
        self.log_service.record_activity(
            user_id=user["id"],
            action_type="login",
            action_details=f"用户 {user['username']} 登录成功",
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        return {
            "message": "登录成功",
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user_id": user["id"],
            "role": user["role"],
        }

    def _generate_access_token(self, user_id, username, role):
        """生成短期有效的 Access Token"""
        payload = {
            "user_id": user_id,
            "username": username,
            "role": role,
            "type": "access",
            "exp": datetime.now(timezone.utc)
            + timedelta(minutes=self.access_token_expire_minutes),  # 过期时间
        }
        return jwt.encode(payload, self.jwt_secret_key, algorithm=self.jwt_algorithm)

    def _generate_refresh_token(self, user_id):
        """生成长期有效的 Refresh Token（存入数据库，做哈希存储）"""
        refresh_token = secrets.token_urlsafe(64)  # 生成随机字符串
        refresh_token_hash = self.bcrypt.generate_password_hash(refresh_token).decode(
            "utf-8"
        )
        expires_at = datetime.now(timezone.utc) + timedelta(
            days=self.refresh_token_expire_days
        )

        self.auth_repo.add_refresh_token(user_id, refresh_token_hash, expires_at)
        return refresh_token

    def refresh_access_token(self, refresh_token_plain: str, ip_address: str, user_agent: str):
        """刷新 Access Token：校验 refresh_token 是否有效，生成新的一对 token"""
        if not refresh_token_plain:
            raise ValueError("缺少刷新令牌 Refresh Token")

        # 1. 遍历数据库中的 refresh_token（存的是哈希值），逐个验证
        all_active_refresh_tokens = self.auth_repo.get_all_active_refresh_tokens()
        valid_token_record = None
        for record in all_active_refresh_tokens:
            try:
                if self.bcrypt.check_password_hash(
                    record["token_hash"], refresh_token_plain
                ):
                    valid_token_record = record
                    break
            except ValueError:
                continue

        if not valid_token_record:
            raise ValueError("刷新令牌无效或已过期")

        # 2. 校验 token 是否过期/撤销
        if datetime.now(timezone.utc) > datetime.fromisoformat(
            valid_token_record["expires_at"]
        ):
            self.auth_repo.revoke_refresh_token_by_id(
                valid_token_record["id"], datetime.now(timezone.utc)
            )
            raise ValueError("刷新令牌已过期")

        if valid_token_record["revoked_at"] is not None:
            raise ValueError("刷新令牌已被撤销")

        # 3. 校验关联的用户是否存在且有效
        user = self.user_repo.find_user_by_id(valid_token_record["user_id"])
        if user is None or user["is_active"] == 0:
            self.auth_repo.revoke_refresh_token_by_id(
                valid_token_record["id"], datetime.now(timezone.utc)
            )
            raise ValueError("用户不存在或已被禁用")

        # 4. 撤销旧的 refresh_token，生成新的 access + refresh
        self.auth_repo.revoke_refresh_token_by_id(
            valid_token_record["id"], datetime.now(timezone.utc)
        )

        new_access_token = self._generate_access_token(
            user["id"], user["username"], user["role"]
        )
        new_refresh_token = self._generate_refresh_token(user["id"])
        
        # 5. 记录令牌刷新日志
        self.log_service.record_activity(
            user_id=user["id"],
            action_type="token_refresh",
            action_details="访问令牌已通过刷新令牌更新",
            ip_address=ip_address or "unknown",
            user_agent=user_agent or "unknown"
        )
        
        return {
            "message": "刷新成功",
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
        }

    def logout_user(self, user_id, refresh_token_plain: str, ip_address, user_agent):
        """登出：撤销用户的 refresh_token"""
        if not refresh_token_plain:
            raise ValueError("登出需要提供刷新令牌 Refresh Token")

        user_refresh_tokens = self.auth_repo.get_all_active_refresh_tokens()

        token_found_and_matched = False
        for record in user_refresh_tokens:
            if record["user_id"] == user_id:  # 必须匹配当前用户
                try:
                    if self.bcrypt.check_password_hash(
                        record["token_hash"], refresh_token_plain
                    ):
                        self.auth_repo.revoke_refresh_token_by_id(
                            record["id"], datetime.now(timezone.utc)
                        )
                        token_found_and_matched = True
                        break
                except ValueError:
                    continue

        if not token_found_and_matched:
            raise ValueError("刷新令牌不存在或已被撤销")

        # 记录登出日志
        self.log_service.record_activity(
            user_id=user_id,
            action_type="logout",
            action_details=f"用户 {user['username']} 登出成功",
            ip_address=ip_address,
            user_agent=user_agent
        )
    
        return {"message": "登出成功，刷新令牌已撤销"}

    def request_password_reset(self, email: str):
        """用户请求重置密码：生成一次性 token（有效期 1 小时），模拟发送到邮箱"""
        if not email:
            raise ValueError("必须提供邮箱")

        user = self.user_repo.find_user_by_username_or_email(email)

        if user:
            user_id = user["id"]
            username = user["username"]
            email = user["email"]

            # 删除该用户以前的 reset_token，避免多个生效
            self.auth_repo.delete_password_reset_tokens_for_user(user_id)

            token = secrets.token_urlsafe(32)  # 生成随机 token
            hashed_token = self.bcrypt.generate_password_hash(token).decode("utf-8")
            expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

            self.auth_repo.add_password_reset_token(user_id, hashed_token, expires_at)

            # 模拟发送邮件
            print(f"收件人: {email}")
            print(f"\n--- {username} 的密码重置请求 ---")
            print(f"使用此 token 重置密码: {token}")
            print(f"有效期至: {expires_at.isoformat()} UTC\n")

        # 即使用户不存在，也返回同样的提示（防止暴力猜邮箱）
        return {"message": "如果该邮箱存在，将会收到密码重置邮件"}

    def reset_password_with_token(self, token_plain: str, new_password: str):
        """用户通过 token 重置密码"""
        if not token_plain or not new_password:
            raise ValueError("必须提供 token 和新密码")

        # 验证新密码规则
        if not (
            len(new_password) >= 8
            and any(char.isdigit() for char in new_password)
            and any(char.isalpha() for char in new_password)
        ):
            raise ValueError("新密码必须至少 8 位，且包含字母和数字")

        # 删除已过期 token，优化验证过程
        self.auth_repo.delete_expired_reset_tokens()
        active_reset_tokens = self.auth_repo.get_all_reset_tokens()

        valid_token_record = None
        for record in active_reset_tokens:
            if datetime.now(timezone.utc) <= datetime.fromisoformat(
                record["expires_at"]
            ):
                try:
                    if self.bcrypt.check_password_hash(
                        record["token_hash"], token_plain
                    ):
                        valid_token_record = record
                        break
                except ValueError:
                    continue

        if not valid_token_record:
            raise ValueError("token 无效或已过期")

        # 更新密码并删除 token
        user_id_from_token = valid_token_record["user_id"]
        hashed_new_password = self.bcrypt.generate_password_hash(new_password).decode(
            "utf-8"
        )

        self.user_repo.update_user_password_hash(user_id_from_token, hashed_new_password)
        self.auth_repo.delete_password_reset_token(valid_token_record["token_hash"])

        return {"message": "密码已成功重置"}

# --- 新增：日志服务类 ---
class LogService:
    def __init__(self, log_repo: LogRepository):
        self.log_repo = log_repo

    def record_activity(self, user_id, action_type, action_details, ip_address, user_agent):
        """记录用户活动日志"""
        try:
            self.log_repo.log_activity(
                user_id=user_id,
                action_type=action_type,
                action_details=action_details,
                ip_address=ip_address,
                user_agent=user_agent
            )
            return True
        except Exception as e:
            print(f"日志记录失败: {str(e)}")  # 日志失败不影响主流程
            return False

    def get_user_logs(self, user_id, page=1, limit=10):
        """获取用户的活动日志（分页）"""
        if page < 1 or limit < 1:
            raise ValueError("页码和每页数量必须为正数")
        return self.log_repo.get_user_activity_logs(user_id, page, limit)
    
    def get_all_logs(self, search_params=None, page=1, limit=10):
        """管理员获取所有日志，支持时间范围筛选（验证时间格式）"""
        if page < 1 or limit < 1:
            raise ValueError("页码和每页数量必须为正数")
        
        # 验证时间格式（支持ISO格式，如：2023-10-01T00:00:00Z）
        search_params = search_params or {}
        if "start_time" in search_params or "end_time" in search_params:
            time_format = "%Y-%m-%dT%H:%M:%SZ"
            for time_key in ["start_time", "end_time"]:
                if time_key in search_params and search_params[time_key]:
                    try:
                        # 验证时间格式并转换为UTC时间字符串
                        datetime.strptime(search_params[time_key], time_format)
                    except ValueError:
                        raise ValueError(f"时间格式无效，应为ISO格式（例如：2023-10-01T00:00:00Z）")
        
        return self.log_repo.get_all_activity_logs(
            search_params=search_params,
            page=page,
            limit=limit
        ) 