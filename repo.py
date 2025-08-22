from abc import ABC, abstractmethod  # 用于抽象基类
import sqlite3
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
import re 

# --- 抽象基类（接口） ---
# 这些类定义了 UserRepository  AuthRepository 和 LogRepository应该做什么。
# 它们依赖的是抽象（方法签名），而不是具体的数据库实现细节。


class UserRepository(ABC):
    def __init__(self, db_connection_func):
        self.get_db_connection = db_connection_func

    @abstractmethod
    def add_user(self, username, email, password_hash, first_name, last_name, role):
        """添加用户"""
        pass

    @abstractmethod
    def find_user_by_id(self, user_id):
        """通过用户ID查找用户"""
        pass

    @abstractmethod
    def find_user_by_username_or_email(self, identifier):
        """通过用户名或邮箱查找用户"""
        pass

    @abstractmethod
    def find_password_hash_by_id(self, user_id):
        """通过用户ID查找密码哈希"""
        pass

    @abstractmethod
    def update_user_profile(self, user_id, first_name, last_name, role, is_active):
        """更新用户资料"""
        pass

    @abstractmethod
    def update_user_password_hash(self, user_id, new_password_hash):
        """更新用户密码哈希"""
        pass

    @abstractmethod
    def deactivate_user(self, user_id):
        """停用用户"""
        pass

    @abstractmethod
    def get_all_users_paginated(
        self, search_params, limit, offset, include_inactive=False
    ):
        """分页获取所有用户，可选是否包含停用用户"""
        pass

    @abstractmethod
    def get_users_count(self, search_params, include_inactive=False):
        """获取用户总数，可选是否包含停用用户"""
        pass


class AuthRepository(ABC):
    def __init__(self, db_connection_func):
        self.get_db_connection = db_connection_func

    @abstractmethod
    def add_refresh_token(self, user_id, token_hash, expires_at):
        """添加刷新令牌"""
        pass

    @abstractmethod
    def get_all_active_refresh_tokens(self):
        """获取所有有效的刷新令牌"""
        pass

    @abstractmethod
    def get_all_reset_tokens(self):
        """获取所有密码重置令牌"""
        pass

    @abstractmethod
    def revoke_refresh_token_by_id(self, token_id, revoked_at):
        """撤销指定刷新令牌"""
        pass

    @abstractmethod
    def delete_password_reset_tokens_for_user(self, user_id):
        """删除用户的所有密码重置令牌"""
        pass

    @abstractmethod
    def add_password_reset_token(self, user_id, token_hash, expires_at):
        """添加密码重置令牌"""
        pass

    @abstractmethod
    def delete_password_reset_token(self, token_hash):
        """删除指定的密码重置令牌"""
        pass

    @abstractmethod
    def delete_expired_refresh_tokens(self):
        """删除过期的刷新令牌"""
        pass

    @abstractmethod
    def delete_expired_reset_tokens(self):
        """删除过期的密码重置令牌"""
        pass


# --- 具体实现类 ---
# 这些类包含了针对数据库（SQLite）的具体查询语句。


class SQLiteUserRepository(UserRepository):
    def add_user(self, username, email, password_hash, first_name, last_name, role):
        conn = self.get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (username, email, password_hash, first_name, last_name, role) VALUES (?, ?, ?, ?, ?, ?)",
                (username, email, password_hash, first_name, last_name, role),
            )
            conn.commit()
            return cursor.lastrowid  # 返回新建用户的ID
        except sqlite3.IntegrityError:
            raise ValueError(
                "用户名或邮箱已存在"
            )  # 抛出更具体的错误
        finally:
            conn.close()

    def find_user_by_id(self, user_id):
        conn = self.get_db_connection()
        user = conn.execute(
            "SELECT id, username, email, first_name, last_name, role, is_active, created_at, updated_at FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        conn.close()
        return dict(user) if user else None

    def find_user_by_username_or_email(self, identifier):
        conn = self.get_db_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE (username = ? OR email = ?) AND is_active = 1",
            (identifier, identifier),
        ).fetchone()
        conn.close()
        return dict(user) if user else None

    def find_password_hash_by_id(self, user_id):
        conn = self.get_db_connection()
        user = conn.execute(
            "SELECT id, password_hash FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        conn.close()
        return dict(user) if user else None

    def update_user_profile(self, user_id, first_name, last_name, role, is_active):
        conn = self.get_db_connection()
        try:
            conn.execute(
                "UPDATE users SET first_name = ?, last_name = ?, role = ?, is_active = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (first_name, last_name, role, is_active, user_id),
            )
            conn.commit()
            return self.find_user_by_id(user_id)  # 返回更新后的用户数据
        except sqlite3.IntegrityError:
            raise ValueError(
                "用户名或邮箱已存在"
            )  # 理论上不该发生，但作为兜底
        finally:
            conn.close()

    def update_user_password_hash(self, user_id, new_password_hash):
        conn = self.get_db_connection()
        try:
            conn.execute(
                "UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (new_password_hash, user_id),
            )
            conn.commit()
            return True
        finally:
            conn.close()

    def deactivate_user(self, user_id):
        conn = self.get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET is_active = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (user_id,),
            )
            conn.commit()
            return cursor.rowcount > 0  # 如果有行被影响则返回 True
        finally:
            conn.close()

    def get_all_users_paginated(
        self, search_params, limit, offset, include_inactive=False
    ):
        conn = self.get_db_connection()

        where_clauses = []
        params = []

        # 搜索参数
        search_username = search_params.get("username")
        search_email = search_params.get("email")
        search_role = search_params.get("role")
        search_is_active = search_params.get("is_active")

        if search_username:
            where_clauses.append("username LIKE ?")
            params.append(f"%{search_username}%")
        if search_email:
            where_clauses.append("email LIKE ?")
            params.append(f"%{search_email}%")
        if search_role:
            where_clauses.append("role = ?")
            params.append(search_role)
        if search_is_active is not None:
            try:
                active_int = int(search_is_active)
                if active_int in [0, 1]:
                    where_clauses.append("is_active = ?")
                    params.append(active_int)
                else:
                    # 业务层应该先校验，这里作为兜底
                    raise ValueError("is_active 必须是 0 或 1。")
            except ValueError:
                raise ValueError("is_active 参数无效，必须是 0 或 1。")

        if not include_inactive:  # 默认只显示活跃用户
            where_clauses.append("is_active = 1")

        where_sql = ""
        if where_clauses:
            where_sql = " WHERE " + " AND ".join(where_clauses)

        sql_query = f"SELECT id, username, email, first_name, last_name, role, is_active, created_at, updated_at FROM users {where_sql} ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        users = conn.execute(sql_query, params).fetchall()
        conn.close()
        return [dict(user) for user in users]

    def get_users_count(self, search_params, include_inactive=False):
        conn = self.get_db_connection()

        where_clauses = []
        params = []

        # 搜索参数
        search_username = search_params.get("username")
        search_email = search_params.get("email")
        search_role = search_params.get("role")
        search_is_active = search_params.get("is_active")

        if search_username:
            where_clauses.append("username LIKE ?")
            params.append(f"%{search_username}%")
        if search_email:
            where_clauses.append("email LIKE ?")
            params.append(f"%{search_email}%")
        if search_role:
            where_clauses.append("role = ?")
            params.append(search_role)
        if search_is_active is not None:
            try:
                active_int = int(search_is_active)
                if active_int in [0, 1]:
                    where_clauses.append("is_active = ?")
                    params.append(active_int)
                else:
                    raise ValueError("is_active 必须是 0 或 1。")
            except ValueError:
                raise ValueError("is_active 参数无效，必须是 0 或 1。")

        if not include_inactive:
            where_clauses.append("is_active = 1")

        where_sql = ""
        if where_clauses:
            where_sql = " WHERE " + " AND ".join(where_clauses)

        count_sql = f"SELECT COUNT(*) FROM users {where_sql}"
        total_users = conn.execute(count_sql, params).fetchone()[0]
        conn.close()
        return total_users


class SQLiteAuthRepository(AuthRepository):
    def add_refresh_token(self, user_id, token_hash, expires_at):
        conn = self.get_db_connection()
        try:
            conn.execute(
                "INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
                (user_id, token_hash, expires_at.isoformat()),
            )
            conn.commit()
            return True
        finally:
            conn.close()

    def get_all_active_refresh_tokens(self):
        conn = self.get_db_connection()
        # 获取所有有效的刷新令牌（包含 user_id, 过期时间等）
        try:
            tokens = conn.execute(
                "SELECT id, user_id, token_hash, expires_at, revoked_at FROM refresh_tokens WHERE revoked_at IS NULL"
            ).fetchall()
            return [dict(token) for token in tokens]
        finally:
            conn.close()

    def get_all_reset_tokens(self):
        conn = self.get_db_connection()
        try:
            # 获取所有密码重置令牌
            tokens = conn.execute(
                "SELECT user_id, expires_at, token_hash FROM password_reset_tokens"
            ).fetchall()
            return [dict(token) for token in tokens]
        finally:
            conn.close()

    def revoke_refresh_token_by_id(self, token_id, revoked_at):
        conn = self.get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE refresh_tokens SET revoked_at = ? WHERE id = ?",
                (revoked_at.isoformat(), token_id),
            )
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()

    def revoke_user_refresh_tokens(self, user_id, revoked_at, exclude_token_id=None):
        # 撤销某个用户的所有刷新令牌（可选排除某个ID），常用于安全操作
        conn = self.get_db_connection()
        try:
            query = "UPDATE refresh_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL"
            params = [revoked_at.isoformat(), user_id]
            if exclude_token_id:
                query += " AND id != ?"
                params.append(exclude_token_id)
            cursor = conn.cursor()
            cursor.execute(query, params)
            conn.commit()
            return cursor.rowcount
        finally:
            conn.close()

    def delete_expired_refresh_tokens(self):
        conn = self.get_db_connection()
        try:
            cursor = conn.cursor()
            # 删除已过期的刷新令牌（无论是否撤销）
            cursor.execute(
                "DELETE FROM refresh_tokens WHERE expires_at < ?",
                (datetime.now(timezone.utc).isoformat(),),
            )
            conn.commit()
            return cursor.rowcount
        finally:
            conn.close()

    def delete_expired_reset_tokens(self):
        conn = self.get_db_connection()
        try:
            cursor = conn.cursor()
            # 删除已过期的密码重置令牌
            cursor.execute(
                "DELETE FROM password_reset_tokens WHERE expires_at < ?",
                (datetime.now(timezone.utc).isoformat(),),
            )
            conn.commit()
            return cursor.rowcount
        finally:
            conn.close()

    def delete_password_reset_tokens_for_user(self, user_id):
        conn = self.get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM password_reset_tokens WHERE user_id = ?", (user_id,)
            )
            conn.commit()
            return cursor.rowcount
        finally:
            conn.close()

    def add_password_reset_token(self, user_id, token_hash, expires_at):
        conn = self.get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
                (user_id, token_hash, expires_at.isoformat()),
            )
            conn.commit()
            return cursor.lastrowid
        finally:
            conn.close()

    def delete_password_reset_token(self, token_hash):
        conn = self.get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM password_reset_tokens WHERE token_hash = ?", (token_hash,)
            )
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()

def _to_china_time(utc_str):
    if not utc_str:
        return None
    dt = datetime.strptime(utc_str, "%Y-%m-%d %H:%M:%S")
    dt = dt.replace(tzinfo=ZoneInfo("UTC")).astimezone(ZoneInfo("Asia/Shanghai"))
    return dt.strftime("%Y-%m-%d %H:%M:%S")

# --- 新增：日志仓库接口及实现 ---
class LogRepository(ABC):
    def __init__(self, db_connection_func):
        self.get_db_connection = db_connection_func

    @abstractmethod
    def log_activity(self, user_id, action_type, action_details, ip_address, user_agent):
        """记录用户活动日志"""
        pass

    @abstractmethod
    def get_user_activity_logs(self, user_id, page=1, limit=10):
        """获取用户的活动日志（分页）"""
        pass


class SQLiteLogRepository(LogRepository):
    def log_activity(self, user_id, action_type, action_details, ip_address, user_agent):
        """写入日志到数据库"""
        conn = self.get_db_connection()
        try:
            conn.execute("""
                INSERT INTO activity_logs 
                (user_id, action_type, action_details, ip_address, user_agent) 
                VALUES (?, ?, ?, ?, ?)
            """, (user_id, action_type, action_details, ip_address, user_agent))
            conn.commit()
            return True
        finally:
            conn.close()
            
    
    def get_user_activity_logs(self, user_id, page=1, limit=10):
        """分页查询用户日志"""
        offset = (page - 1) * limit
        conn = self.get_db_connection()
        try:
            logs = conn.execute("""
                SELECT id, action_type, action_details, ip_address, user_agent, created_at 
                FROM activity_logs 
                WHERE user_id = ? 
                ORDER BY created_at DESC 
                LIMIT ? OFFSET ?
            """, (user_id, limit, offset)).fetchall()

            logs_dict = []
            for log in logs:
                d = dict(log)
                d["created_at"] = _to_china_time(d["created_at"])  # ✅ 转北京时间
                logs_dict.append(d)   
                         
            total = conn.execute(
                "SELECT COUNT(*) FROM activity_logs WHERE user_id = ?", 
                (user_id,)
            ).fetchone()[0]
            
            return {
                # "logs": [dict(log) for log in logs],
                "logs": logs_dict,
                "pagination": {
                    "total": total,
                    "page": page,
                    "limit": limit,
                    "total_pages": (total + limit - 1) // limit
                }
            }
        finally:
            conn.close()
            
    def get_all_activity_logs(self, search_params=None, page=1, limit=10):
        """获取所有日志，添加特殊字符过滤"""
        search_params = search_params or {}
        offset = (page - 1) * limit
        conn = self.get_db_connection()
        
        # 特殊字符过滤函数（移除SQL注入风险字符）
        def sanitize_input(value):
            if not value:
                return value
            # 移除可能导致SQL错误的特殊字符
            return re.sub(r'[#;\'\"\\]', '', str(value))
        
        try:
            where_clauses = []
            params = []

            # 时间范围筛选
            start_time = search_params.get("start_time")
            if start_time:
                sanitized_start = sanitize_input(start_time)
                where_clauses.append("al.created_at >= ?")
                params.append(sanitized_start)
                
            end_time = search_params.get("end_time")
            if end_time:
                sanitized_end = sanitize_input(end_time)
                where_clauses.append("al.created_at <= ?")
                params.append(sanitized_end)

            # 用户ID筛选
            user_id_filter = search_params.get("user_id")
            if user_id_filter:
                where_clauses.append("al.user_id = ?")
                params.append(user_id_filter)

            # 操作类型筛选
            action_type_filter = search_params.get("action_type")
            if action_type_filter:
                sanitized_action = sanitize_input(action_type_filter)
                where_clauses.append("al.action_type = ?")
                params.append(sanitized_action)

            # URL筛选
            url_filter = search_params.get("url")
            if url_filter:
                sanitized_url = sanitize_input(url_filter)
                where_clauses.append("al.action_details LIKE ?")
                params.append(f"%{sanitized_url}%")

            where_sql = " WHERE " + " AND ".join(where_clauses) if where_clauses else ""

            # 执行查询
            logs = conn.execute(f"""
                SELECT al.*, u.username 
                FROM activity_logs al
                JOIN users u ON al.user_id = u.id
                {where_sql}
                ORDER BY al.created_at DESC
                LIMIT ? OFFSET ?
            """, params + [limit, offset]).fetchall()
            
            logs_dict = []
            for log in logs:
                d = dict(log)
                # ✅ 转北京时间
                d["created_at"] = _to_china_time(d["created_at"])
                logs_dict.append(d)
                
            total = conn.execute(f"""
                SELECT COUNT(*) 
                FROM activity_logs al
                JOIN users u ON al.user_id = u.id
                {where_sql}
            """, params).fetchone()[0]

            return {
                # "logs": [dict(log) for log in logs],
                "logs": logs_dict,
                "pagination": {
                    "total": total,
                    "page": page,
                    "limit": limit,
                    "total_pages": (total + limit - 1) // limit
                }
            }
        except sqlite3.OperationalError as e:
            # 捕获SQL操作错误并提供更详细的信息
            raise RuntimeError(f"数据库查询错误: {str(e)}") from e
        finally:
            conn.close()
