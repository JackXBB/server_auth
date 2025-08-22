import sqlite3
import bcrypt

DATABASE_NAME = "users.db"


# 说明：该函数仅用于创建初始管理员账户时对密码进行加密。
# 普通用户密码的哈希处理，会通过 app.py 或 services.py 中的 Bcrypt 实例完成。
def _hash_password_for_initial_admin(password):
    """使用 bcrypt 对密码进行哈希，加密初始管理员密码"""
    
    # 1. 使用 bcrypt.gensalt() 生成随机盐值
    # 2. 使用 bcrypt.hashpw() 将明文密码和盐值进行哈希
    # 3. 使用 decode('utf-8') 将字节类型结果转换为字符串，方便存储
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def get_db_connection():
    """建立与 SQLite 数据库的连接"""
    
    conn = sqlite3.connect(DATABASE_NAME)
    
    # 设置 row_factory，使查询结果可以像字典一样通过列名访问
    conn.row_factory = sqlite3.Row
    
    return conn

def init_db():
    """初始化数据库结构（如果不存在则创建）"""
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 用户表
    # 存储用户信息，包括用户名、邮箱、密码哈希、姓名、角色、是否激活、创建和更新时间
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            first_name TEXT,
            last_name TEXT,
            role TEXT DEFAULT 'user',
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    
    # 密码重置令牌表
    # 存储用户密码重置的令牌哈希及过期时间
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,  -- 存储令牌哈希
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
        """
    )
    
    # 刷新令牌表
    # 存储用户的刷新令牌哈希、过期时间、创建时间及撤销时间
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            revoked_at TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
        """
    )
    
    # 用户活动日志表（记录URL访问等操作）
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            action_type TEXT NOT NULL,  -- 如 access_get, access_post, login, logout
            action_details TEXT,        -- 如 "访问URL: /users/123"
            ip_address TEXT,            -- 客户端IP
            user_agent TEXT,            -- 客户端信息
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    """)
    conn.commit()
    conn.close()
    print("数据库已初始化/存在")


def insert_initial_admin():
    """如果不存在管理员用户，则创建初始管理员账号"""
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # 检查是否已经存在管理员用户
        cursor.execute("SELECT id FROM users WHERE role = 'admin' LIMIT 1")
        
        if cursor.fetchone() is None:
            admin_password = "admin_password_123"  # <<< 注意：创建后请立即修改默认密码
            
            # 对默认管理员密码进行哈希处理
            hashed_admin_password = _hash_password_for_initial_admin(admin_password)

            # 创建初始管理员用户
            cursor.execute(
                "INSERT INTO users (username, email, password_hash, first_name, last_name, role, is_active) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    "admin",               # 用户名
                    "admin@example.com",   # 邮箱
                    hashed_admin_password, # 密码哈希
                    "Admin",               # 名
                    "User",                # 姓
                    "admin",               # 角色
                    1,                     # 激活状态
                ),
            )
            conn.commit()
            print(
                f"初始管理员用户已创建: username='admin', password='{admin_password}'"
            )
        else:
            print("管理员用户已存在，跳过初始管理员创建。")
    
    except sqlite3.IntegrityError as e:
        # 捕获可能的唯一约束冲突（如用户名或邮箱重复）
        print(f"创建初始管理员出错（可能是用户名/邮箱重复）：{e}")
        conn.rollback()
    
    finally:
        conn.close()

if __name__ == "__main__":
    init_db()
    insert_initial_admin()
