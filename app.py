from flask import Flask, request, jsonify, g
from flask_bcrypt import Bcrypt
import os
from dotenv import load_dotenv
from utils import jwt_required, admin_required ,log_url_access   
from flask_cors import CORS

# 导入数据库连接函数
from database import get_db_connection, init_db

# 导入具体的库实现
from repo import SQLiteUserRepository, SQLiteAuthRepository, SQLiteLogRepository

# 导入服务类
from services import UserService, AuthService, LogService

# 从 .env 文件加载环境变量
load_dotenv()

app = Flask(__name__)
CORS(app)  # 为 Flask 应用初始化 CORS，默认允许所有来源
bcrypt = Bcrypt(app)  # 为 Flask 应用初始化 Bcrypt，用于密码加密

# 从环境变量获取密钥
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
app.config["JWT_ALGORITHM"] = os.getenv(
    "JWT_ALGORITHM", "HS256"
)  # 如果未设置，默认使用 HS256 算法

# --- JWT令牌有效期配置 ---
app.config["ACCESS_TOKEN_EXPIRE_MINUTES"] = int(
    os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 15)
)  # Access Token 有效期较短，默认 15 分钟
app.config["REFRESH_TOKEN_EXPIRE_DAYS"] = int(
    os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", 7)
)  # Refresh Token 有效期为 7 天

# 加载邮件配置
app.config["SMTP_SERVER"] = os.getenv("SMTP_SERVER")
app.config["SMTP_PORT"] = int(os.getenv("SMTP_PORT", 587))
app.config["SMTP_USER"] = os.getenv("SMTP_USER")
app.config["SMTP_PASSWORD"] = os.getenv("SMTP_PASSWORD")
app.config["EMAIL_FROM"] = os.getenv("EMAIL_FROM")


# 确保密钥已经设置
if not app.config["SECRET_KEY"] or not app.config["JWT_SECRET_KEY"]:
    raise RuntimeError("SECRET_KEY 和 JWT_SECRET_KEY 必须在 .env 文件中设置")

# 应用启动时初始化数据库
init_db()

# --- 初始化数据库和服务（这里实现依赖注入） ---
user_repository = SQLiteUserRepository(get_db_connection)
auth_repository = SQLiteAuthRepository(get_db_connection)
log_repository = SQLiteLogRepository(get_db_connection)  # 日志仓库
log_service = LogService(log_repository)  # 初始化日志服务
user_service = UserService(user_repository, auth_repository, bcrypt)
auth_service = AuthService(
    user_repository,
    auth_repository,
    bcrypt,
    app.config["JWT_SECRET_KEY"],
    app.config["JWT_ALGORITHM"],
    app.config["ACCESS_TOKEN_EXPIRE_MINUTES"],
    app.config["REFRESH_TOKEN_EXPIRE_DAYS"],
    log_service,  # 传入日志服务
    # 新增邮件配置参数
    smtp_server=app.config["SMTP_SERVER"],
    smtp_port=app.config["SMTP_PORT"],
    smtp_user=app.config["SMTP_USER"],
    smtp_password=app.config["SMTP_PASSWORD"],
    email_from=app.config["EMAIL_FROM"],
)

# --- API 接口定义 ---


# 1. 用户注册接口
@app.route("/register", methods=["POST"])
def register_user_endpoint():
    data = request.get_json()
    try:
        # 调用 UserService 注册用户
        response_data = user_service.register_user(
            data.get("username"),
            data.get("email"),
            data.get("password"),
            data.get("first_name"),
            data.get("last_name"),
            data.get("role", "user"), # 默认角色为 'user'
        )
        return jsonify(response_data), 201
    except ValueError as e:  # Catch specific business logic errors for validation
        if "already exists" in str(e):
            return jsonify({"message": str(e)}), 409   # 冲突错误（用户名或邮箱重复）
        else:
            return (
                jsonify({"message": str(e)}),
                400,    # 验证错误，返回 400
            )  
    except Exception as e:
        return (
            jsonify(
                {
                    "message": "注册过程中发生了意外错误",
                    "error": str(e),
                }
            ),
            500,  # 服务器内部错误
        )


# 2. 用户登录
@app.route("/login", methods=["POST"])
def login_user_endpoint():
    data = request.get_json()
    ip_address = request.remote_addr
    user_agent = request.user_agent.string
    try:
        # 调用认证服务，验证用户名/邮箱和密码
        response_data = auth_service.login_user(
            data.get("username_or_email"), data.get("password"),ip_address=ip_address, user_agent=user_agent
        )
        return jsonify(response_data), 200  # 登录成功，返回 200 OK
    except ValueError as e:
        if "Invalid credentials" in str(e):  
            # 如果凭证无效，返回 401 
            return (
                jsonify({"message": str(e)}),
                401,
            )
        else:
            # 其他验证错误，返回 400 
            return (
                jsonify({"message": str(e)}),
                400,
            )
    except Exception as e:
        # 捕获未预料的异常，返回 500 
        return (
            jsonify(
                {
                    "message": "登录过程中发生了意外错误",
                    "error": str(e),
                }
            ),
            500,
        )

# 3. 刷新访问令牌
@app.route("/refresh", methods=["POST"])
def refresh_token_endpoint():
    data = request.get_json()
    try:
        # 从请求中获取IP和用户代理，传递给服务层
        ip_address = request.remote_addr
        user_agent = request.user_agent.string
        # 调用服务层，使用刷新令牌生成新的访问令牌
        response_data = auth_service.refresh_access_token(data.get("refresh_token"),
            ip_address=ip_address,
            user_agent=user_agent)
        return jsonify(response_data), 200
    except ValueError as e:
        if "Invalid or expired Refresh Token" in str(e):
            return (
                jsonify({"message": str(e)}),
                401,  # 无效或过期的刷新令牌 -> 返回未授权
            )
        elif "not found" in str(e):
            return jsonify({"message": str(e)}), 404  # 未找到资源
        else:
            return jsonify({"message": str(e)}), 400  # 其他刷新令牌问题 -> 错误请求
    except Exception as e:
        return (
            jsonify(
                {
                    "message": "刷新令牌过程中发生未知错误",
                    "error": str(e),
                }
            ),
            500,  # 内部服务器错误
        )


# 4. 用户登出
@app.route("/logout", methods=["POST"])
@jwt_required  # 需要有效的访问令牌才能识别用户
def logout_user_endpoint():
    data = request.get_json()
    ip_address = request.remote_addr
    user_agent = request.user_agent.string
    try:
        # g.user 由 jwt_required 装饰器自动注入，表示当前登录用户
        response_data = auth_service.logout_user(
            g.user["user_id"],            # 当前用户的ID
            data.get("refresh_token"),    # 需要作废的刷新令牌
            ip_address=ip_address, user_agent=user_agent
        )
        return jsonify(response_data), 200
    except ValueError as e:
        return jsonify({"message": str(e)}), 400  # 错误请求（例如刷新令牌无效）
    except Exception as e:
        return (
            jsonify(
                {
                    "message": "登出过程中发生未知错误",
                    "error": str(e),
                }
            ),
            500,  # 内部服务器错误
        )


# 5. 获取用户资料（可以是自己，也可以由管理员查看）
@app.route("/users/<int:user_id>", methods=["GET"])
@jwt_required
@log_url_access(log_service)  # 记录URL访问
def get_user_endpoint(user_id):
    # 权限控制：普通用户只能查看自己的资料；管理员可以查看任何用户资料
    if g.user["user_id"] != user_id and g.user["role"] != "admin":
        return (
            jsonify(
                {
                    "message": "禁止访问：你只能查看自己的资料，除非你是管理员。"
                }
            ),
            403,  # 没有权限 -> 禁止访问
        )

    try:
        user_data = user_service.get_user_profile(user_id)
        if user_data is None:
            return jsonify({"message": "用户不存在"}), 404
        return jsonify(user_data), 200  # 返回用户资料
    except Exception as e:
        return (
            jsonify(
                {
                    "message": "获取用户资料时发生未知错误",
                    "error": str(e),
                }
            ),
            500,  # 内部服务器错误
        )


# 6. 更新用户资料（可以是自己，也可以由管理员操作）
@app.route("/users/<int:user_id>", methods=["PUT"])
@jwt_required
@log_url_access(log_service)  # 记录URL访问
def update_user_endpoint(user_id):
    update_data = request.get_json()

    # 权限控制：普通用户只能更新自己的资料；管理员可以更新任何人的资料
    if g.user["user_id"] != user_id and g.user["role"] != "admin":
        return (
            jsonify(
                {
                    "message": "禁止访问：你只能更新自己的资料，除非你是管理员。"
                }
            ),
            403,
        )

    # 限制普通用户不能修改的字段
    forbidden_for_user_update = [
        "role",         # 不能修改用户角色
        "is_active",    # 不能修改启用状态
        "password_hash",# 不能直接修改密码哈希
        "username",     # 不能修改用户名
        "email",        # 不能修改邮箱
    ]
    if g.user["role"] != "admin":  # 如果不是管理员，则限制更新范围
        for key in forbidden_for_user_update:
            if key in update_data:
                return (
                    jsonify({"message": f"禁止修改字段: '{key}'"}),
                    403,
                )

    try:
        # 再次确认：如果不是管理员，就强制移除 update_data 里敏感字段
        if g.user["role"] != "admin":
            update_data.pop("role", None)
            update_data.pop("is_active", None)

        updated_user = user_service.update_user_profile(user_id, update_data)
        if updated_user is None:  # 用户不存在
            return jsonify({"message": "用户不存在"}), 404
        return jsonify(updated_user), 200
    except ValueError as e:
        if "not found" in str(e):
            return jsonify({"message": str(e)}), 404  # 用户未找到
        else:
            return jsonify({"message": str(e)}), 400  # 其他输入错误
    except Exception as e:
        return (
            jsonify(
                {
                    "message": "更新用户资料时发生未知错误",
                    "error": str(e),
                }
            ),
            500,
        )

# 7. 修改用户密码（仅限已登录用户）
@app.route("/users/<int:user_id>/password", methods=["PUT"])
@jwt_required
def change_password_endpoint(user_id):
    data = request.get_json()

    # 授权由 API 层处理
    if g.user["user_id"] != user_id:
        return (
            jsonify({"message": "禁止操作：您只能修改自己的密码。"}),
            403,
        )

    try:
        response_data = user_service.change_user_password(
            user_id, data.get("old_password"), data.get("new_password")
        )
        return jsonify(response_data), 200
    except ValueError as e:
        if "not found" in str(e):
            return jsonify({"message": str(e)}), 404
        elif "new password" in str(e) or "New password must" in str(e):
            return jsonify({"message": str(e)}), 400
        else:
            return (
                jsonify({"message": str(e)}),
                401,
            )  # 密码错误时返回 401 未授权
    except Exception as e:
        return (
            jsonify(
                {
                    "message": "修改密码时发生未知错误",
                    "error": str(e),
                }
            ),
            500,
        )


# 8. 用户软删除（仅限管理员）
@app.route("/users/<int:user_id>", methods=["DELETE"])
@admin_required  # 由 admin_required 装饰器保护（需要管理员访问令牌）
def soft_delete_user_endpoint(user_id):
    # 授权由 admin_required 装饰器处理
    # 防止管理员停用自己账号 —— 逻辑可以放在这里或保留在 service 层
    if g.user["user_id"] == user_id:
        return (
            jsonify(
                {
                    "message": "禁止操作：管理员不能通过该接口停用自己的账号。"
                }
            ),
            403,
        )

    try:
        response_data = user_service.deactivate_user(user_id)
        return jsonify(response_data), 200
    except ValueError as e:
        return jsonify({"message": str(e)}), 404  # 用户不存在
    except Exception as e:
        return (
            jsonify(
                {
                    "message": "停用用户时发生未知错误",
                    "error": str(e),
                }
            ),
            500,
        )

# 9. 获取所有用户（仅管理员可用，支持搜索/分页）
@app.route("/users", methods=["GET"])
@admin_required  # 受 Access Token 保护（通过 admin_required）
def get_all_users_endpoint():
    try:
        page = request.args.get("page", 1, type=int)   # 当前页码
        limit = request.args.get("limit", 10, type=int)  # 每页数量
        include_inactive = (
            request.args.get("include_inactive", "false").lower() == "true"
        )  # 是否包含已停用用户

        users_data = user_service.get_all_users(
            request.args, page, limit, include_inactive
        )
        return jsonify(users_data), 200
    except ValueError as e:
        return jsonify({"message": str(e)}), 400
    except Exception as e:
        return (
            jsonify(
                {
                    "message": "获取用户列表时发生未知错误",
                    "error": str(e),
                }
            ),
            500,
        )


# 10. 请求密码重置令牌
@app.route("/forgot-password", methods=["POST"])
def forgot_password_endpoint():
    data = request.get_json()
    try:
        response_data = auth_service.request_password_reset(data.get("email"))
        # 无论邮箱是否存在，都返回 200 OK，避免泄露邮箱信息
        return jsonify(response_data), 200
    except ValueError as e:
        return jsonify({"message": str(e)}), 400
    except Exception as e:
        return (
            jsonify(
                {
                    "message": "请求密码重置时发生未知错误",
                    "error": str(e),
                }
            ),
            500,
        )


# 11. 使用令牌重置密码
@app.route("/reset-password", methods=["POST"])
def reset_password_endpoint():
    data = request.get_json()
    try:
        response_data = auth_service.reset_password_with_token(
            data.get("token"), data.get("new_password")
        )
        return jsonify(response_data), 200
    except ValueError as e:
        return jsonify({"message": str(e)}), 400  # 令牌无效或已过期
    except Exception as e:
        return (
            jsonify(
                {
                    "message": "密码重置过程中发生未知错误",
                    "error": str(e),
                }
            ),
            500,
        )

# --- 新增：获取用户日志的接口 ---
@app.route("/users/<int:user_id>/logs", methods=["GET"])
@jwt_required
def get_user_logs_endpoint(user_id):
    # 权限控制
    if g.user["user_id"] != user_id and g.user["role"] != "admin":
        return jsonify({"message": "无权限查看日志"}), 403
    
    page = request.args.get("page", 1, type=int)
    limit = request.args.get("limit", 10, type=int)
    
    try:
        logs_data = log_service.get_user_logs(user_id, page, limit)
        return jsonify(logs_data), 200
    except ValueError as e:
        return jsonify({"message": str(e)}), 400
    except Exception as e:
        return jsonify({"message": "获取日志失败", "error": str(e)}), 500

@app.route("/logs", methods=["GET"])
@admin_required  # 仅管理员可访问
def get_all_logs_endpoint():
    """管理员查看所有日志，支持按时间范围筛选"""
    try:
        # 分页参数
        page = request.args.get("page", 1, type=int)
        limit = request.args.get("limit", 20, type=int)

        # 时间范围筛选参数（ISO格式，如：2023-10-01T00:00:00Z）
        search_params = {
            "start_time": request.args.get("start_time"),  # 开始时间
            "end_time": request.args.get("end_time"),      # 结束时间
            "user_id": request.args.get("user_id", type=int),
            "action_type": request.args.get("action_type"),
            "url": request.args.get("url")
        }

        # 调用服务层获取日志
        logs_data = log_service.get_all_logs(
            search_params=search_params,
            page=page,
            limit=limit
        )

        return jsonify(logs_data), 200
    except ValueError as e:
        return jsonify({"message": str(e)}), 400
    except Exception as e:
        return jsonify({
            "message": "获取日志失败",
            "error": str(e)
        }), 500
        
if __name__ == "__main__":
    app.run(debug=True)
