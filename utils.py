from flask import request, jsonify, g, current_app  
import jwt
from functools import wraps  # 用于装饰器实现
# --- JWT 身份验证装饰器 ---


def jwt_required(f):
    """装饰器：保护需要有效访问令牌（Access Token）的路由"""

    def wrapper(*args, **kwargs):
        token = None
        # 从请求头中获取 Authorization 信息
        if "Authorization" in request.headers:
            auth_header = request.headers["Authorization"]
            if auth_header.startswith("Bearer "):  # 约定格式：Bearer <token>
                token = auth_header.split(" ")[1]

        # 如果没有传递 Token
        if not token:
            return jsonify({"message": "缺少访问令牌！"}), 401

        try:
            # 解码 JWT
            data = jwt.decode(
                token,
                current_app.config["JWT_SECRET_KEY"],  # 密钥
                algorithms=[current_app.config["JWT_ALGORITHM"]],  # 算法，如 HS256
            )

            # 确认 token 类型必须是 access
            if data.get("type") != "access":
                return (
                    jsonify({"message": "令牌类型无效，需要 Access Token！"}),
                    401,
                )

            # 把用户信息存储到 Flask 全局对象 g 中，方便后续使用
            g.user = data
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "访问令牌已过期！"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "访问令牌无效！"}), 401
        except Exception as e:
            return jsonify({"message": f"令牌错误: {str(e)}"}), 401

        # 如果验证成功，继续执行原函数
        return f(*args, **kwargs)

    # 保持被装饰函数的原函数名（Flask 需要识别）
    wrapper.__name__ = f.__name__
    return wrapper


def admin_required(f):
    """装饰器：保护需要管理员角色的路由"""

    @jwt_required  # 先验证 JWT 是否有效
    def wrapper(*args, **kwargs):
        # 检查全局对象 g 中的用户角色是否为 admin
        if not hasattr(g, "user") or g.user.get("role") != "admin":
            return jsonify({"message": "需要管理员权限！"}), 403
        return f(*args, **kwargs)

    wrapper.__name__ = f.__name__
    return wrapper


# --- 新增：通用URL访问日志装饰器 ---
def log_url_access(log_service):
    """
    记录用户访问的URL路径
    自动记录已登录用户访问的所有接口URL
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # 1. 提取访问信息
            user_id = g.user.get('user_id') if hasattr(g, 'user') else None
            url_path = request.path  # 获取访问的URL路径（如 /users/123 或 /nodes）
            request_method = request.method  # 获取请求方法（GET/POST/PUT等）
            ip_address = request.remote_addr
            user_agent = request.user_agent.string

            # 2. 执行原接口逻辑
            response = f(*args, **kwargs)

            # 3. 记录日志（仅当用户已登录时）
            if user_id:
                try:
                    log_service.record_activity(
                        user_id=user_id,
                        action_type=f"access_{request_method.lower()}",  # 如 access_get/access_post
                        action_details=f"访问URL: {url_path}",  # 记录完整URL路径
                        ip_address=ip_address,
                        user_agent=user_agent
                    )
                except Exception as e:
                    current_app.logger.error(f"URL访问日志记录失败: {str(e)}")

            return response
        return wrapper
    return decorator
