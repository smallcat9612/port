def run(target, port, service):
    """示例漏洞检测脚本"""
    if port == 80 and "HTTP" in service:
        return {"vulnerability": "可能的HTTP服务漏洞", "confidence": "medium"}
    elif port == 22 and "SSH" in service:
        return {"vulnerability": "过期的SSH版本", "confidence": "high"}
    return None
