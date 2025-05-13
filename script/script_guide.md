# 端口扫描器脚本开发手册

## 脚本基本规范
1. 每个脚本必须是独立的.py文件
2. 必须包含 `run(target, port, service)` 函数
3. 返回None表示不适用，返回字典表示检测结果

## 函数参数说明
```python
def run(target: str, port: int, service: str) -> Optional[dict]:
    """
    target: 目标IP地址
    port: 端口号 
    service: 服务识别结果(可能为None)
    """
```

## 返回结果格式
```python
{
    "summary": "简要描述",
    "details": [
        {
            "name": "检测项名称",
            "result": "检测结果",
            "risk": "风险等级(低/中/高/严重)", 
            "evidence": "证据/详情"
        }
    ],
    "metadata": {
        "reference": "参考链接",
        "solution": "修复建议"
    }
}
```

## 示例脚本
```python
# SSH服务检测示例
def run(target, port, service):
    if port != 22 or "ssh" not in (service or "").lower():
        return None
        
    results = {
        "summary": "SSH服务安全检测",
        "details": []
    }
    
    try:
        with socket.socket() as s:
            s.connect((target, port))
            banner = s.recv(1024).decode()
            
            if "OpenSSH" in banner and "7.0" in banner:
                results['details'].append({
                    "name": "OpenSSH 7.0漏洞",
                    "result": "存在CVE-2018-15473漏洞",
                    "risk": "高危",
                    "evidence": banner.strip()
                })
    except Exception as e:
        return {"error": str(e)}
        
    return results if results['details'] else None
```

## 开发建议
1. 每个脚本专注一个特定服务/漏洞
2. 设置合理的超时时间(建议3秒)
3. 做好异常处理
4. 不要包含破坏性操作
5. 风险等级说明：
   - 低：信息泄露等低风险问题
   - 中：可能被利用的配置问题  
   - 高：可直接导致入侵的漏洞
   - 严重：可远程代码执行的关键漏洞

## 脚本存放
1. 放在scripts目录下
2. 文件名应明确表示功能，如ftp_anon_login.py
3. 支持子目录分类

## 调试方法
1. 单独运行脚本测试：
```python
print(run("127.0.0.1", 22, "ssh"))
```
2. 通过扫描器测试：
```bash
python port_scanner.py 目标IP --script
