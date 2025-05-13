def run(target, port, service):
    """FTP服务检测脚本"""
    import socket
    import re
    
    # 只处理FTP服务
    if "ftp" not in service.lower() and port != 21:
        return None
        
    results = {
        "service": "FTP",
        "checks": []
    }
    
    try:
        # 连接FTP服务获取banner
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect((target, port))
            banner = s.recv(1024).decode('utf-8', errors='ignore')
            results['banner'] = banner.strip()
            
            # 检查匿名登录
            s.send(b"USER anonymous\r\n")
            response = s.recv(1024).decode()
            if "331" in response:  # 331表示需要密码
                results['checks'].append({
                    'name': '匿名登录',
                    'result': '可能允许',
                    'risk': '高危'
                })
                
            # 检查版本漏洞
            if "vsFTPd" in banner:
                if re.search(r"vsFTPd\s*1\.", banner):
                    results['checks'].append({
                        'name': 'vsFTPd 1.x版本',
                        'result': '存在后门漏洞',
                        'risk': '严重'
                    })
                    
            # 检查其他常见漏洞
            if "ProFTPD" in banner:
                results['checks'].append({
                    'name': 'ProFTPD服务',
                    'result': '检查已知漏洞',
                    'risk': '中危'
                })
                
    except Exception as e:
        results['error'] = str(e)
        
    return results if results['checks'] else None
