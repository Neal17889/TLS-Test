import subprocess
import os

def run_openssl_command(command, description):
    print(f"正在执行: {description}")
    try:
        subprocess.run(command, shell=True, check=True)
        print("执行成功\n")
    except subprocess.CalledProcessError as e:
        print(f"执行失败: {e}")
        exit(1)

def main():
    # 创建CA证书
    run_openssl_command(
        "openssl genrsa -out ca.key 2048",
        "生成CA私钥"
    )
    
    run_openssl_command(
        'openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt -subj "/CN=MyRootCA"',
        "生成自签名CA证书"
    )

    # 生成服务器证书
    run_openssl_command(
        "openssl genrsa -out server.key 2048",
        "生成服务器私钥"
    )
    
    run_openssl_command(
        'openssl req -new -key server.key -out server.csr -subj "/CN=MyGameServer"',
        "生成服务器证书签名请求(CSR)"
    )
    
    run_openssl_command(
        "openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -sha256",
        "用CA签发服务器证书"
    )
    
    run_openssl_command(
        "openssl pkcs12 -export -out server.pfx -inkey server.key -in server.crt -certfile ca.crt -passout pass:",
        "打包服务器证书为PFX(无密码)"
    )

    # 生成客户端证书
    run_openssl_command(
        "openssl genrsa -out client.key 2048",
        "生成客户端私钥"
    )
    
    run_openssl_command(
        'openssl req -new -key client.key -out client.csr -subj "/CN=MyGameClient"',
        "生成客户端证书签名请求(CSR)"
    )
    
    run_openssl_command(
        "openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365 -sha256",
        "用CA签发客户端证书"
    )
    
    # 修改后的客户端PFX生成命令，添加-legacy和-provider-path参数
    run_openssl_command(
        'openssl pkcs12 -export -legacy -provider-path "C:\\Program Files\\OpenSSL-Win64\\bin" -out client.pfx -inkey client.key -in client.crt -certfile ca.crt -passout pass:',
        "打包客户端证书为PFX(无密码，使用legacy模式)"
    )

    # 列出生成的文件
    print("已生成以下文件:")
    for f in ['ca.key', 'ca.crt', 
              'server.key', 'server.csr', 'server.crt', 'server.pfx',
              'client.key', 'client.csr', 'client.crt', 'client.pfx']:
        if os.path.exists(f):
            print(f"- {f} ({os.path.getsize(f)} bytes)")

if __name__ == "__main__":
    main()