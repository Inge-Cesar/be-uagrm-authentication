import base64
import os

def base64_encode_keys():
    priv = open('rsa_private.key').read().strip()
    pub = open('rsa_public.key').read().strip()
    
    priv_b64 = base64.b64encode(priv.encode()).decode()
    pub_b64 = base64.b64encode(pub.encode()).decode()
    
    lines = open('.env').readlines()
    new_lines = []
    
    for line in lines:
        if 'RSA_PRIVATE_KEY' not in line and 'RSA_PUBLIC_KEY' not in line:
            new_lines.append(line)
            
    new_lines.append(f'RSA_PRIVATE_KEY_B64="{priv_b64}"\n')
    new_lines.append(f'RSA_PUBLIC_KEY_B64="{pub_b64}"\n')
    
    with open('.env', 'w') as f:
        f.writelines(new_lines)

if __name__ == "__main__":
    base64_encode_keys()
