import os

def clean_and_fix_env():
    priv = open('rsa_private.key').read().strip().replace('\n', '\\n')
    pub = open('rsa_public.key').read().strip().replace('\n', '\\n')
    
    if os.path.exists('.env'):
        lines = open('.env').readlines()
    else:
        lines = []
        
    new_lines = []
    skip = False
    for line in lines:
        # Detect start of our messed up keys
        if 'RSA_PRIVATE_KEY' in line or 'RSA_PUBLIC_KEY' in line:
            continue
        # Detect lines that look like parts of the RSA key (start with MII, -----, or end with ")
        stripped = line.strip()
        if stripped.startswith('MII') or stripped.startswith('-----') or stripped.endswith('"') and len(stripped) > 50:
            continue
        if stripped == '':
            new_lines.append(line)
        else:
            new_lines.append(line)
            
    # Remove duplicates from new_lines if any (simple approach)
    final_lines = []
    seen = set()
    for line in new_lines:
        if line not in seen or line.strip() == '':
            final_lines.append(line)
            if line.strip() != '':
                seen.add(line)
                
    # Append the clean keys
    final_lines.append(f'RSA_PRIVATE_KEY="{priv}"\n')
    final_lines.append(f'RSA_PUBLIC_KEY="{pub}"\n')
    
    with open('.env', 'w') as f:
        f.writelines(final_lines)

if __name__ == "__main__":
    clean_and_fix_env()
