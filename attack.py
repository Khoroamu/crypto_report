from Crypto.Util.number import inverse
 
def itos(num):
    string = ''
    for i in range(8):
        string += chr(num % 256)
        num >>= 8
    string = string[::-1]
    num >>= 352
    ret = num & ((1 << 32) - 1)
    return ret, string
 
def gcd(a, b):
    if b == 0:
        return a
    return gcd(b, a % b)
 
def extend_gcd(a, b):
    if b == 0:
        return 1, 0
    s1, s2 = extend_gcd(b, a % b)
    ret = s1 - a // b * s2
    return s2, ret
 
def common_modulus_attack(n, e1, c1, e2, c2):
    s1, s2 = extend_gcd(e1, e2)
    # print(x,y)
    if s1 < 0:
        s1 = -s1
        c1 = inverse(c1, n)
    if s2 < 0:
        s2 = -s2
        c2 = inverse(c2, n)
    ret = pow(c1, s1, n) * pow(c2, s2, n) % n
    return ret
 
def common_factor_attack(n1, e1, c1, n2, e2, c2):
    p = gcd(n1, n2)
    q1 = n1 // p
    q2 = n2 // p
    phi1 = (p - 1) * (q1 - 1)
    phi2 = (p - 1) * (q2 - 1)
    d1 = inverse(e1, phi1)
    d2 = inverse(e2, phi2)
    ret1 = pow(c1, d1, n1)
    ret2 = pow(c2, d2, n2)
    return ret1, ret2 
 
def chinese_remainder_theorem(a, m):
    M = 1
    for i in m:
        M *= i
    ret = 0
    for i in range(len(m)):
        ret = (ret + a[i] * M // m[i] * inverse(M // m[i], m[i])) % M
    return ret
 
def broadcast_attack(a, m, e):
    c = chinese_remainder_theorem(a, m)
    l = 1
    r = c
    while l + 1 < r:
        md = (l + r) // 2
        if md ** e < c:
            l = md
        else:
            r = md
    if l ** e == c:
        return l
    if r ** e == c:
        return r
    return 0
 
def pollard_p1(n, e, c, b):
    k = 1
    for i in range(b):
        k *= i + 1
    p = gcd(pow(2, k, n) - 1, n)
    if p == 1 or p == n:
        return 0
    q = n // p
    if p * q != n:
        return 0
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    return pow(c, d, n)
 
def attack():
    n = []
    e = []
    c = []
    
    # 处理加密帧格式
    for i in range(21):
        f = open('./Frame' + str(i))
        s = f.read()
        n.append(int(s[:256], 16))
        e.append(int(s[256:512], 16))
        c.append(int(s[512:], 16))
 
    m = [0 for i in range(21)]
 
    # 共模攻击
    print("尝试共模攻击..")
    for i in range(21):
        for j in range(i):
            if n[i] == n[j]:
                m[i] = common_modulus_attack(n[i], e[i], c[i], e[j], c[j])
                m[j] = m[i]
                print(i, j, "=>", itos(m[i])[1])

    # 广播攻击
    print("尝试广播攻击..")
    index = [3, 8, 12, 16, 20]
    temp = broadcast_attack([c[i] for i in index], [n[i] for i in index], 5)
    for i in index:
        m[i] = temp
    print(index, "=>", itos(temp)[1])
 
    # 公因数攻击
    print("尝试公因数攻击..")
    for i in range(21):
        for j in range(i):
            if gcd(n[i], n[j]) > 1 and n[i] != n[j]:
                m[i], m[j] = common_factor_attack(n[i], e[i], c[i], n[j], e[j], c[j])
                print(i, "=>", itos(m[i])[1])
                print(j, "=>", itos(m[j])[1])
 
    # Pollard p-1 分解
    print("尝试 Pollard p-1 分解..")
    for i in range(1, 21):
        if m[i] > 0:
            continue
        temp = pollard_p1(n[i], e[i], c[i], 10000)
        if temp > 0:
            print(i, "=>", itos(temp)[1])
 
if __name__ == '__main__':
    attack()