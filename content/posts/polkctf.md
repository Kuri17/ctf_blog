---
title : 'Polkctf'
date : 2024-01-18T04:02:07+09:00
draft : true
tags : ["crypto"]
categories : ["ctf"]
math: true
---
# 37C3 Potluck CTF

2023/12/29に開催されたCTFのwriteup.
## lima beans with lemon and lime(184pt)

```python:final.py
#!/usr/bin/env python3

from Crypto.Util.number import getPrime, bytes_to_long
from secrets import randbelow, randbits
# from FLAG import flag

beanCount = 8
beanSize = 2048
lemonSize = beanSize // 2 * beanCount
killerBean = getPrime(beanSize)
queries = 17

def pkcs16(limaBeans):
	filledLimaBeans = [0 for _ in range(beanCount)]
	#flagに足す
	limaBeans += b'A' * ((beanCount * beanSize // 8) - len(limaBeans))
 #flagをintに
	cookedLimaBeans = bytes_to_long(limaBeans)
	for idx in range(beanCount):
		cookedLimaBeans, filledLimaBeans[idx] = divmod(cookedLimaBeans, killerBean)# divmod(a,b) = a//b,a%b
	return filledLimaBeans
	#filledLimaBeans[0]= bytes_to_long(limaBeans) % killerBean,#filledLimaBeans[1]= bytes_to_long(limaBeans) // KillererBean) % killerBean,
def encrypt(limaBeans, lemon, lime):
	limaBeansWithLemonAndLime = 0
	for idx in range(beanCount):
		lemonSlice = lemon[idx]
		limaBean = limaBeans[idx]
		if (lime >> idx) & 1:
			limaBean **= 2
			limaBean %= killerBean
		limaBeansWithLemonAndLime += limaBean * lemonSlice
		limaBeansWithLemonAndLime %= killerBean	

	return limaBeansWithLemonAndLime

flag = pkcs16(flag)
print(f'Hello and welcome to the lima beans with lemon and lime cryptosystem. It it so secure that it even has a {lemonSize} bit encryption key, that is {lemonSize // 256} times bigger than an AES-256, and therefore is {lemonSize // 256} times more secure')
print(f'p: {killerBean}')
for turn in range(queries):
	print('1: Encrypt a message\n2: Encrypt flag\n3: Decrypt message')
	choice = input('> ')
	if choice not in ('1', '2', '3'):
		print('What?')
	if choice == '1':#angouotamesi
		limaBeans = input('msg: ').encode() 
  		#limabeansは2048bit以下である必要がある
		if len(limaBeans) * 8 > beanSize * beanCount:
			print('Hmmm a bit long innit?')
			continue
		limaBeans = pkcs16(limaBeans)
		lemon = [randbelow(2**(beanSize - 48)) for _ in range(beanCount)]
		lime = randbits(beanCount)
		limaBeansWithLemonAndLime = encrypt(limaBeans, lemon, lime)
		print(f'ct: {limaBeansWithLemonAndLime}')
		print(f'iv: {lime}')
		print(f'key: {",".join(map(str, lemon))}')
	elif choice == '2':#flag
		lemon = [randbelow(2**(beanSize//2)) for _ in range(beanCount)]
		lime = randbits(beanCount)
		limaBeansWithLemonAndLime = encrypt(flag, lemon, lime)
		print(f'ct: {limaBeansWithLemonAndLime}')
		print(f'iv: {lime}')
		print(f'key: {",".join(map(str, lemon))}')
	else:
		print('patented, sorry')
```

flagは与えられたファイル内のはpkcs16,encryptによって暗号化される．以下2つの関数の説明．
#### pkcs16
1. flagが2048byte文字列となるようにバイト文字列b'A'を後ろに追加し，整数にした値を\(c\)とする．
2. 既知の2048bitの整数\(k\)で以下の計算を行う
\[
\begin{aligned}
c &= k* r_1 + q_1\\
r_1 &= k* r_2 + q_2\\
r_2 &= k* r_3 + q_3\\
&~~~\vdots\\
r_8 &= k* r_7 + q_8
\end{aligned}
\]

3.\(q_1,q_2,\dots,q_8\)を出力する．

\(r_{i-1}\text{に}r_i\)を代入していくと\(c\)の式で未知の数は\(r_8\)のみとなる．
$$c　=$$
