import hashlib
import sys
import requests

def request_pwned_data(query):
    url = 'https://api.pwnedpasswords.com/range/' + query         #api accepts hash code only
    req= requests.get(url)
    if req.status_code!=200:
        raise RuntimeError(f'the error occured {req.status_code}, check the API.')
    return req

def filter_pwned_data(resp_hash,check_hash):
    print(resp_hash.text)
    resp_hash=(outputs.split(':') for outputs in resp_hash.text.splitlines())
    for hashs, count in resp_hash:
        if hashs==check_hash:
            return int(count)
    return 0

def password_hash(args):
    hashed=hashlib.sha1(args.encode('utf-8')).hexdigest().upper()     #converting the password to sha1 hash code
    hash_5chr,hash_tail=hashed[:5],hashed[5:]
    response=request_pwned_data(hash_5chr)
    return filter_pwned_data(response,hash_tail)

def check_pwned(password):
    for item in password:
        repeats=password_hash(item)
        if repeats>100:
            print(f'{item} was found {repeats} times, you strongly advised to change your password')
        elif 0<repeats<100:
            print(f'{item} was found {repeats} times, so its suggested to change your password')
        else:
            print(f'{item} was not found, you may not required to change the password')
    return 'all checked'
#check_pwned('hello')
check_pwned(sys.argv[1:])




