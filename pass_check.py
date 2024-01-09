import requests
import hashlib
import sys


def api(pas):
    res = requests.get('https://api.pwnedpasswords.com/range/' + pas)
    if res.status_code != 200:
        raise RuntimeError(f'Error Fetching {
                           res.status_code}, check the api and try again')
    return res


def leak_pass_check(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first_5char, tail = sha1password[:5], sha1password[5:]
    response = api(first_5char)
    return leak_pass_check(response, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'Password: {password} was found {count} times')
        else:
            print(f'Password: {password} was not found')
    return 'Done'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
