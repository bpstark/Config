#! /usr/bin/env python3
'''Create a set of jwks'''
import argparse
import json
from subprocess import check_call
import tempfile
from uuid import uuid4

from authlib.jose import jwk

def make_jwk(key: str, ident: str):
    '''convert tempfile to jwk'''
    with open(key, 'rb') as fin:
        json_key = jwk.dumps(fin.read(), kty='RSA')
    json_key['alg'] = 'RS256'
    json_key['kid'] = ident
    return json_key

def make_keys():
    '''Generate the keys needed for creating jwks'''
    priv_key = tempfile.mktemp()
    pub_key = '{}.pub'.format(priv_key)
    check_call(['ssh-keygen', '-t', 'rsa', '-b', '4096',
                '-m', 'PEM', '-f', priv_key, '-q', '-N', ''])
    check_call(['openssl', 'rsa', '-in', priv_key, '-pubout', '-outform', 'PEM', '-out', pub_key])
    return (priv_key, pub_key)

def main(args):
    '''main function'''
    keys = {'private' : {'keys': []}, 'public' : {'keys' : []}}
    for _ in range(args.count):
        ident = str(uuid4())
        priv, pub = make_keys()
        priv = make_jwk(priv, ident)
        pub = make_jwk(pub, ident)
        keys['private']['keys'].append(priv)
        keys['public']['keys'].append(pub)

    with open(args.output, 'w') as fout:
        json.dump(keys['private'], fout)
    with open('{}.pub'.format(args.output), 'w') as fout:
        json.dump(keys['public'], fout)

#pylint: disable=invalid-name
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('-c', '--count', type=int, default=1, metavar='#',
                        help='The number of keys to generate')
    parser.add_argument('output', type=str, help='the file to write data to')
    arguments = parser.parse_args()
    main(arguments)
