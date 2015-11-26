from pwn import *
import random
import re
import socket
import sys

alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_/="

# these are used as legitimate messages/echo arguments to trick people
# read passcode to stdout
red_herring_note = 'I\x89\xe8j\x01\xfe\x0c$H\xb8passcodePH\x89\xe71\xf6j\x02X\x0f\x05H\x89\xc3H\x89\xc7H\x89\xe6j\x05X\x0f\x05H\x83\xc40H\x8b\x14$L\x89\xc7H\x89\xdeI\x89\xd2j(X\x99\x0f\x05'
# spawn shell
red_herring_shellcode = 'jhH\xb8/bin///sPH\x89\xe71\xf6j;X\x99\x0f\x05'

def most_common_char(string):
	if len(string) == 0: return chr(0)
	map = [0] * 256
	for c in string:
		map[ord(c)] += 1
	
	max = 0
	for i in range(len(map)):
		if map[max] < map[i]:
			max = i
	return chr(max)

def count_ascending(string):
	i = 0
	for i in range(1, len(string)):
		if ord(string[i-1]) >= ord(string[i]):
			break
	return i

def random_string(length):
	return "".join(random.choice(alphabet) for _ in xrange(length))

def random_directory():
	return "XXXXXXXX" + random_string(6)

class SendStream(object):
	def __init__(self, c):
		self.__c = c
		self.__command = []
		self.__expects = []
	
	def __append(self, token):
		self.__command.append(token)
	
	def stop_expect(self):
		self.__expects.append(None)
	
	def send(self, command, expects = []):
		self.__c.sendline(" ".join(command))
		self.__expects += expects

	def pwd(self):
		self.send(["pwd"], ["directory is .+"])
		log.info(" pwd")
	
	def echo(self, value):
		# only look for last chunk, since we don't want to fail vulnerable services
		start = len(value)
		start -= start % 14
		expected = value[start:]
		self.send(["echo", value], [expected])
		log.info(" echo %r [%r]" % (value, expected))
	
	def cd(self, dir):
		self.send(["cd", dir])
		log.info(" cd %s" % dir)

	def write(self, passcode):
		self.send(["write", str(passcode)])
		log.info(" write %i" % passcode)

	def read(self, passcode, expect_success = False):
		self.send(["read", str(passcode)], [".+" if expect_success else None])
		log.info(" read %i [likely: %r]" % (passcode, expect_success))

	def mkdir(self):
		self.send(["mkdir"])
		log.info(" mkdir")
	
	def expect(self):
		p = log.progress(" verifying expectations")
		self.__c.shutdown()
		for pattern in self.__expects:
			if pattern == None:
				break
			p.status("checking for '%s'" % pattern)
			self.__c.recvline_regex(pattern)
		p.success("done")

def random_echo(ss):
	ss.echo(random_string(random.randrange(9, 14)))

def random_echo_unsafe(ss):
	ss.echo(random_string(int(random.gauss(15, 3.5))))

def random_echo_shellcode(ss):
	# echo a random part of red_herring_shellcode
	# (trololol)
	size = len(red_herring_shellcode)
	useSize = min(int(random.gauss(size * 3. / 4., size / 8.)), size - 1)
	start = random.randrange(size - useSize)
	shellcodePart = red_herring_shellcode[start:start+useSize]
	ss.echo(shellcodePart)

def random_echo_select(ss):
	i = random.randrange(10)
	if i < 6: return random_echo(ss)
	if i < 9: return random_echo_unsafe(ss)
	return random_echo_shellcode(ss)

def random_cd(ss):
	ss.cd(random_directory())

random_pwd = SendStream.pwd

def random_write(ss):
	ss.write(random.randrange(2**64))

def random_read(ss):
	ss.read(random.randrange(2**64), False)

random_mkdir = SendStream.mkdir

random_commands = [
	random_cd, random_pwd, random_read, random_write, random_mkdir,
	random_echo_select,
]

def escape_note(note):
	safeAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/="
	final = ""
	for i in range(0, len(note), 16):
		final += note[len(final):i-1]
		final += random.choice(safeAlphabet) if note[i].isdigit() else note[i]
	final += note[len(final):]
	return final

def send_random_commands(ss, count, command_set):
	for i in xrange(count):
		random.choice(command_set)(ss)

def send_note(c, note):
	p = log.progress(" storing note")
	top_char = most_common_char(note)
	ascending = count_ascending(note)
	
	match = [None]
	def pred(regex):
		def do_match(input):
			match[0] = re.search(regex, input)
			return match[0] != None
		return do_match
	
	c.recvuntil("please enter the message that you wish to leave")
	c.sendline(note)
	c.recvline_pred(pred("the most common character in your input is '(.)'"))
	assert match[0].group(1) == top_char
	c.recvline_pred(pred("the first ([0-9]+) characters of the string are in ascending order"))
	assert int(match[0].group(1)) == ascending
	
	p.success(repr(note))
	c.recvuntil("please enter your commands\n")

def store_note(c, note, random_degree):
	p = log.progress("store-note")
	send_note(c, note)
	passcode = random.randrange(2**64)
	
	ss = SendStream(c)
	
	safe_set = [random_echo_select, random_cd, random_pwd, random_write]
	send_random_commands(ss, random.randrange(random_degree), safe_set)
	ss.mkdir()
	send_random_commands(ss, random.randrange(random_degree), safe_set)
	ss.stop_expect()
	ss.pwd()
	
	safe_set = [random_echo_select, random_cd, random_pwd]
	send_random_commands(ss, random.randrange(random_degree), safe_set)
	ss.write(passcode)
	send_random_commands(ss, random.randrange(random_degree), safe_set)
	
	ss.expect()
	line = c.recvline().strip()
	id = line[line.rindex("/")+1:]
	
	assert id[:8] == "XXXXXXXX"
	assert len(id) == 14
	p.success("done")
	
	return (id, passcode)

def retrieve_note(c, identifier, passcode, random_degree, assume_success = True):
	p = log.progress("retrieve-note")
	send_note(c, escape_note(random_string(int(random.gauss(32, 2)))))
	
	ss = SendStream(c)
	
	safe_set = [random_echo_select, random_cd, random_pwd]
	send_random_commands(ss, random.randrange(random_degree), safe_set)
	ss.cd(identifier)
	send_random_commands(ss, random.randrange(random_degree), safe_set)
	ss.stop_expect()
	ss.read(passcode, assume_success)
	send_random_commands(ss, random.randrange(random_degree), safe_set)
	
	ss.expect()
	p.success("done")
	
	if assume_success:
		return c.recvline().strip()
	else:
		return None

def random_activity(c, mean, stddev):
	p = log.progress("random-activity")
	send_note(c, escape_note(random_string(int(random.gauss(40, 8)))))
	
	ss = SendStream(c)
	send_random_commands(ss, int(random.gauss(mean, stddev)), random_commands)
	ss.expect()
	p.success("done")

def with_conn(host, port, func):
	c = remote(host, port)
	r = func(c)
	c.close()
	return r
