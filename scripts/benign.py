from interact import *
import random
import sys

def benign(host, port):
	i = random.randrange(10)
	if i < 3:
		note_type = random.randrange(13)
		if note_type < 6: note = random_string(int(random.gauss(40, 8)))
		elif note_type < 9: note = "FLG_" + random_string(16)
		elif note_type < 12: note = "FLAG{%s}" % random_string(32)
		else: note = red_herring_note
		with_conn(host, port, lambda c: store_note(c, note, random.randrange(1, 5)))
	elif i < 6:
		id = random_directory()
		passcode = random.randrange(2**64)
		with_conn(host, port, lambda c: retrieve_note(c, id, passcode, random.randrange(1, 5), False))
	else:
		with_conn(host, port, lambda c: random_activity(c, 15, 3.5))

if __name__ == "__main__":
	benign(sys.argv[1], int(sys.argv[2]))
