from interact import *
import random
import sys

def benign(host, port):
	i = random.randrange(10)
	if i < 3:
		note_type = random.randrange(10)
		if note_type < 2: note = random_string(int(random.gauss(34, 3)))
		elif note_type < 9: note = "FLG" + random_string(13)
		else: note = red_herring_note
		with_conn(host, port, lambda c: store_note(c, note, 2))
	elif i < 6:
		id = random_directory()
		passcode = random.randrange(2**64)
		with_conn(host, port, lambda c: retrieve_note(c, id, passcode, 2, False))
	else:
		with_conn(host, port, lambda c: random_activity(c, 3.5, 0.75))

if __name__ == "__main__":
	benign(sys.argv[1], int(sys.argv[2]))
