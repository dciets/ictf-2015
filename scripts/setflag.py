from interact import *
import sys

def set_flag(host, port, flag):
	store_flag = lambda c: store_note(c, flag, random.randrange(1, 5))
	(directory, passcode) = with_conn(host, port, store_flag)
	return {"FLAG_ID": directory, "TOKEN": str(passcode)}

if __name__ == "__main__":
	print set_flag(sys.argv[1], int(sys.argv[2]), sys.argv[3])
