from interact import *
import sys

def get_flag(host, port, directory, passcode):
	retrieve_flag = lambda c: retrieve_note(c, directory, int(passcode), 2)
	flag = with_conn(host, port, retrieve_flag)
	return {"FLAG": flag}

if __name__ == "__main__":
	print get_flag(sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4]))
