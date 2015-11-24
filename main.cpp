#include <cstdlib>
#include <cstring>
#include <errno.h>
#include <fcntl.h>
#include <iostream>
#include <limits>
#include <memory>
#include <unistd.h>
#include <vector>

#include "main.h"

using namespace std;

namespace
{
	class safe_fd
	{
		int fd;
		
	public:
		static safe_fd in, out;
		
		safe_fd(int fd)
		: fd(dup(fd))
		{
		}
		
		safe_fd(const string& path, int mode, int mask = 0600)
		: fd(open(path.c_str(), mode, mask))
		{
		}
		
		~safe_fd()
		{
			close(fd);
		}
		
		template<size_t N>
		void read(char (&buffer)[N])
		{
			::read(fd, buffer, N - 1);
			buffer[N - 1] = 0;
		}
		
		template<size_t N>
		void write(const char (&buffer)[N])
		{
			::write(fd, buffer, N - 1);
		}
		
		void write(const string& str)
		{
			::write(fd, str.c_str(), str.size());
		}
	};
	
	safe_fd safe_fd::in = safe_fd(0);
	safe_fd safe_fd::out = safe_fd(1);
	
	void analyze_string(const string& input)
	{
		char lastChar = 0;
		size_t ordered = 0;
		unsigned counts[256] = {0};
		for (char c : input)
		{
			counts[c]++;
			if (c > lastChar)
			{
				ordered++;
				lastChar = c;
			}
			else
			{
				lastChar = numeric_limits<char>::max();
			}
		}
		
		size_t maxIndex = 0;
		for (size_t i = 0; i < countof(counts); ++i)
		{
			if (counts[maxIndex] < counts[i])
			{
				maxIndex = i;
			}
		}
		
		char mostCommonChar[] = "the most common character in your input is 'X'.\n";
		snprintf(mostCommonChar, sizeof mostCommonChar, "the most common character in your input is '%c'.\n", static_cast<char>(maxIndex));
		safe_fd::out.write(mostCommonChar);
		
		char orderedChars[] = "the first 999 characters of the string are in ascending order.\n";
		snprintf(orderedChars, sizeof orderedChars, "The first %.3zu characters of the string are in ascending order.\n", ordered);
		safe_fd::out.write(orderedChars);
	}
	
	vector<command> commands;
	char inputBuffer[200];
}

command::command(print_working_directory_tag) : opcode(print_working_directory)
{
}

command::command(make_directory_tag) : opcode(make_directory)
{
}

command::command(read_file_tag) : opcode(read_file)
{
}

command::command(write_file_tag, uint64_t passcode) : opcode(write_file), llu(passcode)
{
}

command::command(authenticate_tag, uint64_t passcode) : opcode(authenticate), llu(passcode)
{
}

command::command(change_directory_tag, const std::string& dir) : opcode(change_directory)
{
	strncpy(str, dir.c_str(), 15);
}

command::command(print_tag, const std::string& message) : opcode(print)
{
	strncpy(str, message.c_str(), 15);
	if (message.size() > 14)
	{
		commands.emplace_back(print_tag(), message.substr(14));
	}
}

void command::perform() const
{
	if (opcode == print_working_directory)
	{
		unique_ptr<char, decltype(free)*> wd(getcwd(nullptr, 0), &free);
		safe_fd::out.write(wd.get());
		safe_fd::out.write("\n");
	}
	else if (opcode == make_directory)
	{
		string format(14, 'X');
		if (mkdtemp(&format[0]))
		{
			chdir(format.c_str());
		}
	}
	else if (opcode == change_directory)
	{
		const char* directory = str;
		for (; *directory == '.'; directory++);
		chdir(directory);
	}
	else if (opcode == authenticate)
	{
		char buffer[] = "18446744073709551616";
		safe_fd("passcode", O_RDONLY).read(buffer);
		uint64_t code = strtoull(buffer, nullptr, 0);
		if (code != llu)
		{
			// hackers
			exit(0xdead);
		}
	}
	else if (opcode == read_file)
	{
		char buffer[200] = {0};
		safe_fd("message", O_RDONLY).read(buffer);
		safe_fd::out.write(string(buffer));
	}
	else if (opcode == write_file)
	{
		safe_fd("passcode", O_CREAT | O_TRUNC | O_WRONLY, 0600).write(to_string(llu));
		safe_fd("message", O_CREAT | O_TRUNC | O_WRONLY, 0600).write(string(inputBuffer));
	}
	else if (opcode == print)
	{
		safe_fd::out.write(str);
	}
}

int main()
{
	safe_fd::out.write("please enter the message that you wish to leave\n");
	safe_fd::in.read(inputBuffer);
	analyze_string(inputBuffer);
	
	commands.reserve(8);
	safe_fd::out.write("please enter your commands\n");
	while (cin)
	{
		string str;
		cin >> str;
		if (str == "echo")
		{
			getline(cin, str);
			commands.emplace_back(print_tag(), str);
		}
		else if (str == "pwd")
		{
			commands.emplace_back(print_working_directory_tag());
		}
		else if (str == "chdir")
		{
			cin >> str;
			commands.emplace_back(change_directory_tag(), str);
		}
		else if (str == "mkdir")
		{
			commands.emplace_back(make_directory_tag());
		}
		else if (str == "read")
		{
			uint64_t passcode;
			cin >> passcode;
			commands.emplace_back(authenticate_tag(), passcode);
			commands.emplace_back(read_file_tag());
		}
		else if (str == "write")
		{
			uint64_t passcode;
			cin >> passcode;
			commands.emplace_back(write_file_tag(), passcode);
		}
	}
	
	for (const command& cmd : commands)
	{
		cmd.perform();
	}
}
