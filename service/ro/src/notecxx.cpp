#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <limits>
#include <memory>
#include <unistd.h>
#include <vector>

#include "notecxx.h"

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
			fill(begin(buffer), end(buffer), 0);
			constexpr size_t max_length = N - 1;
			size_t remaining = max_length;
			while (remaining > 0)
			{
				ssize_t count = ::read(fd, &buffer[max_length - remaining], remaining);
				if (count > 0)
				{
					remaining -= count;
				}
				else if (count == 0 || (count < 0 && errno != EINTR))
				{
					return;
				}
			}
		}
		
		void write(const char* buffer, size_t max_length)
		{
			size_t remaining = max_length;
			while (remaining > 0)
			{
				ssize_t count = ::write(fd, &buffer[max_length - remaining], remaining);
				if (count > 0)
				{
					remaining -= count;
				}
				else if (count == 0 || (count < 0 && errno != EINTR))
				{
					return;
				}
			}
		}
		
		template<size_t N>
		void write(const char (&buffer)[N])
		{
			size_t max_length = strnlen(buffer, N - 1);
			return write(buffer, max_length);
		}
		
		void write(const string& str)
		{
			return write(str.c_str(), str.size());
		}
		
		[[gnu::format(printf, 2, 3)]]
		void printf(const char* format, ...)
		{
			va_list args;
			va_start(args, format);
			vdprintf(fd, format, args);
			va_end(args);
		}
	};
	
	safe_fd safe_fd::in = safe_fd(0);
	safe_fd safe_fd::out = safe_fd(1);
	
	void analyze_string(const string& input)
	{
		size_t ordered = 0;
		unsigned char last_char = 0;
		unsigned counts[256] = {0};
		for (unsigned char c : input)
		{
			counts[c]++;
			if (c > last_char)
			{
				ordered++;
				last_char = c;
			}
			else
			{
				last_char = numeric_limits<unsigned char>::max();
			}
		}
		
		size_t max_index = 0;
		for (size_t i = 0; i < countof(counts); ++i)
		{
			if (counts[max_index] < counts[i])
			{
				max_index = i;
			}
		}
		
		safe_fd::out.printf("the most common character in your input is '%c'\n", static_cast<char>(max_index));
		safe_fd::out.printf("the first %zu characters of the string are in ascending order\n", ordered);
	}
	
	vector<command> commands;
	char input_buffer[200];
	const char whitespace[] = " \r\n\t\v";
}

command::command(command_e op) : opcode(op)
{
	fill(begin(char_storage()), end(char_storage()), 0);
}

command::command(print_working_directory_tag) : command(print_working_directory)
{
}

command::command(make_directory_tag) : command(make_directory)
{
}

command::command(read_file_tag) : command(read_file)
{
}

command::command(write_file_tag, uint64_t passcode) : command(write_file)
{
	llu = passcode;
}

command::command(authenticate_tag, uint64_t passcode) : command(authenticate)
{
	llu = passcode;
}

command::command(change_directory_tag, const std::string& dir) : command(change_directory)
{
	strncpy(char_storage(), dir.c_str(), string_size - 1);
}

command::command(print_tag, const std::string& message) : command(print)
{
	auto max_size = string_size - 1;
	strncpy(char_storage(), message.c_str(), max_size);
	if (message.size() > max_size)
	{
		commands.emplace_back(print_tag(), message.substr(max_size));
	}
}

void command::perform() const
{
	if (opcode == print_working_directory)
	{
		unique_ptr<char, decltype(free)&> wd(getcwd(nullptr, 0), free);
		safe_fd::out.printf("directory is %s\n", wd.get());
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
		const char* directory = char_storage();
		for (; *directory == '.' || *directory == '/'; directory++);
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
		char buffer[200];
		safe_fd("message", O_RDONLY).read(buffer);
		safe_fd::out.write(buffer);
	}
	else if (opcode == write_file)
	{
		safe_fd("passcode", O_CREAT | O_TRUNC | O_WRONLY, 0600).write(to_string(llu));
		safe_fd("message", O_CREAT | O_TRUNC | O_WRONLY, 0600).write(input_buffer);
	}
	else if (opcode == print)
	{
		safe_fd::out.write(char_storage());
	}
}

int main()
{
	setvbuf(stdin, nullptr, _IONBF, 0);
	safe_fd::out.write("please enter the message that you wish to leave\n");
	fgets(input_buffer, sizeof input_buffer, stdin);
	analyze_string(input_buffer);
	
	commands.reserve(4);
	safe_fd::out.write("please enter your commands\n");
	while (cin)
	{
		string str;
		cin >> str;
		if (str == "echo")
		{
			getline(cin, str);
			// trim spaces at beginning and end of string
			str.erase(str.begin(), str.begin() + str.find_first_not_of(whitespace));
			str.erase(str.begin() + str.find_last_not_of(whitespace) + 1, str.end());
			str.push_back('\n');
			commands.emplace_back(print_tag(), str);
		}
		else if (str == "pwd")
		{
			commands.emplace_back(print_working_directory_tag());
		}
		else if (str == "cd")
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
