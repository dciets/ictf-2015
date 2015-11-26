#ifndef main_h
#define main_h

#include <cstdint>
#include <string>
#include <type_traits>

template<typename T, size_t N>
constexpr size_t countof(const T (&)[N])
{
	return N;
}

enum command_e : uint8_t
{
	print = 48,
	print_working_directory,
	change_directory,
	make_directory,
	authenticate,
	read_file,
	write_file,
};

typedef std::integral_constant<uint8_t, print_working_directory>::type print_working_directory_tag;
typedef std::integral_constant<uint8_t, change_directory>::type change_directory_tag;
typedef std::integral_constant<uint8_t, make_directory>::type make_directory_tag;
typedef std::integral_constant<uint8_t, authenticate>::type authenticate_tag;
typedef std::integral_constant<uint8_t, read_file>::type read_file_tag;
typedef std::integral_constant<uint8_t, write_file>::type write_file_tag;
typedef std::integral_constant<uint8_t, print>::type print_tag;

struct command
{
	command_e opcode;
	
	// hopefully this aligns into a 15-char buffer
	char str[7];
	uint64_t llu;
	
	static constexpr size_t string_size = sizeof str + sizeof llu;
	
	inline char (&char_storage())[string_size] { return *(char (*)[string_size])&str; }
	inline const char (&char_storage() const)[string_size] { return *(const char (*)[string_size])&str; }
	
	command(print_working_directory_tag);
	command(make_directory_tag);
	command(read_file_tag);
	command(write_file_tag, uint64_t passcode);
	command(authenticate_tag, uint64_t passcode);
	command(change_directory_tag, const std::string& dir);
	command(print_tag, const std::string& message);
	
	void perform() const;
	
private:
	command(command_e op);
};

int main();

#endif /* main_h */
