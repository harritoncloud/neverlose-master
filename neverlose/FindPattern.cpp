#include "FindPattern.h"

void generate_shift_table(BYTE out[256], const PBYTE pattern, size_t pattern_len, BYTE wild_card)
{
	size_t i = pattern_len;

	for (; i; i--)
	{
		if (pattern[i] == wild_card)
			break;
	}

	size_t max_shift = pattern_len - i;

	if (pattern_len == i)
		max_shift = 1;

	memset(out, static_cast<int>(max_shift), 256);

	for (size_t j = pattern_len - max_shift; j < pattern_len; j++)
		out[pattern[j]] = static_cast<BYTE>(pattern_len - j);
}

void* FindPattern(void* base, size_t scan_size, const PBYTE pattern, size_t pattern_len, BYTE wild_card, size_t offset)
{
	if (!base || !pattern || pattern_len == 0 || scan_size < pattern_len)
		return nullptr;

	if (pattern_len == 1)
	{
		if (pattern[0] == wild_card)
			return static_cast<PBYTE>(base) + offset;

		void* found = memchr(base, pattern[0], scan_size);
		return found ? static_cast<PBYTE>(found) + offset : nullptr;
	}

	BYTE shift_table[256];

	pattern_len -= 1;

	generate_shift_table(
		shift_table,
		pattern,
		pattern_len,
		wild_card
	);

	PBYTE cursor = static_cast<PBYTE>(base);
	PBYTE bound = cursor + scan_size - (pattern_len + 1);

	while (cursor <= bound)
	{
		size_t i = pattern_len;

		while (true)
		{
			if (pattern[i] != wild_card && cursor[i] != pattern[i])
			{
				cursor += shift_table[cursor[pattern_len]];
				break;
			}

			if (!i)
				return cursor + offset;

			i--;
		}
	}

	return nullptr;
}
