#pragma once

#include <iostream>
#include <fstream>
#include <ostream>
#include <cstdio>
#include <vector>
#include <iterator>
#include <filesystem>
#include <string>

using namespace std;

class Cksum
{
public:
	static unsigned long calculateChecksum(string fileName);

private:
	static unsigned long memcrc(char* b, size_t n);
};