#pragma once
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <bitset>

using namespace std;
const int ht_size = 1000; //hash table size

class MacInfo {
private:
	struct LinkedList {
		//data
		string mac;
		string vendor_name;
		string vendor_type;

		//pointer
		LinkedList* next;
	};
	LinkedList* hash_table[ht_size];

	void load_dataset(string file);

	void clear();

	void append(string mac, string vendor_name, string vendor_type);

	int get_hash(string value);

	LinkedList* get_entry(string mac);

public:
	MacInfo(string file);

	void show_workload();

	string get_vendor(string mac);

	string get_vendor_type(string mac);

	string get_type(string mac);
};
