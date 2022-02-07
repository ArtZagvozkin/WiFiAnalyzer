#pragma once
#include <iostream>
#include <fstream>
#include <string>

using namespace std;
const int ht_size = 1000; //hash table size

class VendorIdent {
private:
	struct LinkedList {
		//data
		string mac;
		string vendor_name;

		//pointer
		LinkedList* next;
	};
	LinkedList* hash_table[ht_size];

	void load_dataset(string file);

	void clear();

	void append(string mac, string vendor_name);

	int get_hash(string value);

public:
	VendorIdent(string file);

	string find_vendor(string mac);

	void show_workload();
};
