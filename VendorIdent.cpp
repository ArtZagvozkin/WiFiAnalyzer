//vendor identifier

#include <iostream>
#include <fstream>
//#include <vector>

using namespace std;
const int ht_size = 100; //hash table size

class VendorIdent {
private:
	struct LinkedList
	{
		//data
		string mac;
		string vendor_name;

		//pointers
		LinkedList* next;
		LinkedList* prev;
	};
	LinkedList* hash_table[ht_size];
	

	void load_file(string file)
	{
		ifstream input_file(file);
		string group, surname;

		//
		//Load list of vendors
		//

		input_file.close();
	}

	void clear()
	{
		//
	}

	void append(string mac, string vendor_name)
	{
		//
	}

	int get_id(string value) //hash function
	{
		return 0;
	}

public:
	VendorIdent(string file_dataset)
	{
		clear();
		load_file(file_dataset);
	}

	string find_vendor(string mac)
	{
		return "";
	}

	string show_hash_table()
	{
		//
	}
};
