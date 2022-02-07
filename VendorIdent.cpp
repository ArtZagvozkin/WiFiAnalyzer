#include "VendorIdent.h"

VendorIdent::VendorIdent(string file) {
	clear();
	load_dataset(file);
}

void VendorIdent::clear() {
	for (int i = 0; i < ht_size; i++)
		hash_table[i] = nullptr;
}

void VendorIdent::load_dataset(string file) {
	std::ifstream input_file(file);
	input_file >> noskipws;   //no skip: " ", "\t", "\n"
	string line, mac, vendor_name;

	//read data
	if (input_file.is_open()) {
		while (getline(input_file, line)) {
			mac = "";
			vendor_name = "";

			//get mac and vendor name
			int mode = 0;
			for (int i = 0; i < line.size(); i++) {
				if (line[i] == ':') {
					mode = 1;
					continue;
				}
				if (mode == 0)
					mac += tolower(line[i]);
				else
					vendor_name += line[i];
			}

			//add to hash table
			append(mac, vendor_name);
		}
	}

	input_file.close();
}

void VendorIdent::append(string mac, string vendor_name) {
	int index = get_hash(mac);

	LinkedList* new_node = new LinkedList;
	new_node->mac = mac;
	new_node->vendor_name = vendor_name;
	new_node->next = nullptr;

	if (hash_table[index] == nullptr)
		hash_table[index] = new_node;
	else {
		LinkedList* node = hash_table[index];
		while (node->next != nullptr)
			node = node->next;
		node->next = new_node;
	}
}

int VendorIdent::get_hash(string value) { //hash function
	int hash = 0;

	//calc hash
	for (int i = 0; i < value.length() - 1; i++)
		hash += ((int)value[i] + 57) * (i + 1);

	hash = abs(hash) % ht_size;

	return hash;
}

string VendorIdent::find_vendor(string mac) {
	mac = mac.substr(0, 6);
	int index = get_hash(mac);
	LinkedList* node = hash_table[index];

	if (node != nullptr) {
		do {
			if (node->mac == mac)
				return node->vendor_name;
			node = node->next;
		} while (node != nullptr);
	}

	return "unknown";
}

void VendorIdent::show_workload() {
	int num;
	for (int i = 0; i < ht_size; i++) {
		LinkedList* node = hash_table[i];

		num = 0;
		while (node->next != nullptr) {
			node = node->next;
			num++;
		}
		cout << i << ": " << num << "\n";
	}
}
