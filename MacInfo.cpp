#include "MacInfo.h"

MacInfo::MacInfo(string file) {
	clear();
	load_dataset(file);
}

void MacInfo::clear() {
	for (int i = 0; i < ht_size; i++)
		hash_table[i] = nullptr;
}

void MacInfo::load_dataset(string file) {
	std::ifstream input_file(file);
	input_file >> noskipws;   //no skip: " ", "\t", "\n"
	string line, mac, vendor_name, vendor_type = "";

	//read data
	if (input_file.is_open()) {
		while (getline(input_file, line)) {
			mac = "";
			vendor_name = "";
			vendor_type = "";

			//get mac and vendor name
			int mode = 0;
			for (int i = 0; i < line.size(); i++) {
				if (line[i] == ':') {
					mode++;
					continue;
				}

				if (mode == 0)
					mac += tolower(line[i]);
				else if (mode == 1)
					vendor_name += line[i];
				else if (mode == 2)
					vendor_type += line[i];
			}

			if (vendor_type == "")
				vendor_type = "Other";

			//add to hash table
			append(mac, vendor_name, vendor_type);
		}
	}

	input_file.close();
}

void MacInfo::append(string mac, string vendor_name, string vendor_type) {
	if (mac == "")
		return;

	int index = get_hash(mac);

	LinkedList* new_node = new LinkedList;
	new_node->mac = mac;
	new_node->vendor_name = vendor_name;
	new_node->vendor_type = vendor_type;
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

int MacInfo::get_hash(string value) { //hash function
	if (value == "")
		return 0;

	//calc hash
	int hash = 0;
	for (int i = 0; i < value.length() - 1; i++)
		hash += ((int)value[i] + 57) * (i + 1);

	hash = abs(hash) % ht_size;

	return hash;
}

void MacInfo::show_workload() {
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

MacInfo::LinkedList* MacInfo::get_entry(string mac) {
	int index = get_hash(mac);
	LinkedList* node = hash_table[index];

	if (node != nullptr) {
		do {
			if (node->mac == mac)
				return node;
			node = node->next;
		} while (node != nullptr);
	}

	return nullptr;
}

string MacInfo::get_vendor(string mac) {
	string result = "unknown";
	int k = 7;

	while (k > 5 && result == "unknown") {
		mac = mac.substr(0, k);
		MacInfo::LinkedList* node = get_entry(mac);
		if (node != nullptr)
			result = node->vendor_name;
		k--;
	}

	return result;
}

string MacInfo::get_vendor_type(string mac) {
	string result = "unknown";
	int k = 7;

	while (k > 5 && result == "unknown") {
		mac = mac.substr(0, k);
		MacInfo::LinkedList* node = get_entry(mac);
		if (node != nullptr)
			result = node->vendor_type;
		k--;
	}

	return result;
}

string MacInfo::get_type(string mac) {
	string type = "";

	//skip invalid
	if (mac == "ffffffffffff")
		return "Broadcast";
	if (mac == "unspecified" || mac == "")
		return "none\t";

	// get the first byte
	string byte_hex = mac.substr(0, 2);

	// str hex to int
	std::stringstream ss;
	ss << std::hex << byte_hex;
	int byte_int;
	ss >> byte_int;

	// int to hex bin
	string byte_bin = bitset<8>(byte_int).to_string();

	// type defenition
	// global/local
	if (byte_bin.substr(6, 1) == "0")
		type = "global";
	else
		type = "local";

	// unicast/multicast
	if (byte_bin.substr(7, 1) == "0")
		type += "/unicast";
	else
		type += "/multicast";

	return type;
}
