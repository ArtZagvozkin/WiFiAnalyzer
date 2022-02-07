#pragma once
#include "VendorIdent.h"
#include <iostream>
#include <vector>
#include <set>

using namespace std;

class Topology {
private:
	struct network {
		string mac;
		string ssid;
		string vendor;

		set<string> clients;
	};
	vector<network> networks;
	VendorIdent vendor = VendorIdent("Source/VendorMAC.txt");

	struct edge {
		string mac_src;
		string mac_dst;
		int weight;
	};
	vector<edge> graph;

	int get_net_id(string mac);
	int get_weight(string mac_src, string mac_dst);

public:
	Topology();

	int add_network(string mac);
	void set_ssid(string mac, string ssid);
	bool is_ap(string mac); //is access point?
	void add_pair(string mac_src, string mac_dst, string type);
	void show_net_stat();
	void show_unknown_frames();
};
