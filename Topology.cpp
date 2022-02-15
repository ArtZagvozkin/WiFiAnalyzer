#include "Topology.h"

Topology::Topology() {
	networks.clear();
	graph.clear();
}

int Topology::add_network(string mac) {
	//drop trash
	if (mac == "" || mac == "unspecified" || mac == "ffffffffffff")
		return -1;

	//checking for availability
	for (int i = 0; i < networks.size(); i++)
		if (networks[i].mac == mac)
			return i;

	//create new network
	network new_network;
	new_network.mac = mac;
	new_network.ssid = "unknown";
	new_network.vendor = mac_info.get_vendor(mac);
	networks.push_back(new_network);

	return networks.size() - 1; //return network id
}

void Topology::set_ssid(string mac, string ssid) {
	if (mac != "" && mac != "ffffffffffff")
	{
		int mac_id = 0;
		mac_id = add_network(mac);
		networks[mac_id].ssid = ssid;
	}
}

int Topology::get_net_id(string mac) {
	for (int i = 0; i < networks.size(); i++)
		if (networks[i].mac == mac)
			return i;
	return -1;
}

int Topology::get_weight(string mac_src, string mac_dst) {
	for (int i = 0; i < graph.size(); i++)
		if (graph[i].mac_src == mac_src && graph[i].mac_dst == mac_dst)
			return graph[i].weight;
	return 0;
}

bool Topology::is_ap(string mac) { //is access point
	for (int i = 0; i < networks.size(); i++)
		if (networks[i].mac == mac)
			return true;
	return false;
}

void Topology::add_pair(string mac_src, string mac_dst, string type) {
	if (mac_src == "")
		mac_src = "unspecified";
	if (mac_dst == "")
		mac_dst = "unspecified";

	if (is_ap(mac_src) && is_ap(mac_dst)) { //ap to ap
		int net_id = get_net_id(mac_src);
		networks[net_id].clients.insert(mac_dst);

		net_id = get_net_id(mac_dst);
		networks[net_id].clients.insert(mac_src);
	}
	else if (is_ap(mac_src) && !is_ap(mac_dst)) { //ap to station
		int net_id = get_net_id(mac_src);
		networks[net_id].clients.insert(mac_dst);
	}
	else if (!is_ap(mac_src) && is_ap(mac_dst)) { //station to ap
		int net_id = get_net_id(mac_dst);
		networks[net_id].clients.insert(mac_src);
	}

	//search pair and return
	for (int i = 0; i < graph.size(); i++)
		if (graph[i].mac_src == mac_src && graph[i].mac_dst == mac_dst) {
			graph[i].weight++;
			return;
		}

	//add new frame, if not found
	edge new_edge;
	new_edge.mac_src = mac_src;
	new_edge.mac_dst = mac_dst;
	new_edge.weight = 1;
	graph.push_back(new_edge);
}

bool Topology::is_drons_ssid(string ssid) {
	if (ssid.find("skydio") != std::string::npos)
		return true;
	if (ssid.find("parrot") != std::string::npos)
		return true;

	return false;
}


void Topology::show_net_stat() {
	cout << "Networks:\n";

	if (networks.size() == 0) {
		cout << "\tNot detected" << endl;
		return;
	}

	vector<network> ::iterator net;
	for (net = networks.begin(); net != networks.end(); net++) {
		string net_type = "other";
		if (is_drons_ssid(net->ssid))
			net_type = "Drone";
		else
			net_type = mac_info.get_vendor_type(net->mac);

		cout << "\tssid: " << net->ssid << endl;
		cout << "\tdevice type: " << net_type << endl;
		cout << "\tmac: " << net->mac << endl;
		cout << "\tmac type: " << mac_info.get_type(net->mac) << endl;
		cout << "\tIs drone manufacturer?: " << mac_info.get_vendor_type(net->mac) << endl;
		cout << "\tvendor name: " << net->vendor << endl;
		cout << "\t\tClients \tIN \tOUT \tdevice type \tMAC type \tIs drone manufacturer? \tVendor \n";

		set<string> ::iterator client = net->clients.begin();
		for (client = net->clients.begin(); client != net->clients.end(); client++) {
			int in_frame = get_weight(net->mac, *client);
			int out_frame = get_weight(*client, net->mac);
			string vendor_type = mac_info.get_vendor_type(*client);
			string mac_type = mac_info.get_type(*client);
			string vendor_name = mac_info.get_vendor(*client);

			//remote controller
			string dev_type = mac_info.get_vendor_type(*client);
			if (dev_type == "Drone")
				dev_type = "Rem cont(drone)";
			else
				dev_type += "\t";

			cout << "\t\t" << *client << "\t" << in_frame << "\t" << out_frame << "\t" 
				<< dev_type << "\t" << mac_type << "\t" << vendor_type << "\t\t\t" << vendor_name << "\n";
		}

		cout << endl;
	}
}

void Topology::show_unknown_frames() {
	cout << "Unknown network(from\\to):\n\t";

	//get set of scr_mac and dst_mac
	set<string> set_of_src_mac;
	set<string> set_of_dst_mac;
	for (int i = 0; i < graph.size(); i++) {
		if (is_ap(graph[i].mac_src))
			continue;
		if (is_ap(graph[i].mac_dst))
			continue;
		set_of_src_mac.insert(graph[i].mac_src);
		set_of_dst_mac.insert(graph[i].mac_dst);
	}

	if (set_of_src_mac.size() == 0 || set_of_dst_mac.size() == 0) {
		cout << "\tNot detected" << endl;
		return;
	}

	//Show graph head
	set<string> ::iterator mac_dst;
	for (mac_dst = set_of_dst_mac.begin(); mac_dst != set_of_dst_mac.end(); mac_dst++)
		cout << "\t" << *mac_dst;
	cout << "\n";

	//Show graph data
	set<string> ::iterator mac_src;
	for (mac_src = set_of_src_mac.begin(); mac_src != set_of_src_mac.end(); mac_src++) {
		cout << *mac_src;

		for (mac_dst = set_of_dst_mac.begin(); mac_dst != set_of_dst_mac.end(); mac_dst++)
			cout << "\t" << get_weight(*mac_src, *mac_dst) << "\t";

		cout << "\n";
	}
}
